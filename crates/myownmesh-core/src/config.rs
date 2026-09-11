//! Config schema for `~/.myownmesh/config.json`. Reading & writing
//! lives here so any caller (binary, library embedder, tests) shares
//! the same parse / default behavior.
//!
//! Schema versioning uses one exact hard-alpha `version` field. This build
//! refuses any other version rather than migrating or guessing compatibility.

use std::path::{Path, PathBuf};
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Duration;

#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

/// Flood-protection limits for the self-hosted signaling relay. Defined
/// in the signaling crate (its natural home) and re-used here so the
/// config, the daemon, and the relay all share one shape.
pub use myownmesh_signaling::server::Limits as SignalingLimits;

pub const CONFIG_VERSION: u32 = 2;

const DEFAULT_MESH_EVENT_CAPACITY: u64 = 256;
const DEFAULT_NETWORK_EVENT_CAPACITY: u64 = 256;
const DEFAULT_NETWORK_CONNECTION_TRACE_CAPACITY: u64 = 512;
const MAX_NETWORK_BROADCAST_CAPACITY: usize = usize::MAX >> 1;

fn default_mesh_event_capacity() -> u64 {
    DEFAULT_MESH_EVENT_CAPACITY
}

fn default_network_event_capacity() -> u64 {
    DEFAULT_NETWORK_EVENT_CAPACITY
}

fn default_network_connection_trace_capacity() -> u64 {
    DEFAULT_NETWORK_CONNECTION_TRACE_CAPACITY
}

static CONFIG_TRANSACTION_GATE: OnceLock<Mutex<()>> = OnceLock::new();

fn config_transaction_gate() -> &'static Mutex<()> {
    CONFIG_TRANSACTION_GATE.get_or_init(|| Mutex::new(()))
}

/// The cross-process half of the config transaction fence.
///
/// Unix keeps the lock pathname after release and relies on `flock`'s inode
/// ownership, while Windows uses a synchronous byte-range lock whose
/// ownership is released when the handle closes. Other platforms fail closed
/// because a portable crash-release primitive is unavailable.
struct ConfigFileLease {
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    _file: std::fs::File,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ConfigFileIdentity {
    len: u64,
    #[cfg(unix)]
    dev: u64,
    #[cfg(unix)]
    ino: u64,
    #[cfg(windows)]
    volume_serial: u32,
    #[cfg(windows)]
    file_index: u64,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileTime {
    _low: u32,
    _high: u32,
}

#[cfg(windows)]
#[repr(C)]
struct WindowsFileInformation {
    _attributes: u32,
    _creation_time: WindowsFileTime,
    _access_time: WindowsFileTime,
    _write_time: WindowsFileTime,
    volume_serial: u32,
    _file_size_high: u32,
    _file_size_low: u32,
    _links: u32,
    file_index_high: u32,
    file_index_low: u32,
}

#[cfg(windows)]
#[link(name = "kernel32")]
unsafe extern "system" {
    fn GetFileInformationByHandle(
        file: *mut std::ffi::c_void,
        information: *mut WindowsFileInformation,
    ) -> i32;
    fn LockFileEx(
        file: *mut std::ffi::c_void,
        flags: u32,
        reserved: u32,
        bytes_low: u32,
        bytes_high: u32,
        overlapped: *mut WindowsOverlapped,
    ) -> i32;
}

#[cfg(windows)]
#[repr(C)]
struct WindowsOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

impl ConfigFileIdentity {
    #[cfg(unix)]
    fn from_metadata(metadata: &std::fs::Metadata) -> Self {
        Self {
            len: metadata.len(),
            dev: metadata.dev(),
            ino: metadata.ino(),
        }
    }

    fn from_file(file: &std::fs::File) -> Result<Self> {
        #[cfg(unix)]
        {
            Ok(Self::from_metadata(&file.metadata().map_err(|error| {
                Error::Config(format!("stat config: {error}"))
            })?))
        }

        #[cfg(windows)]
        {
            let mut information = std::mem::MaybeUninit::<WindowsFileInformation>::uninit();
            if unsafe { GetFileInformationByHandle(file.as_raw_handle(), information.as_mut_ptr()) }
                == 0
            {
                return Err(Error::Config(format!(
                    "get config file identity: {}",
                    std::io::Error::last_os_error()
                )));
            }
            let information = unsafe { information.assume_init() };
            let metadata = file
                .metadata()
                .map_err(|error| Error::Config(format!("stat config: {error}")))?;
            Ok(Self {
                len: metadata.len(),
                volume_serial: information.volume_serial,
                file_index: (u64::from(information.file_index_high) << 32)
                    | u64::from(information.file_index_low),
            })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let _ = file;
            Err(Error::Config(
                "config file identity is unsupported on this platform".to_string(),
            ))
        }
    }
}

impl ConfigFileLease {
    fn acquire(path: &Path) -> Result<Self> {
        #[cfg(unix)]
        {
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .open(path)
                .map_err(|error| {
                    Error::Config(format!(
                        "open config transaction lock {}: {error}",
                        path.display()
                    ))
                })?;
            const LOCK_EX: std::os::raw::c_int = 2;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX) } != 0 {
                return Err(Error::Config(format!(
                    "config transaction is busy: {}",
                    path.display()
                )));
            }
            Ok(Self { _file: file })
        }

        #[cfg(windows)]
        {
            const FILE_SHARE_READ: u32 = 0x0000_0001;
            const FILE_SHARE_WRITE: u32 = 0x0000_0002;
            const FILE_SHARE_DELETE: u32 = 0x0000_0004;
            const LOCKFILE_EXCLUSIVE_LOCK: u32 = 0x0000_0002;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
                .open(path)
                .map_err(|error| {
                    Error::Config(format!(
                        "open config transaction lock {}: {error}",
                        path.display()
                    ))
                })?;
            let mut overlapped = WindowsOverlapped {
                internal: 0,
                internal_high: 0,
                offset: 0,
                offset_high: 0,
                event: std::ptr::null_mut(),
            };
            if unsafe {
                LockFileEx(
                    file.as_raw_handle(),
                    LOCKFILE_EXCLUSIVE_LOCK,
                    0,
                    u32::MAX,
                    u32::MAX,
                    &mut overlapped,
                )
            } == 0
            {
                return Err(Error::Config(format!(
                    "lock config transaction {}: {}",
                    path.display(),
                    std::io::Error::last_os_error()
                )));
            }
            Ok(Self { _file: file })
        }

        #[cfg(not(any(unix, windows)))]
        {
            Err(Error::Config(format!(
                "config transactions are unsupported on this platform: {}",
                path.display()
            )))
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

/// One in-process and cross-process config transaction lease.
struct ConfigTransactionLease {
    _file: ConfigFileLease,
    _process: MutexGuard<'static, ()>,
}

impl ConfigTransactionLease {
    fn acquire(config_path: &Path) -> Result<Self> {
        let process = config_transaction_gate()
            .lock()
            .map_err(|_| Error::Config("config transaction gate was poisoned".to_string()))?;
        let parent = config_path.parent().ok_or_else(|| {
            Error::Config(format!(
                "config path has no parent: {}",
                config_path.display()
            ))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|error| Error::Config(format!("create {}: {error}", parent.display())))?;
        let name = config_path.file_name().ok_or_else(|| {
            Error::Config(format!(
                "config path has no file name: {}",
                config_path.display()
            ))
        })?;
        let mut lock_name = name.to_os_string();
        lock_name.push(".lock");
        let lock_path = config_path.with_file_name(lock_name);
        let file = ConfigFileLease::acquire(&lock_path)?;
        Ok(Self {
            _file: file,
            _process: process,
        })
    }
}

/// Topology selector for a single network. Wire-form matches the
/// JSON-tagged shape; embedders construct these directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TopologyMode {
    /// A *shaped* auto-healing ring with `n_preferred` neighbors (2
    /// immediate + (n-2) shortcuts; missing/null defaults to 3): each
    /// node dials only the union of the two sides' preferred sets,
    /// both-sides-shelved non-edges are closed, and broadcasts flood
    /// hop-by-hop with per-node dedup (see
    /// [`crate::topology::Topology::edge`]). This shapes the
    /// signaling/control fabric only — a media session dials its pair
    /// directly, on demand, regardless of mode.
    Ring {
        #[serde(default)]
        n_preferred: Option<u32>,
    },
    /// All spokes connect to a single, config-named hub — and only the
    /// hub. Spoke↔spoke frames route through it.
    Star {
        hub: DeviceId,
    },
    /// A hub *tier*: the named hubs hold a full mesh among themselves,
    /// and every other member (spoke) connects to `spoke_redundancy`
    /// of them, assigned by rendezvous hashing so the mapping is
    /// deterministic on every node and stable as hubs come and go.
    /// Spoke↔spoke frames route spoke → hub (→ hub) → spoke. This is
    /// the hierarchical hub-and-spoke shape: per-spoke connection
    /// count is O(redundancy), per-hub O(spokes/hubs + hubs), and
    /// nobody pays N².
    Hubs {
        hubs: Vec<DeviceId>,
        /// How many hubs each spoke maintains a connection to
        /// (default [`TopologyMode::DEFAULT_SPOKE_REDUNDANCY`],
        /// clamped to the hub count). 1 is minimal; 2 keeps every
        /// spoke reachable through a single hub restart.
        #[serde(default)]
        spoke_redundancy: Option<u32>,
    },
    /// Full mesh — every pair connects and stays connected. The
    /// default, and the truthful name for what every pre-0.2.34
    /// network ran (the old "ring" only shelved app frames; it never
    /// shaped connections). N² cost — fine for small fleets; pick
    /// [`TopologyMode::Ring`] or [`TopologyMode::Hubs`] deliberately
    /// when a network outgrows it.
    /// A bounded shallow routing tree. The configured root is a routing role,
    /// not a semantic trust root; hubs form the finite intermediate tier and
    /// every leaf has one primary hub. Backup candidates are optional warm
    /// alternatives, never a second primary parent or a full hub mesh.
    HubTree {
        root: DeviceId,
        hubs: Vec<DeviceId>,
        backup_candidates: u32,
    },
    FullMesh,
}

// `FullMesh` carries no data, so Default is derivable — but keeping it
// explicit documents that the default is a *decision* (the truthful
// name for pre-0.2.34 behavior), not an accident of variant order.
#[allow(clippy::derivable_impls)]
impl Default for TopologyMode {
    fn default() -> Self {
        TopologyMode::FullMesh
    }
}

impl TopologyMode {
    /// The default `n_preferred` for ring topology (2 immediate +
    /// 1 shortcut). Used when a Ring config omits the field.
    pub const DEFAULT_RING_N_PREFERRED: u32 = 3;

    /// Default hub count each spoke connects to under
    /// [`TopologyMode::Hubs`] — two, so one hub restarting doesn't
    /// strand its spokes.
    pub const DEFAULT_SPOKE_REDUNDANCY: u32 = 2;

    /// Resolve the effective `n_preferred` for a Ring topology,
    /// substituting the default when the field is None. Other
    /// topology modes return 0 — they don't use this value.
    pub fn effective_n_preferred(&self) -> u32 {
        match self {
            TopologyMode::Ring { n_preferred } => {
                n_preferred.unwrap_or(Self::DEFAULT_RING_N_PREFERRED)
            }
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct StunServer {
    pub urls: Vec<String>,
}

/// Built-in STUN URL applied when a deserialized `NetworkConfig` omits
/// `stun_servers`. Points at the project's reference STUN so NAT
/// reflexion works out of the box. STUN is the same program too — a
/// `myownmesh` host running `services.turn` answers STUN on the same
/// port — so run your own and point `stun_servers` at it. Opt out
/// entirely with an explicit empty array (`"stun_servers": []`);
/// `default_stun_servers` only fires when the field is absent.
pub const DEFAULT_NETWORK_STUN: &[&str] = &["stun:stun.myownmesh.com:3478"];

/// Build the default STUN server list. Exposed so embedders that
/// construct `NetworkConfig` programmatically can call
/// `default_stun_servers()` instead of repeating the URL list.
pub fn default_stun_servers() -> Vec<StunServer> {
    vec![StunServer {
        urls: DEFAULT_NETWORK_STUN
            .iter()
            .map(|s| (*s).to_string())
            .collect(),
    }]
}

/// Build the default TURN server list. Relays media/data when no direct
/// path exists (symmetric NAT, CGNAT, locked-down hotspots). Points at
/// the project's reference TURN with a shared guest credential so it
/// works out of the box. That relay is bandwidth-capped per connection,
/// so for sustained throughput run your own — `services.turn` on any
/// `myownmesh` host — and point `turn_servers` at it. Opt out with an
/// explicit empty array (`"turn_servers": []`).
pub fn default_turn_servers() -> Vec<TurnServer> {
    vec![TurnServer {
        // This is an ordered configuration list, not a promise of ICE fallback order.
        urls: vec![
            "turn:turn.myownmesh.com:3478?transport=udp".to_string(),
            "turn:turn.myownmesh.com:3478?transport=tcp".to_string(),
            "turns:turn.myownmesh.com:5349?transport=tcp".to_string(),
        ],
        username: Some("guest".to_string()),
        credential: Some("theguestpassword".to_string()),
    }]
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnServer {
    pub urls: Vec<String>,
    #[serde(default)]
    pub username: Option<String>,
    /// TURN servers use the loose "credential" field name rather than
    /// "password" — keep parity with the RTC ICE config shape so
    /// users copy-pasting from Cloudflare/Metered.ca dashboards see
    /// the field name they expect.
    #[serde(default)]
    pub credential: Option<String>,
}

/// Validate TURN URL syntax without resolving names, opening sockets, or
/// echoing credentials/URLs into errors. `turns` means TLS over TCP; DTLS TURN
/// and arbitrary query parameters are not supported by this transport.
pub fn validate_turn_url(value: &str) -> Result<()> {
    let invalid = || Error::Config("invalid or unsupported TURN URL".into());
    let (secure, rest) = if let Some(rest) = value.strip_prefix("turns:") {
        (true, rest)
    } else if let Some(rest) = value.strip_prefix("turn:") {
        (false, rest)
    } else {
        return Err(invalid());
    };
    let authority = if let Some((authority, query)) = rest.split_once('?') {
        match query {
            "transport=tcp" => {}
            "transport=udp" if !secure => {}
            _ => return Err(invalid()),
        }
        authority
    } else {
        rest
    };
    if authority.is_empty() || !authority.is_ascii() {
        return Err(invalid());
    }
    let (host, port) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6.split_once(']').ok_or_else(invalid)?;
        host.parse::<std::net::Ipv6Addr>().map_err(|_| invalid())?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(suffix.strip_prefix(':').ok_or_else(invalid)?)
        };
        (host, port)
    } else {
        let (host, port) = authority
            .split_once(':')
            .map_or((authority, None), |(host, port)| (host, Some(port)));
        let dns = host.strip_suffix('.').unwrap_or(host);
        if dns.contains('.')
            && dns.bytes().all(|c| c.is_ascii_digit() || c == b'.')
            && dns.parse::<std::net::Ipv4Addr>().is_err()
        {
            return Err(invalid());
        }
        if dns.is_empty()
            || dns.len() > 253
            || dns.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || c == b'-')
            })
        {
            return Err(invalid());
        }
        (host, port)
    };
    if host.is_empty() {
        return Err(invalid());
    }
    if let Some(port) = port {
        if port.is_empty()
            || !port.bytes().all(|c| c.is_ascii_digit())
            || port.parse::<u16>().ok().filter(|p| *p != 0).is_none()
        {
            return Err(invalid());
        }
    }
    Ok(())
}

/// Owner-selected finite mDNS policy. Durations are integer milliseconds in
/// the persisted config so the schema does not depend on Rust's `Duration`
/// representation; the signaling bridge translates these values before
/// creating any backend or socket.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct MdnsPolicyConfig {
    pub max_active_connections: u64,
    pub max_discovered_peers: u64,
    pub outbound_queue_capacity: u64,
    pub max_resolve_owners: u64,
    pub event_capacity: u64,
    pub max_event_epochs: u64,
    /// Maximum TXT records retained from one resolved service.
    pub max_txt_entries: u64,
    /// Maximum encoded TXT bytes retained from one resolved service.
    pub max_txt_bytes: u64,
    /// Maximum unique addresses retained from one resolved service.
    pub max_resolved_addresses: u64,
    pub dial_timeout_ms: u64,
    pub connection_idle_timeout_ms: u64,
    pub inbound_idle_timeout_ms: u64,
    pub reannounce_interval_ms: u64,
    pub query_deadline_ms: u64,
    pub accept_error_backoff_ms: u64,
}

/// Optional owner-selected maintenance policy for configured hub tiers.
///
/// This policy is deliberately separate from [`TopologyMode`]: topology
/// selects the shape and configured hub identities, while these limits bound
/// the local maintenance work that shape may schedule.  Omitting the policy
/// keeps the pre-existing topology behaviour unchanged; a present policy is
/// fully explicit and is never inferred from peer count or a remote
/// advertisement.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HubPolicyConfig {
    pub max_parallel_dials: u64,
    pub max_dials_per_pass: u64,
    pub max_advertisements_per_pass: u64,
    pub exploration_interval_ms: u64,
    pub max_exploration_probes_per_pass: u64,
    pub max_exploration_peers_per_reply: u16,
    pub trickle_imin_ms: u64,
    pub trickle_imax_ms: u64,
    pub trickle_redundancy: u32,
    pub trickle_reset_window_ms: u64,
    pub trickle_max_resets_per_window: u32,
}

impl HubPolicyConfig {
    pub(crate) fn validate(&self) -> bool {
        let semaphore_max = u64::try_from(tokio::sync::Semaphore::MAX_PERMITS).ok();
        self.max_parallel_dials > 0
            && self.max_dials_per_pass > 0
            && self.max_advertisements_per_pass > 0
            && self.exploration_interval_ms > 0
            && self.max_exploration_probes_per_pass > 0
            && self.max_exploration_peers_per_reply > 0
            && usize::from(self.max_exploration_peers_per_reply)
                <= crate::protocol::HUB_DISCOVERY_HARD_MAX_PEERS
            && self.max_parallel_dials <= self.max_dials_per_pass
            && semaphore_max.is_some_and(|max| self.max_dials_per_pass <= max)
            && self.trickle_imin_ms >= 2
            && self.trickle_imax_ms >= self.trickle_imin_ms
            && self.trickle_redundancy > 0
            && self.trickle_reset_window_ms > 0
            && self.trickle_max_resets_per_window > 0
            && usize::try_from(self.max_parallel_dials).is_ok()
            && usize::try_from(self.max_dials_per_pass).is_ok()
            && usize::try_from(self.max_advertisements_per_pass).is_ok()
            && usize::try_from(self.max_exploration_probes_per_pass).is_ok()
    }
}

/// Optional local custody bounds for the explicit shallow HubTree adapter.
/// These values fund relation state only; they are not part of the shared
/// topology digest and are never learned from a peer.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct TreePolicyConfig {
    pub max_children: u64,
    pub max_backups: u64,
    pub max_pending: u64,
    pub max_age_ms: u64,
}

impl TreePolicyConfig {
    pub(crate) fn validate(&self) -> bool {
        self.max_pending == 1
            && self.max_age_ms > 0
            && self
                .max_backups
                .checked_add(1)
                .is_some_and(|slots| u16::try_from(slots).is_ok())
            && usize::try_from(self.max_children).is_ok()
            && usize::try_from(self.max_backups).is_ok()
            && usize::try_from(self.max_pending).is_ok()
    }
}

/// Optional owner-selected bounds for the node-local observation aggregate.
///
/// This is a diagnostic cache only. It has no wire representation, semantic
/// authority, persistence, or routing effect. The option is intentionally
/// absent by default; when present, every bound is explicit and finite.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LocalObservationPolicyConfig {
    pub max_records: u64,
    pub max_records_per_subject: u64,
    pub max_age_ms: u64,
    pub max_maintenance_per_tick: u64,
}

impl LocalObservationPolicyConfig {
    pub(crate) fn validate(&self) -> bool {
        self.max_records > 0
            && self.max_records_per_subject > 0
            && self.max_records_per_subject <= self.max_records
            && self.max_age_ms > 0
            && self.max_maintenance_per_tick > 0
            && usize::try_from(self.max_records).is_ok()
            && usize::try_from(self.max_records_per_subject).is_ok()
            && usize::try_from(self.max_maintenance_per_tick).is_ok()
    }
}

impl Default for MdnsPolicyConfig {
    fn default() -> Self {
        Self {
            max_active_connections: 256,
            max_discovered_peers: 1024,
            outbound_queue_capacity: 128,
            max_resolve_owners: 256,
            event_capacity: 128,
            max_event_epochs: 1024,
            max_txt_entries: myownmesh_signaling::mdns::discovery::MAX_TXT_ENTRIES as u64,
            max_txt_bytes: myownmesh_signaling::mdns::discovery::MAX_TXT_BYTES as u64,
            max_resolved_addresses: myownmesh_signaling::mdns::discovery::MAX_RESOLVED_ADDRESSES
                as u64,
            dial_timeout_ms: 5_000,
            connection_idle_timeout_ms: 30_000,
            inbound_idle_timeout_ms: 120_000,
            reannounce_interval_ms: 60_000,
            query_deadline_ms: 5_000,
            accept_error_backoff_ms: 100,
        }
    }
}

impl MdnsPolicyConfig {
    pub fn validate(&self) -> bool {
        let semaphore_max = match u64::try_from(tokio::sync::Semaphore::MAX_PERMITS) {
            Ok(max) => max,
            Err(_) => return false,
        };
        self.max_active_connections > 0
            && self.max_discovered_peers > 0
            && self.outbound_queue_capacity > 0
            && self.max_resolve_owners > 0
            && self.event_capacity > 0
            && self.max_event_epochs > 0
            && self.max_txt_entries > 0
            && self.max_txt_bytes > 0
            && self.max_txt_bytes <= u16::MAX as u64
            && self.max_resolved_addresses > 0
            && self.dial_timeout_ms > 0
            && self.connection_idle_timeout_ms > 0
            && self.inbound_idle_timeout_ms > 0
            && self.reannounce_interval_ms > 0
            && self.query_deadline_ms > 0
            && self.accept_error_backoff_ms > 0
            && self.max_active_connections <= semaphore_max
            && self.outbound_queue_capacity <= semaphore_max
            && self.event_capacity <= semaphore_max
            && usize::try_from(self.max_active_connections).is_ok()
            && usize::try_from(self.max_discovered_peers).is_ok()
            && usize::try_from(self.outbound_queue_capacity).is_ok()
            && usize::try_from(self.max_resolve_owners).is_ok()
            && usize::try_from(self.event_capacity).is_ok()
            && usize::try_from(self.max_event_epochs).is_ok()
            && usize::try_from(self.max_txt_entries).is_ok()
            && usize::try_from(self.max_txt_bytes).is_ok()
            && usize::try_from(self.max_resolved_addresses).is_ok()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingConfig {
    /// Which *remote* signaling strategy to use: `"nostr"` (default,
    /// relay-based) or `"none"` (no remote signaling at all — pair
    /// with `mdns` for a LAN-only network). Sibling crates can add
    /// others (BitTorrent trackers, MQTT, IPFS, Firebase) and the
    /// engine picks via this field. An unknown value attaches NO
    /// remote driver, loudly — never a silent Nostr fallback, so a
    /// privacy-motivated strategy can't quietly leak presence onto
    /// public relays.
    pub strategy: String,
    /// LAN-local mDNS/DNS-SD signaling, running alongside whatever
    /// `strategy` selects. On by default: co-located peers discover
    /// each other and exchange SDP over the local network, so a mesh
    /// keeps forming/healing even when every relay or venue is
    /// unreachable. Set `false` to stay silent on the local network.
    /// The mDNS driver ignores the relay-oriented fields below
    /// (`servers`, `redundancy`, `denylist`, `public_fallback`).
    pub mdns: bool,
    /// Explicit relay URLs. Empty = use the built-in deterministic
    /// top-N defaults filtered by the denylist.
    pub servers: Vec<String>,
    /// How many relays to keep connected at once. Default 5 — five
    /// independent forwarders are enough that no single relay can
    /// censor or stall the room, while keeping the per-peer
    /// bandwidth tax tolerable.
    pub redundancy: u32,
    /// Hostnames we never connect to even if they'd be picked by the
    /// deterministic shuffle. Used to skip relays known to rate-limit
    /// us, drop our REQs, or otherwise misbehave. Hostname-only
    /// (no scheme); match is case-insensitive.
    pub denylist: Vec<String>,
    /// Fall back to the built-in public relays when every configured /
    /// primary relay (your own and the reference one) is unreachable. On
    /// by default. The fallback is reactive — public relays are only
    /// connected while the primary set is down, and dropped again the
    /// moment one recovers — so steady state never touches public
    /// infrastructure. Set `false` to stay strictly on your own relays.
    pub public_fallback: bool,
    /// Finite owner-selected mDNS workload and timing policy.
    #[serde(default)]
    pub mdns_policy: MdnsPolicyConfig,
    /// Finite owner-selected Nostr recovery and shutdown timing policy.
    #[serde(default)]
    pub nostr_timing: NostrTimingPolicyConfig,
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            strategy: "nostr".to_string(),
            mdns: true,
            servers: Vec::new(),
            redundancy: DEFAULT_SIGNALING_REDUNDANCY,
            denylist: default_signaling_denylist(),
            public_fallback: true,
            mdns_policy: MdnsPolicyConfig::default(),
            nostr_timing: NostrTimingPolicyConfig::default(),
        }
    }
}

/// Persisted owner policy for Nostr reconnect, fallback, and cancellation.
/// Millisecond fields are converted to the signaling driver's `Duration`
/// shape only after this policy has passed validation.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct NostrTimingPolicyConfig {
    /// Maximum owner-selected time for a relay TCP/TLS/WebSocket handshake.
    pub connect_timeout_ms: u64,
    pub reconnect_initial_ms: u64,
    pub reconnect_max_ms: u64,
    pub reconnect_max_attempts: u32,
    pub jitter_percent: u64,
    pub fallback_poll_ms: u64,
    pub fallback_activation_grace_ms: u64,
    pub session_close_timeout_ms: u64,
    pub announcer_cancel_quantum_ms: u64,
}

impl Default for NostrTimingPolicyConfig {
    fn default() -> Self {
        Self {
            connect_timeout_ms: 30_000,
            reconnect_initial_ms: 2_000,
            reconnect_max_ms: 60_000,
            reconnect_max_attempts: 6,
            jitter_percent: 15,
            fallback_poll_ms: 3_000,
            fallback_activation_grace_ms: 20_000,
            session_close_timeout_ms: 1_000,
            announcer_cancel_quantum_ms: 1_000,
        }
    }
}

impl NostrTimingPolicyConfig {
    pub fn validate(&self) -> bool {
        self.connect_timeout_ms > 0
            && self.reconnect_initial_ms > 0
            && self.reconnect_max_ms >= self.reconnect_initial_ms
            && self.reconnect_max_attempts > 0
            && self.jitter_percent <= 100
            && self.fallback_poll_ms > 0
            && self.fallback_activation_grace_ms >= self.fallback_poll_ms
            && self.session_close_timeout_ms > 0
            && self.announcer_cancel_quantum_ms > 0
    }
}

/// Default number of signaling relays to maintain concurrent
/// connections to. Five is the proven sweet spot from MyOwnLLM:
/// fewer means a single relay's outage can stall handshake; more
/// adds per-peer announce bandwidth without improving recovery time.
pub const DEFAULT_SIGNALING_REDUNDANCY: u32 = 5;

/// Hostnames excluded from the default relay shuffle. Known to
/// rate-limit or stall our REQs in field testing.
pub fn default_signaling_denylist() -> Vec<String> {
    vec!["relay.damus.io".to_string(), "chorus.pjv.me".to_string()]
}

/// Local configuration shape matched to the canonical verified bootstrap.
/// Runtime authority remains in the semantic fact graph; this enum only
/// selects the initial config shape presented to that authority.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    #[default]
    Open,
    Closed,
    Silent,
}

/// Explicit limits for solicited introductions and demand-owned direct links.
/// These are workload/lifetime limits, never provider grants or peer authority.
/// Active introductions, reverse breadcrumbs and replay tombstones share one
/// record pool. Existing connection waiters and signaling queues keep their
/// existing owners; this policy does not create parallel registries.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct HubIntroductionPolicyConfig {
    pub max_records: u64,
    pub max_waiters_per_target: u64,
    /// Cumulative complete signaling bytes admitted/forwarded per attempt.
    /// This is not a retained-buffer size or an RSS/storage estimate.
    pub max_signaling_bytes: u64,
    pub max_candidates_per_attempt: u64,
    pub attempt_timeout_ms: u64,
    pub terminal_retention_ms: u64,
    pub max_transient_links: u64,
    pub idle_timeout_ms: u64,
    pub max_maintenance_per_tick: u64,
}

impl HubIntroductionPolicyConfig {
    /// Check the same explicit inputs subsequently consumed by runtime owners.
    /// A successful check does not reserve resources; actual entry/work claims
    /// still require provider admission before retention or native work.
    pub fn checked(self) -> Result<Self> {
        for (field, value) in [
            ("max_records", self.max_records),
            ("max_waiters_per_target", self.max_waiters_per_target),
            (
                "max_candidates_per_attempt",
                self.max_candidates_per_attempt,
            ),
            ("max_transient_links", self.max_transient_links),
            ("max_maintenance_per_tick", self.max_maintenance_per_tick),
        ] {
            checked_application_count(value, field)?;
        }
        if self.max_signaling_bytes == 0 {
            return Err(Error::Config(
                "introduction signaling budget must be nonzero".into(),
            ));
        }
        self.max_records
            .checked_mul(self.max_waiters_per_target)
            .and_then(|value| usize::try_from(value).ok())
            .filter(|value| *value <= isize::MAX as usize)
            .ok_or_else(|| Error::Config("introduction waiter workload overflows".into()))?;
        self.max_records
            .checked_mul(self.max_candidates_per_attempt)
            .ok_or_else(|| Error::Config("introduction candidate workload overflows".into()))?;
        self.max_records
            .checked_mul(self.max_signaling_bytes)
            .ok_or_else(|| Error::Config("introduction signaling workload overflows".into()))?;
        for (field, value) in [
            ("attempt_timeout_ms", self.attempt_timeout_ms),
            ("terminal_retention_ms", self.terminal_retention_ms),
            ("idle_timeout_ms", self.idle_timeout_ms),
        ] {
            checked_application_duration(value, field)?;
        }
        self.attempt_timeout_ms
            .checked_add(self.terminal_retention_ms)
            .filter(|value| *value <= i64::MAX as u64)
            .ok_or_else(|| Error::Config("introduction terminal deadline overflows".into()))?;
        Ok(self)
    }

    /// Plan the introduction controller and its shared bounded record pool.
    /// The implementation supplies raw intrinsic claims for its actual layout.
    /// Each acquisition has its own provider reservation charge; the existing
    /// application scope is not charged again here. This plan is not itself a
    /// lease to acquire in addition to the individual runtime reservations.
    pub fn planned_records_claim(
        self,
        root: ResourceClaim,
        entry: ResourceClaim,
    ) -> Result<ResourceClaim> {
        self.checked()?;
        planned_application_reservations(root, entry, self.max_records)
    }

    /// Plan the separately owned demand-link pool using its actual raw root
    /// and entry shapes. Native connector work and existing waiter/queue
    /// leases remain separately admitted by their existing owners.
    pub fn planned_demand_links_claim(
        self,
        root: ResourceClaim,
        entry: ResourceClaim,
    ) -> Result<ResourceClaim> {
        self.checked()?;
        planned_application_reservations(root, entry, self.max_transient_links)
    }
}

fn application_reservation_claim(raw: ResourceClaim) -> Result<ResourceClaim> {
    crate::resource::FiniteResourceProvider::reservation_planning_charge(raw)
        .map_err(|_| Error::Config("application transport reservation plan overflows".into()))
}

fn planned_application_reservations(
    root: ResourceClaim,
    entry: ResourceClaim,
    count: u64,
) -> Result<ResourceClaim> {
    let root = application_reservation_claim(root)?;
    let entries = application_reservation_claim(entry)?
        .checked_scale(count)
        .map_err(|_| Error::Config("application transport record plan overflows".into()))?;
    root.checked_add(entries)
        .map_err(|_| Error::Config("application transport root plan overflows".into()))
}

fn checked_application_count(value: u64, field: &str) -> Result<usize> {
    usize::try_from(value)
        .ok()
        .filter(|value| *value > 0 && *value <= isize::MAX as usize)
        .ok_or_else(|| {
            Error::Config(format!(
                "application transport {field} is not representable"
            ))
        })
}

fn checked_application_duration(value: u64, field: &str) -> Result<Duration> {
    if value == 0 || value > i64::MAX as u64 {
        return Err(Error::Config(format!(
            "application transport {field} is invalid"
        )));
    }
    let duration = Duration::from_millis(value);
    std::time::Instant::now()
        .checked_add(duration)
        .ok_or_else(|| {
            Error::Config(format!("application transport {field} deadline overflows"))
        })?;
    Ok(duration)
}

/// Owner-selected policy for the engine's time-based safety net.
///
/// These values are persisted with the network rather than kept as process
/// constants: two networks in one mesh may have different latency and power
/// envelopes.  The fixed-size schedules are deliberate; accepting an
/// arbitrary list here would make the scheduler's work itself unbounded.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default)]
pub struct SchedulerPolicyConfig {
    pub reactive_announce_min_interval_ms: u64,
    pub reoffer_min_interval_ms: u64,
    /// Owner-selected inbound silence horizon before a peer is treated as a
    /// liveness/rebuild candidate. This is not an authority decision.
    pub stale_inbound_timeout_ms: u64,
    pub probe_ttl_ms: u64,
    pub probe_resolve_timeout_ms: u64,
    pub skew_warn_ms: u64,
    pub skew_clear_ms: u64,
    pub skew_warn_ticks: u8,
    pub handshake_timeout_ms: u64,
    pub handshake_hello_retry_schedule_ms: [u64; 3],
    pub heartbeat_interval_ms: u64,
    pub heartbeat_timeout_ms: u64,
    pub wake_coalesce_ms: u64,
    pub wake_probe_delay_ms: u64,
    pub liveness_probe_min_interval_ms: u64,
    pub ice_disconnected_restart_ms: u64,
    pub state_watch_interval_ms: u64,
    pub reconnect_retry_backoff_ms: [u64; 4],
    pub data_channel_open_timeout_ms: u64,
    pub offer_build_timeout_ms: u64,
    pub ice_introspect_timeout_ms: u64,
    pub peer_send_timeout_ms: u64,
    pub restart_traffic_grace_ms: u64,
    pub relay_rescue_min_interval_ms: u64,
    pub network_change_restart_cooldown_ms: u64,
    pub reconnecting_grace_ms: u64,
}

impl Default for SchedulerPolicyConfig {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl SchedulerPolicyConfig {
    pub const DEFAULT: Self = Self {
        reactive_announce_min_interval_ms: 1_000,
        reoffer_min_interval_ms: 2_000,
        stale_inbound_timeout_ms: 25_000,
        probe_ttl_ms: 300_000,
        probe_resolve_timeout_ms: 2_000,
        skew_warn_ms: 10_000,
        skew_clear_ms: 5_000,
        skew_warn_ticks: 3,
        handshake_timeout_ms: 30_000,
        handshake_hello_retry_schedule_ms: [5_000, 7_000, 10_000],
        heartbeat_interval_ms: 30_000,
        heartbeat_timeout_ms: 30_000,
        wake_coalesce_ms: 2_000,
        wake_probe_delay_ms: 1_500,
        liveness_probe_min_interval_ms: 5_000,
        ice_disconnected_restart_ms: 1_000,
        state_watch_interval_ms: 2_000,
        reconnect_retry_backoff_ms: [2_000, 4_000, 8_000, 15_000],
        data_channel_open_timeout_ms: 30_000,
        offer_build_timeout_ms: 10_000,
        ice_introspect_timeout_ms: 1_000,
        peer_send_timeout_ms: 2_000,
        restart_traffic_grace_ms: 10_000,
        relay_rescue_min_interval_ms: 30_000,
        network_change_restart_cooldown_ms: 5_000,
        reconnecting_grace_ms: 90_000,
    };

    /// Validate before any engine, task, or transport side effect.
    pub fn validate(&self) -> bool {
        let nonzero = [
            self.reactive_announce_min_interval_ms,
            self.reoffer_min_interval_ms,
            self.stale_inbound_timeout_ms,
            self.probe_ttl_ms,
            self.probe_resolve_timeout_ms,
            self.skew_warn_ms,
            self.skew_clear_ms,
            self.handshake_timeout_ms,
            self.heartbeat_interval_ms,
            self.heartbeat_timeout_ms,
            self.wake_coalesce_ms,
            self.wake_probe_delay_ms,
            self.liveness_probe_min_interval_ms,
            self.ice_disconnected_restart_ms,
            self.state_watch_interval_ms,
            self.data_channel_open_timeout_ms,
            self.offer_build_timeout_ms,
            self.ice_introspect_timeout_ms,
            self.peer_send_timeout_ms,
            self.restart_traffic_grace_ms,
            self.relay_rescue_min_interval_ms,
            self.network_change_restart_cooldown_ms,
            self.reconnecting_grace_ms,
        ]
        .into_iter()
        .all(|value| value > 0);
        let retries_are_ordered = self
            .handshake_hello_retry_schedule_ms
            .windows(2)
            .all(|window| window[0] > 0 && window[0] < window[1])
            && self
                .reconnect_retry_backoff_ms
                .windows(2)
                .all(|window| window[0] > 0 && window[0] < window[1]);
        nonzero
            && retries_are_ordered
            && self.heartbeat_interval_ms.checked_mul(2).is_some()
            && self
                .heartbeat_timeout_ms
                .checked_add(self.heartbeat_interval_ms.checked_mul(2).unwrap_or(0))
                .is_some()
            && self.wake_probe_delay_ms <= self.state_watch_interval_ms
            && self.skew_clear_ms < self.skew_warn_ms
            && self.skew_warn_ms <= i64::MAX as u64
            && self.skew_clear_ms <= i64::MAX as u64
            && self.skew_warn_ticks > 0
            && self.restart_traffic_grace_ms <= self.data_channel_open_timeout_ms
            && self.relay_rescue_min_interval_ms >= self.data_channel_open_timeout_ms
    }

    pub(crate) fn checked(self) -> Result<Self> {
        if self.validate() {
            Ok(self)
        } else {
            Err(Error::Config(
                "scheduler policy contains zero, overflow, or inconsistent values".into(),
            ))
        }
    }
}

/// Owner-selected bounds for the durable semantic fact graph.
///
/// These values are persisted per network so admission and recovery use the
/// same resource envelope after a restart. They are allocation and retention
/// limits, not authority: canonical facts still decide membership and roles.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct SemanticPolicyConfig {
    pub max_fact_encoded_bytes: u64,
    pub max_dependencies_per_fact: u64,
    pub max_authority_uses_per_fact: u64,
    pub max_authority_predecessors_per_use: u64,
    pub max_admitted_facts: u64,
    pub max_admitted_bytes: u64,
    pub max_quarantined_facts: u64,
    pub max_quarantined_bytes: u64,
    pub max_quarantined_facts_per_author: u64,
    pub max_quarantined_bytes_per_author: u64,
    pub max_retained_facts_per_author: u64,
    pub max_retained_bytes_per_author: u64,
    /// Maximum recently admitted bodies kept beside SQLite before one
    /// deterministic cold-history retirement pass. This is an explicit
    /// memory/CPU tradeoff selected by the owner, not a library constant.
    pub max_hot_history_facts: u64,
    pub max_dependency_edges: u64,
    pub max_ready_batch: u64,
    pub max_pending_proofs: u64,
    pub max_pending_proof_bytes: u64,
    pub max_proof_records: u64,
    pub max_proof_bytes: u64,
    pub max_proof_links: u64,
    pub max_author_usage_rows: u64,
    pub max_provisional_rows: u64,
    pub max_transaction_dirty_main_pages: u64,
    pub max_uncheckpointed_wal_frames: u64,
    pub max_freelist_pages: u64,
    pub max_fragmented_pages: u64,
    pub max_main_journal_bytes: u64,
    /// Maximum encoded clean-start checkpoint stored beside canonical rows.
    /// Owners choose this separately because it trades startup latency for
    /// durable storage; it is never inferred from a typical mesh size.
    pub max_live_checkpoint_bytes: u64,
    pub max_database_bytes: u64,
    pub max_wal_bytes: u64,
    pub wal_checkpoint_threshold_bytes: u64,
    pub emergency_reserve_bytes: u64,
}

/// SQLite's default page size used when validating a persisted policy before
/// a store connection exists.  A store may pass its actual page size to the
/// checked envelope helpers below.
pub const SQLITE_DEFAULT_PAGE_SIZE_BYTES: u64 = 4096;
const SQLITE_WAL_HEADER_BYTES: u64 = 32;
const SQLITE_WAL_FRAME_OVERHEAD_BYTES: u64 = 24;
const SQLITE_SHM_CHUNK_BYTES: u64 = 32_768;
const SQLITE_SHM_FIRST_CHUNK_FRAMES: u64 = 4_062;
const SQLITE_SHM_FOLLOWING_CHUNK_FRAMES: u64 = 4_096;

/// The only production provisional-custody owner is the fixed semantic
/// ingress label.  Keep its UTF-8 byte bound independent of fact payloads.
pub(crate) const SEMANTIC_INGRESS_OWNER: &str = "semantic-ingress";
pub(crate) const SEMANTIC_INGRESS_OWNER_MAX_BYTES: u64 = SEMANTIC_INGRESS_OWNER.len() as u64;

/// Canonical semantic schema metadata. Store creation, the capacity planner,
/// and test-only fault-injection controls consume this exact table/index
/// spelling; a duplicated hand-written schema description is a drift defect.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SemanticSchemaTableDescriptor {
    pub(crate) name: &'static str,
    pub(crate) columns: &'static [&'static str],
}

pub(crate) const SEMANTIC_SCHEMA_TABLES: &[SemanticSchemaTableDescriptor] = &[
    SemanticSchemaTableDescriptor {
        name: "meta",
        columns: &["key", "value"],
    },
    SemanticSchemaTableDescriptor {
        name: "facts",
        columns: &["fact_id", "encoded", "status", "author", "domain", "seq"],
    },
    SemanticSchemaTableDescriptor {
        name: "semantic_usage",
        columns: &[
            "usage_id",
            "admitted_count",
            "admitted_bytes",
            "quarantined_count",
            "quarantined_bytes",
            "dependency_edges",
            "provisional_count",
            "author_usage_rows",
            "generation",
        ],
    },
    SemanticSchemaTableDescriptor {
        name: "author_usage",
        columns: &[
            "author",
            "retained_count",
            "retained_bytes",
            "quarantined_count",
            "quarantined_bytes",
        ],
    },
    SemanticSchemaTableDescriptor {
        name: "dependencies",
        columns: &["fact_id", "dep_id"],
    },
    SemanticSchemaTableDescriptor {
        name: "provisional",
        columns: &["fact_id", "owner"],
    },
    SemanticSchemaTableDescriptor {
        name: "proofs",
        columns: &["delivery_id", "encoded", "context_id", "target", "state"],
    },
    SemanticSchemaTableDescriptor {
        name: "proof_facts",
        columns: &["delivery_id", "fact_id"],
    },
    SemanticSchemaTableDescriptor {
        name: "commitments",
        columns: &["name", "value"],
    },
    SemanticSchemaTableDescriptor {
        name: "proof_usage",
        columns: &[
            "usage_id",
            "total_count",
            "total_bytes",
            "total_links",
            "pending_count",
            "pending_bytes",
            "generation",
        ],
    },
];

pub(crate) const SEMANTIC_SCHEMA_INDEXES: &[(&str, &str, &[&str])] = &[
    ("facts_seq_idx", "facts", &["seq"]),
    ("dependencies_dep_idx", "dependencies", &["dep_id"]),
    (
        "proofs_pending_idx",
        "proofs",
        &["context_id", "state", "delivery_id"],
    ),
];

// Every usage value is persisted as one fixed-width eight-byte BLOB.  Keep
// these counts adjacent to the canonical descriptors so the page planner
// cannot silently price a stale column shape.
pub(crate) const SEMANTIC_USAGE_COLUMN_COUNT: u64 = 9;
pub(crate) const PROOF_USAGE_COLUMN_COUNT: u64 = 7;

/// Exact semantic workload maxima consumed by the production storage planner.
/// These are owner-selected persisted bounds, not estimates inferred from a
/// current database.  Omitting a lifecycle dimension is therefore impossible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticStorageWorkload {
    pub max_fact_encoded_bytes: u64,
    pub max_admitted_facts: u64,
    pub max_quarantined_facts: u64,
    pub max_admitted_bytes: u64,
    pub max_quarantined_bytes: u64,
    pub max_dependency_edges: u64,
    pub max_author_usage_rows: u64,
    pub max_proof_records: u64,
    pub max_proof_bytes: u64,
    pub max_proof_links: u64,
    pub max_provisional_rows: u64,
    pub max_transaction_dirty_main_pages: u64,
    pub max_uncheckpointed_wal_frames: u64,
    pub max_freelist_pages: u64,
    pub max_fragmented_pages: u64,
    pub max_main_journal_bytes: u64,
    pub max_live_checkpoint_bytes: u64,
}

/// Checked logical named-file/process-local reservation for one semantic
/// SQLite database.  This is not a backed-capacity or ENOSPC guarantee.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticStorageEnvelope {
    pub page_size_bytes: u64,
    pub main_pages: u64,
    pub main_bytes: u64,
    pub main_journal_bytes: u64,
    /// Hard WAL frame capacity, including one transaction's dirty pages.
    /// This legacy field remains the hard-cap alias used by store consumers.
    pub wal_frames: u64,
    /// Hard WAL byte capacity, including one transaction's dirty pages.
    /// This legacy field remains the hard-cap alias used by store consumers.
    pub wal_bytes: u64,
    /// Retained WAL population at which checkpointing is required.
    pub wal_checkpoint_frames: u64,
    /// Byte size of the retained/checkpoint WAL population.
    pub wal_checkpoint_bytes: u64,
    /// Hard WAL frame capacity after adding the transaction growth bound.
    pub wal_hard_frames: u64,
    /// Hard WAL byte capacity after adding the transaction growth bound.
    pub wal_hard_bytes: u64,
    pub shm_bytes: u64,
    pub emergency_reserve_bytes: u64,
    pub total_bytes: u64,
}

// Test/lab fixtures need a finite envelope to exercise refusal boundaries.
// Production has deliberately no semantic resource default: the network
// owner must state the complete persisted policy.
#[cfg(any(test, feature = "transport-lab"))]
impl Default for SemanticPolicyConfig {
    fn default() -> Self {
        Self {
            max_fact_encoded_bytes: 65_535,
            max_dependencies_per_fact: 64,
            max_authority_uses_per_fact: 32,
            max_authority_predecessors_per_use: 64,
            max_admitted_facts: 100_000,
            max_admitted_bytes: 128 * 1024 * 1024,
            max_quarantined_facts: 4_096,
            max_quarantined_bytes: 16 * 1024 * 1024,
            max_quarantined_facts_per_author: 256,
            max_quarantined_bytes_per_author: 4 * 1024 * 1024,
            max_retained_facts_per_author: 10_000,
            max_retained_bytes_per_author: 16 * 1024 * 1024,
            max_hot_history_facts: 64,
            max_dependency_edges: 1_000_000,
            max_ready_batch: 256,
            max_pending_proofs: 10_000,
            max_pending_proof_bytes: 16 * 1024 * 1024,
            max_proof_records: 100_000,
            max_proof_bytes: 64 * 1024 * 1024,
            max_proof_links: 100_000,
            max_author_usage_rows: 100_000,
            max_provisional_rows: 100_000,
            max_transaction_dirty_main_pages: 1024,
            max_uncheckpointed_wal_frames: 1_018,
            max_freelist_pages: 1024,
            max_fragmented_pages: 1024,
            max_main_journal_bytes: 8 * 1024 * 1024,
            max_live_checkpoint_bytes: 8 * 1024 * 1024,
            // The default semantic maxima include 128 MiB of facts, 1M
            // canonical edges, and 64 MiB of proofs.  The checked page
            // arithmetic below deliberately charges both packed leaves and
            // a worst-case overflow stream, so 2 GiB is the first finite
            // default that can contain those owner-selected maxima.
            max_database_bytes: 2 * 1024 * 1024 * 1024,
            // 1,018 retained frames plus 1,024 pages changed by one
            // transaction, with the 32-byte WAL header charged once.
            max_wal_bytes: 8_413_072,
            wal_checkpoint_threshold_bytes: SQLITE_WAL_HEADER_BYTES
                + 1_018 * (SQLITE_DEFAULT_PAGE_SIZE_BYTES + SQLITE_WAL_FRAME_OVERHEAD_BYTES),
            emergency_reserve_bytes: 8 * 1024 * 1024,
        }
    }
}

impl SemanticPolicyConfig {
    fn checked_shm_bytes(wal_frame_count: u64) -> Option<u64> {
        if wal_frame_count == 0 {
            return Some(0);
        }
        let chunks = if wal_frame_count <= SQLITE_SHM_FIRST_CHUNK_FRAMES {
            1
        } else {
            let remaining = wal_frame_count - SQLITE_SHM_FIRST_CHUNK_FRAMES;
            remaining
                .checked_add(SQLITE_SHM_FOLLOWING_CHUNK_FRAMES - 1)?
                .checked_div(SQLITE_SHM_FOLLOWING_CHUNK_FRAMES)?
                .checked_add(1)?
        };
        SQLITE_SHM_CHUNK_BYTES.checked_mul(chunks)
    }

    pub fn storage_workload(&self) -> SemanticStorageWorkload {
        SemanticStorageWorkload {
            max_fact_encoded_bytes: self.max_fact_encoded_bytes,
            max_admitted_facts: self.max_admitted_facts,
            max_quarantined_facts: self.max_quarantined_facts,
            max_admitted_bytes: self.max_admitted_bytes,
            max_quarantined_bytes: self.max_quarantined_bytes,
            max_dependency_edges: self.max_dependency_edges,
            max_author_usage_rows: self.max_author_usage_rows,
            max_proof_records: self.max_proof_records,
            max_proof_bytes: self.max_proof_bytes,
            max_proof_links: self.max_proof_links,
            max_provisional_rows: self.max_provisional_rows,
            max_transaction_dirty_main_pages: self.max_transaction_dirty_main_pages,
            max_uncheckpointed_wal_frames: self.max_uncheckpointed_wal_frames,
            max_freelist_pages: self.max_freelist_pages,
            max_fragmented_pages: self.max_fragmented_pages,
            max_main_journal_bytes: self.max_main_journal_bytes,
            max_live_checkpoint_bytes: self.max_live_checkpoint_bytes,
        }
    }

    fn checked_schema_pages(
        page_size_bytes: u64,
        workload: SemanticStorageWorkload,
    ) -> Option<u64> {
        const PAGE_HEADER_BYTES: u64 = 8;
        const CELL_POINTER_BYTES: u64 = 2;
        const RECORD_HEADER_BYTES: u64 = 13;
        const FACT_ID_BYTES: u64 = 32;
        const DEVICE_KEY_BYTES: u64 = 32;
        const SQL_INTEGER_BYTES: u64 = 8;
        const FACT_STATUS_MAX_BYTES: u64 = 11;
        const FACT_DOMAIN_MAX_BYTES: u64 = 16;
        const PROOF_STATE_MAX_BYTES: u64 = 12;
        const META_KEY_MAX_BYTES: u64 = 18;
        const COMMITMENT_NAME_MAX_BYTES: u64 = 10;
        let usable = page_size_bytes.checked_sub(PAGE_HEADER_BYTES)?;
        let leaf_capacity = usable.checked_sub(CELL_POINTER_BYTES)?.max(1);
        let interior_capacity = (usable / 16).max(2);
        let checked_sum = |values: &[u64]| -> Option<u64> {
            values
                .iter()
                .try_fold(0u64, |total, value| total.checked_add(*value))
        };
        let checked_rows =
            |rows: u64, bytes_per_row: u64| -> Option<u64> { rows.checked_mul(bytes_per_row) };
        let object_pages = |rows: u64, payload_bytes: u64| -> Option<u64> {
            let record = payload_bytes
                .checked_add(rows.checked_mul(RECORD_HEADER_BYTES)?)?
                .checked_add(rows.checked_mul(CELL_POINTER_BYTES)?)?;
            let overflow_payload = usable.checked_sub(4)?.max(1);
            let overflow = payload_bytes
                .checked_add(overflow_payload - 1)?
                .checked_div(overflow_payload)?;
            let leaves = record
                .checked_add(leaf_capacity - 1)?
                .checked_div(leaf_capacity)?
                .max(1);
            let interior = leaves
                .saturating_sub(1)
                .checked_add(interior_capacity - 1)?
                .checked_div(interior_capacity)?;
            leaves
                .checked_add(interior)?
                .checked_add(overflow)?
                .checked_add(1)
        };
        let fact_rows = workload
            .max_admitted_facts
            .checked_add(workload.max_quarantined_facts)?;
        let fact_payload = workload
            .max_admitted_bytes
            .checked_add(workload.max_quarantined_bytes)?
            .checked_add(checked_rows(
                fact_rows,
                checked_sum(&[
                    FACT_ID_BYTES,
                    FACT_STATUS_MAX_BYTES,
                    DEVICE_KEY_BYTES,
                    FACT_DOMAIN_MAX_BYTES,
                    SQL_INTEGER_BYTES,
                ])?,
            )?)?;
        let table_pages = [
            (
                4,
                checked_sum(&[
                    checked_sum(&[META_KEY_MAX_BYTES, SQL_INTEGER_BYTES])?,
                    checked_sum(&[10, FACT_ID_BYTES])?,
                    checked_sum(&[13, 12])?,
                    workload.max_live_checkpoint_bytes,
                ])?,
            ),
            (fact_rows, fact_payload),
            (
                1,
                checked_rows(
                    1,
                    SEMANTIC_USAGE_COLUMN_COUNT.checked_mul(SQL_INTEGER_BYTES)?,
                )?,
            ),
            (
                workload.max_author_usage_rows,
                checked_rows(
                    workload.max_author_usage_rows,
                    DEVICE_KEY_BYTES + 4 * SQL_INTEGER_BYTES,
                )?,
            ),
            (
                workload.max_dependency_edges,
                checked_rows(workload.max_dependency_edges, 2 * FACT_ID_BYTES)?,
            ),
            (
                workload.max_provisional_rows,
                checked_rows(
                    workload.max_provisional_rows,
                    checked_sum(&[FACT_ID_BYTES, SEMANTIC_INGRESS_OWNER_MAX_BYTES])?,
                )?,
            ),
            (
                workload.max_proof_records,
                workload.max_proof_bytes.checked_add(checked_rows(
                    workload.max_proof_records,
                    FACT_ID_BYTES * 3 + PROOF_STATE_MAX_BYTES,
                )?)?,
            ),
            (
                workload.max_proof_links,
                checked_rows(workload.max_proof_links, 2 * FACT_ID_BYTES)?,
            ),
            (1, checked_sum(&[COMMITMENT_NAME_MAX_BYTES, FACT_ID_BYTES])?),
            (
                1,
                checked_rows(1, PROOF_USAGE_COLUMN_COUNT.checked_mul(SQL_INTEGER_BYTES)?)?,
            ),
        ];
        debug_assert_eq!(table_pages.len(), SEMANTIC_SCHEMA_TABLES.len());
        let mut pages = 1u64; // page-one database header and schema root.
        for (rows, record_bytes) in table_pages {
            pages = pages.checked_add(object_pages(rows, record_bytes)?)?;
        }
        // Only rowid tables with non-integer primary keys own a second
        // autoindex b-tree. The small composite/key-only tables are declared
        // WITHOUT ROWID and their primary keys are already the table b-tree;
        // charging those again would reserve storage that SQLite cannot use.
        // The three named secondary indexes remain separate objects. Separate roots,
        // interior rounding, and overflow streams are all retained in the
        // envelope rather than being hidden by a combined row count.
        let primary_index_trees = [
            (4, META_KEY_MAX_BYTES),
            (fact_rows, FACT_ID_BYTES),
            (workload.max_proof_records, FACT_ID_BYTES),
        ];
        debug_assert_eq!(primary_index_trees.len(), 3);
        for (rows, key_bytes) in primary_index_trees {
            let payload = checked_rows(rows, key_bytes)?;
            pages = pages.checked_add(object_pages(rows, payload)?)?;
        }
        let secondary_index_trees = [
            (fact_rows, SQL_INTEGER_BYTES),
            (workload.max_dependency_edges, FACT_ID_BYTES),
            (workload.max_proof_records, checked_sum(&[32, 12, 32])?),
        ];
        debug_assert_eq!(secondary_index_trees.len(), SEMANTIC_SCHEMA_INDEXES.len());
        for (rows, key_bytes) in secondary_index_trees {
            let payload = checked_rows(rows, key_bytes)?;
            pages = pages.checked_add(object_pages(rows, payload)?)?;
        }
        pages = pages
            .checked_add(workload.max_transaction_dirty_main_pages)?
            .checked_add(workload.max_freelist_pages)?
            .checked_add(workload.max_fragmented_pages)?;
        Some(pages)
    }

    /// Compute a checked envelope from exact owner-selected semantic and
    /// SQLite lifecycle maxima.  Every component is independently charged;
    /// the emergency reserve is never added to the main budget.
    pub fn checked_storage_envelope(
        &self,
        page_size_bytes: u64,
        workload: SemanticStorageWorkload,
    ) -> Result<SemanticStorageEnvelope> {
        if page_size_bytes == 0 {
            return Err(Error::Config("SQLite page size must be nonzero".into()));
        }
        let values = [
            workload.max_fact_encoded_bytes,
            workload.max_admitted_facts,
            workload.max_quarantined_facts,
            workload.max_admitted_bytes,
            workload.max_quarantined_bytes,
            workload.max_dependency_edges,
            workload.max_author_usage_rows,
            workload.max_proof_records,
            workload.max_proof_bytes,
            workload.max_proof_links,
            workload.max_provisional_rows,
            workload.max_transaction_dirty_main_pages,
            workload.max_uncheckpointed_wal_frames,
            workload.max_freelist_pages,
            workload.max_fragmented_pages,
            workload.max_main_journal_bytes,
            workload.max_live_checkpoint_bytes,
        ];
        if values.contains(&0)
            || workload.max_fact_encoded_bytes > self.max_fact_encoded_bytes
            || workload.max_admitted_facts > self.max_admitted_facts
            || workload.max_quarantined_facts > self.max_quarantined_facts
            || workload.max_admitted_bytes > self.max_admitted_bytes
            || workload.max_quarantined_bytes > self.max_quarantined_bytes
            || workload.max_dependency_edges > self.max_dependency_edges
            || workload.max_author_usage_rows > self.max_author_usage_rows
            || workload.max_proof_records > self.max_proof_records
            || workload.max_proof_bytes > self.max_proof_bytes
            || workload.max_proof_links > self.max_proof_links
            || workload.max_provisional_rows > self.max_provisional_rows
            || workload.max_transaction_dirty_main_pages > self.max_transaction_dirty_main_pages
            || workload.max_uncheckpointed_wal_frames > self.max_uncheckpointed_wal_frames
            || workload.max_freelist_pages > self.max_freelist_pages
            || workload.max_fragmented_pages > self.max_fragmented_pages
            || workload.max_main_journal_bytes > self.max_main_journal_bytes
            || workload.max_live_checkpoint_bytes > self.max_live_checkpoint_bytes
        {
            return Err(Error::Config(
                "semantic storage workload exceeds policy".into(),
            ));
        }
        let frame_bytes = page_size_bytes
            .checked_add(SQLITE_WAL_FRAME_OVERHEAD_BYTES)
            .ok_or_else(|| Error::Config("SQLite WAL frame size overflow".into()))?;
        let wal_checkpoint_frames = workload.max_uncheckpointed_wal_frames;
        let wal_hard_frames = wal_checkpoint_frames
            .checked_add(workload.max_transaction_dirty_main_pages)
            .ok_or_else(|| Error::Config("SQLite WAL frame capacity overflow".into()))?;
        let wal_checkpoint_bytes = SQLITE_WAL_HEADER_BYTES
            .checked_add(
                wal_checkpoint_frames
                    .checked_mul(frame_bytes)
                    .ok_or_else(|| Error::Config("SQLite WAL reservation overflow".into()))?,
            )
            .ok_or_else(|| Error::Config("SQLite WAL reservation overflow".into()))?;
        let wal_hard_bytes = SQLITE_WAL_HEADER_BYTES
            .checked_add(
                wal_hard_frames
                    .checked_mul(frame_bytes)
                    .ok_or_else(|| Error::Config("SQLite WAL hard-cap overflow".into()))?,
            )
            .ok_or_else(|| Error::Config("SQLite WAL hard-cap overflow".into()))?;
        let threshold_payload = self
            .wal_checkpoint_threshold_bytes
            .checked_sub(SQLITE_WAL_HEADER_BYTES)
            .ok_or_else(|| Error::Config("WAL checkpoint threshold is below its header".into()))?;
        if threshold_payload % frame_bytes != 0
            || threshold_payload / frame_bytes != wal_checkpoint_frames
        {
            return Err(Error::Config(
                "WAL checkpoint threshold is not aligned to retained WAL frames".into(),
            ));
        }
        if wal_hard_bytes < wal_checkpoint_bytes
            || wal_checkpoint_bytes.checked_add(
                workload
                    .max_transaction_dirty_main_pages
                    .checked_mul(frame_bytes)
                    .ok_or_else(|| Error::Config("SQLite WAL growth overflow".into()))?,
            ) != Some(wal_hard_bytes)
            || wal_hard_bytes > self.max_wal_bytes
        {
            return Err(Error::Config(
                "WAL retained trigger plus transaction growth exceeds hard ceiling".into(),
            ));
        }
        let shm_bytes = Self::checked_shm_bytes(wal_hard_frames)
            .ok_or_else(|| Error::Config("SQLite SHM reservation overflow".into()))?;
        let main_pages = Self::checked_schema_pages(page_size_bytes, workload)
            .ok_or_else(|| Error::Config("SQLite main page arithmetic overflow".into()))?;
        let main_bytes = main_pages
            .checked_mul(page_size_bytes)
            .ok_or_else(|| Error::Config("SQLite main byte arithmetic overflow".into()))?;
        let total_bytes = main_bytes
            .checked_add(workload.max_main_journal_bytes)
            .and_then(|bytes| bytes.checked_add(wal_hard_bytes))
            .and_then(|bytes| bytes.checked_add(shm_bytes))
            .and_then(|bytes| bytes.checked_add(self.emergency_reserve_bytes))
            .ok_or_else(|| Error::Config("SQLite storage envelope overflow".into()))?;
        if total_bytes > self.max_database_bytes {
            return Err(Error::Config(
                "SQLite storage envelope exceeds policy".into(),
            ));
        }
        Ok(SemanticStorageEnvelope {
            page_size_bytes,
            main_pages,
            main_bytes,
            main_journal_bytes: workload.max_main_journal_bytes,
            wal_frames: wal_hard_frames,
            wal_bytes: wal_hard_bytes,
            wal_checkpoint_frames,
            wal_checkpoint_bytes,
            wal_hard_frames,
            wal_hard_bytes,
            shm_bytes,
            emergency_reserve_bytes: self.emergency_reserve_bytes,
            total_bytes,
        })
    }

    /// Validate all persisted semantic bounds before engine side effects.
    /// Every field is checked for a representable, nonzero allocation; the
    /// remaining checks ensure a single fact and all retained stores fit the
    /// selected database and receive-frame envelopes.
    pub fn validate(&self) -> bool {
        let nonzero = [
            self.max_fact_encoded_bytes,
            self.max_dependencies_per_fact,
            self.max_authority_uses_per_fact,
            self.max_authority_predecessors_per_use,
            self.max_admitted_facts,
            self.max_admitted_bytes,
            self.max_quarantined_facts,
            self.max_quarantined_bytes,
            self.max_quarantined_facts_per_author,
            self.max_quarantined_bytes_per_author,
            self.max_retained_facts_per_author,
            self.max_retained_bytes_per_author,
            self.max_hot_history_facts,
            self.max_dependency_edges,
            self.max_ready_batch,
            self.max_pending_proofs,
            self.max_pending_proof_bytes,
            self.max_proof_records,
            self.max_proof_bytes,
            self.max_proof_links,
            self.max_author_usage_rows,
            self.max_provisional_rows,
            self.max_transaction_dirty_main_pages,
            self.max_uncheckpointed_wal_frames,
            self.max_freelist_pages,
            self.max_fragmented_pages,
            self.max_main_journal_bytes,
            self.max_live_checkpoint_bytes,
            self.max_database_bytes,
            self.max_wal_bytes,
            self.wal_checkpoint_threshold_bytes,
            self.emergency_reserve_bytes,
        ]
        .into_iter()
        .all(|value| value > 0);
        let platform = [
            self.max_fact_encoded_bytes,
            self.max_dependencies_per_fact,
            self.max_authority_uses_per_fact,
            self.max_authority_predecessors_per_use,
            self.max_admitted_facts,
            self.max_admitted_bytes,
            self.max_quarantined_facts,
            self.max_quarantined_bytes,
            self.max_quarantined_facts_per_author,
            self.max_quarantined_bytes_per_author,
            self.max_retained_facts_per_author,
            self.max_retained_bytes_per_author,
            self.max_hot_history_facts,
            self.max_dependency_edges,
            self.max_ready_batch,
            self.max_pending_proofs,
            self.max_pending_proof_bytes,
            self.max_proof_records,
            self.max_proof_bytes,
            self.max_proof_links,
            self.max_author_usage_rows,
            self.max_provisional_rows,
            self.max_transaction_dirty_main_pages,
            self.max_uncheckpointed_wal_frames,
            self.max_freelist_pages,
            self.max_fragmented_pages,
            self.max_main_journal_bytes,
            self.max_live_checkpoint_bytes,
            self.max_database_bytes,
            self.max_wal_bytes,
            self.wal_checkpoint_threshold_bytes,
            self.emergency_reserve_bytes,
        ]
        .into_iter()
        .all(|value| usize::try_from(value).is_ok());
        let receive_bound = u64::try_from(crate::protocol::RECEIVE_FRAME_BYTES)
            .map(|bound| self.max_fact_encoded_bytes <= bound)
            .unwrap_or(false);
        let per_author = self.max_quarantined_facts_per_author <= self.max_quarantined_facts
            && self.max_quarantined_bytes_per_author <= self.max_quarantined_bytes
            && self.max_quarantined_facts_per_author <= self.max_retained_facts_per_author
            && self.max_quarantined_bytes_per_author <= self.max_retained_bytes_per_author;
        let retained_global = self
            .max_admitted_facts
            .checked_add(self.max_quarantined_facts)
            .map(|facts| self.max_retained_facts_per_author <= facts)
            .unwrap_or(false)
            && self
                .max_admitted_bytes
                .checked_add(self.max_quarantined_bytes)
                .map(|bytes| self.max_retained_bytes_per_author <= bytes)
                .unwrap_or(false);
        let structural = self.max_dependencies_per_fact <= self.max_dependency_edges
            && self.max_authority_uses_per_fact <= self.max_dependency_edges
            && self.max_authority_predecessors_per_use <= self.max_dependency_edges
            && self.max_ready_batch <= self.max_pending_proofs
            && self.max_pending_proofs <= self.max_proof_records
            && self.max_pending_proof_bytes <= self.max_proof_bytes
            && self.max_fact_encoded_bytes <= self.max_admitted_bytes
            && self.max_fact_encoded_bytes <= self.max_quarantined_bytes
            && self.max_fact_encoded_bytes <= self.max_pending_proof_bytes
            && self.max_fact_encoded_bytes <= self.max_proof_bytes;
        let storage_relationships = self.wal_checkpoint_threshold_bytes <= self.max_wal_bytes
            && self.max_transaction_dirty_main_pages <= self.max_database_bytes
            && self.max_main_journal_bytes <= self.max_database_bytes
            && self.max_live_checkpoint_bytes <= self.max_database_bytes
            && self.max_freelist_pages <= self.max_database_bytes / SQLITE_DEFAULT_PAGE_SIZE_BYTES
            && self.max_fragmented_pages
                <= self.max_database_bytes / SQLITE_DEFAULT_PAGE_SIZE_BYTES;
        nonzero
            && platform
            && receive_bound
            && per_author
            && retained_global
            && structural
            && storage_relationships
            && self
                .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, self.storage_workload())
                .is_ok()
    }

    pub(crate) fn checked(self) -> Result<Self> {
        if self.validate() {
            Ok(self)
        } else {
            Err(Error::Config(
                "semantic policy contains zero, overflow, receive-bound, or inconsistent values"
                    .into(),
            ))
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct NetworkConfig {
    /// Local config record id. User-chosen, unique within this
    /// device's config — distinguishes multiple saved entries for
    /// the same wire-level network (different STUN/TURN setups for
    /// the same fleet, etc.).
    pub id: String,
    /// Wire-level rendezvous handle. Normalised via
    /// [`crate::identity::normalize_network_id`] on load.
    pub network_id: String,
    /// Finite history retained by this network's MeshEvent broadcaster.
    /// The owner chooses it per network; no process-wide fallback is inferred
    /// once a network policy exists.
    #[serde(default = "default_network_event_capacity")]
    pub event_capacity: u64,
    /// Finite history retained by this network's connection-state tracer.
    /// Kept separate so trace volume cannot evict user-visible events.
    #[serde(default = "default_network_connection_trace_capacity")]
    pub connection_trace_capacity: u64,
    /// Cosmetic display name. Empty falls back to `network_id`.
    #[serde(default)]
    pub label: String,
    /// Initial governance kind for this network, matched to the verified
    /// bootstrap's local shape. The constructor default is Open. Closed enables closed
    /// membership at bootstrap. Silent is Open
    /// governance plus two connection-behaviour changes — no
    /// auto-dial on presence (co-present peers surface as `Sighted`
    /// without a WebRTC session until an explicit `connect_peer` or
    /// an inbound offer) and no roster gossip — for a shared open
    /// mesh where every connection is deliberate.
    ///
    /// At runtime, canonical verified facts are authoritative; this field is
    /// only the local shape matched to verified bootstrap on first attach.
    /// Subsequent kind changes come from canonical fact transitions, not from
    /// editing config.json.
    pub kind: NetworkKind,
    /// Checked owner-selected timing and watchdog policy for this network.
    #[serde(default)]
    pub scheduler: SchedulerPolicyConfig,
    /// Checked owner-selected lifetime and storage bounds for semantic facts.
    pub semantic_policy: SemanticPolicyConfig,
    #[serde(default)]
    pub topology: TopologyMode,
    /// Optional bounded local hub maintenance and topology advertisement
    /// policy. `None` is the explicit disabled state; no enabled defaults are
    /// synthesized during V4 deserialization.
    #[serde(default)]
    pub hub: Option<HubPolicyConfig>,
    /// Optional local custody bounds for explicit HubTree parenting. This is
    /// independent from the shared root/hub/backup topology digest.
    #[serde(default)]
    pub tree: Option<TreePolicyConfig>,
    /// Optional in-process observation aggregate. It has no serde/wire
    /// authority and is never consulted by semantic admission or routing.
    #[serde(default)]
    pub local_observations: Option<LocalObservationPolicyConfig>,
    /// Setup-only Hub introduction limits. Every edit requires exact runtime
    /// replacement; this never authorizes forwarding application payloads.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub introduction: Option<HubIntroductionPolicyConfig>,
    #[serde(default)]
    pub signaling: SignalingConfig,
    #[serde(default = "default_stun_servers")]
    pub stun_servers: Vec<StunServer>,
    /// TURN servers. Defaults to the project's reference TURN (shared
    /// guest credential, bandwidth-capped) so symmetric-NAT / CGNAT
    /// peers connect out of the box; run your own and point this at it
    /// for dedicated capacity. Opt out with an explicit empty array
    /// (`"turn_servers": []`) — `default_turn_servers` only fires when
    /// the field is absent. The engine surfaces an `ice-failed-no-turn`
    /// diagnostic if a topology needs TURN and none is reachable.
    #[serde(default = "default_turn_servers")]
    pub turn_servers: Vec<TurnServer>,
    /// Peers this node maintains a standing dial for. On a `Silent`
    /// network these are the one exception to "nothing connects until a
    /// deliberate dial": a pinned peer is (re)dialed whenever it
    /// announces, and its reconnect intent never expires — the shape a
    /// standing remote-support session needs. Populated by
    /// `connect_peer(…, sticky)` at runtime and persisted with the
    /// config so pins survive daemon restarts.
    #[serde(default)]
    pub pinned_peers: Vec<String>,
    /// When true, every authenticating peer is added to the roster
    /// automatically without user approval. Useful for headless
    /// fleet members; off by default.
    #[serde(default)]
    pub auto_approve: bool,
}

impl NetworkConfig {
    /// Validate the complete local ICE configuration before a transport can
    /// clone its vectors and credential strings. The bound is the exact
    /// platform-safe allocation ceiling already used by Tokio broadcasters;
    /// it is not a product limit or a silently substituted server count.
    pub(crate) fn validate_ice_servers(&self) -> Result<()> {
        let mut server_count = 0usize;
        let mut url_count = 0usize;
        let mut retained_bytes = 0usize;
        for server in &self.stun_servers {
            server_count = server_count
                .checked_add(1)
                .ok_or_else(|| Error::Config("network STUN server count overflows".into()))?;
            url_count = url_count
                .checked_add(server.urls.len())
                .ok_or_else(|| Error::Config("network STUN URL count overflows".into()))?;
            if server_count > MAX_NETWORK_BROADCAST_CAPACITY
                || url_count > MAX_NETWORK_BROADCAST_CAPACITY
            {
                return Err(Error::Config(
                    "network STUN workload exceeds the platform allocation limit".into(),
                ));
            }
            for url in &server.urls {
                validate_ice_text("STUN URL", url, &mut retained_bytes)?;
            }
        }
        for server in &self.turn_servers {
            server_count = server_count
                .checked_add(1)
                .ok_or_else(|| Error::Config("network TURN server count overflows".into()))?;
            url_count = url_count
                .checked_add(server.urls.len())
                .ok_or_else(|| Error::Config("network TURN URL count overflows".into()))?;
            if server_count > MAX_NETWORK_BROADCAST_CAPACITY
                || url_count > MAX_NETWORK_BROADCAST_CAPACITY
            {
                return Err(Error::Config(
                    "network TURN workload exceeds the platform allocation limit".into(),
                ));
            }
            for url in &server.urls {
                validate_ice_text("TURN URL", url, &mut retained_bytes)?;
                validate_turn_url(url)?;
            }
            if let Some(username) = &server.username {
                validate_ice_text("TURN username", username, &mut retained_bytes)?;
            }
            if let Some(credential) = &server.credential {
                validate_ice_text("TURN credential", credential, &mut retained_bytes)?;
            }
        }
        Ok(())
    }

    /// Return this network's finite event-history choice in the platform
    /// representation required by its broadcaster.
    pub(crate) fn event_capacity_usize(&self) -> Result<usize> {
        checked_network_capacity(self.event_capacity, "event_capacity")
    }

    /// Return this network's finite connection-trace history choice in the
    /// platform representation required by its tracer broadcaster.
    pub(crate) fn connection_trace_capacity_usize(&self) -> Result<usize> {
        checked_network_capacity(self.connection_trace_capacity, "connection_trace_capacity")
    }

    /// Build a config from just the wire-level network id, filling every
    /// other field with its default (reference STUN/TURN, open
    /// governance, default topology, no roster override, manual
    /// approval). The local `id` defaults to the network id. This backs
    /// `myownmesh ctl networks join <network_id>`, which only takes an
    /// id; richer setups go through config.json or the GUI.
    pub fn from_network_id_with_semantic_policy(
        id: impl Into<String>,
        network_id: impl Into<String>,
        semantic_policy: SemanticPolicyConfig,
    ) -> Self {
        Self {
            id: id.into(),
            network_id: network_id.into(),
            event_capacity: DEFAULT_NETWORK_EVENT_CAPACITY,
            connection_trace_capacity: DEFAULT_NETWORK_CONNECTION_TRACE_CAPACITY,
            label: String::new(),
            kind: Default::default(),
            scheduler: SchedulerPolicyConfig::default(),
            semantic_policy,
            topology: Default::default(),
            hub: None,
            tree: None,
            local_observations: None,
            introduction: None,
            signaling: Default::default(),
            stun_servers: default_stun_servers(),
            turn_servers: default_turn_servers(),
            pinned_peers: Vec::new(),
            auto_approve: false,
        }
    }

    /// Test/lab convenience profile. Shipped applications must use
    /// [`Self::from_network_id_with_semantic_policy`] so resource custody is
    /// never selected by a library constant.
    #[cfg(any(test, feature = "transport-lab"))]
    pub fn from_network_id(id: impl Into<String>, network_id: impl Into<String>) -> Self {
        Self::from_network_id_with_semantic_policy(id, network_id, SemanticPolicyConfig::default())
    }

    /// Return the checked policy before engine construction performs side
    /// effects. Callers must pass this value through rather than substituting
    /// process-wide timing constants.
    pub(crate) fn scheduler_policy(&self) -> Result<SchedulerPolicyConfig> {
        self.validate_topology()?;
        if let Some(introduction) = self.introduction {
            introduction.checked()?;
        }
        match (&self.topology, self.tree) {
            (TopologyMode::HubTree { .. }, None) => {
                return Err(Error::Config(
                    "HubTree requires an explicit local tree policy".into(),
                ));
            }
            (TopologyMode::HubTree { .. }, Some(tree)) if !tree.validate() => {
                return Err(Error::Config("HubTree local policy is invalid".into()));
            }
            (TopologyMode::HubTree { .. }, Some(_)) => {}
            (_, Some(_)) => {
                return Err(Error::Config(
                    "tree policy requires HubTree topology".into(),
                ));
            }
            _ => {}
        }
        if matches!(&self.topology, TopologyMode::HubTree { .. }) && self.hub.is_none() {
            return Err(Error::Config(
                "HubTree requires an explicit hub timing/profile policy".into(),
            ));
        }
        self.semantic_policy()?;
        self.validate_ice_servers()?;
        let scheduler = self.scheduler.checked()?;
        if let Some(hub) = self.hub {
            if !hub.validate()
                || scheduler.state_watch_interval_ms > hub.trickle_imin_ms / 2
                || scheduler.state_watch_interval_ms > hub.exploration_interval_ms
            {
                return Err(Error::Config(
                    "hub policy is invalid or its Trickle interval is not observable by the state-watch tick".into(),
                ));
            }
        }
        if let Some(observations) = self.local_observations {
            if !observations.validate() {
                return Err(Error::Config(
                    "local observation policy contains zero or inconsistent bounds".into(),
                ));
            }
        }
        Ok(scheduler)
    }

    fn validate_topology(&self) -> Result<()> {
        let TopologyMode::HubTree {
            root,
            hubs,
            backup_candidates,
        } = &self.topology
        else {
            return Ok(());
        };
        let root = crate::semantic::DeviceId::from_canonical_str(root)
            .map_err(|_| Error::Config("HubTree root must be a canonical DeviceId".into()))?;
        if hubs.is_empty() {
            return Err(Error::Config("HubTree requires at least one hub".into()));
        }
        let mut normalized = Vec::with_capacity(hubs.len());
        for hub in hubs {
            let hub = crate::semantic::DeviceId::from_canonical_str(hub)
                .map_err(|_| Error::Config("HubTree hubs must be canonical DeviceIds".into()))?;
            if hub == root {
                return Err(Error::Config(
                    "HubTree root cannot also be a configured hub".into(),
                ));
            }
            normalized.push(hub);
        }
        normalized.sort();
        if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(Error::Config("HubTree hubs must be unique".into()));
        }
        let backup_candidates = usize::try_from(*backup_candidates)
            .map_err(|_| Error::Config("HubTree backup candidate count overflows".into()))?;
        if backup_candidates >= normalized.len() {
            return Err(Error::Config(
                "HubTree backup candidates must be fewer than configured hubs".into(),
            ));
        }
        Ok(())
    }

    /// Validate the complete policy subset needed before engine construction
    /// performs side effects. Runtime callers may use the narrower accessors
    /// when they need only one policy.
    pub fn validate(&self) -> Result<()> {
        self.scheduler_policy()?;
        Ok(())
    }

    pub fn checked(self) -> Result<Self> {
        self.validate()?;
        Ok(self)
    }

    /// Return the checked semantic lifetime/storage policy before engine
    /// construction performs side effects.
    pub(crate) fn semantic_policy(&self) -> Result<SemanticPolicyConfig> {
        self.semantic_policy.checked()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct AutoUpdateConfig {
    pub enabled: bool,
    /// `"stable"` or `"beta"`. Beta channel pulls pre-releases; stable
    /// only takes the latest released version.
    pub channel: String,
    /// `"patch"` | `"minor"` | `"all"` | `"none"`. Controls which
    /// version bumps the updater applies without confirmation. While the
    /// project is in fast-moving alpha the default is `"all"` — every
    /// device should ride the latest release rather than stall a few
    /// versions back. The narrower policies stay selectable (and become
    /// the sensible default once the wire format settles); `"none"`
    /// stages updates but waits for an explicit "apply".
    pub auto_apply: String,
    /// Background feed-check cadence. Zero is invalid.
    pub check_interval_hours: u32,
    /// Maximum time for one release-feed request, in milliseconds.
    pub feed_request_timeout_ms: u64,
    /// Maximum time for one artifact/checksum/signature request, in
    /// milliseconds.
    pub artifact_download_timeout_ms: u64,
    /// Override the release feed URL. Null = use the build-time
    /// `MYOWNMESH_RELEASE_URL_STABLE` env-var default.
    pub stable_url: Option<String>,
    pub beta_url: Option<String>,
}

impl Default for AutoUpdateConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            channel: "stable".to_string(),
            // Alpha default: take every release. See the field doc.
            auto_apply: "all".to_string(),
            check_interval_hours: 6,
            feed_request_timeout_ms: 15_000,
            artifact_download_timeout_ms: 300_000,
            stable_url: None,
            beta_url: None,
        }
    }
}

impl AutoUpdateConfig {
    /// Validate updater timing policy before a client, request, or background
    /// operation is created. There is no updater-side clamp or hidden
    /// fallback.
    pub fn validate(&self) -> Result<()> {
        if self.check_interval_hours == 0 {
            return Err(Error::Config(
                "auto_update.check_interval_hours must be non-zero".into(),
            ));
        }
        self.feed_request_timeout()?;
        self.artifact_download_timeout()?;
        Ok(())
    }

    pub fn feed_request_timeout(&self) -> Result<Duration> {
        checked_auto_update_duration(
            "auto_update.feed_request_timeout_ms",
            self.feed_request_timeout_ms,
        )
    }

    pub fn artifact_download_timeout(&self) -> Result<Duration> {
        checked_auto_update_duration(
            "auto_update.artifact_download_timeout_ms",
            self.artifact_download_timeout_ms,
        )
    }
}

fn checked_auto_update_duration(name: &'static str, millis: u64) -> Result<Duration> {
    if millis == 0 {
        return Err(Error::Config(format!("{name} must be non-zero")));
    }
    Ok(Duration::from_millis(millis))
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct AutoCleanupConfig {
    pub updates: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct DaemonConfig {
    pub enabled: bool,
    /// Unix-domain socket path for `myownmesh ctl …` to reach the
    /// running daemon. Null = derive default
    /// (`~/.myownmesh/daemon.sock` on Unix; named pipe on Windows).
    pub control_socket: Option<PathBuf>,
    pub log_level: String,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            control_socket: None,
            log_level: "info".to_string(),
        }
    }
}

/// Default WebSocket port for the self-hosted signaling relay.
/// Arbitrary high port outside the privileged range so the daemon can
/// bind it without root.
pub const DEFAULT_SIGNALING_SERVER_PORT: u16 = 4848;

/// Default UDP port for the self-hosted STUN / TURN service. 3478 is
/// the IANA-assigned STUN/TURN port (RFC 5389 / RFC 5766) — peers
/// configuring `stun:` / `turn:` URLs expect it by default.
pub const DEFAULT_STUN_TURN_PORT: u16 = 3478;

/// How this device offers infrastructure services to the rest of the
/// mesh. Device-level rather than per-network: a STUN / TURN / signaling
/// server serves every network this device participates in (and any
/// external ICE / Nostr client), so the toggles live on the device
/// config, not on an individual [`NetworkConfig`].
///
/// Everything is off by default. Turning a device into an always-on
/// signaling, STUN, or TURN host is an explicit opt-in. When a
/// service is enabled the daemon advertises the matching
/// [`crate::services::ServiceRole`] to peers so the rest of the mesh can
/// discover and adopt it, which is what makes a fully self-hosted,
/// internet-isolated network trivial to stand up.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct ServicesConfig {
    /// Whether this device participates as a regular mesh node. On by
    /// default; turn off for a pure-infrastructure box.
    pub node: NodeServiceConfig,
    pub signaling: SignalingServerConfig,
    pub stun: StunServiceConfig,
    pub turn: TurnServiceConfig,
}

/// Whether this device acts as a regular mesh node and joins its
/// configured networks and participates as a peer. Enabled by default;
/// disable it to run a **pure-infrastructure box** that only hosts
/// signaling / STUN / TURN (advertising itself purely as an edge /
/// ingress-egress point) without joining any network itself.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct NodeServiceConfig {
    pub enabled: bool,
}

impl Default for NodeServiceConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// Self-hosted signaling server: a minimal Nostr-compatible relay
/// (NIP-01 over WebSocket) that mesh peers can use in place of the
/// public Nostr relay pool. Point a network's `signaling.servers` at
/// `ws://this-host:port` and it interoperates with the built-in driver
/// with zero client changes — the same wire format the driver already
/// speaks to public relays.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingServerConfig {
    pub enabled: bool,
    /// Interface to bind. `0.0.0.0` listens on every interface;
    /// `127.0.0.1` keeps it loopback-only.
    pub bind: String,
    pub port: u16,
    /// Flood-protection limits (per-connection rates, per-IP connection
    /// caps, subscription / message-size caps). Safe defaults; loosen for
    /// a busy public relay, tighten for a locked-down private one.
    pub limits: SignalingLimits,
}

impl Default for SignalingServerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_SIGNALING_SERVER_PORT,
            limits: SignalingLimits::default(),
        }
    }
}

/// Self-hosted STUN server. Answers RFC 5389 Binding requests so peers
/// can discover their server-reflexive address without depending on a
/// public STUN provider. Pure reflexion — no auth, no allocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct StunServiceConfig {
    pub enabled: bool,
    pub bind: String,
    pub port: u16,
}

impl Default for StunServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_STUN_TURN_PORT,
        }
    }
}

/// Self-hosted TURN server (RFC 5766) for relaying media / data when no
/// direct path can be found (symmetric NAT — common on phone hotspots).
/// A TURN server also answers STUN Binding requests, so enabling TURN
/// gives STUN for free on the same port; run the standalone STUN service
/// only when you want reflexion without allocations.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct TurnServiceConfig {
    pub enabled: bool,
    /// Opt-in RFC 8656 TCP listener on the UDP control port. TLS is terminated
    /// separately by Caddy, not by this listener.
    pub tcp_enabled: bool,
    /// Separate loopback-only PROXYv2 backend for Caddy's external TLS listener.
    /// This is independent of the public plaintext TCP listener.
    pub tls_proxy_enabled: bool,
    pub tls_proxy_port: u16,
    pub tcp_max_connections: usize,
    pub tcp_max_connections_per_ip: usize,
    /// Absolute accepted-stream deadline until a successful TURN Allocate
    /// response is observed. Incoming frames do not extend this deadline.
    pub tcp_auth_timeout_ms: u64,
    pub tcp_idle_timeout_ms: u64,
    pub bind: String,
    pub port: u16,
    /// Public IP the server hands out in relay allocations. TURN can't
    /// guess its own routable address, so off-LAN clients need this set
    /// explicitly. Empty falls back to the bind address — only correct
    /// when the device already holds a public IP on the bound interface.
    pub public_ip: String,
    /// Authentication realm advertised to clients. Cosmetic but must
    /// match what peers put in their TURN URL credentials.
    pub realm: String,
    /// Static long-term credentials the server accepts. Mirror an entry
    /// into each peer's `turn_servers` config so they can allocate.
    pub credentials: Vec<TurnCredential>,
    /// Per-connection (per-allocation) relayed-bandwidth cap in bytes per
    /// second, applied independently to each direction. `0` = unlimited.
    /// A global QoS knob so one client can't saturate the relay — there's
    /// no per-user override yet, this cap applies to every allocation.
    pub max_bps_per_connection: u64,
    /// Optional fixed UDP port window the server allocates relay sockets
    /// from. `:port` above is only the control channel; every relayed
    /// allocation flows through a separate UDP port, and **all of those
    /// must be open at your firewall AND your cloud provider's security
    /// group**. Default `0` = **unbounded**: relay sockets use the OS
    /// ephemeral range (so you open that whole range — Linux:
    /// `sysctl net.ipv4.ip_local_port_range`), which never artificially
    /// caps the relay. Set both to pin a smaller, predictable window
    /// (e.g. `49152`–`65535`) and open only that. `relay_port_min == 0`
    /// means unbounded regardless of `relay_port_max`.
    pub relay_port_min: u16,
    pub relay_port_max: u16,
}

impl Default for TurnServiceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tcp_enabled: false,
            tls_proxy_enabled: false,
            tls_proxy_port: 3479,
            tcp_max_connections: 256,
            tcp_max_connections_per_ip: 64,
            tcp_auth_timeout_ms: 30_000,
            tcp_idle_timeout_ms: 600_000,
            bind: "0.0.0.0".to_string(),
            port: DEFAULT_STUN_TURN_PORT,
            public_ip: String::new(),
            realm: "myownmesh".to_string(),
            // Ship the same shared credential the *client* default uses
            // (see `default_turn_servers`) so an enabled TURN server
            // accepts the default clients out of the box — "network in a
            // box". Deliberately NOT a secret: it's bandwidth-capped via
            // `max_bps_per_connection`, and anyone can read it, so set
            // your own before relying on it for sustained throughput.
            // Must stay in sync with `default_turn_servers`.
            credentials: vec![TurnCredential {
                username: "guest".to_string(),
                password: "theguestpassword".to_string(),
            }],
            max_bps_per_connection: 0,
            // 0 = unbounded: use the OS ephemeral range so a public relay
            // is never artificially capped out of the box (open udp 3478 +
            // that range at the firewall). Operators who want a smaller
            // firewall surface pin relay_port_min/max to a fixed window.
            relay_port_min: 0,
            relay_port_max: 0,
        }
    }
}

impl TurnServiceConfig {
    /// Validate even while disabled, so a later enable cannot activate invalid
    /// persisted limits. Consumers must check before changing running services.
    pub fn validate_tcp(&self) -> Result<()> {
        if self.tls_proxy_port == 0 || (self.tls_proxy_enabled && self.tls_proxy_port == self.port)
        {
            return Err(Error::Config("invalid TURN TLS proxy backend port".into()));
        }
        if self.tcp_max_connections == 0
            || self.tcp_max_connections > isize::MAX as usize
            || self.tcp_max_connections_per_ip == 0
            || self.tcp_max_connections_per_ip > self.tcp_max_connections
        {
            return Err(Error::Config("invalid TURN TCP connection limits".into()));
        }
        // Direct and proxy listeners each retain a non-borrowable share of
        // both limits; floor/remainder splitting must leave both positive.
        if self.tcp_enabled
            && self.tls_proxy_enabled
            && (self.tcp_max_connections < 2 || self.tcp_max_connections_per_ip < 2)
        {
            return Err(Error::Config(
                "dual TURN TCP listeners require at least two total and per-IP connections".into(),
            ));
        }
        self.tcp_idle_timeout()?;
        self.tcp_auth_timeout()?;
        Ok(())
    }

    pub fn tcp_auth_timeout(&self) -> Result<Duration> {
        checked_turn_duration(self.tcp_auth_timeout_ms, "authentication")
    }

    pub fn tcp_idle_timeout(&self) -> Result<Duration> {
        checked_turn_duration(self.tcp_idle_timeout_ms, "idle")
    }
}

fn checked_turn_duration(millis: u64, phase: &str) -> Result<Duration> {
    if millis == 0 || millis > i64::MAX as u64 {
        return Err(Error::Config(format!("invalid TURN TCP {phase} timeout")));
    }
    let duration = Duration::from_millis(millis);
    std::time::Instant::now()
        .checked_add(duration)
        .ok_or_else(|| Error::Config(format!("TURN TCP {phase} deadline overflows")))?;
    Ok(duration)
}

/// One username / password pair the TURN server accepts. Plaintext in
/// config.json — the file is already 0600-adjacent (lives in
/// `~/.myownmesh`), and long-term TURN credentials are low-value shared
/// secrets, not device identity keys.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TurnCredential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct MeshConfig {
    pub version: u32,
    /// Finite history retained by the mesh-wide MeshEvent broadcaster.
    /// The process owner chooses this independently of each network's
    /// per-network event and connection-trace histories.
    #[serde(default = "default_mesh_event_capacity")]
    pub event_capacity: u64,
    /// Override the identity anchor file path. Null = use the default
    /// (`~/.myownmesh/.secrets/identity.json`).
    #[serde(default)]
    pub identity_path: Option<PathBuf>,
    #[serde(default)]
    pub auto_update: AutoUpdateConfig,
    #[serde(default)]
    pub auto_cleanup: AutoCleanupConfig,
    #[serde(default)]
    pub daemon: DaemonConfig,
    /// Infrastructure services this device hosts for the mesh
    /// (relay / signaling / STUN / TURN). All off by default.
    #[serde(default)]
    pub services: ServicesConfig,
    #[serde(default)]
    pub networks: Vec<NetworkConfig>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            event_capacity: DEFAULT_MESH_EVENT_CAPACITY,
            identity_path: None,
            auto_update: AutoUpdateConfig::default(),
            auto_cleanup: AutoCleanupConfig::default(),
            daemon: DaemonConfig::default(),
            services: ServicesConfig::default(),
            networks: Vec::new(),
        }
    }
}

fn require_current_version(mut cfg: MeshConfig) -> Result<MeshConfig> {
    if cfg.version != CONFIG_VERSION {
        return Err(Error::Config(format!(
            "config version {} is not the current hard-alpha version {}",
            cfg.version, CONFIG_VERSION
        )));
    }
    cfg.services.turn.validate_tcp()?;
    for network in &mut cfg.networks {
        // In-version normalization only: this exact previously persisted
        // reference service opted into the project default, not a custom relay.
        // No other URL list or credential is rewritten, and schema 3 stays refused.
        if network.turn_servers.len() == 1 {
            let server = &network.turn_servers[0];
            if server.urls.len() == 1
                && server.urls[0] == "turn:turn.myownmesh.com:3478"
                && server.username.as_deref() == Some("guest")
                && server.credential.as_deref() == Some("theguestpassword")
            {
                network.turn_servers = default_turn_servers();
            }
        }
        network.validate_ice_servers()?;
    }
    Ok(cfg)
}

/// One deliberately opaque reservation for the loader-owned parsed config.
///
/// Serde defaults can expand a short source into arbitrarily many owned fields
/// as repeatable families grow, so neither source-byte ratios nor a fixed floor
/// truthfully price the resulting allocator graph. The owner therefore names
/// that graph as one broader dependency residual, acquired before parsing and
/// held for exactly as long as the finished [`MeshConfig`]. It also covers the
/// allocation-free serde traversal used to measure the compact encoding before
/// the caller acquires its output buffer; no loader work is performed after the
/// residual owner is released.
fn config_loader_residual_claim() -> ResourceClaim {
    ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
}

/// The one parse-and-quarantine decision, shared by [`MeshConfig::load`] and
/// [`PreparedConfigLoad::commit`].
///
/// Shared rather than duplicated so the two entry points cannot drift: the
/// quarantine, the fail-safe default and the version refusal are one behaviour
/// with two callers, and a second copy would be a second source of truth for
/// what a corrupt config means.
fn parse_or_quarantine(raw: &str, path: &std::path::Path) -> Result<MeshConfig> {
    // Corrupt config (power cut mid-write on an appliance, or a
    // hand-edit gone wrong) → quarantine + defaults, loudly. A
    // parse error here used to stop the daemon from starting at
    // all — the worst brick, since embedders (NanoKVM, AllMyStuff)
    // re-add their networks over the control socket and rewrite
    // this file on their own once the daemon is up. Defaults are
    // fail-safe: no networks joined, no services exposed.
    match serde_json::from_str::<MeshConfig>(raw) {
        Ok(cfg) => require_current_version(cfg),
        Err(e) => {
            let kept = crate::persist::quarantine(path);
            tracing::error!(
                path = %path.display(),
                quarantined = ?kept,
                "config file is corrupt ({e}) — starting from \
                 defaults; the previous contents were kept at the \
                 quarantine path for hand-recovery"
            );
            Ok(MeshConfig::default())
        }
    }
}

fn read_config_bytes(path: &Path) -> Result<Option<Vec<u8>>> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(Some(bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(Error::Config(format!("read {}: {error}", path.display()))),
    }
}

/// Read one config while the transaction lease is held, returning the exact
/// bytes used as the commit CAS witness. A corrupt file may be quarantined by
/// parsing; in that case the post-quarantine absence is the baseline.
fn load_config_locked(path: &Path) -> Result<(MeshConfig, Option<Vec<u8>>)> {
    let Some(bytes) = read_config_bytes(path)? else {
        return Ok((MeshConfig::default(), None));
    };
    let raw = String::from_utf8(bytes.clone())
        .map_err(|error| Error::Config(format!("read {}: {error}", path.display())))?;
    let config = parse_or_quarantine(&raw, path)?;
    let baseline = if path.exists() { Some(bytes) } else { None };
    Ok((config, baseline))
}

fn save_config_locked(path: &Path, config: &MeshConfig) -> Result<()> {
    config.services.turn.validate_tcp()?;
    for network in &config.networks {
        network.validate_ice_servers()?;
    }
    let parent = path
        .parent()
        .ok_or_else(|| Error::Config(format!("config path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|error| Error::Config(format!("create {}: {error}", parent.display())))?;
    let serialized = serde_json::to_string_pretty(config)?;
    crate::persist::write_atomic(path, serialized.as_bytes())
        .map_err(|error| Error::Config(format!("write {}: {error}", path.display())))
}

/// Where a prepared load will get its bytes and exact file identity.
enum PreparedConfigSource {
    /// No file. The plan will produce [`MeshConfig::default`] and reads
    /// nothing.
    Missing,
    /// An **already-open** handle and the length the plan was measured
    /// against. Opened during planning rather than at commit so the bytes that
    /// get read are the bytes that were measured, not whatever a later `open`
    /// would find. The identity rejects an uncoordinated replacement before
    /// the prepared handle can quarantine the wrong pathname.
    Present {
        file: std::fs::File,
        len: u64,
        identity: ConfigFileIdentity,
    },
}

fn ensure_prepared_source_identity(path: &Path, source: &PreparedConfigSource) -> Result<()> {
    match source {
        PreparedConfigSource::Missing => match std::fs::metadata(path) {
            Ok(_) => Err(Error::Config(format!(
                "config {} appeared after preparation",
                path.display()
            ))),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(Error::Config(format!("stat {}: {error}", path.display()))),
        },
        PreparedConfigSource::Present { identity, .. } => {
            let file = std::fs::File::open(path)
                .map_err(|error| Error::Config(format!("open {}: {error}", path.display())))?;
            if ConfigFileIdentity::from_file(&file)? != *identity {
                Err(Error::Config(format!(
                    "config {} changed after preparation",
                    path.display()
                )))
            } else {
                Ok(())
            }
        }
    }
}

/// A measured, funded-but-not-yet-performed config load.
///
/// **Nothing is parsed and no config exists yet.** Planning opens the file and
/// measures it; it allocates no `MeshConfig` and no raw buffer. That is what
/// lets a caller decide whether it may afford the load *before* the load
/// happens, and what makes a refusal provably free of any read, parse or
/// snapshot construction.
///
/// **Core keeps the file semantics; the caller keeps the admission decision.**
/// The transaction lease is acquired during preparation and held through
/// commit. The caller still acquires against [`Self::loader_residual_claim`]
/// and [`Self::load_work_claim`], then hands both leases to [`Self::commit`].
/// Once committed, the funded owner can measure its compact width before the
/// caller acquires output capacity. Quarantine, the fail-safe default and the
/// version refusal stay in this crate, where they are already the one source of
/// truth.
///
/// Move-only, and there is no accessor for the handle. A plan is a single
/// permission to perform one load.
#[must_use = "a prepared load has opened the config file and must be committed or dropped"]
pub struct PreparedConfigLoad {
    source: PreparedConfigSource,
    /// Held from preparation through commit, so supported writers cannot
    /// change the prepared path between its identity check and parse.
    _transaction: ConfigTransactionLease,
    /// Kept because quarantine needs the path, and the plan may be the only
    /// thing still holding it by the time a corrupt parse is discovered.
    path: PathBuf,
    loader_residual_claim: ResourceClaim,
    load_work_claim: ResourceClaim,
}

/// One config, and the funding that keeps it.
///
/// Value before lease: the config is destroyed first and its funding released
/// after, so the claim never describes memory that has already gone — nor is it
/// released while the value it pays for is still standing.
///
/// Borrowed access only. There is no method handing the `MeshConfig` out on its
/// own, because a caller holding one would have a config whose funding had been
/// released with the owner around it.
pub struct FundedMeshConfig {
    value: MeshConfig,
    _loader_residual: ResourceLease,
}

impl FundedMeshConfig {
    pub fn get(&self) -> &MeshConfig {
        &self.value
    }

    /// Exact compact JSON width, counted without constructing an output buffer.
    pub fn compact_encoded_len(&self) -> Result<usize> {
        struct Count(usize);
        impl std::io::Write for Count {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0 = self.0.checked_add(bytes.len()).ok_or_else(|| {
                    std::io::Error::new(std::io::ErrorKind::InvalidData, "config width overflow")
                })?;
                Ok(bytes.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut count = Count(0);
        serde_json::to_writer(&mut count, &self.value)?;
        Ok(count.0)
    }
}

impl PreparedConfigLoad {
    /// The broader dependency represented by the parsed config.
    ///
    /// This names the allocator graph serde constructs and the allocation-free
    /// compact-width traversal performed while that graph is owned. Raw input
    /// bytes and parsing CPU remain separately and mechanically charged by
    /// [`Self::load_work_claim`], which ends when the load finishes.
    pub const fn loader_residual_claim(&self) -> ResourceClaim {
        self.loader_residual_claim
    }

    /// What performing the load costs *while it happens*, and not afterwards.
    ///
    /// The raw text and the parsed config exist at the same moment: the config
    /// is built from a buffer that is still there. A plan that priced only the
    /// result would underfund exactly that peak. This is the other half — the
    /// raw buffer's bytes, the parse work, and the plan's own path — and
    /// [`Self::commit`] releases it before returning, so the transient cost is
    /// charged for the interval it is actually incurred in.
    ///
    /// The path is here rather than in the retention because it dies with the
    /// load: nothing beyond `commit` can reach it, and the parsed config does
    /// not hold it.
    pub const fn load_work_claim(&self) -> ResourceClaim {
        self.load_work_claim
    }

    /// Read, parse and retain, now that the retention is funded.
    ///
    /// The read is bounded by the length measured during planning, and a file
    /// that **grew** since then is refused *before* anything is parsed or
    /// quarantined — a file being rewritten underneath us is not a corrupt
    /// file, and treating it as one would quarantine a perfectly good config
    /// that simply arrived mid-write.
    ///
    /// Everything else is exactly [`MeshConfig::load`]'s behaviour, because it
    /// is literally the same function: complete-read corrupt files are
    /// quarantined and fall back to defaults, and a config whose version is not
    /// current is refused.
    /// Takes **both** leases because both costs are real at different times:
    /// `work_lease` covers the raw buffer and the parse while they exist, and
    /// is released here once the buffer is gone; `loader_residual` covers the
    /// config and travels out inside the returned owner.
    pub fn commit(
        self,
        loader_residual: ResourceLease,
        work_lease: ResourceLease,
    ) -> Result<FundedMeshConfig> {
        use std::io::Read;

        // The leases have to be *these* leases. `ResourceLease::claim` is public,
        // so without this the prepare-then-acquire discipline would be a
        // convention a caller could simply not follow: two unrelated leases, or
        // two zero ones, would buy a `FundedMeshConfig` whose funding describes
        // something else. Checked before the file is read, before anything is
        // parsed, and before a default is constructed, so a caller that gets this
        // wrong has still caused no work.
        //
        // Both leases are dropped on the way out, which returns their capacity to
        // whatever they were taken from. That is the only sound thing to do with
        // them: they are not this plan's, so they cannot be handed back as this
        // plan's, and holding them would strand capacity on a refusal.
        if loader_residual.claim() != self.loader_residual_claim {
            return Err(Error::Config(
                "config loader residual was not taken for this plan's exact residual claim"
                    .to_string(),
            ));
        }
        if work_lease.claim() != self.load_work_claim {
            return Err(Error::Config(
                "config load lease was not taken for this plan's load work claim".to_string(),
            ));
        }

        // Named rather than reached through `self`, so the path can be released
        // deliberately below rather than at the end of this call — after the
        // charge that covers it has already gone back.
        let PreparedConfigLoad {
            source,
            _transaction,
            path,
            loader_residual_claim: _,
            load_work_claim: _,
        } = self;

        ensure_prepared_source_identity(&path, &source)?;

        let value = match source {
            PreparedConfigSource::Missing => MeshConfig::default(),
            PreparedConfigSource::Present { file, len, .. } => {
                // One byte past the measurement: enough to *detect* growth,
                // never enough to read an unbounded file.
                //
                // Reserved up front, at exactly the capacity `load_work_claim`
                // priced. `String::new()` would start empty and grow
                // geometrically toward the same size, asking the allocator for
                // capacity nobody had funded — and doing so *before* the growth
                // refusal below could fire.
                let capacity = usize::try_from(len)
                    .ok()
                    .and_then(|measured| measured.checked_add(1))
                    .ok_or_else(|| {
                        Error::Config(format!("config {} is too large to read", path.display()))
                    })?;
                let mut raw = String::with_capacity(capacity);
                file.take(len.saturating_add(1))
                    .read_to_string(&mut raw)
                    .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
                if raw.len() as u64 > len {
                    return Err(Error::Config(format!(
                        "config {} grew past its measured {len} bytes while being read",
                        path.display()
                    )));
                }
                let parsed = parse_or_quarantine(&raw, &path)?;
                // The buffer's bytes go back before the charge for them does,
                // and both go back before this call returns: the peak where the
                // text and the config are both alive is exactly the interval
                // `work_lease` was acquired for.
                drop(raw);
                parsed
            }
        };
        // The plan's own path is the second allocation `load_work_claim` funds,
        // and it goes back before the charge for it does — the same order the
        // raw buffer follows above.
        drop(path);
        drop(work_lease);
        Ok(FundedMeshConfig {
            value,
            _loader_residual: loader_residual,
        })
    }
}

fn validate_ice_text(field: &str, value: &str, retained_bytes: &mut usize) -> Result<()> {
    if value.len() > MAX_NETWORK_BROADCAST_CAPACITY {
        return Err(Error::Config(format!(
            "network {field} exceeds the platform allocation limit"
        )));
    }
    *retained_bytes = (*retained_bytes)
        .checked_add(value.len())
        .ok_or_else(|| Error::Config("network ICE text workload overflows".into()))?;
    if *retained_bytes > MAX_NETWORK_BROADCAST_CAPACITY {
        return Err(Error::Config(
            "network ICE text workload exceeds the platform allocation limit".into(),
        ));
    }
    Ok(())
}

fn checked_network_capacity(value: u64, field: &str) -> Result<usize> {
    let capacity = usize::try_from(value)
        .map_err(|_| Error::Config(format!("mesh {field} does not fit this platform")))?;
    if capacity == 0 {
        return Err(Error::Config(format!(
            "mesh {field} must be greater than zero"
        )));
    }
    if capacity > MAX_NETWORK_BROADCAST_CAPACITY {
        return Err(Error::Config(format!(
            "mesh {field} exceeds the broadcast capacity limit"
        )));
    }
    Ok(capacity)
}

impl MeshConfig {
    /// Return the mesh owner's finite event-history choice in the platform
    /// representation required by the mesh-wide broadcaster.
    pub(crate) fn event_capacity_usize(&self) -> Result<usize> {
        checked_network_capacity(self.event_capacity, "event_capacity")
    }

    /// Load the config from the default location. Missing file
    /// returns [`MeshConfig::default`] — embedders should call
    /// `save()` afterward if they want the file to exist.
    ///
    /// Unfunded, and kept that way for embedders that have no resource scope.
    /// A caller that must fund the retention before it happens uses
    /// [`MeshConfig::prepare_load`] instead; both share one parse.
    pub fn load() -> Result<Self> {
        let path = crate::dirs::config_path()?;
        let _transaction = ConfigTransactionLease::acquire(&path)?;
        let (config, _) = load_config_locked(&path)?;
        Ok(config)
    }

    /// Measure a config load without performing it.
    ///
    /// Opens and stats the file — so the plan is measured against the same
    /// handle it will later read — and computes what the parsed config will
    /// cost. It allocates no config and no raw buffer, and parses nothing, so a
    /// caller that refuses on the resulting claim has provably performed no
    /// read, no parse and no construction.
    ///
    /// It does allocate one thing: the path it opened, which the plan keeps
    /// because quarantine needs it. That allocation is priced into
    /// [`PreparedConfigLoad::load_work_claim`] and released inside `commit`
    /// before that lease is. It is unfunded between here and the caller's
    /// acquisition, necessarily — the plan is what tells the caller what to
    /// acquire.
    ///
    /// The broader residual covers defaults because
    /// absent fields expand to defaults and the input's own length says nothing
    /// about that expansion.
    pub fn prepare_load() -> Result<PreparedConfigLoad> {
        let path = crate::dirs::config_path()?;
        let transaction = ConfigTransactionLease::acquire(&path)?;
        let source = match std::fs::File::open(&path) {
            Ok(file) => {
                let metadata = file
                    .metadata()
                    .map_err(|e| Error::Config(format!("stat {}: {e}", path.display())))?;
                let len = metadata.len();
                let identity = ConfigFileIdentity::from_file(&file)?;
                PreparedConfigSource::Present {
                    file,
                    len,
                    identity,
                }
            }
            // Absent is the ordinary first-run case, not a failure: the plan
            // will produce defaults, and the loader residual names their
            // allocator graph without pretending the absent file sized it.
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => PreparedConfigSource::Missing,
            Err(e) => return Err(Error::Config(format!("open {}: {e}", path.display()))),
        };

        let raw_bytes = match &source {
            PreparedConfigSource::Missing => 0,
            PreparedConfigSource::Present { len, .. } => usize::try_from(*len).map_err(|_| {
                Error::Config(format!(
                    "config {} is larger than this address space",
                    path.display()
                ))
            })?,
        };
        let too_large = || Error::Config(format!("config {} is too large to plan", path.display()));
        // Serde's finished allocator graph is intentionally not inferred from
        // source bytes. The broader residual is acquired before parsing and
        // remains coupled to the resulting config through its final width walk.
        let loader_residual_claim = config_loader_residual_claim();

        let not_representable =
            || Error::Config("config planning claim is not representable".to_string());

        // What is spent to get there: the raw text's buffer, alive at the same
        // moment as the config built from them, and the work of parsing it.
        // Released by `commit` rather than carried for the value's lifetime.
        //
        // `raw_bytes + 1`, not `raw_bytes`, and the extra byte is not a
        // rounding habit: the read deliberately asks for one byte past the
        // measurement so that growth is *detectable*, and `commit` reserves
        // exactly that much up front. Pricing only `raw_bytes` would leave the
        // detection byte unfunded — and a buffer that had to grow to hold it
        // would request unpriced capacity before the growth refusal it exists
        // to trigger could fire.
        let read_capacity = raw_bytes.checked_add(1).ok_or_else(too_large)?;
        // The plan holds a path, and a path is an allocation like any other. It
        // is charged here rather than to the retention because it dies with the
        // load: `commit` releases it just before it releases this lease, and a
        // plan that is never committed drops it with the plan.
        //
        // Capacity, not length, because capacity is what the allocator is
        // holding; the work claim must cover the path's actual reservation.
        //
        // **The window this does not cover, stated rather than implied.** The
        // path exists from the moment `prepare_load` derives it, which is before
        // the caller can possibly hold a lease for it: the plan is what tells
        // them what to acquire. That is inherent to letting the caller acquire —
        // it is one path allocation, bounded by the config directory, and it is
        // funded for the whole interval in which any funding exists at all.
        let planning_bytes = read_capacity
            .checked_add(path.capacity())
            .ok_or_else(too_large)?;
        let planning_bytes_u64 = u64::try_from(planning_bytes).map_err(|_| not_representable())?;
        let parse_work_u64 = u64::try_from(read_capacity).map_err(|_| not_representable())?;
        let load_work_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, planning_bytes_u64),
            // Work scales with the text that is parsed, and the path is not
            // parsed — so this stays the read capacity rather than following the
            // bytes above.
            (ResourceClass::ParsingOrCpuWork, parse_work_u64),
            // The raw buffer and the plan's path: two allocations, two
            // residuals.
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| not_representable())?;

        Ok(PreparedConfigLoad {
            source,
            _transaction: transaction,
            path,
            loader_residual_claim,
            load_work_claim,
        })
    }

    /// Persist to the default location. Pretty-printed JSON for
    /// easy hand-editing; the file isn't on a hot path.
    pub fn save(&self) -> Result<()> {
        let path = crate::dirs::config_path()?;
        let _transaction = ConfigTransactionLease::acquire(&path)?;
        save_config_locked(&path, self)
    }

    /// Atomically load, mutate, and persist the current configuration.
    ///
    /// The process-local gate and the adjacent OS lock serialize supported
    /// writers. The exact pre-mutation file bytes are then checked again
    /// immediately before the atomic replacement, so an uncoordinated writer
    /// cannot silently erase a disjoint update.
    pub fn transaction<R>(mutate: impl FnOnce(&mut MeshConfig) -> Result<R>) -> Result<R> {
        let path = crate::dirs::config_path()?;
        Self::transaction_at(path, mutate)
    }

    /// Path-parameterized form of [`MeshConfig::transaction`] for embedders
    /// that keep more than one configuration file and for deterministic tests.
    pub fn transaction_at<R>(
        path: impl AsRef<Path>,
        mutate: impl FnOnce(&mut MeshConfig) -> Result<R>,
    ) -> Result<R> {
        let path = path.as_ref();
        let _transaction = ConfigTransactionLease::acquire(path)?;
        let (mut config, baseline) = load_config_locked(path)?;
        let result = mutate(&mut config)?;
        if read_config_bytes(path)? != baseline {
            return Err(Error::Config(format!(
                "config changed during transaction: {}",
                path.display()
            )));
        }
        save_config_locked(path, &config)?;
        Ok(result)
    }

    /// Find a network config by its local `id`.
    pub fn network(&self, id: &str) -> Option<&NetworkConfig> {
        self.networks.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::{Command, Stdio};
    use std::sync::{
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc, Arc,
    };
    use std::thread;

    fn serialized_network(id: &str, network_id: &str) -> serde_json::Value {
        serde_json::to_value(NetworkConfig::from_network_id(id, network_id))
            .expect("constructor network config serializes")
    }

    fn introduction_policy_fixture() -> HubIntroductionPolicyConfig {
        HubIntroductionPolicyConfig {
            max_records: 4,
            max_waiters_per_target: 2,
            max_signaling_bytes: 32_768,
            max_candidates_per_attempt: 4,
            attempt_timeout_ms: 1_000,
            terminal_retention_ms: 2_000,
            max_transient_links: 2,
            idle_timeout_ms: 3_000,
            max_maintenance_per_tick: 2,
        }
    }

    #[test]
    fn introduction_requires_explicit_complete_policy_and_round_trips() {
        let mut network = NetworkConfig::from_network_id("app-policy", "app-policy-net");
        let disabled = serde_json::to_value(&network).unwrap();
        assert!(disabled.get("introduction").is_none());
        assert!(serde_json::from_value::<NetworkConfig>(disabled)
            .unwrap()
            .introduction
            .is_none());
        let policy = introduction_policy_fixture();
        network.introduction = Some(policy);
        network.validate().expect("complete explicit profile");
        let mut encoded = serde_json::to_value(&network).unwrap();
        let decoded: NetworkConfig = serde_json::from_value(encoded.clone()).unwrap();
        assert_eq!(decoded.introduction, Some(policy));
        encoded["introduction"]
            .as_object_mut()
            .unwrap()
            .remove("max_signaling_bytes");
        assert!(serde_json::from_value::<NetworkConfig>(encoded).is_err());
        let mut encoded = serde_json::to_value(policy).unwrap();
        encoded["grant"] = serde_json::json!(1);
        assert!(serde_json::from_value::<HubIntroductionPolicyConfig>(encoded).is_err());
    }

    #[test]
    fn introduction_policy_checks_zero_max_plus_one_and_workload_overflow() {
        let valid = introduction_policy_fixture();
        assert_eq!(valid.checked().unwrap(), valid);
        for field in [
            "max_records",
            "max_waiters_per_target",
            "max_signaling_bytes",
            "max_candidates_per_attempt",
            "attempt_timeout_ms",
            "terminal_retention_ms",
            "max_transient_links",
            "idle_timeout_ms",
            "max_maintenance_per_tick",
        ] {
            let mut value = serde_json::to_value(valid).unwrap();
            value[field] = serde_json::json!(0);
            let invalid: HubIntroductionPolicyConfig = serde_json::from_value(value).unwrap();
            assert!(invalid.checked().is_err(), "zero {field}");
        }
        let mut exact = valid;
        exact.max_transient_links = isize::MAX as u64;
        assert!(exact.checked().is_ok());
        exact.max_transient_links += 1;
        assert!(exact.checked().is_err());
        let mut exact = valid;
        exact.max_records = 1;
        exact.max_transient_links = 1;
        exact.max_waiters_per_target = isize::MAX as u64;
        assert!(exact.checked().is_ok());
        exact.max_waiters_per_target += 1;
        assert!(exact.checked().is_err());
        let mut overflow = valid;
        overflow.max_signaling_bytes = u64::MAX;
        assert!(overflow.checked().is_err());
        overflow = valid;
        overflow.attempt_timeout_ms = u64::MAX;
        assert!(overflow.checked().is_err());
        let mut network = NetworkConfig::from_network_id("intro-invalid", "intro-invalid-net");
        network.introduction = Some(overflow);
        assert!(network.validate().is_err());
    }

    #[test]
    fn introduction_claim_plans_price_distinct_reservations_and_refuse_overflow() {
        use crate::resource::FiniteResourceProvider;
        // Synthetic raw claims discriminate planner arithmetic, not private
        // production object sizes or a deployable provider budget.
        let root = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 17);
        let entry = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 23);
        let reservation =
            |claim| FiniteResourceProvider::reservation_planning_charge(claim).unwrap();
        let policy = introduction_policy_fixture();
        let introduction = policy.planned_records_claim(root, entry).unwrap();
        assert_eq!(
            introduction,
            reservation(root)
                .checked_add(
                    reservation(entry)
                        .checked_scale(policy.max_records)
                        .unwrap(),
                )
                .unwrap()
        );
        assert_ne!(
            introduction,
            reservation(
                root.checked_add(entry.checked_scale(policy.max_records).unwrap(),)
                    .unwrap()
            )
        );
        let demand = policy.planned_demand_links_claim(root, entry).unwrap();
        assert_eq!(
            demand,
            reservation(root)
                .checked_add(
                    reservation(entry)
                        .checked_scale(policy.max_transient_links)
                        .unwrap(),
                )
                .unwrap()
        );
        let excessive = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, u64::MAX);
        assert!(policy.planned_records_claim(excessive, entry).is_err());
        let multiply_overflow = ResourceClaim::single(ResourceClass::QueuedBytes, u64::MAX / 2);
        assert!(policy
            .planned_records_claim(root, multiply_overflow)
            .is_err());
        assert!(policy.planned_demand_links_claim(root, excessive).is_err());

        // Only the standalone provider's process scope is added here. The
        // production planners reuse an already funded application scope.
        let grant = introduction
            .checked_add(FiniteResourceProvider::scope_planning_charge())
            .unwrap();
        let port =
            crate::resource::ResourceProviderPort::new(FiniteResourceProvider::new(grant)).unwrap();
        let scope = port.process_scope();
        let authority = crate::resource::ResourceAuthorityClass::Admitted;
        let retained_root = port.acquire(&scope, authority, root).unwrap();
        let mut entries = Vec::new();
        for _ in 0..policy.max_records {
            entries.push(port.acquire(&scope, authority, entry).unwrap());
        }
        assert!(
            port.acquire(&scope, authority, entry).is_err(),
            "exact max+1 refused"
        );
        drop(entries.pop());
        entries.push(
            port.acquire(&scope, authority, entry)
                .expect("released entry is reusable"),
        );
        drop(entries);
        drop(retained_root);
        let restored_root = port.acquire(&scope, authority, root).unwrap();
        let restored_entries = (0..policy.max_records)
            .map(|_| port.acquire(&scope, authority, entry).unwrap())
            .collect::<Vec<_>>();
        drop(restored_entries);
        drop(restored_root);
    }

    #[test]
    fn scheduler_policy_rejects_zero_overflow_and_bad_order() {
        let valid = SchedulerPolicyConfig::default();
        assert!(valid.validate());
        assert!(!SchedulerPolicyConfig {
            heartbeat_interval_ms: 0,
            ..valid
        }
        .validate());
        assert!(!SchedulerPolicyConfig {
            heartbeat_interval_ms: u64::MAX,
            ..valid
        }
        .validate());
        assert!(!SchedulerPolicyConfig {
            stale_inbound_timeout_ms: 0,
            ..valid
        }
        .validate());
        assert!(!SchedulerPolicyConfig {
            skew_warn_ms: (i64::MAX as u64) + 1,
            ..valid
        }
        .validate());
        assert!(!SchedulerPolicyConfig {
            handshake_hello_retry_schedule_ms: [7_000, 5_000, 10_000],
            ..valid
        }
        .validate());
        assert!(!SchedulerPolicyConfig {
            wake_probe_delay_ms: valid.state_watch_interval_ms + 1,
            ..valid
        }
        .validate());

        let mut network = NetworkConfig::from_network_id("scheduler", "scheduler-net");
        network.scheduler.heartbeat_interval_ms = 42_000;
        let encoded = serde_json::to_string(&network).expect("scheduler policy serializes");
        let decoded: NetworkConfig =
            serde_json::from_str(&encoded).expect("scheduler policy deserializes");
        assert_eq!(
            decoded
                .scheduler_policy()
                .expect("custom scheduler policy remains valid")
                .heartbeat_interval_ms,
            42_000
        );
    }

    #[test]
    fn semantic_policy_defaults_are_exact_and_network_serde_requires_it() {
        let policy = SemanticPolicyConfig::default();
        assert_eq!(policy.max_fact_encoded_bytes, 65_535);
        assert_eq!(policy.max_dependencies_per_fact, 64);
        assert_eq!(policy.max_authority_uses_per_fact, 32);
        assert_eq!(policy.max_authority_predecessors_per_use, 64);
        assert_eq!(policy.max_admitted_facts, 100_000);
        assert_eq!(policy.max_admitted_bytes, 128 * 1024 * 1024);
        assert_eq!(policy.max_quarantined_facts, 4_096);
        assert_eq!(policy.max_quarantined_bytes, 16 * 1024 * 1024);
        assert_eq!(policy.max_quarantined_facts_per_author, 256);
        assert_eq!(policy.max_quarantined_bytes_per_author, 4 * 1024 * 1024);
        assert_eq!(policy.max_retained_facts_per_author, 10_000);
        assert_eq!(policy.max_retained_bytes_per_author, 16 * 1024 * 1024);
        assert_eq!(policy.max_hot_history_facts, 64);
        assert_eq!(policy.max_dependency_edges, 1_000_000);
        assert_eq!(policy.max_ready_batch, 256);
        assert_eq!(policy.max_pending_proofs, 10_000);
        assert_eq!(policy.max_pending_proof_bytes, 16 * 1024 * 1024);
        assert_eq!(policy.max_proof_records, 100_000);
        assert_eq!(policy.max_proof_bytes, 64 * 1024 * 1024);
        assert_eq!(policy.max_main_journal_bytes, 8 * 1024 * 1024);
        assert_eq!(policy.max_live_checkpoint_bytes, 8 * 1024 * 1024);
        assert_eq!(policy.max_database_bytes, 2 * 1024 * 1024 * 1024);
        assert_eq!(policy.max_wal_bytes, 8_413_072);
        assert_eq!(
            policy.wal_checkpoint_threshold_bytes,
            SQLITE_WAL_HEADER_BYTES
                .checked_add(
                    policy
                        .max_uncheckpointed_wal_frames
                        .checked_mul(
                            SQLITE_DEFAULT_PAGE_SIZE_BYTES + SQLITE_WAL_FRAME_OVERHEAD_BYTES,
                        )
                        .expect("default WAL threshold multiplication"),
                )
                .expect("default WAL threshold addition")
        );
        assert_eq!(policy.wal_checkpoint_threshold_bytes, 4_194_192);
        assert_eq!(policy.emergency_reserve_bytes, 8 * 1024 * 1024);
        assert_eq!(
            SEMANTIC_INGRESS_OWNER_MAX_BYTES,
            SEMANTIC_INGRESS_OWNER.len() as u64
        );
        let envelope = policy
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, policy.storage_workload())
            .expect("default SQLite storage envelope is valid");
        assert_eq!(envelope.wal_frames, 2_042);
        assert_eq!(envelope.wal_checkpoint_frames, 1_018);
        assert_eq!(envelope.wal_hard_frames, 2_042);
        assert_eq!(envelope.wal_checkpoint_bytes, 4_194_192);
        assert_eq!(envelope.wal_bytes, 8_413_072);
        assert_eq!(envelope.wal_hard_bytes, 8_413_072);
        assert_eq!(envelope.shm_bytes, 32_768);
        assert!(envelope.main_bytes >= envelope.main_pages * SQLITE_DEFAULT_PAGE_SIZE_BYTES);
        assert_eq!(
            envelope.total_bytes,
            envelope
                .main_bytes
                .checked_add(envelope.main_journal_bytes)
                .and_then(|v| v.checked_add(envelope.wal_bytes))
                .and_then(|v| v.checked_add(envelope.shm_bytes))
                .and_then(|v| v.checked_add(envelope.emergency_reserve_bytes))
                .expect("checked envelope sum")
        );
        assert!(
            envelope.total_bytes <= policy.max_database_bytes,
            "default schema pricing must fit the configured database envelope"
        );
        assert!(policy.validate());
        assert!(policy.checked().is_ok());

        let network = NetworkConfig::from_network_id("semantic", "semantic-net");
        assert_eq!(network.semantic_policy, policy);
        let encoded = serde_json::to_string(&network).expect("semantic policy serializes");
        let decoded: NetworkConfig =
            serde_json::from_str(&encoded).expect("semantic policy deserializes");
        assert_eq!(decoded.semantic_policy, policy);
    }

    #[test]
    fn semantic_schema_usage_widths_match_storage_planner() {
        let semantic_usage = SEMANTIC_SCHEMA_TABLES
            .iter()
            .find(|table| table.name == "semantic_usage")
            .expect("semantic usage descriptor is present");
        let proof_usage = SEMANTIC_SCHEMA_TABLES
            .iter()
            .find(|table| table.name == "proof_usage")
            .expect("proof usage descriptor is present");
        assert_eq!(semantic_usage.columns.len(), 9);
        assert_eq!(proof_usage.columns.len(), 7);
        assert_eq!(
            semantic_usage.columns.len(),
            usize::try_from(SEMANTIC_USAGE_COLUMN_COUNT).expect("usage width fits usize")
        );
        assert_eq!(
            proof_usage.columns.len(),
            usize::try_from(PROOF_USAGE_COLUMN_COUNT).expect("proof usage width fits usize")
        );
        assert_eq!(
            semantic_usage.columns,
            &[
                "usage_id",
                "admitted_count",
                "admitted_bytes",
                "quarantined_count",
                "quarantined_bytes",
                "dependency_edges",
                "provisional_count",
                "author_usage_rows",
                "generation",
            ]
        );
        assert_eq!(
            proof_usage.columns,
            &[
                "usage_id",
                "total_count",
                "total_bytes",
                "total_links",
                "pending_count",
                "pending_bytes",
                "generation",
            ]
        );
    }

    #[test]
    fn semantic_policy_sqlite_envelope_has_checked_boundaries() {
        let mut policy = SemanticPolicyConfig::default();
        policy.max_uncheckpointed_wal_frames = SQLITE_SHM_FIRST_CHUNK_FRAMES - 1;
        policy.max_transaction_dirty_main_pages = 1;
        policy.wal_checkpoint_threshold_bytes = SQLITE_WAL_HEADER_BYTES
            + (SQLITE_SHM_FIRST_CHUNK_FRAMES - 1)
                * (SQLITE_DEFAULT_PAGE_SIZE_BYTES + SQLITE_WAL_FRAME_OVERHEAD_BYTES);
        policy.max_wal_bytes = policy.wal_checkpoint_threshold_bytes
            + SQLITE_DEFAULT_PAGE_SIZE_BYTES
            + SQLITE_WAL_FRAME_OVERHEAD_BYTES;
        let mut workload = policy.storage_workload();
        let envelope = policy
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, workload)
            .expect("the first SHM chunk boundary is valid");
        assert_eq!(
            envelope.wal_checkpoint_frames,
            SQLITE_SHM_FIRST_CHUNK_FRAMES - 1
        );
        assert_eq!(envelope.wal_hard_frames, SQLITE_SHM_FIRST_CHUNK_FRAMES);
        assert_eq!(envelope.shm_bytes, SQLITE_SHM_CHUNK_BYTES);
        assert!(policy.wal_checkpoint_threshold_bytes <= envelope.wal_bytes);
        policy.max_uncheckpointed_wal_frames = SQLITE_SHM_FIRST_CHUNK_FRAMES;
        policy.wal_checkpoint_threshold_bytes = SQLITE_WAL_HEADER_BYTES
            + SQLITE_SHM_FIRST_CHUNK_FRAMES
                * (SQLITE_DEFAULT_PAGE_SIZE_BYTES + SQLITE_WAL_FRAME_OVERHEAD_BYTES);
        policy.max_wal_bytes = policy.wal_checkpoint_threshold_bytes
            + SQLITE_DEFAULT_PAGE_SIZE_BYTES
            + SQLITE_WAL_FRAME_OVERHEAD_BYTES;
        workload = policy.storage_workload();
        let envelope = policy
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, workload)
            .expect("one frame beyond the first SHM chunk is valid");
        assert_eq!(
            envelope.wal_checkpoint_frames,
            SQLITE_SHM_FIRST_CHUNK_FRAMES
        );
        assert_eq!(envelope.wal_hard_frames, SQLITE_SHM_FIRST_CHUNK_FRAMES + 1);
        assert_eq!(envelope.shm_bytes, SQLITE_SHM_CHUNK_BYTES * 2);
        let mut threshold = policy;
        threshold.wal_checkpoint_threshold_bytes = envelope.wal_checkpoint_bytes + 1;
        assert!(threshold
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, workload)
            .is_err());
        workload.max_uncheckpointed_wal_frames = policy.max_uncheckpointed_wal_frames + 1;
        assert!(policy
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, workload)
            .is_err());
        assert!(SemanticPolicyConfig::default()
            .checked_storage_envelope(0, policy.storage_workload())
            .is_err());
        assert!(SemanticPolicyConfig::default()
            .checked_storage_envelope(u64::MAX, policy.storage_workload())
            .is_err());

        let overflow = SemanticPolicyConfig {
            max_database_bytes: u64::MAX,
            emergency_reserve_bytes: u64::MAX,
            ..SemanticPolicyConfig::default()
        };
        assert!(overflow
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, overflow.storage_workload(),)
            .is_err());
    }

    #[test]
    fn semantic_storage_envelope_has_exact_dimension_and_reserve_controls() {
        let policy = SemanticPolicyConfig::default();
        let workload = policy.storage_workload();
        let envelope = policy
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, workload)
            .expect("owner maxima are accepted at the boundary");
        let sum_without_reserve = envelope
            .main_bytes
            .checked_add(envelope.main_journal_bytes)
            .and_then(|v| v.checked_add(envelope.wal_bytes))
            .and_then(|v| v.checked_add(envelope.shm_bytes))
            .expect("component sum");
        assert_eq!(
            envelope.total_bytes,
            sum_without_reserve + envelope.emergency_reserve_bytes,
            "reserve is charged exactly once"
        );

        macro_rules! reject_n_plus_one {
            ($field:ident) => {{
                let mut candidate = workload;
                candidate.$field = policy.$field + 1;
                assert!(
                    policy
                        .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, candidate)
                        .is_err(),
                    "{} N+1 must be refused",
                    stringify!($field)
                );
            }};
        }
        reject_n_plus_one!(max_fact_encoded_bytes);
        reject_n_plus_one!(max_admitted_facts);
        reject_n_plus_one!(max_quarantined_facts);
        reject_n_plus_one!(max_admitted_bytes);
        reject_n_plus_one!(max_quarantined_bytes);
        reject_n_plus_one!(max_dependency_edges);
        reject_n_plus_one!(max_author_usage_rows);
        reject_n_plus_one!(max_proof_records);
        reject_n_plus_one!(max_proof_bytes);
        reject_n_plus_one!(max_proof_links);
        reject_n_plus_one!(max_provisional_rows);
        reject_n_plus_one!(max_transaction_dirty_main_pages);
        reject_n_plus_one!(max_uncheckpointed_wal_frames);
        reject_n_plus_one!(max_freelist_pages);
        reject_n_plus_one!(max_fragmented_pages);
        reject_n_plus_one!(max_main_journal_bytes);
        reject_n_plus_one!(max_live_checkpoint_bytes);
    }

    #[test]
    fn semantic_policy_rejects_zero_and_relationship_violations() {
        let valid = SemanticPolicyConfig::default();

        macro_rules! reject_zero {
            ($field:ident) => {{
                let mut candidate = valid;
                candidate.$field = 0;
                assert!(
                    !candidate.validate(),
                    "zero {} must be rejected",
                    stringify!($field)
                );
                assert!(candidate.checked().is_err());
            }};
        }

        reject_zero!(max_fact_encoded_bytes);
        reject_zero!(max_dependencies_per_fact);
        reject_zero!(max_authority_uses_per_fact);
        reject_zero!(max_authority_predecessors_per_use);
        reject_zero!(max_admitted_facts);
        reject_zero!(max_admitted_bytes);
        reject_zero!(max_quarantined_facts);
        reject_zero!(max_quarantined_bytes);
        reject_zero!(max_quarantined_facts_per_author);
        reject_zero!(max_quarantined_bytes_per_author);
        reject_zero!(max_retained_facts_per_author);
        reject_zero!(max_retained_bytes_per_author);
        reject_zero!(max_hot_history_facts);
        reject_zero!(max_dependency_edges);
        reject_zero!(max_ready_batch);
        reject_zero!(max_pending_proofs);
        reject_zero!(max_pending_proof_bytes);
        reject_zero!(max_proof_records);
        reject_zero!(max_proof_bytes);
        reject_zero!(max_proof_links);
        reject_zero!(max_author_usage_rows);
        reject_zero!(max_provisional_rows);
        reject_zero!(max_transaction_dirty_main_pages);
        reject_zero!(max_uncheckpointed_wal_frames);
        reject_zero!(max_freelist_pages);
        reject_zero!(max_fragmented_pages);
        reject_zero!(max_main_journal_bytes);
        reject_zero!(max_live_checkpoint_bytes);
        reject_zero!(max_database_bytes);
        reject_zero!(max_wal_bytes);
        reject_zero!(wal_checkpoint_threshold_bytes);
        reject_zero!(emergency_reserve_bytes);

        let mut overflow = valid;
        overflow.max_admitted_bytes = u64::MAX;
        assert!(
            !overflow.validate(),
            "retained-byte addition must be checked"
        );
        overflow = valid;
        overflow.max_fact_encoded_bytes = u64::MAX;
        assert!(!overflow.validate(), "fact receive ceiling must be checked");

        let mut relation = valid;
        relation.max_quarantined_facts_per_author = valid.max_quarantined_facts + 1;
        assert!(
            !relation.validate(),
            "per-author fact count cannot exceed global"
        );
        relation = valid;
        relation.max_quarantined_bytes_per_author = valid.max_quarantined_bytes + 1;
        assert!(
            !relation.validate(),
            "per-author bytes cannot exceed global"
        );
        relation = valid;
        relation.max_quarantined_facts_per_author = valid.max_retained_facts_per_author + 1;
        assert!(
            !relation.validate(),
            "quarantine facts cannot exceed retained author cap"
        );
        relation = valid;
        relation.max_quarantined_bytes_per_author = valid.max_retained_bytes_per_author + 1;
        assert!(
            !relation.validate(),
            "quarantine bytes cannot exceed retained author cap"
        );
        relation = valid;
        relation.max_retained_facts_per_author =
            valid.max_admitted_facts + valid.max_quarantined_facts + 1;
        assert!(
            !relation.validate(),
            "retained facts must fit combined global capacity"
        );
        relation = valid;
        relation.max_retained_bytes_per_author =
            valid.max_admitted_bytes + valid.max_quarantined_bytes + 1;
        assert!(
            !relation.validate(),
            "retained bytes must fit combined global capacity"
        );
        relation = valid;
        relation.max_dependencies_per_fact = valid.max_dependency_edges + 1;
        assert!(
            !relation.validate(),
            "dependency structure must fit edge budget"
        );
        relation = valid;
        relation.max_authority_uses_per_fact = valid.max_dependency_edges + 1;
        assert!(
            !relation.validate(),
            "authority-use structure must fit edge budget"
        );
        relation = valid;
        relation.max_authority_predecessors_per_use = valid.max_dependency_edges + 1;
        assert!(
            !relation.validate(),
            "authority predecessor structure must fit edge budget"
        );
        relation = valid;
        relation.max_ready_batch = valid.max_pending_proofs + 1;
        assert!(
            !relation.validate(),
            "ready batch must fit pending-proof count"
        );
        relation = valid;
        relation.max_admitted_bytes = valid.max_fact_encoded_bytes - 1;
        assert!(!relation.validate(), "one fact must fit admitted bytes");
        relation = valid;
        relation.max_quarantined_bytes = valid.max_fact_encoded_bytes - 1;
        assert!(!relation.validate(), "one fact must fit quarantine bytes");
        relation = valid;
        relation.max_pending_proof_bytes = valid.max_fact_encoded_bytes - 1;
        assert!(
            !relation.validate(),
            "one fact must fit pending-proof bytes"
        );
        relation = valid;
        relation.max_pending_proofs = valid.max_proof_records + 1;
        assert!(
            !relation.validate(),
            "pending proofs must fit total proof count"
        );
        relation = valid;
        relation.max_pending_proof_bytes = valid.max_proof_bytes + 1;
        assert!(
            !relation.validate(),
            "pending proof bytes must fit total proof bytes"
        );
        relation = valid;
        relation.max_proof_bytes = valid.max_fact_encoded_bytes - 1;
        assert!(!relation.validate(), "one fact must fit total proof bytes");

        relation = valid;
        relation.max_wal_bytes = valid.max_wal_bytes - 1;
        assert!(
            !relation.validate(),
            "WAL frame workload must fit the WAL ceiling"
        );
        relation = valid;
        relation.max_database_bytes = valid.emergency_reserve_bytes - 1;
        assert!(
            !relation.validate(),
            "database must retain the emergency reserve"
        );
        assert!(valid
            .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, valid.storage_workload(),)
            .is_ok());
    }

    fn transaction_test_path(label: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let id = NEXT.fetch_add(1, Ordering::Relaxed);
        std::env::temp_dir().join(format!(
            "myownmesh-config-{}-{}-{}.json",
            label,
            std::process::id(),
            id
        ))
    }

    fn transaction_lock_path(path: &Path) -> PathBuf {
        let mut name = path
            .file_name()
            .expect("transaction test path has a file name")
            .to_os_string();
        name.push(".lock");
        path.with_file_name(name)
    }

    fn remove_transaction_test_files(path: &Path) {
        let _ = std::fs::remove_file(path);
        let _ = std::fs::remove_file(transaction_lock_path(path));
    }

    fn transaction_marker_path(path: &Path, marker: &str) -> PathBuf {
        let mut name = path
            .file_name()
            .expect("transaction test path has a file name")
            .to_os_string();
        name.push(format!(".{marker}"));
        path.with_file_name(name)
    }

    fn wait_for_transaction_marker(path: &Path) {
        for _ in 0..200 {
            if path.exists() {
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        panic!(
            "timed out waiting for transaction marker {}",
            path.display()
        );
    }

    #[test]
    fn default_is_current_with_defaults() {
        let cfg = MeshConfig::default();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert_eq!(
            cfg.event_capacity_usize()
                .expect("default mesh event capacity is valid"),
            DEFAULT_MESH_EVENT_CAPACITY as usize
        );
        assert!(cfg.auto_update.enabled);
        assert_eq!(cfg.auto_update.channel, "stable");
        // Alpha default: ride every release.
        assert_eq!(cfg.auto_update.auto_apply, "all");
        assert_eq!(cfg.auto_update.check_interval_hours, 6);
        assert_eq!(cfg.auto_update.feed_request_timeout_ms, 15_000);
        assert_eq!(cfg.auto_update.artifact_download_timeout_ms, 300_000);
        assert!(cfg.auto_update.validate().is_ok());
        assert!(cfg.daemon.enabled);
        assert!(cfg.networks.is_empty());
    }

    #[test]
    fn mesh_config_requires_explicit_version_and_defaults_only_optional_fields() {
        assert!(serde_json::from_value::<MeshConfig>(serde_json::json!({})).is_err());

        let mut missing_version = serde_json::to_value(MeshConfig::default()).unwrap();
        missing_version
            .as_object_mut()
            .expect("mesh config serializes as an object")
            .remove("version");
        assert!(serde_json::from_value::<MeshConfig>(missing_version).is_err());

        let minimal: MeshConfig = serde_json::from_value(serde_json::json!({
            "version": CONFIG_VERSION
        }))
        .expect("current V4 version is the required field");
        assert_eq!(minimal, MeshConfig::default());

        let old: MeshConfig = serde_json::from_value(serde_json::json!({ "version": 1 }))
            .expect("version is syntactically valid before policy refusal");
        assert!(require_current_version(old).is_err());
        let future: MeshConfig =
            serde_json::from_value(serde_json::json!({ "version": CONFIG_VERSION + 1 }))
                .expect("future version is syntactically valid before policy refusal");
        assert!(require_current_version(future).is_err());
    }

    #[test]
    fn configured_event_capacities_reject_zero_and_platform_overflow() {
        fn assert_capacity_refusal(result: Result<usize>, field: &str) {
            match result {
                Err(Error::Config(message)) => assert!(message.contains(field)),
                other => panic!("expected typed config refusal for {field}, got {other:?}"),
            }
        }

        let zero = NetworkConfig {
            event_capacity: 0,
            ..NetworkConfig::from_network_id("zero", "zero")
        };
        assert_capacity_refusal(zero.event_capacity_usize(), "event_capacity");

        let mesh_zero = MeshConfig {
            event_capacity: 0,
            ..MeshConfig::default()
        };
        assert_capacity_refusal(mesh_zero.event_capacity_usize(), "event_capacity");

        let zero_trace = NetworkConfig {
            connection_trace_capacity: 0,
            ..NetworkConfig::from_network_id("zero-trace", "zero-trace")
        };
        assert_capacity_refusal(
            zero_trace.connection_trace_capacity_usize(),
            "connection_trace_capacity",
        );

        let exact_max = NetworkConfig {
            event_capacity: MAX_NETWORK_BROADCAST_CAPACITY as u64,
            ..NetworkConfig::from_network_id("exact-max", "exact-max")
        };
        assert_eq!(
            exact_max
                .event_capacity_usize()
                .expect("exact event capacity maximum is valid"),
            MAX_NETWORK_BROADCAST_CAPACITY
        );

        let above_max = NetworkConfig {
            event_capacity: (MAX_NETWORK_BROADCAST_CAPACITY as u64) + 1,
            ..NetworkConfig::from_network_id("above-max", "above-max")
        };
        assert_capacity_refusal(above_max.event_capacity_usize(), "event_capacity");

        let mesh_exact_max = MeshConfig {
            event_capacity: MAX_NETWORK_BROADCAST_CAPACITY as u64,
            ..MeshConfig::default()
        };
        assert_eq!(
            mesh_exact_max
                .event_capacity_usize()
                .expect("exact mesh event capacity maximum is valid"),
            MAX_NETWORK_BROADCAST_CAPACITY
        );

        let mesh_above_max = MeshConfig {
            event_capacity: (MAX_NETWORK_BROADCAST_CAPACITY as u64) + 1,
            ..MeshConfig::default()
        };
        assert_capacity_refusal(mesh_above_max.event_capacity_usize(), "event_capacity");

        let exact_trace_max = NetworkConfig {
            connection_trace_capacity: MAX_NETWORK_BROADCAST_CAPACITY as u64,
            ..NetworkConfig::from_network_id("exact-trace-max", "exact-trace-max")
        };
        assert_eq!(
            exact_trace_max
                .connection_trace_capacity_usize()
                .expect("exact trace capacity maximum is valid"),
            MAX_NETWORK_BROADCAST_CAPACITY
        );

        let above_trace_max = NetworkConfig {
            connection_trace_capacity: (MAX_NETWORK_BROADCAST_CAPACITY as u64) + 1,
            ..NetworkConfig::from_network_id("above-trace-max", "above-trace-max")
        };
        assert_capacity_refusal(
            above_trace_max.connection_trace_capacity_usize(),
            "connection_trace_capacity",
        );

        let overflow_trace = NetworkConfig {
            connection_trace_capacity: u64::MAX,
            ..NetworkConfig::from_network_id("overflow-trace", "overflow-trace")
        };
        assert_capacity_refusal(
            overflow_trace.connection_trace_capacity_usize(),
            "connection_trace_capacity",
        );
    }

    #[test]
    fn topology_default_is_full_mesh() {
        // The truthful default: pre-0.2.34 networks all ran a full
        // mesh (the old "ring" only shelved frames). `Ring` now names
        // the shaped ring and is only ever chosen deliberately.
        assert_eq!(TopologyMode::default(), TopologyMode::FullMesh);
    }

    #[test]
    fn old_hard_alpha_config_is_refused_not_migrated() {
        let old = MeshConfig {
            version: 1,
            ..Default::default()
        };
        assert!(require_current_version(old).is_err());
    }

    #[test]
    fn topology_effective_n_preferred_falls_back() {
        let r = TopologyMode::Ring { n_preferred: None };
        assert_eq!(r.effective_n_preferred(), 3);
        let r5 = TopologyMode::Ring {
            n_preferred: Some(5),
        };
        assert_eq!(r5.effective_n_preferred(), 5);
        // Non-Ring topologies don't have an n_preferred — return 0.
        assert_eq!(TopologyMode::FullMesh.effective_n_preferred(), 0);
    }

    #[test]
    fn topology_serde_tags_by_kind() {
        let ring = TopologyMode::Ring {
            n_preferred: Some(3),
        };
        let s = serde_json::to_string(&ring).unwrap();
        assert!(s.contains("\"kind\":\"ring\""), "got: {s}");
        assert!(s.contains("\"n_preferred\":3"));

        let star = TopologyMode::Star {
            hub: "abcdef".into(),
        };
        let s = serde_json::to_string(&star).unwrap();
        assert!(s.contains("\"kind\":\"star\""));
        assert!(s.contains("\"hub\":\"abcdef\""));

        let full = TopologyMode::FullMesh;
        let s = serde_json::to_string(&full).unwrap();
        assert!(s.contains("\"kind\":\"full_mesh\""));
    }

    #[test]
    fn hub_tree_scheduler_policy_accepts_valid_tree_and_refuses_invalid_policy() {
        let root = crate::identity::Identity::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[1; 32]),
            "hub-tree-root",
        )
        .public_id()
        .to_owned();
        let hub = crate::identity::Identity::from_signing_key(
            ed25519_dalek::SigningKey::from_bytes(&[2; 32]),
            "hub-tree-hub",
        )
        .public_id()
        .to_owned();

        let mut network = NetworkConfig::from_network_id("hub-tree", "hub-tree-net");
        network.topology = TopologyMode::HubTree {
            root,
            hubs: vec![hub],
            backup_candidates: 0,
        };
        network.tree = Some(TreePolicyConfig {
            max_children: 0,
            max_backups: 0,
            max_pending: 1,
            max_age_ms: 1_000,
        });
        network.hub = Some(HubPolicyConfig {
            max_parallel_dials: 1,
            max_dials_per_pass: 1,
            max_advertisements_per_pass: 1,
            exploration_interval_ms: 4_000,
            max_exploration_probes_per_pass: 1,
            max_exploration_peers_per_reply: 1,
            trickle_imin_ms: 4_000,
            trickle_imax_ms: 8_000,
            trickle_redundancy: 1,
            trickle_reset_window_ms: 8_000,
            trickle_max_resets_per_window: 1,
        });
        network
            .scheduler_policy()
            .expect("valid HubTree policy is accepted");

        let mut missing_hub = network.clone();
        missing_hub.hub = None;
        assert!(missing_hub.scheduler_policy().is_err());

        network.tree = Some(TreePolicyConfig {
            max_pending: 2,
            ..network.tree.expect("tree policy remains present")
        });
        assert!(network.scheduler_policy().is_err());
    }

    #[test]
    fn signaling_defaults_carry_denylist() {
        let s = SignalingConfig::default();
        assert_eq!(s.strategy, "nostr");
        assert_eq!(s.redundancy, DEFAULT_SIGNALING_REDUNDANCY);
        assert!(s.denylist.iter().any(|h| h == "relay.damus.io"));
        assert!(s.nostr_timing.validate());
        assert_eq!(s.nostr_timing.connect_timeout_ms, 30_000);
        assert_eq!(s.nostr_timing.reconnect_initial_ms, 2_000);
        assert_eq!(s.nostr_timing.reconnect_max_ms, 60_000);
    }

    #[test]
    fn nostr_timing_policy_rejects_zero_and_inconsistent_values() {
        let valid = NostrTimingPolicyConfig::default();
        assert!(valid.validate());
        assert!(!NostrTimingPolicyConfig {
            connect_timeout_ms: 0,
            ..valid
        }
        .validate());
        assert!(!NostrTimingPolicyConfig {
            reconnect_initial_ms: 0,
            ..valid
        }
        .validate());
        assert!(!NostrTimingPolicyConfig {
            reconnect_max_ms: valid.reconnect_initial_ms - 1,
            ..valid
        }
        .validate());
        assert!(!NostrTimingPolicyConfig {
            reconnect_max_attempts: 0,
            ..valid
        }
        .validate());
        assert!(!NostrTimingPolicyConfig {
            jitter_percent: 101,
            ..valid
        }
        .validate());
        assert!(!NostrTimingPolicyConfig {
            fallback_activation_grace_ms: valid.fallback_poll_ms - 1,
            ..valid
        }
        .validate());
    }

    #[test]
    fn mdns_policy_omission_uses_current_defaults_and_round_trips() {
        let omitted: SignalingConfig = serde_json::from_str(
            r#"{"strategy":"none","mdns":true,"servers":[],"redundancy":1,"denylist":[],"public_fallback":false}"#,
        )
        .unwrap();
        assert_eq!(omitted.mdns_policy, MdnsPolicyConfig::default());

        let configured = MdnsPolicyConfig {
            max_active_connections: 3,
            max_discovered_peers: 5,
            outbound_queue_capacity: 7,
            max_resolve_owners: 11,
            event_capacity: 13,
            max_event_epochs: 17,
            max_txt_entries: 43,
            max_txt_bytes: 47,
            max_resolved_addresses: 53,
            dial_timeout_ms: 19,
            connection_idle_timeout_ms: 23,
            inbound_idle_timeout_ms: 29,
            reannounce_interval_ms: 31,
            query_deadline_ms: 37,
            accept_error_backoff_ms: 41,
        };
        let signaling = SignalingConfig {
            mdns_policy: configured.clone(),
            ..SignalingConfig::default()
        };
        let encoded = serde_json::to_string(&signaling).unwrap();
        let decoded: SignalingConfig = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.mdns_policy, configured);
    }

    #[test]
    fn mdns_policy_rejects_zero_and_platform_overflow() {
        let zero = MdnsPolicyConfig {
            event_capacity: 0,
            ..MdnsPolicyConfig::default()
        };
        assert!(!zero.validate());
        let zero_backoff = MdnsPolicyConfig {
            accept_error_backoff_ms: 0,
            ..MdnsPolicyConfig::default()
        };
        assert!(!zero_backoff.validate());

        let semaphore_max = u64::try_from(tokio::sync::Semaphore::MAX_PERMITS)
            .expect("Tokio semaphore ceiling fits persisted u64 limits");
        let over_active = MdnsPolicyConfig {
            max_active_connections: semaphore_max + 1,
            ..MdnsPolicyConfig::default()
        };
        assert!(!over_active.validate());
        let over_outbound = MdnsPolicyConfig {
            outbound_queue_capacity: semaphore_max + 1,
            ..MdnsPolicyConfig::default()
        };
        assert!(!over_outbound.validate());
        let over_events = MdnsPolicyConfig {
            event_capacity: semaphore_max + 1,
            ..MdnsPolicyConfig::default()
        };
        assert!(!over_events.validate());

        for (field, policy) in [
            (
                "max_txt_entries",
                MdnsPolicyConfig {
                    max_txt_entries: 0,
                    ..MdnsPolicyConfig::default()
                },
            ),
            (
                "max_txt_bytes",
                MdnsPolicyConfig {
                    max_txt_bytes: 0,
                    ..MdnsPolicyConfig::default()
                },
            ),
            (
                "max_resolved_addresses",
                MdnsPolicyConfig {
                    max_resolved_addresses: 0,
                    ..MdnsPolicyConfig::default()
                },
            ),
        ] {
            assert!(!policy.validate(), "zero {field} must be rejected");
        }
        let over_txt_bytes = MdnsPolicyConfig {
            max_txt_bytes: u16::MAX as u64 + 1,
            ..MdnsPolicyConfig::default()
        };
        assert!(!over_txt_bytes.validate());

        if usize::BITS < 64 {
            let overflow = MdnsPolicyConfig {
                max_event_epochs: u64::MAX,
                ..MdnsPolicyConfig::default()
            };
            assert!(!overflow.validate());
            for (field, policy) in [
                (
                    "max_txt_entries",
                    MdnsPolicyConfig {
                        max_txt_entries: u64::MAX,
                        ..MdnsPolicyConfig::default()
                    },
                ),
                (
                    "max_resolved_addresses",
                    MdnsPolicyConfig {
                        max_resolved_addresses: u64::MAX,
                        ..MdnsPolicyConfig::default()
                    },
                ),
            ] {
                assert!(!policy.validate(), "overflow {field} must be rejected");
            }
        }
    }

    #[test]
    fn retired_application_transit_config_fields_are_rejected() {
        for field in [
            "closed_relay",
            "application_transport",
            "endpoint_cipher",
            "routing_policy",
        ] {
            for value in [
                serde_json::Value::Null,
                serde_json::json!({}),
                serde_json::json!({"enabled": false}),
                serde_json::json!({"enabled": true}),
            ] {
                let mut encoded = serialized_network("retired", "retired-net");
                encoded.as_object_mut().unwrap().insert(field.into(), value);
                let error = serde_json::from_value::<NetworkConfig>(encoded).unwrap_err();
                let message = error.to_string();
                assert!(
                    message.contains("unknown field") && message.contains(field),
                    "{message}"
                );
            }
        }
        let mut encoded = serde_json::to_value(introduction_policy_fixture()).unwrap();
        encoded["endpoint_cipher"] = serde_json::json!({});
        assert!(serde_json::from_value::<HubIntroductionPolicyConfig>(encoded).is_err());
    }

    #[test]
    fn round_trip_empty_config() {
        let cfg = MeshConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn mesh_config_rejects_unknown_top_level_fields() {
        let mut value = serde_json::to_value(MeshConfig::default()).unwrap();
        value
            .as_object_mut()
            .expect("mesh config serializes as an object")
            .insert("legacy_network_state".into(), serde_json::json!({}));
        assert!(serde_json::from_value::<MeshConfig>(value).is_err());
    }

    #[test]
    fn network_config_omits_stun_field_picks_up_defaults() {
        // A V4 network record may omit this intentionally optional field and
        // still gets the built-in defaults rather than zero ICE servers.
        let mut json = serialized_network("n1", "test-net");
        let object = json
            .as_object_mut()
            .expect("serialized network is an object");
        object.remove("stun_servers");
        object.remove("turn_servers");
        let cfg: NetworkConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.stun_servers, default_stun_servers());
        assert!(!cfg.stun_servers.is_empty());
        assert!(cfg.stun_servers[0]
            .urls
            .iter()
            .any(|u| u.contains("myownmesh")));
        // TURN is filled in the same way — an omitted field picks up the
        // reference TURN with its guest credential so symmetric-NAT peers
        // connect out of the box.
        assert_eq!(cfg.turn_servers, default_turn_servers());
        assert_eq!(cfg.turn_servers[0].username.as_deref(), Some("guest"));
        assert!(cfg.turn_servers[0].urls[0].contains("myownmesh"));
    }

    #[test]
    fn network_kind_silent_round_trips_and_required_fields_are_enforced() {
        // Explicit `"kind": "silent"` decodes to Silent.
        let mut json = serialized_network("n1", "t");
        json.as_object_mut()
            .expect("serialized network is an object")
            .insert("kind".into(), serde_json::json!("silent"));
        let cfg: NetworkConfig = serde_json::from_value(json).unwrap();
        assert_eq!(cfg.kind, NetworkKind::Silent);
        // A round-trip preserves it.
        let s = serde_json::to_string(&cfg).unwrap();
        assert!(s.contains("\"kind\":\"silent\""), "got: {s}");
        let back: NetworkConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(back.kind, NetworkKind::Silent);

        let mut missing_kind = serialized_network("missing-kind", "t");
        missing_kind
            .as_object_mut()
            .expect("serialized network is an object")
            .remove("kind");
        assert!(serde_json::from_value::<NetworkConfig>(missing_kind).is_err());

        let mut missing_policy = serialized_network("missing-policy", "t");
        missing_policy
            .as_object_mut()
            .expect("serialized network is an object")
            .remove("semantic_policy");
        assert!(serde_json::from_value::<NetworkConfig>(missing_policy).is_err());

        let mut unknown = serialized_network("unknown", "t");
        unknown
            .as_object_mut()
            .expect("serialized network is an object")
            .insert("legacy_member_log".into(), serde_json::json!([]));
        assert!(serde_json::from_value::<NetworkConfig>(unknown).is_err());

        let mut partial_policy = serialized_network("partial-policy", "t");
        partial_policy
            .as_object_mut()
            .expect("serialized network is an object")
            .insert("semantic_policy".into(), serde_json::json!({}));
        assert!(serde_json::from_value::<NetworkConfig>(partial_policy).is_err());
    }

    #[test]
    fn mesh_config_with_a_silent_network_round_trips() {
        let mut cfg = MeshConfig::default();
        let mut net = NetworkConfig::from_network_id("support", "cec-support");
        net.kind = NetworkKind::Silent;
        cfg.networks.push(net);
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
        assert_eq!(back.networks[0].kind, NetworkKind::Silent);
    }

    #[test]
    fn turn_servers_opt_out_with_empty_array() {
        // An explicit empty array disables the default reference TURN.
        let mut json = serialized_network("n1", "t");
        json.as_object_mut()
            .expect("serialized network is an object")
            .insert("turn_servers".into(), serde_json::json!([]));
        let cfg: NetworkConfig = serde_json::from_value(json).unwrap();
        assert!(cfg.turn_servers.is_empty());
    }

    #[test]
    fn services_default_off() {
        let s = ServicesConfig::default();
        // A fresh device IS a node by default; the hosted services are
        // all opt-in.
        assert!(s.node.enabled);
        assert!(!s.signaling.enabled);
        assert!(!s.stun.enabled);
        assert!(!s.turn.enabled);
        assert_eq!(s.signaling.port, DEFAULT_SIGNALING_SERVER_PORT);
        assert_eq!(s.stun.port, DEFAULT_STUN_TURN_PORT);
        assert_eq!(s.turn.port, DEFAULT_STUN_TURN_PORT);
        assert_eq!(s.turn.realm, "myownmesh");
        // Signaling ships safe flood-limit defaults.
        assert_eq!(s.signaling.limits, SignalingLimits::default());
        assert!(s.signaling.limits.max_event_rate > 0);
        // TURN bandwidth is unlimited until configured.
        assert_eq!(s.turn.max_bps_per_connection, 0);
    }

    #[test]
    fn services_round_trip() {
        let mut cfg = MeshConfig::default();
        cfg.services.signaling.enabled = true;
        cfg.services.turn.enabled = true;
        cfg.services.turn.public_ip = "203.0.113.7".to_string();
        // Replace the placeholder default with a real operator entry.
        cfg.services.turn.credentials = vec![TurnCredential {
            username: "alice".into(),
            password: "s3cret".into(),
        }];
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
        assert!(back.services.signaling.enabled);
        assert_eq!(back.services.turn.credentials.len(), 1);
        assert_eq!(back.services.turn.credentials[0].username, "alice");
    }

    #[test]
    fn turn_service_default_ships_placeholder_credential() {
        // The default TURN service carries one non-empty placeholder
        // credential so an enabled relay accepts allocations out of the
        // box and users can see the shape to mirror into `turn_servers`.
        let turn = TurnServiceConfig::default();
        assert_eq!(turn.credentials.len(), 1);
        assert!(!turn.credentials[0].username.is_empty());
        assert!(!turn.credentials[0].password.is_empty());
    }

    #[test]
    fn turn_tcp_defaults_roundtrip_and_legacy_omission_preserve_schema_two() {
        let config: TurnServiceConfig = serde_json::from_str("{}").unwrap();
        assert!(!config.tcp_enabled);
        assert!(!config.tls_proxy_enabled);
        assert_eq!(config.tls_proxy_port, 3479);
        assert_eq!(config.tcp_max_connections, 256);
        assert_eq!(config.tcp_max_connections_per_ip, 64);
        assert_eq!(
            config.tcp_auth_timeout().unwrap(),
            Duration::from_millis(30_000)
        );
        assert_eq!(
            config.tcp_idle_timeout().unwrap(),
            Duration::from_millis(600_000)
        );
        assert!(config.validate_tcp().is_ok());
        let mut enabled = config;
        enabled.tcp_enabled = true;
        enabled.tls_proxy_enabled = true;
        enabled.tcp_max_connections = 7;
        enabled.tcp_max_connections_per_ip = 7;
        enabled.tcp_idle_timeout_ms = 1;
        enabled.tcp_auth_timeout_ms = 1;
        assert!(enabled.validate_tcp().is_ok());
        let encoded = serde_json::to_string(&enabled).unwrap();
        assert_eq!(
            serde_json::from_str::<TurnServiceConfig>(&encoded).unwrap(),
            enabled
        );
        assert_eq!(CONFIG_VERSION, 2);
    }

    #[test]
    fn turn_tcp_refuses_zero_overflow_and_per_ip_excess_before_config_use() {
        for bad in 0..10 {
            let mut config = MeshConfig::default();
            match bad {
                0 => config.services.turn.tcp_max_connections = 0,
                1 => config.services.turn.tcp_max_connections_per_ip = 0,
                2 => config.services.turn.tcp_max_connections_per_ip = 257,
                3 => config.services.turn.tcp_idle_timeout_ms = 0,
                4 => config.services.turn.tcp_idle_timeout_ms = u64::MAX,
                5 => config.services.turn.tcp_max_connections = usize::MAX,
                6 => config.services.turn.tls_proxy_port = 0,
                7 => {
                    config.services.turn.tls_proxy_enabled = true;
                    config.services.turn.tls_proxy_port = config.services.turn.port;
                }
                8 => config.services.turn.tcp_auth_timeout_ms = 0,
                _ => config.services.turn.tcp_auth_timeout_ms = u64::MAX,
            }
            assert!(config.services.turn.validate_tcp().is_err(), "case {bad}");
            assert!(require_current_version(config).is_err(), "case {bad}");
        }
    }

    #[test]
    fn turn_dual_listeners_require_positive_capacity_for_each_class() {
        for (total, per_ip, accepted) in [(1, 1, false), (2, 1, false), (2, 2, true), (3, 3, true)]
        {
            let mut config = MeshConfig::default();
            config.services.turn.tcp_enabled = true;
            config.services.turn.tls_proxy_enabled = true;
            config.services.turn.tcp_max_connections = total;
            config.services.turn.tcp_max_connections_per_ip = per_ip;
            assert_eq!(config.services.turn.validate_tcp().is_ok(), accepted);
            assert_eq!(require_current_version(config).is_ok(), accepted);
        }
    }

    #[test]
    fn turn_single_listener_preserves_one_connection_limits() {
        for (direct, proxy) in [(true, false), (false, true), (false, false)] {
            let mut config = MeshConfig::default();
            config.services.turn.tcp_enabled = direct;
            config.services.turn.tls_proxy_enabled = proxy;
            config.services.turn.tcp_max_connections = 1;
            config.services.turn.tcp_max_connections_per_ip = 1;
            assert!(config.services.turn.validate_tcp().is_ok());
            assert!(require_current_version(config).is_ok());
        }
    }

    #[test]
    fn turn_tls_proxy_can_be_enabled_without_public_plaintext_tcp() {
        let mut config = TurnServiceConfig {
            tls_proxy_enabled: true,
            ..TurnServiceConfig::default()
        };
        assert!(!config.tcp_enabled);
        assert!(config.validate_tcp().is_ok());
        config.tls_proxy_enabled = false;
        config.tls_proxy_port = config.port;
        assert!(
            config.validate_tcp().is_ok(),
            "disabled backend binds no conflicting port"
        );
    }

    #[test]
    fn invalid_turn_update_preserves_persisted_config_bytes() {
        let path = transaction_test_path("invalid-turn-update");
        let mut config = MeshConfig::default();
        save_config_locked(&path, &config).unwrap();
        let before = std::fs::read(&path).unwrap();
        config.services.turn.tcp_auth_timeout_ms = 0;
        assert!(save_config_locked(&path, &config).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        config.services.turn.tcp_auth_timeout_ms = 30_000;
        let mut network = NetworkConfig::from_network_id("local", "context");
        network.turn_servers[0].urls = vec!["turns:relay.example?transport=udp".into()];
        config.networks.push(network);
        assert!(save_config_locked(&path, &config).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), before);
        remove_transaction_test_files(&path);
    }

    #[test]
    fn turn_url_validation_accepts_only_supported_stream_and_datagram_shapes() {
        for url in [
            "turn:relay.example:3478",
            "turn:relay.example?transport=udp",
            "turn:relay.example:3478?transport=tcp",
            "turns:relay.example",
            "turns:relay.example:5349?transport=tcp",
            "turn:[::1]:3478?transport=tcp",
            "turns:[2001:db8::1]:5349",
            "turn:127.0.0.1:65535",
        ] {
            assert!(validate_turn_url(url).is_ok(), "{url}");
        }
        for url in [
            "",
            "stun:relay.example",
            "https://relay.example",
            "turn://relay.example",
            "turn:",
            "turn:relay.example:0",
            "turn:relay.example:65536",
            "turn:relay.example:",
            "turn:relay.example:+3478",
            "turn:relay.example/path",
            "turn:relay.example#fragment",
            "turn:user:password@relay.example",
            "turns:relay.example?transport=udp",
            "turn:relay.example?transport=sctp",
            "turn:relay.example?transport=tcp&transport=udp",
            "turn:relay.example?x=tcp",
            "turn:relay.example?",
            "turn:[invalid]:3478",
            "turn:::1",
            "turn:[::1]tail",
            "turn:bad host",
            "turn:relay..example",
            "turn:999.1.1.1:3478",
        ] {
            assert!(validate_turn_url(url).is_err(), "{url}");
        }
        let mut network = NetworkConfig::from_network_id("local", "context");
        network.turn_servers[0].urls = vec!["turn:private:password@host".into()];
        let error = network.validate_ice_servers().unwrap_err().to_string();
        assert!(!error.contains("private"));
        assert!(!error.contains("password"));
        let mut config = MeshConfig::default();
        config.networks.push(network);
        assert!(require_current_version(config).is_err());
    }

    #[test]
    fn turn_reference_trio_preserves_opt_out_and_custom_client_choices() {
        let default = default_turn_servers();
        assert_eq!(
            default[0].urls,
            [
                "turn:turn.myownmesh.com:3478?transport=udp",
                "turn:turn.myownmesh.com:3478?transport=tcp",
                "turns:turn.myownmesh.com:5349?transport=tcp",
            ]
        );
        for servers in [
            Vec::new(),
            vec![TurnServer {
                urls: vec!["turn:turn.myownmesh.com:3478".into()],
                username: Some("custom".into()),
                credential: default[0].credential.clone(),
            }],
            vec![TurnServer {
                urls: vec!["turn:turn.myownmesh.com:3478".into()],
                username: default[0].username.clone(),
                credential: Some("custom".into()),
            }],
            vec![TurnServer {
                urls: vec!["turn:turn.myownmesh.com:3478?transport=udp".into()],
                username: default[0].username.clone(),
                credential: default[0].credential.clone(),
            }],
            vec![TurnServer {
                urls: vec!["turns:operator.example:4443?transport=tcp".into()],
                username: Some("operator".into()),
                credential: Some("fixture-only".into()),
            }],
        ] {
            let mut network = NetworkConfig::from_network_id("local", "context");
            network.turn_servers = servers.clone();
            let mut config = MeshConfig::default();
            config.networks.push(network);
            let decoded: MeshConfig =
                serde_json::from_str(&serde_json::to_string(&config).unwrap()).unwrap();
            assert_eq!(
                require_current_version(decoded).unwrap().networks[0].turn_servers,
                servers
            );
        }
    }

    #[test]
    fn exact_reference_turn_upgrade_is_in_version_and_idempotent() {
        let mut network = NetworkConfig::from_network_id("local", "context");
        network.turn_servers[0].urls = vec!["turn:turn.myownmesh.com:3478".into()];
        let mut config = MeshConfig::default();
        config.networks.push(network);
        let encoded = serde_json::to_string(&config).unwrap();
        let normalized = require_current_version(serde_json::from_str(&encoded).unwrap()).unwrap();
        assert_eq!(normalized.version, 2);
        assert_eq!(normalized.networks[0].turn_servers, default_turn_servers());
        assert_eq!(
            require_current_version(normalized.clone()).unwrap(),
            normalized
        );
        let mut wrong_version = config;
        wrong_version.version = 3;
        assert!(require_current_version(wrong_version).is_err());
    }

    #[test]
    fn turn_server_default_credential_matches_client_default() {
        // "Network in a box" only works if an enabled TURN server accepts
        // the credential clients use by default — so the server-side
        // placeholder and the client-side `default_turn_servers` entry
        // must stay in lockstep.
        let server = TurnServiceConfig::default();
        let client = default_turn_servers();
        assert_eq!(server.credentials.len(), 1);
        assert_eq!(client.len(), 1);
        assert_eq!(
            Some(&server.credentials[0].username),
            client[0].username.as_ref()
        );
        assert_eq!(
            Some(&server.credentials[0].password),
            client[0].credential.as_ref()
        );
    }

    #[test]
    fn turn_service_default_relay_range_is_unbounded() {
        // Default must NOT cap the relay out of the box — 0 means "use the
        // OS ephemeral range". Operators opt into a fixed window.
        assert_eq!(TurnServiceConfig::default().relay_port_min, 0);
    }

    #[test]
    fn network_config_empty_stun_array_opts_out() {
        // Writing an explicit empty list must remain empty — the
        // defaults only fire when the field is absent.
        let mut json = serialized_network("n1", "test-net");
        json.as_object_mut()
            .expect("serialized network is an object")
            .insert("stun_servers".into(), serde_json::json!([]));
        let cfg: NetworkConfig = serde_json::from_value(json).unwrap();
        assert!(cfg.stun_servers.is_empty());
    }

    #[test]
    fn config_transaction_serializes_same_process_rmw_union() {
        let path = transaction_test_path("union");
        let active = Arc::new(AtomicBool::new(false));
        let overlap = Arc::new(AtomicBool::new(false));
        let (entered_tx, entered_rx) = mpsc::channel();
        let (first_completed_tx, first_completed_rx) = mpsc::channel();
        let (second_attempt_tx, second_attempt_rx) = mpsc::channel();
        let (second_entered_tx, second_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();

        let first_path = path.clone();
        let first_active = Arc::clone(&active);
        let first = thread::spawn(move || {
            MeshConfig::transaction_at(&first_path, move |config| {
                assert!(!first_active.swap(true, Ordering::SeqCst));
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config
                    .networks
                    .push(NetworkConfig::from_network_id("first", "first-wire"));
                first_active.store(false, Ordering::SeqCst);
                first_completed_tx.send(()).unwrap();
                Ok(())
            })
        });

        entered_rx.recv().unwrap();
        let second_path = path.clone();
        let second_active = Arc::clone(&active);
        let second_overlap = Arc::clone(&overlap);
        let second = thread::spawn(move || {
            second_attempt_tx.send(()).unwrap();
            MeshConfig::transaction_at(&second_path, move |config| {
                second_entered_tx.send(()).unwrap();
                if second_active.swap(true, Ordering::SeqCst) {
                    second_overlap.store(true, Ordering::SeqCst);
                }
                config.services.signaling.enabled = true;
                second_active.store(false, Ordering::SeqCst);
                Ok(())
            })
        });

        second_attempt_rx.recv().unwrap();
        assert!(second_entered_rx
            .recv_timeout(Duration::from_millis(25))
            .is_err());
        release_tx.send(()).unwrap();
        first_completed_rx.recv().unwrap();
        second_entered_rx.recv().unwrap();
        first.join().unwrap().unwrap();
        second.join().unwrap().unwrap();

        let final_config = MeshConfig::transaction_at(&path, |config| Ok(config.clone())).unwrap();
        assert!(!overlap.load(Ordering::SeqCst));
        assert!(final_config.services.signaling.enabled);
        assert_eq!(final_config.networks.len(), 1);
        assert_eq!(final_config.networks[0].id, "first");
        remove_transaction_test_files(&path);
    }

    #[test]
    fn config_transaction_subprocess_worker() {
        let Some(path) = std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_PATH") else {
            return;
        };
        let path = PathBuf::from(path);
        let attempted = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_ATTEMPTED")
                .expect("child attempted marker"),
        );
        let entered = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_ENTERED").expect("child entered marker"),
        );
        let completed = PathBuf::from(
            std::env::var_os("MYOWNMESH_CONFIG_TX_CHILD_COMPLETED")
                .expect("child completed marker"),
        );
        std::fs::write(&attempted, b"attempted").expect("child attempted marker write");
        MeshConfig::transaction_at(&path, |config| {
            std::fs::write(&entered, b"entered").expect("child entered marker write");
            config.services.signaling.enabled = true;
            Ok(())
        })
        .expect("child transaction");
        std::fs::write(&completed, b"completed").expect("child completed marker write");
    }

    #[test]
    fn config_transaction_serializes_cross_process_rmw_union() {
        let path = transaction_test_path("subprocess");
        let attempted = transaction_marker_path(&path, "attempted");
        let entered = transaction_marker_path(&path, "entered");
        let completed = transaction_marker_path(&path, "completed");
        let (parent_entered_tx, parent_entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let parent_path = path.clone();
        let parent = thread::spawn(move || {
            MeshConfig::transaction_at(&parent_path, move |config| {
                parent_entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config
                    .networks
                    .push(NetworkConfig::from_network_id("parent", "parent-wire"));
                Ok(())
            })
        });

        parent_entered_rx.recv().unwrap();
        let executable = std::env::current_exe().expect("current test executable");
        let mut child = Command::new(executable)
            .arg("--exact")
            .arg("config::tests::config_transaction_subprocess_worker")
            .arg("--nocapture")
            .env("MYOWNMESH_CONFIG_TX_CHILD_PATH", path.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_ATTEMPTED", attempted.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_ENTERED", entered.as_os_str())
            .env("MYOWNMESH_CONFIG_TX_CHILD_COMPLETED", completed.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn transaction child");

        wait_for_transaction_marker(&attempted);
        thread::sleep(Duration::from_millis(50));
        assert!(!entered.exists(), "child entered before parent release");
        assert!(child.try_wait().unwrap().is_none(), "child completed early");
        release_tx.send(()).unwrap();
        parent.join().unwrap().unwrap();
        wait_for_transaction_marker(&entered);
        wait_for_transaction_marker(&completed);
        assert!(child.wait().unwrap().success());

        let final_config = MeshConfig::transaction_at(&path, |config| Ok(config.clone())).unwrap();
        assert!(final_config.services.signaling.enabled);
        assert_eq!(final_config.networks.len(), 1);
        assert_eq!(final_config.networks[0].id, "parent");
        remove_transaction_test_files(&path);
        let _ = std::fs::remove_file(attempted);
        let _ = std::fs::remove_file(entered);
        let _ = std::fs::remove_file(completed);
    }

    #[test]
    fn config_transaction_rejects_uncoordinated_replacement() {
        let path = transaction_test_path("cas");
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let transaction_path = path.clone();
        let transaction = thread::spawn(move || {
            MeshConfig::transaction_at(&transaction_path, move |config| {
                entered_tx.send(()).unwrap();
                release_rx.recv().unwrap();
                config.services.signaling.enabled = true;
                Ok(())
            })
        });

        entered_rx.recv().unwrap();
        let mut replacement = MeshConfig::default();
        replacement.services.turn.enabled = true;
        save_config_locked(&path, &replacement).unwrap();
        release_tx.send(()).unwrap();
        let error = transaction.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("changed during transaction"));
        remove_transaction_test_files(&path);
    }

    #[test]
    fn prepared_load_rejects_corrupt_to_valid_replacement() {
        let path = transaction_test_path("prepared-identity");
        std::fs::write(&path, b"{ corrupt config").unwrap();
        let transaction = ConfigTransactionLease::acquire(&path).unwrap();
        let file = std::fs::File::open(&path).unwrap();
        let metadata = file.metadata().unwrap();
        let source = PreparedConfigSource::Present {
            len: metadata.len(),
            identity: ConfigFileIdentity::from_file(&file).unwrap(),
            file,
        };

        // A direct atomic replacement is not allowed to make the prepared
        // handle quarantine valid V in place of the corrupt C it measured.
        save_config_locked(&path, &MeshConfig::default()).unwrap();
        assert!(ensure_prepared_source_identity(&path, &source).is_err());

        drop(source);
        drop(transaction);
        remove_transaction_test_files(&path);
    }
}
