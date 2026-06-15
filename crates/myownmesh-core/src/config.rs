//! Config schema for `~/.myownmesh/config.json`. Reading & writing
//! lives here so any caller (binary, library embedder, tests) shares
//! the same parse / default behavior.
//!
//! Schema versioning: a single `version` field on the root. v1 is
//! current; additive changes (new optional fields, new networks)
//! don't bump the version. Field-shape-breaking changes will bump and
//! ship a migration in this module.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};
use crate::identity::DeviceId;

/// Flood-protection limits for the self-hosted signaling relay. Defined
/// in the signaling crate (its natural home) and re-used here so the
/// config, the daemon, and the relay all share one shape.
pub use myownmesh_signaling::server::Limits as SignalingLimits;

pub const CONFIG_VERSION: u32 = 1;

/// Topology selector for a single network. Wire-form matches the
/// JSON-tagged shape; embedders construct these directly.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum TopologyMode {
    /// Default. Auto-healing ring with `n_preferred` neighbors (2
    /// immediate + (n-2) shortcuts). Missing/null `n_preferred`
    /// defaults to 3.
    Ring {
        #[serde(default)]
        n_preferred: Option<u32>,
    },
    /// All spokes route through a single, config-named hub. Hub holds
    /// all peers active; spokes shelve everyone but the hub.
    Star { hub: DeviceId },
    /// Full mesh — every peer keeps every other peer active. N² cost;
    /// only useful for small fixed-size deployments.
    FullMesh,
}

impl Default for TopologyMode {
    fn default() -> Self {
        TopologyMode::Ring { n_preferred: None }
    }
}

impl TopologyMode {
    /// The default `n_preferred` for ring topology (2 immediate +
    /// 1 shortcut). Used when a Ring config omits the field.
    pub const DEFAULT_RING_N_PREFERRED: u32 = 3;

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
        urls: vec!["turn:turn.myownmesh.com:3478".to_string()],
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct SignalingConfig {
    /// Which signaling strategy to use. Only `"nostr"` is supported in
    /// v1; sibling crates can add others (BitTorrent trackers, MQTT,
    /// IPFS, Firebase) and the engine picks via this field.
    pub strategy: String,
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
}

impl Default for SignalingConfig {
    fn default() -> Self {
        Self {
            strategy: "nostr".to_string(),
            servers: Vec::new(),
            redundancy: DEFAULT_SIGNALING_REDUNDANCY,
            denylist: default_signaling_denylist(),
            public_fallback: true,
        }
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

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NetworkConfig {
    /// Local config record id. User-chosen, unique within this
    /// device's config — distinguishes multiple saved entries for
    /// the same wire-level network (different STUN/TURN setups for
    /// the same fleet, etc.).
    pub id: String,
    /// Wire-level rendezvous handle. Normalised via
    /// [`crate::identity::normalize_network_id`] on load.
    pub network_id: String,
    /// Cosmetic display name. Empty falls back to `network_id`.
    #[serde(default)]
    pub label: String,
    /// Initial governance kind for this network. Open is the
    /// default and matches the engine's behaviour through every
    /// release before `network_state_v1` shipped. Closed sets up
    /// the per-network signed state log so the founder
    /// self-elects as `Owner` on first attach. Configs written by
    /// older builds parse via #[serde(default)] without an
    /// explicit field.
    ///
    /// At runtime, the *authoritative* kind is the one in the
    /// signed [`crate::NetworkState`] log; this field is only the
    /// initial value used to bootstrap the log on first attach.
    /// Subsequent kind changes happen via signed transitions, not
    /// by editing config.json.
    #[serde(default)]
    pub kind: crate::network_state::NetworkKind,
    #[serde(default)]
    pub topology: TopologyMode,
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
    /// Override the on-disk roster path. Null = use the default
    /// (`~/.myownmesh/mesh/rosters/{network_id}.json`).
    #[serde(default)]
    pub roster_path: Option<PathBuf>,
    /// When true, every authenticating peer is added to the roster
    /// automatically without user approval. Useful for headless
    /// fleet members; off by default.
    #[serde(default)]
    pub auto_approve: bool,
}

impl NetworkConfig {
    /// Build a config from just the wire-level network id, filling every
    /// other field with its default (reference STUN/TURN, open
    /// governance, default topology, no roster override, manual
    /// approval). The local `id` defaults to the network id. This backs
    /// `myownmesh ctl networks join <network_id>`, which only takes an
    /// id; richer setups go through config.json or the GUI.
    pub fn from_network_id(id: impl Into<String>, network_id: impl Into<String>) -> Self {
        Self {
            id: id.into(),
            network_id: network_id.into(),
            label: String::new(),
            kind: Default::default(),
            topology: Default::default(),
            signaling: Default::default(),
            stun_servers: default_stun_servers(),
            turn_servers: default_turn_servers(),
            roster_path: None,
            auto_approve: false,
        }
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
    pub check_interval_hours: u32,
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
            stable_url: None,
            beta_url: None,
        }
    }
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
/// Everything is off by default — turning a device into an always-on
/// relay, signaling host, or TURN server is an explicit opt-in. When a
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
    pub relay: RelayServiceConfig,
    pub signaling: SignalingServerConfig,
    pub stun: StunServiceConfig,
    pub turn: TurnServiceConfig,
}

/// Whether this device acts as a regular mesh node — i.e. joins its
/// configured networks and participates as a peer. Enabled by default;
/// disable it to run a **pure-infrastructure box** that only hosts
/// signaling / STUN / TURN (advertising itself purely as an edge /
/// ingress-egress point) without joining any network itself. The
/// roster-gated relay forwards traffic *within* networks, so it needs
/// node participation and has no effect when node is off.
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

/// Mesh-member routing. When enabled this device forwards typed-channel
/// traffic between roster members on the reserved
/// [`crate::services::RELAY_CHANNEL`] — turning it into an ingress /
/// egress hub so spokes that can each reach the relay but not each
/// other can still exchange messages. Forwarding is roster-gated: a
/// frame is only relayed when both the sender and the destination are
/// approved peers of this device.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(default)]
pub struct RelayServiceConfig {
    /// Off by default — hosting a relay is opt-in.
    pub enabled: bool,
    /// Ceiling on how many distinct destinations a single inbound frame
    /// may fan out to in broadcast mode. 0 (the default) = unlimited. A
    /// guard against one chatty peer turning the relay into an amplifier.
    pub max_fanout: u32,
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
#[serde(default)]
pub struct MeshConfig {
    pub version: u32,
    /// Override the identity anchor file path. Null = use the default
    /// (`~/.myownmesh/.secrets/identity.json`).
    pub identity_path: Option<PathBuf>,
    pub auto_update: AutoUpdateConfig,
    pub auto_cleanup: AutoCleanupConfig,
    pub daemon: DaemonConfig,
    /// Infrastructure services this device hosts for the mesh
    /// (relay / signaling / STUN / TURN). All off by default.
    pub services: ServicesConfig,
    pub networks: Vec<NetworkConfig>,
}

impl Default for MeshConfig {
    fn default() -> Self {
        Self {
            version: CONFIG_VERSION,
            identity_path: None,
            auto_update: AutoUpdateConfig::default(),
            auto_cleanup: AutoCleanupConfig::default(),
            daemon: DaemonConfig::default(),
            services: ServicesConfig::default(),
            networks: Vec::new(),
        }
    }
}

impl MeshConfig {
    /// Load the config from the default location. Missing file
    /// returns [`MeshConfig::default`] — embedders should call
    /// `save()` afterward if they want the file to exist.
    pub fn load() -> Result<Self> {
        let path = crate::dirs::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let raw = std::fs::read_to_string(&path)
            .map_err(|e| Error::Config(format!("read {}: {e}", path.display())))?;
        let cfg: MeshConfig = serde_json::from_str(&raw)
            .map_err(|e| Error::Config(format!("parse {}: {e}", path.display())))?;
        if cfg.version != CONFIG_VERSION {
            return Err(Error::Config(format!(
                "config version {} unsupported (this build expects v{})",
                cfg.version, CONFIG_VERSION
            )));
        }
        Ok(cfg)
    }

    /// Persist to the default location. Pretty-printed JSON for
    /// easy hand-editing; the file isn't on a hot path.
    pub fn save(&self) -> Result<()> {
        let path = crate::dirs::config_path()?;
        let parent = path.parent().ok_or_else(|| {
            Error::Config(format!("config path has no parent: {}", path.display()))
        })?;
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Config(format!("create {}: {e}", parent.display())))?;
        let serialized = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, serialized)
            .map_err(|e| Error::Config(format!("write {}: {e}", path.display())))?;
        Ok(())
    }

    /// Find a network config by its local `id`.
    pub fn network(&self, id: &str) -> Option<&NetworkConfig> {
        self.networks.iter().find(|n| n.id == id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_v1_with_defaults() {
        let cfg = MeshConfig::default();
        assert_eq!(cfg.version, CONFIG_VERSION);
        assert!(cfg.auto_update.enabled);
        assert_eq!(cfg.auto_update.channel, "stable");
        // Alpha default: ride every release.
        assert_eq!(cfg.auto_update.auto_apply, "all");
        assert_eq!(cfg.auto_update.check_interval_hours, 6);
        assert!(cfg.daemon.enabled);
        assert!(cfg.networks.is_empty());
    }

    #[test]
    fn topology_default_is_ring() {
        let t = TopologyMode::default();
        match t {
            TopologyMode::Ring { n_preferred } => assert!(n_preferred.is_none()),
            _ => panic!("default topology should be ring"),
        }
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
    fn signaling_defaults_carry_denylist() {
        let s = SignalingConfig::default();
        assert_eq!(s.strategy, "nostr");
        assert_eq!(s.redundancy, DEFAULT_SIGNALING_REDUNDANCY);
        assert!(s.denylist.iter().any(|h| h == "relay.damus.io"));
    }

    #[test]
    fn round_trip_empty_config() {
        let cfg = MeshConfig::default();
        let s = serde_json::to_string(&cfg).unwrap();
        let back: MeshConfig = serde_json::from_str(&s).unwrap();
        assert_eq!(cfg, back);
    }

    #[test]
    fn network_config_omits_stun_field_picks_up_defaults() {
        // A user writing a minimal network config without
        // mentioning stun_servers should get the built-in defaults
        // rather than launching with zero ICE servers.
        let json = r#"{
            "id": "n1",
            "network_id": "test-net"
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
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
    fn turn_servers_opt_out_with_empty_array() {
        // An explicit empty array disables the default reference TURN.
        let json = r#"{ "id": "n1", "network_id": "t", "turn_servers": [] }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.turn_servers.is_empty());
    }

    #[test]
    fn services_default_off() {
        let s = ServicesConfig::default();
        // A fresh device IS a node by default; the hosted services are
        // all opt-in.
        assert!(s.node.enabled);
        assert!(!s.relay.enabled);
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
    fn node_defaults_on_for_old_configs() {
        // A config written before the `node` toggle existed must still
        // behave as a node (the field is #[serde(default)] → enabled).
        let json = r#"{ "version": 1, "services": {}, "networks": [] }"#;
        let cfg: MeshConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.services.node.enabled);
    }

    #[test]
    fn config_without_services_field_parses() {
        // A config.json written by a build that predates the services
        // block must still load — the field is #[serde(default)].
        let json = r#"{
            "version": 1,
            "networks": []
        }"#;
        let cfg: MeshConfig = serde_json::from_str(json).unwrap();
        assert_eq!(cfg.services, ServicesConfig::default());
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
        let json = r#"{
            "id": "n1",
            "network_id": "test-net",
            "stun_servers": []
        }"#;
        let cfg: NetworkConfig = serde_json::from_str(json).unwrap();
        assert!(cfg.stun_servers.is_empty());
    }
}
