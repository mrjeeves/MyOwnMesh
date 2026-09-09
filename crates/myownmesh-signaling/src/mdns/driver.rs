//! Concrete mDNS/DNS-SD signaling driver — the LAN-local counterpart
//! of [`crate::nostr::driver`]. Discovery rides DNS-SD (one
//! [`wire::SERVICE_TYPE`] service instance per driver, room handle in
//! TXT); the SDP/candidate exchange rides a unicast TCP connection to
//! the port advertised in SRV, because an SDP with its candidate set
//! is far too large for TXT records.
//!
//! Deliberate properties:
//!
//! - **Clock-free.** No TLS, no timestamps — signaling works on a
//!   host whose wall clock is still at the epoch (a NanoKVM before
//!   its NTP sync), which is exactly the window local claiming has
//!   to cover.
//! - **Untrusted, like a public Nostr room.** Anything on the LAN
//!   can observe the advertisement or inject frames. The engine's
//!   ed25519 mutual-auth handshake over the DTLS channel that this
//!   signaling bootstraps remains the real authentication gate; a
//!   forged frame can at worst waste a handshake attempt.
//! - **Pluggable discovery backend.** The registration/browse half lives
//!   behind [`super::discovery`]: the pure-Rust `mdns-sd` daemon by default
//!   (per-driver socket set, coexists with a system daemon via
//!   SO_REUSEADDR/SO_REUSEPORT), or the platform's own DNS-SD daemon through
//!   the `dnssd` C API on iOS (raw multicast sockets are entitlement-gated
//!   there; mDNSResponder isn't). The exchange below is backend-independent.

use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::OnceLock;
use std::time::Duration;

use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, oneshot, watch, OwnedSemaphorePermit, Semaphore};
#[cfg(test)]
use tokio::sync::{Barrier, Notify};
use tokio::task::{JoinHandle, JoinSet};
use tokio::time::{sleep, timeout};
use tracing::{debug, info, trace, warn};

/// Owner-scoped custody for handles that synchronous `Drop` could not return
/// to the bounded channel reaper. Its capacity is fixed by the driver-owned
/// supervisor/reaper pair, so fallback retention cannot grow with process
/// lifetime or unrelated driver instances.
struct FallbackReaperTasks {
    #[cfg(test)]
    capacity: usize,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    overflow: Mutex<Option<JoinHandle<()>>>,
}

impl FallbackReaperTasks {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            #[cfg(test)]
            capacity,
            tasks: Mutex::new(Vec::with_capacity(capacity)),
            overflow: Mutex::new(None),
        })
    }

    #[cfg(test)]
    fn retain(&self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        let mut tasks = self.tasks.lock();
        if tasks
            .len()
            .checked_add(1)
            .is_none_or(|len| len > self.capacity)
        {
            return Err(task);
        }
        tasks.push(task);
        Ok(())
    }

    #[cfg(test)]
    fn retain_overflow(&self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        let mut overflow = self.overflow.lock();
        if overflow.is_some() {
            Err(task)
        } else {
            *overflow = Some(task);
            Ok(())
        }
    }

    fn take_tasks(&self) -> Vec<JoinHandle<()>> {
        let mut tasks = self.tasks.lock().drain(..).collect::<Vec<_>>();
        if let Some(task) = self.overflow.lock().take() {
            tasks.push(task);
        }
        tasks
    }

    fn take_all(&self) -> Vec<JoinHandle<()>> {
        self.take_tasks()
    }
}

#[cfg(test)]
static TEST_REAPED_FALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_REAPED_FALLBACK_WAKE: OnceLock<Notify> = OnceLock::new();

#[cfg(test)]
fn record_reaped_fallback() {
    TEST_REAPED_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    TEST_REAPED_FALLBACK_WAKE
        .get_or_init(Notify::new)
        .notify_one();
}

use super::discovery::{
    Discovery, DiscoveryBackend, DiscoveryConfig, DiscoveryEvent, DiscoveryLimits,
    MdnsTimingProfile,
};
use super::wire::{self, DeviceIdValidator, Frame};
use crate::nostr::handle::derive_room_handle;
#[cfg(test)]
use crate::task_custodian::DedicatedTaskCustodian;
use crate::task_custodian::{CustodianReservation, TaskCustodian};
use crate::{
    CarrierAttribution, ErasedOwner, ErasedSource, Error, InboundSink, OutboundSource, OwnedSignal,
    SignalingMessage,
};

/// Maximum number of accepted or dialed exchanges owned by one driver.
/// Owner-selected finite mDNS workload limits. Defaults preserve the prior
/// profile, while each driver instance now carries the source of truth.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MdnsLimits {
    pub max_active_connections: usize,
    pub max_discovered_peers: usize,
    pub outbound_queue_capacity: usize,
    pub discovery: DiscoveryLimits,
    /// Owner-selected deadlines and cadence shared by all mDNS tasks and
    /// discovery queries.
    pub timing: MdnsTimingProfile,
}

impl Default for MdnsLimits {
    fn default() -> Self {
        Self {
            max_active_connections: 256,
            max_discovered_peers: 1024,
            outbound_queue_capacity: 128,
            discovery: DiscoveryLimits::default(),
            timing: MdnsTimingProfile::default(),
        }
    }
}

impl MdnsLimits {
    pub fn validate(self) -> bool {
        self.max_active_connections > 0
            && self.max_active_connections <= Semaphore::MAX_PERMITS
            && self.max_discovered_peers > 0
            && self.outbound_queue_capacity > 0
            && self.outbound_queue_capacity <= Semaphore::MAX_PERMITS
            && self.discovery.validate()
            && self.timing.validate()
    }
}

/// Exact bounded discovery ownership acquired before a backend starts. The
/// provider receives one lease for the complete envelope so its accounting
/// cannot omit a queue, worker, parser, or retained-address dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryRetention {
    pub event_queue_slots: usize,
    pub resolve_owner_slots: usize,
    pub event_epoch_slots: usize,
    pub txt_entry_slots: usize,
    pub txt_bytes: usize,
    pub resolved_address_slots: usize,
    pub backend_task_slots: usize,
    pub native_worker_slots: usize,
    /// The outer driver's four root tasks, supervisor, and supervisor reaper.
    /// Backend-internal custody remains separately represented by
    /// `backend_task_slots`/`native_worker_slots`.
    pub outer_driver_task_slots: usize,
    /// Maximum number of task handles held by the driver's root-task Vec.
    /// Embedded discovery contributes one backend supervisor in addition to
    /// the four outer roots; system discovery contributes none.
    pub outer_driver_handle_slots: usize,
    /// The stop and completion oneshot cells owned by the driver supervisor.
    pub outer_driver_stop_signal_slots: usize,
    pub outer_driver_done_signal_slots: usize,
    /// The bounded supervisor-reaper channel and its fallback storage.
    pub outer_driver_reaper_queue_slots: usize,
    /// The independent two-slot observer reserved for the supervisor fallback
    /// and reaper handles when primary custody refuses.
    pub outer_driver_external_reaper_slots: usize,
    pub outer_driver_fallback_slots: usize,
    pub outer_driver_fallback_overflow_slots: usize,
    /// One watch channel carries cancellation to the four outer roots.
    pub outer_driver_cancel_signal_slots: usize,
    /// Bounded state retained by the selected DNS-SD dependency itself. This
    /// remains distinct from application tasks and native workers, even when
    /// a backend's conservative numeric bounds coincide.
    pub opaque_dependency_slots: usize,
    pub scratch_bytes: usize,
}

/// Exact caller-funded custody split for one driver. The driver owner carries
/// only the two final driver handles; the embedded backend receives its own
/// owner because it has an independent observer/runtime envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DriverCustodyPlan {
    pub outer_driver_handle_slots: usize,
    pub backend_runtime_slots: usize,
    pub backend_observer_slots: usize,
    pub backend_queue_slots: usize,
    pub reaper_observer_runtime_slots: usize,
    pub reaper_observer_task_slots: usize,
    pub reaper_observer_queue_slots: usize,
}

/// Derive the checked custody split consumed before any driver/backend task
/// is spawned. The reaper observer dimensions are the exact dedicated-owner
/// envelope used by the injected driver owner, not an additional allocation.
pub fn checked_driver_custody_plan(
    limits: DiscoveryLimits,
    backend: DiscoveryBackend,
) -> Result<DriverCustodyPlan, AliasRefusal> {
    let retention = DiscoveryRetention::from_backend(limits, backend)?;
    let (backend_runtime_slots, backend_observer_slots, backend_queue_slots) =
        checked_backend_custody_dimensions(backend)?;
    Ok(DriverCustodyPlan {
        outer_driver_handle_slots: retention.outer_driver_handle_slots,
        backend_runtime_slots,
        backend_observer_slots,
        backend_queue_slots,
        reaper_observer_runtime_slots: 1,
        reaper_observer_task_slots: 2,
        reaper_observer_queue_slots: 2,
    })
}

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
fn checked_backend_custody_dimensions(
    backend: DiscoveryBackend,
) -> Result<(usize, usize, usize), AliasRefusal> {
    match backend {
        DiscoveryBackend::Embedded => {
            let plan = super::discovery::checked_embedded_custody_plan()
                .ok_or_else(|| AliasRefusal::Arithmetic("invalid embedded custody plan".into()))?;
            Ok((plan.runtime_slots, plan.observer_slots, plan.queue_slots))
        }
        DiscoveryBackend::System => Ok((0, 0, 0)),
    }
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
fn checked_backend_custody_dimensions(
    _backend: DiscoveryBackend,
) -> Result<(usize, usize, usize), AliasRefusal> {
    Ok((0, 0, 0))
}

impl DiscoveryRetention {
    /// Derive every retained discovery dimension from the caller's finite
    /// backend limits, rejecting invalid values or checked arithmetic loss.
    pub fn from_limits(limits: DiscoveryLimits) -> Result<Self, AliasRefusal> {
        Self::from_backend(limits, DiscoveryBackend::Embedded)
    }

    /// Derive retention from the exact backend selected by the build. The
    /// backend owns the queue/worker shape, so the provider claim follows its
    /// checked residency plan rather than duplicating a hidden formula here.
    pub fn from_backend(
        limits: DiscoveryLimits,
        backend: DiscoveryBackend,
    ) -> Result<Self, AliasRefusal> {
        if !limits.validate() {
            return Err(AliasRefusal::Arithmetic("invalid discovery limits".into()));
        }
        let residency = limits
            .checked_residency(backend)
            .map_err(|error| AliasRefusal::Arithmetic(error.to_string()))?;
        let native_worker_slots = match backend {
            DiscoveryBackend::Embedded => 0,
            DiscoveryBackend::System => residency
                .resolve_owner_slots
                .checked_add(2)
                .ok_or_else(|| AliasRefusal::Arithmetic("native worker slots overflow".into()))?,
        };
        // Four outer roots (browse, outbound, accept, re-announce), one
        // supervisor, and one supervisor reaper. Keep this checked even
        // though the present constants total six: changing the spawn graph
        // must not silently wrap the provider-facing envelope.
        let outer_driver_task_slots = 4usize
            .checked_add(1)
            .and_then(|slots| slots.checked_add(1))
            .ok_or_else(|| AliasRefusal::Arithmetic("outer driver task slots overflow".into()))?;
        let outer_driver_handle_slots = 4usize
            .checked_add(usize::from(matches!(backend, DiscoveryBackend::Embedded)))
            .ok_or_else(|| AliasRefusal::Arithmetic("outer driver handle slots overflow".into()))?;
        let outer_driver_stop_signal_slots = 1;
        let outer_driver_done_signal_slots = 1;
        let outer_driver_reaper_queue_slots = 1;
        let outer_driver_external_reaper_slots = 2;
        let outer_driver_fallback_slots = 2;
        let outer_driver_fallback_overflow_slots = 1;
        let outer_driver_cancel_signal_slots = 1;
        Ok(Self {
            event_queue_slots: residency.event_queue_slots,
            resolve_owner_slots: residency.resolve_owner_slots,
            event_epoch_slots: residency.event_epoch_slots,
            txt_entry_slots: residency.concurrent_txt_entry_slots,
            txt_bytes: residency.concurrent_scratch_bytes,
            resolved_address_slots: residency.concurrent_address_slots,
            backend_task_slots: match backend {
                DiscoveryBackend::Embedded => 3,
                DiscoveryBackend::System => 0,
            },
            native_worker_slots,
            outer_driver_task_slots,
            outer_driver_handle_slots,
            outer_driver_stop_signal_slots,
            outer_driver_done_signal_slots,
            outer_driver_reaper_queue_slots,
            outer_driver_external_reaper_slots,
            outer_driver_fallback_slots,
            outer_driver_fallback_overflow_slots,
            outer_driver_cancel_signal_slots,
            opaque_dependency_slots: residency.opaque_residual_slots,
            scratch_bytes: residency.concurrent_scratch_bytes,
        })
    }
}

/// Configuration for one driver instance.
#[derive(Clone)]
pub struct MdnsDriverConfig {
    /// App-id used in the room-handle derivation — same value the
    /// Nostr driver uses, so both transports converge on one room
    /// per `(app_id, network_id)`.
    pub app_id: String,
    /// Network id (the user-facing identifier; the room handle is
    /// derived from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey surfaced
    /// by the mesh layer).
    pub device_id: String,
    /// Port for the TCP exchange listener. 0 (the default) binds an
    /// ephemeral port; the actual port is advertised via SRV.
    pub service_port: u16,
    /// Application-owned canonical Device-ID policy. Signaling must not
    /// duplicate the identity representation used by the core crate.
    pub device_id_validator: DeviceIdValidator,
    /// Application-owned custody for every retained service alias.
    pub alias_provider: Arc<dyn AliasProvider>,
    /// Finite owner-selected workload limits used by all driver/backend
    /// registries and queues.
    pub limits: MdnsLimits,
}

impl std::fmt::Debug for MdnsDriverConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MdnsDriverConfig")
            .field("app_id", &self.app_id)
            .field("network_id", &self.network_id)
            .field("device_id", &self.device_id)
            .field("service_port", &self.service_port)
            .finish_non_exhaustive()
    }
}

/// Typed refusal from the application's exact alias custody provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AliasRefusal {
    Provider(String),
    Arithmetic(String),
}

/// The complete pre-admission retention plan for one alias. The application
/// provider charges both content and the fixed structural cells before the
/// alias table is mutated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AliasRetention {
    pub key_capacity: usize,
    pub peer_capacity: usize,
    pub node_bytes: usize,
}

/// Complete pre-admission plan for one retained peer observation. The peer
/// table is intrusive, so these are the exact moved buffers and node rather
/// than an estimate for a collection's hidden bucket capacity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerRetention {
    pub peer_capacity: usize,
    pub address_capacity: usize,
    pub node_bytes: usize,
}

impl PeerRetention {
    fn for_peer(peer: &String, addrs: &Vec<IpAddr>) -> Self {
        Self::from_parts(peer.capacity(), addrs)
    }

    fn from_parts(peer_capacity: usize, addrs: &Vec<IpAddr>) -> Self {
        Self {
            peer_capacity,
            address_capacity: addrs.capacity(),
            node_bytes: std::mem::size_of::<PeerNode>(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        let address_bytes = self
            .address_capacity
            .checked_mul(std::mem::size_of::<IpAddr>())
            .ok_or_else(|| AliasRefusal::Arithmetic("peer address size overflow".into()))?;
        self.peer_capacity
            .checked_add(address_bytes)
            .and_then(|bytes| bytes.checked_add(self.node_bytes))
            .ok_or_else(|| AliasRefusal::Arithmetic("peer content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("peer content size exceeds u64".into()))
    }

    pub fn allocation_count(self) -> std::result::Result<u64, AliasRefusal> {
        let count = 1usize
            .checked_add(usize::from(self.peer_capacity != 0))
            .and_then(|count| count.checked_add(usize::from(self.address_capacity != 0)))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| AliasRefusal::Arithmetic("peer allocation count overflow".into()))?;
        count
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("peer allocation count exceeds u64".into()))
    }
}

/// Exact stream-time custody plan. The fixed queue and worker shape comes
/// from the existing driver constants; no future connection is reserved at
/// discovery time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionRetention {
    pub key_capacity: usize,
    pub node_bytes: usize,
    pub socket_handles: usize,
    pub native_objects: usize,
    pub queue_slots: usize,
    pub worker_tasks: usize,
    pub opaque_allocations: usize,
}

/// Additional exact identity-buffer plan for an inbound stream whose sender
/// is not known until its first validated frame. This is acquired before the
/// sender key enters the intrusive connection registry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectionIdentityRetention {
    pub key_capacity: usize,
}

impl ConnectionIdentityRetention {
    /// Plan the exact identity buffer retained when an inbound peer becomes
    /// known from its first validated frame.
    pub fn for_peer(peer: &str) -> Self {
        Self {
            key_capacity: peer.len(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection identity size exceeds u64".into()))
    }

    pub fn opaque_count(self) -> std::result::Result<u64, AliasRefusal> {
        1u64.checked_add(u64::from(self.key_capacity != 0))
            .ok_or_else(|| {
                AliasRefusal::Arithmetic("connection identity residual count overflow".into())
            })
    }
}

impl ConnectionRetention {
    /// Plan one concrete connection using the exact wire representation of
    /// its known peer, when present.  An inbound stream has no peer key until
    /// its first authenticated frame and therefore contributes no key bytes
    /// to this plan; its identity buffer is planned separately.
    pub fn for_peer(key: Option<&str>, queue_slots: usize) -> Self {
        Self {
            key_capacity: key.map_or(0, str::len),
            node_bytes: std::mem::size_of::<ConnNode>(),
            socket_handles: 2,
            native_objects: 1,
            queue_slots,
            worker_tasks: 2,
            // One channel allocation and one erased provider-owner allocation.
            opaque_allocations: 2,
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .checked_add(self.node_bytes)
            .ok_or_else(|| AliasRefusal::Arithmetic("connection content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection content size exceeds u64".into()))
    }

    pub fn opaque_count(self) -> std::result::Result<u64, AliasRefusal> {
        self.queue_slots
            .checked_add(self.worker_tasks)
            .and_then(|count| count.checked_add(self.opaque_allocations))
            .ok_or_else(|| AliasRefusal::Arithmetic("connection residual count overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("connection residual count exceeds u64".into()))
    }
}

impl AliasRetention {
    fn for_alias(key: &String, peer: &String) -> Self {
        Self {
            key_capacity: key.capacity(),
            peer_capacity: peer.capacity(),
            node_bytes: std::mem::size_of::<AliasNode>(),
        }
    }

    pub fn accounted_bytes(self) -> std::result::Result<u64, AliasRefusal> {
        self.key_capacity
            .checked_add(self.peer_capacity)
            .and_then(|bytes| bytes.checked_add(self.node_bytes))
            .ok_or_else(|| AliasRefusal::Arithmetic("alias content size overflow".into()))?
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("alias content size exceeds u64".into()))
    }

    pub fn allocation_count(self) -> std::result::Result<u64, AliasRefusal> {
        let count = 1usize
            .checked_add(usize::from(self.key_capacity != 0))
            .and_then(|count| count.checked_add(usize::from(self.peer_capacity != 0)))
            .and_then(|count| count.checked_add(1))
            .ok_or_else(|| AliasRefusal::Arithmetic("alias allocation count overflow".into()))?;
        count
            .try_into()
            .map_err(|_| AliasRefusal::Arithmetic("alias allocation count exceeds u64".into()))
    }
}

/// Required application seam for retaining one discovered service alias.
/// The returned owner is held until that exact alias is removed or displaced.
pub trait AliasProvider: Send + Sync {
    /// Reserve the complete bounded discovery envelope before backend start.
    fn retain_discovery(
        &self,
        retention: DiscoveryRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    fn retain_alias(
        &self,
        key: &str,
        peer: &str,
        retention: AliasRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve the exact intrusive peer node and moved endpoint buffers
    /// before the peer registry is changed.
    fn retain_peer(
        &self,
        peer: &str,
        retention: PeerRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve one concrete stream, its fixed queue/task shape, and registry
    /// node immediately before the stream is split or published.
    fn retain_connection(
        &self,
        peer: Option<&str>,
        retention: ConnectionRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;

    /// Reserve the exact sender identity buffer for an inbound stream whose
    /// peer becomes known only after its first validated frame.
    fn retain_connection_identity(
        &self,
        peer: &str,
        retention: ConnectionIdentityRetention,
    ) -> std::result::Result<ErasedOwner, AliasRefusal>;
}

/// Inbound signaling events the driver pushes to the engine.
/// Mirrors [`crate::nostr::driver::NostrInbound`].
#[derive(Debug, Clone)]
pub enum MdnsInbound {
    /// A peer's advertisement resolved (or refreshed) in our room.
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer's advertisement was withdrawn (mDNS goodbye) or its
    /// record expired from the cache.
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer addressed us directly over the TCP exchange.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
/// Mirrors [`crate::nostr::driver::NostrOutbound`].
#[derive(Debug, Clone)]
pub enum MdnsOutbound {
    /// Ensure our advertisement is registered. The registration is
    /// the announce — mDNS handles repetition and query responses —
    /// so repeats are cheap no-ops.
    Announce,
    /// Withdraw the advertisement (sends the mDNS goodbye, which
    /// surfaces as `PeerLeft` on every browser).
    Leave,
    DirectedToPeer {
        to: String,
        msg: SignalingMessage,
    },
}

// Dial, idle, and re-announce deadlines come from `MdnsTimingProfile`.

// An outbound exchange connection is closed after this much idle —
// signaling for one handshake is bursty; anything longer-lived than
// a burst should re-dial.

// Inbound exchange connections use the owner-selected idle deadline.

// The local re-announce cadence is owner-selected; each peer
// still present in the mDNS cache is re-surfaced to the engine as a
// `PeerAnnounced`. This mirrors the Nostr driver's ~60 s steady
// announce heartbeat, which the engine's re-offer pacing expects —
// a peer stuck at Sighted is re-offered on announce arrivals.

/// Return the discovery backend selected by the target and feature set.
///
/// This is the single selector shared by driver startup and higher-level
/// adapters, so retention and backend-owner decisions cannot drift apart.
pub fn configured_discovery_backend() -> DiscoveryBackend {
    #[cfg(any(target_os = "ios", feature = "system-dnssd"))]
    {
        DiscoveryBackend::System
    }
    #[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
    {
        DiscoveryBackend::Embedded
    }
}

/// Start the driver. Fails fast if the mDNS daemon or the TCP
/// listener can't come up (unlike Nostr, the fallible setup here is
/// synchronous) — callers keep their engine-side receiver and can
/// fall back to other transports.
#[cfg(test)]
pub fn start<S>(
    config: MdnsDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<MdnsInbound>,
) -> crate::Result<MdnsDriverHandle>
where
    S: OutboundSource<MdnsOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    let owner = DedicatedTaskCustodian::new(2)
        .map_err(|error| Error::Other(format!("mDNS custodian unavailable: {error:?}")))?;
    let reaper_owner = DedicatedTaskCustodian::new(2)
        .map_err(|error| Error::Other(format!("mDNS reaper custodian unavailable: {error:?}")))?;
    // Only the selected backend is compiled; match its custody construction here.
    #[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
    let backend_owner = {
        let plan = super::discovery::checked_embedded_custody_plan()
            .ok_or_else(|| Error::Other("invalid embedded custody plan".into()))?;
        Some(
            DedicatedTaskCustodian::new(plan.observer_slots).map_err(|error| {
                Error::Other(format!("mDNS backend custodian unavailable: {error:?}"))
            })? as Arc<dyn TaskCustodian>,
        )
    };
    #[cfg(any(target_os = "ios", feature = "system-dnssd"))]
    let backend_owner = {
        let capacity = config
            .limits
            .discovery
            .max_resolve_owners
            .checked_add(2)
            .ok_or_else(|| Error::Other("invalid system worker capacity".into()))?;
        Some(DedicatedTaskCustodian::new(capacity).map_err(|error| {
            Error::Other(format!("mDNS system custodian unavailable: {error:?}"))
        })? as Arc<dyn TaskCustodian>)
    };
    start_with_custodian(
        config,
        outbound,
        inbound_tx,
        owner,
        backend_owner,
        reaper_owner,
    )
}

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
fn start_discovery_with_custodian(
    config: &DiscoveryConfig,
    backend_custodian_owner: Option<Arc<dyn TaskCustodian>>,
) -> crate::Result<(Discovery, mpsc::Receiver<DiscoveryEvent>)> {
    let owner = backend_custodian_owner.ok_or_else(|| {
        Error::Other("embedded discovery requires provider-funded task custody".into())
    })?;
    Discovery::start_with_custodian(config, owner)
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
fn start_discovery_with_custodian(
    config: &DiscoveryConfig,
    backend_custodian_owner: Option<Arc<dyn TaskCustodian>>,
) -> crate::Result<(Discovery, mpsc::Receiver<DiscoveryEvent>)> {
    let owner = backend_custodian_owner.ok_or_else(|| {
        Error::Other("system discovery requires provider-funded task custody".into())
    })?;
    Discovery::start_with_custodian(config, owner)
}

/// Start with lifecycle-owned bounded custody for final driver handles.
pub fn start_with_custodian<S>(
    config: MdnsDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<MdnsInbound>,
    custodian_owner: Arc<dyn TaskCustodian>,
    backend_custodian_owner: Option<Arc<dyn TaskCustodian>>,
    reaper_custodian_owner: Arc<dyn TaskCustodian>,
) -> crate::Result<MdnsDriverHandle>
where
    S: OutboundSource<MdnsOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    if !(config.device_id_validator)(&config.device_id) {
        return Err(Error::Other("mDNS local device id is not canonical".into()));
    }
    if !config.limits.validate() {
        return Err(Error::Other("invalid mDNS workload limits".into()));
    }
    let discovery_retention =
        DiscoveryRetention::from_backend(config.limits.discovery, configured_discovery_backend())
            .map_err(|refusal| {
            Error::Other(format!("mDNS discovery retention refused: {refusal:?}"))
        })?;
    let discovery_owner = config
        .alias_provider
        .retain_discovery(discovery_retention)
        .map_err(|refusal| {
            Error::Other(format!("mDNS discovery retention refused: {refusal:?}"))
        })?;
    let discovery_owner = Arc::new(Mutex::new(Some(discovery_owner)));
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);

    // TCP exchange listener first — its port goes into the SRV record.
    let std_listener = std::net::TcpListener::bind(("0.0.0.0", config.service_port))
        .map_err(|e| Error::Bind(format!("0.0.0.0:{}", config.service_port), e))?;
    let port = std_listener
        .local_addr()
        .map_err(|e| Error::Bind("local_addr".into(), e))?
        .port();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Error::Bind("set_nonblocking".into(), e))?;

    let instance = wire::instance_name(&room_handle, &config.device_id);
    // Reserve the driver supervisor before Discovery::start or any driver
    // task can spawn. The independent reaper owner below reserves both final
    // reaper paths so refusal of this primary owner remains nonblocking.
    let custodian = custodian_owner
        .reserve(1)
        .map_err(|error| Error::Other(format!("mDNS final-task custodian exhausted: {error:?}")))?;
    let reaper_custodian = reaper_custodian_owner
        .reserve(2)
        .map_err(|error| Error::Other(format!("mDNS reaper custody exhausted: {error:?}")))?;
    // Browse starts inside the backend before the first register, so we never
    // miss a burst of resolves racing our own announce.
    let discovery_config = DiscoveryConfig {
        service_type: wire::SERVICE_TYPE.to_string(),
        instance,
        port,
        txt: wire::txt_properties(&room_handle, &config.device_id),
        limits: config.limits.discovery,
        timing: config.limits.timing,
    };
    let (mut discovery, browse_rx) =
        start_discovery_with_custodian(&discovery_config, backend_custodian_owner)?;
    let discovery_task = discovery.take_task();
    let discovery = Arc::new(discovery);

    // Soft failure (e.g. no usable interface yet) — the re-announce tick
    // retries registration.
    let registered = discovery.register();
    if !registered {
        warn!("mdns register failed (will retry)");
    }

    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..room_handle.len().min(16)],
        port,
        "starting mDNS driver"
    );

    let shared = Arc::new(Shared {
        room_handle,
        device_id: config.device_id,
        device_id_validator: config.device_id_validator,
        alias_provider: config.alias_provider,
        discovery: discovery.clone(),
        discovery_owner: discovery_owner.clone(),
        registered: AtomicBool::new(registered),
        peers: Mutex::new(PeerOwnership::with_max_peers(
            config.limits.max_discovered_peers,
        )),
        aliases: Mutex::new(AliasOwnership::with_max_aliases(
            config.limits.max_discovered_peers,
        )),
        conns: Mutex::new(ConnectionOwnership::default()),
        connection_slots: Arc::new(Semaphore::new(config.limits.max_active_connections)),
        outbound_queue_capacity: config.limits.outbound_queue_capacity,
        timing: config.limits.timing,
        connection_tasks: Arc::new(Mutex::new(Some(JoinSet::new()))),
        #[cfg(test)]
        test_half_gate: Arc::new(Mutex::new(None)),
        stopped: Arc::new(AtomicBool::new(false)),
        // Zero is the permanent exhausted sentinel; live connections start
        // at the first nonzero generation so the first adoption is usable.
        conn_gen: AtomicU64::new(1),
        inbound_tx,
        cancel: watch::channel(false).0,
    });

    let mut tasks = Vec::new();
    if let Some(task) = discovery_task {
        tasks.push(task);
    }

    // Browse pump: mDNS resolutions → peer table + PeerAnnounced/PeerLeft.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_browse(shared, browse_rx).await;
            trace!("mdns browse pump exiting");
        }));
    }

    // Outbound pump: engine events → registration changes + TCP frames.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_outbound(shared, Box::new(ErasedSource::new(outbound))).await;
            trace!("mdns outbound pump exiting");
        }));
    }

    // Accept loop for the TCP exchange.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_accept(shared, std_listener).await;
            trace!("mdns accept loop exiting");
        }));
    }

    // Re-announce tick uses the owner-selected timing profile.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_reannounce(shared).await;
        }));
    }

    let (supervisor_stop, supervisor_stop_rx) = oneshot::channel();
    let (supervisor_done, supervisor_done_rx) = oneshot::channel();
    let supervisor = tokio::spawn(supervise_driver_tasks(
        tasks,
        shared.connection_tasks.clone(),
        supervisor_stop_rx,
        supervisor_done,
    ));
    let fallback_reaper_tasks = FallbackReaperTasks::new(2);
    let (supervisor_reaper, supervisor_reaper_task) =
        spawn_task_reaper(1, Arc::clone(&fallback_reaper_tasks));

    Ok(MdnsDriverHandle {
        discovery,
        stopped: shared.stopped.clone(),
        cancel: shared.cancel.clone(),
        supervisor: Some(supervisor),
        supervisor_reaper: Some(supervisor_reaper),
        supervisor_reaper_task: Some(supervisor_reaper_task),
        fallback_reaper_tasks,
        custodian_owner,
        custodian: Some(custodian),
        reaper_custodian_owner,
        reaper_custodian: Some(reaper_custodian),
        supervisor_stop: Some(supervisor_stop),
        supervisor_done: Some(supervisor_done_rx),
        discovery_owner,
    })
}

/// Handle returned by [`start`]. Drop requests shutdown and cancels every
/// task; all child handles remain owned by the runtime supervisor. Async owners
/// should use [`Self::stop_and_join`] to observe its terminal join.
pub struct MdnsDriverHandle {
    discovery: Arc<Discovery>,
    stopped: Arc<AtomicBool>,
    cancel: watch::Sender<bool>,
    supervisor: Option<JoinHandle<()>>,
    supervisor_reaper: Option<mpsc::Sender<JoinHandle<()>>>,
    supervisor_reaper_task: Option<JoinHandle<()>>,
    fallback_reaper_tasks: Arc<FallbackReaperTasks>,
    custodian_owner: Arc<dyn TaskCustodian>,
    custodian: Option<CustodianReservation>,
    reaper_custodian_owner: Arc<dyn TaskCustodian>,
    reaper_custodian: Option<CustodianReservation>,
    supervisor_stop: Option<oneshot::Sender<()>>,
    supervisor_done: Option<oneshot::Receiver<()>>,
    /// Shared so synchronous Drop keeps the provider lease alive with the
    /// supervisor-owned tasks until their exact joins have been observed.
    discovery_owner: Arc<Mutex<Option<ErasedOwner>>>,
}

impl MdnsDriverHandle {
    fn request_stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        let _ = self.cancel.send(true);
        // Goodbye first (peers get PeerLeft promptly), then shut the
        // backend down (closes the browse stream). The async owner joins
        // tasks after this signal; Drop cancels them if no async owner remains.
        self.discovery.unregister();
        self.discovery.shutdown();
    }

    /// Signal shutdown and join every driver-owned Tokio task.
    pub async fn stop_and_join(mut self) {
        self.request_stop();
        self.request_supervisor_stop();
        if let Some(supervisor) = self.supervisor.take() {
            observe_mdns_task(supervisor, "mDNS supervisor").await;
        }
        if let Some(done) = self.supervisor_done.take() {
            let _ = done.await;
        }
        let reaper = self.supervisor_reaper.take();
        drop(reaper);
        if let Some(reaper_task) = self.supervisor_reaper_task.take() {
            observe_mdns_task(reaper_task, "mDNS task reaper").await;
        }
        reap_fallback_reaper_tasks(&self.fallback_reaper_tasks).await;
        // All driver, connection, and discovery tasks have settled at this
        // point, so releasing the provider lease cannot race backend use.
        let _ = self.discovery_owner.lock().take();
        self.custodian_owner.close();
        self.reaper_custodian_owner.close();
    }

    fn request_supervisor_stop(&mut self) {
        if let Some(stop) = self.supervisor_stop.take() {
            let _ = stop.send(());
        }
    }
}

impl Drop for MdnsDriverHandle {
    fn drop(&mut self) {
        self.request_stop();
        self.request_supervisor_stop();
        let mut custodian = self.custodian.take();
        let mut reaper_custodian = self.reaper_custodian.take();
        if let Some(supervisor) = self.supervisor.take() {
            submit_to_terminal_custody(
                &mut custodian,
                &mut reaper_custodian,
                supervisor,
                "mDNS supervisor",
            );
        }
        drop(self.supervisor_reaper.take());
        if let Some(reaper_task) = self.supervisor_reaper_task.take() {
            // Never route this handle through `fallback_reaper_tasks`: the
            // reaper task owns the code that drains that queue. The separate
            // injected owner has a reserved permit for this terminal handle.
            submit_to_terminal_custody(
                &mut reaper_custodian,
                &mut custodian,
                reaper_task,
                "mDNS external reaper",
            );
        }
    }
}

fn submit_to_terminal_custody(
    primary: &mut Option<CustodianReservation>,
    independent: &mut Option<CustodianReservation>,
    task: JoinHandle<()>,
    context: &str,
) {
    let task = if let Some(primary) = primary.as_mut() {
        match primary.submit(task) {
            Ok(()) => return,
            Err(task) => task,
        }
    } else {
        task
    };
    if let Some(independent) = independent.as_mut() {
        if independent.submit(task).is_ok() {
            return;
        }
    }
    // Reservations are exact and established before spawn. Reaching this
    // branch means an injected lifecycle owner violated that contract; keep
    // the failure explicit instead of blocking, detaching, or dropping the
    // terminal handle on the caller's runtime.
    panic!("{context} terminal custody refused after exact pre-reservation");
}

#[cfg(test)]
fn submit_to_custodian_or_reaper_or_fallback(
    custodian: &mut Option<CustodianReservation>,
    reaper_custodian: &mut Option<CustodianReservation>,
    fallback: &Arc<FallbackReaperTasks>,
    task: JoinHandle<()>,
    context: &str,
) {
    let task = if let Some(custodian) = custodian.as_mut() {
        match custodian.submit(task) {
            Ok(()) => return,
            Err(task) => task,
        }
    } else {
        task
    };
    let task = if let Some(reaper_custodian) = reaper_custodian.as_mut() {
        match reaper_custodian.submit(task) {
            Ok(()) => return,
            Err(task) => task,
        }
    } else {
        task
    };
    retain_or_overflow(fallback, task, context);
}

#[cfg(test)]
fn join_supervisor(
    reaper: &mpsc::Sender<JoinHandle<()>>,
    supervisor: JoinHandle<()>,
    fallback: &Arc<FallbackReaperTasks>,
) {
    match reaper.try_send(supervisor) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(supervisor))
        | Err(tokio::sync::mpsc::error::TrySendError::Closed(supervisor)) => {
            if tokio::runtime::Handle::try_current().is_ok() {
                retain_or_overflow(fallback, supervisor, "mDNS supervisor");
            } else {
                let result = futures::executor::block_on(supervisor);
                if let Err(error) = result {
                    if !error.is_cancelled() {
                        warn!("synchronously reaped mDNS fallback supervisor: {error}");
                    }
                }
                #[cfg(test)]
                record_reaped_fallback();
            }
        }
    }
}

#[cfg(test)]
fn retain_or_overflow(fallback: &Arc<FallbackReaperTasks>, task: JoinHandle<()>, context: &str) {
    let task = match fallback.retain(task) {
        Ok(()) => return,
        Err(task) => task,
    };
    if let Err(task) = fallback.retain_overflow(task) {
        abort_and_observe(task, context);
        #[cfg(test)]
        record_reaped_fallback();
    }
}

#[cfg(test)]
fn abort_and_observe(task: JoinHandle<()>, context: &str) {
    task.abort();
    match futures::executor::block_on(task) {
        Ok(()) => trace!(%context, "aborted task joined normally"),
        Err(error) if error.is_cancelled() => {
            debug!(%context, ?error, "aborted task terminal observed")
        }
        Err(error) if error.is_panic() => warn!(%context, ?error, "aborted task panicked"),
        Err(error) => warn!(%context, ?error, "aborted task failed to join"),
    }
}

async fn reap_fallback_reaper_tasks(fallback: &Arc<FallbackReaperTasks>) {
    let tasks = fallback.take_all();
    for task in tasks {
        observe_mdns_task(task, "mDNS fallback reaper").await;
        #[cfg(test)]
        record_reaped_fallback();
    }
}

async fn observe_mdns_task(task: JoinHandle<()>, context: &str) {
    match task.await {
        Ok(()) => trace!(%context, "task joined normally"),
        Err(error) if error.is_cancelled() => {
            debug!(%context, ?error, "task was cancelled")
        }
        Err(error) if error.is_panic() => warn!(%context, ?error, "task panicked"),
        Err(error) => warn!(%context, ?error, "task failed to join"),
    }
}

fn spawn_task_reaper(
    capacity: usize,
    fallback: Arc<FallbackReaperTasks>,
) -> (mpsc::Sender<JoinHandle<()>>, JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(capacity);
    let task = tokio::spawn(async move {
        reap_owned_tasks(receiver, fallback).await;
    });
    (sender, task)
}

async fn reap_owned_tasks(
    mut receiver: mpsc::Receiver<JoinHandle<()>>,
    fallback: Arc<FallbackReaperTasks>,
) {
    while let Some(task) = receiver.recv().await {
        observe_mdns_task(task, "mDNS driver task").await;
    }
    let tasks = fallback.take_tasks();
    for task in tasks {
        observe_mdns_task(task, "mDNS fallback task").await;
        #[cfg(test)]
        record_reaped_fallback();
    }
}

/// Runtime-owned reaper for every Tokio task created by one driver. The
/// handle intentionally does not retain any child [`JoinHandle`], so dropping
/// it outside an async runtime cannot detach those children or skip custody
/// observation; the reaper consumes, aborts, and joins them exactly once.
async fn supervise_driver_tasks(
    mut tasks: Vec<tokio::task::JoinHandle<()>>,
    connection_tasks: Arc<Mutex<Option<JoinSet<()>>>>,
    supervisor_stop: oneshot::Receiver<()>,
    done: oneshot::Sender<()>,
) {
    let _ = supervisor_stop.await;
    // Let the cancellation watches reach their owners before the hard reaper
    // fence. This is a scheduling handoff only; termination never depends on
    // a timer or an unbounded retry.
    tokio::task::yield_now().await;
    for task in &tasks {
        task.abort();
    }
    while let Some(task) = tasks.pop() {
        observe_mdns_task(task, "mDNS driver task").await;
    }
    let mut connection_tasks = { connection_tasks.lock().take().unwrap_or_default() };
    while let Some(result) = connection_tasks.join_next().await {
        match result {
            Ok(()) => trace!("mDNS connection worker completed during shutdown"),
            Err(error) if error.is_panic() => {
                warn!(?error, "mDNS connection worker panicked during shutdown")
            }
            Err(error) if error.is_cancelled() => {
                debug!(?error, "mDNS connection worker cancelled during shutdown")
            }
            Err(error) => warn!(?error, "mDNS connection worker failed during shutdown"),
        }
    }
    let _ = done.send(());
}

struct Shared {
    room_handle: String,
    device_id: String,
    device_id_validator: DeviceIdValidator,
    alias_provider: Arc<dyn AliasProvider>,
    discovery: Arc<Discovery>,
    discovery_owner: Arc<Mutex<Option<ErasedOwner>>>,
    registered: AtomicBool,
    /// Peers resolved in our room: device id → exchange endpoint.
    peers: Mutex<PeerOwnership>,
    /// Exact backend service aliases grouped by decoded peer. A peer is
    /// withdrawn only after its final alias disappears.
    aliases: Mutex<AliasOwnership>,
    /// Live exchange connections, either direction: device id →
    /// writer. Outbound dials register at connect; inbound accepts
    /// register under the first `from` their frames carry, so a reply
    /// can ride the same socket the request arrived on.
    conns: Mutex<ConnectionOwnership>,
    connection_slots: Arc<Semaphore>,
    outbound_queue_capacity: usize,
    timing: MdnsTimingProfile,
    connection_tasks: Arc<Mutex<Option<JoinSet<()>>>>,
    #[cfg(test)]
    test_half_gate: Arc<Mutex<Option<Arc<TestHalfGate>>>>,
    stopped: Arc<AtomicBool>,
    conn_gen: AtomicU64,
    inbound_tx: InboundSink<MdnsInbound>,
    cancel: watch::Sender<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerEntry {
    addrs: Vec<IpAddr>,
    port: u16,
}

struct PeerNode {
    peer: String,
    entry: PeerEntry,
    owner: ErasedOwner,
    next: Option<Box<PeerNode>>,
}

struct PeerOwnership {
    head: Option<Box<PeerNode>>,
    count: usize,
    max_peers: usize,
}

#[cfg(test)]
impl Default for PeerOwnership {
    fn default() -> Self {
        Self::with_max_peers(MdnsLimits::default().max_discovered_peers)
    }
}

impl PeerOwnership {
    fn with_max_peers(max_peers: usize) -> Self {
        Self {
            head: None,
            count: 0,
            max_peers,
        }
    }

    fn contains(&self, peer: &str) -> bool {
        self.get(peer).is_some()
    }

    fn get(&self, peer: &str) -> Option<PeerEntry> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current.entry.clone());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn keys(&self) -> Vec<String> {
        let mut peers = Vec::with_capacity(self.count);
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            peers.push(current.peer.clone());
            node = current.next.as_deref();
        }
        peers
    }

    fn can_insert(&self, peer: &str) -> std::result::Result<(), AliasRefusal> {
        if self.contains(peer) || self.count < self.max_peers {
            return Ok(());
        }
        Err(AliasRefusal::Provider("peer capacity exhausted".into()))
    }

    fn peer_capacity(&self, peer: &str) -> Option<usize> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current.peer.capacity());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn refresh(
        &mut self,
        peer: &str,
        entry: PeerEntry,
        owner: ErasedOwner,
    ) -> std::result::Result<(), AliasRefusal> {
        if let Some(node) = self.find_mut(peer) {
            node.entry = entry;
            node.owner = owner;
            return Ok(());
        }
        Err(AliasRefusal::Provider("peer refresh lost its node".into()))
    }

    fn insert_new(
        &mut self,
        peer: String,
        entry: PeerEntry,
        owner: ErasedOwner,
    ) -> std::result::Result<(), AliasRefusal> {
        self.can_insert(&peer)?;
        let next = self.head.take();
        self.head = Some(Box::new(PeerNode {
            peer,
            entry,
            owner,
            next,
        }));
        self.count = self
            .count
            .checked_add(1)
            .ok_or_else(|| AliasRefusal::Arithmetic("peer count overflow".into()))?;
        Ok(())
    }

    fn remove(&mut self, peer: &str) -> Option<PeerEntry> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.peer == peer {
                let mut removed = link.take().expect("peer link still present");
                *link = removed.next.take();
                self.count = self.count.checked_sub(1).expect("peer count present");
                return Some(removed.entry);
            }
            link = &mut link.as_mut().expect("peer link present").next;
        }
    }

    fn find_mut(&mut self, peer: &str) -> Option<&mut PeerNode> {
        let mut node = self.head.as_deref_mut();
        while let Some(current) = node {
            if current.peer == peer {
                return Some(current);
            }
            node = current.next.as_deref_mut();
        }
        None
    }
}

/// Exact DNS-SD alias ownership. A decoded peer may be represented by more
/// than one backend service key (for example, one per interface), so one key's
/// removal cannot withdraw the peer while another key remains live.
pub struct AliasOwnership {
    head: Option<Box<AliasNode>>,
    count: usize,
    max_aliases: usize,
}

impl Default for AliasOwnership {
    fn default() -> Self {
        Self::with_max_aliases(MdnsLimits::default().max_discovered_peers)
    }
}

struct AliasNode {
    key: String,
    peer: String,
    generation: u64,
    owner: ErasedOwner,
    next: Option<Box<AliasNode>>,
}

impl AliasOwnership {
    /// Create alias ownership with an explicit finite policy-derived bound.
    pub fn with_max_aliases(max_aliases: usize) -> Self {
        Self {
            head: None,
            count: 0,
            max_aliases,
        }
    }

    /// Bind one exact service key to a decoded peer. Returns an old peer only
    /// when rebinding made that peer lose its final alias.
    pub fn bind(
        &mut self,
        key: String,
        peer: String,
        generation: u64,
        owner: ErasedOwner,
    ) -> std::result::Result<Option<String>, AliasRefusal> {
        let displaced = self
            .peer_for_key(&key)
            .filter(|old_peer| old_peer != &peer)
            .filter(|old_peer| !self.has_other_alias(&key, old_peer));
        let mut cursor = self.head.as_mut();
        while let Some(node) = cursor {
            if node.key == key {
                node.peer = peer;
                node.generation = generation;
                node.owner = owner;
                return Ok(displaced);
            }
            cursor = node.next.as_mut();
        }
        if self.count >= self.max_aliases {
            drop(owner);
            return Err(AliasRefusal::Provider("alias capacity exhausted".into()));
        }
        if self.count == usize::MAX {
            drop(owner);
            return Err(AliasRefusal::Arithmetic("alias count overflow".into()));
        }
        let node = Box::new(AliasNode {
            key,
            peer: peer.clone(),
            generation,
            owner,
            next: self.head.take(),
        });
        self.head = Some(node);
        self.count = self.count.checked_add(1).expect("alias count prechecked");
        Ok(None)
    }

    /// Remove one exact service key. The boolean is true only when its peer
    /// has no remaining aliases.
    pub fn remove(&mut self, key: &str, generation: u64) -> Option<(String, bool)> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.key == key {
                if node.generation != generation {
                    return None;
                }
                let mut removed = link.take().expect("alias link still present");
                *link = removed.next.take();
                self.count = self.count.checked_sub(1).expect("alias count present");
                let peer = removed.peer;
                let last = !self.contains_peer(&peer);
                return Some((peer, last));
            }
            link = &mut link.as_mut().expect("alias link present").next;
        }
    }

    /// Number of aliases currently attached to one decoded peer.
    pub fn alias_count(&self, peer: &str) -> usize {
        let mut count = 0;
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                count += 1;
            }
            node = current.next.as_deref();
        }
        count
    }

    fn contains_peer(&self, peer: &str) -> bool {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer == peer {
                return true;
            }
            node = current.next.as_deref();
        }
        false
    }

    fn has_other_alias(&self, key: &str, peer: &str) -> bool {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.key != key && current.peer == peer {
                return true;
            }
            node = current.next.as_deref();
        }
        false
    }

    fn peer_for_key(&self, key: &str) -> Option<String> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.key == key {
                return Some(current.peer.clone());
            }
            node = current.next.as_deref();
        }
        None
    }
}

#[derive(Clone)]
struct ConnHandle {
    generation: u64,
    tx: mpsc::Sender<OwnedSignal<String, ErasedOwner>>,
    stop: watch::Sender<bool>,
}

struct ConnNode {
    peer: Arc<str>,
    handle: ConnHandle,
    _owner: ErasedOwner,
    next: Option<Box<ConnNode>>,
}

/// Provider custody for one connection remains live until the registry node
/// and both stream halves have retired. A replacement only retires the node;
/// a sibling task still holds its half and therefore keeps the exact owner.
struct ConnectionCustody {
    owner: Mutex<Option<ErasedOwner>>,
    remaining_halves: AtomicUsize,
    retired: AtomicBool,
}

impl ConnectionCustody {
    fn new(owner: ErasedOwner) -> Arc<Self> {
        Arc::new(Self {
            owner: Mutex::new(Some(owner)),
            remaining_halves: AtomicUsize::new(2),
            retired: AtomicBool::new(false),
        })
    }

    fn half(self: &Arc<Self>) -> ConnectionHalf {
        ConnectionHalf {
            custody: Arc::clone(self),
        }
    }

    fn retire(&self) {
        self.retired.store(true, Ordering::Release);
        self.release_if_ready();
    }

    fn release_if_ready(&self) {
        if self.retired.load(Ordering::Acquire)
            && self.remaining_halves.load(Ordering::Acquire) == 0
        {
            let _ = self.owner.lock().take();
        }
    }
}

struct ConnectionCustodyNode {
    custody: Arc<ConnectionCustody>,
}

impl Drop for ConnectionCustodyNode {
    fn drop(&mut self) {
        self.custody.retire();
    }
}

#[cfg(test)]
struct TestHalfGate {
    generation: u64,
    writer_ready: Arc<Barrier>,
    reader_ready: Arc<Barrier>,
    writer_release: Arc<Notify>,
    reader_release: Arc<Notify>,
    writer_exited: Arc<Notify>,
    reader_exited: Arc<Notify>,
}

struct ConnectionHalf {
    custody: Arc<ConnectionCustody>,
}

impl Drop for ConnectionHalf {
    fn drop(&mut self) {
        let previous = self.custody.remaining_halves.fetch_sub(1, Ordering::AcqRel);
        debug_assert!(previous > 0, "connection half retired more than once");
        if previous == 1 {
            self.custody.release_if_ready();
        }
    }
}

#[derive(Default)]
struct ConnectionOwnership {
    head: Option<Box<ConnNode>>,
}

impl ConnectionOwnership {
    fn sender(&self, peer: &str) -> Option<mpsc::Sender<OwnedSignal<String, ErasedOwner>>> {
        let mut node = self.head.as_deref();
        while let Some(current) = node {
            if current.peer.as_ref() == peer {
                return Some(current.handle.tx.clone());
            }
            node = current.next.as_deref();
        }
        None
    }

    fn insert(
        &mut self,
        peer: Arc<str>,
        handle: ConnHandle,
        owner: ErasedOwner,
    ) -> Option<ConnHandle> {
        let displaced = self.remove(&peer, None).map(|node| node.handle);
        self.head = Some(Box::new(ConnNode {
            peer,
            handle,
            _owner: owner,
            next: self.head.take(),
        }));
        displaced
    }

    fn remove(&mut self, peer: &str, generation: Option<u64>) -> Option<ConnNode> {
        let mut link = &mut self.head;
        loop {
            let node = link.as_ref()?;
            if node.peer.as_ref() == peer
                && generation.is_none_or(|generation| node.handle.generation == generation)
            {
                let mut removed = link.take().expect("connection link still present");
                *link = removed.next.take();
                return Some(*removed);
            }
            link = &mut link.as_mut().expect("connection link present").next;
        }
    }

    fn remove_generation(&mut self, peer: &str, generation: u64) {
        let _ = self.remove(peer, Some(generation));
    }
}

/// A connection slot remains occupied until both halves have observed the
/// connection's local stop signal and released their shared owner.
struct ConnectionLease {
    _permit: OwnedSemaphorePermit,
}

fn next_connection_generation(counter: &AtomicU64) -> Option<u64> {
    // MAX is the final valid generation.  Advance to zero only after handing
    // it out; zero is the permanent exhausted sentinel and is never reused
    // for a later connection fence.
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            if value == 0 {
                None
            } else if value == u64::MAX {
                Some(0)
            } else {
                Some(value + 1)
            }
        })
        .ok()
}

/// Reap connection workers while the driver is live. Without this drain a
/// completed worker remains in the JoinSet until shutdown, so sequential
/// connection churn grows the supervisor registry even though the sockets and
/// provider owners have already retired.
fn reap_connection_tasks(shared: &Shared) {
    let mut tasks = shared.connection_tasks.lock();
    let Some(tasks) = tasks.as_mut() else {
        return;
    };
    while let Some(result) = tasks.try_join_next() {
        match result {
            Ok(()) => trace!("mdns connection worker completed"),
            Err(error) if error.is_panic() => warn!(?error, "mdns connection worker panicked"),
            Err(error) if error.is_cancelled() => {
                debug!(?error, "mdns connection worker cancelled")
            }
            Err(error) => warn!(?error, "mdns connection worker failed"),
        }
    }
}

async fn run_browse(shared: Arc<Shared>, mut browse_rx: mpsc::Receiver<DiscoveryEvent>) {
    let _discovery_owner = Arc::clone(&shared.discovery_owner);
    // Stream closes when the backend shuts down.
    let mut cancel = shared.cancel.subscribe();
    loop {
        reap_connection_tasks(&shared);
        let event = tokio::select! {
            event = browse_rx.recv() => event,
            _ = cancel.changed() => return,
        };
        let Some(event) = event else { break };
        if *cancel.borrow() {
            return;
        }
        match event {
            DiscoveryEvent::Resolved {
                generation,
                key,
                mut addrs,
                port,
                txt,
            } => {
                let advert = wire::parse_advert(
                    |k| txt.get(k).cloned(),
                    &shared.room_handle,
                    &shared.device_id,
                    shared.device_id_validator,
                );
                let Some(advert) = advert else { continue };
                if addrs.is_empty() {
                    trace!(peer = %advert.peer, "mdns advert without IPv4 address — skipped");
                    continue;
                }
                addrs.sort();
                let entry = PeerEntry { addrs, port };
                let peer = advert.peer;
                let peers = shared.peers.lock();
                let known = peers.contains(&peer);
                let at_capacity = peers.count >= peers.max_peers;
                let peer_capacity_ok = peers.can_insert(&peer).is_ok();
                let existing_peer_capacity = peers.peer_capacity(&peer);
                drop(peers);
                if (!known && at_capacity) || !peer_capacity_ok {
                    continue;
                }
                let peer_node = (!known).then(|| peer.clone());
                let peer_retention = match peer_node.as_ref() {
                    Some(peer_node) => PeerRetention::for_peer(peer_node, &entry.addrs),
                    None => {
                        PeerRetention::from_parts(existing_peer_capacity.unwrap_or(0), &entry.addrs)
                    }
                };
                let peer_owner = match shared.alias_provider.retain_peer(&peer, peer_retention) {
                    Ok(owner) => owner,
                    Err(refusal) => {
                        debug!(?refusal, "mdns peer retention refused");
                        continue;
                    }
                };
                let retention = AliasRetention::for_alias(&key, &peer);
                let alias_owner = match shared.alias_provider.retain_alias(&key, &peer, retention) {
                    Ok(owner) => owner,
                    Err(refusal) => {
                        drop(peer_owner);
                        debug!(?refusal, "mdns alias retention refused");
                        continue;
                    }
                };
                let bind_result = {
                    let mut aliases = shared.aliases.lock();
                    aliases.bind(key.clone(), peer, generation, alias_owner)
                };
                let (displaced, current_peer) = match bind_result {
                    Ok(displaced) => {
                        let current_peer = shared
                            .aliases
                            .lock()
                            .peer_for_key(&key)
                            .expect("bound alias has a peer");
                        (displaced, current_peer)
                    }
                    Err(refusal) => {
                        drop(peer_owner);
                        debug!(?refusal, "mdns alias bind refused");
                        continue;
                    }
                };
                if let Some(old_peer) = displaced {
                    shared.peers.lock().remove(&old_peer);
                    stop_connection(&shared, &old_peer);
                    debug!(peer = %&old_peer[..old_peer.len().min(16)], "mdns peer lost final alias");
                    if shared
                        .inbound_tx
                        .send(MdnsInbound::PeerLeft {
                            device_id: old_peer,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .is_err()
                    {
                        let _ = shared.cancel.send(true);
                        return;
                    }
                }
                let peer_result = if known {
                    shared
                        .peers
                        .lock()
                        .refresh(&current_peer, entry, peer_owner)
                } else {
                    shared.peers.lock().insert_new(
                        peer_node.expect("new peer node was prepared"),
                        entry,
                        peer_owner,
                    )
                };
                if let Err(refusal) = peer_result {
                    debug!(?refusal, "mdns peer bind refused after pre-admission");
                    return;
                }
                debug!(peer = %&current_peer[..current_peer.len().min(16)], "mdns peer resolved");
                // Every resolve (first sight or cache refresh) surfaces as
                // an announce; the engine is idempotent on repeats, same
                // as with periodic Nostr announces.
                //
                // **`SenderClaimed`, and the mDNS daemon seeing the record is
                // not what makes it otherwise.** The device id here was parsed
                // out of the advertisement's TXT record, which any LAN
                // participant may write with any value: what the daemon
                // established is that *a record* appeared, not whose device it
                // names. The same holds for the expiry and re-surface sites
                // below - withdrawing a record you advertised proves nothing
                // about the device id inside it. Until an mDNS service record
                // carries an independently authenticated binding to the device
                // key, none of this carrier's presence or withdrawal is a
                // carrier-established identity.
                if shared
                    .inbound_tx
                    .send(MdnsInbound::PeerAnnounced {
                        attribution: CarrierAttribution::SenderClaimed,
                        device_id: current_peer,
                    })
                    .is_err()
                {
                    let _ = shared.cancel.send(true);
                    return;
                }
            }
            DiscoveryEvent::Removed { generation, key } => {
                if let Some((peer, last)) = shared.aliases.lock().remove(&key, generation) {
                    if !last {
                        continue;
                    }
                    shared.peers.lock().remove(&peer);
                    stop_connection(&shared, &peer);
                    debug!(peer = %&peer[..peer.len().min(16)], "mdns peer withdrew");
                    if shared
                        .inbound_tx
                        .send(MdnsInbound::PeerLeft {
                            device_id: peer,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .is_err()
                    {
                        let _ = shared.cancel.send(true);
                        return;
                    }
                }
            }
        }
    }
}

async fn run_outbound(
    shared: Arc<Shared>,
    mut source: Box<dyn OutboundSource<MdnsOutbound, Owner = ErasedOwner>>,
) {
    let mut cancel = shared.cancel.subscribe();
    loop {
        reap_connection_tasks(&shared);
        let Some(outbound) = (tokio::select! {
            outbound = source.recv() => outbound,
            _ = cancel.changed() => return,
        }) else {
            break;
        };
        // Dispatched on a borrow. Only the directed arm builds anything, and it
        // is handed the whole owned signal so the encoded line inherits the
        // funding instead of becoming an unowned allocation beside it. The two
        // registration arms build nothing and drop the signal — and its owner —
        // at the end of the iteration.
        if matches!(outbound.value(), MdnsOutbound::DirectedToPeer { .. }) {
            let _ = send_directed(&shared, outbound).await;
            continue;
        }
        let accepted = match outbound.value() {
            MdnsOutbound::Announce => {
                if !shared.registered.load(Ordering::SeqCst) {
                    register(&shared)
                } else {
                    true
                }
                // Already registered: the daemon re-announces and
                // answers queries on its own — nothing to do.
            }
            MdnsOutbound::Leave => {
                if shared.registered.swap(false, Ordering::SeqCst) {
                    shared.discovery.unregister();
                }
                true
            }
            MdnsOutbound::DirectedToPeer { .. } => unreachable!("directed arm handled above"),
        };
        if accepted {
            outbound.accept();
        }
    }
    let _ = shared.cancel.send(true);
    shared.discovery.shutdown();
}

fn register(shared: &Shared) -> bool {
    if shared.discovery.register() {
        shared.registered.store(true, Ordering::SeqCst);
        true
    } else {
        debug!("mdns register retry failed");
        false
    }
}

/// Encode one directed message and get it onto a connection.
///
/// # The encoded line carries the owner, and the writer holds both
///
/// Serializing produces a second allocation the size of the frame. It used to
/// be a bare `String` handed to a writer queue that can park on a slow or dead
/// socket for as long as the connection lasts, with nothing tying that buffer
/// back to whatever admitted the message it came from.
///
/// The encode is a [`OwnedSignal::map`] over the whole signal now, so the line
/// *is* the value and the owner comes with it. The writer queue carries
/// `OwnedSignal<String, ErasedOwner>` and drops an entry only once the write has
/// completed or the connection is gone, so a parked writer keeps its funding
/// live for exactly as long as it keeps the bytes.
async fn send_directed(
    shared: &Arc<Shared>,
    outbound: OwnedSignal<MdnsOutbound, ErasedOwner>,
) -> bool {
    let MdnsOutbound::DirectedToPeer { to, .. } = outbound.value() else {
        return false;
    };
    let to = to.clone();
    let room_handle = shared.room_handle.clone();
    let from = shared.device_id.clone();
    let line = outbound.map(move |outbound| match outbound {
        MdnsOutbound::DirectedToPeer { to, msg } => wire::encode_frame(&Frame {
            v: wire::PROTOCOL_VERSION,
            room: room_handle,
            from,
            to,
            msg,
        }),
        // Unreachable: the borrow above already matched the directed arm, and
        // the value is private, so nothing could have changed it in between.
        // Encoding nothing is the inert answer if that ever stops being true.
        _ => String::new(),
    });
    // Fast path: an existing connection for this peer — in either
    // direction. An inbound connection the peer dialed serves our
    // replies too (see `adopt_stream`), which is what lets a device
    // answer an offer even when its own mDNS view of the offerer is
    // missing or stale (asymmetric visibility).
    // `send` gives the value back when the writer is gone, so a dead connection
    // returns the line *and its owner* here rather than dropping either: the
    // dial below reuses the same allocation and the same funding.
    let commit = line.commit_unit();
    let existing = shared.conns.lock().sender(&to);
    let line = match existing {
        Some(handle) => match handle.try_send(line) {
            Ok(()) => {
                if let Some(commit) = &commit {
                    commit.accept();
                }
                return true;
            }
            Err(mpsc::error::TrySendError::Full(_)) => {
                debug!(peer = %&to[..to.len().min(16)], "mdns connection outbound queue is full or closed");
                return false;
            }
            Err(mpsc::error::TrySendError::Closed(returned)) => returned,
        },
        None => line,
    };

    // Dial. Snapshot the endpoint before awaiting anything.
    let Some(entry) = shared.peers.lock().get(&to) else {
        debug!(peer = %&to[..to.len().min(16)], "mdns directed message for unknown peer dropped");
        return false;
    };
    // All advertised addresses race concurrently and the first
    // connect wins — a host advertises every interface (docker
    // bridges, secondary NICs, …) and dialing serially would burn a
    // the full dial deadline per dead address, longer than a handshake
    // window.
    let dial_timeout = shared.timing.dial_timeout;
    let attempts: Vec<_> = entry
        .addrs
        .iter()
        .map(|addr| {
            let addr = *addr;
            let port = entry.port;
            Box::pin(async move {
                timeout(dial_timeout, TcpStream::connect((addr, port)))
                    .await
                    .map_err(|_| {
                        std::io::Error::new(std::io::ErrorKind::TimedOut, "dial timeout")
                    })?
            })
        })
        .collect();
    match futures::future::select_ok(attempts).await {
        Ok((stream, _rest)) => {
            let Some(tx) = adopt_stream(
                shared,
                stream,
                Some(to.clone()),
                shared.outbound_queue_capacity,
            ) else {
                debug!(peer = %&to[..to.len().min(16)], "mdns connection identity space exhausted");
                return false;
            };
            match tx.send(line).await {
                Ok(()) => {
                    if let Some(commit) = &commit {
                        commit.accept();
                    }
                    true
                }
                Err(_) => false,
            }
        }
        Err(e) => {
            debug!(
                peer = %&to[..to.len().min(16)],
                "mdns peer unreachable on every advertised address: {e}"
            );
            false
        }
    }
}

/// Take ownership of an exchange connection (dialed or accepted):
/// register its writer in the connection table and spawn the writer +
/// reader tasks. `known_peer` is the peer id for outbound dials;
/// inbound connections register lazily under the first authenticated
/// `from` their frames carry, so replies can ride the same socket.
fn adopt_stream(
    shared: &Arc<Shared>,
    stream: TcpStream,
    known_peer: Option<String>,
    queue_capacity: usize,
) -> Option<mpsc::Sender<OwnedSignal<String, ErasedOwner>>> {
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    let connection_retention = ConnectionRetention::for_peer(known_peer.as_deref(), queue_capacity);
    let connection_owner = match shared
        .alias_provider
        .retain_connection(known_peer.as_deref(), connection_retention)
    {
        Ok(owner) => owner,
        Err(refusal) => {
            debug!(?refusal, "mdns connection retention refused");
            return None;
        }
    };
    let slot = shared
        .connection_slots
        .clone()
        .try_acquire_owned()
        .ok()
        .map(|_permit| ConnectionLease { _permit })
        .map(Arc::new)?;
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    let generation = next_connection_generation(&shared.conn_gen)?;
    let (read_half, write_half) = stream.into_split();
    let (tx, rx) = mpsc::channel::<OwnedSignal<String, ErasedOwner>>(queue_capacity);
    let (local_stop, _) = watch::channel(false);
    // Serialize task registration with stop's drain. Once this guard is
    // acquired, shutdown cannot take the registry between the stopped check
    // and publishing either half's JoinHandle.
    let mut connection_tasks = shared.connection_tasks.lock();
    if shared.stopped.load(Ordering::Acquire) {
        return None;
    }
    // The peer this connection is registered under — set at adopt
    // time for outbound dials, on first frame for inbound accepts.
    let registered_as = Arc::new(Mutex::new(None::<Arc<str>>));
    let custody = ConnectionCustody::new(connection_owner);
    if let Some(peer) = known_peer {
        if shared.stopped.load(Ordering::Acquire) {
            return None;
        }
        let peer_key: Arc<str> = Arc::from(peer.as_str());
        let displaced = shared.conns.lock().insert(
            peer_key.clone(),
            ConnHandle {
                generation,
                tx: tx.clone(),
                stop: local_stop.clone(),
            },
            Box::new(ConnectionCustodyNode {
                custody: Arc::clone(&custody),
            }),
        );
        if let Some(displaced) = displaced {
            let _ = displaced.stop.send(true);
        }
        *registered_as.lock() = Some(peer_key);
    }

    // Writer: drains the queue onto the socket; exits on idle, write
    // error, or when every sender is gone.
    {
        let shared = shared.clone();
        let registered_as = registered_as.clone();
        let cancel = shared.cancel.subscribe();
        let local_cancel = local_stop.subscribe();
        let local_stop = local_stop.clone();
        let _slot = slot.clone();
        let writer_custody = Arc::clone(&custody);
        let half = custody.half();
        #[cfg(test)]
        let writer_gate = shared.test_half_gate.lock().clone();
        let writer_task = async move {
            run_writer(
                write_half,
                rx,
                cancel,
                local_cancel,
                shared.timing.connection_idle_timeout,
            )
            .await;
            let _ = local_stop.send(true);
            // Deregister — only our own generation; a newer connection
            // may have replaced this entry already.
            if let Some(peer) = registered_as.lock().clone() {
                shared.conns.lock().remove_generation(&peer, generation);
            } else {
                writer_custody.retire();
            }
            #[cfg(test)]
            let writer_gate = writer_gate.filter(|gate| gate.generation == generation);
            #[cfg(test)]
            if let Some(gate) = writer_gate.as_ref() {
                gate.writer_ready.wait().await;
                gate.writer_release.notified().await;
            }
            drop(half);
            #[cfg(test)]
            if let Some(gate) = writer_gate {
                gate.writer_exited.notify_one();
            }
        };
        let tasks = connection_tasks.as_mut()?;
        tasks.spawn(writer_task);
    }

    // Reader: parses frames addressed to us and (for inbound
    // connections) registers the writer under the sender's id.
    {
        let shared = shared.clone();
        let tx = tx.clone();
        let registered_as = registered_as.clone();
        let local_cancel = local_stop.subscribe();
        let local_stop = local_stop.clone();
        let _slot = slot;
        let reader_custody = Arc::clone(&custody);
        let half = custody.half();
        #[cfg(test)]
        let reader_gate = shared.test_half_gate.lock().clone();
        let reader_task = async move {
            run_reader(
                &shared,
                read_half,
                local_cancel,
                shared.timing.inbound_idle_timeout,
                |from| {
                    if shared.stopped.load(Ordering::Acquire) {
                        return;
                    }
                    let mut reg = registered_as.lock();
                    if reg.is_none() {
                        if !shared.peers.lock().contains(from) {
                            return;
                        }
                        let identity_retention = ConnectionIdentityRetention::for_peer(from);
                        let identity_owner = match shared
                            .alias_provider
                            .retain_connection_identity(from, identity_retention)
                        {
                            Ok(owner) => owner,
                            Err(refusal) => {
                                debug!(?refusal, "mdns connection identity retention refused");
                                return;
                            }
                        };
                        let peer_key: Arc<str> = Arc::from(from);
                        let displaced = shared.conns.lock().insert(
                            peer_key.clone(),
                            ConnHandle {
                                generation,
                                tx: tx.clone(),
                                stop: local_stop.clone(),
                            },
                            Box::new((
                                identity_owner,
                                ConnectionCustodyNode {
                                    custody: Arc::clone(&custody),
                                },
                            )) as ErasedOwner,
                        );
                        if let Some(displaced) = displaced {
                            let _ = displaced.stop.send(true);
                        }
                        *reg = Some(peer_key);
                    }
                },
            )
            .await;
            let _ = local_stop.send(true);
            // A dead read side means the conversation is over even if
            // writes would still go through — deregister so the next
            // exchange re-dials.
            if let Some(peer) = registered_as.lock().clone() {
                shared.conns.lock().remove_generation(&peer, generation);
            } else {
                reader_custody.retire();
            }
            #[cfg(test)]
            let reader_gate = reader_gate.filter(|gate| gate.generation == generation);
            #[cfg(test)]
            if let Some(gate) = reader_gate.as_ref() {
                gate.reader_ready.wait().await;
                gate.reader_release.notified().await;
            }
            drop(half);
            #[cfg(test)]
            if let Some(gate) = reader_gate {
                gate.reader_exited.notify_one();
            }
            trace!("mdns exchange connection closed");
        };
        let tasks = connection_tasks.as_mut()?;
        tasks.spawn(reader_task);
    }

    Some(tx)
}

/// Drain the queue onto the socket.
///
/// Each entry is an [`OwnedSignal`], held for the whole of its own write and
/// dropped at the end of the iteration — after the bytes and the newline are on
/// the wire, or immediately on a write error. So while a line is queued behind a
/// slow peer, or parked half-written, the owner that admitted the message it was
/// encoded from is still alive. On exit the receiver is dropped with everything
/// still queued, releasing those owners together.
async fn run_writer(
    mut write_half: tokio::net::tcp::OwnedWriteHalf,
    mut rx: mpsc::Receiver<OwnedSignal<String, ErasedOwner>>,
    mut cancel: watch::Receiver<bool>,
    mut local_cancel: watch::Receiver<bool>,
    idle_timeout: Duration,
) {
    loop {
        let next = tokio::select! {
            next = timeout(idle_timeout, rx.recv()) => next,
            _ = cancel.changed() => return,
            _ = local_cancel.changed() => return,
        };
        match next {
            Ok(Some(line)) => {
                if !write_with_cancellation(
                    &mut write_half,
                    line.value().as_bytes(),
                    &mut cancel,
                    &mut local_cancel,
                )
                .await
                {
                    return;
                }
                if !write_with_cancellation(&mut write_half, b"\n", &mut cancel, &mut local_cancel)
                    .await
                {
                    return;
                }
                drop(line);
            }
            // Sender dropped (driver stopping / conn replaced) or idle.
            Ok(None) | Err(_) => return,
        }
    }
}

/// Race each socket write with both the driver and exact-connection stop
/// signals. A peer that stops reading must not keep the shutdown join fence
/// waiting on an unbounded `write_all`.
async fn write_with_cancellation(
    write_half: &mut tokio::net::tcp::OwnedWriteHalf,
    bytes: &[u8],
    cancel: &mut watch::Receiver<bool>,
    local_cancel: &mut watch::Receiver<bool>,
) -> bool {
    if *cancel.borrow() || *local_cancel.borrow() {
        return false;
    }
    tokio::select! {
        result = write_half.write_all(bytes) => result.is_ok(),
        _ = cancel.changed() => false,
        _ = local_cancel.changed() => false,
    }
}

async fn run_accept(shared: Arc<Shared>, std_listener: std::net::TcpListener) {
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            warn!("mdns exchange listener unusable: {e}");
            return;
        }
    };
    let mut cancel = shared.cancel.subscribe();
    loop {
        reap_connection_tasks(&shared);
        let accepted = tokio::select! {
            accepted = listener.accept() => Some(accepted),
            _ = cancel.changed() => return,
        };
        match accepted.expect("listener accept branch selected") {
            Ok((stream, _remote)) => {
                if adopt_stream(&shared, stream, None, shared.outbound_queue_capacity).is_none() {
                    debug!("mdns accepted connection identity space exhausted");
                }
            }
            Err(e) => {
                debug!("mdns accept error: {e}");
                if !wait_for_accept_error_backoff(&mut cancel, shared.timing.accept_error_backoff)
                    .await
                {
                    return;
                }
            }
        }
    }
}

async fn wait_for_accept_error_backoff(
    cancel: &mut watch::Receiver<bool>,
    delay: Duration,
) -> bool {
    tokio::select! {
        _ = sleep(delay) => true,
        _ = cancel.changed() => false,
    }
}

async fn run_reader(
    shared: &Arc<Shared>,
    read_half: tokio::net::tcp::OwnedReadHalf,
    mut local_cancel: watch::Receiver<bool>,
    idle_timeout: Duration,
    mut on_peer_frame: impl FnMut(&str),
) {
    let mut reader = BufReader::new(read_half);
    let mut buf: Vec<u8> = Vec::with_capacity(wire::MAX_FRAME_BYTES.min(8192));
    let mut cancel = shared.cancel.subscribe();
    loop {
        if *cancel.borrow() || shared.stopped.load(Ordering::Acquire) {
            return;
        }
        buf.clear();
        let read = tokio::select! {
            read = timeout(
                idle_timeout,
                read_bounded_line(&mut reader, &mut buf),
            ) => read,
            _ = cancel.changed() => return,
            _ = local_cancel.changed() => return,
        };
        match read {
            Ok(Ok(true)) => {}
            // EOF, oversized/garbage frame, io error, or idle timeout —
            // drop the connection; the peer re-dials if it needs us.
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => return,
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            return;
        };
        if line.trim().is_empty() {
            continue;
        }
        let frame = match wire::decode_frame(line) {
            Ok(f) => f,
            Err(e) => {
                trace!("mdns frame parse failed: {e}");
                return;
            }
        };
        if !wire::frame_is_for_us(
            &frame,
            &shared.room_handle,
            &shared.device_id,
            shared.device_id_validator,
        ) {
            trace!("mdns frame for another room/recipient dropped");
            continue;
        }
        on_peer_frame(&frame.from);
        let inbound = match frame.msg {
            // Both are attributed to the frame's own sender field, which is
            // also what the peer table above is keyed on - a leave naming a
            // third party used to reach the engine as that third party's.
            // Sender-claimed either way: `frame.from` is decoded payload too,
            // never checked against the wire source.
            SignalingMessage::Announce { .. } => MdnsInbound::PeerAnnounced {
                device_id: frame.from,
                attribution: CarrierAttribution::SenderClaimed,
            },
            SignalingMessage::Leave { peer_id: _ } => MdnsInbound::PeerLeft {
                device_id: frame.from,
                attribution: CarrierAttribution::SenderClaimed,
            },
            other => MdnsInbound::Message {
                from: frame.from,
                msg: other,
            },
        };
        if shared.inbound_tx.send(inbound).is_err() {
            let _ = shared.cancel.send(true);
            return;
        }
    }
}

/// Read one `\n`-terminated line into `buf` (newline excluded).
/// Returns `Ok(true)` on a full line, `Ok(false)` on clean EOF, and
/// errors if the line exceeds [`wire::MAX_FRAME_BYTES`] — bounding
/// what an unauthenticated LAN peer can make us buffer.
async fn read_bounded_line(
    reader: &mut BufReader<tokio::net::tcp::OwnedReadHalf>,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            if buf.len().saturating_add(pos) > wire::MAX_FRAME_BYTES {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "mdns frame exceeds size cap",
                ));
            }
            buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            return Ok(true);
        }
        if buf.len().saturating_add(chunk.len()) > wire::MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mdns frame exceeds size cap",
            ));
        }
        buf.extend_from_slice(chunk);
        let n = chunk.len();
        reader.consume(n);
    }
}

/// Remove and stop exactly the connection currently registered for `peer`.
/// Signaling the owner before the stale task can publish another frame keeps
/// alias withdrawal and connection replacement on the same lifecycle fence.
fn stop_connection(shared: &Shared, peer: &str) {
    if let Some(node) = shared.conns.lock().remove(peer, None) {
        let _ = node.handle.stop.send(true);
    }
}

async fn run_reannounce(shared: Arc<Shared>) {
    let mut cancel = shared.cancel.subscribe();
    loop {
        tokio::select! {
            _ = sleep(shared.timing.reannounce_interval) => {}
            _ = cancel.changed() => return,
        }
        if *cancel.borrow() {
            return;
        }
        reap_connection_tasks(&shared);
        // Registration retry — covers a register() that failed at
        // start (no usable interface yet) or a transient daemon error.
        if !shared.registered.load(Ordering::SeqCst) {
            register(&shared);
        }
        // Re-surface every cached peer so the engine's announce-paced
        // retry logic (re-offers for Sighted-stuck peers) keeps
        // working without Nostr's relay heartbeat. A crashed peer
        // that never sent its goodbye lingers until its record TTL
        // expires — the engine tolerates announces for unreachable
        // peers, so this is noise, not harm.
        let peers: Vec<String> = shared.peers.lock().keys();
        for device_id in peers {
            if shared
                .inbound_tx
                .send(MdnsInbound::PeerAnnounced {
                    device_id,
                    attribution: CarrierAttribution::SenderClaimed,
                })
                .is_err()
            {
                let _ = shared.cancel.send(true);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
    fn start_test_discovery(
        cfg: &DiscoveryConfig,
    ) -> crate::Result<(Discovery, mpsc::Receiver<DiscoveryEvent>)> {
        let plan = super::super::discovery::checked_embedded_custody_plan()
            .expect("embedded custody plan is valid");
        let owner = DedicatedTaskCustodian::new(plan.observer_slots)
            .expect("embedded discovery custodian starts")
            as Arc<dyn TaskCustodian>;
        Discovery::start_with_custodian(cfg, owner)
    }

    #[cfg(any(target_os = "ios", feature = "system-dnssd"))]
    fn start_test_discovery(
        cfg: &DiscoveryConfig,
    ) -> crate::Result<(Discovery, mpsc::Receiver<DiscoveryEvent>)> {
        let capacity = cfg
            .limits
            .max_resolve_owners
            .checked_add(2)
            .expect("system worker capacity is checked by Discovery");
        let owner = DedicatedTaskCustodian::new(capacity)
            .expect("system discovery custodian starts")
            as Arc<dyn TaskCustodian>;
        Discovery::start_with_custodian(cfg, owner)
    }

    fn panicking_task(
        message: &'static str,
    ) -> (
        tokio::task::JoinHandle<()>,
        tokio::sync::oneshot::Receiver<()>,
    ) {
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            started_tx
                .send(())
                .expect("the panic child start barrier remains live");
            panic!("{message}");
        });
        (task, started_rx)
    }

    struct DropCounter(Arc<AtomicU64>);

    impl Drop for DropCounter {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn peer_retention_replacement_and_refusal_preserve_registry_state() {
        let released = Arc::new(AtomicU64::new(0));
        let mut peers = PeerOwnership::default();
        peers
            .insert_new(
                "peer-a".into(),
                PeerEntry {
                    addrs: vec!["127.0.0.1".parse().unwrap()],
                    port: 1,
                },
                Box::new(DropCounter(Arc::clone(&released))),
            )
            .unwrap();
        peers
            .refresh(
                "peer-a",
                PeerEntry {
                    addrs: vec!["127.0.0.2".parse().unwrap()],
                    port: 2,
                },
                Box::new(DropCounter(Arc::clone(&released))),
            )
            .unwrap();
        assert_eq!(released.load(Ordering::SeqCst), 1);
        assert_eq!(peers.get("peer-a").unwrap().port, 2);

        let max_peers = 2;
        let mut full = PeerOwnership {
            head: None,
            count: max_peers,
            max_peers,
        };
        let refusal = full.insert_new(
            "peer-b".into(),
            PeerEntry {
                addrs: Vec::new(),
                port: 3,
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        assert!(refusal.is_err());
        assert_eq!(full.count, max_peers);
        assert!(!full.contains("peer-b"));
        assert_eq!(released.load(Ordering::SeqCst), 2);
        drop(peers.remove("peer-a"));
        assert_eq!(released.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn connection_registry_replacement_and_generation_removal_release_owner() {
        let released = Arc::new(AtomicU64::new(0));
        let (tx, _rx) = mpsc::channel(1);
        let (stop, _) = watch::channel(false);
        let mut conns = ConnectionOwnership::default();
        conns.insert(
            Arc::from("peer-a"),
            ConnHandle {
                generation: 1,
                tx: tx.clone(),
                stop: stop.clone(),
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        conns.insert(
            Arc::from("peer-a"),
            ConnHandle {
                generation: 2,
                tx,
                stop,
            },
            Box::new(DropCounter(Arc::clone(&released))),
        );
        assert_eq!(released.load(Ordering::SeqCst), 1);
        conns.remove_generation("peer-a", 1);
        assert!(conns.sender("peer-a").is_some());
        conns.remove_generation("peer-a", 2);
        assert!(conns.sender("peer-a").is_none());
        assert_eq!(released.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn alias_registry_refuses_at_policy_bound_before_mutation() {
        let released = Arc::new(AtomicU64::new(0));
        let mut aliases = AliasOwnership::with_max_aliases(1);
        aliases
            .bind(
                "service-a".into(),
                "peer-a".into(),
                1,
                Box::new(DropCounter(Arc::clone(&released))),
            )
            .expect("first alias admitted");
        let refused = aliases.bind(
            "service-b".into(),
            "peer-b".into(),
            2,
            Box::new(DropCounter(Arc::clone(&released))),
        );
        assert!(refused.is_err());
        assert_eq!(aliases.alias_count("peer-a"), 1);
        assert_eq!(aliases.alias_count("peer-b"), 0);
        assert_eq!(released.load(Ordering::Acquire), 1);
    }

    #[cfg_attr(
        any(target_os = "ios", feature = "system-dnssd"),
        ignore = "requires the system mDNS daemon"
    )]
    #[tokio::test]
    async fn connection_registry_replacement_keeps_w0_until_both_halves_retire() {
        let limits = MdnsLimits {
            max_active_connections: 4,
            max_discovered_peers: 1,
            outbound_queue_capacity: 2,
            discovery: DiscoveryLimits {
                max_resolve_owners: 2,
                event_capacity: 3,
                max_event_epochs: 4,
                max_txt_entries: 64,
                max_txt_bytes: 4096,
                max_resolved_addresses: 32,
            },
            timing: MdnsTimingProfile::default(),
        };
        let released = Arc::new(AtomicU64::new(0));
        let attempted = Arc::new(AtomicUsize::new(0));
        let cfg = DiscoveryConfig {
            service_type: wire::SERVICE_TYPE.to_string(),
            instance: format!("mdns-overlap-{}", std::process::id()),
            port: 0,
            txt: Vec::new(),
            limits: limits.discovery,
            timing: limits.timing,
        };
        let (discovery, _events) = start_test_discovery(&cfg).expect("embedded discovery start");
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            room_handle: "room".into(),
            device_id: "local".into(),
            device_id_validator: |_| true,
            alias_provider: Arc::new(CountingProvider {
                released: Arc::clone(&released),
                attempted: Arc::clone(&attempted),
                refuse_after: None,
            }),
            discovery: Arc::new(discovery),
            discovery_owner: Arc::new(Mutex::new(None)),
            registered: AtomicBool::new(false),
            peers: Mutex::new(PeerOwnership::with_max_peers(limits.max_discovered_peers)),
            aliases: Mutex::new(AliasOwnership::default()),
            conns: Mutex::new(ConnectionOwnership::default()),
            connection_slots: Arc::new(Semaphore::new(limits.max_active_connections)),
            outbound_queue_capacity: limits.outbound_queue_capacity,
            timing: limits.timing,
            connection_tasks: Arc::new(Mutex::new(Some(JoinSet::new()))),
            test_half_gate: Arc::new(Mutex::new(None)),
            stopped: Arc::new(AtomicBool::new(false)),
            conn_gen: AtomicU64::new(1),
            inbound_tx: InboundSink::from_unbounded(in_tx),
            cancel: watch::channel(false).0,
        });

        async fn adopt_loopback(shared: &Arc<Shared>, peer: &str) -> TcpStream {
            let listener = TcpListener::bind(("127.0.0.1", 0))
                .await
                .expect("loopback listener");
            let address = listener.local_addr().expect("loopback address");
            let client = TcpStream::connect(address).await.expect("loopback client");
            let (accepted, _) = listener.accept().await.expect("loopback accept");
            assert!(adopt_stream(
                shared,
                accepted,
                Some(peer.to_owned()),
                shared.outbound_queue_capacity,
            )
            .is_some());
            client
        }

        async fn wait_for_releases(released: &AtomicU64, expected: u64) {
            for _ in 0..256 {
                if released.load(Ordering::Acquire) == expected {
                    return;
                }
                tokio::task::yield_now().await;
            }
            assert_eq!(released.load(Ordering::Acquire), expected);
        }

        for (generation, release_writer_first) in [(1, true), (3, false)] {
            let gate = Arc::new(TestHalfGate {
                generation,
                writer_ready: Arc::new(Barrier::new(2)),
                reader_ready: Arc::new(Barrier::new(2)),
                writer_release: Arc::new(Notify::new()),
                reader_release: Arc::new(Notify::new()),
                writer_exited: Arc::new(Notify::new()),
                reader_exited: Arc::new(Notify::new()),
            });
            *shared.test_half_gate.lock() = Some(Arc::clone(&gate));
            let old_client = adopt_loopback(&shared, "peer-a").await;
            let new_client = adopt_loopback(&shared, "peer-a").await;
            drop(old_client);

            gate.writer_ready.wait().await;
            gate.reader_ready.wait().await;
            let prior_releases = generation - 1;
            assert_eq!(released.load(Ordering::Acquire), prior_releases);
            assert!(shared.conns.lock().sender("peer-a").is_some());

            if release_writer_first {
                gate.writer_release.notify_one();
                gate.writer_exited.notified().await;
                assert_eq!(released.load(Ordering::Acquire), prior_releases);
                gate.reader_release.notify_one();
                gate.reader_exited.notified().await;
            } else {
                gate.reader_release.notify_one();
                gate.reader_exited.notified().await;
                assert_eq!(released.load(Ordering::Acquire), prior_releases);
                gate.writer_release.notify_one();
                gate.writer_exited.notified().await;
            }
            wait_for_releases(&released, generation).await;
            assert!(shared.conns.lock().sender("peer-a").is_some());

            drop(new_client);
            wait_for_releases(&released, generation + 1).await;
            assert!(shared.conns.lock().sender("peer-a").is_none());
        }

        assert_eq!(attempted.load(Ordering::Acquire), 4);
        for _ in 0..256 {
            if shared.connection_slots.available_permits() == 4 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(shared.connection_slots.available_permits(), 4);
        reap_connection_tasks(&shared);
        let _ = shared.cancel.send(true);
        let shared = match Arc::try_unwrap(shared) {
            Ok(shared) => shared,
            Err(_) => panic!("connection test retained shared ownership"),
        };
        let mut discovery = match Arc::try_unwrap(shared.discovery) {
            Ok(discovery) => discovery,
            Err(_) => panic!("connection test retained discovery ownership"),
        };
        discovery.shutdown();
        if let Some(task) = discovery.take_task() {
            task.await.expect("discovery shutdown task");
        }
    }

    #[tokio::test]
    async fn connection_slots_have_a_finite_cap_and_release() {
        let max_connections = 3;
        let slots = Arc::new(Semaphore::new(max_connections));
        let mut leases = Vec::with_capacity(max_connections);
        for _ in 0..max_connections {
            leases.push(slots.clone().try_acquire_owned().expect("slot available"));
        }
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(leases.pop());
        assert!(slots.try_acquire_owned().is_ok());
    }

    #[tokio::test]
    async fn connection_supervisor_joins_each_worker_once() {
        let mut supervisor = JoinSet::new();
        supervisor.spawn(async {});
        assert!(supervisor.join_next().await.is_some());
        assert!(supervisor.join_next().await.is_none());
    }

    #[tokio::test]
    async fn runtime_reaper_aborts_and_observes_every_owned_task() {
        struct DropMark(Arc<AtomicBool>);

        impl Drop for DropMark {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
            }
        }

        let dropped = Arc::new(AtomicBool::new(false));
        let task_dropped = Arc::clone(&dropped);
        let task = tokio::spawn(async move {
            let _mark = DropMark(task_dropped);
            std::future::pending::<()>().await;
        });
        let (stop, stop_rx) = oneshot::channel();
        let (done, done_rx) = oneshot::channel();
        let connection_tasks = Arc::new(Mutex::new(Some(JoinSet::new())));
        tokio::spawn(supervise_driver_tasks(
            vec![task],
            connection_tasks,
            stop_rx,
            done,
        ));
        stop.send(()).expect("reaper is waiting for shutdown");
        timeout(Duration::from_secs(1), done_rx)
            .await
            .expect("reaper completes")
            .expect("reaper completion is published");
        assert!(dropped.load(Ordering::Acquire));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driver_drop_transfers_final_handles_to_external_custodian() {
        struct DropMark(Arc<Notify>);

        impl Drop for DropMark {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }

        let cfg = DiscoveryConfig {
            service_type: wire::SERVICE_TYPE.to_string(),
            instance: format!("mdns-custodian-{}", std::process::id()),
            port: 0,
            txt: Vec::new(),
            limits: DiscoveryLimits::default(),
            timing: MdnsTimingProfile::default(),
        };
        let (discovery, _events) = start_test_discovery(&cfg).expect("embedded discovery start");
        let (supervisor_stop, supervisor_stop_rx) = oneshot::channel();
        let supervisor_done_rx = None;
        let fallback_reaper_tasks = FallbackReaperTasks::new(0);
        let (supervisor_reaper, supervisor_reaper_task) =
            spawn_task_reaper(1, Arc::clone(&fallback_reaper_tasks));
        let dropped = Arc::new(Notify::new());
        let dropped_in_supervisor = Arc::clone(&dropped);
        let supervisor = tokio::spawn(async move {
            let _mark = DropMark(dropped_in_supervisor);
            supervisor_stop_rx
                .await
                .expect("Drop must signal the supervisor");
        });
        let custodian_owner = DedicatedTaskCustodian::new(1).expect("test custodian");
        let custodian = custodian_owner
            .reserve(1)
            .expect("the primary custodian must reserve the supervisor handle");
        let reaper_custodian_owner = DedicatedTaskCustodian::new(2).expect("reaper custodian");
        let reaper_custodian = reaper_custodian_owner
            .reserve(2)
            .expect("the independent custodian must reserve both final handles");
        let handle = MdnsDriverHandle {
            discovery: Arc::new(discovery),
            stopped: Arc::new(AtomicBool::new(false)),
            cancel: watch::channel(false).0,
            supervisor: Some(supervisor),
            supervisor_reaper: Some(supervisor_reaper),
            supervisor_reaper_task: Some(supervisor_reaper_task),
            fallback_reaper_tasks,
            custodian_owner,
            custodian: Some(custodian),
            reaper_custodian_owner,
            reaper_custodian: Some(reaper_custodian),
            supervisor_stop: Some(supervisor_stop),
            supervisor_done: supervisor_done_rx,
            discovery_owner: Arc::new(Mutex::new(None)),
        };
        drop(handle);

        timeout(Duration::from_secs(2), dropped.notified())
            .await
            .expect("mDNS Drop must transfer and observe the supervisor externally");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn closed_primary_custody_uses_independent_reaper_owner() {
        let primary_owner = DedicatedTaskCustodian::new(1).expect("primary custodian");
        let primary = primary_owner
            .reserve(1)
            .expect("primary supervisor reservation");
        primary_owner.close();

        let reaper_owner = DedicatedTaskCustodian::new(2).expect("reaper custodian");
        let mut reaper = Some(
            reaper_owner
                .reserve(2)
                .expect("independent reaper reservation"),
        );
        let mut primary = Some(primary);
        let mut progress = reaper_owner.progress();
        let (panic_task, started) = panicking_task("closed primary custody");
        started
            .await
            .expect("panic terminal starts before transfer");
        tokio::task::yield_now().await;
        submit_to_terminal_custody(
            &mut primary,
            &mut reaper,
            panic_task,
            "mDNS closed-primary control",
        );
        timeout(Duration::from_secs(1), progress.changed())
            .await
            .expect("independent reaper observes the refused-primary terminal")
            .expect("reaper progress remains live");
        assert_eq!(*progress.borrow(), 1);

        let normal_task = tokio::spawn(async {});
        submit_to_terminal_custody(
            &mut primary,
            &mut reaper,
            normal_task,
            "mDNS closed-primary second control",
        );
        timeout(Duration::from_secs(1), progress.changed())
            .await
            .expect("independent reaper observes its second terminal")
            .expect("reaper progress remains live");
        assert_eq!(*progress.borrow(), 2);
        reaper_owner.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_capacity_refusal_returns_exact_panicking_handle() {
        let fallback = FallbackReaperTasks::new(0);
        let (task, started) = panicking_task("mDNS fallback capacity refusal");
        started.await.expect("panic task must start before refusal");
        let task = fallback
            .retain(task)
            .expect_err("zero-capacity custody must return the exact handle");
        let error = task.await.expect_err("returned panic must be observed");
        assert!(error.is_panic());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_overflow_transfer_observes_panicking_task() {
        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);
        let fallback = FallbackReaperTasks::new(0);
        let (task, started) = panicking_task("mDNS bounded fallback overflow");
        started
            .await
            .expect("panic task must start before transfer");
        retain_or_overflow(&fallback, task, "mDNS overflow control");
        reap_fallback_reaper_tasks(&fallback).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 1,
            "bounded overflow custody must observe the exact panic"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn both_final_custody_refusals_observe_each_terminal_once() {
        struct RefusingReservation;

        impl crate::task_custodian::TaskReservation for RefusingReservation {
            fn submit(
                &mut self,
                task: tokio::task::JoinHandle<()>,
            ) -> Result<(), tokio::task::JoinHandle<()>> {
                Err(task)
            }
        }

        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);
        for primary_present in [true, false] {
            let fallback = FallbackReaperTasks::new(0);
            let filler = tokio::spawn(std::future::pending::<()>());
            fallback
                .retain_overflow(filler)
                .expect("the bounded overflow slot must admit its one filler");
            let (task, started) = panicking_task("both final custody refusals");
            started
                .await
                .expect("refused child must reach its terminal path");
            tokio::task::yield_now().await;
            let mut custodian =
                primary_present.then(|| Box::new(RefusingReservation) as CustodianReservation);
            let mut reaper_custodian = None;
            submit_to_custodian_or_reaper_or_fallback(
                &mut custodian,
                &mut reaper_custodian,
                &fallback,
                task,
                "mDNS both-final-custody-refusal",
            );
            let filler = fallback
                .take_all()
                .pop()
                .expect("the overflow filler remains explicitly owned");
            filler.abort();
            assert!(
                filler.await.is_err(),
                "overflow filler terminal is observed"
            );
        }
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 2,
            "both refusal permutations observe the refused terminal exactly once"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_full_and_closed_fallbacks_observe_panics_in_and_outside_runtime() {
        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);

        let fallback_reaper_tasks = FallbackReaperTasks::new(1);
        let (full_sender, mut full_receiver) = mpsc::channel(1);
        full_sender
            .try_send(tokio::spawn(std::future::pending::<()>()))
            .expect("the first handle fills the bounded reaper channel");
        let (task, started) = panicking_task("injected mdns panic through full fallback");
        started
            .await
            .expect("the full fallback child starts before transfer");
        join_supervisor(&full_sender, task, &fallback_reaper_tasks);
        reap_fallback_reaper_tasks(&fallback_reaper_tasks).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 1,
            "a full active-runtime transfer joins the exact panicking child"
        );
        let filler = full_receiver
            .try_recv()
            .expect("the full-channel filler remains explicitly owned");
        filler.abort();
        assert!(filler.await.is_err(), "aborted filler must be observed");

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        let (task, started) = panicking_task("injected mdns panic through closed fallback");
        started
            .await
            .expect("the closed fallback child starts before transfer");
        join_supervisor(&closed_sender, task, &fallback_reaper_tasks);
        reap_fallback_reaper_tasks(&fallback_reaper_tasks).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 2,
            "a closed active-runtime transfer joins the exact panicking child"
        );

        let (full_sender, mut full_receiver) = mpsc::channel(1);
        full_sender
            .try_send(tokio::spawn(std::future::pending::<()>()))
            .expect("the no-runtime full channel is deterministically occupied");
        let (task, started) =
            panicking_task("injected mdns panic through outside-runtime full fallback");
        started
            .await
            .expect("the outside-runtime full child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || join_supervisor(&full_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime full fallback returns after joining");
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 3,
            "a full no-runtime transfer synchronously observes the child"
        );
        let filler = full_receiver
            .try_recv()
            .expect("the no-runtime full filler remains explicitly owned");
        filler.abort();
        assert!(filler.await.is_err(), "aborted filler must be observed");

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        let (task, started) =
            panicking_task("injected mdns panic through outside-runtime closed fallback");
        started
            .await
            .expect("the outside-runtime closed child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || join_supervisor(&closed_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime closed fallback returns after joining");
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 4,
            "a closed no-runtime transfer synchronously observes the child"
        );
    }

    #[test]
    fn configured_limits_are_finite_and_reject_zero() {
        let limits = MdnsLimits::default();
        assert!(limits.validate());
        assert!(!MdnsLimits {
            max_active_connections: 0,
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            max_discovered_peers: 0,
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            outbound_queue_capacity: 0,
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            discovery: DiscoveryLimits {
                max_event_epochs: 0,
                ..limits.discovery
            },
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            timing: MdnsTimingProfile {
                query_deadline: Duration::ZERO,
                ..limits.timing
            },
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            timing: MdnsTimingProfile {
                accept_error_backoff: Duration::ZERO,
                ..limits.timing
            },
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            max_active_connections: Semaphore::MAX_PERMITS + 1,
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            outbound_queue_capacity: Semaphore::MAX_PERMITS + 1,
            ..limits
        }
        .validate());
        assert!(!MdnsLimits {
            discovery: DiscoveryLimits {
                event_capacity: Semaphore::MAX_PERMITS + 1,
                ..limits.discovery
            },
            ..limits
        }
        .validate());
    }

    #[test]
    fn non_default_limits_reach_driver_retention_plans() {
        let limits = MdnsLimits {
            max_active_connections: 3,
            max_discovered_peers: 5,
            outbound_queue_capacity: 7,
            discovery: DiscoveryLimits {
                max_resolve_owners: 11,
                event_capacity: 13,
                max_event_epochs: 17,
                max_txt_entries: 19,
                max_txt_bytes: 2048,
                max_resolved_addresses: 23,
            },
            timing: MdnsTimingProfile {
                accept_error_backoff: Duration::from_millis(41),
                ..MdnsTimingProfile::default()
            },
        };
        assert!(limits.validate());
        let peers = PeerOwnership::with_max_peers(limits.max_discovered_peers);
        assert_eq!(peers.max_peers, 5);
        let connection = ConnectionRetention::for_peer(None, limits.outbound_queue_capacity);
        assert_eq!(connection.queue_slots, 7);
        assert_eq!(connection.worker_tasks, 2);
        assert_eq!(limits.discovery.event_capacity, 13);
        assert_eq!(limits.discovery.max_resolve_owners, 11);
        assert_eq!(limits.discovery.max_event_epochs, 17);
        assert_eq!(limits.discovery.max_txt_entries, 19);
        assert_eq!(limits.discovery.max_txt_bytes, 2048);
        assert_eq!(limits.discovery.max_resolved_addresses, 23);
        assert_eq!(
            limits.timing.accept_error_backoff,
            Duration::from_millis(41)
        );
    }

    #[tokio::test]
    async fn accept_error_backoff_honors_profile_and_cancels_immediately() {
        let profile = MdnsTimingProfile {
            accept_error_backoff: Duration::from_millis(1),
            ..MdnsTimingProfile::default()
        };
        assert!(profile.validate());

        let (_cancel_tx, mut cancel) = watch::channel(false);
        assert!(timeout(
            Duration::from_secs(1),
            wait_for_accept_error_backoff(&mut cancel, profile.accept_error_backoff),
        )
        .await
        .expect("configured accept-error backoff completes"));

        let (cancel_tx, mut cancel) = watch::channel(false);
        let backoff = wait_for_accept_error_backoff(&mut cancel, Duration::from_secs(60));
        tokio::pin!(backoff);
        cancel_tx.send(true).expect("cancellation receiver is live");
        assert!(!timeout(Duration::from_secs(1), &mut backoff)
            .await
            .expect("accept-error cancellation is prompt"));
    }

    #[test]
    fn driver_rejects_zero_limits_before_socket_or_daemon_creation() {
        let (out_tx, out_rx) = mpsc::unbounded_channel();
        drop(out_tx);
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let limits = MdnsLimits {
            max_active_connections: 0,
            ..MdnsLimits::default()
        };
        let result = start(
            MdnsDriverConfig {
                app_id: "limits-test".into(),
                network_id: "limits-network".into(),
                device_id: "local".into(),
                service_port: 0,
                device_id_validator: |_| true,
                alias_provider: Arc::new(CountingProvider {
                    released: Arc::new(AtomicU64::new(0)),
                    attempted: Arc::new(AtomicUsize::new(0)),
                    refuse_after: None,
                }),
                limits,
            },
            crate::UnboundedSource::new(out_rx),
            InboundSink::from_unbounded(in_tx),
        );
        assert!(result.is_err());
    }

    #[test]
    fn connection_owner_waits_for_registry_and_both_halves() {
        let released = Arc::new(AtomicU64::new(0));
        let custody = ConnectionCustody::new(Box::new(DropCounter(Arc::clone(&released))));
        let node = ConnectionCustodyNode {
            custody: Arc::clone(&custody),
        };
        let first = custody.half();
        let second = custody.half();
        drop(node);
        drop(first);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(second);
        assert_eq!(released.load(Ordering::SeqCst), 1);

        let released = Arc::new(AtomicU64::new(0));
        let custody = ConnectionCustody::new(Box::new(DropCounter(Arc::clone(&released))));
        let node = ConnectionCustodyNode {
            custody: Arc::clone(&custody),
        };
        let first = custody.half();
        let second = custody.half();
        drop(first);
        drop(node);
        assert_eq!(released.load(Ordering::SeqCst), 0);
        drop(second);
        assert_eq!(released.load(Ordering::SeqCst), 1);
    }

    struct CountingProvider {
        released: Arc<AtomicU64>,
        attempted: Arc<AtomicUsize>,
        refuse_after: Option<usize>,
    }

    impl AliasProvider for CountingProvider {
        fn retain_discovery(
            &self,
            _retention: DiscoveryRetention,
        ) -> std::result::Result<ErasedOwner, AliasRefusal> {
            Ok(Box::new(()))
        }

        fn retain_alias(
            &self,
            _key: &str,
            _peer: &str,
            _retention: AliasRetention,
        ) -> std::result::Result<ErasedOwner, AliasRefusal> {
            Ok(Box::new(()))
        }

        fn retain_peer(
            &self,
            _peer: &str,
            _retention: PeerRetention,
        ) -> std::result::Result<ErasedOwner, AliasRefusal> {
            Ok(Box::new(()))
        }

        fn retain_connection(
            &self,
            _peer: Option<&str>,
            _retention: ConnectionRetention,
        ) -> std::result::Result<ErasedOwner, AliasRefusal> {
            let attempt = self.attempted.fetch_add(1, Ordering::AcqRel);
            if self.refuse_after.is_some_and(|limit| attempt >= limit) {
                return Err(AliasRefusal::Provider("test connection cap".into()));
            }
            Ok(Box::new(DropCounter(Arc::clone(&self.released))))
        }

        fn retain_connection_identity(
            &self,
            _peer: &str,
            _retention: ConnectionIdentityRetention,
        ) -> std::result::Result<ErasedOwner, AliasRefusal> {
            Ok(Box::new(()))
        }
    }

    #[test]
    fn discovery_retention_derives_each_bounded_dimension() {
        let limits = DiscoveryLimits {
            max_resolve_owners: 3,
            event_capacity: 5,
            max_event_epochs: 7,
            max_txt_entries: 8,
            max_txt_bytes: 512,
            max_resolved_addresses: 4,
        };
        let retention = DiscoveryRetention::from_backend(limits, DiscoveryBackend::Embedded)
            .expect("valid retention");
        assert_eq!(retention.event_queue_slots, 10);
        assert_eq!(retention.resolve_owner_slots, 3);
        assert_eq!(retention.event_epoch_slots, 0);
        assert_eq!(retention.txt_entry_slots, 24);
        assert_eq!(
            retention.txt_bytes,
            3 * (512 + 4 * std::mem::size_of::<IpAddr>())
        );
        assert_eq!(retention.resolved_address_slots, 12);
        assert_eq!(retention.backend_task_slots, 3);
        assert_eq!(retention.native_worker_slots, 0);
        assert_eq!(retention.outer_driver_task_slots, 6);
        assert_eq!(retention.outer_driver_handle_slots, 5);
        assert_eq!(retention.outer_driver_stop_signal_slots, 1);
        assert_eq!(retention.outer_driver_done_signal_slots, 1);
        assert_eq!(retention.outer_driver_reaper_queue_slots, 1);
        assert_eq!(retention.outer_driver_external_reaper_slots, 2);
        assert_eq!(retention.outer_driver_fallback_slots, 2);
        assert_eq!(retention.outer_driver_fallback_overflow_slots, 1);
        assert_eq!(retention.outer_driver_cancel_signal_slots, 1);
        assert_eq!(retention.opaque_dependency_slots, 3);
        assert_eq!(
            retention.scratch_bytes,
            3 * (512 + 4 * std::mem::size_of::<IpAddr>())
        );
        let driver_plan = checked_driver_custody_plan(limits, DiscoveryBackend::Embedded)
            .expect("valid driver custody plan");
        assert_eq!(driver_plan.outer_driver_handle_slots, 5);
        // Embedded observer custody exists only when that implementation is compiled.
        #[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
        {
            assert_eq!(driver_plan.backend_runtime_slots, 1);
            assert_eq!(driver_plan.backend_observer_slots, 3);
            assert_eq!(driver_plan.backend_queue_slots, 3);
        }
        #[cfg(any(target_os = "ios", feature = "system-dnssd"))]
        {
            assert_eq!(driver_plan.backend_runtime_slots, 0);
            assert_eq!(driver_plan.backend_observer_slots, 0);
            assert_eq!(driver_plan.backend_queue_slots, 0);
        }
        assert_eq!(driver_plan.reaper_observer_runtime_slots, 1);
        assert_eq!(driver_plan.reaper_observer_task_slots, 2);
        assert_eq!(driver_plan.reaper_observer_queue_slots, 2);

        let system = DiscoveryRetention::from_backend(limits, DiscoveryBackend::System)
            .expect("valid system retention");
        assert_eq!(system.resolve_owner_slots, 3);
        assert_eq!(system.backend_task_slots, 0);
        assert_eq!(system.native_worker_slots, 5);
        assert_eq!(system.outer_driver_task_slots, 6);
        assert_eq!(system.outer_driver_handle_slots, 4);
        assert_eq!(system.outer_driver_stop_signal_slots, 1);
        assert_eq!(system.outer_driver_done_signal_slots, 1);
        assert_eq!(system.outer_driver_reaper_queue_slots, 1);
        assert_eq!(system.outer_driver_external_reaper_slots, 2);
        assert_eq!(system.outer_driver_fallback_slots, 2);
        assert_eq!(system.outer_driver_fallback_overflow_slots, 1);
        assert_eq!(system.outer_driver_cancel_signal_slots, 1);
        assert_eq!(system.opaque_dependency_slots, 5);
        let system_driver_plan = checked_driver_custody_plan(limits, DiscoveryBackend::System)
            .expect("valid system driver custody plan");
        assert_eq!(system_driver_plan.outer_driver_handle_slots, 4);
        assert_eq!(system_driver_plan.backend_runtime_slots, 0);
        assert_eq!(system_driver_plan.backend_observer_slots, 0);
        assert_eq!(system_driver_plan.backend_queue_slots, 0);
        assert_eq!(system_driver_plan.reaper_observer_runtime_slots, 1);
        assert_eq!(system_driver_plan.reaper_observer_task_slots, 2);
        assert_eq!(system_driver_plan.reaper_observer_queue_slots, 2);

        let mut invalid = limits;
        invalid.event_capacity = 0;
        assert!(DiscoveryRetention::from_limits(invalid).is_err());
    }

    #[cfg_attr(
        any(target_os = "ios", feature = "system-dnssd"),
        ignore = "requires the system mDNS daemon"
    )]
    #[tokio::test]
    async fn live_driver_reaps_loopback_connection_churn_before_shutdown() {
        let limits = MdnsLimits {
            max_active_connections: 1,
            max_discovered_peers: 1,
            outbound_queue_capacity: 2,
            discovery: DiscoveryLimits {
                max_resolve_owners: 2,
                event_capacity: 3,
                max_event_epochs: 4,
                max_txt_entries: 64,
                max_txt_bytes: 4096,
                max_resolved_addresses: 32,
            },
            timing: MdnsTimingProfile::default(),
        };
        let released = Arc::new(AtomicU64::new(0));
        let attempted = Arc::new(AtomicUsize::new(0));
        let cfg = DiscoveryConfig {
            service_type: wire::SERVICE_TYPE.to_string(),
            instance: format!("mdns-reap-{}", std::process::id()),
            port: 0,
            txt: Vec::new(),
            limits: limits.discovery,
            timing: limits.timing,
        };
        let (discovery, _events) = start_test_discovery(&cfg).expect("embedded discovery start");
        let (in_tx, _in_rx) = mpsc::unbounded_channel();
        let shared = Arc::new(Shared {
            room_handle: "room".into(),
            device_id: "local".into(),
            device_id_validator: |_| true,
            alias_provider: Arc::new(CountingProvider {
                released: Arc::clone(&released),
                attempted: Arc::clone(&attempted),
                refuse_after: Some(3),
            }),
            discovery: Arc::new(discovery),
            discovery_owner: Arc::new(Mutex::new(None)),
            registered: AtomicBool::new(false),
            peers: Mutex::new(PeerOwnership::with_max_peers(limits.max_discovered_peers)),
            aliases: Mutex::new(AliasOwnership::default()),
            conns: Mutex::new(ConnectionOwnership::default()),
            connection_slots: Arc::new(Semaphore::new(limits.max_active_connections)),
            outbound_queue_capacity: limits.outbound_queue_capacity,
            timing: limits.timing,
            connection_tasks: Arc::new(Mutex::new(Some(JoinSet::new()))),
            test_half_gate: Arc::new(Mutex::new(None)),
            stopped: Arc::new(AtomicBool::new(false)),
            conn_gen: AtomicU64::new(1),
            inbound_tx: InboundSink::from_unbounded(in_tx),
            cancel: watch::channel(false).0,
        });

        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let address = listener.local_addr().unwrap();
        let accept_task = tokio::spawn(run_accept(Arc::clone(&shared), listener));
        for generation in 0..3 {
            let client = TcpStream::connect(address).await.unwrap();
            drop(client);

            let expected_releases = generation + 1;
            for _ in 0..256 {
                if released.load(Ordering::Acquire) == expected_releases
                    && shared.connection_slots.available_permits() == limits.max_active_connections
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
            assert_eq!(released.load(Ordering::Acquire), expected_releases);
            assert_eq!(
                shared.connection_slots.available_permits(),
                limits.max_active_connections
            );
        }

        // A refused stream still reaches the production accept loop. The
        // first refusal follows the third worker, and a second refusal wakes
        // the loop once more so its runtime reaper consumes that completed
        // worker before shutdown; neither refusal creates a worker/owner.
        let refused = TcpStream::connect(address).await.unwrap();
        drop(refused);
        let reaper_wakeup = TcpStream::connect(address).await.unwrap();
        drop(reaper_wakeup);
        for _ in 0..256 {
            if attempted.load(Ordering::Acquire) == 5
                && released.load(Ordering::Acquire) == 3
                && shared
                    .connection_tasks
                    .lock()
                    .as_ref()
                    .is_some_and(|tasks| tasks.is_empty())
            {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(attempted.load(Ordering::Acquire), 5);
        assert_eq!(released.load(Ordering::Acquire), 3);
        assert!(shared
            .connection_tasks
            .lock()
            .as_ref()
            .is_some_and(|tasks| tasks.is_empty()));
        for _ in 0..256 {
            if shared.connection_slots.available_permits() == limits.max_active_connections {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(
            shared.connection_slots.available_permits(),
            limits.max_active_connections
        );
        let _ = shared.cancel.send(true);
        accept_task.await.expect("accept loop shutdown");
        let shared = match Arc::try_unwrap(shared) {
            Ok(shared) => shared,
            Err(_) => panic!("live driver retained a connection task reference"),
        };
        let mut discovery = match Arc::try_unwrap(shared.discovery) {
            Ok(discovery) => discovery,
            Err(_) => panic!("live driver retained a discovery reference"),
        };
        discovery.shutdown();
        if let Some(task) = discovery.take_task() {
            task.await.expect("discovery shutdown task");
        }
    }

    /// An owner that records its own release.
    ///
    /// What the owner type is for is *when* the funding goes back, and no
    /// assertion about a type can observe that. This can: it fires once, in
    /// `Drop`.
    struct ReleaseFlag(Arc<std::sync::atomic::AtomicBool>);

    impl Drop for ReleaseFlag {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// **An encoded frame waiting behind a slow peer still has its funding, and
    /// a connection that goes away releases everything it was still holding.**
    ///
    /// The writer queue is where an outbound line parks: a peer that has stopped
    /// reading, or a socket the OS has not yet failed, can hold a frame there for
    /// as long as the connection lasts. This is the retention that the old
    /// `String` queue had no way to express — the bytes existed with nothing
    /// tying them back to whatever admitted the message they came from.
    ///
    /// Asserted at the queue rather than through [`run_writer`], because the
    /// property is about a line that has *not* been written and a writer that is
    /// draining a real socket is exactly the thing that would make that
    /// non-deterministic. The two halves discriminate in opposite directions: a
    /// queue that dropped the owner on enqueue fails the first assertion, and a
    /// teardown that leaked the queued entries fails the second.
    #[test]
    fn a_queued_line_holds_its_owner_until_the_connection_lets_go() {
        use std::sync::atomic::{AtomicBool, Ordering};
        let released = Arc::new(AtomicBool::new(false));
        let (tx, rx) = mpsc::unbounded_channel::<OwnedSignal<String, ErasedOwner>>();
        tx.send(OwnedSignal::new(
            "frame".to_string(),
            Box::new(ReleaseFlag(Arc::clone(&released))) as ErasedOwner,
        ))
        .expect("the writer queue accepts a line");
        assert!(
            !released.load(Ordering::SeqCst),
            "the encoded bytes are queued and could still be written, so their \
             funding must not be back"
        );
        // The writer exiting drops the receiver with everything still queued —
        // idle timeout, write error, or driver shutdown all end here.
        drop(rx);
        assert!(
            released.load(Ordering::SeqCst),
            "a torn-down connection releases the owners of the lines it never \
             managed to write"
        );
    }

    #[test]
    fn connection_generation_exhaustion_never_reuses_an_exact_fence() {
        let counter = AtomicU64::new(1);
        assert_eq!(next_connection_generation(&counter), Some(1));
        assert_eq!(next_connection_generation(&counter), Some(2));

        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(next_connection_generation(&counter), Some(u64::MAX));
        assert_eq!(next_connection_generation(&counter), None);
        assert_eq!(next_connection_generation(&counter), None);
    }
}
