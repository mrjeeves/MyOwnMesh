//! Concrete Nostr signaling driver. Connects to N relays in
//! parallel, publishes ephemeral signaling events tagged with
//! the room handle, subscribes to inbound events on the same
//! tag, and routes them back to the caller via mpsc channels.
//!
//! Resilience features baked in (see `crate::upstream`):
//!
//! - The subscription REQ is re-sent on every fresh socket, and the
//!   per-socket reconnect backoff (operator-configured, jittered) is the single
//!   anti-flood pace for a flapping relay.
//! - Transition-only logging — no per-event spam.
//! - Directed negotiation (offer / answer / candidate) is tagged with
//!   its recipient (`["p", device_id]`) and the subscription asks for
//!   "presence + directed-to-me", so the relay never fans a pairwise
//!   negotiation to the whole room (see `desired_filters`).
//!
//! The driver is independent of the engine; the
//! [`crate::SignalingChannel`] trait is the seam.

use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;
#[cfg(test)]
use std::sync::OnceLock;

use futures::{Sink, SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{mpsc, watch, Notify};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::WebSocketConfig;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, trace, warn};

use super::delivery::{
    AdmissionSource, DeliveryLease, DeliveryProvider, DeliveryStore, DeliveryTerminal,
    RelaySessionId,
};
use super::event::{
    make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EPHEMERAL_KIND, SIGNALING_EVENT_KIND,
};
use super::handle::derive_room_handle;
use super::shuffle::select_top_n;
#[cfg(test)]
use crate::task_custodian::DedicatedTaskCustodian;
use crate::task_custodian::{CustodianReservation, TaskCustodian};
#[cfg(test)]
use crate::task_custodian::{TaskCustodyError, TaskReservation};
use crate::upstream::{ANNOUNCE_BACKOFF_MS, ANNOUNCE_STEADY_MS, PRESENCE_REPLAY_WINDOW_SECS};
use crate::{
    AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, CarrierAttribution, ErasedOwner,
    ErasedSource, InboundSink, OutboundSource, OwnedSignal, SignalingMessage,
};

#[cfg(test)]
struct UnmeteredAttemptRefusalSink;

#[cfg(test)]
impl AttemptRefusalSink for UnmeteredAttemptRefusalSink {
    fn refused(&self, _refusal: AttemptRefusal) {}
}

const INBOUND_SINK_CLOSED: &str = "inbound sink closed";
const MAX_INBOUND_FRAME_BYTES: usize = 256 * 1024;
type TaskReaperSender = mpsc::Sender<tokio::task::JoinHandle<()>>;

/// Owner-scoped custody for handles that synchronous `Drop` could not return
/// to the bounded channel reaper. Its capacity is derived from the exact
/// task set for this driver, so fallback retention cannot grow with process
/// lifetime or with unrelated driver instances.
#[cfg(test)]
struct FallbackReaperTasks {
    capacity: usize,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    supervisors: Mutex<Vec<tokio::task::JoinHandle<()>>>,
    overflow: Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[cfg(test)]
impl FallbackReaperTasks {
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            tasks: Mutex::new(Vec::with_capacity(capacity)),
            supervisors: Mutex::new(Vec::with_capacity(2)),
            overflow: Mutex::new(None),
        })
    }

    fn retain(&self, task: tokio::task::JoinHandle<()>) -> Result<(), tokio::task::JoinHandle<()>> {
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

    fn retain_supervisor(
        &self,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<(), tokio::task::JoinHandle<()>> {
        let mut supervisors = self.supervisors.lock();
        if supervisors.len() >= 2 {
            return Err(task);
        }
        supervisors.push(task);
        Ok(())
    }

    fn retain_overflow(
        &self,
        task: tokio::task::JoinHandle<()>,
    ) -> Result<(), tokio::task::JoinHandle<()>> {
        let mut overflow = self.overflow.lock();
        if overflow.is_some() {
            Err(task)
        } else {
            *overflow = Some(task);
            Ok(())
        }
    }

    fn take_tasks(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let mut tasks = self.tasks.lock().drain(..).collect::<Vec<_>>();
        if let Some(task) = self.overflow.lock().take() {
            tasks.push(task);
        }
        tasks
    }

    fn take_all(
        &self,
    ) -> (
        Vec<tokio::task::JoinHandle<()>>,
        Vec<tokio::task::JoinHandle<()>>,
    ) {
        (
            self.take_tasks(),
            self.supervisors.lock().drain(..).collect(),
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DriverTaskCounts {
    selected_relays: usize,
    fallback_relays: usize,
    fallback_supervisors: usize,
    outbound: usize,
    announcer: usize,
    driver_tasks: usize,
    cancellers: usize,
    cancel_wakes: usize,
}

impl DriverTaskCounts {
    /// Derive every driver-owned task/coordination slot before any task is
    /// created. The two always-on pumps are explicit so later insertions can
    /// stay within preallocated, configuration-derived capacities.
    fn derive(selected_relays: usize, fallback_relays: usize) -> Option<Self> {
        let fallback_supervisors = usize::from(fallback_relays != 0);
        let outbound = 1;
        let announcer = 1;
        let driver_tasks = selected_relays
            .checked_add(outbound)?
            .checked_add(announcer)?;
        let cancellers = driver_tasks.checked_add(fallback_supervisors)?;
        let cancel_wakes = selected_relays.checked_add(fallback_supervisors)?;
        Some(Self {
            selected_relays,
            fallback_relays,
            fallback_supervisors,
            outbound,
            announcer,
            driver_tasks,
            cancellers,
            cancel_wakes,
        })
    }
}

/// Exact terminal observer capacity required by one Nostr driver.
///
/// The primary reservation covers every driver task that can miss the
/// runtime reaper plus the optional fallback supervisor. The independent
/// reservation additionally covers the reaper handle itself, so a lifecycle
/// owner can fund both reservations before startup without reproducing the
/// relay-count arithmetic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrTaskCustodyPlan {
    pub primary_observer_slots: usize,
    pub reaper_observer_slots: usize,
}

/// The two independent lifecycle owners required before a Nostr driver can
/// spawn. `primary` owns ordinary task/fallback submissions; `reaper` owns
/// the reaper itself and is the non-self terminal route when primary custody
/// refuses a handle.
pub struct NostrTaskCustodyOwners {
    pub primary: Arc<dyn TaskCustodian>,
    pub reaper: Arc<dyn TaskCustodian>,
}

/// Derive exact terminal custody from the selected and fallback relay counts.
/// Returns `None` if any count or reservation would overflow platform
/// capacity. This is the single algebraic source used by driver startup and
/// by lifecycle owners planning the injected custodians.
pub fn derive_task_custody_plan(
    selected_relays: usize,
    fallback_relays: usize,
) -> Option<NostrTaskCustodyPlan> {
    let counts = DriverTaskCounts::derive(selected_relays, fallback_relays)?;
    let primary_observer_slots = counts
        .driver_tasks
        .checked_add(counts.fallback_supervisors)?;
    let reaper_observer_slots = primary_observer_slots.checked_add(1)?;
    Some(NostrTaskCustodyPlan {
        primary_observer_slots,
        reaper_observer_slots,
    })
}

/// Operator-supplied timing for socket recovery and fallback.
/// Presence cadence remains the dependency-owned schedule in `upstream.rs`;
/// these values govern only this driver's cancellation and recovery loops.
/// Every field is required in [`NostrDriverConfig`] and validated before the
/// driver creates identity, provider state, sockets, or tasks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NostrTimingConfig {
    /// Maximum time allowed for one TCP/TLS/WebSocket connection attempt.
    pub connect_timeout: Duration,
    pub reconnect_initial: Duration,
    pub reconnect_max: Duration,
    pub reconnect_max_attempts: u32,
    pub jitter_percent: u64,
    pub fallback_poll: Duration,
    pub fallback_activation_grace: Duration,
    pub session_close_timeout: Duration,
    pub announcer_cancel_quantum: Duration,
}

impl NostrTimingConfig {
    pub fn validate(&self) -> Result<(), crate::Error> {
        let millisecond_fields = [
            ("connect_timeout", self.connect_timeout),
            ("reconnect_initial", self.reconnect_initial),
            ("reconnect_max", self.reconnect_max),
            ("announcer_cancel_quantum", self.announcer_cancel_quantum),
        ];
        if millisecond_fields
            .iter()
            .any(|(_, duration)| duration.is_zero() || duration.as_millis() > u64::MAX as u128)
        {
            return Err(crate::Error::Other(
                "Nostr timing millisecond field is zero or overflows u64".into(),
            ));
        }
        if self.fallback_poll.is_zero()
            || self.fallback_activation_grace.is_zero()
            || self.session_close_timeout.is_zero()
        {
            return Err(crate::Error::Other(
                "Nostr timing duration must be non-zero".into(),
            ));
        }
        if self.reconnect_max < self.reconnect_initial {
            return Err(crate::Error::Other(
                "Nostr reconnect_max must be at least reconnect_initial".into(),
            ));
        }
        if self.reconnect_max_attempts == 0 {
            return Err(crate::Error::Other(
                "Nostr reconnect_max_attempts must be non-zero".into(),
            ));
        }
        if self.jitter_percent > 100 {
            return Err(crate::Error::Other(
                "Nostr jitter_percent must be at most 100".into(),
            ));
        }
        if self.fallback_activation_grace < self.fallback_poll {
            return Err(crate::Error::Other(
                "Nostr fallback grace must cover one polling interval".into(),
            ));
        }
        Ok(())
    }
}

#[cfg(test)]
static TEST_REAPED_TASKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_REAPED_FALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_REAPED_FALLBACK_WAKE: OnceLock<Notify> = OnceLock::new();

#[cfg(test)]
fn record_reaped_fallback() {
    TEST_REAPED_FALLBACKS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    TEST_REAPED_FALLBACK_WAKE
        .get_or_init(Notify::new)
        .notify_one();
}

fn websocket_config() -> WebSocketConfig {
    WebSocketConfig {
        max_message_size: Some(MAX_INBOUND_FRAME_BYTES),
        max_frame_size: Some(MAX_INBOUND_FRAME_BYTES),
        max_write_buffer_size: MAX_INBOUND_FRAME_BYTES + 16 * 1024,
        ..WebSocketConfig::default()
    }
}

fn binary_frame_within_limit(frame: &[u8]) -> bool {
    frame.len() <= MAX_INBOUND_FRAME_BYTES
}

struct InboundFrameLease(Option<Box<dyn DeliveryLease>>);

impl Drop for InboundFrameLease {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lease.finish(DeliveryTerminal::Cancelled);
        }
    }
}

/// Configuration for one driver instance.
#[derive(Debug, Clone)]
pub struct NostrDriverConfig {
    /// App-id used in the room-handle derivation. Forks pick
    /// their own here to isolate from upstream.
    pub app_id: String,
    /// Network id (the user-facing identifier; not the room
    /// handle — we derive that from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey
    /// surfaced by the mesh layer).
    pub device_id: String,
    /// User-supplied relay URLs. Empty = use built-in defaults.
    ///
    /// This is trusted local configuration, not peer input. Its vector and
    /// the derived relay-task set are bounded by the configured list; the
    /// driver does not retain any peer-controlled relay names.
    pub servers: Vec<String>,
    /// Hostnames excluded from the shuffle. This is also trusted local
    /// configuration and is not a wire-grown collection.
    pub denylist: Vec<String>,
    /// Top-N relays to maintain.
    pub redundancy: usize,
    /// Fall back to the built-in public relays when every primary relay is
    /// unreachable. On by default; the fallback is reactive (only while
    /// the primary set is down) so steady state stays on your own relays.
    pub public_fallback: bool,
    /// Explicit operator timing for recovery, fallback, and cancellation.
    pub timing: NostrTimingConfig,
}

/// Inbound signaling events the driver pushes to the engine.
#[derive(Debug, Clone)]
pub enum NostrInbound {
    /// A peer announced their presence in the room.
    PeerAnnounced {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer's signaling connection dropped, as far as the room can tell.
    ///
    /// **`SenderClaimed`, and that is the whole of what it is worth.** Whether
    /// the report came from an intelligent relay noticing a socket close or from
    /// a peer publishing its own `leave`, the device id reaching the engine is
    /// the one in the payload, and neither the relay nor the event author is
    /// authenticated to that device. So this is reachability evidence: it may
    /// update availability, cancel speculative work, and prompt a look at the
    /// connector, and it retires no session in any state.
    ///
    /// **Teardown is the connector's and the heartbeat's.** An earlier version
    /// of this doc said the engine could tear the peer down promptly on it,
    /// which was true and is no longer: exact connector closure, the
    /// authenticated `SessionControl::Depart` over the session itself, or the
    /// heartbeat timeout retire a session, and nothing on this path does.
    PeerLeft {
        device_id: String,
        attribution: CarrierAttribution,
    },
    /// A peer addressed us directly with a signaling message.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
#[derive(Debug, Clone)]
pub enum NostrOutbound {
    Announce,
    /// Graceful departure broadcast — the dual of [`Announce`]. Publishes a
    /// `leave` envelope as a reachability hint: a receiver may stop pacing a
    /// dial or cancel speculative work on it, and may not tear a promoted
    /// session down on it, because the device id it carries is one this sender
    /// wrote. Prompt teardown is the authenticated `SessionControl::Depart`
    /// over the session itself; this only ever arrives ahead of it. Rides the
    /// ephemeral kind (like the rest of the live negotiation traffic) so a
    /// relay never replays it onto a future session.
    Leave,
    DirectedToPeer {
        to: String,
        msg: SignalingMessage,
    },
}

/// Start with lifecycle-owned bounded custody for final driver handles.
/// Callers must derive the exact relay population with
/// [`derive_task_custody_plan`] and reserve both supplied custodians for at
/// least those returned observer-slot counts before calling this function.
/// `custody_owners.primary` funds every bounded fallback slot, while
/// `custody_owners.reaper` independently funds the task reaper and the same
/// fallback population. Both reservations are consumed before any task is
/// spawned; no driver-owned fallback queue or runtime is created here.
pub fn start_with_delivery_provider_and_sinks_with_custodian<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
    outcome_sink: Arc<dyn AttemptOutcomeSink>,
    custody_owners: NostrTaskCustodyOwners,
) -> Result<NostrDriverHandle, crate::Error>
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    start_with_delivery_provider_and_sinks_inner(
        config,
        outbound,
        inbound_tx,
        provider,
        refusal_sink,
        outcome_sink,
        custody_owners,
    )
}

fn start_with_delivery_provider_and_sinks_inner<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound_tx: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
    outcome_sink: Arc<dyn AttemptOutcomeSink>,
    custody_owners: NostrTaskCustodyOwners,
) -> Result<NostrDriverHandle, crate::Error>
where
    S: OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    let NostrTaskCustodyOwners {
        primary: custodian_owner,
        reaper: reaper_custodian_owner,
    } = custody_owners;
    config.timing.validate()?;
    let identity = NostrIdentity::generate();
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);
    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..16],
        pubkey = %&identity.pubkey_hex()[..16],
        "starting Nostr driver"
    );

    // Resolve the top-N relay set.
    let pool_storage: Vec<&str>;
    let pool: Vec<&str> = if config.servers.is_empty() {
        super::defaults::DEFAULT_RELAY_URLS.to_vec()
    } else {
        pool_storage = config.servers.iter().map(String::as_str).collect();
        pool_storage
    };
    let denylist = &config.denylist;
    let filtered: Vec<&str> = pool
        .into_iter()
        .filter(|u| !super::denylist::is_denied(u, denylist))
        .collect();
    let selected = select_top_n(&config.app_id, &filtered, config.redundancy);

    // Public-relay fallback pool. Computed now (before `selected` is
    // moved): the built-in public relays, minus the denylist and anything
    // already in the primary set. These are NOT connected in steady state
    // — a supervisor brings them up only after every primary has been down
    // for a grace window, and drops them again the moment one recovers, so
    // presence isn't leaked to public infrastructure during normal
    // operation. Off entirely when `public_fallback` is false.
    let fallback_urls: Vec<String> = if config.public_fallback {
        super::defaults::FALLBACK_RELAY_URLS
            .iter()
            .map(|s| s.to_string())
            .filter(|u| !super::denylist::is_denied(u, denylist) && !selected.contains(u))
            .collect()
    } else {
        Vec::new()
    };
    let custody_plan =
        derive_task_custody_plan(selected.len(), fallback_urls.len()).ok_or_else(|| {
            crate::Error::Other("Nostr task custody plan overflows platform capacity".into())
        })?;
    let counts =
        DriverTaskCounts::derive(selected.len(), fallback_urls.len()).ok_or_else(|| {
            crate::Error::Other("Nostr relay task count overflows platform capacity".into())
        })?;
    debug_assert_eq!(counts.selected_relays, selected.len());
    debug_assert_eq!(counts.fallback_relays, fallback_urls.len());
    debug_assert_eq!(counts.outbound, 1);
    debug_assert_eq!(counts.announcer, 1);
    // Reserve every possible fallback handle before the first task exists.
    // The primary owner covers the normal fallback route; the independent
    // reaper owner covers the task reaper itself and is also the non-self
    // terminal route if the primary reservation refuses a handle.
    let custodian = custodian_owner
        .reserve(custody_plan.primary_observer_slots)
        .map_err(|error| {
            crate::Error::Other(format!("Nostr fallback custodian exhausted: {error:?}"))
        })?;
    let reaper_custodian = reaper_custodian_owner
        .reserve(custody_plan.reaper_observer_slots)
        .map_err(|error| {
            crate::Error::Other(format!("Nostr reaper custodian exhausted: {error:?}"))
        })?;

    let delivery = DeliveryStore::new_with_outcome_sink(provider, outcome_sink);
    let (presence_tx, _) =
        watch::channel::<Option<Arc<OwnedSignal<NostrEvent, ErasedOwner>>>>(None);
    // Force-reconnect signal. A bumped generation tells every relay
    // task to drop its current socket and redial *now*, skipping the
    // backoff wait — see `run_relay` / `run_relay_session`. The engine
    // bumps it on resume-from-sleep so a zombie relay socket (a TCP
    // connection the OS never tore down while the host was suspended)
    // is replaced immediately instead of waiting minutes for the
    // kernel to notice the peer is gone. `Arc` so the same sender is
    // shared by the driver tasks (which `.subscribe()` receivers) and
    // the engine (which holds a clone to bump it).
    let force_reconnect = Arc::new(watch::channel(0u64).0);
    // Bumped on every fresh relay connection so the engine can wait for
    // signaling to actually come back after a network change before it
    // renegotiates (see `relay_connected` on `DriverShared`).
    let relay_connected = Arc::new(watch::channel(0u64).0);
    let shutdown = watch::channel(false).0;
    let shared = Arc::new(DriverShared {
        identity,
        room_handle,
        device_id: config.device_id.clone(),
        timing: config.timing,
        // Erased once, here, at the only place that knows the producer's owner
        // type. Everything downstream stays concrete, and the owner remains
        // paired with the value it funded.
        outbound: tokio::sync::Mutex::new(Some(Box::new(ErasedSource::new(outbound))
            as Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>>)),
        delivery: delivery.clone(),
        refusal_sink,
        presence_tx,
        force_reconnect: force_reconnect.clone(),
        relay_connected: relay_connected.clone(),
        shutdown: shutdown.clone(),
    });
    // These registries are exact driver cardinalities: one primary entry per
    // selected relay, optionally one fallback supervisor, and one each for
    // outbound/announce. Reserve them before the first spawn so every later
    // insertion remains owned without container growth.
    let mut cancellers = Vec::with_capacity(counts.cancellers);
    let mut cancel_wakes = Vec::with_capacity(counts.cancel_wakes);
    let mut tasks = Vec::with_capacity(counts.driver_tasks);
    // Count of primary relays with a live session; the fallback
    // supervisor watches this to decide when to step in.
    let primary_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Spawn one connection task per primary relay.
    for url in selected {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        let cancel_wake = Arc::new(Notify::new());
        let cancel_wake_for_task = cancel_wake.clone();
        cancellers.push(cancel_token);
        cancel_wakes.push(cancel_wake);
        let live = primary_live.clone();
        tasks.push(tokio::spawn(async move {
            run_relay(
                url,
                shared,
                inbound_tx,
                cancel_token_for_task,
                cancel_wake_for_task,
                Some(live),
            )
            .await;
        }));
    }

    // Spawn the public-relay fallback supervisor (no-op unless the pool is
    // non-empty, i.e. `public_fallback` is on and there are relays to use).
    let fallback_supervisor_task = if !fallback_urls.is_empty() {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        let cancel_wake = Arc::new(Notify::new());
        let cancel_wake_for_task = cancel_wake.clone();
        cancel_wakes.push(cancel_wake);
        let primary_live = primary_live.clone();
        Some(tokio::spawn(async move {
            run_fallback_supervisor(
                fallback_urls,
                shared,
                inbound_tx,
                cancel_token_for_task,
                cancel_wake_for_task,
                primary_live,
            )
            .await;
        }))
    } else {
        None
    };

    // Spawn the outbound pump.
    let shared_for_outbound = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tasks.push(tokio::spawn(async move {
        run_outbound_pump(shared_for_outbound, cancel_token_for_task).await;
    }));

    // Spawn the global announce task. Single ticker per driver
    // instance (NOT per relay) — updates the driver-owned presence watch.
    // `upstream.rs` item 7 for the schedule rationale and the
    // earlier "N-relay = N-publish" bug it fixes.
    let shared_for_announce = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tasks.push(tokio::spawn(async move {
        run_announcer(shared_for_announce, cancel_token_for_task).await;
    }));

    debug_assert_eq!(tasks.len(), counts.driver_tasks);
    debug_assert_eq!(cancellers.len(), counts.cancellers);
    debug_assert_eq!(cancel_wakes.len(), counts.cancel_wakes);
    #[cfg(test)]
    let fallback_reaper_tasks = FallbackReaperTasks::new(counts.driver_tasks);
    let (task_reaper, task_reaper_handle) = spawn_task_reaper(
        counts.driver_tasks,
        #[cfg(test)]
        Arc::clone(&fallback_reaper_tasks),
    );
    Ok(NostrDriverHandle {
        cancellers,
        cancel_wakes,
        tasks: Arc::new(Mutex::new(Some(tasks))),
        fallback_supervisor_task: Mutex::new(fallback_supervisor_task),
        task_reaper: Mutex::new(Some(task_reaper)),
        task_reaper_handle: Mutex::new(Some(task_reaper_handle)),
        custodian_owner,
        custodian: Some(custodian),
        reaper_custodian_owner,
        reaper_custodian: Some(reaper_custodian),
        force_reconnect,
        relay_connected,
        delivery,
        shutdown,
    })
}

/// Handle returned by [`start_with_delivery_provider_and_sinks_with_custodian`].
/// Drop or call [`Self::stop_and_join`] to signal every spawned task to exit.
pub struct NostrDriverHandle {
    cancellers: Vec<Arc<std::sync::atomic::AtomicBool>>,
    cancel_wakes: Vec<Arc<Notify>>,
    tasks: Arc<Mutex<Option<Vec<tokio::task::JoinHandle<()>>>>>,
    fallback_supervisor_task: Mutex<Option<tokio::task::JoinHandle<()>>>,
    task_reaper: Mutex<Option<TaskReaperSender>>,
    task_reaper_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    custodian_owner: Arc<dyn TaskCustodian>,
    custodian: Option<CustodianReservation>,
    /// Independent custody for the reaper handle itself. It cannot be the
    /// fallback drained by that reaper without creating a self-await cycle.
    reaper_custodian_owner: Arc<dyn TaskCustodian>,
    reaper_custodian: Option<CustodianReservation>,
    force_reconnect: Arc<watch::Sender<u64>>,
    relay_connected: Arc<watch::Sender<u64>>,
    delivery: Arc<DeliveryStore>,
    shutdown: watch::Sender<bool>,
}

impl NostrDriverHandle {
    /// Finish all live emissions carrying one existing attempt correlation.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        self.delivery.finish_attempt(attempt, terminal)
    }

    /// Settle a relay entry only for the exact process-local source admission
    /// that owns it. The source never enters the Nostr wire protocol.
    pub fn settle_source(
        &self,
        source: AdmissionSource,
        session: &RelaySessionId,
        event_id: &str,
        terminal: DeliveryTerminal,
    ) -> bool {
        self.delivery
            .settle_source(source, session, event_id, terminal)
    }

    fn request_stop(&self) {
        let _ = self.shutdown.send(true);
        self.delivery.shutdown();
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
        for wake in &self.cancel_wakes {
            wake.notify_waiters();
        }
    }

    /// Signal shutdown and join every driver-owned task. This is the
    /// lifecycle boundary for callers that hold the shared driver handle;
    /// Dropping the handle remains a non-blocking signal operation; the
    /// injected terminal custodians own the transferred tasks and observe
    /// their terminals independently of the caller's runtime.
    /// The task list is consumed exactly once, so concurrent shutdown callers
    /// cannot double-join or lose ownership of a task.
    pub async fn stop_and_join(&self) {
        self.request_stop();
        let fallback_supervisor = { self.fallback_supervisor_task.lock().take() };
        let tasks = self.tasks.lock().take().unwrap_or_default();
        for task in tasks {
            observe_nostr_task(task, "Nostr driver task").await;
        }
        if let Some(supervisor) = fallback_supervisor {
            observe_nostr_task(supervisor, "Nostr fallback supervisor").await;
        }
        let reaper_sender = self.task_reaper.lock().take();
        drop(reaper_sender);
        let reaper = { self.task_reaper_handle.lock().take() };
        if let Some(reaper) = reaper {
            observe_nostr_task(reaper, "Nostr task reaper").await;
        }
        self.custodian_owner.close();
        self.reaper_custodian_owner.close();
    }

    /// Clone of the force-reconnect signal. The engine stashes this
    /// (see `engine::state::NetworkState::set_relay_reconnect`) and
    /// bumps it to make every relay redial immediately — e.g. on
    /// resume from sleep, when the existing sockets are stale.
    pub fn reconnect_signal(&self) -> Arc<watch::Sender<u64>> {
        self.force_reconnect.clone()
    }

    /// Clone of the relay-connected signal. The engine subscribes and, after
    /// asking for a redial on a network change, waits for the next bump (a
    /// fresh relay session) before renegotiating ICE — so the offer isn't
    /// published into a not-yet-reconnected relay. See
    /// `engine::state::NetworkState::set_relay_connected_signal`.
    pub fn connected_signal(&self) -> Arc<watch::Sender<u64>> {
        self.relay_connected.clone()
    }
}

impl Drop for NostrDriverHandle {
    fn drop(&mut self) {
        self.request_stop();
        let mut custodian = self.custodian.take();
        let mut fallback_supervisor = { self.fallback_supervisor_task.lock().take() };
        let reaper_task = { self.task_reaper_handle.lock().take() };
        if let Some(supervisor) = fallback_supervisor.take() {
            submit_to_terminal_custody(
                &mut custodian,
                &mut self.reaper_custodian,
                supervisor,
                "Nostr fallback supervisor",
            );
        }
        let tasks = self.tasks.lock().take().unwrap_or_default();
        drop(self.task_reaper.lock().take());
        for task in tasks {
            task.abort();
            submit_to_terminal_custody(
                &mut custodian,
                &mut self.reaper_custodian,
                task,
                "Nostr driver task",
            );
        }
        if let Some(reaper_task) = reaper_task {
            // The reaper is always submitted last to its independent owner.
            // Its reservation includes every bounded fallback slot, so a
            // primary-owner refusal cannot create a self-await cycle.
            submit_to_terminal_custody(
                &mut self.reaper_custodian,
                &mut custodian,
                reaper_task,
                "Nostr task reaper",
            );
        }
    }
}

fn spawn_task_reaper(
    capacity: usize,
    #[cfg(test)] fallback: Arc<FallbackReaperTasks>,
) -> (TaskReaperSender, tokio::task::JoinHandle<()>) {
    let (sender, receiver) = mpsc::channel(capacity);
    let task = tokio::spawn(async move {
        #[cfg(test)]
        reap_owned_tasks(receiver, fallback).await;
        #[cfg(not(test))]
        reap_owned_tasks(receiver).await;
    });
    (sender, task)
}

fn submit_to_terminal_custody(
    primary: &mut Option<CustodianReservation>,
    independent: &mut Option<CustodianReservation>,
    task: tokio::task::JoinHandle<()>,
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
    // the failure explicit instead of silently aborting or dropping a handle.
    panic!("{context} terminal custody refused after exact pre-reservation");
}

#[cfg(test)]
fn abort_and_join(
    reaper: &TaskReaperSender,
    task: tokio::task::JoinHandle<()>,
    fallback: &Arc<FallbackReaperTasks>,
) {
    task.abort();
    match reaper.try_send(task) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(task))
        | Err(tokio::sync::mpsc::error::TrySendError::Closed(task)) => {
            retain_or_overflow(fallback, task, "Nostr test fallback");
        }
    }
}

#[cfg(test)]
fn retain_or_overflow(
    fallback: &Arc<FallbackReaperTasks>,
    task: tokio::task::JoinHandle<()>,
    context: &str,
) {
    if let Err(task) = fallback.retain(task) {
        fallback
            .retain_overflow(task)
            .unwrap_or_else(|_| panic!("{context} exceeded its funded test capacity"));
    }
}

#[cfg(test)]
async fn reap_fallback_reaper_tasks(fallback: &Arc<FallbackReaperTasks>) {
    let (tasks, supervisors) = fallback.take_all();
    for task in tasks {
        observe_nostr_task(task, "Nostr fallback reaper").await;
        #[cfg(test)]
        record_reaped_fallback();
    }
    for task in supervisors {
        observe_nostr_task(task, "Nostr fallback reaper").await;
        #[cfg(test)]
        record_reaped_fallback();
    }
}

async fn observe_nostr_task(task: tokio::task::JoinHandle<()>, context: &str) {
    match task.await {
        Ok(()) => trace!(%context, "task joined normally"),
        Err(error) if error.is_cancelled() => {
            debug!(%context, ?error, "task was cancelled")
        }
        Err(error) if error.is_panic() => warn!(%context, ?error, "task panicked"),
        Err(error) => warn!(%context, ?error, "task failed to join"),
    }
}

#[cfg(not(test))]
async fn reap_owned_tasks(mut receiver: mpsc::Receiver<tokio::task::JoinHandle<()>>) {
    while let Some(task) = receiver.recv().await {
        observe_nostr_task(task, "Nostr driver task").await;
    }
}

#[cfg(test)]
async fn reap_owned_tasks(
    mut receiver: mpsc::Receiver<tokio::task::JoinHandle<()>>,
    fallback: Arc<FallbackReaperTasks>,
) {
    while let Some(task) = receiver.recv().await {
        observe_nostr_task(task, "Nostr driver task").await;
        TEST_REAPED_TASKS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
    for task in fallback.take_tasks() {
        observe_nostr_task(task, "Nostr fallback task").await;
        TEST_REAPED_FALLBACKS.fetch_add(1, std::sync::atomic::Ordering::AcqRel);
    }
}

struct DriverShared {
    identity: NostrIdentity,
    room_handle: String,
    device_id: String,
    timing: NostrTimingConfig,
    outbound:
        tokio::sync::Mutex<Option<Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>>>>,
    delivery: Arc<DeliveryStore>,
    refusal_sink: Arc<dyn AttemptRefusalSink>,
    presence_tx: watch::Sender<Option<Arc<OwnedSignal<NostrEvent, ErasedOwner>>>>,
    /// Generation counter for forced reconnects. Bumping it wakes
    /// every relay task's `watch::Receiver` so it drops its socket
    /// and redials without waiting out the backoff. See the comment
    /// at the channel's creation in [`start`].
    force_reconnect: Arc<watch::Sender<u64>>,
    /// Monotonic counter bumped each time a relay establishes a fresh
    /// session. The engine waits on a change to this (after asking for a
    /// redial) before it fans out an ICE-restart offer, so the offer isn't
    /// published into a relay that hasn't reconnected yet — those ephemeral
    /// offers/candidates would reach nobody (the "0 remote candidates
    /// arrived" stall). See `engine::network_watch::on_network_change`.
    relay_connected: Arc<watch::Sender<u64>>,
    shutdown: watch::Sender<bool>,
    // Outbound *directed* events (offers / answers / candidates) removed;
    // while every relay socket was mid-reconnect; DeliveryStore owns live attempts.
    // A reconnecting session registers fresh per-relay custody entries.
    // DeliveryStore retains them for the next live relay session.
    // DeliveryStore owns live directed attempts and registers fresh custody
    // entries for each reconnecting relay session. The source owner remains in
    // the exact attempt record until its terminal outcome.
    //
    // `outbound` and the inbound sink are caller-owned queue boundaries. This
    // driver does not add a second queue or an event-id cache: each received
    // frame is parsed once and each outbound value is admitted into the
    // provider-funded DeliveryStore before relay fan-out.
}

/// The NIP-01 filter set for our room subscription:
///
///   1. presence (stored kind, replayed over the `since` window),
///   2. directed-to-me negotiation (ephemeral kind, `#p` = us).
///
/// One REQ, both filters (OR semantics).
///
/// # There is no third, room-wide filter, and there is no longer a state
/// machine that adds one
///
/// An earlier revision kept a per-room capability map: every announced peer
/// recorded whether it stamped recipient tags, and while any of them did not,
/// the subscription added a catch-all that asked the relay for *every* pairwise
/// offer, answer and candidate in the room. Two things were wrong with it.
///
/// It was an unbounded unauthenticated keyspace. The map was keyed by the
/// `peer_id` out of an announce nobody authenticated, so one sender could
/// publish arbitrarily many claimed device ids, grow the map without bound, and
/// — because a claimed id that does not advertise the tag holds the catch-all
/// on — keep every peer's pairwise negotiation flowing past every subscriber.
/// The memory and the metadata amplification were the same lever.
///
/// It was also a mixed-version compatibility path, and the adopted hard-alpha
/// cutover has none: peers are same-build, there is no downgrade, and nothing
/// on the wire needs to ask what shape the other end speaks. The map is deleted
/// rather than capped, because a capacity would have kept the amplification and
/// only bounded the memory.
fn desired_filters(shared: &DriverShared) -> Vec<Value> {
    let since = now_secs().saturating_sub(PRESENCE_REPLAY_WINDOW_SECS);
    vec![
        serde_json::json!({
            "kinds": [SIGNALING_EVENT_KIND],
            "#r": [shared.room_handle.clone()],
            "since": since,
        }),
        // Directed-to-me, plus room-addressed broadcasts: a tagging
        // build stamps broadcast ephemerals (`leave`) with the room
        // handle as their recipient, so the narrowed shape still hears
        // departures. `#p` is an OR-list per NIP-01.
        serde_json::json!({
            "kinds": [SIGNALING_EPHEMERAL_KIND],
            "#r": [shared.room_handle.clone()],
            "#p": [shared.device_id.clone(), shared.room_handle.clone()],
        }),
    ]
}

/// Serialize the room REQ for `desired_filters`.
fn build_req(shared: &DriverShared, sub_id: &str) -> String {
    let mut arr = vec![
        Value::String("REQ".to_string()),
        Value::String(sub_id.to_string()),
    ];
    arr.extend(desired_filters(shared));
    Value::Array(arr).to_string()
}

/// Deterministic configured-percentage jitter on a timer, seeded from the device id and a
/// per-use salt, so co-restarted nodes (a site-wide power blip, a relay
/// outage ending) don't fire their timers in lockstep forever. Pure —
/// same inputs, same wait — which keeps tests exact.
fn jittered_ms(base_ms: u64, jitter_percent: u64, seed: &str, salt: u64) -> u64 {
    use sha2::{Digest, Sha256};
    if base_ms == 0 {
        return 0;
    }
    let mut hasher = Sha256::new();
    hasher.update(seed.as_bytes());
    hasher.update(salt.to_le_bytes());
    let digest = hasher.finalize();
    let raw = u64::from_le_bytes(digest[..8].try_into().expect("8 bytes"));
    // Map to [-jitter, +jitter] of base using a wide intermediate. A valid
    // owner policy may select any u64 millisecond value; doing this in u64
    // would make `span + 1` and the final sum wrap at the boundary.
    let base = u128::from(base_ms);
    let jitter = u128::from(jitter_percent);
    let lower = base.saturating_mul(100u128.saturating_sub(jitter)) / 100;
    let upper = base.saturating_mul(100u128.saturating_add(jitter)) / 100;
    let width = upper.saturating_sub(lower);
    if width == 0 {
        return base_ms;
    }
    let offset = u128::from(raw) % (width + 1);
    lower.saturating_add(offset).min(u128::from(u64::MAX)) as u64
}

fn relay_retry_salt(room: &str, relay: &str, attempt: u32) -> u64 {
    use sha2::{Digest, Sha256};
    let mut hash = Sha256::new();
    for part in [room, relay] {
        hash.update((part.len() as u64).to_le_bytes());
        hash.update(part.as_bytes());
    }
    hash.update(attempt.to_le_bytes());
    u64::from_le_bytes(hash.finalize()[..8].try_into().expect("eight digest bytes"))
}

fn reconnect_base_ms(attempt: u32, timing: &NostrTimingConfig) -> u64 {
    if attempt == 0 {
        return 0;
    }
    let max_ms: u64 = timing
        .reconnect_max
        .as_millis()
        .try_into()
        .expect("validated reconnect_max fits u64 milliseconds");
    let initial_ms: u64 = timing
        .reconnect_initial
        .as_millis()
        .try_into()
        .expect("validated reconnect_initial fits u64 milliseconds");
    initial_ms
        .checked_shl(attempt.saturating_sub(1))
        .unwrap_or(max_ms)
        .min(max_ms)
}

fn next_reconnect_attempt(attempt: u32, max_attempts: u32) -> u32 {
    attempt.saturating_add(1).min(max_attempts)
}

struct RelaySessionCancellation<'a> {
    flag: &'a std::sync::atomic::AtomicBool,
    wake: &'a Notify,
}

enum RelayDialOutcome<T, E> {
    Connected(T),
    Failed(E),
    TimedOut,
    Cancelled,
}

/// Keep a pending socket handshake bounded by the owner-selected deadline
/// while retaining the same cancellation and shutdown linearization as the
/// session writer. The generic future makes a pending dial deterministic in
/// the focused controls without creating a real socket or task.
async fn await_relay_dial<F, T, E>(
    dial: F,
    timeout: Duration,
    cancellation: &RelaySessionCancellation<'_>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> RelayDialOutcome<T, E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let cancel_notified = cancellation.wake.notified();
    tokio::pin!(cancel_notified);
    cancel_notified.as_mut().enable();
    if cancellation.flag.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
        return RelayDialOutcome::Cancelled;
    }
    tokio::select! {
        result = tokio::time::timeout(timeout, dial) => match result {
            Ok(Ok(value)) => RelayDialOutcome::Connected(value),
            Ok(Err(error)) => RelayDialOutcome::Failed(error),
            Err(_) => RelayDialOutcome::TimedOut,
        },
        changed = shutdown_rx.changed() => {
            let _ = changed;
            RelayDialOutcome::Cancelled
        }
        _ = &mut cancel_notified => RelayDialOutcome::Cancelled,
    }
}

#[derive(Debug)]
enum RelayWriteOutcome {
    Cancelled,
    Failed(String),
}

async fn send_relay_frame<S>(
    write: &mut S,
    frame: WsMessage,
    cancellation: &RelaySessionCancellation<'_>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), RelayWriteOutcome>
where
    S: Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    let cancel_notified = cancellation.wake.notified();
    tokio::pin!(cancel_notified);
    cancel_notified.as_mut().enable();
    if cancellation.flag.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
        return Err(RelayWriteOutcome::Cancelled);
    }
    tokio::select! {
        result = write.send(frame) => result
            .map_err(|error| RelayWriteOutcome::Failed(error.to_string())),
        changed = shutdown_rx.changed() => {
            let _ = changed;
            Err(RelayWriteOutcome::Cancelled)
        }
        _ = &mut cancel_notified => Err(RelayWriteOutcome::Cancelled),
    }
}

async fn run_relay(
    url: String,
    shared: Arc<DriverShared>,
    inbound_tx: InboundSink<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    cancel_wake: Arc<Notify>,
    live: Option<Arc<std::sync::atomic::AtomicUsize>>,
) {
    let mut backoff_attempt = 0u32;
    // Receiver for forced reconnects. `borrow_and_update` marks the
    // current generation as seen so a stale value from before this
    // task started can't fire a spurious immediate reconnect.
    let mut force_rx = shared.force_reconnect.subscribe();
    force_rx.borrow_and_update();
    let mut shutdown_rx = shared.shutdown.subscribe();
    let cancellation = RelaySessionCancellation {
        flag: cancel.as_ref(),
        wake: cancel_wake.as_ref(),
    };
    // Tracks consecutive connect failures so we can dampen the log
    // spam from chronically-broken public relays (DNS no-such-host,
    // 403s, TLS handshake timeouts). Without this, a single bad
    // relay floods stderr with one WARN every 1/2/4/8/16/32/60s
    // forever — drowning out everything else. We surface the first
    // failure of a streak at WARN, drop subsequent failures to
    // DEBUG, then announce recovery at INFO once the relay starts
    // accepting again. Mirrors the rationale behind MyOwnLLM's
    // Trystero-patch noise suppression.
    let mut consecutive_failures = 0u32;
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
            return;
        }
        let connect = await_relay_dial(
            tokio_tungstenite::connect_async_with_config(&url, Some(websocket_config()), false),
            shared.timing.connect_timeout,
            &cancellation,
            &mut shutdown_rx,
        )
        .await;
        match connect {
            RelayDialOutcome::Connected((stream, _)) => {
                let (session, session_refusal, refused) =
                    shared.delivery.open_session_with_refusals();
                if let Some(error) = session_refusal {
                    warn!(
                        relay = %short(&url),
                        ?error,
                        "relay-session custody refused by provider"
                    );
                } else {
                    // Provider custody permits the session, but only an EOSE
                    // for its exact subscription establishes relay readiness.
                    let mut observation = RelaySessionObservation::new(live.as_deref());
                    for refusal in refused {
                        warn!(
                            relay = %short(&url),
                            attempt = %refusal.attempt,
                            event_id = %refusal.event_id,
                            ?refusal.refusal,
                            "relay-session delivery refused by provider"
                        );
                        shared.refusal_sink.refused(refusal);
                    }
                    let outcome = run_relay_session(
                        &url,
                        stream,
                        &shared,
                        &inbound_tx,
                        &cancellation,
                        &mut force_rx,
                        RelaySessionContext {
                            id: &session,
                            observation: &mut observation,
                        },
                    )
                    .await;
                    // The store removes only this relay's custody. Its
                    // per-event carrier aggregate decides whether the resulting
                    // carrier observation is new, order-independent, and
                    // reconnect-scoped before notifying the consumer.
                    shared
                        .delivery
                        .close_session(session, DeliveryTerminal::Cancelled);
                    if observation.stable_at(Instant::now()) {
                        consecutive_failures = 0;
                        backoff_attempt = 0;
                    } else {
                        consecutive_failures = consecutive_failures.saturating_add(1);
                    }
                    // Drop always balances an admitted live count, including
                    // cancellation of this caller. It owns no task or payload.
                    drop(observation);
                    trace!(relay = %short(&url), outcome = ?outcome, "relay session ended");
                    if matches!(outcome, RelaySessionOutcome::ConsumerClosed) {
                        let _ = shared.shutdown.send(true);
                        cancel.store(true, std::sync::atomic::Ordering::SeqCst);
                        return;
                    }
                    if matches!(outcome, RelaySessionOutcome::ForcedReconnect) {
                        // Engine asked us to redial now (e.g. resume from
                        // sleep). Skip the backoff entirely and reconnect on
                        // the next loop turn so a fresh socket — and the
                        // open-announce it sends — lands immediately.
                        debug!(relay = %short(&url), "forced reconnect — redialing now");
                        backoff_attempt = 0;
                        continue;
                    }
                }
            }
            RelayDialOutcome::Failed(e) => {
                if consecutive_failures == 0 {
                    warn!(relay = %short(&url), "relay connect failed: {e}");
                } else {
                    debug!(
                        relay = %short(&url),
                        attempt = consecutive_failures.saturating_add(1),
                        "relay still failing: {e}"
                    );
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
            RelayDialOutcome::TimedOut => {
                if consecutive_failures == 0 {
                    warn!(relay = %short(&url), "relay connect timed out after {:?}", shared.timing.connect_timeout);
                } else {
                    debug!(
                        relay = %short(&url),
                        attempt = consecutive_failures.saturating_add(1),
                        "relay connect still timing out after {:?}",
                        shared.timing.connect_timeout
                    );
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
            RelayDialOutcome::Cancelled => return,
        }
        if cancel.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
            return;
        }
        // Reconnect backoff doubles from the owner-configured initial delay
        // until the owner-configured maximum — the increment precedes the
        // shift — then applies the configured percentage per node so a shared
        // outage (relay restart, site-wide blip) doesn't recover as a
        // synchronized redial herd.
        // A forced-reconnect bump cuts the wait short so resume-from-sleep
        // recovery doesn't sit through a backoff that accrued while the
        // host was suspended.
        backoff_attempt =
            next_reconnect_attempt(backoff_attempt, shared.timing.reconnect_max_attempts);
        let base_ms = reconnect_base_ms(backoff_attempt, &shared.timing);
        let wait_ms = jittered_ms(
            base_ms,
            shared.timing.jitter_percent,
            &shared.device_id,
            relay_retry_salt(&shared.room_handle, &url, backoff_attempt),
        );
        debug!(relay = %short(&url), wait_ms, "relay backoff before reconnect");
        tokio::select! {
            _ = sleep(Duration::from_millis(wait_ms)) => {}
            _ = force_rx.changed() => {
                debug!(relay = %short(&url), "forced reconnect during backoff — redialing now");
                backoff_attempt = 0;
            }
            _ = shutdown_rx.changed() => return,
            _ = cancel_wake.notified() => return,
        }
    }
}

/// What the fallback supervisor should do on a given tick. A pure
/// function of the inputs so the policy is unit-testable without spawning
/// relays.
#[derive(Debug, PartialEq)]
enum FallbackAction {
    /// Primary down past the grace and fallback isn't up — start it.
    Activate,
    /// A primary returned while fallback was up — stop it.
    StandDown,
    /// Nothing to change this tick.
    Hold,
}

fn fallback_action(
    timing: &NostrTimingConfig,
    primary_live: usize,
    fallback_active: bool,
    down_for: Duration,
) -> FallbackAction {
    if primary_live > 0 {
        if fallback_active {
            FallbackAction::StandDown
        } else {
            FallbackAction::Hold
        }
    } else if !fallback_active && down_for >= timing.fallback_activation_grace {
        FallbackAction::Activate
    } else {
        FallbackAction::Hold
    }
}

/// Supervises the public-relay fallback. Steady state: idle, sampling
/// `primary_live`. When every primary relay has been down for
/// `shared.timing.fallback_activation_grace` it spawns a `run_relay` task per
/// fallback URL; when a primary returns it cancels them. So the public
/// relays only ever carry traffic when the configured/primary set can't —
/// presence stays off public infrastructure in normal operation.
async fn run_fallback_supervisor(
    urls: Vec<String>,
    shared: Arc<DriverShared>,
    inbound_tx: InboundSink<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    cancel_wake: Arc<Notify>,
    primary_live: Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Instant;

    // Cancel tokens and join handles for the fallback relay tasks currently
    // running. The supervisor owns both halves so standing down cannot leave
    // a detached relay task retaining provider custody.
    let mut active: Vec<(
        Arc<std::sync::atomic::AtomicBool>,
        Arc<Notify>,
        tokio::task::JoinHandle<()>,
    )> = Vec::with_capacity(urls.len());
    let mut down_since: Option<Instant> = None;
    let mut shutdown_rx = shared.shutdown.subscribe();

    loop {
        if cancel.load(SeqCst) || *shutdown_rx.borrow() {
            for (c, wake, _) in &active {
                c.store(true, SeqCst);
                wake.notify_waiters();
            }
            while let Some((_, _, task)) = active.pop() {
                observe_nostr_task(task, "fallback relay task").await;
            }
            return;
        }

        let live = primary_live.load(SeqCst);
        if live == 0 {
            down_since.get_or_insert_with(Instant::now);
        } else {
            down_since = None;
        }
        let down_for = down_since.map(|t| t.elapsed()).unwrap_or(Duration::ZERO);

        match fallback_action(&shared.timing, live, !active.is_empty(), down_for) {
            FallbackAction::Activate => {
                warn!(
                    count = urls.len(),
                    "primary signaling unreachable — bringing up public fallback relays"
                );
                for url in &urls {
                    let task_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    let task_cancel_for_task = task_cancel.clone();
                    let task_wake = Arc::new(Notify::new());
                    let task_wake_for_task = task_wake.clone();
                    let shared = shared.clone();
                    let inbound_tx = inbound_tx.clone();
                    let url = url.clone();
                    let task = tokio::spawn(async move {
                        run_relay(
                            url,
                            shared,
                            inbound_tx,
                            task_cancel_for_task,
                            task_wake_for_task,
                            None,
                        )
                        .await;
                    });
                    debug_assert!(active.len() < active.capacity());
                    active.push((task_cancel, task_wake, task));
                }
            }
            FallbackAction::StandDown => {
                info!("primary signaling recovered — standing down public fallback relays");
                for (c, wake, _) in &active {
                    c.store(true, SeqCst);
                    wake.notify_waiters();
                }
                while let Some((_, _, task)) = active.pop() {
                    observe_nostr_task(task, "fallback relay task").await;
                }
            }
            FallbackAction::Hold => {}
        }

        tokio::select! {
            _ = sleep(shared.timing.fallback_poll) => {}
            _ = shutdown_rx.changed() => {
                for (c, wake, _) in &active {
                    c.store(true, SeqCst);
                    wake.notify_waiters();
                }
                cancel_wake.notify_waiters();
                while let Some((_, _, task)) = active.pop() {
                    observe_nostr_task(task, "fallback relay task").await;
                }
                return;
            }
        }
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Some variants are read only via their Debug impl in trace logs.
enum RelaySessionOutcome {
    Cancelled,
    SocketClosed,
    Error(String),
    /// The engine bumped the force-reconnect signal — drop this socket
    /// and redial immediately, skipping the backoff. Matched in
    /// [`run_relay`].
    ForcedReconnect,
    /// The engine-side inbound consumer is gone; do not reconnect this relay.
    ConsumerClosed,
    /// A capacity NOTICE is a rejected subscription, not a stable session.
    Rejected,
}

const ROOM_SUBSCRIPTION_ID: &str = "mom-sig-1";
// Upstream relay-flap criterion, not a retry cadence or resource grant.
const RELAY_STABLE_SESSION: Duration = Duration::from_secs(10);

struct RelaySessionObservation<'a> {
    live: Option<&'a std::sync::atomic::AtomicUsize>,
    admitted_at: Option<Instant>,
}

impl<'a> RelaySessionObservation<'a> {
    fn new(live: Option<&'a std::sync::atomic::AtomicUsize>) -> Self {
        Self {
            live,
            admitted_at: None,
        }
    }

    fn admit(&mut self, now: Instant) -> bool {
        if self.admitted_at.is_some() {
            return false;
        }
        self.admitted_at = Some(now);
        if let Some(live) = self.live {
            live.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
        true
    }

    fn stable_at(&self, now: Instant) -> bool {
        self.admitted_at
            .and_then(|at| now.checked_duration_since(at))
            .is_some_and(|age| age >= RELAY_STABLE_SESSION)
    }
}

impl Drop for RelaySessionObservation<'_> {
    fn drop(&mut self) {
        if self.admitted_at.is_some() {
            if let Some(live) = self.live {
                live.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
            }
        }
    }
}

struct RelaySessionContext<'a, 'b> {
    id: &'a RelaySessionId,
    observation: &'a mut RelaySessionObservation<'b>,
}

#[derive(Debug, PartialEq, Eq)]
enum RelayControlFrame {
    Other,
    Eose,
    Rejected,
}

/// The relay read loop listens to the driver-owned cancellation signal, so a
/// stopped driver tears down an otherwise-idle socket without a cancellation
/// poll and wakes immediately for inbound frames and outbound work.
async fn send_pending_deliveries<S>(
    url: &str,
    write: &mut S,
    delivery: &Arc<DeliveryStore>,
    session: &RelaySessionId,
    cancellation: &RelaySessionCancellation<'_>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<(), RelayWriteOutcome>
where
    S: Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    // Admission has already funded the attempt record and this exact relay
    // entry. Each loop iteration emits one frame for one funded relay; it
    // never re-admits or acquires a second provider lease for the emission.
    while let Some(event_id) = delivery.next_pending(session) {
        let Some(frame) = delivery.with_event(&event_id, |event| {
            serde_json::json!(["EVENT", event]).to_string()
        }) else {
            continue;
        };
        match send_relay_frame(write, WsMessage::Text(frame), cancellation, shutdown_rx).await {
            Ok(()) => {}
            Err(RelayWriteOutcome::Cancelled) => return Err(RelayWriteOutcome::Cancelled),
            Err(RelayWriteOutcome::Failed(error)) => {
                delivery.settle(
                    session,
                    &event_id,
                    DeliveryTerminal::TypedRefused(format!("local write: {error}")),
                );
                return Err(RelayWriteOutcome::Failed(format!("send publish: {error}")));
            }
        }
    }
    let _ = url;
    Ok(())
}

/// Prepare a relay session's delivery side before entering the main select
/// loop. The notification is enabled before the initial scan and remains
/// armed while the open announcement is written, closing the scan-to-wait
/// gap in which a directed admission could otherwise lose its wakeup.
async fn prepare_relay_delivery<'a, S>(
    url: &str,
    write: &mut S,
    shared: &DriverShared,
    delivery: &'a Arc<DeliveryStore>,
    session: &RelaySessionId,
    cancellation: &RelaySessionCancellation<'_>,
    shutdown_rx: &mut watch::Receiver<bool>,
) -> Result<Pin<Box<tokio::sync::futures::Notified<'a>>>, RelayWriteOutcome>
where
    S: Sink<WsMessage> + Unpin,
    S::Error: std::fmt::Display,
{
    let mut delivery_notified = Box::pin(delivery.notification().notified());
    delivery_notified.as_mut().enable();

    send_pending_deliveries(url, write, delivery, session, cancellation, shutdown_rx).await?;

    // Clone the watch value before branching so its read guard is dropped
    // before the empty branch calls `Sender::send` below.
    let current_presence = shared.presence_tx.borrow().clone();
    let event = if let Some(event) = current_presence {
        event
    } else {
        let event = shared
            .delivery
            .admit_presence(build_announce_event(shared))
            .map_err(|error| {
                RelayWriteOutcome::Failed(format!("presence admission refused: {error:?}"))
            })?;
        let event = Arc::new(event);
        let _ = shared.presence_tx.send(Some(event.clone()));
        event
    };
    let frame = serde_json::json!(["EVENT", event.value()]).to_string();
    match send_relay_frame(write, WsMessage::Text(frame), cancellation, shutdown_rx).await {
        Ok(()) => {}
        Err(RelayWriteOutcome::Cancelled) => return Err(RelayWriteOutcome::Cancelled),
        Err(RelayWriteOutcome::Failed(error)) => {
            return Err(RelayWriteOutcome::Failed(format!(
                "send open-announce: {error}"
            )));
        }
    }

    Ok(delivery_notified)
}

async fn run_relay_session(
    url: &str,
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    shared: &Arc<DriverShared>,
    inbound_tx: &InboundSink<NostrInbound>,
    cancellation: &RelaySessionCancellation<'_>,
    force_rx: &mut watch::Receiver<u64>,
    context: RelaySessionContext<'_, '_>,
) -> RelaySessionOutcome {
    let RelaySessionContext {
        id: session,
        observation,
    } = context;
    let (mut write, mut read) = stream.split();
    let mut shutdown_rx = shared.shutdown.subscribe();

    // Open the room subscription — one REQ, several filters (see
    // `desired_filters`):
    //   - presence on the stored kind, with a `since` window that
    //     replays the last few minutes so a late joiner discovers
    //     everyone already here;
    //   - directed-to-me negotiation on the ephemeral kind (`#p` us).
    // Ephemeral events are never stored, so `since` governs presence
    // replay only — negotiation always arrives live (see
    // `event::SIGNALING_EPHEMERAL_KIND`). The shape is fixed for the life
    // of the session: nothing a peer publishes can widen it. The relay owns
    // the replay result; this task retains only the current socket stream and
    // does not build a local replay queue.
    let sub_id = ROOM_SUBSCRIPTION_ID;
    let req_text = build_req(shared, sub_id);

    match send_relay_frame(
        &mut write,
        WsMessage::Text(req_text),
        cancellation,
        &mut shutdown_rx,
    )
    .await
    {
        Ok(()) => {}
        Err(RelayWriteOutcome::Cancelled) => return RelaySessionOutcome::Cancelled,
        Err(RelayWriteOutcome::Failed(error)) => {
            return RelaySessionOutcome::Error(format!("send REQ: {error}"));
        }
    }

    // Subscribe to the driver-owned presence watch for this socket.
    // Announce ticking lives in `run_announcer` — one shared task
    // per driver instance, not one per relay — so the per-cycle
    // publish rate doesn't scale with relay count.
    let mut presence_rx = shared.presence_tx.subscribe();
    let mut delivery_notified = match prepare_relay_delivery(
        url,
        &mut write,
        shared,
        &shared.delivery,
        session,
        cancellation,
        &mut shutdown_rx,
    )
    .await
    {
        Ok(notification) => notification,
        Err(RelayWriteOutcome::Cancelled) => return RelaySessionOutcome::Cancelled,
        Err(RelayWriteOutcome::Failed(error)) => return RelaySessionOutcome::Error(error),
    };

    loop {
        if cancellation.flag.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
            // Best-effort clean close so the relay sees our departure
            // immediately (a Close frame, falling back to the TCP FIN
            // from dropping the stream). Bounded so a wedged socket
            // can't hang teardown.
            let _ = tokio::time::timeout(shared.timing.session_close_timeout, write.close()).await;
            return RelaySessionOutcome::Cancelled;
        }
        let cancel_notified = cancellation.wake.notified();
        tokio::select! {
            msg = read.next() => {
                let Some(msg) = msg else { return RelaySessionOutcome::SocketClosed };
                let frame = match msg {
                    Ok(WsMessage::Text(t)) => t,
                    Ok(WsMessage::Binary(b)) => {
                        if !binary_frame_within_limit(&b) {
                            trace!(relay = %short(url), "dropping oversized binary frame");
                            continue;
                        }
                        match std::str::from_utf8(&b) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                        }
                    }
                    Ok(WsMessage::Close(_)) => return RelaySessionOutcome::SocketClosed,
                    Ok(_) => continue,
                    Err(e) => return RelaySessionOutcome::Error(format!("ws read: {e}")),
                };
                match handle_inbound_frame_observed(url, &frame, shared, inbound_tx, session.clone()) {
                    Ok(RelayControlFrame::Eose) => {
                        if observation.admit(Instant::now()) {
                            shared.relay_connected.send_modify(|generation| {
                                *generation = generation.checked_add(1).unwrap_or(u64::MAX);
                            });
                            info!(relay = %short(url), "relay room subscription admitted");
                        }
                    }
                    Ok(RelayControlFrame::Rejected) => return RelaySessionOutcome::Rejected,
                    Ok(RelayControlFrame::Other) => {}
                    Err(e) if e == INBOUND_SINK_CLOSED => return RelaySessionOutcome::ConsumerClosed,
                    Err(e) => trace!(relay = %short(url), "inbound frame parse: {e}"),
                }
            }
            _ = &mut delivery_notified => {
                // Re-arm before sending so an admission during this write is
                // observed by the next select turn as well.
                delivery_notified = Box::pin(shared.delivery.notification().notified());
                delivery_notified.as_mut().enable();
                if let Err(error) = send_pending_deliveries(
                    url,
                    &mut write,
                    &shared.delivery,
                    session,
                    cancellation,
                    &mut shutdown_rx,
                )
                .await
                {
                    return match error {
                        RelayWriteOutcome::Cancelled => RelaySessionOutcome::Cancelled,
                        RelayWriteOutcome::Failed(error) => RelaySessionOutcome::Error(error),
                    };
                }
            }
            changed = presence_rx.changed() => {
                if changed.is_err() {
                    return RelaySessionOutcome::Cancelled;
                }
                let event = presence_rx.borrow().clone();
                if let Some(event) = event {
                    let frame = serde_json::json!(["EVENT", event.value()]).to_string();
                    match send_relay_frame(
                        &mut write,
                        WsMessage::Text(frame),
                        cancellation,
                        &mut shutdown_rx,
                    )
                    .await
                    {
                        Ok(()) => {}
                        Err(RelayWriteOutcome::Cancelled) => {
                            return RelaySessionOutcome::Cancelled;
                        }
                        Err(RelayWriteOutcome::Failed(error)) => {
                            return RelaySessionOutcome::Error(format!("send presence: {error}"));
                        }
                    }
                    // The relay socket has synchronously accepted the frame;
                    // commit the exact retained watch record now.
                    event.accept();
                }
            }
            // Forced reconnect — the engine bumped the generation
            // (resume-from-sleep, etc.). Tear this session down so
            // `run_relay` redials immediately onto a fresh socket. We
            // skip the clean Close frame here: the whole point is that
            // the existing socket is likely a zombie, so spending up to
            // a second trying to close it gracefully would defeat the
            // "reconnect now" intent.
            _ = force_rx.changed() => {
                return RelaySessionOutcome::ForcedReconnect;
            }
            _ = shutdown_rx.changed() => {
                return RelaySessionOutcome::Cancelled;
            }
            _ = cancel_notified => {
                return RelaySessionOutcome::Cancelled;
            }
        }
    }
}

/// Global announce ticker. One instance per driver; publishes
/// presence events via the driver-owned watch on the schedule defined by
/// [`ANNOUNCE_BACKOFF_MS`] / [`ANNOUNCE_STEADY_MS`].
///
/// The first announce fires immediately on driver start (a fresh
/// joiner wants to be visible to existing peers without delay).
/// Subsequent waits follow the curve in `upstream.rs` item 7:
/// dense at startup, settling to a 60s steady-state heartbeat.
async fn run_announcer(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut count: usize = 0;
    let mut shutdown_rx = shared.shutdown.subscribe();
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
            return;
        }
        match shared
            .delivery
            .admit_presence(build_announce_event(&shared))
        {
            Ok(event) => {
                // Each connected relay observes this latest best-effort
                // presence value independently; negotiation never enters this
                // path. The provider lease travels with the watch record.
                let _ = shared.presence_tx.send(Some(Arc::new(event)));
            }
            Err(error) => {
                warn!(?error, "presence publication refused before encoding");
            }
        }

        let base_ms = ANNOUNCE_BACKOFF_MS
            .get(count)
            .copied()
            .unwrap_or(ANNOUNCE_STEADY_MS);
        // Jitter the steady cadence by the configured percentage so nodes that came up together
        // — a site restoring power, a fleet rebooting after an update —
        // don't publish their presence in the same instant every cycle
        // forever. The dense early schedule stays exact: it exists to make
        // a fresh joiner visible fast, and determinism there keeps tests
        // and traces legible.
        let wait_ms = if base_ms == ANNOUNCE_STEADY_MS {
            jittered_ms(
                base_ms,
                shared.timing.jitter_percent,
                &shared.device_id,
                count as u64,
            )
        } else {
            base_ms
        };
        count = count.saturating_add(1);

        // Cancellation-aware sleep: chunked at 1s so a stop()
        // call doesn't have to wait a full 60s tick to take
        // effect. Bounded by `chunk` since wait_ms can exceed it.
        let mut remaining = wait_ms;
        while remaining > 0 {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
                return;
            }
            let step = remaining.min(shared.timing.announcer_cancel_quantum.as_millis() as u64);
            tokio::select! {
                _ = sleep(Duration::from_millis(step)) => {}
                _ = shutdown_rx.changed() => return,
            }
            remaining = remaining.saturating_sub(step);
        }
    }
}

#[cfg(test)]
fn handle_inbound_frame(
    url: &str,
    frame: &str,
    shared: &Arc<DriverShared>,
    inbound_tx: &InboundSink<NostrInbound>,
    session: RelaySessionId,
) -> Result<(), String> {
    handle_inbound_frame_observed(url, frame, shared, inbound_tx, session).map(|_| ())
}

fn handle_inbound_frame_observed(
    url: &str,
    frame: &str,
    shared: &Arc<DriverShared>,
    inbound_tx: &InboundSink<NostrInbound>,
    session: RelaySessionId,
) -> Result<RelayControlFrame, String> {
    if frame.len() > MAX_INBOUND_FRAME_BYTES {
        return Err("inbound frame exceeds size cap".to_string());
    }
    let _parse_lease = InboundFrameLease(Some(
        shared
            .delivery
            .reserve_inbound_frame(frame.len())
            .map_err(|error| format!("inbound frame refused before parse: {error:?}"))?,
    ));
    // The provider lease above accounts the raw frame bytes before any JSON
    // allocation. The decoded tree is transient and bounded by that same
    // frame cap; move the EVENT body out of the tree instead of cloning it so
    // the typed event does not create a second decoded subtree. The websocket
    // library's bounded message/write buffers are accounted at its boundary.
    let mut value: Value = serde_json::from_str(frame).map_err(|e| e.to_string())?;
    let arr = value
        .as_array_mut()
        .ok_or_else(|| "not an array".to_string())?;
    let tag = arr
        .first()
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_owned();
    match tag.as_str() {
        "EVENT" => {
            let event_value = arr
                .get_mut(2)
                .ok_or_else(|| "missing event body".to_string())?;
            let event: NostrEvent =
                serde_json::from_value(std::mem::take(event_value)).map_err(|e| e.to_string())?;
            if !event.verify()
                || !event.tags.iter().any(|tag| {
                    tag.first().map(String::as_str) == Some("r")
                        && tag.get(1) == Some(&shared.room_handle)
                })
            {
                return Ok(RelayControlFrame::Other);
            }
            // Skip events we sent ourselves.
            if event.pubkey == shared.identity.pubkey_hex() {
                return Ok(RelayControlFrame::Other);
            }
            // No de-duplication here, deliberately. The relay fan-out
            // duplicate is real — one event published once arrives from
            // every relay that has it, and applying an offer twice via
            // `set_remote_description` wedges WebRTC permanently — but this
            // is the wrong layer to remember it at, and remembering it here
            // was a second bug on top of the first.
            //
            // The ring that used to sit on this line recorded the event id
            // *before* the envelope was parsed and *before* the value was
            // offered onward, and it discarded the offer's result. So a copy
            // the consumer refused under pressure still left its id behind,
            // and the identical copy arriving from the next relay — the one
            // that would have rescued the attempt — was dropped here as
            // already seen. Neither copy ever reached the engine.
            //
            // De-duplication now has one owner, downstream, which commits a
            // key only after the value has actually been accepted and scopes
            // it to the exact attempt it describes. A refused value leaves no
            // history anywhere. See `engine::signaling_ingress`.
            //
            // Pull our envelope out of the content.
            let envelope: SignalingEnvelope =
                serde_json::from_str(&event.content).map_err(|e| e.to_string())?;

            if envelope.msg.peer_id() != envelope.from {
                return Ok(RelayControlFrame::Other);
            }

            // Enforce the presence/negotiation kind split on receive.
            // This is the receive-side half of the replay fix: a
            // stored-kind event can be replayed from history, so we
            // only ever honour an Announce there; an offer/answer/
            // candidate must arrive live on the ephemeral kind. A
            // directed message on the stored kind is stale history
            // (a pre-split build, or a relay that wrongly persisted
            // an ephemeral event) and is dropped rather than applied
            // as a remote description against dead ICE credentials.
            match envelope.msg {
                SignalingMessage::Announce { peer_id } => {
                    if envelope.to != shared.room_handle {
                        return Ok(RelayControlFrame::Other);
                    }
                    if event.kind != SIGNALING_EVENT_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring announce on non-presence kind"
                        );
                        return Ok(RelayControlFrame::Other);
                    }
                    if peer_id == shared.device_id {
                        return Ok(RelayControlFrame::Other);
                    }
                    // Sender-claimed, and deliberately still the body id: on
                    // a relay the envelope's own `from` is a second field the
                    // same sender wrote, so preferring it would buy nothing.
                    // What the tag buys is that this can never cancel an
                    // observation a carrier made itself.
                    inbound_tx
                        .send(NostrInbound::PeerAnnounced {
                            device_id: peer_id,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .map_err(|_| INBOUND_SINK_CLOSED.to_string())?;
                }
                SignalingMessage::Leave { peer_id } => {
                    if envelope.to != shared.room_handle {
                        return Ok(RelayControlFrame::Other);
                    }
                    // Departure rides the ephemeral kind like the rest of
                    // the live negotiation traffic — a stored-kind "leave"
                    // would be stale history, so drop it.
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring leave on non-ephemeral kind"
                        );
                        return Ok(RelayControlFrame::Other);
                    }
                    if peer_id == shared.device_id {
                        return Ok(RelayControlFrame::Other);
                    }
                    inbound_tx
                        .send(NostrInbound::PeerLeft {
                            device_id: peer_id,
                            attribution: CarrierAttribution::SenderClaimed,
                        })
                        .map_err(|_| INBOUND_SINK_CLOSED.to_string())?;
                }
                other => {
                    if envelope.to != shared.device_id {
                        return Ok(RelayControlFrame::Other);
                    }
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "dropping replayed/stored-kind negotiation message"
                        );
                        return Ok(RelayControlFrame::Other);
                    }
                    inbound_tx
                        .send(NostrInbound::Message {
                            from: envelope.from,
                            msg: other,
                        })
                        .map_err(|_| INBOUND_SINK_CLOSED.to_string())?;
                }
            }
        }
        "OK" => {
            let event_id = arr
                .get(1)
                .and_then(Value::as_str)
                .ok_or_else(|| "OK missing event id".to_string())?;
            let accepted = arr
                .get(2)
                .and_then(Value::as_bool)
                .ok_or_else(|| "OK missing acceptance".to_string())?;
            let reason = arr
                .get(3)
                .and_then(Value::as_str)
                .unwrap_or("relay refused event");
            let terminal = if accepted {
                DeliveryTerminal::Accepted
            } else {
                DeliveryTerminal::TypedRefused(reason.to_string())
            };
            if !shared.delivery.settle(&session, event_id, terminal) {
                trace!(relay = %short(url), %event_id, "stale relay OK ignored");
            }
        }
        "EOSE" => {
            if arr.len() == 2 && arr.get(1).and_then(Value::as_str) == Some(ROOM_SUBSCRIPTION_ID) {
                return Ok(RelayControlFrame::Eose);
            }
        }
        "NOTICE" => {
            let body = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            debug!(relay = %short(url), "relay notice: {body}");
            if body.to_ascii_lowercase().contains("too many connections") {
                return Ok(RelayControlFrame::Rejected);
            }
        }
        _ => {
            trace!(relay = %short(url), "unhandled tag: {tag}");
        }
    }
    Ok(RelayControlFrame::Other)
}

#[derive(Debug, Clone, serde::Serialize)]
struct SignalingEnvelope {
    from: String,
    /// Required recipient: a device id for directed negotiation, or the room
    /// handle for an explicit presence/leave broadcast.
    to: String,
    #[serde(flatten)]
    msg: SignalingMessage,
}

impl<'de> serde::Deserialize<'de> for SignalingEnvelope {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        let serde_json::Value::Object(mut object) = value else {
            return Err(serde::de::Error::custom(
                "signaling envelope must be a JSON object",
            ));
        };
        let from = object
            .remove("from")
            .ok_or_else(|| serde::de::Error::custom("signaling envelope is missing from"))?;
        let to = object
            .remove("to")
            .ok_or_else(|| serde::de::Error::custom("signaling envelope is missing to"))?;
        let from: String = serde_json::from_value(from)
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        let to: String = serde_json::from_value(to)
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        if to.is_empty() {
            return Err(serde::de::Error::custom(
                "signaling envelope recipient must not be empty",
            ));
        }
        let msg = serde_json::from_value(serde_json::Value::Object(object))
            .map_err(|error| serde::de::Error::custom(error.to_string()))?;
        Ok(Self { from, to, msg })
    }
}

/// The one announce builder — the periodic ticker, the per-session
/// open-announce, and the engine-driven reactive announce all publish
/// exactly this event, so there is a single place the announce's shape
/// can ever change.
fn build_announce_event(shared: &DriverShared) -> NostrEvent {
    let envelope = SignalingEnvelope {
        from: shared.device_id.clone(),
        to: shared.room_handle.clone(),
        msg: SignalingMessage::Announce {
            peer_id: shared.device_id.clone(),
        },
    };
    make_event(
        &shared.identity,
        SIGNALING_EVENT_KIND,
        vec![vec!["r".into(), shared.room_handle.clone()]],
        serde_json::to_string(&envelope).expect("serialize ok"),
        now_secs(),
    )
}

async fn run_outbound_pump(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut rx_guard = shared.outbound.lock().await;
    let Some(mut rx) = rx_guard.take() else {
        return;
    };
    drop(rx_guard);
    let mut shutdown_rx = shared.shutdown.subscribe();
    loop {
        let Some(outbound) = (tokio::select! {
            outbound = rx.recv() => outbound,
            _ = shutdown_rx.changed() => break,
        }) else {
            break;
        };
        if cancel.load(std::sync::atomic::Ordering::SeqCst) || *shutdown_rx.borrow() {
            break;
        }
        let attempt = outbound_attempt(outbound.value()).map(str::to_owned);
        let shared_for_event = Arc::clone(&shared);
        let owned =
            outbound.map(move |outbound| translate_outbound_event(&shared_for_event, outbound));
        if let Some(attempt) = attempt {
            let report = shared.delivery.admit(attempt.clone(), owned);
            if let Some(refusal) = report.attempt_refusal.clone() {
                let refusal_record = AttemptRefusal {
                    source: report.source,
                    attempt: attempt.clone(),
                    event_id: report.event_id.clone(),
                    refusal: refusal.into_negotiation(),
                };
                warn!(
                    %attempt,
                    event_id = %report.event_id,
                    ?refusal_record.refusal,
                    "negotiation attempt refused before relay admission"
                );
                shared.refusal_sink.refused(refusal_record);
            }
            for (session, error) in &report.refused {
                warn!(
                    ?session,
                    ?error,
                    event_id = %report.event_id,
                    "negotiation delivery refused before frame allocation"
                );
            }
        } else {
            let record = Arc::new(owned);
            if shared.presence_tx.send(Some(record.clone())).is_ok() {
                // The driver-owned watch now retains the funded event record.
                record.accept();
            }
        }
    }
    let _ = shared.shutdown.send(true);
    cancel.store(true, std::sync::atomic::Ordering::SeqCst);
    shared.delivery.shutdown();
}

fn outbound_attempt(outbound: &NostrOutbound) -> Option<&str> {
    let NostrOutbound::DirectedToPeer { msg, .. } = outbound else {
        return None;
    };
    match msg {
        SignalingMessage::Offer { offer_id, .. }
        | SignalingMessage::Answer { offer_id, .. }
        | SignalingMessage::Candidate { offer_id, .. } => Some(offer_id),
        _ => None,
    }
}

fn translate_outbound_event(shared: &DriverShared, outbound: NostrOutbound) -> NostrEvent {
    match outbound {
        NostrOutbound::Announce => build_announce_event(shared),
        NostrOutbound::Leave => {
            let envelope = SignalingEnvelope {
                from: shared.device_id.clone(),
                to: shared.room_handle.clone(),
                msg: SignalingMessage::Leave {
                    peer_id: shared.device_id.clone(),
                },
            };
            make_event(
                &shared.identity,
                SIGNALING_EPHEMERAL_KIND,
                vec![
                    vec!["r".into(), shared.room_handle.clone()],
                    vec!["p".into(), shared.room_handle.clone()],
                ],
                serde_json::to_string(&envelope).expect("serialize ok"),
                now_secs(),
            )
        }
        NostrOutbound::DirectedToPeer { to, msg } => {
            let envelope = SignalingEnvelope {
                from: shared.device_id.clone(),
                to: to.clone(),
                msg,
            };
            make_event(
                &shared.identity,
                SIGNALING_EPHEMERAL_KIND,
                vec![
                    vec!["r".into(), shared.room_handle.clone()],
                    vec!["p".into(), to],
                ],
                serde_json::to_string(&envelope).expect("serialize ok"),
                now_secs(),
            )
        }
    }
}

fn short(url: &str) -> &str {
    url.strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::delivery::UnmeteredDeliveryProvider;
    use crate::nostr::event::NostrIdentity;
    use crate::OwnedSignal;
    use futures::task::{noop_waker, Context, Poll};
    use std::pin::Pin;
    use std::sync::atomic::{AtomicBool, Ordering};
    // Only the controls build channels now: the driver itself takes an
    // `OutboundSource` and an `InboundSink`, and owns no queue in either
    // direction.
    use tokio::sync::mpsc;

    fn poll_to_pending<F: std::future::Future>(future: Pin<&mut F>) {
        let waker = noop_waker();
        let mut context = Context::from_waker(&waker);
        assert!(matches!(future.poll(&mut context), Poll::Pending));
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

    struct ParkedWriteGate {
        parked: tokio::sync::Notify,
        waker: Mutex<Option<std::task::Waker>>,
        announced: AtomicBool,
        released: AtomicBool,
    }

    struct RefusingReservation;

    impl TaskReservation for RefusingReservation {
        fn submit(
            &mut self,
            task: tokio::task::JoinHandle<()>,
        ) -> Result<(), tokio::task::JoinHandle<()>> {
            Err(task)
        }
    }

    struct RefusingCustodian;

    struct PendingDialWitness {
        polled: Arc<AtomicBool>,
        dropped: Arc<AtomicBool>,
    }

    impl std::future::Future for PendingDialWitness {
        type Output = Result<(), ()>;

        fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Self::Output> {
            self.polled.store(true, Ordering::SeqCst);
            Poll::Pending
        }
    }

    impl Drop for PendingDialWitness {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    impl TaskCustodian for RefusingCustodian {
        fn reserve(&self, _slots: usize) -> Result<Box<dyn TaskReservation>, TaskCustodyError> {
            Ok(Box::new(RefusingReservation))
        }

        fn progress(&self) -> tokio::sync::watch::Receiver<u64> {
            let (_sender, receiver) = tokio::sync::watch::channel(0u64);
            receiver
        }
    }

    impl ParkedWriteGate {
        fn release(&self) {
            self.released.store(true, Ordering::SeqCst);
            let waker = self.waker.lock().take();
            if let Some(waker) = waker {
                waker.wake();
            }
        }
    }

    struct ParkedSink {
        frames: Vec<WsMessage>,
        gate: Arc<ParkedWriteGate>,
    }

    impl Sink<WsMessage> for ParkedSink {
        type Error = std::convert::Infallible;

        fn poll_ready(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            if !self.gate.released.load(Ordering::SeqCst) {
                if !self.gate.announced.swap(true, Ordering::SeqCst) {
                    self.gate.parked.notify_one();
                }
                *self.gate.waker.lock() = Some(cx.waker().clone());
                Poll::Pending
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn start_send(mut self: Pin<&mut Self>, item: WsMessage) -> Result<(), Self::Error> {
            self.frames.push(item);
            Ok(())
        }

        fn poll_flush(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }

        fn poll_close(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn fallback_holds_while_a_primary_is_up() {
        let timing = test_timing();
        // Primary connected, fallback not running → leave it alone.
        assert_eq!(
            fallback_action(&timing, 2, false, Duration::ZERO),
            FallbackAction::Hold
        );
        assert_eq!(
            fallback_action(
                &timing,
                1,
                false,
                timing.fallback_activation_grace + Duration::from_secs(1),
            ),
            FallbackAction::Hold
        );
    }

    #[test]
    fn driver_task_counts_refuse_overflow_before_startup() {
        let counts = DriverTaskCounts::derive(3, 2).expect("bounded counts fit");
        assert_eq!(counts.selected_relays, 3);
        assert_eq!(counts.fallback_relays, 2);
        assert_eq!(counts.fallback_supervisors, 1);
        assert_eq!(counts.outbound, 1);
        assert_eq!(counts.announcer, 1);
        assert_eq!(counts.driver_tasks, 5);
        assert_eq!(counts.cancellers, 6);
        assert_eq!(counts.cancel_wakes, 4);
        assert!(
            DriverTaskCounts::derive(usize::MAX - 1, 1).is_none(),
            "overflow must refuse before any task is created"
        );
        assert!(
            derive_task_custody_plan(usize::MAX - 1, 1).is_none(),
            "custody-plan overflow must refuse before any task is created"
        );
    }

    #[test]
    fn terminal_custody_requires_every_fallback_slot_plus_reaper() {
        let counts = DriverTaskCounts::derive(3, 2).expect("bounded counts fit");
        let plan = derive_task_custody_plan(3, 2).expect("custody plan fits");
        assert_eq!(plan.primary_observer_slots, 6);
        assert_eq!(plan.reaper_observer_slots, 7);
        assert_eq!(
            plan.primary_observer_slots,
            counts.driver_tasks + counts.fallback_supervisors
        );
        assert_eq!(plan.reaper_observer_slots, plan.primary_observer_slots + 1);
        let owner =
            DedicatedTaskCustodian::new(plan.reaper_observer_slots - 1).expect("short owner");
        assert!(
            owner.reserve(plan.reaper_observer_slots).is_err(),
            "grant-minus-one must refuse before any task can be spawned"
        );
        owner.close();
    }

    #[tokio::test]
    async fn fallback_registry_refuses_n_plus_one_and_returns_exact_handle() {
        let counts = DriverTaskCounts::derive(2, 1).expect("bounded counts fit");
        let fallback = FallbackReaperTasks::new(counts.driver_tasks);
        for _ in 0..counts.driver_tasks {
            fallback
                .retain(tokio::spawn(async {}))
                .expect("each funded fallback slot accepts one handle");
        }
        let extra = tokio::spawn(async { panic!("N+1 fallback task") });
        let extra = fallback
            .retain(extra)
            .expect_err("N+1 must be refused without dropping its handle");
        assert!(extra
            .await
            .expect_err("returned handle must observe panic")
            .is_panic());
        let retained = fallback.take_tasks();
        assert_eq!(retained.len(), counts.driver_tasks);
        for task in retained {
            task.await.expect("funded fallback task must terminate");
        }
    }

    #[test]
    fn fallback_waits_out_the_grace_then_activates() {
        let timing = test_timing();
        // All primaries down, but not yet past the grace → hold…
        assert_eq!(
            fallback_action(&timing, 0, false, Duration::ZERO),
            FallbackAction::Hold
        );
        assert_eq!(
            fallback_action(
                &timing,
                0,
                false,
                timing.fallback_activation_grace - Duration::from_millis(1),
            ),
            FallbackAction::Hold
        );
        // …then activate once the grace elapses.
        assert_eq!(
            fallback_action(&timing, 0, false, timing.fallback_activation_grace),
            FallbackAction::Activate
        );
    }

    #[test]
    fn fallback_stands_down_when_a_primary_returns() {
        let timing = test_timing();
        // Fallback running and a primary comes back → tear it down.
        assert_eq!(
            fallback_action(&timing, 1, true, Duration::ZERO),
            FallbackAction::StandDown
        );
    }

    #[test]
    fn fallback_holds_while_active_and_primary_still_down() {
        let timing = test_timing();
        // Already covering the outage; don't respawn every tick.
        assert_eq!(
            fallback_action(&timing, 0, true, Duration::ZERO),
            FallbackAction::Hold
        );
    }

    #[test]
    fn recovery_timing_policy_is_checked_and_deterministic() {
        let timing = test_timing();
        assert!(timing.validate().is_ok());
        assert_eq!(timing.connect_timeout, Duration::from_secs(30));
        assert_eq!(timing.reconnect_initial, Duration::from_secs(2));
        assert_eq!(reconnect_base_ms(0, &timing), 0);
        assert_eq!(reconnect_base_ms(1, &timing), 2_000);
        assert_eq!(reconnect_base_ms(5, &timing), 32_000);
        assert_eq!(reconnect_base_ms(6, &timing), 60_000);
        assert_eq!(reconnect_base_ms(u32::MAX, &timing), 60_000);

        let max_ms = timing.reconnect_max.as_millis() as u64;
        let jittered = jittered_ms(max_ms, timing.jitter_percent, "policy", 7);
        let lower = max_ms * (100 - timing.jitter_percent) / 100;
        let upper = max_ms * (100 + timing.jitter_percent) / 100;
        assert!((lower..=upper).contains(&jittered));
        assert_eq!(
            jittered,
            jittered_ms(max_ms, timing.jitter_percent, "policy", 7)
        );

        let mut invalid = timing;
        invalid.reconnect_max = Duration::from_secs(1);
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.jitter_percent = 101;
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.reconnect_initial = Duration::ZERO;
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.connect_timeout = Duration::ZERO;
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.reconnect_max = Duration::MAX;
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.reconnect_max_attempts = 0;
        assert!(invalid.validate().is_err());
        invalid = timing;
        invalid.fallback_activation_grace = Duration::from_secs(1);
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn websocket_limits_bound_text_binary_and_fragmented_messages() {
        let config = websocket_config();
        assert_eq!(config.max_message_size, Some(MAX_INBOUND_FRAME_BYTES));
        assert_eq!(config.max_frame_size, Some(MAX_INBOUND_FRAME_BYTES));
        assert!(config.max_write_buffer_size <= MAX_INBOUND_FRAME_BYTES * 2);
        assert!(!binary_frame_within_limit(&vec![
            0;
            MAX_INBOUND_FRAME_BYTES + 1
        ]));

        // The frame limit is applied by tungstenite before it assembles a
        // fragmented message, while the direct parser guard covers text
        // values that reach this layer through another transport seam.
        let shared = fixture_shared();
        let (tx, _rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);
        let oversized = "x".repeat(MAX_INBOUND_FRAME_BYTES + 1);
        let error = handle_inbound_frame(
            "wss://oversized",
            &oversized,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect_err("oversized text is rejected before parsing");
        assert_eq!(error, "inbound frame exceeds size cap");
    }

    #[tokio::test]
    async fn prearmed_delivery_survives_open_announcement_scan_wait_gap() {
        let shared = fixture_shared();
        let (session, session_refusal, refusals) = shared.delivery.open_session_with_refusals();
        assert!(session_refusal.is_none());
        assert!(refusals.is_empty());
        let gate = Arc::new(ParkedWriteGate {
            parked: tokio::sync::Notify::new(),
            waker: Mutex::new(None),
            announced: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut sink = ParkedSink {
            frames: Vec::new(),
            gate: Arc::clone(&gate),
        };
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);

        // Drive the exact production pre-arm -> initial scan -> open-write
        // helper, parking its open write before it enters the select loop.
        let mut preparation = Box::pin(prepare_relay_delivery(
            "wss://relay-gap",
            &mut sink,
            &shared,
            &shared.delivery,
            &session,
            &cancellation,
            &mut shutdown_rx,
        ));
        let parked_wait = gate.parked.notified();
        tokio::select! {
            result = &mut preparation => panic!("preparation completed before parked write: {result:?}"),
            _ = parked_wait => {}
        }

        // The sole directed event is admitted while the open announcement is
        // parked, exactly the scan→wait gap under review.
        let outbound = NostrOutbound::DirectedToPeer {
            to: "peer-b".into(),
            msg: SignalingMessage::Offer {
                peer_id: "peer-b".into(),
                offer_id: "gap-attempt".into(),
                sdp: "v=0".into(),
            },
        };
        let event = translate_outbound_event(&shared, outbound);
        let event_id = event.id.clone();
        let report = shared.delivery.admit(
            "gap-attempt".into(),
            OwnedSignal::new(event, Box::new(()) as ErasedOwner),
        );
        assert_eq!(report.accepted_sessions, 1);

        gate.release();
        let delivery_notified = preparation.await.expect("open write gate settles");
        delivery_notified.await;
        send_pending_deliveries(
            "wss://relay-gap",
            &mut sink,
            &shared.delivery,
            &session,
            &cancellation,
            &mut shutdown_rx,
        )
        .await
        .expect("same relay sends the admitted event");

        assert_eq!(sink.frames.len(), 2, "open announcement plus one EVENT");
        let frames = sink
            .frames
            .iter()
            .filter_map(|message| match message {
                WsMessage::Text(frame) => {
                    Some(serde_json::from_str::<Value>(frame).expect("EVENT frame is JSON"))
                }
                _ => None,
            })
            .collect::<Vec<_>>();
        assert_eq!(frames.len(), 2, "both writes are EVENT frames");
        assert!(frames.iter().all(|frame| frame[0] == "EVENT"));
        assert_eq!(
            frames
                .iter()
                .filter(|frame| {
                    frame[1]["id"] == event_id && frame[1]["kind"] == SIGNALING_EPHEMERAL_KIND
                })
                .count(),
            1,
            "exactly one directed EVENT for the admitted id"
        );
        assert_eq!(
            frames
                .iter()
                .filter(|frame| frame[1]["kind"] == SIGNALING_EVENT_KIND)
                .count(),
            1,
            "exactly one open announcement"
        );
    }

    #[tokio::test]
    async fn pending_relay_dial_hits_checked_deadline() {
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let result = await_relay_dial(
            std::future::pending::<Result<(), ()>>(),
            Duration::from_millis(1),
            &cancellation,
            &mut shutdown_rx,
        )
        .await;
        assert!(matches!(result, RelayDialOutcome::TimedOut));
    }

    #[tokio::test]
    async fn pending_relay_dial_cancels_before_deadline() {
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut dial = Box::pin(await_relay_dial(
            PendingDialWitness {
                polled: Arc::clone(&polled),
                dropped: Arc::clone(&dropped),
            },
            Duration::from_secs(30),
            &cancellation,
            &mut shutdown_rx,
        ));
        poll_to_pending(dial.as_mut());
        assert!(
            polled.load(Ordering::SeqCst),
            "dial must reach Poll::Pending"
        );
        cancel.store(true, Ordering::SeqCst);
        cancel_wake.notify_waiters();
        assert!(matches!(dial.await, RelayDialOutcome::Cancelled));
        assert!(
            dropped.load(Ordering::SeqCst),
            "cancel must drop the dial witness"
        );
    }

    #[tokio::test]
    async fn pending_relay_dial_cancels_when_shutdown_is_signaled() {
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut dial = Box::pin(await_relay_dial(
            PendingDialWitness {
                polled: Arc::clone(&polled),
                dropped: Arc::clone(&dropped),
            },
            Duration::from_secs(30),
            &cancellation,
            &mut shutdown_rx,
        ));
        poll_to_pending(dial.as_mut());
        assert!(
            polled.load(Ordering::SeqCst),
            "dial must reach Poll::Pending"
        );
        shutdown_tx
            .send(true)
            .expect("shutdown receiver remains live");
        assert!(matches!(dial.await, RelayDialOutcome::Cancelled));
        assert!(
            dropped.load(Ordering::SeqCst),
            "shutdown must drop the dial witness"
        );
    }

    #[tokio::test]
    async fn pending_relay_dial_simultaneous_cancel_and_shutdown_is_cancelled() {
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let polled = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicBool::new(false));
        let mut dial = Box::pin(await_relay_dial(
            PendingDialWitness {
                polled: Arc::clone(&polled),
                dropped: Arc::clone(&dropped),
            },
            Duration::from_secs(30),
            &cancellation,
            &mut shutdown_rx,
        ));
        poll_to_pending(dial.as_mut());
        assert!(
            polled.load(Ordering::SeqCst),
            "dial must reach Poll::Pending"
        );
        cancel.store(true, Ordering::SeqCst);
        cancel_wake.notify_waiters();
        shutdown_tx
            .send(true)
            .expect("shutdown receiver remains live");
        assert!(matches!(dial.await, RelayDialOutcome::Cancelled));
        assert!(
            dropped.load(Ordering::SeqCst),
            "simultaneous cancellation must drop the dial witness"
        );
    }

    #[tokio::test]
    async fn pending_relay_write_cancels_when_shutdown_is_signaled() {
        let gate = Arc::new(ParkedWriteGate {
            parked: tokio::sync::Notify::new(),
            waker: Mutex::new(None),
            announced: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut sink = ParkedSink {
            frames: Vec::new(),
            gate: Arc::clone(&gate),
        };
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let parked_wait = gate.parked.notified();
        let mut write = Box::pin(send_relay_frame(
            &mut sink,
            WsMessage::Text("pending".into()),
            &cancellation,
            &mut shutdown_rx,
        ));
        tokio::select! {
            result = &mut write => panic!("write completed before shutdown: {result:?}"),
            _ = parked_wait => {}
        }

        shutdown_tx
            .send(true)
            .expect("shutdown receiver remains live");
        assert!(matches!(write.await, Err(RelayWriteOutcome::Cancelled)));
        assert!(
            sink.frames.is_empty(),
            "cancelled write must not emit a frame"
        );
    }

    #[tokio::test]
    async fn pending_relay_write_cancels_on_task_notify_without_shutdown_watch() {
        let gate = Arc::new(ParkedWriteGate {
            parked: tokio::sync::Notify::new(),
            waker: Mutex::new(None),
            announced: AtomicBool::new(false),
            released: AtomicBool::new(false),
        });
        let mut sink = ParkedSink {
            frames: Vec::new(),
            gate: Arc::clone(&gate),
        };
        let cancel = AtomicBool::new(false);
        let cancel_wake = Notify::new();
        let cancellation = RelaySessionCancellation {
            flag: &cancel,
            wake: &cancel_wake,
        };
        let (_shutdown_tx, mut shutdown_rx) = watch::channel(false);
        let parked_wait = gate.parked.notified();
        let mut write = Box::pin(send_relay_frame(
            &mut sink,
            WsMessage::Text("pending".into()),
            &cancellation,
            &mut shutdown_rx,
        ));
        tokio::select! {
            result = &mut write => panic!("write completed before task cancellation: {result:?}"),
            _ = parked_wait => {}
        }

        cancel.store(true, Ordering::SeqCst);
        cancel_wake.notify_waiters();
        assert!(matches!(write.await, Err(RelayWriteOutcome::Cancelled)));
        assert!(
            sink.frames.is_empty(),
            "cancelled write must not emit a frame"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outside_runtime_driver_drop_transfers_task_to_reaper() {
        let before = TEST_REAPED_TASKS.load(Ordering::Acquire);
        let fallback_reaper_tasks = FallbackReaperTasks::new(2);
        let (reaper_sender, reaper_task) = spawn_task_reaper(1, Arc::clone(&fallback_reaper_tasks));
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            armed_tx
                .send(())
                .expect("reaper control task must arm before drop");
            std::future::pending::<()>().await;
        });
        armed_rx.await.expect("reaper control task must be running");

        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || abort_and_join(&reaper_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime owner drop must return");

        reaper_task
            .await
            .expect("runtime-owned reaper must terminate after its sender closes");
        assert_eq!(
            TEST_REAPED_TASKS.load(Ordering::Acquire),
            before + 1,
            "the exact aborted task must be awaited by the runtime reaper"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_capacity_refusal_returns_exact_panicking_handle() {
        let fallback = FallbackReaperTasks::new(0);
        let (task, started) = panicking_task("Nostr fallback capacity refusal");
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
        let (task, started) = panicking_task("Nostr bounded fallback overflow");
        started
            .await
            .expect("panic task must start before transfer");
        retain_or_overflow(&fallback, task, "Nostr overflow control");
        reap_fallback_reaper_tasks(&fallback).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 1,
            "bounded overflow custody must observe the exact panic"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_order_transfers_unaborted_reaper_with_active_nested_task() {
        let fallback = FallbackReaperTasks::new(1);
        let (reaper_sender, reaper_task) = spawn_task_reaper(1, Arc::clone(&fallback));
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let nested = tokio::spawn(async move {
            release_rx
                .await
                .expect("nested relay task release remains live");
        });
        reaper_sender
            .send(nested)
            .await
            .expect("reaper accepts the nested relay task");
        drop(reaper_sender);
        fallback
            .retain_supervisor(reaper_task)
            .expect("owner capacity reserves the reaper supervisor");
        release_tx
            .send(())
            .expect("nested relay task remains active until release");
        let (tasks, mut supervisors) = fallback.take_all();
        assert!(
            tasks.is_empty(),
            "nested relay task was joined by its reaper"
        );
        let supervisor = supervisors
            .pop()
            .expect("unaborted reaper supervisor remains joinable");
        supervisor
            .await
            .expect("transferred reaper observes nested relay completion");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn current_thread_drop_uses_independent_terminal_custody() {
        let observer_owner = DedicatedTaskCustodian::new(1).expect("terminal observer");
        let observer = observer_owner
            .reserve(1)
            .expect("terminal observer reservation");
        let mut progress = observer_owner.progress();
        let baseline = *progress.borrow();
        let mut primary: Option<CustodianReservation> = Some(Box::new(RefusingReservation));
        let mut independent = Some(observer);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        let completed = Arc::new(AtomicBool::new(false));
        let child_completed = Arc::clone(&completed);
        let task = tokio::spawn(async move {
            started_tx.send(()).expect("origin task signals startup");
            release_rx.await.expect("fixture owner releases its task");
            child_completed.store(true, Ordering::Release);
        });
        let completion = task.abort_handle();
        started_rx
            .await
            .expect("origin task is running before handoff");
        assert!(
            !completion.is_finished(),
            "handoff exercises a live owned task"
        );
        std::thread::spawn(move || {
            submit_to_terminal_custody(
                &mut primary,
                &mut independent,
                task,
                "Nostr current-thread refusal",
            );
        })
        .join()
        .expect("current-thread Drop transfer must not block on its origin runtime");
        // The observer only joins: the fixture still owns the stop signal.
        // Keep this runtime polling until the external observer proves the
        // exact transferred handle terminal, then join the observer thread.
        release_tx
            .send(())
            .expect("transferred task remains owned until release");
        while *progress.borrow() == baseline {
            progress
                .changed()
                .await
                .expect("terminal observer stays live");
        }
        let observed = *progress.borrow();
        let finished = completion.is_finished();
        observer_owner.close();
        assert_eq!(
            observed,
            baseline + 1,
            "the sole transferred task was joined"
        );
        assert!(finished, "the exact origin task reached terminal");
        assert!(
            completed.load(Ordering::Acquire),
            "owned release completed normally"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn refusing_primary_custody_never_routes_reaper_to_its_fallback() {
        let fallback = FallbackReaperTasks::new(1);
        let (reaper_sender, reaper_receiver) = mpsc::channel(1);
        let reaper_done = Arc::new(Notify::new());
        let reaper_done_for_task = Arc::clone(&reaper_done);
        let fallback_for_task = Arc::clone(&fallback);
        let reaper_task = tokio::spawn(async move {
            let mut receiver = reaper_receiver;
            while let Some(task) = receiver.recv().await {
                observe_nostr_task(task, "Nostr control reaper").await;
            }
            for task in fallback_for_task.take_tasks() {
                observe_nostr_task(task, "Nostr fallback reaper").await;
            }
            reaper_done_for_task.notify_one();
        });
        let reaper_custodian_owner = DedicatedTaskCustodian::new(1).expect("reaper custodian");
        let reaper_custodian = reaper_custodian_owner
            .reserve(1)
            .expect("the reaper custodian must reserve its own handle");
        let reaper_owner_for_control = Arc::clone(&reaper_custodian_owner);
        let handle = NostrDriverHandle {
            cancellers: Vec::new(),
            cancel_wakes: Vec::new(),
            tasks: Arc::new(Mutex::new(Some(Vec::new()))),
            fallback_supervisor_task: Mutex::new(None),
            task_reaper: Mutex::new(Some(reaper_sender)),
            task_reaper_handle: Mutex::new(Some(reaper_task)),
            custodian_owner: Arc::new(RefusingCustodian),
            custodian: Some(Box::new(RefusingReservation)),
            reaper_custodian_owner,
            reaper_custodian: Some(reaper_custodian),
            force_reconnect: Arc::new(watch::channel(0u64).0),
            relay_connected: Arc::new(watch::channel(0u64).0),
            delivery: DeliveryStore::new(Arc::new(UnmeteredDeliveryProvider)),
            shutdown: watch::channel(false).0,
        };
        drop(handle);
        tokio::time::timeout(Duration::from_secs(2), reaper_done.notified())
            .await
            .expect("an independently observed reaper must reach terminal");
        reaper_owner_for_control.close();
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn driver_drop_transfers_active_nested_task_with_full_overflow() {
        struct DropMark(Arc<AtomicBool>, Arc<Notify>);

        impl Drop for DropMark {
            fn drop(&mut self) {
                self.0.store(true, Ordering::Release);
                self.1.notify_one();
            }
        }

        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);
        let fallback = FallbackReaperTasks::new(0);
        let (filler, filler_started) = panicking_task("Nostr full overflow filler");
        filler_started
            .await
            .expect("overflow filler must start before Drop");
        fallback
            .retain_overflow(filler)
            .expect("the bounded overflow slot must accept one exact filler");

        let (reaper_sender, reaper_task) = spawn_task_reaper(1, Arc::clone(&fallback));
        let custodian_owner = DedicatedTaskCustodian::new(2).expect("test custodian");
        let custodian = custodian_owner
            .reserve(2)
            .expect("the external custodian must reserve both final supervisors");
        let reaper_custodian_owner = DedicatedTaskCustodian::new(1).expect("reaper custodian");
        let reaper_custodian = reaper_custodian_owner
            .reserve(1)
            .expect("the reaper custodian must reserve its own handle");
        let observer_owner = Arc::clone(&custodian_owner);
        let reaper_observer_owner = Arc::clone(&reaper_custodian_owner);
        let mut terminal_progress = observer_owner.progress();
        let terminal_target = *terminal_progress.borrow() + 2;
        let mut reaper_progress = reaper_observer_owner.progress();
        let reaper_target = *reaper_progress.borrow() + 1;
        let (fallback_shutdown, mut fallback_shutdown_rx) = watch::channel(false);
        let fallback_supervisor = tokio::spawn(async move {
            fallback_shutdown_rx
                .changed()
                .await
                .expect("Drop shutdown reaches the fallback supervisor");
        });
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_for_task = Arc::clone(&dropped);
        let dropped_wake = Arc::new(Notify::new());
        let dropped_wake_for_task = Arc::clone(&dropped_wake);
        let (nested_started_tx, nested_started_rx) = tokio::sync::oneshot::channel();
        let nested = tokio::spawn(async move {
            let _mark = DropMark(dropped_for_task, dropped_wake_for_task);
            nested_started_tx
                .send(())
                .expect("nested drop marker is installed");
            std::future::pending::<()>().await;
        });
        nested_started_rx
            .await
            .expect("nested child starts before driver Drop");
        let handle = NostrDriverHandle {
            cancellers: vec![Arc::new(AtomicBool::new(false))],
            cancel_wakes: vec![Arc::new(Notify::new())],
            tasks: Arc::new(Mutex::new(Some(vec![nested]))),
            fallback_supervisor_task: Mutex::new(Some(fallback_supervisor)),
            task_reaper: Mutex::new(Some(reaper_sender)),
            task_reaper_handle: Mutex::new(Some(reaper_task)),
            custodian_owner,
            custodian: Some(custodian),
            reaper_custodian_owner,
            reaper_custodian: Some(reaper_custodian),
            force_reconnect: Arc::new(watch::channel(0u64).0),
            relay_connected: Arc::new(watch::channel(0u64).0),
            delivery: DeliveryStore::new(Arc::new(UnmeteredDeliveryProvider)),
            shutdown: fallback_shutdown,
        };
        drop(handle);

        tokio::time::timeout(Duration::from_secs(2), async {
            dropped_wake.notified().await;
            // The drop notification proves cancellation ran, not that the
            // reaper has also observed its overflow filler. Join all three
            // transferred handles within the existing terminal deadline.
            while *terminal_progress.borrow() < terminal_target {
                terminal_progress
                    .changed()
                    .await
                    .expect("driver observer stays live");
            }
            while *reaper_progress.borrow() < reaper_target {
                reaper_progress
                    .changed()
                    .await
                    .expect("reaper observer stays live");
            }
        })
        .await
        .expect("external custody path must observe nested task cancellation");
        observer_owner.close();
        reaper_observer_owner.close();
        assert_eq!(*terminal_progress.borrow(), terminal_target);
        assert_eq!(*reaper_progress.borrow(), reaper_target);
        let supervisors = fallback.supervisors.lock().drain(..).collect::<Vec<_>>();
        assert_eq!(
            supervisors.len(),
            0,
            "final supervisors must leave the dropped handle graph"
        );
        assert!(
            dropped.load(Ordering::Acquire),
            "Drop must abort and observe the active nested relay task"
        );
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 1,
            "the full overflow filler must be terminal-observed"
        );
        assert!(fallback.take_tasks().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_full_and_closed_fallbacks_observe_panics_in_and_outside_runtime() {
        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);

        let fallback_reaper_tasks = FallbackReaperTasks::new(1);
        let (full_sender, mut full_receiver) = mpsc::channel(1);
        full_sender
            .try_send(tokio::spawn(std::future::pending::<()>()))
            .expect("the first handle fills the bounded reaper channel");
        let (task, started) = panicking_task("injected nostr panic through full fallback");
        started
            .await
            .expect("the full fallback child starts before transfer");
        abort_and_join(&full_sender, task, &fallback_reaper_tasks);
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
        let (task, started) = panicking_task("injected nostr panic through closed fallback");
        started
            .await
            .expect("the closed fallback child starts before transfer");
        abort_and_join(&closed_sender, task, &fallback_reaper_tasks);
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
            panicking_task("injected nostr panic through outside-runtime full fallback");
        started
            .await
            .expect("the outside-runtime full child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || abort_and_join(&full_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime full fallback returns after joining");
        reap_fallback_reaper_tasks(&fallback_reaper_tasks).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 3,
            "a full no-runtime transfer remains owned until the explicit observer joins it"
        );
        let filler = full_receiver
            .try_recv()
            .expect("the no-runtime full filler remains explicitly owned");
        filler.abort();
        assert!(filler.await.is_err(), "aborted filler must be observed");

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        let (task, started) =
            panicking_task("injected nostr panic through outside-runtime closed fallback");
        started
            .await
            .expect("the outside-runtime closed child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || abort_and_join(&closed_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime closed fallback returns after joining");
        reap_fallback_reaper_tasks(&fallback_reaper_tasks).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 4,
            "a closed no-runtime transfer remains owned until the explicit observer joins it"
        );
    }

    fn fixture_shared() -> Arc<DriverShared> {
        let identity = NostrIdentity::generate();
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
        // The standalone shape: an unbounded source has no accountant, so its
        // owner is `()`, and erasing that is what lets the fixture hand the
        // driver the same concrete `ErasedOwner` the bridge does.
        let out_rx: Box<dyn OutboundSource<NostrOutbound, Owner = ErasedOwner>> = Box::new(
            crate::ErasedSource::new(crate::UnboundedSource::new(out_rx)),
        );
        Arc::new(DriverShared {
            identity,
            room_handle: "test-room".into(),
            device_id: "self-device".into(),
            timing: test_timing(),
            outbound: tokio::sync::Mutex::new(Some(out_rx)),
            delivery: DeliveryStore::new(Arc::new(UnmeteredDeliveryProvider)),
            refusal_sink: Arc::new(UnmeteredAttemptRefusalSink),
            presence_tx: watch::channel(None).0,
            force_reconnect: Arc::new(watch::channel(0u64).0),
            relay_connected: Arc::new(watch::channel(0u64).0),
            shutdown: watch::channel(false).0,
        })
    }

    fn test_timing() -> NostrTimingConfig {
        NostrTimingConfig {
            connect_timeout: Duration::from_secs(30),
            reconnect_initial: Duration::from_secs(2),
            reconnect_max: Duration::from_secs(60),
            reconnect_max_attempts: 6,
            jitter_percent: 15,
            fallback_poll: Duration::from_secs(3),
            fallback_activation_grace: Duration::from_secs(20),
            session_close_timeout: Duration::from_secs(1),
            announcer_cancel_quantum: Duration::from_secs(1),
        }
    }

    /// Build a Nostr `EVENT` frame carrying an Announce envelope
    /// from a fixed peer. The event ID is whatever the signer
    /// produced; we wrap it the same way a relay would so
    /// `handle_inbound_frame` parses it exactly like in production.
    #[test]
    fn relay_admission_is_subscription_scoped_and_balanced() {
        let shared = fixture_shared();
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);
        for (frame, expected) in [
            (r#"["EOSE","other"]"#, RelayControlFrame::Other),
            (r#"["EOSE"]"#, RelayControlFrame::Other),
            (r#"["EOSE","mom-sig-1",0]"#, RelayControlFrame::Other),
            (r#"["EOSE","mom-sig-1"]"#, RelayControlFrame::Eose),
            (
                r#"["NOTICE","too many connections"]"#,
                RelayControlFrame::Rejected,
            ),
        ] {
            assert_eq!(
                handle_inbound_frame_observed(
                    "relay",
                    frame,
                    &shared,
                    &tx,
                    RelaySessionId::fresh()
                )
                .unwrap(),
                expected
            );
        }
        assert!(rx.try_recv().is_err());
        let live = AtomicUsize::new(0);
        let start = Instant::now();
        {
            let mut observation = RelaySessionObservation::new(Some(&live));
            assert!(!observation.stable_at(start + RELAY_STABLE_SESSION));
            assert!(observation.admit(start));
            assert!(!observation.admit(start));
            assert_eq!(live.load(std::sync::atomic::Ordering::SeqCst), 1);
            assert!(!observation.stable_at(start + RELAY_STABLE_SESSION - Duration::from_nanos(1)));
            assert!(observation.stable_at(start + RELAY_STABLE_SESSION));
        }
        assert_eq!(live.load(std::sync::atomic::Ordering::SeqCst), 0);
        assert_ne!(
            relay_retry_salt("room-a", "relay", 1),
            relay_retry_salt("room-b", "relay", 1)
        );
        assert_ne!(
            relay_retry_salt("room", "relay-a", 1),
            relay_retry_salt("room", "relay-b", 1)
        );
    }

    #[test]
    fn inbound_integrity_room_and_envelope_mismatch_are_refused_before_delivery() {
        let shared = fixture_shared();
        let signer = NostrIdentity::generate();
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);
        let (valid, _) = announce_frame_for("peer", &signer);
        let mut tampered: Value = serde_json::from_str(&valid).unwrap();
        tampered[2]["content"] = Value::String("changed after signing".into());
        let mismatch = SignalingEnvelope {
            from: "sender".into(),
            to: "test-room".into(),
            msg: SignalingMessage::Announce {
                peer_id: "different".into(),
            },
        };
        for (room, content) in [
            ("test-room", serde_json::to_string(&mismatch).unwrap()),
            (
                "other-room",
                serde_json::to_string(&SignalingEnvelope {
                    from: "peer".into(),
                    to: "test-room".into(),
                    msg: SignalingMessage::Announce {
                        peer_id: "peer".into(),
                    },
                })
                .unwrap(),
            ),
        ] {
            let event = crate::nostr::event::make_event(
                &signer,
                SIGNALING_EVENT_KIND,
                vec![vec!["r".into(), room.into()]],
                content,
                1_700_000_000,
            );
            let frame = serde_json::json!(["EVENT", "sub", event]).to_string();
            handle_inbound_frame("relay", &frame, &shared, &tx, RelaySessionId::fresh()).unwrap();
        }
        handle_inbound_frame(
            "relay",
            &tampered.to_string(),
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .unwrap();
        assert!(rx.try_recv().is_err());
        handle_inbound_frame("relay", &valid, &shared, &tx, RelaySessionId::fresh()).unwrap();
        assert!(matches!(
            rx.try_recv(),
            Ok(NostrInbound::PeerAnnounced { .. })
        ));
    }

    fn announce_frame_for(peer: &str, signer: &NostrIdentity) -> (String, String) {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: "test-room".into(),
            msg: SignalingMessage::Announce {
                peer_id: peer.into(),
            },
        };
        let content = serde_json::to_string(&envelope).unwrap();
        let event = crate::nostr::event::make_event(
            signer,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            content,
            1_700_000_000,
        );
        let frame = serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&event).unwrap()])
            .to_string();
        (frame, event.id)
    }

    /// **The same event from two relays is offered onward twice, because this
    /// layer no longer decides what a duplicate is.**
    ///
    /// It used to. A ring of event ids sat in front of the envelope parse, and
    /// the second relay's copy was dropped here. That was one layer too early in
    /// two separate ways: the id was recorded before the value was offered, and
    /// the offer's result was discarded — so a copy the consumer refused under
    /// pressure still poisoned the id, and the copy that would have rescued the
    /// attempt was swallowed on its way past.
    ///
    /// What happens to the second copy downstream depends on what it is, and the
    /// two answers are different on purpose.
    ///
    /// *Stamped negotiation* — an offer, answer or candidate — carries the
    /// engine-minted attempt correlation, so the duplicate is collapsed once,
    /// downstream, after acceptance and against that exact attempt (see
    /// `engine::signaling_ingress`).
    ///
    /// *Presence* — an announce or a leave — carries no such stamp, and is not
    /// de-duplicated at all: one copy per relay reaches the engine, **by
    /// design**. `ensure_peer_session` is idempotent, so the second copy is a
    /// no-op rather than a second session, and the alternative — a driver-side
    /// ring keyed on event id — is exactly what was deleted here and for good
    /// reason. Saying "it is deduped downstream" of presence would be false.
    ///
    /// What this control fixes in place is that the driver does not *also* have
    /// an opinion about either class: two relay copies produce two offers, and a
    /// policy that quietly reappeared here would fail this line rather than
    /// silently double-guard the boundary.
    #[test]
    fn every_relay_copy_is_offered_onward_from_this_layer() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let (frame, _event_id) = announce_frame_for(&peer_pub, &peer_signer);
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");
        handle_inbound_frame(
            "wss://relay-b",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("dup parses");
        handle_inbound_frame(
            "wss://relay-c",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("dup parses");

        for relay in ["a", "b", "c"] {
            match rx.try_recv() {
                Ok(NostrInbound::PeerAnnounced { device_id, .. }) => {
                    assert_eq!(device_id, peer_pub, "relay {relay}'s copy names the peer")
                }
                other => panic!("relay {relay}'s copy must be offered onward, got {other:?}"),
            }
        }
        assert!(
            rx.try_recv().is_err(),
            "non-vacuity: three copies in, exactly three out — the layer is not \
             inventing deliveries either"
        );
    }

    /// Different events from the same peer (e.g. periodic re-announces)
    /// must NOT be deduped — each one is a fresh signal that signaling
    /// is alive.
    ///
    /// Nothing is dropped here on an event id, either. The relay-replay case —
    /// several copies of one event id arriving from several relays — is offered
    /// onward from this layer too, which is what the control above this one
    /// pins. What becomes of a duplicate is decided downstream and differs by
    /// class: stamped negotiation is collapsed against its exact attempt, while
    /// unstamped presence is intentionally not de-duplicated at all and reaches
    /// the engine once per relay copy.
    #[test]
    fn distinct_events_each_fire_inbound() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let (frame1, id1) = announce_frame_for(&peer_pub, &peer_signer);

        // Bump the timestamp so the second event hashes to a
        // different id (NIP-01 events are content-addressed).
        let envelope = SignalingEnvelope {
            from: peer_pub.clone(),
            to: "test-room".into(),
            msg: SignalingMessage::Announce {
                peer_id: peer_pub.clone(),
            },
        };
        let ev2 = crate::nostr::event::make_event(
            &peer_signer,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            serde_json::to_string(&envelope).unwrap(),
            1_700_000_005,
        );
        let frame2 =
            serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&ev2).unwrap()]).to_string();
        assert_ne!(id1, ev2.id, "test fixture: events must have distinct ids");

        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);
        handle_inbound_frame(
            "wss://relay-a",
            &frame1,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame 1 parses");
        handle_inbound_frame(
            "wss://relay-a",
            &frame2,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame 2 parses");

        assert!(matches!(
            rx.try_recv().expect("first announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
        assert!(matches!(
            rx.try_recv().expect("second announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
    }

    /// Build a directed Offer frame from `peer` to `to`, signed by
    /// `signer`, on the given Nostr `kind`. Used to exercise the
    /// presence/negotiation kind guard from both sides.
    fn offer_frame_for(peer: &str, to: &str, signer: &NostrIdentity, kind: u16) -> String {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: to.into(),
            msg: SignalingMessage::Offer {
                peer_id: peer.into(),
                offer_id: "off-1".into(),
                sdp: "v=0\r\n".into(),
            },
        };
        let content = serde_json::to_string(&envelope).unwrap();
        let event = crate::nostr::event::make_event(
            signer,
            kind,
            vec![vec!["r".into(), "test-room".into()]],
            content,
            1_700_000_000,
        );
        serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&event).unwrap()]).to_string()
    }

    #[test]
    fn nostr_envelope_requires_recipient_and_rejects_unknown_fields() {
        let missing_recipient = r#"{"from":"peer-a","kind":"announce","peer_id":"peer-a"}"#;
        assert!(
            serde_json::from_str::<SignalingEnvelope>(missing_recipient).is_err(),
            "Nostr envelopes must carry an explicit current recipient"
        );
        let unknown = r#"{"from":"peer-a","to":"test-room","kind":"announce","peer_id":"peer-a","accepted":true}"#;
        assert!(
            serde_json::from_str::<SignalingEnvelope>(unknown).is_err(),
            "ignored envelope/message fields must not decode"
        );
    }

    /// A live offer on the ephemeral kind is delivered to the engine.
    #[test]
    fn offer_on_ephemeral_kind_is_delivered() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let frame = offer_frame_for(
            &peer_pub,
            "self-device",
            &peer_signer,
            SIGNALING_EPHEMERAL_KIND,
        );
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        match rx.try_recv().expect("offer delivered") {
            NostrInbound::Message { from, msg } => {
                assert_eq!(from, peer_pub);
                assert!(matches!(msg, SignalingMessage::Offer { .. }));
            }
            other => panic!("expected Message(Offer), got {other:?}"),
        }
    }

    /// The replay-poisoning fix: an offer that arrives on the STORED
    /// presence kind is replayed history (or a pre-split build), not a
    /// live negotiation. It must be dropped so it can never bind a
    /// fresh PeerConnection to dead ICE credentials.
    #[test]
    fn offer_on_stored_kind_is_dropped() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let frame = offer_frame_for(&peer_pub, "self-device", &peer_signer, SIGNALING_EVENT_KIND);
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        assert!(
            rx.try_recv().is_err(),
            "a directed offer on the stored kind must be dropped, not applied"
        );
    }

    /// Mirror guard: presence is only honoured on the stored kind, so
    /// an Announce wrongly published on the ephemeral kind is ignored.
    #[test]
    fn announce_on_ephemeral_kind_is_dropped() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let envelope = SignalingEnvelope {
            from: peer_pub.clone(),
            to: "test-room".into(),
            msg: SignalingMessage::Announce {
                peer_id: peer_pub.clone(),
            },
        };
        let ev = crate::nostr::event::make_event(
            &peer_signer,
            SIGNALING_EPHEMERAL_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            serde_json::to_string(&envelope).unwrap(),
            1_700_000_000,
        );
        let frame =
            serde_json::json!(["EVENT", "sub-1", serde_json::to_value(&ev).unwrap()]).to_string();
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();
        let tx = InboundSink::from_unbounded(tx);

        handle_inbound_frame(
            "wss://relay-a",
            &frame,
            &shared,
            &tx,
            RelaySessionId::fresh(),
        )
        .expect("frame parses");

        assert!(
            rx.try_recv().is_err(),
            "an announce on the ephemeral kind must be dropped"
        );
    }

    /// **One subscription shape, and nothing a peer publishes can widen it.**
    ///
    /// The filter set used to be three: presence, directed-to-me, and — while
    /// any announced peer had not advertised the recipient-tag capability — a
    /// room-wide catch-all that asked the relay for every pairwise negotiation
    /// in the room. Whether the third one was attached was decided by an
    /// unbounded map keyed on unauthenticated announce ids, so one sender could
    /// hold it on for everybody and read the room's whole negotiation traffic.
    ///
    /// Both assertions are the fix, and each is the other's non-vacuity: there
    /// are exactly two filters, and every filter that asks for the negotiation
    /// kind names us as its recipient. A re-introduced catch-all fails the
    /// second even if it kept the count at two.
    #[test]
    fn the_subscription_asks_only_for_presence_and_directed_to_me() {
        let shared = fixture_shared();
        let filters = desired_filters(&shared);
        assert_eq!(
            filters.len(),
            2,
            "presence + directed-to-me, with no room-wide third"
        );
        assert_eq!(
            filters[0]["kinds"][0],
            serde_json::json!(SIGNALING_EVENT_KIND),
            "presence filter carries the stored kind"
        );
        for filter in &filters {
            if filter["kinds"][0] == serde_json::json!(SIGNALING_EPHEMERAL_KIND) {
                assert!(
                    filter
                        .get("#p")
                        .and_then(|p| p.as_array())
                        .is_some_and(|p| p.iter().any(|v| v == "self-device")),
                    "a negotiation filter must name us as the recipient; an \
                     unconstrained one is the amplification this deleted"
                );
            }
        }
    }

    #[test]
    fn build_req_replaces_same_sub_id() {
        let shared = fixture_shared();
        let req = build_req(&shared, "mom-sig-1");
        let v: Value = serde_json::from_str(&req).unwrap();
        assert_eq!(v[0], "REQ");
        assert_eq!(v[1], "mom-sig-1");
        assert_eq!(
            v.as_array().unwrap().len(),
            2 + 2,
            "REQ + sub id + the two filters"
        );
    }

    #[test]
    fn jitter_stays_within_15_percent_and_is_deterministic() {
        for salt in 0..64u64 {
            let w = jittered_ms(120_000, 15, "some-device", salt);
            assert!((102_000..=138_000).contains(&w), "±15% bound, got {w}");
            assert_eq!(
                w,
                jittered_ms(120_000, 15, "some-device", salt),
                "same inputs, same wait"
            );
        }
        // Different nodes land on different offsets (not all identical).
        let a = jittered_ms(120_000, 15, "device-a", 1);
        let b = jittered_ms(120_000, 15, "device-b", 1);
        let c = jittered_ms(120_000, 15, "device-c", 1);
        assert!(
            !(a == b && b == c),
            "three nodes shouldn't share one jitter offset"
        );
        assert_eq!(jittered_ms(0, 15, "x", 0), 0, "zero base stays zero");
    }

    #[test]
    fn reconnect_attempt_and_jitter_boundaries_do_not_wrap() {
        assert_eq!(next_reconnect_attempt(u32::MAX, u32::MAX), u32::MAX);
        assert_eq!(next_reconnect_attempt(u32::MAX - 1, u32::MAX), u32::MAX);
        let wide = jittered_ms(u64::MAX, 100, "boundary", u64::MAX);
        assert_eq!(
            wide,
            jittered_ms(u64::MAX, 100, "boundary", u64::MAX),
            "wide jitter arithmetic remains deterministic at the boundary"
        );

        let mut timing = test_timing();
        timing.reconnect_initial = Duration::from_millis(u64::MAX);
        timing.reconnect_max = Duration::from_millis(u64::MAX);
        assert_eq!(reconnect_base_ms(u32::MAX, &timing), u64::MAX);
    }
}
