//! Self-hosted signaling relay — a Nostr relay (NIP-01 over WebSocket)
//! that mesh peers point their `signaling.servers` at to run a network
//! with no dependency on the public Nostr relay pool.
//!
//! It speaks plain NIP-01, so the [`crate::nostr`] driver and even public
//! relays interoperate unchanged. On top of that baseline it adds
//! **stateful coordination** — the "intelligent relay" behaviour — all as
//! optional accelerators that degrade gracefully to plain NIP-01:
//!
//! - **Live presence.** The relay learns `(connection → device, room)`
//!   from the announces a peer publishes, so it tracks who is actually
//!   connected right now. A peer subscribing gets the *live* member set
//!   replayed instantly, not just the time-windowed store — near-instant
//!   discovery even if a member's last announce is old.
//! - **Instant departure.** When a member's socket closes, the relay
//!   emits a `leave` ([`SignalingMessage::Leave`](crate::SignalingMessage))
//!   to the room so peers tear the connection down promptly instead of
//!   waiting out a heartbeat timeout. Public relays never send this;
//!   peers that don't get it fall back to timeout detection.
//! - **Flood limits.** Per-connection token buckets, per-IP connection
//!   caps, subscription / filter / message-size / presence caps, and
//!   strike-based disconnection — so the relay is safe to stand up publicly.
//!
//! ## What it deliberately skips
//!
//! Signature verification. The relay is a forwarder; the mesh runs its
//! own ed25519 mutual authentication over the resulting WebRTC channel,
//! so a forged Nostr event only buys a failed handshake. (It does hold a
//! Nostr keypair, but only to *sign its own* synthesized `leave` events
//! so they're well-formed for any peer that does verify.)
//!
//! Event kinds follow NIP-01: ephemeral events (`20000..=29999`, e.g. the
//! mesh's `21077` negotiation + `leave` traffic) are forwarded but never
//! stored; everything else (e.g. `1077` presence) is retained for
//! late-joiner replay.

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::pin::Pin;
#[cfg(test)]
use std::sync::atomic::AtomicUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
#[cfg(test)]
use std::sync::OnceLock;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use futures_util::{FutureExt, SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, watch};
use tokio::task::JoinHandle;
use tokio_tungstenite::accept_async_with_config;
use tokio_tungstenite::tungstenite::{protocol::WebSocketConfig, Message as WsMessage};
use tracing::{debug, info, trace, warn};

use crate::nostr::event::{
    make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EPHEMERAL_KIND, SIGNALING_EVENT_KIND,
};
#[cfg(test)]
use crate::task_custodian::DedicatedTaskCustodian;
use crate::task_custodian::{CustodianReservation, TaskCustodian};
use crate::{Error, Result};

type WriterRegistry = Arc<Mutex<HashMap<u64, Option<JoinHandle<()>>>>>;
type WriterSettlementSender = mpsc::Sender<u64>;
type ConnectionRegistry = Arc<Mutex<HashMap<u64, JoinHandle<()>>>>;
type ConnectionCompletionSender = mpsc::Sender<u64>;
type TaskReaperSender = mpsc::Sender<JoinHandle<()>>;

/// Owner-scoped custody for handles that synchronous `Drop` could not return
/// to the bounded channel reaper. Its capacity is derived from the exact
/// number of tasks one server can own, so fallback retention cannot grow with
/// process lifetime or unrelated server instances.
struct FallbackReaperTasks {
    capacity: usize,
    tasks: Mutex<Vec<JoinHandle<()>>>,
    overflow: Mutex<Option<JoinHandle<()>>>,
    /// The caller-funded terminal owner used when both the runtime reaper
    /// channel and this bounded staging area are unavailable.  Keeping this
    /// owner beside the staging state makes the last-resort path preserve the
    /// exact handle instead of aborting or detaching it.
    custodian_owner: Option<Arc<dyn TaskCustodian>>,
}

impl FallbackReaperTasks {
    #[cfg(test)]
    fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            tasks: Mutex::new(Vec::with_capacity(capacity)),
            overflow: Mutex::new(None),
            custodian_owner: None,
        })
    }

    fn with_owner(capacity: usize, custodian_owner: Arc<dyn TaskCustodian>) -> Arc<Self> {
        Arc::new(Self {
            capacity,
            tasks: Mutex::new(Vec::with_capacity(capacity)),
            overflow: Mutex::new(None),
            custodian_owner: Some(custodian_owner),
        })
    }

    fn retain(&self, task: JoinHandle<()>) -> std::result::Result<(), JoinHandle<()>> {
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

    fn retain_overflow(&self, task: JoinHandle<()>) -> std::result::Result<(), JoinHandle<()>> {
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
static TEST_PARK_NEXT_WRITER: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_WRITER_PARKED: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_PANIC_AFTER_WRITER: AtomicBool = AtomicBool::new(false);
#[cfg(test)]
static TEST_REAPED_TASKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_REAPED_FALLBACKS: AtomicUsize = AtomicUsize::new(0);
#[cfg(test)]
static TEST_REAPED_FALLBACK_WAKE: OnceLock<tokio::sync::Notify> = OnceLock::new();
#[cfg(test)]
static TEST_GATE_SERIAL: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

#[cfg(test)]
fn record_reaped_fallback() {
    TEST_REAPED_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    TEST_REAPED_FALLBACK_WAKE
        .get_or_init(tokio::sync::Notify::new)
        .notify_one();
}

/// Flood-protection limits for the signaling relay. Every field is finite and
/// non-zero: an unbounded deployment is not a valid server configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Max connections admitted globally, including handshakes in progress.
    pub max_connections: u32,
    /// Max `EVENT` publishes per second per connection (token bucket,
    /// 1-second burst).
    pub max_event_rate: u32,
    /// Max `REQ` subscriptions per second per connection.
    pub max_req_rate: u32,
    /// Max concurrent subscriptions a single connection may hold.
    pub max_subscriptions: u32,
    /// Max filters in a single `REQ` (extra filters are dropped).
    pub max_filters_per_req: u32,
    /// Max size of a single client frame in bytes.
    pub max_message_bytes: u32,
    /// Max concurrent connections from one IP address.
    pub max_connections_per_ip: u32,
    /// Max distinct live `(room, device)` memberships one connection may
    /// own. Since global connections are bounded, total live presence is
    /// bounded by `max_connections * max_presence_memberships`.
    pub max_presence_memberships: u32,
    /// Max bytes in the HTTP upgrade request before the WebSocket parser.
    pub max_handshake_bytes: u32,
    /// Max payload bytes in one incoming WebSocket frame.
    pub max_frame_bytes: u32,
    /// Max replayable events retained across all rooms.
    pub max_stored_events: u32,
    /// Seconds a stored event remains replayable.
    pub stored_retention_secs: u64,
    /// Seconds between operator-visible activity heartbeat snapshots.
    /// Independent from event-retention policy.
    pub stats_heartbeat_interval_secs: u64,
    /// Max events materialized for one `REQ` replay.
    pub max_replay_per_req: u32,
    /// Max pending wire frames per connection.
    pub outbound_queue_cap: u32,
    /// Rate-limit violations allowed before disconnect.
    pub strike_limit: u32,
    /// Seconds a trickling HTTP upgrade may hold its admission reservation.
    pub handshake_timeout_secs: u64,
    /// Seconds allowed for a writer to finish after connection shutdown.
    pub writer_stop_timeout_secs: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_connections: 256,
            max_event_rate: 50,
            max_req_rate: 20,
            max_subscriptions: 64,
            max_filters_per_req: 16,
            max_message_bytes: 65_536,
            max_connections_per_ip: 64,
            max_presence_memberships: 256,
            max_handshake_bytes: 16 * 1024,
            max_frame_bytes: 65_536,
            max_stored_events: 8192,
            stored_retention_secs: 15 * 60,
            stats_heartbeat_interval_secs: 15 * 60,
            max_replay_per_req: 500,
            outbound_queue_cap: 128,
            strike_limit: 50,
            handshake_timeout_secs: 10,
            writer_stop_timeout_secs: 2,
        }
    }
}

impl Limits {
    /// Reject zero/unlimited values before any listener or connection task is
    /// created. Keeping the check at the public construction boundary makes
    /// every live relay finite, including deployments that deserialize this
    /// type from configuration.
    pub fn validate(&self) -> Result<()> {
        let fields = [
            ("max_connections", self.max_connections),
            ("max_event_rate", self.max_event_rate),
            ("max_req_rate", self.max_req_rate),
            ("max_subscriptions", self.max_subscriptions),
            ("max_filters_per_req", self.max_filters_per_req),
            ("max_message_bytes", self.max_message_bytes),
            ("max_connections_per_ip", self.max_connections_per_ip),
            ("max_presence_memberships", self.max_presence_memberships),
            ("max_handshake_bytes", self.max_handshake_bytes),
            ("max_frame_bytes", self.max_frame_bytes),
            ("max_stored_events", self.max_stored_events),
            ("max_replay_per_req", self.max_replay_per_req),
            ("outbound_queue_cap", self.outbound_queue_cap),
            ("strike_limit", self.strike_limit),
        ];
        if let Some((name, _)) = fields.iter().find(|(_, value)| *value == 0) {
            return Err(Error::Other(format!("{name} must be finite and non-zero")));
        }
        for (name, value) in fields {
            if usize::try_from(value).is_err() {
                return Err(Error::Other(format!(
                    "{name} does not fit the platform usize"
                )));
            }
        }
        for (name, value) in [
            ("stored_retention_secs", self.stored_retention_secs),
            (
                "stats_heartbeat_interval_secs",
                self.stats_heartbeat_interval_secs,
            ),
            ("handshake_timeout_secs", self.handshake_timeout_secs),
            ("writer_stop_timeout_secs", self.writer_stop_timeout_secs),
        ] {
            if value == 0 {
                return Err(Error::Other(format!("{name} must be finite and non-zero")));
            }
        }
        for (name, left, right) in [
            (
                "stored event byte ceiling",
                self.max_stored_events,
                self.max_message_bytes,
            ),
            (
                "replay byte ceiling",
                self.max_replay_per_req,
                self.max_message_bytes,
            ),
            (
                "outbound queue slot ceiling",
                self.max_connections,
                self.outbound_queue_cap,
            ),
        ] {
            Self::checked_product(name, left, right)?;
        }
        let write_buffer = u64::from(self.max_message_bytes)
            .checked_mul(2)
            .ok_or_else(|| Error::Other("max write buffer size overflow".into()))?;
        usize::try_from(write_buffer).map_err(|_| {
            Error::Other("max write buffer size does not fit platform usize".into())
        })?;
        Ok(())
    }

    fn checked_usize(value: u32, name: &'static str) -> Result<usize> {
        usize::try_from(value)
            .map_err(|_| Error::Other(format!("{name} does not fit the platform usize")))
    }

    fn checked_write_buffer_size(&self) -> Result<usize> {
        let value = u64::from(self.max_message_bytes)
            .checked_mul(2)
            .ok_or_else(|| Error::Other("max write buffer size overflow".into()))?;
        usize::try_from(value)
            .map_err(|_| Error::Other("max write buffer size does not fit platform usize".into()))
    }

    fn handshake_timeout(&self) -> Duration {
        Duration::from_secs(self.handshake_timeout_secs)
    }

    fn writer_stop_timeout(&self) -> Duration {
        Duration::from_secs(self.writer_stop_timeout_secs)
    }

    /// Keep the activity heartbeat on its own operator-selected horizon;
    /// storage retention is a separate policy and must not control it.
    fn stats_heartbeat_interval(&self) -> Duration {
        Duration::from_secs(self.stats_heartbeat_interval_secs)
    }

    fn checked_product(name: &'static str, left: u32, right: u32) -> Result<usize> {
        let value = u64::from(left)
            .checked_mul(u64::from(right))
            .ok_or_else(|| Error::Other(format!("{name} overflow")))?;
        usize::try_from(value)
            .map_err(|_| Error::Other(format!("{name} does not fit platform usize")))
    }
}

/// Live activity snapshot for the relay — surfaced in the periodic log
/// heartbeat and via `ctl services status` so an operator can tell at a
/// glance whether peers are actually reaching the relay. A public
/// deployment behind a misconfigured proxy / wrong DNS shows
/// `connections: 0` here, which says "traffic isn't arriving" rather than
/// "the relay is broken".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RelayStatsSnapshot {
    /// Connections open right now.
    pub connections: u64,
    /// Connections accepted since startup.
    pub connections_total: u64,
    /// Rooms with at least one live member.
    pub rooms: u64,
    /// `EVENT`s the relay has accepted and fanned out since startup.
    pub events_relayed: u64,
}

/// A running signaling relay. Constructed via
/// [`SignalingServer::start_with_custodian`].
pub struct SignalingServer;

struct RegistryTerminal {
    progress: watch::Sender<u64>,
    hub_idle_before_reap: AtomicBool,
}

impl RegistryTerminal {
    fn new() -> Self {
        let (progress, _) = watch::channel(0);
        Self {
            progress,
            hub_idle_before_reap: AtomicBool::new(false),
        }
    }
}

/// Handle to a running signaling relay. Drop it (or call
/// [`SignalingServerHandle::stop_and_wait`]) to shut the listener down.
pub struct SignalingServerHandle {
    task: Option<JoinHandle<()>>,
    heartbeat: Option<JoinHandle<()>>,
    connections: ConnectionRegistry,
    writers: WriterRegistry,
    registry_terminal: Arc<RegistryTerminal>,
    task_reaper: Mutex<Option<TaskReaperSender>>,
    task_reaper_handle: Mutex<Option<JoinHandle<()>>>,
    custodian_owner: Arc<dyn TaskCustodian>,
    custodian: Option<CustodianReservation>,
    fallback_reaper_tasks: Arc<FallbackReaperTasks>,
    writer_stop_timeout: Duration,
    local_addr: SocketAddr,
    hub: Hub,
}

/// Terminal failures observed while draining the server's owned tasks.
#[derive(Debug, thiserror::Error)]
#[error("signaling server shutdown failed: {failures:?}")]
pub struct SignalingShutdownError {
    pub failures: Vec<SignalingShutdownFailure>,
}

#[derive(Debug)]
pub struct SignalingShutdownFailure {
    pub task: String,
    pub error: String,
}

impl SignalingServerHandle {
    /// The address the relay actually bound (resolves an ephemeral port
    /// to the real one — used in tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Live activity snapshot — connections, rooms, events relayed.
    pub fn stats(&self) -> RelayStatsSnapshot {
        self.hub.snapshot()
    }

    /// Wait until the accept loop has observed and awaited every finished
    /// connection task and all exact writer placeholders are retired. The
    /// return value records whether Hub admission was already idle before the
    /// finished handler was extracted for observation.
    pub async fn wait_for_registry_idle(&self) -> bool {
        let mut progress = self.registry_terminal.progress.subscribe();
        loop {
            let idle = self.connections.lock().is_empty() && self.writers.lock().is_empty();
            if idle {
                return self
                    .registry_terminal
                    .hub_idle_before_reap
                    .load(Ordering::Acquire);
            }
            if progress.changed().await.is_err() {
                return false;
            }
        }
    }

    /// Gracefully stop the listener and heartbeat, signal every live
    /// connection, and await all owned connection/writer tasks. A writer that
    /// cannot close within the bounded stop interval is aborted and joined so
    /// no detached task survives this fence.
    pub async fn stop_and_wait(mut self) -> std::result::Result<(), SignalingShutdownError> {
        self.hub.shutdown();
        let mut failures = Vec::new();
        if let Some(task) = self.task.take() {
            if let Err(error) = task.await {
                warn!("signaling accept loop did not complete normally: {error}");
                if !error.is_cancelled() {
                    failures.push(SignalingShutdownFailure {
                        task: "accept".into(),
                        error: error.to_string(),
                    });
                }
            }
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            heartbeat.abort();
            if let Err(error) = heartbeat.await {
                warn!("signaling heartbeat did not complete normally: {error}");
                if !error.is_cancelled() {
                    failures.push(SignalingShutdownFailure {
                        task: "heartbeat".into(),
                        error: error.to_string(),
                    });
                }
            }
        }

        let tasks = {
            let mut owned = self.connections.lock();
            std::mem::take(&mut *owned)
        };
        for (conn_id, task) in tasks {
            if let Err(error) = task.await {
                warn!("signaling connection task did not complete normally: {error}");
                if !error.is_cancelled() {
                    failures.push(SignalingShutdownFailure {
                        task: format!("connection:{conn_id}"),
                        error: error.to_string(),
                    });
                }
            }
        }

        let writer_ids = self.writers.lock().keys().copied().collect::<Vec<_>>();
        for conn_id in writer_ids {
            if let Err(error) = settle_writer_observed(
                &self.writers,
                conn_id,
                self.writer_stop_timeout,
                self.custodian_owner.as_ref(),
                &self.fallback_reaper_tasks,
            )
            .await
            {
                failures.push(SignalingShutdownFailure {
                    task: format!("writer:{conn_id}"),
                    error,
                });
            }
        }
        let reaper_sender = self.task_reaper.lock().take();
        drop(reaper_sender);
        let reaper = self.task_reaper_handle.lock().take();
        if let Some(reaper) = reaper {
            if let Err(error) = reaper.await {
                warn!("signaling task reaper did not complete normally: {error}");
                if !error.is_cancelled() {
                    failures.push(SignalingShutdownFailure {
                        task: "reaper".into(),
                        error: error.to_string(),
                    });
                }
            }
        }
        reap_fallback_reaper_tasks(&self.fallback_reaper_tasks).await;
        self.custodian_owner.close();
        if failures.is_empty() {
            Ok(())
        } else {
            Err(SignalingShutdownError { failures })
        }
    }
}

impl Drop for SignalingServerHandle {
    fn drop(&mut self) {
        self.hub.shutdown();
        let mut custodian = self.custodian.take();
        let reaper = self.task_reaper.lock().take();
        if let Some(task) = self.task.take() {
            if let Some(reaper) = reaper.as_ref() {
                abort_and_join(reaper, task, &self.fallback_reaper_tasks);
            } else {
                task.abort();
                retain_or_join_fallback(&self.fallback_reaper_tasks, task);
            }
        }
        if let Some(heartbeat) = self.heartbeat.take() {
            if let Some(reaper) = reaper.as_ref() {
                abort_and_join(reaper, heartbeat, &self.fallback_reaper_tasks);
            } else {
                heartbeat.abort();
                retain_or_join_fallback(&self.fallback_reaper_tasks, heartbeat);
            }
        }
        let tasks = {
            let mut owned = self.connections.lock();
            std::mem::take(&mut *owned)
        };
        for (_, task) in tasks {
            if let Some(reaper) = reaper.as_ref() {
                abort_and_join(reaper, task, &self.fallback_reaper_tasks);
            } else {
                task.abort();
                retain_or_join_fallback(&self.fallback_reaper_tasks, task);
            }
        }
        let writers = {
            let mut owned = self.writers.lock();
            std::mem::take(&mut *owned)
        };
        for (_, writer) in writers {
            if let Some(writer) = writer {
                if let Some(reaper) = reaper.as_ref() {
                    abort_and_join(reaper, writer, &self.fallback_reaper_tasks);
                } else {
                    writer.abort();
                    retain_or_join_fallback(&self.fallback_reaper_tasks, writer);
                }
            }
        }
        drop(reaper);
        if let Some(reaper_task) = { self.task_reaper_handle.lock().take() } {
            submit_to_custodian_or_fallback(
                &mut custodian,
                &self.fallback_reaper_tasks,
                reaper_task,
                "signaling task reaper",
            );
        }
    }
}

/// Abort a task owned by a dropped server, then transfer its exact join handle
/// to the runtime-owned reaper. Full or closed reaper channels use the
/// bounded owner-backed staging path; no synchronous wait or detached task is
/// permitted from `Drop`.
fn abort_and_join(
    reaper: &TaskReaperSender,
    task: JoinHandle<()>,
    fallback: &Arc<FallbackReaperTasks>,
) {
    task.abort();
    match reaper.try_send(task) {
        Ok(()) => {}
        Err(tokio::sync::mpsc::error::TrySendError::Full(task))
        | Err(tokio::sync::mpsc::error::TrySendError::Closed(task)) => {
            retain_or_overflow(fallback, task, "signaling task");
        }
    }
}

fn retain_or_join_fallback(fallback: &Arc<FallbackReaperTasks>, task: JoinHandle<()>) {
    if let Some(owner) = fallback.custodian_owner.as_ref() {
        let mut reservation = owner.reserve(1).unwrap_or_else(|error| {
            panic!("signaling fallback custody violated its preflight contract: {error:?}")
        });
        if let Err(task) = reservation.submit(task) {
            panic!(
                "signaling fallback custodian rejected a preflighted handle; returned handle must remain owned: {task:?}"
            );
        }
    } else {
        retain_or_overflow(fallback, task, "signaling fallback task");
    }
}

fn submit_to_custodian_or_fallback(
    custodian: &mut Option<CustodianReservation>,
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
    retain_or_overflow(fallback, task, context);
}

fn retain_or_overflow(fallback: &Arc<FallbackReaperTasks>, task: JoinHandle<()>, context: &str) {
    let task = match fallback.retain(task) {
        Ok(()) => return,
        Err(task) => task,
    };
    if let Err(task) = fallback.retain_overflow(task) {
        if let Some(owner) = fallback.custodian_owner.as_ref() {
            let mut reservation = owner.reserve(1).unwrap_or_else(|error| {
                panic!(
                    "signaling terminal custody violated its preflight contract ({context}): {error:?}"
                )
            });
            if let Err(task) = reservation.submit(task) {
                panic!(
                    "signaling terminal custodian rejected a preflighted handle ({context}); returned handle must remain owned: {task:?}"
                );
            }
        } else {
            // Unit controls construct a deliberately tiny holder without an
            // external owner to exercise the bounded overflow branch.  Keep
            // that seam test-only in spirit; production holders always carry
            // the caller-selected custodian above.
            #[cfg(test)]
            {
                task.abort();
                warn!(
                    %context,
                    "signaling test fallback custody exhausted after bounded overflow"
                );
            }
            #[cfg(not(test))]
            {
                let _ = &task;
                panic!("signaling terminal custody missing caller-funded owner ({context})");
            }
        }
    }
}

async fn reap_fallback_reaper_tasks(fallback: &Arc<FallbackReaperTasks>) {
    let tasks = fallback.take_all();
    for task in tasks {
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                warn!("signaling fallback reaper did not join normally: {error}");
            }
        }
        #[cfg(test)]
        record_reaped_fallback();
    }
}

fn spawn_task_reaper(
    capacity: usize,
    fallback: Arc<FallbackReaperTasks>,
) -> (TaskReaperSender, JoinHandle<()>) {
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
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                warn!("dropped signaling task did not join normally: {error}");
            }
        }
        #[cfg(test)]
        TEST_REAPED_TASKS.fetch_add(1, Ordering::AcqRel);
    }
    let tasks = fallback.take_tasks();
    for task in tasks {
        if let Err(error) = task.await {
            if !error.is_cancelled() {
                warn!("dropped signaling fallback task did not join normally: {error}");
            }
        }
        #[cfg(test)]
        TEST_REAPED_FALLBACKS.fetch_add(1, Ordering::AcqRel);
    }
}

impl SignalingServer {
    /// Number of caller-funded task slots needed by one relay.  The first
    /// term covers every handle which can be transferred synchronously from
    /// `Drop`; the second covers one exact terminal observer per live
    /// connection and writer placeholder.
    pub fn required_task_custody_slots(limits: &Limits) -> Result<usize> {
        let registry_capacity = Limits::checked_usize(limits.max_connections, "max_connections")?;
        registry_capacity
            .checked_mul(4)
            .and_then(|capacity| capacity.checked_add(3))
            .ok_or_else(|| Error::Other("signaling custodian capacity overflow".into()))
    }

    /// Bind a TCP listener and start accepting WebSocket signaling
    /// connections. Returns once the socket is bound; the accept loop
    /// runs in a spawned task.
    pub async fn start(bind: &str, port: u16, limits: Limits) -> Result<SignalingServerHandle> {
        let _ = (bind, port);
        limits.validate()?;
        Err(Error::Other(
            "signaling startup requires caller-funded task custody; use start_with_custodian"
                .into(),
        ))
    }

    /// Start with a caller-selected lifecycle task custodian. Its capacity
    /// must satisfy [`Self::required_task_custody_slots`] before any socket
    /// or worker side effect is admitted.
    pub async fn start_with_custodian(
        bind: &str,
        port: u16,
        limits: Limits,
        custodian_owner: Arc<dyn TaskCustodian>,
    ) -> Result<SignalingServerHandle> {
        limits.validate()?;
        let writer_stop_timeout = limits.writer_stop_timeout();
        let heartbeat_interval = limits.stats_heartbeat_interval();
        let registry_capacity = Limits::checked_usize(limits.max_connections, "max_connections")?;
        // Validate the complete finite owner envelope before binding or
        // spawning.  This includes both synchronous Drop transfers and the
        // per-registry terminal observers.
        let custody_capacity = Self::required_task_custody_slots(&limits)?;
        let probe = custodian_owner.reserve(custody_capacity).map_err(|error| {
            Error::Other(format!(
                "signaling task custodian cannot fund required envelope: {error:?}"
            ))
        })?;
        drop(probe);
        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        info!(%local_addr, "signaling relay listening (NIP-01 over WebSocket)");
        let hub = Hub::new(limits);
        // Admission bounds live connections, and the completion channel lets
        // accept_loop retire finished handles before the next admit; these
        // registries therefore need no growth beyond one slot per admission.
        let connections = Arc::new(Mutex::new(HashMap::with_capacity(registry_capacity)));
        let writers = Arc::new(Mutex::new(HashMap::with_capacity(registry_capacity)));
        let registry_terminal = Arc::new(RegistryTerminal::new());
        let reaper_capacity = registry_capacity
            .checked_mul(2)
            .and_then(|capacity| capacity.checked_add(2))
            .ok_or_else(|| Error::Other("signaling task reaper capacity overflow".into()))?;
        let fallback_reaper_tasks = FallbackReaperTasks::with_owner(
            reaper_capacity
                .checked_add(1)
                .ok_or_else(|| Error::Other("signaling fallback capacity overflow".into()))?,
            Arc::clone(&custodian_owner),
        );
        let custodian = custodian_owner.reserve(1).map_err(|error| {
            Error::Other(format!(
                "signaling final-task custodian exhausted: {error:?}"
            ))
        })?;
        let (task_reaper, task_reaper_handle) =
            spawn_task_reaper(reaper_capacity, Arc::clone(&fallback_reaper_tasks));
        let (writer_settlement_tx, writer_settlement_rx) = mpsc::channel(registry_capacity.max(1));
        let (completion_tx, completion_rx) = mpsc::channel(registry_capacity);
        let task = tokio::spawn(accept_loop(
            listener,
            AcceptLoopContext {
                hub: hub.clone(),
                connections: Arc::clone(&connections),
                writers: Arc::clone(&writers),
                registry_terminal: Arc::clone(&registry_terminal),
                registry_capacity,
                completion_rx,
                writer_settlement_rx,
                completion_tx,
                writer_settlement_tx: writer_settlement_tx.clone(),
                writer_stop_timeout,
                custodian_owner: Arc::clone(&custodian_owner),
                fallback_reaper_tasks: Arc::clone(&fallback_reaper_tasks),
            },
        ));
        let heartbeat = tokio::spawn(stats_heartbeat(hub.clone(), heartbeat_interval));
        Ok(SignalingServerHandle {
            task: Some(task),
            heartbeat: Some(heartbeat),
            connections,
            writers,
            registry_terminal,
            task_reaper: Mutex::new(Some(task_reaper)),
            task_reaper_handle: Mutex::new(Some(task_reaper_handle)),
            custodian_owner,
            custodian: Some(custodian),
            fallback_reaper_tasks,
            writer_stop_timeout,
            local_addr,
            hub,
        })
    }
}

/// Periodic activity log so an operator watching the daemon can see the
/// relay is alive and whether anyone is connected. `connections: 0` every
/// interval is the tell that traffic isn't reaching the relay (DNS / TLS /
/// firewall) rather than the relay itself being broken.
async fn stats_heartbeat(hub: Hub, interval: Duration) {
    let mut tick = tokio::time::interval(interval);
    tick.tick().await; // consume the immediate first tick
    loop {
        tick.tick().await;
        let s = hub.snapshot();
        info!(
            connections = s.connections,
            rooms = s.rooms,
            events_relayed = s.events_relayed,
            "signaling: relay activity"
        );
    }
}

struct AcceptLoopContext {
    hub: Hub,
    connections: ConnectionRegistry,
    writers: WriterRegistry,
    registry_terminal: Arc<RegistryTerminal>,
    registry_capacity: usize,
    completion_rx: mpsc::Receiver<u64>,
    writer_settlement_rx: mpsc::Receiver<u64>,
    completion_tx: ConnectionCompletionSender,
    writer_settlement_tx: WriterSettlementSender,
    writer_stop_timeout: Duration,
    custodian_owner: Arc<dyn TaskCustodian>,
    fallback_reaper_tasks: Arc<FallbackReaperTasks>,
}

/// The immutable, cloneable connection dependencies captured at accept time.
/// Keeping these exact owners together prevents a connection task from
/// accidentally receiving a mismatched registry, settlement channel, or
/// terminal custodian.
#[derive(Clone)]
struct ConnectionContext {
    hub: Hub,
    writers: WriterRegistry,
    writer_settlement_tx: WriterSettlementSender,
    registry_terminal: Arc<RegistryTerminal>,
    custodian_owner: Arc<dyn TaskCustodian>,
    fallback_reaper_tasks: Arc<FallbackReaperTasks>,
}

async fn accept_loop(listener: TcpListener, context: AcceptLoopContext) {
    let AcceptLoopContext {
        hub,
        connections,
        writers,
        registry_terminal,
        registry_capacity,
        mut completion_rx,
        mut writer_settlement_rx,
        completion_tx,
        writer_settlement_tx,
        writer_stop_timeout,
        custodian_owner,
        fallback_reaper_tasks,
    } = context;
    let mut shutdown = hub.shutdown_signal();
    let mut custody_progress = custodian_owner.progress();
    // A refused exact notification stays with the accept-loop owner. These
    // queues are bounded by the corresponding live registry, so another
    // producer cannot steal the only retry slot as it could on try_send.
    let mut pending_connections = VecDeque::with_capacity(registry_capacity);
    let mut pending_writers = VecDeque::with_capacity(registry_capacity);
    loop {
        tokio::select! {
            biased;
            completion = completion_rx.recv() => {
                match completion {
                    Some(conn_id) => {
                        let observed = observe_completed_connection(
                            conn_id,
                            &connections,
                            &hub,
                            Arc::clone(&registry_terminal),
                            writer_stop_timeout,
                            custodian_owner.as_ref(),
                            &fallback_reaper_tasks,
                        )
                        .await;
                        if !observed && !pending_connections.contains(&conn_id) {
                            debug_assert!(
                                pending_connections.len() < registry_capacity,
                                "pending connection IDs exceed the live registry bound"
                            );
                            pending_connections.push_back(conn_id);
                        }
                    }
                    None => break,
                }
            }
            settlement = writer_settlement_rx.recv() => {
                match settlement {
                    Some(conn_id) => {
                        let settled = settle_writer_with_progress(
                            &writers,
                            conn_id,
                            writer_stop_timeout,
                            Arc::clone(&registry_terminal),
                            custodian_owner.as_ref(),
                            &fallback_reaper_tasks,
                        )
                        .await;
                        if !settled && !pending_writers.contains(&conn_id) {
                            debug_assert!(
                                pending_writers.len() < registry_capacity,
                                "pending writer IDs exceed the live registry bound"
                            );
                            pending_writers.push_back(conn_id);
                        }
                    }
            None => break,
                }
            }
            changed = custody_progress.changed(), if !pending_connections.is_empty() || !pending_writers.is_empty() => {
                if changed.is_err() {
                    break;
                }
                if let Some(conn_id) = pending_connections.pop_front() {
                    if !observe_completed_connection(
                        conn_id,
                        &connections,
                        &hub,
                        Arc::clone(&registry_terminal),
                        writer_stop_timeout,
                        custodian_owner.as_ref(),
                        &fallback_reaper_tasks,
                    )
                    .await
                    {
                        pending_connections.push_front(conn_id);
                    }
                }
                if let Some(conn_id) = pending_writers.pop_front() {
                    if !settle_writer_with_progress(
                        &writers,
                        conn_id,
                        writer_stop_timeout,
                        Arc::clone(&registry_terminal),
                        custodian_owner.as_ref(),
                        &fallback_reaper_tasks,
                    )
                    .await
                    {
                        pending_writers.push_front(conn_id);
                    }
                }
            }
            changed = shutdown.changed() => {
                if changed.is_err() || *shutdown.borrow() {
                    break;
                }
            }
            result = listener.accept() => {
                match result {
                Ok((stream, peer)) => {
                let hub = hub.clone();
                let connections = Arc::clone(&connections);
                let writers = Arc::clone(&writers);
                let registry_terminal = Arc::clone(&registry_terminal);
                let writer_settlement_tx = writer_settlement_tx.clone();
                let custodian_owner = Arc::clone(&custodian_owner);
                let fallback_reaper_tasks = Arc::clone(&fallback_reaper_tasks);
                let Some(admission) = hub.admit(peer.ip()) else {
                    let mut stream = stream;
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n",
                        )
                        .await;
                    let _ = stream.shutdown().await;
                    continue;
                };
                // Keep admission and exact registry capacity fail-closed for
                // this accepted socket. Completed handlers are retired only
                // by the exact-ID completion branch above; extraction is
                // under the mutex and JoinError observation is outside it.
                let registry_available = {
                    let owned = connections.lock();
                    owned.len() < registry_capacity
                        && writer_registry_slot_available(&writers, registry_capacity)
                };
                if !registry_available {
                    drop(admission);
                    let mut stream = stream;
                    let _ = stream.shutdown().await;
                    continue;
                }
                // The accept loop is the only connection-registry writer;
                // publishing under this guard closes the check/spawn gap.
                let conn_id = admission.id;
                let completion_tx = completion_tx.clone();
                let connection_context = ConnectionContext {
                    hub,
                    writers,
                    writer_settlement_tx,
                    registry_terminal,
                    custodian_owner,
                    fallback_reaper_tasks,
                };
                let task = tokio::spawn(async move {
                    let result = std::panic::AssertUnwindSafe(handle_conn(
                        stream,
                        peer,
                        admission,
                        connection_context,
                    ))
                    .catch_unwind()
                    .await;
                    match result {
                        Ok(Ok(())) => {}
                        Ok(Err(e)) => trace!(%peer, "signaling conn ended: {e}"),
                        Err(_) => warn!(%peer, "signaling connection handler panicked"),
                    }
                    if completion_tx.send(conn_id).await.is_err() {
                        trace!(conn_id, "signaling completion channel closed during shutdown");
                    }
                });
                let mut owned = connections.lock();
                owned.insert(conn_id, task);
                }
                Err(e) => warn!("signaling accept error: {e}"),
                }
            }
        }
    }
}

async fn handle_conn(
    stream: TcpStream,
    peer: SocketAddr,
    admission: Admission,
    context: ConnectionContext,
) -> Result<()> {
    let ConnectionContext {
        hub,
        writers,
        writer_settlement_tx,
        registry_terminal,
        custodian_owner,
        fallback_reaper_tasks,
    } = context;
    let limits = hub.limits();
    let max_message_bytes = Limits::checked_usize(limits.max_message_bytes, "max_message_bytes")?;
    let max_frame_bytes = Limits::checked_usize(limits.max_frame_bytes, "max_frame_bytes")?;
    let max_handshake_bytes =
        Limits::checked_usize(limits.max_handshake_bytes, "max_handshake_bytes")?;
    let outbound_queue_cap =
        Limits::checked_usize(limits.outbound_queue_cap, "outbound_queue_cap")?;
    let registry_capacity = Limits::checked_usize(limits.max_connections, "max_connections")?;
    let ws_config = WebSocketConfig {
        max_message_size: Some(max_message_bytes),
        max_frame_size: Some(max_frame_bytes),
        write_buffer_size: 0,
        max_write_buffer_size: limits.checked_write_buffer_size()?,
        ..WebSocketConfig::default()
    };
    let handshake = tokio::time::timeout(
        limits.handshake_timeout(),
        accept_async_with_config(
            HandshakeLimitedStream::new(stream, max_handshake_bytes),
            Some(ws_config),
        ),
    )
    .await;
    let ws = match handshake {
        Ok(Ok(ws)) => ws,
        Ok(Err(e)) => {
            // A failed handshake means something reached us on the TCP
            // port but didn't complete a WebSocket upgrade. The most
            // common cause in a public deployment is a `wss://` (TLS)
            // client hitting this *plain-ws* listener with no TLS proxy
            // in front — the TLS ClientHello isn't valid HTTP, so the
            // upgrade fails here. (An HTTP health probe looks the same.)
            // Log it at `warn` so an operator debugging "peers never
            // connect" can see that traffic IS arriving but the handshake
            // is wrong, rather than staring at silence.
            warn!(%peer, "signaling: websocket handshake failed — a wss:// client on a plain-ws relay (no TLS proxy)?: {e}");
            return Ok(());
        }
        Err(_) => {
            warn!(%peer, "signaling: websocket handshake timed out");
            return Ok(());
        }
    };
    let (write, mut read) = ws.split();
    let (out_tx, mut out_rx) = mpsc::channel::<WsMessage>(outbound_queue_cap);
    let mut write = Some(write);

    let writer_slot_available = writer_registry_slot_available(&writers, registry_capacity);
    if !writer_slot_available {
        if let Some(mut write) = write.take() {
            let _ = write.close().await;
        }
        return Ok(());
    }
    let Some(conn_id) = admission.activate(out_tx.clone()) else {
        if let Some(mut write) = write.take() {
            let _ = write.close().await;
        }
        return Ok(());
    };
    let mut cleanup = ConnectionCleanup::new(hub.clone(), conn_id);
    cleanup.install_settlement_sender(writer_settlement_tx);

    // Writer task: drains the per-connection outbound queue to the
    // socket. The closed watch is the fence: queued frames are not drained
    // after the hub has revoked this connection's admission.
    let (closed_tx, mut closed_rx) = watch::channel(false);
    let writer_registered = {
        let mut owned_writers = writers.lock();
        if owned_writers.len() >= registry_capacity {
            false
        } else {
            let mut write = write.take().expect("writer slot was checked above");
            let writer = tokio::spawn(async move {
                #[cfg(test)]
                if TEST_PARK_NEXT_WRITER.swap(false, Ordering::AcqRel) {
                    // This is a one-shot production-path test witness: the
                    // real writer remains owned by the registry until the
                    // configured settlement timeout aborts and joins it.
                    TEST_WRITER_PARKED.store(true, Ordering::Release);
                    std::future::pending::<()>().await;
                }
                loop {
                    tokio::select! {
                        changed = closed_rx.changed() => {
                            if changed.is_err() || *closed_rx.borrow() {
                                break;
                            }
                        }
                        msg = out_rx.recv() => {
                            let Some(msg) = msg else { break };
                            if *closed_rx.borrow() {
                                break;
                            }
                            if write.send(msg).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = write.close().await;
            });
            owned_writers.insert(conn_id, Some(writer));
            true
        }
    };
    if !writer_registered {
        hub.unregister(conn_id);
        cleanup.disarm();
        if let Some(mut write) = write {
            let _ = write.close().await;
        }
        drop(out_tx);
        return Ok(());
    }
    cleanup.install_closed_signal(closed_tx.clone());

    #[cfg(test)]
    if TEST_PANIC_AFTER_WRITER.load(Ordering::Acquire) {
        // Give the just-published writer one poll so the parked-writer
        // witness is real before this injected terminal path drops cleanup.
        tokio::task::yield_now().await;
        if TEST_PANIC_AFTER_WRITER.swap(false, Ordering::AcqRel) {
            panic!("injected connection panic after writer registration");
        }
    }

    let mut shutdown = hub.shutdown_signal();
    if *shutdown.borrow() {
        let _ = closed_tx.send(true);
        settle_writer_with_progress(
            &writers,
            conn_id,
            limits.writer_stop_timeout(),
            Arc::clone(&registry_terminal),
            custodian_owner.as_ref(),
            &fallback_reaper_tasks,
        )
        .await;
        cleanup.unregister();
        drop(out_tx);
        cleanup.disarm();
        return Ok(());
    }
    loop {
        let frame = tokio::select! {
            frame = read.next() => frame,
            changed = shutdown.changed() => {
                if changed.is_ok() && *shutdown.borrow() {
                    break;
                }
                continue;
            }
        };
        let Some(frame) = frame else { break };
        match frame {
            // `on_client_message` returns false when the connection has
            // earned a disconnect (sustained rate-limit abuse).
            Ok(WsMessage::Text(txt)) => {
                if !hub.on_client_message(conn_id, &txt) {
                    break;
                }
            }
            // Keep long-lived idle connections alive — split streams
            // don't auto-pong, so we answer pings ourselves.
            Ok(WsMessage::Ping(p)) => {
                let _ = out_tx.try_send(WsMessage::Pong(p));
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    let _ = closed_tx.send(true);
    settle_writer_with_progress(
        &writers,
        conn_id,
        limits.writer_stop_timeout(),
        registry_terminal,
        custodian_owner.as_ref(),
        &fallback_reaper_tasks,
    )
    .await;
    cleanup.unregister();
    drop(out_tx);
    cleanup.disarm();
    Ok(())
}

async fn observe_completed_connection(
    conn_id: u64,
    tasks: &ConnectionRegistry,
    hub: &Hub,
    registry_terminal: Arc<RegistryTerminal>,
    timeout: Duration,
    custodian_owner: &dyn TaskCustodian,
    fallback_reaper_tasks: &Arc<FallbackReaperTasks>,
) -> bool {
    // Reserve external custody before removing the exact handler from the
    // registry. If this bound is exhausted, leave admission fail-closed and
    // let a later progress event retry observation without detaching a task.
    let mut custodian = match custodian_owner.reserve(1) {
        Ok(custodian) => custodian,
        Err(error) => {
            warn!(?error, conn_id, "connection terminal custodian exhausted");
            return false;
        }
    };
    let hub_idle_before_reap = hub.snapshot().connections == 0;
    let task = {
        let mut owned = tasks.lock();
        owned.remove(&conn_id)
    };
    let Some(task) = task else {
        trace!(
            conn_id,
            "signaling completion arrived for an unowned connection"
        );
        return true;
    };
    if hub_idle_before_reap {
        registry_terminal
            .hub_idle_before_reap
            .store(true, Ordering::Release);
    }
    // The accept loop may be aborted while this observation is pending. Keep
    // the exact child in a dedicated owner so cancellation cannot detach it.
    let (done_tx, done_rx) = tokio::sync::oneshot::channel();
    let reaper = tokio::spawn(async move {
        reap_connection_task(conn_id, task, timeout).await;
        publish_registry_progress(&registry_terminal);
        let _ = done_tx.send(());
    });
    match custodian.submit(reaper) {
        Ok(()) => {
            let _ = done_rx.await;
        }
        Err(reaper) => {
            warn!(
                conn_id,
                "connection terminal custodian refused reserved handle"
            );
            retain_or_overflow(fallback_reaper_tasks, reaper, "signaling connection reaper");
        }
    }
    true
}

async fn reap_connection_task(conn_id: u64, mut task: JoinHandle<()>, timeout: Duration) {
    match tokio::time::timeout(timeout, &mut task).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => {
            warn!(
                conn_id,
                "signaling connection task did not complete normally: {error}"
            );
        }
        Err(_) => {
            warn!(conn_id, "signaling connection task exceeded reaper timeout");
            task.abort();
            if let Err(error) = task.await {
                warn!(
                    conn_id,
                    "signaling connection task abort did not join normally: {error}"
                );
            }
        }
    }
}

fn publish_registry_progress(registry_terminal: &RegistryTerminal) {
    registry_terminal
        .progress
        .send_modify(|epoch| *epoch = epoch.checked_add(1).expect("registry progress exhausted"));
}

#[cfg(test)]
fn connection_registry_slot_available(tasks: &ConnectionRegistry, capacity: usize) -> bool {
    tasks.lock().len() < capacity
}

fn writer_registry_slot_available(tasks: &WriterRegistry, capacity: usize) -> bool {
    tasks.lock().len() < capacity
}

#[cfg(test)]
async fn settle_writer(writers: &WriterRegistry, conn_id: u64, timeout: Duration) {
    let owner = DedicatedTaskCustodian::new(1).expect("test custodian");
    let fallback = FallbackReaperTasks::new(1);
    let _ = settle_writer_observed(writers, conn_id, timeout, owner.as_ref(), &fallback).await;
}

async fn settle_writer_observed(
    writers: &WriterRegistry,
    conn_id: u64,
    timeout: Duration,
    custodian_owner: &dyn TaskCustodian,
    fallback_reaper_tasks: &Arc<FallbackReaperTasks>,
) -> std::result::Result<(), String> {
    settle_writer_inner(
        writers,
        conn_id,
        timeout,
        None,
        custodian_owner,
        fallback_reaper_tasks,
    )
    .await
}

async fn settle_writer_with_progress(
    writers: &WriterRegistry,
    conn_id: u64,
    timeout: Duration,
    registry_terminal: Arc<RegistryTerminal>,
    custodian_owner: &dyn TaskCustodian,
    fallback_reaper_tasks: &Arc<FallbackReaperTasks>,
) -> bool {
    settle_writer_inner(
        writers,
        conn_id,
        timeout,
        Some(registry_terminal),
        custodian_owner,
        fallback_reaper_tasks,
    )
    .await
    .is_ok()
}

async fn settle_writer_inner(
    writers: &WriterRegistry,
    conn_id: u64,
    timeout: Duration,
    registry_terminal: Option<Arc<RegistryTerminal>>,
    custodian_owner: &dyn TaskCustodian,
    fallback_reaper_tasks: &Arc<FallbackReaperTasks>,
) -> std::result::Result<(), String> {
    // Reserve cancellation-safe custody before extracting the placeholder.
    // If the external observer is exhausted, leave the exact writer in the
    // registry rather than creating a local reaper that a cancelled waiter
    // could detach.
    let needs_custody = writers
        .lock()
        .get(&conn_id)
        .and_then(Option::as_ref)
        .is_some();
    let mut custodian = if needs_custody {
        Some(
            custodian_owner
                .reserve(1)
                .map_err(|_| "writer terminal custodian exhausted".to_string())?,
        )
    } else {
        None
    };
    let writer = {
        let mut owned = writers.lock();
        owned.get_mut(&conn_id).and_then(Option::take)
    };
    if let Some(writer) = writer {
        let Some(custodian) = custodian.as_mut() else {
            writers.lock().insert(conn_id, Some(writer));
            return Err("writer terminal custodian was not reserved".into());
        };
        // Once the placeholder is extracted, this dedicated owner is the
        // cancellation-safe custody for the exact writer. If the accept or
        // stop waiter is cancelled, this task still joins the writer and
        // retires the same ID.
        let writers = Arc::clone(writers);
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let reaper = tokio::spawn(async move {
            let result = await_writer_with_timeout(writer, timeout).await;
            writers.lock().remove(&conn_id);
            if let Some(registry_terminal) = registry_terminal {
                publish_registry_progress(&registry_terminal);
            }
            let _ = done_tx.send(result);
        });
        match custodian.submit(reaper) {
            Ok(()) => match done_rx.await {
                Ok(result) => result?,
                Err(_) => return Err("writer terminal observer dropped".into()),
            },
            Err(reaper) => {
                warn!(conn_id, "writer terminal custodian refused reserved handle");
                retain_or_overflow(fallback_reaper_tasks, reaper, "signaling writer reaper");
            }
        }
    } else {
        writers.lock().remove(&conn_id);
    }
    Ok(())
}

#[cfg(test)]
async fn process_writer_settlement(
    receiver: &mut mpsc::Receiver<u64>,
    writers: &WriterRegistry,
    timeout: Duration,
) {
    let owner = DedicatedTaskCustodian::new(1).expect("test custodian");
    let fallback = FallbackReaperTasks::new(1);
    if let Some(conn_id) = receiver.recv().await {
        let _ = settle_writer_observed(writers, conn_id, timeout, owner.as_ref(), &fallback).await;
    }
}

fn notify_writer_settlement(sender: &WriterSettlementSender, conn_id: u64) -> bool {
    match sender.try_send(conn_id) {
        Ok(()) => true,
        Err(mpsc::error::TrySendError::Full(conn_id)) => {
            debug_assert!(false, "writer settlement queue full for conn_id={conn_id}");
            warn!(
                conn_id,
                "writer settlement queue full; cleanup requires owner attention"
            );
            false
        }
        Err(mpsc::error::TrySendError::Closed(conn_id)) => {
            trace!(conn_id, "writer settlement queue closed during shutdown");
            false
        }
    }
}

async fn await_writer_with_timeout(
    mut writer: JoinHandle<()>,
    timeout: Duration,
) -> std::result::Result<(), String> {
    match tokio::time::timeout(timeout, &mut writer).await {
        Ok(Ok(())) => Ok(()),
        Ok(Err(error)) => {
            warn!("signaling writer task did not complete normally: {error}");
            if error.is_cancelled() {
                Ok(())
            } else {
                Err(error.to_string())
            }
        }
        Err(_) => {
            writer.abort();
            if let Err(error) = writer.await {
                warn!("signaling writer task aborted during bounded shutdown: {error}");
            }
            Ok(())
        }
    }
}

struct ConnectionCleanup {
    hub: Hub,
    conn_id: u64,
    closed: Option<watch::Sender<bool>>,
    settlement: Option<WriterSettlementSender>,
    armed: bool,
}

impl ConnectionCleanup {
    fn new(hub: Hub, conn_id: u64) -> Self {
        Self {
            hub,
            conn_id,
            closed: None,
            settlement: None,
            armed: true,
        }
    }

    fn install_closed_signal(&mut self, closed: watch::Sender<bool>) {
        self.closed = Some(closed);
    }

    fn install_settlement_sender(&mut self, settlement: WriterSettlementSender) {
        self.settlement = Some(settlement);
    }

    fn unregister(&self) {
        self.hub.unregister(self.conn_id);
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for ConnectionCleanup {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        if let Some(closed) = &self.closed {
            let _ = closed.send(true);
        }
        self.hub.unregister(self.conn_id);
        if let Some(settlement) = &self.settlement {
            notify_writer_settlement(settlement, self.conn_id);
        }
    }
}

/// Shared relay state. Cheap to clone — wraps an `Arc<Mutex<…>>`. All the
/// real logic lives on [`HubInner`] so it runs under a single lock with
/// no re-entrancy.
/// Adapter that bounds the HTTP upgrade bytes before tungstenite parses the
/// request. It switches to transparent forwarding immediately after the
/// terminating CRLF pair, preserving any coalesced WebSocket bytes.
struct HandshakeLimitedStream {
    inner: TcpStream,
    max_bytes: usize,
    seen: usize,
    header_state: u8,
    complete: bool,
}

impl HandshakeLimitedStream {
    fn new(inner: TcpStream, max_bytes: usize) -> Self {
        Self {
            inner,
            max_bytes,
            seen: 0,
            header_state: 0,
            complete: false,
        }
    }

    fn observe(&mut self, bytes: &[u8]) {
        for byte in bytes {
            self.header_state = match (self.header_state, *byte) {
                (0, b'\r') => 1,
                (1, b'\n') => 2,
                (2, b'\r') => 3,
                (3, b'\n') => {
                    self.complete = true;
                    return;
                }
                (1, b'\r') => 1,
                _ => 0,
            };
        }
    }
}

impl AsyncRead for HandshakeLimitedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.complete {
            return Pin::new(&mut self.inner).poll_read(cx, buf);
        }
        if self.seen >= self.max_bytes {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "websocket handshake exceeds configured limit",
            )));
        }
        let amount = buf.remaining().min((self.max_bytes - self.seen).min(8192));
        if amount == 0 {
            return Poll::Ready(Ok(()));
        }
        let mut scratch = [0u8; 8192];
        let mut limited = ReadBuf::new(&mut scratch[..amount]);
        match Pin::new(&mut self.inner).poll_read(cx, &mut limited) {
            Poll::Ready(Ok(())) => {
                let bytes = limited.filled();
                let n = bytes.len();
                buf.put_slice(bytes);
                self.seen += n;
                self.observe(bytes);
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for HandshakeLimitedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[derive(Clone)]
struct Hub {
    inner: Arc<Mutex<HubInner>>,
    shutdown: watch::Sender<bool>,
}

/// A global/per-IP admission reservation held from TCP accept through the
/// WebSocket upgrade. Dropping it before activation releases both counters.
struct Admission {
    hub: Hub,
    id: u64,
    ip: IpAddr,
    active: bool,
}

impl Admission {
    fn activate(mut self, out: mpsc::Sender<WsMessage>) -> Option<u64> {
        let id = self.id;
        if self.hub.register(id, out, self.ip) {
            self.active = false;
            Some(id)
        } else {
            None
        }
    }
}

impl Drop for Admission {
    fn drop(&mut self) {
        if self.active {
            self.hub.release(self.id, self.ip);
        }
    }
}

struct HubInner {
    next_id: u64,
    conns: HashMap<u64, ConnEntry>,
    stored: VecDeque<StoredEvent>,
    /// room → device → live presence. The relay's view of who is
    /// connected right now, drives instant discovery + departure.
    presence: HashMap<String, HashMap<String, Presence>>,
    /// Concurrent connection count per source IP, for admission control.
    ip_counts: HashMap<IpAddr, u32>,
    /// Reservations held by handshakes plus registered connections.
    active_connections: u32,
    limits: Limits,
    /// Keypair used only to sign the relay's own synthesized `leave`
    /// events so they're well-formed for verifying peers.
    identity: NostrIdentity,
    /// Activity counters surfaced via [`Hub::snapshot`] (live connection
    /// count + room count are read directly from the maps).
    connections_total: u64,
    events_relayed: u64,
}

struct ConnEntry {
    out: OutboundSender,
    /// subscription id → its filter set (OR semantics across filters).
    subs: HashMap<String, Vec<Value>>,
    ip: IpAddr,
    /// `(room, device)` pairs this connection is the live presence owner
    /// of — used to emit departures when it closes. Its length is bounded by
    /// `HubInner::limits.max_presence_memberships`.
    present: Vec<(String, String)>,
    event_bucket: TokenBucket,
    req_bucket: TokenBucket,
    strikes: u32,
}

#[derive(Clone)]
struct OutboundSender(mpsc::Sender<WsMessage>);

impl OutboundSender {
    fn try_send(&self, message: WsMessage) -> std::result::Result<(), ()> {
        self.0.try_send(message).map_err(|_| ())
    }
}

struct StoredEvent {
    received_at: Instant,
    event: NostrEvent,
}

/// One live member, as the relay sees it: which connection owns it and
/// its latest announce (replayed verbatim for instant discovery).
struct Presence {
    conn_id: u64,
    announce: NostrEvent,
}

impl Hub {
    fn new(limits: Limits) -> Self {
        let (shutdown, _) = watch::channel(false);
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                next_id: 1,
                conns: HashMap::new(),
                stored: VecDeque::new(),
                presence: HashMap::new(),
                ip_counts: HashMap::new(),
                active_connections: 0,
                limits,
                identity: NostrIdentity::generate(),
                connections_total: 0,
                events_relayed: 0,
            })),
            shutdown,
        }
    }

    fn admit(&self, ip: IpAddr) -> Option<Admission> {
        let id = self.inner.lock().admit(ip)?;
        Some(Admission {
            hub: self.clone(),
            id,
            ip,
            active: true,
        })
    }

    fn limits(&self) -> Limits {
        self.inner.lock().limits.clone()
    }

    fn register(&self, id: u64, out: mpsc::Sender<WsMessage>, ip: IpAddr) -> bool {
        self.inner.lock().register(id, out, ip)
    }

    fn release(&self, id: u64, ip: IpAddr) {
        self.inner.lock().release(id, ip);
    }

    fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }

    fn shutdown_signal(&self) -> watch::Receiver<bool> {
        self.shutdown.subscribe()
    }

    fn unregister(&self, id: u64) {
        self.inner.lock().unregister(id);
    }

    fn on_client_message(&self, id: u64, txt: &str) -> bool {
        self.inner.lock().on_client_message(id, txt)
    }

    fn snapshot(&self) -> RelayStatsSnapshot {
        let g = self.inner.lock();
        RelayStatsSnapshot {
            connections: g.conns.len() as u64,
            connections_total: g.connections_total,
            rooms: g.presence.len() as u64,
            events_relayed: g.events_relayed,
        }
    }
}

impl HubInner {
    fn admit(&mut self, ip: IpAddr) -> Option<u64> {
        if self.active_connections >= self.limits.max_connections {
            return None;
        }
        let id = self.next_id;
        let next_id = id.checked_add(1)?;
        if self.limits.max_connections_per_ip > 0 {
            let n = self.ip_counts.get(&ip).copied().unwrap_or(0);
            if n >= self.limits.max_connections_per_ip {
                return None;
            }
        }
        *self.ip_counts.entry(ip).or_insert(0) += 1;
        self.next_id = next_id;
        self.active_connections += 1;
        self.connections_total += 1;
        Some(id)
    }

    fn register(&mut self, id: u64, out: mpsc::Sender<WsMessage>, ip: IpAddr) -> bool {
        if self.conns.contains_key(&id) {
            return false;
        }
        self.conns.insert(
            id,
            ConnEntry {
                out: OutboundSender(out),
                subs: HashMap::new(),
                ip,
                present: Vec::new(),
                event_bucket: TokenBucket::new(self.limits.max_event_rate),
                req_bucket: TokenBucket::new(self.limits.max_req_rate),
                strikes: 0,
            },
        );
        // Per-connection churn, not a daemon event: on a relay holding 20+
        // clients this fires constantly, and every reconnect writes a pair of
        // lines forever. The running total is what a healthy log wants, and
        // that's on the periodic summary — this stays available at debug.
        debug!(%ip, active = self.conns.len(), "signaling: client connected");
        true
    }

    fn release(&mut self, _id: u64, ip: IpAddr) {
        self.active_connections = self.active_connections.saturating_sub(1);
        if let Some(c) = self.ip_counts.get_mut(&ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.ip_counts.remove(&ip);
            }
        }
    }

    fn unregister(&mut self, id: u64) {
        let Some(entry) = self.conns.remove(&id) else {
            return;
        };
        self.active_connections = self.active_connections.saturating_sub(1);
        if let Some(c) = self.ip_counts.get_mut(&entry.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.ip_counts.remove(&entry.ip);
            }
        }
        debug!(ip = %entry.ip, active = self.conns.len(), "signaling: client disconnected");
        // Emit a departure for each device this connection was the live
        // owner of (skip any that a newer connection has since taken
        // over — presence holds only the latest owner per device).
        for (room, device) in &entry.present {
            let is_owner = self
                .presence
                .get(room)
                .and_then(|m| m.get(device))
                .map(|p| p.conn_id == id)
                .unwrap_or(false);
            if !is_owner {
                continue;
            }
            if let Some(m) = self.presence.get_mut(room) {
                m.remove(device);
                if m.is_empty() {
                    self.presence.remove(room);
                }
            }
            // Drop the departed peer's stored announces so a new
            // subscriber doesn't discover a ghost.
            self.stored.retain(|s| {
                presence_of(&s.event)
                    .map(|(r, d)| !(r == *room && d == *device))
                    .unwrap_or(true)
            });
            let leave = build_leave_event(&self.identity, room, device);
            let leave_value = serde_json::to_value(&leave).unwrap_or(Value::Null);
            fanout(&self.conns, &leave_value, &leave, None);
            trace!(%device, %room, "signaling: emitted leave");
        }
    }

    /// Returns false when the connection should be dropped.
    fn on_client_message(&mut self, conn_id: u64, txt: &str) -> bool {
        if self.limits.max_message_bytes > 0 && txt.len() as u32 > self.limits.max_message_bytes {
            return self.strike(conn_id);
        }
        let arr: Vec<Value> = match serde_json::from_str(txt) {
            Ok(a) => a,
            Err(e) => {
                trace!("signaling: undecodable client frame: {e}");
                return true;
            }
        };
        let Some(verb) = arr.first().and_then(|v| v.as_str()) else {
            return true;
        };
        match verb {
            "REQ" => {
                if !self.take_token(conn_id, true) {
                    return self.strike(conn_id);
                }
                self.handle_req(conn_id, &arr);
                true
            }
            "EVENT" => {
                if !self.take_token(conn_id, false) {
                    return self.strike(conn_id);
                }
                self.handle_event(conn_id, &arr);
                true
            }
            "CLOSE" => {
                self.handle_close(conn_id, &arr);
                true
            }
            other => {
                trace!("signaling: ignoring verb {other}");
                true
            }
        }
    }

    fn take_token(&mut self, conn_id: u64, is_req: bool) -> bool {
        match self.conns.get_mut(&conn_id) {
            Some(conn) => {
                let bucket = if is_req {
                    &mut conn.req_bucket
                } else {
                    &mut conn.event_bucket
                };
                bucket.allow()
            }
            None => false,
        }
    }

    fn strike(&mut self, conn_id: u64) -> bool {
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.strikes += 1;
            if conn.strikes > self.limits.strike_limit {
                let _ = conn.out.try_send(WsMessage::Text(
                    json!(["NOTICE", "rate limit exceeded — closing"]).to_string(),
                ));
                return false;
            }
        }
        true
    }

    /// `["REQ", subid, filter, …]` — register the subscription, then
    /// replay matching stored events *and* the live presence set
    /// (deduped), then `EOSE`.
    fn handle_req(&mut self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        let subid = subid.to_string();
        let filters = bounded_filters(
            arr.get(2..).unwrap_or_default(),
            Limits::checked_usize(self.limits.max_filters_per_req, "max_filters_per_req")
                .unwrap_or(usize::MAX),
        );

        // Retention is a live bound, not merely a bound applied when another
        // publisher happens to arrive. Reap expired stored material before
        // replay so an idle relay cannot hand out stale events or retain them
        // indefinitely between publishes.
        prune(
            &mut self.stored,
            Limits::checked_usize(self.limits.max_stored_events, "max_stored_events")
                .unwrap_or(usize::MAX),
            Duration::from_secs(self.limits.stored_retention_secs),
        );

        // Enforce the per-connection subscription ceiling for new ids.
        if self.limits.max_subscriptions > 0 {
            if let Some(conn) = self.conns.get(&conn_id) {
                if !conn.subs.contains_key(&subid)
                    && conn.subs.len()
                        >= Limits::checked_usize(self.limits.max_subscriptions, "max_subscriptions")
                            .unwrap_or(usize::MAX)
                {
                    if let Some(conn) = self.conns.get(&conn_id) {
                        let _ = conn.out.try_send(WsMessage::Text(
                            json!(["CLOSED", subid, "rate-limited: too many subscriptions"])
                                .to_string(),
                        ));
                    }
                    return;
                }
            }
        }

        // Candidate replay set: stored matches ∪ live-presence announces,
        // deduped by event id. Presence catches members whose announce
        // aged out of the store — that's the "instant discovery" win.
        let replay = bounded_replay(
            &filters,
            &self.stored,
            &self.presence,
            Limits::checked_usize(self.limits.max_replay_per_req, "max_replay_per_req")
                .unwrap_or(usize::MAX),
        );

        let Some(conn) = self.conns.get_mut(&conn_id) else {
            return;
        };
        conn.subs.insert(subid.clone(), filters);
        let out = conn.out.clone();
        let replayed = replay.len();
        for ev in replay {
            let ev_value = serde_json::to_value(&ev).unwrap_or(Value::Null);
            let _ = out.try_send(WsMessage::Text(
                json!(["EVENT", subid, ev_value]).to_string(),
            ));
        }
        let _ = out.try_send(WsMessage::Text(json!(["EOSE", subid]).to_string()));
        trace!(%subid, replayed, "signaling REQ");
    }

    /// `["EVENT", event]` — track presence, store if replayable, fan out
    /// to matching subscriptions, and `OK` the publisher.
    fn handle_event(&mut self, conn_id: u64, arr: &[Value]) {
        let Some(ev_val) = arr.get(1) else {
            return;
        };
        let event: NostrEvent = match serde_json::from_value(ev_val.clone()) {
            Ok(e) => e,
            Err(e) => {
                trace!("signaling: bad EVENT: {e}");
                return;
            }
        };

        // Authenticity: never store or fan out a forged event. The id must bind
        // the event's fields and the BIP-340 signature must be the pubkey's, so
        // a peer can't spoof another's presence (or a `leave`) through us. The
        // mesh's own ed25519 handshake remains the real peer auth on the
        // resulting WebRTC channel; this stops the relay being a
        // discovery-injection vector. Every legitimate client event is built by
        // `make_event`, so this only rejects malformed or forged traffic.
        if !event.verify() {
            trace!("signaling: dropping EVENT with bad id/signature");
            if let Some(conn) = self.conns.get(&conn_id) {
                let _ = conn.out.try_send(WsMessage::Text(
                    json!(["OK", event.id, false, "invalid: bad signature"]).to_string(),
                ));
            }
            return;
        }
        // Live presence: an announce makes this connection the owner of
        // (room, device). Best-effort — only well-formed mesh announces
        // parse; generic NIP-01 traffic is ignored here.
        let presence = presence_of(&event);
        if let Some((room, device)) = &presence {
            let already_owned = self
                .conns
                .get(&conn_id)
                .map(|conn| conn.present.iter().any(|(r, d)| r == room && d == device))
                .unwrap_or(false);
            let over_cap = !already_owned
                && self
                    .conns
                    .get(&conn_id)
                    .map(|conn| {
                        conn.present.len()
                            >= Limits::checked_usize(
                                self.limits.max_presence_memberships,
                                "max_presence_memberships",
                            )
                            .unwrap_or(usize::MAX)
                    })
                    .unwrap_or(false);
            if over_cap {
                if let Some(conn) = self.conns.get(&conn_id) {
                    let _ = conn.out.try_send(WsMessage::Text(
                        json!([
                            "OK",
                            event.id,
                            false,
                            "rate-limited: too many live presence memberships"
                        ])
                        .to_string(),
                    ));
                }
                trace!(%room, %device, "signaling presence membership refused at per-connection limit");
                return;
            }
        }
        self.events_relayed = self.events_relayed.saturating_add(1);

        if let Some((room, device)) = presence {
            self.presence.entry(room.clone()).or_default().insert(
                device.clone(),
                Presence {
                    conn_id,
                    announce: event.clone(),
                },
            );
            if let Some(conn) = self.conns.get_mut(&conn_id) {
                if !conn.present.iter().any(|(r, d)| r == &room && d == &device) {
                    conn.present.push((room, device));
                }
            }
        }

        if is_stored_kind(event.kind) {
            self.stored.push_back(StoredEvent {
                received_at: Instant::now(),
                event: event.clone(),
            });
            prune(
                &mut self.stored,
                Limits::checked_usize(self.limits.max_stored_events, "max_stored_events")
                    .unwrap_or(usize::MAX),
                Duration::from_secs(self.limits.stored_retention_secs),
            );
        }

        let delivered = fanout(&self.conns, ev_val, &event, None);
        if let Some(conn) = self.conns.get(&conn_id) {
            let _ = conn.out.try_send(WsMessage::Text(
                json!(["OK", event.id, true, ""]).to_string(),
            ));
        }
        trace!(kind = event.kind, delivered, "signaling EVENT");
    }

    /// `["CLOSE", subid]` — drop the subscription.
    fn handle_close(&mut self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.subs.remove(subid);
        }
    }
}

fn bounded_filters(filters: &[Value], max: usize) -> Vec<Value> {
    filters.iter().take(max).cloned().collect()
}

/// Scan the replay sources while keeping both the retained event payload and
/// deduplication working sets at the configured bound.
fn bounded_replay(
    filters: &[Value],
    stored: &VecDeque<StoredEvent>,
    presence: &HashMap<String, HashMap<String, Presence>>,
    max: usize,
) -> VecDeque<NostrEvent> {
    let mut replay = VecDeque::new();
    let mut seen: HashSet<String> = HashSet::new();
    if max == 0 {
        return replay;
    }
    let mut consider = |event: &NostrEvent| {
        if matches_any(filters, event) && seen.insert(event.id.clone()) {
            replay.push_back(event.clone());
            if replay.len() > max {
                if let Some(evicted) = replay.pop_front() {
                    seen.remove(&evicted.id);
                }
            }
        }
    };
    for stored in stored {
        consider(&stored.event);
    }
    for room in presence.values() {
        for member in room.values() {
            consider(&member.announce);
        }
    }
    replay
}

/// Fan an event out to every matching subscription on every connection
/// (optionally skipping one). Returns the number of frames delivered.
fn fanout(
    conns: &HashMap<u64, ConnEntry>,
    ev_value: &Value,
    ev: &NostrEvent,
    skip: Option<u64>,
) -> usize {
    let mut delivered = 0usize;
    for (id, conn) in conns {
        if Some(*id) == skip {
            continue;
        }
        for (subid, filters) in &conn.subs {
            if matches_any(filters, ev) {
                let frame = json!(["EVENT", subid, ev_value]).to_string();
                if conn.out.try_send(WsMessage::Text(frame)).is_ok() {
                    delivered += 1;
                }
            }
        }
    }
    delivered
}

/// Extract `(room, device)` from an event if it's a well-formed mesh
/// presence announce: kind 1077, an `r` tag, and a content envelope
/// whose `kind` is `announce` carrying `from`. Returns `None` for
/// anything else (generic NIP-01 traffic, negotiation frames, etc.).
fn presence_of(ev: &NostrEvent) -> Option<(String, String)> {
    if ev.kind != SIGNALING_EVENT_KIND {
        return None;
    }
    let room = ev
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "r")
        .map(|t| t[1].clone())?;
    let content: Value = serde_json::from_str(&ev.content).ok()?;
    if content.get("kind").and_then(|k| k.as_str()) != Some("announce") {
        return None;
    }
    let from = content.get("from")?.as_str()?.to_string();
    Some((room, from))
}

/// Build a signed `leave` event for a departed device in a room. Mirrors
/// the envelope shape the driver expects: `{from, kind:"leave", peer_id}`
/// on the ephemeral kind. Tagged `["p", room]` — broadcast ephemerals are
/// "addressed to the room" — so drivers whose subscription has narrowed
/// to recipient-tagged events (see the driver's `desired_filters`) still
/// hear the departure.
fn build_leave_event(identity: &NostrIdentity, room: &str, device: &str) -> NostrEvent {
    let envelope = json!({ "from": device, "kind": "leave", "peer_id": device });
    make_event(
        identity,
        SIGNALING_EPHEMERAL_KIND,
        vec![
            vec!["r".to_string(), room.to_string()],
            vec!["p".to_string(), room.to_string()],
        ],
        envelope.to_string(),
        now_secs(),
    )
}

/// Token bucket for per-connection rate limiting. A `rate` of 0 disables
/// the limit (always allows).
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let capacity = rate.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: rate as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        if self.refill_per_sec <= 0.0 {
            return true; // unlimited
        }
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// True when *any* filter in the set matches (NIP-01 OR semantics). An
/// empty filter set, or a `REQ` with no filters at all, matches
/// everything.
fn matches_any(filters: &[Value], ev: &NostrEvent) -> bool {
    filters.is_empty() || filters.iter().any(|f| filter_matches(f, ev))
}

/// Match one NIP-01 filter object against an event. Every present
/// constraint must hold (AND within a filter); unknown keys are ignored.
fn filter_matches(filter: &Value, ev: &NostrEvent) -> bool {
    let Some(obj) = filter.as_object() else {
        return false;
    };
    for (key, val) in obj {
        match key.as_str() {
            "ids" => {
                if !str_list_contains(val, &ev.id) {
                    return false;
                }
            }
            "authors" => {
                if !str_list_contains(val, &ev.pubkey) {
                    return false;
                }
            }
            "kinds" => {
                let ok = val
                    .as_array()
                    .map(|a| a.iter().any(|k| k.as_u64() == Some(ev.kind as u64)))
                    .unwrap_or(false);
                if !ok {
                    return false;
                }
            }
            "since" => {
                if let Some(s) = val.as_u64() {
                    if ev.created_at < s {
                        return false;
                    }
                }
            }
            "until" => {
                if let Some(u) = val.as_u64() {
                    if ev.created_at > u {
                        return false;
                    }
                }
            }
            "limit" => {}
            tag if tag.len() == 2 && tag.starts_with('#') => {
                let letter = &tag[1..];
                let ok = ev
                    .tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == letter && str_list_contains(val, &t[1]));
                if !ok {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn str_list_contains(val: &Value, needle: &str) -> bool {
    val.as_array()
        .map(|a| a.iter().any(|x| x.as_str() == Some(needle)))
        .unwrap_or(false)
}

/// NIP-01: ephemeral events (`20000..=29999`) are never stored; every
/// other kind is replayable.
fn is_stored_kind(kind: u16) -> bool {
    !(20000..=29999).contains(&kind)
}

fn prune(stored: &mut VecDeque<StoredEvent>, max_stored_events: usize, retention: Duration) {
    let now = Instant::now();
    while let Some(front) = stored.front() {
        if now.duration_since(front.received_at) > retention {
            stored.pop_front();
        } else {
            break;
        }
    }
    while stored.len() > max_stored_events {
        stored.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio_tungstenite::connect_async;

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

    struct DropFlag(Arc<AtomicBool>);

    impl Drop for DropFlag {
        fn drop(&mut self) {
            self.0.store(true, Ordering::Release);
        }
    }

    struct TestGateReset;

    impl Drop for TestGateReset {
        fn drop(&mut self) {
            TEST_PARK_NEXT_WRITER.store(false, Ordering::Release);
            TEST_WRITER_PARKED.store(false, Ordering::Release);
            TEST_PANIC_AFTER_WRITER.store(false, Ordering::Release);
        }
    }

    fn ev(kind: u16, room: &str, created_at: u64) -> NostrEvent {
        NostrEvent {
            id: format!("id-{kind}-{created_at}"),
            pubkey: "pk".into(),
            created_at,
            kind,
            tags: vec![vec!["r".into(), room.into()]],
            content: "{}".into(),
            sig: "sig".into(),
        }
    }

    fn announce(identity: &NostrIdentity, room: &str, device: &str, created_at: u64) -> NostrEvent {
        make_event(
            identity,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), room.into()]],
            json!({ "from": device, "kind": "announce", "peer_id": device }).to_string(),
            created_at,
        )
    }

    fn test_connection(hub: &Hub, ip: &str) -> (u64, mpsc::Receiver<WsMessage>) {
        let admission = hub.admit(ip.parse().unwrap()).unwrap();
        let (out, input) = mpsc::channel(32);
        let id = admission.activate(out).unwrap();
        (id, input)
    }

    async fn start_test_server(
        bind: &str,
        port: u16,
        limits: Limits,
    ) -> Result<SignalingServerHandle> {
        let capacity = SignalingServer::required_task_custody_slots(&limits)?;
        let owner = DedicatedTaskCustodian::new(capacity)
            .map_err(|error| Error::Other(format!("test custodian: {error:?}")))?;
        SignalingServer::start_with_custodian(bind, port, limits, owner).await
    }

    fn send_event(hub: &Hub, conn_id: u64, event: &NostrEvent) -> bool {
        let frame = serde_json::to_string(&json!(["EVENT", event])).unwrap();
        hub.inner.lock().on_client_message(conn_id, &frame)
    }

    #[test]
    fn kind_storage_split_matches_nip01() {
        assert!(is_stored_kind(1077));
        assert!(!is_stored_kind(21077));
        assert!(is_stored_kind(0));
        assert!(!is_stored_kind(20000));
        assert!(!is_stored_kind(29999));
        assert!(is_stored_kind(30000));
    }

    #[test]
    fn filter_matches_room_and_kind() {
        let e = ev(1077, "room-a", 1000);
        let f = json!({ "kinds": [1077, 21077], "#r": ["room-a"] });
        assert!(filter_matches(&f, &e));
        assert!(!filter_matches(&json!({ "#r": ["room-b"] }), &e));
        assert!(!filter_matches(&json!({ "kinds": [9999] }), &e));
    }

    #[test]
    fn filter_since_until() {
        let e = ev(1077, "r", 1000);
        assert!(filter_matches(&json!({ "since": 999 }), &e));
        assert!(filter_matches(&json!({ "since": 1000 }), &e));
        assert!(!filter_matches(&json!({ "since": 1001 }), &e));
        assert!(filter_matches(&json!({ "until": 1000 }), &e));
        assert!(!filter_matches(&json!({ "until": 999 }), &e));
    }

    #[test]
    fn empty_filter_matches_everything() {
        let e = ev(1077, "r", 1000);
        assert!(matches_any(&[], &e));
        assert!(matches_any(&[json!({})], &e));
    }

    #[test]
    fn unknown_filter_keys_ignored() {
        let e = ev(1077, "r", 1000);
        assert!(filter_matches(&json!({ "futurefield": ["x"] }), &e));
    }

    #[test]
    fn presence_extracted_only_from_real_announces() {
        // A real mesh announce: kind 1077, r tag, content envelope.
        let mut a = ev(1077, "room-a", 1000);
        a.content = json!({ "from": "devA", "kind": "announce", "peer_id": "devA" }).to_string();
        assert_eq!(presence_of(&a), Some(("room-a".into(), "devA".into())));

        // Negotiation traffic (ephemeral kind) is not presence.
        let mut o = ev(21077, "room-a", 1000);
        o.content = json!({ "from": "devA", "kind": "offer", "peer_id": "devA" }).to_string();
        assert_eq!(presence_of(&o), None);

        // A simplified event with non-envelope content is not presence.
        assert_eq!(presence_of(&ev(1077, "room-a", 1000)), None);
    }

    #[test]
    fn token_bucket_zero_is_unlimited() {
        // TokenBucket's internal zero behavior is retained for its local
        // arithmetic contract; public Limits rejects zero before startup.
        let mut b = TokenBucket::new(0);
        for _ in 0..1000 {
            assert!(b.allow());
        }
    }

    #[test]
    fn limits_reject_every_unlimited_field() {
        let mut cases = Vec::new();
        let limits = Limits {
            max_connections: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_event_rate: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_req_rate: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_subscriptions: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_filters_per_req: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_message_bytes: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_connections_per_ip: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_presence_memberships: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_handshake_bytes: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_frame_bytes: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_stored_events: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            stored_retention_secs: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            stats_heartbeat_interval_secs: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            max_replay_per_req: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            outbound_queue_cap: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            strike_limit: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            handshake_timeout_secs: 0,
            ..Limits::default()
        };
        cases.push(limits);
        let limits = Limits {
            writer_stop_timeout_secs: 0,
            ..Limits::default()
        };
        cases.push(limits);
        assert!(cases.into_iter().all(|limits| limits.validate().is_err()));
        assert!(Limits::default().validate().is_ok());
    }

    #[test]
    fn activity_heartbeat_uses_its_configured_horizon() {
        let limits = Limits {
            stored_retention_secs: 7,
            stats_heartbeat_interval_secs: 11,
            ..Limits::default()
        };
        assert_eq!(
            limits.stats_heartbeat_interval(),
            Duration::from_secs(11),
            "heartbeat cadence must remain independent from retention"
        );
    }

    #[test]
    fn configured_transient_limits_bound_filter_and_replay_materialization() {
        let filters = vec![json!({}), json!({"kinds": [1]}), json!({"kinds": [2]})];
        assert_eq!(bounded_filters(&filters, 2).len(), 2);

        let mut stored = VecDeque::new();
        for created_at in 1..=4 {
            stored.push_back(StoredEvent {
                received_at: Instant::now(),
                event: ev(1, "room", created_at),
            });
        }
        let limits = Limits {
            max_replay_per_req: 2,
            ..Limits::default()
        };
        let replay = bounded_replay(
            &[],
            &stored,
            &HashMap::new(),
            Limits::checked_usize(limits.max_replay_per_req, "max_replay_per_req").unwrap(),
        );
        assert_eq!(replay.len(), 2);
        assert_eq!(
            replay
                .iter()
                .map(|event| event.created_at)
                .collect::<Vec<_>>(),
            vec![3, 4]
        );
    }

    #[test]
    fn malformed_client_frame_preserves_bounded_relay_state() {
        let hub = Hub::new(Limits::default());
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let before = hub.inner.lock();
        let stored = before.stored.len();
        let presence = before.presence.len();
        let events_relayed = before.events_relayed;
        drop(before);

        assert!(hub.inner.lock().on_client_message(conn_id, "[not-json"));

        let after = hub.inner.lock();
        assert_eq!(after.stored.len(), stored);
        assert_eq!(after.presence.len(), presence);
        assert_eq!(after.events_relayed, events_relayed);
        assert!(after.conns.contains_key(&conn_id));
    }

    #[test]
    fn configured_admission_refusal_does_not_mutate_counters() {
        let hub = Hub::new(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let first = hub.admit("127.0.0.1".parse().unwrap()).unwrap();
        let before = hub.inner.lock();
        let next_id = before.next_id;
        let active_connections = before.active_connections;
        let connections_total = before.connections_total;
        let ip_counts = before.ip_counts.clone();
        drop(before);

        assert!(hub.admit("127.0.0.2".parse().unwrap()).is_none());
        let after = hub.inner.lock();
        assert_eq!(after.next_id, next_id);
        assert_eq!(after.active_connections, active_connections);
        assert_eq!(after.connections_total, connections_total);
        assert_eq!(after.ip_counts, ip_counts);
        drop(after);
        drop(first);
    }

    #[test]
    fn configured_storage_limit_and_retention_are_applied() {
        let limits = Limits {
            max_stored_events: 2,
            stored_retention_secs: 1,
            ..Limits::default()
        };
        let mut stored = VecDeque::new();
        stored.push_back(StoredEvent {
            received_at: Instant::now() - Duration::from_secs(2),
            event: ev(1, "room", 1),
        });
        stored.push_back(StoredEvent {
            received_at: Instant::now(),
            event: ev(1, "room", 2),
        });
        stored.push_back(StoredEvent {
            received_at: Instant::now(),
            event: ev(1, "room", 3),
        });

        prune(
            &mut stored,
            Limits::checked_usize(limits.max_stored_events, "max_stored_events").unwrap(),
            Duration::from_secs(limits.stored_retention_secs),
        );
        assert_eq!(stored.len(), 2);
        assert_eq!(stored.front().unwrap().event.created_at, 2);
    }

    #[test]
    fn replay_request_reaps_expired_storage_before_materialization() {
        let hub = Hub::new(Limits {
            stored_retention_secs: 1,
            ..Limits::default()
        });
        let (conn_id, mut input) = test_connection(&hub, "127.0.0.1");
        hub.inner.lock().stored.push_back(StoredEvent {
            received_at: Instant::now() - Duration::from_secs(2),
            event: ev(1, "idle-room", 1),
        });

        let request = serde_json::to_string(&json!(["REQ", "idle", {"kinds": [1]}])).unwrap();
        assert!(hub.inner.lock().on_client_message(conn_id, &request));

        let mut replayed = false;
        while let Ok(message) = input.try_recv() {
            if let WsMessage::Text(text) = message {
                replayed |= text.to_string().contains("EVENT");
            }
        }
        assert!(
            !replayed,
            "expired material must not be replayed after an idle interval"
        );
        assert!(hub.inner.lock().stored.is_empty());
    }

    #[test]
    fn configured_queue_and_timeout_limits_are_consumed() {
        let limits = Limits {
            outbound_queue_cap: 2,
            handshake_timeout_secs: 11,
            writer_stop_timeout_secs: 3,
            ..Limits::default()
        };
        limits.validate().unwrap();
        assert_eq!(limits.handshake_timeout(), Duration::from_secs(11));
        assert_eq!(limits.writer_stop_timeout(), Duration::from_secs(3));

        let capacity =
            Limits::checked_usize(limits.outbound_queue_cap, "outbound_queue_cap").unwrap();
        let (sender, mut receiver) = mpsc::channel(capacity);
        assert!(sender.try_send(WsMessage::Text("one".into())).is_ok());
        assert!(sender.try_send(WsMessage::Text("two".into())).is_ok());
        assert!(sender.try_send(WsMessage::Text("three".into())).is_err());
        assert!(receiver.try_recv().is_ok());
    }

    #[test]
    fn configured_strike_limit_refuses_after_threshold() {
        let hub = Hub::new(Limits {
            strike_limit: 1,
            ..Limits::default()
        });
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let mut inner = hub.inner.lock();
        assert!(inner.strike(conn_id));
        assert!(!inner.strike(conn_id));
        drop(inner);
        hub.unregister(conn_id);
    }

    #[tokio::test]
    async fn dropping_handle_aborts_tasks_and_releases_observer_state() {
        let hub = Hub::new(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let observer = hub.clone();
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let identity = NostrIdentity::generate();
        assert!(send_event(
            &hub,
            conn_id,
            &announce(&identity, "room", "device", 1)
        ));

        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let connection_task = tokio::spawn({
            let hub = hub.clone();
            async move {
                let _cleanup = ConnectionCleanup::new(hub, conn_id);
                armed_tx
                    .send(())
                    .expect("cleanup task start receiver must remain live");
                std::future::pending::<()>().await;
            }
        });
        let connections = Arc::new(Mutex::new(HashMap::from([(conn_id, connection_task)])));
        armed_rx.await.expect("cleanup task must arm before drop");
        let fallback_reaper_tasks = FallbackReaperTasks::new(5);
        let (task_reaper, task_reaper_handle) =
            spawn_task_reaper(4, Arc::clone(&fallback_reaper_tasks));
        let custodian_owner = DedicatedTaskCustodian::new(1).expect("test custodian");
        let custodian = custodian_owner
            .reserve(1)
            .expect("the external custodian must reserve the final reaper");
        let handle = SignalingServerHandle {
            task: None,
            heartbeat: None,
            connections,
            writers: Arc::new(Mutex::new(HashMap::new())),
            registry_terminal: Arc::new(RegistryTerminal::new()),
            task_reaper: Mutex::new(Some(task_reaper)),
            task_reaper_handle: Mutex::new(Some(task_reaper_handle)),
            custodian_owner,
            custodian: Some(custodian),
            fallback_reaper_tasks,
            writer_stop_timeout: Duration::from_secs(2),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            hub,
        };
        drop(handle);

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                let released = {
                    let state = observer.inner.lock();
                    state.active_connections == 0
                        && state.conns.is_empty()
                        && state.presence.is_empty()
                        && state.ip_counts.is_empty()
                };
                if released {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("dropping the server handle must release connection state");
    }

    #[tokio::test]
    async fn dropping_handle_during_connection_reap_keeps_child_owned() {
        let hub = Hub::new(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let observer = hub.clone();
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_in_child = Arc::clone(&dropped);
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let child = tokio::spawn({
            let hub = hub.clone();
            async move {
                let _cleanup = ConnectionCleanup::new(hub, conn_id);
                let _drop_flag = DropFlag(dropped_in_child);
                armed_tx.send(()).expect("child must arm before completion");
                std::future::pending::<()>().await;
            }
        });
        let connections = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        connections.lock().insert(conn_id, child);
        armed_rx.await.expect("child must arm before completion");

        let writers = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        let registry_terminal = Arc::new(RegistryTerminal::new());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (completion_tx, completion_rx) = mpsc::channel(1);
        let (settlement_tx, settlement_rx) = mpsc::channel(1);
        let accept_task = tokio::spawn(accept_loop(
            listener,
            AcceptLoopContext {
                hub: hub.clone(),
                connections: Arc::clone(&connections),
                writers: Arc::clone(&writers),
                registry_terminal: Arc::clone(&registry_terminal),
                registry_capacity: 1,
                completion_rx,
                writer_settlement_rx: settlement_rx,
                completion_tx: completion_tx.clone(),
                writer_settlement_tx: settlement_tx,
                writer_stop_timeout: Duration::from_secs(2),
                custodian_owner: DedicatedTaskCustodian::new(1).expect("test custodian"),
                fallback_reaper_tasks: FallbackReaperTasks::new(2),
            },
        ));
        let mut progress = registry_terminal.progress.subscribe();
        let progress_before_drop = *progress.borrow();
        completion_tx
            .send(conn_id)
            .await
            .expect("completion must reach accept loop");
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if connections.lock().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("completion must extract the exact child before drop");
        tokio::task::yield_now().await;

        let fallback_reaper_tasks = FallbackReaperTasks::new(5);
        let (task_reaper, task_reaper_handle) =
            spawn_task_reaper(4, Arc::clone(&fallback_reaper_tasks));
        let handle = SignalingServerHandle {
            task: Some(accept_task),
            heartbeat: None,
            connections: Arc::clone(&connections),
            writers: Arc::clone(&writers),
            registry_terminal: Arc::clone(&registry_terminal),
            task_reaper: Mutex::new(Some(task_reaper)),
            task_reaper_handle: Mutex::new(Some(task_reaper_handle)),
            custodian_owner: DedicatedTaskCustodian::new(1).expect("test custodian"),
            custodian: None,
            fallback_reaper_tasks,
            writer_stop_timeout: Duration::from_secs(2),
            local_addr: "127.0.0.1:0".parse().unwrap(),
            hub,
        };
        drop(handle);

        tokio::time::timeout(Duration::from_secs(4), progress.changed())
            .await
            .expect("connection reaper must publish terminal progress after Drop")
            .expect("connection reaper progress sender must remain live");
        assert!(*progress.borrow() > progress_before_drop);
        assert!(dropped.load(Ordering::Acquire));
        assert!(connections.lock().is_empty());
        assert!(writers.lock().is_empty());
        let state = observer.inner.lock();
        assert_eq!(state.active_connections, 0);
        assert!(state.conns.is_empty());
        assert!(state.presence.is_empty());
        assert!(state.ip_counts.is_empty());
    }

    #[tokio::test]
    async fn registry_pressure_refuses_before_spawning_an_unowned_task() {
        let tasks = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        tasks
            .lock()
            .insert(1, tokio::spawn(std::future::pending::<()>()));
        assert!(!connection_registry_slot_available(&tasks, 1));
        assert_eq!(tasks.lock().len(), 1);

        let task = tasks.lock().remove(&1).unwrap();
        task.abort();
        assert!(
            task.await.is_err(),
            "aborted registry task must be observed"
        );
    }

    #[tokio::test]
    async fn finished_handler_and_writer_panics_are_reaped_and_observed() {
        let hub = Hub::new(Limits::default());
        let registry_terminal = Arc::new(RegistryTerminal::new());
        let connections = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        let writers = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        let (settlement_tx, mut settlement_rx) = mpsc::channel(1);
        connections
            .lock()
            .insert(1, tokio::spawn(async { panic!("injected handler panic") }));
        writers.lock().insert(
            1,
            Some(tokio::spawn(async { panic!("injected writer panic") })),
        );
        tokio::task::yield_now().await;
        let custodian_owner = DedicatedTaskCustodian::new(1).expect("test custodian");

        observe_completed_connection(
            1,
            &connections,
            &hub,
            Arc::clone(&registry_terminal),
            Duration::from_secs(2),
            custodian_owner.as_ref(),
            &FallbackReaperTasks::new(2),
        )
        .await;
        settlement_tx.send(1).await.unwrap();
        process_writer_settlement(&mut settlement_rx, &writers, Duration::from_secs(2)).await;
        assert!(connections.lock().is_empty());
        assert!(writers.lock().is_empty());
    }

    #[test]
    fn presence_cap_refuses_only_new_membership_and_duplicate_is_idempotent() {
        let hub = Hub::new(Limits {
            max_presence_memberships: 1,
            ..Limits::default()
        });
        let (first_id, mut first_input) = test_connection(&hub, "127.0.0.1");
        let (second_id, _second_input) = test_connection(&hub, "127.0.0.2");
        let identity = NostrIdentity::generate();
        let first = announce(&identity, "room-a", "device-a", 1);
        let duplicate = announce(&identity, "room-a", "device-a", 2);
        let second = announce(&identity, "room-b", "device-b", 3);

        assert!(send_event(&hub, first_id, &first));
        assert!(send_event(&hub, first_id, &duplicate));
        assert!(send_event(&hub, first_id, &second));

        let mut refused = false;
        while let Ok(message) = first_input.try_recv() {
            if let WsMessage::Text(text) = message {
                let text = text.to_string();
                if text.contains(&second.id) && text.contains("false") {
                    refused = true;
                }
            }
        }
        assert!(refused, "the exact over-cap presence event must be refused");

        let inner = hub.inner.lock();
        assert_eq!(inner.conns[&first_id].present.len(), 1);
        assert_eq!(inner.presence["room-a"]["device-a"].conn_id, first_id);
        assert!(!inner.presence.contains_key("room-b"));
        assert!(inner.conns.contains_key(&second_id));
    }

    #[test]
    fn presence_cap_is_released_after_disconnect() {
        let hub = Hub::new(Limits {
            max_presence_memberships: 1,
            ..Limits::default()
        });
        let (first_id, _first_input) = test_connection(&hub, "127.0.0.1");
        let identity = NostrIdentity::generate();
        let first = announce(&identity, "room-a", "device-a", 1);
        assert!(send_event(&hub, first_id, &first));

        hub.unregister(first_id);
        assert!(hub.inner.lock().presence.is_empty());

        let (second_id, _second_input) = test_connection(&hub, "127.0.0.2");
        let second = announce(&identity, "room-b", "device-b", 2);
        assert!(send_event(&hub, second_id, &second));
        let inner = hub.inner.lock();
        assert_eq!(inner.conns[&second_id].present.len(), 1);
        assert_eq!(inner.presence["room-b"]["device-b"].conn_id, second_id);
    }

    #[test]
    fn connection_id_exhaustion_refuses_without_admission() {
        let hub = Hub::new(Limits::default());
        hub.inner.lock().next_id = u64::MAX;

        assert!(hub.admit("127.0.0.1".parse().unwrap()).is_none());
        let inner = hub.inner.lock();
        assert_eq!(inner.next_id, u64::MAX);
        assert_eq!(inner.active_connections, 0);
        assert_eq!(inner.connections_total, 0);
        assert!(inner.ip_counts.is_empty());
    }

    #[test]
    fn token_bucket_limits_burst() {
        // Capacity == rate, so the first `rate` calls pass and the next
        // is denied (no time elapsed to refill).
        let mut b = TokenBucket::new(5);
        let mut passed = 0;
        for _ in 0..20 {
            if b.allow() {
                passed += 1;
            }
        }
        assert_eq!(passed, 5);
    }

    #[test]
    fn build_leave_event_is_parseable_envelope() {
        let id = NostrIdentity::generate();
        let leave = build_leave_event(&id, "room-a", "devA");
        assert_eq!(leave.kind, SIGNALING_EPHEMERAL_KIND);
        let content: Value = serde_json::from_str(&leave.content).unwrap();
        assert_eq!(content["kind"], "leave");
        assert_eq!(content["peer_id"], "devA");
        assert_eq!(content["from"], "devA");
        assert!(leave
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "r" && t[1] == "room-a"));
        assert!(
            leave
                .tags
                .iter()
                .any(|t| t.len() >= 2 && t[0] == "p" && t[1] == "room-a"),
            "synthesized leave is room-addressed so narrowed subscriptions match it"
        );
    }

    #[tokio::test]
    async fn connection_cleanup_observes_normal_writer_completion() {
        let hub = Hub::new(Limits::default());
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let writers = Arc::new(Mutex::new(HashMap::new()));
        let completed = Arc::new(AtomicBool::new(false));
        let completed_in_writer = Arc::clone(&completed);
        let mut cleanup = ConnectionCleanup::new(hub.clone(), conn_id);
        writers.lock().insert(
            conn_id,
            Some(tokio::spawn(async move {
                completed_in_writer.store(true, Ordering::Release);
            })),
        );

        cleanup.unregister();
        cleanup.install_closed_signal(watch::channel(false).0);
        cleanup.disarm();
        settle_writer(&writers, conn_id, Duration::from_secs(2)).await;

        assert!(completed.load(Ordering::Acquire));
        assert_eq!(hub.snapshot().connections, 0);
    }

    #[tokio::test]
    async fn connection_cleanup_aborts_writer_on_bounded_timeout() {
        let hub = Hub::new(Limits::default());
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let writers = Arc::new(Mutex::new(HashMap::new()));
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_in_writer = Arc::clone(&dropped);
        let mut cleanup = ConnectionCleanup::new(hub.clone(), conn_id);
        writers.lock().insert(
            conn_id,
            Some(tokio::spawn(async move {
                let _drop_flag = DropFlag(dropped_in_writer);
                std::future::pending::<()>().await;
            })),
        );

        cleanup.unregister();
        cleanup.install_closed_signal(watch::channel(false).0);
        cleanup.disarm();
        let writer = writers
            .lock()
            .get_mut(&conn_id)
            .and_then(Option::take)
            .expect("writer remains owned until timeout settlement");
        assert!(
            await_writer_with_timeout(writer, Duration::ZERO)
                .await
                .is_ok(),
            "bounded writer timeout settlement should succeed"
        );
        writers.lock().remove(&conn_id);
        tokio::task::yield_now().await;

        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(hub.snapshot().connections, 0);
    }

    #[tokio::test]
    async fn connection_cleanup_repairs_injected_panic_and_observes_join_error() {
        let hub = Hub::new(Limits::default());
        let (conn_id, _input) = test_connection(&hub, "127.0.0.1");
        let writers = Arc::new(Mutex::new(HashMap::new()));
        let (settlement_tx, mut settlement_rx) = mpsc::channel(1);
        let dropped = Arc::new(AtomicBool::new(false));
        let dropped_in_writer = Arc::clone(&dropped);
        let (closed_tx, mut closed_rx) = watch::channel(false);
        let task_hub = hub.clone();
        let task_writers = Arc::clone(&writers);
        let task = tokio::spawn(async move {
            let mut cleanup = ConnectionCleanup::new(task_hub, conn_id);
            task_writers.lock().insert(
                conn_id,
                Some(tokio::spawn(async move {
                    let _drop_flag = DropFlag(dropped_in_writer);
                    let _ = closed_rx.changed().await;
                })),
            );
            cleanup.install_closed_signal(closed_tx);
            cleanup.install_settlement_sender(settlement_tx);
            panic!("injected connection panic after activation");
        });

        let error = task.await.expect_err("injected connection must panic");
        assert!(error.is_panic());
        assert_eq!(writers.lock().len(), 1);
        process_writer_settlement(&mut settlement_rx, &writers, Duration::from_secs(2)).await;
        tokio::task::yield_now().await;
        assert!(dropped.load(Ordering::Acquire));
        assert_eq!(hub.snapshot().connections, 0);
    }

    #[tokio::test]
    async fn accept_reaper_settles_panic_and_cancel_before_successor_admission() {
        let hub = Hub::new(Limits {
            max_connections: 1,
            ..Limits::default()
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let connections = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        let writers = Arc::new(Mutex::new(HashMap::with_capacity(1)));
        let registry_terminal = Arc::new(RegistryTerminal::new());
        let (completion_tx, completion_rx) = mpsc::channel(1);
        let (settlement_tx, settlement_rx) = mpsc::channel(1);
        let accept_task = tokio::spawn(accept_loop(
            listener,
            AcceptLoopContext {
                hub: hub.clone(),
                connections: Arc::clone(&connections),
                writers: Arc::clone(&writers),
                registry_terminal: Arc::clone(&registry_terminal),
                registry_capacity: 1,
                completion_rx,
                writer_settlement_rx: settlement_rx,
                completion_tx: completion_tx.clone(),
                writer_settlement_tx: settlement_tx.clone(),
                writer_stop_timeout: Duration::from_secs(1),
                custodian_owner: DedicatedTaskCustodian::new(1).expect("test custodian"),
                fallback_reaper_tasks: FallbackReaperTasks::new(2),
            },
        ));

        let first = hub
            .admit("127.0.0.1".parse().unwrap())
            .expect("first admission must fit");
        let first_id = first
            .activate(mpsc::channel::<WsMessage>(1).0)
            .expect("first connection must register");
        writers
            .lock()
            .insert(first_id, Some(tokio::spawn(std::future::pending::<()>())));
        let first_completion_tx = completion_tx.clone();
        let first_task = tokio::spawn({
            let hub = hub.clone();
            let settlement_tx = settlement_tx.clone();
            async move {
                let _ = std::panic::AssertUnwindSafe(async move {
                    let mut cleanup = ConnectionCleanup::new(hub, first_id);
                    cleanup.install_settlement_sender(settlement_tx);
                    panic!("injected handler panic after activation");
                })
                .catch_unwind()
                .await;
                let _ = first_completion_tx.send(first_id).await;
            }
        });
        connections.lock().insert(first_id, first_task);

        let mut progress = registry_terminal.progress.subscribe();
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if hub.snapshot().connections == 0 && writers.lock().is_empty() {
                    break;
                }
                progress
                    .changed()
                    .await
                    .expect("completion progress must remain published");
            }
        })
        .await
        .expect("accept reaper must settle a panicked connection");
        drop(
            hub.admit("127.0.0.1".parse().unwrap())
                .expect("successor must fit after panic settlement"),
        );

        let second = hub
            .admit("127.0.0.1".parse().unwrap())
            .expect("second admission must fit");
        let second_id = second
            .activate(mpsc::channel::<WsMessage>(1).0)
            .expect("second connection must register");
        writers
            .lock()
            .insert(second_id, Some(tokio::spawn(std::future::pending::<()>())));
        let (armed_tx, armed_rx) = tokio::sync::oneshot::channel();
        let second_handler = tokio::spawn({
            let hub = hub.clone();
            let settlement_tx = settlement_tx.clone();
            async move {
                let mut cleanup = ConnectionCleanup::new(hub, second_id);
                cleanup.install_settlement_sender(settlement_tx);
                armed_tx.send(()).expect("cancel witness must arm");
                std::future::pending::<()>().await;
            }
        });
        let second_abort = second_handler.abort_handle();
        let second_task = tokio::spawn(async move {
            let result = second_handler.await;
            assert!(
                result.is_err_and(|error| error.is_cancelled()),
                "cancelled connection handler must be observed"
            );
            let _ = completion_tx.send(second_id).await;
        });
        armed_rx
            .await
            .expect("cancel witness must arm before abort");
        connections.lock().insert(second_id, second_task);
        second_abort.abort();

        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if hub.snapshot().connections == 0 && writers.lock().is_empty() {
                    break;
                }
                progress
                    .changed()
                    .await
                    .expect("completion progress must remain published");
            }
        })
        .await
        .expect("accept reaper must settle a cancelled connection");
        drop(
            hub.admit("127.0.0.1".parse().unwrap())
                .expect("successor must fit after cancellation settlement"),
        );

        accept_task.abort();
        assert!(
            accept_task.await.is_err(),
            "aborted accept task must be observed"
        );
    }

    #[tokio::test]
    async fn production_writer_timeout_releases_placeholder_before_successor() {
        let _gate = TEST_GATE_SERIAL.lock().await;
        let _reset = TestGateReset;
        TEST_PARK_NEXT_WRITER.store(true, Ordering::Release);
        TEST_WRITER_PARKED.store(false, Ordering::Release);
        TEST_PANIC_AFTER_WRITER.store(true, Ordering::Release);
        let server = start_test_server(
            "127.0.0.1",
            0,
            Limits {
                max_connections: 1,
                writer_stop_timeout_secs: 1,
                ..Limits::default()
            },
        )
        .await
        .unwrap();
        let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
        let (first, _) = connect_async(&url).await.unwrap();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if server.stats().connections == 0
                    && server
                        .writers
                        .lock()
                        .values()
                        .any(|writer| writer.is_none())
                    && TEST_WRITER_PARKED.load(Ordering::Acquire)
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("W0 cleanup must unregister Hub before settlement parks");
        let successor_admission = server
            .hub
            .admit("127.0.0.1".parse().unwrap())
            .expect("Hub admission must be available after W0 cleanup");
        assert!(
            !writer_registry_slot_available(&server.writers, 1),
            "the exact writer placeholder must still fence the successor"
        );
        let combined_registry_available = {
            let owned_connections = server.connections.lock();
            owned_connections.is_empty() && writer_registry_slot_available(&server.writers, 1)
        };
        assert!(
            !combined_registry_available,
            "the production accept predicate must remain closed while W0 settles"
        );
        drop(successor_admission);
        assert_eq!(server.writers.lock().len(), 1);

        drop(first);
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                if server.stats().connections == 0 && server.writers.lock().is_empty() {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("configured writer timeout must abort, join, and release W0");

        let (second, _) = connect_async(&url).await.unwrap();
        drop(second);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if server.stats().connections == 0 {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("W1 must settle before shutdown");
        server
            .stop_and_wait()
            .await
            .expect("configured writer timeout shutdown succeeds");
    }

    #[tokio::test]
    async fn stop_and_wait_finishes_inflight_settlement_before_draining_registries() {
        let _gate = TEST_GATE_SERIAL.lock().await;
        let _reset = TestGateReset;
        TEST_PARK_NEXT_WRITER.store(true, Ordering::Release);
        TEST_WRITER_PARKED.store(false, Ordering::Release);
        TEST_PANIC_AFTER_WRITER.store(true, Ordering::Release);
        let server = start_test_server(
            "127.0.0.1",
            0,
            Limits {
                max_connections: 1,
                writer_stop_timeout_secs: 1,
                ..Limits::default()
            },
        )
        .await
        .unwrap();
        let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
        let (first, _) = connect_async(&url).await.unwrap();
        let progress = server.registry_terminal.progress.subscribe();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if TEST_WRITER_PARKED.load(Ordering::Acquire)
                    && server.stats().connections == 0
                    && server
                        .writers
                        .lock()
                        .values()
                        .any(|writer| writer.is_none())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer settlement must be in flight before shutdown");

        let writer_id = server
            .writers
            .lock()
            .keys()
            .next()
            .copied()
            .expect("the parked writer remains exactly owned");
        let progress_before_shutdown = *progress.borrow();
        drop(first);
        let hub = server.hub.clone();
        let connections = Arc::clone(&server.connections);
        let writers = Arc::clone(&server.writers);
        let error = server
            .stop_and_wait()
            .await
            .expect_err("the injected writer panic must reach the shutdown result");
        assert!(
            error
                .failures
                .iter()
                .any(|failure| failure.task == format!("writer:{writer_id}")),
            "shutdown must identify the exact panicking writer: {error}"
        );

        assert!(
            *progress.borrow() > progress_before_shutdown,
            "stop_and_wait must publish progress after the parked writer's terminal join"
        );
        assert!(connections.lock().is_empty());
        assert!(writers.lock().is_empty());
        assert_eq!(hub.snapshot().connections, 0);
    }

    #[tokio::test]
    async fn dropping_server_after_writer_extraction_reaps_exact_writer() {
        let _gate = TEST_GATE_SERIAL.lock().await;
        let _reset = TestGateReset;
        TEST_PARK_NEXT_WRITER.store(true, Ordering::Release);
        TEST_WRITER_PARKED.store(false, Ordering::Release);
        TEST_PANIC_AFTER_WRITER.store(true, Ordering::Release);
        let server = start_test_server(
            "127.0.0.1",
            0,
            Limits {
                max_connections: 1,
                writer_stop_timeout_secs: 1,
                ..Limits::default()
            },
        )
        .await
        .unwrap();
        let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
        let (first, _) = connect_async(&url).await.unwrap();
        let mut progress = server.registry_terminal.progress.subscribe();

        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if TEST_WRITER_PARKED.load(Ordering::Acquire)
                    && server.stats().connections == 0
                    && server
                        .writers
                        .lock()
                        .values()
                        .any(|writer| writer.is_none())
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("writer must be extracted before server drop");

        let progress_before_drop = *progress.borrow_and_update();
        let writers = Arc::clone(&server.writers);
        drop(first);
        drop(server);

        tokio::time::timeout(Duration::from_secs(3), progress.changed())
            .await
            .expect("dedicated writer reaper must outlive waiter/server drop")
            .expect("dedicated writer reaper must publish terminal progress");
        assert!(
            *progress.borrow() > progress_before_drop,
            "writer terminal progress must be published after server drop"
        );
        assert!(writers.lock().is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outside_runtime_drop_transfers_task_to_runtime_reaper() {
        let _gate = TEST_GATE_SERIAL.lock().await;
        TEST_REAPED_TASKS.store(0, Ordering::Release);
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
            1,
            "the exact aborted task must be awaited by the runtime reaper"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn fallback_capacity_refusal_returns_exact_panicking_handle() {
        let fallback = FallbackReaperTasks::new(0);
        let (task, started) = panicking_task("server fallback capacity refusal");
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
        let (task, started) = panicking_task("server bounded fallback overflow");
        started
            .await
            .expect("panic task must start before transfer");
        retain_or_overflow(&fallback, task, "server overflow control");
        reap_fallback_reaper_tasks(&fallback).await;
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 1,
            "bounded overflow custody must observe the exact panic"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reaper_full_and_closed_fallbacks_observe_panics_in_and_outside_runtime() {
        let _gate = TEST_GATE_SERIAL.lock().await;
        let before = TEST_REAPED_FALLBACKS.load(Ordering::Acquire);

        let fallback_reaper_tasks = FallbackReaperTasks::new(1);
        let (full_sender, mut full_receiver) = mpsc::channel(1);
        full_sender
            .try_send(tokio::spawn(std::future::pending::<()>()))
            .expect("the first handle fills the bounded reaper channel");
        let (task, started) = panicking_task("injected server panic through full fallback");
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
        let (task, started) = panicking_task("injected server panic through closed fallback");
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
            panicking_task("injected server panic through outside-runtime full fallback");
        started
            .await
            .expect("the outside-runtime full child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || abort_and_join(&full_sender, task, &fallback_for_thread))
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
            panicking_task("injected server panic through outside-runtime closed fallback");
        started
            .await
            .expect("the outside-runtime closed child starts before transfer");
        let fallback_for_thread = Arc::clone(&fallback_reaper_tasks);
        std::thread::spawn(move || abort_and_join(&closed_sender, task, &fallback_for_thread))
            .join()
            .expect("outside-runtime closed fallback returns after joining");
        assert_eq!(
            TEST_REAPED_FALLBACKS.load(Ordering::Acquire),
            before + 4,
            "a closed no-runtime transfer synchronously observes the child"
        );
    }

    #[tokio::test]
    async fn bounded_settlement_queue_accepts_exact_connection_population() {
        let limits = Limits {
            max_connections: 3,
            ..Limits::default()
        };
        let capacity = Limits::checked_usize(limits.max_connections, "max_connections").unwrap();
        let writers = Arc::new(Mutex::new(HashMap::with_capacity(capacity)));
        let (settlement_tx, settlement_rx) = mpsc::channel(capacity);

        // Consume the first exact notification while its writer is parked;
        // the remaining admitted population consumes the bounded queue slots
        // derived from max_connections.
        let (release_tx, release_rx) = tokio::sync::oneshot::channel();
        writers.lock().insert(
            0,
            Some(tokio::spawn(async move {
                let _ = release_rx.await;
            })),
        );
        assert!(notify_writer_settlement(&settlement_tx, 0));
        let settlement_writers = Arc::clone(&writers);
        let first_settlement = tokio::spawn(async move {
            let mut settlement_rx = settlement_rx;
            process_writer_settlement(
                &mut settlement_rx,
                &settlement_writers,
                Duration::from_secs(2),
            )
            .await;
            settlement_rx
        });
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if matches!(writers.lock().get(&0), Some(None)) {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first exact writer must be in-flight during queue pressure");

        for conn_id in 1..capacity as u64 {
            writers.lock().insert(conn_id, Some(tokio::spawn(async {})));
            assert!(notify_writer_settlement(&settlement_tx, conn_id));
        }
        assert_eq!(writers.lock().len(), capacity);

        release_tx.send(()).unwrap();
        let mut settlement_rx = first_settlement.await.unwrap();
        for _ in 1..capacity {
            process_writer_settlement(&mut settlement_rx, &writers, Duration::from_secs(2)).await;
        }
        assert!(writers.lock().is_empty());

        // With no settlement in flight, the channel itself accepts exactly
        // C one-shot notifications and rejects the next one explicitly.
        for conn_id in 0..capacity as u64 {
            writers.lock().insert(conn_id, Some(tokio::spawn(async {})));
            assert!(notify_writer_settlement(&settlement_tx, conn_id));
        }
        assert!(matches!(
            settlement_tx.try_send(capacity as u64),
            Err(mpsc::error::TrySendError::Full(id)) if id == capacity as u64
        ));

        for _ in 0..capacity {
            process_writer_settlement(&mut settlement_rx, &writers, Duration::from_secs(2)).await;
        }
        assert!(writers.lock().is_empty());
    }
}
