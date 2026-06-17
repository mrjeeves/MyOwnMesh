//! Concrete Nostr signaling driver. Connects to N relays in
//! parallel, publishes ephemeral signaling events tagged with
//! the room handle, subscribes to inbound events on the same
//! tag, and routes them back to the caller via mpsc channels.
//!
//! Resilience features baked in (see `crate::upstream`):
//!
//! - Subscription replay on socket reconnect, with anti-flood
//!   backoff at 5 / 10 / 15 / 30 / 60 s.
//! - Transition-only logging — no per-event spam.
//! - Per-relay backoff on connection failure, capped at 60 s.
//!
//! The driver is independent of the engine; the
//! [`crate::SignalingChannel`] trait is the seam.

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc, watch};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, trace, warn};

use super::event::{
    make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EPHEMERAL_KIND, SIGNALING_EVENT_KIND,
};
use super::handle::derive_room_handle;
use super::relay::SubscriptionReplay;
use super::shuffle::select_top_n;
use crate::upstream::{ANNOUNCE_BACKOFF_MS, ANNOUNCE_STEADY_MS, PRESENCE_REPLAY_WINDOW_SECS};
use crate::SignalingMessage;

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
    pub servers: Vec<String>,
    /// Hostnames excluded from the shuffle.
    pub denylist: Vec<String>,
    /// Top-N relays to maintain.
    pub redundancy: usize,
    /// Fall back to the built-in public relays when every primary relay is
    /// unreachable. On by default; the fallback is reactive (only while
    /// the primary set is down) so steady state stays on your own relays.
    pub public_fallback: bool,
}

/// Inbound signaling events the driver pushes to the engine.
#[derive(Debug, Clone)]
pub enum NostrInbound {
    /// A peer announced their presence in the room.
    PeerAnnounced { device_id: String },
    /// A peer's signaling connection dropped — an intelligent relay told
    /// us the instant the peer's socket closed, so the engine can tear
    /// the peer down promptly instead of waiting for a heartbeat timeout.
    PeerLeft { device_id: String },
    /// A peer addressed us directly with a signaling message.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
#[derive(Debug, Clone)]
pub enum NostrOutbound {
    Announce,
    DirectedToPeer { to: String, msg: SignalingMessage },
}

/// Start the driver. Spawns a coordinator task per relay; returns
/// the handle (drop to stop).
pub fn start(
    config: NostrDriverConfig,
    outbound_rx: mpsc::UnboundedReceiver<NostrOutbound>,
    inbound_tx: mpsc::UnboundedSender<NostrInbound>,
) -> NostrDriverHandle {
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

    // Fan-out channel for outbound events. Capacity is generous
    // so a slow relay can't backpressure the publish side.
    let (publish_tx, _) = broadcast::channel::<Arc<NostrEvent>>(64);
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
    let shared = Arc::new(DriverShared {
        identity,
        room_handle,
        device_id: config.device_id.clone(),
        relays: Mutex::new(Vec::new()),
        outbound: tokio::sync::Mutex::new(Some(outbound_rx)),
        publish_tx,
        force_reconnect: force_reconnect.clone(),
        seen_event_ids: Mutex::new(std::collections::VecDeque::with_capacity(
            SEEN_EVENT_CAPACITY,
        )),
        outbound_replay: Mutex::new(std::collections::VecDeque::new()),
    });
    {
        let mut relays = shared.relays.lock();
        for url in &selected {
            relays.push(RelayHandle {
                url: url.clone(),
                connected: false,
            });
        }
    }

    let mut cancellers = Vec::new();

    // Count of primary relays with a live session; the fallback
    // supervisor watches this to decide when to step in.
    let primary_live = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Spawn one connection task per primary relay.
    for url in selected {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        let live = primary_live.clone();
        tokio::spawn(async move {
            run_relay(url, shared, inbound_tx, cancel_token_for_task, Some(live)).await;
        });
    }

    // Spawn the public-relay fallback supervisor (no-op unless the pool is
    // non-empty, i.e. `public_fallback` is on and there are relays to use).
    if !fallback_urls.is_empty() {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        let primary_live = primary_live.clone();
        tokio::spawn(async move {
            run_fallback_supervisor(
                fallback_urls,
                shared,
                inbound_tx,
                cancel_token_for_task,
                primary_live,
            )
            .await;
        });
    }

    // Spawn the outbound pump.
    let shared_for_outbound = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tokio::spawn(async move {
        run_outbound_pump(shared_for_outbound, cancel_token_for_task).await;
    });

    // Spawn the global announce task. Single ticker per driver
    // instance (NOT per relay) — fans out via `publish_tx`. See
    // `upstream.rs` item 7 for the schedule rationale and the
    // earlier "N-relay = N-publish" bug it fixes.
    let shared_for_announce = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tokio::spawn(async move {
        run_announcer(shared_for_announce, cancel_token_for_task).await;
    });

    NostrDriverHandle {
        cancellers,
        force_reconnect,
    }
}

/// Handle returned by [`start`]. Drop or call [`Self::stop`] to
/// signal every spawned task to exit.
pub struct NostrDriverHandle {
    cancellers: Vec<Arc<std::sync::atomic::AtomicBool>>,
    force_reconnect: Arc<watch::Sender<u64>>,
}

impl NostrDriverHandle {
    pub fn stop(self) {
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    /// Clone of the force-reconnect signal. The engine stashes this
    /// (see `engine::state::NetworkState::set_relay_reconnect`) and
    /// bumps it to make every relay redial immediately — e.g. on
    /// resume from sleep, when the existing sockets are stale.
    pub fn reconnect_signal(&self) -> Arc<watch::Sender<u64>> {
        self.force_reconnect.clone()
    }
}

impl Drop for NostrDriverHandle {
    fn drop(&mut self) {
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct DriverShared {
    identity: NostrIdentity,
    room_handle: String,
    device_id: String,
    relays: Mutex<Vec<RelayHandle>>,
    outbound: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<NostrOutbound>>>,
    publish_tx: broadcast::Sender<Arc<NostrEvent>>,
    /// Generation counter for forced reconnects. Bumping it wakes
    /// every relay task's `watch::Receiver` so it drops its socket
    /// and redials without waiting out the backoff. See the comment
    /// at the channel's creation in [`start`].
    force_reconnect: Arc<watch::Sender<u64>>,
    /// Cross-relay event-ID dedupe ring. Each Nostr event has a
    /// sha256 `id`; the same event published once to N relays
    /// arrives N times if we don't dedupe. Without this, the engine
    /// receives every announce N× (cosmetic log spam) AND every
    /// Offer / Answer N× (functional: calling
    /// `set_remote_description` twice on the same peer connection
    /// puts WebRTC into an unrecoverable state and stalls the
    /// handshake at Sighted — exactly the "they just sit there"
    /// symptom users hit in the field). 2048 entries covers the
    /// busiest realistic mesh comfortably without growing
    /// unboundedly.
    seen_event_ids: Mutex<std::collections::VecDeque<String>>,
    /// Outbound *directed* events (offers / answers / candidates) buffered
    /// while every relay socket was mid-reconnect, when `publish_tx` has no
    /// subscribers and a plain send would be dropped. This is the
    /// network-change race: the engine fires its ICE-restart offers the
    /// same instant the relay redials (both triggered by the IP change),
    /// so without buffering the restart offers vanish into the ~1 s
    /// reconnect window — the peer never hears them and the Offerer side
    /// never recovers (observed directly in the field). The next relay to
    /// (re)connect drains and replays these; see `run_outbound_pump` and
    /// the relay session's subscribe path. Bounded ([`OUTBOUND_REPLAY_CAP`])
    /// and TTL'd ([`OUTBOUND_REPLAY_TTL_MS`]) so a long outage can't grow it
    /// unboundedly or replay an offer the negotiation has moved past.
    outbound_replay: Mutex<std::collections::VecDeque<(std::time::Instant, Arc<NostrEvent>)>>,
}

/// Window size of `seen_event_ids` — re-exported from
/// [`crate::upstream`] which catalogues the rationale alongside the
/// other upstream-Trystero fixes. The dedup itself lives here in
/// the driver where the relay-fanout happens; the constant lives
/// there with the rest of the tuning surface.
use crate::upstream::SEEN_EVENT_CAPACITY;

#[allow(dead_code)]
struct RelayHandle {
    url: String,
    connected: bool,
}

async fn run_relay(
    url: String,
    shared: Arc<DriverShared>,
    inbound_tx: mpsc::UnboundedSender<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    live: Option<Arc<std::sync::atomic::AtomicUsize>>,
) {
    let mut backoff_attempt = 0u32;
    let mut replay = SubscriptionReplay::new();
    // Receiver for forced reconnects. `borrow_and_update` marks the
    // current generation as seen so a stale value from before this
    // task started can't fire a spurious immediate reconnect.
    let mut force_rx = shared.force_reconnect.subscribe();
    force_rx.borrow_and_update();
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
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match tokio_tungstenite::connect_async(&url).await {
            Ok((stream, _)) => {
                if consecutive_failures > 0 {
                    info!(
                        relay = %short(&url),
                        attempts = consecutive_failures,
                        "relay recovered after failed attempts"
                    );
                } else {
                    info!(relay = %short(&url), "relay connected");
                }
                consecutive_failures = 0;
                backoff_attempt = 0;
                // Count this live session so the fallback supervisor can
                // tell whether any primary relay is currently connected.
                // `None` for fallback tasks (they don't gate themselves).
                if let Some(c) = &live {
                    c.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
                let outcome = run_relay_session(
                    &url,
                    stream,
                    &shared,
                    &inbound_tx,
                    &mut replay,
                    &cancel,
                    &mut force_rx,
                )
                .await;
                if let Some(c) = &live {
                    c.fetch_sub(1, std::sync::atomic::Ordering::SeqCst);
                }
                trace!(relay = %short(&url), outcome = ?outcome, "relay session ended");
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
            Err(e) => {
                if consecutive_failures == 0 {
                    warn!(relay = %short(&url), "relay connect failed: {e}");
                } else {
                    debug!(
                        relay = %short(&url),
                        attempt = consecutive_failures + 1,
                        "relay still failing: {e}"
                    );
                }
                consecutive_failures = consecutive_failures.saturating_add(1);
            }
        }
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Reconnect backoff: 1 / 2 / 4 / 8 / 16 s capped at 60 s. A
        // forced-reconnect bump cuts the wait short so resume-from-sleep
        // recovery doesn't sit through a backoff that accrued while the
        // host was suspended.
        backoff_attempt = (backoff_attempt + 1).min(6);
        let wait = (1u64 << backoff_attempt).min(60);
        debug!(relay = %short(&url), wait_s = wait, "relay backoff before reconnect");
        tokio::select! {
            _ = sleep(Duration::from_secs(wait)) => {}
            _ = force_rx.changed() => {
                debug!(relay = %short(&url), "forced reconnect during backoff — redialing now");
                backoff_attempt = 0;
            }
        }
    }
}

/// How often the fallback supervisor samples primary-relay health.
const FALLBACK_POLL_MS: u64 = 3_000;

/// How long *every* primary relay must be continuously unreachable before
/// the public fallback is brought up. Long enough that a routine
/// reconnect or a brief blip doesn't leak presence to public relays;
/// short enough that a real outage recovers in seconds.
const FALLBACK_ACTIVATION_GRACE_MS: u64 = 20_000;

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

fn fallback_action(primary_live: usize, fallback_active: bool, down_for_ms: u64) -> FallbackAction {
    if primary_live > 0 {
        if fallback_active {
            FallbackAction::StandDown
        } else {
            FallbackAction::Hold
        }
    } else if !fallback_active && down_for_ms >= FALLBACK_ACTIVATION_GRACE_MS {
        FallbackAction::Activate
    } else {
        FallbackAction::Hold
    }
}

/// Supervises the public-relay fallback. Steady state: idle, sampling
/// `primary_live`. When every primary relay has been down for
/// [`FALLBACK_ACTIVATION_GRACE_MS`] it spawns a `run_relay` task per
/// fallback URL; when a primary returns it cancels them. So the public
/// relays only ever carry traffic when the configured/primary set can't —
/// presence stays off public infrastructure in normal operation.
async fn run_fallback_supervisor(
    urls: Vec<String>,
    shared: Arc<DriverShared>,
    inbound_tx: mpsc::UnboundedSender<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
    primary_live: Arc<std::sync::atomic::AtomicUsize>,
) {
    use std::sync::atomic::Ordering::SeqCst;
    use std::time::Instant;

    // Cancel tokens for the fallback relay tasks currently running.
    let mut active: Vec<Arc<std::sync::atomic::AtomicBool>> = Vec::new();
    let mut down_since: Option<Instant> = None;

    loop {
        if cancel.load(SeqCst) {
            for c in &active {
                c.store(true, SeqCst);
            }
            return;
        }

        let live = primary_live.load(SeqCst);
        if live == 0 {
            down_since.get_or_insert_with(Instant::now);
        } else {
            down_since = None;
        }
        let down_for_ms = down_since
            .map(|t| t.elapsed().as_millis() as u64)
            .unwrap_or(0);

        match fallback_action(live, !active.is_empty(), down_for_ms) {
            FallbackAction::Activate => {
                warn!(
                    count = urls.len(),
                    "primary signaling unreachable — bringing up public fallback relays"
                );
                for url in &urls {
                    let task_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                    active.push(task_cancel.clone());
                    let shared = shared.clone();
                    let inbound_tx = inbound_tx.clone();
                    let url = url.clone();
                    tokio::spawn(async move {
                        run_relay(url, shared, inbound_tx, task_cancel, None).await;
                    });
                }
            }
            FallbackAction::StandDown => {
                info!("primary signaling recovered — standing down public fallback relays");
                for c in &active {
                    c.store(true, SeqCst);
                }
                active.clear();
            }
            FallbackAction::Hold => {}
        }

        sleep(Duration::from_millis(FALLBACK_POLL_MS)).await;
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
}

/// How often the relay read loop wakes on an otherwise-idle socket to
/// re-check the cancel flag. The loop wakes immediately on any inbound
/// frame or outbound publish; this bounds how long a *stopped* driver
/// (handle dropped / `stop()`) holds an idle socket open before it tears
/// it down — which is what lets an intelligent relay emit our `leave`
/// promptly rather than waiting on its own connection timeout.
const RELAY_CANCEL_POLL_MS: u64 = 250;

async fn run_relay_session(
    url: &str,
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    shared: &Arc<DriverShared>,
    inbound_tx: &mpsc::UnboundedSender<NostrInbound>,
    replay: &mut SubscriptionReplay,
    cancel: &Arc<std::sync::atomic::AtomicBool>,
    force_rx: &mut watch::Receiver<u64>,
) -> RelaySessionOutcome {
    let (mut write, mut read) = stream.split();

    // Open subscription for the room handle. We subscribe to both
    // signaling kinds in one REQ:
    //   - SIGNALING_EVENT_KIND (stored): presence announces. The
    //     `since` window replays the last few minutes so a late
    //     joiner discovers everyone already here.
    //   - SIGNALING_EPHEMERAL_KIND (not stored): live offer/answer/
    //     candidate. The relay has nothing to replay for these, so
    //     `since` is a no-op for them — they only ever arrive live.
    // The window therefore governs presence replay only; connection
    // negotiation is never replayed, which is the whole point of the
    // ephemeral kind (see `event::SIGNALING_EPHEMERAL_KIND`).
    let sub_id = "mom-sig-1";
    let req = serde_json::json!([
        "REQ",
        sub_id,
        {
            "kinds": [SIGNALING_EVENT_KIND, SIGNALING_EPHEMERAL_KIND],
            "#r": [shared.room_handle.clone()],
            "since": now_secs().saturating_sub(PRESENCE_REPLAY_WINDOW_SECS),
        }
    ]);
    let req_text = req.to_string();
    let _ = replay.observe_send(&req_text);

    if let Err(e) = write.send(WsMessage::Text(req_text.clone())).await {
        return RelaySessionOutcome::Error(format!("send REQ: {e}"));
    }

    // Mark the socket as opened so the replay layer knows.
    let _decision = replay.on_open();
    replay.record_replay();

    // Subscribe to the broadcast so outbound events fan to this socket.
    // Announce ticking lives in `run_announcer` — one shared task
    // per driver instance, not one per relay — so the per-cycle
    // publish rate doesn't scale with relay count.
    let mut publish_rx = shared.publish_tx.subscribe();

    // Replay any directed events buffered while every relay was
    // mid-reconnect (the network-change race — see
    // `DriverShared::outbound_replay`). Now that this socket is subscribed,
    // re-publish them so they fan out to every connected relay and reach
    // the peer; draining means only the first relay back replays. This is
    // what lets the Offerer side's ICE-restart offers survive the relay
    // redial instead of being dropped.
    {
        let fresh = {
            let mut buf = shared.outbound_replay.lock();
            drain_fresh_outbound(&mut buf, std::time::Instant::now())
        };
        if !fresh.is_empty() {
            debug!(
                relay = %short(url),
                count = fresh.len(),
                "replaying buffered outbound events after relay reconnect"
            );
            for event in fresh {
                let _ = shared.publish_tx.send(event);
            }
        }
    }

    // One-shot "hello, I'm on this relay" publish so a freshly
    // (re)connected relay immediately learns we're here, rather
    // than waiting up to ANNOUNCE_STEADY_MS for the next global
    // tick. Cheap — the relay-side dedup (by event id) means a
    // tick that fires shortly after is harmless.
    {
        let event = build_announce_event(shared);
        let frame = serde_json::json!(["EVENT", event]).to_string();
        if let Err(e) = write.send(WsMessage::Text(frame)).await {
            return RelaySessionOutcome::Error(format!("send open-announce: {e}"));
        }
    }

    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            // Best-effort clean close so the relay sees our departure
            // immediately (a Close frame, falling back to the TCP FIN
            // from dropping the stream). Bounded so a wedged socket
            // can't hang teardown.
            let _ = tokio::time::timeout(std::time::Duration::from_secs(1), write.close()).await;
            return RelaySessionOutcome::Cancelled;
        }
        tokio::select! {
            msg = read.next() => {
                let Some(msg) = msg else { return RelaySessionOutcome::SocketClosed };
                let frame = match msg {
                    Ok(WsMessage::Text(t)) => t,
                    Ok(WsMessage::Binary(b)) => match std::str::from_utf8(&b) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    },
                    Ok(WsMessage::Close(_)) => return RelaySessionOutcome::SocketClosed,
                    Ok(_) => continue,
                    Err(e) => return RelaySessionOutcome::Error(format!("ws read: {e}")),
                };
                if let Err(e) = handle_inbound_frame(url, &frame, shared, inbound_tx) {
                    trace!(relay = %short(url), "inbound frame parse: {e}");
                }
            }
            publish = publish_rx.recv() => {
                match publish {
                    Ok(event) => {
                        let frame = serde_json::json!(["EVENT", &*event]).to_string();
                        if let Err(e) = write.send(WsMessage::Text(frame)).await {
                            return RelaySessionOutcome::Error(format!("send publish: {e}"));
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return RelaySessionOutcome::Cancelled;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(relay = %short(url), "publish bus lagged {n} events");
                    }
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
            // Idle-wake so a stopped/dropped handle is noticed within one
            // poll interval even on a quiet socket. Without this, a
            // `read.next()` parked on an idle connection could hold the
            // socket open long after `stop()`, delaying the relay's
            // departure signal. Normal traffic wakes the loop sooner via
            // the branches above; this only bites when nothing is moving.
            _ = tokio::time::sleep(std::time::Duration::from_millis(RELAY_CANCEL_POLL_MS)) => {}
        }
    }
}

/// Global announce ticker. One instance per driver; publishes
/// presence events via `publish_tx` on the schedule defined by
/// [`ANNOUNCE_BACKOFF_MS`] / [`ANNOUNCE_STEADY_MS`].
///
/// The first announce fires immediately on driver start (a fresh
/// joiner wants to be visible to existing peers without delay).
/// Subsequent waits follow the curve in `upstream.rs` item 7:
/// dense at startup, settling to a 60s steady-state heartbeat.
async fn run_announcer(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut count: usize = 0;
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let event = build_announce_event(&shared);
        // `publish_tx` is a broadcast — every connected relay's
        // run_relay loop receives this on its `publish_rx` and
        // writes it to its own socket. One tick → one publish →
        // N writes (one per relay), independent of how many
        // relays are currently connected.
        let _ = shared.publish_tx.send(Arc::new(event));

        let wait_ms = ANNOUNCE_BACKOFF_MS
            .get(count)
            .copied()
            .unwrap_or(ANNOUNCE_STEADY_MS);
        count = count.saturating_add(1);

        // Cancellation-aware sleep: chunked at 1s so a stop()
        // call doesn't have to wait a full 60s tick to take
        // effect. Bounded by `chunk` since wait_ms can exceed it.
        let mut remaining = wait_ms;
        const CHUNK_MS: u64 = 1_000;
        while remaining > 0 {
            if cancel.load(std::sync::atomic::Ordering::SeqCst) {
                return;
            }
            let step = remaining.min(CHUNK_MS);
            sleep(Duration::from_millis(step)).await;
            remaining = remaining.saturating_sub(step);
        }
    }
}

fn handle_inbound_frame(
    url: &str,
    frame: &str,
    shared: &Arc<DriverShared>,
    inbound_tx: &mpsc::UnboundedSender<NostrInbound>,
) -> Result<(), String> {
    let value: Value = serde_json::from_str(frame).map_err(|e| e.to_string())?;
    let arr = value.as_array().ok_or_else(|| "not an array".to_string())?;
    let tag = arr.first().and_then(|v| v.as_str()).unwrap_or("");
    match tag {
        "EVENT" => {
            let event_value = arr.get(2).ok_or_else(|| "missing event body".to_string())?;
            let event: NostrEvent =
                serde_json::from_value(event_value.clone()).map_err(|e| e.to_string())?;
            // Skip events we sent ourselves.
            if event.pubkey == shared.identity.pubkey_hex() {
                return Ok(());
            }
            // Cross-relay dedup. The same Nostr event (same sha256
            // `id`) gets delivered by every relay that has it — with
            // `signaling.redundancy` typically 4-5, that's a 4-5×
            // amplification on every announce, offer, answer, and
            // candidate. The engine layer above us is mostly
            // idempotent on announces (`ensure_peer_session`
            // short-circuits) but NOT on Offer/Answer:
            // `set_remote_description` on an already-stable
            // RTCPeerConnection puts WebRTC into a permanently
            // wedged state — exactly the "they just sit there"
            // symptom users see when peers reach Sighted and
            // nothing advances. Filtering by event ID here is the
            // canonical fix per `upstream.rs` item 5: signaling-layer
            // concerns belong in signaling-layer code, not bolted
            // into every engine handler.
            {
                let mut seen = shared.seen_event_ids.lock();
                if seen.iter().any(|id| id == &event.id) {
                    return Ok(()); // already delivered via another relay
                }
                if seen.len() >= SEEN_EVENT_CAPACITY {
                    seen.pop_front();
                }
                seen.push_back(event.id.clone());
            }
            // Pull our envelope out of the content.
            let envelope: SignalingEnvelope =
                serde_json::from_str(&event.content).map_err(|e| e.to_string())?;

            // Skip messages directed to a different recipient.
            if let Some(to) = &envelope.to {
                if to != &shared.device_id {
                    return Ok(());
                }
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
                    if event.kind != SIGNALING_EVENT_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring announce on non-presence kind"
                        );
                        return Ok(());
                    }
                    if peer_id == shared.device_id {
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::PeerAnnounced { device_id: peer_id });
                }
                SignalingMessage::Leave { peer_id } => {
                    // Departure rides the ephemeral kind like the rest of
                    // the live negotiation traffic — a stored-kind "leave"
                    // would be stale history, so drop it.
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "ignoring leave on non-ephemeral kind"
                        );
                        return Ok(());
                    }
                    if peer_id == shared.device_id {
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::PeerLeft { device_id: peer_id });
                }
                other => {
                    if event.kind != SIGNALING_EPHEMERAL_KIND {
                        trace!(
                            relay = %short(url),
                            kind = event.kind,
                            "dropping replayed/stored-kind negotiation message"
                        );
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::Message {
                        from: envelope.from,
                        msg: other,
                    });
                }
            }
        }
        "EOSE" => {
            trace!(relay = %short(url), "EOSE");
        }
        "NOTICE" => {
            let body = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            debug!(relay = %short(url), "relay notice: {body}");
        }
        _ => {
            trace!(relay = %short(url), "unhandled tag: {tag}");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignalingEnvelope {
    from: String,
    /// Recipient device id, or None for a broadcast (announce).
    #[serde(default)]
    to: Option<String>,
    #[serde(flatten)]
    msg: SignalingMessage,
}

fn build_announce_event(shared: &DriverShared) -> NostrEvent {
    let envelope = SignalingEnvelope {
        from: shared.device_id.clone(),
        to: None,
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

/// Cap on the outbound replay buffer — see [`DriverShared::outbound_replay`].
/// A network change produces a handful of offers plus a candidate trickle
/// per peer; 256 covers a large mesh's burst with headroom while bounding
/// memory if every relay stays down.
const OUTBOUND_REPLAY_CAP: usize = 256;

/// Buffered outbound events older than this are stale — the ICE
/// negotiation they belonged to has moved on — and are dropped rather than
/// replayed. Comfortably longer than a relay reconnect (sub-second to
/// ~2 s), shorter than the engine's checking-timeout, so a replay always
/// lands inside the attempt it was meant for.
const OUTBOUND_REPLAY_TTL_MS: u64 = 10_000;

/// Push an outbound event onto the replay buffer, evicting the oldest if
/// it would exceed [`OUTBOUND_REPLAY_CAP`].
fn push_outbound_replay(
    buf: &mut std::collections::VecDeque<(std::time::Instant, Arc<NostrEvent>)>,
    now: std::time::Instant,
    event: Arc<NostrEvent>,
) {
    buf.push_back((now, event));
    while buf.len() > OUTBOUND_REPLAY_CAP {
        buf.pop_front();
    }
}

/// Drain the replay buffer, returning the events still within
/// [`OUTBOUND_REPLAY_TTL_MS`] in order. Stale entries are discarded; the
/// buffer is emptied either way, so the first relay back replays and the
/// rest see nothing.
fn drain_fresh_outbound(
    buf: &mut std::collections::VecDeque<(std::time::Instant, Arc<NostrEvent>)>,
    now: std::time::Instant,
) -> Vec<Arc<NostrEvent>> {
    let ttl = Duration::from_millis(OUTBOUND_REPLAY_TTL_MS);
    buf.drain(..)
        .filter(|(t, _)| now.duration_since(*t) <= ttl)
        .map(|(_, e)| e)
        .collect()
}

async fn run_outbound_pump(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut rx_guard = shared.outbound.lock().await;
    let Some(mut rx) = rx_guard.take() else {
        return;
    };
    drop(rx_guard);
    while let Some(outbound) = rx.recv().await {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Presence rides the stored kind; directed negotiation rides
        // the ephemeral kind so it's never replayed onto a future
        // session. The kind is chosen by message class, not content.
        let (envelope, kind) = match outbound {
            NostrOutbound::Announce => (
                SignalingEnvelope {
                    from: shared.device_id.clone(),
                    to: None,
                    msg: SignalingMessage::Announce {
                        peer_id: shared.device_id.clone(),
                    },
                },
                SIGNALING_EVENT_KIND,
            ),
            NostrOutbound::DirectedToPeer { to, msg } => (
                SignalingEnvelope {
                    from: shared.device_id.clone(),
                    to: Some(to),
                    msg,
                },
                SIGNALING_EPHEMERAL_KIND,
            ),
        };
        let event = Arc::new(make_event(
            &shared.identity,
            kind,
            vec![vec!["r".into(), shared.room_handle.clone()]],
            serde_json::to_string(&envelope).expect("serialize ok"),
            now_secs(),
        ));
        // Fan out to every connected relay session via the
        // broadcast bus. Sessions that aren't subscribed yet
        // (still connecting / reconnecting) will pick up the
        // next event after their subscribe — for the
        // active-handshake path that's the periodic announce
        // running on each relay's own timer.
        if shared.publish_tx.receiver_count() == 0 {
            // Every relay is mid-reconnect. Buffer directed negotiation
            // (offers / answers / candidates, on the ephemeral kind) so the
            // next relay up replays it — without this the network-change
            // ICE-restart offers are lost to the reconnect window and the
            // Offerer side never recovers. Announce rides the stored kind
            // and is self-healing (the periodic tick + each relay's
            // open-announce re-send it), so buffering it would only add a
            // redundant publish.
            if kind == SIGNALING_EPHEMERAL_KIND {
                let mut buf = shared.outbound_replay.lock();
                push_outbound_replay(&mut buf, std::time::Instant::now(), event);
                debug!(
                    "no relay subscribers ready; buffered directed event for replay on reconnect"
                );
            } else {
                debug!("no relay subscribers ready; announce dropped (re-ticks on reconnect)");
            }
            continue;
        }
        let _ = shared.publish_tx.send(event);
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
    use crate::nostr::event::NostrIdentity;

    #[test]
    fn fallback_holds_while_a_primary_is_up() {
        // Primary connected, fallback not running → leave it alone.
        assert_eq!(fallback_action(2, false, 0), FallbackAction::Hold);
        assert_eq!(
            fallback_action(1, false, FALLBACK_ACTIVATION_GRACE_MS * 10),
            FallbackAction::Hold
        );
    }

    #[test]
    fn fallback_waits_out_the_grace_then_activates() {
        // All primaries down, but not yet past the grace → hold…
        assert_eq!(fallback_action(0, false, 0), FallbackAction::Hold);
        assert_eq!(
            fallback_action(0, false, FALLBACK_ACTIVATION_GRACE_MS - 1),
            FallbackAction::Hold
        );
        // …then activate once the grace elapses.
        assert_eq!(
            fallback_action(0, false, FALLBACK_ACTIVATION_GRACE_MS),
            FallbackAction::Activate
        );
    }

    #[test]
    fn fallback_stands_down_when_a_primary_returns() {
        // Fallback running and a primary comes back → tear it down.
        assert_eq!(fallback_action(1, true, 999_999), FallbackAction::StandDown);
    }

    #[test]
    fn fallback_holds_while_active_and_primary_still_down() {
        // Already covering the outage; don't respawn every tick.
        assert_eq!(fallback_action(0, true, 999_999), FallbackAction::Hold);
    }

    fn test_event(signer: &NostrIdentity, n: u8) -> Arc<NostrEvent> {
        let envelope = SignalingEnvelope {
            from: "peer".into(),
            to: Some("self-device".into()),
            msg: SignalingMessage::Announce {
                peer_id: format!("p{n}"),
            },
        };
        Arc::new(crate::nostr::event::make_event(
            signer,
            SIGNALING_EPHEMERAL_KIND,
            vec![vec!["r".into(), "test-room".into()]],
            serde_json::to_string(&envelope).unwrap(),
            1_700_000_000,
        ))
    }

    #[test]
    fn outbound_replay_caps_at_limit_evicting_oldest() {
        use std::collections::VecDeque;
        let id = NostrIdentity::generate();
        let now = std::time::Instant::now();
        let mut buf: VecDeque<(std::time::Instant, Arc<NostrEvent>)> = VecDeque::new();
        for n in 0..(OUTBOUND_REPLAY_CAP as u32 + 50) {
            push_outbound_replay(&mut buf, now, test_event(&id, n as u8));
        }
        assert_eq!(
            buf.len(),
            OUTBOUND_REPLAY_CAP,
            "buffer must not grow past the cap"
        );
    }

    #[test]
    fn drain_fresh_outbound_keeps_recent_drops_stale_and_empties() {
        use std::collections::VecDeque;
        let id = NostrIdentity::generate();
        // Use Add (not Sub) to build a reference "now" 60 s ahead of the
        // stale timestamp — avoids any Instant underflow on a freshly
        // booted host while still putting the first event well past the TTL.
        let base = std::time::Instant::now();
        let now = base + Duration::from_secs(60);
        let mut buf: VecDeque<(std::time::Instant, Arc<NostrEvent>)> = VecDeque::new();
        push_outbound_replay(&mut buf, base, test_event(&id, 1)); // 60 s old → stale
        push_outbound_replay(&mut buf, now, test_event(&id, 2)); // fresh
        push_outbound_replay(&mut buf, now, test_event(&id, 3)); // fresh
        let fresh = drain_fresh_outbound(&mut buf, now);
        assert_eq!(fresh.len(), 2, "only the two fresh events should replay");
        assert!(
            buf.is_empty(),
            "drain empties the buffer regardless of which entries were stale"
        );
    }

    fn fixture_shared() -> Arc<DriverShared> {
        let identity = NostrIdentity::generate();
        let (publish_tx, _) = broadcast::channel::<Arc<NostrEvent>>(16);
        let (_out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
        Arc::new(DriverShared {
            identity,
            room_handle: "test-room".into(),
            device_id: "self-device".into(),
            relays: Mutex::new(Vec::new()),
            outbound: tokio::sync::Mutex::new(Some(out_rx)),
            publish_tx,
            force_reconnect: Arc::new(watch::channel(0u64).0),
            seen_event_ids: Mutex::new(std::collections::VecDeque::with_capacity(
                SEEN_EVENT_CAPACITY,
            )),
            outbound_replay: Mutex::new(std::collections::VecDeque::new()),
        })
    }

    /// Build a Nostr `EVENT` frame carrying an Announce envelope
    /// from a fixed peer. The event ID is whatever the signer
    /// produced; we wrap it the same way a relay would so
    /// `handle_inbound_frame` parses it exactly like in production.
    fn announce_frame_for(peer: &str, signer: &NostrIdentity) -> (String, String) {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: None,
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

    /// Same event delivered twice (simulating two relays carrying
    /// the same Nostr event) should produce exactly one inbound
    /// announce on the engine-facing channel. This is the canonical
    /// "Offer-applied-twice wedges WebRTC" regression — see
    /// `upstream.rs` item 6.
    #[test]
    fn duplicate_event_id_only_fires_inbound_once() {
        let shared = fixture_shared();
        let peer_signer = NostrIdentity::generate();
        let peer_pub = peer_signer.pubkey_hex().to_string();
        let (frame, event_id) = announce_frame_for(&peer_pub, &peer_signer);
        let (tx, mut rx) = mpsc::unbounded_channel::<NostrInbound>();

        handle_inbound_frame("wss://relay-a", &frame, &shared, &tx).expect("frame parses");
        handle_inbound_frame("wss://relay-b", &frame, &shared, &tx).expect("dup parses");
        handle_inbound_frame("wss://relay-c", &frame, &shared, &tx).expect("dup parses");

        let first = rx.try_recv().expect("first delivery lands");
        match first {
            NostrInbound::PeerAnnounced { device_id } => assert_eq!(device_id, peer_pub),
            other => panic!("expected PeerAnnounced, got {other:?}"),
        }
        assert!(
            rx.try_recv().is_err(),
            "no second delivery for same event id"
        );

        let seen = shared.seen_event_ids.lock();
        assert!(
            seen.iter().any(|id| id == &event_id),
            "event id recorded in dedupe ring"
        );
    }

    /// Different events from the same peer (e.g. periodic re-announces)
    /// must NOT be deduped — each one is a fresh signal that signaling
    /// is alive. Only relay-replays of the SAME event id should drop.
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
            to: None,
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
        handle_inbound_frame("wss://relay-a", &frame1, &shared, &tx).expect("frame 1 parses");
        handle_inbound_frame("wss://relay-a", &frame2, &shared, &tx).expect("frame 2 parses");

        assert!(matches!(
            rx.try_recv().expect("first announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
        assert!(matches!(
            rx.try_recv().expect("second announce"),
            NostrInbound::PeerAnnounced { .. }
        ));
    }

    /// The dedup ring is bounded so a long-lived mesh doesn't grow
    /// without bound. Past `SEEN_EVENT_CAPACITY` the oldest entries
    /// roll off — a very old event could legitimately re-deliver,
    /// which is fine: at that age it's effectively a fresh event.
    #[test]
    fn seen_ring_bounded_at_capacity() {
        let shared = fixture_shared();
        {
            let mut seen = shared.seen_event_ids.lock();
            for i in 0..SEEN_EVENT_CAPACITY + 50 {
                if seen.len() >= SEEN_EVENT_CAPACITY {
                    seen.pop_front();
                }
                seen.push_back(format!("id-{i}"));
            }
        }
        let seen = shared.seen_event_ids.lock();
        assert_eq!(seen.len(), SEEN_EVENT_CAPACITY);
    }

    /// Build a directed Offer frame from `peer` to `to`, signed by
    /// `signer`, on the given Nostr `kind`. Used to exercise the
    /// presence/negotiation kind guard from both sides.
    fn offer_frame_for(peer: &str, to: &str, signer: &NostrIdentity, kind: u16) -> String {
        let envelope = SignalingEnvelope {
            from: peer.into(),
            to: Some(to.into()),
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

        handle_inbound_frame("wss://relay-a", &frame, &shared, &tx).expect("frame parses");

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

        handle_inbound_frame("wss://relay-a", &frame, &shared, &tx).expect("frame parses");

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
            to: None,
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

        handle_inbound_frame("wss://relay-a", &frame, &shared, &tx).expect("frame parses");

        assert!(
            rx.try_recv().is_err(),
            "an announce on the ephemeral kind must be dropped"
        );
    }
}
