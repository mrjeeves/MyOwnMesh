//! Shared per-network state. Exposes the operations subsystems
//! (`Channel<T>`, `Rpc`, `MeshHandle`) call to interact with the
//! engine; all per-peer state mutation is funneled through the
//! command queue so the driver loop owns serial access.

use std::sync::Arc;

use dashmap::DashMap;
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, mpsc, oneshot, watch};
use tracing::trace;

use crate::channels::RawChannelFrame;
use crate::config::{NetworkConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::events::{DiagEntry, DiagLevel, DropReason, MeshEvent, MeshPhase, PhaseEvent};
use crate::identity::Identity;
use crate::protocol::{rpc::RpcRequestMessage, CapabilityAdvert};
use crate::roster::Roster;
use crate::rpc::RpcInner;
use crate::topology::Topology;
use crate::transport::webrtc::{AudioSample, VideoSample};
use crate::transport::{LocalIceCandidate, Transport, TransportEvent};

use super::conn_trace::ConnTrace;
use super::connection::PeerConnection;
use super::scheduler::{
    RECONNECTING_GRACE_MS, RECONNECT_RETRY_BACKOFF_MS, RELAY_RESCUE_MIN_INTERVAL_MS,
};

/// One assembled video access unit from a peer's track lane, as the
/// embedder-facing subscription surfaces it.
#[derive(Debug, Clone)]
pub struct InboundVideoSample {
    /// The authenticated peer the unit arrived from.
    pub from: String,
    pub sample: VideoSample,
}

/// One audio frame from a peer's track lane, as the engine's
/// subscribers receive it (tagged with the sending peer).
#[derive(Debug, Clone)]
pub struct InboundAudioSample {
    /// Sending peer's device id.
    pub from: String,
    pub sample: AudioSample,
}

/// Bookkeeping for an offerer-side reconnect intent. When we drop a peer we
/// were the *offerer* for (a recoverable `IceFailed`), we keep one of these
/// in [`NetworkState::reconnect_intents`] and the single state-watch tick
/// re-offers on a backoff until the link comes back or `give_up_at` passes.
/// This is the offerer-side counterpart to an answerer recovering from the
/// remote's re-offers — without it, an offerer-role peer that drops on a
/// network shift is never re-offered (it only comes back on the peer's slow
/// steady-state announce). The backoff (`next_retry_at`/`attempt`) keeps the
/// recovery from publishing an offer on every tick — one re-offer per
/// backoff step, never cadence traffic.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectIntent {
    /// Stop retrying after this instant (drop time + `RECONNECTING_GRACE_MS`).
    pub give_up_at: std::time::Instant,
    /// Earliest instant for the next re-offer; advanced by the backoff each
    /// time the tick services this intent.
    pub next_retry_at: std::time::Instant,
    /// Number of re-offers issued so far — indexes `RECONNECT_RETRY_BACKOFF_MS`.
    pub attempt: usize,
}

/// Bump a reconnect intent's backoff after a re-offer: advance the attempt
/// and push `next_retry_at` out by the next step (saturating at the last
/// one). One offer per backoff window — never a per-tick publish.
fn advance_backoff(intent: &mut ReconnectIntent, now: std::time::Instant) {
    let step = RECONNECT_RETRY_BACKOFF_MS
        .get(intent.attempt)
        .copied()
        .or_else(|| RECONNECT_RETRY_BACKOFF_MS.last().copied())
        .unwrap_or(15_000);
    intent.attempt = intent.attempt.saturating_add(1);
    intent.next_retry_at = now + std::time::Duration::from_millis(step);
}

/// Engine command queue entry. Anything that mutates per-peer
/// state, sends a frame, or reconfigures the network goes through
/// here so the driver loop handles it serially.
pub enum NetworkCmd {
    /// Stop the engine and tear down all peer sessions.
    Shutdown,
    /// Switch the topology selector at runtime.
    SetTopology(TopologyMode),
    /// Approve a peer into the roster (and emit the approve frame).
    ApproveRoster {
        device_id: String,
        label: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Remove a peer from the roster and drop any active session.
    RemoveRoster {
        device_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Drop a single peer, surfacing the given reason in the
    /// `Dropped` event.
    DropPeer {
        device_id: String,
        reason: DropReason,
    },
    /// Manually triggered in-place reconnect — the non-destructive twin of a
    /// leave-then-rejoin. `peer == None` reconnects the whole network (redial
    /// signaling + renegotiate ICE with every peer); `peer == Some(id)`
    /// reconnects just that one peer. Nothing is torn down and no `Leave` is
    /// announced, so peers keep their sessions and app-level state — this is
    /// the gentle recovery the GUI's refresh / reconnect controls drive
    /// instead of the old `NetworkRemove` + `NetworkAdd`. See
    /// [`super::network_watch::reconnect_all_in_place`].
    Reconnect { peer: Option<String> },
    /// Send a [`crate::protocol::MeshMessage::Channel`] frame to
    /// one peer.
    SendChannelFrame {
        peer: String,
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Broadcast a channel frame to every active peer.
    BroadcastChannelFrame {
        channel: String,
        payload: serde_json::Value,
        reply: oneshot::Sender<usize>,
    },
    /// Send an RPC request frame to one peer.
    SendRpcRequest {
        peer: String,
        request: RpcRequestMessage,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Push a new capabilities advert to every active peer.
    BroadcastCapabilities {
        caps: CapabilityAdvert,
        reply: oneshot::Sender<usize>,
    },
    /// Per-peer transport event — pumped in from the per-peer
    /// transport task so the driver loop processes everything
    /// serially.
    TransportEvent {
        device_id: String,
        /// Epoch of the [`PeerConnection`](super::connection::PeerConnection)
        /// session this event came from. The driver drops the event if it
        /// no longer matches the peer's current epoch (a stale, torn-down
        /// session still draining its event queue).
        epoch: u64,
        event: TransportEvent,
    },

    // ---- governance (closed networks) ----
    /// Float a new signed transition. The engine signs with the
    /// local identity, persists the proposal to the governance
    /// state's pending list, and broadcasts a
    /// `NetworkStatePropose` to every active peer that supports
    /// `network_state_v1`. Reply carries the new proposal id so
    /// the caller can correlate acks.
    ProposeTransition {
        variant: crate::network_state::TransitionVariant,
        /// Per-device custody second factor, if the network requires one on
        /// this device. `None` when no custody lock is enrolled.
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Sign an existing pending proposal. Verifies the local user
    /// has authority for the variant + that the proposal hasn't
    /// already been signed by this device, then signs and
    /// broadcasts a `NetworkStateAck { decision: Sign }`. If the
    /// signature satisfies the quorum, the engine ratifies the
    /// transition in the same step.
    SignProposal {
        proposal_id: String,
        /// Per-device custody second factor (see `ProposeTransition`).
        mfa_code: Option<String>,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Deny a pending proposal. Any single deny invalidates the
    /// proposal — the engine drops it from pending and broadcasts
    /// the signed deny.
    DenyProposal {
        proposal_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Withdraw a proposal the local device floated. No
    /// broadcast — peers see the proposal disappear via the
    /// next `NetworkState` snapshot.
    WithdrawProposal {
        proposal_id: String,
        reply: oneshot::Sender<Result<()>>,
    },
    /// Proposer-initiated split fallback. Spawns a derived closed
    /// network from the signers the proposer has so far. Reply
    /// carries the derived `network_id` so the caller can join
    /// the new network straight away.
    SpawnSplit {
        proposal_id: String,
        reply: oneshot::Sender<Result<String>>,
    },
    /// Snapshot of the current governance state. Used by the
    /// control protocol to surface live state to the GUI.
    GovernanceSnapshot {
        reply: oneshot::Sender<crate::network_state::NetworkState>,
    },
}

/// Inbound signaling messages from the signaling task.
#[derive(Debug)]
pub enum SignalingInbound {
    PeerAnnounced {
        device_id: String,
    },
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
    PeerLeft {
        device_id: String,
    },
}

/// Outbound signaling messages from the engine to the signaling task.
#[derive(Debug)]
pub enum SignalingOutbound {
    Announce,
    /// Graceful departure broadcast — the dual of [`Announce`]. Tells every
    /// peer in the room to tear our session down *now* instead of waiting
    /// out the heartbeat timeout (~90 s). Emitted on a deliberate leave
    /// (network remove / transport restart / daemon shutdown) so that a
    /// "reconnect" — which is a leave-then-rejoin — doesn't strand peers
    /// holding a dead session whose ICE still falsely reports `Connected`.
    /// Public relays never synthesise a `Leave` for us (only an intelligent
    /// signaling server does), so the departing peer announces its own.
    Leave,
    Offer {
        device_id: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        candidate: LocalIceCandidate,
    },
}

/// The shared state for a single joined network. Every long-lived
/// subsystem (driver loop, channels, rpc, handle) holds an
/// `Arc<NetworkState>`. Internally everything uses non-blocking
/// concurrent primitives (DashMap, RwLock, broadcast) so callers
/// don't serialize on a single lock.
pub struct NetworkState {
    pub network_id: String,
    pub identity: Arc<Identity>,
    pub transport: Transport,

    pub config: RwLock<NetworkConfig>,
    pub topology: RwLock<TopologyMode>,
    pub topology_impl: RwLock<Box<dyn Topology>>,

    pub peers: DashMap<String, Arc<PeerConnection>>,
    pub roster: RwLock<Roster>,
    /// Signed governance state — kind + role assignments + the
    /// append-only signed transition log + pending proposals.
    /// Authority on a `closed` network derives from this; on an
    /// `open` network it's a no-op tracker that ratifies the
    /// open→closed transition if one ever fires.
    ///
    /// The on-disk projection lives at
    /// `~/.myownmesh/mesh/states/{network_id}.json` (per-network,
    /// 0600 on Unix). Loaded once on construction; the engine
    /// persists after every signed transition that lands.
    pub governance_state: RwLock<crate::network_state::NetworkState>,
    pub current_phase: RwLock<MeshPhase>,

    pub events_tx: broadcast::Sender<MeshEvent>,
    pub channel_subscribers: DashMap<String, broadcast::Sender<RawChannelFrame>>,
    /// Fan-out for assembled video access units arriving on peers'
    /// track lanes. One broadcast per network (subscribers filter by
    /// `from`); kept shallow — video is a freshness stream, a lagging
    /// subscriber loses old frames, never delays new ones.
    pub video_subscribers: broadcast::Sender<InboundVideoSample>,
    /// Fan-out for audio frames arriving on peers' audio lanes —
    /// deeper than video's (audio frames are tiny and a dropped one
    /// is an audible tick), still bounded so a lagging subscriber
    /// sheds the oldest instead of growing a backlog.
    pub audio_subscribers: broadcast::Sender<InboundAudioSample>,
    pub rpc: RwLock<Option<Arc<RpcInner>>>,

    pub signaling_tx: mpsc::UnboundedSender<SignalingOutbound>,
    pub signaling_inbound_tx: mpsc::UnboundedSender<SignalingInbound>,
    pub cmd_tx: mpsc::UnboundedSender<NetworkCmd>,

    /// Receiving end of `signaling_tx` — held here so callers can
    /// drain it via [`Self::take_signaling_outbound_rx`] when they
    /// bring up their signaling task.
    signaling_outbound_rx: Mutex<Option<mpsc::UnboundedReceiver<SignalingOutbound>>>,

    /// Offerer-side reconnect intents (see [`ReconnectIntent`]). Keyed by
    /// device id; an entry lives from the moment we drop a peer we owe an
    /// offer to until the link is re-established or the reconnecting grace
    /// expires. Events re-offer these immediately (relay reconnect, the
    /// peer's announce); the state-watch tick is the backstop that retries
    /// on a backoff for the cases no event covers.
    pub reconnect_intents: Mutex<std::collections::HashMap<String, ReconnectIntent>>,

    /// Last time we reflected a peer's announce with one of our
    /// own. Rate-limited so a room with N peers all reacting to
    /// each other's announces doesn't degenerate into a publish
    /// storm — one outbound reactive announce per
    /// [`REACTIVE_ANNOUNCE_MIN_INTERVAL_MS`] coalesces any number
    /// of inbound announces in that window. See the comment on
    /// the call site in `engine::mod::handle_signaling_inbound`
    /// for the discovery rationale.
    pub last_reactive_announce_at: Mutex<Option<std::time::Instant>>,

    /// Latched state of the passive clock-skew diagnostic — warn once when
    /// this device's wall clock has disagreed with its peers' (measured off
    /// the heartbeat pings they already send) for several consecutive
    /// ticks, clear once when it resolves. See `heartbeat::watch_clock_skew`.
    pub clock_skew_watch: Mutex<super::heartbeat::ClockSkewWatch>,

    /// Force-reconnect handle for the signaling driver, stashed by
    /// [`crate::engine::signaling_bridge::attach_nostr`] once the
    /// Nostr driver is up. Bumping the generation makes every relay
    /// drop its socket and redial immediately (see the driver's
    /// `force_reconnect`); the engine triggers it on resume-from-sleep
    /// so a zombie relay socket is replaced at once rather than after
    /// the kernel's multi-minute TCP timeout. `None` when no driver is
    /// attached (e.g. the in-process local broker used in tests).
    relay_reconnect: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// The signaling driver's relay-connected generation (its
    /// `relay_connected`); bumped on every fresh relay session. After a
    /// network change asks for a redial, the change handler waits for the
    /// next bump before renegotiating ICE, so the offer isn't published into
    /// a relay that hasn't reconnected yet. `None` when no driver is attached.
    relay_connected: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// Last time the ICE-failure path forced a relay redial via
    /// [`request_relay_reconnect_throttled`]. Gates the "no remote
    /// candidates arrived" rescue (see
    /// `ice_watchdog::on_checking_timeout`) so a peer that keeps timing
    /// out every `ICE_CHECKING_TIMEOUT_MS` can't redial the relays on
    /// every cycle — one redial per
    /// [`RELAY_RESCUE_MIN_INTERVAL_MS`] window is enough to recover a
    /// genuinely-wedged signaling socket without churning healthy ones.
    last_relay_rescue_at: Mutex<Option<std::time::Instant>>,

    /// Set by the network watcher when the OS reports *no* primary
    /// outbound IP (neither v4 nor v6) — i.e. the host is fully
    /// offline, the state macOS lands in for a second or two on wake
    /// before the interface comes back. While true, the ICE machinery
    /// holds off re-gathering and tearing down peers: a `restart_ice()`
    /// in this window can't bind a socket (the `Network is unreachable`
    /// wall in the logs) and would only burn a checking-timeout on a
    /// doomed attempt. Cleared the moment an interface returns, at which
    /// point the network-change handler drives a clean restart fan-out.
    offline: std::sync::atomic::AtomicBool,

    /// Broadcast of per-peer connection-state transitions for the
    /// Phase-0 connection tracer (`engine::conn_trace`). Kept separate
    /// from `events_tx` so trace volume can never evict real Peer /
    /// Phase events from the GUI's subscriber, and so `receiver_count()`
    /// cleanly reflects whether anyone is watching — which is what gates
    /// the sweep's cost in the driver loop.
    pub conn_trace_tx: broadcast::Sender<ConnTrace>,
    /// When true, the connection tracer emits even with no live
    /// subscriber, so daemon file logs capture transitions. Read once
    /// from `MYOWNMESH_CONN_TRACE` at construction (any non-empty value
    /// other than `0` enables it).
    conn_trace_force_on: bool,
}

impl NetworkState {
    /// Construct a new network state. Returns the state plus the
    /// inbound signaling receiver and the command-queue receiver
    /// the driver consumes.
    #[allow(clippy::type_complexity)]
    pub fn new(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
    ) -> Result<(
        Arc<Self>,
        mpsc::UnboundedReceiver<SignalingInbound>,
        mpsc::UnboundedReceiver<NetworkCmd>,
    )> {
        let topology_impl = crate::topology::from_mode(&config.topology);
        let roster = crate::roster::load(&config.network_id)?;
        // Load (or initialise) the per-network signed state log. If
        // the config requests Closed kind but the on-disk log says
        // Open (or vice-versa), the on-disk log wins — kind is
        // authoritatively a signed-state property, not a config one.
        // The config field only seeds new networks at first attach.
        let governance_state = {
            let mut s = crate::network_state::load(&config.network_id)?;
            if s.transitions.is_empty() && s.kind == crate::network_state::NetworkKind::Open {
                // Brand-new state log — adopt the config's initial
                // kind. (For the open default, this is a no-op; for
                // Closed, the engine emits the founder-self-election
                // transition on first ACTIVE.)
                s.kind = config.kind;
            }
            s
        };
        let (events_tx, _) = broadcast::channel(256);
        // Shallow: at 30 fps a depth of 16 is half a second of slack —
        // beyond that a slow consumer should lose frames, not delay them.
        let (video_subscribers, _) = broadcast::channel(16);
        let (audio_subscribers, _) = broadcast::channel(64);
        // Deep enough to ride out a transition storm (a sleep/wake
        // fan-out re-handshaking every peer) without the watcher lagging;
        // lossy past that, with a `lagged` marker surfaced to the stream.
        let (conn_trace_tx, _) = broadcast::channel(512);
        let conn_trace_force_on = std::env::var("MYOWNMESH_CONN_TRACE")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        let (signaling_tx, signaling_outbound_rx) = mpsc::unbounded_channel();
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel();
        let (signaling_inbound_tx, signaling_inbound_rx) = mpsc::unbounded_channel();
        let state = Arc::new(Self {
            network_id: config.network_id.clone(),
            identity,
            transport,
            config: RwLock::new(config.clone()),
            topology: RwLock::new(config.topology.clone()),
            topology_impl: RwLock::new(topology_impl),
            peers: DashMap::new(),
            roster: RwLock::new(roster),
            governance_state: RwLock::new(governance_state),
            current_phase: RwLock::new(MeshPhase::Joining),
            events_tx,
            channel_subscribers: DashMap::new(),
            video_subscribers,
            audio_subscribers,
            rpc: RwLock::new(None),
            signaling_tx,
            signaling_inbound_tx,
            cmd_tx,
            signaling_outbound_rx: Mutex::new(Some(signaling_outbound_rx)),
            reconnect_intents: Mutex::new(std::collections::HashMap::new()),
            last_reactive_announce_at: Mutex::new(None),
            clock_skew_watch: Mutex::new(super::heartbeat::ClockSkewWatch::default()),
            relay_reconnect: Mutex::new(None),
            relay_connected: Mutex::new(None),
            last_relay_rescue_at: Mutex::new(None),
            offline: std::sync::atomic::AtomicBool::new(false),
            conn_trace_tx,
            conn_trace_force_on,
        });
        Ok((state, signaling_inbound_rx, cmd_rx))
    }

    /// Take the outbound signaling receiver so the signaling task
    /// can drain it. Only one consumer is supported; subsequent
    /// calls return `None`.
    pub fn take_signaling_outbound_rx(
        self: &Arc<Self>,
    ) -> Option<mpsc::UnboundedReceiver<SignalingOutbound>> {
        self.signaling_outbound_rx.lock().take()
    }

    /// Remember that we owe `device_id` a fresh offer after a recoverable
    /// drop, so the engine self-drives the reconnect instead of waiting for
    /// the peer's slow steady-state announce. The *first* drop opens the
    /// grace window; subsequent drops while the intent is still live (a failed
    /// rebuild that never opened a channel) deliberately do NOT extend it, so
    /// a peer that never comes back ages out at the grace instead of spinning
    /// forever. A genuine reconnect clears the intent
    /// ([`clear_reconnect_intent`](Self::clear_reconnect_intent) on
    /// `DataChannelOpen`), so the next loss opens a fresh window.
    pub fn record_reconnect_intent(&self, device_id: &str) {
        let now = std::time::Instant::now();
        self.reconnect_intents
            .lock()
            .entry(device_id.to_string())
            .or_insert(ReconnectIntent {
                give_up_at: now + std::time::Duration::from_millis(RECONNECTING_GRACE_MS),
                next_retry_at: now,
                attempt: 0,
            });
    }

    /// Forget a reconnect intent — the link is back (or the peer was
    /// explicitly removed). Cheap no-op if none was held.
    pub fn clear_reconnect_intent(&self, device_id: &str) {
        self.reconnect_intents.lock().remove(device_id);
    }

    /// Whether we're currently holding a reconnect intent for this peer.
    pub fn has_reconnect_intent(&self, device_id: &str) -> bool {
        self.reconnect_intents.lock().contains_key(device_id)
    }

    /// Intent ids whose backoff is due now. Drops expired intents (past the
    /// reconnecting grace) and advances the backoff of the ones returned, so
    /// the state-watch tick re-offers each at most once per backoff step.
    pub fn due_reconnect_intents(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| now < i.give_up_at);
        let mut due = Vec::new();
        for (id, intent) in map.iter_mut() {
            if now >= intent.next_retry_at {
                due.push(id.clone());
                advance_backoff(intent, now);
            }
        }
        due
    }

    /// All live intent ids, with their backoff advanced. Used when a strong
    /// event — a relay reconnect after a network shift — makes it worth
    /// re-offering everything we owe at once, rather than waiting for each
    /// one's backoff to come due on the tick.
    pub fn flush_reconnect_intents(&self) -> Vec<String> {
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| now < i.give_up_at);
        for intent in map.values_mut() {
            advance_backoff(intent, now);
        }
        map.keys().cloned().collect()
    }

    /// Register the signaling driver's force-reconnect signal. Called
    /// once when the Nostr driver is attached.
    pub fn set_relay_reconnect(&self, signal: Arc<watch::Sender<u64>>) {
        *self.relay_reconnect.lock() = Some(signal);
    }

    /// Register the signaling driver's relay-connected signal (its
    /// `relay_connected` generation). Called once when the Nostr driver is
    /// attached, alongside [`set_relay_reconnect`].
    pub fn set_relay_connected_signal(&self, signal: Arc<watch::Sender<u64>>) {
        *self.relay_connected.lock() = Some(signal);
    }

    /// A receiver for the relay-connected generation, or `None` when no
    /// driver is attached (tests, the in-process broker). Callers
    /// `borrow_and_update()` to set a baseline, then `changed()` to wait for
    /// the next fresh relay session.
    pub fn relay_connected_rx(&self) -> Option<watch::Receiver<u64>> {
        self.relay_connected.lock().as_ref().map(|s| s.subscribe())
    }

    /// Ask every relay to drop its socket and redial immediately,
    /// skipping the backoff. Returns `true` if a driver was attached
    /// to receive the request. Used on resume-from-sleep so the node
    /// stops being invisible the moment it wakes instead of waiting
    /// for a stale socket to time out. Cheap and idempotent — bumps a
    /// `watch` generation the relay tasks observe.
    pub fn request_relay_reconnect(&self) -> bool {
        match self.relay_reconnect.lock().as_ref() {
            Some(signal) => {
                signal.send_modify(|gen| *gen = gen.wrapping_add(1));
                true
            }
            None => false,
        }
    }

    /// Like [`request_relay_reconnect`], but throttled to at most one
    /// redial per [`RELAY_RESCUE_MIN_INTERVAL_MS`]. This is the rescue
    /// path for the "ICE timed out with zero remote candidates"
    /// fingerprint — the peer's candidates never crossed the relay, which
    /// is almost always a relay socket that went stale after a network
    /// blip (held open for minutes because the kernel never saw a
    /// FIN/RST). Unlike the bare redial, this fires *even when other peers
    /// are still up*: a wedged relay socket starves candidate delivery for
    /// every peer, not just one, so gating on "no other live peer" (the
    /// old behavior) left the wedge in place whenever the room wasn't
    /// completely dark. The throttle is what makes that safe — a peer
    /// stuck re-timing-out every `ICE_CHECKING_TIMEOUT_MS` can still only
    /// bounce the relays once per window.
    ///
    /// Returns `true` when a redial was actually issued (driver attached
    /// *and* past the throttle), `false` when suppressed — callers log the
    /// distinction so the rescue's decisions are visible in diagnostics.
    pub fn request_relay_reconnect_throttled(&self) -> bool {
        let now = std::time::Instant::now();
        {
            let mut guard = self.last_relay_rescue_at.lock();
            let due = guard
                .map(|prev| {
                    now.duration_since(prev)
                        >= std::time::Duration::from_millis(RELAY_RESCUE_MIN_INTERVAL_MS)
                })
                .unwrap_or(true);
            if !due {
                return false;
            }
            *guard = Some(now);
        }
        self.request_relay_reconnect()
    }

    /// Record whether the host currently has any primary outbound IP.
    /// Called by the network watcher each time the snapshot changes.
    /// Returns the previous value so the caller can detect the
    /// online→offline / offline→online edges.
    pub fn set_offline(&self, offline: bool) -> bool {
        self.offline
            .swap(offline, std::sync::atomic::Ordering::Relaxed)
    }

    /// True while the host has no primary outbound IP. The ICE
    /// machinery checks this to avoid re-gathering or dropping peers
    /// during a brief network outage (see `set_offline`).
    pub fn is_offline(&self) -> bool {
        self.offline.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Emit a top-level mesh event. Silently drops if no
    /// subscribers — the broadcast channel returns an error on
    /// every send-with-zero-listeners, and we'd rather log nothing
    /// than spam on every emit.
    pub fn emit(&self, event: MeshEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Subscribe to this network's connection-state transition trace.
    /// The control socket's `trace_subscribe` op hands the receiver to
    /// a `ctl trace` client; subscribing is also what flips
    /// [`conn_trace_enabled`](Self::conn_trace_enabled) on, so the
    /// driver's sweep starts emitting.
    pub fn subscribe_conn_trace(&self) -> broadcast::Receiver<ConnTrace> {
        self.conn_trace_tx.subscribe()
    }

    /// Whether the connection tracer should do any work this sweep.
    /// True when forced on via `MYOWNMESH_CONN_TRACE`, or when at least
    /// one subscriber is attached. The driver loop checks this first so
    /// the production path with no observer pays only one atomic load.
    pub fn conn_trace_enabled(&self) -> bool {
        self.conn_trace_force_on || self.conn_trace_tx.receiver_count() > 0
    }

    /// Emit one connection-state trace record. Lossy like
    /// [`emit`](Self::emit) — drops if there is no subscriber.
    pub fn emit_conn_trace(&self, trace: ConnTrace) {
        let _ = self.conn_trace_tx.send(trace);
    }

    /// Emit a structured diagnostic — both to the tracing layer
    /// (visible in daemon stderr) and to the broadcast channel as
    /// a [`MeshEvent::Diag`] (consumed by the GUI's Activity tab).
    /// Prefer this over a bare `tracing::info!`/`warn!` for events
    /// the user should see in the UI; the helper writes to both
    /// surfaces so operators reading logs and users watching the
    /// GUI stay in sync.
    pub fn log_diag(&self, level: DiagLevel, category: &str, message: impl Into<String>) {
        self.log_diag_with(level, category, message, serde_json::Value::Null);
    }

    /// Variant of [`log_diag`] that carries a structured `detail`
    /// payload alongside the message. Use for events where the GUI
    /// might want to drill into fields (peer id, error code, etc.)
    /// rather than just render the human-readable line.
    pub fn log_diag_with(
        &self,
        level: DiagLevel,
        category: &str,
        message: impl Into<String>,
        detail: serde_json::Value,
    ) {
        let message = message.into();
        // Console line reads "category: message" — clean, demo-like, no
        // field-suffix clutter. The structured network_id + category still
        // ride the MeshEvent::Diag below for the GUI; only the console
        // rendering is simplified.
        match level {
            DiagLevel::Debug => tracing::debug!("{category}: {message}"),
            DiagLevel::Info => tracing::info!("{category}: {message}"),
            DiagLevel::Warn => tracing::warn!("{category}: {message}"),
            DiagLevel::Error => tracing::error!("{category}: {message}"),
        }
        self.emit(MeshEvent::Diag(DiagEntry {
            ts: now_unix_ms(),
            network_id: self.network_id.clone(),
            level,
            category: category.to_string(),
            message,
            detail,
        }));
    }

    /// Update the per-network phase and emit on change.
    pub fn set_phase(&self, next: MeshPhase) {
        let mut current = self.current_phase.write();
        let prev = *current;
        if prev == next {
            return;
        }
        *current = next;
        drop(current);
        self.emit(MeshEvent::Phase(PhaseEvent::Changed {
            network_id: self.network_id.clone(),
            prev,
            next,
        }));
        self.log_diag(DiagLevel::Info, "phase", format!("{prev:?} → {next:?}"));
    }

    /// Subscribe to a named user channel. Returns a fresh
    /// broadcast::Receiver every call; the engine fan-outs each
    /// inbound channel frame to all subscribers.
    pub fn subscribe_channel(&self, name: &str) -> broadcast::Receiver<RawChannelFrame> {
        if let Some(tx) = self.channel_subscribers.get(name) {
            tx.subscribe()
        } else {
            let (tx, rx) = broadcast::channel(256);
            self.channel_subscribers.insert(name.to_string(), tx);
            rx
        }
    }

    /// Engine-side dispatch: route an inbound channel frame to
    /// the matching subscribers. Silently drops when no
    /// subscribers are registered for the named channel.
    pub fn dispatch_channel_frame(&self, name: &str, from: &str, payload: serde_json::Value) {
        if let Some(tx) = self.channel_subscribers.get(name) {
            let frame = RawChannelFrame {
                from: from.to_string(),
                payload,
            };
            let _ = tx.send(frame);
        } else {
            trace!(channel = name, "no subscriber for channel frame");
        }
    }

    /// Subscribe to assembled video access units from every peer on
    /// this network (filter by [`InboundVideoSample::from`]). Lagging
    /// loses old frames, never delays new ones — video is freshness.
    pub fn subscribe_video(&self) -> broadcast::Receiver<InboundVideoSample> {
        self.video_subscribers.subscribe()
    }

    /// Engine-side dispatch: fan an assembled access unit out to the
    /// video subscribers. Silently drops with none registered.
    pub fn dispatch_video(&self, from: &str, sample: VideoSample) {
        let _ = self.video_subscribers.send(InboundVideoSample {
            from: from.to_string(),
            sample,
        });
    }

    /// Write one encoded H.264 access unit (Annex-B) onto the video
    /// lane to `peer`. `duration` paces the RTP clock (1/fps). Errors
    /// when the peer is unknown or its session isn't established;
    /// writes on a lane the peer never consumes are simply discarded
    /// by the far side.
    pub async fn send_video_sample(
        &self,
        peer: &str,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let session = {
            let Some(p) = self.peers.get(peer) else {
                return Err(Error::Network(format!("peer not found: {peer}")));
            };
            let session = p.session.lock().clone();
            session
        };
        let session =
            session.ok_or_else(|| Error::Transport("session not yet established".into()))?;
        session.send_video(lane, data, duration).await
    }

    /// Subscribe to audio frames from every peer on this network
    /// (filter by [`InboundAudioSample::from`]). Lagging loses old
    /// frames, never delays new ones — live audio is freshness too.
    pub fn subscribe_audio(&self) -> broadcast::Receiver<InboundAudioSample> {
        self.audio_subscribers.subscribe()
    }

    /// Engine-side dispatch: fan an audio frame out to the audio
    /// subscribers. Silently drops with none registered.
    pub fn dispatch_audio(&self, from: &str, sample: AudioSample) {
        let _ = self.audio_subscribers.send(InboundAudioSample {
            from: from.to_string(),
            sample,
        });
    }

    /// Write one encoded Opus frame onto the audio lane to `peer`.
    /// `duration` is the frame length (20 ms canonically) — it paces
    /// the RTP clock. Same contract as [`Self::send_video_sample`].
    pub async fn send_audio_sample(
        &self,
        peer: &str,
        lane: u8,
        data: bytes::Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let session = {
            let Some(p) = self.peers.get(peer) else {
                return Err(Error::Network(format!("peer not found: {peer}")));
            };
            let session = p.session.lock().clone();
            session
        };
        let session =
            session.ok_or_else(|| Error::Transport("session not yet established".into()))?;
        session.send_audio(lane, data, duration).await
    }

    /// Send a channel frame to one peer via the command queue.
    /// Used by [`crate::Channel::send_to`].
    pub async fn send_channel_frame(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelFrame {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a channel frame to every active peer. Returns
    /// the count of peers it was dispatched to.
    pub async fn broadcast_channel_frame(
        &self,
        channel: &str,
        payload: serde_json::Value,
    ) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastChannelFrame {
                channel: channel.to_string(),
                payload,
                reply,
            })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Send an RPC request to one peer. Lower-level than the
    /// `Rpc` facade; `Rpc::call` builds the request, registers
    /// the pending entry, and then calls this.
    pub async fn send_rpc_request(&self, peer: &str, request: RpcRequestMessage) -> Result<()> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendRpcRequest {
                peer: peer.to_string(),
                request,
                reply,
            })
            .map_err(|_| Error::Network("engine command queue closed".into()))?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a capabilities update to every active peer.
    pub async fn broadcast_capabilities(&self, caps: CapabilityAdvert) -> usize {
        let (reply, rx) = oneshot::channel();
        if self
            .cmd_tx
            .send(NetworkCmd::BroadcastCapabilities { caps, reply })
            .is_err()
        {
            return 0;
        }
        rx.await.unwrap_or(0)
    }

    /// Persist `device_id` into the per-network roster. Does NOT
    /// transition any active session — call
    /// [`crate::engine::handshake::send_local_approve`] (or the
    /// higher-level [`crate::JoinedNetwork::roster_approve`])
    /// to actually emit the `approve` frame.
    pub async fn approve_roster(&self, device_id: &str, label: &str) -> Result<()> {
        let mut roster = self.roster.write();
        crate::roster::add_peer_in(&mut roster, device_id, label);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// Remove a peer from the roster and tear down any session.
    pub async fn remove_roster(&self, device_id: &str) -> Result<()> {
        let mut roster = self.roster.write();
        crate::roster::remove_peer_in(&mut roster, device_id);
        crate::roster::save(&roster)?;
        Ok(())
    }

    /// True if the peer is currently in the roster.
    pub fn is_rostered(&self, device_id: &str) -> bool {
        crate::roster::is_authorized(&self.roster.read(), device_id)
    }

    /// Total count of peers in any state.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Snapshot the current per-peer view as an owned list. The
    /// engine drops behind the lock during this call; callers
    /// should treat the snapshot as instantaneous and re-fetch
    /// for fresh data.
    pub fn peer_snapshot(&self) -> Vec<crate::handle::PeerInfo> {
        self.peers
            .iter()
            .map(|e| {
                let device_id = e.key().clone();
                let data = e.value().state.read();
                let pubkey = crate::signing::pubkey_part(&device_id);
                let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
                crate::handle::PeerInfo {
                    device_id: device_id.clone(),
                    status: data.status,
                    tier: data.tier,
                    rtt_ms: data.rtt_ms,
                    clock_skew_ms: data.clock_skew_ms,
                    label: data.label.clone(),
                    capabilities: data.capabilities.clone(),
                    local_shelved: data.local_shelved,
                    remote_shelved: data.remote_shelved,
                    authenticated: data.authenticated,
                    device_suffix,
                    verification_code_received: data.verification_code_received.clone(),
                    verification_code_sent: data.verification_code_sent.clone(),
                    local_approve_sent: data.local_approve_sent,
                    remote_approve_seen: data.remote_approve_seen,
                    needs_turn: data.no_turn_diag_emitted,
                    local_candidates: data.diag.local_candidates.clone(),
                    remote_candidates: data.diag.remote_candidates.clone(),
                    selected_pair: data.selected_pair,
                }
            })
            .collect()
    }

    /// Per-peer detail. Returns `None` if the peer is not in the
    /// engine's map.
    pub fn peer_info(&self, device_id: &str) -> Option<crate::handle::PeerInfo> {
        let peer = self.peers.get(device_id)?;
        let data = peer.state.read();
        let pubkey = crate::signing::pubkey_part(device_id);
        let device_suffix = crate::identity::display_suffix(pubkey.as_bytes());
        Some(crate::handle::PeerInfo {
            device_id: device_id.to_string(),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            clock_skew_ms: data.clock_skew_ms,
            label: data.label.clone(),
            capabilities: data.capabilities.clone(),
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix,
            verification_code_received: data.verification_code_received.clone(),
            verification_code_sent: data.verification_code_sent.clone(),
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.no_turn_diag_emitted,
            local_candidates: data.diag.local_candidates.clone(),
            remote_candidates: data.diag.remote_candidates.clone(),
            selected_pair: data.selected_pair,
        })
    }

    /// Tear down every active peer session. Called from the
    /// driver's shutdown path.
    pub async fn shutdown(&self) {
        let sessions: Vec<_> = self
            .peers
            .iter()
            .filter_map(|e| e.value().session.lock().clone())
            .collect();
        for s in sessions {
            let _ = s.close().await;
        }
        self.peers.clear();
    }

    /// Broadcast a graceful departure so peers drop our session immediately
    /// rather than waiting out the ~90 s heartbeat timeout. Fire-and-forget,
    /// like every other signaling publish: the message is handed to the
    /// signaling driver and rides the relays best-effort. Callers tearing
    /// the network down (see [`crate::JoinedNetwork::announce_leave`]) should
    /// emit this *before* dropping the signaling driver and give it a brief
    /// moment to reach the relays.
    pub fn announce_departure(&self) {
        let _ = self.signaling_tx.send(SignalingOutbound::Leave);
    }

    /// Queue an in-place reconnect on the engine driver — redial signaling and
    /// renegotiate ICE without leaving the room. `peer == None` reconnects
    /// every peer on this network; `peer == Some(id)` reconnects just that one.
    /// The non-destructive twin of [`Self::announce_departure`] + rejoin: no
    /// `Leave` is announced and no session is torn down, so peers keep their
    /// connections and app-level state. The actual work runs on the driver via
    /// [`NetworkCmd::Reconnect`] so it's serialized with every other per-peer
    /// mutation. See [`super::network_watch::reconnect_all_in_place`].
    pub fn reconnect(&self, peer: Option<String>) {
        let _ = self.cmd_tx.send(NetworkCmd::Reconnect { peer });
    }
}

/// Unix epoch milliseconds. Stamped on every [`DiagEntry`] so the
/// GUI's Activity log can render a per-entry HH:MM:SS clock — wall
/// time, not monotonic: the user cares what time it actually was
/// when something happened, not how long after process start.
pub(crate) fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}
