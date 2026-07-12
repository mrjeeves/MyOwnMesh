//! The state-watch **tick registry** — the engine's secondary control path.
//!
//! The engine has two control paths, and the split is deliberate:
//!
//! 1. **Events (primary).** Everything that *drives* state is event-driven and
//!    handled the instant it arrives in the driver loop's `select!`: a
//!    transport event (ICE-state change, data-channel open/close, an inbound
//!    frame), a signaling message (announce, offer, answer, candidate), a
//!    command. Recovery reacts to these immediately — a relay reconnect
//!    flushes reconnect intents, an inbound offer rebuilds, a data-channel
//!    close records an intent. Near-instant in the common case.
//!
//! 2. **Tickers (secondary).** Some conditions are the *absence* of an event —
//!    a data channel that never opened, a restart that never carried traffic,
//!    a reconnect that needs another nudge, a primary-IP that quietly moved.
//!    No event can signal "nothing happened", so a single periodic pass (the
//!    state-watch tick, [`super::scheduler::STATE_WATCH_INTERVAL_MS`]) confirms
//!    everything still looks right and repairs what doesn't.
//!
//! A [`Ticker`] is one such time-based subsystem. The driver builds a
//! [`TickRegistry`] of them at startup and runs the whole set on each tick.
//! New network-intelligence systems (smarter reconnect policy, presence
//! decay, route health, congestion sensing) register here as additional
//! tickers and interact with the engine through the same state + event model
//! the existing ones use — they read [`NetworkState`] and drive recovery via
//! the engine's normal actions, never by holding a lock across an await.
//!
//! In steady state every ticker is a cheap no-op: nothing is in a
//! transitional state, so the registry does no per-peer work.

use std::sync::Arc;

use async_trait::async_trait;

use super::state::NetworkState;

/// One registered, time-based subsystem run on every state-watch tick. Each
/// is self-contained: it inspects [`NetworkState`] and drives recovery
/// through the engine's normal actions. Implementations must return quickly
/// when there's nothing to do (the steady-state case) and must not hold a
/// per-peer lock across an `.await`.
#[async_trait]
pub(crate) trait Ticker: Send {
    /// Stable identifier for logs and diagnostics.
    fn name(&self) -> &'static str;

    /// Run one pass over the current state.
    async fn tick(&mut self, state: &Arc<NetworkState>);
}

/// The ordered set of [`Ticker`]s the driver runs each state-watch tick.
/// Order is registration order; keep it stable so one ticker's repair is
/// observed by the next in the same pass when that matters.
pub(crate) struct TickRegistry {
    tickers: Vec<Box<dyn Ticker>>,
}

impl TickRegistry {
    pub(crate) fn new() -> Self {
        Self {
            tickers: Vec::new(),
        }
    }

    /// Register a subsystem. Builder-style so the driver can assemble the
    /// registry in one expression.
    pub(crate) fn register(mut self, ticker: impl Ticker + 'static) -> Self {
        self.tickers.push(Box::new(ticker));
        self
    }

    /// Run every registered ticker once, in registration order.
    pub(crate) async fn run(&mut self, state: &Arc<NetworkState>) {
        for ticker in self.tickers.iter_mut() {
            ticker.tick(state).await;
        }
    }

    /// Names of the registered tickers, for the startup diagnostic.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.tickers.iter().map(|t| t.name()).collect()
    }
}

/// Time-based ICE recovery: reclaims connect-timeouts, re-drives stalled ICE
/// restarts, verifies restarts carried traffic, and backfills the selected
/// candidate pair. Wraps the cohesive [`super::ice_watchdog`] subsystem — the
/// per-peer conditions there are all "a transition that should have completed
/// by now hasn't".
pub(crate) struct IceWatchdogTicker;

#[async_trait]
impl Ticker for IceWatchdogTicker {
    fn name(&self) -> &'static str {
        "ice-watchdog"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::ice_watchdog::poll_all(state).await;
    }
}

/// Detects a change in the OS's primary outbound IP (Wi-Fi↔cellular handoff,
/// VPN up/down, resume-from-sleep) and kicks the relay-redial + ICE-restart
/// fan-out. Holds the last-seen snapshot as its own state.
pub(crate) struct NetworkWatchTicker {
    watch: super::network_watch::NetworkWatch,
}

impl NetworkWatchTicker {
    pub(crate) async fn new() -> Self {
        Self {
            watch: super::network_watch::NetworkWatch::new().await,
        }
    }
}

#[async_trait]
impl Ticker for NetworkWatchTicker {
    fn name(&self) -> &'static str {
        "network-watch"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        self.watch.poll(state).await;
    }
}

/// Offerer-side reconnect supervisor — the backstop for the reconnect
/// intents events couldn't already resolve. Re-offers each peer we owe an
/// offer to whose backoff has come due, and ages out the ones past the
/// reconnecting grace. The event paths (relay-reconnect flush, inbound
/// announce) handle the common case; this guarantees forward progress when
/// no event arrives.
pub(crate) struct ReconnectSupervisor;

#[async_trait]
impl Ticker for ReconnectSupervisor {
    fn name(&self) -> &'static str {
        "reconnect-supervisor"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::service_reconnect_intents(state).await;
    }
}

/// Connection-shaping pass for pruning topologies — closes
/// both-sides-shelved non-edges and dials missing edges (see
/// `ladder::shape_connections`). Keys on the shelve handshake, which
/// completes asynchronously — a tick is the natural place to observe
/// "both sides have now agreed". No-op for non-pruning modes.
pub(crate) struct TopologyShapeTicker;

#[async_trait]
impl Ticker for TopologyShapeTicker {
    fn name(&self) -> &'static str {
        "topology-shape"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::ladder::shape_connections(state).await;
    }
}

/// Coalesced media renegotiation — one in-place offer per peer whose
/// lane set changed since the last pass (see
/// `engine::service_media_renegotiations`). No-op when no lanes moved.
pub(crate) struct MediaRenegotiationTicker;

#[async_trait]
impl Ticker for MediaRenegotiationTicker {
    fn name(&self) -> &'static str {
        "media-renegotiation"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::service_media_renegotiations(state).await;
    }
}

/// Acked-delivery maintenance — expires lapsed outbox entries (their
/// callers get an error instead of silence) and re-attempts flushes for
/// peers holding unsent frames after a transient send failure. The event
/// paths (enqueue, the ACTIVE transition, inbound acks) drive the common
/// case; this is the no-event backstop, a cheap no-op when every outbox
/// is drained.
pub(crate) struct ReliableSendTicker;

#[async_trait]
impl Ticker for ReliableSendTicker {
    fn name(&self) -> &'static str {
        "reliable-send"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::reliable::tick(state).await;
    }
}
