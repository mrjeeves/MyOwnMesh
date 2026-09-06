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
//!    state-watch tick, configured by `NetworkConfig::scheduler`) confirms
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
    #[cfg(feature = "transport-lab")]
    passes: u64,
}

/// Fixed-size transport-lab correlation metadata for state-watch execution.
/// It contains no peer, payload, or operation history; HubController exposes
/// its own bounded discovery counters alongside this pass count.
#[cfg(feature = "transport-lab")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct TickDiagnostics {
    pub(crate) passes: u64,
    pub(crate) registered_tickers: u64,
}

impl TickRegistry {
    pub(crate) fn new() -> Self {
        Self {
            tickers: vec![
                Box::new(HubTicker),
                Box::new(ParentingTicker),
                Box::new(LocalObservationTicker),
            ],
            #[cfg(feature = "transport-lab")]
            passes: 0,
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
        #[cfg(feature = "transport-lab")]
        {
            self.passes = self.passes.saturating_add(1);
        }
        for ticker in self.tickers.iter_mut() {
            ticker.tick(state).await;
        }
    }

    /// Snapshot bounded tick cadence for transport-lab correlation.  This is
    /// intentionally read-only and does not alter ticker scheduling.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn diagnostics(&self) -> TickDiagnostics {
        TickDiagnostics {
            passes: self.passes,
            registered_tickers: u64::try_from(self.tickers.len()).unwrap_or(u64::MAX),
        }
    }

    /// Names of the registered tickers, for the startup diagnostic.
    pub(crate) fn names(&self) -> Vec<&'static str> {
        self.tickers.iter().map(|t| t.name()).collect()
    }
}

/// Bounded RFC6206 maintenance for the optional configured hub tier.
pub(crate) struct HubTicker;

#[async_trait]
impl Ticker for HubTicker {
    fn name(&self) -> &'static str {
        "hub-advertisement"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        state.poll_hub().await;
    }
}

/// Bounded HubTree parent registration and expiry maintenance.  This shares
/// the existing state-watch cadence and never creates a detached task.
pub(crate) struct ParentingTicker;

#[async_trait]
impl Ticker for ParentingTicker {
    fn name(&self) -> &'static str {
        "hub-tree-parenting"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        state.poll_parenting().await;
    }
}

/// Bounded maintenance for the optional node-local observation aggregate.
/// The graph is diagnostic-only; its refusal path is intentionally ignored.
pub(crate) struct LocalObservationTicker;

#[async_trait]
impl Ticker for LocalObservationTicker {
    fn name(&self) -> &'static str {
        "local-observation"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        state.maintain_local_observation();
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

/// Canonical fact anti-entropy backstop. Event-driven advertisements remain
/// the fast path; this bounded, byte-paged inventory pass repairs a fact lost
/// while a peer's data channel was transiently unavailable. It snapshots exact
/// current owners before each page send and keeps every page context-bound.
pub(crate) struct FactInventoryTicker;

#[async_trait]
impl Ticker for FactInventoryTicker {
    fn name(&self) -> &'static str {
        "fact-inventory"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::governance::broadcast_fact_inventory(state).await;
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

/// Recovery backstop for coalesced renegotiation. The WebRTC
/// `negotiationneeded` callback drives the ordinary path immediately; this
/// pass retries debt that could not run because signaling was not stable or a
/// prior attempt failed. No-op when nothing is pending.
pub(crate) struct MediaRenegotiationTicker;

#[async_trait]
impl Ticker for MediaRenegotiationTicker {
    fn name(&self) -> &'static str {
        "renegotiation"
    }

    async fn tick(&mut self, state: &Arc<NetworkState>) {
        super::service_media_renegotiations(state).await;
    }
}

/// Acked-delivery maintenance — re-attempts flushes for sessions still holding
/// frames that have not reached the wire after a transient send failure.
///
/// Nothing expires here and nothing is expired anywhere: a retained frame ends
/// when the peer acknowledges it or when the session retaining it ends, and this
/// loop is the arbiter of neither. The frames belong to the session, not to a
/// per-device outbox, so there is no queue here to age out and no caller for this
/// tick to answer.
///
/// The event paths — submission, the ACTIVE transition, inbound acknowledgements
/// — drive the common case. This is the no-event backstop, and a cheap no-op once
/// every live session has flushed.
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
