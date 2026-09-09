//! Per-peer connection state held by the engine.
//!
//! Each entry in the engine's `peers` map is a [`PeerConnection`]:
//! the shared [`PeerStateData`] (status, tier, watermarks,
//! capabilities) plus the optional WebRTC connector worker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::protocol::CapabilityAdvert;
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};
use crate::transport::{PeerDiag, SelectedCandidatePair, WebRtcConnectorWorker};

use super::ladder::ConnectionTier;
use crate::runtime::attempt::AttemptOwnerSet;
use crate::runtime::peer_session::{
    DedupToken, DetachedDedupSet, PromotedChannelBinding, PromotedDedupDrain, PromotedDedupSet,
};

/// Fixed inline storage for one peer's rolling clock-skew samples.
///
/// The window size is the existing heartbeat policy window. Keeping the
/// samples beside the peer state avoids a heap allocation on every admitted
/// ping while retaining the same newest-last eviction order.
#[derive(Debug)]
pub struct ClockSkewSamples {
    values: [i64; SKEW_WINDOW],
    len: usize,
}

pub(super) const SKEW_WINDOW: usize = 5;

/// Application-use accounting for one demand-owned exact connection. The
/// NetworkState entry owns the peer token and funding; this inline state is
/// neither a peer selector nor a second session/flow registry. Heartbeats and
/// discovery never call it. Reserving retirement fences subsequent app work
/// while the caller checks the exact session's real queues and flow owners.
pub(super) struct DemandLinkActivity {
    active: u64,
    last_use: Instant,
    retiring: bool,
}

impl DemandLinkActivity {
    pub(super) fn new(now: Instant) -> Self {
        Self {
            active: 0,
            last_use: now,
            retiring: false,
        }
    }

    pub(super) fn begin(&mut self, now: Instant) -> bool {
        if self.retiring || now < self.last_use {
            return false;
        }
        let Some(active) = self.active.checked_add(1) else {
            return false;
        };
        self.active = active;
        self.last_use = now;
        true
    }

    pub(super) fn finish(&mut self, now: Instant) {
        // An unpaired finish must not make a busy connection appear idle.
        if self.active == 0 {
            self.retiring = true;
            return;
        }
        self.active -= 1;
        if now < self.last_use {
            self.retiring = true;
        } else {
            self.last_use = now;
        }
    }

    pub(super) fn reserve_idle(&mut self, now: Instant, idle: std::time::Duration) -> bool {
        if idle.is_zero() || self.retiring || self.active != 0 {
            return false;
        }
        let Some(elapsed) = now.checked_duration_since(self.last_use) else {
            return false;
        };
        if elapsed < idle {
            return false;
        }
        self.retiring = true;
        true
    }

    pub(super) fn cancel_idle(&mut self) {
        // Only an exact reservation guard may undo its own idle reservation.
        self.retiring = false;
    }

    pub(super) fn idle_reserved(&self) -> bool {
        self.retiring && self.active == 0
    }
}

#[cfg(test)]
mod demand_link_activity_controls {
    use super::DemandLinkActivity;
    use std::time::{Duration, Instant};

    #[test]
    fn demand_idle_requires_zero_use_and_exact_deadline() {
        let start = Instant::now();
        let idle = Duration::from_secs(4);
        let mut activity = DemandLinkActivity::new(start);
        assert!(activity.begin(start));
        assert!(!activity.reserve_idle(start + idle, idle));
        activity.finish(start + idle);
        assert!(!activity.reserve_idle(start + idle + idle - Duration::from_millis(1), idle));
        assert!(activity.reserve_idle(start + idle + idle, idle));
        assert!(activity.idle_reserved());
        assert!(!activity.begin(start + idle + idle));
        activity.cancel_idle();
        assert!(!activity.idle_reserved());
        assert!(activity.begin(start + idle + idle));
    }

    #[test]
    fn demand_activity_refuses_clock_regression_and_count_exhaustion() {
        let start = Instant::now();
        let later = start + Duration::from_secs(1);
        let mut activity = DemandLinkActivity::new(later);
        assert!(!activity.begin(start));
        assert!(!activity.reserve_idle(start, Duration::from_secs(1)));
        activity.active = u64::MAX;
        assert!(!activity.begin(later));
        assert!(!activity.reserve_idle(later + Duration::from_secs(10), Duration::from_secs(1)));
    }

    #[test]
    fn independent_demand_owner_never_inherits_old_activity() {
        let start = Instant::now();
        let idle = Duration::from_secs(1);
        let mut old = DemandLinkActivity::new(start);
        let mut successor = DemandLinkActivity::new(start);
        assert!(old.begin(start));
        assert!(successor.begin(start));
        old.finish(start);
        assert!(old.reserve_idle(start + idle, idle));
        assert!(old.idle_reserved());
        assert!(!successor.idle_reserved());
        assert!(!successor.reserve_idle(start + idle, idle));
    }
}

impl Default for ClockSkewSamples {
    fn default() -> Self {
        Self {
            values: [0; SKEW_WINDOW],
            len: 0,
        }
    }
}

impl ClockSkewSamples {
    pub(super) fn push(&mut self, sample: i64) {
        if self.len < SKEW_WINDOW {
            self.values[self.len] = sample;
            self.len += 1;
        } else {
            self.values.copy_within(1.., 0);
            self.values[SKEW_WINDOW - 1] = sample;
        }
    }

    pub(super) fn as_slice(&self) -> &[i64] {
        &self.values[..self.len]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerStatus {
    /// Signaling has surfaced the peer; transport is being
    /// brought up.
    Sighted,
    /// Data channel is open; hello/auth_response in flight.
    Handshaking,
    /// Auth verified; awaiting user (or auto-roster) approval.
    PendingApproval,
    /// Both sides have exchanged `approve`; app traffic flows.
    Active,
    /// Active connection demoted by the topology selector. The
    /// data channel stays open as a heartbeat path.
    Shelved,
    /// Connection dropped; reconnect attempts in progress.
    Reconnecting,
    /// Connection torn down. The engine retains the entry only
    /// briefly so an immediate reconnect can short-circuit
    /// approval.
    Offline,
    /// Fatal error — peer is excluded until user intervention.
    Error,
}

#[derive(Debug)]
pub struct PeerStateData {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub authenticated: bool,
    /// Attempt-owned funding for the peer-supplied Hello representation kept
    /// here until this connector is retired. This is deliberately not copied
    /// into snapshots: it is ownership, not diagnostic state.
    pub(crate) hello_retention: Option<crate::resource::ResourceLease>,
    /// True after the exact current data channel accepts our `Approve` bytes
    /// for transmission. This does not prove remote receipt.
    pub local_approve_sent: bool,
    /// True only after this exact peer sends us an inbound `Approve`.
    pub remote_approve_seen: bool,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub label: String,
    /// The short codes the two endpoints display for out-of-band comparison.
    ///
    /// Presentation only. Neither is an authentication input: the Endpoint Auth
    /// Task owns the contributions the transcript is built from, so nothing a
    /// later frame writes here can move a proof.
    pub verification_code_sent: Option<String>,
    pub verification_code_received: Option<String>,
    pub last_recv_at: Option<Instant>,
    pub last_ping_sent_at: Option<Instant>,
    /// Wall-clock of the most recent SDP offer we sent for this
    /// peer (either the original from `ensure_peer_session` or a
    /// re-poke from `handle_signaling_inbound`). Used to rate-
    /// limit the announce-driven re-offer path so a burst of
    /// inbound announces (e.g. REQ-replay delivering 14 stored
    /// announces in one ms) doesn't translate into 14 outbound
    /// offers. `None` until we've sent the first offer for this
    /// session; cleared on `drop_peer`.
    pub last_offer_sent_at: Option<Instant>,
    /// Wall-clock of the most recent announce-driven liveness probe we
    /// fired for this peer. When a peer we believe is connected re-announces
    /// but its inbound has gone silent, we ping it and rebuild if no traffic
    /// confirms the link (see `confirm_active_session_on_announce`). This
    /// single-flights that probe so an announce burst (REQ replay) can't
    /// stack a dozen probe tasks on one peer. `None` until the first probe;
    /// cleared with the rest of the state on `drop_peer` (a rebuild starts a
    /// fresh `PeerStateData`).
    pub last_liveness_probe_at: Option<Instant>,
    pub last_ping_t: Option<i64>,
    pub rtt_ms: Option<u32>,
    /// Rolling clock-skew samples against this peer, newest last (ms;
    /// positive = the peer's wall clock reads ahead of ours). Each inbound
    /// heartbeat ping contributes one — its `t` is the sender's wall clock,
    /// corrected by half our measured RTT — so the estimate is purely
    /// passive: no extra traffic to any node. Capped at
    /// `SKEW_WINDOW`.
    pub clock_skew_samples: ClockSkewSamples,
    /// Median of [`Self::clock_skew_samples`] — the per-peer estimate
    /// surfaced in `PeerInfo` and folded into the network-wide check in
    /// `heartbeat::tick`. `None` until the first inbound ping.
    pub clock_skew_ms: Option<i64>,
    pub ice_disconnected_since: Option<Instant>,
    /// When this peer's transport session (the `RTCPeerConnection`) was
    /// created. The single clock for a *connecting* peer: if its data
    /// channel hasn't opened within `DATA_CHANNEL_OPEN_TIMEOUT_MS` of
    /// this, the attempt is treated as failed and rebuilt. Replaces the
    /// old ICE-`Checking` timeout — we time the reliable milestone (a data
    /// channel that actually opened) instead of webrtc-rs's unreliable ICE
    /// connection state. `None` only for the session-less peers some unit
    /// tests insert; set in `ensure_peer_session` when the session opens.
    pub session_started_at: Option<Instant>,
    /// The connector's track set changed on this session and the SDP no
    /// longer matches — the renegotiation pass owes this peer one in-place
    /// offer. Coalesced: any number of changes between passes costs a
    /// single renegotiation.
    pub media_reneg_pending: bool,
    /// A renegotiation task is currently running for this peer
    /// (spawned off the driver — see `service_media_renegotiations`).
    /// Single-flight guard: the tick skips a peer whose offer is still
    /// in flight instead of stacking a second one onto webrtc-rs.
    pub media_reneg_inflight: bool,
    /// True once this session's data channel has fired `on_open` — the one
    /// reliable "transport is up" signal (DTLS + SCTP genuinely
    /// established). The connect-timeout watchdog only reclaims a peer
    /// whose channel never opened; once it's open, liveness is governed by
    /// inbound-frame recency (heartbeat), not by ICE state.
    pub data_channel_open: bool,
    pub handshake_started_at: Option<Instant>,
    pub hello_attempt: u32,
    /// Consecutive `ICE failed` events since the last successful
    /// transition to Active. Drives the no-TURN diagnostic: after
    /// a few failures with zero relay candidates we tell the user
    /// their setup will never work without TURN.
    pub ice_failed_count: u32,
    /// One-shot guard so we don't re-emit the no-TURN diagnostic
    /// every time the ladder cycles. Reset when the peer becomes
    /// Active again.
    pub no_turn_diag_emitted: bool,
    /// The ICE candidate pair actually in use, once the agent has
    /// nominated one. The graph uses this to classify the link as
    /// LAN (host↔host), STUN (srflx involved), or TURN (relay
    /// involved) without relying on heuristics over the gathered-
    /// candidate counts. `None` until ICE reaches Connected.
    pub selected_pair: Option<SelectedCandidatePair>,
    /// Count of inbound frames the admission gate dropped because the peer
    /// hadn't reached the phase they require (an application/RPC/reliable/
    /// governance/media frame arriving before the ed25519 handshake + approval
    /// finished). Drives a power-of-two-throttled warn so a pre-admission
    /// flood can't be turned into a log-amplification primitive.
    pub admission_rejected: u64,
    pub diag: PeerDiag,
}

/// One peer's session record and state data, borrowed together.
///
/// The whole value of this type is that its three fields were read under **one**
/// observation — see [`PeerConnection::with_peer_view`], which is the only way
/// to obtain it. Nothing here is owned, so a caller can measure it without
/// allocating, and nothing can outlive the guards it was read from.
///
/// `session` is `None` for a peer with no current promoted session. That is a
/// fact about the peer, not a failure to read it: its state is still present and
/// still borrowed from the same instant.
///
/// `Copy`, because it is three shared references: a caller that measures the
/// view and then builds from it is reading the same borrows twice, not
/// observing the peer twice.
#[derive(Clone, Copy)]
pub(super) struct PeerView<'a> {
    pub(super) device_id: &'a str,
    pub(super) data: &'a PeerStateData,
    pub(super) session: Option<&'a crate::runtime::peer_session::PeerSessionState>,
}

/// Clonable point-in-time view for diagnostics and compatibility callers.
///
/// This deliberately omits mutable ownership such as the pending candidate
/// queue. Mutating a snapshot cannot alter the live peer or duplicate an
/// observation lease.
#[derive(Debug, Clone)]
pub struct PeerStateSnapshot {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub rtt_ms: Option<u32>,
    pub clock_skew_ms: Option<i64>,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub authenticated: bool,
    pub verification_code_received: Option<String>,
    pub verification_code_sent: Option<String>,
    pub local_approve_sent: bool,
    pub remote_approve_seen: bool,
    pub needs_turn: bool,
    pub diag: PeerDiag,
    pub selected_pair: Option<SelectedCandidatePair>,
}

impl PeerStateData {
    pub(super) fn record_clock_skew_sample(&mut self, sample: i64) -> Option<i64> {
        self.clock_skew_samples.push(sample);
        crate::engine::heartbeat::median(self.clock_skew_samples.as_slice())
    }

    /// The admission boundary: `true` once this peer has proven its ed25519
    /// identity (`authenticated`) **and** both sides have approved (`Active`,
    /// or `Shelved` — an admitted `Active` peer parked by the topology
    /// selector). This is the single predicate every inbound application/RPC/
    /// reliable/governance/routing/media path — and the application-level
    /// outbound senders — gate on. A merely-connected peer (`Sighted`/
    /// `Handshaking`/`PendingApproval`) is **not** admitted: a live DTLS data
    /// channel is not authorization. The `authenticated` conjunct is defence in
    /// depth — even if some path reached `Active` without authenticating, no
    /// traffic flows.
    /// Test-only legacy observation. Production admission uses the
    /// provenance-bearing channel or promoted-session slot instead.
    #[cfg(test)]
    pub fn is_admitted(&self) -> bool {
        self.authenticated && matches!(self.status, PeerStatus::Active | PeerStatus::Shelved)
    }

    /// The diagnostic view of this peer's *state*.
    ///
    /// `capabilities` is supplied rather than read, because it is no longer peer
    /// state: it belongs to the promoted session, and only a caller holding the
    /// entry can reach that. [`PeerConnection::snapshot`] is that caller. Passing
    /// it in keeps the one public snapshot shape while making it impossible to
    /// fill the field from anything that outlives the session.
    pub fn snapshot(&self, capabilities: Option<CapabilityAdvert>) -> PeerStateSnapshot {
        PeerStateSnapshot {
            status: self.status,
            tier: self.tier,
            rtt_ms: self.rtt_ms,
            clock_skew_ms: self.clock_skew_ms,
            label: self.label.clone(),
            capabilities,
            local_shelved: self.local_shelved,
            remote_shelved: self.remote_shelved,
            authenticated: self.authenticated,
            verification_code_received: self.verification_code_received.clone(),
            verification_code_sent: self.verification_code_sent.clone(),
            local_approve_sent: self.local_approve_sent,
            remote_approve_seen: self.remote_approve_seen,
            needs_turn: self.no_turn_diag_emitted,
            diag: self.diag.clone(),
            selected_pair: self.selected_pair,
        }
    }
}

impl Default for PeerStateData {
    fn default() -> Self {
        Self {
            status: PeerStatus::Sighted,
            tier: ConnectionTier::Steady,
            authenticated: false,
            hello_retention: None,
            local_approve_sent: false,
            remote_approve_seen: false,
            local_shelved: false,
            remote_shelved: false,
            label: String::new(),
            verification_code_sent: None,
            verification_code_received: None,
            last_recv_at: None,
            last_ping_sent_at: None,
            last_offer_sent_at: None,
            last_liveness_probe_at: None,
            last_ping_t: None,
            rtt_ms: None,
            clock_skew_samples: ClockSkewSamples::default(),
            clock_skew_ms: None,
            ice_disconnected_since: None,
            session_started_at: None,
            media_reneg_pending: false,
            media_reneg_inflight: false,
            data_channel_open: false,
            handshake_started_at: None,
            hello_attempt: 0,
            ice_failed_count: 0,
            no_turn_diag_emitted: false,
            selected_pair: None,
            admission_rejected: 0,
            diag: PeerDiag::default(),
        }
    }
}

/// What one call to [`PeerConnection::promote_session_if_needed`] did.
///
/// Three answers rather than a boolean, because the caller acts differently on
/// each and one of them is an event. A session that was *minted* by this call is
/// the only moment at which anything owed to a new session becomes owed, and it
/// happens exactly once per session however many operations later reuse it. A
/// boolean collapses `Current` and `NewlyPromoted` into "usable", which is
/// enough to proceed but not enough to announce — and an announcement derived
/// from "usable" would fire on every operation for the life of the session.
///
/// `Refused` covers both the terminal refusals and the capacity one. Neither
/// minted a session, so neither announces; the capacity refusal in particular
/// leaves the authenticated channel installed, so a later operation promotes and
/// *that* call is the one that announces.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(super) enum Promotion {
    /// A session was already installed and every use-time conjunct still holds.
    Current,
    /// This call minted the session. Nothing owed to it has been done yet.
    NewlyPromoted,
    /// No usable session, and none was minted.
    Refused,
}

impl Promotion {
    /// Whether the caller may proceed against a live session.
    pub(super) fn is_usable(self) -> bool {
        matches!(self, Self::Current | Self::NewlyPromoted)
    }
}

pub(super) struct SpeculativePromotion {
    pub(super) displaced_attempt: Option<AttemptDisplacement>,
    pub(super) selected: bool,
}

pub(super) struct AttemptDisplacement {
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: PromotedDedupSet,
    pub(super) retired_dedup: DetachedDedupSet,
}

pub(super) struct SpeculativeRetirement {
    pub(super) worker: Arc<WebRtcConnectorWorker>,
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: PromotedDedupSet,
}

/// Fixed terminal cause; never retains a transport error string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum IntroductionTerminalDisposition {
    Denied,
    AuthFailed,
    IceFailed,
    UserLeft,
    TopologyPruned,
    HeartbeatTimeout,
    TransportError,
}

impl IntroductionTerminalDisposition {
    pub(super) fn from_drop_reason(reason: &crate::events::DropReason) -> Self {
        use crate::events::DropReason;
        match reason {
            DropReason::Denied => Self::Denied,
            DropReason::AuthFailed => Self::AuthFailed,
            DropReason::IceFailed => Self::IceFailed,
            DropReason::UserLeft => Self::UserLeft,
            DropReason::TopologyPruned => Self::TopologyPruned,
            DropReason::HeartbeatTimeout => Self::HeartbeatTimeout,
            DropReason::TransportError { .. } => Self::TransportError,
        }
    }
}

/// Inline custody in the existing demand record, not a ClosingWorker entry.
/// All backing remains owned until native AND engine receiver have joined.
pub(super) struct IntroducedRetirement {
    pub(super) worker: Arc<WebRtcConnectorWorker>,
    pub(super) terminal: Option<IntroductionTerminalDisposition>,
    authenticated_channel: Option<crate::endpoint_auth::AuthenticatedChannelCapability>,
    auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    dedup: Option<DedupToken>,
    additional_dedup: PromotedDedupSet,
}

impl IntroducedRetirement {
    #[cfg(test)]
    pub(super) fn authenticated_custody_for_test(&self) -> bool {
        self.authenticated_channel
            .as_ref()
            .is_some_and(|capability| {
                self.worker
                    .matches_connector_identity_for_retirement(capability.record().connector())
                    && capability.belongs_to(capability.record().connector())
            })
            && self.auth.as_ref().is_some_and(|task| {
                task.is_retired()
                    && self
                        .worker
                        .matches_connector_identity_for_retirement(task.incarnation())
            })
    }

    pub(super) fn release_after_join(self, peer: &PeerConnection) {
        peer.release_dedup_custody(self.dedup, self.additional_dedup.drain_tokens());
        drop(self.auth);
        // The real connected handoff is not dropped to initiate cleanup: it
        // remains here until the caller has joined native AND engine pump.
        drop(self.authenticated_channel);
    }
}

pub(super) struct DedupDrain {
    primary: Option<DedupToken>,
    additional: PromotedDedupDrain,
}

/// Exact custody for one retired native worker.
///
/// The worker and every dedup token accepted by that worker move together
/// through native close.  A callback terminal path may therefore start a
/// close and return to its pump without releasing the signaling key while the
/// native close is still in flight.  The entry remains in `closing_workers`
/// until the exact worker reports completion, so shutdown can join the same
/// owner if its narrow waiter is cancelled or unavailable.
struct ClosingWorker {
    worker: Arc<WebRtcConnectorWorker>,
    dedup: Option<DedupToken>,
    additional_dedup: PromotedDedupDrain,
    additional_attached: bool,
}

/// The one pre-promotion owner for a connector installation.
///
/// Promotion transfers the connector into `PromotedSessionSlot`; keeping the
/// unpromoted phase in an explicit owner prevents callers from borrowing an
/// ownership-bearing field as a compatibility mirror.
struct UnpromotedConnector {
    worker: Arc<WebRtcConnectorWorker>,
}

impl Iterator for DedupDrain {
    type Item = DedupToken;

    fn next(&mut self) -> Option<Self::Item> {
        self.primary.take().or_else(|| self.additional.next())
    }
}

/// A provider-funded connector being considered as a replacement for the
/// promoted connector.  This slot is deliberately separate from `session`:
/// signaling may drive it, but it cannot borrow or mutate application
/// authority until Endpoint Auth has completed on this exact worker.
pub(super) struct SpeculativeAttempt {
    pub(super) correlation: String,
    pub(super) session: Arc<WebRtcConnectorWorker>,
    pub(super) endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    pub(super) authenticated_channel: Option<crate::endpoint_auth::AuthenticatedChannelCapability>,
    /// The one durable proof delivery admitted on this exact candidate, if
    /// any.  Keeping this binding on the candidate makes the ACK fence
    /// candidate-relative rather than a lookup by delivery id alone.
    pub(super) proof_delivery: Option<crate::semantic::ProofDeliveryId>,
    pub(super) dedup: Option<DedupToken>,
    pub(super) additional_dedup: PromotedDedupSet,
}

impl PeerConnection {
    pub(super) fn speculative_attempt_claim(correlation: &str) -> ResourceClaim {
        let correlation_bytes = u64::try_from(correlation.len())
            .expect("correlation length fits the provider accounting width");
        let node_claim = AttemptOwnerSet::<SpeculativeAttempt>::entry_claim()
            .expect("candidate owner node claim is representable");
        let correlation_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, correlation_bytes),
            (
                ResourceClass::StorageObject,
                u64::from(correlation_bytes != 0),
            ),
        ])
        .expect("candidate correlation claim is representable");
        node_claim
            .checked_add(correlation_claim)
            .expect("candidate record accounting cannot overflow")
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntroductionBackingPhase {
    InUse,
    Retiring,
    Reusable,
    Unusable,
}

/// Funds the retained peer/registry storage even between native attempts.
/// A full ticket, not its generation-free wire correlation, names each use.
struct IntroductionBacking {
    lease: crate::resource::ResourceLease,
    ticket: Option<super::hub_introduction::IntroductionTicket>,
    phase: IntroductionBackingPhase,
}

pub struct PeerConnection {
    pub device_id: String,
    pub state: RwLock<PeerStateData>,
    /// Sole owner slot for the pre-promotion connector. Promotion transfers
    /// authority into `promoted_session`; this slot is never consulted after
    /// that transfer.
    unpromoted_connector: Mutex<Option<UnpromotedConnector>>,
    speculative: Mutex<AttemptOwnerSet<SpeculativeAttempt>>,
    closing_workers: Mutex<AttemptOwnerSet<ClosingWorker>>,
    /// One retained observer for each native close owner. The worker itself
    /// remains terminal custody; this handle observes its result exactly once.
    closing_waiters: Mutex<Vec<(Weak<WebRtcConnectorWorker>, JoinHandle<()>)>>,
    retired_dedup: Mutex<DetachedDedupSet>,
    signaling_runtime: RwLock<Option<Weak<crate::engine::signaling_ingress::SignalingRuntime>>>,
    /// At most one renegotiation may be in flight for this installation.
    /// Keeping it as an exact slot avoids an uncharged growable worker list.
    media_renegotiation_worker: Mutex<Option<Arc<WebRtcConnectorWorker>>>,
    /// Unpromoted Endpoint Auth task mirror. Promoted channel auth is owned
    /// by the slot's exact channel record; this field is retained only for the
    /// pre-promotion handshake and compatibility accessors.
    endpoint_auth: Mutex<Option<Arc<crate::endpoint_auth::EndpointAuthTask>>>,
    /// The Arc 04 authority artifact for the exact current channel.
    ///
    /// `PeerStateData::authenticated` remains as legacy diagnostic and policy
    /// state, but a bool cannot be invalidated by channel replacement and
    /// carries no provenance. This slot does: it is installed only by the
    /// endpoint-auth task that owns the current connector, and it is dropped
    /// whenever that connector is retired or replaced.
    authenticated_channel: Mutex<Option<crate::endpoint_auth::AuthenticatedChannelCapability>>,
    /// The correlation naming this unpromoted connection attempt, for
    /// de-duplication. A promoted channel's exact correlation is owned by its
    /// slot record; `attempt()` is slot-first and this value is only the
    /// unpromoted/compatibility mirror.
    ///
    /// One installation of a peer is one attempt, so this is minted here, once,
    /// and a replacement installation gets a different one. It rides every
    /// offer, answer and candidate this side emits for the attempt, and the
    /// answering side adopts the offerer's value through [`Self::adopt_attempt`]
    /// so both ends name the attempt the same thing.
    ///
    /// **What it is for, and the one thing it is not.** The signaling ingress
    /// keys de-duplication under it, which is the only way to tell "the second
    /// relay's copy of this offer" from "the same host candidate again on a
    /// fresh attempt" — the two are byte-identical otherwise, which is how a
    /// retired attempt's key used to swallow a live one. It is sender-chosen and
    /// unauthenticated on arrival, so it may scope that and nothing else: it is
    /// not a route identity, not a path generation, not a session generation,
    /// and no decision anywhere reads it as authority or preference.
    attempt: RwLock<String>,
    attempt_dedup: Mutex<Option<DedupToken>>,
    additional_attempt_dedup: Mutex<PromotedDedupSet>,
    /// The promoted session bundle. This slot is the sole post-promotion
    /// authority: it owns channel membership/selection, Endpoint Auth,
    /// correlation, capability, realtime flows, and logical application state.
    /// The legacy mirrors above remain only for unpromoted/compatibility paths.
    promoted_session: crate::runtime::peer_session::PromotedSessionSlot,
    registry_retired: AtomicBool,
    /// Diagnostic-only rebuild ordinal. It is never accepted as callback,
    /// attempt, resource, or application authority.
    pub epoch: u64,
    unpromoted_offer_in_flight: AtomicBool,
    // Present only for demand-created placeholders. Its backing remains
    // funded while any captured owner/worker task retains this connection.
    _introduction_backing: Mutex<Option<IntroductionBacking>>,
}

/// Exact-owner witness for one legacy untrusted-signaling mutation.
///
/// The registry mints this only while the named installation is current and
/// unpromoted. Its lifetime blocks both normal and speculative promotion for
/// that installation until the awaited mutation has completed or been
/// cancelled.
pub(super) struct UnpromotedNegotiation {
    peer: Arc<PeerConnection>,
}

impl UnpromotedNegotiation {
    pub(super) fn new(peer: Arc<PeerConnection>) -> Self {
        Self { peer }
    }
}

impl Drop for UnpromotedNegotiation {
    fn drop(&mut self) {
        self.peer
            .unpromoted_offer_in_flight
            .store(false, Ordering::Release);
    }
}

/// Process-wide diagnostic sequence for [`PeerConnection::epoch`].
static DIAGNOSTIC_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl PeerConnection {
    fn retain_closing_worker(&self, worker: Arc<WebRtcConnectorWorker>) {
        worker.retire();
        let mut closing = self.closing_workers.lock();
        if closing.any(|current| Arc::ptr_eq(&current.worker, &worker)) {
            return;
        }
        let Some(entry_lease) = worker
            .reserve_attempt_work(
                AttemptOwnerSet::<ClosingWorker>::entry_claim()
                    .expect("closing owner node claim is representable"),
            )
            .ok()
        else {
            worker.start_close();
            return;
        };
        let _ = closing.insert(
            ClosingWorker {
                worker,
                dedup: None,
                additional_dedup: PromotedDedupSet::new().drain_tokens(),
                additional_attached: false,
            },
            entry_lease,
        );
    }

    fn retain_closing_worker_with_dedup(
        &self,
        worker: Arc<WebRtcConnectorWorker>,
        dedup: Option<DedupToken>,
        additional_dedup: PromotedDedupDrain,
    ) {
        worker.retire();
        let mut closing = self.closing_workers.lock();
        let mut unretained_dedup = dedup;
        let mut unretained_additional_dedup = Some(additional_dedup);
        if let Some(current) = closing.find_mut(|current| Arc::ptr_eq(&current.worker, &worker)) {
            if current.dedup.is_none() {
                current.dedup = unretained_dedup.take();
            }
            if !current.additional_attached {
                current.additional_dedup = unretained_additional_dedup
                    .take()
                    .expect("additional dedup input is present");
                current.additional_attached = true;
            }
        } else {
            let Some(entry_lease) = worker
                .reserve_attempt_work(
                    AttemptOwnerSet::<ClosingWorker>::entry_claim()
                        .expect("closing owner node claim is representable"),
                )
                .ok()
            else {
                worker.start_close();
                drop(closing);
                self.release_dedup_custody(
                    unretained_dedup,
                    unretained_additional_dedup
                        .unwrap_or_else(|| PromotedDedupSet::new().drain_tokens()),
                );
                return;
            };
            let _ = closing.insert(
                ClosingWorker {
                    worker,
                    dedup: unretained_dedup.take(),
                    additional_dedup: unretained_additional_dedup
                        .take()
                        .expect("additional dedup input is present"),
                    additional_attached: true,
                },
                entry_lease,
            );
        }
        drop(closing);
        self.release_dedup_custody(
            unretained_dedup,
            unretained_additional_dedup.unwrap_or_else(|| PromotedDedupSet::new().drain_tokens()),
        );
    }

    fn release_dedup_custody(
        &self,
        dedup: Option<DedupToken>,
        additional_dedup: PromotedDedupDrain,
    ) {
        let runtime = self
            .signaling_runtime
            .read()
            .as_ref()
            .and_then(Weak::upgrade);
        if let Some(runtime) = runtime {
            if let Some(dedup) = dedup {
                runtime.forget_token(dedup);
            }
            for dedup in additional_dedup {
                runtime.forget_token(dedup);
            }
        } else {
            let mut retired = self.retired_dedup.lock();
            if let Some(dedup) = dedup {
                let _ = retired.insert(dedup);
            }
            for dedup in additional_dedup {
                let _ = retired.insert(dedup);
            }
        }
    }

    fn complete_closing_worker(&self, worker: &Arc<WebRtcConnectorWorker>) {
        let mut closing = self.closing_workers.lock();
        let Some(current) = closing.remove_where(|current| Arc::ptr_eq(&current.worker, worker))
        else {
            return;
        };
        self.release_dedup_custody(current.dedup, current.additional_dedup);
    }

    fn complete_closing_worker_if_weak(&self, worker: &Weak<WebRtcConnectorWorker>) {
        let mut closing = self.closing_workers.lock();
        let Some(current) =
            closing.remove_where(|current| worker.as_ptr() == Arc::as_ptr(&current.worker))
        else {
            return;
        };
        self.release_dedup_custody(current.dedup, current.additional_dedup);
    }

    fn spawn_one_closing_worker(self: &Arc<Self>, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        let Some(current) = self.closing_workers.lock().with(
            |current| Arc::ptr_eq(&current.worker, worker),
            |current| Arc::clone(&current.worker),
        ) else {
            return false;
        };
        let identity = Arc::downgrade(&current);
        current.start_close();
        let waiter = current.close_waiter();
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return true;
        };
        let peer = Arc::clone(self);
        let mut waiters = self.closing_waiters.lock();
        if waiters
            .iter()
            .any(|(identity, _)| identity.as_ptr() == Arc::as_ptr(&current))
        {
            return true;
        }
        let waiter_handle = handle.spawn(async move {
            if let Err(error) = waiter.await {
                tracing::warn!(%error, "exact retired connector native close failed");
            }
            peer.complete_closing_worker_if_weak(&identity);
        });
        waiters.push((Arc::downgrade(&current), waiter_handle));
        drop(waiters);
        drop(current);
        true
    }

    /// Start one exact retired worker without awaiting it from a transport
    /// callback.  The closing entry owns all dedup custody until the native
    /// owner settles; the waiter is only a convenience, never the custody.
    pub(super) fn start_exact_retired_worker(
        self: &Arc<Self>,
        worker: &Arc<WebRtcConnectorWorker>,
        dedup: Option<DedupToken>,
        additional_dedup: PromotedDedupDrain,
    ) -> bool {
        let Some(_current) = self.closing_workers.lock().with(
            |current| Arc::ptr_eq(&current.worker, worker),
            |current| Arc::clone(&current.worker),
        ) else {
            self.release_dedup_custody(dedup, additional_dedup);
            return false;
        };
        {
            let mut closing = self.closing_workers.lock();
            let Some(entry) = closing.find_mut(|entry| Arc::ptr_eq(&entry.worker, worker)) else {
                drop(closing);
                self.release_dedup_custody(dedup, additional_dedup);
                return false;
            };
            let mut unretained_dedup = dedup;
            let mut unretained_additional_dedup = Some(additional_dedup);
            if entry.dedup.is_none() {
                entry.dedup = unretained_dedup.take();
            }
            if !entry.additional_attached {
                entry.additional_dedup = unretained_additional_dedup
                    .take()
                    .expect("additional dedup input is present");
                entry.additional_attached = true;
            }
            drop(closing);
            self.release_dedup_custody(
                unretained_dedup,
                unretained_additional_dedup
                    .unwrap_or_else(|| PromotedDedupSet::new().drain_tokens()),
            );
        }
        self.spawn_one_closing_worker(worker)
    }

    /// Start every currently retained native close before a caller hands the
    /// peer to a detached or shutdown-visible supervisor.
    pub(super) fn start_all_retired_workers(&self) {
        let mut workers = Vec::new();
        self.closing_workers
            .lock()
            .for_each(|entry| workers.push(Arc::clone(&entry.worker)));
        for worker in workers {
            worker.start_close();
        }
    }

    pub(super) fn revoke_promoted_session(self: &Arc<Self>) {
        let workers = self.promoted_session.take_workers_with_dedup();
        drop(self.take_unpromoted_connector());
        drop(self.endpoint_auth.lock().take());
        drop(self.authenticated_channel.lock().take());
        drop(self.media_renegotiation_worker.lock().take());
        for (worker, dedup, additional_dedup) in workers {
            self.retain_closing_worker_with_dedup(Arc::clone(&worker), dedup, additional_dedup);
            let _ = self.spawn_one_closing_worker(&worker);
        }
    }

    pub(super) fn bind_signaling_runtime(
        &self,
        runtime: Weak<crate::engine::signaling_ingress::SignalingRuntime>,
    ) {
        *self.signaling_runtime.write() = Some(runtime);
    }

    /// Replace this installed peer's connector after its promoted session and
    /// authenticated channel have both been consumed. Controls only.
    ///
    /// Production installs a new [`PeerConnection`] when a connector is
    /// replaced. The exact-session fence control deliberately keeps this
    /// installation (and therefore its owner token) fixed so replacement of the
    /// session cannot be confused with replacement of the peer. This seam makes
    /// only that normally-atomic fixture step separable; the replacement still
    /// has to present its own live connector and authenticated handoff before it
    /// can promote.
    #[cfg(test)]
    pub(crate) fn replace_connector_for_session_control(&self, worker: Arc<WebRtcConnectorWorker>) {
        assert!(
            !self.promoted_session.is_installed(),
            "the session control replaces a connector only after revocation"
        );
        assert!(
            self.authenticated_channel.lock().is_none(),
            "a successfully promoted channel is consumed before replacement"
        );
        let replaced = self.install_unpromoted_connector(worker);
        drop(replaced);
    }

    /// This attempt's correlation, for stamping an outbound signal.
    pub(super) fn attempt(&self) -> String {
        if let Some(worker) = self.promoted_session.selected_worker() {
            if let Some(correlation) = self.promoted_session.correlation_for(&worker) {
                return correlation;
            }
        }
        self.attempt.read().clone()
    }

    /// The selected slot channel is the post-promotion authority. The explicit
    /// unpromoted owner is consulted only before promotion.
    pub(super) fn current_worker(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        if self.promoted_session.is_installed() {
            self.promoted_session.selected_worker()
        } else {
            self.current_unpromoted_worker()
        }
    }

    /// Whether this installation has a current worker in either lifecycle
    /// phase. The promoted slot remains authoritative when it is installed.
    pub(super) fn has_current_worker(&self) -> bool {
        self.current_worker().is_some()
    }

    /// Install the sole pre-promotion connector owner, returning the prior
    /// owner for an explicit retirement path.
    #[cfg(test)]
    pub(super) fn install_unpromoted_connector(
        &self,
        worker: Arc<WebRtcConnectorWorker>,
    ) -> Option<Arc<WebRtcConnectorWorker>> {
        self.unpromoted_connector
            .lock()
            .replace(UnpromotedConnector { worker })
            .map(|owner| owner.worker)
    }

    /// Take the pre-promotion connector owner without consulting promoted
    /// session state.
    pub(super) fn take_unpromoted_connector(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        self.unpromoted_connector
            .lock()
            .take()
            .map(|owner| owner.worker)
    }

    fn current_unpromoted_worker(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        self.unpromoted_connector
            .lock()
            .as_ref()
            .map(|owner| Arc::clone(&owner.worker))
    }

    /// Called only under the registry installation fence and then the demand
    /// record lock. Never consults the selected promoted channel or takes a
    /// successor's correlation. Negotiation/promotion winning first refuses
    /// this terminal transition without modifying any owner.
    pub(super) fn detach_failed_introduction(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> Option<IntroducedRetirement> {
        self.detach_introduction(worker, ticket, None)
    }

    /// Only the caller's explicit exact-owner terminal fence may use this
    /// sibling. Controller expiry/Terminal is not permission to take a live
    /// authenticated capability.
    pub(super) fn detach_terminal_introduction(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        ticket: super::hub_introduction::IntroductionTicket,
        terminal: IntroductionTerminalDisposition,
    ) -> Option<IntroducedRetirement> {
        self.detach_introduction(worker, ticket, Some(terminal))
    }

    fn detach_introduction(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        ticket: super::hub_introduction::IntroductionTicket,
        terminal: Option<IntroductionTerminalDisposition>,
    ) -> Option<IntroducedRetirement> {
        let attempt = self.attempt.read();
        if !ticket.matches_attempt(&attempt)
            || self.registry_retired()
            || self.unpromoted_offer_in_flight()
            || self.promoted_session.contains_worker(worker)
        {
            return None;
        }
        let mut backing = self._introduction_backing.lock();
        let backing = backing.as_mut().filter(|backing| {
            backing.ticket == Some(ticket) && backing.phase == IntroductionBackingPhase::InUse
        })?;
        let mut capability = self.authenticated_channel.lock();
        if terminal.is_some() {
            if capability.as_ref().is_some_and(|capability| {
                !worker.matches_connector_identity_for_retirement(capability.record().connector())
                    || !capability.belongs_to(capability.record().connector())
            }) {
                return None;
            }
        } else if capability.as_ref().is_some_and(|capability| {
            worker
                .live_connector_incarnation()
                .as_ref()
                .is_some_and(|incarnation| capability.belongs_to(incarnation))
        }) {
            return None;
        }
        let mut slot = self.unpromoted_connector.lock();
        if !slot
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(&current.worker, worker))
        {
            return None;
        }
        let mut auth = self.endpoint_auth.lock();
        if auth.as_ref().is_some_and(|task| {
            if terminal.is_some() {
                !worker.matches_connector_identity_for_retirement(task.incarnation())
            } else {
                !worker.owns_endpoint_auth(task)
            }
        }) {
            return None;
        }
        // Retire the actual task while its installation is still excluded;
        // no later authentication result can promote this detached worker.
        if let Some(task) = auth.as_ref() {
            task.retire();
        }
        let detached = IntroducedRetirement {
            terminal,
            authenticated_channel: if terminal.is_some() {
                capability.take()
            } else {
                None
            },
            worker: slot
                .take()
                .expect("exact unpromoted slot was checked")
                .worker,
            auth: auth.take(),
            dedup: self.attempt_dedup.lock().take(),
            additional_dedup: std::mem::replace(
                &mut *self.additional_attempt_dedup.lock(),
                PromotedDedupSet::new(),
            ),
        };
        backing.phase = IntroductionBackingPhase::Retiring;
        detached.worker.retire();
        Some(detached)
    }

    /// Removing an empty installation is optional. Independent promoted,
    /// speculative, negotiating, closing, or media owners always preserve it.
    pub(super) fn retire_empty_introduction_installation(&self) -> bool {
        if self.current_unpromoted_worker().is_some()
            || self.holds_promoted_session()
            || self.has_speculative()
            || self.closing_workers.lock().any(|_| true)
            || self.unpromoted_offer_in_flight()
            || self.endpoint_auth.lock().is_some()
            || self.authenticated_channel.lock().is_some()
            || self.media_renegotiation_worker.lock().is_some()
        {
            return false;
        }
        self.registry_retired.store(true, Ordering::Release);
        true
    }

    /// Adopt the offerer's correlation for this attempt.
    ///
    /// The offering side mints; the answering side adopts, so one attempt has
    /// one name on both ends rather than two names that agree about nothing.
    /// Called when an offer is applied, before any answer or candidate for that
    /// attempt is emitted.
    ///
    /// Returns the correlation this displaced, when it displaced a different
    /// one. That return value is not a courtesy: a rebuild offer — the peer tore
    /// its connection down and built a fresh one on the same installation —
    /// establishes a second attempt here, and the keys the ingress remembered
    /// under the first can never legitimately match again. The caller releases
    /// them. Without the hand-back there is no other way to learn the old value,
    /// and it would sit in the ring until provider pressure evicted it.
    ///
    /// Ignores an empty value, which is what an unstamped frame decodes to:
    /// blanking the field would leave this side emitting uncorrelated signals
    /// for an attempt that has a perfectly good name.
    #[cfg(test)]
    pub(super) fn adopt_attempt(&self, attempt: &str) -> Option<String> {
        let previous = self.attempt();
        self.adopt_attempt_with_dedup(attempt, None)
            .map(|_| previous)
    }

    pub(super) fn adopt_attempt_with_dedup(
        &self,
        attempt: &str,
        dedup: Option<DedupToken>,
    ) -> Option<AttemptDisplacement> {
        if attempt.is_empty() {
            return None;
        }
        let mut current = self.attempt.write();
        if *current == attempt {
            if let Some(dedup) = dedup {
                let worker = self.current_unpromoted_worker();
                let mut retained = self.additional_attempt_dedup.lock();
                if let Some(worker) = worker {
                    if let Err(dedup) = retained.try_push_speculative(&worker, dedup) {
                        drop(retained);
                        if let Some(runtime) = self
                            .signaling_runtime
                            .read()
                            .as_ref()
                            .and_then(Weak::upgrade)
                        {
                            runtime.forget_token(dedup);
                        }
                    }
                } else {
                    drop(retained);
                    if let Some(runtime) = self
                        .signaling_runtime
                        .read()
                        .as_ref()
                        .and_then(Weak::upgrade)
                    {
                        runtime.forget_token(dedup);
                    }
                }
            }
            return None;
        }
        *current = attempt.to_string();
        let previous = std::mem::replace(&mut *self.attempt_dedup.lock(), dedup);
        let additional_dedup = std::mem::replace(
            &mut *self.additional_attempt_dedup.lock(),
            PromotedDedupSet::new(),
        );
        Some(AttemptDisplacement {
            dedup: previous,
            additional_dedup,
            retired_dedup: DetachedDedupSet::new(),
        })
    }

    pub(super) fn retain_current_dedup(&self, token: DedupToken) {
        let worker = self.current_unpromoted_worker();
        let mut retained = self.additional_attempt_dedup.lock();
        if let Some(worker) = worker {
            if let Err(token) = retained.try_push_speculative(&worker, token) {
                drop(retained);
                if let Some(runtime) = self
                    .signaling_runtime
                    .read()
                    .as_ref()
                    .and_then(Weak::upgrade)
                {
                    runtime.forget_token(token);
                }
            }
        } else {
            drop(retained);
            if let Some(runtime) = self
                .signaling_runtime
                .read()
                .as_ref()
                .and_then(Weak::upgrade)
            {
                runtime.forget_token(token);
            }
        }
    }

    /// Install a separately owned replacement attempt.  The correlation is
    /// only a lookup key; ownership is proved by the worker stored here.
    #[cfg(test)]
    pub(super) fn install_speculative(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
    ) -> bool {
        let mut dedup = None;
        self.install_speculative_with_dedup(correlation, session, attempt_lease, &mut dedup)
    }

    pub(super) fn install_speculative_with_dedup(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
        dedup: &mut Option<DedupToken>,
    ) -> bool {
        if self.registry_retired() || self.current_worker().is_none() {
            return false;
        }
        self.install_speculative_after_precheck(correlation, session, attempt_lease, dedup)
    }

    fn install_speculative_after_precheck(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
        dedup: &mut Option<DedupToken>,
    ) -> bool {
        let mut candidates = self.speculative.lock();
        // Retirement sets this flag before waiting for the same slot lock. If
        // insertion won the lock first, retirement drains the new slot after
        // release; if retirement won first, this recheck refuses the insert.
        if self.registry_retired() {
            return false;
        }
        if candidates.any(|attempt| Arc::ptr_eq(&attempt.session, &session)) {
            return false;
        }
        candidates.insert(
            SpeculativeAttempt {
                correlation,
                session,
                endpoint_auth: None,
                authenticated_channel: None,
                proof_delivery: None,
                dedup: dedup.take(),
                additional_dedup: PromotedDedupSet::new(),
            },
            attempt_lease,
        )
    }

    /// Controls only: stage retirement after the optimistic precheck and
    /// before the speculative slot insertion. The production insertion seam
    /// is reused after that staged edge, so the control distinguishes the
    /// slot-locked retirement recheck from the old check-then-insert shape.
    #[cfg(test)]
    pub(super) fn install_speculative_after_retire_race_for_test(
        &self,
        correlation: String,
        session: Arc<WebRtcConnectorWorker>,
        attempt_lease: ResourceLease,
    ) -> bool {
        if self.registry_retired() || self.current_worker().is_none() {
            return false;
        }
        self.retire_connector();
        let mut dedup = None;
        self.install_speculative_after_precheck(correlation, session, attempt_lease, &mut dedup)
    }

    #[cfg(test)]
    pub(super) fn speculative_resources_empty_for_test(&self) -> bool {
        self.speculative.lock().is_empty()
    }

    #[cfg(test)]
    pub(super) fn speculative_worker_for(
        &self,
        correlation: &str,
    ) -> Option<Arc<WebRtcConnectorWorker>> {
        self.speculative.lock().with(
            |attempt| attempt.correlation == correlation,
            |attempt| Arc::clone(&attempt.session),
        )
    }

    pub(super) fn speculative_workers_for(
        &self,
        correlation: &str,
    ) -> Vec<Arc<WebRtcConnectorWorker>> {
        let mut workers = Vec::new();
        self.speculative.lock().for_each(|attempt| {
            if attempt.correlation == correlation {
                workers.push(Arc::clone(&attempt.session));
            }
        });
        workers
    }

    /// Read-only presence check over the existing funded speculative owners.
    pub(super) fn has_speculative(&self) -> bool {
        self.speculative.lock().any(|_| true)
    }

    pub(super) fn speculative_is_exact(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> bool {
        self.speculative.lock().any(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        })
    }

    /// Bind one pending proof to this exact speculative candidate.  The
    /// candidate owns at most one proof generation; a repeated bind is
    /// idempotent only for the same delivery identity.
    pub(super) fn bind_speculative_proof_delivery(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        delivery_id: crate::semantic::ProofDeliveryId,
    ) -> bool {
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.find_mut(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        match attempt.proof_delivery {
            Some(current) => current == delivery_id,
            None => {
                attempt.proof_delivery = Some(delivery_id);
                true
            }
        }
    }

    pub(super) fn speculative_proof_delivery_matches(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        delivery_id: crate::semantic::ProofDeliveryId,
    ) -> bool {
        self.speculative.lock().any(|attempt| {
            attempt.correlation == correlation
                && Arc::ptr_eq(&attempt.session, worker)
                && attempt.proof_delivery == Some(delivery_id)
        })
    }

    /// Whether any live speculative sidecar owns this exact durable delivery.
    /// The registry mutation fence supplies the installation check around this
    /// observation; callers must not use it as a device-level lookup.
    pub(super) fn speculative_proof_delivery_owned(
        &self,
        delivery_id: crate::semantic::ProofDeliveryId,
    ) -> bool {
        self.speculative
            .lock()
            .any(|attempt| attempt.proof_delivery == Some(delivery_id))
    }

    pub(super) fn clear_speculative_proof_delivery(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        delivery_id: crate::semantic::ProofDeliveryId,
    ) -> bool {
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.find_mut(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        if attempt.proof_delivery != Some(delivery_id) {
            return false;
        }
        attempt.proof_delivery = None;
        true
    }

    pub(super) fn speculative_endpoint_auth(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.speculative
            .lock()
            .with(
                |attempt| {
                    attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
                },
                |attempt| attempt.endpoint_auth.clone(),
            )
            .flatten()
    }

    /// Remove one failed or superseded candidate.  The promoted worker is not
    /// touched, even when the candidate's carrier correlation is forged.
    pub(super) fn take_speculative_exact(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<SpeculativeRetirement> {
        let mut candidates = self.speculative.lock();
        let attempt = candidates.remove_where(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        })?;
        if let Some(task) = attempt.endpoint_auth {
            task.retire();
        }
        let worker = attempt.session;
        self.retain_closing_worker(Arc::clone(&worker));
        Some(SpeculativeRetirement {
            worker,
            dedup: attempt.dedup,
            additional_dedup: attempt.additional_dedup,
        })
    }

    pub(super) fn retain_dedup_for_worker(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        token: DedupToken,
    ) -> bool {
        {
            let mut candidates = self.speculative.lock();
            if let Some(attempt) = candidates.find_mut(|attempt| {
                attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
            }) {
                return attempt
                    .additional_dedup
                    .try_push_speculative(worker, token)
                    .is_ok();
            }
        }
        self.promoted_session.retain_dedup_for_worker(worker, token)
    }

    pub(super) fn install_speculative_endpoint_auth(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        if self.registry_retired() {
            return false;
        }
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.find_mut(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        if !attempt.session.owns_endpoint_auth(&task) || attempt.endpoint_auth.is_some() {
            return false;
        }
        attempt.endpoint_auth = Some(task);
        true
    }

    pub(super) fn install_speculative_authenticated_channel(
        &self,
        correlation: &str,
        worker: &Arc<WebRtcConnectorWorker>,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
        capability: crate::endpoint_auth::AuthenticatedChannelCapability,
    ) -> bool {
        if self.registry_retired() {
            return false;
        }
        let mut candidates = self.speculative.lock();
        let Some(attempt) = candidates.find_mut(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, worker)
        }) else {
            return false;
        };
        if attempt
            .endpoint_auth
            .as_ref()
            .is_none_or(|current| !Arc::ptr_eq(current, task))
            || attempt.authenticated_channel.is_some()
            || task.is_retired()
            || !capability.belongs_to(task.incarnation())
            || !task.issued(&capability)
        {
            return false;
        }
        attempt.authenticated_channel = Some(capability);
        true
    }

    /// Prove the exact authenticated speculative candidate for the one
    /// durable eviction proof exception.  This intentionally does not touch
    /// the promoted-session slot or peer status: the candidate remains a
    /// transport-only carrier until its proof and Deny have been attempted.
    /// The caller holds the registry mutation fence while this synchronous
    /// witness is minted.
    pub(super) fn speculative_proof_admission(
        &self,
        correlation: &str,
        candidate: &Arc<WebRtcConnectorWorker>,
        mesh_context: &str,
        total_bytes: usize,
    ) -> Option<(Arc<crate::endpoint_auth::EndpointAuthTask>, ResourceLease)> {
        if self.registry_retired() || candidate.live_connector_incarnation().is_none() {
            return None;
        }
        let mut candidates = self.speculative.lock();
        let attempt = candidates.find_mut(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, candidate)
        })?;
        let endpoint_auth = attempt.endpoint_auth.as_ref()?.clone();
        let capability = attempt.authenticated_channel.as_ref()?;
        if endpoint_auth.is_retired()
            || !candidate.owns_endpoint_auth(&endpoint_auth)
            || !capability.belongs_to(endpoint_auth.incarnation())
            || !endpoint_auth.issued(capability)
            || !endpoint_auth
                .context_matches(mesh_context, crate::signing::pubkey_part(&self.device_id))
        {
            return None;
        }
        // The claim covers both the ProofDelivery and the ordered Deny.  It
        // is one bounded witness, so a failed first send cannot leave an
        // unfunded second send or any retry loop hidden behind the candidate.
        let claim =
            crate::application_gateway::AdmittedApplicationFrame::claim(total_bytes).ok()?;
        let work = candidate.reserve_attempt_work(claim).ok()?;
        Some((endpoint_auth, work))
    }

    /// Atomically move an authenticated speculative connector into the
    /// promoted slot.  The caller holds the registry mutation fence, so the
    /// predecessor can be retired after this returns without a device-id
    /// re-resolution race.
    pub(super) fn promote_speculative_if_needed(
        &self,
        correlation: &str,
        candidate: &Arc<WebRtcConnectorWorker>,
        broker: &crate::runtime::session_broker::SessionBroker,
        mesh_context: &str,
        policy_admits: bool,
    ) -> Option<SpeculativePromotion> {
        if self.registry_retired()
            || !policy_admits
            || !self.application_capability_admits()
            || self.unpromoted_offer_in_flight()
        {
            return None;
        }
        let (
            candidate,
            connector,
            capability,
            endpoint_auth,
            correlation,
            mut dedup,
            additional_dedup,
        ) = {
            let mut candidates = self.speculative.lock();
            let attempt = candidates.find_mut(|attempt| {
                attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, candidate)
            })?;
            let endpoint_auth = attempt.endpoint_auth.as_ref()?.clone();
            if endpoint_auth.is_retired() || !attempt.session.owns_endpoint_auth(&endpoint_auth) {
                return None;
            }
            let connector = attempt.session.live_connector_incarnation().cloned()?;
            let capability = attempt.authenticated_channel.take()?;
            let endpoint_auth = attempt
                .endpoint_auth
                .take()
                .expect("the checked endpoint-auth task remains installed");
            (
                Arc::clone(&attempt.session),
                connector,
                capability,
                endpoint_auth,
                attempt.correlation.clone(),
                attempt.dedup.take(),
                std::mem::replace(&mut attempt.additional_dedup, PromotedDedupSet::new()),
            )
        };
        let policy = crate::runtime::session_broker::CurrentPolicyAdmission::from_admitted_peer(
            mesh_context,
            &self.device_id,
            true,
        );
        let mut channel = Some(capability);
        let promoted = match self
            .promoted_session
            .with_established_session(|established| {
                broker.promote_additional(&mut channel, &connector, policy, established)
            }) {
            Some(Ok(promoted)) => promoted,
            Some(Err(_)) | None => {
                if let Some(capability) = channel {
                    let mut candidates = self.speculative.lock();
                    if let Some(attempt) =
                        candidates.find_mut(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
                    {
                        // Capacity refusal leaves the exact authenticated
                        // channel in `channel`; restore it together with the
                        // Endpoint Auth and all candidate-owned dedup custody.
                        attempt.authenticated_channel = Some(capability);
                        attempt.endpoint_auth = Some(endpoint_auth);
                        attempt.dedup = dedup;
                        attempt.additional_dedup = additional_dedup;
                    } else {
                        endpoint_auth.retire();
                    }
                } else {
                    // The broker consumed the channel on a terminal refusal.
                    // Keep the candidate's remaining custody attached to this
                    // exact attempt until its normal terminal edge.
                    let mut candidates = self.speculative.lock();
                    if let Some(attempt) =
                        candidates.find_mut(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
                    {
                        attempt.endpoint_auth = Some(endpoint_auth);
                        attempt.dedup = dedup;
                        attempt.additional_dedup = additional_dedup;
                    } else {
                        endpoint_auth.retire();
                    }
                }
                return None;
            }
        };
        let binding = PromotedChannelBinding {
            worker: Arc::clone(&candidate),
            endpoint_auth: Some(Arc::clone(&endpoint_auth)),
            correlation: correlation.clone(),
            dedup: dedup.take(),
            additional_dedup,
        };
        if let Err(refusal) =
            self.promoted_session
                .add_channel(promoted, candidate.new_session_flows(), binding)
        {
            let (_reason, session, flows, binding) = refusal.into_parts();
            let crate::runtime::peer_session::PromotedChannelBinding {
                worker: binding_worker,
                endpoint_auth: returned_endpoint_auth,
                correlation: returned_correlation,
                dedup: returned_dedup,
                additional_dedup: returned_additional_dedup,
            } = *binding;
            let authenticated = (*session)
                .demote()
                .expect("a refused additional session retains its authenticated channel");
            debug_assert!(Arc::ptr_eq(&binding_worker, &candidate));
            debug_assert_eq!(returned_correlation, correlation);
            drop(flows);
            // Slot allocation refusal is retryable. Restore the exact
            // speculative owner rather than retiring a candidate whose
            // Endpoint Auth and authenticated capability remain valid.
            if let Some(attempt) = self
                .speculative
                .lock()
                .find_mut(|attempt| Arc::ptr_eq(&attempt.session, &candidate))
            {
                attempt.authenticated_channel = Some(authenticated);
                attempt.endpoint_auth = returned_endpoint_auth;
                attempt.dedup = returned_dedup;
                attempt.additional_dedup = returned_additional_dedup;
            } else if let Some(endpoint_auth) = returned_endpoint_auth {
                endpoint_auth.retire();
            }
            return None;
        }
        let mut candidates = self.speculative.lock();
        let _ = candidates.remove_where(|attempt| {
            attempt.correlation == correlation && Arc::ptr_eq(&attempt.session, &candidate)
        });
        Some(SpeculativePromotion {
            displaced_attempt: None,
            // Selection is now an explicit policy seam; authenticated
            // promotion must not implicitly select the newly added channel.
            selected: false,
        })
    }

    pub(super) fn new(device_id: String, worker: Option<Arc<WebRtcConnectorWorker>>) -> Self {
        Self::new_with_attempt(device_id, worker, mint_attempt(), None)
    }

    pub(super) fn new_introduction(
        device_id: String,
        attempt: String,
        backing: crate::resource::ResourceLease,
    ) -> Self {
        Self::new_with_attempt(device_id, None, attempt, Some(backing))
    }

    fn new_with_attempt(
        device_id: String,
        worker: Option<Arc<WebRtcConnectorWorker>>,
        attempt: String,
        backing: Option<crate::resource::ResourceLease>,
    ) -> Self {
        Self {
            device_id,
            state: RwLock::new(PeerStateData::default()),
            unpromoted_connector: Mutex::new(worker.map(|worker| UnpromotedConnector { worker })),
            speculative: Mutex::new(AttemptOwnerSet::new()),
            closing_workers: Mutex::new(AttemptOwnerSet::new()),
            closing_waiters: Mutex::new(Vec::new()),
            retired_dedup: Mutex::new(DetachedDedupSet::new()),
            signaling_runtime: RwLock::new(None),
            media_renegotiation_worker: Mutex::new(None),
            endpoint_auth: Mutex::new(None),
            authenticated_channel: Mutex::new(None),
            attempt: RwLock::new(attempt),
            attempt_dedup: Mutex::new(None),
            additional_attempt_dedup: Mutex::new(PromotedDedupSet::new()),
            promoted_session: crate::runtime::peer_session::PromotedSessionSlot::new(),
            registry_retired: AtomicBool::new(false),
            epoch: DIAGNOSTIC_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            unpromoted_offer_in_flight: AtomicBool::new(false),
            _introduction_backing: Mutex::new(backing.map(|lease| IntroductionBacking {
                lease,
                ticket: None,
                phase: IntroductionBackingPhase::InUse,
            })),
        }
    }

    /// Only a freshly installed empty placeholder may acquire this worker.
    /// The registry's exact-current fence must surround this synchronous call.
    pub(super) fn attach_introduction_worker(
        &self,
        worker: Arc<WebRtcConnectorWorker>,
        ticket: Option<super::hub_introduction::IntroductionTicket>,
    ) -> bool {
        if self.registry_retired()
            || self.holds_promoted_session()
            || self.has_authenticated_channel()
            || self.state.read().authenticated
        {
            return false;
        }
        let attempt = self.attempt.read();
        let backing = self._introduction_backing.lock();
        if !backing.as_ref().is_some_and(|backing| {
            backing.ticket == ticket
                && backing.phase == IntroductionBackingPhase::InUse
                && ticket.is_none_or(|ticket| ticket.matches_attempt(&attempt))
        }) {
            return false;
        }
        let mut slot = self.unpromoted_connector.lock();
        if slot.is_some() {
            return false;
        }
        *slot = Some(UnpromotedConnector { worker });
        true
    }

    /// Bind a never-published placeholder to the constructor's full ticket.
    /// Raw legacy test placeholders stay unbound and cannot become reusable.
    pub(super) fn bind_initial_introduction(
        &self,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> bool {
        if self.registry_retired()
            || self.state.read().authenticated
            || !self.introduction_is_empty()
        {
            return false;
        }
        let attempt = self.attempt.read();
        if !ticket.matches_attempt(&attempt) {
            return false;
        }
        let mut backing = self._introduction_backing.lock();
        let Some(backing) = backing.as_mut().filter(|backing| {
            backing.ticket.is_none() && backing.phase == IntroductionBackingPhase::InUse
        }) else {
            return false;
        };
        backing.ticket = Some(ticket);
        true
    }

    pub(super) fn introduction_ticket_matches(
        &self,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> bool {
        let attempt = self.attempt.read();
        ticket.matches_attempt(&attempt)
            && self
                ._introduction_backing
                .lock()
                .as_ref()
                .is_some_and(|backing| {
                    backing.ticket == Some(ticket)
                        && backing.phase == IntroductionBackingPhase::InUse
                })
    }

    /// Caller holds the registry mutation fence; nothing here selects a new
    /// owner. Any independent native/session/media/closing work forbids reset.
    fn introduction_is_empty(&self) -> bool {
        self.current_unpromoted_worker().is_none()
            && !self.holds_promoted_session()
            && !self.has_speculative()
            && !self.closing_workers.lock().any(|_| true)
            && self.closing_waiters.lock().is_empty()
            && !self.unpromoted_offer_in_flight()
            && self.endpoint_auth.lock().is_none()
            && self.authenticated_channel.lock().is_none()
            && self.media_renegotiation_worker.lock().is_none()
    }

    /// Only the exact joined demand-record transaction may call this. The
    /// original backing NEVER leaves the retained installation here. Failed
    /// native/join outcomes clear old truth but cannot authorize fresh reuse.
    pub(super) fn finish_retained_introduction(
        &self,
        ticket: super::hub_introduction::IntroductionTicket,
        reusable: bool,
    ) -> bool {
        if self.registry_retired() || !self.introduction_is_empty() {
            return false;
        }
        let attempt = self.attempt.read();
        if !ticket.matches_attempt(&attempt) {
            return false;
        }
        let mut backing = self._introduction_backing.lock();
        let Some(backing) = backing.as_mut().filter(|backing| {
            backing.ticket == Some(ticket) && backing.phase == IntroductionBackingPhase::Retiring
        }) else {
            return false;
        };
        drop(attempt); // registry mutation still excludes attempt replacement
        let mut old = {
            let mut data = self.state.write();
            std::mem::replace(
                &mut *data,
                PeerStateData {
                    status: PeerStatus::Offline,
                    ..PeerStateData::default()
                },
            )
        };
        // Hello's strings and other retained representation must die BEFORE
        // their lease, whose field precedes those strings in PeerStateData.
        let hello_retention = old.hello_retention.take();
        drop(old);
        drop(hello_retention);
        backing.phase = if reusable {
            IntroductionBackingPhase::Reusable
        } else {
            IntroductionBackingPhase::Unusable
        };
        true
    }

    /// Additional attempt proof for the registry's atomic no-worker cleanup.
    /// The registry checks lifecycle/installation while holding its mutation
    /// fence; this reads the original bounded correlation without cloning it.
    pub(super) fn unstarted_introduction_matches(&self, introduction_id: &[u8; 16]) -> bool {
        let attempt = self.attempt.read();
        let mut expected = [0u8; 32];
        hex::encode_to_slice(introduction_id, &mut expected).is_ok()
            && attempt.as_bytes() == expected.as_slice()
    }

    /// Adopt only discovery-only or exactly joined reusable storage under the
    /// registry fence. Return old funding until displaced ownership is gone.
    // Return the original move-only lease on refusal; boxing would add unfunded storage.
    #[allow(clippy::result_large_err)]
    pub(super) fn adopt_empty_introduction(
        &self,
        ticket: super::hub_introduction::IntroductionTicket,
        backing: crate::resource::ResourceLease,
    ) -> std::result::Result<
        (
            Option<AttemptDisplacement>,
            Option<crate::resource::ResourceLease>,
        ),
        crate::resource::ResourceLease,
    > {
        if self.registry_retired()
            || !self.introduction_is_empty()
            || self.state.read().authenticated
        {
            return Err(backing);
        }
        let mut attempt = self.attempt.write();
        let mut retained = self._introduction_backing.lock();
        if retained.as_ref().is_some_and(|previous| {
            previous.phase != IntroductionBackingPhase::Reusable || previous.ticket == Some(ticket)
        }) {
            return Err(backing);
        }
        // Incoming funding is owned before the fresh attempt allocation. Keep
        // old storage funded until the caller disposes displaced ownership.
        let previous = retained.replace(IntroductionBacking {
            lease: backing,
            ticket: Some(ticket),
            phase: IntroductionBackingPhase::InUse,
        });
        *attempt = ticket.attempt(); // one owned encoding, no borrowed-copy buffer
        drop(attempt);
        if previous.is_some() {
            self.state.write().status = PeerStatus::Sighted;
        }
        let displaced = AttemptDisplacement {
            dedup: self.attempt_dedup.lock().take(),
            additional_dedup: std::mem::replace(
                &mut *self.additional_attempt_dedup.lock(),
                PromotedDedupSet::new(),
            ),
            retired_dedup: DetachedDedupSet::new(),
        };
        drop(retained);
        Ok((Some(displaced), previous.map(|previous| previous.lease)))
    }

    pub(super) fn begin_unpromoted_negotiation(&self) -> bool {
        if self.registry_retired() || self.holds_promoted_session() {
            return false;
        }
        if self
            .unpromoted_offer_in_flight
            .compare_exchange(false, true, Ordering::Acquire, Ordering::Relaxed)
            .is_err()
        {
            return false;
        }
        if self.current_worker().is_none() {
            self.unpromoted_offer_in_flight
                .store(false, Ordering::Release);
            return false;
        }
        true
    }

    pub(super) fn unpromoted_offer_in_flight(&self) -> bool {
        self.unpromoted_offer_in_flight.load(Ordering::Acquire)
    }

    /// Return a clonable diagnostic view without copying mutable ownership.
    ///
    /// The advertisement is read through the live session first and bound to a
    /// local, **before** the state guard is taken. That order is required, not
    /// stylistic: the lender runs promotion, which holds `promoted_session`
    /// while re-reading `state`, so taking `state` first and the session second
    /// would close a lock cycle. A peer with no current session reports `None`,
    /// which is the truthful answer — nothing has been advertised over a session
    /// that does not exist.
    pub fn snapshot(&self) -> PeerStateSnapshot {
        self.with_peer_view(|view| {
            let capabilities = view.session.and_then(|app| app.capabilities());
            view.data.snapshot(capabilities)
        })
    }

    /// Lend this peer's session record and state data as **one** observation.
    ///
    /// This is the fence the snapshot paths were missing. The shape it replaces
    /// read the advertisement through the session lender, released that guard,
    /// and *then* took `state` — two observations stitched together, so a
    /// snapshot could pair one session's advert with state written after that
    /// session had already been replaced.
    ///
    /// Here the state guard is taken **inside** the session lender, so both are
    /// held together for the closure's whole life. That is the documented order
    /// and not a new one: the lender's own liveness predicate already takes
    /// `state.read()` while holding `promoted_session`, and no writer in this crate takes
    /// `state.write()` while holding the slot. Reversing it — state first, then
    /// the session — is the direction that closes a cycle, and it is what
    /// [`Self::with_live_session`]'s warning forbids.
    ///
    /// A peer with no current session yields `None` for the session half rather
    /// than being skipped. That is the truthful answer and it is why this cannot
    /// be written as a plain `Option` chain: an unpromoted peer still has state
    /// worth reporting, and it must be reported from the same read.
    ///
    /// **The closure must not re-enter the registry, the session lender, or the
    /// provider.** Two locks are held for its duration, and provider
    /// acquisition under them is exactly the reentrancy the resource discipline
    /// forbids. Callers measure and copy here; they acquire elsewhere.
    pub(super) fn with_peer_view<R>(&self, view: impl FnOnce(PeerView<'_>) -> R) -> R {
        // Moved through an `Option` because it is `FnOnce` and there are two
        // exits — a live session and none — and a closure cannot be called on
        // both paths.
        let mut view = Some(view);
        let seen = self.with_live_session_state(|_session, app| {
            let data = self.state.read();
            (view.take().expect("the peer view runs exactly once"))(PeerView {
                device_id: &self.device_id,
                data: &data,
                session: Some(app),
            })
        });
        match seen {
            Some(result) => result,
            None => {
                let data = self.state.read();
                (view.take().expect("the peer view runs exactly once"))(PeerView {
                    device_id: &self.device_id,
                    data: &data,
                    session: None,
                })
            }
        }
    }

    /// Retire the exact connector worker owned by this registry entry.
    /// External `Arc` holders cannot keep callbacks or queued candidates live.
    pub(crate) fn retire_connector(&self) {
        self.registry_retired.store(true, Ordering::Release);
        // Replacement invalidation is a security control, not housekeeping:
        // because the certificate-fingerprint binding is not session-unique,
        // exact connector ownership is what distinguishes this channel from
        // another between the same pair. A capability authenticated under the
        // retired connector must not survive into its replacement.
        drop(self.authenticated_channel.lock().take());
        // The promoted session carries that same channel's authority, so it is
        // dropped on the same edge. Dropping it also releases its
        // post-authentication resource reservation, so a retired connector does
        // not hold session capacity its replacement then has to compete for.
        // The coalesced renegotiation slot is another strong worker owner; clear
        // it under the same retirement fence before collecting close custody.
        drop(self.media_renegotiation_worker.lock().take());
        let mut workers = self.promoted_session.take_workers_with_dedup();
        // Retire the endpoint-auth task at the source, so a superseded
        // connector refuses promotion rather than merely failing to install
        // afterwards. Without this the task stays live with its handoff
        // intact, `belongs_to` still answers true, and a late AuthResponse can
        // still mint a capability — one that install would reject, but only
        // after the fact. Retiring here makes `authenticate` fail closed with
        // `ChannelNotCurrent`.
        if let Some(task) = self.endpoint_auth.lock().as_ref() {
            task.retire();
        }
        while let Some(attempt) = self.speculative.lock().pop() {
            if let Some(task) = attempt.endpoint_auth {
                task.retire();
            }
            attempt.session.retire();
            workers.push((
                attempt.session,
                attempt.dedup,
                attempt.additional_dedup.drain_tokens(),
            ));
        }
        let worker = self.take_unpromoted_connector();
        if let Some(worker) = worker {
            workers.push((
                worker,
                self.attempt_dedup.lock().take(),
                std::mem::replace(
                    &mut *self.additional_attempt_dedup.lock(),
                    PromotedDedupSet::new(),
                )
                .drain_tokens(),
            ));
        }
        for (worker, dedup, additional_dedup) in workers {
            self.retain_closing_worker_with_dedup(worker, dedup, additional_dedup);
        }
    }

    pub(super) fn take_retired_dedup(&self) -> DetachedDedupSet {
        std::mem::replace(&mut *self.retired_dedup.lock(), DetachedDedupSet::new())
    }

    /// Fence the exact connector, await its single native cleanup owner, then
    /// release Endpoint Auth Task's connected-channel claim.
    pub(super) async fn retire_and_close(&self) -> crate::Result<()> {
        self.retire_connector();
        let result = self.await_retired_workers().await;
        drop(self.authenticated_channel.lock().take());
        self.promoted_session.clear();
        drop(self.endpoint_auth.lock().take());
        result
    }

    /// Await every worker this peer already retired without retiring the live
    /// logical session. Candidate refusal uses this in controls to prove the
    /// native owners really settled; full peer teardown calls it after first
    /// moving every remaining worker into the same list.
    pub(super) async fn await_retired_workers(&self) -> crate::Result<()> {
        let mut result = Ok(());
        loop {
            let mut workers = Vec::new();
            self.closing_workers
                .lock()
                .for_each(|entry| workers.push(Arc::clone(&entry.worker)));
            if workers.is_empty() {
                let waiters = std::mem::take(&mut *self.closing_waiters.lock());
                for (_, waiter) in waiters {
                    if let Err(error) = waiter.await {
                        tracing::warn!(%error, "exact retired connector waiter failed");
                    }
                }
                return result;
            }
            for worker in &workers {
                worker.start_close();
            }
            let outcomes =
                futures::future::join_all(workers.into_iter().map(|worker| async move {
                    let outcome = worker.retire_and_close().await;
                    (worker, outcome)
                }))
                .await;
            for (worker, outcome) in outcomes {
                if let Err(error) = outcome {
                    if result.is_ok() {
                        result = Err(error);
                    }
                }
                self.complete_closing_worker(&worker);
            }
        }
    }

    #[cfg(test)]
    pub(super) fn retired_worker_count_for_test(&self) -> usize {
        self.closing_workers.lock().len()
    }

    pub(super) fn registry_retired(&self) -> bool {
        self.registry_retired.load(Ordering::Acquire)
    }

    /// Final synchronous idle check, called only under the registry mutation
    /// fence with the exact demand worker and an exclusive use reservation.
    /// Do not equate an empty flow map with joined native tails: the provider
    /// includes its outstanding funded pumps/retirement owners in quiescence.
    pub(super) fn demand_queues_quiescent(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        if self.promoted_channel_count() != 1
            || self.unpromoted_connector.lock().is_some()
            || self.has_speculative()
            || self.has_pending_media_renegotiation()
            || self.closing_workers.lock().any(|_| true)
        {
            return false;
        }
        if self.with_live_session_state(|_session, app| {
            app.pending() == 0 && app.rpc_mut().pending_is_empty()
        }) != Some(true)
        {
            return false;
        }
        self.with_live_session_flow_and_exact_worker(worker, |_session, flows, _live, _worker| {
            flows.is_quiescent()
        }) == Some(true)
    }

    pub(super) fn install_endpoint_auth(
        &self,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        if self.promoted_session.is_installed() {
            return false;
        }
        let exact_connector = self
            .current_unpromoted_worker()
            .is_some_and(|worker| worker.owns_endpoint_auth(&task));
        if !exact_connector {
            return false;
        }
        let mut current = self.endpoint_auth.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(task);
        true
    }

    pub(super) fn endpoint_auth_is_current(
        &self,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        self.endpoint_auth_task()
            .is_some_and(|current| Arc::ptr_eq(&current, task))
    }

    /// The current endpoint-auth task, if this entry still owns one.
    pub(super) fn endpoint_auth_task(&self) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        if self.registry_retired() {
            return None;
        }
        if self.promoted_session.is_installed() {
            return self
                .promoted_session
                .selected_worker()
                .as_ref()
                .and_then(|worker| self.promoted_session.endpoint_auth_for(worker));
        }
        self.endpoint_auth.lock().clone()
    }

    pub(super) fn endpoint_auth_task_for(
        &self,
        worker: Option<&Arc<WebRtcConnectorWorker>>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        if self.registry_retired() {
            return None;
        }
        let Some(worker) = worker else {
            return self.endpoint_auth_task();
        };
        if self.promoted_session.is_installed() {
            return self.promoted_session.endpoint_auth_for(worker);
        }
        self.promoted_session.endpoint_auth_for(worker).or_else(|| {
            self.unpromoted_connector
                .lock()
                .as_ref()
                .filter(|current| Arc::ptr_eq(&current.worker, worker))
                .and_then(|_| self.endpoint_auth.lock().clone())
        })
    }

    pub(super) fn attempt_for_worker(&self, worker: &Arc<WebRtcConnectorWorker>) -> Option<String> {
        self.promoted_session.correlation_for(worker).or_else(|| {
            self.current_worker()
                .as_ref()
                .filter(|current| Arc::ptr_eq(current, worker))
                .map(|_| self.attempt())
        })
    }

    pub(super) fn owns_authenticated_worker(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        !self.registry_retired()
            && (self.promoted_session.contains_worker(worker)
                || self
                    .current_worker()
                    .is_some_and(|current| Arc::ptr_eq(&current, worker)))
    }

    pub(super) fn mark_media_renegotiation(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        if !self.application_capability_admits() || !self.owns_authenticated_worker(worker) {
            return false;
        }
        let mut pending = self.media_renegotiation_worker.lock();
        // Retirement may have removed this exact channel after the optimistic
        // check above. Re-prove ownership while holding the coalescing slot so a
        // stale caller cannot repopulate it after retirement clears the slot.
        if !self.application_capability_admits() || !self.owns_authenticated_worker(worker) {
            return false;
        }
        match pending.as_ref() {
            None => {
                *pending = Some(Arc::clone(worker));
                true
            }
            Some(current) => Arc::ptr_eq(current, worker),
        }
    }

    pub(super) fn media_renegotiation_worker(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        self.media_renegotiation_worker.lock().clone()
    }

    pub(super) fn clear_media_renegotiation_worker(&self, worker: &Arc<WebRtcConnectorWorker>) {
        let mut pending = self.media_renegotiation_worker.lock();
        if pending
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, worker))
        {
            drop(pending.take());
        }
    }

    pub(super) fn has_pending_media_renegotiation(&self) -> bool {
        self.media_renegotiation_worker.lock().is_some()
    }

    pub(super) fn retire_authenticated_worker(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> Option<crate::runtime::peer_session::RemovedPromotedChannel> {
        let removed = self.promoted_session.remove_channel(worker)?;
        self.clear_media_renegotiation_worker(worker);
        if removed.selection_needed {
            // Selection is explicit: only the slot may certify that exactly
            // one surviving channel is still live and capability-bound.
            let _ = self.select_unique_usable_channel();
        }
        self.retain_closing_worker(Arc::clone(&removed.worker));
        Some(removed)
    }

    /// Observe the actual typed acquisition result without restoring a work
    /// scope withdrawn by the authenticated handoff's ordinary Drop.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn reserve_closing_entry_for_test(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> std::result::Result<ResourceLease, crate::resource::ResourceUnavailable> {
        worker.reserve_attempt_work(
            AttemptOwnerSet::<ClosingWorker>::entry_claim()
                .expect("closing owner node claim is representable"),
        )
    }

    /// Distinct finite-pressure control BEFORE an owned connected handoff
    /// drops. It must not be described as promoted-channel removal pressure.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn retain_closing_worker_under_pressure_for_test(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
    ) -> std::result::Result<(ResourceLease, crate::resource::ResourcePressure), &'static str> {
        let pressure = (|| {
            use crate::resource::{FiniteResourceProvider, ResourceUnavailable};
            let entry = AttemptOwnerSet::<ClosingWorker>::entry_claim()
                .map_err(|_| "closing entry claim overflow")?;
            let charge = FiniteResourceProvider::reservation_charge_for_test(entry)
                .map_err(|_| "closing entry reservation overflow")?;
            let record = FiniteResourceProvider::reservation_charge_for_test(ResourceClaim::ZERO)
                .map_err(|_| "seal reservation overflow")?;
            // Prove this exact acquisition could succeed before applying the
            // seal. No permanent fixture grant or production claim changes.
            drop(
                worker
                    .reserve_attempt_work(entry)
                    .map_err(|_| "closing entry already unavailable before pressure")?,
            );
            let free = match worker.reserve_attempt_work(ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                u64::MAX,
            )) {
                Err(ResourceUnavailable::Pressure(pressure))
                    if pressure.dimension == ResourceClass::AccountedMemoryBytes =>
                {
                    pressure
                        .capacity
                        .checked_sub(pressure.in_use)
                        .ok_or("pressure usage exceeds capacity")?
                }
                _ => return Err("memory probe did not report finite pressure"),
            };
            let leave = charge
                .amount(ResourceClass::AccountedMemoryBytes)
                .checked_sub(1)
                .ok_or("closing entry has no accounted byte")?;
            let seal_bytes = free
                .checked_sub(leave)
                .and_then(|amount| {
                    amount.checked_sub(record.amount(ResourceClass::AccountedMemoryBytes))
                })
                .ok_or("insufficient slack for exact pressure seal")?;
            let seal = worker
                .reserve_attempt_work(ResourceClaim::single(
                    ResourceClass::AccountedMemoryBytes,
                    seal_bytes,
                ))
                .map_err(|_| "reported slack could not fund the seal")?;
            match worker.reserve_attempt_work(entry) {
                Err(ResourceUnavailable::Pressure(pressure))
                    if pressure.dimension == ResourceClass::AccountedMemoryBytes
                        && pressure.capacity.checked_sub(pressure.in_use) == Some(leave) =>
                {
                    Ok((seal, pressure))
                }
                _ => Err("exact closing entry did not refuse at one byte short"),
            }
        })();
        // Exercise the unchanged real acquisition/fallback even if test
        // preparation failed; the caller still awaits original cleanup.
        self.retain_closing_worker(Arc::clone(worker));
        pressure
    }

    pub(super) fn take_attempt_displacement(&self) -> AttemptDisplacement {
        let additional_dedup = std::mem::replace(
            &mut *self.additional_attempt_dedup.lock(),
            PromotedDedupSet::new(),
        );
        AttemptDisplacement {
            dedup: self.attempt_dedup.lock().take(),
            additional_dedup,
            retired_dedup: DetachedDedupSet::new(),
        }
    }

    pub(super) fn take_current_dedups(&self) -> DedupDrain {
        DedupDrain {
            primary: self.attempt_dedup.lock().take(),
            additional: std::mem::replace(
                &mut *self.additional_attempt_dedup.lock(),
                PromotedDedupSet::new(),
            )
            .drain_tokens(),
        }
    }

    /// Build an entry that already holds `task` as its current endpoint-auth
    /// task, without a connector worker.
    ///
    /// The worker check in [`Self::install_endpoint_auth`] is deliberately
    /// bypassed: it is not what this seam exists to exercise. Controls use it
    /// to drive the real [`Self::install_authenticated_channel`] — including
    /// its capability/incarnation binding — against tasks built from genuine
    /// connector fixtures, which live in the transport module's test tree.
    #[cfg(test)]
    pub(crate) fn with_endpoint_auth_for_test(
        device_id: String,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> Self {
        let peer = Self::new(device_id, None);
        *peer.endpoint_auth.lock() = Some(task);
        peer
    }

    /// Install the authenticated-channel capability produced by `task`.
    ///
    /// Refused unless `task` is still this entry's current endpoint-auth task,
    /// is not retired, and the entry has not been retired — so a capability
    /// cannot be installed against a channel that has already been replaced.
    /// Refused a second time, so one channel yields at most one installed
    /// capability. Also refused unless the capability was promoted from that
    /// same connector incarnation.
    pub(crate) fn install_authenticated_channel(
        &self,
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
        capability: crate::endpoint_auth::AuthenticatedChannelCapability,
    ) -> bool {
        let mut current = self.authenticated_channel.lock();
        if current.is_some() {
            return false;
        }
        // Rechecked *under* the slot lock, not before taking it. Checking
        // first would leave a window in which `retire_connector` sets retired,
        // takes an empty slot, and returns — after which this call would write
        // a capability into an already-invalidated entry, surviving the very
        // replacement invalidation it is supposed to obey. With the recheck
        // here, retirement either lands before it (and is seen) or blocks on
        // this same lock and takes the capability we just installed.
        // `is_retired` is checked explicitly: a task can be retired between
        // `authenticate` returning and this install, and it stays in the slot
        // when that happens, so slot identity alone would not notice.
        if self.registry_retired() || task.is_retired() || !self.endpoint_auth_is_current(task) {
            return false;
        }
        // The capability must have been promoted from *this* task's connector
        // incarnation. Checking only that `task` is current would accept a
        // capability promoted from a superseded channel whenever the caller
        // supplied the current task alongside it — a cross-channel relay the
        // certificate-fingerprint binding cannot rule out by itself.
        if !capability.belongs_to(task.incarnation()) {
            return false;
        }
        // And it must carry *this* task's authenticated context. The answer
        // comes from the capability's own private record — mesh, local and
        // remote Device, profile, and connector — not from anything the caller
        // supplied, so a capability authenticated for another mesh or another
        // peer is refused here even when the current task is handed in with it.
        if !task.issued(&capability) {
            return false;
        }
        *current = Some(capability);
        true
    }

    /// Install a real authenticated capability, bypassing only provenance.
    ///
    /// For call-site tests that need to exercise the inbound / send / reliable
    /// wiring rather than the promotion path. The capability installed here is
    /// a genuine [`crate::endpoint_auth::AuthenticatedChannelCapability`], so
    /// the gate is satisfied the same way production satisfies it — what is
    /// skipped is only the connector-provenance check, which is proven
    /// separately by the transport controls. This is deliberately not a way to
    /// make [`Self::has_authenticated_channel`] answer `true` without a
    /// capability present.
    #[cfg(test)]
    pub(crate) fn install_authenticated_channel_for_test(&self) {
        *self.authenticated_channel.lock() = Some(crate::endpoint_auth::authenticated_for_test(
            crate::runtime::runtime_for_test(),
        ));
    }

    /// Install a real authenticated capability **for this entry's own live
    /// connector**, in this Mesh's own context.
    ///
    /// The difference from [`Self::install_authenticated_channel_for_test`] is
    /// the whole point: that one installs a capability bound to a fixture
    /// connector, a fixture runtime, and a fixture context, which satisfies
    /// `has_authenticated_channel` but can never promote — `promote` compares
    /// the connector by pointer identity and the runtime by incarnation, and
    /// `is_current_for` re-proves the mesh context and remote Device at every
    /// use. A control that needs a *promoted session* therefore needs this
    /// form, which takes the handoff the peer's own connector produced and
    /// names this Mesh and this peer.
    ///
    /// Provenance is still the only thing skipped: no exchange ran, so the
    /// task-issued path is bypassed exactly as above. Every conjunct promotion
    /// actually evaluates is real, so promotion can still refuse — and does,
    /// for a retired connector, an unadmitted peer, a foreign context, or
    /// exhausted session capacity.
    ///
    /// `handoff` is moved: it carries the connected claim's retention
    /// obligation, so a capability built from it and then dropped returns that
    /// claim through the connector's own close owner rather than releasing it
    /// early.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn install_authenticated_channel_over_for_test(
        &self,
        handoff: crate::connector::ConnectedChannelHandoff,
        mesh_context: &str,
        local_device_id: &str,
    ) {
        let capability = crate::endpoint_auth::authenticated_over_for_test(
            handoff,
            mesh_context,
            local_device_id,
            &self.device_id,
        );
        *self.authenticated_channel.lock() = Some(capability);
    }

    /// Whether a promoted `SessionCapability` is installed on this entry.
    ///
    /// Observation only: it cannot lend one, clone one, or revive one, and it
    /// answers nothing about whether that session would still be admitted.
    /// Controls need it to separate "the fence refused and dropped the session"
    /// from "the fence refused and left it installed" — which is the whole
    /// difference between a revocation that takes effect and one that merely
    /// declines the next call while the authority stays alive behind it.
    ///
    /// **This is also what "a live session" means, and the booleans it replaces
    /// were not it.** `authenticated && data_channel_open` describes the transport
    /// underneath a session; promotion is the session. Two owners now read this
    /// rather than those booleans: graceful departure, which may only depart a
    /// session that exists, and the carrier-withdrawal arm, which may not retire
    /// one. A channel that has closed while recovery or replacement is in
    /// progress leaves the promoted session installed, and that is the whole
    /// point - the connector and the Peer Session own that state, not signaling.
    ///
    /// Production, and there is no counterfeit. Only a real connector promotes,
    /// which is why every control that needs the true case lives behind
    /// `transport-lab`; a control that wanted to fake one would be asserting
    /// against a session the product cannot produce.
    pub(crate) fn holds_promoted_session(&self) -> bool {
        self.promoted_session.is_installed()
    }

    /// Whether this current installation still has a usable recovery path.
    ///
    /// A promoted session is usable when any channel still proves both a live
    /// connector incarnation and capability membership. Selection is not part
    /// of this observation: multiple usable channels remain ambiguous and are
    /// deliberately left untouched. An unpromoted installation is usable only
    /// when its current connector is still live.
    pub(crate) fn has_usable_session_for_recovery(&self) -> bool {
        if self.registry_retired() {
            return false;
        }
        if self.promoted_session.is_installed() {
            return self.promoted_session.has_usable_channel();
        }
        self.unpromoted_connector
            .lock()
            .as_ref()
            .is_some_and(|owner| owner.worker.live_connector_incarnation().is_some())
    }

    pub(super) fn promoted_channel_count(&self) -> usize {
        self.promoted_session.channel_count()
    }

    /// Select the sole exact channel that still proves live connector and
    /// capability membership. Zero or multiple usable channels leave the
    /// logical session unselected; admission never calls this implicitly.
    pub(super) fn select_unique_usable_channel(&self) -> Option<Arc<WebRtcConnectorWorker>> {
        self.promoted_session.select_unique_usable()
    }

    /// Select one exact installed promoted channel without consulting channel
    /// order or applying fallback policy. The slot owns the identity check.
    #[cfg(test)]
    pub(super) fn select_promoted_channel(&self, worker: &Arc<WebRtcConnectorWorker>) -> bool {
        self.promoted_session.select_channel(worker)
    }

    /// Promote this entry's authenticated channel into a live session, once.
    ///
    /// Called only from inside the registry mutation lock, which is what makes
    /// the policy conjunct true of *this installation* rather than of a device
    /// id a replacement may have taken over. It takes no registry lock itself.
    ///
    /// Idempotent by construction: a session already promoted for the live
    /// connector is reused, so one channel yields at most one session and one
    /// resource reservation. A cached session that no longer names the live
    /// connector is dropped rather than returned — that is the replacement
    /// invalidation, applied at use.
    ///
    /// The capability is never taken out of its slot here. The slot is lent to
    /// the broker, which borrows the channel for every fallible step and moves
    /// it out only after the post-authentication reservation succeeds. A
    /// capacity refusal therefore leaves the exact channel installed, and the
    /// next operation retries it; a terminal refusal — superseded connector,
    /// refused policy, runtime disagreement — empties the slot inside the
    /// broker, because a capability whose own record does not match this entry's
    /// context is one this entry must not keep.
    ///
    /// The selected slot is consulted before the unpromoted phase state, and
    /// each guard is released before the next slot/fence is taken.
    /// This keeps membership and selection in one authority while avoiding a
    /// nested slot/mirror lock cycle. Reading the worker a moment early costs
    /// nothing: a connector that retires in the gap fails the `is_current_for`
    /// recheck below, or the `is_active` proof before promotion, or — for a
    /// session installed against a connector that retired immediately after —
    /// the `belongs_to` check at the next use. Every one of those refuses
    /// rather than admits.
    pub(super) fn promote_session_if_needed(
        &self,
        broker: &crate::runtime::session_broker::SessionBroker,
        mesh_context: &str,
        policy_admits: bool,
    ) -> Promotion {
        // An inbound legacy Offer holds this exact-owner witness across its
        // awaited SDP application, attempt adoption, and answer creation.
        // Refuse promotion for that same installation until the complete Offer
        // mutation has finished; otherwise the later answer-side effect could
        // run against a session promoted after the Offer's initial check.
        if self.unpromoted_offer_in_flight() {
            return Promotion::Refused;
        }
        // The promoted slot is retained authority, not a bypass around the
        // current registry fence. A policy revocation or exact registry
        // retirement must destroy it before the slot can report `Current`;
        // otherwise a later operation would reuse a session minted under an
        // admission the mesh has already withdrawn.
        if self.registry_retired() || !policy_admits || !self.application_capability_admits() {
            self.promoted_session.clear();
            return Promotion::Refused;
        }
        let worker = self.current_worker();
        let live_connector = worker
            .as_ref()
            .and_then(|worker| worker.live_connector_incarnation().cloned());
        // A promoted bundle may intentionally have no selected transport
        // while its other authenticated channels and logical application
        // state remain live. Selection is explicit; do not let the reuse
        // probe below treat that unselected bundle as revoked and discard the
        // logical session.
        if self.promoted_session.is_installed() && self.promoted_session.selected_worker().is_none()
        {
            return Promotion::Refused;
        }
        // The use-time recheck, not merely a currentness test: current policy,
        // connector, mesh context, remote Device, principal and reservation
        // runtime are all re-proved against the session's own record before it
        // authorizes anything.
        //
        // Policy belongs in that conjunction and not only on the promotion path
        // below. Admission is *retained* state: an eviction, a denial or a
        // topology change revokes it long after promotion, and a session
        // promoted while it held would otherwise never be asked again — every
        // operation this fence admits would keep running for a peer the mesh has
        // since refused.
        match self.promoted_session.reuse_or_revoke() {
            crate::runtime::peer_session::Reuse::Current => return Promotion::Current,
            // Refused outright rather than re-promoted. Promoting again here
            // would take a fresh post-authentication reservation for authority
            // that was just withdrawn, on the same call that observed the
            // withdrawal.
            crate::runtime::peer_session::Reuse::Revoked => return Promotion::Refused,
            crate::runtime::peer_session::Reuse::Vacant => {}
        }

        let (Some(connector), Some(worker)) = (live_connector, worker) else {
            return Promotion::Refused;
        };
        // Re-proved under `promoted_session`, because the incarnation was read
        // before that guard was taken. This is the narrow window the lock order
        // opens, and closing it here means a connector that retired in the gap
        // costs a refused promotion rather than a session installed against a
        // connector that is already gone. Asked of the worker, which is where
        // the adapter's retirement state lives — the incarnation itself is an
        // identity token and answers no liveness question.
        if worker.live_connector_incarnation().is_none() {
            return Promotion::Refused;
        }
        let policy = crate::runtime::session_broker::CurrentPolicyAdmission::from_admitted_peer(
            mesh_context,
            &self.device_id,
            true,
        );
        // The slot is lent to the broker, not its contents. The channel is
        // borrowed for every fallible step and moved out only once the
        // post-authentication reservation has been taken, so a capacity refusal
        // leaves this entry's exact authenticated channel installed and the next
        // application operation retries that same proven channel. The terminal
        // refusals — superseded connector, refused policy, runtime disagreement —
        // still empty the slot, inside the broker, where the decision is made.
        let promotion = {
            let mut channel = self.authenticated_channel.lock();
            broker.promote(&mut channel, &connector, policy)
        };
        match promotion {
            Ok(session) => {
                // The flow set is built by the exact worker this session was
                // promoted from, so its registry and the session's connector are
                // the same one by construction rather than by a later check.
                // Real Endpoint Auth always leaves its exact task here. The
                // optional form is reserved for the transport-lab helper that
                // installs a real capability directly and therefore has no
                // task to counterfeit merely to exercise this admission seam.
                let endpoint_auth = self.endpoint_auth.lock().clone();
                let correlation = self.attempt();
                let install = self.promoted_session.install(
                    session,
                    worker.new_session_flows(),
                    PromotedChannelBinding {
                        worker: Arc::clone(&worker),
                        endpoint_auth,
                        correlation,
                        dedup: self.attempt_dedup.lock().take(),
                        additional_dedup: std::mem::replace(
                            &mut *self.additional_attempt_dedup.lock(),
                            PromotedDedupSet::new(),
                        ),
                    },
                );
                if let Err(refusal) = install {
                    // Slot allocation is a capacity refusal, not a channel
                    // revocation.  Move the exact authenticated capability
                    // back out of the broker session and restore every
                    // unpromoted owner before returning; dropping the session
                    // here would make a transient slot shortage destroy the
                    // only retryable authenticated channel.
                    let (_reason, session, flows, binding) = refusal.into_parts();
                    let crate::runtime::peer_session::PromotedChannelBinding {
                        worker: binding_worker,
                        endpoint_auth,
                        correlation: binding_correlation,
                        dedup,
                        additional_dedup,
                    } = *binding;
                    let authenticated = (*session)
                        .demote()
                        .expect("a refused promoted session retains its authenticated channel");
                    debug_assert!(Arc::ptr_eq(&binding_worker, &worker));
                    debug_assert_eq!(binding_correlation, self.attempt());
                    drop(flows);
                    *self.authenticated_channel.lock() = Some(authenticated);
                    if let Some(endpoint_auth) = endpoint_auth {
                        let mut current = self.endpoint_auth.lock();
                        if current.is_none() {
                            *current = Some(endpoint_auth);
                        }
                    }
                    *self.attempt_dedup.lock() = dedup;
                    *self.additional_attempt_dedup.lock() = additional_dedup;
                    return Promotion::Refused;
                }
                // Initial promotion establishes membership; selection is a
                // separate explicit seam even when this first channel is the
                // only one currently present.
                let _ = self.promoted_session.select_channel(&worker);
                Promotion::NewlyPromoted
            }
            // Includes the capacity refusal, which is not terminal: the exact
            // authenticated channel is still installed, so the next application
            // operation retries it and *that* promotion is the newly promoted
            // one. Nothing is announced for an attempt that minted no session.
            Err(_) => Promotion::Refused,
        }
    }

    /// Run one effect against this entry's live promoted session.
    ///
    /// The session is lent, never handed out: it is not `Clone`, and the borrow
    /// ends with the closure, so a caller cannot retain application authority
    /// past the fence that authorized it.
    /// Lend this entry's live session together with a **freshly acquired** live
    /// connector incarnation.
    ///
    /// The freshness is the whole point and it is structural, not a convention:
    /// the incarnation handed to `effect` is obtained from the current worker on
    /// this call, and `live_connector_incarnation` yields `None` once that
    /// connector is retired. A caller therefore cannot reach the closure with a
    /// stale identity, and cannot substitute one — it does not supply the
    /// argument, this does.
    ///
    /// That distinction matters because a retained `Arc<ConnectorIncarnation>`
    /// stays pointer-equal to itself forever. Validating a flow against the
    /// `Arc` it stored at open time proves only that the flow is the flow; it
    /// says nothing about whether the connector is still alive, so a retired
    /// peer would keep passing its own gate. Every flow operation must compare
    /// against an incarnation acquired now, which is what this hands out.
    ///
    /// The session is re-checked against that fresh identity before the effect
    /// runs, so a session promoted from a superseded connector yields `None`
    /// rather than an operation.
    /// Lend this entry's live session, and nothing else.
    ///
    /// The same fence as [`Self::with_live_session_flow`] — current worker, a
    /// freshly acquired live incarnation, a promoted session that belongs to it —
    /// projected down to the authority alone. An operation that needs to prove a
    /// session authorized it, but has no business touching the realtime flow set,
    /// asks for this: lending the flow set to a caller that only needed the proof
    /// would hand out a mutable namespace as a side effect of authorization.
    ///
    /// **Do not call this while holding a [`PeerStateData`] guard.** The lender
    /// runs promotion, and promotion holds `promoted_session` while it re-reads
    /// `state` for the retained-policy conjunct; entering here from inside a
    /// `state` guard closes a cycle in the opposite direction. Bind the result
    /// first, then take the guard.
    pub(super) fn with_live_session<R>(
        &self,
        effect: impl FnOnce(&crate::runtime::session_broker::SessionCapability) -> R,
    ) -> Option<R> {
        self.with_live_session_flow_and_worker(|session, _flows, _live, _worker| effect(session))
    }

    /// Lend this entry's live session together with the application state that
    /// session owns.
    ///
    /// The same fence again, projected to the pair that belongs to the
    /// application side: the authority, and the record whose lifetime *is* that
    /// authority's. Nothing here can outlive the session, because the borrow ends
    /// with the closure and the record is a field of the thing being borrowed
    /// from.
    ///
    /// Carries [`Self::with_live_session`]'s lock-order warning unchanged.
    pub(super) fn with_live_session_state<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        if !self.application_capability_admits() {
            return None;
        }
        self.promoted_session.with_live(|bundle| {
            let (session, app) = bundle.app_mut()?;
            Some(effect(session, app))
        })?
    }

    /// Lend only the logical application state named by the promoted-session
    /// witness.  This is deliberately independent of channel selection: an
    /// admitted frame may finish its funded logical commit after its carrying
    /// channel has been removed.  The slot's logical lender re-proves the
    /// session witness and returns `None` for a replacement or retired slot;
    /// no compatibility mirror participates in that decision.
    pub(super) fn with_logical_session_state<R>(
        &self,
        effect: impl FnOnce(&mut crate::runtime::peer_session::LogicalSessionOperation<'_>) -> R,
    ) -> Option<R> {
        self.promoted_session.with_logical_operation(effect)
    }

    pub(super) fn with_live_session_flow<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> R,
    ) -> Option<R> {
        self.with_live_session_flow_and_worker(|session, flows, live, _worker| {
            effect(session, flows, live)
        })
    }

    /// The same fence, additionally lending the connector worker.
    ///
    /// The one body both forms share, so the currency rule is stated once: two
    /// copies of a fence are two things that can drift, and the one that drifts
    /// is the one nobody is reading.
    ///
    /// The worker is lent for the operations that must reach the *native*
    /// connector — creating a transceiver or a track — which cannot happen
    /// under this lock because they await. A caller clones the handle out,
    /// releases the lock, does the async work, and re-enters to commit. The
    /// handle is not authority: it grants nothing this fence has not already
    /// proved, and re-entering proves it again rather than trusting the clone.
    pub(super) fn with_live_session_flow_and_worker<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        if !self.application_capability_admits() {
            return None;
        }
        let worker = self.current_worker()?;
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live(|bundle| {
            let (session, flows, channel_worker) = bundle.flows_mut()?;
            if !Arc::ptr_eq(channel_worker, &worker) {
                return None;
            }
            Some(effect(session, flows, &live, &worker))
        })?
    }

    pub(super) fn with_live_session_flow_and_exact_worker<R>(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        if !self.application_capability_admits() {
            return None;
        }
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live_worker(
            worker,
            |session| session.belongs_to(&live),
            |session, flows, channel_worker| effect(session, flows, &live, channel_worker),
        )
    }

    pub(super) fn with_live_session_flow_and_exact_worker_with_correlation<R>(
        &self,
        worker: &Arc<WebRtcConnectorWorker>,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<WebRtcConnectorWorker>,
            &str,
        ) -> R,
    ) -> Option<R> {
        if !self.application_capability_admits() {
            return None;
        }
        let live = worker.live_connector_incarnation()?.clone();
        self.promoted_session.with_live_worker_and_correlation(
            worker,
            |session| session.belongs_to(&live),
            |session, flows, channel_worker, correlation| {
                effect(session, flows, &live, channel_worker, correlation)
            },
        )
    }

    /// Whether this entry holds a live authenticated channel for its exact
    /// current connector.
    ///
    /// This is the provenance-carrying counterpart to
    /// `PeerStateData::authenticated`: a retired entry answers `false` even if
    /// the legacy bool is still set.
    /// The two slots are read **one at a time, never nested**, and that is a
    /// correctness requirement rather than a style choice.
    ///
    /// The promoted slot is inspected before `authenticated_channel`, and
    /// those locks are never nested here. [`Self::promote_session_if_needed`]
    /// may hold the promoted slot while it takes the capability slot, so the
    /// separate observations below must keep their guards short-lived rather
    /// than composing them into one lock-holding expression.
    ///
    /// Every other acquisition on this entry, here and elsewhere, takes exactly
    /// one of these locks per statement and releases it before the next, so no
    /// other pair can be held at once in either direction.
    pub(crate) fn has_authenticated_channel(&self) -> bool {
        if self.registry_retired() {
            return false;
        }
        // Either slot counts. Promotion *moves* the capability into the session,
        // so once a session exists the capability slot is empty and reading it
        // alone would report a promoted peer as unauthenticated — which would
        // un-admit the very peer that just satisfied every conjunct.
        let holds_capability = self.authenticated_channel.lock().is_some();
        if holds_capability {
            return true;
        }
        self.promoted_session.is_installed()
    }

    /// The single application admission predicate for this exact connection.
    ///
    /// Authentication alone is intentionally insufficient: a live data
    /// channel, an Endpoint Auth response, and an installed capability are
    /// transport proofs, not approval. Conversely, status alone is retained
    /// policy history and can survive replacement without a live capability.
    /// Application/RPC/reliable/realtime/governance/routing/media promotion and
    /// lending therefore use this conjunction at their connection boundary.
    /// The authenticated-but-pending durable semantic exception is owned by the
    /// registry's separate, explicitly scoped admission path.
    fn application_capability_admits(&self) -> bool {
        if self.registry_retired() || !self.has_authenticated_channel() {
            return false;
        }
        let data = self.state.read();
        data.authenticated && matches!(data.status, PeerStatus::Active | PeerStatus::Shelved)
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;

    #[test]
    fn application_admission_requires_authenticated_approved_capability() {
        let peer = PeerConnection::new("pre-auth-peer".to_string(), None);
        assert!(!peer.application_capability_admits());

        peer.install_authenticated_channel_for_test();
        assert!(!peer.application_capability_admits());

        {
            let mut state = peer.state.write();
            state.authenticated = true;
            state.status = PeerStatus::PendingApproval;
        }
        assert!(!peer.application_capability_admits());

        {
            let mut state = peer.state.write();
            state.status = PeerStatus::Active;
        }
        assert!(peer.application_capability_admits());
    }
}

/// Mint one attempt correlation.
///
/// Random rather than a counter: a counter would be a process-visible ordering,
/// and this must not order anything. Base32 of eight random bytes, which is the
/// same shape the carrier translations used to mint individually and short
/// enough to ride every candidate without being a payload.
fn mint_attempt() -> String {
    use rand::Rng;
    let bytes: [u8; 8] = rand::thread_rng().gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}
