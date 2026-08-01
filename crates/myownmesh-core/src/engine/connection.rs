//! Per-peer connection state held by the engine.
//!
//! Each entry in the engine's `peers` map is a [`PeerConnection`]:
//! the shared [`PeerStateData`] (status, tier, watermarks,
//! capabilities) plus the optional [`PeerSession`] handle to the
//! WebRTC layer.

use std::future::Future;
use std::mem::size_of;
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::protocol::CapabilityAdvert;
use crate::resource::{
    ObservationLease, PeerConnectionResourceScope, PreAuthResourceFamily, ResourceMeasurement,
    ResourceUse,
};
use crate::transport::{LocalIceCandidate, PeerDiag, PeerSession, SelectedCandidatePair};

use super::ladder::ConnectionTier;

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

/// One remote candidate paired with the observation that follows its current
/// owner. Moving this value moves the observation. Dropping it ends the
/// observation.
#[derive(Debug)]
pub(super) struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    observation: CandidateObservationLease,
}

impl PendingRemoteCandidate {
    fn observe(candidate: LocalIceCandidate, resource_scope: &PeerConnectionResourceScope) -> Self {
        let observation = CandidateObservationLease {
            _observation: resource_scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::CandidateObject,
                candidate_resource_measurement(&candidate),
            ),
        };
        Self {
            candidate,
            observation,
        }
    }
}

/// Apply an observed candidate while keeping its observation alive for the
/// complete asynchronous operation. Cancellation drops both the future and
/// its observation.
pub(super) async fn apply_pending_remote_candidate<F, Fut, T>(
    pending: PendingRemoteCandidate,
    apply: F,
) -> T
where
    F: FnOnce(LocalIceCandidate) -> Fut,
    Fut: Future<Output = T>,
{
    let PendingRemoteCandidate {
        candidate,
        observation,
    } = pending;
    let result = apply(candidate).await;
    drop(observation);
    result
}

#[derive(Debug)]
struct CandidateObservationLease {
    _observation: ObservationLease,
}

#[derive(Debug, Default)]
struct PendingRemoteCandidateQueue {
    entries: Vec<PendingRemoteCandidate>,
    container_observation: Option<ObservationLease>,
}

impl PendingRemoteCandidateQueue {
    fn push(&mut self, candidate: LocalIceCandidate, resource_scope: &PeerConnectionResourceScope) {
        self.entries
            .push(PendingRemoteCandidate::observe(candidate, resource_scope));
        let measurement = queue_container_resource_measurement(&self.entries);
        match self.container_observation.as_mut() {
            Some(observation) => observation.replace_measurement(measurement),
            None => {
                self.container_observation =
                    Some(resource_scope.observe_pre_authentication_measurement(
                        PreAuthResourceFamily::CandidateObject,
                        measurement,
                    ));
            }
        }
    }

    fn take(&mut self) -> PendingRemoteCandidateDrain {
        let queue = std::mem::take(self);
        PendingRemoteCandidateDrain {
            entries: queue.entries.into_iter(),
            _container_observation: queue.container_observation,
        }
    }
}

#[derive(Debug)]
pub(super) struct PendingRemoteCandidateDrain {
    entries: std::vec::IntoIter<PendingRemoteCandidate>,
    _container_observation: Option<ObservationLease>,
}

impl Default for PendingRemoteCandidateDrain {
    fn default() -> Self {
        Self {
            entries: Vec::new().into_iter(),
            _container_observation: None,
        }
    }
}

impl PendingRemoteCandidateDrain {
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.entries.len() == 0
    }
}

impl Iterator for PendingRemoteCandidateDrain {
    type Item = PendingRemoteCandidate;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for PendingRemoteCandidateDrain {}

fn candidate_resource_measurement(candidate: &LocalIceCandidate) -> ResourceMeasurement {
    let (logical_bytes, logical_inexact) = measured_sum([
        candidate.candidate.len(),
        candidate.sdp_mid.as_ref().map_or(0, String::len),
        candidate.username_fragment.as_ref().map_or(0, String::len),
    ]);
    let (retained_bytes, retained_inexact) = measured_sum([
        candidate.candidate.capacity(),
        candidate.sdp_mid.as_ref().map_or(0, String::capacity),
        candidate
            .username_fragment
            .as_ref()
            .map_or(0, String::capacity),
    ]);
    let observed = ResourceUse::observed(1, logical_bytes, retained_bytes, 0);
    if logical_inexact || retained_inexact {
        ResourceMeasurement::inexact(observed)
    } else {
        ResourceMeasurement::exact(observed)
    }
}

fn queue_container_resource_measurement(
    entries: &Vec<PendingRemoteCandidate>,
) -> ResourceMeasurement {
    let bytes = entries
        .capacity()
        .checked_mul(size_of::<PendingRemoteCandidate>());
    let (retained_bytes, inexact) = measured_usize(bytes);
    let observed = ResourceUse::observed(0, 0, retained_bytes, 0);
    if inexact {
        ResourceMeasurement::inexact(observed)
    } else {
        ResourceMeasurement::exact(observed)
    }
}

fn measured_usize(value: Option<usize>) -> (u64, bool) {
    match value.and_then(|value| u64::try_from(value).ok()) {
        Some(value) => (value, false),
        None => (u64::MAX, true),
    }
}

fn measured_sum<const N: usize>(values: [usize; N]) -> (u64, bool) {
    let mut sum = 0_u64;
    let mut inexact = false;
    for value in values {
        let (value, conversion_inexact) = measured_usize(Some(value));
        inexact |= conversion_inexact;
        match sum.checked_add(value) {
            Some(next) => sum = next,
            None => {
                sum = u64::MAX;
                inexact = true;
            }
        }
    }
    (sum, inexact)
}

#[derive(Debug)]
pub struct PeerStateData {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub authenticated: bool,
    /// Features the peer advertised in its `hello` (see
    /// `protocol::features`). Empty until the hello lands — and empty
    /// forever for a pre-features build, which is exactly the "assume
    /// nothing optional" senders must gate on.
    pub features: Vec<String>,
    pub local_approve_sent: bool,
    pub remote_approve_seen: bool,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    pub nonce_sent: Option<String>,
    pub nonce_received: Option<String>,
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
    /// `heartbeat::SKEW_WINDOW`.
    pub clock_skew_samples: Vec<i64>,
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
    /// A media lane opened or closed on this session and the SDP no
    /// longer matches — the media-renegotiation pass owes this peer one
    /// in-place offer. Coalesced: any number of lane changes between
    /// passes costs a single renegotiation.
    pub media_reneg_pending: bool,
    /// A media-renegotiation task is currently running for this peer
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
    /// True once we've successfully applied the peer's SDP via
    /// `set_remote_description`. Until this is true, inbound ICE
    /// candidates can't be added to the PC (webrtc-rs returns
    /// "remote description is not set") and would otherwise be
    /// dropped — including the LAN Host candidate that arrives
    /// trickle-style fractions of a second before the answer on a
    /// fast local network, which leaves the agent classifying the
    /// remote as `PeerReflexive` (discovered via STUN binding) and
    /// the GUI mis-painting a LAN link as STUN. We instead queue
    /// pre-SDP candidates in `pending_remote_candidates` and
    /// drain them inside `apply_remote_sdp` once the description
    /// is in place.
    pub remote_description_set: bool,
    /// Remote ICE candidates that arrived before we'd applied the
    /// peer's SDP. Drained and applied after the first successful
    /// `set_remote_description`; see [`remote_description_set`].
    pending_remote_candidates: PendingRemoteCandidateQueue,
    /// Count of inbound frames the admission gate dropped because the peer
    /// hadn't reached the phase they require (an application/RPC/reliable/
    /// governance/media frame arriving before the ed25519 handshake + approval
    /// finished). Drives a power-of-two-throttled warn so a pre-admission
    /// flood can't be turned into a log-amplification primitive.
    pub admission_rejected: u64,
    pub diag: PeerDiag,
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
    pub fn is_admitted(&self) -> bool {
        self.authenticated && matches!(self.status, PeerStatus::Active | PeerStatus::Shelved)
    }

    pub(super) fn take_pending_remote_candidates(&mut self) -> PendingRemoteCandidateDrain {
        self.pending_remote_candidates.take()
    }

    pub fn snapshot(&self) -> PeerStateSnapshot {
        PeerStateSnapshot {
            status: self.status,
            tier: self.tier,
            rtt_ms: self.rtt_ms,
            clock_skew_ms: self.clock_skew_ms,
            label: self.label.clone(),
            capabilities: self.capabilities.clone(),
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
            features: Vec::new(),
            local_approve_sent: false,
            remote_approve_seen: false,
            local_shelved: false,
            remote_shelved: false,
            label: String::new(),
            capabilities: None,
            nonce_sent: None,
            nonce_received: None,
            verification_code_sent: None,
            verification_code_received: None,
            last_recv_at: None,
            last_ping_sent_at: None,
            last_offer_sent_at: None,
            last_liveness_probe_at: None,
            last_ping_t: None,
            rtt_ms: None,
            clock_skew_samples: Vec::new(),
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
            remote_description_set: false,
            pending_remote_candidates: PendingRemoteCandidateQueue::default(),
            admission_rejected: 0,
            diag: PeerDiag::default(),
        }
    }
}

pub struct PeerConnection {
    pub device_id: String,
    pub state: RwLock<PeerStateData>,
    pub session: Mutex<Option<Arc<PeerSession>>>,
    resource_scope: PeerConnectionResourceScope,
    /// Monotonic id for *this* session of the peer. Each rebuild (drop +
    /// re-open) gets a fresh epoch, so transport events pumped in from a
    /// torn-down session — a `DataChannelClosed` for the old PC that lands
    /// a millisecond after the replacement session was created — can be
    /// recognised as stale and ignored, instead of calling `drop_peer` on
    /// the live session and triggering yet another needless rebuild.
    pub epoch: u64,
}

/// Process-wide monotonic source for [`PeerConnection::epoch`]. A plain
/// counter: uniqueness across a process lifetime is all the staleness
/// check needs, and wrap-around at u64 is not reachable in practice.
static SESSION_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl PeerConnection {
    pub(super) fn new(
        device_id: String,
        session: Option<Arc<PeerSession>>,
        resource_scope: PeerConnectionResourceScope,
    ) -> Self {
        Self {
            device_id,
            state: RwLock::new(PeerStateData::default()),
            session: Mutex::new(session),
            resource_scope,
            epoch: SESSION_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    pub(super) fn observe_remote_candidate(
        &self,
        candidate: LocalIceCandidate,
    ) -> PendingRemoteCandidate {
        PendingRemoteCandidate::observe(candidate, &self.resource_scope)
    }

    /// Return a clonable diagnostic view without copying mutable ownership.
    pub fn snapshot(&self) -> PeerStateSnapshot {
        self.state.read().snapshot()
    }

    pub(super) fn queue_remote_candidate(
        &self,
        state: &mut PeerStateData,
        candidate: LocalIceCandidate,
    ) {
        state
            .pending_remote_candidates
            .push(candidate, &self.resource_scope);
    }

    /// End observations for candidates that still belong to this peer's
    /// compatibility queue. This is called when the peer is removed or
    /// replaced, even if another `Arc` keeps the retired peer object alive.
    pub(super) fn discard_pending_remote_candidates(&self) {
        let pending = self.state.write().take_pending_remote_candidates();
        drop(pending);
    }

    #[cfg(test)]
    fn resource_report(&self) -> crate::resource::ResourceReport {
        self.resource_scope.report()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        ProcessResourceRoot, ResourceFamilyReport, PRE_AUTH_RESOURCE_FAMILY_COUNT,
    };
    use std::task::{Context, Poll, Waker};

    fn candidate_report(
        reports: &[ResourceFamilyReport<PreAuthResourceFamily>; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    ) -> ResourceFamilyReport<PreAuthResourceFamily> {
        *reports
            .iter()
            .find(|report| report.family == PreAuthResourceFamily::CandidateObject)
            .expect("candidate family is present")
    }

    fn observed_candidate() -> LocalIceCandidate {
        let candidate_fixture = "candidate:foundation 1 udp host";
        let mut candidate =
            String::with_capacity(candidate_fixture.len() + "candidate-slack".len());
        candidate.push_str(candidate_fixture);

        let mid_fixture = "data";
        let mut sdp_mid = String::with_capacity(mid_fixture.len() + "mid-slack".len());
        sdp_mid.push_str(mid_fixture);

        let username_fixture = "remote-fragment";
        let mut username_fragment =
            String::with_capacity(username_fixture.len() + "fragment-slack".len());
        username_fragment.push_str(username_fixture);

        LocalIceCandidate {
            candidate,
            sdp_mid: Some(sdp_mid),
            sdp_mline_index: None,
            username_fragment: Some(username_fragment),
        }
    }

    fn observed_peer() -> PeerConnection {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let context = mesh.network_instance_scope();
        PeerConnection::new(
            "candidate-test-peer".to_string(),
            None,
            context.peer_connection_scope(),
        )
    }

    #[test]
    fn v4_arc02_candidate_queue_observes_items_strings_and_container_separately() {
        let peer = observed_peer();
        let candidate = observed_candidate();
        let candidate_use = candidate_resource_measurement(&candidate).observed();

        let container_use = {
            let mut state = peer.state.write();
            peer.queue_remote_candidate(&mut state, candidate);
            queue_container_resource_measurement(&state.pending_remote_candidates.entries)
                .observed()
        };

        let active = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(active.active.items(), candidate_use.items());
        assert_eq!(active.active.logical_bytes(), candidate_use.logical_bytes());
        assert_eq!(
            active.active.retained_bytes(),
            candidate_use.retained_bytes() + container_use.retained_bytes()
        );
        assert_eq!(active.active.tasks(), ResourceUse::ZERO.tasks());
        assert_eq!(active.active_lease_count, 2);

        let mut drain = peer.state.write().take_pending_remote_candidates();
        assert_eq!(
            drain.len(),
            usize::try_from(candidate_use.items()).expect("fixture item count fits")
        );
        let pending = drain.next().expect("queued candidate moves into drain");
        assert!(drain.is_empty());

        let draining = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(draining.active, active.active);
        drop(pending);

        let container_only = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(container_only.active.items(), ResourceUse::ZERO.items());
        assert_eq!(
            container_only.active.logical_bytes(),
            ResourceUse::ZERO.logical_bytes()
        );
        assert_eq!(
            container_only.active.retained_bytes(),
            container_use.retained_bytes()
        );
        assert_eq!(container_only.active_lease_count, 1);

        drop(drain);
        let completed = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.active_lease_count, 0);
        assert_eq!(completed.completed_lease_count, 2);
    }

    #[test]
    fn v4_arc02_dropping_peer_releases_queued_candidate_observations() {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let context = mesh.network_instance_scope();
        let peer = PeerConnection::new(
            "replacement-session-peer".to_string(),
            None,
            context.peer_connection_scope(),
        );
        {
            let mut state = peer.state.write();
            peer.queue_remote_candidate(&mut state, observed_candidate());
        }
        assert_ne!(
            candidate_report(&context.report().pre_authentication).active,
            ResourceUse::ZERO
        );

        drop(peer);

        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.active_lease_count, 0);
        assert_eq!(completed.completed_lease_count, 2);
    }

    #[test]
    fn v4_arc02_cancelling_candidate_application_releases_its_observation() {
        let peer = observed_peer();
        let pending = peer.observe_remote_candidate(observed_candidate());
        let mut application = Box::pin(apply_pending_remote_candidate(pending, |_| {
            std::future::pending::<Result<(), ()>>()
        }));
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        assert_eq!(application.as_mut().poll(&mut context), Poll::Pending);
        let active = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(active.active.items(), 1);
        assert_eq!(active.active_lease_count, 1);

        drop(application);
        let completed = candidate_report(&peer.resource_report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.active_lease_count, 0);
        assert_eq!(completed.completed_lease_count, 1);
    }

    #[test]
    fn v4_arc02_candidate_application_releases_on_success_and_failure() {
        for expected in [Ok("success"), Err("failure")] {
            let peer = observed_peer();
            let pending = peer.observe_remote_candidate(observed_candidate());
            let mut application = Box::pin(apply_pending_remote_candidate(pending, move |_| {
                std::future::ready(expected)
            }));
            let waker = Waker::noop();
            let mut context = Context::from_waker(waker);

            assert_eq!(
                application.as_mut().poll(&mut context),
                Poll::Ready(expected)
            );
            let completed = candidate_report(&peer.resource_report().pre_authentication);
            assert_eq!(completed.active, ResourceUse::ZERO);
            assert_eq!(completed.active_lease_count, 0);
            assert_eq!(completed.completed_lease_count, 1);
        }
    }

    #[test]
    fn v4_arc02_unsupported_candidate_measurement_saturates_without_panicking() {
        assert_eq!(measured_usize(None), (u64::MAX, true));
    }

    #[test]
    #[ignore = "manual candidate-observer metadata measurement"]
    fn v4_arc02_candidate_observer_metadata_measurement() {
        println!(
            "arc02_candidate_metadata_bytes local_candidate={} observation_lease={} pending_candidate={} queue={} drain={} vec_header={}",
            size_of::<LocalIceCandidate>(),
            size_of::<CandidateObservationLease>(),
            size_of::<PendingRemoteCandidate>(),
            size_of::<PendingRemoteCandidateQueue>(),
            size_of::<PendingRemoteCandidateDrain>(),
            size_of::<Vec<PendingRemoteCandidate>>()
        );
    }
}
