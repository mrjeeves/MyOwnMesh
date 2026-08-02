//! Per-peer connection state held by the engine.
//!
//! Each entry in the engine's `peers` map is a [`PeerConnection`]:
//! the shared [`PeerStateData`] (status, tier, watermarks,
//! capabilities) plus the optional WebRTC connector worker.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::protocol::CapabilityAdvert;
use crate::transport::{PeerDiag, SelectedCandidatePair, WebRtcConnectorWorker};

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
    /// True after the exact current data channel accepts our `Approve` bytes
    /// for transmission. This does not prove remote receipt.
    pub local_approve_sent: bool,
    /// True only after this exact peer sends us an inbound `Approve`.
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
            admission_rejected: 0,
            diag: PeerDiag::default(),
        }
    }
}

pub struct PeerConnection {
    pub device_id: String,
    pub state: RwLock<PeerStateData>,
    pub(super) session: Mutex<Option<Arc<WebRtcConnectorWorker>>>,
    endpoint_auth: Mutex<Option<Arc<crate::endpoint_auth::EndpointAuthTask>>>,
    realtime_flow: Mutex<Option<Arc<crate::connector::ConnectorRealtimeFlowCapability>>>,
    registry_retired: AtomicBool,
    /// Diagnostic-only rebuild ordinal. It is never accepted as callback,
    /// attempt, resource, or application authority.
    pub epoch: u64,
}

/// Process-wide diagnostic sequence for [`PeerConnection::epoch`].
static DIAGNOSTIC_EPOCH: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl PeerConnection {
    pub(super) fn new(device_id: String, session: Option<Arc<WebRtcConnectorWorker>>) -> Self {
        Self {
            device_id,
            state: RwLock::new(PeerStateData::default()),
            session: Mutex::new(session),
            endpoint_auth: Mutex::new(None),
            realtime_flow: Mutex::new(None),
            registry_retired: AtomicBool::new(false),
            epoch: DIAGNOSTIC_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }

    /// Return a clonable diagnostic view without copying mutable ownership.
    pub fn snapshot(&self) -> PeerStateSnapshot {
        self.state.read().snapshot()
    }

    /// Retire the exact connector worker owned by this registry entry.
    /// External `Arc` holders cannot keep callbacks or queued candidates live.
    pub(super) fn retire_connector(&self) {
        self.registry_retired.store(true, Ordering::Release);
        drop(self.realtime_flow.lock().take());
        let worker = self.session.lock().clone();
        if let Some(worker) = worker {
            worker.retire();
        }
    }

    /// Fence the exact connector, await its single native cleanup owner, then
    /// release Endpoint Auth Task's connected-channel claim.
    pub(super) async fn retire_and_close(&self) -> crate::Result<()> {
        self.retire_connector();
        let worker = self.session.lock().clone();
        let result = match worker {
            Some(worker) => worker.retire_and_close().await,
            None => Ok(()),
        };
        drop(self.endpoint_auth.lock().take());
        result
    }

    pub(super) fn registry_retired(&self) -> bool {
        self.registry_retired.load(Ordering::Acquire)
    }

    pub(super) fn install_endpoint_auth(
        &self,
        task: Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> bool {
        let exact_connector = self
            .session
            .lock()
            .as_ref()
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
        self.endpoint_auth
            .lock()
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, task))
    }

    /// Temporary Arc 03 adapter. Endpoint Auth owns connected-channel
    /// provenance, while the existing authenticated and mutually-approved
    /// state machine remains the admission fact until Arc 04 implements the
    /// channel-bound transcript capability.
    pub(super) fn install_legacy_realtime_flow(&self) -> bool {
        if self.registry_retired() || !self.state.read().is_admitted() {
            return false;
        }
        let worker = self.session.lock().clone();
        let task = self.endpoint_auth.lock().clone();
        let Some((worker, task)) = worker.zip(task) else {
            return false;
        };
        let Some(capability) = worker.admit_legacy_realtime_flow(&task) else {
            return false;
        };
        let mut current = self.realtime_flow.lock();
        if current.is_some() {
            return false;
        }
        *current = Some(capability);
        true
    }

    pub(super) fn realtime_flow_ports(
        &self,
    ) -> Option<(
        Arc<WebRtcConnectorWorker>,
        Arc<crate::connector::ConnectorRealtimeFlowCapability>,
    )> {
        if self.registry_retired() || !self.state.read().is_admitted() {
            return None;
        }
        let worker = self.session.lock().clone()?;
        let capability = self.realtime_flow.lock().clone()?;
        worker
            .owns_realtime_flow(&capability)
            .then_some((worker, capability))
    }
}
