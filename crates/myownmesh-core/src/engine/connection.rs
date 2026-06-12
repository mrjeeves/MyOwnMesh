//! Per-peer connection state held by the engine.
//!
//! Each entry in the engine's `peers` map is a [`PeerConnection`]:
//! the shared [`PeerStateData`] (status, tier, watermarks,
//! capabilities) plus the optional [`PeerSession`] handle to the
//! WebRTC layer.

use std::sync::Arc;
use std::time::Instant;

use parking_lot::{Mutex, RwLock};
use serde::{Deserialize, Serialize};

use crate::protocol::CapabilityAdvert;
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
    /// Out of the topology's connect set: no transport at all.
    /// Presence is tracked via signaling announces; the engine
    /// re-dials when the connect set rebalances the peer back in.
    /// Unlike `Offline`, parked is a deliberate steady state, not a
    /// fault — no reconnection tier ever fires for it.
    Parked,
    /// Connection dropped; reconnect attempts in progress.
    Reconnecting,
    /// Connection torn down. The engine retains the entry only
    /// briefly so an immediate reconnect can short-circuit
    /// approval.
    Offline,
    /// Fatal error — peer is excluded until user intervention.
    Error,
}

#[derive(Debug, Clone)]
pub struct PeerStateData {
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub authenticated: bool,
    pub local_approve_sent: bool,
    pub remote_approve_seen: bool,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    /// Feature ids the peer advertised in its `hello`. Empty until a
    /// handshake has completed (or for legacy peers that predate the
    /// features list). The park sweep consults this to exempt peers
    /// that don't speak `topology_park_v1`.
    pub remote_features: Vec<String>,
    /// When the connect-set selector first found this (connected)
    /// peer outside the connect set. Parking only fires after the
    /// peer has been continuously outside for `PARK_LINGER_MS` —
    /// hysteresis that absorbs transient peer-view divergence while
    /// announces propagate. Cleared whenever the peer is back in.
    pub park_pending_since: Option<Instant>,
    /// Last signaling announce observed while parked. Parked entries
    /// have no transport to detect death on, so presence decays by
    /// announce-recency: entries silent past
    /// `PARKED_PRESENCE_TTL_MS` are removed by the park sweep.
    pub last_announce_at: Option<Instant>,
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
    pub last_ping_t: Option<i64>,
    pub rtt_ms: Option<u32>,
    pub ice_disconnected_since: Option<Instant>,
    /// When ICE entered `Checking` for the current attempt. Set on the
    /// transition into Checking, cleared the moment it reaches
    /// Connected (or goes Disconnected/Failed/Closed). The
    /// checking-timeout watchdog reads this to rebuild a peer that's
    /// been stuck mid-negotiation too long instead of waiting out
    /// webrtc-rs's ~30 s internal timer.
    pub ice_checking_since: Option<Instant>,
    /// How many times the checking-timeout has *extended* this attempt
    /// instead of tearing it down, because the agent had succeeded pairs
    /// (connectivity exists) but hadn't nominated yet. Bounds the grace so
    /// a pair that succeeds-but-never-nominates can't stall a peer
    /// forever; reset whenever ICE leaves Checking. See
    /// `ice_watchdog::on_checking_timeout`.
    pub checking_grace_used: u8,
    pub handshake_started_at: Option<Instant>,
    pub hello_attempt: u32,
    pub rehandshake_attempt: u32,
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
    pub pending_remote_candidates: Vec<LocalIceCandidate>,
    pub diag: PeerDiag,
}

impl Default for PeerStateData {
    fn default() -> Self {
        Self {
            status: PeerStatus::Sighted,
            tier: ConnectionTier::Steady,
            authenticated: false,
            local_approve_sent: false,
            remote_approve_seen: false,
            local_shelved: false,
            remote_shelved: false,
            label: String::new(),
            capabilities: None,
            remote_features: Vec::new(),
            park_pending_since: None,
            last_announce_at: None,
            nonce_sent: None,
            nonce_received: None,
            verification_code_sent: None,
            verification_code_received: None,
            last_recv_at: None,
            last_ping_sent_at: None,
            last_offer_sent_at: None,
            last_ping_t: None,
            rtt_ms: None,
            ice_disconnected_since: None,
            ice_checking_since: None,
            checking_grace_used: 0,
            handshake_started_at: None,
            hello_attempt: 0,
            rehandshake_attempt: 0,
            ice_failed_count: 0,
            no_turn_diag_emitted: false,
            selected_pair: None,
            remote_description_set: false,
            pending_remote_candidates: Vec::new(),
            diag: PeerDiag::default(),
        }
    }
}

pub struct PeerConnection {
    pub device_id: String,
    pub state: RwLock<PeerStateData>,
    pub session: Mutex<Option<Arc<PeerSession>>>,
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
    pub fn new(device_id: String, session: Option<Arc<PeerSession>>) -> Self {
        Self {
            device_id,
            state: RwLock::new(PeerStateData::default()),
            session: Mutex::new(session),
            epoch: SESSION_EPOCH.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
}
