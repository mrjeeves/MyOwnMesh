//! WebRTC peer connection wrapper. Bridges webrtc-rs's callback-
//! driven API to a single mpsc the engine drains in its main loop.
//!
//! Lifecycle per peer:
//!
//! 1. Engine calls [`Transport::open_peer`] with [`Role::Offerer`]
//!    or [`Role::Answerer`]. A fresh [`PeerSession`] is returned.
//! 2. Offerer: [`PeerSession::create_offer`], then ship the SDP via
//!    signaling. Answerer: receive remote SDP, call
//!    [`PeerSession::set_remote_description`], then `create_answer`,
//!    then ship the SDP back.
//! 3. ICE candidates flow both ways via signaling; engine pushes
//!    inbound candidates into [`PeerSession::add_ice_candidate`].
//! 4. Once the data channel opens, the engine can [`PeerSession::send`]
//!    and observe [`TransportEvent::Message`] frames.
//! 5. Drop the [`PeerSession`] to tear down, or call
//!    [`PeerSession::close`] for explicit shutdown.

use std::sync::Arc;

use bytes::Bytes;
use serde::{Deserialize, Serialize};
use tokio::sync::{mpsc, Mutex};
use tracing::{debug, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;

use crate::error::{Error, Result};

use super::ice::build_rtc_configuration;

/// Stable label for the application data channel. Receivers can
/// filter the incoming [`on_data_channel`] event on this so other
/// channels (e.g. browser-initiated debug) don't get routed into
/// the mesh frame path.
pub const APP_DATA_CHANNEL_LABEL: &str = "myownmesh";

/// Who initiated this peer pairing. Drives whether we create the
/// data channel pre-offer (offerer) or wait for the peer to open
/// it (answerer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Offerer,
    Answerer,
}

/// Transport-layer event surfaced to the engine. The engine pumps
/// these on the network's main loop; nothing here lives across
/// tokio runtime ticks.
#[derive(Debug)]
pub enum TransportEvent {
    /// A locally-gathered ICE candidate the engine should ship to
    /// the peer over signaling. `None` after gathering completes.
    LocalIceCandidate(Option<LocalIceCandidate>),
    /// ICE connection state changed.
    IceConnectionStateChanged(RTCIceConnectionState),
    /// PeerConnection state changed (covers the full DTLS+ICE
    /// lifecycle, including `Failed` and `Closed`).
    PeerConnectionStateChanged(RTCPeerConnectionState),
    /// Data channel opened — peer is reachable for app traffic.
    DataChannelOpen,
    /// Inbound application frame.
    Message(Bytes),
    /// Data channel closed (peer initiated or local error).
    DataChannelClosed,
}

/// One locally-gathered ICE candidate, in the form the signaling
/// layer needs (matches the webrtc-rs `RTCIceCandidateInit` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
}

impl LocalIceCandidate {
    fn into_init(self) -> RTCIceCandidateInit {
        RTCIceCandidateInit {
            candidate: self.candidate,
            sdp_mid: self.sdp_mid,
            sdp_mline_index: self.sdp_mline_index,
            username_fragment: self.username_fragment,
        }
    }
}

/// Engine-owned WebRTC factory. Construct once per [`crate::Mesh`]
/// instance; cheap to clone.
#[derive(Clone)]
pub struct Transport {
    api: Arc<webrtc::api::API>,
}

impl Transport {
    /// Build a fresh transport with the default media engine and
    /// interceptors. The webrtc-rs defaults cover everything we
    /// need for data-channel-only operation.
    pub fn new() -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| Error::Transport(format!("register codecs: {e}")))?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| Error::Transport(format!("register interceptors: {e}")))?;
        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .build();
        Ok(Self { api: Arc::new(api) })
    }

    /// Open a new [`PeerSession`] for the given peer with the
    /// supplied STUN/TURN configuration. The session immediately
    /// installs all webrtc callbacks; events flow out the returned
    /// receiver until the session is dropped.
    pub async fn open_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
    ) -> Result<(PeerSession, mpsc::UnboundedReceiver<TransportEvent>)> {
        let config = build_rtc_configuration(stun, turn);
        self.open_peer_with_config(role, config).await
    }

    /// Lower-level entry point that takes an explicit
    /// `RTCConfiguration`. Tests can use this to short-circuit
    /// the user-config path.
    pub async fn open_peer_with_config(
        &self,
        role: Role,
        config: RTCConfiguration,
    ) -> Result<(PeerSession, mpsc::UnboundedReceiver<TransportEvent>)> {
        let pc = self
            .api
            .new_peer_connection(config)
            .await
            .map_err(|e| Error::Transport(format!("new_peer_connection: {e}")))?;
        let pc = Arc::new(pc);

        let (events_tx, events_rx) = mpsc::unbounded_channel();
        let data_channel = Arc::new(Mutex::new(None::<Arc<RTCDataChannel>>));

        register_callbacks(&pc, &events_tx, &data_channel);

        // Offerer creates the data channel synchronously so the
        // resulting SDP includes it. Answerer waits for the
        // `on_data_channel` callback that fires when the peer's
        // offer is applied.
        if role == Role::Offerer {
            let dc = pc
                .create_data_channel(
                    APP_DATA_CHANNEL_LABEL,
                    Some(RTCDataChannelInit {
                        ordered: Some(true),
                        ..Default::default()
                    }),
                )
                .await
                .map_err(|e| Error::Transport(format!("create_data_channel: {e}")))?;
            install_data_channel_handlers(dc.clone(), events_tx.clone());
            *data_channel.lock().await = Some(dc);
        }

        Ok((
            PeerSession {
                pc,
                data_channel,
                events_tx,
                role,
            },
            events_rx,
        ))
    }
}

fn register_callbacks(
    pc: &Arc<RTCPeerConnection>,
    events_tx: &mpsc::UnboundedSender<TransportEvent>,
    data_channel: &Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
) {
    // Local ICE candidate gathered — ship via signaling.
    {
        let tx = events_tx.clone();
        pc.on_ice_candidate(Box::new(move |cand| {
            let tx = tx.clone();
            Box::pin(async move {
                let msg = match cand {
                    Some(c) => match c.to_json() {
                        Ok(init) => Some(LocalIceCandidate {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_mline_index: init.sdp_mline_index,
                            username_fragment: init.username_fragment,
                        }),
                        Err(e) => {
                            warn!("ice_candidate to_json: {e}");
                            return;
                        }
                    },
                    None => None,
                };
                let _ = tx.send(TransportEvent::LocalIceCandidate(msg));
            })
        }));
    }

    // ICE connection state changed.
    {
        let tx = events_tx.clone();
        pc.on_ice_connection_state_change(Box::new(move |state| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(TransportEvent::IceConnectionStateChanged(state));
            })
        }));
    }

    // PeerConnection state changed.
    {
        let tx = events_tx.clone();
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(TransportEvent::PeerConnectionStateChanged(state));
            })
        }));
    }

    // Answerer side: data channel arrives via callback.
    {
        let tx = events_tx.clone();
        let dc_slot = data_channel.clone();
        pc.on_data_channel(Box::new(move |dc| {
            let tx = tx.clone();
            let dc_slot = dc_slot.clone();
            Box::pin(async move {
                if dc.label() != APP_DATA_CHANNEL_LABEL {
                    trace!(label = dc.label(), "ignoring non-app data channel");
                    return;
                }
                install_data_channel_handlers(dc.clone(), tx);
                *dc_slot.lock().await = Some(dc);
            })
        }));
    }
}

fn install_data_channel_handlers(
    dc: Arc<RTCDataChannel>,
    tx: mpsc::UnboundedSender<TransportEvent>,
) {
    {
        let tx = tx.clone();
        dc.on_open(Box::new(move || {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(TransportEvent::DataChannelOpen);
            })
        }));
    }
    {
        let tx = tx.clone();
        dc.on_close(Box::new(move || {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(TransportEvent::DataChannelClosed);
            })
        }));
    }
    {
        let tx = tx.clone();
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let tx = tx.clone();
            Box::pin(async move {
                let _ = tx.send(TransportEvent::Message(msg.data));
            })
        }));
    }
    {
        let tx = tx.clone();
        dc.on_error(Box::new(move |err| {
            let tx = tx.clone();
            Box::pin(async move {
                warn!("data channel error: {err}");
                let _ = tx.send(TransportEvent::DataChannelClosed);
            })
        }));
    }
}

/// Render an ICE candidate as a compact `kind net addr:port` string
/// for the connectivity-check snapshot — e.g. `host udp4
/// 192.168.1.50:54321`. Keeps the log line readable while still
/// showing the exact address so the user can spot a wrong subnet, a
/// link-local IPv6 that won't route, or a srflx that resolved to an
/// unexpected public IP.
fn fmt_candidate(
    t: webrtc::ice::candidate::CandidateType,
    net: webrtc::ice::network_type::NetworkType,
    ip: &str,
    port: u16,
) -> String {
    use webrtc::ice::candidate::CandidateType;
    let kind = match t {
        CandidateType::Host => "host",
        CandidateType::ServerReflexive => "srflx",
        CandidateType::PeerReflexive => "prflx",
        CandidateType::Relay => "relay",
        CandidateType::Unspecified => "?",
    };
    format!("{kind} {net} {ip}:{port}")
}

/// Lower-case wire name for a candidate-pair check state, matching the
/// strings [`super::diag::IceCheckSnapshot`] compares against.
fn pair_state_str(s: webrtc::ice::candidate::CandidatePairState) -> String {
    use webrtc::ice::candidate::CandidatePairState as S;
    match s {
        S::Waiting => "waiting",
        S::InProgress => "in-progress",
        S::Failed => "failed",
        S::Succeeded => "succeeded",
        S::Unspecified => "unspecified",
    }
    .to_string()
}

/// One peer's WebRTC session — peer connection, application data
/// channel, and transport-level event sink.
pub struct PeerSession {
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    events_tx: mpsc::UnboundedSender<TransportEvent>,
    role: Role,
}

impl PeerSession {
    pub fn role(&self) -> Role {
        self.role
    }

    /// True once the data channel is established on this side
    /// (open and `on_open` fired).
    pub async fn has_data_channel(&self) -> bool {
        self.data_channel.lock().await.is_some()
    }

    /// Build an offer SDP. Offerer-only (answerer never calls this).
    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        let offer = self
            .pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_offer: {e}")))?;
        self.pc
            .set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (offer): {e}")))?;
        Ok(offer)
    }

    /// Apply the remote SDP. Both sides call this — offerer with
    /// the answer they got back, answerer with the offer they
    /// received first.
    pub async fn set_remote_description(&self, desc: RTCSessionDescription) -> Result<()> {
        self.pc
            .set_remote_description(desc)
            .await
            .map_err(|e| Error::Transport(format!("set_remote_description: {e}")))
    }

    /// Build an answer SDP. Answerer-only; call after
    /// [`Self::set_remote_description`].
    pub async fn create_answer(&self) -> Result<RTCSessionDescription> {
        let answer = self
            .pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_answer: {e}")))?;
        self.pc
            .set_local_description(answer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (answer): {e}")))?;
        Ok(answer)
    }

    /// Add an ICE candidate the peer sent us. The peer's nominal
    /// `null` (gathering complete) is also acceptable.
    pub async fn add_ice_candidate(&self, cand: LocalIceCandidate) -> Result<()> {
        self.pc
            .add_ice_candidate(cand.into_init())
            .await
            .map_err(|e| Error::Transport(format!("add_ice_candidate: {e}")))
    }

    /// Send bytes on the data channel. Returns the number of bytes
    /// queued for transmission (matches webrtc-rs's contract).
    pub async fn send(&self, payload: Bytes) -> Result<usize> {
        let dc = self.data_channel.lock().await;
        let dc = dc
            .as_ref()
            .ok_or_else(|| Error::Transport("data channel not open".into()))?;
        dc.send(&payload)
            .await
            .map_err(|e| Error::Transport(format!("data channel send: {e}")))
    }

    /// Force ICE restart. Used by the engine's Tier 2.5 / Tier 3
    /// recovery path.
    pub async fn restart_ice(&self) -> Result<()> {
        self.pc
            .restart_ice()
            .await
            .map_err(|e| Error::Transport(format!("restart_ice: {e}")))
    }

    /// Read the peer connection's current ICE state. Useful for
    /// the ICE watchdog without subscribing to every transition.
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.pc.ice_connection_state()
    }

    /// Read the overall connection state (DTLS + ICE composite).
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.pc.connection_state()
    }

    /// Ask the underlying ICE agent which candidate pair it actually
    /// selected for sending packets. This is the authoritative
    /// answer to "is this a LAN link or going through STUN/TURN" —
    /// gathered candidate counts only tell us what was tried, not
    /// what's in use. Returns `None` until ICE has settled
    /// (Connected / Completed) and the agent has nominated a pair.
    ///
    /// Implementation note: webrtc-rs's `get_selected_candidate_pair`
    /// returns a struct with private fields and no accessors (as of
    /// 0.13), so we go through the stats API instead — the candidate-
    /// pair stats expose `nominated` plus ids that resolve to local /
    /// remote candidate stats with public `candidate_type` fields.
    pub async fn selected_candidate_pair(&self) -> Option<super::diag::SelectedCandidatePair> {
        use webrtc::ice::candidate::{CandidatePairState, CandidateType};
        use webrtc::stats::StatsReportType;
        let report = self.pc.get_stats().await;
        // Find the nominated pair. There can be several pair entries
        // (one per checklist combination); only the nominated one is
        // currently carrying packets.
        //
        // Fallback: webrtc-rs doesn't always flip `nominated=true` on
        // the controlling (Offerer) side — the field can stay false
        // even after ICE is solidly Connected and bytes are flowing.
        // When no pair is marked nominated, fall back to the
        // Succeeded pair with the most bytes_received (the one
        // actually carrying traffic); if multiple have zero bytes,
        // any Succeeded pair classifies the same way for our
        // purposes (LAN / STUN / TURN). Without this fallback the
        // Offerer side stays unclassified on a healthy LAN pair —
        // packets flow, GUI never paints the link type.
        let (local_id, remote_id) = {
            let nominated = report.reports.values().find_map(|r| match r {
                StatsReportType::CandidatePair(p) if p.nominated => {
                    Some((p.local_candidate_id.clone(), p.remote_candidate_id.clone()))
                }
                _ => None,
            });
            match nominated {
                Some(ids) => ids,
                None => report
                    .reports
                    .values()
                    .filter_map(|r| match r {
                        StatsReportType::CandidatePair(p)
                            if p.state == CandidatePairState::Succeeded =>
                        {
                            Some(p)
                        }
                        _ => None,
                    })
                    .max_by_key(|p| p.bytes_received)
                    .map(|p| (p.local_candidate_id.clone(), p.remote_candidate_id.clone()))?,
            }
        };
        fn map(t: CandidateType) -> super::diag::IceCandidateKind {
            match t {
                CandidateType::Host => super::diag::IceCandidateKind::Host,
                CandidateType::ServerReflexive => super::diag::IceCandidateKind::ServerReflexive,
                CandidateType::PeerReflexive => super::diag::IceCandidateKind::PeerReflexive,
                CandidateType::Relay => super::diag::IceCandidateKind::Relay,
                CandidateType::Unspecified => super::diag::IceCandidateKind::Unknown,
            }
        }
        let local = report.reports.values().find_map(|r| match r {
            StatsReportType::LocalCandidate(c) if c.id == local_id => Some(map(c.candidate_type)),
            _ => None,
        })?;
        let remote = report.reports.values().find_map(|r| match r {
            StatsReportType::RemoteCandidate(c) if c.id == remote_id => Some(map(c.candidate_type)),
            _ => None,
        })?;
        Some(super::diag::SelectedCandidatePair { local, remote })
    }

    /// Capture a full connectivity-check snapshot from the ICE agent's
    /// stats. Where [`Self::selected_candidate_pair`] only reports the
    /// *winning* pair once ICE is Connected, this returns **every**
    /// candidate pair and its live STUN check counters at any point in
    /// the lifecycle — the data you need to answer "why is this peer
    /// stuck in Checking / why did it go Failed". The engine logs it on
    /// ICE failure and periodically while a peer is still checking.
    pub async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        use std::collections::HashMap;
        use webrtc::stats::StatsReportType;

        let report = self.pc.get_stats().await;

        // First pass: build candidate-id → "kind net addr:port" so the
        // pairs below can render real addresses instead of opaque ids,
        // and collect the flat local/remote candidate lists.
        let mut by_id: HashMap<String, String> = HashMap::new();
        let mut local_candidates = Vec::new();
        let mut remote_candidates = Vec::new();
        for r in report.reports.values() {
            match r {
                StatsReportType::LocalCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    local_candidates.push(s);
                }
                StatsReportType::RemoteCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    remote_candidates.push(s);
                }
                _ => {}
            }
        }

        // Second pass: the candidate pairs and their check counters.
        let mut pairs = Vec::new();
        for r in report.reports.values() {
            if let StatsReportType::CandidatePair(p) = r {
                let resolve = |id: &str| by_id.get(id).cloned().unwrap_or_else(|| id.to_string());
                pairs.push(super::diag::IcePairSnapshot {
                    local: resolve(&p.local_candidate_id),
                    remote: resolve(&p.remote_candidate_id),
                    state: pair_state_str(p.state),
                    nominated: p.nominated,
                    requests_sent: p.requests_sent,
                    responses_received: p.responses_received,
                    requests_received: p.requests_received,
                    responses_sent: p.responses_sent,
                    bytes_sent: p.bytes_sent,
                    bytes_received: p.bytes_received,
                });
            }
        }

        // Stable ordering so successive snapshots diff cleanly in the
        // log: succeeded pairs first, then by descending check
        // activity (the pairs actually doing something float up).
        pairs.sort_by(|a, b| {
            (b.state == "succeeded")
                .cmp(&(a.state == "succeeded"))
                .then((b.requests_sent + b.responses_received).cmp(&(a.requests_sent + a.responses_received)))
        });
        local_candidates.sort();
        remote_candidates.sort();
        super::diag::IceCheckSnapshot {
            local_candidates,
            remote_candidates,
            pairs,
        }
    }

    /// Close the connection. Idempotent — subsequent close calls
    /// no-op, and dropping the session calls close implicitly via
    /// `RTCPeerConnection::drop`.
    pub async fn close(&self) -> Result<()> {
        debug!("closing peer connection");
        self.pc
            .close()
            .await
            .map_err(|e| Error::Transport(format!("close: {e}")))?;
        // Signal upstream so any pending engine select! finishes.
        let _ = self.events_tx.send(TransportEvent::DataChannelClosed);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn loopback_handshake_opens_data_channel() {
        // Bring up two peer sessions on the same in-process
        // Transport. No STUN / TURN — they exchange host
        // candidates over the same loopback interface. Verifies
        // the entire offer/answer/candidate cycle plus the
        // data-channel handshake without external dependencies.
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();

        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone())
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg)
            .await
            .expect("answerer");

        let offer = offerer.create_offer().await.expect("create_offer");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        offerer
            .set_remote_description(answer)
            .await
            .expect("offerer.set_remote");

        // Pump ICE candidates between the two sides for up to 10s.
        // Either order is fine — we just need both to see the
        // DataChannelOpen event before the deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut off_open = false;
        let mut ans_open = false;

        while (!off_open || !ans_open) && tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        answerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to answerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { off_open = true; }
                }
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        offerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to offerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { ans_open = true; }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        assert!(off_open, "offerer never saw DataChannelOpen");
        assert!(ans_open, "answerer never saw DataChannelOpen");

        offerer
            .send(Bytes::from_static(b"hello"))
            .await
            .expect("send");
        // Drain answerer events for the message.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = false;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::Message(b) = ev {
                        assert_eq!(b.as_ref(), b"hello");
                        got = true;
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
        assert!(got, "answerer never received the app frame");

        offerer.close().await.expect("close offerer");
        answerer.close().await.expect("close answerer");
    }
}
