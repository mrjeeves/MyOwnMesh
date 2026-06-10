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
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_H264};
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

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
    /// One assembled access unit from the peer's video track lane.
    VideoSample(VideoSample),
}

/// One H.264 access unit off the peer's video track — Annex-B bytes
/// ready for a decoder. `rtp_timestamp` ticks at the 90 kHz video
/// clock; `key` marks an IDR (a safe decode entry point).
#[derive(Debug, Clone)]
pub struct VideoSample {
    pub rtp_timestamp: u32,
    pub key: bool,
    pub data: Bytes,
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

        // One H.264 video lane, provisioned on **every** connection at
        // setup — both roles add the local track before SDP runs, so the
        // one offer/answer negotiates a sendrecv video m-line once and
        // for all, and no renegotiation path needs to exist anywhere.
        // An idle lane costs nothing: no samples written, no RTP sent.
        let video_track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: MIME_TYPE_H264.to_owned(),
                ..Default::default()
            },
            "video".to_string(),
            "myownmesh".to_string(),
        ));
        let rtp_sender = pc
            .add_track(Arc::clone(&video_track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|e| Error::Transport(format!("add_track: {e}")))?;
        // Drain the sender's RTCP so its interceptors (NACK responder,
        // reports) actually run; the task ends with the connection.
        tokio::spawn(async move {
            let mut buf = vec![0u8; 1500];
            while rtp_sender.read(&mut buf).await.is_ok() {}
        });

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
                video_track,
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

    // The peer's video track lane went live — pump its RTP into
    // assembled access units until the track (i.e. the connection) ends.
    {
        let tx = events_tx.clone();
        pc.on_track(Box::new(move |track, _receiver, _transceiver| {
            let tx = tx.clone();
            Box::pin(async move {
                if track.kind() != RTPCodecType::Video {
                    trace!(kind = ?track.kind(), "ignoring non-video track");
                    return;
                }
                tokio::spawn(pump_video_track(track, tx));
            })
        }));
    }
}

/// Drain one remote video track: depacketize H.264 RTP into access
/// units and surface each as [`TransportEvent::VideoSample`]. Ends
/// when the track does (peer connection closed).
async fn pump_video_track(track: Arc<TrackRemote>, tx: mpsc::UnboundedSender<TransportEvent>) {
    let mut assembler = H264AuAssembler::default();
    loop {
        let pkt = match track.read_rtp().await {
            Ok((pkt, _)) => pkt,
            Err(_) => break, // track ended with its connection
        };
        match assembler.push(&pkt) {
            Ok(Some(sample)) => {
                if tx.send(TransportEvent::VideoSample(sample)).is_err() {
                    break;
                }
            }
            Ok(None) => {}
            // A malformed packet (or one straddling a loss the NACK
            // retransmit didn't cover) costs the current unit only —
            // the stream re-syncs on the next timestamp, and the
            // sender's periodic IDR bounds any visible damage.
            Err(e) => trace!("video depacketize: {e}"),
        }
    }
}

/// Reassembles H.264 access units from RTP, loss- and reorder-aware:
/// payloads collect per RTP timestamp keyed by *unwrapped sequence
/// number*, and a unit is emitted only when the chain from its first
/// packet to its marker packet is **contiguous** — so a packet lost
/// mid-unit can never splice the survivors into a corrupt unit that
/// reaches a decoder (the bug shape: at streaming bitrates a keyframe
/// spans hundreds of packets, and one hole per keyframe means a decode
/// error every time). A hole simply waits — the NACK interceptor's
/// retransmit fills it out of order and the unit still emits — and a
/// unit whose hole never fills is dropped whole when the next timestamp
/// arrives. Late retransmits of an abandoned unit can't clobber the
/// live one. Depacketization runs per-unit in sequence order, so FU-A
/// fragment state never straddles a loss.
#[derive(Default)]
struct H264AuAssembler {
    /// RTP timestamp of the unit being collected.
    timestamp: u32,
    /// Unwrapped seq → raw RTP payload, for the current timestamp only.
    parts: std::collections::BTreeMap<i64, Bytes>,
    /// Unwrapped seq of the current unit's marker packet, once seen.
    marker_seq: Option<i64>,
    /// Unwrapped seq of the last *emitted* unit's marker — the next unit
    /// must start at exactly +1, which is what makes the contiguity
    /// check exact. `None` after an abandoned unit (the anchor is lost);
    /// the next unit then re-anchors on a payload that *starts* an AU.
    prev_end: Option<i64>,
    /// Sequence unwrapper state: (last raw seq, its unwrapped value).
    last_seq: Option<(u16, i64)>,
}

/// More packets than any sane unit (a 40 Mbps keyframe is ~400): a unit
/// this size means the stream is wedged — drop it rather than balloon.
const MAX_AU_PARTS: usize = 2048;

impl H264AuAssembler {
    fn push(&mut self, pkt: &webrtc::rtp::packet::Packet) -> Result<Option<VideoSample>> {
        if pkt.payload.is_empty() {
            return Ok(None); // padding / probe
        }
        let seq = self.unwrap_seq(pkt.header.sequence_number);
        let ts = pkt.header.timestamp;
        if ts != self.timestamp {
            if self.parts.is_empty() || newer_rtp_ts(ts, self.timestamp) {
                // The next unit begins; an unfinished current one is
                // dropped whole (its hole is now hopeless) and the exact
                // start anchor is gone with it.
                if !self.parts.is_empty() {
                    self.prev_end = None;
                }
                self.parts.clear();
                self.marker_seq = None;
                self.timestamp = ts;
            } else {
                // A late retransmit of a unit we already abandoned —
                // never let it wipe the one being collected.
                return Ok(None);
            }
        }
        if self.parts.len() >= MAX_AU_PARTS {
            self.parts.clear();
            self.marker_seq = None;
            self.prev_end = None;
            return Err(Error::Transport("video unit overflowed reassembly".into()));
        }
        self.parts.insert(seq, pkt.payload.clone());
        if pkt.header.marker {
            self.marker_seq = Some(seq);
        }
        self.try_emit()
    }

    /// Emit the collected unit if its packet chain is complete.
    fn try_emit(&mut self) -> Result<Option<VideoSample>> {
        let Some(end) = self.marker_seq else {
            return Ok(None);
        };
        let start = match self.prev_end {
            Some(prev) => prev + 1,
            None => {
                // No anchor (stream start, or the previous unit was
                // abandoned): accept the lowest packet we hold only if it
                // plausibly *begins* a unit — a mid-unit join waits for
                // the next one instead of emitting a headless tail.
                let Some((&lo, first)) = self.parts.iter().next() else {
                    return Ok(None);
                };
                if !payload_starts_au(first) {
                    return Ok(None);
                }
                lo
            }
        };
        if end < start {
            return Ok(None); // a stale marker from before the anchor
        }
        let need = (end - start + 1) as usize;
        if self.parts.range(start..=end).count() < need {
            return Ok(None); // a hole — wait for the retransmit
        }
        // Complete: depacketize in sequence order with fresh FU state.
        use webrtc::rtp::packetizer::Depacketizer;
        let mut depacketizer = webrtc::rtp::codecs::h264::H264Packet::default();
        let mut data = Vec::new();
        let mut failed = None;
        for (_, payload) in self.parts.range(start..=end) {
            match depacketizer.depacketize(payload) {
                Ok(part) => data.extend_from_slice(&part),
                Err(e) => {
                    failed = Some(format!("h264 depacketize: {e}"));
                    break;
                }
            }
        }
        // Either way this unit is consumed and the next one anchors
        // right after it.
        self.prev_end = Some(end);
        self.parts.clear();
        self.marker_seq = None;
        if let Some(e) = failed {
            return Err(Error::Transport(e));
        }
        if data.is_empty() {
            return Ok(None);
        }
        let data = Bytes::from(data);
        Ok(Some(VideoSample {
            rtp_timestamp: self.timestamp,
            key: au_has_idr(&data),
            data,
        }))
    }

    /// Map a raw 16-bit RTP sequence number onto an unbounded line, so
    /// ordering survives wraparound. The anchor only advances forward;
    /// older arrivals (retransmits) resolve to their original position.
    fn unwrap_seq(&mut self, raw: u16) -> i64 {
        match self.last_seq {
            None => {
                let unwrapped = i64::from(raw);
                self.last_seq = Some((raw, unwrapped));
                unwrapped
            }
            Some((last_raw, last_unwrapped)) => {
                let delta = i64::from(raw.wrapping_sub(last_raw) as i16);
                let unwrapped = last_unwrapped + delta;
                if delta > 0 {
                    self.last_seq = Some((raw, unwrapped));
                }
                unwrapped
            }
        }
    }
}

/// RTP timestamp `a` is newer than `b` (mod 2³², shortest distance).
fn newer_rtp_ts(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < u32::MAX / 2
}

/// Whether an RTP payload can be the *first* packet of an access unit:
/// a single NAL (types 1–23), a STAP-A aggregate (24), or a fragment
/// with its start bit set (FU-A/FU-B, 28/29). Mid-unit fragments fail.
fn payload_starts_au(payload: &Bytes) -> bool {
    let Some(&b0) = payload.first() else {
        return false;
    };
    match b0 & 0x1F {
        1..=23 => true,
        24 => true,
        28 | 29 => payload.get(1).is_some_and(|b1| b1 & 0x80 != 0),
        _ => false,
    }
}

/// Whether an Annex-B access unit contains an IDR slice (NAL type 5)
/// — a safe decoder entry point. (SPS/PPS ride along with IDRs but
/// don't make a frame decodable by themselves.)
fn au_has_idr(data: &[u8]) -> bool {
    annexb_nal_types(data).any(|t| t == 5)
}

/// Iterate the NAL unit types of an Annex-B stream (both 3- and
/// 4-byte start codes).
fn annexb_nal_types(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i + 3 <= data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                if data[i + 2] == 1 {
                    if i + 3 < data.len() {
                        let t = data[i + 3] & 0x1F;
                        i += 4;
                        return Some(t);
                    }
                    i += 3;
                    continue;
                }
                if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                    if i + 4 < data.len() {
                        let t = data[i + 4] & 0x1F;
                        i += 5;
                        return Some(t);
                    }
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
        None
    })
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

/// True if `ip` is a private / local-scope address — RFC1918 v4
/// (`10/8`, `172.16/12`, `192.168/16`), v4 link-local (`169.254/16`),
/// v6 unique-local (`fc00::/7`), or v6 link-local (`fe80::/10`).
/// Carrier-grade NAT space (`100.64/10`) is deliberately excluded: it's
/// reachable only via the carrier, not a LAN. Used to classify a
/// connected ICE pair as a direct local link from its endpoint address
/// rather than trusting the ICE candidate type alone — a peer-reflexive
/// candidate on a `192.168.x.x` address is still the LAN.
fn is_private_lan_ip(ip: &str) -> bool {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            // fc00::/7 (unique-local) or fe80::/10 (link-local).
            (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
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
/// channel, the provisioned video track lane, and transport-level
/// event sink.
pub struct PeerSession {
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    video_track: Arc<TrackLocalStaticSample>,
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

    /// Write one encoded H.264 access unit (Annex-B) onto this peer's
    /// video lane. `duration` paces the RTP timestamp advance (1/fps).
    /// Before the lane's negotiation completes, webrtc-rs treats the
    /// write as a no-op (the track has no bound sender yet) — callers
    /// can simply start writing once the peer is up.
    pub async fn send_video(&self, data: Bytes, duration: std::time::Duration) -> Result<()> {
        self.video_track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("video write_sample: {e}")))
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
        // Classify from the candidate's actual address first, falling
        // back to the ICE type. A *working* pair whose endpoint is a
        // private/RFC1918 address is, by definition, a direct
        // local-network link: those ranges aren't routable across the
        // internet, so if packets are flowing the two devices share a
        // LAN. We report it as `Host` even when ICE labelled the
        // candidate `prflx` (peer-reflexive) — which happens routinely
        // when the remote's host candidate arrived a beat before its
        // SDP and was learned from a STUN binding rather than the
        // candidate list, the exact reason a genuinely-local peer was
        // mis-painted as "STUN / over the internet". `Relay` always
        // wins (a TURN relay is a relay even on a private address).
        fn classify(t: CandidateType, ip: &str) -> super::diag::IceCandidateKind {
            use super::diag::IceCandidateKind;
            match t {
                CandidateType::Relay => IceCandidateKind::Relay,
                _ if is_private_lan_ip(ip) => IceCandidateKind::Host,
                CandidateType::Host => IceCandidateKind::Host,
                CandidateType::ServerReflexive => IceCandidateKind::ServerReflexive,
                CandidateType::PeerReflexive => IceCandidateKind::PeerReflexive,
                CandidateType::Unspecified => IceCandidateKind::Unknown,
            }
        }
        let local = report.reports.values().find_map(|r| match r {
            StatsReportType::LocalCandidate(c) if c.id == local_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
            _ => None,
        })?;
        let remote = report.reports.values().find_map(|r| match r {
            StatsReportType::RemoteCandidate(c) if c.id == remote_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
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
                .then(
                    (b.requests_sent + b.responses_received)
                        .cmp(&(a.requests_sent + a.responses_received)),
                )
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

    // ---- the H.264 access-unit assembler ------------------------------

    fn rtp_pkt(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> webrtc::rtp::packet::Packet {
        webrtc::rtp::packet::Packet {
            header: webrtc::rtp::header::Header {
                sequence_number: seq,
                timestamp: ts,
                marker,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(payload),
        }
    }

    /// A single-NAL IDR payload (type 5) — emits as one whole unit.
    const IDR_NAL: &[u8] = &[0x65, 0xAA, 0xBB];
    /// The same IDR as three FU-A fragments (start / middle / end).
    const FU_S: &[u8] = &[0x7C, 0x85, 0x11];
    const FU_M: &[u8] = &[0x7C, 0x05, 0x22];
    const FU_E: &[u8] = &[0x7C, 0x45, 0x33];

    #[test]
    fn single_packet_units_emit_in_order() {
        let mut asm = H264AuAssembler::default();
        let s1 = asm.push(&rtp_pkt(1, 100, true, IDR_NAL)).unwrap().unwrap();
        assert!(s1.key, "type-5 NAL is a key unit");
        assert_eq!(&s1.data[..], &[0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
        let s2 = asm.push(&rtp_pkt(2, 200, true, IDR_NAL)).unwrap();
        assert!(s2.is_some(), "the anchored next unit emits too");
    }

    #[test]
    fn fragments_reassemble_even_when_reordered() {
        let mut asm = H264AuAssembler::default();
        // Anchor with a complete first unit.
        asm.push(&rtp_pkt(9, 100, true, IDR_NAL)).unwrap().unwrap();
        // Fragments arrive start, END (marker), middle — out of order.
        assert!(asm.push(&rtp_pkt(10, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(12, 200, true, FU_E)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(11, 200, false, FU_M))
            .unwrap()
            .expect("contiguous after the late middle arrives");
        // Reconstructed: start code + NAL header (idc|type) + fragments.
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
        assert!(s.key);
    }

    #[test]
    fn a_hole_mid_unit_drops_that_unit_never_a_torn_one() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(20, 100, true, IDR_NAL)).unwrap().unwrap();
        // Unit 2 loses its middle fragment for good.
        assert!(asm.push(&rtp_pkt(21, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(23, 200, true, FU_E)).unwrap().is_none());
        // Unit 3 arrives — unit 2 is abandoned, and unit 3 (which starts
        // an AU) emits despite the lost anchor.
        let s = asm
            .push(&rtp_pkt(24, 300, true, IDR_NAL))
            .unwrap()
            .expect("the stream re-syncs on the next unit");
        assert_eq!(s.rtp_timestamp, 300);
    }

    #[test]
    fn an_anchored_hole_waits_for_the_retransmit() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(29, 100, true, IDR_NAL)).unwrap().unwrap();
        // The unit's *first* packet is missing; the marker alone must not
        // emit a headless tail.
        assert!(asm.push(&rtp_pkt(31, 200, false, FU_M)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(32, 200, true, FU_E)).unwrap().is_none());
        // The NACK retransmit fills the hole late — the unit completes.
        let s = asm
            .push(&rtp_pkt(30, 200, false, FU_S))
            .unwrap()
            .expect("retransmit completes the chain");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn late_retransmit_of_an_abandoned_unit_cannot_clobber_the_live_one() {
        let mut asm = H264AuAssembler::default();
        // Unit at ts 100 never completes (tail lost)…
        assert!(asm.push(&rtp_pkt(40, 100, false, FU_S)).unwrap().is_none());
        // …the next unit begins…
        assert!(asm.push(&rtp_pkt(42, 200, false, FU_S)).unwrap().is_none());
        // …a stale retransmit for ts 100 arrives and must be ignored…
        assert!(asm.push(&rtp_pkt(41, 100, true, FU_E)).unwrap().is_none());
        // …and the live unit still completes intact.
        let s = asm
            .push(&rtp_pkt(43, 200, true, FU_E))
            .unwrap()
            .expect("live unit unaffected by the stale packet");
        assert_eq!(s.rtp_timestamp, 200);
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x33]);
    }

    #[test]
    fn a_headless_tail_never_emits_without_an_anchor() {
        let mut asm = H264AuAssembler::default();
        // Fresh stream joined mid-unit: middle + end fragments only.
        assert!(asm.push(&rtp_pkt(50, 100, false, FU_M)).unwrap().is_none());
        assert!(
            asm.push(&rtp_pkt(51, 100, true, FU_E)).unwrap().is_none(),
            "a contiguous-looking run that doesn't *start* a unit stays dropped"
        );
    }

    #[test]
    fn sequence_wraparound_is_transparent() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(65534, 100, true, IDR_NAL))
            .unwrap()
            .unwrap();
        assert!(asm
            .push(&rtp_pkt(65535, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(asm.push(&rtp_pkt(0, 200, false, FU_M)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(1, 200, true, FU_E))
            .unwrap()
            .expect("the chain is contiguous across the wrap");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn au_start_detection_matches_rtp_payload_shapes() {
        assert!(payload_starts_au(&Bytes::from_static(IDR_NAL)));
        assert!(payload_starts_au(&Bytes::from_static(FU_S)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_M)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_E)));
        // STAP-A aggregates start units too.
        assert!(payload_starts_au(&Bytes::from_static(&[0x78, 0x00, 0x01])));
    }

    #[test]
    fn private_lan_ips_recognised_public_ones_not() {
        // RFC1918 + link-local → LAN.
        assert!(is_private_lan_ip("192.168.1.50"));
        assert!(is_private_lan_ip("10.0.0.3"));
        assert!(is_private_lan_ip("172.16.4.9"));
        assert!(is_private_lan_ip("169.254.10.20"));
        assert!(is_private_lan_ip("fe80::1"));
        assert!(is_private_lan_ip("fd12:3456::1"));
        // Public, CGNAT, and junk → not LAN.
        assert!(!is_private_lan_ip("1.2.3.4"));
        assert!(!is_private_lan_ip("100.64.0.1")); // carrier-grade NAT, not a LAN
        assert!(!is_private_lan_ip("2606:4700::1111"));
        assert!(!is_private_lan_ip("not-an-ip"));
    }

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

    #[test]
    fn annexb_nal_scan_finds_types_across_both_start_codes() {
        // 4-byte start code SPS (7), 3-byte start code PPS (8), then IDR (5).
        let au = [
            0, 0, 0, 1, 0x67, 0xAA, // SPS
            0, 0, 1, 0x68, 0xBB, // PPS
            0, 0, 0, 1, 0x65, 0x11, 0x22, // IDR slice
        ];
        let types: Vec<u8> = annexb_nal_types(&au).collect();
        assert_eq!(types, vec![7, 8, 5]);
        assert!(au_has_idr(&au));

        // A delta slice (type 1) alone is not a key.
        let p = [0, 0, 0, 1, 0x41, 0x99];
        assert!(!au_has_idr(&p));

        // Degenerate inputs scan to nothing without panicking.
        assert_eq!(annexb_nal_types(&[]).count(), 0);
        assert_eq!(annexb_nal_types(&[0, 0, 1]).count(), 0);
    }

    #[test]
    fn au_assembler_groups_by_timestamp_and_drops_torn_units() {
        let mut asm = H264AuAssembler::default();
        // Two single-NAL packets of one frame; marker closes it.
        assert!(asm
            .push(&rtp_pkt(1, 1000, false, &[0x41, 1, 1, 1]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(2, 1000, true, &[0x65, 2, 2, 2]))
            .unwrap()
            .expect("marker completes the unit");
        assert!(s.key, "an IDR NAL anywhere in the unit marks it key");
        assert_eq!(s.rtp_timestamp, 1000);
        // Depacketized single NALs come back with start codes attached.
        assert_eq!(
            s.data.as_ref(),
            &[0, 0, 0, 1, 0x41, 1, 1, 1, 0, 0, 0, 1, 0x65, 2, 2, 2]
        );

        // A unit whose marker never arrived is dropped when the next
        // timestamp starts; the new unit is unaffected.
        assert!(asm
            .push(&rtp_pkt(3, 2000, false, &[0x41, 7, 7, 7]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(4, 3000, true, &[0x41, 9, 9, 9]))
            .unwrap()
            .expect("fresh unit completes");
        assert_eq!(s.rtp_timestamp, 3000);
        assert!(!s.key);
        assert_eq!(s.data.as_ref(), &[0, 0, 0, 1, 0x41, 9, 9, 9]);
    }

    #[tokio::test]
    async fn loopback_video_lane_carries_h264_samples() {
        // Same loopback bring-up as the data-channel test, but the
        // assertion is on the provisioned video lane: an Annex-B access
        // unit written on the offerer's track arrives at the answerer as
        // one assembled VideoSample, byte-equal and key-flagged. This is
        // the negotiation-without-renegotiation property end to end:
        // m-line in the one offer/answer, RTP, depacketize, reassembly.
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

        // One synthetic IDR access unit. The H264 payloader parses
        // Annex-B, so the bytes must be a plausible NAL stream.
        let au: Vec<u8> = {
            let mut v = vec![0u8, 0, 0, 1, 0x65];
            v.extend((0..400u32).map(|i| (i % 251) as u8));
            v
        };

        // The track binds only once negotiation + ICE complete, and
        // writes before that are silent no-ops — so keep (re)sending
        // the unit at frame cadence until the far side reports it.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut received: Option<VideoSample> = None;
        let mut send_tick = tokio::time::interval(std::time::Duration::from_millis(50));
        while received.is_none() && tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = send_tick.tick() => {
                    let _ = offerer
                        .send_video(Bytes::from(au.clone()), std::time::Duration::from_millis(33))
                        .await;
                }
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        answerer.add_ice_candidate(c.clone()).await.expect("ice → answerer");
                    }
                }
                Some(ev) = ans_rx.recv() => {
                    match ev {
                        TransportEvent::LocalIceCandidate(Some(c)) => {
                            offerer.add_ice_candidate(c.clone()).await.expect("ice → offerer");
                        }
                        TransportEvent::VideoSample(s) => received = Some(s),
                        _ => {}
                    }
                }
            }
        }

        let sample = received.expect("answerer never received a video sample");
        assert_eq!(sample.data.as_ref(), &au[..], "AU survives byte-exact");
        assert!(sample.key, "IDR unit arrives key-flagged");

        offerer.close().await.expect("close offerer");
        answerer.close().await.expect("close answerer");
    }
}
