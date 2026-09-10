//! WebRTC transport. Wraps `webrtc-rs` so the engine can drive peer
//! connections without dealing with the crate's callback-driven API
//! directly. Every transport event lands on the exact worker's
//! bounded mailbox and is handled in order by that worker's pump.
//!
//! Architecture:
//!
//! - One [`Transport`] per engine instance — owns the shared
//!   `webrtc::api::API` (codec / interceptor / setting registries).
//! - One [`PeerSession`] per remote peer — owns the
//!   `RTCPeerConnection` and the application data channel. Drops
//!   close the connection.
//! - Events ([`TransportEvent`]) flow out of `PeerSession` on a
//!   bounded mpsc. One worker pump handles each peer in order, while
//!   exact owner checks fence replacement races.

pub mod diag;
pub mod ice;
pub(crate) mod webrtc;

pub use diag::{
    IceCandidateKind, IceCandidateStats, IceCheckSnapshot, IcePairSnapshot, PeerDiag,
    SelectedCandidatePair,
};
pub use ice::{build_rtc_configuration, classify_candidate_sdp};
#[cfg(not(feature = "transport-lab"))]
pub(crate) use webrtc::TransportEvent;
#[cfg(feature = "transport-lab")]
pub use webrtc::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant, TransportEvent, TransportLabCallbackGrant,
    TransportLabCallbackWorkload, TransportLabRealtimeWorkload,
};
// `EndpointAuthHandoff` is deliberately no longer re-exported: it is now an
// internal WebRTC detail that converts to the generic
// `connector::ConnectedChannelHandoff` at the boundary, and endpoint
// authentication names only the generic form.
/// Controls only. Named here so the live open-path controls can arm a connector
/// to withhold one binding component.
///
/// There is no production re-export, because the type does not exist outside
/// the controls. The gate carries `transport-lab` as well as `test` to match
/// both the type itself and its only consumers, the live open-path controls: a
/// default-feature test build has no live link to arm, so re-exporting there
/// would name something that neither exists nor could be used.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) use webrtc::WithheldBindingComponent;
pub(crate) use webrtc::{
    DataChannelOpenOwnership, RemoteCandidateDisposition, StartedConnectorSend,
    WebRtcConnectorEvent, WebRtcConnectorWorker,
};
/// The realtime names are all `WebRtc`-qualified, and there is no unqualified
/// spelling of any of them.
///
/// A codec, a framing strategy, an RTCP feedback mechanism, an RTP kind, a
/// profile, and the four flow DTOs are WebRTC facts. Published unqualified they
/// read as *the* realtime vocabulary, which invites an application to treat them
/// as the generic layer's concepts and a second provider to believe it has to
/// fit into them. No compatibility alias is kept for the unqualified names: a
/// caller updates the spelling or does not compile, which is the only signal
/// strong enough to relocate a concept.
pub use webrtc::{
    LocalIceCandidate, PeerSession, RealtimeInboundArrival, Role, Transport,
    WebRtcConnectorProfile, WebRtcConnectorProfileError, WebRtcRealtimeCodec,
    WebRtcRealtimeFlowOpen, WebRtcRealtimeFraming, WebRtcRealtimeInboundArrival,
    WebRtcRealtimeInboundUnit, WebRtcRealtimeOutboundUnit, WebRtcRealtimeProfile,
    WebRtcRealtimeProfileError, WebRtcRealtimeRtcpFeedback, WebRtcRtpKind,
};
