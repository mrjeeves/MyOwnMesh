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
pub mod webrtc;

pub use diag::{
    IceCandidateKind, IceCandidateStats, IceCheckSnapshot, IcePairSnapshot, PeerDiag,
    SelectedCandidatePair,
};
pub use ice::{build_rtc_configuration, classify_candidate_sdp};
pub use webrtc::{
    resolved_media_lanes, AudioSample, LocalIceCandidate, PeerSession, Role, Transport,
    TransportEvent, VideoSample, MEDIA_LANES,
};
pub(crate) use webrtc::{
    DataChannelOpenOwnership, EndpointAuthHandoff, RemoteCandidateDisposition,
    WebRtcConnectorEvent, WebRtcConnectorIncarnation, WebRtcConnectorWorker,
};
