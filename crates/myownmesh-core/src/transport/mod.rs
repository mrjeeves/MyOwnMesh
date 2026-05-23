//! WebRTC transport. Wraps `webrtc-rs` so the engine can drive peer
//! connections without dealing with the crate's callback-driven API
//! directly — every transport event lands on an mpsc the engine
//! drains in its main loop.
//!
//! Architecture:
//!
//! - One [`Transport`] per engine instance — owns the shared
//!   `webrtc::api::API` (codec / interceptor / setting registries).
//! - One [`PeerSession`] per remote peer — owns the
//!   `RTCPeerConnection` and the application data channel. Drops
//!   close the connection.
//! - Events ([`TransportEvent`]) flow out of `PeerSession` on an
//!   mpsc. The engine matches on them serially so there are no
//!   races on per-peer state.

pub mod diag;
pub mod ice;
pub mod webrtc;

pub use diag::{IceCandidateKind, IceCandidateStats, PeerDiag};
pub use ice::{build_rtc_configuration, classify_candidate_sdp};
pub use webrtc::{LocalIceCandidate, PeerSession, Role, Transport, TransportEvent};
