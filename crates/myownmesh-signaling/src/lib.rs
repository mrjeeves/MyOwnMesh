//! Signaling for MyOwnMesh. Two strategies ship today — [`nostr`]
//! (the remote default, relay-based) and [`mdns`] (LAN-local DNS-SD
//! discovery + unicast TCP exchange, on by default alongside the
//! remote strategy) — and sibling crates can add others (BitTorrent
//! trackers, MQTT, IPFS, Firebase); the engine picks at construction
//! time.
//!
//! Wire-compatibility note: the room-handle derivation and relay
//! shuffle in [`nostr`] are byte-compatible with upstream Trystero
//! `0.24.x` so a future hybrid deployment (JS Trystero peers + Rust
//! MyOwnMesh peers, both using the same TRYSTERO_APP_ID) is
//! possible. By default the app-ids differ
//! (`myownmesh-cloud-mesh-v1` vs `myownllm-cloud-mesh-v1`) so the
//! two ecosystems never meet on the wire.
//!
//! See [`upstream`] for the catalogue of upstream Trystero
//! limitations this implementation works around natively — without
//! requiring users to apply patches.

pub mod local;
pub mod mdns;
pub mod nostr;
pub mod server;
pub mod upstream;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Signaling-layer capability id: the sender stamps a recipient tag on
/// every ephemeral event it publishes — `["p", <device id>]` on directed
/// offer / answer / candidate, `["p", <room handle>]` on room-addressed
/// broadcasts (`leave`) — so subscribers can ask the relay for "directed
/// to me (or the room)" instead of receiving every pairwise negotiation
/// in the room. Advertised in the announce's `caps` so receivers know
/// when the whole room tags — see `nostr::driver` for the adaptive
/// subscription that drops the legacy catch-all filter once it does.
pub const SIG_CAP_PTAG: &str = "ptag";

/// One signaling message — either an offer/answer SDP exchange, an
/// ICE candidate, or the periodic presence-announce. Each carries
/// the sender's peer-id (Device ID) so receivers route correctly.
///
/// Candidate payloads carry the full RTCIceCandidateInit-equivalent
/// shape so the receiving WebRTC stack can apply them verbatim.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SignalingMessage {
    Announce {
        peer_id: String,
        /// Signaling-layer capabilities of the announcing build (e.g.
        /// [`SIG_CAP_PTAG`]). `default` so pre-caps announces decode as
        /// an empty list — receivers treat empty as "legacy build".
        #[serde(default)]
        caps: Vec<String>,
    },
    Offer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    Answer {
        peer_id: String,
        offer_id: String,
        sdp: String,
    },
    Candidate {
        peer_id: String,
        candidate: String,
        #[serde(default)]
        sdp_mid: Option<String>,
        #[serde(default)]
        sdp_mline_index: Option<u16>,
        #[serde(default)]
        username_fragment: Option<String>,
    },
    /// A peer left the room. Sent two ways, both as a pure accelerator over
    /// the heartbeat-timeout fallback:
    ///
    /// - **Self-announced** by a peer making a deliberate exit (network
    ///   remove, transport restart, daemon shutdown) so the others drop its
    ///   session immediately rather than stranding on a dead connection
    ///   whose ICE still reports `Connected` for ~90 s. This is what makes a
    ///   "reconnect" (leave-then-rejoin) come back promptly.
    /// - **Synthesised** by an intelligent [`server`] relay the instant a
    ///   member's WebSocket closes, covering crashes / yanked cables where
    ///   the peer never got to announce.
    ///
    /// Public relays never synthesise it; on those, a deliberate exit still
    /// self-announces, and an ungraceful one falls back to timeout-based
    /// detection.
    Leave { peer_id: String },
}

/// Per-relay health snapshot. Diagnostic-only — surfaced via the
/// mesh's [`crate::upstream::SIGNALING_HEALTH`] feed so the UI can
/// show "5/5 relays open" or "2/5 relays open, 3 retrying".
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelayHealth {
    /// Socket is open and we've received at least one inbound EVENT
    /// since opening (or since the last subscription replay).
    Live,
    /// Socket is open but no inbound EVENT seen yet — could be a
    /// fresh connection or a stuck subscription.
    Opening,
    /// Socket connecting / reconnecting.
    Reconnecting,
    /// Backed off after repeated failures; will retry per the
    /// per-socket schedule.
    BackedOff,
    /// Permanently denied (in the user-configured denylist).
    Denied,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("websocket: {0}")]
    Socket(String),
    #[error("decode: {0}")]
    Decode(String),
    #[error("encode: {0}")]
    Encode(#[from] serde_json::Error),
    #[error("no relays available")]
    NoRelays,
    /// The self-hosted signaling [`server`] couldn't bind its listener.
    #[error("bind {0}: {1}")]
    Bind(String, #[source] std::io::Error),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, Error>;

/// Strategy-agnostic signaling channel. The mesh engine talks to one
/// of these per joined network. Implementations spin up their own
/// background tasks for socket lifecycle, message routing, etc.
#[async_trait]
pub trait SignalingChannel: Send + Sync {
    /// Publish a message to the network room. Returns once at least
    /// one relay has accepted the publish; failures past the first
    /// success are logged but not propagated.
    async fn send(&self, msg: &SignalingMessage) -> Result<()>;

    /// Best-effort snapshot of per-relay health. Used by the
    /// engine's signaling-health watchdog.
    fn relay_health(&self) -> Vec<(String, RelayHealth)>;

    /// Disconnect from all relays and stop background tasks.
    async fn close(&self);
}
