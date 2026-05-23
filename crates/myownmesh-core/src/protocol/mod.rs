//! Wire protocol for peer connections.
//!
//! Every frame on the WebRTC data channel is one of the variants
//! below, serialized as a JSON object with a `kind` discriminator.
//! The pre-active phases are:
//!
//!   1. `hello` — each side announces its claimed Device ID, a random
//!      nonce, a verification code, and an optional capabilities
//!      blob. Sent immediately on channel open.
//!   2. `auth_response` — each side returns the other's nonce signed
//!      with its own private key. Receiving a valid signature
//!      authenticates that the sender owns the keypair matching its
//!      claimed Device ID.
//!
//! After mutual auth verification, the receiver side either
//! auto-accepts (peer is in the roster) or queues the request for
//! user approval. The receiver sends `approve` once cleared; the
//! connection becomes ACTIVE on both sides at that point.
//!
//! Post-active, peers exchange:
//!   - `capabilities_update` whenever local capabilities change
//!   - `shelve` / `unshelve` to negotiate topology
//!   - `ping` / `pong` for keepalive
//!   - `rpc_request` / `rpc_response` / `rpc_stream_chunk` /
//!     `rpc_stream_end` for embedder-defined request/response calls
//!   - Application data over typed user-defined channels (see
//!     [`crate::events`])
//!
//! Forward compat: a receiver getting an unknown `kind` silently
//! drops the frame. Peers gate optional traffic per-peer via
//! [`features`] capability negotiation so older peers aren't bombed
//! with frames they'll discard.

pub mod features;
pub mod handshake;
pub mod keepalive;
pub mod rpc;
pub mod topology;

pub use features::{Feature, ADVERTISED_FEATURES};
pub use handshake::{ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage};
pub use keepalive::{PingMessage, PongMessage};
pub use rpc::{
    CapabilitiesUpdateMessage, CapabilityAdvert, RpcRequestMessage, RpcResponseMessage,
    RpcStreamChunkMessage, RpcStreamEndMessage,
};
pub use topology::{ShelveMessage, UnshelveMessage};

use serde::{Deserialize, Serialize};

/// Tagged union of every wire frame the mesh transport carries.
/// Receivers match on `kind`; unknown kinds are silently dropped on
/// deserialize via the `Unknown` catch-all variant so we can decode
/// the rest of an incoming stream even when a sender emits a frame
/// from a future protocol revision.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum MeshMessage {
    Hello(HelloMessage),
    AuthResponse(AuthResponseMessage),
    Approve(ApproveMessage),
    Deny(DenyMessage),
    Ping(PingMessage),
    Pong(PongMessage),
    CapabilitiesUpdate(CapabilitiesUpdateMessage),
    Shelve(ShelveMessage),
    Unshelve(UnshelveMessage),
    RpcRequest(RpcRequestMessage),
    RpcResponse(RpcResponseMessage),
    RpcStreamChunk(RpcStreamChunkMessage),
    RpcStreamEnd(RpcStreamEndMessage),
    /// Application payload on a user-defined typed channel. The
    /// `channel` name is the embedder's identifier; `payload` is the
    /// raw serialized message body. Receivers route to the matching
    /// `Channel<T>` registration or discard.
    Channel {
        channel: String,
        /// Opaque to the mesh — embedders decide their own framing.
        /// `serde_json::Value` rather than `Bytes` so the entire
        /// frame stays JSON-encodable; embedders wanting binary
        /// efficiency can base64-encode into a string field.
        payload: serde_json::Value,
    },
    /// Unknown frame from a future protocol revision. Captured here
    /// so the receiver's deserializer doesn't fail the whole stream
    /// — the engine forwards Unknown frames as `Diag` events but
    /// otherwise ignores them.
    #[serde(other)]
    Unknown,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unknown_kind_decodes_as_unknown_variant() {
        let raw = r#"{"kind":"definitely_not_a_real_kind","whatever":1}"#;
        let msg: MeshMessage = serde_json::from_str(raw).unwrap();
        assert!(matches!(msg, MeshMessage::Unknown));
    }

    #[test]
    fn hello_round_trips() {
        let msg = MeshMessage::Hello(HelloMessage {
            protocol: crate::PROTOCOL_VERSION,
            device_id: "peer1".into(),
            label: "Laptop".into(),
            nonce: "noncexyz".into(),
            verification_code: "abc123".into(),
            capabilities: None,
            max_connections: None,
            features: vec!["ring_topology".into()],
            app_version: Some("0.1.0".into()),
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::Hello(h) => {
                assert_eq!(h.device_id, "peer1");
                assert_eq!(h.nonce, "noncexyz");
            }
            _ => panic!("did not round-trip as Hello"),
        }
    }
}
