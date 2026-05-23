//! Generic RPC frames. Embedders register handlers under string
//! method names; callers invoke them with opaque JSON payloads. A
//! single in-flight map keyed by `request_id` matches responses back
//! to their callers. Streamed responses use
//! `rpc_stream_chunk` + `rpc_stream_end` so a single request can
//! emit many ordered messages (file transfers, partial inference
//! results, etc.).

use bytes::Bytes;
use serde::{Deserialize, Serialize};

/// Capability advertisement broadcast in [`super::handshake::HelloMessage`]
/// and refreshed via [`CapabilitiesUpdateMessage`]. The mesh treats
/// every field opaquely; the embedder interprets them.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct CapabilityAdvert {
    /// Free-form capability tag strings the embedder uses to gate
    /// behavior ("transcribe", "infer", "host-files", etc.). The
    /// mesh doesn't validate these; it forwards them as-is so other
    /// peers can filter on them.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Sender's app version. Cosmetic, used by the UI to show
    /// "running 0.3.1" beside each peer.
    #[serde(default)]
    pub app_version: Option<String>,
    /// Hint about how many concurrent connections the peer can
    /// service. Feeds the topology selector when scaling out — peers
    /// that can hold more get more preferred slots.
    #[serde(default)]
    pub max_connections: Option<u32>,
    /// Embedder-defined structured advertisement. JSON-encoded so
    /// the mesh stays type-agnostic; downstream apps deserialize
    /// into their own type.
    #[serde(default)]
    pub extra: serde_json::Value,
}

/// Push an updated [`CapabilityAdvert`] to peers. Sent whenever local
/// state changes that affects what we can offer. Receivers replace
/// their cached copy wholesale.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapabilitiesUpdateMessage {
    pub capabilities: CapabilityAdvert,
}

/// Single-shot or streaming request to a remote peer's handler.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcRequestMessage {
    /// Caller-generated id, unique within the sender's in-flight
    /// map. Returned verbatim in the response.
    pub request_id: String,
    /// Method name the receiver dispatches on. Embedder-defined.
    pub method: String,
    /// Opaque payload. Receivers interpret based on `method`.
    pub payload: serde_json::Value,
    /// When true, the responder should reply with
    /// [`RpcStreamChunkMessage`] frames followed by
    /// [`RpcStreamEndMessage`]. When false, a single
    /// [`RpcResponseMessage`] is expected.
    #[serde(default)]
    pub streaming: bool,
}

/// Single-shot response. Either `ok` carries the result or `error`
/// carries a message; never both.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcResponseMessage {
    pub request_id: String,
    /// Result payload (deserialized by the caller). Mutually
    /// exclusive with `error`.
    #[serde(default)]
    pub ok: Option<serde_json::Value>,
    /// Error message. Mutually exclusive with `ok`.
    #[serde(default)]
    pub error: Option<String>,
}

/// One chunk in a streamed response. The payload may be JSON
/// (small structured updates) or base64-encoded bytes (large file
/// transfers); receivers route by request method.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStreamChunkMessage {
    pub request_id: String,
    /// Monotonic sequence number — receivers reorder if needed,
    /// though the WebRTC data channel preserves order on its own.
    pub seq: u64,
    pub payload: serde_json::Value,
}

/// Terminator for a streamed response. After this frame the
/// receiver may discard the in-flight entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcStreamEndMessage {
    pub request_id: String,
    /// When set, the stream terminated with an error.
    #[serde(default)]
    pub error: Option<String>,
}

/// Convenience helper for constructing an `RpcRequestMessage` from
/// a typed body. Returns `Err` if the body fails to serialize.
pub fn make_request<T: serde::Serialize>(
    request_id: impl Into<String>,
    method: impl Into<String>,
    body: &T,
    streaming: bool,
) -> Result<RpcRequestMessage, serde_json::Error> {
    Ok(RpcRequestMessage {
        request_id: request_id.into(),
        method: method.into(),
        payload: serde_json::to_value(body)?,
        streaming,
    })
}

/// Helpers for the binary path. Base64 keeps file chunks JSON-safe
/// without forcing a custom binary frame; switch to a sidecar
/// binary channel if profiling shows the encoding is a bottleneck.
pub fn bytes_to_payload(b: &Bytes) -> serde_json::Value {
    use data_encoding::BASE64;
    serde_json::Value::String(BASE64.encode(b))
}

pub fn payload_to_bytes(v: &serde_json::Value) -> Option<Bytes> {
    use data_encoding::BASE64;
    let s = v.as_str()?;
    BASE64.decode(s.as_bytes()).ok().map(Bytes::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_round_trip_through_payload() {
        let original = Bytes::from(vec![1, 2, 3, 4, 5, 6, 7, 8]);
        let payload = bytes_to_payload(&original);
        let back = payload_to_bytes(&payload).unwrap();
        assert_eq!(original, back);
    }

    #[test]
    fn make_request_round_trips() {
        #[derive(Serialize, Deserialize)]
        struct Body {
            x: u32,
        }
        let req = make_request("r1", "echo", &Body { x: 42 }, false).unwrap();
        assert_eq!(req.request_id, "r1");
        assert_eq!(req.method, "echo");
        assert_eq!(req.payload["x"], 42);
        assert!(!req.streaming);
    }
}
