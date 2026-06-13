//! Wire frames the daemon writes to a duplex (post-
//! `EventsSubscribe`) client connection. Every line is exactly
//! one of these variants, tagged via the `kind` field so a
//! client can dispatch on it without trying to guess from
//! shape.
//!
//! Backward compat: `Event` / `Lagged` were the only `kind`s
//! the original event stream emitted, and the existing
//! MyOwnMesh GUI client already ignores unknown kinds via its
//! `match _ => {}` default in
//! `gui/src-tauri/src/main.rs::run_event_pump`. New variants
//! land additively without breaking it.

use serde::Serialize;
use serde_json::Value;

use myownmesh_core::events::MeshEvent;

/// Server → client wire frame on a duplex event socket.
///
/// Pre-`EventsSubscribe`, the daemon emits the legacy
/// [`crate::control::Response`] shape (no `kind` tag) so the
/// existing one-shot request/response clients keep working.
/// After `EventsSubscribe`, every server-initiated line is a
/// `ServerOut` JSON object.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ServerOut {
    /// Live mesh event (peer state, phase, diag).
    Event { event: MeshEvent },
    /// Subscriber was too slow; some events were dropped.
    /// `skipped` is the number lost since the last successful
    /// receive.
    Lagged { skipped: u64 },
    /// Inbound RPC request arrived from a peer for a method
    /// this client has claimed. The client must respond with
    /// either a single `rpc_respond` (single-shot) or a
    /// sequence of `rpc_stream_chunk` lines terminated by
    /// `rpc_stream_end` (streaming).
    RpcInbound {
        network: String,
        from: String,
        request_id: String,
        method: String,
        payload: Value,
        /// `true` if the peer asked for a streaming response.
        /// Determined by the wire frame's `streaming` flag, not
        /// by the local handler's mode — clients should
        /// respect the peer's intent.
        streaming: bool,
    },
    /// Chunk of a streaming response to an outbound RPC call
    /// the client made via `RpcCallStream`. Multiple chunks may
    /// arrive before `RpcCallStreamEnd`.
    RpcCallStreamChunk { request_id: String, payload: Value },
    /// End-of-stream marker for an outbound `RpcCallStream`.
    /// `error` is set if the peer terminated the stream with
    /// an error rather than a clean close.
    RpcCallStreamEnd {
        request_id: String,
        error: Option<String>,
    },
    /// Inbound typed-channel message for a channel this client
    /// has subscribed to.
    ChannelInbound {
        network: String,
        from: String,
        channel: String,
        payload: Value,
    },
    /// One assembled video access unit from a peer's track lane,
    /// for a client that called `video_subscribe` on the network.
    /// `data` is the Annex-B H.264 unit, base64; `rtp_timestamp`
    /// ticks at the 90 kHz video clock; `key` marks an IDR.
    VideoInbound {
        network: String,
        from: String,
        /// Which of the peer's video lanes the unit arrived on — lets a
        /// subscriber keep several simultaneous streams from one peer apart.
        stream: u8,
        rtp_timestamp: u32,
        key: bool,
        data: String,
    },
    /// One Opus frame off a peer's audio track lane (base64 payload).
    AudioInbound {
        network: String,
        from: String,
        /// Which of the peer's audio lanes the frame arrived on.
        stream: u8,
        rtp_timestamp: u32,
        data: String,
    },
    /// A more-recent client claimed a method this client had
    /// previously registered. The displaced client should stop
    /// expecting `RpcInbound` events for `method`; any
    /// in-flight calls are left to resolve naturally (the
    /// displaced client can still answer them).
    HandlerDisplaced {
        network: String,
        method: String,
        /// Best-effort short id of the displacing client; the
        /// daemon does not surface socket addresses.
        by: String,
    },
}
