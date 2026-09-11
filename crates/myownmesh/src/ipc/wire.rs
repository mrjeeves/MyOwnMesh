//! Wire frames the daemon writes to a duplex (post-
//! `EventsSubscribe`) client connection. Every line is exactly
//! one of these variants, tagged via the `kind` field so a
//! client can dispatch on it without trying to guess from
//! shape.
//!
//! Current event handling: every line is forwarded to the frontend verbatim
//! as `mesh://event`; the frontend dispatches on recognized `kind` values and
//! renders other current server frames generically.
//! The serializer for these frames is the enum below.

use serde::Serialize;
use serde_json::Value;

use myownmesh_core::events::MeshEvent;

/// Server → client wire frame on a duplex event socket.
///
/// Before `EventsSubscribe`, the daemon emits the untagged
/// [`crate::control::Response`] shape for one-shot request/response calls. The
/// response has no `kind` because it is already
/// associated with the request on that connection. After `EventsSubscribe`,
/// every server-initiated line is a tagged `ServerOut` JSON object.
#[derive(Debug, Serialize)]
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
        operation_id: u64,
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
    RpcCallStreamChunk {
        request_id: String,
        #[serde(serialize_with = "serialize_rpc_stream_chunk")]
        payload: myownmesh_core::rpc::RpcStreamChunk,
    },
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
    // This socket carries nothing about realtime flows: units ride a binary
    // `realtime_pipe`, and every flow operation answers on the connection that
    // requested it. See [`crate::control::Request::RealtimePipe`].
    /// A more-recent client claimed a method this client had
    /// previously registered. The displaced client should stop
    /// expecting `RpcInbound` events for `method`; the displaced claim's
    /// in-flight calls are cancelled and truthfully failed.
    HandlerDisplaced {
        network: String,
        method: String,
        /// Best-effort short id of the displacing client; the
        /// daemon does not surface socket addresses.
        by: String,
    },
}

fn serialize_rpc_stream_chunk<S: serde::Serializer>(
    chunk: &myownmesh_core::rpc::RpcStreamChunk,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    chunk.value().serialize(serializer)
}

/// A borrowed mirror of [`ServerOut::RpcInbound`], for measuring a frame that
/// does not exist yet.
///
/// The mailbox prices an item by serializing it, and an inbound RPC frame is
/// assembled from a call whose payload a remote peer chose the size of. Building
/// it in order to ask whether it can be admitted is the admission arriving after
/// the allocation it was about, so the question is asked of this instead: the
/// same tag, the same field names, the same order, every field a borrow.
///
/// **It must serialize byte-for-byte as the variant it mirrors.** That is the
/// whole of its contract and the only reason it is here rather than in `bridge`,
/// where the builder that uses it lives: a mirror kept beside the thing it
/// mirrors is one a change to either has to walk past. `v4_r2_daemon_a_measured_\
/// inbound_frame_matches_the_frame_it_becomes` is what checks it, and it checks
/// the encoded bytes rather than the fields, because equal fields that encode
/// differently is exactly the failure a hand-written mirror has.
#[derive(Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub(crate) enum ServerOutView<'a> {
    RpcInbound {
        network: &'a str,
        from: &'a str,
        request_id: &'a str,
        operation_id: u64,
        method: &'a str,
        payload: &'a Value,
        streaming: bool,
    },
    HandlerDisplaced {
        network: &'a str,
        method: &'a str,
        by: crate::ipc::clients::ClientId,
    },
    /// The same mirror for a channel fan-out frame, and it exists for a sharper
    /// reason than the RPC one: a fan-out multiplies one peer frame by the
    /// local subscriber count, so the payload a remote chose the size of was
    /// being deep-cloned once per subscriber before any of those subscribers'
    /// mailboxes could refuse it.
    ///
    /// Same tag, same field names, same order, every field a borrow of the
    /// funded delivery the pump is holding.
    ChannelInbound {
        network: &'a str,
        from: &'a str,
        channel: &'a str,
        payload: &'a Value,
    },
    /// The mirror for a forwarded stream chunk. The payload is not copied into
    /// this frame — it is *moved* out of the funded `RpcStreamChunk` — so the
    /// reason this mirror exists is not to avoid a clone but to let the builder
    /// subtract the reservation core is already holding for that same graph
    /// before charging the outer queue for it a second time.
    RpcCallStreamChunk {
        request_id: &'a str,
        payload: &'a Value,
    },
    /// The mirror for an end-of-stream marker.
    ///
    /// `error` is deliberately not `Option<&str>`. A remote terminal's text is
    /// peer-sized and still funded by core's session lease, and a locally
    /// generated one has no business being formatted into a `String` before the
    /// writer mailbox has agreed to hold it. Both cases are therefore rendered
    /// at serialization time from something that already exists.
    RpcCallStreamEnd {
        request_id: &'a str,
        error: TerminalReasonView<'a>,
    },
}

/// Why a forwarded stream ended, in a form that can be measured before the
/// owned `Option<String>` it becomes exists.
///
/// **Serializes exactly as that `Option<String>` would.** `Clean` is `null`,
/// and both other arms are the JSON string the built frame will carry.
#[derive(Debug, Clone, Copy)]
pub(crate) enum TerminalReasonView<'a> {
    /// The stream ended without an error.
    Clean,
    /// Peer-selected text. Core still owns the funding; the daemon reads it by
    /// borrow and holds the terminal until the write-side owner exists.
    Remote(&'a myownmesh_core::rpc::RpcStreamTerminal),
    /// A refusal this daemon generated. Held as its cause, not as a message:
    /// the message is rendered straight into the serializer past admission.
    LocalChunkRefusal(&'a myownmesh_core::ResourceMailboxAdmissionError),
}

/// The one place the local refusal text is spelled, so the measured width and
/// the built frame cannot disagree about it.
const LOCAL_CHUNK_REFUSAL: &str = "local stream chunk was refused";

impl TerminalReasonView<'_> {
    /// The owned field the mirrored frame carries. Called by the builder past
    /// admission and by nothing else.
    pub(crate) fn into_owned(self) -> Option<String> {
        match self {
            Self::Clean => None,
            Self::Remote(terminal) => Some(terminal.reason().to_owned()),
            Self::LocalChunkRefusal(error) => Some(format!("{LOCAL_CHUNK_REFUSAL}: {error}")),
        }
    }
}

impl Serialize for TerminalReasonView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self {
            Self::Clean => serializer.serialize_none(),
            Self::Remote(terminal) => serializer.serialize_some(terminal.reason()),
            Self::LocalChunkRefusal(error) => serializer.serialize_some(&LocalRefusalText(error)),
        }
    }
}

/// Renders the local refusal message into the serializer without ever holding
/// it as an owned `String`.
#[derive(Debug)]
struct LocalRefusalText<'a>(&'a myownmesh_core::ResourceMailboxAdmissionError);

impl Serialize for LocalRefusalText<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(&format_args!("{LOCAL_CHUNK_REFUSAL}: {}", self.0))
    }
}

/// Off-node retention owned by one queued outbound frame.
///
/// Every variant is pure serializable data — no oneshot, sender, or socket
/// handle rides in one — so one measurement over the whole frame is exact where
/// a per-variant match would only restate it, and core's shared costing for a
/// serializable value answers it completely. That is not true of every mailbox
/// item: `NetworkCmd` carries reply handles serialization cannot see, which is
/// why its implementation enumerates variants and adds a `SocketOrHandle` term.
/// There is nothing here for such a term to count.
///
/// Delegated rather than derived. This used to restate core's JSON-tree
/// costing, which meant one question — what does a JSON-shaped value retain —
/// had two answers in two crates that could drift apart independently. There is
/// one answer now, and it lives with the trait it serves.
unsafe impl myownmesh_core::ResourceMailboxItem for ServerOut {
    fn measured_claim(
        &self,
    ) -> Result<myownmesh_core::MailboxMeasurement<Self>, myownmesh_core::ResourceMailboxItemError>
    {
        myownmesh_core::measure_serialized_mailbox_item::<Self>(self)
    }
}
