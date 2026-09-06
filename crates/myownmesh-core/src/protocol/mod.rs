//! Wire protocol for peer connections.
//!
//! Every frame on the WebRTC data channel is one of the variants
//! below, serialized as a JSON object with a `kind` discriminator.
//! The pre-active phases are:
//!
//!   1. `hello` — each side announces its claimed Device ID, a random
//!      nonce, a verification code, and its supported feature ids.
//!      Sent immediately on channel open. It carries no application
//!      capability advertisement: a Hello is admitted before any
//!      session exists, so a blob here would be attacker-controlled
//!      application metadata arriving ahead of the boundary that
//!      admits application payload. See [`handshake::HelloMessage`].
//!   2. `auth_response` — each side returns its proof over the one
//!      domain-separated endpoint-auth transcript. That transcript binds the
//!      mesh context and profile, signer role, both Device IDs, both fresh
//!      contributions, and both certificate fingerprints. Receiving a valid
//!      proof authenticates the peer's key while binding it to this exact
//!      endpoint-auth context; a nonce-only signature is not accepted.
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
//!   - `routed_application` for signed, context-bound application payloads
//!     carried across the bounded topology-selected hop chain
//!   - Application data over typed user-defined channels (see
//!     [`crate::events`])
//!
//! The frame set is closed. A receiver getting a `kind` this build
//! does not implement refuses it — the frame fails to deserialize and
//! reaches no handler — so there is no revision-tolerance to rely on.
//! There is no optional feature negotiation or mixed-version mode in this
//! protocol. `hello.features` carries only the closed endpoint-authentication
//! profile required before any post-active frame is admitted.

pub mod departure;
pub mod facts;
pub mod features;
pub mod handshake;
pub mod hub;
pub mod keepalive;
pub mod parenting;
pub mod relay;
pub mod rpc;
pub mod topology;

pub use departure::{
    DepartureCorrelation, DepartureCorrelationError, DEPARTURE_CORRELATION_BYTES,
    DEPARTURE_CORRELATION_WIRE_CHARS,
};
pub use facts::{
    CanonicalFact, FactContent, FactId, FactInventory, FactPageMessage, FactRequest,
    ProofAckMessage, ProofDeliveryMessage, SignedFact,
};
pub use features::{Feature, ADVERTISED_FEATURES};
pub use handshake::{
    ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage, DENY_REASON_EVICTED,
};
pub use hub::{
    configuration_digest, HubAdvertisement, HubDiscoveryRequest, HubDiscoveryResponse,
    HubTrickleProfile, HUB_CONFIGURATION_DIGEST_DOMAIN, HUB_DISCOVERY_HARD_MAX_PEERS,
};
pub use keepalive::{PingMessage, PongMessage};
pub use parenting::{
    hub_tree_configuration_digest, HubTreeAttachRejection, HubTreeAttachRequest,
    HubTreeAttachResponse, HubTreeTopologyKind, HUB_TREE_ATTACH_MAX_WIRE_BYTES,
    HUB_TREE_CONFIGURATION_DIGEST_DOMAIN, HUB_TREE_PRIMARY_DEPTH,
};
pub use relay::{
    ClosedRelayControl, ClosedRelayData, ClosedRelayDataDirection, OpaqueRelayPacket, RelayKeyShare,
};
pub use rpc::{
    CapabilitiesUpdateMessage, CapabilityAdvert, RpcRequestMessage, RpcResponseMessage,
    RpcStreamChunkMessage, RpcStreamEndMessage,
};
pub use topology::{
    ClosedRoutedPayload, RoutedApplicationEnvelope, RoutedApplicationError,
    RoutedApplicationLimits, RoutedHop, ShelveMessage, UnshelveMessage,
};

use serde::{Deserialize, Serialize};

/// The exact largest frame the WebRTC receive callback can deliver. Semantic
/// anti-entropy uses this existing protocol boundary, not an item count.
pub(crate) const RECEIVE_FRAME_BYTES: usize = relay::CLOSED_RELAY_WEBRTC_CALLBACK_BYTES as usize;

/// Exactly how many bytes `value`'s compact JSON encoding occupies, counted
/// without building it.
///
/// **Why counting is not the same as encoding and measuring.** A retained buffer
/// has to be funded before it exists, or the acquisition it is supposed to be
/// gated by happens after the allocation it was gating — and every refusal path
/// pays for a buffer it then throws away. Counting first makes the refusal free:
/// under pressure, a stale session, or a closed gateway, nothing was built.
///
/// The count is exact rather than an upper bound. It is produced by the same
/// serializer, over the same borrowed value, that
/// [`encode_json_exact`] then runs — so a claim taken for this number funds
/// precisely the buffer that follows, with nothing rounded up to be safe.
///
/// `None` for a value that will not serialize, and for one whose encoding would
/// not fit in a `usize`. Both are refusals rather than panics: this counts
/// application- and peer-supplied values.
///
/// **Private, and generic only inside this module.** "Counting is free" is a
/// claim about the `Serialize` impl being walked, not about this writer: a
/// hand-written impl may allocate, or do arbitrary work, while it writes. The
/// two shapes below are derived over crate-owned types, so the property is
/// checkable by reading them. Exposing the generic form would let a future
/// caller pass a type nobody checked and escape the guarantee silently, so
/// callers reach it through the concrete wrappers instead.
fn encoded_json_len<T>(value: &T) -> Option<usize>
where
    T: Serialize + ?Sized,
{
    struct CountingWriter(usize);

    impl std::io::Write for CountingWriter {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0 = self.0.checked_add(buf.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "encoded length exceeds the addressable range",
                )
            })?;
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut counter = CountingWriter(0);
    serde_json::to_writer(&mut counter, value).ok()?;
    Some(counter.0)
}

/// Encode `value` into one allocation of exactly `len` bytes.
///
/// One allocation and no growth: the buffer is created at the counted size, so
/// there is no doubling as it fills and no second buffer when it is boxed. That
/// is what makes "the claim funds this allocation" a statement about a single
/// object rather than about a peak.
///
/// `None` if the encoding does not come out at exactly `len`. A mismatch would
/// mean the value changed between counting and encoding, and installing a buffer
/// of one size under a lease taken for another is the defect this whole pattern
/// exists to prevent — so it is refused rather than reconciled.
///
/// Private for the same reason as [`encoded_json_len`], and it must stay paired
/// with it: the two have to walk the same impl for the count to describe the
/// buffer.
fn encode_json_exact<T>(value: &T, len: usize) -> Option<Box<[u8]>>
where
    T: Serialize + ?Sized,
{
    let mut buffer = Vec::with_capacity(len);
    serde_json::to_writer(&mut buffer, value).ok()?;
    (buffer.len() == len).then(|| buffer.into_boxed_slice())
}

/// Count the exact compact JSON bytes of one authenticated departure receipt.
///
/// The count walks the same protocol-owned value that is later encoded, so a
/// provider claim can fund the receipt buffer without a guessed multiplier.
pub(crate) fn departure_receipt_json_len(correlation: &DepartureCorrelation) -> Option<usize> {
    let message = MeshMessage::SessionControl(SessionControl::DepartObserved {
        correlation: correlation.clone(),
    });
    encoded_json_len(&message)
}

/// Encode one departure receipt into exactly the counted allocation.
pub(crate) fn encode_departure_receipt_exact(
    correlation: &DepartureCorrelation,
) -> Option<Box<[u8]>> {
    let message = MeshMessage::SessionControl(SessionControl::DepartObserved {
        correlation: correlation.clone(),
    });
    let len = encoded_json_len(&message)?;
    encode_json_exact(&message, len)
}

/// First-stage classification obtained from the small leading JSON tag only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameAdmission {
    Protocol,
    /// A canonical signed fact or bounded fact page. These frames are durable
    /// semantic traffic, not application payload: a later admission seam may
    /// carry them to an authenticated PendingApproval peer without widening
    /// that peer's access to inventory, requests, or realtime application
    /// traffic.
    DurableFact,
    Application,
}

/// What this side owes when a frame of this kind cannot be carried.
///
/// Read from the same bounded leading tag as [`FrameAdmission`], and read there
/// for the same reason: the path that most needs the answer is the one where the
/// frame was *never decoded*. A frame the resource owner will not fund is
/// refused before its bytes are parsed, so a receiver that wants to distinguish
/// "lost one datagram" from "stranded a caller" cannot ask the decoded message —
/// asking it would mean parsing exactly the payload the refusal exists to avoid
/// parsing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FailurePolicy {
    /// Dropping this frame settles nothing and strands nobody. Nothing local is
    /// waiting on it, and the sender's contract for it is best-effort, so the
    /// loss is the whole of the damage and the session carries on.
    DropFrame,
    /// This frame is the completion something local is waiting for, or is
    /// itself a delivery contract. Dropping it leaves that waiter with nothing
    /// else coming — the peer has already sent its one answer — so the session
    /// that could not carry it ends, and the ending is what resolves the waiter.
    EndSession,
}

/// A frame's admission phase and its failure policy, both from the leading tag.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ClassifiedFrame {
    pub(crate) admission: FrameAdmission,
    pub(crate) on_failure: FailurePolicy,
}

/// Parse only the canonical leading `kind` envelope emitted by this protocol.
///
/// Mixed-version support is intentionally absent. A peer that reorders the tag
/// behind attacker-controlled payload is malformed rather than making the
/// classifier scan or deserialize that payload before admission.
///
/// **The failure policy defaults to [`FailurePolicy::EndSession`]**, including
/// for a kind that is in the closed set but not named below and for one that is
/// not in it at all. That is the fail-closed direction here: ending a session
/// this side could not serve is the existing behaviour of every refusal site, so
/// an unnamed kind keeps it, and only a kind proved to strand nobody is
/// downgraded. A default of `DropFrame` would silently make some future
/// completion-bearing variant lose its caller.
pub(crate) fn classify_frame(bytes: &[u8]) -> Option<ClassifiedFrame> {
    const PREFIX: &[u8] = br#"{"kind":""#;
    const MAX_KIND_BYTES: usize = 32;
    let rest = bytes.strip_prefix(PREFIX)?;
    let end = rest
        .iter()
        .take(MAX_KIND_BYTES + 1)
        .position(|byte| *byte == b'"')?;
    if end > MAX_KIND_BYTES {
        return None;
    }
    let kind = std::str::from_utf8(&rest[..end]).ok()?;
    Some(match kind {
        // The four pre-admission frames. Their policy is never read: they are
        // handled before any session exists, so there is none to end. Named
        // `EndSession` anyway rather than given a third variant meaning
        // "inapplicable", which would be a value every consumer had to handle
        // and no consumer could act on.
        "hello" | "auth_response" | "approve" | "deny" => ClassifiedFrame {
            admission: FrameAdmission::Protocol,
            on_failure: FailurePolicy::EndSession,
        },
        // Facts and exact proof delivery/receipt are the only non-handshake
        // frames with a durable semantic identity. Keep this exact set distinct from every
        // inventory/request/application kind; those remain Application
        // and retain their existing failure policies below.
        "fact" | "fact_page" | "proof_delivery" | "proof_ack" => ClassifiedFrame {
            admission: FrameAdmission::DurableFact,
            on_failure: FailurePolicy::EndSession,
        },
        // Inventories and requests carry only exact context plus identifiers.
        // They are non-authoritative coordination traffic and must not receive
        // the durable-fact admission reserved for signed bodies.
        "fact_inventory" | "fact_request" => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::EndSession,
        },
        // The one best-effort application delivery. A plain `Channel` frame
        // carries no sequence, is acknowledged by nobody, and resolves no local
        // wait: `MeshMessage::Channel` is delivered to whatever subscribers
        // exist and forgotten. Its acknowledged counterpart is `ChannelSeq`,
        // which is *not* named here — a sender retains that one until it is
        // acked, so losing it silently is a hole in the contract this side
        // publishes.
        //
        // This is the kind a peer can make expensive at will, and so the one a
        // peer could otherwise use to end a session on demand by sending
        // payload the owner will not fund. Backpressure is not a reason to
        // destroy a session that is working.
        "channel" => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::DropFrame,
        },
        // Routed application envelopes carry their own authenticated origin
        // and bounded hop chain. They are still application traffic: the
        // current authenticated carrier must be admitted before decoding or
        // forwarding one.
        "routed_application"
        | "hub_advertisement"
        | "hub_discovery_request"
        | "hub_discovery_response"
        | "hub_tree_attach_request"
        | "hub_tree_attach_response" => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::EndSession,
        },
        _ => ClassifiedFrame {
            admission: FrameAdmission::Application,
            on_failure: FailurePolicy::EndSession,
        },
    })
}

/// Authenticated control for the exact Peer Session carrying it.
///
/// **Not application payload, not a durable fact, and not signaling.** It is the
/// narrow control an endpoint may exercise over the session it is already
/// speaking on.
///
/// # Why it carries no target
///
/// There is no Device ID field, and its absence is the security property rather
/// than an economy. The session defines its own two endpoints, so every variant
/// can affect only the connector that carried it. A target field would
/// immediately be a way for one authenticated peer to name a *third* device's
/// session — the same third-party naming that makes an unauthenticated carrier
/// hint untrustworthy, reintroduced on the one path that is trusted.
///
/// # What a receiver may do with it
///
/// `Depart` may retire the exact session that carried it. Renegotiation controls
/// may mutate only that same connector, after application admission and the
/// connector's fixed offerer/answerer role are re-proved. A frame that arrives
/// on a channel which has since been retired affects nothing; it cannot be
/// redirected through a Device ID lookup to a successor.
///
/// A deliberate departure has exactly one correlated receipt:
/// [`SessionControl::DepartObserved`]. There is no retry, timer, or grace
/// period. If either control is lost, ordinary connector closure and lifecycle
/// cancellation resolve the departure; no alternate acknowledgement framework
/// is introduced.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum SessionControl {
    /// This endpoint is leaving deliberately: a graceful network leave, a
    /// network removal, or a daemon shutdown. **Not** sent by a reconnect,
    /// which keeps its session and application state while the transport
    /// underneath it recovers or is replaced.
    Depart {
        /// Opaque bounded receipt correlation. It is scoped to this exact
        /// authenticated session and carries no target identity.
        correlation: DepartureCorrelation,
    },
    /// Receipt for a matching `Depart` on this exact authenticated session.
    DepartObserved { correlation: DepartureCorrelation },
    /// The answerer has a locally authorized track-set change. It cannot create
    /// an offer without glare, so it asks this channel's fixed offerer to make
    /// the one in-band offer. The exact authenticated connector carrying the
    /// frame is the correlation and target.
    RenegotiateRequest,
    /// SDP created by this channel's fixed offerer for connector-local media
    /// changes. This is authenticated application control, not carrier
    /// signaling, and may be applied only to the exact answerer connector that
    /// carried it.
    RenegotiateOffer { sdp: String },
    /// The exact answerer connector's reply to [`Self::RenegotiateOffer`].
    /// Only the matching fixed offerer connector may apply it, and only while
    /// that connector is awaiting an answer.
    RenegotiateAnswer { sdp: String },
}

/// Tagged union of every wire frame the mesh transport carries.
///
/// The set is closed. There is no catch-all variant and no
/// `serde(other)`, so a frame whose `kind` is not one of these fails
/// to deserialize and is refused before any handler sees it. That is
/// the point rather than an omission: tolerating a kind this build
/// does not implement is mixed-version operation, which this protocol
/// no longer offers. Frames are discrete, so refusing one costs
/// nothing but that frame.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
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
    /// Session-local advisory hub information. The carrier session supplies
    /// authenticity; this is never forwarded or applied as configuration.
    HubAdvertisement(HubAdvertisement),
    /// Bounded unicast query for other peer identities known by one configured
    /// hub. This is advisory application traffic, never a routing authority.
    HubDiscoveryRequest(HubDiscoveryRequest),
    /// Bounded unicast response to [`MeshMessage::HubDiscoveryRequest`].
    HubDiscoveryResponse(HubDiscoveryResponse),
    /// Direct shallow hub-tree relation request. It is advisory application
    /// traffic and does not transfer authority or an address.
    HubTreeAttachRequest(HubTreeAttachRequest),
    /// Direct shallow hub-tree relation result bound to one request.
    HubTreeAttachResponse(HubTreeAttachResponse),
    /// Authenticated exact-session control. See [`SessionControl`] for why it
    /// has no target field and what a receiver may do with it.
    SessionControl(SessionControl),
    /// Exact Closed relay route control. Every variant carries its complete
    /// context, three-party identity, and session binding.
    ClosedRelayControl(ClosedRelayControl),
    /// Opaque ciphertext for one exact Closed relay route.
    ClosedRelayData(ClosedRelayData),
    /// Signed, context-bound application traffic carried across a bounded
    /// topology-selected hop chain.
    RoutedApplication(RoutedApplicationEnvelope),
    RpcRequest(RpcRequestMessage),
    RpcResponse(RpcResponseMessage),
    RpcStreamChunk(RpcStreamChunkMessage),
    RpcStreamEnd(RpcStreamEndMessage),

    // -- closed-network semantic facts --
    /// One independently verifiable canonical V4 authority fact.
    Fact(SignedFact),
    /// A bounded exact-context page of canonical V4 authority facts.
    FactPage(FactPageMessage),
    /// Non-authoritative exact-context inventory of known FactIds.
    FactInventory(FactInventory),
    /// Non-authoritative exact-context request for signed facts by FactId.
    FactRequest(FactRequest),
    /// Exact, durable stand-down proof. Receipt is acknowledged only after the
    /// signed facts are durably admitted and canonically project the target.
    ProofDelivery(ProofDeliveryMessage),
    /// Verified receipt for one exact proof delivery identity.
    ProofAck(ProofAckMessage),

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

    // -- reliable channel delivery --
    /// A channel frame under the acknowledged-delivery contract: one
    /// entry of the sender's per-session reliable stream. `stream` is
    /// minted once per promoted session (a fresh session = a fresh
    /// stream) so the receiver can tell a retransmit from a reset; `seq`
    /// is strictly increasing within a stream. Receivers deliver exactly
    /// once (dropping seqs at or below their high-water mark), then
    /// acknowledge cumulatively with [`Self::ChannelAck`]. Senders retain
    /// each entry for the life of the session that queued it, until it is
    /// acked or that session ends. See `engine::reliable`.
    ChannelSeq {
        stream: u64,
        seq: u64,
        channel: String,
        payload: serde_json::Value,
    },
    /// Cumulative acknowledgement for [`Self::ChannelSeq`]: every entry
    /// of `stream` with `seq <= up_to` has been delivered to the
    /// receiver's channel router.
    ChannelAck {
        stream: u64,
        up_to: u64,
    },
}

/// [`MeshMessage::ChannelSeq`] with its two owned fields borrowed.
///
/// **Why a mirror instead of the variant.** Building the variant means owning
/// its fields: a `String` copied out of the caller's channel name, and the
/// payload moved in. A reliable send has to know the frame's exact encoded size
/// *before* it acquires the capacity to retain it, and constructing the variant
/// to find that out allocates on every path — including the ones that then
/// refuse. This serializes from what the caller already has.
///
/// **It must encode byte-identically, and that is pinned by a control.** The
/// tag is written first and then the fields in declaration order, which is
/// exactly what `#[serde(tag = "kind")]` does for the variant, and the tag
/// string is the `rename_all = "snake_case"` form of its name. Anything that
/// changes `ChannelSeq`'s shape without changing this produces frames a peer
/// cannot read, so [`tests::borrowed_channel_seq_encodes_exactly_like_the_variant`]
/// fails on that change rather than shipping it.
#[derive(Serialize)]
pub(crate) struct BorrowedChannelSeq<'a> {
    kind: &'static str,
    stream: u64,
    seq: u64,
    channel: &'a str,
    payload: &'a serde_json::Value,
}

impl<'a> BorrowedChannelSeq<'a> {
    pub(crate) fn new(
        stream: u64,
        seq: u64,
        channel: &'a str,
        payload: &'a serde_json::Value,
    ) -> Self {
        Self {
            kind: "channel_seq",
            stream,
            seq,
            channel,
            payload,
        }
    }

    /// Exactly how many bytes this frame will occupy on the wire, without
    /// building it.
    ///
    /// Free of allocation because of what it walks: four scalars and two
    /// borrows, all with derived or serde_json's own `Serialize`. The payload is
    /// a `Value` the caller already owns, and writing one out neither copies it
    /// nor builds an intermediate.
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        encoded_json_len(self)
    }

    /// The frame, in one allocation of exactly `len` bytes.
    pub(crate) fn encode_exact(&self, len: usize) -> Option<Box<[u8]>> {
        encode_json_exact(self, len)
    }
}

impl CapabilityAdvert {
    /// Exactly how many bytes this advertisement encodes to, without building
    /// it.
    ///
    /// The shape is closed and its `Serialize` is derived, so the walk is a
    /// `Vec<String>`, an `Option<String>` and a `Value` — no impl of anyone's
    /// choosing runs here, which is what makes "counting costs nothing" a
    /// property of this type rather than a hope about the caller's.
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        encoded_json_len(self)
    }

    /// The advertisement, in one allocation of exactly `len` bytes.
    pub(crate) fn encode_exact(&self, len: usize) -> Option<Box<[u8]>> {
        encode_json_exact(self, len)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The borrowed frame is the wire frame, byte for byte.
    ///
    /// This is what lets a reliable send count its size from borrowed fields and
    /// then encode the bytes it actually puts on the wire from the same value.
    /// If the two ever diverge, peers get a frame they cannot read — so the
    /// comparison is over the whole encoding, not over its length, and the
    /// values below exercise the parts most likely to drift: a channel name
    /// needing escapes, and a payload that is a nested tree rather than a scalar.
    #[test]
    fn borrowed_channel_seq_encodes_exactly_like_the_variant() {
        let channel = "chat/\"room\"\n1";
        let payload = serde_json::json!({
            "nested": ["a", 1, true, null],
            "unicode": "ü\u{1F600}",
        });

        let owned = serde_json::to_vec(&MeshMessage::ChannelSeq {
            stream: 9,
            seq: 4_294_967_297,
            channel: channel.to_string(),
            payload: payload.clone(),
        })
        .expect("the owned variant serializes");
        let mirror = BorrowedChannelSeq::new(9, 4_294_967_297, channel, &payload);
        let borrowed = serde_json::to_vec(&mirror).expect("the borrowed mirror serializes");

        assert_eq!(
            String::from_utf8_lossy(&borrowed),
            String::from_utf8_lossy(&owned),
            "the borrowed mirror must produce the exact frame the variant does"
        );
        assert_eq!(
            mirror.encoded_len(),
            Some(owned.len()),
            "counting must agree with encoding, since the claim is taken from the count"
        );
    }

    #[test]
    fn bounded_leading_tag_classifies_without_parsing_application_payload() {
        // Every payload below is unparseable JSON, and every answer is
        // nonetheless exact: the classifier reads the tag and stops. That is
        // the property both fields depend on, since the frame whose policy
        // matters most is the one whose bytes are never decoded.
        assert_eq!(
            classify_frame(br#"{"kind":"hello","payload":[}}"#),
            Some(ClassifiedFrame {
                admission: FrameAdmission::Protocol,
                on_failure: FailurePolicy::EndSession,
            })
        );
        assert_eq!(
            classify_frame(br#"{"kind":"channel","payload":[}}"#),
            Some(ClassifiedFrame {
                admission: FrameAdmission::Application,
                on_failure: FailurePolicy::DropFrame,
            })
        );
        assert_eq!(
            classify_frame(br#"{"kind":"routed_application","payload":[}}"#),
            Some(ClassifiedFrame {
                admission: FrameAdmission::Application,
                on_failure: FailurePolicy::EndSession,
            })
        );
        for fact_kind in ["fact", "fact_page", "proof_delivery", "proof_ack"] {
            assert_eq!(
                classify_frame(format!(r#"{{"kind":"{fact_kind}","payload":[}}"#).as_bytes()),
                Some(ClassifiedFrame {
                    admission: FrameAdmission::DurableFact,
                    on_failure: FailurePolicy::EndSession,
                }),
                "only canonical fact kinds receive the durable-fact class"
            );
        }
        for coordination_kind in ["fact_inventory", "fact_request"] {
            assert_eq!(
                classify_frame(
                    format!(r#"{{"kind":"{coordination_kind}","payload":[}}"#).as_bytes()
                ),
                Some(ClassifiedFrame {
                    admission: FrameAdmission::Application,
                    on_failure: FailurePolicy::EndSession,
                }),
                "fact coordination is not durable-fact admission"
            );
        }
        assert_eq!(classify_frame(br#"{"payload":[],"kind":"hello"}"#), None);
    }

    #[test]
    fn durable_fact_class_does_not_widen_to_inventory_or_application_frames() {
        let classify = |kind: &str| {
            classify_frame(format!(r#"{{"kind":"{kind}","payload":[}}"#).as_bytes())
                .expect("canonical leading tag classifies")
        };

        for kind in [
            "fact_inventory",
            "fact_request",
            "rpc_request",
            "rpc_response",
            "rpc_stream_chunk",
            "rpc_stream_end",
            "channel_seq",
            "channel_ack",
            "routed_application",
        ] {
            assert_eq!(
                classify(kind).admission,
                FrameAdmission::Application,
                "{kind} remains application admission"
            );
            assert_eq!(
                classify(kind).on_failure,
                FailurePolicy::EndSession,
                "{kind} retains its completion-bearing failure policy"
            );
        }
        assert_eq!(classify("channel").admission, FrameAdmission::Application);
        assert_eq!(classify("channel").on_failure, FailurePolicy::DropFrame);
        for kind in ["hello", "auth_response", "approve", "deny"] {
            assert_eq!(classify(kind).admission, FrameAdmission::Protocol);
        }
    }

    #[test]
    fn routed_application_round_trips_as_application_and_rejects_unknown_fields() {
        let origin_key = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
        let destination_key = ed25519_dalek::SigningKey::from_bytes(&[22; 32]);
        let origin = crate::semantic::DeviceId::from_public_key_bytes(
            *origin_key.verifying_key().as_bytes(),
        )
        .expect("origin device id");
        let destination = crate::semantic::DeviceId::from_public_key_bytes(
            *destination_key.verifying_key().as_bytes(),
        )
        .expect("destination device id");
        let envelope = RoutedApplicationEnvelope::new(
            crate::semantic::MeshContextId::from_bytes([23; 32]),
            origin,
            destination,
            [24; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "protocol-test".into(),
                payload: serde_json::json!({"probe": true}),
            },
            &origin_key,
        )
        .expect("routed envelope");
        envelope.verify().expect("origin envelope verifies");

        let message = MeshMessage::RoutedApplication(envelope.clone());
        let encoded = serde_json::to_vec(&message).expect("routed message serializes");
        assert!(String::from_utf8_lossy(&encoded).contains(r#""kind":"routed_application""#));
        let decoded: MeshMessage =
            serde_json::from_slice(&encoded).expect("routed message decodes");
        let MeshMessage::RoutedApplication(decoded) = decoded else {
            panic!("decoded message changed routed variant");
        };
        assert_eq!(decoded, envelope);
        decoded.verify().expect("decoded envelope verifies");

        let mut unknown = serde_json::to_value(MeshMessage::RoutedApplication(envelope)).unwrap();
        unknown["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeshMessage>(unknown).is_err());
    }

    /// Only the best-effort delivery is droppable, and the acknowledged one is
    /// not.
    ///
    /// The discrimination the policy exists for, at the level it is decided.
    /// `channel` and `channel_seq` share a prefix, a shape and a payload field;
    /// they differ in that a `ChannelSeq` sender retains its frame until this
    /// side acknowledges it. A policy that read the shape rather than the tag —
    /// or that matched on a prefix — would give both the same answer, and one of
    /// those answers is a silent hole in an acknowledged-delivery contract.
    #[test]
    fn only_the_best_effort_channel_frame_is_droppable() {
        let policy = |raw: &str| {
            classify_frame(raw.as_bytes())
                .expect("a canonical envelope classifies")
                .on_failure
        };
        assert_eq!(
            policy(r#"{"kind":"channel","x":1}"#),
            FailurePolicy::DropFrame
        );
        for completion_bearing in [
            r#"{"kind":"channel_seq","x":1}"#,
            r#"{"kind":"channel_ack","x":1}"#,
            r#"{"kind":"rpc_response","x":1}"#,
            r#"{"kind":"rpc_stream_chunk","x":1}"#,
            r#"{"kind":"rpc_stream_end","x":1}"#,
        ] {
            assert_eq!(
                policy(completion_bearing),
                FailurePolicy::EndSession,
                "a frame something local is waiting on is never silently lost: \
                 {completion_bearing}"
            );
        }
        // And the fail-closed default: a kind this build does not implement is
        // not a licence to drop frames quietly.
        assert_eq!(
            policy(r#"{"kind":"definitely_not_a_real_kind","x":1}"#),
            FailurePolicy::EndSession
        );
    }

    #[test]
    fn unknown_kind_is_refused() {
        let raw = r#"{"kind":"definitely_not_a_real_kind","whatever":1}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw).is_err());
    }

    #[test]
    fn mesh_message_rejects_unknown_fields_at_the_outer_wire_layer() {
        let raw = r#"{"kind":"channel","channel":"control","payload":null,"legacy":true}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw).is_err());
    }

    #[test]
    fn hello_round_trips() {
        let msg = MeshMessage::Hello(HelloMessage {
            protocol: crate::PROTOCOL_VERSION,
            device_id: "peer1".into(),
            label: "Laptop".into(),
            nonce: "noncexyz".into(),
            verification_code: "abc123".into(),
            features: vec![Feature::ENDPOINT_AUTH_V1.into()],
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

    #[test]
    fn canonical_fact_page_round_trips() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[13; 32]);
        let device =
            crate::semantic::DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
                .unwrap();
        let context = crate::semantic::MeshContextId::from_bytes([14; 32]);
        let fact = crate::semantic::SignedFact::sign(
            crate::semantic::FactContent::new(
                crate::semantic::FactDomain::Governance,
                context,
                crate::semantic::FactBody::RoleRevoke {
                    target: device.clone(),
                },
                device,
                Vec::new(),
            ),
            &key,
        )
        .unwrap();
        let page = FactPageMessage::new(context, vec![fact], None, true).unwrap();
        let msg = MeshMessage::FactPage(page);
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""kind":"fact_page""#));
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::FactPage(page) => {
                assert_eq!(page.context_id, context);
                assert_eq!(page.facts.len(), 1);
                assert!(page.complete);
            }
            _ => panic!("did not round-trip as FactPage"),
        }
    }

    #[test]
    fn durable_fact_round_trips_and_rejects_unknown_wire_fields() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[11; 32]);
        let device =
            crate::semantic::DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
                .unwrap();
        let context = crate::semantic::MeshContextId::from_bytes([12; 32]);
        let content = crate::semantic::FactContent::new(
            crate::semantic::FactDomain::Governance,
            context,
            crate::semantic::FactBody::RoleRevoke {
                target: device.clone(),
            },
            device.clone(),
            Vec::new(),
        );
        let fact = crate::semantic::SignedFact::sign(content, &key).unwrap();
        let message = MeshMessage::Fact(fact.clone());

        let encoded = serde_json::to_vec(&message).unwrap();
        let decoded: MeshMessage = serde_json::from_slice(&encoded).unwrap();
        assert!(matches!(decoded, MeshMessage::Fact(actual) if actual == fact));

        let mut outer_wire = serde_json::to_value(&message).unwrap();
        outer_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeshMessage>(outer_wire).is_err());

        let mut nested_wire = serde_json::to_value(&message).unwrap();
        nested_wire["content"]["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<MeshMessage>(nested_wire).is_err());

        let unsupported_body = serde_json::json!({
            "kind": "future_semantic_kind",
        });
        assert!(
            serde_json::from_value::<crate::semantic::FactBody>(unsupported_body).is_err(),
            "unsupported semantic kind must be refused by semantic decoding"
        );
    }

    #[test]
    fn fact_inventory_and_request_canonicalize_ids_and_preserve_context() {
        let context = crate::semantic::MeshContextId::from_bytes([7; 32]);
        let first = crate::semantic::FactId::from_bytes([1; 32]);
        let second = crate::semantic::FactId::from_bytes([2; 32]);
        let inventory = FactInventory::new(context, [second, first, second]);
        assert_eq!(inventory.context_id(), context);
        assert_eq!(inventory.fact_ids(), &[first, second]);
        let request = FactRequest::new(context, [second, first, second]);
        assert_eq!(request.context_id(), context);
        assert_eq!(request.fact_ids(), &[first, second]);

        for message in [
            MeshMessage::FactInventory(inventory),
            MeshMessage::FactRequest(request),
        ] {
            let encoded = serde_json::to_string(&message).expect("fact coordination serializes");
            let decoded: MeshMessage =
                serde_json::from_str(&encoded).expect("fact coordination round-trips");
            match (message, decoded) {
                (MeshMessage::FactInventory(expected), MeshMessage::FactInventory(actual)) => {
                    assert_eq!(actual, expected);
                }
                (MeshMessage::FactRequest(expected), MeshMessage::FactRequest(actual)) => {
                    assert_eq!(actual, expected);
                }
                _ => panic!("fact coordination changed wire variant"),
            }
        }
    }

    #[test]
    fn fact_coordination_rejects_noncanonical_id_order_or_duplicates() {
        let context = crate::semantic::MeshContextId::from_bytes([8; 32]);
        let first = crate::semantic::FactId::from_bytes([1; 32]);
        let second = crate::semantic::FactId::from_bytes([2; 32]);
        let context = serde_json::to_string(&context).unwrap();
        let first = serde_json::to_string(&first).unwrap();
        let second = serde_json::to_string(&second).unwrap();
        for kind in ["fact_inventory", "fact_request"] {
            let raw = format!(
                r#"{{"kind":"{kind}","context_id":{context},"fact_ids":[{second},{first}]}}"#
            );
            assert!(serde_json::from_str::<MeshMessage>(&raw).is_err());
            let raw = format!(
                r#"{{"kind":"{kind}","context_id":{context},"fact_ids":[{first},{first}]}}"#
            );
            assert!(serde_json::from_str::<MeshMessage>(&raw).is_err());
        }
    }

    #[test]
    fn authenticated_departure_control_round_trips_with_bounded_correlation() {
        let correlation = DepartureCorrelation::from_bytes([0x11; DEPARTURE_CORRELATION_BYTES]);
        let message = MeshMessage::SessionControl(SessionControl::Depart {
            correlation: correlation.clone(),
        });
        let encoded = serde_json::to_string(&message).expect("departure serializes");
        assert!(encoded.contains(r#""op":"depart""#));
        assert!(!encoded.contains("device_id"));
        let decoded: MeshMessage = serde_json::from_str(&encoded).expect("departure decodes");
        assert!(matches!(
            decoded,
            MeshMessage::SessionControl(SessionControl::Depart { correlation: value })
                if value == correlation
        ));
        let observed = MeshMessage::SessionControl(SessionControl::DepartObserved {
            correlation: correlation.clone(),
        });
        let observed_encoded = serde_json::to_string(&observed).expect("receipt serializes");
        assert!(observed_encoded.contains(r#""op":"depart_observed""#));
        let observed_decoded: MeshMessage =
            serde_json::from_str(&observed_encoded).expect("receipt decodes");
        assert!(matches!(
            observed_decoded,
            MeshMessage::SessionControl(SessionControl::DepartObserved { correlation: value })
                if value == correlation
        ));
        let exact_len = departure_receipt_json_len(&correlation).expect("receipt is countable");
        let exact = encode_departure_receipt_exact(&correlation).expect("receipt is encodable");
        assert_eq!(
            exact.len(),
            exact_len,
            "the receipt uses the exact allocation that was counted"
        );
        let exact_decoded: MeshMessage =
            serde_json::from_slice(&exact).expect("exactly encoded receipt decodes");
        assert!(matches!(
            exact_decoded,
            MeshMessage::SessionControl(SessionControl::DepartObserved { correlation: value })
                if value == correlation
        ));
        let too_long = "a".repeat(DEPARTURE_CORRELATION_WIRE_CHARS + 1);
        assert!(serde_json::from_str::<MeshMessage>(&format!(
            r#"{{"kind":"session_control","op":"depart","correlation":"{too_long}"}}"#
        ))
        .is_err());
        let with_unknown =
            encoded.replacen(r#""correlation""#, r#""legacy":true,"correlation""#, 1);
        assert!(serde_json::from_str::<MeshMessage>(&with_unknown).is_err());
    }

    #[test]
    fn authenticated_renegotiation_control_round_trips_on_the_session_wire() {
        let message = MeshMessage::SessionControl(SessionControl::RenegotiateOffer {
            sdp: "v=0\r\na=ice-ufrag:exact-channel\r\n".to_string(),
        });
        let encoded = serde_json::to_string(&message).expect("session control serializes");
        assert!(encoded.contains(r#""kind":"session_control""#));
        assert!(encoded.contains(r#""op":"renegotiate_offer""#));
        let decoded: MeshMessage = serde_json::from_str(&encoded).expect("session control decodes");
        assert!(matches!(
            decoded,
            MeshMessage::SessionControl(SessionControl::RenegotiateOffer { sdp })
                if sdp.contains("exact-channel")
        ));
    }

    #[test]
    fn a_fact_kind_this_build_implements_and_a_future_one_is_refused() {
        // The removed unbounded bundle is refused before any durable handler.
        let raw = r#"{"kind":"fact_bundle","facts":[]}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw).is_err());
        // The inverse fails closed: there is no mixed-version live fallback.
        let raw_future = r#"{"kind":"network_state_some_future_thing","whatever":1}"#;
        assert!(serde_json::from_str::<MeshMessage>(raw_future).is_err());
    }
}
