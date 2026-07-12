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
pub mod governance;
pub mod handshake;
pub mod keepalive;
pub mod rpc;
pub mod topology;

pub use features::{Feature, ADVERTISED_FEATURES};
pub use governance::{
    AckDecision, NetworkStateAckMessage, NetworkStateBroadcast, NetworkStateProposeMessage,
    NetworkStateSplitMessage, RosterEntriesMessage, RosterEntry, RosterRequestMessage,
    RosterSummaryMessage,
};
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

    // -- closed-network governance (gated by `network_state_v1`) --
    /// Sender's snapshot of the network's governance state.
    /// Broadcast on ACTIVE; receivers compare against their own to
    /// detect drift.
    NetworkState(NetworkStateBroadcast),
    /// In-flight transition awaiting signatures. The proposer signs
    /// at issue time; co-signers respond with `NetworkStateAck`.
    NetworkStatePropose(NetworkStateProposeMessage),
    /// Sign-or-deny response to a `NetworkStatePropose`.
    NetworkStateAck(NetworkStateAckMessage),
    /// Proposer-initiated split fallback after the consent timeout
    /// expires on a stuck close. Spawns a derived closed network
    /// containing the signers the proposer had so far.
    NetworkStateSplit(NetworkStateSplitMessage),

    // -- roster gossip (gated by `network_state_v1`) --
    /// Merkle-root summary of the sender's roster. Triggers a
    /// `RosterRequest` from receivers whose root disagrees.
    RosterSummary(RosterSummaryMessage),
    /// "Send me the entries I'm missing." Carried alone on a
    /// targeted reply to a `RosterSummary`.
    RosterRequest(RosterRequestMessage),
    /// Roster entries the responder is sharing. Receivers verify
    /// each entry's authority chain before merging.
    RosterEntries(RosterEntriesMessage),

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

    // -- reliable channel delivery (gated by `reliable_channels_v1`) --
    /// A channel frame under the acknowledged-delivery contract: one
    /// entry of the sender's per-peer outbox stream. `stream` is minted
    /// once per outbox lifetime (a fresh daemon run = a fresh stream) so
    /// the receiver can tell a retransmit from a reset; `seq` is
    /// strictly increasing within a stream. Receivers deliver exactly
    /// once (dropping seqs at or below their high-water mark), then
    /// acknowledge cumulatively with [`Self::ChannelAck`]. Senders keep
    /// each entry queued — across session rebuilds — until acked or its
    /// TTL lapses. See `engine::reliable`.
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

    #[test]
    fn network_state_broadcast_round_trips() {
        use crate::network_state::NetworkKind;
        let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
            kind: NetworkKind::Closed,
            transitions_count: 4,
            member_log_count: 2,
            roster_root: "abcdefghij".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::NetworkState(b) => {
                assert_eq!(b.kind, NetworkKind::Closed);
                assert_eq!(b.transitions_count, 4);
                assert_eq!(b.member_log_count, 2);
                assert_eq!(b.roster_root, "abcdefghij");
            }
            _ => panic!("did not round-trip as NetworkState"),
        }
    }

    #[test]
    fn network_state_kind_discriminator_is_snake_case() {
        // Wire-level kind tag must be snake_case so the JS GUI's
        // existing dispatch tables don't need a special case for
        // these. Pinning here so a future #[serde(rename_all)]
        // tweak doesn't silently break interop.
        let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
            kind: crate::network_state::NetworkKind::Open,
            transitions_count: 0,
            member_log_count: 0,
            roster_root: "x".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""kind":"network_state""#));
    }

    #[test]
    fn ack_decision_round_trips() {
        let msg = MeshMessage::NetworkStateAck(NetworkStateAckMessage {
            proposal_id: "prop_x".into(),
            signer: "alice".into(),
            decision: AckDecision::Deny,
            at: 42,
            signature: "sig".into(),
        });
        let s = serde_json::to_string(&msg).unwrap();
        assert!(s.contains(r#""decision":"deny""#));
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        match back {
            MeshMessage::NetworkStateAck(a) => {
                assert_eq!(a.decision, AckDecision::Deny);
                assert_eq!(a.signer, "alice");
            }
            _ => panic!("did not round-trip as NetworkStateAck"),
        }
    }

    #[test]
    fn roster_summary_round_trips() {
        let msg = MeshMessage::RosterSummary(RosterSummaryMessage {
            root: "merkle_root".into(),
            count: 3,
            last_edit_ts: 1700000000,
        });
        let s = serde_json::to_string(&msg).unwrap();
        let back: MeshMessage = serde_json::from_str(&s).unwrap();
        assert!(matches!(back, MeshMessage::RosterSummary(_)));
    }

    #[test]
    fn roster_request_defaults_clean() {
        // include_all + subtree_hashes are #[serde(default)] so an
        // empty request frame parses without per-field nulls. v1
        // peers send `{ "kind": "roster_request" }` literally.
        let raw = r#"{"kind":"roster_request"}"#;
        let msg: MeshMessage = serde_json::from_str(raw).unwrap();
        match msg {
            MeshMessage::RosterRequest(r) => {
                assert!(!r.include_all);
                assert!(r.subtree_hashes.is_empty());
            }
            _ => panic!("did not parse as RosterRequest"),
        }
    }

    #[test]
    fn old_peer_drops_governance_frame_as_unknown() {
        // A v0 peer (no `network_state_v1` flag) receiving one of
        // these frames just sees an Unknown variant — its dispatch
        // loop logs and drops without errors. The sender side gates
        // emission on the peer's advertised features, but receivers
        // belt-and-braces handle the case.
        let raw = r#"{"kind":"network_state_propose","proposal_id":"x","variant":{"kind":"role_grant","target":"a","role":"member"},"proposer":"b","created_at":0,"signature":"s"}"#;
        let msg: MeshMessage = serde_json::from_str(raw).unwrap();
        assert!(matches!(msg, MeshMessage::NetworkStatePropose(_)));
        // And the inverse — a future kind a v1 doesn't know about
        // still hits Unknown.
        let raw_future = r#"{"kind":"network_state_some_future_thing","whatever":1}"#;
        let msg: MeshMessage = serde_json::from_str(raw_future).unwrap();
        assert!(matches!(msg, MeshMessage::Unknown));
    }
}
