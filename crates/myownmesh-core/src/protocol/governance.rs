//! Wire frames for closed-network governance + roster gossip.
//!
//! Three families share this module:
//!
//!   1. **Network-state advertisement** ([`NetworkStateBroadcast`])
//!      — emitted on every ACTIVE transition so each peer can detect
//!      whether the other has news. Carries the network's current
//!      `kind`, the transition log length (so a stale receiver
//!      knows it needs an update), and the roster Merkle root.
//!
//!   2. **Proposal / ack / split** ([`NetworkStateProposeMessage`],
//!      [`NetworkStateAckMessage`], [`NetworkStateSplitMessage`])
//!      — the in-flight half of the governance flow. Each is
//!      individually signed under [`crate::SIGN_DOMAIN_TAG_STATE`].
//!      A receiver drops any frame whose signer set + variant
//!      doesn't satisfy the quorum table for its operation.
//!
//!   3. **Roster gossip** ([`RosterSummaryMessage`],
//!      [`RosterRequestMessage`], [`RosterEntriesMessage`]) — Merkle
//!      summary + diff fetch. v1 keeps the diff coarse: when roots
//!      disagree, the requester asks for the *full* roster (one
//!      `RosterRequest { include_all: true }` → one `RosterEntries`
//!      with everything). A tree-walk variant is wire-compatible with
//!      this shape and can ship in a later release without changing
//!      the message kind.
//!
//! All variants are gated by the `network_state_v1` feature flag;
//! older peers won't advertise it and senders skip these kinds
//! against them.

use serde::{Deserialize, Serialize};

use crate::network_state::{NetworkKind, Role, Transition, TransitionVariant};
use crate::roster::AuthorizedPeer;

/// "This is what I think the network looks like." Emitted on every
/// per-peer ACTIVE transition so the two sides can quickly notice
/// they're out of sync and reconcile.
///
/// The governance-kind field is named `network_kind` on the wire,
/// not `kind`, to avoid colliding with the outer
/// `#[serde(tag = "kind")]` MeshMessage discriminator — without the
/// rename, both would write the literal key `"kind"` and the
/// deserializer would reject the duplicate.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateBroadcast {
    /// Sender's view of the governance kind.
    #[serde(rename = "network_kind")]
    pub kind: NetworkKind,
    /// Sender's transition-log length. A receiver whose own log is
    /// shorter knows it's behind and requests the missing transitions
    /// via the catch-up path.
    pub transitions_count: u32,
    /// Sender's **member**-log length. The member tier is union-merged, not
    /// strict-prefix, so its length alone isn't a total order — but a receiver
    /// whose own member log is shorter knows it's missing entries and pulls.
    /// `#[serde(default)]` so an older peer (which omits it, → 0) never makes us
    /// think we're behind on a tier it doesn't track.
    #[serde(default)]
    pub member_log_count: u32,
    /// Base32-lowercase Merkle root over the sender's current
    /// roster. Receivers compare to their own; equal roots = caught
    /// up, unequal = trigger a `RosterRequest`.
    pub roster_root: String,
}

/// "I propose this transition." Signed by the proposer; one of the
/// signatures in the eventual ratified [`crate::Transition`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateProposeMessage {
    /// Random per-proposal id. Receivers track by this so an ack
    /// targeting an unknown id is dropped.
    pub proposal_id: String,
    /// What the proposer wants to do.
    pub variant: TransitionVariant,
    /// Pubkey of the device floating the proposal.
    pub proposer: String,
    /// Wall-clock seconds at issue time. Receivers track this against
    /// `STATE_PROPOSAL_TIMEOUT_S` to know when the proposer becomes
    /// eligible to fire a split fallback.
    pub created_at: u64,
    /// Proposer's signature over the canonical payload bytes (see
    /// [`crate::network_state::transition_payload`]). Receivers
    /// verify before recording the proposal.
    pub signature: String,
}

/// "I sign / deny your proposal." The proposer's view assembles all
/// the acks against `proposal_id` and decides when the quorum is
/// satisfied (or, on a single deny, gives up).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateAckMessage {
    pub proposal_id: String,
    pub signer: String,
    pub decision: AckDecision,
    /// Wall-clock seconds at decision time. Informational.
    pub at: u64,
    /// On `decision = "sign"`, the signer's ed25519 over the original
    /// transition payload (the same bytes the proposer signed). On
    /// `decision = "deny"`, a signature over the deny statement so
    /// a denier can't have their deny forged.
    pub signature: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AckDecision {
    Sign,
    Deny,
}

/// "Stuck close — I'm spawning a derived closed network with the
/// signers I have." Sent by the proposer of the original close once
/// `STATE_PROPOSAL_TIMEOUT_S` has elapsed and the unanimous quorum
/// hasn't been met. Carries the resulting `Split` transition fully
/// signed (proposer-as-would-be-owner is the single signer; the
/// co-signers come along automatically as members of the new
/// network).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStateSplitMessage {
    /// Id of the parent proposal that's being split out of. Carried
    /// so receivers can correlate with the proposal they've been
    /// tracking and remove it from their pending set.
    pub parent_proposal_id: String,
    /// Deterministically derived from the parent + signer set; see
    /// [`crate::network_state::derive_split_network_id`].
    pub new_network_id: String,
    /// Pubkeys of every member moving into the new closed network
    /// (the proposer + every signer of the parent proposal). The
    /// proposer becomes founder-owner; everyone else lands as
    /// member (and the new network's owner can promote them after).
    pub members: Vec<String>,
    /// Proposer's pubkey. Single-signer for splits per the design.
    pub proposer: String,
    pub at: u64,
    /// Signature over the canonical `Split` transition payload for
    /// the *new* network (binding to `new_network_id`). Verifiers
    /// recompute the payload and check this signature before
    /// recording the split.
    pub signature: String,
}

// ---- roster gossip --------------------------------------------------

/// "My roster Merkle root is X with N entries." Emitted on ACTIVE
/// and after every local roster mutation that completes. Receivers
/// whose own root disagrees issue a `RosterRequestMessage`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterSummaryMessage {
    /// Base32-lowercase Merkle root. Stable across rebuilds when the
    /// roster content matches.
    pub root: String,
    pub count: u32,
    /// Wall-clock seconds of the most recent `approved_at` in the
    /// roster. Tie-breaker for "which side is ahead" when roots
    /// disagree but neither side knows which has the newer state.
    pub last_edit_ts: u64,
}

/// "Send me the entries under this hash." v1 just asks for the full
/// roster (`include_all = true`); a future revision can populate
/// `subtree_hashes` to walk a Merkle tree without changing the
/// frame's kind.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct RosterRequestMessage {
    /// True = send every entry. v1's only valid setting.
    #[serde(default)]
    pub include_all: bool,
    /// Specific subtree hashes the requester is missing. Empty in v1.
    #[serde(default)]
    pub subtree_hashes: Vec<String>,
}

/// "Here are the entries you asked for." Carries one or more
/// authorised-peer records. Receivers merge into their local roster
/// after verifying each entry's authority chain — for v1 (open
/// networks dominant), this means `add_peer_in()` semantics, no
/// signature check; for closed networks, the receiver applies
/// `verify_quorum`-equivalent logic before merging.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterEntriesMessage {
    pub entries: Vec<RosterEntry>,
    /// The network's signed governance log, carried alongside the roster so
    /// **roles converge with membership** — the receiver re-derives who holds
    /// which role (most importantly *who the owner is*) by verifying this log
    /// from genesis ([`crate::network_state::verify_log`]), rather than trusting
    /// a gossiped role tag. The receiver only adopts a log that extends its own,
    /// so a peer can't rewrite a genesis. Empty on an open network (no signed
    /// log) and, via `#[serde(default)]`, absent from an older peer's reply —
    /// which then behaves exactly as before (membership-only gossip).
    #[serde(default)]
    pub transitions: Vec<Transition>,
    /// The network's signed **member** log — per-member admit/remove entries,
    /// each authored by one owner/manager. Carried alongside the governance log
    /// so membership converges by **union-merge** ([`crate::network_state::merge_member_logs`]):
    /// two managers' concurrent (offline) admissions both survive, where the
    /// strict-prefix governance log would fork. `#[serde(default)]`, so an older
    /// peer that doesn't send it just contributes no member entries.
    #[serde(default)]
    pub member_log: Vec<Transition>,
}

/// A single rosterable peer. Mirrors [`AuthorizedPeer`] plus the
/// minimal extra context a receiver needs to apply governance
/// checks — namely, the `role` granter so an authority chain can
/// be reconstructed without the receiver having to ask for the full
/// transition log too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RosterEntry {
    pub device_id: String,
    pub label: String,
    pub approved_at: u64,
    pub role: Role,
    /// Pubkey that authored this entry's most recent change (the
    /// member who added/promoted it). Receivers cross-reference
    /// against the local `NetworkState.roles` to confirm the
    /// granter held the required authority at the moment of grant.
    /// Empty on entries from open networks.
    #[serde(default)]
    pub granted_by: String,
}

impl From<&AuthorizedPeer> for RosterEntry {
    fn from(p: &AuthorizedPeer) -> Self {
        Self {
            device_id: p.device_id.clone(),
            label: p.label.clone(),
            approved_at: p.approved_at,
            role: p.role,
            granted_by: String::new(),
        }
    }
}
