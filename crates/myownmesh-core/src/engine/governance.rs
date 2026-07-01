//! Engine half of closed-network governance.
//!
//! Owns the proposal lifecycle:
//!
//!   1. **Propose** — the local device floats a transition. The
//!      engine signs the canonical payload with the local identity,
//!      appends a `Proposal` to the persisted state's pending list,
//!      and broadcasts a `NetworkStatePropose` to every active peer.
//!
//!   2. **Inbound propose** — a peer's signed proposal arrives. The
//!      engine verifies the signature (and rejects the frame if it
//!      fails), then records the proposal in pending. The local
//!      user surfaces it via the GUI's Approvals tab and chooses
//!      sign / deny.
//!
//!   3. **Sign / deny** — the local device authors an
//!      `NetworkStateAck`. Sign signatures accumulate; deny is a
//!      single-shot kill switch. When the accumulated signer set
//!      satisfies the quorum table for the variant (see
//!      [`crate::network_state::verify_quorum`]), the engine
//!      builds the final `Transition`, applies it to the state via
//!      `apply_transition`, persists, and emits an authoritative
//!      `NetworkState` broadcast so peers learn the new shape.
//!
//!   4. **Withdraw / split** — the proposer can withdraw before
//!      ratification or, after `STATE_PROPOSAL_TIMEOUT_S`, fire a
//!      proposer-initiated split that spawns a derived closed
//!      network from the signers it has.
//!
//! All mutations go through here (rather than directly into
//! `NetworkState.governance_state`) so persistence + ack-emission
//! stay co-located with the state mutation that motivates them.

use std::sync::Arc;

use rand::Rng;

use crate::error::{Error, Result};
use crate::events::DropReason;
use crate::network_state::{self, NetworkKind, Proposal, Role, Transition, TransitionVariant};
use crate::protocol::{
    AckDecision, MeshMessage, NetworkStateAckMessage, NetworkStateBroadcast,
    NetworkStateProposeMessage, NetworkStateSplitMessage, RosterEntriesMessage, RosterEntry,
    RosterRequestMessage, RosterSummaryMessage,
};

use super::connection::PeerStatus;
use super::state::{NetworkCmd, NetworkState as EngineState};

// ---- helpers --------------------------------------------------------

fn now_unix() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn new_proposal_id() -> String {
    // 16 hex chars of entropy ≈ 64 bits. Collisions across a single
    // network would require ~2^32 proposals, which the engine
    // doesn't admit; sufficient.
    let suffix: u64 = rand::thread_rng().gen();
    format!("prop_{suffix:016x}")
}

/// Strip the display suffix (`-XXXXX`) from a Device ID. The
/// governance store keys everything on the bare pubkey.
fn pk(device_id: &str) -> String {
    crate::signing::pubkey_part(device_id).to_string()
}

/// Iterate active peers — those whose data channel is ACTIVE +
/// authenticated. Used to broadcast governance frames.
fn active_peer_ids(state: &Arc<EngineState>) -> Vec<String> {
    state
        .peers
        .iter()
        .filter_map(|entry| {
            let peer = entry.value();
            let data = peer.state.read();
            if matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) && data.authenticated
            {
                Some(entry.key().clone())
            } else {
                None
            }
        })
        .collect()
}

async fn broadcast(state: &Arc<EngineState>, msg: MeshMessage) {
    for peer_id in active_peer_ids(state) {
        // Best-effort: a failure to send to one peer doesn't block
        // delivery to the others. The next peer's `NetworkState`
        // broadcast on its own ACTIVE transition will catch them up.
        if let Err(e) = super::send_to_peer(state, &peer_id, &msg).await {
            tracing::debug!(peer = %peer_id, err = %e, "governance broadcast send failed");
        }
    }
}

fn diag(state: &Arc<EngineState>, level: crate::events::DiagLevel, msg: impl Into<String>) {
    state.log_diag(level, "governance", msg);
}

// ---- snapshot -------------------------------------------------------

/// Read-only copy of the current governance state — kind, roles,
/// transitions, pending proposals, splits. Used by the control
/// protocol to surface live state to clients.
pub fn snapshot(state: &Arc<EngineState>) -> network_state::NetworkState {
    state.governance_state.read().clone()
}

// ---- local proposals ------------------------------------------------

/// Float a new signed transition from this device. Signs with the
/// local identity, persists to pending, broadcasts to peers.
pub async fn propose(
    state: &Arc<EngineState>,
    variant: TransitionVariant,
    mfa_code: Option<&str>,
) -> Result<String> {
    // Idempotency short-circuit — placed *before* the custody gate, because
    // re-asserting an already-applied grant authorizes nothing and must never
    // spend an MFA code. A `RoleGrant` whose target already sits at that exact
    // role in the signed state is a no-op: signing it again would append a
    // redundant transition and grow the log on every re-assertion. (The owner
    // re-signs its fleet members on each startup to keep the signed roster
    // authoritative; with closed-network membership now riding the log, that
    // re-assertion has to be free.) We check the *explicit* role map, not
    // `role_of` — an absent target reads as the default `Member` there but is
    // NOT yet signed into the log, so granting it Member is meaningful and must
    // proceed (this is exactly how a not-yet-signed member gets admitted).
    if let TransitionVariant::RoleGrant { target, role } = &variant {
        if state.governance_state.read().roles.get(target).copied() == Some(*role) {
            return Ok(String::new());
        }
    }
    // Custody lock: authoring a governance transition is a custody-affecting
    // act. If this device enrolled a second factor for this network, a fresh
    // code is required here; otherwise this is a no-op. Composes with — does
    // not replace — the cryptographic owner-quorum checked at ratification.
    crate::custody::require(&state.network_id, mfa_code)?;
    let self_pubkey = state.identity.public_id().to_string();
    let signature =
        network_state::sign_transition(&state.network_id, &variant, state.identity.signing_key());
    let id = new_proposal_id();
    let proposal = Proposal {
        id: id.clone(),
        created_at: member_tier_timestamp(state, &variant),
        proposer: self_pubkey.clone(),
        variant: variant.clone(),
        signers: vec![self_pubkey.clone()],
        signatures: vec![signature.clone()],
        deniers: Vec::new(),
        split_spawned: false,
    };

    {
        let mut gov = state.governance_state.write();
        gov.pending.push(proposal);
        network_state::save(&gov)?;
    }

    let msg = MeshMessage::NetworkStatePropose(NetworkStateProposeMessage {
        proposal_id: id.clone(),
        variant,
        proposer: self_pubkey,
        created_at: now_unix(),
        signature,
    });
    broadcast(state, msg).await;

    // After every governance-mutating step that wrote to pending or
    // transitions, broadcast a fresh state snapshot so peers
    // catch up without waiting for their own ACTIVE transition.
    broadcast_state(state).await;

    // The proposer may have all the signatures they need already
    // (e.g. a single-signer founder self-election on an empty
    // network, or a sole-owner closed→open transition). Try to
    // ratify immediately.
    let _ = try_ratify(state, &id).await;

    Ok(id)
}

/// Sign an existing pending proposal authored elsewhere (or
/// re-sign — a no-op if the local pubkey is already in the signer
/// list). Broadcasts the signed ack. If the signature satisfies the
/// quorum, ratifies the transition in the same step.
pub async fn sign_proposal(
    state: &Arc<EngineState>,
    proposal_id: &str,
    mfa_code: Option<&str>,
) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    let (variant, signature) = {
        let mut gov = state.governance_state.write();
        let idx = gov
            .pending
            .iter()
            .position(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if !gov.pending[idx].deniers.is_empty() {
            return Err(Error::Other("proposal has been denied".into()));
        }
        if gov.pending[idx].signers.iter().any(|s| s == &self_pubkey) {
            return Err(Error::Other("already signed".into()));
        }
        // Custody lock: co-signing is authoring. Gate here — after the
        // proposal is known valid and unsigned by us — so a one-time recovery
        // code is never spent on a sign that wouldn't have happened anyway.
        crate::custody::require(&state.network_id, mfa_code)?;
        let variant = gov.pending[idx].variant.clone();
        let signature = network_state::sign_transition(
            &state.network_id,
            &variant,
            state.identity.signing_key(),
        );
        gov.pending[idx].signers.push(self_pubkey.clone());
        gov.pending[idx].signatures.push(signature.clone());
        network_state::save(&gov)?;
        (variant, signature)
    };

    let msg = MeshMessage::NetworkStateAck(NetworkStateAckMessage {
        proposal_id: proposal_id.to_string(),
        signer: self_pubkey,
        decision: AckDecision::Sign,
        at: now_unix(),
        signature,
    });
    broadcast(state, msg).await;

    let _ = try_ratify(state, proposal_id).await;
    let _ = variant; // silence unused if try_ratify path doesn't read it
    Ok(())
}

/// Deny a pending proposal. Signs a deny payload (so a deny can't
/// be forged) and broadcasts. Any single deny invalidates the
/// proposal.
pub async fn deny_proposal(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    let signature = {
        let mut gov = state.governance_state.write();
        let idx = gov
            .pending
            .iter()
            .position(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if gov.pending[idx].deniers.iter().any(|s| s == &self_pubkey) {
            return Err(Error::Other("already denied".into()));
        }
        // Deny payload is a distinct byte string so a sign signature
        // can't be repurposed as a deny. We bind to (network_id,
        // proposal_id, signer) — the proposal id is unique within
        // the network so this is replay-safe.
        let payload = format!(
            "{}deny|{}|{}|{}",
            network_state::SIGN_DOMAIN_TAG_STATE,
            state.network_id,
            proposal_id,
            self_pubkey
        );
        let sig = crate::signing::sign_with(state.identity.signing_key(), payload.as_bytes());
        gov.pending[idx].deniers.push(self_pubkey.clone());
        network_state::save(&gov)?;
        sig
    };

    let msg = MeshMessage::NetworkStateAck(NetworkStateAckMessage {
        proposal_id: proposal_id.to_string(),
        signer: self_pubkey,
        decision: AckDecision::Deny,
        at: now_unix(),
        signature,
    });
    broadcast(state, msg).await;
    // Symmetric with `sign_proposal`: call try_ratify so the
    // denier's own pending list drops the proposal right away
    // (the inbound ack handler does this for receivers, but the
    // denier herself wouldn't otherwise clean up until the next
    // mutation).
    let _ = try_ratify(state, proposal_id).await;
    broadcast_state(state).await;
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!("proposal {proposal_id} denied"),
    );
    Ok(())
}

/// Withdraw a proposal authored by the local device. No broadcast —
/// peers see the proposal disappear via the next state snapshot.
pub async fn withdraw_proposal(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let self_pubkey = state.identity.public_id().to_string();
    {
        let mut gov = state.governance_state.write();
        let idx = gov
            .pending
            .iter()
            .position(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        if gov.pending[idx].proposer != self_pubkey {
            return Err(Error::Other(
                "only the proposer can withdraw a proposal".into(),
            ));
        }
        gov.pending.remove(idx);
        network_state::save(&gov)?;
    }
    broadcast_state(state).await;
    Ok(())
}

/// Fire the proposer-initiated split fallback. Spawns a derived
/// closed network from the signers the proposal has so far; the
/// local device becomes founder-owner of the new network.
pub async fn spawn_split(state: &Arc<EngineState>, proposal_id: &str) -> Result<String> {
    let self_pubkey = state.identity.public_id().to_string();
    let (new_network_id, signers, split_signature) = {
        let mut gov = state.governance_state.write();
        let idx = gov
            .pending
            .iter()
            .position(|p| p.id == proposal_id)
            .ok_or_else(|| Error::Other(format!("proposal not found: {proposal_id}")))?;
        let p = &gov.pending[idx];
        if p.proposer != self_pubkey {
            return Err(Error::Other("only the proposer can spawn a split".into()));
        }
        if p.split_spawned {
            return Err(Error::Other("split already spawned".into()));
        }
        if !matches!(
            &p.variant,
            TransitionVariant::KindChange {
                to: NetworkKind::Closed
            }
        ) {
            return Err(Error::Other(
                "splits only apply to stuck open→closed proposals".into(),
            ));
        }

        // Derived network id is deterministic from the parent + signer
        // set, so the same signers always land in the same network
        // (idempotent retry-safe). The signed payload binds the new
        // network's id + members; the proposer is the lone signer
        // since the split's quorum is single-signer (the would-be
        // founder owner).
        let signers = p.signers.clone();
        let new_network_id = network_state::derive_split_network_id(&state.network_id, &signers);
        let split_variant = TransitionVariant::Split {
            new_network_id: new_network_id.clone(),
            members: signers.clone(),
        };
        let split_signature = network_state::sign_transition(
            &state.network_id,
            &split_variant,
            state.identity.signing_key(),
        );

        // Record the split on the parent's transition log + splits
        // index. The parent's kind stays Open — the split is
        // additive, not a kind change on the parent.
        let transition = Transition {
            at: now_unix(),
            variant: split_variant,
            signers: vec![self_pubkey.clone()],
            signatures: vec![split_signature.clone()],
        };
        let after = network_state::apply_transition(gov.clone(), &transition);
        *gov = after;
        gov.pending[idx].split_spawned = true;
        network_state::save(&gov)?;

        (new_network_id, signers, split_signature)
    };

    let msg = MeshMessage::NetworkStateSplit(NetworkStateSplitMessage {
        parent_proposal_id: proposal_id.to_string(),
        new_network_id: new_network_id.clone(),
        members: signers,
        proposer: self_pubkey,
        at: now_unix(),
        signature: split_signature,
    });
    broadcast(state, msg).await;
    broadcast_state(state).await;
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!("spawned split → {new_network_id}"),
    );
    Ok(new_network_id)
}

// ---- inbound dispatch -----------------------------------------------

/// A peer asks us to consider their proposal. Verify the proposer's
/// signature; if valid + not already known, add to pending so the
/// local user can sign or deny.
pub async fn on_propose(state: &Arc<EngineState>, peer_id: &str, msg: NetworkStateProposeMessage) {
    // Reject if the claimed proposer's pubkey isn't the one that
    // actually owns the data channel. A peer can't author a
    // proposal "as" someone else.
    let peer_pubkey = pk(peer_id);
    if msg.proposer != peer_pubkey {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!(
                "rejecting proposal claiming proposer={} from peer={}",
                &msg.proposer[..msg.proposer.len().min(12)],
                &peer_pubkey[..peer_pubkey.len().min(12)]
            ),
        );
        return;
    }
    // Verify the proposer actually signed the canonical payload.
    let payload = network_state::transition_payload(&state.network_id, &msg.variant);
    let ok = crate::signing::verify(&msg.proposer, &payload, &msg.signature).unwrap_or(false);
    if !ok {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting unsigned/forged proposal {}", msg.proposal_id),
        );
        return;
    }

    let added = {
        let mut gov = state.governance_state.write();
        if gov.pending.iter().any(|p| p.id == msg.proposal_id) {
            false
        } else {
            gov.pending.push(Proposal {
                id: msg.proposal_id.clone(),
                created_at: msg.created_at,
                proposer: msg.proposer.clone(),
                variant: msg.variant.clone(),
                signers: vec![msg.proposer.clone()],
                signatures: vec![msg.signature.clone()],
                deniers: Vec::new(),
                split_spawned: false,
            });
            if let Err(e) = network_state::save(&gov) {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!("persist after inbound propose failed: {e}"),
                );
            }
            true
        }
    };
    if added {
        diag(
            state,
            crate::events::DiagLevel::Info,
            format!(
                "inbound proposal {} from {}",
                msg.proposal_id,
                &msg.proposer[..msg.proposer.len().min(12)]
            ),
        );
    }
    let _ = try_ratify(state, &msg.proposal_id).await;
}

/// A peer's sign or deny response to a proposal we already have.
/// Verify the ack-signature, fold the decision into the pending
/// record, ratify if the new signer set satisfies the quorum.
pub async fn on_ack(state: &Arc<EngineState>, peer_id: &str, msg: NetworkStateAckMessage) {
    let peer_pubkey = pk(peer_id);
    if msg.signer != peer_pubkey {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!(
                "rejecting ack claiming signer={} from peer={}",
                &msg.signer[..msg.signer.len().min(12)],
                &peer_pubkey[..peer_pubkey.len().min(12)]
            ),
        );
        return;
    }

    let variant = {
        let gov = state.governance_state.read();
        match gov.pending.iter().find(|p| p.id == msg.proposal_id) {
            Some(p) => p.variant.clone(),
            None => {
                diag(
                    state,
                    crate::events::DiagLevel::Debug,
                    format!("ack for unknown proposal {}", msg.proposal_id),
                );
                return;
            }
        }
    };

    let payload = match msg.decision {
        AckDecision::Sign => network_state::transition_payload(&state.network_id, &variant),
        AckDecision::Deny => format!(
            "{}deny|{}|{}|{}",
            network_state::SIGN_DOMAIN_TAG_STATE,
            state.network_id,
            msg.proposal_id,
            msg.signer
        )
        .into_bytes(),
    };
    let ok = crate::signing::verify(&msg.signer, &payload, &msg.signature).unwrap_or(false);
    if !ok {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting forged ack on {}", msg.proposal_id),
        );
        return;
    }

    {
        let mut gov = state.governance_state.write();
        let Some(idx) = gov.pending.iter().position(|p| p.id == msg.proposal_id) else {
            return;
        };
        match msg.decision {
            AckDecision::Sign => {
                if !gov.pending[idx].signers.iter().any(|s| s == &msg.signer) {
                    gov.pending[idx].signers.push(msg.signer.clone());
                    gov.pending[idx].signatures.push(msg.signature.clone());
                }
            }
            AckDecision::Deny => {
                if !gov.pending[idx].deniers.iter().any(|s| s == &msg.signer) {
                    gov.pending[idx].deniers.push(msg.signer.clone());
                }
            }
        }
        if let Err(e) = network_state::save(&gov) {
            diag(
                state,
                crate::events::DiagLevel::Warn,
                format!("persist after ack failed: {e}"),
            );
        }
    }

    let _ = try_ratify(state, &msg.proposal_id).await;
}

/// A peer spawned a split from a proposal we were tracking. Verify
/// the proposer's signature over the new network's `Split`
/// payload, then record the split in our parent network's state.
pub async fn on_split(state: &Arc<EngineState>, peer_id: &str, msg: NetworkStateSplitMessage) {
    let peer_pubkey = pk(peer_id);
    if msg.proposer != peer_pubkey {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            "rejecting split with mismatched proposer",
        );
        return;
    }
    let split_variant = TransitionVariant::Split {
        new_network_id: msg.new_network_id.clone(),
        members: msg.members.clone(),
    };
    let payload = network_state::transition_payload(&state.network_id, &split_variant);
    let ok = crate::signing::verify(&msg.proposer, &payload, &msg.signature).unwrap_or(false);
    if !ok {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            "rejecting unsigned split",
        );
        return;
    }

    // Idempotency: if we already have this exact split recorded,
    // skip — a redelivered frame shouldn't append twice.
    {
        let mut gov = state.governance_state.write();
        if gov
            .splits
            .iter()
            .any(|s| s.new_network_id == msg.new_network_id)
        {
            return;
        }
        let transition = Transition {
            at: msg.at,
            variant: split_variant,
            signers: vec![msg.proposer.clone()],
            signatures: vec![msg.signature.clone()],
        };
        let after = network_state::apply_transition(gov.clone(), &transition);
        *gov = after;
        // Mark the parent proposal as split-spawned if we still
        // have it in pending.
        if let Some(p) = gov
            .pending
            .iter_mut()
            .find(|p| p.id == msg.parent_proposal_id)
        {
            p.split_spawned = true;
        }
        if let Err(e) = network_state::save(&gov) {
            diag(
                state,
                crate::events::DiagLevel::Warn,
                format!("persist after split failed: {e}"),
            );
        }
    }
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!(
            "split → {} spawned by {}",
            msg.new_network_id,
            &msg.proposer[..msg.proposer.len().min(12)]
        ),
    );
}

/// A peer broadcasts their view of the network's governance state.
/// We diag-log governance drift, and — because the broadcast carries the
/// sender's roster membership root — drive roster convergence off it too:
/// if their roster membership differs from ours, pull the delta. This
/// makes the post-mutation `NetworkState` broadcast double as a roster
/// summary, so a peer learns of new members the moment any governance
/// frame lands, not just on its own ACTIVE transition.
pub async fn on_state_broadcast(
    state: &Arc<EngineState>,
    peer_id: &str,
    msg: NetworkStateBroadcast,
) {
    let (local_kind, local_count, local_member_count) = {
        let gov = state.governance_state.read();
        (
            gov.kind,
            gov.transitions.len() as u32,
            gov.member_log.len() as u32,
        )
    };
    if local_kind != msg.kind || local_count != msg.transitions_count {
        diag(
            state,
            crate::events::DiagLevel::Info,
            format!(
                "governance drift with {}: local {:?}/{} vs theirs {:?}/{}",
                &peer_id[..peer_id.len().min(12)],
                local_kind,
                local_count,
                msg.kind,
                msg.transitions_count
            ),
        );
    }
    // Pull the peer's roster — which now carries the signed governance log —
    // when *either* our membership root differs or the peer's log is ahead of
    // ours. The log half is what converges roles (who the owner is) fleet-wide:
    // a role grant (or the founder election) bumps `transitions_count` without
    // necessarily changing membership, so a membership-only check would miss it.
    let membership_differs =
        crate::roster::membership_root(&state.roster.read()) != msg.roster_root;
    if membership_differs
        || msg.transitions_count > local_count
        || msg.member_log_count > local_member_count
    {
        request_roster(state, peer_id).await;
    }
}

// ---- roster gossip --------------------------------------------------
//
// Anti-entropy over the per-network roster. The contract (see
// `docs/NETWORK-TYPES.md`): once a peer is *mutually* confirmed (the
// bilateral approve handshake completes and the link goes ACTIVE) it is
// persisted into the local roster and advertised to the rest of the
// network so every member converges on the same membership.
//
// "Advertise, don't flood": we broadcast a compact membership *summary*
// (a 52-char root, not the entries) to active peers. A peer whose root
// disagrees pulls the full roster with one targeted `RosterRequest`; the
// responder replies peer-to-peer with `RosterEntries`. Each node that
// learns a new member re-summarises to ITS active peers, so an update
// ripples hop-by-hop along whatever shape the network actually has — a
// ring forwards it neighbour-to-neighbour, a star through the hub —
// reaching members we have no direct link to, instead of every node
// blasting its whole roster at every other node.
//
// Merges are additive and idempotent: gossip only ever *adds* members it
// was missing, never rewrites or removes existing entries. That is the
// correct membership model for an `open` network (a member is anyone any
// current member has vouched for) and keeps the protocol convergent —
// removals on an open network are local, and authority changes on a
// `closed` network ride the signed transition log, not roster gossip.

/// Broadcast our roster membership summary to every active peer. Cheap —
/// one small frame per peer carrying a root, not the roster itself.
/// Called when our roster changes (a peer is confirmed / approved) and on
/// each ACTIVE transition so a freshly-connected peer reconciles at once.
pub async fn broadcast_roster_summary(state: &Arc<EngineState>) {
    let summary = crate::roster::summary(&state.roster.read());
    broadcast(state, MeshMessage::RosterSummary(summary)).await;
}

/// Inbound roster summary. If the sender's membership root differs from
/// ours, ask for their full roster so we can merge what we're missing.
pub async fn on_roster_summary(state: &Arc<EngineState>, peer_id: &str, msg: RosterSummaryMessage) {
    maybe_request_roster(state, peer_id, &msg.root).await;
}

/// Inbound roster request. Reply peer-to-peer (not broadcast) with our
/// full roster as entries. v1 always sends everything (`include_all`); a
/// subtree-walk can ship later without changing the frame kind.
pub async fn on_roster_request(
    state: &Arc<EngineState>,
    peer_id: &str,
    _msg: RosterRequestMessage,
) {
    let entries: Vec<RosterEntry> = state
        .roster
        .read()
        .authorized_devices
        .iter()
        .map(RosterEntry::from)
        .collect();
    // Carry the signed governance log with the roster so roles converge with
    // membership: the requester verifies it from genesis and re-derives who is
    // owner/controller, instead of trusting a gossiped role tag. Empty on an
    // open network (no signed log).
    let (transitions, member_log) = {
        let gov = state.governance_state.read();
        (gov.transitions.clone(), gov.member_log.clone())
    };
    let msg = MeshMessage::RosterEntries(RosterEntriesMessage {
        entries,
        transitions,
        member_log,
    });
    if let Err(e) = super::send_to_peer(state, peer_id, &msg).await {
        tracing::debug!(peer = %peer_id, err = %e, "roster entries reply send failed");
    }
}

/// Inbound roster entries. Additively merge any members we were missing,
/// persist if the roster changed, and — if it did — re-summarise to our
/// peers so the new member propagates onward (gossip convergence).
pub async fn on_roster_entries(state: &Arc<EngineState>, peer_id: &str, msg: RosterEntriesMessage) {
    // Membership trust is split by network kind:
    //
    //   * `open` network — permissionless gossip: "a member is anyone any
    //     current member has vouched for" (see the module note). The unsigned
    //     `entries` are merged additively.
    //   * `closed` network — owner-**signed** only. Membership rides the signed
    //     transition log (a ratified `RoleGrant`) and is derived from the
    //     verified log in `adopt_transition_log` below. The unsigned `entries`
    //     are NOT a trust input here — not even from a Controller/Owner. The
    //     stance is deliberately the strong form of MOM-01: the *data* must be
    //     signed by an authority, not merely vouched for by an authenticated
    //     sender. An authenticated peer (a freshly-approved Member, or an
    //     attacker who cleared one approval) gossiping `entries` can no longer
    //     conscript anyone into a closed network — there is simply no unsigned
    //     path in. A closed network's roster is exactly the verified,
    //     owner-signed log: complete, self-sufficient, and identical on every
    //     member that has adopted the log.
    let kind = { state.governance_state.read().kind };
    if kind == NetworkKind::Open {
        let self_pk = state.identity.public_id().to_string();
        let added = {
            let mut roster = state.roster.write();
            let mut added = 0usize;
            for entry in &msg.entries {
                let pubkey = crate::signing::pubkey_part(&entry.device_id).to_string();
                // Our own entry is locally authoritative; never let a peer's
                // gossip rewrite how we see ourselves.
                if pubkey == self_pk {
                    continue;
                }
                // Additive only — skip members we already hold so a stale
                // label / timestamp from a peer can't clobber ours and a local
                // removal can't be undone by a no-op rewrite.
                if crate::roster::is_authorized(&roster, &pubkey) {
                    continue;
                }
                crate::roster::add_peer_in(&mut roster, &pubkey, &entry.label);
                // On an open network the role tag is cosmetic; adopt whatever
                // the gossip carried.
                if entry.role != Role::Member {
                    crate::roster::set_role_in(&mut roster, &pubkey, entry.role);
                }
                added += 1;
            }
            if added > 0 {
                if let Err(e) = crate::roster::save(&roster) {
                    diag(
                        state,
                        crate::events::DiagLevel::Warn,
                        format!("persist after roster merge failed: {e}"),
                    );
                }
            }
            added
        };
        if added > 0 {
            diag(
                state,
                crate::events::DiagLevel::Info,
                format!(
                    "roster: merged {added} member(s) from {}",
                    &peer_id[..peer_id.len().min(12)]
                ),
            );
            broadcast_roster_summary(state).await;
        }
    } else if !msg.entries.is_empty() {
        // A closed network ignores unsigned membership gossip outright. Surface
        // it at debug so a pre-signed-membership peer (or a probe) is visible
        // without alarming — any legitimate membership it carries arrives
        // signed in the log below.
        diag(
            state,
            crate::events::DiagLevel::Debug,
            format!(
                "roster: ignored {} unsigned entry(ies) on a closed network from {} \
                 (membership is owner-signed; deriving from the log)",
                msg.entries.len(),
                &peer_id[..peer_id.len().min(12)]
            ),
        );
    }
    // Roles AND closed-network membership ride the signed log: verify the
    // peer's log, adopt it when it extends ours, and re-derive the roster from
    // it. On a closed network this is the *only* membership source — every
    // member is a ratified `RoleGrant` authored by an owner/controller.
    adopt_transition_log(state, peer_id, &msg.transitions, &msg.member_log).await;
}

/// Re-derive the full role projection from both logs: owners and managers from
/// the verified **governance** log, plus the union-merged **member** set as
/// `Member`. With a member tier, the governance log alone no longer carries
/// members, so this is the single source of truth for `gov.roles`. A governance
/// log that fails to verify (never expected for our own ratified state) falls
/// back to no governance roles rather than panicking.
fn project_roles(
    network_id: &str,
    transitions: &[Transition],
    member_log: &[Transition],
) -> std::collections::BTreeMap<String, Role> {
    let gov = network_state::verify_log(network_id, transitions)
        .unwrap_or_else(|_| network_state::NetworkState::empty_for(network_id));
    let mut roles = gov.roles.clone();
    for m in network_state::verify_member_log(&gov, member_log, network_id) {
        roles.entry(m).or_insert(Role::Member);
    }
    roles
}

/// Adopt a peer's two signed logs, converging both tiers of the cert chain.
///
/// The **governance** log (kind changes, owner/manager grants and removals,
/// splits) is verified from genesis ([`crate::network_state::verify_log`]) and
/// adopted only when it **extends** ours — shares our prefix and is strictly
/// longer — so a peer can add a grant or the founder election we hadn't seen
/// but can never rewrite our genesis (and the owner it elected) out from under
/// us. A divergent log is rejected whole, leaving our state untouched.
///
/// The **member** log (per-member admits/removals) is **union-merged**
/// ([`crate::network_state::merge_member_logs`]) — commutative, so two
/// managers' concurrent offline admissions both survive instead of forking the
/// way a strict-prefix log would. Either tier may change independently; if
/// either does we reproject the full role map from both logs, mirror it into
/// the roster, and re-gossip so it ripples on. We keep our in-flight pending
/// proposals throughout.
async fn adopt_transition_log(
    state: &Arc<EngineState>,
    peer_id: &str,
    incoming_gov: &[Transition],
    incoming_members: &[Transition],
) {
    // Governance log: decide adoption (verified, fork-guarded) without holding
    // the write lock across verify_log.
    let rebuilt: Option<network_state::NetworkState> = {
        let extends = {
            let gov = state.governance_state.read();
            let longer = incoming_gov.len() > gov.transitions.len();
            let shares_prefix = incoming_gov
                .iter()
                .zip(gov.transitions.iter())
                .all(|(a, b)| a.variant == b.variant && same_signer_set(a, b));
            if longer && !shares_prefix {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!(
                        "rejecting forked governance log from {}",
                        &peer_id[..peer_id.len().min(12)]
                    ),
                );
            }
            longer && shares_prefix
        };
        if extends {
            match network_state::verify_log(&state.network_id, incoming_gov) {
                Ok(s) => Some(s),
                Err(e) => {
                    diag(
                        state,
                        crate::events::DiagLevel::Warn,
                        format!(
                            "rejecting invalid governance log from {}: {e}",
                            &peer_id[..peer_id.len().min(12)]
                        ),
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    // Apply both tiers under the write lock; reproject + mirror if either moved.
    let (changed, roles, kind) = {
        let mut gov = state.governance_state.write();
        let mut changed = false;

        if let Some(rebuilt) = rebuilt {
            // Re-check length in case it raced another adopter.
            if rebuilt.transitions.len() > gov.transitions.len() {
                gov.kind = rebuilt.kind;
                gov.transitions = rebuilt.transitions;
                gov.splits = rebuilt.splits;
                changed = true;
            }
        }

        if !incoming_members.is_empty() {
            let merged = network_state::merge_member_logs(&gov.member_log, incoming_members);
            // Union only ever grows; a longer result means new entries.
            if merged.len() > gov.member_log.len() {
                gov.member_log = merged;
                changed = true;
            }
        }

        let kind = gov.kind;
        if !changed {
            (false, gov.roles.clone(), kind)
        } else {
            let projected = project_roles(&state.network_id, &gov.transitions, &gov.member_log);
            gov.roles = projected.clone();
            if let Err(e) = network_state::save(&gov) {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!("persist after adopting logs failed: {e}"),
                );
            }
            (true, projected, kind)
        }
    };

    if !changed {
        return;
    }

    // Mirror the converged roles into the roster's `role` projection so every
    // peer row — and AllMyStuff's fleet view, which reads this projection —
    // renders the right authority/membership without re-reading the logs. On a
    // **closed** network the roster *is* the signed membership, so we also prune
    // anyone the logs no longer carry — this is how an eviction learned only via
    // gossip actually de-authorises the target (the local-ratify path removes it
    // directly; without this the two paths disagreed and evictions never
    // converged).
    {
        let mut roster = state.roster.write();
        let prune = kind == NetworkKind::Closed && !roles.is_empty();
        let self_pk = state.identity.public_id().to_string();
        if mirror_roles_to_roster(&roles, &mut roster, prune, &self_pk) {
            if let Err(e) = crate::roster::save(&roster) {
                diag(
                    state,
                    crate::events::DiagLevel::Warn,
                    format!("persist roster after role mirror failed: {e}"),
                );
            }
        }
    }
    diag(
        state,
        crate::events::DiagLevel::Info,
        format!(
            "adopted converged logs from {}",
            &peer_id[..peer_id.len().min(12)]
        ),
    );
    // Tell our own peers — both the new membership and the new governance
    // counts — so it ripples on.
    broadcast_roster_summary(state).await;
    broadcast_state(state).await;
}

/// Mirror a [`crate::network_state::NetworkState::roles`] map into the roster's
/// per-entry `role` projection. Role-bearing pubkeys missing from the roster
/// are added (a bare entry, so the owner shows up even before membership gossip
/// reaches us). Returns whether the roster changed (to gate the disk write).
///
/// `roles` here is the **complete** membership projection: `project_roles` folds
/// every member of the signed member-log in as [`Role::Member`], so a device
/// absent from `roles` is genuinely not a member.
///
/// `prune_to_membership` should be set for a **closed** network, whose roster is
/// exactly the signed membership. Then any roster entry not in `roles` is
/// **removed** — except this device (`self_pubkey`), which is always locally
/// authoritative — so an `Evict`/`RoleRevoke` that reaches us only through
/// gossip actually drops the target. On an open network it stays unset: `roles`
/// is empty there and membership isn't the signed logs, so we merely clear a
/// stale role tag rather than delete rows.
fn mirror_roles_to_roster(
    roles: &std::collections::BTreeMap<String, Role>,
    roster: &mut crate::roster::Roster,
    prune_to_membership: bool,
    self_pubkey: &str,
) -> bool {
    let mut changed = false;
    for (pubkey, role) in roles {
        if !crate::roster::is_authorized(roster, pubkey) {
            crate::roster::add_peer_in(roster, pubkey, "");
            changed = true;
        }
        if crate::roster::set_role_in(roster, pubkey, *role) {
            changed = true;
        }
    }
    if prune_to_membership {
        let self_pk = crate::signing::pubkey_part(self_pubkey);
        let before = roster.authorized_devices.len();
        roster
            .authorized_devices
            .retain(|e| roles.contains_key(&e.device_id) || e.device_id == self_pk);
        if roster.authorized_devices.len() != before {
            changed = true;
        }
    } else {
        for entry in roster.authorized_devices.iter_mut() {
            if !roles.contains_key(&entry.device_id) && entry.role != Role::Member {
                entry.role = Role::Member;
                changed = true;
            }
        }
    }
    changed
}

/// If `their_root` (a membership root) differs from ours, send a targeted
/// request for the peer's full roster. We only ever *pull* on a mismatch —
/// the side that's behind asks — so two peers don't both dump their whole
/// rosters at each other. Idempotent and convergent: once memberships
/// agree the roots match and no request fires.
async fn maybe_request_roster(state: &Arc<EngineState>, peer_id: &str, their_root: &str) {
    let our_root = crate::roster::membership_root(&state.roster.read());
    if our_root == their_root {
        return;
    }
    request_roster(state, peer_id).await;
}

/// Send a targeted full-roster request to one peer. The reply
/// ([`on_roster_request`]) carries both the membership entries and the signed
/// governance log, so this is the single pull that converges *both* membership
/// and roles.
async fn request_roster(state: &Arc<EngineState>, peer_id: &str) {
    let msg = MeshMessage::RosterRequest(RosterRequestMessage {
        include_all: true,
        subtree_hashes: Vec::new(),
    });
    if let Err(e) = super::send_to_peer(state, peer_id, &msg).await {
        tracing::debug!(peer = %peer_id, err = %e, "roster request send failed");
    }
}

// ---- ratification ---------------------------------------------------

/// Reorder a transition's `(signer, signature)` pairs into a canonical,
/// peer-independent order: the proposer first, then every other signer sorted
/// by pubkey, each signature carried with its signer. Signatures are matched to
/// signers positionally by [`network_state::verify_transition_signatures`], so
/// the two vectors are permuted together.
///
/// Ratification runs the assembled transition through this so that two peers
/// which gathered the same co-signatures in different ack-arrival orders record
/// the *byte-identical* entry. That is what the shared-prefix fork guard in
/// [`adopt_transition_log`] — and any future hash over the log — depend on.
/// ed25519 signatures are deterministic, so once the signer order agrees the
/// whole entry agrees. Keeping the proposer first preserves the
/// `signers.first() == founder/proposer` convention `apply_transition` relies
/// on (genesis and splits are single-signer, so this is a no-op for them).
fn canonicalize_signers(
    proposer: &str,
    signers: &[String],
    signatures: &[String],
) -> (Vec<String>, Vec<String>) {
    // A malformed pending record with mismatched lengths is left as-is so the
    // downstream signature check rejects it cleanly rather than mis-pairing.
    if signers.len() != signatures.len() {
        return (signers.to_vec(), signatures.to_vec());
    }
    let mut pairs: Vec<(&String, &String)> = signers.iter().zip(signatures.iter()).collect();
    pairs.sort_by(|a, b| {
        let ka = (if a.0 == proposer { 0 } else { 1 }, a.0);
        let kb = (if b.0 == proposer { 0 } else { 1 }, b.0);
        ka.cmp(&kb)
    });
    pairs
        .into_iter()
        .map(|(s, g)| (s.clone(), g.clone()))
        .unzip()
}

/// The pubkey a member-tier transition acts on, if it is one.
fn member_entry_target(t: &Transition) -> Option<&str> {
    match &t.variant {
        TransitionVariant::RoleGrant { target, .. }
        | TransitionVariant::RoleRevoke { target }
        | TransitionVariant::Evict { target } => Some(target.as_str()),
        _ => None,
    }
}

/// Timestamp to stamp on a newly-authored transition. Member-tier entries
/// (member admit/remove) converge by last-writer-wins on `at`
/// ([`network_state::verify_member_log`]), so a re-admit that follows an evict
/// of the same device must carry a **strictly-later** `at` — otherwise the
/// evict tombstone keeps winning and the re-admit silently no-ops. We stamp one
/// past the newest existing member-log entry for that target (across every
/// author, since the member log is union-merged), never earlier than the wall
/// clock. Governance-tier transitions order by log position, not `at`, so they
/// just take the wall clock.
fn member_tier_timestamp(state: &Arc<EngineState>, variant: &TransitionVariant) -> u64 {
    let now = now_unix();
    let gov = state.governance_state.read();
    let target = match variant {
        TransitionVariant::RoleGrant {
            target,
            role: Role::Member,
        } => target.as_str(),
        TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target }
            if gov.role_of(target) == Role::Member =>
        {
            target.as_str()
        }
        _ => return now,
    };
    let newest = gov
        .member_log
        .iter()
        .filter(|t| member_entry_target(t) == Some(target))
        .map(|t| t.at)
        .max()
        .unwrap_or(0);
    now.max(newest.saturating_add(1))
}

/// Whether two transitions carry the same signer *set*, order-independent.
/// The shared-prefix fork guard uses this so the same ratified transition,
/// recorded with its co-signers in different orders on two peers, is recognised
/// as the same entry rather than a fork. New ratifications are canonicalised by
/// [`canonicalize_signers`]; this also tolerates logs written before that.
fn same_signer_set(a: &Transition, b: &Transition) -> bool {
    if a.signers.len() != b.signers.len() {
        return false;
    }
    let a_set: std::collections::BTreeSet<&str> = a.signers.iter().map(String::as_str).collect();
    let b_set: std::collections::BTreeSet<&str> = b.signers.iter().map(String::as_str).collect();
    a_set == b_set
}

/// If `proposal_id`'s pending entry has gathered enough signatures
/// to satisfy the quorum table for its variant — and hasn't been
/// denied — fold it into the signed transition log, apply, persist,
/// and broadcast a fresh state snapshot.
async fn try_ratify(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
    let (transition, applied) = {
        let mut gov = state.governance_state.write();
        let Some(idx) = gov.pending.iter().position(|p| p.id == proposal_id) else {
            return Ok(());
        };
        if !gov.pending[idx].deniers.is_empty() {
            // Denied — drop from pending and bail.
            gov.pending.remove(idx);
            network_state::save(&gov)?;
            return Ok(());
        }
        let p = &gov.pending[idx];

        // Fold the (signer, signature) pairs into a canonical order —
        // proposer first, then the rest sorted by signer pubkey — so that two
        // peers who collected the same co-signatures in different ack-arrival
        // orders record the *byte-identical* transition. Without this, the
        // shared-prefix fork guard in `adopt_transition_log` would see two
        // orderings of the same multi-signer transition as divergent logs and
        // refuse to converge. ed25519 signatures are deterministic, so once the
        // signer order agrees the whole entry agrees. Genesis and splits are
        // single-signer, so `first()` still resolves to the founder/proposer
        // (canonicalisation is a no-op there).
        let (signers, signatures) = canonicalize_signers(&p.proposer, &p.signers, &p.signatures);
        let candidate = Transition {
            at: p.created_at,
            variant: p.variant.clone(),
            signers,
            signatures,
        };
        if network_state::verify_transition_signatures(&state.network_id, &candidate).is_err() {
            // Should never happen — we verified each at intake.
            return Ok(());
        }

        // Quorum check. Authority is read entirely off the signed state
        // (`gov.roles`), reconstructed from the log — no external roster is
        // consulted, so this matches what a converging peer's `verify_log`
        // will re-derive.
        if network_state::verify_quorum(&gov, &candidate).is_err() {
            return Ok(());
        }

        let transition = candidate;
        // Route by tier: a member admit/removal rides the union-merged member
        // log (so two managers' concurrent offline admissions don't fork);
        // everything else (kind change, owner/manager grant or removal, split)
        // extends the strict governance log. A removal is member-tier iff its
        // target is currently a plain member.
        let member_tier = match &transition.variant {
            TransitionVariant::RoleGrant {
                role: Role::Member, ..
            } => true,
            TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target } => {
                gov.role_of(target) == Role::Member
            }
            _ => false,
        };
        if member_tier {
            gov.member_log.push(transition.clone());
            gov.roles = project_roles(&state.network_id, &gov.transitions, &gov.member_log);
        } else {
            // Apply to the governance log (also advances `gov.roles`).
            let after = network_state::apply_transition(gov.clone(), &transition);
            *gov = after;
        }
        gov.pending.retain(|p| p.id != proposal_id);
        network_state::save(&gov)?;
        (transition, true)
    };

    if applied {
        // Mirror role grants into the on-disk roster's `role`
        // projection so peers' rows render with the new authority
        // without re-reading the state log.
        if let TransitionVariant::RoleGrant { target, role } = &transition.variant {
            let mut roster = state.roster.write();
            if !crate::roster::is_authorized(&roster, target) {
                // Granting a role to a non-member is allowed — we
                // add them to the roster too so the local peer
                // list reflects reality.
                crate::roster::add_peer_in(&mut roster, target, "");
            }
            crate::roster::set_role_in(&mut roster, target, *role);
            crate::roster::save(&roster)?;
        }
        if let TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        } = &transition.variant
        {
            // Founder self-election promoted the local identity to
            // Owner; mirror onto the local roster entry.
            let self_pk = state.identity.public_id().to_string();
            let mut roster = state.roster.write();
            if !crate::roster::is_authorized(&roster, &self_pk) {
                let label = state.identity.label();
                crate::roster::add_peer_in(&mut roster, &self_pk, &label);
            }
            crate::roster::set_role_in(&mut roster, &self_pk, Role::Owner);
            crate::roster::save(&roster)?;
        }
        if let TransitionVariant::Evict { target } = &transition.variant {
            // The evict's whole purpose: drop the target from the roster
            // projection so it loses authorisation here. Because every
            // peer that ratifies this transition runs the same mirror,
            // the removal propagates across the closed network (unlike a
            // bare roster remove, which is local + additive-gossip only).
            let removed = {
                let mut roster = state.roster.write();
                let was = crate::roster::is_authorized(&roster, target);
                if was {
                    crate::roster::remove_peer_in(&mut roster, target);
                    crate::roster::save(&roster)?;
                }
                was
            };
            if removed {
                // Tear down any live session to the evicted device so it
                // can't keep riding an already-open data channel.
                let _ = state.cmd_tx.send(NetworkCmd::DropPeer {
                    device_id: target.clone(),
                    reason: DropReason::Denied,
                });
            }
        }

        diag(
            state,
            crate::events::DiagLevel::Info,
            format!("ratified transition: {:?}", transition.variant),
        );
        // Membership/roles may have changed — summarise so peers reconcile (a
        // member admit shows up as a roster-root + member-log-count bump).
        broadcast_roster_summary(state).await;
        broadcast_state(state).await;
    }

    Ok(())
}

// ---- state broadcast ------------------------------------------------

/// Emit a `NetworkState` snapshot to every active peer. Called
/// after every mutation to keep peers in sync without waiting on
/// the next ACTIVE transition.
pub async fn broadcast_state(state: &Arc<EngineState>) {
    let (kind, transitions_count, member_log_count) = {
        let gov = state.governance_state.read();
        (
            gov.kind,
            gov.transitions.len() as u32,
            gov.member_log.len() as u32,
        )
    };
    // Membership root (not the full merkle root) so peers reconcile on
    // *who is in the network*, not on per-node label / timestamp churn —
    // see `roster::membership_root`.
    let roster_root = crate::roster::membership_root(&state.roster.read());
    let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
        kind,
        transitions_count,
        member_log_count,
        roster_root,
    });
    broadcast(state, msg).await;
}
