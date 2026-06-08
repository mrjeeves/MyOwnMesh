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
use crate::network_state::{self, NetworkKind, Proposal, Role, Transition, TransitionVariant};
use crate::protocol::{
    AckDecision, MeshMessage, NetworkStateAckMessage, NetworkStateBroadcast,
    NetworkStateProposeMessage, NetworkStateSplitMessage, RosterEntriesMessage, RosterEntry,
    RosterRequestMessage, RosterSummaryMessage,
};

use super::connection::PeerStatus;
use super::state::NetworkState as EngineState;

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
pub async fn propose(state: &Arc<EngineState>, variant: TransitionVariant) -> Result<String> {
    let self_pubkey = state.identity.public_id().to_string();
    let signature =
        network_state::sign_transition(&state.network_id, &variant, state.identity.signing_key());
    let id = new_proposal_id();
    let proposal = Proposal {
        id: id.clone(),
        created_at: now_unix(),
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
pub async fn sign_proposal(state: &Arc<EngineState>, proposal_id: &str) -> Result<()> {
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
    let (local_kind, local_count) = {
        let gov = state.governance_state.read();
        (gov.kind, gov.transitions.len() as u32)
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
    maybe_request_roster(state, peer_id, &msg.roster_root).await;
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
    let msg = MeshMessage::RosterEntries(RosterEntriesMessage { entries });
    if let Err(e) = super::send_to_peer(state, peer_id, &msg).await {
        tracing::debug!(peer = %peer_id, err = %e, "roster entries reply send failed");
    }
}

/// Inbound roster entries. Additively merge any members we were missing,
/// persist if the roster changed, and — if it did — re-summarise to our
/// peers so the new member propagates onward (gossip convergence).
pub async fn on_roster_entries(state: &Arc<EngineState>, peer_id: &str, msg: RosterEntriesMessage) {
    let kind = state.governance_state.read().kind;
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
            // label / timestamp from a peer can't clobber ours and a
            // local removal can't be undone by a no-op rewrite.
            if crate::roster::is_authorized(&roster, &pubkey) {
                continue;
            }
            crate::roster::add_peer_in(&mut roster, &pubkey, &entry.label);
            // Role authority: on an `open` network the tag is cosmetic, so
            // adopt whatever the gossip carried. On a `closed` network the
            // signed transition log is the only source of authority, so a
            // freshly-learned member lands as the default `Member` and is
            // promoted (if at all) by a ratified RoleGrant, never by raw
            // gossip.
            if kind == NetworkKind::Open && entry.role != Role::Member {
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
    let msg = MeshMessage::RosterRequest(RosterRequestMessage {
        include_all: true,
        subtree_hashes: Vec::new(),
    });
    if let Err(e) = super::send_to_peer(state, peer_id, &msg).await {
        tracing::debug!(peer = %peer_id, err = %e, "roster request send failed");
    }
}

// ---- ratification ---------------------------------------------------

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

        // Verify every signature in the set re-derives correctly.
        let signers = p.signers.clone();
        let signatures = p.signatures.clone();
        let candidate = Transition {
            at: p.created_at,
            variant: p.variant.clone(),
            signers: signers.clone(),
            signatures: signatures.clone(),
        };
        if network_state::verify_transition_signatures(&state.network_id, &candidate).is_err() {
            // Should never happen — we verified each at intake.
            return Ok(());
        }

        // Quorum check.
        let members = {
            // Members for quorum = everyone in the roster *plus* the
            // role-tagged peers in the governance state. We dedupe so
            // a peer who happens to be in both isn't counted twice.
            let mut set: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
            for entry in state.roster.read().authorized_devices.iter() {
                set.insert(entry.device_id.clone());
            }
            for k in gov.roles.keys() {
                set.insert(k.clone());
            }
            // The local identity is always implicitly a member (it
            // owns the daemon). Without this, founder self-election
            // wouldn't find the founder in the member set.
            set.insert(state.identity.public_id().to_string());
            set.into_iter().collect::<Vec<_>>()
        };
        if network_state::verify_quorum(&gov, &candidate, &members).is_err() {
            return Ok(());
        }

        let transition = candidate;
        // Apply, drop from pending, persist.
        let after = network_state::apply_transition(gov.clone(), &transition);
        *gov = after;
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

        diag(
            state,
            crate::events::DiagLevel::Info,
            format!("ratified transition: {:?}", transition.variant),
        );
        broadcast_state(state).await;
    }

    Ok(())
}

// ---- state broadcast ------------------------------------------------

/// Emit a `NetworkState` snapshot to every active peer. Called
/// after every mutation to keep peers in sync without waiting on
/// the next ACTIVE transition.
pub async fn broadcast_state(state: &Arc<EngineState>) {
    let (kind, transitions_count) = {
        let gov = state.governance_state.read();
        (gov.kind, gov.transitions.len() as u32)
    };
    // Membership root (not the full merkle root) so peers reconcile on
    // *who is in the network*, not on per-node label / timestamp churn —
    // see `roster::membership_root`.
    let roster_root = crate::roster::membership_root(&state.roster.read());
    let msg = MeshMessage::NetworkState(NetworkStateBroadcast {
        kind,
        transitions_count,
        roster_root,
    });
    broadcast(state, msg).await;
}
