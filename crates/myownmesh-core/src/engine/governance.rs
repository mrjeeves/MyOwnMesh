//! Engine half of closed-network governance.
//!
//! Canonical governance ingress and projection.
//!
//! Signed V4 facts are admitted into the one bootstrap-bound `FactGraph` and
//! broadcast with their exact content address. Compatibility carriers never
//! provide authority; all governance decisions come from the semantic graph.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::error::{Error, Result};
use crate::events::DropReason;
use crate::protocol::{
    FactInventory, FactPageMessage, FactRequest, MeshMessage, ProofAckMessage, ProofDeliveryMessage,
};
use crate::semantic::{DeviceId, FactBody, FactContent, FactId, SignedFact};

use super::connection::PeerStatus;
use super::peer_registry::{LogicalSessionOperation, PeerOwnerToken};
use super::state::NetworkState as EngineState;

// ---- helpers --------------------------------------------------------

fn canonical_device(value: &str) -> Result<DeviceId> {
    DeviceId::from_canonical_str(value)
        .map_err(|error| Error::Other(format!("noncanonical DeviceId: {error}")))
}

fn signed_fact(
    state: &Arc<EngineState>,
    body: FactBody,
    extra_parents: Vec<FactId>,
) -> Result<SignedFact> {
    #[cfg(feature = "transport-lab")]
    let _author_witness_sign_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::AuthorWitnessSign,
    );
    let author = canonical_device(state.identity.public_id())?;
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let witness = graph.authoring_witness(&body, &author);
    // Keep the authoring path explicit about the typed AuthorityLineage.  The
    // witness currently derives these same parents, but carrying the heads
    // here makes it impossible for a future ordinary-cell-only witness to
    // omit a cross-cell authority fork or selected branch.
    let mut authority_parents = extra_parents;
    for subject in body.authority_use_subjects(&author) {
        authority_parents.extend(graph.authority_lineage(&subject).heads().iter().copied());
    }
    let content = FactContent::from_authoring_witness(&graph, body, &witness, authority_parents);
    SignedFact::sign(content, state.identity.signing_key())
        .map_err(|error| Error::Other(format!("semantic fact rejected: {error}")))
}

async fn admit_authored_fact(
    state: &Arc<EngineState>,
    fact: &SignedFact,
) -> Result<crate::semantic::SemanticDelta> {
    let (admission, _, delta) = state
        .admit_fact_durably_with_delta_async(fact.clone())
        .await?;
    if matches!(admission, crate::semantic::Admission::Quarantined { .. }) {
        return Err(Error::Other(
            "authored semantic fact is missing a causal parent".into(),
        ));
    }
    Ok(delta)
}

/// Return the complete causal proof for the current closed-network eviction of
/// `target`.  The inventory/request exchange can discover these identifiers,
/// but an evicted reconnect is denied before it can become an ordinary active
/// peer, so that first delivery must carry the proof itself.  Starting from
/// both exclusive cells is intentional: an eviction advances role and
/// membership together, while a later causal restoration can advance only one
/// of them.
fn current_eviction_proof_bundle(
    state: &Arc<EngineState>,
    target: &str,
) -> Option<Vec<SignedFact>> {
    let target = canonical_device(target).ok()?;
    let graph = state.authoritative_fact_graph();
    let bundle = graph.read().eviction_proof_bundle(&target);
    bundle
}

/// Strip the display suffix (`-XXXXX`) from a Device ID. The
/// governance store keys everything on the bare pubkey.
fn pk(device_id: &str) -> String {
    crate::signing::pubkey_part(device_id).to_string()
}

/// Canonical policy admission for registry and handshake fences. The bootstrap
/// binding and the shared FactGraph are the only authority inputs.
/// The decision itself is always delegated to the graph's sealed semantic
/// evaluator so every consumer uses one projection and one conflict rule.
pub(super) fn canonical_policy_admits_from(
    bootstrap: &crate::semantic::VerifiedBootstrap,
    graph: &crate::semantic::FactGraph,
    local_device_id: &str,
    remote_device_id: &str,
) -> bool {
    let Ok(local) = crate::semantic::DeviceId::from_canonical_str(local_device_id) else {
        return false;
    };
    let Ok(remote) = crate::semantic::DeviceId::from_canonical_str(remote_device_id) else {
        return false;
    };
    canonical_policy_admits_devices(bootstrap, graph, &local, &remote)
}

/// Evaluate already-owned canonical identities without interning or retaining
/// them. The caller supplies the same bootstrap and graph policy fence.
pub(super) fn canonical_policy_admits_devices(
    bootstrap: &crate::semantic::VerifiedBootstrap,
    graph: &crate::semantic::FactGraph,
    local: &DeviceId,
    remote: &DeviceId,
) -> bool {
    if graph.context_id() != bootstrap.context_id() {
        return false;
    }
    if local == remote {
        return false;
    }
    let evaluator = graph.evaluator();
    if evaluator.is_stood_down(local) || evaluator.is_stood_down(remote) {
        return false;
    }
    match bootstrap.policy() {
        crate::semantic::VerifiedProjectPolicy::Open => true,
        crate::semantic::VerifiedProjectPolicy::Closed(_) => {
            evaluator.admits_closed_session(local, remote)
        }
    }
}

#[derive(Default)]
struct CanonicalProjection {
    roles: BTreeMap<String, crate::semantic::Role>,
    evicted: BTreeSet<String>,
    stood_down: BTreeSet<String>,
}

/// Convert the sealed semantic projection into the read-only roster shape. The
/// graph, evaluator, and typed projection decide every value; this projection
/// performs only key conversion and has no independent governance rules.
fn canonical_projection_snapshot(state: &Arc<EngineState>) -> CanonicalProjection {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let evaluator = graph.evaluator();
    let projection = evaluator.projection();
    let mut result = CanonicalProjection::default();

    let mut subjects = BTreeSet::new();
    for root in state.verified_bootstrap().authority_roots().iter() {
        subjects.insert(root.clone());
    }
    for (cell, _) in projection.cells() {
        match cell {
            crate::semantic::ExclusiveCell::Role { subject }
            | crate::semantic::ExclusiveCell::Membership { subject } => {
                subjects.insert(subject.clone());
            }
            crate::semantic::ExclusiveCell::Decision { .. } => {}
        }
    }
    subjects.extend(projection.stand_down_targets().cloned());

    for subject in subjects {
        let subject_string = subject.to_string();
        // Role(C) remains a normal exclusive-cell projection.  The typed
        // AuthorityLineage is an independent currentness fence for the
        // authority that may author that projection; it is not a replacement
        // for Role-cell Resolution semantics.
        let role = evaluator.effective_authorized_role(&subject);
        let membership = evaluator.effective_membership(&subject);
        let stood_down = evaluator.is_stood_down(&subject);
        if membership == Some(false) {
            result.evicted.insert(subject_string.clone());
        }
        if stood_down {
            result.stood_down.insert(subject_string.clone());
        }
        if let Some(role) = role {
            if membership != Some(false) && !stood_down {
                result.roles.insert(
                    subject_string,
                    match role {
                        crate::semantic::Role::Member => crate::semantic::Role::Member,
                        crate::semantic::Role::Controller => crate::semantic::Role::Controller,
                        crate::semantic::Role::Owner => crate::semantic::Role::Owner,
                    },
                );
            }
        }
    }
    result
}

fn canonical_projection_for_subjects(
    state: &Arc<EngineState>,
    subjects: &BTreeSet<DeviceId>,
) -> CanonicalProjection {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let evaluator = graph.evaluator();
    let mut result = CanonicalProjection::default();
    for subject in subjects {
        let subject_string = subject.to_string();
        let role = evaluator.effective_authorized_role(subject);
        let membership = evaluator.effective_membership(subject);
        let stood_down = evaluator.is_stood_down(subject);
        if membership == Some(false) {
            result.evicted.insert(subject_string.clone());
        }
        if stood_down {
            result.stood_down.insert(subject_string.clone());
        }
        if let Some(role) = role {
            if membership != Some(false) && !stood_down {
                result.roles.insert(subject_string, role);
            }
        }
    }
    result
}

pub(crate) fn apply_canonical_projection_checked(state: &Arc<EngineState>) -> Result<bool> {
    apply_canonical_projection_with(state, |candidate, affected| {
        crate::roster::save_affected(candidate, affected)
    })
}

fn apply_canonical_projection_with<F>(state: &Arc<EngineState>, save: F) -> Result<bool>
where
    F: FnOnce(&crate::roster::Roster, &BTreeSet<String>) -> Result<()>,
{
    #[cfg(feature = "transport-lab")]
    let _projection_roster_publish_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::ProjectionRosterPublish,
    );
    let projection = canonical_projection_snapshot(state);
    let CanonicalProjection {
        roles,
        evicted,
        stood_down,
        ..
    } = projection;
    let roster_changed = {
        let mut roster = state.roster.write();
        let previous_keys = roster
            .authorized_devices
            .iter()
            .map(|peer| peer.device_id.clone())
            .collect::<BTreeSet<_>>();
        let mut candidate = roster.clone();
        let mut desired = previous_keys
            .iter()
            .cloned()
            .map(|key| (key, None))
            .collect::<BTreeMap<_, _>>();
        for (pubkey, role) in &roles {
            if !evicted.contains(pubkey) && !stood_down.contains(pubkey) {
                desired.insert(pubkey.clone(), Some(*role));
            }
        }
        let changed = crate::roster::apply_projected_roles_in(&mut candidate, &desired);
        if changed {
            let affected_keys = previous_keys
                .into_iter()
                .chain(
                    candidate
                        .authorized_devices
                        .iter()
                        .map(|peer| peer.device_id.clone()),
                )
                .collect::<BTreeSet<_>>();
            // The role is a derived in-memory field and is intentionally not
            // part of RosterEntryRecord. Persist only membership or metadata
            // changes; the canonical graph still updates the live role below.
            if !crate::roster::persisted_metadata_equal(&roster, &candidate, &affected_keys) {
                save(&candidate, &affected_keys)?;
            }
            *roster = candidate;
        }
        Ok(changed)
    };
    roster_changed
}

/// Apply only the exact roster subjects returned by a journal delta. The
/// roster remains a projection cache: unaffected rows are retained, while an
/// affected subject is inserted, updated, or removed from its current typed
/// semantic result. This avoids enumerating the full projection per fact.
pub(crate) fn apply_canonical_projection_delta_checked(
    state: &Arc<EngineState>,
    delta: &crate::semantic::SemanticDelta,
) -> Result<bool> {
    apply_canonical_projection_delta_with_projection(state, delta).map(|(changed, _)| changed)
}

fn apply_canonical_projection_delta_with_projection(
    state: &Arc<EngineState>,
    delta: &crate::semantic::SemanticDelta,
) -> Result<(bool, CanonicalProjection)> {
    apply_canonical_projection_delta_with_projection_and_save(
        state,
        delta,
        crate::roster::save_affected,
    )
}

fn apply_canonical_projection_delta_with_projection_and_save<F>(
    state: &Arc<EngineState>,
    delta: &crate::semantic::SemanticDelta,
    save: F,
) -> Result<(bool, CanonicalProjection)>
where
    F: FnOnce(&crate::roster::Roster, &BTreeSet<String>) -> Result<()>,
{
    #[cfg(feature = "transport-lab")]
    let _projection_roster_publish_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::ProjectionRosterPublish,
    );
    let projection = canonical_projection_for_subjects(state, delta.affected_subjects());
    let CanonicalProjection {
        roles,
        evicted,
        stood_down,
    } = projection;
    let mut roster = state.roster.write();
    let affected_keys = delta
        .affected_subjects()
        .iter()
        .map(|subject| pk(subject))
        .collect::<BTreeSet<_>>();
    let before = roster.authorized_devices.snapshot_keys(&affected_keys);
    let desired = delta
        .affected_subjects()
        .iter()
        .map(|subject| {
            let subject_string = subject.to_string();
            let role = roles.get(&subject_string).copied().filter(|_| {
                !evicted.contains(&subject_string) && !stood_down.contains(&subject_string)
            });
            (pk(subject), role)
        })
        .collect::<BTreeMap<_, _>>();
    let changed = crate::roster::apply_projected_roles_in(&mut roster, &desired);
    if changed {
        // Semantic roles are an in-memory/UI projection and are deliberately
        // absent from RosterEntryRecord. Skip filesystem work when only that
        // non-persisted field changed; membership or metadata changes still
        // cross the exact save fence.
        let persisted_changed =
            !crate::roster::persisted_metadata_matches_snapshot(&before, &roster, &affected_keys);
        if persisted_changed {
            if let Err(error) = save(&roster, &affected_keys) {
                roster
                    .authorized_devices
                    .restore_snapshot(&affected_keys, &before);
                return Err(error);
            }
        }
    }
    Ok((
        changed,
        CanonicalProjection {
            roles,
            evicted,
            stood_down,
        },
    ))
}

/// Iterate active peers — those whose data channel is ACTIVE +
/// authenticated. Used to broadcast governance frames.
fn active_peer_ids(state: &Arc<EngineState>) -> Vec<String> {
    state.peers.collect_map(|peer| {
        let data = peer.state.read();
        if matches!(data.status, PeerStatus::Active | PeerStatus::Shelved) && data.authenticated {
            Some(peer.device_id.clone())
        } else {
            None
        }
    })
}

fn inventory_peer_owners(state: &Arc<EngineState>) -> Vec<PeerOwnerToken> {
    state.peers.owners_snapshot(|peer| {
        let data = peer.state.read();
        inventory_owner_is_eligible(
            data.status,
            data.authenticated,
            peer.current_worker().is_some(),
        )
    })
}

fn inventory_owner_is_eligible(status: PeerStatus, authenticated: bool, has_worker: bool) -> bool {
    authenticated && has_worker && matches!(status, PeerStatus::Active | PeerStatus::Shelved)
}

async fn broadcast(state: &Arc<EngineState>, msg: MeshMessage) {
    for peer_id in active_peer_ids(state) {
        let result = super::send_to_peer(state, &peer_id, &msg).await;
        // Best-effort: a failure to send to one peer doesn't block
        // delivery to the others. The next fact inventory pass will repair
        // any advertisement lost while this channel was unavailable.
        if let Err(e) = result {
            tracing::debug!(peer = %peer_id, err = %e, "governance broadcast send failed");
        }
    }
}

/// Broadcast only while the exact peer installation that justified the
/// broadcast remains current.
///
/// Replacement is checked before every send. A send already started before
/// replacement may finish, but no later send is initiated by the retired
/// owner. This keeps the activation trigger local without changing ordinary
/// governance broadcasts that originate from durable governance mutations.
async fn broadcast_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
    msg: MeshMessage,
) -> bool {
    if state.peers.get_if_current(owner).is_none() {
        return false;
    }
    for peer_id in active_peer_ids(state) {
        if state.peers.get_if_current(owner).is_none() {
            return false;
        }
        if let Err(e) = super::send_to_peer(state, &peer_id, &msg).await {
            tracing::debug!(peer = %peer_id, err = %e, "owner-bound governance broadcast send failed");
        }
    }
    state.peers.get_if_current(owner).is_some()
}

struct FactInventoryCursor {
    source: FactInventorySource,
    context_id: crate::semantic::MeshContextId,
    cursor: Option<FactId>,
    finished: bool,
    invalid: bool,
    #[cfg(test)]
    visited_candidates: usize,
}

enum FactInventorySource {
    Durable(Arc<EngineState>),
    #[cfg(test)]
    Graph(Arc<parking_lot::RwLock<crate::semantic::FactGraph>>),
}

impl FactInventoryCursor {
    fn next_page(&mut self) -> Option<FactInventory> {
        if self.finished || self.invalid {
            return None;
        }
        // The empty envelope establishes the exact fixed overhead, including
        // the context encoding and the two array delimiters. Each FactId is
        // then serialized once and added to one checked running total; this
        // avoids cloning and re-encoding the entire candidate page for every
        // graph entry while the graph read guard is held.
        let empty_len = match serde_json::to_vec(&MeshMessage::FactInventory(FactInventory::new(
            self.context_id,
            std::iter::empty(),
        ))) {
            Ok(encoded) => encoded.len(),
            Err(_) => {
                self.invalid = true;
                return None;
            }
        };
        let fact_ids = {
            let mut fact_ids = Vec::new();
            let mut encoded_len = empty_len;
            let maximum_ids = crate::protocol::RECEIVE_FRAME_BYTES
                .saturating_sub(empty_len)
                .checked_div(53)
                .unwrap_or(0)
                .saturating_add(1);
            let candidates = match &self.source {
                FactInventorySource::Durable(state) => {
                    match state.admitted_semantic_fact_ids_after(self.cursor, maximum_ids) {
                        Ok(ids) => ids,
                        Err(_) => {
                            self.invalid = true;
                            return None;
                        }
                    }
                }
                #[cfg(test)]
                FactInventorySource::Graph(graph) => graph
                    .read()
                    .ids_after(self.cursor)
                    .take(maximum_ids)
                    .copied()
                    .collect(),
            };
            for fact_id in candidates {
                #[cfg(test)]
                {
                    self.visited_candidates = self.visited_candidates.saturating_add(1);
                }
                let id_len = match serde_json::to_vec(&fact_id) {
                    Ok(encoded) => encoded.len(),
                    Err(_) => {
                        self.invalid = true;
                        return None;
                    }
                };
                let separator_len = if fact_ids.is_empty() { 0 } else { 1 };
                let candidate_len = encoded_len
                    .checked_add(separator_len)
                    .and_then(|length| length.checked_add(id_len));
                let Some(candidate_len) = candidate_len else {
                    self.invalid = true;
                    return None;
                };
                if candidate_len > crate::protocol::RECEIVE_FRAME_BYTES {
                    if fact_ids.is_empty() {
                        self.invalid = true;
                        return None;
                    }
                    break;
                }
                fact_ids.push(fact_id);
                encoded_len = candidate_len;
            }
            fact_ids
        };
        if fact_ids.is_empty() {
            self.finished = true;
            return None;
        }
        self.cursor = fact_ids.last().copied();
        Some(FactInventory::new(self.context_id, fact_ids))
    }

    fn is_valid(&self) -> bool {
        !self.invalid
    }

    #[cfg(test)]
    fn visited_candidates(&self) -> usize {
        self.visited_candidates
    }
}

fn local_fact_inventory_cursor(state: &Arc<EngineState>) -> FactInventoryCursor {
    FactInventoryCursor {
        source: FactInventorySource::Durable(Arc::clone(state)),
        context_id: state.mesh_context_id(),
        cursor: None,
        finished: false,
        invalid: false,
        #[cfg(test)]
        visited_candidates: 0,
    }
}

/// Advertise the exact canonical graph inventory to active peers.  The
/// inventory contains identifiers only; it is a repair hint, never authority.
pub async fn broadcast_fact_inventory(state: &Arc<EngineState>) {
    let owners = inventory_peer_owners(state);
    for owner in owners {
        let mut inventory = local_fact_inventory_cursor(state);
        while let Some(page) = inventory.next_page() {
            let result =
                super::send_to_peer_owner(state, &owner, &MeshMessage::FactInventory(page)).await;
            if let Err(error) = result {
                tracing::debug!(peer = %owner.device_id(), %error, "fact inventory broadcast send failed");
            }
        }
        if !inventory.is_valid() {
            tracing::debug!(peer = %owner.device_id(), "fact inventory cannot fit the exact receive-safe frame boundary");
        }
    }
}

fn delta_inventory_pages(
    context_id: crate::semantic::MeshContextId,
    delta: &crate::semantic::SemanticDelta,
) -> Option<Vec<FactInventory>> {
    let mut ids = BTreeSet::new();
    for row in delta.rows() {
        if row.status() == crate::semantic::SemanticFactStatus::Admitted {
            ids.insert(row.fact().id);
        }
    }
    ids.extend(delta.promoted().iter().copied());

    let mut pages = Vec::new();
    let mut current = Vec::new();
    let empty_len = serde_json::to_vec(&MeshMessage::FactInventory(FactInventory::new(
        context_id,
        std::iter::empty(),
    )))
    .ok()?
    .len();
    let mut encoded_len = empty_len;
    for id in ids {
        let id_len = serde_json::to_vec(&id).ok()?.len();
        let separator_len = if current.is_empty() { 0 } else { 1 };
        let candidate_len = encoded_len
            .checked_add(separator_len)
            .and_then(|length| length.checked_add(id_len))?;
        if candidate_len > crate::protocol::RECEIVE_FRAME_BYTES {
            if current.is_empty() {
                return None;
            }
            pages.push(FactInventory::new(context_id, std::mem::take(&mut current)));
            encoded_len = empty_len;
            let single_len = encoded_len.checked_add(id_len)?;
            if single_len > crate::protocol::RECEIVE_FRAME_BYTES {
                return None;
            }
            current.push(id);
            encoded_len = single_len;
        } else {
            current.push(id);
            encoded_len = candidate_len;
        }
    }
    if !current.is_empty() {
        pages.push(FactInventory::new(context_id, current));
    }
    Some(pages)
}

async fn broadcast_fact_inventory_delta(
    state: &Arc<EngineState>,
    delta: &crate::semantic::SemanticDelta,
) {
    let Some(pages) = delta_inventory_pages(state.mesh_context_id(), delta) else {
        tracing::debug!("semantic delta inventory exceeds the exact receive-safe frame boundary");
        return;
    };
    if pages.is_empty() {
        return;
    }
    for owner in inventory_peer_owners(state) {
        for page in &pages {
            if let Err(error) =
                super::send_to_peer_owner(state, &owner, &MeshMessage::FactInventory(page.clone()))
                    .await
            {
                tracing::debug!(
                    peer = %owner.device_id(),
                    %error,
                    "fact delta inventory broadcast send failed"
                );
            }
        }
    }
}

/// Activation-bound inventory advertisement.  The exact owner fence is held
/// for each send, so a replacement cannot make an old installation advertise
/// on behalf of its successor.
pub(super) async fn broadcast_fact_inventory_for_owner(
    state: &Arc<EngineState>,
    owner: &PeerOwnerToken,
) -> bool {
    if state.peers.get_if_current(owner).is_none() {
        return false;
    }
    let mut inventory = local_fact_inventory_cursor(state);
    while let Some(page) = inventory.next_page() {
        if !broadcast_for_owner(state, owner, MeshMessage::FactInventory(page)).await {
            return false;
        }
    }
    if !inventory.is_valid() {
        tracing::debug!(peer = %owner.device_id(), "owner-bound fact inventory exceeds the exact receive-safe frame boundary");
        return false;
    }
    true
}

/// Ask the exact logical sender for canonical facts absent from our graph.
pub(super) async fn on_fact_inventory(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    inventory: FactInventory,
) {
    if inventory.context_id() != state.mesh_context_id() {
        return;
    }
    // A page is only a one-way repair hint. Do not answer it with a partial
    // reciprocal inventory: that would echo every page back and keep two
    // incomparable inventories alive indefinitely. The periodic/event-driven
    // full inventory pass repairs lost pages and converges once missing ids
    // have been admitted.
    let mut missing = Vec::new();
    for id in inventory.fact_ids() {
        match state.admitted_semantic_fact(*id) {
            Ok(Some(_)) => {}
            Ok(None) => missing.push(*id),
            Err(error) => {
                tracing::debug!(%error, "durable fact inventory lookup failed");
                return;
            }
        }
    }
    if !missing.is_empty() {
        let request = FactRequest::new(state.mesh_context_id(), missing);
        let mut pages = request.pages();
        for fact_ids in pages.by_ref() {
            let page = FactRequest::new(request.context_id(), fact_ids);
            let result =
                super::send_logical_reply(state, route, &MeshMessage::FactRequest(page)).await;
            if let Err(error) = result {
                tracing::debug!(
                    peer = %route.owner().device_id(),
                    %error,
                    "fact inventory request send failed"
                );
                break;
            }
        }
        if !pages.is_valid() {
            tracing::debug!(peer = %route.owner().device_id(), "fact inventory request exceeds the exact receive-safe frame boundary");
        }
    }
}

/// Reply on the captured logical route with only the requested facts known by
/// this exact graph.  Unknown IDs are ignored and the sorted request order is
/// retained by `FactRequest`'s canonical constructor.
pub(super) async fn on_fact_request(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    request: FactRequest,
) {
    if request.context_id() != state.mesh_context_id() {
        return;
    }
    let mut page_facts = Vec::new();
    for id in request.fact_ids() {
        let Ok(Some(fact)) = state.admitted_semantic_fact(*id) else {
            continue;
        };
        page_facts.push(fact);
        let Some(encoded_len) = fact_page_encoded_len(state.mesh_context_id(), &page_facts, false)
        else {
            tracing::debug!(peer = %route.owner().device_id(), "fact page could not be sized");
            return;
        };
        if encoded_len > crate::protocol::RECEIVE_FRAME_BYTES {
            let last = page_facts.pop().expect("the just-added fact is present");
            if page_facts.is_empty() {
                match send_single_fact_page(state, route, last).await {
                    Ok(true) => continue,
                    Ok(false) => {
                        tracing::debug!(peer = %route.owner().device_id(), "fact page and single fact exceed the exact receive-safe frame boundary");
                        // This exact fact cannot cross the receive boundary.
                        // It is not a transport failure: continue the request
                        // so later individually transmittable facts are not
                        // starved behind it.
                        continue;
                    }
                    Err(error) => {
                        tracing::debug!(peer = %route.owner().device_id(), %error, "single fact reply send failed");
                        return;
                    }
                }
            }
            if send_fact_page(state, route, std::mem::take(&mut page_facts), false)
                .await
                .is_err()
            {
                tracing::debug!(
                    peer = %route.owner().device_id(),
                    "fact page reply send failed"
                );
                return;
            }
            page_facts.push(last);
            if fact_page_encoded_len(state.mesh_context_id(), &page_facts, false)
                .is_none_or(|length| length > crate::protocol::RECEIVE_FRAME_BYTES)
            {
                let last = page_facts.pop().expect("the just-added fact is present");
                match send_single_fact_page(state, route, last).await {
                    Ok(true) => {}
                    Ok(false) => {
                        tracing::debug!(peer = %route.owner().device_id(), "fact page and single fact exceed the exact receive-safe frame boundary");
                        // Skip only this untransmittable fact. A later
                        // request item still deserves its own exact attempt.
                    }
                    Err(error) => {
                        tracing::debug!(peer = %route.owner().device_id(), %error, "single fact reply send failed");
                        return;
                    }
                }
            }
        }
    }
    if !page_facts.is_empty()
        && send_fact_page(state, route, page_facts, true)
            .await
            .is_err()
    {
        tracing::debug!(peer = %route.owner().device_id(), "fact page reply send failed");
    }
}

async fn send_fact_page(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    facts: Vec<crate::semantic::SignedFact>,
    complete: bool,
) -> Result<()> {
    let next_cursor = (!complete)
        .then(|| facts.last().map(|fact| fact.id))
        .flatten();
    let page = FactPageMessage::new(state.mesh_context_id(), facts, next_cursor, complete)
        .map_err(Error::Other)?;
    super::send_logical_reply(state, route, &MeshMessage::FactPage(page)).await
}

fn fact_page_encoded_len(
    context_id: crate::semantic::MeshContextId,
    facts: &[crate::semantic::SignedFact],
    complete: bool,
) -> Option<usize> {
    let next_cursor = (!complete)
        .then(|| facts.last().map(|fact| fact.id))
        .flatten();
    FactPageMessage::new(context_id, facts.to_vec(), next_cursor, complete)
        .ok()?
        .encoded_len()
}

/// Send one canonical fact when its one-item page envelope would be too
/// large. The standalone `fact` frame has a different envelope and may still
/// fit the exact receive boundary; refusing only after checking that frame
/// preserves later requested IDs instead of abandoning the whole request.
async fn send_single_fact_page(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    fact: crate::semantic::SignedFact,
) -> Result<bool> {
    let message = MeshMessage::Fact(fact);
    let encoded_len = serde_json::to_vec(&message)
        .map(|encoded| encoded.len())
        .map_err(Error::Serde)?;
    if encoded_len > crate::protocol::RECEIVE_FRAME_BYTES {
        return Ok(false);
    }
    super::send_logical_reply(state, route, &message).await?;
    Ok(true)
}

/// Verify that any eviction material in a reduced page agrees with the
/// canonical projection before it can be acknowledged.  Ordinary governance
/// ordinary governance pages have no target-level acknowledgement condition;
/// eviction closures do.  In particular, a signed proof is not acknowledged
/// merely because its bytes entered the graph: the exact target must be stood
/// down by the resulting authoritative projection.  The plain `Evict` closure
/// used during a denied handshake is checked against the corresponding
/// membership tombstone instead.
pub(super) fn fact_page_projection_is_verified(
    state: &Arc<EngineState>,
    facts: &[SignedFact],
) -> bool {
    state
        .authoritative_fact_graph()
        .read()
        .bundle_projection_is_verified(facts)
}

/// Verify the target-bound projection condition for one typed proof delivery.
/// The wire identity is checked by `ProofDeliveryMessage::validate`; this
/// predicate adds the receiver's exact mesh-context fence and requires the
/// delivery target itself to be represented by the resulting canonical
/// stand-down/eviction projection. A valid page for some other target can
/// therefore never settle this delivery.
pub(super) fn proof_delivery_projection_is_verified(
    state: &Arc<EngineState>,
    delivery: &ProofDeliveryMessage,
) -> bool {
    if delivery.context_id != state.mesh_context_id() {
        return false;
    }
    let graph = state.authoritative_fact_graph();
    let verified = graph
        .read()
        .proof_bundle_is_verified(&delivery.target, &delivery.facts);
    verified
}

/// A FactPage acknowledgement is the receiver's exact current inventory on
/// the same logical route that requested the page.  It is deliberately an
/// inventory rather than a new authority fact: the sender learns which signed
/// facts actually entered our graph and can request any remaining causal
/// dependencies, while the route only selects where the coordination reply is
/// sent.  This also works for a disconnected/offline proof source when the
/// next exact session is established; no heartbeat or carrier observation is
/// treated as acknowledgement.
pub(super) async fn acknowledge_fact_page(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
) {
    let mut inventory = local_fact_inventory_cursor(state);
    while let Some(page) = inventory.next_page() {
        if let Err(error) =
            super::send_logical_reply(state, route, &MeshMessage::FactInventory(page)).await
        {
            tracing::debug!(
                peer = %route.owner().device_id(),
                %error,
                "fact page acknowledgement send failed"
            );
            break;
        }
    }
    if !inventory.is_valid() {
        tracing::debug!(peer = %route.owner().device_id(), "fact page acknowledgement exceeds the exact receive-safe frame boundary");
    }
}

/// Emit the only verified receipt for a typed proof delivery. The exact
/// context, target, and content-derived delivery identity are copied from the
/// validated wire envelope; no generic inventory can settle this proof.
pub(super) async fn acknowledge_proof_delivery(
    state: &Arc<EngineState>,
    route: &LogicalSessionOperation,
    delivery: &ProofDeliveryMessage,
) {
    let ack = MeshMessage::ProofAck(ProofAckMessage::for_delivery(delivery));
    if let Err(error) = super::send_logical_reply(state, route, &ack).await {
        tracing::debug!(
            peer = %route.owner().device_id(),
            %error,
            "proof delivery acknowledgement send failed"
        );
    }
}

/// Carry the bootstrap root's initial member grant to the exact authenticated
/// installation that is still waiting for approval.  This is deliberately a
/// governance-only pre-admission seam: a pending peer receives one
/// self-authenticating canonical fact in an exact-context FactPage, never
/// application, inventory, request, or realtime traffic. The captured owner
/// and worker use the admitted pending semantic lane and its bounded send claim.
/// This is one send attempt, not a remote ACK; failure neither retries the
/// write nor undoes the committed grant or its local approval reevaluation.
async fn send_pending_role_grant(
    state: &Arc<EngineState>,
    target: &str,
    fact: &SignedFact,
) -> Option<PeerOwnerToken> {
    let owner = state.peers.owner(target)?;
    let owner = state
        .peers
        .with_current(&owner, |peer| {
            let data = peer.state.read();
            if !data.authenticated || !matches!(data.status, PeerStatus::PendingApproval) {
                return None;
            }
            let worker = peer.current_worker()?;
            Some(owner.for_worker(worker))
        })
        .flatten()?;
    state.peers.get_if_current(&owner)?;
    if let Err(error) =
        super::send_pending_semantic_facts(state, &owner, std::slice::from_ref(fact)).await
    {
        tracing::debug!(peer = %target, %error, "pending RoleGrant send failed");
    }
    Some(owner)
}

/// Ask the exact current pending installation to run the ordinary approval
/// send/recheck after its canonical RoleGrant projection has committed.
async fn request_pending_approval(state: &Arc<EngineState>, peer_id: &str) {
    let Some(owner) = state.peers.owner(peer_id) else {
        return;
    };
    let pending = state.peers.with_current(&owner, |peer| {
        let data = peer.state.read();
        data.authenticated && matches!(data.status, PeerStatus::PendingApproval)
    });
    if pending == Some(true) {
        super::handshake::reevaluate_after_role_grant(state, &owner).await;
    }
}

fn diag(state: &Arc<EngineState>, level: crate::events::DiagLevel, msg: impl Into<String>) {
    state.log_diag(level, "governance", msg);
}

// ---- local proposals ------------------------------------------------

/// Admit, project, and publish one already-typed canonical governance fact.
/// The read-only roster projection is refreshed only after durable graph
/// admission.
async fn commit_proposal(
    state: &Arc<EngineState>,
    body: FactBody,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    crate::custody::require(&state.network_id, mfa_code)?;
    let fact = signed_fact(state, body, Vec::new())?;
    let delta = admit_authored_fact(state, &fact).await?;
    let (_, projected) = apply_canonical_projection_delta_with_projection(state, &delta)?;
    #[cfg(feature = "transport-lab")]
    let _post_commit_broadcast_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::PostCommitBroadcast,
    );
    broadcast_fact_inventory_delta(state, &delta).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    #[cfg(feature = "transport-lab")]
    drop(_post_commit_broadcast_phase);
    if let FactBody::RoleGrant { target, role } = &fact.content.body {
        if *role == crate::semantic::Role::Member
            && projected.roles.get(&pk(target)) == Some(&crate::semantic::Role::Member)
        {
            if let Some(owner) = send_pending_role_grant(state, target, &fact).await {
                super::handshake::reevaluate_after_role_grant(state, &owner).await;
            }
        }
    }
    Ok(fact.id)
}

/// Author and publish an exact canonical role grant.
pub async fn propose_role_grant(
    state: &Arc<EngineState>,
    target: &str,
    role: crate::semantic::Role,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::RoleGrant {
            target: canonical_device(target)?,
            role,
        },
        mfa_code,
    )
    .await
}

/// Author and publish an exact canonical role revoke.
pub async fn propose_role_revoke(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::RoleRevoke {
            target: canonical_device(target)?,
        },
        mfa_code,
    )
    .await
}

/// Author and publish an exact canonical eviction.
pub async fn propose_evict(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    commit_proposal(
        state,
        FactBody::Evict {
            target: canonical_device(target)?,
        },
        mfa_code,
    )
    .await
}

/// Author and broadcast the owner-signed membership restoration fact used
/// after a Closed eviction. Membership admission and the role grant remain
/// separate canonical cells; callers must issue the causal RoleGrant(Member)
/// afterward when session authority is also being restored.
pub async fn propose_membership_admit(
    state: &Arc<EngineState>,
    target: &str,
    mfa_code: Option<&str>,
) -> Result<FactId> {
    crate::custody::require(&state.network_id, mfa_code)?;
    let fact = signed_fact(
        state,
        FactBody::MembershipAdmit {
            target: canonical_device(target)?,
        },
        Vec::new(),
    )?;
    let delta = admit_authored_fact(state, &fact).await?;
    apply_canonical_projection_delta_checked(state, &delta)?;
    #[cfg(feature = "transport-lab")]
    let _post_commit_broadcast_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::PostCommitBroadcast,
    );
    broadcast_fact_inventory_delta(state, &delta).await;
    broadcast(state, MeshMessage::Fact(fact.clone())).await;
    #[cfg(feature = "transport-lab")]
    drop(_post_commit_broadcast_phase);
    Ok(fact.id)
}

/// Publish one already-durable semantic delta without passing its facts back
/// through admission. A group commit may include both the requested fact and
/// quarantine promotions; the sparse projection is applied once, and every
/// changed fact gets the same post-commit lifecycle handling as an ordinary
/// single admission.
pub(super) async fn on_committed_facts(
    state: &Arc<EngineState>,
    facts: Vec<SignedFact>,
    delta: crate::semantic::SemanticDelta,
) {
    if facts.is_empty() {
        return;
    }
    if let Err(error) = apply_canonical_projection_delta_checked(state, &delta) {
        diag(
            state,
            crate::events::DiagLevel::Warn,
            format!("rejecting semantic fact projection: {error}"),
        );
        return;
    }
    // Fact admission is the explicit lifecycle boundary for terminal recovery.
    // Refresh the local stand-down cache, then reconcile only the subject whose
    // canonical cell may have changed. Recovery never waits for a ticker to
    // discover that signed policy has become negative.
    refresh_self_evicted(state);
    for fact in &facts {
        match &fact.content.body {
            FactBody::RoleGrant { target, .. }
            | FactBody::RoleRevoke { target }
            | FactBody::Evict { target }
            | FactBody::MembershipAdmit { target }
            | FactBody::EvictionProof { target, .. }
            | FactBody::Attestation { target, .. } => {
                super::reconcile_terminal_recovery_policy(state, target);
            }
            FactBody::SelfStandDown { device_id, .. } => {
                super::reconcile_terminal_recovery_policy(state, device_id);
            }
            FactBody::Resolution { cell, .. } => match cell {
                crate::semantic::ExclusiveCell::Role { subject }
                | crate::semantic::ExclusiveCell::Membership { subject } => {
                    super::reconcile_terminal_recovery_policy(state, subject);
                }
                crate::semantic::ExclusiveCell::Decision { .. } => {}
            },
            FactBody::AuthorityLineageResolution { subject, .. } => {
                super::reconcile_terminal_recovery_policy(state, subject);
            }
        }
    }
    #[cfg(feature = "transport-lab")]
    let _post_commit_broadcast_phase = crate::semantic::store::AdmissionPhaseGuard::new(
        crate::semantic::store::AdmissionPhase::PostCommitBroadcast,
    );
    broadcast_fact_inventory_delta(state, &delta).await;
    #[cfg(feature = "transport-lab")]
    drop(_post_commit_broadcast_phase);
    for fact in facts {
        match &fact.content.body {
            FactBody::RoleGrant { target, .. } if pk(target) == pk(state.identity.public_id()) => {
                request_pending_approval(state, &fact.content.author).await;
            }
            _ => {}
        }
    }
}

// ---- eviction enforcement -------------------------------------------
//
// The signed log is a closed network's tombstone: an `Evict` in the
// member tier is the durable, verifiable "this device is OUT." What was
// missing was ENFORCEMENT at the boundary — an evicted device that never
// heard the news (offline during the evict) redialed forever, and the
// handshake treated it as a fresh face: pending-approval nudges at best,
// and on an auto-approve network (every fleet mesh) it was re-approved,
// re-rostered on mutual ACTIVE, and re-gossiped — resurrection on a loop.
// The three pieces below close that loop: the verdict helpers, the
// deny-with-proof at the handshake, and the self-evicted quiescence.

/// Whether `device_id`'s pubkey is explicitly evicted by this network's
/// signed state. Only meaningful on closed governance (open networks have no
/// signed membership); false there. The verdict is derived from the sealed
/// semantic membership projection, so roster data cannot outrank the canonical
/// graph.
pub(super) fn log_evicted(state: &Arc<EngineState>, device_id: &str) -> bool {
    if matches!(
        state.verified_bootstrap().policy(),
        crate::semantic::VerifiedProjectPolicy::Open
    ) {
        return false;
    }
    canonical_projection_snapshot(state)
        .evicted
        .contains(&pk(device_id))
}

/// Recompute and cache whether the signed state has evicted THIS device
/// (see [`EngineState::self_evicted`]). Called at driver startup and
/// after every log adoption/ratification, so the verdict tracks the
/// signed state in both directions: an eviction stands the engine down
/// (announce/dial gates read the flag), and a later re-admit — the
/// owner re-claiming the device signs a fresh member grant — clears it
/// and the network comes back to life without a restart.
///
/// On the false→true edge this also clears every standing dial
/// (reconnect intents, sticky dials) and emits the `governance` /
/// `self_evicted` diag event — the signal an embedding app (AllMyStuff)
/// uses to tear down its fleet state cleanly.
pub(crate) fn refresh_self_evicted(state: &Arc<EngineState>) {
    use std::sync::atomic::Ordering;
    let verdict = log_evicted(state, state.identity.public_id());
    let was = state.self_evicted.swap(verdict, Ordering::SeqCst);
    if verdict && !was {
        // Ratification and adopted-log refreshes can reach this edge without
        // passing through the mod.rs subject reconciler.  Detach the current
        // exact carrier guards before clearing recovery custody so a stale
        // source cannot retain or settle an emission after self-eviction.
        state.detach_signaling_guards();
        state.cancel_all_recovery_demands();
        state.reconnect_intents.lock().clear();
        state.sticky_peers.lock().clear();
        state.log_diag_with(
            crate::events::DiagLevel::Warn,
            "governance",
            "this device was EVICTED from the network by its signed governance — standing down \
             (no more announces or dials here; a re-admit revives it)",
            serde_json::json!({
                "hint": "self_evicted",
                "network": state.network_id.clone(),
            }),
        );
    } else if !verdict && was {
        state.log_diag(
            crate::events::DiagLevel::Info,
            "governance",
            "re-admitted by the signed governance — this network is live again",
        );
    }
}

/// The handshake gate: if the authenticated `device_id` is evicted by
/// our signed state and deny it.
/// and drop the session. Returns true when the peer was denied — the
/// caller must stop the admission flow (no pending-approval, no
/// auto-approve; those were exactly the resurrection engine). The signed
/// eviction closure is sent over the durable semantic lane before the denial,
/// so the denied device can verify it independently through causal admission;
/// a spoofed transport deny still changes nothing.
pub(super) async fn deny_if_evicted(
    state: &Arc<EngineState>,
    owner: &super::peer_registry::PeerOwnerToken,
) -> bool {
    let device_id = owner.device_id();
    if !log_evicted(state, device_id) {
        return false;
    }
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "governance",
        format!(
            "denied {} — evicted by the signed state (proof attached so it can stand down)",
            &device_id[..device_id.len().min(12)]
        ),
        serde_json::json!({ "peer": device_id, "reason": "evicted" }),
    );
    // Deliver the signed eviction closure before ending this installation.
    // Pending peers use the narrow semantic lane; an already-active test/lab
    // installation uses the ordinary application lane. Both are owner-bound,
    // provider-funded writes, and either refusal leaves the proof available for
    // the next inventory/request exchange rather than changing the decision.
    if let Some(bundle) = current_eviction_proof_bundle(state, device_id) {
        let message = FactPageMessage::new(state.mesh_context_id(), bundle.clone(), None, true)
            .map(MeshMessage::FactPage);
        let proof_result = match super::send_pending_semantic_facts(state, owner, &bundle).await {
            Ok(()) => Ok(()),
            Err(_) => match message {
                Ok(message) => super::send_to_peer_owner(state, owner, &message).await,
                Err(error) => Err(Error::Other(format!(
                    "eviction proof fact page refused: {error}"
                ))),
            },
        };
        if let Err(error) = proof_result {
            tracing::debug!(
                peer = %device_id,
                %error,
                "eviction proof bundle delivery failed"
            );
        }
    }
    let deny = MeshMessage::Deny(crate::protocol::DenyMessage {
        reason: Some(crate::protocol::DENY_REASON_EVICTED.to_string()),
    });
    // One attempt, and the attempt's return is the boundary. The proof is
    // best-effort diagnostic material rather than authority — the peer is
    // already denied by the current policy projection — so nothing here waits
    // for it to be received, acknowledged, or retried, and no elapsed duration
    // participates in the drop.
    if let Err(e) = super::send_to_peer_owner(state, owner, &deny).await {
        tracing::debug!(peer = %device_id, err = %e, "eviction deny send failed");
    }
    // Owner-bound, so a peer that was already replaced under the same Device ID
    // keeps its successor: `drop_peer_if_current` drops nothing when this token
    // is no longer the current one.
    super::drop_peer_if_current(state, owner, DropReason::Denied).await;
    true
}

/// Controls for semantic proof forwarding.
#[cfg(test)]
mod governance_projection_controls {
    use super::*;

    fn policy_device(key: &ed25519_dalek::SigningKey) -> DeviceId {
        let canonical = data_encoding::BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_ascii_lowercase();
        DeviceId::from_canonical_str_uninterned(&canonical).expect("frame-owned canonical identity")
    }

    fn assert_policy_parity(
        bootstrap: &crate::semantic::VerifiedBootstrap,
        graph: &crate::semantic::FactGraph,
        local: &DeviceId,
        remote: &DeviceId,
        expected: bool,
    ) {
        // Exercise borrowed frame-owned identities before the compatibility
        // wrapper performs its intentionally unchanged ordinary interning.
        assert_eq!(
            canonical_policy_admits_devices(bootstrap, graph, local, remote),
            expected
        );
        assert_eq!(
            canonical_policy_admits_from(bootstrap, graph, local, remote),
            expected
        );
    }

    fn signed_policy_fact(
        graph: &crate::semantic::FactGraph,
        key: &ed25519_dalek::SigningKey,
        body: FactBody,
    ) -> SignedFact {
        let author = policy_device(key);
        let witness = graph.authoring_witness(&body, &author);
        let content =
            FactContent::from_authoring_witness(graph, body, &witness, std::iter::empty());
        SignedFact::sign(content, key).expect("real policy fact signs")
    }

    fn admit_policy_fact(
        graph: &mut crate::semantic::FactGraph,
        key: &ed25519_dalek::SigningKey,
        body: FactBody,
    ) -> FactId {
        let fact = signed_policy_fact(graph, key, body);
        let id = fact.id;
        assert_eq!(graph.admit(fact), Ok(crate::semantic::Admission::Inserted));
        id
    }

    #[test]
    fn canonical_policy_typed_open_parity_and_string_validation() {
        let bootstrap = crate::semantic::VerifiedBootstrap::open("typed-policy-open").unwrap();
        let graph = crate::semantic::FactGraph::from_bootstrap(&bootstrap);
        let local = policy_device(&ed25519_dalek::SigningKey::from_bytes(&[0xb1; 32]));
        let remote = policy_device(&ed25519_dalek::SigningKey::from_bytes(&[0xb2; 32]));
        assert_policy_parity(&bootstrap, &graph, &local, &remote, true);
        assert_policy_parity(&bootstrap, &graph, &remote, &local, true);
        assert_policy_parity(&bootstrap, &graph, &local, &local, false);
        let foreign = crate::semantic::VerifiedBootstrap::open("typed-policy-foreign").unwrap();
        assert_ne!(bootstrap.context_id(), foreign.context_id());
        assert_policy_parity(&foreign, &graph, &local, &remote, false);
        for invalid in [
            String::new(),
            local.to_ascii_uppercase(),
            format!("{local}-label"),
        ] {
            assert!(!canonical_policy_admits_from(
                &bootstrap, &graph, &invalid, &remote
            ));
            assert!(!canonical_policy_admits_from(
                &bootstrap, &graph, &remote, &invalid
            ));
        }
        // Open has no durable fact domain; do not manufacture an Open graph
        // stand-down projection through a test-only authority bypass.
    }

    #[test]
    fn canonical_policy_typed_closed_parity_role_and_stand_down() {
        let root_key = ed25519_dalek::SigningKey::from_bytes(&[0xb3; 32]);
        let other_key = ed25519_dalek::SigningKey::from_bytes(&[0xb4; 32]);
        let member_key = ed25519_dalek::SigningKey::from_bytes(&[0xb5; 32]);
        let local = policy_device(&root_key);
        let remote = policy_device(&other_key);
        let member = policy_device(&member_key);
        let bootstrap = crate::semantic::VerifiedBootstrap::create_closed(
            "typed-policy-closed",
            vec![root_key.clone()],
            [0xb6; 32],
        )
        .unwrap();
        let mut graph = crate::semantic::FactGraph::from_bootstrap(&bootstrap);
        assert_policy_parity(&bootstrap, &graph, &local, &remote, false);
        admit_policy_fact(
            &mut graph,
            &root_key,
            FactBody::RoleGrant {
                target: remote.clone(),
                role: crate::semantic::Role::Member,
            },
        );
        assert_policy_parity(&bootstrap, &graph, &local, &remote, true);
        assert_policy_parity(&bootstrap, &graph, &local, &local, false);
        assert_policy_parity(&bootstrap, &graph, &local, &member, false);
        assert_policy_parity(&bootstrap, &graph, &member, &local, false);
        let foreign = crate::semantic::VerifiedBootstrap::create_closed(
            "typed-policy-closed",
            vec![root_key.clone()],
            [0xb7; 32],
        )
        .unwrap();
        assert_ne!(bootstrap.context_id(), foreign.context_id());
        assert_policy_parity(&foreign, &graph, &local, &remote, false);
        admit_policy_fact(
            &mut graph,
            &root_key,
            FactBody::RoleGrant {
                target: member.clone(),
                role: crate::semantic::Role::Member,
            },
        );
        assert_policy_parity(&bootstrap, &graph, &local, &member, true);
        assert_policy_parity(&bootstrap, &graph, &member, &local, true);
        assert!(!graph.evaluator().is_stood_down(&remote));

        // Match the real causal evaluator proof chain: same-target eviction,
        // authorized member attestation, root-authored proof, then the
        // target's own acknowledgement of that proof. Empty or invented
        // evidence cannot reach signing/admission.
        let proposal = admit_policy_fact(
            &mut graph,
            &root_key,
            FactBody::Evict {
                target: remote.clone(),
            },
        );
        let attestation = admit_policy_fact(
            &mut graph,
            &member_key,
            FactBody::Attestation {
                target: remote.clone(),
                proposal,
                decision: crate::semantic::AttestationDecision::Evict,
                signer: member.clone(),
                contributions: Vec::new(),
            },
        );
        let proof = admit_policy_fact(
            &mut graph,
            &root_key,
            FactBody::EvictionProof {
                target: remote.clone(),
                evidence: vec![attestation],
            },
        );
        // The proof already stands the target down; SelfStandDown does not
        // newly revoke an otherwise admitted endpoint.
        assert!(graph.evaluator().is_stood_down(&remote));
        assert_policy_parity(&bootstrap, &graph, &local, &remote, false);
        assert_policy_parity(&bootstrap, &graph, &remote, &local, false);
        assert!(matches!(
            &graph.get(&proof).expect("eviction proof was admitted").content.body,
            FactBody::EvictionProof { target, evidence }
                if target == &remote && evidence.as_slice() == [attestation]
        ));
        let stand_down = signed_policy_fact(
            &graph,
            &other_key,
            FactBody::SelfStandDown {
                device_id: remote.clone(),
                evidence: vec![proof],
            },
        );
        let stand_down_id = stand_down.id;
        assert!(graph.get(&stand_down_id).is_none());
        // Compare the complete existing persistence representation, including
        // signed bodies, quarantine, indexes, counters, revisions, generation
        // and projection. This in-memory fixture performs no SQLite writes.
        let before = serde_json::to_vec(&graph.live_checkpoint()).expect("checkpoint encodes");
        assert_eq!(
            graph.admit(stand_down),
            Err(crate::semantic::SemanticError::NoOp(
                "stand-down is already effective"
            ))
        );
        assert!(graph.get(&stand_down_id).is_none());
        assert_eq!(
            serde_json::to_vec(&graph.live_checkpoint()).expect("checkpoint encodes"),
            before
        );
        assert!(!graph.evaluator().is_stood_down(&local));
        assert!(graph.evaluator().is_stood_down(&remote));
        assert_policy_parity(&bootstrap, &graph, &local, &remote, false);
        assert_policy_parity(&bootstrap, &graph, &remote, &local, false);
        assert_policy_parity(&bootstrap, &graph, &local, &member, true);
    }

    static CONCURRENT_LANE_FIXTURE: std::sync::atomic::AtomicU64 =
        std::sync::atomic::AtomicU64::new(0);

    #[tokio::test]
    async fn concurrent_role_grants_use_one_bounded_durable_lane() {
        let fixture_id = CONCURRENT_LANE_FIXTURE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let state = crate::engine::build_test_closed_state(
            &format!(
                "concurrent-role-grant-lane-{}-{fixture_id}",
                std::process::id()
            ),
            [0x43; 32],
        );
        let target_a = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let target_b = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();

        let (grant_a, grant_b) = tokio::join!(
            propose_role_grant(&state, &target_a, crate::semantic::Role::Member, None),
            propose_role_grant(&state, &target_b, crate::semantic::Role::Member, None),
        );
        assert!(
            grant_a.is_ok(),
            "first concurrent grant failed: {grant_a:?}"
        );
        assert!(
            grant_b.is_ok(),
            "second concurrent grant failed: {grant_b:?}"
        );
        assert_eq!(
            state.durable_admission_max_for_test(),
            1,
            "the blocking admission lane must never run two workers at once"
        );
    }

    #[tokio::test]
    async fn eviction_proof_bundle_contains_the_exact_causal_closure() {
        let state = crate::engine::build_test_closed_state("eviction-proof-bundle", [10; 32]);
        let target = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let evict_id = propose_evict(&state, &target, None)
            .await
            .expect("the verified root can author an eviction");

        let bundle = current_eviction_proof_bundle(&state, &target)
            .expect("a current eviction has a deliverable proof closure");
        let bundle_ids: BTreeSet<_> = bundle.iter().map(|fact| fact.id).collect();
        assert!(bundle_ids.contains(&evict_id));
        assert!(
            bundle.iter().all(|fact| {
                crate::semantic::causal::dependencies(fact)
                    .into_iter()
                    .all(|dependency| bundle_ids.contains(&dependency))
            }),
            "an offline proof bundle must carry every causal dependency"
        );
    }

    #[test]
    fn projection_persistence_failure_is_returned_before_roster_commit() {
        let state = crate::engine::build_test_closed_state("projection-save-failure", [0x2a; 32]);
        state.roster.write().authorized_devices.clear();

        let attempted = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let attempted_by_save = Arc::clone(&attempted);
        let error = apply_canonical_projection_with(&state, move |_, _| {
            attempted_by_save.store(true, std::sync::atomic::Ordering::SeqCst);
            Err(Error::Roster(
                "injected projection persistence failure".into(),
            ))
        })
        .expect_err("projection persistence failure must reach the caller");
        assert!(attempted.load(std::sync::atomic::Ordering::SeqCst));
        assert!(matches!(error, Error::Roster(_)));
        assert!(state.roster.read().authorized_devices.is_empty());

        let changed = apply_canonical_projection_with(&state, |_, _| Ok(()))
            .expect("a successful persistence boundary must commit the projection");
        assert!(changed);
        assert!(!state.roster.read().authorized_devices.is_empty());
    }

    #[tokio::test]
    async fn role_projection_skips_persistence_and_metadata_failure_is_returned() -> Result<()> {
        let state = crate::engine::build_test_closed_state("indexed-roster-delta", [0x2c; 32]);
        let first_target = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let second_target = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        propose_role_grant(&state, &first_target, crate::semantic::Role::Member, None)
            .await
            .expect("first target grant admits");
        propose_role_grant(&state, &second_target, crate::semantic::Role::Member, None)
            .await
            .expect("second target grant admits");
        {
            let mut roster = state.roster.write();
            for index in 0..2_048 {
                crate::roster::add_peer_in(
                    &mut roster,
                    &format!("unrelated-{index:04}"),
                    "unrelated",
                );
            }
        }

        let second_fact = signed_fact(
            &state,
            FactBody::RoleGrant {
                target: canonical_device(&first_target).expect("first target is canonical"),
                role: crate::semantic::Role::Controller,
            },
            Vec::new(),
        )?;
        let (_, _, second_delta) = state
            .admit_fact_durably_with_delta_async(second_fact)
            .await
            .expect("second target role change admits");
        crate::roster::AuthorizedDevices::reset_test_counters();
        let roster_role = |target: &str| -> Option<crate::semantic::Role> {
            let pubkey = crate::signing::pubkey_part(target);
            let roster = state.roster.read();
            let entries: &[crate::roster::AuthorizedPeer] =
                std::ops::Deref::deref(&roster.authorized_devices);
            entries
                .iter()
                .find(|peer| peer.device_id == pubkey)
                .map(|peer| peer.role)
        };
        let before_success = serde_json::to_vec(&*state.roster.read()).expect("roster serializes");
        let role_save_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let role_save_calls_by_save = Arc::clone(&role_save_calls);
        let (changed, _) = apply_canonical_projection_delta_with_projection_and_save(
            &state,
            &second_delta,
            move |_, _| {
                role_save_calls_by_save.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(Error::Roster(
                    "role-only projection must not persist".into(),
                ))
            },
        )
        .expect("indexed existing-subject role projection succeeds without persistence");
        assert!(changed);
        assert_eq!(
            role_save_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "role-only projection must not enter the persistence path"
        );
        assert_eq!(
            crate::roster::AuthorizedDevices::test_counters(),
            (0, 0),
            "existing-subject role change must not scan or rebuild the roster"
        );
        assert_eq!(
            serde_json::to_vec(&*state.roster.read()).expect("roster serializes"),
            before_success,
            "role-only projection metadata is intentionally not serialized"
        );
        assert_eq!(
            roster_role(&first_target),
            Some(crate::semantic::Role::Controller),
            "the role change updates the keyed in-memory row"
        );

        // A second role-only projection must remain on the same no-persistence
        // path.  This catches an implementation that skips the first write but
        // accidentally rewrites the advisory row on a later role transition.
        let third_fact = signed_fact(
            &state,
            FactBody::RoleGrant {
                target: canonical_device(&first_target).expect("first target is canonical"),
                role: crate::semantic::Role::Owner,
            },
            Vec::new(),
        )?;
        let (_, _, third_delta) = state
            .admit_fact_durably_with_delta_async(third_fact)
            .await
            .expect("repeated role-only change admits");
        let repeated_role_save_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let repeated_role_save_calls_by_save = Arc::clone(&repeated_role_save_calls);
        let (changed, _) = apply_canonical_projection_delta_with_projection_and_save(
            &state,
            &third_delta,
            move |_, _| {
                repeated_role_save_calls_by_save.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                Err(Error::Roster(
                    "repeated role-only projection must not persist".into(),
                ))
            },
        )
        .expect("repeated role-only projection remains persistence-free");
        assert!(changed);
        assert_eq!(
            repeated_role_save_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "repeated role-only projection must not enter the persistence path"
        );
        assert_eq!(
            roster_role(&first_target),
            Some(crate::semantic::Role::Owner),
            "the repeated role change updates the keyed in-memory row"
        );

        let stale_target = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        crate::roster::add_peer_in(&mut state.roster.write(), &stale_target, "stale");
        let before_failure = serde_json::to_vec(&*state.roster.read()).expect("roster serializes");
        crate::roster::AuthorizedDevices::reset_test_counters();
        let error = match apply_canonical_projection_with(&state, |_, _| {
            Err(Error::Roster(
                "injected projection persistence failure".into(),
            ))
        }) {
            Ok(_) => panic!("injected save failure must reach the caller"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::Roster(_)));
        assert_eq!(
            serde_json::to_vec(&*state.roster.read()).expect("roster serializes"),
            before_failure,
            "a real persisted-byte refusal preserves exact serialized bytes"
        );
        assert_eq!(
            roster_role(&first_target),
            Some(crate::semantic::Role::Owner),
            "a metadata persistence refusal does not disturb the live role projection"
        );
        Ok(())
    }

    #[test]
    fn startup_projection_rebuilds_role_from_graph_without_roster_write() {
        let state = crate::engine::build_test_closed_state("projection-restart-role", [0x2d; 32]);
        let root = state.identity.public_id().to_string();
        assert!(crate::roster::is_authorized(&state.roster.read(), &root));
        crate::roster::set_role_in(
            &mut state.roster.write(),
            &root,
            crate::semantic::Role::Member,
        );
        let before = serde_json::to_vec(&*state.roster.read()).expect("roster serializes");
        let save_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let save_calls_by_save = Arc::clone(&save_calls);
        let changed = apply_canonical_projection_with(&state, move |_, _| {
            save_calls_by_save.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(Error::Roster(
                "startup role reconstruction must not persist".into(),
            ))
        })
        .expect("startup projection rebuilds the role from canonical state");
        assert!(changed);
        assert_eq!(
            save_calls.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "canonical role restoration must not rewrite advisory metadata"
        );
        let root_pubkey = crate::signing::pubkey_part(&root);
        let role = state
            .roster
            .read()
            .authorized_devices
            .iter()
            .find(|peer| peer.device_id == root_pubkey)
            .map(|peer| peer.role);
        assert_eq!(
            role,
            Some(crate::semantic::Role::Owner),
            "restart projection must derive the authority tier from the graph"
        );
        assert_eq!(
            serde_json::to_vec(&*state.roster.read()).expect("roster serializes"),
            before,
            "rebuilding a derived role leaves persisted roster bytes unchanged"
        );
    }

    #[test]
    fn full_projection_reconciliation_includes_removed_disk_keys() {
        let state = crate::engine::build_test_closed_state("projection-stale-key", [0x2b; 32]);
        let stale = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        crate::roster::add_peer_in(&mut state.roster.write(), &stale, "stale");
        let captured = Arc::new(std::sync::Mutex::new(None));
        let captured_by_save = Arc::clone(&captured);
        let changed = apply_canonical_projection_with(&state, move |_, affected| {
            *captured_by_save.lock().unwrap() = Some(affected.clone());
            Ok(())
        })
        .expect("projection reconciliation succeeds");
        assert!(
            changed,
            "the stale advisory row is removed from the candidate"
        );
        assert!(captured
            .lock()
            .unwrap()
            .as_ref()
            .is_some_and(|keys| keys.contains(&crate::signing::pubkey_part(&stale).to_string())));
        assert!(!crate::roster::is_authorized(&state.roster.read(), &stale));
    }

    #[test]
    fn fact_inventory_cursor_streams_receive_safe_pages_and_reaches_quiescence() {
        let state = crate::engine::build_test_state("fact-inventory-cursor-controls");
        let context_id = state.mesh_context_id();
        let author = DeviceId::from_canonical_str(state.identity.public_id())
            .expect("fixture identity is canonical");
        let mut graph = crate::semantic::FactGraph::from_bootstrap(state.verified_bootstrap());

        // Use valid signed facts in a real graph, while varying only the
        // causal parent so the producer sees a large deterministic key set.
        // The cursor itself retains no graph-wide collection.
        for index in 0..2_048u64 {
            let mut parent = [0u8; 32];
            parent[..8].copy_from_slice(&index.to_be_bytes());
            let content = FactContent::new(
                crate::semantic::FactDomain::Governance,
                context_id,
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: crate::semantic::Role::Member,
                },
                author.clone(),
                vec![FactId::from_bytes(parent)],
            );
            let fact = SignedFact::sign(content, state.identity.signing_key())
                .expect("fixture fact signs");
            graph.facts.insert(fact.id, fact);
        }
        let expected_ids = graph.ids().count();
        let graph = Arc::new(parking_lot::RwLock::new(graph));
        let mut cursor = FactInventoryCursor {
            source: FactInventorySource::Graph(graph),
            context_id,
            cursor: None,
            finished: false,
            invalid: false,
            visited_candidates: 0,
        };
        let mut page_count = 0;
        let mut observed = BTreeSet::new();
        let mut first_page = None;

        while let Some(page) = cursor.next_page() {
            page_count += 1;
            if first_page.is_none() {
                first_page = Some(page.clone());
            }
            let encoded = serde_json::to_vec(&MeshMessage::FactInventory(page.clone()))
                .expect("inventory page serializes");
            assert!(encoded.len() <= crate::protocol::RECEIVE_FRAME_BYTES);
            assert!(page.fact_ids().windows(2).all(|pair| pair[0] < pair[1]));
            observed.extend(page.fact_ids().iter().copied());
        }

        assert!(cursor.is_valid());
        assert!(page_count >= 2, "control must exercise multiple pages");
        assert_eq!(observed.len(), expected_ids);
        assert!(
            cursor.visited_candidates() >= expected_ids
                && cursor.visited_candidates() <= expected_ids + page_count,
            "inventory sizing visits each candidate once plus at most one lookahead per page"
        );
        let first_page = first_page.expect("the nonempty graph produces a first page");
        let first_len = serde_json::to_vec(&MeshMessage::FactInventory(first_page.clone()))
            .expect("the exact-boundary page serializes")
            .len();
        let next_id = {
            let FactInventorySource::Graph(graph) = &cursor.source else {
                panic!("unit cursor uses the graph source");
            };
            let graph = graph.read();
            let candidate = graph
                .ids_after(first_page.fact_ids().last().copied())
                .next()
                .copied()
                .expect("the control has a max-plus-one candidate");
            candidate
        };
        let mut max_plus_one_ids = first_page.fact_ids().to_vec();
        max_plus_one_ids.push(next_id);
        let max_plus_one_len = serde_json::to_vec(&MeshMessage::FactInventory(FactInventory::new(
            context_id,
            max_plus_one_ids,
        )))
        .expect("the max-plus-one candidate serializes")
        .len();
        assert!(
            first_len <= crate::protocol::RECEIVE_FRAME_BYTES,
            "the exact maximum page fits the receive-safe boundary"
        );
        assert!(
            max_plus_one_len > crate::protocol::RECEIVE_FRAME_BYTES,
            "the max-plus-one candidate is refused before page construction"
        );
        assert!(
            cursor.next_page().is_none(),
            "a drained cursor is quiescent"
        );
    }

    #[test]
    fn delta_inventory_splits_bounded_pages_without_unrelated_ids() {
        let state = crate::engine::build_test_state("delta-inventory-page-controls");
        let mut delta = crate::semantic::SemanticDelta::default();
        let expected = (0..2_048u64)
            .map(|index| {
                let mut bytes = [0u8; 32];
                bytes[..8].copy_from_slice(&(index + 1).to_be_bytes());
                let id = FactId::from_bytes(bytes);
                delta.push_promoted_for_test(id);
                id
            })
            .collect::<BTreeSet<_>>();

        let pages = delta_inventory_pages(state.mesh_context_id(), &delta)
            .expect("all fixed-size IDs fit in bounded pages");
        assert!(
            pages.len() > 1,
            "control must exercise multiple delta pages"
        );
        let observed = pages
            .iter()
            .flat_map(|page| {
                let encoded = serde_json::to_vec(&MeshMessage::FactInventory(page.clone()))
                    .expect("inventory page serializes");
                assert!(encoded.len() <= crate::protocol::RECEIVE_FRAME_BYTES);
                assert!(page.fact_ids().windows(2).all(|pair| pair[0] < pair[1]));
                page.fact_ids().iter().copied()
            })
            .collect::<BTreeSet<_>>();
        assert_eq!(observed, expected);
    }

    #[test]
    fn delta_inventory_excludes_authenticated_pending_owners() {
        assert!(!inventory_owner_is_eligible(
            PeerStatus::PendingApproval,
            true,
            true
        ));
        assert!(!inventory_owner_is_eligible(
            PeerStatus::Active,
            false,
            true
        ));
        assert!(!inventory_owner_is_eligible(
            PeerStatus::Active,
            true,
            false
        ));
        assert!(inventory_owner_is_eligible(PeerStatus::Active, true, true));
        assert!(inventory_owner_is_eligible(PeerStatus::Shelved, true, true));
    }

    /// Exercise the real registry snapshot rather than testing the eligibility
    /// predicate in isolation.  The promoted fixtures retain their native
    /// workers and event receivers, so `current_worker()` is the same live
    /// worker the production inventory path observes.
    #[cfg(test)]
    #[tokio::test]
    #[ignore = "opens local WebRTC objects; run explicitly in the isolated harness"]
    async fn inventory_peer_owners_snapshots_only_live_authenticated_workers() {
        let state = crate::engine::build_test_state("inventory-owner-registry-control");

        let active = crate::engine::insert_promoted_peer(&state, "inventory-active").await;
        let shelved = crate::engine::insert_promoted_peer(&state, "inventory-shelved").await;
        shelved.peer.state.write().status = PeerStatus::Shelved;

        let pending = crate::engine::insert_promoted_peer(&state, "inventory-pending").await;
        pending.peer.state.write().status = PeerStatus::PendingApproval;

        let unauthenticated =
            crate::engine::insert_promoted_peer(&state, "inventory-unauthenticated").await;
        unauthenticated.peer.state.write().authenticated = false;

        crate::engine::insert_session_less_peer(&state, "inventory-no-worker", None);
        let no_worker = state
            .peers
            .get("inventory-no-worker")
            .expect("the connector-less peer was installed");
        {
            let mut data = no_worker.state.write();
            data.status = PeerStatus::Active;
            data.authenticated = true;
        }

        let mut observed = inventory_peer_owners(&state)
            .into_iter()
            .map(|owner| owner.device_id().to_string())
            .collect::<Vec<_>>();
        observed.sort();
        assert_eq!(
            observed,
            vec![
                "inventory-active".to_string(),
                "inventory-shelved".to_string()
            ]
        );

        // Keep every owner and receiver alive through the snapshot.  Dropping
        // one here would retire the native worker and make the control pass for
        // the wrong reason.
        drop((active, shelved, pending, unauthenticated, no_worker));
    }

    #[tokio::test]
    async fn delta_inventory_mixes_admitted_rows_and_promoted_ids() {
        let state =
            crate::engine::build_test_closed_state("delta-inventory-mixed-control", [0x42; 32]);
        let target_a = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let target_b = crate::identity::Identity::ephemeral()
            .public_id()
            .to_string();
        let fact_a = signed_fact(
            &state,
            FactBody::RoleGrant {
                target: DeviceId::from_canonical_str(&target_a).expect("target A is canonical"),
                role: crate::semantic::Role::Member,
            },
            Vec::new(),
        )
        .expect("fact A signs");
        let fact_b = signed_fact(
            &state,
            FactBody::RoleGrant {
                target: DeviceId::from_canonical_str(&target_b).expect("target B is canonical"),
                role: crate::semantic::Role::Member,
            },
            Vec::new(),
        )
        .expect("fact B signs");
        let admitted_a = fact_a.id;
        let admitted_b = fact_b.id;
        let delta_a = admit_authored_fact(&state, &fact_a)
            .await
            .expect("fact A admits");
        let delta_b = admit_authored_fact(&state, &fact_b)
            .await
            .expect("fact B admits");
        let promoted_a = FactId::from_bytes([0xa1; 32]);
        let promoted_b = FactId::from_bytes([0xb2; 32]);
        assert_ne!(admitted_a, promoted_a);
        assert_ne!(admitted_b, promoted_b);

        let mut delta = crate::semantic::SemanticDelta::default();
        // Use rows returned by real durable admissions, then deliberately
        // reverse them and repeat/reorder the promoted IDs.  The page builder
        // must canonicalize the union rather than preserve producer insertion
        // order or emit duplicates.
        for row in delta_b.rows().iter().chain(delta_a.rows().iter()) {
            delta.push_row_for_test(row.clone());
        }
        delta.push_promoted_for_test(promoted_b);
        delta.push_promoted_for_test(admitted_a);
        delta.push_promoted_for_test(promoted_a);
        delta.push_promoted_for_test(admitted_b);
        delta.push_promoted_for_test(promoted_b);
        delta.push_promoted_for_test(admitted_a);

        let pages = delta_inventory_pages(state.mesh_context_id(), &delta)
            .expect("the mixed bounded delta fits");
        let observed = pages
            .iter()
            .flat_map(|page| {
                let encoded = serde_json::to_vec(&MeshMessage::FactInventory(page.clone()))
                    .expect("inventory page serializes");
                assert!(encoded.len() <= crate::protocol::RECEIVE_FRAME_BYTES);
                assert!(page.fact_ids().windows(2).all(|pair| pair[0] < pair[1]));
                page.fact_ids().iter().copied()
            })
            .collect::<Vec<_>>();
        let expected = BTreeSet::from([admitted_a, admitted_b, promoted_a, promoted_b]);
        assert_eq!(observed, expected.iter().copied().collect::<Vec<_>>());
        assert_eq!(observed.iter().copied().collect::<BTreeSet<_>>(), expected);
        assert!(!observed.contains(&FactId::from_bytes([0xc3; 32])));
    }
}
