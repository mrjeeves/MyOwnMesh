#![cfg(feature = "transport-lab")]

//! Production-shaped R3 controls for durable stand-down proof delivery.
//!
//! These controls intentionally use the state-owned transport-lab façade and
//! proof-wire APIs from the proof-delivery lane.  The façade keeps each test
//! on the same durable semantic slot as production.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SignalingConfig,
    TopologyMode,
};
use myownmesh_core::engine::transport_lab::{
    admit_durable_proof, durable_proof_records, materialize_durable_proof_delivery,
    pending_durable_proofs, promote_exact_owner_for_lab, proof_owner_for_device,
    rebind_durable_proof, rpc, settle_durable_proof_ack, supersede_durable_proof,
};
use myownmesh_core::engine::transport_lab::{
    attach_local, create_network_in_instance_root, import_network_in_instance_root,
    ingest_semantic_fact, spawn_network_in_instance_root,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::protocol::{ProofAckMessage, ProofDeliveryMessage};
use myownmesh_core::semantic::{
    AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactContent, FactGraph, ProofRecord,
    ProofRecordState, SignedFact, VerifiedBootstrap,
};
use myownmesh_core::CapabilityAdvert;
use myownmesh_signaling::local::LocalBroker;
use tempfile::TempDir;
use tokio::time::{Duration, Instant};

mod support;

fn closed_config(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: format!("{id}-wire"),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: NetworkKind::Closed,
        semantic_policy: Default::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        tree: None,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: true,
        closed_relay: ClosedRelayPolicyConfig::default(),
    }
}

fn device(identity: &Identity) -> DeviceId {
    DeviceId::from_canonical_str(identity.public_id()).expect("identity has canonical device id")
}

fn authored(graph: &FactGraph, signer: &Identity, body: FactBody) -> SignedFact {
    authored_with_support(graph, signer, body, std::iter::empty())
}

fn authored_with_support<I>(
    graph: &FactGraph,
    signer: &Identity,
    body: FactBody,
    support: I,
) -> SignedFact
where
    I: IntoIterator<Item = myownmesh_core::semantic::FactId>,
{
    let signer_id = device(signer);
    let witness = graph.authoring_witness(&body, &signer_id);
    let content = FactContent::from_authoring_witness(graph, body, &witness, support);
    SignedFact::sign(content, signer.signing_key()).expect("fixture fact signs")
}

/// Build a complete, causal eviction proof.  It is deliberately returned in
/// causal order so production ingestion can persist each fact before the next
/// one is admitted; the wire envelope re-sorts it by FactId independently.
fn stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    owner: &Identity,
    target: &Identity,
    member: &Identity,
) -> Vec<SignedFact> {
    let target_id = device(target);
    let member_id = device(member);
    let mut graph = FactGraph::from_bootstrap(bootstrap);

    let grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(grant.clone()).expect("target grant admits");

    let member_grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: member_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph
        .admit(member_grant.clone())
        .expect("member grant admits");

    let proposal = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
    );
    graph
        .admit(proposal.clone())
        .expect("eviction proposal admits");

    let attestation = authored(
        &graph,
        member,
        FactBody::Attestation {
            target: target_id.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: member_id,
            contributions: Vec::new(),
        },
    );
    graph
        .admit(attestation.clone())
        .expect("member eviction attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph.admit(proof.clone()).expect("eviction proof admits");

    vec![grant, member_grant, proposal, attestation, proof]
}

/// Extend an adopted eviction with a causal regrant and a distinct second
/// eviction. The second closure includes the first history, but its new
/// regrant/proposal/attestation/proof identities force a new delivery id.
fn reissued_stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
    member: &Identity,
) -> Vec<SignedFact> {
    let target_id = device(target);
    let member_id = device(member);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }

    let regrant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(regrant.clone()).expect("causal regrant admits");

    let proposal = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
    );
    graph
        .admit(proposal.clone())
        .expect("second eviction proposal admits");

    let attestation = authored(
        &graph,
        member,
        FactBody::Attestation {
            target: target_id.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: member_id,
            contributions: Vec::new(),
        },
    );
    graph
        .admit(attestation.clone())
        .expect("second eviction attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph
        .admit(proof.clone())
        .expect("second eviction proof admits");

    let mut facts = prior.to_vec();
    facts.extend([regrant, proposal, attestation, proof]);
    facts
}

fn regrant_after_eviction_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
) -> Vec<SignedFact> {
    let target_id = device(target);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }
    let membership = authored(
        &graph,
        owner,
        FactBody::MembershipAdmit {
            target: target_id.clone(),
        },
    );
    graph
        .admit(membership.clone())
        .expect("causal membership restoration admits");
    let role = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id,
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph
        .admit(role.clone())
        .expect("causal role restoration admits");
    vec![membership, role]
}

struct CrossTargetFacts {
    facts: Vec<SignedFact>,
    cross_target_evict: SignedFact,
    target_evict: SignedFact,
}

struct ConcurrentResolutionFacts {
    facts: Vec<SignedFact>,
    membership_admit: SignedFact,
    evict: SignedFact,
    resolution: SignedFact,
}

/// Build two concurrent membership decisions and resolve the exact Evict
/// branch.  Both decisions are authored from the same predecessor graph, so
/// the receiver must carry the typed Resolution and both cited heads rather
/// than relying on arrival order or a final boolean.
fn concurrent_evict_membership_resolution_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    resolver: &Identity,
    target: &Identity,
) -> ConcurrentResolutionFacts {
    let target_id = device(target);
    let resolver_id = device(resolver);
    let mut base = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        base.admit(fact).expect("prior eviction history admits");
    }

    let resolver_grant = authored(
        &base,
        owner,
        FactBody::RoleGrant {
            target: resolver_id,
            role: myownmesh_core::semantic::Role::Owner,
        },
    );
    base.admit(resolver_grant.clone())
        .expect("distinct Owner resolver grant admits");

    let membership_admit = authored(
        &base,
        owner,
        FactBody::MembershipAdmit {
            target: target_id.clone(),
        },
    );
    let evict = authored(
        &base,
        resolver,
        FactBody::Evict {
            target: target_id.clone(),
        },
    );
    let mut concurrent = base.clone();
    concurrent
        .admit(membership_admit.clone())
        .expect("concurrent MembershipAdmit admits");
    concurrent
        .admit(evict.clone())
        .expect("concurrent Evict admits");

    let cell = ExclusiveCell::membership(target_id);
    let mut cited_heads = concurrent.cell_heads(&cell);
    cited_heads.sort();
    assert!(cited_heads.contains(&membership_admit.id));
    assert!(cited_heads.contains(&evict.id));
    let resolution = authored(
        &concurrent,
        resolver,
        FactBody::Resolution {
            cell: cell.clone(),
            cited_heads,
            selected_head: evict.id,
        },
    );
    concurrent
        .admit(resolution.clone())
        .expect("typed Resolution selects the Evict branch");
    assert_eq!(
        concurrent.projection().value(&cell),
        Some(evict.id),
        "typed Resolution selects Evict rather than MembershipAdmit"
    );
    assert_eq!(
        concurrent.evaluator().effective_membership(&device(target)),
        Some(false),
        "the selected Evict branch remains terminal membership"
    );

    let mut facts = prior.to_vec();
    facts.extend([
        resolver_grant,
        membership_admit.clone(),
        evict.clone(),
        resolution.clone(),
    ]);
    ConcurrentResolutionFacts {
        facts,
        membership_admit,
        evict,
        resolution,
    }
}

/// Build a fresh target proof whose target Evict explicitly depends on an
/// Evict for a different device.  The dependency is carried through the real
/// authoring witness plus an exact causal support parent, so the receiver must
/// admit the cross-target fact before the target's terminal projection can
/// become authoritative.
fn cross_target_stand_down_facts(
    bootstrap: &VerifiedBootstrap,
    prior: &[SignedFact],
    owner: &Identity,
    target: &Identity,
    member: &Identity,
    cross_target: &Identity,
) -> CrossTargetFacts {
    let target_id = device(target);
    let member_id = device(member);
    let cross_target_id = device(cross_target);
    let mut graph = FactGraph::from_bootstrap(bootstrap);
    for fact in prior.iter().cloned() {
        graph.admit(fact).expect("prior eviction history admits");
    }

    let regrant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph.admit(regrant.clone()).expect("target regrant admits");

    let cross_grant = authored(
        &graph,
        owner,
        FactBody::RoleGrant {
            target: cross_target_id.clone(),
            role: myownmesh_core::semantic::Role::Member,
        },
    );
    graph
        .admit(cross_grant.clone())
        .expect("cross-target grant admits");

    let cross_target_evict = authored(
        &graph,
        owner,
        FactBody::Evict {
            target: cross_target_id,
        },
    );
    graph
        .admit(cross_target_evict.clone())
        .expect("cross-target eviction admits");

    let target_evict = authored_with_support(
        &graph,
        owner,
        FactBody::Evict {
            target: target_id.clone(),
        },
        [cross_target_evict.id],
    );
    assert!(
        myownmesh_core::semantic::causal::dependencies(&target_evict)
            .contains(&cross_target_evict.id),
        "target Evict carries the cross-target causal dependency"
    );
    graph
        .admit(target_evict.clone())
        .expect("cross-target target eviction admits");

    let attestation = authored(
        &graph,
        member,
        FactBody::Attestation {
            target: target_id.clone(),
            proposal: target_evict.id,
            decision: AttestationDecision::Evict,
            signer: member_id,
            contributions: Vec::new(),
        },
    );
    graph
        .admit(attestation.clone())
        .expect("cross-target target attestation admits");

    let proof = authored(
        &graph,
        owner,
        FactBody::EvictionProof {
            target: target_id,
            evidence: vec![attestation.id],
        },
    );
    graph
        .admit(proof.clone())
        .expect("cross-target target proof admits");

    let mut facts = prior.to_vec();
    facts.extend([
        regrant,
        cross_grant,
        cross_target_evict.clone(),
        target_evict.clone(),
        attestation,
        proof,
    ]);
    CrossTargetFacts {
        facts,
        cross_target_evict,
        target_evict,
    }
}

fn receiver_admits_delivery(
    bootstrap: &VerifiedBootstrap,
    delivery: &ProofDeliveryMessage,
) -> FactGraph {
    let mut receiver = FactGraph::from_bootstrap(bootstrap);
    for fact in delivery.facts.iter().cloned() {
        receiver
            .admit(fact)
            .expect("receiver durably admits proof fact");
    }
    receiver
        .retry_quarantined()
        .expect("receiver resolves proof dependencies");
    receiver
}

async fn create_fixture(
    root: &TempDir,
    id: &str,
) -> (
    Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    tokio::task::JoinHandle<()>,
    Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    tokio::task::JoinHandle<()>,
    Arc<Identity>,
    Identity,
    Identity,
    Vec<SignedFact>,
    myownmesh_core::semantic::MeshContextId,
    NetworkConfig,
    LocalBroker,
    TempDir,
) {
    let identity = Arc::new(Identity::ephemeral());
    let target = Identity::ephemeral();
    let member = Identity::ephemeral();
    let config = closed_config(id);
    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x73; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let facts = stand_down_facts(
        state.verified_bootstrap(),
        identity.as_ref(),
        &target,
        &member,
    );

    // Keep a real authenticated target installation in the sender registry so
    // the transport-lab façade can issue the exact owner witness used by
    // rebind/settle.  The target receives the grants but not the eviction
    // closure: it remains a live carrier while the sender adopts the proof.
    let target_root = TempDir::new().expect("target instance root");
    let target_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-target",
    ));
    let (target_state, target_driver) = import_network_in_instance_root(
        config.clone(),
        target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        state.verified_bootstrap().record().clone(),
    )
    .await
    .expect("target imports the exact bootstrap");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&state, fact.clone()).await;
        ingest_semantic_fact(&target_state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("compact the admitted roster grants");
    target_state
        .compact_semantic_state()
        .expect("compact target roster grants");

    let broker = LocalBroker::new();
    let mut state_events = state.events_tx.subscribe();
    let mut target_events = target_state.events_tx.subscribe();
    attach_local(&state, &broker);
    attach_local(&target_state, &broker);
    wait_for_approval(&mut state_events, target.public_id()).await;
    wait_for_approval(&mut target_events, identity.public_id()).await;

    for fact in facts.iter().skip(2).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("compact the adopted semantic proof");
    (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        facts,
        context,
        config,
        broker,
        target_root,
    )
}

async fn wait_for_approval(
    rx: &mut tokio::sync::broadcast::Receiver<myownmesh_core::MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(myownmesh_core::MeshEvent::Peer(myownmesh_core::PeerEvent::Approved {
                device_id,
                ..
            }))) if device_id == peer_id => return,
            _ => continue,
        }
    }
}

async fn wait_for_proof_owner(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    device_id: &str,
) -> myownmesh_core::engine::transport_lab::ProofOwner {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if let Some(owner) = proof_owner_for_device(state, device_id) {
            return owner;
        }
        if Instant::now() > deadline {
            panic!("never installed proof owner for {device_id}");
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_no_proof_owner(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    device_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if proof_owner_for_device(state, device_id).is_none() {
            return;
        }
        if Instant::now() > deadline {
            panic!("stale proof owner remained installed for {device_id}");
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_replayed_proof(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    previous: &ProofRecord,
) -> (ProofRecord, bool) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let target = previous.target.to_string();
    loop {
        let Some(owner) = proof_owner_for_device(state, &target) else {
            if Instant::now() > deadline {
                panic!("production proof replay did not expose a current owner");
            }
            tokio::task::yield_now().await;
            continue;
        };
        let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
            state,
            &owner,
            &previous.fact_ids,
        )
        .expect("current owner proof identity");
        assert_eq!(expected.context_id, previous.context_id);
        assert_eq!(expected.target, previous.target);
        assert_eq!(expected.delivery_id, previous.delivery_id);
        assert_eq!(expected.fact_ids, previous.fact_ids);
        assert_eq!(expected.owner, previous.owner);
        assert_ne!(expected.binding, previous.binding);
        let current = durable_proof_records(state)
            .expect("replay durable records")
            .into_iter()
            .find(|record| record.delivery_id == previous.delivery_id);
        if let Some(current) = current {
            match current.state {
                ProofRecordState::Pending => {
                    if current == expected {
                        return (current, true);
                    }
                }
                ProofRecordState::Settled => {
                    assert_exact_delivery_metadata(&current, &expected);
                    return (current, false);
                }
                ProofRecordState::Superseded => {
                    panic!(
                        "replayed delivery {} was Superseded before the test terminal",
                        previous.delivery_id
                    );
                }
            }
        }
        if Instant::now() > deadline {
            panic!("production proof replay did not expose Pending or an exact Settled tombstone");
        }
        tokio::task::yield_now().await;
    }
}

async fn wait_for_durable_record_state(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    delivery_id: myownmesh_core::semantic::ProofDeliveryId,
    expected: ProofRecordState,
) -> ProofRecord {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        let record = durable_proof_records(state)
            .expect("read exact durable replay state")
            .into_iter()
            .find(|record| record.delivery_id == delivery_id)
            .expect("durable delivery record remains observable");
        if record.state == expected {
            return record;
        }
        if Instant::now() > deadline {
            panic!(
                "durable delivery {delivery_id} remained {:?}, expected {expected:?}",
                record.state
            );
        }
        tokio::task::yield_now().await;
    }
}

fn assert_exact_delivery_metadata(actual: &ProofRecord, expected: &ProofRecord) {
    assert_eq!(actual.context_id, expected.context_id);
    assert_eq!(actual.target, expected.target);
    assert_eq!(actual.delivery_id, expected.delivery_id);
    assert_eq!(actual.fact_ids, expected.fact_ids);
    assert_eq!(actual.owner, expected.owner);
    assert_eq!(actual.binding, expected.binding);
}

fn assert_settled_tombstone(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    expected: &ProofRecord,
) {
    let tombstone = durable_proof_records(state)
        .expect("read exact durable terminal record")
        .into_iter()
        .find(|record| record.delivery_id == expected.delivery_id)
        .expect("exact delivery tombstone remains persisted");
    assert_exact_delivery_metadata(&tombstone, expected);
    assert_eq!(tombstone.state, ProofRecordState::Settled);
}

struct DurableSlot {
    directory: PathBuf,
    stem: String,
}

/// Locate the exact slot once. Subsequent observations address only its four
/// bounded paths, so duplicate/no-op comparisons are O(delta), not scans of
/// unrelated durable state.
fn discover_durable_slot(root: &Path) -> DurableSlot {
    fn visit(root: &Path) -> Option<DurableSlot> {
        let Ok(entries) = std::fs::read_dir(root) else {
            return None;
        };
        for entry in entries {
            let entry = entry.expect("durable slot entry is readable");
            let path = entry.path();
            if path.is_dir() {
                if let Some(slot) = visit(&path) {
                    return Some(slot);
                }
                continue;
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if let Some(stem) = name.strip_suffix("-store.sqlite3") {
                return Some(DurableSlot {
                    directory: path.parent().expect("slot has a parent").to_path_buf(),
                    stem: stem.to_string(),
                });
            }
        }
        None
    }

    visit(root).expect("fixture creates one canonical semantic slot")
}

/// Capture only the exact slot and its four SQLite sidecars. The relative
/// names make equality independent of the temporary test directory.
fn durable_slot_footprint(slot: &DurableSlot) -> BTreeMap<String, u64> {
    let mut files = BTreeMap::new();
    for suffix in [
        "-store.sqlite3",
        "-store.sqlite3-wal",
        "-store.sqlite3-shm",
        "-store.sqlite3-journal",
    ] {
        let path = slot.directory.join(format!("{}{}", slot.stem, suffix));
        if path.is_file() {
            files.insert(
                path.file_name()
                    .expect("slot file has a name")
                    .to_string_lossy()
                    .into_owned(),
                std::fs::metadata(&path)
                    .expect("durable slot metadata is readable")
                    .len(),
            );
        }
    }
    files
}

fn durable_slot_totals(files: &BTreeMap<String, u64>) -> serde_json::Value {
    let mut main_bytes = 0u64;
    let mut wal_bytes = 0u64;
    let mut shm_bytes = 0u64;
    let mut journal_bytes = 0u64;
    for (path, size) in files {
        let total = if path.ends_with("-store.sqlite3") {
            &mut main_bytes
        } else if path.ends_with("-store.sqlite3-wal") {
            &mut wal_bytes
        } else if path.ends_with("-store.sqlite3-shm") {
            &mut shm_bytes
        } else if path.ends_with("-store.sqlite3-journal") {
            &mut journal_bytes
        } else {
            continue;
        };
        *total = total
            .checked_add(*size)
            .expect("durable slot footprint fits u64");
    }
    serde_json::json!({
        "main_bytes": main_bytes,
        "wal_bytes": wal_bytes,
        "shm_bytes": shm_bytes,
        "journal_bytes": journal_bytes,
    })
}

fn elapsed_micros(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_micros()).expect("operation timing fits u64")
}

fn encoded_record_bytes(records: &[ProofRecord]) -> u64 {
    records
        .iter()
        .map(|record| {
            u64::try_from(
                serde_json::to_vec(record)
                    .expect("proof record serializes for policy accounting")
                    .len(),
            )
            .expect("proof record bytes fit u64")
        })
        .try_fold(0u64, |total, bytes| total.checked_add(bytes))
        .expect("proof record bytes fit u64")
}

fn reference_facts(record: &ProofRecord, references: &[SignedFact]) -> Vec<SignedFact> {
    record
        .fact_ids
        .iter()
        .map(|fact_id| {
            references
                .iter()
                .find(|fact| fact.id == *fact_id)
                .cloned()
                .expect("proof record fact has a reference body")
        })
        .collect()
}

#[tokio::test]
async fn r3_pending_proof_is_persisted_before_send_and_replayed_after_restart() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-replay").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("pending proof record");
    let persisted =
        admit_durable_proof(&state, record.clone()).expect("persist before transport send");
    assert_eq!(persisted.delivery_id, record.delivery_id);
    assert_eq!(
        pending_durable_proofs(&state)
            .expect("pending records")
            .len(),
        1
    );

    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("typed proof delivery");
    assert_eq!(delivery.delivery_id, record.delivery_id);
    let duplicate = admit_durable_proof(&state, record.clone())
        .expect("same delivery id is an idempotent enqueue");
    assert_eq!(duplicate, record);

    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("first target lifecycle shutdown");
    driver.await.expect("first lifecycle shutdown");
    drop(owner);
    drop(state);
    drop(target_state);

    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target")),
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("reopen target before sender");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("reopened target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen after offline interval");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&reopened, &record).await;
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(rebound.delivery_id, delivery.delivery_id);

    let receiver = receiver_admits_delivery(reopened.verified_bootstrap(), &delivery);
    assert!(receiver.projection().is_stood_down(&target_id));
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(
        ack.matches(&delivery),
        "ACK is typed to this exact delivery"
    );
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&reopened, &reopened_owner, &rebound, record.delivery_id)
                .expect("settle exact delivery");
        if !first_settle {
            assert_settled_tombstone(&reopened, &rebound);
        }
    }
    assert_settled_tombstone(&reopened, &rebound);
    if replay_was_pending {
        assert!(!settle_durable_proof_ack(
            &reopened,
            &reopened_owner,
            &rebound,
            record.delivery_id,
        )
        .expect("duplicate ACK is an idempotent no-op"));
    }
    assert!(pending_durable_proofs(&reopened)
        .expect("settled records filter from replay")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("reopened lifecycle shutdown");
    drop(reopened);

    // A second lifecycle boundary must preserve the exact terminal tombstone;
    // no pending record or fresh ACK may be manufactured after settlement.
    let (reopened_again, reopened_again_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen after exact terminal settlement");
    attach_local(&reopened_again, &broker);
    let terminal_again = wait_for_durable_record_state(
        &reopened_again,
        record.delivery_id,
        ProofRecordState::Settled,
    )
    .await;
    assert_exact_delivery_metadata(&terminal_again, &rebound);
    assert!(pending_durable_proofs(&reopened_again)
        .expect("terminal record remains excluded from replay")
        .is_empty());
    reopened_again.request_shutdown();
    reopened_again_driver
        .await
        .expect("second reopened lifecycle shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("reopened target lifecycle shutdown");
}

#[tokio::test]
async fn r3_pending_approval_proof_delivery_sends_one_ack_and_settles_sender() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        _member,
        facts,
        _context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-pending-ack").await;
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("PendingApproval proof record");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("valid proof delivery");
    admit_durable_proof(&state, record.clone()).expect("persist PendingApproval proof");

    // The target was offline while the source adopted the eviction closure.
    // Close the original endpoint, then recreate the same identity/root with
    // auto-approval disabled so the proof is admitted through the real
    // PendingApproval semantic lane before the denial terminalizes the session.
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("offline-evicted target shutdown");
    drop(owner);
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;

    let mut target_config = config.clone();
    target_config.auto_approve = false;
    let restarted_target_identity = Arc::new(Identity::from_signing_key(
        target_signing_key,
        "r3-pending-ack-target",
    ));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        target_config,
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        state.mesh_context_id(),
        target_bootstrap,
    )
    .await
    .expect("recreate offline-evicted target");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("target retains only pre-eviction facts");
    let target_initial_fact_count = restarted_target.semantic_fact_count();
    attach_local(&restarted_target, &broker);

    let rebound_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let settled =
        wait_for_durable_record_state(&state, record.delivery_id, ProofRecordState::Settled).await;
    let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &rebound_owner,
        &record.fact_ids,
    )
    .expect("current owner proof identity");
    assert_exact_delivery_metadata(&settled, &expected);
    assert_eq!(
        durable_proof_records(&state)
            .expect("settled sender proof records")
            .into_iter()
            .filter(|candidate| candidate.delivery_id == record.delivery_id)
            .count(),
        1,
        "one exact sender record is settled by the matching ACK"
    );
    assert!(pending_durable_proofs(&state)
        .expect("settled proof leaves no pending sender record")
        .is_empty());

    let deadline = Instant::now() + Duration::from_secs(20);
    while !restarted_target
        .self_evicted
        .load(std::sync::atomic::Ordering::SeqCst)
    {
        if Instant::now() > deadline {
            panic!("PendingApproval target never adopted the valid ProofDelivery");
        }
        tokio::task::yield_now().await;
    }
    assert!(
        restarted_target.semantic_fact_count() > target_initial_fact_count,
        "valid ProofDelivery adds the complete eviction closure"
    );
    assert_eq!(
        restarted_target.semantic_unresolved_count(),
        0,
        "PendingApproval proof admission resolves every dependency"
    );
    assert!(
        !settle_durable_proof_ack(&state, &rebound_owner, &settled, delivery.delivery_id,)
            .expect("duplicate matching ACK is idempotent")
    );

    state.request_shutdown();
    driver.await.expect("sender lifecycle shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
}

#[tokio::test]
async fn r3_cross_target_pending_approval_proof_acknowledges_exact_closure() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        member,
        prior,
        _context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-cross-target").await;
    let cross_target = Identity::ephemeral();
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let cross = cross_target_stand_down_facts(
        state.verified_bootstrap(),
        &prior,
        state.identity.as_ref(),
        &target,
        &member,
        &cross_target,
    );
    for fact in cross.facts.iter().skip(prior.len()).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit cross-target eviction closure");
    assert!(
        !state.is_rostered(target.public_id()),
        "the target's terminal projection is active before delivery"
    );

    let record = myownmesh_core::engine::transport_lab::canonical_durable_eviction_proof_record(
        &state, &owner,
    )
    .expect("derive canonical cross-target proof record")
    .expect("cross-target target eviction proof exists");
    assert!(
        record.fact_ids.contains(&cross.cross_target_evict.id),
        "canonical proof carries the cross-target Evict dependency"
    );
    assert!(
        record.fact_ids.contains(&cross.target_evict.id),
        "canonical proof carries the target Evict head"
    );
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("cross-target proof delivery");
    assert!(
        delivery
            .facts
            .iter()
            .any(|fact| fact.id == cross.cross_target_evict.id),
        "wire delivery contains the exact cross-target dependency"
    );
    admit_durable_proof(&state, record.clone()).expect("persist cross-target proof");

    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("offline-evicted target shutdown");
    drop(owner);
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;

    let mut target_config = config.clone();
    target_config.auto_approve = false;
    let restarted_target_identity = Arc::new(Identity::from_signing_key(
        target_signing_key,
        "r3-cross-target-target",
    ));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        target_config,
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        state.mesh_context_id(),
        target_bootstrap,
    )
    .await
    .expect("recreate cross-target PendingApproval target");
    for fact in prior.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("target retains the authenticated roster grants");
    let target_initial_fact_count = restarted_target.semantic_fact_count();
    attach_local(&restarted_target, &broker);

    let rebound_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let settled =
        wait_for_durable_record_state(&state, record.delivery_id, ProofRecordState::Settled).await;
    let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &rebound_owner,
        &record.fact_ids,
    )
    .expect("current cross-target owner proof identity");
    assert_exact_delivery_metadata(&settled, &expected);
    assert_eq!(
        durable_proof_records(&state)
            .expect("settled cross-target sender records")
            .into_iter()
            .filter(|candidate| candidate.delivery_id == record.delivery_id)
            .count(),
        1,
        "one exact sender record is settled by the matching ACK"
    );
    assert!(pending_durable_proofs(&state)
        .expect("settled cross-target proof leaves no pending record")
        .is_empty());
    assert!(
        restarted_target
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "PendingApproval target adopts the terminal cross-target proof"
    );
    assert!(
        restarted_target.semantic_fact_count() > target_initial_fact_count,
        "target receives the cross-target causal closure"
    );
    assert_eq!(
        restarted_target.semantic_unresolved_count(),
        0,
        "cross-target dependency is durably resolved before ACK"
    );
    assert!(
        !restarted_target.is_rostered(target.public_id()),
        "target terminal projection holds after exact delivery"
    );
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    assert!(
        !settle_durable_proof_ack(&state, &rebound_owner, &settled, ack.delivery_id)
            .expect("duplicate matching ACK is idempotent"),
        "a second matching ACK does not settle twice"
    );

    state.request_shutdown();
    driver.await.expect("cross-target sender shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("cross-target target shutdown");
}

#[tokio::test]
async fn r3_resolution_selected_evict_delivers_exact_pending_approval_closure() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        member,
        prior,
        _context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-resolution-pending").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let scenario = concurrent_evict_membership_resolution_facts(
        state.verified_bootstrap(),
        &prior,
        state.identity.as_ref(),
        &member,
        &target,
    );
    for fact in scenario.facts.iter().skip(prior.len()).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit concurrent Evict/MembershipAdmit resolution");
    assert!(
        !state.is_rostered(target.public_id()),
        "the selected Evict resolution keeps the target stood down"
    );

    let record = myownmesh_core::engine::transport_lab::canonical_durable_eviction_proof_record(
        &state, &owner,
    )
    .expect("derive canonical resolved eviction proof")
    .expect("resolved Evict remains a canonical terminal proof");
    for fact_id in [
        scenario.membership_admit.id,
        scenario.evict.id,
        scenario.resolution.id,
    ] {
        assert!(
            record.fact_ids.contains(&fact_id),
            "canonical proof carries every exact resolution dependency"
        );
    }
    let delivery = materialize_durable_proof_delivery(&state, &record)
        .expect("materialize resolved eviction proof delivery");
    let wire_resolution = delivery
        .facts
        .iter()
        .find_map(|fact| match &fact.content.body {
            FactBody::Resolution { selected_head, .. } => Some(*selected_head),
            _ => None,
        })
        .expect("wire closure contains the typed Resolution");
    assert_eq!(wire_resolution, scenario.evict.id);
    assert!(delivery.facts.iter().any(|fact| {
        fact.id == scenario.membership_admit.id
            && matches!(fact.content.body, FactBody::MembershipAdmit { .. })
    }));
    assert!(delivery.facts.iter().any(|fact| {
        fact.id == scenario.evict.id && matches!(fact.content.body, FactBody::Evict { .. })
    }));
    admit_durable_proof(&state, record.clone()).expect("persist resolved proof before send");

    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    target_state.request_shutdown();
    target_driver
        .await
        .expect("offline PendingApproval target shutdown");
    drop(owner);
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;

    let mut target_config = config.clone();
    target_config.auto_approve = false;
    let restarted_target_identity = Arc::new(Identity::from_signing_key(
        target_signing_key,
        "r3-resolution-target",
    ));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        target_config,
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        state.mesh_context_id(),
        target_bootstrap,
    )
    .await
    .expect("recreate PendingApproval resolution target");
    for fact in prior.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("target commits pre-eviction authenticated facts");
    let target_initial_fact_count = restarted_target.semantic_fact_count();
    attach_local(&restarted_target, &broker);

    let rebound_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let settled =
        wait_for_durable_record_state(&state, record.delivery_id, ProofRecordState::Settled).await;
    let expected = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &rebound_owner,
        &record.fact_ids,
    )
    .expect("current owner proof identity");
    assert_exact_delivery_metadata(&settled, &expected);
    assert_eq!(
        durable_proof_records(&state)
            .expect("settled resolved proof records")
            .into_iter()
            .filter(|candidate| candidate.delivery_id == record.delivery_id)
            .count(),
        1,
        "exactly one matching ACK settles the resolved proof"
    );
    assert!(pending_durable_proofs(&state)
        .expect("settled resolved proof leaves no pending record")
        .is_empty());
    assert!(
        restarted_target
            .self_evicted
            .load(std::sync::atomic::Ordering::SeqCst),
        "PendingApproval target adopts the resolved Evict closure"
    );
    assert!(restarted_target.semantic_fact_count() > target_initial_fact_count);
    assert_eq!(restarted_target.semantic_unresolved_count(), 0);
    assert!(
        !restarted_target.is_rostered(&target_id.to_string()),
        "target stand-down projection holds after exact closure delivery"
    );
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    assert!(
        !settle_durable_proof_ack(&state, &rebound_owner, &settled, ack.delivery_id,)
            .expect("duplicate matching ACK is idempotent")
    );

    state.request_shutdown();
    driver.await.expect("resolved sender lifecycle shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("resolved target lifecycle shutdown");
}

#[tokio::test]
async fn r3_stale_e0_is_superseded_before_e1_reconnect_replay() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        e0_facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-supersede").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &e0_facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E0 pending proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0).expect("E0 proof delivery");
    admit_durable_proof(&state, e0.clone()).expect("persist E0 before send");
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);

    // ACK loss is represented by shutting down with E0 still Pending. Close
    // both endpoint lifecycles so the resumed delivery crosses a genuine
    // authenticated target boundary rather than reusing a live connection.
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    driver.await.expect("sender restart boundary");
    target_state.request_shutdown();
    target_driver
        .await
        .expect("target endpoint restart boundary");
    drop(owner);
    drop(state);
    drop(target_state);

    // Recreate the same target identity and durable root with only the
    // pre-eviction roster facts.  Attach it before the sender resumes so the
    // next authenticated session is the sole replay trigger.
    let restarted_target_identity =
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target"));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("recreate target endpoint from the same identity");
    for fact in e0_facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("recreated target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("sender reconnects from the durable slot");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (e0_rebound, e0_was_pending) = wait_for_replayed_proof(&reopened, &e0).await;
    assert_eq!(
        e0_rebound.state,
        if e0_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(e0_rebound.delivery_id, e0_delivery.delivery_id);

    // A causal regrant followed by a fresh eviction creates E1 with a new
    // canonical closure. The stale E0 is retired as Superseded, never as an
    // ACK, before the admitted reconnect can enumerate replayable records.
    let e0_before_e1 = durable_proof_records(&reopened)
        .expect("read E0 before constructing E1")
        .into_iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("E0 remains durably observable before E1");
    assert_exact_delivery_metadata(&e0_before_e1, &e0_rebound);
    let e0_pending_before_e1 = match e0_before_e1.state {
        ProofRecordState::Pending => true,
        ProofRecordState::Settled => false,
        ProofRecordState::Superseded => {
            panic!("E0 cannot be Superseded before E1 is constructed")
        }
    };
    let e1_facts = reissued_stand_down_facts(
        reopened.verified_bootstrap(),
        &e0_facts,
        reopened.identity.as_ref(),
        &target,
        &member,
    );
    for fact in e1_facts.iter().skip(e0_facts.len()).cloned() {
        ingest_semantic_fact(&reopened, fact).await;
    }
    reopened
        .compact_semantic_state()
        .expect("compact the newly admitted E1 closure");
    let e1 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &reopened,
        &reopened_owner,
        &e1_facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E1 pending proof record");
    let e1_delivery =
        materialize_durable_proof_delivery(&reopened, &e1).expect("E1 proof delivery");
    assert_ne!(
        e0.delivery_id, e1.delivery_id,
        "E1 must not reuse E0 identity"
    );
    admit_durable_proof(&reopened, e1.clone()).expect("persist E1 closure");
    let supersede_result = if e0_pending_before_e1 {
        Some(supersede_durable_proof(
            &reopened,
            &reopened_owner,
            &e0,
            Some(e1.delivery_id),
        ))
    } else {
        assert_settled_tombstone(&reopened, &e0_rebound);
        None
    };
    let records = durable_proof_records(&reopened).expect("read E0/E1 terminal records");
    let e0_tombstone = records
        .iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("exact E0 tombstone remains persisted");
    assert_exact_delivery_metadata(e0_tombstone, &e0_rebound);
    match supersede_result.as_ref() {
        None => assert_eq!(e0_tombstone.state, ProofRecordState::Settled),
        Some(Ok(true)) => assert_eq!(e0_tombstone.state, ProofRecordState::Superseded),
        Some(Ok(false)) => assert_eq!(
            e0_tombstone.state,
            ProofRecordState::Superseded,
            "an idempotent supersession is legal only with the exact Superseded tombstone"
        ),
        Some(Err(_)) => assert_eq!(
            e0_tombstone.state,
            ProofRecordState::Settled,
            "a supersession error is legal only when the exact ACK won the race"
        ),
    }
    assert_ne!(e0_tombstone.state, ProofRecordState::Pending);
    let e1_pending = records
        .iter()
        .find(|record| record.delivery_id == e1.delivery_id)
        .expect("exact E1 replacement remains persisted");
    assert_exact_delivery_metadata(e1_pending, &e1);
    assert_eq!(e1_pending.state, ProofRecordState::Pending);
    if e0_tombstone.state == ProofRecordState::Superseded {
        assert!(
            !supersede_durable_proof(&reopened, &reopened_owner, &e0, Some(e1.delivery_id))
                .expect("repeated E0 supersession is idempotent")
        );
    }

    let pending = pending_durable_proofs(&reopened).expect("enumerate reconnect replay");
    assert_eq!(
        pending,
        vec![e1.clone()],
        "reconnect must emit E1, never E0"
    );
    assert!(!pending
        .iter()
        .any(|record| record.delivery_id == e0.delivery_id));
    let receiver = receiver_admits_delivery(reopened.verified_bootstrap(), &e1_delivery);
    assert!(
        receiver.projection().is_stood_down(&target_id),
        "the fresh E1 closure still proves the target stand-down"
    );

    reopened.request_shutdown();
    reopened_driver.await.expect("reconnect lifecycle shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
}

#[tokio::test]
async fn r3_external_transport_pause_supersedes_materialized_e0_before_resume() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-external-pause").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;

    // External transport is paused at the exact boundary after E0 selection
    // and materialization.  Until the final send admission below, E0 is only
    // an in-memory typed delivery and cannot be emitted by a carrier.
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("materialized E0 proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0)
        .expect("materialize E0 while transport is paused");
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);
    assert!(
        durable_proof_records(&state)
            .expect("observe unadmitted E0")
            .into_iter()
            .all(|record| record.delivery_id != e0.delivery_id),
        "materialization alone must not admit E0 to the durable send queue"
    );

    // While E0 is paused, durably commit the causal G1 restoration and build
    // its exact successor E1.  The successor includes G1 and a fresh closure,
    // so its delivery identity cannot alias the materialized E0 identity.
    let g1_facts = regrant_after_eviction_facts(
        state.verified_bootstrap(),
        &facts,
        state.identity.as_ref(),
        &target,
    );
    for fact in g1_facts.iter().cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit G1 while E0 is paused");
    assert!(
        state.is_rostered(target.public_id()),
        "G1 clears the old stand-down before E1 is authored"
    );
    let mut g1_history = facts.clone();
    g1_history.extend(g1_facts.iter().cloned());
    let e1_facts = reissued_stand_down_facts(
        state.verified_bootstrap(),
        &g1_history,
        state.identity.as_ref(),
        &target,
        &member,
    );
    for fact in e1_facts.iter().skip(g1_history.len()).cloned() {
        ingest_semantic_fact(&state, fact).await;
    }
    state
        .compact_semantic_state()
        .expect("durably commit exact E1 closure");
    let e1 = myownmesh_core::engine::transport_lab::canonical_durable_eviction_proof_record(
        &state, &owner,
    )
    .expect("derive canonical E1 proof record")
    .expect("current E1 eviction proof exists");
    let e1_new_facts = &e1_facts[g1_history.len()..];
    assert!(
        e1.fact_ids.contains(&g1_history[g1_history.len() - 1].id),
        "canonical E1 includes causal G1"
    );
    let e1_role_head = e1_new_facts
        .iter()
        .find(|fact| matches!(&fact.content.body, FactBody::RoleGrant { .. }))
        .expect("E1 has a current role head");
    let e1_evict_head = e1_new_facts
        .iter()
        .find(|fact| matches!(&fact.content.body, FactBody::Evict { .. }))
        .expect("E1 has a current membership/Evict head");
    assert!(e1.fact_ids.contains(&e1_role_head.id));
    assert!(e1.fact_ids.contains(&e1_evict_head.id));
    let mut canonical_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    for fact in e1_facts.iter().cloned() {
        canonical_graph
            .admit(fact)
            .expect("E1 history rebuilds for canonical seed selection");
    }
    let selected_stand_down_seed = canonical_graph
        .projection()
        .stand_down(&target_id)
        .map(|stand_down| stand_down.proof);
    let mut reachable = BTreeSet::new();
    let mut pending = vec![e1_role_head.id, e1_evict_head.id];
    if let Some(proof) = selected_stand_down_seed {
        assert!(
            e1.fact_ids.contains(&proof),
            "canonical E1 contains its selected stand-down seed"
        );
        pending.push(proof);
    }
    while let Some(id) = pending.pop() {
        if !reachable.insert(id) {
            continue;
        }
        let fact = e1_facts
            .iter()
            .find(|fact| fact.id == id)
            .expect("every selected-head dependency is in E1 history");
        pending.extend(myownmesh_core::semantic::causal::dependencies(fact));
    }
    assert_eq!(
        e1.fact_ids.iter().copied().collect::<BTreeSet<_>>(),
        reachable,
        "canonical E1 is exactly the selected-head causal closure"
    );
    let e1_delivery =
        materialize_durable_proof_delivery(&state, &e1).expect("materialize exact E1 delivery");
    assert_ne!(e0.delivery_id, e1.delivery_id);
    assert_eq!(e1_delivery.delivery_id, e1.delivery_id);

    // Resume admits both records only after G1/E1 are durable.  Close both
    // endpoint lifecycles at this pause boundary, then recreate the same
    // target identity and root before the sender's next carrier attach.  The
    // following attach is therefore the sole replay trigger: production must
    // supersede stale E0 and send only the canonical E1.
    admit_durable_proof(&state, e0.clone()).expect("admit paused E0 for replay fencing");
    admit_durable_proof(&state, e1.clone()).expect("admit exact E1 for replay");
    let pending_before_resume = pending_durable_proofs(&state).expect("pending E0/E1");
    assert!(pending_before_resume.iter().any(|record| record == &e0));
    assert!(pending_before_resume.iter().any(|record| record == &e1));
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    driver.await.expect("paused sender shutdown");
    target_state.request_shutdown();
    target_driver
        .await
        .expect("paused target endpoint shutdown");
    drop(owner);
    drop(state);
    drop(target_state);

    let restarted_target_identity =
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target"));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("recreate target endpoint from the same identity");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("recreated target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("resume sender after G1/E1 commit");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let e0_terminal =
        wait_for_durable_record_state(&reopened, e0.delivery_id, ProofRecordState::Superseded)
            .await;
    let rebound_e0_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let rebound_e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &reopened,
        &rebound_e0_owner,
        &e0.fact_ids,
    )
    .expect("derive exact rebound E0 identity");
    assert_eq!(rebound_e0.context_id, e0.context_id);
    assert_eq!(rebound_e0.target, e0.target);
    assert_eq!(rebound_e0.delivery_id, e0.delivery_id);
    assert_eq!(rebound_e0.fact_ids, e0.fact_ids);
    assert_eq!(rebound_e0.owner, e0.owner);
    assert_ne!(rebound_e0.binding, e0.binding);
    assert_eq!(e0_terminal.context_id, e0.context_id);
    assert_eq!(e0_terminal.target, e0.target);
    assert_eq!(e0_terminal.delivery_id, e0.delivery_id);
    assert_eq!(e0_terminal.fact_ids, e0.fact_ids);
    assert_eq!(e0_terminal.owner, e0.owner);
    assert!(
        e0_terminal.binding == e0.binding || e0_terminal.binding == rebound_e0.binding,
        "E0 tombstone retains either its original or exact rebound owner binding"
    );
    assert!(
        !pending_durable_proofs(&reopened)
            .expect("enumerate resumed exact replay")
            .iter()
            .any(|record| record.delivery_id == e0.delivery_id),
        "the stale, materialized E0 is never emitted after resume"
    );

    let rebound_e1 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &reopened,
        &reopened_owner,
        &e1.fact_ids,
    )
    .expect("derive exact rebound E1 identity");
    assert_eq!(rebound_e1.context_id, e1.context_id);
    assert_eq!(rebound_e1.target, e1.target);
    assert_eq!(rebound_e1.delivery_id, e1.delivery_id);
    assert_eq!(rebound_e1.fact_ids, e1.fact_ids);
    assert_eq!(rebound_e1.owner, e1.owner);
    assert_ne!(rebound_e1.binding, e1.binding);
    let (e1_rebound, e1_was_pending) = wait_for_replayed_proof(&reopened, &e1).await;
    assert_eq!(
        e1_rebound.state,
        if e1_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );
    assert_eq!(e1_rebound.delivery_id, e1.delivery_id);
    assert_eq!(e1_rebound.context_id, context);
    assert_eq!(e1_rebound.target, target_id);
    assert_exact_delivery_metadata(&e1_rebound, &rebound_e1);
    let deadline = Instant::now() + Duration::from_secs(20);
    while restarted_target.is_rostered(target.public_id()) {
        if Instant::now() > deadline {
            panic!("canonical E1 was not sent after external transport resumed");
        }
        tokio::task::yield_now().await;
    }

    reopened.request_shutdown();
    reopened_driver.await.expect("resumed sender shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
}

#[tokio::test]
async fn r3_regrant_before_resume_supersedes_e0_without_replay_or_stand_down() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        context,
        config,
        _broker,
        target_root,
    ) = create_fixture(&root, "r3-regrant-race").await;
    assert!(
        target_state.is_rostered(target.public_id()),
        "initial authenticated target has not received a stand-down proof"
    );

    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let e0 = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("E0 proof record");
    let e0_delivery = materialize_durable_proof_delivery(&state, &e0).expect("E0 delivery");
    admit_durable_proof(&state, e0.clone()).expect("persist selected E0");
    assert_eq!(
        durable_proof_records(&state)
            .expect("observe selected E0")
            .into_iter()
            .find(|record| record.delivery_id == e0.delivery_id)
            .expect("selected E0 remains present")
            .state,
        ProofRecordState::Pending
    );
    assert_eq!(e0_delivery.delivery_id, e0.delivery_id);

    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    eprintln!("r3 park control: waiting for selected E0 lifecycle shutdown");
    target_state.request_shutdown();
    eprintln!("r3 park control: waiting for original target lifecycle shutdown");
    tokio::time::timeout(Duration::from_secs(20), target_driver)
        .await
        .expect("original target lifecycle shutdown timed out")
        .expect("original target lifecycle shutdown");
    drop(target_state);
    tokio::time::timeout(Duration::from_secs(20), driver)
        .await
        .expect("selected E0 lifecycle shutdown timed out")
        .expect("selected E0 lifecycle shutdown");
    eprintln!("r3 park control: selected E0 lifecycle shutdown completed");
    eprintln!("r3 park control: original target lifecycle shutdown completed");
    drop(_broker);
    drop(owner);
    drop(state);

    // Deterministic resume barrier: restore the target's pre-eviction roster
    // first, then reopen the source and commit G1 before transport replay.
    eprintln!("r3 park control: spawning reopened target network");
    let (reopened_target, reopened_target_driver) = tokio::time::timeout(
        Duration::from_secs(20),
        import_network_in_instance_root(
            config.clone(),
            Arc::new(Identity::from_signing_key(target_signing_key, "r3-target")),
            support::test_transport(),
            target_root.path().to_path_buf(),
            context,
            target_bootstrap,
        ),
    )
    .await
    .expect("reopen target before replay timed out")
    .expect("reopen target before replay");
    eprintln!("r3 park control: reopened target network spawned");
    let broker = LocalBroker::new();
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&reopened_target, fact).await;
    }
    reopened_target
        .compact_semantic_state()
        .expect("reopened target commits the pre-eviction roster");
    attach_local(&reopened_target, &broker);

    eprintln!("r3 park control: spawning reopened network");
    let (reopened, reopened_driver) = tokio::time::timeout(
        Duration::from_secs(20),
        spawn_network_in_instance_root(
            config.clone(),
            identity,
            support::test_transport(),
            root.path().to_path_buf(),
        ),
    )
    .await
    .expect("reopen before replay timed out")
    .expect("reopen before replay");
    eprintln!("r3 park control: reopened network spawned");
    let g1_facts = regrant_after_eviction_facts(
        reopened.verified_bootstrap(),
        &facts,
        reopened.identity.as_ref(),
        &target,
    );
    for fact in g1_facts.iter().cloned() {
        ingest_semantic_fact(&reopened, fact).await;
    }
    reopened
        .compact_semantic_state()
        .expect("durably commit G1 before resume");
    assert!(
        reopened.is_rostered(target.public_id()),
        "G1 restoration clears the sender's active stand-down before replay"
    );
    let selected_before_resume = durable_proof_records(&reopened)
        .expect("observe E0 before resume")
        .into_iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("E0 remains durable across the regrant");
    assert_exact_delivery_metadata(&selected_before_resume, &e0);
    assert_eq!(selected_before_resume.state, ProofRecordState::Pending);
    assert!(
        reopened.is_rostered(target.public_id()),
        "G1 restores the target role before the parked replay begins"
    );
    assert!(
        reopened.is_rostered(target.public_id()),
        "G1 restores session policy while E0 is still pending"
    );

    let rpc = rpc(&reopened).expect("reopened sender funds one RPC dispatcher");
    let advert = CapabilityAdvert {
        tags: vec!["r3-capability-debt".to_string()],
        app_version: Some("r3-park-v1".to_string()),
        extra: serde_json::json!({"r3": "parked"}),
    };
    rpc.advertise(advert.clone())
        .expect("reopened sender advertises local capability debt");
    assert_eq!(rpc.capabilities(), advert);

    // Attach the source broker before explicitly re-entering the exact
    // promotion fence. Replay must inspect the current proof selection, fence
    // E0 as Superseded, and never send E0.
    attach_local(&reopened, &broker);
    eprintln!("r3 park control: waiting for exact reopened owner promotion");
    let promotion_deadline = Instant::now() + Duration::from_secs(20);
    let mut owner_observed = false;
    let _reopened_owner = loop {
        if let Some(reopened_owner) = proof_owner_for_device(&reopened, target.public_id()) {
            owner_observed = true;
            if promote_exact_owner_for_lab(&reopened, &reopened_owner) {
                break reopened_owner;
            }
        }
        if Instant::now() >= promotion_deadline {
            panic!("exact reopened owner promotion was not admitted within 20s (owner_observed={owner_observed})");
        }
        tokio::task::yield_now().await;
    };
    eprintln!("r3 park control: exact reopened owner promotion observed");
    let e0_terminal =
        wait_for_durable_record_state(&reopened, e0.delivery_id, ProofRecordState::Superseded)
            .await;
    assert_exact_delivery_metadata(&e0_terminal, &e0);
    assert_eq!(
        e0_terminal.state,
        ProofRecordState::Superseded,
        "G1 reconciliation durably supersedes E0 before capability send"
    );
    assert!(
        !pending_durable_proofs(&reopened)
            .expect("enumerate resumed replay")
            .iter()
            .any(|record| record.delivery_id == e0.delivery_id),
        "the selected E0 is never replayed after G1 restoration"
    );
    assert!(
        reopened_target.is_rostered(target.public_id()),
        "the stale E0 never reaches the target as a stand-down-causing proof"
    );

    let e0_after_release = durable_proof_records(&reopened)
        .expect("observe E0 after releasing capability replay")
        .into_iter()
        .find(|record| record.delivery_id == e0.delivery_id)
        .expect("E0 tombstone remains after capability replay release");
    assert_exact_delivery_metadata(&e0_after_release, &e0);
    assert_eq!(
        e0_after_release.state,
        ProofRecordState::Superseded,
        "releasing the capability park cannot revive terminal E0"
    );
    assert!(
        !pending_durable_proofs(&reopened)
            .expect("enumerate replay after capability release")
            .iter()
            .any(|record| record.delivery_id == e0.delivery_id),
        "released capability replay still cannot emit E0"
    );
    assert!(
        reopened_target.is_rostered(target.public_id()),
        "releasing the parked capability send preserves the no-E0 terminal"
    );

    reopened.request_shutdown();
    eprintln!("r3 park control: waiting for resumed sender shutdown");
    tokio::time::timeout(Duration::from_secs(20), reopened_driver)
        .await
        .expect("resumed sender shutdown timed out")
        .expect("resumed sender shutdown");
    eprintln!("r3 park control: resumed sender shutdown completed");
    reopened_target.request_shutdown();
    eprintln!("r3 park control: waiting for reopened target lifecycle shutdown");
    tokio::time::timeout(Duration::from_secs(20), reopened_target_driver)
        .await
        .expect("reopened target lifecycle shutdown timed out")
        .expect("reopened target lifecycle shutdown");
    eprintln!("r3 park control: reopened target lifecycle shutdown completed");
}

#[tokio::test]
async fn r3_receiver_refuses_pre_stand_down_ack_and_stale_owner_binding() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        _identity,
        target,
        _member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-typed").await;
    let target_id = device(&target);
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("typed pending record");
    admit_durable_proof(&state, record.clone()).expect("enqueue typed record");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("complete delivery serializes");

    // Replace the target installation. The first witness is now stale, while
    // the replacement witness is the only one allowed to rebind the Pending
    // record through the state-owned façade.
    target_state.request_shutdown();
    target_driver
        .await
        .expect("stale target lifecycle shutdown");
    drop(target_state);
    wait_for_no_proof_owner(&state, target.public_id()).await;
    let replacement_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-target-replacement",
    ));
    let (replacement, replacement_driver) = spawn_network_in_instance_root(
        config.clone(),
        replacement_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
    )
    .await
    .expect("replacement target lifecycle");
    attach_local(&replacement, &broker);
    let replacement_owner = wait_for_proof_owner(&state, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&state, &record).await;
    assert!(!rebind_durable_proof(&state, &owner, &record).expect("stale owner refusal"));
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );

    let prefix = ProofDeliveryMessage::new(context, target_id.clone(), facts[..3].to_vec())
        .expect("prefix delivery serializes");
    let prefix_receiver = receiver_admits_delivery(state.verified_bootstrap(), &prefix);
    assert!(
        !prefix_receiver.projection().is_stood_down(&target_id),
        "a receiver cannot ACK before canonical proof evidence is admitted"
    );

    // The receiver is a second durable NetworkState, not only an in-memory
    // reducer.  Its production ingress must adopt the exact proof facts before
    // the canonical projection can authorize an ACK.
    let receiver_root = TempDir::new().expect("receiver instance root");
    let receiver_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-receiver",
    ));
    let (receiver_state, receiver_driver) = import_network_in_instance_root(
        config.clone(),
        receiver_identity,
        support::test_transport(),
        receiver_root.path().to_path_buf(),
        context,
        state.verified_bootstrap().record().clone(),
    )
    .await
    .expect("receiver imports the exact bootstrap");
    for fact in facts.iter().cloned() {
        ingest_semantic_fact(&receiver_state, fact).await;
    }
    receiver_state
        .compact_semantic_state()
        .expect("receiver durably commits the proof graph");
    assert!(
        !receiver_state.is_rostered(target.public_id()),
        "receiver projection is stood down only after complete proof admission"
    );
    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&state, &replacement_owner, &rebound, ack.delivery_id)
                .expect("exact ACK settles");
        if !first_settle {
            assert_settled_tombstone(&state, &rebound);
        }
    }
    assert_settled_tombstone(&state, &rebound);
    assert!(pending_durable_proofs(&state)
        .expect("settled proof filters")
        .is_empty());

    state.request_shutdown();
    driver.await.expect("typed delivery lifecycle shutdown");
    replacement.request_shutdown();
    replacement_driver
        .await
        .expect("replacement target shutdown");
    receiver_state.request_shutdown();
    receiver_driver.await.expect("receiver lifecycle shutdown");
}

#[tokio::test]
async fn r3_restart_preserves_adopted_graph_self_eviction_and_pending_receipt() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        target,
        _member,
        facts,
        context,
        config,
        broker,
        target_root,
    ) = create_fixture(&root, "r3-restart").await;
    let owner = wait_for_proof_owner(&state, target.public_id()).await;
    let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
        &state,
        &owner,
        &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
    )
    .expect("restart pending record");
    admit_durable_proof(&state, record.clone()).expect("persist restart receipt");
    let delivery =
        materialize_durable_proof_delivery(&state, &record).expect("restart replay delivery");
    let target_signing_key = target.signing_key().clone();
    let target_bootstrap = state.verified_bootstrap().record().clone();
    state.request_shutdown();
    driver.await.expect("pre-restart shutdown");
    target_state.request_shutdown();
    target_driver
        .await
        .expect("target endpoint restart boundary");
    drop(owner);
    drop(state);
    drop(target_state);

    // Recreate the target from the same signing key and durable instance root
    // before the sender resumes.  This closes the old endpoint lifecycle so
    // the replay must cross a genuine authenticated transport boundary.
    let restarted_target_identity =
        Arc::new(Identity::from_signing_key(target_signing_key, "r3-target"));
    let (restarted_target, restarted_target_driver) = import_network_in_instance_root(
        config.clone(),
        restarted_target_identity,
        support::test_transport(),
        target_root.path().to_path_buf(),
        context,
        target_bootstrap,
    )
    .await
    .expect("recreate target endpoint from the same identity");
    for fact in facts.iter().take(2).cloned() {
        ingest_semantic_fact(&restarted_target, fact).await;
    }
    restarted_target
        .compact_semantic_state()
        .expect("recreated target commits the authenticated roster grants");
    attach_local(&restarted_target, &broker);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart durable network");
    attach_local(&reopened, &broker);
    let reopened_owner = wait_for_proof_owner(&reopened, target.public_id()).await;
    let (rebound, replay_was_pending) = wait_for_replayed_proof(&reopened, &record).await;
    assert!(
        !reopened.is_rostered(target.public_id()),
        "restart preserves the adopted eviction/stand-down projection"
    );
    assert!(
        reopened.semantic_fact_count() >= facts.len(),
        "restart preserves every adopted proof fact"
    );
    assert_eq!(
        rebound.state,
        if replay_was_pending {
            ProofRecordState::Pending
        } else {
            ProofRecordState::Settled
        }
    );

    // Reopen the same signed log as the evicted device.  This is the
    // self-eviction boundary: the receiver's own durable projection must
    // remain stood down after it adopts the persisted proof facts.
    let receiver_root = TempDir::new().expect("self-evicted receiver root");
    let receiver_identity = Arc::new(Identity::from_signing_key(
        target.signing_key().clone(),
        "r3-self-evicted",
    ));
    let (receiver_state, receiver_driver) = import_network_in_instance_root(
        config.clone(),
        receiver_identity,
        support::test_transport(),
        receiver_root.path().to_path_buf(),
        context,
        reopened.verified_bootstrap().record().clone(),
    )
    .await
    .expect("self-evicted receiver imports bootstrap");
    for fact in facts.iter().cloned() {
        ingest_semantic_fact(&receiver_state, fact).await;
    }
    receiver_state
        .compact_semantic_state()
        .expect("self-evicted receiver commits proof graph");
    assert!(
        !receiver_state.is_rostered(target.public_id()),
        "self-eviction remains active after receiver restart/adoption"
    );

    let ack = ProofAckMessage::for_delivery(&delivery);
    assert!(ack.matches(&delivery));
    if replay_was_pending {
        let first_settle =
            settle_durable_proof_ack(&reopened, &reopened_owner, &rebound, record.delivery_id)
                .expect("restart ACK settles");
        if !first_settle {
            assert_settled_tombstone(&reopened, &rebound);
        }
    }
    assert_settled_tombstone(&reopened, &rebound);
    assert!(pending_durable_proofs(&reopened)
        .expect("restart receipt settles")
        .is_empty());

    reopened.request_shutdown();
    reopened_driver.await.expect("post-restart shutdown");
    restarted_target.request_shutdown();
    restarted_target_driver
        .await
        .expect("recreated target lifecycle shutdown");
    receiver_state.request_shutdown();
    receiver_driver
        .await
        .expect("self-evicted receiver shutdown");
}

#[tokio::test]
async fn r3_many_pending_deliveries_preserve_unrelated_links_and_footprints() {
    let root = TempDir::new().expect("instance root");
    let (
        state,
        driver,
        target_state,
        target_driver,
        identity,
        _target,
        _member,
        facts,
        _context,
        config,
        _broker,
        _target_root,
    ) = create_fixture(&root, "r3-many-deliveries").await;
    let owner = wait_for_proof_owner(&state, _target.public_id()).await;
    let slot = discover_durable_slot(root.path());

    // Every non-empty contiguous fact window is a distinct P record and
    // retains its exact L fact links.  This gives the mutation controls more
    // than one unrelated row while keeping the workload derived entirely
    // from the authenticated proof closure.
    let seed_admission_started = Instant::now();
    let mut records = Vec::new();
    let mut linked_fact_ids = BTreeSet::new();
    for start in 0..facts.len() {
        for end in (start + 1)..=facts.len() {
            let fact_ids: Vec<_> = facts[start..end].iter().map(|fact| fact.id).collect();
            linked_fact_ids.extend(fact_ids.iter().copied());
            let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
                &state, &owner, &fact_ids,
            )
            .expect("derive bounded proof record from admitted facts");
            materialize_durable_proof_delivery(&state, &record)
                .expect("materialize each exact linked delivery");
            admit_durable_proof(&state, record.clone()).expect("persist each pending delivery");
            records.push(record);
        }
    }
    let seed_admission_elapsed_us = elapsed_micros(seed_admission_started);
    assert!(
        records.len() > facts.len(),
        "the control must seed many proof rows and linked facts"
    );
    assert!(
        u64::try_from(records.len()).expect("seed record count fits u64")
            <= config.semantic_policy.max_proof_records,
        "seed proof records remain inside the configured retained-record limit"
    );
    let seeded = durable_proof_records(&state).expect("read seeded proof rows");
    assert_eq!(seeded.len(), records.len());
    assert_eq!(
        seeded
            .iter()
            .flat_map(|record| record.fact_ids.iter().copied())
            .collect::<BTreeSet<_>>(),
        linked_fact_ids,
        "all seeded L links are retained"
    );
    for record in &records {
        let delivery = materialize_durable_proof_delivery(&state, record)
            .expect("materialize each seeded pending proof");
        assert_eq!(
            delivery.facts,
            reference_facts(record, &facts),
            "seeded proof materializes the exact signed reference bodies"
        );
    }
    let mut seed_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    for fact in &facts {
        seed_graph
            .admit(fact.clone())
            .expect("seed facts admit into reference graph");
    }
    assert_eq!(
        state.semantic_fact_count(),
        seed_graph.len(),
        "production seed semantic count matches the reference graph"
    );
    assert_eq!(
        state.semantic_unresolved_count(),
        seed_graph.quarantined().count(),
        "production seed unresolved count matches the reference graph"
    );

    let duplicate_before = durable_slot_footprint(&slot);
    assert_eq!(
        admit_durable_proof(&state, records[0].clone()).expect("duplicate enqueue"),
        records[0],
        "byte-identical P enqueue is idempotent"
    );
    let duplicate_after = durable_slot_footprint(&slot);
    assert_eq!(
        duplicate_before, duplicate_after,
        "duplicate enqueue is a durable byte/page no-op"
    );

    let rebind_before = durable_slot_footprint(&slot);
    assert!(
        rebind_durable_proof(&state, &owner, &records[1]).expect("same-owner rebind"),
        "the exact current owner may rebind one pending delivery"
    );
    let rebind_after = durable_slot_footprint(&slot);

    let supersede_before = durable_slot_footprint(&slot);
    assert!(
        supersede_durable_proof(&state, &owner, &records[2], Some(records[3].delivery_id),)
            .expect("supersede one exact pending delivery"),
        "the exact current owner may supersede one delivery"
    );
    let supersede_after = durable_slot_footprint(&slot);

    let settle_delivery =
        materialize_durable_proof_delivery(&state, &records[4]).expect("settle delivery wire");
    let settle_before = durable_slot_footprint(&slot);
    assert!(
        settle_durable_proof_ack(&state, &owner, &records[4], settle_delivery.delivery_id)
            .expect("settle one exact delivery"),
        "the exact owner and delivery settle one pending record"
    );
    let settle_after = durable_slot_footprint(&slot);

    let duplicate_ack_before = durable_slot_footprint(&slot);
    assert!(
        !settle_durable_proof_ack(&state, &owner, &records[4], settle_delivery.delivery_id)
            .expect("duplicate ACK"),
        "duplicate ACK is an idempotent semantic no-op"
    );
    let duplicate_ack_after = durable_slot_footprint(&slot);
    assert_eq!(
        duplicate_ack_before, duplicate_ack_after,
        "duplicate ACK is a durable byte/page no-op"
    );

    let mut expected = records.clone();
    expected[2].state = ProofRecordState::Superseded;
    expected[4].state = ProofRecordState::Settled;
    expected.sort_by_key(|record| record.delivery_id);
    let observed = durable_proof_records(&state).expect("observe mixed terminal records");
    assert_eq!(observed.len(), expected.len());
    for expected_record in &expected {
        let actual = observed
            .iter()
            .find(|record| record.delivery_id == expected_record.delivery_id)
            .expect("each unrelated proof row remains present");
        assert_exact_delivery_metadata(actual, expected_record);
        assert_eq!(actual.state, expected_record.state);
    }
    assert_eq!(
        observed
            .iter()
            .flat_map(|record| record.fact_ids.iter().copied())
            .collect::<BTreeSet<_>>(),
        linked_fact_ids,
        "settle/rebind/supersede preserve every unrelated L fact link"
    );
    let pending_after_seed_started = Instant::now();
    let pending_after_seed =
        pending_durable_proofs(&state).expect("pending records after mixed terminal mutations");
    let pending_after_seed_us = elapsed_micros(pending_after_seed_started);
    let expected_pending_count = expected
        .iter()
        .filter(|record| record.state == ProofRecordState::Pending)
        .count();
    let seed_pending_records = expected
        .iter()
        .filter(|record| record.state == ProofRecordState::Pending)
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(
        pending_after_seed.len(),
        expected_pending_count,
        "pending N and terminal records remain exactly partitioned"
    );
    assert_eq!(
        pending_after_seed, seed_pending_records,
        "the exact sorted pending record set is retained after seed mutations"
    );
    let seed_pending_serialized_bytes = encoded_record_bytes(&pending_after_seed);
    let seed_total_serialized_bytes = encoded_record_bytes(&observed);
    assert!(
        seed_pending_serialized_bytes <= config.semantic_policy.max_pending_proof_bytes,
        "seed pending proof bytes remain inside the configured pending limit"
    );
    assert!(
        seed_total_serialized_bytes <= config.semantic_policy.max_proof_bytes,
        "seed proof bytes remain inside the configured retained limit"
    );
    assert!(
        u64::try_from(pending_after_seed.len()).expect("pending count fits u64")
            <= config.semantic_policy.max_pending_proofs,
        "seed pending count remains inside the configured pending limit"
    );
    let seed_link_count = observed
        .iter()
        .map(|record| u64::try_from(record.fact_ids.len()).expect("link count fits u64"))
        .try_fold(0u64, |total, links| total.checked_add(links))
        .expect("seed proof links fit u64");
    assert!(
        seed_link_count <= config.semantic_policy.max_proof_links,
        "seed proof links remain inside the configured link limit"
    );
    let unrelated_rows_preserved = observed == expected;
    assert!(
        unrelated_rows_preserved,
        "the seeded rows and links remain exact before history pressure"
    );
    let pending_linked_fact_count = linked_fact_ids.len();
    assert_eq!(
        pending_linked_fact_count, 5,
        "history pressure keeps the pending proof link set fixed"
    );

    // Keep the pending proof set and its five linked facts fixed while adding
    // a finite, mechanically-derived terminal history.  Repeated grants for
    // one bounded roster subject produce unique causal FactIds without
    // expanding the roster subject set; each one is persisted through the
    // production ingress and then retired through the exact current owner.
    let mut terminal_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    for fact in &facts {
        terminal_graph
            .admit(fact.clone())
            .expect("seed facts admit into history fixture graph");
    }
    let mut terminal_history = Vec::new();
    let mut terminal_reference_facts = Vec::new();
    let mut history_metrics = Vec::new();
    for target_count in [10usize, 100usize] {
        assert!(
            u64::try_from(target_count).expect("history count fits u64")
                <= config.semantic_policy.max_proof_records,
            "history cases remain inside the configured proof-record capacity"
        );
        while terminal_history.len() < target_count {
            let role = if terminal_history.len() % 2 == 0 {
                myownmesh_core::semantic::Role::Controller
            } else {
                myownmesh_core::semantic::Role::Member
            };
            let fact = authored(
                &terminal_graph,
                identity.as_ref(),
                FactBody::RoleGrant {
                    target: device(&_member),
                    role,
                },
            );
            terminal_graph
                .admit(fact.clone())
                .expect("derived terminal-history fact admits");
            ingest_semantic_fact(&state, fact.clone()).await;
            let record = myownmesh_core::engine::transport_lab::new_durable_proof_record(
                &state,
                &owner,
                &[fact.id],
            )
            .expect("derive terminal-history proof record");
            materialize_durable_proof_delivery(&state, &record)
                .map(|delivery| {
                    assert_eq!(
                        delivery.facts,
                        vec![fact.clone()],
                        "terminal-history proof materializes its exact signed body"
                    );
                })
                .expect("materialize terminal-history proof");
            admit_durable_proof(&state, record.clone()).expect("persist terminal-history proof");
            assert!(
                supersede_durable_proof(&state, &owner, &record, None)
                    .expect("retire terminal-history proof"),
                "each derived terminal-history proof retires once"
            );
            let mut terminal = record;
            terminal.state = ProofRecordState::Superseded;
            terminal_history.push(terminal);
            terminal_reference_facts.push(fact);
        }

        let terminal_fact_ids = terminal_history
            .iter()
            .flat_map(|record| record.fact_ids.iter().copied())
            .collect::<BTreeSet<_>>();
        let terminal_delivery_ids = terminal_history
            .iter()
            .map(|record| record.delivery_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(
            terminal_fact_ids.len(),
            terminal_history.len(),
            "terminal history FactIds are unique"
        );
        assert_eq!(
            terminal_delivery_ids.len(),
            terminal_history.len(),
            "terminal history delivery IDs are unique"
        );
        assert!(
            terminal_fact_ids.is_disjoint(&linked_fact_ids),
            "terminal history FactIds do not overlap the seeded link set"
        );
        let seed_delivery_ids = expected
            .iter()
            .map(|record| record.delivery_id)
            .collect::<BTreeSet<_>>();
        assert!(
            terminal_delivery_ids.is_disjoint(&seed_delivery_ids),
            "terminal history delivery IDs do not overlap seeded records"
        );

        let pending_started = Instant::now();
        let pending = pending_durable_proofs(&state).expect("list pending history baseline");
        let pending_us = elapsed_micros(pending_started);
        assert_eq!(
            pending.len(),
            expected_pending_count,
            "terminal history does not change the pending proof count"
        );
        assert_eq!(
            pending, seed_pending_records,
            "terminal history preserves the exact sorted pending record set"
        );
        let observed = durable_proof_records(&state).expect("observe terminal history baseline");
        let mut expected_at_history = expected.clone();
        expected_at_history.extend(terminal_history.iter().cloned());
        expected_at_history.sort_by_key(|record| record.delivery_id);
        assert_eq!(
            observed, expected_at_history,
            "terminal history preserves the exact sorted full record set"
        );
        let terminal_count = observed
            .iter()
            .filter(|record| record.state != ProofRecordState::Pending)
            .count();
        let expected_record_count = records
            .len()
            .checked_add(terminal_history.len())
            .expect("history record count fits usize");
        assert_eq!(
            observed.len(),
            expected_record_count,
            "history retains the exact seed-plus-terminal record count"
        );
        assert!(
            u64::try_from(observed.len()).expect("history record count fits u64")
                <= config.semantic_policy.max_proof_records,
            "history records remain inside the configured retained-record limit"
        );
        assert_eq!(
            terminal_count,
            records.len() - expected_pending_count + terminal_history.len(),
            "terminal history count is exact"
        );
        let actual_fact_ids = observed
            .iter()
            .flat_map(|record| record.fact_ids.iter().copied())
            .collect::<BTreeSet<_>>();
        let mut expected_fact_ids = linked_fact_ids.clone();
        expected_fact_ids.extend(terminal_fact_ids.iter().copied());
        assert_eq!(
            actual_fact_ids, expected_fact_ids,
            "terminal history preserves the exact union of linked FactIds"
        );
        assert_eq!(
            state.semantic_fact_count(),
            terminal_graph.len(),
            "production history semantic count matches the reference graph"
        );
        assert_eq!(
            state.semantic_unresolved_count(),
            terminal_graph.quarantined().count(),
            "production history unresolved count matches the reference graph"
        );
        let pending_serialized_bytes = encoded_record_bytes(&pending);
        let total_serialized_bytes = encoded_record_bytes(&observed);
        assert!(
            pending_serialized_bytes <= config.semantic_policy.max_pending_proof_bytes,
            "history pending proof bytes remain inside the configured pending limit"
        );
        assert!(
            total_serialized_bytes <= config.semantic_policy.max_proof_bytes,
            "history proof bytes remain inside the configured retained limit"
        );
        assert!(
            u64::try_from(pending.len()).expect("pending count fits u64")
                <= config.semantic_policy.max_pending_proofs,
            "history pending count remains inside the configured pending limit"
        );
        let history_link_count = observed
            .iter()
            .map(|record| u64::try_from(record.fact_ids.len()).expect("link count fits u64"))
            .try_fold(0u64, |total, links| total.checked_add(links))
            .expect("history proof links fit u64");
        assert!(
            history_link_count <= config.semantic_policy.max_proof_links,
            "history proof links remain inside the configured link limit"
        );
        let mut history_references = facts.clone();
        history_references.extend(terminal_reference_facts.iter().cloned());
        for record in &terminal_history {
            let mut descriptive = record.clone();
            descriptive.state = ProofRecordState::Pending;
            let delivery = materialize_durable_proof_delivery(&state, &descriptive)
                .expect("materialize descriptive terminal proof");
            assert_eq!(
                delivery.facts,
                reference_facts(record, &history_references),
                "terminal history retains exact signed reference bodies"
            );
        }
        let history_footprint = durable_slot_footprint(&slot);
        let history_bytes = history_footprint
            .values()
            .try_fold(0u64, |total, size| total.checked_add(*size))
            .expect("history footprint fits u64");
        assert!(
            history_bytes <= config.semantic_policy.max_database_bytes,
            "history pressure remains inside the configured database envelope"
        );
        history_metrics.push(serde_json::json!({
            "terminal_history_count": terminal_history.len(),
            "pending_count": pending.len(),
            "pending_listing_elapsed_us": pending_us,
            "pending_serialized_bytes": pending_serialized_bytes,
            "total_serialized_bytes": total_serialized_bytes,
            "terminal_count": terminal_count,
            "terminal_linked_fact_count": terminal_history.len(),
            "footprint": durable_slot_totals(&history_footprint),
        }));
    }
    expected.extend(terminal_history.iter().cloned());
    expected.sort_by_key(|record| record.delivery_id);
    let mut all_reference_facts = facts.clone();
    all_reference_facts.extend(terminal_reference_facts.iter().cloned());

    // The configured database budget is the only bound used for footprint
    // qualification; no test-local byte multiplier is smuggled in.
    for footprint in [
        &duplicate_after,
        &rebind_after,
        &supersede_after,
        &settle_after,
        &duplicate_ack_after,
    ] {
        let bytes = footprint
            .values()
            .try_fold(0u64, |total, size| total.checked_add(*size))
            .expect("durable footprint fits u64");
        assert!(
            bytes <= config.semantic_policy.max_database_bytes,
            "SQLite main/WAL/SHM/journal footprint stays within configured budget"
        );
    }

    let configured_max_database_bytes = config.semantic_policy.max_database_bytes;
    state.request_shutdown();
    driver.await.expect("many-delivery sender shutdown");
    target_state.request_shutdown();
    target_driver.await.expect("many-delivery target shutdown");
    drop(owner);
    drop(state);

    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart many-delivery network");
    let reopened_records = durable_proof_records(&reopened).expect("replay exact proof rows");
    let reopened_exact_equality = reopened_records == expected;
    assert_eq!(
        reopened_records, expected,
        "restart replays the exact pending set and terminal records"
    );
    let reopened_pending_records =
        pending_durable_proofs(&reopened).expect("replay pending proof rows");
    assert_eq!(
        reopened_pending_records, seed_pending_records,
        "reopen preserves the exact sorted pending record set"
    );
    let reopened_pending_count = reopened_pending_records.len();
    let reopened_terminal_count = reopened_records
        .iter()
        .filter(|record| record.state != ProofRecordState::Pending)
        .count();
    assert_eq!(
        reopened_pending_count,
        expected
            .iter()
            .filter(|record| record.state == ProofRecordState::Pending)
            .count(),
        "restart preserves the exact pending count"
    );
    assert!(
        u64::try_from(reopened_records.len()).expect("reopened record count fits u64")
            <= config.semantic_policy.max_proof_records,
        "reopened records remain inside the configured retained-record limit"
    );
    assert!(
        u64::try_from(reopened_pending_count).expect("reopened pending count fits u64")
            <= config.semantic_policy.max_pending_proofs,
        "reopened pending count remains inside the configured pending limit"
    );
    assert_eq!(
        reopened.semantic_fact_count(),
        terminal_graph.len(),
        "reopen production semantic count matches the reference graph"
    );
    assert_eq!(
        reopened.semantic_unresolved_count(),
        terminal_graph.quarantined().count(),
        "reopen production unresolved count matches the reference graph"
    );
    let reopened_fact_ids = reopened_records
        .iter()
        .flat_map(|record| record.fact_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    let expected_fact_ids = expected
        .iter()
        .flat_map(|record| record.fact_ids.iter().copied())
        .collect::<BTreeSet<_>>();
    assert_eq!(
        reopened_fact_ids, expected_fact_ids,
        "reopen preserves the exact union of linked FactIds"
    );
    for record in &reopened_records {
        let mut descriptive = record.clone();
        descriptive.state = ProofRecordState::Pending;
        let delivery = materialize_durable_proof_delivery(&reopened, &descriptive)
            .expect("materialize descriptive reopened proof");
        assert_eq!(
            delivery.facts,
            reference_facts(record, &all_reference_facts),
            "reopen materializes the exact signed reference bodies"
        );
    }
    let reopened_pending_serialized_bytes = encoded_record_bytes(&reopened_pending_records);
    let reopened_total_serialized_bytes = encoded_record_bytes(&reopened_records);
    assert!(
        reopened_pending_serialized_bytes <= config.semantic_policy.max_pending_proof_bytes,
        "reopened pending proof bytes remain inside the configured pending limit"
    );
    assert!(
        reopened_total_serialized_bytes <= config.semantic_policy.max_proof_bytes,
        "reopened proof bytes remain inside the configured retained limit"
    );
    let reopened_link_count = reopened_records
        .iter()
        .map(|record| u64::try_from(record.fact_ids.len()).expect("link count fits u64"))
        .try_fold(0u64, |total, links| total.checked_add(links))
        .expect("reopened proof links fit u64");
    assert!(
        reopened_link_count <= config.semantic_policy.max_proof_links,
        "reopened proof links remain inside the configured link limit"
    );
    eprintln!(
        "DURABLE_PROOF_DELIVERY_R3_METRIC {}",
        serde_json::json!({
            "selector": "r3_many_pending_deliveries_preserve_unrelated_links_and_footprints",
            "seeded_proof_count": records.len(),
            "linked_fact_count": linked_fact_ids.len(),
            "final_record_count": reopened_records.len(),
            "final_linked_fact_count": reopened_fact_ids.len(),
            "configured_max_database_bytes": configured_max_database_bytes,
            "operations": {
                "duplicate_enqueue": {
                    "before": durable_slot_totals(&duplicate_before),
                    "after": durable_slot_totals(&duplicate_after),
                },
                "rebind": {
                    "before": durable_slot_totals(&rebind_before),
                    "after": durable_slot_totals(&rebind_after),
                },
                "supersede": {
                    "before": durable_slot_totals(&supersede_before),
                    "after": durable_slot_totals(&supersede_after),
                },
                "settle": {
                    "before": durable_slot_totals(&settle_before),
                    "after": durable_slot_totals(&settle_after),
                },
                "duplicate_ack": {
                    "before": durable_slot_totals(&duplicate_ack_before),
                    "after": durable_slot_totals(&duplicate_ack_after),
                },
            },
            "unrelated_rows_preserved": unrelated_rows_preserved,
            "no_op_footprints_equal": duplicate_before == duplicate_after
                && duplicate_ack_before == duplicate_ack_after,
            "pending_linked_fact_count": pending_linked_fact_count,
            "seed_admission_elapsed_us": seed_admission_elapsed_us,
            "seed_pending_listing_elapsed_us": pending_after_seed_us,
            "seed_pending_serialized_bytes": seed_pending_serialized_bytes,
            "seed_total_serialized_bytes": seed_total_serialized_bytes,
            "history_pressure": history_metrics,
            "reopened_exact_equality": reopened_exact_equality,
            "reopened_pending_count": reopened_pending_count,
            "reopened_terminal_count": reopened_terminal_count,
            "reopened_pending_serialized_bytes": reopened_pending_serialized_bytes,
            "reopened_total_serialized_bytes": reopened_total_serialized_bytes,
            "seed_semantic_fact_count": seed_graph.len(),
            "final_semantic_fact_count": reopened.semantic_fact_count(),
            "final_semantic_unresolved_count": reopened.semantic_unresolved_count(),
            "provider_ledger_available": false,
            "provider_evidence_ceiling": "support::test_transport hides exact provider ledger; this selector does not prove provider baseline",
        })
    );
    reopened.request_shutdown();
    reopened_driver
        .await
        .expect("many-delivery reopened shutdown");
}
