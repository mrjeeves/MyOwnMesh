#![cfg(feature = "transport-lab")]

//! Dedicated controls for the transport-independent V4 semantic owner.

use std::collections::HashMap;

use ed25519_dalek::SigningKey;

use myownmesh_core::protocol::FactPageMessage;
use myownmesh_core::semantic::{
    Admission, AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactContent, FactDomain,
    FactGraph, FactId, Role, SemanticAdmissionPolicy, SemanticCapacityDimension, SemanticError,
    SignedFact, VerifiedBootstrap,
};

#[derive(Debug, Clone, PartialEq, Eq)]
struct GraphState {
    context_id: myownmesh_core::semantic::MeshContextId,
    admitted: Vec<(FactId, Vec<u8>)>,
    quarantined: Vec<(FactId, Vec<u8>)>,
    projection: myownmesh_core::semantic::Projection,
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid device id")
}

fn closed_bootstrap(seed: u8, creation_id: u8) -> VerifiedBootstrap {
    VerifiedBootstrap::create_closed("semantic-controls", vec![key(seed)], [creation_id; 32])
        .expect("semantic bootstrap verifies")
}

fn fact(
    bootstrap: &VerifiedBootstrap,
    key: &SigningKey,
    body: FactBody,
    parents: Vec<FactId>,
) -> SignedFact {
    let domain = body.domain();
    SignedFact::sign(
        FactContent::new(domain, bootstrap.context_id(), body, author(key), parents),
        key,
    )
    .expect("semantic fixture fact signs")
}

fn graph_state(graph: &FactGraph) -> GraphState {
    GraphState {
        context_id: graph.context_id(),
        admitted: graph
            .ids()
            .map(|id| {
                (
                    *id,
                    graph
                        .get(id)
                        .expect("admitted fact remains present")
                        .content
                        .canonical_bytes(),
                )
            })
            .collect(),
        quarantined: graph
            .quarantined()
            .map(|(id, fact)| (*id, fact.content.canonical_bytes()))
            .collect(),
        projection: graph.projection(),
    }
}

fn authored(
    graph: &FactGraph,
    key: &SigningKey,
    body: FactBody,
    support: Vec<FactId>,
) -> SignedFact {
    let author = author(key);
    let witness = graph.authoring_witness(&body, &author);
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, support),
        key,
    )
    .expect("authoring witness fact signs")
}

fn fact_with_authority_predecessors(
    bootstrap: &VerifiedBootstrap,
    key: &SigningKey,
    body: FactBody,
    parents: Vec<FactId>,
    overrides: &[(DeviceId, Vec<FactId>)],
) -> SignedFact {
    let mut content = FactContent::new(
        body.domain(),
        bootstrap.context_id(),
        body,
        author(key),
        parents,
    );
    for authority_use in &mut content.authority_uses {
        if let Some((_, predecessors)) = overrides
            .iter()
            .find(|(subject, _)| subject == &authority_use.subject)
        {
            authority_use.predecessors = predecessors.clone();
        }
    }
    SignedFact::sign(content, key).expect("authority lineage fixture fact signs")
}

#[test]
fn canonical_field_mutation_is_refused() {
    let signing_key = key(1);
    let bootstrap = closed_bootstrap(1, 1);
    let original_target = author(&key(8));
    let mutated_target = author(&key(9));
    let mut signed = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: original_target,
            role: Role::Member,
        },
        Vec::new(),
    );
    signed.content.body = FactBody::RoleGrant {
        target: mutated_target,
        role: Role::Member,
    };
    assert!(matches!(
        signed.verify(),
        Err(SemanticError::InvalidAuthorityUse)
    ));
}

#[test]
fn wire_file_and_cache_round_trips_preserve_one_fact_identity() {
    let signing_key = key(2);
    let bootstrap = closed_bootstrap(2, 2);
    let signed = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: author(&signing_key),
            role: Role::Member,
        },
        Vec::new(),
    );
    let page = FactPageMessage::new(bootstrap.context_id(), vec![signed.clone()], None, true)
        .expect("fact page is bounded");
    let wire = serde_json::to_vec(&page).expect("fact page serializes");
    let decoded: FactPageMessage = serde_json::from_slice(&wire).expect("fact page decodes");
    assert_eq!(decoded.facts[0], signed);
    assert_eq!(decoded.facts[0].id, signed.id);

    let file = tempfile::NamedTempFile::new().expect("semantic fixture file opens");
    std::fs::write(file.path(), &wire).expect("canonical page writes to file");
    let from_file: FactPageMessage =
        serde_json::from_slice(&std::fs::read(file.path()).expect("canonical page reads"))
            .expect("canonical file page decodes");
    assert_eq!(from_file.facts[0], signed);

    let mut cache = HashMap::new();
    cache.insert(decoded.facts[0].id, decoded.facts[0].clone());
    assert_eq!(cache.get(&signed.id), Some(&signed));
}

#[test]
fn arrival_order_is_independent_and_missing_parents_quarantine() {
    let signing_key = key(3);
    let bootstrap = closed_bootstrap(3, 3);
    let target = author(&key(6));
    let genesis = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let successor = fact(
        &bootstrap,
        &signing_key,
        FactBody::RoleRevoke { target },
        vec![genesis.id],
    );

    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    assert!(matches!(
        graph.admit(successor.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 1);
    graph.admit(genesis.clone()).expect("genesis admits");
    assert_eq!(graph.retry_quarantined().unwrap(), vec![successor.id]);

    let mut reverse = FactGraph::from_bootstrap(&bootstrap);
    reverse
        .admit(genesis)
        .expect("genesis admits in reverse fixture");
    reverse
        .admit(successor)
        .expect("successor admits after parent");
    assert_eq!(graph.projection(), reverse.projection());
}

#[test]
fn ready_invalid_fact_does_not_starve_valid_sibling_in_either_arrival_order() {
    let root_key = key(63);
    let bad_key = key(64);
    let bootstrap = closed_bootstrap(63, 63);
    let genesis_target = author(&key(65));
    let good_target = author(&key(66));
    let genesis = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: genesis_target,
            role: Role::Member,
        },
        Vec::new(),
    );
    let bad = fact(
        &bootstrap,
        &bad_key,
        FactBody::RoleGrant {
            target: good_target.clone(),
            role: Role::Member,
        },
        vec![genesis.id],
    );
    let good = fact_with_authority_predecessors(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: good_target.clone(),
            role: Role::Member,
        },
        vec![genesis.id],
        &[
            (author(&root_key), vec![genesis.id]),
            (good_target.clone(), vec![]),
        ],
    );

    for reverse_order in [false, true] {
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        if reverse_order {
            graph.admit(good.clone()).expect("good fact quarantines");
            graph.admit(bad.clone()).expect("bad fact quarantines");
        } else {
            graph.admit(bad.clone()).expect("bad fact quarantines");
            graph.admit(good.clone()).expect("good fact quarantines");
        }
        graph.admit(genesis.clone()).expect("genesis admits");
        assert_eq!(
            graph.retry_quarantined(),
            Err(SemanticError::UnauthorizedRoleGrant),
            "the rejected sibling remains observable without blocking valid work"
        );
        assert_eq!(
            graph.evaluator().effective_role(&good_target),
            Some(Role::Member)
        );
        assert_eq!(graph.quarantined().count(), 0);
    }
}

#[test]
fn eviction_proof_stands_down_and_restoration_is_causal() {
    let signing_key = key(4);
    let device = author(&signing_key);

    let eviction_bootstrap = closed_bootstrap(4, 4);
    let eviction_target = author(&key(6));
    let mut graph = FactGraph::from_bootstrap(&eviction_bootstrap);
    let proposal = authored(
        &graph,
        &signing_key,
        FactBody::Evict {
            target: eviction_target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(proposal.clone())
        .expect("eviction proposal admits");
    let attestation = authored(
        &graph,
        &signing_key,
        FactBody::Attestation {
            target: eviction_target.clone(),
            proposal: proposal.id,
            decision: AttestationDecision::Evict,
            signer: device.clone(),
            contributions: Vec::new(),
        },
        Vec::new(),
    );
    graph
        .admit(attestation.clone())
        .expect("eviction attestation admits");
    let cells_before_proof = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
    let proof = authored(
        &graph,
        &signing_key,
        FactBody::EvictionProof {
            target: eviction_target.clone(),
            evidence: vec![attestation.id],
        },
        Vec::new(),
    );
    graph
        .admit(proof)
        .expect("eviction proof admits after evidence");
    assert!(graph.projection().is_stood_down(&eviction_target));
    let cells_after_proof = graph
        .projection()
        .cells()
        .map(|(cell, projection)| (cell.clone(), projection.clone()))
        .collect::<Vec<_>>();
    assert!(
        cells_before_proof == cells_after_proof,
        "proof evidence does not mutate ordinary exclusive cells"
    );

    let restoration = authored(
        &graph,
        &signing_key,
        FactBody::MembershipAdmit {
            target: eviction_target.clone(),
        },
        Vec::new(),
    );
    assert!(
        restoration
            .content
            .parents
            .contains(&proof_id_for(&graph, &eviction_target)),
        "stand-down restoration must carry the active proof lineage"
    );
    graph.admit(restoration).expect("owner restoration admits");
    assert!(
        !graph.projection().is_stood_down(&eviction_target),
        "an effective causal MembershipAdmit supersedes stand-down evidence"
    );
}

fn proof_id_for(graph: &FactGraph, target: &DeviceId) -> FactId {
    graph
        .ids()
        .copied()
        .find(|id| {
            matches!(
                graph.get(id).map(|fact| &fact.content.body),
                Some(FactBody::EvictionProof { target: found, .. }) if found == target
            )
        })
        .expect("the graph contains the active eviction proof")
}

#[test]
fn closed_repeats_are_idempotent_and_author_lifetime_cap_is_exact() {
    let root_key = key(200);
    let bootstrap = closed_bootstrap(200, 200);
    let target_a = author(&key(201));
    let target_b = author(&key(202));
    let target_c = author(&key(203));
    let policy = SemanticAdmissionPolicy {
        max_retained_facts_per_author: 4,
        ..SemanticAdmissionPolicy::default()
    };
    let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);

    let meaningful = [
        FactBody::RoleGrant {
            target: target_a.clone(),
            role: Role::Member,
        },
        FactBody::RoleGrant {
            target: target_b.clone(),
            role: Role::Member,
        },
        FactBody::RoleRevoke { target: target_a },
        FactBody::RoleRevoke { target: target_b },
    ];
    for body in meaningful {
        let candidate = authored(&graph, &root_key, body, Vec::new());
        assert_eq!(graph.admit(candidate.clone()), Ok(Admission::Inserted));
        let before_repeat = graph_state(&graph);
        assert_eq!(graph.admit(candidate), Ok(Admission::AlreadyPresent));
        assert_eq!(
            graph_state(&graph),
            before_repeat,
            "a repeated state-equivalent fact has no graph or projection growth"
        );
    }

    let before_n_plus_one = graph_state(&graph);
    let over_cap = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: target_c,
            role: Role::Member,
        },
        Vec::new(),
    );
    assert!(matches!(
        graph.admit(over_cap),
        Err(SemanticError::CapacityExceeded {
            dimension: SemanticCapacityDimension::RetainedFactsPerAuthor,
            limit: 4,
            observed: 5,
        })
    ));
    assert_eq!(
        graph_state(&graph),
        before_n_plus_one,
        "the retained-per-author N+1 refusal leaves graph, projection, and identity unchanged"
    );
}

#[test]
fn open_lifecycle_has_zero_durable_fact_authorship() {
    let bootstrap = VerifiedBootstrap::open("semantic-open-presence").expect("open bootstrap");
    let signer = key(204);
    let candidate = fact(
        &bootstrap,
        &signer,
        FactBody::RoleGrant {
            target: author(&signer),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let before = graph_state(&graph);
    assert_eq!(
        graph.admit(candidate),
        Err(SemanticError::DomainMismatch),
        "Open lifecycle presence cannot author a durable governance fact"
    );
    assert_eq!(graph_state(&graph), before);
}

#[test]
fn attestation_mutation_and_forged_eviction_are_rejected() {
    let signing_key = key(5);
    let bootstrap = closed_bootstrap(5, 5);
    let device = author(&signing_key);
    let mut attestation = SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::Attestation {
                target: device.clone(),
                proposal: FactId::from_bytes([8; 32]),
                decision: AttestationDecision::Approve,
                signer: device.clone(),
                contributions: Vec::new(),
            },
            device.clone(),
            Vec::new(),
        ),
        &signing_key,
    )
    .expect("attestation signs");
    attestation.content.body = FactBody::Attestation {
        target: device.clone(),
        proposal: FactId::from_bytes([8; 32]),
        decision: AttestationDecision::Reject,
        signer: device.clone(),
        contributions: Vec::new(),
    };
    assert!(matches!(
        attestation.verify(),
        Err(SemanticError::FactIdMismatch)
    ));

    let other_device = author(&key(6));
    let mismatched_eviction = FactContent::new(
        FactDomain::EvictionProof,
        bootstrap.context_id(),
        FactBody::SelfStandDown {
            device_id: other_device,
            evidence: vec![FactId::from_bytes([7; 32])],
        },
        author(&signing_key),
        Vec::new(),
    );
    assert!(matches!(
        SignedFact::sign(mismatched_eviction, &signing_key),
        Err(SemanticError::InvalidStandDownProof)
    ));
}

#[test]
fn foreign_context_is_rejected_before_quarantine() {
    let signing_key = key(7);
    let local = closed_bootstrap(7, 1);
    let foreign = closed_bootstrap(7, 2);
    assert_ne!(local.context_id(), foreign.context_id());

    let foreign_fact = fact(
        &foreign,
        &signing_key,
        FactBody::RoleGrant {
            target: author(&signing_key),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&local);
    assert!(matches!(
        graph.admit(foreign_fact),
        Err(SemanticError::ContextMismatch { .. })
    ));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 0);
}

#[test]
fn authoring_witness_makes_ids_and_projection_arrival_order_independent() {
    let root_key = key(20);
    let bootstrap = closed_bootstrap(20, 20);
    let target = author(&key(21));
    let mut left = FactGraph::from_bootstrap(&bootstrap);
    let mut right = FactGraph::from_bootstrap(&bootstrap);

    let member_left = authored(
        &left,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let owner_left = authored(
        &left,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    let member_right = authored(
        &right,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let owner_right = authored(
        &right,
        &root_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    assert_eq!(member_left.id, member_right.id);
    assert_eq!(owner_left.id, owner_right.id);

    left.admit(member_left).expect("member branch admits");
    left.admit(owner_left).expect("owner branch admits");
    right
        .admit(owner_right)
        .expect("reverse owner branch admits");
    right
        .admit(member_right)
        .expect("reverse member branch admits");
    assert_eq!(
        left.ids().copied().collect::<Vec<_>>(),
        right.ids().copied().collect::<Vec<_>>(),
        "the same signed branch set has identical accepted FactIds"
    );
    assert_eq!(left.projection(), right.projection());
    assert!(left
        .projection()
        .is_conflicted(&myownmesh_core::semantic::ExclusiveCell::role(target)));
}

#[test]
fn missing_authority_predecessor_does_not_become_valid_after_late_grant() {
    let root_key = key(22);
    let controller_key = key(23);
    let bootstrap = closed_bootstrap(22, 22);
    let target = author(&key(24));
    let controller = author(&controller_key);
    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let stale = fact(
        &bootstrap,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    assert_eq!(
        graph.admit(stale.clone()),
        Err(SemanticError::UnauthorizedRoleGrant)
    );
    graph
        .admit(controller_grant.clone())
        .expect("late controller grant admits");
    assert_eq!(graph.evaluator().effective_role(&target), None);
    assert_eq!(
        graph.admit(stale),
        Err(SemanticError::UnauthorizedRoleGrant)
    );

    let causally_supported = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        vec![controller_grant.id],
    );
    graph
        .admit(causally_supported)
        .expect("supported controller grant admits");
    assert_eq!(
        graph.evaluator().effective_role(&target),
        Some(Role::Member)
    );
}

#[test]
fn stale_operation_is_explicit_but_arrival_order_independent() {
    let root_key = key(25);
    let controller_key = key(26);
    let bootstrap = closed_bootstrap(25, 25);
    let controller = author(&controller_key);
    let target = author(&key(27));
    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    let mut source = FactGraph::from_bootstrap(&bootstrap);
    source
        .admit(controller_grant.clone())
        .expect("controller grant admits");
    let earlier_operation = authored(
        &source,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        vec![controller_grant.id],
    );
    let later_revoke = authored(
        &source,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );

    source
        .admit(earlier_operation.clone())
        .expect("the operation is valid in its signed causal profile");
    source
        .admit(later_revoke.clone())
        .expect("the revoke admits after the shared controller grant");

    let mut reverse = FactGraph::from_bootstrap(&bootstrap);
    assert!(matches!(
        reverse.admit(earlier_operation.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert!(matches!(
        reverse.admit(later_revoke.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    reverse
        .admit(controller_grant)
        .expect("shared causal predecessor admits");
    let retried = reverse
        .retry_quarantined()
        .expect("the same signed facts admit independent of delivery order");
    assert_eq!(
        retried
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>(),
        [earlier_operation.id, later_revoke.id]
            .into_iter()
            .collect::<std::collections::BTreeSet<_>>()
    );
    assert_eq!(
        source.ids().copied().collect::<Vec<_>>(),
        reverse.ids().copied().collect::<Vec<_>>(),
        "accepted FactIds are permutation-independent"
    );
    assert_eq!(source.projection(), reverse.projection());
    assert_eq!(reverse.evaluator().effective_role(&target), None);
    assert_eq!(reverse.evaluator().effective_role(&controller), None);
}

#[test]
fn omitted_concurrent_root_lineage_is_explicit_conflict_not_arrival_order_authority() {
    let root_key = key(67);
    let bootstrap = closed_bootstrap(67, 67);
    let root = author(&root_key);
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let revoke = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleRevoke {
            target: root.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(revoke)
        .expect("root revoke advances its role cell");

    let omitted = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: author(&key(68)),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph
        .admit(omitted)
        .expect("a candidate-relative fork may be admitted without seeing the concurrent revoke");
    assert_eq!(graph.authority_use_heads(&root).len(), 2);
    assert_eq!(
        graph.evaluator().effective_role(&author(&key(68))),
        None,
        "the concurrent signed AuthorityUse fork fails closed"
    );
}

#[test]
fn signed_authority_use_omission_is_rejected_when_the_candidate_cites_a_predecessor() {
    let root_key = key(74);
    let controller_key = key(75);
    let bootstrap = closed_bootstrap(74, 74);
    let controller = author(&controller_key);
    let target = author(&key(76));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph.admit(grant.clone()).expect("controller grant admits");
    let honest = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let mut malformed_content = honest.content.clone();
    malformed_content
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == controller)
        .expect("author AuthorityUse is present")
        .predecessors
        .clear();
    let malformed = SignedFact::sign(malformed_content, &controller_key)
        .expect("malformed content remains internally signed");
    assert_eq!(
        graph.admit(malformed),
        Err(SemanticError::UnauthorizedRoleGrant),
        "the candidate must carry the exact signed authority predecessor"
    );

    let mut supersets_content = honest.content.clone();
    supersets_content
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == target)
        .expect("target AuthorityUse is present")
        .predecessors = vec![grant.id];
    let supersets = SignedFact::sign(supersets_content, &controller_key)
        .expect("superset content remains internally signed");
    assert_eq!(
        graph.admit(supersets),
        Err(SemanticError::UnauthorizedRoleGrant),
        "an authority predecessor superset cannot smuggle unrelated lineage"
    );
}

#[test]
fn authority_use_fork_requires_explicit_typed_selection_across_arrival_orders() {
    let root_key = key(77);
    let controller_key = key(78);
    let bootstrap = closed_bootstrap(77, 77);
    let controller = author(&controller_key);
    let target = author(&key(79));
    let later_target = author(&key(80));

    let mut seeded = FactGraph::from_bootstrap(&bootstrap);
    let grant_controller = authored(
        &seeded,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    seeded
        .admit(grant_controller.clone())
        .expect("the controller grant admits");

    let operation = authored(
        &seeded,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &seeded,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );

    let mut forward = seeded.clone();
    forward
        .admit(operation.clone())
        .expect("the controller branch admits");
    forward
        .admit(revoke.clone())
        .expect("the root revoke branch admits");
    let mut reverse = seeded.clone();
    reverse
        .admit(revoke.clone())
        .expect("the root revoke branch admits first");
    reverse
        .admit(operation.clone())
        .expect("the controller branch admits second");

    // A selector that omits a current AuthorityUse head remains invalid even
    // when its signed AuthorityUse(C) predecessor set is complete. Deliver
    // it through production quarantine first, then retry after both omitted
    // heads arrive; retry rejects and clears it rather than repairing the
    // citation set from arrival order.
    let omitted_head = fact(
        &bootstrap,
        &controller_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: vec![operation.id],
            selected_head: operation.id,
        },
        vec![operation.id, revoke.id],
    );
    let mut quarantined = seeded;
    assert!(matches!(
        quarantined.admit(omitted_head),
        Ok(Admission::Quarantined { .. })
    ));
    assert_eq!(quarantined.quarantined().count(), 1);
    quarantined
        .admit(revoke.clone())
        .expect("the omitted selector's revoke parent admits");
    quarantined
        .admit(operation.clone())
        .expect("the omitted selector's operation parent admits");
    assert_eq!(
        quarantined.retry_quarantined(),
        Err(SemanticError::IncompleteResolution),
        "complete AuthorityUse predecessors cannot hide an omitted current head"
    );
    assert_eq!(quarantined.quarantined().count(), 0);

    assert_eq!(
        forward.authority_use_heads(&controller),
        reverse.authority_use_heads(&controller),
        "the concurrent AuthorityUse(C) fork is independent of arrival order"
    );
    assert_eq!(
        forward.evaluator().effective_role(&target),
        None,
        "an unresolved AuthorityUse fork cannot authorize the controller branch"
    );
    assert_eq!(forward.projection(), reverse.projection());

    let later = fact(
        &bootstrap,
        &controller_key,
        FactBody::RoleGrant {
            target: later_target.clone(),
            role: Role::Member,
        },
        vec![operation.id, revoke.id],
    );
    assert_eq!(
        forward.admit(later),
        Err(SemanticError::UnauthorizedRoleGrant),
        "an ordinary later fact cannot resolve or revive the fork"
    );

    let mut malformed = FactContent::new(
        FactDomain::Governance,
        bootstrap.context_id(),
        FactBody::RoleGrant {
            target: later_target,
            role: Role::Member,
        },
        controller.clone(),
        vec![operation.id, revoke.id],
    );
    malformed
        .authority_uses
        .iter_mut()
        .find(|use_| use_.subject == controller)
        .expect("the direct candidate carries AuthorityUse(C)")
        .predecessors = vec![operation.id];
    let malformed = SignedFact::sign(malformed, &controller_key)
        .expect("the malicious candidate remains internally signed");
    assert_eq!(
        reverse.admit(malformed),
        Err(SemanticError::UnauthorizedRoleGrant),
        "direct FactContent construction cannot omit the competing predecessor"
    );

    let make_selection = |graph: &FactGraph, selected_head| {
        authored(
            graph,
            &root_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: vec![operation.id, revoke.id],
                selected_head,
            },
            Vec::new(),
        )
    };
    let ordinary_role_selection = authored(
        &forward,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: operation.id,
        },
        Vec::new(),
    );
    assert_eq!(
        forward.admit(ordinary_role_selection),
        Err(SemanticError::IncompleteResolution),
        "ordinary Role(C) resolution cannot select the cross-cell O lineage"
    );
    assert_eq!(
        forward.authority_lineage(&controller).heads().len(),
        2,
        "ordinary Role(C) resolution leaves AuthorityLineage(C) unresolved"
    );
    assert_eq!(
        forward.authority_lineage(&controller).selected_branch(),
        None,
        "ordinary Role(C) resolution cannot collapse AuthorityLineage(C)"
    );
    let selection_operation = make_selection(&forward, operation.id);
    let selection_operation_reverse = make_selection(&reverse, operation.id);
    assert_eq!(
        selection_operation.id, selection_operation_reverse.id,
        "typed AuthorityUse selection has one identity in either arrival order"
    );
    let selection_operation_id = selection_operation.id;
    forward
        .admit(selection_operation)
        .expect("the typed selection of the controller branch admits");
    assert_eq!(
        forward.authority_lineage(&controller).selected_branch(),
        Some(operation.id),
        "typed AuthorityLineage(C) selection records the selected O authority branch"
    );
    assert_eq!(
        forward.evaluator().effective_role(&controller),
        None,
        "selecting O in Role(C) cannot cross-select a role for C"
    );
    assert_eq!(
        forward.evaluator().effective_membership(&controller),
        None,
        "selecting O leaves C's same-cell membership projection unchanged"
    );
    assert!(
        !forward
            .evaluator()
            .admits_closed_session(&controller, &controller),
        "selecting O cannot make revoked C eligible for a closed session"
    );
    assert_eq!(
        forward.evaluator().effective_role(&target),
        Some(Role::Member),
        "the selected AuthorityUse branch is effective"
    );
    let regrant_after_o = authored(
        &forward,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    forward
        .admit(regrant_after_o.clone())
        .expect("the root can regrant C after selecting O");
    assert_eq!(
        forward.authority_lineage(&controller).effective_head(),
        Some(regrant_after_o.id),
        "the later regrant advances the selected O lineage"
    );
    assert_eq!(
        forward.evaluator().effective_role(&controller),
        Some(Role::Controller),
        "the selected O lineage permits C's later regrant"
    );
    assert_eq!(
        forward.evaluator().effective_role(&target),
        Some(Role::Member),
        "a regrant cannot discard the selected O branch"
    );

    let selection_revoke = make_selection(&reverse, revoke.id);
    let selection_revoke_id = selection_revoke.id;
    reverse
        .admit(selection_revoke)
        .expect("the typed selection of the revoke branch admits");
    assert_eq!(
        reverse.authority_lineage(&controller).selected_branch(),
        Some(revoke.id),
        "typed Role(C) selection records the selected R authority branch"
    );
    assert_eq!(
        reverse.evaluator().effective_role(&controller),
        None,
        "selecting R keeps revoked C's role cell inactive"
    );
    assert_eq!(
        reverse.evaluator().effective_membership(&controller),
        None,
        "selecting R keeps C's membership cell explicitly absent"
    );
    assert!(
        !reverse
            .evaluator()
            .admits_closed_session(&controller, &controller),
        "selecting R keeps closed-session admission fail-closed"
    );
    assert_eq!(
        reverse.evaluator().effective_role(&target),
        None,
        "the unselected controller branch remains permanently ineffective"
    );
    let regrant_after_r = authored(
        &reverse,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    reverse
        .admit(regrant_after_r.clone())
        .expect("the root can regrant C after selecting R");
    assert_eq!(
        reverse.authority_lineage(&controller).effective_head(),
        Some(regrant_after_r.id),
        "the later regrant advances the selected R lineage"
    );
    assert_eq!(
        reverse.evaluator().effective_role(&controller),
        Some(Role::Controller),
        "the selected R lineage permits C's later regrant"
    );
    assert_eq!(
        reverse.evaluator().effective_role(&target),
        None,
        "the later regrant cannot revive the losing O operation"
    );
    assert!(
        reverse
            .evaluator()
            .admits_closed_session(&controller, &controller),
        "the selected R lineage admits C only after the explicit regrant"
    );
    assert_ne!(
        selection_operation_id, selection_revoke_id,
        "selecting opposite AuthorityUse branches has distinct typed facts"
    );
    assert_eq!(
        reverse.authority_use_heads(&controller).len(),
        1,
        "the explicit selection replaces, rather than preserves, the fork head set"
    );
}

#[test]
fn cross_cell_resolution_cannot_select_a_role_authority_fork() {
    let root_key = key(124);
    let controller_key = key(125);
    let bootstrap = closed_bootstrap(124, 124);
    let controller = author(&controller_key);
    let target = author(&key(126));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);

    let grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(grant.clone())
        .expect("G controller grant admits");
    let operation = authored(
        &graph,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &graph,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(operation.clone())
        .expect("O controller operation admits");
    graph.admit(revoke.clone()).expect("R root revoke admits");
    let authority_heads = graph.authority_use_heads(&controller);
    assert_eq!(
        authority_heads.len(),
        2,
        "G/O/R establishes the concurrent AuthorityUse fork before the payload"
    );

    // A Membership(C) resolution may cite the exact AuthorityUse(C) fork,
    // but it is not a typed selection of that lineage. The cross-cell
    // payload is rejected before it can collapse the fork.
    let membership_resolution = authored(
        &graph,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: authority_heads.clone(),
            selected_head: operation.id,
        },
        Vec::new(),
    );
    assert_eq!(
        graph.admit(membership_resolution),
        Err(SemanticError::IncompleteResolution),
        "Membership(C) cannot bypass the AuthorityUse(C) resolution type"
    );
    assert_eq!(
        graph.authority_lineage(&controller).heads().len(),
        2,
        "the rejected payload leaves the exact AuthorityUse(C) fork intact"
    );
    assert!(
        !graph.authority_lineage(&controller).is_singular(),
        "an unresolved AuthorityUse(C) fork remains non-singular"
    );
    assert_eq!(
        graph.authority_lineage(&controller).selected_branch(),
        None,
        "a Membership(C) payload cannot select AuthorityUse(C)"
    );
    assert_eq!(
        graph.evaluator().effective_role(&controller),
        None,
        "the revoked controller remains inactive"
    );
    assert_eq!(
        graph.evaluator().effective_role(&target),
        None,
        "the losing O/RoleGrant(X) remains inactive"
    );

    // A Closed authority selector must cite the complete current lineage.
    // An incomplete typed selector is refused before it can affect either
    // projection; no removed Open participation cell is involved.
    let incomplete_authority_resolution = authored(
        &graph,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: vec![revoke.id],
            selected_head: revoke.id,
        },
        Vec::new(),
    );
    assert_eq!(
        graph.admit(incomplete_authority_resolution),
        Err(SemanticError::IncompleteResolution),
        "an incomplete Closed authority selector is refused before projection"
    );
    assert_eq!(
        graph.evaluator().effective_role(&target),
        None,
        "a rejected authority selector leaves the role loser inactive"
    );
}

#[test]
fn second_order_payload_resolution_cannot_join_the_role_authority_fork() {
    let root_key = key(128);
    let controller_key = key(129);
    let authority_a_key = key(130);
    let authority_d_key = key(131);
    let bootstrap = closed_bootstrap(128, 128);
    let controller = author(&controller_key);
    let authority_a = author(&authority_a_key);
    let authority_d = author(&authority_d_key);
    let target = author(&key(132));
    let mut base = FactGraph::from_bootstrap(&bootstrap);

    let grant_controller = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    base.admit(grant_controller.clone())
        .expect("G controller grant admits");
    let grant_a = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: authority_a.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    base.admit(grant_a.clone()).expect("A owner grant admits");
    let grant_d = authored(
        &base,
        &root_key,
        FactBody::RoleGrant {
            target: authority_d.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    base.admit(grant_d.clone()).expect("D owner grant admits");
    assert_eq!(
        base.evaluator().effective_role(&controller),
        Some(Role::Controller)
    );
    assert_eq!(
        base.evaluator().effective_role(&authority_a),
        Some(Role::Owner)
    );
    assert_eq!(
        base.evaluator().effective_role(&authority_d),
        Some(Role::Owner)
    );

    // O, R, M, and E are all authored from the same singular base. O uses C;
    // R uses A; M and E use D, while all four carry C's exact G predecessor.
    let operation = authored(
        &base,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &base,
        &authority_a_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let membership = authored(
        &base,
        &authority_d_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let evict = authored(
        &base,
        &authority_d_key,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = base.clone();
    for branch in [
        operation.clone(),
        revoke.clone(),
        membership.clone(),
        evict.clone(),
    ] {
        fork.admit(branch)
            .expect("concurrent second-order branch admits");
    }
    let authority_heads = fork.authority_use_heads(&controller);
    assert_eq!(
        authority_heads.len(),
        4,
        "O/R/M/E form the complete AuthorityUse(C) conflict set"
    );
    let membership_cell = ExclusiveCell::membership(controller.clone());
    let mut payload_heads = fork.cell_heads(&membership_cell);
    payload_heads.sort();
    let mut expected_payload_heads = vec![membership.id, evict.id];
    expected_payload_heads.sort();
    assert_eq!(
        payload_heads, expected_payload_heads,
        "M/E are the exact ordinary Membership(C) payload heads"
    );

    let resolution = authored(
        &fork,
        &root_key,
        FactBody::Resolution {
            cell: membership_cell,
            cited_heads: payload_heads.clone(),
            selected_head: evict.id,
        },
        Vec::new(),
    );
    let controller_use = resolution
        .content
        .authority_uses
        .iter()
        .find(|authority_use| authority_use.subject == controller)
        .expect("Q carries AuthorityUse(C)");
    assert_eq!(
        controller_use.predecessors, authority_heads,
        "Q carries every O/R/M/E AuthorityUse(C) predecessor"
    );

    let admission = fork.admit(resolution);
    assert!(
        matches!(
            admission,
            Ok(Admission::Inserted) | Err(SemanticError::IncompleteResolution)
        ),
        "Q is either rejected or remains a payload-local resolution"
    );
    assert!(
        fork.projection()
            .is_conflicted(&ExclusiveCell::role(controller.clone())),
        "R/E keep C's role cell conflicted"
    );
    assert_eq!(
        fork.evaluator().effective_role(&controller),
        None,
        "C remains revoked under the unresolved role authority fork"
    );
    assert_eq!(
        fork.evaluator().effective_role(&target),
        None,
        "O/RoleGrant(X) remains inactive after the payload attempt"
    );
    assert_eq!(
        fork.authority_lineage(&controller).selected_branch(),
        None,
        "no payload resolution invents a selected AuthorityUse(C) branch"
    );
}

#[test]
fn membership_admit_uses_controller_tier_with_owner_counterfactual() {
    let root_key = key(69);
    let controller_key = key(70);
    let member_key = key(71);
    let bootstrap = closed_bootstrap(69, 69);
    let controller = author(&controller_key);
    let member = author(&member_key);
    let target = author(&key(72));
    let mut graph = FactGraph::from_bootstrap(&bootstrap);

    let controller_grant = fact(
        &bootstrap,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    graph
        .admit(controller_grant)
        .expect("root controller grant admits");
    let member_grant = authored(
        &graph,
        &root_key,
        FactBody::RoleGrant {
            target: member.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    graph.admit(member_grant).expect("root member grant admits");

    let controller_admit = authored(
        &graph,
        &controller_key,
        FactBody::MembershipAdmit {
            target: target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(controller_admit)
        .expect("Controller may sign a member admission");

    let member_admit = authored(
        &graph,
        &member_key,
        FactBody::MembershipAdmit {
            target: author(&key(73)),
        },
        Vec::new(),
    );
    assert_eq!(
        graph.admit(member_admit),
        Err(SemanticError::UnauthorizedMembershipAdmit),
        "a plain Member cannot author a member-log admission"
    );

    let owner_admit = authored(
        &graph,
        &root_key,
        FactBody::MembershipAdmit {
            target: target.clone(),
        },
        Vec::new(),
    );
    graph
        .admit(owner_admit)
        .expect("Owner remains a valid higher-tier member-admission signer");
}

#[test]
fn finite_authority_fork_requires_complete_resolution_before_regrant() {
    let root_key = key(110);
    let controller_key = key(111);
    let target = author(&key(112));
    let future_target = author(&key(113));
    let bootstrap = closed_bootstrap(110, 110);
    let controller = author(&controller_key);
    let mut source = FactGraph::from_bootstrap(&bootstrap);

    // G grants C. O and R are then authored from the same exact G base: O is
    // the controller's operation, while R revokes that controller. Their
    // AuthorityUse(C) records therefore form an incomparable fork.
    let grant = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source
        .admit(grant.clone())
        .expect("G controller grant admits");
    let operation = authored(
        &source,
        &controller_key,
        FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    let revoke = authored(
        &source,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(operation.clone())
        .expect("O controller operation admits");
    fork.admit(revoke.clone()).expect("R root revoke admits");
    assert_eq!(fork.authority_use_heads(&controller).len(), 2);
    assert_eq!(fork.evaluator().effective_role(&target), None);
    assert_eq!(fork.evaluator().effective_role(&controller), None);

    // No ordinary operation may smuggle a choice through the unresolved fork.
    let blocked = authored(
        &fork,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    assert_eq!(
        fork.admit(blocked),
        Err(SemanticError::UnauthorizedRoleGrant),
        "the unresolved AuthorityUse fork fails closed"
    );

    let incomplete = fact(
        &bootstrap,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id],
            selected_head: operation.id,
        },
        vec![operation.id],
    );
    assert_eq!(
        fork.admit(incomplete),
        Err(SemanticError::IncompleteResolution),
        "Q must cite every incomparable AuthorityUse(C) head"
    );
    let wrong = fact(
        &bootstrap,
        &root_key,
        FactBody::Resolution {
            cell: ExclusiveCell::role(controller.clone()),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: grant.id,
        },
        vec![operation.id, revoke.id],
    );
    assert_eq!(
        fork.admit(wrong),
        Err(SemanticError::ResolutionSelectionNotCited),
        "Q cannot select a head outside the complete conflict set"
    );

    // Q selects R. N is the only later regrant; O remains a historical loser.
    let resolution = authored(
        &fork,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: vec![operation.id, revoke.id],
            selected_head: revoke.id,
        },
        Vec::new(),
    );
    fork.admit(resolution)
        .expect("Q complete AuthorityLineage(C) resolution selecting R admits");
    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    fork.admit(regrant).expect("N regrant admits");
    let future = authored(
        &fork,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );
    fork.admit(future)
        .expect("post-N controller operation admits");
    assert_eq!(
        fork.evaluator().effective_role(&controller),
        Some(Role::Controller)
    );
    assert_eq!(
        fork.evaluator().effective_role(&future_target),
        Some(Role::Member)
    );
    assert_eq!(
        fork.evaluator().effective_role(&target),
        None,
        "O remains permanently inactive after Q selects R and N regrants C"
    );
}

#[test]
fn stale_selector_follows_newer_typed_role_resolution() {
    let root_key = key(140);
    let controller_key = key(141);
    let owner_a_key = key(142);
    let future_target = author(&key(143));
    let bootstrap = closed_bootstrap(140, 140);
    let controller = author(&controller_key);
    let owner_a = author(&owner_a_key);

    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let grant = authored(
        &source,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Controller,
        },
        Vec::new(),
    );
    source.admit(grant).expect("G controller grant admits");

    // M and V are concurrent facts from the same C-authority base.  V is an
    // Evict, so it advances both the Role(C) and Membership(C) cells while M
    // advances only Membership(C).
    let membership_m = authored(
        &source,
        &controller_key,
        FactBody::MembershipAdmit {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let eviction_v = authored(
        &source,
        &controller_key,
        FactBody::Evict {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let mut fork = source.clone();
    fork.admit(membership_m.clone())
        .expect("M membership head admits");
    fork.admit(eviction_v.clone())
        .expect("V eviction head admits");
    let mut authority_heads = fork.authority_use_heads(&controller);
    authority_heads.sort();
    let mut expected_authority_heads = vec![membership_m.id, eviction_v.id];
    expected_authority_heads.sort();
    assert_eq!(authority_heads, expected_authority_heads);
    assert_eq!(fork.evaluator().effective_role(&controller), None);
    assert_eq!(fork.evaluator().effective_membership(&controller), None);
    let role_selection = authored(
        &fork,
        &root_key,
        FactBody::AuthorityLineageResolution {
            subject: controller.clone(),
            cited_heads: authority_heads,
            selected_head: eviction_v.id,
        },
        Vec::new(),
    );
    fork.admit(role_selection.clone())
        .expect("typed AuthorityLineage(C) selection of V admits");
    assert_eq!(
        fork.evaluator().effective_membership(&controller),
        Some(false),
        "the typed Role(C) selection projects V's eviction before Q"
    );
    let regrant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    fork.admit(regrant.clone())
        .expect("causal Owner regrant admits");
    let owner_grant = authored(
        &fork,
        &root_key,
        FactBody::RoleGrant {
            target: owner_a.clone(),
            role: Role::Owner,
        },
        Vec::new(),
    );
    fork.admit(owner_grant.clone())
        .expect("GA owner grant admits");
    let post_ga = fork.clone();

    // Q and R are authored from the same exact post-GA graph, so their arrival
    // order cannot choose an authority branch.
    let payload = post_ga.clone();
    let mut payload_heads = vec![membership_m.id, eviction_v.id];
    payload_heads.sort();
    let mut expected_payload_heads = vec![membership_m.id, eviction_v.id];
    expected_payload_heads.sort();
    assert_eq!(payload_heads, expected_payload_heads);
    let q = authored(
        &payload,
        &controller_key,
        FactBody::Resolution {
            cell: ExclusiveCell::membership(controller.clone()),
            cited_heads: payload_heads,
            selected_head: membership_m.id,
        },
        Vec::new(),
    );
    let r = authored(
        &payload,
        &root_key,
        FactBody::RoleRevoke {
            target: controller.clone(),
        },
        Vec::new(),
    );
    let q_id = q.id;
    let r_id = r.id;
    let mut settled = post_ga.clone();
    settled
        .admit(q.clone())
        .expect("Q membership resolution admits");
    settled.admit(r.clone()).expect("R role revoke admits");
    // Pick from a bounded, deterministic set of valid redundant-support
    // profiles until the production IDs make the old LIFO walk observable:
    // R must sort after T2, so pending.pop() would visit R first, follow its
    // older T0 path, and potentially select the stale branch before T2's
    // explicit R selector is considered.
    let redundant_supports = [
        Vec::new(),
        vec![membership_m.id],
        vec![eviction_v.id],
        vec![role_selection.id],
        vec![regrant.id],
        vec![owner_grant.id],
        vec![membership_m.id, role_selection.id],
        vec![eviction_v.id, role_selection.id],
        vec![membership_m.id, regrant.id],
        vec![eviction_v.id, regrant.id],
        vec![role_selection.id, owner_grant.id],
        vec![regrant.id, owner_grant.id],
        vec![membership_m.id, eviction_v.id, role_selection.id],
        vec![membership_m.id, eviction_v.id, regrant.id],
        vec![role_selection.id, regrant.id, owner_grant.id],
        vec![
            membership_m.id,
            eviction_v.id,
            role_selection.id,
            regrant.id,
            owner_grant.id,
        ],
    ];
    let role_resolution = redundant_supports
        .into_iter()
        .map(|support| {
            authored(
                &settled,
                &owner_a_key,
                FactBody::AuthorityLineageResolution {
                    subject: controller.clone(),
                    cited_heads: vec![q_id, r_id],
                    selected_head: r_id,
                },
                support,
            )
        })
        .find(|candidate| r_id > candidate.id)
        .expect("bounded redundant support profiles produce R.id > T2.id");
    let role_resolution_id = role_resolution.id;
    assert!(
        r_id > role_resolution_id,
        "R must sort after T2 so the old first-hit walk follows R -> T0"
    );
    let mut after_selection = settled.clone();
    after_selection
        .admit(role_resolution.clone())
        .expect("typed AuthorityLineage(C) resolution over Q/R admits");
    let regrant_after_selection = authored(
        &after_selection,
        &root_key,
        FactBody::RoleGrant {
            target: controller.clone(),
            role: Role::Owner,
        },
        vec![r_id],
    );
    after_selection
        .admit(regrant_after_selection.clone())
        .expect("post-selection Owner regrant admits");
    let future = authored(
        &after_selection,
        &controller_key,
        FactBody::RoleGrant {
            target: future_target.clone(),
            role: Role::Member,
        },
        Vec::new(),
    );

    for order in [[q.clone(), r.clone()], [r.clone(), q.clone()]] {
        let mut graph = source.clone();
        for fact in [
            membership_m.clone(),
            eviction_v.clone(),
            role_selection.clone(),
            regrant.clone(),
            owner_grant.clone(),
        ] {
            graph.admit(fact).expect("post-GA Q/R fact admits");
        }
        for fact in order {
            graph.admit(fact).expect("post-N Q/R fact admits");
        }
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            None,
            "R revokes C even when Q arrives first"
        );
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "the Q/R AuthorityUse fork keeps Membership(C) fail-closed"
        );
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            None,
            "the concurrent Q/R fork has no selected Role(C) branch"
        );
        assert!(
            !graph
                .evaluator()
                .admits_closed_session(&controller, &controller),
            "the revoked Role(C) keeps closed-session admission fail-closed"
        );
        let mut authority_heads = graph.authority_use_heads(&controller);
        authority_heads.sort();
        let mut expected_authority_heads = vec![q_id, r_id];
        expected_authority_heads.sort();
        assert_eq!(
            authority_heads, expected_authority_heads,
            "Q and R form the complete concurrent AuthorityUse(C) heads"
        );

        graph
            .admit(role_resolution.clone())
            .expect("typed AuthorityLineage(C) resolution selects R from the complete Q/R fork");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(r_id),
            "the typed AuthorityLineage(C) resolution, not payload Q, selects R"
        );
        graph
            .admit(regrant_after_selection.clone())
            .expect("the causal post-selection Owner regrant admits");
        let successor = graph
            .get(&regrant_after_selection.id)
            .expect("U2 remains in the public graph");
        assert!(
            successor.content.parents.contains(&r_id)
                && successor.content.parents.contains(&role_resolution_id),
            "U2 retains both the redundant R and causally newer T2 parents"
        );
        assert_eq!(
            graph.authority_lineage(&controller).effective_head(),
            Some(regrant_after_selection.id),
            "the effective lineage follows the causally newer U2 successor"
        );
        graph
            .admit(future.clone())
            .expect("post-regrant controller operation admits");
        assert_eq!(
            graph.evaluator().effective_role(&controller),
            Some(Role::Owner),
            "N restores C as Owner without reviving Q"
        );
        assert_eq!(
            graph.evaluator().effective_role(&future_target),
            Some(Role::Member),
            "the regranted Owner can author a future operation"
        );
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "Q's membership restoration remains suppressed after regrant"
        );
        assert_eq!(
            graph
                .projection()
                .value(&ExclusiveCell::membership(controller.clone())),
            None,
            "Q cannot become the effective Membership(C) projection"
        );
    }
}
