#![cfg(feature = "transport-lab")]

//! Production semantic admission-capacity controls.
//!
//! Every control below drives the public `FactGraph` owner with its immutable
//! `SemanticAdmissionPolicy`.  The test helpers only observe the graph's
//! canonical retained facts; they do not reproduce admission, quarantine, or
//! waiter accounting in a second ledger.
//!
//! The lifecycle control at the end of this file enters the public Mesh and
//! NetworkState creation path, so its StorageBytes assertions cover the
//! provider-funded durable owner rather than a test-local accounting model.
//! The SQLite VFS and writer-error hooks themselves remain crate-private; the
//! unavailable restore/WriterBusy and failed-cleanup cases are called out in
//! the handoff rather than represented by a synthetic fixture.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};

use myownmesh_core::config::{
    NetworkConfig, NetworkKind, SemanticPolicyConfig, SQLITE_DEFAULT_PAGE_SIZE_BYTES,
};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
use myownmesh_core::semantic::causal::dependencies;
use myownmesh_core::semantic::{
    Admission, DeviceId, FactBody, FactContent, FactGraph, FactId, Role, SemanticAdmissionPolicy,
    SemanticCapacityDimension, SemanticError, SignedFact, VerifiedBootstrap,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};

static HOME_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ScopedMeshHome {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl ScopedMeshHome {
    fn new(path: &Path) -> Self {
        let lock = HOME_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("semantic capacity home lock");
        let previous = std::env::var_os("MYOWNMESH_HOME");
        std::env::set_var("MYOWNMESH_HOME", path);
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for ScopedMeshHome {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var("MYOWNMESH_HOME", previous);
        } else {
            std::env::remove_var("MYOWNMESH_HOME");
        }
    }
}

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn device(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid fixture key")
}

fn bootstrap() -> (VerifiedBootstrap, SigningKey) {
    let root = key(7);
    (
        VerifiedBootstrap::create_closed("semantic-capacity-controls", vec![root.clone()], [7; 32])
            .expect("capacity fixture bootstrap verifies"),
        root,
    )
}

fn role_grant(
    bootstrap: &VerifiedBootstrap,
    author: &SigningKey,
    target_seed: u8,
    parents: Vec<FactId>,
) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            myownmesh_core::semantic::FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::RoleGrant {
                target: device(&key(target_seed)),
                role: Role::Member,
            },
            device(author),
            parents,
        ),
        author,
    )
    .expect("role-grant fixture signs")
}

fn authored_role_grant(graph: &FactGraph, author: &SigningKey, target_seed: u8) -> SignedFact {
    let body = FactBody::RoleGrant {
        target: device(&key(target_seed)),
        role: Role::Member,
    };
    let witness = graph.authoring_witness(&body, &device(author));
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, Vec::<FactId>::new()),
        author,
    )
    .expect("authored role-grant fixture signs")
}

fn fact_cost(fact: &SignedFact) -> (u64, u64) {
    (
        u64::try_from(
            serde_json::to_vec(fact)
                .expect("fixture fact serializes")
                .len(),
        )
        .expect("fixture bytes fit u64"),
        u64::try_from(dependencies(fact).len()).expect("fixture edges fit u64"),
    )
}

fn policy(mut update: impl FnMut(&mut SemanticAdmissionPolicy)) -> SemanticAdmissionPolicy {
    let mut policy = SemanticAdmissionPolicy::default();
    update(&mut policy);
    policy
}

fn graph_digest(graph: &FactGraph) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"admitted");
    for id in graph.ids() {
        let fact = graph.get(id).expect("graph id has a retained fact");
        hasher.update(id.as_bytes());
        hasher.update(fact.content.canonical_bytes());
    }
    hasher.update(b"quarantined");
    for (id, fact) in graph.quarantined() {
        hasher.update(id.as_bytes());
        hasher.update(fact.content.canonical_bytes());
    }
    hasher.finalize().into()
}

fn admitted_bytes(graph: &FactGraph) -> u64 {
    graph
        .ids()
        .map(|id| {
            let fact = graph.get(id).expect("graph id has a retained fact");
            u64::try_from(
                serde_json::to_vec(fact)
                    .expect("fixture fact serializes")
                    .len(),
            )
            .expect("fixture bytes fit u64")
        })
        .sum()
}

fn quarantined_bytes(graph: &FactGraph) -> u64 {
    graph
        .quarantined()
        .map(|(_, fact)| {
            u64::try_from(
                serde_json::to_vec(fact)
                    .expect("fixture fact serializes")
                    .len(),
            )
            .expect("fixture bytes fit u64")
        })
        .sum()
}

fn author_count(graph: &FactGraph, author: &DeviceId) -> usize {
    graph
        .ids()
        .filter(|id| {
            graph
                .get(id)
                .is_some_and(|fact| &fact.content.author == author)
        })
        .count()
}

fn retained_author_count(graph: &FactGraph, author: &DeviceId) -> usize {
    author_count(graph, author)
        + graph
            .quarantined()
            .filter(|(_, fact)| &fact.content.author == author)
            .count()
}

fn retained_author_bytes(graph: &FactGraph, author: &DeviceId) -> u64 {
    graph
        .ids()
        .filter_map(|id| graph.get(id))
        .chain(graph.quarantined().map(|(_, fact)| fact))
        .filter(|fact| &fact.content.author == author)
        .map(|fact| {
            u64::try_from(
                serde_json::to_vec(fact)
                    .expect("fixture fact serializes")
                    .len(),
            )
            .expect("fixture bytes fit u64")
        })
        .sum()
}

fn capacity_dimension(error: SemanticError) -> SemanticCapacityDimension {
    match error {
        SemanticError::CapacityExceeded { dimension, .. } => dimension,
        other => panic!("expected capacity refusal, got {other:?}"),
    }
}

fn database_footprint(policy: &SemanticPolicyConfig) -> (u64, u64, u64, u64, u64, u64) {
    let envelope = policy
        .checked_storage_envelope(SQLITE_DEFAULT_PAGE_SIZE_BYTES, policy.storage_workload())
        .expect("default semantic database envelope is valid");
    (
        envelope.main_bytes,
        envelope.main_journal_bytes,
        envelope.wal_bytes,
        envelope.shm_bytes,
        envelope.emergency_reserve_bytes,
        envelope.total_bytes,
    )
}

fn lifecycle_config(
    network_id: &str,
    mut semantic_policy: SemanticPolicyConfig,
    max_database_bytes: u64,
) -> NetworkConfig {
    semantic_policy.max_database_bytes = max_database_bytes;
    let mut config = NetworkConfig::from_network_id(network_id, network_id);
    config.kind = NetworkKind::Closed;
    config.semantic_policy = semantic_policy;
    config.signaling.strategy = "none".into();
    config.signaling.mdns = false;
    config.stun_servers.clear();
    config.turn_servers.clear();
    config
}

#[test]
fn production_graph_admits_exact_count_and_bytes_then_refuses_n_plus_one() {
    let (bootstrap, root) = bootstrap();
    let mut source = FactGraph::from_bootstrap(&bootstrap);
    let mut facts = Vec::new();
    for seed in 20..24 {
        let fact = if source.is_empty() {
            role_grant(&bootstrap, &root, seed, Vec::new())
        } else {
            authored_role_grant(&source, &root, seed)
        };
        source.admit(fact.clone()).expect("source grant admits");
        facts.push(fact);
    }
    let exact_bytes = facts[..2].iter().map(|fact| fact_cost(fact).0).sum();

    let mut graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_admitted_facts = 2;
            limits.max_admitted_bytes = exact_bytes;
        }),
    );
    assert_eq!(graph.admit(facts[0].clone()), Ok(Admission::Inserted));
    assert_eq!(graph.admit(facts[1].clone()), Ok(Admission::Inserted));
    assert_eq!(graph.len(), 2);
    assert_eq!(admitted_bytes(&graph), exact_bytes);
    assert_eq!(author_count(&graph, &device(&root)), 2);

    let before = graph_digest(&graph);
    let error = graph
        .admit(facts[2].clone())
        .expect_err("global N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::AdmittedFacts
    );
    assert_eq!(graph.len(), 2, "global count refusal retains no candidate");
    assert_eq!(admitted_bytes(&graph), exact_bytes);
    assert_eq!(graph_digest(&graph), before);

    let mut byte_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_admitted_facts = 3;
            limits.max_admitted_bytes = exact_bytes;
        }),
    );
    byte_graph
        .admit(facts[0].clone())
        .expect("first exact byte item admits");
    byte_graph
        .admit(facts[1].clone())
        .expect("second exact byte item admits");
    let before = graph_digest(&byte_graph);
    let error = byte_graph
        .admit(facts[2].clone())
        .expect_err("byte N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::AdmittedBytes
    );
    assert_eq!(byte_graph.len(), 2);
    assert_eq!(admitted_bytes(&byte_graph), exact_bytes);
    assert_eq!(graph_digest(&byte_graph), before);
}

#[test]
fn production_graph_accounts_quarantine_and_per_author_bounds_exactly() {
    let (bootstrap, root) = bootstrap();
    let facts: Vec<_> = (30..34)
        .map(|seed| {
            role_grant(
                &bootstrap,
                &root,
                seed,
                vec![FactId::from_bytes([seed; 32])],
            )
        })
        .collect();
    let exact_bytes = facts[..2].iter().map(|fact| fact_cost(fact).0).sum();
    let mut graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_quarantined_facts = 2;
            limits.max_quarantined_bytes = exact_bytes;
            limits.max_quarantined_facts_per_author = 2;
            limits.max_quarantined_bytes_per_author = exact_bytes;
        }),
    );
    for fact in &facts[..2] {
        assert!(matches!(
            graph.admit(fact.clone()),
            Ok(Admission::Quarantined { .. })
        ));
    }
    assert_eq!(graph.quarantined().count(), 2);
    assert_eq!(quarantined_bytes(&graph), exact_bytes);
    let before = graph_digest(&graph);
    let error = graph
        .admit(facts[2].clone())
        .expect_err("quarantine N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::QuarantinedFacts
    );
    assert_eq!(graph.quarantined().count(), 2);
    assert_eq!(quarantined_bytes(&graph), exact_bytes);
    assert_eq!(graph_digest(&graph), before);

    let mut author_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_quarantined_facts = 3;
            limits.max_quarantined_bytes = exact_bytes + fact_cost(&facts[2]).0;
            limits.max_quarantined_facts_per_author = 2;
            limits.max_quarantined_bytes_per_author = exact_bytes;
        }),
    );
    for fact in &facts[..2] {
        author_graph
            .admit(fact.clone())
            .expect("per-author quarantine item admits");
    }
    let before = graph_digest(&author_graph);
    let error = author_graph
        .admit(facts[2].clone())
        .expect_err("per-author quarantine N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::QuarantinedFactsPerAuthor
    );
    assert_eq!(author_graph.quarantined().count(), 2);
    assert_eq!(graph_digest(&author_graph), before);
}

#[test]
fn production_graph_replay_and_semantic_refusals_do_not_change_commitment() {
    let (bootstrap, root) = bootstrap();
    let fact = role_grant(&bootstrap, &root, 40, Vec::new());
    let mut graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| limits.max_admitted_facts = 1),
    );
    assert_eq!(graph.admit(fact.clone()), Ok(Admission::Inserted));
    let before = graph_digest(&graph);
    assert_eq!(graph.admit(fact.clone()), Ok(Admission::AlreadyPresent));
    assert_eq!(
        graph_digest(&graph),
        before,
        "identical replay has no growth"
    );

    let mut altered = fact.clone();
    altered.signature = "altered-same-id".into();
    assert!(matches!(
        graph.admit(altered),
        Err(SemanticError::InvalidSignature)
    ));
    assert_eq!(
        graph_digest(&graph),
        before,
        "altered same-ID refusal is atomic"
    );

    let outsider = key(41);
    let unauthorized = role_grant(&bootstrap, &outsider, 42, Vec::new());
    assert!(matches!(
        graph.admit(unauthorized),
        Err(SemanticError::CapacityExceeded { .. }) | Err(SemanticError::UnauthorizedRoleGrant)
    ));
    assert_eq!(
        graph_digest(&graph),
        before,
        "semantic no-op refusal cannot mutate retained facts"
    );
}

#[test]
fn production_graph_wakes_only_indexed_waiters_and_refuses_ineligible_author() {
    let (bootstrap, root) = bootstrap();
    let parent = role_grant(&bootstrap, &root, 50, Vec::new());
    let child = {
        let mut producer = FactGraph::from_bootstrap(&bootstrap);
        producer
            .admit(parent.clone())
            .expect("producer parent admits for an exact child witness");
        authored_role_grant(&producer, &root, 54)
    };
    let other_dependency = FactId::from_bytes([0xa5; 32]);
    let other = role_grant(&bootstrap, &root, 51, vec![other_dependency]);
    let mut graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_ready_batch = 1;
            limits.max_quarantined_facts = 4;
        }),
    );
    assert!(matches!(
        graph.admit(child.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert!(matches!(
        graph.admit(other.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    graph.admit(parent).expect("parent admits");
    assert!(graph.get(&child.id).is_none());
    assert!(graph.quarantined().any(|(id, _)| *id == child.id));
    assert_eq!(graph.retry_quarantined().unwrap(), vec![child.id]);
    assert!(graph.get(&child.id).is_some());
    assert!(graph.quarantined().any(|(id, _)| *id == other.id));

    let outsider = key(52);
    assert_eq!(graph.evaluator().effective_role(&device(&outsider)), None);
    let ineligible = role_grant(
        &bootstrap,
        &outsider,
        53,
        vec![FactId::from_bytes([0xa6; 32])],
    );
    let before = graph_digest(&graph);
    let before_len = graph.len();
    let before_quarantined = graph.quarantined().count();
    let before_quarantined_bytes = quarantined_bytes(&graph);
    assert!(matches!(
        graph.admit(ineligible),
        Err(SemanticError::QuarantineSignerNotEligible)
    ));
    assert_eq!(graph.len(), before_len);
    assert_eq!(graph.quarantined().count(), before_quarantined);
    assert_eq!(quarantined_bytes(&graph), before_quarantined_bytes);
    assert_eq!(
        graph_digest(&graph),
        before,
        "ineligible signer refusal is atomic before quarantine"
    );
}

#[test]
fn production_graph_enforces_combined_retained_per_author_count_and_bytes() {
    let (bootstrap, root) = bootstrap();
    let author = device(&root);
    let admitted = role_grant(&bootstrap, &root, 70, Vec::new());
    let quarantined = role_grant(&bootstrap, &root, 71, vec![FactId::from_bytes([0xb3; 32])]);
    let count_successor = role_grant(&bootstrap, &root, 72, vec![FactId::from_bytes([0xb4; 32])]);
    let exact_count = 2;

    let mut count_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_retained_facts_per_author = exact_count;
            limits.max_retained_bytes_per_author = u64::MAX;
            limits.max_quarantined_facts = 4;
        }),
    );
    assert_eq!(count_graph.admit(admitted.clone()), Ok(Admission::Inserted));
    assert!(matches!(
        count_graph.admit(quarantined.clone()),
        Ok(Admission::Quarantined { .. })
    ));
    assert_eq!(
        retained_author_count(&count_graph, &author),
        exact_count as usize
    );
    let before = graph_digest(&count_graph);
    let error = count_graph
        .admit(count_successor)
        .expect_err("combined retained count N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::RetainedFactsPerAuthor
    );
    assert_eq!(
        retained_author_count(&count_graph, &author),
        exact_count as usize
    );
    assert_eq!(graph_digest(&count_graph), before);

    let exact_bytes = fact_cost(&admitted).0 + fact_cost(&quarantined).0;
    let byte_successor = role_grant(&bootstrap, &root, 73, vec![FactId::from_bytes([0xb5; 32])]);
    let mut byte_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| {
            limits.max_retained_facts_per_author = 4;
            limits.max_retained_bytes_per_author = exact_bytes;
            limits.max_quarantined_facts = 4;
        }),
    );
    assert_eq!(byte_graph.admit(admitted), Ok(Admission::Inserted));
    assert!(matches!(
        byte_graph.admit(quarantined),
        Ok(Admission::Quarantined { .. })
    ));
    assert_eq!(retained_author_bytes(&byte_graph, &author), exact_bytes);
    let before = graph_digest(&byte_graph);
    let error = byte_graph
        .admit(byte_successor)
        .expect_err("combined retained bytes N+1 is refused");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::RetainedBytesPerAuthor
    );
    assert_eq!(retained_author_bytes(&byte_graph, &author), exact_bytes);
    assert_eq!(graph_digest(&byte_graph), before);
}

#[test]
fn production_graph_refuses_structural_dependency_edge_overflow_before_retention() {
    let (bootstrap, root) = bootstrap();
    let first_parent = FactId::from_bytes([0xb1; 32]);
    let second_parent = FactId::from_bytes([0xb2; 32]);
    let candidate = role_grant(&bootstrap, &root, 60, vec![first_parent, second_parent]);

    let mut dependency_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| limits.max_dependencies_per_fact = 1),
    );
    let before = graph_digest(&dependency_graph);
    let error = dependency_graph
        .admit(candidate.clone())
        .expect_err("per-fact dependency edge cap refuses before quarantine");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::DependenciesPerFact
    );
    assert_eq!(dependency_graph.len(), 0);
    assert_eq!(dependency_graph.quarantined().count(), 0);
    assert_eq!(graph_digest(&dependency_graph), before);

    let mut aggregate_graph = FactGraph::from_bootstrap_with_policy(
        &bootstrap,
        policy(|limits| limits.max_dependency_edges = 1),
    );
    let before = graph_digest(&aggregate_graph);
    let error = aggregate_graph
        .admit(candidate)
        .expect_err("aggregate dependency edge cap refuses before retention");
    assert_eq!(
        capacity_dimension(error),
        SemanticCapacityDimension::DependencyEdges
    );
    assert_eq!(aggregate_graph.len(), 0);
    assert_eq!(aggregate_graph.quarantined().count(), 0);
    assert_eq!(graph_digest(&aggregate_graph), before);
}

#[tokio::test(flavor = "current_thread")]
async fn production_lifecycle_funds_exact_database_envelope_and_releases_it(
) -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("semantic capacity home");
    let _home = ScopedMeshHome::new(home.path());
    let semantic_policy = SemanticPolicyConfig::default();
    let (main_bytes, journal_bytes, wal_bytes, shm_bytes, emergency_reserve_bytes, budget) =
        database_footprint(&semantic_policy);
    assert!(budget <= semantic_policy.max_database_bytes);

    let grant = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        (
            class,
            if class == ResourceClass::StorageBytes {
                budget
            } else {
                1_000_000_000
            },
        )
    }))
    .expect("finite production lifecycle grant is representable");
    let provider = FiniteResourceProvider::new(grant);
    let provider_view = provider.clone();
    let resources = ResourceProviderPort::new(provider)
        .expect("production lifecycle provider is constructible");
    let policy = WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    );
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(Identity::ephemeral()),
        policy,
    )
    .await?;
    let provider_baseline = provider_view.in_use();
    let failed_cleanup_baseline = provider_view.retained_after_failed_cleanup();

    // Occupy B-1 through the public application-resource scope.  Network
    // creation must refuse before publishing a semantic owner because the
    // durable path needs the whole exact B-byte claim.
    let blocker_scope = mesh.local_application_resource_scope()?;
    let blocker = blocker_scope.acquire(ResourceClaim::single(
        ResourceClass::StorageBytes,
        budget.checked_sub(1).expect("database budget is nonzero"),
    ))?;
    let blocked_baseline = provider_view.in_use();
    let blocked = mesh
        .create_network(
            lifecycle_config("semantic-capacity-blocked", semantic_policy, budget),
            [0x31; 32],
        )
        .await;
    assert!(
        blocked.is_err(),
        "B-1 free capacity refuses the exact B owner"
    );
    assert_eq!(
        provider_view.in_use(),
        blocked_baseline,
        "provider refusal leaves the public lifecycle baseline unchanged"
    );
    drop(blocker);
    drop(blocker_scope);
    assert_eq!(
        provider_view.in_use(),
        provider_baseline,
        "releasing the failed reservation restores the provider baseline"
    );

    let network = mesh
        .create_network(
            lifecycle_config("semantic-capacity-exact", semantic_policy, budget),
            [0x32; 32],
        )
        .await?;
    let live_provider = provider_view.in_use();
    assert_eq!(
        live_provider
            .amount(ResourceClass::StorageBytes)
            .checked_sub(provider_baseline.amount(ResourceClass::StorageBytes)),
        Some(budget),
        "the live NetworkState owns exactly B additional StorageBytes"
    );
    assert!(
        live_provider.amount(ResourceClass::OpaqueDependencyResidual)
            > provider_baseline.amount(ResourceClass::OpaqueDependencyResidual),
        "the live owner also carries provider bookkeeping"
    );
    let live_baseline = live_provider;

    // Keep the footprint evidence machine-readable so a durable run can
    // compare the policy envelope with the provider's observed live claim.
    eprintln!(
        "{{\"event\":\"semantic_capacity_footprint\",\"M\":{},\"J\":{},\"W\":{},\"S\":{},\"R\":{},\"B\":{},\"provider_baseline_storage\":{},\"provider_live_storage\":{},\"provider_baseline_opaque_dependency_residual\":{},\"provider_live_opaque_dependency_residual\":{}}}",
        main_bytes,
        journal_bytes,
        wal_bytes,
        shm_bytes,
        emergency_reserve_bytes,
        budget,
        provider_baseline.amount(ResourceClass::StorageBytes),
        live_provider.amount(ResourceClass::StorageBytes),
        provider_baseline.amount(ResourceClass::OpaqueDependencyResidual),
        live_provider.amount(ResourceClass::OpaqueDependencyResidual),
    );

    // A second production lifecycle attempt with max+1 must fail at provider
    // admission while the first owner is live, without changing its state.
    let over = mesh
        .create_network(
            lifecycle_config(
                "semantic-capacity-over",
                semantic_policy,
                budget
                    .checked_add(1)
                    .expect("database budget increment fits"),
            ),
            [0x33; 32],
        )
        .await;
    assert!(over.is_err(), "max+1 StorageBytes cannot be admitted");
    assert_eq!(
        provider_view.in_use(),
        live_baseline,
        "max+1 refusal does not mutate the live owner or provider"
    );

    network.leave().await?;
    assert_eq!(
        provider_view.in_use(),
        provider_baseline,
        "normal close releases the exact database envelope and bookkeeping"
    );
    assert_eq!(
        provider_view.retained_after_failed_cleanup(),
        failed_cleanup_baseline,
        "normal close leaves no sticky failed-cleanup claim"
    );
    eprintln!(
        "{{\"event\":\"semantic_capacity_terminal\",\"provider_storage\":{},\"provider_opaque_dependency_residual\":{},\"provider_retained_after_failed_cleanup\":{}}}",
        provider_view.in_use().amount(ResourceClass::StorageBytes),
        provider_view
            .in_use()
            .amount(ResourceClass::OpaqueDependencyResidual),
        provider_view
            .retained_after_failed_cleanup()
            .amount(ResourceClass::StorageBytes),
    );
    Ok(())
}
