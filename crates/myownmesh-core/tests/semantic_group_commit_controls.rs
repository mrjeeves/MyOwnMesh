#![cfg(feature = "transport-lab")]

//! Production-shaped controls for bounded semantic group admission.
//!
//! The aggregate journal/store seam is crate-private, so this integration
//! surface drives its public page/engine boundary. These controls prove the
//! observable contract: ordered reduction, duplicate replay, quarantine
//! promotion, and restart identity.

use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode, SQLITE_DEFAULT_PAGE_SIZE_BYTES,
};
use myownmesh_core::engine::transport_lab::SemanticCommitFaultForLab;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactId, SemanticFactPage, SemanticFactPageRequest,
    SemanticStateIdentity, SignedFact,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, Identity, Mesh, MeshConfig, MeshHandle,
    ResourceClaim, ResourceClass, ResourceProviderPort, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};
use tempfile::TempDir;

static HOME_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();
static TEST_RESOURCE_PROVIDER: OnceLock<ResourceProviderPort> = OnceLock::new();

struct ScopedMeshHome {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl ScopedMeshHome {
    fn new(path: &Path) -> Self {
        let lock = HOME_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
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

struct Fixture {
    _home: TempDir,
    _env: ScopedMeshHome,
    mesh: MeshHandle,
    network: myownmesh_core::JoinedNetwork,
    identity: std::sync::Arc<Identity>,
}

async fn fixture(label: &str) -> Fixture {
    let home = TempDir::new().expect("semantic group home");
    let env = ScopedMeshHome::new(home.path());
    let identity = std::sync::Arc::new(Identity::ephemeral());
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        identity.clone(),
        connector_policy(),
    )
    .await
    .expect("open connector-capable mesh");
    let network = mesh
        .create_network(closed_config(label), [0x7a; 32])
        .await
        .expect("create Closed network");
    Fixture {
        _home: home,
        _env: env,
        mesh,
        network,
        identity,
    }
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let semantic_policy = SemanticPolicyConfig::default();
    let semantic_storage_bytes = semantic_policy
        .checked_storage_envelope(
            SQLITE_DEFAULT_PAGE_SIZE_BYTES,
            semantic_policy.storage_workload(),
        )
        .expect("finite group semantic storage envelope")
        .total_bytes;
    let resources = TEST_RESOURCE_PROVIDER
        .get_or_init(|| {
            let requested =
                ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
                    (
                        class,
                        if class == ResourceClass::StorageBytes {
                            semantic_storage_bytes
                        } else {
                            1_000_000_000
                        },
                    )
                }))
                .expect("group fixture resource claim");
            let grant = FiniteResourceProvider::reservation_planning_charge(requested)
                .expect("group fixture reservation charge");
            ResourceProviderPort::new(FiniteResourceProvider::new(grant))
                .expect("group fixture resource provider")
        })
        .clone();
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn closed_config(label: &str) -> NetworkConfig {
    NetworkConfig {
        id: label.to_string(),
        network_id: format!("{label}-wire"),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: label.to_string(),
        kind: NetworkKind::Closed,
        semantic_policy: Default::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        application_transport: None,
        tree: None,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
        closed_relay: ClosedRelayPolicyConfig::default(),
    }
}

fn signer_device(identity: &Identity) -> DeviceId {
    DeviceId::from_canonical_str(identity.public_id()).expect("fixture signer device")
}

fn signed_role_grant(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: &Identity,
    parents: Vec<FactId>,
) -> SignedFact {
    signed_role_grant_with_role(
        context,
        signer,
        target,
        myownmesh_core::semantic::Role::Member,
        parents,
    )
}

fn signed_role_grant_with_role(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: &Identity,
    role: myownmesh_core::semantic::Role,
    parents: Vec<FactId>,
) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            myownmesh_core::semantic::FactDomain::Governance,
            context,
            FactBody::RoleGrant {
                target: DeviceId::from_canonical_str(target.public_id()).expect("target device"),
                role,
            },
            signer_device(signer),
            parents,
        ),
        signer.signing_key(),
    )
    .expect("fixture role grant signs")
}

#[tokio::test]
async fn one_page_uses_one_durable_commit_without_readmission() {
    let fixture = fixture("group-one-commit").await;
    let context = fixture
        .network
        .semantic_state_identity()
        .expect("group identity")
        .context_id();

    let targets = [
        Identity::ephemeral(),
        Identity::ephemeral(),
        Identity::ephemeral(),
    ];
    let facts: Vec<_> = targets
        .iter()
        .map(|target| signed_role_grant(context, &fixture.identity, target, Vec::new()))
        .collect();

    let before = fixture
        .network
        .semantic_state_identity()
        .expect("group baseline identity");
    fixture.network.reset_semantic_admission_profile_for_lab();
    let committed = fixture
        .network
        .import_semantic_fact_page(page(context, &facts))
        .await
        .expect("causally ordered page commits");
    let profile = fixture.network.semantic_admission_profile_for_lab();
    assert_eq!(
        committed.admitted_fact_count(),
        before.admitted_fact_count() + facts.len() as u64,
        "the complete page is retained"
    );
    assert_eq!(
        profile.commit_wal_terminal.count, 1,
        "one page crosses exactly one FULL/WAL commit boundary"
    );
    assert_eq!(
        profile.causal_journal_apply.count, 1,
        "one page is one aggregate graph journal"
    );
    assert_eq!(
        profile.async_envelope_inclusive.count, 1,
        "the already-durable page is reduced without per-fact re-admission"
    );

    fixture.network.reset_semantic_admission_profile_for_lab();
    let replay = fixture
        .network
        .import_semantic_fact_page(page(context, &facts))
        .await
        .expect("exact page replay is accepted");
    let replay_profile = fixture.network.semantic_admission_profile_for_lab();
    assert_same_identity(&committed, &replay);
    assert_eq!(
        replay_profile.commit_wal_terminal.count, 0,
        "exact replay performs no durable commit"
    );
    fixture.network.leave().await.expect("one-commit shutdown");
}

fn page(
    context: myownmesh_core::semantic::MeshContextId,
    facts: &[SignedFact],
) -> SemanticFactPage {
    let mut facts = facts.to_vec();
    facts.sort_by_key(|fact| fact.id);
    serde_json::from_value(serde_json::json!({
        "context_id": context,
        "facts": facts,
        "next_cursor": null,
        "complete": true,
    }))
    .expect("strict semantic page")
}

fn all_facts(network: &myownmesh_core::JoinedNetwork) -> Vec<SignedFact> {
    network
        .export_semantic_fact_page(SemanticFactPageRequest {
            context_id: network
                .semantic_state_identity()
                .expect("semantic identity")
                .context_id(),
            cursor: None,
            max_facts: 64,
            max_encoded_bytes: myownmesh_core::protocol::relay::CLOSED_RELAY_WEBRTC_CALLBACK_BYTES
                as u32,
        })
        .expect("export semantic page")
        .facts()
        .to_vec()
}

fn assert_same_identity(before: &SemanticStateIdentity, after: &SemanticStateIdentity) {
    assert_eq!(before, after, "semantic identity changed unexpectedly");
}

#[tokio::test]
async fn concurrent_unrelated_admissions_converge_and_exact_replay_is_a_noop() {
    let fixture = fixture("group-concurrent").await;
    let baseline = fixture
        .network
        .semantic_state_identity()
        .expect("baseline identity");
    let target_a = Identity::ephemeral();
    let target_b = Identity::ephemeral();
    let (result_a, result_b) = tokio::join!(
        fixture.network.propose_role_grant(
            target_a.public_id(),
            myownmesh_core::semantic::Role::Member,
            None
        ),
        fixture.network.propose_role_grant(
            target_b.public_id(),
            myownmesh_core::semantic::Role::Member,
            None
        ),
    );
    let id_a = result_a.expect("first unrelated grant");
    let id_b = result_b.expect("second unrelated grant");
    assert_ne!(id_a, id_b, "unrelated grants have distinct identities");
    let committed = fixture
        .network
        .semantic_state_identity()
        .expect("committed identity");
    assert_eq!(
        committed.admitted_fact_count(),
        baseline
            .admitted_fact_count()
            .checked_add(2)
            .expect("fact count fits"),
        "both concurrent valid facts are retained exactly once"
    );

    let mut facts = all_facts(&fixture.network);
    facts.reverse();
    let replayed = fixture
        .network
        .import_semantic_fact_page(page(committed.context_id(), &facts))
        .await
        .expect("replay reordered exact facts");
    assert_same_identity(&committed, &replayed);
    fixture.network.leave().await.expect("group shutdown");
}

#[tokio::test]
async fn mixed_valid_duplicate_and_invalid_page_is_refused_before_mutation() {
    let fixture = fixture("group-mixed").await;
    let target = Identity::ephemeral();
    let fact_id = fixture
        .network
        .propose_role_grant(
            target.public_id(),
            myownmesh_core::semantic::Role::Member,
            None,
        )
        .await
        .expect("valid grant");
    let before = fixture
        .network
        .semantic_state_identity()
        .expect("mixed baseline");
    let mut facts = all_facts(&fixture.network);
    let valid = facts
        .iter()
        .find(|fact| fact.id == fact_id)
        .cloned()
        .expect("valid fact export");
    let mut invalid = valid.clone();
    invalid.signature = "not-a-signature".into();
    facts.clear();
    facts.extend([valid.clone(), invalid]);
    assert!(
        fixture
            .network
            .import_semantic_fact_page(page(before.context_id(), &facts))
            .await
            .is_err(),
        "invalid input refuses the entire page before reduction"
    );
    let after = fixture
        .network
        .semantic_state_identity()
        .expect("mixed post-refusal identity");
    assert_same_identity(&before, &after);
    fixture.network.leave().await.expect("mixed shutdown");
}

#[tokio::test]
async fn bounded_envelope_refusal_preserves_identity_and_provider_baseline() {
    let fixture = fixture("group-refusal").await;
    let before = fixture
        .network
        .semantic_state_identity()
        .expect("refusal baseline identity");
    let resources = fixture.mesh.resource_report();
    assert!(
        fixture
            .network
            .import_semantic_fact_page(page(before.context_id(), &[]))
            .await
            .is_err(),
        "empty group is refused before the durable reducer"
    );
    assert_same_identity(
        &before,
        &fixture
            .network
            .semantic_state_identity()
            .expect("refusal post-identity"),
    );
    assert_eq!(
        fixture.mesh.resource_report(),
        resources,
        "envelope refusal releases all provider-backed page custody"
    );
    fixture.network.leave().await.expect("refusal shutdown");
}

#[tokio::test]
async fn precommit_failure_rolls_back_nonempty_group_and_consumes_one_shot() {
    let fixture = fixture("group-precommit-failure").await;
    let before = fixture
        .network
        .semantic_state_identity()
        .expect("precommit baseline identity");
    let before_facts = all_facts(&fixture.network);
    let resources = fixture.mesh.resource_report();

    fixture.network.reset_semantic_admission_profile_for_lab();
    fixture
        .network
        .arm_semantic_commit_fault_for_lab(SemanticCommitFaultForLab::BeforeCommit)
        .expect("arm exact owner precommit fault");
    assert!(
        fixture
            .network
            .arm_semantic_commit_fault_for_lab(SemanticCommitFaultForLab::BeforeCommit)
            .is_err(),
        "a second one-shot arm must be refused while the first remains pending"
    );

    // An envelope refusal happens before the durable owner and must not
    // consume the pending fault.
    assert!(
        fixture
            .network
            .import_semantic_fact_page(page(before.context_id(), &[]))
            .await
            .is_err(),
        "empty page is refused before durable admission"
    );
    assert_same_identity(
        &before,
        &fixture
            .network
            .semantic_state_identity()
            .expect("post-envelope identity"),
    );

    let target = Identity::ephemeral();
    assert!(
        fixture
            .network
            .propose_role_grant(
                target.public_id(),
                myownmesh_core::semantic::Role::Member,
                None,
            )
            .await
            .is_err(),
        "the real public ingress reaches and refuses after SQL apply"
    );
    let profile = fixture.network.semantic_admission_profile_for_lab();
    assert!(
        profile.sql_apply.count > 0,
        "nonempty fault control reached actual semantic SQL apply"
    );
    assert_eq!(
        profile.commit_wal_terminal.count, 0,
        "definite precommit failure never crosses SQLite COMMIT"
    );
    assert_eq!(
        profile.projection_roster_publish.count, 0,
        "definite durable failure publishes no projection"
    );
    assert_eq!(
        profile.post_commit_broadcast.count, 0,
        "definite durable failure broadcasts no semantic delta"
    );
    assert_same_identity(
        &before,
        &fixture
            .network
            .semantic_state_identity()
            .expect("precommit rollback identity"),
    );
    assert_eq!(
        all_facts(&fixture.network),
        before_facts,
        "precommit rollback leaves the exact exported graph unchanged"
    );
    assert_eq!(
        fixture.mesh.resource_report(),
        resources,
        "precommit rollback releases all page and semantic custody"
    );

    fixture
        .network
        .arm_semantic_commit_fault_for_lab(SemanticCommitFaultForLab::BeforeCommit)
        .expect("the consumed one-shot can be rearmed after the real commit boundary");
    fixture.network.leave().await.expect("precommit shutdown");
}

#[tokio::test]
async fn ambiguous_commit_reconciles_and_reopens_exact_group_state() {
    let fixture = fixture("group-ambiguous-commit").await;
    let before = fixture
        .network
        .semantic_state_identity()
        .expect("ambiguous baseline identity");
    let before_facts = all_facts(&fixture.network);
    let resources = fixture.mesh.resource_report();

    fixture.network.reset_semantic_admission_profile_for_lab();
    fixture
        .network
        .arm_semantic_commit_fault_for_lab(SemanticCommitFaultForLab::CommitOutcomeUnknown)
        .expect("arm exact owner ambiguous commit fault");
    let target = Identity::ephemeral();
    let target_device = DeviceId::from_canonical_str(target.public_id()).expect("target device");
    assert!(
        fixture
            .network
            .propose_role_grant(
                target.public_id(),
                myownmesh_core::semantic::Role::Member,
                None,
            )
            .await
            .is_err(),
        "lost worker reply is surfaced as an uncertain public outcome"
    );
    let profile = fixture.network.semantic_admission_profile_for_lab();
    assert!(
        profile.sql_apply.count > 0,
        "ambiguous control reached actual semantic SQL apply"
    );
    assert_eq!(
        profile.commit_wal_terminal.count, 1,
        "ambiguous control crossed the real SQLite COMMIT boundary"
    );
    assert_eq!(
        profile.projection_roster_publish.count, 0,
        "uncertain caller result does not publish before reconciliation"
    );
    assert_eq!(
        profile.post_commit_broadcast.count, 0,
        "uncertain caller result does not broadcast before reconciliation"
    );

    let committed = fixture
        .network
        .semantic_state_identity()
        .expect("reconciled live identity");
    assert_ne!(
        committed, before,
        "reconciliation observes the actual committed semantic mutation"
    );
    let committed_facts = all_facts(&fixture.network);
    assert_eq!(
        committed_facts.len(),
        before_facts.len() + 1,
        "exactly the nonempty transaction's fact was durably committed"
    );
    assert!(
        committed_facts.iter().any(|fact| matches!(
            &fact.content.body,
            FactBody::RoleGrant { target: current, .. } if current == &target_device
        )),
        "reconciliation retained the exact public-ingress target fact"
    );
    for fact in &before_facts {
        assert!(
            committed_facts.iter().any(|current| current == fact),
            "reconciliation retains every pre-existing exported fact"
        );
    }
    assert_eq!(
        fixture.mesh.resource_report(),
        resources,
        "ambiguous reconciliation leaves provider custody at the live-network baseline"
    );

    let config = closed_config("group-ambiguous-commit");
    fixture
        .network
        .leave()
        .await
        .expect("ambiguous pre-reopen shutdown");
    let reopened = fixture
        .mesh
        .join(config)
        .await
        .expect("reopen committed group");
    let restored = reopened
        .semantic_state_identity()
        .expect("reopened reconciled identity");
    assert_same_identity(&committed, &restored);
    assert_eq!(
        all_facts(&reopened),
        committed_facts,
        "reopen restores the exact reconciled graph/store transcript"
    );
    reopened.leave().await.expect("ambiguous reopen shutdown");
}

#[tokio::test]
async fn restart_restores_exact_committed_group_identity() {
    let fixture = fixture("group-restart").await;
    let target_a = Identity::ephemeral();
    let target_b = Identity::ephemeral();
    let (first, second) = tokio::join!(
        fixture.network.propose_role_grant(
            target_a.public_id(),
            myownmesh_core::semantic::Role::Member,
            None
        ),
        fixture.network.propose_role_grant(
            target_b.public_id(),
            myownmesh_core::semantic::Role::Member,
            None
        ),
    );
    first.expect("restart group first grant");
    second.expect("restart group second grant");
    let committed = fixture
        .network
        .semantic_state_identity()
        .expect("restart committed identity");
    let config = closed_config("group-restart");
    fixture.network.leave().await.expect("restart pre-shutdown");
    let reopened = fixture.mesh.join(config).await.expect("restart network");
    let restored = reopened
        .semantic_state_identity()
        .expect("restart restored identity");
    assert_same_identity(&committed, &restored);
    reopened.leave().await.expect("restart shutdown");
}
