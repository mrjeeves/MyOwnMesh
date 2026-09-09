#![cfg(feature = "transport-lab")]

//! Production-shaped R1 controls for the instance-owned semantic snapshot.
//!
//! The lower-level store controls cover torn writes, writer death, custody
//! validation, and compaction.  These controls prove the engine uses that
//! same store owner for a real Closed network lifecycle and does not rebuild a
//! fresh graph on restart.

use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use myownmesh_core::config::{NetworkConfig, NetworkKind, SignalingConfig, TopologyMode};
use myownmesh_core::engine::governance;
use myownmesh_core::engine::transport_lab::{
    create_network_in_instance_root, ingest_semantic_fact, spawn_network_in_instance_root,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::content::AuthorityUse;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactDomain, Role, SemanticFactPageRequest,
    SemanticRecentFactsRequest, SignedFact,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, ResourceClaim, ResourceClass,
    ResourceProviderPort, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use myownmesh_core::{Mesh, MeshConfig};
use tempfile::TempDir;

mod support;

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
            .expect("mesh-home environment lock");
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DurableFootprint {
    database_bytes: u64,
    wal_bytes: u64,
    shm_bytes: u64,
    journal_bytes: u64,
}

fn durable_footprint(root: &Path) -> DurableFootprint {
    fn visit(path: &Path, footprint: &mut DurableFootprint) {
        let Ok(entries) = fs::read_dir(path) else {
            return;
        };
        for entry in entries {
            let entry = entry.expect("durable semantic entry is readable");
            let entry_path = entry.path();
            let file_type = entry
                .file_type()
                .expect("durable semantic entry type is readable");
            if file_type.is_dir() {
                visit(&entry_path, footprint);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let size = entry
                .metadata()
                .expect("durable semantic entry metadata is readable")
                .len();
            let slot = if name.ends_with("-store.sqlite3") {
                &mut footprint.database_bytes
            } else if name.ends_with("-store.sqlite3-wal") {
                &mut footprint.wal_bytes
            } else if name.ends_with("-store.sqlite3-shm") {
                &mut footprint.shm_bytes
            } else if name.ends_with("-store.sqlite3-journal") {
                &mut footprint.journal_bytes
            } else {
                continue;
            };
            *slot = slot
                .checked_add(size)
                .expect("durable semantic footprint fits u64");
        }
    }

    let mut footprint = DurableFootprint::default();
    if root.exists() {
        visit(root, &mut footprint);
    }
    footprint
}

fn elapsed_millis(start: Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).expect("restart timing fits u64")
}

fn semantic_fact_page(
    context_id: myownmesh_core::semantic::MeshContextId,
    facts: &[SignedFact],
) -> myownmesh_core::semantic::SemanticFactPage {
    serde_json::from_value(serde_json::json!({
        "context_id": context_id,
        "facts": facts,
        "next_cursor": null,
        "complete": true,
    }))
    .expect("strict semantic page decodes")
}

async fn has_projected_member(network: &myownmesh_core::JoinedNetwork, device_id: &str) -> bool {
    network
        .roster_list()
        .await
        .map(|peers| {
            peers
                .iter()
                .any(|peer| peer.device_id == device_id && peer.role == Role::Member)
        })
        .unwrap_or(false)
}

fn has_projected_member_in_state(
    state: &Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    device_id: &str,
) -> bool {
    let public_key = myownmesh_core::signing::pubkey_part(device_id);
    state
        .roster
        .read()
        .authorized_devices
        .iter()
        .any(|peer| peer.device_id == public_key && peer.role == Role::Member)
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let requested = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        (
            class,
            if class == ResourceClass::StorageBytes {
                myownmesh_core::config::SemanticPolicyConfig::default().max_database_bytes
            } else {
                1_000_000_000
            },
        )
    }))
    .expect("restart fixture resource grant");
    let grant = FiniteResourceProvider::reservation_planning_charge(requested)
        .expect("restart fixture reservation bookkeeping");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("restart fixture resource provider");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn closed_config(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: NetworkKind::Closed,
        semantic_policy: Default::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        hub: None,
        local_observations: None,
        tree: None,
        introduction: None,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn signed_role_grant(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: DeviceId,
    parents: Vec<myownmesh_core::semantic::FactId>,
) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            context,
            FactBody::RoleGrant {
                target,
                role: myownmesh_core::semantic::Role::Member,
            },
            DeviceId::from_canonical_str(signer.public_id()).expect("signer id"),
            parents,
        ),
        signer.signing_key(),
    )
    .expect("signed role grant")
}

fn signed_role_grant_with_authority(
    context: myownmesh_core::semantic::MeshContextId,
    signer: &Identity,
    target: DeviceId,
    parents: Vec<myownmesh_core::semantic::FactId>,
    authority_uses: Vec<AuthorityUse>,
) -> SignedFact {
    let mut content = FactContent::new(
        FactDomain::Governance,
        context,
        FactBody::RoleGrant {
            target,
            role: myownmesh_core::semantic::Role::Member,
        },
        DeviceId::from_canonical_str(signer.public_id()).expect("signer id"),
        parents,
    );
    content.authority_uses = authority_uses;
    SignedFact::sign(content, signer.signing_key()).expect("signed role grant")
}

#[tokio::test]
async fn closed_network_restart_restores_the_committed_semantic_graph() {
    let home = TempDir::new().expect("mesh home");
    let _home = ScopedMeshHome::new(home.path());
    let identity = Arc::new(Identity::ephemeral());
    let config = closed_config("r1-restart", "r1-wire-network");
    let target = Identity::ephemeral();

    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        identity.clone(),
        connector_policy(),
    )
    .await
    .expect("open connector-capable mesh");
    let provider_baseline = mesh.resource_report();
    let network = mesh
        .create_network(config.clone(), [0x91; 32])
        .await
        .expect("create Closed network");
    let initial_identity = network
        .semantic_state_identity()
        .expect("read initial semantic identity");
    let context = initial_identity.context_id();
    let pre_admission_footprint = durable_footprint(home.path());
    let admission_started = Instant::now();
    let fact_id = network
        .propose_role_grant(target.public_id(), Role::Member, None)
        .await
        .expect("commit canonical member grant");
    let admission_ms = elapsed_millis(admission_started);
    let admitted_identity = network
        .semantic_state_identity()
        .expect("read admitted semantic identity");
    let admitted_footprint = durable_footprint(home.path());
    assert_ne!(
        admitted_identity, initial_identity,
        "the Closed admission changes the exact semantic identity"
    );
    assert_eq!(
        admitted_identity.admitted_fact_count(),
        initial_identity
            .admitted_fact_count()
            .checked_add(1)
            .expect("admitted fact count fits u64"),
        "the admission adds exactly one canonical fact"
    );
    assert_eq!(
        admitted_identity.unresolved_fact_count(),
        initial_identity.unresolved_fact_count(),
        "the admission does not create unresolved custody"
    );
    assert_ne!(
        admitted_footprint, pre_admission_footprint,
        "the first Closed admission publishes a durable footprint change"
    );
    assert!(
        has_projected_member(&network, target.public_id()).await,
        "the live state observes the committed canonical grant"
    );
    let page = network
        .export_semantic_fact_page(SemanticFactPageRequest {
            context_id: context,
            cursor: None,
            max_facts: 64,
            max_encoded_bytes: 65_535,
        })
        .expect("export admitted fact");
    let admitted_fact = page
        .facts()
        .iter()
        .find(|fact| fact.id == fact_id)
        .cloned()
        .expect("the admitted fact is exported");
    {
        let recent = network
            .recent_semantic_facts(SemanticRecentFactsRequest {
                max_facts: 2,
                max_encoded_bytes: 65_535,
            })
            .expect("render bounded recent facts");
        assert_eq!(
            recent.total_admitted_fact_count(),
            admitted_identity.admitted_fact_count()
        );
        assert!(recent.facts().iter().any(|fact| fact.id == fact_id));
        let human_readable = serde_json::to_value(&recent).expect("recent facts render as JSON");
        assert!(human_readable.get("facts").is_some());
    }
    let checkpoint_started = Instant::now();
    network
        .compact_semantic_state()
        .expect("compact semantic snapshot");
    let checkpoint_ms = elapsed_millis(checkpoint_started);
    let compacted_footprint = durable_footprint(home.path());
    assert_eq!(
        network
            .semantic_state_identity()
            .expect("read compacted semantic identity"),
        admitted_identity,
        "compaction preserves the exact semantic identity"
    );
    let duplicate_started = Instant::now();
    network
        .import_semantic_fact_page(semantic_fact_page(context, &[admitted_fact]))
        .await
        .expect("replay the exact admitted fact");
    let duplicate_ms = elapsed_millis(duplicate_started);
    assert_eq!(
        network
            .semantic_state_identity()
            .expect("read duplicate semantic identity"),
        admitted_identity,
        "duplicate admission is an exact semantic no-op"
    );
    assert_eq!(
        durable_footprint(home.path()),
        compacted_footprint,
        "duplicate admission causes no durable DB/WAL/SHM/journal churn"
    );
    let shutdown_started = Instant::now();
    network.leave().await.expect("first Closed shutdown");
    let shutdown_ms = elapsed_millis(shutdown_started);
    assert_eq!(
        mesh.resource_report(),
        provider_baseline,
        "first shutdown releases all provider-backed network custody"
    );

    let network_id = config.network_id.clone();
    let restart_started = Instant::now();
    let reopened = mesh.join(config).await.expect("reopen Closed network");
    let restart_ms = elapsed_millis(restart_started);
    assert_eq!(
        reopened
            .semantic_state_identity()
            .expect("read restart identity"),
        admitted_identity,
        "restart restores the exact semantic identity"
    );
    assert!(
        has_projected_member(&reopened, target.public_id()).await,
        "restart restores the exact admitted graph through NetworkState"
    );
    assert_eq!(
        durable_footprint(home.path()),
        compacted_footprint,
        "restart preserves the complete DB/WAL/SHM/journal footprint"
    );
    let restart_shutdown_started = Instant::now();
    reopened.leave().await.expect("reopened Closed shutdown");
    let restart_shutdown_ms = elapsed_millis(restart_shutdown_started);
    assert_eq!(
        mesh.resource_report(),
        provider_baseline,
        "restart shutdown releases the reacquired provider custody"
    );
    println!(
        "{}",
        serde_json::json!({
            "schema": "myownmesh.durable_semantic_restart.v1",
            "network_kind": "closed",
            "network_id": network_id,
            "stages_ms": {
                "admission": admission_ms,
                "checkpoint": checkpoint_ms,
                "duplicate": duplicate_ms,
                "shutdown": shutdown_ms,
                "restart": restart_ms,
                "restart_shutdown": restart_shutdown_ms,
            },
            "controls": {
                "duplicate_no_churn": true,
                "restart_identity_equal": true,
                "provider_baseline_restored": true,
                "footprint": {
                    "database_bytes": compacted_footprint.database_bytes,
                    "wal_bytes": compacted_footprint.wal_bytes,
                    "shm_bytes": compacted_footprint.shm_bytes,
                    "journal_bytes": compacted_footprint.journal_bytes,
                },
            },
        })
    );
}

#[tokio::test]
async fn quarantine_unrelated_commit_restart_then_parent_settles_exact_custody() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let config = closed_config("r1-quarantine", "r1-quarantine-wire");
    let target = Identity::ephemeral();
    let unrelated = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x92; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let unrelated_fact = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(unrelated.public_id()).expect("unrelated target id"),
        Vec::new(),
    );
    let root_device = DeviceId::from_canonical_str(identity.public_id()).expect("root id");
    let target_device = DeviceId::from_canonical_str(target.public_id()).expect("target id");
    let mut parent_authority_uses = vec![
        AuthorityUse {
            subject: root_device,
            predecessors: vec![unrelated_fact.id],
        },
        AuthorityUse {
            subject: target_device.clone(),
            predecessors: Vec::new(),
        },
    ];
    parent_authority_uses.sort_by(|left, right| left.subject.cmp(&right.subject));
    let parent = signed_role_grant_with_authority(
        context,
        identity.as_ref(),
        target_device,
        vec![unrelated_fact.id],
        parent_authority_uses,
    );
    let unresolved = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(target.public_id()).expect("target id"),
        vec![parent.id],
    );

    ingest_semantic_fact(&state, unresolved).await;
    assert_eq!(state.semantic_fact_count(), 0);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&state, unrelated_fact).await;
    assert_eq!(state.semantic_fact_count(), 1);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    drop(state);
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen unresolved snapshot");
    assert_eq!(reopened.semantic_fact_count(), 1);
    assert_eq!(reopened.semantic_unresolved_count(), 1);
    assert_eq!(reopened.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&reopened, parent).await;
    assert_eq!(reopened.semantic_fact_count(), 3);
    assert_eq!(reopened.semantic_unresolved_count(), 0);
    assert_eq!(
        reopened.semantic_provisional_custody_count(),
        0,
        "resolving the exact parent settles its provisional custody"
    );
    assert!(
        has_projected_member_in_state(&reopened, target.public_id()),
        "the resolved child is projected after durable settlement"
    );
    reopened.request_shutdown();
    reopened_driver.await.expect("reopened driver shutdown");
}

#[tokio::test]
async fn rejected_quarantine_is_settled_without_starving_valid_restart_progress() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let outsider = Identity::ephemeral();
    let config = closed_config("r1-rejected-quarantine", "r1-rejected-wire");
    let parent_target = Identity::ephemeral();
    let unrelated = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x93; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    let unrelated_fact = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(unrelated.public_id()).expect("unrelated target id"),
        Vec::new(),
    );
    let root_device = DeviceId::from_canonical_str(identity.public_id()).expect("root id");
    let target_device = DeviceId::from_canonical_str(parent_target.public_id()).expect("target id");
    let mut parent_authority_uses = vec![
        AuthorityUse {
            subject: root_device,
            predecessors: vec![unrelated_fact.id],
        },
        AuthorityUse {
            subject: target_device.clone(),
            predecessors: Vec::new(),
        },
    ];
    parent_authority_uses.sort_by(|left, right| left.subject.cmp(&right.subject));
    let parent = signed_role_grant_with_authority(
        context,
        identity.as_ref(),
        target_device,
        vec![unrelated_fact.id],
        parent_authority_uses,
    );
    let rejected = signed_role_grant(
        context,
        &outsider,
        DeviceId::from_canonical_str(parent_target.public_id()).expect("target id"),
        vec![parent.id],
    );

    ingest_semantic_fact(&state, rejected).await;
    assert_eq!(state.semantic_fact_count(), 0);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&state, unrelated_fact).await;
    assert_eq!(state.semantic_fact_count(), 1);
    assert_eq!(state.semantic_unresolved_count(), 1);
    assert_eq!(state.semantic_provisional_custody_count(), 1);

    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    drop(state);
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("reopen rejected quarantine snapshot");
    assert_eq!(reopened.semantic_fact_count(), 1);
    assert_eq!(reopened.semantic_unresolved_count(), 1);
    assert_eq!(reopened.semantic_provisional_custody_count(), 1);

    ingest_semantic_fact(&reopened, parent).await;
    assert_eq!(reopened.semantic_fact_count(), 2);
    assert_eq!(reopened.semantic_unresolved_count(), 0);
    assert_eq!(reopened.semantic_provisional_custody_count(), 0);

    reopened.request_shutdown();
    reopened_driver.await.expect("second driver shutdown");
    drop(reopened);
    let (restored, restored_driver) = spawn_network_in_instance_root(
        config,
        identity,
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("restart after rejected quarantine settlement");
    assert_eq!(restored.semantic_fact_count(), 2);
    assert_eq!(restored.semantic_unresolved_count(), 0);
    assert_eq!(restored.semantic_provisional_custody_count(), 0);
    restored.request_shutdown();
    restored_driver.await.expect("final driver shutdown");
}

#[tokio::test]
async fn shutdown_fences_stale_state_before_same_slot_reopen_and_append() {
    let root = TempDir::new().expect("instance root");
    let identity = Arc::new(Identity::ephemeral());
    let config = closed_config("r1-stale-reopen", "r1-stale-reopen-wire");
    let preserved_target = Identity::ephemeral();
    let stale_target = Identity::ephemeral();
    let replacement_target = Identity::ephemeral();

    let (state, driver) = create_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
        [0x94; 32],
    )
    .await
    .expect("create Closed network");
    let context = state.mesh_context_id();
    governance::propose_role_grant(&state, preserved_target.public_id(), Role::Member, None)
        .await
        .expect("commit the fact preserved across reopen");
    let committed_count = state.semantic_fact_count();
    // Keep this Arc as the stale caller while its driver and original owner
    // are shut down. Shutdown releases the durable writer lease, but the
    // state-level fence must reject every later mutation through this stale
    // handle rather than allowing it to write the reopened slot.
    let stale = Arc::clone(&state);
    let stale_fact = signed_role_grant(
        context,
        identity.as_ref(),
        DeviceId::from_canonical_str(stale_target.public_id()).expect("stale target id"),
        Vec::new(),
    );
    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    assert!(
        stale.compact_semantic_state().is_err(),
        "a stale state cannot compact after shutdown"
    );
    ingest_semantic_fact(&stale, stale_fact).await;
    assert_eq!(
        stale.semantic_fact_count(),
        committed_count,
        "a stale semantic admission cannot append after shutdown"
    );
    assert_eq!(stale.semantic_unresolved_count(), 0);
    assert_eq!(stale.semantic_provisional_custody_count(), 0);

    // The old Arc remains held deliberately: successful reopen therefore
    // proves shutdown released the writer lease without reviving stale
    // mutation authority.
    let (reopened, reopened_driver) = spawn_network_in_instance_root(
        config.clone(),
        identity.clone(),
        support::test_transport(),
        root.path().to_path_buf(),
    )
    .await
    .expect("same-slot reopen after shutdown");
    assert_eq!(reopened.semantic_fact_count(), committed_count);
    assert!(
        has_projected_member_in_state(&reopened, preserved_target.public_id()),
        "reopened state preserves the pre-shutdown canonical projection"
    );

    governance::propose_role_grant(
        &reopened,
        replacement_target.public_id(),
        Role::Member,
        None,
    )
    .await
    .expect("replacement state appends a fresh canonical fact");
    assert_eq!(reopened.semantic_fact_count(), committed_count + 1);
    assert!(
        has_projected_member_in_state(&reopened, replacement_target.public_id()),
        "replacement append projects through the same durable owner"
    );
    assert_eq!(reopened.semantic_unresolved_count(), 0);
    assert_eq!(reopened.semantic_provisional_custody_count(), 0);

    reopened.request_shutdown();
    reopened_driver.await.expect("replacement driver shutdown");
    drop(stale);
}
