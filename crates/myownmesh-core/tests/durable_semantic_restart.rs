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
use std::time::{Duration, Instant};

use myownmesh_core::config::{NetworkConfig, NetworkKind, SignalingConfig, TopologyMode};
use myownmesh_core::engine::governance;
use myownmesh_core::engine::transport_lab::{
    create_network_in_instance_root, ingest_semantic_fact, spawn_network_in_instance_root,
};
use myownmesh_core::identity::Identity;
use myownmesh_core::semantic::content::AuthorityUse;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactDomain, FactGraph, Role, SemanticError,
    SemanticFactPageRequest, SemanticRecentFactsRequest, SignedFact,
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

fn authored_fact_with_support<I>(
    graph: &FactGraph,
    signer: &Identity,
    body: FactBody,
    support: I,
) -> SignedFact
where
    I: IntoIterator<Item = myownmesh_core::semantic::FactId>,
{
    let author = DeviceId::from_canonical_str(signer.public_id()).expect("signer id");
    let witness = graph.authoring_witness(&body, &author);
    let content = FactContent::from_authoring_witness(graph, body, &witness, support);
    SignedFact::sign(content, signer.signing_key()).expect("signed witnessed fact")
}

const CLOSED_RESTART_CHILD_SELECTOR: &str =
    "closed_network_restart_restores_the_committed_semantic_graph";
const SHUTDOWN_FENCES_CHILD_SELECTOR: &str =
    "shutdown_fences_stale_state_before_same_slot_reopen_and_append";
const CLOSED_RESTART_CHILD_SELECTOR_ENV: &str = "MYOWNMESH_DURABLE_RESTART_CHILD_SELECTOR";
const CLOSED_RESTART_CHILD_HOME_ENV: &str = "MYOWNMESH_DURABLE_RESTART_CHILD_HOME";
const CLOSED_RESTART_CHILD_COMPLETED: &str = "durable-restart-child-completed";

fn durable_child_home(selector: &str) -> Option<std::path::PathBuf> {
    let selected = std::env::var_os(CLOSED_RESTART_CHILD_SELECTOR_ENV)?;
    assert_eq!(
        selected,
        std::ffi::OsStr::new(selector),
        "wrong durable restart child selector"
    );
    let home = std::path::PathBuf::from(
        std::env::var_os(CLOSED_RESTART_CHILD_HOME_ENV).expect("durable restart child home"),
    );
    assert!(
        home.is_absolute() && home.is_dir(),
        "durable restart child home must exist and be absolute"
    );
    assert_eq!(
        std::env::var_os("MYOWNMESH_HOME"),
        Some(home.clone().into_os_string())
    );
    Some(home)
}

async fn run_durable_child(selector: &str, home_path: &Path) -> myownmesh_core::Result<()> {
    let _home = ScopedMeshHome::new(home_path);
    match selector {
        CLOSED_RESTART_CHILD_SELECTOR => run_closed_network_restart(home_path).await?,
        SHUTDOWN_FENCES_CHILD_SELECTOR => run_shutdown_fences_body().await,
        _ => panic!("unknown durable restart child selector: {selector}"),
    }
    fs::write(
        home_path.join(CLOSED_RESTART_CHILD_COMPLETED),
        selector.as_bytes(),
    )
    .expect("durable restart child completion marker");
    Ok(())
}

async fn run_exact_durable_child(selector: &str) -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("isolated durable restart home");
    let home_path = home.path().to_path_buf();
    let mut command = tokio::process::Command::new(
        std::env::current_exe().expect("durable restart test executable"),
    );
    command
        .args(["--exact", selector, "--nocapture", "--test-threads=1"])
        .env("MYOWNMESH_HOME", &home_path)
        .env(CLOSED_RESTART_CHILD_SELECTOR_ENV, selector)
        .env(CLOSED_RESTART_CHILD_HOME_ENV, &home_path)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::inherit())
        .stderr(std::process::Stdio::inherit())
        .kill_on_drop(true);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.as_std_mut().creation_flags(0x08000000);
    }
    let mut child = command
        .spawn()
        .expect("spawn exact isolated durable restart");
    let deadline = Instant::now() + Duration::from_secs(120);
    let status = match tokio::time::timeout_at(deadline.into(), child.wait()).await {
        Ok(status) => status.expect("reap durable restart child"),
        Err(_) => {
            let killed = child.start_kill();
            let reaped = tokio::time::timeout(Duration::from_secs(10), child.wait()).await;
            panic!("durable restart child deadline expired; kill={killed:?}, reap={reaped:?}");
        }
    };
    assert!(
        Instant::now() <= deadline,
        "durable restart child completed after deadline"
    );
    assert!(
        status.success(),
        "isolated durable restart failed: {status}"
    );
    assert_eq!(
        fs::read(home_path.join(CLOSED_RESTART_CHILD_COMPLETED))
            .expect("durable restart child completed, not zero selected tests"),
        selector.as_bytes(),
    );
    Ok(())
}

#[tokio::test]
async fn closed_network_restart_restores_the_committed_semantic_graph() -> myownmesh_core::Result<()>
{
    if let Some(home_path) = durable_child_home(CLOSED_RESTART_CHILD_SELECTOR) {
        run_durable_child(CLOSED_RESTART_CHILD_SELECTOR, &home_path).await?;
        return Ok(());
    }
    run_exact_durable_child(CLOSED_RESTART_CHILD_SELECTOR).await?;
    Ok(())
}

async fn run_closed_network_restart(home_path: &Path) -> myownmesh_core::Result<()> {
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
    let pre_admission_footprint = durable_footprint(home_path);
    let admission_started = Instant::now();
    let fact_id = network
        .propose_role_grant(target.public_id(), Role::Member, None)
        .await
        .expect("commit canonical member grant");
    let admission_ms = elapsed_millis(admission_started);
    let admitted_identity = network
        .semantic_state_identity()
        .expect("read admitted semantic identity");
    let admitted_footprint = durable_footprint(home_path);
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
    let compacted_footprint = durable_footprint(home_path);
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
        durable_footprint(home_path),
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
        durable_footprint(home_path),
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
    Ok(())
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
    let mut signing_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    let unrelated_fact = authored_fact_with_support(
        &signing_graph,
        identity.as_ref(),
        FactBody::RoleGrant {
            target: DeviceId::from_canonical_str(unrelated.public_id())
                .expect("unrelated target id"),
            role: Role::Member,
        },
        Vec::new(),
    );
    signing_graph
        .admit(unrelated_fact.clone())
        .expect("unrelated fact is a valid graph predecessor");
    let target_device = DeviceId::from_canonical_str(target.public_id()).expect("target id");
    let parent = authored_fact_with_support(
        &signing_graph,
        identity.as_ref(),
        FactBody::MembershipAdmit {
            target: target_device.clone(),
        },
        Vec::new(),
    );
    signing_graph
        .admit(parent.clone())
        .expect("membership parent is a valid graph predecessor");
    let unresolved = authored_fact_with_support(
        &signing_graph,
        identity.as_ref(),
        FactBody::RoleGrant {
            target: target_device,
            role: Role::Member,
        },
        [parent.id],
    );
    signing_graph
        .admit(unresolved.clone())
        .expect("positive F2 is admitted by the witnessed local graph");
    assert_eq!(
        signing_graph.get(&unresolved.id),
        Some(&unresolved),
        "positive F2 is present in the completed local signing graph"
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
    let mut signing_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    let unrelated_fact = authored_fact_with_support(
        &signing_graph,
        identity.as_ref(),
        FactBody::RoleGrant {
            target: DeviceId::from_canonical_str(unrelated.public_id())
                .expect("unrelated target id"),
            role: Role::Member,
        },
        Vec::new(),
    );
    signing_graph
        .admit(unrelated_fact.clone())
        .expect("unrelated fact is a valid graph predecessor");
    let target_device = DeviceId::from_canonical_str(parent_target.public_id()).expect("target id");
    let parent = authored_fact_with_support(
        &signing_graph,
        identity.as_ref(),
        FactBody::MembershipAdmit {
            target: target_device.clone(),
        },
        Vec::new(),
    );
    signing_graph
        .admit(parent.clone())
        .expect("membership parent is a valid graph predecessor");
    let mut rejected_authority_uses = vec![
        AuthorityUse {
            subject: DeviceId::from_canonical_str(identity.public_id()).expect("root id"),
            predecessors: Vec::new(),
        },
        AuthorityUse {
            subject: DeviceId::from_canonical_str(parent_target.public_id()).expect("target id"),
            predecessors: Vec::new(),
        },
    ];
    rejected_authority_uses.sort_by(|left, right| left.subject.cmp(&right.subject));
    let rejected = signed_role_grant_with_authority(
        state.mesh_context_id(),
        identity.as_ref(),
        target_device,
        vec![parent.id],
        rejected_authority_uses,
    );
    let mut validation_graph = signing_graph.clone();
    assert!(matches!(
        validation_graph.admit(rejected.clone()),
        Err(SemanticError::UnauthorizedRoleGrant)
    ));

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

async fn run_shutdown_fences_body() {
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
    governance::propose_role_grant(&state, preserved_target.public_id(), Role::Member, None)
        .await
        .expect("commit the fact preserved across reopen");
    let committed_count = state.semantic_fact_count();
    assert!(committed_count > 0, "the pre-shutdown graph is nonempty");
    // Keep this Arc as the stale caller while its driver and original owner
    // are shut down. Shutdown releases the durable writer lease, but the
    // state-level fence must reject every later mutation through this stale
    // handle rather than allowing it to write the reopened slot.
    let stale = Arc::clone(&state);
    let mut retired_boundary_graph = FactGraph::from_bootstrap(state.verified_bootstrap());
    let stale_fact = authored_fact_with_support(
        &retired_boundary_graph,
        identity.as_ref(),
        FactBody::RoleGrant {
            target: DeviceId::from_canonical_str(stale_target.public_id())
                .expect("stale target id"),
            role: Role::Member,
        },
        Vec::new(),
    );
    retired_boundary_graph
        .admit(stale_fact.clone())
        .expect("stale fact is valid against the retained bootstrap boundary");
    state.request_shutdown();
    driver.await.expect("first driver shutdown");
    assert_eq!(stale.semantic_fact_count(), 0);
    assert_eq!(stale.semantic_unresolved_count(), 0);
    assert_eq!(stale.semantic_provisional_custody_count(), 0);
    assert!(
        stale.compact_semantic_state().is_err(),
        "a stale state cannot compact after shutdown"
    );
    ingest_semantic_fact(&stale, stale_fact).await;
    assert_eq!(
        stale.semantic_fact_count(),
        0,
        "shutdown retires the stale live graph before rejecting admission"
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

#[tokio::test]
async fn shutdown_fences_stale_state_before_same_slot_reopen_and_append() {
    if let Some(home_path) = durable_child_home(SHUTDOWN_FENCES_CHILD_SELECTOR) {
        run_durable_child(SHUTDOWN_FENCES_CHILD_SELECTOR, &home_path)
            .await
            .expect("isolated shutdown-fences child");
        return;
    }
    run_exact_durable_child(SHUTDOWN_FENCES_CHILD_SELECTOR)
        .await
        .expect("isolated shutdown-fences parent");
}
