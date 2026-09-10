#![cfg(feature = "transport-lab")]

//! Production lifecycle control separating founderless Open presence from the
//! signed Closed semantic ledger.  The Open baseline is the first joined empty
//! store; all later reconnect, departure, and restart phases must preserve that
//! exact filesystem footprint and public semantic identity.  Closed then uses
//! the same lifecycle operations, adds signed facts, and proves that a replay
//! is a durable no-op before reopening the same projection.

use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::Instant;

use myownmesh_core::config::{NetworkConfig, NetworkKind, SemanticPolicyConfig};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
use myownmesh_core::semantic::{SemanticFactPageRequest, SignedFact};
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

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct DbFootprint {
    main_bytes: u64,
    wal_bytes: u64,
    shm_bytes: u64,
    journal_bytes: u64,
    temporary_bytes: u64,
}

fn db_footprint(root: &Path) -> DbFootprint {
    fn visit(path: &Path, footprint: &mut DbFootprint) {
        for entry in fs::read_dir(path).expect("semantic state root is readable") {
            let entry = entry.expect("semantic state entry is readable");
            let entry_path = entry.path();
            let file_type = entry
                .file_type()
                .expect("semantic state entry type is readable");
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
                .expect("semantic state entry metadata is readable")
                .len();
            if name.ends_with("-store.sqlite3") {
                footprint.main_bytes = footprint
                    .main_bytes
                    .checked_add(size)
                    .expect("main SQLite footprint fits u64");
            } else if name.ends_with("-store.sqlite3-wal") {
                footprint.wal_bytes = footprint
                    .wal_bytes
                    .checked_add(size)
                    .expect("WAL footprint fits u64");
            } else if name.ends_with("-store.sqlite3-shm") {
                footprint.shm_bytes = footprint
                    .shm_bytes
                    .checked_add(size)
                    .expect("SHM footprint fits u64");
            } else if name.ends_with("-store.sqlite3-journal") {
                footprint.journal_bytes = footprint
                    .journal_bytes
                    .checked_add(size)
                    .expect("rollback journal footprint fits u64");
            } else if name.contains("-store.sqlite3.") && name.ends_with(".tmp") {
                footprint.temporary_bytes = footprint
                    .temporary_bytes
                    .checked_add(size)
                    .expect("store temporary footprint fits u64");
            }
        }
    }

    let mut footprint = DbFootprint::default();
    if root.exists() {
        visit(root, &mut footprint);
    }
    footprint
}

fn record_closed_footprint(
    observed: DbFootprint,
    active_baseline: DbFootprint,
    closed_baseline: &mut Option<DbFootprint>,
    label: &str,
) {
    if let Some(expected) = *closed_baseline {
        assert_eq!(observed, expected, "{label}: closed footprint changed");
        return;
    }

    assert_eq!(
        observed.main_bytes, active_baseline.main_bytes,
        "{label}: closed lifecycle changed persistent SQLite bytes"
    );
    assert_eq!(
        observed.wal_bytes, 0,
        "{label}: closed lifecycle left a WAL file"
    );
    assert_eq!(
        observed.shm_bytes, 0,
        "{label}: closed lifecycle left a SHM file"
    );
    assert_eq!(
        observed.journal_bytes, 0,
        "{label}: closed lifecycle left a rollback journal"
    );
    assert_eq!(
        observed.temporary_bytes, 0,
        "{label}: closed lifecycle left a temporary store"
    );
    *closed_baseline = Some(observed);
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let requested = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        (
            class,
            if class == ResourceClass::StorageBytes {
                SemanticPolicyConfig::default().max_database_bytes
            } else {
                1_000_000_000
            },
        )
    }))
    .expect("ledger fixture resource grant");
    let grant = FiniteResourceProvider::reservation_planning_charge(requested)
        .expect("ledger fixture reservation bookkeeping");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("ledger fixture resource provider");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn network_config(id: &str, kind: NetworkKind) -> NetworkConfig {
    let mut config = NetworkConfig::from_network_id(id, id);
    config.kind = kind;
    config.signaling.strategy = "none".into();
    config.signaling.mdns = false;
    config.stun_servers.clear();
    config.turn_servers.clear();
    config.pinned_peers.clear();
    config.auto_approve = false;
    config
}

async fn reopen_after_lifecycle(
    mesh: &myownmesh_core::MeshHandle,
    config: &NetworkConfig,
    identity: myownmesh_core::semantic::SemanticStateIdentity,
    footprint: DbFootprint,
    label: &str,
) -> myownmesh_core::Result<myownmesh_core::JoinedNetwork> {
    let started = Instant::now();
    let network = mesh.join(config.clone()).await?;
    let elapsed_ns = started.elapsed().as_nanos();
    let identity_before_checkpoint = network.semantic_state_identity()?;
    network.compact_semantic_state()?;
    assert_eq!(
        network.semantic_state_identity()?,
        identity_before_checkpoint,
        "{label}: checkpoint changed public semantic identity"
    );
    assert_eq!(
        network.semantic_state_identity()?,
        identity,
        "{label}: restart changed public semantic identity"
    );
    assert_eq!(
        db_footprint(&myownmesh_core::dirs::data_dir()?),
        footprint,
        "{label}: restart changed the durable SQLite baseline"
    );
    println!("open_closed_semantic_ledger restart label={label} elapsed_ns={elapsed_ns}");
    Ok(network)
}

async fn exported_fact(
    network: &myownmesh_core::JoinedNetwork,
    wanted: myownmesh_core::semantic::FactId,
) -> myownmesh_core::Result<SignedFact> {
    let identity = network.semantic_state_identity()?;
    let page = network.export_semantic_fact_page(SemanticFactPageRequest {
        context_id: identity.context_id(),
        cursor: None,
        max_facts: 64,
        max_encoded_bytes: 65_535,
    })?;
    page.facts()
        .iter()
        .find(|fact| fact.id == wanted)
        .cloned()
        .ok_or_else(|| myownmesh_core::Error::Other("the admitted fact was not exported".into()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn open_presence_is_empty_while_closed_ledger_survives_exact_lifecycle(
) -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("semantic ledger home");
    let _home = ScopedMeshHome::new(home.path());
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(Identity::ephemeral()),
        connector_policy(),
    )
    .await?;

    let open_config = network_config("open-ledger-control", NetworkKind::Open);
    let mut open = Some(mesh.join(open_config.clone()).await?);
    let open_identity = open
        .as_ref()
        .expect("Open network exists after initial join")
        .semantic_state_identity()?;
    assert_eq!(open_identity.admitted_fact_count(), 0);
    assert_eq!(open_identity.unresolved_fact_count(), 0);
    open.as_ref()
        .expect("Open network exists for canonical checkpoint")
        .compact_semantic_state()?;
    assert_eq!(
        open.as_ref()
            .expect("Open network exists after canonical checkpoint")
            .semantic_state_identity()?,
        open_identity,
        "Open checkpoint changed semantic identity"
    );
    let open_active_baseline = db_footprint(home.path());
    let mut open_closed_baseline = None;

    // Open has an empty/bootstrap SQLite baseline owned by the joined network.
    // The explicit checkpoint makes the physical WAL layout canonical; leave
    // may close SQLite and checkpoint it without changing semantic history.
    for cycle in 0..3 {
        let current = open
            .take()
            .expect("Open network exists at every cycle entry");
        current.reconnect(None);
        current.announce_leave().await;
        assert_eq!(
            current.semantic_state_identity()?,
            open_identity,
            "Open cycle {cycle}: presence changed semantic identity"
        );
        assert_eq!(
            db_footprint(home.path()),
            open_active_baseline,
            "Open cycle {cycle}: presence changed durable store footprint"
        );
        current.leave().await?;
        record_closed_footprint(
            db_footprint(home.path()),
            open_active_baseline,
            &mut open_closed_baseline,
            &format!("Open cycle {cycle}"),
        );
        if cycle != 2 {
            open = Some(
                reopen_after_lifecycle(
                    &mesh,
                    &open_config,
                    open_identity.clone(),
                    open_active_baseline,
                    "Open",
                )
                .await?,
            );
        }
    }
    assert!(open.is_none(), "Open cycles leave no joined network owner");

    let closed_config = network_config("closed-ledger-control", NetworkKind::Closed);
    let mut closed = Some(
        mesh.create_network(closed_config.clone(), [0x5a; 32])
            .await?,
    );
    let closed_initial = closed
        .as_ref()
        .expect("Closed network exists after initial creation")
        .semantic_state_identity()?;
    assert_eq!(closed_initial.admitted_fact_count(), 0);
    assert_eq!(closed_initial.unresolved_fact_count(), 0);
    closed
        .as_ref()
        .expect("Closed network exists for canonical checkpoint")
        .compact_semantic_state()?;
    assert_eq!(
        closed
            .as_ref()
            .expect("Closed network exists after canonical checkpoint")
            .semantic_state_identity()?,
        closed_initial,
        "Closed baseline checkpoint changed semantic identity"
    );
    let closed_active_baseline = db_footprint(home.path());
    let mut closed_shutdown_baseline = None;

    // Closed takes the same topology path before any semantic admission.  The
    // baseline includes the existing Open store and the Closed store, so a
    // mismatch is explicitly attributable to this Closed lifecycle phase.
    for cycle in 0..2 {
        let current = closed
            .take()
            .expect("Closed network exists at every cycle entry");
        current.reconnect(None);
        current.announce_leave().await;
        assert_eq!(
            current.semantic_state_identity()?,
            closed_initial,
            "Closed pre-ledger cycle {cycle}: topology changed semantic identity"
        );
        assert_eq!(
            db_footprint(home.path()),
            closed_active_baseline,
            "Closed pre-ledger cycle {cycle}: topology changed durable store footprint"
        );
        current.leave().await?;
        record_closed_footprint(
            db_footprint(home.path()),
            closed_active_baseline,
            &mut closed_shutdown_baseline,
            &format!("Closed pre-ledger cycle {cycle}"),
        );
        closed = Some(
            reopen_after_lifecycle(
                &mesh,
                &closed_config,
                closed_initial.clone(),
                closed_active_baseline,
                "Closed pre-ledger",
            )
            .await?,
        );
    }
    let mut closed = closed
        .take()
        .expect("Closed network exists for semantic admissions");

    let target_one = Identity::ephemeral();
    let first_started = Instant::now();
    let first_id = closed
        .propose_role_grant(
            target_one.public_id(),
            myownmesh_core::semantic::Role::Member,
            None,
        )
        .await?;
    let first_elapsed_ns = first_started.elapsed().as_nanos();
    let after_first = closed.semantic_state_identity()?;
    assert_eq!(
        after_first.admitted_fact_count(),
        closed_initial
            .admitted_fact_count()
            .checked_add(1)
            .expect("Closed fact count fits u64"),
        "Closed admission must create one canonical fact"
    );
    let first_fact = exported_fact(&closed, first_id).await?;
    closed.compact_semantic_state()?;
    assert_eq!(
        closed.semantic_state_identity()?,
        after_first,
        "Closed first-admission checkpoint changed semantic identity"
    );
    let first_ledger = db_footprint(home.path());

    // The exact signed fact re-enters through the public verified import path.
    // AlreadyPresent must be a durable no-op: neither public identity nor the
    // Durable store footprint may not flap.
    let replay_started = Instant::now();
    closed
        .import_semantic_fact_page(semantic_fact_page(
            closed_initial.context_id(),
            &[first_fact],
        ))
        .await?;
    let replay_elapsed_ns = replay_started.elapsed().as_nanos();
    assert_eq!(
        closed.semantic_state_identity()?,
        after_first,
        "Closed byte-identical fact replay changed semantic identity"
    );
    assert_eq!(
        db_footprint(home.path()),
        first_ledger,
        "Closed byte-identical fact replay changed durable store footprint"
    );

    let target_two = Identity::ephemeral();
    let second_started = Instant::now();
    closed
        .propose_role_grant(
            target_two.public_id(),
            myownmesh_core::semantic::Role::Member,
            None,
        )
        .await?;
    let second_elapsed_ns = second_started.elapsed().as_nanos();
    let closed_final = closed.semantic_state_identity()?;
    assert_eq!(
        closed_final.admitted_fact_count(),
        after_first
            .admitted_fact_count()
            .checked_add(1)
            .expect("Closed fact count fits u64"),
        "Closed second admission must create one additional canonical fact"
    );
    closed.compact_semantic_state()?;
    assert_eq!(
        closed.semantic_state_identity()?,
        closed_final,
        "Closed final-admission checkpoint changed semantic identity"
    );
    let closed_final_ledger = db_footprint(home.path());
    assert_ne!(
        closed_final, closed_initial,
        "Closed ledger control must distinguish admissions from Open presence"
    );

    closed.reconnect(None);
    closed.announce_leave().await;
    assert_eq!(
        closed.semantic_state_identity()?,
        closed_final,
        "Closed post-ledger reconnect changed semantic identity"
    );
    assert_eq!(
        db_footprint(home.path()),
        closed_final_ledger,
        "Closed post-ledger reconnect changed durable store footprint"
    );
    closed.leave().await?;
    let closed_final_shutdown_baseline = db_footprint(home.path());
    assert_eq!(
        closed_final_shutdown_baseline.main_bytes, closed_final_ledger.main_bytes,
        "Closed post-ledger shutdown changed persistent SQLite bytes"
    );
    assert_eq!(
        closed_final_shutdown_baseline.wal_bytes, 0,
        "Closed post-ledger shutdown left a WAL file"
    );
    assert_eq!(
        closed_final_shutdown_baseline.shm_bytes, 0,
        "Closed post-ledger shutdown left a SHM file"
    );
    assert_eq!(
        closed_final_shutdown_baseline.journal_bytes, 0,
        "Closed post-ledger shutdown left a rollback journal"
    );
    assert_eq!(
        closed_final_shutdown_baseline.temporary_bytes, 0,
        "Closed post-ledger shutdown left a temporary store"
    );
    closed = reopen_after_lifecycle(
        &mesh,
        &closed_config,
        closed_final.clone(),
        closed_final_ledger,
        "Closed post-ledger",
    )
    .await?;
    closed.leave().await?;
    assert_eq!(
        db_footprint(home.path()),
        closed_final_shutdown_baseline,
        "Closed final shutdown footprint changed"
    );
    println!(
        "open_closed_semantic_ledger admissions first_ns={first_elapsed_ns} replay_ns={replay_elapsed_ns} second_ns={second_elapsed_ns} active_baseline={closed_active_baseline:?} first={first_ledger:?} final={closed_final_ledger:?} closed_shutdown={closed_final_shutdown_baseline:?}"
    );
    Ok(())
}
