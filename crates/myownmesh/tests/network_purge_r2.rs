#![cfg(all(unix, feature = "transport-lab"))]

//! R2 control-socket coverage for network purge and bulk forget.
//!
//! These controls use the embedded daemon's real Unix socket and wire JSON,
//! rather than calling the dispatcher directly.  The dispatcher unit seam
//! owns the deterministic `WriterBusy` control: the public daemon surface
//! quiesces and releases the joined owner before purge, so there is no honest
//! external operation that can hold a competing semantic writer at that
//! boundary.  The socket controls below cover the reachable missing-owner,
//! filesystem-error, partial-bulk, and exact-success outcomes.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::{Mutex, MutexGuard};
use std::time::Instant;

use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

const PURGE_MAX_LIVE_NETWORKS: u64 = 2;

fn test_env_guard() -> MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn test_resource_port() -> myownmesh_core::ResourceProviderPort {
    static PORT: std::sync::OnceLock<myownmesh_core::ResourceProviderPort> =
        std::sync::OnceLock::new();
    PORT.get_or_init(|| {
        let policy = myownmesh_core::config::SemanticPolicyConfig::default();
        let storage_claim = myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::StorageBytes,
            policy.max_database_bytes,
        );
        let storage_grant =
            myownmesh_core::FiniteResourceProvider::reservation_planning_charge(storage_claim)
                .expect("the purge semantic storage reservation is representable")
                .checked_scale(PURGE_MAX_LIVE_NETWORKS)
                .expect("the purge semantic storage owner capacity is representable");
        let workload = myownmesh_core::ResourceClaim::try_from_entries(
            myownmesh_core::ResourceClass::ALL
                .into_iter()
                .filter(|class| *class != myownmesh_core::ResourceClass::StorageBytes)
                .map(|class| (class, 1_000_000_000)),
        )
        .expect("the purge fixture claim is representable")
        .checked_add(storage_grant)
        .expect("the purge fixture storage grant combines");
        myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(
            workload,
        ))
        .expect("the purge fixture provider opens")
    })
    .clone()
}

fn network(id: &str) -> myownmesh_core::NetworkConfig {
    let mut network = myownmesh_core::NetworkConfig::from_network_id(id, id);
    network.stun_servers.clear();
    network.turn_servers.clear();
    network.auto_approve = true;
    network
}

fn connector_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
    myownmesh_core::WebRtcConnectorCapablePolicy::new(
        test_resource_port(),
        myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_data_only(),
        ),
    )
}

async fn wait_for_socket(socket: &Path) {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the purge control socket path is valid");
    tokio::time::timeout(std::time::Duration::from_secs(10), async move {
        loop {
            match LocalSocketStream::connect(name.clone()).await {
                Ok(stream) => {
                    drop(stream);
                    return;
                }
                Err(_) => tokio::task::yield_now().await,
            }
        }
    })
    .await
    .expect("the purge control socket becomes ready");
}

async fn request(socket: &Path, request: &str) -> Value {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the purge control socket path is valid");
    let mut stream = LocalSocketStream::connect(name)
        .await
        .expect("connect the purge control socket");
    stream
        .write_all(request.as_bytes())
        .await
        .expect("write the purge request");
    stream
        .write_all(b"\n")
        .await
        .expect("write the purge request terminator");
    let mut line = String::new();
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        BufReader::new(stream).read_line(&mut line),
    )
    .await
    .expect("the purge response arrives")
    .expect("read the purge response");
    serde_json::from_str(&line).expect("the purge response is JSON")
}

async fn run_ctl_leave(home: &Path, network: &str) -> std::process::Output {
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"))
            .args(["ctl", "networks", "leave", network])
            .env("MYOWNMESH_HOME", home)
            .kill_on_drop(true)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .output(),
    )
    .await
    .expect("the CLI purge response arrives")
    .expect("the CLI purge process exits")
}

fn store_files(root: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in std::fs::read_dir(&directory).expect("walk the isolated daemon state") {
            let entry = entry.expect("read an isolated daemon state entry");
            let path = entry.path();
            let file_type = entry
                .file_type()
                .expect("read an isolated daemon state entry type");
            if file_type.is_dir() {
                pending.push(path);
            } else if file_type.is_file()
                && path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .is_some_and(|name| name.ends_with("-store.sqlite3"))
            {
                files.push(path);
            }
        }
    }
    files.sort();
    files
}

fn error_text(response: &Value) -> &str {
    assert_eq!(response.get("ok").and_then(Value::as_bool), Some(false));
    response
        .get("error")
        .and_then(Value::as_str)
        .expect("a refused purge has an exact error")
}

fn cli_removed(response: &Value, expected: &str) {
    assert_eq!(
        response.get("removed").and_then(Value::as_str),
        Some(expected)
    );
}

fn file_bytes(path: &Path) -> Option<u64> {
    std::fs::metadata(path)
        .ok()
        .filter(|metadata| metadata.is_file())
        .map(|metadata| metadata.len())
}

#[tokio::test]
#[ignore = "process-level purge/recreate control; run in release qualification"]
async fn purge_socket_success_deletes_exact_semantic_store() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated purge home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = true;
    let net = network("purge-exact-success");
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        networks: vec![net.clone()],
        ..Default::default()
    };
    config
        .save()
        .expect("persist the exact purge fixture config");
    let mut competing_daemon_config = myownmesh_core::MeshConfig::default().daemon;
    competing_daemon_config.control_socket =
        Some(home.path().join("private").join("competitor.sock"));
    let mut competing_services = myownmesh_core::MeshConfig::default().services;
    competing_services.node.enabled = true;
    let competing_config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: competing_daemon_config,
        services: competing_services,
        networks: vec![net.clone()],
        ..Default::default()
    };
    let daemon = myownmesh::embedded::start_connector_capable(
        config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await
    .expect("start the purge fixture daemon");
    wait_for_socket(&socket).await;
    let before = store_files(home.path());
    assert_eq!(
        before.len(),
        1,
        "the joined network has one canonical SQLite store"
    );
    let main_store = before[0].clone();
    assert!(main_store.is_file());
    let neighbor = main_store.with_file_name(format!(
        "{}-neighbor",
        main_store
            .file_name()
            .and_then(|name| name.to_str())
            .expect("the canonical store has a UTF-8 file name")
    ));
    std::fs::write(&neighbor, b"neighbor state").expect("create the similarly named neighbor");
    let journal = main_store.with_extension("sqlite3-journal");
    std::fs::write(&journal, b"journal state").expect("create the exact journal sidecar");
    let wal = main_store.with_extension("sqlite3-wal");
    let shm = main_store.with_extension("sqlite3-shm");
    let sidecars: Vec<PathBuf> = [wal.clone(), shm.clone()]
        .into_iter()
        .filter(|path| path.exists())
        .collect();

    let competing = myownmesh::embedded::start_connector_capable(
        competing_config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await;
    let competing_error = match competing {
        Ok(competing_daemon) => {
            competing_daemon
                .shutdown()
                .await
                .expect("clean up an unexpected competing daemon");
            panic!("a live semantic owner did not refuse a competing startup");
        }
        Err(error) => error,
    };
    let competing_writer_busy = competing_error
        .to_string()
        .contains("semantic snapshot writer is busy:");
    assert!(
        competing_writer_busy,
        "competing owner refusal preserves the exact writer fence: {competing_error}"
    );
    let main_before_bytes = file_bytes(&main_store);
    let wal_before_bytes = file_bytes(&wal);
    let shm_before_bytes = file_bytes(&shm);
    let journal_before_bytes = file_bytes(&journal);
    let neighbor_before_bytes = file_bytes(&neighbor);
    let purge_started = Instant::now();

    let output = run_ctl_leave(home.path(), &net.id).await;
    assert!(
        output.status.success(),
        "ctl networks leave failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("the CLI purge response is JSON data");
    cli_removed(&response, "purge-exact-success");
    assert!(
        !main_store.exists(),
        "successful purge removes the exact canonical SQLite store"
    );
    assert!(
        sidecars.iter().all(|path| !path.exists()),
        "successful purge removes present WAL/SHM sidecars for the exact store"
    );
    assert!(
        !journal.exists(),
        "successful purge removes the exact journal sidecar"
    );
    assert!(
        neighbor.exists(),
        "purge does not remove a similarly named neighboring file"
    );
    let purge_elapsed_ms = purge_started.elapsed().as_millis();
    let main_after_bytes = file_bytes(&main_store);
    let wal_after_bytes = file_bytes(&wal);
    let shm_after_bytes = file_bytes(&shm);
    let journal_after_bytes = file_bytes(&journal);
    let neighbor_after_bytes = file_bytes(&neighbor);

    let shutdown_started = Instant::now();
    let primary_shutdown = daemon.shutdown().await;
    let primary_terminal_ok = primary_shutdown.is_ok();
    primary_shutdown.expect("clean shutdown after successful purge");
    let primary_shutdown_elapsed_ms = shutdown_started.elapsed().as_millis();

    let mut restart_daemon_config = myownmesh_core::MeshConfig::default().daemon;
    restart_daemon_config.control_socket = Some(socket.clone());
    let mut restart_services = myownmesh_core::MeshConfig::default().services;
    restart_services.node.enabled = true;
    let restart_config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: restart_daemon_config,
        services: restart_services,
        networks: vec![net.clone()],
        ..Default::default()
    };
    restart_config
        .save()
        .expect("persist the fresh Open restart fixture config");
    let recreate_started = Instant::now();
    let restarted = myownmesh::embedded::start_connector_capable(
        restart_config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await
    .expect("a purged Open network starts with a fresh semantic store");
    wait_for_socket(&socket).await;
    let restarted_stores = store_files(home.path());
    assert_eq!(
        restarted_stores,
        vec![main_store.clone()],
        "restart recreates exactly the purged Open semantic store"
    );
    assert!(
        !journal.exists(),
        "recreated semantic store has no stale journal sidecar"
    );
    assert!(neighbor.exists(), "restart preserves the neighboring file");
    let recreate_elapsed_ms = recreate_started.elapsed().as_millis();
    let recreated_main_bytes = file_bytes(&main_store);
    let recreated_wal_bytes = file_bytes(&wal);
    let recreated_shm_bytes = file_bytes(&shm);
    let recreated_journal_bytes = file_bytes(&journal);
    let recreated_neighbor_bytes = file_bytes(&neighbor);
    let restarted_terminal_ok = restarted.shutdown().await.map(|_| true).unwrap_or(false);
    assert!(
        restarted_terminal_ok,
        "freshly recreated daemon reaches a clean terminal baseline"
    );
    eprintln!(
        "NETWORK_PURGE_R2_METRIC {}",
        serde_json::json!({
            "selector": "purge_socket_success_deletes_exact_semantic_store",
            "purge_elapsed_ms": purge_elapsed_ms,
            "recreate_elapsed_ms": recreate_elapsed_ms,
            "files": {
                "main": {
                    "before_bytes": main_before_bytes,
                    "after_bytes": main_after_bytes,
                    "recreated_bytes": recreated_main_bytes,
                },
                "wal": {
                    "before_bytes": wal_before_bytes,
                    "after_bytes": wal_after_bytes,
                    "recreated_bytes": recreated_wal_bytes,
                },
                "shm": {
                    "before_bytes": shm_before_bytes,
                    "after_bytes": shm_after_bytes,
                    "recreated_bytes": recreated_shm_bytes,
                },
                "journal": {
                    "before_bytes": journal_before_bytes,
                    "after_bytes": journal_after_bytes,
                    "recreated_bytes": recreated_journal_bytes,
                },
                "neighbor": {
                    "before_bytes": neighbor_before_bytes,
                    "after_bytes": neighbor_after_bytes,
                    "recreated_bytes": recreated_neighbor_bytes,
                },
            },
            "neighbor_survived": neighbor_after_bytes == neighbor_before_bytes
                && recreated_neighbor_bytes == neighbor_before_bytes,
            "competing_writer_busy": competing_writer_busy,
            "terminal_baseline": {
                "primary_shutdown_ok": primary_terminal_ok,
                "restarted_shutdown_ok": restarted_terminal_ok,
                "primary_shutdown_elapsed_ms": primary_shutdown_elapsed_ms,
            },
        })
    );
}

#[tokio::test]
async fn purge_socket_surfaces_io_failure_and_bulk_aggregates_partial_result() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated bulk purge home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = true;
    let first = network("purge-bulk-first");
    let second = network("purge-bulk-second");
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        networks: vec![first, second],
        ..Default::default()
    };
    config
        .save()
        .expect("persist the bulk purge fixture config");
    let daemon = myownmesh::embedded::start_connector_capable(
        config,
        connector_policy(),
        myownmesh::control::RealtimeAdvert::unsupported(),
    )
    .await
    .expect("start the bulk purge fixture daemon");
    wait_for_socket(&socket).await;
    let stores = store_files(home.path());
    assert_eq!(
        stores.len(),
        2,
        "both networks have canonical SQLite stores"
    );
    let broken = stores[0].clone();
    let healthy = stores[1].clone();
    let healthy_sidecars: Vec<PathBuf> = [
        healthy.with_extension("sqlite3-wal"),
        healthy.with_extension("sqlite3-shm"),
    ]
    .into_iter()
    .filter(|path| path.exists())
    .collect();
    let healthy_journal = healthy.with_extension("sqlite3-journal");
    std::fs::write(&healthy_journal, b"healthy journal state")
        .expect("create the healthy exact journal sidecar");
    std::fs::remove_file(&broken).expect("remove the exact main store before replacement");
    std::fs::create_dir(&broken).expect("replace the main store with an I/O failure shape");

    let response = request(&socket, r#"{"op":"forget_all_networks"}"#).await;
    let error = error_text(&response);
    assert!(error.contains("forget all failed for 1 network(s)"));
    assert!(error.contains("purge-bulk-first"));
    assert!(error.contains("purge-bulk-second"));
    assert!(
        error.contains("completed:"),
        "bulk refusal reports the successful sibling as completed"
    );
    assert!(
        broken.is_dir(),
        "the failing main store was not silently deleted"
    );
    assert!(
        !healthy.exists(),
        "the healthy network's exact main store is deleted despite the sibling failure"
    );
    assert!(
        healthy_sidecars.iter().all(|path| !path.exists()),
        "the healthy network's present WAL/SHM sidecars are deleted"
    );
    assert!(
        !healthy_journal.exists(),
        "the healthy network's exact journal sidecar is deleted"
    );

    daemon
        .shutdown()
        .await
        .expect("clean shutdown after bulk purge");
}

#[tokio::test]
async fn purge_socket_missing_owner_refuses_without_config_mutation() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated missing-owner home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = false;
    let config = myownmesh_core::MeshConfig {
        identity_path: Some(home.path().join("identity.json")),
        auto_update: myownmesh_core::AutoUpdateConfig {
            enabled: false,
            ..Default::default()
        },
        daemon: daemon_config,
        services,
        ..Default::default()
    };
    config
        .save()
        .expect("persist the missing-owner fixture config");
    let config_path = myownmesh_core::dirs::config_path().expect("resolve the fixture config");
    let before = std::fs::read(&config_path).expect("read the fixture config before refusal");
    let daemon = myownmesh::embedded::start_infrastructure_only(config, test_resource_port())
        .await
        .expect("start the missing-owner fixture daemon");
    wait_for_socket(&socket).await;

    let output = run_ctl_leave(home.path(), "purge-missing-owner").await;
    assert!(
        !output.status.success(),
        "missing-owner CLI request succeeded"
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("daemon error: unknown network: purge-missing-owner"),
        "missing-owner CLI refusal was not preserved: stderr={}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(
        std::fs::read(&config_path).expect("read the fixture config after refusal"),
        before,
        "missing-owner refusal does not mutate config"
    );

    daemon
        .shutdown()
        .await
        .expect("clean shutdown after missing-owner refusal");
}
