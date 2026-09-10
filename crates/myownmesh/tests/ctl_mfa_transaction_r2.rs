#![cfg(all(unix, feature = "transport-lab"))]

//! R2 control-socket coverage for the shipped MFA CLI.
//!
//! The daemon is the real control surface (embedded for ordinary requests and
//! the shipped `myownmesh serve` process for the hard-death boundary), while
//! the client for every request is the built `myownmesh ctl` binary. This keeps
//! the assertion at the boundary users cross: an enrollment response is not a
//! terminal custody decision, and an exact transaction can be queried after a
//! discarded reply.

use std::path::Path;
use std::process::{Output, Stdio};

use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
use serde_json::Value;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

fn test_resource_port() -> myownmesh_core::ResourceProviderPort {
    let claim = myownmesh_core::ResourceClaim::try_from_entries(
        myownmesh_core::ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000_000)),
    )
    .expect("the CLI control fixture claim is representable");
    myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(claim))
        .expect("the CLI control fixture provider opens")
}

async fn wait_for_socket(socket: &Path) {
    let name = socket
        .to_fs_name::<GenericFilePath>()
        .expect("the CLI control socket path is valid");
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
    .expect("the real control socket becomes ready");
}

async fn run_ctl(home: &Path, args: &[&str]) -> Output {
    let args = args.iter().map(|arg| (*arg).to_owned()).collect::<Vec<_>>();
    let rendered_args = args.join(" ");
    let mut command = tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"));
    command
        .arg("ctl")
        .arg("governance")
        .arg("mfa")
        .args(&args)
        .env("MYOWNMESH_HOME", home)
        .kill_on_drop(true)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    let child = command
        .spawn()
        .unwrap_or_else(|error| panic!("spawn shipped myownmesh ctl {rendered_args}: {error}"));
    tokio::time::timeout(std::time::Duration::from_secs(10), child.wait_with_output())
        .await
        .unwrap_or_else(|_| {
            panic!("shipped myownmesh ctl timed out after 10s for arguments: {rendered_args}")
        })
        .unwrap_or_else(|error| panic!("wait for shipped myownmesh ctl {rendered_args}: {error}"))
}

fn response(output: Output, what: &str) -> Value {
    assert!(
        output.status.success(),
        "{what} failed: stdout={} stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "{what} did not print JSON: {error}; stdout={}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

fn transaction_data<'a>(value: &'a Value, _what: &str) -> &'a Value {
    value
}

fn field<'a>(data: &'a Value, key: &str, what: &str) -> &'a str {
    data.get(key)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("{what} response has no string field {key}: {data}"))
}

#[tokio::test]
async fn shipped_ctl_mfa_prepare_commit_query_redeliver_and_stale_successor_are_exact() {
    let home = tempfile::tempdir().expect("isolated CLI home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let socket = home.path().join("private").join("daemon.sock");
    let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
    daemon_config.control_socket = Some(socket.clone());
    let mut services = myownmesh_core::MeshConfig::default().services;
    services.node.enabled = false;
    let config = myownmesh_core::MeshConfig {
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
        .expect("persist the CLI's isolated socket config");
    let daemon =
        myownmesh::embedded::start_infrastructure_only(config.clone(), test_resource_port())
            .await
            .expect("start the real embedded control server");
    wait_for_socket(&socket).await;

    let network = "ctl-r2-exact-mfa";

    // Explicit Prepare crosses the shipped CLI and real control socket while
    // leaving exact material durably Prepared for query/redelivery/abort.
    let prepared_initial = response(
        run_ctl(home.path(), &["prepare", network]).await,
        "ctl mfa prepare",
    );
    let prepared_data = transaction_data(&prepared_initial, "ctl mfa prepare");
    let first_transaction = field(prepared_data, "transaction_id", "ctl mfa prepare");
    let first_secret = field(prepared_data, "secret", "ctl mfa prepare");
    assert!(!first_transaction.is_empty());
    assert!(!first_secret.is_empty());

    let queried = response(
        run_ctl(home.path(), &["query", network, first_transaction]).await,
        "ctl mfa query prepared",
    );
    let queried_data = transaction_data(&queried, "ctl mfa query prepared");
    assert_eq!(
        field(queried_data, "state", "ctl mfa query prepared"),
        "prepared"
    );
    assert_eq!(
        field(queried_data, "transaction_id", "ctl mfa query prepared"),
        first_transaction
    );
    assert_eq!(
        field(queried_data, "secret", "ctl mfa query prepared"),
        first_secret
    );

    let redelivered = response(
        run_ctl(home.path(), &["redeliver", network, first_transaction]).await,
        "ctl mfa redeliver prepared",
    );
    let redelivered_data = transaction_data(&redelivered, "ctl mfa redeliver prepared");
    assert_eq!(
        field(
            redelivered_data,
            "transaction_id",
            "ctl mfa redeliver prepared"
        ),
        first_transaction
    );
    assert_eq!(
        field(redelivered_data, "secret", "ctl mfa redeliver prepared"),
        first_secret
    );

    let aborted = response(
        run_ctl(home.path(), &["abort", network, first_transaction]).await,
        "ctl mfa abort first transaction",
    );
    assert_eq!(
        field(
            transaction_data(&aborted, "ctl mfa abort first transaction"),
            "state",
            "ctl mfa abort first transaction"
        ),
        "absent"
    );

    // A fresh Prepare is a successor generation. The stale first transaction
    // can be queried or committed, but it must report Absent and never touch
    // this exact successor.
    let prepared = response(
        run_ctl(home.path(), &["prepare", network]).await,
        "ctl mfa prepare successor",
    );
    let prepared_data = transaction_data(&prepared, "ctl mfa prepare successor");
    let second_transaction = field(prepared_data, "transaction_id", "ctl mfa prepare successor");
    let second_secret = field(prepared_data, "secret", "ctl mfa prepare successor");
    assert_ne!(first_transaction, second_transaction);
    assert!(!second_secret.is_empty());

    let stale_commit = response(
        run_ctl(home.path(), &["commit", network, first_transaction]).await,
        "ctl mfa stale commit",
    );
    assert_eq!(
        field(
            transaction_data(&stale_commit, "ctl mfa stale commit"),
            "state",
            "ctl mfa stale commit"
        ),
        "absent"
    );
    let successor_query = response(
        run_ctl(home.path(), &["query", network, second_transaction]).await,
        "ctl mfa query successor after stale commit",
    );
    let successor_data = transaction_data(
        &successor_query,
        "ctl mfa query successor after stale commit",
    );
    assert_eq!(
        field(
            successor_data,
            "state",
            "ctl mfa query successor after stale commit"
        ),
        "prepared"
    );
    assert_eq!(
        field(
            successor_data,
            "secret",
            "ctl mfa query successor after stale commit"
        ),
        second_secret
    );

    // Discard the final commit response deliberately. Querying the same exact
    // transaction is the lost-ACK recovery path and must expose Committed;
    // a requested-state guess cannot satisfy this assertion.
    let _discarded_commit = run_ctl(home.path(), &["commit", network, second_transaction]).await;
    let recovered = response(
        run_ctl(home.path(), &["query", network, second_transaction]).await,
        "ctl mfa query after discarded commit response",
    );
    let recovered_data =
        transaction_data(&recovered, "ctl mfa query after discarded commit response");
    assert_eq!(
        field(
            recovered_data,
            "state",
            "ctl mfa query after discarded commit response"
        ),
        "committed"
    );
    assert!(recovered_data.get("secret").is_none());
    assert!(recovered_data.get("otpauth_uri").is_none());
    assert!(recovered_data.get("recovery_codes").is_none());

    let duplicate_commit = response(
        run_ctl(home.path(), &["commit", network, second_transaction]).await,
        "ctl mfa duplicate commit",
    );
    assert_eq!(
        field(
            transaction_data(&duplicate_commit, "ctl mfa duplicate commit"),
            "state",
            "ctl mfa duplicate commit"
        ),
        "committed"
    );
    let late_abort = response(
        run_ctl(home.path(), &["abort", network, second_transaction]).await,
        "ctl mfa late abort",
    );
    assert_eq!(
        field(
            transaction_data(&late_abort, "ctl mfa late abort"),
            "state",
            "ctl mfa late abort"
        ),
        "committed"
    );

    // A daemon boundary must not lose a Prepared transaction. Shut down the
    // in-process fixture first, then use the shipped daemon with a real
    // transport-lab pause after durable preparation and before its first
    // response write. The raw client never reads that response: the marker
    // contains no transaction or material, and the parked daemon is killed
    // before the client is restarted against the same custody root.
    let restart_network = "ctl-r2-restart-recovery";
    daemon
        .shutdown()
        .await
        .expect("shut down the in-process fixture before restart recovery");

    let barrier_listener = TcpListener::bind(("127.0.0.1", 0))
        .await
        .expect("bind the loopback transport-lab barrier");
    let barrier_address = barrier_listener
        .local_addr()
        .expect("read the loopback barrier address");
    let resource_grant = "accounted_memory_bytes=1000000000,queued_bytes=1000000000,\
        socket_or_handle=1000000000,native_transport_object=1000000000,\
        worker_or_task=1000000000,callback_or_scheduled_work=1000000000,\
        storage_bytes=1000000000,storage_object=1000000000,\
        relay_or_provider_allocation=1000000000,parsing_or_cpu_work=1000000000,\
        opaque_dependency_residual=1000000000";
    let mut parked_daemon = tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"))
        .arg("serve")
        .env("MYOWNMESH_HOME", home.path())
        .env("MYOWNMESH_RESOURCE_GRANT", resource_grant)
        .env(
            "MYOWNMESH_TRANSPORT_LAB_MFA_BARRIER",
            barrier_address.to_string(),
        )
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the shipped daemon for the parked prepare");
    wait_for_socket(&socket).await;
    let socket_name = socket
        .as_path()
        .to_fs_name::<GenericFilePath>()
        .expect("the control socket path is valid");
    let mut raw_client = LocalSocketStream::connect(socket_name)
        .await
        .expect("connect the raw client before the parked prepare");
    raw_client
        .write_all(
            br#"{"op":"governance_mfa_prepare","network":"ctl-r2-restart-recovery"}
"#,
        )
        .await
        .expect("send the prepare without reading its response");
    let (mut barrier_stream, _) = tokio::time::timeout(
        std::time::Duration::from_secs(10),
        barrier_listener.accept(),
    )
    .await
    .expect("the daemon reaches the pre-write barrier")
    .expect("the barrier accepts the daemon");
    let mut marker = [0_u8; 9];
    tokio::time::timeout(
        std::time::Duration::from_secs(10),
        barrier_stream.read_exact(&mut marker),
    )
    .await
    .expect("the daemon announces the durable prepare")
    .expect("read the complete barrier marker");
    assert_eq!(&marker, b"PREPARED\n");
    drop(raw_client);
    parked_daemon
        .kill()
        .await
        .expect("hard-kill the daemon while its response is parked");
    let killed = tokio::time::timeout(std::time::Duration::from_secs(10), parked_daemon.wait())
        .await
        .expect("the killed daemon exits")
        .expect("wait for the killed daemon");
    assert!(!killed.success(), "the parked daemon was hard-killed");

    // The oracle is read only after the crash and never supplies arguments to
    // the recovery client. It proves that exactly one durable Prepared record
    // survived, including the full material the client must recover by N.
    let prepared = myownmesh_core::custody::prepared_enrollments()
        .expect("read the durable prepared records after hard-kill");
    let mut matching = prepared
        .into_iter()
        .filter(|record| record.network_id() == restart_network)
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "hard-kill leaves exactly one prepared transaction for the network"
    );
    let oracle = matching
        .pop()
        .expect("the exact prepared recovery oracle exists");
    let restart_transaction = oracle.transaction_id().to_owned();
    let restart_secret = oracle.enrolled().secret_b32.clone();
    let restart_otpauth = oracle.enrolled().otpauth_uri.clone();
    let restart_recovery_codes = oracle.enrolled().recovery_codes.clone();

    // Restart without the lab hook. The recovery-aware Prepare command
    // receives only N and must recover the exact durable transaction and
    // material; Commit remains a separate explicit client decision.
    let mut recovered_daemon = tokio::process::Command::new(env!("CARGO_BIN_EXE_myownmesh"))
        .arg("serve")
        .env("MYOWNMESH_HOME", home.path())
        .env("MYOWNMESH_RESOURCE_GRANT", resource_grant)
        .kill_on_drop(true)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn the restarted shipped daemon");
    wait_for_socket(&socket).await;

    let recovered_material = response(
        run_ctl(home.path(), &["prepare", restart_network]).await,
        "ctl mfa prepare after daemon restart",
    );
    assert_eq!(
        field(
            &recovered_material,
            "transaction_id",
            "ctl mfa recovered enrollment material",
        ),
        restart_transaction
    );
    assert_eq!(
        field(
            &recovered_material,
            "secret",
            "ctl mfa recovered enrollment material",
        ),
        restart_secret
    );
    assert_eq!(
        field(
            &recovered_material,
            "otpauth_uri",
            "ctl mfa recovered enrollment material",
        ),
        restart_otpauth
    );
    assert_eq!(
        recovered_material
            .get("recovery_codes")
            .and_then(Value::as_array)
            .expect("ctl mfa recovered enrollment has recovery codes")
            .iter()
            .map(|value| value.as_str().expect("recovery code is a string"))
            .collect::<Vec<_>>(),
        restart_recovery_codes
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
    );
    let recovered_commit = response(
        run_ctl(
            home.path(),
            &["commit", restart_network, &restart_transaction],
        )
        .await,
        "ctl mfa commit after daemon restart",
    );
    assert_eq!(
        field(
            &recovered_commit,
            "transaction_id",
            "ctl mfa recovered enrollment commit",
        ),
        restart_transaction
    );
    assert_eq!(
        field(
            &recovered_commit,
            "state",
            "ctl mfa recovered enrollment commit",
        ),
        "committed"
    );
    assert!(recovered_commit.get("secret").is_none());
    assert!(recovered_commit.get("otpauth_uri").is_none());
    assert!(recovered_commit.get("recovery_codes").is_none());
    let recovered_query = response(
        run_ctl(
            home.path(),
            &["query", restart_network, &restart_transaction],
        )
        .await,
        "ctl mfa query after daemon restart recovery",
    );
    let recovered_query_data = transaction_data(
        &recovered_query,
        "ctl mfa query after daemon restart recovery",
    );
    assert_eq!(
        field(
            recovered_query_data,
            "state",
            "ctl mfa query after daemon restart recovery",
        ),
        "committed"
    );
    assert!(recovered_query_data.get("secret").is_none());
    assert!(recovered_query_data.get("otpauth_uri").is_none());
    assert!(recovered_query_data.get("recovery_codes").is_none());
    assert!(
        !myownmesh_core::custody::prepared_enrollments()
            .expect("reopen prepared records after exact recovery")
            .iter()
            .any(|record| record.network_id() == restart_network),
        "exact recovery commits the one prepared record without creating a successor"
    );

    // Two real shipped Prepare clients racing on one network may both win
    // the recovery-aware classification, but they must observe the same
    // exact transaction/material. No response may fabricate a second record.
    let concurrent_network = "ctl-r2-concurrent-prepare";
    let left_args = ["prepare", concurrent_network];
    let right_args = ["prepare", concurrent_network];
    let (left, right) = tokio::join!(
        run_ctl(home.path(), &left_args),
        run_ctl(home.path(), &right_args),
    );
    let left = response(left, "first concurrent ctl mfa prepare");
    let right = response(right, "second concurrent ctl mfa prepare");
    let left_data = transaction_data(&left, "first concurrent ctl mfa prepare");
    let right_data = transaction_data(&right, "second concurrent ctl mfa prepare");
    assert_eq!(
        field(
            left_data,
            "transaction_id",
            "first concurrent ctl mfa prepare"
        ),
        field(
            right_data,
            "transaction_id",
            "second concurrent ctl mfa prepare"
        )
    );
    assert_eq!(
        field(left_data, "secret", "first concurrent ctl mfa prepare"),
        field(right_data, "secret", "second concurrent ctl mfa prepare")
    );
    assert_eq!(
        field(left_data, "otpauth_uri", "first concurrent ctl mfa prepare",),
        field(
            right_data,
            "otpauth_uri",
            "second concurrent ctl mfa prepare",
        )
    );
    let left_recovery_codes = left_data
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("first concurrent ctl mfa prepare has recovery codes")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("first concurrent recovery code is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let right_recovery_codes = right_data
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("second concurrent ctl mfa prepare has recovery codes")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("second concurrent recovery code is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(left_recovery_codes, right_recovery_codes);
    let concurrent_transaction = field(
        left_data,
        "transaction_id",
        "first concurrent ctl mfa prepare",
    )
    .to_owned();
    let concurrent_secret =
        field(left_data, "secret", "first concurrent ctl mfa prepare").to_owned();
    let concurrent_otpauth =
        field(left_data, "otpauth_uri", "first concurrent ctl mfa prepare").to_owned();
    let prepared = myownmesh_core::custody::prepared_enrollments()
        .expect("read the exact concurrent prepared record");
    let mut matching = prepared
        .into_iter()
        .filter(|record| {
            record.network_id() == concurrent_network
                && record.transaction_id() == concurrent_transaction
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching.len(),
        1,
        "concurrent Prepare creates exactly one durable prepared record"
    );
    let matching = matching
        .pop()
        .expect("the exact concurrent prepared record exists");
    assert_eq!(matching.enrolled().secret_b32, concurrent_secret);
    assert_eq!(matching.enrolled().otpauth_uri, concurrent_otpauth);
    assert_eq!(matching.enrolled().recovery_codes, left_recovery_codes);
    let concurrent_abort = response(
        run_ctl(
            home.path(),
            &["abort", concurrent_network, &concurrent_transaction],
        )
        .await,
        "ctl mfa abort concurrent prepared transaction",
    );
    assert_eq!(
        field(
            transaction_data(
                &concurrent_abort,
                "ctl mfa abort concurrent prepared transaction",
            ),
            "state",
            "ctl mfa abort concurrent prepared transaction",
        ),
        "absent"
    );

    // Disable is a terminal custody operation, not a way to bypass the
    // explicit Prepared -> Commit/Abort transaction protocol. A valid
    // recovery code must be rejected while the exact transaction remains
    // Prepared and redeliverable. Only exact Abort may then permit a fresh
    // generation for this network.
    let disable_network = "ctl-r2-disable-prepared";
    let disable_prepared = response(
        run_ctl(home.path(), &["prepare", disable_network]).await,
        "ctl mfa prepare before disable",
    );
    let disable_data = transaction_data(&disable_prepared, "ctl mfa prepare before disable");
    let disable_transaction = field(
        disable_data,
        "transaction_id",
        "ctl mfa prepare before disable",
    )
    .to_owned();
    let disable_secret = field(disable_data, "secret", "ctl mfa prepare before disable").to_owned();
    let disable_otpauth = field(
        disable_data,
        "otpauth_uri",
        "ctl mfa prepare before disable",
    )
    .to_owned();
    let disable_recovery_codes = disable_data
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("ctl mfa prepare before disable has recovery codes")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("disable recovery code is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    let disable_code = disable_recovery_codes
        .first()
        .expect("prepared enrollment has a valid disable test code")
        .clone();

    let disable_output = run_ctl(home.path(), &["disable", disable_network, &disable_code]).await;
    assert!(
        !disable_output.status.success(),
        "disable must fail while the exact enrollment is Prepared: stdout={} stderr={}",
        String::from_utf8_lossy(&disable_output.stdout),
        String::from_utf8_lossy(&disable_output.stderr)
    );

    let still_prepared = response(
        run_ctl(
            home.path(),
            &["query", disable_network, &disable_transaction],
        )
        .await,
        "ctl mfa query after rejected disable",
    );
    let still_prepared_data =
        transaction_data(&still_prepared, "ctl mfa query after rejected disable");
    assert_eq!(
        field(
            still_prepared_data,
            "state",
            "ctl mfa query after rejected disable",
        ),
        "prepared"
    );
    assert_eq!(
        field(
            still_prepared_data,
            "transaction_id",
            "ctl mfa query after rejected disable",
        ),
        disable_transaction
    );
    assert_eq!(
        field(
            still_prepared_data,
            "secret",
            "ctl mfa query after rejected disable"
        ),
        disable_secret
    );
    assert_eq!(
        field(
            still_prepared_data,
            "otpauth_uri",
            "ctl mfa query after rejected disable",
        ),
        disable_otpauth
    );
    let still_prepared_codes = still_prepared_data
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("rejected disable keeps recovery codes queryable")
        .iter()
        .map(|value| {
            value
                .as_str()
                .expect("queried disable recovery code is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(still_prepared_codes, disable_recovery_codes);

    let disable_records = myownmesh_core::custody::prepared_enrollments()
        .expect("read the prepared record after rejected disable");
    let matching_disable_records = disable_records
        .into_iter()
        .filter(|record| {
            record.network_id() == disable_network && record.transaction_id() == disable_transaction
        })
        .collect::<Vec<_>>();
    assert_eq!(
        matching_disable_records.len(),
        1,
        "rejected disable leaves exactly one durable prepared record"
    );
    let matching_disable_record = matching_disable_records
        .into_iter()
        .next()
        .expect("the exact prepared record survives rejected disable");
    assert_eq!(
        matching_disable_record.enrolled().secret_b32,
        disable_secret
    );
    assert_eq!(
        matching_disable_record.enrolled().otpauth_uri,
        disable_otpauth
    );
    assert_eq!(
        matching_disable_record.enrolled().recovery_codes,
        disable_recovery_codes
    );

    let disable_abort = response(
        run_ctl(
            home.path(),
            &["abort", disable_network, &disable_transaction],
        )
        .await,
        "ctl mfa abort after rejected disable",
    );
    assert_eq!(
        field(
            transaction_data(&disable_abort, "ctl mfa abort after rejected disable"),
            "state",
            "ctl mfa abort after rejected disable",
        ),
        "absent"
    );
    let disable_successor = response(
        run_ctl(home.path(), &["prepare", disable_network]).await,
        "ctl mfa prepare after exact abort",
    );
    let disable_successor_data =
        transaction_data(&disable_successor, "ctl mfa prepare after exact abort");
    let disable_successor_transaction = field(
        disable_successor_data,
        "transaction_id",
        "ctl mfa prepare after exact abort",
    );
    let disable_successor_secret = field(
        disable_successor_data,
        "secret",
        "ctl mfa prepare after exact abort",
    );
    assert_ne!(disable_successor_transaction, disable_transaction);
    assert_ne!(disable_successor_secret, disable_secret);
    let disable_successor_abort = response(
        run_ctl(
            home.path(),
            &["abort", disable_network, disable_successor_transaction],
        )
        .await,
        "ctl mfa abort successor after rejected disable",
    );
    assert_eq!(
        field(
            transaction_data(
                &disable_successor_abort,
                "ctl mfa abort successor after rejected disable",
            ),
            "state",
            "ctl mfa abort successor after rejected disable",
        ),
        "absent"
    );

    // Prepare returns material, and only the explicit Commit command settles
    // its exact transaction. The follow-up query proves the result is not
    // merely Prepared.
    let enroll_network = "ctl-r2-explicit-enroll";
    let enrollment_material = response(
        run_ctl(home.path(), &["prepare", enroll_network]).await,
        "ctl mfa prepare for explicit commit",
    );
    let enroll_transaction = field(
        &enrollment_material,
        "transaction_id",
        "ctl mfa enroll material",
    );
    let enroll_secret = field(&enrollment_material, "secret", "ctl mfa enroll material");
    assert!(!enroll_transaction.is_empty());
    assert!(!enroll_secret.is_empty());
    assert!(!field(
        &enrollment_material,
        "otpauth_uri",
        "ctl mfa enroll material"
    )
    .is_empty());
    assert!(!enrollment_material
        .get("recovery_codes")
        .and_then(Value::as_array)
        .expect("ctl mfa enroll material has recovery codes")
        .is_empty());
    let enrolled = response(
        run_ctl(home.path(), &["commit", enroll_network, enroll_transaction]).await,
        "ctl mfa explicit commit",
    );
    assert_eq!(
        field(&enrolled, "network", "ctl mfa explicit commit"),
        enroll_network
    );
    assert_eq!(
        field(&enrolled, "transaction_id", "ctl mfa explicit commit"),
        enroll_transaction
    );
    assert_eq!(
        field(&enrolled, "state", "ctl mfa explicit commit"),
        "committed"
    );
    assert!(enrolled.get("secret").is_none());
    assert!(enrolled.get("otpauth_uri").is_none());
    assert!(enrolled.get("recovery_codes").is_none());
    let enrolled_query = response(
        run_ctl(home.path(), &["query", enroll_network, enroll_transaction]).await,
        "ctl mfa query after enroll",
    );
    let enrolled_query_data = transaction_data(&enrolled_query, "ctl mfa query after enroll");
    assert_eq!(
        field(enrolled_query_data, "state", "ctl mfa query after enroll"),
        "committed"
    );
    assert!(enrolled_query_data.get("secret").is_none());
    assert!(enrolled_query_data.get("otpauth_uri").is_none());
    assert!(enrolled_query_data.get("recovery_codes").is_none());

    recovered_daemon
        .kill()
        .await
        .expect("hard-kill the recovered daemon after exact CLI checks");
    tokio::time::timeout(std::time::Duration::from_secs(10), recovered_daemon.wait())
        .await
        .expect("the recovered daemon exits")
        .expect("wait for the recovered daemon");
    std::env::remove_var("MYOWNMESH_HOME");
}
