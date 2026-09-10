//! R2 process-death control for provisional MFA enrollment.
//!
//! The enrollment record is installed before its response is observable and
//! remains `Prepared` across every write outcome. A hard-dead child cannot run
//! a Rust `Drop`, so restart can query or re-deliver exact material, and only
//! an explicit commit or abort is terminal.
//!
//! The pipe is the lifecycle barrier. The parent blocks on the child's
//! explicit marker and then kills it; there are no timing guesses, polling
//! loops, or sleeps. Explicit abort/commit calls below model client commands.

#![cfg(feature = "transport-lab")]

use std::io::{BufRead, BufReader, Write};
use std::process::{Child, Command, Stdio};
use std::sync::Mutex;

const CHILD_MODE: &str = "MYOWNMESH_R2_CHILD_MODE";
const CHILD_NETWORK: &str = "MYOWNMESH_R2_CHILD_NETWORK";
const PREPARE_RACE_MODE: &str = "prepare-race";

/// `MYOWNMESH_HOME` is process-global, and the integration harness launches
/// child processes that inherit it. Serialize every parent test that changes
/// it so parallel libtest scheduling cannot redirect another test's custody
/// reads or writes into the wrong temporary root. Poison is recovered because
/// a prior test panic must not permanently disable the remaining controls.
static TEST_ENV_LOCK: Mutex<()> = Mutex::new(());

fn test_env_guard() -> std::sync::MutexGuard<'static, ()> {
    TEST_ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn spawn_child(
    home: &std::path::Path,
    mode: &str,
    network: &str,
) -> (Child, BufReader<std::process::ChildStdout>) {
    let mut child = Command::new(std::env::current_exe().expect("the integration test executable"))
        .arg("--exact")
        .arg("child_provisional_enrollment")
        .arg("--nocapture")
        .env("MYOWNMESH_HOME", home)
        .env(CHILD_MODE, mode)
        .env(CHILD_NETWORK, network)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn provisional enrollment child");
    let stdout = child.stdout.take().expect("child stdout");
    (child, BufReader::new(stdout))
}

fn read_marker(reader: &mut BufReader<std::process::ChildStdout>) -> String {
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line).expect("child lifecycle marker");
        assert!(
            read != 0,
            "child exited before publishing a lifecycle marker"
        );
        let marker = line.trim_end();
        if marker == "PREPARED"
            || marker.starts_with("PREPARED ")
            || marker == "KEPT"
            || marker == "COMMITTED"
            || marker == "ACKED"
            || marker == "CALLER_READY"
            || marker.starts_with("RESULT ")
            || (marker.starts_with("DELIVERED ") && marker.len() > "DELIVERED ".len())
        {
            return marker.to_owned();
        }
    }
}

#[test]
fn v4_r2_child_hard_death_distinguishes_prepared_from_delivered_enrollment() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated MyOwnMesh home");
    let network = "r2-hard-death";
    std::env::set_var("MYOWNMESH_HOME", home.path());

    // The child has installed the lock, but has not crossed the observable
    // response boundary. A hard stop is the real process-death edge: armed
    // Drop cannot run in the child, so restart must recover this provisional
    // record rather than treating it as a delivered enrollment.
    let (mut prepared, mut prepared_out) = spawn_child(home.path(), "prepared", network);
    let prepared_marker = read_marker(&mut prepared_out);
    let prepared_transaction = prepared_marker
        .strip_prefix("PREPARED ")
        .expect("prepared marker carries the exact transaction identity");
    assert!(!prepared_transaction.is_empty());
    assert!(
        myownmesh_core::custody::is_enrolled(network),
        "prepared child must first prove that its durable lock exists"
    );
    prepared.kill().expect("hard-stop prepared child");
    prepared.wait().expect("reap prepared child");
    assert!(
        myownmesh_core::custody::is_enrolled(network),
        "restart preserves the prepared lock until an explicit terminal command"
    );
    match myownmesh_core::custody::enrollment_transaction(network, prepared_transaction)
        .expect("query prepared transaction after hard death")
    {
        myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared) => {
            let duplicate = prepared.clone();
            prepared
                .abort()
                .expect("explicit abort settles the pre-publication transaction");
            duplicate
                .abort()
                .expect("duplicate exact abort is idempotent");
        }
        other => panic!("prepared hard death changed exact state: {other:?}"),
    }
    assert!(!myownmesh_core::custody::is_enrolled(network));

    // Material delivery is not a commit. Kill the child after the exact
    // material marker and before an explicit commit, then query and settle
    // the same transaction from durable storage.
    let (mut delivered, mut delivered_out) = spawn_child(home.path(), "delivered", network);
    let marker = read_marker(&mut delivered_out);
    let delivered_fields = marker
        .strip_prefix("DELIVERED ")
        .expect("delivered enrollment marker carries material and transaction");
    let (recovery_code, delivered_transaction) = delivered_fields
        .rsplit_once(' ')
        .expect("delivered marker carries an exact transaction identity");
    assert!(
        !recovery_code.is_empty(),
        "the delivered marker must carry observable enrollment material"
    );
    assert!(myownmesh_core::custody::is_enrolled(network));
    delivered.kill().expect("hard-stop after material delivery");
    delivered.wait().expect("reap delivered child");
    let redelivered =
        match myownmesh_core::custody::enrollment_transaction(network, delivered_transaction)
            .expect("query exact prepared transaction after material-only death")
        {
            myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared) => prepared,
            other => panic!("material-only death changed exact state: {other:?}"),
        };
    assert_eq!(redelivered.enrolled().recovery_codes[0], recovery_code);
    let duplicate_commit = redelivered.clone();
    redelivered
        .commit()
        .expect("explicit commit settles the redelivered transaction");
    duplicate_commit
        .commit()
        .expect("duplicate exact commit is idempotent");
    assert!(matches!(
        myownmesh_core::custody::enrollment_transaction(network, delivered_transaction)
            .expect("query exact committed transaction"),
        myownmesh_core::custody::EnrollmentTransaction::Committed
    ));
    assert!(
        myownmesh_core::custody::is_enrolled(network),
        "explicitly committed enrollment remains after restart"
    );

    // Cleanup uses the material that was deliberately observable only in the
    // delivered branch. The prepared branch has no recovery material to use.
    myownmesh_core::custody::disable(network, recovery_code)
        .expect("disable delivered enrollment during test cleanup");
    assert!(!myownmesh_core::custody::is_enrolled(network));

    // A durable commit can itself be followed by process death before the
    // client receives its final acknowledgement. Querying the same identity
    // after restart must resolve that lost ACK as Committed.
    let (mut committed, mut committed_out) = spawn_child(home.path(), "commit-before-ack", network);
    let marker = read_marker(&mut committed_out);
    let committed_fields = marker
        .strip_prefix("DELIVERED ")
        .expect("commit-before-ack marker carries material and transaction");
    let (committed_code, committed_transaction) = committed_fields
        .rsplit_once(' ')
        .expect("commit-before-ack marker carries transaction identity");
    committed
        .stdin
        .as_mut()
        .expect("commit-before-ack child stdin")
        .write_all(b"COMMIT\n")
        .expect("request explicit child commit");
    assert_eq!(read_marker(&mut committed_out), "COMMITTED");
    committed
        .kill()
        .expect("hard-stop after durable commit before final ACK");
    committed.wait().expect("reap committed child");
    assert!(matches!(
        myownmesh_core::custody::enrollment_transaction(network, committed_transaction)
            .expect("query lost final ACK transaction"),
        myownmesh_core::custody::EnrollmentTransaction::Committed
    ));
    myownmesh_core::custody::disable(network, committed_code)
        .expect("disable committed enrollment during test cleanup");
    assert!(!myownmesh_core::custody::is_enrolled(network));

    // Commit and abort race on the same exact prepared transaction. The
    // settlement API returns the state actually established under its writer
    // guard, so both command replies must agree with the one durable winner.
    // A stale clone is then exercised against a successor to prove that the
    // exact transaction fence cannot settle the successor by network alone.
    let race_network = "r2-atomic-settlement";
    let provisional =
        myownmesh_core::custody::install_provisional_enroll(race_network, "r2-atomic")
            .expect("install atomic settlement enrollment");
    let race_transaction = provisional.transaction_id().to_owned();
    drop(provisional);
    let prepared =
        match myownmesh_core::custody::enrollment_transaction(race_network, &race_transaction)
            .expect("query atomic settlement transaction")
        {
            myownmesh_core::custody::EnrollmentTransaction::Prepared(prepared) => prepared,
            other => panic!("atomic settlement did not start Prepared: {other:?}"),
        };
    let stale = prepared.clone();
    let cleanup_code = prepared.enrolled().recovery_codes[0].clone();
    let commit_candidate = prepared.clone();
    let abort_candidate = prepared;
    let gate = std::sync::Arc::new(std::sync::Barrier::new(3));
    let commit_gate = std::sync::Arc::clone(&gate);
    let abort_gate = std::sync::Arc::clone(&gate);
    let commit_thread = std::thread::spawn(move || {
        commit_gate.wait();
        commit_candidate.settle(myownmesh_core::custody::EnrollmentSettlementRequest::Commit)
    });
    let abort_thread = std::thread::spawn(move || {
        abort_gate.wait();
        abort_candidate.settle(myownmesh_core::custody::EnrollmentSettlementRequest::Abort)
    });
    gate.wait();
    let commit_result = commit_thread
        .join()
        .expect("commit command does not panic")
        .expect("commit command reaches the atomic settlement API");
    let abort_result = abort_thread
        .join()
        .expect("abort command does not panic")
        .expect("abort command reaches the atomic settlement API");
    assert_eq!(
        commit_result, abort_result,
        "every racing reply reports the same exact durable winner"
    );
    let final_state =
        match myownmesh_core::custody::enrollment_transaction(race_network, &race_transaction)
            .expect("query atomic settlement winner")
        {
            myownmesh_core::custody::EnrollmentTransaction::Committed => {
                myownmesh_core::custody::EnrollmentSettlementResult::Committed
            }
            myownmesh_core::custody::EnrollmentTransaction::Absent => {
                myownmesh_core::custody::EnrollmentSettlementResult::Absent
            }
            myownmesh_core::custody::EnrollmentTransaction::Prepared(_) => {
                panic!("racing terminal commands left the transaction Prepared")
            }
        };
    assert_eq!(commit_result, final_state);

    if final_state == myownmesh_core::custody::EnrollmentSettlementResult::Committed {
        myownmesh_core::custody::disable(race_network, &cleanup_code)
            .expect("disable committed race winner");
    }
    let successor =
        myownmesh_core::custody::install_provisional_enroll(race_network, "r2-successor")
            .expect("install successor after exact race terminal");
    let successor_transaction = successor.transaction_id().to_owned();
    assert_eq!(
        stale
            .settle(myownmesh_core::custody::EnrollmentSettlementRequest::Commit)
            .expect("stale exact settlement is a no-op"),
        myownmesh_core::custody::EnrollmentSettlementResult::Absent
    );
    assert!(myownmesh_core::custody::is_enrolled(race_network));
    successor
        .abort()
        .expect("abort exact successor after stale settlement control");
    assert!(matches!(
        myownmesh_core::custody::enrollment_transaction(race_network, &successor_transaction)
            .expect("query successor after cleanup"),
        myownmesh_core::custody::EnrollmentTransaction::Absent
    ));
}

#[test]
fn v4_r2_cross_process_prepare_race_returns_one_exact_prepared_record() {
    let _test_env_guard = test_env_guard();
    let home = tempfile::tempdir().expect("isolated MyOwnMesh home");
    let network = format!("r2-prepare-race-{}", std::process::id());
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let (mut first, mut first_out) = spawn_child(home.path(), PREPARE_RACE_MODE, &network);
    let (mut second, mut second_out) = spawn_child(home.path(), PREPARE_RACE_MODE, &network);
    let first_caller_marker = read_marker(&mut first_out);
    assert!(
        first_caller_marker == "CALLER_READY",
        "first child reaches the pre-prepare barrier"
    );
    let second_caller_marker = read_marker(&mut second_out);
    assert!(
        second_caller_marker == "CALLER_READY",
        "second child reaches the pre-prepare barrier"
    );

    for child in [&mut first, &mut second] {
        child
            .stdin
            .as_mut()
            .expect("prepare-race child stdin")
            .write_all(b"GO\n")
            .expect("release prepare-race callers");
    }

    let first_marker = read_marker(&mut first_out);
    let second_marker = read_marker(&mut second_out);
    assert!(
        first_marker.starts_with("RESULT ") && second_marker.starts_with("RESULT "),
        "both children prepare only after the shared GO barrier"
    );

    fn parse_result(marker: &str) -> (&str, &str, &str, &str, Vec<&str>) {
        let fields: Vec<_> = marker.splitn(6, ' ').collect();
        assert_eq!(
            fields.len(),
            6,
            "RESULT carries complete enrollment material"
        );
        let codes: Vec<_> = fields[5].split(',').collect();
        assert!(!fields[2].is_empty(), "RESULT carries transaction identity");
        assert!(!fields[3].is_empty(), "RESULT carries the secret");
        assert!(!fields[4].is_empty(), "RESULT carries the otpauth URI");
        assert!(!codes.is_empty() && codes.iter().all(|code| !code.is_empty()));
        (fields[1], fields[2], fields[3], fields[4], codes)
    }

    let first_result = parse_result(&first_marker);
    let second_result = parse_result(&second_marker);
    assert_ne!(
        first_result.0, second_result.0,
        "the cross-process writer fence classifies Fresh and Existing distinctly"
    );
    assert!(
        matches!(
            (first_result.0, second_result.0),
            ("fresh", "existing") | ("existing", "fresh")
        ),
        "exactly one child inserts and exactly one recovers"
    );
    assert_eq!(
        first_result.1, second_result.1,
        "children report the same transaction"
    );
    assert_eq!(
        first_result.2, second_result.2,
        "children report the same secret"
    );
    assert_eq!(
        first_result.3, second_result.3,
        "children report the same otpauth URI"
    );
    assert_eq!(
        first_result.4, second_result.4,
        "children report the same recovery codes"
    );

    first.wait().expect("reap first prepare-race child");
    second.wait().expect("reap second prepare-race child");

    let prepared = myownmesh_core::custody::prepared_enrollments()
        .expect("enumerate durable prepared records");
    assert_eq!(
        prepared.len(),
        1,
        "the two children leave exactly one durable Prepared record"
    );
    let prepared = prepared.into_iter().next().expect("one prepared record");
    assert_eq!(prepared.network_id(), network);
    assert_eq!(prepared.transaction_id(), first_result.1);
    assert_eq!(prepared.enrolled().secret_b32, first_result.2);
    assert_eq!(prepared.enrolled().otpauth_uri, first_result.3);
    assert_eq!(
        prepared.enrolled().recovery_codes,
        first_result
            .4
            .iter()
            .map(|code| (*code).to_owned())
            .collect::<Vec<_>>()
    );
    prepared.abort().expect("explicitly abort race transaction");
    assert!(
        myownmesh_core::custody::prepared_enrollments()
            .expect("enumerate after explicit abort")
            .is_empty(),
        "explicit abort cleans the exact prepared record"
    );
}

#[test]
fn child_provisional_enrollment() {
    let (Some(mode), Some(network)) = (
        std::env::var_os(CHILD_MODE),
        std::env::var_os(CHILD_NETWORK),
    ) else {
        return;
    };
    let mode = mode.to_string_lossy();
    let network = network.to_string_lossy();

    if mode == PREPARE_RACE_MODE {
        println!("CALLER_READY");
        std::io::stdout()
            .flush()
            .expect("flush pre-prepare lifecycle marker");
        let mut go = String::new();
        std::io::stdin()
            .read_line(&mut go)
            .expect("parent prepare-race GO");
        assert_eq!(go.trim(), "GO");

        let preparation = myownmesh_core::custody::prepare_or_recover_provisional_enroll(
            &network,
            "r2-prepare-race",
        )
        .expect("child prepares or recovers the exact enrollment");
        let (state, transaction_id, enrolled) = match &preparation {
            myownmesh_core::custody::EnrollmentPreparation::Fresh(fresh) => {
                ("fresh", fresh.transaction_id(), fresh.enrolled())
            }
            myownmesh_core::custody::EnrollmentPreparation::Existing(existing) => {
                ("existing", existing.transaction_id(), existing.enrolled())
            }
        };
        println!(
            "RESULT {state} {transaction_id} {} {} {}",
            enrolled.secret_b32,
            enrolled.otpauth_uri,
            enrolled.recovery_codes.join(",")
        );
        std::io::stdout()
            .flush()
            .expect("flush prepare-race result marker");
        return;
    }

    let provisional = myownmesh_core::custody::install_provisional_enroll(&network, "r2-child")
        .expect("child installs provisional enrollment");
    assert!(
        myownmesh_core::custody::is_enrolled(&network),
        "prepared child must first prove durable lock exists"
    );

    if mode == "prepared" {
        println!("PREPARED {}", provisional.transaction_id());
    } else {
        let code = provisional
            .enrolled()
            .recovery_codes
            .first()
            .expect("enrollment has a recovery code");
        println!("DELIVERED {code} {}", provisional.transaction_id());
    }
    std::io::stdout()
        .flush()
        .expect("flush child lifecycle marker");

    let mut ack = String::new();
    std::io::stdin()
        .read_line(&mut ack)
        .expect("parent lifecycle acknowledgement");
    if (mode == "delivered" || mode == "commit-before-ack") && ack.trim() == "COMMIT" {
        provisional
            .commit()
            .expect("explicit child commit settles the exact transaction");
        println!("COMMITTED");
        std::io::stdout().flush().expect("flush kept marker");
        if mode == "commit-before-ack" {
            let mut final_ack = String::new();
            std::io::stdin()
                .read_line(&mut final_ack)
                .expect("parent final acknowledgement");
            if final_ack.trim() == "ACK" {
                println!("ACKED");
                std::io::stdout()
                    .flush()
                    .expect("flush final acknowledgement");
            }
        }
    }
}
