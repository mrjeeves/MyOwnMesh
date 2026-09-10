#![cfg(feature = "transport-lab")]

//! A silent area at scale, measured: one operator node and N member
//! boxes on a **Silent** mesh, over the real engine + WebRTC transport
//! (in-process `LocalBroker` signaling, loopback ICE). This is the
//! hub-and-quiet-spokes shape any embedder builds a help desk, kiosk
//! fleet, or appliance estate on.
//!
//! Asserts the Silent contract end to end:
//!   * members DISCOVER nothing actionable — they sit Sighted-only,
//!     never authenticate to anyone on their own, and never see each
//!     other;
//!   * every member still surfaces to the operator (presence), and a
//!     deliberate `connect_peer` from the operator — and only that —
//!     brings a session up;
//!   * after N sessions, each member is connected to exactly one peer:
//!     the operator. No spoke↔spoke sessions exist.
//!
//! And measures what the user actually feels:
//!   * discovery time (attach → the operator sees all N),
//!   * deliberate-dial latency (connect_peer → both sides authenticated),
//!   * app-frame round trip through the established session,
//!
//! printed as p50/p95/max with the per-lane traffic counters, so two
//! builds (or two topologies) can be compared honestly:
//!
//! ```text
//! cargo test --test silent_area_scale -- --nocapture
//! SILENT_SCALE_SPOKES=32 cargo test --test silent_area_scale -- --ignored --nocapture
//! ```

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, NetworkKind, SignalingConfig, TopologyMode};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::engine::transport_lab::NetworkState;
use myownmesh_core::engine::transport_lab::{attach_local, channel, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

const CHANNEL: &str = "area-probe";
const NETWORK_ID: &str = "silent-area-scale";
const DIAL_TIMEOUT: Duration = Duration::from_secs(60);
const REDIAL_INTERVAL: Duration = Duration::from_secs(4);
const ADMISSION_POLL_INTERVAL: Duration = Duration::from_millis(25);

fn silent_cfg(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: NETWORK_ID.into(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: NetworkKind::Silent,
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
        auto_approve: true,
    }
}

struct Node {
    state: Arc<NetworkState>,
    id: String,
    // Drivers are kept alive for the run; dropping them stops the engine.
    _driver: tokio::task::JoinHandle<()>,
}

async fn spawn_node(label: &str, transport: &Transport, broker: &LocalBroker) -> Node {
    let identity = Arc::new(Identity::ephemeral());
    let id = identity.public_id().to_string();
    let (state, driver) = spawn_network(silent_cfg(label), identity, transport.clone())
        .await
        .unwrap_or_else(|e| panic!("{label} engine: {e}"));
    attach_local(&state, broker);
    Node {
        state,
        id,
        _driver: driver,
    }
}

fn admitted(state: &Arc<NetworkState>, peer: &str) -> bool {
    state.peer_info(peer).is_some_and(|peer| {
        peer.authenticated && matches!(peer.status, PeerStatus::Active | PeerStatus::Shelved)
    })
}

/// One side's view of a peer, or the absence of a record for it.
///
/// Read from the existing `PeerInfo` snapshot; nothing new is exposed. Called
/// only from the failure path, so an ordinary passing run never evaluates it.
///
/// **These describe whichever peer record exists under this device id at the
/// instant of the read, and nothing else.** A record that was rebuilt has
/// already replaced the one before it, so `hello_sent`, `local_approve_sent`,
/// `remote_approve_seen` and `selected_pair` carry no evidence about an attempt
/// that was abandoned first and must not be read as if they did.
fn peer_state(state: &Arc<NetworkState>, peer: &str) -> String {
    match state.peer_info(peer) {
        Some(info) => format!(
            "authenticated={} status={:?} local_shelved={} remote_shelved={} hello_sent={} local_approve_sent={} remote_approve_seen={} selected_pair={}",
            info.authenticated,
            info.status,
            info.local_shelved,
            info.remote_shelved,
            info.verification_code_sent.is_some(),
            info.local_approve_sent,
            info.remote_approve_seen,
            info.selected_pair.is_some(),
        ),
        None => "no peer record".to_string(),
    }
}

/// Both sides' admission state for every member, plus the provider's own
/// capacity, at the instant a wait gave up.
///
/// Built only on a failing path, so a passing run pays nothing for it. Both
/// directions are reported because `admitted` is a conjunction over them: a
/// member the operator still holds but which no longer holds the operator is a
/// different fault from one that never came up. The two provider reports
/// separate a refusal on capacity from a refusal with capacity to spare.
fn admission_diagnostic(operator: &Node, spokes: &[Node], transport: &Transport) -> String {
    use std::fmt::Write as _;
    let mut out = String::new();
    for (i, spoke) in spokes.iter().enumerate() {
        let _ = write!(
            out,
            "\n  member-{i}: operator sees [{}] · member sees [{}]",
            peer_state(&operator.state, &spoke.id),
            peer_state(&spoke.state, &operator.id),
        );
    }
    let _ = write!(
        out,
        "\n  process resources: {:?}\n  mesh resources: {:?}",
        transport.connector_resource_report(),
        transport.mesh_connector_resource_report(),
    );
    out
}

async fn converge_all_operator_sessions(operator: &Node, spokes: &[Node], transport: &Transport) {
    let deadline = Instant::now() + DIAL_TIMEOUT;
    let mut next_dial = Instant::now();
    loop {
        let admitted_count = spokes
            .iter()
            .filter(|spoke| {
                admitted(&operator.state, &spoke.id) && admitted(&spoke.state, &operator.id)
            })
            .count();
        if admitted_count == spokes.len() {
            return;
        }
        if Instant::now() >= next_dial {
            for spoke in spokes.iter().filter(|spoke| {
                !admitted(&operator.state, &spoke.id) || !admitted(&spoke.state, &operator.id)
            }) {
                operator.state.connect_peer(&spoke.id);
            }
            next_dial = Instant::now() + REDIAL_INTERVAL;
        }
        assert!(
            Instant::now() < deadline,
            "only {admitted_count}/{} operator sessions were concurrently admitted before the existing dial deadline{}",
            spokes.len(),
            admission_diagnostic(operator, spokes, transport)
        );
        tokio::time::sleep(ADMISSION_POLL_INTERVAL).await;
    }
}

fn percentile(sorted_ms: &[f64], p: f64) -> f64 {
    if sorted_ms.is_empty() {
        return 0.0;
    }
    let idx = ((sorted_ms.len() as f64 - 1.0) * p).round() as usize;
    sorted_ms[idx.min(sorted_ms.len() - 1)]
}

fn report(label: &str, mut samples_ms: Vec<f64>) {
    samples_ms.sort_by(|a, b| a.partial_cmp(b).expect("finite latencies"));
    println!(
        "  {label}: n={} p50={:.1}ms p95={:.1}ms max={:.1}ms",
        samples_ms.len(),
        percentile(&samples_ms, 0.50),
        percentile(&samples_ms, 0.95),
        percentile(&samples_ms, 1.00),
    );
}

async fn run_area(n_spokes: usize) {
    let started = Instant::now();
    let broker = LocalBroker::new();
    let transport = support::test_transport();

    let operator = spawn_node("operator", &transport, &broker).await;
    let mut spokes = Vec::with_capacity(n_spokes);
    for i in 0..n_spokes {
        spokes.push(spawn_node(&format!("member-{i}"), &transport, &broker).await);
    }
    println!(
        "silent-area: 1 operator + {n_spokes} members spawned in {:.1}s",
        started.elapsed().as_secs_f64()
    );

    // ---- discovery: every member surfaces on the operator side ---------
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(30);
    loop {
        let seen = spokes
            .iter()
            .filter(|s| operator.state.peer_info(&s.id).is_some())
            .count();
        if seen == n_spokes {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "operator discovered only {seen}/{n_spokes} members in 30s"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    println!(
        "  discovery: operator sees all {n_spokes} members in {:.2}s",
        t0.elapsed().as_secs_f64()
    );

    // ---- silence: members connect to nobody on their own ---------------
    tokio::time::sleep(Duration::from_secs(3)).await;
    for (i, spoke) in spokes.iter().enumerate() {
        assert!(
            !admitted(&spoke.state, &operator.id),
            "member-{i} was admitted to the operator without a deliberate dial"
        );
        for (j, other) in spokes.iter().enumerate() {
            if i != j {
                assert!(
                    !admitted(&spoke.state, &other.id),
                    "member-{i} was admitted to member-{j} on a silent mesh"
                );
            }
        }
    }
    println!("  silence: no member connected to anyone unprompted ✓");

    // ---- deliberate dials: the operator opens each session -------------------
    // Sequential, so each latency sample is a clean single-connection
    // measurement rather than a thundering herd of concurrent ICE runs.
    // connect_peer is idempotent; the slow re-dial cadence recovers an
    // offer that gathered slowly on a busy runner (Windows loopback ICE
    // is markedly slower than Linux/macOS).
    let mut dial_ms = Vec::with_capacity(n_spokes);
    for spoke in &spokes {
        let t0 = Instant::now();
        let deadline = t0 + DIAL_TIMEOUT;
        let mut next_dial = Instant::now();
        loop {
            if Instant::now() >= next_dial {
                operator.state.connect_peer(&spoke.id);
                next_dial = Instant::now() + REDIAL_INTERVAL;
            }
            if admitted(&operator.state, &spoke.id) && admitted(&spoke.state, &operator.id) {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "operator dial to {} did not come up in 60s{}",
                spoke.id,
                admission_diagnostic(&operator, &spokes, &transport)
            );
            tokio::time::sleep(ADMISSION_POLL_INTERVAL).await;
        }
        dial_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    report("dial connect→session", dial_ms);

    // Sequential latency sampling can leave an early session stale while a
    // slow runner brings up later sessions. Re-drive only missing pairs and
    // require one simultaneous admitted snapshot before testing N-session
    // shape or application delivery.
    converge_all_operator_sessions(&operator, &spokes, &transport).await;

    // ---- the area shape holds under N sessions --------------------------
    for (i, spoke) in spokes.iter().enumerate() {
        assert!(
            admitted(&operator.state, &spoke.id) && admitted(&spoke.state, &operator.id),
            "member-{i} is not mutually admitted to the operator"
        );
        for (j, other) in spokes.iter().enumerate() {
            if i != j {
                assert!(
                    !admitted(&spoke.state, &other.id),
                    "member-{i} ↔ member-{j} session appeared — spokes must only see the operator"
                );
            }
        }
    }
    println!("  shape: every member holds exactly one session (the operator) ✓");

    // ---- app-frame RTT through each session ------------------------------
    // Every member echoes probe frames back; the operator measures the round
    // trip. This is the Phase B acked path end to end: queue → wire →
    // deliver → echo → wire → deliver.
    for spoke in &spokes {
        // One resource-backed mailbox per member, held by its echo task for the
        // run. `recv` separates the two endings the old receiver merged: `None`
        // is the channel going away with the network, `Err` is one frame that
        // did not decode.
        let mut rx = channel::<serde_json::Value>(CHANNEL.to_owned(), spoke.state.clone())
            .subscribe()
            .expect("member subscription admitted");
        let echo_state = spoke.state.clone();
        let operator_id = operator.id.clone();
        let member = spoke.id.clone();
        tokio::spawn(async move {
            while let Some(next) = rx.recv().await {
                match next {
                    Ok(frame) => {
                        let _ = echo_state
                            .send_channel_frame(&operator_id, CHANNEL, frame.body().clone())
                            .await;
                    }
                    // Reported and survivable, which is the truthful shape here.
                    // A panic would be swallowed by a `JoinHandle` nobody awaits
                    // and ending the loop would stop every later echo, so both
                    // would reach the operator as nothing but a timeout. Saying
                    // it keeps the real fault visible while the run still
                    // measures the sessions that are working.
                    Err(e) => eprintln!("member {member} dropped an undecodable probe frame: {e}"),
                }
            }
        });
    }
    let mut echo_rx = channel::<serde_json::Value>(CHANNEL.to_owned(), operator.state.clone())
        .subscribe()
        .expect("operator subscription admitted");
    let pings_per_spoke: usize = 10;
    let mut rtt_ms = Vec::with_capacity(n_spokes * pings_per_spoke);
    for (i, spoke) in spokes.iter().enumerate() {
        for seq in 0..pings_per_spoke {
            let payload = serde_json::json!({ "probe": i, "seq": seq });
            let t0 = Instant::now();
            operator
                .state
                .send_channel_frame(&spoke.id, CHANNEL, payload.clone())
                .await
                .unwrap_or_else(|e| panic!("probe send to member-{i}: {e}"));
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                let remaining = deadline.saturating_duration_since(Instant::now());
                assert!(
                    remaining > Duration::ZERO,
                    "echo from member-{i} seq {seq} never arrived"
                );
                match tokio::time::timeout(remaining, echo_rx.recv()).await {
                    Ok(Some(Ok(frame))) if frame.body() == &payload => break,
                    Ok(Some(Ok(_))) => {} // stale/other frame — keep draining
                    // The old receiver reported both of these as "stream
                    // closed". They are different faults and only one of them
                    // has an error to name.
                    Ok(Some(Err(e))) => panic!("operator echo frame did not decode: {e}"),
                    Ok(None) => panic!(
                        "operator echo channel closed while member-{i} seq {seq} was outstanding"
                    ),
                    Err(_) => panic!("echo from member-{i} seq {seq} timed out"),
                }
            }
            rtt_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
        }
    }
    report("app-frame RTT", rtt_ms);

    // ---- counters: the observability the status surface reports ---------
    let t = operator.state.traffic_snapshot();
    println!(
        "  operator counters: app tx {}f/{}B rx {}f/{}B · control tx {}f rx {}f · announces rx {}",
        t.app_tx.frames,
        t.app_tx.bytes,
        t.app_rx.frames,
        t.app_rx.bytes,
        t.control_tx.frames,
        t.control_rx.frames,
        t.announces_rx,
    );
    println!(
        "silent-area: full run ({n_spokes} members) in {:.1}s",
        started.elapsed().as_secs_f64()
    );
}

/// Shared `MYOWNMESH_HOME` for the whole test binary. SAFETY: tests that
/// mutate this env var must not run concurrently with tests reading it in
/// another home — within this binary both tests use the same shared home,
/// and per-node state is keyed by ephemeral identities so runs don't
/// collide on disk.
fn shared_home() {
    use std::sync::OnceLock;
    static HOME: OnceLock<tempfile::TempDir> = OnceLock::new();
    let dir = HOME.get_or_init(|| tempfile::tempdir().expect("tempdir"));
    std::env::set_var("MYOWNMESH_HOME", dir.path());
}

/// The default-run smoke: small enough for CI, still the full shape.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_area_smoke() {
    shared_home();
    run_area(5).await;
}

/// The soak: `SILENT_SCALE_SPOKES` members (default 24). Run on demand:
/// `SILENT_SCALE_SPOKES=32 cargo test --test silent_area_scale -- --ignored --nocapture`
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "scale soak — run on demand with --ignored --nocapture"]
async fn silent_area_soak() {
    shared_home();
    let n = std::env::var("SILENT_SCALE_SPOKES")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(24);
    run_area(n).await;
}
mod support;
