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

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::state::NetworkState;
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::NetworkKind;
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

const CHANNEL: &str = "area-probe";
const NETWORK_ID: &str = "silent-area-scale";

fn silent_cfg(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: NETWORK_ID.into(),
        label: id.to_string(),
        kind: NetworkKind::Silent,
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
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

fn authenticated(state: &Arc<NetworkState>, peer: &str) -> bool {
    state
        .peer_info(peer)
        .map(|p| p.authenticated)
        .unwrap_or(false)
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
    let transport = Transport::new().expect("transport");

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
            !authenticated(&spoke.state, &operator.id),
            "member-{i} authenticated to the operator without a deliberate dial"
        );
        for (j, other) in spokes.iter().enumerate() {
            if i != j {
                assert!(
                    !authenticated(&spoke.state, &other.id),
                    "member-{i} authenticated to member-{j} on a silent mesh"
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
        let deadline = t0 + Duration::from_secs(60);
        let mut next_dial = Instant::now();
        loop {
            if Instant::now() >= next_dial {
                operator.state.connect_peer(&spoke.id);
                next_dial = Instant::now() + Duration::from_secs(4);
            }
            if authenticated(&operator.state, &spoke.id)
                && authenticated(&spoke.state, &operator.id)
            {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "operator dial to {} did not come up in 60s",
                spoke.id
            );
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        dial_ms.push(t0.elapsed().as_secs_f64() * 1000.0);
    }
    report("dial connect→session", dial_ms);

    // ---- the area shape holds under N sessions --------------------------
    for (i, spoke) in spokes.iter().enumerate() {
        for (j, other) in spokes.iter().enumerate() {
            if i != j {
                assert!(
                    !authenticated(&spoke.state, &other.id),
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
        let mut rx = spoke.state.subscribe_channel(CHANNEL);
        let echo_state = spoke.state.clone();
        let operator_id = operator.id.clone();
        tokio::spawn(async move {
            while let Ok(frame) = rx.recv().await {
                let _ = echo_state
                    .send_channel_frame(&operator_id, CHANNEL, frame.payload)
                    .await;
            }
        });
    }
    let mut echo_rx = operator.state.subscribe_channel(CHANNEL);
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
                    Ok(Ok(frame)) if frame.payload == payload => break,
                    Ok(Ok(_)) => {} // stale/other frame — keep draining
                    Ok(Err(e)) => panic!("operator echo stream closed: {e}"),
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
