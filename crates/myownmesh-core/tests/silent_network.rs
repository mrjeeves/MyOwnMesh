//! End-to-end engine integration test for a **Silent** network: two
//! co-present peers on a Silent mesh discover each other (`Sighted`) but do
//! NOT auto-connect — no handshake runs until one side issues an explicit
//! `connect_peer`, after which both reach `Approved`. Exercises the real
//! engine + WebRTC transport through an in-process `LocalBroker`, mirroring
//! `two_peer_handshake.rs`.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, NetworkKind, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn silent_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: "silent-two-peer".into(),
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

#[tokio::test]
async fn silent_peers_are_sighted_but_do_not_connect_until_dialed() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: single-threaded MYOWNMESH_HOME mutation per test; do not run
    // tests that mutate this env var in parallel.
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) =
        spawn_network(silent_network("alice"), alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, _bob_driver) =
        spawn_network(silent_network("bob"), bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Both peers must DISCOVER each other (Sighted) but must NOT auto-advance to
    // Authenticated/Approved on their own — that is the whole point of Silent.
    // Watch a fixed window: require Sighted, panic on any premature auth.
    let bob_pub = bob_id.public_id().to_string();
    let alice_pub = alice_id.public_id().to_string();
    tokio::join!(
        expect_sighted_but_not_authenticated(&mut alice_events, &bob_pub),
        expect_sighted_but_not_authenticated(&mut bob_events, &alice_pub),
    );

    // Sanity: the engine tracked the peer but opened no session (the peer sits
    // at Sighted, not authenticated).
    let bob_seen = alice_state
        .peer_info(&bob_pub)
        .expect("alice tracks bob as discovered");
    assert!(
        !bob_seen.authenticated,
        "a silent-network peer must not authenticate on its own"
    );

    // Fresh receivers for the post-dial phase (the window above drained events).
    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    // Deliberate dial of exactly bob. Only now does a connection form; bob's
    // Silent node answers the inbound offer (that path is not gated), so both
    // sides handshake and — with auto_approve — reach Approved. We re-issue the
    // dial on a slow cadence: connect_peer is idempotent once a session exists,
    // but a periodic re-dial recovers a first offer that gathered slowly or was
    // dropped on a busy CI runner (Windows ICE over loopback is markedly slower
    // than Linux/macOS). Both sides must still reach Approved for the test to pass.
    let deadline = Instant::now() + Duration::from_secs(60);
    let mut alice_ok = false;
    let mut bob_ok = false;
    let mut next_dial = Instant::now();
    while !(alice_ok && bob_ok) {
        assert!(
            Instant::now() <= deadline,
            "silent dial did not reach mutual Approved in time (alice_ok={alice_ok}, bob_ok={bob_ok})"
        );
        if Instant::now() >= next_dial {
            alice_state.connect_peer(&bob_pub);
            next_dial = Instant::now() + Duration::from_secs(4);
        }
        tokio::select! {
            r = tokio::time::timeout(Duration::from_millis(200), alice_events.recv()) => {
                if let Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. }))) = r {
                    alice_ok |= device_id == bob_pub;
                }
            }
            r = tokio::time::timeout(Duration::from_millis(200), bob_events.recv()) => {
                if let Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. }))) = r {
                    bob_ok |= device_id == alice_pub;
                }
            }
        }
    }
}

/// Collect events for a fixed window. Require a `Sighted` for `peer`, and fail
/// if the peer reaches `Authenticated`/`Approved` — proof the Silent network
/// discovered the peer without dialing it.
async fn expect_sighted_but_not_authenticated(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut saw_sighted = false;
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Sighted { device_id, .. }))) if device_id == peer => {
                saw_sighted = true;
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer =>
            {
                panic!("silent network auto-authenticated {peer} without a deliberate dial");
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. }))) if device_id == peer => {
                panic!("silent network auto-approved {peer} without a deliberate dial");
            }
            _ => {}
        }
    }
    assert!(
        saw_sighted,
        "expected to discover {peer} via Sighted on a silent network"
    );
}
