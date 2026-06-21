//! Regression test for the "reconnect strands peers" bug: a graceful
//! departure (`NetworkState::announce_departure`) must make the *other*
//! peer drop our session immediately, instead of waiting out the ~90 s
//! heartbeat timeout.
//!
//! Two peers handshake through an in-process `LocalBroker`; one announces a
//! departure; the other must emit `PeerEvent::Dropped { UserLeft }` within a
//! couple of seconds. Before the fix the engine had no way to *send* a
//! `leave` (only an intelligent relay synthesised one), so on the default
//! public relays a leave-then-rejoin — which is exactly what the app's
//! "reconnect" button does — left peers showing online-but-unconnectable
//! until the heartbeat backstop fired.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::events::DropReason;
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn fresh_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: "peer-leave-test".into(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        auto_approve: true,
    }
}

#[tokio::test]
async fn graceful_departure_drops_peer_without_waiting_for_heartbeat() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: set process-wide; leave-tests must not run in parallel against
    // the same env var (same constraint as two_peer_handshake).
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) =
        spawn_network(fresh_network("alice"), alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, _bob_driver) =
        spawn_network(fresh_network("bob"), bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Both sides connected.
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // Alice makes a deliberate exit. This is what the daemon now emits
    // before tearing a network down on remove / restart / shutdown.
    alice_state.announce_departure();

    // Bob must drop Alice promptly with `UserLeft`, not sit on a dead
    // session until the heartbeat timeout. A generous-but-far-below-90 s
    // window: the heartbeat backstop is HEARTBEAT_TIMEOUT_MS (30 s) +
    // WAKE_DETECTION_THRESHOLD_MS (60 s), so anything under that proves the
    // leave drove the drop, not the timeout.
    let reason = wait_for_drop(
        &mut bob_events,
        alice_id.public_id(),
        Duration::from_secs(5),
    )
    .await;
    assert_eq!(
        reason,
        DropReason::UserLeft,
        "a graceful departure should drop the peer as UserLeft"
    );
}

async fn wait_for_approval(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return;
            }
            _ => continue,
        }
    }
}

async fn wait_for_drop(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
    within: Duration,
) -> DropReason {
    let deadline = Instant::now() + within;
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerDropped for {peer_id} within {within:?}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Dropped {
                device_id, reason, ..
            }))) if device_id == peer_id => {
                return reason;
            }
            _ => continue,
        }
    }
}
