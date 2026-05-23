//! End-to-end engine integration test: two peers handshake
//! through an in-process LocalBroker, exchange a channel
//! message, and shut down cleanly.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{Channel, MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn fresh_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: format!("two-peer-test-{id}"),
        label: id.to_string(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        auto_approve: true,
    }
}

#[tokio::test]
async fn two_peers_handshake_and_exchange_channel_message() {
    // Each test gets its own MYOWNMESH_HOME so the roster /
    // identity anchor never collides with another test or with a
    // developer's real config.
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: tests run with single-threaded MYOWNMESH_HOME
    // mutation, but this is set process-wide. Different tests
    // should not run in parallel against the same env var.
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    // Same wire-level network id, same broker — but two distinct
    // identities and two engines.
    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let mut alice_cfg = fresh_network("alice");
    let mut bob_cfg = fresh_network("bob");
    // Both peers join the same wire-level network.
    alice_cfg.network_id = "two-peer-handshake".into();
    bob_cfg.network_id = "two-peer-handshake".into();

    let (alice_state, _alice_driver) =
        spawn_network(alice_cfg, alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
        .await
        .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Wait until both peers see PeerApproved for each other.
    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // Type-safe channel send.
    let alice_chan: Channel<String> = Channel::new("greetings".into(), alice_state.clone());
    let bob_chan: Channel<String> = Channel::new("greetings".into(), bob_state.clone());
    let mut bob_sub = bob_chan.subscribe();

    alice_chan
        .send_to(bob_id.public_id(), &"hello from alice".to_string())
        .await
        .expect("alice send");

    let deadline = Instant::now() + Duration::from_secs(10);
    let msg = loop {
        if Instant::now() > deadline {
            panic!("bob did not receive the channel message");
        }
        if let Ok(Some(Ok(msg))) =
            tokio::time::timeout(Duration::from_millis(100), bob_sub.recv()).await
        {
            break msg;
        }
    };
    assert_eq!(msg.from, alice_id.public_id());
    assert_eq!(msg.body, "hello from alice");

    // Reverse direction.
    let mut alice_sub = alice_chan.subscribe();
    bob_chan
        .send_to(alice_id.public_id(), &"hi back".to_string())
        .await
        .expect("bob send");
    let deadline = Instant::now() + Duration::from_secs(10);
    let msg = loop {
        if Instant::now() > deadline {
            panic!("alice did not receive the reply");
        }
        if let Ok(Some(Ok(msg))) =
            tokio::time::timeout(Duration::from_millis(100), alice_sub.recv()).await
        {
            break msg;
        }
    };
    assert_eq!(msg.from, bob_id.public_id());
    assert_eq!(msg.body, "hi back");
}

async fn wait_for_approval(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerApproved for {peer_id}");
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return;
            }
            _ => continue,
        }
    }
}
