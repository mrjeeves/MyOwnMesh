#![cfg(feature = "transport-lab")]

//! End-to-end engine integration test: two peers handshake
//! through an in-process LocalBroker, exchange a channel
//! message, and shut down cleanly.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, RoutingPolicyConfig, SignalingConfig, TopologyMode,
};
use myownmesh_core::engine::transport_lab::{attach_local, channel, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::{Channel, MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn fresh_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: format!("two-peer-test-{id}"),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: Default::default(),
        semantic_policy: Default::default(),
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        tree: None,
        signaling: SignalingConfig::default(),
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

fn fresh_network_with_auto_approve(id: &str, auto_approve: bool) -> NetworkConfig {
    let mut config = fresh_network(id);
    config.auto_approve = auto_approve;
    config
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
    let transport = support::test_transport();

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
    let alice_chan: Channel<String> = channel("greetings".into(), alice_state.clone());
    let bob_chan: Channel<String> = channel("greetings".into(), bob_state.clone());
    let mut bob_sub = bob_chan.subscribe().expect("bob subscription admitted");

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
    assert_eq!(msg.from(), alice_id.public_id());
    assert_eq!(msg.body(), &"hello from alice");

    // Reverse direction.
    let mut alice_sub = alice_chan.subscribe().expect("alice subscription admitted");
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
    assert_eq!(msg.from(), bob_id.public_id());
    assert_eq!(msg.body(), &"hi back");
}

#[tokio::test]
async fn application_payload_is_refused_before_approval_then_delivered_after_approval() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: this test uses an isolated home and does not run concurrently
    // with another test that mutates MYOWNMESH_HOME.
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = support::test_transport();
    let pending_alice = Arc::new(Identity::ephemeral());
    let pending_bob = Arc::new(Identity::ephemeral());
    let mut pending_alice_cfg = fresh_network_with_auto_approve("pending-alice", false);
    let mut pending_bob_cfg = fresh_network_with_auto_approve("pending-bob", false);
    pending_alice_cfg.network_id = "two-peer-pre-approval".into();
    pending_bob_cfg.network_id = "two-peer-pre-approval".into();

    let (pending_alice_state, _pending_alice_driver) =
        spawn_network(pending_alice_cfg, pending_alice.clone(), transport.clone())
            .await
            .expect("pending alice engine");
    let (pending_bob_state, _pending_bob_driver) =
        spawn_network(pending_bob_cfg, pending_bob.clone(), transport.clone())
            .await
            .expect("pending bob engine");
    let mut pending_alice_events = pending_alice_state.events_tx.subscribe();
    attach_local(&pending_alice_state, &broker);
    attach_local(&pending_bob_state, &broker);

    let pending_alice_chan: Channel<String> =
        channel("pre-approval".into(), pending_alice_state.clone());
    let pending_bob_chan: Channel<String> =
        channel("pre-approval".into(), pending_bob_state.clone());
    let mut pending_bob_sub = pending_bob_chan
        .subscribe()
        .expect("pending subscription admitted locally");

    wait_for_authenticated(&mut pending_alice_events, pending_bob.public_id()).await;

    let refusal = pending_alice_chan
        .send_to(pending_bob.public_id(), &"must not cross".to_string())
        .await
        .expect_err("application traffic before approval must be refused");
    assert!(
        match &refusal {
            myownmesh_core::ChannelError::Transport(message) =>
                message.contains("no live promoted session"),
            _ => false,
        },
        "pre-approval refusal must preserve the typed transport admission error: {refusal:?}"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), pending_bob_sub.recv())
            .await
            .is_err(),
        "a refused pre-approval payload must not reach the subscriber"
    );

    // The public approval control is intentionally not a raw state mutation.
    // A second real pair with the explicit auto-approval configuration proves
    // the positive half of the same production channel contract after signed
    // authentication and bilateral approval have completed.
    let approved_alice = Arc::new(Identity::ephemeral());
    let approved_bob = Arc::new(Identity::ephemeral());
    let mut approved_alice_cfg = fresh_network_with_auto_approve("approved-alice", true);
    let mut approved_bob_cfg = fresh_network_with_auto_approve("approved-bob", true);
    approved_alice_cfg.network_id = "two-peer-post-approval".into();
    approved_bob_cfg.network_id = "two-peer-post-approval".into();
    let (approved_alice_state, _approved_alice_driver) = spawn_network(
        approved_alice_cfg,
        approved_alice.clone(),
        transport.clone(),
    )
    .await
    .expect("approved alice engine");
    let (approved_bob_state, _approved_bob_driver) =
        spawn_network(approved_bob_cfg, approved_bob.clone(), transport)
            .await
            .expect("approved bob engine");
    let mut approved_alice_events = approved_alice_state.events_tx.subscribe();
    let mut approved_bob_events = approved_bob_state.events_tx.subscribe();
    attach_local(&approved_alice_state, &broker);
    attach_local(&approved_bob_state, &broker);
    wait_for_authenticated_and_approval(&mut approved_alice_events, approved_bob.public_id()).await;
    wait_for_authenticated_and_approval(&mut approved_bob_events, approved_alice.public_id()).await;

    let approved_alice_chan: Channel<String> =
        channel("post-approval".into(), approved_alice_state.clone());
    let approved_bob_chan: Channel<String> =
        channel("post-approval".into(), approved_bob_state.clone());
    let mut approved_bob_sub = approved_bob_chan
        .subscribe()
        .expect("approved subscription admitted locally");
    approved_alice_chan
        .send_to(approved_bob.public_id(), &"approved payload".to_string())
        .await
        .expect("approved application send");
    let delivered = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            if let Some(Ok(message)) = approved_bob_sub.recv().await {
                break message;
            }
        }
    })
    .await
    .expect("approved payload delivery");
    assert_eq!(delivered.from(), approved_alice.public_id());
    assert_eq!(delivered.body(), &"approved payload");
}

async fn wait_for_authenticated(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw PeerAuthenticated for {peer_id}");
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        if matches!(
            next,
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer_id
        ) {
            return;
        }
    }
}

async fn wait_for_authenticated_and_approval(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut authenticated = false;
    loop {
        if Instant::now() > deadline {
            panic!("never saw signed authentication and approval for {peer_id}");
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer_id =>
            {
                authenticated = true
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                assert!(
                    authenticated,
                    "PeerApproved must follow the signed PeerAuthenticated event"
                );
                return;
            }
            _ => {}
        }
    }
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
mod support;
