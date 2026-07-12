//! Regression test for the "refresh button strands the peer" bug: the GUI's
//! reconnect / refresh control used to leave-and-rejoin the network, which
//! announces a departure (`Leave`) and tears the peer's session down on the
//! *other* side. The in-place reconnect (`NetworkState::reconnect`) must
//! instead refresh the transport — renegotiate ICE — **without** announcing a
//! leave, so a refresh on one side never drops the peer on the other.
//!
//! This is the dual of `peer_leave.rs`: there a departure *must* drop the peer
//! promptly; here a reconnect must *not* drop it at all (no `UserLeft`).

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
        network_id: "reconnect-in-place-test".into(),
        label: id.to_string(),
        kind: Default::default(),
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
async fn in_place_reconnect_does_not_announce_a_leave() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: set process-wide; leave/reconnect tests must not run in parallel
    // against the same env var (same constraint as two_peer_handshake).
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

    // Alice hits the refresh control: an in-place reconnect of every peer.
    // Unlike a network remove/re-add, this announces NO departure.
    alice_state.reconnect(None);

    // Bob must NOT see a `UserLeft` drop for Alice — that's the signal a
    // *leave* would have produced (and exactly what stranded the peer before).
    // A generous window: well past the LEAVE flush + broker round-trip, so if a
    // leave were going out it would have landed.
    assert!(
        !saw_user_left(
            &mut bob_events,
            alice_id.public_id(),
            Duration::from_secs(3)
        )
        .await,
        "an in-place reconnect must not announce a leave — Bob should never see UserLeft"
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

/// Drain events for `within`, returning true if a `Dropped { UserLeft }` for
/// `peer_id` appeared. Recoverable churn (e.g. a transient `IceFailed` from the
/// renegotiation) is ignored — only the leave signal fails the test.
async fn saw_user_left(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
    within: Duration,
) -> bool {
    let deadline = Instant::now() + within;
    loop {
        if Instant::now() > deadline {
            return false;
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Dropped {
                device_id, reason, ..
            }))) if device_id == peer_id && reason == DropReason::UserLeft => {
                return true;
            }
            _ => continue,
        }
    }
}
