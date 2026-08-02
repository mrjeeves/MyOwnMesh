//! Regression test: **a node must not report a link ACTIVE off its own
//! approval.**
//!
//! Admission is bilateral by design — `authenticated && local_approve_sent &&
//! remote_approve_seen` — and the receiving end enforces it strictly: an
//! endpoint with an open data channel but an unfinished approval may drive
//! only the handshake itself, and every application frame is dropped at the
//! gate.
//!
//! `send_local_approve` used to complete by calling `on_approve`, whose first
//! act is to latch `remote_approve_seen`. So approving a peer also recorded
//! that the peer had approved *us*, and one side's half of the handshake was
//! enough to go ACTIVE.
//!
//! That is invisible while both ends roster each other, and silently wrong the
//! moment they don't — which is the normal state of a closed network, where
//! `auto_approve` is false and the roster is the only way in. The un-rostered
//! side never approves back, so it sits at PendingApproval discarding
//! everything; the other side calls the link ACTIVE, gossips to it, and accepts
//! sends for it. The operator gets a healthy-looking peer and a tunnel that
//! answers nothing, with no error at either end. (Found the long way round: a
//! KVM that never pre-rostered its owner, whose app showed it connected while
//! its daemon logged "dropping pre-admission frame" until the idle channel
//! died, every forty seconds, forever.)
//!
//! Alice rosters Bob. Bob does not roster Alice. Nobody may reach ACTIVE.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

/// A CLOSED network's shape: `auto_approve` off, so the roster is the only
/// thing that admits a peer.
fn closed_network(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: "one-sided-roster".to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

#[tokio::test]
async fn one_sided_roster_never_reaches_active() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: process-wide, as in the sibling engine integration tests — they
    // are not run concurrently against the same var.
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) =
        spawn_network(closed_network("alice"), alice_id.clone(), transport.clone())
            .await
            .expect("alice engine");
    let (bob_state, _bob_driver) =
        spawn_network(closed_network("bob"), bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");

    // The asymmetry under test: Alice knows Bob, Bob has never heard of Alice.
    alice_state
        .approve_roster(bob_id.public_id(), "bob")
        .await
        .expect("alice rosters bob");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    // Both ends must actually complete the signed handshake, or this test
    // would pass on a connection that never happened.
    wait_for_authenticated(&mut alice_events, bob_id.public_id()).await;
    wait_for_authenticated(&mut bob_events, alice_id.public_id()).await;

    // Alice approved Bob (he's rostered). Bob will never approve Alice. Give
    // the wrong answer every chance to appear.
    tokio::time::sleep(Duration::from_secs(2)).await;

    assert_status_not_active(&alice_state, bob_id.public_id(), "alice");
    assert_status_not_active(&bob_state, alice_id.public_id(), "bob");

    assert!(
        !saw_approved(&mut alice_events, bob_id.public_id()),
        "alice announced Bob as approved without his approve — the link she \
         would then treat as carrying traffic is one Bob drops at the \
         admission gate"
    );
}

fn assert_status_not_active(
    state: &Arc<myownmesh_core::engine::state::NetworkState>,
    peer_id: &str,
    who: &str,
) {
    let pubkey = myownmesh_core::signing::pubkey_part(peer_id);
    for p in state.peer_snapshot() {
        if myownmesh_core::signing::pubkey_part(&p.device_id) != pubkey {
            continue;
        }
        assert!(
            !matches!(p.status, PeerStatus::Active | PeerStatus::Shelved),
            "{who} reached {:?} with a peer that never approved back",
            p.status
        );
        return;
    }
    panic!("{who} has no peer entry for {peer_id} — the handshake did not run");
}

/// Drain anything already queued and report whether an Approved event for
/// `peer_id` is among it.
fn saw_approved(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) -> bool {
    while let Ok(ev) = rx.try_recv() {
        if let MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) = ev {
            if device_id == peer_id {
                return true;
            }
        }
    }
    false
}

async fn wait_for_authenticated(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(20);
    loop {
        if Instant::now() > deadline {
            panic!("never saw the handshake authenticate {peer_id}");
        }
        match tokio::time::timeout(Duration::from_millis(200), rx.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer_id =>
            {
                return;
            }
            _ => continue,
        }
    }
}
