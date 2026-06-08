//! End-to-end engine integration test: roster persistence + gossip.
//!
//! Covers the "remember the network roster, and converge it across the
//! members" contract:
//!
//!   1. When two peers complete the bilateral approve handshake and the
//!      link goes ACTIVE, each side persists the other into its roster —
//!      even on an `auto_approve` network where no human clicked Approve.
//!      (Before this landed, auto-approved peers reached ACTIVE but were
//!      never remembered — the "we keep losing our roster" symptom.)
//!
//!   2. A roster change made on one member (here: approving a peer that
//!      isn't directly connected) propagates to the other members by
//!      anti-entropy gossip — a compact membership summary, then a pulled
//!      diff — so every node converges on the same membership without a
//!      full-roster flood.
//!
//! Companion to `two_peer_handshake.rs` (open-network handshake) and
//! `closed_network_governance.rs` (signed transitions).

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network, NetworkCmd};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn fresh_network(id: &str, network_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        // Auto-approve fires the wire-level approve automatically so both
        // peers reach ACTIVE without a human Approve click — which is the
        // exact path we want to prove now persists the roster on its own.
        auto_approve: true,
    }
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

fn rostered(state: &Arc<myownmesh_core::engine::state::NetworkState>, device_id: &str) -> bool {
    myownmesh_core::roster::is_authorized(&state.roster.read(), device_id)
}

#[tokio::test]
async fn mutual_approve_persists_roster_on_both_sides() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let mut alice_cfg = fresh_network("alice", "roster-gossip-persist");
    let mut bob_cfg = fresh_network("bob", "roster-gossip-persist");
    alice_cfg.network_id = "roster-gossip-persist".into();
    bob_cfg.network_id = "roster-gossip-persist".into();

    let (alice_state, _ad) = spawn_network(alice_cfg, alice_id.clone(), transport.clone())
        .await
        .expect("alice engine");
    let (bob_state, _bd) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
        .await
        .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // The bilateral handshake completing must have persisted each peer
    // into the other's roster — no explicit approve_roster call here.
    assert!(
        rostered(&alice_state, bob_id.public_id()),
        "alice should have rostered bob on mutual ACTIVE"
    );
    assert!(
        rostered(&bob_state, alice_id.public_id()),
        "bob should have rostered alice on mutual ACTIVE"
    );
}

#[tokio::test]
async fn roster_membership_gossips_to_connected_peer() {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    // Carol never connects — she's only ever a roster entry that Alice
    // vouches for. The test proves Bob learns of her purely via gossip.
    let carol_id = Arc::new(Identity::ephemeral());

    let mut alice_cfg = fresh_network("alice", "roster-gossip-converge");
    let mut bob_cfg = fresh_network("bob", "roster-gossip-converge");
    alice_cfg.network_id = "roster-gossip-converge".into();
    bob_cfg.network_id = "roster-gossip-converge".into();

    let (alice_state, _ad) = spawn_network(alice_cfg, alice_id.clone(), transport.clone())
        .await
        .expect("alice engine");
    let (bob_state, _bd) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
        .await
        .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    // Alice approves Carol through the command queue — the same path the
    // GUI's "Approve" takes — which persists Carol locally AND advertises
    // the new membership to active peers.
    let (tx, rx) = tokio::sync::oneshot::channel();
    alice_state
        .cmd_tx
        .send(NetworkCmd::ApproveRoster {
            device_id: carol_id.public_id().to_string(),
            label: "carol".into(),
            reply: tx,
        })
        .expect("queue approve");
    rx.await.expect("approve reply").expect("approve ok");

    // Bob has no direct link to Carol; he must converge on her purely
    // through Alice's gossip (summary → request → entries → merge).
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        if rostered(&bob_state, carol_id.public_id()) {
            break;
        }
        if Instant::now() > deadline {
            panic!("bob never converged on carol via roster gossip");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}
