//! Two peers chat with each other through the in-process broker.
//!
//! ```
//! cargo run --example two_peer_chat -p myownmesh-core
//! ```
//!
//! Demonstrates: spinning up two engine instances with distinct
//! ephemeral identities, connecting them via `LocalBroker`,
//! waiting for the handshake to complete, and exchanging typed
//! messages on a named channel.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{Channel, MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug)]
struct ChatLine {
    text: String,
}

fn cfg(label: &str) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "two-peer-chat".into(),
        label: label.into(),
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

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,myownmesh=info")
        .init();

    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().unwrap();

    let alice = Arc::new(Identity::ephemeral());
    let bob = Arc::new(Identity::ephemeral());

    let (alice_net, _ad) = spawn_network(cfg("alice"), alice.clone(), transport.clone())
        .await
        .unwrap();
    let (bob_net, _bd) = spawn_network(cfg("bob"), bob.clone(), transport.clone())
        .await
        .unwrap();

    let mut alice_events = alice_net.events_tx.subscribe();
    let mut bob_events = bob_net.events_tx.subscribe();

    attach_local(&alice_net, &broker);
    attach_local(&bob_net, &broker);

    // Wait for both sides to see the peer become Active.
    println!("waiting for handshake...");
    wait_until_approved(&mut alice_events, bob.public_id()).await;
    wait_until_approved(&mut bob_events, alice.public_id()).await;
    println!(
        "ALICE ({}) and BOB ({}) are connected.\n",
        alice.public_id(),
        bob.public_id()
    );

    let alice_chan: Channel<ChatLine> = Channel::new("chat".into(), alice_net.clone());
    let bob_chan: Channel<ChatLine> = Channel::new("chat".into(), bob_net.clone());
    let mut bob_sub = bob_chan.subscribe();
    let mut alice_sub = alice_chan.subscribe();

    // Alice sends to Bob.
    alice_chan
        .send_to(
            bob.public_id(),
            &ChatLine {
                text: "hello bob".into(),
            },
        )
        .await
        .unwrap();
    let msg = bob_sub.recv().await.unwrap().unwrap();
    println!("BOB ◀── {}", msg.body.text);

    // Bob replies.
    bob_chan
        .send_to(
            alice.public_id(),
            &ChatLine {
                text: "hey alice".into(),
            },
        )
        .await
        .unwrap();
    let msg = alice_sub.recv().await.unwrap().unwrap();
    println!("ALICE ◀── {}", msg.body.text);

    // Give the broker a moment to settle before we tear down.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

async fn wait_until_approved(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
    while let Ok(event) = rx.recv().await {
        if let MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) = event {
            if device_id == peer_id {
                return;
            }
        }
    }
}
