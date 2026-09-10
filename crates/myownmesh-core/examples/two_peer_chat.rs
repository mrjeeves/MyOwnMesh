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

#[cfg(feature = "transport-lab")]
use std::time::Duration;

#[cfg(feature = "transport-lab")]
use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
#[cfg(feature = "transport-lab")]
use myownmesh_core::identity::Identity;
#[cfg(feature = "transport-lab")]
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
#[cfg(feature = "transport-lab")]
use myownmesh_core::{
    ConnectorCallbackPolicy, Mesh, MeshConfig, MeshEvent, PeerEvent, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};
#[cfg(feature = "transport-lab")]
use myownmesh_signaling::local::LocalBroker;
#[cfg(feature = "transport-lab")]
use serde::{Deserialize, Serialize};

#[cfg(feature = "transport-lab")]
#[derive(Serialize, Deserialize, Debug)]
struct ChatLine {
    text: String,
}

#[cfg(feature = "transport-lab")]
fn cfg(label: &str) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "two-peer-chat".into(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: label.into(),
        kind: Default::default(),
        semantic_policy: Default::default(),
        hub: None,
        local_observations: None,
        introduction: None,
        tree: None,
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

#[cfg(feature = "transport-lab")]
fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 100_000_000)),
    )
    .expect("example resource grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("example resource provider is valid");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

#[cfg(feature = "transport-lab")]
#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter("info,myownmesh=info")
        .init();

    let tmp = tempfile::tempdir().unwrap();
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let alice = Identity::ephemeral();
    let bob = Identity::ephemeral();
    let alice_device = alice.public_id().to_string();
    let bob_device = bob.public_id().to_string();
    let policy = connector_policy();
    let alice_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(alice),
        policy.clone(),
    )
    .await
    .unwrap();
    let bob_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(bob),
        policy,
    )
    .await
    .unwrap();
    let alice_net = alice_mesh.join(cfg("alice")).await.unwrap();
    let bob_net = bob_mesh.join(cfg("bob")).await.unwrap();
    let mut alice_events = alice_mesh.events();
    let mut bob_events = bob_mesh.events();

    alice_net.attach_local(&broker);
    bob_net.attach_local(&broker);

    // Wait for both sides to see the peer become Active.
    println!("waiting for handshake...");
    wait_until_approved(&mut alice_events, &bob_device).await;
    wait_until_approved(&mut bob_events, &alice_device).await;
    println!("ALICE ({alice_device}) and BOB ({bob_device}) are connected.\n");

    let alice_chan = alice_net.channel::<ChatLine>("chat");
    let bob_chan = bob_net.channel::<ChatLine>("chat");
    let mut bob_sub = bob_chan
        .subscribe()
        .expect("Bob's live channel admits its subscription");
    let mut alice_sub = alice_chan
        .subscribe()
        .expect("Alice's live channel admits its subscription");

    // Alice sends to Bob.
    alice_chan
        .send_to(
            &bob_device,
            &ChatLine {
                text: "hello bob".into(),
            },
        )
        .await
        .unwrap();
    let msg = bob_sub.recv().await.unwrap().unwrap();
    println!("BOB ◀── {}", msg.body().text);

    // Bob replies.
    bob_chan
        .send_to(
            &alice_device,
            &ChatLine {
                text: "hey alice".into(),
            },
        )
        .await
        .unwrap();
    let msg = alice_sub.recv().await.unwrap().unwrap();
    println!("ALICE ◀── {}", msg.body().text);

    // Give the broker a moment to settle before we tear down.
    tokio::time::sleep(Duration::from_millis(100)).await;
}

#[cfg(not(feature = "transport-lab"))]
fn main() {
    eprintln!("run this demo with --features transport-lab");
}

#[cfg(feature = "transport-lab")]
async fn wait_until_approved(rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>, peer_id: &str) {
    while let Ok(event) = rx.recv().await {
        if let MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) = event {
            if device_id == peer_id {
                return;
            }
        }
    }
}
