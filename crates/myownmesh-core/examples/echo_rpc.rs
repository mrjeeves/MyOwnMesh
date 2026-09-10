//! Generic RPC echo handler.
//!
//! ```
//! cargo run --example echo_rpc -p myownmesh-core
//! ```
//!
//! Demonstrates: two peers handshake, one registers an "echo"
//! handler, the other calls it and receives the echoed payload.

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
    ConnectorCallbackPolicy, Mesh, MeshConfig, MeshEvent, PeerEvent, RpcResponse,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
#[cfg(feature = "transport-lab")]
use myownmesh_signaling::local::LocalBroker;

#[cfg(feature = "transport-lab")]
fn cfg(label: &str) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "echo-rpc-demo".into(),
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
    let server_id = Identity::ephemeral();
    let client_id = Identity::ephemeral();
    let server_device = server_id.public_id().to_string();
    let client_device = client_id.public_id().to_string();
    let policy = connector_policy();
    let server_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(server_id),
        policy.clone(),
    )
    .await
    .unwrap();
    let client_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(client_id),
        policy,
    )
    .await
    .unwrap();
    let server_net = server_mesh.join(cfg("server")).await.unwrap();
    let client_net = client_mesh.join(cfg("client")).await.unwrap();
    let server_rpc = server_net.rpc();
    let client_rpc = client_net.rpc();

    // Server registers an echo handler.
    server_rpc
        .serve("echo", |call| async move {
            Ok(RpcResponse::from_value(call.payload))
        })
        .expect("server handler admission");

    let mut server_events = server_mesh.events();
    let mut client_events = client_mesh.events();
    server_net.attach_local(&broker);
    client_net.attach_local(&broker);

    wait_until_approved(&mut server_events, &client_device).await;
    wait_until_approved(&mut client_events, &server_device).await;
    println!("client and server connected.");

    let resp = client_rpc
        .call(&server_device, "echo", serde_json::json!({"msg": "ping"}))
        .await
        .unwrap();
    println!("echo returned: {}", resp.body);
    assert_eq!(resp.body, serde_json::json!({"msg": "ping"}));
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
