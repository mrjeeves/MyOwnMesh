//! Generic RPC echo handler.
//!
//! ```
//! cargo run --example echo_rpc -p myownmesh-core
//! ```
//!
//! Demonstrates: two peers handshake, one registers an "echo"
//! handler, the other calls it and receives the echoed payload.

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::rpc::Rpc;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent, RpcResponse};
use myownmesh_signaling::local::LocalBroker;

fn cfg(label: &str) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "echo-rpc-demo".into(),
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

    let server_id = Arc::new(Identity::ephemeral());
    let client_id = Arc::new(Identity::ephemeral());

    let (server_net, _sd) = spawn_network(cfg("server"), server_id.clone(), transport.clone())
        .await
        .unwrap();
    let (client_net, _cd) = spawn_network(cfg("client"), client_id.clone(), transport.clone())
        .await
        .unwrap();

    let server_rpc = Rpc::attach(&server_net);
    let client_rpc = Rpc::attach(&client_net);

    // Server registers an echo handler.
    server_rpc.serve("echo", |call| async move {
        Ok(RpcResponse::from_value(call.payload))
    });

    let mut server_events = server_net.events_tx.subscribe();
    let mut client_events = client_net.events_tx.subscribe();
    attach_local(&server_net, &broker);
    attach_local(&client_net, &broker);

    wait_until_approved(&mut server_events, client_id.public_id()).await;
    wait_until_approved(&mut client_events, server_id.public_id()).await;
    println!("client and server connected.");

    let resp = client_rpc
        .call(
            server_id.public_id(),
            "echo",
            serde_json::json!({"msg": "ping"}),
        )
        .await
        .unwrap();
    println!("echo returned: {}", resp.body);
    assert_eq!(resp.body, serde_json::json!({"msg": "ping"}));
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
