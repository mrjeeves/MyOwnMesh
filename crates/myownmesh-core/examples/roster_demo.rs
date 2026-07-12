//! Roster management demo.
//!
//! ```
//! cargo run --example roster_demo -p myownmesh-core
//! ```
//!
//! Demonstrates: building two peers with `auto_approve = false` so
//! the second peer needs explicit user approval, then approving
//! it programmatically and watching the connection transition to
//! `Active`.

use std::sync::Arc;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use myownmesh_signaling::local::LocalBroker;

fn cfg(label: &str, auto_approve: bool) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "roster-demo".into(),
        label: label.into(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve,
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

    let host = Arc::new(Identity::ephemeral());
    let guest = Arc::new(Identity::ephemeral());

    // Host requires explicit approval; guest auto-approves.
    let (host_net, _hd) = spawn_network(cfg("host", false), host.clone(), transport.clone())
        .await
        .unwrap();
    let (guest_net, _gd) = spawn_network(cfg("guest", true), guest.clone(), transport.clone())
        .await
        .unwrap();

    let mut host_events = host_net.events_tx.subscribe();
    attach_local(&host_net, &broker);
    attach_local(&guest_net, &broker);

    println!(
        "Host pubkey: {}\nGuest pubkey: {}\n",
        host.public_id(),
        guest.public_id()
    );

    // Wait for the guest to authenticate. We'll see them in
    // `PendingApproval` first because host.auto_approve = false.
    // The `verification_code` field on the event is the eyeball-
    // check code surfaced to the user before they click approve.
    // (Note: depending on which order the hello/auth_response
    // frames arrive in on this side, the code field can be empty
    // for the very first emission — the production UI reads it
    // from PeerInfo.capabilities or re-fetches it via the engine.)
    let mut guest_pubkey = None;
    while let Ok(event) = host_events.recv().await {
        if let MeshEvent::Peer(PeerEvent::Authenticated {
            device_id,
            verification_code,
            label,
            ..
        }) = event
        {
            println!(
                "Host: '{label}' ({device_id}) wants to join.\n      verification code = {verification_code:?}"
            );
            guest_pubkey = Some(device_id);
            break;
        }
    }
    let guest_pubkey = guest_pubkey.expect("authenticated event");

    // The user "confirms" the code over an out-of-band channel
    // and approves. Two steps:
    //   1. Persist the approval to the roster so future reconnects
    //      auto-allow without prompting.
    //   2. Emit the `approve` frame for the current session so the
    //      connection transitions to Active.
    println!("Host: approving guest into roster...");
    host_net
        .approve_roster(&guest_pubkey, "Guest's laptop")
        .await
        .unwrap();
    myownmesh_core::engine::handshake::send_local_approve(&host_net, &guest_pubkey).await;

    while let Ok(event) = host_events.recv().await {
        if let MeshEvent::Peer(PeerEvent::Approved {
            device_id, label, ..
        }) = event
        {
            if device_id == guest_pubkey {
                println!("Host: {label} is now active.");
                break;
            }
        }
    }

    let roster = myownmesh_core::roster::load(&host_net.network_id).unwrap();
    println!("\nRoster ({}):", host_net.network_id);
    for entry in roster.authorized_devices {
        println!("  - {} ({})", entry.label, entry.device_id);
    }
}
