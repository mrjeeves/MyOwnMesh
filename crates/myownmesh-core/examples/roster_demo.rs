//! Roster management demo.
//!
//! ```
//! cargo run --example roster_demo -p myownmesh-core
//! ```
//!
//! Demonstrates: building two peers with semantic admission enabled,
//! observing the authenticated peer, and watching the connection transition
//! to `Active` before listing the canonical roster projection.
#[cfg(feature = "transport-lab")]
use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, RoutingPolicyConfig, SignalingConfig, TopologyMode,
};
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
fn cfg(label: &str, auto_approve: bool) -> NetworkConfig {
    NetworkConfig {
        id: label.into(),
        network_id: "roster-demo".into(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: label.into(),
        kind: Default::default(),
        semantic_policy: Default::default(),
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        tree: None,
        scheduler: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve,
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
    let host = Identity::ephemeral();
    let guest = Identity::ephemeral();
    let host_device = host.public_id().to_string();
    let guest_device = guest.public_id().to_string();
    let policy = connector_policy();
    let host_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(host),
        policy.clone(),
    )
    .await
    .unwrap();
    let guest_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        std::sync::Arc::new(guest),
        policy,
    )
    .await
    .unwrap();

    // Both peers use the configured semantic admission path.
    let host_net = host_mesh.join(cfg("host", true)).await.unwrap();
    let guest_net = guest_mesh.join(cfg("guest", true)).await.unwrap();
    let mut host_events = host_mesh.events();
    host_net.attach_local(&broker);
    guest_net.attach_local(&broker);

    println!("Host pubkey: {host_device}\nGuest pubkey: {guest_device}\n");

    // Wait for the guest to authenticate and then become active through the
    // semantic admission path. The verification code remains observable for
    // deployments that choose to add an out-of-band policy gate.
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

    let roster = myownmesh_core::roster::load(host_net.network_id()).unwrap();
    println!("\nRoster ({}):", host_net.network_id());
    for entry in roster.authorized_devices {
        println!("  - {} ({})", entry.label, entry.device_id);
    }
}
#[cfg(not(feature = "transport-lab"))]
fn main() {
    eprintln!("run this demo with --features transport-lab");
}
