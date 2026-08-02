#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    NetworkConfig, SignalingConfig, TopologyMode, TurnCredential, TurnServer as IceTurnServer,
    TurnServiceConfig,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::engine::{attach_local, spawn_network, NetworkCmd};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::{IceCandidateKind, Transport};
use myownmesh_core::{Channel, MeshEvent, PeerEvent};
use myownmesh_services::TurnServer;
use myownmesh_signaling::local::LocalBroker;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn network_config(label: &str, turn_url: String) -> NetworkConfig {
    NetworkConfig {
        id: label.to_string(),
        network_id: "turn-endpoint-auth".to_string(),
        label: label.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: vec![IceTurnServer {
            urls: vec![turn_url],
            username: Some("arc03-user".to_string()),
            credential: Some("arc03-password".to_string()),
        }],
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

async fn wait_for_authenticated_then_approved(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    let mut authenticated = false;
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            match events.recv().await.expect("mesh event stream remains open") {
                MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })
                    if device_id == peer_id =>
                {
                    authenticated = true;
                }
                MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) if device_id == peer_id => {
                    assert!(
                        authenticated,
                        "application admission must follow endpoint authentication"
                    );
                    return;
                }
                _ => {}
            }
        }
    })
    .await
    .expect("endpoint authentication and approval timed out");
}

async fn receive_string(
    channel: &mut myownmesh_core::channels::ChannelSubscription<String>,
) -> (String, String) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if let Some(Ok(message)) = channel.recv().await {
                return (message.from, message.body);
            }
        }
    })
    .await
    .expect("endpoint data did not cross the selected TURN path")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turn_selected_session_authenticates_endpoints_before_bidirectional_data() {
    let home = tempfile::tempdir().expect("isolated MyOwnMesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let turn = TurnServer::start(&TurnServiceConfig {
        enabled: true,
        bind: "127.0.0.1".to_string(),
        port: 0,
        public_ip: "127.0.0.1".to_string(),
        realm: "arc03-test".to_string(),
        credentials: vec![TurnCredential {
            username: "arc03-user".to_string(),
            password: "arc03-password".to_string(),
        }],
        max_bps_per_connection: 0,
        relay_port_min: 0,
        relay_port_max: 0,
    })
    .await
    .expect("real TURN server starts");
    let turn_url = format!("turn:{}?transport=udp", turn.local_addr());

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let (alice, alice_driver) = spawn_network(
        network_config("alice", turn_url.clone()),
        Arc::clone(&alice_id),
        Transport::new_relay_only_for_lab().expect("relay-only Alice transport"),
    )
    .await
    .expect("Alice engine starts");
    let (bob, bob_driver) = spawn_network(
        network_config("bob", turn_url),
        Arc::clone(&bob_id),
        Transport::new_relay_only_for_lab().expect("relay-only Bob transport"),
    )
    .await
    .expect("Bob engine starts");

    let mut alice_events = alice.events_tx.subscribe();
    let mut bob_events = bob.events_tx.subscribe();
    let broker = LocalBroker::new();
    attach_local(&alice, &broker);
    attach_local(&bob, &broker);

    tokio::join!(
        wait_for_authenticated_then_approved(&mut alice_events, bob_id.public_id()),
        wait_for_authenticated_then_approved(&mut bob_events, alice_id.public_id())
    );

    for (state, peer_id) in [(&alice, bob_id.public_id()), (&bob, alice_id.public_id())] {
        let peer = state
            .peer_info(peer_id)
            .expect("approved peer remains current");
        assert_eq!(peer.status, PeerStatus::Active);
        assert!(peer.authenticated);
        assert!(peer.local_approve_sent);
        assert!(peer.remote_approve_seen);
        let pair = peer.selected_pair.expect("ICE reports the selected pair");
        assert_eq!(pair.local, IceCandidateKind::Relay);
        assert_eq!(pair.remote, IceCandidateKind::Relay);
    }

    let alice_channel = Channel::<String>::new("arc03-proof".to_string(), Arc::clone(&alice));
    let bob_channel = Channel::<String>::new("arc03-proof".to_string(), Arc::clone(&bob));
    let mut alice_receive = alice_channel.subscribe();
    let mut bob_receive = bob_channel.subscribe();

    alice_channel
        .send_to(bob_id.public_id(), &"alice-over-turn".to_string())
        .await
        .expect("authenticated Alice send");
    assert_eq!(
        receive_string(&mut bob_receive).await,
        (
            alice_id.public_id().to_string(),
            "alice-over-turn".to_string()
        )
    );

    bob_channel
        .send_to(alice_id.public_id(), &"bob-over-turn".to_string())
        .await
        .expect("authenticated Bob send");
    assert_eq!(
        receive_string(&mut alice_receive).await,
        (bob_id.public_id().to_string(), "bob-over-turn".to_string())
    );

    alice
        .cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Alice shutdown reaches its driver");
    bob.cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Bob shutdown reaches its driver");
    alice_driver.await.expect("Alice driver shuts down cleanly");
    bob_driver.await.expect("Bob driver shuts down cleanly");
    drop((alice, bob));
    tokio::task::yield_now().await;
    turn.stop().await.expect("TURN server stops cleanly");
}
