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
use myownmesh_core::transport::webrtc::LaneKind;
use myownmesh_core::transport::{IceCandidateKind, Transport};
use myownmesh_core::{
    Channel, ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy,
    ConnectorCallbackServiceWeights, ConnectorCapableResourcePolicy, ConnectorResourcePolicy,
    MeshConnectorResourcePolicy, MeshEvent, PeerEvent, RealtimeConnectorPolicy,
};
use myownmesh_services::TurnServer;
use myownmesh_signaling::local::LocalBroker;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn network_config(label: &str, turn_url: String, auto_approve: bool) -> NetworkConfig {
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
        auto_approve,
    }
}

fn test_connector_resource_policy() -> ConnectorCapableResourcePolicy {
    let two = std::num::NonZeroUsize::new(2)
        .expect("the two-endpoint fixture candidate bound is nonzero");
    let callback = std::num::NonZeroUsize::new(16).expect("fixture callback bound is nonzero");
    let callbacks = ConnectorCallbackPolicy::new(
        ConnectorCallbackMailboxCapacities::new(callback, callback),
        ConnectorCallbackServiceWeights::data_only(callback, callback),
        RealtimeConnectorPolicy::Disabled,
    )
    .expect("fixture data-only callback policy is valid");
    let process = ConnectorResourcePolicy::new(two, callbacks, Duration::from_secs(10))
        .expect("fixture native-close observation limit is nonzero");
    ConnectorCapableResourcePolicy::new(process, MeshConnectorResourcePolicy::new(two))
}

fn relay_only_test_transport() -> Transport {
    Transport::new_relay_only_for_lab()
        .expect("relay-only test transport")
        .with_connector_resource_policy(test_connector_resource_policy())
        .expect("fixture process connector policy is consistent")
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

async fn wait_for_authenticated(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if matches!(
                events.recv().await.expect("mesh event stream remains open"),
                MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. }) if device_id == peer_id
            ) {
                return;
            }
        }
    })
    .await
    .expect("endpoint authentication timed out");
}

async fn wait_for_relay_pair(state: &myownmesh_core::engine::state::NetworkState, peer_id: &str) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if state
                .peer_info(peer_id)
                .and_then(|peer| peer.selected_pair)
                .is_some_and(|pair| {
                    pair.local == IceCandidateKind::Relay && pair.remote == IceCandidateKind::Relay
                })
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("relay-selected candidate pair timed out");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn turn_selected_session_authenticates_endpoints_before_bidirectional_data() {
    let observed_at = std::time::Instant::now();
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
        network_config("alice", turn_url.clone(), true),
        Arc::clone(&alice_id),
        relay_only_test_transport(),
    )
    .await
    .expect("Alice engine starts");
    let (bob, bob_driver) = spawn_network(
        network_config("bob", turn_url.clone(), true),
        Arc::clone(&bob_id),
        relay_only_test_transport(),
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
    if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
        println!(
            "arc03_turn_raw authenticated_and_approved_ns={}",
            observed_at.elapsed().as_nanos()
        );
    }

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

    let positive_close_at = std::time::Instant::now();
    alice
        .cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Alice shutdown reaches its driver");
    bob.cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Bob shutdown reaches its driver");
    alice_driver.await.expect("Alice driver shuts down cleanly");
    bob_driver.await.expect("Bob driver shuts down cleanly");
    if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
        println!(
            "arc03_turn_raw positive_shutdown_ns={}",
            positive_close_at.elapsed().as_nanos()
        );
    }
    drop((alice, bob));
    tokio::task::yield_now().await;

    // Negative control on the same real TURN service. A relay-selected and
    // endpoint-authenticated channel that has not received mutual application
    // admission cannot send endpoint data, open a real-time lane, or send a
    // real-time sample.
    let carol_id = Arc::new(Identity::ephemeral());
    let dave_id = Arc::new(Identity::ephemeral());
    let (carol, carol_driver) = spawn_network(
        network_config("carol", turn_url.clone(), false),
        Arc::clone(&carol_id),
        relay_only_test_transport(),
    )
    .await
    .expect("Carol engine starts");
    let (dave, dave_driver) = spawn_network(
        network_config("dave", turn_url, false),
        Arc::clone(&dave_id),
        relay_only_test_transport(),
    )
    .await
    .expect("Dave engine starts");
    let mut carol_events = carol.events_tx.subscribe();
    let mut dave_events = dave.events_tx.subscribe();
    let negative_broker = LocalBroker::new();
    attach_local(&carol, &negative_broker);
    attach_local(&dave, &negative_broker);

    tokio::join!(
        wait_for_authenticated(&mut carol_events, dave_id.public_id()),
        wait_for_authenticated(&mut dave_events, carol_id.public_id())
    );
    tokio::join!(
        wait_for_relay_pair(&carol, dave_id.public_id()),
        wait_for_relay_pair(&dave, carol_id.public_id())
    );
    for (state, peer_id) in [(&carol, dave_id.public_id()), (&dave, carol_id.public_id())] {
        let peer = state
            .peer_info(peer_id)
            .expect("pending peer remains current");
        assert_eq!(peer.status, PeerStatus::PendingApproval);
        assert!(peer.authenticated);
        assert!(!peer.local_approve_sent);
        assert!(!peer.remote_approve_seen);
    }

    let carol_channel = Channel::<String>::new("arc03-negative".to_string(), Arc::clone(&carol));
    carol_channel
        .send_to(dave_id.public_id(), &"must-not-send".to_string())
        .await
        .expect_err("relay selection cannot bypass session admission");
    carol
        .send_video_sample(
            dave_id.public_id(),
            0,
            b"must-not-send".to_vec().into(),
            Duration::from_millis(1),
        )
        .await
        .expect_err("relay selection cannot bypass real-time-flow admission");
    let (lane_reply, lane_result) = tokio::sync::oneshot::channel();
    carol
        .cmd_tx
        .send(NetworkCmd::MediaLaneOpen {
            peer: dave_id.public_id().to_string(),
            kind: LaneKind::Video,
            reply: lane_reply,
        })
        .expect("negative lane request reaches the engine");
    lane_result
        .await
        .expect("engine returns the negative lane result")
        .expect_err("worker possession cannot bypass real-time-flow admission");

    carol
        .cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Carol shutdown reaches its driver");
    dave.cmd_tx
        .send(NetworkCmd::Shutdown)
        .expect("Dave shutdown reaches its driver");
    carol_driver.await.expect("Carol driver shuts down cleanly");
    dave_driver.await.expect("Dave driver shuts down cleanly");
    drop((carol, dave));
    tokio::task::yield_now().await;
    turn.stop().await.expect("TURN server stops cleanly");
}
