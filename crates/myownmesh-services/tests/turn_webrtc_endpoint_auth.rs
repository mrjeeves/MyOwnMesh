#![cfg(target_os = "linux")]

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    NetworkConfig, RoutingPolicyConfig, SchedulerPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode, TurnCredential, TurnServer as IceTurnServer, TurnServiceConfig,
    SQLITE_DEFAULT_PAGE_SIZE_BYTES,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::engine::transport_lab::{attach_local, channel, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::{IceCandidateKind, Transport};
use myownmesh_core::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant, ConnectorCallbackPolicy,
    FiniteResourceProvider, LocalApplicationResourceScope, MeshEvent, PeerEvent, ResourceClaim,
    ResourceClass, ResourceProviderPort, TransportLabCallbackWorkload,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use myownmesh_services::TurnServer;
use myownmesh_signaling::local::LocalBroker;

const TEST_TIMEOUT: Duration = Duration::from_secs(30);

fn service_scope() -> LocalApplicationResourceScope {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, 1_000_000)),
    )
    .expect("TURN service fixture grant is representable");
    let port = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("TURN service fixture provider is valid");
    LocalApplicationResourceScope::transport_lab_child_of(&port)
        .expect("TURN service fixture scope is valid")
}

fn network_config(label: &str, turn_url: String, auto_approve: bool) -> NetworkConfig {
    NetworkConfig {
        id: label.to_string(),
        network_id: "turn-endpoint-auth".to_string(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: label.to_string(),
        kind: Default::default(),
        scheduler: SchedulerPolicyConfig::default(),
        semantic_policy: myownmesh_core::config::SemanticPolicyConfig::default(),
        topology: TopologyMode::FullMesh,
        routing_policy: RoutingPolicyConfig::default(),
        tree: None,
        hub: None,
        local_observations: None,
        application_transport: None,
        signaling: SignalingConfig::default(),
        closed_relay: Default::default(),
        stun_servers: Vec::new(),
        turn_servers: vec![IceTurnServer {
            urls: vec![turn_url],
            username: Some("arc03-user".to_string()),
            credential: Some("arc03-password".to_string()),
        }],
        pinned_peers: Vec::new(),
        auto_approve,
    }
}

fn test_connector_resource_policy() -> WebRtcConnectorCapablePolicy {
    let four = std::num::NonZeroUsize::new(4)
        .expect("the four-connector fixture candidate bound is nonzero");
    let callback = std::num::NonZeroUsize::new(16).expect("fixture callback bound is nonzero");
    // This fixture mints its own finite provider via
    // `transport_lab_connector_fixture_grant`, so it has to state the largest
    // payload it will fund for each callback class — nothing else can derive
    // the byte grant, and a callback class funded for no payload is what left
    // gathered ICE candidates refused for want of `QueuedBytes`.
    //
    // Both are fixture numbers chosen here and stated here. Deliberately *not*
    // the signaling frame limit used for the candidate and SDP envelopes below:
    // that limit belongs to another layer, and a borrowed number that happens to
    // be large enough is exactly how the original underfunding stayed invisible.
    // Control covers one gathered ICE candidate's JSON; endpoint data covers the
    // handshake frames this two-peer scenario exchanges.
    let control_payload_ceiling =
        std::num::NonZeroUsize::new(4_096).expect("the fixture control payload ceiling is nonzero");
    let endpoint_payload_ceiling = std::num::NonZeroUsize::new(16_384)
        .expect("the fixture endpoint payload ceiling is nonzero");
    let callback_workload = TransportLabCallbackWorkload {
        control_slots: callback,
        endpoint_slots: callback,
        control_payload_bytes: u64::try_from(control_payload_ceiling.get())
            .expect("the fixture control payload ceiling fits u64"),
        endpoint_payload_bytes: u64::try_from(endpoint_payload_ceiling.get())
            .expect("the fixture endpoint payload ceiling fits u64"),
        realtime: None,
    };
    let webrtc = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    let connectors = std::num::NonZeroU64::new(
        u64::try_from(four.get()).expect("fixture connector count fits u64"),
    )
    .expect("the fixture connector count is nonzero");
    let frame_bytes = std::num::NonZeroU64::new(
        u64::try_from(myownmesh_signaling::mdns::wire::MAX_FRAME_BYTES)
            .expect("the signaling frame limit fits u64"),
    )
    .expect("the signaling frame limit is nonzero");
    let candidate_total_content = std::num::NonZeroU64::new(
        frame_bytes
            .get()
            .checked_mul(connectors.get())
            .expect("fixture candidate content envelope fits u64"),
    )
    .expect("the fixture candidate content envelope is nonzero");
    let candidate_total_string_capacity = std::num::NonZeroU64::new(
        candidate_total_content
            .get()
            .checked_mul(3)
            .expect("the three candidate string fields fit the fixture envelope"),
    )
    .expect("the fixture candidate string envelope is nonzero");
    // A retained candidate has at least one content byte, so this is the
    // conservative item bound implied by the cumulative content envelope.
    let max_unique_candidates = candidate_total_content;
    let candidate_workload = transport_lab_remote_candidate_fixture_grant(
        max_unique_candidates,
        connectors,
        candidate_total_string_capacity,
        candidate_total_content,
        frame_bytes,
    )
    .expect("fixture candidate claims are representable");
    let remote_descriptions = transport_lab_remote_description_fixture_grant(
        connectors,
        frame_bytes,
        std::num::NonZeroU64::new(1).expect("the data-only profile has one media section"),
        std::num::NonZeroU64::new(1).expect("the data-only profile has one active binding"),
        frame_bytes,
    )
    .expect("fixture remote-SDP claims are representable");
    // The grant is priced against four identical connector profiles, and the
    // policy the fixture actually installs is that same profile. Clone for the
    // pricing slice so the one profile stays owned here for the policy below.
    let profiles = vec![webrtc.clone(); four.get()];
    let mesh_scopes =
        std::num::NonZeroU64::new(4).expect("the two-scenario fixture Mesh scope count is nonzero");
    // Gateway parsing capacity, which none of the grants above price: they cover
    // building connectors and moving signaling through them, while this covers
    // turning one inbound frame into a `serde_json::Value` tree. It is added
    // here, at the full-engine owner that runs a real handshake, rather than
    // inside `transport_lab_connector_fixture_grant` — that helper prices
    // transport construction and has no business naming what the application
    // gateway may allocate.
    //
    // Two simultaneous claims per connector, both with a named holder: the
    // peer's `Hello` retains its claim for the connection's whole life, and one
    // further protocol or application frame is being parsed at any moment.
    //
    // This fixture's own frame size, not borrowed from the signaling frame limit
    // used for the candidate and SDP envelopes above, and the claim itself comes
    // from the gateway rather than being restated here. It funds a parse and
    // gates nothing on the wire.
    const JSON_FRAME_BYTES: usize = 8 * 1024;
    const JSON_CLAIMS_PER_CONNECTOR: u64 = 2;
    let json_input_work =
        myownmesh_core::application_gateway::json_input_work_claim(JSON_FRAME_BYTES)
            .expect("the fixture JSON input claim is representable")
            .checked_scale(
                connectors
                    .get()
                    .checked_mul(JSON_CLAIMS_PER_CONNECTOR)
                    .expect("the fixture JSON claim count is representable"),
            )
            .expect("the fixture JSON input capacity is representable");
    let grant = transport_lab_connector_fixture_grant(&profiles, mesh_scopes, callback_workload)
        .expect("fixture structural and callback claims are representable")
        .checked_add(candidate_workload)
        .and_then(|claim| claim.checked_add(remote_descriptions))
        .and_then(|claim| claim.checked_add(json_input_work))
        .and_then(|claim| {
            // The positive and negative controls each own two engines.  The
            // explicit engine handles and drivers are fully shut down before
            // the second pair starts; shutdown releases each semantic store
            // lease even though channel/subscription locals retain the old
            // NetworkState Arcs.  Carol/Dave therefore exercise reuse of the
            // same two funded storage envelopes, and the peak is two.
            const LIVE_NETWORK_OWNERS: u64 = 2;
            let semantic_policy = SemanticPolicyConfig::default();
            let envelope = semantic_policy
                .checked_storage_envelope(
                    SQLITE_DEFAULT_PAGE_SIZE_BYTES,
                    semantic_policy.storage_workload(),
                )
                .expect("fixture semantic storage envelope is representable");
            let storage_claim =
                ResourceClaim::single(ResourceClass::StorageBytes, envelope.total_bytes);
            let storage_grant = FiniteResourceProvider::reservation_planning_charge(storage_claim)
                .expect("fixture semantic storage reservation is representable")
                .checked_scale(LIVE_NETWORK_OWNERS)
                .expect("fixture semantic storage owner capacity is representable");
            assert_eq!(
                storage_grant.amount(ResourceClass::StorageBytes),
                envelope
                    .total_bytes
                    .checked_mul(LIVE_NETWORK_OWNERS)
                    .expect("fixture semantic storage byte capacity is representable"),
                "semantic storage funding equals the checked envelope per owner"
            );
            assert_eq!(
                storage_grant.amount(ResourceClass::OpaqueDependencyResidual),
                LIVE_NETWORK_OWNERS,
                "semantic storage funding includes one reservation record per owner"
            );
            claim.checked_add(storage_grant)
        })
        .expect("the fixture provider grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("the fixture provider accounts for its process scope");
    WebRtcConnectorCapablePolicy::new(resources, webrtc)
}

fn relay_only_test_transport(policy: &WebRtcConnectorCapablePolicy) -> Transport {
    Transport::new_relay_only_for_lab()
        .expect("relay-only test transport")
        .with_connector_resource_policy(policy.clone())
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
                event => {
                    if std::env::var_os("MYOWNMESH_ARC03_DEBUG_EVENTS").is_some() {
                        eprintln!("arc03 TURN event while awaiting approval: {event:?}");
                    }
                }
            }
        }
    })
    .await
    .expect("endpoint authentication and approval timed out");
}

async fn receive_string(
    channel: &mut myownmesh_core::channels::ChannelSubscription<String>,
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
) -> (String, String) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                message = channel.recv() => {
                    if let Some(Ok(message)) = message {
                        return (message.from().to_string(), message.body().clone());
                    }
                }
                event = events.recv(), if std::env::var_os("MYOWNMESH_ARC03_DEBUG_EVENTS").is_some() => {
                    if let Ok(event) = event {
                        eprintln!("arc03 TURN event while awaiting endpoint data: {event:?}");
                    }
                }
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

async fn wait_for_reported_relay_pair(
    peers: [(&myownmesh_core::engine::transport_lab::NetworkState, &str); 2],
) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if peers.iter().any(|(state, peer_id)| {
                state
                    .peer_info(peer_id)
                    .and_then(|peer| peer.selected_pair)
                    .is_some_and(|pair| {
                        pair.local == IceCandidateKind::Relay
                            && pair.remote == IceCandidateKind::Relay
                    })
            }) {
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

    let turn = TurnServer::start_with_resource_scope(
        &TurnServiceConfig {
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
        },
        service_scope(),
    )
    .await
    .expect("real TURN server starts");
    let turn_url = format!("turn:{}?transport=udp", turn.local_addr());

    let test_resources = test_connector_resource_policy();
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let (alice, alice_driver) = spawn_network(
        network_config("alice", turn_url.clone(), true),
        Arc::clone(&alice_id),
        relay_only_test_transport(&test_resources),
    )
    .await
    .expect("Alice engine starts");
    let (bob, bob_driver) = spawn_network(
        network_config("bob", turn_url.clone(), true),
        Arc::clone(&bob_id),
        relay_only_test_transport(&test_resources),
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
    wait_for_reported_relay_pair([(&alice, bob_id.public_id()), (&bob, alice_id.public_id())])
        .await;

    let mut reported_relay_pair = false;
    for (state, peer_id) in [(&alice, bob_id.public_id()), (&bob, alice_id.public_id())] {
        let peer = state
            .peer_info(peer_id)
            .expect("approved peer remains current");
        assert_eq!(peer.status, PeerStatus::Active);
        assert!(peer.authenticated);
        assert!(peer.local_approve_sent);
        assert!(peer.remote_approve_seen);
        if let Some(pair) = peer.selected_pair {
            assert_eq!(pair.local, IceCandidateKind::Relay);
            assert_eq!(pair.remote, IceCandidateKind::Relay);
            reported_relay_pair = true;
        }
    }
    assert!(reported_relay_pair, "ICE reports the selected relay pair");

    let alice_channel = channel::<String>("arc03-proof".to_string(), Arc::clone(&alice));
    let bob_channel = channel::<String>("arc03-proof".to_string(), Arc::clone(&bob));
    let mut alice_receive = alice_channel
        .subscribe()
        .expect("alice subscription admitted");
    let mut bob_receive = bob_channel.subscribe().expect("bob subscription admitted");

    alice_channel
        .send_to(bob_id.public_id(), &"alice-over-turn".to_string())
        .await
        .expect("authenticated Alice send");
    assert_eq!(
        receive_string(&mut bob_receive, &mut bob_events).await,
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
        receive_string(&mut alice_receive, &mut alice_events).await,
        (bob_id.public_id().to_string(), "bob-over-turn".to_string())
    );

    let positive_close_at = std::time::Instant::now();
    alice.request_shutdown();
    bob.request_shutdown();
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

    // Negative control on the same real TURN service: a relay-selected and
    // endpoint-authenticated channel without mutual application admission
    // cannot send endpoint data.
    //
    // A second control used to sit here, proving a data-only profile could not
    // acquire the fixed video/audio lane surface merely because TURN was
    // selected. That was a profile-exclusion control over a surface that no
    // longer exists — there is no lane to open and no media entry point on this
    // path — so it is gone rather than restated against realtime flows, which
    // are reached through `JoinedNetwork` and not from an engine handle.
    let carol_id = Arc::new(Identity::ephemeral());
    let dave_id = Arc::new(Identity::ephemeral());
    let (carol, carol_driver) = spawn_network(
        network_config("carol", turn_url.clone(), false),
        Arc::clone(&carol_id),
        relay_only_test_transport(&test_resources),
    )
    .await
    .expect("Carol engine starts");
    let (dave, dave_driver) = spawn_network(
        network_config("dave", turn_url, false),
        Arc::clone(&dave_id),
        relay_only_test_transport(&test_resources),
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
    wait_for_reported_relay_pair([(&carol, dave_id.public_id()), (&dave, carol_id.public_id())])
        .await;
    for (state, peer_id) in [(&carol, dave_id.public_id()), (&dave, carol_id.public_id())] {
        let peer = state
            .peer_info(peer_id)
            .expect("pending peer remains current");
        assert_eq!(peer.status, PeerStatus::PendingApproval);
        assert!(peer.authenticated);
        assert!(!peer.local_approve_sent);
        assert!(!peer.remote_approve_seen);
    }

    let carol_channel = channel::<String>("arc03-negative".to_string(), Arc::clone(&carol));
    carol_channel
        .send_to(dave_id.public_id(), &"must-not-send".to_string())
        .await
        .expect_err("relay selection cannot bypass session admission");

    carol.request_shutdown();
    dave.request_shutdown();
    carol_driver.await.expect("Carol driver shuts down cleanly");
    dave_driver.await.expect("Dave driver shuts down cleanly");
    drop((carol, dave));
    tokio::task::yield_now().await;
    turn.stop().await.expect("TURN server stops cleanly");
}
