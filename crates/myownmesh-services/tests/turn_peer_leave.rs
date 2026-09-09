#![cfg(target_os = "linux")]

//! Production-shaped authenticated departure control over a real TURN link.

use std::sync::{Arc, OnceLock};
use std::time::Duration;

use myownmesh_core::config::{
    NetworkConfig, RoutingPolicyConfig, SchedulerPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode, TurnCredential, TurnServer as IceTurnServer, TurnServiceConfig,
    SQLITE_DEFAULT_PAGE_SIZE_BYTES,
};
use myownmesh_core::engine::transport_lab::{attach_local, channel, depart_for_lab, spawn_network};
use myownmesh_core::events::{DropReason, MeshEvent, PeerEvent};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{
    transport_lab_connector_fixture_grant, transport_lab_remote_candidate_fixture_grant,
    transport_lab_remote_description_fixture_grant, ConnectorCallbackPolicy,
    FiniteResourceProvider, LocalApplicationResourceScope, ResourceClaim, ResourceClass,
    ResourceProviderPort, TransportLabCallbackWorkload, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
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

static PROCESS_CONTROL_LOCK: OnceLock<Arc<tokio::sync::Mutex<()>>> = OnceLock::new();

struct ProcessControlGuard {
    _lock: tokio::sync::OwnedMutexGuard<()>,
    previous_home: Option<std::ffi::OsString>,
}

impl Drop for ProcessControlGuard {
    fn drop(&mut self) {
        match &self.previous_home {
            Some(previous) => std::env::set_var("MYOWNMESH_HOME", previous),
            None => std::env::remove_var("MYOWNMESH_HOME"),
        }
    }
}

async fn exclusive_process_controls() -> ProcessControlGuard {
    let lock = PROCESS_CONTROL_LOCK
        .get_or_init(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
        .lock_owned()
        .await;
    ProcessControlGuard {
        _lock: lock,
        previous_home: std::env::var_os("MYOWNMESH_HOME"),
    }
}

fn policy() -> WebRtcConnectorCapablePolicy {
    let connectors = std::num::NonZeroU64::new(4).expect("connector bound is nonzero");
    let callback_slots = std::num::NonZeroUsize::new(16).expect("callback bound is nonzero");
    let frame_bytes = std::num::NonZeroU64::new(
        u64::try_from(myownmesh_signaling::mdns::wire::MAX_FRAME_BYTES)
            .expect("frame limit fits u64"),
    )
    .expect("frame limit is nonzero");
    let callback = TransportLabCallbackWorkload {
        control_slots: callback_slots,
        endpoint_slots: callback_slots,
        control_payload_bytes: 4_096,
        endpoint_payload_bytes: 16_384,
        realtime: None,
    };
    let profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    let profiles = vec![profile.clone(); connectors.get() as usize];
    let candidate_total_content = std::num::NonZeroU64::new(
        frame_bytes
            .get()
            .checked_mul(connectors.get())
            .expect("candidate content envelope fits u64"),
    )
    .expect("candidate content envelope is nonzero");
    let candidate_total_string_capacity = std::num::NonZeroU64::new(
        candidate_total_content
            .get()
            .checked_mul(3)
            .expect("candidate string envelope fits u64"),
    )
    .expect("candidate string envelope is nonzero");
    let candidate = transport_lab_remote_candidate_fixture_grant(
        candidate_total_content,
        connectors,
        candidate_total_string_capacity,
        candidate_total_content,
        frame_bytes,
    )
    .expect("candidate grant is representable");
    let descriptions = transport_lab_remote_description_fixture_grant(
        connectors,
        frame_bytes,
        std::num::NonZeroU64::new(1).expect("media section bound is nonzero"),
        std::num::NonZeroU64::new(1).expect("binding bound is nonzero"),
        frame_bytes,
    )
    .expect("description grant is representable");
    let json_work = myownmesh_core::application_gateway::json_input_work_claim(8 * 1024)
        .expect("JSON input claim is representable")
        .checked_scale(
            connectors
                .get()
                .checked_mul(2)
                .expect("JSON claim count is representable"),
        )
        .expect("JSON input capacity is representable");
    let grant = transport_lab_connector_fixture_grant(
        &profiles,
        std::num::NonZeroU64::new(4).expect("mesh scope bound is nonzero"),
        callback,
    )
    .expect("connector grant is representable")
    .checked_add(candidate)
    .and_then(|claim| claim.checked_add(descriptions))
    .and_then(|claim| claim.checked_add(json_work))
    .and_then(|claim| {
        // Alice and Bob are the only simultaneous semantic owners in this
        // departure control.  The process provider is funded for both exact
        // durable slots, not for an arbitrary max-database multiplier.
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
    .expect("TURN fixture grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("TURN fixture provider is valid");
    WebRtcConnectorCapablePolicy::new(resources, profile)
}

fn config(id: &str, turn_url: String) -> NetworkConfig {
    NetworkConfig {
        id: id.into(),
        network_id: "turn-depart-observed".into(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.into(),
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
            username: Some("depart-user".into()),
            credential: Some("depart-password".into()),
        }],
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

async fn wait_for_approved(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if matches!(
                events.recv().await.expect("event stream remains open"),
                MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) if device_id == peer_id
            ) {
                return;
            }
        }
    })
    .await
    .expect("TURN peers did not become approved");
}

async fn wait_for_user_left(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    tokio::time::timeout(TEST_TIMEOUT, async {
        loop {
            if matches!(
                events.recv().await.expect("event stream remains open"),
                MeshEvent::Peer(PeerEvent::Dropped { device_id, reason, .. })
                    if device_id == peer_id && reason == DropReason::UserLeft
            ) {
                return;
            }
        }
    })
    .await
    .expect("authenticated TURN departure was not observed");
}

#[tokio::test]
// Native TURN owns UDP sockets and is therefore opt-in for ordinary test
// suites; the Linux integration job invokes this exact ignored test.
#[ignore = "opens native TURN/WebRTC peers; run explicitly in the isolated Linux harness"]
async fn authenticated_depart_observed_over_actual_turn() {
    let _process_controls = exclusive_process_controls().await;
    let home = tempfile::tempdir().expect("isolated MyOwnMesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());
    let turn = TurnServer::start_with_resource_scope(
        &TurnServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
            public_ip: "127.0.0.1".into(),
            realm: "depart-control".into(),
            credentials: vec![TurnCredential {
                username: "depart-user".into(),
                password: "depart-password".into(),
            }],
            max_bps_per_connection: 0,
            relay_port_min: 0,
            relay_port_max: 0,
        },
        service_scope(),
    )
    .await
    .expect("real TURN service starts");
    let turn_url = format!("turn:{}?transport=udp", turn.local_addr());
    let transport = Transport::new_relay_only_for_lab()
        .expect("relay-only transport")
        .with_connector_resource_policy(policy())
        .expect("TURN policy is consistent");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());
    let (alice, alice_driver) = spawn_network(
        config("alice", turn_url.clone()),
        Arc::clone(&alice_id),
        transport.clone(),
    )
    .await
    .expect("alice engine starts");
    let (bob, bob_driver) = spawn_network(config("bob", turn_url), bob_id.clone(), transport)
        .await
        .expect("bob engine starts");
    let mut alice_events = alice.events_tx.subscribe();
    let mut bob_events = bob.events_tx.subscribe();
    let broker = LocalBroker::new();
    attach_local(&alice, &broker);
    attach_local(&bob, &broker);
    wait_for_approved(&mut alice_events, bob_id.public_id()).await;
    wait_for_approved(&mut bob_events, alice_id.public_id()).await;

    // Relay-only transport makes this the carrying channel for the
    // authenticated session. Prove its receipt settles before departure
    // retires the session, rather than treating relay selection as a shape
    // assertion around the teardown path.
    let alice_channel = channel::<String>("turn-receipt-before-close".into(), alice.clone());
    let mut bob_channel = channel::<String>("turn-receipt-before-close".into(), bob.clone())
        .subscribe()
        .expect("bob subscribes to the TURN carrying channel");
    alice_channel
        .send_to(bob_id.public_id(), &"turn-receipt".to_string())
        .await
        .expect("TURN carrying-channel receipt is accepted");
    let received = tokio::time::timeout(TEST_TIMEOUT, bob_channel.recv())
        .await
        .expect("TURN carrying-channel receipt timed out")
        .expect("TURN carrying channel closed before receipt")
        .expect("TURN carrying-channel receipt is valid");
    assert_eq!(received.body(), "turn-receipt");

    let departure = depart_for_lab(&alice).await;
    assert_eq!(departure.observed, 1);
    assert_eq!(departure.cancelled, 0);
    wait_for_user_left(&mut bob_events, alice_id.public_id()).await;
    assert_eq!(
        alice.peer_count(),
        0,
        "relay departure closes Alice only after its authenticated waiter completes"
    );
    assert_eq!(bob.peer_count(), 0);
    alice.request_shutdown();
    bob.request_shutdown();
    alice_driver.await.expect("alice shuts down cleanly");
    bob_driver.await.expect("bob shuts down cleanly");
    turn.stop().await.expect("TURN service stops cleanly");
}
