#![cfg(feature = "transport-lab")]

use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::events::{MeshEvent, PeerEvent};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::semantic::VerifiedBootstrap;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactGraph, MeshContextId, Role, SignedFact,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, TransportLabCallbackWorkload,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use myownmesh_signaling::local::LocalBroker;

// Native ICE gathering and endpoint-auth promotion are intentionally the same
// production path as the shipped two-daemon runner. Give that path the same
// bounded window instead of imposing a unit-test-sized deadline.
const STAGE_TIMEOUT: Duration = Duration::from_secs(90);

fn semantic_fact_page(
    context_id: MeshContextId,
    facts: &[SignedFact],
) -> myownmesh_core::semantic::SemanticFactPage {
    let facts = canonical_fact_order(facts);
    serde_json::from_value(serde_json::json!({
        "context_id": context_id,
        "facts": facts,
        "next_cursor": null,
        "complete": true,
    }))
    .expect("strict semantic page decodes")
}

fn canonical_fact_order(facts: &[SignedFact]) -> Vec<SignedFact> {
    let mut ordered = facts.to_vec();
    ordered.sort_unstable_by_key(|fact| fact.id);
    ordered
}

async fn bounded<T>(
    stage: &'static str,
    future: impl std::future::Future<Output = T>,
) -> myownmesh_core::Result<T> {
    eprintln!("production-relay stage begin: {stage}");
    match tokio::time::timeout(STAGE_TIMEOUT, future).await {
        Ok(value) => {
            eprintln!("production-relay stage complete: {stage}");
            Ok(value)
        }
        Err(_) => {
            eprintln!("production-relay stage timed out: {stage}");
            Err(myownmesh_core::Error::Network(format!(
                "relay stage timed out: {stage}"
            )))
        }
    }
}

fn init_relay_trace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "myownmesh_core::engine=trace,myownmesh_core::transport=debug",
        ))
        .with_test_writer()
        .try_init();
}

fn finite_connector_policy(
    session_identity: &str,
    share_identity: &Identity,
    share_peer: DeviceId,
    share_context: MeshContextId,
) -> (
    WebRtcConnectorCapablePolicy,
    FiniteResourceProvider,
    ResourceProviderPort,
) {
    let profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    // The complete fixture overlaps two original links with one replacement
    // before W0 is retired: three real links, two endpoints each.
    let connector_profiles = [
        profile.clone(),
        profile.clone(),
        profile.clone(),
        profile.clone(),
        profile.clone(),
        profile.clone(),
    ];
    let connector_count = NonZeroU64::new(
        u64::try_from(connector_profiles.len()).expect("connector profile count fits u64"),
    )
    .expect("connector count is nonzero");
    let max_relay_frame_bytes = usize::try_from(
        myownmesh_core::protocol::relay::closed_relay_worst_case_json_bytes(
            myownmesh_core::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES
                + myownmesh_core::protocol::relay::CLOSED_RELAY_AEAD_TAG_BYTES,
        )
        .expect("the maximum Closed relay frame size is representable"),
    )
    .expect("the maximum Closed relay frame size fits usize");
    let frame_bytes = NonZeroU64::new(
        u64::try_from(myownmesh_signaling::mdns::wire::MAX_FRAME_BYTES)
            .expect("frame limit fits u64"),
    )
    .expect("frame limit is nonzero");
    let candidate_content = NonZeroU64::new(
        frame_bytes
            .get()
            .checked_mul(connector_count.get())
            .expect("candidate content capacity fits u64"),
    )
    .expect("candidate content capacity is nonzero");
    let candidate_strings = NonZeroU64::new(
        candidate_content
            .get()
            .checked_mul(3)
            .expect("candidate string capacity fits u64"),
    )
    .expect("candidate string capacity is nonzero");
    let workload = TransportLabCallbackWorkload {
        control_slots: NonZeroUsize::new(64).expect("control slots are nonzero"),
        endpoint_slots: NonZeroUsize::new(64).expect("endpoint slots are nonzero"),
        control_payload_bytes: 16 * 1024,
        endpoint_payload_bytes: u64::try_from(max_relay_frame_bytes)
            .expect("the maximum Closed relay frame payload fits u64"),
        realtime: None,
    };
    // The raw connector grant funds callback/opening work only. Promotion
    // retains one exact Session Broker reservation per real-link endpoint, so
    // price six promoted sessions separately rather than borrowing slack
    // from connector construction.
    let promoted_sessions =
        myownmesh_core::session_reservation_planning_claim_for_correlation(session_identity)
            .checked_scale(connector_count.get())
            .expect("six promoted-session planning claims are representable");
    // Native inbound frames are parsed twice at a live connector boundary:
    // one retained Hello and one current application frame. Use the public
    // gateway formula at the maximum serialized Closed relay frame, then add
    // the provider reservation bookkeeping for each of the two claims and
    // each of the six connectors. The raw connector grant does not fund
    // promoted-session or application JSON parsing retention.
    let json_frame_reservation =
        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
            myownmesh_core::application_gateway::json_input_work_claim(max_relay_frame_bytes)
                .expect("the maximum-frame JSON claim is representable"),
        )
        .expect("the maximum-frame JSON reservation charge is representable");
    let json_parsing = json_frame_reservation
        .checked_scale(2)
        .and_then(|claim| claim.checked_scale(connector_count.get()))
        .expect("two maximum-frame JSON claims per connector are representable");
    let relay_grant = myownmesh_core::transport_lab_connector_fixture_grant(
        &connector_profiles,
        NonZeroU64::new(3).expect("mesh scope count is nonzero"),
        workload,
    )
    .expect("the finite connector fixture grant is representable")
    .checked_add(promoted_sessions)
    .and_then(|claim| claim.checked_add(json_parsing))
    .expect("the connector, session, and JSON grants combine without overflow")
    .checked_add(
        myownmesh_core::transport_lab_remote_candidate_fixture_grant(
            connector_count,
            connector_count,
            candidate_strings,
            candidate_content,
            frame_bytes,
        )
        .expect("the finite remote-candidate grant is representable"),
    )
    .expect("the candidate grant combines without overflow")
    .checked_add(
        ResourceClaim::try_from_entries([
            (
                ResourceClass::StorageObject,
                connector_count
                    .get()
                    .checked_mul(2)
                    .expect("applied candidate storage capacity fits u64"),
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                connector_count
                    .get()
                    .checked_mul(3)
                    .expect("applied candidate residual capacity fits u64"),
            ),
        ])
        .expect("the applied candidate retention claim is representable"),
    )
    .expect("the applied candidate retention combines without overflow")
    .checked_add(
        myownmesh_core::transport_lab_remote_description_fixture_grant(
            connector_count,
            frame_bytes,
            NonZeroU64::new(1).expect("one media section is nonzero"),
            NonZeroU64::new(1).expect("one active binding is nonzero"),
            frame_bytes,
        )
        .expect("the finite remote-description grant is representable"),
    )
    .expect("the combined finite connector grant is representable");
    let share_profile = ClosedRelayPolicyConfig {
        enabled: true,
        ..ClosedRelayPolicyConfig::default()
    };
    let share_witness =
        myownmesh_core::engine::transport_lab::transport_lab_pending_share_capacity_witness(
            share_identity,
            share_context,
            share_peer,
            DeviceId::from_canonical_str(session_identity)
                .expect("relay id is canonical for the share witness"),
            [0x51; 16],
            &share_profile,
        )
        .expect("generated key-share survives the exact JSON decode boundary");
    for (capacity, length) in [
        (
            share_witness.capacities.mesh,
            share_witness.decoded_lengths.mesh,
        ),
        (
            share_witness.capacities.from,
            share_witness.decoded_lengths.from,
        ),
        (
            share_witness.capacities.to,
            share_witness.decoded_lengths.to,
        ),
        (
            share_witness.capacities.signature,
            share_witness.decoded_lengths.signature,
        ),
    ] {
        assert!(
            capacity >= length,
            "decoded key-share capacity must upper-bound its retained string"
        );
    }
    let closed_relay_workload = myownmesh_core::engine::transport_lab::ClosedRelayFixtureWorkload {
        network_roots: NonZeroU64::new(3).expect("three Closed relay networks are nonzero"),
        endpoint_leases: NonZeroU64::new(10).expect("five endpoint pairs are nonzero"),
        pending_leases: NonZeroU64::new(1).expect("one pending lease is nonzero"),
        engine_allocations: NonZeroU64::new(5).expect("five engine allocations are nonzero"),
        runtime_allocations: NonZeroU64::new(5).expect("five runtime allocations are nonzero"),
        pending_expiry_tasks: NonZeroU64::new(5).expect("five expiry reservations are nonzero"),
        pending_share: share_witness.capacities,
    };
    let closed_relay_grant =
        myownmesh_core::engine::transport_lab::transport_lab_closed_relay_fixture_grant(
            &ClosedRelayPolicyConfig {
                enabled: true,
                ..ClosedRelayPolicyConfig::default()
            },
            closed_relay_workload,
        )
        .expect("the finite Closed relay fixture grant is representable");
    let closed_relay_components = [
        closed_relay_grant.runtime_roots,
        closed_relay_grant.engine_roots,
        closed_relay_grant.endpoint_leases,
        closed_relay_grant.pending_leases,
        closed_relay_grant.engine_allocations,
        closed_relay_grant.runtime_allocations,
        closed_relay_grant.pending_expiry_tasks,
    ]
    .into_iter()
    .try_fold(ResourceClaim::ZERO, |total, component| {
        total.checked_add(component)
    })
    .expect("Closed relay component totals are representable");
    assert_eq!(
        closed_relay_components, closed_relay_grant.total,
        "Closed relay grant exposes its exact checked component decomposition"
    );
    assert_eq!(
        closed_relay_grant
            .endpoint_leases
            .amount(ResourceClass::RelayOrProviderAllocation),
        10,
        "endpoint reservation count is charged once per planned endpoint lease"
    );
    assert_eq!(
        closed_relay_grant
            .pending_leases
            .amount(ResourceClass::RelayOrProviderAllocation),
        1,
        "pending reservation count is charged once per planned pending lease"
    );
    assert_eq!(
        closed_relay_grant
            .engine_allocations
            .amount(ResourceClass::RelayOrProviderAllocation),
        5,
        "engine allocation reservation count is charged once per planned allocation"
    );
    assert_eq!(
        closed_relay_grant
            .runtime_allocations
            .amount(ResourceClass::RelayOrProviderAllocation),
        5,
        "runtime allocation reservation count is charged once per planned allocation"
    );
    assert_eq!(
        closed_relay_grant
            .total
            .amount(ResourceClass::RelayOrProviderAllocation),
        21,
        "the five-open construction bound charges endpoint+pending+engine+runtime relay units"
    );
    let relay_grant = relay_grant
        .checked_add(closed_relay_grant.total)
        .expect("Closed relay grant combines without overflow");
    let semantic_policy = SemanticPolicyConfig::default();
    let semantic_storage_owner_count = 3_u64;
    let semantic_storage_claim = ResourceClaim::single(
        ResourceClass::StorageBytes,
        semantic_policy.max_database_bytes,
    );
    let semantic_storage_grant =
        FiniteResourceProvider::reservation_planning_charge(semantic_storage_claim)
            .expect("three-node semantic storage reservation is representable")
            .checked_scale(semantic_storage_owner_count)
            .expect("three-node semantic storage capacity is representable");
    let expected_storage_bytes = semantic_policy
        .max_database_bytes
        .checked_mul(semantic_storage_owner_count)
        .expect("three-node semantic storage bytes are representable");
    assert_eq!(
        semantic_storage_grant.amount(ResourceClass::StorageBytes),
        expected_storage_bytes,
        "semantic storage is funded exactly once per live network owner"
    );
    assert_eq!(
        semantic_storage_grant.amount(ResourceClass::OpaqueDependencyResidual),
        semantic_storage_owner_count,
        "semantic storage reserves exactly one provider record per live owner"
    );
    let grant = relay_grant
        .checked_add(semantic_storage_grant)
        .expect("relay and semantic grants combine without overflow");
    assert_eq!(
        grant.amount(ResourceClass::StorageBytes),
        expected_storage_bytes,
        "the three-node provider has no hidden storage slack"
    );
    let provider = FiniteResourceProvider::new(grant);
    let meter = provider.clone();
    let resources = ResourceProviderPort::new(provider).expect("finite provider is valid");
    let process_scope = resources.clone();
    (
        WebRtcConnectorCapablePolicy::new(resources, profile),
        meter,
        process_scope,
    )
}

fn network_config(id: &str, network_id: &str, relay: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.into(),
        network_id: network_id.into(),
        event_capacity: 256,
        connection_trace_capacity: 512,
        label: id.into(),
        kind: NetworkKind::Closed,
        semantic_policy: Default::default(),
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        application_transport: None,
        tree: None,
        scheduler: Default::default(),
        topology: TopologyMode::Star {
            hub: relay.to_string(),
        },
        signaling: SignalingConfig {
            strategy: "none".into(),
            mdns: false,
            ..SignalingConfig::default()
        },
        closed_relay: ClosedRelayPolicyConfig {
            enabled: true,
            pending_handshake_timeout_ms: ClosedRelayPolicyConfig::default()
                .pending_handshake_timeout_ms,
            ..ClosedRelayPolicyConfig::default()
        },
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

fn member_grant(graph: &FactGraph, signer: &Identity, target: DeviceId) -> SignedFact {
    let author = DeviceId::from_public_key_bytes(*signer.verifying_key().as_bytes())
        .expect("signer id is canonical");
    let body = FactBody::RoleGrant {
        target,
        role: Role::Member,
    };
    let witness = graph.authoring_witness(&body, &author);
    SignedFact::sign(
        FactContent::from_authoring_witness(graph, body, &witness, []),
        signer.signing_key(),
    )
    .expect("root-signed member grant is valid")
}

async fn wait_for_authenticated_and_approved(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    expected: &[String],
) {
    let mut authenticated = vec![false; expected.len()];
    let mut approved = vec![false; expected.len()];
    while approved.iter().any(|ready| !ready) {
        let event = events.recv().await.expect("mesh event stream remains live");
        let (device_id, is_authenticated, is_approved) = match event {
            MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. }) => (device_id, true, false),
            MeshEvent::Peer(PeerEvent::Approved { device_id, .. }) => (device_id, false, true),
            _ => continue,
        };
        let Some(index) = expected.iter().position(|peer| peer == &device_id) else {
            continue;
        };
        if is_authenticated {
            authenticated[index] = true;
        }
        if is_approved {
            assert!(
                authenticated[index],
                "promotion must follow authenticated Hello/AuthResponse for {device_id}"
            );
            approved[index] = true;
        }
    }
}

fn assert_active_profile(network: &myownmesh_core::JoinedNetwork, peer: &str) {
    let info = network
        .peer(peer)
        .expect("the exact promoted peer is observable");
    assert!(matches!(info.status, PeerStatus::Active));
    assert!(info.authenticated);
    let profile = info
        .authenticated_profile()
        .expect("active peer has a redacted authenticated profile");
    assert_eq!(profile.protocol_version, myownmesh_core::PROTOCOL_VERSION);
    assert!(profile.endpoint_auth_v1);
}

fn assert_baseline(label: &str, before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} pre-auth {:?} active baseline",
            before.family
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} pre-auth {:?} lease baseline",
            before.family
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(
            after.active, before.active,
            "{label} post-auth {:?} active baseline",
            before.family
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} post-auth {:?} lease baseline",
            before.family
        );
    }
}

fn first_payload_diagnostics(
    label: &str,
    alice_net: &myownmesh_core::JoinedNetwork,
    relay_net: &myownmesh_core::JoinedNetwork,
    carol_net: &myownmesh_core::JoinedNetwork,
    relay_id: &str,
    alice_id: &str,
    carol_id: &str,
) {
    eprintln!(
        "production-relay first-payload {label}: peers alice->relay={:?} relay->alice={:?} relay->carol={:?} carol->relay={:?}",
        alice_net.peer(relay_id),
        relay_net.peer(alice_id),
        relay_net.peer(carol_id),
        carol_net.peer(relay_id),
    );
    eprintln!(
        "production-relay first-payload {label}: resources alice={:?} relay={:?} carol={:?}",
        alice_net.resource_report(),
        relay_net.resource_report(),
        carol_net.resource_report(),
    );
}

async fn exact_transport_diagnostics(
    label: &str,
    alice_net: &myownmesh_core::JoinedNetwork,
    relay_net: &myownmesh_core::JoinedNetwork,
    sender: &myownmesh_core::engine::transport_lab::TransportChannelWitness,
    receiver: &myownmesh_core::engine::transport_lab::TransportChannelWitness,
) {
    let sender_snapshot = alice_net.transport_channel_snapshot_for_lab(sender).await;
    let receiver_snapshot = relay_net.transport_channel_snapshot_for_lab(receiver).await;
    assert!(
        sender_snapshot.is_some(),
        "{label}: captured Alice-to-relay channel remains observable"
    );
    assert!(
        receiver_snapshot.is_some(),
        "{label}: captured relay-from-Alice channel remains observable"
    );
    eprintln!(
        "production-relay exact-channel {label}: sender={sender_snapshot:?} receiver={receiver_snapshot:?}"
    );
}

// Match the shipped daemon's multi-thread Tokio runtime. Native WebRTC owns
// callbacks and worker threads that are not representative on the macro's
// default current-thread test runtime.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_members_relay_through_production_local_broker() -> myownmesh_core::Result<()> {
    init_relay_trace();
    let home = tempfile::tempdir().expect("temporary mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let alice = Arc::new(Identity::ephemeral());
    let relay = Arc::new(Identity::ephemeral());
    let carol = Arc::new(Identity::ephemeral());
    let alice_id = alice.public_id().to_string();
    let relay_id = relay.public_id().to_string();
    let carol_id = carol.public_id().to_string();
    let network_id = "closed-member-relay-production";

    let bootstrap = VerifiedBootstrap::create_closed(network_id, [alice.signing_key()], [0x91; 32])
        .expect("closed bootstrap is valid");
    let record = bootstrap.record().clone();
    let context_id = bootstrap.context_id();
    let mut graph = FactGraph::from_bootstrap(&bootstrap);
    let grant_relay = member_grant(
        &graph,
        &alice,
        DeviceId::from_canonical_str(&relay_id).expect("relay id is canonical"),
    );
    graph
        .admit(grant_relay.clone())
        .expect("relay grant admits");
    let grant_carol = member_grant(
        &graph,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("Carol id is canonical"),
    );
    let member_facts = vec![grant_relay, grant_carol];
    // Exercise the wire-page contract independently from causal authoring
    // order: pages are FactId-ordered, while signed bodies retain the
    // dependencies established by the authoring graph above.
    let mut reverse_page_facts = canonical_fact_order(&member_facts);
    reverse_page_facts.reverse();
    let canonical_page_facts = canonical_fact_order(&reverse_page_facts);
    let supplied_ids: Vec<_> = reverse_page_facts.iter().map(|fact| fact.id).collect();
    let canonical_ids: Vec<_> = canonical_page_facts.iter().map(|fact| fact.id).collect();
    assert_ne!(
        supplied_ids, canonical_ids,
        "reverse page input is discriminating"
    );
    assert!(canonical_ids.windows(2).all(|pair| pair[0] < pair[1]));

    let (policy, provider, process_scope) = finite_connector_policy(
        &relay_id,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("Carol id is canonical"),
        context_id,
    );
    let alice_mesh = bounded(
        "open Alice mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), alice, policy.clone()),
    )
    .await??;
    let relay_mesh = bounded(
        "open relay mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), relay, policy.clone()),
    )
    .await??;
    let carol_mesh = bounded(
        "open Carol mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), carol, policy),
    )
    .await??;
    let baseline_alice = alice_mesh.resource_report();
    let baseline_relay = relay_mesh.resource_report();
    let baseline_carol = carol_mesh.resource_report();
    let provider_baseline = provider.in_use();
    let provider_failed_cleanup_baseline = provider.retained_after_failed_cleanup();
    let provider_reservations_baseline = provider.active_reservations();
    let provider_scopes_baseline = provider.active_scopes();
    let process_scope_id = process_scope.process_scope().id();

    let alice_net = bounded(
        "create Alice network",
        alice_mesh.create_network(network_config("alice", network_id, &relay_id), [0x91; 32]),
    )
    .await??;
    let relay_net = bounded(
        "import relay network",
        relay_mesh.import_network(
            network_config("relay", network_id, &relay_id),
            context_id,
            record.clone(),
        ),
    )
    .await??;
    let carol_net = bounded(
        "import Carol network",
        carol_mesh.import_network(
            network_config("carol", network_id, &relay_id),
            context_id,
            record,
        ),
    )
    .await??;
    for network in [&alice_net, &relay_net, &carol_net] {
        bounded(
            "import member facts",
            network.import_semantic_fact_page(semantic_fact_page(context_id, &reverse_page_facts)),
        )
        .await??;
    }

    let mut alice_events = alice_mesh.events();
    let mut relay_events = relay_mesh.events();
    let mut carol_events = carol_mesh.events();
    let relay_expected = [alice_id.clone(), carol_id.clone()];
    let broker = LocalBroker::new();
    alice_net.attach_local(&broker);
    relay_net.attach_local(&broker);
    carol_net.attach_local(&broker);

    let (alice_ready, relay_ready, carol_ready) = tokio::join!(
        bounded(
            "Alice-relay production handshake",
            wait_for_authenticated_and_approved(&mut alice_events, std::slice::from_ref(&relay_id)),
        ),
        bounded(
            "relay production handshakes",
            wait_for_authenticated_and_approved(&mut relay_events, &relay_expected),
        ),
        bounded(
            "Carol-relay production handshake",
            wait_for_authenticated_and_approved(&mut carol_events, std::slice::from_ref(&relay_id)),
        ),
    );
    alice_ready?;
    relay_ready?;
    carol_ready?;

    // Reinstall the same authenticated device identity over a fresh real
    // connector after the LocalBroker promotion.  The public transport-lab
    // seam performs the same PeerRegistry replacement boundary as production;
    // the route assertions below therefore exercise W1 rather than merely a
    // second logical Closed-relay session.
    let alice_relay_w1 = bounded(
        "replace Alice-relay owner installation",
        alice_net.install_promoted_peer_over_real_link(&relay_net),
    )
    .await?;
    assert_eq!(alice_relay_w1.peer_device_id(), relay_id);
    assert_active_profile(&alice_net, &relay_id);
    assert_active_profile(&relay_net, &alice_id);

    assert_active_profile(&alice_net, &relay_id);
    assert_active_profile(&relay_net, &alice_id);
    assert_active_profile(&relay_net, &carol_id);
    assert_active_profile(&carol_net, &relay_id);
    assert!(!alice_net
        .peer(&carol_id)
        .is_some_and(|peer| matches!(peer.status, PeerStatus::Active)));
    assert!(!carol_net
        .peer(&alice_id)
        .is_some_and(|peer| matches!(peer.status, PeerStatus::Active)));

    let (alice_channel, carol_channel) = tokio::join!(
        bounded(
            "open Alice-Carol relay",
            alice_net.open_closed_relay(&relay_id, &carol_id),
        ),
        bounded("accept Alice-Carol relay", carol_net.accept_closed_relay()),
    );
    let alice_channel = alice_channel??;
    let carol_channel = carol_channel??;
    assert_eq!(alice_channel.peer_device_id(), carol_id);
    assert_eq!(alice_channel.relay_device_id(), relay_id);
    assert_eq!(carol_channel.peer_device_id(), alice_id);
    assert_eq!(carol_channel.relay_device_id(), relay_id);
    assert_eq!(alice_channel.session_id(), carol_channel.session_id());
    assert_ne!(alice_channel.session_id(), [0; 16]);

    let alice_sender_witness = alice_net
        .capture_transport_channel_for_lab(&relay_id)
        .expect("capture the exact Alice-to-relay worker before first payload");
    let relay_receiver_witness = relay_net
        .capture_transport_channel_for_lab(&alice_id)
        .expect("capture the exact relay-from-Alice worker before first payload");
    let sentinel = b"closed-relay plaintext must not reach B".to_vec();
    exact_transport_diagnostics(
        "before Alice send",
        &alice_net,
        &relay_net,
        &alice_sender_witness,
        &relay_receiver_witness,
    )
    .await;
    first_payload_diagnostics(
        "before Alice send",
        &alice_net,
        &relay_net,
        &carol_net,
        &relay_id,
        &alice_id,
        &carol_id,
    );
    bounded(
        "send Alice-to-Carol opaque payload",
        alice_channel.send(&sentinel),
    )
    .await??;
    exact_transport_diagnostics(
        "after Alice send",
        &alice_net,
        &relay_net,
        &alice_sender_witness,
        &relay_receiver_witness,
    )
    .await;
    first_payload_diagnostics(
        "after Alice send",
        &alice_net,
        &relay_net,
        &carol_net,
        &relay_id,
        &alice_id,
        &carol_id,
    );
    let received = bounded("receive Alice-to-Carol payload", carol_channel.recv()).await;
    if received.as_ref().map_or(true, |result| result.is_err()) {
        exact_transport_diagnostics(
            "Alice receive timeout/failure",
            &alice_net,
            &relay_net,
            &alice_sender_witness,
            &relay_receiver_witness,
        )
        .await;
        first_payload_diagnostics(
            "Alice receive failure",
            &alice_net,
            &relay_net,
            &carol_net,
            &relay_id,
            &alice_id,
            &carol_id,
        );
    }
    assert_eq!(received??, sentinel);
    let reverse = b"Carol-to-Alice opaque reply".to_vec();
    bounded(
        "send Carol-to-Alice opaque payload",
        carol_channel.send(&reverse),
    )
    .await??;
    assert_eq!(
        bounded("receive Carol-to-Alice payload", alice_channel.recv()).await??,
        reverse
    );
    // B owns only the authenticated relay legs.  No public endpoint handle or
    // plaintext receive path exists on B; the sentinel crossed only A's/C's
    // endpoint sessions while the B leg remained a keyless forwarder.

    drop(alice_sender_witness);
    drop(relay_receiver_witness);

    bounded("close Carol endpoint", carol_channel.close()).await??;
    let _ = bounded("close Alice endpoint", alice_channel.close()).await;
    let _ = bounded(
        "retire replacement Alice-relay owner",
        alice_relay_w1.retire(),
    )
    .await?;
    bounded("shutdown Alice network", alice_net.shutdown()).await??;
    bounded("shutdown relay network", relay_net.shutdown()).await??;
    bounded("shutdown Carol network", carol_net.shutdown()).await??;
    drop(alice_net);
    drop(relay_net);
    drop(carol_net);
    assert_baseline("Alice", &baseline_alice, &alice_mesh.resource_report());
    assert_baseline("relay", &baseline_relay, &relay_mesh.resource_report());
    assert_baseline("Carol", &baseline_carol, &carol_mesh.resource_report());
    assert_eq!(
        provider.in_use(),
        provider_baseline,
        "provider in-use claim returns to its exact pre-network baseline"
    );
    assert_eq!(
        provider.retained_after_failed_cleanup(),
        provider_failed_cleanup_baseline,
        "failed-cleanup retention returns to its exact pre-network baseline"
    );
    assert_eq!(
        provider.active_reservations(),
        provider_reservations_baseline,
        "provider reservation cardinality returns to its exact pre-network baseline"
    );
    assert_eq!(
        provider.active_scopes(),
        provider_scopes_baseline,
        "provider scope cardinality returns to its exact pre-network baseline"
    );
    assert_eq!(
        process_scope.process_scope().id(),
        process_scope_id,
        "the process scope identity remains stable for the provider lifetime"
    );
    Ok(())
}
