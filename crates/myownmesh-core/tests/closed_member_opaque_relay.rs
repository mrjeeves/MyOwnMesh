#![cfg(feature = "transport-lab")]

use std::future::Future;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SemanticPolicyConfig,
    SignalingConfig, TopologyMode,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::resource::{
    PostAuthResourceFamily, PreAuthResourceFamily, ResourceFamilyReport, ResourceReport,
    ResourceUse,
};
use myownmesh_core::semantic::VerifiedBootstrap;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactGraph, MeshContextId, Role, SignedFact,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, FiniteResourceProvider, Identity, Mesh, MeshConfig, ResourceClaim,
    ResourceClass, ResourceProviderPort, TransportLabCallbackWorkload,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};

const STAGE_TIMEOUT: Duration = Duration::from_secs(10);

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

fn semantic_fact_page(
    context_id: MeshContextId,
    facts: &[SignedFact],
) -> myownmesh_core::semantic::SemanticFactPage {
    // The wire page is an ordered projection, while the signed facts remain
    // byte-for-byte unchanged.  Deliberately accept the fixture's reverse
    // order here so a successful import proves the canonical page rule rather
    // than depending on the random order in which the two signatures hash.
    let mut canonical = facts.to_vec();
    canonical.sort_unstable_by_key(|fact| fact.id);
    assert!(
        canonical.windows(2).all(|pair| pair[0].id < pair[1].id),
        "membership page facts must have distinct canonical IDs"
    );
    serde_json::from_value(serde_json::json!({
        "context_id": context_id,
        "facts": canonical,
        "next_cursor": null,
        "complete": true,
    }))
    .expect("strict semantic page decodes")
}

async fn bounded_value<T>(
    stage: &'static str,
    future: impl Future<Output = T>,
) -> myownmesh_core::Result<T> {
    tokio::time::timeout(STAGE_TIMEOUT, future)
        .await
        .map_err(|_| {
            myownmesh_core::Error::Network(format!("closed relay stage timed out: {stage}"))
        })
}

async fn bounded_result<T>(
    stage: &'static str,
    future: impl Future<Output = myownmesh_core::Result<T>>,
) -> myownmesh_core::Result<T> {
    let outcome = bounded_value(stage, future).await;
    match &outcome {
        Err(error) => eprintln!("[closed-relay-stage] timeout stage={stage}: {error:?}"),
        Ok(Err(error)) => eprintln!("[closed-relay-stage] error stage={stage}: {error:?}"),
        Ok(Ok(_)) => {}
    }
    outcome?
}

fn init_relay_trace() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(
            "myownmesh_core::engine=trace,myownmesh_core::transport=debug",
        ))
        .with_test_writer()
        .try_init();
}

fn assert_live_custody_baseline(label: &str, before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(
            after.family, before.family,
            "{label} family identity is stable"
        );
        assert_eq!(
            after.active, before.active,
            "{label} live custody returned to baseline"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} live lease count returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state returned to baseline"
        );
        // Precision metadata is scope-wide sticky history: an inexact
        // transport observation may set it during the lifecycle, but it must
        // never disappear after cleanup.
        assert!(
            !before.measurement_inexact || after.measurement_inexact,
            "{label} measurement precision state is monotonic"
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(
            after.family, before.family,
            "{label} family identity is stable"
        );
        assert_eq!(
            after.active, before.active,
            "{label} live custody returned to baseline"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} live lease count returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence returned to baseline"
        );
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state returned to baseline"
        );
        assert!(
            !before.measurement_inexact || after.measurement_inexact,
            "{label} measurement precision state is monotonic"
        );
    }
}

fn assert_no_activity_baseline(label: &str, before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(
            after.family, before.family,
            "{label} family identity is stable"
        );
        assert_eq!(
            after.active, before.active,
            "{label} active use is unchanged"
        );
        assert_eq!(
            after.peak_active, before.peak_active,
            "{label} peak active use is unchanged"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} active lease count is unchanged"
        );
        assert_eq!(
            after.peak_active_lease_count, before.peak_active_lease_count,
            "{label} peak active lease count is unchanged"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence is unchanged"
        );
        if let (Some(before_age), Some(after_age)) =
            (before.oldest_active_lifetime, after.oldest_active_lifetime)
        {
            assert!(
                after_age >= before_age,
                "{label} oldest-active age must not move backwards"
            );
        }
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state is unchanged"
        );
        assert_eq!(
            after.completed_lease_count, before.completed_lease_count,
            "{label} completed lease count is unchanged"
        );
        assert_eq!(
            after.completed_total_use, before.completed_total_use,
            "{label} completed use is unchanged"
        );
        assert_eq!(
            after.completed_total_lifetime, before.completed_total_lifetime,
            "{label} completed lifetime is unchanged"
        );
        assert_eq!(
            after.measurement_inexact, before.measurement_inexact,
            "{label} measurement precision state is unchanged"
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(
            after.family, before.family,
            "{label} family identity is stable"
        );
        assert_eq!(
            after.active, before.active,
            "{label} active use is unchanged"
        );
        assert_eq!(
            after.peak_active, before.peak_active,
            "{label} peak active use is unchanged"
        );
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "{label} active lease count is unchanged"
        );
        assert_eq!(
            after.peak_active_lease_count, before.peak_active_lease_count,
            "{label} peak active lease count is unchanged"
        );
        assert_eq!(
            after.oldest_active_lifetime.is_some(),
            before.oldest_active_lifetime.is_some(),
            "{label} oldest-active presence is unchanged"
        );
        if let (Some(before_age), Some(after_age)) =
            (before.oldest_active_lifetime, after.oldest_active_lifetime)
        {
            assert!(
                after_age >= before_age,
                "{label} oldest-active age must not move backwards"
            );
        }
        assert_eq!(
            after.oldest_active_lifetime_inexact, before.oldest_active_lifetime_inexact,
            "{label} oldest-active precision state is unchanged"
        );
        assert_eq!(
            after.completed_lease_count, before.completed_lease_count,
            "{label} completed lease count is unchanged"
        );
        assert_eq!(
            after.completed_total_use, before.completed_total_use,
            "{label} completed use is unchanged"
        );
        assert_eq!(
            after.completed_total_lifetime, before.completed_total_lifetime,
            "{label} completed lifetime is unchanged"
        );
        assert_eq!(
            after.measurement_inexact, before.measurement_inexact,
            "{label} measurement precision state is unchanged"
        );
    }
}

fn assert_inexact_transport_observed(label: &str, report: &ResourceReport) {
    assert!(
        report
            .pre_authentication
            .iter()
            .any(|family| family.measurement_inexact)
            || report
                .post_authentication
                .iter()
                .any(|family| family.measurement_inexact),
        "{label} final report records an inexact transport observation"
    );
}

fn synthetic_resource_report(oldest_active_lifetime: Duration) -> ResourceReport {
    ResourceReport {
        pre_authentication: PreAuthResourceFamily::ALL.map(|family| ResourceFamilyReport {
            family,
            active: ResourceUse::observed(1, 0, 0, 1),
            peak_active: ResourceUse::observed(1, 0, 0, 1),
            active_lease_count: 1,
            peak_active_lease_count: 1,
            oldest_active_lifetime: Some(oldest_active_lifetime),
            oldest_active_lifetime_inexact: false,
            completed_lease_count: 0,
            completed_total_use: ResourceUse::ZERO,
            completed_total_lifetime: Duration::ZERO,
            measurement_inexact: false,
        }),
        post_authentication: PostAuthResourceFamily::ALL.map(|family| ResourceFamilyReport {
            family,
            active: ResourceUse::observed(1, 0, 0, 1),
            peak_active: ResourceUse::observed(1, 0, 0, 1),
            active_lease_count: 1,
            peak_active_lease_count: 1,
            oldest_active_lifetime: Some(oldest_active_lifetime),
            oldest_active_lifetime_inexact: false,
            completed_lease_count: 0,
            completed_total_use: ResourceUse::ZERO,
            completed_total_lifetime: Duration::ZERO,
            measurement_inexact: false,
        }),
    }
}

#[test]
fn resource_report_baseline_helpers_distinguish_live_and_history() {
    let before = synthetic_resource_report(Duration::from_millis(5));
    let mut after = synthetic_resource_report(Duration::from_millis(8));
    assert_no_activity_baseline("age-only observation", &before, &after);
    assert_live_custody_baseline("age-only observation", &before, &after);

    after.pre_authentication[0].completed_lease_count = 1;
    after.pre_authentication[0].completed_total_use = ResourceUse::observed(1, 0, 0, 1);
    after.pre_authentication[0].completed_total_lifetime = Duration::from_millis(1);
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_no_activity_baseline("completed-history change", &before, &after);
    }))
    .is_err());
    assert_live_custody_baseline("completed-history change", &before, &after);

    for change in ["active", "lease count", "family"] {
        let mut changed = synthetic_resource_report(Duration::from_millis(8));
        match change {
            "active" => changed.pre_authentication[0].active = ResourceUse::observed(1, 0, 0, 0),
            "lease count" => changed.pre_authentication[0].active_lease_count = 2,
            "family" => changed.pre_authentication[0].family = PreAuthResourceFamily::Cleanup,
            _ => unreachable!(),
        }
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_live_custody_baseline(change, &before, &changed);
        }))
        .is_err());
    }
    for post_authentication in [false, true] {
        let mut inexact = synthetic_resource_report(Duration::from_millis(8));
        if post_authentication {
            inexact.post_authentication[0].measurement_inexact = true;
        } else {
            inexact.pre_authentication[0].measurement_inexact = true;
        }
        assert_live_custody_baseline("sticky precision acquired", &before, &inexact);
        assert_live_custody_baseline("sticky precision retained", &inexact, &inexact);
        assert_inexact_transport_observed("positive observation", &inexact);
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_live_custody_baseline("sticky precision cannot reset", &inexact, &before);
        }))
        .is_err());
        assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_no_activity_baseline("precision change is activity", &before, &inexact);
        }))
        .is_err());
    }
    assert!(std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        assert_inexact_transport_observed("missing observation must fail", &before);
    }))
    .is_err());
}

fn resource_snapshot(
    stage: &'static str,
    provider: &FiniteResourceProvider,
    meshes: &[(&'static str, &myownmesh_core::MeshHandle)],
) {
    let in_use = provider.in_use();
    eprintln!(
        "[closed-relay-resource] stage={stage} WorkerOrTask={} NativeTransportObject={} active_reservations={} active_scopes={}",
        in_use.amount(ResourceClass::WorkerOrTask),
        in_use.amount(ResourceClass::NativeTransportObject),
        provider.active_reservations(),
        provider.active_scopes(),
    );
    for (name, mesh) in meshes {
        if let Some(report) = mesh.connector_resource_report() {
            eprintln!(
                "[closed-relay-resource] stage={stage} mesh={name} active_candidates={} failed_cleanup_candidates={} queued_jobs={} active_jobs={}",
                report.active_candidates,
                report.failed_cleanup_candidates,
                report.cleanup.queued_jobs,
                report.cleanup.active_jobs,
            );
        }
    }
}

fn connector_policy(
    session_identity: &str,
    share_identity: &Identity,
    share_peer: DeviceId,
    share_context: MeshContextId,
) -> (WebRtcConnectorCapablePolicy, FiniteResourceProvider) {
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
    let claim = relay_grant
        .checked_add(semantic_storage_grant)
        .expect("relay and semantic grants combine without overflow");
    assert_eq!(
        claim.amount(ResourceClass::StorageBytes),
        expected_storage_bytes,
        "the three-node provider has no hidden storage slack"
    );
    let finite = FiniteResourceProvider::new(claim);
    let meter = finite.clone();
    let resources = ResourceProviderPort::new(finite)
        .expect("the finite provider accounts for its process scope");
    (WebRtcConnectorCapablePolicy::new(resources, profile), meter)
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
        topology: TopologyMode::Star { hub: relay.into() },
        signaling: SignalingConfig::default(),
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

// Match the production-shaped relay runtime while keeping the libtest root
// future small: Tokio's macro still polls that root on the calling test
// thread, so the complete scenario is spawned onto a worker below.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn closed_members_exchange_opaque_payloads_only_through_relay() -> myownmesh_core::Result<()>
{
    tokio::spawn(closed_members_exchange_opaque_payloads_only_through_relay_inner())
        .await
        .expect("opaque relay scenario task joined")
}

async fn closed_members_exchange_opaque_payloads_only_through_relay_inner(
) -> myownmesh_core::Result<()> {
    init_relay_trace();
    let home = tempfile::tempdir().expect("temporary mesh home");
    // This control runs as one isolated integration-test process. The public
    // Mesh constructors retain the provider and all durable network state;
    // the temporary home prevents fixture state from crossing test runs.
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let alice = Arc::new(Identity::ephemeral());
    let relay = Arc::new(Identity::ephemeral());
    let carol = Arc::new(Identity::ephemeral());
    let alice_id = alice.public_id().to_string();
    let relay_id = relay.public_id().to_string();
    let carol_id = carol.public_id().to_string();
    let network_id = "closed-opaque-relay-e2e";

    let bootstrap = VerifiedBootstrap::create_closed(network_id, [alice.signing_key()], [0x91; 32])
        .expect("closed bootstrap is valid");
    let record = bootstrap.record().clone();
    let context_id = bootstrap.context_id();
    let mut fact_graph = FactGraph::from_bootstrap(&bootstrap);
    let grant_relay = member_grant(
        &fact_graph,
        &alice,
        DeviceId::from_canonical_str(&relay_id).expect("relay id is canonical"),
    );
    fact_graph
        .admit(grant_relay.clone())
        .expect("relay member grant admits");
    let grant_carol = member_grant(
        &fact_graph,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("target id is canonical"),
    );
    let mut signed_members = vec![grant_relay, grant_carol];
    signed_members.sort_unstable_by_key(|fact| fact.id);
    let signed_members_wire: Vec<_> = signed_members.iter().rev().cloned().collect();
    assert_eq!(signed_members_wire.len(), 2);
    assert!(signed_members_wire[0].id > signed_members_wire[1].id);

    let (policy, provider) = connector_policy(
        &relay_id,
        &alice,
        DeviceId::from_canonical_str(&carol_id).expect("Carol id is canonical"),
        context_id,
    );
    resource_snapshot("policy", &provider, &[]);
    let alice_mesh = bounded_result(
        "open Alice mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), alice, policy.clone()),
    )
    .await?;
    resource_snapshot("mesh-open-alice", &provider, &[("alice", &alice_mesh)]);
    let relay_mesh = bounded_result(
        "open relay mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), relay, policy.clone()),
    )
    .await?;
    resource_snapshot(
        "mesh-open-relay",
        &provider,
        &[("alice", &alice_mesh), ("relay", &relay_mesh)],
    );
    let carol_mesh = bounded_result(
        "open Carol mesh",
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), carol, policy),
    )
    .await?;
    resource_snapshot(
        "mesh-open-carol",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    let baseline_alice = alice_mesh.resource_report();
    let baseline_relay = relay_mesh.resource_report();
    let baseline_carol = carol_mesh.resource_report();
    let provider_baseline = provider.in_use();
    let provider_failed_cleanup_baseline = provider.retained_after_failed_cleanup();
    let provider_reservations_baseline = provider.active_reservations();
    let provider_scopes_baseline = provider.active_scopes();

    // An invalid finite relay profile is refused before NetworkState admits
    // any pending handshake or allocation. Keep this production constructor
    // control separate from the live three-member route below so a refusal
    // cannot borrow or contaminate its custody.
    let mut refused_profile = network_config(
        "invalid-closed-relay",
        "closed-opaque-relay-invalid-profile",
        &relay_id,
    );
    refused_profile.closed_relay.max_allocations = 0;
    assert!(!refused_profile.closed_relay.validate());
    let refused_network = bounded_result(
        "reject invalid closed relay profile",
        alice_mesh.create_network(refused_profile, [0x91; 32]),
    )
    .await;
    assert!(matches!(
        refused_network,
        Err(myownmesh_core::Error::Network(_))
    ));
    assert_no_activity_baseline(
        "profile refusal",
        &baseline_alice,
        &alice_mesh.resource_report(),
    );

    let alice_net = bounded_result(
        "create Alice network",
        alice_mesh.create_network(network_config("alice", network_id, &relay_id), [0x91; 32]),
    )
    .await?;
    resource_snapshot(
        "network-create-alice",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    let relay_net = bounded_result(
        "import relay network",
        relay_mesh.import_network(
            network_config("relay", network_id, &relay_id),
            context_id,
            record.clone(),
        ),
    )
    .await?;
    resource_snapshot(
        "network-import-relay",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    let carol_net = bounded_result(
        "import Carol network",
        carol_mesh.import_network(
            network_config("carol", network_id, &relay_id),
            context_id,
            record,
        ),
    )
    .await?;
    resource_snapshot(
        "network-import-carol",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );

    // Membership is admitted through the public durable reducer on every
    // member. No engine/runtime/key state is used by this control.
    bounded_result(
        "import Alice membership facts",
        alice_net.import_semantic_fact_page(semantic_fact_page(context_id, &signed_members_wire)),
    )
    .await?;
    resource_snapshot(
        "facts-import-alice",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    bounded_result(
        "import relay membership facts",
        relay_net.import_semantic_fact_page(semantic_fact_page(context_id, &signed_members_wire)),
    )
    .await?;
    resource_snapshot(
        "facts-import-relay",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    bounded_result(
        "import Carol membership facts",
        carol_net.import_semantic_fact_page(semantic_fact_page(context_id, &signed_members_wire)),
    )
    .await?;
    resource_snapshot(
        "facts-import-carol",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    for network in [&alice_net, &relay_net, &carol_net] {
        let roster = bounded_result("read member roster", network.roster_list()).await?;
        assert!(roster.iter().any(|peer| peer.device_id == relay_id));
        assert!(roster.iter().any(|peer| peer.device_id == carol_id));
    }

    resource_snapshot(
        "before-first-link",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    let alice_relay_w0 = bounded_value(
        "install Alice-relay link",
        alice_net.install_promoted_peer_over_real_link(&relay_net),
    )
    .await?;
    resource_snapshot(
        "after-first-link",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    resource_snapshot(
        "before-second-link",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    let relay_carol = bounded_value(
        "install relay-Carol link",
        relay_net.install_promoted_peer_over_real_link(&carol_net),
    )
    .await?;
    resource_snapshot(
        "after-second-link",
        &provider,
        &[
            ("alice", &alice_mesh),
            ("relay", &relay_mesh),
            ("carol", &carol_mesh),
        ],
    );
    assert_eq!(alice_relay_w0.peer_device_id(), relay_id);
    assert_eq!(relay_carol.peer_device_id(), carol_id);
    assert!(alice_net.peer(&carol_id).is_none(), "no direct A-C session");
    assert!(carol_net.peer(&alice_id).is_none(), "no direct C-A session");
    assert!(alice_net.peer(&relay_id).is_some());
    assert!(carol_net.peer(&relay_id).is_some());

    // Route mismatches are refused before any pending or admitted relay
    // custody is created. The public facade generates session IDs, so these
    // malformed routes are the production-shaped admission boundary exposed
    // to an integration test.
    let relay_before_route_refusals = relay_mesh.resource_report();
    for (label, relay_name, target_name) in [
        ("direct Alice-Carol route", &carol_id, &carol_id),
        ("relay-target collision", &relay_id, &relay_id),
        ("requester-target collision", &relay_id, &alice_id),
    ] {
        let refused =
            bounded_result(label, alice_net.open_closed_relay(relay_name, target_name)).await;
        assert!(matches!(
            refused,
            Err(myownmesh_core::Error::ClosedRelay(
                myownmesh_core::error::ClosedRelayError::InvalidPacket
            ))
        ));
    }
    assert_no_activity_baseline(
        "route refusal",
        &relay_before_route_refusals,
        &relay_mesh.resource_report(),
    );

    let a_to_c = bounded_result(
        "open Alice-to-Carol relay",
        alice_net.open_closed_relay(&relay_id, &carol_id),
    )
    .await?;
    let c_from_a = bounded_result(
        "accept Alice-to-Carol relay",
        carol_net.accept_closed_relay(),
    )
    .await?;
    assert_eq!(a_to_c.peer_device_id(), carol_id);
    assert_eq!(a_to_c.relay_device_id(), relay_id);
    assert_eq!(c_from_a.peer_device_id(), alice_id);
    assert_eq!(c_from_a.relay_device_id(), relay_id);
    assert_eq!(a_to_c.session_id(), c_from_a.session_id());
    assert_ne!(a_to_c.session_id(), [0; 16]);

    let max_plaintext =
        usize::try_from(ClosedRelayPolicyConfig::default().max_frame_ciphertext_bytes)
            .expect("configured relay plaintext bound fits usize");
    let max_a_to_c: Vec<u8> = (0..max_plaintext)
        .map(|index| (index % 251) as u8)
        .collect();
    let oversized_a_to_c = vec![0xa5; max_plaintext + 1];
    let oversized = bounded_result(
        "reject oversized Alice-to-Carol payload",
        a_to_c.send(&oversized_a_to_c),
    )
    .await;
    assert!(matches!(
        oversized,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::InvalidPacket
        ))
    ));
    bounded_result(
        "send maximum Alice-to-Carol payload",
        a_to_c.send(&max_a_to_c),
    )
    .await?;
    assert_eq!(
        bounded_result("receive maximum Alice-to-Carol payload", c_from_a.recv()).await?,
        max_a_to_c
    );

    // Re-installing the same far identity is the public transport-lab
    // replacement seam: it displaces the exact W0 owner on both sides while
    // retaining W0's opaque link for a delayed close.  This is intentionally
    // a peer-owner replacement, not merely a new Closed-relay session.
    let alice_relay_w1 = bounded_value(
        "replace Alice-relay owner installation",
        alice_net.install_promoted_peer_over_real_link(&relay_net),
    )
    .await?;
    assert_eq!(alice_relay_w1.peer_device_id(), relay_id);
    assert_active_profile(&alice_net, &relay_id);
    assert_active_profile(&relay_net, &alice_id);
    let _ = bounded_value(
        "retire stale Alice-relay W0 transport",
        alice_relay_w0.retire(),
    )
    .await?;
    assert_active_profile(&alice_net, &relay_id);
    assert_active_profile(&relay_net, &alice_id);
    assert!(matches!(
        bounded_result(
            "reject stale relay-owner W0 data",
            a_to_c.send(b"stale relay W0")
        )
        .await,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::Owner
        ))
    ));
    bounded_result("close Carol endpoint", c_from_a.close()).await?;
    assert!(matches!(
        bounded_result(
            "reject send after Carol close",
            a_to_c.send(b"after target close")
        )
        .await,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::Owner
        ))
    ));

    // Re-open the exact same route while the stale requester handle still
    // exists. The fresh session must receive a new coordinate, and the old
    // W0 handle must remain unable to forward through W1's allocation.
    let w0_session_id = a_to_c.session_id();
    let a_to_c_w1 = bounded_result(
        "open Alice-to-Carol replacement relay",
        alice_net.open_closed_relay(&relay_id, &carol_id),
    )
    .await?;
    let c_from_a_w1 = bounded_result(
        "accept Alice-to-Carol replacement relay",
        carol_net.accept_closed_relay(),
    )
    .await?;
    assert_ne!(w0_session_id, a_to_c_w1.session_id());
    assert_eq!(a_to_c_w1.session_id(), c_from_a_w1.session_id());
    assert!(matches!(
        bounded_result("reject stale W0 send", a_to_c.send(b"stale W0")).await,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::Owner
        ))
    ));
    bounded_result("send replacement W1 payload", a_to_c_w1.send(b"live W1")).await?;
    assert_eq!(
        bounded_result("receive replacement W1 payload", c_from_a_w1.recv()).await?,
        b"live W1"
    );
    // W0 is terminal while W1 is live. Closing the retained W0 requester is
    // the delayed-old-close control; W1 must remain the only usable route.
    bounded_result("close delayed old W0 requester", a_to_c.close()).await?;
    bounded_result("close replacement Alice endpoint", a_to_c_w1.close()).await?;
    bounded_result("close replacement Carol endpoint", c_from_a_w1.close()).await?;

    let c_to_a = bounded_result(
        "open Carol-to-Alice relay",
        carol_net.open_closed_relay(&relay_id, &alice_id),
    )
    .await?;
    let a_from_c = bounded_result(
        "accept Carol-to-Alice relay",
        alice_net.accept_closed_relay(),
    )
    .await?;
    assert_eq!(c_to_a.peer_device_id(), alice_id);
    assert_eq!(c_to_a.relay_device_id(), relay_id);
    assert_eq!(a_from_c.peer_device_id(), carol_id);
    assert_eq!(a_from_c.relay_device_id(), relay_id);
    assert_eq!(c_to_a.session_id(), a_from_c.session_id());

    let max_c_to_a: Vec<u8> = (0..max_plaintext)
        .map(|index| ((index * 3) % 251) as u8)
        .collect();
    let oversized_c_to_a = vec![0x5a; max_plaintext + 1];
    let oversized = bounded_result(
        "reject oversized Carol-to-Alice payload",
        c_to_a.send(&oversized_c_to_a),
    )
    .await;
    assert!(matches!(
        oversized,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::InvalidPacket
        ))
    ));
    bounded_result(
        "send maximum Carol-to-Alice payload",
        c_to_a.send(&max_c_to_a),
    )
    .await?;
    assert_eq!(
        bounded_result("receive maximum Carol-to-Alice payload", a_from_c.recv()).await?,
        max_c_to_a
    );
    bounded_result("close Alice endpoint", a_from_c.close()).await?;
    assert!(matches!(
        bounded_result(
            "reject send after Alice close",
            c_to_a.send(b"after target close")
        )
        .await,
        Err(myownmesh_core::Error::ClosedRelay(
            myownmesh_core::error::ClosedRelayError::Owner
        ))
    ));
    // The public channel consumes its handle, so duplicate terminal close is
    // represented by closing the opposite endpoint after the round trip has
    // already terminalized it; it must remain harmless and bounded.
    bounded_result("duplicate terminal Carol close", c_to_a.close()).await?;

    // Accepted endpoints are deliberately dropped without calling close;
    // shutdown must still release their exact endpoint and relay custody.
    let dropped_a_to_c = bounded_result(
        "open dropped Alice-to-Carol relay",
        alice_net.open_closed_relay(&relay_id, &carol_id),
    )
    .await?;
    let dropped_c_from_a = bounded_result(
        "accept dropped Alice-to-Carol relay",
        carol_net.accept_closed_relay(),
    )
    .await?;
    assert_eq!(
        dropped_a_to_c.session_id(),
        dropped_c_from_a.session_id(),
        "dropped endpoint pair must identify one exact route"
    );
    let dropped_session_id = dropped_a_to_c.session_id();
    // The target has accepted the offer but has deliberately not pulled a
    // packet. Dropping both public channels without close must retire only
    // that exact route; a fresh same-route admission gets a new coordinate
    // and remains independently usable.
    drop(dropped_c_from_a);
    drop(dropped_a_to_c);
    let replacement_a_to_c = bounded_result(
        "open successor after dropped Alice-to-Carol relay",
        alice_net.open_closed_relay(&relay_id, &carol_id),
    )
    .await?;
    let replacement_c_from_a = bounded_result(
        "accept successor after dropped Alice-to-Carol relay",
        carol_net.accept_closed_relay(),
    )
    .await?;
    assert_ne!(replacement_a_to_c.session_id(), dropped_session_id);
    assert_eq!(
        replacement_a_to_c.session_id(),
        replacement_c_from_a.session_id(),
        "successor must be one exact endpoint pair"
    );
    bounded_result(
        "send successor after dropped endpoint pair",
        replacement_a_to_c.send(b"successor after dropped route"),
    )
    .await?;
    assert_eq!(
        bounded_result(
            "receive successor after dropped endpoint pair",
            replacement_c_from_a.recv(),
        )
        .await?,
        b"successor after dropped route"
    );
    bounded_result(
        "close successor target endpoint",
        replacement_c_from_a.close(),
    )
    .await?;
    bounded_result(
        "close successor requester endpoint",
        replacement_a_to_c.close(),
    )
    .await?;

    let _ = bounded_value("retire relay-Carol link", relay_carol.retire()).await?;
    let _ = bounded_value("retire Alice-relay W1 link", alice_relay_w1.retire()).await?;
    bounded_result("shutdown Alice network", alice_net.shutdown()).await?;
    bounded_result("shutdown relay network", relay_net.shutdown()).await?;
    bounded_result("shutdown Carol network", carol_net.shutdown()).await?;
    drop(alice_net);
    drop(relay_net);
    drop(carol_net);
    let live_alice = alice_mesh.resource_report();
    let live_relay = relay_mesh.resource_report();
    let live_carol = carol_mesh.resource_report();
    assert_live_custody_baseline("Alice", &baseline_alice, &live_alice);
    assert_live_custody_baseline("relay", &baseline_relay, &live_relay);
    assert_live_custody_baseline("Carol", &baseline_carol, &live_carol);
    assert_inexact_transport_observed("Alice", &live_alice);
    assert_inexact_transport_observed("relay", &live_relay);
    assert_inexact_transport_observed("Carol", &live_carol);
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
    Ok(())
}
