#![cfg(feature = "transport-lab")]

//! Public, native opaque-flow acceptance. The fixture installs one real
//! authenticated WebRTC session and then uses only `JoinedNetwork` operations:
//! no flow reducer, queue, or provider-internal helper is called here.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use myownmesh_core::config::{NetworkConfig, SignalingConfig};
use myownmesh_core::realtime::{
    OpaqueFlowMode, OpaqueFlowOpen, RealtimeFlowDirection, RealtimeRefusal,
    MAX_APPLICATION_FLOW_BODY_BYTES,
};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};
use tokio::time::Instant;

const NETWORK_ID: &str = "opaque-flow-acceptance";
const FIXTURE_GRANT_PER_CLASS: u64 = 8_000_000_000;

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

async fn within<T>(
    operation: &'static str,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| format!("{operation}: exceeded its original absolute deadline"))?;
    require(
        Instant::now() <= deadline,
        format!("{operation}: completed after its original absolute deadline"),
    )?;
    Ok(value)
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, FIXTURE_GRANT_PER_CLASS)),
    )
    .expect("opaque-flow fixture grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("opaque-flow fixture resource provider opens");
    WebRtcConnectorCapablePolicy::new(
        resources,
        // Opaque byte lanes require the generic realtime scheduler, but no RTP
        // profile, codec, transceiver, or track is registered by this fixture.
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_realtime()),
    )
}

fn network(id: &str) -> NetworkConfig {
    let mut config = NetworkConfig::from_network_id(id, NETWORK_ID);
    config.label = id.to_owned();
    config.signaling = SignalingConfig {
        strategy: "none".to_owned(),
        mdns: false,
        public_fallback: false,
        ..SignalingConfig::default()
    };
    config.auto_approve = true;
    config
        .validate()
        .expect("opaque-flow network config validates");
    config
}

fn assert_resource_baseline(actual: &ResourceReport, baseline: &ResourceReport) {
    for (actual, baseline) in actual
        .pre_authentication
        .iter()
        .zip(&baseline.pre_authentication)
    {
        assert_eq!(actual.family, baseline.family);
        assert_eq!(actual.active, baseline.active);
        assert_eq!(actual.active_lease_count, baseline.active_lease_count);
    }
    for (actual, baseline) in actual
        .post_authentication
        .iter()
        .zip(&baseline.post_authentication)
    {
        assert_eq!(actual.family, baseline.family);
        assert_eq!(actual.active, baseline.active);
        assert_eq!(actual.active_lease_count, baseline.active_lease_count);
    }
}

fn require_active_resource_baseline(
    actual: &ResourceReport,
    baseline: &ResourceReport,
    operation: &'static str,
) -> Result<(), String> {
    for (actual, baseline) in actual
        .pre_authentication
        .iter()
        .zip(&baseline.pre_authentication)
    {
        require(
            actual.family == baseline.family
                && actual.active == baseline.active
                && actual.active_lease_count == baseline.active_lease_count,
            format!(
                "{operation}: pre-auth {:?} active resources changed: actual={:?}/{}, baseline={:?}/{}",
                actual.family,
                actual.active,
                actual.active_lease_count,
                baseline.active,
                baseline.active_lease_count,
            ),
        )?;
    }
    for (actual, baseline) in actual
        .post_authentication
        .iter()
        .zip(&baseline.post_authentication)
    {
        require(
            actual.family == baseline.family
                && actual.active == baseline.active
                && actual.active_lease_count == baseline.active_lease_count,
            format!(
                "{operation}: post-auth {:?} active resources changed: actual={:?}/{}, baseline={:?}/{}",
                actual.family,
                actual.active,
                actual.active_lease_count,
                baseline.active,
                baseline.active_lease_count,
            ),
        )?;
    }
    Ok(())
}

async fn receive_exact(
    receiver: &myownmesh_core::JoinedNetwork,
    inbound: &myownmesh_core::realtime::RealtimeInboundStream,
    operation: &'static str,
    deadline: Instant,
    expected_label: &[u8],
    expected_body: &[u8],
) -> Result<(), String> {
    let arrival = within(operation, deadline, receiver.recv_opaque_flow(inbound))
        .await?
        .map_err(|error| format!("typed opaque receive refused: {error}"))?
        .ok_or_else(|| "opaque inbound stream ended before the selected unit".to_owned())?;
    require(
        arrival.label == expected_label,
        "opaque label changed in core",
    )?;
    require(
        arrival.bytes.as_ref() == expected_body,
        "opaque body changed in core",
    )
}

async fn wait_until_stale(
    network: &myownmesh_core::JoinedNetwork,
    flow: &myownmesh_core::realtime::RealtimeFlowHandle,
    operation: &'static str,
    deadline: Instant,
) -> Result<(), String> {
    within(operation, deadline, async {
        loop {
            if !network.realtime_is_current(flow) {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn opaque_bytes_modes_reopen_bounds_and_stale_owner_use_real_session() {
    let home = tempfile::tempdir().expect("isolated opaque-flow home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let alice_identity = Arc::new(Identity::ephemeral());
    let bob_identity = Arc::new(Identity::ephemeral());
    let alice_id = alice_identity.public_id().to_owned();
    let bob_id = bob_identity.public_id().to_owned();
    let policy = connector_policy();
    let alice_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        alice_identity,
        policy.clone(),
    )
    .await
    .expect("Alice mesh opens");
    let bob_mesh =
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), bob_identity, policy)
            .await
            .expect("Bob mesh opens");
    let alice_baseline = alice_mesh.resource_report();
    let bob_baseline = bob_mesh.resource_report();
    let alice = alice_mesh
        .join(network("alice"))
        .await
        .expect("Alice joins");
    let bob = bob_mesh.join(network("bob")).await.expect("Bob joins");

    let stage_deadline = Instant::now() + Duration::from_secs(30);
    let mut link = Some(
        within(
            "initial-real-link-open",
            stage_deadline,
            alice.install_retirable_session_over_real_link(&bob),
        )
        .await
        .expect("real promoted link opens"),
    );
    assert_eq!(link.as_ref().expect("link owner").peer_device_id(), bob_id);
    assert!(alice.peer(&bob_id).is_some());
    assert!(bob.peer(&alice_id).is_some());

    let result: Result<(), String> = async {
        let bob_inbound = bob
            .realtime_inbound(&alice_id)
            .ok_or_else(|| "Bob could not claim Alice's exact inbound session".to_owned())?;
        require(
            bob.realtime_inbound(&alice_id).is_none(),
            "a second inbound reader was admitted for the same session",
        )?;

        require(
            OpaqueFlowOpen::new(
                b"too-large".to_vec(),
                RealtimeFlowDirection::Outbound,
                OpaqueFlowMode::ReliableOrdered,
                u32::try_from(MAX_APPLICATION_FLOW_BODY_BYTES + 1)
                    .map_err(|_| "max+1 body is not representable".to_owned())?,
            )
            .is_none(),
            "the representation-level max+1 request was accepted",
        )?;

        let reliable_label = vec![0, 0xff, b'r', b'e', b'l'];
        let reliable_inbound_open = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Inbound,
            OpaqueFlowMode::ReliableOrdered,
            u32::try_from(MAX_APPLICATION_FLOW_BODY_BYTES)
                .map_err(|_| "opaque body ceiling is not u32".to_owned())?,
        )
        .ok_or_else(|| "reliable inbound opaque request is well formed".to_owned())?;
        let reliable_outbound_open = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            u32::try_from(MAX_APPLICATION_FLOW_BODY_BYTES)
                .map_err(|_| "opaque body ceiling is not u32".to_owned())?,
        )
        .ok_or_else(|| "reliable outbound opaque request is well formed".to_owned())?;
        let first_inbound = within(
            "reliable-inbound-first-open",
            stage_deadline,
            bob.open_opaque_flow(&alice_id, &reliable_inbound_open),
        )
        .await?
        .map_err(|error| format!("inbound-first reliable open refused: {error}"))?;
        let mismatched_outbound_open = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            1024,
        )
        .ok_or_else(|| "mismatched reciprocal request is representable".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-mismatched-reciprocal-open",
                    stage_deadline,
                    alice.open_opaque_flow(&bob_id, &mismatched_outbound_open),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "a mismatched reciprocal request claimed or replaced the dormant record",
        )?;
        let first = within(
            "reliable-matching-reciprocal-open",
            stage_deadline,
            alice.open_opaque_flow(&bob_id, &reliable_outbound_open),
        )
        .await?
        .map_err(|error| format!("matching reciprocal reliable open refused: {error}"))?;
        require(
            matches!(
                within(
                    "reliable-duplicate-local-claim",
                    stage_deadline,
                    alice.open_opaque_flow(&bob_id, &reliable_outbound_open),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "a second local application claim was admitted for one reciprocal record",
        )?;
        let first_body = Bytes::from_static(b"\0\xff\x80{not-json}\n\0");
        alice
            .send_opaque_flow(&first, first_body.clone())
            .map_err(|error| format!("first reliable body refused: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "reliable-first-receive",
            stage_deadline,
            &reliable_label,
            &first_body,
        )
        .await?;
        within(
            "reliable-first-local-close",
            stage_deadline,
            alice.close_realtime(first),
        )
        .await?
        .map_err(|error| format!("first reliable close refused: {error}"))?;
        wait_until_stale(
            &bob,
            &first_inbound,
            "reliable-first-remote-stale",
            stage_deadline,
        )
        .await?;
        require(
            within(
                "reliable-first-stale-remote-close",
                stage_deadline,
                bob.close_realtime(first_inbound),
            )
            .await?
                == Err(RealtimeRefusal::SessionNotCurrent),
            "the remote counterpart survived the exact reciprocal close",
        )?;

        // Reusing the exact label after the awaited close is a new flow
        // incarnation. The provider must not parse the application's changed
        // packetization or allocate a new logical registry.
        let reopened_inbound = within(
            "reliable-reopen-inbound-first",
            stage_deadline,
            bob.open_opaque_flow(&alice_id, &reliable_inbound_open),
        )
        .await?
        .map_err(|error| format!("inbound-first reliable reopen refused: {error}"))?;
        let reopened = within(
            "reliable-reopen-matching-reciprocal",
            stage_deadline,
            alice.open_opaque_flow(&bob_id, &reliable_outbound_open),
        )
        .await?
        .map_err(|error| format!("reliable reopen refused: {error}"))?;
        let packetized = [
            Bytes::from_static(b"\x01"),
            Bytes::from(vec![0xff, 0, 3, 0x80, 9, 9, 9, 0]),
        ];
        for body in packetized {
            alice
                .send_opaque_flow(&reopened, body.clone())
                .map_err(|error| format!("reopened body refused: {error}"))?;
            receive_exact(
                &bob,
                &bob_inbound,
                "reliable-reopen-packetized-receive",
                stage_deadline,
                &reliable_label,
                &body,
            )
            .await?;
        }

        // Change borrows the same move-only handle and must mutate only the
        // negotiated ceiling.  These are all pre-publication refusals, so one
        // successful predecessor send after the group proves that none of them
        // replaced or retired the existing flow.
        let alice_before_change = alice_mesh.resource_report();
        let bob_before_change = bob_mesh.resource_report();
        let zero_ceiling = OpaqueFlowOpen {
            label: reliable_label.clone(),
            direction: RealtimeFlowDirection::Outbound,
            mode: OpaqueFlowMode::ReliableOrdered,
            max_unit_bytes: 0,
        };
        require(
            matches!(
                within(
                    "reliable-change-zero-ceiling-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &zero_ceiling),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "Change accepted a zero body ceiling",
        )?;
        let excessive_ceiling = OpaqueFlowOpen {
            label: reliable_label.clone(),
            direction: RealtimeFlowDirection::Outbound,
            mode: OpaqueFlowMode::ReliableOrdered,
            max_unit_bytes: u32::try_from(MAX_APPLICATION_FLOW_BODY_BYTES + 1)
                .map_err(|_| "max+1 change ceiling is not representable".to_owned())?,
        };
        require(
            matches!(
                within(
                    "reliable-change-max-plus-one-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &excessive_ceiling),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "Change accepted a body ceiling above the global bound",
        )?;
        let wrong_label = OpaqueFlowOpen::new(
            b"reliable-change-other-label".to_vec(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "wrong-label Change request is representable".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-change-label-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &wrong_label),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "Change replaced the exact flow label",
        )?;
        let wrong_direction = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Inbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "wrong-direction Change request is representable".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-change-direction-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &wrong_direction),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "Change converted a local sender into an inbound flow",
        )?;
        let wrong_mode = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::PartialUnordered { max_retransmits: 0 },
            32,
        )
        .ok_or_else(|| "wrong-mode Change request is representable".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-change-mode-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &wrong_mode),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "Change moved an existing flow onto the other persistent mode",
        )?;
        let unsupported_mode = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::PartialUnordered { max_retransmits: 2 },
            32,
        )
        .ok_or_else(|| "unsupported-mode Change request is structurally valid".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-change-unsupported-mode-refusal",
                    stage_deadline,
                    alice.change_opaque_flow(&reopened, &unsupported_mode),
                )
                .await?,
                Err(RealtimeRefusal::SessionNotCurrent)
            ),
            "Change treated an unavailable native mode as ready",
        )?;
        let local_inbound_change = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "local-inbound Change request is representable".to_owned())?;
        require(
            matches!(
                within(
                    "reliable-change-local-inbound-refusal",
                    stage_deadline,
                    bob.change_opaque_flow(&reopened_inbound, &local_inbound_change),
                )
                .await?,
                Err(RealtimeRefusal::FlowRefused)
            ),
            "the reciprocal inbound application claim initiated Change",
        )?;
        require(
            alice.realtime_is_current(&reopened)
                && bob.realtime_is_current(&reopened_inbound)
                && reopened.label() == reliable_label.as_slice(),
            "a pre-publication Change refusal mutated the exact live flow",
        )?;
        let predecessor_body = Bytes::from_static(b"predecessor-still-current");
        alice
            .send_opaque_flow(&reopened, predecessor_body.clone())
            .map_err(|error| format!("predecessor send after refused Change: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "reliable-change-predecessor-receive",
            stage_deadline,
            &reliable_label,
            &predecessor_body,
        )
        .await?;

        let changed_open = OpaqueFlowOpen::new(
            reliable_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "changed reliable request is well formed".to_owned())?;
        within(
            "reliable-change-lower-ceiling",
            stage_deadline,
            alice.change_opaque_flow(&reopened, &changed_open),
        )
        .await?
        .map_err(|error| format!("reliable Change refused: {error}"))?;
        require(
            alice.realtime_is_current(&reopened)
                && bob.realtime_is_current(&reopened_inbound)
                && reopened.label() == reliable_label.as_slice(),
            "successful Change replaced the exact flow or handle authority",
        )?;
        let changed_body = Bytes::from(vec![0xc3; 32]);
        alice
            .send_opaque_flow(&reopened, changed_body.clone())
            .map_err(|error| format!("changed-ceiling body refused: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "reliable-change-new-ceiling-receive",
            stage_deadline,
            &reliable_label,
            &changed_body,
        )
        .await?;
        require(
            alice.send_opaque_flow(&reopened, Bytes::from(vec![0xc4; 33]))
                == Err(RealtimeRefusal::FlowRefused),
            "the changed flow admitted one byte above its negotiated ceiling",
        )?;
        let fresh_body = Bytes::from_static(b"fresh-after-ceiling-refusal");
        alice
            .send_opaque_flow(&reopened, fresh_body.clone())
            .map_err(|error| format!("fresh send after ceiling refusal: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "reliable-change-fresh-receive",
            stage_deadline,
            &reliable_label,
            &fresh_body,
        )
        .await?;
        within(
            "reliable-change-restore-global-ceiling",
            stage_deadline,
            alice.change_opaque_flow(&reopened, &reliable_outbound_open),
        )
        .await?
        .map_err(|error| format!("restoring reliable ceiling refused: {error}"))?;
        require(
            alice.realtime_is_current(&reopened) && bob.realtime_is_current(&reopened_inbound),
            "restoring the ceiling replaced the exact flow",
        )?;
        require_active_resource_baseline(
            &alice_mesh.resource_report(),
            &alice_before_change,
            "Alice Change persistent-lane census",
        )?;
        require_active_resource_baseline(
            &bob_mesh.resource_report(),
            &bob_before_change,
            "Bob Change persistent-lane census",
        )?;
        let maximal = Bytes::from(vec![0xa5; MAX_APPLICATION_FLOW_BODY_BYTES]);
        alice
            .send_opaque_flow(&reopened, maximal.clone())
            .map_err(|error| format!("maximal opaque body refused: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "reliable-reopen-maximal-receive",
            stage_deadline,
            &reliable_label,
            &maximal,
        )
        .await?;
        within(
            "reliable-reopen-local-close",
            stage_deadline,
            alice.close_realtime(reopened),
        )
        .await?
        .map_err(|error| format!("reopened reliable close refused: {error}"))?;
        wait_until_stale(
            &bob,
            &reopened_inbound,
            "reliable-reopen-remote-stale",
            stage_deadline,
        )
        .await?;
        require(
            matches!(
                within(
                    "reliable-change-closed-remote-refusal",
                    stage_deadline,
                    bob.change_opaque_flow(&reopened_inbound, &local_inbound_change),
                )
                .await?,
                Err(RealtimeRefusal::SessionNotCurrent)
            ),
            "Change on the closed reciprocal handle reached a live flow",
        )?;
        require(
            within(
                "reliable-reopen-stale-remote-close",
                stage_deadline,
                bob.close_realtime(reopened_inbound),
            )
            .await?
                == Err(RealtimeRefusal::SessionNotCurrent),
            "the reopened remote counterpart survived the exact close",
        )?;

        let partial_label = vec![b'p', 0, 0xfe];
        let unsupported_partial_open = OpaqueFlowOpen::new(
            partial_label.clone(),
            RealtimeFlowDirection::Inbound,
            OpaqueFlowMode::PartialUnordered { max_retransmits: 2 },
            1024,
        )
        .ok_or_else(|| "unsupported partial request is structurally well formed".to_owned())?;
        require(
            matches!(
                within(
                    "partial-unsupported-inbound-open",
                    stage_deadline,
                    bob.open_opaque_flow(&alice_id, &unsupported_partial_open),
                )
                .await?,
                Err(RealtimeRefusal::ProviderConfigurationInvalid)
            ),
            "a nonzero partial-retransmit mode was not refused by the provider",
        )?;

        // The refused unsupported mode must not publish or retain a flow:
        // the same label remains available to the provider's supported
        // unordered/no-retransmit lane and its reciprocal application claim.
        let partial_inbound_open = OpaqueFlowOpen::new(
            partial_label.clone(),
            RealtimeFlowDirection::Inbound,
            OpaqueFlowMode::PartialUnordered { max_retransmits: 0 },
            1024,
        )
        .ok_or_else(|| "partial inbound opaque request is well formed".to_owned())?;
        let partial_outbound_open = OpaqueFlowOpen::new(
            partial_label.clone(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::PartialUnordered { max_retransmits: 0 },
            1024,
        )
        .ok_or_else(|| "partial outbound opaque request is well formed".to_owned())?;
        let partial_inbound = within(
            "partial-supported-inbound-first-open",
            stage_deadline,
            bob.open_opaque_flow(&alice_id, &partial_inbound_open),
        )
        .await?
        .map_err(|error| format!("inbound-first partial open refused: {error}"))?;
        let partial = within(
            "partial-supported-matching-reciprocal-open",
            stage_deadline,
            alice.open_opaque_flow(&bob_id, &partial_outbound_open),
        )
        .await?
        .map_err(|error| format!("partial open refused: {error}"))?;
        let partial_body = Bytes::from_static(b"\xffpartial\0unordered");
        alice
            .send_opaque_flow(&partial, partial_body.clone())
            .map_err(|error| format!("partial body refused: {error}"))?;
        receive_exact(
            &bob,
            &bob_inbound,
            "partial-supported-receive",
            stage_deadline,
            &partial_label,
            &partial_body,
        )
        .await?;
        within(
            "partial-supported-local-close",
            stage_deadline,
            alice.close_realtime(partial),
        )
        .await?
        .map_err(|error| format!("partial close refused: {error}"))?;
        wait_until_stale(
            &bob,
            &partial_inbound,
            "partial-supported-remote-stale",
            stage_deadline,
        )
        .await?;
        require(
            within(
                "partial-supported-stale-remote-close",
                stage_deadline,
                bob.close_realtime(partial_inbound),
            )
            .await?
                == Err(RealtimeRefusal::SessionNotCurrent),
            "the partial remote counterpart survived the exact close",
        )?;

        let stale_inbound_open = OpaqueFlowOpen::new(
            b"stale-owner".to_vec(),
            RealtimeFlowDirection::Inbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "stale-owner inbound request is well formed".to_owned())?;
        let stale_outbound_open = OpaqueFlowOpen::new(
            b"stale-owner".to_vec(),
            RealtimeFlowDirection::Outbound,
            OpaqueFlowMode::ReliableOrdered,
            32,
        )
        .ok_or_else(|| "stale-owner outbound request is well formed".to_owned())?;
        let stale_inbound = within(
            "stale-owner-inbound-first-open",
            stage_deadline,
            bob.open_opaque_flow(&alice_id, &stale_inbound_open),
        )
        .await?
        .map_err(|error| format!("inbound-first stale-owner open refused: {error}"))?;
        let stale = within(
            "stale-owner-matching-reciprocal-open",
            stage_deadline,
            alice.open_opaque_flow(&bob_id, &stale_outbound_open),
        )
        .await?
        .map_err(|error| format!("stale-owner setup open refused: {error}"))?;
        let retired = link
            .take()
            .ok_or_else(|| "real link owner was already consumed".to_owned())?;
        let retire_results = within(
            "stale-owner-real-link-retire",
            stage_deadline,
            retired.retire_sessions(),
        )
        .await?;
        require(
            retire_results.iter().all(Result::is_ok),
            format!("real link retirement failed: {retire_results:?}"),
        )?;
        wait_until_stale(
            &alice,
            &stale,
            "stale-owner-local-handle-stale",
            stage_deadline,
        )
        .await?;
        wait_until_stale(
            &bob,
            &stale_inbound,
            "stale-owner-remote-handle-stale",
            stage_deadline,
        )
        .await?;
        require(
            alice.send_opaque_flow(&stale, Bytes::from_static(b"late"))
                == Err(RealtimeRefusal::SessionNotCurrent),
            "a stale flow handle resolved into a retired/replacement session",
        )?;
        require(
            within(
                "stale-owner-local-close-refusal",
                stage_deadline,
                alice.close_realtime(stale),
            )
            .await?
                == Err(RealtimeRefusal::SessionNotCurrent),
            "closing a stale handle reached a successor flow",
        )?;
        require(
            within(
                "stale-owner-remote-close-refusal",
                stage_deadline,
                bob.close_realtime(stale_inbound),
            )
            .await?
                == Err(RealtimeRefusal::SessionNotCurrent),
            "the retired session left its reciprocal inbound handle current",
        )?;
        drop(bob_inbound);
        Ok(())
    }
    .await;

    let cleanup_deadline = Instant::now() + Duration::from_secs(20);
    let mut cleanup_failures = Vec::new();
    if let Some(link) = link.take() {
        match within(
            "cleanup-real-link-retire",
            cleanup_deadline,
            link.retire_sessions(),
        )
        .await
        {
            Ok(results) => cleanup_failures.extend(
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string()),
            ),
            Err(error) => cleanup_failures.push(error),
        }
    }
    for (name, network) in [("alice", &alice), ("bob", &bob)] {
        match within(
            "cleanup-network-shutdown",
            cleanup_deadline,
            network.shutdown(),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup_failures.push(format!("{name} shutdown: {error}")),
            Err(error) => cleanup_failures.push(format!("{name} shutdown: {error}")),
        }
    }
    drop((alice, bob));
    assert_resource_baseline(&alice_mesh.resource_report(), &alice_baseline);
    assert_resource_baseline(&bob_mesh.resource_report(), &bob_baseline);
    assert!(
        cleanup_failures.is_empty(),
        "opaque-flow cleanup failed: {cleanup_failures:?}; result={result:?}"
    );
    assert!(result.is_ok(), "opaque-flow acceptance failed: {result:?}");
}
