#![cfg(feature = "transport-lab")]

//! Public encrypted-fallback acceptance in a four-node sparse HubTree. The
//! physical links are root-Hub plus the two endpoint-Hub edges. The forwarding
//! Hub must move the routed envelope without ever delivering the channel
//! name/body to its application gateway.

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{
    ApplicationTransportPolicyConfig, EndpointCipherPolicyConfig, HubIntroductionPolicyConfig,
    HubPolicyConfig, NetworkConfig, RoutingPolicyConfig, SignalingConfig, TopologyMode,
    TreePolicyConfig,
};
use myownmesh_core::engine::connection::PeerStatus;
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};
use tokio::time::Instant;

const NETWORK_ID: &str = "encrypted-hub-routing-acceptance";
const CHANNEL: &str = "private-endpoint-channel";
const FIXTURE_GRANT_PER_CLASS: u64 = 8_000_000_000;

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

async fn within<T>(
    stage: &'static str,
    deadline: Instant,
    future: impl Future<Output = T>,
) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| format!("{stage}: operation exceeded its original absolute deadline"))?;
    require(
        Instant::now() <= deadline,
        format!("{stage}: operation completed after its original absolute deadline"),
    )?;
    Ok(value)
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, FIXTURE_GRANT_PER_CLASS)),
    )
    .expect("encrypted route fixture grant is representable");
    WebRtcConnectorCapablePolicy::new(
        ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("encrypted route resource provider opens"),
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn application_policy() -> ApplicationTransportPolicyConfig {
    ApplicationTransportPolicyConfig {
        introduction: HubIntroductionPolicyConfig {
            max_records: 16,
            max_waiters_per_target: 4,
            max_signaling_bytes: (16 + 4)
                * myownmesh_core::protocol::hub_introduction::HUB_INTRODUCTION_MAX_WIRE_BYTES
                    as u64,
            max_candidates_per_attempt: 16,
            attempt_timeout_ms: 10_000,
            terminal_retention_ms: 10_000,
            max_transient_links: 6,
            idle_timeout_ms: 2_000,
            max_maintenance_per_tick: 16,
        },
        endpoint_cipher: EndpointCipherPolicyConfig {
            max_sessions: 6,
            max_plaintext_bytes: myownmesh_core::protocol::topology::max_routed_plaintext_bytes()
                as u64,
            replay_window: 64,
            max_age_ms: 30_000,
        },
    }
    .checked()
    .expect("finite encrypted route policy validates")
}

fn config(id: &str, root: &str, hub: &str, max_children: u64) -> NetworkConfig {
    let mut config = NetworkConfig::from_network_id(id, NETWORK_ID);
    config.label = id.to_owned();
    config.topology = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: vec![hub.to_owned()],
        backup_candidates: 0,
    };
    config.routing_policy = RoutingPolicyConfig {
        max_next_hops: 1,
        max_parallel_routes: 1,
        ..RoutingPolicyConfig::default()
    };
    config.hub = Some(HubPolicyConfig {
        max_parallel_dials: 1,
        max_dials_per_pass: 1,
        max_advertisements_per_pass: 2,
        exploration_interval_ms: 20,
        max_exploration_probes_per_pass: 1,
        max_exploration_peers_per_reply: 2,
        trickle_imin_ms: 20,
        trickle_imax_ms: 40,
        trickle_redundancy: 1,
        trickle_reset_window_ms: 40,
        trickle_max_resets_per_window: 1,
    });
    config.tree = Some(TreePolicyConfig {
        max_children,
        max_backups: 0,
        max_pending: 1,
        max_age_ms: 60_000,
    });
    config.signaling = SignalingConfig {
        strategy: "none".to_owned(),
        mdns: false,
        public_fallback: false,
        ..SignalingConfig::default()
    };
    config.application_transport = Some(application_policy());
    config.auto_approve = true;
    config.scheduler.state_watch_interval_ms = 5;
    config.scheduler.wake_probe_delay_ms = 1;
    config.validate().expect("encrypted route config validates");
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

fn require_no_current_direct(
    network: &myownmesh_core::JoinedNetwork,
    local_id: &str,
    peer_id: &str,
) -> Result<(), String> {
    let peer = network.peer(peer_id).map(|peer| {
        (
            peer.status,
            peer.authenticated,
            peer.local_approve_sent,
            peer.remote_approve_seen,
        )
    });
    let witness = network.capture_transport_channel_for_lab(peer_id);
    let has_current_transport = witness.is_some();
    drop(witness);
    require(
        !has_current_transport
            && matches!(
                peer,
                None | Some((PeerStatus::Sighted, false, false, false))
            ),
        format!(
            "no-direct state local={local_id} remote={peer_id} peer={peer:?} \
             current_transport={has_current_transport}"
        ),
    )
}

async fn wait_for_parent(
    endpoint: &myownmesh_core::JoinedNetwork,
    stage: &'static str,
    deadline: Instant,
) -> Result<(), String> {
    within(stage, deadline, async {
        loop {
            if endpoint
                .parenting_snapshot_for_lab()
                .is_some_and(|snapshot| snapshot.primary_parent.is_some() && snapshot.pending == 0)
            {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn unavailable_direct_path_uses_ciphertext_fallback_without_hub_plaintext() {
    let home = tempfile::tempdir().expect("isolated encrypted route home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let root_identity = Arc::new(Identity::ephemeral());
    let alice_identity = Arc::new(Identity::ephemeral());
    let hub_identity = Arc::new(Identity::ephemeral());
    let bob_identity = Arc::new(Identity::ephemeral());
    let root_id = root_identity.public_id().to_owned();
    let alice_id = alice_identity.public_id().to_owned();
    let hub_id = hub_identity.public_id().to_owned();
    let bob_id = bob_identity.public_id().to_owned();
    let policy = connector_policy();
    let root_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        root_identity,
        policy.clone(),
    )
    .await
    .expect("root mesh opens");
    let alice_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        alice_identity,
        policy.clone(),
    )
    .await
    .expect("Alice mesh opens");
    let hub_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        hub_identity,
        policy.clone(),
    )
    .await
    .expect("Hub mesh opens");
    let bob_mesh =
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), bob_identity, policy)
            .await
            .expect("Bob mesh opens");
    let baselines = [
        root_mesh.resource_report(),
        alice_mesh.resource_report(),
        hub_mesh.resource_report(),
        bob_mesh.resource_report(),
    ];
    let root = root_mesh
        .join(config("root", &root_id, &hub_id, 1))
        .await
        .expect("root joins");
    let alice = alice_mesh
        .join(config("alice", &root_id, &hub_id, 0))
        .await
        .expect("Alice joins");
    let hub = hub_mesh
        .join(config("hub", &root_id, &hub_id, 2))
        .await
        .expect("Hub joins");
    let bob = bob_mesh
        .join(config("bob", &root_id, &hub_id, 0))
        .await
        .expect("Bob joins");

    let stage_deadline = Instant::now() + Duration::from_secs(40);
    let root_hub = within(
        "root-hub-open",
        stage_deadline,
        root.install_promoted_peer_over_real_link(&hub),
    )
    .await
    .expect("root-Hub real link opens");
    let mut alice_hub = Some(
        within(
            "alice-hub-open",
            stage_deadline,
            alice.install_promoted_peer_over_real_link(&hub),
        )
        .await
        .expect("Alice-Hub real link opens"),
    );
    let bob_hub = within(
        "bob-hub-open",
        stage_deadline,
        bob.install_promoted_peer_over_real_link(&hub),
    )
    .await
    .expect("Bob-Hub real link opens");
    wait_for_parent(&hub, "hub-parent-settle", stage_deadline)
        .await
        .expect("Hub root relation settles");
    wait_for_parent(&alice, "alice-parent-settle", stage_deadline)
        .await
        .expect("Alice Hub relation settles");
    wait_for_parent(&bob, "bob-parent-settle", stage_deadline)
        .await
        .expect("Bob Hub relation settles");
    assert_eq!(
        root.parenting_snapshot_for_lab()
            .expect("root relation table exists")
            .accepted_children,
        1
    );
    assert_eq!(
        hub.parenting_snapshot_for_lab()
            .expect("Hub relation table exists")
            .accepted_children,
        2
    );
    let result: Result<(), String> = async {
        require_no_current_direct(&alice, &alice_id, &bob_id)?;
        require_no_current_direct(&bob, &bob_id, &alice_id)?;
        let mut hub_subscription = hub
            .channel::<Vec<u8>>(CHANNEL)
            .subscribe()
            .map_err(|error| format!("Hub subscription refused: {error}"))?;
        let mut bob_subscription = bob
            .channel::<Vec<u8>>(CHANNEL)
            .subscribe()
            .map_err(|error| format!("Bob subscription refused: {error}"))?;
        let hub_before = hub.traffic();
        let payload = vec![0, 0xff, b'{', 0x80, b'}', 0, 4, 5];
        within(
            "encrypted-fallback-send",
            stage_deadline,
            alice.channel::<Vec<u8>>(CHANNEL).send_to(&bob_id, &payload),
        )
        .await?
        .map_err(|error| format!("encrypted fallback send refused: {error}"))?;
        let delivered = within(
            "encrypted-fallback-receive",
            stage_deadline,
            bob_subscription.recv(),
        )
        .await?
        .ok_or_else(|| "Bob subscription closed".to_owned())?
        .map_err(|error| format!("Bob decode refused: {error}"))?;
        require(delivered.from() == alice_id, "wrong fallback sender")?;
        require(
            delivered.body() == &payload,
            "fallback plaintext changed at endpoint",
        )?;
        require(
            tokio::time::timeout(Duration::from_millis(150), hub_subscription.recv())
                .await
                .is_err(),
            "the forwarding Hub delivered endpoint plaintext to its channel API",
        )?;
        let hub_after = hub.traffic();
        require(
            hub_after.app_rx.frames > hub_before.app_rx.frames
                && hub_after.app_tx.frames > hub_before.app_tx.frames,
            "the only physical forwarding Hub did not account the routed envelope",
        )?;
        require_no_current_direct(&alice, &alice_id, &bob_id)?;
        require_no_current_direct(&bob, &bob_id, &alice_id)?;

        let too_large =
            vec![0u8; myownmesh_core::protocol::topology::max_routed_plaintext_bytes() + 1];
        require(
            alice
                .channel::<Vec<u8>>(CHANNEL)
                .send_to(&bob_id, &too_large)
                .await
                .is_err(),
            "routed plaintext above the complete encrypted-inner ceiling was accepted",
        )?;
        require(
            tokio::time::timeout(Duration::from_millis(150), bob_subscription.recv())
                .await
                .is_err(),
            "a refused over-ceiling body reached the destination",
        )?;

        let retired = alice_hub
            .take()
            .ok_or_else(|| "Alice-Hub link owner was already consumed".to_owned())?;
        let retirement = within("alice-hub-retire", stage_deadline, retired.retire()).await?;
        require(
            retirement.iter().all(Result::is_ok),
            format!("Alice-Hub retirement failed: {retirement:?}"),
        )?;
        require(
            alice
                .channel::<Vec<u8>>(CHANNEL)
                .send_to(&bob_id, &vec![9, 8, 7])
                .await
                .is_err(),
            "a retired exact carrier was resolved through a stale owner",
        )?;
        Ok(())
    }
    .await;

    let cleanup_deadline = Instant::now() + Duration::from_secs(30);
    let mut cleanup_failures = Vec::new();
    if let Some(link) = alice_hub.take() {
        match within("cleanup-alice-hub-retire", cleanup_deadline, link.retire()).await {
            Ok(results) => cleanup_failures.extend(
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string()),
            ),
            Err(error) => cleanup_failures.push(error),
        }
    }
    match within("cleanup-bob-hub-retire", cleanup_deadline, bob_hub.retire()).await {
        Ok(results) => cleanup_failures.extend(
            results
                .into_iter()
                .filter_map(Result::err)
                .map(|error| error.to_string()),
        ),
        Err(error) => cleanup_failures.push(error),
    }
    match within(
        "cleanup-root-hub-retire",
        cleanup_deadline,
        root_hub.retire(),
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
    for (name, stage, network) in [
        ("root", "cleanup-root-shutdown", &root),
        ("alice", "cleanup-alice-shutdown", &alice),
        ("hub", "cleanup-hub-shutdown", &hub),
        ("bob", "cleanup-bob-shutdown", &bob),
    ] {
        match within(stage, cleanup_deadline, network.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup_failures.push(format!("{name} shutdown: {error}")),
            Err(error) => cleanup_failures.push(format!("{name} shutdown: {error}")),
        }
    }
    drop((root, alice, hub, bob));
    for (mesh, baseline) in [root_mesh, alice_mesh, hub_mesh, bob_mesh]
        .iter()
        .zip(&baselines)
    {
        assert_resource_baseline(&mesh.resource_report(), baseline);
    }
    assert!(
        cleanup_failures.is_empty(),
        "encrypted route cleanup failed: {cleanup_failures:?}; result={result:?}"
    );
    assert!(
        result.is_ok(),
        "encrypted fallback acceptance failed: {result:?}"
    );
}
