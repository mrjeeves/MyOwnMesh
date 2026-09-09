#![cfg(feature = "transport-lab")]

//! Six-node sparse-HubTree acceptance through the public demand and channel
//! APIs. One real root-to-Hub infrastructure link and four real leaf-to-Hub
//! links are installed; the selected leaves have no direct session until two
//! callers make the same bounded explicit demand.

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

const NETWORK_ID: &str = "hub-introduction-acceptance";
const CHANNEL: &str = "introduced-direct-payload";
const FIXTURE_GRANT_PER_CLASS: u64 = 8_000_000_000;

fn require(condition: bool, message: impl Into<String>) -> Result<(), String> {
    condition.then_some(()).ok_or_else(|| message.into())
}

async fn within<T>(deadline: Instant, future: impl Future<Output = T>) -> Result<T, String> {
    let value = tokio::time::timeout_at(deadline, future)
        .await
        .map_err(|_| "operation exceeded its original absolute deadline".to_owned())?;
    require(
        Instant::now() <= deadline,
        "operation completed after its original absolute deadline",
    )?;
    Ok(value)
}

fn connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, FIXTURE_GRANT_PER_CLASS)),
    )
    .expect("Hub introduction fixture grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("Hub introduction resource provider opens");
    WebRtcConnectorCapablePolicy::new(
        resources,
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
    .expect("finite application transport policy validates")
}

fn hub_tree_config(id: &str, root: &str, hub: &str) -> NetworkConfig {
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
        max_advertisements_per_pass: 4,
        exploration_interval_ms: 20,
        max_exploration_probes_per_pass: 1,
        max_exploration_peers_per_reply: 4,
        trickle_imin_ms: 20,
        trickle_imax_ms: 40,
        trickle_redundancy: 1,
        trickle_reset_window_ms: 40,
        trickle_max_resets_per_window: 1,
    });
    config.tree = Some(TreePolicyConfig {
        max_children: 4,
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
    config
        .validate()
        .expect("Hub introduction config validates");
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

fn emit_introduction_snapshot(
    node: &'static str,
    network: &myownmesh_core::JoinedNetwork,
    source_id: &str,
    destination_id: &str,
    source: [u8; 32],
    destination: [u8; 32],
) {
    let snapshot = network.introduction_snapshot_for_lab(source, destination);
    eprintln!(
        "hub-introduction-snapshot network={NETWORK_ID} node={node} source={source_id} \
         destination={destination_id} snapshot={snapshot:?}"
    );
}

fn direct_observation(
    network: &myownmesh_core::JoinedNetwork,
    peer_id: &str,
) -> (Option<(PeerStatus, bool, bool, bool)>, bool) {
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
    (peer, has_current_transport)
}

fn require_no_current_direct(
    network: &myownmesh_core::JoinedNetwork,
    local_id: &str,
    peer_id: &str,
) -> Result<(), String> {
    let (peer, has_current_transport) = direct_observation(network, peer_id);
    require(
        !has_current_transport
            && matches!(
                peer,
                None | Some((PeerStatus::Sighted, false, false, false))
            ),
        format!(
            "pre-demand direct state local={local_id} remote={peer_id} \
             peer={peer:?} current_transport={has_current_transport}"
        ),
    )
}

fn current_active_direct(observation: &(Option<(PeerStatus, bool, bool, bool)>, bool)) -> bool {
    observation.1 && matches!(observation.0, Some((PeerStatus::Active, true, _, _)))
}

async fn wait_for_bilateral_current_active(
    source: &myownmesh_core::JoinedNetwork,
    source_id: &str,
    destination: &myownmesh_core::JoinedNetwork,
    destination_id: &str,
    deadline: Instant,
) -> Result<(), String> {
    loop {
        let source_observation = direct_observation(source, destination_id);
        let destination_observation = direct_observation(destination, source_id);
        if Instant::now() > deadline {
            return Err(format!(
                "post-demand bilateral direct state exceeded its original absolute deadline: \
                 source_local={source_id} source_remote={destination_id} \
                 source_peer={:?} source_current_transport={} \
                 destination_local={destination_id} destination_remote={source_id} \
                 destination_peer={:?} destination_current_transport={}",
                source_observation.0,
                source_observation.1,
                destination_observation.0,
                destination_observation.1,
            ));
        }
        if current_active_direct(&source_observation)
            && current_active_direct(&destination_observation)
        {
            return Ok(());
        }
        if tokio::time::timeout_at(deadline, tokio::task::yield_now())
            .await
            .is_err()
        {
            return Err(format!(
                "post-demand bilateral direct state exceeded its original absolute deadline: \
                 source_local={source_id} source_remote={destination_id} \
                 source_peer={:?} source_current_transport={} \
                 destination_local={destination_id} destination_remote={source_id} \
                 destination_peer={:?} destination_current_transport={}",
                source_observation.0,
                source_observation.1,
                destination_observation.0,
                destination_observation.1,
            ));
        }
    }
}

async fn wait_for_parent(
    network: &myownmesh_core::JoinedNetwork,
    deadline: Instant,
) -> Result<(), String> {
    within(deadline, async {
        loop {
            if network
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

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn coalesced_hub_introduction_creates_one_direct_endpoint_path() {
    let home = tempfile::tempdir().expect("isolated Hub introduction home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let identities = (0..6)
        .map(|_| Arc::new(Identity::ephemeral()))
        .collect::<Vec<_>>();
    let root_id = identities[0].public_id().to_owned();
    let hub_id = identities[1].public_id().to_owned();
    let leaf_ids = identities[2..]
        .iter()
        .map(|identity| identity.public_id().to_owned())
        .collect::<Vec<_>>();
    let policy = connector_policy();
    let mut meshes = Vec::new();
    for identity in &identities {
        meshes.push(
            Mesh::open_connector_capable_with_identity(
                MeshConfig::default(),
                identity.clone(),
                policy.clone(),
            )
            .await
            .expect("fixture mesh opens"),
        );
    }
    let baselines = meshes
        .iter()
        .map(|mesh| mesh.resource_report())
        .collect::<Vec<_>>();
    let root = meshes[0]
        .join(hub_tree_config("root", &root_id, &hub_id))
        .await
        .expect("root joins");
    let hub = meshes[1]
        .join(hub_tree_config("hub", &root_id, &hub_id))
        .await
        .expect("Hub joins");
    let mut leaves = Vec::new();
    for (index, mesh) in meshes.iter().enumerate().skip(2) {
        leaves.push(
            mesh.join(hub_tree_config(&format!("leaf-{index}"), &root_id, &hub_id))
                .await
                .expect("leaf joins"),
        );
    }

    let stage_deadline = Instant::now() + Duration::from_secs(40);
    let mut links = Vec::new();
    links.push(
        within(
            stage_deadline,
            root.install_promoted_peer_over_real_link(&hub),
        )
        .await
        .expect("real root-Hub link opens"),
    );
    for leaf in &leaves {
        links.push(
            within(
                stage_deadline,
                hub.install_promoted_peer_over_real_link(leaf),
            )
            .await
            .expect("real leaf-Hub link opens"),
        );
    }
    wait_for_parent(&hub, stage_deadline)
        .await
        .expect("Hub establishes its real root relation");
    for leaf in &leaves {
        wait_for_parent(leaf, stage_deadline)
            .await
            .expect("leaf establishes its real Hub relation");
    }
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
        4
    );

    let mut signaling_drivers = Vec::new();
    let result: Result<(), String> = async {
        for (name, network) in [
            ("root", &root),
            ("hub", &hub),
            ("leaf-0", &leaves[0]),
            ("leaf-1", &leaves[1]),
            ("leaf-2", &leaves[2]),
            ("leaf-3", &leaves[3]),
        ] {
            let drivers = network
                .attach_signaling()
                .map_err(|error| format!("{name} signaling attachment refused: {error}"))?
                .ok_or_else(|| format!("{name} signaling receiver was already consumed"))?;
            signaling_drivers.push((name, drivers));
        }
        let source = &leaves[0];
        let destination = &leaves[1];
        let destination_id = &leaf_ids[1];
        require_no_current_direct(source, &leaf_ids[0], destination_id)?;
        require_no_current_direct(destination, destination_id, &leaf_ids[0])?;

        let remaining = stage_deadline.saturating_duration_since(Instant::now());
        let (first, second) = within(stage_deadline, async {
            tokio::join!(
                source.connect_peer_wait(destination_id, false, remaining),
                source.connect_peer_wait(destination_id, false, remaining),
            )
        })
        .await?;
        let source_key = *identities[2].verifying_key().as_bytes();
        let destination_key = *identities[3].verifying_key().as_bytes();
        emit_introduction_snapshot(
            "source",
            source,
            &leaf_ids[0],
            destination_id,
            source_key,
            destination_key,
        );
        emit_introduction_snapshot(
            "hub",
            &hub,
            &leaf_ids[0],
            destination_id,
            source_key,
            destination_key,
        );
        emit_introduction_snapshot(
            "destination",
            destination,
            &leaf_ids[0],
            destination_id,
            source_key,
            destination_key,
        );
        first.map_err(|error| format!("first coalesced demand failed: {error}"))?;
        second.map_err(|error| format!("second coalesced demand failed: {error}"))?;
        wait_for_bilateral_current_active(
            source,
            &leaf_ids[0],
            destination,
            destination_id,
            stage_deadline,
        )
        .await?;

        let hub_before = hub.traffic();
        let hub_channel = hub.channel::<Vec<u8>>(CHANNEL);
        let mut hub_subscription = hub_channel
            .subscribe()
            .map_err(|error| format!("Hub channel subscription refused: {error}"))?;
        let destination_channel = destination.channel::<Vec<u8>>(CHANNEL);
        let mut destination_subscription = destination_channel
            .subscribe()
            .map_err(|error| format!("destination channel subscription refused: {error}"))?;
        let payload = vec![0, 0xff, 3, 0x80, 9, 0, 7];
        within(
            stage_deadline,
            source
                .channel::<Vec<u8>>(CHANNEL)
                .send_to(destination_id, &payload),
        )
        .await?
        .map_err(|error| format!("direct post-introduction payload refused: {error}"))?;
        let delivered = within(stage_deadline, destination_subscription.recv())
            .await?
            .ok_or_else(|| "destination channel closed".to_owned())?
            .map_err(|error| format!("destination decode refused: {error}"))?;
        require(delivered.from() == leaf_ids[0], "wrong introduced sender")?;
        require(delivered.body() == &payload, "direct payload changed")?;
        require(
            tokio::time::timeout(Duration::from_millis(150), hub_subscription.recv())
                .await
                .is_err(),
            "the Hub application layer received the endpoint payload",
        )?;
        let hub_after = hub.traffic();
        require(
            hub_after.app_rx == hub_before.app_rx && hub_after.app_tx == hub_before.app_tx,
            "post-introduction direct payload traversed the Hub application lane",
        )?;
        Ok(())
    }
    .await;

    let cleanup_deadline = Instant::now() + Duration::from_secs(30);
    let mut cleanup_failures = Vec::new();
    for link in links {
        match within(cleanup_deadline, link.retire()).await {
            Ok(results) => cleanup_failures.extend(
                results
                    .into_iter()
                    .filter_map(Result::err)
                    .map(|error| error.to_string()),
            ),
            Err(error) => cleanup_failures.push(error),
        }
    }
    for (name, drivers) in signaling_drivers {
        if let Err(error) = within(cleanup_deadline, drivers.shutdown()).await {
            cleanup_failures.push(format!("{name} signaling shutdown: {error}"));
        }
    }
    for (name, network) in std::iter::once(("root".to_owned(), &root))
        .chain(std::iter::once(("hub".to_owned(), &hub)))
        .chain(
            leaves
                .iter()
                .enumerate()
                .map(|(index, leaf)| (format!("leaf-{index}"), leaf)),
        )
    {
        match within(cleanup_deadline, network.shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => cleanup_failures.push(format!("{name} shutdown: {error}")),
            Err(error) => cleanup_failures.push(format!("{name} shutdown: {error}")),
        }
    }
    drop((root, hub));
    drop(leaves);
    for (mesh, baseline) in meshes.iter().zip(&baselines) {
        assert_resource_baseline(&mesh.resource_report(), baseline);
    }
    assert!(
        cleanup_failures.is_empty(),
        "Hub introduction cleanup failed: {cleanup_failures:?}; result={result:?}"
    );
    assert!(
        result.is_ok(),
        "Hub introduction acceptance failed: {result:?}"
    );
}
