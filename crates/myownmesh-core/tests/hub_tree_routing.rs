#![cfg(feature = "transport-lab")]

//! Production-path controls for the explicit shallow HubTree adapter.
//!
//! The fixture keeps the configured root and the preferred hub absent.  A's
//! only live next hop is B, even though B is lower-ranked than the absent
//! candidate under the same deterministic selector.  B and C therefore form
//! the authenticated route that must remain usable without a tree-parent
//! service or an accepted child relation.

use std::sync::Arc;
use std::time::Duration;

use ed25519_dalek::SigningKey;
use myownmesh_core::config::{
    HubPolicyConfig, NetworkConfig, RoutingPolicyConfig, SignalingConfig, TopologyMode,
    TreePolicyConfig,
};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::topology::{self, Topology};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};

const FIXTURE_DIMENSION_GRANT: u64 = 8_000_000_000;
const NETWORK_ID: &str = "hub-tree-routing-production";
const CHANNEL_NAME: &str = "hub-tree-route";

fn finite_connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, FIXTURE_DIMENSION_GRANT)),
    )
    .expect("finite HubTree fixture grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("finite HubTree fixture provider is valid");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn deterministic_identity(seed: u8) -> Arc<Identity> {
    Arc::new(Identity::from_signing_key(
        SigningKey::from_bytes(&[seed; 32]),
        format!("hub-tree-{seed}"),
    ))
}

fn hub_policy() -> HubPolicyConfig {
    HubPolicyConfig {
        max_parallel_dials: 1,
        max_dials_per_pass: 1,
        max_advertisements_per_pass: 1,
        exploration_interval_ms: 4_000,
        max_exploration_probes_per_pass: 1,
        max_exploration_peers_per_reply: 1,
        trickle_imin_ms: 4_000,
        trickle_imax_ms: 8_000,
        trickle_redundancy: 1,
        trickle_reset_window_ms: 8_000,
        trickle_max_resets_per_window: 1,
    }
}

fn tree_policy() -> TreePolicyConfig {
    TreePolicyConfig {
        max_children: 0,
        max_backups: 0,
        max_pending: 1,
        max_age_ms: 10_000,
    }
}

fn hub_tree_config(id: &str, root: &str, hubs: &[String]) -> NetworkConfig {
    let mut config = NetworkConfig::from_network_id(id, NETWORK_ID);
    config.label = id.to_owned();
    config.topology = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: hubs.to_vec(),
        backup_candidates: 0,
    };
    config.routing_policy = RoutingPolicyConfig {
        max_next_hops: 1,
        max_parallel_routes: 1,
        ..RoutingPolicyConfig::default()
    };
    config.hub = Some(hub_policy());
    config.tree = Some(tree_policy());
    config.signaling = SignalingConfig {
        strategy: "none".to_owned(),
        mdns: false,
        ..SignalingConfig::default()
    };
    config.auto_approve = true;
    config
}

fn fast_hub_tree_config(id: &str, root: &str, hubs: &[String], max_children: u64) -> NetworkConfig {
    let mut config = hub_tree_config(id, root, hubs);
    config.hub = Some(HubPolicyConfig {
        max_parallel_dials: 1,
        max_dials_per_pass: 1,
        max_advertisements_per_pass: 1,
        exploration_interval_ms: 20,
        max_exploration_probes_per_pass: 1,
        max_exploration_peers_per_reply: 1,
        trickle_imin_ms: 20,
        trickle_imax_ms: 40,
        trickle_redundancy: 1,
        trickle_reset_window_ms: 40,
        trickle_max_resets_per_window: 1,
    });
    config.scheduler.state_watch_interval_ms = 5;
    config.scheduler.wake_probe_delay_ms = 1;
    config.tree = Some(TreePolicyConfig {
        max_children,
        max_backups: 0,
        max_pending: 1,
        // Expiry is covered by the deterministic ParentingState controls;
        // this live transport fixture keeps accepted relations stable while
        // it observes routing, replacement, and discovery independently.
        max_age_ms: 60_000,
    });
    config
}

fn fast_hub_tree_config_with_backup(
    id: &str,
    root: &str,
    hubs: &[String],
    max_children: u64,
    backup_candidates: u32,
) -> NetworkConfig {
    let mut config = fast_hub_tree_config(id, root, hubs, max_children);
    config.topology = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: hubs.to_vec(),
        backup_candidates,
    };
    config.tree = Some(TreePolicyConfig {
        max_children,
        max_backups: u64::from(backup_candidates),
        max_pending: 1,
        max_age_ms: 60_000,
    });
    config
}

fn raw_public_key(seed: u8) -> [u8; 32] {
    *SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .as_bytes()
}

fn choose_leaf_identity(
    root: &str,
    hubs: &[String],
    desired_parent: &str,
    seeds: std::ops::RangeInclusive<u8>,
) -> (Arc<Identity>, u8) {
    let mode = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: hubs.to_vec(),
        backup_candidates: 0,
    };
    let selector = topology::from_mode(&mode);
    for seed in seeds {
        let identity = deterministic_identity(seed);
        let id = identity.public_id().to_owned();
        if selector
            .next_hops(&id, root, hubs, 1)
            .first()
            .is_some_and(|candidate| candidate == desired_parent)
        {
            return (identity, seed);
        }
    }
    panic!("identity pool did not produce the requested HubTree parent");
}

fn choose_leaf_outside_prefix(
    root: &str,
    hubs: &[String],
    outside_parent: &str,
    seeds: std::ops::RangeInclusive<u8>,
) -> (Arc<Identity>, u8) {
    let prefix_mode = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: hubs.to_vec(),
        backup_candidates: 1,
    };
    let full_mode = TopologyMode::HubTree {
        root: root.to_owned(),
        hubs: hubs.to_vec(),
        backup_candidates: 2,
    };
    let prefix_selector = topology::from_mode(&prefix_mode);
    let full_selector = topology::from_mode(&full_mode);
    for seed in seeds {
        let identity = deterministic_identity(seed);
        let id = identity.public_id().to_owned();
        let prefix = prefix_selector.next_hops(&id, root, hubs, 2);
        let full = full_selector.next_hops(&id, root, hubs, 3);
        if !prefix.iter().any(|candidate| candidate == outside_parent)
            && full
                .last()
                .is_some_and(|candidate| candidate == outside_parent)
        {
            return (identity, seed);
        }
    }
    panic!("identity pool did not produce an out-of-prefix HubTree parent");
}

async fn wait_for_parent(
    network: &myownmesh_core::JoinedNetwork,
    expected_parent: [u8; 32],
) -> myownmesh_core::handle::ParentingSnapshotForLab {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(snapshot) = network.parenting_snapshot_for_lab() {
                if snapshot.primary_parent == Some(expected_parent) && snapshot.pending == 0 {
                    return snapshot;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HubTree parent registration settles")
}

async fn wait_for_generation_after(
    network: &myownmesh_core::JoinedNetwork,
    previous_generation: u64,
) -> myownmesh_core::handle::ParentingSnapshotForLab {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let Some(snapshot) = network.parenting_snapshot_for_lab() {
                if snapshot.generation > previous_generation && snapshot.pending == 0 {
                    return snapshot;
                }
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HubTree attempt reaches a terminal response")
}

async fn wait_for_no_parent(network: &myownmesh_core::JoinedNetwork) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if network
                .parenting_snapshot_for_lab()
                .is_some_and(|snapshot| snapshot.primary_parent.is_none() && snapshot.pending == 0)
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("HubTree relation retires with its transport owner");
}

fn choose_hub_pair(root: &str, leaf: &str, destination: &str, hubs: &[String]) -> (String, String) {
    for absent in hubs {
        for selected in hubs {
            if absent == selected {
                continue;
            }
            let mode = TopologyMode::HubTree {
                root: root.to_owned(),
                hubs: vec![absent.clone(), selected.clone()],
                backup_candidates: 0,
            };
            let selector = topology::from_mode(&mode);
            let destination_peer = destination.to_owned();
            let both_connected =
                selector.next_hops(leaf, destination, &[absent.clone(), selected.clone()], 1);
            let selected_only =
                selector.next_hops(leaf, destination, std::slice::from_ref(selected), 1);
            let selected_to_destination = selector.next_hops(
                selected,
                destination,
                std::slice::from_ref(&destination_peer),
                1,
            );
            if both_connected == vec![absent.clone()]
                && selected_only == vec![selected.clone()]
                && selected_to_destination == vec![destination_peer]
            {
                return (absent.clone(), selected.clone());
            }
        }
    }
    panic!("deterministic identity pool did not produce the requested HubTree ranking");
}

async fn wait_for_transport_gone(network: &myownmesh_core::JoinedNetwork, peer: &str) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if network.capture_transport_channel_for_lab(peer).is_none() {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("retired real-link owner settles");
}

fn assert_live_resource_baseline(
    local_identity: &str,
    actual: &ResourceReport,
    baseline: &ResourceReport,
) {
    assert_eq!(
        actual.pre_authentication.len(),
        baseline.pre_authentication.len(),
        "mesh {local_identity}: pre-authentication family report length changed"
    );
    assert_eq!(
        actual.post_authentication.len(),
        baseline.post_authentication.len(),
        "mesh {local_identity}: post-authentication family report length changed"
    );
    for (actual, baseline) in actual
        .pre_authentication
        .iter()
        .zip(baseline.pre_authentication.iter())
    {
        assert_eq!(
            actual.family,
            baseline.family,
            "mesh {local_identity}: pre-authentication family ordering changed: actual={:?} baseline={:?}",
            actual.family,
            baseline.family
        );
        assert_eq!(
            actual.active,
            baseline.active,
            "mesh {local_identity}: pre-authentication {:?} active mismatch: actual={:?} baseline={:?}; active_lease_count actual={} baseline={}",
            actual.family,
            actual.active,
            baseline.active,
            actual.active_lease_count,
            baseline.active_lease_count
        );
        assert_eq!(
            actual.active_lease_count,
            baseline.active_lease_count,
            "mesh {local_identity}: pre-authentication {:?} lease-count mismatch: actual active={:?} leases={} baseline active={:?} leases={}",
            actual.family,
            actual.active,
            actual.active_lease_count,
            baseline.active,
            baseline.active_lease_count
        );
    }
    for (actual, baseline) in actual
        .post_authentication
        .iter()
        .zip(baseline.post_authentication.iter())
    {
        assert_eq!(
            actual.family,
            baseline.family,
            "mesh {local_identity}: post-authentication family ordering changed: actual={:?} baseline={:?}",
            actual.family,
            baseline.family
        );
        assert_eq!(
            actual.active,
            baseline.active,
            "mesh {local_identity}: post-authentication {:?} active mismatch: actual={:?} baseline={:?}; active_lease_count actual={} baseline={}",
            actual.family,
            actual.active,
            baseline.active,
            actual.active_lease_count,
            baseline.active_lease_count
        );
        assert_eq!(
            actual.active_lease_count,
            baseline.active_lease_count,
            "mesh {local_identity}: post-authentication {:?} lease-count mismatch: actual active={:?} leases={} baseline active={:?} leases={}",
            actual.family,
            actual.active,
            actual.active_lease_count,
            baseline.active,
            baseline.active_lease_count
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn hub_tree_routes_without_parent_service_and_fails_without_exit_path(
) -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("isolated mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    // The root and every candidate are deterministic, but only A, B, and C
    // are opened.  The pair selection is a reference check against the same
    // production HubTree selector used by each network.
    let root_identity = deterministic_identity(1);
    let a_identity = deterministic_identity(2);
    let c_identity = deterministic_identity(3);
    let hub_identities: Vec<_> = (0x10..0x30).map(deterministic_identity).collect();
    let root_id = root_identity.public_id().to_owned();
    let a_id = a_identity.public_id().to_owned();
    let c_id = c_identity.public_id().to_owned();
    let hub_ids: Vec<_> = hub_identities
        .iter()
        .map(|identity| identity.public_id().to_owned())
        .collect();
    let (absent_hub_id, b_id) = choose_hub_pair(&root_id, &a_id, &c_id, &hub_ids);
    let b_identity = hub_identities
        .iter()
        .find(|identity| identity.public_id() == b_id)
        .expect("selected hub identity is retained")
        .clone();
    let configured_hubs = vec![absent_hub_id.clone(), b_id.clone()];

    let reference_mode = TopologyMode::HubTree {
        root: root_id.clone(),
        hubs: configured_hubs.clone(),
        backup_candidates: 0,
    };
    let reference = topology::from_mode(&reference_mode);
    assert_eq!(
        reference.next_hops(&a_id, &c_id, &[absent_hub_id.clone(), b_id.clone()], 1),
        vec![absent_hub_id.clone()],
        "the absent hub is the preferred candidate when present"
    );
    assert_eq!(
        reference.next_hops(&a_id, &c_id, std::slice::from_ref(&b_id), 1),
        vec![b_id.clone()],
        "the connected lower-ranked hub is the bounded fallback"
    );
    assert_eq!(
        reference.next_hops(&b_id, &c_id, std::slice::from_ref(&c_id), 1),
        vec![c_id.clone()],
        "B is C's primary configured hub"
    );

    let policy = finite_connector_policy();
    let a_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        a_identity,
        policy.clone(),
    )
    .await?;
    let b_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        b_identity,
        policy.clone(),
    )
    .await?;
    let c_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        c_identity,
        policy.clone(),
    )
    .await?;
    let baselines = [
        a_mesh.resource_report(),
        b_mesh.resource_report(),
        c_mesh.resource_report(),
    ];

    let a = a_mesh
        .join(hub_tree_config("a", &root_id, &configured_hubs))
        .await?;
    let b = b_mesh
        .join(hub_tree_config("b", &root_id, &configured_hubs))
        .await?;
    let c = c_mesh
        .join(hub_tree_config("c", &root_id, &configured_hubs))
        .await?;

    let a_b = a.install_promoted_peer_over_real_link(&b).await;
    let b_c = b.install_promoted_peer_over_real_link(&c).await;
    assert_eq!(a_b.peer_device_id(), b_id);
    assert_eq!(b_c.peer_device_id(), c_id);
    assert!(a.peer(&b_id).is_some(), "A-B is an authenticated live link");
    assert!(b.peer(&c_id).is_some(), "B-C is an authenticated live link");
    assert!(a.peer(&c_id).is_none(), "A has no direct C owner");
    assert!(a.peer(&root_id).is_none(), "the configured root is absent");

    let c_channel = c.channel::<String>(CHANNEL_NAME);
    let mut c_subscription = c_channel.subscribe().expect("C subscription is funded");
    let a_channel = a.channel::<String>(CHANNEL_NAME);
    let routed_payload = "A-to-C through authenticated B".to_owned();
    a_channel
        .send_to(&c_id, &routed_payload)
        .await
        .expect("the authenticated B-C route is usable without an accepted parent relation");
    let delivered = tokio::time::timeout(Duration::from_secs(5), c_subscription.recv())
        .await
        .expect("C receives the routed payload")
        .expect("C subscription remains live")
        .expect("C receives without a decode refusal");
    assert_eq!(delivered.from(), a_id);
    assert_eq!(delivered.body(), &routed_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), c_subscription.recv())
            .await
            .is_err(),
        "the routed payload is delivered exactly once"
    );

    // Capture both exact endpoint owners while the authenticated link is
    // still live.  The lab terminal seam uses these captured witnesses for
    // an injected exact terminal notification rather than re-resolving a
    // device id after the link closes; this is not natural-close convergence.
    let a_b_witness = a
        .capture_transport_channel_for_lab(&b_id)
        .expect("A-B transport owner is capturable before closure");
    let b_a_witness = b
        .capture_transport_channel_for_lab(&a_id)
        .expect("B-A transport owner is capturable before closure");
    a.retire_transport_channel_for_lab(&a_b_witness).await;
    b.retire_transport_channel_for_lab(&b_a_witness).await;
    let _ = a_b.retire().await;
    wait_for_transport_gone(&a, &b_id).await;
    drop(a_b_witness);
    drop(b_a_witness);
    assert!(a.peer(&c_id).is_none(), "A still has no direct C owner");

    let a_c = a.install_promoted_peer_over_real_link(&c).await;
    assert_eq!(a_c.peer_device_id(), c_id);
    let direct_payload = "A-to-C direct after B retirement".to_owned();
    a_channel
        .send_to(&c_id, &direct_payload)
        .await
        .expect("the authenticated direct A-C route is usable");
    let delivered = tokio::time::timeout(Duration::from_secs(5), c_subscription.recv())
        .await
        .expect("C receives the direct payload")
        .expect("C subscription remains live")
        .expect("C receives the direct payload without decode refusal");
    assert_eq!(delivered.from(), a_id);
    assert_eq!(delivered.body(), &direct_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), c_subscription.recv())
            .await
            .is_err(),
        "the direct payload is delivered exactly once"
    );

    let a_c_witness = a
        .capture_transport_channel_for_lab(&c_id)
        .expect("A-C transport owner is capturable before closure");
    let c_a_witness = c
        .capture_transport_channel_for_lab(&a_id)
        .expect("C-A transport owner is capturable before closure");
    a.retire_transport_channel_for_lab(&a_c_witness).await;
    c.retire_transport_channel_for_lab(&c_a_witness).await;
    let _ = a_c.retire().await;
    wait_for_transport_gone(&a, &c_id).await;
    drop(a_c_witness);
    drop(c_a_witness);
    assert!(
        a.capture_transport_channel_for_lab(&b_id).is_none(),
        "A has no retained B exit path"
    );
    assert!(
        a.capture_transport_channel_for_lab(&c_id).is_none(),
        "A has no retained C exit path"
    );
    let no_route = a_channel
        .send_to(&c_id, &"must not send without an A exit path".to_owned())
        .await
        .expect_err("A has no pre-send route to C");
    assert!(
        no_route.to_string().contains("no usable next hop"),
        "the refusal is the typed pre-send no-route path, got: {no_route}"
    );

    let _ = b_c.retire().await;
    a.shutdown().await?;
    b.shutdown().await?;
    c.shutdown().await?;
    drop(a);
    drop(b);
    drop(c);
    assert_live_resource_baseline(
        &a_mesh.device_id(),
        &a_mesh.resource_report(),
        &baselines[0],
    );
    assert_live_resource_baseline(
        &b_mesh.device_id(),
        &b_mesh.resource_report(),
        &baselines[1],
    );
    assert_live_resource_baseline(
        &c_mesh.device_id(),
        &c_mesh.resource_report(),
        &baselines[2],
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn hub_tree_real_wire_parenting_route_capacity_and_discovery() -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("isolated mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let root_identity = deterministic_identity(1);
    let h1_identity = deterministic_identity(0x10);
    let h2_identity = deterministic_identity(0x11);
    let root_id = root_identity.public_id().to_owned();
    let h1_id = h1_identity.public_id().to_owned();
    let h2_id = h2_identity.public_id().to_owned();
    let configured_hubs = vec![h1_id.clone(), h2_id.clone()];
    let (l1_identity, l1_seed) =
        choose_leaf_identity(&root_id, &configured_hubs, &h1_id, 0x40..=0x7f);
    let (l2_identity, l2_seed) =
        choose_leaf_identity(&root_id, &configured_hubs, &h2_id, 0x80..=0xbf);
    let (overflow_identity, _overflow_seed) =
        choose_leaf_identity(&root_id, &configured_hubs, &h1_id, 0xc0..=0xfe);
    let l1_id = l1_identity.public_id().to_owned();
    let l2_id = l2_identity.public_id().to_owned();
    let overflow_id = overflow_identity.public_id().to_owned();

    let selector = topology::from_mode(&TopologyMode::HubTree {
        root: root_id.clone(),
        hubs: configured_hubs.clone(),
        backup_candidates: 0,
    });
    assert_eq!(
        selector.next_hops(&l1_id, &root_id, &configured_hubs, 1),
        vec![h1_id.clone()]
    );
    assert_eq!(
        selector.next_hops(&l2_id, &root_id, &configured_hubs, 1),
        vec![h2_id.clone()]
    );
    assert_eq!(
        selector.next_hops(&overflow_id, &root_id, &configured_hubs, 1),
        vec![h1_id.clone()]
    );

    let policy = finite_connector_policy();
    let root_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        root_identity,
        policy.clone(),
    )
    .await?;
    let h1_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h1_identity.clone(),
        policy.clone(),
    )
    .await?;
    let h2_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h2_identity,
        policy.clone(),
    )
    .await?;
    let l1_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        l1_identity,
        policy.clone(),
    )
    .await?;
    let l2_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        l2_identity,
        policy.clone(),
    )
    .await?;
    let overflow_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        overflow_identity,
        policy.clone(),
    )
    .await?;
    let baselines = [
        root_mesh.resource_report(),
        h1_mesh.resource_report(),
        h2_mesh.resource_report(),
        l1_mesh.resource_report(),
        l2_mesh.resource_report(),
        overflow_mesh.resource_report(),
    ];

    let root = root_mesh
        .join(fast_hub_tree_config("root", &root_id, &configured_hubs, 2))
        .await?;
    let h1 = h1_mesh
        .join(fast_hub_tree_config("h1", &root_id, &configured_hubs, 1))
        .await?;
    let h2 = h2_mesh
        .join(fast_hub_tree_config("h2", &root_id, &configured_hubs, 1))
        .await?;
    let l1 = l1_mesh
        .join(fast_hub_tree_config("l1", &root_id, &configured_hubs, 0))
        .await?;
    let l2 = l2_mesh
        .join(fast_hub_tree_config("l2", &root_id, &configured_hubs, 0))
        .await?;
    let overflow = overflow_mesh
        .join(fast_hub_tree_config(
            "overflow",
            &root_id,
            &configured_hubs,
            0,
        ))
        .await?;

    // These are the only four transport links.  Consequently the successful
    // application delivery below has exactly the physical four-hop route
    // L1-H1-R-H2-L2; no direct or alternate transport can hide a route error.
    let root_h1 = root.install_promoted_peer_over_real_link(&h1).await;
    let root_h2 = root.install_promoted_peer_over_real_link(&h2).await;
    let h1_l1 = h1.install_promoted_peer_over_real_link(&l1).await;
    let h2_l2 = h2.install_promoted_peer_over_real_link(&l2).await;
    assert_eq!(root_h1.peer_device_id(), h1_id);
    assert_eq!(root_h2.peer_device_id(), h2_id);
    assert_eq!(h1_l1.peer_device_id(), l1_id);
    assert_eq!(h2_l2.peer_device_id(), l2_id);

    wait_for_parent(&h1, raw_public_key(1)).await;
    wait_for_parent(&h2, raw_public_key(1)).await;
    let l1_parent = wait_for_parent(&l1, raw_public_key(0x10)).await;
    let l2_parent = wait_for_parent(&l2, raw_public_key(0x11)).await;
    // `wait_for_parent` returns a value snapshot.  Read H1/H2 again after
    // their leaf admissions, otherwise the child count is necessarily stale.
    let h1_parent = h1
        .parenting_snapshot_for_lab()
        .expect("H1 has a HubTree table after leaf admission");
    let h2_parent = h2
        .parenting_snapshot_for_lab()
        .expect("H2 has a HubTree table after leaf admission");
    assert_eq!(h1_parent.accepted_children, 1);
    assert_eq!(h2_parent.accepted_children, 1);
    assert_eq!(l1_parent.accepted_children, 0);
    assert_eq!(l2_parent.accepted_children, 0);
    assert_eq!(
        root.parenting_snapshot_for_lab()
            .expect("root has a HubTree table")
            .accepted_children,
        2
    );
    assert!(l1.peer(&root_id).is_none());
    assert!(l1.peer(&h2_id).is_none());
    assert!(l2.peer(&root_id).is_none());
    assert!(l2.peer(&h1_id).is_none());

    let l2_channel = l2.channel::<String>(CHANNEL_NAME);
    let mut l2_subscription = l2_channel.subscribe().expect("L2 subscription is funded");
    let l1_channel = l1.channel::<String>(CHANNEL_NAME);
    let mut l1_subscription = l1_channel.subscribe().expect("L1 subscription is funded");
    let four_hop_payload = format!("L1-{l1_seed}-to-L2-{l2_seed}");
    l1_channel
        .send_to(&l2_id, &four_hop_payload)
        .await
        .expect("forward four-hop payload is sent");
    let delivered = tokio::time::timeout(Duration::from_secs(5), l2_subscription.recv())
        .await
        .expect("four-hop payload reaches L2")
        .expect("L2 subscription remains live")
        .expect("four-hop payload decodes");
    assert_eq!(delivered.from(), l1_id);
    assert_eq!(delivered.body(), &four_hop_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), l2_subscription.recv())
            .await
            .is_err(),
        "four-hop payload is delivered exactly once"
    );
    let reverse_payload = "L2-to-L1 reverse four-hop payload".to_owned();
    l2_channel
        .send_to(&l1_id, &reverse_payload)
        .await
        .expect("reverse four-hop payload is sent");
    let reverse_delivered = tokio::time::timeout(Duration::from_secs(5), l1_subscription.recv())
        .await
        .expect("reverse four-hop payload reaches L1")
        .expect("L1 subscription remains live")
        .expect("reverse four-hop payload decodes");
    assert_eq!(reverse_delivered.from(), l2_id);
    assert_eq!(reverse_delivered.body(), &reverse_payload);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), l1_subscription.recv())
            .await
            .is_err(),
        "reverse four-hop payload is delivered exactly once"
    );

    // H1's one-child service is full.  The sixth leaf is connected only to
    // H1, so the production attach request must be refused rather than
    // silently becoming a relation through the other configured candidate.
    let overflow_before = overflow
        .parenting_snapshot_for_lab()
        .expect("overflow has a HubTree table")
        .generation;
    let overflow_h1 = overflow.install_promoted_peer_over_real_link(&h1).await;
    let overflow_after = wait_for_generation_after(&overflow, overflow_before).await;
    assert!(overflow_after.primary_parent.is_none());
    assert_eq!(overflow_after.pending, 0);
    assert_eq!(
        h1.parenting_snapshot_for_lab()
            .expect("H1 has a HubTree table")
            .accepted_children,
        1,
        "H1 capacity refusal does not displace L1"
    );
    let overflow_witness = overflow
        .capture_transport_channel_for_lab(&h1_id)
        .expect("overflow-H1 owner is capturable");
    let h1_overflow_witness = h1
        .capture_transport_channel_for_lab(&overflow_id)
        .expect("H1-overflow owner is capturable");
    overflow
        .retire_transport_channel_for_lab(&overflow_witness)
        .await;
    h1.retire_transport_channel_for_lab(&h1_overflow_witness)
        .await;
    let _ = overflow_h1.retire().await;
    wait_for_transport_gone(&overflow, &h1_id).await;

    // The accepted L1-H1 relation is replaced by a fresh owner with the same
    // canonical identity.  The old exact witness is deliberately invoked
    // after W1 is current; it must not retire the successor relation.
    let old_l1_h1_witness = l1
        .capture_transport_channel_for_lab(&h1_id)
        .expect("W0 L1-H1 owner is capturable");
    let old_h1_l1_witness = h1
        .capture_transport_channel_for_lab(&l1_id)
        .expect("W0 H1-L1 owner is capturable");
    l1.retire_transport_channel_for_lab(&old_l1_h1_witness)
        .await;
    h1.retire_transport_channel_for_lab(&old_h1_l1_witness)
        .await;
    let _ = h1_l1.retire().await;
    wait_for_transport_gone(&l1, &h1_id).await;
    wait_for_no_parent(&l1).await;

    let h1_mesh_w1 = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h1_identity,
        policy.clone(),
    )
    .await?;
    let h1_w1_baseline = h1_mesh_w1.resource_report();
    let h1_w1 = h1_mesh_w1
        .join(fast_hub_tree_config("h1-w1", &root_id, &configured_hubs, 1))
        .await?;
    let h1_l1_w1 = h1_w1.install_promoted_peer_over_real_link(&l1).await;
    wait_for_parent(&l1, raw_public_key(0x10)).await;
    l1.retire_transport_channel_for_lab(&old_l1_h1_witness)
        .await;
    h1.retire_transport_channel_for_lab(&old_h1_l1_witness)
        .await;
    assert!(
        l1.parenting_snapshot_for_lab()
            .expect("L1 has a HubTree table")
            .primary_parent
            == Some(raw_public_key(0x10)),
        "stale W0 witness cannot retire the W1 relation"
    );

    let new_l1_h1_witness = l1
        .capture_transport_channel_for_lab(&h1_id)
        .expect("W1 L1-H1 owner is capturable");
    let new_h1_l1_witness = h1_w1
        .capture_transport_channel_for_lab(&l1_id)
        .expect("W1 H1-L1 owner is capturable");
    l1.retire_transport_channel_for_lab(&new_l1_h1_witness)
        .await;
    h1_w1
        .retire_transport_channel_for_lab(&new_h1_l1_witness)
        .await;
    let _ = h1_l1_w1.retire().await;
    wait_for_transport_gone(&l1, &h1_id).await;
    wait_for_no_parent(&l1).await;

    // Discovery is paced independently from accepted-parent maintenance. H2
    // has two eligible current owners (R and L2), while pages are capped at
    // one, so L2 can obtain two pages from its configured H2 peer.
    // The fixed diagnostics facade is intentionally used instead of private
    // handler calls or a payload/event-history approximation.
    let discovery_before = l2
        .hub_discovery_diagnostics_for_lab()
        .expect("L2 has a hub controller");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if l2
                .hub_discovery_diagnostics_for_lab()
                .is_some_and(|diagnostics| {
                    diagnostics.pages_accepted >= discovery_before.pages_accepted + 2
                        && diagnostics.cursor_advances > discovery_before.cursor_advances
                        && diagnostics.continuation_pages_accepted
                            > discovery_before.continuation_pages_accepted
                })
            {
                return;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("healthy-parent discovery reaches two bounded pages");
    let discovery = l2
        .hub_discovery_diagnostics_for_lab()
        .expect("L2 retains fixed discovery diagnostics");
    assert_eq!(discovery.configured_hubs, 2);
    assert!(discovery.requests_started >= discovery_before.requests_started + 2);
    assert!(discovery.requests_bound >= discovery_before.requests_bound + 2);
    assert!(discovery.responses_accepted >= discovery_before.responses_accepted + 2);
    assert!(discovery.cursor_advances > discovery_before.cursor_advances);
    assert!(discovery.last_page_len <= 1);
    assert_eq!(discovery.pending_requests, 0);
    let known_directory_keys = [raw_public_key(1), raw_public_key(l2_seed)];
    assert!(discovery
        .last_accepted_first
        .is_some_and(|key| known_directory_keys.contains(&key)));
    assert!(discovery
        .last_accepted_last
        .is_some_and(|key| known_directory_keys.contains(&key)));
    assert!(discovery
        .last_accepted_request_after
        .is_none_or(|key| known_directory_keys.contains(&key)));
    // These three fields are captured atomically from the same accepted
    // response.  Compare semantic DeviceId ordering rather than raw key
    // bytes: canonical identifier ordering is the protocol's cursor order.
    match (
        discovery.last_accepted_request_after,
        discovery.last_accepted_first,
        discovery.last_accepted_last,
    ) {
        (Some(after), Some(first), Some(last)) => {
            let after = myownmesh_core::semantic::DeviceId::from_public_key_bytes(after)
                .expect("accepted request cursor is a canonical key");
            let first = myownmesh_core::semantic::DeviceId::from_public_key_bytes(first)
                .expect("accepted page first key is canonical");
            let last = myownmesh_core::semantic::DeviceId::from_public_key_bytes(last)
                .expect("accepted page last key is canonical");
            assert!(
                after < first,
                "accepted continuation page advances its cursor"
            );
            assert!(first <= last, "accepted page keys preserve canonical order");
        }
        (None, Some(_first), Some(_last)) => {}
        _ => panic!("accepted discovery diagnostics must retain one complete page tuple"),
    }
    assert!(
        l2.parenting_snapshot_for_lab()
            .expect("L2 has a HubTree table")
            .primary_parent
            == Some(raw_public_key(0x11)),
        "discovery does not suppress a healthy accepted parent"
    );

    // Advance only L2's parenting clock.  The exact transport owner remains
    // live, but the accepted relation is no longer a valid routing preference
    // once its age is crossed.  The atomic lab seam observes expiry before a
    // scheduler tick can perform the paced reattachment.
    let expired = l2
        .advance_parenting_clock_and_snapshot_for_lab(60_001)?
        .expect("L2 retains its parenting table after clock advance");
    assert!(expired.primary_parent.is_none());
    assert_eq!(expired.pending, 0);
    assert!(
        l2.peer(&h2_id).is_some(),
        "relation age does not falsely claim the transport owner is gone"
    );
    let renewed = wait_for_parent(&l2, raw_public_key(0x11)).await;
    assert!(
        renewed.generation > expired.generation,
        "expired relation is replaced by a newer paced registration"
    );

    drop(old_l1_h1_witness);
    drop(old_h1_l1_witness);
    drop(overflow_witness);
    drop(h1_overflow_witness);
    drop(new_l1_h1_witness);
    drop(new_h1_l1_witness);
    let _ = root_h1.retire().await;
    let _ = root_h2.retire().await;
    let _ = h2_l2.retire().await;
    root.shutdown().await?;
    h1.shutdown().await?;
    h2.shutdown().await?;
    l1.shutdown().await?;
    l2.shutdown().await?;
    overflow.shutdown().await?;
    h1_w1.shutdown().await?;
    drop(root);
    drop(h1);
    drop(h2);
    drop(l1);
    drop(l2);
    drop(overflow);
    drop(h1_w1);
    assert_live_resource_baseline(
        &root_mesh.device_id(),
        &root_mesh.resource_report(),
        &baselines[0],
    );
    assert_live_resource_baseline(
        &h1_mesh.device_id(),
        &h1_mesh.resource_report(),
        &baselines[1],
    );
    assert_live_resource_baseline(
        &h2_mesh.device_id(),
        &h2_mesh.resource_report(),
        &baselines[2],
    );
    assert_live_resource_baseline(
        &l1_mesh.device_id(),
        &l1_mesh.resource_report(),
        &baselines[3],
    );
    assert_live_resource_baseline(
        &l2_mesh.device_id(),
        &l2_mesh.resource_report(),
        &baselines[4],
    );
    assert_live_resource_baseline(
        &overflow_mesh.device_id(),
        &overflow_mesh.resource_report(),
        &baselines[5],
    );
    assert_live_resource_baseline(
        &h1_mesh_w1.device_id(),
        &h1_mesh_w1.resource_report(),
        &h1_w1_baseline,
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn hub_tree_connected_full_prefix_uses_live_out_of_prefix_parent(
) -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("isolated mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let root_identity = deterministic_identity(1);
    let h0_identity = deterministic_identity(0x20);
    let h1_identity = deterministic_identity(0x21);
    let h2_identity = deterministic_identity(0x22);
    let root_id = root_identity.public_id().to_owned();
    let hubs = vec![
        h0_identity.public_id().to_owned(),
        h1_identity.public_id().to_owned(),
        h2_identity.public_id().to_owned(),
    ];
    let h0_id = hubs[0].clone();
    let h1_id = hubs[1].clone();
    let h2_id = hubs[2].clone();
    let (target_identity, _target_seed) =
        choose_leaf_outside_prefix(&root_id, &hubs, &h2_id, 0x40..=0x7f);
    let (f0_identity, _f0_seed) = choose_leaf_identity(&root_id, &hubs, &h0_id, 0x80..=0xbf);
    let (f1_identity, _f1_seed) = choose_leaf_identity(&root_id, &hubs, &h1_id, 0xc0..=0xfe);
    let target_id = target_identity.public_id().to_owned();
    let f0_id = f0_identity.public_id().to_owned();
    let f1_id = f1_identity.public_id().to_owned();

    let prefix_selector = topology::from_mode(&TopologyMode::HubTree {
        root: root_id.clone(),
        hubs: hubs.clone(),
        backup_candidates: 1,
    });
    let all_selector = topology::from_mode(&TopologyMode::HubTree {
        root: root_id.clone(),
        hubs: hubs.clone(),
        backup_candidates: 2,
    });
    let prefix = prefix_selector.next_hops(&target_id, &root_id, &hubs, 2);
    let all = all_selector.next_hops(&target_id, &root_id, &hubs, 3);
    assert_eq!(all.last(), Some(&h2_id));
    assert!(!prefix.iter().any(|candidate| candidate == &h2_id));

    let policy = finite_connector_policy();
    let root_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        root_identity,
        policy.clone(),
    )
    .await?;
    let h0_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h0_identity,
        policy.clone(),
    )
    .await?;
    let h1_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h1_identity,
        policy.clone(),
    )
    .await?;
    let h2_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        h2_identity,
        policy.clone(),
    )
    .await?;
    let target_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        target_identity,
        policy.clone(),
    )
    .await?;
    let f0_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        f0_identity,
        policy.clone(),
    )
    .await?;
    let f1_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        f1_identity,
        policy.clone(),
    )
    .await?;
    let baselines = [
        root_mesh.resource_report(),
        h0_mesh.resource_report(),
        h1_mesh.resource_report(),
        h2_mesh.resource_report(),
        target_mesh.resource_report(),
        f0_mesh.resource_report(),
        f1_mesh.resource_report(),
    ];

    let root = root_mesh
        .join(fast_hub_tree_config_with_backup(
            "root-3", &root_id, &hubs, 3, 1,
        ))
        .await?;
    let h0 = h0_mesh
        .join(fast_hub_tree_config_with_backup(
            "h0", &root_id, &hubs, 1, 1,
        ))
        .await?;
    let h1 = h1_mesh
        .join(fast_hub_tree_config_with_backup(
            "h1", &root_id, &hubs, 1, 1,
        ))
        .await?;
    let h2 = h2_mesh
        .join(fast_hub_tree_config_with_backup(
            "h2", &root_id, &hubs, 1, 1,
        ))
        .await?;
    let target = target_mesh
        .join(fast_hub_tree_config_with_backup(
            "target", &root_id, &hubs, 0, 1,
        ))
        .await?;
    let f0 = f0_mesh
        .join(fast_hub_tree_config_with_backup(
            "f0", &root_id, &hubs, 0, 1,
        ))
        .await?;
    let f1 = f1_mesh
        .join(fast_hub_tree_config_with_backup(
            "f1", &root_id, &hubs, 0, 1,
        ))
        .await?;

    let root_h0 = root.install_promoted_peer_over_real_link(&h0).await;
    let root_h1 = root.install_promoted_peer_over_real_link(&h1).await;
    let root_h2 = root.install_promoted_peer_over_real_link(&h2).await;
    wait_for_parent(&h0, raw_public_key(1)).await;
    wait_for_parent(&h1, raw_public_key(1)).await;
    wait_for_parent(&h2, raw_public_key(1)).await;
    assert_eq!(
        root.parenting_snapshot_for_lab()
            .expect("root has a HubTree table")
            .accepted_children,
        3
    );

    let h0_f0 = h0.install_promoted_peer_over_real_link(&f0).await;
    let h1_f1 = h1.install_promoted_peer_over_real_link(&f1).await;
    wait_for_parent(&f0, raw_public_key(0x20)).await;
    wait_for_parent(&f1, raw_public_key(0x21)).await;
    assert_eq!(
        h0.parenting_snapshot_for_lab()
            .expect("H0 has a HubTree table")
            .accepted_children,
        1
    );
    assert_eq!(
        h1.parenting_snapshot_for_lab()
            .expect("H1 has a HubTree table")
            .accepted_children,
        1
    );

    // All three candidate hubs are connected. H0 and H1 occupy the static
    // two-entry preferred prefix, while H2 is a live lower-ranked candidate.
    // The attach cursor must continue after capacity refusals and admit H2;
    // a preferred-service cap must not become a global connection veto.
    let target_h0 = target.install_promoted_peer_over_real_link(&h0).await;
    let target_h1 = target.install_promoted_peer_over_real_link(&h1).await;
    let target_h2 = target.install_promoted_peer_over_real_link(&h2).await;
    let target_parent = wait_for_parent(&target, raw_public_key(0x22)).await;
    assert_eq!(target_parent.accepted_children, 0);
    assert_eq!(
        h0.parenting_snapshot_for_lab()
            .expect("H0 has a HubTree table")
            .accepted_children,
        1,
        "H0 remains full while target falls back"
    );
    assert_eq!(
        h1.parenting_snapshot_for_lab()
            .expect("H1 has a HubTree table")
            .accepted_children,
        1,
        "H1 remains full while target falls back"
    );
    assert_eq!(
        h2.parenting_snapshot_for_lab()
            .expect("H2 has a HubTree table")
            .accepted_children,
        1,
        "H2 accepts the connected out-of-prefix target"
    );
    assert!(target.peer(&h0_id).is_some());
    assert!(target.peer(&h1_id).is_some());
    assert!(target.peer(&h2_id).is_some());
    let target_h0_witness = target
        .capture_transport_channel_for_lab(&h0_id)
        .expect("target-H0 owner is capturable");
    let h0_target_witness = h0
        .capture_transport_channel_for_lab(&target_id)
        .expect("H0-target owner is capturable");
    let target_h1_witness = target
        .capture_transport_channel_for_lab(&h1_id)
        .expect("target-H1 owner is capturable");
    let h1_target_witness = h1
        .capture_transport_channel_for_lab(&target_id)
        .expect("H1-target owner is capturable");
    let target_h2_witness = target
        .capture_transport_channel_for_lab(&h2_id)
        .expect("target-H2 owner is capturable");
    let h2_target_witness = h2
        .capture_transport_channel_for_lab(&target_id)
        .expect("H2-target owner is capturable");
    eprintln!("[hub-tree-teardown] retire target-h0");
    target
        .retire_transport_channel_for_lab(&target_h0_witness)
        .await;
    eprintln!("[hub-tree-teardown] retire h0-target");
    h0.retire_transport_channel_for_lab(&h0_target_witness)
        .await;
    eprintln!("[hub-tree-teardown] retire target-h1");
    target
        .retire_transport_channel_for_lab(&target_h1_witness)
        .await;
    eprintln!("[hub-tree-teardown] retire h1-target");
    h1.retire_transport_channel_for_lab(&h1_target_witness)
        .await;
    eprintln!("[hub-tree-teardown] retire target-h2");
    target
        .retire_transport_channel_for_lab(&target_h2_witness)
        .await;
    eprintln!("[hub-tree-teardown] retire h2-target");
    h2.retire_transport_channel_for_lab(&h2_target_witness)
        .await;
    // The witness is a retained exact-owner observation.  Release each after
    // its terminal notification, before the network shutdown baseline.
    drop(target_h0_witness);
    drop(h0_target_witness);
    drop(target_h1_witness);
    drop(h1_target_witness);
    drop(target_h2_witness);
    drop(h2_target_witness);
    eprintln!("[hub-tree-teardown] close target-h0 link handle");
    let _ = target_h0.retire().await;
    eprintln!("[hub-tree-teardown] close target-h1 link handle");
    let _ = target_h1.retire().await;
    eprintln!("[hub-tree-teardown] close target-h2 link handle");
    let _ = target_h2.retire().await;
    eprintln!("[hub-tree-teardown] close h0-f0 link handle");
    let _ = h0_f0.retire().await;
    eprintln!("[hub-tree-teardown] close h1-f1 link handle");
    let _ = h1_f1.retire().await;
    eprintln!("[hub-tree-teardown] close root-h0 link handle");
    let _ = root_h0.retire().await;
    eprintln!("[hub-tree-teardown] close root-h1 link handle");
    let _ = root_h1.retire().await;
    eprintln!("[hub-tree-teardown] close root-h2 link handle");
    let _ = root_h2.retire().await;
    eprintln!("[hub-tree-teardown] shutdown root");
    root.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown h0");
    h0.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown h1");
    h1.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown h2");
    h2.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown target");
    target.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown f0");
    f0.shutdown().await?;
    eprintln!("[hub-tree-teardown] shutdown f1");
    f1.shutdown().await?;
    drop(root);
    drop(h0);
    drop(h1);
    drop(h2);
    drop(target);
    drop(f0);
    drop(f1);
    assert_live_resource_baseline(
        &root_mesh.device_id(),
        &root_mesh.resource_report(),
        &baselines[0],
    );
    assert_live_resource_baseline(
        &h0_mesh.device_id(),
        &h0_mesh.resource_report(),
        &baselines[1],
    );
    assert_live_resource_baseline(
        &h1_mesh.device_id(),
        &h1_mesh.resource_report(),
        &baselines[2],
    );
    assert_live_resource_baseline(
        &h2_mesh.device_id(),
        &h2_mesh.resource_report(),
        &baselines[3],
    );
    assert_live_resource_baseline(
        &target_mesh.device_id(),
        &target_mesh.resource_report(),
        &baselines[4],
    );
    assert_live_resource_baseline(
        &f0_mesh.device_id(),
        &f0_mesh.resource_report(),
        &baselines[5],
    );
    assert_live_resource_baseline(
        &f1_mesh.device_id(),
        &f1_mesh.resource_report(),
        &baselines[6],
    );
    Ok(())
}
