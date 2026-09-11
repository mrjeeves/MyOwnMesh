#![cfg(feature = "transport-lab")]

//! Production-path topology and direct endpoint controls.
//!
//! The topology planner remains bounded and deterministic, while application
//! bytes use an authenticated direct endpoint. Hub/sibling selection is not a
//! member-payload forwarding permission.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort, ResourceReport,
};
use myownmesh_core::{
    ConnectorCallbackPolicy, Identity, Mesh, MeshConfig, WebRtcConnectorCapablePolicy,
    WebRtcConnectorProfile,
};

const FIXTURE_DIMENSION_GRANT: u64 = 8_000_000_000;
const ROUTE_NETWORK_ID: &str = "topology-routing-production";
const CHANNEL_NAME: &str = "bounded-route";

fn finite_connector_policy() -> WebRtcConnectorCapablePolicy {
    let grant = ResourceClaim::try_from_entries(
        ResourceClass::ALL
            .into_iter()
            .map(|class| (class, FIXTURE_DIMENSION_GRANT)),
    )
    .expect("finite routing fixture grant is representable");
    let resources = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
        .expect("finite routing fixture provider is valid");
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn assert_live_resource_baseline(actual: &ResourceReport, baseline: &ResourceReport) {
    for (actual, baseline) in actual
        .pre_authentication
        .iter()
        .zip(baseline.pre_authentication.iter())
    {
        assert_eq!(actual.family, baseline.family);
        assert_eq!(actual.active, baseline.active);
        assert_eq!(
            actual.active_lease_count, baseline.active_lease_count,
            "pre-authentication active lease custody changed"
        );
    }
    for (actual, baseline) in actual
        .post_authentication
        .iter()
        .zip(baseline.post_authentication.iter())
    {
        assert_eq!(actual.family, baseline.family);
        assert_eq!(actual.active, baseline.active);
        assert_eq!(
            actual.active_lease_count, baseline.active_lease_count,
            "post-authentication active lease custody changed"
        );
    }
}

fn routing_config(id: &str, topology: TopologyMode, auto_approve: bool) -> NetworkConfig {
    let mut config = NetworkConfig::from_network_id(id, ROUTE_NETWORK_ID);
    config.label = id.to_owned();
    config.topology = topology;
    config.signaling = SignalingConfig {
        strategy: "none".to_owned(),
        mdns: false,
        ..SignalingConfig::default()
    };
    config.auto_approve = auto_approve;
    config
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn bounded_route_fails_over_and_preserves_exact_once_delivery() -> myownmesh_core::Result<()>
{
    let home = tempfile::tempdir().expect("isolated mesh home");
    std::env::set_var("MYOWNMESH_HOME", home.path());

    let identities = [
        Arc::new(Identity::ephemeral()),
        Arc::new(Identity::ephemeral()),
        Arc::new(Identity::ephemeral()),
        Arc::new(Identity::ephemeral()),
    ];
    let mut ordered = identities.into_iter().collect::<Vec<_>>();
    ordered.sort_by(|left, right| left.public_id().cmp(right.public_id()));
    let a_identity = ordered[0].clone();
    let b1_identity = ordered[1].clone();
    let c_identity = ordered[2].clone();
    let b2_identity = ordered[3].clone();
    let a_id = a_identity.public_id().to_owned();
    let b1_id = b1_identity.public_id().to_owned();
    let b2_id = b2_identity.public_id().to_owned();
    let c_id = c_identity.public_id().to_owned();

    let policy = finite_connector_policy();
    let a_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        a_identity,
        policy.clone(),
    )
    .await?;
    let b1_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        b1_identity,
        policy.clone(),
    )
    .await?;
    let b2_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        b2_identity,
        policy.clone(),
    )
    .await?;
    let c_mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        c_identity,
        policy.clone(),
    )
    .await?;
    let mesh_baselines = [
        a_mesh.resource_report(),
        b1_mesh.resource_report(),
        b2_mesh.resource_report(),
        c_mesh.resource_report(),
    ];

    let a = a_mesh
        .join(routing_config(
            "a",
            TopologyMode::Ring {
                n_preferred: Some(2),
            },
            true,
        ))
        .await?;
    let b1 = b1_mesh
        .join(routing_config(
            "b1",
            TopologyMode::Star { hub: b2_id.clone() },
            true,
        ))
        .await?;
    let b2 = b2_mesh
        .join(routing_config(
            "b2",
            TopologyMode::Ring {
                n_preferred: Some(2),
            },
            true,
        ))
        .await?;
    let c = c_mesh
        .join(routing_config(
            "c",
            TopologyMode::Ring {
                n_preferred: Some(2),
            },
            true,
        ))
        .await?;

    let a_b1 = a.install_promoted_peer_over_real_link(&b1).await;
    let a_b2 = a.install_promoted_peer_over_real_link(&b2).await;
    let b2_c = b2.install_promoted_peer_over_real_link(&c).await;
    assert_eq!(a_b1.peer_device_id(), b1_id);
    assert_eq!(a_b2.peer_device_id(), b2_id);
    assert_eq!(b2_c.peer_device_id(), c_id);

    assert!(a.peer(&b1_id).is_some(), "B1 is an active first route");
    assert!(a.peer(&b2_id).is_some(), "B2 is an active sibling route");
    assert!(a.peer(&c_id).is_none(), "A has no direct C owner");

    let topology = myownmesh_core::topology::from_mode(&TopologyMode::Ring {
        n_preferred: Some(2),
    });
    let eligible = vec![b1_id.clone(), b2_id.clone()];
    let hops = topology.next_hops(&a_id, &c_id, &eligible, 2);
    assert_eq!(
        hops.len(),
        2,
        "the production topology returns both bounded siblings"
    );
    assert!(hops.iter().all(|hop| eligible.contains(hop)));
    assert!(hops.iter().any(|hop| hop == &b1_id));
    assert!(hops.iter().any(|hop| hop == &b2_id));

    let c_channel = c.channel::<String>(CHANNEL_NAME);
    let mut c_subscription = c_channel.subscribe().expect("C subscription is funded");
    let c_rx_before = c.traffic().app_rx.frames;

    let a_c = a.install_promoted_peer_over_real_link(&c).await;
    assert_eq!(a_c.peer_device_id(), c_id);
    assert!(
        a.peer(&c_id).is_some(),
        "A-C is an authenticated direct endpoint"
    );
    let a_channel = a.channel::<String>(CHANNEL_NAME);
    a_channel
        .send_to(&c_id, &"one direct application payload".to_owned())
        .await
        .expect("the direct endpoint carries application bytes");

    let delivered = tokio::time::timeout(Duration::from_secs(5), c_subscription.recv())
        .await
        .expect("C receives the direct application payload")
        .expect("C subscription remains live")
        .expect("C receives without a decode refusal");
    assert_eq!(delivered.from(), a_id);
    assert_eq!(
        delivered.body(),
        &"one direct application payload".to_owned()
    );
    assert!(
        c.traffic().app_rx.frames > c_rx_before,
        "C observed one direct application frame"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), c_subscription.recv())
            .await
            .is_err(),
        "the direct message is delivered exactly once"
    );

    let _ = a_c.retire().await;
    let _ = a_b1.retire().await;
    let _ = a_b2.retire().await;
    let _ = b2_c.retire().await;
    a.shutdown().await?;
    b1.shutdown().await?;
    b2.shutdown().await?;
    c.shutdown().await?;
    drop(a);
    drop(b1);
    drop(b2);
    drop(c);
    assert_live_resource_baseline(&a_mesh.resource_report(), &mesh_baselines[0]);
    assert_live_resource_baseline(&b1_mesh.resource_report(), &mesh_baselines[1]);
    assert_live_resource_baseline(&b2_mesh.resource_report(), &mesh_baselines[2]);
    assert_live_resource_baseline(&c_mesh.resource_report(), &mesh_baselines[3]);
    Ok(())
}
