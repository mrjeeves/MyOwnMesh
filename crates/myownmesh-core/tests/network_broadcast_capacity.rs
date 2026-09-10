//! Public capacity-boundary controls for mesh and per-network broadcasters.
//!
//! The public API intentionally exposes receivers, not broadcaster internals.
//! These controls therefore verify constructor refusal before provider
//! installation and preserve the distinct mesh/network configuration domains.

use std::sync::Arc;

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::identity::Identity;
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
use myownmesh_core::{Error, Mesh, MeshConfig};

#[path = "support/semantic_policy.rs"]
mod semantic_policy;
use semantic_policy::ordinary_semantic_policy;

fn no_side_effect_provider() -> (ResourceProviderPort, FiniteResourceProvider) {
    // The port's process scope has one opaque bookkeeping unit of its own;
    // fund that exact provider construction charge while leaving every mesh
    // admission dimension otherwise at zero.
    let provider = FiniteResourceProvider::new(ResourceClaim::single(
        ResourceClass::OpaqueDependencyResidual,
        1,
    ));
    let resources = ResourceProviderPort::new(provider.clone())
        .expect("one opaque bookkeeping unit funds the provider port");
    (resources, provider)
}

async fn open_with_capacity(event_capacity: u64) -> myownmesh_core::Result<()> {
    let identity = Arc::new(Identity::ephemeral());
    let config = MeshConfig {
        event_capacity,
        ..MeshConfig::default()
    };
    let (resources, provider) = no_side_effect_provider();
    let before = provider.in_use();
    let result = Mesh::open_infrastructure_only_with_identity(config, identity, resources.clone())
        .await
        .map(|_| ());
    assert_eq!(
        provider.in_use(),
        before,
        "invalid event capacity must not install or consume provider resources"
    );
    drop(resources);
    assert_eq!(
        provider.in_use(),
        ResourceClaim::ZERO,
        "the retained provider port must release its bookkeeping scope"
    );
    result
}

#[tokio::test]
async fn mesh_event_capacity_refuses_zero_and_too_large_before_side_effects() {
    let zero = open_with_capacity(0).await;
    assert!(matches!(zero, Err(Error::Config(message)) if message.contains("event_capacity")));

    let too_large = u64::try_from(usize::MAX >> 1)
        .expect("Tokio broadcast bound fits the config representation")
        + 1;
    let refused = open_with_capacity(too_large).await;
    assert!(matches!(
        refused,
        Err(Error::Config(message)) if message.contains("event_capacity")
    ));
}

#[test]
fn mesh_and_network_broadcaster_capacities_remain_distinct_config_fields() {
    let mesh = MeshConfig {
        event_capacity: 3,
        ..MeshConfig::default()
    };
    let network = NetworkConfig {
        event_capacity: 5,
        connection_trace_capacity: 7,
        scheduler: Default::default(),
        ..NetworkConfig::from_network_id_with_semantic_policy(
            "capacity",
            "capacity",
            ordinary_semantic_policy(),
        )
    };
    let mesh_wire = serde_json::to_value(&mesh).expect("mesh config serializes");
    let network_wire = serde_json::to_value(&network).expect("network config serializes");
    assert_eq!(mesh_wire["event_capacity"], 3);
    assert_eq!(network_wire["event_capacity"], 5);
    assert_eq!(network_wire["connection_trace_capacity"], 7);
    assert_ne!(
        mesh_wire["event_capacity"], network_wire["connection_trace_capacity"],
        "mesh event and per-network trace choices must not alias"
    );
}
