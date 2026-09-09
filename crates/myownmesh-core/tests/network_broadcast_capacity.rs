//! Public capacity-boundary controls for mesh and per-network broadcasters.
//!
//! The public API intentionally exposes receivers, not broadcaster internals.
//! These controls therefore verify constructor refusal before provider
//! installation and preserve the distinct mesh/network configuration domains.

use std::sync::Arc;

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::identity::Identity;
use myownmesh_core::resource::{FiniteResourceProvider, ResourceClaim, ResourceProviderPort};
use myownmesh_core::{Error, Mesh, MeshConfig};

fn no_side_effect_provider() -> ResourceProviderPort {
    ResourceProviderPort::new(FiniteResourceProvider::new(ResourceClaim::ZERO))
        .expect("zero fixture provider is structurally valid")
}

async fn open_with_capacity(event_capacity: u64) -> myownmesh_core::Result<()> {
    let identity = Arc::new(Identity::ephemeral());
    let config = MeshConfig {
        event_capacity,
        ..MeshConfig::default()
    };
    Mesh::open_infrastructure_only_with_identity(config, identity, no_side_effect_provider())
        .await
        .map(|_| ())
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
        ..NetworkConfig::from_network_id("capacity", "capacity")
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
