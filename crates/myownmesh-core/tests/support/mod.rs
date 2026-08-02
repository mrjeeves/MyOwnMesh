use std::num::NonZeroUsize;
use std::time::Duration;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy, ConnectorCallbackServiceWeights,
    ConnectorCapableResourcePolicy, ConnectorResourcePolicy, MeshConnectorResourcePolicy,
};

/// Explicit integration-test resource owner.
///
/// These values cover the known in-process multi-device test fixtures. They
/// are test inputs only and make no production sizing claim.
pub fn test_transport() -> Transport {
    let connector_count = NonZeroUsize::new(16).expect("fixture connector bound is nonzero");
    let callback_capacity = NonZeroUsize::new(16).expect("fixture callback capacity is nonzero");
    let callbacks = ConnectorCallbackPolicy::new(
        ConnectorCallbackMailboxCapacities::new(callback_capacity, callback_capacity),
        ConnectorCallbackServiceWeights::new(
            callback_capacity,
            callback_capacity,
            callback_capacity,
        ),
        NonZeroUsize::new(myownmesh_core::engine::MAX_ENDPOINT_FRAME_BYTES)
            .expect("fixture real-time unit limit is nonzero"),
        Duration::from_secs(10),
    )
    .expect("fixture real-time useful lifetime is nonzero");
    let policy = ConnectorResourcePolicy::new(connector_count, callbacks, Duration::from_secs(10))
        .expect("fixture close deadline is nonzero");
    let policy = ConnectorCapableResourcePolicy::new(
        policy,
        MeshConnectorResourcePolicy::new(connector_count),
    );
    Transport::new()
        .expect("transport")
        .with_connector_resource_policy(policy)
        .expect("fixture process connector policy is consistent")
}
