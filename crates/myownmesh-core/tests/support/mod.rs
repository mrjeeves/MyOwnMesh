use std::num::NonZeroUsize;
use std::time::Duration;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackMailboxCapacities, ConnectorResourceOwnerPort, ConnectorResourcePolicy,
};

/// Explicit integration-test resource owner.
///
/// These values cover the known in-process multi-device test fixtures. They
/// are test inputs only and make no production sizing claim.
pub fn test_transport() -> Transport {
    let connector_count = NonZeroUsize::new(16).expect("fixture connector bound is nonzero");
    let callback_capacity = NonZeroUsize::new(16).expect("fixture callback capacity is nonzero");
    let policy = ConnectorResourcePolicy::new(
        connector_count,
        ConnectorCallbackMailboxCapacities::new(
            callback_capacity,
            callback_capacity,
            callback_capacity,
            callback_capacity,
        ),
        Duration::from_secs(10),
    )
    .expect("fixture close deadline is nonzero");
    Transport::new()
        .expect("transport")
        .with_connector_resource_owner(ConnectorResourceOwnerPort::new(policy))
}
