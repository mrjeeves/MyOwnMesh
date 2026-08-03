use std::num::NonZeroUsize;
use std::time::Duration;

use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackMailboxCapacities, ConnectorCallbackPolicy, ConnectorCallbackServiceWeights,
    ConnectorCapableResourcePolicy, ConnectorResourcePolicy, MeshConnectorResourcePolicy,
    RealtimeConnectorPolicy,
};

/// Explicit integration-test resource owner.
///
/// These values cover the known in-process multi-device test fixtures. They
/// are test inputs only and make no production sizing claim.
pub fn test_transport() -> Transport {
    // Every integration-test binary has one real process resource root, while
    // libtest runs up to one test case per worker concurrently. Keep the
    // established per-Mesh fixture ceiling separate from the process ceiling
    // so parallel tests cannot consume one another's connector allowance.
    let mesh_connector_count =
        NonZeroUsize::new(16).expect("fixture per-Mesh connector bound is nonzero");
    let test_workers = std::env::var("RUST_TEST_THREADS")
        .ok()
        .map(|raw| {
            raw.parse::<NonZeroUsize>()
                .expect("RUST_TEST_THREADS must be a nonzero integer")
        })
        .unwrap_or_else(|| {
            std::thread::available_parallelism()
                .expect("integration-test worker concurrency must be observable")
        });
    let process_connector_count = NonZeroUsize::new(
        mesh_connector_count
            .get()
            .checked_mul(test_workers.get())
            .expect("integration-test process connector bound must fit usize"),
    )
    .expect("derived integration-test process connector bound is nonzero");
    let callback_capacity = NonZeroUsize::new(16).expect("fixture callback capacity is nonzero");
    let callbacks = ConnectorCallbackPolicy::new(
        ConnectorCallbackMailboxCapacities::new(callback_capacity, callback_capacity),
        ConnectorCallbackServiceWeights::data_only(callback_capacity, callback_capacity),
        RealtimeConnectorPolicy::Disabled,
    )
    .expect("fixture data-only callback policy is valid");
    let policy =
        ConnectorResourcePolicy::new(process_connector_count, callbacks, Duration::from_secs(10))
            .expect("fixture close observation limit is nonzero");
    let policy = ConnectorCapableResourcePolicy::new(
        policy,
        MeshConnectorResourcePolicy::new(mesh_connector_count),
    );
    Transport::new()
        .expect("transport")
        .with_connector_resource_policy(policy)
        .expect("fixture process connector policy is consistent")
}
