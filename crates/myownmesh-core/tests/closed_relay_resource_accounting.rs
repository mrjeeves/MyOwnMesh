//! Regression controls for removal of the custom closed-relay accounting lane.

use myownmesh_core::config::NetworkConfig;

#[path = "support/semantic_policy.rs"]
mod semantic_policy;
use semantic_policy::ordinary_semantic_policy;

#[test]
fn closed_relay_resource_policy_is_not_deserializable_after_cutover() {
    let current = serde_json::to_value(NetworkConfig::from_network_id_with_semantic_policy(
        "cutover",
        "cutover",
        ordinary_semantic_policy(),
    ))
    .expect("explicit ordinary network config serializes");
    assert!(serde_json::from_value::<NetworkConfig>(current.clone()).is_ok());
    let mut value = current;
    value["closed_relay"] = serde_json::json!({
        "max_allocations": 1,
        "max_frame_ciphertext_bytes": 1024
    });
    let error = serde_json::from_value::<NetworkConfig>(value)
        .expect_err("retired config key must not parse")
        .to_string();
    assert!(
        error.contains("unknown field"),
        "not an unknown-field refusal: {error}"
    );
    assert!(
        error.contains("closed_relay"),
        "refusal did not name closed_relay: {error}"
    );
}
