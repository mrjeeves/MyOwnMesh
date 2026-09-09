//! Cutover boundary: custom member relay payloads are no longer an application path.

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::protocol::MeshMessage;

#[test]
fn retired_member_payload_variants_fail_closed_at_the_wire_boundary() {
    for kind in [
        "routed_application",
        "closed_relay_control",
        "closed_relay_data",
        "endpoint_ciphertext",
        "opaque_relay_packet",
    ] {
        let wire = format!(r#"{{"kind":"{kind}","payload":{{}}}}"#);
        let error = serde_json::from_str::<MeshMessage>(&wire)
            .expect_err("retired custom payload must not parse")
            .to_string();
        assert!(
            error.contains("unknown variant"),
            "not an unknown-kind refusal: {error}"
        );
        assert!(
            error.contains(kind),
            "refusal did not name retired kind {kind}: {error}"
        );
    }
    assert!(serde_json::from_str::<MeshMessage>(r#"{"kind":"ping","t":0}"#).is_ok());
}

#[test]
fn retired_member_policy_keys_fail_closed_during_config_decode() {
    let current = serde_json::to_value(NetworkConfig::from_network_id("cutover", "cutover"))
        .expect("default network config serializes");
    assert!(serde_json::from_value::<NetworkConfig>(current.clone()).is_ok());
    let mut value = current;
    for key in ["application_transport", "closed_relay", "endpoint_cipher"] {
        value[key] = serde_json::json!({});
        let error = serde_json::from_value::<NetworkConfig>(value.clone())
            .expect_err("retired config key must not parse")
            .to_string();
        assert!(
            error.contains("unknown field"),
            "not an unknown-field refusal: {error}"
        );
        assert!(
            error.contains(key),
            "refusal did not name retired config key {key}: {error}"
        );
        value.as_object_mut().unwrap().remove(key);
    }
}
