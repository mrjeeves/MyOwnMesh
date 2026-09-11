//! The retired closed member relay has no production application route.

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::protocol::MeshMessage;

#[test]
fn closed_member_relay_wire_and_config_names_are_not_compatibility_aliases() {
    for raw in [
        r#"{"kind":"closed_relay_control","op":"open"}"#,
        r#"{"kind":"closed_relay_data","payload":"opaque"}"#,
        r#"{"kind":"routed_application","origin":"member","payload":"opaque"}"#,
    ] {
        let error = serde_json::from_str::<MeshMessage>(raw)
            .expect_err("retired member relay wire must not parse")
            .to_string();
        assert!(
            error.contains("unknown variant"),
            "not an unknown-kind refusal: {error}"
        );
        let kind = raw
            .split("\"kind\":\"")
            .nth(1)
            .and_then(|value| value.split('"').next())
            .expect("fixture contains a kind");
        assert!(
            error.contains(kind),
            "refusal did not name retired kind {kind}: {error}"
        );
    }
    assert!(serde_json::from_str::<MeshMessage>(r#"{"kind":"ping","t":0}"#).is_ok());

    let current = serde_json::to_value(NetworkConfig::from_network_id("cutover", "cutover"))
        .expect("default network config serializes");
    assert!(serde_json::from_value::<NetworkConfig>(current.clone()).is_ok());
    let mut config = current;
    config["closed_relay"] = serde_json::json!({"max_allocations": 1});
    let error = serde_json::from_value::<NetworkConfig>(config)
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
