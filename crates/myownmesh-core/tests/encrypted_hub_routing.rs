//! Cutover boundary: HubTree is setup/introduction only, not member payload transit.

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::protocol::{HubIntroductionBody, MeshMessage};

#[test]
fn encrypted_member_transit_and_legacy_wrapper_keys_are_refused() {
    for raw in [
        r#"{"kind":"routed_application","payload":{"ciphertext":"member"}}"#,
        r#"{"kind":"closed_relay_data","payload":{"ciphertext":"member"}}"#,
    ] {
        let error = serde_json::from_str::<MeshMessage>(raw)
            .expect_err("retired member transit must not parse")
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
    let mut value = current;
    value["application_transport"] = serde_json::json!({
        "introduction": {},
        "endpoint_cipher": {}
    });
    let error = serde_json::from_value::<NetworkConfig>(value)
        .expect_err("retired config key must not parse")
        .to_string();
    assert!(
        error.contains("unknown field"),
        "not an unknown-field refusal: {error}"
    );
    assert!(
        error.contains("application_transport"),
        "refusal did not name application_transport: {error}"
    );
}

#[test]
fn hub_introduction_wire_rejects_arbitrary_application_fields() {
    for (raw, field) in [
        (
            r#"{"op":"request","payload":{"application":"member"}}"#,
            "payload",
        ),
        (
            r#"{"op":"accept","application_payload":"member"}"#,
            "application_payload",
        ),
        (
            r#"{"op":"cancel","payload":{"application":"member"}}"#,
            "payload",
        ),
        (
            r#"{"op":"offer","sdp":"v=0","application_payload":"member"}"#,
            "application_payload",
        ),
    ] {
        assert!(
            serde_json::from_str::<HubIntroductionBody>(raw)
                .expect_err("arbitrary introduction field must not parse")
                .to_string()
                .contains("unknown field"),
            "introduction signaling must reject unknown field {field}: {raw}"
        );
        let error = serde_json::from_str::<HubIntroductionBody>(raw)
            .expect_err("arbitrary introduction field must not parse")
            .to_string();
        assert!(
            error.contains(field),
            "refusal did not name {field}: {error}"
        );
    }
    let current = serde_json::to_string(&HubIntroductionBody::Request {})
        .expect("current introduction body serializes");
    assert!(serde_json::from_str::<HubIntroductionBody>(&current).is_ok());
    for current in [
        HubIntroductionBody::Accept {},
        HubIntroductionBody::Cancel {},
    ] {
        let wire = serde_json::to_string(&current).expect("current introduction body serializes");
        assert!(serde_json::from_str::<HubIntroductionBody>(&wire).is_ok());
    }
}
