//! Handshake frames: `hello`, `auth_response`, `approve`, `deny`.
//!
//! The hello/auth_response pair binds both sides to independently drawn
//! contributions and the exact channel. Approve/deny is the user-facing trust
//! gate after mutual authentication. Canonical governance proof is exchanged
//! as semantic facts, never as unsigned fields on a handshake frame.

use serde::{de::Deserializer, Deserialize, Serialize};

fn deserialize_current_protocol<'de, D>(deserializer: D) -> Result<u32, D::Error>
where
    D: Deserializer<'de>,
{
    let protocol = u32::deserialize(deserializer)?;
    if protocol == crate::PROTOCOL_VERSION {
        Ok(protocol)
    } else {
        Err(serde::de::Error::custom(format!(
            "unsupported core wire protocol version {protocol}; expected {}",
            crate::PROTOCOL_VERSION
        )))
    }
}

pub(crate) fn verification_code_has_protocol_shape(code: &str) -> bool {
    code.len() == 6
        && code
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
}

/// Sent immediately on channel open by both ends. Carries only the identity,
/// endpoint-auth contribution, human verification code, and closed profile
/// advertisement needed before a session exists.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HelloMessage {
    /// The closed wire profile version. Unknown frame kinds and unsupported
    /// profiles fail closed; there is no optional-frame negotiation.
    #[serde(deserialize_with = "deserialize_current_protocol")]
    pub protocol: u32,
    /// Bare-pubkey Device ID, base32-lowercase, with any display suffix omitted.
    pub device_id: String,
    /// Self-reported cosmetic label.
    #[serde(default)]
    pub label: String,
    /// Fresh per-attempt contribution bound into endpoint authentication.
    pub nonce: String,
    /// Six-character human verification code.
    pub verification_code: String,
    /// Closed profile advertisement; must include `endpoint_auth_v1`.
    #[serde(default)]
    pub features: Vec<String>,
}

impl HelloMessage {
    /// Validate the non-negotiable core wire version for programmatically
    /// constructed hellos. Wire deserialization applies the same check before
    /// an engine handshake can reach endpoint authentication.
    pub fn validate_protocol(&self) -> Result<(), String> {
        if self.protocol == crate::PROTOCOL_VERSION {
            Ok(())
        } else {
            Err(format!(
                "unsupported core wire protocol version {}; expected {}",
                self.protocol,
                crate::PROTOCOL_VERSION
            ))
        }
    }
}

/// Response proving possession of the key matching `HelloMessage::device_id`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuthResponseMessage {
    /// Base32-lowercase signature over the endpoint-auth transcript.
    pub signature: String,
}

/// Sent once the peer is cleared for application traffic.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ApproveMessage {}

/// Reason carried when a denial reflects signed semantic eviction state.
pub const DENY_REASON_EVICTED: &str = "evicted";

/// Sent when the local side rejects the peer. The reason is a decision hint;
/// any governance proof is a separately exchanged canonical signed fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DenyMessage {
    #[serde(default)]
    pub reason: Option<String>,
}

#[cfg(test)]
mod verification_code_tests {
    use super::verification_code_has_protocol_shape;

    #[test]
    fn verification_code_is_exactly_six_lowercase_ascii_alphanumerics() {
        assert!(verification_code_has_protocol_shape("abc123"));
        for malformed in ["abc12", "abc1234", "ABC123", "abc-12", "\u{e5}bc123"] {
            assert!(
                !verification_code_has_protocol_shape(malformed),
                "{malformed:?}"
            );
        }
    }
}

#[cfg(test)]
mod protocol_version_tests {
    use super::{ApproveMessage, AuthResponseMessage, DenyMessage, HelloMessage};

    fn hello_json(protocol: Option<u32>) -> String {
        let mut value = serde_json::json!({
            "device_id": "device",
            "label": "label",
            "nonce": "nonce",
            "verification_code": "abc123",
            "features": ["endpoint_auth_v1"]
        });
        if let Some(protocol) = protocol {
            value["protocol"] = serde_json::json!(protocol);
        }
        value.to_string()
    }

    #[test]
    fn previous_and_future_versions_refuse_before_auth() {
        for protocol in [
            crate::PROTOCOL_VERSION.saturating_sub(1),
            crate::PROTOCOL_VERSION.saturating_add(1),
        ] {
            let error = serde_json::from_str::<HelloMessage>(&hello_json(Some(protocol)))
                .expect_err("non-current core version must fail at wire decode");
            assert!(error
                .to_string()
                .contains("unsupported core wire protocol version"));
        }
    }

    #[test]
    fn missing_version_refuses_before_auth() {
        let error = serde_json::from_str::<HelloMessage>(&hello_json(None))
            .expect_err("missing core version must fail at wire decode");
        assert!(error.to_string().contains("missing field `protocol`"));
    }

    #[test]
    fn current_version_is_the_only_programmatic_version() {
        let hello = HelloMessage {
            protocol: crate::PROTOCOL_VERSION,
            device_id: "device".into(),
            label: String::new(),
            nonce: "nonce".into(),
            verification_code: "abc123".into(),
            features: Vec::new(),
        };
        hello
            .validate_protocol()
            .expect("current version validates");
        let mut stale = hello;
        stale.protocol = crate::PROTOCOL_VERSION.saturating_sub(1);
        assert!(stale.validate_protocol().is_err());
    }

    #[test]
    fn handshake_control_frames_refuse_unknown_fields() {
        assert!(serde_json::from_str::<AuthResponseMessage>(
            r#"{"signature":"proof","capabilities":{}}"#
        )
        .is_err());
        assert!(
            serde_json::from_str::<ApproveMessage>(r#"{"capabilities":{"rpc":true}}"#).is_err()
        );
        assert!(
            serde_json::from_str::<DenyMessage>(r#"{"reason":"denied","approval":true}"#).is_err()
        );
    }
}
