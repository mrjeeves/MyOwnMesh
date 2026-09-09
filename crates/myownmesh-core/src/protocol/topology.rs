//! Topology negotiation frames and bounded identity records shared by direct
//! hub introduction.

use serde::{Deserialize, Serialize};

use crate::semantic::DeviceId;

/// "I'm not going to send you application traffic for now".
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShelveMessage {
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshelveMessage {}

/// One authenticated handoff in a bounded hub-introduction hop chain. This is
/// retained for introduction metadata, not application-payload routing.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedHop {
    #[serde(deserialize_with = "bounded_device_id")]
    pub forwarder: DeviceId,
    pub previous_remaining_ttl: u8,
    pub remaining_ttl: u8,
    pub prior_digest: [u8; 32],
    #[serde(deserialize_with = "super::hub_introduction::bounded_text::<_, 103>")]
    pub signature: String,
}

/// Bounded work for identity records in a hub-introduction envelope. Decode
/// does not intern identities or create an application route.
pub(super) const WIRE_DEVICE_COUNT: usize = 6;
pub(super) const WIRE_DEVICE_TEXT_BYTES: usize = 52;

pub(super) fn wire_device_work_bytes() -> Option<usize> {
    DeviceId::uninterned_backing_bytes()
        .checked_mul(WIRE_DEVICE_COUNT)
        .and_then(|bytes| bytes.checked_add(WIRE_DEVICE_TEXT_BYTES))
}

/// Bounded canonical string wire with private Arc/Box custody.
pub(super) fn bounded_device_id<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<DeviceId, D::Error> {
    struct CanonicalDevice;
    impl<'de> serde::de::Visitor<'de> for CanonicalDevice {
        type Value = DeviceId;

        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("a canonical 52-byte device key")
        }

        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<DeviceId, E> {
            if value.len() != WIRE_DEVICE_TEXT_BYTES {
                return Err(E::custom("device key length"));
            }
            DeviceId::from_canonical_str_uninterned(value).map_err(E::custom)
        }
    }

    d.deserialize_str(CanonicalDevice)
}

#[cfg(test)]
pub(super) fn cold_wire_keys_for_test(domain: &[u8]) -> [ed25519_dalek::SigningKey; 6] {
    use sha2::{Digest, Sha256};

    std::array::from_fn(|index| {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update([index as u8]);
        let seed: [u8; 32] = hash.finalize().into();
        ed25519_dalek::SigningKey::from_bytes(&seed)
    })
}

#[cfg(test)]
pub(super) fn cold_wire_device_for_test(key: &ed25519_dalek::SigningKey) -> DeviceId {
    let text = data_encoding::BASE32_NOPAD
        .encode(key.verifying_key().as_bytes())
        .to_lowercase();
    DeviceId::from_canonical_str_uninterned(&text).unwrap()
}
