//! Membership-independent endpoint ciphertext. These DTOs grant no authority.
//! BASE64_NOPAD ciphertext is bounded before decoding; routing still checks the
//! complete serialized max-hop envelope against its receive ceiling.

use data_encoding::BASE64_NOPAD;
use serde::{Deserialize, Serialize};

pub const ENDPOINT_CIPHER_VERSION: u8 = 1;
pub const ENDPOINT_CIPHER_SUITE: u8 = 1;
pub const MAX_CIPHERTEXT_BYTES: usize = 40_000;
pub const AEAD_TAG_BYTES: usize = 16;
pub const MAX_PLAINTEXT_BYTES: usize = MAX_CIPHERTEXT_BYTES - AEAD_TAG_BYTES;
pub const MAX_REPLAY_WINDOW: usize = 4_096;

const KEY_SHARE_DOMAIN: &[u8] = b"myownmesh-routed-e2e-share-v1:";
// Domain + maximal binding (including introduction) + sender/ephemeral/offer
// hash + the fixed-width offered ceiling. Reserve exactly, without growth.
pub(crate) const MAX_KEY_SHARE_SIGNING_BYTES: usize =
    KEY_SHARE_DOMAIN.len() + 2 + 32 * 3 + 16 + 1 + 16 + 32 * 3 + 4;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum CipherError {
    #[error("endpoint cipher resource authority refused")]
    Authority,
    #[error("endpoint cipher resource scope refused")]
    Scope,
    #[error("endpoint cipher operation owner refused")]
    OperationOwner,
    #[error("invalid endpoint cipher binding")]
    Binding,
    #[error("endpoint cipher signature refused")]
    Signature,
    #[error("endpoint cipher transcript refused")]
    Transcript,
    #[error("endpoint cipher authentication refused")]
    Authentication,
    #[error("endpoint cipher replay refused")]
    Replay,
    #[error("endpoint cipher size or policy limit")]
    Limit,
    #[error("endpoint cipher expired or closed")]
    Closed,
    #[error("endpoint cipher sequence exhausted")]
    Exhausted,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EpochBinding {
    pub version: u8,
    pub suite: u8,
    pub context: [u8; 32],
    pub initiator: [u8; 32],
    pub responder: [u8; 32],
    pub epoch: [u8; 16],
    pub introduction: Option<[u8; 16]>,
}

impl EpochBinding {
    pub fn validate(&self) -> Result<(), CipherError> {
        if self.version != ENDPOINT_CIPHER_VERSION
            || self.suite != ENDPOINT_CIPHER_SUITE
            || self.initiator == self.responder
            || self.epoch == [0; 16]
            || self.introduction == Some([0; 16])
            || ed25519_dalek::VerifyingKey::from_bytes(&self.initiator).is_err()
            || ed25519_dalek::VerifyingKey::from_bytes(&self.responder).is_err()
        {
            return Err(CipherError::Binding);
        }
        Ok(())
    }

    pub fn destination(&self, sender: &[u8; 32]) -> Result<[u8; 32], CipherError> {
        if sender == &self.initiator {
            Ok(self.responder)
        } else if sender == &self.responder {
            Ok(self.initiator)
        } else {
            Err(CipherError::Binding)
        }
    }

    pub(crate) fn append_canonical(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&[self.version, self.suite]);
        out.extend_from_slice(&self.context);
        out.extend_from_slice(&self.initiator);
        out.extend_from_slice(&self.responder);
        out.extend_from_slice(&self.epoch);
        match self.introduction {
            Some(id) => {
                out.push(1);
                out.extend_from_slice(&id);
            }
            None => out.push(0),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyShare {
    pub binding: EpochBinding,
    pub sender: [u8; 32],
    pub ephemeral: [u8; 32],
    /// Zero for the offer, SHA-256 of the signed offer for the answer.
    pub offer_hash: [u8; 32],
    /// Local whole-plaintext ceiling, including encrypted channel metadata.
    /// Signed by this endpoint; the agreed limit is the minimum of both offers.
    pub offered_max_plaintext_bytes: u32,
    #[serde(with = "signature_bytes")]
    pub signature: [u8; 64],
}

impl KeyShare {
    pub fn validate(&self) -> Result<(), CipherError> {
        self.binding.validate()?;
        self.binding.destination(&self.sender)?;
        if self.offered_max_plaintext_bytes == 0
            || self.offered_max_plaintext_bytes > MAX_PLAINTEXT_BYTES as u32
        {
            return Err(CipherError::Limit);
        }
        if self.ephemeral == [0; 32]
            || (self.sender == self.binding.initiator && self.offer_hash != [0; 32])
        {
            return Err(CipherError::Binding);
        }
        Ok(())
    }

    pub(crate) fn signing_bytes(&self) -> Vec<u8> {
        let len = MAX_KEY_SHARE_SIGNING_BYTES
            - if self.binding.introduction.is_none() {
                16
            } else {
                0
            };
        let mut out = Vec::with_capacity(len);
        out.extend_from_slice(KEY_SHARE_DOMAIN);
        self.binding.append_canonical(&mut out);
        out.extend_from_slice(&self.sender);
        out.extend_from_slice(&self.ephemeral);
        out.extend_from_slice(&self.offer_hash);
        out.extend_from_slice(&self.offered_max_plaintext_bytes.to_be_bytes());
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KeyConfirmation {
    pub binding: EpochBinding,
    pub sender: [u8; 32],
    pub transcript_hash: [u8; 32],
    pub tag: [u8; AEAD_TAG_BYTES],
}

impl KeyConfirmation {
    pub fn validate(&self) -> Result<(), CipherError> {
        self.binding.validate()?;
        self.binding.destination(&self.sender)?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CiphertextPacket {
    pub binding: EpochBinding,
    pub sender: [u8; 32],
    pub sequence: u64,
    #[serde(with = "ciphertext_bytes")]
    pub ciphertext: Vec<u8>,
}

impl CiphertextPacket {
    pub fn validate(&self) -> Result<(), CipherError> {
        self.binding.validate()?;
        self.binding.destination(&self.sender)?;
        if self.sequence == 0
            || !(AEAD_TAG_BYTES..=MAX_CIPHERTEXT_BYTES).contains(&self.ciphertext.len())
        {
            return Err(CipherError::Limit);
        }
        Ok(())
    }
}

fn decode_bounded<E: serde::de::Error>(value: &str, max: usize) -> Result<Vec<u8>, E> {
    let encoded_max = (max * 8).div_ceil(6);
    if value.len() > encoded_max {
        return Err(E::custom("endpoint cipher encoded bound"));
    }
    let bytes = BASE64_NOPAD
        .decode(value.as_bytes())
        .map_err(|_| E::custom("endpoint cipher base64"))?;
    if bytes.len() > max || !canonical_encoding_matches(&bytes, value) {
        return Err(E::custom("endpoint cipher noncanonical bytes"));
    }
    Ok(bytes)
}

fn canonical_encoding_matches(bytes: &[u8], value: &str) -> bool {
    let mut offset = 0;
    for chunk in bytes.chunks(3) {
        let mut encoded = [0; 4];
        let len = BASE64_NOPAD.encode_len(chunk.len());
        BASE64_NOPAD.encode_mut(chunk, &mut encoded[..len]);
        if value.as_bytes().get(offset..offset + len) != Some(&encoded[..len]) {
            return false;
        }
        offset += len;
    }
    offset == value.len()
}

/// Streaming encoding permits allocation-free outer-envelope byte counting.
struct Base64Display<'a>(&'a [u8]);
impl std::fmt::Display for Base64Display<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        for chunk in self.0.chunks(3) {
            let mut encoded = [0; 4];
            let len = BASE64_NOPAD.encode_len(chunk.len());
            BASE64_NOPAD.encode_mut(chunk, &mut encoded[..len]);
            f.write_str(std::str::from_utf8(&encoded[..len]).map_err(|_| std::fmt::Error)?)?;
        }
        Ok(())
    }
}

struct BoundedBytes<const MAX: usize>;
impl<'de, const MAX: usize> serde::de::Visitor<'de> for BoundedBytes<MAX> {
    type Value = Vec<u8>;
    fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("bounded canonical unpadded base64")
    }
    fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<Self::Value, E> {
        decode_bounded(value, MAX)
    }
}

mod ciphertext_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        if bytes.len() > MAX_CIPHERTEXT_BYTES {
            return Err(serde::ser::Error::custom("endpoint ciphertext bound"));
        }
        s.collect_str(&Base64Display(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        d.deserialize_str(BoundedBytes::<MAX_CIPHERTEXT_BYTES>)
    }
}

mod signature_bytes {
    use super::*;
    pub fn serialize<S: serde::Serializer>(bytes: &[u8; 64], s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(&Base64Display(bytes))
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(d: D) -> Result<[u8; 64], D::Error> {
        d.deserialize_str(BoundedBytes::<64>)?
            .try_into()
            .map_err(|_| serde::de::Error::custom("endpoint signature length"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn bounded_cipher_encoding_refuses_oversize_padding_and_arrays() {
        let value = BASE64_NOPAD.encode(&vec![1; MAX_CIPHERTEXT_BYTES + 1]);
        assert!(decode_bounded::<serde_json::Error>(&value, MAX_CIPHERTEXT_BYTES).is_err());
        assert!(decode_bounded::<serde_json::Error>("AQ==", 1).is_err());
        assert_eq!(decode_bounded::<serde_json::Error>("AQ", 1).unwrap(), [1]);
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(with = "ciphertext_bytes")]
            _bytes: Vec<u8>,
        }
        assert!(serde_json::from_str::<Wrapper>(r#"{"_bytes":[1]}"#).is_err());
    }

    #[test]
    fn streaming_base64_preserves_canonical_bytes_at_all_chunk_tails() {
        for len in [0, 1, 2, 3, 4, 64, MAX_CIPHERTEXT_BYTES] {
            let bytes = vec![255; len];
            let actual = Base64Display(&bytes).to_string();
            assert_eq!(actual, BASE64_NOPAD.encode(&bytes));
            assert_eq!(
                decode_bounded::<serde_json::Error>(&actual, MAX_CIPHERTEXT_BYTES).unwrap(),
                bytes
            );
        }
        assert!(
            decode_bounded::<serde_json::Error>("AR", 1).is_err(),
            "nonzero trailing bits refused"
        );
    }
}
