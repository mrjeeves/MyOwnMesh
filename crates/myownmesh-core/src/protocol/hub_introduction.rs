//! Bounded signed native-connection introduction. This is advisory control,
//! never an application body, membership proof, or authority to create a peer.
//! The engine owns exact carrier admission, replay/tombstones and monotonic
//! deadlines; signatures alone confer none of those capabilities.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::topology::RoutedHop;
use crate::resource::{ResourceClaim, ResourceClass};
use crate::semantic::{DeviceId, MeshContextId};

pub const HUB_INTRODUCTION_MAX_WIRE_BYTES: usize = 16_384;
pub const HUB_INTRODUCTION_MAX_SDP_BYTES: usize = 8_192;
pub const HUB_INTRODUCTION_MAX_CANDIDATE_BYTES: usize = 2_048;
pub const HUB_INTRODUCTION_MAX_HOPS: u8 = 4;
const DOMAIN: &[u8] = b"myownmesh-hub-introduction-v1\0";
const HOP_DOMAIN: &[u8] = b"myownmesh-hub-introduction-hop-v1\0";
const REQUEST_DOMAIN: &[u8] = b"myownmesh-hub-introduction-request-v1\0";
const MAX_SIGNING_DOMAIN_BYTES: usize = if DOMAIN.len() > HOP_DOMAIN.len() {
    DOMAIN.len()
} else {
    HOP_DOMAIN.len()
};
const CANONICAL_WORK_BYTES: usize = HUB_INTRODUCTION_MAX_WIRE_BYTES + MAX_SIGNING_DOMAIN_BYTES;
// sign_with: encoded and lowercase signatures; verify: uppercase key/key
// bytes and uppercase signature/signature bytes. These calls are sequential,
// but retaining their sum also funds a newly signed hop during publication.
const SIGNATURE_WORK_BYTES: usize = 2 * 103 + 52 + 32 + 103 + 64;
const CRYPTO_OPERATIONS: usize =
    1 + (HUB_INTRODUCTION_MAX_HOPS as usize + 1) + 1 + (HUB_INTRODUCTION_MAX_HOPS as usize + 1) + 1;

/// Raw transient claim for ONE bounded introduction transaction: construction
/// or decode, verify, optional Request digest, append one hop, encode and send.
/// `max_wire_bytes` bounds BOTH input and output (use the protocol maximum
/// before constructing a response whose final size is not yet known).
///
/// One existing structural JSON claim covers decoded shape/fragments. Added
/// capacity covers two wire buffers, two simultaneously live canonical
/// buffers (origin + hop), signature encoding scratch, the envelope root and
/// the fixed four-hop vector. Canonical encoders below count before reserving
/// and never grow; hop vectors reserve exactly four requested slots.
/// Six frame-owned, non-interned DeviceId Arc+Box backings and 52 parsed-text
/// bytes are charged explicitly; escaped text remains in structural JSON
/// work. Canonical validation uses stack bytes, not the global interner.
///
/// CPU is conservative byte-work plus explicit opaque crypto/allocation
/// residual, NOT a measured CPU-time or allocator/RSS/whole-crypto-heap bound.
/// The engine normalizes/acquires ONCE before any operation, and keeps the
/// lease with decoded/encoded values through terminal send. Existing records,
/// queues, native signaling and caller-owned input/body buffers need their own
/// existing custody; this is neither a provider grant nor another registry.
pub fn introduction_work_claim(
    max_wire_bytes: usize,
) -> Result<ResourceClaim, HubIntroductionError> {
    if max_wire_bytes == 0 || max_wire_bytes > HUB_INTRODUCTION_MAX_WIRE_BYTES {
        return Err(HubIntroductionError::Wire);
    }
    let memory = max_wire_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(CANONICAL_WORK_BYTES.checked_mul(2)?))
        .and_then(|n| n.checked_add(SIGNATURE_WORK_BYTES))
        .and_then(|n| n.checked_add(std::mem::size_of::<HubIntroductionEnvelope>()))
        .and_then(|n| {
            n.checked_add(
                std::mem::size_of::<RoutedHop>().checked_mul(HUB_INTRODUCTION_MAX_HOPS as usize)?,
            )
        })
        .and_then(|n| n.checked_add(super::topology::wire_device_work_bytes()?))
        .ok_or(HubIntroductionError::Work)?;
    let byte_work = CANONICAL_WORK_BYTES
        .checked_mul(CRYPTO_OPERATIONS)
        .and_then(|n| n.checked_add(max_wire_bytes.checked_mul(2)?))
        .and_then(|n| {
            n.checked_add(
                super::topology::WIRE_DEVICE_COUNT * super::topology::WIRE_DEVICE_TEXT_BYTES,
            )
        })
        .ok_or(HubIntroductionError::Work)?;
    let convert = |value| u64::try_from(value).map_err(|_| HubIntroductionError::Work);
    let scratch = ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, convert(memory)?),
        (ResourceClass::ParsingOrCpuWork, convert(byte_work)?),
        // Eight owned/transient allocation categories in the capacity ledger
        // plus each opaque signature operation; JSON fragments are separate.
        (
            ResourceClass::OpaqueDependencyResidual,
            convert(8 + CRYPTO_OPERATIONS + 2 * super::topology::WIRE_DEVICE_COUNT)?,
        ),
    ])
    .map_err(|_| HubIntroductionError::Work)?;
    crate::application_gateway::structural_json_claim(max_wire_bytes)
        .map_err(|_| HubIntroductionError::Work)?
        .checked_add(scratch)
        .map_err(|_| HubIntroductionError::Work)
}

/// Responder-generated freshness, bound to the exact signed Request. This is
/// not a wall-clock deadline or a bearer capability. The funded owner must
/// compare it to its still-live attempt before constructing any native work.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntroductionChallenge {
    pub request_hash: [u8; 32],
    pub responder_challenge: [u8; 32],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntroductionRefusal {
    NotAdmitted,
    Capacity,
    Expired,
    Replay,
    NoRoute,
    Cancelled,
    Unsupported,
    OutcomeUnknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum HubIntroductionBody {
    Request {},
    Accept {},
    Refuse {
        reason: IntroductionRefusal,
    },
    Cancel {},
    Offer {
        #[serde(deserialize_with = "bounded_text::<_, 8192>")]
        sdp: String,
    },
    Answer {
        #[serde(deserialize_with = "bounded_text::<_, 8192>")]
        sdp: String,
    },
    Candidate {
        #[serde(deserialize_with = "bounded_text::<_, 2048>")]
        candidate: String,
        #[serde(default, deserialize_with = "optional_text")]
        sdp_mid: Option<String>,
        sdp_mline_index: Option<u16>,
        #[serde(default, deserialize_with = "optional_text")]
        username_fragment: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HubIntroductionEnvelope {
    version: u8,
    context_id: MeshContextId,
    #[serde(deserialize_with = "super::topology::bounded_device_id")]
    source: DeviceId,
    #[serde(deserialize_with = "super::topology::bounded_device_id")]
    destination: DeviceId,
    introduction_id: [u8; 16],
    sequence: u64,
    challenge: Option<IntroductionChallenge>,
    initial_hop_budget: u8,
    remaining_ttl: u8,
    body: HubIntroductionBody,
    #[serde(deserialize_with = "bounded_text::<_, 103>")]
    signature: String,
    #[serde(deserialize_with = "bounded_hops")]
    hops: Vec<RoutedHop>,
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum HubIntroductionError {
    #[error("unsupported introduction version")]
    Version,
    #[error("invalid introduction coordinates")]
    Coordinates,
    #[error("introduction body exceeds its closed representation")]
    Body,
    #[error("introduction signature refused")]
    Signature,
    #[error("introduction carrier or hop chain refused")]
    Hop,
    #[error("introduction context mismatch")]
    Context,
    #[error("introduction responder challenge mismatch")]
    Challenge,
    #[error("introduction exceeds complete wire ceiling")]
    Wire,
    #[error("introduction work claim is not representable")]
    Work,
}

impl HubIntroductionEnvelope {
    // Keep the signed context/endpoints/challenge and moved body explicit at
    // this construction boundary; grouping them would change the wire API.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        context_id: MeshContextId,
        source: DeviceId,
        destination: DeviceId,
        introduction_id: [u8; 16],
        sequence: u64,
        challenge: Option<IntroductionChallenge>,
        initial_hop_budget: u8,
        body: HubIntroductionBody,
        key: &SigningKey,
    ) -> Result<Self, HubIntroductionError> {
        if source.as_bytes() != *key.verifying_key().as_bytes() {
            return Err(HubIntroductionError::Signature);
        }
        let mut value = Self {
            version: 1,
            context_id,
            source,
            destination,
            introduction_id,
            sequence,
            challenge,
            initial_hop_budget,
            remaining_ttl: initial_hop_budget,
            body,
            signature: String::new(),
            hops: Vec::with_capacity(HUB_INTRODUCTION_MAX_HOPS as usize),
        };
        value.validate_shape()?;
        // Refuse escaped/oversized bodies before allocating canonical signing
        // buffers. The signature is added below and the final size rechecked.
        value.validate_wire()?;
        value.signature = crate::signing::sign_with(key, &value.origin_bytes()?);
        value.validate_wire()?;
        Ok(value)
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }
    pub fn source(&self) -> &DeviceId {
        &self.source
    }
    pub fn destination(&self) -> &DeviceId {
        &self.destination
    }
    pub fn introduction_id(&self) -> [u8; 16] {
        self.introduction_id
    }
    pub fn sequence(&self) -> u64 {
        self.sequence
    }
    pub fn challenge(&self) -> Option<IntroductionChallenge> {
        self.challenge
    }
    pub fn initial_hop_budget(&self) -> u8 {
        self.initial_hop_budget
    }
    pub fn remaining_ttl(&self) -> u8 {
        self.remaining_ttl
    }
    pub fn body(&self) -> &HubIntroductionBody {
        &self.body
    }
    pub fn hops(&self) -> &[RoutedHop] {
        &self.hops
    }
    /// Complete MeshMessage bytes; callers must reserve their own retained and
    /// encoding work before allocation or admitting an introduction record.
    pub fn complete_encoded_len(&self) -> Option<usize> {
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: &'static str,
            #[serde(flatten)]
            envelope: &'a HubIntroductionEnvelope,
        }
        super::encoded_json_len(&Wire {
            kind: "hub_introduction",
            envelope: self,
        })
    }
    /// Exactly the complete MeshMessage, built under the caller's previously
    /// acquired work lease. Do not replace this with an unfunded serde Vec.
    pub fn encode_complete(&self) -> Result<Vec<u8>, HubIntroductionError> {
        self.validate_shape()?;
        self.validate_wire()?;
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: &'static str,
            #[serde(flatten)]
            envelope: &'a HubIntroductionEnvelope,
        }
        let wire = Wire {
            kind: "hub_introduction",
            envelope: self,
        };
        let len = self
            .complete_encoded_len()
            .ok_or(HubIntroductionError::Wire)?;
        let mut encoded = Vec::with_capacity(len);
        serde_json::to_writer(&mut encoded, &wire).map_err(|_| HubIntroductionError::Wire)?;
        if encoded.len() != len {
            return Err(HubIntroductionError::Wire);
        }
        Ok(encoded)
    }
    pub fn current_carrier(&self) -> &DeviceId {
        self.hops.last().map_or(&self.source, |hop| &hop.forwarder)
    }

    /// Route-independent digest of the exact signed request. Different hop
    /// carriers do not manufacture different demands. This authenticates the
    /// origin only; the adapter must still check its actual current carrier.
    pub fn request_digest(&self) -> Result<[u8; 32], HubIntroductionError> {
        self.validate_shape()?;
        self.validate_wire()?;
        if !matches!(&self.body, HubIntroductionBody::Request {}) {
            return Err(HubIntroductionError::Challenge);
        }
        let bytes = self.origin_bytes()?;
        verify(&self.source, &bytes, &self.signature)?;
        let mut digest = Sha256::new();
        digest.update(REQUEST_DOMAIN);
        digest.update(bytes);
        digest.update(self.signature.as_bytes());
        Ok(digest.finalize().into())
    }

    /// Compare against the exact live owner's challenge, never one supplied
    /// by a different inbound message. Signature/carrier, attempt, phase and
    /// monotonic deadline checks remain separate mandatory adapter checks.
    pub fn validate_challenge_binding(
        &self,
        expected: IntroductionChallenge,
    ) -> Result<(), HubIntroductionError> {
        if self.challenge != Some(expected)
            || expected.request_hash == [0; 32]
            || expected.responder_challenge == [0; 32]
        {
            return Err(HubIntroductionError::Challenge);
        }
        Ok(())
    }

    pub fn verify_for_previous_hop(
        &self,
        previous: &DeviceId,
        context: MeshContextId,
    ) -> Result<(), HubIntroductionError> {
        if self.context_id != context {
            return Err(HubIntroductionError::Context);
        }
        self.validate_shape()?;
        self.validate_wire()?;
        let bytes = self.origin_bytes()?;
        verify(&self.source, &bytes, &self.signature)?;
        let mut digest: [u8; 32] = Sha256::digest(&bytes).into();
        let mut ttl = self.initial_hop_budget;
        for hop in &self.hops {
            if ttl == 0
                || hop.previous_remaining_ttl != ttl
                || hop.remaining_ttl != ttl - 1
                || hop.prior_digest != digest
            {
                return Err(HubIntroductionError::Hop);
            }
            let bytes = self.hop_bytes(hop)?;
            verify(&hop.forwarder, &bytes, &hop.signature)?;
            digest = next_digest(&digest, &bytes, &hop.signature);
            ttl = hop.remaining_ttl;
        }
        if ttl != self.remaining_ttl || previous != self.current_carrier() {
            return Err(HubIntroductionError::Hop);
        }
        Ok(())
    }

    pub fn append_hop(
        &mut self,
        forwarder: DeviceId,
        key: &SigningKey,
    ) -> Result<(), HubIntroductionError> {
        self.verify_for_previous_hop(self.current_carrier(), self.context_id)?;
        if DeviceId::canonical_key_bytes(&forwarder)
            .map_err(|_| HubIntroductionError::Coordinates)?
            != forwarder.as_bytes()
        {
            return Err(HubIntroductionError::Coordinates);
        }
        if forwarder.as_bytes() != *key.verifying_key().as_bytes() {
            return Err(HubIntroductionError::Signature);
        }
        if self.remaining_ttl == 0 {
            return Err(HubIntroductionError::Hop);
        }
        let mut digest: [u8; 32] = Sha256::digest(self.origin_bytes()?).into();
        for hop in &self.hops {
            digest = next_digest(&digest, &self.hop_bytes(hop)?, &hop.signature);
        }
        let mut hop = RoutedHop {
            forwarder,
            previous_remaining_ttl: self.remaining_ttl,
            remaining_ttl: self.remaining_ttl - 1,
            prior_digest: digest,
            signature: String::new(),
        };
        hop.signature = crate::signing::sign_with(key, &self.hop_bytes(&hop)?);
        self.hops.push(hop);
        self.remaining_ttl -= 1;
        if let Err(error) = self.validate_wire() {
            self.hops.pop();
            self.remaining_ttl += 1;
            return Err(error);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), HubIntroductionError> {
        if self.version != 1 {
            return Err(HubIntroductionError::Version);
        }
        for id in [&self.source, &self.destination]
            .into_iter()
            .chain(self.hops.iter().map(|hop| &hop.forwarder))
        {
            if DeviceId::canonical_key_bytes(id).map_err(|_| HubIntroductionError::Coordinates)?
                != id.as_bytes()
            {
                return Err(HubIntroductionError::Coordinates);
            }
        }
        if self.source == self.destination || self.introduction_id == [0; 16] {
            return Err(HubIntroductionError::Coordinates);
        }
        if !(1..=HUB_INTRODUCTION_MAX_HOPS).contains(&self.initial_hop_budget)
            || self.remaining_ttl > self.initial_hop_budget
            || self.hops.len() > usize::from(self.initial_hop_budget)
        {
            return Err(HubIntroductionError::Hop);
        }
        let bounded = |text: &str, limit| !text.is_empty() && text.len() <= limit;
        let valid = match &self.body {
            HubIntroductionBody::Offer { sdp } | HubIntroductionBody::Answer { sdp } => {
                bounded(sdp, HUB_INTRODUCTION_MAX_SDP_BYTES)
            }
            HubIntroductionBody::Candidate {
                candidate,
                sdp_mid,
                username_fragment,
                ..
            } => {
                bounded(candidate, HUB_INTRODUCTION_MAX_CANDIDATE_BYTES)
                    && sdp_mid.as_ref().is_none_or(|v| bounded(v, 64))
                    && username_fragment.as_ref().is_none_or(|v| bounded(v, 64))
            }
            HubIntroductionBody::Request {} | HubIntroductionBody::Accept {} => self.sequence == 0,
            HubIntroductionBody::Refuse { .. } | HubIntroductionBody::Cancel {} => true,
        };
        if !valid {
            return Err(HubIntroductionError::Body);
        }
        match &self.body {
            HubIntroductionBody::Request {} if self.challenge.is_some() => {
                return Err(HubIntroductionError::Challenge)
            }
            HubIntroductionBody::Request {} | HubIntroductionBody::Refuse { .. } => {}
            _ if self.challenge.is_none() => return Err(HubIntroductionError::Challenge),
            _ => {}
        }
        if let Some(challenge) = self.challenge {
            self.validate_challenge_binding(challenge)?;
        }
        if matches!(
            &self.body,
            HubIntroductionBody::Offer { .. }
                | HubIntroductionBody::Answer { .. }
                | HubIntroductionBody::Candidate { .. }
                | HubIntroductionBody::Cancel {}
        ) && self.sequence == 0
        {
            return Err(HubIntroductionError::Coordinates);
        }
        Ok(())
    }

    fn origin_bytes(&self) -> Result<Vec<u8>, HubIntroductionError> {
        signed_bytes(
            DOMAIN,
            &(
                self.version,
                self.context_id,
                &self.source,
                &self.destination,
                self.introduction_id,
                self.sequence,
                self.challenge,
                self.initial_hop_budget,
                &self.body,
            ),
        )
    }
    fn hop_bytes(&self, hop: &RoutedHop) -> Result<Vec<u8>, HubIntroductionError> {
        signed_bytes(
            HOP_DOMAIN,
            &(
                self.context_id,
                &self.source,
                &self.destination,
                self.introduction_id,
                self.sequence,
                self.challenge,
                hop.prior_digest,
                &hop.forwarder,
                hop.previous_remaining_ttl,
                hop.remaining_ttl,
            ),
        )
    }
    fn validate_wire(&self) -> Result<(), HubIntroductionError> {
        let remaining_hops = usize::from(self.initial_hop_budget)
            .checked_sub(self.hops.len())
            .ok_or(HubIntroductionError::Hop)?;
        match self
            .complete_encoded_len()
            .and_then(|len| len.checked_add(remaining_hops * 512))
        {
            Some(len) if len <= HUB_INTRODUCTION_MAX_WIRE_BYTES => Ok(()),
            _ => Err(HubIntroductionError::Wire),
        }
    }
}

fn signed_bytes(
    value_domain: &[u8],
    value: &impl Serialize,
) -> Result<Vec<u8>, HubIntroductionError> {
    let len = super::encoded_json_len(value)
        .and_then(|n| n.checked_add(value_domain.len()))
        .filter(|n| *n <= CANONICAL_WORK_BYTES)
        .ok_or(HubIntroductionError::Wire)?;
    let mut out = Vec::with_capacity(len);
    out.extend_from_slice(value_domain);
    serde_json::to_writer(&mut out, value).map_err(|_| HubIntroductionError::Wire)?;
    if out.len() != len {
        return Err(HubIntroductionError::Wire);
    }
    Ok(out)
}
fn verify(id: &DeviceId, bytes: &[u8], signature: &str) -> Result<(), HubIntroductionError> {
    if signature.len() != 103
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || (b'2'..=b'7').contains(&byte))
        || !crate::signing::verify(id, bytes, signature).unwrap_or(false)
    {
        return Err(HubIntroductionError::Signature);
    }
    Ok(())
}
fn next_digest(previous: &[u8; 32], bytes: &[u8], signature: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(previous);
    digest.update(bytes);
    digest.update(signature.as_bytes());
    digest.finalize().into()
}

pub(super) fn bounded_text<'de, D: serde::Deserializer<'de>, const N: usize>(
    d: D,
) -> Result<String, D::Error> {
    struct Text<const N: usize>;
    impl<'de, const N: usize> serde::de::Visitor<'de> for Text<N> {
        type Value = String;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "a string of at most {N} bytes")
        }
        fn visit_str<E: serde::de::Error>(self, value: &str) -> Result<String, E> {
            if value.len() > N {
                return Err(E::custom("introduction text bound"));
            }
            Ok(value.to_owned())
        }
    }
    d.deserialize_str(Text::<N>)
}

fn optional_text<'de, D: serde::Deserializer<'de>>(d: D) -> Result<Option<String>, D::Error> {
    #[derive(Deserialize)]
    struct Text(#[serde(deserialize_with = "bounded_text::<_, 64>")] String);
    Option::<Text>::deserialize(d).map(|value| value.map(|text| text.0))
}

pub(super) fn bounded_hops<'de, D: serde::Deserializer<'de>>(
    d: D,
) -> Result<Vec<RoutedHop>, D::Error> {
    struct Hops;
    impl<'de> serde::de::Visitor<'de> for Hops {
        type Value = Vec<RoutedHop>;
        fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str("at most four signed hops")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(
            self,
            mut seq: A,
        ) -> Result<Self::Value, A::Error> {
            if seq.size_hint().is_some_and(|n| n > 4) {
                return Err(serde::de::Error::custom("hop bound"));
            }
            let mut hops = Vec::with_capacity(HUB_INTRODUCTION_MAX_HOPS as usize);
            while hops.len() < HUB_INTRODUCTION_MAX_HOPS as usize {
                match seq.next_element()? {
                    Some(hop) => hops.push(hop),
                    None => return Ok(hops),
                }
            }
            // A fifth element is refused without constructing a fifth
            // identity backing or signed-hop object, even without size_hint.
            if seq.next_element::<serde::de::IgnoredAny>()?.is_some() {
                return Err(serde::de::Error::custom("hop bound"));
            }
            Ok(hops)
        }
    }
    d.deserialize_seq(Hops)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cold_introduction_keys_are_frame_owned_through_challenge_verify_and_drop() {
        use super::super::topology::{cold_wire_device_for_test, cold_wire_keys_for_test};
        let keys = cold_wire_keys_for_test(b"cold-introduction-uninterned-wire-v1");
        let context = MeshContextId::from_bytes([73; 32]);
        let mut request = HubIntroductionEnvelope::new(
            context,
            cold_wire_device_for_test(&keys[0]),
            cold_wire_device_for_test(&keys[1]),
            [73; 16],
            0,
            None,
            4,
            HubIntroductionBody::Request {},
            &keys[0],
        )
        .unwrap();
        let digest = request.request_digest().unwrap();
        for key in &keys[2..] {
            request
                .append_hop(cold_wire_device_for_test(key), key)
                .unwrap();
        }
        let wire = serde_json::to_vec(&request).unwrap();
        let complete = request.encode_complete().unwrap();
        let origin = request.origin_bytes().unwrap();
        let hop_bytes: Vec<_> = request
            .hops
            .iter()
            .map(|hop| request.hop_bytes(hop).unwrap())
            .collect();
        drop(request);
        for tampered in [false, true] {
            let mut decoded: HubIntroductionEnvelope = serde_json::from_slice(&wire).unwrap();
            let probes: Vec<_> = [&decoded.source, &decoded.destination]
                .into_iter()
                .chain(decoded.hops.iter().map(|hop| &hop.forwarder))
                .map(DeviceId::backing_liveness_for_test)
                .collect();
            assert_eq!(probes.len(), 6);
            assert_eq!(decoded.encode_complete().unwrap(), complete);
            assert_eq!(decoded.origin_bytes().unwrap(), origin);
            assert_eq!(decoded.request_digest().unwrap(), digest);
            for (hop, expected) in decoded.hops.iter().zip(&hop_bytes) {
                assert_eq!(&decoded.hop_bytes(hop).unwrap(), expected);
            }
            if tampered {
                let replacement = if decoded.signature.starts_with('a') {
                    "b"
                } else {
                    "a"
                };
                decoded.signature.replace_range(..1, replacement);
                assert_eq!(
                    decoded.request_digest(),
                    Err(HubIntroductionError::Signature)
                );
            } else {
                decoded
                    .verify_for_previous_hop(decoded.current_carrier(), context)
                    .unwrap();
                assert_eq!(
                    decoded.verify_for_previous_hop(
                        decoded.current_carrier(),
                        MeshContextId::from_bytes([74; 32])
                    ),
                    Err(HubIntroductionError::Context)
                );
                let challenge = IntroductionChallenge {
                    request_hash: digest,
                    responder_challenge: [75; 32],
                };
                let accepted = HubIntroductionEnvelope::new(
                    context,
                    decoded.destination.clone(),
                    decoded.source.clone(),
                    decoded.introduction_id,
                    0,
                    Some(challenge),
                    4,
                    HubIntroductionBody::Accept {},
                    &keys[1],
                )
                .unwrap();
                accepted
                    .verify_for_previous_hop(accepted.current_carrier(), context)
                    .unwrap();
                accepted.validate_challenge_binding(challenge).unwrap();
                drop(accepted);
            }
            assert!(probes.iter().all(|alive| alive()));
            drop(decoded);
            assert!(probes.iter().all(|alive| !alive()));
            drop(probes);
        }
        let original: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        for field in ["source", "destination"] {
            for bad in [
                "a".repeat(53),
                original[field].as_str().unwrap().to_uppercase(),
            ] {
                let mut malformed = original.clone();
                malformed[field] = serde_json::Value::String(bad);
                assert!(serde_json::from_value::<HubIntroductionEnvelope>(malformed).is_err());
            }
        }
        let mut malformed = original.clone();
        malformed["hops"][0]["forwarder"] = serde_json::json!("x".repeat(53));
        assert!(serde_json::from_value::<HubIntroductionEnvelope>(malformed).is_err());
        let mut fifth = original;
        fifth["hops"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"not_a_hop": true}));
        assert!(serde_json::from_value::<HubIntroductionEnvelope>(fifth).is_err());

        // Later ordinary construction must not reuse the frame's backing.
        // This is not a global-interner telemetry or capacity assertion.
        let decoded: HubIntroductionEnvelope = serde_json::from_slice(&wire).unwrap();
        let ordinary =
            DeviceId::from_public_key_bytes(*keys[0].verifying_key().as_bytes()).unwrap();
        assert_eq!(decoded.source, ordinary);
        assert_ne!(decoded.source.as_ptr(), ordinary.as_ptr());
        drop(ordinary);
        let alive = decoded.source.backing_liveness_for_test();
        drop(decoded);
        assert!(!alive());
        drop(alive);
    }

    fn request() -> (HubIntroductionEnvelope, SigningKey) {
        let key = SigningKey::from_bytes(&[21; 32]);
        let source = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap();
        let peer = SigningKey::from_bytes(&[22; 32]);
        let destination =
            DeviceId::from_public_key_bytes(*peer.verifying_key().as_bytes()).unwrap();
        (
            HubIntroductionEnvelope::new(
                MeshContextId::from_bytes([1; 32]),
                source,
                destination,
                [2; 16],
                0,
                None,
                4,
                HubIntroductionBody::Request {},
                &key,
            )
            .unwrap(),
            key,
        )
    }
    #[test]
    fn introduction_binds_context_request_coordinates_and_hops() {
        let (mut value, key) = request();
        value
            .verify_for_previous_hop(value.source(), value.context_id())
            .unwrap();
        assert_eq!(
            value.verify_for_previous_hop(value.source(), MeshContextId::from_bytes([3; 32])),
            Err(HubIntroductionError::Context)
        );
        let original = value.clone();
        for _ in 0..4 {
            value.append_hop(original.source().clone(), &key).unwrap();
        }
        assert_eq!(value.remaining_ttl(), 0);
        assert_eq!(
            value.append_hop(original.source().clone(), &key),
            Err(HubIntroductionError::Hop)
        );
        value
            .verify_for_previous_hop(original.source(), value.context_id())
            .unwrap();
        assert_eq!(
            value.request_digest().unwrap(),
            original.request_digest().unwrap()
        );
        let mut changed = original;
        changed.introduction_id[0] ^= 1;
        assert_eq!(
            changed.verify_for_previous_hop(changed.source(), changed.context_id()),
            Err(HubIntroductionError::Signature)
        );
    }
    #[test]
    fn introduction_refuses_plaintext_unknown_fields_and_oversized_signaling() {
        let (mut value, _) = request();
        let mut json = serde_json::to_value(&value).unwrap();
        json["payload"] = serde_json::json!("no application payload permitted");
        assert!(serde_json::from_value::<HubIntroductionEnvelope>(json).is_err());
        for (op, body) in [
            ("request", HubIntroductionBody::Request {}),
            ("accept", HubIntroductionBody::Accept {}),
            ("cancel", HubIntroductionBody::Cancel {}),
        ] {
            let encoded = serde_json::to_value(&body).unwrap();
            assert_eq!(encoded, serde_json::json!({ "op": op }));
            assert_eq!(
                serde_json::from_value::<HubIntroductionBody>(encoded.clone()).unwrap(),
                body
            );
            let mut with_extra = encoded;
            with_extra["extra"] = serde_json::json!(true);
            assert!(serde_json::from_value::<HubIntroductionBody>(with_extra).is_err());
        }
        value.sequence = 1;
        value.body = HubIntroductionBody::Offer {
            sdp: "x".repeat(HUB_INTRODUCTION_MAX_SDP_BYTES + 1),
        };
        assert_eq!(value.validate_shape(), Err(HubIntroductionError::Body));
        assert!(
            serde_json::from_str::<HubIntroductionBody>(r#"{"op":"channel","payload":1}"#).is_err()
        );
        let too_long =
            serde_json::json!({"op":"offer","sdp":"x".repeat(HUB_INTRODUCTION_MAX_SDP_BYTES + 1)});
        assert!(serde_json::from_value::<HubIntroductionBody>(too_long).is_err());
        let mut old_clock = serde_json::to_value(request().0).unwrap();
        old_clock["expires_at_ms"] = serde_json::json!(u64::MAX);
        assert!(serde_json::from_value::<HubIntroductionEnvelope>(old_clock).is_err());
    }
    #[test]
    fn introduction_full_envelope_roundtrip_is_exact_and_capacity_bounded() {
        let (request, key) = request();
        let challenge = Some(IntroductionChallenge {
            request_hash: request.request_digest().unwrap(),
            responder_challenge: [255; 32],
        });
        for body in [
            HubIntroductionBody::Offer {
                sdp: "x".repeat(HUB_INTRODUCTION_MAX_SDP_BYTES),
            },
            HubIntroductionBody::Candidate {
                candidate: "x".repeat(HUB_INTRODUCTION_MAX_CANDIDATE_BYTES),
                sdp_mid: Some("x".repeat(64)),
                sdp_mline_index: Some(u16::MAX),
                username_fragment: Some("x".repeat(64)),
            },
        ] {
            let mut value = HubIntroductionEnvelope::new(
                request.context_id(),
                request.source().clone(),
                request.destination().clone(),
                request.introduction_id(),
                1,
                challenge,
                4,
                body,
                &key,
            )
            .unwrap();
            for _ in 0..4 {
                value.append_hop(request.source().clone(), &key).unwrap();
            }
            let message = super::super::MeshMessage::HubIntroduction(value.clone());
            let bytes = serde_json::to_vec(&message).unwrap();
            assert_eq!(value.complete_encoded_len(), Some(bytes.len()));
            assert!(bytes.len() <= HUB_INTRODUCTION_MAX_WIRE_BYTES);
            let super::super::MeshMessage::HubIntroduction(decoded) =
                serde_json::from_slice(&bytes).unwrap()
            else {
                panic!("wrong wire variant")
            };
            assert_eq!(decoded, value);
            decoded
                .verify_for_previous_hop(request.source(), request.context_id())
                .unwrap();
        }
        let result = HubIntroductionEnvelope::new(
            request.context_id(),
            request.source().clone(),
            request.destination().clone(),
            request.introduction_id(),
            1,
            challenge,
            4,
            HubIntroductionBody::Offer {
                sdp: "\0".repeat(HUB_INTRODUCTION_MAX_SDP_BYTES),
            },
            &key,
        );
        assert_eq!(
            result,
            Err(HubIntroductionError::Wire),
            "escaped wire size, not raw SDP length, bounds retention"
        );
    }

    #[test]
    fn signed_responder_challenge_binds_offer_and_rejects_old_transcript() {
        let (request, initiator) = request();
        let responder = SigningKey::from_bytes(&[22; 32]);
        let original = IntroductionChallenge {
            request_hash: request.request_digest().unwrap(),
            responder_challenge: [31; 32],
        };
        let fresh = IntroductionChallenge {
            responder_challenge: [32; 32],
            ..original
        };
        let accept = |binding| {
            HubIntroductionEnvelope::new(
                request.context_id(),
                request.destination().clone(),
                request.source().clone(),
                request.introduction_id(),
                0,
                Some(binding),
                4,
                HubIntroductionBody::Accept {},
                &responder,
            )
            .unwrap()
        };
        let old_accept = accept(original);
        let new_accept = accept(fresh);
        for accepted in [&old_accept, &new_accept] {
            accepted
                .verify_for_previous_hop(request.destination(), request.context_id())
                .unwrap();
            assert_eq!(
                accepted.challenge().unwrap().request_hash,
                request.request_digest().unwrap()
            );
            assert_eq!(
                accepted.request_digest(),
                Err(HubIntroductionError::Challenge)
            );
        }
        let offer = HubIntroductionEnvelope::new(
            request.context_id(),
            request.source().clone(),
            request.destination().clone(),
            request.introduction_id(),
            1,
            Some(original),
            4,
            HubIntroductionBody::Offer {
                sdp: "v=0\r\n".into(),
            },
            &initiator,
        )
        .unwrap();
        offer
            .verify_for_previous_hop(request.source(), request.context_id())
            .unwrap();
        offer.validate_challenge_binding(original).unwrap();
        // The old signature remains authentic, but after a newly funded
        // challenge its captured transcript no longer authorizes native work.
        // Actual local-demand/deadline/native-allocation checks are adapter
        // controls, not properties of this stateless wire comparison.
        assert_eq!(
            offer.validate_challenge_binding(fresh),
            Err(HubIntroductionError::Challenge)
        );
        let mut forged = offer.clone();
        forged.challenge = Some(fresh);
        assert_eq!(
            forged.verify_for_previous_hop(request.source(), request.context_id()),
            Err(HubIntroductionError::Signature)
        );
        let mut wrong_request = old_accept.clone();
        wrong_request.challenge.as_mut().unwrap().request_hash[0] ^= 1;
        assert_eq!(
            wrong_request.verify_for_previous_hop(request.destination(), request.context_id()),
            Err(HubIntroductionError::Signature)
        );
        let no_challenge = HubIntroductionEnvelope::new(
            request.context_id(),
            request.source().clone(),
            request.destination().clone(),
            request.introduction_id(),
            1,
            None,
            4,
            HubIntroductionBody::Offer {
                sdp: "v=0\r\n".into(),
            },
            &initiator,
        );
        assert_eq!(no_challenge, Err(HubIntroductionError::Challenge));
        for body in [
            HubIntroductionBody::Answer {
                sdp: "v=0\r\n".into(),
            },
            HubIntroductionBody::Candidate {
                candidate: "candidate:1".into(),
                sdp_mid: None,
                sdp_mline_index: None,
                username_fragment: None,
            },
            HubIntroductionBody::Cancel {},
        ] {
            let message = HubIntroductionEnvelope::new(
                request.context_id(),
                request.destination().clone(),
                request.source().clone(),
                request.introduction_id(),
                2,
                Some(original),
                4,
                body,
                &responder,
            )
            .unwrap();
            message
                .verify_for_previous_hop(request.destination(), request.context_id())
                .unwrap();
            message.validate_challenge_binding(original).unwrap();
            assert_eq!(
                message.validate_challenge_binding(fresh),
                Err(HubIntroductionError::Challenge)
            );
        }
    }

    #[test]
    fn introduction_work_claim_prices_parse_and_live_scratch_without_scope_or_grant() {
        let n = HUB_INTRODUCTION_MAX_WIRE_BYTES;
        let parse = crate::application_gateway::structural_json_claim(n).unwrap();
        let claim = introduction_work_claim(n).unwrap();
        let extra = claim.checked_sub(parse).unwrap();
        let capacity = 2 * n
            + 2 * CANONICAL_WORK_BYTES
            + SIGNATURE_WORK_BYTES
            + std::mem::size_of::<HubIntroductionEnvelope>()
            + HUB_INTRODUCTION_MAX_HOPS as usize * std::mem::size_of::<RoutedHop>()
            + 6 * DeviceId::uninterned_backing_bytes()
            + 52;
        assert_eq!(
            extra.amount(ResourceClass::AccountedMemoryBytes),
            capacity as u64
        );
        assert_eq!(
            extra.amount(ResourceClass::OpaqueDependencyResidual),
            (8 + CRYPTO_OPERATIONS + 12) as u64
        );
        assert_eq!(
            extra.amount(ResourceClass::ParsingOrCpuWork),
            (CANONICAL_WORK_BYTES * CRYPTO_OPERATIONS + 2 * n + 6 * 52) as u64
        );
        assert_eq!(introduction_work_claim(0), Err(HubIntroductionError::Wire));
        assert_eq!(
            introduction_work_claim(n + 1),
            Err(HubIntroductionError::Wire)
        );
        assert_eq!(
            introduction_work_claim(usize::MAX),
            Err(HubIntroductionError::Wire)
        );
        assert!(claim.amount(ResourceClass::AccountedMemoryBytes) > (2 * n) as u64);
    }

    #[test]
    fn introduction_counted_encoders_match_full_wire_and_bound_simultaneous_buffers() {
        let (request, key) = request();
        let challenge = Some(IntroductionChallenge {
            request_hash: request.request_digest().unwrap(),
            responder_challenge: [255; 32],
        });
        let mut message = HubIntroductionEnvelope::new(
            request.context_id(),
            request.source().clone(),
            request.destination().clone(),
            request.introduction_id(),
            1,
            challenge,
            4,
            HubIntroductionBody::Offer {
                sdp: "x".repeat(HUB_INTRODUCTION_MAX_SDP_BYTES),
            },
            &key,
        )
        .unwrap();
        for _ in 0..4 {
            message.append_hop(request.source().clone(), &key).unwrap();
        }
        let canonical = message.origin_bytes().unwrap();
        assert!(canonical.len() <= CANONICAL_WORK_BYTES);
        for hop in message.hops() {
            let hop_bytes = message.hop_bytes(hop).unwrap();
            assert!(canonical.len() + hop_bytes.len() <= 2 * CANONICAL_WORK_BYTES);
        }
        let encoded = message.encode_complete().unwrap();
        assert_eq!(message.complete_encoded_len(), Some(encoded.len()));
        assert_eq!(
            encoded,
            serde_json::to_vec(&super::super::MeshMessage::HubIntroduction(message)).unwrap()
        );
        assert!(encoded.len() <= HUB_INTRODUCTION_MAX_WIRE_BYTES);
        assert_eq!(
            signed_bytes(DOMAIN, &"\0".repeat(HUB_INTRODUCTION_MAX_WIRE_BYTES)),
            Err(HubIntroductionError::Wire)
        );
    }
}
