//! Topology negotiation frames. Each peer runs the topology selector
//! locally and emits `shelve`/`unshelve` to peers based on the diff
//! between the previous and new preferred sets.
//!
//! Receivers track shelving direction independently:
//!   - `local_shelved`  — we sent `shelve` to them (they're not in our preferred set)
//!   - `remote_shelved` — they sent `shelve` to us (we're not in theirs)
//!
//! A connection is effectively shelved when either flag is true.
//! Either side can `unshelve` later when the selector promotes them.

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::endpoint_cipher::{CiphertextPacket, EpochBinding, KeyConfirmation, KeyShare};
use crate::resource::{ResourceClaim, ResourceClass};
use crate::semantic::{DeviceId, MeshContextId};

/// Ciphertext (including its AEAD tag), not a plaintext or JSON-value budget.
/// The complete max-hop envelope is checked separately against the wire cap.
pub const MAX_ROUTED_APPLICATION_PAYLOAD_BYTES: usize =
    super::endpoint_cipher::MAX_CIPHERTEXT_BYTES;
pub const MAX_ROUTED_HOP_BUDGET: u8 = 4;
/// Conservative complete metadata reservation, including outer discriminator,
/// worst numeric-array spellings, origin signature and all four hop records.
/// A maximal serialized-shape control below pins this bound to the real DTOs.
pub const ROUTED_CIPHERTEXT_METADATA_BYTES: usize = 8_192;
pub const MAX_ROUTED_APPLICATION_PLAINTEXT_BYTES: usize = {
    let wire_capacity = ((super::RECEIVE_FRAME_BYTES - ROUTED_CIPHERTEXT_METADATA_BYTES) / 4) * 3;
    let ciphertext = if wire_capacity < MAX_ROUTED_APPLICATION_PAYLOAD_BYTES {
        wire_capacity
    } else {
        MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
    };
    ciphertext - super::endpoint_cipher::AEAD_TAG_BYTES
};
pub const fn max_routed_plaintext_bytes() -> usize {
    MAX_ROUTED_APPLICATION_PLAINTEXT_BYTES
}
const MAX_ROUTED_HOP_ENCODED_BYTES: usize = 512;
const ROUTED_APPLICATION_DOMAIN: &[u8] = b"myownmesh-routed-application-v2\0";
const ROUTED_HOP_DOMAIN: &[u8] = b"myownmesh-routed-application-hop-v2\0";
// Existing signed byte layout, not a new transcript: three length-prefixed
// 32-byte coordinates, message id, hop budget and payload length prefix.
const ROUTED_ORIGIN_FIXED_BYTES: usize =
    ROUTED_APPLICATION_DOMAIN.len() + 3 * (4 + 32) + 16 + 1 + 4;
const ROUTED_HOP_SIGNING_BYTES: usize =
    ROUTED_HOP_DOMAIN.len() + 32 + 3 * (4 + 32) + 16 + (4 + 32) + 2;
const ROUTED_CANONICAL_PAYLOAD_BYTES: usize = super::RECEIVE_FRAME_BYTES;
const ROUTED_CANONICAL_ORIGIN_BYTES: usize =
    ROUTED_ORIGIN_FIXED_BYTES + ROUTED_CANONICAL_PAYLOAD_BYTES;
const ROUTED_SIGNATURE_WORK_BYTES: usize = 2 * 103 + 52 + 32 + 103 + 64;
const ROUTED_SIGNATURE_OPERATIONS: usize = 2 * (MAX_ROUTED_HOP_BUDGET as usize + 1) + 2;

// Two endpoints plus four forwarders, each independently frame-owned even
// when keys repeat. No static interner node or capacity is created by decode.
pub(super) const WIRE_DEVICE_COUNT: usize = 2 + MAX_ROUTED_HOP_BUDGET as usize;
pub(super) const WIRE_DEVICE_TEXT_BYTES: usize = 52;
pub(super) fn wire_device_work_bytes() -> Option<usize> {
    DeviceId::uninterned_backing_bytes()
        .checked_mul(WIRE_DEVICE_COUNT)
        .and_then(|bytes| bytes.checked_add(WIRE_DEVICE_TEXT_BYTES))
}

/// Bounded canonical string wire, with private Arc/Box custody, never the
/// ordinary semantic DeviceId deserializer (which interns globally).
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

/// Raw bounded work for one routed construct/clone-or-decode, verification,
/// one-hop forwarding and complete encoding transaction. `max_wire_bytes`
/// bounds BOTH complete input/output; use 65535 before an unknown builder.
/// Normalize/acquire once in the caller before any clone/Box/new/verify/encode,
/// and retain its guard with the result until the terminal send completes.
///
/// The existing JSON structural claim covers decoded shape/fragments. Added
/// requested capacity covers two wire buffers, one canonical payload + origin
/// and a hop buffer, one independent boxed payload clone (including ciphertext),
/// envelope root, eight hop slots during a fixed-capacity vector replacement,
/// five retained signature strings and transient signature/DeviceId encoding.
/// Six uninterned Arc+Box identity backings are charged separately using the
/// identity owner's intrinsic layout, plus 52 bytes of parsed-text scratch;
/// escaped JSON parser storage remains in the structural claim. Validation
/// uses fixed stack canonical-key buffers, never reconstructs interned IDs.
/// This is a conservative simultaneous-capacity ledger, not all allocations
/// being live at once. No 8192-byte wire metadata reserve is used as heap money.
///
/// Excludes original epoch/AEAD/plaintext and caller input custody, route plan,
/// command/mailbox/queue/node/native buffers and any additional retained clone.
/// Those require the existing disjoint owner claims. Byte-work/opaque residual
/// are accounting inputs, not measured CPU time, allocator RSS or exhaustive
/// dependency crypto heap. No scope, lease or provider grant is created here.
pub fn routed_work_claim(max_wire_bytes: usize) -> Result<ResourceClaim, RoutedApplicationError> {
    if max_wire_bytes == 0 || max_wire_bytes > super::RECEIVE_FRAME_BYTES {
        return Err(RoutedApplicationError::InvalidLimits);
    }
    let memory = max_wire_bytes
        .checked_mul(2)
        .and_then(|n| n.checked_add(ROUTED_CANONICAL_PAYLOAD_BYTES))
        .and_then(|n| n.checked_add(ROUTED_CANONICAL_ORIGIN_BYTES))
        .and_then(|n| n.checked_add(ROUTED_HOP_SIGNING_BYTES))
        .and_then(|n| n.checked_add(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES))
        .and_then(|n| n.checked_add(std::mem::size_of::<ClosedRoutedPayload>()))
        .and_then(|n| n.checked_add(std::mem::size_of::<RoutedApplicationEnvelope>()))
        .and_then(|n| {
            n.checked_add(
                std::mem::size_of::<RoutedHop>().checked_mul(2 * MAX_ROUTED_HOP_BUDGET as usize)?,
            )
        })
        .and_then(|n| n.checked_add((MAX_ROUTED_HOP_BUDGET as usize + 1) * 103))
        .and_then(|n| n.checked_add(ROUTED_SIGNATURE_WORK_BYTES))
        .and_then(|n| n.checked_add(wire_device_work_bytes()?))
        .ok_or(RoutedApplicationError::Encoding)?;
    let byte_work = ROUTED_CANONICAL_ORIGIN_BYTES
        .checked_mul(ROUTED_SIGNATURE_OPERATIONS + 6)
        .and_then(|n| n.checked_add(max_wire_bytes.checked_mul(2)?))
        .and_then(|n| n.checked_add(WIRE_DEVICE_COUNT * WIRE_DEVICE_TEXT_BYTES))
        .ok_or(RoutedApplicationError::Encoding)?;
    let convert = |value| u64::try_from(value).map_err(|_| RoutedApplicationError::Encoding);
    let scratch = ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, convert(memory)?),
        (ResourceClass::ParsingOrCpuWork, convert(byte_work)?),
        (
            ResourceClass::OpaqueDependencyResidual,
            convert(12 + ROUTED_SIGNATURE_OPERATIONS + 2 * WIRE_DEVICE_COUNT)?,
        ),
    ])
    .map_err(|_| RoutedApplicationError::Encoding)?;
    crate::application_gateway::structural_json_claim(max_wire_bytes)
        .map_err(|_| RoutedApplicationError::Encoding)?
        .checked_add(scratch)
        .map_err(|_| RoutedApplicationError::Encoding)
}

/// "I'm not going to send you application traffic for now — keep the
/// data channel open as a heartbeat so we can flip back to active
/// quickly when the topology rebalances."
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ShelveMessage {
    /// Why we're shelving — surfaced in the Activity log so the
    /// user can see "shelved bob (out-of-ring)" vs "shelved bob
    /// (over capacity)". Optional.
    #[serde(default)]
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UnshelveMessage {}

/// Routed application bodies are endpoint ciphertext; only the fixed typed
/// endpoint key handshake may precede it. Facts, arbitrary handshake JSON and
/// nested routed envelopes are not payload variants. Legacy channel values
/// remain expressible only so callers receive a typed downgrade refusal.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ClosedRoutedPayload {
    /// Kept as a source-level refusal discriminator. No constructor/verifier
    /// accepts this legacy plaintext representation for routing.
    ChannelFrame {
        channel: String,
        payload: Value,
    },
    EndpointCiphertext {
        packet: CiphertextPacket,
    },
    /// Fixed cryptographic handshake only, never arbitrary application bytes.
    EndpointControl {
        control: EndpointCipherControl,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum EndpointCipherControl {
    Share(KeyShare),
    Confirmation(KeyConfirmation),
}
impl EndpointCipherControl {
    pub fn binding(&self) -> &EpochBinding {
        match self {
            Self::Share(value) => &value.binding,
            Self::Confirmation(value) => &value.binding,
        }
    }
    pub fn sender(&self) -> [u8; 32] {
        match self {
            Self::Share(value) => value.sender,
            Self::Confirmation(value) => value.sender,
        }
    }
    pub fn validate(&self) -> Result<(), super::endpoint_cipher::CipherError> {
        match self {
            Self::Share(value) => value.validate(),
            Self::Confirmation(value) => value.validate(),
        }
    }
}

/// One authenticated handoff in a routed envelope's bounded hop chain.
/// `remaining_ttl` is exactly one less than the preceding carrier's value.
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

/// A signed, context-bound application message that can cross a bounded
/// number of topology-selected hops.  Origin authorization is immutable;
/// each mutable TTL change must be represented by an authenticated hop.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutedApplicationEnvelope {
    version: u8,
    context_id: MeshContextId,
    #[serde(deserialize_with = "bounded_device_id")]
    origin: DeviceId,
    #[serde(deserialize_with = "bounded_device_id")]
    destination: DeviceId,
    message_id: [u8; 16],
    initial_hop_budget: u8,
    remaining_ttl: u8,
    payload: ClosedRoutedPayload,
    #[serde(deserialize_with = "super::hub_introduction::bounded_text::<_, 103>")]
    origin_signature: String,
    #[serde(deserialize_with = "super::hub_introduction::bounded_hops")]
    hops: Vec<RoutedHop>,
}

/// Checked limits supplied by the owning network policy. The protocol maxima
/// are the only defaults; a network may select stricter limits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RoutedApplicationLimits {
    pub max_payload_bytes: usize,
    pub max_hop_budget: u8,
}

impl Default for RoutedApplicationLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: MAX_ROUTED_APPLICATION_PAYLOAD_BYTES,
            max_hop_budget: MAX_ROUTED_HOP_BUDGET,
        }
    }
}

impl RoutedApplicationLimits {
    pub fn checked(
        max_payload_bytes: usize,
        max_hop_budget: u8,
    ) -> Result<Self, RoutedApplicationError> {
        if max_payload_bytes == 0
            || max_payload_bytes > MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
            || max_hop_budget == 0
            || max_hop_budget > MAX_ROUTED_HOP_BUDGET
        {
            return Err(RoutedApplicationError::InvalidLimits);
        }
        Ok(Self {
            max_payload_bytes,
            max_hop_budget,
        })
    }
}

#[derive(Debug, Error, Clone, PartialEq, Eq)]
pub enum RoutedApplicationError {
    #[error("routed envelope contains a non-canonical device id")]
    NonCanonicalDeviceId,
    #[error("routed envelope origin does not match the signing key")]
    OriginKeyMismatch,
    #[error("routed envelope origin and destination must differ")]
    EndpointsMustDiffer,
    #[error("routed envelope message id must not be all zero")]
    InvalidMessageId,
    #[error("routed envelope hop budget is outside the bounded range")]
    InvalidHopBudget,
    #[error("routed envelope limits are outside the protocol maxima")]
    InvalidLimits,
    #[error("routed envelope hop budget is exhausted")]
    HopBudgetExhausted,
    #[error("routed envelope hop chain is invalid")]
    InvalidHopChain,
    #[error("routed envelope channel is empty or oversized")]
    InvalidChannel,
    #[error("routed envelope payload is oversized")]
    PayloadTooLarge,
    #[error("routed envelope exceeds the receive-frame ceiling")]
    WireTooLarge,
    #[error("routed envelope signature is invalid")]
    InvalidSignature,
    #[error("routed envelope signature encoding is invalid")]
    SignatureEncoding,
    #[error("routed envelope canonical encoding failed")]
    Encoding,
    #[error("routed envelope context does not match")]
    ContextMismatch,
    #[error("routed envelope was not carried by the expected previous hop")]
    PreviousHopMismatch,
    #[error("legacy plaintext routed application payload is refused")]
    LegacyPlaintextRefused,
    #[error("endpoint ciphertext/control binding is invalid")]
    InvalidCiphertext,
    #[error("unsupported routed envelope version")]
    UnsupportedVersion,
}

impl RoutedApplicationEnvelope {
    /// Create an origin-authorized envelope.  The caller supplies the exact
    /// message id so engine-level replay/correlation policy remains explicit.
    pub fn new(
        context_id: MeshContextId,
        origin: DeviceId,
        destination: DeviceId,
        message_id: [u8; 16],
        initial_hop_budget: u8,
        payload: ClosedRoutedPayload,
        signing_key: &SigningKey,
    ) -> Result<Self, RoutedApplicationError> {
        Self::new_with_limits(
            context_id,
            origin,
            destination,
            message_id,
            initial_hop_budget,
            payload,
            signing_key,
            RoutedApplicationLimits::default(),
        )
    }

    // Explicit signed coordinates, moved payload and caller policy retain
    // their existing ownership boundary without another aggregate or Box.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_limits(
        context_id: MeshContextId,
        origin: DeviceId,
        destination: DeviceId,
        message_id: [u8; 16],
        initial_hop_budget: u8,
        payload: ClosedRoutedPayload,
        signing_key: &SigningKey,
        limits: RoutedApplicationLimits,
    ) -> Result<Self, RoutedApplicationError> {
        if origin.as_bytes() != *signing_key.verifying_key().as_bytes() {
            return Err(RoutedApplicationError::OriginKeyMismatch);
        }
        let envelope = Self {
            version: 2,
            context_id,
            origin,
            destination,
            message_id,
            initial_hop_budget,
            remaining_ttl: initial_hop_budget,
            payload,
            origin_signature: String::new(),
            hops: Vec::with_capacity(MAX_ROUTED_HOP_BUDGET as usize),
        };
        envelope.validate_unsigned(limits)?;
        envelope.validate_wire()?;
        let mut envelope = envelope;
        envelope.origin_signature =
            crate::signing::sign_with(signing_key, &envelope.origin_signing_bytes()?);
        envelope.validate_wire()?;
        Ok(envelope)
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub fn origin(&self) -> &DeviceId {
        &self.origin
    }

    pub fn destination(&self) -> &DeviceId {
        &self.destination
    }

    pub fn message_id(&self) -> [u8; 16] {
        self.message_id
    }

    pub fn initial_hop_budget(&self) -> u8 {
        self.initial_hop_budget
    }

    pub fn remaining_ttl(&self) -> u8 {
        self.remaining_ttl
    }

    pub fn payload(&self) -> &ClosedRoutedPayload {
        &self.payload
    }

    /// Transfer the opaque application payload to the destination without
    /// cloning its potentially peer-sized JSON value.
    pub(crate) fn into_payload(self) -> ClosedRoutedPayload {
        self.payload
    }

    pub fn hops(&self) -> &[RoutedHop] {
        &self.hops
    }

    pub fn origin_signature(&self) -> &str {
        &self.origin_signature
    }

    /// Count the bare compact JSON envelope for unit comparisons against the
    /// complete MeshMessage encoding used by production routing admission.
    #[cfg(test)]
    pub(crate) fn encoded_len(&self) -> Option<usize> {
        super::encoded_json_len(self)
    }

    /// Actual complete MeshMessage bytes, including its leading discriminator.
    /// This is a length measurement, not a resource grant or authentication.
    pub fn complete_encoded_len(&self) -> Option<usize> {
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: &'static str,
            #[serde(flatten)]
            envelope: &'a RoutedApplicationEnvelope,
        }
        super::encoded_json_len(&Wire {
            kind: "routed_application",
            envelope: self,
        })
    }

    /// Complete MeshMessage encoded under the caller's pre-acquired work and
    /// output guards. This validates representation, not the current owner or
    /// signature; those remain mandatory before effects in the caller.
    pub fn encode_complete(&self) -> Result<Vec<u8>, RoutedApplicationError> {
        self.validate_unsigned(RoutedApplicationLimits::default())?;
        self.validate_wire()?;
        #[derive(Serialize)]
        struct Wire<'a> {
            kind: &'static str,
            #[serde(flatten)]
            envelope: &'a RoutedApplicationEnvelope,
        }
        let wire = Wire {
            kind: "routed_application",
            envelope: self,
        };
        let len = self
            .complete_encoded_len()
            .ok_or(RoutedApplicationError::Encoding)?;
        let mut encoded = Vec::with_capacity(len);
        serde_json::to_writer(&mut encoded, &wire).map_err(|_| RoutedApplicationError::Encoding)?;
        if encoded.len() != len {
            return Err(RoutedApplicationError::Encoding);
        }
        Ok(encoded)
    }

    /// Verify an envelope at its currently authenticated carrier.
    pub fn verify(&self) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop(self.current_carrier(), self.context_id)
    }

    /// Append a signed handoff for `forwarder`.  The new TTL is forced to be
    /// exactly one below the previous carrier's TTL and can never be raised.
    pub fn append_hop(
        &mut self,
        forwarder: DeviceId,
        signing_key: &SigningKey,
    ) -> Result<(), RoutedApplicationError> {
        self.append_hop_with_limits(forwarder, signing_key, RoutedApplicationLimits::default())
    }

    pub fn append_hop_with_limits(
        &mut self,
        forwarder: DeviceId,
        signing_key: &SigningKey,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop_with_limits(self.current_carrier(), self.context_id, limits)?;
        Self::validate_device(&forwarder)?;
        if forwarder.as_bytes() != *signing_key.verifying_key().as_bytes() {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        if self.hops.len() >= usize::from(limits.max_hop_budget)
            || self.hops.len() >= usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::HopBudgetExhausted);
        }
        let remaining_ttl = self
            .remaining_ttl
            .checked_sub(1)
            .ok_or(RoutedApplicationError::HopBudgetExhausted)?;
        let prior_digest = self.chain_digest()?;
        let mut hop = RoutedHop {
            forwarder,
            previous_remaining_ttl: self.remaining_ttl,
            remaining_ttl,
            prior_digest,
            signature: String::new(),
        };
        hop.signature = crate::signing::sign_with(signing_key, &self.hop_signing_bytes(&hop)?);
        let old_ttl = self.remaining_ttl;
        // A derived Clone may have capacity=len rather than four. Replace
        // that storage explicitly so push cannot geometrically grow it.
        if self.hops.capacity() < MAX_ROUTED_HOP_BUDGET as usize {
            let mut hops = Vec::with_capacity(MAX_ROUTED_HOP_BUDGET as usize);
            hops.append(&mut self.hops);
            self.hops = hops;
        }
        self.hops.push(hop);
        self.remaining_ttl = remaining_ttl;
        if let Err(error) = self.validate_wire() {
            self.hops.pop();
            self.remaining_ttl = old_ttl;
            return Err(error);
        }
        Ok(())
    }

    /// Verify the origin authorization, every hop signature, the exact
    /// context, and the carrier identity for this delivery attempt.
    pub fn verify_for_previous_hop(
        &self,
        previous_owner: &DeviceId,
        context_id: MeshContextId,
    ) -> Result<(), RoutedApplicationError> {
        self.verify_for_previous_hop_with_limits(
            previous_owner,
            context_id,
            RoutedApplicationLimits::default(),
        )
    }

    pub fn verify_for_previous_hop_with_limits(
        &self,
        previous_owner: &DeviceId,
        context_id: MeshContextId,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        if self.context_id != context_id {
            return Err(RoutedApplicationError::ContextMismatch);
        }
        self.validate_unsigned(limits)?;
        self.validate_wire()?;
        if self.hops.len() > usize::from(limits.max_hop_budget)
            || self.hops.len() > usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        let origin_bytes = self.origin_signing_bytes()?;
        let valid = crate::signing::verify(&self.origin, &origin_bytes, &self.origin_signature)
            .map_err(|_| RoutedApplicationError::SignatureEncoding)?;
        if !valid {
            return Err(RoutedApplicationError::InvalidSignature);
        }
        let mut expected_digest = Self::digest(&origin_bytes);
        let mut expected_previous_ttl = self.initial_hop_budget;
        for hop in &self.hops {
            Self::validate_device(&hop.forwarder)?;
            if expected_previous_ttl == 0
                || hop.prior_digest != expected_digest
                || hop.previous_remaining_ttl != expected_previous_ttl
                || hop.remaining_ttl != expected_previous_ttl - 1
            {
                return Err(RoutedApplicationError::InvalidHopChain);
            }
            let hop_bytes = self.hop_signing_bytes(hop)?;
            let valid = crate::signing::verify(&hop.forwarder, &hop_bytes, &hop.signature)
                .map_err(|_| RoutedApplicationError::SignatureEncoding)?;
            if !valid {
                return Err(RoutedApplicationError::InvalidSignature);
            }
            expected_digest =
                Self::digest_with_signature(&expected_digest, &hop_bytes, &hop.signature);
            expected_previous_ttl = hop.remaining_ttl;
        }
        let expected_ttl = self
            .hops
            .last()
            .map_or(self.initial_hop_budget, |hop| hop.remaining_ttl);
        if self.remaining_ttl != expected_ttl
            || self.hops.len() > usize::from(limits.max_hop_budget)
            || self.hops.len() > usize::from(self.initial_hop_budget)
        {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        if self.current_carrier() != previous_owner {
            return Err(RoutedApplicationError::PreviousHopMismatch);
        }
        self.validate_wire()
    }

    fn current_carrier(&self) -> &DeviceId {
        self.hops.last().map_or(&self.origin, |hop| &hop.forwarder)
    }

    fn validate_unsigned(
        &self,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        if self.version != 2 {
            return Err(RoutedApplicationError::UnsupportedVersion);
        }
        Self::validate_device(&self.origin)?;
        Self::validate_device(&self.destination)?;
        if self.origin == self.destination {
            return Err(RoutedApplicationError::EndpointsMustDiffer);
        }
        if self.message_id.iter().all(|byte| *byte == 0) {
            return Err(RoutedApplicationError::InvalidMessageId);
        }
        if self.initial_hop_budget == 0 || self.initial_hop_budget > limits.max_hop_budget {
            return Err(RoutedApplicationError::InvalidHopBudget);
        }
        if self.remaining_ttl > self.initial_hop_budget {
            return Err(RoutedApplicationError::InvalidHopBudget);
        }
        if self.remaining_ttl != self.initial_hop_budget && self.hops.is_empty() {
            return Err(RoutedApplicationError::InvalidHopChain);
        }
        self.validate_payload(limits)
    }

    fn validate_payload(
        &self,
        limits: RoutedApplicationLimits,
    ) -> Result<(), RoutedApplicationError> {
        let (binding, sender) = match &self.payload {
            ClosedRoutedPayload::ChannelFrame { .. } => {
                return Err(RoutedApplicationError::LegacyPlaintextRefused)
            }
            ClosedRoutedPayload::EndpointCiphertext { packet } => {
                packet
                    .validate()
                    .map_err(|_| RoutedApplicationError::InvalidCiphertext)?;
                if packet.ciphertext.len() > limits.max_payload_bytes {
                    return Err(RoutedApplicationError::PayloadTooLarge);
                }
                (&packet.binding, packet.sender)
            }
            ClosedRoutedPayload::EndpointControl { control } => {
                control
                    .validate()
                    .map_err(|_| RoutedApplicationError::InvalidCiphertext)?;
                (control.binding(), control.sender())
            }
        };
        if binding.context != *self.context_id.as_bytes()
            || sender != self.origin.as_bytes()
            || binding
                .destination(&sender)
                .map_err(|_| RoutedApplicationError::InvalidCiphertext)?
                != self.destination.as_bytes()
        {
            return Err(RoutedApplicationError::InvalidCiphertext);
        }
        Ok(())
    }

    fn validate_device(device: &DeviceId) -> Result<(), RoutedApplicationError> {
        let canonical = DeviceId::canonical_key_bytes(device)
            .map_err(|_| RoutedApplicationError::NonCanonicalDeviceId)?;
        if canonical != device.as_bytes() {
            return Err(RoutedApplicationError::NonCanonicalDeviceId);
        }
        Ok(())
    }

    fn origin_signing_bytes(&self) -> Result<Vec<u8>, RoutedApplicationError> {
        let payload_len = canonical_payload_len(&self.payload)?;
        let len = ROUTED_ORIGIN_FIXED_BYTES
            .checked_add(payload_len)
            .ok_or(RoutedApplicationError::Encoding)?;
        let payload = canonical_payload_bytes(&self.payload)?;
        let mut bytes = Vec::with_capacity(len);
        bytes.extend_from_slice(ROUTED_APPLICATION_DOMAIN);
        append_len_prefixed(&mut bytes, self.context_id.as_bytes())?;
        append_len_prefixed(&mut bytes, self.origin.as_bytes().as_slice())?;
        append_len_prefixed(&mut bytes, self.destination.as_bytes().as_slice())?;
        bytes.extend_from_slice(&self.message_id);
        bytes.push(self.initial_hop_budget);
        append_len_prefixed(&mut bytes, &payload)?;
        if bytes.len() != len {
            return Err(RoutedApplicationError::Encoding);
        }
        Ok(bytes)
    }

    fn hop_signing_bytes(&self, hop: &RoutedHop) -> Result<Vec<u8>, RoutedApplicationError> {
        let mut bytes = Vec::with_capacity(ROUTED_HOP_SIGNING_BYTES);
        bytes.extend_from_slice(ROUTED_HOP_DOMAIN);
        bytes.extend_from_slice(&hop.prior_digest);
        append_len_prefixed(&mut bytes, self.context_id.as_bytes())?;
        append_len_prefixed(&mut bytes, self.origin.as_bytes().as_slice())?;
        append_len_prefixed(&mut bytes, self.destination.as_bytes().as_slice())?;
        bytes.extend_from_slice(&self.message_id);
        append_len_prefixed(&mut bytes, hop.forwarder.as_bytes().as_slice())?;
        bytes.push(hop.previous_remaining_ttl);
        bytes.push(hop.remaining_ttl);
        if bytes.len() != ROUTED_HOP_SIGNING_BYTES {
            return Err(RoutedApplicationError::Encoding);
        }
        Ok(bytes)
    }

    fn chain_digest(&self) -> Result<[u8; 32], RoutedApplicationError> {
        let mut digest = Self::digest(&self.origin_signing_bytes()?);
        for hop in &self.hops {
            let hop_bytes = self.hop_signing_bytes(hop)?;
            digest = Self::digest_with_signature(&digest, &hop_bytes, &hop.signature);
        }
        Ok(digest)
    }

    fn digest(bytes: &[u8]) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(bytes);
        hasher.finalize().into()
    }

    fn digest_with_signature(previous: &[u8; 32], bytes: &[u8], signature: &str) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(previous);
        hasher.update(bytes);
        hasher.update(signature.as_bytes());
        hasher.finalize().into()
    }

    fn validate_wire(&self) -> Result<(), RoutedApplicationError> {
        let encoded = self
            .complete_encoded_len()
            .ok_or(RoutedApplicationError::Encoding)?;
        let remaining_hops = usize::from(self.initial_hop_budget)
            .checked_sub(self.hops.len())
            .ok_or(RoutedApplicationError::InvalidHopChain)?;
        let reserved = encoded
            .checked_add(remaining_hops * MAX_ROUTED_HOP_ENCODED_BYTES)
            .ok_or(RoutedApplicationError::WireTooLarge)?;
        if reserved > super::RECEIVE_FRAME_BYTES {
            return Err(RoutedApplicationError::WireTooLarge);
        }
        Ok(())
    }
}

fn append_len_prefixed(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), RoutedApplicationError> {
    let length = u32::try_from(bytes.len()).map_err(|_| RoutedApplicationError::Encoding)?;
    out.extend_from_slice(&length.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn canonical_payload_len(payload: &ClosedRoutedPayload) -> Result<usize, RoutedApplicationError> {
    if matches!(payload, ClosedRoutedPayload::ChannelFrame { .. }) {
        return Err(RoutedApplicationError::LegacyPlaintextRefused);
    }
    let len = super::encoded_json_len(payload).ok_or(RoutedApplicationError::Encoding)?;
    if len > ROUTED_CANONICAL_PAYLOAD_BYTES {
        return Err(RoutedApplicationError::WireTooLarge);
    }
    Ok(len)
}

fn canonical_payload_bytes(
    payload: &ClosedRoutedPayload,
) -> Result<Vec<u8>, RoutedApplicationError> {
    // Identical existing typed JSON bytes, counted before the only buffer is
    // requested. The bounded base64 serializer streams without another String.
    let len = canonical_payload_len(payload)?;
    let mut bytes = Vec::with_capacity(len);
    serde_json::to_writer(&mut bytes, payload).map_err(|_| RoutedApplicationError::Encoding)?;
    if bytes.len() != len {
        return Err(RoutedApplicationError::Encoding);
    }
    Ok(bytes)
}

#[cfg(test)]
pub(crate) fn ciphertext_payload_for_test(
    context: MeshContextId,
    origin: &DeviceId,
    destination: &DeviceId,
    ciphertext_bytes: usize,
) -> ClosedRoutedPayload {
    ClosedRoutedPayload::EndpointCiphertext {
        packet: CiphertextPacket {
            binding: EpochBinding {
                version: 1,
                suite: 1,
                context: *context.as_bytes(),
                initiator: origin.as_bytes(),
                responder: destination.as_bytes(),
                epoch: [255; 16],
                introduction: Some([255; 16]),
            },
            sender: origin.as_bytes(),
            sequence: u64::MAX,
            ciphertext: vec![255; ciphertext_bytes],
        },
    }
}

#[cfg(test)]
pub(super) fn cold_wire_keys_for_test(domain: &[u8]) -> [SigningKey; 6] {
    std::array::from_fn(|index| {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update([index as u8]);
        let seed: [u8; 32] = hash.finalize().into();
        SigningKey::from_bytes(&seed)
    })
}

#[cfg(test)]
pub(super) fn cold_wire_device_for_test(key: &SigningKey) -> DeviceId {
    let text = data_encoding::BASE32_NOPAD
        .encode(key.verifying_key().as_bytes())
        .to_lowercase();
    DeviceId::from_canonical_str_uninterned(&text).unwrap()
}

#[cfg(test)]
mod routed_tests {
    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device(key: &SigningKey) -> DeviceId {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn cold_routed_wire_keys_are_frame_owned_through_verify_refusal_and_drop() {
        // Domain-unique fixture keys: no ordinary DeviceId constructor is used
        // until after the cold decode/verify/drop controls below.
        let keys = cold_wire_keys_for_test(b"cold-routed-uninterned-wire-v1");
        let source = cold_wire_device_for_test(&keys[0]);
        let destination = cold_wire_device_for_test(&keys[1]);
        let context = MeshContextId::from_bytes([71; 32]);
        let payload = ciphertext_payload_for_test(context, &source, &destination, 32);
        let mut value = RoutedApplicationEnvelope::new(
            context,
            source,
            destination,
            [71; 16],
            4,
            payload,
            &keys[0],
        )
        .unwrap();
        for key in &keys[2..] {
            value
                .append_hop(cold_wire_device_for_test(key), key)
                .unwrap();
        }
        let wire = serde_json::to_vec(&value).unwrap();
        let complete = value.encode_complete().unwrap();
        let origin_bytes = value.origin_signing_bytes().unwrap();
        let hops: Vec<_> = value
            .hops
            .iter()
            .map(|hop| value.hop_signing_bytes(hop).unwrap())
            .collect();
        drop(value);

        for tampered in [false, true] {
            let mut decoded: RoutedApplicationEnvelope = serde_json::from_slice(&wire).unwrap();
            let probes: Vec<_> = [&decoded.origin, &decoded.destination]
                .into_iter()
                .chain(decoded.hops.iter().map(|hop| &hop.forwarder))
                .map(DeviceId::backing_liveness_for_test)
                .collect();
            assert_eq!(probes.len(), 6);
            assert!(probes.iter().all(|alive| alive()));
            assert_eq!(decoded.origin_signing_bytes().unwrap(), origin_bytes);
            for (hop, expected) in decoded.hops.iter().zip(&hops) {
                assert_eq!(&decoded.hop_signing_bytes(hop).unwrap(), expected);
            }
            assert_eq!(decoded.encode_complete().unwrap(), complete);
            if tampered {
                let replacement = if decoded.origin_signature.starts_with('a') {
                    "b"
                } else {
                    "a"
                };
                decoded.origin_signature.replace_range(..1, replacement);
                assert_eq!(
                    decoded.verify(),
                    Err(RoutedApplicationError::InvalidSignature)
                );
            } else {
                decoded.verify().unwrap();
                assert_eq!(
                    decoded.verify_for_previous_hop(
                        decoded.current_carrier(),
                        MeshContextId::from_bytes([72; 32])
                    ),
                    Err(RoutedApplicationError::ContextMismatch)
                );
            }
            assert!(probes.iter().all(|alive| alive()));
            drop(decoded);
            assert!(probes.iter().all(|alive| !alive()));
            // Weak probes keep only the Arc control block until this drop.
            drop(probes);
        }
        let original: serde_json::Value = serde_json::from_slice(&wire).unwrap();
        for field in ["origin", "destination"] {
            for bad in [
                "a".repeat(53),
                original[field].as_str().unwrap().to_uppercase(),
            ] {
                let mut malformed = original.clone();
                malformed[field] = serde_json::Value::String(bad);
                assert!(serde_json::from_value::<RoutedApplicationEnvelope>(malformed).is_err());
            }
        }
        let mut malformed = original.clone();
        malformed["hops"][0]["forwarder"] = serde_json::json!("x".repeat(53));
        assert!(serde_json::from_value::<RoutedApplicationEnvelope>(malformed).is_err());
        let mut fifth = original;
        fifth["hops"]
            .as_array_mut()
            .unwrap()
            .push(serde_json::json!({"not_a_hop": true}));
        assert!(serde_json::from_value::<RoutedApplicationEnvelope>(fifth).is_err());

        // No global-interner instrumentation is introduced. Distinct backing
        // from a later ordinary constructor discriminates the cold visitor;
        // the production callsite census covers no re-interning on validation.
        let decoded: RoutedApplicationEnvelope = serde_json::from_slice(&wire).unwrap();
        let ordinary = device(&keys[0]);
        assert_eq!(decoded.origin, ordinary);
        assert_ne!(decoded.origin.as_ptr(), ordinary.as_ptr());
        drop(ordinary);
        let alive = decoded.origin.backing_liveness_for_test();
        drop(decoded);
        assert!(!alive());
        drop(alive);
    }

    #[test]
    fn routed_work_claim_prices_structural_decode_and_bounded_scratch() {
        for n in [1, super::super::RECEIVE_FRAME_BYTES] {
            let claim = routed_work_claim(n).unwrap();
            let parse = crate::application_gateway::structural_json_claim(n).unwrap();
            let extra = claim.checked_sub(parse).unwrap();
            let memory = 2 * n
                + ROUTED_CANONICAL_PAYLOAD_BYTES
                + ROUTED_CANONICAL_ORIGIN_BYTES
                + ROUTED_HOP_SIGNING_BYTES
                + MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
                + std::mem::size_of::<ClosedRoutedPayload>()
                + std::mem::size_of::<RoutedApplicationEnvelope>()
                + 2 * MAX_ROUTED_HOP_BUDGET as usize * std::mem::size_of::<RoutedHop>()
                + (MAX_ROUTED_HOP_BUDGET as usize + 1) * 103
                + ROUTED_SIGNATURE_WORK_BYTES
                + 6 * DeviceId::uninterned_backing_bytes()
                + 52;
            assert_eq!(
                extra.amount(ResourceClass::AccountedMemoryBytes),
                memory as u64
            );
            assert_eq!(
                extra.amount(ResourceClass::ParsingOrCpuWork),
                (ROUTED_CANONICAL_ORIGIN_BYTES * (ROUTED_SIGNATURE_OPERATIONS + 6) + 2 * n + 6 * 52)
                    as u64
            );
            assert_eq!(
                extra.amount(ResourceClass::OpaqueDependencyResidual),
                (12 + ROUTED_SIGNATURE_OPERATIONS + 12) as u64
            );
        }
        for n in [0, super::super::RECEIVE_FRAME_BYTES + 1, usize::MAX] {
            assert_eq!(
                routed_work_claim(n),
                Err(RoutedApplicationError::InvalidLimits)
            );
        }
    }

    #[test]
    fn routed_exact_capacity_encoders_preserve_signed_bytes_at_maximum_hops() {
        // Independent old-layout construction: do not share production length
        // constants or append_len_prefixed with the signed-byte oracle.
        fn old_field(out: &mut Vec<u8>, field: &[u8]) {
            out.extend_from_slice(&u32::try_from(field.len()).unwrap().to_be_bytes());
            out.extend_from_slice(field);
        }
        let origin_key = key(61);
        let origin = device(&origin_key);
        let destination = device(&key(62));
        let context = MeshContextId::from_bytes([255; 32]);
        let payload = ciphertext_payload_for_test(
            context,
            &origin,
            &destination,
            MAX_ROUTED_APPLICATION_PAYLOAD_BYTES,
        );
        let old_payload = serde_json::to_vec(&payload).unwrap();
        assert_eq!(canonical_payload_len(&payload).unwrap(), old_payload.len());
        assert_eq!(canonical_payload_bytes(&payload).unwrap(), old_payload);
        let mut envelope = RoutedApplicationEnvelope::new(
            context,
            origin,
            destination,
            [255; 16],
            MAX_ROUTED_HOP_BUDGET,
            payload,
            &origin_key,
        )
        .unwrap();
        let mut old_origin = b"myownmesh-routed-application-v2\0".to_vec();
        old_field(&mut old_origin, context.as_bytes());
        old_field(&mut old_origin, &envelope.origin.as_bytes());
        old_field(&mut old_origin, &envelope.destination.as_bytes());
        old_origin.extend_from_slice(&envelope.message_id);
        old_origin.push(envelope.initial_hop_budget);
        old_field(&mut old_origin, &old_payload);
        assert_eq!(envelope.origin_signing_bytes().unwrap(), old_origin);
        assert_eq!(
            old_origin.len(),
            ROUTED_ORIGIN_FIXED_BYTES + old_payload.len()
        );
        assert_eq!(
            envelope.origin_signature,
            crate::signing::sign_with(&origin_key, &old_origin)
        );
        let zero_hop_wire = envelope.encode_complete().unwrap();
        assert_eq!(envelope.complete_encoded_len(), Some(zero_hop_wire.len()));
        assert_eq!(
            zero_hop_wire,
            serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(
                envelope.clone()
            ))
            .unwrap()
        );
        for seed in [63, 64, 65, 66] {
            let hop_key = key(seed);
            // Exercise clone capacity=len followed by bounded replacement.
            envelope = envelope.clone();
            envelope.append_hop(device(&hop_key), &hop_key).unwrap();
            let hop = envelope.hops.last().unwrap();
            let mut old_hop = b"myownmesh-routed-application-hop-v2\0".to_vec();
            old_hop.extend_from_slice(&hop.prior_digest);
            old_field(&mut old_hop, context.as_bytes());
            old_field(&mut old_hop, &envelope.origin.as_bytes());
            old_field(&mut old_hop, &envelope.destination.as_bytes());
            old_hop.extend_from_slice(&envelope.message_id);
            old_field(&mut old_hop, &hop.forwarder.as_bytes());
            old_hop.push(hop.previous_remaining_ttl);
            old_hop.push(hop.remaining_ttl);
            assert_eq!(envelope.hop_signing_bytes(hop).unwrap(), old_hop);
            assert_eq!(old_hop.len(), ROUTED_HOP_SIGNING_BYTES);
            assert_eq!(hop.signature, crate::signing::sign_with(&hop_key, &old_hop));
            envelope.verify().unwrap();
            let encoded = envelope.encode_complete().unwrap();
            assert_eq!(envelope.complete_encoded_len(), Some(encoded.len()));
            assert_eq!(
                encoded,
                serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(
                    envelope.clone()
                ))
                .unwrap()
            );
            assert!(encoded.len() <= super::super::RECEIVE_FRAME_BYTES);
            let decoded: super::super::MeshMessage = serde_json::from_slice(&encoded).unwrap();
            let super::super::MeshMessage::RoutedApplication(decoded) = decoded else {
                panic!("complete encoder must retain the routed discriminator")
            };
            assert_eq!(decoded, envelope);
            decoded.verify().unwrap();
        }
        assert_eq!(envelope.hops.len(), 4);
        let extra_key = key(67);
        assert_eq!(
            envelope.append_hop(device(&extra_key), &extra_key),
            Err(RoutedApplicationError::HopBudgetExhausted)
        );
        let mut oversized = envelope.clone();
        let ClosedRoutedPayload::EndpointCiphertext { packet } = &mut oversized.payload else {
            unreachable!()
        };
        packet.ciphertext.push(0);
        assert_eq!(
            oversized.encode_complete(),
            Err(RoutedApplicationError::InvalidCiphertext)
        );
        let mut legacy = envelope;
        legacy.payload = ClosedRoutedPayload::ChannelFrame {
            channel: "not-a-fallback".into(),
            payload: serde_json::json!({}),
        };
        assert_eq!(
            legacy.encode_complete(),
            Err(RoutedApplicationError::LegacyPlaintextRefused)
        );
    }

    fn envelope() -> (RoutedApplicationEnvelope, SigningKey, DeviceId) {
        let origin_key = key(7);
        let destination_key = key(8);
        let origin = device(&origin_key);
        let destination = device(&destination_key);
        let context = MeshContextId::from_bytes([3; 32]);
        let payload = ciphertext_payload_for_test(context, &origin, &destination, 32);
        let envelope = RoutedApplicationEnvelope::new(
            context,
            origin,
            destination.clone(),
            [9; 16],
            4,
            payload,
            &origin_key,
        )
        .unwrap();
        (envelope, origin_key, destination)
    }

    #[test]
    fn signed_envelope_round_trips_and_binds_exact_fields() {
        let (envelope, _, _) = envelope();
        envelope
            .verify_for_previous_hop(envelope.origin(), envelope.context_id())
            .unwrap();
        let wire = serde_json::to_vec(&envelope).unwrap();
        let decoded: RoutedApplicationEnvelope = serde_json::from_slice(&wire).unwrap();
        assert_eq!(decoded, envelope);
        decoded
            .verify_for_previous_hop(decoded.origin(), decoded.context_id())
            .unwrap();
    }

    #[test]
    fn encoded_len_matches_wire_at_zero_and_max_hops() {
        let (mut envelope, _, _) = envelope();
        assert_eq!(
            envelope.encoded_len(),
            Some(serde_json::to_vec(&envelope).unwrap().len())
        );
        for seed in [20, 21, 22, 23] {
            let hop_key = key(seed);
            envelope
                .append_hop(device(&hop_key), &hop_key)
                .expect("bounded hop is admitted");
        }
        assert_eq!(envelope.remaining_ttl(), 0);
        assert_eq!(
            envelope.encoded_len(),
            Some(serde_json::to_vec(&envelope).unwrap().len())
        );
    }

    #[test]
    fn max_sized_payload_can_be_moved_without_cloning() {
        let origin_key = key(24);
        let origin = device(&origin_key);
        let destination = device(&key(25));
        let payload = ciphertext_payload_for_test(
            MeshContextId::from_bytes([6; 32]),
            &origin,
            &destination,
            MAX_ROUTED_APPLICATION_PAYLOAD_BYTES,
        );
        let ClosedRoutedPayload::EndpointCiphertext { packet } = &payload else {
            unreachable!()
        };
        let allocation = packet.ciphertext.as_ptr();
        let envelope = RoutedApplicationEnvelope::new_with_limits(
            MeshContextId::from_bytes([6; 32]),
            origin,
            destination,
            [2; 16],
            1,
            payload,
            &origin_key,
            RoutedApplicationLimits::checked(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES, 1).unwrap(),
        )
        .unwrap();
        match envelope.into_payload() {
            ClosedRoutedPayload::EndpointCiphertext { packet } => {
                assert_eq!(
                    packet.ciphertext.len(),
                    MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
                );
                assert_eq!(packet.ciphertext.as_ptr(), allocation);
            }
            _ => panic!("ciphertext payload variant changed"),
        }
    }

    #[test]
    fn hop_chain_is_signed_bounded_and_ttl_cannot_increase() {
        let (mut envelope, origin_key, _) = envelope();
        let next_key = key(10);
        let next = device(&next_key);
        envelope.append_hop(next.clone(), &next_key).unwrap();
        assert_eq!(envelope.remaining_ttl(), 3);
        envelope
            .verify_for_previous_hop(&next, envelope.context_id())
            .unwrap();
        assert!(envelope
            .append_hop(device(&origin_key), &origin_key)
            .is_ok());

        let mut forged = serde_json::to_value(&envelope).unwrap();
        forged["remaining_ttl"] = serde_json::json!(4);
        let forged: RoutedApplicationEnvelope = serde_json::from_value(forged).unwrap();
        assert!(matches!(
            forged.verify_for_previous_hop(forged.current_carrier(), forged.context_id()),
            Err(RoutedApplicationError::InvalidHopChain)
                | Err(RoutedApplicationError::InvalidHopBudget)
        ));
    }

    #[test]
    fn unknown_nested_protocol_kinds_and_unknown_fields_are_rejected() {
        let (envelope, _, _) = envelope();
        let mut wire = serde_json::to_value(envelope).unwrap();
        wire["unexpected"] = serde_json::json!(true);
        assert!(serde_json::from_value::<RoutedApplicationEnvelope>(wire).is_err());

        let nested = serde_json::json!({"kind":"routed_application_envelope","context_id":"x"});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(nested).is_err());
        let handshake = serde_json::json!({"kind":"handshake","payload":{}});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(handshake).is_err());
        let fact = serde_json::json!({"kind":"fact","payload":{}});
        assert!(serde_json::from_value::<ClosedRoutedPayload>(fact).is_err());
    }

    #[test]
    fn forgery_context_and_payload_changes_fail_verification() {
        let (envelope, _, _) = envelope();
        for (field, value) in [
            (
                "destination",
                serde_json::to_value(device(&key(11))).unwrap(),
            ),
            (
                "context_id",
                serde_json::to_value(MeshContextId::from_bytes([4; 32])).unwrap(),
            ),
            (
                "message_id",
                serde_json::json!([8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8]),
            ),
        ] {
            let mut wire = serde_json::to_value(&envelope).unwrap();
            wire[field] = value;
            let changed: RoutedApplicationEnvelope = serde_json::from_value(wire).unwrap();
            assert!(changed
                .verify_for_previous_hop(changed.origin(), changed.context_id())
                .is_err());
        }
        let mut wire = serde_json::to_value(&envelope).unwrap();
        wire["payload"]["packet"]["sequence"] = serde_json::json!(2);
        let changed: RoutedApplicationEnvelope = serde_json::from_value(wire).unwrap();
        assert!(changed
            .verify_for_previous_hop(changed.origin(), changed.context_id())
            .is_err());
    }

    #[test]
    fn payload_and_message_bounds_are_enforced() {
        let origin_key = key(12);
        let origin = device(&origin_key);
        let destination = device(&key(13));
        let result = RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([5; 32]),
            origin,
            destination,
            [0; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: Value::Null,
            },
            &origin_key,
        );
        assert_eq!(result, Err(RoutedApplicationError::InvalidMessageId));

        let result = RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([5; 32]),
            device(&origin_key),
            device(&key(13)),
            [1; 16],
            1,
            ClosedRoutedPayload::ChannelFrame {
                channel: "chat".into(),
                payload: Value::String("x".repeat(MAX_ROUTED_APPLICATION_PAYLOAD_BYTES + 1)),
            },
            &origin_key,
        );
        assert_eq!(result, Err(RoutedApplicationError::LegacyPlaintextRefused));
    }

    #[test]
    fn ciphertext_max_hop_complete_wire_reservation_includes_all_metadata() {
        let (mut value, key, destination) = envelope();
        value.payload = ciphertext_payload_for_test(
            value.context_id(),
            value.origin(),
            &destination,
            MAX_ROUTED_APPLICATION_PAYLOAD_BYTES,
        );
        value.origin_signature =
            crate::signing::sign_with(&key, &value.origin_signing_bytes().unwrap());
        for seed in [20, 21, 22, 23] {
            let key = key_for_bound(seed);
            value.append_hop(device(&key), &key).unwrap();
        }
        value.verify().unwrap();
        assert!(
            serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(value.clone()))
                .unwrap()
                .len()
                <= super::super::RECEIVE_FRAME_BYTES
        );
        // Deliberately maximal *representation* (not an authority fixture):
        // each raw byte numeric field uses three decimal digits, u64 uses 20.
        value.message_id = [255; 16];
        value.origin_signature = "z".repeat(103);
        for hop in &mut value.hops {
            hop.prior_digest = [255; 32];
            hop.signature = "z".repeat(103);
            assert!(super::super::encoded_json_len(hop).unwrap() < MAX_ROUTED_HOP_ENCODED_BYTES);
        }
        let ClosedRoutedPayload::EndpointCiphertext { packet } = &mut value.payload else {
            unreachable!()
        };
        packet.binding.context = [255; 32];
        packet.binding.initiator = [255; 32];
        packet.binding.responder = [255; 32];
        packet.sender = [255; 32];
        let encoded_body = (packet.ciphertext.len() * 8).div_ceil(6);
        let counted = value.complete_encoded_len().unwrap();
        let wire =
            serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(value)).unwrap();
        assert_eq!(counted, wire.len());
        assert!(wire.len() - encoded_body <= ROUTED_CIPHERTEXT_METADATA_BYTES);
        assert!(wire.len() <= super::super::RECEIVE_FRAME_BYTES);
        assert_eq!(
            max_routed_plaintext_bytes() + super::super::endpoint_cipher::AEAD_TAG_BYTES,
            MAX_ROUTED_APPLICATION_PAYLOAD_BYTES
        );
    }

    fn key_for_bound(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn ciphertext_and_control_outer_bindings_have_no_plaintext_downgrade() {
        let (value, key, destination) = envelope();
        let context = value.context_id();
        let source = value.origin().clone();
        let legacy = ClosedRoutedPayload::ChannelFrame {
            channel: "secret-channel".into(),
            payload: serde_json::json!("secret-body"),
        };
        assert_eq!(
            RoutedApplicationEnvelope::new(
                context,
                source.clone(),
                destination.clone(),
                [1; 16],
                4,
                legacy,
                &key
            ),
            Err(RoutedApplicationError::LegacyPlaintextRefused)
        );
        let mut packet = match value.payload.clone() {
            ClosedRoutedPayload::EndpointCiphertext { packet } => packet,
            _ => unreachable!(),
        };
        packet.ciphertext.push(0);
        packet.binding.context = [9; 32];
        assert_eq!(
            RoutedApplicationEnvelope::new(
                context,
                source.clone(),
                destination.clone(),
                [1; 16],
                4,
                ClosedRoutedPayload::EndpointCiphertext {
                    packet: packet.clone()
                },
                &key
            ),
            Err(RoutedApplicationError::InvalidCiphertext)
        );
        packet.binding.context = *context.as_bytes();
        packet.ciphertext = vec![0; MAX_ROUTED_APPLICATION_PAYLOAD_BYTES + 1];
        assert_eq!(
            RoutedApplicationEnvelope::new(
                context,
                source.clone(),
                destination.clone(),
                [1; 16],
                4,
                ClosedRoutedPayload::EndpointCiphertext {
                    packet: packet.clone()
                },
                &key
            ),
            Err(RoutedApplicationError::InvalidCiphertext)
        );
        let control = EndpointCipherControl::Share(KeyShare {
            binding: packet.binding,
            sender: source.as_bytes(),
            offered_max_plaintext_bytes: max_routed_plaintext_bytes() as u32,
            ephemeral: [1; 32],
            offer_hash: [0; 32],
            signature: [0; 64],
        });
        let routed = RoutedApplicationEnvelope::new(
            context,
            source,
            destination,
            [1; 16],
            4,
            ClosedRoutedPayload::EndpointControl { control },
            &key,
        )
        .unwrap();
        routed.verify().unwrap(); // Endpoint must separately verify share/confirmation, never deliver this as data.
        let wire = serde_json::to_string(&routed).unwrap();
        assert!(!wire.contains("secret-channel"));
        assert!(!wire.contains("secret-body"));
    }

    #[test]
    fn endpoint_control_max_hop_wire_reservation_includes_signed_limit() {
        use ed25519_dalek::Signer;
        let (value, initiator_key, responder) = envelope();
        let context = value.context_id();
        let initiator = value.origin().clone();
        let ClosedRoutedPayload::EndpointCiphertext { packet } = value.payload else {
            unreachable!()
        };
        let responder_key = key(8);
        let offer_limit = max_routed_plaintext_bytes() as u32;
        for from_responder in [false, true] {
            let (source, destination, signer) = if from_responder {
                (responder.clone(), initiator.clone(), &responder_key)
            } else {
                (initiator.clone(), responder.clone(), &initiator_key)
            };
            let mut share = KeyShare {
                binding: packet.binding.clone(),
                sender: source.as_bytes(),
                ephemeral: [255; 32],
                offered_max_plaintext_bytes: offer_limit,
                offer_hash: if from_responder { [255; 32] } else { [0; 32] },
                signature: [0; 64],
            };
            share.signature = signer.sign(&share.signing_bytes()).to_bytes();
            let confirmation = KeyConfirmation {
                binding: packet.binding.clone(),
                sender: source.as_bytes(),
                transcript_hash: [255; 32],
                tag: [255; 16],
            };
            for control in [
                EndpointCipherControl::Share(share),
                EndpointCipherControl::Confirmation(confirmation),
            ] {
                control.validate().unwrap();
                let mut routed = RoutedApplicationEnvelope::new(
                    context,
                    source.clone(),
                    destination.clone(),
                    [255; 16],
                    MAX_ROUTED_HOP_BUDGET,
                    ClosedRoutedPayload::EndpointControl { control },
                    signer,
                )
                .unwrap();
                for seed in [20, 21, 22, 23] {
                    let hop_key = key(seed);
                    routed.append_hop(device(&hop_key), &hop_key).unwrap();
                }
                routed.verify().unwrap();
                let counted = routed.complete_encoded_len().unwrap();
                let wire = serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(
                    routed.clone(),
                ))
                .unwrap();
                assert_eq!(counted, wire.len());
                assert!(wire.len() <= ROUTED_CIPHERTEXT_METADATA_BYTES);
                assert!(wire.len() <= super::super::RECEIVE_FRAME_BYTES);
                let super::super::MeshMessage::RoutedApplication(decoded) =
                    serde_json::from_slice(&wire).unwrap()
                else {
                    panic!("control variant changed")
                };
                assert_eq!(decoded, routed);
                decoded.verify().unwrap();

                // Worst serialized representation, not a cryptographic
                // confirmation/negotiation fixture: every raw byte field has
                // three decimal digits and both signed local offers use the
                // largest admissible value. Outer DeviceIds/context already
                // have fixed-width canonical base32 representations.
                routed.origin_signature = "z".repeat(103);
                for hop in &mut routed.hops {
                    hop.prior_digest = [255; 32];
                    hop.signature = "z".repeat(103);
                    assert!(
                        super::super::encoded_json_len(hop).unwrap() < MAX_ROUTED_HOP_ENCODED_BYTES
                    );
                }
                let ClosedRoutedPayload::EndpointControl { control } = &mut routed.payload else {
                    unreachable!()
                };
                let binding = match control {
                    EndpointCipherControl::Share(share) => {
                        assert_eq!(share.offered_max_plaintext_bytes, offer_limit);
                        share.sender = [255; 32];
                        share.offer_hash = [255; 32];
                        share.signature = [255; 64];
                        &mut share.binding
                    }
                    EndpointCipherControl::Confirmation(confirmation) => {
                        confirmation.sender = [255; 32];
                        &mut confirmation.binding
                    }
                };
                binding.context = [255; 32];
                binding.initiator = [255; 32];
                binding.responder = [255; 32];
                binding.epoch = [255; 16];
                binding.introduction = Some([255; 16]);
                let counted = routed.complete_encoded_len().unwrap();
                let wire =
                    serde_json::to_vec(&super::super::MeshMessage::RoutedApplication(routed))
                        .unwrap();
                assert_eq!(counted, wire.len());
                assert!(wire.len() <= ROUTED_CIPHERTEXT_METADATA_BYTES);
                assert!(wire.len() <= super::super::RECEIVE_FRAME_BYTES);
            }
        }
    }
}
