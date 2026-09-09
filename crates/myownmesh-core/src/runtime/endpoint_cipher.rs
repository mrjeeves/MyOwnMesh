//! Endpoint-only routed encryption; neither membership nor route authority.
//! The engine owns registry slots, exact owner gates, timers and all wire work.
//! Moved, Admitted leases in the exact expected scope precede retention. Each
//! operation consumes its own lease; returned guards retain that lease through
//! borrowed serialization/delivery. Scope identity is not endpoint authority.
//!
//! These crate-internal APIs are finite-census seams for trusted implementation,
//! not a universal no-extraction boundary: borrowed DTOs/bytes can be copied,
//! and a mapping callback can publish side effects. Review every production
//! caller and actual queue owner to prove all copies are funded until terminal
//! release, including error/cancellation paths. The guard alone does not prove it.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use ed25519_dalek::{Signature, Signer, VerifyingKey};
use hkdf::Hkdf;
use rand_core::{OsRng, RngCore};
use sha2::{Digest, Sha256};
use std::time::{Duration, Instant};
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::{Zeroize, Zeroizing};

use crate::identity::Identity;
use crate::protocol::endpoint_cipher::{
    CipherError, CiphertextPacket, EpochBinding, KeyConfirmation, KeyShare, AEAD_TAG_BYTES,
    ENDPOINT_CIPHER_SUITE, ENDPOINT_CIPHER_VERSION, MAX_PLAINTEXT_BYTES, MAX_REPLAY_WINDOW,
};
use crate::resource::{
    FundedArc, ResourceAuthorityClass, ResourceClaim, ResourceClass, ResourceLease, ResourceScope,
};
use crate::semantic::{DeviceId, MeshContextId};

const MATERIAL_BYTES: usize = 72;
const TRANSCRIPT_WORK_BYTES: usize = 2_048;

#[derive(Clone, Copy, Debug)]
pub(crate) struct CipherLimits {
    pub max_plaintext_bytes: usize,
    pub replay_window: usize,
    pub lifetime: Duration,
}

impl CipherLimits {
    pub(crate) fn validate(&self) -> Result<(), CipherError> {
        if self.max_plaintext_bytes == 0
            || self.max_plaintext_bytes > MAX_PLAINTEXT_BYTES
            || !(1..=MAX_REPLAY_WINDOW).contains(&self.replay_window)
            || self.lifetime.is_zero()
        {
            return Err(CipherError::Limit);
        }
        Ok(())
    }
}

/// One claim survives pending -> confirming -> ready. No second key lease.
/// Registry entries and serialized queues are priced separately by their owner.
pub(crate) fn epoch_claim(limits: CipherLimits) -> Result<ResourceClaim, CipherError> {
    limits.validate()?;
    let bytes = std::mem::size_of::<PendingEpoch>()
        .max(std::mem::size_of::<ConfirmingEpoch>())
        .max(std::mem::size_of::<ReadyEpoch>())
        // FundedArc holds value and funding in two shared allocations. The
        // exact same lease survives outstanding operations after epoch drop.
        .checked_add(4 * std::mem::size_of::<usize>())
        .ok_or(CipherError::Limit)?
        .checked_add(std::mem::size_of::<ResourceLease>())
        .ok_or(CipherError::Limit)?
        .checked_add(std::mem::size_of::<OperationOwner>())
        .ok_or(CipherError::Limit)?
        .checked_add(limits.replay_window)
        .and_then(|v| v.checked_add(TRANSCRIPT_WORK_BYTES))
        // The retained KeyShare field is covered by size_of above. Share
        // signing/hashing uses one temporary at a time: price its added BEu32.
        // signing_bytes reserves its exact canonical length, not a growth cap.
        .and_then(|v| v.checked_add(std::mem::size_of::<u32>()))
        .ok_or(CipherError::Limit)?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes as u64),
        (ResourceClass::OpaqueDependencyResidual, 8),
    ])
    .map_err(|_| CipherError::Limit)
}

/// Intrinsic operation/output custody, not a complete route-envelope claim.
/// Wire owner adds its complete max-hop JSON and queue ownership to the moved
/// lease. Borrowed access does not prevent copies; caller census must account
/// for every retained copy and its actual terminal owner.
pub(crate) fn data_work_claim(plaintext_bytes: usize) -> Result<ResourceClaim, CipherError> {
    if plaintext_bytes > MAX_PLAINTEXT_BYTES {
        return Err(CipherError::Limit);
    }
    let bytes = plaintext_bytes
        .checked_add(AEAD_TAG_BYTES)
        .and_then(|v| v.checked_mul(4))
        .and_then(|v| v.checked_add(TRANSCRIPT_WORK_BYTES))
        .and_then(|v| v.checked_add(std::mem::size_of::<CipherOperation>()))
        .and_then(|v| {
            v.checked_add(
                std::mem::size_of::<FundedCiphertext>().max(std::mem::size_of::<FundedPlaintext>()),
            )
        })
        .ok_or(CipherError::Limit)?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes as u64),
        (ResourceClass::OpaqueDependencyResidual, 8),
    ])
    .map_err(|_| CipherError::Limit)
}

fn require_claim(
    lease: &ResourceLease,
    expected_scope: &ResourceScope,
    claim: ResourceClaim,
) -> Result<(), CipherError> {
    if lease.authority() != ResourceAuthorityClass::Admitted {
        return Err(CipherError::Authority);
    }
    if &lease.scope() != expected_scope {
        return Err(CipherError::Scope);
    }
    lease
        .claim()
        .checked_sub(claim)
        .map(|_| ())
        .map_err(|_| CipherError::Limit)
}

// Identity of one particular process-local cipher epoch, not wire identity,
// not logical-session or membership authority. Never serialized or exported.
struct OperationOwner {
    scope: ResourceScope,
}

/// Move-only reservation for ONE operation of ONE epoch. Minting consumes the
/// lease. Consuming an operation cannot furnish a second encrypt/decrypt call.
pub(crate) struct CipherOperation {
    owner: FundedArc<OperationOwner>,
    max_plaintext: usize,
    funding: ResourceLease,
}

/// Holds exclusive operation funding for its own lifetime. Trusted callers must
/// keep it (or its mapped guard) through serialization and terminal native send.
/// This wrapper is not Clone, but packet() exposes a Clone DTO; source discipline
/// and the finite production-caller census must exclude uncharged escaped copies.
pub(crate) struct FundedCiphertext {
    packet: CiphertextPacket,
    _operation: CipherOperation,
}
impl FundedCiphertext {
    #[cfg(test)]
    pub(crate) fn packet(&self) -> &CiphertextPacket {
        &self.packet
    }

    /// Internal finite-census mapping seam, not a side-effect isolation boundary.
    /// Outer owner prices BOTH retained packet/envelope copies and serialized
    /// peak bytes. This funding check precedes the callback, but cannot validate
    /// its claim or prevent it from copying/publishing data elsewhere. Reviewed
    /// builders must return owned storage only through this guard, publish no
    /// escaped copies, and leave no retained side effects on Err/unwind. Actual
    /// queue cancellation must join/drop work before releasing its funding.
    pub(crate) fn try_map<T>(
        self,
        outer_claim: ResourceClaim,
        build: impl FnOnce(&CiphertextPacket) -> Result<T, CipherError>,
    ) -> Result<FundedCipherOutput<T>, CipherError> {
        let complete = data_work_claim(self._operation.max_plaintext)?
            .checked_add(outer_claim)
            .map_err(|_| CipherError::Limit)?;
        require_claim(
            &self._operation.funding,
            &self._operation.owner.scope,
            complete,
        )?;
        let value = build(&self.packet)?;
        Ok(FundedCipherOutput {
            value,
            _operation: self._operation,
        })
    }
}

/// Owned outer envelope/serialized output retaining exclusive operation and
/// epoch funding. Pass this guard through the final queue/native-send owner.
/// value() can expose copyable or interior-mutable T; terminal custody requires
/// a census of actual callers, not a universal guarantee from this generic type.
pub(crate) struct FundedCipherOutput<T> {
    value: T,
    _operation: CipherOperation,
}
impl<T> FundedCipherOutput<T> {
    pub(crate) fn value(&self) -> &T {
        &self.value
    }
}

/// Owns and erases this plaintext allocation only. bytes() can be copied; any
/// delivery copy needs reviewed funding/lifetime and its own erasure policy.
pub(crate) struct FundedPlaintext {
    bytes: Zeroizing<Vec<u8>>,
    _operation: CipherOperation,
}
impl FundedPlaintext {
    pub(crate) fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

pub(crate) struct PendingEpoch {
    share: KeyShare,
    secret: EphemeralSecret,
    limits: CipherLimits,
    expires: Instant,
    owner: FundedArc<OperationOwner>,
}

impl PendingEpoch {
    // The expected scope and moved lease stay explicit beside the endpoint
    // binding and local limits; do not hide this admission/custody boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn initiate(
        identity: &Identity,
        context: MeshContextId,
        peer: &DeviceId,
        introduction: Option<[u8; 16]>,
        limits: CipherLimits,
        expected_scope: &ResourceScope,
        funding: ResourceLease,
        now: Instant,
    ) -> Result<(Self, KeyShare), CipherError> {
        require_claim(&funding, expected_scope, epoch_claim(limits)?)?;
        let mut epoch = [0; 16];
        OsRng.fill_bytes(&mut epoch);
        let binding = EpochBinding {
            version: ENDPOINT_CIPHER_VERSION,
            suite: ENDPOINT_CIPHER_SUITE,
            context: *context.as_bytes(),
            initiator: identity.signing_key().verifying_key().to_bytes(),
            responder: peer.as_bytes(),
            epoch,
            introduction,
        };
        Self::begin(identity, binding, [0; 32], limits, funding, now)
    }

    // Preserve the borrowed signed offer and expected scope separately from
    // the moved funding lease; no signature or ownership regrouping for lint.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn respond(
        identity: &Identity,
        context: MeshContextId,
        peer: &DeviceId,
        introduction: Option<[u8; 16]>,
        offer: &KeyShare,
        limits: CipherLimits,
        expected_scope: &ResourceScope,
        funding: ResourceLease,
        now: Instant,
    ) -> Result<(Self, KeyShare), CipherError> {
        require_claim(&funding, expected_scope, epoch_claim(limits)?)?;
        verify_share(offer)?;
        if offer.binding.context != *context.as_bytes()
            || offer.binding.initiator != peer.as_bytes()
            || offer.binding.responder != identity.signing_key().verifying_key().to_bytes()
            || offer.sender != offer.binding.initiator
            || offer.binding.introduction != introduction
        {
            return Err(CipherError::Binding);
        }
        Self::begin(
            identity,
            offer.binding.clone(),
            share_hash(offer),
            limits,
            funding,
            now,
        )
    }

    fn begin(
        identity: &Identity,
        binding: EpochBinding,
        offer_hash: [u8; 32],
        limits: CipherLimits,
        funding: ResourceLease,
        now: Instant,
    ) -> Result<(Self, KeyShare), CipherError> {
        binding.validate()?;
        let expires = now.checked_add(limits.lifetime).ok_or(CipherError::Limit)?;
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let mut share = KeyShare {
            binding,
            sender: identity.signing_key().verifying_key().to_bytes(),
            ephemeral: PublicKey::from(&secret).to_bytes(),
            offer_hash,
            offered_max_plaintext_bytes: u32::try_from(limits.max_plaintext_bytes)
                .map_err(|_| CipherError::Limit)?,
            signature: [0; 64],
        };
        share.signature = identity
            .signing_key()
            .sign(&share.signing_bytes())
            .to_bytes();
        let outbound = share.clone();
        let owner = FundedArc::new(
            OperationOwner {
                scope: funding.scope(),
            },
            funding,
        )
        .map_err(|_| CipherError::Authority)?;
        Ok((
            Self {
                share,
                secret,
                limits,
                expires,
                owner,
            },
            outbound,
        ))
    }

    #[cfg(test)]
    pub(crate) fn binding(&self) -> &EpochBinding {
        &self.share.binding
    }

    /// All peer-controlled checks before the registry takes the pending state.
    /// A public fixed scalar detects non-contributory X25519 points without
    /// consuming this epoch's secret. This value is NOT used for key derivation.
    /// Unique mutable access also serializes the prepaid transcript/DH scratch;
    /// concurrent checks cannot share one operation's bounded working budget.
    pub(crate) fn verify_peer_share(
        &mut self,
        peer: &KeyShare,
        now: Instant,
    ) -> Result<(), CipherError> {
        if now >= self.expires {
            return Err(CipherError::Closed);
        }
        verify_share(peer)?;
        if peer.binding != self.share.binding
            || peer.sender != self.share.binding.destination(&self.share.sender)?
        {
            return Err(CipherError::Binding);
        }
        let (offer, answer) = if self.share.sender == self.share.binding.initiator {
            (&self.share, peer)
        } else {
            (peer, &self.share)
        };
        if answer.offer_hash != share_hash(offer) {
            return Err(CipherError::Transcript);
        }
        if x25519_dalek::x25519([0; 32], peer.ephemeral) == [0; 32] {
            return Err(CipherError::Authentication);
        }
        Ok(())
    }

    /// Engine calls verify_peer_share before taking the exact registry entry.
    /// Rechecking here prevents any internal caller from bypassing validation.
    pub(crate) fn finish(
        mut self,
        peer: &KeyShare,
        now: Instant,
    ) -> Result<(ConfirmingEpoch, KeyConfirmation), CipherError> {
        self.verify_peer_share(peer, now)?;
        let effective_max_plaintext = self
            .limits
            .max_plaintext_bytes
            .min(self.share.offered_max_plaintext_bytes as usize)
            .min(peer.offered_max_plaintext_bytes as usize);
        let (offer, answer) = if self.share.sender == self.share.binding.initiator {
            (&self.share, peer)
        } else {
            (peer, &self.share)
        };
        let transcript_hash = transcript_hash(offer, answer);
        let shared = self.secret.diffie_hellman(&PublicKey::from(peer.ephemeral));
        if shared.as_bytes() == &[0; 32] {
            return Err(CipherError::Authentication);
        }
        let mut info = Vec::with_capacity(256);
        info.extend_from_slice(b"myownmesh-routed-e2e-key-v1:");
        self.share.binding.append_canonical(&mut info);
        info.extend_from_slice(&transcript_hash);
        let keys = derive_material(shared.as_bytes(), &info)?;
        let session = ReadyEpoch {
            binding: self.share.binding,
            local: self.share.sender,
            keys,
            transcript_hash,
            next_send: 1,
            replay: ReplayWindow::new(self.limits.replay_window),
            expires: self.expires,
            max_plaintext: effective_max_plaintext,
            closed: false,
            owner: self.owner,
        };
        let tag = encrypt(
            session.send_key(),
            &session.nonce(true, 0),
            &session.aad(session.local, 0, true),
            &[],
        )?;
        let confirmation = KeyConfirmation {
            binding: session.binding.clone(),
            sender: session.local,
            transcript_hash,
            tag: tag.try_into().map_err(|_| CipherError::Authentication)?,
        };
        Ok((ConfirmingEpoch { session }, confirmation))
    }
}

pub(crate) struct ConfirmingEpoch {
    session: ReadyEpoch,
}
impl ConfirmingEpoch {
    #[cfg(test)]
    pub(crate) fn binding(&self) -> &EpochBinding {
        &self.session.binding
    }
    /// Borrowing prevalidation leaves the legitimate confirming epoch intact
    /// on forged same-binding tags. Engine checks before removing its record.
    pub(crate) fn verify_confirmation(
        &mut self,
        confirmation: &KeyConfirmation,
        now: Instant,
    ) -> Result<(), CipherError> {
        if self.session.closed || now >= self.session.expires {
            return Err(CipherError::Closed);
        }
        confirmation.validate()?;
        if confirmation.binding != self.session.binding
            || confirmation.sender != self.session.peer_key()
            || confirmation.transcript_hash != self.session.transcript_hash
        {
            return Err(CipherError::Transcript);
        }
        decrypt(
            self.session.recv_key(),
            &self.session.nonce(false, 0),
            &self.session.aad(confirmation.sender, 0, true),
            &confirmation.tag,
        )?;
        Ok(())
    }
    pub(crate) fn confirm(
        mut self,
        confirmation: &KeyConfirmation,
        now: Instant,
    ) -> Result<ReadyEpoch, CipherError> {
        self.verify_confirmation(confirmation, now)?;
        Ok(self.session)
    }
}

/// Deliberately neither Clone nor Serialize nor Debug. Only confirmation mints
/// Ready. Engine authentication/policy checks are additionally required.
pub(crate) struct ReadyEpoch {
    binding: EpochBinding,
    local: [u8; 32],
    keys: Zeroizing<[u8; MATERIAL_BYTES]>,
    transcript_hash: [u8; 32],
    next_send: u64,
    replay: ReplayWindow,
    expires: Instant,
    max_plaintext: usize,
    closed: bool,
    owner: FundedArc<OperationOwner>,
}

impl ReadyEpoch {
    #[cfg(test)]
    pub(crate) fn binding(&self) -> &EpochBinding {
        &self.binding
    }
    /// Confirmed minimum of the signed offers; includes all encrypted channel
    /// metadata, not just the application body. Lifetime/replay remain local.
    pub(crate) fn max_plaintext_bytes(&self) -> usize {
        self.max_plaintext
    }
    #[cfg(test)]
    pub(crate) fn local_key(&self) -> [u8; 32] {
        self.local
    }
    pub(crate) fn peer_key(&self) -> [u8; 32] {
        if self.local == self.binding.initiator {
            self.binding.responder
        } else {
            self.binding.initiator
        }
    }
    fn send_first(&self) -> bool {
        self.local == self.binding.initiator
    }
    fn send_key(&self) -> &[u8] {
        if self.send_first() {
            &self.keys[..32]
        } else {
            &self.keys[32..64]
        }
    }
    fn recv_key(&self) -> &[u8] {
        if self.send_first() {
            &self.keys[32..64]
        } else {
            &self.keys[..32]
        }
    }
    fn nonce(&self, sending: bool, seq: u64) -> [u8; 12] {
        let first = if sending {
            self.send_first()
        } else {
            !self.send_first()
        };
        let mut nonce = [0; 12];
        nonce[..4].copy_from_slice(if first {
            &self.keys[64..68]
        } else {
            &self.keys[68..72]
        });
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        nonce
    }
    fn aad(&self, sender: [u8; 32], seq: u64, confirmation: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256);
        out.extend_from_slice(if confirmation {
            b"myownmesh-routed-e2e-confirm-v1:"
        } else {
            b"myownmesh-routed-e2e-channel-message-v1:"
        });
        self.binding.append_canonical(&mut out);
        out.extend_from_slice(&self.transcript_hash);
        out.extend_from_slice(&sender);
        out.extend_from_slice(&seq.to_be_bytes());
        out
    }
    fn ensure_live(&mut self, now: Instant) -> Result<(), CipherError> {
        if self.closed || now >= self.expires {
            self.close();
            return Err(CipherError::Closed);
        }
        Ok(())
    }
    pub(crate) fn close(&mut self) {
        self.keys.zeroize();
        self.closed = true;
    }
    pub(crate) fn operation(
        &mut self,
        max_plaintext: usize,
        work: ResourceLease,
        now: Instant,
    ) -> Result<CipherOperation, CipherError> {
        self.ensure_live(now)?;
        if max_plaintext > self.max_plaintext {
            return Err(CipherError::Limit);
        }
        require_claim(&work, &self.owner.scope, data_work_claim(max_plaintext)?)?;
        Ok(CipherOperation {
            owner: self.owner.clone(),
            max_plaintext,
            funding: work,
        })
    }
    fn check_operation(&self, operation: &CipherOperation, len: usize) -> Result<(), CipherError> {
        if !FundedArc::ptr_eq(&self.owner, &operation.owner) {
            return Err(CipherError::OperationOwner);
        }
        if len > operation.max_plaintext {
            return Err(CipherError::Limit);
        }
        require_claim(&operation.funding, &self.owner.scope, data_work_claim(len)?)
    }
    pub(crate) fn seal(
        &mut self,
        plaintext: &[u8],
        now: Instant,
        operation: CipherOperation,
    ) -> Result<FundedCiphertext, CipherError> {
        self.ensure_live(now)?;
        if plaintext.len() > self.max_plaintext {
            return Err(CipherError::Limit);
        }
        self.check_operation(&operation, plaintext.len())?;
        let sequence = self.next_send;
        let Some(next) = sequence.checked_add(1) else {
            self.close();
            return Err(CipherError::Exhausted);
        };
        // Consume before sealing; errors/ambiguous network sends cannot reuse it.
        self.next_send = next;
        let ciphertext = encrypt(
            self.send_key(),
            &self.nonce(true, sequence),
            &self.aad(self.local, sequence, false),
            plaintext,
        )?;
        let packet = CiphertextPacket {
            binding: self.binding.clone(),
            sender: self.local,
            sequence,
            ciphertext,
        };
        Ok(FundedCiphertext {
            packet,
            _operation: operation,
        })
    }
    pub(crate) fn open(
        &mut self,
        packet: &CiphertextPacket,
        now: Instant,
        operation: CipherOperation,
    ) -> Result<FundedPlaintext, CipherError> {
        self.ensure_live(now)?;
        packet.validate()?;
        if packet.binding != self.binding || packet.sender != self.peer_key() {
            return Err(CipherError::Binding);
        }
        let len = packet
            .ciphertext
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(CipherError::Limit)?;
        if len > self.max_plaintext {
            return Err(CipherError::Limit);
        }
        self.check_operation(&operation, len)?;
        if !self.replay.can_accept(packet.sequence) {
            return Err(CipherError::Replay);
        }
        let plaintext = decrypt(
            self.recv_key(),
            &self.nonce(false, packet.sequence),
            &self.aad(packet.sender, packet.sequence, false),
            &packet.ciphertext,
        )?;
        self.replay.record(packet.sequence);
        Ok(FundedPlaintext {
            bytes: Zeroizing::new(plaintext),
            _operation: operation,
        })
    }
}

fn verify_share(share: &KeyShare) -> Result<(), CipherError> {
    share.validate()?;
    VerifyingKey::from_bytes(&share.sender)
        .map_err(|_| CipherError::Signature)?
        .verify_strict(
            &share.signing_bytes(),
            &Signature::from_bytes(&share.signature),
        )
        .map_err(|_| CipherError::Signature)
}
fn share_hash(share: &KeyShare) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(share.signing_bytes());
    hash.update(share.signature);
    hash.finalize().into()
}
fn transcript_hash(offer: &KeyShare, answer: &KeyShare) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"myownmesh-routed-e2e-transcript-v1:");
    hash.update(share_hash(offer));
    hash.update(share_hash(answer));
    hash.finalize().into()
}

// Shared primitive composition with ClosedMemberRelay. Domain/transcript and
// admission remain the caller's: extracting these does not open its authority.
pub(super) fn derive_material(
    shared: &[u8],
    info: &[u8],
) -> Result<Zeroizing<[u8; MATERIAL_BYTES]>, CipherError> {
    let mut material = Zeroizing::new([0; MATERIAL_BYTES]);
    Hkdf::<Sha256>::new(None, shared)
        .expand(info, material.as_mut())
        .map_err(|_| CipherError::Authentication)?;
    Ok(material)
}
pub(super) fn encrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    bytes: &[u8],
) -> Result<Vec<u8>, CipherError> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| CipherError::Authentication)?
        .encrypt(Nonce::from_slice(nonce), Payload { msg: bytes, aad })
        .map_err(|_| CipherError::Authentication)
}
pub(super) fn decrypt(
    key: &[u8],
    nonce: &[u8; 12],
    aad: &[u8],
    bytes: &[u8],
) -> Result<Vec<u8>, CipherError> {
    Aes256Gcm::new_from_slice(key)
        .map_err(|_| CipherError::Authentication)?
        .decrypt(Nonce::from_slice(nonce), Payload { msg: bytes, aad })
        .map_err(|_| CipherError::Authentication)
}

/// Existing ClosedMemberRelay sliding window, shared without semantic changes.
pub(super) struct ReplayWindow {
    width: usize,
    highest: Option<u64>,
    seen: Vec<bool>,
}
impl ReplayWindow {
    pub(super) fn new(width: usize) -> Self {
        Self {
            width,
            highest: None,
            seen: vec![false; width],
        }
    }
    pub(super) fn can_accept(&self, sequence: u64) -> bool {
        let Some(highest) = self.highest else {
            return true;
        };
        if sequence > highest {
            return true;
        }
        let delta = highest - sequence;
        delta < self.width as u64 && !self.seen[delta as usize]
    }
    pub(super) fn record(&mut self, sequence: u64) {
        let Some(highest) = self.highest else {
            self.highest = Some(sequence);
            self.seen[0] = true;
            return;
        };
        if sequence > highest {
            let advance = sequence - highest;
            if advance >= self.width as u64 {
                self.seen.fill(false);
            } else {
                self.seen.rotate_right(advance as usize);
                self.seen[..advance as usize].fill(false);
            }
            self.highest = Some(sequence);
            self.seen[0] = true;
        } else {
            self.seen[(highest - sequence) as usize] = true;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};

    fn limits() -> CipherLimits {
        CipherLimits {
            max_plaintext_bytes: 1024,
            replay_window: 4,
            lifetime: Duration::from_secs(10),
        }
    }

    struct Fixture {
        provider: FiniteResourceProvider,
        port: ResourceProviderPort,
        alice: Identity,
        bob: Identity,
        now: Instant,
    }
    impl Fixture {
        fn new() -> Self {
            let epoch =
                FiniteResourceProvider::reservation_planning_charge(epoch_claim(limits()).unwrap())
                    .unwrap();
            let work =
                FiniteResourceProvider::reservation_planning_charge(data_work_claim(1024).unwrap())
                    .unwrap();
            let grant = epoch
                .checked_scale(4)
                .unwrap()
                .checked_add(work.checked_scale(8).unwrap())
                .unwrap()
                .checked_add(
                    FiniteResourceProvider::scope_planning_charge()
                        .checked_scale(2)
                        .unwrap(),
                )
                .unwrap();
            let provider = FiniteResourceProvider::new(grant);
            let port = ResourceProviderPort::new(provider.clone()).unwrap();
            Self {
                provider,
                port,
                alice: Identity::ephemeral(),
                bob: Identity::ephemeral(),
                now: Instant::now(),
            }
        }
        fn scope(&self) -> ResourceScope {
            self.port.process_scope()
        }
        fn lease(&self, claim: ResourceClaim) -> ResourceLease {
            self.port
                .acquire(&self.scope(), ResourceAuthorityClass::Admitted, claim)
                .unwrap()
        }
        fn id(identity: &Identity) -> DeviceId {
            DeviceId::from_canonical_str(identity.public_id()).unwrap()
        }
        fn pending(&self) -> (PendingEpoch, KeyShare, PendingEpoch, KeyShare) {
            self.pending_with_limits(1024, 1024)
        }
        fn pending_with_limits(
            &self,
            offered: usize,
            answered: usize,
        ) -> (PendingEpoch, KeyShare, PendingEpoch, KeyShare) {
            let context = MeshContextId::from_bytes([3; 32]);
            let a_limits = CipherLimits {
                max_plaintext_bytes: offered,
                ..limits()
            };
            let b_limits = CipherLimits {
                max_plaintext_bytes: answered,
                ..limits()
            };
            let (a, offer) = PendingEpoch::initiate(
                &self.alice,
                context,
                &Self::id(&self.bob),
                Some([9; 16]),
                a_limits,
                &self.scope(),
                self.lease(epoch_claim(a_limits).unwrap()),
                self.now,
            )
            .unwrap();
            let (b, answer) = PendingEpoch::respond(
                &self.bob,
                context,
                &Self::id(&self.alice),
                Some([9; 16]),
                &offer,
                b_limits,
                &self.scope(),
                self.lease(epoch_claim(b_limits).unwrap()),
                self.now,
            )
            .unwrap();
            assert_eq!(a.binding(), b.binding());
            (a, offer, b, answer)
        }
        fn ready(&self) -> (ReadyEpoch, ReadyEpoch) {
            self.ready_with_limits(1024, 1024)
        }
        fn ready_with_limits(&self, offered: usize, answered: usize) -> (ReadyEpoch, ReadyEpoch) {
            let (mut a, offer, mut b, answer) = self.pending_with_limits(offered, answered);
            a.verify_peer_share(&answer, self.now).unwrap();
            b.verify_peer_share(&offer, self.now).unwrap();
            let (mut a, a_confirm) = a.finish(&answer, self.now).unwrap();
            let (mut b, b_confirm) = b.finish(&offer, self.now).unwrap();
            assert_eq!(a.binding(), b.binding());
            a.verify_confirmation(&b_confirm, self.now).unwrap();
            b.verify_confirmation(&a_confirm, self.now).unwrap();
            (
                a.confirm(&b_confirm, self.now).unwrap(),
                b.confirm(&a_confirm, self.now).unwrap(),
            )
        }
        fn operation(&self, epoch: &mut ReadyEpoch, len: usize) -> CipherOperation {
            epoch
                .operation(len, self.lease(data_work_claim(len).unwrap()), self.now)
                .unwrap()
        }
        // These helpers retain the production guards, never return bare bytes.
        fn send(
            &self,
            epoch: &mut ReadyEpoch,
            bytes: &[u8],
        ) -> Result<FundedCiphertext, CipherError> {
            let operation = epoch.operation(
                bytes.len(),
                self.lease(data_work_claim(bytes.len())?),
                self.now,
            )?;
            epoch.seal(bytes, self.now, operation)
        }
        fn receive(
            &self,
            epoch: &mut ReadyEpoch,
            packet: &CiphertextPacket,
        ) -> Result<FundedPlaintext, CipherError> {
            let len = packet
                .ciphertext
                .len()
                .checked_sub(AEAD_TAG_BYTES)
                .ok_or(CipherError::Limit)?;
            let operation = epoch.operation(len, self.lease(data_work_claim(len)?), self.now)?;
            epoch.open(packet, self.now, operation)
        }
    }

    #[test]
    fn signed_asymmetric_limits_agree_and_enforce_exact_max_in_both_orientations() {
        for (offered, answered) in [(8, 32), (32, 8)] {
            let f = Fixture::new();
            let baseline = f.provider.in_use();
            let (mut a, mut b) = f.ready_with_limits(offered, answered);
            assert_eq!(a.max_plaintext_bytes(), 8);
            assert_eq!(b.max_plaintext_bytes(), 8);
            let ready_usage = f.provider.in_use();
            for epoch in [&mut a, &mut b] {
                assert!(matches!(
                    epoch.operation(9, f.lease(data_work_claim(9).unwrap()), f.now),
                    Err(CipherError::Limit)
                ));
                let operation = f.operation(epoch, 8);
                assert!(matches!(
                    epoch.seal(&[1; 9], f.now, operation),
                    Err(CipherError::Limit)
                ));
                assert_eq!(epoch.next_send, 1);
                assert!(epoch.replay.highest.is_none());
            }
            assert_eq!(f.provider.in_use(), ready_usage);
            let packet = f.send(&mut a, &[7; 8]).unwrap();
            let mut oversized = packet.packet().clone();
            oversized.ciphertext.push(0);
            let operation = f.operation(&mut b, 8);
            assert!(matches!(
                b.open(&oversized, f.now, operation),
                Err(CipherError::Limit)
            ));
            assert!(b.replay.highest.is_none());
            assert_eq!(f.receive(&mut b, packet.packet()).unwrap().bytes(), &[7; 8]);
            let reverse = f.send(&mut b, &[9; 8]).unwrap();
            let mut oversized = reverse.packet().clone();
            oversized.ciphertext.push(0);
            let operation = f.operation(&mut a, 8);
            assert!(matches!(
                a.open(&oversized, f.now, operation),
                Err(CipherError::Limit)
            ));
            assert!(a.replay.highest.is_none());
            assert_eq!(
                f.receive(&mut a, reverse.packet()).unwrap().bytes(),
                &[9; 8]
            );
            drop((packet, reverse, a, b));
            assert_eq!(f.provider.in_use(), baseline);
        }
    }

    #[test]
    fn offered_limit_tampering_and_invalid_ranges_preserve_pending_epoch() {
        let f = Fixture::new();
        let (mut a, offer, mut b, answer) = f.pending();
        let baseline = f.provider.in_use();
        let mut changed = answer.clone();
        changed.offered_max_plaintext_bytes = 512;
        assert_eq!(
            a.verify_peer_share(&changed, f.now),
            Err(CipherError::Signature)
        );
        let mut changed_offer = offer.clone();
        changed_offer.offered_max_plaintext_bytes = 512;
        assert_eq!(
            b.verify_peer_share(&changed_offer, f.now),
            Err(CipherError::Signature)
        );
        changed_offer.signature = f
            .alice
            .signing_key()
            .sign(&changed_offer.signing_bytes())
            .to_bytes();
        assert_eq!(
            b.verify_peer_share(&changed_offer, f.now),
            Err(CipherError::Transcript),
            "answer offer_hash binds even an otherwise valid re-signed offer"
        );
        for value in [0, MAX_PLAINTEXT_BYTES as u32 + 1, u32::MAX] {
            let mut bad_answer = answer.clone();
            bad_answer.offered_max_plaintext_bytes = value;
            bad_answer.signature = f
                .bob
                .signing_key()
                .sign(&bad_answer.signing_bytes())
                .to_bytes();
            assert_eq!(
                a.verify_peer_share(&bad_answer, f.now),
                Err(CipherError::Limit)
            );
            let mut bad_offer = offer.clone();
            bad_offer.offered_max_plaintext_bytes = value;
            bad_offer.signature = f
                .alice
                .signing_key()
                .sign(&bad_offer.signing_bytes())
                .to_bytes();
            assert_eq!(
                b.verify_peer_share(&bad_offer, f.now),
                Err(CipherError::Limit)
            );
            assert!(matches!(
                PendingEpoch::respond(
                    &f.bob,
                    MeshContextId::from_bytes([3; 32]),
                    &Fixture::id(&f.alice),
                    Some([9; 16]),
                    &bad_offer,
                    limits(),
                    &f.scope(),
                    f.lease(epoch_claim(limits()).unwrap()),
                    f.now
                ),
                Err(CipherError::Limit)
            ));
            assert_eq!(f.provider.in_use(), baseline);
        }
        a.verify_peer_share(&answer, f.now).unwrap();
        b.verify_peer_share(&offer, f.now).unwrap();
        let (a, a_confirm) = a.finish(&answer, f.now).unwrap();
        let (b, b_confirm) = b.finish(&offer, f.now).unwrap();
        assert_eq!(
            a.confirm(&b_confirm, f.now).unwrap().max_plaintext_bytes(),
            1024
        );
        assert_eq!(
            b.confirm(&a_confirm, f.now).unwrap().max_plaintext_bytes(),
            1024
        );
    }

    #[test]
    fn confirmation_binds_both_limit_offers_even_when_effective_min_is_unchanged() {
        let f = Fixture::new();
        let (a, offer, b, answer) = f.pending_with_limits(8, 16);
        let mut changed = answer.clone();
        changed.offered_max_plaintext_bytes = 32;
        changed.signature = f
            .bob
            .signing_key()
            .sign(&changed.signing_bytes())
            .to_bytes();
        let (mut a, a_confirm) = a.finish(&changed, f.now).unwrap();
        let (mut b, old_confirm) = b.finish(&offer, f.now).unwrap();
        assert_eq!(a.session.max_plaintext_bytes(), 8);
        assert_eq!(b.session.max_plaintext_bytes(), 8);
        assert_ne!(a_confirm.transcript_hash, old_confirm.transcript_hash);
        assert_eq!(
            a.verify_confirmation(&old_confirm, f.now),
            Err(CipherError::Transcript)
        );
        let mut patched = old_confirm.clone();
        patched.transcript_hash = a_confirm.transcript_hash;
        assert_eq!(
            a.verify_confirmation(&patched, f.now),
            Err(CipherError::Authentication)
        );
        assert_eq!(
            b.verify_confirmation(&a_confirm, f.now),
            Err(CipherError::Transcript)
        );
        assert_eq!(a.session.next_send, 1);
        assert!(a.session.replay.highest.is_none());
        assert!(!a.session.closed);
    }

    #[test]
    fn one_byte_agreement_refuses_whole_channel_message_without_counter_change() {
        let f = Fixture::new();
        let (mut a, b) = f.ready_with_limits(1, 32);
        assert_eq!(a.max_plaintext_bytes(), 1);
        assert_eq!(b.max_plaintext_bytes(), 1);
        // This is the actual inner public message shape, not a raw-body length.
        // Engine must separately count it before allocation; this primitive control
        // proves refusal, not a useful channel payload or assembled send PASS.
        let message = crate::protocol::MeshMessage::Channel {
            channel: "a".into(),
            payload: serde_json::Value::Null,
        };
        let bytes = serde_json::to_vec(&message).unwrap();
        assert!(bytes.len() > a.max_plaintext_bytes());
        let baseline = f.provider.in_use();
        assert!(matches!(
            a.operation(
                bytes.len(),
                f.lease(data_work_claim(bytes.len()).unwrap()),
                f.now
            ),
            Err(CipherError::Limit)
        ));
        let operation = f.operation(&mut a, 1);
        assert!(matches!(
            a.seal(&bytes, f.now, operation),
            Err(CipherError::Limit)
        ));
        assert_eq!(a.next_send, 1);
        assert!(a.replay.highest.is_none());
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn offered_limit_canonical_bytes_are_exact_bounded_and_required_on_wire() {
        use crate::protocol::endpoint_cipher::MAX_KEY_SHARE_SIGNING_BYTES;
        let f = Fixture::new();
        let (a, mut offer, b, _) = f.pending();
        for introduction in [None, Some([9; 16])] {
            offer.binding.introduction = introduction;
            offer.offered_max_plaintext_bytes = MAX_PLAINTEXT_BYTES as u32;
            let bytes = offer.signing_bytes();
            assert_eq!(
                bytes.len(),
                MAX_KEY_SHARE_SIGNING_BYTES - if introduction.is_none() { 16 } else { 0 }
            );
            assert!(bytes.capacity() <= TRANSCRIPT_WORK_BYTES + std::mem::size_of::<u32>());
            assert_eq!(
                &bytes[bytes.len() - 4..],
                &(MAX_PLAINTEXT_BYTES as u32).to_be_bytes()
            );
            assert!(bytes.len() <= TRANSCRIPT_WORK_BYTES + std::mem::size_of::<u32>());
            offer.signature = f.alice.signing_key().sign(&bytes).to_bytes();
            verify_share(&offer).unwrap();
            let value = serde_json::to_value(&offer).unwrap();
            assert_eq!(
                serde_json::from_value::<KeyShare>(value.clone()).unwrap(),
                offer
            );
            let mut missing = value;
            missing
                .as_object_mut()
                .unwrap()
                .remove("offered_max_plaintext_bytes");
            assert!(serde_json::from_value::<KeyShare>(missing).is_err());
        }
        drop((a, b));
    }

    #[test]
    fn confirmed_epoch_encrypts_channel_body_and_refuses_tamper_replay_reflection() {
        let f = Fixture::new();
        let baseline = f.provider.in_use();
        let (mut a, mut b) = f.ready();
        assert_eq!(a.local_key(), b.peer_key());
        let body =
            br#"{"kind":"channel_frame","channel":"private-market","payload":{"bytes":[0,255]}}"#;
        let packet = f.send(&mut a, body).unwrap();
        assert!(!packet
            .packet()
            .ciphertext
            .windows(b"private-market".len())
            .any(|v| v == b"private-market"));
        let mut tampered = packet.packet().clone();
        tampered.ciphertext[0] ^= 1;
        assert!(matches!(
            f.receive(&mut b, &tampered),
            Err(CipherError::Authentication)
        ));
        assert!(matches!(
            f.receive(&mut a, packet.packet()),
            Err(CipherError::Binding)
        ));
        let plaintext = f.receive(&mut b, packet.packet()).unwrap();
        assert_eq!(plaintext.bytes(), body);
        assert!(matches!(
            f.receive(&mut b, packet.packet()),
            Err(CipherError::Replay)
        ));
        let reverse = f.send(&mut b, &[0, 255, 7]).unwrap();
        assert_eq!(
            f.receive(&mut a, reverse.packet()).unwrap().bytes(),
            [0, 255, 7]
        );
        drop((packet, plaintext, reverse, a, b));
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn signed_contributions_refuse_full_key_context_intro_and_transcript_substitution() {
        let f = Fixture::new();
        let (mut a, offer, b, answer) = f.pending();
        let mut wrong = answer.clone();
        wrong.ephemeral[0] ^= 1;
        assert_eq!(
            a.verify_peer_share(&wrong, f.now),
            Err(CipherError::Signature)
        );
        // Same visible binding + forged signature cannot consume pending state.
        a.verify_peer_share(&answer, f.now).unwrap();
        drop(a.finish(&answer, f.now).unwrap());
        drop(b);
        for field in 0..4 {
            let mut wrong = offer.clone();
            match field {
                0 => wrong.binding.context[0] ^= 1,
                1 => {
                    wrong.binding.responder = Identity::ephemeral()
                        .signing_key()
                        .verifying_key()
                        .to_bytes()
                }
                2 => wrong.binding.introduction = None,
                _ => wrong.binding.suite = 2,
            }
            wrong.signature = f
                .alice
                .signing_key()
                .sign(&wrong.signing_bytes())
                .to_bytes();
            assert!(PendingEpoch::respond(
                &f.bob,
                MeshContextId::from_bytes([3; 32]),
                &Fixture::id(&f.alice),
                Some([9; 16]),
                &wrong,
                limits(),
                &f.scope(),
                f.lease(epoch_claim(limits()).unwrap()),
                f.now
            )
            .is_err());
        }
        let (mut a, _, b, answer) = f.pending();
        let mut wrong = answer.clone();
        wrong.offer_hash[0] ^= 1;
        wrong.signature = f.bob.signing_key().sign(&wrong.signing_bytes()).to_bytes();
        assert_eq!(
            a.verify_peer_share(&wrong, f.now),
            Err(CipherError::Transcript)
        );
        drop(a.finish(&answer, f.now).unwrap());
        drop(b);
    }

    #[test]
    fn confirmation_refuses_wrong_tag_transcript_epoch_and_direction() {
        for field in 0..4 {
            let f = Fixture::new();
            let (a, offer, b, answer) = f.pending();
            let (mut a, a_confirm) = a.finish(&answer, f.now).unwrap();
            let (b, b_confirm) = b.finish(&offer, f.now).unwrap();
            let mut wrong = b_confirm.clone();
            match field {
                0 => wrong.tag[0] ^= 1,
                1 => wrong.transcript_hash[0] ^= 1,
                2 => wrong.binding.epoch[0] ^= 1,
                _ => wrong = a_confirm,
            }
            assert!(a.verify_confirmation(&wrong, f.now).is_err());
            // In particular a forged same-binding tag preserves the real epoch.
            a.verify_confirmation(&b_confirm, f.now).unwrap();
            drop(a.confirm(&b_confirm, f.now).unwrap());
            drop(b);
        }
    }

    #[test]
    fn endpoint_share_domain_and_low_order_key_are_refused() {
        let f = Fixture::new();
        let (mut a, _, b, answer) = f.pending();
        let mut wrong = answer.clone();
        let mut wrong_domain = b"myownmesh-closed-opaque-relay-key-v1:".to_vec();
        wrong_domain.extend_from_slice(&wrong.signing_bytes());
        wrong.signature = f.bob.signing_key().sign(&wrong_domain).to_bytes();
        assert_eq!(
            a.verify_peer_share(&wrong, f.now),
            Err(CipherError::Signature)
        );
        wrong = answer.clone();
        wrong.ephemeral = [0; 32];
        wrong.ephemeral[0] = 1;
        wrong.signature = f.bob.signing_key().sign(&wrong.signing_bytes()).to_bytes();
        assert_eq!(
            a.verify_peer_share(&wrong, f.now),
            Err(CipherError::Authentication)
        );
        drop(a.finish(&answer, f.now).unwrap());
        drop(b);
    }

    #[test]
    fn authenticated_bytes_reject_cross_context_destination_and_sequence_edits() {
        let f = Fixture::new();
        let (mut a, mut b) = f.ready();
        let packet = f.send(&mut a, b"exact channel body").unwrap();
        for field in 0..5 {
            let mut bad = packet.packet().clone();
            match field {
                0 => bad.binding.context[0] ^= 1,
                1 => {
                    bad.binding.responder = Identity::ephemeral()
                        .signing_key()
                        .verifying_key()
                        .to_bytes()
                }
                2 => bad.sequence += 1,
                3 => bad.binding.introduction = None,
                _ => bad.binding.version += 1,
            }
            assert!(f.receive(&mut b, &bad).is_err());
        }
        assert_eq!(
            f.receive(&mut b, packet.packet()).unwrap().bytes(),
            b"exact channel body"
        );
    }

    #[test]
    fn route_changes_reordering_and_new_epoch_do_not_reset_replay() {
        let f = Fixture::new();
        let (mut a, mut b) = f.ready();
        let first = f.send(&mut a, b"first").unwrap();
        let second = f.send(&mut a, b"second").unwrap();
        assert_eq!(
            f.receive(&mut b, second.packet()).unwrap().bytes(),
            b"second"
        );
        assert_eq!(f.receive(&mut b, first.packet()).unwrap().bytes(), b"first");
        assert!(matches!(
            f.receive(&mut b, first.packet()),
            Err(CipherError::Replay)
        ));
        for _ in 0..5 {
            let packet = f.send(&mut a, b"next").unwrap();
            f.receive(&mut b, packet.packet()).unwrap();
        }
        assert!(matches!(
            f.receive(&mut b, first.packet()),
            Err(CipherError::Replay)
        ));
        let (mut new_a, mut new_b) = f.ready();
        assert_ne!(a.binding().epoch, new_a.binding().epoch);
        assert!(matches!(
            f.receive(&mut new_b, first.packet()),
            Err(CipherError::Binding)
        ));
        let fresh = f.send(&mut new_a, b"fresh").unwrap();
        assert_eq!(fresh.packet().sequence, 1);
        assert_eq!(
            f.receive(&mut new_b, fresh.packet()).unwrap().bytes(),
            b"fresh"
        );
    }

    #[test]
    fn exhaustion_close_and_expiry_erase_keys_and_do_not_extend_lifetime() {
        let f = Fixture::new();
        let (mut a, mut b) = f.ready();
        let baseline = f.provider.in_use();
        let operation = f.operation(&mut a, 8);
        a.next_send = u64::MAX;
        assert!(matches!(
            a.seal(b"no wrap", f.now, operation),
            Err(CipherError::Exhausted)
        ));
        assert!(a.keys.iter().all(|v| *v == 0));
        assert!(matches!(
            f.send(&mut a, b"closed"),
            Err(CipherError::Closed)
        ));
        let operation = f.operation(&mut b, 8);
        assert!(matches!(
            b.seal(b"expired", f.now + limits().lifetime, operation),
            Err(CipherError::Closed)
        ));
        assert!(b.keys.iter().all(|v| *v == 0));
        assert_eq!(
            f.provider.in_use(),
            baseline,
            "rejected operations release their exact reservations"
        );
        let (a, offer, b, answer) = f.pending();
        assert!(matches!(
            a.finish(&answer, f.now + limits().lifetime),
            Err(CipherError::Closed)
        ));
        drop((b, offer));
        assert_eq!(f.provider.in_use(), baseline);
        let (a, offer, b, answer) = f.pending();
        let (a, _) = a.finish(&answer, f.now).unwrap();
        let (_, confirmation) = b.finish(&offer, f.now).unwrap();
        assert!(matches!(
            a.confirm(&confirmation, f.now + limits().lifetime),
            Err(CipherError::Closed)
        ));
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn cipher_bounds_and_funding_refuse_without_consuming_sequence() {
        let f = Fixture::new();
        let (mut a, mut b) = f.ready();
        let baseline = f.provider.in_use();
        assert!(matches!(
            f.send(&mut a, &vec![1; 1025]),
            Err(CipherError::Limit)
        ));
        assert!(matches!(
            a.operation(8, f.lease(ResourceClaim::ZERO), f.now),
            Err(CipherError::Limit)
        ));
        assert_eq!(a.next_send, 1);
        assert_eq!(f.provider.in_use(), baseline);
        let packet = f.send(&mut a, &vec![1; 1024]).unwrap();
        let operation = f.operation(&mut b, 1);
        assert!(matches!(
            b.open(packet.packet(), f.now, operation),
            Err(CipherError::Limit)
        ));
        assert!(b.replay.highest.is_none());
        assert_eq!(
            f.receive(&mut b, packet.packet()).unwrap().bytes().len(),
            1024
        );
        let mut invalid = limits();
        invalid.replay_window = 0;
        assert_eq!(epoch_claim(invalid), Err(CipherError::Limit));
        assert!(PendingEpoch::initiate(
            &f.alice,
            MeshContextId::from_bytes([3; 32]),
            &Fixture::id(&f.bob),
            None,
            limits(),
            &f.scope(),
            f.lease(ResourceClaim::ZERO),
            f.now
        )
        .is_err());
    }

    #[test]
    fn pending_requires_admitted_authority_and_exact_expected_scope() {
        let f = Fixture::new();
        let foreign = Fixture::new();
        let baseline = f.provider.in_use();
        let foreign_baseline = foreign.provider.in_use();
        for authority in [
            ResourceAuthorityClass::Cleanup,
            ResourceAuthorityClass::Speculative,
        ] {
            let funding = f
                .port
                .acquire(&f.scope(), authority, epoch_claim(limits()).unwrap())
                .unwrap();
            assert!(matches!(
                PendingEpoch::initiate(
                    &f.alice,
                    MeshContextId::from_bytes([3; 32]),
                    &Fixture::id(&f.bob),
                    None,
                    limits(),
                    &f.scope(),
                    funding,
                    f.now
                ),
                Err(CipherError::Authority)
            ));
            assert_eq!(f.provider.in_use(), baseline);
        }
        let funding = foreign.lease(epoch_claim(limits()).unwrap());
        assert!(matches!(
            PendingEpoch::initiate(
                &f.alice,
                MeshContextId::from_bytes([3; 32]),
                &Fixture::id(&f.bob),
                None,
                limits(),
                &f.scope(),
                funding,
                f.now
            ),
            Err(CipherError::Scope)
        ));
        assert_eq!(foreign.provider.in_use(), foreign_baseline);
        let child = f.port.create_scope(&f.scope()).unwrap();
        let funding = f
            .port
            .acquire(
                &child,
                ResourceAuthorityClass::Admitted,
                epoch_claim(limits()).unwrap(),
            )
            .unwrap();
        assert!(matches!(
            PendingEpoch::initiate(
                &f.alice,
                MeshContextId::from_bytes([3; 32]),
                &Fixture::id(&f.bob),
                None,
                limits(),
                &f.scope(),
                funding,
                f.now
            ),
            Err(CipherError::Scope)
        ));
        drop(child);
        assert_eq!(f.provider.in_use(), baseline);
        let (a, _, b, _) = f.pending();
        drop((a, b));
        assert_eq!(f.provider.in_use(), baseline);
        let (a, offer) = PendingEpoch::initiate(
            &f.alice,
            MeshContextId::from_bytes([3; 32]),
            &Fixture::id(&f.bob),
            None,
            limits(),
            &f.scope(),
            f.lease(epoch_claim(limits()).unwrap()),
            f.now,
        )
        .unwrap();
        let with_offer = f.provider.in_use();
        for authority in [
            ResourceAuthorityClass::Cleanup,
            ResourceAuthorityClass::Speculative,
        ] {
            let funding = f
                .port
                .acquire(&f.scope(), authority, epoch_claim(limits()).unwrap())
                .unwrap();
            assert!(matches!(
                PendingEpoch::respond(
                    &f.bob,
                    MeshContextId::from_bytes([3; 32]),
                    &Fixture::id(&f.alice),
                    None,
                    &offer,
                    limits(),
                    &f.scope(),
                    funding,
                    f.now
                ),
                Err(CipherError::Authority)
            ));
            assert_eq!(f.provider.in_use(), with_offer);
        }
        assert!(matches!(
            PendingEpoch::respond(
                &f.bob,
                MeshContextId::from_bytes([3; 32]),
                &Fixture::id(&f.alice),
                None,
                &offer,
                limits(),
                &f.scope(),
                foreign.lease(epoch_claim(limits()).unwrap()),
                f.now
            ),
            Err(CipherError::Scope)
        ));
        assert_eq!(foreign.provider.in_use(), foreign_baseline);
        assert_eq!(f.provider.in_use(), with_offer);
        drop(a);
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn work_rejects_wrong_authority_scope_and_epoch_without_state_mutation() {
        let f = Fixture::new();
        let foreign = Fixture::new();
        let (mut a, mut b) = f.ready();
        let baseline = f.provider.in_use();
        for authority in [
            ResourceAuthorityClass::Cleanup,
            ResourceAuthorityClass::Speculative,
        ] {
            let lease = f
                .port
                .acquire(&f.scope(), authority, data_work_claim(8).unwrap())
                .unwrap();
            assert!(matches!(
                a.operation(8, lease, f.now),
                Err(CipherError::Authority)
            ));
        }
        assert!(matches!(
            a.operation(8, foreign.lease(data_work_claim(8).unwrap()), f.now),
            Err(CipherError::Scope)
        ));
        let operation = f.operation(&mut b, 8);
        assert!(matches!(
            a.seal(b"foreign", f.now, operation),
            Err(CipherError::OperationOwner)
        ));
        assert_eq!(a.next_send, 1);
        assert!(b.replay.highest.is_none());
        assert_eq!(f.provider.in_use(), baseline);
        let packet = f.send(&mut a, b"body").unwrap();
        let before = f.provider.in_use();
        let operation = f.operation(&mut a, 8);
        assert!(matches!(
            b.open(packet.packet(), f.now, operation),
            Err(CipherError::OperationOwner)
        ));
        assert!(b.replay.highest.is_none());
        assert_eq!(f.provider.in_use(), before);
        assert_eq!(f.receive(&mut b, packet.packet()).unwrap().bytes(), b"body");
    }

    #[test]
    fn owned_outputs_hold_exact_funding_through_borrow_and_release_on_drop() {
        let f = Fixture::new();
        let (mut a, mut b) = f.ready();
        let baseline = f.provider.in_use();
        let claim = data_work_claim(8).unwrap();
        let charged = FiniteResourceProvider::reservation_planning_charge(claim).unwrap();
        let operation = f.operation(&mut a, 8);
        assert_eq!(f.provider.in_use(), baseline.checked_add(charged).unwrap());
        // Cancellation consumes no cipher sequence and drops only this lease.
        drop(operation);
        assert_eq!(a.next_send, 1);
        assert_eq!(f.provider.in_use(), baseline);
        let operation = f.operation(&mut a, 8);
        let packet = a.seal(b"private", f.now, operation).unwrap();
        assert_eq!(f.provider.in_use(), baseline.checked_add(charged).unwrap());
        let operation = f.operation(&mut b, 8);
        let plaintext = b.open(packet.packet(), f.now, operation).unwrap();
        assert_eq!(plaintext.bytes(), b"private");
        assert_eq!(
            f.provider.in_use(),
            baseline
                .checked_add(charged.checked_scale(2).unwrap())
                .unwrap()
        );
        drop(packet);
        assert_eq!(plaintext.bytes(), b"private");
        assert_eq!(f.provider.in_use(), baseline.checked_add(charged).unwrap());
        drop(plaintext);
        assert_eq!(f.provider.in_use(), baseline);
        let operation = f.operation(&mut a, 8);
        a.close();
        assert!(matches!(
            a.seal(b"closed", f.now, operation),
            Err(CipherError::Closed)
        ));
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn mapped_wire_output_retains_epoch_and_operation_until_terminal_drop() {
        let f = Fixture::new();
        let baseline = f.provider.in_use();
        let (mut a, b) = f.ready();
        let outer = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, 1024),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .unwrap();
        let complete = data_work_claim(8).unwrap().checked_add(outer).unwrap();
        let operation = a.operation(8, f.lease(complete), f.now).unwrap();
        let packet = a.seal(b"private", f.now, operation).unwrap();
        let wire = packet
            .try_map(outer, |packet| {
                serde_json::to_vec(packet).map_err(|_| CipherError::Limit)
            })
            .unwrap();
        assert!(wire.value().len() <= 1024);
        drop((a, b));
        let epoch_charge =
            FiniteResourceProvider::reservation_planning_charge(epoch_claim(limits()).unwrap())
                .unwrap();
        let operation_charge =
            FiniteResourceProvider::reservation_planning_charge(complete).unwrap();
        assert_eq!(
            f.provider.in_use(),
            baseline
                .checked_add(epoch_charge)
                .unwrap()
                .checked_add(operation_charge)
                .unwrap(),
            "native/queue guard retains its exact epoch stamp charge after key owner drops"
        );
        assert!(!wire.value().is_empty());
        drop(wire);
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn mapping_refuses_before_allocation_and_releases_on_builder_error() {
        let f = Fixture::new();
        let (mut a, _) = f.ready();
        let baseline = f.provider.in_use();
        let packet = f.send(&mut a, b"body").unwrap();
        let called = std::cell::Cell::new(false);
        let result = packet.try_map(
            ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 1),
            |_| {
                called.set(true);
                Ok(())
            },
        );
        assert!(matches!(result, Err(CipherError::Limit)));
        assert!(!called.get());
        assert_eq!(f.provider.in_use(), baseline);
        let packet = f.send(&mut a, b"body").unwrap();
        let result = packet.try_map::<()>(ResourceClaim::ZERO, |_| Err(CipherError::Binding));
        assert!(matches!(result, Err(CipherError::Binding)));
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn shared_aes256_gcm_empty_message_vector_is_stable() {
        // AES-256-GCM, all-zero 256-bit key and 96-bit IV, empty AAD/message.
        // This fixed expected tag pins shared primitive output independently
        // of the endpoint round-trip and the Closed relay adapter.
        let expected = hex::decode("530f8afbc74536b9a963b4f1c4cb738b").unwrap();
        let ciphertext = encrypt(&[0; 32], &[0; 12], &[], &[]).unwrap();
        assert_eq!(ciphertext, expected);
        assert!(decrypt(&[0; 32], &[0; 12], &[], &ciphertext)
            .unwrap()
            .is_empty());
        let mut tampered = ciphertext;
        tampered[0] ^= 1;
        assert_eq!(
            decrypt(&[0; 32], &[0; 12], &[], &tampered),
            Err(CipherError::Authentication)
        );
    }
}
