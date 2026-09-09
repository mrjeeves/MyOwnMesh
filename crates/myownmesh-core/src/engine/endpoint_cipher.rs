//! One network-local endpoint cipher registry; not authentication or membership.
//!
//! Caller holds the canonical graph admission fence before entering this
//! synchronous controller. Publication invalidates subjects under graph.write.
//! No carrier identity, peer lookup, graph callback, payload queue or await is
//! owned here. A Hub leg change does not touch an endpoint epoch.
//!
//! Output access/mapping is an INTERNAL FINITE-CENSUS seam. Borrowed values can
//! be cloned; builders must not publish escaped copies, including on Err or
//! unwind. Caller prices all clone/wire/queue peaks before construction and
//! keeps the returned guard through the actual terminal queue/native owner.

use std::collections::BTreeSet;
use std::mem::size_of;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use ed25519_dalek::{Signature, VerifyingKey};
use tokio::sync::Notify;

use crate::config::EndpointCipherPolicyConfig;
use crate::identity::Identity;
use crate::protocol::endpoint_cipher::{
    CipherError, CiphertextPacket, EpochBinding, KeyConfirmation, KeyShare, AEAD_TAG_BYTES,
    MAX_KEY_SHARE_SIGNING_BYTES,
};
use crate::protocol::topology::EndpointCipherControl;
use crate::resource::{
    FundedArc, LeasedMap, LocalApplicationResourceScope, ResourceClaim, ResourceClass,
    ResourceLease, ResourceScope,
};
use crate::runtime::endpoint_cipher::{
    self as primitive, CipherLimits, ConfirmingEpoch, FundedCipherOutput, FundedCiphertext,
    FundedPlaintext, PendingEpoch, ReadyEpoch,
};
use crate::semantic::{DeviceId, MeshContextId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub(crate) enum ControllerError {
    #[error("endpoint cipher policy or coordinate refused")]
    Invalid,
    #[error("endpoint cipher resource pressure")]
    Pressure,
    #[error("endpoint cipher capacity refused")]
    Capacity,
    #[error("endpoint cipher exact epoch is stale")]
    Stale,
    #[error("endpoint cipher handshake is not ready")]
    Phase,
    #[error("endpoint cipher competing epoch refused")]
    Glare,
    #[error("endpoint cipher controller is shut down")]
    Shutdown,
    #[error(transparent)]
    Cipher(#[from] CipherError),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum CipherPhase {
    Pending = 0,
    Confirming = 1,
    Ready = 2,
    Retired = 3,
}

struct RootIdentity {
    scope: ResourceScope,
    waiters: AtomicUsize,
}

struct EpochSignal {
    root: FundedArc<RootIdentity>,
    generation: u64,
    peer: [u8; 32],
    binding: EpochBinding,
    deadline: Instant,
    phase: AtomicU8,
    notification: Notify,
}

impl EpochSignal {
    fn set(&self, phase: CipherPhase) {
        self.phase.store(phase as u8, Ordering::Release);
        self.notification.notify_waiters();
    }
    fn phase(&self, now: Instant) -> CipherPhase {
        if now >= self.deadline {
            return CipherPhase::Retired;
        }
        match self.phase.load(Ordering::Acquire) {
            0 => CipherPhase::Pending,
            1 => CipherPhase::Confirming,
            2 => CipherPhase::Ready,
            _ => CipherPhase::Retired,
        }
    }
}

/// Crate-private correlation, NEVER policy authority. Clones retain shared
/// backing, but callers must fund their own containing command/waiter storage.
#[derive(Clone)]
pub(crate) struct EpochTicket {
    signal: FundedArc<EpochSignal>,
}
impl EpochTicket {
    pub(crate) fn binding(&self) -> &EpochBinding {
        &self.signal.binding
    }
    pub(crate) fn peer_key(&self) -> [u8; 32] {
        self.signal.peer
    }
    pub(crate) fn generation(&self) -> u64 {
        self.signal.generation
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.signal.deadline
    }
    pub(crate) fn phase(&self, now: Instant) -> CipherPhase {
        self.signal.phase(now)
    }
}

/// No waiter registration list in the controller. Cap is max_sessions globally
/// per root (not per route). The owned caller must pin/enable notification BEFORE
/// checking phase, then wait outside locks under deadline(), and drop on cancel.
pub(crate) struct ReadinessWaiter {
    ticket: EpochTicket,
    _work: ResourceLease,
}
impl ReadinessWaiter {
    pub(crate) fn ticket(&self) -> &EpochTicket {
        &self.ticket
    }
    pub(crate) fn deadline(&self) -> Instant {
        self.ticket.deadline()
    }
    pub(crate) fn phase(&self, now: Instant) -> CipherPhase {
        self.ticket.phase(now)
    }
    pub(crate) fn notification(&self) -> &Notify {
        &self.ticket.signal.notification
    }
}
impl Drop for ReadinessWaiter {
    fn drop(&mut self) {
        self.ticket
            .signal
            .root
            .waiters
            .fetch_sub(1, Ordering::AcqRel);
    }
}

// Boxed phase backing is paid by primitive::epoch_claim (max state size).
// Map node prices only these pointers/tag, caches and signal handle. Moving a
// phase out of its box frees that backing before allocating the next box.
enum Phase {
    Pending(Box<PendingEpoch>),
    Confirming(Box<ConfirmingEpoch>),
    Ready(Box<ReadyEpoch>),
    Transition,
}
struct Record {
    phase: Phase,
    signal: FundedArc<EpochSignal>,
    local_share: KeyShare,
    peer_share: Option<KeyShare>,
    local_confirmation: Option<KeyConfirmation>,
    peer_confirmation: Option<KeyConfirmation>,
}
impl Drop for Record {
    fn drop(&mut self) {
        self.signal.set(CipherPhase::Retired);
    }
}

pub(crate) struct ControlFrames {
    pub(crate) first: EndpointCipherControl,
    pub(crate) second: Option<EndpointCipherControl>,
}
impl ControlFrames {
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn iter(&self) -> impl Iterator<Item = &EndpointCipherControl> {
        std::iter::once(&self.first).chain(self.second.iter())
    }
}
pub(crate) struct ControlOutput {
    frames: ControlFrames,
    ticket: EpochTicket,
    work: ResourceLease,
}
impl ControlOutput {
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn frames(&self) -> &ControlFrames {
        &self.frames
    }
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn ticket(&self) -> &EpochTicket {
        &self.ticket
    }
    /// Pure, finite-census builder only. Full outer claim was acquired before
    /// these frame clones; no callback-owned storage may escape on error.
    pub(crate) fn try_map<T>(
        self,
        build: impl FnOnce(&ControlFrames) -> Result<T, ControllerError>,
    ) -> Result<PreparedOutput<T>, ControllerError> {
        let value = build(&self.frames)?;
        Ok(PreparedOutput {
            storage: PreparedStorage::Control {
                value,
                _work: self.work,
            },
            ticket: self.ticket,
        })
    }
}

pub(crate) struct SealedOutput {
    cipher: FundedCiphertext,
    ticket: EpochTicket,
    outer: ResourceClaim,
}
impl SealedOutput {
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn packet(&self) -> &CiphertextPacket {
        self.cipher.packet()
    }
    pub(crate) fn try_map<T>(
        self,
        build: impl FnOnce(&CiphertextPacket) -> Result<T, CipherError>,
    ) -> Result<PreparedOutput<T>, ControllerError> {
        let value = self.cipher.try_map(self.outer, build)?;
        Ok(PreparedOutput {
            storage: PreparedStorage::Cipher(value),
            ticket: self.ticket,
        })
    }
}

enum PreparedStorage<T> {
    Control { value: T, _work: ResourceLease },
    Cipher(FundedCipherOutput<T>),
}
/// Move this complete guard into the actual command/queue owner, not a cloned
/// value(). Work admitted under the caller's graph fence may settle afterwards;
/// it never authorizes a fresh operation on a retired ticket or an uncertain retry.
pub(crate) struct PreparedOutput<T> {
    storage: PreparedStorage<T>,
    ticket: EpochTicket,
}
impl<T> PreparedOutput<T> {
    pub(crate) fn value(&self) -> &T {
        match &self.storage {
            PreparedStorage::Control { value, .. } => value,
            PreparedStorage::Cipher(value) => value.value(),
        }
    }
    pub(crate) fn ticket(&self) -> &EpochTicket {
        &self.ticket
    }
}

pub(crate) struct OpenedOutput {
    plaintext: FundedPlaintext,
    _ticket: EpochTicket,
}
impl OpenedOutput {
    pub(crate) fn bytes(&self) -> &[u8] {
        self.plaintext.bytes()
    }
}

pub(crate) struct ControlUpdate {
    pub(crate) ticket: EpochTicket,
    pub(crate) output: Option<ControlOutput>,
}
pub(crate) struct EpochObservation {
    pub(crate) ticket: EpochTicket,
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) phase: CipherPhase,
    pub(crate) max_plaintext_bytes: Option<usize>,
}

pub(crate) struct EndpointCipherController {
    records: LeasedMap<[u8; 32], Record>,
    resources: LocalApplicationResourceScope,
    root: FundedArc<RootIdentity>,
    policy: EndpointCipherPolicyConfig,
    limits: CipherLimits,
    context: MeshContextId,
    local: [u8; 32],
    generation: u64,
    count: usize,
    cursor: Option<[u8; 32]>,
    stopped: bool,
}

fn memory(bytes: usize, allocations: u64) -> Result<ResourceClaim, ControllerError> {
    ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| ControllerError::Invalid)?,
        ),
        (ResourceClass::OpaqueDependencyResidual, allocations),
    ])
    .map_err(|_| ControllerError::Invalid)
}
fn add(a: ResourceClaim, b: ResourceClaim) -> Result<ResourceClaim, ControllerError> {
    a.checked_add(b).map_err(|_| ControllerError::Invalid)
}
fn shared_bytes<T>() -> usize {
    size_of::<T>() + size_of::<ResourceLease>() + 4 * size_of::<usize>()
}
// Return across a function boundary so the old box allocation is destroyed
// before the caller can allocate successor phase backing under the same lease.
#[allow(clippy::boxed_local)] // The funded phase box must be freed at this boundary.
fn unbox<T>(value: Box<T>) -> T {
    *value
}

impl EndpointCipherController {
    pub(crate) fn root_claim() -> Result<ResourceClaim, ControllerError> {
        memory(size_of::<Self>() + shared_bytes::<RootIdentity>(), 2)
    }
    pub(crate) fn entry_claim() -> Result<ResourceClaim, ControllerError> {
        // Additional box allocation residual only: its state bytes are already
        // in epoch_claim, never charge inline whole-epoch storage again.
        add(
            LeasedMap::<[u8; 32], Record>::entry_claim().map_err(|_| ControllerError::Invalid)?,
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1),
        )
    }
    pub(crate) fn signal_claim() -> Result<ResourceClaim, ControllerError> {
        memory(shared_bytes::<EpochSignal>(), 2)
    }
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn epoch_claim(
        policy: EndpointCipherPolicyConfig,
    ) -> Result<ResourceClaim, ControllerError> {
        Ok(primitive::epoch_claim(Self::limits(policy)?)?)
    }
    /// Planning ONLY, never acquired as a second runtime lease. Signal has its
    /// own allocation lifetime, so its separate reservation must be counted;
    /// combining raw entry+signal and wrapping once would omit one record.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn planned_retention_claim(
        policy: EndpointCipherPolicyConfig,
    ) -> Result<ResourceClaim, ControllerError> {
        use crate::resource::FiniteResourceProvider;
        let epoch = Self::epoch_claim(policy)?;
        let charge = |raw| {
            FiniteResourceProvider::reservation_planning_charge(raw)
                .map_err(|_| ControllerError::Invalid)
        };
        let per = add(
            add(
                charge(Self::entry_claim()?)?,
                charge(Self::signal_claim()?)?,
            )?,
            charge(epoch)?,
        )?;
        add(
            charge(Self::root_claim()?)?,
            per.checked_scale(policy.max_sessions)
                .map_err(|_| ControllerError::Invalid)?,
        )
    }
    pub(crate) fn waiter_claim() -> Result<ResourceClaim, ControllerError> {
        memory(
            size_of::<ReadinessWaiter>() + size_of::<tokio::sync::futures::Notified<'static>>(),
            1,
        )
    }
    pub(crate) fn control_work_claim(
        outer: ResourceClaim,
    ) -> Result<ResourceClaim, ControllerError> {
        add(
            memory(size_of::<ControlOutput>() + MAX_KEY_SHARE_SIGNING_BYTES, 0)?,
            outer,
        )
    }
    pub(crate) fn data_work_claim(
        len: usize,
        outer: ResourceClaim,
    ) -> Result<ResourceClaim, ControllerError> {
        add(
            add(primitive::data_work_claim(len)?, outer)?,
            memory(
                size_of::<EpochTicket>() + size_of::<ResourceClaim>() + size_of::<usize>(),
                0,
            )?,
        )
    }
    fn limits(policy: EndpointCipherPolicyConfig) -> Result<CipherLimits, ControllerError> {
        policy.checked().map_err(|_| ControllerError::Invalid)?;
        let limits = CipherLimits {
            max_plaintext_bytes: usize::try_from(policy.max_plaintext_bytes)
                .map_err(|_| ControllerError::Invalid)?,
            replay_window: usize::try_from(policy.replay_window)
                .map_err(|_| ControllerError::Invalid)?,
            lifetime: Duration::from_millis(policy.max_age_ms),
        };
        limits.validate()?;
        Ok(limits)
    }
    pub(crate) fn new(
        policy: EndpointCipherPolicyConfig,
        resources: LocalApplicationResourceScope,
        context: MeshContextId,
        local: &DeviceId,
    ) -> Result<Self, ControllerError> {
        let limits = Self::limits(policy)?;
        let lease = resources
            .acquire(Self::root_claim()?)
            .map_err(|_| ControllerError::Pressure)?;
        let root = FundedArc::new(
            RootIdentity {
                scope: lease.scope(),
                waiters: AtomicUsize::new(0),
            },
            lease,
        )
        .map_err(|_| ControllerError::Invalid)?;
        Ok(Self {
            records: LeasedMap::new(),
            resources,
            root,
            policy,
            limits,
            context,
            local: local.as_bytes(),
            generation: 0,
            count: 0,
            cursor: None,
            stopped: false,
        })
    }
    fn acquire(&self, claim: ResourceClaim) -> Result<ResourceLease, ControllerError> {
        self.resources
            .acquire(claim)
            .map_err(|_| ControllerError::Pressure)
    }
    fn identity(&self, identity: &Identity, peer: &DeviceId) -> Result<(), ControllerError> {
        if self.stopped {
            return Err(ControllerError::Shutdown);
        }
        if identity.signing_key().verifying_key().to_bytes() != self.local
            || peer.as_bytes() == self.local
        {
            return Err(ControllerError::Invalid);
        }
        Ok(())
    }
    fn incoming(
        &self,
        peer: &DeviceId,
        binding: &EpochBinding,
        sender: [u8; 32],
    ) -> Result<(), ControllerError> {
        binding.validate()?;
        if binding.context != *self.context.as_bytes()
            || sender != peer.as_bytes()
            || binding.destination(&sender)? != self.local
        {
            return Err(ControllerError::Invalid);
        }
        Ok(())
    }
    fn check(&self, ticket: &EpochTicket, now: Instant) -> Result<(), ControllerError> {
        if self.stopped {
            return Err(ControllerError::Shutdown);
        }
        if !FundedArc::ptr_eq(&self.root, &ticket.signal.root)
            || ticket.phase(now) == CipherPhase::Retired
        {
            return Err(ControllerError::Stale);
        }
        let record = self
            .records
            .get(&ticket.signal.peer)
            .ok_or(ControllerError::Stale)?;
        if !FundedArc::ptr_eq(&record.signal, &ticket.signal) {
            return Err(ControllerError::Stale);
        }
        Ok(())
    }
    pub(crate) fn current(&self, ticket: &EpochTicket, now: Instant) -> bool {
        self.check(ticket, now).is_ok()
    }
    /// Physical retention, including expired records awaiting bounded reap.
    /// This is a lab seed/refusal predicate, never endpoint policy authority.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn has_epochs(&self) -> bool {
        self.count != 0
    }
    pub(crate) fn observe(&self, peer: &DeviceId, now: Instant) -> Option<EpochObservation> {
        let record = self.records.get(&peer.as_bytes())?;
        let phase = record.signal.phase(now);
        let max = if phase == CipherPhase::Ready {
            match &record.phase {
                Phase::Ready(epoch) => Some(epoch.max_plaintext_bytes()),
                _ => None,
            }
        } else {
            None
        };
        Some(EpochObservation {
            ticket: EpochTicket {
                signal: record.signal.clone(),
            },
            #[cfg(all(test, feature = "transport-lab"))]
            phase,
            max_plaintext_bytes: max,
        })
    }
    pub(crate) fn waiter(
        &self,
        ticket: &EpochTicket,
        now: Instant,
    ) -> Result<ReadinessWaiter, ControllerError> {
        self.check(ticket, now)?;
        let work = self.acquire(Self::waiter_claim()?)?;
        let cap =
            usize::try_from(self.policy.max_sessions).map_err(|_| ControllerError::Invalid)?;
        self.root
            .waiters
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value < cap {
                    value.checked_add(1)
                } else {
                    None
                }
            })
            .map_err(|_| ControllerError::Capacity)?;
        Ok(ReadinessWaiter {
            ticket: ticket.clone(),
            _work: work,
        })
    }
    fn remove(&mut self, peer: &[u8; 32]) -> bool {
        if let Some(record) = self.records.remove(peer) {
            self.count -= 1;
            drop(record); // retirement notifies; all key backing drops here
            true
        } else {
            false
        }
    }
    pub(crate) fn retire(&mut self, ticket: &EpochTicket) -> bool {
        if !FundedArc::ptr_eq(&self.root, &ticket.signal.root) {
            return false;
        }
        let matches = self
            .records
            .get(&ticket.signal.peer)
            .map(|record| FundedArc::ptr_eq(&record.signal, &ticket.signal))
            .unwrap_or(false);
        matches && self.remove(&ticket.signal.peer)
    }
    pub(crate) fn retire_all(&mut self) {
        while let Some((key, _)) = self.records.successor_after(None) {
            let key = *key;
            self.remove(&key);
        }
        self.cursor = None;
    }
    pub(crate) fn shutdown(&mut self) {
        self.stopped = true;
        self.retire_all();
    }
    /// Traverses the caller's already-retained finite affected set once. At
    /// most max_sessions removals; no DeviceId reconstruction/interning, graph
    /// lookup, new subject collection or callback allocation under graph.write.
    pub(crate) fn invalidate_subjects(&mut self, subjects: &BTreeSet<DeviceId>) {
        for subject in subjects {
            if self.count == 0 {
                break;
            }
            let key = subject.as_bytes();
            if key == self.local {
                self.retire_all();
                return;
            }
            self.remove(&key);
        }
    }
    /// At most min(scan_budget,max_sessions) records, with a persistent ordered
    /// cursor; logical use checks expiry even before physical maintenance.
    pub(crate) fn expire(&mut self, now: Instant, scan_budget: usize) -> usize {
        let cap = self.count.min(scan_budget);
        let mut removed = 0;
        for _ in 0..cap {
            let next = self
                .records
                .successor_after(self.cursor.as_ref())
                .or_else(|| self.records.successor_after(None))
                .map(|(key, record)| (*key, record.signal.deadline));
            let Some((key, deadline)) = next else {
                self.cursor = None;
                break;
            };
            self.cursor = Some(key);
            if now >= deadline && self.remove(&key) {
                removed += 1;
            }
        }
        removed
    }
    fn expire_peer(&mut self, peer: &[u8; 32], now: Instant) {
        if self
            .records
            .get(peer)
            .map(|r| now >= r.signal.deadline)
            .unwrap_or(false)
        {
            self.remove(peer);
        }
    }
    fn make_record(
        &self,
        identity: &Identity,
        peer: &DeviceId,
        intro: Option<[u8; 16]>,
        offer: Option<&KeyShare>,
        now: Instant,
    ) -> Result<(Record, ResourceLease), ControllerError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(ControllerError::Capacity)?;
        let entry = self.acquire(Self::entry_claim()?)?;
        let signal_lease = self.acquire(Self::signal_claim()?)?;
        let epoch_lease = self.acquire(primitive::epoch_claim(self.limits)?)?;
        let (pending, share) = if let Some(offer) = offer {
            PendingEpoch::respond(
                identity,
                self.context,
                peer,
                intro,
                offer,
                self.limits,
                &self.root.scope,
                epoch_lease,
                now,
            )?
        } else {
            PendingEpoch::initiate(
                identity,
                self.context,
                peer,
                intro,
                self.limits,
                &self.root.scope,
                epoch_lease,
                now,
            )?
        };
        let deadline = now
            .checked_add(self.limits.lifetime)
            .ok_or(ControllerError::Invalid)?;
        let signal = FundedArc::new(
            EpochSignal {
                root: self.root.clone(),
                generation,
                peer: peer.as_bytes(),
                binding: share.binding.clone(),
                deadline,
                phase: AtomicU8::new(CipherPhase::Pending as u8),
                notification: Notify::new(),
            },
            signal_lease,
        )
        .map_err(|_| ControllerError::Invalid)?;
        let mut record = Record {
            phase: Phase::Pending(Box::new(pending)),
            signal,
            local_share: share,
            peer_share: None,
            local_confirmation: None,
            peer_confirmation: None,
        };
        if let Some(offer) = offer {
            Self::finish_share(&mut record, offer, now)?;
        }
        Ok((record, entry))
    }
    fn install(
        &mut self,
        peer: [u8; 32],
        record: Record,
        entry: ResourceLease,
    ) -> Result<EpochTicket, ControllerError> {
        let ticket = EpochTicket {
            signal: record.signal.clone(),
        };
        self.records
            .insert(peer, record, entry)
            .map_err(|_| ControllerError::Stale)?;
        self.generation = ticket.generation();
        self.count += 1;
        Ok(ticket)
    }
    fn response(record: &Record, work: ResourceLease) -> ControlOutput {
        // Bounded signed controls only. All clones occur after control-work
        // admission; cached copies remain inside the separately funded map.
        let first = if record.local_share.sender == record.local_share.binding.responder {
            EndpointCipherControl::Share(record.local_share.clone())
        } else if let Some(confirmation) = &record.local_confirmation {
            EndpointCipherControl::Confirmation(confirmation.clone())
        } else {
            EndpointCipherControl::Share(record.local_share.clone())
        };
        let second = if record.local_share.sender == record.local_share.binding.responder {
            record
                .local_confirmation
                .clone()
                .map(EndpointCipherControl::Confirmation)
        } else {
            None
        };
        ControlOutput {
            frames: ControlFrames { first, second },
            ticket: EpochTicket {
                signal: record.signal.clone(),
            },
            work,
        }
    }
    pub(crate) fn begin(
        &mut self,
        identity: &Identity,
        peer: &DeviceId,
        intro: Option<[u8; 16]>,
        outer: ResourceClaim,
        now: Instant,
    ) -> Result<ControlUpdate, ControllerError> {
        self.identity(identity, peer)?;
        self.expire_peer(&peer.as_bytes(), now);
        if let Some(record) = self.records.get(&peer.as_bytes()) {
            if record.local_share.binding.introduction != intro {
                return Err(ControllerError::Glare);
            }
            return Ok(ControlUpdate {
                ticket: EpochTicket {
                    signal: record.signal.clone(),
                },
                output: None,
            });
        }
        if self.count as u64 >= self.policy.max_sessions {
            return Err(ControllerError::Capacity);
        }
        let work = self.acquire(Self::control_work_claim(outer)?)?;
        let (record, entry) = self.make_record(identity, peer, intro, None, now)?;
        let output = Self::response(&record, work);
        let ticket = self.install(peer.as_bytes(), record, entry)?;
        Ok(ControlUpdate {
            ticket,
            output: Some(output),
        })
    }
    /// Explicit local rekey. Fully funds/builds the new offer BEFORE retiring
    /// the old exact epoch. Remote unsolicited offers cannot replace Ready.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn rekey(
        &mut self,
        identity: &Identity,
        peer: &DeviceId,
        ticket: &EpochTicket,
        intro: Option<[u8; 16]>,
        outer: ResourceClaim,
        now: Instant,
    ) -> Result<ControlUpdate, ControllerError> {
        self.check(ticket, now)?;
        if peer.as_bytes() != ticket.peer_key() {
            return Err(ControllerError::Invalid);
        }
        self.identity(identity, peer)?;
        let work = self.acquire(Self::control_work_claim(outer)?)?;
        let (record, entry) = self.make_record(identity, peer, intro, None, now)?;
        let output = Self::response(&record, work);
        self.retire(ticket);
        let ticket = self.install(peer.as_bytes(), record, entry)?;
        Ok(ControlUpdate {
            ticket,
            output: Some(output),
        })
    }
    fn finish_share(
        record: &mut Record,
        share: &KeyShare,
        now: Instant,
    ) -> Result<(), ControllerError> {
        let Phase::Pending(epoch) = &mut record.phase else {
            return Err(ControllerError::Phase);
        };
        epoch.verify_peer_share(share, now)?;
        let Phase::Pending(epoch) = std::mem::replace(&mut record.phase, Phase::Transition) else {
            unreachable!()
        };
        let pending = unbox(epoch);
        let (confirming, confirmation) = pending.finish(share, now)?;
        record.phase = Phase::Confirming(Box::new(confirming));
        record.peer_share = Some(share.clone());
        record.local_confirmation = Some(confirmation);
        record.signal.set(CipherPhase::Confirming);
        Ok(())
    }
    pub(crate) fn receive_control(
        &mut self,
        identity: &Identity,
        peer: &DeviceId,
        control: &EndpointCipherControl,
        outer: ResourceClaim,
        now: Instant,
    ) -> Result<ControlUpdate, ControllerError> {
        self.identity(identity, peer)?;
        self.incoming(peer, control.binding(), control.sender())?;
        let work = self.acquire(Self::control_work_claim(outer)?)?;
        control.validate()?;
        // Authenticate before comparing glare keys or removing any predecessor.
        if let EndpointCipherControl::Share(share) = control {
            VerifyingKey::from_bytes(&share.sender)
                .map_err(|_| CipherError::Signature)?
                .verify_strict(
                    &share.signing_bytes(),
                    &Signature::from_bytes(&share.signature),
                )
                .map_err(|_| CipherError::Signature)?;
        }
        self.expire_peer(&peer.as_bytes(), now);
        let existing = self.records.get(&peer.as_bytes());
        let same = existing
            .map(|r| r.local_share.binding == *control.binding())
            .unwrap_or(false);
        if !same {
            let EndpointCipherControl::Share(offer) = control else {
                return Err(ControllerError::Stale);
            };
            if offer.sender != offer.binding.initiator {
                return Err(ControllerError::Stale);
            }
            if let Some(old) = existing {
                let local_pending = matches!(old.phase, Phase::Pending(_))
                    && old.local_share.sender == old.local_share.binding.initiator;
                if !local_pending || offer.binding.initiator >= self.local {
                    return Err(ControllerError::Glare);
                }
            } else if self.count as u64 >= self.policy.max_sessions {
                return Err(ControllerError::Capacity);
            }
            // Even a winning signed low-order offer must finish verification
            // and fund a replacement before it may retire the legitimate loser.
            let (record, entry) =
                self.make_record(identity, peer, offer.binding.introduction, Some(offer), now)?;
            let output = Self::response(&record, work);
            self.remove(&peer.as_bytes());
            let ticket = self.install(peer.as_bytes(), record, entry)?;
            return Ok(ControlUpdate {
                ticket,
                output: Some(output),
            });
        }
        let record = self
            .records
            .get_mut(&peer.as_bytes())
            .ok_or(ControllerError::Stale)?;
        let result = match control {
            EndpointCipherControl::Share(share) => {
                if let Some(prior) = &record.peer_share {
                    if prior != share {
                        return Err(ControllerError::Glare);
                    }
                } else if let Err(error) = Self::finish_share(record, share, now) {
                    if matches!(record.phase, Phase::Transition) {
                        self.remove(&peer.as_bytes());
                    }
                    return Err(error);
                }
                Ok(Some(Self::response(record, work)))
            }
            EndpointCipherControl::Confirmation(confirmation) => {
                if let Some(prior) = &record.peer_confirmation {
                    if prior != confirmation {
                        return Err(ControllerError::Phase);
                    }
                    Ok(None)
                } else {
                    let Phase::Confirming(epoch) = &mut record.phase else {
                        return Err(ControllerError::Phase);
                    };
                    epoch.verify_confirmation(confirmation, now)?;
                    let Phase::Confirming(epoch) =
                        std::mem::replace(&mut record.phase, Phase::Transition)
                    else {
                        unreachable!()
                    };
                    let confirming = unbox(epoch);
                    match confirming.confirm(confirmation, now) {
                        Ok(ready) => {
                            record.phase = Phase::Ready(Box::new(ready));
                            record.peer_confirmation = Some(confirmation.clone());
                            record.signal.set(CipherPhase::Ready);
                            Ok(None)
                        }
                        Err(error) => Err(ControllerError::Cipher(error)),
                    }
                }
            }
        };
        // Normal adversarial refusals returned before phase consumption above.
        // Unexpected post-validation crypto failure permanently retires rather
        // than leaving a keyless Transition entry that appears live.
        if matches!(record.phase, Phase::Transition) {
            self.remove(&peer.as_bytes());
            return Err(result.err().unwrap_or(ControllerError::Phase));
        }
        let ticket = EpochTicket {
            signal: record.signal.clone(),
        };
        Ok(ControlUpdate {
            ticket,
            output: result?,
        })
    }
    pub(crate) fn seal(
        &mut self,
        ticket: &EpochTicket,
        plaintext: &[u8],
        outer: ResourceClaim,
        now: Instant,
    ) -> Result<SealedOutput, ControllerError> {
        self.check(ticket, now)?;
        let record = self
            .records
            .get(&ticket.peer_key())
            .ok_or(ControllerError::Stale)?;
        let Phase::Ready(epoch) = &record.phase else {
            return Err(ControllerError::Phase);
        };
        if plaintext.len() > epoch.max_plaintext_bytes() {
            return Err(CipherError::Limit.into());
        }
        let work = self.acquire(Self::data_work_claim(plaintext.len(), outer)?)?;
        let record = self
            .records
            .get_mut(&ticket.peer_key())
            .ok_or(ControllerError::Stale)?;
        let Phase::Ready(epoch) = &mut record.phase else {
            return Err(ControllerError::Phase);
        };
        let operation = epoch.operation(plaintext.len(), work, now)?;
        let cipher = epoch.seal(plaintext, now, operation)?;
        Ok(SealedOutput {
            cipher,
            ticket: ticket.clone(),
            outer,
        })
    }
    pub(crate) fn open(
        &mut self,
        ticket: &EpochTicket,
        packet: &CiphertextPacket,
        outer: ResourceClaim,
        now: Instant,
    ) -> Result<OpenedOutput, ControllerError> {
        self.check(ticket, now)?;
        if &packet.binding != ticket.binding() || packet.sender != ticket.peer_key() {
            return Err(ControllerError::Invalid);
        }
        packet.validate()?;
        let len = packet
            .ciphertext
            .len()
            .checked_sub(AEAD_TAG_BYTES)
            .ok_or(CipherError::Limit)?;
        let record = self
            .records
            .get(&ticket.peer_key())
            .ok_or(ControllerError::Stale)?;
        let Phase::Ready(epoch) = &record.phase else {
            return Err(ControllerError::Phase);
        };
        if len > epoch.max_plaintext_bytes() {
            return Err(CipherError::Limit.into());
        }
        let work = self.acquire(Self::data_work_claim(len, outer)?)?;
        let record = self
            .records
            .get_mut(&ticket.peer_key())
            .ok_or(ControllerError::Stale)?;
        let Phase::Ready(epoch) = &mut record.phase else {
            return Err(ControllerError::Phase);
        };
        let operation = epoch.operation(len, work, now)?;
        let plaintext = epoch.open(packet, now, operation)?;
        Ok(OpenedOutput {
            plaintext,
            _ticket: ticket.clone(),
        })
    }
}

impl Drop for EndpointCipherController {
    fn drop(&mut self) {
        self.shutdown();
    }
}

#[cfg(all(test, feature = "transport-lab"))]
mod tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
    use ed25519_dalek::Signer;

    fn policy(cap: u64) -> EndpointCipherPolicyConfig {
        EndpointCipherPolicyConfig {
            max_sessions: cap,
            max_plaintext_bytes: 1024,
            replay_window: 4,
            max_age_ms: 100,
        }
    }
    fn id(identity: &Identity) -> DeviceId {
        DeviceId::from_public_key_bytes(identity.signing_key().verifying_key().to_bytes()).unwrap()
    }
    fn outer() -> ResourceClaim {
        memory(4096, 1).unwrap()
    }
    struct Fixture {
        a: EndpointCipherController,
        b: EndpointCipherController,
        alice: Identity,
        bob: Identity,
        provider: FiniteResourceProvider,
        now: Instant,
    }
    impl Fixture {
        fn new(cap: u64) -> Self {
            Self::with_limits(cap, 1024, 1024)
        }
        fn with_limits(cap: u64, left: u64, right: u64) -> Self {
            let charge = |raw| FiniteResourceProvider::reservation_planning_charge(raw).unwrap();
            let retained = EndpointCipherController::planned_retention_claim(policy(cap)).unwrap();
            // Two live roots plus two fully funded replacement candidates;
            // this is a bounded test grant, never a production default.
            let replacement = add(
                add(
                    charge(EndpointCipherController::entry_claim().unwrap()),
                    charge(EndpointCipherController::signal_claim().unwrap()),
                )
                .unwrap(),
                charge(EndpointCipherController::epoch_claim(policy(cap)).unwrap()),
            )
            .unwrap();
            let work = add(
                charge(EndpointCipherController::control_work_claim(outer()).unwrap())
                    .checked_scale(8)
                    .unwrap(),
                charge(EndpointCipherController::data_work_claim(1024, outer()).unwrap())
                    .checked_scale(8)
                    .unwrap(),
            )
            .unwrap();
            let grant = retained
                .checked_scale(2)
                .unwrap()
                .checked_add(replacement.checked_scale(2).unwrap())
                .unwrap()
                .checked_add(work)
                .unwrap()
                .checked_add(
                    charge(EndpointCipherController::waiter_claim().unwrap())
                        .checked_scale(4)
                        .unwrap(),
                )
                .unwrap()
                .checked_add(
                    FiniteResourceProvider::scope_planning_charge()
                        .checked_scale(3)
                        .unwrap(),
                )
                .unwrap();
            let provider = FiniteResourceProvider::new(grant);
            let port = ResourceProviderPort::new(provider.clone()).unwrap();
            let first =
                Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[1; 32]), "a");
            let second =
                Identity::from_signing_key(ed25519_dalek::SigningKey::from_bytes(&[2; 32]), "b");
            let (alice, bob) = if id(&first).as_bytes() < id(&second).as_bytes() {
                (first, second)
            } else {
                (second, first)
            };
            let context = MeshContextId::from_bytes([7; 32]);
            let a_policy = EndpointCipherPolicyConfig {
                max_plaintext_bytes: left,
                ..policy(cap)
            };
            let b_policy = EndpointCipherPolicyConfig {
                max_plaintext_bytes: right,
                ..policy(cap)
            };
            let a = EndpointCipherController::new(
                a_policy,
                LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap(),
                context,
                &id(&alice),
            )
            .unwrap();
            let b = EndpointCipherController::new(
                b_policy,
                LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap(),
                context,
                &id(&bob),
            )
            .unwrap();
            Self {
                a,
                b,
                alice,
                bob,
                provider,
                now: Instant::now(),
            }
        }
        fn ready(&mut self) -> (EpochTicket, EpochTicket) {
            let offer = self
                .a
                .begin(&self.alice, &id(&self.bob), None, outer(), self.now)
                .unwrap();
            let answer = self
                .b
                .receive_control(
                    &self.bob,
                    &id(&self.alice),
                    &offer.output.as_ref().unwrap().frames().first,
                    outer(),
                    self.now,
                )
                .unwrap();
            let confirm = self
                .a
                .receive_control(
                    &self.alice,
                    &id(&self.bob),
                    &answer.output.as_ref().unwrap().frames().first,
                    outer(),
                    self.now,
                )
                .unwrap();
            self.b
                .receive_control(
                    &self.bob,
                    &id(&self.alice),
                    &confirm.output.as_ref().unwrap().frames().first,
                    outer(),
                    self.now,
                )
                .unwrap();
            self.a
                .receive_control(
                    &self.alice,
                    &id(&self.bob),
                    answer
                        .output
                        .as_ref()
                        .unwrap()
                        .frames()
                        .second
                        .as_ref()
                        .unwrap(),
                    outer(),
                    self.now,
                )
                .unwrap();
            assert_eq!(offer.ticket.phase(self.now), CipherPhase::Ready);
            assert_eq!(answer.ticket.phase(self.now), CipherPhase::Ready);
            (offer.ticket, answer.ticket)
        }
    }

    #[test]
    fn controller_invalid_input_preserves_pending_and_confirmation_precedes_data() {
        let mut f = Fixture::new(2);
        let baseline = f.provider.in_use();
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        assert!(matches!(
            f.a.seal(&offer.ticket, b"body", outer(), f.now),
            Err(ControllerError::Phase)
        ));
        let answer =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        let EndpointCipherControl::Share(share) = &answer.output.as_ref().unwrap().frames().first
        else {
            panic!("answer share");
        };
        let mut forged = share.clone();
        forged.signature[0] ^= 1;
        let usage = f.provider.in_use();
        assert!(matches!(
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &EndpointCipherControl::Share(forged),
                outer(),
                f.now
            ),
            Err(ControllerError::Cipher(CipherError::Signature))
        ));
        assert_eq!(f.provider.in_use(), usage);
        assert!(f.a.current(&offer.ticket, f.now));
        assert_eq!(offer.ticket.phase(f.now), CipherPhase::Pending);
        let confirm =
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &answer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        let EndpointCipherControl::Confirmation(real) = answer
            .output
            .as_ref()
            .unwrap()
            .frames()
            .second
            .as_ref()
            .unwrap()
        else {
            panic!("confirmation");
        };
        let mut wrong = real.clone();
        wrong.tag[0] ^= 1;
        assert!(matches!(
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &EndpointCipherControl::Confirmation(wrong),
                outer(),
                f.now
            ),
            Err(ControllerError::Cipher(CipherError::Authentication))
        ));
        assert_eq!(offer.ticket.phase(f.now), CipherPhase::Confirming);
        assert!(matches!(
            f.a.seal(&offer.ticket, b"body", outer(), f.now),
            Err(ControllerError::Phase)
        ));
        f.a.receive_control(
            &f.alice,
            &id(&f.bob),
            &EndpointCipherControl::Confirmation(real.clone()),
            outer(),
            f.now,
        )
        .unwrap();
        f.b.receive_control(
            &f.bob,
            &id(&f.alice),
            &confirm.output.as_ref().unwrap().frames().first,
            outer(),
            f.now,
        )
        .unwrap();
        let packet = f.a.seal(&offer.ticket, b"private", outer(), f.now).unwrap();
        let plain =
            f.b.open(&answer.ticket, packet.packet(), outer(), f.now)
                .unwrap();
        assert_eq!(plain.bytes(), b"private");
        assert!(matches!(
            f.b.open(&answer.ticket, packet.packet(), outer(), f.now),
            Err(ControllerError::Cipher(CipherError::Replay))
        ));
        drop((packet, plain, offer, answer, confirm));
        f.a.retire_all();
        f.b.retire_all();
        assert_eq!(f.provider.in_use(), baseline);
    }

    #[test]
    fn controller_context_full_key_and_same_binding_bad_share_do_not_evict() {
        let mut f = Fixture::new(2);
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let answer =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        let EndpointCipherControl::Share(valid) = &answer.output.as_ref().unwrap().frames().first
        else {
            panic!("share");
        };
        for field in 0..3 {
            let mut bad = valid.clone();
            match field {
                0 => bad.binding.context[0] ^= 1,
                1 => bad.binding.initiator = id(&Identity::ephemeral()).as_bytes(),
                _ => {
                    bad.ephemeral = [0; 32];
                    bad.ephemeral[0] = 1;
                }
            }
            bad.signature = f.bob.signing_key().sign(&bad.signing_bytes()).to_bytes();
            assert!(f
                .a
                .receive_control(
                    &f.alice,
                    &id(&f.bob),
                    &EndpointCipherControl::Share(bad),
                    outer(),
                    f.now
                )
                .is_err());
            assert!(f.a.current(&offer.ticket, f.now));
            assert_eq!(offer.ticket.phase(f.now), CipherPhase::Pending);
        }
        let unrelated = Identity::ephemeral();
        assert!(matches!(
            f.a.receive_control(
                &f.alice,
                &id(&unrelated),
                &answer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now
            ),
            Err(ControllerError::Invalid)
        ));
        assert!(matches!(
            f.a.begin(&unrelated, &id(&f.bob), None, outer(), f.now),
            Err(ControllerError::Invalid)
        ));
        f.a.receive_control(
            &f.alice,
            &id(&f.bob),
            &answer.output.as_ref().unwrap().frames().first,
            outer(),
            f.now,
        )
        .unwrap();
        assert_eq!(offer.ticket.phase(f.now), CipherPhase::Confirming);
    }

    #[test]
    fn controller_glare_is_deterministic_and_failed_winner_keeps_loser() {
        let mut f = Fixture::new(1);
        assert!(id(&f.alice).as_bytes() < id(&f.bob).as_bytes());
        let a_offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let b_offer =
            f.b.begin(&f.bob, &id(&f.alice), None, outer(), f.now)
                .unwrap();
        let waiter = f.b.waiter(&b_offer.ticket, f.now).unwrap();
        assert!(matches!(
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &b_offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now
            ),
            Err(ControllerError::Glare)
        ));
        let EndpointCipherControl::Share(real) = &a_offer.output.as_ref().unwrap().frames().first
        else {
            panic!("share");
        };
        let mut bad = real.clone();
        bad.ephemeral = [0; 32];
        bad.ephemeral[0] = 1;
        bad.signature = f.alice.signing_key().sign(&bad.signing_bytes()).to_bytes();
        let before = f.provider.in_use();
        assert!(matches!(
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &EndpointCipherControl::Share(bad),
                outer(),
                f.now
            ),
            Err(ControllerError::Cipher(CipherError::Authentication))
        ));
        assert_eq!(f.provider.in_use(), before);
        assert!(f.b.current(&b_offer.ticket, f.now));
        let answer =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &a_offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        assert_eq!(waiter.phase(f.now), CipherPhase::Retired);
        assert!(!f.b.current(&b_offer.ticket, f.now));
        assert!(f.b.current(&answer.ticket, f.now));
        assert_eq!(f.b.count, 1);
        let confirm =
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &answer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        f.b.receive_control(
            &f.bob,
            &id(&f.alice),
            &confirm.output.as_ref().unwrap().frames().first,
            outer(),
            f.now,
        )
        .unwrap();
        f.a.receive_control(
            &f.alice,
            &id(&f.bob),
            answer
                .output
                .as_ref()
                .unwrap()
                .frames()
                .second
                .as_ref()
                .unwrap(),
            outer(),
            f.now,
        )
        .unwrap();
        let packet = f.a.seal(&a_offer.ticket, b"glare", outer(), f.now).unwrap();
        assert_eq!(
            f.b.open(&answer.ticket, packet.packet(), outer(), f.now)
                .unwrap()
                .bytes(),
            b"glare"
        );
    }

    #[test]
    fn controller_duplicates_preserve_deadline_generation_and_cipher_counters() {
        let mut f = Fixture::new(2);
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let answer =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        let later = f.now + Duration::from_millis(20);
        let duplicate =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &offer.output.as_ref().unwrap().frames().first,
                outer(),
                later,
            )
            .unwrap();
        assert_eq!(duplicate.ticket.generation(), answer.ticket.generation());
        assert_eq!(duplicate.ticket.deadline(), answer.ticket.deadline());
        assert_eq!(
            duplicate.output.as_ref().unwrap().frames().first,
            answer.output.as_ref().unwrap().frames().first
        );
        assert_eq!(
            duplicate.output.as_ref().unwrap().frames().second,
            answer.output.as_ref().unwrap().frames().second
        );
        let confirm =
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &answer.output.as_ref().unwrap().frames().first,
                outer(),
                later,
            )
            .unwrap();
        f.b.receive_control(
            &f.bob,
            &id(&f.alice),
            &confirm.output.as_ref().unwrap().frames().first,
            outer(),
            later,
        )
        .unwrap();
        f.a.receive_control(
            &f.alice,
            &id(&f.bob),
            answer
                .output
                .as_ref()
                .unwrap()
                .frames()
                .second
                .as_ref()
                .unwrap(),
            outer(),
            later,
        )
        .unwrap();
        let repeat =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), later)
                .unwrap();
        assert!(
            repeat.output.is_none(),
            "local coalescing does not blindly resend an unknown offer"
        );
        let duplicate_confirm =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &confirm.output.as_ref().unwrap().frames().first,
                outer(),
                later,
            )
            .unwrap();
        assert!(duplicate_confirm.output.is_none());
        let first = f.a.seal(&offer.ticket, b"first", outer(), later).unwrap();
        let second = f.a.seal(&repeat.ticket, b"next", outer(), later).unwrap();
        assert_eq!(first.packet().sequence, 1);
        assert_eq!(second.packet().sequence, 2);
        assert_eq!(repeat.ticket.deadline(), f.now + Duration::from_millis(100));
        assert_eq!(repeat.ticket.generation(), offer.ticket.generation());
    }

    #[test]
    fn controller_original_expiry_blocks_use_before_bounded_physical_cleanup() {
        let mut f = Fixture::new(2);
        let (a, b) = f.ready();
        let deadline = a.deadline();
        assert!(f.a.current(&a, deadline - Duration::from_nanos(1)));
        let count = f.a.count;
        assert!(f.a.has_epochs());
        assert!(!f.a.current(&a, deadline));
        assert_eq!(
            f.a.observe(&id(&f.bob), deadline).unwrap().phase,
            CipherPhase::Retired
        );
        assert!(matches!(
            f.a.seal(&a, b"late", outer(), deadline),
            Err(ControllerError::Stale)
        ));
        assert_eq!(f.a.expire(deadline, 0), 0);
        assert_eq!(
            f.a.count, count,
            "logical expiry is distinct from physical retention"
        );
        assert!(
            f.a.has_epochs(),
            "lab seeding must refuse expired-but-retained records too"
        );
        assert_eq!(f.a.expire(deadline, 1), 1);
        assert_eq!(f.a.count, 0);
        assert!(!f.a.has_epochs());
        assert_eq!(f.a.expire(deadline, 1), 0);
        assert_eq!(a.phase(deadline), CipherPhase::Retired);
        assert_eq!(f.b.expire(b.deadline(), 1), 1);
    }

    #[test]
    fn controller_invalidation_rekey_and_new_root_never_revive_old_tickets() {
        let mut f = Fixture::new(2);
        let (old_a, old_b) = f.ready();
        let old_packet = f.a.seal(&old_a, b"old", outer(), f.now).unwrap();
        let mut affected = BTreeSet::new();
        affected.insert(id(&f.bob));
        f.a.invalidate_subjects(&affected);
        assert!(!f.a.current(&old_a, f.now));
        assert!(
            f.b.current(&old_b, f.now),
            "other root is not magically notified without its publication fence"
        );
        f.b.retire_all(); // OutcomeUnknown / local restore fence
        let (new_a, new_b) = f.ready();
        assert_ne!(new_a.binding().epoch, old_a.binding().epoch);
        assert!(matches!(
            f.a.seal(&old_a, b"stale", outer(), f.now),
            Err(ControllerError::Stale)
        ));
        assert!(matches!(
            f.b.open(&new_b, old_packet.packet(), outer(), f.now),
            Err(ControllerError::Invalid)
        ));
        assert!(!f.a.retire(&old_a));
        assert!(f.a.current(&new_a, f.now));
        let replacement =
            f.a.rekey(&f.alice, &id(&f.bob), &new_a, None, outer(), f.now)
                .unwrap();
        assert_eq!(new_a.phase(f.now), CipherPhase::Retired);
        assert!(replacement.ticket.generation() > new_a.generation());
        assert_eq!(replacement.ticket.phase(f.now), CipherPhase::Pending);
        assert!(
            matches!(
                f.b.receive_control(
                    &f.bob,
                    &id(&f.alice),
                    &replacement.output.as_ref().unwrap().frames().first,
                    outer(),
                    f.now
                ),
                Err(ControllerError::Glare)
            ),
            "remote cannot replace a still-Ready epoch unsolicited"
        );
        let fresh_root = EndpointCipherController::new(
            f.a.policy,
            f.a.resources.clone(),
            f.a.context,
            &id(&f.alice),
        )
        .unwrap();
        assert!(!fresh_root.current(&replacement.ticket, f.now));
        let mut local = BTreeSet::new();
        local.insert(id(&f.alice));
        f.a.invalidate_subjects(&local);
        assert_eq!(f.a.count, 0);
        f.a.shutdown();
        assert!(matches!(
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now),
            Err(ControllerError::Shutdown)
        ));
    }

    #[test]
    fn controller_capacity_pressure_and_effective_limit_refusals_preserve_current() {
        let mut f = Fixture::new(1);
        let (a, b) = f.ready();
        let other = Identity::ephemeral();
        assert!(matches!(
            f.a.begin(&f.alice, &id(&other), None, outer(), f.now),
            Err(ControllerError::Capacity)
        ));
        let pressure = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, u64::MAX / 2);
        let before = f.provider.in_use();
        assert!(matches!(
            f.a.rekey(&f.alice, &id(&f.bob), &a, None, pressure, f.now),
            Err(ControllerError::Pressure)
        ));
        assert!(matches!(
            f.a.seal(&a, b"blocked", pressure, f.now),
            Err(ControllerError::Pressure)
        ));
        assert!(matches!(
            f.a.seal(&a, &[0; 1025], outer(), f.now),
            Err(ControllerError::Cipher(CipherError::Limit))
        ));
        assert_eq!(f.provider.in_use(), before);
        assert!(f.a.current(&a, f.now));
        assert_eq!(
            f.a.observe(&id(&f.bob), f.now).unwrap().max_plaintext_bytes,
            Some(1024)
        );
        let max = f.a.seal(&a, &[255; 1024], outer(), f.now).unwrap();
        assert_eq!(max.packet().sequence, 1, "refusals consume no nonce");
        assert_eq!(
            f.b.open(&b, max.packet(), outer(), f.now).unwrap().bytes(),
            &[255; 1024]
        );
    }

    #[tokio::test]
    async fn controller_ready_notification_uses_confirmed_effective_limit() {
        let mut f = Fixture::with_limits(1, 64, 1024);
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let waiter = f.a.waiter(&offer.ticket, f.now).unwrap();
        let notified = waiter.notification().notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        let answer =
            f.b.receive_control(
                &f.bob,
                &id(&f.alice),
                &offer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        assert_eq!(answer.output.as_ref().unwrap().frames().iter().count(), 2);
        let confirm =
            f.a.receive_control(
                &f.alice,
                &id(&f.bob),
                &answer.output.as_ref().unwrap().frames().first,
                outer(),
                f.now,
            )
            .unwrap();
        f.a.receive_control(
            &f.alice,
            &id(&f.bob),
            answer
                .output
                .as_ref()
                .unwrap()
                .frames()
                .second
                .as_ref()
                .unwrap(),
            outer(),
            f.now,
        )
        .unwrap();
        f.b.receive_control(
            &f.bob,
            &id(&f.alice),
            &confirm.output.as_ref().unwrap().frames().first,
            outer(),
            f.now,
        )
        .unwrap();
        notified.await;
        assert_eq!(waiter.phase(f.now), CipherPhase::Ready);
        assert_eq!(
            f.a.observe(&id(&f.bob), f.now).unwrap().max_plaintext_bytes,
            Some(64)
        );
        assert_eq!(
            f.b.observe(&id(&f.alice), f.now)
                .unwrap()
                .max_plaintext_bytes,
            Some(64)
        );
        assert!(matches!(
            f.a.seal(&offer.ticket, &[0; 65], outer(), f.now),
            Err(ControllerError::Cipher(CipherError::Limit))
        ));
        let exact = f.a.seal(&offer.ticket, &[0; 64], outer(), f.now).unwrap();
        assert_eq!(exact.packet().sequence, 1);
        assert_eq!(
            f.b.open(&answer.ticket, exact.packet(), outer(), f.now)
                .unwrap()
                .bytes()
                .len(),
            64
        );
    }

    #[test]
    fn controller_one_byte_agreement_cannot_admit_encoded_channel_message() {
        let mut f = Fixture::with_limits(1, 1, 64);
        let (a, b) = f.ready();
        assert_eq!(
            f.a.observe(&id(&f.bob), f.now).unwrap().max_plaintext_bytes,
            Some(1)
        );
        assert_eq!(
            f.b.observe(&id(&f.alice), f.now)
                .unwrap()
                .max_plaintext_bytes,
            Some(1)
        );
        let bytes = serde_json::to_vec(&crate::protocol::MeshMessage::Channel {
            channel: "x".into(),
            payload: serde_json::Value::Null,
        })
        .unwrap();
        assert!(bytes.len() > 1);
        let before = f.provider.in_use();
        assert!(matches!(
            f.a.seal(&a, &bytes, outer(), f.now),
            Err(ControllerError::Cipher(CipherError::Limit))
        ));
        assert!(matches!(
            f.b.seal(&b, &bytes, outer(), f.now),
            Err(ControllerError::Cipher(CipherError::Limit))
        ));
        assert_eq!(f.provider.in_use(), before);
        let Phase::Ready(epoch) = &f.a.records.get(&id(&f.bob).as_bytes()).unwrap().phase else {
            panic!("Ready");
        };
        // Sending an arbitrary single byte is not a useful Channel delivery;
        // inspect the unchanged nonce using the next legitimate primitive seal.
        assert_eq!(epoch.max_plaintext_bytes(), 1);
        let probe = f.a.seal(&a, &[0], outer(), f.now).unwrap();
        assert_eq!(probe.packet().sequence, 1);
    }

    #[tokio::test]
    async fn controller_readiness_waiters_are_funded_capped_and_retirement_notifies() {
        let mut f = Fixture::new(1);
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let before = f.provider.in_use();
        let waiter = f.a.waiter(&offer.ticket, f.now).unwrap();
        let charged = FiniteResourceProvider::reservation_planning_charge(
            EndpointCipherController::waiter_claim().unwrap(),
        )
        .unwrap();
        assert_eq!(f.provider.in_use(), before.checked_add(charged).unwrap());
        assert!(matches!(
            f.a.waiter(&offer.ticket, f.now),
            Err(ControllerError::Capacity)
        ));
        {
            let notified = waiter.notification().notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            assert_eq!(waiter.phase(f.now), CipherPhase::Pending);
            assert_eq!(waiter.deadline(), offer.ticket.deadline());
            assert!(f.a.retire(waiter.ticket()));
            // Notification has already happened; no real-time sleeping or
            // network fixture. Joining notification still borrows the waiter.
            notified.await;
            assert_eq!(waiter.phase(f.now), CipherPhase::Retired);
        }
        drop(waiter);
        assert_eq!(f.a.root.waiters.load(Ordering::Acquire), 0);
        let new_offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let waiter = f.a.waiter(&new_offer.ticket, f.now).unwrap();
        drop(waiter); // cancellation releases capacity with no epoch retirement
        assert!(f.a.current(&new_offer.ticket, f.now));
        assert_eq!(f.a.root.waiters.load(Ordering::Acquire), 0);
    }

    #[test]
    fn controller_guarded_outputs_release_on_builder_error_cancel_and_terminal_drop() {
        let mut f = Fixture::new(2);
        let baseline = f.provider.in_use();
        let (a, b) = f.ready();
        let ready_usage = f.provider.in_use();
        let cipher = f.a.seal(&a, b"guarded", outer(), f.now).unwrap();
        let prepared = cipher
            .try_map(|packet| serde_json::to_vec(packet).map_err(|_| CipherError::Limit))
            .unwrap();
        assert!(!prepared.value().is_empty());
        assert!(f.a.current(prepared.ticket(), f.now));
        f.a.retire_all();
        f.b.retire_all();
        drop((a, b));
        assert_ne!(
            f.provider.in_use(),
            baseline,
            "prepared output retains signal/root/primitive work through terminal"
        );
        drop(prepared);
        assert_eq!(f.provider.in_use(), baseline);
        let (a, b) = f.ready();
        assert_eq!(f.provider.in_use(), ready_usage);
        let cipher = f.a.seal(&a, b"refuse", outer(), f.now).unwrap();
        assert!(matches!(
            cipher.try_map::<()>(|_| Err(CipherError::Limit)),
            Err(ControllerError::Cipher(CipherError::Limit))
        ));
        assert_eq!(f.provider.in_use(), ready_usage);
        let next = f.a.seal(&a, b"cancel", outer(), f.now).unwrap();
        assert_eq!(
            next.packet().sequence,
            2,
            "mapping failure does not enable a fresh-sequence retry"
        );
        drop(next);
        assert_eq!(f.provider.in_use(), ready_usage);
        f.a.retire_all();
        f.b.retire_all();
        drop((a, b));
        assert_eq!(f.provider.in_use(), baseline);
        let offer =
            f.a.begin(&f.alice, &id(&f.bob), None, outer(), f.now)
                .unwrap();
        let ticket = offer.ticket;
        let output = offer.output.unwrap();
        assert!(f.a.current(output.ticket(), f.now));
        let prepared = output
            .try_map(|frames| {
                serde_json::to_vec(&frames.first).map_err(|_| ControllerError::Invalid)
            })
            .unwrap();
        f.a.retire_all();
        drop(ticket);
        assert!(!prepared.value().is_empty());
        drop(prepared);
        assert_eq!(f.provider.in_use(), baseline);
    }
}
