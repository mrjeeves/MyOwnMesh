//! Attempt-owned Nostr delivery custody.
//!
//! A negotiation event is retained by its source owner until the exact live
//! attempt finishes.  The attempt record itself has provider custody before
//! it enters the map, and every relay connection gets its own provider-backed
//! entry; a reconnect is a new session and can receive the still-live event.
//! This module deliberately has no count cap, elapsed TTL, retry timer, or
//! route authority.

use std::borrow::Borrow;
use std::io::Write;
use std::mem;
use std::num::NonZeroU64;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;

use parking_lot::Mutex;
use tokio::sync::Notify;

use super::event::NostrEvent;
use crate::{
    AttemptOutcome, AttemptOutcomeKind, AttemptOutcomeSink, AttemptRefusal, ErasedOwner,
    NegotiationRefusal, OwnedSignal,
};

/// An opaque identity for one concrete relay WebSocket session.
///
/// Pointer identity is intentional: a reconnect can never reuse an old
/// numeric generation and therefore cannot settle an old entry by ABA.
#[derive(Clone)]
pub enum RelaySessionId {
    Live(Arc<()>),
    /// A provider-refused session has no allocated identity and can never be
    /// inserted or used to settle delivery. Keeping this zero-allocation
    /// sentinel lets `open_session` report refusal without creating an
    /// unfunded `Arc` merely to satisfy its return shape.
    Rejected,
}

impl RelaySessionId {
    pub(crate) fn fresh() -> Self {
        Self::Live(Arc::new(()))
    }

    fn rejected() -> Self {
        Self::Rejected
    }
}

impl std::fmt::Debug for RelaySessionId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("RelaySessionId")
            .field(&match self {
                Self::Live(value) => Arc::as_ptr(value) as usize,
                Self::Rejected => 0,
            })
            .finish()
    }
}

impl PartialEq for RelaySessionId {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Self::Live(left), Self::Live(right)) => Arc::ptr_eq(left, right),
            (Self::Rejected, Self::Rejected) => true,
            _ => false,
        }
    }
}

impl Eq for RelaySessionId {}

impl std::hash::Hash for RelaySessionId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        match self {
            Self::Live(value) => std::hash::Hash::hash(&(Arc::as_ptr(value) as usize), state),
            Self::Rejected => std::hash::Hash::hash(&0usize, state),
        }
    }
}

/// Exact provider input computed before the encoded EVENT frame is allocated.
///
/// The fields deliberately distinguish the event frame from the attempt,
/// key/map, and session structures.  An attached provider can therefore
/// charge the record that owns a refusal independently from each relay copy;
/// folding all of these into one per-relay number would double-charge an
/// attempt when it has multiple relays.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DeliveryRetention {
    pub encoded_event_bytes: usize,
    /// The relay record is inline in `DeliveryMapNode`; the node lease below
    /// owns this allocation, so the inline record charge is zero.
    pub structural_entry_bytes: usize,
    /// Exact allocation size of the provider-owned relay entry node.
    pub relay_entry_bytes: usize,
    /// Exact bytes for the attempt record allocation.
    /// The attempt record is inline in `DeliveryMapNode`; the node lease owns
    /// it and this inline record charge is therefore zero.
    pub attempt_record_bytes: usize,
    /// Exact bytes for the event-id key allocation.
    pub attempt_key_bytes: usize,
    /// Exact allocation size of `Box<DeliveryMapNode<String, AttemptEntry>>`,
    /// reserved before the attempt node is inserted.
    pub attempt_entry_bytes: usize,
}

/// Exact provider inputs for one relay-session registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SessionRetention {
    /// Provider accounting commitment for the live `RelaySessionId` handle.
    /// This is deliberately not an allocator-layout claim: the provider also
    /// owns an opaque residual for the identity allocation.
    pub session_identity_bytes: usize,
    /// Record commitment carrying the identity accounting above. The session
    /// map record itself is inline in `session_entry_bytes`.
    pub session_record_bytes: usize,
    pub session_set_node_bytes: usize,
    /// Exact allocation size of the provider-owned session entry node.
    pub session_entry_bytes: usize,
}

/// Why a provider refused a per-relay delivery entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryRefusal {
    Provider(String),
}

/// One-shot terminal outcome for a per-relay entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DeliveryTerminal {
    Accepted,
    TypedRefused(String),
    AttemptCompleted,
    AttemptReplaced,
    Cancelled,
    Shutdown,
}

/// Provider-owned lease for one exact attempt or (event, relay-session)
/// delivery.
pub trait DeliveryLease: Send + Sync {
    fn finish(self: Box<Self>, terminal: DeliveryTerminal);
}

/// Narrow seam for the core resource provider.
///
/// The event is borrowed so the provider can compute its exact reservation
/// before the encoded frame is allocated.  The returned lease remains with
/// that relay-session entry until one terminal outcome consumes it.
pub trait DeliveryProvider: Send + Sync {
    /// Fund the bounded raw-frame parse before JSON or envelope decoding.
    ///
    /// Providers charge `encoded_event_bytes` from the supplied retention; no
    /// peer-controlled collection is built before this lease is acquired.
    /// The lease is released when the caller finishes the parse.
    fn reserve_inbound_frame(
        &self,
        frame_bytes: usize,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Observe the process-local source before duplicate detection.  This is
    /// intentionally only the binding hook: the provider-owned lifetime is
    /// acquired through [`Self::reserve_admission_source`] below, while an
    /// owner-aware provider can bind the source to its exact emission before
    /// a duplicate refusal is produced.
    fn on_admission_source(&self, _source: AdmissionSource, _attempt: &str, _event_id: &str) {}

    /// Retain one opaque provider residual for the process-local admission
    /// identity. The lease prevents that token from becoming an unaccounted
    /// authority path.
    fn reserve_admission_source(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the `RelaySessionId` Arc allocation before it is created.
    fn reserve_session_identity(
        &self,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the session record before it is inserted into the live session set.
    fn reserve_session_record(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact session-set node before insertion.
    fn reserve_session_set_node(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact one-allocation session-map entry.
    fn reserve_session_entry(
        &self,
        session: RelaySessionId,
        retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact attempt record before it is inserted into the live map.
    fn reserve_attempt_record(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact event-id key allocation.
    fn reserve_attempt_key(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact per-relay delivery allocation.
    fn reserve(
        &self,
        attempt: &str,
        session: RelaySessionId,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact attempt-map entry owned by the provider.
    fn reserve_attempt_entry(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the exact relay-map entry owned by the provider.
    fn reserve_relay_entry(
        &self,
        attempt: &str,
        session: RelaySessionId,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;

    /// Fund the owned attempt-correlation string separately from the event-id
    /// key.
    fn reserve_attempt_correlation(
        &self,
        attempt: &str,
        event: &NostrEvent,
        retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal>;
}

/// Test-only provider for local delivery-driver controls. Production core
/// attachment must pass an explicit provider and both caller-funded terminal
/// custodians through
/// [`super::driver::start_with_delivery_provider_and_sinks_with_custodian`];
/// [`super::driver::derive_task_custody_plan`] supplies the exact observer
/// reservations for the selected and fallback relay sets.
#[cfg(test)]
pub struct UnmeteredDeliveryProvider;

struct UnmeteredLease;

struct UnmeteredAttemptOutcomeSink;

impl AttemptOutcomeSink for UnmeteredAttemptOutcomeSink {
    fn outcome(&self, _outcome: AttemptOutcome) {}
}

impl DeliveryLease for UnmeteredLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {}
}

#[cfg(test)]
impl DeliveryProvider for UnmeteredDeliveryProvider {
    fn reserve_inbound_frame(
        &self,
        _frame_bytes: usize,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_admission_source(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_identity(
        &self,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }

    fn reserve_attempt_correlation(
        &self,
        _attempt: &str,
        _event: &NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(UnmeteredLease))
    }
}

struct RelayEntry {
    lease: Box<dyn DeliveryLease>,
    map_lease: Box<dyn DeliveryLease>,
    in_flight: bool,
}

impl DeliveryRetention {
    /// Compute the frame and owned-record shape before any frame or map node
    /// is allocated. The map-node sizes are the exact boxed allocation types
    /// used by this module, and their provider leases are acquired before
    /// insertion.
    pub fn for_attempt(_attempt: &str, event: &NostrEvent) -> Self {
        let mut counter = CountingWriter(0);
        counter.write_all(b"[\"EVENT\",").expect("counting writer");
        serde_json::to_writer(&mut counter, event).expect("event serializes");
        counter.write_all(b"]").expect("counting writer");
        let relay_entry_bytes = std::mem::size_of::<DeliveryMapNode<RelaySessionId, RelayEntry>>();
        let attempt_entry_bytes = std::mem::size_of::<DeliveryMapNode<String, AttemptEntry>>();
        Self {
            encoded_event_bytes: counter.0,
            structural_entry_bytes: 0,
            relay_entry_bytes,
            attempt_record_bytes: 0,
            attempt_key_bytes: event.id.len(),
            attempt_entry_bytes,
        }
    }
}

impl SessionRetention {
    fn exact() -> Self {
        let session_entry_bytes =
            std::mem::size_of::<DeliveryMapNode<RelaySessionId, SessionEntry>>();
        Self {
            session_identity_bytes: std::mem::size_of::<Arc<()>>(),
            session_record_bytes: std::mem::size_of::<Arc<()>>(),
            session_set_node_bytes: 0,
            session_entry_bytes,
        }
    }
}

struct CountingWriter(usize);

impl Write for CountingWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self.0.saturating_add(bytes.len());
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Successful admissions and typed per-relay refusals are both retained in
/// the attempt record; one refused relay never rolls back healthy relays.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AdmissionRefusal {
    DuplicateLiveEvent,
    /// The process-local identity space is exhausted; no provider dispatch
    /// or live attempt admission occurred.
    AdmissionIdentityExhausted,
    /// The exact attempt owner was refused before its record was admitted.
    Provider(DeliveryRefusal),
}

/// Process-local identity for one source emission admission. It deliberately
/// never enters a Nostr frame: two identical wire event ids can still be
/// distinguished while their source owners are alive in this process. The
/// token is only a copyable lookup handle; provider custody is held by the
/// matching `AttemptEntry::source_lease`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum AdmissionSource {
    Live(NonZeroU64),
    /// No live identity was minted. This sentinel is returned only with a
    /// typed local refusal and can never match an admitted attempt.
    Unavailable,
}

static NEXT_ADMISSION_SOURCE: AtomicU64 = AtomicU64::new(1);

impl AdmissionSource {
    fn checked_value(current: u64) -> Option<(Self, u64)> {
        let source = Self::Live(NonZeroU64::new(current)?);
        let next = current.checked_add(1).unwrap_or(0);
        Some((source, next))
    }

    /// Try to mint a process-local source for an exact emission. The checked
    /// CAS sequence never wraps or reuses an identity; exhaustion is a typed
    /// absence rather than an ABA-prone wrapped value.
    pub fn try_fresh() -> Option<Self> {
        try_fresh_from(&NEXT_ADMISSION_SOURCE)
    }
}

fn try_fresh_from(counter: &AtomicU64) -> Option<AdmissionSource> {
    let mut current = counter.load(std::sync::atomic::Ordering::Acquire);
    loop {
        let (source, next) = AdmissionSource::checked_value(current)?;
        match counter.compare_exchange_weak(
            current,
            next,
            std::sync::atomic::Ordering::AcqRel,
            std::sync::atomic::Ordering::Acquire,
        ) {
            Ok(_) => return Some(source),
            Err(observed) => current = observed,
        }
    }
}

impl AdmissionRefusal {
    pub(crate) fn into_negotiation(self) -> NegotiationRefusal {
        match self {
            Self::DuplicateLiveEvent => NegotiationRefusal::DuplicateLiveEvent,
            Self::AdmissionIdentityExhausted => {
                NegotiationRefusal::Provider("admission identity exhausted".to_string())
            }
            Self::Provider(DeliveryRefusal::Provider(reason)) => {
                NegotiationRefusal::Provider(reason)
            }
        }
    }
}

#[derive(Debug)]
pub struct AdmissionReport {
    /// Process-local source identity for this admission, including a refused
    /// duplicate. `Unavailable` marks checked mint exhaustion and is never a
    /// live settlement authority. The value is never serialized into a Nostr
    /// event.
    pub source: AdmissionSource,
    pub event_id: String,
    pub accepted_sessions: usize,
    pub refused: Vec<(RelaySessionId, DeliveryRefusal)>,
    pub attempt_refusal: Option<AdmissionRefusal>,
}

fn exhausted_admission_report(owned: OwnedSignal<NostrEvent, ErasedOwner>) -> AdmissionReport {
    AdmissionReport {
        source: AdmissionSource::Unavailable,
        event_id: owned.value().id.clone(),
        accepted_sessions: 0,
        refused: Vec::new(),
        attempt_refusal: Some(AdmissionRefusal::AdmissionIdentityExhausted),
    }
}

fn closed_admission_report(owned: OwnedSignal<NostrEvent, ErasedOwner>) -> AdmissionReport {
    AdmissionReport {
        source: AdmissionSource::Unavailable,
        event_id: owned.value().id.clone(),
        accepted_sessions: 0,
        refused: Vec::new(),
        attempt_refusal: Some(AdmissionRefusal::Provider(DeliveryRefusal::Provider(
            "delivery store is closed".to_string(),
        ))),
    }
}

struct AttemptEntry {
    source: AdmissionSource,
    attempt: String,
    owned: OwnedSignal<NostrEvent, ErasedOwner>,
    source_lease: Box<dyn DeliveryLease>,
    record_lease: Box<dyn DeliveryLease>,
    key_lease: Box<dyn DeliveryLease>,
    correlation_lease: Option<Box<dyn DeliveryLease>>,
    map_lease: Box<dyn DeliveryLease>,
    relays: DeliveryMap<RelaySessionId, RelayEntry>,
    carrier: CarrierAggregate,
    provider_refused: bool,
}

/// Order-independent carrier observations for one live event.
///
/// The first accepted relay wins the event-level outcome, while duplicate ACKs
/// still release their own custody. A refusal from one relay is only a
/// candidate terminal until every live relay has either refused or
/// disappeared. The selected refusal is the lexicographically smallest
/// observed reason, so relay completion order cannot change the result.
/// `unavailable_reported` is scoped to the current carrier epoch and is reset
/// when a reconnect admits a relay.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct CarrierAggregate {
    accepted_session: Option<RelaySessionId>,
    typed_refusal: Option<String>,
    terminal_emitted: bool,
    unavailable_reported: bool,
}

impl CarrierAggregate {
    /// Record the first accepted relay. Later duplicate ACKs remain valid
    /// custody releases but cannot emit a second event-level outcome.
    pub fn observe_accepted(&mut self, session: RelaySessionId) -> bool {
        if self.terminal_emitted {
            return false;
        }
        self.accepted_session = Some(session);
        self.terminal_emitted = true;
        true
    }

    /// Record a typed relay refusal without making it terminal while another
    /// carrier remains viable. Reasons are normalized by deterministic
    /// ordering so relay arrival order cannot choose the result.
    pub fn observe_typed_refusal(&mut self, reason: &str) {
        if self.terminal_emitted {
            return;
        }
        let replace = match self.typed_refusal.as_deref() {
            None => true,
            Some(current) => reason < current,
        };
        if replace {
            self.typed_refusal = Some(reason.to_string());
        }
    }

    /// Start a fresh carrier epoch after a relay reconnects.
    pub fn observe_reconnect(&mut self) {
        if !self.terminal_emitted {
            self.unavailable_reported = false;
            self.typed_refusal = None;
        }
    }

    /// Claim the one all-carrier refusal notification for this epoch.
    ///
    /// Individual relay sessions may fail concurrently after the last funded
    /// relay has gone away.  Only the first failure owns the provider/core
    /// refusal; a successful reconnect starts a new epoch through
    /// [`Self::observe_reconnect`].
    pub fn observe_all_carrier_refusal(&mut self) -> bool {
        if self.terminal_emitted || self.unavailable_reported {
            return false;
        }
        self.unavailable_reported = true;
        true
    }

    /// Return the one aggregate outcome for this unavailable carrier epoch.
    pub fn unavailable_outcome(&mut self) -> Option<AttemptOutcomeKind> {
        if self.terminal_emitted || self.unavailable_reported {
            return None;
        }
        self.unavailable_reported = true;
        Some(match &self.typed_refusal {
            Some(reason) => AttemptOutcomeKind::TypedRefused(reason.clone()),
            None => AttemptOutcomeKind::CarrierUnavailable,
        })
    }
}

struct SessionEntry {
    record_lease: Box<dyn DeliveryLease>,
    node_lease: Box<dyn DeliveryLease>,
    entry_lease: Box<dyn DeliveryLease>,
}

/// A provider-funded, one-allocation-per-entry map.
///
/// HashMap bucket arrays are process allocations whose geometric growth is
/// impossible to price from a tuple `size_of`. This intrusive map allocates
/// exactly one boxed node per insertion; the caller acquires that node's
/// provider lease before calling `insert`. It has no spare capacity, bucket
/// control bytes, or reallocation path.
struct DeliveryMap<K, V> {
    head: Option<Box<DeliveryMapNode<K, V>>>,
    len: usize,
}

struct DeliveryMapNode<K, V> {
    key: K,
    value: V,
    next: Option<Box<DeliveryMapNode<K, V>>>,
}

impl<K, V> Default for DeliveryMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> Drop for DeliveryMap<K, V> {
    fn drop(&mut self) {
        let mut next = self.head.take();
        while let Some(mut node) = next {
            // Break the ownership chain before this node drops. Its own
            // fields then drop normally, while the loop owns the remainder.
            next = node.next.take();
        }
    }
}

impl<K, V> DeliveryMap<K, V> {
    fn new() -> Self {
        Self { head: None, len: 0 }
    }

    fn len(&self) -> usize {
        self.len
    }

    fn is_empty(&self) -> bool {
        self.len == 0
    }

    fn iter(&self) -> DeliveryMapIter<'_, K, V> {
        DeliveryMapIter {
            next: self.head.as_deref(),
        }
    }

    fn iter_mut(&mut self) -> DeliveryMapIterMut<'_, K, V> {
        DeliveryMapIterMut {
            next: self.head.as_deref_mut(),
        }
    }

    fn into_values(self) -> impl Iterator<Item = V> {
        self.into_iter().map(|(_, value)| value)
    }
}

impl<K, V> DeliveryMap<K, V> {
    fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.iter()
            .find_map(|(candidate, value)| (candidate.borrow() == key).then_some(value))
    }

    fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.iter_mut()
            .find_map(|(candidate, value)| (candidate.borrow() == key).then_some(value))
    }

    fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        self.get(key).is_some()
    }

    fn insert(&mut self, key: K, value: V) -> Option<V>
    where
        K: PartialEq,
    {
        let mut link = &mut self.head;
        loop {
            match link {
                Some(node) if node.key == key => {
                    return Some(mem::replace(&mut node.value, value));
                }
                Some(node) => link = &mut node.next,
                None => {
                    *link = Some(Box::new(DeliveryMapNode {
                        key,
                        value,
                        next: None,
                    }));
                    self.len += 1;
                    return None;
                }
            }
        }
    }

    fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Eq + ?Sized,
    {
        let mut link = &mut self.head;
        loop {
            let matches = match link.as_ref() {
                Some(node) => node.key.borrow() == key,
                None => return None,
            };
            if matches {
                let mut removed = link.take().expect("the node was borrowed above");
                *link = removed.next.take();
                self.len -= 1;
                return Some(removed.value);
            }
            link = &mut link
                .as_mut()
                .expect("a nonmatching node exists while advancing")
                .next;
        }
    }
}

impl<K, V> IntoIterator for DeliveryMap<K, V> {
    type Item = (K, V);
    type IntoIter = DeliveryMapIntoIter<K, V>;

    fn into_iter(mut self) -> Self::IntoIter {
        DeliveryMapIntoIter {
            next: self.head.take(),
        }
    }
}

struct DeliveryMapIter<'a, K, V> {
    next: Option<&'a DeliveryMapNode<K, V>>,
}

impl<'a, K, V> Iterator for DeliveryMapIter<'a, K, V> {
    type Item = (&'a K, &'a V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next?;
        self.next = node.next.as_deref();
        Some((&node.key, &node.value))
    }
}

struct DeliveryMapIterMut<'a, K, V> {
    next: Option<&'a mut DeliveryMapNode<K, V>>,
}

impl<'a, K, V> Iterator for DeliveryMapIterMut<'a, K, V> {
    type Item = (&'a K, &'a mut V);

    fn next(&mut self) -> Option<Self::Item> {
        let node = self.next.take()?;
        self.next = node.next.as_deref_mut();
        Some((&node.key, &mut node.value))
    }
}

struct DeliveryMapIntoIter<K, V> {
    next: Option<Box<DeliveryMapNode<K, V>>>,
}

impl<K, V> Drop for DeliveryMapIntoIter<K, V> {
    fn drop(&mut self) {
        let mut next = self.next.take();
        while let Some(mut node) = next {
            next = node.next.take();
        }
    }
}

impl<K, V> Iterator for DeliveryMapIntoIter<K, V> {
    type Item = (K, V);

    fn next(&mut self) -> Option<Self::Item> {
        let mut node = self.next.take()?;
        self.next = node.next.take();
        Some((node.key, node.value))
    }
}

struct DeliveryState {
    closed: bool,
    sessions: DeliveryMap<RelaySessionId, SessionEntry>,
    attempts: DeliveryMap<String, AttemptEntry>,
}

struct RetainedDeliveryLease(Option<Box<dyn DeliveryLease>>);

impl Drop for RetainedDeliveryLease {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            lease.finish(DeliveryTerminal::Cancelled);
        }
    }
}

/// The live attempt owner and its per-relay delivery entries.
///
/// This map is the sole local owner of outbound negotiation retention. Each
/// node and owned value is inserted only after its provider lease succeeds;
/// the provider therefore remains the source of truth for aggregate count and
/// byte pressure. No elapsed-time retry or event-id cache is kept here.
pub struct DeliveryStore {
    provider: Arc<dyn DeliveryProvider>,
    outcome_sink: Arc<dyn AttemptOutcomeSink>,
    state: Mutex<DeliveryState>,
    notify: Notify,
}

impl DeliveryStore {
    pub fn new(provider: Arc<dyn DeliveryProvider>) -> Arc<Self> {
        Self::new_with_outcome_sink(provider, Arc::new(UnmeteredAttemptOutcomeSink))
    }

    pub fn new_with_outcome_sink(
        provider: Arc<dyn DeliveryProvider>,
        outcome_sink: Arc<dyn AttemptOutcomeSink>,
    ) -> Arc<Self> {
        Arc::new(Self {
            provider,
            outcome_sink,
            state: Mutex::new(DeliveryState {
                closed: false,
                sessions: DeliveryMap::new(),
                attempts: DeliveryMap::new(),
            }),
            notify: Notify::new(),
        })
    }

    pub fn notification(&self) -> &Notify {
        &self.notify
    }

    /// Fund one raw inbound frame before the driver parses it. The returned
    /// lease is intentionally independent of any outbound attempt and must be
    /// finished by the caller after parsing or local refusal.
    pub fn reserve_inbound_frame(
        &self,
        frame_bytes: usize,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        let state = self.state.lock();
        if state.closed {
            return Err(DeliveryRefusal::Provider(
                "delivery store is closed".to_string(),
            ));
        }
        let lease = self.provider.reserve_inbound_frame(frame_bytes);
        drop(state);
        lease
    }

    /// Admit one retained presence event before it is placed in the shared
    /// watch or encoded for a relay. The lease travels with the event through
    /// the watch and every relay's borrowed copy, and is released when the
    /// final copy leaves those owners.
    pub fn admit_presence(
        &self,
        event: NostrEvent,
    ) -> Result<OwnedSignal<NostrEvent, ErasedOwner>, DeliveryRefusal> {
        let state = self.state.lock();
        if state.closed {
            return Err(DeliveryRefusal::Provider(
                "delivery store is closed".to_string(),
            ));
        }
        let retention = DeliveryRetention::for_attempt("<presence>", &event);
        let lease = self
            .provider
            .reserve_admission_source("<presence>", &event, retention)?;
        drop(state);
        Ok(OwnedSignal::new(
            event,
            Box::new(RetainedDeliveryLease(Some(lease))) as ErasedOwner,
        ))
    }

    /// Register a session and return only refusals that left the exact
    /// attempt with no funded relay.  Partial relay refusal is observable in
    /// the per-relay report but is not an attempt terminal.
    pub fn open_session_with_refusals(
        &self,
    ) -> (RelaySessionId, Option<DeliveryRefusal>, Vec<AttemptRefusal>) {
        let mut state = self.state.lock();
        if state.closed {
            return (
                RelaySessionId::rejected(),
                Some(DeliveryRefusal::Provider(
                    "delivery store is closed".to_string(),
                )),
                Vec::new(),
            );
        }
        let retention = SessionRetention::exact();
        let identity_lease = match self.provider.reserve_session_identity(retention) {
            Ok(lease) => lease,
            Err(error) => return (RelaySessionId::rejected(), Some(error), Vec::new()),
        };
        let session = RelaySessionId::fresh();
        let record_lease = identity_lease;
        let node_lease = match self
            .provider
            .reserve_session_set_node(session.clone(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                record_lease.finish(DeliveryTerminal::Cancelled);
                return (RelaySessionId::rejected(), Some(error), Vec::new());
            }
        };
        let entry_lease = match self
            .provider
            .reserve_session_entry(session.clone(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                node_lease.finish(DeliveryTerminal::Cancelled);
                record_lease.finish(DeliveryTerminal::Cancelled);
                return (RelaySessionId::rejected(), Some(error), Vec::new());
            }
        };
        state.sessions.insert(
            session.clone(),
            SessionEntry {
                record_lease,
                node_lease,
                entry_lease,
            },
        );
        let mut refused = Vec::new();
        for (_, entry) in state.attempts.iter_mut() {
            let retention = DeliveryRetention::for_attempt(&entry.attempt, entry.owned.value());
            match self.provider.reserve(
                &entry.attempt,
                session.clone(),
                entry.owned.value(),
                retention,
            ) {
                Ok(lease) => {
                    match self.provider.reserve_relay_entry(
                        &entry.attempt,
                        session.clone(),
                        entry.owned.value(),
                        retention,
                    ) {
                        Ok(map_lease) => {
                            entry.provider_refused = false;
                            entry.carrier.observe_reconnect();
                            entry.relays.insert(
                                session.clone(),
                                RelayEntry {
                                    lease,
                                    map_lease,
                                    in_flight: false,
                                },
                            );
                        }
                        Err(error) => {
                            lease.finish(DeliveryTerminal::Cancelled);
                            if entry.relays.is_empty() {
                                entry.provider_refused = true;
                                if entry.carrier.observe_all_carrier_refusal() {
                                    refused.push(AttemptRefusal {
                                        source: entry.source,
                                        attempt: entry.attempt.clone(),
                                        event_id: entry.owned.value().id.clone(),
                                        refusal: NegotiationRefusal::Provider(match &error {
                                            DeliveryRefusal::Provider(reason) => reason.clone(),
                                        }),
                                    });
                                }
                            }
                        }
                    }
                }
                Err(error) => {
                    // A refused reconnect does not invalidate an already
                    // funded relay.  Mark the attempt retryable only when
                    // this leaves it with no live relay entry; otherwise the
                    // healthy relay's authoritative ACK may retire it.
                    if entry.relays.is_empty() {
                        entry.provider_refused = true;
                        if entry.carrier.observe_all_carrier_refusal() {
                            refused.push(AttemptRefusal {
                                source: entry.source,
                                attempt: entry.attempt.clone(),
                                event_id: entry.owned.value().id.clone(),
                                refusal: NegotiationRefusal::Provider(match &error {
                                    DeliveryRefusal::Provider(reason) => reason.clone(),
                                }),
                            });
                        }
                    }
                }
            }
        }
        (session, None, refused)
    }

    /// Admit a translated negotiation. Existing sessions are funded before
    /// this value can be encoded or queued for any relay.
    pub fn admit(
        &self,
        attempt: String,
        owned: OwnedSignal<NostrEvent, ErasedOwner>,
    ) -> AdmissionReport {
        let mut state = self.state.lock();
        if state.closed {
            return closed_admission_report(owned);
        }
        let Some(source) = AdmissionSource::try_fresh() else {
            return exhausted_admission_report(owned);
        };
        let event_id_ref = owned.value().id.as_str();
        self.provider
            .on_admission_source(source, &attempt, event_id_ref);
        let retention = DeliveryRetention::for_attempt(&attempt, owned.value());
        let source_lease =
            match self
                .provider
                .reserve_admission_source(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    return AdmissionReport {
                        source,
                        event_id: event_id_ref.to_owned(),
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            };
        if state.attempts.contains_key(event_id_ref) {
            source_lease.finish(DeliveryTerminal::Cancelled);
            return AdmissionReport {
                source,
                event_id: event_id_ref.to_owned(),
                accepted_sessions: 0,
                refused: Vec::new(),
                attempt_refusal: Some(AdmissionRefusal::DuplicateLiveEvent),
            };
        }
        let record_lease =
            match self
                .provider
                .reserve_attempt_record(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    source_lease.finish(DeliveryTerminal::Cancelled);
                    return AdmissionReport {
                        source,
                        event_id: event_id_ref.to_owned(),
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            };
        let key_lease = match self
            .provider
            .reserve_attempt_key(&attempt, owned.value(), retention)
        {
            Ok(lease) => lease,
            Err(error) => {
                source_lease.finish(DeliveryTerminal::Cancelled);
                record_lease.finish(DeliveryTerminal::Cancelled);
                return AdmissionReport {
                    source,
                    event_id: event_id_ref.to_owned(),
                    accepted_sessions: 0,
                    refused: Vec::new(),
                    attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                };
            }
        };
        let correlation_lease = if attempt.is_empty() {
            None
        } else {
            match self
                .provider
                .reserve_attempt_correlation(&attempt, owned.value(), retention)
            {
                Ok(lease) => Some(lease),
                Err(error) => {
                    source_lease.finish(DeliveryTerminal::Cancelled);
                    key_lease.finish(DeliveryTerminal::Cancelled);
                    record_lease.finish(DeliveryTerminal::Cancelled);
                    return AdmissionReport {
                        source,
                        event_id: event_id_ref.to_owned(),
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            }
        };
        let map_lease =
            match self
                .provider
                .reserve_attempt_entry(&attempt, owned.value(), retention)
            {
                Ok(lease) => lease,
                Err(error) => {
                    source_lease.finish(DeliveryTerminal::Cancelled);
                    if let Some(lease) = correlation_lease {
                        lease.finish(DeliveryTerminal::Cancelled);
                    }
                    key_lease.finish(DeliveryTerminal::Cancelled);
                    record_lease.finish(DeliveryTerminal::Cancelled);
                    return AdmissionReport {
                        source,
                        event_id: event_id_ref.to_owned(),
                        accepted_sessions: 0,
                        refused: Vec::new(),
                        attempt_refusal: Some(AdmissionRefusal::Provider(error)),
                    };
                }
            };
        let event_id = owned.value().id.clone();
        let mut relays = DeliveryMap::new();
        let mut refused = Vec::new();
        for (session, _) in state.sessions.iter() {
            let session = session.clone();
            match self
                .provider
                .reserve(&attempt, session.clone(), owned.value(), retention)
            {
                Ok(lease) => match self.provider.reserve_relay_entry(
                    &attempt,
                    session.clone(),
                    owned.value(),
                    retention,
                ) {
                    Ok(map_lease) => {
                        relays.insert(
                            session,
                            RelayEntry {
                                lease,
                                map_lease,
                                in_flight: false,
                            },
                        );
                    }
                    Err(error) => {
                        lease.finish(DeliveryTerminal::Cancelled);
                        refused.push((session, error));
                    }
                },
                Err(error) => refused.push((session, error)),
            }
        }
        let accepted_sessions = relays.len();
        let provider_refused = !refused.is_empty() && relays.is_empty();
        let attempt_refusal = if relays.is_empty() {
            refused
                .first()
                .map(|(_, error)| AdmissionRefusal::Provider(error.clone()))
        } else {
            None
        };
        state.attempts.insert(
            event_id.clone(),
            AttemptEntry {
                source,
                attempt,
                owned,
                source_lease,
                record_lease,
                key_lease,
                correlation_lease,
                map_lease,
                relays,
                carrier: CarrierAggregate::default(),
                // A partial refusal still has a funded live relay and may
                // settle authoritatively there.  Only an all-refused active
                // set needs to remain marked for a later reconnect retry.
                provider_refused,
            },
        );
        drop(state);
        self.notify.notify_waiters();
        AdmissionReport {
            source,
            event_id,
            accepted_sessions,
            refused,
            attempt_refusal,
        }
    }

    /// Mark and return one pending entry for a session.
    ///
    /// The one-at-a-time seam keeps the relay task from creating a second
    /// collection proportional to the number of live attempts. The delivery
    /// map remains the sole owner of pending event identities.
    pub fn next_pending(&self, session: &RelaySessionId) -> Option<String> {
        let mut state = self.state.lock();
        for (event_id, entry) in state.attempts.iter_mut() {
            if let Some(relay) = entry.relays.get_mut(session) {
                if !relay.in_flight {
                    relay.in_flight = true;
                    return Some(event_id.clone());
                }
            }
        }
        None
    }

    /// Borrow an event only after its relay entry has been provider-funded.
    pub fn with_event<R>(&self, event_id: &str, f: impl FnOnce(&NostrEvent) -> R) -> Option<R> {
        let state = self.state.lock();
        state
            .attempts
            .get(event_id)
            .map(|entry| f(entry.owned.value()))
    }

    /// Settle exactly one event/session pair. A stale session cannot settle a
    /// fresh reconnect because its entry was removed when the old session died.
    pub fn settle(
        &self,
        session: &RelaySessionId,
        event_id: &str,
        terminal: DeliveryTerminal,
    ) -> bool {
        self.settle_with_source(None, session, event_id, terminal)
    }

    /// Settle only when the event still belongs to this exact process-local
    /// admission. This is the Core seam for same-wire-id E1/E2 emissions;
    /// stale E2 disposal cannot consume E1's relay custody.
    pub fn settle_source(
        &self,
        source: AdmissionSource,
        session: &RelaySessionId,
        event_id: &str,
        terminal: DeliveryTerminal,
    ) -> bool {
        self.settle_with_source(Some(source), session, event_id, terminal)
    }

    fn settle_with_source(
        &self,
        source: Option<AdmissionSource>,
        session: &RelaySessionId,
        event_id: &str,
        terminal: DeliveryTerminal,
    ) -> bool {
        if matches!(source, Some(AdmissionSource::Unavailable)) {
            return false;
        }
        let (leases, outcome) = {
            let mut state = self.state.lock();
            let (
                lease,
                remove_attempt,
                source,
                attempt,
                has_remaining,
                typed_refusal,
                accepted_outcome,
            ) = {
                let Some(entry) = state.attempts.get_mut(event_id) else {
                    return false;
                };
                if source.is_some_and(|expected| expected != entry.source) {
                    return false;
                }
                let Some(relay) = entry.relays.remove(session) else {
                    return false;
                };
                if let DeliveryTerminal::TypedRefused(reason) = &terminal {
                    entry.carrier.observe_typed_refusal(reason);
                }
                let accepted_outcome = matches!(&terminal, DeliveryTerminal::Accepted)
                    && entry.carrier.observe_accepted(session.clone());
                let has_remaining = !entry.relays.is_empty();
                let remove_attempt = matches!(
                    &terminal,
                    DeliveryTerminal::Accepted | DeliveryTerminal::TypedRefused(_)
                ) && !has_remaining
                    && !entry.provider_refused;
                let typed_refusal = entry.carrier.typed_refusal.clone();
                (
                    relay,
                    remove_attempt,
                    entry.source,
                    entry.attempt.clone(),
                    has_remaining,
                    typed_refusal,
                    accepted_outcome,
                )
            };
            let outcome = match &terminal {
                DeliveryTerminal::Accepted if accepted_outcome => Some(AttemptOutcome {
                    source,
                    attempt,
                    event_id: event_id.to_string(),
                    kind: AttemptOutcomeKind::Accepted {
                        session: Some(session.clone()),
                    },
                }),
                DeliveryTerminal::Accepted => None,
                DeliveryTerminal::TypedRefused(_) if !has_remaining => {
                    typed_refusal.map(|reason| AttemptOutcome {
                        source,
                        attempt,
                        event_id: event_id.to_string(),
                        kind: AttemptOutcomeKind::TypedRefused(reason),
                    })
                }
                DeliveryTerminal::TypedRefused(_) => None,
                _ => None,
            };
            if remove_attempt {
                // Remove the source owner atomically with the final relay
                // entry.  A reconnect may otherwise acquire this mutex after
                // the lease is detached but before the old implementation
                // removed the attempt, fund a fresh entry, and then have
                // that entry erased by the stale removal.
                let entry = state
                    .attempts
                    .remove(event_id)
                    .expect("attempt exists while settling its relay");
                let mut leases = vec![
                    lease.lease,
                    lease.map_lease,
                    entry.source_lease,
                    entry.record_lease,
                    entry.key_lease,
                ];
                if let Some(correlation_lease) = entry.correlation_lease {
                    leases.push(correlation_lease);
                }
                leases.push(entry.map_lease);
                (leases, outcome)
            } else {
                (vec![lease.lease, lease.map_lease], outcome)
            }
        };
        for lease in leases {
            lease.finish(terminal.clone());
        }
        if let Some(outcome) = outcome {
            self.outcome_sink.outcome(outcome);
        }
        true
    }

    /// Release every entry for an exact attempt lifecycle terminal.
    pub fn finish_attempt(&self, attempt: &str, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            let ids: Vec<String> = state
                .attempts
                .iter()
                .filter(|(_, entry)| entry.attempt == attempt)
                .map(|(id, _)| id.clone())
                .collect();
            for id in ids {
                if let Some(entry) = state.attempts.remove(&id) {
                    count += entry.relays.len();
                    if !entry.carrier.terminal_emitted {
                        let kind = match &terminal {
                            DeliveryTerminal::Accepted | DeliveryTerminal::AttemptCompleted => {
                                AttemptOutcomeKind::Accepted { session: None }
                            }
                            DeliveryTerminal::TypedRefused(reason) => {
                                AttemptOutcomeKind::TypedRefused(reason.clone())
                            }
                            DeliveryTerminal::AttemptReplaced => AttemptOutcomeKind::Replaced,
                            DeliveryTerminal::Cancelled | DeliveryTerminal::Shutdown => {
                                AttemptOutcomeKind::Cancelled
                            }
                        };
                        outcomes.push(AttemptOutcome {
                            source: entry.source,
                            attempt: entry.attempt.clone(),
                            event_id: entry.owned.value().id.clone(),
                            kind,
                        });
                    }
                    leases.push(entry.source_lease);
                    leases.push(entry.record_lease);
                    leases.push(entry.key_lease);
                    leases.extend(entry.correlation_lease);
                    leases.push(entry.map_lease);
                    leases.extend(
                        entry
                            .relays
                            .into_values()
                            .flat_map(|relay| [relay.lease, relay.map_lease]),
                    );
                }
            }
        }
        for lease in leases {
            lease.finish(terminal.clone());
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }

    /// Retire one relay session while preserving live attempts for a fresh
    /// reconnect.
    pub fn close_session(&self, session: RelaySessionId, terminal: DeliveryTerminal) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            if let Some(session_entry) = state.sessions.remove(&session) {
                leases.push(session_entry.record_lease);
                leases.push(session_entry.node_lease);
                leases.push(session_entry.entry_lease);
            }
            for (_, entry) in state.attempts.iter_mut() {
                if let Some(relay) = entry.relays.remove(&session) {
                    count += 1;
                    if entry.relays.is_empty() {
                        if let Some(kind) = entry.carrier.unavailable_outcome() {
                            outcomes.push(AttemptOutcome {
                                source: entry.source,
                                attempt: entry.attempt.clone(),
                                event_id: entry.owned.value().id.clone(),
                                kind,
                            });
                        }
                    }
                    leases.push(relay.lease);
                    leases.push(relay.map_lease);
                }
            }
        }
        for lease in leases {
            lease.finish(terminal.clone());
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }

    /// Release all per-relay custody and every live source owner.
    pub fn shutdown(&self) -> usize {
        let mut leases = Vec::new();
        let mut outcomes = Vec::new();
        let mut count = 0;
        {
            let mut state = self.state.lock();
            if state.closed {
                return 0;
            }
            state.closed = true;
            for (_, session_entry) in mem::take(&mut state.sessions).into_iter() {
                leases.push(session_entry.record_lease);
                leases.push(session_entry.node_lease);
                leases.push(session_entry.entry_lease);
            }
            for (_, entry) in mem::take(&mut state.attempts).into_iter() {
                count += entry.relays.len();
                if !entry.carrier.terminal_emitted {
                    outcomes.push(AttemptOutcome {
                        source: entry.source,
                        attempt: entry.attempt.clone(),
                        event_id: entry.owned.value().id.clone(),
                        kind: AttemptOutcomeKind::Cancelled,
                    });
                }
                leases.push(entry.source_lease);
                leases.push(entry.record_lease);
                leases.push(entry.key_lease);
                leases.extend(entry.correlation_lease);
                leases.push(entry.map_lease);
                leases.extend(
                    entry
                        .relays
                        .into_values()
                        .flat_map(|relay| [relay.lease, relay.map_lease]),
                );
            }
        }
        for lease in leases {
            lease.finish(DeliveryTerminal::Shutdown);
        }
        for outcome in outcomes {
            self.outcome_sink.outcome(outcome);
        }
        count
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nostr::event::{make_event, NostrIdentity, SIGNALING_EPHEMERAL_KIND};
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{OnceLock, Weak};

    fn open_test_session(store: &DeliveryStore) -> (RelaySessionId, Vec<AttemptRefusal>) {
        let (session, session_refusal, refused) = store.open_session_with_refusals();
        assert!(
            session_refusal.is_none(),
            "test session admission must succeed"
        );
        (session, refused)
    }

    struct CountingProvider {
        live: Arc<AtomicUsize>,
    }

    struct CountingLease {
        live: Arc<AtomicUsize>,
    }

    impl DeliveryLease for CountingLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    struct ByteLease {
        live: Arc<AtomicUsize>,
        bytes: Arc<AtomicUsize>,
        amount: usize,
    }

    impl DeliveryLease for ByteLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            self.live.fetch_sub(1, Ordering::SeqCst);
            self.bytes.fetch_sub(self.amount, Ordering::SeqCst);
        }
    }

    macro_rules! unmetered_reservations {
        () => {
            fn reserve_inbound_frame(
                &self,
                _frame_bytes: usize,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_identity(
                &self,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_record(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_set_node(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_session_entry(
                &self,
                _session: RelaySessionId,
                _retention: SessionRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_attempt_record(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }
        };
    }

    macro_rules! unmetered_admission_source {
        () => {
            fn reserve_admission_source(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }
        };
    }

    macro_rules! unmetered_exact_entries {
        () => {
            fn reserve_attempt_entry(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_relay_entry(
                &self,
                _attempt: &str,
                _session: RelaySessionId,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }

            fn reserve_attempt_correlation(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }
        };
    }

    macro_rules! unmetered_attempt_key {
        () => {
            fn reserve_attempt_key(
                &self,
                _attempt: &str,
                _event: &NostrEvent,
                _retention: DeliveryRetention,
            ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
                Ok(Box::new(UnmeteredLease))
            }
        };
    }

    impl DeliveryProvider for CountingProvider {
        unmetered_reservations!();
        unmetered_admission_source!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: self.live.clone(),
            }))
        }
    }

    struct ExactCustodyProvider {
        live: Arc<AtomicUsize>,
        bytes: Arc<AtomicUsize>,
        calls: Arc<Mutex<Vec<String>>>,
    }

    impl ExactCustodyProvider {
        fn lease_bytes(&self, label: &str, amount: usize) -> Box<dyn DeliveryLease> {
            self.calls.lock().push(label.to_string());
            self.live.fetch_add(1, Ordering::SeqCst);
            self.bytes.fetch_add(amount, Ordering::SeqCst);
            Box::new(ByteLease {
                live: Arc::clone(&self.live),
                bytes: Arc::clone(&self.bytes),
                amount,
            })
        }
    }

    impl DeliveryProvider for ExactCustodyProvider {
        unmetered_reservations!();
        unmetered_admission_source!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(self.lease_bytes("encoded-event", retention.encoded_event_bytes))
        }

        fn reserve_attempt_key(
            &self,
            _attempt: &str,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(self.lease_bytes("attempt-key", retention.attempt_key_bytes))
        }

        fn reserve_attempt_correlation(
            &self,
            attempt: &str,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(!attempt.is_empty());
            Ok(self.lease_bytes("attempt-correlation", attempt.len()))
        }

        fn reserve_attempt_entry(
            &self,
            _attempt: &str,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(retention.attempt_entry_bytes > 0);
            Ok(self.lease_bytes("attempt-entry", retention.attempt_entry_bytes))
        }

        fn reserve_relay_entry(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            assert!(retention.relay_entry_bytes > 0);
            Ok(self.lease_bytes("relay-entry", retention.relay_entry_bytes))
        }
    }

    struct OpenOnFinishProvider {
        store: Arc<OnceLock<Weak<DeliveryStore>>>,
        fresh: Arc<Mutex<Option<RelaySessionId>>>,
    }

    struct OpenOnFinishLease {
        store: Arc<OnceLock<Weak<DeliveryStore>>>,
        fresh: Arc<Mutex<Option<RelaySessionId>>>,
    }

    impl DeliveryLease for OpenOnFinishLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            let store = self
                .store
                .get()
                .expect("store weak reference is initialized")
                .upgrade()
                .expect("delivery store remains live during settlement");
            let (session, _) = open_test_session(&store);
            *self.fresh.lock() = Some(session);
        }
    }

    impl DeliveryProvider for OpenOnFinishProvider {
        unmetered_reservations!();
        unmetered_admission_source!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(Box::new(OpenOnFinishLease {
                store: Arc::clone(&self.store),
                fresh: Arc::clone(&self.fresh),
            }))
        }
    }

    struct DropMarker(Arc<AtomicBool>);

    impl Drop for DropMarker {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    struct RecordingOutcomeSink {
        outcomes: Arc<Mutex<Vec<AttemptOutcome>>>,
    }

    impl AttemptOutcomeSink for RecordingOutcomeSink {
        fn outcome(&self, outcome: AttemptOutcome) {
            self.outcomes.lock().push(outcome);
        }
    }

    fn recording_store(
        provider: Arc<dyn DeliveryProvider>,
    ) -> (Arc<DeliveryStore>, Arc<Mutex<Vec<AttemptOutcome>>>) {
        let outcomes = Arc::new(Mutex::new(Vec::new()));
        let store = DeliveryStore::new_with_outcome_sink(
            provider,
            Arc::new(RecordingOutcomeSink {
                outcomes: Arc::clone(&outcomes),
            }),
        );
        (store, outcomes)
    }

    struct RejectOnceProvider {
        live: Arc<AtomicUsize>,
        refused: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for RejectOnceProvider {
        unmetered_reservations!();
        unmetered_admission_source!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if self.refused.fetch_add(1, Ordering::SeqCst) == 0 {
                return Err(DeliveryRefusal::Provider("test refusal".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: self.live.clone(),
            }))
        }
    }

    struct ToggleProvider {
        allow: Arc<AtomicBool>,
        live: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for ToggleProvider {
        unmetered_reservations!();
        unmetered_admission_source!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if !self.allow.load(Ordering::SeqCst) {
                return Err(DeliveryRefusal::Provider("carrier unavailable".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: Arc::clone(&self.live),
            }))
        }
    }

    struct SourceResidueProvider {
        live: Arc<AtomicUsize>,
    }

    struct SourceResidueLease {
        live: Arc<AtomicUsize>,
    }

    impl DeliveryLease for SourceResidueLease {
        fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
            self.live.fetch_sub(1, Ordering::SeqCst);
        }
    }

    impl DeliveryProvider for SourceResidueProvider {
        unmetered_reservations!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve_admission_source(
            &self,
            _attempt: &str,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(SourceResidueLease {
                live: Arc::clone(&self.live),
            }))
        }

        fn reserve(
            &self,
            _attempt: &str,
            _session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(Box::new(UnmeteredLease))
        }
    }

    struct RefuseSpecificProvider {
        target: Arc<Mutex<Option<RelaySessionId>>>,
        live: Arc<AtomicUsize>,
    }

    impl DeliveryProvider for RefuseSpecificProvider {
        unmetered_reservations!();
        unmetered_admission_source!();
        unmetered_attempt_key!();
        unmetered_exact_entries!();

        fn reserve(
            &self,
            _attempt: &str,
            session: RelaySessionId,
            _event: &NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            if self.target.lock().as_ref() == Some(&session) {
                return Err(DeliveryRefusal::Provider("selected relay refusal".into()));
            }
            self.live.fetch_add(1, Ordering::SeqCst);
            Ok(Box::new(CountingLease {
                live: Arc::clone(&self.live),
            }))
        }
    }

    fn event() -> NostrEvent {
        make_event(
            &NostrIdentity::generate(),
            SIGNALING_EPHEMERAL_KIND,
            vec![],
            "attempt".into(),
            1,
        )
    }

    #[test]
    fn large_delivery_map_chain_unlinks_iteratively() {
        const CHAIN: usize = 100_000;
        fn chain(size: usize) -> DeliveryMap<usize, usize> {
            let mut map = DeliveryMap::new();
            for key in 0..size {
                let next = map.head.take();
                map.head = Some(Box::new(DeliveryMapNode {
                    key,
                    value: key,
                    next,
                }));
                map.len += 1;
            }
            map
        }

        let mut map = chain(CHAIN);
        assert_eq!(map.len(), CHAIN);
        assert_eq!(map.remove(&0), Some(0));
        assert_eq!(map.remove(&(CHAIN / 2)), Some(CHAIN / 2));
        assert_eq!(map.remove(&(CHAIN - 1)), Some(CHAIN - 1));
        assert_eq!(map.len(), CHAIN - 3);
        drop(map);

        let mut remainder = chain(CHAIN).into_iter();
        assert_eq!(remainder.next(), Some((CHAIN - 1, CHAIN - 1)));
        assert_eq!(remainder.next(), Some((CHAIN - 2, CHAIN - 2)));
        drop(remainder);
    }

    #[test]
    fn admission_source_mint_is_checked_and_non_aba() {
        let (_, next) = AdmissionSource::checked_value(1).expect("one is live");
        assert_eq!(next, 2);
        let (_, exhausted) = AdmissionSource::checked_value(u64::MAX)
            .expect("the final nonzero identity is still usable");
        assert_eq!(exhausted, 0, "zero is the permanent exhausted sentinel");
        assert!(AdmissionSource::checked_value(0).is_none());
        assert_ne!(
            AdmissionSource::try_fresh().expect("first test source exists"),
            AdmissionSource::try_fresh().expect("second test source exists"),
        );
    }

    #[test]
    fn local_admission_source_exhaustion_is_typed_without_rewinding_global_state() {
        let counter = AtomicU64::new(u64::MAX);
        assert_eq!(
            try_fresh_from(&counter),
            Some(AdmissionSource::Live(NonZeroU64::new(u64::MAX).unwrap()))
        );
        assert_eq!(try_fresh_from(&counter), None);
        assert_eq!(try_fresh_from(&counter), None);
        assert_ne!(
            AdmissionSource::try_fresh().expect("first test source exists"),
            AdmissionSource::try_fresh().expect("second test source exists"),
        );
    }

    #[test]
    fn exhausted_admission_is_typed_and_never_dispatches_provider_custody() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(SourceResidueProvider {
            live: Arc::clone(&live),
        }));
        let (session, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = exhausted_admission_report(owned);
        assert_eq!(report.source, AdmissionSource::Unavailable);
        assert_eq!(report.accepted_sessions, 0);
        assert_eq!(
            report.attempt_refusal,
            Some(AdmissionRefusal::AdmissionIdentityExhausted)
        );
        assert!(!store.settle_source(
            report.source,
            &session,
            &event_id,
            DeliveryTerminal::Accepted,
        ));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn outcome_sink_records_exact_accepted_relay_custody() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("accepted-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(&session, &event_id, DeliveryTerminal::Accepted));

        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, report.source);
        assert_eq!(records[0].attempt, "accepted-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(
            records[0].kind,
            AttemptOutcomeKind::Accepted {
                session: Some(session)
            }
        );
    }

    #[test]
    fn outcome_sink_aggregates_carrier_unavailable_after_all_relays_close() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = open_test_session(&store);
        let (second, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("carrier-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        store.close_session(first, DeliveryTerminal::Cancelled);
        store.close_session(second, DeliveryTerminal::Cancelled);

        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, report.source);
        assert_eq!(records[0].attempt, "carrier-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(records[0].kind, AttemptOutcomeKind::CarrierUnavailable);
    }

    #[test]
    fn outcome_sink_records_typed_refusal_for_exact_attempt() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("refused-attempt".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(
            &session,
            &event_id,
            DeliveryTerminal::TypedRefused("negotiation rejected".into()),
        ));

        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, report.source);
        assert_eq!(records[0].attempt, "refused-attempt");
        assert_eq!(records[0].event_id, event_id);
        assert_eq!(
            records[0].kind,
            AttemptOutcomeKind::TypedRefused("negotiation rejected".into())
        );
    }

    #[test]
    fn outcome_sink_records_replaced_and_cancelled_attempt_terminals() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (session, _) = open_test_session(&store);
        let replaced = event();
        let replaced_id = replaced.id.clone();
        let replaced_report = store.admit(
            "replaced-attempt".into(),
            OwnedSignal::new(replaced, Box::new(()) as ErasedOwner),
        );
        assert!(store.finish_attempt("replaced-attempt", DeliveryTerminal::AttemptReplaced) > 0);
        let cancelled = event();
        let cancelled_id = cancelled.id.clone();
        let cancelled_report = store.admit(
            "cancelled-attempt".into(),
            OwnedSignal::new(cancelled, Box::new(()) as ErasedOwner),
        );
        assert!(store.finish_attempt("cancelled-attempt", DeliveryTerminal::Cancelled) > 0);
        store.close_session(session, DeliveryTerminal::Cancelled);

        let records = outcomes.lock();
        assert!(records.iter().any(|record| {
            record.attempt == "replaced-attempt"
                && record.source == replaced_report.source
                && record.event_id == replaced_id
                && record.kind == AttemptOutcomeKind::Replaced
        }));
        assert!(records.iter().any(|record| {
            record.attempt == "cancelled-attempt"
                && record.source == cancelled_report.source
                && record.event_id == cancelled_id
                && record.kind == AttemptOutcomeKind::Cancelled
        }));
    }

    #[test]
    fn stale_session_terminal_cannot_settle_fresh_attempt_outcome() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (stale, _) = open_test_session(&store);
        let old = event();
        store.admit(
            "old-attempt".into(),
            OwnedSignal::new(old, Box::new(()) as ErasedOwner),
        );
        store.close_session(stale.clone(), DeliveryTerminal::Cancelled);

        let (fresh, _) = open_test_session(&store);
        let current = event();
        let current_id = current.id.clone();
        store.admit(
            "fresh-attempt".into(),
            OwnedSignal::new(current, Box::new(()) as ErasedOwner),
        );
        assert!(!store.settle(&stale, &current_id, DeliveryTerminal::Accepted));
        assert!(store.settle(&fresh, &current_id, DeliveryTerminal::Accepted));

        let records = outcomes.lock();
        assert!(records.iter().any(|record| {
            record.attempt == "old-attempt" && record.kind == AttemptOutcomeKind::CarrierUnavailable
        }));
        assert!(records.iter().any(|record| {
            record.attempt == "fresh-attempt"
                && record.event_id == current_id
                && matches!(record.kind, AttemptOutcomeKind::Accepted { .. })
        }));
    }

    #[test]
    fn relay_entries_settle_independently_and_reconnect_is_fresh() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(CountingProvider { live: live.clone() }));
        let (a, _) = open_test_session(&store);
        let (b, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let id = owned.value().id.clone();
        let report = store.admit("attempt-1".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        assert!(report.refused.is_empty());
        assert_eq!(live.load(Ordering::SeqCst), 2);
        assert!(store.settle(&a, &id, DeliveryTerminal::Accepted));
        assert_eq!(live.load(Ordering::SeqCst), 1);
        assert!(store.settle(&b, &id, DeliveryTerminal::TypedRefused("no".into())));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(
            store.finish_attempt("attempt-1", DeliveryTerminal::AttemptCompleted),
            0
        );
        store.close_session(a, DeliveryTerminal::Cancelled);
        store.close_session(b, DeliveryTerminal::Cancelled);
        let (c, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let id = owned.value().id.clone();
        let report = store.admit("attempt-2".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(store.next_pending(&c), Some(id.clone()));
        store.close_session(c.clone(), DeliveryTerminal::Cancelled);
        let (d, _) = open_test_session(&store);
        assert_eq!(store.next_pending(&d), Some(id.clone()));
        assert!(!store.settle(&c, &id, DeliveryTerminal::Accepted));
        store.close_session(d, DeliveryTerminal::Cancelled);
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn final_settlement_removes_attempt_before_reentrant_reconnect() {
        let store_ref = Arc::new(OnceLock::new());
        let fresh_session = Arc::new(Mutex::new(None));
        let store = DeliveryStore::new(Arc::new(OpenOnFinishProvider {
            store: Arc::clone(&store_ref),
            fresh: Arc::clone(&fresh_session),
        }));
        assert!(store_ref.set(Arc::downgrade(&store)).is_ok());

        let (old_session, _) = open_test_session(&store);
        let owner_dropped = Arc::new(AtomicBool::new(false));
        let event = event();
        let event_id = event.id.clone();
        let report = store.admit(
            "attempt-reentrant-reconnect".into(),
            OwnedSignal::new(
                event,
                Box::new(DropMarker(Arc::clone(&owner_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(report.accepted_sessions, 1);

        assert!(store.settle(&old_session, &event_id, DeliveryTerminal::Accepted));
        assert!(owner_dropped.load(Ordering::SeqCst));
        let fresh = fresh_session
            .lock()
            .clone()
            .expect("lease finish opens a fresh session");
        assert!(store.next_pending(&fresh).is_none());
        assert!(!store.settle(&fresh, &event_id, DeliveryTerminal::Accepted));
    }

    #[test]
    fn duplicate_live_event_refusal_preserves_original_custody() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live: live.clone() }));
        let (session, _) = open_test_session(&store);
        let event = event();
        let event_id = event.id.clone();
        let original_dropped = Arc::new(AtomicBool::new(false));
        let first = store.admit(
            "attempt-same-source".into(),
            OwnedSignal::new(
                event.clone(),
                Box::new(DropMarker(Arc::clone(&original_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(first.accepted_sessions, 1);
        assert_eq!(first.attempt_refusal, None);
        assert_eq!(live.load(Ordering::SeqCst), 1);

        let duplicate_dropped = Arc::new(AtomicBool::new(false));
        let duplicate = store.admit(
            "attempt-same-source".into(),
            OwnedSignal::new(
                event,
                Box::new(DropMarker(Arc::clone(&duplicate_dropped))) as ErasedOwner,
            ),
        );
        assert_eq!(duplicate.accepted_sessions, 0);
        assert!(duplicate.refused.is_empty());
        assert_eq!(
            duplicate.attempt_refusal,
            Some(AdmissionRefusal::DuplicateLiveEvent)
        );
        assert_ne!(first.source, duplicate.source);
        assert!(duplicate_dropped.load(Ordering::SeqCst));
        assert!(!original_dropped.load(Ordering::SeqCst));
        assert_eq!(store.next_pending(&session), Some(event_id.clone()));
        assert_eq!(live.load(Ordering::SeqCst), 1);

        assert!(!store.settle_source(
            duplicate.source,
            &session,
            &event_id,
            DeliveryTerminal::Accepted,
        ));
        assert!(store.settle_source(
            first.source,
            &session,
            &event_id,
            DeliveryTerminal::Accepted,
        ));
        assert!(original_dropped.load(Ordering::SeqCst));
        assert_eq!(live.load(Ordering::SeqCst), 0);
        let records = outcomes.lock();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].source, first.source);
        assert_eq!(records[0].event_id, event_id);
        assert!(!store.settle(&session, &event_id, DeliveryTerminal::Accepted));
    }

    #[test]
    fn admission_source_residual_is_exactly_settled_on_duplicate_and_terminal() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(SourceResidueProvider {
            live: Arc::clone(&live),
        }));
        let (session, _) = open_test_session(&store);
        let event = event();
        let event_id = event.id.clone();
        let first = store.admit(
            "source-residual".into(),
            OwnedSignal::new(event.clone(), Box::new(()) as ErasedOwner),
        );
        assert_eq!(first.accepted_sessions, 1);
        assert_eq!(live.load(Ordering::SeqCst), 1);

        let duplicate = store.admit(
            "source-residual".into(),
            OwnedSignal::new(event, Box::new(()) as ErasedOwner),
        );
        assert_eq!(
            duplicate.attempt_refusal,
            Some(AdmissionRefusal::DuplicateLiveEvent)
        );
        assert_eq!(
            live.load(Ordering::SeqCst),
            1,
            "duplicate source residual settles immediately"
        );
        assert!(!store.settle_source(
            duplicate.source,
            &session,
            &event_id,
            DeliveryTerminal::Accepted,
        ));
        assert!(store.settle_source(
            first.source,
            &session,
            &event_id,
            DeliveryTerminal::Accepted,
        ));
        assert_eq!(live.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn one_provider_refusal_keeps_healthy_relay_entry() {
        let live = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(RejectOnceProvider {
            live: live.clone(),
            refused: Arc::new(AtomicUsize::new(0)),
        }));
        let (a, _) = open_test_session(&store);
        let (b, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let report = store.admit("partial".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(report.refused.len(), 1);
        assert_eq!(live.load(Ordering::SeqCst), 1);
        let id = report.event_id;
        assert!(store.next_pending(&a).is_none() || store.next_pending(&b).is_none());
        assert_eq!(
            store.finish_attempt("partial", DeliveryTerminal::AttemptReplaced),
            1
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert!(!store.settle(&a, &id, DeliveryTerminal::Accepted));
    }

    #[test]
    fn admission_refusal_permutation_preserves_the_other_relay() {
        fn exercise(refuse_first: bool) {
            let target = Arc::new(Mutex::new(None));
            let live = Arc::new(AtomicUsize::new(0));
            let store = DeliveryStore::new(Arc::new(RefuseSpecificProvider {
                target: Arc::clone(&target),
                live: Arc::clone(&live),
            }));
            let (first, _) = open_test_session(&store);
            let (second, _) = open_test_session(&store);
            let refused = if refuse_first {
                first.clone()
            } else {
                second.clone()
            };
            let healthy = if refuse_first { second } else { first };
            *target.lock() = Some(refused);

            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let id = owned.value().id.clone();
            let report = store.admit("admission-permutation".into(), owned);
            assert_eq!(report.accepted_sessions, 1);
            assert_eq!(report.refused.len(), 1);
            assert!(report.attempt_refusal.is_none());
            assert_eq!(store.next_pending(&healthy), Some(id.clone()));
            assert_eq!(live.load(Ordering::SeqCst), 1);
            assert_eq!(
                store.finish_attempt("admission-permutation", DeliveryTerminal::Accepted),
                1
            );
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }

        exercise(true);
        exercise(false);
    }

    #[test]
    fn relay_refusal_outcome_is_order_independent_while_peer_remains_viable() {
        fn exercise(reverse: bool) {
            let live = Arc::new(AtomicUsize::new(0));
            let (store, outcomes) = recording_store(Arc::new(CountingProvider {
                live: Arc::clone(&live),
            }));
            let (first_session, _) = open_test_session(&store);
            let (second_session, _) = open_test_session(&store);
            let (first, second) = if reverse {
                (second_session, first_session)
            } else {
                (first_session, second_session)
            };
            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let id = owned.value().id.clone();
            let report = store.admit("refusal-order".into(), owned);
            assert_eq!(report.accepted_sessions, 2);

            assert!(store.settle(
                &first,
                &id,
                DeliveryTerminal::TypedRefused("first relay refused".into()),
            ));
            assert!(outcomes.lock().is_empty());
            assert_eq!(store.next_pending(&second), Some(id.clone()));
            assert_eq!(live.load(Ordering::SeqCst), 1);

            assert!(store.settle(&second, &id, DeliveryTerminal::Accepted));
            let records = outcomes.lock();
            assert_eq!(records.len(), 1);
            assert!(matches!(
                records[0].kind,
                AttemptOutcomeKind::Accepted { .. }
            ));
            assert_eq!(live.load(Ordering::SeqCst), 0);
        }

        exercise(false);
        exercise(true);
    }

    #[test]
    fn carrier_aggregate_is_deterministic_and_reconnect_scoped() {
        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = open_test_session(&store);
        let (second, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("aggregate-accepted".into(), owned);
        assert_eq!(report.accepted_sessions, 2);
        assert!(store.settle(&first, &event_id, DeliveryTerminal::Accepted));
        assert!(store.settle(&second, &event_id, DeliveryTerminal::Accepted));
        assert_eq!(outcomes.lock().len(), 1);

        fn refusal_order(reverse: bool) -> String {
            let live = Arc::new(AtomicUsize::new(0));
            let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
            let (first, _) = open_test_session(&store);
            let (second, _) = open_test_session(&store);
            let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
            let event_id = owned.value().id.clone();
            let report = store.admit("aggregate-refusal".into(), owned);
            assert_eq!(report.accepted_sessions, 2);
            let (earlier, later) = if reverse {
                (second, first)
            } else {
                (first, second)
            };
            assert!(store.settle(
                &earlier,
                &event_id,
                DeliveryTerminal::TypedRefused("z-last".into()),
            ));
            assert!(outcomes.lock().is_empty());
            assert!(store.settle(
                &later,
                &event_id,
                DeliveryTerminal::TypedRefused("a-first".into()),
            ));
            let records = outcomes.lock();
            assert_eq!(records.len(), 1);
            assert_eq!(
                records[0].kind,
                AttemptOutcomeKind::TypedRefused("a-first".into())
            );
            records[0].attempt.clone()
        }

        assert_eq!(refusal_order(false), refusal_order(true));

        let live = Arc::new(AtomicUsize::new(0));
        let (store, outcomes) = recording_store(Arc::new(CountingProvider { live }));
        let (first, _) = open_test_session(&store);
        let (second, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        store.admit("aggregate-reconnect".into(), owned);
        store.close_session(first, DeliveryTerminal::Cancelled);
        assert!(outcomes.lock().is_empty());
        store.close_session(second, DeliveryTerminal::Cancelled);
        assert_eq!(outcomes.lock().len(), 1);
        let (fresh, _) = open_test_session(&store);
        assert!(store.next_pending(&fresh).is_some());
        store.close_session(fresh, DeliveryTerminal::Cancelled);
        assert_eq!(outcomes.lock().len(), 2);
    }

    #[test]
    fn all_carrier_refusal_is_once_only_and_rearms_after_eligible_reconnect() {
        let allow = Arc::new(AtomicBool::new(true));
        let live = Arc::new(AtomicUsize::new(0));
        let provider = Arc::new(ToggleProvider {
            allow: Arc::clone(&allow),
            live: Arc::clone(&live),
        });
        let store = DeliveryStore::new(provider);
        let (initial, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let report = store.admit("all-carrier-once".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert!(store.settle(&initial, &event_id, DeliveryTerminal::Cancelled,));
        assert_eq!(live.load(Ordering::SeqCst), 0);

        allow.store(false, Ordering::SeqCst);
        let (_, first_session_refusal, first_refusals) = store.open_session_with_refusals();
        assert!(first_session_refusal.is_none());
        assert_eq!(first_refusals.len(), 1);
        assert_eq!(first_refusals[0].attempt, "all-carrier-once");
        assert_eq!(first_refusals[0].event_id, event_id);
        let (_, second_session_refusal, second_refusals) = store.open_session_with_refusals();
        assert!(second_session_refusal.is_none());
        assert!(second_refusals.is_empty());

        allow.store(true, Ordering::SeqCst);
        let (fresh, fresh_session_refusal, fresh_refusals) = store.open_session_with_refusals();
        assert!(fresh_session_refusal.is_none());
        assert!(fresh_refusals.is_empty());
        assert_eq!(store.next_pending(&fresh), Some(event_id.clone()));
        assert!(store.settle(&fresh, &event_id, DeliveryTerminal::Cancelled));
        assert_eq!(live.load(Ordering::SeqCst), 0);

        allow.store(false, Ordering::SeqCst);
        let (_, third_session_refusal, third_refusals) = store.open_session_with_refusals();
        assert!(third_session_refusal.is_none());
        assert_eq!(third_refusals.len(), 1);
        assert_eq!(third_refusals[0].attempt, "all-carrier-once");
        assert_eq!(third_refusals[0].event_id, event_id);
    }

    #[test]
    fn provider_delta_covers_correlation_and_each_exact_entry() {
        let live = Arc::new(AtomicUsize::new(0));
        let calls = Arc::new(Mutex::new(Vec::new()));
        let retention = DeliveryRetention::for_attempt("exact-correlation", &event());
        assert_eq!(retention.structural_entry_bytes, 0);
        assert_eq!(retention.attempt_record_bytes, 0);
        assert_eq!(
            retention.attempt_entry_bytes,
            std::mem::size_of::<DeliveryMapNode<String, AttemptEntry>>()
        );
        assert_eq!(
            retention.relay_entry_bytes,
            std::mem::size_of::<DeliveryMapNode<RelaySessionId, RelayEntry>>()
        );
        let session_retention = SessionRetention::exact();
        assert!(session_retention.session_identity_bytes > 0);
        assert_eq!(
            session_retention.session_identity_bytes,
            std::mem::size_of::<Arc<()>>(),
            "Arc retention is an accounting commitment, not heap-layout arithmetic"
        );
        assert_eq!(
            session_retention.session_record_bytes,
            session_retention.session_identity_bytes
        );
        assert_eq!(session_retention.session_set_node_bytes, 0);
        assert!(session_retention.session_entry_bytes > 0);
        let bytes = Arc::new(AtomicUsize::new(0));
        let store = DeliveryStore::new(Arc::new(ExactCustodyProvider {
            live: Arc::clone(&live),
            bytes: Arc::clone(&bytes),
            calls: Arc::clone(&calls),
        }));
        let (session, _) = open_test_session(&store);
        let owned = OwnedSignal::new(event(), Box::new(()) as ErasedOwner);
        let event_id = owned.value().id.clone();
        let expected_retained_bytes = retention.attempt_key_bytes
            + retention.attempt_entry_bytes
            + "exact-correlation".len()
            + retention.encoded_event_bytes
            + retention.relay_entry_bytes;
        let baseline_bytes = bytes.load(Ordering::SeqCst);
        let report = store.admit("exact-correlation".into(), owned);
        assert_eq!(report.accepted_sessions, 1);
        assert_eq!(
            *calls.lock(),
            vec![
                "attempt-key".to_string(),
                "attempt-correlation".to_string(),
                "attempt-entry".to_string(),
                "encoded-event".to_string(),
                "relay-entry".to_string(),
            ]
        );
        assert_eq!(live.load(Ordering::SeqCst), 5);
        assert_eq!(
            bytes.load(Ordering::SeqCst),
            baseline_bytes + expected_retained_bytes
        );
        assert_eq!(
            store.finish_attempt("exact-correlation", DeliveryTerminal::Accepted),
            1
        );
        assert_eq!(live.load(Ordering::SeqCst), 0);
        assert_eq!(bytes.load(Ordering::SeqCst), baseline_bytes);
        assert!(!store.settle(&session, &event_id, DeliveryTerminal::Accepted));
    }
}
