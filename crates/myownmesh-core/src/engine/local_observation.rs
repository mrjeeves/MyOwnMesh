//! Node-local observation evidence.
//!
//! This module is deliberately not part of the semantic graph.  Its records
//! are local diagnostics about what this node saw, referred, or observed as an
//! outcome.  They are not facts, signatures, authority, routing input, or
//! wire material.  The store is an aggregate cache: repeating the same
//! subject/referrer/locator observation updates one bounded record instead of
//! appending an event history.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Instant;

use crate::resource::{
    LeasedMap, LocalApplicationResourceScope, ResourceClaimArithmeticError, ResourceUnavailable,
};
use crate::semantic::DeviceId;

/// A full raw Ed25519 public key used by this local cache.
///
/// The cache accepts an already validated [`DeviceId`] and stores only its
/// fixed raw bytes.  It therefore retains neither an interned semantic
/// `DeviceId` pointee nor an unbounded display string.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ObservationDeviceKey([u8; 32]);

impl ObservationDeviceKey {
    pub(super) fn from_device(device: &DeviceId) -> Self {
        Self(device.as_bytes())
    }
}

/// A bounded local locator.  A locator is evidence's coordinate only; it is
/// never a capability or an authority-bearing address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) enum ObservationLocator {
    Socket(SocketAddr),
    ViaPeer(ObservationDeviceKey),
}

impl ObservationLocator {
    fn lower_bound() -> Self {
        Self::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn mentions(self, peer: ObservationDeviceKey) -> bool {
        matches!(self, Self::ViaPeer(candidate) if candidate == peer)
    }
}

/// All provenance is explicit and typed.  `referrer = None` means the local
/// node observed the subject directly; it does not mean an unknown identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ObservationProvenance {
    pub(super) observer: ObservationDeviceKey,
    pub(super) referrer: Option<ObservationDeviceKey>,
    pub(super) subject: ObservationDeviceKey,
}

/// Whether a sighting only claimed a locator or was authenticated locally.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservationSighting {
    #[cfg(all(test, feature = "transport-lab"))]
    ClaimedLocator,
    Authenticated,
}

/// Local outcome classes.  These names describe this node's observation and
/// deliberately do not reuse semantic admission or authority vocabulary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ObservationOutcome {
    Succeeded,
    #[cfg(all(test, feature = "transport-lab"))]
    Failed,
    #[cfg(all(test, feature = "transport-lab"))]
    Stale,
    #[cfg(all(test, feature = "transport-lab"))]
    KeyMismatch,
}

/// A local monotonic clock value.  It is meaningful only inside one node.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ObservationTick(pub(super) u64);

/// Clock injection seam for deterministic maintenance and expiry controls.
pub(super) trait ObservationClock: Clone + Send + Sync {
    fn now(&self) -> ObservationTick;
}

/// Production clock.  It never accepts peer-supplied timestamps and cannot be
/// compared across nodes.
#[derive(Clone)]
pub(super) struct MonotonicObservationClock {
    origin: Instant,
}

impl MonotonicObservationClock {
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl ObservationClock for MonotonicObservationClock {
    fn now(&self) -> ObservationTick {
        ObservationTick(u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX))
    }
}

/// Explicit finite limits for one node-local observation owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct LocalObservationLimits {
    pub(super) max_records: usize,
    pub(super) max_records_per_subject: usize,
    pub(super) max_age_ticks: u64,
    pub(super) max_maintenance_work: usize,
}

impl LocalObservationLimits {
    fn validate(self) -> Result<(), LocalObservationRefusal> {
        if self.max_records == 0
            || self.max_records_per_subject == 0
            || self.max_age_ticks == 0
            || self.max_maintenance_work == 0
        {
            return Err(LocalObservationRefusal::Disabled);
        }
        if self.max_records_per_subject > self.max_records {
            return Err(LocalObservationRefusal::InvalidLimits);
        }
        Ok(())
    }
}

/// Local-only refusal.  No variant represents a semantic or wire decision.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub(super) enum LocalObservationRefusal {
    #[error("local observation is disabled")]
    Disabled,
    #[error("local observation limits are invalid")]
    InvalidLimits,
    #[error("local observation cache is at capacity")]
    Capacity,
    #[error("local observation clock moved backwards")]
    ClockRegression,
    #[error("local observation time arithmetic overflowed")]
    TimeOverflow,
    #[error("local observation resource claim arithmetic failed")]
    ResourceArithmetic,
    #[error("local observation generation overflowed")]
    GenerationOverflow,
    #[error("local observation outcome ticket is stale")]
    StaleOutcome,
    #[error("local observation owner does not match the retained record")]
    OwnerMismatch,
    #[error("local observation owner has been retired")]
    OwnerRetired,
    #[error("local observation success requires an authenticated sighting")]
    UnauthenticatedOutcome,
    #[error("local observation index invariant failed")]
    Invariant,
    #[error("local observation provider refused the retained entry: {0}")]
    Provider(ResourceUnavailable),
}

impl From<ResourceUnavailable> for LocalObservationRefusal {
    fn from(value: ResourceUnavailable) -> Self {
        Self::Provider(value)
    }
}

impl From<ResourceClaimArithmeticError> for LocalObservationRefusal {
    fn from(value: ResourceClaimArithmeticError) -> Self {
        match value {
            ResourceClaimArithmeticError::Overflow { .. }
            | ResourceClaimArithmeticError::Underflow { .. } => Self::ResourceArithmetic,
        }
    }
}

/// Subject-first aggregate key.  Referrer, subject, and locator are all
/// bounded fixed-width values; the map has no string or peer-pointer key.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct ObservationKey {
    pub(super) subject: ObservationDeviceKey,
    pub(super) referrer: Option<ObservationDeviceKey>,
    pub(super) locator: ObservationLocator,
}

impl ObservationKey {
    fn from_provenance(provenance: ObservationProvenance, locator: ObservationLocator) -> Self {
        Self {
            subject: provenance.subject,
            referrer: provenance.referrer,
            locator,
        }
    }

    fn lower_bound(subject: ObservationDeviceKey) -> Self {
        Self {
            subject,
            referrer: None,
            locator: ObservationLocator::lower_bound(),
        }
    }

    fn mentions(self, peer: ObservationDeviceKey) -> bool {
        self.subject == peer || self.referrer == Some(peer) || self.locator.mentions(peer)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) struct SightingCounters {
    pub(super) claimed: u64,
    pub(super) authenticated: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) struct OutcomeCounters {
    pub(super) succeeded: u64,
    pub(super) failed: u64,
    pub(super) stale: u64,
    pub(super) key_mismatch: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub(super) struct ObservationCounters {
    pub(super) sightings: SightingCounters,
    pub(super) referrals: u64,
    pub(super) outcomes: OutcomeCounters,
}

impl ObservationCounters {
    fn sighting(self, kind: ObservationSighting) -> Result<Self, LocalObservationRefusal> {
        let mut next = self;
        match kind {
            #[cfg(all(test, feature = "transport-lab"))]
            ObservationSighting::ClaimedLocator => {
                next.sightings.claimed = next
                    .sightings
                    .claimed
                    .checked_add(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
            }
            ObservationSighting::Authenticated => {
                next.sightings.authenticated = next
                    .sightings
                    .authenticated
                    .checked_add(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
            }
        }
        Ok(next)
    }

    fn referral(self) -> Result<Self, LocalObservationRefusal> {
        let mut next = self;
        next.referrals = next
            .referrals
            .checked_add(1)
            .ok_or(LocalObservationRefusal::Invariant)?;
        Ok(next)
    }

    fn outcome(self, outcome: ObservationOutcome) -> Result<Self, LocalObservationRefusal> {
        let mut next = self;
        let counter = match outcome {
            ObservationOutcome::Succeeded => &mut next.outcomes.succeeded,
            #[cfg(all(test, feature = "transport-lab"))]
            ObservationOutcome::Failed => &mut next.outcomes.failed,
            #[cfg(all(test, feature = "transport-lab"))]
            ObservationOutcome::Stale => &mut next.outcomes.stale,
            #[cfg(all(test, feature = "transport-lab"))]
            ObservationOutcome::KeyMismatch => &mut next.outcomes.key_mismatch,
        };
        *counter = counter
            .checked_add(1)
            .ok_or(LocalObservationRefusal::Invariant)?;
        Ok(next)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ObservationAggregate {
    pub(super) observer: ObservationDeviceKey,
    pub(super) sequence: u64,
    pub(super) counters: ObservationCounters,
    pub(super) first_seen: ObservationTick,
    pub(super) last_seen: ObservationTick,
    pub(super) expires_at: ObservationTick,
}

/// Opaque local outcome capability.  Both the purge generation and the exact
/// record sequence are required, so a delayed outcome cannot mutate a
/// successor record under the same subject/referrer/locator key.  The
/// authenticated bit additionally prevents a referral or claimed-locator
/// ticket from being presented as a successful operation result; failure
/// classes remain attributable before authentication completes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ObservationOutcomeTicket {
    key: ObservationKey,
    generation: u64,
    sequence: u64,
    authenticated: bool,
}

/// One provider-funded compact observation cache.
///
/// `records` is the only retained dynamic collection.  Its subject-first key
/// makes subject scans bounded by `max_records_per_subject`; a maintenance
/// cursor bounds expiry work without an expiry index or a whole-cache scan on
/// each insertion.  The resource scope is declared last so map leases release
/// before the scope token itself is dropped.
pub(super) struct LocalObservationGraph<C: ObservationClock> {
    records: LeasedMap<ObservationKey, ObservationAggregate>,
    limits: LocalObservationLimits,
    clock: C,
    next_sequence: u64,
    generation: u64,
    record_count: usize,
    last_now: Option<ObservationTick>,
    maintenance_cursor: Option<ObservationKey>,
    retired: bool,
    resources: LocalApplicationResourceScope,
}

impl<C: ObservationClock> LocalObservationGraph<C> {
    pub(super) fn new(
        resources: LocalApplicationResourceScope,
        limits: LocalObservationLimits,
        clock: C,
    ) -> Result<Self, LocalObservationRefusal> {
        limits.validate()?;
        Ok(Self {
            records: LeasedMap::new(),
            limits,
            clock,
            next_sequence: 1,
            generation: 0,
            record_count: 0,
            last_now: None,
            maintenance_cursor: None,
            retired: false,
            resources,
        })
    }

    fn now(&mut self) -> Result<ObservationTick, LocalObservationRefusal> {
        let now = self.clock.now();
        if self.last_now.is_some_and(|last| now < last) {
            return Err(LocalObservationRefusal::ClockRegression);
        }
        self.last_now = Some(now);
        Ok(now)
    }

    fn expiry(&self, now: ObservationTick) -> Result<ObservationTick, LocalObservationRefusal> {
        now.0
            .checked_add(self.limits.max_age_ticks)
            .map(ObservationTick)
            .ok_or(LocalObservationRefusal::TimeOverflow)
    }

    fn next_key_after(&self, cursor: Option<&ObservationKey>) -> Option<ObservationKey> {
        self.records
            .successor_after(cursor)
            .map(|(key, _)| *key)
            .or_else(|| {
                cursor.and_then(|_| self.records.successor_after(None).map(|(key, _)| *key))
            })
    }

    fn bump_generation(&mut self) -> Result<(), LocalObservationRefusal> {
        self.generation = self
            .generation
            .checked_add(1)
            .ok_or(LocalObservationRefusal::GenerationOverflow)?;
        Ok(())
    }

    /// Perform at most the configured maintenance quantum.  Expired entries
    /// not reached in this pass remain in storage but are filtered from every
    /// read path, so expiry is never dependent on a timely purge.
    fn maintain_at(&mut self, now: ObservationTick) -> Result<usize, LocalObservationRefusal> {
        let mut cursor = self.maintenance_cursor;
        let start = self.next_key_after(cursor.as_ref());
        let mut removed: usize = 0;
        for step in 0..self.limits.max_maintenance_work {
            let Some(key) = self.next_key_after(cursor.as_ref()) else {
                cursor = None;
                break;
            };
            if step > 0 && Some(key) == start {
                break;
            }
            cursor = Some(key);
            let expired = self
                .records
                .get(&key)
                .is_some_and(|record| record.expires_at <= now);
            if expired {
                if self.generation == u64::MAX {
                    return Err(LocalObservationRefusal::GenerationOverflow);
                }
                self.records
                    .remove(&key)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                self.record_count = self
                    .record_count
                    .checked_sub(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                self.bump_generation()?;
                removed = removed
                    .checked_add(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
            }
        }
        self.maintenance_cursor = cursor;
        Ok(removed)
    }

    /// Run one bounded maintenance quantum using the owner-local monotonic
    /// clock.  This is the only periodic hook needed by the adapter: it does
    /// not create a timer or scan beyond `max_maintenance_work` entries.
    pub(super) fn maintain_now(&mut self) -> Result<usize, LocalObservationRefusal> {
        if self.retired {
            return Ok(0);
        }
        let now = self.now()?;
        self.maintain_at(now)
    }

    fn first_subject_key(&self, subject: ObservationDeviceKey) -> Option<ObservationKey> {
        let floor = ObservationKey::lower_bound(subject);
        self.records.get(&floor).map(|_| floor).or_else(|| {
            self.records
                .successor_after(Some(&floor))
                .map(|(key, _)| *key)
        })
    }

    fn subject_count(
        &self,
        subject: ObservationDeviceKey,
    ) -> Result<usize, LocalObservationRefusal> {
        let mut cursor = self.first_subject_key(subject);
        let mut count: usize = 0;
        while let Some(key) = cursor {
            if key.subject != subject {
                break;
            }
            count = count
                .checked_add(1)
                .ok_or(LocalObservationRefusal::Invariant)?;
            cursor = self
                .records
                .successor_after(Some(&key))
                .map(|(next, _)| *next);
            if count >= self.limits.max_records_per_subject {
                break;
            }
        }
        Ok(count)
    }

    fn insert_new(
        &mut self,
        key: ObservationKey,
        provenance: ObservationProvenance,
        counters: ObservationCounters,
        authenticated: bool,
        now: ObservationTick,
    ) -> Result<ObservationOutcomeTicket, LocalObservationRefusal> {
        if self.record_count >= self.limits.max_records
            || self.subject_count(key.subject)? >= self.limits.max_records_per_subject
        {
            return Err(LocalObservationRefusal::Capacity);
        }
        let sequence = self.next_sequence;
        let next_sequence = sequence
            .checked_add(1)
            .ok_or(LocalObservationRefusal::Invariant)?;
        let expiry = self.expiry(now)?;
        let node_claim = LeasedMap::<ObservationKey, ObservationAggregate>::entry_claim()?;
        let lease = self.resources.acquire(node_claim)?;
        let aggregate = ObservationAggregate {
            observer: provenance.observer,
            sequence,
            counters,
            first_seen: now,
            last_seen: now,
            expires_at: expiry,
        };
        if self.records.insert(key, aggregate, lease).is_err() {
            return Err(LocalObservationRefusal::Invariant);
        }
        self.next_sequence = next_sequence;
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(LocalObservationRefusal::Invariant)?;
        Ok(ObservationOutcomeTicket {
            key,
            generation: self.generation,
            sequence,
            authenticated,
        })
    }

    fn observe(
        &mut self,
        provenance: ObservationProvenance,
        locator: ObservationLocator,
        counters: ObservationCounters,
        authenticated: bool,
    ) -> Result<ObservationOutcomeTicket, LocalObservationRefusal> {
        if self.retired {
            return Err(LocalObservationRefusal::OwnerRetired);
        }
        let now = self.now()?;
        self.maintain_at(now)?;
        let key = ObservationKey::from_provenance(provenance, locator);
        if let Some(existing) = self.records.get(&key) {
            if existing.observer != provenance.observer {
                return Err(LocalObservationRefusal::OwnerMismatch);
            }
            if existing.expires_at <= now {
                if self.generation == u64::MAX {
                    return Err(LocalObservationRefusal::GenerationOverflow);
                }
                self.records
                    .remove(&key)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                self.record_count = self
                    .record_count
                    .checked_sub(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                self.bump_generation()?;
                return self.insert_new(key, provenance, counters, authenticated, now);
            }
            let expiry = self.expiry(now)?;
            let mut aggregate = *existing;
            aggregate.counters = ObservationCounters {
                sightings: SightingCounters {
                    claimed: aggregate
                        .counters
                        .sightings
                        .claimed
                        .checked_add(counters.sightings.claimed)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                    authenticated: aggregate
                        .counters
                        .sightings
                        .authenticated
                        .checked_add(counters.sightings.authenticated)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                },
                referrals: aggregate
                    .counters
                    .referrals
                    .checked_add(counters.referrals)
                    .ok_or(LocalObservationRefusal::Invariant)?,
                outcomes: OutcomeCounters {
                    succeeded: aggregate
                        .counters
                        .outcomes
                        .succeeded
                        .checked_add(counters.outcomes.succeeded)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                    failed: aggregate
                        .counters
                        .outcomes
                        .failed
                        .checked_add(counters.outcomes.failed)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                    stale: aggregate
                        .counters
                        .outcomes
                        .stale
                        .checked_add(counters.outcomes.stale)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                    key_mismatch: aggregate
                        .counters
                        .outcomes
                        .key_mismatch
                        .checked_add(counters.outcomes.key_mismatch)
                        .ok_or(LocalObservationRefusal::Invariant)?,
                },
            };
            aggregate.last_seen = now;
            aggregate.expires_at = expiry;
            *self
                .records
                .get_mut(&key)
                .ok_or(LocalObservationRefusal::Invariant)? = aggregate;
            return Ok(ObservationOutcomeTicket {
                key,
                generation: self.generation,
                sequence: aggregate.sequence,
                authenticated,
            });
        }
        self.insert_new(key, provenance, counters, authenticated, now)
    }

    pub(super) fn record_sighting(
        &mut self,
        provenance: ObservationProvenance,
        locator: ObservationLocator,
        kind: ObservationSighting,
    ) -> Result<ObservationOutcomeTicket, LocalObservationRefusal> {
        self.observe(
            provenance,
            locator,
            ObservationCounters::default().sighting(kind)?,
            matches!(kind, ObservationSighting::Authenticated),
        )
    }

    pub(super) fn record_referral(
        &mut self,
        provenance: ObservationProvenance,
        locator: ObservationLocator,
    ) -> Result<ObservationOutcomeTicket, LocalObservationRefusal> {
        self.observe(
            provenance,
            locator,
            ObservationCounters::default().referral()?,
            false,
        )
    }

    pub(super) fn record_outcome(
        &mut self,
        ticket: ObservationOutcomeTicket,
        outcome: ObservationOutcome,
    ) -> Result<(), LocalObservationRefusal> {
        if self.retired {
            return Err(LocalObservationRefusal::OwnerRetired);
        }
        let now = self.now()?;
        self.maintain_at(now)?;
        let generation = self.generation;
        let expiry = self.expiry(now)?;
        let expired = self
            .records
            .get(&ticket.key)
            .is_some_and(|record| record.expires_at <= now);
        if expired {
            if self.generation == u64::MAX {
                return Err(LocalObservationRefusal::GenerationOverflow);
            }
            self.records
                .remove(&ticket.key)
                .ok_or(LocalObservationRefusal::Invariant)?;
            self.record_count = self
                .record_count
                .checked_sub(1)
                .ok_or(LocalObservationRefusal::Invariant)?;
            self.bump_generation()?;
            return Err(LocalObservationRefusal::StaleOutcome);
        }
        let record = self
            .records
            .get_mut(&ticket.key)
            .ok_or(LocalObservationRefusal::StaleOutcome)?;
        if generation != ticket.generation || record.sequence != ticket.sequence {
            return Err(LocalObservationRefusal::StaleOutcome);
        }
        let counters = record.counters.outcome(outcome)?;
        record.counters = counters;
        record.last_seen = now;
        record.expires_at = expiry;
        Ok(())
    }

    /// Record an operation outcome with the ticket's exact owner generation
    /// and aggregate sequence.  A successful result requires an authenticated
    /// local sighting, while failed, stale, and key-mismatch results are valid
    /// before authentication completes.  Thus a failed referral attempt is
    /// observable without turning a claimed hint into success authority.  The
    /// ticket fence prevents a late callback from updating a successor owner;
    /// refusal never changes networking, authentication, or routing.
    pub(super) fn record_authenticated_outcome(
        &mut self,
        ticket: ObservationOutcomeTicket,
        outcome: ObservationOutcome,
    ) -> Result<(), LocalObservationRefusal> {
        if self.retired {
            return Err(LocalObservationRefusal::OwnerRetired);
        }
        if !ticket.authenticated && matches!(outcome, ObservationOutcome::Succeeded) {
            return Err(LocalObservationRefusal::UnauthenticatedOutcome);
        }
        self.record_outcome(ticket, outcome)
    }

    /// Visit only one subject's live records.  Expired records are filtered
    /// even when the bounded maintenance cursor has not reached them.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn for_subject(
        &mut self,
        subject: ObservationDeviceKey,
        mut visit: impl FnMut(ObservationKey, ObservationAggregate),
    ) -> Result<(), LocalObservationRefusal> {
        if self.retired {
            return Ok(());
        }
        let now = self.now()?;
        self.maintain_at(now)?;
        let mut cursor = self.first_subject_key(subject);
        let mut inspected = 0;
        while let Some(key) = cursor {
            if key.subject != subject || inspected >= self.limits.max_records_per_subject {
                break;
            }
            if let Some(record) = self.records.get(&key) {
                if record.expires_at > now {
                    visit(key, *record);
                }
            }
            inspected += 1;
            cursor = self
                .records
                .successor_after(Some(&key))
                .map(|(next, _)| *next);
        }
        Ok(())
    }

    fn remove_matching(
        &mut self,
        mut matches: impl FnMut(ObservationKey, ObservationAggregate) -> bool,
    ) -> Result<usize, LocalObservationRefusal> {
        if self.generation == u64::MAX {
            return Err(LocalObservationRefusal::GenerationOverflow);
        }
        let mut cursor = None;
        let start = self.records.successor_after(None).map(|(key, _)| *key);
        let mut removed: usize = 0;
        let bound = self.record_count;
        for step in 0..bound {
            let Some(key) = self.next_key_after(cursor.as_ref()) else {
                break;
            };
            if step > 0 && Some(key) == start {
                break;
            }
            cursor = Some(key);
            let Some(record) = self.records.get(&key).copied() else {
                continue;
            };
            if matches(key, record) {
                self.records
                    .remove(&key)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                self.record_count = self
                    .record_count
                    .checked_sub(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
                removed = removed
                    .checked_add(1)
                    .ok_or(LocalObservationRefusal::Invariant)?;
            }
        }
        if removed != 0 {
            self.bump_generation()?;
        }
        Ok(removed)
    }

    /// Remove records mentioning a retired peer in subject, referrer, or
    /// via-peer locator position.  Observer identity is also checked so a
    /// replacement cannot inherit stale local evidence.
    pub(super) fn retire_peer(
        &mut self,
        peer: ObservationDeviceKey,
    ) -> Result<usize, LocalObservationRefusal> {
        if self.retired {
            return Ok(0);
        }
        self.remove_matching(|key, record| key.mentions(peer) || record.observer == peer)
    }

    /// Retire the graph owner.  This is a local lifecycle operation, not a
    /// semantic departure, and removes every retained record deterministically.
    pub(super) fn retire_owner(&mut self) -> Result<usize, LocalObservationRefusal> {
        if self.retired {
            return Ok(0);
        }
        let removed = self.remove_matching(|_, _| true)?;
        self.maintenance_cursor = None;
        self.retired = true;
        Ok(removed)
    }

    #[cfg(test)]
    pub(super) fn record_count_for_test(&self) -> usize {
        self.record_count
    }
}

#[cfg(all(test, feature = "transport-lab"))]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    use crate::resource::{
        FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
    };

    #[derive(Clone)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn new(value: u64) -> Self {
            Self(Arc::new(AtomicU64::new(value)))
        }

        fn set(&self, value: u64) {
            self.0.store(value, Ordering::Release);
        }
    }

    impl ObservationClock for TestClock {
        fn now(&self) -> ObservationTick {
            ObservationTick(self.0.load(Ordering::Acquire))
        }
    }

    fn device(byte: u8) -> ObservationDeviceKey {
        let signing_key = SigningKey::from_bytes(&[byte; 32]);
        ObservationDeviceKey::from_device(
            &DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("derived public key bytes"),
        )
    }

    fn fixture(
        limits: LocalObservationLimits,
        clock: TestClock,
    ) -> (
        LocalObservationGraph<TestClock>,
        FiniteResourceProvider,
        LocalApplicationResourceScope,
    ) {
        let node =
            LeasedMap::<ObservationKey, ObservationAggregate>::entry_claim().expect("entry claim");
        let per_entry =
            FiniteResourceProvider::reservation_planning_charge(node).expect("reservation charge");
        // ResourceProviderPort::new registers the process scope, and
        // transport_lab_child_of then registers the graph's child scope.
        // Both are live before the first leased map entry, so price both
        // exact bookkeeping records rather than relying on incidental slack.
        let grant = FiniteResourceProvider::scope_planning_charge()
            .checked_add(FiniteResourceProvider::scope_planning_charge())
            .expect("finite scope grant")
            .checked_add(
                per_entry
                    .checked_scale(limits.max_records as u64)
                    .expect("finite test grant"),
            )
            .expect("finite test grant");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("local observation child scope");
        let graph =
            LocalObservationGraph::new(scope.clone(), limits, clock).expect("observation graph");
        (graph, provider, scope)
    }

    fn limits(max_records: usize, per_subject: usize, age: u64) -> LocalObservationLimits {
        LocalObservationLimits {
            max_records,
            max_records_per_subject: per_subject,
            max_age_ticks: age,
            max_maintenance_work: 1,
        }
    }

    #[test]
    fn aggregate_updates_are_bounded_and_provider_funded() {
        let clock = TestClock::new(1);
        let (mut graph, provider, scope) = fixture(limits(2, 1, 10), clock.clone());
        let provenance = ObservationProvenance {
            observer: device(1),
            referrer: Some(device(2)),
            subject: device(3),
        };
        let locator = ObservationLocator::ViaPeer(device(2));
        let before = provider.in_use();
        let first = graph
            .record_sighting(provenance, locator, ObservationSighting::ClaimedLocator)
            .expect("first sighting");
        let authenticated = graph
            .record_sighting(provenance, locator, ObservationSighting::Authenticated)
            .expect("same aggregate updates in place");
        assert!(matches!(
            graph.record_authenticated_outcome(first, ObservationOutcome::Succeeded),
            Err(LocalObservationRefusal::UnauthenticatedOutcome)
        ));
        graph
            .record_authenticated_outcome(first, ObservationOutcome::Failed)
            .expect("pre-authenticated operation failure");
        graph
            .record_authenticated_outcome(first, ObservationOutcome::Stale)
            .expect("pre-authenticated stale result");
        graph
            .record_authenticated_outcome(first, ObservationOutcome::KeyMismatch)
            .expect("pre-authenticated key mismatch");
        graph
            .record_authenticated_outcome(authenticated, ObservationOutcome::Succeeded)
            .expect("authenticated outcome ticket");
        assert_eq!(graph.record_count_for_test(), 1);
        assert!(matches!(
            graph.record_sighting(
                ObservationProvenance {
                    observer: device(9),
                    ..provenance
                },
                locator,
                ObservationSighting::Authenticated,
            ),
            Err(LocalObservationRefusal::OwnerMismatch)
        ));
        assert!(graph
            .record_sighting(
                ObservationProvenance {
                    subject: provenance.subject,
                    ..provenance
                },
                ObservationLocator::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1)),
                ObservationSighting::ClaimedLocator,
            )
            .is_err());
        let claimed = provider.in_use();
        assert!(claimed != before);
        graph
            .retire_peer(provenance.subject)
            .expect("peer retirement");
        assert_eq!(provider.in_use(), before);
        let replacement = graph
            .record_referral(provenance, locator)
            .expect("peer-retired aggregate can be replaced");
        assert_ne!(replacement.sequence, first.sequence);
        assert!(matches!(
            graph.record_authenticated_outcome(authenticated, ObservationOutcome::Failed),
            Err(LocalObservationRefusal::StaleOutcome)
        ));
        assert_eq!(graph.record_count_for_test(), 1);
        graph.retire_owner().expect("owner retirement");
        assert_eq!(graph.record_count_for_test(), 0);
        assert_eq!(provider.in_use(), before);
        assert!(matches!(
            graph.record_referral(provenance, locator),
            Err(LocalObservationRefusal::OwnerRetired)
        ));
        drop(graph);
        drop(scope);
    }

    #[test]
    fn expiry_regression_overflow_and_stale_ticket_are_refused() {
        let clock = TestClock::new(u64::MAX - 1);
        let (mut graph, provider, scope) = fixture(limits(1, 1, 10), clock.clone());
        let provenance = ObservationProvenance {
            observer: device(4),
            referrer: None,
            subject: device(5),
        };
        assert!(matches!(
            graph.record_referral(provenance, ObservationLocator::ViaPeer(device(6))),
            Err(LocalObservationRefusal::TimeOverflow)
        ));
        clock.set(1);
        assert!(matches!(
            graph.record_referral(provenance, ObservationLocator::ViaPeer(device(6))),
            Err(LocalObservationRefusal::ClockRegression)
        ));
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            0
        );
        drop(graph);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn expired_records_are_filtered_before_bounded_purge() {
        let clock = TestClock::new(1);
        let (mut graph, provider, scope) = fixture(limits(3, 3, 2), clock.clone());
        let provenance = ObservationProvenance {
            observer: device(7),
            referrer: None,
            subject: device(8),
        };
        let first_locator =
            ObservationLocator::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 1));
        let second_locator =
            ObservationLocator::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 2));
        graph
            .record_sighting(
                provenance,
                first_locator,
                ObservationSighting::Authenticated,
            )
            .expect("first local aggregate");
        let second = graph
            .record_sighting(
                provenance,
                second_locator,
                ObservationSighting::ClaimedLocator,
            )
            .expect("second local aggregate");
        clock.set(2);
        let high_locator =
            ObservationLocator::Socket(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 3));
        graph
            .record_sighting(provenance, high_locator, ObservationSighting::Authenticated)
            .expect("later live aggregate");
        clock.set(3);
        let mut visited = 0;
        graph
            .for_subject(provenance.subject, |_, aggregate| {
                assert!(aggregate.expires_at > ObservationTick(3));
                visited += 1;
            })
            .expect("bounded subject read");
        assert_eq!(visited, 1);
        assert_eq!(graph.record_count_for_test(), 3);
        let fresh = graph
            .record_referral(provenance, second_locator)
            .expect("expired target is replaced with a fresh sequence");
        assert_ne!(fresh.sequence, second.sequence);
        assert!(matches!(
            graph.record_outcome(second, ObservationOutcome::Failed),
            Err(LocalObservationRefusal::StaleOutcome)
        ));
        assert_eq!(graph.record_count_for_test(), 2);
        graph.retire_owner().expect("owner retirement");
        assert!(matches!(
            graph.record_referral(provenance, second_locator),
            Err(LocalObservationRefusal::OwnerRetired)
        ));
        assert!(matches!(
            graph.record_outcome(fresh, ObservationOutcome::Failed),
            Err(LocalObservationRefusal::OwnerRetired)
        ));
        drop(graph);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }
}
