//! Capability boundary for one bounded connection attempt.
//!
//! This Arc 02 module adds authority types only. It does not redirect the
//! current attempt runtime or change transport behavior.

use std::sync::{Arc, Mutex};

use crate::resource::ResourceUse;

use super::RuntimeIncarnation;

struct AttemptOwnership {
    runtime: RuntimeIncarnation,
}

struct AggregateReservationState {
    active: ResourceUse,
    poisoned: bool,
}

struct AggregateReservation {
    capacity: ResourceUse,
    state: Mutex<AggregateReservationState>,
}

impl AggregateReservation {
    fn new(capacity: ResourceUse) -> Self {
        Self {
            capacity,
            state: Mutex::new(AggregateReservationState {
                active: ResourceUse::ZERO,
                poisoned: false,
            }),
        }
    }

    fn reserve(self: &Arc<Self>, claim: ResourceUse) -> Option<CandidateReservation> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return None,
        };
        if state.poisoned {
            return None;
        }
        let next = state.active.checked_add(claim)?;
        if !next.fits_within(self.capacity) {
            return None;
        }
        state.active = next;
        Some(CandidateReservation {
            aggregate: Arc::clone(self),
            claim,
        })
    }

    #[cfg(test)]
    fn active(&self) -> ResourceUse {
        match self.state.lock() {
            Ok(state) => state.active,
            Err(poisoned) => poisoned.into_inner().active,
        }
    }

    #[cfg(test)]
    fn is_poisoned(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.poisoned,
            Err(_) => true,
        }
    }

    #[cfg(test)]
    fn corrupt_active_for_test(&self, active: ResourceUse) {
        let mut state = self
            .state
            .lock()
            .expect("test corruption fixture requires an unpoisoned mutex");
        state.active = active;
    }
}

/// One live child claim against an attempt's aggregate reservation.
///
/// Dropping the child returns its claim. This guard is created before the
/// allocation closure runs, so a candidate cannot consume resources first and
/// ask for accounting afterward.
struct CandidateReservation {
    aggregate: Arc<AggregateReservation>,
    claim: ResourceUse,
}

impl Drop for CandidateReservation {
    fn drop(&mut self) {
        let mut state = match self.aggregate.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.poisoned = true;
                return;
            }
        };
        if state.poisoned {
            return;
        }
        match state.active.checked_sub(self.claim) {
            Some(active) => state.active = active,
            None => state.poisoned = true,
        }
    }
}

/// Proof that pre-authentication work was admitted for one attempt.
///
/// The private field prevents public IDs, wire values, and serialized state
/// from being treated as a permit. The permit is intentionally neither
/// `Clone` nor serializable.
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct PreAuthAttemptPermit {
    attempt: Arc<AttemptOwnership>,
    aggregate: Arc<AggregateReservation>,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    fn admitted(runtime: RuntimeIncarnation, capacity: ResourceUse) -> Self {
        Self {
            attempt: Arc::new(AttemptOwnership { runtime }),
            aggregate: Arc::new(AggregateReservation::new(capacity)),
        }
    }

    /// Reserve one child and only then run the candidate allocation.
    ///
    /// The attempt permit remains alive and may issue more child reservations
    /// from the same aggregate. The closure is never called when admission
    /// fails.
    fn allocate_candidate<T>(
        &self,
        claim: ResourceUse,
        allocate: impl FnOnce() -> T,
    ) -> Option<(CandidateCapability, T)> {
        let reservation = self.aggregate.reserve(claim)?;
        let capability = CandidateCapability {
            attempt: Arc::clone(&self.attempt),
            reservation,
        };
        let candidate = allocate();
        Some((capability, candidate))
    }
}

/// Local authority to attempt one connector candidate.
///
/// The capability owns one child resource reservation and an exact, local
/// witness for the attempt that issued it. It does not consume the attempt
/// permit. One admitted attempt can therefore own multiple candidates under
/// one aggregate reservation. The capability has no public constructor and is
/// neither `Clone` nor serializable.
///
/// A public peer label cannot create a candidate capability:
///
/// ```compile_fail,E0308
/// use myownmesh_core::runtime::attempt::CandidateCapability;
///
/// let public_peer_id = String::new();
/// let _candidate = CandidateCapability::from(public_peer_id);
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct CandidateCapability {
    attempt: Arc<AttemptOwnership>,
    reservation: CandidateReservation,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl CandidateCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.attempt.runtime
    }

    #[cfg(test)]
    fn belongs_to(&self, permit: &PreAuthAttemptPermit) -> bool {
        Arc::ptr_eq(&self.attempt, &permit.attempt)
            && Arc::ptr_eq(&self.reservation.aggregate, &permit.aggregate)
    }
}

/// Temporary adapter for legacy candidate objects.
///
/// It carries the old object beside, rather than inside, the authority proof.
/// Supplying a legacy value cannot mint a capability. Arc 03 deletes this
/// wrapper after the connector consumes `CandidateCapability` directly.
#[allow(
    dead_code,
    reason = "Arc 03 installs and deletes this migration adapter"
)]
pub(crate) struct LegacyCandidate<T> {
    capability: CandidateCapability,
    legacy: T,
}

#[allow(
    dead_code,
    reason = "Arc 03 installs and deletes this migration adapter"
)]
impl<T> LegacyCandidate<T> {
    pub(crate) fn new(capability: CandidateCapability, legacy: T) -> Self {
        Self { capability, legacy }
    }

    pub(crate) fn capability(&self) -> &CandidateCapability {
        &self.capability
    }

    fn into_parts(self) -> (CandidateCapability, T) {
        (self.capability, self.legacy)
    }
}

#[cfg(test)]
pub(crate) fn candidate_for_test(runtime: RuntimeIncarnation) -> CandidateCapability {
    let claim = ResourceUse::observed(1, 0, 0, 0);
    let permit = PreAuthAttemptPermit::admitted(runtime, claim);
    permit
        .allocate_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its exact fixture claim")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate() {
        let runtime = crate::runtime::runtime_for_test();
        let one = ResourceUse::observed(1, 0, 0, 0);
        let two = ResourceUse::observed(2, 0, 0, 0);
        let permit = PreAuthAttemptPermit::admitted(runtime.clone(), two);
        let (first, first_value) = permit
            .allocate_candidate(one, || "first")
            .expect("first child fits");
        let (second, second_value) = permit
            .allocate_candidate(one, || "second")
            .expect("second child fits");

        assert_eq!(first_value, "first");
        assert_eq!(second_value, "second");
        assert!(first.runtime().is_same(&runtime));
        assert!(first.belongs_to(&permit));
        assert!(second.belongs_to(&permit));
        assert_eq!(permit.aggregate.active(), two);
        assert!(permit.allocate_candidate(one, || "third").is_none());

        fn accepts_candidate(_: CandidateCapability) {}
        accepts_candidate(first);
        assert_eq!(permit.aggregate.active(), one);
        accepts_candidate(second);
        assert_eq!(permit.aggregate.active(), ResourceUse::ZERO);
    }

    #[test]
    fn v4_arc02_candidate_allocation_runs_only_after_child_reservation() {
        let one = ResourceUse::observed(1, 0, 0, 0);
        let permit = PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), one);
        let (first, saw_active) = permit
            .allocate_candidate(one, || permit.aggregate.active())
            .expect("fixture child fits");
        assert_eq!(saw_active, one);

        let allocation_called = std::cell::Cell::new(false);
        let refused = permit.allocate_candidate(one, || allocation_called.set(true));
        assert!(refused.is_none());
        assert!(!allocation_called.get());
        drop(first);
    }

    #[test]
    fn v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed() {
        let child_claim = ResourceUse::observed(2, 0, 0, 0);
        let aggregate_capacity = ResourceUse::observed(4, 0, 0, 0);
        let corrupted_active = ResourceUse::observed(1, 0, 0, 0);
        let permit =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), aggregate_capacity);
        let (first, ()) = permit
            .allocate_candidate(child_claim, || ())
            .expect("first child fits");
        let (second, ()) = permit
            .allocate_candidate(child_claim, || ())
            .expect("second child fits");
        assert_eq!(permit.aggregate.active(), aggregate_capacity);

        permit.aggregate.corrupt_active_for_test(corrupted_active);
        drop(first);

        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
        let allocation_called = std::cell::Cell::new(false);
        assert!(permit
            .allocate_candidate(child_claim, || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());

        drop(second);
        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
    }

    #[test]
    fn v4_arc02_legacy_adapter_requires_an_existing_capability() {
        let wrapper = LegacyCandidate::new(
            candidate_for_test(crate::runtime::runtime_for_test()),
            "legacy candidate",
        );
        let _ = wrapper.capability();
        let (_capability, legacy) = wrapper.into_parts();

        assert_eq!(legacy, "legacy candidate");
    }
}
