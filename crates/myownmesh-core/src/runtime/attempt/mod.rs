//! Capability boundary for one bounded connection attempt.
//!
//! The attempt owner admits connector candidates before allocation, retires
//! losing work, and transfers an exact child claim when a candidate connects.

use std::num::NonZeroUsize;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tokio::sync::watch;

use crate::resource::{PreAuthResourceFamily, ResourceUse, PRE_AUTH_RESOURCE_FAMILY_COUNT};

use super::RuntimeIncarnation;

struct AttemptOwnership {
    runtime: RuntimeIncarnation,
    active: AtomicBool,
    transition: Mutex<()>,
    retired: watch::Sender<bool>,
}

/// One componentwise resource vector indexed by the closed pre-authentication
/// family set.
///
/// A resource quantity in one family cannot cover another family. This value
/// is local, non-serializable accounting state. It does not select or imply any
/// production capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PreAuthResourceClaim {
    by_family: [ResourceUse; PRE_AUTH_RESOURCE_FAMILY_COUNT],
}

impl PreAuthResourceClaim {
    const ZERO: Self = Self {
        by_family: [ResourceUse::ZERO; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    };

    #[allow(
        dead_code,
        reason = "Arc 03 production claims wait for owner-approved measurements"
    )]
    fn single(family: PreAuthResourceFamily, use_: ResourceUse) -> Self {
        let mut claim = Self::ZERO;
        claim.by_family[family.index()] = use_;
        claim
    }

    fn checked_add(self, other: Self) -> Option<Self> {
        let mut combined = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            combined.by_family[index] =
                self.by_family[index].checked_add(other.by_family[index])?;
        }
        Some(combined)
    }

    fn checked_sub(self, other: Self) -> Option<Self> {
        let mut remainder = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            remainder.by_family[index] =
                self.by_family[index].checked_sub(other.by_family[index])?;
        }
        Some(remainder)
    }

    #[cfg(test)]
    fn componentwise_max(self, other: Self) -> Self {
        let mut maximum = Self::ZERO;
        for family in PreAuthResourceFamily::ALL {
            let index = family.index();
            let left = self.by_family[index];
            let right = other.by_family[index];
            maximum.by_family[index] = ResourceUse::observed(
                left.items().max(right.items()),
                left.logical_bytes().max(right.logical_bytes()),
                left.retained_bytes().max(right.retained_bytes()),
                left.tasks().max(right.tasks()),
            );
        }
        maximum
    }

    #[cfg(test)]
    fn for_family(self, family: PreAuthResourceFamily) -> ResourceUse {
        self.by_family[family.index()]
    }
}

/// Resource claim for exactly one connector candidate.
///
/// This type establishes only the cardinality that is independent of owner
/// policy: one connector candidate owns one transport object. It does not
/// decide the remaining per-family quantities or any production capacity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConnectorCandidateResourceClaim {
    opening: PreAuthResourceClaim,
    connected: PreAuthResourceClaim,
}

impl ConnectorCandidateResourceClaim {
    #[allow(
        dead_code,
        reason = "production construction waits for owner-approved per-family measurements"
    )]
    fn checked(opening: PreAuthResourceClaim, connected: PreAuthResourceClaim) -> Option<Self> {
        let opening_transport = opening.by_family[PreAuthResourceFamily::TransportObject.index()];
        let connected_transport =
            connected.by_family[PreAuthResourceFamily::TransportObject.index()];
        (opening_transport.items() == 1 && connected_transport.items() == 1)
            .then_some(Self { opening, connected })
    }

    /// The mechanically fixed Arc 03 claim. It describes the one native peer
    /// connection and one connector-construction operation whose ownership
    /// this arc can prove. It is not a complete WebRTC allocation budget and
    /// does not select a process-wide admission limit.
    pub(crate) fn exact_connector_floor() -> Self {
        let transport = PreAuthResourceClaim::single(
            PreAuthResourceFamily::TransportObject,
            ResourceUse::observed(1, 0, 0, 0),
        );
        let mut opening = transport;
        opening.by_family[PreAuthResourceFamily::ConnectorSpecificWork.index()] =
            ResourceUse::observed(1, 0, 0, 0);
        opening.by_family[PreAuthResourceFamily::Task.index()] = ResourceUse::observed(1, 0, 0, 1);
        let mut connected = transport;
        connected.by_family[PreAuthResourceFamily::Task.index()] =
            ResourceUse::observed(1, 0, 0, 1);
        Self { opening, connected }
    }

    #[cfg(test)]
    fn aggregate_capacity(self) -> PreAuthResourceClaim {
        self.opening.componentwise_max(self.connected)
    }
}

/// Owner-selected bounds for the connector's closed callback-class set.
///
/// Codec and media names belong to the WebRTC compatibility adapter. The
/// connector resource owner accounts only for control, endpoint data, and
/// codec-neutral real-time flow callbacks.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackMailboxCapacities {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
    realtime: NonZeroUsize,
}

impl ConnectorCallbackMailboxCapacities {
    pub const fn new(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
        realtime: NonZeroUsize,
    ) -> Self {
        Self {
            control,
            endpoint_data,
            realtime,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }

    pub const fn realtime(self) -> NonZeroUsize {
        self.realtime
    }
}

/// Owner-selected scheduler weights for the closed callback-class set.
///
/// No default exists. A weight is a maximum consecutive service quantum when
/// the selected class remains ready. Empty classes are skipped, so a stalled
/// class cannot block the others.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackServiceWeights {
    control: NonZeroUsize,
    endpoint_data: NonZeroUsize,
    realtime: NonZeroUsize,
}

impl ConnectorCallbackServiceWeights {
    pub const fn new(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
        realtime: NonZeroUsize,
    ) -> Self {
        Self {
            control,
            endpoint_data,
            realtime,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
    }

    pub const fn realtime(self) -> NonZeroUsize {
        self.realtime
    }
}

/// Owner-selected callback behavior for one connector.
///
/// Endpoint frames retain the protocol's independent frame limit. The
/// real-time unit limit and enqueue deadline are separate operational inputs
/// because an encoded access unit is not an endpoint message frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackPolicy {
    mailboxes: ConnectorCallbackMailboxCapacities,
    service_weights: ConnectorCallbackServiceWeights,
    max_realtime_unit_bytes: NonZeroUsize,
    realtime_enqueue_deadline: Duration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorCallbackPolicyError {
    #[error("real-time callback enqueue deadline must be nonzero")]
    ZeroRealtimeEnqueueDeadline,
    #[error(
        "{class} callback mailbox capacity {requested} exceeds Tokio's supported maximum {maximum}"
    )]
    MailboxCapacityExceedsRuntimeLimit {
        class: &'static str,
        requested: usize,
        maximum: usize,
    },
}

impl ConnectorCallbackPolicy {
    pub fn new(
        mailboxes: ConnectorCallbackMailboxCapacities,
        service_weights: ConnectorCallbackServiceWeights,
        max_realtime_unit_bytes: NonZeroUsize,
        realtime_enqueue_deadline: Duration,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        if realtime_enqueue_deadline.is_zero() {
            return Err(ConnectorCallbackPolicyError::ZeroRealtimeEnqueueDeadline);
        }
        for (class, requested) in [
            ("control", mailboxes.control().get()),
            ("endpoint-data", mailboxes.endpoint_data().get()),
            ("real-time", mailboxes.realtime().get()),
        ] {
            if requested > tokio::sync::Semaphore::MAX_PERMITS {
                return Err(
                    ConnectorCallbackPolicyError::MailboxCapacityExceedsRuntimeLimit {
                        class,
                        requested,
                        maximum: tokio::sync::Semaphore::MAX_PERMITS,
                    },
                );
            }
        }
        Ok(Self {
            mailboxes,
            service_weights,
            max_realtime_unit_bytes,
            realtime_enqueue_deadline,
        })
    }

    pub const fn mailboxes(self) -> ConnectorCallbackMailboxCapacities {
        self.mailboxes
    }

    pub const fn service_weights(self) -> ConnectorCallbackServiceWeights {
        self.service_weights
    }

    pub const fn max_realtime_unit_bytes(self) -> NonZeroUsize {
        self.max_realtime_unit_bytes
    }

    pub const fn realtime_enqueue_deadline(self) -> Duration {
        self.realtime_enqueue_deadline
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn unrestricted_lab(mailbox_capacity: NonZeroUsize) -> Self {
        Self {
            mailboxes: ConnectorCallbackMailboxCapacities::new(
                mailbox_capacity,
                mailbox_capacity,
                mailbox_capacity,
            ),
            service_weights: ConnectorCallbackServiceWeights::new(
                mailbox_capacity,
                mailbox_capacity,
                mailbox_capacity,
            ),
            max_realtime_unit_bytes: NonZeroUsize::new(usize::MAX).expect("usize::MAX is nonzero"),
            // Raw transport labs are the compatibility bypass. Production
            // policy construction rejects a zero enqueue deadline.
            realtime_enqueue_deadline: Duration::ZERO,
        }
    }
}

/// Explicit policy supplied by the process resource owner.
///
/// Arc 03 deliberately provides no `Default`: the maximum number of admitted
/// candidates, callback capacities, and native-close deadline are operational
/// values that require owner review.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourcePolicy {
    max_active_candidates: NonZeroUsize,
    callbacks: ConnectorCallbackPolicy,
    native_close_timeout: Duration,
}

impl ConnectorResourcePolicy {
    pub fn new(
        max_active_candidates: NonZeroUsize,
        callbacks: ConnectorCallbackPolicy,
        native_close_timeout: Duration,
    ) -> Option<Self> {
        (!native_close_timeout.is_zero()).then_some(Self {
            max_active_candidates,
            callbacks,
            native_close_timeout,
        })
    }

    pub const fn max_active_candidates(self) -> NonZeroUsize {
        self.max_active_candidates
    }

    pub const fn callbacks(self) -> ConnectorCallbackPolicy {
        self.callbacks
    }

    pub const fn native_close_timeout(self) -> Duration {
        self.native_close_timeout
    }
}

/// A process resource root already owns a different connector policy.
///
/// Reusing the installed policy is safe. Replacing it while live claims may
/// exist would split the process limit, so the root refuses the change.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the process connector resource policy is already installed with different values")]
pub struct ConnectorResourcePolicyConflict {
    pub installed: ConnectorResourcePolicy,
    pub requested: ConnectorResourcePolicy,
}

/// Point-in-time report from the connector resource owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorResourceOwnerReport {
    pub max_active_candidates: NonZeroUsize,
    pub active_candidates: usize,
    /// Exact candidate claims retained after a native cleanup failure. These
    /// slots remain consumed until process exit and cannot be reused.
    pub failed_cleanup_candidates: usize,
    /// Aggregate accounting is no longer exact, so all later admissions are
    /// refused. A known per-candidate cleanup failure does not set this flag.
    pub accounting_poisoned: bool,
    pub callbacks: ConnectorCallbackPolicy,
    pub native_close_timeout: Duration,
}

/// Unique cancellation and retirement owner for one connection attempt.
///
/// This value is not a resource permit and cannot create connector authority.
/// It only controls whether capabilities already issued by the same admitted
/// attempt remain live. Dropping or retiring it invalidates candidate
/// capabilities that have not already been consumed into a later capability,
/// including candidate values held by delayed callbacks.
pub(crate) struct AttemptLifetime {
    attempt: Arc<AttemptOwnership>,
}

impl AttemptLifetime {
    pub(crate) fn retire(&self) {
        {
            let _transition = match self.attempt.transition.lock() {
                Ok(transition) => transition,
                Err(poisoned) => poisoned.into_inner(),
            };
            self.attempt.active.store(false, Ordering::Release);
        }
        // Notify after releasing the attempt transition. Connector cleanup may
        // take its own authority mutex, so this prevents a reverse nested edge.
        self.attempt.retired.send_replace(true);
    }

    #[cfg(test)]
    pub(crate) fn is_active(&self) -> bool {
        self.attempt.active.load(Ordering::Acquire)
    }
}

/// Cloneable, non-retiring witness for work owned by one attempt.
///
/// Only [`AttemptLifetime`] can retire the attempt. Candidate workers retain
/// this witness so they can reject and cancel work after that unique owner has
/// ended the attempt without gaining cancellation authority themselves.
#[derive(Clone)]
pub(crate) struct AttemptLiveness {
    attempt: Arc<AttemptOwnership>,
}

impl AttemptLiveness {
    pub(crate) fn is_active(&self) -> bool {
        self.attempt.active.load(Ordering::Acquire)
    }

    #[allow(
        dead_code,
        reason = "production admitted workers will select this signal with connector retirement"
    )]
    pub(crate) fn subscribe_retirement(&self) -> watch::Receiver<bool> {
        self.attempt.retired.subscribe()
    }
}

impl Drop for AttemptLifetime {
    fn drop(&mut self) {
        self.retire();
    }
}

struct ConnectorResourceOwnerState {
    active: PreAuthResourceClaim,
    active_candidates: usize,
    failed_cleanup_candidates: usize,
    accounting_poisoned: bool,
}

struct ConnectorResourceOwnerInner {
    policy: ConnectorResourcePolicy,
    state: Mutex<ConnectorResourceOwnerState>,
}

impl ConnectorResourceOwnerInner {
    fn new(policy: ConnectorResourcePolicy) -> Self {
        Self {
            policy,
            state: Mutex::new(ConnectorResourceOwnerState {
                active: PreAuthResourceClaim::ZERO,
                active_candidates: 0,
                failed_cleanup_candidates: 0,
                accounting_poisoned: false,
            }),
        }
    }

    fn reserve(
        self: &Arc<Self>,
        claim: PreAuthResourceClaim,
    ) -> Option<ConnectorCandidateReservation> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return None,
        };
        if state.accounting_poisoned {
            return None;
        }
        if state.active_candidates >= self.policy.max_active_candidates.get() {
            return None;
        }
        let next = state.active.checked_add(claim)?;
        state.active = next;
        state.active_candidates += 1;
        Some(ConnectorCandidateReservation {
            owner: Arc::clone(self),
            claim,
            release_on_drop: true,
        })
    }

    /// Replace one live child's claim without exposing an unreserved gap.
    /// Inconsistent subtraction poisons the aggregate and preserves its last
    /// conservative value. Capacity refusal leaves the old claim live.
    fn transition(&self, old: PreAuthResourceClaim, new: PreAuthResourceClaim) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.accounting_poisoned = true;
                return false;
            }
        };
        if state.accounting_poisoned {
            return false;
        }
        let Some(without_old) = state.active.checked_sub(old) else {
            state.accounting_poisoned = true;
            return false;
        };
        let Some(next) = without_old.checked_add(new) else {
            return false;
        };
        state.active = next;
        true
    }

    fn report(&self) -> ConnectorResourceOwnerReport {
        let (active_candidates, failed_cleanup_candidates, accounting_poisoned) =
            match self.state.lock() {
                Ok(state) => (
                    state.active_candidates,
                    state.failed_cleanup_candidates,
                    state.accounting_poisoned,
                ),
                Err(poisoned) => {
                    let state = poisoned.into_inner();
                    (
                        state.active_candidates,
                        state.failed_cleanup_candidates,
                        true,
                    )
                }
            };
        ConnectorResourceOwnerReport {
            max_active_candidates: self.policy.max_active_candidates,
            active_candidates,
            failed_cleanup_candidates,
            accounting_poisoned,
            callbacks: self.policy.callbacks,
            native_close_timeout: self.policy.native_close_timeout,
        }
    }

    fn poison_accounting(&self) {
        match self.state.lock() {
            Ok(mut state) => state.accounting_poisoned = true,
            Err(poisoned) => poisoned.into_inner().accounting_poisoned = true,
        }
    }

    #[cfg(test)]
    fn active(&self) -> PreAuthResourceClaim {
        match self.state.lock() {
            Ok(state) => state.active,
            Err(poisoned) => poisoned.into_inner().active,
        }
    }

    #[cfg(test)]
    fn is_poisoned(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.accounting_poisoned,
            Err(_) => true,
        }
    }

    #[cfg(test)]
    fn corrupt_active_for_test(&self, active: PreAuthResourceClaim) {
        let mut state = self
            .state
            .lock()
            .expect("test corruption fixture requires an unpoisoned mutex");
        state.active = active;
    }
}

/// Cloneable port into one process resource owner.
///
/// The port is constructed only from an explicit owner policy and is shared by
/// all attempts created by a `Transport`. Attempts can request the fixed
/// structural connector claim, but only this owner can admit it.
#[derive(Clone)]
pub struct ConnectorResourceOwnerPort {
    inner: Arc<ConnectorResourceOwnerInner>,
}

impl ConnectorResourceOwnerPort {
    pub(crate) fn new(policy: ConnectorResourcePolicy) -> Self {
        Self {
            inner: Arc::new(ConnectorResourceOwnerInner::new(policy)),
        }
    }

    pub fn report(&self) -> ConnectorResourceOwnerReport {
        self.inner.report()
    }

    pub(crate) fn policy(&self) -> ConnectorResourcePolicy {
        self.inner.policy
    }

    pub(crate) fn callbacks(&self) -> ConnectorCallbackPolicy {
        self.inner.policy.callbacks
    }

    pub(crate) fn native_close_timeout(&self) -> Duration {
        self.inner.policy.native_close_timeout
    }

    pub(crate) fn poison_accounting(&self) {
        self.inner.poison_accounting();
    }
}

#[cfg(test)]
impl From<PreAuthResourceClaim> for ConnectorResourceOwnerPort {
    fn from(capacity: PreAuthResourceClaim) -> Self {
        let candidates = usize::try_from(
            capacity.by_family[PreAuthResourceFamily::TransportObject.index()].items(),
        )
        .ok()
        .and_then(NonZeroUsize::new)
        .expect("test owner capacity includes at least one connector");
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(one, one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            NonZeroUsize::new(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
                .expect("endpoint frame fixture limit is nonzero"),
            Duration::from_secs(1),
        )
        .expect("test realtime enqueue deadline is nonzero");
        let policy = ConnectorResourcePolicy::new(candidates, callbacks, Duration::from_secs(1))
            .expect("test close timeout is nonzero");
        Self::new(policy)
    }
}

/// One live child claim against an attempt's aggregate reservation.
///
/// Dropping the child returns its claim. This guard is created before the
/// allocation closure runs, so a candidate cannot consume resources first and
/// ask for accounting afterward.
struct ConnectorCandidateReservation {
    owner: Arc<ConnectorResourceOwnerInner>,
    claim: PreAuthResourceClaim,
    release_on_drop: bool,
}

impl ConnectorCandidateReservation {
    fn transition(&mut self, next: PreAuthResourceClaim) -> bool {
        if !self.owner.transition(self.claim, next) {
            return false;
        }
        self.claim = next;
        true
    }

    /// Convert this exact live claim into a process-owned failed-cleanup slot.
    /// The aggregate already includes the claim, so this records the terminal
    /// disposition and prevents `Drop` from making the slot reusable.
    fn retain_after_cleanup_failure(&mut self) {
        if !self.release_on_drop {
            return;
        }
        let mut state = match self.owner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.accounting_poisoned = true;
                self.release_on_drop = false;
                return;
            }
        };
        match state.failed_cleanup_candidates.checked_add(1) {
            Some(retained) => state.failed_cleanup_candidates = retained,
            None => state.accounting_poisoned = true,
        }
        self.release_on_drop = false;
    }
}

impl Drop for ConnectorCandidateReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        let mut state = match self.owner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                state.accounting_poisoned = true;
                return;
            }
        };
        if state.accounting_poisoned {
            return;
        }
        match state.active.checked_sub(self.claim) {
            Some(active) if state.active_candidates > 0 => {
                state.active = active;
                state.active_candidates -= 1;
            }
            None => state.accounting_poisoned = true,
            Some(_) => state.accounting_poisoned = true,
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
    resource_owner: ConnectorResourceOwnerPort,
    #[cfg(test)]
    aggregate: Arc<ConnectorResourceOwnerInner>,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    fn admitted(
        runtime: RuntimeIncarnation,
        resource_owner: impl Into<ConnectorResourceOwnerPort>,
    ) -> (Self, AttemptLifetime) {
        let resource_owner = resource_owner.into();
        let (retired, _retirement_receiver) = watch::channel(false);
        let attempt = Arc::new(AttemptOwnership {
            runtime,
            active: AtomicBool::new(true),
            transition: Mutex::new(()),
            retired,
        });
        let lifetime = AttemptLifetime {
            attempt: Arc::clone(&attempt),
        };
        (
            Self {
                attempt,
                #[cfg(test)]
                aggregate: Arc::clone(&resource_owner.inner),
                resource_owner,
            },
            lifetime,
        )
    }

    /// Reserve one child and only then run the candidate allocation.
    ///
    /// The attempt permit remains alive and may issue more child reservations
    /// from the same aggregate. The closure is never called when admission
    /// fails.
    fn allocate_connector_candidate<T>(
        &self,
        claim: ConnectorCandidateResourceClaim,
        allocate: impl FnOnce() -> T,
    ) -> Option<(ConnectorCandidateCapability, T)> {
        let capability = self.reserve_connector_candidate(claim)?;
        let candidate = allocate();
        Some((capability, candidate))
    }

    /// Reserve the opening claim before asynchronous connector construction.
    /// The attempt permit remains available for other racing candidates.
    pub(crate) fn reserve_connector_candidate(
        &self,
        claim: ConnectorCandidateResourceClaim,
    ) -> Option<ConnectorCandidateCapability> {
        let _transition = self.attempt.transition.lock().ok()?;
        if !self.attempt.active.load(Ordering::Acquire) {
            return None;
        }
        let reservation = self.resource_owner.inner.reserve(claim.opening)?;
        Some(ConnectorCandidateCapability {
            attempt: Arc::clone(&self.attempt),
            reservation,
            connected_claim: claim.connected,
        })
    }
}

/// Admit one single-candidate attempt at the exact Arc 03 connector floor.
/// This attempt-local capacity is not a process or ingress limit.
pub(crate) fn admit_single_connector_candidate(
    runtime: RuntimeIncarnation,
    resource_owner: ConnectorResourceOwnerPort,
) -> (
    PreAuthAttemptPermit,
    AttemptLifetime,
    ConnectorCandidateResourceClaim,
) {
    let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, resource_owner);
    (permit, lifetime, claim)
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
/// use myownmesh_core::runtime::attempt::ConnectorCandidateCapability;
///
/// let public_peer_id = String::new();
/// let _candidate = ConnectorCandidateCapability::from(public_peer_id);
/// ```
#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
pub struct ConnectorCandidateCapability {
    attempt: Arc<AttemptOwnership>,
    reservation: ConnectorCandidateReservation,
    connected_claim: PreAuthResourceClaim,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl ConnectorCandidateCapability {
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.attempt.runtime
    }

    pub(crate) fn liveness(&self) -> AttemptLiveness {
        AttemptLiveness {
            attempt: Arc::clone(&self.attempt),
        }
    }

    pub(crate) fn is_live(&self) -> bool {
        let Ok(_transition) = self.attempt.transition.lock() else {
            return false;
        };
        self.attempt.active.load(Ordering::Acquire)
    }

    pub(crate) fn retain_after_cleanup_failure(&mut self) {
        self.reservation.retain_after_cleanup_failure();
    }

    pub(crate) fn promote_if_live<T>(self, promote: impl FnOnce(Self) -> T) -> Option<T> {
        self.try_promote_if_live(promote).ok()
    }

    /// Promote without losing cleanup ownership when retirement or a
    /// fail-closed aggregate refuses the transition.
    #[allow(
        clippy::result_large_err,
        reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
    )]
    pub(crate) fn try_promote_if_live<T>(
        mut self,
        promote: impl FnOnce(Self) -> T,
    ) -> std::result::Result<T, Self> {
        let attempt = Arc::clone(&self.attempt);
        let _transition = match attempt.transition.lock() {
            Ok(transition) => transition,
            Err(_) => return Err(self),
        };
        if !attempt.active.load(Ordering::Acquire) {
            return Err(self);
        }
        if !self.reservation.transition(self.connected_claim) {
            return Err(self);
        }
        Ok(promote(self))
    }

    #[cfg(test)]
    pub(crate) fn reservation_is_active_for_test(&self) -> bool {
        self.reservation.owner.active() != PreAuthResourceClaim::ZERO
    }

    #[cfg(test)]
    fn belongs_to(&self, permit: &PreAuthAttemptPermit) -> bool {
        Arc::ptr_eq(&self.attempt, &permit.attempt)
            && Arc::ptr_eq(&self.reservation.owner, &permit.resource_owner.inner)
    }
}

#[cfg(test)]
fn candidate_capacity(items: u64) -> PreAuthResourceClaim {
    PreAuthResourceClaim::single(
        PreAuthResourceFamily::TransportObject,
        ResourceUse::observed(items, 0, 0, 0),
    )
}

#[cfg(test)]
fn candidate_claim() -> ConnectorCandidateResourceClaim {
    ConnectorCandidateResourceClaim::checked(candidate_capacity(1), candidate_capacity(1))
        .expect("one transport object is one connector candidate")
}

#[cfg(test)]
pub(crate) fn connector_candidate_for_test(
    runtime: RuntimeIncarnation,
) -> (ConnectorCandidateCapability, AttemptLifetime) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, claim.aggregate_capacity());
    let capability = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its exact fixture claim");
    (capability, lifetime)
}

#[cfg(test)]
pub(crate) fn two_connector_candidates_for_test(
    runtime: RuntimeIncarnation,
) -> (
    ConnectorCandidateCapability,
    ConnectorCandidateCapability,
    AttemptLifetime,
) {
    let claim = candidate_claim();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, candidate_capacity(2));
    let first = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its first candidate");
    let second = permit
        .allocate_connector_candidate(claim, || ())
        .map(|(capability, ())| capability)
        .expect("the fixture aggregate admits its second candidate");
    (first, second, lifetime)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn explicit_test_policy(max_active_candidates: usize) -> ConnectorResourcePolicy {
        let one = NonZeroUsize::new(1).expect("fixture value is nonzero");
        let callbacks = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(one, one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            NonZeroUsize::new(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
                .expect("fixture real-time unit limit is nonzero"),
            Duration::from_secs(1),
        )
        .expect("fixture real-time enqueue deadline is nonzero");
        ConnectorResourcePolicy::new(
            NonZeroUsize::new(max_active_candidates).expect("fixture connector bound is nonzero"),
            callbacks,
            Duration::from_secs(1),
        )
        .expect("fixture close timeout is nonzero")
    }

    #[test]
    fn v4_arc03d_process_root_shares_one_connector_limit_across_mesh_runtimes() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let policy = explicit_test_policy(1);
        let first_owner = root
            .install_connector_policy(policy)
            .expect("first Mesh runtime installs the policy");
        let second_owner = root
            .install_connector_policy(policy)
            .expect("second Mesh runtime reuses the policy");
        let claim = candidate_claim();
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_owner);
        let first = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh runtime consumes the process slot");
        let (second_attempt, _second_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), second_owner);
        assert!(second_attempt.reserve_connector_candidate(claim).is_none());
        drop(first);
        assert!(second_attempt.reserve_connector_candidate(claim).is_some());
    }

    #[test]
    fn v4_arc03d_process_root_rejects_a_conflicting_policy() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let installed = explicit_test_policy(1);
        let requested = explicit_test_policy(2);
        root.install_connector_policy(installed)
            .expect("fixture installs its first policy");
        let error = match root.install_connector_policy(requested) {
            Ok(_) => panic!("a live process root cannot split its connector limit"),
            Err(error) => error,
        };
        assert_eq!(error.installed, installed);
        assert_eq!(error.requested, requested);
    }

    #[test]
    fn v4_arc03d_concurrent_process_policy_installation_has_one_winner() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let first_policy = explicit_test_policy(1);
        let second_policy = explicit_test_policy(2);
        let barrier = Arc::new(std::sync::Barrier::new(3));

        let first_root = root.clone();
        let first_barrier = Arc::clone(&barrier);
        let first = std::thread::spawn(move || {
            first_barrier.wait();
            first_root.install_connector_policy(first_policy)
        });
        let second_root = root.clone();
        let second_barrier = Arc::clone(&barrier);
        let second = std::thread::spawn(move || {
            second_barrier.wait();
            second_root.install_connector_policy(second_policy)
        });

        barrier.wait();
        let first_result = first.join().expect("first installer joins");
        let second_result = second.join().expect("second installer joins");
        assert_ne!(first_result.is_ok(), second_result.is_ok());

        let installed = root
            .connector_resource_owner()
            .expect("one concurrent installer owns the root")
            .policy();
        for result in [first_result, second_result] {
            match result {
                Ok(owner) => assert_eq!(owner.policy(), installed),
                Err(conflict) => {
                    assert_eq!(conflict.installed, installed);
                    assert_ne!(conflict.requested, installed);
                }
            }
        }
    }

    #[test]
    fn v4_arc03d_callback_policy_rejects_runtime_panicking_capacity() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let unsupported = NonZeroUsize::new(
            tokio::sync::Semaphore::MAX_PERMITS
                .checked_add(1)
                .expect("Tokio's maximum is below usize::MAX"),
        )
        .expect("the unsupported fixture is nonzero");

        let error = ConnectorCallbackPolicy::new(
            ConnectorCallbackMailboxCapacities::new(unsupported, one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            one,
            Duration::from_secs(1),
        )
        .expect_err("policy construction rejects a capacity that mpsc::channel would panic on");

        assert!(matches!(
            error,
            ConnectorCallbackPolicyError::MailboxCapacityExceedsRuntimeLimit {
                class: "control",
                requested,
                maximum,
            } if requested == tokio::sync::Semaphore::MAX_PERMITS + 1
                && maximum == tokio::sync::Semaphore::MAX_PERMITS
        ));
    }

    #[test]
    fn v4_arc02_attempt_issues_multiple_candidate_children_from_one_aggregate() {
        let runtime = crate::runtime::runtime_for_test();
        let one = candidate_claim();
        let two = candidate_capacity(2);
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(runtime.clone(), two);
        let (first, first_value) = permit
            .allocate_connector_candidate(one, || "first")
            .expect("first child fits");
        let (second, second_value) = permit
            .allocate_connector_candidate(one, || "second")
            .expect("second child fits");

        assert_eq!(first_value, "first");
        assert_eq!(second_value, "second");
        assert!(first.runtime().is_same(&runtime));
        assert!(first.is_live());
        assert!(first.belongs_to(&permit));
        assert!(second.belongs_to(&permit));
        assert_eq!(permit.aggregate.active(), two);
        assert!(permit
            .allocate_connector_candidate(one, || "third")
            .is_none());

        fn accepts_candidate(_: ConnectorCandidateCapability) {}
        accepts_candidate(first);
        assert_eq!(permit.aggregate.active(), one.opening);
        accepts_candidate(second);
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
    }

    #[test]
    fn v4_arc02_candidate_allocation_runs_only_after_child_reservation() {
        let one = candidate_claim();
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            one.aggregate_capacity(),
        );
        let (first, saw_active) = permit
            .allocate_connector_candidate(one, || permit.aggregate.active())
            .expect("fixture child fits");
        assert_eq!(saw_active, one.opening);

        let allocation_called = std::cell::Cell::new(false);
        let refused = permit.allocate_connector_candidate(one, || allocation_called.set(true));
        assert!(refused.is_none());
        assert!(!allocation_called.get());
        drop(first);
    }

    #[test]
    fn v4_arc02_inconsistent_child_release_poisoned_aggregate_stays_closed() {
        let child_claim = candidate_claim();
        let aggregate_capacity = candidate_capacity(2);
        let corrupted_active = PreAuthResourceClaim::ZERO;
        let (permit, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), aggregate_capacity);
        let (first, ()) = permit
            .allocate_connector_candidate(child_claim, || ())
            .expect("first child fits");
        let (second, ()) = permit
            .allocate_connector_candidate(child_claim, || ())
            .expect("second child fits");
        assert_eq!(permit.aggregate.active(), aggregate_capacity);

        permit.aggregate.corrupt_active_for_test(corrupted_active);
        drop(first);

        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
        let allocation_called = std::cell::Cell::new(false);
        assert!(permit
            .allocate_connector_candidate(child_claim, || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());

        drop(second);
        assert!(permit.aggregate.is_poisoned());
        assert_eq!(permit.aggregate.active(), corrupted_active);
    }

    #[test]
    fn v4_arc03_attempt_retirement_invalidates_every_connector_candidate() {
        let runtime = crate::runtime::runtime_for_test();
        let one = candidate_claim();
        let two = candidate_capacity(2);
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, two);
        let (first, ()) = permit
            .allocate_connector_candidate(one, || ())
            .expect("first connector candidate fits");
        let (second, ()) = permit
            .allocate_connector_candidate(one, || ())
            .expect("second connector candidate fits");

        assert!(first.is_live());
        assert!(second.is_live());
        lifetime.retire();
        assert!(!first.is_live());
        assert!(!second.is_live());
    }

    #[test]
    fn v4_arc03_retired_attempt_refuses_later_candidate_allocation() {
        let one = candidate_claim();
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            one.aggregate_capacity(),
        );
        lifetime.retire();
        let allocation_called = std::cell::Cell::new(false);

        assert!(permit
            .allocate_connector_candidate(one, || allocation_called.set(true))
            .is_none());
        assert!(!allocation_called.get());
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
    }

    #[test]
    fn v4_arc03_attempt_retirement_signal_replays_to_late_subscriber() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let liveness = candidate.liveness();
        lifetime.retire();

        assert!(!liveness.is_active());
        assert!(*liveness.subscribe_retirement().borrow());
    }

    #[test]
    fn v4_arc03_promotion_and_retirement_have_one_linearized_order() {
        let (candidate, lifetime) =
            connector_candidate_for_test(crate::runtime::runtime_for_test());
        let lifetime = Arc::new(lifetime);
        let (promotion_entered_tx, promotion_entered_rx) = std::sync::mpsc::channel();
        let (release_promotion_tx, release_promotion_rx) = std::sync::mpsc::channel();
        let promotion = std::thread::spawn(move || {
            candidate.promote_if_live(|candidate| {
                promotion_entered_tx
                    .send(())
                    .expect("test observes promotion inside transition");
                release_promotion_rx
                    .recv()
                    .expect("test releases promotion");
                candidate
            })
        });
        promotion_entered_rx
            .recv()
            .expect("promotion acquires the transition first");

        let retire_lifetime = Arc::clone(&lifetime);
        let (retirement_contended_tx, retirement_contended_rx) = std::sync::mpsc::channel();
        let (retired_tx, retired_rx) = std::sync::mpsc::channel();
        let retirement = std::thread::spawn(move || {
            let contended = matches!(
                retire_lifetime.attempt.transition.try_lock(),
                Err(std::sync::TryLockError::WouldBlock)
            );
            retirement_contended_tx
                .send(contended)
                .expect("test observes retirement waiting on promotion");
            if contended {
                retire_lifetime.retire();
                retired_tx.send(()).expect("retirement reports completion");
            }
        });
        let retirement_contended = retirement_contended_rx
            .recv()
            .expect("retirement shares the promotion transition");
        assert!(
            retired_rx.try_recv().is_err(),
            "retirement cannot pass an in-progress promotion"
        );

        release_promotion_tx
            .send(())
            .expect("release the promotion transition");
        assert!(
            promotion.join().expect("promotion thread joins").is_some(),
            "promotion linearized before retirement"
        );
        retirement.join().expect("retirement thread joins");
        assert!(
            retirement_contended,
            "retirement must contend on the same transition as promotion"
        );
        retired_rx
            .recv()
            .expect("retirement completes after promotion");
        assert!(!lifetime.is_active());
    }

    #[test]
    fn v4_arc03_reservation_precedes_allocation_and_retirement_fences_result() {
        let claim = candidate_claim();
        let (permit, lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            claim.aggregate_capacity(),
        );
        let lifetime = Arc::new(lifetime);
        let (allocation_entered_tx, allocation_entered_rx) = std::sync::mpsc::channel();
        let (release_allocation_tx, release_allocation_rx) = std::sync::mpsc::channel();
        let allocation = std::thread::spawn(move || {
            permit.allocate_connector_candidate(claim, || {
                allocation_entered_tx
                    .send(())
                    .expect("test observes allocation inside transition");
                release_allocation_rx
                    .recv()
                    .expect("test releases allocation");
            })
        });
        allocation_entered_rx
            .recv()
            .expect("allocation acquires the transition first");

        lifetime.retire();
        assert!(!lifetime.is_active());
        release_allocation_tx
            .send(())
            .expect("release allocation transition");
        let (candidate, ()) = allocation
            .join()
            .expect("allocation thread joins")
            .expect("reservation completed before allocation began");
        assert!(!candidate.is_live());
    }

    #[test]
    fn v4_arc03_resource_families_cannot_substitute_for_each_other() {
        let one_candidate = candidate_claim();
        let one_task = PreAuthResourceClaim::single(
            PreAuthResourceFamily::Task,
            ResourceUse::observed(1, 0, 0, 0),
        );
        let capacity = one_candidate
            .opening
            .checked_add(one_task)
            .expect("fixture sum");
        let (permit, _lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), capacity);
        let (candidate, ()) = permit
            .allocate_connector_candidate(one_candidate, || ())
            .expect("candidate family has one item of capacity");

        assert!(
            permit
                .allocate_connector_candidate(one_candidate, || ())
                .is_none(),
            "unused task capacity must not authorize another candidate object"
        );
        assert_eq!(
            permit
                .aggregate
                .active()
                .for_family(PreAuthResourceFamily::Task),
            ResourceUse::ZERO
        );
        drop(candidate);
    }

    #[test]
    fn v4_arc03_connector_candidate_claim_rejects_zero_and_mislabeled_resources() {
        assert!(ConnectorCandidateResourceClaim::checked(
            PreAuthResourceClaim::ZERO,
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            PreAuthResourceClaim::single(
                PreAuthResourceFamily::Task,
                ResourceUse::observed(1, 0, 0, 0),
            ),
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            candidate_capacity(2),
            candidate_capacity(1)
        )
        .is_none());
        assert!(ConnectorCandidateResourceClaim::checked(
            candidate_capacity(1),
            candidate_capacity(1)
        )
        .is_some());
    }

    #[test]
    fn v4_arc03_promotion_atomically_releases_candidate_only_claims() {
        let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
        let (permit, _lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            claim.aggregate_capacity(),
        );
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("opening claim fits");
        assert_eq!(permit.aggregate.active(), claim.opening);

        let connected = candidate
            .promote_if_live(|candidate| candidate)
            .expect("live candidate promotes");
        assert_eq!(permit.aggregate.active(), claim.connected);
        assert_eq!(
            permit
                .aggregate
                .active()
                .for_family(PreAuthResourceFamily::ConnectorSpecificWork),
            ResourceUse::ZERO
        );
        drop(connected);
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
    }
}
