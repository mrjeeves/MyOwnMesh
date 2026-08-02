//! Capability boundary for one bounded connection attempt.
//!
//! The attempt owner admits connector candidates before allocation, retires
//! losing work, and transfers an exact child claim when a candidate connects.

use std::collections::HashMap;
use std::num::{NonZeroU64, NonZeroUsize};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
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
}

impl ConnectorCallbackMailboxCapacities {
    pub const fn new(control: NonZeroUsize, endpoint_data: NonZeroUsize) -> Self {
        Self {
            control,
            endpoint_data,
        }
    }

    pub const fn control(self) -> NonZeroUsize {
        self.control
    }

    pub const fn endpoint_data(self) -> NonZeroUsize {
        self.endpoint_data
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
/// real-time unit limit and useful lifetime are separate operational inputs
/// because an encoded access unit is not an endpoint message frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCallbackPolicy {
    mailboxes: ConnectorCallbackMailboxCapacities,
    service_weights: ConnectorCallbackServiceWeights,
    max_realtime_unit_bytes: NonZeroUsize,
    realtime_useful_lifetime: Duration,
    realtime_flows: Option<ConnectorRealtimeFlowPolicy>,
}

/// Owner-selected resource envelope for connector-local real-time flows.
///
/// The envelope is codec-neutral. It bounds independent flow queues and the
/// bytes retained by all real-time work on one connector. No production
/// default exists. Omitting this policy leaves real-time flow admission
/// disabled while control and endpoint-data connector work remains usable.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorRealtimeFlowPolicy {
    max_active_flows: NonZeroUsize,
    queue_capacity_per_flow: NonZeroUsize,
    max_inbound_fragment_bytes: NonZeroUsize,
    max_in_progress_units: NonZeroUsize,
    max_retained_bytes: NonZeroUsize,
}

impl ConnectorRealtimeFlowPolicy {
    pub const fn new(
        max_active_flows: NonZeroUsize,
        queue_capacity_per_flow: NonZeroUsize,
        max_inbound_fragment_bytes: NonZeroUsize,
        max_in_progress_units: NonZeroUsize,
        max_retained_bytes: NonZeroUsize,
    ) -> Self {
        Self {
            max_active_flows,
            queue_capacity_per_flow,
            max_inbound_fragment_bytes,
            max_in_progress_units,
            max_retained_bytes,
        }
    }

    pub const fn max_active_flows(self) -> NonZeroUsize {
        self.max_active_flows
    }

    pub const fn queue_capacity_per_flow(self) -> NonZeroUsize {
        self.queue_capacity_per_flow
    }

    pub const fn max_inbound_fragment_bytes(self) -> NonZeroUsize {
        self.max_inbound_fragment_bytes
    }

    pub const fn max_in_progress_units(self) -> NonZeroUsize {
        self.max_in_progress_units
    }

    pub const fn max_retained_bytes(self) -> NonZeroUsize {
        self.max_retained_bytes
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ConnectorCallbackPolicyError {
    #[error("real-time unit useful lifetime must be nonzero")]
    ZeroRealtimeUsefulLifetime,
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
        realtime_useful_lifetime: Duration,
    ) -> std::result::Result<Self, ConnectorCallbackPolicyError> {
        if realtime_useful_lifetime.is_zero() {
            return Err(ConnectorCallbackPolicyError::ZeroRealtimeUsefulLifetime);
        }
        for (class, requested) in [
            ("control", mailboxes.control().get()),
            ("endpoint-data", mailboxes.endpoint_data().get()),
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
            realtime_useful_lifetime,
            realtime_flows: None,
        })
    }

    /// Install the explicit connector-local real-time resource envelope.
    ///
    /// This is a builder instead of a fallback. Production callers that need
    /// real-time work must deliberately provide every value.
    pub const fn with_realtime_flow_policy(
        mut self,
        realtime_flows: ConnectorRealtimeFlowPolicy,
    ) -> Self {
        self.realtime_flows = Some(realtime_flows);
        self
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

    pub const fn realtime_useful_lifetime(self) -> Duration {
        self.realtime_useful_lifetime
    }

    pub const fn realtime_flow_policy(self) -> Option<ConnectorRealtimeFlowPolicy> {
        self.realtime_flows
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn unrestricted_lab(mailbox_capacity: NonZeroUsize) -> Self {
        Self {
            mailboxes: ConnectorCallbackMailboxCapacities::new(mailbox_capacity, mailbox_capacity),
            service_weights: ConnectorCallbackServiceWeights::new(
                mailbox_capacity,
                mailbox_capacity,
                mailbox_capacity,
            ),
            // Leave arithmetic headroom for simultaneous guarded input and
            // output observations in the raw compatibility laboratory.
            max_realtime_unit_bytes: NonZeroUsize::new(usize::MAX / 2)
                .expect("half of usize::MAX is nonzero"),
            // Raw transport labs are the compatibility bypass. Production
            // policy construction rejects a zero useful lifetime.
            realtime_useful_lifetime: Duration::ZERO,
            realtime_flows: Some(ConnectorRealtimeFlowPolicy::new(
                NonZeroUsize::new(usize::MAX / 2).expect("half of usize::MAX is nonzero"),
                mailbox_capacity,
                NonZeroUsize::new(usize::MAX).expect("usize::MAX is nonzero"),
                NonZeroUsize::new(usize::MAX).expect("usize::MAX is nonzero"),
                NonZeroUsize::new(usize::MAX).expect("usize::MAX is nonzero"),
            )),
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

/// Explicit owner-selected connector ceiling for one live [`crate::Mesh`]
/// runtime.
///
/// This value has no `Default` and is not derived from the process ceiling or
/// the number of Mesh runtimes. Arc 03E implements a hard child ceiling only.
/// It does not reserve capacity for a child and does not borrow capacity from
/// another child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshConnectorResourcePolicy {
    max_active_candidates: NonZeroUsize,
}

/// Complete connector admission policy for one connector-capable [`crate::Mesh`].
///
/// The process component is installed once and shared across Mesh runtimes.
/// The Mesh component is an independent hard ceiling for this exact runtime.
/// Both values are owner-selected. Neither is inferred from the other.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectorCapableResourcePolicy {
    process: ConnectorResourcePolicy,
    mesh: MeshConnectorResourcePolicy,
}

impl ConnectorCapableResourcePolicy {
    pub const fn new(process: ConnectorResourcePolicy, mesh: MeshConnectorResourcePolicy) -> Self {
        Self { process, mesh }
    }

    pub const fn process(self) -> ConnectorResourcePolicy {
        self.process
    }

    pub const fn mesh(self) -> MeshConnectorResourcePolicy {
        self.mesh
    }
}

impl MeshConnectorResourcePolicy {
    pub const fn new(max_active_candidates: NonZeroUsize) -> Self {
        Self {
            max_active_candidates,
        }
    }

    pub const fn max_active_candidates(self) -> NonZeroUsize {
        self.max_active_candidates
    }
}

/// Point-in-time report for one exact live Mesh connector scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshConnectorResourceReport {
    pub max_active_candidates: NonZeroUsize,
    pub active_candidates: usize,
    /// Exact claims retained after native cleanup failure in this Mesh scope.
    pub failed_cleanup_candidates: usize,
    /// The process and this exact child can no longer prove their aggregate.
    pub accounting_poisoned: bool,
}

/// A process owner could not issue a new Mesh connector scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeshConnectorResourceScopeIssueError {
    #[error("the process connector resource policy is not installed")]
    ProcessPolicyMissing,
    #[error("connector resource accounting is unavailable")]
    AccountingUnavailable,
    #[error("the process exhausted its local Mesh connector scope identities")]
    ScopeIdentityExhausted,
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
    next_mesh_scope_id: Option<NonZeroU64>,
    mesh_scopes: HashMap<NonZeroU64, MeshConnectorResourceOwnerState>,
}

struct MeshConnectorResourceOwnerState {
    policy: MeshConnectorResourcePolicy,
    active: PreAuthResourceClaim,
    active_candidates: usize,
    failed_cleanup_candidates: usize,
    accounting_poisoned: bool,
    report: Arc<MeshConnectorResourceReportState>,
}

struct MeshConnectorResourceReportState {
    active_candidates: AtomicUsize,
    failed_cleanup_candidates: AtomicUsize,
    accounting_poisoned: AtomicBool,
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
                next_mesh_scope_id: NonZeroU64::new(1),
                mesh_scopes: HashMap::new(),
            }),
        }
    }

    fn issue_mesh_scope(
        self: &Arc<Self>,
        policy: MeshConnectorResourcePolicy,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_all_locked(&mut state);
                return Err(MeshConnectorResourceScopeIssueError::AccountingUnavailable);
            }
        };
        if state.accounting_poisoned {
            return Err(MeshConnectorResourceScopeIssueError::AccountingUnavailable);
        }
        let id = state
            .next_mesh_scope_id
            .ok_or(MeshConnectorResourceScopeIssueError::ScopeIdentityExhausted)?;
        state.next_mesh_scope_id = id.get().checked_add(1).and_then(NonZeroU64::new);
        let report = Arc::new(MeshConnectorResourceReportState {
            active_candidates: AtomicUsize::new(0),
            failed_cleanup_candidates: AtomicUsize::new(0),
            accounting_poisoned: AtomicBool::new(false),
        });
        state.mesh_scopes.insert(
            id,
            MeshConnectorResourceOwnerState {
                policy,
                active: PreAuthResourceClaim::ZERO,
                active_candidates: 0,
                failed_cleanup_candidates: 0,
                accounting_poisoned: false,
                report: Arc::clone(&report),
            },
        );
        drop(state);
        Ok(MeshConnectorResourceScope {
            token: Arc::new(MeshConnectorResourceScopeToken {
                id,
                owner: Arc::clone(self),
                policy,
                report,
            }),
        })
    }

    fn reserve(
        self: &Arc<Self>,
        mesh_scope: Arc<MeshConnectorResourceScopeToken>,
        claim: PreAuthResourceClaim,
    ) -> Option<ConnectorCandidateReservation> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope.id);
                return None;
            }
        };
        if state.accounting_poisoned {
            return None;
        }
        if state.active_candidates >= self.policy.max_active_candidates.get() {
            return None;
        }
        let Some(child) = state.mesh_scopes.get(&mesh_scope.id) else {
            Self::poison_all_locked(&mut state);
            return None;
        };
        if child.accounting_poisoned
            || child.active_candidates >= child.policy.max_active_candidates.get()
        {
            return None;
        }
        let next_process = state.active.checked_add(claim)?;
        let next_process_candidates = state.active_candidates.checked_add(1)?;
        let next_child = child.active.checked_add(claim)?;
        let next_child_candidates = child.active_candidates.checked_add(1)?;
        state.active = next_process;
        state.active_candidates = next_process_candidates;
        let Some(child) = state.mesh_scopes.get_mut(&mesh_scope.id) else {
            Self::poison_all_locked(&mut state);
            return None;
        };
        child.active = next_child;
        child.active_candidates = next_child_candidates;
        child
            .report
            .active_candidates
            .store(next_child_candidates, Ordering::Release);
        Some(ConnectorCandidateReservation {
            owner: Arc::clone(self),
            mesh_scope,
            claim,
            release_on_drop: true,
        })
    }

    /// Replace one live child's claim without exposing an unreserved gap.
    /// Inconsistent subtraction poisons the aggregate and preserves its last
    /// conservative value. Capacity refusal leaves the old claim live.
    fn transition(
        &self,
        mesh_scope_id: NonZeroU64,
        old: PreAuthResourceClaim,
        new: PreAuthResourceClaim,
    ) -> bool {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope_id);
                return false;
            }
        };
        if state.accounting_poisoned {
            return false;
        }
        let Some(child) = state.mesh_scopes.get(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return false;
        };
        if child.accounting_poisoned {
            return false;
        }
        let Some(process_without_old) = state.active.checked_sub(old) else {
            Self::poison_locked(&mut state, mesh_scope_id);
            return false;
        };
        let Some(child_without_old) = child.active.checked_sub(old) else {
            Self::poison_locked(&mut state, mesh_scope_id);
            return false;
        };
        let Some(next_process) = process_without_old.checked_add(new) else {
            return false;
        };
        let Some(next_child) = child_without_old.checked_add(new) else {
            return false;
        };
        state.active = next_process;
        let Some(child) = state.mesh_scopes.get_mut(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return false;
        };
        child.active = next_child;
        true
    }

    fn retain_after_cleanup_failure(&self, mesh_scope_id: NonZeroU64) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope_id);
                return;
            }
        };
        if state.accounting_poisoned {
            return;
        }
        let Some(child) = state.mesh_scopes.get(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return;
        };
        let Some(process_retained) = state.failed_cleanup_candidates.checked_add(1) else {
            Self::poison_locked(&mut state, mesh_scope_id);
            return;
        };
        let Some(child_retained) = child.failed_cleanup_candidates.checked_add(1) else {
            Self::poison_locked(&mut state, mesh_scope_id);
            return;
        };
        state.failed_cleanup_candidates = process_retained;
        let Some(child) = state.mesh_scopes.get_mut(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return;
        };
        child.failed_cleanup_candidates = child_retained;
        child
            .report
            .failed_cleanup_candidates
            .store(child_retained, Ordering::Release);
    }

    fn release(&self, mesh_scope_id: NonZeroU64, claim: PreAuthResourceClaim) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope_id);
                return;
            }
        };
        if state.accounting_poisoned {
            return;
        }
        let Some(child) = state.mesh_scopes.get(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return;
        };
        let next_process = state.active.checked_sub(claim);
        let next_child = child.active.checked_sub(claim);
        let next_process_candidates = state.active_candidates.checked_sub(1);
        let next_child_candidates = child.active_candidates.checked_sub(1);
        let (
            Some(next_process),
            Some(next_child),
            Some(next_process_candidates),
            Some(next_child_candidates),
        ) = (
            next_process,
            next_child,
            next_process_candidates,
            next_child_candidates,
        )
        else {
            Self::poison_locked(&mut state, mesh_scope_id);
            return;
        };
        state.active = next_process;
        state.active_candidates = next_process_candidates;
        let Some(child) = state.mesh_scopes.get_mut(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return;
        };
        child.active = next_child;
        child.active_candidates = next_child_candidates;
        child
            .report
            .active_candidates
            .store(next_child_candidates, Ordering::Release);
    }

    fn retire_mesh_scope(&self, mesh_scope_id: NonZeroU64) {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope_id);
                return;
            }
        };
        let Some(child) = state.mesh_scopes.get(&mesh_scope_id) else {
            Self::poison_all_locked(&mut state);
            return;
        };
        if child.failed_cleanup_candidates > 0 {
            if child.active_candidates == child.failed_cleanup_candidates
                && child.active != PreAuthResourceClaim::ZERO
            {
                // Every remaining claim is deliberately process-owned after a
                // native close failure. Retain the child record so its exact
                // accounting remains attributable without poisoning healthy
                // process capacity or unrelated Mesh scopes.
                return;
            }
            Self::poison_locked(&mut state, mesh_scope_id);
            return;
        }
        if child.active_candidates != 0 || child.active != PreAuthResourceClaim::ZERO {
            Self::poison_locked(&mut state, mesh_scope_id);
            return;
        }
        state.mesh_scopes.remove(&mesh_scope_id);
    }

    fn poison_mesh_accounting(&self, mesh_scope_id: NonZeroU64) {
        match self.state.lock() {
            Ok(mut state) => Self::poison_locked(&mut state, mesh_scope_id),
            Err(poisoned) => {
                let mut state = poisoned.into_inner();
                Self::poison_locked(&mut state, mesh_scope_id);
            }
        }
    }

    fn poison_locked(state: &mut ConnectorResourceOwnerState, mesh_scope_id: NonZeroU64) {
        if let Some(child) = state.mesh_scopes.get_mut(&mesh_scope_id) {
            child.accounting_poisoned = true;
        }
        Self::poison_all_locked(state);
    }

    fn poison_all_locked(state: &mut ConnectorResourceOwnerState) {
        state.accounting_poisoned = true;
        for child in state.mesh_scopes.values_mut() {
            child.accounting_poisoned = true;
            child
                .report
                .accounting_poisoned
                .store(true, Ordering::Release);
        }
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
                    let mut state = poisoned.into_inner();
                    Self::poison_all_locked(&mut state);
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

/// Cloneable administrative port into the one process connector owner.
///
/// This port reports the process aggregate but cannot be used as an attempt
/// capability. The process root uses it to issue unforgeable per-Mesh child
/// scopes, and only those child scopes can admit connector candidates.
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

    pub(crate) fn issue_mesh_scope(
        &self,
        policy: MeshConnectorResourcePolicy,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        self.inner.issue_mesh_scope(policy)
    }

    pub(crate) fn policy(&self) -> ConnectorResourcePolicy {
        self.inner.policy
    }
}

struct MeshConnectorResourceScopeToken {
    id: NonZeroU64,
    owner: Arc<ConnectorResourceOwnerInner>,
    policy: MeshConnectorResourcePolicy,
    report: Arc<MeshConnectorResourceReportState>,
}

impl Drop for MeshConnectorResourceScopeToken {
    fn drop(&mut self) {
        self.owner.retire_mesh_scope(self.id);
    }
}

/// Unforgeable admission and accounting scope for one live [`crate::Mesh`]
/// runtime.
///
/// Only [`crate::ProcessResourceRoot`] can issue this scope. Clones retain the
/// same exact local scope. The value is not serializable and has no public
/// constructor.
#[derive(Clone)]
pub struct MeshConnectorResourceScope {
    token: Arc<MeshConnectorResourceScopeToken>,
}

impl MeshConnectorResourceScope {
    pub fn report(&self) -> MeshConnectorResourceReport {
        MeshConnectorResourceReport {
            max_active_candidates: self.token.policy.max_active_candidates(),
            active_candidates: self.token.report.active_candidates.load(Ordering::Acquire),
            failed_cleanup_candidates: self
                .token
                .report
                .failed_cleanup_candidates
                .load(Ordering::Acquire),
            accounting_poisoned: self
                .token
                .report
                .accounting_poisoned
                .load(Ordering::Acquire),
        }
    }

    pub(crate) fn process_report(&self) -> ConnectorResourceOwnerReport {
        self.token.owner.report()
    }

    pub(crate) fn callbacks(&self) -> ConnectorCallbackPolicy {
        self.token.owner.policy.callbacks
    }

    pub(crate) fn native_close_timeout(&self) -> Duration {
        self.token.owner.policy.native_close_timeout
    }

    pub(crate) fn poison_accounting(&self) {
        self.token.owner.poison_mesh_accounting(self.token.id);
    }

    fn reserve(&self, claim: PreAuthResourceClaim) -> Option<ConnectorCandidateReservation> {
        self.token.owner.reserve(Arc::clone(&self.token), claim)
    }

    #[cfg(test)]
    fn active(&self) -> Option<PreAuthResourceClaim> {
        let state = match self.token.owner.state.lock() {
            Ok(state) => state,
            Err(poisoned) => poisoned.into_inner(),
        };
        state
            .mesh_scopes
            .get(&self.token.id)
            .map(|scope| scope.active)
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
            ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            NonZeroUsize::new(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
                .expect("endpoint frame fixture limit is nonzero"),
            Duration::from_secs(1),
        )
        .expect("test real-time useful lifetime is nonzero");
        let policy = ConnectorResourcePolicy::new(candidates, callbacks, Duration::from_secs(1))
            .expect("test close timeout is nonzero");
        Self::new(policy)
    }
}

#[cfg(test)]
impl From<PreAuthResourceClaim> for MeshConnectorResourceScope {
    fn from(capacity: PreAuthResourceClaim) -> Self {
        let process_owner = ConnectorResourceOwnerPort::from(capacity);
        let candidates = usize::try_from(
            capacity.by_family[PreAuthResourceFamily::TransportObject.index()].items(),
        )
        .ok()
        .and_then(NonZeroUsize::new)
        .expect("test Mesh capacity includes at least one connector");
        process_owner
            .issue_mesh_scope(MeshConnectorResourcePolicy::new(candidates))
            .expect("test process owner issues one explicit Mesh scope")
    }
}

/// One live child claim against an attempt's aggregate reservation.
///
/// Dropping the child returns its claim. This guard is created before the
/// allocation closure runs, so a candidate cannot consume resources first and
/// ask for accounting afterward.
struct ConnectorCandidateReservation {
    owner: Arc<ConnectorResourceOwnerInner>,
    mesh_scope: Arc<MeshConnectorResourceScopeToken>,
    claim: PreAuthResourceClaim,
    release_on_drop: bool,
}

impl ConnectorCandidateReservation {
    fn transition(&mut self, next: PreAuthResourceClaim) -> bool {
        if !self.owner.transition(self.mesh_scope.id, self.claim, next) {
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
        self.owner.retain_after_cleanup_failure(self.mesh_scope.id);
        self.release_on_drop = false;
    }
}

impl Drop for ConnectorCandidateReservation {
    fn drop(&mut self) {
        if !self.release_on_drop {
            return;
        }
        self.owner.release(self.mesh_scope.id, self.claim);
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
    resource_scope: MeshConnectorResourceScope,
    #[cfg(test)]
    aggregate: Arc<ConnectorResourceOwnerInner>,
}

#[allow(dead_code, reason = "Arc 03 moves the production attempt caller")]
impl PreAuthAttemptPermit {
    // The attempt owner will call this only after the resource owner admits
    // the work. It stays private until that production port is migrated.
    fn admitted(
        runtime: RuntimeIncarnation,
        resource_scope: impl Into<MeshConnectorResourceScope>,
    ) -> (Self, AttemptLifetime) {
        let resource_scope = resource_scope.into();
        #[cfg(test)]
        let aggregate = Arc::clone(&resource_scope.token.owner);
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
                aggregate,
                resource_scope,
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
        let reservation = self.resource_scope.reserve(claim.opening)?;
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
    resource_scope: MeshConnectorResourceScope,
) -> (
    PreAuthAttemptPermit,
    AttemptLifetime,
    ConnectorCandidateResourceClaim,
) {
    let claim = ConnectorCandidateResourceClaim::exact_connector_floor();
    let (permit, lifetime) = PreAuthAttemptPermit::admitted(runtime, resource_scope);
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
            && Arc::ptr_eq(&self.reservation.mesh_scope, &permit.resource_scope.token)
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
            ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::new(one, one, one),
            NonZeroUsize::new(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
                .expect("fixture real-time unit limit is nonzero"),
            Duration::from_secs(1),
        )
        .expect("fixture real-time useful lifetime is nonzero");
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
        root.install_connector_policy(policy)
            .expect("first Mesh runtime installs the policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        );
        let first_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the second Mesh scope");
        let claim = candidate_claim();
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope);
        let first = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh runtime consumes the process slot");
        let (second_attempt, _second_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), second_scope);
        assert!(second_attempt.reserve_connector_candidate(claim).is_none());
        drop(first);
        assert!(second_attempt.reserve_connector_candidate(claim).is_some());
    }

    #[test]
    fn v4_arc03e_mesh_scope_requires_the_single_installed_process_owner() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        let error = match root.issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        )) {
            Ok(_) => panic!("an ownerless process cannot issue a Mesh connector scope"),
            Err(error) => error,
        };
        assert_eq!(
            error,
            MeshConnectorResourceScopeIssueError::ProcessPolicyMissing
        );
    }

    #[test]
    fn v4_arc03e_mesh_ceiling_isolates_children_inside_the_process_cap() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(3))
            .expect("fixture installs the process policy");
        let first_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(1).expect("fixture first Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(3).expect("fixture second Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the second Mesh scope");
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope.clone());
        let (second_attempt, _second_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            second_scope.clone(),
        );
        let claim = candidate_claim();

        let first = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh uses its one explicit slot");
        assert!(
            first_attempt.reserve_connector_candidate(claim).is_none(),
            "the first Mesh cannot consume free process capacity above its child ceiling"
        );
        let second_a = second_attempt
            .reserve_connector_candidate(claim)
            .expect("second Mesh uses the second process slot");
        let second_b = second_attempt
            .reserve_connector_candidate(claim)
            .expect("second Mesh uses the third process slot");
        assert!(
            second_attempt.reserve_connector_candidate(claim).is_none(),
            "combined children cannot exceed the process cap"
        );

        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            3
        );
        assert_eq!(first_scope.report().active_candidates, 1);
        assert_eq!(second_scope.report().active_candidates, 2);

        drop(first);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            2
        );
        assert_eq!(first_scope.report().active_candidates, 0);
        assert!(second_attempt.reserve_connector_candidate(claim).is_some());
        drop(second_a);
        drop(second_b);
    }

    #[test]
    fn v4_arc03e_failed_cleanup_retains_the_exact_process_and_mesh_claim() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(2))
            .expect("fixture installs the process policy");
        let first_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(1).expect("fixture first Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(MeshConnectorResourcePolicy::new(
                NonZeroUsize::new(2).expect("fixture second Mesh ceiling is nonzero"),
            ))
            .expect("process owner issues the second Mesh scope");
        let (first_attempt, _first_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), first_scope.clone());
        let (second_attempt, _second_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            second_scope.clone(),
        );
        let claim = candidate_claim();

        let mut failed = first_attempt
            .reserve_connector_candidate(claim)
            .expect("first Mesh reserves its exact candidate");
        failed.retain_after_cleanup_failure();
        drop(failed);

        let process_report = root.connector_resource_owner().unwrap().report();
        let first_report = first_scope.report();
        assert_eq!(process_report.active_candidates, 1);
        assert_eq!(process_report.failed_cleanup_candidates, 1);
        assert_eq!(first_report.active_candidates, 1);
        assert_eq!(first_report.failed_cleanup_candidates, 1);
        assert!(!process_report.accounting_poisoned);
        assert!(!first_report.accounting_poisoned);
        assert!(first_attempt.reserve_connector_candidate(claim).is_none());

        let other = second_attempt
            .reserve_connector_candidate(claim)
            .expect("unrelated Mesh can use the remaining process slot");
        assert!(second_attempt.reserve_connector_candidate(claim).is_none());
        drop(other);
        assert_eq!(second_scope.report().active_candidates, 0);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            1
        );
    }

    #[test]
    fn v4_arc03e_final_failed_cleanup_scope_drop_keeps_unrelated_capacity_usable() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(2))
            .expect("fixture installs the process policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(1).expect("fixture Mesh ceiling is nonzero"),
        );
        let retained_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the retained Mesh scope");
        let (retained_attempt, retained_lifetime) = PreAuthAttemptPermit::admitted(
            crate::runtime::runtime_for_test(),
            retained_scope.clone(),
        );
        let mut failed = retained_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("retained Mesh reserves its exact candidate");
        failed.retain_after_cleanup_failure();
        drop(failed);
        drop(retained_attempt);
        drop(retained_lifetime);
        drop(retained_scope);

        let retained_report = root.connector_resource_owner().unwrap().report();
        assert_eq!(retained_report.active_candidates, 1);
        assert_eq!(retained_report.failed_cleanup_candidates, 1);
        assert!(!retained_report.accounting_poisoned);

        let unrelated_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("retained cleanup does not poison scope issuance");
        let (unrelated_attempt, _unrelated_lifetime) =
            PreAuthAttemptPermit::admitted(crate::runtime::runtime_for_test(), unrelated_scope);
        let unrelated = unrelated_attempt
            .reserve_connector_candidate(candidate_claim())
            .expect("unrelated Mesh uses the remaining process slot");
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            2
        );
        drop(unrelated);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            1
        );
        assert!(
            !root
                .connector_resource_owner()
                .unwrap()
                .report()
                .accounting_poisoned
        );
    }

    #[test]
    fn v4_arc03e_concurrent_children_never_oversubscribe_either_ceiling() {
        let root = crate::resource::ProcessResourceRoot::isolated();
        root.install_connector_policy(explicit_test_policy(3))
            .expect("fixture installs the process policy");
        let mesh_policy = MeshConnectorResourcePolicy::new(
            NonZeroUsize::new(2).expect("fixture Mesh ceiling is nonzero"),
        );
        let first_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the first Mesh scope");
        let second_scope = root
            .issue_mesh_connector_scope(mesh_policy)
            .expect("process owner issues the second Mesh scope");
        let barrier = Arc::new(std::sync::Barrier::new(9));
        let mut workers = Vec::new();
        for index in 0..8 {
            let scope = if index % 2 == 0 {
                first_scope.clone()
            } else {
                second_scope.clone()
            };
            let barrier = Arc::clone(&barrier);
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                scope.reserve(candidate_claim().opening)
            }));
        }
        barrier.wait();
        let reservations: Vec<_> = workers
            .into_iter()
            .filter_map(|worker| worker.join().expect("admission worker joins"))
            .collect();

        assert_eq!(reservations.len(), 3);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            3
        );
        assert!(first_scope.report().active_candidates <= 2);
        assert!(second_scope.report().active_candidates <= 2);
        drop(reservations);
        assert_eq!(
            root.connector_resource_owner()
                .unwrap()
                .report()
                .active_candidates,
            0
        );
        assert_eq!(first_scope.report().active_candidates, 0);
        assert_eq!(second_scope.report().active_candidates, 0);
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
            ConnectorCallbackMailboxCapacities::new(unsupported, one),
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
        assert!(permit.resource_scope.report().accounting_poisoned);
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
        assert_eq!(permit.resource_scope.active(), Some(claim.opening));

        let connected = candidate
            .promote_if_live(|candidate| candidate)
            .expect("live candidate promotes");
        assert_eq!(permit.aggregate.active(), claim.connected);
        assert_eq!(permit.resource_scope.active(), Some(claim.connected));
        assert_eq!(
            permit
                .aggregate
                .active()
                .for_family(PreAuthResourceFamily::ConnectorSpecificWork),
            ResourceUse::ZERO
        );
        drop(connected);
        assert_eq!(permit.aggregate.active(), PreAuthResourceClaim::ZERO);
        assert_eq!(
            permit.resource_scope.active(),
            Some(PreAuthResourceClaim::ZERO)
        );
    }
}
