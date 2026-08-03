//! Process and per-Mesh connector resource ownership.

use super::*;

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

pub(super) struct ConnectorResourceOwnerInner {
    policy: ConnectorResourcePolicy,
    state: Mutex<ConnectorResourceOwnerState>,
    cleanup_executor: ConnectorCleanupExecutor,
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
            cleanup_executor: ConnectorCleanupExecutor::new(policy.max_active_candidates()),
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

    pub(super) fn reserve(
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
        if state.active_candidates >= self.policy.max_active_candidates().get() {
            return None;
        }
        let Some(child) = state.mesh_scopes.get(&mesh_scope.id) else {
            Self::poison_all_locked(&mut state);
            return None;
        };
        if child.accounting_poisoned
            || child.active_candidates >= child.policy.max_active_candidates().get()
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
    pub(super) fn transition(
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

    pub(super) fn retain_after_cleanup_failure(&self, mesh_scope_id: NonZeroU64) {
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

    pub(super) fn release(&self, mesh_scope_id: NonZeroU64, claim: PreAuthResourceClaim) {
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
            max_active_candidates: self.policy.max_active_candidates(),
            active_candidates,
            failed_cleanup_candidates,
            accounting_poisoned,
            callbacks: self.policy.callbacks(),
            pending_remote_candidates: self.policy.pending_remote_candidates(),
            legacy_media: self.policy.legacy_media(),
        }
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> PreAuthResourceClaim {
        match self.state.lock() {
            Ok(state) => state.active,
            Err(poisoned) => poisoned.into_inner().active,
        }
    }

    #[cfg(test)]
    pub(super) fn is_poisoned(&self) -> bool {
        match self.state.lock() {
            Ok(state) => state.accounting_poisoned,
            Err(_) => true,
        }
    }

    #[cfg(test)]
    pub(super) fn corrupt_active_for_test(&self, active: PreAuthResourceClaim) {
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

pub(super) struct MeshConnectorResourceScopeToken {
    pub(super) id: NonZeroU64,
    pub(super) owner: Arc<ConnectorResourceOwnerInner>,
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
    pub(super) token: Arc<MeshConnectorResourceScopeToken>,
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
        self.token.owner.policy.callbacks()
    }

    pub(crate) fn pending_remote_candidates(&self) -> PendingRemoteCandidatePolicy {
        self.token.owner.policy.pending_remote_candidates()
    }

    pub(crate) fn legacy_media(&self) -> Option<LegacyWebRtcMediaProfile> {
        self.token.owner.policy.legacy_media()
    }

    pub(crate) fn submit_cleanup(
        &self,
        cleanup: ConnectorCleanupFuture,
    ) -> std::result::Result<(), ConnectorCleanupFuture> {
        self.token.owner.cleanup_executor.submit(cleanup)
    }

    pub(crate) fn poison_accounting(&self) {
        self.token.owner.poison_mesh_accounting(self.token.id);
    }

    pub(super) fn reserve(
        &self,
        claim: PreAuthResourceClaim,
    ) -> Option<ConnectorCandidateReservation> {
        self.token.owner.reserve(Arc::clone(&self.token), claim)
    }

    #[cfg(test)]
    pub(super) fn active(&self) -> Option<PreAuthResourceClaim> {
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

pub(crate) type ConnectorCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;

struct ConnectorCleanupExecutorState {
    sender: Option<tokio::sync::mpsc::Sender<ConnectorCleanupFuture>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// One bounded, single-purpose cleanup executor for the process connector
/// owner. It is started lazily and multiplexes all close futures on one Tokio
/// runtime and one OS thread. Queue capacity is the already owner-selected
/// process candidate ceiling, so cleanup does not introduce another value.
struct ConnectorCleanupExecutor {
    capacity: NonZeroUsize,
    state: Mutex<ConnectorCleanupExecutorState>,
}

impl ConnectorCleanupExecutor {
    fn new(capacity: NonZeroUsize) -> Self {
        Self {
            capacity,
            state: Mutex::new(ConnectorCleanupExecutorState {
                sender: None,
                thread: None,
            }),
        }
    }

    fn submit(
        &self,
        cleanup: ConnectorCleanupFuture,
    ) -> std::result::Result<(), ConnectorCleanupFuture> {
        let mut state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => return Err(cleanup),
        };
        if state.sender.is_none() {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(_) => return Err(cleanup),
            };
            let (sender, mut receiver) = tokio::sync::mpsc::channel(self.capacity.get());
            let thread = match std::thread::Builder::new()
                .name("myownmesh-connector-cleanup".to_string())
                .spawn(move || {
                    runtime.block_on(async move {
                        while let Some(cleanup) = receiver.recv().await {
                            tokio::spawn(cleanup);
                        }
                    });
                }) {
                Ok(thread) => thread,
                Err(_) => return Err(cleanup),
            };
            state.sender = Some(sender);
            state.thread = Some(thread);
        }
        let Some(sender) = state.sender.as_ref() else {
            return Err(cleanup);
        };
        match sender.try_send(cleanup) {
            Ok(()) => Ok(()),
            Err(tokio::sync::mpsc::error::TrySendError::Full(cleanup))
            | Err(tokio::sync::mpsc::error::TrySendError::Closed(cleanup)) => Err(cleanup),
        }
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
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("test data-only callback policy is valid");
        let policy = ConnectorResourcePolicy::new(
            candidates,
            callbacks,
            PendingRemoteCandidatePolicy::new(candidates, candidates),
        );
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
