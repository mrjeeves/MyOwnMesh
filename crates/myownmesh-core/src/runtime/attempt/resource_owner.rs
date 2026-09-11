//! Provider-backed process and per-Mesh connector resource ownership.

use super::*;
use crate::resource::{
    ResourceAuthorityClass, ResourceClaim, ResourceClass, ResourceLease, ResourceProviderPort,
    ResourceScope, ResourceUnavailable,
};
use futures_util::FutureExt;
use std::sync::Weak;

/// Point-in-time diagnostics for one exact live Mesh connector scope.
///
/// These values report ownership events. They never grant capacity or reject
/// provider-approved work.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MeshConnectorResourceReport {
    pub active_candidates: usize,
    pub failed_cleanup_candidates: usize,
    pub accounting_poisoned: bool,
}

/// The selected resource provider could not issue a Mesh attribution scope.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum MeshConnectorResourceScopeIssueError {
    #[error("the process resource provider is not installed")]
    ResourceProviderMissing,
    #[error("the connector resource provider refused the Mesh scope: {0}")]
    ResourceUnavailable(#[from] ResourceUnavailable),
}

#[derive(Default)]
struct ConnectorResourceDiagnosticsState {
    active_candidates: usize,
    failed_cleanup_candidates: usize,
    accounting_poisoned: bool,
}

#[derive(Default)]
pub(super) struct ConnectorResourceDiagnostics {
    state: Mutex<ConnectorResourceDiagnosticsState>,
}

impl ConnectorResourceDiagnostics {
    fn note_acquired(&self) {
        let mut state = self.lock();
        match state.active_candidates.checked_add(1) {
            Some(active) => state.active_candidates = active,
            None => state.accounting_poisoned = true,
        }
    }

    fn note_released(&self) {
        let mut state = self.lock();
        match state.active_candidates.checked_sub(1) {
            Some(active) => state.active_candidates = active,
            None => state.accounting_poisoned = true,
        }
    }

    fn note_failed_cleanup(&self) {
        let mut state = self.lock();
        match state.failed_cleanup_candidates.checked_add(1) {
            Some(failed) => state.failed_cleanup_candidates = failed,
            None => state.accounting_poisoned = true,
        }
    }

    fn poison(&self) {
        self.lock().accounting_poisoned = true;
    }

    fn report(&self) -> MeshConnectorResourceReport {
        let state = self.lock();
        MeshConnectorResourceReport {
            active_candidates: state.active_candidates,
            failed_cleanup_candidates: state.failed_cleanup_candidates,
            accounting_poisoned: state.accounting_poisoned,
        }
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, ConnectorResourceDiagnosticsState> {
        self.state.lock().unwrap_or_else(|poisoned| {
            let mut state = poisoned.into_inner();
            state.accounting_poisoned = true;
            state
        })
    }
}

pub(super) fn poison_reservation_diagnostics(
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    process_diagnostics.poison();
    mesh_diagnostics.poison();
}

pub(super) struct ConnectorResourceOwnerInner {
    provider: ResourceProviderPort,
    process_scope: ResourceScope,
    diagnostics: Arc<ConnectorResourceDiagnostics>,
    cleanup_executor: ConnectorCleanupExecutor,
}

impl ConnectorResourceOwnerInner {
    fn new(provider: ResourceProviderPort) -> Self {
        let process_scope = provider.process_scope();
        Self {
            provider,
            process_scope,
            diagnostics: Arc::new(ConnectorResourceDiagnostics::default()),
            cleanup_executor: ConnectorCleanupExecutor::new(),
        }
    }

    fn issue_mesh_scope(
        self: &Arc<Self>,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        self.cleanup_executor
            .prepare(&self.provider, &self.process_scope)?;
        let scope = self.provider.create_scope(&self.process_scope)?;
        Ok(MeshConnectorResourceScope {
            token: Arc::new(MeshConnectorResourceScopeToken {
                owner: Arc::clone(self),
                scope,
                diagnostics: Arc::new(ConnectorResourceDiagnostics::default()),
            }),
        })
    }

    fn report(&self) -> ConnectorResourceOwnerReport {
        let diagnostics = self.diagnostics.report();
        ConnectorResourceOwnerReport {
            active_candidates: diagnostics.active_candidates,
            failed_cleanup_candidates: diagnostics.failed_cleanup_candidates,
            accounting_poisoned: diagnostics.accounting_poisoned,
            cleanup: self.cleanup_executor.report(),
        }
    }
}

/// Cloneable administrative port into one process resource provider.
///
/// It cannot admit work directly. It only issues attribution scopes that draw
/// from the exact provider identity supplied by the process owner.
#[derive(Clone)]
pub struct ConnectorResourceOwnerPort {
    inner: Arc<ConnectorResourceOwnerInner>,
}

impl ConnectorResourceOwnerPort {
    pub(crate) fn new(provider: ResourceProviderPort) -> Self {
        Self {
            inner: Arc::new(ConnectorResourceOwnerInner::new(provider)),
        }
    }

    pub fn report(&self) -> ConnectorResourceOwnerReport {
        self.inner.report()
    }

    pub(crate) fn issue_mesh_scope(
        &self,
    ) -> Result<MeshConnectorResourceScope, MeshConnectorResourceScopeIssueError> {
        self.inner.issue_mesh_scope()
    }

    pub(crate) fn same_provider(&self, provider: &ResourceProviderPort) -> bool {
        self.inner.provider.same_provider(provider)
    }
}

/// One-shot proof that an exact connector reservation has entered cleanup.
///
/// The capability retains the reservation state, including its move-only
/// provider lease, until the queued or running cleanup job is destroyed. It
/// cannot be cloned and one reservation can mint it only once.
pub(crate) struct ConnectorCleanupCapability {
    pub(super) reservation: Arc<ConnectorCandidateReservationState>,
}

pub(super) struct MeshConnectorResourceScopeToken {
    pub(super) owner: Arc<ConnectorResourceOwnerInner>,
    pub(super) scope: ResourceScope,
    diagnostics: Arc<ConnectorResourceDiagnostics>,
}

/// Exact process-local resource scope for work owned by one connector.
///
/// Cloning this port preserves attribution to the same connector. It does not
/// grant capacity. Every successful acquisition still creates a distinct,
/// finite provider lease.
#[derive(Clone)]
pub(crate) struct ConnectorWorkResourceScope {
    provider: ResourceProviderPort,
    scope: ResourceScope,
    /// The process cleanup executor this connector's subordinate native objects
    /// submit their retirements to.
    ///
    /// Carried here rather than looked up, because the owners that need it need
    /// it from a destructor: by the time a native object's owner is dropping
    /// there is nothing left to ask. A work scope is already the thing that
    /// funds native work on this connector, so it is also the honest place to
    /// find out where that work goes to be undone.
    cleanup_submission: ConnectorCleanupSubmissionPort,
}

impl ConnectorWorkResourceScope {
    /// Where this connector's subordinate native retirements are submitted.
    pub(crate) fn cleanup_submission(&self) -> &ConnectorCleanupSubmissionPort {
        &self.cleanup_submission
    }

    pub(crate) fn acquire(
        &self,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.provider.acquire(&self.scope, authority, claim)
    }

    #[cfg(test)]
    pub(crate) fn pressure(
        &self,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> Result<crate::resource::ResourcePressure, ResourceUnavailable> {
        self.provider.pressure(&self.scope, authority, dimension)
    }
}

/// Unforgeable attribution and admission scope for one live [`crate::Mesh`]
/// runtime.
///
/// Scope creation grants no capacity. Clones retain the same provider child
/// scope, and every connector candidate acquires a separate child lease from
/// the process owner's shared finite grant.
#[derive(Clone)]
pub struct MeshConnectorResourceScope {
    pub(super) token: Arc<MeshConnectorResourceScopeToken>,
}

impl MeshConnectorResourceScope {
    pub fn report(&self) -> MeshConnectorResourceReport {
        self.token.diagnostics.report()
    }

    pub(crate) fn process_report(&self) -> ConnectorResourceOwnerReport {
        self.token.owner.report()
    }

    pub(crate) fn submit_cleanup(
        &self,
        capability: ConnectorCleanupCapability,
        cleanup: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> ConnectorCleanupSubmission {
        if !Arc::ptr_eq(
            &capability.reservation.process_diagnostics,
            &self.token.owner.diagnostics,
        ) {
            return ConnectorCleanupSubmission::refused(ConnectorCleanupJob::new(
                capability,
                cleanup,
                on_complete,
                on_failure,
            ));
        }
        self.token
            .owner
            .cleanup_executor
            .submit(ConnectorCleanupJob::new(
                capability,
                cleanup,
                on_complete,
                on_failure,
            ))
    }

    /// A durable, cloneable port for submitting subordinate native cleanup.
    ///
    /// Handed to owners that must be able to submit a retirement from `Drop`.
    /// That is the whole reason it exists: `Drop` cannot await and cannot assume
    /// a runtime, and the executor behind this port already owns its own thread
    /// and its own runtime, so a submission through it is a synchronous send
    /// onto an unbounded channel and nothing else.
    ///
    /// It grants no capacity. Every job it accepts still arrives with an exact
    /// lease acquired beforehand.
    pub(crate) fn cleanup_submission_port(&self) -> ConnectorCleanupSubmissionPort {
        ConnectorCleanupSubmissionPort {
            owner: Arc::downgrade(&self.token.owner),
        }
    }

    /// Mark the diagnostics inexact without replacing provider truth.
    pub(crate) fn poison_accounting(&self) {
        self.token.owner.diagnostics.poison();
        self.token.diagnostics.poison();
    }

    #[cfg(test)]
    pub(crate) fn fail_cleanup_executor_for_test(&self) {
        self.token.owner.cleanup_executor.fail_for_test();
    }

    /// Reserve post-authentication session capacity from this Mesh's grant.
    ///
    /// `Admitted` authority, not `Speculative`: a promoted session is not
    /// candidate work and must not be reclaimed as though it were. This is the
    /// explicit resource transition promotion performs — a successful
    /// pre-authentication lease is not reusable as proof that this capacity
    /// exists, so the claim is acquired fresh here or the promotion refuses.
    ///
    /// The lease is returned bare rather than wrapped in a candidate
    /// reservation: a session has no candidate lifecycle, no cleanup job, and no
    /// reclaim subscription. Dropping it releases exactly this reservation.
    pub(crate) fn reserve_session(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.token.owner.provider.acquire(
            &self.token.scope,
            ResourceAuthorityClass::Admitted,
            claim,
        )
    }

    /// Reserve retention owned by the local Application Gateway from this
    /// Mesh runtime's admitted resource scope. It is deliberately a sibling of
    /// session reservation: local application truth is not attributed to any
    /// remote session, while both draw on the process owner's finite grant.
    pub(crate) fn reserve_application(
        &self,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.token.owner.provider.acquire(
            &self.token.scope,
            ResourceAuthorityClass::Admitted,
            claim,
        )
    }

    pub(super) fn reserve(
        &self,
        claim: ResourceClaim,
    ) -> Result<ConnectorCandidateReservation, ResourceUnavailable> {
        let (connector_scope, lease) = self.token.owner.provider.create_scope_with_lease(
            &self.token.scope,
            ResourceAuthorityClass::Speculative,
            claim,
        )?;
        let work_scope = ConnectorWorkResourceScope {
            provider: self.token.owner.provider.clone(),
            scope: connector_scope,
            cleanup_submission: self.cleanup_submission_port(),
        };
        self.token.owner.diagnostics.note_acquired();
        self.token.diagnostics.note_acquired();
        Ok(ConnectorCandidateReservation {
            state: Arc::new(ConnectorCandidateReservationState {
                lease: Mutex::new(Some(lease)),
                work_scope,
                process_diagnostics: Arc::clone(&self.token.owner.diagnostics),
                mesh_diagnostics: Arc::clone(&self.token.diagnostics),
                cleanup_capability_issued: AtomicBool::new(false),
                cleanup_lifecycle: Mutex::new(Default::default()),
            }),
        })
    }

    #[cfg(test)]
    pub(super) fn same_provider(&self, other: &Self) -> bool {
        self.token
            .owner
            .provider
            .same_provider(&other.token.owner.provider)
    }
}

/// A durable handle on the process cleanup executor, for owners that must submit
/// from a destructor.
///
/// **Synchronous and runtime-independent by construction.** Submission is a send
/// on the executor's unbounded channel; the executor's own thread and runtime do
/// the awaiting. A holder can therefore submit from `Drop`, during an unwind, or
/// from a thread that has never seen a Tokio runtime, and the answer is the same
/// in all three.
///
/// Cloning it keeps the same executor and grants nothing. It is a *port*, not a
/// capability: a job still has to bring its own exact lease.
#[derive(Clone)]
pub(crate) struct ConnectorCleanupSubmissionPort {
    owner: Weak<ConnectorResourceOwnerInner>,
}

impl ConnectorCleanupSubmissionPort {
    /// Queue one subordinate native retirement.
    ///
    /// `funding` is the queue slot's own exact lease, acquired by the caller
    /// before the object it retires could need retiring — so the submission
    /// itself can never be refused for want of capacity at the one moment the
    /// caller has no way to react.
    ///
    /// A refused submission retains the job in its returned answer. Dropping
    /// that answer drops the job and runs `on_failure`, so a caller cannot
    /// discard a refusal without taking its failure path. That is the same shape
    /// the connector's own close uses and it is deliberate: there is no way to
    /// submit and hear nothing back.
    pub(crate) fn submit_subordinate(
        &self,
        funding: ResourceLease,
        cleanup: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> ConnectorCleanupSubmission {
        let cleanup = ConnectorCleanupJob::subordinate(funding, cleanup, on_complete, on_failure);
        let Some(owner) = self.owner.upgrade() else {
            let mut cleanup = cleanup;
            cleanup.fail("cleanup resource owner is unavailable".to_string());
            return ConnectorCleanupSubmission::refused(cleanup);
        };
        owner.cleanup_executor.submit(cleanup)
    }
}

pub(crate) type ConnectorCleanupFuture = Pin<Box<dyn Future<Output = ()> + Send + 'static>>;
pub(crate) type ConnectorCleanupCompletion = Box<dyn FnOnce() + Send + 'static>;
pub(crate) type ConnectorCleanupFailure = Box<dyn FnOnce(String) + Send + 'static>;

/// The synchronous answer to one cleanup submission.
///
/// A refusal retains the complete job by value so dropping the answer still
/// runs the job's failure callback and releases its exact funding. This is a
/// dedicated wrapper rather than `Result<(), ConnectorCleanupJob>` because the
/// job is large enough to trip `clippy::result_large_err`, whose suggested
/// remedy is to box the error. That box would be an allocation nothing has
/// reserved; this wrapper keeps the job inline and preserves its existing
/// allocation-free ownership and drop semantics.
#[must_use]
pub(crate) struct ConnectorCleanupSubmission {
    refused: Option<ConnectorCleanupJob>,
}

impl ConnectorCleanupSubmission {
    fn accepted() -> Self {
        Self { refused: None }
    }

    fn refused(job: ConnectorCleanupJob) -> Self {
        Self { refused: Some(job) }
    }

    pub(crate) fn was_refused(&self) -> bool {
        self.refused.is_some()
    }
}

/// Exact connector-owned claim reserved before one cleanup job can exist.
/// Inline bytes cover the queued record and its two linked queue pointers.
/// Four residual units name the boxed close future, boxed completion callback,
/// boxed failure callback, and channel-node allocator metadata whose byte
/// sizes are dependency-owned.
pub(crate) fn cleanup_job_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let links = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let bytes = std::mem::size_of::<ConnectorCleanupJob>()
        .checked_add(links)
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::CallbackOrScheduledWork, 1),
        (ResourceClass::OpaqueDependencyResidual, 4),
    ])
}

/// Exact finite claim for the one late-transport terminal custodian retained
/// by each connector.  The custodian owns one bounded command slot, one OS
/// worker, and the opaque platform/thread state that Rust cannot size.
pub(crate) fn late_transport_custodian_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<std::sync::mpsc::SyncSender<()>>()
        .checked_add(std::mem::size_of::<std::thread::JoinHandle<()>>())
        .and_then(|value| {
            value.checked_add(std::mem::size_of::<Vec<tokio::task::JoinHandle<()>>>())
        })
        .and_then(|value| value.checked_add(std::mem::size_of::<std::sync::Arc<()>>()))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::WorkerOrTask, 1),
        // Command enum payload, thread stack, and platform channel state are
        // dependency-owned and remain explicit opaque residuals.
        (ResourceClass::OpaqueDependencyResidual, 3),
    ])
}

/// What funds one queued cleanup job for as long as it is queued or running.
///
/// Two shapes, because there are two kinds of cleanup and collapsing them would
/// break one of them. A **connector** close consumes its reservation's one-shot
/// proof, which is what makes "this connector has entered cleanup" a fact the
/// provider knows rather than a claim the connector makes. A **subordinate**
/// job — one native object belonging to a connector that is otherwise perfectly
/// alive — has no such reservation and must not consume the connector's, so it
/// brings an ordinary exact lease acquired before the job could be needed.
///
/// Held and never read. Its whole purpose is to be dropped exactly when the job
/// leaves the queue, which is what makes the queue slot funded rather than free.
///
/// The payloads are named and underscore-prefixed for that reason, rather than
/// carried positionally: a held-not-read value is exactly what the leading
/// underscore states, and it is the same convention [`ConnectorCleanupJob`]'s
/// own `_funding` field uses one declaration below. Naming them also stops a
/// later reader from mistaking an unread payload for an unused one and
/// discarding it — dropping either of these early would release the funding
/// while the job it pays for is still queued.
enum ConnectorCleanupFunding {
    Connector {
        _capability: ConnectorCleanupCapability,
    },
    Subordinate {
        _lease: ResourceLease,
    },
}

/// One queued cleanup job: the work, its two callbacks, and the funding that
/// pays for all of it.
///
/// **`_funding` is declared last, and that is the whole of the ordering.**
/// [`cleanup_job_claim`] prices this job's inline bytes *and* four residuals
/// standing for the boxed close future, the boxed completion callback, the
/// boxed failure callback and the channel node — so the funding covers three
/// heap allocations that live in the three `Option` fields above it. Fields are
/// destroyed in declaration order, so funding declared first would be handed
/// back while all three of those allocations were still there. Declared last,
/// it is released only once every allocation it names is gone.
///
/// This type has its own [`Drop`], and that does not change the rule: an
/// explicit `drop` body runs *before* any field is destroyed, so the failure
/// callback below still fires with the funding fully intact, and the three
/// boxes are freed after it and before the funding goes back.
pub(crate) struct ConnectorCleanupJob {
    future: Option<ConnectorCleanupFuture>,
    on_complete: Option<ConnectorCleanupCompletion>,
    on_failure: Option<ConnectorCleanupFailure>,
    _funding: ConnectorCleanupFunding,
}

impl ConnectorCleanupJob {
    fn new(
        capability: ConnectorCleanupCapability,
        future: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> Self {
        Self {
            future: Some(future),
            on_complete: Some(on_complete),
            on_failure: Some(on_failure),
            _funding: ConnectorCleanupFunding::Connector {
                _capability: capability,
            },
        }
    }

    /// One subordinate native object's retirement, funded by its own lease.
    fn subordinate(
        funding: ResourceLease,
        future: ConnectorCleanupFuture,
        on_complete: ConnectorCleanupCompletion,
        on_failure: ConnectorCleanupFailure,
    ) -> Self {
        Self {
            future: Some(future),
            on_complete: Some(on_complete),
            on_failure: Some(on_failure),
            _funding: ConnectorCleanupFunding::Subordinate { _lease: funding },
        }
    }

    fn fail(&mut self, reason: String) {
        self.future = None;
        self.on_complete = None;
        if let Some(on_failure) = self.on_failure.take() {
            on_failure(reason);
        }
    }

    fn complete(mut self) -> ConnectorCleanupCompletion {
        self.future = None;
        self.on_failure = None;
        let completion = self
            .on_complete
            .take()
            .expect("a successful cleanup job owns one completion callback");
        drop(self);
        completion
    }
}

impl Drop for ConnectorCleanupJob {
    fn drop(&mut self) {
        if self.on_failure.is_some() {
            self.fail("cleanup job terminated before completion".to_string());
        }
    }
}

struct ConnectorCleanupHealthState {
    queued_jobs: AtomicUsize,
    active_jobs: AtomicUsize,
    completed_jobs: std::sync::atomic::AtomicU64,
    failed_jobs: std::sync::atomic::AtomicU64,
    executor_failed: AtomicBool,
}

struct ConnectorCleanupExecutorState {
    sender: Option<tokio::sync::mpsc::UnboundedSender<ConnectorCleanupJob>>,
    thread: Option<std::thread::JoinHandle<()>>,
}

/// One process-local cleanup executor.
///
/// Submission does not wait and has no second producer queue. The channel is
/// intentionally unbounded because each one-shot job is already backed by the
/// connector lease's pre-reserved `CallbackOrScheduledWork` cleanup claim.
struct ConnectorCleanupExecutor {
    state: Mutex<ConnectorCleanupExecutorState>,
    health: Arc<ConnectorCleanupHealthState>,
    #[cfg(test)]
    forced_termination: Arc<tokio::sync::Notify>,
}

impl ConnectorCleanupExecutor {
    fn new() -> Self {
        Self {
            state: Mutex::new(ConnectorCleanupExecutorState {
                sender: None,
                thread: None,
            }),
            health: Arc::new(ConnectorCleanupHealthState {
                queued_jobs: AtomicUsize::new(0),
                active_jobs: AtomicUsize::new(0),
                completed_jobs: std::sync::atomic::AtomicU64::new(0),
                failed_jobs: std::sync::atomic::AtomicU64::new(0),
                executor_failed: AtomicBool::new(false),
            }),
            #[cfg(test)]
            forced_termination: Arc::new(tokio::sync::Notify::new()),
        }
    }

    /// Reserve the process cleanup infrastructure before constructing its
    /// runtime, channel, or OS thread. The lease moves into the executor
    /// thread and remains live until every submitted cleanup future ends.
    fn prepare(
        &self,
        provider: &ResourceProviderPort,
        process_scope: &ResourceScope,
    ) -> Result<(), ResourceUnavailable> {
        if self.health.executor_failed.load(Ordering::Acquire) {
            return Err(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            });
        }
        let mut state = self.state.lock().map_err(|_| {
            self.health.executor_failed.store(true, Ordering::Release);
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            }
        })?;
        if state.sender.is_some() {
            return Ok(());
        }

        let infrastructure_lease = provider.acquire(
            process_scope,
            ResourceAuthorityClass::Cleanup,
            cleanup_executor_infrastructure_claim().map_err(|error| match error {
                crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
                | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => {
                    ResourceUnavailable::ProviderInvariant { dimension }
                }
            })?,
        )?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
        let (sender, mut receiver) = tokio::sync::mpsc::unbounded_channel::<ConnectorCleanupJob>();
        let health = Arc::clone(&self.health);
        #[cfg(test)]
        let forced_termination = Arc::clone(&self.forced_termination);
        let thread = std::thread::Builder::new()
            .name("myownmesh-connector-cleanup".to_string())
            .spawn(move || {
                let _infrastructure_lease = infrastructure_lease;
                let loop_health = Arc::clone(&health);
                let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    runtime.block_on(async move {
                        let mut jobs = tokio::task::JoinSet::new();
                        let mut receiver_open = true;
                        let forced_failure = async move {
                            #[cfg(test)]
                            forced_termination.notified().await;
                            #[cfg(not(test))]
                            std::future::pending::<()>().await;
                        };
                        tokio::pin!(forced_failure);
                        loop {
                            if !receiver_open && jobs.is_empty() {
                                break;
                            }
                            tokio::select! {
                                _ = &mut forced_failure => {
                                    panic!("injected cleanup executor termination");
                                }
                                received = receiver.recv(), if receiver_open => {
                                    match received {
                                        Some(mut cleanup) => {
                                            loop_health.queued_jobs.fetch_sub(1, Ordering::AcqRel);
                                            let job_health = Arc::clone(&loop_health);
                                            jobs.spawn(async move {
                                                job_health.active_jobs.fetch_add(1, Ordering::AcqRel);
                                                let future = cleanup
                                                    .future
                                                    .take()
                                                    .expect("queued cleanup job owns one future");
                                                let outcome = std::panic::AssertUnwindSafe(future)
                                                    .catch_unwind()
                                                    .await;
                                                match outcome {
                                                    Ok(()) => {
                                                        let completion = cleanup.complete();
                                                        completion();
                                                        job_health.completed_jobs.fetch_add(1, Ordering::AcqRel);
                                                    }
                                                    Err(_) => {
                                                        cleanup.fail("cleanup future panicked".to_string());
                                                        drop(cleanup);
                                                        job_health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                                                    }
                                                }
                                                job_health.active_jobs.fetch_sub(1, Ordering::AcqRel);
                                            });
                                        }
                                        None => receiver_open = false,
                                    }
                                }
                                completed = jobs.join_next(), if !jobs.is_empty() => {
                                    if completed.is_some_and(|result| result.is_err()) {
                                        loop_health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                                    }
                                }
                            }
                        }
                    });
                }));
                if outcome.is_err() {
                    health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                }
                health.executor_failed.store(true, Ordering::Release);
            })
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
        state.sender = Some(sender);
        state.thread = Some(thread);
        Ok(())
    }

    fn submit(&self, mut cleanup: ConnectorCleanupJob) -> ConnectorCleanupSubmission {
        if self.health.executor_failed.load(Ordering::Acquire) {
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            cleanup.fail("cleanup executor is unavailable".to_string());
            return ConnectorCleanupSubmission::refused(cleanup);
        }
        let state = match self.state.lock() {
            Ok(state) => state,
            Err(_) => {
                self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
                cleanup.fail("cleanup executor state is poisoned".to_string());
                return ConnectorCleanupSubmission::refused(cleanup);
            }
        };
        let Some(sender) = state.sender.as_ref() else {
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            cleanup.fail("cleanup executor has no submission port".to_string());
            return ConnectorCleanupSubmission::refused(cleanup);
        };
        self.health.queued_jobs.fetch_add(1, Ordering::AcqRel);
        if let Err(error) = sender.send(cleanup) {
            self.health.queued_jobs.fetch_sub(1, Ordering::AcqRel);
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            let mut cleanup = error.0;
            cleanup.fail("cleanup executor queue is closed".to_string());
            return ConnectorCleanupSubmission::refused(cleanup);
        }
        ConnectorCleanupSubmission::accepted()
    }

    fn report(&self) -> ConnectorCleanupHealth {
        ConnectorCleanupHealth {
            queued_jobs: self.health.queued_jobs.load(Ordering::Acquire),
            active_jobs: self.health.active_jobs.load(Ordering::Acquire),
            completed_jobs: self.health.completed_jobs.load(Ordering::Acquire),
            failed_jobs: self.health.failed_jobs.load(Ordering::Acquire),
            executor_failed: self.health.executor_failed.load(Ordering::Acquire),
        }
    }

    #[cfg(test)]
    fn fail_for_test(&self) {
        self.health.executor_failed.store(true, Ordering::Release);
        self.forced_termination.notify_one();
        if let Ok(mut state) = self.state.lock() {
            state.sender.take();
        }
    }
}

impl Drop for ConnectorCleanupExecutor {
    fn drop(&mut self) {
        let state = self
            .state
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.sender.take();
        let Some(thread) = state.thread.take() else {
            return;
        };
        // The close-owner path relinquishes its resource scope before this
        // executor can be destroyed, so this join is reached only by the
        // external owner that outlives queued cleanup. A self-join would be a
        // structural bug rather than a recoverable cleanup failure.
        assert_ne!(
            thread.thread().id(),
            std::thread::current().id(),
            "cleanup executor cannot join itself"
        );
        if thread.join().is_err() {
            self.health.failed_jobs.fetch_add(1, Ordering::AcqRel);
            self.health.executor_failed.store(true, Ordering::Release);
        }
    }
}

/// Mechanically derived process claim for the persistent cleanup owner.
///
/// Inline bytes cover the runtime value, channel sender, thread handle, and
/// health state. Four residual units name the runtime heap, channel heap,
/// native thread stack, and platform runtime internals that Rust does not
/// expose as exact byte quantities.
pub(crate) fn cleanup_executor_infrastructure_claim(
) -> Result<ResourceClaim, crate::resource::ResourceClaimArithmeticError> {
    let bytes = std::mem::size_of::<tokio::runtime::Runtime>()
        .checked_add(std::mem::size_of::<
            tokio::sync::mpsc::UnboundedSender<ConnectorCleanupJob>,
        >())
        .and_then(|value| value.checked_add(std::mem::size_of::<std::thread::JoinHandle<()>>()))
        .and_then(|value| value.checked_add(std::mem::size_of::<ConnectorCleanupHealthState>()))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    let bytes = u64::try_from(bytes).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        }
    })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::CallbackOrScheduledWork, 1),
        (ResourceClass::OpaqueDependencyResidual, 4),
    ])
}

pub(super) fn release_reservation(
    lease: ResourceLease,
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    drop(lease);
    process_diagnostics.note_released();
    mesh_diagnostics.note_released();
}

pub(super) fn retain_failed_reservation(
    lease: ResourceLease,
    process_diagnostics: &ConnectorResourceDiagnostics,
    mesh_diagnostics: &ConnectorResourceDiagnostics,
) {
    let expected = lease.claim();
    match lease.retain_after_failed_cleanup() {
        Ok(retained) if retained == expected => {
            process_diagnostics.note_failed_cleanup();
            mesh_diagnostics.note_failed_cleanup();
        }
        Ok(_) | Err(_) => {
            process_diagnostics.poison();
            mesh_diagnostics.poison();
        }
    }
}
