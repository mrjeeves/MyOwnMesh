//! Outside-runtime ownership of admitted service cleanup.
//!
//! An Owner must outlive the runtime and service producers using its Port.
//! Ports never join. Every admitted entry has one disposition, including an
//! entry still under construction when admission closes.

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard};
use std::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};
use std::thread::{self, JoinHandle};

use myownmesh_core::{
    FiniteResourceProvider, FundedArc, LocalApplicationResourceScope, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceUnavailable,
};
use tokio::sync::Notify;

#[derive(Debug, thiserror::Error)]
pub enum ServiceCleanupError {
    #[error("service cleanup claim: {0}")]
    Claim(#[from] ResourceClaimArithmeticError),
    #[error("service cleanup resources: {0}")]
    Resources(#[from] ResourceUnavailable),
    #[error("service cleanup admission closed")]
    Closed,
    #[error("service cleanup worker start: {0}")]
    WorkerStart(#[source] std::io::Error),
    #[error("service cleanup worker failed")]
    WorkerJoin,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ServiceCleanupReport {
    pub completed: u64,
    pub task_failures: u64,
    pub worker_failures: u64,
}

/// Nonclone joining owner. Construct and close this OUTSIDE the service runtime.
pub struct ServiceCleanupOwner {
    port: ServiceCleanupPort,
    worker: Option<JoinHandle<()>>,
    // Retained until the exact root worker has joined, including Drop fallback.
    _worker_lease: ResourceLease,
}

#[derive(Clone)]
pub struct ServiceCleanupPort {
    queue: FundedArc<CleanupQueue>,
}

struct CleanupQueue {
    state: Mutex<QueueState>,
    changed: Condvar,
}

struct QueueState {
    accepting: bool,
    outstanding: u64,
    head: Option<CleanupEntry>,
    report: ServiceCleanupReport,
    #[cfg(test)]
    waiting_with_outstanding: bool,
}

// The Box is deallocated before its external lease. Do not move the lease into
// CleanupNode: field Drop happens before Box deallocation.
struct CleanupEntry {
    node: Box<CleanupNode>,
    lease: ResourceLease,
}

struct CleanupNode {
    worker: Option<JoinHandle<WorkerOutcome>>,
    service_lease: Option<ResourceLease>,
    turn_backing: Option<crate::turn::TurnBacking>,
    completion: FundedArc<ServiceCompletion>,
    wake: CleanupWake,
    next: Option<CleanupEntry>,
}

#[derive(Clone, Copy, Default)]
pub(crate) struct WorkerOutcome {
    pub(crate) task_failed: bool,
    pub(crate) runtime_destroyed: bool,
    /// The worker could not prove native/runtime destruction. Never release
    /// its exact startup obligation as though ordinary cancellation completed.
    pub(crate) cleanup_unobserved: bool,
}

pub(crate) struct ServiceCompletion {
    state: Mutex<TaskState>,
    input_changed: Condvar,
    joined: AtomicBool,
    joined_notify: Notify,
    // One atomic orders request and actual future destruction. Terminal states
    // never change, including a late handle Drop after origin-runtime teardown.
    // 0=live/unrequested, 1=requested, 2=unexpected terminal, 3=requested terminal.
    stun_provenance: AtomicU8,
    #[cfg(test)]
    listener_polled: AtomicBool,
    #[cfg(test)]
    runtime_destroyed: AtomicBool,
}

struct TaskState {
    task: Option<tokio::task::JoinHandle<()>>,
    input_closed: bool,
    task_failed: bool,
}

impl ServiceCompletion {
    pub(crate) fn request_stun_stop(&self) {
        let _ = self
            .stun_provenance
            .compare_exchange(0, 1, Ordering::AcqRel, Ordering::Acquire);
    }

    pub(crate) fn stun_task_failed(&self, result: &Result<(), tokio::task::JoinError>) -> bool {
        match result {
            Ok(()) => false,
            Err(error) => {
                !error.is_cancelled() || self.stun_provenance.load(Ordering::Acquire) != 3
            }
        }
    }

    #[cfg(test)]
    pub(crate) fn listener_was_polled(&self) -> bool {
        self.listener_polled.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn is_joined(&self) -> bool {
        self.joined.load(Ordering::Acquire)
    }
    #[cfg(test)]
    pub(crate) fn runtime_destroyed(&self) -> bool {
        self.runtime_destroyed.load(Ordering::Acquire)
    }
    pub(crate) async fn wait_joined(&self) {
        loop {
            let notified = self.joined_notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.joined.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    pub(crate) fn task_failed(&self) -> bool {
        lock_recover(&self.state).task_failed
    }
}

/// Constructed before spawn and captured by the future, so even a future that
/// is never first-polled stamps its actual terminal disposition on destruction.
pub(crate) struct StunTerminalGuard(pub(crate) FundedArc<ServiceCompletion>);

impl StunTerminalGuard {
    pub(crate) fn entered(&self) {
        #[cfg(test)]
        self.0.listener_polled.store(true, Ordering::Release);
    }
}

impl Drop for StunTerminalGuard {
    fn drop(&mut self) {
        let _ = self
            .0
            .stun_provenance
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |state| match state {
                0 => Some(2),
                1 => Some(3),
                _ => None,
            });
    }
}

/// The construction/handle guard is the one owner of a registered, unqueued
/// node. Dropping it closes input and submits that same preallocated node.
pub(crate) struct ServiceCustody {
    entry: Option<CleanupEntry>,
    port: ServiceCleanupPort,
}

pub(crate) fn record_claim<T>() -> Result<ResourceClaim, ServiceCleanupError> {
    Ok(ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            std::mem::size_of::<T>() as u64,
        ),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])?)
}

pub(crate) fn planned(claim: ResourceClaim) -> Result<ResourceClaim, ServiceCleanupError> {
    Ok(FiniteResourceProvider::reservation_planning_charge(claim)?)
}

pub(crate) fn funded<T>(value: T, lease: ResourceLease) -> FundedArc<T> {
    // A LocalApplicationResourceScope issues admitted, never speculative,
    // custody. A contradictory authority is a provider invariant, not a reason
    // to discard an already admitted native owner.
    FundedArc::new(value, lease).unwrap_or_else(|_| std::process::abort())
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(|_| std::process::abort())
}

fn lock_recover<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn root_worker_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::WorkerOrTask, 1),
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
    .expect("fixed cleanup root worker claim")
}

impl ServiceCleanupOwner {
    pub fn planning_charge() -> Result<ResourceClaim, ServiceCleanupError> {
        Ok(planned(record_claim::<CleanupQueue>()?)?.checked_add(planned(root_worker_claim())?)?)
    }

    pub fn new(scope: LocalApplicationResourceScope) -> Result<Self, ServiceCleanupError> {
        Self::new_inner(
            scope,
            #[cfg(test)]
            false,
        )
    }

    fn new_inner(
        scope: LocalApplicationResourceScope,
        #[cfg(test)] refuse_spawn: bool,
    ) -> Result<Self, ServiceCleanupError> {
        let queue_lease = scope.acquire(record_claim::<CleanupQueue>()?)?;
        let worker_lease = scope.acquire(root_worker_claim())?;
        let port = ServiceCleanupPort {
            queue: funded(
                CleanupQueue {
                    state: Mutex::new(QueueState {
                        accepting: true,
                        outstanding: 0,
                        head: None,
                        report: ServiceCleanupReport::default(),
                        #[cfg(test)]
                        waiting_with_outstanding: false,
                    }),
                    changed: Condvar::new(),
                },
                queue_lease,
            ),
        };
        let worker_port = port.clone();
        #[cfg(test)]
        if refuse_spawn {
            return Err(ServiceCleanupError::WorkerStart(std::io::Error::other(
                "injected root spawn refusal",
            )));
        }
        let worker = thread::Builder::new()
            .name("service-cleanup-root".into())
            .spawn(move || worker_port.run())
            .map_err(ServiceCleanupError::WorkerStart)?;
        Ok(Self {
            port,
            worker: Some(worker),
            _worker_lease: worker_lease,
        })
    }

    pub fn port(&self) -> ServiceCleanupPort {
        self.port.clone()
    }

    pub fn begin_close(&self) {
        lock(&self.port.queue.state).accepting = false;
        self.port.queue.changed.notify_all();
    }

    /// Close admission and join after every admitted node's disposition. Must
    /// not run on a runtime thread whose destruction/advancement is required.
    pub fn close_and_join(mut self) -> Result<ServiceCleanupReport, ServiceCleanupError> {
        self.begin_close();
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| ServiceCleanupError::WorkerJoin)?;
        }
        Ok(lock(&self.port.queue.state).report)
    }
}

impl Drop for ServiceCleanupOwner {
    fn drop(&mut self) {
        self.begin_close();
        if let Some(worker) = self.worker.take() {
            if worker.join().is_err() {
                // No terminal report can excuse loss of outstanding custody.
                std::process::abort();
            }
        }
    }
}

impl ServiceCleanupPort {
    #[cfg(test)]
    pub(crate) fn report_for_test(&self) -> ServiceCleanupReport {
        lock(&self.queue.state).report
    }

    #[cfg(test)]
    pub(crate) fn accepting_for_test(&self) -> bool {
        lock(&self.queue.state).accepting
    }

    #[cfg(test)]
    fn wait_closed_with_outstanding(&self) {
        let mut state = lock(&self.queue.state);
        while !state.waiting_with_outstanding {
            state = self.queue.changed.wait(state).unwrap();
        }
    }
    pub fn entry_planning_charge() -> Result<ResourceClaim, ServiceCleanupError> {
        Ok(planned(record_claim::<CleanupNode>()?)?
            .checked_add(planned(record_claim::<ServiceCompletion>()?)?)?
            .checked_add(planned(record_claim::<WakeRecord>()?)?)?)
    }

    pub(crate) fn reserve(
        &self,
        scope: &LocalApplicationResourceScope,
        service_lease: ResourceLease,
    ) -> Result<ServiceCustody, ServiceCleanupError> {
        let node_lease = scope.acquire(record_claim::<CleanupNode>()?)?;
        let completion_lease = scope.acquire(record_claim::<ServiceCompletion>()?)?;
        let wake_lease = scope.acquire(record_claim::<WakeRecord>()?)?;
        let entry = CleanupEntry {
            node: Box::new(CleanupNode {
                worker: None,
                service_lease: Some(service_lease),
                turn_backing: None,
                completion: funded(
                    ServiceCompletion {
                        state: Mutex::new(TaskState {
                            task: None,
                            input_closed: false,
                            task_failed: false,
                        }),
                        input_changed: Condvar::new(),
                        joined: AtomicBool::new(false),
                        joined_notify: Notify::new(),
                        stun_provenance: AtomicU8::new(0),
                        #[cfg(test)]
                        listener_polled: AtomicBool::new(false),
                        #[cfg(test)]
                        runtime_destroyed: AtomicBool::new(false),
                    },
                    completion_lease,
                ),
                wake: CleanupWake::new(wake_lease),
                next: None,
            }),
            lease: node_lease,
        };
        {
            let mut state = lock(&self.queue.state);
            if !state.accepting {
                return Err(ServiceCleanupError::Closed);
            }
            state.outstanding = state
                .outstanding
                .checked_add(1)
                .ok_or(ServiceCleanupError::Closed)?;
        }
        Ok(ServiceCustody {
            entry: Some(entry),
            port: self.clone(),
        })
    }

    fn submit(&self, mut entry: CleanupEntry) {
        let mut state = lock(&self.queue.state);
        if state.outstanding == 0 || entry.node.next.is_some() {
            std::process::abort();
        }
        // Closing forbids registration, not this already-registered handoff.
        entry.node.next = state.head.take();
        state.head = Some(entry);
        self.queue.changed.notify_all();
    }

    fn run(&self) {
        loop {
            let batch = {
                let mut state = lock(&self.queue.state);
                loop {
                    if state.head.is_some() {
                        break state.head.take();
                    }
                    if !state.accepting && state.outstanding == 0 {
                        return;
                    }
                    #[cfg(test)]
                    if !state.accepting {
                        state.waiting_with_outstanding = true;
                        self.queue.changed.notify_all();
                    }
                    state = self
                        .queue
                        .changed
                        .wait(state)
                        .unwrap_or_else(|_| std::process::abort());
                }
            };
            let mut batch = batch;
            while let Some(mut entry) = batch {
                batch = entry.node.next.take();
                // Unexpected internal unwind must not detach an owned bundle.
                let completed = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    self.complete(entry);
                }));
                if completed.is_err() {
                    std::process::abort();
                }
            }
        }
    }

    fn complete(&self, mut entry: CleanupEntry) {
        let mut worker_failed = false;
        let outcome = match entry.node.worker.take() {
            Some(worker) => match worker.join() {
                Ok(outcome) => outcome,
                Err(_) => {
                    worker_failed = true;
                    // STUN's original handle stays in the record if its
                    // observer unwinds. Retarget only after that worker joins.
                    let mut outcome = observe_stun(&entry.node.completion, &entry.node.wake);
                    outcome.cleanup_unobserved = true;
                    outcome
                }
            },
            None => WorkerOutcome::default(), // registered pre-spawn rollback
        };
        let completion = entry.node.completion.clone();
        #[cfg(test)]
        completion
            .runtime_destroyed
            .store(outcome.runtime_destroyed, Ordering::Release);
        #[cfg(not(test))]
        let _runtime_destroyed = outcome.runtime_destroyed;
        lock_recover(&completion.state).task_failed |= outcome.task_failed || worker_failed;
        if let Some(lease) = entry.node.service_lease.take() {
            if outcome.cleanup_unobserved {
                if lease.retain_after_failed_cleanup().is_err() {
                    std::process::abort();
                }
            } else {
                drop(lease);
            }
        }
        if let Some(backing) = entry.node.turn_backing.take() {
            backing.release_after_join(outcome.cleanup_unobserved);
        }
        drop(entry.node);
        drop(entry.lease);
        // Waiters take this disposition fence after the joined witness. This
        // prevents immediate exact-grant reuse racing our final record clone.
        let mut state = lock(&self.queue.state);
        completion.joined.store(true, Ordering::Release);
        completion.joined_notify.notify_waiters();
        drop(completion);
        state.report.completed = state
            .report
            .completed
            .checked_add(1)
            .unwrap_or_else(|| std::process::abort());
        state.report.task_failures = state
            .report
            .task_failures
            .checked_add(u64::from(outcome.task_failed))
            .unwrap_or_else(|| std::process::abort());
        state.report.worker_failures = state
            .report
            .worker_failures
            .checked_add(u64::from(worker_failed || outcome.cleanup_unobserved))
            .unwrap_or_else(|| std::process::abort());
        state.outstanding = state
            .outstanding
            .checked_sub(1)
            .unwrap_or_else(|| std::process::abort());
        self.queue.changed.notify_all();
    }
}

impl ServiceCustody {
    pub(crate) fn observe_disposition(&self) {
        drop(lock(&self.port.queue.state));
    }
    pub(crate) fn set_turn_backing(&mut self, backing: crate::turn::TurnBacking) {
        let node = &mut self.entry.as_mut().expect("owned unsubmitted entry").node;
        if node.worker.is_some() || node.turn_backing.is_some() {
            std::process::abort();
        }
        node.turn_backing = Some(backing);
    }
    pub(crate) fn completion(&self) -> FundedArc<ServiceCompletion> {
        self.entry
            .as_ref()
            .expect("owned unsubmitted entry")
            .node
            .completion
            .clone()
    }

    pub(crate) fn spawn_stun_observer(&mut self) -> Result<(), ServiceCleanupError> {
        let entry = self.entry.as_ref().expect("owned unsubmitted entry");
        let completion = entry.node.completion.clone();
        let wake = entry.node.wake.clone();
        self.spawn_worker(move || observe_stun(&completion, &wake))
    }

    pub(crate) fn spawn_worker(
        &mut self,
        run: impl FnOnce() -> WorkerOutcome + Send + 'static,
    ) -> Result<(), ServiceCleanupError> {
        self.spawn_worker_inner(
            run,
            #[cfg(test)]
            false,
        )
    }

    fn spawn_worker_inner(
        &mut self,
        run: impl FnOnce() -> WorkerOutcome + Send + 'static,
        #[cfg(test)] refuse_spawn: bool,
    ) -> Result<(), ServiceCleanupError> {
        let entry = self.entry.as_mut().expect("owned unsubmitted entry");
        if entry.node.worker.is_some() {
            std::process::abort();
        }
        #[cfg(test)]
        if refuse_spawn {
            return Err(ServiceCleanupError::WorkerStart(std::io::Error::other(
                "injected service spawn refusal",
            )));
        }
        entry.node.worker = Some(
            thread::Builder::new()
                .name("service-owner".into())
                .spawn(run)
                .map_err(ServiceCleanupError::WorkerStart)?,
        );
        Ok(())
    }

    pub(crate) fn finish_stun(
        &mut self,
        task: Option<tokio::task::JoinHandle<()>>,
        task_failed: bool,
    ) {
        if let Some(entry) = &self.entry {
            let mut state = lock_recover(&entry.node.completion.state);
            if state.input_closed || state.task.is_some() {
                std::process::abort();
            }
            state.task = task;
            state.task_failed |= task_failed;
        } else if task.is_some() {
            std::process::abort();
        }
        self.submit();
    }

    pub(crate) fn submit(&mut self) {
        if let Some(entry) = self.entry.take() {
            lock_recover(&entry.node.completion.state).input_closed = true;
            entry.node.completion.input_changed.notify_all();
            self.port.submit(entry);
        }
    }
}

impl Drop for ServiceCustody {
    fn drop(&mut self) {
        self.submit();
    }
}

fn observe_stun(completion: &ServiceCompletion, wake: &CleanupWake) -> WorkerOutcome {
    wake.bind_current();
    let waker = wake.waker();
    let mut context = Context::from_waker(&waker);
    let mut state = lock_recover(&completion.state);
    while !state.input_closed {
        state = completion
            .input_changed
            .wait(state)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
    }
    if let Some(task) = state.task.as_mut() {
        let result = loop {
            match Pin::new(&mut *task).poll(&mut context) {
                Poll::Ready(result) => break result,
                Poll::Pending => thread::park(),
            }
        };
        state.task.take(); // completed handle removed before any reporting
        state.task_failed |= completion.stun_task_failed(&result);
    }
    WorkerOutcome {
        task_failed: state.task_failed,
        cleanup_unobserved: false,
        runtime_destroyed: false,
    }
}

// RawWaker is required here solely to preserve allocation-before-lease release
// on the *last* dependency-owned Waker. No raw pointer/Arc escapes this module.
// Every data pointer owns one Arc strong reference. Clone increments that same
// allocation; drop holds independent funding until Arc deallocation completes.
struct WakeRecord {
    target: Mutex<Option<thread::Thread>>,
    funding: Arc<ResourceLease>,
}

#[derive(Clone)]
struct CleanupWake {
    record: Arc<WakeRecord>,
    _funding: Arc<ResourceLease>, // after record, including ordinary clone Drop
}

impl CleanupWake {
    fn new(lease: ResourceLease) -> Self {
        let funding = Arc::new(lease);
        Self {
            record: Arc::new(WakeRecord {
                target: Mutex::new(None),
                funding: funding.clone(),
            }),
            _funding: funding,
        }
    }

    fn bind_current(&self) {
        *lock_recover(&self.record.target) = Some(thread::current());
    }

    fn waker(&self) -> Waker {
        let ptr = Arc::into_raw(self.record.clone()).cast::<()>();
        // SAFETY: ptr owns exactly one strong reference and only WAKE_VTABLE
        // operates on it. The funding guard in wake_drop outlives deallocation.
        unsafe { Waker::from_raw(RawWaker::new(ptr, &WAKE_VTABLE)) }
    }
}

unsafe fn wake_clone(ptr: *const ()) -> RawWaker {
    // SAFETY: the caller's live RawWaker owns a reference throughout cloning.
    unsafe {
        Arc::increment_strong_count(ptr.cast::<WakeRecord>());
    }
    RawWaker::new(ptr, &WAKE_VTABLE)
}

unsafe fn wake_ref(ptr: *const ()) {
    // SAFETY: this borrowed operation cannot outlive the caller's reference.
    let record = unsafe { &*ptr.cast::<WakeRecord>() };
    if let Some(target) = lock_recover(&record.target).as_ref() {
        target.unpark();
    }
}

unsafe fn wake_drop(ptr: *const ()) {
    // SAFETY: consumes exactly the reference represented by this RawWaker.
    let record = unsafe { Arc::from_raw(ptr.cast::<WakeRecord>()) };
    let funding = record.funding.clone();
    drop(record);
    drop(funding);
}

unsafe fn wake_owned(ptr: *const ()) {
    // Wake without consuming, then release the one owned reference.
    unsafe {
        wake_ref(ptr);
        wake_drop(ptr);
    }
}

static WAKE_VTABLE: RawWakerVTable =
    RawWakerVTable::new(wake_clone, wake_owned, wake_ref, wake_drop);

#[cfg(test)]
mod tests {
    use super::*;
    use myownmesh_core::ResourceProviderPort;

    fn resources(
        work: ResourceClaim,
    ) -> (
        FiniteResourceProvider,
        ResourceProviderPort,
        LocalApplicationResourceScope,
    ) {
        let grant = work
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
        (provider, port, scope)
    }

    fn service_claim() -> ResourceClaim {
        ResourceClaim::try_from_entries([
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::WorkerOrTask, 2),
        ])
        .unwrap()
    }

    #[test]
    fn closed_root_waits_for_registered_unqueued_service_disposition() {
        let root = test_support::TestRoot::new();
        let (provider, provider_port, scope) = resources(
            planned(service_claim())
                .unwrap()
                .checked_add(ServiceCleanupPort::entry_planning_charge().unwrap())
                .unwrap(),
        );
        let port = root.port();
        let mut custody = port
            .reserve(&scope, scope.acquire(service_claim()).unwrap())
            .unwrap();
        let terminal = custody.completion();
        custody.spawn_stun_observer().unwrap();
        root.begin_close();
        port.wait_closed_with_outstanding();
        let before = port.report_for_test();
        let still_owned =
            !terminal.is_joined() && provider.in_use().amount(ResourceClass::WorkerOrTask) == 2;
        custody.submit();
        drop((custody, port));
        let report = root.close();
        let joined = terminal.is_joined();
        drop((terminal, scope, provider_port));
        assert_eq!(before.completed, 0);
        assert!(still_owned && joined);
        assert_eq!(report.completed, 1);
        assert_eq!(report.worker_failures, 0);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn cleanup_record_refusal_precedes_registration_and_spawn() {
        let root = test_support::TestRoot::new();
        // Exact admitted prefix only: startup + node, but no completion record.
        let prefix = planned(service_claim())
            .unwrap()
            .checked_add(planned(record_claim::<CleanupNode>().unwrap()).unwrap())
            .unwrap();
        let (provider, provider_port, scope) = resources(prefix);
        let baseline = provider.in_use();
        let refused = root
            .port()
            .reserve(&scope, scope.acquire(service_claim()).unwrap());
        let resources_refused = matches!(refused, Err(ServiceCleanupError::Resources(_)));
        drop(refused);
        let restored = provider.in_use() == baseline;
        let report = root.close();
        drop((scope, provider_port));
        assert!(resources_refused && restored);
        assert_eq!(report.completed, 0, "no node was registered");
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn both_constructor_spawn_failures_restore_the_owned_prefix() {
        let (provider, provider_port, scope) =
            resources(ServiceCleanupOwner::planning_charge().unwrap());
        let baseline = provider.in_use();
        let refused = ServiceCleanupOwner::new_inner(scope.clone(), true);
        let root_refused = matches!(refused, Err(ServiceCleanupError::WorkerStart(_)));
        drop(refused);
        let root_restored = provider.in_use() == baseline;
        drop((scope, provider_port));
        let root_zero = provider.in_use() == ResourceClaim::ZERO;

        let root = test_support::TestRoot::new();
        let (provider, provider_port, scope) = resources(
            planned(service_claim())
                .unwrap()
                .checked_add(ServiceCleanupPort::entry_planning_charge().unwrap())
                .unwrap(),
        );
        let mut custody = root
            .port()
            .reserve(&scope, scope.acquire(service_claim()).unwrap())
            .unwrap();
        let terminal = custody.completion();
        let refused = custody.spawn_worker_inner(WorkerOutcome::default, true);
        let service_refused = matches!(refused, Err(ServiceCleanupError::WorkerStart(_)));
        custody.submit();
        drop(custody);
        let report = root.close();
        let joined = terminal.is_joined();
        drop((terminal, scope, provider_port));
        assert!(root_refused && root_restored && root_zero && service_refused && joined);
        assert_eq!(report.completed, 1);
        assert_eq!(
            report.worker_failures, 0,
            "registered pre-spawn rollback, not a detached worker"
        );
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn wake_clone_retains_exact_record_through_last_raw_owner() {
        let (provider, port, scope) =
            resources(planned(record_claim::<WakeRecord>().unwrap()).unwrap());
        let baseline = provider.in_use();
        let wake = CleanupWake::new(
            scope
                .acquire(record_claim::<WakeRecord>().unwrap())
                .unwrap(),
        );
        wake.bind_current();
        let raw = wake.waker();
        let last = raw.clone();
        drop((wake, raw));
        let held = provider.in_use().checked_sub(baseline).unwrap();
        last.wake_by_ref();
        drop(last);
        let restored = provider.in_use() == baseline;
        drop((scope, port));
        assert_eq!(
            held,
            planned(record_claim::<WakeRecord>().unwrap()).unwrap()
        );
        assert!(restored);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    fn observer_panic_preserves_provenance(request_before_terminal: bool) {
        let root = test_support::TestRoot::new();
        let service = planned(service_claim()).unwrap();
        let (provider, port, scope) = resources(
            service
                .checked_add(ServiceCleanupPort::entry_planning_charge().unwrap())
                .unwrap(),
        );
        let mut custody = root
            .port()
            .reserve(&scope, scope.acquire(service_claim()).unwrap())
            .unwrap();
        let terminal = custody.completion();
        // Panic before consuming the original handle; the root's existing
        // recovery path must join that handle using the same terminal record.
        custody
            .spawn_worker(|| panic!("injected observer panic before original task observation"))
            .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let guard = StunTerminalGuard(terminal.clone());
        let task = runtime.spawn(async move {
            let _guard = guard;
            std::future::pending::<()>().await;
        });
        if request_before_terminal {
            terminal.request_stun_stop();
            task.abort();
        }
        drop(runtime);
        terminal.request_stun_stop(); // cannot rewrite an already unexpected Drop
        task.abort();
        custody.finish_stun(Some(task), false);
        drop(custody);
        let report = root.close();
        let joined = terminal.is_joined();
        drop((terminal, scope, port));
        assert!(joined);
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, u64::from(!request_before_terminal));
        assert_eq!(report.worker_failures, 1);
        // Failed retention transfers the raw obligation and retires its
        // reservation bookkeeping; it does not retain the planner surcharge.
        assert_eq!(provider.retained_after_failed_cleanup(), service_claim());
        assert_eq!(provider.in_use(), service_claim());
    }

    #[test]
    fn observer_panic_recovery_keeps_unexpected_listener_terminal_failure() {
        observer_panic_preserves_provenance(false);
    }

    #[test]
    fn observer_panic_recovery_does_not_invent_listener_failure_after_requested_abort() {
        observer_panic_preserves_provenance(true);
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use myownmesh_core::ResourceProviderPort;

    pub(crate) struct TestRoot {
        owner: Option<ServiceCleanupOwner>,
        scope: LocalApplicationResourceScope,
        provider_port: ResourceProviderPort,
        provider: FiniteResourceProvider,
    }

    impl TestRoot {
        pub(crate) fn new() -> Self {
            let grant = ServiceCleanupOwner::planning_charge()
                .expect("root plan")
                .checked_add(
                    FiniteResourceProvider::scope_planning_charge()
                        .checked_scale(2)
                        .expect("actual root scopes"),
                )
                .expect("root grant");
            let provider = FiniteResourceProvider::new(grant);
            let provider_port =
                ResourceProviderPort::new(provider.clone()).expect("root process scope");
            let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port)
                .expect("root application scope");
            let owner = ServiceCleanupOwner::new(scope.clone()).expect("outside root");
            Self {
                owner: Some(owner),
                scope,
                provider_port,
                provider,
            }
        }

        pub(crate) fn port(&self) -> ServiceCleanupPort {
            self.owner
                .as_ref()
                .expect("outside owner not joined")
                .port()
        }

        pub(crate) fn begin_close(&self) {
            self.owner
                .as_ref()
                .expect("outside owner not joined")
                .begin_close();
        }

        pub(crate) fn close(mut self) -> ServiceCleanupReport {
            let report = self
                .owner
                .take()
                .expect("exact root")
                .close_and_join()
                .expect("root joined");
            let Self {
                owner,
                scope,
                provider_port,
                provider,
            } = self;
            drop((owner, scope, provider_port));
            assert_eq!(
                provider.in_use(),
                ResourceClaim::ZERO,
                "isolated root owners released"
            );
            assert_eq!(
                provider.retained_after_failed_cleanup(),
                ResourceClaim::ZERO
            );
            report
        }
    }

    /// The root is outside both the future and its runtime, including unwind.
    /// Services retain their preexisting fixture scopes; this distinct private
    /// provider pays only the newly explicit root and its two actual scopes.
    pub(crate) fn with_runtime<F, Fut>(body: F)
    where
        F: FnOnce(ServiceCleanupPort) -> Fut,
        Fut: Future<Output = ()>,
    {
        let root = TestRoot::new();
        let port = root.port();
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("test runtime");
            runtime.block_on(body(port));
            drop(runtime);
        }));
        root.close();
        if let Err(error) = result {
            std::panic::resume_unwind(error);
        }
    }
}
