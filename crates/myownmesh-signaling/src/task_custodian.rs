//! Injected, bounded custody for signaling task handles.
//!
//! A lifecycle owner creates one [`DedicatedTaskCustodian`] (or supplies an
//! implementation of [`TaskCustodian`]) and passes it to a driver before the
//! driver spawns work. Reservations are exact and synchronous, so `Drop` can
//! transfer a final handle without blocking or re-entering an executor. The
//! dedicated observer owns its own runtime thread and drains reserved handles
//! concurrently; it is independent of the runtime that created the driver.

use std::sync::Arc;
use std::thread;

use parking_lot::Mutex;
use tokio::sync::{mpsc, watch, OwnedSemaphorePermit, Semaphore};
use tokio::task::{JoinHandle, JoinSet};
use tracing::{debug, trace, warn};

/// The object-safe lifecycle seam for final signaling task custody.
pub trait TaskCustodian: Send + Sync {
    /// Reserve exactly `slots` final handles before spawning them.
    fn reserve(&self, slots: usize) -> Result<Box<dyn TaskReservation>, TaskCustodyError>;

    /// Subscribe to lossless terminal progress for retryable reservations.
    /// Callers use this only to wake a bounded pending-ID queue; refused
    /// handles/IDs remain owned until a later reservation succeeds.
    fn progress(&self) -> watch::Receiver<u64>;

    /// Close the observer after the lifecycle has joined its own tasks.
    /// Implementations may use this to synchronously join their observer;
    /// `Drop` paths must not call it.
    fn close(&self) {}
}

/// A reservation-backed, synchronous submission seam used by `Drop`.
pub trait TaskReservation: Send + Sync + 'static {
    /// Transfer one exact terminal handle to the external observer.
    fn submit(&mut self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>>;
}

/// Failure to establish or consume an injected bounded custody reservation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskCustodyError {
    InvalidCapacity,
    CapacityExhausted,
    ObserverUnavailable,
}

struct CustodyItem {
    task: JoinHandle<()>,
    permit: OwnedSemaphorePermit,
}

struct DedicatedInner {
    capacity: usize,
    permits: Arc<Semaphore>,
    sender: Mutex<Option<mpsc::Sender<CustodyItem>>>,
    progress: watch::Sender<u64>,
    /// Retained for the explicit process-lifetime observer contract.
    service: Mutex<Option<thread::JoinHandle<()>>>,
}

/// A caller-independent observer backed by a dedicated Tokio runtime thread.
pub struct DedicatedTaskCustodian {
    inner: Arc<DedicatedInner>,
}

impl DedicatedTaskCustodian {
    /// Create a bounded observer with exactly `capacity` reservation slots.
    pub fn new(capacity: usize) -> Result<Arc<Self>, TaskCustodyError> {
        if capacity == 0 {
            return Err(TaskCustodyError::InvalidCapacity);
        }
        let permits = Arc::new(Semaphore::new(capacity));
        let (sender, receiver) = mpsc::channel(capacity);
        let (progress, _) = watch::channel(0u64);
        let progress_for_thread = progress.clone();
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(1);
        let service = thread::Builder::new()
            .name("myownmesh-signaling-custodian".into())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let Ok(runtime) = runtime else {
                    let _ = ready_tx.send(false);
                    return;
                };
                let _ = ready_tx.send(true);
                runtime.block_on(run(receiver, progress_for_thread));
            })
            .map_err(|_| TaskCustodyError::ObserverUnavailable)?;
        let ready = ready_rx.recv();
        if !matches!(ready, Ok(true)) {
            let _ = service.join();
            return Err(TaskCustodyError::ObserverUnavailable);
        }
        Ok(Arc::new(Self {
            inner: Arc::new(DedicatedInner {
                capacity,
                permits,
                sender: Mutex::new(Some(sender)),
                progress,
                service: Mutex::new(Some(service)),
            }),
        }))
    }
}

impl TaskCustodian for DedicatedTaskCustodian {
    fn reserve(&self, slots: usize) -> Result<Box<dyn TaskReservation>, TaskCustodyError> {
        if slots == 0 || slots > self.inner.capacity {
            return Err(TaskCustodyError::InvalidCapacity);
        }
        let mut permits = Vec::with_capacity(slots);
        for _ in 0..slots {
            match self.inner.permits.clone().try_acquire_owned() {
                Ok(permit) => permits.push(permit),
                Err(_) => return Err(TaskCustodyError::CapacityExhausted),
            }
        }
        Ok(Box::new(DedicatedTaskReservation {
            owner: Arc::clone(&self.inner),
            permits,
        }))
    }

    fn progress(&self) -> watch::Receiver<u64> {
        self.inner.progress.subscribe()
    }

    fn close(&self) {
        let sender = self.inner.sender.lock().take();
        drop(sender);
        let service = self.inner.service.lock().take();
        if let Some(service) = service {
            if service.thread().id() != thread::current().id() {
                let _ = service.join();
            }
        }
    }
}

struct DedicatedTaskReservation {
    owner: Arc<DedicatedInner>,
    permits: Vec<OwnedSemaphorePermit>,
}

impl TaskReservation for DedicatedTaskReservation {
    fn submit(&mut self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        let service_finished = self
            .owner
            .service
            .lock()
            .as_ref()
            .is_some_and(|service| service.is_finished());
        if service_finished {
            return Err(task);
        }
        let Some(permit) = self.permits.pop() else {
            return Err(task);
        };
        let sender = self.owner.sender.lock().as_ref().cloned();
        let Some(sender) = sender else {
            self.permits.push(permit);
            return Err(task);
        };
        match sender.try_send(CustodyItem { task, permit }) {
            Ok(()) => Ok(()),
            Err(mpsc::error::TrySendError::Full(item))
            | Err(mpsc::error::TrySendError::Closed(item)) => {
                let CustodyItem { task, permit } = item;
                self.permits.push(permit);
                Err(task)
            }
        }
    }
}

/// Crate-local reservation handle used by the three signaling drivers.
pub(crate) type CustodianReservation = Box<dyn TaskReservation>;

async fn run(mut receiver: mpsc::Receiver<CustodyItem>, progress: watch::Sender<u64>) {
    let mut observers = JoinSet::new();
    loop {
        tokio::select! {
            item = receiver.recv() => match item {
                Some(item) => { observers.spawn(observe(item, progress.clone())); }
                None => break,
            },
            result = observers.join_next(), if !observers.is_empty() => {
                log_observer_result(result);
            }
        }
    }
    while let Some(result) = observers.join_next().await {
        log_observer_result(Some(result));
    }
}

async fn observe(item: CustodyItem, progress: watch::Sender<u64>) {
    match item.task.await {
        Ok(()) => trace!("signaling custodian observed normal task completion"),
        Err(error) if error.is_cancelled() => {
            debug!(?error, "signaling custodian observed task cancellation")
        }
        Err(error) if error.is_panic() => {
            warn!(?error, "signaling custodian observed task panic")
        }
        Err(error) => warn!(?error, "signaling custodian observed task join failure"),
    }
    drop(item.permit);
    progress.send_modify(|epoch| *epoch = epoch.wrapping_add(1));
}

fn log_observer_result(result: Option<Result<(), tokio::task::JoinError>>) {
    if let Some(Err(error)) = result {
        warn!(?error, "signaling custodian observer failed");
    }
}
