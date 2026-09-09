//! Provider-backed terminal custody for the signaling bridge.
//!
//! The signaling crate supplies the runtime-independent, object-safe observer
//! (`TaskCustodian`/`TaskReservation`).  This adapter adds the core provider
//! reservation and keeps its exact lease in the bridge reaper task until that
//! task has drained the fan-out handle.

use std::sync::{mpsc, Arc};

use parking_lot::Mutex;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use tracing::{error, warn};

use myownmesh_signaling::mdns::driver::DriverCustodyPlan;
use myownmesh_signaling::{TaskCustodian, TaskCustodyError, TaskReservation};

use crate::resource::{
    LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease, ResourceUnavailable,
};

/// The bridge submits one fan-out handle and one reaper handle to the
/// reservation.  This is also the capacity of the dedicated observer's
/// semaphore and queue.
pub(crate) const SIGNALING_TASK_SLOTS: usize = 2;

const FANOUT_TASKS: u64 = 1;
const REAPER_TASKS: u64 = 1;
const DEDICATED_OBSERVER_RUNTIME: u64 = 1;
const DEDICATED_OBSERVER_TASKS: u64 = SIGNALING_TASK_SLOTS as u64;
const DEDICATED_OBSERVER_QUEUE_SLOTS: u64 = SIGNALING_TASK_SLOTS as u64;
const DEDICATED_OBSERVER_SEMAPHORE_SLOTS: u64 = SIGNALING_TASK_SLOTS as u64;
const DEDICATED_OBSERVER_PROGRESS_WATCH: u64 = 1;
const DEDICATED_OBSERVER_READY_QUEUE_SLOTS: u64 = 1;
const DEDICATED_OBSERVER_JOINSET_NODES: u64 = SIGNALING_TASK_SLOTS as u64;
const TERMINAL_OWNER_TASKS: u64 = 1;
const TERMINAL_OWNER_QUEUE_SLOTS: u64 = 1;
const SIGNALING_TERMINAL_QUEUE_SLOTS: u64 = SIGNALING_TASK_SLOTS as u64 + 1;
const NOSTR_TERMINAL_QUEUE_SLOTS: usize = 1;

/// A bridge reservation owns the fan-out/reaper pair separately from the
/// dedicated observer envelope.  Keeping these claims distinct means the
/// observer charge cannot be released merely because the bridge reaper has
/// finished.
const BRIDGE_TASKS: u64 = FANOUT_TASKS + REAPER_TASKS;
const BRIDGE_QUEUE_SLOTS: u64 = 1;

/// Exact final-task reservation for one signaling bridge instance.
pub(crate) struct SignalingTaskCustodian {
    // The reservation holds the observer's exact semaphore permits for the
    // lifetime of the production custodian; test controls may submit through
    // it, but production terminal custody uses the non-runtime owner below.
    _reservation: Box<dyn myownmesh_signaling::TaskReservation>,
    observer_owner: Arc<TerminalOwnerState>,
    bridge_lease: Option<ResourceLease>,
}

/// Ownership-preserving rejection for a refused terminal task submission.
/// Boxing keeps the `Result` small without discarding either the task or the
/// provider lease when the bounded terminal queue refuses them.
pub(crate) type TerminalTaskRejection = (JoinHandle<()>, ResourceLease);

impl SignalingTaskCustodian {
    /// The bridge reaper accepts one terminal handle at a time.  Keep the
    /// channel capacity beside the provider claim so the two cannot drift.
    pub(crate) const REAPER_QUEUE_SLOTS: usize = 1;

    /// Return the complete provider claim for one signaling bridge lifecycle.
    /// The public total is retained for planning and controls; construction
    /// acquires its bridge and observer portions independently.
    #[cfg(test)]
    pub(crate) fn provider_claim() -> Result<ResourceClaim, ResourceUnavailable> {
        let worker_tasks = BRIDGE_TASKS.checked_add(observer_worker_claim()?).ok_or(
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            },
        )?;
        let opaque_residual = BRIDGE_QUEUE_SLOTS
            .checked_add(observer_opaque_claim()?)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::WorkerOrTask, worker_tasks),
            (ResourceClass::OpaqueDependencyResidual, opaque_residual),
        ])
        .map_err(|error| ResourceUnavailable::ProviderInvariant {
            dimension: match error {
                crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
                | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => {
                    dimension
                }
            },
        })
    }

    pub(crate) fn bridge_claim() -> ResourceClaim {
        ResourceClaim::try_from_entries([
            (ResourceClass::WorkerOrTask, BRIDGE_TASKS),
            (ResourceClass::OpaqueDependencyResidual, BRIDGE_QUEUE_SLOTS),
        ])
        .expect("signaling bridge claim is fixed and representable")
    }

    pub(crate) fn observer_claim() -> Result<ResourceClaim, ResourceUnavailable> {
        ResourceClaim::try_from_entries([
            (ResourceClass::WorkerOrTask, observer_worker_claim()?),
            (
                ResourceClass::OpaqueDependencyResidual,
                observer_opaque_claim()?,
            ),
        ])
        .map_err(|error| ResourceUnavailable::ProviderInvariant {
            dimension: match error {
                crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
                | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => {
                    dimension
                }
            },
        })
    }

    /// Reserve the exact fan-out and reaper population before either spawns.
    pub(crate) fn reserve(
        scope: LocalApplicationResourceScope,
    ) -> Result<Self, ResourceUnavailable> {
        let bridge_lease = scope.acquire(Self::bridge_claim())?;
        let observer_lease = match scope.acquire(Self::observer_claim()?) {
            Ok(lease) => lease,
            Err(error) => {
                drop(bridge_lease);
                return Err(error);
            }
        };
        let observer = myownmesh_signaling::DedicatedTaskCustodian::new(SIGNALING_TASK_SLOTS)
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            });
        let observer = match observer {
            Ok(observer) => observer,
            Err(error) => {
                drop(observer_lease);
                drop(bridge_lease);
                return Err(error);
            }
        };
        let observer_owner = match TerminalOwnerState::new(
            observer,
            observer_lease,
            "myownmesh-signaling-terminal-custodian",
            SIGNALING_TERMINAL_QUEUE_SLOTS as usize,
        ) {
            Ok(owner) => owner,
            Err(error) => {
                drop(bridge_lease);
                return Err(error);
            }
        };
        let reservation =
            TaskCustodian::reserve(observer_owner.observer().as_ref(), SIGNALING_TASK_SLOTS)
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::WorkerOrTask,
                });
        let reservation = match reservation {
            Ok(reservation) => reservation,
            Err(error) => {
                observer_owner.close();
                drop(bridge_lease);
                return Err(error);
            }
        };
        Ok(Self {
            _reservation: Box::new(OwnedTaskReservation {
                inner: reservation,
                _owner: Arc::clone(&observer_owner),
            }),
            observer_owner,
            bridge_lease: Some(bridge_lease),
        })
    }

    /// Move the provider lease into the terminal owner together with the
    /// final task that proves the bridge's fan-out terminal state.
    pub(crate) fn take_lease(&mut self) -> Option<ResourceLease> {
        self.bridge_lease.take()
    }

    /// Transfer the exact final handles to the injected observer.
    #[cfg(test)]
    pub(crate) fn submit(&mut self, tasks: Vec<JoinHandle<()>>) -> Result<(), Vec<JoinHandle<()>>> {
        if tasks.len() != SIGNALING_TASK_SLOTS {
            return match self.observer_owner.submit_refused(tasks) {
                Ok(()) => Ok(()),
                Err(tasks) => Err(tasks),
            };
        }
        let mut remaining = tasks.into_iter();
        for _ in 0..SIGNALING_TASK_SLOTS {
            let task = remaining.next().expect("exact signaling task population");
            if let Err(task) = self._reservation.submit(task) {
                let mut refused = vec![task];
                refused.extend(remaining);
                return match self.observer_owner.submit_refused(refused) {
                    Ok(()) => Ok(()),
                    Err(tasks) => Err(tasks),
                };
            }
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn observer_for_test(&self) -> Arc<myownmesh_signaling::DedicatedTaskCustodian> {
        self.observer_owner.observer()
    }

    #[cfg(test)]
    pub(crate) fn reservation_for_test(&mut self) -> &mut dyn TaskReservation {
        self._reservation.as_mut()
    }

    #[cfg(test)]
    pub(crate) fn take_terminal_thread_for_test(&self) -> Option<std::thread::JoinHandle<()>> {
        self.observer_owner.take_terminal_thread_for_test()
    }

    /// Release observer and bridge custody after ordinary shutdown has joined
    /// both bridge handles.
    pub(crate) fn close(&mut self) {
        self.observer_owner.close();
        self.bridge_lease.take();
    }

    /// Transfer a bridge task together with the lease that protects it to the
    /// non-runtime terminal owner. The lease is released only after the task
    /// has reached its observed terminal state.
    pub(crate) fn submit_with_lease(
        &self,
        task: JoinHandle<()>,
        lease: ResourceLease,
    ) -> Result<(), Box<TerminalTaskRejection>> {
        self.observer_owner.submit_with_lease(task, lease)
    }

    /// Transfer one task directly to the non-runtime terminal owner.
    pub(crate) fn submit_terminal(&self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        self.observer_owner.submit_terminal(task)
    }
}

impl Drop for SignalingTaskCustodian {
    fn drop(&mut self) {
        // Drop may run inside a current-thread runtime. The observer owner
        // transfers its remaining lease and observer to a pre-created
        // non-runtime terminal thread; it never synchronously closes here.
        self.bridge_lease.take();
    }
}

fn observer_worker_claim() -> Result<u64, ResourceUnavailable> {
    DEDICATED_OBSERVER_RUNTIME
        .checked_add(DEDICATED_OBSERVER_TASKS)
        .and_then(|count| count.checked_add(TERMINAL_OWNER_TASKS))
        .ok_or(ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::WorkerOrTask,
        })
}

fn observer_opaque_claim() -> Result<u64, ResourceUnavailable> {
    DEDICATED_OBSERVER_QUEUE_SLOTS
        .checked_add(DEDICATED_OBSERVER_SEMAPHORE_SLOTS)
        .and_then(|count| count.checked_add(DEDICATED_OBSERVER_PROGRESS_WATCH))
        .and_then(|count| count.checked_add(DEDICATED_OBSERVER_READY_QUEUE_SLOTS))
        .and_then(|count| count.checked_add(DEDICATED_OBSERVER_JOINSET_NODES))
        .and_then(|count| count.checked_add(SIGNALING_TERMINAL_QUEUE_SLOTS))
        .ok_or(ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })
}

/// Provider-funded terminal custody for the mDNS driver's primary, backend,
/// and independent reaper reservations.
///
/// This owner is passed to the driver before it starts. Its lease therefore
/// covers the six outer driver tasks, dedicated observer runtime, all primary,
/// backend, and reaper reservations, and every bounded observer structure
/// before the driver can reserve or spawn work.
/// The lease is released only by the driver's explicit close boundary, after
/// its observer has drained the submitted handles.
pub(crate) struct MdnsTaskCustodian {
    state: Arc<TerminalOwnerState>,
}

struct TerminalOwnerState {
    observer: Mutex<Option<Arc<myownmesh_signaling::DedicatedTaskCustodian>>>,
    lease: Mutex<Option<ResourceLease>>,
    terminal_sender: Mutex<Option<mpsc::SyncSender<TerminalMessage>>>,
    terminal_thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl TerminalOwnerState {
    fn new(
        observer: Arc<myownmesh_signaling::DedicatedTaskCustodian>,
        lease: ResourceLease,
        thread_name: &'static str,
        terminal_queue_slots: usize,
    ) -> Result<Arc<Self>, ResourceUnavailable> {
        let (terminal_sender, terminal_receiver) = mpsc::sync_channel(terminal_queue_slots);
        let terminal_thread =
            match std::thread::Builder::new()
                .name(thread_name.into())
                .spawn(move || {
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .ok();
                    while let Ok(message) = terminal_receiver.recv() {
                        match message {
                            TerminalMessage::Task(task) => {
                                if let Some(runtime) = runtime.as_ref() {
                                    runtime.block_on(async {
                                        if let Err(error) = task.await {
                                            warn!(
                                                ?error,
                                                "terminal owner observed refused task failure"
                                            );
                                        }
                                    });
                                } else {
                                    task.abort();
                                    let _ = futures::executor::block_on(task);
                                }
                            }
                            TerminalMessage::TaskWithLease { task, lease } => {
                                if let Some(runtime) = runtime.as_ref() {
                                    runtime.block_on(async {
                                        if let Err(error) = task.await {
                                            warn!(
                                                ?error,
                                                "terminal owner observed leased task failure"
                                            );
                                        }
                                    });
                                } else {
                                    task.abort();
                                    let _ = futures::executor::block_on(task);
                                }
                                drop(lease);
                            }
                            TerminalMessage::Close(bundle) => {
                                bundle.observer.close();
                                drop(bundle.lease);
                                break;
                            }
                        }
                    }
                }) {
                Ok(thread) => thread,
                Err(_) => {
                    observer.close();
                    drop(lease);
                    return Err(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::WorkerOrTask,
                    });
                }
            };
        Ok(Arc::new(Self {
            observer: Mutex::new(Some(observer)),
            lease: Mutex::new(Some(lease)),
            terminal_sender: Mutex::new(Some(terminal_sender)),
            terminal_thread: Mutex::new(Some(terminal_thread)),
        }))
    }

    fn observer(&self) -> Arc<myownmesh_signaling::DedicatedTaskCustodian> {
        self.observer
            .lock()
            .as_ref()
            .cloned()
            .expect("terminal observer remains live until close")
    }

    #[cfg(test)]
    fn take_terminal_thread_for_test(&self) -> Option<std::thread::JoinHandle<()>> {
        self.terminal_thread.lock().take()
    }

    fn close(&self) {
        let observer = self.observer.lock().take();
        let lease = self.lease.lock().take();
        let sender = self.terminal_sender.lock().take();
        match (observer, lease, sender) {
            (Some(observer), Some(lease), Some(sender)) => {
                if let Err(mpsc::SendError(TerminalMessage::Close(bundle))) =
                    sender.send(TerminalMessage::Close(TerminalBundle { observer, lease }))
                {
                    bundle.observer.close();
                    if let Err(error) = bundle.lease.retain_after_failed_cleanup() {
                        error!(?error, "terminal owner could not retain provider custody");
                    }
                }
            }
            (observer, lease, sender) => {
                drop(sender);
                if let Some(observer) = observer {
                    observer.close();
                }
                drop(lease);
            }
        }
        if let Some(thread) = self.terminal_thread.lock().take() {
            if thread.thread().id() != std::thread::current().id() {
                let _ = thread.join();
            }
        }
    }

    fn submit_refused(&self, tasks: Vec<JoinHandle<()>>) -> Result<(), Vec<JoinHandle<()>>> {
        let sender = self.terminal_sender.lock();
        let Some(sender) = sender.as_ref() else {
            return Err(tasks);
        };
        let mut remaining = Vec::new();
        for task in tasks {
            if let Err(error) = sender.try_send(TerminalMessage::Task(task)) {
                match error {
                    mpsc::TrySendError::Full(TerminalMessage::Task(task))
                    | mpsc::TrySendError::Disconnected(TerminalMessage::Task(task)) => {
                        remaining.push(task)
                    }
                    mpsc::TrySendError::Full(TerminalMessage::Close(bundle))
                    | mpsc::TrySendError::Disconnected(TerminalMessage::Close(bundle)) => {
                        observe_impossible_close(
                            bundle,
                            "terminal close submitted through task fallback",
                        )
                    }
                    mpsc::TrySendError::Full(TerminalMessage::TaskWithLease { task, lease })
                    | mpsc::TrySendError::Disconnected(TerminalMessage::TaskWithLease {
                        task,
                        lease,
                    }) => observe_impossible_task_with_lease(
                        task,
                        lease,
                        "leased task submitted through plain task fallback",
                    ),
                }
            }
        }
        if remaining.is_empty() {
            Ok(())
        } else {
            Err(remaining)
        }
    }

    fn submit_terminal(&self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        self.submit_refused(vec![task]).map_err(|mut tasks| {
            tasks
                .pop()
                .expect("a refused terminal submission retains its handle")
        })
    }

    fn submit_with_lease(
        &self,
        task: JoinHandle<()>,
        lease: ResourceLease,
    ) -> Result<(), Box<TerminalTaskRejection>> {
        let sender = self.terminal_sender.lock();
        let Some(sender) = sender.as_ref() else {
            return Err(Box::new((task, lease)));
        };
        match sender.try_send(TerminalMessage::TaskWithLease { task, lease }) {
            Ok(()) => Ok(()),
            Err(mpsc::TrySendError::Full(TerminalMessage::TaskWithLease { task, lease }))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::TaskWithLease {
                task,
                lease,
            })) => Err(Box::new((task, lease))),
            Err(mpsc::TrySendError::Full(TerminalMessage::Task(task)))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::Task(task))) => {
                observe_impossible_task(task, "plain task returned from leased task custody")
            }
            Err(mpsc::TrySendError::Full(TerminalMessage::Close(bundle)))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::Close(bundle))) => {
                observe_impossible_close(bundle, "terminal close returned from leased task custody")
            }
        }
    }
}

impl Drop for TerminalOwnerState {
    fn drop(&mut self) {
        // Driver Drop may occur inside a current-thread Tokio runtime. Move
        // the observer and lease to the pre-created non-runtime owner; Drop
        // itself never waits for tasks that still need the caller's runtime.
        let observer = self.observer.get_mut().take();
        let lease = self.lease.get_mut().take();
        let sender = self.terminal_sender.get_mut().take();
        let Some(sender) = sender else {
            if let Some(lease) = lease {
                let _ = lease.retain_after_failed_cleanup();
            }
            return;
        };
        let (Some(observer), Some(lease)) = (observer, lease) else {
            drop(sender);
            return;
        };
        let bundle = TerminalBundle { observer, lease };
        match sender.try_send(TerminalMessage::Close(bundle)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(TerminalMessage::Close(bundle)))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::Close(bundle))) => {
                if let Err(error) = bundle.lease.retain_after_failed_cleanup() {
                    error!(?error, "terminal owner could not retain provider custody");
                }
            }
            Err(mpsc::TrySendError::Full(TerminalMessage::Task(task)))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::Task(task))) => {
                observe_impossible_task(task, "plain task returned from terminal close")
            }
            Err(mpsc::TrySendError::Full(TerminalMessage::TaskWithLease { task, lease }))
            | Err(mpsc::TrySendError::Disconnected(TerminalMessage::TaskWithLease {
                task,
                lease,
            })) => observe_impossible_task_with_lease(
                task,
                lease,
                "leased task returned from terminal close",
            ),
        }
    }
}

fn observe_impossible_task(task: JoinHandle<()>, context: &'static str) -> ! {
    task.abort();
    let _ = futures::executor::block_on(task);
    panic!("{context}");
}

fn observe_impossible_task_with_lease(
    task: JoinHandle<()>,
    lease: ResourceLease,
    context: &'static str,
) -> ! {
    task.abort();
    let _ = futures::executor::block_on(task);
    drop(lease);
    panic!("{context}");
}

fn observe_impossible_close(bundle: TerminalBundle, context: &'static str) -> ! {
    bundle.observer.close();
    if let Err(error) = bundle.lease.retain_after_failed_cleanup() {
        error!(?error, "terminal owner could not retain provider custody");
    }
    panic!("{context}");
}

struct TerminalBundle {
    observer: Arc<myownmesh_signaling::DedicatedTaskCustodian>,
    lease: ResourceLease,
}

enum TerminalMessage {
    Task(JoinHandle<()>),
    TaskWithLease {
        task: JoinHandle<()>,
        lease: ResourceLease,
    },
    Close(TerminalBundle),
}

impl MdnsTaskCustodian {
    const OBSERVER_TASKS: usize = SIGNALING_TASK_SLOTS;
    const PRIMARY_DRIVER_TASKS: usize = 1;

    #[cfg(test)]
    pub(crate) fn provider_claim(
        outer_driver_task_slots: usize,
    ) -> Result<ResourceClaim, ResourceUnavailable> {
        Self::provider_claim_with_plan(outer_driver_task_slots, None)
    }

    pub(crate) fn provider_claim_with_plan(
        outer_driver_task_slots: usize,
        plan: Option<DriverCustodyPlan>,
    ) -> Result<ResourceClaim, ResourceUnavailable> {
        let outer_driver_task_slots = outer_driver_task_slots.try_into().map_err(|_| {
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            }
        })?;
        let (observer_runtime, observer_tasks, observer_queue) = plan
            .and_then(|plan| {
                let observer_tasks = plan
                    .reaper_observer_task_slots
                    .checked_add(Self::PRIMARY_DRIVER_TASKS)
                    .and_then(|slots| slots.checked_add(plan.backend_observer_slots))?;
                let observer_queue = plan
                    .reaper_observer_queue_slots
                    .checked_add(Self::PRIMARY_DRIVER_TASKS)
                    .and_then(|slots| slots.checked_add(plan.backend_observer_slots))?;
                Some((
                    plan.reaper_observer_runtime_slots,
                    observer_tasks,
                    observer_queue,
                ))
            })
            .unwrap_or((
                DEDICATED_OBSERVER_RUNTIME as usize,
                DEDICATED_OBSERVER_TASKS as usize,
                DEDICATED_OBSERVER_QUEUE_SLOTS as usize,
            ));
        let plan_worker: u64 = plan
            .map(|plan| {
                plan.backend_runtime_slots
                    .checked_add(plan.backend_observer_slots)
                    .ok_or(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::WorkerOrTask,
                    })?
                    .try_into()
                    .map_err(|_| ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::WorkerOrTask,
                    })
            })
            .transpose()?
            .unwrap_or(0);
        let plan_queue: u64 = plan
            .map(|plan| {
                plan.backend_queue_slots.try_into().map_err(|_| {
                    ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    }
                })
            })
            .transpose()?
            .unwrap_or(0);
        let observer_runtime: u64 =
            observer_runtime
                .try_into()
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::WorkerOrTask,
                })?;
        let observer_tasks: u64 =
            observer_tasks
                .try_into()
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::WorkerOrTask,
                })?;
        let observer_queue: u64 =
            observer_queue
                .try_into()
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
        let workers = observer_runtime
            .checked_add(observer_tasks)
            .and_then(|count| count.checked_add(outer_driver_task_slots))
            .and_then(|count| count.checked_add(plan_worker))
            .and_then(|count| count.checked_add(TERMINAL_OWNER_TASKS))
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
        let observer_semaphore = observer_tasks;
        let observer_joinset = observer_tasks;
        let opaque = observer_queue
            .checked_add(observer_semaphore)
            .and_then(|count| count.checked_add(DEDICATED_OBSERVER_PROGRESS_WATCH))
            .and_then(|count| count.checked_add(DEDICATED_OBSERVER_READY_QUEUE_SLOTS))
            .and_then(|count| count.checked_add(observer_joinset))
            .and_then(|count| count.checked_add(plan_queue))
            .and_then(|count| count.checked_add(TERMINAL_OWNER_QUEUE_SLOTS))
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::WorkerOrTask, workers),
            (ResourceClass::OpaqueDependencyResidual, opaque),
        ])
        .map_err(|error| ResourceUnavailable::ProviderInvariant {
            dimension: match error {
                crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
                | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => {
                    dimension
                }
            },
        })
    }

    #[cfg(test)]
    pub(crate) fn take_terminal_thread_for_test(&self) -> Option<std::thread::JoinHandle<()>> {
        self.state.take_terminal_thread_for_test()
    }

    #[cfg(test)]
    pub(crate) fn reserve(
        scope: LocalApplicationResourceScope,
        outer_driver_task_slots: usize,
    ) -> Result<Arc<Self>, ResourceUnavailable> {
        Self::reserve_with_plan(scope, outer_driver_task_slots, None)
    }

    pub(crate) fn reserve_with_plan(
        scope: LocalApplicationResourceScope,
        outer_driver_task_slots: usize,
        plan: Option<DriverCustodyPlan>,
    ) -> Result<Arc<Self>, ResourceUnavailable> {
        let lease = scope.acquire(Self::provider_claim_with_plan(
            outer_driver_task_slots,
            plan,
        )?)?;
        let observer_slots = plan
            .map(|plan| {
                plan.reaper_observer_task_slots
                    .checked_add(Self::PRIMARY_DRIVER_TASKS)
                    .and_then(|slots| slots.checked_add(plan.backend_observer_slots))
                    .ok_or(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::WorkerOrTask,
                    })
            })
            .transpose()?
            .unwrap_or(Self::OBSERVER_TASKS);
        let observer =
            myownmesh_signaling::DedicatedTaskCustodian::new(observer_slots).map_err(|_| {
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::WorkerOrTask,
                }
            })?;
        let state = TerminalOwnerState::new(
            observer,
            lease,
            "myownmesh-mdns-terminal-custodian",
            TERMINAL_OWNER_QUEUE_SLOTS as usize,
        )?;
        Ok(Arc::new(Self { state }))
    }
}

/// The independent provider-funded owners required by one Nostr driver.
/// Each owner retains its lease until the driver's transferred handles have
/// reached terminal observation.
pub(crate) struct NostrTaskCustodians {
    pub(crate) primary: Arc<NostrTaskOwner>,
    pub(crate) reaper: Arc<NostrTaskOwner>,
}

pub(crate) struct NostrTaskOwner {
    state: Arc<TerminalOwnerState>,
}

impl NostrTaskCustodians {
    pub(crate) fn reserve(
        scope: LocalApplicationResourceScope,
        plan: myownmesh_signaling::nostr::driver::NostrTaskCustodyPlan,
    ) -> Result<Self, ResourceUnavailable> {
        let primary = reserve_nostr_owner(
            &scope,
            plan.primary_observer_slots,
            "myownmesh-nostr-terminal-custodian",
        )?;
        let reaper = match reserve_nostr_owner(
            &scope,
            plan.reaper_observer_slots,
            "myownmesh-nostr-reaper-custodian",
        ) {
            Ok(owner) => owner,
            Err(error) => {
                primary.state.close();
                return Err(error);
            }
        };
        Ok(Self { primary, reaper })
    }
}

fn reserve_nostr_owner(
    scope: &LocalApplicationResourceScope,
    observer_slots: usize,
    thread_name: &'static str,
) -> Result<Arc<NostrTaskOwner>, ResourceUnavailable> {
    let lease = scope.acquire(observer_claim_for_slots(
        observer_slots,
        NOSTR_TERMINAL_QUEUE_SLOTS,
    )?)?;
    let observer =
        myownmesh_signaling::DedicatedTaskCustodian::new(observer_slots).map_err(|_| {
            ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            }
        })?;
    let state = TerminalOwnerState::new(observer, lease, thread_name, NOSTR_TERMINAL_QUEUE_SLOTS)?;
    Ok(Arc::new(NostrTaskOwner { state }))
}

fn observer_claim_for_slots(
    observer_slots: usize,
    terminal_queue_slots: usize,
) -> Result<ResourceClaim, ResourceUnavailable> {
    let observer_slots: u64 =
        observer_slots
            .try_into()
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::WorkerOrTask,
            })?;
    let terminal_queue_slots: u64 =
        terminal_queue_slots
            .try_into()
            .map_err(|_| ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            })?;
    let workers = DEDICATED_OBSERVER_RUNTIME
        .checked_add(observer_slots)
        .and_then(|count| count.checked_add(TERMINAL_OWNER_TASKS))
        .ok_or(ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::WorkerOrTask,
        })?;
    let opaque = observer_slots
        .checked_add(observer_slots)
        .and_then(|count| count.checked_add(DEDICATED_OBSERVER_PROGRESS_WATCH))
        .and_then(|count| count.checked_add(DEDICATED_OBSERVER_READY_QUEUE_SLOTS))
        .and_then(|count| count.checked_add(observer_slots))
        .and_then(|count| count.checked_add(terminal_queue_slots))
        .ok_or(ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::OpaqueDependencyResidual,
        })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::WorkerOrTask, workers),
        (ResourceClass::OpaqueDependencyResidual, opaque),
    ])
    .map_err(|error| ResourceUnavailable::ProviderInvariant {
        dimension: match error {
            crate::resource::ResourceClaimArithmeticError::Overflow { dimension }
            | crate::resource::ResourceClaimArithmeticError::Underflow { dimension } => dimension,
        },
    })
}

struct OwnedTaskReservation {
    inner: Box<dyn TaskReservation>,
    _owner: Arc<TerminalOwnerState>,
}

impl TaskReservation for OwnedTaskReservation {
    fn submit(&mut self, task: JoinHandle<()>) -> Result<(), JoinHandle<()>> {
        // Keep the outer owner alongside the driver's reservation so its
        // nonblocking Drop transfer cannot release custody early.
        self.inner.submit(task)
    }
}

impl TaskCustodian for MdnsTaskCustodian {
    fn reserve(&self, slots: usize) -> Result<Box<dyn TaskReservation>, TaskCustodyError> {
        let observer = self
            .state
            .observer
            .lock()
            .as_ref()
            .cloned()
            .ok_or(TaskCustodyError::ObserverUnavailable)?;
        let inner = TaskCustodian::reserve(observer.as_ref(), slots)?;
        Ok(Box::new(OwnedTaskReservation {
            inner,
            _owner: Arc::clone(&self.state),
        }))
    }

    fn progress(&self) -> watch::Receiver<u64> {
        let observer = self
            .state
            .observer
            .lock()
            .as_ref()
            .cloned()
            .expect("mDNS observer remains live until terminal close");
        TaskCustodian::progress(observer.as_ref())
    }

    fn close(&self) {
        self.state.close();
    }
}

impl TaskCustodian for NostrTaskOwner {
    fn reserve(&self, slots: usize) -> Result<Box<dyn TaskReservation>, TaskCustodyError> {
        let observer = self.state.observer();
        let inner = TaskCustodian::reserve(observer.as_ref(), slots)?;
        Ok(Box::new(OwnedTaskReservation {
            inner,
            _owner: Arc::clone(&self.state),
        }))
    }

    fn progress(&self) -> watch::Receiver<u64> {
        TaskCustodian::progress(self.state.observer().as_ref())
    }

    fn close(&self) {
        self.state.close();
    }
}
