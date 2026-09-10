//! Run the daemon wholly inside a host application's process.
//!
//! This is `myownmesh serve` minus the process: the same mesh instance,
//! network registry, hosted services, updater tick, and control-socket
//! listener, started as tasks on the caller's tokio runtime and torn down
//! through the returned [`EmbeddedDaemon`] instead of a signal handler.
//!
//! The one intended consumer is a mobile app (iOS forbids spawning the
//! daemon as a child process), but nothing here is mobile-specific — any
//! embedder that wants the daemon in-process can use it.

use tracing::info;

use crate::control;
use crate::registry::NetworkRegistry;
use crate::services::ServiceManager;

/// Typed startup failures for the embedded daemon.
#[derive(Debug, thiserror::Error)]
pub enum EmbeddedStartError {
    /// Infrastructure-only startup must not create a network participant.
    #[error("infrastructure-only startup requires node participation to be disabled")]
    InfrastructureOnlyRequiresNodeDisabled,

    #[error("open mesh: {0}")]
    OpenMesh(#[from] myownmesh_core::Error),

    #[error("service policy: {0}")]
    ServicePolicy(#[from] crate::services::ServicePolicyError),

    #[error("service policy: {primary}; startup cleanup failed: {cleanup:?}")]
    ServicePolicyWithCleanup {
        primary: crate::services::ServicePolicyError,
        cleanup: Vec<String>,
    },

    #[error("network startup: {0}")]
    NetworkStartup(String),

    #[error("custody startup recovery: {0}")]
    CustodyRecovery(myownmesh_core::Error),

    #[error("cleanup custodian startup: {0}")]
    CleanupCustody(String),

    /// A transport-lab daemon must state an exact supported ICE policy.
    #[cfg(feature = "transport-lab")]
    #[error("MYOWNMESH_TRANSPORT_LAB_ICE_POLICY must be 'all' or 'relay': {0}")]
    TransportLabIcePolicy(String),
}

#[cfg(feature = "transport-lab")]
fn transport_lab_relay_only(value: Option<&str>) -> Result<bool, EmbeddedStartError> {
    match value {
        None | Some("all") => Ok(false),
        Some("relay") => Ok(true),
        Some(value) => Err(EmbeddedStartError::TransportLabIcePolicy(value.to_owned())),
    }
}

/// Ordered terminal failures observed while draining the daemon.
#[derive(Debug, thiserror::Error)]
#[error("daemon shutdown failed: {failures:?}")]
pub struct EmbeddedShutdownError {
    pub failures: Vec<EmbeddedShutdownFailure>,
}

#[derive(Debug)]
pub struct EmbeddedShutdownFailure {
    pub stage: &'static str,
    pub error: String,
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
enum EmbeddedCleanupResult {
    Pending = 0,
    Clean = 1,
    Failed = 2,
}

// Reuse the existing one-byte, shared terminal witness allocation. This is
// observation only, never a service/cleanup owner or permission to release it.
#[cfg(test)]
#[repr(transparent)]
struct EmbeddedCleanupOutcome(std::sync::atomic::AtomicU8);

#[cfg(test)]
impl EmbeddedCleanupOutcome {
    fn load(&self, ordering: std::sync::atomic::Ordering) -> bool {
        self.0.load(ordering) != EmbeddedCleanupResult::Pending as u8
    }

    fn result(&self) -> EmbeddedCleanupResult {
        match self.0.load(std::sync::atomic::Ordering::SeqCst) {
            0 => EmbeddedCleanupResult::Pending,
            1 => EmbeddedCleanupResult::Clean,
            _ => EmbeddedCleanupResult::Failed,
        }
    }
}

#[cfg(test)]
const _: () = {
    assert!(
        std::mem::size_of::<EmbeddedCleanupOutcome>()
            == std::mem::size_of::<std::sync::atomic::AtomicBool>()
    );
    assert!(
        std::mem::align_of::<EmbeddedCleanupOutcome>()
            == std::mem::align_of::<std::sync::atomic::AtomicBool>()
    );
};

#[cfg(test)]
struct EmbeddedTaskWitness {
    control_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    control_terminal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    updater_started: std::sync::Arc<std::sync::atomic::AtomicBool>,
    updater_terminal: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cleanup_terminal: std::sync::Arc<EmbeddedCleanupOutcome>,
    cleanup_thread_joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
    cleanup_root_join_errors: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cleanup_root_panics: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    cleanup_root_cancellations: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    updater_gate: std::sync::Arc<tokio::sync::Notify>,
    updater_gate_open: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

#[cfg(test)]
impl EmbeddedTaskWitness {
    fn new() -> Self {
        use std::sync::atomic::AtomicBool;
        Self {
            control_started: std::sync::Arc::new(AtomicBool::new(false)),
            control_terminal: std::sync::Arc::new(AtomicBool::new(false)),
            updater_started: std::sync::Arc::new(AtomicBool::new(false)),
            updater_terminal: std::sync::Arc::new(AtomicBool::new(false)),
            cleanup_terminal: std::sync::Arc::new(EmbeddedCleanupOutcome(
                std::sync::atomic::AtomicU8::new(EmbeddedCleanupResult::Pending as u8),
            )),
            cleanup_thread_joined: std::sync::Arc::new(AtomicBool::new(false)),
            cleanup_root_join_errors: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cleanup_root_panics: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            cleanup_root_cancellations: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
            updater_gate: std::sync::Arc::new(tokio::sync::Notify::new()),
            updater_gate_open: std::sync::Arc::new(AtomicBool::new(false)),
        }
    }
}

#[cfg(test)]
struct EmbeddedTaskTerminal(std::sync::Arc<std::sync::atomic::AtomicBool>);

#[cfg(test)]
static INJECT_CLEANUP_RUNTIME_FAILURE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);

#[cfg(all(test, unix))]
fn set_cleanup_runtime_failure_for_test(fail: bool) {
    INJECT_CLEANUP_RUNTIME_FAILURE.store(fail, std::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
impl Drop for EmbeddedTaskTerminal {
    fn drop(&mut self) {
        use std::sync::atomic::Ordering;
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The one pre-existing owner that owns the non-awaitable Drop handoff.
///
/// `EmbeddedDaemon::drop` cannot await, and spawning a cleanup future from
/// there would make the service/network drain itself detachable. This
/// custodian is therefore created before either daemon root task. Drop only
/// installs a request in its mailbox and latches the normal supervisor
/// cancellation; the custodian then joins both roots and drains services and
/// networks in the same order as [`EmbeddedDaemon::shutdown`].
///
/// The custodian's `WorkerOrTask` lease is acquired before its owner thread is
/// spawned and held until its terminal branch, so cleanup is part of the
/// caller-selected finite resource grant. Its terminal signal is retained for
/// the graceful path; the non-awaitable Drop path observes the shared witness
/// while the already-existing custodian performs the bounded drain. The
/// custodian's OS-thread handle is then transferred to the process-owned join
/// reaper, which retains and joins it after that terminal signal.
struct EmbeddedCleanupCustodian {
    mailbox: myownmesh_core::FundedArc<EmbeddedCleanupMailbox>,
    service_port: myownmesh_services::ServiceCleanupPort,
    requested: std::sync::atomic::AtomicBool,
    terminal:
        Option<tokio::sync::oneshot::Receiver<std::result::Result<(), EmbeddedShutdownError>>>,
    thread_reaper: std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>,
    thread: Option<std::thread::JoinHandle<()>>,
    #[cfg(test)]
    cleanup_thread_joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    cleanup_thread_joining: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct EmbeddedCleanupThreadBatch {
    thread: std::thread::JoinHandle<()>,
    _mailbox: Option<myownmesh_core::FundedArc<EmbeddedCleanupMailbox>>,
    #[cfg(test)]
    joined: std::sync::Arc<std::sync::atomic::AtomicBool>,
    #[cfg(test)]
    joining: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

struct EmbeddedCleanupThreadReaper {
    sender: Option<std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>>,
    _thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
    /// The reaper is process-lived, so its one `WorkerOrTask` charge is held
    /// for the same lifetime rather than being silently borrowed from the
    /// first daemon that happened to start it.
    _lease: myownmesh_core::ResourceLease,
}

impl Drop for EmbeddedCleanupThreadReaper {
    fn drop(&mut self) {
        // Close the mailbox before joining so the receiver can observe its
        // terminal state. The process-global owner is retained by OnceLock;
        // this path is also used by isolated controls that must observe the
        // owner thread's join rather than detach it.
        self.sender.take();
        if let Some(thread) = self
            ._thread
            .lock()
            .expect("cleanup reaper mutex is not poisoned")
            .take()
        {
            let _ = thread.join();
        }
    }
}

// One process-lived owner receives cleanup-thread handles after a synchronous
// Drop. Keeping its own JoinHandle in the OnceLock means this owner is not
// itself detached; it is deliberately non-self because it never joins the
// thread that is executing it. Its worker/task lease is acquired before the
// thread is spawned and remains in this OnceLock until process exit.
static EMBEDDED_CLEANUP_THREAD_REAPER: std::sync::OnceLock<
    std::sync::Mutex<Option<EmbeddedCleanupThreadReaper>>,
> = std::sync::OnceLock::new();

fn embedded_cleanup_thread_reaper(
    scope: &myownmesh_core::LocalApplicationResourceScope,
) -> std::result::Result<std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>, String> {
    let slot = EMBEDDED_CLEANUP_THREAD_REAPER.get_or_init(|| std::sync::Mutex::new(None));
    embedded_cleanup_thread_reaper_in(scope, slot)
}

fn embedded_cleanup_thread_reaper_in(
    scope: &myownmesh_core::LocalApplicationResourceScope,
    slot: &std::sync::Mutex<Option<EmbeddedCleanupThreadReaper>>,
) -> std::result::Result<std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>, String> {
    let mut slot = slot
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    if let Some(reaper) = slot.as_ref() {
        return Ok(reaper
            .sender
            .as_ref()
            .expect("a live cleanup reaper retains its mailbox")
            .clone());
    }

    let reaper = {
        // This is process-lifetime work, not a per-daemon cleanup charge.
        // Acquire it before constructing the OS thread so a provider with no
        // spare WorkerOrTask capacity refuses the reaper before any work is
        // made live.
        let lease = scope
            .acquire(myownmesh_core::ResourceClaim::single(
                myownmesh_core::ResourceClass::WorkerOrTask,
                1,
            ))
            .map_err(|error| error.to_string())?;
        // This is an owner handoff, not a work queue.  It must never make a
        // synchronous Drop wait behind another daemon's cleanup-thread join.
        // The process-owned receiver drains every submitted terminal handle;
        // its sender remains retained by the owner for the owner's lifetime.
        let (sender, receiver) = std::sync::mpsc::channel::<EmbeddedCleanupThreadBatch>();
        let thread = std::thread::Builder::new()
            .name("myownmesh-embedded-cleanup-join".to_string())
            .spawn(move || {
                while let Ok(batch) = receiver.recv() {
                    #[cfg(test)]
                    batch
                        .joining
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                    let _ = batch.thread.join();
                    // The joined witness must not race the final funded
                    // transfer backing release in exact-baseline controls.
                    drop(batch._mailbox);
                    #[cfg(test)]
                    batch
                        .joined
                        .store(true, std::sync::atomic::Ordering::SeqCst);
                }
            })
            .map_err(|error| error.to_string())?;
        EmbeddedCleanupThreadReaper {
            sender: Some(sender),
            _thread: std::sync::Mutex::new(Some(thread)),
            _lease: lease,
        }
    };
    let sender = reaper
        .sender
        .as_ref()
        .expect("a newly built cleanup reaper retains its mailbox")
        .clone();
    *slot = Some(reaper);
    Ok(sender)
}

struct EmbeddedCleanupMailbox {
    request: std::sync::Mutex<Option<EmbeddedCleanupRequest>>,
    ready: std::sync::Condvar,
}

enum EmbeddedCleanupRequest {
    Graceful,
    #[cfg(test)]
    Blocked {
        release: std::sync::Arc<std::sync::atomic::AtomicBool>,
    },
    Dropped {
        control: Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
        updater: Option<tokio::task::JoinHandle<()>>,
        service_manager: std::sync::Arc<ServiceManager>,
        registry: std::sync::Arc<NetworkRegistry>,
    },
}

/// Fixed ownership-transfer storage, not a whole-runtime/allocator bound.
/// FundedArc retains it through the final cleanup-thread join; the two channel
/// internals and shared allocation metadata use the existing residual model.
pub(crate) fn cleanup_storage_claim(
) -> Result<myownmesh_core::ResourceClaim, myownmesh_core::ResourceClaimArithmeticError> {
    let dimension = myownmesh_core::ResourceClass::AccountedMemoryBytes;
    let bytes = [
        std::mem::size_of::<EmbeddedCleanupCustodian>(),
        std::mem::size_of::<EmbeddedCleanupMailbox>(),
        std::mem::size_of::<EmbeddedCleanupThreadBatch>(),
        std::mem::size_of::<myownmesh_core::ResourceLease>(),
        std::mem::size_of::<Result<myownmesh_services::ServiceCleanupPort, String>>(),
        std::mem::size_of::<Result<(), EmbeddedShutdownError>>(),
    ]
    .into_iter()
    .try_fold(0_u64, |total, bytes| {
        u64::try_from(bytes)
            .ok()
            .and_then(|bytes| total.checked_add(bytes))
            .ok_or(myownmesh_core::ResourceClaimArithmeticError::Overflow { dimension })
    })?;
    myownmesh_core::ResourceClaim::try_from_entries([
        (dimension, bytes),
        (myownmesh_core::ResourceClass::OpaqueDependencyResidual, 3),
    ])
}

impl EmbeddedCleanupCustodian {
    fn new(
        lease: myownmesh_core::ResourceLease,
        scope: myownmesh_core::LocalApplicationResourceScope,
        thread_reaper: std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>,
        #[cfg(test)] witness: std::sync::Arc<EmbeddedTaskWitness>,
    ) -> std::result::Result<Self, String> {
        let storage = scope
            .acquire(cleanup_storage_claim().map_err(|e| e.to_string())?)
            .map_err(|e| e.to_string())?;
        let mailbox = myownmesh_core::FundedArc::new(
            EmbeddedCleanupMailbox {
                request: std::sync::Mutex::new(None),
                ready: std::sync::Condvar::new(),
            },
            storage,
        )
        .map_err(|_| "cleanup storage requires admitted funding".to_string())?;
        let thread_mailbox = mailbox.clone();
        let (terminal_sender, terminal) = tokio::sync::oneshot::channel();
        let (ready_sender, ready_receiver) = std::sync::mpsc::sync_channel(1);
        #[cfg(test)]
        let cleanup_thread_joined = std::sync::Arc::clone(&witness.cleanup_thread_joined);
        #[cfg(test)]
        let cleanup_thread_joining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread = std::thread::Builder::new()
            .name("myownmesh-embedded-cleanup".to_string())
            .spawn(move || {
                #[cfg(test)]
                if INJECT_CLEANUP_RUNTIME_FAILURE.load(std::sync::atomic::Ordering::SeqCst) {
                    let _ = ready_sender.send(Err("injected cleanup runtime failure".to_string()));
                    return;
                }
                let runtime = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(runtime) => runtime,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                // Neither this owner nor its joining Drop ever enters the
                // origin runtime or the cleanup runtime's block_on future.
                let owner = match myownmesh_services::ServiceCleanupOwner::new(scope) {
                    Ok(owner) => owner,
                    Err(error) => {
                        let _ = ready_sender.send(Err(error.to_string()));
                        return;
                    }
                };
                if ready_sender.send(Ok(owner.port())).is_err() {
                    let _ = owner.close_and_join();
                    return;
                }
                let request = {
                    let mut slot = thread_mailbox
                        .request
                        .lock()
                        .expect("embedded cleanup mailbox is not poisoned");
                    loop {
                        if let Some(request) = slot.take() {
                            break request;
                        }
                        slot = thread_mailbox
                            .ready
                            .wait(slot)
                            .expect("embedded cleanup mailbox is not poisoned");
                    }
                };
                let mut failures = runtime.block_on(async {
                    let mut failures = Vec::new();
                    {
                        match request {
                            EmbeddedCleanupRequest::Graceful => {}
                            #[cfg(test)]
                            EmbeddedCleanupRequest::Blocked { release } => {
                                while !release.load(std::sync::atomic::Ordering::SeqCst) {
                                    tokio::task::yield_now().await;
                                }
                            }
                            EmbeddedCleanupRequest::Dropped {
                                control,
                                updater,
                                service_manager,
                                registry,
                            } => {
                                let control_result = match control {
                                    Some(control) => control.await,
                                    None => Ok(Ok(())),
                                };
                                match &control_result {
                                    Ok(Ok(())) => {}
                                    Ok(Err(error)) => {
                                        failures.push(EmbeddedShutdownFailure {
                                            stage: "control",
                                            error: error.clone(),
                                        });
                                    }
                                    Err(error) => failures.push(EmbeddedShutdownFailure {
                                        stage: "control",
                                        error: error.to_string(),
                                    }),
                                }
                                #[cfg(test)]
                                if let Err(error) = &control_result {
                                    witness
                                        .cleanup_root_join_errors
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    if error.is_panic() {
                                        witness
                                            .cleanup_root_panics
                                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    }
                                    if error.is_cancelled() {
                                        witness
                                            .cleanup_root_cancellations
                                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    }
                                }
                                let updater_result = match updater {
                                    Some(updater) => updater.await,
                                    None => Ok(()),
                                };
                                #[cfg(test)]
                                if let Err(error) = &updater_result {
                                    witness
                                        .cleanup_root_join_errors
                                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    if error.is_panic() {
                                        witness
                                            .cleanup_root_panics
                                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    }
                                    if error.is_cancelled() {
                                        witness
                                            .cleanup_root_cancellations
                                            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                                    }
                                }
                                if let Err(error) = updater_result {
                                    failures.push(EmbeddedShutdownFailure {
                                        stage: "updater",
                                        error: error.to_string(),
                                    });
                                }
                                owner.begin_close();
                                if let Err(error) = service_manager.shutdown().await {
                                    failures.push(EmbeddedShutdownFailure {
                                        stage: "services",
                                        error: error.to_string(),
                                    });
                                }
                                for outcome in registry.shutdown_all_with_departures().await {
                                    if let Err(error) = outcome {
                                        failures.push(EmbeddedShutdownFailure {
                                            stage: "network",
                                            error,
                                        });
                                    }
                                }
                            }
                        }
                    }
                    failures
                });
                match owner.close_and_join() {
                    Ok(report) if report.task_failures == 0 && report.worker_failures == 0 => {}
                    Ok(report) => failures.push(EmbeddedShutdownFailure {
                        stage: "service_cleanup",
                        error: format!(
                            "{} task failures, {} worker failures",
                            report.task_failures, report.worker_failures
                        ),
                    }),
                    Err(error) => failures.push(EmbeddedShutdownFailure {
                        stage: "service_cleanup",
                        error: error.to_string(),
                    }),
                }
                drop(runtime);
                drop(lease);
                let outcome = if failures.is_empty() {
                    Ok(())
                } else {
                    Err(EmbeddedShutdownError { failures })
                };
                #[cfg(test)]
                witness.cleanup_terminal.0.store(
                    (if outcome.is_ok() {
                        EmbeddedCleanupResult::Clean
                    } else {
                        EmbeddedCleanupResult::Failed
                    }) as u8,
                    std::sync::atomic::Ordering::SeqCst,
                );
                let _ = terminal_sender.send(outcome);
            })
            .map_err(|error| error.to_string())?;
        let service_port = match ready_receiver.recv() {
            Ok(Ok(port)) => port,
            Ok(Err(error)) => {
                let _ = thread.join();
                #[cfg(test)]
                cleanup_thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(error);
            }
            Err(error) => {
                let _ = thread.join();
                #[cfg(test)]
                cleanup_thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
                return Err(format!(
                    "cleanup runtime readiness handshake failed: {error}"
                ));
            }
        };
        Ok(Self {
            mailbox,
            service_port,
            requested: std::sync::atomic::AtomicBool::new(false),
            terminal: Some(terminal),
            thread_reaper,
            thread: Some(thread),
            #[cfg(test)]
            cleanup_thread_joined,
            #[cfg(test)]
            cleanup_thread_joining,
        })
    }

    fn request(&self, request: EmbeddedCleanupRequest) {
        if self
            .requested
            .swap(true, std::sync::atomic::Ordering::SeqCst)
        {
            // A second request could discard live handles. Never detach them.
            std::process::abort();
        }
        let mut slot = self
            .mailbox
            .request
            .lock()
            .expect("embedded cleanup mailbox is not poisoned");
        debug_assert!(slot.is_none(), "embedded cleanup is requested once");
        if slot.is_none() {
            *slot = Some(request);
        }
        drop(slot);
        self.mailbox.ready.notify_one();
    }

    async fn finish_graceful(mut self) -> std::result::Result<(), EmbeddedShutdownError> {
        if !self.requested.load(std::sync::atomic::Ordering::SeqCst) {
            self.request(EmbeddedCleanupRequest::Graceful);
        }
        let terminal = self
            .terminal
            .take()
            .expect("embedded cleanup task is present until shutdown");
        let terminal_result = terminal.await.map_err(|error| error.to_string());
        let thread = self
            .thread
            .take()
            .expect("embedded cleanup thread is present until terminal cleanup");
        let thread_result = thread.join();
        #[cfg(test)]
        self.cleanup_thread_joined
            .store(true, std::sync::atomic::Ordering::SeqCst);
        let mut failures = Vec::new();
        match terminal_result {
            Ok(Ok(())) => {}
            Ok(Err(error)) => failures.extend(error.failures),
            Err(error) => failures.push(EmbeddedShutdownFailure {
                stage: "cleanup",
                error: format!("cleanup terminal signal failed: {error}"),
            }),
        }
        if thread_result.is_err() {
            failures.push(EmbeddedShutdownFailure {
                stage: "cleanup",
                error: "embedded cleanup thread panicked before join".to_string(),
            });
        }
        if failures.is_empty() {
            Ok(())
        } else {
            Err(EmbeddedShutdownError { failures })
        }
    }

    fn handoff_drop(
        &self,
        control: Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
        updater: Option<tokio::task::JoinHandle<()>>,
        service_manager: std::sync::Arc<ServiceManager>,
        registry: std::sync::Arc<NetworkRegistry>,
    ) {
        self.request(EmbeddedCleanupRequest::Dropped {
            control,
            updater,
            service_manager,
            registry,
        });
    }
}

fn handoff_cleanup_thread(
    thread_reaper: &std::sync::mpsc::Sender<EmbeddedCleanupThreadBatch>,
    batch: EmbeddedCleanupThreadBatch,
) {
    // The reaper is established before any daemon task and retains its own
    // sender, so a disconnected owner is an invariant failure.  Never join
    // here: this function is called from synchronous Drop and the cleanup
    // thread may still be driving its own Tokio runtime.
    if thread_reaper.send(batch).is_err() {
        // There is no safe synchronous fallback here: joining could wait on
        // the cleanup runtime, while dropping the returned handle would
        // detach its terminal owner.  The owner is established before daemon
        // tasks and retained for process lifetime, so this is an invariant
        // failure; fail closed without leaving an unobserved handle behind.
        std::process::abort();
    }
}

impl Drop for EmbeddedCleanupCustodian {
    fn drop(&mut self) {
        // A daemon Drop hands the roots to this already-running owner before
        // this value is dropped. Graceful shutdown consumes its terminal
        // signal. If construction is abandoned before either handoff, wake the
        // owner into its empty terminal branch rather than leaving it parked.
        if !self.requested.load(std::sync::atomic::Ordering::SeqCst) {
            self.request(EmbeddedCleanupRequest::Graceful);
        }
        if let Some(thread) = self.thread.take() {
            let batch = EmbeddedCleanupThreadBatch {
                thread,
                _mailbox: Some(self.mailbox.clone()),
                #[cfg(test)]
                joined: std::sync::Arc::clone(&self.cleanup_thread_joined),
                #[cfg(test)]
                joining: std::sync::Arc::clone(&self.cleanup_thread_joining),
            };
            handoff_cleanup_thread(&self.thread_reaper, batch);
        }
    }
}

/// A daemon running inside this process. Keep it alive for the daemon's
/// lifetime; call [`shutdown`](Self::shutdown) for the same graceful teardown
/// `myownmesh serve` performs on SIGTERM (stop services, announce departures,
/// leave networks).
pub struct EmbeddedDaemon {
    mesh: myownmesh_core::MeshHandle,
    registry: std::sync::Arc<NetworkRegistry>,
    service_manager: std::sync::Arc<ServiceManager>,
    supervisor: crate::supervisor::RuntimeSupervisor,
    cleanup: Option<EmbeddedCleanupCustodian>,
    cleanup_handed_off: bool,
    #[cfg(test)]
    _task_witness: std::sync::Arc<EmbeddedTaskWitness>,
    /// The control surface, retained so shutdown can wait for it.
    ///
    /// Held rather than detached, and that is the whole of it: dropping the
    /// handle this spawn returns detaches the task, so [`Self::shutdown`] had no
    /// way to know whether `control::serve` had returned. Its `serve` is what
    /// makes the terminal claim — no accepted connection task is still live and
    /// the client registry has reached `Closed` — and an embedder that returned
    /// from `shutdown` without it was reporting a daemon closed while its
    /// control socket, its connection tasks and their registrations were all
    /// still up.
    control: Option<tokio::task::JoinHandle<std::result::Result<(), String>>>,
    /// The updater is part of this daemon's lifecycle rather than a detached
    /// process-global task. Shutdown requests cancellation and joins it.
    updater: Option<tokio::task::JoinHandle<()>>,
}

/// Construct the actual armed startup owner before a network/service await.
/// The same Drop handles a partially started daemon (no root tasks yet).
fn arm_daemon_cleanup(
    mesh: myownmesh_core::MeshHandle,
    cleanup: EmbeddedCleanupCustodian,
    #[cfg(test)] task_witness: std::sync::Arc<EmbeddedTaskWitness>,
) -> EmbeddedDaemon {
    let registry = NetworkRegistry::new();
    let service_manager =
        ServiceManager::new(mesh.clone(), registry.clone(), cleanup.service_port.clone());
    EmbeddedDaemon {
        mesh,
        registry,
        service_manager,
        supervisor: crate::supervisor::RuntimeSupervisor::new(),
        cleanup: Some(cleanup),
        cleanup_handed_off: false,
        #[cfg(test)]
        _task_witness: task_witness,
        control: None,
        updater: None,
    }
}

impl Drop for EmbeddedDaemon {
    fn drop(&mut self) {
        if self.cleanup_handed_off {
            return;
        }
        // Drop cannot await. Latch the same cancellation state used by the
        // graceful path, then hand both root handles to the pre-existing
        // custodian. This keeps their JoinErrors and service/network teardown
        // behind one bounded owner rather than aborting and detaching them.
        self.supervisor.request_shutdown();
        let control = self.control.take();
        let updater = self.updater.take();
        self.cleanup
            .as_ref()
            .expect("embedded cleanup custodian is present until shutdown")
            .handoff_drop(
                control,
                updater,
                std::sync::Arc::clone(&self.service_manager),
                std::sync::Arc::clone(&self.registry),
            );
    }
}

impl EmbeddedDaemon {
    /// The device handle — identity, events, joins.
    pub fn mesh(&self) -> &myownmesh_core::MeshHandle {
        &self.mesh
    }

    /// The runtime's shutdown request, for a host that must observe one it did
    /// not make.
    ///
    /// A reset submits through this object, so a host that only ever waits on
    /// its own signal would keep running against state the daemon has deleted.
    /// There is no subscribe-in-time rule: the request is a latched state, and
    /// `wait_requested` resolves on one submitted before this handle even
    /// existed — which it can be, since the control socket is accepting before
    /// startup returns.
    pub fn supervisor(&self) -> &crate::supervisor::RuntimeSupervisor {
        &self.supervisor
    }

    /// Hold this daemon until its runtime is asked to stop, then drain it.
    ///
    /// The whole of what a host with no signal source of its own has to do, and
    /// the reason it exists is that the two halves were previously the host's to
    /// join: a reset submitted through the supervisor stopped the *control
    /// surface*, while hosted services, departure announcements and every joined
    /// network were only torn down by [`Self::shutdown`]. A host that did not
    /// write that glue kept a half-dead daemon.
    ///
    /// One drain, shared with an embedder's explicit `shutdown` — this is that
    /// call, after the wait. Idempotent because it consumes the daemon: there is
    /// no second drain to run, rather than a flag saying there is not. Nothing
    /// here is timed and nothing ends the host process; this returns and the
    /// application carries on.
    pub async fn run_until_shutdown(self) -> std::result::Result<(), EmbeddedShutdownError> {
        self.supervisor.wait_requested().await;
        self.shutdown().await
    }

    /// Graceful teardown, exactly like the serve binary's signal path.
    ///
    /// The control surface goes first and is *awaited*, and the order is the
    /// contract rather than a preference. Everything below this line removes
    /// state a control request can still be dispatched against — hosted
    /// services, then every joined network — so a connection task outliving the
    /// broadcast would be operating on a daemon that had already reported those
    /// gone. Awaiting `serve` is what establishes that no such task exists: it
    /// does not return until every connection it accepted has ended and its
    /// client registry has reached `Closed`.
    ///
    /// Nothing here is timed. `serve`'s own drain is what ends the accepted
    /// tasks, and it ends them by signalling rather than by aborting, so a
    /// request already in flight is finished rather than dropped half-applied.
    pub async fn shutdown(mut self) -> std::result::Result<(), EmbeddedShutdownError> {
        // Transfer every actual owner before the first await. Cancellation of
        // this waiter cannot detach a taken task or strand startup services.
        self.supervisor.request_shutdown();
        self.cleanup
            .as_ref()
            .expect("cleanup owner is armed")
            .handoff_drop(
                self.control.take(),
                self.updater.take(),
                self.service_manager.clone(),
                self.registry.clone(),
            );
        self.cleanup_handed_off = true; // ownership transferred, not a success claim
        let cleanup = self
            .cleanup
            .take()
            .expect("cleanup terminal owner is present");
        cleanup.finish_graceful().await
    }
}

/// Start the daemon with the connector policy selected by the process owner.
///
/// This is the only Arc 03 daemon path that can establish connectors. No
/// capacity, callback weight, or structural real-time limit is inferred here.
///
/// `realtime` must describe the profile that was actually registered on
/// `connector_policy` — [`RealtimeAdvert::unsupported`] if none was. It travels
/// separately rather than being read back off the policy because core keeps a
/// registered profile's codecs and capacity crate-private, so the caller that
/// registered it is the only place that can still see both halves.
///
/// It carries no promise: support, the registered encoding families, and a
/// ceiling only where the owner stated one. Whether a particular flow can open
/// is answered by the typed refusal at open time.
pub async fn start_connector_capable(
    cfg: myownmesh_core::MeshConfig,
    connector_policy: myownmesh_core::WebRtcConnectorCapablePolicy,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    #[cfg(feature = "transport-lab")]
    let mesh = {
        let requested = std::env::var("MYOWNMESH_TRANSPORT_LAB_ICE_POLICY");
        let value = match requested {
            Ok(value) => Some(value),
            Err(std::env::VarError::NotPresent) => None,
            Err(std::env::VarError::NotUnicode(_)) => {
                return Err(EmbeddedStartError::TransportLabIcePolicy(
                    "value is not UTF-8".to_string(),
                ));
            }
        };
        if transport_lab_relay_only(value.as_deref())? {
            myownmesh_core::Mesh::open_connector_capable_relay_only_for_lab(
                cfg.clone(),
                connector_policy,
            )
            .await?
        } else {
            myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?
        }
    };
    #[cfg(not(feature = "transport-lab"))]
    let mesh = myownmesh_core::Mesh::open_connector_capable(cfg.clone(), connector_policy).await?;
    start_with_mesh(cfg, mesh, realtime).await
}

/// Start a daemon that only hosts signaling, STUN, or TURN infrastructure.
///
/// The configuration must explicitly disable node participation. This form
/// installs no connector policy, joins no network, and cannot later enable
/// node participation through the live service configuration.
///
/// It still takes the owner's exact resource port. Installing no connector
/// policy removes the connector's demands, not the daemon's: this process
/// still admits IPC payloads, local application state and its own tasks, and
/// all of that has to be funded from an envelope the owner chose rather than
/// from one this function invented.
pub async fn start_infrastructure_only(
    cfg: myownmesh_core::MeshConfig,
    resources: myownmesh_core::ResourceProviderPort,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    if cfg.services.node.enabled {
        return Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled);
    }
    let mesh = myownmesh_core::Mesh::open_infrastructure_only(cfg.clone(), resources).await?;
    // Infrastructure-only installs no connector policy at all, so there is no
    // realtime path to advertise.
    start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported()).await
}

async fn start_with_mesh(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    start_with_mesh_inner(cfg, mesh, realtime, false).await
}

#[cfg(all(test, unix))]
async fn start_with_mesh_for_drop_control(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    start_with_mesh_inner(cfg, mesh, realtime, true).await
}

async fn start_with_mesh_inner(
    cfg: myownmesh_core::MeshConfig,
    mesh: myownmesh_core::MeshHandle,
    realtime: control::RealtimeAdvert,
    park_updater_for_test: bool,
) -> std::result::Result<EmbeddedDaemon, EmbeddedStartError> {
    #[cfg(not(test))]
    let _ = park_updater_for_test;
    info!(
        version = env!("CARGO_PKG_VERSION"),
        networks = cfg.networks.len(),
        "embedded daemon starting"
    );

    info!(device_id = %mesh.identity().display_id(), "identity ready");

    // Recover interrupted provisional custody before any control socket is
    // spawned. A corrupt store or an unresolvable owner lease is a startup
    // failure: exposing a live control surface while custody state is
    // uncertain would turn an interrupted handoff into an authority decision.
    myownmesh_core::custody::recover_provisional_enrollments()
        .map_err(EmbeddedStartError::CustodyRecovery)?;

    // Construct and synchronously ready the cleanup owner before any service,
    // network, listener, or daemon root can be started. A readiness failure
    // therefore returns the caller's lease before startup has background work
    // to clean up.
    let cleanup_scope = mesh.local_application_resource_scope()?;
    let thread_reaper = embedded_cleanup_thread_reaper(&cleanup_scope)
        .map_err(EmbeddedStartError::CleanupCustody)?;
    let cleanup_lease = cleanup_scope
        .acquire(myownmesh_core::ResourceClaim::single(
            myownmesh_core::ResourceClass::WorkerOrTask,
            1,
        ))
        .map_err(|error| EmbeddedStartError::CleanupCustody(error.to_string()))?;
    #[cfg(test)]
    let task_witness = std::sync::Arc::new(EmbeddedTaskWitness::new());
    #[cfg(test)]
    if !park_updater_for_test {
        task_witness
            .updater_gate_open
            .store(true, std::sync::atomic::Ordering::SeqCst);
    }
    #[cfg(test)]
    let cleanup_witness = std::sync::Arc::clone(&task_witness);
    let cleanup = EmbeddedCleanupCustodian::new(
        cleanup_lease,
        cleanup_scope,
        thread_reaper,
        #[cfg(test)]
        cleanup_witness,
    )
    .map_err(EmbeddedStartError::CleanupCustody)?;

    // The registry holds every JoinedNetwork + its signaling driver handle so
    // the control socket can address them by id. Node participation is a
    // toggle, exactly as in the serve binary.
    // The partially constructed daemon IS the armed startup guard. All roots
    // exist here before any joining/service future can suspend or be cancelled.
    let mut daemon = arm_daemon_cleanup(
        mesh.clone(),
        cleanup,
        #[cfg(test)]
        task_witness.clone(),
    );
    let registry = daemon.registry.clone();
    let service_manager = daemon.service_manager.clone();
    let supervisor = daemon.supervisor.clone();
    if cfg.services.node.enabled {
        if let Err(error) =
            crate::services::join_networks_checked(&mesh, &registry, &cfg.networks).await
        {
            return Err(EmbeddedStartError::NetworkStartup(
                match daemon.shutdown().await {
                    Ok(()) => error,
                    Err(cleanup) => format!("{error}; startup cleanup failed: {cleanup}"),
                },
            ));
        }
    } else {
        info!("node participation disabled — pure-infrastructure mode (hosting services only)");
    }

    // Infrastructure services (signaling / STUN / TURN); an all-off config
    // (the default) starts nothing.
    let report = match service_manager.apply(cfg.services.clone()).await {
        Ok(report) => report,
        Err(error) => {
            return Err(match daemon.shutdown().await {
                Ok(()) => error.into(),
                Err(cleanup) => EmbeddedStartError::ServicePolicyWithCleanup {
                    primary: error,
                    cleanup: vec![cleanup.to_string()],
                },
            });
        }
    };
    info!(
        signaling = report.signaling.running,
        stun = report.stun.running,
        turn = report.turn.running,
        "services applied from config"
    );

    // Updater tick. Spawned even when disabled in config — the task just
    // exits early.
    // The updater is owned by the embedded daemon and observes the same
    // latched shutdown signal as the control surface.
    let updater_supervisor = supervisor.clone();
    #[cfg(test)]
    let updater_witness = std::sync::Arc::clone(&task_witness);
    daemon.updater = Some(tokio::spawn(async move {
        #[cfg(test)]
        let _terminal =
            EmbeddedTaskTerminal(std::sync::Arc::clone(&updater_witness.updater_terminal));
        #[cfg(test)]
        updater_witness
            .updater_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        #[cfg(test)]
        loop {
            if updater_witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            let notified = updater_witness.updater_gate.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if updater_witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
            {
                break;
            }
            tokio::select! {
                _ = notified => {}
                _ = updater_supervisor.wait_requested() => break,
            }
        }
        myownmesh_updater::tick_until_shutdown(async move {
            updater_supervisor.wait_requested().await;
        })
        .await;
    }));

    // Control socket: the same listener + wire protocol every client talks
    // to, whether the daemon is a process or embedded.
    let ctl_supervisor = supervisor.clone();
    let ctl_mesh = mesh.clone();
    let ctl_registry = registry.clone();
    let ctl_services = service_manager.clone();
    let ctl_socket = cfg.daemon.control_socket.clone();
    #[cfg(test)]
    let control_witness = std::sync::Arc::clone(&task_witness);
    // Kept, not discarded. See [`EmbeddedDaemon::control`].
    daemon.control = Some(tokio::spawn(async move {
        #[cfg(test)]
        let _terminal =
            EmbeddedTaskTerminal(std::sync::Arc::clone(&control_witness.control_terminal));
        #[cfg(test)]
        control_witness
            .control_started
            .store(true, std::sync::atomic::Ordering::SeqCst);
        control::serve(
            ctl_mesh,
            ctl_registry,
            ctl_services,
            ctl_socket,
            realtime,
            ctl_supervisor,
        )
        .await
        .map_err(|error| error.to_string())
    }));

    Ok(daemon)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The production armed-startup owner with a real STUN listener, then the
    /// actual public shutdown future cancelled after its synchronous handoff.
    /// No extra ServiceCleanupOwner is parked in the fixture to mask Drop.
    #[test]
    fn armed_startup_drop_and_cancelled_shutdown_join_service_owners() {
        use std::sync::atomic::Ordering;
        crate::services::run_isolated_service_fixture(
            "embedded::tests::armed_startup_drop_and_cancelled_shutdown_join_service_owners",
            || {
                let stun_plan = myownmesh_services::StunServer::startup_planning_charge().unwrap();
                let scope_plan = myownmesh_core::FiniteResourceProvider::scope_planning_charge();
                // Actual Mesh constructor: process scope, Mesh-owned application scope,
                // and the child scope retained by the real STUN service. No root credit.
                let service_grant = stun_plan
                    .checked_add(scope_plan.checked_scale(3).unwrap())
                    .unwrap();
                let service_provider = myownmesh_core::FiniteResourceProvider::new(service_grant);
                let service_resources =
                    myownmesh_core::ResourceProviderPort::new(service_provider.clone()).unwrap();
                let service_baseline = service_provider.in_use();
                assert_eq!(
                    service_baseline, scope_plan,
                    "only the actual process scope exists before Mesh"
                );
                for cancel_shutdown in [false, true] {
                    let root_plan =
                        myownmesh_services::ServiceCleanupOwner::planning_charge().unwrap();
                    let storage_plan =
                        myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                            cleanup_storage_claim().unwrap(),
                        )
                        .unwrap();
                    // Process+application scopes, one isolated embedded final reaper,
                    // one cleanup thread, and the actual root/storage plans.
                    let grant = cleanup_reaper_control_grant(2)
                        .checked_add(root_plan)
                        .and_then(|c| c.checked_add(storage_plan))
                        .unwrap();
                    let provider = myownmesh_core::FiniteResourceProvider::new(grant);
                    let port = myownmesh_core::ResourceProviderPort::new(provider.clone()).unwrap();
                    let scope =
                        myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(
                            &port,
                        )
                        .unwrap();
                    let reaper = std::sync::Mutex::new(None);
                    let sender = embedded_cleanup_thread_reaper_in(&scope, &reaper).unwrap();
                    let witness = std::sync::Arc::new(EmbeddedTaskWitness::new());
                    let runtime = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                        .unwrap();
                    let (was_live, live_service_use, pending_handoff, terminal) =
                        runtime.block_on(async {
                            let mesh =
                                myownmesh_core::Mesh::open_infrastructure_only_with_identity(
                                    myownmesh_core::MeshConfig::default(),
                                    std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
                                    service_resources.clone(),
                                )
                                .await
                                .unwrap();
                            let cleanup = EmbeddedCleanupCustodian::new(
                                scope
                                    .acquire(myownmesh_core::ResourceClaim::single(
                                        myownmesh_core::ResourceClass::WorkerOrTask,
                                        1,
                                    ))
                                    .unwrap(),
                                scope.clone(),
                                sender.clone(),
                                witness.clone(),
                            )
                            .unwrap();
                            let mut daemon = arm_daemon_cleanup(mesh, cleanup, witness.clone());
                            let mut config = myownmesh_core::ServicesConfig::default();
                            config.node.enabled = false;
                            config.stun.enabled = true;
                            config.stun.bind = "127.0.0.1".into();
                            config.stun.port = 0;
                            let started = daemon.service_manager.apply(config).await;
                            let live = started.as_ref().is_ok_and(|report| report.stun.running);
                            let live_service_use = service_provider.in_use();
                            let pending;
                            if cancel_shutdown {
                                let (release, wait) = tokio::sync::oneshot::channel::<()>();
                                daemon.control = Some(tokio::spawn(async move {
                                    let _ = wait.await;
                                    Ok(())
                                }));
                                let mut shutdown = Box::pin(daemon.shutdown());
                                pending = std::future::poll_fn(|cx| {
                                    std::task::Poll::Ready(
                                        std::future::Future::poll(shutdown.as_mut(), cx)
                                            .is_pending(),
                                    )
                                })
                                .await;
                                drop(shutdown); // actual public shutdown cancellation
                                let _ = release.send(()); // always release before checks
                            } else {
                                pending = true;
                                drop(daemon); // partially started, both root slots absent
                            }
                            let terminal =
                                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                                    while !witness.cleanup_thread_joined.load(Ordering::SeqCst) {
                                        tokio::task::yield_now().await;
                                    }
                                })
                                .await
                                .is_ok();
                            (live, live_service_use, pending, terminal)
                        });
                    drop(runtime);
                    drop(sender);
                    drop(reaper); // actual final embedded thread reaper join
                    drop(scope);
                    drop(port);
                    assert!(was_live, "the armed owner held an actual STUN listener");
                    assert_eq!(live_service_use, service_grant,
                "the actual private Mesh/STUN provider owns the exact ready service and scope plans");
                    assert!(
                        pending_handoff,
                        "shutdown suspends only after moving the held control owner"
                    );
                    assert!(
                        terminal,
                        "cleanup must complete within the original ten-second stage bound"
                    );
                    assert!(witness.cleanup_terminal.load(Ordering::SeqCst));
                    assert_eq!(witness.cleanup_terminal.result(), EmbeddedCleanupResult::Clean,
                "the aggregate result survives a dropped shutdown receiver; any service/owner failure refuses clean terminal");
                    assert!(witness.cleanup_thread_joined.load(Ordering::SeqCst));
                    assert_eq!(
                        provider.in_use(),
                        myownmesh_core::ResourceClaim::ZERO,
                        "all outside owner/storage/scope leases are released after observed joins"
                    );
                    assert_eq!(service_provider.in_use(), service_baseline,
                "actual STUN, Mesh and service ports release all but the installed process scope");
                }
                drop(service_resources);
                assert_eq!(service_provider.in_use(), scope_plan,
            "ProcessResourceRoot retains its installed provider: exact process-scope baseline, not fabricated ZERO");
            },
        );
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn transport_lab_ice_policy_is_explicit_and_fail_closed() {
        assert!(!transport_lab_relay_only(None).expect("absent selects normal ICE"));
        assert!(!transport_lab_relay_only(Some("all")).expect("all selects normal ICE"));
        assert!(transport_lab_relay_only(Some("relay")).expect("relay selects relay-only ICE"));
        assert!(matches!(
            transport_lab_relay_only(Some("host")),
            Err(EmbeddedStartError::TransportLabIcePolicy(value)) if value == "host"
        ));
    }

    // The connector-capable startup fixture below installs a connector policy,
    // so it spends from the one binary-wide budget `crate::test_resource_provider`
    // grants. It serializes on `crate::exclusive_connector_fixture` with every
    // other module that draws on the same pool. The infrastructure-only test
    // beside it installs no policy and takes no guard.

    fn connector_test_policy() -> myownmesh_core::WebRtcConnectorCapablePolicy {
        // Elastic real-time, which is the only shape there is: what this
        // fixture may do is what `crate::test_resource_provider` funds, and the
        // eleven local counts that used to be stated here bounded nothing the
        // provider was not already bounding.
        let webrtc = myownmesh_core::WebRtcConnectorProfile::new(
            myownmesh_core::ConnectorCallbackPolicy::elastic_realtime(),
        );
        myownmesh_core::WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc)
    }

    /// Initialize the process-lifetime cleanup-thread owner before taking a
    /// provider baseline. Its one `WorkerOrTask` lease is deliberately part of
    /// that baseline, not a hidden first-start delta attributed to a daemon.
    #[cfg(unix)]
    fn ensure_cleanup_thread_reaper_for_test() {
        let scope = crate::test_application_scope();
        embedded_cleanup_thread_reaper(&scope)
            .expect("the test provider funds the process cleanup-thread reaper");
    }

    fn cleanup_reaper_control_grant(worker_capacity: u64) -> myownmesh_core::ResourceClaim {
        myownmesh_core::ResourceClaim::try_from_entries([
            (
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                2_u64
                    .checked_add(worker_capacity)
                    .expect("the bounded cleanup reaper control grant is representable"),
            ),
            (myownmesh_core::ResourceClass::WorkerOrTask, worker_capacity),
        ])
        .expect("the cleanup reaper control grant is representable")
    }

    /// A transient provider refusal must not poison process-lifetime reaper
    /// initialization. The first exact provider funds its two scopes but no
    /// `WorkerOrTask`; a later provider funds exactly the process scope, local
    /// scope, and one reaper reservation and can therefore start and join the
    /// owner in the same process.
    #[test]
    fn cleanup_reaper_retries_after_transient_worker_refusal() {
        let refused_provider =
            myownmesh_core::FiniteResourceProvider::new(cleanup_reaper_control_grant(0));
        let refused_port = myownmesh_core::ResourceProviderPort::new(refused_provider)
            .expect("the refusal provider funds its process scope");
        let refused_scope =
            myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&refused_port)
                .expect("the refusal provider funds its local scope");
        let slot = std::sync::Mutex::new(None);
        let refusal = embedded_cleanup_thread_reaper_in(&refused_scope, &slot);
        assert!(
            refusal.is_err(),
            "the first provider refuses the reaper before a thread is spawned"
        );
        assert!(
            slot.lock()
                .expect("the isolated reaper slot is not poisoned")
                .is_none(),
            "a transient refusal must not publish an error or partial owner"
        );
        drop(refused_scope);
        drop(refused_port);

        let provider = myownmesh_core::FiniteResourceProvider::new(cleanup_reaper_control_grant(1));
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the retry provider funds its process scope");
        let scope = myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("the retry provider funds its local scope");
        let sender = embedded_cleanup_thread_reaper_in(&scope, &slot)
            .expect("the exact-capacity retry provider starts the reaper");
        assert_eq!(
            provider
                .in_use()
                .amount(myownmesh_core::ResourceClass::WorkerOrTask),
            1
        );

        let joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let thread_joined = std::sync::Arc::clone(&joined);
        let thread = std::thread::spawn(move || {
            thread_joined.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        sender
            .send(EmbeddedCleanupThreadBatch {
                thread,
                _mailbox: None,
                joined: std::sync::Arc::clone(&joined),
                joining: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            })
            .expect("the live retry reaper accepts one terminal join request");
        drop(sender);
        drop(slot);
        assert!(
            joined.load(std::sync::atomic::Ordering::SeqCst),
            "the successful retry owner observes its queued thread terminal"
        );
        drop(scope);
        drop(port);
        assert_eq!(provider.in_use(), myownmesh_core::ResourceClaim::ZERO);
    }

    /// Two abandoned daemons may hand off their cleanup roots while the
    /// process owner is still joining the first root.  The second synchronous
    /// Drop must return at that saturation boundary; the pre-established owner
    /// then joins both roots and releases its exact provider lease.
    #[test]
    fn cleanup_reaper_saturation_keeps_drop_nonblocking_and_joins_every_root() {
        fn spin_until(flag: &std::sync::atomic::AtomicBool) -> bool {
            for _ in 0..100_000 {
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return true;
                }
                std::thread::yield_now();
            }
            false
        }

        let provider = myownmesh_core::FiniteResourceProvider::new(cleanup_reaper_control_grant(1));
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the saturation provider funds its process scope");
        let scope = myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("the saturation provider funds its local scope");
        let slot = std::sync::Mutex::new(None);
        let sender = embedded_cleanup_thread_reaper_in(&scope, &slot)
            .expect("the pre-established owner is funded before either handoff");

        let first_release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_joining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first_release_thread = std::sync::Arc::clone(&first_release);
        let first_started_thread = std::sync::Arc::clone(&first_started);
        let first_thread = std::thread::spawn(move || {
            first_started_thread.store(true, std::sync::atomic::Ordering::SeqCst);
            while !first_release_thread.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::yield_now();
            }
        });
        assert!(
            spin_until(&first_started),
            "the first daemon cleanup root started"
        );
        sender
            .send(EmbeddedCleanupThreadBatch {
                thread: first_thread,
                _mailbox: None,
                joined: std::sync::Arc::clone(&first_joined),
                joining: std::sync::Arc::clone(&first_joining),
            })
            .expect("the first daemon cleanup root enters the process owner");
        assert!(
            spin_until(&first_joining),
            "the process owner is joining the first daemon root before saturation"
        );

        let second_release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_started = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_joined = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_joining = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second_release_thread = std::sync::Arc::clone(&second_release);
        let second_started_thread = std::sync::Arc::clone(&second_started);
        let second_thread = std::thread::spawn(move || {
            second_started_thread.store(true, std::sync::atomic::Ordering::SeqCst);
            while !second_release_thread.load(std::sync::atomic::Ordering::SeqCst) {
                std::thread::yield_now();
            }
        });
        assert!(
            spin_until(&second_started),
            "the second daemon cleanup root started"
        );

        let handoff_returned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handoff_returned_thread = std::sync::Arc::clone(&handoff_returned);
        let handoff_sender = sender.clone();
        let second_joined_thread = std::sync::Arc::clone(&second_joined);
        let second_joining_thread = std::sync::Arc::clone(&second_joining);
        let handoff = std::thread::spawn(move || {
            handoff_cleanup_thread(
                &handoff_sender,
                EmbeddedCleanupThreadBatch {
                    thread: second_thread,
                    _mailbox: None,
                    joined: second_joined_thread,
                    joining: second_joining_thread,
                },
            );
            handoff_returned_thread.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(
            spin_until(&handoff_returned),
            "a second synchronous Drop returns while the first root join is saturated"
        );

        first_release.store(true, std::sync::atomic::Ordering::SeqCst);
        second_release.store(true, std::sync::atomic::Ordering::SeqCst);
        handoff
            .join()
            .expect("the second Drop handoff returns cleanly");
        assert!(
            spin_until(&first_joined),
            "the first root terminal is observed exactly"
        );
        assert!(
            spin_until(&second_joining),
            "the queued second root reaches its owner"
        );
        assert!(
            spin_until(&second_joined),
            "the second root terminal is observed exactly"
        );

        drop(sender);
        drop(slot);
        drop(scope);
        drop(port);
        assert_eq!(provider.in_use(), myownmesh_core::ResourceClaim::ZERO);
    }

    /// Exercise the actual custodian Drop path with two daemon-shaped cleanup
    /// owners.  The first root deliberately keeps the reaper's join occupied;
    /// dropping the second custodian must still return without joining on this
    /// caller thread, and both cleanup leases must eventually be released.
    #[test]
    fn cleanup_custodian_drop_saturation_is_nonblocking_and_exact() {
        fn spin_until(flag: &std::sync::atomic::AtomicBool) -> bool {
            for _ in 0..100_000 {
                if flag.load(std::sync::atomic::Ordering::SeqCst) {
                    return true;
                }
                std::thread::yield_now();
            }
            false
        }

        let per_owner = myownmesh_services::ServiceCleanupOwner::planning_charge()
            .expect("service cleanup root plan")
            .checked_add(
                myownmesh_core::FiniteResourceProvider::reservation_planning_charge(
                    cleanup_storage_claim().expect("cleanup storage plan"),
                )
                .expect("normalized cleanup storage"),
            )
            .expect("complete added cleanup plan");
        let grant = cleanup_reaper_control_grant(3)
            .checked_add(
                per_owner
                    .checked_scale(2)
                    .expect("two concrete cleanup owners"),
            )
            .expect("saturation cohort grant");
        let provider = myownmesh_core::FiniteResourceProvider::new(grant);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the custodian saturation provider funds its process scope");
        let scope = myownmesh_core::LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("the custodian saturation provider funds its local scope");
        let slot = std::sync::Mutex::new(None);
        let sender = embedded_cleanup_thread_reaper_in(&scope, &slot)
            .expect("the process owner is established before daemon cleanup");
        let worker_claim =
            myownmesh_core::ResourceClaim::single(myownmesh_core::ResourceClass::WorkerOrTask, 1);

        let first_witness = std::sync::Arc::new(EmbeddedTaskWitness::new());
        let first_release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let first = EmbeddedCleanupCustodian::new(
            scope
                .acquire(worker_claim)
                .expect("the first daemon cleanup owner is funded"),
            scope.clone(),
            sender.clone(),
            std::sync::Arc::clone(&first_witness),
        )
        .expect("the first daemon cleanup owner is ready");
        let first_joining = std::sync::Arc::clone(&first.cleanup_thread_joining);
        first.request(EmbeddedCleanupRequest::Blocked {
            release: std::sync::Arc::clone(&first_release),
        });
        drop(first);
        assert!(
            spin_until(&first_joining),
            "the reaper is joining the first daemon cleanup root"
        );

        let second_witness = std::sync::Arc::new(EmbeddedTaskWitness::new());
        let second_release = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let second = EmbeddedCleanupCustodian::new(
            scope
                .acquire(worker_claim)
                .expect("the second daemon cleanup owner is funded"),
            scope.clone(),
            sender.clone(),
            std::sync::Arc::clone(&second_witness),
        )
        .expect("the second daemon cleanup owner is ready");
        let second_joining = std::sync::Arc::clone(&second.cleanup_thread_joining);
        second.request(EmbeddedCleanupRequest::Blocked {
            release: std::sync::Arc::clone(&second_release),
        });

        let handoff_returned = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let handoff_returned_thread = std::sync::Arc::clone(&handoff_returned);
        let handoff = std::thread::spawn(move || {
            drop(second);
            handoff_returned_thread.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        assert!(
            spin_until(&handoff_returned),
            "the second daemon Drop returns while the first root join is saturated"
        );

        first_release.store(true, std::sync::atomic::Ordering::SeqCst);
        second_release.store(true, std::sync::atomic::Ordering::SeqCst);
        handoff
            .join()
            .expect("the second daemon Drop handoff returns cleanly");
        assert!(
            spin_until(&first_witness.cleanup_thread_joined),
            "the first daemon cleanup thread is joined exactly once"
        );
        assert!(
            spin_until(&second_joining),
            "the queued second daemon root reaches the terminal owner"
        );
        assert!(
            spin_until(&second_witness.cleanup_thread_joined),
            "the second daemon cleanup thread is joined exactly once"
        );
        assert!(
            first_witness
                .cleanup_terminal
                .load(std::sync::atomic::Ordering::SeqCst)
                && second_witness
                    .cleanup_terminal
                    .load(std::sync::atomic::Ordering::SeqCst),
            "both daemon cleanup roots report terminal completion"
        );

        drop(sender);
        drop(slot);
        drop(scope);
        drop(port);
        assert_eq!(provider.in_use(), myownmesh_core::ResourceClaim::ZERO);
    }

    /// Cleanup runtime readiness is a startup gate: an injected construction
    /// failure must return before either root task or the control listener is
    /// created, and the reserved provider capacity must be returned.
    #[cfg(unix)]
    #[tokio::test]
    async fn embedded_cleanup_runtime_failure_leaves_no_startup_residue() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};

        let _fixture = crate::exclusive_connector_fixture().await;
        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes its process pressure");
        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            provider.clone(),
        )
        .await
        .expect("the test mesh opens before cleanup readiness");

        set_cleanup_runtime_failure_for_test(true);
        let result =
            start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                .await;
        set_cleanup_runtime_failure_for_test(false);
        match result {
            Err(EmbeddedStartError::CleanupCustody(error)) => {
                assert!(error.contains("injected cleanup runtime failure"));
            }
            Err(_) => panic!("injected readiness returned the wrong startup error"),
            Ok(_) => panic!("injected readiness unexpectedly started the daemon"),
        }

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "readiness failure occurs before the control listener/root tasks"
        );
        let after = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes post-failure pressure");
        assert_eq!(
            after, baseline,
            "readiness refusal returns the exact WorkerOrTask provider baseline"
        );
    }

    /// `shutdown` does not return before `control::serve` and the connections it
    /// accepted have ended.
    ///
    /// Dropping the spawn's `JoinHandle` would detach the task, leaving
    /// `shutdown` nothing to wait on: it would return while the control socket,
    /// its connection tasks and their registrations were all still up, and then
    /// tear down the services and networks those tasks were still dispatching
    /// against, telling an embedder the daemon was closed while it was not.
    ///
    /// The load-bearing observation is taken at the ordering boundary itself:
    /// the control task sets a witness only after `serve` returns, and shutdown
    /// snapshots that witness immediately before it starts service teardown.
    /// A detached task that happens to finish on the next await cannot make that
    /// earlier snapshot true.
    ///
    /// Two external consequences are asserted as companions, and neither is a
    /// duration:
    ///
    /// 1. the client's own socket reaches end of file, which happens when the
    ///    connection task that was serving it has ended;
    /// 2. and a fresh connect to the same path is refused, which can only be
    ///    true once `serve` has returned and taken its listener with it.
    ///
    /// The subscription is what makes the first claim non-vacuous. An idle
    /// connection might end for any number of reasons; an `events_subscribe`
    /// that has been acked is a connection parked in the stream loop, which is
    /// exactly the task `shutdown` has to wait for.
    ///
    /// Unix-only, for the reason the control-surface shutdown controls are: a
    /// socket at a path this control chooses. Elsewhere the name is
    /// process-wide and two controls in one binary would fight over it.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r2_daemon_embedded_shutdown_waits_for_its_control_surface() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
        use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};

        /// Long enough that a loaded machine will not trip it, short enough that
        /// a genuine hang is named. Nothing below asserts because of it.
        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);
        async fn guarded<F: std::future::Future>(what: &str, future: F) -> F::Output {
            match tokio::time::timeout(HANG_GUARD, future).await {
                Ok(value) => value,
                Err(_) => panic!("hang guard: {what}"),
            }
        }

        let temp = tempfile::tempdir().expect("temporary daemon state");
        // The parent is deliberately absent: production creates it with
        // owner-only permissions before binding.
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };

        // Parallel test binaries must not race over the process identity
        // anchor in the runner's home directory. Identity injection changes
        // only key storage; `start_with_mesh` below is the same embedded
        // daemon path whose control task and shutdown ordering this control
        // owns.
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        let stream = guarded("client connects", async {
            loop {
                // The listener binds inside the spawned control task, so the
                // first connect can lose the race with it. The guard is what
                // fails if it never appears at all.
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => return stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await;
        let (client_reader, mut client_writer) = stream.split();
        let mut client_reader = BufReader::new(client_reader);
        client_writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the client sends its subscribe");
        let mut ack = String::new();
        guarded(
            "the subscription is acked",
            client_reader.read_line(&mut ack),
        )
        .await
        .expect("the daemon answers the subscribe");
        assert!(
            ack.contains("\"subscribed\":true"),
            "non-vacuity: this connection is parked in the stream loop: {ack}"
        );

        guarded("embedded shutdown returns", daemon.shutdown())
            .await
            .expect("embedded daemon shutdown succeeds");

        // The claim, read from outside the daemon: this client's connection was
        // parked in the stream loop above, so a shutdown that returned while
        // `control::serve` was still up would leave it open. That it reads to
        // end is the ordering.
        let mut rest = Vec::new();
        guarded(
            "the client's connection ended",
            client_reader.read_to_end(&mut rest),
        )
        .await
        .expect("the client's half reads to end");

        // And the listener is gone with it.
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "serve returned, so its control socket no longer accepts connections"
        );
    }

    /// The synchronous backstop is distinct from graceful `shutdown`: a host
    /// that abandons the handle must at least latch cancellation and hand the
    /// root tasks to the pre-existing cleanup custodian before their join
    /// handles are dropped. The cloned supervisor makes the latch observable
    /// after the daemon itself is gone; the refused reconnect proves the
    /// control listener was not detached.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r7_embedded_drop_latches_and_drains_root_tasks() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon =
            start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                .await
                .expect("the daemon test grant starts an infrastructure-only daemon");
        let supervisor = daemon.supervisor().clone();
        let witness = std::sync::Arc::clone(&daemon._task_witness);
        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");

        let stream = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            loop {
                match LocalSocketStream::connect(name.clone()).await {
                    Ok(stream) => break stream,
                    Err(_) => tokio::task::yield_now().await,
                }
            }
        })
        .await
        .expect("the control listener starts and accepts a client");
        let (reader, mut writer) = stream.split();
        writer
            .write_all(b"{\"op\":\"events_subscribe\"}\n")
            .await
            .expect("the live control client sends subscribe");
        let mut reader = BufReader::new(reader);
        let mut ack = String::new();
        tokio::time::timeout(
            std::time::Duration::from_secs(10),
            reader.read_line(&mut ack),
        )
        .await
        .expect("the live control client receives an ack")
        .expect("the live control client can read its ack");
        assert!(ack.contains("\"subscribed\":true"));
        assert!(
            witness
                .control_started
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop control is non-vacuous: control task started"
        );
        assert!(
            witness
                .updater_started
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop control is non-vacuous: updater task started"
        );
        assert!(
            !witness
                .updater_gate_open
                .load(std::sync::atomic::Ordering::SeqCst)
                && !witness
                    .updater_terminal
                    .load(std::sync::atomic::Ordering::SeqCst),
            "drop control holds a live updater root before Drop"
        );
        drop(daemon);
        assert!(
            supervisor.shutdown_requested(),
            "drop must synchronously latch the daemon cancellation state"
        );
        tokio::time::timeout(std::time::Duration::from_secs(10), async {
            while !witness
                .control_terminal
                .load(std::sync::atomic::Ordering::SeqCst)
                || !witness
                    .updater_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
                || !witness
                    .cleanup_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
                || !witness
                    .cleanup_thread_joined
                    .load(std::sync::atomic::Ordering::SeqCst)
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("drop observes terminal roots and joins the cleanup custodian");
        assert!(
            witness
                .cleanup_thread_joined
                .load(std::sync::atomic::Ordering::SeqCst),
            "drop cleanup observes the custodian OS-thread join"
        );
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "drop must drain the live root control task rather than detach it"
        );
        drop(temp);
    }

    /// Drop is also safe when the caller destroys its runtime before dropping
    /// the daemon. The cleanup custodian owns the handoff on its own OS thread
    /// and runtime, so the canceled root join errors remain observable rather
    /// than being lost with the caller runtime.
    #[cfg(unix)]
    #[test]
    fn v4_r7_embedded_drop_survives_caller_runtime_destruction() {
        use std::sync::atomic::Ordering;

        let fixture_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the fixture runtime builds");
        let _fixture = fixture_runtime.block_on(crate::exclusive_connector_fixture());
        drop(fixture_runtime);
        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes its process pressure");

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the inner current-thread runtime builds");
        let startup_provider = provider.clone();
        let (daemon, witness, supervisor, temp) = runtime.block_on(async move {
            let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
            daemon_config.control_socket = Some(socket);
            let mut services = myownmesh_core::MeshConfig::default().services;
            services.node.enabled = false;
            let cfg = myownmesh_core::MeshConfig {
                auto_update: myownmesh_core::AutoUpdateConfig {
                    enabled: false,
                    ..Default::default()
                },
                daemon: daemon_config,
                services,
                ..Default::default()
            };
            let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
                cfg.clone(),
                std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
                startup_provider,
            )
            .await
            .expect("the inner runtime opens the infrastructure-only mesh");
            let daemon =
                start_with_mesh_for_drop_control(cfg, mesh, control::RealtimeAdvert::unsupported())
                    .await
                    .expect("the inner runtime starts the daemon");
            let witness = std::sync::Arc::clone(&daemon._task_witness);
            let supervisor = daemon.supervisor().clone();
            for _ in 0..4 {
                tokio::task::yield_now().await;
            }
            assert!(
                witness.updater_started.load(Ordering::SeqCst),
                "the runtime-destruction control starts the updater root"
            );
            assert!(
                !witness.updater_terminal.load(Ordering::SeqCst),
                "the updater remains live before the caller runtime is destroyed"
            );
            (daemon, witness, supervisor, temp)
        });

        // The daemon is deliberately dropped with no caller runtime alive.
        drop(runtime);
        assert!(
            !supervisor.shutdown_requested(),
            "runtime destruction alone does not submit daemon shutdown"
        );
        drop(daemon);
        assert!(
            supervisor.shutdown_requested(),
            "outside-runtime Drop latches the daemon cancellation state"
        );

        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the outside observer runtime builds");
        observer.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !witness
                    .cleanup_terminal
                    .load(std::sync::atomic::Ordering::SeqCst)
                    || !witness.cleanup_thread_joined.load(Ordering::SeqCst)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the independent custodian reaches terminal cleanup and is joined");
        });
        drop(observer);

        assert!(
            witness.cleanup_thread_joined.load(Ordering::SeqCst),
            "outside-runtime cleanup reports the OS-thread join"
        );
        assert!(
            witness.cleanup_root_join_errors.load(Ordering::SeqCst) > 0,
            "runtime destruction produces an observed root JoinError"
        );
        let join_errors = witness.cleanup_root_join_errors.load(Ordering::SeqCst);
        let panics = witness.cleanup_root_panics.load(Ordering::SeqCst);
        let cancellations = witness.cleanup_root_cancellations.load(Ordering::SeqCst);
        assert_eq!(
            join_errors,
            panics + cancellations,
            "every root JoinError is classified exactly once"
        );
        assert!(
            cancellations > 0,
            "caller-runtime destruction is observed as root cancellation"
        );

        let after = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes post-cleanup pressure");
        assert_eq!(
            after, baseline,
            "cleanup returns the exact WorkerOrTask provider baseline"
        );
        drop(temp);
    }

    /// A reset submitted **before** the host has a waiter still drains the whole
    /// daemon, and leaves the process hosting it running.
    ///
    /// The discriminating control for B2, and the ordering is the whole of it.
    /// The request used to be a broadcast send: `start_with_mesh` spawns the
    /// control socket and only *then* returns the handle a host could subscribe
    /// through, so a reset arriving in that window signalled nobody, latched the
    /// submitted flag so no later request could signal either, and left the host
    /// waiting forever on a daemon whose state had already been deleted. Here
    /// the request is submitted first — the way the reset arm submits it, once
    /// its response has reached a write disposition — and the waiter is
    /// constructed afterwards, by `run_until_shutdown`.
    ///
    /// `run_until_shutdown` rather than a direct `shutdown`, because a direct
    /// call drains whether or not anything ever observed the request, which is
    /// exactly the claim under test. What it reaches is the same single drain:
    /// the control surface awaited, then hosted services, then departures, then
    /// every joined network.
    ///
    /// The request and an embedder's own `shutdown` are one idempotent path, so
    /// a second submission submits nothing second — asserted rather than
    /// inferred.
    ///
    /// The host being alive is not asserted with a duration or a probe: this
    /// control body simply continues, and a process that had exited could not
    /// run it.
    ///
    /// Unix-only for the reason the control above is: the socket sits at a path
    /// this control chooses.
    #[cfg(unix)]
    #[tokio::test]
    async fn v4_r7_daemon_b2_a_reset_submitted_before_any_waiter_drains_the_whole_daemon() {
        use interprocess::local_socket::{tokio::prelude::*, GenericFilePath, ToFsName};

        const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(10);

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        daemon_config.control_socket = Some(socket.clone());
        let mut services = myownmesh_core::MeshConfig::default().services;
        services.node.enabled = false;
        let cfg = myownmesh_core::MeshConfig {
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            services,
            ..Default::default()
        };
        let mesh = myownmesh_core::Mesh::open_infrastructure_only_with_identity(
            cfg.clone(),
            std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
            crate::test_resource_provider(),
        )
        .await
        .expect("the test identity opens an infrastructure-only mesh");
        let daemon = start_with_mesh(cfg, mesh, control::RealtimeAdvert::unsupported())
            .await
            .expect("the daemon test grant starts an infrastructure-only daemon");

        assert!(
            !daemon.supervisor().shutdown_requested(),
            "non-vacuity: nothing has asked this runtime to stop yet"
        );
        // The reset arm's action, submitted once the response has reached its
        // write disposition — and before anything below waits on it.
        assert!(
            daemon.supervisor().request_shutdown(),
            "the reset submits the one request"
        );
        // And the embedder's own shutdown, on the same path, afterwards.
        assert!(
            !daemon.supervisor().request_shutdown(),
            "which a later caller does not submit a second time"
        );

        // The waiter is constructed here, strictly after both submissions. A
        // request that had been a notification would have nothing left to
        // deliver, and this would never return.
        match tokio::time::timeout(HANG_GUARD, daemon.run_until_shutdown()).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => panic!("daemon shutdown failed: {error}"),
            Err(_) => panic!("hang guard: a waiter built after the request resolves and drains"),
        }

        let name = socket
            .as_path()
            .to_fs_name::<GenericFilePath>()
            .expect("the control socket path is a valid fs name");
        assert!(
            LocalSocketStream::connect(name).await.is_err(),
            "the drain really ran: serve returned and took its listener with it"
        );
        // Reached, which is the whole of the host-process claim.
        drop(temp);
    }

    #[tokio::test]
    async fn infrastructure_start_requires_node_participation_disabled() {
        // A real port, so the refusal below is the node-participation check and
        // not a missing grant standing in for it.
        let result = start_infrastructure_only(
            myownmesh_core::MeshConfig::default(),
            crate::test_resource_provider(),
        )
        .await;
        assert!(matches!(
            result,
            Err(EmbeddedStartError::InfrastructureOnlyRequiresNodeDisabled)
        ));
    }

    /// Configured network startup is checked as a unit: an invalid entry is
    /// returned to the embedder before the control surface becomes live, and
    /// any earlier joined entry is drained through the same registry owner.
    #[tokio::test]
    async fn checked_network_startup_propagates_refusal_before_control_spawn() {
        let _fixture = crate::exclusive_connector_fixture().await;
        const CHILD_HOME: &str = "MYOWNMESH_EMBEDDED_NETWORK_REFUSAL_CHILD_HOME";
        const SELECTOR: &str =
            "embedded::tests::checked_network_startup_propagates_refusal_before_control_spawn";
        const COMPLETED: &[u8] = b"typed-network-refusal/no-listener passed\n";

        // The provider fixture lock does not serialize unrelated global-path
        // readers. Set the custody home only on an exact-selector child, never
        // in this test process's environment.
        let Some(child_home) = std::env::var_os(CHILD_HOME) else {
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    if !matches!(self.0.try_wait(), Ok(Some(_))) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
            }

            let temp = tempfile::tempdir().expect("temporary daemon custody home");
            // Stay inside the retained selector's 30-second process envelope,
            // reserving its final two seconds for exact-child kill/reap.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(28);
            let mut child = OwnedChild(
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args(["--exact", SELECTOR, "--nocapture", "--test-threads=1"])
                    .env(CHILD_HOME, temp.path())
                    .env("MYOWNMESH_HOME", temp.path())
                    .stdin(std::process::Stdio::null())
                    .spawn()
                    .expect("isolated exact-selector child"),
            );
            let status = loop {
                let status = child.0.try_wait().expect("observe exact child");
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "isolated startup child exceeded its absolute work deadline"
                );
                if let Some(status) = status {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            drop(child);
            assert!(status.success(), "isolated startup child failed: {status}");
            assert_eq!(
                std::fs::read(temp.path().join("completed")).expect("child exercised the selector"),
                COMPLETED,
                "child completed the exact network refusal and no-listener assertions"
            );
            return;
        };
        assert!(
            std::env::var_os("MYOWNMESH_HOME").as_ref() == Some(&child_home),
            "child marker must match the isolated custody home"
        );
        let child_home = std::path::PathBuf::from(child_home);
        let mut cfg = myownmesh_core::MeshConfig {
            identity_path: Some(child_home.join("identity.json")),
            daemon: myownmesh_core::config::DaemonConfig {
                control_socket: Some(child_home.join("daemon.sock")),
                ..Default::default()
            },
            ..Default::default()
        };
        let mut invalid =
            myownmesh_core::NetworkConfig::from_network_id("startup-control", "startup-network");
        invalid.network_id.clear();
        cfg.networks.push(invalid);

        let result = start_connector_capable(
            cfg,
            connector_test_policy(),
            control::RealtimeAdvert::unsupported(),
        )
        .await;
        match result {
            Err(EmbeddedStartError::NetworkStartup(error)) => {
                assert!(
                    error.contains("network id is empty"),
                    "typed refusal: {error}"
                );
            }
            Err(other) => panic!("startup returned the wrong typed error: {other}"),
            Ok(daemon) => {
                let cleanup = daemon.shutdown().await;
                panic!("invalid configured network unexpectedly started; shutdown: {cleanup:?}");
            }
        }
        assert!(
            !child_home.join("daemon.sock").exists(),
            "network startup refusal precedes control listener creation"
        );
        // Witness only the original exact refusal and no-listener oracles.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(child_home.join("completed"))
            .expect("new child refusal witness")
            .write_all(COMPLETED)
            .expect("write child refusal witness");
    }

    /// There is one connector-capable startup form, and it takes only the
    /// owner-supplied policy: a policy carrying no sidecar profile still
    /// produces a connector, so no second form is needed and none can install an
    /// authority the caller could not otherwise reach.
    #[tokio::test]
    async fn the_connector_capable_daemon_starts_from_the_owner_policy_alone() {
        let _fixture = crate::exclusive_connector_fixture().await;
        const CHILD_HOME: &str = "MYOWNMESH_EMBEDDED_POLICY_STARTUP_CHILD_HOME";
        const SELECTOR: &str =
            "embedded::tests::the_connector_capable_daemon_starts_from_the_owner_policy_alone";
        const COMPLETED: &[u8] = b"startup/report/shutdown passed\n";

        // The provider fixture lock does not serialize unrelated global-path
        // readers. Set the custody home only on an exact-selector child, never
        // in this test process's environment.
        let Some(child_home) = std::env::var_os(CHILD_HOME) else {
            struct OwnedChild(std::process::Child);
            impl Drop for OwnedChild {
                fn drop(&mut self) {
                    if !matches!(self.0.try_wait(), Ok(Some(_))) {
                        let _ = self.0.kill();
                        let _ = self.0.wait();
                    }
                }
            }

            let temp = tempfile::tempdir().expect("temporary daemon custody home");
            // Stay inside the retained selector's 30-second process envelope,
            // reserving its final two seconds for exact-child kill/reap.
            let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(28);
            let mut child = OwnedChild(
                std::process::Command::new(std::env::current_exe().expect("test executable"))
                    .args(["--exact", SELECTOR, "--nocapture", "--test-threads=1"])
                    .env(CHILD_HOME, temp.path())
                    .env("MYOWNMESH_HOME", temp.path())
                    .stdin(std::process::Stdio::null())
                    .spawn()
                    .expect("isolated exact-selector child"),
            );
            let status = loop {
                let status = child.0.try_wait().expect("observe exact child");
                assert!(
                    tokio::time::Instant::now() < deadline,
                    "isolated startup child exceeded its absolute work deadline"
                );
                if let Some(status) = status {
                    break status;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            drop(child);
            assert!(status.success(), "isolated startup child failed: {status}");
            assert_eq!(
                std::fs::read(temp.path().join("completed")).expect("child exercised the selector"),
                COMPLETED,
                "child completed the real startup, report and shutdown assertions"
            );
            return;
        };
        assert!(
            std::env::var_os("MYOWNMESH_HOME").as_ref() == Some(&child_home),
            "child marker must match the isolated custody home"
        );
        let child_home = std::path::PathBuf::from(child_home);
        let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
        // GenericFilePath requires the native pipe prefix on Windows. The
        // Unix private parent is created by the production owner-only adapter.
        #[cfg(windows)]
        let socket = std::path::PathBuf::from(format!(
            r"\\.\pipe\myownmesh-embedded-policy-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock after epoch")
                .as_nanos()
        ));
        #[cfg(not(windows))]
        let socket = child_home.join("private").join("daemon.sock");
        daemon_config.control_socket = Some(socket);
        let cfg = myownmesh_core::MeshConfig {
            identity_path: Some(child_home.join("identity.json")),
            auto_update: myownmesh_core::AutoUpdateConfig {
                enabled: false,
                ..Default::default()
            },
            daemon: daemon_config,
            ..Default::default()
        };

        let daemon = start_connector_capable(
            cfg,
            connector_test_policy(),
            control::RealtimeAdvert::unsupported(),
        )
        .await
        .expect("the connector-capable daemon starts from the policy alone");
        assert!(daemon.mesh().connector_resource_report().is_some());
        daemon
            .shutdown()
            .await
            .expect("connector-capable daemon shutdown succeeds");
        // A successful child with zero selected tests cannot satisfy this
        // freshly-created witness; write it only after awaited shutdown.
        use std::io::Write;
        std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(child_home.join("completed"))
            .expect("new child completion witness")
            .write_all(COMPLETED)
            .expect("write child completion witness");
    }

    /// A caller may destroy its current-thread runtime while the embedded
    /// daemon owns real service and network state. Drop must transfer both
    /// roots to the independent cleanup owner, join that owner thread, and
    /// return every service/registry/provider charge to the exact baseline.
    #[cfg(unix)]
    #[test]
    fn embedded_drop_with_live_service_and_registry_returns_exact_baseline() {
        use std::sync::atomic::Ordering;

        let fixture_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the fixture runtime builds");
        let _fixture = fixture_runtime.block_on(crate::exclusive_connector_fixture());
        drop(fixture_runtime);

        let provider = crate::test_resource_provider();
        ensure_cleanup_thread_reaper_for_test();
        let process_scope = provider.process_scope();
        let baseline_worker = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::WorkerOrTask,
            )
            .expect("the test provider exposes worker pressure")
            .in_use;
        let baseline_opaque = provider
            .pressure(
                &process_scope,
                myownmesh_core::ResourceAuthorityClass::Admitted,
                myownmesh_core::ResourceClass::OpaqueDependencyResidual,
            )
            .expect("the test provider exposes opaque pressure")
            .in_use;

        let temp = tempfile::tempdir().expect("temporary daemon state");
        let socket = temp.path().join("private").join("daemon.sock");
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the inner current-thread runtime builds");
        let _startup_provider = provider.clone();
        let (daemon, witness, supervisor, registry, services, temp) =
            runtime.block_on(async move {
                let mut daemon_config = myownmesh_core::MeshConfig::default().daemon;
                daemon_config.control_socket = Some(socket);
                let mut service_config = myownmesh_core::MeshConfig::default().services;
                service_config.stun.enabled = true;
                service_config.stun.bind = "127.0.0.1".into();
                service_config.stun.port = 0;

                let mut network = myownmesh_core::config::NetworkConfig::from_network_id(
                    "embedded-live-registry",
                    "embedded-live-registry",
                );
                network.signaling.strategy = "none".into();
                network.signaling.mdns = true;
                network.stun_servers.clear();
                network.turn_servers.clear();
                let cfg = myownmesh_core::MeshConfig {
                    auto_update: myownmesh_core::AutoUpdateConfig {
                        enabled: false,
                        ..Default::default()
                    },
                    daemon: daemon_config,
                    services: service_config,
                    networks: vec![network],
                    ..Default::default()
                };
                let mesh = myownmesh_core::Mesh::open_connector_capable_with_identity(
                    cfg.clone(),
                    std::sync::Arc::new(myownmesh_core::Identity::ephemeral()),
                    connector_test_policy(),
                )
                .await
                .expect("the inner runtime opens the connector-capable mesh");
                let daemon = start_with_mesh_for_drop_control(
                    cfg,
                    mesh,
                    control::RealtimeAdvert::unsupported(),
                )
                .await
                .expect("the inner runtime starts the live daemon");
                let status = daemon.service_manager.status().await;
                assert!(
                    status.stun.running,
                    "the live STUN service is actually running"
                );
                assert_eq!(
                    daemon.registry.joined_count(),
                    1,
                    "the registry owns one live network"
                );
                let witness = std::sync::Arc::clone(&daemon._task_witness);
                let supervisor = daemon.supervisor().clone();
                let registry = std::sync::Arc::clone(&daemon.registry);
                let services = std::sync::Arc::clone(&daemon.service_manager);
                (daemon, witness, supervisor, registry, services, temp)
            });

        drop(runtime);
        assert!(!supervisor.shutdown_requested());
        drop(daemon);
        assert!(supervisor.shutdown_requested());

        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("the outside observer runtime builds");
        observer.block_on(async {
            tokio::time::timeout(std::time::Duration::from_secs(10), async {
                while !witness.cleanup_terminal.load(Ordering::SeqCst)
                    || !witness.cleanup_thread_joined.load(Ordering::SeqCst)
                {
                    tokio::task::yield_now().await;
                }
            })
            .await
            .expect("the independent custodian joins after cleanup");
            assert_eq!(registry.joined_count(), 0, "Drop drains the live registry");
            assert!(
                !services.status().await.stun.running,
                "Drop drains the live STUN service"
            );
        });
        drop(observer);

        // These observations are Port owners. Their queue backing is retained
        // after worker join until the final observer is actually released.
        drop(services);
        drop(registry);
        assert_eq!(
            provider
                .pressure(
                    &process_scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    myownmesh_core::ResourceClass::WorkerOrTask,
                )
                .expect("post-cleanup worker pressure")
                .in_use,
            baseline_worker,
        );
        assert_eq!(
            provider
                .pressure(
                    &process_scope,
                    myownmesh_core::ResourceAuthorityClass::Admitted,
                    myownmesh_core::ResourceClass::OpaqueDependencyResidual,
                )
                .expect("post-cleanup opaque pressure")
                .in_use,
            baseline_opaque,
        );
        drop(temp);
    }
}
