//! Exact native WebRTC cleanup ownership and conservative claim retention.

use super::*;
use std::sync::atomic::AtomicUsize;
use std::task::{Context, Poll, Wake, Waker};
use std::thread;
#[cfg(any(test, feature = "transport-lab"))]
use tokio::sync::mpsc;

/// A bounded handoff for task handles that must be joined after their owning
/// object is dropped.  The batch is moved as one message so a drop never
/// publishes a prefix and loses the remainder when the receiver is full.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) type TaskReaperSender = mpsc::Sender<Vec<tokio::task::JoinHandle<()>>>;

#[cfg(test)]
static TEST_REAPED_TRANSPORT_TASKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_PANICKED_TRANSPORT_TASKS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
#[cfg(test)]
static TEST_TRANSPORT_PANIC_WAKE: std::sync::OnceLock<tokio::sync::Notify> =
    std::sync::OnceLock::new();
#[cfg(test)]
static TEST_TRANSPORT_REAP_WAKE: std::sync::OnceLock<tokio::sync::Notify> =
    std::sync::OnceLock::new();
#[cfg(test)]
static TEST_TRANSPORT_REAP_CONDVAR: std::sync::OnceLock<(
    std::sync::Mutex<()>,
    std::sync::Condvar,
)> = std::sync::OnceLock::new();

fn record_join_result(result: std::result::Result<(), tokio::task::JoinError>) {
    if let Err(error) = result {
        if !error.is_cancelled() {
            #[cfg(test)]
            TEST_PANICKED_TRANSPORT_TASKS.fetch_add(1, Ordering::AcqRel);
            #[cfg(test)]
            if let Some(wake) = TEST_TRANSPORT_PANIC_WAKE.get() {
                wake.notify_waiters();
            }
            warn!("WebRTC transport task did not join normally: {error}");
        }
    }
    #[cfg(test)]
    {
        TEST_REAPED_TRANSPORT_TASKS.fetch_add(1, Ordering::AcqRel);
        if let Some(wake) = TEST_TRANSPORT_REAP_WAKE.get() {
            wake.notify_waiters();
        }
        if let Some((lock, wake)) = TEST_TRANSPORT_REAP_CONDVAR.get() {
            let _guard = lock
                .lock()
                .expect("transport reaper witness lock remains live");
            wake.notify_all();
        }
    }
}

enum LateTransportCommand {
    Batch(Vec<tokio::task::JoinHandle<()>>),
}

/// A single, pre-created terminal owner for tasks admitted after the normal
/// connector cleanup owner has sealed.  The bounded synchronous channel is
/// deliberately capacity one: a late submission is moved as one batch, never
/// as a prefix, and the worker owns the only retained OS join handle.
pub(super) struct LateTransportCustodian {
    sender: SyncMutex<Option<std::sync::mpsc::SyncSender<LateTransportCommand>>>,
    worker: SyncMutex<Option<std::thread::JoinHandle<()>>>,
    terminal: Arc<LateTransportTerminalWitness>,
}

pub(super) struct LateTransportTerminalWitness {
    closed: AtomicBool,
    reaped: AtomicUsize,
    panicked: AtomicUsize,
}

impl LateTransportTerminalWitness {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            closed: AtomicBool::new(false),
            reaped: AtomicUsize::new(0),
            panicked: AtomicUsize::new(0),
        })
    }
}

impl LateTransportCustodian {
    pub(super) fn new(funding: crate::resource::ResourceLease) -> std::io::Result<Arc<Self>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let terminal = LateTransportTerminalWitness::new();
        let worker_terminal = Arc::clone(&terminal);
        let worker = std::thread::Builder::new()
            .name("myownmesh-webrtc-late-terminal".to_string())
            .spawn(move || {
                let _funding = funding;
                while let Ok(command) = receiver.recv() {
                    match command {
                        LateTransportCommand::Batch(tasks) => {
                            for task in tasks {
                                let result = join_task_without_runtime(task);
                                let panicked =
                                    result.as_ref().is_err_and(|error| !error.is_cancelled());
                                record_join_result(result);
                                if panicked {
                                    worker_terminal.panicked.fetch_add(1, Ordering::AcqRel);
                                }
                                worker_terminal.reaped.fetch_add(1, Ordering::AcqRel);
                            }
                        }
                    }
                }
                worker_terminal.closed.store(true, Ordering::Release);
            })?;
        Ok(Arc::new(Self {
            sender: SyncMutex::new(Some(sender)),
            worker: SyncMutex::new(Some(worker)),
            terminal,
        }))
    }

    #[cfg(any(test, feature = "transport-lab"))]
    fn new_unfunded() -> std::io::Result<Arc<Self>> {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let terminal = LateTransportTerminalWitness::new();
        let worker_terminal = Arc::clone(&terminal);
        let worker = std::thread::Builder::new()
            .name("myownmesh-webrtc-test-late-terminal".to_string())
            .spawn(move || {
                while let Ok(command) = receiver.recv() {
                    match command {
                        LateTransportCommand::Batch(tasks) => {
                            for task in tasks {
                                let result = join_task_without_runtime(task);
                                let panicked =
                                    result.as_ref().is_err_and(|error| !error.is_cancelled());
                                record_join_result(result);
                                if panicked {
                                    worker_terminal.panicked.fetch_add(1, Ordering::AcqRel);
                                }
                                worker_terminal.reaped.fetch_add(1, Ordering::AcqRel);
                            }
                        }
                    }
                }
                worker_terminal.closed.store(true, Ordering::Release);
            })?;
        Ok(Arc::new(Self {
            sender: SyncMutex::new(Some(sender)),
            worker: SyncMutex::new(Some(worker)),
            terminal,
        }))
    }

    pub(super) fn submit(
        &self,
        tasks: Vec<tokio::task::JoinHandle<()>>,
    ) -> std::result::Result<(), Vec<tokio::task::JoinHandle<()>>> {
        if tasks.is_empty() {
            return Ok(());
        }
        let sender = self.sender.lock();
        let Some(sender_ref) = sender.as_ref() else {
            return Err(tasks);
        };
        // A full channel is backpressured only until the already-admitted
        // batch is consumed. Sending the enum moves the complete batch, so no
        // task can be detached between the full and retry observations.
        match sender_ref.try_send(LateTransportCommand::Batch(tasks)) {
            Ok(()) => Ok(()),
            Err(std::sync::mpsc::TrySendError::Full(command)) => match sender_ref.send(command) {
                Ok(()) => Ok(()),
                Err(std::sync::mpsc::SendError(LateTransportCommand::Batch(tasks))) => Err(tasks),
            },
            Err(std::sync::mpsc::TrySendError::Disconnected(LateTransportCommand::Batch(
                tasks,
            ))) => Err(tasks),
        }
    }

    pub(super) fn close_and_join(&self) -> bool {
        self.sender.lock().take();
        let mut worker_slot = self.worker.lock();
        if worker_slot
            .as_ref()
            .is_some_and(|worker| worker.thread().id() == std::thread::current().id())
        {
            return false;
        }
        let Some(worker) = worker_slot.take() else {
            return self.terminal.closed.load(Ordering::Acquire);
        };
        worker.join().is_ok() && self.terminal.closed.load(Ordering::Acquire)
    }

    pub(super) fn close_sender(&self) {
        self.sender.lock().take();
    }
}

impl Drop for LateTransportCustodian {
    fn drop(&mut self) {
        self.sender.get_mut().take();
        // The exact task batch has already been transferred before this owner
        // can drop. Production closes and joins this worker from the cleanup
        // future; Drop only closes its bounded command stream and never joins
        // synchronously from an arbitrary Tokio runtime.
    }
}

pub(super) async fn join_task_batch(tasks: Vec<tokio::task::JoinHandle<()>>) {
    for task in tasks {
        record_join_result(task.await);
    }
}

#[cfg(any(test, feature = "transport-lab"))]
fn spawn_task_reaper() -> (TaskReaperSender, tokio::task::JoinHandle<()>) {
    let (sender, mut receiver) = mpsc::channel(1);
    let task = tokio::spawn(async move {
        while let Some(tasks) = receiver.recv().await {
            join_task_batch(tasks).await;
        }
    });
    (sender, task)
}

/// Submit a batch to the bounded runtime reaper.  The fallback retains the
/// exact handles when the queue is full or its owner is already closing. The
/// fallback uses the connector's pre-created terminal custodian, and returns
/// any rejected batch by value so its handles remain observable.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) fn submit_task_batch(
    reaper: &TaskReaperSender,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) {
    if tasks.is_empty() {
        return;
    }
    let tasks = match reaper.try_send(tasks) {
        Ok(()) => return,
        Err(mpsc::error::TrySendError::Full(tasks))
        | Err(mpsc::error::TrySendError::Closed(tasks)) => tasks,
    };
    let custodian = LateTransportCustodian::new_unfunded()
        .expect("fallback terminal custodian worker remains constructible");
    if let Err(tasks) = submit_task_batch_fallback(&custodian, tasks) {
        for task in tasks {
            record_join_result(join_task_without_runtime(task));
        }
    }
    let _ = custodian.close_and_join();
}

#[cfg(any(test, feature = "transport-lab"))]
fn submit_task_batch_fallback(
    custodian: &LateTransportCustodian,
    tasks: Vec<tokio::task::JoinHandle<()>>,
) -> std::result::Result<(), Vec<tokio::task::JoinHandle<()>>> {
    if tasks.is_empty() {
        return Ok(());
    }
    custodian.submit(tasks)
}

struct ThreadUnparker(thread::Thread);

impl Wake for ThreadUnparker {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

fn join_task_without_runtime(
    mut task: tokio::task::JoinHandle<()>,
) -> std::result::Result<(), tokio::task::JoinError> {
    let waker = Waker::from(Arc::new(ThreadUnparker(thread::current())));
    let mut context = Context::from_waker(&waker);
    let mut task = std::pin::Pin::new(&mut task);
    loop {
        match std::future::Future::poll(task.as_mut(), &mut context) {
            Poll::Ready(result) => return result,
            Poll::Pending => thread::park(),
        }
    }
}

/// Observe a task that was submitted after its normal close owner completed.
/// This is an invariant violation, but dropping the handle would make it a
/// detached task; the fallback keeps terminal observation exact even when the
/// caller is outside the originating runtime.
#[cfg(test)]
fn observe_late_transport_task(
    task: tokio::task::JoinHandle<()>,
) -> Option<Arc<LateTransportCustodian>> {
    let Ok(custodian) = LateTransportCustodian::new_unfunded() else {
        warn!("late WebRTC test terminal custodian could not be created");
        return None;
    };
    if let Err(tasks) = submit_task_batch_fallback(&custodian, vec![task]) {
        for task in tasks {
            record_join_result(join_task_without_runtime(task));
        }
    }
    Some(custodian)
}

/// Runtime-independent custody for the raw test/transport-lab constructor.
///
/// The raw constructor intentionally has no production connector reservation,
/// but it still cannot hand a native peer to a construction guard that has no
/// owner.  This custodian is created before the dependency constructor runs;
/// its dedicated thread owns the close runtime and observes the one close
/// result even when the caller runtime is being torn down.  It is never a
/// best-effort fallback: thread/channel creation failure is returned before
/// native construction starts, and a failed handoff retains the peer and
/// reports an error through the waiter.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) struct PeerConstructionCloseCustodian {
    commands: std::sync::mpsc::SyncSender<PeerConstructionCloseCommand>,
    worker: SyncMutex<Option<std::thread::JoinHandle<()>>>,
    native: SyncMutex<Option<Arc<RTCPeerConnection>>>,
    completion: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
    started: std::sync::atomic::AtomicBool,
}

#[cfg(any(test, feature = "transport-lab"))]
enum PeerConstructionCloseCommand {
    Close {
        native: Arc<RTCPeerConnection>,
        completion: tokio::sync::watch::Sender<Option<std::result::Result<(), String>>>,
    },
    Shutdown,
}

#[cfg(any(test, feature = "transport-lab"))]
impl PeerConstructionCloseCustodian {
    pub(super) fn new() -> std::io::Result<Arc<Self>> {
        let (commands, receiver) = std::sync::mpsc::sync_channel(1);
        let (completion, _completion_receiver) = tokio::sync::watch::channel(None);
        let worker_completion = completion.clone();
        let worker = std::thread::Builder::new()
            .name("myownmesh-webrtc-lab-close".to_string())
            .spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build();
                let Ok(runtime) = runtime else {
                    let Ok(command) = receiver.recv() else {
                        return;
                    };
                    match command {
                        PeerConstructionCloseCommand::Close { completion, .. } => {
                            completion.send_replace(Some(Err(
                                "lab native close runtime could not be created".to_string(),
                            )));
                        }
                        PeerConstructionCloseCommand::Shutdown => {}
                    }
                    return;
                };
                let Ok(command) = receiver.recv() else {
                    return;
                };
                match command {
                    PeerConstructionCloseCommand::Close { native, completion } => {
                        let result = runtime
                            .block_on(native.close())
                            .map_err(|error| format!("native peer close: {error}"));
                        completion.send_replace(Some(result));
                    }
                    PeerConstructionCloseCommand::Shutdown => {}
                }
            })?;
        Ok(Arc::new(Self {
            commands,
            worker: SyncMutex::new(Some(worker)),
            native: SyncMutex::new(None),
            completion: worker_completion,
            started: std::sync::atomic::AtomicBool::new(false),
        }))
    }

    pub(super) fn attach_native(&self, native: Arc<RTCPeerConnection>) -> bool {
        if self.started.load(Ordering::Acquire) {
            return false;
        }
        let mut current = self.native.lock();
        if self.started.load(Ordering::Acquire) || current.is_some() {
            return false;
        }
        *current = Some(native);
        true
    }

    pub(super) fn start(&self) {
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        let Some(native) = self.native.lock().take() else {
            self.completion.send_replace(Some(Err(
                "lab native close started without an attached peer".to_string(),
            )));
            let _ = self.commands.send(PeerConstructionCloseCommand::Shutdown);
            return;
        };
        let command = PeerConstructionCloseCommand::Close {
            native,
            completion: self.completion.clone(),
        };
        if let Err(std::sync::mpsc::SendError(PeerConstructionCloseCommand::Close {
            native,
            completion,
        })) = self.commands.send(command)
        {
            *self.native.lock() = Some(native);
            completion.send_replace(Some(Err(
                "lab native close worker stopped before custody handoff".to_string(),
            )));
        }
    }

    pub(super) async fn wait(&self) -> Result<()> {
        let mut completion = self.completion.subscribe();
        loop {
            if let Some(result) = completion.borrow().clone() {
                return result.map_err(Error::Transport);
            }
            if completion.changed().await.is_err() {
                return Err(Error::Transport(
                    "lab native close worker stopped without a terminal result".to_string(),
                ));
            }
        }
    }
}

#[cfg(any(test, feature = "transport-lab"))]
impl Drop for PeerConstructionCloseCustodian {
    fn drop(&mut self) {
        if !self.started.load(Ordering::Acquire) {
            self.start();
        }
        if let Some(worker) = self.worker.get_mut().take() {
            if worker.join().is_err() {
                warn!("lab native close worker panicked before join");
            }
        }
    }
}

/// The task supervisor for one connector's transport-owned worker tasks.
///
/// Its channel is deliberately capacity one: the task set itself is bounded
/// by the connector's leased negotiated-track records, while the reaper only
/// needs one exact moved batch at a time.  Closing the sender lets the reaper
/// finish all accepted batches and then terminate.
#[cfg(any(test, feature = "transport-lab"))]
pub(super) struct TaskReaper {
    sender: Option<TaskReaperSender>,
    task: Option<tokio::task::JoinHandle<()>>,
    fallback_custodian: Arc<LateTransportCustodian>,
}

#[cfg(any(test, feature = "transport-lab"))]
impl TaskReaper {
    pub(super) fn new() -> Self {
        tokio::runtime::Handle::try_current()
            .expect("raw transport task custody requires an active Tokio runtime");
        let (sender, task) = spawn_task_reaper();
        Self {
            sender: Some(sender),
            task: Some(task),
            fallback_custodian: LateTransportCustodian::new_unfunded()
                .expect("late custodian worker remains constructible"),
        }
    }

    pub(super) fn sender(&self) -> Option<&TaskReaperSender> {
        self.sender.as_ref()
    }

    pub(super) async fn wait(mut self) {
        self.sender.take();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
        assert!(self.fallback_custodian.close_and_join());
    }
}

#[cfg(any(test, feature = "transport-lab"))]
impl Drop for TaskReaper {
    fn drop(&mut self) {
        // Dropping the sender is the reaper's terminal signal.  Its own task
        // remains runtime-owned until all accepted batches have been joined;
        // callers never lose a child handle merely because this supervisor
        // value is being dropped.
        self.sender.take();
        if let Some(task) = self.task.take() {
            if let Err(tasks) = self.fallback_custodian.submit(vec![task]) {
                for task in tasks {
                    record_join_result(join_task_without_runtime(task));
                }
            }
        }
    }
}

#[derive(Clone, Debug)]
pub(super) enum ConnectorCloseStatus {
    Open,
    Closing,
    Closed,
    Failed(String),
}

enum ConnectedClaimRetention {
    Empty,
    One(Box<crate::connector::ConnectedChannelCapability>),
    Multiple(Vec<crate::connector::ConnectedChannelCapability>),
}

/// The WebRTC close owner is the retention behind a generic channel handoff.
///
/// The generic handoff cannot know how to hold a claim through native close;
/// this impl is the one narrow bridge that lets it delegate to the exact owner
/// that does. It adds no behaviour of its own.
impl crate::connector::ConnectedChannelRetention for ConnectorCloseOwner {
    fn retain_connected_claim(
        self: Arc<Self>,
        capability: crate::connector::ConnectedChannelCapability,
    ) {
        ConnectorCloseOwner::retain_connected_claim(&self, capability);
    }
}

impl ConnectedClaimRetention {
    fn release_after_cleanup_success(&mut self) {
        match self {
            Self::Empty => {}
            Self::One(capability) => capability.release_after_cleanup_success(),
            Self::Multiple(capabilities) => {
                for capability in capabilities {
                    capability.release_after_cleanup_success();
                }
            }
        }
    }

    fn retain_after_cleanup_failure(&mut self) {
        match self {
            Self::Empty => {}
            Self::One(capability) => capability.retain_after_cleanup_failure(),
            Self::Multiple(capabilities) => {
                for capability in capabilities {
                    capability.retain_after_cleanup_failure();
                }
            }
        }
    }
}

pub(super) type NativeCloseFuture<'a> = Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Owner-private close boundary for the native connector allocation.
/// Production wraps the existing webrtc-rs peer connection. Tests supply a
/// deterministic close result without allocating a socket-bearing peer.
pub(super) trait NativeConnectorClosePort: Send + Sync {
    fn close(&self) -> NativeCloseFuture<'_>;
}

pub(super) struct WebRtcNativeClosePort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

impl NativeConnectorClosePort for WebRtcNativeClosePort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))
        })
    }
}

#[cfg(test)]
pub(super) struct WebRtcNativeCloseErrorPort {
    pub(super) peer: Arc<RTCPeerConnection>,
}

#[cfg(test)]
impl NativeConnectorClosePort for WebRtcNativeCloseErrorPort {
    fn close(&self) -> NativeCloseFuture<'_> {
        Box::pin(async {
            self.peer
                .close()
                .await
                .map_err(|error| Error::Transport(format!("close: {error}")))?;
            Err(Error::Transport(
                "injected native close failure after physical close".to_string(),
            ))
        })
    }
}

/// A deterministic hold point at the one native close. **Controls only.**
///
/// The refusal path this exists for is asynchronous by construction: the engine
/// arm returns as soon as it has started the close, and the actual native close
/// runs on the cleanup executor. A control that wants to state "the claim is
/// still retained while the close is in flight" therefore has no moment it can
/// name — by the time it looks, the close has usually finished and released.
///
/// So the gate names that moment. It is installed before the arm runs, it
/// counts every entry into the native close, it publishes that entry so a
/// control can await it without sleeping, and it parks the close until the
/// control opens it. Nothing here can *cause* a close: it can only hold one that
/// production already started, which is why an armed connector still proves the
/// production ordering rather than a fixture's.
///
/// The failure injection is deliberately applied *after* the physical close has
/// run, so the failure twin exercises the real native close and then reports the
/// failure the owner is supposed to be conservative about. A gate that skipped
/// the close would prove retention over a connector that was never closed.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct NativeCloseGate {
    /// How many times the native close has reached this gate. A `watch` rather
    /// than a counter so a control can await the first entry deterministically.
    entries: watch::Sender<usize>,
    /// The permit. Closes park until this is `true`.
    open: watch::Sender<bool>,
    /// Whether to report a failure for a close that physically ran.
    inject_failure: AtomicBool,
}

#[cfg(all(test, feature = "transport-lab"))]
impl NativeCloseGate {
    fn new() -> Arc<Self> {
        let (entries, _entries_receiver) = watch::channel(0usize);
        let (open, _open_receiver) = watch::channel(false);
        Arc::new(Self {
            entries,
            open,
            inject_failure: AtomicBool::new(false),
        })
    }

    /// Record this entry, then park until the control opens the gate.
    ///
    /// The count is published before parking, so a control that observes the
    /// entry is observing a close that has genuinely reached the native
    /// boundary rather than one that merely submitted.
    async fn hold(&self) {
        self.entries.send_modify(|count| *count += 1);
        let mut open = self.open.subscribe();
        loop {
            // The borrow is released before the await: holding a `watch` guard
            // across a suspension point would block every other sender.
            if *open.borrow() {
                return;
            }
            if open.changed().await.is_err() {
                // The handle was dropped with no receiver left to notify. The
                // handle's own `Drop` opens the gate for exactly this reason,
                // so proceeding is the safe reading: never wedge the executor.
                return;
            }
        }
    }

    /// What this gate reports about a close that has already run successfully.
    ///
    /// Consulted only on the dependency's own success, so an armed gate can add
    /// a failure but can never mask one.
    fn observe_native_close(&self) -> Result<()> {
        if self.inject_failure.load(Ordering::Acquire) {
            return Err(Error::Transport(
                "injected native close failure observed after the physical close".to_string(),
            ));
        }
        Ok(())
    }
}

/// A control's handle on one connector's native close gate. **Controls only.**
///
/// Held by the control for as long as it wants the hold point to exist. Its
/// `Drop` opens the gate unconditionally: a control that panics an assertion
/// mid-hold must not leave a cleanup task parked forever on the shared
/// executor, because that would turn one failing control into a wedged suite.
#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct NativeCloseGateHandle {
    gate: Arc<NativeCloseGate>,
}

#[cfg(all(test, feature = "transport-lab"))]
impl NativeCloseGateHandle {
    /// How many native closes have reached the gate. The load-bearing
    /// observation: the refusal must start exactly one.
    pub(crate) fn entries(&self) -> usize {
        *self.gate.entries.borrow()
    }

    /// Park until at least one native close has reached the gate.
    ///
    /// No sleep and no retry loop: this is a `watch` change notification, so it
    /// resolves on the entry itself. Callers bound it with a deadline so a
    /// close that never arrives fails the control rather than hanging it.
    pub(crate) async fn wait_for_entry(&self) {
        let mut entries = self.gate.entries.subscribe();
        loop {
            if *entries.borrow() > 0 {
                return;
            }
            if entries.changed().await.is_err() {
                return;
            }
        }
    }

    /// Report a failure for the close that runs, *after* it has run.
    pub(crate) fn inject_close_failure(&self) {
        self.gate.inject_failure.store(true, Ordering::Release);
    }

    /// Let the held close proceed. Idempotent; `Drop` does the same.
    pub(crate) fn open(&self) {
        self.gate.open.send_replace(true);
    }
}

#[cfg(all(test, feature = "transport-lab"))]
impl Drop for NativeCloseGateHandle {
    fn drop(&mut self) {
        self.gate.open.send_replace(true);
    }
}

/// Single cleanup owner for one native peer connection.
pub(super) struct ConnectorCloseOwner {
    pub(super) ownership: ConnectorOwnership,
    late_transport_custodian: Arc<LateTransportCustodian>,
    resource_owner: SyncMutex<Option<MeshConnectorResourceScope>>,
    cleanup_capability: SyncMutex<Option<crate::runtime::attempt::ConnectorCleanupCapability>>,
    /// The transport object observation ends when native cleanup succeeds,
    /// independently of any worker `Arc` retained by a caller after close.
    transport_observation: SyncMutex<Option<ObservationLease>>,
    native: SyncMutex<Option<Arc<dyn NativeConnectorClosePort>>>,
    remote_candidates: SyncMutex<Option<Arc<SyncMutex<RemoteCandidateState>>>>,
    realtime_flows: SyncMutex<Option<Arc<RealtimeFlowRegistry>>>,
    native_allocation_started: AtomicBool,
    started: AtomicBool,
    cleanup_submitted: AtomicBool,
    cleanup_complete: AtomicBool,
    status: watch::Sender<ConnectorCloseStatus>,
    status_transition: SyncMutex<()>,
    connected_claims: SyncMutex<ConnectedClaimRetention>,
    remote_description_resources:
        SyncMutex<std::collections::LinkedList<Arc<RemoteDescriptionResourceOwner>>>,
    /// Connector-owned observers for transport tasks whose native work must
    /// finish before this close owner reports terminal status to its caller.
    transport_tasks: SyncMutex<Vec<tokio::task::JoinHandle<()>>>,
    /// Set after the operation fence has drained and all task-bearing realtime
    /// records have been extracted. The cleanup future waits for this fence
    /// before its final task drain; late submissions are still retained until
    /// that drain, never silently dropped.
    transport_tasks_sealed: AtomicBool,
    transport_tasks_sealed_signal: watch::Sender<bool>,
    transport_tasks_seal_required: AtomicBool,
    late_transport_sealed: AtomicBool,
    #[cfg(test)]
    fail_background_start: AtomicBool,
    #[cfg(test)]
    panic_cleanup_future: AtomicBool,
    /// The hold point at this connector's one native close. **Controls only.**
    ///
    /// Installed at most once and never removed, so a control cannot arrange a
    /// hold, observe it, and then quietly disarm the same connector.
    #[cfg(all(test, feature = "transport-lab"))]
    native_close_gate: SyncMutex<Option<Arc<NativeCloseGate>>>,
}

async fn wait_on_status(mut status: watch::Receiver<ConnectorCloseStatus>) -> Result<()> {
    loop {
        match status.borrow().clone() {
            ConnectorCloseStatus::Closed => return Ok(()),
            ConnectorCloseStatus::Failed(error) => {
                return Err(Error::Transport(format!(
                    "native peer cleanup failed and retained its exact claim: {error}"
                )));
            }
            ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {}
        }
        if status.changed().await.is_err() {
            return Err(Error::Transport(
                "native peer cleanup owner stopped".to_string(),
            ));
        }
    }
}

impl ConnectorCloseOwner {
    pub(super) fn new(
        ownership: ConnectorOwnership,
        resource_owner: MeshConnectorResourceScope,
        cleanup_capability: crate::runtime::attempt::ConnectorCleanupCapability,
        transport_observation: Option<ObservationLease>,
        late_transport_custodian: Arc<LateTransportCustodian>,
    ) -> Arc<Self> {
        let (status, _receiver) = watch::channel(ConnectorCloseStatus::Open);
        Arc::new(Self {
            ownership,
            late_transport_custodian,
            resource_owner: SyncMutex::new(Some(resource_owner)),
            cleanup_capability: SyncMutex::new(Some(cleanup_capability)),
            transport_observation: SyncMutex::new(transport_observation),
            native: SyncMutex::new(None),
            remote_candidates: SyncMutex::new(None),
            realtime_flows: SyncMutex::new(None),
            native_allocation_started: AtomicBool::new(false),
            started: AtomicBool::new(false),
            cleanup_submitted: AtomicBool::new(false),
            cleanup_complete: AtomicBool::new(false),
            status,
            status_transition: SyncMutex::new(()),
            connected_claims: SyncMutex::new(ConnectedClaimRetention::Empty),
            remote_description_resources: SyncMutex::new(std::collections::LinkedList::new()),
            transport_tasks: SyncMutex::new(Vec::new()),
            transport_tasks_sealed: AtomicBool::new(false),
            transport_tasks_sealed_signal: watch::channel(false).0,
            transport_tasks_seal_required: AtomicBool::new(false),
            late_transport_sealed: AtomicBool::new(false),
            #[cfg(test)]
            fail_background_start: AtomicBool::new(false),
            #[cfg(test)]
            panic_cleanup_future: AtomicBool::new(false),
            #[cfg(all(test, feature = "transport-lab"))]
            native_close_gate: SyncMutex::new(None),
        })
    }

    pub(super) fn attach_native(self: &Arc<Self>, native: Arc<RTCPeerConnection>) -> bool {
        self.attach_native_port(Arc::new(WebRtcNativeClosePort { peer: native }))
    }

    /// Marks the point after which dependency-owned constructor work may have
    /// allocated native resources that MyOwnMesh cannot individually close.
    ///
    /// This is set before entering the native constructor. If construction is
    /// cancelled before a close port is returned, cleanup retains the exact
    /// connector claim instead of proving a release it cannot observe.
    pub(super) fn mark_native_allocation_started(&self) {
        self.native_allocation_started
            .store(true, Ordering::Release);
    }

    /// Records that native construction returned without a closeable port.
    /// The exact connector claim remains retained because dependency-owned
    /// allocation cannot be disproved.
    pub(super) fn finish_native_allocation_without_close_port(&self, reason: String) {
        self.fail_cleanup(reason);
    }

    pub(super) fn attach_native_port(
        self: &Arc<Self>,
        native: Arc<dyn NativeConnectorClosePort>,
    ) -> bool {
        let mut current = self.native.lock();
        if current.is_some() {
            drop(current);
            if let Some(resource_owner) = self.resource_owner.lock().as_ref() {
                resource_owner.poison_accounting();
            }
            self.fail_cleanup("duplicate native peer installation".to_string());
            return false;
        }
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed | ConnectorCloseStatus::Failed(_)
        ) {
            return false;
        }
        *current = Some(native);
        drop(current);
        if self.started.load(Ordering::Acquire) {
            self.submit_cleanup_if_ready();
        }
        true
    }

    pub(super) fn attach_remote_candidates(
        &self,
        candidates: Arc<SyncMutex<RemoteCandidateState>>,
    ) -> bool {
        let mut current = self.remote_candidates.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate remote-candidate owner installation".to_string());
            return false;
        }
        *current = Some(candidates);
        true
    }

    pub(super) fn attach_realtime_flows(&self, flows: Arc<RealtimeFlowRegistry>) -> bool {
        let mut current = self.realtime_flows.lock();
        if current.is_some() {
            drop(current);
            self.fail_cleanup("duplicate real-time registry owner installation".to_string());
            return false;
        }
        *current = Some(flows);
        self.transport_tasks_seal_required
            .store(true, Ordering::Release);
        true
    }

    pub(super) fn retain_remote_description_resources(
        &self,
        resources: Arc<RemoteDescriptionResourceOwner>,
    ) {
        let mut retained = self.remote_description_resources.lock();
        if retained
            .iter()
            .any(|current| Arc::ptr_eq(current, &resources))
        {
            return;
        }
        retained.push_back(resources);
    }

    /// Retain one transport task under this connector's terminal owner. The
    /// caller has already fenced admission; the owner observes every handle
    /// after native cleanup and never delegates it to an unowned runtime task.
    pub(super) fn retain_transport_task(&self, task: tokio::task::JoinHandle<()>) {
        let _transition = self.status_transition.lock();
        if self.cleanup_complete.load(Ordering::Acquire)
            || self.late_transport_sealed.load(Ordering::Acquire)
        {
            drop(_transition);
            if let Err(tasks) = self.late_transport_custodian.submit(vec![task]) {
                // A late callback racing the final custodian seal still owns
                // its exact task. Abort and observe it directly; it must never
                // be dropped merely because the bounded handoff is closed.
                for task in tasks {
                    task.abort();
                    record_join_result(join_task_without_runtime(task));
                }
                warn!("late WebRTC terminal custodian was closed before task handoff");
            }
            return;
        }
        // Sealing stops ordinary callback admission, but an operation already
        // inside the fence may still publish its owned task while the close
        // owner is waiting for that fence. Retain that task in the same
        // registry so the final drain observes it; only a terminal owner
        // routes a genuinely late task to the pre-created custodian.
        self.transport_tasks.lock().push(task);
    }

    pub(super) fn seal_transport_tasks(&self) {
        // Serialize the seal with task admission.  A late callback must see
        // either the open registry or the sealed fence, never a gap between
        // those two observations.
        let _transition = self.status_transition.lock();
        let _retained = self.transport_tasks.lock();
        self.transport_tasks_sealed.store(true, Ordering::Release);
        self.transport_tasks_sealed_signal.send_replace(true);
    }

    async fn wait_for_transport_task_seal(&self) {
        if self.transport_tasks_sealed.load(Ordering::Acquire) {
            return;
        }
        let mut sealed = self.transport_tasks_sealed_signal.subscribe();
        loop {
            if *sealed.borrow() {
                return;
            }
            if sealed.changed().await.is_err() {
                return;
            }
        }
    }

    async fn wait_for_transport_tasks(&self) {
        loop {
            let tasks = std::mem::take(&mut *self.transport_tasks.lock());
            join_task_batch(tasks).await;
            let _transition = self.status_transition.lock();
            if self.transport_tasks.lock().is_empty() {
                self.transport_tasks_sealed.store(true, Ordering::Release);
                self.transport_tasks_sealed_signal.send_replace(true);
                return;
            }
        }
    }

    pub(super) fn retire_local(&self) {
        self.ownership.retire();
        if let Some(candidates) = self.remote_candidates.lock().as_ref() {
            drain_remote_candidates(candidates);
        }
        if let Some(flows) = self.realtime_flows.lock().as_ref() {
            flows.retire();
        }
    }

    pub(super) fn retain_connected_claim(
        self: &Arc<Self>,
        mut capability: crate::connector::ConnectedChannelCapability,
    ) {
        let mut retained = self.connected_claims.lock();
        if self.ownership.cleanup_failed.load(Ordering::Acquire) {
            capability.retain_after_cleanup_failure();
        }
        if self.cleanup_complete.load(Ordering::Acquire) {
            drop(capability);
            return;
        }
        *retained = match std::mem::replace(&mut *retained, ConnectedClaimRetention::Empty) {
            ConnectedClaimRetention::Empty => ConnectedClaimRetention::One(Box::new(capability)),
            ConnectedClaimRetention::One(primary) => {
                trace!("native cleanup retains a duplicate connected claim");
                ConnectedClaimRetention::Multiple(vec![*primary, capability])
            }
            ConnectedClaimRetention::Multiple(mut claims) => {
                claims.push(capability);
                ConnectedClaimRetention::Multiple(claims)
            }
        };
        drop(retained);
        self.start();
    }

    /// This close owner as the transport-independent retention obligation.
    ///
    /// The generic handoff calls back through this on drop, so the connected
    /// claim returns to exactly the same retention path it uses today.
    pub(super) fn generic_retention(
        self: &Arc<Self>,
    ) -> Arc<dyn crate::connector::ConnectedChannelRetention> {
        Arc::clone(self) as Arc<dyn crate::connector::ConnectedChannelRetention>
    }

    pub(super) fn start(self: &Arc<Self>) {
        self.retire_local();
        if self.started.swap(true, Ordering::AcqRel) {
            return;
        }
        {
            let _transition = self.status_transition.lock();
            let current = self.status.borrow().clone();
            match current {
                ConnectorCloseStatus::Closed => return,
                ConnectorCloseStatus::Failed(_) => {}
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing => {
                    self.status.send_replace(ConnectorCloseStatus::Closing);
                }
            }
        }
        self.submit_cleanup_if_ready();
    }

    /// Submit cleanup only after either no native allocation was started or an
    /// exact native close port has arrived. A close request racing a native
    /// constructor remains `Closing` and keeps its finite claim. Late port
    /// attachment then wakes this same owner and completes the one close.
    fn submit_cleanup_if_ready(self: &Arc<Self>) {
        let native_ready = self.native.lock().is_some();
        if !native_ready && self.native_allocation_started.load(Ordering::Acquire) {
            return;
        }
        if self.cleanup_submitted.swap(true, Ordering::AcqRel) {
            return;
        }
        #[cfg(test)]
        if self.fail_background_start.load(Ordering::Acquire) {
            self.fail_cleanup("cleanup background task failed to start".to_string());
            return;
        }
        let Some(mut cleanup_capability) = self.cleanup_capability.lock().take() else {
            self.fail_cleanup("connector cleanup capability is missing".to_string());
            return;
        };
        if let Err(error) = cleanup_capability.begin_cleanup() {
            self.fail_cleanup(format!(
                "resource provider refused the cleanup transition: {error}"
            ));
            return;
        }
        let Some(resource_owner) = self.resource_owner.lock().take() else {
            self.fail_cleanup("connector resource owner is missing".to_string());
            return;
        };
        self.ownership.relinquish_work_resource_scope();
        let owner = Arc::clone(self);
        let completion_owner = Arc::clone(self);
        let failure_owner = Arc::clone(self);
        let refused = resource_owner
            .submit_cleanup(
                cleanup_capability,
                Box::pin(async move { owner.run().await }),
                Box::new(move || {
                    completion_owner.publish_cleanup_job_completion();
                }),
                Box::new(move |reason| {
                    failure_owner.fail_cleanup(reason);
                }),
            )
            .was_refused();
        drop(resource_owner);
        if refused {
            self.fail_cleanup("process cleanup executor refused the close owner".to_string());
        }
    }

    async fn run(self: Arc<Self>) {
        #[cfg(test)]
        if self.panic_cleanup_future.load(Ordering::Acquire) {
            panic!("injected cleanup future panic");
        }
        let native = self.native.lock().clone();
        let Some(native) = native else {
            if self.native_allocation_started.load(Ordering::Acquire) {
                self.fail_cleanup(
                    "native construction ended without an observable close owner".to_string(),
                );
            } else {
                self.finish_closed().await;
            }
            return;
        };
        self.ownership.incarnation.retire();
        self.ownership.operation_fence.wait_for_operations().await;
        if self.transport_tasks_seal_required.load(Ordering::Acquire) {
            self.wait_for_transport_task_seal().await;
        }
        // Outbound pumps own their sender until `remove_track` has returned.
        // Join them before native close so the terminal status cannot race a
        // still-live sender or release its connector claim early.
        self.wait_for_transport_tasks().await;
        // Controls only, compiled out of production. The hold is taken *after*
        // the operation fence has drained and *before* the native close, which
        // is the one window in which "this connector is closing and its claim is
        // still retained" is a true statement about a real close in flight.
        #[cfg(all(test, feature = "transport-lab"))]
        let gate = self.native_close_gate.lock().clone();
        #[cfg(all(test, feature = "transport-lab"))]
        if let Some(gate) = gate.as_ref() {
            gate.hold().await;
        }
        // The one native close is matched directly on the dependency's own
        // future, and that shape is pinned by the Arc 03 connector-worker
        // boundary check. It is pinned because it is the honest shape: nothing
        // between this owner and the dependency gets to decide the outcome of
        // the close in production.
        let outcome = match native.close().await {
            // The physical close has already run and reported success. The only
            // thing that can still turn this into a failure is an installed
            // control gate, and only after the fact — so a failure twin
            // exercises a genuine close and then reports the failure this owner
            // is supposed to be conservative about, rather than skipping the
            // close. In production there is no gate and this is `Ok(())`.
            Ok(()) => self.observe_gated_native_close(),
            Err(error) => Err(error),
        };
        match outcome {
            Ok(()) => self.finish_closed().await,
            Err(error) => self.fail_cleanup(error.to_string()),
        }
    }

    /// What an installed control gate reports about a close that has run.
    ///
    /// The gate is installed at most once and is never removed, so re-reading it
    /// here yields the same gate the hold above used.
    #[cfg(all(test, feature = "transport-lab"))]
    fn observe_gated_native_close(&self) -> Result<()> {
        let gate = self.native_close_gate.lock().clone();
        match gate {
            Some(gate) => gate.observe_native_close(),
            None => Ok(()),
        }
    }

    /// Production has no gate: the dependency's close is the whole outcome.
    #[cfg(not(all(test, feature = "transport-lab")))]
    fn observe_gated_native_close(&self) -> Result<()> {
        Ok(())
    }

    async fn finish_closed(&self) {
        {
            let _transition = self.status_transition.lock();
            self.late_transport_sealed.store(true, Ordering::Release);
        }
        let joined = self.join_late_transport_custodian().await;
        if !joined {
            self.fail_cleanup("late transport terminal custodian did not join".to_string());
            return;
        }
        let _transition = self.status_transition.lock();
        let terminal_failure = matches!(*self.status.borrow(), ConnectorCloseStatus::Failed(_));
        // Native close has completed, so end only this transport observation
        // before publishing cleanup completion. On a prior terminal failure,
        // the conservative failed-cleanup path retains it until the owner dies.
        if !terminal_failure {
            drop(self.transport_observation.lock().take());
        }
        self.cleanup_complete.store(true, Ordering::Release);
        if terminal_failure {
            // A failure recorded before start remains authoritative, but a
            // later successful native close still retires all subordinate
            // connector objects. Their exact failed claims were already moved
            // into provider retention and are not made reusable here.
            self.connected_claims.lock().retain_after_cleanup_failure();
            for resources in self.remote_description_resources.lock().iter() {
                resources.retain_after_cleanup_failure();
            }
        } else {
            self.ownership.complete_cleanup();
            self.connected_claims.lock().release_after_cleanup_success();
        }
        self.native.lock().take();
        self.remote_candidates.lock().take();
        self.realtime_flows.lock().take();
        self.remote_description_resources.lock().clear();
        *self.connected_claims.lock() = ConnectedClaimRetention::Empty;
    }

    async fn join_late_transport_custodian(&self) -> bool {
        let custodian = Arc::clone(&self.late_transport_custodian);
        tokio::task::spawn_blocking(move || custodian.close_and_join())
            .await
            .unwrap_or(false)
    }

    fn publish_cleanup_job_completion(&self) {
        let _transition = self.status_transition.lock();
        if self.cleanup_complete.load(Ordering::Acquire)
            && matches!(
                *self.status.borrow(),
                ConnectorCloseStatus::Open | ConnectorCloseStatus::Closing
            )
        {
            self.status.send_replace(ConnectorCloseStatus::Closed);
        }
    }

    /// Retain this connector's exact cleanup claims after a known native
    /// close failure. The process aggregate remains exact, so unrelated
    /// connector slots remain admissible.
    pub(super) fn fail_cleanup(&self, reason: String) {
        let _transition = self.status_transition.lock();
        if matches!(
            *self.status.borrow(),
            ConnectorCloseStatus::Closed | ConnectorCloseStatus::Failed(_)
        ) {
            return;
        }
        #[cfg(any(test, feature = "transport-lab"))]
        {
            let bounded_reason = reason
                .char_indices()
                .nth(256)
                .map_or(reason.as_str(), |(index, _)| &reason[..index]);
            eprintln!("[arc03j-cleanup-failure] {bounded_reason}");
        }
        self.late_transport_sealed.store(true, Ordering::Release);
        self.late_transport_custodian.close_sender();
        self.ownership.cleanup_failed.store(true, Ordering::Release);
        self.retire_local();
        self.ownership.retain_after_cleanup_failure();
        self.connected_claims.lock().retain_after_cleanup_failure();
        for resources in self.remote_description_resources.lock().iter() {
            resources.retain_after_cleanup_failure();
        }
        self.status
            .send_replace(ConnectorCloseStatus::Failed(reason));
    }

    pub(super) async fn wait(self: &Arc<Self>) -> Result<()> {
        let status = self.status.subscribe();
        self.start();
        let result = wait_on_status(status).await;
        self.wait_for_transport_tasks().await;
        let _ = self.join_late_transport_custodian().await;
        result
    }

    #[cfg(test)]
    pub(super) fn fail_background_start_for_test(&self) {
        self.fail_background_start.store(true, Ordering::Release);
    }

    #[cfg(test)]
    pub(super) fn panic_cleanup_future_for_test(&self) {
        self.panic_cleanup_future.store(true, Ordering::Release);
    }

    /// Install this connector's one native-close hold point. **Controls only.**
    ///
    /// Exactly once per connector: a second installation would let a control
    /// replace a gate whose entries it had already counted, so the invariant a
    /// twin states about "one close" would be about two different gates.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn install_native_close_gate_for_test(&self) -> NativeCloseGateHandle {
        let gate = NativeCloseGate::new();
        let mut installed = self.native_close_gate.lock();
        assert!(
            installed.is_none(),
            "the native close gate is installed exactly once per connector"
        );
        *installed = Some(Arc::clone(&gate));
        NativeCloseGateHandle { gate }
    }

    #[cfg(test)]
    pub(super) fn retained_connected_claims_for_test(&self) -> usize {
        match &*self.connected_claims.lock() {
            ConnectedClaimRetention::Empty => 0,
            ConnectedClaimRetention::One(_) => 1,
            ConnectedClaimRetention::Multiple(claims) => claims.len(),
        }
    }
}

#[cfg(test)]
mod task_reaper_tests {
    use super::*;

    async fn wait_for_reaped(target: usize) {
        let wake = TEST_TRANSPORT_REAP_WAKE.get_or_init(tokio::sync::Notify::new);
        loop {
            let notified = wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire) >= target {
                return;
            }
            notified.await;
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn raw_close_custody_refuses_unattached_start_without_detaching_worker() {
        let custodian = PeerConstructionCloseCustodian::new()
            .expect("the raw construction close custodian has a pre-existing worker");
        custodian.start();
        assert!(custodian.wait().await.is_err());
        drop(custodian);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn bounded_reaper_observes_aborted_transport_task() {
        let before = TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire);
        let (sender, reaper) = spawn_task_reaper();
        let (started_tx, started_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            started_tx
                .send(())
                .expect("transport task start barrier remains live");
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("transport task reached its park");
        task.abort();
        submit_task_batch(&sender, vec![task]);
        drop(sender);
        reaper.await.expect("transport reaper joins cleanly");
        assert_eq!(
            TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire),
            before + 1,
            "the exact cancelled transport task was observed by the reaper"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn outside_runtime_drop_transfers_exact_transport_batch() {
        let before = TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire);
        let (sender, reaper) = spawn_task_reaper();
        let (started_tx, started_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            started_tx
                .send(())
                .expect("transport task start barrier remains live");
            std::future::pending::<()>().await;
        });
        started_rx.await.expect("transport task reached its park");
        std::thread::spawn(move || {
            task.abort();
            submit_task_batch(&sender, vec![task]);
        })
        .join()
        .expect("off-runtime transport drop returns");
        reaper.await.expect("transport reaper drains after drop");
        assert_eq!(
            TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire),
            before + 1,
            "the exact task moved by an off-runtime drop was joined"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn full_reaper_fallback_observes_transport_panic() {
        let before = TEST_PANICKED_TRANSPORT_TASKS.load(Ordering::Acquire);
        let wake = TEST_TRANSPORT_PANIC_WAKE.get_or_init(tokio::sync::Notify::new);
        let notified = wake.notified();
        tokio::pin!(notified);
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .try_send(vec![tokio::spawn(std::future::pending::<()>())])
            .expect("bounded reaper fixture accepts its filler");
        let task = tokio::spawn(async {
            panic!("injected transport task panic");
        });
        submit_task_batch(&sender, vec![task]);
        let filler = receiver
            .try_recv()
            .expect("the full-channel filler remains explicitly owned");
        for filler in filler {
            filler.abort();
            let _ = filler.await;
        }
        notified.await;
        assert_eq!(
            TEST_PANICKED_TRANSPORT_TASKS.load(Ordering::Acquire),
            before + 1,
            "the active-runtime fallback observes a panicking transport task"
        );

        let (closed_sender, closed_receiver) = mpsc::channel(1);
        drop(closed_receiver);
        let notified = wake.notified();
        tokio::pin!(notified);
        let task = tokio::spawn(async {
            panic!("injected closed-reaper transport task panic");
        });
        submit_task_batch(&closed_sender, vec![task]);
        notified.await;
        assert_eq!(
            TEST_PANICKED_TRANSPORT_TASKS.load(Ordering::Acquire),
            before + 2,
            "the closed-runtime fallback observes a panicking transport task"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn late_task_fallback_observes_cancel_and_panic_terminals() {
        let before_reaped = TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire);
        let before_panicked = TEST_PANICKED_TRANSPORT_TASKS.load(Ordering::Acquire);

        let cancelled = tokio::spawn(async {
            std::future::pending::<()>().await;
        });
        cancelled.abort();
        let cancelled_custodian = observe_late_transport_task(cancelled)
            .expect("late cancellation custodian remains constructible");

        let panicked = tokio::spawn(async {
            panic!("injected late transport task panic");
        });
        let panicked_custodian = observe_late_transport_task(panicked)
            .expect("late panic custodian remains constructible");

        wait_for_reaped(before_reaped + 2).await;
        assert_eq!(
            TEST_PANICKED_TRANSPORT_TASKS.load(Ordering::Acquire),
            before_panicked + 1,
            "late fallback observes both cancellation and panic terminals"
        );
        assert!(
            tokio::task::spawn_blocking(move || { cancelled_custodian.close_and_join() })
                .await
                .expect("late cancellation custodian join task remains live")
        );
        assert!(
            tokio::task::spawn_blocking(move || { panicked_custodian.close_and_join() })
                .await
                .expect("late panic custodian join task remains live")
        );
    }

    #[test]
    fn late_task_fallback_survives_runtime_destruction() {
        let before_reaped = TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire);
        TEST_TRANSPORT_REAP_CONDVAR
            .get_or_init(|| (std::sync::Mutex::new(()), std::sync::Condvar::new()));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("late-task fixture runtime remains constructible");
        let custodian = LateTransportCustodian::new_unfunded()
            .expect("late runtime-destruction custodian remains constructible");
        let custodian_for_runtime = Arc::clone(&custodian);
        runtime.block_on(async move {
            let task = tokio::spawn(async {
                std::future::pending::<()>().await;
            });
            task.abort();
            assert!(custodian_for_runtime.submit(vec![task]).is_ok());
        });
        drop(runtime);

        let (lock, wake) = TEST_TRANSPORT_REAP_CONDVAR
            .get()
            .expect("late-task terminal witness remains installed");
        let mut guard = lock.lock().expect("late-task witness lock remains live");
        while TEST_REAPED_TRANSPORT_TASKS.load(Ordering::Acquire) < before_reaped + 1 {
            guard = wake
                .wait(guard)
                .expect("late-task terminal witness wait remains live");
        }
        assert!(std::thread::spawn(move || custodian.close_and_join())
            .join()
            .expect("runtime-destruction custodian join remains observed"));
    }

    #[tokio::test(flavor = "current_thread")]
    async fn late_custodian_closed_handoff_retains_terminal_observation() {
        let custodian = LateTransportCustodian::new_unfunded()
            .expect("closed-handoff custodian remains constructible");
        assert!(tokio::task::spawn_blocking({
            let custodian = Arc::clone(&custodian);
            move || custodian.close_and_join()
        })
        .await
        .expect("closed-handoff custodian join remains observed"));

        let task = tokio::spawn(async { std::future::pending::<()>().await });
        task.abort();
        let mut rejected = custodian
            .submit(vec![task])
            .expect_err("closed custodian refuses handoff");
        for task in rejected.drain(..) {
            let result = tokio::task::spawn_blocking(move || join_task_without_runtime(task))
                .await
                .expect("closed-handoff rejected task join worker remains observed");
            record_join_result(result);
        }
    }
}
