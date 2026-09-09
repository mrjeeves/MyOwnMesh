//! Dependency-neutral admission and custody hooks for embedders.
//!
//! The TURN crate deliberately does not depend on an application resource
//! provider. An embedding owner supplies this small interface and retains the
//! returned lease beside the exact native object or task it funded.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

/// A bounded dependency-owned object or task category.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ResourceKind {
    ReadLoop,
    CommandLoop,
    Allocation,
    AllocationTimer,
    PacketPump,
    Permission,
    ChannelBind,
    Reservation,
    Nonce,
    Queue,
    RelayProbe,
    /// One shared, funded first-failure record (not an active task lease).
    CleanupRecord,
}

/// Finite work retained by one admitted object.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceCharge {
    pub units: u64,
    pub retained_bytes: u64,
}

impl ResourceCharge {
    pub const fn units(units: u64) -> Self {
        Self {
            units,
            retained_bytes: 0,
        }
    }

    pub const fn with_bytes(units: u64, retained_bytes: u64) -> Self {
        Self {
            units,
            retained_bytes,
        }
    }
}

/// Typed refusal from the owner-selected provider.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceAdmissionError;

/// One noncloneable exact owner charge. Dropping the concrete implementation
/// releases the provider reservation; TURN only stores and moves this trait
/// object and never fabricates or duplicates it.
pub trait ResourceLease: Send + Sync {}

/// Owner-supplied admission authority. Implementations must acquire before
/// the corresponding native bind, channel, task, or retained map mutation.
pub trait ResourceAdmission: Send + Sync {
    fn acquire(
        &self,
        kind: ResourceKind,
        charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupTaskLayer {
    ServerRead,
    ServerCommand,
    ManagerChild,
    AllocationChild,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CleanupFailure {
    TaskPanicked(CleanupTaskLayer),
    UnexpectedCancellation(CleanupTaskLayer),
    AllocationClose,
    ControlSocketClose,
    RelaySocketClose,
}

struct CleanupStatusRecord {
    first: std::sync::Mutex<Option<CleanupFailure>>,
    #[cfg(test)]
    changed: tokio::sync::Notify,
}

/// Every clone carries both owners. Field order deallocates the record before
/// releasing its funding; neither inner Arc nor a Weak can escape this wrapper.
#[derive(Clone)]
pub struct CleanupStatus {
    record: Arc<CleanupStatusRecord>,
    _funding: Arc<Box<dyn ResourceLease>>,
}

impl CleanupStatus {
    pub fn charge() -> Result<ResourceCharge, ResourceAdmissionError> {
        let bytes = std::mem::size_of::<CleanupStatusRecord>()
            .checked_add(std::mem::size_of::<Box<dyn ResourceLease>>())
            .ok_or(ResourceAdmissionError)?;
        Ok(ResourceCharge::with_bytes(
            1,
            u64::try_from(bytes).map_err(|_| ResourceAdmissionError)?,
        ))
    }

    pub fn new(admission: &dyn ResourceAdmission) -> Result<Self, ResourceAdmissionError> {
        let funding = admission.acquire(ResourceKind::CleanupRecord, Self::charge()?)?;
        Ok(Self {
            record: Arc::new(CleanupStatusRecord {
                first: std::sync::Mutex::new(None),
                #[cfg(test)]
                changed: tokio::sync::Notify::new(),
            }),
            _funding: Arc::new(funding),
        })
    }

    pub fn record(&self, failure: CleanupFailure) {
        self.record
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get_or_insert(failure);
        #[cfg(test)]
        self.record.changed.notify_waiters();
    }

    pub fn first(&self) -> Option<CleanupFailure> {
        *self
            .record
            .first
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    pub fn result(&self) -> crate::error::Result<()> {
        self.first()
            .map_or(Ok(()), |failure| Err(crate::error::Error::Cleanup(failure)))
    }

    #[cfg(test)]
    pub(crate) async fn wait_for_failure(&self) {
        loop {
            let changed = self.record.changed.notified();
            tokio::pin!(changed);
            changed.as_mut().enable();
            if self.first().is_some() {
                return;
            }
            changed.await;
        }
    }

    pub(crate) fn error(&self, error: &crate::error::Error, fallback: CleanupFailure) {
        self.record(match error {
            crate::error::Error::Cleanup(failure) => *failure,
            _ => fallback,
        });
    }

    pub(crate) fn observe_join(
        &self,
        result: Result<(), tokio::task::JoinError>,
        layer: CleanupTaskLayer,
        abort_requested: bool,
    ) {
        if let Err(error) = result {
            if error.is_panic() {
                self.record(CleanupFailure::TaskPanicked(layer));
            } else if !abort_requested || !error.is_cancelled() {
                self.record(CleanupFailure::UnexpectedCancellation(layer));
            }
        }
    }
}

/// Per-instance, nondefault custody controls. Gate holds are observations of
/// production close, never an alternative graceful command terminator.
#[cfg(feature = "custody-lab")]
#[derive(Clone)]
pub struct CleanupProbe {
    record: Arc<CleanupProbeRecord>,
    _funding: Arc<Box<dyn ResourceLease>>,
}

#[cfg(feature = "custody-lab")]
struct CleanupProbeRecord {
    vec_reached: tokio::sync::Notify,
    vec_release: tokio::sync::Notify,
    parent_reached: tokio::sync::Notify,
    parent_release: tokio::sync::Notify,
    command_reached: tokio::sync::Notify,
    command_hold: tokio::sync::Notify,
    command_terminal: std::sync::atomic::AtomicBool,
    command_joined: std::sync::atomic::AtomicBool,
    read_joined: std::sync::atomic::AtomicBool,
    read_waiting: tokio::sync::Notify,
    panic_command: std::sync::atomic::AtomicBool,
    panic_read: std::sync::atomic::AtomicBool,
    startup_stage: std::sync::atomic::AtomicU8,
    startup_reached: tokio::sync::Notify,
    startup_release: tokio::sync::Notify,
    panic_startup: std::sync::atomic::AtomicBool,
    request_taken: std::sync::atomic::AtomicUsize,
    plaintext_dropped: std::sync::atomic::AtomicBool,
    transient_released: std::sync::atomic::AtomicBool,
}

#[cfg(feature = "custody-lab")]
impl CleanupProbe {
    pub fn charge() -> ResourceCharge {
        ResourceCharge::with_bytes(
            1,
            (std::mem::size_of::<CleanupProbeRecord>()
                + std::mem::size_of::<Box<dyn ResourceLease>>()) as u64,
        )
    }

    pub fn new(admission: &dyn ResourceAdmission) -> Result<Self, ResourceAdmissionError> {
        let lease = admission.acquire(ResourceKind::CleanupRecord, Self::charge())?;
        Ok(Self {
            record: Arc::new(CleanupProbeRecord {
                vec_reached: tokio::sync::Notify::new(),
                vec_release: tokio::sync::Notify::new(),
                parent_reached: tokio::sync::Notify::new(),
                parent_release: tokio::sync::Notify::new(),
                command_reached: tokio::sync::Notify::new(),
                command_hold: tokio::sync::Notify::new(),
                command_terminal: std::sync::atomic::AtomicBool::new(false),
                command_joined: std::sync::atomic::AtomicBool::new(false),
                read_joined: std::sync::atomic::AtomicBool::new(false),
                read_waiting: tokio::sync::Notify::new(),
                panic_command: std::sync::atomic::AtomicBool::new(false),
                panic_read: std::sync::atomic::AtomicBool::new(false),
                startup_stage: std::sync::atomic::AtomicU8::new(0),
                startup_reached: tokio::sync::Notify::new(),
                startup_release: tokio::sync::Notify::new(),
                panic_startup: std::sync::atomic::AtomicBool::new(false),
                request_taken: std::sync::atomic::AtomicUsize::new(0),
                plaintext_dropped: std::sync::atomic::AtomicBool::new(false),
                transient_released: std::sync::atomic::AtomicBool::new(false),
            }),
            _funding: Arc::new(lease),
        })
    }

    pub async fn wait_vec_taken(&self) {
        self.record.vec_reached.notified().await;
    }
    pub async fn wait_parent_before_abort(&self) {
        self.record.parent_reached.notified().await;
    }
    pub async fn wait_command_held(&self) {
        self.record.command_reached.notified().await;
    }
    pub async fn wait_read_join_started(&self) {
        self.record.read_waiting.notified().await;
    }
    pub fn release_vec(&self) {
        self.record.vec_release.notify_one();
    }
    pub fn release_parent(&self) {
        self.record.parent_release.notify_one();
    }
    pub fn command_terminal(&self) -> bool {
        self.record.command_terminal.load(Ordering::Acquire)
    }
    pub fn command_joined(&self) -> bool {
        self.record.command_joined.load(Ordering::Acquire)
    }
    pub fn read_joined(&self) -> bool {
        self.record.read_joined.load(Ordering::Acquire)
    }
    pub fn panic_command_on_close(&self) {
        self.record.panic_command.store(true, Ordering::Release);
    }
    pub fn panic_read_after_command_join(&self) {
        self.record.panic_read.store(true, Ordering::Release);
    }

    /// Wrapper startup gates share this explicitly funded per-instance record.
    /// They do not replace any native close path or release the command gate.
    pub fn hold_startup_before_request(&self) {
        self.record.startup_stage.store(1, Ordering::Release);
    }
    pub fn hold_startup_before_ready(&self) {
        self.record.startup_stage.store(2, Ordering::Release);
    }
    pub fn panic_startup_before_request(&self) {
        self.record.panic_startup.store(true, Ordering::Release);
    }
    pub async fn wait_startup_held(&self) {
        self.record.startup_reached.notified().await;
    }
    pub fn release_startup(&self) {
        self.record.startup_release.notify_one();
    }
    pub async fn before_startup_request(&self) {
        self.startup_gate(1).await;
        if self.record.panic_startup.load(Ordering::Acquire) {
            panic!("injected TURN lifecycle startup panic");
        }
    }
    pub async fn before_startup_ready(&self) {
        self.startup_gate(2).await;
    }
    async fn startup_gate(&self, stage: u8) {
        if self.record.startup_stage.load(Ordering::Acquire) == stage {
            self.record.startup_reached.notify_one();
            self.record.startup_release.notified().await;
        }
    }
    pub fn mark_request_taken(&self) {
        self.record.request_taken.fetch_add(1, Ordering::AcqRel);
    }
    pub fn mark_plaintext_dropped(&self) {
        self.record.plaintext_dropped.store(true, Ordering::Release);
    }
    pub fn mark_transient_released(&self) {
        self.record
            .transient_released
            .store(true, Ordering::Release);
    }
    pub fn requests_taken(&self) -> usize {
        self.record.request_taken.load(Ordering::Acquire)
    }
    pub fn plaintext_dropped(&self) -> bool {
        self.record.plaintext_dropped.load(Ordering::Acquire)
    }
    pub fn transient_released(&self) -> bool {
        self.record.transient_released.load(Ordering::Acquire)
    }

    pub(crate) async fn after_vec_take(&self) {
        self.record.vec_reached.notify_one();
        self.record.vec_release.notified().await;
    }

    pub(crate) async fn before_command_abort(&self) {
        self.record.parent_reached.notify_one();
        self.record.parent_release.notified().await;
    }

    pub(crate) async fn command_after_ack(&self) {
        let _terminal = CommandTerminal(self.clone());
        self.record.command_reached.notify_one();
        if self.record.panic_command.load(Ordering::Acquire) {
            panic!("injected TURN command panic");
        }
        // No release API: the real parent abort must destroy this future.
        self.record.command_hold.notified().await;
    }

    pub(crate) fn mark_command_joined(&self) {
        self.record.command_joined.store(true, Ordering::Release);
        if self.record.panic_read.load(Ordering::Acquire) {
            panic!("injected TURN read panic");
        }
    }

    pub(crate) fn mark_read_joined(&self) {
        self.record.read_joined.store(true, Ordering::Release);
    }

    pub(crate) fn mark_read_waiting(&self) {
        self.record.read_waiting.notify_one();
    }
}

#[cfg(feature = "custody-lab")]
struct CommandTerminal(CleanupProbe);

#[cfg(feature = "custody-lab")]
impl Drop for CommandTerminal {
    fn drop(&mut self) {
        self.0
            .record
            .command_terminal
            .store(true, Ordering::Release);
    }
}

#[cfg(test)]
pub(crate) struct UnboundedTestAdmission;

#[cfg(test)]
impl ResourceAdmission for UnboundedTestAdmission {
    fn acquire(
        &self,
        _kind: ResourceKind,
        _charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError> {
        Ok(Box::new(UnboundedTestLease))
    }
}

#[cfg(test)]
struct UnboundedTestLease;

#[cfg(test)]
impl ResourceLease for UnboundedTestLease {}

/// Bounded adapter for vendored integration examples and downstream fixture
/// crates. It is intentionally simple but finite: every acquired unit (and
/// each retained KiB) consumes one slot, and dropping the lease restores it.
/// Production embeddings should provide their own owner-selected adapter.
#[doc(hidden)]
pub struct BoundedTestAdmission {
    remaining: Arc<AtomicU64>,
}

impl BoundedTestAdmission {
    pub fn new(limit: u64) -> Self {
        Self {
            remaining: Arc::new(AtomicU64::new(limit)),
        }
    }

    #[cfg(test)]
    pub(crate) fn remaining_for_test(&self) -> u64 {
        self.remaining.load(Ordering::Acquire)
    }
}

struct BoundedTestLease {
    remaining: Arc<AtomicU64>,
    charge: u64,
}

impl ResourceLease for BoundedTestLease {}

impl Drop for BoundedTestLease {
    fn drop(&mut self) {
        self.remaining.fetch_add(self.charge, Ordering::Release);
    }
}

impl ResourceAdmission for BoundedTestAdmission {
    fn acquire(
        &self,
        _kind: ResourceKind,
        charge: ResourceCharge,
    ) -> Result<Box<dyn ResourceLease>, ResourceAdmissionError> {
        let retained_slots = charge
            .retained_bytes
            .checked_add(1023)
            .ok_or(ResourceAdmissionError)?
            / 1024;
        let needed = charge
            .units
            .checked_add(retained_slots)
            .ok_or(ResourceAdmissionError)?;
        if needed == 0 {
            return Err(ResourceAdmissionError);
        }
        let mut current = self.remaining.load(Ordering::Acquire);
        loop {
            if current < needed {
                return Err(ResourceAdmissionError);
            }
            match self.remaining.compare_exchange_weak(
                current,
                current - needed,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => {
                    return Ok(Box::new(BoundedTestLease {
                        remaining: Arc::clone(&self.remaining),
                        charge: needed,
                    }))
                }
                Err(observed) => current = observed,
            }
        }
    }
}
