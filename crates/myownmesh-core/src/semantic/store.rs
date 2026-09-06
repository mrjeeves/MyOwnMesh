//! Persistence for the local canonical bootstrap pair.
//!
//! The temporary file is synchronized before the create-once hard link on all
//! platforms. Unix also synchronizes the containing directory and propagates
//! that failure. Other platforms retain functional create-once persistence,
//! but a successful return does not claim parent-directory crash durability.
//!
//! The local slot is only a storage locator.  It is hashed before it reaches
//! the path and is never consulted as a source of semantic authority; the
//! [`BootstrapRecord`] stored there must still pass all of the bootstrap
//! module's context, basis, and root-signature checks.

use std::any::Any;
use std::borrow::Borrow;
use std::fs::OpenOptions;
use std::io::{self, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{channel, sync_channel, Receiver, Sender, SyncSender};
use std::sync::{Arc, Mutex, MutexGuard};
use std::thread::{self, JoinHandle};
use std::time::Duration;
#[cfg(feature = "transport-lab")]
use std::time::Instant;

#[cfg(unix)]
use std::os::fd::AsRawFd;

#[cfg(windows)]
use std::os::windows::fs::OpenOptionsExt;

use data_encoding::BASE32_NOPAD;
use rusqlite::{params, Connection, OptionalExtension, TransactionBehavior};
use serde::{Deserialize, Serialize};
use serde_json::Error as JsonError;
use sha2::{Digest, Sha256};
use thiserror::Error;

use super::causal::{dependencies as canonical_dependencies, LiveFactGraphCheckpoint};
use super::proof_outbox::{ProofDeliveryId, ProofRecord, ProofRecordState};
#[cfg(test)]
use super::SemanticFactRow;
use super::{
    BootstrapError, BootstrapRecord, DeviceId, ExpectedMeshContext, FactGraph, FactId,
    MeshContextId, SemanticDelta, SemanticFactStatus, SignedFact, VerifiedBootstrap,
};
use crate::config::{
    SemanticPolicyConfig, SEMANTIC_INGRESS_OWNER, SEMANTIC_INGRESS_OWNER_MAX_BYTES,
};
use crate::resource::{ResourceClaim, ResourceClass, ResourceLease};

const BOOTSTRAP_DIRECTORY: &str = "bootstrap";
const SEMANTIC_DIRECTORY: &str = "semantic";
const SEMANTIC_DATABASE_FILE: &str = "store.sqlite3";
// Version 4 makes the compact binary fact codec the only durable encoding.
// Earlier databases are rejected as a unit instead of mixing JSON and binary
// rows or carrying a permanent compatibility decoder in the engine.
const SEMANTIC_DATABASE_VERSION: u64 = 4;
const LIVE_CHECKPOINT_KEY: &str = "live_checkpoint_v1";
#[cfg(test)]
const SQLITE_WAL_HEADER_BYTES: u64 = 32;
#[cfg(test)]
const SQLITE_WAL_FRAME_OVERHEAD_BYTES: u64 = 24;
static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
#[cfg(test)]
static ORDERED_RESTORE_ROWS: AtomicU64 = AtomicU64::new(0);

struct DigestWriter<'a>(&'a mut Sha256);

impl Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

fn hash_json_into<T: Serialize>(hasher: &mut Sha256, value: &T) -> Result<(), JsonError> {
    serde_json::to_writer(DigestWriter(hasher), value)
}

#[cfg(feature = "transport-lab")]
const ADMISSION_PHASE_COUNT: usize = 13;

#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy)]
pub(crate) enum AdmissionPhase {
    AsyncAdmissionEnvelopeInclusive,
    AsyncLanePermitWaitExclusive,
    PublicationGraphReplayColdLookup,
    CausalJournalApply,
    StoreWorkerHandoff,
    StorePlan,
    CapacityPreflight,
    BeginImmediate,
    SqlApply,
    CommitWalTerminal,
    AuthorWitnessSign,
    ProjectionRosterPublish,
    PostCommitBroadcast,
}

#[cfg(feature = "transport-lab")]
impl AdmissionPhase {
    const fn index(self) -> usize {
        match self {
            Self::AsyncAdmissionEnvelopeInclusive => 0,
            Self::AsyncLanePermitWaitExclusive => 1,
            Self::PublicationGraphReplayColdLookup => 2,
            Self::CausalJournalApply => 3,
            Self::StoreWorkerHandoff => 4,
            Self::StorePlan => 5,
            Self::CapacityPreflight => 6,
            Self::BeginImmediate => 7,
            Self::SqlApply => 8,
            Self::CommitWalTerminal => 9,
            Self::AuthorWitnessSign => 10,
            Self::ProjectionRosterPublish => 11,
            Self::PostCommitBroadcast => 12,
        }
    }
}

#[cfg(feature = "transport-lab")]
pub(crate) struct AdmissionPhaseGuard {
    phase: AdmissionPhase,
    started: Instant,
}

#[cfg(feature = "transport-lab")]
impl AdmissionPhaseGuard {
    pub(crate) fn new(phase: AdmissionPhase) -> Self {
        Self {
            phase,
            started: Instant::now(),
        }
    }
}

#[cfg(feature = "transport-lab")]
impl Drop for AdmissionPhaseGuard {
    fn drop(&mut self) {
        let index = self.phase.index();
        let elapsed = self.started.elapsed().as_nanos();
        let nanos = u64::try_from(elapsed).unwrap_or(u64::MAX);
        let _ = ADMISSION_PHASE_COUNTS[index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(1)),
        );
        let _ = ADMISSION_PHASE_NANOS[index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.saturating_add(nanos)),
        );
        let _ = ADMISSION_PHASE_MAX_NANOS[index].fetch_update(
            Ordering::Relaxed,
            Ordering::Relaxed,
            |value| Some(value.max(nanos)),
        );
    }
}

#[cfg(feature = "transport-lab")]
static ADMISSION_PHASE_COUNTS: [AtomicU64; ADMISSION_PHASE_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[cfg(feature = "transport-lab")]
static ADMISSION_PHASE_NANOS: [AtomicU64; ADMISSION_PHASE_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[cfg(feature = "transport-lab")]
static ADMISSION_PHASE_MAX_NANOS: [AtomicU64; ADMISSION_PHASE_COUNT] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

#[cfg(feature = "transport-lab")]
pub(crate) fn reset_admission_phase_profile() {
    for counter in &ADMISSION_PHASE_COUNTS {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in &ADMISSION_PHASE_NANOS {
        counter.store(0, Ordering::Relaxed);
    }
    for counter in &ADMISSION_PHASE_MAX_NANOS {
        counter.store(0, Ordering::Relaxed);
    }
}

#[cfg(feature = "transport-lab")]
pub(crate) fn admission_phase_profile_snapshot() -> (
    [u64; ADMISSION_PHASE_COUNT],
    [u64; ADMISSION_PHASE_COUNT],
    [u64; ADMISSION_PHASE_COUNT],
) {
    let mut counts = [0; ADMISSION_PHASE_COUNT];
    let mut nanos = [0; ADMISSION_PHASE_COUNT];
    let mut max_nanos = [0; ADMISSION_PHASE_COUNT];
    for index in 0..ADMISSION_PHASE_COUNT {
        counts[index] = ADMISSION_PHASE_COUNTS[index].load(Ordering::Relaxed);
        nanos[index] = ADMISSION_PHASE_NANOS[index].load(Ordering::Relaxed);
        max_nanos[index] = ADMISSION_PHASE_MAX_NANOS[index].load(Ordering::Relaxed);
    }
    (counts, nanos, max_nanos)
}

/// A local store for one bootstrap record.
///
/// `local_slot` is deliberately only a locator.  It is hashed for the file
/// name and never enters [`BootstrapRecord`] validation or authority checks.
#[derive(Debug, Clone)]
pub struct BootstrapStore {
    path: PathBuf,
}

/// One process-local provisional custody claim carried by a durable semantic
/// snapshot. It is bookkeeping only: the fact identity and owner are stored
/// together so an interrupted write cannot publish one without the other.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProvisionalCustody {
    pub fact_id: FactId,
    pub owner: String,
}

impl ProvisionalCustody {
    pub fn new(fact_id: FactId, owner: impl Into<String>) -> Self {
        Self {
            fact_id,
            owner: owner.into(),
        }
    }
}

/// The verified result of reopening a durable semantic snapshot.
#[derive(Debug, Clone)]
pub struct RestoredSemanticState {
    graph: FactGraph,
    provisional: Vec<ProvisionalCustody>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DurableLiveCheckpoint {
    version: u16,
    generation: u64,
    graph: LiveFactGraphCheckpoint,
    provisional: Vec<ProvisionalCustody>,
    checksum: [u8; 32],
}

impl RestoredSemanticState {
    pub fn graph(&self) -> &FactGraph {
        &self.graph
    }

    pub fn provisional_custody(&self) -> &[ProvisionalCustody] {
        &self.provisional
    }

    pub(crate) fn into_parts(self) -> (FactGraph, Vec<ProvisionalCustody>) {
        (self.graph, self.provisional)
    }
}

/// A single atomic durable fact/projection/custody store.
///
/// Each hashed slot is one SQLite database. A create-new sidecar lease
/// serializes writers across processes; transactions make fact, dependency,
/// custody, proof, and commitment changes visible together.
#[derive(Debug, Clone)]
pub struct DurableSemanticStore {
    path: PathBuf,
    lock_path: PathBuf,
    process_gate: Arc<Mutex<()>>,
    policy: SemanticPolicyConfig,
    #[cfg(any(test, feature = "transport-lab"))]
    commit_injection: Arc<CommitInjectionControl>,
}

/// One-shot commit controls belong to one exact store slot.  They are test
/// and transport-lab custody only; keeping them behind the store clone means
/// a cloned owner observes the same slot-local control without introducing
/// process-global state or affecting another semantic owner.
#[cfg(any(test, feature = "transport-lab"))]
#[derive(Debug, Default)]
struct CommitInjectionControl {
    next: Mutex<Option<SemanticCommitFaultForLab>>,
}

#[cfg(any(test, feature = "transport-lab"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SemanticCommitFaultForLab {
    /// Fail after semantic SQL apply and before SQLite COMMIT. Dropping the
    /// transaction rolls back the actual SQL mutation.
    BeforeCommit,
    /// Commit the semantic delta, then lose the worker reply so the caller
    /// receives the real `OutcomeUnknown` boundary and must reconcile.
    CommitOutcomeUnknown,
}

/// The ordinary SQLite connection owned by the semantic storage worker.
///
/// This wrapper exists only to keep bounded statement collection and snapshot
/// handling in one place. It deliberately uses SQLite's default VFS; file
/// locking, WAL, sync, recovery, and checkpoint behavior remain SQLite's job.
struct SemanticSqliteConnection {
    inner: Connection,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct CheckpointReport {
    busy: bool,
    log_frames: u64,
    checkpointed_frames: u64,
}

impl SemanticSqliteConnection {
    fn query_row<T, P, F>(&self, sql: &str, params: P, map: F) -> rusqlite::Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.inner.query_row(sql, params, map)
    }

    fn prepare<T, F>(&self, sql: &str, use_statement: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&mut rusqlite::Statement<'_>) -> rusqlite::Result<T>,
    {
        let mut statement = self.inner.prepare(sql)?;
        use_statement(&mut statement)
    }

    fn with_read_snapshot<T, F>(&self, read: F) -> rusqlite::Result<T>
    where
        F: FnOnce(&Connection) -> rusqlite::Result<T>,
    {
        let transaction = self.inner.unchecked_transaction()?;
        match read(&transaction) {
            Ok(value) => {
                transaction.commit()?;
                Ok(value)
            }
            Err(error) => {
                let _ = transaction.rollback();
                Err(error)
            }
        }
    }

    fn transaction(&mut self) -> rusqlite::Result<SemanticSqliteTransaction<'_>> {
        self.inner
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map(SemanticSqliteTransaction)
    }

    fn page_size(&self) -> rusqlite::Result<u64> {
        self.pragma_u64("page_size")
    }

    fn page_count(&self) -> rusqlite::Result<u64> {
        self.pragma_u64("page_count")
    }

    fn pragma_u64(&self, name: &str) -> rusqlite::Result<u64> {
        debug_assert!(matches!(
            name,
            "page_size"
                | "page_count"
                | "max_page_count"
                | "journal_size_limit"
                | "wal_autocheckpoint"
        ));
        self.inner
            .query_row(&format!("PRAGMA {name}"), [], |row| row.get::<_, i64>(0))
            .and_then(|value| u64::try_from(value).map_err(|_| rusqlite::Error::InvalidQuery))
    }

    fn checkpoint(&self, truncate: bool) -> rusqlite::Result<CheckpointReport> {
        let sql = if truncate {
            "PRAGMA wal_checkpoint(TRUNCATE)"
        } else {
            "PRAGMA wal_checkpoint(PASSIVE)"
        };
        self.inner.query_row(sql, [], |row| {
            let busy = row.get::<_, i64>(0)?;
            let log_frames = row.get::<_, i64>(1)?;
            let checkpointed_frames = row.get::<_, i64>(2)?;
            if !matches!(busy, 0 | 1) || log_frames < 0 || checkpointed_frames < 0 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(CheckpointReport {
                busy: busy != 0,
                log_frames: u64::try_from(log_frames).map_err(|_| rusqlite::Error::InvalidQuery)?,
                checkpointed_frames: u64::try_from(checkpointed_frames)
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
            })
        })
    }
}

struct SemanticSqliteTransaction<'connection>(rusqlite::Transaction<'connection>);

impl SemanticSqliteTransaction<'_> {
    fn execute<P>(&self, sql: &str, params: P) -> rusqlite::Result<usize>
    where
        P: rusqlite::Params,
    {
        self.0.execute(sql, params)
    }

    fn execute_batch(&self, sql: &str) -> rusqlite::Result<()> {
        self.0.execute_batch(sql)
    }

    fn query_row<T, P, F>(&self, sql: &str, params: P, map: F) -> rusqlite::Result<T>
    where
        P: rusqlite::Params,
        F: FnOnce(&rusqlite::Row<'_>) -> rusqlite::Result<T>,
    {
        self.0.query_row(sql, params, map)
    }

    fn commit(self) -> rusqlite::Result<()> {
        self.0.commit()
    }
}

type WorkerValue = Box<dyn Any + Send>;
type WorkerResult = Result<WorkerValue, DurableStoreError>;
type WorkerOperation =
    Box<dyn FnOnce(&DurableSemanticStore, &mut SemanticSqliteConnection) -> WorkerResult + Send>;

enum WorkerCommand {
    Run {
        create: bool,
        reopen: bool,
        compact_after_reopen: bool,
        drop_commit_result: bool,
        operation: WorkerOperation,
        reply: Sender<WorkerResult>,
    },
    Shutdown(Sender<()>),
}

/// A bounded, process-live owner for the one SQLite connection belonging to a
/// semantic slot. The connection never crosses the worker thread boundary;
/// callers exchange only owned commands and typed results.
struct SemanticStorageWorker {
    commands: SyncSender<WorkerCommand>,
    join: Option<JoinHandle<()>>,
    poisoned: Arc<AtomicBool>,
    storage_funded: bool,
}

impl SemanticStorageWorker {
    fn start(
        store: DurableSemanticStore,
        writer_lease: WriterLease,
        storage_lease: Option<ResourceLease>,
    ) -> Result<Self, DurableStoreError> {
        // Calls are already serialized by the owner's process gate. A
        // rendezvous channel therefore transfers exactly one owned command
        // without inventing a second, hard-coded backlog or retaining burst
        // traffic outside the resource provider.
        let (commands, receiver) = sync_channel(0);
        let path = store.path.clone();
        let storage_funded = storage_lease.is_some();
        let poisoned = Arc::new(AtomicBool::new(false));
        let worker_poisoned = Arc::clone(&poisoned);
        let join = thread::Builder::new()
            .name("myownmesh-semantic-storage".into())
            .spawn(move || {
                if catch_unwind(AssertUnwindSafe(|| {
                    semantic_storage_worker_loop(
                        store,
                        receiver,
                        writer_lease,
                        storage_lease,
                        Arc::clone(&worker_poisoned),
                    )
                }))
                .is_err()
                {
                    worker_poisoned.store(true, Ordering::Release);
                }
            })
            .map_err(|source| DurableStoreError::Io { path, source })?;
        Ok(Self {
            commands,
            join: Some(join),
            poisoned,
            storage_funded,
        })
    }

    fn call<T, F>(
        &self,
        create: bool,
        reopen: bool,
        compact_after_reopen: bool,
        operation: F,
    ) -> Result<T, DurableStoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &DurableSemanticStore,
                &mut SemanticSqliteConnection,
            ) -> Result<T, DurableStoreError>
            + Send
            + 'static,
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(DurableStoreError::WorkerPanicked);
        }
        let (reply, result) = channel();
        let operation: WorkerOperation = Box::new(move |store, connection| {
            operation(store, connection).map(|value| Box::new(value) as WorkerValue)
        });
        #[cfg(feature = "transport-lab")]
        let handoff = AdmissionPhaseGuard::new(AdmissionPhase::StoreWorkerHandoff);
        self.commands
            .send(WorkerCommand::Run {
                create,
                reopen,
                compact_after_reopen,
                drop_commit_result: false,
                operation,
                reply,
            })
            .map_err(|_| {
                if self.poisoned.load(Ordering::Acquire) {
                    DurableStoreError::WorkerPanicked
                } else {
                    DurableStoreError::OwnerReleased
                }
            })?;
        #[cfg(feature = "transport-lab")]
        drop(handoff);
        let value = result.recv().map_err(|_| {
            if self.poisoned.load(Ordering::Acquire) {
                DurableStoreError::WorkerPanicked
            } else {
                DurableStoreError::OwnerReleased
            }
        })??;
        value
            .downcast::<T>()
            .map(|value| *value)
            .map_err(|_| DurableStoreError::Corrupt {
                path: PathBuf::from("semantic-worker"),
                reason: "worker result type mismatch".into(),
            })
    }

    /// Submit a commit operation while retaining the accepted-command
    /// boundary. A failed rendezvous send is definitely pre-operation; a
    /// lost result after the send is ambiguous because SQLite may already
    /// have crossed COMMIT.
    fn call_commit<F>(
        &self,
        create: bool,
        reopen: bool,
        compact_after_reopen: bool,
        drop_commit_result: bool,
        operation: F,
    ) -> Result<(), DurableStoreError>
    where
        F: FnOnce(
                &DurableSemanticStore,
                &mut SemanticSqliteConnection,
            ) -> Result<(), DurableStoreError>
            + Send
            + 'static,
    {
        if self.poisoned.load(Ordering::Acquire) {
            return Err(DurableStoreError::WorkerPanicked);
        }
        let (reply, result) = channel();
        let operation: WorkerOperation = Box::new(move |store, connection| {
            operation(store, connection).map(|()| Box::new(()) as WorkerValue)
        });
        #[cfg(feature = "transport-lab")]
        let handoff = AdmissionPhaseGuard::new(AdmissionPhase::StoreWorkerHandoff);
        self.commands
            .send(WorkerCommand::Run {
                create,
                reopen,
                compact_after_reopen,
                drop_commit_result,
                operation,
                reply,
            })
            .map_err(|_| {
                if self.poisoned.load(Ordering::Acquire) {
                    DurableStoreError::WorkerPanicked
                } else {
                    DurableStoreError::OwnerReleased
                }
            })?;
        #[cfg(feature = "transport-lab")]
        drop(handoff);
        result
            .recv()
            .map_err(|_| DurableStoreError::OutcomeUnknown)??;
        Ok(())
    }

    fn shutdown(mut self) -> Result<(), DurableStoreError> {
        let (reply, result) = channel();
        let sent = self.commands.send(WorkerCommand::Shutdown(reply)).is_ok();
        if sent {
            let _ = result.recv();
        }
        drop(self.commands);
        let joined = self
            .join
            .take()
            .map(|join| join.join().is_ok())
            .unwrap_or(true);
        if sent && joined && !self.poisoned.load(Ordering::Acquire) {
            Ok(())
        } else {
            Err(DurableStoreError::WorkerPanicked)
        }
    }
}

fn semantic_storage_worker_loop(
    store: DurableSemanticStore,
    receiver: Receiver<WorkerCommand>,
    _writer_lease: WriterLease,
    _storage_lease: Option<ResourceLease>,
    poisoned: Arc<AtomicBool>,
) {
    let mut connection: Option<SemanticSqliteConnection> = None;
    while let Ok(command) = receiver.recv() {
        let (create, reopen, compact_after_reopen, drop_commit_result, operation, reply) =
            match command {
                WorkerCommand::Run {
                    create,
                    reopen,
                    compact_after_reopen,
                    drop_commit_result,
                    operation,
                    reply,
                } => (
                    create,
                    reopen,
                    compact_after_reopen,
                    drop_commit_result,
                    operation,
                    reply,
                ),
                WorkerCommand::Shutdown(reply) => {
                    let closing = connection.take();
                    drop(closing);
                    let _ = reply.send(());
                    break;
                }
            };
        let result = catch_unwind(AssertUnwindSafe(|| {
            let mut result = if connection.is_none() {
                match store.open_database(create) {
                    Ok(opened) => {
                        connection = Some(opened);
                        operation(&store, connection.as_mut().expect("worker connection"))
                    }
                    Err(error) => Err(error),
                }
            } else {
                operation(&store, connection.as_mut().expect("worker connection"))
            };
            if result.is_ok() && reopen {
                connection.take();
                if let Err(error) = match store.open_database(false) {
                    Ok(opened) => {
                        connection = Some(opened);
                        if compact_after_reopen {
                            store.checkpoint_and_compact_connection(
                                connection.as_ref().expect("worker connection"),
                            )
                        } else {
                            Ok(())
                        }
                    }
                    Err(error) => Err(error),
                } {
                    result = Err(error);
                }
            }
            result
        }));
        match result {
            Ok(result) => {
                if drop_commit_result
                    && matches!(
                        &result,
                        Err(DurableStoreError::InjectedCommitOutcomeUnknown)
                    )
                {
                    // The SQLite COMMIT already succeeded.  Dropping only
                    // this reply models a lost owner result while retaining
                    // the worker/connection for the caller's reconciliation.
                    drop(reply);
                    continue;
                }
                let _ = reply.send(result);
            }
            Err(_) => {
                poisoned.store(true, Ordering::Release);
                let _ = reply.send(Err(DurableStoreError::WorkerPanicked));
                break;
            }
        }
    }
    drop(connection);
}

/// The process/lifetime owner of one writable semantic slot. Graph commits
/// and proof-outbox mutations may share this owner; no second writer can open
/// the slot until the owner is dropped (including on process death).
pub struct DurableSemanticOwner {
    store: DurableSemanticStore,
    worker: Mutex<Option<SemanticStorageWorker>>,
}

impl std::fmt::Debug for DurableSemanticOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DurableSemanticOwner")
            .field("store", &self.store)
            .field(
                "writer_live",
                &self
                    .worker
                    .lock()
                    .map(|worker| worker.is_some())
                    .unwrap_or(false),
            )
            .field(
                "storage_live",
                &self
                    .worker
                    .lock()
                    .map(|worker| {
                        worker
                            .as_ref()
                            .map(|worker| worker.storage_funded)
                            .unwrap_or(false)
                    })
                    .unwrap_or(false),
            )
            .finish()
    }
}

#[derive(Debug, Clone)]
struct V4StoreAggregate {
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    quarantined: Vec<SignedFact>,
    /// True when `facts` is stored in causal admission order. Older version-3
    /// databases did not record this marker and use the legacy rebuild.
    admission_ordered: bool,
    /// Version-2 domain-separated Patricia-Merkle projection root.
    projection_commitment: [u8; 32],
    provisional: Vec<ProvisionalCustody>,
    proofs: Vec<ProofRecord>,
}

#[derive(Debug, Clone)]
struct PlannedDeltaRow {
    fact: SignedFact,
    status: SemanticFactStatus,
    existing: bool,
    promote: bool,
}

#[derive(Debug, Clone)]
struct PlannedDeltaRemoval {
    id: FactId,
    author: [u8; 32],
    encoded_bytes: u64,
    dependency_count: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct SemanticUsage {
    admitted_count: u64,
    admitted_bytes: u64,
    quarantined_count: u64,
    quarantined_bytes: u64,
    dependency_edges: u64,
    provisional_count: u64,
    author_usage_rows: u64,
    generation: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct AuthorUsage {
    retained_count: u64,
    retained_bytes: u64,
    quarantined_count: u64,
    quarantined_bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct ProofUsage {
    total_count: u64,
    total_bytes: u64,
    total_links: u64,
    pending_count: u64,
    pending_bytes: u64,
    generation: u64,
}

#[derive(Debug, Clone)]
struct SemanticDeltaPlan {
    base_usage: SemanticUsage,
    usage: SemanticUsage,
    author_usage: std::collections::BTreeMap<[u8; 32], AuthorUsage>,
    /// Version-2 projection root expected before and after this atomic delta.
    expected_base_projection: [u8; 32],
    projection_commitment: [u8; 32],
    rows: Vec<PlannedDeltaRow>,
    removed: Vec<PlannedDeltaRemoval>,
    custody_added: Vec<ProvisionalCustody>,
    custody_removed: Vec<FactId>,
    changed: bool,
}

#[derive(Debug)]
struct WriterLease {
    #[cfg(not(any(unix, windows)))]
    path: PathBuf,
    #[cfg(unix)]
    _file: std::fs::File,
    #[cfg(windows)]
    _file: std::fs::File,
}

impl WriterLease {
    fn acquire(path: &Path) -> Result<Self, DurableStoreError> {
        #[cfg(unix)]
        {
            let mut options = OpenOptions::new();
            options.read(true).write(true).create(true);
            let mut file = options.open(path).map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            // LOCK_NB keeps a competing process fail-closed rather than
            // waiting behind an unbounded writer. The kernel releases this
            // advisory lease if its process is interrupted.
            const LOCK_EX: std::os::raw::c_int = 2;
            const LOCK_NB: std::os::raw::c_int = 4;
            if unsafe { flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) } != 0 {
                return Err(DurableStoreError::WriterBusy {
                    path: path.to_path_buf(),
                });
            }
            file.set_len(0).map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            writeln!(file, "pid={}", std::process::id()).map_err(|source| {
                DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                }
            })?;
            file.sync_all().map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(Self { _file: file })
        }

        #[cfg(windows)]
        {
            // Delete-on-close makes a hard-dead writer recoverable without
            // unlink/recreate races or a PID/timeout oracle. The zero share
            // mode keeps the live lease exclusive across processes.
            const FILE_FLAG_DELETE_ON_CLOSE: u32 = 0x0400_0000;
            let mut options = OpenOptions::new();
            options
                .read(true)
                .write(true)
                .create_new(true)
                .share_mode(0)
                .custom_flags(FILE_FLAG_DELETE_ON_CLOSE);
            let mut file = options.open(path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableStoreError::WriterBusy {
                        path: path.to_path_buf(),
                    }
                } else {
                    DurableStoreError::Io {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
            if let Err(source) = writeln!(file, "pid={}", std::process::id()) {
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            file.sync_all().map_err(|source| DurableStoreError::Io {
                path: path.to_path_buf(),
                source,
            })?;
            Ok(Self { _file: file })
        }

        #[cfg(not(any(unix, windows)))]
        {
            let mut file = OpenOptions::new();
            file.write(true).create_new(true);
            let mut file = file.open(path).map_err(|source| {
                if source.kind() == std::io::ErrorKind::AlreadyExists {
                    DurableStoreError::WriterBusy {
                        path: path.to_path_buf(),
                    }
                } else {
                    DurableStoreError::Io {
                        path: path.to_path_buf(),
                        source,
                    }
                }
            })?;
            if let Err(source) = writeln!(file, "pid={}", std::process::id()) {
                let _ = std::fs::remove_file(path);
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            if let Err(source) = file.sync_all() {
                let _ = std::fs::remove_file(path);
                return Err(DurableStoreError::Io {
                    path: path.to_path_buf(),
                    source,
                });
            }
            Ok(Self {
                path: path.to_path_buf(),
            })
        }
    }
}

#[cfg(unix)]
unsafe extern "C" {
    fn flock(fd: std::os::raw::c_int, operation: std::os::raw::c_int) -> std::os::raw::c_int;
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            const LOCK_UN: std::os::raw::c_int = 8;
            let _ = unsafe { flock(self._file.as_raw_fd(), LOCK_UN) };
        }
        // Unix deliberately retains the lock pathname. flock owns the
        // inode lease and removing the name after unlock would permit a
        // competing process to create a second inode in the gap. Windows
        // uses FILE_FLAG_DELETE_ON_CLOSE, so the kernel removes its path
        // only after the owning handle is gone.
        #[cfg(not(any(unix, windows)))]
        let _ = std::fs::remove_file(&self.path);
    }
}

impl BootstrapStore {
    /// Open a store rooted below one explicit instance directory.
    pub fn new(instance_root: impl Into<PathBuf>, local_slot: impl AsRef<str>) -> Self {
        let digest = Sha256::digest(local_slot.as_ref().as_bytes());
        let slot = BASE32_NOPAD.encode(&digest).to_lowercase();
        Self {
            path: instance_root
                .into()
                .join(BOOTSTRAP_DIRECTORY)
                .join(format!("{slot}.json")),
        }
    }

    /// The resolved storage path, exposed for diagnostics and controls only.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Persist a newly created local record, or return the identical record
    /// already established at this slot. Local creation is crate-local and
    /// requires the authenticated process principal; callers cannot turn an
    /// arbitrary record into first-install authority from outside the crate.
    pub(crate) fn persist_new<R>(
        &self,
        principal: &crate::application_gateway::LocalPrincipalCapability,
        record: R,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError>
    where
        R: Borrow<BootstrapRecord>,
    {
        let verified = VerifiedBootstrap::from_record(record.borrow().clone())
            .map_err(BootstrapStoreError::Invalid)?;
        let _expected_context =
            ExpectedMeshContext::for_local_import(principal, verified.context_id());
        self.persist_verified(verified)
    }

    /// Import a record only when it matches the already authenticated context.
    ///
    /// The candidate is fully verified before the store is consulted, and the
    /// sealed expected context is compared before any install can occur.
    pub fn import_expected<R>(
        &self,
        expected_context: &ExpectedMeshContext,
        record: R,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError>
    where
        R: Borrow<BootstrapRecord>,
    {
        let verified = VerifiedBootstrap::from_record(record.borrow().clone())
            .map_err(BootstrapStoreError::Invalid)?;
        if !expected_context.matches(&verified.context_id()) {
            return Err(BootstrapStoreError::ContextMismatch {
                expected: expected_context.context_id(),
                actual: verified.context_id(),
            });
        }
        self.persist_verified(verified)
    }

    /// Restore and verify the exact persisted pair.
    pub fn restore(&self) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let record = self
            .read_record()?
            .ok_or_else(|| BootstrapStoreError::Missing {
                path: self.path.clone(),
            })?;
        VerifiedBootstrap::from_record(record).map_err(|source| BootstrapStoreError::Corrupt {
            path: self.path.clone(),
            reason: source.to_string(),
        })
    }

    /// Restore and verify the record expected for an authenticated context.
    #[cfg(test)]
    pub fn restore_expected(
        &self,
        expected_context: &ExpectedMeshContext,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let verified = self.restore()?;
        if !expected_context.matches(&verified.context_id()) {
            return Err(BootstrapStoreError::ContextMismatch {
                expected: expected_context.context_id(),
                actual: verified.context_id(),
            });
        }
        Ok(verified)
    }

    fn persist_verified(
        &self,
        verified: VerifiedBootstrap,
    ) -> Result<VerifiedBootstrap, BootstrapStoreError> {
        let bytes = serde_json::to_vec(verified.record())?;

        if let Some(existing) = self.read_record()? {
            if existing == *verified.record() {
                let parent = self
                    .path
                    .parent()
                    .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
                sync_directory_chain(parent)?;
                return Ok(verified);
            }
            return Err(BootstrapStoreError::Conflict {
                path: self.path.clone(),
            });
        }

        let parent = self
            .path
            .parent()
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        ensure_directory_chain(parent)?;
        sync_directory_chain(parent)?;
        let temp = self.write_temp(&bytes)?;
        match std::fs::hard_link(&temp, &self.path) {
            Ok(()) => {
                let _ = std::fs::remove_file(&temp);
                sync_directory_chain(parent)?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let _ = std::fs::remove_file(&temp);
                let existing = self.read_record()?.ok_or_else(|| BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::NotFound,
                        "bootstrap appeared and disappeared during create",
                    ),
                })?;
                if existing == *verified.record() {
                    sync_directory_chain(parent)?;
                    return Ok(verified);
                }
                return Err(BootstrapStoreError::Conflict {
                    path: self.path.clone(),
                });
            }
            Err(source) => {
                let _ = std::fs::remove_file(&temp);
                return Err(BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        }
        Ok(verified)
    }

    fn write_temp(&self, bytes: &[u8]) -> Result<PathBuf, BootstrapStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        let name = self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .ok_or_else(|| BootstrapStoreError::InvalidPath(self.path.clone()))?;
        let counter = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let temp = parent.join(format!(".{name}.{}.{}.tmp", std::process::id(), counter));
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&temp)
            .map_err(|source| BootstrapStoreError::Io {
                path: temp.clone(),
                source,
            })?;
        if let Err(source) = file.write_all(bytes).and_then(|_| file.sync_all()) {
            let _ = std::fs::remove_file(&temp);
            return Err(BootstrapStoreError::Io { path: temp, source });
        }
        Ok(temp)
    }

    fn read_record(&self) -> Result<Option<BootstrapRecord>, BootstrapStoreError> {
        let bytes = match std::fs::read(&self.path) {
            Ok(bytes) => bytes,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        };
        let record: BootstrapRecord =
            serde_json::from_slice(&bytes).map_err(|source| BootstrapStoreError::Corrupt {
                path: self.path.clone(),
                reason: source.to_string(),
            })?;
        VerifiedBootstrap::from_record(record.clone()).map_err(|source| {
            BootstrapStoreError::Corrupt {
                path: self.path.clone(),
                reason: source.to_string(),
            }
        })?;
        Ok(Some(record))
    }
}

impl DurableSemanticStore {
    #[cfg(any(test, feature = "transport-lab"))]
    pub fn new(instance_root: impl Into<PathBuf>, local_slot: impl AsRef<str>) -> Self {
        Self::with_policy(instance_root, local_slot, SemanticPolicyConfig::default())
    }

    /// Construct a store with the caller's already-validated semantic policy.
    /// No database or writer lease is opened until an operation is requested.
    pub fn with_policy(
        instance_root: impl Into<PathBuf>,
        local_slot: impl AsRef<str>,
        policy: SemanticPolicyConfig,
    ) -> Self {
        let root = instance_root.into();
        let digest = Sha256::digest(local_slot.as_ref().as_bytes());
        let slot = BASE32_NOPAD.encode(&digest).to_lowercase();
        let directory = root.join(SEMANTIC_DIRECTORY);
        Self {
            path: directory.join(format!("{slot}-{SEMANTIC_DATABASE_FILE}")),
            lock_path: directory.join(format!("{slot}.lock")),
            process_gate: Arc::new(Mutex::new(())),
            policy: policy,
            #[cfg(any(test, feature = "transport-lab"))]
            commit_injection: Arc::new(CommitInjectionControl::default()),
        }
    }

    /// Arm one exact, one-shot owner-commit control for deterministic
    /// transport-lab and unit evidence.  The control is slot-local and is
    /// consumed only at its named commit boundary; it is never production
    /// behavior or shared cross-test state.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn arm_commit_injection(
        &self,
        injection: SemanticCommitFaultForLab,
    ) -> Result<(), DurableStoreError> {
        let mut next = self
            .commit_injection
            .next
            .lock()
            .map_err(|_| DurableStoreError::CommitInjectionPoisoned)?;
        if next.is_some() {
            return Err(DurableStoreError::CommitInjectionAlreadyArmed);
        }
        *next = Some(injection);
        Ok(())
    }

    #[cfg(any(test, feature = "transport-lab"))]
    fn take_commit_injection(&self, expected: SemanticCommitFaultForLab) -> bool {
        let Ok(mut next) = self.commit_injection.next.lock() else {
            return false;
        };
        if *next == Some(expected) {
            *next = None;
            true
        } else {
            false
        }
    }

    #[cfg(any(test, feature = "transport-lab"))]
    fn commit_injection_is_armed(&self, expected: SemanticCommitFaultForLab) -> bool {
        self.commit_injection
            .next
            .lock()
            .map(|next| *next == Some(expected))
            .unwrap_or(false)
    }

    fn encode_stored_fact(&self, fact: &SignedFact) -> Result<Vec<u8>, DurableStoreError> {
        super::storage_codec::encode(fact).map_err(|reason| DurableStoreError::Rebuild {
            path: self.path.clone(),
            reason: format!("fact storage encoding failed: {reason}"),
        })
    }

    fn decode_stored_fact(
        &self,
        encoded: &[u8],
        context: MeshContextId,
        author: &[u8],
        fact_id: &[u8],
    ) -> Result<SignedFact, DurableStoreError> {
        let author: [u8; 32] = author.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "invalid fact author index".into(),
        })?;
        let fact_id: [u8; 32] = fact_id.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "invalid fact id index".into(),
        })?;
        super::storage_codec::decode(encoded, context, author, fact_id).map_err(|reason| {
            DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: format!("invalid stored fact: {reason}"),
            }
        })
    }

    fn context_id_from_connection(
        &self,
        connection: &Connection,
    ) -> Result<MeshContextId, DurableStoreError> {
        let context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        let context: [u8; 32] = context.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "invalid context id".into(),
        })?;
        Ok(MeshContextId::from_bytes(context))
    }

    fn canonical_fact_bytes(fact: &SignedFact) -> Result<u64, DurableStoreError> {
        u64::try_from(serde_json::to_vec(fact)?.len()).map_err(|_| DurableStoreError::InvalidPolicy)
    }

    /// Remove this instance's canonical semantic snapshot while holding both
    /// the in-process gate and the cross-process writer lease.  The lease
    /// pathname is deliberately retained: it is the stable identity of this
    /// exact `(instance_root, local_slot)` slot, not disposable snapshot data.
    /// An active [`DurableSemanticOwner`] therefore makes purge fail closed
    /// with [`DurableStoreError::WriterBusy`] instead of racing its final
    /// publication.
    #[cfg(test)]
    pub fn purge(&self) -> Result<(), DurableStoreError> {
        let _gate = self.lock_process()?;
        let lease = WriterLease::acquire(&self.lock_path)?;
        let result = self.purge_storage_slot();
        drop(lease);
        result
    }

    fn purge_storage_slot(&self) -> Result<(), DurableStoreError> {
        let database_path = self.resolved_database_path()?;
        // Purge already holds the in-process gate and the cross-process
        // writer lease. It intentionally destroys the slot, so opening or
        // checkpointing the database first is unnecessary and would prevent
        // an operator from purging a corrupt/non-SQLite main file. Remove
        // sidecars before the main file so no surviving WAL can be paired
        // with a later database created at the same pathname.
        for path in [
            database_path.with_extension("sqlite3-journal"),
            database_path.with_extension("sqlite3-wal"),
            database_path.with_extension("sqlite3-shm"),
            database_path.clone(),
        ] {
            match std::fs::remove_file(&path) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(source) => return Err(DurableStoreError::Io { path, source }),
            }
        }
        #[cfg(unix)]
        {
            let parent = database_path
                .parent()
                .ok_or_else(|| DurableStoreError::InvalidPath(database_path.clone()))?;
            let directory =
                std::fs::File::open(parent).map_err(|source| DurableStoreError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
            directory
                .sync_all()
                .map_err(|source| DurableStoreError::Io {
                    path: parent.to_path_buf(),
                    source,
                })?;
        }
        Ok(())
    }

    fn resolved_database_path(&self) -> Result<PathBuf, DurableStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let canonical_parent =
            std::fs::canonicalize(parent).map_err(|source| DurableStoreError::Io {
                path: parent.to_path_buf(),
                source,
            })?;
        #[cfg(windows)]
        let canonical_parent = canonical_parent
            .strip_prefix(r"\\?\")
            .unwrap_or(canonical_parent.as_path())
            .to_path_buf();
        let file_name = self
            .path
            .file_name()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        Ok(canonical_parent.join(file_name))
    }

    fn lock_process(&self) -> Result<MutexGuard<'_, ()>, DurableStoreError> {
        self.process_gate
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)
    }

    /// The resolved snapshot path, exposed for diagnostics and interruption
    /// controls only.
    #[cfg(test)]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Commit facts, their derived projection commitment, and provisional
    /// custody in one SQLite transaction. The writer lease covers validation
    /// and publication, so a competing process cannot interleave a partial
    /// state.
    #[cfg(test)]
    pub fn commit<I>(&self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let lease = self.begin_write()?;
        lease.commit(graph, provisional)
    }

    /// Acquire the cross-process writer lease and hold it until commit or
    /// drop. Readers remain lock-free and only consume complete snapshots.
    #[cfg(test)]
    pub fn begin_write(&self) -> Result<DurableSemanticWriter, DurableStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let lease = WriterLease::acquire(&self.lock_path)?;
        Ok(DurableSemanticWriter {
            store: self.clone(),
            lease,
        })
    }

    /// Open the slot for the entire lifetime of the semantic owner. This is
    /// the shared writable gate used by a live NetworkState and its proof
    /// outbox; a competing process is refused before state publication.
    #[cfg(test)]
    pub fn open_writable(&self) -> Result<DurableSemanticOwner, DurableStoreError> {
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let lease = WriterLease::acquire(&self.lock_path)?;
        let worker = SemanticStorageWorker::start(self.clone(), lease, None)?;
        Ok(DurableSemanticOwner {
            store: self.clone(),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Return the exact finite StorageBytes claim for this slot. The claim is
    /// the checked database envelope: main database, MainJournal, WAL, SHM,
    /// and the unspendable emergency reserve are all funded before opening.
    pub(crate) fn storage_claim(&self) -> Result<ResourceClaim, DurableStoreError> {
        let envelope = self
            .policy
            .checked_storage_envelope(
                crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES,
                self.policy.storage_workload(),
            )
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        Ok(ResourceClaim::single(
            ResourceClass::StorageBytes,
            envelope.total_bytes,
        ))
    }

    /// Open a writable owner with caller-funded StorageBytes custody. If
    /// directory creation or writer-lease acquisition fails, the supplied
    /// lease is dropped here and returned to its provider by its Drop path.
    pub(crate) fn open_writable_funded(
        &self,
        storage_lease: ResourceLease,
    ) -> Result<DurableSemanticOwner, DurableStoreError> {
        if storage_lease.claim() != self.storage_claim()? {
            return Err(DurableStoreError::InvalidPolicy);
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| DurableStoreError::InvalidPath(self.path.clone()))?;
        std::fs::create_dir_all(parent).map_err(|source| DurableStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })?;
        let lease = WriterLease::acquire(&self.lock_path)?;
        let worker = SemanticStorageWorker::start(self.clone(), lease, Some(storage_lease))?;
        Ok(DurableSemanticOwner {
            store: self.clone(),
            worker: Mutex::new(Some(worker)),
        })
    }

    /// Reopen, verify, and rebuild the exact graph and projection commitment.
    /// A stale temporary file from an interrupted writer is ignored because
    /// the published snapshot itself is never truncated.
    #[cfg(test)]
    pub fn restore(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let _gate = self.lock_process()?;
        self.restore_unlocked(bootstrap)
    }

    /// Verify the canonical representation and checkpoint the WAL under the
    /// writer lease. Compaction never prunes authority history.
    #[cfg(test)]
    pub fn compact(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let _gate = self.lock_process()?;
        let lease = self.begin_write()?;
        let state = self.restore_unlocked(bootstrap)?;
        lease.store.checkpoint_and_compact()?;
        Ok(state)
    }

    #[cfg(test)]
    pub(crate) fn proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let _gate = self.lock_process()?;
        self.proof_records_unlocked(context_id)
    }

    #[cfg(test)]
    pub(crate) fn pending_proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let _gate = self.lock_process()?;
        let connection = self.open_database(true)?;
        self.pending_proof_records_connection(&connection, context_id)
    }

    fn proof_records_unlocked(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let connection = self.open_database(false)?;
        self.proof_records_connection(&connection, context_id)
    }

    fn proof_records_connection(
        &self,
        connection: &SemanticSqliteConnection,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        connection
            .with_read_snapshot(|connection| {
                Ok(self.proof_records_in_snapshot(connection, context_id))
            })
            .map_err(DurableStoreError::Sqlite)?
    }

    fn pending_proof_records_connection(
        &self,
        connection: &SemanticSqliteConnection,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let pending_state = serde_json::to_string(&ProofRecordState::Pending)?;
        connection
            .with_read_snapshot(|connection| {
                Ok((|| -> Result<Vec<ProofRecord>, DurableStoreError> {
                    let stored_context: Vec<u8> = connection
                        .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                            row.get(0)
                        })
                        .map_err(DurableStoreError::Sqlite)?;
                    if stored_context.as_slice() != context_id.as_bytes() {
                        let actual = stored_context
                            .try_into()
                            .map(MeshContextId::from_bytes)
                            .map_err(|_| DurableStoreError::Corrupt {
                                path: self.path.clone(),
                                reason: "invalid context id".into(),
                            })?;
                        return Err(DurableStoreError::ContextMismatch {
                            expected: context_id,
                            actual,
                        });
                    }

                    // A semantic slot has one context. Refuse a mixed-context
                    // database before returning a partial Pending view; this is
                    // scalar and does not materialize terminal records.
                    let context_bytes = context_id.as_bytes().to_vec();
                    let foreign_context: Option<Vec<u8>> = connection
                        .query_row(
                            "SELECT context_id FROM proofs
                         WHERE context_id < ? ORDER BY context_id LIMIT 1",
                            params![context_bytes.clone()],
                            |row| row.get(0),
                        )
                        .optional()
                        .map_err(DurableStoreError::Sqlite)?
                        .or(connection
                            .query_row(
                                "SELECT context_id FROM proofs
                             WHERE context_id > ? ORDER BY context_id LIMIT 1",
                                params![context_bytes],
                                |row| row.get(0),
                            )
                            .optional()
                            .map_err(DurableStoreError::Sqlite)?);
                    if let Some(actual) = foreign_context {
                        let actual =
                            actual
                                .try_into()
                                .map(MeshContextId::from_bytes)
                                .map_err(|_| DurableStoreError::Corrupt {
                                    path: self.path.clone(),
                                    reason: "invalid proof context index".into(),
                                })?;
                        return Err(DurableStoreError::ContextMismatch {
                            expected: context_id,
                            actual,
                        });
                    }

                    let fixed_row_bytes = self
                        .policy
                        .max_pending_proofs
                        .checked_mul(108)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    let row_bytes = self
                        .policy
                        .max_pending_proof_bytes
                        .checked_add(fixed_row_bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    let rows = bounded_query_collect(
                        connection,
                        "SELECT delivery_id,encoded,context_id,target,state
                     FROM proofs
                     WHERE context_id=? AND state=?
                     ORDER BY delivery_id",
                        params![context_id.as_bytes().to_vec(), pending_state],
                        self.policy.max_pending_proofs,
                        row_bytes,
                        "pending proof rows",
                        |row| {
                            let delivery_id: Vec<u8> = row.get(0)?;
                            let encoded: Vec<u8> = row.get(1)?;
                            let row_context: Vec<u8> = row.get(2)?;
                            let target: Vec<u8> = row.get(3)?;
                            let state: String = row.get(4)?;
                            let bytes = [
                                delivery_id.len(),
                                encoded.len(),
                                row_context.len(),
                                target.len(),
                                state.len(),
                            ]
                            .into_iter()
                            .try_fold(
                                0u64,
                                |total, length| -> rusqlite::Result<u64> {
                                    total
                                        .checked_add(
                                            u64::try_from(length)
                                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                                        )
                                        .ok_or(rusqlite::Error::InvalidQuery)
                                },
                            )?;
                            Ok(((delivery_id, encoded, row_context, target, state), bytes))
                        },
                    )?;
                    let proofs = rows
                        .into_iter()
                        .map(|row| self.decode_proof_row(row))
                        .collect::<Result<Vec<_>, _>>()?;
                    canonical_proofs(&proofs)?;

                    let stored_usage = self.read_proof_usage_raw(connection)?;
                    let expected_usage = Self::proof_usage(&proofs, stored_usage.generation)?;
                    if expected_usage.pending_count != stored_usage.pending_count
                        || expected_usage.pending_bytes != stored_usage.pending_bytes
                    {
                        return Err(DurableStoreError::Corrupt {
                            path: self.path.clone(),
                            reason: "pending proof usage does not match indexed rows".into(),
                        });
                    }
                    if stored_usage.total_count > self.policy.max_proof_records
                        || stored_usage.total_bytes > self.policy.max_proof_bytes
                        || stored_usage.total_links > self.policy.max_proof_links
                        || expected_usage.pending_count > self.policy.max_pending_proofs
                        || expected_usage.pending_bytes > self.policy.max_pending_proof_bytes
                    {
                        return Err(DurableStoreError::LimitExceeded("pending proof retention"));
                    }

                    let mut statement = connection
                        .prepare(
                            "SELECT fact_id FROM proof_facts WHERE delivery_id=? ORDER BY fact_id",
                        )
                        .map_err(DurableStoreError::Sqlite)?;
                    for proof in &proofs {
                        let mut rows = statement
                            .query(params![proof.delivery_id.as_bytes().to_vec()])
                            .map_err(DurableStoreError::Sqlite)?;
                        let mut fact_ids = Vec::with_capacity(proof.fact_ids.len());
                        while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
                            if fact_ids.len() >= proof.fact_ids.len().saturating_add(1) {
                                return Err(DurableStoreError::LimitExceeded("proof links"));
                            }
                            let value: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
                            let value: [u8; 32] =
                                value.try_into().map_err(|_| DurableStoreError::Corrupt {
                                    path: self.path.clone(),
                                    reason: "invalid pending proof fact link".into(),
                                })?;
                            fact_ids.push(FactId::from_bytes(value));
                        }
                        if fact_ids != proof.fact_ids {
                            return Err(DurableStoreError::Corrupt {
                                path: self.path.clone(),
                                reason: "pending proof fact index does not match proof bytes"
                                    .into(),
                            });
                        }
                    }
                    Ok(proofs)
                })())
            })
            .map_err(DurableStoreError::Sqlite)?
    }

    fn proof_records_in_snapshot(
        &self,
        connection: &Connection,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let stored_context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        if stored_context.as_slice() != context_id.as_bytes() {
            let actual = stored_context
                .try_into()
                .map(MeshContextId::from_bytes)
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid context id".into(),
                })?;
            return Err(DurableStoreError::ContextMismatch {
                expected: context_id,
                actual,
            });
        }

        let rows = bounded_query_collect(
            connection,
            "SELECT delivery_id,encoded,context_id,target,state FROM proofs ORDER BY delivery_id",
            [],
            self.policy.max_proof_records,
            self.policy.max_proof_bytes,
            "proof rows",
            |row| {
                let delivery_id: Vec<u8> = row.get(0)?;
                let encoded: Vec<u8> = row.get(1)?;
                let row_context: Vec<u8> = row.get(2)?;
                let target: Vec<u8> = row.get(3)?;
                let state: String = row.get(4)?;
                let bytes =
                    u64::try_from(encoded.len()).map_err(|_| rusqlite::Error::InvalidQuery)?;
                Ok(((delivery_id, encoded, row_context, target, state), bytes))
            },
        )?;
        let proofs = rows
            .into_iter()
            .map(|row| self.decode_proof_row(row))
            .collect::<Result<Vec<_>, _>>()?;
        canonical_proofs(&proofs)?;
        if proofs.iter().any(|proof| proof.context_id != context_id) {
            return Err(DurableStoreError::ContextMismatch {
                expected: context_id,
                actual: proofs
                    .iter()
                    .find(|proof| proof.context_id != context_id)
                    .expect("mismatched proof exists")
                    .context_id,
            });
        }

        let mut statement = connection
            .prepare("SELECT fact_id FROM proof_facts WHERE delivery_id=? ORDER BY fact_id")
            .map_err(DurableStoreError::Sqlite)?;
        for proof in &proofs {
            let mut rows = statement
                .query(params![proof.delivery_id.as_bytes().to_vec()])
                .map_err(DurableStoreError::Sqlite)?;
            let mut fact_ids = Vec::with_capacity(proof.fact_ids.len());
            while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
                if fact_ids.len() >= proof.fact_ids.len().saturating_add(1) {
                    return Err(DurableStoreError::LimitExceeded("proof links"));
                }
                let value: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
                let value: [u8; 32] = value.try_into().map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid proof fact link".into(),
                })?;
                fact_ids.push(FactId::from_bytes(value));
            }
            if fact_ids != proof.fact_ids {
                return Err(DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "proof fact index does not match proof bytes".into(),
                });
            }
        }
        drop(statement);

        let orphaned: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM proof_facts pf
                 LEFT JOIN facts f ON f.fact_id=pf.fact_id
                 LEFT JOIN proofs p ON p.delivery_id=pf.delivery_id
                 WHERE f.fact_id IS NULL OR p.delivery_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if orphaned != 0 {
            return Err(DurableStoreError::UnknownProofFact);
        }
        let stored = self.read_proof_usage_raw(connection)?;
        let expected = Self::proof_usage(&proofs, stored.generation)?;
        if stored != expected {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "proof usage does not match normalized rows".into(),
            });
        }
        Ok(proofs)
    }

    fn admitted_causal_history_in_snapshot(
        &self,
        connection: &Connection,
        roots: &[FactId],
    ) -> Result<Vec<SignedFact>, DurableStoreError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders = std::iter::repeat_n("(?)", roots.len())
            .collect::<Vec<_>>()
            .join(",");
        let sql = format!(
            "WITH RECURSIVE roots(fact_id) AS (VALUES {placeholders}),
             closure(fact_id) AS (
                 SELECT fact_id FROM roots
                 UNION
                 SELECT d.dep_id FROM dependencies d JOIN closure c ON d.fact_id=c.fact_id
             )
             SELECT f.fact_id,f.encoded,f.author
             FROM facts f JOIN closure c ON c.fact_id=f.fact_id
             WHERE f.status='admitted'
             ORDER BY f.seq"
        );
        let values = roots
            .iter()
            .map(|id| id.as_bytes().to_vec())
            .collect::<Vec<_>>();
        let params = rusqlite::params_from_iter(values.iter());
        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = bounded_query_collect(
            connection,
            &sql,
            params,
            self.policy.max_proof_links,
            self.policy.max_proof_bytes,
            "causal verification history",
            |row| {
                let id: Vec<u8> = row.get(0)?;
                let encoded: Vec<u8> = row.get(1)?;
                let author: Vec<u8> = row.get(2)?;
                let bytes = u64::try_from(id.len())
                    .ok()
                    .and_then(|value| value.checked_add(u64::try_from(encoded.len()).ok()?))
                    .and_then(|value| value.checked_add(u64::try_from(author.len()).ok()?))
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                Ok(((id, encoded, author), bytes))
            },
        )?;
        let context = self.context_id_from_connection(connection)?;
        rows.into_iter()
            .map(|(id, encoded, author)| self.decode_stored_fact(&encoded, context, &author, &id))
            .collect()
    }

    fn provisional_in_snapshot(
        &self,
        connection: &Connection,
    ) -> Result<Vec<ProvisionalCustody>, DurableStoreError> {
        let rows: Vec<(Vec<u8>, String)> = bounded_query_collect(
            connection,
            "SELECT fact_id,owner FROM provisional ORDER BY fact_id,owner",
            [],
            self.policy.max_provisional_rows,
            self.policy
                .max_provisional_rows
                .checked_mul(32 + SEMANTIC_INGRESS_OWNER_MAX_BYTES)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "provisional rows",
            |row| {
                let fact_id: Vec<u8> = row.get(0)?;
                let owner: String = row.get(1)?;
                let bytes = u64::try_from(fact_id.len())
                    .ok()
                    .and_then(|value| value.checked_add(u64::try_from(owner.len()).ok()?))
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                Ok(((fact_id, owner), bytes))
            },
        )?;
        canonical_provisional(
            rows.into_iter()
                .map(|(fact_id, owner)| {
                    let fact_id: [u8; 32] =
                        fact_id.try_into().map_err(|_| DurableStoreError::Corrupt {
                            path: self.path.clone(),
                            reason: "invalid provisional fact id".into(),
                        })?;
                    Ok(ProvisionalCustody {
                        fact_id: FactId::from_bytes(fact_id),
                        owner,
                    })
                })
                .collect::<Result<Vec<_>, DurableStoreError>>()?,
        )
    }

    #[cfg(test)]
    pub(crate) fn mutate_proof_records<F>(
        &self,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError>,
    {
        let _gate = self.lock_process()?;
        self.mutate_proof_records_locked(context_id, mutation)
    }

    #[cfg(test)]
    fn mutate_proof_records_locked<F>(
        &self,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError>,
    {
        let mut connection = self.open_database(true)?;
        self.mutate_proof_records_on_connection(&mut connection, context_id, mutation)
    }

    #[cfg(test)]
    fn mutate_proof_records_on_connection<F>(
        &self,
        connection: &mut SemanticSqliteConnection,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError>,
    {
        let mut snapshot = self.load_snapshot_connection(&connection, &self.path)?;
        self.validate_aggregate_limits(&snapshot)?;
        if snapshot.context_id != context_id {
            return Err(DurableStoreError::ContextMismatch {
                expected: context_id,
                actual: snapshot.context_id,
            });
        }
        let previous_proofs = snapshot.proofs.clone();
        mutation(&mut snapshot.proofs)?;
        canonical_proofs(&snapshot.proofs)?;
        validate_proofs_for_aggregate(&snapshot)?;
        self.validate_aggregate_limits(&snapshot)?;
        if previous_proofs == snapshot.proofs {
            return Ok(snapshot.proofs);
        }
        self.preflight_capacity(&connection)?;
        let transaction = connection
            .transaction()
            .map_err(DurableStoreError::Sqlite)?;
        let proof_generation = self
            .read_proof_usage_tx(&transaction)?
            .generation
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        Self::persist_proof_delta(&transaction, &previous_proofs, &snapshot.proofs)?;
        Self::write_proof_usage(
            &transaction,
            Self::proof_usage(&snapshot.proofs, proof_generation)?,
        )?;
        transaction.commit().map_err(DurableStoreError::Sqlite)?;
        Ok(snapshot.proofs)
    }

    fn read_snapshot(&self) -> Result<V4StoreAggregate, DurableStoreError> {
        let connection = self.open_database(false)?;
        let snapshot = self.load_snapshot_connection(&connection, &self.path)?;
        self.validate_aggregate_limits(&snapshot)?;
        Ok(snapshot)
    }

    fn ensure_pending_proof_index(connection: &Connection) -> Result<(), DurableStoreError> {
        let proofs_table: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master
                 WHERE type='table' AND name='proofs'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if proofs_table != 0 {
            connection
                .execute_batch(
                    "CREATE INDEX IF NOT EXISTS proofs_pending_idx
                     ON proofs(context_id,state,delivery_id);",
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        Ok(())
    }

    fn open_database(&self, create: bool) -> Result<SemanticSqliteConnection, DurableStoreError> {
        if !self.policy.validate() {
            return Err(DurableStoreError::InvalidPolicy);
        }
        if !self.path.is_absolute() {
            return Err(DurableStoreError::InvalidPath(self.path.clone()));
        }
        match std::fs::metadata(&self.path) {
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && !create => {
                return Err(DurableStoreError::Missing {
                    path: self.path.clone(),
                });
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => {
                return Err(DurableStoreError::Io {
                    path: self.path.clone(),
                    source,
                });
            }
        }
        let database_path = self.resolved_database_path()?;
        let envelope = self
            .policy
            .checked_storage_envelope(
                crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES,
                self.policy.storage_workload(),
            )
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        let mut flags = rusqlite::OpenFlags::SQLITE_OPEN_READ_WRITE
            | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX
            | rusqlite::OpenFlags::SQLITE_OPEN_NOFOLLOW;
        if create {
            flags |= rusqlite::OpenFlags::SQLITE_OPEN_CREATE;
        }
        let connection = Connection::open_with_flags(&database_path, flags)
            .map_err(DurableStoreError::Sqlite)?;
        connection
            .busy_timeout(Duration::from_secs(5))
            .map_err(DurableStoreError::Sqlite)?;

        let configured_page_size = i64::try_from(crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES)
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        connection
            .pragma_update(None, "page_size", configured_page_size)
            .map_err(DurableStoreError::Sqlite)?;
        let journal_mode: String = connection
            .query_row("PRAGMA journal_mode=WAL", [], |row| row.get(0))
            .map_err(DurableStoreError::Sqlite)?;
        if !journal_mode.eq_ignore_ascii_case("wal") {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: format!("SQLite refused WAL mode: {journal_mode}"),
            });
        }
        connection
            .execute_batch(
                "PRAGMA synchronous=FULL;
                 PRAGMA foreign_keys=ON;
                 PRAGMA trusted_schema=OFF;",
            )
            .map_err(DurableStoreError::Sqlite)?;

        let max_pages =
            i64::try_from(envelope.main_pages).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let journal_limit =
            i64::try_from(envelope.wal_hard_bytes).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let autocheckpoint = i64::try_from(envelope.wal_checkpoint_frames)
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        connection
            .execute_batch(&format!(
                "PRAGMA max_page_count={max_pages};
                 PRAGMA journal_size_limit={journal_limit};
                 PRAGMA wal_autocheckpoint={autocheckpoint};"
            ))
            .map_err(DurableStoreError::Sqlite)?;

        // A legacy V4 database may predate the pending-proof index.  Install
        // only this additive schema object before a write-capable fast path;
        // never rebuild, delete, or rewrite existing proof rows here.  New
        // databases have no proofs table yet and receive the index atomically
        // from create_schema during their first snapshot publication.
        if create {
            Self::ensure_pending_proof_index(&connection)?;
        }

        let connection = SemanticSqliteConnection { inner: connection };
        let page_size = connection.page_size().map_err(DurableStoreError::Sqlite)?;
        if page_size != crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES {
            return Err(DurableStoreError::InvalidPolicy);
        }
        let actual_envelope = self
            .policy
            .checked_storage_envelope(page_size, self.policy.storage_workload())
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        if actual_envelope.main_bytes != envelope.main_bytes
            || actual_envelope.main_journal_bytes != envelope.main_journal_bytes
            || actual_envelope.wal_bytes != envelope.wal_bytes
            || actual_envelope.shm_bytes != envelope.shm_bytes
        {
            return Err(DurableStoreError::InvalidPolicy);
        }
        let max_pages = envelope.main_pages;
        let page_count = connection.page_count().map_err(DurableStoreError::Sqlite)?;
        if page_count > max_pages {
            return Err(DurableStoreError::LimitExceeded("database pages"));
        }
        if connection
            .pragma_u64("max_page_count")
            .map_err(DurableStoreError::Sqlite)?
            != max_pages
            || connection
                .pragma_u64("journal_size_limit")
                .map_err(DurableStoreError::Sqlite)?
                != envelope.wal_hard_bytes
            || connection
                .pragma_u64("wal_autocheckpoint")
                .map_err(DurableStoreError::Sqlite)?
                != envelope.wal_checkpoint_frames
        {
            return Err(DurableStoreError::InvalidPolicy);
        }
        Ok(connection)
    }

    fn create_schema(transaction: &SemanticSqliteTransaction<'_>) -> Result<(), DurableStoreError> {
        transaction
            .execute_batch(
                "DROP INDEX IF EXISTS facts_status_idx;
                DROP INDEX IF EXISTS facts_author_idx;
                DROP INDEX IF EXISTS facts_domain_seq_idx;
                DROP INDEX IF EXISTS proof_facts_fact_idx;
                CREATE TABLE IF NOT EXISTS meta (
                    key TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS facts (
                    fact_id BLOB PRIMARY KEY NOT NULL,
                    encoded BLOB NOT NULL,
                    status TEXT NOT NULL CHECK(status IN ('admitted','quarantined')),
                    author BLOB NOT NULL,
                    domain TEXT NOT NULL,
                    seq INTEGER NOT NULL
                );
                CREATE INDEX IF NOT EXISTS facts_seq_idx ON facts(seq);
                CREATE TABLE IF NOT EXISTS semantic_usage (
                    usage_id INTEGER PRIMARY KEY CHECK(usage_id = 1),
                    admitted_count BLOB NOT NULL,
                    admitted_bytes BLOB NOT NULL,
                    quarantined_count BLOB NOT NULL,
                    quarantined_bytes BLOB NOT NULL,
                    dependency_edges BLOB NOT NULL,
                    provisional_count BLOB NOT NULL,
                    author_usage_rows BLOB NOT NULL,
                    generation BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS author_usage (
                    author BLOB PRIMARY KEY NOT NULL,
                    retained_count BLOB NOT NULL,
                    retained_bytes BLOB NOT NULL,
                    quarantined_count BLOB NOT NULL,
                    quarantined_bytes BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS dependencies (
                    fact_id BLOB NOT NULL REFERENCES facts(fact_id) ON DELETE CASCADE,
                    dep_id BLOB NOT NULL,
                    PRIMARY KEY(fact_id, dep_id)
                ) WITHOUT ROWID;
                CREATE INDEX IF NOT EXISTS dependencies_dep_idx ON dependencies(dep_id);
                CREATE TABLE IF NOT EXISTS provisional (
                    fact_id BLOB NOT NULL REFERENCES facts(fact_id) ON DELETE CASCADE,
                    owner TEXT NOT NULL,
                    PRIMARY KEY(fact_id, owner)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS proofs (
                    delivery_id BLOB PRIMARY KEY NOT NULL,
                    encoded BLOB NOT NULL,
                    context_id BLOB NOT NULL,
                    target BLOB NOT NULL,
                    state TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS proofs_pending_idx
                    ON proofs(context_id,state,delivery_id);
                CREATE TABLE IF NOT EXISTS proof_facts (
                    delivery_id BLOB NOT NULL REFERENCES proofs(delivery_id) ON DELETE CASCADE,
                    fact_id BLOB NOT NULL REFERENCES facts(fact_id),
                    PRIMARY KEY(delivery_id, fact_id)
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS commitments (
                    name TEXT PRIMARY KEY NOT NULL,
                    value BLOB NOT NULL
                ) WITHOUT ROWID;
                CREATE TABLE IF NOT EXISTS proof_usage (
                    usage_id INTEGER PRIMARY KEY CHECK(usage_id = 1),
                    total_count BLOB NOT NULL,
                    total_bytes BLOB NOT NULL,
                    total_links BLOB NOT NULL,
                    pending_count BLOB NOT NULL,
                    pending_bytes BLOB NOT NULL,
                    generation BLOB NOT NULL
                );",
            )
            .map_err(DurableStoreError::Sqlite)
    }

    fn decode_usage_counter(
        &self,
        value: Vec<u8>,
        reason: &'static str,
    ) -> Result<u64, DurableStoreError> {
        Ok(u64::from_be_bytes(value.try_into().map_err(|_| {
            DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: reason.into(),
            }
        })?))
    }

    fn read_semantic_usage(
        &self,
        connection: &SemanticSqliteConnection,
    ) -> Result<SemanticUsage, DurableStoreError> {
        let values: (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = connection
            .query_row(
                "SELECT admitted_count,admitted_bytes,quarantined_count,
                        quarantined_bytes,dependency_edges,provisional_count,
                        author_usage_rows,generation
                 FROM semantic_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(SemanticUsage {
            admitted_count: self.decode_usage_counter(values.0, "invalid admitted usage count")?,
            admitted_bytes: self.decode_usage_counter(values.1, "invalid admitted usage bytes")?,
            quarantined_count: self
                .decode_usage_counter(values.2, "invalid quarantined usage count")?,
            quarantined_bytes: self
                .decode_usage_counter(values.3, "invalid quarantined usage bytes")?,
            dependency_edges: self
                .decode_usage_counter(values.4, "invalid dependency usage count")?,
            provisional_count: self
                .decode_usage_counter(values.5, "invalid provisional usage count")?,
            author_usage_rows: self
                .decode_usage_counter(values.6, "invalid author usage row count")?,
            generation: self.decode_usage_counter(values.7, "invalid usage generation")?,
        })
    }

    fn read_author_usage(
        &self,
        connection: &SemanticSqliteConnection,
        author: [u8; 32],
    ) -> Result<Option<AuthorUsage>, DurableStoreError> {
        let values: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT retained_count,retained_bytes,quarantined_count,quarantined_bytes
                 FROM author_usage WHERE author=?",
                params![author.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        values
            .map(|values| {
                Ok(AuthorUsage {
                    retained_count: self
                        .decode_usage_counter(values.0, "invalid retained author count")?,
                    retained_bytes: self
                        .decode_usage_counter(values.1, "invalid retained author bytes")?,
                    quarantined_count: self
                        .decode_usage_counter(values.2, "invalid quarantined author count")?,
                    quarantined_bytes: self
                        .decode_usage_counter(values.3, "invalid quarantined author bytes")?,
                })
            })
            .transpose()
    }

    fn read_semantic_usage_tx(
        &self,
        transaction: &SemanticSqliteTransaction<'_>,
    ) -> Result<SemanticUsage, DurableStoreError> {
        let values: (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = transaction
            .query_row(
                "SELECT admitted_count,admitted_bytes,quarantined_count,
                        quarantined_bytes,dependency_edges,provisional_count,
                        author_usage_rows,generation
                 FROM semantic_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(SemanticUsage {
            admitted_count: self.decode_usage_counter(values.0, "invalid admitted usage count")?,
            admitted_bytes: self.decode_usage_counter(values.1, "invalid admitted usage bytes")?,
            quarantined_count: self
                .decode_usage_counter(values.2, "invalid quarantined usage count")?,
            quarantined_bytes: self
                .decode_usage_counter(values.3, "invalid quarantined usage bytes")?,
            dependency_edges: self
                .decode_usage_counter(values.4, "invalid dependency usage count")?,
            provisional_count: self
                .decode_usage_counter(values.5, "invalid provisional usage count")?,
            author_usage_rows: self
                .decode_usage_counter(values.6, "invalid author usage row count")?,
            generation: self.decode_usage_counter(values.7, "invalid usage generation")?,
        })
    }

    fn read_semantic_usage_raw(
        &self,
        connection: &Connection,
    ) -> Result<SemanticUsage, DurableStoreError> {
        let values: (
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
            Vec<u8>,
        ) = connection
            .query_row(
                "SELECT admitted_count,admitted_bytes,quarantined_count,
                        quarantined_bytes,dependency_edges,provisional_count,
                        author_usage_rows,generation
                 FROM semantic_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                        row.get(6)?,
                        row.get(7)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(SemanticUsage {
            admitted_count: self.decode_usage_counter(values.0, "invalid admitted usage count")?,
            admitted_bytes: self.decode_usage_counter(values.1, "invalid admitted usage bytes")?,
            quarantined_count: self
                .decode_usage_counter(values.2, "invalid quarantined usage count")?,
            quarantined_bytes: self
                .decode_usage_counter(values.3, "invalid quarantined usage bytes")?,
            dependency_edges: self
                .decode_usage_counter(values.4, "invalid dependency usage count")?,
            provisional_count: self
                .decode_usage_counter(values.5, "invalid provisional usage count")?,
            author_usage_rows: self
                .decode_usage_counter(values.6, "invalid author usage row count")?,
            generation: self.decode_usage_counter(values.7, "invalid usage generation")?,
        })
    }

    #[cfg(test)]
    fn read_author_usage_raw(
        &self,
        connection: &Connection,
        author: [u8; 32],
    ) -> Result<Option<AuthorUsage>, DurableStoreError> {
        let values: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> = connection
            .query_row(
                "SELECT retained_count,retained_bytes,quarantined_count,quarantined_bytes
                 FROM author_usage WHERE author=?",
                params![author.to_vec()],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        values
            .map(|values| {
                Ok(AuthorUsage {
                    retained_count: self
                        .decode_usage_counter(values.0, "invalid retained author count")?,
                    retained_bytes: self
                        .decode_usage_counter(values.1, "invalid retained author bytes")?,
                    quarantined_count: self
                        .decode_usage_counter(values.2, "invalid quarantined author count")?,
                    quarantined_bytes: self
                        .decode_usage_counter(values.3, "invalid quarantined author bytes")?,
                })
            })
            .transpose()
    }

    fn write_semantic_usage(
        transaction: &SemanticSqliteTransaction<'_>,
        usage: SemanticUsage,
    ) -> Result<(), DurableStoreError> {
        transaction
            .execute(
                "INSERT INTO semantic_usage(
                     usage_id,admitted_count,admitted_bytes,quarantined_count,
                     quarantined_bytes,dependency_edges,provisional_count,
                     author_usage_rows,generation)
                 VALUES(1,?,?,?,?,?,?,?,?)
                 ON CONFLICT(usage_id) DO UPDATE SET
                     admitted_count=excluded.admitted_count,
                     admitted_bytes=excluded.admitted_bytes,
                     quarantined_count=excluded.quarantined_count,
                     quarantined_bytes=excluded.quarantined_bytes,
                     dependency_edges=excluded.dependency_edges,
                     provisional_count=excluded.provisional_count,
                     author_usage_rows=excluded.author_usage_rows,
                     generation=excluded.generation",
                params![
                    usage.admitted_count.to_be_bytes().to_vec(),
                    usage.admitted_bytes.to_be_bytes().to_vec(),
                    usage.quarantined_count.to_be_bytes().to_vec(),
                    usage.quarantined_bytes.to_be_bytes().to_vec(),
                    usage.dependency_edges.to_be_bytes().to_vec(),
                    usage.provisional_count.to_be_bytes().to_vec(),
                    usage.author_usage_rows.to_be_bytes().to_vec(),
                    usage.generation.to_be_bytes().to_vec(),
                ],
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(())
    }

    fn write_author_usage(
        transaction: &SemanticSqliteTransaction<'_>,
        author: [u8; 32],
        usage: AuthorUsage,
    ) -> Result<(), DurableStoreError> {
        if usage == AuthorUsage::default() {
            transaction
                .execute(
                    "DELETE FROM author_usage WHERE author=?",
                    params![author.to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
        } else {
            transaction
                .execute(
                    "INSERT INTO author_usage(
                         author,retained_count,retained_bytes,quarantined_count,quarantined_bytes)
                     VALUES(?,?,?,?,?)
                     ON CONFLICT(author) DO UPDATE SET
                         retained_count=excluded.retained_count,
                         retained_bytes=excluded.retained_bytes,
                         quarantined_count=excluded.quarantined_count,
                         quarantined_bytes=excluded.quarantined_bytes",
                    params![
                        author.to_vec(),
                        usage.retained_count.to_be_bytes().to_vec(),
                        usage.retained_bytes.to_be_bytes().to_vec(),
                        usage.quarantined_count.to_be_bytes().to_vec(),
                        usage.quarantined_bytes.to_be_bytes().to_vec(),
                    ],
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        Ok(())
    }

    fn proof_usage(
        proofs: &[ProofRecord],
        generation: u64,
    ) -> Result<ProofUsage, DurableStoreError> {
        proofs.iter().try_fold(
            ProofUsage {
                generation,
                ..ProofUsage::default()
            },
            |mut usage, proof| {
                let encoded_bytes = u64::try_from(serde_json::to_vec(proof)?.len())
                    .map_err(|_| DurableStoreError::LimitExceeded("proof bytes"))?;
                usage.total_count = usage
                    .total_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::LimitExceeded("proof count"))?;
                usage.total_bytes = usage
                    .total_bytes
                    .checked_add(encoded_bytes)
                    .ok_or(DurableStoreError::LimitExceeded("proof bytes"))?;
                usage.total_links = usage
                    .total_links
                    .checked_add(
                        u64::try_from(proof.fact_ids.len())
                            .map_err(|_| DurableStoreError::LimitExceeded("proof links"))?,
                    )
                    .ok_or(DurableStoreError::LimitExceeded("proof links"))?;
                if proof.is_pending() {
                    usage.pending_count = usage
                        .pending_count
                        .checked_add(1)
                        .ok_or(DurableStoreError::LimitExceeded("pending proof count"))?;
                    usage.pending_bytes = usage
                        .pending_bytes
                        .checked_add(encoded_bytes)
                        .ok_or(DurableStoreError::LimitExceeded("pending proof bytes"))?;
                }
                Ok(usage)
            },
        )
    }

    fn write_proof_usage(
        transaction: &SemanticSqliteTransaction<'_>,
        usage: ProofUsage,
    ) -> Result<(), DurableStoreError> {
        transaction
            .execute(
                "INSERT INTO proof_usage(
                     usage_id,total_count,total_bytes,total_links,pending_count,pending_bytes,generation)
                 VALUES(1,?,?,?,?,?,?)
                 ON CONFLICT(usage_id) DO UPDATE SET
                     total_count=excluded.total_count,total_bytes=excluded.total_bytes,
                     total_links=excluded.total_links,
                     pending_count=excluded.pending_count,pending_bytes=excluded.pending_bytes,
                     generation=excluded.generation",
                params![
                    usage.total_count.to_be_bytes().to_vec(),
                    usage.total_bytes.to_be_bytes().to_vec(),
                    usage.total_links.to_be_bytes().to_vec(),
                    usage.pending_count.to_be_bytes().to_vec(),
                    usage.pending_bytes.to_be_bytes().to_vec(),
                    usage.generation.to_be_bytes().to_vec(),
                ],
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(())
    }

    fn write_proof_usage_cas(
        transaction: &SemanticSqliteTransaction<'_>,
        expected_generation: u64,
        usage: ProofUsage,
    ) -> Result<(), DurableStoreError> {
        let updated = transaction
            .execute(
                "UPDATE proof_usage SET total_count=?,total_bytes=?,total_links=?,pending_count=?,
                        pending_bytes=?,generation=?
                 WHERE usage_id=1 AND generation=?",
                params![
                    usage.total_count.to_be_bytes().to_vec(),
                    usage.total_bytes.to_be_bytes().to_vec(),
                    usage.total_links.to_be_bytes().to_vec(),
                    usage.pending_count.to_be_bytes().to_vec(),
                    usage.pending_bytes.to_be_bytes().to_vec(),
                    usage.generation.to_be_bytes().to_vec(),
                    expected_generation.to_be_bytes().to_vec(),
                ],
            )
            .map_err(DurableStoreError::Sqlite)?;
        if updated != 1 {
            return Err(DurableStoreError::DeltaConflict);
        }
        Ok(())
    }

    fn read_proof_usage(
        &self,
        connection: &SemanticSqliteConnection,
    ) -> Result<ProofUsage, DurableStoreError> {
        let values: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT total_count,total_bytes,total_links,pending_count,pending_bytes,generation
                 FROM proof_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(ProofUsage {
            total_count: self.decode_usage_counter(values.0, "invalid total proof count")?,
            total_bytes: self.decode_usage_counter(values.1, "invalid total proof bytes")?,
            total_links: self.decode_usage_counter(values.2, "invalid total proof links")?,
            pending_count: self.decode_usage_counter(values.3, "invalid pending proof count")?,
            pending_bytes: self.decode_usage_counter(values.4, "invalid pending proof bytes")?,
            generation: self.decode_usage_counter(values.5, "invalid proof generation")?,
        })
    }

    fn read_proof_usage_raw(
        &self,
        connection: &rusqlite::Connection,
    ) -> Result<ProofUsage, DurableStoreError> {
        let values: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = connection
            .query_row(
                "SELECT total_count,total_bytes,total_links,pending_count,pending_bytes,generation
                 FROM proof_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(ProofUsage {
            total_count: self.decode_usage_counter(values.0, "invalid total proof count")?,
            total_bytes: self.decode_usage_counter(values.1, "invalid total proof bytes")?,
            total_links: self.decode_usage_counter(values.2, "invalid total proof links")?,
            pending_count: self.decode_usage_counter(values.3, "invalid pending proof count")?,
            pending_bytes: self.decode_usage_counter(values.4, "invalid pending proof bytes")?,
            generation: self.decode_usage_counter(values.5, "invalid proof generation")?,
        })
    }

    fn read_proof_usage_tx(
        &self,
        transaction: &SemanticSqliteTransaction<'_>,
    ) -> Result<ProofUsage, DurableStoreError> {
        let values: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>) = transaction
            .query_row(
                "SELECT total_count,total_bytes,total_links,pending_count,pending_bytes,generation
                 FROM proof_usage WHERE usage_id=1",
                [],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                        row.get(5)?,
                    ))
                },
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(ProofUsage {
            total_count: self.decode_usage_counter(values.0, "invalid total proof count")?,
            total_bytes: self.decode_usage_counter(values.1, "invalid total proof bytes")?,
            total_links: self.decode_usage_counter(values.2, "invalid total proof links")?,
            pending_count: self.decode_usage_counter(values.3, "invalid pending proof count")?,
            pending_bytes: self.decode_usage_counter(values.4, "invalid pending proof bytes")?,
            generation: self.decode_usage_counter(values.5, "invalid proof generation")?,
        })
    }

    fn read_proof_record_connection(
        &self,
        connection: &SemanticSqliteConnection,
        delivery_id: ProofDeliveryId,
    ) -> Result<Option<ProofRecord>, DurableStoreError> {
        let values: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> = connection
            .query_row(
                "SELECT delivery_id,encoded,context_id,target,state
                 FROM proofs WHERE delivery_id=?",
                params![delivery_id.as_bytes().to_vec()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        values
            .map(|values| self.decode_proof_row(values))
            .transpose()
    }

    fn read_proof_record_tx(
        &self,
        transaction: &SemanticSqliteTransaction<'_>,
        delivery_id: ProofDeliveryId,
    ) -> Result<Option<ProofRecord>, DurableStoreError> {
        let values: Option<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> = transaction
            .query_row(
                "SELECT delivery_id,encoded,context_id,target,state
                 FROM proofs WHERE delivery_id=?",
                params![delivery_id.as_bytes().to_vec()],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        values
            .map(|values| self.decode_proof_row(values))
            .transpose()
    }

    fn decode_proof_row(
        &self,
        values: (Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String),
    ) -> Result<ProofRecord, DurableStoreError> {
        let (delivery_id, encoded, context_id, target, state) = values;
        let proof: ProofRecord = serde_json::from_slice(&encoded)?;
        let delivery_id: [u8; 32] =
            delivery_id
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid proof delivery index".into(),
                })?;
        let context_id: [u8; 32] =
            context_id
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid proof context index".into(),
                })?;
        let target: [u8; 32] = target.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "invalid proof target index".into(),
        })?;
        if proof.delivery_id.as_bytes() != &delivery_id
            || proof.context_id.as_bytes() != &context_id
            || proof.target.as_bytes() != target
            || serde_json::to_string(&proof.state)? != state
        {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "proof index does not match signed bytes".into(),
            });
        }
        proof
            .validate()
            .map_err(|error| DurableStoreError::InvalidProof(error.to_string()))?;
        Ok(proof)
    }

    /// Compare the immutable delivery payload while deliberately ignoring
    /// state, which is the separately persisted lifecycle field.
    fn same_delivery_payload(left: &ProofRecord, right: &ProofRecord) -> bool {
        left.version == right.version
            && left.context_id == right.context_id
            && left.target == right.target
            && left.delivery_id == right.delivery_id
            && left.fact_ids == right.fact_ids
            && left.owner == right.owner
            && left.binding == right.binding
    }

    fn next_proof_usage(
        &self,
        current: ProofUsage,
        before: Option<&ProofRecord>,
        after: Option<&ProofRecord>,
    ) -> Result<ProofUsage, DurableStoreError> {
        let mut usage = current;
        if let Some(proof) = before {
            self.adjust_proof_usage(&mut usage, proof, false)?;
        }
        if let Some(proof) = after {
            self.adjust_proof_usage(&mut usage, proof, true)?;
        }
        usage.generation = usage
            .generation
            .checked_add(1)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        if usage.total_count > self.policy.max_proof_records {
            return Err(DurableStoreError::LimitExceeded("proof count"));
        }
        if usage.total_bytes > self.policy.max_proof_bytes {
            return Err(DurableStoreError::LimitExceeded("proof bytes"));
        }
        if usage.total_links > self.policy.max_proof_links {
            return Err(DurableStoreError::LimitExceeded("proof links"));
        }
        if usage.pending_count > self.policy.max_pending_proofs {
            return Err(DurableStoreError::LimitExceeded("pending proof count"));
        }
        if usage.pending_bytes > self.policy.max_pending_proof_bytes {
            return Err(DurableStoreError::LimitExceeded("pending proof bytes"));
        }
        Ok(usage)
    }

    fn adjust_proof_usage(
        &self,
        usage: &mut ProofUsage,
        proof: &ProofRecord,
        add: bool,
    ) -> Result<(), DurableStoreError> {
        let bytes = u64::try_from(serde_json::to_vec(proof)?.len())
            .map_err(|_| DurableStoreError::LimitExceeded("proof bytes"))?;
        let sign = if add { 1i128 } else { -1i128 };
        let apply = |value: &mut u64, delta: i128| -> Result<(), DurableStoreError> {
            let next = i128::from(*value) + delta;
            *value = u64::try_from(next).map_err(|_| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "proof usage underflow".into(),
            })?;
            Ok(())
        };
        apply(&mut usage.total_count, sign)?;
        apply(&mut usage.total_bytes, sign * i128::from(bytes))?;
        let links = i128::try_from(proof.fact_ids.len())
            .map_err(|_| DurableStoreError::LimitExceeded("proof links"))?;
        apply(&mut usage.total_links, sign * links)?;
        if proof.is_pending() {
            apply(&mut usage.pending_count, sign)?;
            apply(&mut usage.pending_bytes, sign * i128::from(bytes))?;
        }
        Ok(())
    }

    fn commit_proof_change(
        &self,
        connection: &mut SemanticSqliteConnection,
        delivery_id: ProofDeliveryId,
        before: Option<&ProofRecord>,
        after: Option<&ProofRecord>,
    ) -> Result<(), DurableStoreError> {
        if before == after {
            return Ok(());
        }
        if before.into_iter().chain(after).any(|proof| {
            u64::try_from(proof.owner.len()).unwrap_or(u64::MAX)
                > self.policy.max_fact_encoded_bytes
                || u64::try_from(proof.binding.len()).unwrap_or(u64::MAX)
                    > self.policy.max_fact_encoded_bytes
        }) {
            return Err(DurableStoreError::LimitExceeded("proof binding bytes"));
        }
        self.preflight_capacity(connection)?;
        let transaction = connection
            .transaction()
            .map_err(DurableStoreError::Sqlite)?;
        let current = self.read_proof_record_tx(&transaction, delivery_id)?;
        if current.as_ref() != before {
            return Err(DurableStoreError::ProofConflict);
        }
        let current_usage = self.read_proof_usage_tx(&transaction)?;
        let usage = self.next_proof_usage(current_usage, before, after)?;
        match (before, after) {
            (Some(_), None) => {
                transaction
                    .execute(
                        "DELETE FROM proof_facts WHERE delivery_id=?",
                        params![delivery_id.as_bytes().to_vec()],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                transaction
                    .execute(
                        "DELETE FROM proofs WHERE delivery_id=?",
                        params![delivery_id.as_bytes().to_vec()],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
            }
            (None, Some(proof)) => {
                transaction
                    .execute(
                        "INSERT INTO proofs(delivery_id,encoded,context_id,target,state)
                         VALUES(?,?,?,?,?)",
                        params![
                            delivery_id.as_bytes().to_vec(),
                            serde_json::to_vec(proof)?,
                            proof.context_id.as_bytes().to_vec(),
                            proof.target.as_bytes().to_vec(),
                            serde_json::to_string(&proof.state)?
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                for fact_id in &proof.fact_ids {
                    transaction
                        .execute(
                            "INSERT INTO proof_facts(delivery_id,fact_id) VALUES(?,?)",
                            params![delivery_id.as_bytes().to_vec(), fact_id.as_bytes().to_vec()],
                        )
                        .map_err(DurableStoreError::Sqlite)?;
                }
            }
            (Some(previous), Some(proof)) => {
                if previous.fact_ids != proof.fact_ids {
                    transaction
                        .execute(
                            "DELETE FROM proof_facts WHERE delivery_id=?",
                            params![delivery_id.as_bytes().to_vec()],
                        )
                        .map_err(DurableStoreError::Sqlite)?;
                    for fact_id in &proof.fact_ids {
                        transaction
                            .execute(
                                "INSERT INTO proof_facts(delivery_id,fact_id) VALUES(?,?)",
                                params![
                                    delivery_id.as_bytes().to_vec(),
                                    fact_id.as_bytes().to_vec()
                                ],
                            )
                            .map_err(DurableStoreError::Sqlite)?;
                    }
                }
                let updated = transaction
                    .execute(
                        "UPDATE proofs SET encoded=?,context_id=?,target=?,state=?
                         WHERE delivery_id=?",
                        params![
                            serde_json::to_vec(proof)?,
                            proof.context_id.as_bytes().to_vec(),
                            proof.target.as_bytes().to_vec(),
                            serde_json::to_string(&proof.state)?,
                            delivery_id.as_bytes().to_vec()
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                if updated != 1 {
                    return Err(DurableStoreError::ProofConflict);
                }
            }
            (None, None) => return Ok(()),
        }
        Self::write_proof_usage_cas(&transaction, current_usage.generation, usage)?;
        transaction.commit().map_err(DurableStoreError::Sqlite)
    }

    /// Check SQLite's configured main-page limit before beginning a write.
    /// SQLite owns WAL reuse and automatic checkpointing; sidecar file lengths
    /// are high-water marks, not live allocation counters or transaction
    /// admission oracles.
    fn preflight_capacity(
        &self,
        connection: &SemanticSqliteConnection,
    ) -> Result<(), DurableStoreError> {
        let page_size = connection.page_size().map_err(DurableStoreError::Sqlite)?;
        let envelope = self
            .policy
            .checked_storage_envelope(page_size, self.policy.storage_workload())
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        if connection.page_count().map_err(DurableStoreError::Sqlite)? > envelope.main_pages {
            return Err(DurableStoreError::LimitExceeded("database pages"));
        }
        Ok(())
    }

    fn validate_aggregate_limits(
        &self,
        snapshot: &V4StoreAggregate,
    ) -> Result<(), DurableStoreError> {
        if !self.policy.validate() {
            return Err(DurableStoreError::InvalidPolicy);
        }
        if snapshot.facts.len() as u64 > self.policy.max_admitted_facts
            || snapshot.quarantined.len() as u64 > self.policy.max_quarantined_facts
        {
            return Err(DurableStoreError::LimitExceeded("fact count"));
        }
        let all_facts = snapshot
            .facts
            .iter()
            .map(|fact| (fact, true))
            .chain(snapshot.quarantined.iter().map(|fact| (fact, false)));
        let mut total_fact_bytes = 0u64;
        let mut admitted_bytes = 0u64;
        let mut quarantined_bytes = 0u64;
        let mut retained_by_author = std::collections::BTreeMap::<[u8; 32], (u64, u64)>::new();
        let mut dependency_edges = 0u64;
        for (fact, admitted) in all_facts {
            let bytes = serde_json::to_vec(fact)?;
            let bytes = u64::try_from(bytes.len())
                .map_err(|_| DurableStoreError::LimitExceeded("fact bytes conversion"))?;
            if bytes > self.policy.max_fact_encoded_bytes {
                return Err(DurableStoreError::LimitExceeded("fact bytes"));
            }
            total_fact_bytes = total_fact_bytes
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if admitted {
                admitted_bytes = admitted_bytes
                    .checked_add(bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            } else {
                quarantined_bytes = quarantined_bytes
                    .checked_add(bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            }
            let entry = retained_by_author
                .entry(fact.content.author.as_bytes())
                .or_default();
            entry.0 = entry
                .0
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            entry.1 = entry
                .1
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let dependencies = canonical_dependencies(fact);
            dependency_edges =
                dependency_edges
                    .checked_add(u64::try_from(dependencies.len()).map_err(|_| {
                        DurableStoreError::LimitExceeded("dependency count conversion")
                    })?)
                    .and_then(|total| total.checked_add(fact.content.authority_uses.len() as u64))
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            if dependencies.len() as u64 > self.policy.max_dependencies_per_fact
                || fact.content.authority_uses.len() as u64
                    > self.policy.max_authority_uses_per_fact
                || fact.content.authority_uses.iter().any(|authority_use| {
                    authority_use.predecessors.len() as u64
                        > self.policy.max_authority_predecessors_per_use
                })
            {
                return Err(DurableStoreError::LimitExceeded("dependencies per fact"));
            }
        }
        if admitted_bytes > self.policy.max_admitted_bytes
            || quarantined_bytes > self.policy.max_quarantined_bytes
            || total_fact_bytes > self.policy.max_database_bytes
            || dependency_edges > self.policy.max_dependency_edges
            || u64::try_from(retained_by_author.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?
                > self.policy.max_author_usage_rows
            || retained_by_author.values().any(|(facts, bytes)| {
                *facts > self.policy.max_retained_facts_per_author
                    || *bytes > self.policy.max_retained_bytes_per_author
            })
        {
            return Err(DurableStoreError::LimitExceeded("fact retention"));
        }
        if u64::try_from(snapshot.provisional.len())
            .map_err(|_| DurableStoreError::InvalidPolicy)?
            > self.policy.max_provisional_rows
        {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }
        if snapshot
            .provisional
            .iter()
            .any(|claim| claim.owner != SEMANTIC_INGRESS_OWNER)
        {
            return Err(DurableStoreError::InvalidCustody);
        }
        let total_proof_bytes: u64 = snapshot.proofs.iter().try_fold(0u64, |total, proof| {
            let bytes = u64::try_from(serde_json::to_vec(proof)?.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?;
            if u64::try_from(proof.owner.len()).unwrap_or(u64::MAX)
                > self.policy.max_fact_encoded_bytes
                || u64::try_from(proof.binding.len()).unwrap_or(u64::MAX)
                    > self.policy.max_fact_encoded_bytes
            {
                return Err(DurableStoreError::LimitExceeded("proof binding bytes"));
            }
            total
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)
        })?;
        let proof_link_count = snapshot.proofs.iter().try_fold(0u64, |total, proof| {
            total
                .checked_add(
                    u64::try_from(proof.fact_ids.len())
                        .map_err(|_| DurableStoreError::InvalidPolicy)?,
                )
                .ok_or(DurableStoreError::InvalidPolicy)
        })?;
        let mut pending = snapshot.proofs.iter().filter(|proof| proof.is_pending());
        let pending_proof_count = pending.clone().count() as u64;
        let pending_proof_bytes: u64 = pending.try_fold(0u64, |total, proof| {
            let bytes = u64::try_from(serde_json::to_vec(proof)?.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?;
            total
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)
        })?;
        if snapshot.proofs.len() as u64 > self.policy.max_proof_records
            || total_proof_bytes > self.policy.max_proof_bytes
            || proof_link_count > self.policy.max_proof_links
            || pending_proof_count > self.policy.max_pending_proofs
            || pending_proof_bytes > self.policy.max_pending_proof_bytes
        {
            return Err(DurableStoreError::LimitExceeded("proof retention"));
        }
        Ok(())
    }

    fn plan_semantic_delta(
        &self,
        connection: &SemanticSqliteConnection,
        context_id: MeshContextId,
        delta: &SemanticDelta,
        expected_base_projection: [u8; 32],
        projection_commitment: [u8; 32],
        custody: &[ProvisionalCustody],
        row_limit_override: Option<usize>,
    ) -> Result<SemanticDeltaPlan, DurableStoreError> {
        let batch_limit = usize::try_from(self.policy.max_ready_batch)
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        let max_rows = row_limit_override.unwrap_or(
            batch_limit
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?,
        );
        if delta.rows().len() > max_rows
            || delta.promoted().len() > batch_limit
            || delta.removed().len() > batch_limit
            || delta.provisional_added().len() > max_rows
            || delta.provisional_removed().len() > max_rows
        {
            return Err(DurableStoreError::LimitExceeded("semantic delta batch"));
        }
        let stored_context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        if stored_context.as_slice() != context_id.as_bytes() {
            return Err(DurableStoreError::ContextMismatch {
                expected: context_id,
                actual: stored_context
                    .try_into()
                    .map(MeshContextId::from_bytes)
                    .unwrap_or_else(|_| MeshContextId::from_bytes([0; 32])),
            });
        }
        let base_usage = self.read_semantic_usage(connection)?;
        let stored_projection: Vec<u8> = connection
            .query_row(
                "SELECT value FROM commitments WHERE name='projection'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let stored_projection: [u8; 32] =
            stored_projection
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid projection commitment".into(),
                })?;
        if stored_projection != expected_base_projection {
            return Err(DurableStoreError::DeltaConflict);
        }

        let mut seen = std::collections::BTreeSet::new();
        let mut rows = Vec::new();
        let mut affected_authors = std::collections::BTreeSet::new();
        for row in delta.rows() {
            let fact = row.fact();
            if !seen.insert(fact.id) || fact.content.mesh_context != context_id {
                return Err(DurableStoreError::DeltaConflict);
            }
            let encoded_bytes = Self::canonical_fact_bytes(fact)?;
            let dependency_count = u64::try_from(canonical_dependencies(fact).len())
                .map_err(|_| DurableStoreError::LimitExceeded("fact delta dependencies"))?;
            if encoded_bytes > self.policy.max_fact_encoded_bytes
                || dependency_count > self.policy.max_dependencies_per_fact
                || fact.content.authority_uses.len() as u64
                    > self.policy.max_authority_uses_per_fact
                || fact.content.authority_uses.iter().any(|authority_use| {
                    authority_use.predecessors.len() as u64
                        > self.policy.max_authority_predecessors_per_use
                })
            {
                return Err(DurableStoreError::LimitExceeded("fact delta"));
            }
            let expected_status = match row.status() {
                SemanticFactStatus::Admitted => "admitted",
                SemanticFactStatus::Quarantined => "quarantined",
            };
            let expected_author = fact.content.author.as_bytes();
            let expected_domain = serde_json::to_string(&fact.content.domain)?;
            let existing: Option<(Vec<u8>, String, Vec<u8>, String)> = connection
                .query_row(
                    "SELECT encoded,status,author,domain FROM facts WHERE fact_id=?",
                    params![fact.id.as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
                )
                .optional()
                .map_err(DurableStoreError::Sqlite)?;
            let (existing, promote) = match existing {
                Some((stored_encoded, stored_status, stored_author, stored_domain)) => {
                    let stored_fact = self.decode_stored_fact(
                        &stored_encoded,
                        context_id,
                        &stored_author,
                        fact.id.as_bytes(),
                    )?;
                    if stored_fact != *fact
                        || stored_author != expected_author
                        || stored_domain != expected_domain
                    {
                        return Err(DurableStoreError::DeltaConflict);
                    }
                    match (stored_status.as_str(), expected_status) {
                        ("admitted", "admitted") | ("quarantined", "quarantined") => (true, false),
                        ("quarantined", "admitted") => (true, true),
                        _ => return Err(DurableStoreError::DeltaConflict),
                    }
                }
                None => (false, false),
            };
            affected_authors.insert(expected_author);
            rows.push(PlannedDeltaRow {
                fact: fact.clone(),
                status: row.status(),
                existing,
                promote,
            });
        }

        let mut promoted = std::collections::BTreeSet::new();
        for id in delta.promoted() {
            if !promoted.insert(*id) || !rows.iter().any(|row| row.fact.id == *id && row.promote) {
                return Err(DurableStoreError::DeltaConflict);
            }
        }
        if rows
            .iter()
            .filter(|row| row.promote)
            .any(|row| !promoted.contains(&row.fact.id))
        {
            return Err(DurableStoreError::DeltaConflict);
        }
        let mut removed = Vec::new();
        let mut removed_ids = std::collections::BTreeSet::new();
        for id in delta.removed() {
            if !removed_ids.insert(*id) || seen.contains(id) {
                return Err(DurableStoreError::DeltaConflict);
            }
            let existing: Option<(Vec<u8>, String)> = connection
                .query_row(
                    "SELECT encoded,status FROM facts WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .map_err(DurableStoreError::Sqlite)?;
            let Some((encoded, status)) = existing else {
                return Err(DurableStoreError::DeltaConflict);
            };
            if status != "quarantined" {
                return Err(DurableStoreError::DeltaConflict);
            }
            let author: Vec<u8> = connection
                .query_row(
                    "SELECT author FROM facts WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .map_err(DurableStoreError::Sqlite)?;
            let author: [u8; 32] = author.try_into().map_err(|_| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "invalid removed fact author".into(),
            })?;
            let removed_fact =
                self.decode_stored_fact(&encoded, context_id, &author, id.as_bytes())?;
            if removed_fact.id != *id {
                return Err(DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "removed fact id does not match row".into(),
                });
            }
            let dependency_count = canonical_dependencies(&removed_fact)
                .len()
                .checked_add(removed_fact.content.authority_uses.len())
                .ok_or(DurableStoreError::InvalidPolicy)?;
            removed.push(PlannedDeltaRemoval {
                id: *id,
                author,
                encoded_bytes: Self::canonical_fact_bytes(&removed_fact)?,
                dependency_count: u64::try_from(dependency_count).map_err(|_| {
                    DurableStoreError::Corrupt {
                        path: self.path.clone(),
                        reason: "removed dependency count overflow".into(),
                    }
                })?,
            });
            affected_authors.insert(author);
        }
        for id in &removed_ids {
            let dependents: Vec<Vec<u8>> = bounded_vfs_query_collect(
                connection,
                "SELECT fact_id FROM dependencies WHERE dep_id=?",
                params![id.as_bytes().to_vec()],
                self.policy.max_dependency_edges,
                self.policy
                    .max_dependency_edges
                    .checked_mul(32)
                    .ok_or(DurableStoreError::InvalidPolicy)?,
                "dependent fact bytes",
                |row| {
                    let value: Vec<u8> = row.get(0)?;
                    let bytes =
                        u64::try_from(value.len()).map_err(|_| rusqlite::Error::InvalidQuery)?;
                    Ok((value, bytes))
                },
            )?;
            for dependent in dependents {
                let dependent = dependent.try_into().map(FactId::from_bytes).map_err(|_| {
                    DurableStoreError::Corrupt {
                        path: self.path.clone(),
                        reason: "invalid dependent fact id".into(),
                    }
                })?;
                if !removed_ids.contains(&dependent) {
                    return Err(DurableStoreError::DeltaConflict);
                }
            }
        }

        let mut removed_custody_ids = std::collections::BTreeSet::new();
        for id in delta.provisional_removed() {
            if !removed_custody_ids.insert(*id) {
                return Err(DurableStoreError::DeltaConflict);
            }
        }
        let mut expected_custody_removals = promoted.clone();
        expected_custody_removals.extend(removed_ids.iter().copied());
        if removed_custody_ids != expected_custody_removals {
            return Err(DurableStoreError::DeltaConflict);
        }
        for id in &removed_custody_ids {
            let status: String = connection
                .query_row(
                    "SELECT status FROM facts WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .map_err(DurableStoreError::Sqlite)?;
            let custody_count: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM provisional WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .map_err(DurableStoreError::Sqlite)?;
            if status != "quarantined" || custody_count != 1 {
                return Err(DurableStoreError::DeltaConflict);
            }
        }

        let mut added_custody = Vec::new();
        let mut added_ids = std::collections::BTreeSet::new();
        for id in delta.provisional_added() {
            if !added_ids.insert(*id) {
                return Err(DurableStoreError::DeltaConflict);
            }
            let claim = custody
                .iter()
                .find(|claim| claim.fact_id == *id)
                .ok_or(DurableStoreError::InvalidCustody)?;
            if claim.owner != SEMANTIC_INGRESS_OWNER {
                return Err(DurableStoreError::InvalidCustody);
            }
            let status = if let Some(row) = rows.iter().find(|row| row.fact.id == *id) {
                Some(row.status)
            } else {
                let status: Option<String> = connection
                    .query_row(
                        "SELECT status FROM facts WHERE fact_id=?",
                        params![id.as_bytes().to_vec()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(DurableStoreError::Sqlite)?;
                match status.as_deref() {
                    Some("quarantined") => Some(SemanticFactStatus::Quarantined),
                    Some("admitted") => Some(SemanticFactStatus::Admitted),
                    Some(_) => return Err(DurableStoreError::DeltaConflict),
                    None => None,
                }
            };
            if status != Some(SemanticFactStatus::Quarantined) {
                return Err(DurableStoreError::InvalidCustody);
            }
            let current: Option<String> = connection
                .query_row(
                    "SELECT owner FROM provisional WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(DurableStoreError::Sqlite)?;
            if let Some(owner) = current {
                if owner != claim.owner {
                    return Err(DurableStoreError::DeltaConflict);
                }
            } else {
                added_custody.push(claim.clone());
            }
        }
        let mut custody_ids = std::collections::BTreeSet::new();
        if custody
            .iter()
            .any(|claim| !added_ids.contains(&claim.fact_id) || !custody_ids.insert(claim.fact_id))
        {
            return Err(DurableStoreError::InvalidCustody);
        }
        let mut removed_custody = Vec::new();
        for id in &removed_custody_ids {
            if removed_ids.contains(id) {
                // Removing the quarantined fact cascades its custody row in
                // the same transaction; do not schedule a second delete.
                continue;
            }
            removed_custody.push(*id);
        }
        let added_provisional_rows =
            u64::try_from(added_custody.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let removed_custody_rows =
            u64::try_from(removed_custody.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let removed_fact_rows =
            u64::try_from(removed.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let next_provisional_rows = base_usage
            .provisional_count
            .checked_add(added_provisional_rows)
            .and_then(|count| count.checked_sub(removed_custody_rows))
            .and_then(|count| count.checked_sub(removed_fact_rows))
            .ok_or(DurableStoreError::InvalidPolicy)?;
        if next_provisional_rows > self.policy.max_provisional_rows {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }

        let mut add_admitted = 0u64;
        let mut add_admitted_bytes = 0u64;
        let mut add_quarantined = 0u64;
        let mut add_quarantined_bytes = 0u64;
        let mut add_dependencies = 0u64;
        let mut add_retained = std::collections::BTreeMap::<[u8; 32], (u64, u64)>::new();
        let mut add_quarantined_author = std::collections::BTreeMap::<[u8; 32], (u64, u64)>::new();
        let mut remove_quarantined = 0u64;
        let mut remove_quarantined_bytes = 0u64;
        let mut remove_quarantined_author =
            std::collections::BTreeMap::<[u8; 32], (u64, u64)>::new();
        for row in rows.iter().filter(|row| !row.existing) {
            let bytes = u64::try_from(serde_json::to_vec(&row.fact)?.len())
                .map_err(|_| DurableStoreError::LimitExceeded("fact delta bytes"))?;
            let deps = u64::try_from(canonical_dependencies(&row.fact).len())
                .map_err(|_| DurableStoreError::LimitExceeded("fact delta dependencies"))?;
            add_dependencies = add_dependencies
                .checked_add(deps)
                .and_then(|total| total.checked_add(row.fact.content.authority_uses.len() as u64))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let author = row.fact.content.author.as_bytes();
            let retained = add_retained.entry(author).or_default();
            retained.0 = retained
                .0
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            retained.1 = retained
                .1
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            match row.status {
                SemanticFactStatus::Admitted => {
                    add_admitted = add_admitted
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    add_admitted_bytes = add_admitted_bytes
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                }
                SemanticFactStatus::Quarantined => {
                    add_quarantined = add_quarantined
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    add_quarantined_bytes = add_quarantined_bytes
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    let quarantine = add_quarantined_author.entry(author).or_default();
                    quarantine.0 = quarantine
                        .0
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    quarantine.1 = quarantine
                        .1
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                }
            }
        }
        for row in rows.iter().filter(|row| row.promote) {
            let bytes = u64::try_from(serde_json::to_vec(&row.fact)?.len())
                .map_err(|_| DurableStoreError::LimitExceeded("fact delta bytes"))?;
            add_admitted = add_admitted
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            add_admitted_bytes = add_admitted_bytes
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            remove_quarantined = remove_quarantined
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            remove_quarantined_bytes = remove_quarantined_bytes
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let quarantine = remove_quarantined_author
                .entry(row.fact.content.author.as_bytes())
                .or_default();
            quarantine.0 = quarantine
                .0
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            quarantine.1 = quarantine
                .1
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
        }
        let mut remove_dependencies = 0u64;
        let mut remove_retained = std::collections::BTreeMap::<[u8; 32], (u64, u64)>::new();
        for row in &removed {
            remove_quarantined = remove_quarantined
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            remove_quarantined_bytes = remove_quarantined_bytes
                .checked_add(row.encoded_bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            remove_dependencies = remove_dependencies
                .checked_add(row.dependency_count)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let retained = remove_retained.entry(row.author).or_default();
            retained.0 = retained
                .0
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            retained.1 = retained
                .1
                .checked_add(row.encoded_bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let quarantine = remove_quarantined_author.entry(row.author).or_default();
            quarantine.0 = quarantine
                .0
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            quarantine.1 = quarantine
                .1
                .checked_add(row.encoded_bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
        }
        let changed = rows.iter().any(|row| !row.existing || row.promote)
            || !removed.is_empty()
            || !added_custody.is_empty()
            || !removed_custody.is_empty();
        let mut usage = base_usage;
        usage.admitted_count = usage
            .admitted_count
            .checked_add(add_admitted)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        usage.admitted_bytes = usage
            .admitted_bytes
            .checked_add(add_admitted_bytes)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        usage.quarantined_count = usage
            .quarantined_count
            .checked_add(add_quarantined)
            .and_then(|value| value.checked_sub(remove_quarantined))
            .ok_or(DurableStoreError::InvalidPolicy)?;
        usage.quarantined_bytes = usage
            .quarantined_bytes
            .checked_add(add_quarantined_bytes)
            .and_then(|value| value.checked_sub(remove_quarantined_bytes))
            .ok_or(DurableStoreError::InvalidPolicy)?;
        usage.dependency_edges = usage
            .dependency_edges
            .checked_add(add_dependencies)
            .and_then(|value| value.checked_sub(remove_dependencies))
            .ok_or(DurableStoreError::InvalidPolicy)?;
        let added_provisional_count =
            u64::try_from(added_custody.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        let removed_provisional_count = u64::try_from(removed_custody_ids.len())
            .map_err(|_| DurableStoreError::InvalidPolicy)?;
        usage.provisional_count = usage
            .provisional_count
            .checked_add(added_provisional_count)
            .and_then(|value| value.checked_sub(removed_provisional_count))
            .ok_or(DurableStoreError::InvalidPolicy)?;
        if usage.provisional_count > self.policy.max_provisional_rows {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }
        usage.generation = if changed {
            base_usage
                .generation
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?
        } else {
            base_usage.generation
        };
        let fact_count = usage
            .admitted_count
            .checked_add(usage.quarantined_count)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        let fact_bytes = usage
            .admitted_bytes
            .checked_add(usage.quarantined_bytes)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        let max_fact_count = self
            .policy
            .max_admitted_facts
            .checked_add(self.policy.max_quarantined_facts)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        if usage.admitted_count > self.policy.max_admitted_facts
            || usage.admitted_bytes > self.policy.max_admitted_bytes
            || usage.quarantined_count > self.policy.max_quarantined_facts
            || usage.quarantined_bytes > self.policy.max_quarantined_bytes
            || fact_count > max_fact_count
            || fact_bytes > self.policy.max_database_bytes
            || usage.dependency_edges > self.policy.max_dependency_edges
        {
            return Err(DurableStoreError::LimitExceeded("semantic delta quotas"));
        }
        let mut author_usage = std::collections::BTreeMap::new();
        for author in affected_authors {
            let current = self
                .read_author_usage(connection, author)?
                .unwrap_or_default();
            let add = add_retained.get(&author).copied().unwrap_or_default();
            let remove = remove_retained.get(&author).copied().unwrap_or_default();
            let retained_count = current
                .retained_count
                .checked_add(add.0)
                .and_then(|value| value.checked_sub(remove.0))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let retained_bytes = current
                .retained_bytes
                .checked_add(add.1)
                .and_then(|value| value.checked_sub(remove.1))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if retained_count > self.policy.max_retained_facts_per_author
                || retained_bytes > self.policy.max_retained_bytes_per_author
            {
                return Err(DurableStoreError::LimitExceeded(
                    "retained facts per author",
                ));
            }
            let add = add_quarantined_author
                .get(&author)
                .copied()
                .unwrap_or_default();
            let remove = remove_quarantined_author
                .get(&author)
                .copied()
                .unwrap_or_default();
            let quarantined_count = current
                .quarantined_count
                .checked_add(add.0)
                .and_then(|value| value.checked_sub(remove.0))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let quarantined_bytes = current
                .quarantined_bytes
                .checked_add(add.1)
                .and_then(|value| value.checked_sub(remove.1))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if quarantined_count > self.policy.max_quarantined_facts_per_author
                || quarantined_bytes > self.policy.max_quarantined_bytes_per_author
            {
                return Err(DurableStoreError::LimitExceeded(
                    "quarantined facts per author",
                ));
            }
            author_usage.insert(
                author,
                AuthorUsage {
                    retained_count,
                    retained_bytes,
                    quarantined_count,
                    quarantined_bytes,
                },
            );
        }
        let mut next_author_rows = base_usage.author_usage_rows;
        for (author, usage) in &author_usage {
            let present: Option<i64> = connection
                .query_row(
                    "SELECT 1 FROM author_usage WHERE author=?",
                    params![author.to_vec()],
                    |row| row.get(0),
                )
                .optional()
                .map_err(DurableStoreError::Sqlite)?;
            if present.is_some() && *usage == AuthorUsage::default() {
                next_author_rows = next_author_rows
                    .checked_sub(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            } else if present.is_none() && *usage != AuthorUsage::default() {
                next_author_rows = next_author_rows
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            }
        }
        if next_author_rows > self.policy.max_author_usage_rows {
            return Err(DurableStoreError::LimitExceeded("author usage rows"));
        }
        usage.author_usage_rows = next_author_rows;
        if !changed {
            if stored_projection != projection_commitment {
                return Err(DurableStoreError::DeltaConflict);
            }
        }
        Ok(SemanticDeltaPlan {
            base_usage,
            usage,
            author_usage,
            expected_base_projection,
            projection_commitment,
            rows,
            removed,
            custody_added: added_custody,
            custody_removed: removed_custody,
            changed,
        })
    }

    fn apply_semantic_delta(
        &self,
        transaction: &SemanticSqliteTransaction<'_>,
        plan: &SemanticDeltaPlan,
    ) -> Result<(), DurableStoreError> {
        let current_usage = self.read_semantic_usage_tx(transaction)?;
        if current_usage != plan.base_usage {
            return Err(DurableStoreError::DeltaConflict);
        }
        let stored_projection: Vec<u8> = transaction
            .query_row(
                "SELECT value FROM commitments WHERE name='projection'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let stored_projection: [u8; 32] =
            stored_projection
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid projection commitment".into(),
                })?;
        if stored_projection != plan.expected_base_projection {
            return Err(DurableStoreError::DeltaConflict);
        }
        let mut next_seq: i64 = transaction
            .query_row(
                "SELECT seq FROM facts ORDER BY seq DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?
            .unwrap_or(-1i64)
            .checked_add(1i64)
            .ok_or(DurableStoreError::LimitExceeded("fact sequence"))?;
        for removal in &plan.removed {
            let deleted = transaction
                .execute(
                    "DELETE FROM facts WHERE fact_id=? AND status='quarantined'",
                    params![removal.id.as_bytes().to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
            if deleted != 1 {
                return Err(DurableStoreError::DeltaConflict);
            }
        }
        for row in &plan.rows {
            let status = match row.status {
                SemanticFactStatus::Admitted => "admitted",
                SemanticFactStatus::Quarantined => "quarantined",
            };
            if row.promote {
                let updated = transaction
                    .execute(
                        "UPDATE facts SET status='admitted' WHERE fact_id=? AND status='quarantined'",
                        params![row.fact.id.as_bytes().to_vec()],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                if updated != 1 {
                    return Err(DurableStoreError::DeltaConflict);
                }
            } else if !row.existing {
                let encoded = self.encode_stored_fact(&row.fact)?;
                let author = row.fact.content.author.as_bytes().to_vec();
                let domain = serde_json::to_string(&row.fact.content.domain)?;
                transaction
                    .execute(
                        "INSERT INTO facts(fact_id,encoded,status,author,domain,seq)
                         VALUES(?,?,?,?,?,?)",
                        params![
                            row.fact.id.as_bytes().to_vec(),
                            encoded,
                            status,
                            author,
                            domain,
                            next_seq,
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                next_seq = next_seq
                    .checked_add(1)
                    .ok_or(DurableStoreError::LimitExceeded("fact sequence"))?;
                for dependency in canonical_dependencies(&row.fact) {
                    transaction
                        .execute(
                            "INSERT INTO dependencies(fact_id,dep_id) VALUES(?,?)",
                            params![
                                row.fact.id.as_bytes().to_vec(),
                                dependency.as_bytes().to_vec()
                            ],
                        )
                        .map_err(DurableStoreError::Sqlite)?;
                }
            }
        }
        for removal in &plan.removed {
            transaction
                .execute(
                    "DELETE FROM provisional WHERE fact_id=?",
                    params![removal.id.as_bytes().to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        for id in &plan.custody_removed {
            let deleted = transaction
                .execute(
                    "DELETE FROM provisional WHERE fact_id=?",
                    params![id.as_bytes().to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
            if deleted != 1 {
                return Err(DurableStoreError::DeltaConflict);
            }
        }
        for custody in &plan.custody_added {
            if custody.owner != SEMANTIC_INGRESS_OWNER {
                return Err(DurableStoreError::InvalidCustody);
            }
            transaction
                .execute(
                    "INSERT INTO provisional(fact_id,owner) VALUES(?,?)",
                    params![custody.fact_id.as_bytes().to_vec(), custody.owner],
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        Self::write_semantic_usage(transaction, plan.usage)?;
        for (author, usage) in &plan.author_usage {
            Self::write_author_usage(transaction, *author, *usage)?;
        }
        transaction
            .execute(
                "INSERT INTO commitments(name,value) VALUES('projection',?)
                 ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                params![plan.projection_commitment.to_vec()],
            )
            .map_err(DurableStoreError::Sqlite)?;
        Ok(())
    }

    fn persist_snapshot_transaction(
        &self,
        transaction: &SemanticSqliteTransaction<'_>,
        graph: &FactGraph,
        provisional: &[ProvisionalCustody],
        proofs: &[ProofRecord],
        projection_commitment: [u8; 32],
    ) -> Result<(), DurableStoreError> {
        Self::create_schema(transaction)?;
        let existing_context: Option<Vec<u8>> = transaction
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        if let Some(existing_context) = existing_context {
            if existing_context.as_slice() != graph.context_id().as_bytes() {
                let actual = existing_context
                    .try_into()
                    .map(MeshContextId::from_bytes)
                    .unwrap_or_else(|_| MeshContextId::from_bytes([0; 32]));
                return Err(DurableStoreError::ContextMismatch {
                    expected: graph.context_id(),
                    actual,
                });
            }
        }
        let previous_generation: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT generation FROM semantic_usage WHERE usage_id=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        let generation = match previous_generation {
            Some(value) => self
                .decode_usage_counter(value, "invalid usage generation")?
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            None => 0,
        };
        let previous_proof_generation: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT generation FROM proof_usage WHERE usage_id=1",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        let proof_generation = match previous_proof_generation {
            Some(value) => self
                .decode_usage_counter(value, "invalid proof generation")?
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            None => 0,
        };
        let encoded_context = graph.context_id().as_bytes().to_vec();
        transaction
            .execute(
                "INSERT INTO meta(key,value) VALUES('database_version',?)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![SEMANTIC_DATABASE_VERSION.to_be_bytes().to_vec()],
            )
            .map_err(DurableStoreError::Sqlite)?;
        transaction
            .execute(
                "INSERT INTO meta(key,value) VALUES('context_id',?)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![encoded_context],
            )
            .map_err(DurableStoreError::Sqlite)?;
        transaction
            .execute(
                "INSERT INTO meta(key,value) VALUES('fact_sequence','admission_v1')
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                [],
            )
            .map_err(DurableStoreError::Sqlite)?;
        transaction
            .execute(
                "INSERT INTO commitments(name,value) VALUES('projection',?)
                 ON CONFLICT(name) DO UPDATE SET value=excluded.value",
                params![projection_commitment.to_vec()],
            )
            .map_err(DurableStoreError::Sqlite)?;

        let mut usage = SemanticUsage {
            generation,
            ..SemanticUsage::default()
        };
        let mut author_usage = std::collections::BTreeMap::<[u8; 32], AuthorUsage>::new();
        let mut write_fact = transaction
            .0
            .prepare_cached(
                "INSERT INTO facts(fact_id,encoded,status,author,domain,seq)
                 VALUES(?,?,?,?,?,?)
                 ON CONFLICT(fact_id) DO UPDATE SET encoded=excluded.encoded,
                   status=excluded.status,author=excluded.author,domain=excluded.domain,seq=excluded.seq",
            )
            .map_err(DurableStoreError::Sqlite)?;
        let mut clear_dependencies = transaction
            .0
            .prepare_cached("DELETE FROM dependencies WHERE fact_id=?")
            .map_err(DurableStoreError::Sqlite)?;
        let mut write_dependency = transaction
            .0
            .prepare_cached("INSERT INTO dependencies(fact_id,dep_id) VALUES(?,?)")
            .map_err(DurableStoreError::Sqlite)?;
        if graph.admission_order.len() != graph.facts.len() {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "graph admission order is incomplete".into(),
            });
        }
        for (seq, (status, fact)) in graph
            .admission_order
            .iter()
            .map(|id| {
                (
                    "admitted",
                    graph
                        .facts
                        .get(id)
                        .expect("complete graph admission order was checked"),
                )
            })
            .chain(graph.quarantined.values().map(|fact| ("quarantined", fact)))
            .enumerate()
        {
            let encoded_bytes = Self::canonical_fact_bytes(fact)?;
            let encoded = self.encode_stored_fact(fact)?;
            if encoded_bytes > self.policy.max_fact_encoded_bytes {
                return Err(DurableStoreError::LimitExceeded("fact bytes"));
            }
            let dependencies = self.canonical_dependency_edges_for(graph, fact)?;
            if dependencies.len() as u64 > self.policy.max_dependencies_per_fact
                || fact.content.authority_uses.len() as u64
                    > self.policy.max_authority_uses_per_fact
                || fact.content.authority_uses.iter().any(|authority_use| {
                    authority_use.predecessors.len() as u64
                        > self.policy.max_authority_predecessors_per_use
                })
            {
                return Err(DurableStoreError::LimitExceeded("dependencies per fact"));
            }
            let author = author_usage
                .entry(fact.content.author.as_bytes())
                .or_default();
            author.retained_count = author
                .retained_count
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            author.retained_bytes = author
                .retained_bytes
                .checked_add(encoded_bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if status == "admitted" {
                usage.admitted_count = usage
                    .admitted_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                usage.admitted_bytes = usage
                    .admitted_bytes
                    .checked_add(encoded_bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            } else {
                usage.quarantined_count = usage
                    .quarantined_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                usage.quarantined_bytes = usage
                    .quarantined_bytes
                    .checked_add(encoded_bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                author.quarantined_count = author
                    .quarantined_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                author.quarantined_bytes = author
                    .quarantined_bytes
                    .checked_add(encoded_bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            }
            usage.dependency_edges = usage
                .dependency_edges
                .checked_add(
                    u64::try_from(dependencies.len())
                        .map_err(|_| DurableStoreError::InvalidPolicy)?,
                )
                .and_then(|count| count.checked_add(fact.content.authority_uses.len() as u64))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let sequence = i64::try_from(seq).map_err(|_| DurableStoreError::InvalidPolicy)?;
            write_fact
                .execute(params![
                    fact.id.as_bytes().as_slice(),
                    encoded,
                    status,
                    fact.content.author.as_bytes().as_slice(),
                    serde_json::to_string(&fact.content.domain)?,
                    sequence
                ])
                .map_err(DurableStoreError::Sqlite)?;
            clear_dependencies
                .execute(params![fact.id.as_bytes().as_slice()])
                .map_err(DurableStoreError::Sqlite)?;
            for dependency in dependencies {
                write_dependency
                    .execute(params![
                        fact.id.as_bytes().as_slice(),
                        dependency.as_bytes().as_slice()
                    ])
                    .map_err(DurableStoreError::Sqlite)?;
            }
        }
        drop(write_dependency);
        drop(clear_dependencies);
        drop(write_fact);
        if usage.admitted_count > self.policy.max_admitted_facts
            || usage.admitted_bytes > self.policy.max_admitted_bytes
            || usage.quarantined_count > self.policy.max_quarantined_facts
            || usage.quarantined_bytes > self.policy.max_quarantined_bytes
            || usage.dependency_edges > self.policy.max_dependency_edges
            || author_usage.values().any(|usage| {
                usage.retained_count > self.policy.max_retained_facts_per_author
                    || usage.retained_bytes > self.policy.max_retained_bytes_per_author
                    || usage.quarantined_count > self.policy.max_quarantined_facts_per_author
                    || usage.quarantined_bytes > self.policy.max_quarantined_bytes_per_author
            })
        {
            return Err(DurableStoreError::LimitExceeded("fact retention"));
        }
        usage.provisional_count =
            u64::try_from(provisional.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        usage.author_usage_rows =
            u64::try_from(author_usage.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        if usage.provisional_count > self.policy.max_provisional_rows {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }
        if usage.author_usage_rows > self.policy.max_author_usage_rows {
            return Err(DurableStoreError::LimitExceeded("author usage rows"));
        }
        Self::write_semantic_usage(transaction, usage)?;
        transaction
            .execute("DELETE FROM author_usage", [])
            .map_err(DurableStoreError::Sqlite)?;
        for (author, usage) in author_usage {
            Self::write_author_usage(transaction, author, usage)?;
        }
        transaction
            .execute("DELETE FROM provisional", [])
            .map_err(DurableStoreError::Sqlite)?;
        for custody in provisional {
            if custody.owner != SEMANTIC_INGRESS_OWNER {
                return Err(DurableStoreError::InvalidCustody);
            }
            transaction
                .execute(
                    "INSERT INTO provisional(fact_id,owner) VALUES(?,?)",
                    params![custody.fact_id.as_bytes().to_vec(), custody.owner],
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        Self::replace_proofs(transaction, proofs)?;
        Self::write_proof_usage(transaction, Self::proof_usage(proofs, proof_generation)?)
    }

    fn canonical_dependency_edges_for(
        &self,
        graph: &FactGraph,
        fact: &SignedFact,
    ) -> Result<Vec<FactId>, DurableStoreError> {
        if let Some(edges) = graph.canonical_dependency_edges(&fact.id) {
            return Ok(edges);
        }
        // Quarantined facts are intentionally not admitted into the graph's
        // derived index. The shared canonical decoder remains the exact same
        // edge definition used by bulk_restore for this row class.
        if graph.get(&fact.id).is_none() {
            return Ok(canonical_dependencies(fact));
        }
        Err(DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "canonical dependency index unavailable".into(),
        })
    }

    fn replace_proofs(
        transaction: &SemanticSqliteTransaction<'_>,
        proofs: &[ProofRecord],
    ) -> Result<(), DurableStoreError> {
        transaction
            .execute("DELETE FROM proof_facts", [])
            .map_err(DurableStoreError::Sqlite)?;
        transaction
            .execute("DELETE FROM proofs", [])
            .map_err(DurableStoreError::Sqlite)?;
        for proof in proofs {
            transaction
                .execute(
                    "INSERT INTO proofs(delivery_id,encoded,context_id,target,state)
                     VALUES(?,?,?,?,?)",
                    params![
                        proof.delivery_id.as_bytes().to_vec(),
                        serde_json::to_vec(proof)?,
                        proof.context_id.as_bytes().to_vec(),
                        proof.target.as_bytes().to_vec(),
                        serde_json::to_string(&proof.state)?
                    ],
                )
                .map_err(DurableStoreError::Sqlite)?;
            for fact_id in &proof.fact_ids {
                transaction
                    .execute(
                        "INSERT INTO proof_facts(delivery_id,fact_id) VALUES(?,?)",
                        params![
                            proof.delivery_id.as_bytes().to_vec(),
                            fact_id.as_bytes().to_vec()
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
            }
        }
        Ok(())
    }

    /// Persist only proof records whose canonical row or fact links changed.
    /// The caller has already validated the complete logical proof set; this
    /// routine keeps the durable write set proportional to that delta and
    /// leaves identical records completely untouched.
    #[cfg(test)]
    fn persist_proof_delta(
        transaction: &SemanticSqliteTransaction<'_>,
        before: &[ProofRecord],
        after: &[ProofRecord],
    ) -> Result<(), DurableStoreError> {
        let before = before
            .iter()
            .map(|proof| (proof.delivery_id, proof))
            .collect::<std::collections::BTreeMap<_, _>>();
        let after = after
            .iter()
            .map(|proof| (proof.delivery_id, proof))
            .collect::<std::collections::BTreeMap<_, _>>();
        for delivery_id in before.keys().filter(|id| !after.contains_key(id)) {
            transaction
                .execute(
                    "DELETE FROM proof_facts WHERE delivery_id=?",
                    params![delivery_id.as_bytes().to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
            transaction
                .execute(
                    "DELETE FROM proofs WHERE delivery_id=?",
                    params![delivery_id.as_bytes().to_vec()],
                )
                .map_err(DurableStoreError::Sqlite)?;
        }
        for (delivery_id, proof) in &after {
            let changed = before
                .get(delivery_id)
                .map(|previous| {
                    serde_json::to_vec(*previous).ok() != serde_json::to_vec(*proof).ok()
                        || previous.fact_ids != proof.fact_ids
                })
                .unwrap_or(true);
            if !changed {
                continue;
            }
            if before.contains_key(delivery_id) {
                transaction
                    .execute(
                        "DELETE FROM proof_facts WHERE delivery_id=?",
                        params![delivery_id.as_bytes().to_vec()],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
                transaction
                    .execute(
                        "UPDATE proofs SET encoded=?,context_id=?,target=?,state=?
                         WHERE delivery_id=?",
                        params![
                            serde_json::to_vec(*proof)?,
                            proof.context_id.as_bytes().to_vec(),
                            proof.target.as_bytes().to_vec(),
                            serde_json::to_string(&proof.state)?,
                            delivery_id.as_bytes().to_vec()
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
            } else {
                transaction
                    .execute(
                        "INSERT INTO proofs(delivery_id,encoded,context_id,target,state)
                         VALUES(?,?,?,?,?)",
                        params![
                            delivery_id.as_bytes().to_vec(),
                            serde_json::to_vec(*proof)?,
                            proof.context_id.as_bytes().to_vec(),
                            proof.target.as_bytes().to_vec(),
                            serde_json::to_string(&proof.state)?
                        ],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
            }
            for fact_id in &proof.fact_ids {
                transaction
                    .execute(
                        "INSERT INTO proof_facts(delivery_id,fact_id) VALUES(?,?)",
                        params![delivery_id.as_bytes().to_vec(), fact_id.as_bytes().to_vec()],
                    )
                    .map_err(DurableStoreError::Sqlite)?;
            }
        }
        Ok(())
    }

    fn preflight_snapshot_rows(
        &self,
        connection: &rusqlite::Connection,
        path: &Path,
    ) -> Result<(), DurableStoreError> {
        let scalar = |sql: &str| {
            connection
                .query_row(sql, [], |row| row.get::<_, i64>(0))
                .map_err(DurableStoreError::Sqlite)
        };
        let checked = |value: i64, reason: &'static str| {
            u64::try_from(value).map_err(|_| DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: reason.into(),
            })
        };
        let count_at_most = |sql: &str, limit: u64, label: &'static str| {
            let observed = checked(scalar(sql)?, "negative persisted row count")?;
            if observed > limit {
                return Err(DurableStoreError::LimitExceeded(label));
            }
            Ok(())
        };
        let max_length_at_most = |sql: &str, limit: u64, label: &'static str| {
            let observed: Option<i64> = connection
                .query_row(sql, [], |row| row.get(0))
                .map_err(DurableStoreError::Sqlite)?;
            let observed = observed
                .map(|value| checked(value, "negative persisted column length"))
                .transpose()?
                .unwrap_or(0);
            if observed > limit {
                return Err(DurableStoreError::LimitExceeded(label));
            }
            Ok(())
        };
        let sum_length_at_most = |sql: &str, limit: u64, label: &'static str| {
            let observed = checked(scalar(sql)?, "negative persisted byte sum")?;
            if observed > limit {
                return Err(DurableStoreError::LimitExceeded(label));
            }
            Ok(())
        };
        let exact_width = |sql: &str, label: &'static str| {
            let observed = checked(scalar(sql)?, "negative persisted width mismatch count")?;
            if observed != 0 {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: label.into(),
                });
            }
            Ok(())
        };
        let max_fact_rows = self
            .policy
            .max_admitted_facts
            .checked_add(self.policy.max_quarantined_facts)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        let max_fact_bytes = self
            .policy
            .max_admitted_bytes
            .checked_add(self.policy.max_quarantined_bytes)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        count_at_most("SELECT COUNT(*) FROM meta", 4, "meta rows")?;
        max_length_at_most("SELECT MAX(LENGTH(key)) FROM meta", 18, "meta key bytes")?;
        max_length_at_most(
            "SELECT MAX(LENGTH(value)) FROM meta",
            self.policy.max_live_checkpoint_bytes,
            "meta value bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(key)),0) FROM meta",
            4u64.checked_mul(18)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "meta key bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(value)),0) FROM meta",
            self.policy
                .max_live_checkpoint_bytes
                .checked_add(3 * 32)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "meta value bytes",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM meta
             WHERE key NOT IN ('database_version','context_id','fact_sequence','live_checkpoint_v1')",
            "unknown semantic metadata key",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM meta
             WHERE key != 'live_checkpoint_v1' AND LENGTH(value) > 32",
            "semantic metadata value exceeds its fixed bound",
        )?;

        count_at_most("SELECT COUNT(*) FROM facts", max_fact_rows, "fact rows")?;
        count_at_most(
            "SELECT COUNT(*) FROM facts WHERE status='admitted'",
            self.policy.max_admitted_facts,
            "admitted fact rows",
        )?;
        count_at_most(
            "SELECT COUNT(*) FROM facts WHERE status='quarantined'",
            self.policy.max_quarantined_facts,
            "quarantined fact rows",
        )?;
        max_length_at_most(
            "SELECT MAX(LENGTH(encoded)) FROM facts",
            self.policy.max_fact_encoded_bytes,
            "fact encoded bytes",
        )?;
        let fact_bytes = checked(
            scalar("SELECT COALESCE(SUM(LENGTH(encoded)),0) FROM facts")?,
            "negative fact byte sum",
        )?;
        if fact_bytes > max_fact_bytes {
            return Err(DurableStoreError::LimitExceeded("fact bytes"));
        }
        let admitted_bytes = checked(
            scalar("SELECT COALESCE(SUM(CASE WHEN status='admitted' THEN LENGTH(encoded) ELSE 0 END),0) FROM facts")?,
            "negative admitted fact byte sum",
        )?;
        if admitted_bytes > self.policy.max_admitted_bytes {
            return Err(DurableStoreError::LimitExceeded("admitted fact bytes"));
        }
        let quarantined_bytes = checked(
            scalar("SELECT COALESCE(SUM(CASE WHEN status='quarantined' THEN LENGTH(encoded) ELSE 0 END),0) FROM facts")?,
            "negative quarantined fact byte sum",
        )?;
        if quarantined_bytes > self.policy.max_quarantined_bytes {
            return Err(DurableStoreError::LimitExceeded("quarantined fact bytes"));
        }
        max_length_at_most(
            "SELECT MAX(LENGTH(status)) FROM facts",
            11,
            "fact status bytes",
        )?;
        max_length_at_most(
            "SELECT MAX(LENGTH(domain)) FROM facts",
            16,
            "fact domain bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(status)),0) FROM facts",
            max_fact_rows
                .checked_mul(11)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "fact status bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(domain)),0) FROM facts",
            max_fact_rows
                .checked_mul(16)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "fact domain bytes",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM facts WHERE LENGTH(fact_id) != 32",
            "fact identity width mismatch",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM facts WHERE LENGTH(author) != 32",
            "fact author width mismatch",
        )?;

        count_at_most(
            "SELECT COUNT(*) FROM semantic_usage",
            1,
            "semantic usage rows",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM semantic_usage WHERE usage_id != 1",
            "semantic usage identity mismatch",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM semantic_usage WHERE LENGTH(admitted_count) != 8
             OR LENGTH(admitted_bytes) != 8 OR LENGTH(quarantined_count) != 8
             OR LENGTH(quarantined_bytes) != 8 OR LENGTH(dependency_edges) != 8
             OR LENGTH(provisional_count) != 8 OR LENGTH(author_usage_rows) != 8
             OR LENGTH(generation) != 8",
            "semantic usage counter width mismatch",
        )?;
        for column in [
            "admitted_count",
            "admitted_bytes",
            "quarantined_count",
            "quarantined_bytes",
            "dependency_edges",
            "provisional_count",
            "author_usage_rows",
            "generation",
        ] {
            max_length_at_most(
                &format!("SELECT MAX(LENGTH({column})) FROM semantic_usage"),
                8,
                "semantic usage bytes",
            )?;
        }
        for column in [
            "admitted_count",
            "admitted_bytes",
            "quarantined_count",
            "quarantined_bytes",
            "dependency_edges",
            "provisional_count",
            "author_usage_rows",
            "generation",
        ] {
            sum_length_at_most(
                &format!("SELECT COALESCE(SUM(LENGTH({column})),0) FROM semantic_usage"),
                8,
                "semantic usage bytes",
            )?;
        }

        count_at_most(
            "SELECT COUNT(*) FROM author_usage",
            self.policy.max_author_usage_rows,
            "author usage rows",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM author_usage WHERE LENGTH(author) != 32",
            "author identity width mismatch",
        )?;
        for column in [
            "retained_count",
            "retained_bytes",
            "quarantined_count",
            "quarantined_bytes",
        ] {
            max_length_at_most(
                &format!("SELECT MAX(LENGTH({column})) FROM author_usage"),
                8,
                "author usage bytes",
            )?;
        }
        exact_width(
            "SELECT COUNT(*) FROM author_usage WHERE LENGTH(retained_count) != 8
             OR LENGTH(retained_bytes) != 8 OR LENGTH(quarantined_count) != 8
             OR LENGTH(quarantined_bytes) != 8",
            "author usage counter width mismatch",
        )?;
        for column in [
            "retained_count",
            "retained_bytes",
            "quarantined_count",
            "quarantined_bytes",
        ] {
            sum_length_at_most(
                &format!("SELECT COALESCE(SUM(LENGTH({column})),0) FROM author_usage"),
                self.policy
                    .max_author_usage_rows
                    .checked_mul(8)
                    .ok_or(DurableStoreError::InvalidPolicy)?,
                "author usage bytes",
            )?;
        }

        count_at_most(
            "SELECT COUNT(*) FROM dependencies",
            self.policy.max_dependency_edges,
            "dependency rows",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM dependencies WHERE LENGTH(fact_id) != 32 OR LENGTH(dep_id) != 32",
            "dependency identity width mismatch",
        )?;

        count_at_most(
            "SELECT COUNT(*) FROM provisional",
            self.policy.max_provisional_rows,
            "provisional rows",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM provisional WHERE LENGTH(fact_id) != 32",
            "provisional identity width mismatch",
        )?;
        max_length_at_most(
            "SELECT MAX(LENGTH(owner)) FROM provisional",
            SEMANTIC_INGRESS_OWNER_MAX_BYTES,
            "provisional owner bytes",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM provisional WHERE owner != 'semantic-ingress'",
            "provisional owner mismatch",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(owner)),0) FROM provisional",
            self.policy
                .max_provisional_rows
                .checked_mul(SEMANTIC_INGRESS_OWNER_MAX_BYTES)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "provisional owner bytes",
        )?;

        count_at_most(
            "SELECT COUNT(*) FROM proofs",
            self.policy.max_proof_records,
            "proof rows",
        )?;
        let pending_state = serde_json::to_string(&ProofRecordState::Pending)?;
        let pending_proof_count = checked(
            connection
                .query_row(
                    "SELECT COUNT(*) FROM proofs WHERE state=?",
                    params![pending_state.clone()],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(DurableStoreError::Sqlite)?,
            "negative pending proof row count",
        )?;
        if pending_proof_count > self.policy.max_pending_proofs {
            return Err(DurableStoreError::LimitExceeded("pending proof rows"));
        }
        max_length_at_most(
            "SELECT MAX(LENGTH(encoded)) FROM proofs",
            self.policy.max_proof_bytes,
            "proof encoded bytes",
        )?;
        let proof_bytes = checked(
            scalar("SELECT COALESCE(SUM(LENGTH(encoded)),0) FROM proofs")?,
            "negative proof byte sum",
        )?;
        if proof_bytes > self.policy.max_proof_bytes {
            return Err(DurableStoreError::LimitExceeded("proof bytes"));
        }
        let pending_proof_bytes = checked(
            connection
                .query_row(
                    "SELECT COALESCE(SUM(CASE WHEN state=? THEN LENGTH(encoded) ELSE 0 END),0) FROM proofs",
                    params![pending_state],
                    |row| row.get::<_, i64>(0),
                )
                .map_err(DurableStoreError::Sqlite)?,
            "negative pending proof byte sum",
        )?;
        if pending_proof_bytes > self.policy.max_pending_proof_bytes {
            return Err(DurableStoreError::LimitExceeded("pending proof bytes"));
        }
        max_length_at_most(
            "SELECT MAX(LENGTH(state)) FROM proofs",
            12,
            "proof state bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(state)),0) FROM proofs",
            self.policy
                .max_proof_records
                .checked_mul(12)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "proof state bytes",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM proofs WHERE LENGTH(delivery_id) != 32 OR LENGTH(context_id) != 32 OR LENGTH(target) != 32",
            "proof identity width mismatch",
        )?;

        count_at_most(
            "SELECT COUNT(*) FROM proof_facts",
            self.policy.max_proof_links,
            "proof links",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM proof_facts WHERE LENGTH(delivery_id) != 32 OR LENGTH(fact_id) != 32",
            "proof link identity width mismatch",
        )?;

        count_at_most("SELECT COUNT(*) FROM commitments", 1, "commitment rows")?;
        max_length_at_most(
            "SELECT MAX(LENGTH(name)) FROM commitments",
            10,
            "commitment name bytes",
        )?;
        sum_length_at_most(
            "SELECT COALESCE(SUM(LENGTH(name)),0) FROM commitments",
            10,
            "commitment name bytes",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM commitments WHERE LENGTH(value) != 32",
            "commitment value width mismatch",
        )?;

        count_at_most("SELECT COUNT(*) FROM proof_usage", 1, "proof usage rows")?;
        exact_width(
            "SELECT COUNT(*) FROM proof_usage WHERE usage_id != 1",
            "proof usage identity mismatch",
        )?;
        exact_width(
            "SELECT COUNT(*) FROM proof_usage WHERE LENGTH(total_count) != 8
             OR LENGTH(total_bytes) != 8 OR LENGTH(total_links) != 8
             OR LENGTH(pending_count) != 8
             OR LENGTH(pending_bytes) != 8 OR LENGTH(generation) != 8",
            "proof usage counter width mismatch",
        )?;
        for column in [
            "total_count",
            "total_bytes",
            "total_links",
            "pending_count",
            "pending_bytes",
            "generation",
        ] {
            max_length_at_most(
                &format!("SELECT MAX(LENGTH({column})) FROM proof_usage"),
                8,
                "proof usage bytes",
            )?;
        }
        for column in [
            "total_count",
            "total_bytes",
            "total_links",
            "pending_count",
            "pending_bytes",
            "generation",
        ] {
            sum_length_at_most(
                &format!("SELECT COALESCE(SUM(LENGTH({column})),0) FROM proof_usage"),
                8,
                "proof usage bytes",
            )?;
        }
        Ok(())
    }

    fn load_snapshot_connection(
        &self,
        connection: &SemanticSqliteConnection,
        path: &Path,
    ) -> Result<V4StoreAggregate, DurableStoreError> {
        connection
            .with_read_snapshot(|connection| {
                Ok(self.load_snapshot_connection_in_snapshot(connection, path))
            })
            .map_err(DurableStoreError::Sqlite)?
    }

    fn load_snapshot_connection_in_snapshot(
        &self,
        connection: &rusqlite::Connection,
        path: &Path,
    ) -> Result<V4StoreAggregate, DurableStoreError> {
        // Check every persisted count, width, and encoded-byte total before
        // fetching even the metadata blobs below.  This keeps corrupt rows
        // from turning into unbounded Vec/String materialization.
        self.preflight_snapshot_rows(connection, path)?;
        let version: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM meta WHERE key='database_version'",
                [],
                |row| row.get(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        let Some(version) = version else {
            return Err(if path.exists() {
                DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "database metadata is missing".into(),
                }
            } else {
                DurableStoreError::Missing {
                    path: path.to_path_buf(),
                }
            });
        };
        if version.as_slice() != SEMANTIC_DATABASE_VERSION.to_be_bytes().as_slice() {
            return Err(DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: "unsupported database version".into(),
            });
        }
        let max_fact_rows = self
            .policy
            .max_admitted_facts
            .checked_add(self.policy.max_quarantined_facts)
            .ok_or(DurableStoreError::InvalidPolicy)?;
        let context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        let context: [u8; 32] = context.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: "invalid context id".into(),
        })?;
        let context_id = MeshContextId::from_bytes(context);
        let fact_sequence = connection
            .query_row(
                "SELECT value FROM meta WHERE key='fact_sequence'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        if fact_sequence.as_deref() != Some("admission_v1") {
            return Err(DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: "unsupported fact sequence".into(),
            });
        }
        let admission_ordered = true;
        let admitted_capacity: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM facts WHERE status='admitted'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let quarantined_capacity: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM facts WHERE status='quarantined'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let mut admitted = Vec::with_capacity(
            usize::try_from(admitted_capacity).map_err(|_| DurableStoreError::InvalidPolicy)?,
        );
        let mut quarantined = Vec::with_capacity(
            usize::try_from(quarantined_capacity).map_err(|_| DurableStoreError::InvalidPolicy)?,
        );
        let mut fact_statement = connection
            .prepare_cached(
                "SELECT fact_id,encoded,status,author,domain,seq FROM facts ORDER BY seq",
            )
            .map_err(DurableStoreError::Sqlite)?;
        let mut rows = fact_statement
            .query([])
            .map_err(DurableStoreError::Sqlite)?;
        let mut previous_seq = None;
        let mut fact_rows = 0u64;
        while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
            fact_rows = fact_rows
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if fact_rows > max_fact_rows {
                return Err(DurableStoreError::LimitExceeded("fact rows"));
            }
            let fact_id: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
            let encoded: Vec<u8> = row.get(1).map_err(DurableStoreError::Sqlite)?;
            let status: String = row.get(2).map_err(DurableStoreError::Sqlite)?;
            let author: Vec<u8> = row.get(3).map_err(DurableStoreError::Sqlite)?;
            let domain: String = row.get(4).map_err(DurableStoreError::Sqlite)?;
            let seq: i64 = row.get(5).map_err(DurableStoreError::Sqlite)?;
            if seq < 0
                || previous_seq
                    .map(|previous| seq <= previous)
                    .unwrap_or(false)
            {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "fact sequence index is not strictly increasing".into(),
                });
            }
            previous_seq = Some(seq);
            let fact = self.decode_stored_fact(&encoded, context_id, &author, &fact_id)?;
            if fact.content.author.as_bytes().as_slice() != author.as_slice()
                || serde_json::to_string(&fact.content.domain)? != domain
            {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "fact index does not match signed bytes".into(),
                });
            }
            if status == "admitted" {
                admitted.push(fact);
            } else if status == "quarantined" {
                quarantined.push(fact);
            } else {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid fact status".into(),
                });
            }
        }
        drop(rows);
        drop(fact_statement);
        let mut dependency_edges = 0u64;
        let mut facts_by_id = admitted
            .iter()
            .chain(quarantined.iter())
            .collect::<Vec<_>>();
        facts_by_id.sort_unstable_by_key(|fact| fact.id);
        let mut dependency_statement = connection
            .prepare_cached("SELECT fact_id,dep_id FROM dependencies ORDER BY fact_id,dep_id")
            .map_err(DurableStoreError::Sqlite)?;
        let mut dependency_rows = dependency_statement
            .query([])
            .map_err(DurableStoreError::Sqlite)?;
        let decode_dependency = |row: &rusqlite::Row<'_>| {
            let fact_id: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
            let dependency: Vec<u8> = row.get(1).map_err(DurableStoreError::Sqlite)?;
            let fact_id = fact_id.try_into().map(FactId::from_bytes).map_err(|_| {
                DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid dependency fact id".into(),
                }
            })?;
            let dependency = dependency.try_into().map(FactId::from_bytes).map_err(|_| {
                DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid dependency id".into(),
                }
            })?;
            Ok::<_, DurableStoreError>((fact_id, dependency))
        };
        let mut next_dependency = dependency_rows
            .next()
            .map_err(DurableStoreError::Sqlite)?
            .map(&decode_dependency)
            .transpose()?;
        for fact in facts_by_id {
            let expected = canonical_dependencies(fact);
            let mut actual = Vec::with_capacity(expected.len());
            while let Some((fact_id, dependency)) = next_dependency.as_ref().copied() {
                if fact_id < fact.id {
                    return Err(DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "dependency index names an unknown fact".into(),
                    });
                }
                if fact_id > fact.id {
                    break;
                }
                actual.push(dependency);
                dependency_edges = dependency_edges
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                if dependency_edges > self.policy.max_dependency_edges {
                    return Err(DurableStoreError::LimitExceeded("dependency rows"));
                }
                next_dependency = dependency_rows
                    .next()
                    .map_err(DurableStoreError::Sqlite)?
                    .map(&decode_dependency)
                    .transpose()?;
            }
            if actual != expected {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "dependency index does not match signed bytes".into(),
                });
            }
        }
        if next_dependency.is_some() {
            return Err(DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: "dependency index names an unknown fact".into(),
            });
        }
        drop(dependency_rows);
        drop(dependency_statement);
        for fact in admitted.iter().chain(quarantined.iter()) {
            dependency_edges = dependency_edges
                .checked_add(fact.content.authority_uses.len() as u64)
                .ok_or_else(|| DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "dependency count overflow".into(),
                })?;
        }
        let provisional_rows: Vec<(Vec<u8>, String)> = bounded_query_collect(
            connection,
            "SELECT fact_id,owner FROM provisional ORDER BY fact_id,owner",
            [],
            self.policy.max_provisional_rows,
            self.policy
                .max_provisional_rows
                .checked_mul(
                    32u64
                        .checked_add(SEMANTIC_INGRESS_OWNER_MAX_BYTES)
                        .ok_or(DurableStoreError::InvalidPolicy)?,
                )
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "provisional owner bytes",
            |row| {
                let fact_id: Vec<u8> = row.get(0)?;
                let owner: String = row.get(1)?;
                let row_bytes = u64::try_from(fact_id.len())
                    .ok()
                    .and_then(|bytes| bytes.checked_add(u64::try_from(owner.len()).ok()?))
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                Ok(((fact_id, owner), row_bytes))
            },
        )?;
        if u64::try_from(provisional_rows.len()).map_err(|_| DurableStoreError::InvalidPolicy)?
            > self.policy.max_provisional_rows
        {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }
        let provisional = provisional_rows
            .into_iter()
            .map(|row| {
                let (fact_id, owner) = row;
                if owner != SEMANTIC_INGRESS_OWNER {
                    return Err(DurableStoreError::InvalidCustody);
                }
                let fact_id = fact_id.try_into().map(FactId::from_bytes).map_err(|_| {
                    DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "invalid custody fact id".into(),
                    }
                })?;
                Ok(ProvisionalCustody { fact_id, owner })
            })
            .collect::<Result<Vec<_>, DurableStoreError>>()?;
        let proof_rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, String)> = bounded_query_collect(
            connection,
            "SELECT delivery_id,encoded,context_id,target,state
                 FROM proofs ORDER BY delivery_id",
            [],
            self.policy.max_proof_records,
            self.policy
                .max_proof_records
                .checked_mul(108)
                .and_then(|fixed| self.policy.max_proof_bytes.checked_add(fixed))
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "proof bytes",
            |row| {
                let delivery_id: Vec<u8> = row.get(0)?;
                let encoded: Vec<u8> = row.get(1)?;
                let context_id: Vec<u8> = row.get(2)?;
                let target: Vec<u8> = row.get(3)?;
                let state: String = row.get(4)?;
                let row_bytes = [
                    delivery_id.len(),
                    encoded.len(),
                    context_id.len(),
                    target.len(),
                    state.len(),
                ]
                .into_iter()
                .try_fold(0u64, |total, length| -> rusqlite::Result<u64> {
                    total
                        .checked_add(
                            u64::try_from(length).map_err(|_| rusqlite::Error::InvalidQuery)?,
                        )
                        .ok_or(rusqlite::Error::InvalidQuery)
                })?;
                Ok(((delivery_id, encoded, context_id, target, state), row_bytes))
            },
        )?;
        let proofs = proof_rows
            .into_iter()
            .map(|row| {
                let (delivery_id, encoded, context_id, target, state) = row;
                let proof: ProofRecord = serde_json::from_slice(&encoded).map_err(|error| {
                    DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: error.to_string(),
                    }
                })?;
                let delivery_id: [u8; 32] =
                    delivery_id
                        .try_into()
                        .map_err(|_| DurableStoreError::Corrupt {
                            path: path.to_path_buf(),
                            reason: "invalid proof delivery index".into(),
                        })?;
                let context_id: [u8; 32] =
                    context_id
                        .try_into()
                        .map_err(|_| DurableStoreError::Corrupt {
                            path: path.to_path_buf(),
                            reason: "invalid proof context index".into(),
                        })?;
                let target: [u8; 32] =
                    target.try_into().map_err(|_| DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "invalid proof target index".into(),
                    })?;
                if proof.delivery_id.as_bytes() != &delivery_id
                    || proof.context_id.as_bytes() != &context_id
                    || proof.target.as_bytes() != target
                    || serde_json::to_string(&proof.state)? != state
                {
                    return Err(DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "proof index does not match signed bytes".into(),
                    });
                }
                Ok(proof)
            })
            .collect::<Result<Vec<ProofRecord>, DurableStoreError>>()?;
        let stored_proof_usage = self.read_proof_usage_raw(connection)?;
        let normalized_proof_usage = Self::proof_usage(&proofs, stored_proof_usage.generation)?;
        if stored_proof_usage != normalized_proof_usage {
            return Err(DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: "proof usage does not match normalized rows".into(),
            });
        }
        let proof_link_rows: Vec<(Vec<u8>, Vec<u8>)> = bounded_query_collect(
            connection,
            "SELECT delivery_id,fact_id FROM proof_facts ORDER BY delivery_id,fact_id",
            [],
            self.policy.max_proof_links,
            self.policy
                .max_proof_links
                .checked_mul(64)
                .ok_or(DurableStoreError::InvalidPolicy)?,
            "proof link bytes",
            |row| {
                let delivery_id: Vec<u8> = row.get(0)?;
                let fact_id: Vec<u8> = row.get(1)?;
                let row_bytes = u64::try_from(delivery_id.len())
                    .ok()
                    .and_then(|bytes| bytes.checked_add(u64::try_from(fact_id.len()).ok()?))
                    .ok_or(rusqlite::Error::InvalidQuery)?;
                Ok(((delivery_id, fact_id), row_bytes))
            },
        )?;
        if u64::try_from(proof_link_rows.len()).map_err(|_| DurableStoreError::InvalidPolicy)?
            > self.policy.max_proof_links
        {
            return Err(DurableStoreError::LimitExceeded("proof links"));
        }
        let mut proof_links = std::collections::BTreeMap::<[u8; 32], Vec<FactId>>::new();
        for row in proof_link_rows {
            let (delivery_id, fact_id) = row;
            let delivery_id = delivery_id
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid proof delivery id".into(),
                })?;
            let fact_id = fact_id.try_into().map(FactId::from_bytes).map_err(|_| {
                DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid proof fact link".into(),
                }
            })?;
            proof_links.entry(delivery_id).or_default().push(fact_id);
        }
        for proof in &proofs {
            if proof_links
                .remove(proof.delivery_id.as_bytes())
                .unwrap_or_default()
                != proof.fact_ids
            {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "proof fact index does not match proof bytes".into(),
                });
            }
        }
        {
            let (expected, expected_authors) =
                usage_from_facts(&admitted, &quarantined, dependency_edges, 0)?;
            let stored = connection
                .query_row(
                    "SELECT admitted_count,admitted_bytes,quarantined_count,
                            quarantined_bytes,dependency_edges,provisional_count,
                            author_usage_rows,generation
                     FROM semantic_usage WHERE usage_id=1",
                    [],
                    |row| {
                        Ok((
                            row.get::<_, Vec<u8>>(0)?,
                            row.get::<_, Vec<u8>>(1)?,
                            row.get::<_, Vec<u8>>(2)?,
                            row.get::<_, Vec<u8>>(3)?,
                            row.get::<_, Vec<u8>>(4)?,
                            row.get::<_, Vec<u8>>(5)?,
                            row.get::<_, Vec<u8>>(6)?,
                            row.get::<_, Vec<u8>>(7)?,
                        ))
                    },
                )
                .map_err(DurableStoreError::Sqlite)?;
            let stored = SemanticUsage {
                admitted_count: decode_counter_for_path(
                    stored.0,
                    path,
                    "invalid admitted usage count",
                )?,
                admitted_bytes: decode_counter_for_path(
                    stored.1,
                    path,
                    "invalid admitted usage bytes",
                )?,
                quarantined_count: decode_counter_for_path(
                    stored.2,
                    path,
                    "invalid quarantined usage count",
                )?,
                quarantined_bytes: decode_counter_for_path(
                    stored.3,
                    path,
                    "invalid quarantined usage bytes",
                )?,
                dependency_edges: decode_counter_for_path(
                    stored.4,
                    path,
                    "invalid dependency usage count",
                )?,
                provisional_count: decode_counter_for_path(
                    stored.5,
                    path,
                    "invalid provisional usage count",
                )?,
                author_usage_rows: decode_counter_for_path(
                    stored.6,
                    path,
                    "invalid author usage row count",
                )?,
                generation: decode_counter_for_path(stored.7, path, "invalid usage generation")?,
            };
            if stored.admitted_count != expected.admitted_count
                || stored.admitted_bytes != expected.admitted_bytes
                || stored.quarantined_count != expected.quarantined_count
                || stored.quarantined_bytes != expected.quarantined_bytes
                || stored.dependency_edges != expected.dependency_edges
                || stored.provisional_count
                    != u64::try_from(provisional.len()).map_err(|_| DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "provisional row count overflow".into(),
                    })?
            {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "semantic usage does not match normalized rows".into(),
                });
            }
            let author_rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> =
                bounded_query_collect(
                    connection,
                    "SELECT author,retained_count,retained_bytes,quarantined_count,quarantined_bytes
                     FROM author_usage ORDER BY author",
                    [],
                    self.policy.max_author_usage_rows,
                    self.policy
                        .max_author_usage_rows
                        .checked_mul(64)
                        .ok_or(DurableStoreError::InvalidPolicy)?,
                    "author usage bytes",
                    |row| {
                        let author: Vec<u8> = row.get(0)?;
                        let retained_count: Vec<u8> = row.get(1)?;
                        let retained_bytes: Vec<u8> = row.get(2)?;
                        let quarantined_count: Vec<u8> = row.get(3)?;
                        let quarantined_bytes: Vec<u8> = row.get(4)?;
                        let row_bytes = [
                            author.len(),
                            retained_count.len(),
                            retained_bytes.len(),
                            quarantined_count.len(),
                            quarantined_bytes.len(),
                        ]
                        .into_iter()
                        .try_fold(0u64, |total, length| -> rusqlite::Result<u64> {
                            total
                                .checked_add(
                                    u64::try_from(length).map_err(|_| {
                                        rusqlite::Error::InvalidQuery
                                    })?,
                                )
                                .ok_or(rusqlite::Error::InvalidQuery)
                        })?;
                        Ok((
                            (
                                author,
                                retained_count,
                                retained_bytes,
                                quarantined_count,
                                quarantined_bytes,
                            ),
                            row_bytes,
                        ))
                    },
                )?;
            if u64::try_from(author_rows.len()).map_err(|_| DurableStoreError::InvalidPolicy)?
                > self.policy.max_author_usage_rows
            {
                return Err(DurableStoreError::LimitExceeded("author usage rows"));
            }
            let mut actual_authors = std::collections::BTreeMap::new();
            for row in author_rows {
                let (author, retained_count, retained_bytes, quarantined_count, quarantined_bytes) =
                    row;
                let author: [u8; 32] =
                    author.try_into().map_err(|_| DurableStoreError::Corrupt {
                        path: path.to_path_buf(),
                        reason: "invalid author usage key".into(),
                    })?;
                actual_authors.insert(
                    author,
                    AuthorUsage {
                        retained_count: decode_counter_for_path(
                            retained_count,
                            path,
                            "invalid retained author count",
                        )?,
                        retained_bytes: decode_counter_for_path(
                            retained_bytes,
                            path,
                            "invalid retained author bytes",
                        )?,
                        quarantined_count: decode_counter_for_path(
                            quarantined_count,
                            path,
                            "invalid quarantined author count",
                        )?,
                        quarantined_bytes: decode_counter_for_path(
                            quarantined_bytes,
                            path,
                            "invalid quarantined author bytes",
                        )?,
                    },
                );
            }
            if actual_authors != expected_authors {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "author usage does not match normalized rows".into(),
                });
            }
            if stored.author_usage_rows
                != u64::try_from(actual_authors.len()).map_err(|_| DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "author usage row count overflow".into(),
                })?
            {
                return Err(DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "semantic usage author row count mismatch".into(),
                });
            }
        }
        if !proof_links.is_empty() {
            return Err(DurableStoreError::Corrupt {
                path: path.to_path_buf(),
                reason: "proof fact index names an unknown proof".into(),
            });
        }
        let projection_commitment: Vec<u8> = connection
            .query_row(
                "SELECT value FROM commitments WHERE name='projection'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let projection_commitment =
            projection_commitment
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: path.to_path_buf(),
                    reason: "invalid projection commitment".into(),
                })?;
        let snapshot = V4StoreAggregate::new_with_proofs(
            context_id,
            admitted,
            quarantined,
            admission_ordered,
            projection_commitment,
            provisional,
            proofs,
        )?;
        canonical_proofs(&snapshot.proofs)?;
        validate_proofs_for_aggregate(&snapshot)?;
        Ok(snapshot)
    }

    fn restore_unlocked(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let connection = self.open_database(false)?;
        self.restore_from_connection(&connection, bootstrap)
    }

    fn restore_live_checkpoint(
        &self,
        connection: &SemanticSqliteConnection,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<Option<RestoredSemanticState>, DurableStoreError> {
        let encoded: Option<Vec<u8>> = connection
            .query_row(
                "SELECT value FROM meta WHERE key=?",
                params![LIVE_CHECKPOINT_KEY],
                |row| row.get(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        let Some(encoded) = encoded else {
            return Ok(None);
        };
        if encoded.len() as u64 > self.policy.max_live_checkpoint_bytes {
            return Err(DurableStoreError::LimitExceeded("live checkpoint bytes"));
        }
        let checkpoint: DurableLiveCheckpoint =
            serde_json::from_slice(&encoded).map_err(|error| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: format!("invalid live checkpoint: {error}"),
            })?;
        if checkpoint.version != 1 {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "unsupported live checkpoint version".into(),
            });
        }
        let database_version: Vec<u8> = connection
            .query_row(
                "SELECT value FROM meta WHERE key='database_version'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if database_version.as_slice() != SEMANTIC_DATABASE_VERSION.to_be_bytes().as_slice() {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "unsupported database version".into(),
            });
        }
        let stored_context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        if stored_context.as_slice() != bootstrap.context_id().as_bytes() {
            let actual = stored_context
                .try_into()
                .map(MeshContextId::from_bytes)
                .unwrap_or_else(|_| MeshContextId::from_bytes([0; 32]));
            return Err(DurableStoreError::ContextMismatch {
                expected: bootstrap.context_id(),
                actual,
            });
        }
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&(
            checkpoint.generation,
            &checkpoint.graph,
            &checkpoint.provisional,
        ))?);
        if hasher.finalize().as_slice() != checkpoint.checksum {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "live checkpoint checksum mismatch".into(),
            });
        }
        let stored_usage = self.read_semantic_usage(connection)?;
        if checkpoint.generation != stored_usage.generation {
            // A process stopped between a semantic commit and its clean
            // checkpoint. The cache is merely stale; replay remains the
            // canonical crash-recovery path.
            return Ok(None);
        }
        let projection: Vec<u8> = connection
            .query_row(
                "SELECT value FROM commitments WHERE name='projection'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let projection: [u8; 32] =
            projection
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid projection commitment".into(),
                })?;
        let graph = FactGraph::from_live_checkpoint(bootstrap, self.policy, checkpoint.graph)
            .map_err(|reason| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason,
            })?;
        let counters = graph.durable_usage_counters();
        if counters
            != (
                stored_usage.admitted_count,
                stored_usage.admitted_bytes,
                stored_usage.quarantined_count,
                stored_usage.quarantined_bytes,
                stored_usage.dependency_edges,
            )
            || checkpoint.provisional.len() as u64 != stored_usage.provisional_count
        {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "live checkpoint counters do not match durable usage".into(),
            });
        }
        if !graph.verify_projection_commitment(projection) {
            return Err(DurableStoreError::ProjectionMismatch {
                path: self.path.clone(),
            });
        }
        validate_provisional_for_state(&checkpoint.provisional, &graph)?;
        Ok(Some(RestoredSemanticState {
            graph,
            provisional: checkpoint.provisional,
        }))
    }

    fn persist_live_checkpoint_connection(
        &self,
        connection: &mut SemanticSqliteConnection,
        graph: LiveFactGraphCheckpoint,
        provisional: Vec<ProvisionalCustody>,
    ) -> Result<(), DurableStoreError> {
        self.preflight_capacity(connection)?;
        let transaction = connection
            .transaction()
            .map_err(DurableStoreError::Sqlite)?;
        let generation: Vec<u8> = transaction
            .query_row(
                "SELECT generation FROM semantic_usage WHERE usage_id=1",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let generation = self.decode_usage_counter(generation, "invalid usage generation")?;
        let mut hasher = Sha256::new();
        hasher.update(serde_json::to_vec(&(generation, &graph, &provisional))?);
        let mut checksum = [0u8; 32];
        checksum.copy_from_slice(&hasher.finalize());
        let checkpoint = DurableLiveCheckpoint {
            version: 1,
            generation,
            graph,
            provisional,
            checksum,
        };
        let encoded = serde_json::to_vec(&checkpoint)?;
        if encoded.len() as u64 > self.policy.max_live_checkpoint_bytes {
            return Err(DurableStoreError::LimitExceeded("live checkpoint bytes"));
        }
        transaction
            .execute(
                "INSERT INTO meta(key,value) VALUES(?,?)
                 ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![LIVE_CHECKPOINT_KEY, encoded],
            )
            .map_err(DurableStoreError::Sqlite)?;
        transaction.commit().map_err(DurableStoreError::Sqlite)
    }

    fn restore_ordered_in_snapshot(
        &self,
        connection: &Connection,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        self.preflight_snapshot_rows(connection, &self.path)?;
        let version: Vec<u8> = connection
            .query_row(
                "SELECT value FROM meta WHERE key='database_version'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if version.as_slice() != SEMANTIC_DATABASE_VERSION.to_be_bytes().as_slice() {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "unsupported database version".into(),
            });
        }
        let context: Vec<u8> = connection
            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                row.get(0)
            })
            .map_err(DurableStoreError::Sqlite)?;
        let context: [u8; 32] = context.try_into().map_err(|_| DurableStoreError::Corrupt {
            path: self.path.clone(),
            reason: "invalid context id".into(),
        })?;
        let context_id = MeshContextId::from_bytes(context);
        if context_id != bootstrap.context_id() {
            return Err(DurableStoreError::ContextMismatch {
                expected: bootstrap.context_id(),
                actual: context_id,
            });
        }
        let stored_usage = self.read_semantic_usage_raw(connection)?;
        let mut expected_usage = SemanticUsage {
            generation: stored_usage.generation,
            ..SemanticUsage::default()
        };
        let mut expected_authors = std::collections::BTreeMap::<[u8; 32], AuthorUsage>::new();
        let mut quarantined = Vec::new();
        let mut graph = FactGraph::from_bootstrap_with_policy(bootstrap, self.policy);
        graph.begin_deferred_projection_commitment();

        let mut dependency_statement = connection
            .prepare("SELECT dep_id FROM dependencies WHERE fact_id=? ORDER BY dep_id")
            .map_err(DurableStoreError::Sqlite)?;
        let mut fact_statement = connection
            .prepare("SELECT fact_id,encoded,status,author,domain,seq FROM facts ORDER BY seq")
            .map_err(DurableStoreError::Sqlite)?;
        let mut rows = fact_statement
            .query([])
            .map_err(DurableStoreError::Sqlite)?;
        let mut previous_seq = None;
        while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
            #[cfg(test)]
            ORDERED_RESTORE_ROWS.fetch_add(1, Ordering::Relaxed);
            let fact_id: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
            let encoded: Vec<u8> = row.get(1).map_err(DurableStoreError::Sqlite)?;
            let status: String = row.get(2).map_err(DurableStoreError::Sqlite)?;
            let author: Vec<u8> = row.get(3).map_err(DurableStoreError::Sqlite)?;
            let domain: String = row.get(4).map_err(DurableStoreError::Sqlite)?;
            let seq: i64 = row.get(5).map_err(DurableStoreError::Sqlite)?;
            if seq < 0 || previous_seq.is_some_and(|previous| seq <= previous) {
                return Err(DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "fact sequence index is not strictly increasing".into(),
                });
            }
            previous_seq = Some(seq);
            let fact = self.decode_stored_fact(&encoded, context_id, &author, &fact_id)?;
            if fact.content.author.as_bytes().as_slice() != author.as_slice()
                || serde_json::to_string(&fact.content.domain)? != domain
            {
                return Err(DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "fact index does not match signed bytes".into(),
                });
            }

            let expected_dependencies = canonical_dependencies(&fact);
            let mut dependency_rows = dependency_statement
                .query(params![fact.id.as_bytes().to_vec()])
                .map_err(DurableStoreError::Sqlite)?;
            let mut actual_dependencies = Vec::with_capacity(expected_dependencies.len());
            while let Some(row) = dependency_rows.next().map_err(DurableStoreError::Sqlite)? {
                let dependency: Vec<u8> = row.get(0).map_err(DurableStoreError::Sqlite)?;
                let dependency: [u8; 32] =
                    dependency
                        .try_into()
                        .map_err(|_| DurableStoreError::Corrupt {
                            path: self.path.clone(),
                            reason: "invalid dependency id".into(),
                        })?;
                actual_dependencies.push(FactId::from_bytes(dependency));
            }
            if actual_dependencies != expected_dependencies {
                return Err(DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "dependency index does not match signed bytes".into(),
                });
            }

            let bytes = Self::canonical_fact_bytes(&fact)?;
            expected_usage.dependency_edges = expected_usage
                .dependency_edges
                .checked_add(
                    u64::try_from(actual_dependencies.len())
                        .map_err(|_| DurableStoreError::InvalidPolicy)?,
                )
                .and_then(|value| value.checked_add(fact.content.authority_uses.len() as u64))
                .ok_or(DurableStoreError::InvalidPolicy)?;
            let author_usage = expected_authors
                .entry(fact.content.author.as_bytes())
                .or_default();
            author_usage.retained_count = author_usage
                .retained_count
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            author_usage.retained_bytes = author_usage
                .retained_bytes
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;

            match status.as_str() {
                "admitted" => {
                    expected_usage.admitted_count = expected_usage
                        .admitted_count
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    expected_usage.admitted_bytes = expected_usage
                        .admitted_bytes
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    let needs_history = expected_dependencies
                        .iter()
                        .any(|dependency| graph.get(dependency).is_none());
                    let history = if needs_history {
                        self.admitted_causal_history_in_snapshot(
                            connection,
                            &expected_dependencies,
                        )?
                    } else {
                        Vec::new()
                    };
                    let journal = if history.is_empty() {
                        graph.admit_journaled(fact)
                    } else {
                        graph.admit_journaled_with_history(fact, history)
                    }
                    .map_err(|error| DurableStoreError::Rebuild {
                        path: self.path.clone(),
                        reason: error.to_string(),
                    })?;
                    if !matches!(journal.admission(), super::Admission::Inserted) {
                        return Err(DurableStoreError::Rebuild {
                            path: self.path.clone(),
                            reason: "admitted row did not replay as admitted".into(),
                        });
                    }
                    journal.commit();
                    graph.retire_cold_history();
                }
                "quarantined" => {
                    expected_usage.quarantined_count = expected_usage
                        .quarantined_count
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    expected_usage.quarantined_bytes = expected_usage
                        .quarantined_bytes
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    author_usage.quarantined_count = author_usage
                        .quarantined_count
                        .checked_add(1)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    author_usage.quarantined_bytes = author_usage
                        .quarantined_bytes
                        .checked_add(bytes)
                        .ok_or(DurableStoreError::InvalidPolicy)?;
                    quarantined.push(fact);
                }
                _ => {
                    return Err(DurableStoreError::Corrupt {
                        path: self.path.clone(),
                        reason: "invalid fact status".into(),
                    })
                }
            }
        }
        drop(rows);
        drop(fact_statement);
        drop(dependency_statement);

        let orphaned_dependencies: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM dependencies d LEFT JOIN facts f ON f.fact_id=d.fact_id WHERE f.fact_id IS NULL",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if orphaned_dependencies != 0 {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "dependency index names an unknown fact".into(),
            });
        }

        for fact in quarantined {
            let dependencies = canonical_dependencies(&fact);
            let history = self.admitted_causal_history_in_snapshot(connection, &dependencies)?;
            let journal = graph
                .admit_journaled_with_history(fact, history)
                .map_err(|error| DurableStoreError::Rebuild {
                    path: self.path.clone(),
                    reason: error.to_string(),
                })?;
            if !matches!(journal.admission(), super::Admission::Quarantined { .. }) {
                return Err(DurableStoreError::Rebuild {
                    path: self.path.clone(),
                    reason: "quarantined row did not replay as quarantined".into(),
                });
            }
            journal.commit();
            graph.retire_cold_history();
        }
        graph.finish_deferred_projection_commitment();

        let provisional = self.provisional_in_snapshot(connection)?;
        expected_usage.provisional_count =
            u64::try_from(provisional.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        expected_usage.author_usage_rows =
            u64::try_from(expected_authors.len()).map_err(|_| DurableStoreError::InvalidPolicy)?;
        if expected_usage != stored_usage {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "semantic usage does not match streamed rows".into(),
            });
        }

        let author_rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>, Vec<u8>)> =
            bounded_query_collect(
                connection,
                "SELECT author,retained_count,retained_bytes,quarantined_count,quarantined_bytes FROM author_usage ORDER BY author",
                [],
                self.policy.max_author_usage_rows,
                self.policy.max_author_usage_rows.checked_mul(64).ok_or(DurableStoreError::InvalidPolicy)?,
                "author usage rows",
                |row| {
                    let values = (row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?);
                    Ok((values, 64))
                },
            )?;
        let mut actual_authors = std::collections::BTreeMap::new();
        for (author, retained_count, retained_bytes, quarantined_count, quarantined_bytes) in
            author_rows
        {
            let author: [u8; 32] = author.try_into().map_err(|_| DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "invalid author usage key".into(),
            })?;
            actual_authors.insert(
                author,
                AuthorUsage {
                    retained_count: decode_counter_for_path(
                        retained_count,
                        &self.path,
                        "invalid retained author count",
                    )?,
                    retained_bytes: decode_counter_for_path(
                        retained_bytes,
                        &self.path,
                        "invalid retained author bytes",
                    )?,
                    quarantined_count: decode_counter_for_path(
                        quarantined_count,
                        &self.path,
                        "invalid quarantined author count",
                    )?,
                    quarantined_bytes: decode_counter_for_path(
                        quarantined_bytes,
                        &self.path,
                        "invalid quarantined author bytes",
                    )?,
                },
            );
        }
        if actual_authors != expected_authors {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "author usage does not match streamed rows".into(),
            });
        }

        validate_provisional_for_state(&provisional, &graph)?;
        let _proofs = self.proof_records_in_snapshot(connection, context_id)?;
        let projection_commitment: Vec<u8> = connection
            .query_row(
                "SELECT value FROM commitments WHERE name='projection'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        let projection_commitment: [u8; 32] =
            projection_commitment
                .try_into()
                .map_err(|_| DurableStoreError::Corrupt {
                    path: self.path.clone(),
                    reason: "invalid projection commitment".into(),
                })?;
        if !graph.verify_projection_commitment(projection_commitment) {
            return Err(DurableStoreError::ProjectionMismatch {
                path: self.path.clone(),
            });
        }
        Ok(RestoredSemanticState { graph, provisional })
    }

    fn restore_from_connection(
        &self,
        connection: &SemanticSqliteConnection,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let application_tables: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema
                 WHERE type='table' AND name NOT LIKE 'sqlite_%'",
                [],
                |row| row.get(0),
            )
            .map_err(DurableStoreError::Sqlite)?;
        if application_tables == 0 {
            // SQLite creates the main file before the first transaction. A
            // refused initial publication may therefore leave a valid empty
            // database, which is logically the same state as no snapshot.
            return Err(DurableStoreError::Missing {
                path: self.path.clone(),
            });
        }
        match self.restore_live_checkpoint(connection, bootstrap) {
            Ok(Some(restored)) => return Ok(restored),
            Ok(None) => {}
            Err(error) => {
                // The checkpoint is a bounded acceleration cache. Canonical
                // signed history remains recoverable through the existing
                // validating replay when the cache is damaged or obsolete.
                tracing::warn!(%error, "ignoring unusable semantic live checkpoint");
            }
        }
        let fact_sequence = connection
            .query_row(
                "SELECT value FROM meta WHERE key='fact_sequence'",
                [],
                |row| row.get::<_, String>(0),
            )
            .optional()
            .map_err(DurableStoreError::Sqlite)?;
        if fact_sequence.as_deref() != Some("admission_v1") {
            return Err(DurableStoreError::Corrupt {
                path: self.path.clone(),
                reason: "unsupported fact sequence".into(),
            });
        }
        connection
            .with_read_snapshot(|connection| {
                Ok(self.restore_ordered_in_snapshot(connection, bootstrap))
            })
            .map_err(DurableStoreError::Sqlite)?
    }
}

impl DurableSemanticOwner {
    /// Arm a slot-local one-shot commit control on this exact durable owner.
    /// The control is intended only for deterministic unit/transport-lab
    /// failure evidence and never changes ordinary production behavior.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn arm_commit_injection(
        &self,
        injection: SemanticCommitFaultForLab,
    ) -> Result<(), DurableStoreError> {
        self.store.arm_commit_injection(injection)
    }

    fn worker_call<T, F>(
        &self,
        create: bool,
        reopen: bool,
        compact_after_reopen: bool,
        operation: F,
    ) -> Result<T, DurableStoreError>
    where
        T: Send + 'static,
        F: FnOnce(
                &DurableSemanticStore,
                &mut SemanticSqliteConnection,
            ) -> Result<T, DurableStoreError>
            + Send
            + 'static,
    {
        self.worker
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)?
            .as_ref()
            .ok_or(DurableStoreError::OwnerReleased)?
            .call(create, reopen, compact_after_reopen, operation)
    }

    fn worker_call_commit<F>(
        &self,
        create: bool,
        reopen: bool,
        compact_after_reopen: bool,
        operation: F,
    ) -> Result<(), DurableStoreError>
    where
        F: FnOnce(
                &DurableSemanticStore,
                &mut SemanticSqliteConnection,
            ) -> Result<(), DurableStoreError>
            + Send
            + 'static,
    {
        #[cfg(any(test, feature = "transport-lab"))]
        let drop_commit_result = self
            .store
            .commit_injection_is_armed(SemanticCommitFaultForLab::CommitOutcomeUnknown);
        #[cfg(not(any(test, feature = "transport-lab")))]
        let drop_commit_result = false;
        self.worker
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)?
            .as_ref()
            .ok_or(DurableStoreError::OwnerReleased)?
            .call_commit(
                create,
                reopen,
                compact_after_reopen,
                drop_commit_result,
                operation,
            )
    }

    fn ensure_live_unlocked(&self) -> Result<(), DurableStoreError> {
        let worker = self
            .worker
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)?;
        match worker.as_ref() {
            Some(worker) if worker.poisoned.load(Ordering::Acquire) => {
                Err(DurableStoreError::WorkerPanicked)
            }
            Some(_) => Ok(()),
            None => Err(DurableStoreError::OwnerReleased),
        }
    }

    pub(crate) fn ensure_live(&self) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()
    }

    /// Read one admitted canonical fact by content id. Historical bodies are
    /// served from SQLite rather than retained in the live authority graph.
    pub(crate) fn admitted_fact(
        &self,
        fact_id: FactId,
    ) -> Result<Option<SignedFact>, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            let context = store.context_id_from_connection(&connection.inner)?;
            let row: Option<(Vec<u8>, String, Vec<u8>)> = connection
                .query_row(
                    "SELECT encoded,status,author FROM facts WHERE fact_id=?",
                    params![fact_id.as_bytes().to_vec()],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .map_err(DurableStoreError::Sqlite)?;
            let Some((encoded, status, author)) = row else {
                return Ok(None);
            };
            if status != "admitted" {
                return Ok(None);
            }
            let fact = store.decode_stored_fact(&encoded, context, &author, fact_id.as_bytes())?;
            Ok(Some(fact))
        })
    }

    pub(crate) fn admitted_facts(
        &self,
        fact_ids: Vec<FactId>,
    ) -> Result<Vec<Option<SignedFact>>, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            let context = store.context_id_from_connection(&connection.inner)?;
            let mut statement = connection
                .inner
                .prepare("SELECT encoded,status,author FROM facts WHERE fact_id=?")
                .map_err(DurableStoreError::Sqlite)?;
            let mut facts = Vec::with_capacity(fact_ids.len());
            for fact_id in fact_ids {
                let row: Option<(Vec<u8>, String, Vec<u8>)> = statement
                    .query_row(params![fact_id.as_bytes().to_vec()], |row| {
                        Ok((row.get(0)?, row.get(1)?, row.get(2)?))
                    })
                    .optional()
                    .map_err(DurableStoreError::Sqlite)?;
                let fact = match row {
                    Some((encoded, status, author)) if status == "admitted" => Some(
                        store.decode_stored_fact(&encoded, context, &author, fact_id.as_bytes())?,
                    ),
                    Some(_) | None => None,
                };
                facts.push(fact);
            }
            Ok(facts)
        })
    }

    /// Read a bounded deterministic page of admitted fact ids from SQLite.
    pub(crate) fn admitted_fact_ids_after(
        &self,
        cursor: Option<FactId>,
        limit: usize,
    ) -> Result<Vec<FactId>, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            let limit = i64::try_from(limit).map_err(|_| DurableStoreError::InvalidPolicy)?;
            let mut ids = Vec::new();
            let sql = if cursor.is_some() {
                "SELECT fact_id FROM facts WHERE status='admitted' AND fact_id>? ORDER BY fact_id LIMIT ?"
            } else {
                "SELECT fact_id FROM facts WHERE status='admitted' ORDER BY fact_id LIMIT ?"
            };
            connection.prepare(sql, |statement| {
                let mut rows = match cursor {
                    Some(cursor) => statement.query(params![cursor.as_bytes().to_vec(), limit])?,
                    None => statement.query(params![limit])?,
                };
                while let Some(row) = rows.next()? {
                    let encoded: Vec<u8> = row.get(0)?;
                    let bytes: [u8; 32] = encoded
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?;
                    ids.push(FactId::from_bytes(bytes));
                }
                Ok(())
            })
            .map_err(DurableStoreError::Sqlite)?;
            if ids.len() > usize::try_from(limit).unwrap_or(usize::MAX) {
                return Err(DurableStoreError::Corrupt {
                    path: store.path.clone(),
                    reason: "fact id page exceeded its SQL limit".into(),
                });
            }
            Ok(ids)
        })
    }

    /// Stream the exact durable semantic state commitment without
    /// materializing historical facts in the process heap.
    pub(crate) fn state_identity_digest(
        &self,
        context_id: MeshContextId,
    ) -> Result<(u64, u64, [u8; 32]), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            connection
                .with_read_snapshot(|connection| {
                    Ok((|| -> Result<(u64, u64, [u8; 32]), DurableStoreError> {
                        let stored_context: Vec<u8> = connection
                            .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                                row.get(0)
                            })
                            .map_err(DurableStoreError::Sqlite)?;
                        if stored_context.as_slice() != context_id.as_bytes() {
                            return Err(DurableStoreError::ContextMismatch {
                                expected: context_id,
                                actual: stored_context
                                    .try_into()
                                    .map(MeshContextId::from_bytes)
                                    .unwrap_or_else(|_| MeshContextId::from_bytes([0; 32])),
                            });
                        }
                        let usage = store.read_semantic_usage_raw(connection)?;
                        let mut hasher = Sha256::new();
                        hasher.update(b"myownmesh-semantic-state-v2\0context\0");
                        hasher.update(context_id.as_bytes());
                        hasher.update(b"\0admitted-count\0");
                        hasher.update(usage.admitted_count.to_le_bytes());
                        hasher.update(b"\0admitted\0");
                        for (status, count_label) in [
                            ("admitted", usage.admitted_count),
                            ("quarantined", usage.quarantined_count),
                        ] {
                            if status == "quarantined" {
                                hasher.update(b"\0unresolved-count\0");
                                hasher.update(count_label.to_le_bytes());
                                hasher.update(b"\0unresolved\0");
                            }
                            let sql = "SELECT fact_id,encoded,author FROM facts \
                                       WHERE status=? ORDER BY fact_id";
                            let mut statement =
                                connection.prepare(sql).map_err(DurableStoreError::Sqlite)?;
                            let mut rows = statement
                                .query(params![status])
                                .map_err(DurableStoreError::Sqlite)?;
                            let mut observed = 0u64;
                            while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
                                let fact_id: Vec<u8> =
                                    row.get(0).map_err(DurableStoreError::Sqlite)?;
                                let encoded: Vec<u8> =
                                    row.get(1).map_err(DurableStoreError::Sqlite)?;
                                let author: Vec<u8> =
                                    row.get(2).map_err(DurableStoreError::Sqlite)?;
                                if fact_id.len() != 32 {
                                    return Err(DurableStoreError::Corrupt {
                                        path: store.path.clone(),
                                        reason: "semantic identity row has an invalid id".into(),
                                    });
                                }
                                let fact = store
                                    .decode_stored_fact(&encoded, context_id, &author, &fact_id)?;
                                hasher.update(&fact_id);
                                hash_json_into(&mut hasher, &fact)?;
                                hasher.update([0]);
                                observed = observed
                                    .checked_add(1)
                                    .ok_or(DurableStoreError::InvalidPolicy)?;
                            }
                            if observed != count_label {
                                return Err(DurableStoreError::Corrupt {
                                    path: store.path.clone(),
                                    reason: "semantic identity rows do not match usage".into(),
                                });
                            }
                        }
                        let digest = hasher.finalize();
                        let mut commitment = [0u8; 32];
                        commitment.copy_from_slice(&digest);
                        Ok((usage.admitted_count, usage.quarantined_count, commitment))
                    })())
                })
                .map_err(DurableStoreError::Sqlite)?
        })
    }

    /// Load the bounded admitted causal closure needed to validate a stale or
    /// out-of-order candidate. SQLite performs recursive traversal; ordinary
    /// current-head admissions return only their direct hot witnesses and do
    /// not allocate history-sized process state.
    pub(crate) fn admitted_causal_history(
        &self,
        roots: Vec<FactId>,
    ) -> Result<Vec<SignedFact>, DurableStoreError> {
        if roots.is_empty() {
            return Ok(Vec::new());
        }
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            connection
                .with_read_snapshot(|connection| {
                    Ok((|| -> Result<Vec<SignedFact>, DurableStoreError> {
                        let placeholders = std::iter::repeat_n("(?)", roots.len())
                            .collect::<Vec<_>>()
                            .join(",");
                        let sql = format!(
                            "WITH RECURSIVE roots(fact_id) AS (VALUES {placeholders}),
                 closure(fact_id) AS (
                     SELECT fact_id FROM roots
                     UNION
                     SELECT d.dep_id FROM dependencies d JOIN closure c ON d.fact_id=c.fact_id
                 )
                 SELECT f.fact_id,f.encoded,f.author
                 FROM facts f JOIN closure c ON c.fact_id=f.fact_id
                 WHERE f.status='admitted'
                 ORDER BY f.seq"
                        );
                        let values = roots
                            .iter()
                            .map(|id| id.as_bytes().to_vec())
                            .collect::<Vec<_>>();
                        let params = rusqlite::params_from_iter(values.iter());
                        let rows: Vec<(Vec<u8>, Vec<u8>, Vec<u8>)> = bounded_query_collect(
                            connection,
                            &sql,
                            params,
                            store.policy.max_proof_links,
                            store.policy.max_proof_bytes,
                            "causal verification history",
                            |row| {
                                let id: Vec<u8> = row.get(0)?;
                                let encoded: Vec<u8> = row.get(1)?;
                                let author: Vec<u8> = row.get(2)?;
                                let bytes = u64::try_from(id.len())
                                    .ok()
                                    .and_then(|value| {
                                        value.checked_add(u64::try_from(encoded.len()).ok()?)
                                    })
                                    .and_then(|value| {
                                        value.checked_add(u64::try_from(author.len()).ok()?)
                                    })
                                    .ok_or(rusqlite::Error::InvalidQuery)?;
                                Ok(((id, encoded, author), bytes))
                            },
                        )?;
                        let context = store.context_id_from_connection(connection)?;
                        rows.into_iter()
                            .map(|(id, encoded, author)| {
                                store.decode_stored_fact(&encoded, context, &author, &id)
                            })
                            .collect()
                    })())
                })
                .map_err(DurableStoreError::Sqlite)?
        })
    }

    pub(crate) fn release(&self) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        let worker = self
            .worker
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)?
            .take();
        worker
            .map(SemanticStorageWorker::shutdown)
            .unwrap_or(Ok(()))
    }

    /// Purge the exact slot while retaining both the owner writer lease and a
    /// fresh caller-funded storage lease for the complete purge operation.
    pub(crate) fn purge_funded(
        &self,
        storage_lease: ResourceLease,
    ) -> Result<(), DurableStoreError> {
        if storage_lease.claim() != self.store.storage_claim()? {
            return Err(DurableStoreError::InvalidPolicy);
        }
        let _storage_lease = storage_lease;
        let _gate = self.store.lock_process()?;
        // Shutdown releases the owner's long-lived lease at its existing
        // terminal fence.  Purge then acquires one exact replacement lease
        // while the fresh storage lease is already held; no filesystem work
        // occurs between that admission and the purge.
        if self
            .worker
            .lock()
            .map_err(|_| DurableStoreError::InProcessGatePoisoned)?
            .is_some()
        {
            return Err(DurableStoreError::WriterBusy {
                path: self.store.lock_path.clone(),
            });
        }
        let _purge_lease = WriterLease::acquire(&self.store.lock_path)?;
        self.store.purge_storage_slot()
    }

    pub fn commit<I>(&self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let graph = graph.clone();
        let provisional = provisional.into_iter().collect::<Vec<_>>();
        self.worker_call(true, false, false, move |store, connection| {
            store.store_snapshot_on_connection(connection, &graph, provisional)
        })
    }

    pub(crate) fn commit_semantic_delta(
        &self,
        context_id: MeshContextId,
        delta: &SemanticDelta,
        expected_base_projection: [u8; 32],
        projection_commitment: [u8; 32],
        custody: &[ProvisionalCustody],
    ) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let delta = delta.clone();
        let custody = custody.to_vec();
        self.worker_call_commit(false, false, false, move |store, connection| {
            #[cfg(feature = "transport-lab")]
            let plan_phase = AdmissionPhaseGuard::new(AdmissionPhase::StorePlan);
            let plan = store.plan_semantic_delta(
                connection,
                context_id,
                &delta,
                expected_base_projection,
                projection_commitment,
                &custody,
                None,
            )?;
            #[cfg(feature = "transport-lab")]
            drop(plan_phase);
            if !plan.changed {
                return Ok(());
            }
            #[cfg(feature = "transport-lab")]
            let preflight_phase = AdmissionPhaseGuard::new(AdmissionPhase::CapacityPreflight);
            store.preflight_capacity(connection)?;
            #[cfg(feature = "transport-lab")]
            drop(preflight_phase);
            #[cfg(feature = "transport-lab")]
            let begin_phase = AdmissionPhaseGuard::new(AdmissionPhase::BeginImmediate);
            let transaction = connection
                .transaction()
                .map_err(DurableStoreError::Sqlite)?;
            #[cfg(feature = "transport-lab")]
            drop(begin_phase);
            #[cfg(feature = "transport-lab")]
            let apply_phase = AdmissionPhaseGuard::new(AdmissionPhase::SqlApply);
            store.apply_semantic_delta(&transaction, &plan)?;
            #[cfg(feature = "transport-lab")]
            drop(apply_phase);
            #[cfg(any(test, feature = "transport-lab"))]
            if store.take_commit_injection(SemanticCommitFaultForLab::BeforeCommit) {
                return Err(DurableStoreError::InjectedPrecommitFailure);
            }
            #[cfg(feature = "transport-lab")]
            let _commit_phase = AdmissionPhaseGuard::new(AdmissionPhase::CommitWalTerminal);
            transaction
                .commit()
                .map_err(|_| DurableStoreError::OutcomeUnknown)
                .and_then(|()| {
                    #[cfg(any(test, feature = "transport-lab"))]
                    if store.take_commit_injection(SemanticCommitFaultForLab::CommitOutcomeUnknown)
                    {
                        return Err(DurableStoreError::InjectedCommitOutcomeUnknown);
                    }
                    Ok(())
                })
        })
    }

    #[cfg(feature = "transport-lab")]
    pub(crate) fn commit_semantic_seed_delta_for_lab(
        &self,
        context_id: MeshContextId,
        delta: &SemanticDelta,
        expected_base_projection: [u8; 32],
        projection_commitment: [u8; 32],
        max_rows: usize,
    ) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let delta = delta.clone();
        self.worker_call(false, false, false, move |store, connection| {
            let plan = store.plan_semantic_delta(
                connection,
                context_id,
                &delta,
                expected_base_projection,
                projection_commitment,
                &[],
                Some(max_rows),
            )?;
            if !plan.changed {
                return Ok(());
            }
            store.preflight_capacity(connection)?;
            let transaction = connection
                .transaction()
                .map_err(DurableStoreError::Sqlite)?;
            store.apply_semantic_delta(&transaction, &plan)?;
            transaction.commit().map_err(DurableStoreError::Sqlite)
        })
    }

    pub(crate) fn enqueue_proof(
        &self,
        record: ProofRecord,
    ) -> Result<ProofRecord, DurableStoreError> {
        record
            .validate()
            .map_err(|error| DurableStoreError::InvalidProof(error.to_string()))?;
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            let stored_context: Vec<u8> = connection
                .query_row("SELECT value FROM meta WHERE key='context_id'", [], |row| {
                    row.get(0)
                })
                .map_err(DurableStoreError::Sqlite)?;
            if stored_context.as_slice() != record.context_id.as_bytes() {
                return Err(DurableStoreError::ContextMismatch {
                    expected: record.context_id,
                    actual: stored_context
                        .try_into()
                        .map(MeshContextId::from_bytes)
                        .unwrap_or_else(|_| MeshContextId::from_bytes([0; 32])),
                });
            }
            for fact_id in &record.fact_ids {
                let known: Option<i64> = connection
                    .query_row(
                        "SELECT 1 FROM facts WHERE fact_id=?",
                        params![fact_id.as_bytes().to_vec()],
                        |row| row.get(0),
                    )
                    .optional()
                    .map_err(DurableStoreError::Sqlite)?;
                if known.is_none() {
                    return Err(DurableStoreError::UnknownProofFact);
                }
            }
            if let Some(existing) =
                store.read_proof_record_connection(connection, record.delivery_id)?
            {
                if !DurableSemanticStore::same_delivery_payload(&existing, &record) {
                    return Err(DurableStoreError::ProofConflict);
                }
                return Ok(existing);
            }
            store.commit_proof_change(connection, record.delivery_id, None, Some(&record))?;
            Ok(record)
        })
    }

    pub(crate) fn rebind_proof(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_owner: &str,
        expected_binding: &str,
        new_owner: String,
        new_binding: String,
    ) -> Result<ProofRecord, DurableStoreError> {
        if new_owner.is_empty() || new_binding.is_empty() {
            return Err(DurableStoreError::InvalidProof(
                "proof owner and binding are required".into(),
            ));
        }
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let expected_owner = expected_owner.to_owned();
        let expected_binding = expected_binding.to_owned();
        self.worker_call(false, false, false, move |store, connection| {
            let current = store
                .read_proof_record_connection(connection, delivery_id)?
                .ok_or(DurableStoreError::ProofNotFound)?;
            if current.context_id != context_id {
                return Err(DurableStoreError::ContextMismatch {
                    expected: context_id,
                    actual: current.context_id,
                });
            }
            if current.state != ProofRecordState::Pending {
                return Err(DurableStoreError::ProofSettled);
            }
            if current.owner != expected_owner || current.binding != expected_binding {
                return Err(DurableStoreError::StaleProofBinding);
            }
            let mut next = current.clone();
            next.owner = new_owner;
            next.binding = new_binding;
            store.commit_proof_change(connection, delivery_id, Some(&current), Some(&next))?;
            Ok(next)
        })
    }

    pub(crate) fn settle_proof(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
    ) -> Result<bool, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            let Some(current) = store.read_proof_record_connection(connection, delivery_id)? else {
                return Ok(false);
            };
            if current.context_id != context_id {
                return Err(DurableStoreError::ContextMismatch {
                    expected: context_id,
                    actual: current.context_id,
                });
            }
            if current.state != ProofRecordState::Pending {
                return Ok(false);
            }
            let mut next = current.clone();
            next.state = ProofRecordState::Settled;
            store.commit_proof_change(connection, delivery_id, Some(&current), Some(&next))?;
            Ok(true)
        })
    }

    pub(crate) fn supersede_proof(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_target: &DeviceId,
        replacement_delivery_id: Option<ProofDeliveryId>,
    ) -> Result<bool, DurableStoreError> {
        if replacement_delivery_id == Some(delivery_id) {
            return Err(DurableStoreError::DeltaConflict);
        }
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let expected_target = expected_target.clone();
        self.worker_call(false, false, false, move |store, connection| {
            let current = store
                .read_proof_record_connection(connection, delivery_id)?
                .ok_or(DurableStoreError::ProofNotFound)?;
            if current.context_id != context_id {
                return Err(DurableStoreError::ContextMismatch {
                    expected: context_id,
                    actual: current.context_id,
                });
            }
            if current.target != expected_target {
                return Err(DurableStoreError::StaleProofTarget);
            }
            if current.state != ProofRecordState::Pending {
                return Ok(false);
            }
            let mut next = current.clone();
            next.state = ProofRecordState::Superseded;
            store.commit_proof_change(connection, delivery_id, Some(&current), Some(&next))?;
            Ok(true)
        })
    }

    pub fn restore(
        &self,
        bootstrap: &VerifiedBootstrap,
    ) -> Result<RestoredSemanticState, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let bootstrap = bootstrap.clone();
        self.worker_call(false, false, false, move |store, connection| {
            store.restore_from_connection(connection, &bootstrap)
        })
    }

    /// Persist the already-validated bounded live continuation at the same
    /// publication fence used by admission. This is a cache of canonical
    /// SQLite history, not a second authority: a generation mismatch falls
    /// back to ordinary replay after an unclean stop.
    pub(crate) fn persist_live_checkpoint(
        &self,
        graph: &FactGraph,
        provisional: &[ProvisionalCustody],
    ) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        let graph = graph.live_checkpoint();
        let provisional = provisional.to_vec();
        self.worker_call(false, false, false, move |store, connection| {
            store.persist_live_checkpoint_connection(connection, graph, provisional)
        })
    }

    pub fn compact(&self) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, true, true, |_store, _connection| Ok(()))
    }

    /// Finish a transport-lab bulk seed with the same SQLite TRUNCATE
    /// checkpoint used by ordinary compaction, without rebuilding the graph
    /// that the fixture has already validated in memory.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn checkpoint_scale_seed_for_lab(&self) -> Result<(), DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(true, true, true, |_store, _connection| Ok(()))
    }

    pub(crate) fn proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            store.proof_records_connection(connection, context_id)
        })
    }

    pub(crate) fn pending_proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        // Preserve the historical Missing error instead of allowing the
        // migration-capable worker open to create an empty slot.
        drop(self.store.open_database(false)?);
        self.worker_call(true, false, false, move |store, connection| {
            DurableSemanticStore::ensure_pending_proof_index(&connection.inner)?;
            store.pending_proof_records_connection(connection, context_id)
        })
    }

    #[cfg(test)]
    pub(crate) fn mutate_proof_records<F>(
        &self,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError> + Send + 'static,
    {
        let _gate = self.store.lock_process()?;
        self.ensure_live_unlocked()?;
        self.worker_call(false, false, false, move |store, connection| {
            store.mutate_proof_records_on_connection(connection, context_id, mutation)
        })
    }
}

impl Drop for DurableSemanticOwner {
    fn drop(&mut self) {
        if let Ok(worker) = self.worker.get_mut() {
            if let Some(worker) = worker.take() {
                let _ = worker.shutdown();
            }
        }
    }
}

/// A held durable writer lease. Dropping without commit is an explicit abort;
/// the previously published snapshot remains untouched.
#[cfg(test)]
pub struct DurableSemanticWriter {
    store: DurableSemanticStore,
    lease: WriterLease,
}

#[cfg(test)]
impl DurableSemanticWriter {
    pub fn commit<I>(self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let _gate = self.store.lock_process()?;
        let result = self.store.store_snapshot(graph, provisional);
        drop(self.lease);
        result
    }
}

impl DurableSemanticStore {
    fn store_snapshot<I>(&self, graph: &FactGraph, provisional: I) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let mut connection = self.open_database(true)?;
        self.store_snapshot_on_connection(&mut connection, graph, provisional)
    }

    fn store_snapshot_on_connection<I>(
        &self,
        connection: &mut SemanticSqliteConnection,
        graph: &FactGraph,
        provisional: I,
    ) -> Result<(), DurableStoreError>
    where
        I: IntoIterator<Item = ProvisionalCustody>,
    {
        let provisional = canonical_provisional(provisional)?;
        validate_provisional_for_state(&provisional, graph)?;
        if !self.policy.validate() {
            return Err(DurableStoreError::InvalidPolicy);
        }
        if u64::try_from(provisional.len()).map_err(|_| DurableStoreError::InvalidPolicy)?
            > self.policy.max_provisional_rows
        {
            return Err(DurableStoreError::LimitExceeded("provisional rows"));
        }
        if provisional
            .iter()
            .any(|claim| claim.owner != SEMANTIC_INGRESS_OWNER)
        {
            return Err(DurableStoreError::InvalidCustody);
        }
        // A newly created file has no schema until its first snapshot. Compile
        // a zero-row canonical query to distinguish that case without scanning
        // or materializing any proof rows.
        let schema_initialized =
            match connection.prepare("SELECT delivery_id FROM proofs LIMIT 0", |_| Ok(())) {
                Ok(()) => true,
                Err(error) if error.to_string() == "no such table: proofs" => false,
                Err(error) => return Err(DurableStoreError::Sqlite(error)),
            };
        let proofs = if !schema_initialized {
            Vec::new()
        } else {
            let proof_count = connection
                .query_row("SELECT COUNT(*) FROM proofs", [], |row| {
                    row.get::<_, i64>(0)
                })
                .map_err(DurableStoreError::Sqlite)?;
            if proof_count == 0 {
                Vec::new()
            } else {
                match self.load_snapshot_connection(connection, &self.path) {
                    Ok(snapshot) => {
                        if snapshot.context_id != graph.context_id() {
                            return Err(DurableStoreError::ContextMismatch {
                                expected: graph.context_id(),
                                actual: snapshot.context_id,
                            });
                        }
                        snapshot.proofs
                    }
                    Err(DurableStoreError::Missing { .. }) => Vec::new(),
                    Err(error) => return Err(error),
                }
            }
        };
        validate_proofs_for_state(&proofs, graph)?;
        if proofs.len() as u64 > self.policy.max_proof_records {
            return Err(DurableStoreError::LimitExceeded("proof count"));
        }
        let proof_bytes = proofs.iter().try_fold(0u64, |total, proof| {
            let bytes = u64::try_from(serde_json::to_vec(proof)?.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?;
            total
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)
        })?;
        if proof_bytes > self.policy.max_proof_bytes {
            return Err(DurableStoreError::LimitExceeded("proof bytes"));
        }
        let mut pending_proofs = proofs.iter().filter(|proof| proof.is_pending());
        let pending_count = pending_proofs.clone().count() as u64;
        let pending_bytes = pending_proofs.try_fold(0u64, |total, proof| {
            let bytes = u64::try_from(serde_json::to_vec(proof)?.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?;
            total
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)
        })?;
        if pending_count > self.policy.max_pending_proofs
            || pending_bytes > self.policy.max_pending_proof_bytes
        {
            return Err(DurableStoreError::LimitExceeded("pending proof retention"));
        }
        let projection_commitment = graph.projection_commitment_root();
        self.preflight_capacity(connection)?;
        let transaction = connection
            .transaction()
            .map_err(DurableStoreError::Sqlite)?;
        self.persist_snapshot_transaction(
            &transaction,
            graph,
            &provisional,
            &proofs,
            projection_commitment,
        )?;
        transaction.commit().map_err(DurableStoreError::Sqlite)?;
        Ok(())
    }

    fn checkpoint_and_compact(&self) -> Result<(), DurableStoreError> {
        let connection = self.open_database(false)?;
        self.checkpoint_and_compact_connection(&connection)
    }

    fn checkpoint_and_compact_connection(
        &self,
        connection: &SemanticSqliteConnection,
    ) -> Result<(), DurableStoreError> {
        let report = connection
            .checkpoint(true)
            .map_err(DurableStoreError::Sqlite)?;
        if report.busy || report.log_frames != 0 || report.checkpointed_frames != 0 {
            return Err(DurableStoreError::LimitExceeded("WAL checkpoint"));
        }
        Ok(())
    }
}

impl V4StoreAggregate {
    fn new_with_proofs(
        context_id: MeshContextId,
        facts: Vec<SignedFact>,
        quarantined: Vec<SignedFact>,
        admission_ordered: bool,
        projection_commitment: [u8; 32],
        provisional: Vec<ProvisionalCustody>,
        proofs: Vec<ProofRecord>,
    ) -> Result<Self, DurableStoreError> {
        let snapshot = Self {
            context_id,
            facts,
            quarantined,
            admission_ordered,
            projection_commitment,
            provisional,
            proofs,
        };
        Ok(snapshot)
    }
}

fn canonical_proofs(values: &[ProofRecord]) -> Result<(), DurableStoreError> {
    for proof in values {
        proof
            .validate()
            .map_err(|error| DurableStoreError::InvalidProof(error.to_string()))?;
    }
    if values
        .windows(2)
        .any(|pair| pair[0].delivery_id >= pair[1].delivery_id)
    {
        return Err(DurableStoreError::DuplicateProof);
    }
    Ok(())
}

fn validate_proofs_for_aggregate(snapshot: &V4StoreAggregate) -> Result<(), DurableStoreError> {
    let mut known = std::collections::BTreeSet::new();
    known.extend(snapshot.facts.iter().map(|fact| fact.id));
    known.extend(snapshot.quarantined.iter().map(|fact| fact.id));
    for proof in &snapshot.proofs {
        if proof
            .fact_ids
            .iter()
            .any(|fact_id| !known.contains(fact_id))
        {
            return Err(DurableStoreError::UnknownProofFact);
        }
    }
    Ok(())
}

fn canonical_provisional<I>(values: I) -> Result<Vec<ProvisionalCustody>, DurableStoreError>
where
    I: IntoIterator<Item = ProvisionalCustody>,
{
    let mut values: Vec<_> = values.into_iter().collect();
    if values
        .iter()
        .any(|claim| claim.owner != SEMANTIC_INGRESS_OWNER)
    {
        return Err(DurableStoreError::InvalidCustody);
    }
    values.sort_by(|left, right| {
        left.fact_id
            .cmp(&right.fact_id)
            .then_with(|| left.owner.cmp(&right.owner))
    });
    if values.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(DurableStoreError::DuplicateCustody);
    }
    Ok(values)
}

fn validate_provisional_for_state(
    claims: &[ProvisionalCustody],
    graph: &FactGraph,
) -> Result<(), DurableStoreError> {
    let unresolved: std::collections::BTreeSet<_> =
        graph.quarantined().map(|(id, _)| *id).collect();
    if claims.len() != unresolved.len()
        || claims
            .iter()
            .any(|claim| !unresolved.contains(&claim.fact_id))
    {
        return Err(DurableStoreError::UnknownCustodyFact);
    }
    Ok(())
}

fn validate_proofs_for_state(
    proofs: &[ProofRecord],
    graph: &FactGraph,
) -> Result<(), DurableStoreError> {
    canonical_proofs(proofs)?;
    let mut known = std::collections::BTreeSet::new();
    known.extend(graph.facts.keys().copied());
    known.extend(graph.quarantined().map(|(id, _)| *id));
    for proof in proofs {
        if proof
            .fact_ids
            .iter()
            .any(|fact_id| !known.contains(fact_id))
        {
            return Err(DurableStoreError::UnknownProofFact);
        }
    }
    Ok(())
}

fn decode_counter_for_path(
    value: Vec<u8>,
    path: &Path,
    reason: &'static str,
) -> Result<u64, DurableStoreError> {
    Ok(u64::from_be_bytes(value.try_into().map_err(|_| {
        DurableStoreError::Corrupt {
            path: path.to_path_buf(),
            reason: reason.into(),
        }
    })?))
}

fn bounded_query_collect<T, P, F>(
    connection: &rusqlite::Connection,
    sql: &str,
    params: P,
    row_limit: u64,
    byte_limit: u64,
    label: &'static str,
    mut map: F,
) -> Result<Vec<T>, DurableStoreError>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<(T, u64)>,
{
    let mut statement = connection.prepare(sql).map_err(DurableStoreError::Sqlite)?;
    let mut rows = statement.query(params).map_err(DurableStoreError::Sqlite)?;
    let mut values = Vec::new();
    let mut row_count = 0u64;
    let mut byte_count = 0u64;
    while let Some(row) = rows.next().map_err(DurableStoreError::Sqlite)? {
        if row_count >= row_limit {
            return Err(DurableStoreError::LimitExceeded(label));
        }
        let (value, row_bytes) = map(row).map_err(DurableStoreError::Sqlite)?;
        let next_bytes = byte_count
            .checked_add(row_bytes)
            .ok_or(DurableStoreError::LimitExceeded(label))?;
        if next_bytes > byte_limit {
            return Err(DurableStoreError::LimitExceeded(label));
        }
        byte_count = next_bytes;
        row_count = row_count
            .checked_add(1)
            .ok_or(DurableStoreError::LimitExceeded(label))?;
        values.push(value);
    }
    Ok(values)
}

fn bounded_vfs_query_collect<T, P, F>(
    connection: &SemanticSqliteConnection,
    sql: &str,
    params: P,
    row_limit: u64,
    byte_limit: u64,
    label: &'static str,
    mut map: F,
) -> Result<Vec<T>, DurableStoreError>
where
    P: rusqlite::Params,
    F: FnMut(&rusqlite::Row<'_>) -> rusqlite::Result<(T, u64)>,
{
    let exceeded = std::cell::Cell::new(false);
    let result = connection.prepare(sql, |statement| {
        let mut rows = statement.query(params)?;
        let mut values = Vec::new();
        let mut row_count = 0u64;
        let mut byte_count = 0u64;
        while let Some(row) = rows.next()? {
            if row_count >= row_limit {
                exceeded.set(true);
                return Err(rusqlite::Error::InvalidQuery);
            }
            let (value, row_bytes) = map(row)?;
            let Some(next_bytes) = byte_count.checked_add(row_bytes) else {
                exceeded.set(true);
                return Err(rusqlite::Error::InvalidQuery);
            };
            if next_bytes > byte_limit {
                exceeded.set(true);
                return Err(rusqlite::Error::InvalidQuery);
            }
            byte_count = next_bytes;
            row_count = row_count.checked_add(1).ok_or_else(|| {
                exceeded.set(true);
                rusqlite::Error::InvalidQuery
            })?;
            values.push(value);
        }
        Ok(values)
    });
    match result {
        Ok(values) => Ok(values),
        Err(_) if exceeded.get() => Err(DurableStoreError::LimitExceeded(label)),
        Err(error) => Err(DurableStoreError::Sqlite(error)),
    }
}

fn usage_from_facts(
    admitted: &[SignedFact],
    quarantined: &[SignedFact],
    dependency_edges: u64,
    generation: u64,
) -> Result<
    (
        SemanticUsage,
        std::collections::BTreeMap<[u8; 32], AuthorUsage>,
    ),
    DurableStoreError,
> {
    let mut usage = SemanticUsage {
        dependency_edges,
        generation,
        ..SemanticUsage::default()
    };
    let mut authors = std::collections::BTreeMap::<[u8; 32], AuthorUsage>::new();
    for (facts, quarantined) in [(admitted, false), (quarantined, true)] {
        for fact in facts {
            let bytes = u64::try_from(serde_json::to_vec(fact)?.len())
                .map_err(|_| DurableStoreError::InvalidPolicy)?;
            let entry = authors.entry(fact.content.author.as_bytes()).or_default();
            entry.retained_count = entry
                .retained_count
                .checked_add(1)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            entry.retained_bytes = entry
                .retained_bytes
                .checked_add(bytes)
                .ok_or(DurableStoreError::InvalidPolicy)?;
            if quarantined {
                usage.quarantined_count = usage
                    .quarantined_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                usage.quarantined_bytes = usage
                    .quarantined_bytes
                    .checked_add(bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                entry.quarantined_count = entry
                    .quarantined_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                entry.quarantined_bytes = entry
                    .quarantined_bytes
                    .checked_add(bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            } else {
                usage.admitted_count = usage
                    .admitted_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
                usage.admitted_bytes = usage
                    .admitted_bytes
                    .checked_add(bytes)
                    .ok_or(DurableStoreError::InvalidPolicy)?;
            }
        }
    }
    Ok((usage, authors))
}

/// Compute the same projection commitment that is sealed into the durable
/// snapshot, for a live graph inspection.  Keeping this wrapper beside the
/// snapshot encoder keeps callers on the versioned Merkle root API.
pub(crate) fn projection_commitment_for_graph(graph: &FactGraph) -> [u8; 32] {
    graph.projection_commitment_root()
}

/// Create a missing directory hierarchy one component at a time. Each newly
/// created child is followed by a sync of its containing directory, so a
/// first install does not rely on `create_dir_all`'s unsignaled hierarchy.
fn ensure_directory_chain(path: &Path) -> Result<(), BootstrapStoreError> {
    let mut missing = Vec::new();
    let mut cursor = path.to_path_buf();
    loop {
        match std::fs::symlink_metadata(&cursor) {
            Ok(metadata) => {
                if !metadata.is_dir() {
                    return Err(BootstrapStoreError::Io {
                        path: cursor,
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotADirectory,
                            "bootstrap store component is not a directory",
                        ),
                    });
                }
                break;
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                missing.push(cursor.clone());
                cursor = cursor
                    .parent()
                    .map(|parent| {
                        if parent.as_os_str().is_empty() {
                            PathBuf::from(".")
                        } else {
                            parent.to_path_buf()
                        }
                    })
                    .ok_or_else(|| BootstrapStoreError::InvalidPath(path.to_path_buf()))?;
            }
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: cursor,
                    source,
                });
            }
        }
    }

    for child in missing.iter().rev() {
        match std::fs::create_dir(child) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let metadata =
                    std::fs::symlink_metadata(child).map_err(|source| BootstrapStoreError::Io {
                        path: child.clone(),
                        source,
                    })?;
                if !metadata.is_dir() {
                    return Err(BootstrapStoreError::Io {
                        path: child.clone(),
                        source: std::io::Error::new(
                            std::io::ErrorKind::NotADirectory,
                            "bootstrap store component is not a directory",
                        ),
                    });
                }
            }
            Err(source) => {
                return Err(BootstrapStoreError::Io {
                    path: child.clone(),
                    source,
                });
            }
        }
        let containing = child
            .parent()
            .map(|parent| {
                if parent.as_os_str().is_empty() {
                    PathBuf::from(".")
                } else {
                    parent.to_path_buf()
                }
            })
            .ok_or_else(|| BootstrapStoreError::InvalidPath(child.clone()))?;
        sync_parent(&containing)?;
    }
    Ok(())
}

/// Re-establish directory durability edges from the record directory through
/// its existing ancestors. This is needed both after linking and on an
/// identical-record retry, where the file already exists but a prior caller's
/// directory sync may have failed or been interrupted.
fn sync_directory_chain(path: &Path) -> Result<(), BootstrapStoreError> {
    let mut current = Some(path.to_path_buf());
    while let Some(directory) = current {
        sync_parent(&directory)?;
        current = directory.parent().and_then(|parent| {
            if parent.as_os_str().is_empty() {
                (directory.as_path() != Path::new(".")).then(|| PathBuf::from("."))
            } else if parent == directory.as_path() {
                None
            } else {
                Some(parent.to_path_buf())
            }
        });
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(parent: &Path) -> Result<(), BootstrapStoreError> {
    let directory = std::fs::File::open(parent).map_err(|source| BootstrapStoreError::Io {
        path: parent.to_path_buf(),
        source,
    })?;
    directory
        .sync_all()
        .map_err(|source| BootstrapStoreError::Io {
            path: parent.to_path_buf(),
            source,
        })
}

#[cfg(not(unix))]
fn sync_parent(parent: &Path) -> Result<(), BootstrapStoreError> {
    let _ = parent;
    Ok(())
}

/// Fail-closed storage and validation failures.
#[derive(Debug, Error)]
pub enum BootstrapStoreError {
    #[error("bootstrap store is missing: {path}")]
    Missing { path: PathBuf },
    #[error("bootstrap store is corrupt at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("bootstrap record conflicts with the established record at {path}")]
    Conflict { path: PathBuf },
    #[error("bootstrap context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("bootstrap record is invalid: {0}")]
    Invalid(#[source] BootstrapError),
    #[error("bootstrap store path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("bootstrap store I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("bootstrap record serialization failed: {0}")]
    Serialization(#[from] JsonError),
}

/// Fail-closed errors for the atomic semantic snapshot store.
#[derive(Debug, Error)]
pub enum DurableStoreError {
    #[error("semantic snapshot is missing: {path}")]
    Missing { path: PathBuf },
    #[error("semantic snapshot is corrupt at {path}: {reason}")]
    Corrupt { path: PathBuf, reason: String },
    #[error("semantic delta conflicts with the durable generation or row state")]
    DeltaConflict,
    #[error("semantic snapshot context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("semantic snapshot projection commitment mismatch at {path}")]
    ProjectionMismatch { path: PathBuf },
    #[error("semantic snapshot cannot rebuild at {path}: {reason}")]
    Rebuild { path: PathBuf, reason: String },
    #[error("semantic snapshot writer is busy: {path}")]
    WriterBusy { path: PathBuf },
    #[error("semantic snapshot in-process gate is poisoned")]
    InProcessGatePoisoned,
    #[error("semantic snapshot owner has been released")]
    OwnerReleased,
    #[error("semantic storage worker panicked")]
    WorkerPanicked,
    /// The worker or SQLite returned after the atomic commit boundary could
    /// not be classified. Callers must reconcile exact fact IDs, generation,
    /// and projection commitment before retrying; this is never a rollback
    /// indication.
    #[error("semantic snapshot commit outcome is unknown; reconcile durable state")]
    OutcomeUnknown,
    #[error("semantic snapshot commit was refused before SQLite mutation by the test control")]
    InjectedPrecommitFailure,
    #[error("semantic snapshot commit result was intentionally lost after SQLite COMMIT")]
    InjectedCommitOutcomeUnknown,
    #[error("semantic snapshot commit injection control is poisoned")]
    CommitInjectionPoisoned,
    #[error("semantic snapshot commit injection is already armed")]
    CommitInjectionAlreadyArmed,
    #[error("semantic snapshot path has no parent: {0}")]
    InvalidPath(PathBuf),
    #[error("semantic snapshot I/O at {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("semantic snapshot contains invalid provisional custody")]
    InvalidCustody,
    #[error("semantic snapshot provisional custody names an unknown fact")]
    UnknownCustodyFact,
    #[error("semantic snapshot contains duplicate provisional custody")]
    DuplicateCustody,
    #[error("semantic snapshot contains an invalid proof record: {0}")]
    InvalidProof(String),
    #[error("semantic snapshot contains duplicate proof delivery identity")]
    DuplicateProof,
    #[error("semantic snapshot proof delivery identity conflicts with existing metadata")]
    ProofConflict,
    #[error("semantic snapshot proof delivery identity was not found")]
    ProofNotFound,
    #[error("semantic snapshot proof delivery is already settled")]
    ProofSettled,
    #[error("semantic snapshot proof binding is stale")]
    StaleProofBinding,
    #[error("semantic snapshot proof target is stale")]
    StaleProofTarget,
    #[error("semantic snapshot proof names an unknown fact")]
    UnknownProofFact,
    #[error("semantic store policy is invalid")]
    InvalidPolicy,
    #[error("semantic store limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("semantic SQLite operation failed: {0}")]
    Sqlite(#[source] rusqlite::Error),
    #[error("semantic snapshot serialization failed: {0}")]
    Serialization(#[from] JsonError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{FactBody, FactContent, FactDomain, ProofRecord};
    use ed25519_dalek::SigningKey;
    use std::process::{Command, Stdio};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn root() -> PathBuf {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "myownmesh-bootstrap-store-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test store root");
        root
    }

    fn closed(scope: &str, seed: u8, creation_id: [u8; 32]) -> VerifiedBootstrap {
        VerifiedBootstrap::create_closed(scope, vec![key(seed)], creation_id)
            .expect("test bootstrap")
    }

    fn expected(verified: &VerifiedBootstrap) -> ExpectedMeshContext {
        let principal = principal();
        ExpectedMeshContext::for_local_import(&principal, verified.context_id())
    }

    fn principal() -> crate::application_gateway::LocalPrincipalCapability {
        let runtime = crate::runtime::runtime_for_test();
        crate::application_gateway::LocalPrincipalCapability::for_test(runtime)
    }

    fn root_fact(bootstrap: &VerifiedBootstrap, signing_key: &SigningKey) -> SignedFact {
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        root_fact_for_target(bootstrap, signing_key, author)
    }

    fn root_fact_for_target(
        bootstrap: &VerifiedBootstrap,
        signing_key: &SigningKey,
        target: super::super::DeviceId,
    ) -> SignedFact {
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target,
                    role: super::super::Role::Member,
                },
                author,
                Vec::new(),
            ),
            signing_key,
        )
        .expect("test root fact")
    }

    #[test]
    fn round_trip_preserves_exact_pair_and_uses_local_slot_hash() {
        let root = root();
        let first = closed("scope-a", 1, [1; 32]);
        let store = BootstrapStore::new(&root, "local-device-slot");
        let principal = principal();
        let saved = store
            .persist_new(&principal, first.record())
            .expect("persist");
        assert_eq!(saved.record(), first.record());
        let restored = store.restore().expect("restore");
        assert_eq!(restored.record(), first.record());
        assert!(store.path().starts_with(root.join(BOOTSTRAP_DIRECTORY)));
        assert!(!store.path().to_string_lossy().contains("local-device-slot"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn hierarchy_obstruction_propagates_without_installing_a_record() {
        let root = root();
        let first = closed("scope-a", 10, [10; 32]);
        let blocked = root.join("blocked");
        std::fs::write(&blocked, b"not a directory").expect("blocking file");
        let store = BootstrapStore::new(&blocked, "slot");
        let principal = principal();
        assert!(matches!(
            store.persist_new(&principal, first.record()),
            Err(BootstrapStoreError::Io { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn nested_missing_hierarchy_is_created_before_first_install() {
        let root = root();
        let first = closed("scope-a", 11, [11; 32]);
        let instance = root.join("mesh").join("instance");
        let store = BootstrapStore::new(&instance, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("nested hierarchy persist");
        assert!(instance.join(BOOTSTRAP_DIRECTORY).is_dir());
        assert_eq!(store.restore().expect("nested hierarchy restore"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn relative_dot_ancestor_chain_terminates() {
        sync_directory_chain(Path::new(".")).expect("relative dot sync");
    }

    #[test]
    fn identical_persist_and_import_are_idempotent() {
        let root = root();
        let first = closed("scope-a", 2, [2; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("first persist");
        assert_eq!(
            store
                .persist_new(&principal, first.record())
                .expect("same persist")
                .record(),
            first.record()
        );
        assert_eq!(
            store
                .import_expected(&expected(&first), first.record())
                .expect("same import")
                .record(),
            first.record()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn conflicting_record_is_refused_without_replacement() {
        let root = root();
        let first = closed("scope-a", 3, [3; 32]);
        let second = closed("scope-a", 3, [4; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("first persist");
        assert!(matches!(
            store.persist_new(&principal, second.record()),
            Err(BootstrapStoreError::Conflict { .. })
        ));
        assert_eq!(store.restore().expect("original remains"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn missing_corrupt_and_mutated_records_fail_closed() {
        let root = root();
        let first = closed("scope-a", 4, [5; 32]);
        let store = BootstrapStore::new(&root, "slot");
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Missing { .. })
        ));
        std::fs::create_dir_all(store.path().parent().expect("store parent")).expect("parent");
        std::fs::write(store.path(), b"not-json").expect("corrupt bytes");
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Corrupt { .. })
        ));
        std::fs::write(
            store.path(),
            serde_json::to_vec(first.record()).expect("record json"),
        )
        .expect("valid record");
        let other = closed("other-scope", 4, [5; 32]);
        assert!(matches!(
            store.restore_expected(&expected(&other)),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn reopened_store_reads_the_same_established_record() {
        let root = root();
        let first = closed("scope-a", 5, [6; 32]);
        let store = BootstrapStore::new(&root, "slot");
        let principal = principal();
        store
            .persist_new(&principal, first.record())
            .expect("persist");
        let reopened = BootstrapStore::new(&root, "slot");
        assert_eq!(reopened.restore().expect("reopen"), first);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn opposite_order_unmatched_valid_candidates_install_neither() {
        let root = root();
        let first = closed("scope-a", 8, [8; 32]);
        let second = closed("scope-b", 9, [9; 32]);
        let store = BootstrapStore::new(&root, "slot");
        assert!(matches!(
            store.import_expected(&expected(&first), second.record()),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        assert!(matches!(
            store.import_expected(&expected(&second), first.record()),
            Err(BootstrapStoreError::ContextMismatch { .. })
        ));
        assert!(matches!(
            store.restore(),
            Err(BootstrapStoreError::Missing { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn concurrent_conflicting_writers_have_one_winner_and_no_replacement() {
        let root = root();
        let first = closed("scope-a", 6, [6; 32]);
        let second = closed("scope-a", 7, [7; 32]);
        let store = std::sync::Arc::new(BootstrapStore::new(&root, "slot"));
        let first_record = first.record().clone();
        let second_record = second.record().clone();
        let first_expected = expected(&first);
        let second_expected = expected(&second);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let left_store = std::sync::Arc::clone(&store);
        let left_barrier = std::sync::Arc::clone(&barrier);
        let left = std::thread::spawn(move || {
            left_barrier.wait();
            left_store.import_expected(&first_expected, first_record)
        });
        let right_store = std::sync::Arc::clone(&store);
        let right_barrier = std::sync::Arc::clone(&barrier);
        let right = std::thread::spawn(move || {
            right_barrier.wait();
            right_store.import_expected(&second_expected, second_record)
        });
        barrier.wait();
        let left = left.join().expect("left writer");
        let right = right.join().expect("right writer");
        assert_eq!(left.is_ok(), right.is_err());
        assert_eq!(left.is_err(), right.is_ok());
        let restored = store.restore().expect("one established record remains");
        assert!(restored == first || restored == second);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_snapshot_round_trips_projection_and_provisional_custody() {
        let root = root();
        let signing_key = key(12);
        let bootstrap = closed("scope-a", 12, [12; 32]);
        let fact = root_fact(&bootstrap, &signing_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("root fact admits");
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        let missing = FactId::from_bytes([0xabu8; 32]);
        let unresolved = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: super::super::Role::Member,
                },
                author,
                vec![missing],
            ),
            &signing_key,
        )
        .expect("unresolved fact signs");
        graph
            .admit(unresolved.clone())
            .expect("missing-parent fact quarantines");
        let store = DurableSemanticStore::new(&root, "semantic-slot");
        let custody = ProvisionalCustody::new(unresolved.id, SEMANTIC_INGRESS_OWNER);
        store
            .commit(&graph, vec![custody.clone()])
            .expect("atomic semantic commit");
        let restored = store.restore(&bootstrap).expect("semantic reopen");
        assert_eq!(restored.graph().len(), 1);
        assert_eq!(
            restored
                .graph()
                .quarantined()
                .map(|(id, _)| *id)
                .collect::<Vec<_>>(),
            vec![unresolved.id]
        );
        assert_eq!(restored.provisional_custody(), &[custody]);
        let compacted = store.compact(&bootstrap).expect("compact and reopen");
        assert_eq!(compacted.graph().len(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn snapshot_loader_keeps_preflight_and_fetch_on_one_read_snapshot() {
        let root = root();
        let signing_key = key(13);
        let bootstrap = closed("scope-a", 13, [13; 32]);
        let fact = root_fact(&bootstrap, &signing_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact).expect("root fact admits");
        let store = DurableSemanticStore::new(&root, "read-snapshot-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");

        let snapshot_connection = store.open_database(false).expect("snapshot connection");
        let mut writer_connection = store.open_database(true).expect("writer connection");
        let observed = snapshot_connection
            .with_read_snapshot(|connection| {
                let before: String = connection.query_row(
                    "SELECT domain FROM facts ORDER BY seq LIMIT 1",
                    [],
                    |row| row.get(0),
                )?;
                let transaction = writer_connection
                    .transaction()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                transaction.execute(
                    "UPDATE facts SET domain='changed-in-flight' WHERE seq=0",
                    [],
                )?;
                transaction.commit()?;
                let during: String = connection.query_row(
                    "SELECT domain FROM facts ORDER BY seq LIMIT 1",
                    [],
                    |row| row.get(0),
                )?;
                Ok((before, during))
            })
            .expect("read snapshot");
        assert_eq!(observed.0, observed.1);
        let changed: String = writer_connection
            .query_row("SELECT domain FROM facts ORDER BY seq LIMIT 1", [], |row| {
                row.get(0)
            })
            .expect("writer observes commit");
        assert_eq!(changed, "changed-in-flight");
        let transaction = writer_connection
            .transaction()
            .expect("restore transaction");
        transaction
            .execute("UPDATE facts SET domain=? WHERE seq=0", params![observed.0])
            .expect("restore fixture row");
        transaction.commit().expect("restore commit");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn runtime_row_and_link_caps_refuse_before_publication() {
        let unresolved = |bootstrap: &VerifiedBootstrap, signing_key: &SigningKey, marker: u8| {
            let author = super::super::DeviceId::from_public_key_bytes(
                *signing_key.verifying_key().as_bytes(),
            )
            .expect("test author id");
            SignedFact::sign(
                FactContent::new(
                    FactDomain::Governance,
                    bootstrap.context_id(),
                    FactBody::RoleGrant {
                        target: author.clone(),
                        role: super::super::Role::Member,
                    },
                    author,
                    vec![FactId::from_bytes([marker; 32])],
                ),
                signing_key,
            )
            .expect("unresolved fact signs")
        };

        let runtime_root = root();
        let bootstrap = closed("scope-a", 60, [60; 32]);
        let signing_key = key(60);
        let root_fact_record = root_fact(&bootstrap, &signing_key);
        let first = unresolved(&bootstrap, &signing_key, 0x61);
        let second = unresolved(&bootstrap, &signing_key, 0x62);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(root_fact_record).expect("root fact admits");
        graph.admit(first.clone()).expect("first quarantines");
        graph.admit(second.clone()).expect("second quarantines");
        let mut policy = SemanticPolicyConfig::default();
        policy.max_provisional_rows = 1;
        let store = DurableSemanticStore::with_policy(&runtime_root, "provisional-cap", policy);
        assert!(matches!(
            store.commit(
                &graph,
                vec![
                    ProvisionalCustody::new(first.id, SEMANTIC_INGRESS_OWNER),
                    ProvisionalCustody::new(second.id, SEMANTIC_INGRESS_OWNER),
                ],
            ),
            Err(DurableStoreError::LimitExceeded("provisional rows"))
        ));
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Missing { .. })
        ));
        let _ = std::fs::remove_dir_all(runtime_root);

        let author_root = root();
        let first_key = key(63);
        let second_key = key(64);
        let bootstrap = closed("scope-a", 63, [63; 32]);
        let second_author =
            super::super::DeviceId::from_public_key_bytes(*second_key.verifying_key().as_bytes())
                .expect("second author id");
        let grant = root_fact_for_target(&bootstrap, &first_key, second_author.clone());
        let second = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: second_author.clone(),
                    role: super::super::Role::Member,
                },
                second_author,
                vec![FactId::from_bytes([0x64; 32])],
            ),
            &second_key,
        )
        .expect("second-author fact signs");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("grant admits");
        graph
            .admit(second.clone())
            .expect("second-author fact quarantines");
        let mut policy = SemanticPolicyConfig::default();
        policy.max_author_usage_rows = 1;
        let store = DurableSemanticStore::with_policy(&author_root, "author-cap", policy);
        assert!(matches!(
            store.commit(
                &graph,
                vec![ProvisionalCustody::new(second.id, SEMANTIC_INGRESS_OWNER)],
            ),
            Err(DurableStoreError::LimitExceeded("author usage rows"))
        ));
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Missing { .. })
        ));
        let _ = std::fs::remove_dir_all(author_root);

        let root = root();
        let first_key = key(66);
        let bootstrap = closed("scope-a", 66, [66; 32]);
        let first = root_fact(&bootstrap, &first_key);
        let second_author =
            super::super::DeviceId::from_public_key_bytes(*key(67).verifying_key().as_bytes())
                .expect("second author id");
        let grant = root_fact_for_target(&bootstrap, &first_key, second_author.clone());
        let target =
            super::super::DeviceId::from_public_key_bytes(*key(68).verifying_key().as_bytes())
                .expect("second target id");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first.clone()).expect("first fact admits");
        graph.admit(grant.clone()).expect("grant admits");
        let mut policy = SemanticPolicyConfig::default();
        policy.max_proof_links = 1;
        let store = DurableSemanticStore::with_policy(&root, "proof-link-cap", policy);
        store
            .commit(&graph, Vec::new())
            .expect("initial proof graph");
        let owner = store.open_writable().expect("proof owner");
        let proof = ProofRecord::pending(
            bootstrap.context_id(),
            target,
            vec![first.id, grant.id],
            "proof-owner",
            "proof-binding",
        )
        .expect("proof record");
        assert!(matches!(
            owner.enqueue_proof(proof),
            Err(DurableStoreError::LimitExceeded("proof links"))
        ));
        assert!(owner
            .proof_records(bootstrap.context_id())
            .expect("proof rows remain readable")
            .is_empty());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn oversized_persisted_blob_is_rejected_before_materialization() {
        let oversized_root = root();
        let bootstrap = closed("scope-a", 69, [69; 32]);
        let signing_key = key(69);
        let fact = root_fact(&bootstrap, &signing_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact).expect("root fact admits");
        let store = DurableSemanticStore::new(&oversized_root, "oversized-variable-slot");
        store
            .commit(&graph, Vec::new())
            .expect("initial bounded snapshot");

        let connection = Connection::open(store.path()).expect("open persisted snapshot");
        connection
            .execute("UPDATE facts SET encoded=?", params![vec![0u8; 65_536]])
            .expect("tamper variable encoded column");
        drop(connection);
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::LimitExceeded("fact encoded bytes"))
        ));
        let _ = std::fs::remove_dir_all(oversized_root);

        let root = root();
        let bootstrap = closed("scope-a", 70, [70; 32]);
        let signing_key = key(70);
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test author id");
        let unresolved = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: super::super::Role::Member,
                },
                author,
                vec![FactId::from_bytes([0x70; 32])],
            ),
            &signing_key,
        )
        .expect("unresolved fact signs");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(unresolved.clone())
            .expect("unresolved fact quarantines");
        let store = DurableSemanticStore::new(&root, "oversized-owner-slot");
        store
            .commit(
                &graph,
                vec![ProvisionalCustody::new(
                    unresolved.id,
                    SEMANTIC_INGRESS_OWNER,
                )],
            )
            .expect("initial custody snapshot");
        let connection = Connection::open(store.path()).expect("open custody snapshot");
        connection
            .execute("UPDATE provisional SET owner=?", params!["wrong-owner"])
            .expect("tamper owner identity");
        drop(connection);
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Corrupt { reason, .. })
                if reason == "provisional owner mismatch"
        ));
        let connection = Connection::open(store.path()).expect("reopen custody snapshot");
        connection
            .execute(
                "UPDATE provisional SET owner=?",
                params!["x".repeat(65_536)],
            )
            .expect("tamper variable owner column");
        drop(connection);
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::LimitExceeded("provisional owner bytes"))
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn create_then_immediate_typed_reopen_uses_canonical_vfs_slot() {
        let root = root();
        let store = DurableSemanticStore::new(&root, "canonical-reopen-slot");
        let first = store.open_database(true).expect("create canonical slot");
        drop(first);
        let second = store
            .open_database(false)
            .expect("immediate canonical typed reopen");
        drop(second);
        assert!(store.path().exists());
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_connection_installs_wal_durability_and_limits() {
        let root = root();
        let bootstrap = closed("scope-a", 29, [29; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "exact-wal-ceiling-slot");
        let envelope = store
            .policy
            .checked_storage_envelope(
                crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES,
                store.policy.storage_workload(),
            )
            .expect("checked WAL envelope");
        store.commit(&graph, Vec::new()).expect("initial snapshot");

        let mut connection = store
            .open_database(false)
            .expect("reopen configured SQLite slot");
        let mode: String = connection
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .expect("journal mode");
        assert_eq!(mode.to_ascii_lowercase(), "wal");
        assert_eq!(
            connection.pragma_u64("max_page_count").unwrap(),
            envelope.main_pages
        );
        assert_eq!(
            connection.pragma_u64("journal_size_limit").unwrap(),
            envelope.wal_hard_bytes
        );
        assert_eq!(
            connection.pragma_u64("wal_autocheckpoint").unwrap(),
            envelope.wal_checkpoint_frames
        );
        assert_eq!(
            connection
                .query_row("PRAGMA synchronous", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            2
        );
        assert_eq!(
            connection
                .query_row("PRAGMA foreign_keys", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            1
        );
        assert_eq!(
            connection
                .query_row("PRAGMA trusted_schema", [], |row| row.get::<_, i64>(0))
                .unwrap(),
            0
        );
        let transaction = connection
            .transaction()
            .expect("ordinary immediate transaction");
        transaction
            .commit()
            .expect("ordinary immediate transaction commits");
        drop(connection);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn wal_checkpoint_and_hard_frame_arithmetic_is_exact() {
        let policy = SemanticPolicyConfig::default();
        let envelope = policy
            .checked_storage_envelope(
                crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES,
                policy.storage_workload(),
            )
            .expect("default WAL envelope");
        let frame_bytes = crate::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES
            .checked_add(SQLITE_WAL_FRAME_OVERHEAD_BYTES)
            .expect("frame arithmetic");
        assert_eq!(
            envelope.wal_checkpoint_frames,
            policy.max_uncheckpointed_wal_frames
        );
        assert_eq!(
            envelope.wal_checkpoint_bytes,
            SQLITE_WAL_HEADER_BYTES + envelope.wal_checkpoint_frames * frame_bytes
        );
        assert_eq!(
            envelope.wal_hard_frames,
            envelope.wal_checkpoint_frames + policy.max_transaction_dirty_main_pages
        );
        assert_eq!(
            envelope.wal_hard_bytes,
            SQLITE_WAL_HEADER_BYTES + envelope.wal_hard_frames * frame_bytes
        );
    }

    #[test]
    fn semantic_delta_fences_stale_base_and_malformed_sets_without_writing() {
        let root = root();
        let bootstrap = closed("scope-a", 30, [30; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "delta-fence-slot");
        let owner = store.open_writable().expect("open semantic owner");
        owner
            .commit(&graph, Vec::new())
            .expect("initial semantic snapshot");
        let base = projection_commitment_for_graph(&graph);
        let before_noop = store
            .read_semantic_usage_raw(&Connection::open(store.path()).expect("open noop database"))
            .expect("read noop usage");
        owner
            .commit_semantic_delta(
                bootstrap.context_id(),
                &SemanticDelta::default(),
                base,
                base,
                &[],
            )
            .expect("identical semantic delta is a no-op");
        let after_noop = store
            .read_semantic_usage_raw(&Connection::open(store.path()).expect("reopen noop database"))
            .expect("read unchanged noop usage");
        assert_eq!(before_noop, after_noop);
        let mut empty = SemanticDelta::default();
        assert!(matches!(
            owner.commit_semantic_delta(bootstrap.context_id(), &empty, [0xff; 32], base, &[]),
            Err(DurableStoreError::DeltaConflict)
        ));

        let id = FactId::from_bytes([0x31; 32]);
        empty.push_promoted_for_test(id);
        assert!(matches!(
            owner.commit_semantic_delta(bootstrap.context_id(), &empty, base, base, &[]),
            Err(DurableStoreError::DeltaConflict)
        ));

        let mut custody_delta = SemanticDelta::default();
        custody_delta.push_provisional_added_for_test(id);
        assert!(matches!(
            owner.commit_semantic_delta(
                bootstrap.context_id(),
                &custody_delta,
                base,
                base,
                &[ProvisionalCustody::new(id, SEMANTIC_INGRESS_OWNER)]
            ),
            Err(DurableStoreError::InvalidCustody)
        ));
        assert_eq!(
            owner
                .restore(&bootstrap)
                .expect("unchanged reopen")
                .graph()
                .len(),
            0
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_delta_accounts_promotion_against_admitted_limit() {
        let root = root();
        let signing_key = key(31);
        let bootstrap = closed("scope-a", 31, [31; 32]);
        let root_fact = root_fact(&bootstrap, &signing_key);
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        let missing = FactId::from_bytes([0x32; 32]);
        let unresolved = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: author.clone(),
                    role: super::super::Role::Member,
                },
                author,
                vec![missing],
            ),
            &signing_key,
        )
        .expect("unresolved fact signs");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(root_fact).expect("root fact admits");
        graph
            .admit(unresolved.clone())
            .expect("missing-parent fact quarantines");
        let mut policy = SemanticPolicyConfig::default();
        policy.max_admitted_facts = 1;
        policy.max_retained_facts_per_author = policy
            .max_admitted_facts
            .checked_add(policy.max_quarantined_facts)
            .expect("fixture retained-fact limit");
        let store = DurableSemanticStore::with_policy(&root, "promotion-limit-slot", policy);
        let owner = store.open_writable().expect("open semantic owner");
        let custody = ProvisionalCustody::new(unresolved.id, SEMANTIC_INGRESS_OWNER);
        owner
            .commit(&graph, vec![custody.clone()])
            .expect("initial semantic snapshot");
        let base = projection_commitment_for_graph(&graph);
        let mut delta = SemanticDelta::default();
        delta.push_row_for_test(SemanticFactRow::for_test(
            unresolved.clone(),
            SemanticFactStatus::Admitted,
        ));
        delta.push_promoted_for_test(unresolved.id);
        delta.push_provisional_removed_for_test(unresolved.id);
        assert!(matches!(
            owner.commit_semantic_delta(bootstrap.context_id(), &delta, base, [0x33; 32], &[]),
            Err(DurableStoreError::LimitExceeded("semantic delta quotas"))
        ));
        let restored = owner.restore(&bootstrap).expect("refusal keeps old state");
        assert_eq!(restored.graph().len(), 1);
        assert!(restored
            .graph()
            .quarantined()
            .any(|(id, _)| *id == unresolved.id));
        assert_eq!(restored.provisional_custody(), &[custody]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_delta_non_tail_removal_reopens_with_sparse_sequence() {
        let root = root();
        let signing_key = key(33);
        let bootstrap = closed("scope-a", 33, [33; 32]);
        let root_fact = root_fact(&bootstrap, &signing_key);
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        let unresolved = |marker: u8| {
            SignedFact::sign(
                FactContent::new(
                    FactDomain::Governance,
                    bootstrap.context_id(),
                    FactBody::RoleGrant {
                        target: author.clone(),
                        role: super::super::Role::Member,
                    },
                    author.clone(),
                    vec![FactId::from_bytes([marker; 32])],
                ),
                &signing_key,
            )
            .expect("unresolved fact signs")
        };
        let quarantined = unresolved(0x41);
        let retained = unresolved(0x42);
        let replacement = unresolved(0x43);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(root_fact).expect("root fact admits");
        graph
            .admit(quarantined.clone())
            .expect("first fact quarantines");
        graph
            .admit(retained.clone())
            .expect("second fact quarantines");

        let store = DurableSemanticStore::new(&root, "sparse-sequence-slot");
        let owner = store.open_writable().expect("open semantic owner");
        let quarantined_custody = ProvisionalCustody::new(quarantined.id, SEMANTIC_INGRESS_OWNER);
        let retained_custody = ProvisionalCustody::new(retained.id, SEMANTIC_INGRESS_OWNER);
        owner
            .commit(
                &graph,
                vec![quarantined_custody.clone(), retained_custody.clone()],
            )
            .expect("initial semantic snapshot");

        let base = projection_commitment_for_graph(&graph);
        let replacement_custody = ProvisionalCustody::new(replacement.id, SEMANTIC_INGRESS_OWNER);
        let mut delta = SemanticDelta::default();
        delta.push_row_for_test(SemanticFactRow::for_test(
            replacement.clone(),
            SemanticFactStatus::Quarantined,
        ));
        delta.push_removed_for_test(quarantined.id);
        delta.push_provisional_added_for_test(replacement.id);
        delta.push_provisional_removed_for_test(quarantined.id);
        owner
            .commit_semantic_delta(
                bootstrap.context_id(),
                &delta,
                base,
                base,
                std::slice::from_ref(&replacement_custody),
            )
            .expect("non-tail removal commits");

        let restored = owner.restore(&bootstrap).expect("sparse sequence reopen");
        assert_eq!(restored.graph().len(), 1);
        let quarantined_ids = restored
            .graph()
            .quarantined()
            .map(|(id, _)| *id)
            .collect::<Vec<_>>();
        assert!(quarantined_ids.contains(&retained.id));
        assert!(quarantined_ids.contains(&replacement.id));
        assert!(!quarantined_ids.contains(&quarantined.id));
        assert!(restored.provisional_custody().contains(&retained_custody));
        assert!(restored
            .provisional_custody()
            .contains(&replacement_custody));
        assert!(!restored
            .provisional_custody()
            .contains(&quarantined_custody));

        let connection = Connection::open(store.path()).expect("open semantic database");
        let usage = store
            .read_semantic_usage_raw(&connection)
            .expect("read usage counters");
        assert_eq!(usage.admitted_count, 1);
        assert_eq!(usage.quarantined_count, 2);
        let author_usage = store
            .read_author_usage_raw(&connection, author.as_bytes())
            .expect("read author counters")
            .expect("author counters exist");
        assert_eq!(author_usage.retained_count, 3);
        assert_eq!(author_usage.quarantined_count, 2);
        let sequences = connection
            .prepare("SELECT seq FROM facts ORDER BY seq")
            .expect("prepare sequence query")
            .query_map([], |row| row.get::<_, i64>(0))
            .expect("query sequences")
            .collect::<Result<Vec<_>, _>>()
            .expect("read sequences");
        assert_eq!(sequences, vec![0, 2, 3]);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn semantic_delta_append_uses_sequence_index() {
        let root = root();
        let bootstrap = closed("scope-a", 34, [34; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "sequence-index-slot");
        store
            .commit(&graph, Vec::new())
            .expect("initial semantic snapshot");
        let connection = Connection::open(store.path()).expect("open semantic database");
        let indexes = connection
            .prepare("PRAGMA index_list(facts)")
            .expect("prepare index query")
            .query_map([], |row| row.get::<_, String>(1))
            .expect("query indexes")
            .collect::<Result<Vec<_>, _>>()
            .expect("read indexes");
        assert!(indexes.iter().any(|name| name == "facts_seq_idx"));
        let details = connection
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT seq FROM facts ORDER BY seq DESC LIMIT 1",
            )
            .expect("prepare query plan")
            .query_map([], |row| row.get::<_, String>(3))
            .expect("query plan")
            .collect::<Result<Vec<_>, _>>()
            .expect("read query plan");
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("facts_seq_idx")),
            "sequence append must use its dedicated index: {details:?}"
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn corrupt_usage_scalar_is_rejected_before_graph_exposure() {
        let root = root();
        let bootstrap = closed("scope-a", 32, [32; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "usage-corruption-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let mut connection = store
            .open_database(false)
            .expect("open typed semantic database for corruption fixture");
        {
            let transaction = connection
                .transaction()
                .expect("begin typed corruption transaction");
            assert_eq!(
                transaction
                    .execute(
                        "UPDATE semantic_usage SET admitted_count=?",
                        params![7u64.to_be_bytes().to_vec()],
                    )
                    .expect("tamper usage scalar"),
                1
            );
            transaction
                .commit()
                .expect("commit typed scalar corruption");
        }
        drop(connection);
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Corrupt { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn delta_planner_has_no_whole_ledger_aggregate_queries() {
        let source = include_str!("store.rs");
        let planner = source
            .split_once("fn plan_semantic_delta")
            .and_then(|(_, rest)| rest.split_once("fn apply_semantic_delta"))
            .map(|(planner, _)| planner)
            .expect("planner source slice");
        assert!(!planner.contains("COUNT(*) FROM facts"));
        assert!(!planner.contains("SUM(length(encoded))"));
        assert_eq!(
            planner.matches("COUNT(*) FROM dependencies").count(),
            planner
                .matches("COUNT(*) FROM dependencies WHERE fact_id")
                .count()
        );
        assert!(planner.contains("self.read_semantic_usage(connection)"));
        assert!(planner.contains(".read_author_usage(connection, author)?"));
    }

    #[test]
    fn writer_lease_excludes_a_competing_process_and_releases_on_drop() {
        let root = root();
        let store = DurableSemanticStore::new(&root, "lease-slot");
        let lease = store.begin_write().expect("first writer lease");
        assert!(matches!(
            store.begin_write(),
            Err(DurableStoreError::WriterBusy { .. })
        ));
        drop(lease);
        store.begin_write().expect("lease released");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn purge_fences_live_owner_then_removes_only_canonical_snapshot() {
        let root = root();
        let store = DurableSemanticStore::new(&root, "purge-slot");
        let owner = store.open_writable().expect("live owner");
        std::fs::write(store.path(), b"canonical snapshot").expect("test canonical snapshot");
        assert!(matches!(
            store.purge(),
            Err(DurableStoreError::WriterBusy { .. })
        ));
        assert!(store.path().exists(), "live owner must fence purge");
        owner.release().expect("release live owner");
        store.purge().expect("purge released slot");
        assert!(!store.path().exists(), "canonical snapshot was purged");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn released_owner_refuses_stale_mutation_and_allows_same_slot_reopen() {
        let root = root();
        let bootstrap = closed("scope-a", 20, [20; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "release-slot");
        let owner = store.open_writable().expect("first owner");
        owner.commit(&graph, Vec::new()).expect("initial snapshot");
        owner.release().expect("release owner");
        assert!(matches!(
            owner.restore(&bootstrap),
            Err(DurableStoreError::OwnerReleased)
        ));
        assert!(matches!(
            owner.commit(&graph, Vec::new()),
            Err(DurableStoreError::OwnerReleased)
        ));
        assert!(matches!(
            owner.compact(),
            Err(DurableStoreError::OwnerReleased)
        ));
        assert!(matches!(
            owner.mutate_proof_records(bootstrap.context_id(), |_| Ok(())),
            Err(DurableStoreError::OwnerReleased)
        ));
        drop(owner);

        let reopened = store.open_writable().expect("same slot reopens");
        reopened.restore(&bootstrap).expect("reopen snapshot");
        drop(reopened);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn clean_live_checkpoint_restores_without_history_replay() {
        let root = root();
        let bootstrap = closed("checkpoint-restart", 21, [21; 32]);
        let signing_key = key(21);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let first_target =
            super::super::DeviceId::from_public_key_bytes(*key(22).verifying_key().as_bytes())
                .expect("first test target id");
        let journal = graph
            .admit_journaled(root_fact_for_target(&bootstrap, &signing_key, first_target))
            .expect("admit checkpoint fact");
        assert!(matches!(
            journal.admission(),
            super::super::Admission::Inserted
        ));
        journal.commit();
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("test root id");
        let body = FactBody::RoleGrant {
            target: super::super::DeviceId::from_public_key_bytes(
                *key(23).verifying_key().as_bytes(),
            )
            .expect("test target id"),
            role: super::super::Role::Member,
        };
        let witness = graph.authoring_witness(&body, &author);
        let dependent = SignedFact::sign(
            FactContent::from_authoring_witness(&graph, body, &witness, std::iter::empty()),
            &signing_key,
        )
        .expect("dependent checkpoint fact signs");
        graph
            .admit(dependent)
            .expect("dependent checkpoint fact admits");

        let store = DurableSemanticStore::new(&root, "checkpoint-restart-slot");
        let owner = store.open_writable().expect("checkpoint owner");
        owner
            .commit(&graph, Vec::new())
            .expect("canonical snapshot");
        graph.seal_live_checkpoint();
        owner
            .persist_live_checkpoint(&graph, &[])
            .expect("persist bounded live checkpoint");
        owner.release().expect("release checkpoint owner");
        drop(owner);

        ORDERED_RESTORE_ROWS.store(0, Ordering::Relaxed);
        let reopened = store.open_writable().expect("reopen checkpoint owner");
        let restored = reopened.restore(&bootstrap).expect("restore checkpoint");
        assert_eq!(restored.graph().len(), 2);
        assert_eq!(
            ORDERED_RESTORE_ROWS.load(Ordering::Relaxed),
            0,
            "a current clean checkpoint must not enumerate historical rows"
        );
        reopened.release().expect("release reopened owner");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn interrupted_temporary_write_does_not_hide_the_last_complete_snapshot() {
        let root = root();
        let bootstrap = closed("scope-a", 13, [13; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "restart-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");

        let stale_temp = store.path().with_extension("sqlite3.tmp");
        std::fs::write(&stale_temp, b"interrupted replacement").expect("interrupted temp");
        assert_eq!(
            store
                .restore(&bootstrap)
                .expect("reopen old snapshot")
                .graph()
                .len(),
            0
        );
        store
            .commit(&graph, Vec::new())
            .expect("next commit replaces interrupted temp");
        assert!(stale_temp.exists(), "unrelated stale temp is not consulted");
        let _ = std::fs::remove_file(stale_temp);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn tampered_projection_commitment_is_rejected() {
        let root = root();
        let bootstrap = closed("scope-a", 14, [14; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "commitment-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let connection = Connection::open(store.path()).expect("sqlite database");
        connection
            .execute(
                "UPDATE commitments SET value=? WHERE name='projection'",
                params![vec![0u8; 32]],
            )
            .expect("tampered commitment");
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::ProjectionMismatch { .. })
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn older_semantic_database_is_hard_refused() {
        let root = root();
        let bootstrap = closed("scope-a", 140, [140; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "v1-refusal-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let connection = Connection::open(store.path()).expect("sqlite database");
        connection
            .execute(
                "UPDATE meta SET value=? WHERE key='database_version'",
                params![2u64.to_be_bytes().to_vec()],
            )
            .expect("tamper database version");
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Corrupt { reason, .. })
                if reason == "unsupported database version"
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn canonical_dependency_index_omission_and_extra_are_rejected() {
        let make_graph = |bootstrap: &VerifiedBootstrap, signing_key: &SigningKey| {
            let target =
                super::super::DeviceId::from_public_key_bytes(*key(141).verifying_key().as_bytes())
                    .expect("test target id");
            let parent = root_fact_for_target(bootstrap, signing_key, target.clone());
            let author = super::super::DeviceId::from_public_key_bytes(
                *signing_key.verifying_key().as_bytes(),
            )
            .expect("test root id");
            let mut graph = FactGraph::from_bootstrap(bootstrap);
            let parent_id = parent.id;
            graph.admit(parent).expect("parent admits");
            let body = FactBody::RoleRevoke { target };
            let witness = graph.authoring_witness(&body, &author);
            let child = SignedFact::sign(
                FactContent::from_authoring_witness(&graph, body, &witness, std::iter::empty()),
                signing_key,
            )
            .expect("dependent fact signs");
            let child_id = child.id;
            graph.admit(child).expect("child admits");
            assert!(
                graph
                    .canonical_dependency_edges(&child_id)
                    .expect("child dependency edges")
                    .contains(&parent_id),
                "the revoke must retain its exact grant predecessor"
            );
            (graph, child_id)
        };

        let omission_root = root();
        let bootstrap = closed("scope-a", 142, [142; 32]);
        let signing_key = key(142);
        let (graph, child_id) = make_graph(&bootstrap, &signing_key);
        let store = DurableSemanticStore::new(&omission_root, "dependency-omission-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let connection = Connection::open(store.path()).expect("sqlite database");
        connection
            .execute(
                "DELETE FROM dependencies WHERE fact_id=?",
                params![child_id.as_bytes().to_vec()],
            )
            .expect("omit canonical dependency");
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::Corrupt { reason, .. })
                if reason == "dependency index does not match signed bytes"
        ));
        drop(connection);

        let extra_root = root();
        let extra_bootstrap = closed("scope-a", 143, [143; 32]);
        let extra_signing_key = key(143);
        let (extra_graph, extra_child_id) = make_graph(&extra_bootstrap, &extra_signing_key);
        let extra_store = DurableSemanticStore::new(&extra_root, "dependency-extra-slot");
        extra_store
            .commit(&extra_graph, Vec::new())
            .expect("extra initial snapshot");
        let extra_connection = Connection::open(extra_store.path()).expect("sqlite database");
        extra_connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .expect("disable foreign keys for corruption fixture");
        extra_connection
            .execute(
                "INSERT INTO dependencies(fact_id,dep_id) VALUES(?,?)",
                params![
                    extra_child_id.as_bytes().to_vec(),
                    FactId::from_bytes([0xee; 32]).as_bytes().to_vec()
                ],
            )
            .expect("add extra dependency");
        assert!(matches!(
            extra_store.restore(&extra_bootstrap),
            Err(DurableStoreError::Corrupt { reason, .. })
                if reason == "dependency index does not match signed bytes"
        ));
        let _ = std::fs::remove_dir_all(omission_root);
        let _ = std::fs::remove_dir_all(extra_root);
    }

    #[test]
    fn provisional_custody_must_name_a_fact_in_the_rebuilt_graph() {
        let root = root();
        let bootstrap = closed("scope-a", 15, [15; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::new(&root, "custody-fact-slot");
        store.commit(&graph, Vec::new()).expect("initial snapshot");
        let connection = Connection::open(store.path()).expect("sqlite database");
        connection
            .execute_batch("PRAGMA foreign_keys=OFF;")
            .expect("disable foreign keys for corruption fixture");
        connection
            .execute(
                "INSERT INTO provisional(fact_id,owner) VALUES(?,?)",
                params![
                    FactId::from_bytes([0xabu8; 32]).as_bytes().to_vec(),
                    SEMANTIC_INGRESS_OWNER
                ],
            )
            .expect("orphan custody fixture");
        connection
            .execute(
                "UPDATE semantic_usage SET provisional_count=? WHERE usage_id=1",
                params![1u64.to_be_bytes().to_vec()],
            )
            .expect("keep aggregate counter coherent");
        drop(connection);
        assert!(matches!(
            store.restore(&bootstrap),
            Err(DurableStoreError::UnknownCustodyFact)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn sqlite_schema_and_policy_are_bounded_and_indexed() {
        let root = root();
        let bootstrap = closed("schema", 21, [21; 32]);
        let graph = FactGraph::from_bootstrap(&bootstrap);
        let store = DurableSemanticStore::with_policy(
            &root,
            "schema-slot",
            SemanticPolicyConfig::default(),
        );
        store.commit(&graph, Vec::new()).expect("bounded commit");
        let connection = Connection::open(store.path()).expect("sqlite database");
        let journal: String = connection
            .pragma_query_value(None, "journal_mode", |row| row.get(0))
            .expect("WAL mode");
        assert_eq!(journal.to_ascii_lowercase(), "wal");
        let indexed: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name='dependencies_dep_idx'",
                [],
                |row| row.get(0),
            )
            .expect("dependency index");
        assert_eq!(indexed, 1);
        for descriptor in crate::config::SEMANTIC_SCHEMA_TABLES {
            let present: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
                    [descriptor.name],
                    |row| row.get(0),
                )
                .expect("schema descriptor lookup");
            assert_eq!(present, 1, "missing canonical table {}", descriptor.name);
            for &column in descriptor.columns {
                let quoted = format!("PRAGMA table_info({})", descriptor.name);
                let found: i64 = connection
                    .prepare(&quoted)
                    .expect("table-info statement")
                    .query_map([], |row| row.get::<_, String>(1))
                    .expect("table-info rows")
                    .filter_map(Result::ok)
                    .filter(|name| name == column)
                    .count() as i64;
                assert_eq!(
                    found, 1,
                    "missing canonical column {}.{}",
                    descriptor.name, column
                );
            }
        }
        for &(index, table, columns) in crate::config::SEMANTIC_SCHEMA_INDEXES {
            let present: i64 = connection
                .query_row(
                    "SELECT COUNT(*) FROM sqlite_master WHERE type='index' AND name=?",
                    [index],
                    |row| row.get(0),
                )
                .expect("index descriptor lookup");
            assert_eq!(present, 1, "missing canonical index {index}");
            assert!(!table.is_empty() && !columns.is_empty());
        }
        assert!(matches!(
            DurableSemanticStore::with_policy(
                &root,
                "invalid-slot",
                SemanticPolicyConfig {
                    max_database_bytes: 1,
                    ..SemanticPolicyConfig::default()
                }
            )
            .commit(&graph, Vec::new()),
            Err(DurableStoreError::InvalidPolicy)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn child_process_contention_and_hard_death_release_the_writer() {
        let root = root();
        let ready = root.join("child-ready");
        let store = DurableSemanticStore::new(&root, "child-slot");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("child_writer_holds_lease")
            .env("MYOWNMESH_STORE_CHILD_ROOT", &root)
            .env("MYOWNMESH_STORE_CHILD_READY", &ready)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn child writer");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        let child_ready = ready.exists();
        let contended = matches!(
            store.begin_write(),
            Err(DurableStoreError::WriterBusy { .. })
        );
        child.kill().expect("hard-stop child writer");
        child.wait().expect("reap child writer");
        assert!(child_ready, "child must publish that its lease is held");
        assert!(contended, "live child writer must exclude this process");
        store
            .begin_write()
            .expect("hard-dead child must not strand the writer lease");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifetime_owner_blocks_second_open_then_reopens_for_append() {
        let root = root();
        let signing_key = key(16);
        let bootstrap = closed("scope-a", 16, [16; 32]);
        let target_key = key(17);
        let target =
            super::super::DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes())
                .expect("target id");
        let first = root_fact_for_target(&bootstrap, &signing_key, target.clone());
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first.clone()).expect("first fact");
        let store = DurableSemanticStore::new(&root, "lifetime-slot");
        store
            .commit(&graph, Vec::new())
            .expect("initial publication");

        let ready = root.join("lifetime-child-ready");
        let mut child = Command::new(std::env::current_exe().expect("test executable"))
            .arg("child_holds_lifetime_owner")
            .env("MYOWNMESH_STORE_CHILD_ROOT", &root)
            .env("MYOWNMESH_STORE_CHILD_READY", &ready)
            .env("MYOWNMESH_STORE_CHILD_SLOT", "lifetime-slot")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live owner");
        let deadline = Instant::now() + Duration::from_secs(5);
        while !ready.exists() && Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.exists(), "child must publish its live owner");
        assert!(matches!(
            store.open_writable(),
            Err(DurableStoreError::WriterBusy { .. })
        ));
        child.kill().expect("hard-stop live owner");
        child.wait().expect("reap live owner");

        let owner = store.open_writable().expect("reopen after owner death");
        let second = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleRevoke { target },
                super::super::DeviceId::from_public_key_bytes(
                    *signing_key.verifying_key().as_bytes(),
                )
                .expect("root id"),
                vec![first.id],
            ),
            &signing_key,
        )
        .expect("second fact");
        graph.admit(second).expect("append second fact");
        owner
            .commit(&graph, Vec::new())
            .expect("append publication");
        assert_eq!(
            store
                .restore(&bootstrap)
                .expect("final reopen")
                .graph()
                .len(),
            2
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn lifetime_owner_preserves_deterministic_graph_and_proof_union() {
        let root = root();
        let signing_key = key(18);
        let bootstrap = closed("scope-a", 18, [18; 32]);
        let target_key = key(19);
        let target =
            super::super::DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes())
                .expect("target id");
        let first = root_fact_for_target(&bootstrap, &signing_key, target.clone());
        let mut graph_a = FactGraph::from_bootstrap(&bootstrap);
        graph_a.admit(first.clone()).expect("first fact");

        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("root id");
        let second = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleRevoke {
                    target: target.clone(),
                },
                author,
                vec![first.id],
            ),
            &signing_key,
        )
        .expect("second fact");
        let mut graph_b = graph_a.clone();
        graph_b.admit(second).expect("second fact");

        let store = DurableSemanticStore::new(&root, "union-slot");
        let owner = store.open_writable().expect("owner");
        owner
            .commit(&graph_a, Vec::new())
            .expect("graph A publication");
        let proof = ProofRecord::pending(
            bootstrap.context_id(),
            target,
            vec![first.id],
            "proof-owner",
            "proof-binding",
        )
        .expect("proof record");
        let owner = std::sync::Arc::new(owner);
        let context_id = bootstrap.context_id();
        let (proof_entered_tx, proof_entered_rx) = mpsc::channel();
        let (proof_release_tx, proof_release_rx) = mpsc::channel();
        let proof_owner = std::sync::Arc::clone(&owner);
        let proof_for_thread = proof.clone();
        let proof_thread = std::thread::spawn(move || {
            proof_owner
                .mutate_proof_records(context_id, move |records| {
                    proof_entered_tx.send(()).expect("proof parked");
                    proof_release_rx.recv().expect("release proof transaction");
                    records.push(proof_for_thread);
                    Ok(())
                })
                .expect("proof publication");
        });
        proof_entered_rx.recv().expect("proof transaction entered");

        let (graph_started_tx, graph_started_rx) = mpsc::channel();
        let (graph_done_tx, graph_done_rx) = mpsc::channel();
        let graph_owner = std::sync::Arc::clone(&owner);
        let graph_thread = std::thread::spawn(move || {
            graph_started_tx.send(()).expect("graph commit started");
            graph_owner
                .commit(&graph_b, Vec::new())
                .expect("graph B preserves proof");
            graph_done_tx.send(()).expect("graph commit completed");
        });
        graph_started_rx.recv().expect("graph commit entered");
        assert!(matches!(
            graph_done_rx.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Timeout)
        ));
        proof_release_tx
            .send(())
            .expect("release proof transaction");
        proof_thread.join().expect("proof transaction thread");
        graph_thread.join().expect("graph commit thread");
        graph_done_rx.recv().expect("graph commit completion");

        let restored = owner.restore(&bootstrap).expect("union restore");
        assert_eq!(restored.graph().len(), 2);
        assert_eq!(
            owner.proof_records(bootstrap.context_id()).unwrap(),
            vec![proof]
        );
        owner.compact().expect("union compact");
        let compacted = owner.restore(&bootstrap).expect("post-compact restore");
        assert_eq!(compacted.graph().len(), 2);
        assert_eq!(
            owner.proof_records(bootstrap.context_id()).unwrap().len(),
            1
        );
        drop(owner);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn pending_proof_read_is_bounded_and_refuses_selected_corruption() {
        let root = root();
        let signing_key = key(20);
        let bootstrap = closed("pending-index", 20, [20; 32]);
        let target_key = key(21);
        let target =
            super::super::DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes())
                .expect("target id");
        let author =
            super::super::DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("author id");
        let first = root_fact_for_target(&bootstrap, &signing_key, target.clone());
        let second = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleRevoke {
                    target: target.clone(),
                },
                author.clone(),
                vec![first.id],
            ),
            &signing_key,
        )
        .expect("second fact");
        let third = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: target.clone(),
                    role: super::super::Role::Member,
                },
                author,
                vec![second.id],
            ),
            &signing_key,
        )
        .expect("third fact");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first.clone()).expect("first fact");
        graph.admit(second.clone()).expect("second fact");
        graph.admit(third.clone()).expect("third fact");
        let store = DurableSemanticStore::new(&root, "pending-index-slot");
        store.commit(&graph, Vec::new()).expect("initial graph");
        let explain = store.open_database(false).expect("query-plan connection");
        let mut plan = explain
            .inner
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT delivery_id FROM proofs
                 WHERE context_id=? AND state=?
                 ORDER BY delivery_id",
            )
            .expect("pending query plan");
        let pending_state =
            serde_json::to_string(&ProofRecordState::Pending).expect("pending state token");
        let details = plan
            .query_map(
                params![bootstrap.context_id().as_bytes().to_vec(), pending_state],
                |row| row.get::<_, String>(3),
            )
            .expect("pending query plan rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("pending query plan details");
        assert!(
            details
                .iter()
                .any(|detail| detail.contains("proofs_pending_idx")),
            "pending listing uses the bounded context/state/order index: {details:?}"
        );
        drop(plan);
        let mut lower_plan = explain
            .inner
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT context_id FROM proofs
                 WHERE context_id < ? ORDER BY context_id LIMIT 1",
            )
            .expect("lower foreign-context plan");
        let lower_details = lower_plan
            .query_map(params![bootstrap.context_id().as_bytes().to_vec()], |row| {
                row.get::<_, String>(3)
            })
            .expect("lower foreign-context plan rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("lower foreign-context plan details");
        assert!(
            lower_details
                .iter()
                .any(|detail| detail.contains("proofs_pending_idx")),
            "lower foreign-context probe uses the bounded context index: {lower_details:?}"
        );
        drop(lower_plan);
        let mut upper_plan = explain
            .inner
            .prepare(
                "EXPLAIN QUERY PLAN
                 SELECT context_id FROM proofs
                 WHERE context_id > ? ORDER BY context_id LIMIT 1",
            )
            .expect("upper foreign-context plan");
        let upper_details = upper_plan
            .query_map(params![bootstrap.context_id().as_bytes().to_vec()], |row| {
                row.get::<_, String>(3)
            })
            .expect("upper foreign-context plan rows")
            .collect::<Result<Vec<_>, _>>()
            .expect("upper foreign-context plan details");
        assert!(
            upper_details
                .iter()
                .any(|detail| detail.contains("proofs_pending_idx")),
            "upper foreign-context probe uses the bounded context index: {upper_details:?}"
        );
        drop(upper_plan);
        drop(explain);
        let owner = store.open_writable().expect("proof owner");
        let context_id = bootstrap.context_id();
        let pending = ProofRecord::pending(
            context_id,
            target.clone(),
            vec![first.id],
            "pending-owner",
            "pending-binding",
        )
        .expect("pending record");
        owner
            .enqueue_proof(pending.clone())
            .expect("pending enqueue");

        let terminal_one = ProofRecord::pending(
            context_id,
            target.clone(),
            vec![second.id],
            "terminal-owner-1",
            "terminal-binding-1",
        )
        .expect("first terminal record");
        owner
            .enqueue_proof(terminal_one.clone())
            .expect("first terminal enqueue");
        assert!(owner
            .supersede_proof(context_id, terminal_one.delivery_id, &target, None)
            .expect("first terminal supersession"));
        let pending_after_one = owner
            .pending_proof_records(context_id)
            .expect("pending after first terminal");
        assert_eq!(pending_after_one, vec![pending.clone()]);

        let terminal_two = ProofRecord::pending(
            context_id,
            target.clone(),
            vec![third.id],
            "terminal-owner-2",
            "terminal-binding-2",
        )
        .expect("second terminal record");
        owner
            .enqueue_proof(terminal_two.clone())
            .expect("second terminal enqueue");
        assert!(owner
            .supersede_proof(context_id, terminal_two.delivery_id, &target, None)
            .expect("second terminal supersession"));
        let pending_after_two = owner
            .pending_proof_records(context_id)
            .expect("pending after second terminal");
        assert_eq!(pending_after_two, vec![pending.clone()]);
        let mut expected_terminal_one = terminal_one.clone();
        expected_terminal_one.state = ProofRecordState::Superseded;
        let mut expected_terminal_two = terminal_two.clone();
        expected_terminal_two.state = ProofRecordState::Superseded;
        let mut expected_records = vec![
            pending.clone(),
            expected_terminal_one,
            expected_terminal_two,
        ];
        expected_records.sort_by_key(|record| record.delivery_id);
        assert_eq!(
            owner.proof_records(context_id).expect("full proof audit"),
            expected_records,
            "full audit retains terminal tombstones while pending read stays fixed"
        );

        owner.release().expect("release before reopen");
        let reopened = store.open_writable().expect("reopen proof owner");
        assert_eq!(
            reopened
                .proof_records(context_id)
                .expect("reopened full proof audit"),
            expected_records,
            "reopen preserves the exact full record set"
        );
        assert_eq!(
            reopened
                .pending_proof_records(context_id)
                .expect("reopened pending index"),
            vec![pending.clone()]
        );

        reopened
            .release()
            .expect("release before legacy-index migration");
        let legacy_connection = store
            .open_database(false)
            .expect("open legacy schema connection");
        legacy_connection
            .inner
            .execute_batch("DROP INDEX IF EXISTS proofs_pending_idx")
            .expect("remove pending index from legacy fixture");
        drop(legacy_connection);
        let migrated = store
            .open_writable()
            .expect("legacy schema migration owner");
        assert_eq!(
            migrated
                .pending_proof_records(context_id)
                .expect("legacy migration restores pending index"),
            vec![pending.clone()]
        );
        assert_eq!(
            migrated
                .proof_records(context_id)
                .expect("legacy migration preserves full records"),
            expected_records,
        );
        let index_present = migrated
            .worker_call(false, false, false, |_store, connection| {
                connection
                    .query_row(
                        "SELECT COUNT(*) FROM sqlite_master
                     WHERE type='index' AND name='proofs_pending_idx'",
                        [],
                        |row| row.get::<_, i64>(0),
                    )
                    .map_err(DurableStoreError::Sqlite)
            })
            .expect("legacy index presence");
        assert_eq!(
            index_present, 1,
            "legacy migration installs only the additive index"
        );

        let usage_before = migrated
            .worker_call(false, false, false, |store, connection| {
                store.read_proof_usage(connection)
            })
            .expect("read usage before selected corruption");
        migrated.release().expect("release before corruption");
        let connection = store
            .open_database(true)
            .expect("open corruption connection");
        connection
            .inner
            .execute(
                "UPDATE proofs SET encoded=? WHERE delivery_id=?",
                params![
                    b"not-json".to_vec(),
                    pending.delivery_id.as_bytes().to_vec()
                ],
            )
            .expect("corrupt selected pending row");
        drop(connection);
        let corrupted = store.open_writable().expect("reopen corrupted owner");
        assert!(matches!(
            corrupted.pending_proof_records(context_id),
            Err(DurableStoreError::Serialization(_)) | Err(DurableStoreError::Corrupt { .. })
        ));
        let usage_after = corrupted
            .worker_call(false, false, false, |store, connection| {
                store.read_proof_usage(connection)
            })
            .expect("read usage after refused pending read");
        assert_eq!(
            usage_after, usage_before,
            "failed pending read does not mutate usage"
        );
        corrupted.release().expect("release corrupted owner");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn digest_writer_preserves_json_bytes_and_propagates_serializer_errors() {
        let bootstrap = closed("digest-writer", 22, [22; 32]);
        let fact = root_fact(&bootstrap, &key(22));
        let bytes = serde_json::to_vec(&fact).expect("representative fact JSON");
        let mut expected = Sha256::new();
        expected.update(&bytes);
        let mut streamed = Sha256::new();
        hash_json_into(&mut streamed, &fact).expect("stream representative fact JSON");
        assert_eq!(expected.finalize(), streamed.finalize());

        struct FailingJson;
        impl serde::Serialize for FailingJson {
            fn serialize<S>(&self, _serializer: S) -> Result<S::Ok, S::Error>
            where
                S: serde::Serializer,
            {
                Err(serde::ser::Error::custom("deliberate serializer failure"))
            }
        }
        let mut hasher = Sha256::new();
        assert!(hash_json_into(&mut hasher, &FailingJson).is_err());
    }

    #[test]
    fn semantic_worker_is_thread_owned_and_panic_poisoned() {
        let root = root();
        let store = DurableSemanticStore::new(&root, "worker-lifecycle-slot");
        let owner = store.open_writable().expect("worker owner");
        let worker_name = owner
            .worker_call(true, false, false, |_, _| {
                Ok(std::thread::current()
                    .name()
                    .unwrap_or("unnamed")
                    .to_owned())
            })
            .expect("worker call");
        assert_eq!(worker_name, "myownmesh-semantic-storage");
        assert!(matches!(
            owner.worker_call::<(), _>(false, false, false, |_, _| {
                panic!("deliberate semantic worker panic")
            }),
            Err(DurableStoreError::WorkerPanicked)
        ));
        assert!(matches!(
            owner.release(),
            Err(DurableStoreError::WorkerPanicked)
        ));
        let reopened = store
            .open_writable()
            .expect("panic worker must release writer lease");
        reopened.release().expect("reopened owner release");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn child_writer_holds_lease() {
        let (Some(root), Some(ready)) = (
            std::env::var_os("MYOWNMESH_STORE_CHILD_ROOT"),
            std::env::var_os("MYOWNMESH_STORE_CHILD_READY"),
        ) else {
            return;
        };
        let store = DurableSemanticStore::new(root, "child-slot");
        let _lease = store.begin_write().expect("child writer lease");
        std::fs::write(ready, b"ready").expect("child ready marker");
        std::thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn child_holds_lifetime_owner() {
        let (Some(root), Some(ready), Some(slot)) = (
            std::env::var_os("MYOWNMESH_STORE_CHILD_ROOT"),
            std::env::var_os("MYOWNMESH_STORE_CHILD_READY"),
            std::env::var_os("MYOWNMESH_STORE_CHILD_SLOT"),
        ) else {
            return;
        };
        let store = DurableSemanticStore::new(root, slot.to_string_lossy());
        let _owner = store.open_writable().expect("child lifetime owner");
        std::fs::write(ready, b"ready").expect("child ready marker");
        std::thread::sleep(Duration::from_secs(30));
    }
}
