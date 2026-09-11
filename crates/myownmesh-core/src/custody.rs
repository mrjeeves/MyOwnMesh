//! Per-device custody MFA (TOTP) for closed-network governance.
//!
//! A device may enroll a TOTP authenticator (RFC 6238, HMAC-SHA1, the
//! shape every standard authenticator app speaks) against a specific
//! network. Once enrolled, **this device refuses to *author* — propose or
//! co-sign — a governance transition for that network without a fresh
//! second-factor code**. It is a *local custody lock*: it guards this
//! device's signing authority against misuse (a transferred laptop, a
//! shoulder-surfer, a stray script), and it is deliberately **not** a
//! replacement for the network's cryptographic owner-quorum — that still
//! protects against *remote* forgery. The two compose: quorum says "enough
//! owners agreed", custody says "and this owner really meant it, here and
//! now".
//!
//! Scope is per `(device, network)`: each owner device enrolls its own
//! secret; there is no shared "fleet password" to leak. Enrollment lives in
//! `~/.myownmesh/.secrets/custody.json` (0600), never gossiped. A prepared
//! handoff also keeps its one-time recovery material in that protected file
//! until the handoff is explicitly committed or aborted, so a process restart
//! can re-deliver the exact transaction rather than silently losing custody.
//!
//! The gate is [`require`]; enrollment management is [`enroll`] /
//! [`is_enrolled`] / [`disable`]. Higher layers decide *which* networks must
//! enroll (e.g. a Fleet mandates it, a Mesh may not) — this module only
//! enforces the lock once it exists. Prepared installs carry a process-local
//! lease for diagnostics and duplicate admission, but durable recovery is
//! driven by the transaction record rather than lease death.

use std::collections::BTreeMap;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use data_encoding::BASE32_NOPAD;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha1::Sha1;
use sha2::{Digest, Sha256};

use crate::error::{Error, Result};

type HmacSha1 = Hmac<Sha1>;

/// TOTP digits — 6 is the universal authenticator default.
const DIGITS: u32 = 6;
/// TOTP step in seconds — 30 is the universal default.
const PERIOD: u64 = 30;
/// Accept the code from one step either side of now, to tolerate clock
/// skew and a code typed as the window rolls. (±30s.)
const SKEW_STEPS: i64 = 1;
/// Shared-secret length. RFC 4226 recommends ≥160 bits.
const SECRET_LEN: usize = 20;
/// One-time recovery codes minted at enrollment.
const RECOVERY_CODES: usize = 10;
/// Issuer label shown in the authenticator app.
const ISSUER: &str = "MyOwnMesh";

// ---------------------------------------------------------------------------
// On-disk model
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct CustodyStore {
    #[serde(default)]
    networks: BTreeMap<String, Enrollment>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    /// Base32 (RFC 4648, no pad) TOTP shared secret.
    secret_b32: String,
    /// SHA-256 hex of each *unused* one-time recovery code. A code is
    /// removed from this list the moment it is consumed.
    recovery_hashes: Vec<String>,
    created_at: u64,
    /// The durable transaction phase. A prepared record is visible before
    /// the caller's handoff and remains exact-retryable until it is committed
    /// or explicitly aborted.
    phase: EnrollmentPhase,
    /// Stable identity of this one enrollment transaction. It is deliberately
    /// independent of the process nonce: a stale handle must not commit or
    /// abort a successor that reused the network key.
    transaction_id: String,
    /// The exact one-time material needed to re-deliver a prepared handoff.
    /// This is present only while `phase` is `Prepared` and is cleared by a
    /// successful commit. The enclosing custody file is mode 0600.
    prepared_recovery_codes: Vec<String>,
    /// Authenticator account label needed to reconstruct the exact URI when a
    /// prepared handoff is re-delivered after a restart.
    prepared_account: String,
    process_nonce: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
enum EnrollmentPhase {
    Prepared,
    Committed,
}

/// Validated enrollment material for rendering before an exact Commit: the
/// secret (as base32 and as an `otpauth://` URI for QR rendering) and the
/// cleartext recovery codes. While the record is Prepared, the exact one-time
/// material remains in the mode-0600 custody file for redelivery, including
/// after a lost response or restart; a successful Commit clears that copy and
/// retains only its hashes, so it is never redelivered after Commit.
#[derive(Debug, Clone, Serialize)]
pub struct Enrolled {
    pub secret_b32: String,
    pub otpauth_uri: String,
    pub recovery_codes: Vec<String>,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Whether this device holds a custody enrollment for `network_id`.
pub fn is_enrolled(network_id: &str) -> bool {
    store_path()
        .ok()
        .and_then(|p| {
            recover_provisional_at(&p).ok()?;
            load_at(&p).ok()
        })
        .map(|s| s.networks.contains_key(network_id))
        .unwrap_or(false)
}

/// One enrollment that is **installed** but is not yet its caller's.
///
/// The secret and recovery codes are validated for rendering before exact
/// Commit. While the record is Prepared, that exact material remains in the
/// protected custody file for redelivery after a lost response or restart;
/// after Commit it is cleared and is never redelivered.
/// Writing after the
/// response is sent lets a device be told it is locked when the write then
/// failed and it is not; never writing until then lets two callers both be told
/// they are locked, because neither one exists to refuse the other.
///
/// So the lock is installed *first*, under the store's serializing lock, and
/// this value identifies it until the material has been handed over. A successful
/// response therefore names a lock that already exists, and an install that
/// failed is an error response rather than a promise.
///
/// **Explicit settlement.** The transaction remains prepared when this value
/// is dropped or its process dies. [`Self::commit`] makes it committed and
/// [`Self::abort`] removes it; only these explicit transitions alter durable
/// custody.
///
/// **Exactly this record.** Both transitions compare the currently-installed
/// secret and transaction ID against the exact handle, so a stale handle cannot
/// settle a successor.
#[must_use = "a prepared enrollment must be explicitly committed or aborted"]
pub struct ProvisionalEnrollment {
    /// The store this was installed in — held so the undo cannot be pointed at
    /// a different one, and so the controls never touch the real one.
    path: PathBuf,
    network_id: String,
    transaction_id: String,
    enrolled: Enrolled,
    /// An OS-held lease for this exact provisional record. The kernel drops
    /// it when the process dies, which is the cross-process liveness fence
    /// recovery needs; a nonce in the JSON alone cannot distinguish a live
    /// process from a different process that merely started later.
    lease: Option<OwnerLease>,
}

// Prepared records intentionally retain the one-time recovery material until
// explicit settlement; committed records clear it from durable storage.

/// Return the exact durable state of one enrollment transaction.
#[derive(Debug, Clone, Serialize)]
pub enum EnrollmentTransaction {
    /// The exact transaction material remains available for redelivery.
    Prepared(PreparedEnrollment),
    /// The exact transaction committed and its recovery material was cleared.
    Committed,
    /// No record matches both supplied identities.
    Absent,
}

/// The result of an idempotent MFA prepare request.
///
/// A fresh request installs one Prepared record before returning. A request
/// that arrives after a response was lost (or while the original handoff is
/// still unresolved) returns the exact durable record instead of minting a
/// second secret or transaction. The two cases are distinct so a caller can
/// retain the right local handoff value without making durability depend on a
/// process-local lease.
pub enum EnrollmentPreparation {
    /// A new Prepared record, with its process-local owner lease.
    Fresh(ProvisionalEnrollment),
    /// An existing Prepared record recovered from durable custody.
    Existing(PreparedEnrollment),
}

/// The one explicit terminal operation allowed for a prepared transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentSettlementRequest {
    /// Publish the prepared enrollment as committed custody.
    Commit,
    /// Remove the exact prepared enrollment.
    Abort,
}

/// The actual durable terminal state observed after an exact settlement.
///
/// This is deliberately independent of the requested operation: a concurrent
/// loser reports the state established by the winner rather than claiming that
/// its own requested transition occurred.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentSettlementResult {
    /// The exact transaction is committed, including an idempotent retry.
    Committed,
    /// The exact transaction is absent, including an idempotent abort or a
    /// stale transaction that cannot touch a successor.
    Absent,
}

/// Return the state of one exact transaction without selecting or mutating any
/// other enrollment. A stale transaction ID therefore observes `Absent` even
/// when a successor is installed for the same network.
pub fn enrollment_transaction(
    network_id: &str,
    transaction_id: &str,
) -> Result<EnrollmentTransaction> {
    enrollment_transaction_at(&store_path()?, network_id, transaction_id)
}

/// Return every prepared transaction whose exact material can be re-delivered.
///
/// This is a durable read: it does not acquire or require the original
/// process's owner lease, and it never changes a prepared record. The caller
/// must explicitly call [`PreparedEnrollment::commit`] after handing the
/// material to its recipient, or [`PreparedEnrollment::abort`] to discard it.
///
/// Enumeration is a transport-lab recovery control, not part of the shipped
/// custody surface. Querying one known transaction remains available through
/// [`enrollment_transaction`] in ordinary builds.
#[cfg(feature = "transport-lab")]
pub fn prepared_enrollments() -> Result<Vec<PreparedEnrollment>> {
    prepared_enrollments_at(&store_path()?)
}

/// A prepared custody transaction recovered from durable storage.
///
/// The transaction identity, TOTP secret, and one-time recovery codes are
/// reconstructed from the exact prepared record. It has no process lease, so
/// a new process may explicitly commit or abort the same transaction after a
/// crash. Dropping this value is not an abort; only the explicit methods alter
/// durable custody.
#[derive(Debug, Clone, Serialize)]
pub struct PreparedEnrollment {
    network_id: String,
    transaction_id: String,
    enrolled: Enrolled,
    /// The exact durable store from which this handle was recovered.
    ///
    /// This is process-local query context, not part of the public wire or
    /// serialized enrollment material. Keeping it on the handle ensures an
    /// explicit settlement addresses the same injected store that produced
    /// the handle, rather than re-resolving the process-global default.
    #[serde(skip_serializing)]
    path: PathBuf,
}

impl PreparedEnrollment {
    /// The network this prepared transaction locks.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// The stable identity of this exact durable handoff transaction.
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// The exact material that may be re-delivered to the caller.
    pub fn enrolled(&self) -> &Enrolled {
        &self.enrolled
    }

    /// Settle this exact prepared transaction under one writer guard and
    /// return the actual durable terminal state.
    pub fn settle(
        self,
        request: EnrollmentSettlementRequest,
    ) -> Result<EnrollmentSettlementResult> {
        settle_exact_at(
            &self.path,
            &self.network_id,
            &self.transaction_id,
            &self.enrolled.secret_b32,
            request,
        )
    }

    /// Commit this exact prepared transaction, idempotently.
    pub fn commit(self) -> Result<EnrollmentSettlementResult> {
        self.settle(EnrollmentSettlementRequest::Commit)
    }

    /// Explicitly abort this exact prepared transaction, idempotently.
    pub fn abort(self) -> Result<EnrollmentSettlementResult> {
        self.settle(EnrollmentSettlementRequest::Abort)
    }
}

impl ProvisionalEnrollment {
    /// The validated material the caller renders before exact Commit.
    pub fn enrolled(&self) -> &Enrolled {
        &self.enrolled
    }

    /// The network this locks.
    pub fn network_id(&self) -> &str {
        &self.network_id
    }

    /// The stable identity of this exact durable handoff transaction.
    pub fn transaction_id(&self) -> &str {
        &self.transaction_id
    }

    /// The caller has the material, so commit the prepared transaction.
    ///
    /// The durable transition is fallible and the error is returned to the
    /// caller. A failed commit leaves the durable Prepared record intact so
    /// it can be queried and retried after the error.
    pub fn commit(mut self) -> Result<()> {
        let result = settle_exact_at(
            &self.path,
            &self.network_id,
            &self.transaction_id,
            &self.enrolled.secret_b32,
            EnrollmentSettlementRequest::Commit,
        )
        .map(|_| ());
        // Do not let `Drop` turn a durable commit error into an implicit
        // abort. The prepared record is the recovery source for a retry.
        self.lease.take();
        result
    }

    /// The caller does not have the material, so remove exactly this lock.
    ///
    /// Reported rather than swallowed, so a daemon whose store it could not
    /// reach says so. Dropping the handle does not perform this transition;
    /// an unwind or process exit leaves the durable record available instead.
    ///
    /// A failed explicit abort leaves the Prepared record available for an
    /// exact retry; the operation is idempotent and never removes a successor.
    pub fn abort(mut self) -> Result<()> {
        settle_exact_at(
            &self.path,
            &self.network_id,
            &self.transaction_id,
            &self.enrolled.secret_b32,
            EnrollmentSettlementRequest::Abort,
        )?;
        self.lease.take();
        Ok(())
    }
}

impl Drop for ProvisionalEnrollment {
    fn drop(&mut self) {
        // Dropping a handle is not an implicit transition. Prepared custody
        // remains durable and re-deliverable until explicit commit or abort.
        self.lease.take();
    }
}

/// Enroll a fresh TOTP authenticator for `network_id` on this device.
/// `account` is the human label shown in the authenticator app (e.g. the
/// device label). Fails if an enrollment already exists — [`disable`] it
/// first (which itself requires a valid code), so the lock can't be
/// silently rotated away.
///
/// Installs and keeps in one step. A caller that has to hand the material to
/// somebody else before it can say the enrollment succeeded uses
/// [`install_provisional_enroll`] and settles it against whether the handoff
/// actually happened.
pub fn enroll(network_id: &str, account: &str) -> Result<Enrolled> {
    let provisional = install_provisional_enroll(network_id, account)?;
    let enrolled = provisional.enrolled.clone();
    provisional.commit()?;
    Ok(enrolled)
}

/// Install an enrollment whose explicit commit or abort the caller owns. See
/// [`ProvisionalEnrollment`].
pub fn install_provisional_enroll(
    network_id: &str,
    account: &str,
) -> Result<ProvisionalEnrollment> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    install_provisional_enroll_at(&path, network_id, account)
}

/// Prepare an MFA enrollment, or recover the exact current Prepared record.
///
/// The absent/check/insert or existing-record classification is one durable
/// transaction under [`STORE_LOCK`] and the cross-process [`WriterLease`]. A
/// Prepared record is never rotated or overwritten here, and a Committed
/// record retains the strict install refusal. Only explicit commit or abort
/// can settle the returned transaction.
pub fn prepare_or_recover_provisional_enroll(
    network_id: &str,
    account: &str,
) -> Result<EnrollmentPreparation> {
    let path = store_path()?;
    prepare_or_recover_provisional_enroll_at(&path, network_id, account)
}

/// Validate the durable prepared-enrollment store without expiring records.
///
/// Callers may invoke this at daemon startup, and all public custody entry
/// points perform the same check before reading or mutating the store. A
/// prepared handoff remains available after its creating process dies; only an
/// exact explicit commit or abort changes that state.
pub fn recover_provisional_enrollments() -> Result<usize> {
    recover_provisional_at(&store_path()?)
}

/// The gate. `Ok(())` when the network has no enrollment on this device (the
/// lock is a no-op) **or** when `code` verifies — a TOTP for the current
/// window, or a one-time recovery code, which is then consumed. `Err`
/// otherwise. Custody-affecting governance authoring calls this before it
/// signs.
pub fn require(network_id: &str, code: Option<&str>) -> Result<()> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    require_at(&path, network_id, code)
}

/// Remove the custody lock for `network_id` — but only on presentation of a
/// valid code, so the lock can't be undone by someone who doesn't already
/// satisfy it.
pub fn disable(network_id: &str, code: &str) -> Result<()> {
    let path = store_path()?;
    recover_provisional_at(&path)?;
    disable_at(&path, network_id, code)
}

// ---------------------------------------------------------------------------
// Path-injectable core (so unit tests never touch the real secrets dir)
// ---------------------------------------------------------------------------

/// Serializes every read-modify-write of the custody store.
///
/// The store is one file read, checked, edited and written back, and the check
/// is what makes "this device has one lock" true. Two of those sequences
/// interleaving is the whole failure: both read a store with no entry for the
/// network, both pass the duplicate check, both write, and the last write wins —
/// so two callers are told they are enrolled and only one of the two secrets
/// opens the lock that survives. `write_atomic` prevents a torn file; it cannot
/// prevent a lost update, because the loser's read happened before the winner's
/// write existed to be read.
///
/// Held across load → check → save and never across an `await`, since nothing
/// under it is async. Poison-tolerant: a caller that panicked mid-sequence left
/// the *file* consistent — `save_at` is atomic — so refusing every later
/// enrollment because of it would turn one panic into a permanently unusable
/// custody store.
static STORE_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
static PROCESS_NONCE: std::sync::OnceLock<String> = std::sync::OnceLock::new();

/// A process-owned lease for one exact provisional record. The file is
/// deliberately retained only as long as its owner is live; its advisory
/// kernel lock is the authority and the contents are diagnostic metadata,
/// never a liveness decision. The record secret is part of the lease path, so
/// disabling this record permits a successor to acquire a distinct lease even
/// while a stale same-process handle still awaits its exact rollback.
struct OwnerLease {
    file: File,
    #[cfg(windows)]
    overlapped: Box<WinOverlapped>,
}

impl OwnerLease {
    fn acquire(path: &Path, network_id: &str, record_secret: &str, nonce: &str) -> Result<Self> {
        let lease_path = owner_lease_path(path, network_id, record_secret);
        if let Some(parent) = lease_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Custody(format!("create custody lease dir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .map_err(|e| Error::Custody(format!("open custody owner lease: {e}")))?;
        #[cfg(unix)]
        if !try_lock_owner_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody owner lease: {e}")))?
        {
            return Err(Error::Custody(format!(
                "a live process owns the provisional custody lease for {network_id}"
            )));
        }
        #[cfg(windows)]
        let overlapped = try_lock_owner_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody owner lease: {e}")))?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::Custody(
            "cross-process custody leases are unsupported on this platform".into(),
        ));

        let mut lease = Self {
            file,
            #[cfg(windows)]
            overlapped,
        };
        lease
            .file
            .set_len(0)
            .and_then(|_| {
                lease
                    .file
                    .write_all(format!("{} {nonce}\n", std::process::id()).as_bytes())
            })
            .and_then(|_| lease.file.sync_data())
            .map_err(|e| Error::Custody(format!("write custody owner lease: {e}")))?;
        restrict_file(&lease_path);
        Ok(lease)
    }
}

impl Drop for OwnerLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock_owner_file(&self.file);
        #[cfg(windows)]
        unlock_owner_file(&self.file, &mut self.overlapped);
        // Retain the stable pathname. Removing it after unlock allows a
        // contender to lock the old inode/handle before unlink while another
        // process creates and locks a replacement file. The kernel lock, not
        // pathname lifetime, is the liveness authority.
    }
}

/// The shared custody file is one logical map even when two processes mutate
/// different network keys. This lease serializes the complete load/check/
/// mutate/save transaction across processes; it is never unlinked, so every
/// contender always refers to the same inode.
struct WriterLease {
    file: File,
    #[cfg(windows)]
    overlapped: Box<WinOverlapped>,
}

impl WriterLease {
    fn acquire(path: &Path) -> Result<Self> {
        let lease_path = writer_lease_path(path);
        if let Some(parent) = lease_path.parent() {
            std::fs::create_dir_all(parent)
                .map_err(|e| Error::Custody(format!("create writer lease dir: {e}")))?;
        }
        let file = OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&lease_path)
            .map_err(|e| Error::Custody(format!("open custody writer lease: {e}")))?;
        restrict_file(&lease_path);
        #[cfg(unix)]
        lock_writer_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody writer lease: {e}")))?;
        #[cfg(windows)]
        let overlapped = lock_writer_file(&file)
            .map_err(|e| Error::Custody(format!("lock custody writer lease: {e}")))?;
        #[cfg(not(any(unix, windows)))]
        return Err(Error::Custody(
            "cross-process custody leases are unsupported on this platform".into(),
        ));
        Ok(Self {
            file,
            #[cfg(windows)]
            overlapped,
        })
    }
}

impl Drop for WriterLease {
    fn drop(&mut self) {
        #[cfg(unix)]
        unlock_owner_file(&self.file);
        #[cfg(windows)]
        unlock_owner_file(&self.file, &mut self.overlapped);
    }
}

fn owner_lease_path(path: &Path, network_id: &str, record_secret: &str) -> PathBuf {
    let mut digest = Sha256::new();
    digest.update(network_id.as_bytes());
    digest.update([0]);
    digest.update(record_secret.as_bytes());
    path.with_file_name(format!(
        "{}.{}.lease",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("custody"),
        hex::encode(digest.finalize())
    ))
}

fn writer_lease_path(path: &Path) -> PathBuf {
    path.with_file_name(format!(
        "{}.writer.lock",
        path.file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("custody")
    ))
}

#[cfg(unix)]
fn try_lock_owner_file(file: &File) -> io::Result<bool> {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        const LOCK_NB: i32 = 4;
        if flock(file.as_raw_fd(), LOCK_EX | LOCK_NB) == 0 {
            Ok(true)
        } else if io::Error::last_os_error().kind() == io::ErrorKind::WouldBlock {
            Ok(false)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(unix)]
fn unlock_owner_file(file: &File) {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_UN: i32 = 8;
        let _ = flock(file.as_raw_fd(), LOCK_UN);
    }
}

#[cfg(unix)]
fn lock_writer_file(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;
    unsafe {
        unsafe extern "C" {
            fn flock(fd: i32, operation: i32) -> i32;
        }
        const LOCK_EX: i32 = 2;
        if flock(file.as_raw_fd(), LOCK_EX) == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
#[repr(C)]
struct WinOverlapped {
    internal: usize,
    internal_high: usize,
    offset: u32,
    offset_high: u32,
    event: *mut std::ffi::c_void,
}

#[cfg(windows)]
// SAFETY: The OVERLAPPED value is allocated in a Box and is never moved after
// LockFileEx receives its address. Moving the owning Box between threads keeps
// that address stable. `event` is always null, so there is no event handle or
// other pointed-to state to transfer. Windows associates the byte-range lock
// with the file handle, and UnlockFileEx accepts that same handle from the
// thread that owns the moved lease. The lease remains uniquely owned, so no
// concurrent access to the OVERLAPPED value is possible.
unsafe impl Send for WinOverlapped {}

#[cfg(windows)]
fn try_lock_owner_file(file: &File) -> io::Result<Box<WinOverlapped>> {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn LockFileEx(
                file: *mut std::ffi::c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
        const LOCKFILE_FAIL_IMMEDIATELY: u32 = 1;
        let mut overlapped = Box::new(WinOverlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        });
        if LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK | LOCKFILE_FAIL_IMMEDIATELY,
            0,
            u32::MAX,
            u32::MAX,
            &mut *overlapped,
        ) != 0
        {
            Ok(overlapped)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(windows)]
fn unlock_owner_file(file: &File, overlapped: &mut WinOverlapped) {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn UnlockFileEx(
                file: *mut std::ffi::c_void,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        let _ = UnlockFileEx(file.as_raw_handle(), 0, u32::MAX, u32::MAX, overlapped);
    }
}

#[cfg(windows)]
fn lock_writer_file(file: &File) -> io::Result<Box<WinOverlapped>> {
    use std::os::windows::io::AsRawHandle;
    unsafe {
        unsafe extern "system" {
            fn LockFileEx(
                file: *mut std::ffi::c_void,
                flags: u32,
                reserved: u32,
                low: u32,
                high: u32,
                overlapped: *mut WinOverlapped,
            ) -> i32;
        }
        const LOCKFILE_EXCLUSIVE_LOCK: u32 = 2;
        let mut overlapped = Box::new(WinOverlapped {
            internal: 0,
            internal_high: 0,
            offset: 0,
            offset_high: 0,
            event: std::ptr::null_mut(),
        });
        if LockFileEx(
            file.as_raw_handle(),
            LOCKFILE_EXCLUSIVE_LOCK,
            0,
            u32::MAX,
            u32::MAX,
            &mut *overlapped,
        ) != 0
        {
            Ok(overlapped)
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

#[cfg(not(any(unix, windows)))]
fn unlock_owner_file(_file: &File) {}

fn store_guard() -> std::sync::MutexGuard<'static, ()> {
    STORE_LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

fn store_transaction_guard(
    path: &Path,
) -> Result<(std::sync::MutexGuard<'static, ()>, WriterLease)> {
    let serialized = store_guard();
    let writer = WriterLease::acquire(path)?;
    Ok((serialized, writer))
}

fn install_provisional_enroll_at(
    path: &Path,
    network_id: &str,
    account: &str,
) -> Result<ProvisionalEnrollment> {
    recover_provisional_at(path)?;
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    create_provisional_enroll_at(path, network_id, account, &mut store)
}

fn prepare_or_recover_provisional_enroll_at(
    path: &Path,
    network_id: &str,
    account: &str,
) -> Result<EnrollmentPreparation> {
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(enrollment) = store.networks.get(network_id) else {
        return create_provisional_enroll_at(path, network_id, account, &mut store)
            .map(EnrollmentPreparation::Fresh);
    };
    if is_prepared(enrollment) {
        return prepared_enrollment_from_record(path, network_id, enrollment)
            .map(EnrollmentPreparation::Existing);
    }
    Err(Error::Custody(format!(
        "network {network_id} already has MFA enrolled on this device; disable it first"
    )))
}

fn create_provisional_enroll_at(
    path: &Path,
    network_id: &str,
    account: &str,
    store: &mut CustodyStore,
) -> Result<ProvisionalEnrollment> {
    if store.networks.contains_key(network_id) {
        return Err(Error::Custody(format!(
            "network {network_id} already has MFA enrolled on this device; disable it first"
        )));
    }
    let secret = random_bytes(SECRET_LEN);
    let secret_b32 = BASE32_NOPAD.encode(&secret);
    let recovery_codes = gen_recovery_codes();
    let recovery_hashes = recovery_codes.iter().map(|c| hash_code(c)).collect();
    let otpauth_uri = provisioning_uri(&secret_b32, account);
    let transaction_id = BASE32_NOPAD.encode(&random_bytes(16)).to_lowercase();
    let lease = OwnerLease::acquire(path, network_id, &secret_b32, process_nonce())?;
    store.networks.insert(
        network_id.to_string(),
        Enrollment {
            secret_b32: secret_b32.clone(),
            recovery_hashes,
            created_at: now_unix(),
            phase: EnrollmentPhase::Prepared,
            transaction_id: transaction_id.clone(),
            prepared_recovery_codes: recovery_codes.clone(),
            prepared_account: account.to_string(),
            process_nonce: process_nonce().to_string(),
        },
    );
    // Written before anything is answered, so what comes back names a lock that
    // exists. A failure here is the caller's failure: no material has been
    // shown, and nothing is installed.
    save_at(path, store)?;
    Ok(ProvisionalEnrollment {
        path: path.to_path_buf(),
        network_id: network_id.to_string(),
        transaction_id,
        enrolled: Enrolled {
            secret_b32,
            otpauth_uri,
            recovery_codes,
        },
        lease: Some(lease),
    })
}

/// Commit the exact installed record, preserving the same generation fence
/// used by rollback. A stale handle can never commit a successor, and a
/// record already committed by an earlier idempotent handoff is left alone.
fn settle_exact_at(
    path: &Path,
    network_id: &str,
    transaction_id: &str,
    secret_b32: &str,
    request: EnrollmentSettlementRequest,
) -> Result<EnrollmentSettlementResult> {
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(installed) = store.networks.get(network_id) else {
        return Ok(EnrollmentSettlementResult::Absent);
    };
    if !constant_eq(installed.secret_b32.as_bytes(), secret_b32.as_bytes())
        || !constant_eq(
            installed.transaction_id.as_bytes(),
            transaction_id.as_bytes(),
        )
    {
        return Ok(EnrollmentSettlementResult::Absent);
    }
    if !is_prepared(installed) {
        return Ok(EnrollmentSettlementResult::Committed);
    }
    match request {
        EnrollmentSettlementRequest::Commit => {
            let installed = store
                .networks
                .get_mut(network_id)
                .expect("exact prepared record remains under writer guard");
            installed.phase = EnrollmentPhase::Committed;
            installed.prepared_recovery_codes.clear();
            installed.prepared_account.clear();
            installed.process_nonce.clear();
            save_at(path, &store)?;
            Ok(EnrollmentSettlementResult::Committed)
        }
        EnrollmentSettlementRequest::Abort => {
            store.networks.remove(network_id);
            save_at(path, &store)?;
            Ok(EnrollmentSettlementResult::Absent)
        }
    }
}

/// Validate the durable store without expiring prepared transactions.
///
/// Prepared custody is recoverable material, so neither owner-lease death nor
/// a changed process nonce is permission to delete it. The explicit abort path
/// is the only prepared-to-absent transition.
fn recover_provisional_at(path: &Path) -> Result<usize> {
    let _serialized = store_guard();
    let _ = load_at(path)?;
    Ok(0)
}

/// Remove `network_id`'s lock, but only while it is still the exact one
/// `secret_b32` names.
///
/// The comparison is the difference between an undo and a denial of service. A
/// rollback that keys on the network alone removes whatever lock is installed by
/// the time it runs — including a successor the operator enrolled after the
/// first attempt failed, whose material *was* delivered. Constant-time, for the
/// same reason every other comparison against stored custody material here is.
fn is_prepared(enrollment: &Enrollment) -> bool {
    enrollment.phase == EnrollmentPhase::Prepared
}

#[cfg(any(test, feature = "transport-lab"))]
fn prepared_enrollments_at(path: &Path) -> Result<Vec<PreparedEnrollment>> {
    let _serialized = store_guard();
    let store = load_at(path)?;
    store
        .networks
        .into_iter()
        .filter_map(|(network_id, enrollment)| {
            if !is_prepared(&enrollment) {
                return None;
            }
            Some((network_id, enrollment))
        })
        .map(|(network_id, enrollment)| {
            prepared_enrollment_from_record(path, &network_id, &enrollment)
        })
        .collect()
}

fn prepared_enrollment_from_record(
    path: &Path,
    network_id: &str,
    enrollment: &Enrollment,
) -> Result<PreparedEnrollment> {
    if enrollment.transaction_id.is_empty() {
        return Err(Error::Custody(format!(
            "prepared custody record for {network_id} has no transaction identity"
        )));
    }
    if enrollment.secret_b32.is_empty() {
        return Err(Error::Custody(format!(
            "prepared custody record for {network_id} has no secret"
        )));
    }
    if enrollment.prepared_recovery_codes.is_empty() {
        return Err(Error::Custody(format!(
            "prepared custody record for {network_id} has no re-deliverable recovery material"
        )));
    }
    if enrollment.prepared_account.is_empty() {
        return Err(Error::Custody(format!(
            "prepared custody record for {network_id} has no account label"
        )));
    }
    let enrolled = Enrolled {
        secret_b32: enrollment.secret_b32.clone(),
        otpauth_uri: provisioning_uri(&enrollment.secret_b32, &enrollment.prepared_account),
        recovery_codes: enrollment.prepared_recovery_codes.clone(),
    };
    Ok(PreparedEnrollment {
        network_id: network_id.to_owned(),
        transaction_id: enrollment.transaction_id.clone(),
        enrolled,
        path: path.to_path_buf(),
    })
}

fn enrollment_transaction_at(
    path: &Path,
    network_id: &str,
    transaction_id: &str,
) -> Result<EnrollmentTransaction> {
    let _serialized = store_guard();
    let mut store = load_at(path)?;
    let Some(enrollment) = store.networks.remove(network_id) else {
        return Ok(EnrollmentTransaction::Absent);
    };
    if !constant_eq(
        enrollment.transaction_id.as_bytes(),
        transaction_id.as_bytes(),
    ) {
        return Ok(EnrollmentTransaction::Absent);
    }
    if is_prepared(&enrollment) {
        return prepared_enrollment_from_record(path, network_id, &enrollment)
            .map(EnrollmentTransaction::Prepared);
    }
    Ok(EnrollmentTransaction::Committed)
}

#[cfg(test)]
fn enroll_at(path: &Path, network_id: &str, account: &str) -> Result<Enrolled> {
    let provisional = install_provisional_enroll_at(path, network_id, account)?;
    let enrolled = provisional.enrolled.clone();
    provisional.commit()?;
    Ok(enrolled)
}

/// What a supplied code earns against one exact enrollment record.
enum CodeVerdict {
    /// A TOTP for the current window. Nothing about the record changes, and
    /// nothing is owed to disk.
    Totp,
    /// A one-time recovery code, at this position in `recovery_hashes`.
    ///
    /// Consuming it is the *caller's* write, not this check's, because whether
    /// a write is owed depends on what the caller does with the record next: a
    /// gate that keeps the enrollment has to burn the code, and a disable that
    /// removes the whole record has nothing left to burn it out of.
    Recovery(usize),
}

/// Check `code` against one already-loaded enrollment.
///
/// Factored out so both callers authorize identically **and neither has to
/// reach for the store lock to do it**. That second half is the load-bearing
/// one: `disable_at` used to authorize by calling the lock-taking gate, which
/// released [`STORE_LOCK`] before the removal ran, and the removal then deleted
/// whichever record existed by the time it reacquired. Two local control
/// requests were enough — a disable against a network with no enrollment
/// returned `Ok` without validating anything, and then removed a *successor*
/// that a concurrent enroll had installed and already answered for. Verification
/// is a pure function of one record, so it belongs where the record is, under
/// the caller's own guard.
fn verify_code(enrollment: &Enrollment, code: Option<&str>) -> Result<CodeVerdict> {
    let Some(code) = code.map(str::trim).filter(|c| !c.is_empty()) else {
        return Err(Error::Custody(
            "this change requires your authenticator code".into(),
        ));
    };
    // TOTP for the current window (±1 step) first.
    let secret = BASE32_NOPAD
        .decode(enrollment.secret_b32.as_bytes())
        .map_err(|e| Error::Custody(format!("stored secret is not valid base32: {e}")))?;
    if verify_totp_at(&secret, code, now_unix()) {
        return Ok(CodeVerdict::Totp);
    }
    // Otherwise a one-time recovery code.
    let h = hash_code(code);
    if let Some(pos) = enrollment
        .recovery_hashes
        .iter()
        .position(|x| constant_eq(x.as_bytes(), h.as_bytes()))
    {
        return Ok(CodeVerdict::Recovery(pos));
    }
    Err(Error::Custody("invalid authenticator code".into()))
}

fn require_at(path: &Path, network_id: &str, code: Option<&str>) -> Result<()> {
    // A recovery code is *consumed* on match, which makes this a store mutation
    // like any other: two gates racing on the same code could otherwise both
    // read it unused and both be admitted by it.
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(enr) = store.networks.get_mut(network_id) else {
        return Ok(()); // not enrolled on this device → the gate is a no-op
    };
    match verify_code(enr, code)? {
        CodeVerdict::Totp => Ok(()),
        CodeVerdict::Recovery(pos) => {
            enr.recovery_hashes.remove(pos);
            save_at(path, &store)
        }
    }
}

fn disable_at(path: &Path, network_id: &str, code: &str) -> Result<()> {
    // One guard, one load, one verify, one removal, one save. The record the
    // code is checked against and the record that is removed are the same
    // borrow of the same loaded store, so nothing can be installed, rolled back
    // or replaced between the two — which is the whole correction here. The
    // previous shape authorized through the lock-taking gate and reacquired for
    // the removal, and that gap was enough for a disable to delete an
    // enrollment nobody had authorized it against.
    let (_serialized, _writer) = store_transaction_guard(path)?;
    let mut store = load_at(path)?;
    let Some(enrollment) = store.networks.get(network_id) else {
        // Nothing is installed, so there is nothing to remove and nothing to
        // write. Answering `Ok` keeps disable idempotent — the end state it
        // promises is "this network has no lock", which already holds — and
        // writing nothing is what makes that answer safe: the old shape's
        // unconditional removal-and-save is exactly what could take a
        // successor away.
        return Ok(());
    };
    if is_prepared(enrollment) {
        return Err(Error::Custody(format!(
            "network {network_id} has a Prepared MFA transaction; explicitly abort it before disabling"
        )));
    }
    // The verdict itself is spent here. A recovery code needs no consumption
    // write on this path: the same locked mutation removes the record the code
    // would have been burned out of, and saves once.
    verify_code(enrollment, Some(code))?;
    store.networks.remove(network_id);
    save_at(path, &store)
}

// ---------------------------------------------------------------------------
// TOTP / HOTP (RFC 6238 / RFC 4226)
// ---------------------------------------------------------------------------

fn hotp(secret: &[u8], counter: u64) -> u32 {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(&counter.to_be_bytes());
    let digest = mac.finalize().into_bytes();
    // Dynamic truncation (RFC 4226 §5.3).
    let offset = (digest[digest.len() - 1] & 0x0f) as usize;
    let bin = (u32::from(digest[offset] & 0x7f) << 24)
        | (u32::from(digest[offset + 1]) << 16)
        | (u32::from(digest[offset + 2]) << 8)
        | u32::from(digest[offset + 3]);
    bin % 10u32.pow(DIGITS)
}

// Computing a code *from the secret* is what an authenticator app does, not
// the daemon — the whole point of the second factor is that it comes from a
// separate device. So this lives test-only; production never derives its own
// code (it only ever `verify`s one supplied from outside).
#[cfg(test)]
fn totp_at(secret: &[u8], unix: u64) -> String {
    format!(
        "{:0width$}",
        hotp(secret, unix / PERIOD),
        width = DIGITS as usize
    )
}

fn verify_totp_at(secret: &[u8], code: &str, unix: u64) -> bool {
    let code = code.trim();
    if code.len() != DIGITS as usize || !code.bytes().all(|b| b.is_ascii_digit()) {
        return false;
    }
    let step = (unix / PERIOD) as i64;
    for d in -SKEW_STEPS..=SKEW_STEPS {
        let counter = (step + d).max(0) as u64;
        let candidate = format!("{:0width$}", hotp(secret, counter), width = DIGITS as usize);
        if constant_eq(candidate.as_bytes(), code.as_bytes()) {
            return true;
        }
    }
    false
}

fn provisioning_uri(secret_b32: &str, account: &str) -> String {
    let label = format!("{}:{}", pct(ISSUER), pct(account));
    format!(
        "otpauth://totp/{label}?secret={secret_b32}&issuer={}&algorithm=SHA1&digits={DIGITS}&period={PERIOD}",
        pct(ISSUER)
    )
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Percent-encode everything but the RFC 3986 unreserved set.
fn pct(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for &b in s.as_bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    if getrandom::getrandom(&mut v).is_err() {
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut v);
    }
    v
}

/// `RECOVERY_CODES` formatted as `xxxxx-xxxxx` (base32, lowercase).
fn gen_recovery_codes() -> Vec<String> {
    (0..RECOVERY_CODES)
        .map(|_| {
            let raw = BASE32_NOPAD.encode(&random_bytes(8)).to_lowercase();
            let c: String = raw.chars().take(10).collect();
            format!("{}-{}", &c[..5], &c[5..])
        })
        .collect()
}

/// Normalise (strip separators + case) then SHA-256-hex, so a recovery code
/// matches whether the user types the dashes or not.
fn hash_code(code: &str) -> String {
    let normalized: String = code
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(|c| c.to_lowercase())
        .collect();
    let mut h = Sha256::new();
    h.update(normalized.as_bytes());
    hex::encode(h.finalize())
}

fn constant_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn process_nonce() -> &'static str {
    PROCESS_NONCE
        .get_or_init(|| hex::encode(random_bytes(16)))
        .as_str()
}

fn store_path() -> Result<PathBuf> {
    Ok(crate::dirs::secrets_dir()?.join("custody.json"))
}

fn load_at(path: &Path) -> Result<CustodyStore> {
    match std::fs::read(path) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(CustodyStore::default()),
        Err(e) => Err(Error::Custody(format!("read custody store: {e}"))),
    }
}

fn save_at(path: &Path, store: &CustodyStore) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| Error::Custody(format!("create secrets dir: {e}")))?;
        restrict_dir(parent);
    }
    let bytes = serde_json::to_vec_pretty(store)?;
    // Atomic so a power cut can't truncate the store. Note load_at
    // deliberately stays hard-fail on a corrupt file: falling back to
    // an empty store would silently turn OFF custody (MFA) for every
    // enrolled network — fail-open. Corruption is prevented here
    // instead of forgiven there.
    crate::persist::write_atomic(path, &bytes)
        .map_err(|e| Error::Custody(format!("write custody store: {e}")))?;
    restrict_file(path);
    Ok(())
}

#[cfg(unix)]
fn restrict_dir(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700));
}
#[cfg(unix)]
fn restrict_file(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
}
#[cfg(not(unix))]
fn restrict_dir(_path: &Path) {}
#[cfg(not(unix))]
fn restrict_file(_path: &Path) {}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 6238 Appendix B reference vector (SHA-1 seed, T=59s). The 8-digit
    /// reference is 94287082; truncated to our 6 digits that's 287082.
    #[test]
    fn totp_matches_rfc6238_vector() {
        let secret = b"12345678901234567890";
        assert_eq!(totp_at(secret, 59), "287082");
        assert!(verify_totp_at(secret, "287082", 59));
        // A code from ten steps away is outside the ±1 skew window.
        assert!(!verify_totp_at(secret, "287082", 59 + 10 * PERIOD));
        // Wrong shape is rejected outright.
        assert!(!verify_totp_at(secret, "1234567", 59));
        assert!(!verify_totp_at(secret, "abcdef", 59));
    }

    #[test]
    fn skew_window_accepts_adjacent_steps() {
        let secret = b"12345678901234567890";
        let code = totp_at(secret, 1000);
        assert!(verify_totp_at(secret, &code, 1000));
        assert!(verify_totp_at(secret, &code, 1000 + PERIOD)); // +1 step
        assert!(verify_totp_at(secret, &code, 1000 - PERIOD)); // -1 step
        assert!(!verify_totp_at(secret, &code, 1000 + 2 * PERIOD)); // +2 steps: out
    }

    #[test]
    fn recovery_hash_is_separator_and_case_insensitive() {
        assert_eq!(hash_code("ABCDE-FGHIJ"), hash_code("abcdefghij"));
        assert_eq!(hash_code("ab cd ef"), hash_code("ABCDEF"));
        assert_ne!(hash_code("abcde"), hash_code("abcdf"));
    }

    #[test]
    fn provisioning_uri_is_authenticator_shaped() {
        let uri = provisioning_uri("JBSWY3DPEHPK3PXP", "my laptop");
        assert!(uri.starts_with("otpauth://totp/MyOwnMesh:my%20laptop?"));
        assert!(uri.contains("secret=JBSWY3DPEHPK3PXP"));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
    }

    fn tmp() -> PathBuf {
        // A process-global counter guarantees a distinct path per call even
        // when tests run concurrently and the clock is too coarse to separate
        // them (observed flaking on macOS, where two disk tests collided on
        // one file and stomped each other's store).
        use std::sync::atomic::{AtomicU64, Ordering};
        static N: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "mom-custody-test-{}-{}-{}.json",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed),
            now_unix_nanos()
        ))
    }
    fn now_unix_nanos() -> u128 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    }

    #[test]
    fn enroll_then_gate_accepts_totp_and_consumes_recovery() {
        let path = tmp();
        let net = "fleet-xyz";

        // Not enrolled → the gate is a no-op even with no code.
        assert!(require_at(&path, net, None).is_ok());

        let enrolled = enroll_at(&path, net, "laptop").expect("enroll");
        assert_eq!(enrolled.recovery_codes.len(), RECOVERY_CODES);

        // Enrolled → a custody change with no code is refused.
        assert!(require_at(&path, net, None).is_err());
        // Wrong code refused.
        assert!(require_at(&path, net, Some("000000")).is_err());

        // A correct TOTP (computed from the returned secret, as an
        // authenticator app would) is accepted, and is reusable within its
        // window (TOTP is not one-time).
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();
        let code = totp_at(&secret, now_unix());
        assert!(require_at(&path, net, Some(&code)).is_ok());
        assert!(require_at(&path, net, Some(&code)).is_ok());

        // A recovery code works once, then is burned.
        let rc = &enrolled.recovery_codes[0];
        assert!(require_at(&path, net, Some(rc)).is_ok());
        assert!(
            require_at(&path, net, Some(rc)).is_err(),
            "a recovery code must be single-use"
        );

        // Other networks are unaffected (per-network scope).
        assert!(require_at(&path, "some-mesh", None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    /// Two callers enrolling one network at once leave one lock, and the one
    /// success is the secret that opens it.
    ///
    /// The discriminating case for install-before-answer. Two clients used to be
    /// able to run load → duplicate check → insert → save concurrently: both
    /// read a store with no entry, both passed the check, and the last write
    /// won. Both callers were told they were enrolled, and only one of the two
    /// secrets opened the lock that survived — the other held material for a
    /// lock that does not exist, on a device that now refuses to author
    /// governance without a code it cannot produce.
    ///
    /// Real threads and a barrier, so the two sequences genuinely overlap rather
    /// than being asserted to. The *outcome* is deterministic under every
    /// interleaving, which is the property: whichever thread takes
    /// [`STORE_LOCK`] first installs, and the other one's duplicate check now
    /// sees the entry the first wrote, because it is behind that same lock.
    #[test]
    fn v4_r7_core_b1_two_concurrent_enrollments_leave_one_lock_and_one_success() {
        let path = tmp();
        let net = "fleet-concurrent";

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let racing: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    install_provisional_enroll_at(&path, net, "phone").map(|installed| {
                        let material = installed.enrolled().clone();
                        // The response reached its caller, so the lock stands.
                        installed.commit().expect("commit concurrent enrollment");
                        material
                    })
                })
            })
            .collect();
        let answered: Vec<Enrolled> = racing
            .into_iter()
            .filter_map(|thread| thread.join().expect("neither enrollment panics").ok())
            .collect();

        assert_eq!(
            answered.len(),
            1,
            "exactly one caller is told it enrolled; the other is refused, \
             rather than both being told yes and one of them being wrong"
        );
        let secret = BASE32_NOPAD
            .decode(answered[0].secret_b32.as_bytes())
            .expect("the answered secret is base32");
        let code = totp_at(&secret, now_unix());
        assert!(
            require_at(&path, net, Some(&code)).is_ok(),
            "and the secret that came back is the installed lock — not the \
             loser's, and not one that was overwritten"
        );
        assert!(
            require_at(&path, net, Some("000000")).is_err(),
            "non-vacuity: the gate is really locked, not accepting everything"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A repeated prepare returns the exact durable transaction and one-time
    /// material rather than rotating the lock or allocating a new transaction.
    #[test]
    fn v4_r2_prepare_recovers_exact_existing_prepared_material() {
        let path = tmp();
        let net = "fleet-prepare-retry";
        let first =
            prepare_or_recover_provisional_enroll_at(&path, net, "laptop").expect("first prepare");
        let (first_transaction, first_material) = match &first {
            EnrollmentPreparation::Fresh(fresh) => {
                (fresh.transaction_id().to_owned(), fresh.enrolled().clone())
            }
            EnrollmentPreparation::Existing(_) => panic!("first prepare was not fresh"),
        };
        drop(first);

        let retry = prepare_or_recover_provisional_enroll_at(&path, net, "different-account")
            .expect("prepared retry");
        match retry {
            EnrollmentPreparation::Existing(existing) => {
                assert_eq!(existing.transaction_id(), first_transaction);
                assert_eq!(existing.enrolled().secret_b32, first_material.secret_b32);
                assert_eq!(existing.enrolled().otpauth_uri, first_material.otpauth_uri);
                assert_eq!(
                    existing.enrolled().recovery_codes,
                    first_material.recovery_codes
                );
            }
            EnrollmentPreparation::Fresh(_) => panic!("prepared retry rotated the record"),
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Concurrent prepare callers classify one writer's insertion as Fresh and
    /// the other as Existing, with identical material from the durable record.
    #[test]
    fn v4_r2_concurrent_prepare_callers_share_one_prepared_material() {
        let path = tmp();
        let net = "fleet-prepare-race";
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let callers: Vec<_> = (0..2)
            .map(|_| {
                let path = path.clone();
                let barrier = std::sync::Arc::clone(&barrier);
                std::thread::spawn(move || {
                    barrier.wait();
                    prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
                })
            })
            .collect();

        let results: Vec<_> = callers
            .into_iter()
            .map(|caller| caller.join().expect("prepare caller does not panic"))
            .collect::<Result<Vec<_>>>()
            .expect("both prepare callers complete");
        let mut fresh = None;
        let mut existing = None;
        for result in results {
            match result {
                EnrollmentPreparation::Fresh(value) => fresh = Some(value),
                EnrollmentPreparation::Existing(value) => existing = Some(value),
            }
        }
        let fresh = fresh.expect("one caller installs the prepared record");
        let existing = existing.expect("the other caller recovers the prepared record");
        assert_eq!(fresh.transaction_id(), existing.transaction_id());
        assert_eq!(fresh.enrolled().secret_b32, existing.enrolled().secret_b32);
        assert_eq!(
            fresh.enrolled().recovery_codes,
            existing.enrolled().recovery_codes
        );

        let _ = std::fs::remove_file(&path);
    }

    /// A committed record remains a strict refusal for Prepare; only the
    /// explicit terminal operation can make a fresh prepare possible again.
    #[test]
    fn v4_r2_prepare_refuses_committed_until_explicit_abort() {
        let path = tmp();
        let net = "fleet-prepare-committed";
        let first = match prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
            .expect("first prepare")
        {
            EnrollmentPreparation::Fresh(value) => value,
            EnrollmentPreparation::Existing(_) => panic!("first prepare was not fresh"),
        };
        first.commit().expect("commit exact prepared record");
        assert!(
            prepare_or_recover_provisional_enroll_at(&path, net, "laptop").is_err(),
            "Prepare must preserve committed refusal"
        );

        let _ = std::fs::remove_file(&path);
    }

    /// Disable is not an alternate abort path: even valid material cannot
    /// remove a Prepared transaction. The exact material remains recoverable,
    /// and only an exact explicit Abort permits a distinct successor.
    #[test]
    fn v4_r2_disable_refuses_prepared_material_until_explicit_abort() {
        let path = tmp();
        let net = "fleet-disable-prepared";
        let prepared = match prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
            .expect("prepare")
        {
            EnrollmentPreparation::Fresh(value) => value,
            EnrollmentPreparation::Existing(_) => panic!("first prepare was not fresh"),
        };
        let transaction_id = prepared.transaction_id().to_owned();
        let material = prepared.enrolled().clone();
        let secret = BASE32_NOPAD
            .decode(material.secret_b32.as_bytes())
            .expect("prepared secret is base32");
        let totp = totp_at(&secret, now_unix());
        assert!(
            disable_at(&path, net, &totp).is_err(),
            "a valid TOTP must not turn Prepared into Absent"
        );
        assert!(matches!(
            enrollment_transaction_at(&path, net, &transaction_id)
                .expect("query after prepared TOTP refusal"),
            EnrollmentTransaction::Prepared(_)
        ));

        let recovery_code = material.recovery_codes[0].clone();
        assert!(
            disable_at(&path, net, &recovery_code).is_err(),
            "a valid recovery code must not turn Prepared into Absent"
        );
        drop(prepared);

        let recovered = match prepare_or_recover_provisional_enroll_at(&path, net, "other-device")
            .expect("recover after disable refusals")
        {
            EnrollmentPreparation::Existing(value) => value,
            EnrollmentPreparation::Fresh(_) => panic!("disable refusal rotated Prepared"),
        };
        assert_eq!(recovered.transaction_id(), transaction_id);
        assert_eq!(recovered.enrolled().secret_b32, material.secret_b32);
        assert_eq!(recovered.enrolled().otpauth_uri, material.otpauth_uri);
        assert_eq!(recovered.enrolled().recovery_codes, material.recovery_codes);
        assert_eq!(
            recovered.abort().expect("explicit abort"),
            EnrollmentSettlementResult::Absent
        );

        let successor = match prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
            .expect("successor prepare after explicit abort")
        {
            EnrollmentPreparation::Fresh(value) => value,
            EnrollmentPreparation::Existing(_) => panic!("explicit abort did not clear Prepared"),
        };
        assert_ne!(successor.transaction_id(), transaction_id);
        successor.abort().expect("clean successor");
        let _ = std::fs::remove_file(&path);
    }

    /// Explicit Abort, rather than handle drop or lease death, permits a fresh
    /// successor transaction and does not reuse the old transaction identity.
    #[test]
    fn v4_r2_prepare_explicit_abort_permits_fresh_successor() {
        let path = tmp();
        let net = "fleet-prepare-abort";
        let first = match prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
            .expect("first prepare")
        {
            EnrollmentPreparation::Fresh(value) => value,
            EnrollmentPreparation::Existing(_) => panic!("first prepare was not fresh"),
        };
        let first_transaction = first.transaction_id().to_owned();
        first.abort().expect("explicit abort");

        let successor = match prepare_or_recover_provisional_enroll_at(&path, net, "laptop")
            .expect("successor prepare")
        {
            EnrollmentPreparation::Fresh(value) => value,
            EnrollmentPreparation::Existing(_) => panic!("aborted record was recovered"),
        };
        assert_ne!(successor.transaction_id(), first_transaction);
        successor.abort().expect("clean successor");

        let _ = std::fs::remove_file(&path);
    }

    /// A prepared enrollment remains durable when its handle is dropped, and an
    /// explicit abort cannot remove a successor that arrives later.
    ///
    /// The lock is installed *before* the response, so a response that is
    /// refused or whose socket ended still leaves an exact transaction that a
    /// later process can query and redeliver. Only an explicit abort removes
    /// it.
    ///
    /// The stale-transaction half is driven end to end: the first attempt is
    /// explicitly aborted, a second enrollment is installed and committed, and
    /// a late abort for the first exact identity cannot affect it.
    #[test]
    fn v4_r2_prepared_enrollment_redelivers_and_explicit_abort_preserves_successor() {
        let path = tmp();
        let net = "fleet-unhanded";

        let unhanded = install_provisional_enroll_at(&path, net, "laptop").expect("install");
        assert_eq!(
            unhanded.enrolled().recovery_codes.len(),
            RECOVERY_CODES,
            "the caller is given the whole validated material before exact Commit"
        );
        assert_eq!(unhanded.network_id(), net);
        let transaction_id = unhanded.transaction_id().to_owned();
        let original_material = unhanded.enrolled().clone();
        assert!(
            is_enrolled_at(&path, net),
            "non-vacuity: the lock is on disk before anything is answered, which \
             is the ordering the whole repair rests on"
        );

        // The response never reached `Sent`; dropping the local handle does not
        // implicitly abort the durable transaction.
        drop(unhanded);
        assert!(
            is_enrolled_at(&path, net),
            "a dropped handle leaves a prepared lock for redelivery"
        );
        assert!(
            require_at(&path, net, None).is_err(),
            "the prepared lock remains an effective custody gate"
        );
        let recovered = prepared_enrollments_at(&path).expect("recover prepared material");
        assert_eq!(recovered.len(), 1);
        let recovered = recovered.into_iter().next().expect("prepared transaction");
        assert_eq!(recovered.transaction_id(), transaction_id);
        assert_eq!(
            recovered.enrolled().secret_b32,
            original_material.secret_b32
        );
        assert_eq!(
            recovered.enrolled().recovery_codes,
            original_material.recovery_codes
        );
        recovered
            .abort()
            .expect("explicitly abort unhanded transaction");
        assert!(!is_enrolled_at(&path, net));

        // A first attempt that *did* answer, and is then explicitly surrendered
        // in the ordinary way, lets a successor exist.
        let first = install_provisional_enroll_at(&path, net, "laptop").expect("install again");
        let first_transaction = first.transaction_id().to_owned();
        let stale_first = match enrollment_transaction_at(&path, net, &first_transaction)
            .expect("query first prepared transaction")
        {
            EnrollmentTransaction::Prepared(value) => value,
            other => panic!("expected first Prepared transaction, got {other:?}"),
        };
        first.abort().expect("explicitly abort first transaction");

        let successor = install_provisional_enroll_at(&path, net, "laptop").expect("the successor");
        let successor_material = successor.enrolled().clone();
        successor.commit().expect("commit successor enrollment");
        assert!(
            is_enrolled_at(&path, net),
            "non-vacuity: there is a successor lock for a stale undo to threaten"
        );

        // Settling the now-stale recovered handle cannot affect the successor.
        assert!(
            is_enrolled_at(&path, net),
            "the successor's lock is not the first attempt's to remove"
        );
        let successor_secret = BASE32_NOPAD
            .decode(successor_material.secret_b32.as_bytes())
            .expect("the successor secret is base32");
        assert!(
            require_at(&path, net, Some(&totp_at(&successor_secret, now_unix()))).is_ok(),
            "and it is still satisfied by the secret its own caller was shown"
        );

        assert_eq!(
            stale_first.abort().expect("late exact abort is idempotent"),
            EnrollmentSettlementResult::Absent,
            "a stale late abort reports Absent without touching the successor"
        );
        assert!(is_enrolled_at(&path, net));

        let _ = std::fs::remove_file(&path);
    }

    /// A prepared record remains after owner-lease/process death; the lease and
    /// nonce are not an implicit abort authority.
    #[test]
    fn v4_r2_hard_death_recovery_preserves_prepared_transaction() {
        let path = tmp();
        let net = "fleet-hard-death";

        let live = install_provisional_enroll_at(&path, net, "laptop").expect("install");
        assert_eq!(
            recover_provisional_at(&path).expect("live recovery"),
            0,
            "startup recovery must not steal a handoff owned by this process"
        );

        // A different nonce alone is not evidence of a dead owner: the live
        // kernel lease remains authoritative and must preserve this record.
        let mut store = load_at(&path).expect("read installed record");
        store
            .networks
            .get_mut(net)
            .expect("installed network")
            .process_nonce = "dead-process-incarnation".into();
        save_at(&path, &store).expect("persist crash snapshot");

        assert_eq!(
            recover_provisional_at(&path).expect("live recovery"),
            0,
            "the next recovery pass cannot steal a record with a live lease"
        );
        assert!(is_enrolled_at(&path, net));
        drop(live);
        let _ = std::fs::remove_file(&path);
    }

    /// Concurrent exact terminal requests report the durable winner rather
    /// than each claiming its own requested transition. The writer lease and
    /// serialized guard make the race a pair of whole transactions: commit
    /// wins and both observe `Committed`, or abort wins and both observe
    /// `Absent`.
    #[test]
    fn v4_r2_concurrent_settlement_reports_actual_durable_winner() {
        let path = tmp();
        let net = "fleet-settlement-race";

        let provisional = install_provisional_enroll_at(&path, net, "laptop").expect("install");
        let transaction_id = provisional.transaction_id().to_owned();
        drop(provisional);

        let prepared = match enrollment_transaction_at(&path, net, &transaction_id)
            .expect("query prepared transaction")
        {
            EnrollmentTransaction::Prepared(prepared) => prepared,
            other => panic!("expected prepared transaction, got {other:?}"),
        };
        let competing = match enrollment_transaction_at(&path, net, &transaction_id)
            .expect("query competing prepared transaction")
        {
            EnrollmentTransaction::Prepared(prepared) => prepared,
            other => panic!("expected competing prepared transaction, got {other:?}"),
        };

        let barrier = std::sync::Arc::new(std::sync::Barrier::new(2));
        let commit_barrier = std::sync::Arc::clone(&barrier);
        let abort_barrier = std::sync::Arc::clone(&barrier);
        let commit_thread = std::thread::spawn(move || {
            commit_barrier.wait();
            prepared.commit()
        });
        let abort_thread = std::thread::spawn(move || {
            abort_barrier.wait();
            competing.abort()
        });
        let commit_state = commit_thread
            .join()
            .expect("commit settlement does not panic")
            .expect("commit settlement succeeds");
        let abort_state = abort_thread
            .join()
            .expect("abort settlement does not panic")
            .expect("abort settlement succeeds");

        assert_eq!(
            commit_state, abort_state,
            "both callers observe the same actual durable winner"
        );
        assert!(matches!(
            commit_state,
            EnrollmentSettlementResult::Committed | EnrollmentSettlementResult::Absent
        ));
        let final_state = enrollment_transaction_at(&path, net, &transaction_id)
            .expect("query final settlement state");
        match (commit_state, final_state) {
            (EnrollmentSettlementResult::Committed, EnrollmentTransaction::Committed)
            | (EnrollmentSettlementResult::Absent, EnrollmentTransaction::Absent) => {}
            (state, durable) => panic!("settlement result {state:?} disagrees with {durable:?}"),
        }

        let _ = std::fs::remove_file(&path);
    }

    /// Pre-V4 custody records are refused instead of being interpreted as a
    /// committed or provisional enrollment. The explicit phase is part of the
    /// current storage shape, and the retired provisional marker is unknown.
    #[test]
    fn v4_r2_pre_v4_custody_shapes_are_refused() {
        let missing_phase = serde_json::json!({
            "networks": {
                "legacy": {
                    "secret_b32": "JBSWY3DPEHPK3PXP",
                    "recovery_hashes": [],
                    "created_at": 1,
                    "transaction_id": "legacy-transaction",
                    "prepared_recovery_codes": [],
                    "prepared_account": "legacy",
                    "process_nonce": ""
                }
            }
        });
        assert!(
            serde_json::from_value::<CustodyStore>(missing_phase).is_err(),
            "a record without the explicit current phase must fail closed"
        );

        let provisional_marker = serde_json::json!({
            "networks": {
                "legacy": {
                    "secret_b32": "JBSWY3DPEHPK3PXP",
                    "recovery_hashes": [],
                    "created_at": 1,
                    "phase": "Prepared",
                    "transaction_id": "legacy-transaction",
                    "prepared_recovery_codes": ["abcde-fghij"],
                    "prepared_account": "legacy",
                    "provisional": true,
                    "process_nonce": ""
                }
            }
        });
        assert!(
            serde_json::from_value::<CustodyStore>(provisional_marker).is_err(),
            "the retired provisional marker must fail closed"
        );
    }

    /// The commit side of the restart transaction is just as important as
    /// rollback: an atomic handoff leaves a committed record that a later
    /// recovery pass preserves, while clearing the re-delivery material.
    #[test]
    fn v4_r2_committed_handoff_survives_restart_recovery() {
        let path = tmp();
        let net = "fleet-committed-restart";

        let provisional = install_provisional_enroll_at(&path, net, "phone").expect("install");
        let transaction_id = provisional.transaction_id().to_owned();
        provisional.commit().expect("commit handoff");
        let store = load_at(&path).expect("read committed record");
        let enrollment = store.networks.get(net).expect("committed network");
        assert_eq!(enrollment.phase, EnrollmentPhase::Committed);
        assert!(enrollment.process_nonce.is_empty());
        assert!(enrollment.prepared_recovery_codes.is_empty());
        assert!(enrollment.prepared_account.is_empty());
        assert!(matches!(
            enrollment_transaction_at(&path, net, &transaction_id).expect("query committed"),
            EnrollmentTransaction::Committed
        ));
        assert!(matches!(
            enrollment_transaction_at(&path, net, "stale-transaction").expect("query stale"),
            EnrollmentTransaction::Absent
        ));
        assert_eq!(
            recover_provisional_at(&path).expect("restart recovery"),
            0,
            "committed custody is not provisional recovery input"
        );
        assert!(is_enrolled_at(&path, net));
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn disable_requires_a_valid_code_then_clears_the_lock() {
        let path = tmp();
        let net = "fleet-abc";
        let enrolled = enroll_at(&path, net, "phone").expect("enroll");
        let secret = BASE32_NOPAD.decode(enrolled.secret_b32.as_bytes()).unwrap();

        // Can't disable without satisfying the lock.
        assert!(disable_at(&path, net, "000000").is_err());
        assert!(is_enrolled_at(&path, net));

        // With a valid code it clears, and the gate is a no-op again.
        let code = totp_at(&secret, now_unix());
        assert!(disable_at(&path, net, &code).is_ok());
        assert!(!is_enrolled_at(&path, net));
        assert!(require_at(&path, net, None).is_ok());

        let _ = std::fs::remove_file(&path);
    }

    // Test-only mirror of `is_enrolled` against an explicit path.
    fn is_enrolled_at(path: &Path, network_id: &str) -> bool {
        load_at(path)
            .map(|s| s.networks.contains_key(network_id))
            .unwrap_or(false)
    }
}
