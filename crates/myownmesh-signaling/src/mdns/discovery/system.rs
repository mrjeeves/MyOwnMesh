//! The system discovery backend: registration + browsing through the
//! platform's own DNS-SD daemon via the stable `dnssd` C API — mDNSResponder
//! on Apple platforms (where the symbols live in libSystem), Avahi's
//! `libdns_sd` compat shim on Linux (where we link `dns_sd`).
//!
//! Why this exists: iOS 14+ blocks raw multicast/broadcast sockets unless the
//! app holds the Apple-granted `com.apple.developer.networking.multicast`
//! entitlement, which rules out the pure-Rust [`super::embedded`] backend
//! there. mDNSResponder performs the multicast on the app's behalf; talking to
//! it needs no entitlement — only the `NSBonjourServices` /
//! `NSLocalNetworkUsageDescription` Info.plist keys. Local claiming on an
//! iPhone rides this.
//!
//! ## Threading model
//!
//! Every `DNSServiceRef` is owned by **exactly one thread**, which polls its
//! socket fd and runs `DNSServiceProcessResult` (callbacks fire synchronously
//! inside that call, on that thread) until it's done or the backend shuts
//! down, then deallocates the ref. Commands (`unregister` / `shutdown`) only
//! flip atomics those threads observe on their next poll tick (≤500 ms).
//! Deallocating a registered ref is what sends the mDNS goodbye.
//!
//! Long-lived refs (the browse, the registration) each get a thread for the
//! driver's lifetime; per-instance resolve + address lookups are short-lived
//! threads that exit once the answer or owner-selected query deadline arrives.

use std::collections::HashMap;
use std::ffi::{c_char, c_void, CStr, CString};
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{debug, trace, warn};

use super::{
    DiscoveryConfig, DiscoveryEvent, DiscoveryLimits, ResolveCompletion, ResolveHint, ResolveLease,
    ResolveOwnership, MAX_DNS_NAME_BYTES, MAX_TXT_KEY_BYTES, MAX_TXT_VALUE_BYTES,
};
#[cfg(test)]
use crate::task_custodian::DedicatedTaskCustodian;
use crate::task_custodian::{CustodianReservation, TaskCustodian};
use crate::Error;

/// Poll cadence used only to re-check stop/deadline state around the
/// dependency-owned DNSServiceRef socket. It is a liveness implementation
/// bound, not a discovery workload or queue capacity; query duration remains
/// owner-selected through `MdnsTimingProfile::query_deadline`.
const DNS_SD_POLL_TIMEOUT_MS: i32 = 500;
/// DNS-SD encodes each TXT string with one octet of length. Keep this wire
/// fact separate from the application's value/parser guards in `super`.
const DNS_SD_TXT_STRING_MAX_BYTES: usize = u8::MAX as usize;

// ---- the dnssd C API (dns_sd.h) ----------------------------------------

type DNSServiceRef = *mut c_void;
type DNSServiceFlags = u32;
type DNSServiceErrorType = i32;

const NO_ERROR: DNSServiceErrorType = 0;
const FLAG_MORE_COMING: DNSServiceFlags = 0x1;
const FLAG_ADD: DNSServiceFlags = 0x2;
/// "Any interface" for registration/browse.
const INTERFACE_ANY: u32 = 0;

type RegisterReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type BrowseReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type ResolveReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
type QueryRecordReply = unsafe extern "C" fn(
    DNSServiceRef,
    DNSServiceFlags,
    u32,
    DNSServiceErrorType,
    *const c_char,
    u16,
    u16,
    u16,
    *const c_void,
    u32,
    *mut c_void,
);

/// DNS A record / IN class, for the address query.
const RR_TYPE_A: u16 = 1;
const RR_CLASS_IN: u16 = 1;
// Retain one generation for each discovered peer that the mDNS driver can
// retain. This keeps the system backend's exact-key epoch table bounded by
// the configured peer-state ceiling rather than growing with stale callbacks.
#[cfg_attr(not(target_vendor = "apple"), link(name = "dns_sd"))]
extern "C" {
    fn DNSServiceRegister(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port_network_order: u16,
        txt_len: u16,
        txt_record: *const c_void,
        callback: Option<RegisterReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceBrowse(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        regtype: *const c_char,
        domain: *const c_char,
        callback: Option<BrowseReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceResolve(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        callback: Option<ResolveReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    // NB: the address lookup rides DNSServiceQueryRecord (an A query) rather
    // than the more obvious DNSServiceGetAddrInfo — Avahi's Bonjour compat
    // shim never implemented the latter, and QueryRecord is supported by
    // both mDNSResponder and Avahi.
    fn DNSServiceQueryRecord(
        sd_ref: *mut DNSServiceRef,
        flags: DNSServiceFlags,
        interface_index: u32,
        fullname: *const c_char,
        rr_type: u16,
        rr_class: u16,
        callback: Option<QueryRecordReply>,
        context: *mut c_void,
    ) -> DNSServiceErrorType;
    fn DNSServiceRefSockFD(sd_ref: DNSServiceRef) -> i32;
    fn DNSServiceProcessResult(sd_ref: DNSServiceRef) -> DNSServiceErrorType;
    fn DNSServiceRefDeallocate(sd_ref: DNSServiceRef);
}

/// A `DNSServiceRef` being handed to the thread that will own it.
struct SendRef(DNSServiceRef);
// SAFETY: the ref is created on one thread and then used exclusively by the
// receiving thread (poll + ProcessResult + Deallocate); dnssd refs have no
// thread affinity, only a no-concurrent-use rule, which single ownership
// guarantees.
unsafe impl Send for SendRef {}

// ---- TXT record codec ---------------------------------------------------

/// Encode DNS TXT rdata: length-prefixed `key=value` strings.
fn encode_txt(entries: &[(String, String)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (k, v) in entries {
        let entry = format!("{k}={v}");
        let bytes = entry.as_bytes();
        // A TXT string caps at 255 bytes; our entries (version, room hash,
        // device pubkey) are all far below it. Oversize would be a programmer
        // error — truncate defensively rather than emit corrupt rdata.
        let len = bytes.len().min(DNS_SD_TXT_STRING_MAX_BYTES);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out
}

/// Parse DNS TXT rdata into a key→value map (a flag entry maps to "").
fn parse_txt(rdata: &[u8], max_bytes: usize, max_entries: usize) -> HashMap<String, String> {
    if rdata.len() > max_bytes {
        return HashMap::new();
    }
    let mut out = HashMap::new();
    let mut p = 0usize;
    let mut entries = 0usize;
    while p < rdata.len() {
        entries += 1;
        if entries > max_entries {
            return HashMap::new();
        }
        let len = rdata[p] as usize;
        p += 1;
        let end = (p + len).min(rdata.len());
        if let Ok(s) = std::str::from_utf8(&rdata[p..end]) {
            match s.split_once('=') {
                Some((k, v)) if k.len() <= MAX_TXT_KEY_BYTES && v.len() <= MAX_TXT_VALUE_BYTES => {
                    out.insert(k.to_string(), v.to_string())
                }
                None if !s.is_empty() && s.len() <= MAX_TXT_KEY_BYTES => {
                    out.insert(s.to_string(), String::new())
                }
                None => None,
                Some(_) => None,
            };
        }
        p = end;
    }
    out
}

/// `_myownmesh._tcp.local.` → (`_myownmesh._tcp`, default domain). The dnssd
/// API takes the regtype and domain as separate arguments.
fn regtype_of(service_type: &str) -> String {
    service_type
        .trim_end_matches('.')
        .trim_end_matches(".local")
        .to_string()
}

// ---- the ref-processing loop --------------------------------------------

/// Poll `sd_ref`'s fd and run `DNSServiceProcessResult` until `until` says
/// stop, an error surfaces, or (if set) `deadline` passes. Callbacks fire
/// synchronously inside ProcessResult, on this thread.
///
/// SAFETY: caller guarantees exclusive ownership of `sd_ref` and that any
/// callback context outlives the loop.
unsafe fn process_ref(sd_ref: DNSServiceRef, until: impl Fn() -> bool, deadline: Option<Instant>) {
    let fd = DNSServiceRefSockFD(sd_ref);
    if fd < 0 {
        return;
    }
    loop {
        if until() {
            return;
        }
        if let Some(d) = deadline {
            if Instant::now() >= d {
                return;
            }
        }
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let rc = libc::poll(&mut pfd, 1, DNS_SD_POLL_TIMEOUT_MS);
        if rc < 0 {
            return;
        }
        if rc == 0 {
            continue; // tick: re-check until()/deadline
        }
        // `libc` exposes the error-bit constants on POSIX targets but not on
        // Windows.  Any nonzero result is handed to the DNS-SD API, which
        // reports readiness and terminal/error states through its return code;
        // this keeps the same fail-closed behavior without target-specific
        // constants.
        if pfd.revents == 0 {
            continue;
        }
        if DNSServiceProcessResult(sd_ref) != NO_ERROR {
            return;
        }
    }
}

// ---- the backend ---------------------------------------------------------

struct Inner {
    regtype: CString,
    instance: CString,
    port: u16,
    txt: Vec<u8>,
    stopped: AtomicBool,
    /// The live registration's stop flag, if registered.
    registration: Mutex<Option<Arc<AtomicBool>>>,
    /// Exact service-instance resolve ownership. Duplicate per-interface Adds
    /// coalesce into one pending follow-up, and Removed/shutdown invalidates
    /// the active generation before any late result can be published.
    resolving: ResolveOwnership,
    /// The discovery event generation outlives a completed resolve lease so a
    /// later Removed callback can withdraw the exact Resolved state. Resolve
    /// ownership is deliberately separate: it tracks work, while this table
    /// tracks the published key epoch.
    epochs: EventEpochs,
    /// Serializes browse removals with resolve completion so a removal cannot
    /// withdraw one epoch while a late completion publishes another.
    resolution_fence: Mutex<()>,
    tx: mpsc::Sender<DiscoveryEvent>,
    /// Native workers remain retained until their terminal result is observed;
    /// shutdown joins any that are still live. This keeps callback contexts
    /// and resolve ownership alive only for their owner.
    workers: WorkerRegistry,
    /// Caller-funded custody retained for the complete native-worker
    /// envelope. Native DNS-SD handles are joined by `workers`; this
    /// reservation makes that bounded ownership explicit before the first
    /// native API call or thread spawn and remains held through shutdown.
    _worker_custody: CustodianReservation,
    /// Keep the lifecycle owner alive for the same interval as its
    /// reservation, including callback-held `Inner` references.
    _custodian_owner: Arc<dyn TaskCustodian>,
    query_deadline: Duration,
    discovery_limits: DiscoveryLimits,
}

/// A checked, non-wrapping epoch for each exact DNS-SD service-instance key.
/// The C API's Removed callback carries only the key, so the epoch must remain
/// after a resolve worker completes and must be removed atomically with the
/// exact-key withdrawal.
#[derive(Debug)]
struct EventEpochs {
    current: Mutex<HashMap<String, u64>>,
    next: std::sync::atomic::AtomicU64,
    max_epochs: usize,
}

impl EventEpochs {
    #[cfg(test)]
    fn new() -> Self {
        Self::with_max_epochs(super::DiscoveryLimits::default().max_event_epochs)
    }

    fn with_max_epochs(max_epochs: usize) -> Self {
        Self {
            current: Mutex::new(HashMap::new()),
            next: std::sync::atomic::AtomicU64::new(1),
            max_epochs,
        }
    }

    fn admit(&self, key: &str) -> Option<u64> {
        let mut current = self.current.lock();
        if let Some(&generation) = current.get(key) {
            return Some(generation);
        }
        if current.len() >= self.max_epochs {
            return None;
        }
        let generation = next_epoch(&self.next)?;
        current.insert(key.to_owned(), generation);
        Some(generation)
    }

    fn current(&self, key: &str) -> Option<u64> {
        self.current.lock().get(key).copied()
    }

    fn remove_if_current(&self, key: &str, generation: u64) -> bool {
        let mut current = self.current.lock();
        if current.get(key).copied() == Some(generation) {
            current.remove(key);
            true
        } else {
            false
        }
    }

    fn clear(&self) {
        self.current.lock().clear();
    }
}

/// Own native worker handles until their terminal result has been observed.
/// Extraction happens under the mutex; joining always happens after releasing
/// it, so a worker cannot deadlock against a callback trying to register a
/// successor worker.
#[derive(Debug)]
struct WorkerRegistry {
    workers: Mutex<Vec<std::thread::JoinHandle<()>>>,
    max_workers: usize,
}

impl WorkerRegistry {
    fn with_capacity(max_workers: usize) -> Self {
        Self {
            workers: Mutex::new(Vec::with_capacity(max_workers)),
            max_workers,
        }
    }

    fn push(&self, worker: std::thread::JoinHandle<()>) -> Result<(), std::thread::JoinHandle<()>> {
        // A terminal handle still occupies its reserved slot until its result
        // is observed. Reap those handles before deciding that the registry is
        // full; otherwise a finished worker can permanently refuse its exact
        // successor. Extraction keeps all joins outside the mutex.
        let (result, finished) = {
            let mut workers = self.workers.lock();
            let mut finished = Vec::new();
            let mut live = Vec::with_capacity(self.max_workers);
            for worker in workers.drain(..) {
                if worker.is_finished() {
                    finished.push(worker);
                } else {
                    live.push(worker);
                }
            }
            *workers = live;
            let result = if workers.len() >= self.max_workers {
                Err(worker)
            } else {
                workers.push(worker);
                Ok(())
            };
            (result, finished)
        };
        for worker in finished {
            observe_worker(worker);
        }
        result
    }

    fn reap_finished(&self) {
        let finished = {
            let mut workers = self.workers.lock();
            let mut finished = Vec::new();
            let mut live = Vec::with_capacity(self.max_workers);
            for worker in workers.drain(..) {
                if worker.is_finished() {
                    finished.push(worker);
                } else {
                    live.push(worker);
                }
            }
            *workers = live;
            finished
        };
        for worker in finished {
            observe_worker(worker);
        }
    }

    fn join_all(&self) {
        loop {
            let workers = std::mem::take(&mut *self.workers.lock());
            if workers.is_empty() {
                return;
            }
            for worker in workers {
                observe_worker(worker);
            }
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.workers.lock().len()
    }
}

fn observe_worker(worker: std::thread::JoinHandle<()>) {
    if worker.join().is_err() {
        warn!("system dns-sd worker terminated by panic");
    }
}

/// Allocate an epoch without ever wrapping or reusing an exhausted value.
/// Zero is the permanent exhausted sentinel.
fn next_epoch(counter: &std::sync::atomic::AtomicU64) -> Option<u64> {
    counter
        .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
            if value == 0 {
                None
            } else if value == u64::MAX {
                Some(0)
            } else {
                Some(value + 1)
            }
        })
        .ok()
}

pub struct Discovery {
    inner: Arc<Inner>,
}

impl Discovery {
    /// Connect to the system daemon, start browsing, and hand back the event
    /// stream. Fails fast when the daemon is unreachable (no mDNSResponder /
    /// Avahi) — callers fall back to their other signaling transports.
    #[cfg(test)]
    pub fn start(cfg: &DiscoveryConfig) -> crate::Result<(Self, mpsc::Receiver<DiscoveryEvent>)> {
        let worker_capacity = cfg
            .limits
            .max_resolve_owners
            .checked_add(2)
            .ok_or_else(|| Error::Other("system worker capacity overflow".into()))?;
        let owner = DedicatedTaskCustodian::new(worker_capacity)
            .map_err(|error| Error::Other(format!("system custodian unavailable: {error:?}")))?;
        Self::start_with_custodian(cfg, owner)
    }

    pub fn start_with_custodian(
        cfg: &DiscoveryConfig,
        custodian_owner: Arc<dyn TaskCustodian>,
    ) -> crate::Result<(Self, mpsc::Receiver<DiscoveryEvent>)> {
        if !cfg.validate() || !cfg.limits.validate() || !cfg.timing.validate() {
            return Err(Error::Other("invalid discovery configuration".into()));
        }
        cfg.limits
            .checked_residency(crate::mdns::discovery::DiscoveryBackend::System)
            .map_err(|error| {
                Error::Other(format!("invalid system discovery residency: {error}"))
            })?;
        // The browse and registration workers are permanent; at most R
        // resolve workers may be admitted. Reserve the complete handle
        // registry before touching the native DNS-SD API so every spawned
        // worker has a bounded custody slot.
        let worker_capacity = cfg
            .limits
            .max_resolve_owners
            .checked_add(2)
            .ok_or_else(|| Error::Other("system worker capacity overflow".into()))?;
        let worker_custody = custodian_owner
            .reserve(worker_capacity)
            .map_err(|error| Error::Other(format!("system worker custody exhausted: {error:?}")))?;
        let regtype = CString::new(regtype_of(&cfg.service_type))
            .map_err(|e| Error::Other(format!("service type: {e}")))?;
        let instance = CString::new(cfg.instance.as_str())
            .map_err(|e| Error::Other(format!("instance name: {e}")))?;

        let (tx, rx) = mpsc::channel(cfg.limits.event_capacity);
        let inner = Arc::new(Inner {
            regtype,
            instance,
            port: cfg.port,
            txt: encode_txt(&cfg.txt),
            stopped: AtomicBool::new(false),
            registration: Mutex::new(None),
            resolving: ResolveOwnership::with_max_owners(cfg.limits.max_resolve_owners),
            epochs: EventEpochs::with_max_epochs(cfg.limits.max_event_epochs),
            resolution_fence: Mutex::new(()),
            tx,
            workers: WorkerRegistry::with_capacity(worker_capacity),
            _worker_custody: worker_custody,
            _custodian_owner: custodian_owner,
            query_deadline: cfg.timing.query_deadline,
            discovery_limits: cfg.limits,
        });

        // Browse first (mirrors the embedded backend: never miss resolves
        // racing our own announce). Created here so a daemon-unreachable
        // error surfaces synchronously to the caller.
        let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
        let ctx = Arc::into_raw(inner.clone()) as *mut c_void;
        let err = unsafe {
            DNSServiceBrowse(
                &mut sd_ref,
                0,
                INTERFACE_ANY,
                inner.regtype.as_ptr(),
                std::ptr::null(),
                Some(browse_cb),
                ctx,
            )
        };
        if err != NO_ERROR {
            // Reclaim the context Arc we leaked for the callback.
            unsafe { drop(Arc::from_raw(ctx as *const Inner)) };
            return Err(Error::Other(format!(
                "system dns-sd browse failed (is the mDNS daemon running?): {err}"
            )));
        }

        let browse_inner = inner.clone();
        let browse_ref = SendRef(sd_ref);
        // The callback context crosses into the thread as a plain address;
        // it's the leaked Arc reclaimed at thread exit.
        let ctx_addr = ctx as usize;
        let browse_worker = match std::thread::Builder::new()
            .name("dnssd-browse".into())
            .spawn(move || {
                let browse_ref = browse_ref;
                unsafe {
                    process_ref(
                        browse_ref.0,
                        || browse_inner.stopped.load(Ordering::SeqCst),
                        None,
                    );
                    DNSServiceRefDeallocate(browse_ref.0);
                    // The browse callback's context Arc.
                    drop(Arc::from_raw(ctx_addr as *const Inner));
                }
                trace!("dnssd browse thread exiting");
            }) {
            Ok(worker) => worker,
            Err(e) => {
                unsafe {
                    DNSServiceRefDeallocate(sd_ref);
                    drop(Arc::from_raw(ctx as *const Inner));
                }
                return Err(Error::Other(format!("spawn dnssd browse thread: {e}")));
            }
        };
        if let Err(browse_worker) = inner.workers.push(browse_worker) {
            inner.stopped.store(true, Ordering::Release);
            observe_worker(browse_worker);
            return Err(Error::Other(
                "system worker custody refused the browse worker".into(),
            ));
        }

        Ok((Discovery { inner }, rx))
    }

    /// Attempt (re-)registration — the announce. Idempotent while registered.
    /// `false` = the daemon refused synchronously; the caller's re-announce
    /// tick retries. Name conflicts are auto-renamed by the daemon.
    pub fn register(&self) -> bool {
        let mut slot = self.inner.registration.lock();
        if slot.is_some() {
            return true;
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            return false;
        }
        let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
        let err = unsafe {
            DNSServiceRegister(
                &mut sd_ref,
                0,
                INTERFACE_ANY,
                self.inner.instance.as_ptr(),
                self.inner.regtype.as_ptr(),
                std::ptr::null(), // default domain
                std::ptr::null(), // default host
                self.inner.port.to_be(),
                self.inner.txt.len() as u16,
                self.inner.txt.as_ptr() as *const c_void,
                Some(register_cb),
                std::ptr::null_mut(),
            )
        };
        if err != NO_ERROR {
            debug!("dnssd register failed (will retry): {err}");
            return false;
        }
        if self.inner.stopped.load(Ordering::Acquire) {
            unsafe { DNSServiceRefDeallocate(sd_ref) };
            return false;
        }

        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let global = self.inner.clone();
        let reg_ref = SendRef(sd_ref);
        let spawned = std::thread::Builder::new()
            .name("dnssd-register".into())
            .spawn(move || {
                let reg_ref = reg_ref;
                unsafe {
                    process_ref(
                        reg_ref.0,
                        || {
                            thread_stop.load(Ordering::SeqCst)
                                || global.stopped.load(Ordering::SeqCst)
                        },
                        None,
                    );
                    // Deallocating the registered ref sends the goodbye.
                    DNSServiceRefDeallocate(reg_ref.0);
                }
                trace!("dnssd register thread exiting");
            });
        match spawned {
            Ok(worker) => {
                if self.inner.stopped.load(Ordering::Acquire) {
                    stop.store(true, Ordering::Release);
                    drop(slot);
                    observe_worker(worker);
                    return false;
                }
                // Keep the registration guard until the worker is retained so
                // shutdown cannot drain the registry between the stop check
                // and this insertion.
                if let Err(worker) = self.inner.workers.push(worker) {
                    stop.store(true, Ordering::Release);
                    drop(slot);
                    observe_worker(worker);
                    return false;
                }
                *slot = Some(stop);
                drop(slot);
                self.inner.workers.reap_finished();
                true
            }
            Err(e) => {
                warn!("spawn dnssd register thread: {e}");
                unsafe { DNSServiceRefDeallocate(sd_ref) };
                false
            }
        }
    }

    /// Withdraw the advertisement (the goodbye rides the ref deallocation).
    pub fn unregister(&self) {
        if let Some(stop) = self.inner.registration.lock().take() {
            stop.store(true, Ordering::SeqCst);
        }
    }

    /// Stop everything: the registration (goodbye), the browse, and any
    /// in-flight resolves, within one poll tick.
    pub fn shutdown(&self) {
        self.unregister();
        self.inner.stopped.store(true, Ordering::SeqCst);
        {
            let _resolution_fence = self.inner.resolution_fence.lock();
            self.inner.resolving.shutdown();
            self.inner.epochs.clear();
        }
        // Joining the browse worker first closes the only callback path that
        // can enqueue a new resolve worker. Drain in rounds so a callback
        // racing the first take cannot leave an unjoined worker behind.
        self.inner.workers.join_all();
    }

    /// The system backend owns native worker threads rather than a Tokio pump;
    /// keep the common driver ownership seam explicit.
    pub fn take_task(&mut self) -> Option<tokio::task::JoinHandle<()>> {
        None
    }
}

impl Drop for Discovery {
    fn drop(&mut self) {
        self.shutdown();
    }
}

// ---- callbacks + the per-instance resolve pipeline -----------------------

unsafe extern "C" fn register_cb(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    error: DNSServiceErrorType,
    name: *const c_char,
    _regtype: *const c_char,
    _domain: *const c_char,
    _ctx: *mut c_void,
) {
    if error != NO_ERROR {
        warn!("dnssd registration error: {error}");
    } else if !name.is_null() {
        trace!(
            instance = %CStr::from_ptr(name).to_string_lossy(),
            "dnssd registration confirmed"
        );
    }
}

unsafe extern "C" fn browse_cb(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    service_name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    ctx: *mut c_void,
) {
    if error != NO_ERROR || service_name.is_null() || regtype.is_null() || domain.is_null() {
        return;
    }
    // Borrow the context Arc without consuming it (the browse thread owns the
    // strong count and reclaims it at exit).
    let inner = &*(ctx as *const Inner);
    let Some(name_bytes) = bounded_cstr(service_name, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Some(regtype_bytes) = bounded_cstr(regtype, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Some(domain_bytes) = bounded_cstr(domain, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Ok(name) = String::from_utf8(name_bytes.to_vec()) else {
        return;
    };

    if flags & FLAG_ADD != 0 {
        let _resolution_fence = inner.resolution_fence.lock();
        // Our own advertisement echoes back; wire::parse_advert drops it by
        // TXT peer id downstream, but skipping the resolve early saves a
        // thread + query per announce.
        if let Ok(ours) = inner.instance.to_str() {
            if name == ours {
                return;
            }
        }
        let lease = match inner.resolving.admit(name) {
            ResolveHint::Started(lease) => lease,
            ResolveHint::Coalesced => return,
            ResolveHint::Refused => {
                debug!("mdns resolve hint refused or shutdown");
                return;
            }
        };
        let name = lease.instance().to_owned();
        let Some(event_generation) = inner.epochs.admit(&name) else {
            let _ = lease.cancel();
            return;
        };
        let epoch_key = name.clone();
        let (Ok(regtype), Ok(domain)) = (
            String::from_utf8(regtype_bytes.to_vec()),
            String::from_utf8(domain_bytes.to_vec()),
        ) else {
            let _ = lease.cancel();
            inner.epochs.remove_if_current(&name, event_generation);
            return;
        };
        let inner = {
            // A real clone for the resolve thread to hold.
            Arc::increment_strong_count(ctx as *const Inner);
            Arc::from_raw(ctx as *const Inner)
        };
        let spawn_result = std::thread::Builder::new()
            .name("dnssd-resolve".into())
            .spawn(move || {
                run_resolve(
                    inner,
                    name,
                    regtype,
                    domain,
                    interface_index,
                    lease,
                    event_generation,
                )
            });
        match spawn_result {
            Ok(worker) => {
                let callback_inner = &*(ctx as *const Inner);
                if let Err(worker) = callback_inner.workers.push(worker) {
                    warn!("system worker custody refused a resolve worker");
                    callback_inner.resolving.cancel(&epoch_key);
                    callback_inner
                        .epochs
                        .remove_if_current(&epoch_key, event_generation);
                    // The callback holds the publication fence. Release it
                    // before joining so a resolve worker that already entered
                    // its handoff cannot wait on the same fence forever.
                    drop(_resolution_fence);
                    observe_worker(worker);
                    return;
                }
                callback_inner.workers.reap_finished();
            }
            Err(_) => {
                warn!("dnssd resolve thread failed to spawn");
                (&*(ctx as *const Inner))
                    .epochs
                    .remove_if_current(&epoch_key, event_generation);
            }
        }
        // Keep publication under the same fence as admission. Shutdown takes
        // this fence before draining workers, so it cannot observe the epoch
        // cleared while the corresponding JoinHandle is still unpublished.
        drop(_resolution_fence);
    } else {
        let generation = {
            let _resolution_fence = inner.resolution_fence.lock();
            retire_removed_generation(&inner.resolving, &inner.epochs, &name)
        };
        if let Some(generation) = generation {
            // Cancel the exact owner before trying to publish the withdrawal.
            // A full consumer queue must not keep a resolved worker current;
            // the worker will observe this stale generation and dispose its
            // retained event and lease.  The withdrawal itself is best effort
            // at this bounded callback boundary, just as before.
            if let Ok(queue_slot) = inner.tx.try_reserve() {
                publish_removed(queue_slot, generation, name);
            }
        }
    }
}

/// Publish a withdrawal using the permit admitted by the callback. Keeping
/// this as a consuming helper makes the one-reservation rule explicit for the
/// system backend's capacity-one path.
fn publish_removed(queue_slot: mpsc::Permit<'_, DiscoveryEvent>, generation: u64, key: String) {
    let _ = queue_slot.send(DiscoveryEvent::Removed { generation, key });
}

/// Retire an exact backend key before attempting to enqueue its withdrawal.
/// This ordering lets a full event stream stale a resolver immediately while
/// leaving the already-admitted withdrawal to the bounded queue boundary.
fn retire_removed_generation(
    resolving: &ResolveOwnership,
    epochs: &EventEpochs,
    key: &str,
) -> Option<u64> {
    resolving.cancel(key);
    let generation = epochs.current(key);
    if let Some(generation) = generation {
        epochs.remove_if_current(key, generation);
    }
    generation
}

/// The result of trying to hand one resolved event to the bounded discovery
/// stream.  On a full stream the event is returned intact so the resolver can
/// keep it beside its exact [`ResolveLease`]; it is never silently dropped.
#[derive(Debug)]
enum ResolvedHandoff {
    Full(DiscoveryEvent),
    Closed(DiscoveryEvent),
}

/// Try one nonblocking resolved-event handoff.  The caller owns the returned
/// event on both refusal paths and therefore also owns the decision to retry,
/// cancel a stale generation, or release it after the stream is closed.
fn try_publish_resolved(
    sender: &mpsc::Sender<DiscoveryEvent>,
    event: DiscoveryEvent,
) -> std::result::Result<(), ResolvedHandoff> {
    match sender.try_reserve() {
        Ok(permit) => {
            permit.send(event);
            Ok(())
        }
        Err(mpsc::error::TrySendError::Full(())) => Err(ResolvedHandoff::Full(event)),
        Err(mpsc::error::TrySendError::Closed(())) => Err(ResolvedHandoff::Closed(event)),
    }
}

/// Borrow a NUL-terminated C string only after proving its bound. This keeps
/// callbacks from cloning attacker-controlled names before resolve ownership
/// and its bounded queue slot have been admitted.
unsafe fn bounded_cstr<'a>(ptr: *const c_char, max: usize) -> Option<&'a [u8]> {
    if ptr.is_null() {
        return None;
    }
    for len in 0..=max {
        if *ptr.add(len) == 0 {
            return Some(std::slice::from_raw_parts(ptr.cast::<u8>(), len));
        }
    }
    None
}

/// One resolved SRV+TXT answer, filled by `resolve_cb`.
#[derive(Default)]
struct ResolveOut {
    done: bool,
    host: Option<String>,
    port: u16,
    txt: HashMap<String, String>,
    interface_index: u32,
    max_txt_bytes: usize,
    max_txt_entries: usize,
}

unsafe extern "C" fn resolve_cb(
    _sd_ref: DNSServiceRef,
    _flags: DNSServiceFlags,
    interface_index: u32,
    error: DNSServiceErrorType,
    _fullname: *const c_char,
    host_target: *const c_char,
    port_network_order: u16,
    txt_len: u16,
    txt_record: *const u8,
    ctx: *mut c_void,
) {
    let out = &mut *(ctx as *mut ResolveOut);
    out.done = true;
    if error != NO_ERROR || host_target.is_null() {
        return;
    }
    let Some(host_bytes) = bounded_cstr(host_target, MAX_DNS_NAME_BYTES) else {
        return;
    };
    let Ok(host) = String::from_utf8(host_bytes.to_vec()) else {
        return;
    };
    out.host = Some(host);
    out.port = u16::from_be(port_network_order);
    out.interface_index = interface_index;
    if !txt_record.is_null() && txt_len > 0 && txt_len as usize <= out.max_txt_bytes {
        out.txt = parse_txt(
            std::slice::from_raw_parts(txt_record, txt_len as usize),
            out.max_txt_bytes,
            out.max_txt_entries,
        );
    }
}

/// IPv4 addresses for a resolved host, filled by `addr_cb`.
#[derive(Default)]
struct AddrOut {
    done: bool,
    addrs: Vec<IpAddr>,
    max_addresses: usize,
    overflowed: bool,
}

unsafe extern "C" fn addr_cb(
    _sd_ref: DNSServiceRef,
    flags: DNSServiceFlags,
    _interface_index: u32,
    error: DNSServiceErrorType,
    _fullname: *const c_char,
    rr_type: u16,
    _rr_class: u16,
    rd_len: u16,
    rdata: *const c_void,
    _ttl: u32,
    ctx: *mut c_void,
) {
    let out = &mut *(ctx as *mut AddrOut);
    if error == NO_ERROR
        && flags & FLAG_ADD != 0
        && rr_type == RR_TYPE_A
        && rd_len == 4
        && !rdata.is_null()
    {
        let octets = std::slice::from_raw_parts(rdata as *const u8, 4);
        let ip = IpAddr::V4(Ipv4Addr::new(octets[0], octets[1], octets[2], octets[3]));
        if !out.addrs.contains(&ip) {
            if out.addrs.len() >= out.max_addresses {
                // Do not retain a prefix: callback order must not decide
                // which addresses become authoritative for this resolution.
                out.overflowed = true;
            } else {
                out.addrs.push(ip);
            }
        }
    }
    if flags & FLAG_MORE_COMING == 0 {
        out.done = true;
    }
}

fn run_resolve(
    inner: Arc<Inner>,
    name: String,
    regtype: String,
    domain: String,
    interface_index: u32,
    lease: ResolveLease,
    event_generation: u64,
) {
    let mut lease = Some(lease);
    loop {
        if inner.stopped.load(Ordering::Acquire) {
            return;
        }
        let result = resolve_instance(
            &inner,
            &name,
            &regtype,
            &domain,
            interface_index,
            inner.query_deadline,
        );

        // Keep one exact resolved value beside its active generation until it
        // is delivered.  A full stream is not a terminal outcome: dropping
        // the value and completing the lease here would leave the epoch live
        // while the engine never learns the resolution.  The ownership table
        // still permits only one coalesced follow-up hint for this key.
        let mut pending = result.map(|(addrs, port, txt)| DiscoveryEvent::Resolved {
            generation: event_generation,
            key: name.clone(),
            addrs,
            port,
            txt,
        });
        loop {
            if inner.stopped.load(Ordering::Acquire)
                || inner.epochs.current(&name) != Some(event_generation)
            {
                if let Some(lease) = lease.take() {
                    let _ = lease.cancel();
                }
                inner.epochs.remove_if_current(&name, event_generation);
                return;
            }

            let handoff = {
                let _resolution_fence = inner.resolution_fence.lock();
                if inner.stopped.load(Ordering::Acquire)
                    || inner.epochs.current(&name) != Some(event_generation)
                {
                    None
                } else if let Some(event) = pending.take() {
                    match try_publish_resolved(&inner.tx, event) {
                        Ok(()) => Some(Ok(lease
                            .take()
                            .expect("resolved event handoff owns its lease")
                            .complete())),
                        Err(ResolvedHandoff::Full(event)) => {
                            pending = Some(event);
                            Some(Err(false))
                        }
                        Err(ResolvedHandoff::Closed(event)) => {
                            pending = Some(event);
                            Some(Err(true))
                        }
                    }
                } else {
                    Some(Ok(lease
                        .take()
                        .expect("resolved follow-up owns its lease")
                        .complete()))
                }
            };

            let Some(handoff) = handoff else {
                if let Some(lease) = lease.take() {
                    let _ = lease.cancel();
                }
                inner.epochs.remove_if_current(&name, event_generation);
                return;
            };
            match handoff {
                Ok(ResolveCompletion::Finished) => return,
                Ok(ResolveCompletion::Followup(next)) => {
                    lease = Some(next);
                    break;
                }
                Err(true) => {
                    // A closed stream cannot recover; retain the exact event
                    // only long enough to dispose it with its exact lease.
                    discard_closed_resolution(
                        &inner.epochs,
                        &name,
                        event_generation,
                        lease.take().expect("closed resolution owns its lease"),
                        &mut pending,
                    );
                    return;
                }
                Err(false) => {
                    // The existing backend poll cadence bounds shutdown
                    // observation while avoiding a second timer or a busy
                    // retry loop on a full consumer queue.
                    std::thread::sleep(Duration::from_millis(DNS_SD_POLL_TIMEOUT_MS as u64));
                }
            }
        }
    }
}

/// Dispose the exact event and ownership for a terminal closed handoff.
///
/// A full handoff is deliberately not routed here: the event and lease remain
/// owned by the resolver for its bounded retry.  Closed is terminal, so both
/// the event and its exact generation must be settled before the worker exits.
fn discard_closed_resolution(
    epochs: &EventEpochs,
    instance: &str,
    generation: u64,
    lease: ResolveLease,
    pending: &mut Option<DiscoveryEvent>,
) {
    pending.take();
    let _ = lease.cancel();
    epochs.remove_if_current(instance, generation);
}

fn resolve_instance(
    inner: &Arc<Inner>,
    name: &str,
    regtype: &str,
    domain: &str,
    interface_index: u32,
    query_deadline: Duration,
) -> Option<(Vec<IpAddr>, u16, HashMap<String, String>)> {
    let (Ok(c_name), Ok(c_regtype), Ok(c_domain)) = (
        CString::new(name),
        CString::new(regtype),
        CString::new(domain),
    ) else {
        return None;
    };

    // SRV + TXT.
    let mut out = ResolveOut {
        max_txt_bytes: inner.discovery_limits.max_txt_bytes,
        max_txt_entries: inner.discovery_limits.max_txt_entries,
        ..ResolveOut::default()
    };
    let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
    let resolve_deadline = checked_query_deadline(query_deadline)?;
    let err = unsafe {
        DNSServiceResolve(
            &mut sd_ref,
            0,
            interface_index,
            c_name.as_ptr(),
            c_regtype.as_ptr(),
            c_domain.as_ptr(),
            Some(resolve_cb),
            &mut out as *mut ResolveOut as *mut c_void,
        )
    };
    if err != NO_ERROR {
        debug!("dnssd resolve of {name} failed: {err}");
        return None;
    }
    unsafe {
        process_ref(
            sd_ref,
            || out.done || inner.stopped.load(Ordering::SeqCst),
            Some(resolve_deadline),
        );
        DNSServiceRefDeallocate(sd_ref);
    }
    let host = out.host.clone()?;

    // Address lookup — an A query (v4 only, matching the embedded backend:
    // the exchange dials IPv4 addresses; parity keeps the driver identical).
    let c_host = CString::new(host).ok()?;
    let mut addrs = AddrOut {
        max_addresses: inner.discovery_limits.max_resolved_addresses,
        ..AddrOut::default()
    };
    let mut sd_ref: DNSServiceRef = std::ptr::null_mut();
    let address_deadline = checked_query_deadline(query_deadline)?;
    let err = unsafe {
        DNSServiceQueryRecord(
            &mut sd_ref,
            0,
            out.interface_index,
            c_host.as_ptr(),
            RR_TYPE_A,
            RR_CLASS_IN,
            Some(addr_cb),
            &mut addrs as *mut AddrOut as *mut c_void,
        )
    };
    if err != NO_ERROR {
        debug!("dnssd getaddrinfo for {name} failed: {err}");
        return None;
    }
    unsafe {
        process_ref(
            sd_ref,
            || addrs.done || inner.stopped.load(Ordering::SeqCst),
            Some(address_deadline),
        );
        DNSServiceRefDeallocate(sd_ref);
    }

    let addresses = accepted_addresses(addrs)?;
    Some((addresses, out.port, out.txt))
}

fn accepted_addresses(out: AddrOut) -> Option<Vec<IpAddr>> {
    if out.overflowed || out.addrs.is_empty() {
        None
    } else {
        Some(out.addrs)
    }
}

fn checked_query_deadline(query_deadline: Duration) -> Option<Instant> {
    checked_query_deadline_with(query_deadline, |duration| {
        Instant::now().checked_add(duration)
    })
}

fn checked_query_deadline_with<F>(query_deadline: Duration, checked_add: F) -> Option<Instant>
where
    F: FnOnce(Duration) -> Option<Instant>,
{
    checked_add(query_deadline)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_codec_round_trips() {
        let limits = DiscoveryLimits::default();
        let entries = vec![
            ("v".to_string(), "1".to_string()),
            ("room".to_string(), "a".repeat(64)),
            ("peer".to_string(), "b".repeat(52)),
        ];
        let rdata = encode_txt(&entries);
        let parsed = parse_txt(&rdata, limits.max_txt_bytes, limits.max_txt_entries);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed["v"], "1");
        assert_eq!(parsed["room"], "a".repeat(64));
        assert_eq!(parsed["peer"], "b".repeat(52));

        // Flag entries (no '=') parse as empty values; garbage is skipped.
        let parsed = parse_txt(
            &[4, b'f', b'l', b'a', b'g'],
            limits.max_txt_bytes,
            limits.max_txt_entries,
        );
        assert_eq!(parsed["flag"], "");
        // Truncated length prefixes never panic.
        let parsed = parse_txt(&[200, b'x'], limits.max_txt_bytes, limits.max_txt_entries);
        assert!(parsed.is_empty() || parsed.contains_key("x"));
    }

    fn emit_address(out: &mut AddrOut, octets: [u8; 4], more_coming: bool) {
        let flags = FLAG_ADD | if more_coming { FLAG_MORE_COMING } else { 0 };
        unsafe {
            addr_cb(
                std::ptr::null_mut(),
                flags,
                0,
                NO_ERROR,
                std::ptr::null(),
                RR_TYPE_A,
                RR_CLASS_IN,
                4,
                octets.as_ptr().cast(),
                0,
                out as *mut AddrOut as *mut c_void,
            );
        }
    }

    #[test]
    fn address_overflow_refuses_the_whole_resolution_without_publication() {
        let mut out = AddrOut {
            max_addresses: 2,
            ..AddrOut::default()
        };
        emit_address(&mut out, [192, 0, 2, 1], true);
        emit_address(&mut out, [192, 0, 2, 2], true);
        emit_address(&mut out, [192, 0, 2, 3], false);
        assert!(out.overflowed);
        assert_eq!(out.addrs.len(), 2);

        let mut published = 0usize;
        if let Some(addresses) = accepted_addresses(out) {
            published += addresses.len();
        }
        assert_eq!(published, 0, "overflow must not publish a retained prefix");
    }

    #[test]
    fn configured_address_capacity_publishes_all_unique_addresses_at_the_bound() {
        let mut out = AddrOut {
            max_addresses: 3,
            ..AddrOut::default()
        };
        emit_address(&mut out, [192, 0, 2, 1], true);
        emit_address(&mut out, [192, 0, 2, 2], true);
        emit_address(&mut out, [192, 0, 2, 3], false);
        assert!(!out.overflowed);
        let addresses = accepted_addresses(out).expect("exact bound is publishable");
        assert_eq!(addresses.len(), 3);
        assert_eq!(addresses[0], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 1)));
        assert_eq!(addresses[2], IpAddr::V4(Ipv4Addr::new(192, 0, 2, 3)));
    }

    #[test]
    fn regtype_strips_the_local_domain() {
        assert_eq!(regtype_of("_myownmesh._tcp.local."), "_myownmesh._tcp");
        assert_eq!(regtype_of("_myownmesh._tcp"), "_myownmesh._tcp");
    }

    #[test]
    fn checked_query_deadline_gates_backend_call_without_platform_assumptions() {
        let mut backend_called = false;
        let refused =
            checked_query_deadline_with(Duration::from_secs(1), |_| None).and_then(|_| {
                backend_called = true;
                Some(())
            });
        assert!(refused.is_none());
        assert!(
            !backend_called,
            "backend witness must follow checked deadline"
        );

        let mut backend_called = false;
        let accepted = checked_query_deadline(Duration::from_secs(1)).and_then(|_| {
            backend_called = true;
            Some(())
        });
        assert!(accepted.is_some());
        assert!(
            backend_called,
            "representable deadline reaches backend witness"
        );
    }

    #[test]
    fn event_epochs_fence_stale_removal_and_exhaust_without_reuse() {
        let epochs = EventEpochs::new();
        let first = epochs.admit("service-a").expect("first epoch");
        assert_eq!(epochs.current("service-a"), Some(first));
        assert!(!epochs.remove_if_current("service-a", first + 1));
        assert_eq!(epochs.current("service-a"), Some(first));
        assert!(epochs.remove_if_current("service-a", first));

        let successor = epochs.admit("service-a").expect("successor epoch");
        assert_ne!(successor, first);
        assert!(epochs.remove_if_current("service-a", successor));

        epochs.next.store(u64::MAX, Ordering::Release);
        let last = epochs.admit("service-last").expect("final epoch");
        assert_eq!(last, u64::MAX);
        assert!(epochs.remove_if_current("service-last", last));
        assert_eq!(epochs.admit("service-exhausted"), None);
    }

    #[test]
    fn event_epochs_enforce_the_configured_non_default_cap() {
        let epochs = EventEpochs::with_max_epochs(2);
        assert!(epochs.admit("service-1").is_some());
        assert!(epochs.admit("service-2").is_some());
        assert_eq!(epochs.admit("service-3"), None);
        let first = epochs.current("service-1").expect("first epoch");
        assert!(epochs.remove_if_current("service-1", first));
        assert!(epochs.admit("service-3").is_some());
    }

    #[test]
    fn event_epoch_capacity_one_fences_stale_withdrawal_and_allows_progress() {
        let epochs = EventEpochs::with_max_epochs(1);
        let first = epochs.admit("service-first").expect("first epoch");
        assert_eq!(epochs.admit("service-blocked"), None);
        assert!(!epochs.remove_if_current("service-first", first + 1));
        assert_eq!(epochs.current("service-first"), Some(first));
        assert!(epochs.remove_if_current("service-first", first));
        let successor = epochs.admit("service-successor").expect("successor epoch");
        assert_ne!(successor, first);
        assert!(!epochs.remove_if_current("service-successor", first));
        assert!(epochs.remove_if_current("service-successor", successor));
    }

    #[test]
    fn removed_consumes_its_already_admitted_slot_at_capacity_one() {
        let (tx, mut rx) = mpsc::channel(1);
        let slot = tx.try_reserve().expect("capacity-one slot is admitted");
        publish_removed(slot, 7, "service-withdrawn".to_string());
        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Removed { generation: 7, key }) if key == "service-withdrawn"
        ));
        assert!(tx.try_reserve().is_ok(), "slot is reusable after delivery");
    }

    fn resolved_for_handoff_test(generation: u64, key: &str) -> DiscoveryEvent {
        DiscoveryEvent::Resolved {
            generation,
            key: key.to_string(),
            addrs: vec!["192.0.2.1".parse().expect("test address")],
            port: 42_424,
            txt: HashMap::new(),
        }
    }

    #[test]
    fn resolved_handoff_capacity_one_preserves_b_after_a_and_closed_cleanup() {
        let (tx, mut rx) = mpsc::channel(1);
        try_publish_resolved(&tx, resolved_for_handoff_test(1, "service-a"))
            .expect("first resolved event should occupy the one slot");

        let event_b = resolved_for_handoff_test(2, "service-b");
        let event_b = match try_publish_resolved(&tx, event_b) {
            Err(ResolvedHandoff::Full(event)) => event,
            other => panic!("second event must remain owned while A is queued: {other:?}"),
        };
        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Resolved { generation: 1, key, .. }) if key == "service-a"
        ));

        try_publish_resolved(&tx, event_b).expect("B must be deliverable after A is consumed");
        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Resolved { generation: 2, key, .. }) if key == "service-b"
        ));
        assert!(
            tx.try_reserve().is_ok(),
            "delivery must release capacity exactly"
        );

        drop(rx);
        let closed = resolved_for_handoff_test(3, "service-closed");
        match try_publish_resolved(&tx, closed) {
            Err(ResolvedHandoff::Closed(DiscoveryEvent::Resolved {
                generation: 3, key, ..
            })) => assert_eq!(key, "service-closed"),
            other => panic!("closed stream must return the exact event: {other:?}"),
        }
    }

    #[test]
    fn resolve_handoff_error_states_preserve_or_settle_exact_owner() {
        let resolving = ResolveOwnership::with_max_owners(2);
        let epochs = EventEpochs::with_max_epochs(2);

        let full_lease = match resolving.admit("service-full") {
            ResolveHint::Started(lease) => lease,
            other => panic!("full-state resolve owner must start: {other:?}"),
        };
        let full_generation = epochs.admit("service-full").expect("full epoch");
        let (tx, mut rx) = mpsc::channel(1);
        try_publish_resolved(&tx, resolved_for_handoff_test(1, "queued"))
            .expect("queue must admit the first event");
        let mut full_pending = Some(resolved_for_handoff_test(2, "service-full"));
        let full_error: Result<ResolveCompletion, bool> =
            match try_publish_resolved(&tx, full_pending.take().expect("full event")) {
                Err(ResolvedHandoff::Full(event)) => {
                    full_pending = Some(event);
                    Err(false)
                }
                other => panic!("full handoff must preserve its event: {other:?}"),
            };
        assert!(matches!(full_error, Err(false)));
        assert!(full_pending.is_some(), "full must retain its exact event");
        assert_eq!(resolving.active_count(), 1);
        assert_eq!(epochs.current("service-full"), Some(full_generation));

        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Resolved { key, .. }) if key == "queued"
        ));
        try_publish_resolved(&tx, full_pending.take().expect("retained full event"))
            .expect("full event must publish after capacity is released");
        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Resolved { key, .. }) if key == "service-full"
        ));
        assert!(matches!(full_lease.complete(), ResolveCompletion::Finished));
        assert_eq!(resolving.active_count(), 0);

        let closed_lease = match resolving.admit("service-closed") {
            ResolveHint::Started(lease) => lease,
            other => panic!("closed-state resolve owner must start: {other:?}"),
        };
        let closed_generation = epochs.admit("service-closed").expect("closed epoch");
        let (closed_tx, closed_rx) = mpsc::channel(1);
        drop(closed_rx);
        let mut closed_pending = Some(resolved_for_handoff_test(3, "service-closed"));
        let closed_error: Result<ResolveCompletion, bool> =
            match try_publish_resolved(&closed_tx, closed_pending.take().expect("closed event")) {
                Err(ResolvedHandoff::Closed(event)) => {
                    closed_pending = Some(event);
                    Err(true)
                }
                other => panic!("closed handoff must return its exact event: {other:?}"),
            };
        match closed_error {
            Err(true) => discard_closed_resolution(
                &epochs,
                "service-closed",
                closed_generation,
                closed_lease,
                &mut closed_pending,
            ),
            other => panic!("closed handoff must be terminal: {other:?}"),
        }
        assert!(closed_pending.is_none(), "closed event must be disposed");
        assert_eq!(resolving.active_count(), 0);
        assert_eq!(epochs.current("service-closed"), None);
    }

    #[test]
    fn full_event_stream_stales_removed_generation_before_withdrawal_delivery() {
        let resolving = ResolveOwnership::with_max_owners(1);
        let lease = match resolving.admit("service-stale") {
            ResolveHint::Started(lease) => lease,
            other => panic!("exact resolve owner must start: {other:?}"),
        };
        let epochs = EventEpochs::new();
        let generation = epochs.admit("service-stale").expect("event epoch");
        let (tx, mut rx) = mpsc::channel(1);
        try_publish_resolved(&tx, resolved_for_handoff_test(9, "service-a"))
            .expect("A fills the capacity-one stream");

        assert_eq!(
            retire_removed_generation(&resolving, &epochs, "service-stale"),
            Some(generation)
        );
        assert_eq!(resolving.active_count(), 0);
        assert_eq!(epochs.current("service-stale"), None);

        let stale = resolved_for_handoff_test(generation, "service-stale");
        assert!(matches!(
            try_publish_resolved(&tx, stale),
            Err(ResolvedHandoff::Full(DiscoveryEvent::Resolved { key, .. }))
                if key == "service-stale"
        ));
        drop(lease);
        assert!(matches!(
            rx.try_recv(),
            Ok(DiscoveryEvent::Resolved { generation: 9, key, .. }) if key == "service-a"
        ));
        assert!(
            tx.try_reserve().is_ok(),
            "stale disposal must not leak a slot"
        );
    }

    #[test]
    fn worker_registry_consumes_normal_panic_cancel_and_shutdown_is_empty() {
        let workers = WorkerRegistry::with_capacity(3);
        workers
            .push(std::thread::spawn(|| {}))
            .expect("first worker has a reserved slot");
        workers
            .push(std::thread::spawn(|| panic!("injected worker failure")))
            .expect("second worker has a reserved slot");

        let canceled = Arc::new(AtomicBool::new(false));
        let canceled_worker = Arc::clone(&canceled);
        workers
            .push(std::thread::spawn(move || {
                while !canceled_worker.load(Ordering::Acquire) {
                    std::thread::yield_now();
                }
            }))
            .expect("third worker has a reserved slot");
        canceled.store(true, Ordering::Release);

        workers.join_all();
        assert_eq!(workers.len(), 0);
        workers.reap_finished();
        assert_eq!(workers.len(), 0);
    }

    #[test]
    fn worker_registry_refuses_true_live_full_without_dropping_the_unowned_handle() {
        let workers = WorkerRegistry::with_capacity(1);
        let (release_tx, release_rx) = std::sync::mpsc::sync_channel(0);
        workers
            .push(std::thread::spawn(move || {
                release_rx.recv().expect("test releases live worker");
            }))
            .expect("the sole worker slot is available");
        let refused = workers
            .push(std::thread::spawn(|| {}))
            .expect_err("a true-live-full registry must refuse before custody is exceeded");
        observe_worker(refused);
        release_tx.send(()).expect("live worker is still retained");
        workers.join_all();
        assert_eq!(workers.len(), 0);
    }

    #[test]
    fn worker_registry_reaps_stale_terminal_full_before_admitting_successor() {
        let workers = WorkerRegistry::with_capacity(1);
        workers
            .push(std::thread::spawn(|| {}))
            .expect("the sole worker slot is available");
        while !workers.workers.lock()[0].is_finished() {
            std::thread::yield_now();
        }

        workers
            .push(std::thread::spawn(|| {}))
            .expect("a stale terminal slot is reclaimed before successor admission");
        workers.join_all();
        assert_eq!(workers.len(), 0);
    }

    #[test]
    fn injected_custody_refusal_precedes_native_start() {
        let cfg = DiscoveryConfig {
            service_type: "_momtest._tcp.local.".into(),
            instance: "mom-custody-refusal".into(),
            port: 45454,
            txt: vec![("v".into(), "1".into())],
            limits: DiscoveryLimits {
                max_resolve_owners: 1,
                event_capacity: 2,
                max_event_epochs: 2,
                max_txt_entries: 2,
                max_txt_bytes: 64,
                max_resolved_addresses: 2,
            },
            timing: crate::mdns::discovery::MdnsTimingProfile::default(),
        };
        let owner = DedicatedTaskCustodian::new(1).expect("test custodian starts");
        let result = Discovery::start_with_custodian(&cfg, owner);
        match result {
            Err(Error::Other(message)) => {
                assert!(
                    message.contains("system worker custody exhausted"),
                    "unexpected refusal: {message}"
                );
            }
            Ok((discovery, _events)) => {
                discovery.shutdown();
                panic!("worker custody refusal must precede native discovery start");
            }
            Err(error) => panic!("unexpected system discovery error: {error}"),
        }
    }

    /// End-to-end through the real system daemon: register an instance, browse
    /// it back, check the TXT survives. Needs a running mDNS daemon
    /// (mDNSResponder / avahi with the dns_sd compat lib), so it's ignored by
    /// default: `cargo test --features system-dnssd -- --ignored`.
    #[tokio::test(flavor = "multi_thread")]
    #[ignore = "needs a running system mDNS daemon (mDNSResponder / avahi)"]
    async fn registers_and_browses_via_the_system_daemon() {
        let limits = crate::mdns::discovery::DiscoveryLimits {
            max_resolve_owners: 3,
            event_capacity: 5,
            max_event_epochs: 7,
            max_txt_entries: 8,
            max_txt_bytes: 512,
            max_resolved_addresses: 4,
        };
        let cfg = DiscoveryConfig {
            service_type: "_momtest._tcp.local.".into(),
            instance: format!("mom-selftest-{}", std::process::id()),
            port: 45454,
            txt: vec![
                ("v".into(), "1".into()),
                ("room".into(), "roomhash".into()),
                ("peer".into(), "peerpubkey".into()),
            ],
            limits,
            timing: crate::mdns::discovery::MdnsTimingProfile::default(),
        };

        // A browser under a different instance name, so the advertiser's
        // own-echo skip doesn't apply.
        let browser_cfg = DiscoveryConfig {
            instance: "mom-selftest-browser".into(),
            ..cfg.clone()
        };
        let (browser, mut events) = Discovery::start(&browser_cfg).expect("browser start");

        let (advertiser, _adv_events) = Discovery::start(&cfg).expect("advertiser start");
        assert!(advertiser.register(), "register should be accepted");

        // The browser should resolve the advertiser within a few seconds.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
        loop {
            let remaining = deadline
                .checked_duration_since(tokio::time::Instant::now())
                .expect("timed out waiting for the system daemon to resolve our instance");
            let ev = tokio::time::timeout(remaining, events.recv())
                .await
                .expect("timed out")
                .expect("event stream open");
            if let DiscoveryEvent::Resolved { key, port, txt, .. } = ev {
                if key == cfg.instance {
                    assert_eq!(port, 45454);
                    assert_eq!(txt.get("room").map(String::as_str), Some("roomhash"));
                    assert_eq!(txt.get("peer").map(String::as_str), Some("peerpubkey"));
                    break;
                }
            }
        }

        advertiser.shutdown();
        browser.shutdown();
    }
}
