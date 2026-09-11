//! The discovery half of the mDNS driver — DNS-SD registration and browsing —
//! behind one seam with two backends:
//!
//! - [`embedded`] (the default): the pure-Rust `mdns-sd` daemon, raw multicast
//!   sockets. Works anywhere the OS lets an application join the mDNS
//!   multicast group.
//! - [`system`] (iOS always; opt-in elsewhere via the `system-dnssd` feature):
//!   the platform's own DNS-SD daemon through the stable `dnssd` C API —
//!   mDNSResponder on Apple platforms, Avahi's `libdns_sd` compat shim on
//!   Linux. iOS 14+ blocks raw multicast sockets unless the app holds the
//!   Apple-granted `com.apple.developer.networking.multicast` entitlement, but
//!   talking to mDNSResponder needs no entitlement — only the standard
//!   `NSLocalNetworkUsageDescription` / `NSBonjourServices` Info.plist keys.
//!   This is what makes **local claiming** work properly on an iPhone.
//!
//! Both backends speak standard mDNS/DNS-SD on the wire — same service type,
//! same TXT records — so a peer using one discovers a peer using the other.
//! The signaling exchange itself (the unicast TCP connection) is
//! backend-independent and lives in [`super::driver`].

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Owner-selected timing profile shared by the mDNS driver and discovery
/// backends.  Keeping these values in the immutable driver limits means the
/// planner and the enforcement paths consume the same source of truth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MdnsTimingProfile {
    pub dial_timeout: Duration,
    pub connection_idle_timeout: Duration,
    pub inbound_idle_timeout: Duration,
    pub reannounce_interval: Duration,
    pub query_deadline: Duration,
    pub accept_error_backoff: Duration,
}

impl Default for MdnsTimingProfile {
    fn default() -> Self {
        Self {
            dial_timeout: Duration::from_secs(5),
            connection_idle_timeout: Duration::from_secs(30),
            inbound_idle_timeout: Duration::from_secs(120),
            reannounce_interval: Duration::from_secs(60),
            query_deadline: Duration::from_secs(5),
            accept_error_backoff: Duration::from_millis(100),
        }
    }
}

impl MdnsTimingProfile {
    pub fn validate(self) -> bool {
        self.dial_timeout > Duration::ZERO
            && self.connection_idle_timeout > Duration::ZERO
            && self.inbound_idle_timeout > Duration::ZERO
            && self.reannounce_interval > Duration::ZERO
            && self.query_deadline > Duration::ZERO
            && self.accept_error_backoff > Duration::ZERO
    }
}

/// Owner-selected finite limits for one discovery backend instance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryLimits {
    /// Maximum exact service instances with an active resolve owner.
    pub max_resolve_owners: usize,
    /// Capacity of each bounded backend-to-driver event handoff.
    pub event_capacity: usize,
    /// Maximum exact system-backend service-key epochs retained for stale
    /// removal fencing.
    pub max_event_epochs: usize,
    /// Maximum TXT entries copied from one resolved service.
    pub max_txt_entries: usize,
    /// Maximum encoded TXT bytes retained for one resolved service, including
    /// one length octet per entry.
    pub max_txt_bytes: usize,
    /// Maximum unique IPv4 addresses retained for one resolved service.
    pub max_resolved_addresses: usize,
}

impl Default for DiscoveryLimits {
    /// Backend defaults for direct signaling users. The core mesh translates
    /// its persisted `MdnsPolicyConfig` into every field before attachment.
    fn default() -> Self {
        Self {
            max_resolve_owners: 256,
            event_capacity: 128,
            max_event_epochs: 1024,
            max_txt_entries: MAX_TXT_ENTRIES,
            max_txt_bytes: MAX_TXT_BYTES,
            max_resolved_addresses: MAX_RESOLVED_ADDRESSES,
        }
    }
}

impl DiscoveryConfig {
    /// Validate all caller-provided strings before either backend constructs a
    /// daemon object or copies TXT material into its native representation.
    pub(crate) fn validate(&self) -> bool {
        if self.service_type.is_empty()
            || self.service_type.len() > MAX_DNS_NAME_BYTES
            || self.instance.is_empty()
            || self.instance.len() > MAX_DNS_NAME_BYTES
            || self.txt.len() > self.limits.max_txt_entries
        {
            return false;
        }
        self.txt
            .iter()
            .try_fold(0usize, |total, (key, value)| {
                if key.is_empty()
                    || key.len() > MAX_TXT_KEY_BYTES
                    || value.len() > MAX_TXT_VALUE_BYTES
                {
                    return None;
                }
                let entry_bytes = key
                    .len()
                    .checked_add(1)
                    .and_then(|bytes| bytes.checked_add(value.len()))?;
                if entry_bytes > u8::MAX as usize {
                    return None;
                }
                total
                    .checked_add(1)
                    .and_then(|total| total.checked_add(entry_bytes))
            })
            .is_some_and(|total| total <= self.limits.max_txt_bytes)
    }
}

impl DiscoveryLimits {
    pub fn validate(self) -> bool {
        self.max_resolve_owners > 0
            && self.event_capacity > 0
            && self.event_capacity <= tokio::sync::Semaphore::MAX_PERMITS
            && self.max_event_epochs > 0
            && self.max_txt_entries > 0
            && self.max_txt_bytes > 0
            && self.max_txt_bytes <= u16::MAX as usize
            && self.max_resolved_addresses > 0
    }

    /// Compute the complete bounded residency envelope for one backend.
    ///
    /// `payload_owner_slots` is the exact number of latest-state owners that
    /// the backend can retain at once: the embedded backend has two bounded
    /// event handoffs (`R + 2E`), while the system backend has one (`R + E`).
    /// Per-resolver TXT, address, and scratch ownership is multiplied by `R`
    /// with checked arithmetic. Library command/cache state and native DNS-SD
    /// objects are reported only as bounded opaque residual slots; this API
    /// deliberately does not claim byte precision for those dependencies.
    pub fn checked_residency(
        self,
        backend: DiscoveryBackend,
    ) -> Result<DiscoveryResidency, DiscoveryResidencyError> {
        if !self.validate() {
            return Err(DiscoveryResidencyError::InvalidLimits);
        }
        let event_queue_slots = match backend {
            DiscoveryBackend::Embedded => self
                .event_capacity
                .checked_mul(2)
                .ok_or(DiscoveryResidencyError::Overflow("event queue slots"))?,
            DiscoveryBackend::System => self.event_capacity,
        };
        let payload_owner_slots = self
            .max_resolve_owners
            .checked_add(event_queue_slots)
            .ok_or(DiscoveryResidencyError::Overflow("payload owner slots"))?;
        let per_resolver_scratch_bytes = self
            .max_txt_bytes
            .checked_add(
                self.max_resolved_addresses
                    .checked_mul(std::mem::size_of::<IpAddr>())
                    .ok_or(DiscoveryResidencyError::Overflow("resolver address bytes"))?,
            )
            .ok_or(DiscoveryResidencyError::Overflow("resolver scratch bytes"))?;
        let concurrent_txt_entry_slots = self
            .max_resolve_owners
            .checked_mul(self.max_txt_entries)
            .ok_or(DiscoveryResidencyError::Overflow("resolver TXT slots"))?;
        let concurrent_address_slots = self
            .max_resolve_owners
            .checked_mul(self.max_resolved_addresses)
            .ok_or(DiscoveryResidencyError::Overflow("resolver address slots"))?;
        let concurrent_scratch_bytes = self
            .max_resolve_owners
            .checked_mul(per_resolver_scratch_bytes)
            .ok_or(DiscoveryResidencyError::Overflow(
                "resolver scratch aggregate",
            ))?;
        let (event_epoch_slots, opaque_residual_slots) = match backend {
            DiscoveryBackend::Embedded => (0, 3),
            DiscoveryBackend::System => (
                self.max_event_epochs,
                self.max_resolve_owners
                    .checked_add(2)
                    .ok_or(DiscoveryResidencyError::Overflow("native worker slots"))?,
            ),
        };
        Ok(DiscoveryResidency {
            backend,
            event_queue_slots,
            resolve_owner_slots: self.max_resolve_owners,
            event_epoch_slots,
            payload_owner_slots,
            concurrent_txt_entry_slots,
            concurrent_address_slots,
            per_resolver_scratch_bytes,
            concurrent_scratch_bytes,
            opaque_residual_slots,
        })
    }
}

/// Discovery implementation selected by the platform and feature set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryBackend {
    /// The pure-Rust `mdns-sd` backend with two bounded event handoffs.
    Embedded,
    /// The system DNS-SD backend with native resolver workers and epochs.
    System,
}

/// Checked backend-specific residency plan consumed by driver custody.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryResidency {
    pub backend: DiscoveryBackend,
    pub event_queue_slots: usize,
    pub resolve_owner_slots: usize,
    pub event_epoch_slots: usize,
    pub payload_owner_slots: usize,
    pub concurrent_txt_entry_slots: usize,
    pub concurrent_address_slots: usize,
    pub per_resolver_scratch_bytes: usize,
    pub concurrent_scratch_bytes: usize,
    pub opaque_residual_slots: usize,
}

/// Why a backend residency plan could not be constructed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryResidencyError {
    InvalidLimits,
    Overflow(&'static str),
}

impl std::fmt::Display for DiscoveryResidencyError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidLimits => formatter.write_str("invalid discovery limits"),
            Self::Overflow(field) => write!(formatter, "discovery residency overflow: {field}"),
        }
    }
}

impl std::error::Error for DiscoveryResidencyError {}
/// DNS-SD's maximum encoded domain-name length (including length octets and
/// the root terminator). This is a wire/dependency bound, not an application
/// workload setting.
pub const MAX_DNS_NAME_BYTES: usize = 255;
/// Default bound for direct backend users. DNS-SD does not define an
/// entry-count policy; the core mesh supplies its persisted owner value through
/// [`DiscoveryLimits::max_txt_entries`].
pub const MAX_TXT_ENTRIES: usize = 64;
/// Defensive key bound for the application's TXT map. The DNS-SD wire limit
/// applies to each encoded TXT string, so this is intentionally distinct from
/// [`MAX_TXT_VALUE_BYTES`].
pub const MAX_TXT_KEY_BYTES: usize = 128;
/// Maximum value size accepted by the application's TXT map. A DNS-SD TXT
/// string carries its encoded length in one octet; the backend's encoder keeps
/// that dependency limit as a final defensive check.
pub const MAX_TXT_VALUE_BYTES: usize = 255;
/// Default total TXT payload bound for direct backend users. This is not a
/// DNS-SD wire maximum; the core mesh supplies its persisted owner value
/// through [`DiscoveryLimits::max_txt_bytes`], subject to the DNS-SD `u16`
/// length.
pub const MAX_TXT_BYTES: usize = 4096;
/// Default unique IPv4-address bound for direct backend users. DNS-SD supplies
/// no application address-count limit; the core mesh supplies its persisted
/// owner value through [`DiscoveryLimits::max_resolved_addresses`].
pub const MAX_RESOLVED_ADDRESSES: usize = 32;

/// What a backend needs to advertise + browse one service instance.
#[derive(Debug, Clone)]
pub struct DiscoveryConfig {
    /// DNS-SD service type, in the `_x._tcp.local.` form ([`super::wire::SERVICE_TYPE`]).
    pub service_type: String,
    /// Our instance name (a bare DNS label, [`super::wire::instance_name`]).
    pub instance: String,
    /// Port the SRV record advertises (our TCP exchange listener).
    pub port: u16,
    /// TXT records for the advertisement ([`super::wire::txt_properties`]).
    pub txt: Vec<(String, String)>,
    /// Validated owner-selected discovery workload limits.
    pub limits: DiscoveryLimits,
    /// Validated owner-selected timing values used by system queries.
    pub timing: MdnsTimingProfile,
}

/// One discovery observation. `key` is a backend-opaque identifier that is
/// stable between a `Resolved` and the `Removed` that withdraws it — the
/// driver treats it as an opaque map key and never interprets it.
#[derive(Debug, Clone)]
pub enum DiscoveryEvent {
    /// A service instance resolved (first sight or cache refresh): where its
    /// exchange listens and its TXT records.
    Resolved {
        /// Exact coalescer generation for this service-instance state.
        generation: u64,
        key: String,
        addrs: Vec<IpAddr>,
        port: u16,
        txt: HashMap<String, String>,
    },
    /// An instance withdrew (goodbye) or expired from the cache.
    Removed {
        /// Generation of the state being withdrawn, not a new successor token.
        generation: u64,
        key: String,
    },
}

#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
#[derive(Debug)]
struct CoalescedDiscoveryEvent {
    generation: u64,
    event: Option<DiscoveryEvent>,
    state: CoalescedDiscoveryState,
}

#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoalescedDiscoveryState {
    Active,
    Removed,
}

/// A bounded latest-state table for events that are waiting for the delivery
/// owner.  This table is deliberately keyed by the backend's exact service
/// instance name; it never uses a device id decoded from TXT data.
#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
pub(crate) struct DiscoveryEventCoalescer {
    pending: Mutex<HashMap<String, CoalescedDiscoveryEvent>>,
    next_generation: AtomicU64,
    stopped: AtomicBool,
    max_pending: usize,
}

#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DiscoveryEventAdmission {
    Started { generation: u64 },
    Coalesced { generation: u64 },
    Refused,
}

#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
impl DiscoveryEventCoalescer {
    #[cfg(test)]
    pub(crate) fn new() -> Self {
        Self::with_limits(DiscoveryLimits::default())
    }

    pub(crate) fn with_limits(limits: DiscoveryLimits) -> Self {
        Self {
            pending: Mutex::new(HashMap::new()),
            next_generation: AtomicU64::new(1),
            stopped: AtomicBool::new(false),
            max_pending: limits.max_resolve_owners,
        }
    }

    /// Admit the exact key before the caller copies its event payload.
    pub(crate) fn admit(&self, key: &str) -> DiscoveryEventAdmission {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopped.load(Ordering::Acquire) {
            return DiscoveryEventAdmission::Refused;
        }
        if let Some(existing) = pending.get(key) {
            return DiscoveryEventAdmission::Coalesced {
                generation: existing.generation,
            };
        }
        if pending.len() >= self.max_pending {
            return DiscoveryEventAdmission::Refused;
        }
        let Some(generation) = next_generation(&self.next_generation) else {
            return DiscoveryEventAdmission::Refused;
        };
        pending.insert(
            key.to_owned(),
            CoalescedDiscoveryEvent {
                generation,
                event: None,
                state: CoalescedDiscoveryState::Active,
            },
        );
        DiscoveryEventAdmission::Started { generation }
    }

    /// Return the generation of an already active key without creating a
    /// generation for an unrelated/stale removal notification.
    pub(crate) fn admit_existing(&self, key: &str) -> Option<u64> {
        let pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        pending.get(key).map(|slot| slot.generation)
    }

    /// Replace the latest state for an admitted exact key. A stale generation
    /// cannot publish into a replacement slot.
    pub(crate) fn publish(&self, key: &str, generation: u64, event: DiscoveryEvent) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = pending.get_mut(key) else {
            return false;
        };
        if slot.generation != generation
            || event.generation() != generation
            || self.stopped.load(Ordering::Acquire)
        {
            return false;
        }
        slot.state = match event {
            DiscoveryEvent::Resolved { .. } => CoalescedDiscoveryState::Active,
            DiscoveryEvent::Removed { .. } => CoalescedDiscoveryState::Removed,
        };
        slot.event = Some(event);
        true
    }

    pub(crate) fn take_ready(&self) -> Option<(String, u64, DiscoveryEvent)> {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let key = pending
            .iter()
            .find_map(|(key, slot)| slot.event.is_some().then(|| key.clone()))?;
        let slot = pending.get_mut(&key)?;
        let event = slot.event.take()?;
        Some((key, slot.generation, event))
    }

    pub(crate) fn restore(&self, key: &str, generation: u64, event: DiscoveryEvent) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = pending.get_mut(key) else {
            return false;
        };
        if slot.generation != generation || self.stopped.load(Ordering::Acquire) {
            return false;
        }
        slot.event = Some(event);
        true
    }

    pub(crate) fn finish(&self, key: &str, generation: u64) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = pending.get(key) else {
            return false;
        };
        if slot.generation != generation || slot.event.is_some() {
            return false;
        }
        if slot.state == CoalescedDiscoveryState::Removed {
            pending.remove(key);
        }
        true
    }

    pub(crate) fn cancel(&self, key: &str, generation: u64) -> bool {
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        if pending
            .get(key)
            .is_some_and(|slot| slot.generation == generation)
        {
            pending.remove(key);
            true
        } else {
            false
        }
    }

    pub(crate) fn shutdown(&self) {
        self.stopped.store(true, Ordering::Release);
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    #[cfg(test)]
    fn pending_count(&self) -> usize {
        self.pending.lock().unwrap_or_else(|e| e.into_inner()).len()
    }
}

#[cfg(any(test, not(any(target_os = "ios", feature = "system-dnssd"))))]
impl DiscoveryEvent {
    pub(crate) fn generation(&self) -> u64 {
        match self {
            Self::Resolved { generation, .. } | Self::Removed { generation, .. } => *generation,
        }
    }
}

/// Result of admitting one exact service-instance browse hint.
#[derive(Debug)]
pub enum ResolveHint {
    /// This instance has one active resolve owner.
    Started(ResolveLease),
    /// A resolve is already active (or already has a pending follow-up) for
    /// this exact instance; no additional owner was allocated.
    Coalesced,
    /// The ownership table is full or has been shut down.
    Refused,
}

/// Result of completing one active resolve owner.
#[derive(Debug)]
pub enum ResolveCompletion {
    /// There is no follow-up for this instance.
    Finished,
    /// A coalesced hint earned one exact follow-up owner.
    Followup(ResolveLease),
}

#[derive(Debug)]
struct ResolveSlot {
    generation: u64,
    pending: bool,
}

#[derive(Debug)]
struct ResolveOwnershipInner {
    slots: Mutex<HashMap<String, ResolveSlot>>,
    next_generation: AtomicU64,
    stopped: AtomicBool,
    max_owners: usize,
}

/// Provider-side ownership for service-instance resolution.
///
/// The key is the exact backend service-instance name, not a device id decoded
/// later from untrusted TXT. One active owner and at most one coalesced pending
/// hint exist per key. Cancellation removes only the requested key; a stale
/// lease cannot cancel a newer generation for the same instance. Shutdown
/// invalidates all generations before clearing the table.
#[derive(Clone, Debug)]
pub struct ResolveOwnership {
    inner: Arc<ResolveOwnershipInner>,
}

impl ResolveOwnership {
    /// Create ownership with an explicit finite owner-selected bound.
    pub fn with_max_owners(max_owners: usize) -> Self {
        Self {
            inner: Arc::new(ResolveOwnershipInner {
                slots: Mutex::new(HashMap::new()),
                next_generation: AtomicU64::new(1),
                stopped: AtomicBool::new(false),
                max_owners,
            }),
        }
    }

    /// Admit a browse hint for one exact service instance.
    pub fn admit(&self, instance: impl Into<String>) -> ResolveHint {
        let instance = instance.into();
        let mut slots = self.inner.slots.lock().unwrap_or_else(|e| e.into_inner());
        if self.inner.stopped.load(Ordering::Acquire) {
            return ResolveHint::Refused;
        }
        if let Some(slot) = slots.get_mut(&instance) {
            slot.pending = true;
            return ResolveHint::Coalesced;
        }
        if slots.len() >= self.inner.max_owners {
            return ResolveHint::Refused;
        }
        let Some(generation) = next_generation(&self.inner.next_generation) else {
            return ResolveHint::Refused;
        };
        slots.insert(
            instance.clone(),
            ResolveSlot {
                generation,
                pending: false,
            },
        );
        ResolveHint::Started(ResolveLease {
            tracker: Arc::clone(&self.inner),
            instance,
            generation,
        })
    }

    /// Cancel all active and pending work for one exact service instance.
    pub fn cancel(&self, instance: &str) -> bool {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(instance)
            .is_some()
    }

    /// Invalidate every active and pending resolve owner.
    pub fn shutdown(&self) {
        self.inner.stopped.store(true, Ordering::Release);
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clear();
    }

    /// Number of exact service instances with an active owner.
    pub fn active_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .len()
    }

    /// Number of exact service instances with one coalesced pending hint.
    pub fn pending_count(&self) -> usize {
        self.inner
            .slots
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .values()
            .filter(|slot| slot.pending)
            .count()
    }
}

/// One exact active resolve owner. Dropping it cancels only its generation.
#[derive(Debug)]
pub struct ResolveLease {
    tracker: Arc<ResolveOwnershipInner>,
    instance: String,
    generation: u64,
}

impl ResolveLease {
    /// The exact backend service-instance name owned by this lease.
    pub fn instance(&self) -> &str {
        &self.instance
    }

    /// Explicitly cancel this generation.
    pub fn cancel(self) -> bool {
        self.tracker
            .cancel_generation(&self.instance, self.generation)
    }

    /// Complete this owner and retain one coalesced follow-up, if any.
    pub fn complete(self) -> ResolveCompletion {
        self.complete_with(|| {})
    }

    pub(crate) fn complete_with<F>(self, publish: F) -> ResolveCompletion
    where
        F: FnOnce(),
    {
        let tracker = Arc::clone(&self.tracker);
        let instance = self.instance.clone();
        let generation = self.generation;
        let mut slots = tracker.slots.lock().unwrap_or_else(|e| e.into_inner());
        let Some(slot) = slots.get_mut(&instance) else {
            return ResolveCompletion::Finished;
        };
        if slot.generation != generation || tracker.stopped.load(Ordering::Acquire) {
            return ResolveCompletion::Finished;
        }
        publish();
        if slot.pending {
            let Some(next_generation) = next_generation(&tracker.next_generation) else {
                slots.remove(&instance);
                return ResolveCompletion::Finished;
            };
            slot.generation = next_generation;
            slot.pending = false;
            drop(slots);
            ResolveCompletion::Followup(ResolveLease {
                tracker,
                instance,
                generation: next_generation,
            })
        } else {
            slots.remove(&instance);
            ResolveCompletion::Finished
        }
    }
}

impl Drop for ResolveLease {
    fn drop(&mut self) {
        self.tracker
            .cancel_generation(&self.instance, self.generation);
    }
}

impl ResolveOwnershipInner {
    fn cancel_generation(&self, instance: &str, generation: u64) -> bool {
        let mut slots = self.slots.lock().unwrap_or_else(|e| e.into_inner());
        if slots
            .get(instance)
            .is_some_and(|slot| slot.generation == generation)
        {
            slots.remove(instance);
            true
        } else {
            false
        }
    }
}

/// Allocate a generation without ever wrapping or reusing an exhausted value.
/// Zero is the permanent exhausted sentinel; MAX is handed out once and then
/// the counter is sealed.
fn next_generation(counter: &AtomicU64) -> Option<u64> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generation_exhaustion_refuses_without_reuse() {
        let ownership = ResolveOwnership::with_max_owners(1);
        ownership
            .inner
            .next_generation
            .store(u64::MAX, Ordering::Release);
        let last = ownership.admit("last");
        assert!(matches!(&last, ResolveHint::Started(_)));
        assert!(matches!(
            ownership.admit("after-exhaustion"),
            ResolveHint::Refused
        ));
        drop(last);
        assert!(matches!(
            ownership.admit("still-exhausted"),
            ResolveHint::Refused
        ));
    }

    #[test]
    fn event_coalescer_is_bounded_and_keeps_latest_exact_key_state() {
        let coalescer = DiscoveryEventCoalescer::new();
        let first_generation = match coalescer.admit("service-a") {
            DiscoveryEventAdmission::Started { generation } => generation,
            other => panic!("first event was not admitted: {other:?}"),
        };
        assert!(coalescer.publish(
            "service-a",
            first_generation,
            DiscoveryEvent::Resolved {
                generation: first_generation,
                key: "service-a".into(),
                addrs: vec![IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)],
                port: 1,
                txt: HashMap::new(),
            }
        ));
        let coalesced_generation = match coalescer.admit("service-a") {
            DiscoveryEventAdmission::Coalesced { generation } => generation,
            other => panic!("same exact key was not coalesced: {other:?}"),
        };
        assert_eq!(coalesced_generation, first_generation);
        assert_eq!(
            coalescer.admit_existing("service-a"),
            Some(first_generation)
        );
        assert!(coalescer.publish(
            "service-a",
            coalesced_generation,
            DiscoveryEvent::Removed {
                generation: coalesced_generation,
                key: "service-a".into(),
            }
        ));
        let (old_key, old_generation, old_event) = coalescer.take_ready().expect("latest state");
        assert_eq!(old_key, "service-a");
        assert_eq!(old_generation, first_generation);
        assert_eq!(old_event.generation(), first_generation);
        assert!(coalescer.finish(&old_key, old_generation));

        let successor_generation = match coalescer.admit("service-a") {
            DiscoveryEventAdmission::Started { generation } => generation,
            other => panic!("successor was not admitted: {other:?}"),
        };
        assert_ne!(successor_generation, first_generation);
        assert!(coalescer.publish(
            "service-a",
            successor_generation,
            DiscoveryEvent::Removed {
                generation: successor_generation,
                key: "service-a".into(),
            }
        ));
        assert!(!coalescer.restore("service-a", first_generation, old_event));
        let (_, generation, event) = coalescer.take_ready().expect("successor state");
        assert_eq!(generation, successor_generation);
        assert_eq!(event.generation(), successor_generation);
        assert!(coalescer.finish("service-a", successor_generation));
    }

    #[test]
    fn event_coalescer_refuses_at_ownership_cap_and_clears_on_shutdown() {
        let limits = DiscoveryLimits {
            max_resolve_owners: 3,
            event_capacity: 5,
            max_event_epochs: 7,
            max_txt_entries: 8,
            max_txt_bytes: 512,
            max_resolved_addresses: 4,
        };
        assert!(limits.validate());
        let coalescer = DiscoveryEventCoalescer::with_limits(limits);
        let max_owners = limits.max_resolve_owners;
        for index in 0..max_owners {
            assert!(matches!(
                coalescer.admit(&format!("service-{index}")),
                DiscoveryEventAdmission::Started { .. }
            ));
        }
        assert_eq!(coalescer.pending_count(), max_owners);
        assert_eq!(
            coalescer.admit("service-over-capacity"),
            DiscoveryEventAdmission::Refused
        );
        let released_generation = match coalescer.admit("service-0") {
            DiscoveryEventAdmission::Coalesced { generation } => generation,
            other => panic!("existing exact key was not found: {other:?}"),
        };
        assert!(coalescer.cancel("service-0", released_generation));
        assert!(matches!(
            coalescer.admit("service-after-release"),
            DiscoveryEventAdmission::Started { .. }
        ));
        coalescer.shutdown();
        assert_eq!(coalescer.pending_count(), 0);
        assert_eq!(
            coalescer.admit("after-shutdown"),
            DiscoveryEventAdmission::Refused
        );
    }

    #[test]
    fn backend_residency_is_distinct_checked_and_bounded() {
        let limits = DiscoveryLimits {
            max_resolve_owners: 3,
            event_capacity: 5,
            max_event_epochs: 7,
            max_txt_entries: 8,
            max_txt_bytes: 512,
            max_resolved_addresses: 4,
        };
        let per_resolver = 512 + 4 * std::mem::size_of::<IpAddr>();
        let concurrent = 3 * per_resolver;
        let embedded = limits
            .checked_residency(DiscoveryBackend::Embedded)
            .expect("embedded residency fits");
        assert_eq!(embedded.event_queue_slots, 10);
        assert_eq!(embedded.payload_owner_slots, 13);
        assert_eq!(embedded.event_epoch_slots, 0);
        assert_eq!(embedded.per_resolver_scratch_bytes, per_resolver);
        assert_eq!(embedded.concurrent_scratch_bytes, concurrent);
        assert_eq!(embedded.opaque_residual_slots, 3);

        let system = limits
            .checked_residency(DiscoveryBackend::System)
            .expect("system residency fits");
        assert_eq!(system.event_queue_slots, 5);
        assert_eq!(system.payload_owner_slots, 8);
        assert_eq!(system.event_epoch_slots, 7);
        assert_eq!(system.concurrent_txt_entry_slots, 24);
        assert_eq!(system.concurrent_address_slots, 12);
        assert_eq!(system.concurrent_scratch_bytes, concurrent);
        assert_eq!(system.opaque_residual_slots, 5);

        let mut overflowing = limits;
        overflowing.max_resolve_owners = usize::MAX;
        assert!(matches!(
            overflowing.checked_residency(DiscoveryBackend::System),
            Err(DiscoveryResidencyError::Overflow(_))
        ));
    }

    #[test]
    fn timing_profile_rejects_zero_before_backend_start() {
        let profile = MdnsTimingProfile {
            query_deadline: Duration::ZERO,
            ..MdnsTimingProfile::default()
        };
        assert!(!profile.validate());
        let backoff_profile = MdnsTimingProfile {
            accept_error_backoff: Duration::ZERO,
            ..MdnsTimingProfile::default()
        };
        assert!(!backoff_profile.validate());
        assert!(MdnsTimingProfile::default().validate());
    }

    #[test]
    fn discovery_payload_limits_reject_zero_and_oversized_wire_bytes() {
        let limits = DiscoveryLimits::default();
        assert!(limits.validate());
        assert!(!DiscoveryLimits {
            max_txt_entries: 0,
            ..limits
        }
        .validate());
        assert!(!DiscoveryLimits {
            max_txt_bytes: 0,
            ..limits
        }
        .validate());
        assert!(!DiscoveryLimits {
            max_resolved_addresses: 0,
            ..limits
        }
        .validate());
        assert!(DiscoveryLimits {
            max_txt_bytes: u16::MAX as usize,
            ..limits
        }
        .validate());
        assert!(!DiscoveryLimits {
            max_txt_bytes: u16::MAX as usize + 1,
            ..limits
        }
        .validate());
    }

    #[test]
    fn discovery_config_bounds_payload_before_backend_start() {
        let mut config = DiscoveryConfig {
            service_type: "_mesh._tcp.local.".into(),
            instance: "instance".into(),
            port: 1,
            txt: vec![("key".into(), "value".into())],
            limits: DiscoveryLimits::default(),
            timing: MdnsTimingProfile::default(),
        };
        assert!(config.validate());

        config.limits = DiscoveryLimits {
            max_txt_entries: 1,
            max_txt_bytes: 64,
            max_resolved_addresses: 1,
            ..config.limits
        };
        config.txt = vec![("first".into(), "value".into()); 2];
        assert!(!config.validate());

        config.txt = vec![("key".into(), "value".into()); MAX_TXT_ENTRIES + 1];
        assert!(!config.validate());
        config.txt = vec![("key".into(), "x".repeat(MAX_TXT_VALUE_BYTES + 1))];
        assert!(!config.validate());
        config.txt = vec![("x".repeat(MAX_TXT_KEY_BYTES + 1), "value".into())];
        assert!(!config.validate());
    }

    #[test]
    fn resolve_ownership_uses_the_configured_non_default_cap() {
        let ownership = ResolveOwnership::with_max_owners(2);
        let first = ownership.admit("service-1");
        let second = ownership.admit("service-2");
        assert!(matches!(&first, ResolveHint::Started(_)));
        assert!(matches!(&second, ResolveHint::Started(_)));
        assert!(matches!(ownership.admit("service-3"), ResolveHint::Refused));
        drop(first);
        drop(second);
        assert_eq!(ownership.active_count(), 0);
    }

    #[test]
    fn resolve_ownership_capacity_one_cancels_and_allows_unrelated_progress() {
        let ownership = ResolveOwnership::with_max_owners(1);
        let first = match ownership.admit("service-first") {
            ResolveHint::Started(lease) => lease,
            other => panic!("first service was not admitted: {other:?}"),
        };
        assert!(matches!(
            ownership.admit("service-blocked"),
            ResolveHint::Refused
        ));
        assert!(ownership.cancel("service-first"));
        assert_eq!(ownership.active_count(), 0);
        drop(first);
        assert!(matches!(
            ownership.admit("service-unrelated"),
            ResolveHint::Started(_)
        ));
    }
}

#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
mod system;
#[cfg(any(target_os = "ios", feature = "system-dnssd"))]
pub use system::Discovery;

#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
mod embedded;
#[cfg(not(any(target_os = "ios", feature = "system-dnssd")))]
pub use embedded::{checked_embedded_custody_plan, Discovery, EmbeddedCustodyPlan};
