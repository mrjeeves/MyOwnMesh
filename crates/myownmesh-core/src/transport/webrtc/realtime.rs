//! Codec-neutral connector-local real-time flow ownership and accounting.

use super::*;

/// Opaque process-local identity for one connector real-time flow.
///
/// The key is scheduling identity only. It is not serialized and grants no
/// authority. Codec, lane, and application-purpose names stay in the WebRTC
/// compatibility adapter that owns the corresponding flow port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct RealtimeFlowKey(std::num::NonZeroU64);

static NEXT_REALTIME_FLOW_KEY: AtomicU64 = AtomicU64::new(1);

impl RealtimeFlowKey {
    fn issue() -> Option<Self> {
        NEXT_REALTIME_FLOW_KEY
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |current| {
                current.checked_add(1)
            })
            .ok()
            .and_then(std::num::NonZeroU64::new)
            .map(Self)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowDropReason {
    OwnerPolicyMissing,
    FlowLimit,
    FragmentOversize,
    FragmentCount,
    UnitOversize,
    InProgressLimit,
    AggregateBytes,
    FlowQueueFull,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowDomain {
    InboundQuarantine,
    OutboundCompatibility,
}

impl RealtimeFlowDomain {
    pub(super) const fn index(self) -> usize {
        match self {
            Self::InboundQuarantine => 0,
            Self::OutboundCompatibility => 1,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowObservation {
    Flow {
        key: RealtimeFlowKey,
        domain: RealtimeFlowDomain,
        active_flows: usize,
    },
    Assembly {
        key: RealtimeFlowKey,
        in_progress_units: usize,
        retained_bytes: usize,
    },
    Queue {
        key: RealtimeFlowKey,
        units: usize,
        retained_bytes: usize,
    },
    Service {
        key: RealtimeFlowKey,
        queue_age: Duration,
        payload_bytes: usize,
    },
    Drop {
        key: Option<RealtimeFlowKey>,
        reason: RealtimeFlowDropReason,
        queue_age: Duration,
        payload_bytes: usize,
    },
}

/// Observation seam for the owner-run measurement harness.
///
/// Production installs no recorder. Test and lab recorders receive raw values
/// and own their own bounded storage or streaming output.
pub(super) trait RealtimeFlowObserver: Send + Sync {
    fn observe(&self, observation: RealtimeFlowObservation);
}

struct QueuedRealtimeEvent {
    event: QueuedTransportEvent,
    queued_at: Instant,
    payload_bytes: usize,
}

pub(super) struct RealtimeFlowQueue {
    domain: RealtimeFlowDomain,
    events: std::collections::VecDeque<QueuedRealtimeEvent>,
    scheduled: bool,
    in_progress_units: usize,
}

pub(super) struct RealtimeFlowRegistryState {
    pub(super) flows: std::collections::BTreeMap<RealtimeFlowKey, RealtimeFlowQueue>,
    pub(super) ready: std::collections::VecDeque<RealtimeFlowKey>,
    pub(super) retained_bytes_by_domain: [usize; 2],
    pub(super) in_progress_units: usize,
    pub(super) accounting_poisoned_by_domain: [bool; 2],
    pub(super) retired: bool,
}

pub(super) struct RealtimeFlowRegistry {
    policy: Option<EnabledRealtimeConnectorPolicy>,
    pub(super) max_unit_bytes: usize,
    pub(super) state: SyncMutex<RealtimeFlowRegistryState>,
    pub(super) ready: tokio::sync::Notify,
    observer: Option<Arc<dyn RealtimeFlowObserver>>,
}

impl RealtimeFlowRegistry {
    pub(super) fn new(policy: ConnectorCallbackPolicy) -> Arc<Self> {
        Self::with_observer(policy, None)
    }

    pub(super) fn with_observer(
        policy: ConnectorCallbackPolicy,
        observer: Option<Arc<dyn RealtimeFlowObserver>>,
    ) -> Arc<Self> {
        let realtime = match policy.realtime() {
            RealtimeConnectorPolicy::Disabled => None,
            RealtimeConnectorPolicy::Enabled(enabled) => Some(enabled),
        };
        Arc::new(Self {
            policy: realtime,
            max_unit_bytes: realtime.map_or(0, |enabled| enabled.max_unit_bytes().get()),
            state: SyncMutex::new(RealtimeFlowRegistryState {
                flows: std::collections::BTreeMap::new(),
                ready: std::collections::VecDeque::new(),
                retained_bytes_by_domain: [0; 2],
                in_progress_units: 0,
                accounting_poisoned_by_domain: [false; 2],
                retired: false,
            }),
            ready: tokio::sync::Notify::new(),
            observer,
        })
    }

    fn record(&self, observation: RealtimeFlowObservation) {
        if let Some(observer) = self.observer.as_ref() {
            observer.observe(observation);
        }
    }

    pub(super) fn is_enabled(&self) -> bool {
        self.policy.is_some()
    }

    fn open_flow(self: &Arc<Self>, domain: RealtimeFlowDomain) -> Option<RealtimeFlowPort> {
        let Some(policy) = self.policy else {
            self.record(RealtimeFlowObservation::Drop {
                key: None,
                reason: RealtimeFlowDropReason::OwnerPolicyMissing,
                queue_age: Duration::ZERO,
                payload_bytes: 0,
            });
            return None;
        };
        let Some(key) = RealtimeFlowKey::issue() else {
            self.record(RealtimeFlowObservation::Drop {
                key: None,
                reason: RealtimeFlowDropReason::FlowLimit,
                queue_age: Duration::ZERO,
                payload_bytes: 0,
            });
            return None;
        };
        let mut state = self.state.lock();
        if state.retired {
            return None;
        }
        if state.accounting_poisoned_by_domain[domain.index()] {
            return None;
        }
        let active_in_domain = state
            .flows
            .values()
            .filter(|flow| flow.domain == domain)
            .count();
        let limit = match domain {
            RealtimeFlowDomain::InboundQuarantine => {
                policy.flows().max_inbound_active_flows().get()
            }
            RealtimeFlowDomain::OutboundCompatibility => {
                policy.flows().max_outbound_active_flows().get()
            }
        };
        if active_in_domain >= limit {
            drop(state);
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::FlowLimit,
                queue_age: Duration::ZERO,
                payload_bytes: 0,
            });
            return None;
        }
        state.flows.insert(
            key,
            RealtimeFlowQueue {
                domain,
                events: std::collections::VecDeque::new(),
                scheduled: false,
                in_progress_units: 0,
            },
        );
        let Some(active_flows) = active_in_domain.checked_add(1) else {
            state.accounting_poisoned_by_domain[domain.index()] = true;
            state.flows.remove(&key);
            return None;
        };
        drop(state);
        self.record(RealtimeFlowObservation::Flow {
            key,
            domain,
            active_flows,
        });
        Some(RealtimeFlowPort {
            lifetime: Arc::new(RealtimeFlowLifetime {
                key,
                registry: Arc::clone(self),
            }),
        })
    }

    pub(super) fn open_inbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_flow(RealtimeFlowDomain::InboundQuarantine)
    }

    pub(super) fn open_outbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_flow(RealtimeFlowDomain::OutboundCompatibility)
    }

    fn remove_flow(&self, key: RealtimeFlowKey) {
        let mut state = self.state.lock();
        if let Some(flow) = state.flows.remove(&key) {
            state.ready.retain(|candidate| *candidate != key);
            let domain = flow.domain;
            let active_flows = state
                .flows
                .values()
                .filter(|candidate| candidate.domain == domain)
                .count();
            drop(state);
            self.record(RealtimeFlowObservation::Flow {
                key,
                domain,
                active_flows,
            });
            // Drop queued payloads after releasing the registry mutex. Their
            // exact byte leases return capacity through the same registry.
            drop(flow);
        }
    }

    fn retained_bytes(state: &RealtimeFlowRegistryState) -> Option<usize> {
        state.retained_bytes_by_domain[0].checked_add(state.retained_bytes_by_domain[1])
    }

    fn release_bytes_locked(
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
        bytes: usize,
    ) -> bool {
        let index = domain.index();
        if state.accounting_poisoned_by_domain[index] {
            return false;
        }
        match state.retained_bytes_by_domain[index].checked_sub(bytes) {
            Some(retained) => {
                state.retained_bytes_by_domain[index] = retained;
                true
            }
            None => {
                state.accounting_poisoned_by_domain[index] = true;
                false
            }
        }
    }

    fn release_unit_locked(
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
    ) -> bool {
        if state.accounting_poisoned_by_domain[domain.index()] {
            return false;
        }
        match state.in_progress_units.checked_sub(1) {
            Some(units) => {
                state.in_progress_units = units;
                true
            }
            None => {
                state.accounting_poisoned_by_domain[domain.index()] = true;
                false
            }
        }
    }

    pub(super) fn begin_unit(
        self: &Arc<Self>,
        lifetime: Arc<RealtimeFlowLifetime>,
    ) -> Option<RealtimeAssemblyReservation> {
        let key = lifetime.key;
        let policy = self.policy?.flows();
        let mut state = self.state.lock();
        if state.retired {
            return None;
        }
        let domain = state.flows.get(&key)?.domain;
        if state.accounting_poisoned_by_domain[domain.index()] {
            return None;
        }
        let current_flow_units = state.flows.get(&key)?.in_progress_units;
        if current_flow_units >= policy.max_in_progress_units_per_flow().get() {
            drop(state);
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::InProgressLimit,
                queue_age: Duration::ZERO,
                payload_bytes: 0,
            });
            return None;
        }
        let Some(next_flow_units) = current_flow_units.checked_add(1) else {
            state.accounting_poisoned_by_domain[domain.index()] = true;
            return None;
        };
        let Some(next_total_units) = state.in_progress_units.checked_add(1) else {
            state.accounting_poisoned_by_domain[domain.index()] = true;
            return None;
        };
        let Some(flow) = state.flows.get_mut(&key) else {
            state.accounting_poisoned_by_domain[domain.index()] = true;
            return None;
        };
        flow.in_progress_units = next_flow_units;
        state.in_progress_units = next_total_units;
        let in_progress_units = state.in_progress_units;
        let retained_bytes = Self::retained_bytes(&state).unwrap_or(usize::MAX);
        drop(state);
        self.record(RealtimeFlowObservation::Assembly {
            key,
            in_progress_units,
            retained_bytes,
        });
        Some(RealtimeAssemblyReservation {
            registry: Arc::clone(self),
            key,
            domain,
            _lifetime: lifetime,
            retained_bytes: 0,
            retained_fragments: 0,
            active: true,
        })
    }

    pub(super) fn reserve_output(
        self: &Arc<Self>,
        key: RealtimeFlowKey,
        bytes: usize,
    ) -> Option<RealtimeOutputReservation> {
        if bytes > self.max_unit_bytes {
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::UnitOversize,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return None;
        }
        let policy = self.policy?.flows();
        let mut state = self.state.lock();
        if state.retired {
            return None;
        }
        let domain = state.flows.get(&key)?.domain;
        if state.accounting_poisoned_by_domain[domain.index()] {
            return None;
        }
        let byte_budgets = policy.byte_budgets();
        let index = domain.index();
        let Some(next_domain) = state.retained_bytes_by_domain[index].checked_add(bytes) else {
            state.accounting_poisoned_by_domain[index] = true;
            return None;
        };
        let domain_limit = match domain {
            RealtimeFlowDomain::InboundQuarantine => byte_budgets.max_inbound_bytes().get(),
            RealtimeFlowDomain::OutboundCompatibility => byte_budgets.max_outbound_bytes().get(),
        };
        let other = state.retained_bytes_by_domain[1 - index];
        let Some(next_total) = next_domain.checked_add(other) else {
            state.accounting_poisoned_by_domain[index] = true;
            return None;
        };
        if next_domain > domain_limit || next_total > byte_budgets.max_total_bytes().get() {
            drop(state);
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::AggregateBytes,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return None;
        }
        state.retained_bytes_by_domain[index] = next_domain;
        drop(state);
        Some(RealtimeOutputReservation {
            registry: Arc::clone(self),
            key,
            domain,
            bytes,
            active: true,
        })
    }

    pub(super) fn enqueue(
        &self,
        key: RealtimeFlowKey,
        mut event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        if !std::ptr::eq(self, Arc::as_ref(&reservation.registry))
            || reservation.key != key
            || !reservation.active
        {
            return false;
        }
        let Some(policy) = self.policy.map(EnabledRealtimeConnectorPolicy::flows) else {
            return false;
        };
        let now = Instant::now();
        let mut state = self.state.lock();
        let domain = reservation.domain;
        if state.retired {
            return false;
        }
        if state.accounting_poisoned_by_domain[domain.index()] {
            return false;
        }
        let Some(flow) = state.flows.get_mut(&key) else {
            drop(state);
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::Retired,
                queue_age: Duration::ZERO,
                payload_bytes: reservation.bytes,
            });
            return false;
        };
        if flow.domain != domain {
            state.accounting_poisoned_by_domain[domain.index()] = true;
            return false;
        }
        if flow.events.len() >= policy.queue_capacity_per_flow().get() {
            drop(state);
            self.record(RealtimeFlowObservation::Drop {
                key: Some(key),
                reason: RealtimeFlowDropReason::FlowQueueFull,
                queue_age: Duration::ZERO,
                payload_bytes: reservation.bytes,
            });
            return match policy.overflow_rule() {
                crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest => true,
            };
        }
        let payload_bytes = reservation.bytes;
        let reservation = reservation.into_payload_lease();
        if let Err(reservation) = event.attach_realtime_reservation(reservation) {
            drop(state);
            drop(reservation);
            return false;
        }
        let was_empty = flow.events.is_empty();
        flow.events.push_back(QueuedRealtimeEvent {
            event,
            queued_at: now,
            payload_bytes,
        });
        let units = flow.events.len();
        if was_empty && !flow.scheduled {
            flow.scheduled = true;
            state.ready.push_back(key);
        }
        let retained_bytes = Self::retained_bytes(&state).unwrap_or(usize::MAX);
        drop(state);
        self.record(RealtimeFlowObservation::Queue {
            key,
            units,
            retained_bytes,
        });
        self.ready.notify_one();
        true
    }

    pub(super) fn try_recv(&self) -> Option<QueuedTransportEvent> {
        let now = Instant::now();
        let mut state = self.state.lock();
        if state.retired {
            return None;
        }
        while let Some(key) = state.ready.pop_front() {
            let Some(flow) = state.flows.get_mut(&key) else {
                continue;
            };
            let Some(event) = flow.events.pop_front() else {
                flow.scheduled = false;
                continue;
            };
            if flow.events.is_empty() {
                flow.scheduled = false;
            } else {
                state.ready.push_back(key);
            }
            drop(state);
            self.record(RealtimeFlowObservation::Service {
                key,
                queue_age: now.saturating_duration_since(event.queued_at),
                payload_bytes: event.payload_bytes,
            });
            return Some(event.event);
        }
        None
    }

    pub(super) fn is_empty(&self) -> bool {
        self.state
            .lock()
            .flows
            .values()
            .all(|flow| flow.events.is_empty())
    }

    /// Stop all later flow work and release every queued complete unit.
    /// In-progress assembly reservations remain with their exact owners and
    /// release when those owners return or are cancelled.
    pub(super) fn retire(&self) {
        let queued = {
            let mut state = self.state.lock();
            if state.retired {
                return;
            }
            state.retired = true;
            state.ready.clear();
            state
                .flows
                .values_mut()
                .flat_map(|flow| {
                    flow.scheduled = false;
                    flow.events.drain(..)
                })
                .collect::<Vec<_>>()
        };
        drop(queued);
        self.ready.notify_waiters();
    }
}

pub(super) struct RealtimeFlowLifetime {
    key: RealtimeFlowKey,
    pub(super) registry: Arc<RealtimeFlowRegistry>,
}

impl Drop for RealtimeFlowLifetime {
    fn drop(&mut self) {
        self.registry.remove_flow(self.key);
    }
}

#[derive(Clone)]
pub(super) struct RealtimeFlowPort {
    pub(super) lifetime: Arc<RealtimeFlowLifetime>,
}

impl RealtimeFlowPort {
    pub(super) fn key(&self) -> RealtimeFlowKey {
        self.lifetime.key
    }

    pub(super) fn begin_unit(&self) -> Option<RealtimeAssemblyReservation> {
        self.lifetime
            .registry
            .begin_unit(Arc::clone(&self.lifetime))
    }

    pub(super) fn reserve_output(&self, bytes: usize) -> Option<RealtimeOutputReservation> {
        self.lifetime.registry.reserve_output(self.key(), bytes)
    }

    pub(super) fn enqueue(
        &self,
        event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        self.lifetime
            .registry
            .enqueue(self.key(), event, reservation)
    }
}

pub(super) struct RealtimeAssemblyReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    _lifetime: Arc<RealtimeFlowLifetime>,
    retained_bytes: usize,
    retained_fragments: usize,
    active: bool,
}

impl RealtimeAssemblyReservation {
    fn poison_domain(&self) {
        self.registry.state.lock().accounting_poisoned_by_domain[self.domain.index()] = true;
    }

    pub(super) fn retain_fragment(&mut self, bytes: usize) -> bool {
        let Some(policy) = self
            .registry
            .policy
            .map(EnabledRealtimeConnectorPolicy::flows)
        else {
            return false;
        };
        if bytes > policy.max_inbound_fragment_bytes().get() {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::FragmentOversize,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return false;
        }
        let Some(fragment_count) = self.retained_fragments.checked_add(1) else {
            self.poison_domain();
            return false;
        };
        if fragment_count > policy.max_inbound_fragments_per_unit().get() {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::FragmentCount,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return false;
        }
        let Some(unit_bytes) = self.retained_bytes.checked_add(bytes) else {
            self.poison_domain();
            return false;
        };
        if unit_bytes > self.registry.max_unit_bytes {
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::UnitOversize,
                queue_age: Duration::ZERO,
                payload_bytes: unit_bytes,
            });
            return false;
        }
        let mut state = self.registry.state.lock();
        if state.accounting_poisoned_by_domain[self.domain.index()] {
            return false;
        }
        let policy = policy.byte_budgets();
        let index = self.domain.index();
        let Some(next_domain) = state.retained_bytes_by_domain[index].checked_add(bytes) else {
            state.accounting_poisoned_by_domain[index] = true;
            return false;
        };
        let other = state.retained_bytes_by_domain[1 - index];
        let Some(next_total) = next_domain.checked_add(other) else {
            state.accounting_poisoned_by_domain[index] = true;
            return false;
        };
        let domain_limit = match self.domain {
            RealtimeFlowDomain::InboundQuarantine => policy.max_inbound_bytes().get(),
            RealtimeFlowDomain::OutboundCompatibility => policy.max_outbound_bytes().get(),
        };
        if next_domain > domain_limit || next_total > policy.max_total_bytes().get() {
            drop(state);
            self.registry.record(RealtimeFlowObservation::Drop {
                key: Some(self.key),
                reason: RealtimeFlowDropReason::AggregateBytes,
                queue_age: Duration::ZERO,
                payload_bytes: bytes,
            });
            return false;
        }
        state.retained_bytes_by_domain[index] = next_domain;
        self.retained_bytes = unit_bytes;
        self.retained_fragments = fragment_count;
        let in_progress_units = state.in_progress_units;
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state).unwrap_or(usize::MAX);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Assembly {
            key: self.key,
            in_progress_units,
            retained_bytes,
        });
        true
    }
}

impl Drop for RealtimeAssemblyReservation {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.registry.state.lock();
        let flow_released = state.flows.get_mut(&self.key).is_some_and(|flow| {
            match flow.in_progress_units.checked_sub(1) {
                Some(units) => {
                    flow.in_progress_units = units;
                    true
                }
                None => false,
            }
        });
        if !flow_released {
            state.accounting_poisoned_by_domain[self.domain.index()] = true;
        }
        RealtimeFlowRegistry::release_bytes_locked(&mut state, self.domain, self.retained_bytes);
        RealtimeFlowRegistry::release_unit_locked(&mut state, self.domain);
        let in_progress_units = state.in_progress_units;
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state).unwrap_or(usize::MAX);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Assembly {
            key: self.key,
            in_progress_units,
            retained_bytes,
        });
    }
}

pub(super) struct RealtimeOutputReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    bytes: usize,
    active: bool,
}

impl RealtimeOutputReservation {
    pub(super) fn shrink_to(&mut self, bytes: usize) -> bool {
        if bytes > self.bytes {
            return false;
        }
        let Some(released) = self.bytes.checked_sub(bytes) else {
            self.registry.state.lock().accounting_poisoned_by_domain[self.domain.index()] = true;
            return false;
        };
        if released != 0 {
            let mut state = self.registry.state.lock();
            if !RealtimeFlowRegistry::release_bytes_locked(&mut state, self.domain, released) {
                return false;
            }
            self.bytes = bytes;
        }
        true
    }

    pub(super) fn into_payload_lease(mut self) -> RealtimePayloadLease {
        self.active = false;
        RealtimePayloadLease(Arc::new(RealtimePayloadReservation {
            registry: Arc::clone(&self.registry),
            key: self.key,
            domain: self.domain,
            bytes: self.bytes,
        }))
    }
}

impl Drop for RealtimeOutputReservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.registry.state.lock();
            RealtimeFlowRegistry::release_bytes_locked(&mut state, self.domain, self.bytes);
        }
    }
}

struct RealtimePayloadReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    bytes: usize,
}

impl Drop for RealtimePayloadReservation {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock();
        RealtimeFlowRegistry::release_bytes_locked(&mut state, self.domain, self.bytes);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state).unwrap_or(usize::MAX);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Queue {
            key: self.key,
            units: 0,
            retained_bytes,
        });
    }
}

#[derive(Clone)]
pub(super) struct RealtimePayloadLease(Arc<RealtimePayloadReservation>);

impl std::fmt::Debug for RealtimePayloadLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealtimePayloadLease")
            .field("key", &self.0.key)
            .field("bytes", &self.0.bytes)
            .finish()
    }
}
