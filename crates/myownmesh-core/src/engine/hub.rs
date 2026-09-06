//! Bounded, session-local hub maintenance.
//!
//! A hub controller is a local planner adapter.  It never elects a hub,
//! applies remote configuration, signs facts, or forwards advertisements.
//! The only wire value it emits is the advisory HubAdvertisement, sent through
//! the normal exact-owner application gate.

use std::num::NonZeroU32;
use std::time::Instant;

use rand_core::RngCore;

use crate::config::{HubPolicyConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::protocol::{configuration_digest, HubAdvertisement, HubTrickleProfile};
use crate::resource::{LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease};
use crate::semantic::{DeviceId, MeshContextId};

use super::peer_registry::PeerOwnerToken;
use super::trickle::{TricklePolicy, TricklePoll, TrickleTimer};

#[derive(Clone)]
struct HubCursor {
    origin: DeviceId,
    binding_namespace: [u8; 16],
    binding_epoch: u64,
    sequence: u64,
    pending_request: Option<u64>,
    pending_started_ms: u64,
    after: Option<DeviceId>,
    pending_binding: Option<([u8; 16], u64)>,
    pending_max_peers: u16,
}

/// Fixed-size transport-lab metadata for the bounded discovery adapter.  This
/// deliberately contains no peer IDs, payloads, or event history; the IDs
/// remain private to the live cursors and are never exposed as diagnostics.
#[cfg(feature = "transport-lab")]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HubDiscoveryDiagnostics {
    pub(crate) configured_hubs: u64,
    pub(crate) pending_requests: u64,
    pub(crate) requests_started: u64,
    pub(crate) requests_bound: u64,
    pub(crate) responses_accepted: u64,
    pub(crate) responses_rejected: u64,
    pub(crate) pages_accepted: u64,
    pub(crate) continuation_pages_accepted: u64,
    pub(crate) cursor_advances: u64,
    pub(crate) cursors_with_after: u64,
    pub(crate) last_request_after: Option<[u8; 32]>,
    pub(crate) last_accepted_request_after: Option<[u8; 32]>,
    pub(crate) last_accepted_first: Option<[u8; 32]>,
    pub(crate) last_accepted_last: Option<[u8; 32]>,
    pub(crate) exploration_cursor: u64,
    pub(crate) last_page_len: u16,
    pub(crate) last_page_has_more: bool,
    pub(crate) exploration_sequence: u64,
    pub(crate) next_exploration_ms: u64,
}

/// The independent cadence gate for parent maintenance. Directory replies and
/// advertisement delivery do not touch this state, so a healthy parent does
/// not turn exploration into a synchronized retry loop.
#[derive(Clone, Copy)]
struct ParentAttemptPacer {
    next_due_ms: u64,
    last_now_ms: Option<u64>,
    clock_fenced: bool,
}

impl ParentAttemptPacer {
    fn new<R: RngCore>(interval_ms: u64, rng: &mut R) -> Result<Self> {
        let jitter = Self::jitter(interval_ms, rng)?;
        let next_due_ms = interval_ms
            .checked_add(jitter)
            .ok_or_else(|| Error::Network("parent attempt deadline overflowed".into()))?;
        Ok(Self {
            next_due_ms,
            last_now_ms: None,
            clock_fenced: false,
        })
    }

    fn jitter<R: RngCore>(maximum: u64, rng: &mut R) -> Result<u64> {
        let upper_exclusive = maximum
            .checked_add(1)
            .ok_or_else(|| Error::Network("parent attempt jitter range overflowed".into()))?;
        let threshold = upper_exclusive.wrapping_neg() % upper_exclusive;
        loop {
            let sample = rng.next_u64();
            if sample >= threshold {
                return Ok(sample % upper_exclusive);
            }
        }
    }

    fn prepare<R: RngCore>(&mut self, now_ms: u64, interval_ms: u64, rng: &mut R) -> Result<bool> {
        if self.clock_fenced {
            return Err(Error::Network("parent attempt clock is fenced".into()));
        }
        if self.last_now_ms.is_some_and(|last| now_ms < last) {
            return Err(Error::Network(
                "parent attempt clock moved backwards".into(),
            ));
        }
        self.last_now_ms = Some(now_ms);
        if now_ms < self.next_due_ms {
            return Ok(false);
        }
        let jitter = match Self::jitter(interval_ms, rng) {
            Ok(jitter) => jitter,
            Err(error) => {
                self.clock_fenced = true;
                return Err(error);
            }
        };
        let delay = match interval_ms.checked_add(jitter) {
            Some(delay) => delay,
            None => {
                self.clock_fenced = true;
                return Err(Error::Network("parent attempt delay overflowed".into()));
            }
        };
        self.next_due_ms = match now_ms.checked_add(delay) {
            Some(next_due_ms) => next_due_ms,
            None => {
                self.clock_fenced = true;
                return Err(Error::Network("parent attempt deadline overflowed".into()));
            }
        };
        Ok(true)
    }
}

/// The local owner of one optional hub-advertisement schedule and its replay
/// cursors.  Cursors are fixed to the configured hub count and carry the
/// exact owner binding, so a replacement installation starts a new sequence.
pub(crate) struct HubController {
    policy: HubPolicyConfig,
    context_id: MeshContextId,
    local_id: DeviceId,
    digest: [u8; 32],
    timer: TrickleTimer,
    started_at: Instant,
    cursors: Box<[HubCursor]>,
    recipient_after: Option<DeviceId>,
    exploration_cursor: usize,
    exploration_sequence: u64,
    next_exploration_ms: u64,
    parent_attempt: ParentAttemptPacer,
    inbound_window_started_ms: u64,
    inbound_window_count: u64,
    #[cfg(feature = "transport-lab")]
    discovery_pending_requests: u64,
    #[cfg(feature = "transport-lab")]
    discovery_requests_started: u64,
    #[cfg(feature = "transport-lab")]
    discovery_requests_bound: u64,
    #[cfg(feature = "transport-lab")]
    discovery_responses_accepted: u64,
    #[cfg(feature = "transport-lab")]
    discovery_responses_rejected: u64,
    #[cfg(feature = "transport-lab")]
    discovery_pages_accepted: u64,
    #[cfg(feature = "transport-lab")]
    discovery_continuation_pages_accepted: u64,
    #[cfg(feature = "transport-lab")]
    discovery_cursor_advances: u64,
    #[cfg(feature = "transport-lab")]
    discovery_cursors_with_after: u64,
    #[cfg(feature = "transport-lab")]
    discovery_last_request_after: Option<[u8; 32]>,
    #[cfg(feature = "transport-lab")]
    discovery_last_accepted_request_after: Option<[u8; 32]>,
    #[cfg(feature = "transport-lab")]
    discovery_last_accepted_first: Option<[u8; 32]>,
    #[cfg(feature = "transport-lab")]
    discovery_last_accepted_last: Option<[u8; 32]>,
    #[cfg(feature = "transport-lab")]
    discovery_last_page_len: u16,
    #[cfg(feature = "transport-lab")]
    discovery_last_page_has_more: bool,
    _root_lease: ResourceLease,
}

impl HubController {
    pub(crate) fn root_claim(hub_count: usize) -> Result<ResourceClaim> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(
                std::mem::size_of::<HubCursor>()
                    .checked_mul(hub_count)
                    .ok_or_else(|| Error::Config("hub cursor claim overflows".into()))?,
            )
            .ok_or_else(|| Error::Config("hub controller claim overflows".into()))?;
        Ok(ResourceClaim::single(
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes)
                .map_err(|_| Error::Config("hub controller claim exceeds u64".into()))?,
        ))
    }

    pub(crate) fn new(
        policy: HubPolicyConfig,
        topology: &TopologyMode,
        context_id: MeshContextId,
        local_id: DeviceId,
        resources: &LocalApplicationResourceScope,
    ) -> Result<Option<Self>> {
        if !policy.validate() {
            return Err(Error::Config("hub policy is invalid".into()));
        }
        let raw_hubs = match topology {
            TopologyMode::Hubs { hubs, .. } | TopologyMode::HubTree { hubs, .. } => hubs,
            _ => return Ok(None),
        };
        // The controller lease is acquired before semantic interning and
        // before the retained cursor table is built.  DeviceId stores an
        // interned canonical string, so charge that raw backing explicitly;
        // the fixed cursor handles are covered by root_claim.
        let identity_bytes = raw_hubs
            .iter()
            .try_fold(0usize, |bytes, hub| bytes.checked_add(hub.len()))
            .ok_or_else(|| Error::Config("hub identity backing overflows".into()))?;
        let identity_claim = ResourceClaim::single(
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(identity_bytes)
                .map_err(|_| Error::Config("hub identity backing exceeds u64".into()))?,
        );
        let normalized_scratch_bytes = raw_hubs
            .len()
            .checked_mul(std::mem::size_of::<DeviceId>())
            .ok_or_else(|| Error::Config("hub normalization backing overflows".into()))?;
        let normalized_scratch_claim = ResourceClaim::single(
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(normalized_scratch_bytes)
                .map_err(|_| Error::Config("hub normalization backing exceeds u64".into()))?,
        );
        let claim = Self::root_claim(raw_hubs.len())?
            .checked_add(identity_claim)
            .and_then(|claim| claim.checked_add(normalized_scratch_claim))
            .map_err(|_| Error::Config("hub controller claim overflows".into()))?;
        let root_lease = resources
            .acquire(claim)
            .map_err(|error| Error::Network(format!("hub controller resource refusal: {error}")))?;
        let (hubs, redundancy, tree_root, tree_backup) = match topology {
            TopologyMode::Hubs {
                hubs,
                spoke_redundancy,
            } => (
                hubs,
                spoke_redundancy.unwrap_or(TopologyMode::DEFAULT_SPOKE_REDUNDANCY),
                None,
                0,
            ),
            TopologyMode::HubTree {
                root,
                hubs,
                backup_candidates,
            } => {
                let root = DeviceId::from_canonical_str(root)
                    .map_err(|_| Error::Config("hub-tree root is not canonical".into()))?;
                (hubs, 1, Some(root), *backup_candidates)
            }
            _ => unreachable!("raw_hubs already selected this topology"),
        };
        let mut normalized = hubs
            .iter()
            .map(|hub| {
                DeviceId::from_canonical_str(hub)
                    .map_err(|_| Error::Config("hub identity is not canonical".into()))
            })
            .collect::<Result<Vec<_>>>()?;
        normalized.sort();
        normalized.dedup();
        if normalized.is_empty() {
            return Ok(None);
        }
        if redundancy == 0 {
            return Err(Error::Config("hub topology redundancy is zero".into()));
        }
        let trickle = TricklePolicy::checked(
            policy.trickle_imin_ms,
            policy.trickle_imax_ms,
            NonZeroU32::new(policy.trickle_redundancy)
                .ok_or_else(|| Error::Config("hub Trickle redundancy is zero".into()))?,
            policy.trickle_reset_window_ms,
            NonZeroU32::new(policy.trickle_max_resets_per_window)
                .ok_or_else(|| Error::Config("hub Trickle reset budget is zero".into()))?,
        )
        .map_err(|error| Error::Config(format!("hub Trickle policy rejected: {error:?}")))?;
        let mut rng = rand_core::OsRng;
        let timer = TrickleTimer::start(trickle, 0, &mut rng)
            .map_err(|error| Error::Config(format!("hub Trickle start rejected: {error:?}")))?;
        let parent_attempt = ParentAttemptPacer::new(policy.exploration_interval_ms, &mut rng)?;
        let digest = tree_root.map_or_else(
            || {
                configuration_digest(
                    &normalized,
                    redundancy,
                    HubTrickleProfile::new(
                        policy.trickle_imin_ms,
                        policy.trickle_imax_ms,
                        u64::from(policy.trickle_redundancy),
                        policy.trickle_reset_window_ms,
                        u64::from(policy.trickle_max_resets_per_window),
                    ),
                )
            },
            |root| {
                crate::protocol::hub_tree_configuration_digest(
                    context_id,
                    crate::protocol::HubTreeTopologyKind::ShallowV1,
                    &root,
                    &normalized,
                    tree_backup,
                    HubTrickleProfile::new(
                        policy.trickle_imin_ms,
                        policy.trickle_imax_ms,
                        u64::from(policy.trickle_redundancy),
                        policy.trickle_reset_window_ms,
                        u64::from(policy.trickle_max_resets_per_window),
                    ),
                )
            },
        );
        let cursors: Box<[HubCursor]> = normalized
            .into_iter()
            .map(|origin| HubCursor {
                origin,
                binding_namespace: [0; 16],
                binding_epoch: 0,
                sequence: 0,
                pending_request: None,
                pending_started_ms: 0,
                after: None,
                pending_binding: None,
                pending_max_peers: 0,
            })
            .collect();
        Ok(Some(Self {
            policy,
            context_id,
            local_id,
            digest,
            timer,
            started_at: Instant::now(),
            cursors,
            recipient_after: None,
            exploration_cursor: 0,
            exploration_sequence: 0,
            next_exploration_ms: policy.exploration_interval_ms,
            parent_attempt,
            inbound_window_started_ms: 0,
            inbound_window_count: 0,
            #[cfg(feature = "transport-lab")]
            discovery_pending_requests: 0,
            #[cfg(feature = "transport-lab")]
            discovery_requests_started: 0,
            #[cfg(feature = "transport-lab")]
            discovery_requests_bound: 0,
            #[cfg(feature = "transport-lab")]
            discovery_responses_accepted: 0,
            #[cfg(feature = "transport-lab")]
            discovery_responses_rejected: 0,
            #[cfg(feature = "transport-lab")]
            discovery_pages_accepted: 0,
            #[cfg(feature = "transport-lab")]
            discovery_continuation_pages_accepted: 0,
            #[cfg(feature = "transport-lab")]
            discovery_cursor_advances: 0,
            #[cfg(feature = "transport-lab")]
            discovery_cursors_with_after: 0,
            #[cfg(feature = "transport-lab")]
            discovery_last_request_after: None,
            #[cfg(feature = "transport-lab")]
            discovery_last_accepted_request_after: None,
            #[cfg(feature = "transport-lab")]
            discovery_last_accepted_first: None,
            #[cfg(feature = "transport-lab")]
            discovery_last_accepted_last: None,
            #[cfg(feature = "transport-lab")]
            discovery_last_page_len: 0,
            #[cfg(feature = "transport-lab")]
            discovery_last_page_has_more: false,
            _root_lease: root_lease,
        }))
    }

    #[cfg(feature = "transport-lab")]
    fn discovery_rejected(&mut self) {
        self.discovery_responses_rejected = self.discovery_responses_rejected.saturating_add(1);
    }

    fn now_ms(&self) -> u64 {
        u64::try_from(self.started_at.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn exploration_jitter(maximum: u64) -> u64 {
        let mut rng = rand_core::OsRng;
        if maximum == u64::MAX {
            return rng.next_u64();
        }
        let range = maximum + 1;
        let limit = u64::MAX - (u64::MAX % range);
        loop {
            let sample = rng.next_u64();
            if sample < limit {
                return sample % range;
            }
        }
    }

    fn cursor_mut(&mut self, origin: &DeviceId) -> Option<&mut HubCursor> {
        self.cursors
            .iter_mut()
            .find(|cursor| &cursor.origin == origin)
    }

    /// Admit an advertisement only from the exact current owner that carried
    /// it.  The digest is a local topology/schedule commitment, never a
    /// remote configuration instruction.
    pub(crate) fn observe_advertisement(
        &mut self,
        owner: &PeerOwnerToken,
        advertisement: &HubAdvertisement,
    ) -> bool {
        if advertisement.context_id() != self.context_id
            || advertisement.origin() == &self.local_id
            || advertisement.configuration_digest() != self.digest
            || owner.device_id() != advertisement.origin().to_string()
        {
            return false;
        }
        let binding = owner.binding_coordinate();
        let Some((current_namespace, current_epoch, current_sequence)) = self
            .cursors
            .iter()
            .find(|cursor| &cursor.origin == advertisement.origin())
            .map(|cursor| {
                (
                    cursor.binding_namespace,
                    cursor.binding_epoch,
                    cursor.sequence,
                )
            })
        else {
            return false;
        };
        let binding_changed = current_namespace != binding.binding_namespace
            || current_epoch != binding.binding_epoch;
        // A replacement owner gets a fresh replay namespace.  Reset that
        // cursor before comparing sequence numbers; otherwise a valid lower
        // sequence from the new binding is rejected by the predecessor's
        // high-water mark.
        if binding_changed {
            let Some(cursor) = self.cursor_mut(advertisement.origin()) else {
                return false;
            };
            cursor.binding_namespace = binding.binding_namespace;
            cursor.binding_epoch = binding.binding_epoch;
            cursor.sequence = 0;
        }
        if advertisement.sequence() <= current_sequence && !binding_changed {
            return false;
        }
        if self.timer.observe_consistent().is_err() {
            return false;
        }
        let Some(cursor) = self.cursor_mut(advertisement.origin()) else {
            return false;
        };
        cursor.sequence = advertisement.sequence();
        true
    }

    /// Whether this controller's local identity is one of the configured hubs.
    pub(crate) fn local_is_hub(&self) -> bool {
        self.cursors
            .iter()
            .any(|cursor| cursor.origin == self.local_id)
    }

    pub(crate) fn configured_hub(&self, device_id: &str) -> bool {
        self.cursors
            .iter()
            .any(|cursor| cursor.origin.to_string() == device_id)
    }

    /// Advance the independent parent-attempt gate. The deadline is advanced
    /// before the caller resolves an owner or starts transport work, so an
    /// unavailable owner cannot turn one state-watch tick into a retry loop.
    pub(crate) fn prepare_parent_attempt(&mut self) -> Result<bool> {
        let now = self.now_ms();
        let mut rng = rand_core::OsRng;
        self.parent_attempt
            .prepare(now, self.policy.exploration_interval_ms, &mut rng)
    }

    /// Prepare one bounded unicast directory query. Unlike advertisements,
    /// this cadence is never suppressed by Trickle; it is only sent to a
    /// configured current hub and carries no address or authority data.
    pub(crate) fn prepare_discovery(
        &mut self,
    ) -> Option<(DeviceId, crate::protocol::HubDiscoveryRequest)> {
        let now = self.now_ms();
        if now < self.next_exploration_ms {
            return None;
        }
        #[cfg(feature = "transport-lab")]
        let mut expired_pending = 0u64;
        for cursor in &mut self.cursors {
            if cursor.pending_request.is_some()
                && now.saturating_sub(cursor.pending_started_ms)
                    >= self.policy.exploration_interval_ms
            {
                cursor.pending_request = None;
                cursor.pending_binding = None;
                #[cfg(feature = "transport-lab")]
                {
                    expired_pending = expired_pending.saturating_add(1);
                }
            }
        }
        #[cfg(feature = "transport-lab")]
        {
            self.discovery_pending_requests = self
                .discovery_pending_requests
                .saturating_sub(expired_pending);
        }
        let len = self.cursors.len();
        for offset in 0..len {
            let index = (self.exploration_cursor + offset) % len;
            let (target, after) = {
                let cursor = &self.cursors[index];
                if cursor.origin == self.local_id || cursor.pending_request.is_some() {
                    continue;
                }
                (cursor.origin.clone(), cursor.after.clone())
            };
            self.exploration_cursor = (index + 1) % len;
            self.exploration_sequence = self.exploration_sequence.checked_add(1)?;
            let sequence = self.exploration_sequence;
            let request = crate::protocol::HubDiscoveryRequest::new(
                self.context_id,
                sequence,
                after,
                self.policy.max_exploration_peers_per_reply,
            )
            .ok()?;
            {
                let cursor = &mut self.cursors[index];
                cursor.pending_request = Some(sequence);
                cursor.pending_started_ms = now;
                cursor.pending_binding = None;
                cursor.pending_max_peers = self.policy.max_exploration_peers_per_reply;
            }
            #[cfg(feature = "transport-lab")]
            {
                self.discovery_pending_requests = self.discovery_pending_requests.saturating_add(1);
                self.discovery_requests_started = self.discovery_requests_started.saturating_add(1);
            }
            let delay =
                self.policy
                    .exploration_interval_ms
                    .saturating_add(Self::exploration_jitter(
                        self.policy.exploration_interval_ms,
                    ));
            self.next_exploration_ms = now.saturating_add(delay);
            return Some((target, request));
        }
        None
    }

    pub(crate) fn bind_discovery_request(
        &mut self,
        target: &DeviceId,
        owner: &PeerOwnerToken,
    ) -> bool {
        let binding = owner.binding_coordinate();
        let bound = {
            let Some(cursor) = self.cursor_mut(target) else {
                return false;
            };
            if cursor.pending_request.is_none() {
                return false;
            }
            cursor.pending_binding = Some((binding.binding_namespace, binding.binding_epoch));
            true
        };
        #[cfg(feature = "transport-lab")]
        {
            if bound {
                self.discovery_requests_bound = self.discovery_requests_bound.saturating_add(1);
                self.discovery_last_request_after = self
                    .cursor_mut(target)
                    .and_then(|cursor| cursor.after.as_ref().map(DeviceId::as_bytes));
            }
        }
        bound
    }

    pub(crate) fn observe_discovery_response(
        &mut self,
        owner: &PeerOwnerToken,
        response: &crate::protocol::HubDiscoveryResponse,
    ) -> Option<Vec<DeviceId>> {
        if response.context_id() != self.context_id {
            #[cfg(feature = "transport-lab")]
            self.discovery_rejected();
            return None;
        }
        let Ok(origin) = DeviceId::from_canonical_str(owner.device_id()) else {
            #[cfg(feature = "transport-lab")]
            self.discovery_rejected();
            return None;
        };
        let now = self.now_ms();
        let exploration_interval = self.policy.exploration_interval_ms;
        let Some(cursor_index) = self
            .cursors
            .iter()
            .position(|cursor| cursor.origin == origin)
        else {
            #[cfg(feature = "transport-lab")]
            self.discovery_rejected();
            return None;
        };
        let (
            pending_request,
            pending_started_ms,
            pending_max_peers,
            pending_after,
            pending_binding,
        ) = {
            let cursor = &self.cursors[cursor_index];
            (
                cursor.pending_request,
                cursor.pending_started_ms,
                cursor.pending_max_peers,
                cursor.after.clone(),
                cursor.pending_binding,
            )
        };
        if pending_request != Some(response.request_sequence()) {
            #[cfg(feature = "transport-lab")]
            self.discovery_rejected();
            return None;
        }
        let binding = owner.binding_coordinate();
        if pending_binding != Some((binding.binding_namespace, binding.binding_epoch)) {
            {
                let cursor = &mut self.cursors[cursor_index];
                cursor.pending_request = None;
                cursor.pending_binding = None;
            }
            #[cfg(feature = "transport-lab")]
            {
                self.discovery_pending_requests = self.discovery_pending_requests.saturating_sub(1);
                self.discovery_rejected();
            }
            return None;
        }
        if now.saturating_sub(pending_started_ms) >= exploration_interval
            || response.peers().len() > usize::from(pending_max_peers)
            || (pending_after.is_some()
                && response
                    .peers()
                    .first()
                    .is_some_and(|first| first <= pending_after.as_ref().expect("checked above")))
        {
            {
                let cursor = &mut self.cursors[cursor_index];
                cursor.pending_request = None;
                cursor.pending_binding = None;
            }
            #[cfg(feature = "transport-lab")]
            {
                self.discovery_pending_requests = self.discovery_pending_requests.saturating_sub(1);
                self.discovery_rejected();
            }
            return None;
        }
        let next_after = response.next_after().cloned();
        {
            let cursor = &mut self.cursors[cursor_index];
            cursor.pending_request = None;
            cursor.pending_binding = None;
            cursor.after = next_after.clone();
        }
        #[cfg(feature = "transport-lab")]
        let accepted_first = response.peers().first().map(DeviceId::as_bytes);
        #[cfg(feature = "transport-lab")]
        let accepted_last = response.peers().last().map(DeviceId::as_bytes);
        #[cfg(feature = "transport-lab")]
        let accepted_after = pending_after.as_ref().map(DeviceId::as_bytes);
        #[cfg(feature = "transport-lab")]
        {
            self.discovery_pending_requests = self.discovery_pending_requests.saturating_sub(1);
            self.discovery_responses_accepted = self.discovery_responses_accepted.saturating_add(1);
            self.discovery_pages_accepted = self.discovery_pages_accepted.saturating_add(1);
            if pending_after.is_some() && !response.peers().is_empty() {
                self.discovery_continuation_pages_accepted =
                    self.discovery_continuation_pages_accepted.saturating_add(1);
            }
            if next_after.is_some() {
                self.discovery_cursor_advances = self.discovery_cursor_advances.saturating_add(1);
            }
            match (pending_after.is_some(), next_after.is_some()) {
                (false, true) => {
                    self.discovery_cursors_with_after =
                        self.discovery_cursors_with_after.saturating_add(1);
                }
                (true, false) => {
                    self.discovery_cursors_with_after =
                        self.discovery_cursors_with_after.saturating_sub(1);
                }
                _ => {}
            }
            self.discovery_last_accepted_request_after = accepted_after;
            self.discovery_last_accepted_first = accepted_first;
            self.discovery_last_accepted_last = accepted_last;
            self.discovery_last_page_len =
                u16::try_from(response.peers().len()).unwrap_or(u16::MAX);
            self.discovery_last_page_has_more = next_after.is_some();
        }
        Some(response.peers().to_vec())
    }

    /// Return aggregate discovery progress without exposing cursor IDs or
    /// retaining an unbounded event log.  The cursor itself remains private so
    /// only the exact-owner response path can advance it.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn discovery_diagnostics(&self) -> HubDiscoveryDiagnostics {
        HubDiscoveryDiagnostics {
            configured_hubs: u64::try_from(self.cursors.len()).unwrap_or(u64::MAX),
            pending_requests: self.discovery_pending_requests,
            requests_started: self.discovery_requests_started,
            requests_bound: self.discovery_requests_bound,
            responses_accepted: self.discovery_responses_accepted,
            responses_rejected: self.discovery_responses_rejected,
            pages_accepted: self.discovery_pages_accepted,
            continuation_pages_accepted: self.discovery_continuation_pages_accepted,
            cursor_advances: self.discovery_cursor_advances,
            cursors_with_after: self.discovery_cursors_with_after,
            last_request_after: self.discovery_last_request_after,
            last_accepted_request_after: self.discovery_last_accepted_request_after,
            last_accepted_first: self.discovery_last_accepted_first,
            last_accepted_last: self.discovery_last_accepted_last,
            exploration_cursor: u64::try_from(self.exploration_cursor).unwrap_or(u64::MAX),
            last_page_len: self.discovery_last_page_len,
            last_page_has_more: self.discovery_last_page_has_more,
            exploration_sequence: self.exploration_sequence,
            next_exploration_ms: self.next_exploration_ms,
        }
    }

    pub(crate) fn max_exploration_probes_per_pass(&self) -> usize {
        usize::try_from(self.policy.max_exploration_probes_per_pass).unwrap_or(usize::MAX)
    }

    /// Apply one finite inbound reply budget. This is deliberately aggregate
    /// rather than a peer-sized map: untrusted requesters cannot allocate
    /// persistent rate-limit state, while exact current-owner admission still
    /// remains the caller's required fence.
    pub(crate) fn accept_discovery_request(&mut self) -> bool {
        let now = self.now_ms();
        if now.saturating_sub(self.inbound_window_started_ms) >= self.policy.exploration_interval_ms
        {
            self.inbound_window_started_ms = now;
            self.inbound_window_count = 0;
        }
        let limit = self.policy.max_exploration_probes_per_pass;
        if self.inbound_window_count >= limit {
            return false;
        }
        self.inbound_window_count = self.inbound_window_count.saturating_add(1);
        true
    }

    /// Prepare one bounded Trickle decision without doing transport work while
    /// the controller mutex is held.
    pub(crate) fn prepare_poll(&mut self) -> Option<(HubAdvertisement, usize)> {
        if !self.local_is_hub() {
            return None;
        }
        let mut rng = rand_core::OsRng;
        let Ok(TricklePoll::Transmit { .. }) = self.timer.poll(self.now_ms(), &mut rng) else {
            return None;
        };
        let sequence = self.timer.generation().saturating_add(1);
        let advertisement = HubAdvertisement::new(
            self.context_id,
            self.local_id.clone(),
            sequence,
            self.digest,
        )
        .ok()?;
        Some((
            advertisement,
            usize::try_from(self.policy.max_advertisements_per_pass).ok()?,
        ))
    }

    pub(crate) fn recipient_after(&self) -> Option<DeviceId> {
        self.recipient_after.clone()
    }

    /// Advance before transport sends. The identity cursor is retained across
    /// registry iteration order changes, and failed sends still consume the
    /// attempt so an unavailable early recipient cannot starve later peers.
    pub(crate) fn advance_recipient_after(&mut self, recipient: DeviceId) {
        self.recipient_after = Some(recipient);
    }

    pub(crate) fn acknowledge_delivery(&mut self) {
        let _ = self.timer.acknowledge_repair();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Copy)]
    struct FixedRng(u64);

    impl RngCore for FixedRng {
        fn next_u32(&mut self) -> u32 {
            self.0 as u32
        }

        fn next_u64(&mut self) -> u64 {
            self.0
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for byte in dest {
                *byte = self.0 as u8;
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    struct RejectThenAcceptRng {
        samples: [u64; 2],
        index: usize,
        calls: u8,
    }

    impl RngCore for RejectThenAcceptRng {
        fn next_u32(&mut self) -> u32 {
            self.next_u64() as u32
        }

        fn next_u64(&mut self) -> u64 {
            let sample = self.samples.get(self.index).copied().unwrap_or(11);
            self.index = self.index.saturating_add(1);
            self.calls = self.calls.saturating_add(1);
            sample
        }

        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(8) {
                let bytes = self.next_u64().to_le_bytes();
                let length = chunk.len();
                chunk.copy_from_slice(&bytes[..length]);
            }
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> std::result::Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    #[test]
    fn parent_attempt_jitter_rejection_progresses_in_two_draws() {
        let mut rng = RejectThenAcceptRng {
            samples: [0, 11],
            index: 0,
            calls: 0,
        };
        assert_eq!(
            ParentAttemptPacer::jitter(10, &mut rng).expect("bounded jitter"),
            0
        );
        assert_eq!(rng.calls, 2);
    }

    #[test]
    fn parent_attempt_is_minimum_jittered_and_interval_paced() {
        let mut zero_remainder = FixedRng(11);
        let mut pacer =
            ParentAttemptPacer::new(10, &mut zero_remainder).expect("valid parent cadence");
        assert_eq!(pacer.next_due_ms, 10);
        assert!(!pacer
            .prepare(9, 10, &mut zero_remainder)
            .expect("before deadline"));
        assert!(pacer
            .prepare(10, 10, &mut zero_remainder)
            .expect("at deadline"));
        assert_eq!(pacer.next_due_ms, 20);
        assert!(!pacer
            .prepare(10, 10, &mut zero_remainder)
            .expect("repeated same-tick poll is paced"));

        let mut max = FixedRng(u64::MAX);
        let jittered = ParentAttemptPacer::new(10, &mut max).expect("valid jitter");
        assert_eq!(jittered.next_due_ms, 10 + u64::MAX % 11);
        assert!(jittered.next_due_ms >= 10);
        assert!(jittered.next_due_ms <= 20);
    }

    #[test]
    fn parent_attempt_rejects_backward_clock_and_fences_overflow() {
        let mut zero_remainder = FixedRng(11);
        let mut pacer =
            ParentAttemptPacer::new(10, &mut zero_remainder).expect("valid parent cadence");
        assert!(pacer
            .prepare(10, 10, &mut zero_remainder)
            .expect("at deadline"));
        assert!(pacer.prepare(9, 10, &mut zero_remainder).is_err());
        assert!(!pacer
            .prepare(10, 10, &mut zero_remainder)
            .expect("backward sample does not reset cadence"));

        let mut overflowing = ParentAttemptPacer {
            next_due_ms: 0,
            last_now_ms: Some(u64::MAX - 2),
            clock_fenced: false,
        };
        assert!(overflowing
            .prepare(u64::MAX - 1, 10, &mut zero_remainder)
            .is_err());
        assert!(overflowing.clock_fenced);
        assert!(overflowing
            .prepare(u64::MAX - 1, 10, &mut zero_remainder)
            .is_err());
    }
}
