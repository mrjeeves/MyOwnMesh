//! Bounded topology routing for directed application frames.
//!
//! This module owns routing mechanics, not peer authority.  The caller supplies
//! a topology snapshot and the peer-registry adapter resolves each candidate
//! through the exact current promoted/authenticated/approved-session fence.
//! A carrier, an authenticated handshake, or a raw device id is not an
//! application routing capability.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, Mutex};

use bytes::Bytes;
use ed25519_dalek::SigningKey;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;

use crate::protocol::{RoutedApplicationEnvelope, RoutedApplicationError, RoutedApplicationLimits};
use crate::resource::{
    LeasedMap, LocalApplicationResourceScope, ResourceClass, ResourceUnavailable,
};
use crate::semantic::{DeviceId, MeshContextId};
use crate::topology::Topology;

/// Fixed-width replay identity.  All fields are part of the signed route
/// context; no retained key hides an unfunded string allocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct RouteKey {
    context_id: MeshContextId,
    origin: [u8; 32],
    destination: [u8; 32],
    message_id: [u8; 16],
}

impl RouteKey {
    pub(crate) const fn new(
        context_id: MeshContextId,
        origin: [u8; 32],
        destination: [u8; 32],
        message_id: [u8; 16],
    ) -> Self {
        Self {
            context_id,
            origin,
            destination,
            message_id,
        }
    }

    pub(crate) fn from_envelope(envelope: &RoutedApplicationEnvelope) -> Self {
        Self::new(
            envelope.context_id(),
            envelope.origin().as_bytes(),
            envelope.destination().as_bytes(),
            envelope.message_id(),
        )
    }
}

/// Checked owner-selected routing limits.  The config layer converts its
/// checked `RoutingPolicyConfig` into this value; this module has no hidden
/// workload defaults.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct RoutingPolicy {
    max_next_hops: usize,
    max_parallel_routes: usize,
    max_envelope_bytes: u64,
    max_dedup_entries: usize,
    max_dedup_bytes: u64,
    max_hop_budget: u8,
}

impl RoutingPolicy {
    pub(crate) fn checked(
        max_next_hops: usize,
        max_parallel_routes: usize,
        max_envelope_bytes: u64,
        max_dedup_entries: usize,
        max_dedup_bytes: u64,
        max_hop_budget: u8,
    ) -> Result<Self, RoutePolicyRefusal> {
        if max_next_hops == 0
            || max_parallel_routes == 0
            || max_envelope_bytes == 0
            || max_dedup_entries == 0
            || max_dedup_bytes == 0
            || max_hop_budget == 0
        {
            return Err(RoutePolicyRefusal::Zero);
        }
        if max_parallel_routes > max_next_hops {
            return Err(RoutePolicyRefusal::InconsistentParallelism);
        }
        let max_payload_bytes =
            usize::try_from(max_envelope_bytes).map_err(|_| RoutePolicyRefusal::Overflow)?;
        let _ = RoutedApplicationLimits::checked(max_payload_bytes, max_hop_budget)
            .map_err(RoutePolicyRefusal::ProtocolLimits)?;
        Ok(Self {
            max_next_hops,
            max_parallel_routes,
            max_envelope_bytes,
            max_dedup_entries,
            max_dedup_bytes,
            max_hop_budget,
        })
    }

    pub(crate) const fn max_next_hops(self) -> usize {
        self.max_next_hops
    }

    pub(crate) const fn max_parallel_routes(self) -> usize {
        self.max_parallel_routes
    }

    pub(crate) const fn max_envelope_bytes(self) -> u64 {
        self.max_envelope_bytes
    }

    pub(crate) const fn max_dedup_entries(self) -> usize {
        self.max_dedup_entries
    }

    pub(crate) const fn max_dedup_bytes(self) -> u64 {
        self.max_dedup_bytes
    }

    pub(crate) const fn max_hop_budget(self) -> u8 {
        self.max_hop_budget
    }

    fn protocol_limits(self) -> RoutedApplicationLimits {
        RoutedApplicationLimits::checked(
            usize::try_from(self.max_envelope_bytes).expect("checked routing policy fits usize"),
            self.max_hop_budget,
        )
        .expect("checked routing policy satisfies protocol limits")
    }
}

#[derive(Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum RoutePolicyRefusal {
    #[error("routing policy values must be nonzero")]
    Zero,
    #[error("max_parallel_routes cannot exceed max_next_hops")]
    InconsistentParallelism,
    #[error("routing policy arithmetic overflowed")]
    Overflow,
    #[error("routing policy exceeds protocol limits: {0}")]
    ProtocolLimits(RoutedApplicationError),
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteRefusal {
    #[error("routed envelope was refused: {0}")]
    Envelope(RoutedApplicationError),
    #[error("route TTL exceeds the owner policy")]
    TtlExceedsPolicy,
    #[error("local node is not an authorized forwarder")]
    NotForwarder,
    #[error("route origin is not admitted by the owner policy")]
    OriginNotAdmitted,
    #[error("topology returned no usable next hop")]
    NoRoute,
    #[error("topology returned a next hop that is not connected")]
    InvalidNextHop,
    #[error("route envelope exceeds the owner policy")]
    EnvelopeTooLarge,
    #[error("route replay custody is unavailable: {0}")]
    ResourceUnavailable(ResourceUnavailable),
    #[error("route replay window is full under the owner policy")]
    DedupCapacityExceeded,
    #[error("route replay accounting overflowed")]
    AccountingOverflow,
}

/// A finite, best-first route plan.  The hop list has already been
/// canonicalized and bounded by checked owner policy and topology output.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct RoutePlan {
    next_hops: Vec<String>,
    outgoing_ttl: u8,
    max_parallel_routes: usize,
}

impl RoutePlan {
    pub(crate) fn next_hops(&self) -> &[String] {
        &self.next_hops
    }

    pub(crate) const fn outgoing_ttl(&self) -> u8 {
        self.outgoing_ttl
    }

    pub(crate) const fn max_parallel_routes(&self) -> usize {
        self.max_parallel_routes
    }
}

/// Build a bounded plan from topology-owned next hops.  `connected` is the
/// snapshot of candidates that passed the peer-registry's exact promoted,
/// authenticated and approved-session predicate.  Dispatch checks that
/// predicate again immediately before the actual send.
pub(crate) fn plan_next_hops(
    topology: &dyn Topology,
    self_id: &str,
    destination: &str,
    connected: &[String],
    incoming_ttl: u8,
    policy: RoutingPolicy,
) -> Result<RoutePlan, RouteRefusal> {
    plan_next_hops_with_local_origin(
        topology,
        self_id,
        destination,
        connected,
        incoming_ttl,
        policy,
        false,
    )
}

fn plan_next_hops_with_local_origin(
    topology: &dyn Topology,
    self_id: &str,
    destination: &str,
    connected: &[String],
    incoming_ttl: u8,
    policy: RoutingPolicy,
    allow_local_origination: bool,
) -> Result<RoutePlan, RouteRefusal> {
    plan_next_hops_with_local_origin_and_tree_parent(
        topology,
        self_id,
        destination,
        connected,
        incoming_ttl,
        policy,
        allow_local_origination,
        None,
    )
}

fn plan_next_hops_with_local_origin_and_tree_parent(
    topology: &dyn Topology,
    self_id: &str,
    destination: &str,
    connected: &[String],
    incoming_ttl: u8,
    policy: RoutingPolicy,
    allow_local_origination: bool,
    preferred_parent: Option<&str>,
) -> Result<RoutePlan, RouteRefusal> {
    if destination.is_empty() {
        return Err(RouteRefusal::Envelope(
            RoutedApplicationError::NonCanonicalDeviceId,
        ));
    }
    if incoming_ttl > policy.max_hop_budget() || incoming_ttl > topology.flood_ttl() {
        return Err(RouteRefusal::TtlExceedsPolicy);
    }

    let direct = connected.iter().any(|candidate| candidate == destination);
    let outgoing_ttl = incoming_ttl.checked_sub(1).ok_or(RouteRefusal::Envelope(
        RoutedApplicationError::HopBudgetExhausted,
    ))?;
    let limit = policy.max_next_hops();
    if direct {
        return Ok(RoutePlan {
            next_hops: vec![destination.to_owned()],
            outgoing_ttl,
            max_parallel_routes: 1,
        });
    }
    if !allow_local_origination && !topology.forwards(self_id, connected) {
        return Err(RouteRefusal::NotForwarder);
    }
    let mut next_hops = Vec::with_capacity(limit.min(connected.len()));
    if let Some(preferred_parent) = preferred_parent {
        let is_connected = connected
            .iter()
            .any(|candidate| candidate == preferred_parent);
        if limit > 0
            && is_connected
            && preferred_parent != self_id
            && topology.preferred_next_hop(self_id, destination, connected, preferred_parent)
        {
            next_hops.push(preferred_parent.to_owned());
        }
    }
    for hop in topology.next_hops(self_id, destination, connected, limit) {
        if hop == self_id || !connected.iter().any(|candidate| candidate == &hop) {
            return Err(RouteRefusal::InvalidNextHop);
        }
        if !next_hops.iter().any(|candidate| candidate == &hop) {
            if next_hops.len() == limit {
                break;
            }
            next_hops.push(hop);
        }
    }
    if next_hops.is_empty() {
        return Err(RouteRefusal::NoRoute);
    }
    Ok(RoutePlan {
        next_hops,
        outgoing_ttl,
        max_parallel_routes: policy.max_parallel_routes(),
    })
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct RouteGeneration(u64);

struct ReplayWindow {
    by_key: LeasedMap<RouteKey, RouteGeneration>,
    by_generation: LeasedMap<RouteGeneration, RouteKey>,
    next_generation: u64,
    retained_entries: usize,
    retained_bytes: u64,
}

impl ReplayWindow {
    fn new() -> Self {
        Self {
            by_key: LeasedMap::new(),
            by_generation: LeasedMap::new(),
            next_generation: 0,
            retained_entries: 0,
            retained_bytes: 0,
        }
    }
}

/// State and provider-funded replay custody for one live network instance.
/// Both maps are protected by one mutex.  Each retained node owns its exact
/// map-node lease; FIFO eviction and shutdown release all retained funding.
pub(crate) struct RoutingState {
    policy: RoutingPolicy,
    replay_scope: LocalApplicationResourceScope,
    replay: Mutex<ReplayWindow>,
}

impl RoutingState {
    pub(crate) fn try_new(
        scope: &LocalApplicationResourceScope,
        policy: RoutingPolicy,
    ) -> Result<Self, ResourceUnavailable> {
        Ok(Self {
            policy,
            replay_scope: scope.child()?,
            replay: Mutex::new(ReplayWindow::new()),
        })
    }

    pub(crate) const fn policy(&self) -> RoutingPolicy {
        self.policy
    }

    /// Verify and admit a frame captured from one exact previous hop.  The
    /// protocol verifier and captured-hop check precede replay custody.  A
    /// relay plan is computed before its key is retained, so no-route does not
    /// poison a later retry.
    pub(crate) fn admit_captured_previous_hop<C, P>(
        &self,
        local_id: &DeviceId,
        captured_previous_hop: &DeviceId,
        connected: C,
        origin_policy_admits: P,
        topology: &dyn Topology,
        context_id: MeshContextId,
        envelope: RoutedApplicationEnvelope,
        signing_key: &SigningKey,
    ) -> Result<RouteAdmission, RouteRefusal>
    where
        C: FnOnce() -> Vec<String>,
        P: FnOnce(&RoutedApplicationEnvelope) -> bool,
    {
        self.admit_captured_previous_hop_with_tree_parent(
            local_id,
            captured_previous_hop,
            connected,
            origin_policy_admits,
            topology,
            context_id,
            envelope,
            signing_key,
            None,
        )
    }

    pub(crate) fn admit_captured_previous_hop_with_tree_parent<C, P>(
        &self,
        local_id: &DeviceId,
        captured_previous_hop: &DeviceId,
        connected: C,
        origin_policy_admits: P,
        topology: &dyn Topology,
        context_id: MeshContextId,
        mut envelope: RoutedApplicationEnvelope,
        signing_key: &SigningKey,
        preferred_parent: Option<&str>,
    ) -> Result<RouteAdmission, RouteRefusal>
    where
        C: FnOnce() -> Vec<String>,
        P: FnOnce(&RoutedApplicationEnvelope) -> bool,
    {
        validate_routed_envelope(&envelope, captured_previous_hop, context_id, self.policy)?;
        let encoded_len = envelope
            .encoded_len()
            .ok_or(RouteRefusal::Envelope(RoutedApplicationError::Encoding))?;
        if u64::try_from(encoded_len).map_err(|_| RouteRefusal::AccountingOverflow)?
            > self.policy.max_envelope_bytes()
        {
            return Err(RouteRefusal::EnvelopeTooLarge);
        }
        if !origin_policy_admits(&envelope) {
            return Err(RouteRefusal::OriginNotAdmitted);
        }
        let key = RouteKey::from_envelope(&envelope);
        if self.replay_contains(key) {
            return Ok(RouteAdmission::Duplicate);
        }
        if envelope.destination() == local_id {
            return match self.admit_replay(key)? {
                ReplayDecision::New => Ok(RouteAdmission::Destination { envelope }),
                ReplayDecision::Duplicate => Ok(RouteAdmission::Duplicate),
            };
        }

        let local_origination = captured_previous_hop == local_id
            && envelope.origin() == local_id
            && envelope.hops().is_empty();
        let connected = connected();
        let plan = plan_next_hops_with_local_origin_and_tree_parent(
            topology,
            local_id,
            envelope.destination(),
            &connected,
            envelope.remaining_ttl(),
            self.policy,
            local_origination,
            preferred_parent,
        )?;
        envelope
            .append_hop_with_limits(local_id.clone(), signing_key, self.policy.protocol_limits())
            .map_err(RouteRefusal::Envelope)?;
        let encoded_len = envelope
            .encoded_len()
            .ok_or(RouteRefusal::Envelope(RoutedApplicationError::Encoding))?;
        if u64::try_from(encoded_len).map_err(|_| RouteRefusal::AccountingOverflow)?
            > self.policy.max_envelope_bytes()
        {
            return Err(RouteRefusal::EnvelopeTooLarge);
        }
        match self.admit_replay(key)? {
            ReplayDecision::New => Ok(RouteAdmission::Relay { envelope, plan }),
            ReplayDecision::Duplicate => Ok(RouteAdmission::Duplicate),
        }
    }

    fn replay_contains(&self, key: RouteKey) -> bool {
        self.replay
            .lock()
            .expect("routing replay mutex must not be poisoned")
            .by_key
            .contains_key(&key)
    }

    fn admit_replay(&self, key: RouteKey) -> Result<ReplayDecision, RouteRefusal> {
        let mut replay = self
            .replay
            .lock()
            .expect("routing replay mutex must not be poisoned");
        if replay.by_key.contains_key(&key) {
            return Ok(ReplayDecision::Duplicate);
        }

        let key_claim = LeasedMap::<RouteKey, RouteGeneration>::entry_claim()
            .map_err(|_| RouteRefusal::AccountingOverflow)?;
        let generation_claim = LeasedMap::<RouteGeneration, RouteKey>::entry_claim()
            .map_err(|_| RouteRefusal::AccountingOverflow)?;
        let per_entry = key_claim
            .amount(ResourceClass::AccountedMemoryBytes)
            .checked_add(generation_claim.amount(ResourceClass::AccountedMemoryBytes))
            .ok_or(RouteRefusal::AccountingOverflow)?;
        let will_evict = replay.retained_entries >= self.policy.max_dedup_entries();
        let retained_after_evict = if will_evict {
            replay
                .retained_bytes
                .checked_sub(per_entry)
                .ok_or(RouteRefusal::AccountingOverflow)?
        } else {
            replay.retained_bytes
        };
        let next_bytes = retained_after_evict
            .checked_add(per_entry)
            .ok_or(RouteRefusal::AccountingOverflow)?;
        if next_bytes > self.policy.max_dedup_bytes() {
            return Err(RouteRefusal::DedupCapacityExceeded);
        }

        let generation = RouteGeneration(
            replay
                .next_generation
                .checked_add(1)
                .ok_or(RouteRefusal::AccountingOverflow)?,
        );

        // Evict before acquiring the replacement leases.  This is the
        // progress path for an owner grant sized exactly to the checked
        // replay window: no hidden one-entry headroom is required.  The old
        // replay key is deliberately removed before a fallible replacement;
        // on refusal the window is smaller, never over-admitted or left with
        // an unpaid node.
        if will_evict {
            let Some((_, old_key)) = replay.by_generation.pop_first_entry() else {
                return Err(RouteRefusal::ResourceUnavailable(
                    ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    },
                ));
            };
            replay.by_key.remove(&old_key);
            replay.retained_bytes = replay
                .retained_bytes
                .checked_sub(per_entry)
                .ok_or(RouteRefusal::AccountingOverflow)?;
            replay.retained_entries = replay
                .retained_entries
                .checked_sub(1)
                .ok_or(RouteRefusal::AccountingOverflow)?;
        }
        let key_lease = self
            .replay_scope
            .acquire(key_claim)
            .map_err(RouteRefusal::ResourceUnavailable)?;
        let generation_lease = self
            .replay_scope
            .acquire(generation_claim)
            .map_err(RouteRefusal::ResourceUnavailable)?;
        replay
            .by_key
            .insert(key, generation, key_lease)
            .map_err(|_| {
                RouteRefusal::ResourceUnavailable(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })
            })?;
        if replay
            .by_generation
            .insert(generation, key, generation_lease)
            .is_err()
        {
            replay.by_key.remove(&key);
            return Err(RouteRefusal::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                },
            ));
        }
        replay.next_generation = generation.0;
        replay.retained_entries = replay
            .retained_entries
            .checked_add(1)
            .ok_or(RouteRefusal::AccountingOverflow)?;
        replay.retained_bytes = next_bytes;
        Ok(ReplayDecision::New)
    }
}

/// Exact provider charge retained by one admitted replay identity.
///
/// This is a test-only view of the same two private map-node claims acquired
/// by `admit_replay`; callers cannot substitute a layout-compatible proxy for
/// either production key type.
#[cfg(all(test, feature = "route-flow-diagnostics"))]
pub(super) fn replay_entry_reservation_charge_for_test() -> crate::resource::ResourceClaim {
    let key_claim = LeasedMap::<RouteKey, RouteGeneration>::entry_claim()
        .expect("the production replay-key map-node claim is representable");
    let generation_claim = LeasedMap::<RouteGeneration, RouteKey>::entry_claim()
        .expect("the production replay-generation map-node claim is representable");
    let key_charge =
        crate::resource::FiniteResourceProvider::reservation_charge_for_test(key_claim)
            .expect("the production replay-key reservation charge is representable");
    let generation_charge =
        crate::resource::FiniteResourceProvider::reservation_charge_for_test(generation_claim)
            .expect("the production replay-generation reservation charge is representable");
    key_charge
        .checked_add(generation_charge)
        .expect("the two production replay map-node charges compose")
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ReplayDecision {
    New,
    Duplicate,
}

/// Duplicate replay keys are returned before payload delivery and must be
/// swallowed at both a destination and relay.
pub(crate) enum RouteAdmission {
    Destination {
        envelope: RoutedApplicationEnvelope,
    },
    Relay {
        envelope: RoutedApplicationEnvelope,
        plan: RoutePlan,
    },
    Duplicate,
}

/// Verify origin authorization, exact hop-chain signatures, context and the
/// captured previous-hop identity before routing or retaining the replay key.
pub(crate) fn validate_routed_envelope(
    envelope: &RoutedApplicationEnvelope,
    previous_owner: &DeviceId,
    context_id: MeshContextId,
    policy: RoutingPolicy,
) -> Result<(), RouteRefusal> {
    envelope
        .verify_for_previous_hop_with_limits(previous_owner, context_id, policy.protocol_limits())
        .map_err(RouteRefusal::Envelope)
}

/// Exact peer-registry adapter.  Implementations must return only a currently
/// promoted, authenticated and policy-approved session, and must send through
/// the application capability path.  Carrier handles cannot implement this
/// contract in the production adapter.
pub(crate) trait ExactApprovedSession: Send + Sync {
    fn peer_id(&self) -> &str;
    fn send_routed<'a>(
        &'a self,
        frame: Bytes,
    ) -> Pin<Box<dyn Future<Output = Result<(), RouteSendError>> + Send + 'a>>;
}

pub(crate) trait ExactApprovedSessionProvider: Send + Sync {
    fn exact_approved_session(&self, peer_id: &str) -> Option<Arc<dyn ExactApprovedSession>>;
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum RouteSendError {
    /// The exact approved session was already closed before a write began.
    #[error("approved session closed")]
    Closed,
    /// The exact approved session refused before a write began.
    #[error("approved session refused routed application frame")]
    Refused,
    /// A legacy generic send failure; conservatively treated as uncertain.
    #[error("approved session send failed")]
    Failed,
    /// The write boundary was crossed, but delivery cannot be established.
    #[error("approved session send outcome is unknown")]
    OutcomeUnknown,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub(crate) struct RouteDispatchReport {
    pub(crate) attempted: usize,
    pub(crate) delivered: usize,
    pub(crate) unavailable: usize,
    pub(crate) refused: usize,
    pub(crate) failed: usize,
    pub(crate) outcome_unknown: usize,
}

type RouteSendFuture = Pin<Box<dyn Future<Output = Result<(), RouteSendError>> + Send>>;

fn send_routed_to_session(session: Arc<dyn ExactApprovedSession>, frame: Bytes) -> RouteSendFuture {
    Box::pin(async move { session.send_routed(frame).await })
}

/// Dispatch all finite plan futures concurrently and drain them to completion.
/// Session lookup is repeated at the actual write boundary, so a stale
/// candidate or carrier-only peer cannot become an application capability.
pub(crate) async fn dispatch_routed_frame(
    plan: RoutePlan,
    frame: Bytes,
    sessions: &dyn ExactApprovedSessionProvider,
) -> RouteDispatchReport {
    let mut futures: FuturesUnordered<RouteSendFuture> = FuturesUnordered::new();
    let mut report = RouteDispatchReport::default();
    let mut next_hop = 0usize;
    let window = plan.max_parallel_routes().min(plan.next_hops().len());
    while next_hop < plan.next_hops().len() && futures.len() < window {
        let hop = &plan.next_hops()[next_hop];
        next_hop += 1;
        let Some(session) = sessions.exact_approved_session(hop) else {
            report.unavailable = report.unavailable.saturating_add(1);
            continue;
        };
        if session.peer_id() != hop {
            report.unavailable = report.unavailable.saturating_add(1);
            continue;
        }
        let outbound = frame.clone();
        futures.push(send_routed_to_session(session, outbound));
    }

    let mut succeeded = false;
    let mut uncertain = false;
    while let Some(result) = futures.next().await {
        report.attempted = report.attempted.saturating_add(1);
        match result {
            Ok(()) => {
                report.delivered = report.delivered.saturating_add(1);
                succeeded = true;
            }
            Err(RouteSendError::Closed) => {
                report.unavailable = report.unavailable.saturating_add(1)
            }
            Err(RouteSendError::Refused) => report.refused = report.refused.saturating_add(1),
            Err(RouteSendError::Failed) => {
                report.failed = report.failed.saturating_add(1);
                uncertain = true;
            }
            Err(RouteSendError::OutcomeUnknown) => {
                report.outcome_unknown = report.outcome_unknown.saturating_add(1);
                uncertain = true;
            }
        }
        if !succeeded && !uncertain {
            while next_hop < plan.next_hops().len() && futures.len() < window {
                let hop = &plan.next_hops()[next_hop];
                next_hop += 1;
                let Some(session) = sessions.exact_approved_session(hop) else {
                    report.unavailable = report.unavailable.saturating_add(1);
                    continue;
                };
                if session.peer_id() != hop {
                    report.unavailable = report.unavailable.saturating_add(1);
                    continue;
                }
                let outbound = frame.clone();
                futures.push(send_routed_to_session(session, outbound));
            }
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use data_encoding::BASE32_NOPAD;
    use ed25519_dalek::SigningKey;
    use std::collections::HashSet;

    fn canonical_key(seed: u8) -> String {
        let key = SigningKey::from_bytes(&[seed; 32]);
        BASE32_NOPAD
            .encode(key.verifying_key().as_bytes())
            .to_lowercase()
    }

    struct TestTopology;

    impl Topology for TestTopology {
        fn select_preferred(&self, _self_id: &str, _peer_ids: &[String]) -> HashSet<String> {
            HashSet::new()
        }

        fn forwards(&self, _self_id: &str, _all: &[String]) -> bool {
            true
        }

        fn next_hops(
            &self,
            _self_id: &str,
            _dest: &str,
            _connected: &[String],
            limit: usize,
        ) -> Vec<String> {
            ["b", "a", "b"]
                .into_iter()
                .map(str::to_owned)
                .take(limit)
                .collect()
        }

        fn flood_ttl(&self) -> u8 {
            4
        }
    }

    struct CandidateTopology {
        hops: &'static [&'static str],
    }

    impl Topology for CandidateTopology {
        fn select_preferred(&self, _self_id: &str, _peer_ids: &[String]) -> HashSet<String> {
            HashSet::new()
        }

        fn forwards(&self, _self_id: &str, _all: &[String]) -> bool {
            true
        }

        fn preferred_next_hop(
            &self,
            _self_id: &str,
            _dest: &str,
            _connected: &[String],
            _preferred_parent: &str,
        ) -> bool {
            true
        }

        fn next_hops(
            &self,
            _self_id: &str,
            _dest: &str,
            _connected: &[String],
            limit: usize,
        ) -> Vec<String> {
            self.hops
                .iter()
                .copied()
                .map(str::to_owned)
                .take(limit)
                .collect()
        }

        fn flood_ttl(&self) -> u8 {
            4
        }
    }

    pub(super) struct LeafTopology;

    impl Topology for LeafTopology {
        fn select_preferred(&self, _self_id: &str, _peer_ids: &[String]) -> HashSet<String> {
            HashSet::new()
        }

        fn forwards(&self, _self_id: &str, _all: &[String]) -> bool {
            false
        }

        fn next_hops(
            &self,
            _self_id: &str,
            _dest: &str,
            _connected: &[String],
            limit: usize,
        ) -> Vec<String> {
            vec!["b".to_owned()].into_iter().take(limit).collect()
        }

        fn flood_ttl(&self) -> u8 {
            4
        }
    }

    #[test]
    fn plan_is_best_first_deduplicated_and_bounded() {
        let policy = RoutingPolicy::checked(3, 2, 1024, 2, 4096, 4).expect("valid policy");
        let connected = vec!["a".to_owned(), "b".to_owned()];
        let plan = plan_next_hops(&TestTopology, "self", "destination", &connected, 3, policy)
            .expect("topology route");
        assert_eq!(plan.next_hops(), &["b".to_owned(), "a".to_owned()]);
        assert_eq!(plan.outgoing_ttl(), 2);
        assert_eq!(plan.max_parallel_routes(), 2);
    }

    #[test]
    fn preferred_tree_parent_is_connected_preference_only() {
        let policy = RoutingPolicy::checked(1, 1, 1024, 1, 4096, 4).expect("valid policy");
        let topology = CandidateTopology {
            hops: &["h0", "h1"],
        };
        let connected = vec!["h0".to_owned(), "h1".to_owned(), "h2".to_owned()];

        let preferred = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            "leaf",
            "destination",
            &connected,
            3,
            policy,
            false,
            Some("h2"),
        )
        .expect("connected parent preference is usable");
        assert_eq!(preferred.next_hops(), &["h2"]);

        let absent = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            "leaf",
            "destination",
            &connected,
            3,
            policy,
            false,
            Some("h9"),
        )
        .expect("stale parent falls back to generic route");
        assert_eq!(absent.next_hops(), &["h0"]);

        let ordinary = plan_next_hops(&topology, "leaf", "destination", &connected, 3, policy)
            .expect("ordinary route");
        assert_eq!(ordinary.next_hops(), &["h0"]);

        let direct = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            "leaf",
            "h1",
            &connected,
            3,
            policy,
            false,
            Some("h2"),
        )
        .expect("direct destination route");
        assert_eq!(direct.next_hops(), &["h1"]);

        let no_route = plan_next_hops_with_local_origin_and_tree_parent(
            &CandidateTopology { hops: &[] },
            "leaf",
            "destination",
            &connected,
            3,
            policy,
            false,
            None,
        );
        assert!(matches!(no_route, Err(RouteRefusal::NoRoute)));
    }

    #[test]
    fn real_hub_tree_accepts_connected_parent_outside_static_prefix() {
        let root = canonical_key(41);
        let hubs = (42..=44).map(canonical_key).collect::<Vec<_>>();
        let leaf = canonical_key(45);
        let destination = canonical_key(46);
        let topology = crate::topology::tree::HubTreeSelector {
            root: root.clone(),
            hubs: hubs.clone(),
            backup_candidates: 1,
        };
        let static_prefix = topology.next_hops(&leaf, &destination, &hubs, 2);
        assert_eq!(static_prefix.len(), 2);
        let accepted_parent = hubs
            .iter()
            .find(|hub| !static_prefix.contains(hub))
            .expect("third hub is outside the static parent prefix")
            .clone();
        let policy = RoutingPolicy::checked(1, 1, 1024, 1, 4096, 4).expect("valid policy");

        let preferred = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            &leaf,
            &destination,
            &hubs,
            3,
            policy,
            true,
            Some(&accepted_parent),
        )
        .expect("accepted connected parent is preferred");
        assert_eq!(preferred.next_hops(), &[accepted_parent]);

        let generic = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            &leaf,
            &destination,
            &hubs,
            3,
            policy,
            true,
            None,
        )
        .expect("generic tree route");
        assert_eq!(generic.next_hops(), &static_prefix[..1]);

        let stale = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            &leaf,
            &destination,
            &hubs,
            3,
            policy,
            true,
            Some("unknown-parent"),
        )
        .expect("unknown parent falls back");
        assert_eq!(stale.next_hops(), &static_prefix[..1]);
        let root_hint = plan_next_hops_with_local_origin_and_tree_parent(
            &topology,
            &leaf,
            &destination,
            &hubs,
            3,
            policy,
            true,
            Some(&root),
        )
        .expect("invalid leaf parent role falls back");
        assert_eq!(root_hint.next_hops(), &static_prefix[..1]);
    }

    #[test]
    fn policy_and_expired_ttl_refuse_before_routing_work() {
        assert_eq!(
            RoutingPolicy::checked(0, 1, 1, 1, 1, 1).map(|_| ()),
            Err(RoutePolicyRefusal::Zero)
        );
        assert_eq!(
            RoutingPolicy::checked(1, 2, 1, 1, 1, 1).map(|_| ()),
            Err(RoutePolicyRefusal::InconsistentParallelism)
        );
        let policy = RoutingPolicy::checked(1, 1, 1024, 1, 4096, 4).expect("valid policy");
        let connected = vec!["a".to_owned(), "b".to_owned()];
        assert!(matches!(
            plan_next_hops(&TestTopology, "self", "b", &connected, 0, policy),
            Err(RouteRefusal::Envelope(
                RoutedApplicationError::HopBudgetExhausted
            ))
        ));
    }

    #[test]
    fn leaf_origination_bypasses_forwarder_gate_but_transit_does_not() {
        let policy = RoutingPolicy::checked(2, 1, 1024, 1, 4096, 4).expect("valid policy");
        let connected = vec!["b".to_owned()];
        assert!(matches!(
            plan_next_hops_with_local_origin(
                &LeafTopology,
                "leaf",
                "destination",
                &connected,
                3,
                policy,
                false,
            ),
            Err(RouteRefusal::NotForwarder)
        ));
        let plan = plan_next_hops_with_local_origin(
            &LeafTopology,
            "leaf",
            "destination",
            &connected,
            3,
            policy,
            true,
        )
        .expect("verified local origin can use its topology-selected route");
        assert_eq!(plan.next_hops(), &["b".to_owned()]);
    }
}

#[cfg(test)]
mod dispatch_controls {
    use super::*;
    use futures_util::future::poll_fn;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};

    #[derive(Clone, Copy)]
    enum MockOutcome {
        Delivered,
        Refused,
        Failed,
        OutcomeUnknown,
        Closed,
    }

    struct TwoPartyGate {
        entered: AtomicUsize,
        released: AtomicUsize,
        waiters: Mutex<Vec<Waker>>,
    }

    impl TwoPartyGate {
        fn new() -> Self {
            Self {
                entered: AtomicUsize::new(0),
                released: AtomicUsize::new(0),
                waiters: Mutex::new(Vec::new()),
            }
        }

        fn poll(&self, context: &mut Context<'_>) -> Poll<()> {
            if self.released.load(Ordering::Acquire) != 0 {
                return Poll::Ready(());
            }
            let entered = self.entered.fetch_add(1, Ordering::AcqRel) + 1;
            let mut waiters = self.waiters.lock().expect("gate waiters");
            if self.released.load(Ordering::Acquire) != 0 {
                return Poll::Ready(());
            }
            if entered >= 2 {
                self.released.store(1, Ordering::Release);
                let waiters = std::mem::take(&mut *waiters);
                for waiter in waiters {
                    waiter.wake();
                }
                Poll::Ready(())
            } else {
                waiters.push(context.waker().clone());
                Poll::Pending
            }
        }

        fn entered(&self) -> usize {
            self.entered.load(Ordering::Acquire)
        }
    }

    struct MockSession {
        id: String,
        outcome: MockOutcome,
        calls: Arc<AtomicUsize>,
        active: Arc<AtomicUsize>,
        max_active: Arc<AtomicUsize>,
        frame_ptrs: Arc<Mutex<Vec<usize>>>,
        gate: Option<Arc<TwoPartyGate>>,
    }

    impl ExactApprovedSession for MockSession {
        fn peer_id(&self) -> &str {
            &self.id
        }

        fn send_routed<'a>(
            &'a self,
            frame: Bytes,
        ) -> Pin<Box<dyn Future<Output = Result<(), RouteSendError>> + Send + 'a>> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            self.frame_ptrs
                .lock()
                .expect("pointer log")
                .push(frame.as_ptr() as usize);
            let active = Arc::clone(&self.active);
            let max_active = Arc::clone(&self.max_active);
            let outcome = self.outcome;
            let gate = self.gate.clone();
            Box::pin(async move {
                let now = active.fetch_add(1, Ordering::SeqCst) + 1;
                max_active.fetch_max(now, Ordering::SeqCst);
                if let Some(gate) = gate {
                    poll_fn(|context| gate.poll(context)).await;
                }
                let result = match outcome {
                    MockOutcome::Delivered => Ok(()),
                    MockOutcome::Refused => Err(RouteSendError::Refused),
                    MockOutcome::Failed => Err(RouteSendError::Failed),
                    MockOutcome::OutcomeUnknown => Err(RouteSendError::OutcomeUnknown),
                    MockOutcome::Closed => Err(RouteSendError::Closed),
                };
                active.fetch_sub(1, Ordering::SeqCst);
                result
            })
        }
    }

    struct MockSessions {
        sessions: Vec<Arc<MockSession>>,
        frame_ptrs: Arc<Mutex<Vec<usize>>>,
    }

    impl ExactApprovedSessionProvider for MockSessions {
        fn exact_approved_session(&self, peer_id: &str) -> Option<Arc<dyn ExactApprovedSession>> {
            self.sessions
                .iter()
                .find(|session| session.peer_id() == peer_id)
                .cloned()
                .map(|session| session as Arc<dyn ExactApprovedSession>)
        }
    }

    fn plan(hops: &[&str], parallel: usize) -> RoutePlan {
        RoutePlan {
            next_hops: hops.iter().map(|hop| (*hop).to_owned()).collect(),
            outgoing_ttl: 1,
            max_parallel_routes: parallel,
        }
    }

    fn envelope() -> RoutedApplicationEnvelope {
        use ed25519_dalek::SigningKey;
        let origin_key = SigningKey::from_bytes(&[1; 32]);
        let origin = DeviceId::from_public_key_bytes(*origin_key.verifying_key().as_bytes())
            .expect("origin id");
        let destination_key = SigningKey::from_bytes(&[2; 32]);
        let destination =
            DeviceId::from_public_key_bytes(*destination_key.verifying_key().as_bytes())
                .expect("destination id");
        RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([3; 32]),
            origin,
            destination,
            [4; 16],
            2,
            crate::protocol::ClosedRoutedPayload::ChannelFrame {
                channel: "route-test".to_owned(),
                payload: serde_json::json!({"value": "payload"}),
            },
            &origin_key,
        )
        .expect("valid routed envelope")
    }

    fn encoded_frame() -> Bytes {
        let envelope = envelope();
        let message = crate::protocol::MeshMessage::RoutedApplication(envelope);
        Bytes::from(serde_json::to_vec(&message).expect("encoded routed frame"))
    }

    fn sessions_with_gate(
        outcomes: &[(&str, MockOutcome)],
        gate: Option<Arc<TwoPartyGate>>,
    ) -> MockSessions {
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));
        let frame_ptrs = Arc::new(Mutex::new(Vec::new()));
        MockSessions {
            sessions: outcomes
                .iter()
                .map(|(id, outcome)| {
                    Arc::new(MockSession {
                        id: (*id).to_owned(),
                        outcome: *outcome,
                        calls: Arc::new(AtomicUsize::new(0)),
                        active: Arc::clone(&active),
                        max_active: Arc::clone(&max_active),
                        frame_ptrs: Arc::clone(&frame_ptrs),
                        gate: gate.clone(),
                    })
                })
                .collect(),
            frame_ptrs,
        }
    }

    fn sessions(outcomes: &[(&str, MockOutcome)]) -> MockSessions {
        sessions_with_gate(outcomes, None)
    }

    #[test]
    fn refused_best_hop_backfills_later_hop() {
        let sessions = sessions(&[("a", MockOutcome::Refused), ("b", MockOutcome::Delivered)]);
        let report = futures::executor::block_on(dispatch_routed_frame(
            plan(&["a", "b"], 1),
            encoded_frame(),
            &sessions,
        ));
        assert_eq!(report.attempted, 2);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.refused, 1);
        assert_eq!(sessions.sessions[0].calls.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.sessions[1].calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn uncertain_result_stops_new_fallback_scheduling() {
        let sessions = sessions(&[
            ("a", MockOutcome::OutcomeUnknown),
            ("b", MockOutcome::Delivered),
        ]);
        let report = futures::executor::block_on(dispatch_routed_frame(
            plan(&["a", "b"], 1),
            encoded_frame(),
            &sessions,
        ));
        assert_eq!(report.attempted, 1);
        assert_eq!(report.outcome_unknown, 1);
        assert_eq!(sessions.sessions[0].calls.load(Ordering::SeqCst), 1);
        assert_eq!(sessions.sessions[1].calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn generic_failure_is_conservatively_uncertain() {
        let sessions = sessions(&[("a", MockOutcome::Failed), ("b", MockOutcome::Delivered)]);
        let report = futures::executor::block_on(dispatch_routed_frame(
            plan(&["a", "b"], 1),
            encoded_frame(),
            &sessions,
        ));
        assert_eq!(report.attempted, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(sessions.sessions[1].calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn first_success_stops_new_scheduling() {
        let sessions = sessions(&[
            ("a", MockOutcome::Delivered),
            ("b", MockOutcome::Failed),
            ("c", MockOutcome::Closed),
        ]);
        let report = futures::executor::block_on(dispatch_routed_frame(
            plan(&["a", "b", "c"], 1),
            encoded_frame(),
            &sessions,
        ));
        assert_eq!(report.attempted, 1);
        assert_eq!(report.delivered, 1);
        assert_eq!(sessions.sessions[1].calls.load(Ordering::SeqCst), 0);
        assert_eq!(sessions.sessions[2].calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn started_parallel_futures_are_drained_with_bounded_activity() {
        let gate = Arc::new(TwoPartyGate::new());
        let sessions = sessions_with_gate(
            &[("a", MockOutcome::Delivered), ("b", MockOutcome::Failed)],
            Some(Arc::clone(&gate)),
        );
        let report = futures::executor::block_on(dispatch_routed_frame(
            plan(&["a", "b"], 2),
            encoded_frame(),
            &sessions,
        ));
        assert_eq!(report.attempted, 2);
        assert_eq!(report.delivered, 1);
        assert_eq!(report.failed, 1);
        assert_eq!(gate.entered(), 2, "both sends must enter before release");
        let max_active = sessions.sessions[0].max_active.load(Ordering::SeqCst);
        assert_eq!(
            max_active, 2,
            "parallel control did not exercise both sends"
        );
        let pointers = sessions.frame_ptrs.lock().expect("pointer log");
        assert_eq!(pointers.len(), 2);
        assert_eq!(
            pointers[0], pointers[1],
            "parallel sends deep-cloned the envelope"
        );
    }
}

#[cfg(all(test, feature = "transport-lab"))]
mod replay_controls {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceClaim, ResourceProviderPort};
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn scope_grant(extra: Option<ResourceClaim>) -> ResourceClaim {
        let scope = FiniteResourceProvider::scope_record_charge_for_test();
        (0..3)
            .try_fold(ResourceClaim::ZERO, |grant, _| grant.checked_add(scope))
            .and_then(|grant| extra.map_or(Ok(grant), |claim| grant.checked_add(claim)))
            .expect("scope grant is representable")
    }

    fn exact_cap_fixture() -> (
        FiniteResourceProvider,
        LocalApplicationResourceScope,
        RoutingState,
        RoutingPolicy,
    ) {
        let key_claim =
            LeasedMap::<RouteKey, RouteGeneration>::entry_claim().expect("key entry claim");
        let generation_claim =
            LeasedMap::<RouteGeneration, RouteKey>::entry_claim().expect("generation entry claim");
        let key_charge = FiniteResourceProvider::reservation_charge_for_test(key_claim)
            .expect("key reservation charge");
        let generation_charge =
            FiniteResourceProvider::reservation_charge_for_test(generation_claim)
                .expect("generation reservation charge");
        let map_grant = key_charge
            .checked_add(generation_charge)
            .expect("map grant");
        let provider = FiniteResourceProvider::new(scope_grant(Some(map_grant)));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let scope =
            LocalApplicationResourceScope::transport_lab_child_of(&port).expect("local scope");
        let policy = RoutingPolicy::checked(
            1,
            1,
            16 * 1024,
            1,
            key_claim
                .amount(ResourceClass::AccountedMemoryBytes)
                .checked_add(generation_claim.amount(ResourceClass::AccountedMemoryBytes))
                .expect("dedup byte limit"),
            4,
        )
        .expect("policy");
        let state = RoutingState::try_new(&scope, policy).expect("routing state");
        (provider, scope, state, policy)
    }

    #[test]
    fn exact_cap_replay_eviction_progresses_and_duplicate_does_not_churn() {
        let (provider, scope, state, _policy) = exact_cap_fixture();
        let first = RouteKey::new(
            MeshContextId::from_bytes([1; 32]),
            [2; 32],
            [3; 32],
            [4; 16],
        );
        let second = RouteKey::new(
            MeshContextId::from_bytes([1; 32]),
            [2; 32],
            [3; 32],
            [5; 16],
        );
        assert_eq!(
            state.admit_replay(first).expect("first admission"),
            ReplayDecision::New
        );
        let after_first = provider.in_use();
        assert_eq!(
            state.admit_replay(first).expect("duplicate admission"),
            ReplayDecision::Duplicate
        );
        assert_eq!(provider.in_use(), after_first);
        assert_eq!(
            state.admit_replay(second).expect("evict and admit"),
            ReplayDecision::New
        );
        assert_eq!(provider.in_use(), after_first);
        assert!(!state
            .replay
            .lock()
            .expect("replay lock")
            .by_key
            .contains_key(&first));
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn serialized_size_refuses_before_replay_and_after_hop_growth() {
        use ed25519_dalek::SigningKey;
        let origin_key = SigningKey::from_bytes(&[7; 32]);
        let local_key = SigningKey::from_bytes(&[8; 32]);
        let origin = DeviceId::from_public_key_bytes(*origin_key.verifying_key().as_bytes())
            .expect("origin id");
        let local = DeviceId::from_public_key_bytes(*local_key.verifying_key().as_bytes())
            .expect("local id");
        let destination_key = SigningKey::from_bytes(&[9; 32]);
        let destination =
            DeviceId::from_public_key_bytes(*destination_key.verifying_key().as_bytes())
                .expect("destination id");
        let envelope = RoutedApplicationEnvelope::new(
            MeshContextId::from_bytes([10; 32]),
            origin.clone(),
            destination.clone(),
            [11; 16],
            2,
            crate::protocol::ClosedRoutedPayload::ChannelFrame {
                channel: "route-size".to_owned(),
                payload: serde_json::json!({"value": "bounded"}),
            },
            &origin_key,
        )
        .expect("envelope");
        let initial = u64::try_from(envelope.encoded_len().expect("initial encoding"))
            .expect("initial length");
        let limits = RoutedApplicationLimits::checked(initial as usize, 2).expect("limits");
        let mut grown_envelope = envelope.clone();
        grown_envelope
            .append_hop_with_limits(local.clone(), &local_key, limits)
            .expect("hop growth");
        let grown = u64::try_from(grown_envelope.encoded_len().expect("grown encoding"))
            .expect("grown length");
        assert!(grown > initial);

        let early_provider = FiniteResourceProvider::new(scope_grant(None));
        let early_port = ResourceProviderPort::new(early_provider.clone()).expect("process scope");
        let early_scope = LocalApplicationResourceScope::transport_lab_child_of(&early_port)
            .expect("local scope");
        let early_policy =
            RoutingPolicy::checked(1, 1, initial - 1, 1, 4096, 4).expect("early refusal policy");
        let early_state = RoutingState::try_new(&early_scope, early_policy).expect("routing state");
        let topology = crate::topology::from_mode(&crate::config::TopologyMode::FullMesh);
        let early_connected_calls = Arc::new(AtomicUsize::new(0));
        let early_origin_calls = Arc::new(AtomicUsize::new(0));
        let early_connected_calls_for_closure = Arc::clone(&early_connected_calls);
        let early_origin_calls_for_closure = Arc::clone(&early_origin_calls);
        let early_destination = destination.clone();
        let early_refusal = early_state.admit_captured_previous_hop(
            &local,
            &origin,
            move || {
                early_connected_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                vec![early_destination.to_string()]
            },
            move |_| {
                early_origin_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                true
            },
            topology.as_ref(),
            MeshContextId::from_bytes([10; 32]),
            envelope.clone(),
            &local_key,
        );
        assert!(matches!(early_refusal, Err(RouteRefusal::EnvelopeTooLarge)));
        assert_eq!(early_connected_calls.load(Ordering::SeqCst), 0);
        assert_eq!(early_origin_calls.load(Ordering::SeqCst), 0);
        assert_eq!(
            early_state
                .replay
                .lock()
                .expect("replay lock")
                .retained_entries,
            0
        );
        drop(early_state);
        drop(early_scope);
        assert_eq!(
            early_provider.in_use(),
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        );

        let provider = FiniteResourceProvider::new(scope_grant(None));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let local_scope =
            LocalApplicationResourceScope::transport_lab_child_of(&port).expect("local scope");
        let policy = RoutingPolicy::checked(1, 1, initial, 1, 4096, 4).expect("policy");
        let state = RoutingState::try_new(&local_scope, policy).expect("routing state");
        let origin_calls = Arc::new(AtomicUsize::new(0));
        let connected_calls = Arc::new(AtomicUsize::new(0));
        let origin_calls_for_connected = Arc::clone(&origin_calls);
        let origin_calls_for_policy = Arc::clone(&origin_calls);
        let connected_calls_for_closure = Arc::clone(&connected_calls);
        let route_destination = destination.clone();
        let refusal = state.admit_captured_previous_hop(
            &local,
            &origin,
            move || {
                assert_eq!(origin_calls_for_connected.load(Ordering::SeqCst), 1);
                connected_calls_for_closure.fetch_add(1, Ordering::SeqCst);
                vec![route_destination.to_string()]
            },
            move |_| {
                origin_calls_for_policy.fetch_add(1, Ordering::SeqCst);
                true
            },
            topology.as_ref(),
            MeshContextId::from_bytes([10; 32]),
            envelope,
            &local_key,
        );
        assert!(matches!(refusal, Err(RouteRefusal::EnvelopeTooLarge)));
        assert_eq!(origin_calls.load(Ordering::SeqCst), 1);
        assert_eq!(connected_calls.load(Ordering::SeqCst), 1);
        assert_eq!(
            state.replay.lock().expect("replay lock").retained_entries,
            0
        );
    }

    #[test]
    fn production_admission_allows_signed_leaf_origin_but_refuses_transit() {
        use ed25519_dalek::SigningKey;

        let (_provider, scope, state, policy) = exact_cap_fixture();
        let local_key = SigningKey::from_bytes(&[21; 32]);
        let origin_key = SigningKey::from_bytes(&[22; 32]);
        let previous_key = SigningKey::from_bytes(&[23; 32]);
        let destination_key = SigningKey::from_bytes(&[24; 32]);
        let local = DeviceId::from_public_key_bytes(*local_key.verifying_key().as_bytes())
            .expect("local id");
        let origin = DeviceId::from_public_key_bytes(*origin_key.verifying_key().as_bytes())
            .expect("origin id");
        let previous = DeviceId::from_public_key_bytes(*previous_key.verifying_key().as_bytes())
            .expect("previous id");
        let destination =
            DeviceId::from_public_key_bytes(*destination_key.verifying_key().as_bytes())
                .expect("destination id");
        let context = MeshContextId::from_bytes([25; 32]);
        let payload = || crate::protocol::ClosedRoutedPayload::ChannelFrame {
            channel: "leaf-origin".to_owned(),
            payload: serde_json::json!({"value": "signed"}),
        };

        let local_envelope = RoutedApplicationEnvelope::new(
            context,
            local.clone(),
            destination.clone(),
            [26; 16],
            2,
            payload(),
            &local_key,
        )
        .expect("signed local-origin envelope");
        let local_admission = state
            .admit_captured_previous_hop(
                &local,
                &local,
                || vec!["b".to_owned()],
                |_| true,
                &super::tests::LeafTopology,
                context,
                local_envelope,
                &local_key,
            )
            .expect("local origin can route from a leaf");
        assert!(matches!(local_admission, RouteAdmission::Relay { .. }));

        let mut transit_envelope = RoutedApplicationEnvelope::new(
            context,
            origin,
            destination,
            [27; 16],
            3,
            payload(),
            &origin_key,
        )
        .expect("signed transit envelope");
        transit_envelope
            .append_hop_with_limits(previous.clone(), &previous_key, policy.protocol_limits())
            .expect("signed prior transit hop");
        let transit_refusal = state.admit_captured_previous_hop(
            &local,
            &previous,
            || vec!["b".to_owned()],
            |_| true,
            &super::tests::LeafTopology,
            context,
            transit_envelope,
            &local_key,
        );
        assert!(matches!(transit_refusal, Err(RouteRefusal::NotForwarder)));

        drop(state);
        drop(scope);
    }
}
