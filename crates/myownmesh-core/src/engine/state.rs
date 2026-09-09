//! Shared per-network state. Exposes the operations subsystems
//! (`Channel<T>`, `Rpc`, `MeshHandle`) call to interact with the
//! engine; all per-peer state mutation is funneled through the
//! command queue so the driver loop owns serial access.

use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use bytes::Bytes;

struct SignalingEmissionAllocator {
    next: AtomicU64,
}

impl SignalingEmissionAllocator {
    const fn new(next: u64) -> Self {
        Self {
            next: AtomicU64::new(next),
        }
    }

    fn next(&self) -> std::result::Result<u64, SignalingEmissionIdExhausted> {
        let mut current = self.next.load(Ordering::Acquire);
        loop {
            if current == 0 {
                return Err(SignalingEmissionIdExhausted);
            }
            let next = if current == u64::MAX { 0 } else { current + 1 };
            match self.next.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(current),
                Err(observed) => current = observed,
            }
        }
    }
}

static NEXT_SIGNALING_EMISSION_ID: SignalingEmissionAllocator = SignalingEmissionAllocator::new(1);

/// Allocate the current value and advance to a permanent zero sentinel.
///
/// `MAX` is a valid final identity.  The following call observes zero and
/// refuses, so an exhausted counter cannot wrap into an identity that could
/// alias a still-live fence.
fn next_non_wrapping(counter: &AtomicU64) -> Option<u64> {
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

use crate::config::{NetworkConfig, TopologyMode};
use crate::error::{Error, Result};
use crate::events::{DiagEntry, DiagLevel, MeshEvent, MeshPhase, PhaseEvent};
use crate::identity::Identity;
use crate::resource::{
    strings_measure, FundedArc, LeasedMap, LeasedQueue, LocalApplicationResourceScope,
    MailboxMeasurement, MeshRuntimeResourceScope, NetworkInstanceResourceScope, ResourceClaim,
    ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceMailboxItem,
    ResourceMailboxItemError, ResourceMailboxReceiver, ResourceMailboxSendError,
    ResourceMailboxSender, ResourceReport, ResourceUnavailable,
};
use crate::roster::Roster;
use crate::runtime::session_broker::SessionBroker;
use crate::semantic::DeviceId;
use crate::topology::Topology;
use crate::transport::webrtc::{
    RealtimeDirection, RealtimeFlowError, RealtimeFlowName, RealtimeFlowRemains,
    RealtimeFlowSetIdentity, RealtimeFlowSpec, RealtimeSendUnit, SessionRealtimeFlows,
};
use crate::transport::{LocalIceCandidate, Transport};
use parking_lot::{Mutex, RwLock};
use tokio::sync::{broadcast, oneshot, watch, Notify, Semaphore};
use tokio::task::JoinHandle;

#[cfg(test)]
use super::carrier_state::CarrierAttemptList;
use super::carrier_state::{
    CarrierAttemptCarrier, CarrierAttemptNode, CarrierInstanceList, CarrierInstanceNode,
    CarrierState, RecoveryCohort, RecoveryCohortCause, RecoveryCohortCauseList,
    RecoveryCohortGeneration, RecoveryPublication,
};
pub(crate) use super::carrier_state::{
    CarrierEmissionAdmission, CarrierEmissionRecord, CarrierEmissionSettlement,
    RecoveryPublicationStart,
};
pub(crate) use super::command::NetworkCmd;
use super::peer_registry::{PeerOwnerToken, PeerRegistry};
use super::signaling_ingress::EphemeralIngress;
#[cfg(feature = "transport-lab")]
use crate::semantic::store::{AdmissionPhase, AdmissionPhaseGuard};
use crate::semantic::store::{DurableSemanticOwner, DurableSemanticStore, ProvisionalCustody};
use crate::semantic::{DurableProofOutbox, ProofDeliveryId, ProofRecord};

#[cfg(feature = "transport-lab")]
pub(crate) type ParentingSnapshotForLab = (Option<[u8; 32]>, usize, usize, u64);

pub(crate) type AttemptSettlement = Arc<
    dyn Fn(&str, myownmesh_signaling::nostr::delivery::DeliveryTerminal) -> usize + Send + Sync,
>;

struct PeerEventPumpRegistry {
    handles: Vec<JoinHandle<()>>,
    pending_registrations: usize,
    closed: bool,
}

/// One exact child-side HubTree registration retained until its matching
/// response arrives.  The owner token and parenting witness are deliberately
/// kept together so a replacement cannot inherit the pending relation.
struct PendingParentAttach {
    owner: PeerOwnerToken,
    witness: super::parenting::ParentOwnerWitness,
    ticket: super::parenting::ParentAttachTicket,
    request: super::parenting::ParentAttachRequest,
    wire_request: crate::protocol::HubTreeAttachRequest,
}

/// Joinable tasks admitted by an exact shutdown mutation witness.  The
/// witness keeps shutdown from closing this registry between the producer's
/// admission check and its handle registration; once shutdown has drained
/// those witnesses, `closed` makes the registry a permanent refusal point.
struct ShutdownTaskRegistry {
    handles: Vec<ShutdownTask>,
    closed: bool,
}

struct ShutdownTask {
    handle: JoinHandle<()>,
    cancel_on_shutdown: bool,
}

impl ShutdownTaskRegistry {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
            closed: false,
        }
    }

    fn push(&mut self, handle: JoinHandle<()>, cancel_on_shutdown: bool) {
        self.handles.push(ShutdownTask {
            handle,
            cancel_on_shutdown,
        });
    }

    fn take_for_shutdown(&mut self) -> Vec<ShutdownTask> {
        self.closed = true;
        std::mem::take(&mut self.handles)
    }
}

impl PeerEventPumpRegistry {
    fn new() -> Self {
        Self {
            handles: Vec::new(),
            pending_registrations: 0,
            closed: false,
        }
    }
}

/// A synchronous, funded witness for sending one exact Pending proof.  The
/// witness owns the provider claim and exact endpoint/worker identity; it is
/// intentionally returned only after the publication gate, canonical policy,
/// outbox, and registry checks have all succeeded.  Transport code must drop
/// the state gate before awaiting on the returned worker.
#[must_use = "dropping an admitted proof send releases its exact provider claim"]
pub(crate) struct DurableProofSendAdmission {
    owner: PeerOwnerToken,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
    endpoint_auth: Arc<crate::endpoint_auth::EndpointAuthTask>,
    mesh_context: String,
    bytes: Bytes,
    work: ResourceLease,
}

/// Result of the final durable proof admission fence.  Superseded is a
/// terminal non-send outcome: the pending record was retired under the same
/// publication gate that observed it was no longer canonical.
pub(crate) enum DurableProofSendPreparation {
    Ready(Box<DurableProofSendAdmission>),
    Superseded,
}

impl DurableProofSendAdmission {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PeerOwnerToken,
        Arc<crate::transport::WebRtcConnectorWorker>,
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        String,
        Bytes,
        ResourceLease,
    ) {
        (
            self.owner,
            self.worker,
            self.endpoint_auth,
            self.mesh_context,
            self.bytes,
            self.work,
        )
    }
}

/// Process-local identity for one exact recovery cohort publication.  It is
/// deliberately separate from any wire/event id: carrier copies must report
/// back to this process and stale reports must never settle a later cohort.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct RecoveryPublishId {
    generation: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct RecoveryCarrierInstance(u64);

/// Process-local identity for one Offer/Answer/Candidate emission.  It is
/// deliberately not serialized or inferred from an attempt string: two
/// emissions may share one negotiation attempt and still settle separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct SignalingEmissionId(u64);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SignalingEmissionIdExhausted;

impl SignalingEmissionId {
    /// Reserve one process-local emission identity without wrapping.
    ///
    /// Zero is an internal exhausted sentinel and is never returned. MAX is
    /// returned once, then the allocator enters the sentinel state; every
    /// later call reports typed exhaustion rather than aliasing an earlier
    /// live emission.
    pub(crate) fn next() -> std::result::Result<Self, SignalingEmissionIdExhausted> {
        NEXT_SIGNALING_EMISSION_ID.next().map(Self)
    }
}

#[cfg(test)]
#[test]
fn signaling_emission_id_exhaustion_is_typed_and_nonwrapping() {
    let allocator = SignalingEmissionAllocator::new(u64::MAX);
    assert_eq!(
        allocator.next().map(SignalingEmissionId),
        Ok(SignalingEmissionId(u64::MAX))
    );
    assert_eq!(
        allocator.next().map(SignalingEmissionId),
        Err(SignalingEmissionIdExhausted)
    );
    assert_eq!(
        allocator.next().map(SignalingEmissionId),
        Err(SignalingEmissionIdExhausted)
    );
}

#[cfg(test)]
#[test]
fn checked_local_id_exhaustion_does_not_reuse_the_last_value() {
    let counter = AtomicU64::new(u64::MAX);
    assert_eq!(next_non_wrapping(&counter), Some(u64::MAX));
    assert_eq!(next_non_wrapping(&counter), None);
    assert_eq!(next_non_wrapping(&counter), None);
}

/// Internal driver work for reducing one authenticated candidate.
///
/// Kept out of [`NetworkCmd`]: neither the exact worker pointer nor candidate
/// promotion is part of the public command surface.
pub(super) struct SpeculativePromotionCmd {
    pub(super) owner: PeerOwnerToken,
    pub(super) candidate: Arc<crate::transport::WebRtcConnectorWorker>,
    pub(super) correlation: String,
}

unsafe impl ResourceMailboxItem for SpeculativePromotionCmd {
    fn measured_claim(
        &self,
    ) -> std::result::Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        let measure = strings_measure([self.correlation.as_str()])?;
        MailboxMeasurement::from_parts(measure.0, measure.1, measure.2)
    }
}

#[cfg(test)]
pub(super) fn speculative_promotion_item_charge_for_test(correlation: &str) -> ResourceClaim {
    struct PlanningItem<'a>(&'a str);

    unsafe impl crate::resource::ResourceMailboxItemBuilder<SpeculativePromotionCmd>
        for PlanningItem<'_>
    {
        fn measured_claim(
            &self,
        ) -> std::result::Result<
            MailboxMeasurement<SpeculativePromotionCmd>,
            ResourceMailboxItemError,
        > {
            let measure = strings_measure([self.0])?;
            MailboxMeasurement::from_parts(measure.0, measure.1, measure.2)
        }

        fn build(self) -> SpeculativePromotionCmd {
            unreachable!("planning a fixture mailbox charge never builds the command")
        }
    }

    ResourceMailboxSender::<SpeculativePromotionCmd>::building_item_planning_charge(&PlanningItem(
        correlation,
    ))
    .expect("fixture speculative-promotion charge is representable")
}

/// See a closed flow's native half retired, whichever half it had.
///
/// A free function rather than a method, and the only place the engine waits on
/// either kind of retirement, so there is exactly one account of what closing a
/// flow costs. Two would be two things that can disagree about which half a
/// flow had.
///
/// The two arms are asymmetric because the ownership is. **Outbound** removal
/// belongs to the pump, which is the only holder of the sender and the peer
/// connection: closing the flow drops its queue, the pump wakes, removes its
/// own track and completes the lease. The engine does not remove anything here
/// — it waits for the removal to have happened. **Inbound** has no pump-side
/// owner for the transceiver, so the engine stops it directly against the
/// identity it takes out of the retirement the close handed back.
///
/// A dropped sender on the outbound lease is completion, not failure: it means
/// the pump is gone, and a pump that is gone has already run its exit. There is
/// nothing left to wait for and nothing a retry could learn, so the error is
/// discarded rather than surfaced as a close failure the caller cannot act on.
///
/// Awaits, so every caller is outside the fence before it runs. Nothing here is
/// retried, timed or generation-checked.
fn opaque_wire_mode(mode: crate::realtime::OpaqueFlowMode) -> crate::protocol::ApplicationFlowMode {
    match mode {
        crate::realtime::OpaqueFlowMode::ReliableOrdered => {
            crate::protocol::ApplicationFlowMode::ReliableOrdered
        }
        crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits } => {
            crate::protocol::ApplicationFlowMode::PartialUnordered { max_retransmits }
        }
    }
}

fn opaque_local_mode(
    mode: crate::protocol::ApplicationFlowMode,
) -> std::result::Result<crate::realtime::OpaqueFlowMode, RealtimeFlowError> {
    match mode {
        crate::protocol::ApplicationFlowMode::ReliableOrdered => {
            Ok(crate::realtime::OpaqueFlowMode::ReliableOrdered)
        }
        crate::protocol::ApplicationFlowMode::PartialUnordered { max_retransmits: 0 } => {
            Ok(crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits: 0 })
        }
        _ => Err(RealtimeFlowError::FlowRefused),
    }
}

async fn retire_realtime_remains(
    worker: &Arc<crate::transport::WebRtcConnectorWorker>,
    remains: RealtimeFlowRemains,
) {
    match remains {
        RealtimeFlowRemains::Inbound(mut retirement) => {
            // Taken rather than dropped: this caller is going to await the
            // receipt, and the retirement must not also submit one of its own
            // behind it. Dropping it instead would still retire the
            // transceiver — it would just do it without telling anybody.
            let identity = retirement.take_for_explicit_close();
            worker.close_inbound_realtime_transceiver(&identity).await;
        }
        RealtimeFlowRemains::Outbound(completed) => {
            let _ = completed.await;
        }
        // A flow whose native half never came up, or one whose pump has already
        // taken the cleanup because the flow set was dropped rather than closed.
        RealtimeFlowRemains::None => {}
    }
}

use super::conn_trace::ConnTrace;
/// Bookkeeping for an offerer-side reconnect intent. When we drop a peer we
/// were the *offerer* for (a recoverable `IceFailed`), we keep one of these
/// in [`NetworkState::reconnect_intents`] and event paths re-offer on a
/// backoff until the link comes back or `give_up_at` passes.
/// This is the offerer-side counterpart to an answerer recovering from the
/// remote's re-offers — without it, an offerer-role peer that drops on a
/// network shift is never re-offered (it only comes back on the peer's slow
/// steady-state announce). The backoff (`next_retry_at`/`attempt`) keeps the
/// recovery from publishing an offer on every event — one re-offer per
/// backoff step, never cadence traffic.
#[derive(Debug, Clone, Copy)]
pub struct ReconnectIntent {
    /// Stop retrying after this instant (drop time plus the configured
    /// reconnecting grace).
    /// A sticky intent ignores this — see [`ReconnectIntent::sticky`].
    pub give_up_at: std::time::Instant,
    /// Earliest instant for the next re-offer; advanced by the backoff each
    /// time an event services this intent.
    pub next_retry_at: std::time::Instant,
    /// Number of re-offers issued so far — indexes the configured reconnect
    /// retry schedule.
    pub attempt: usize,
    /// A pinned peer's intent: never expires, and once the active backoff
    /// schedule is spent it parks (no more event-driven re-offers) and waits
    /// for the peer's next announce to dial — the recovery loop a support
    /// session needs on a Silent network, without endless blind offers to
    /// a peer that may be off for the weekend.
    pub sticky: bool,
}

/// Bump a reconnect intent's backoff after a re-offer: advance the attempt
/// and push `next_retry_at` out by the next step (saturating at the last
/// one). One offer per backoff window — never a per-tick publish.
fn advance_backoff(
    intent: &mut ReconnectIntent,
    now: std::time::Instant,
    retry_schedule_ms: &[u64; 4],
) -> bool {
    let step = retry_schedule_ms
        .get(intent.attempt)
        .copied()
        .unwrap_or_else(|| retry_schedule_ms[retry_schedule_ms.len() - 1]);
    let Some(next_retry_at) = now.checked_add(std::time::Duration::from_millis(step)) else {
        return false;
    };
    intent.attempt = intent.attempt.saturating_add(1);
    intent.next_retry_at = next_retry_at;
    true
}

/// Emitted once per session, on the call that minted it — never on reuse and
/// Manually triggered in-place reconnect — the non-destructive twin of a
/// announced, so peers keep their sessions and app-level state — this is
/// answering an inbound offer. Idempotent — a no-op if a live session
/// how many peers the push reached — so the reply channel was charged for on
pub(super) struct ConnectWaitShared {
    id: u64,
    device_id: String,
    cancelled: AtomicBool,
    introduction: Mutex<Option<IntroductionWaitBinding>>,
    outcome: Mutex<ChannelDemandOutcome>,
    settlement_queued: AtomicBool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IntroductionWaitBinding {
    ticket: super::hub_introduction::IntroductionTicket,
    deadline: std::time::Instant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ChannelDemandOutcome {
    Ready,
    NoOwnedAttemptRefused,
    FailedSettlementJoined,
    TerminalRefused,
    Unsettled,
}

/// Funding and activity for links created by admitted application demand.
/// This table cannot create or authorize a peer: the only session identity it
/// retains is the token minted by the existing peer registry.
struct DemandOwnedLink {
    owner: PeerOwnerToken,
    introduction: super::hub_introduction::IntroductionTicket,
    generation: u64,
    activity: super::connection::DemandLinkActivity,
    settlement: IntroductionSettlementPhase,
    detached: Option<super::connection::IntroducedRetirement>,
    pump: Option<JoinHandle<()>>,
    pump_registered: bool,
    pump_joined: Option<bool>,
    native_closed: Option<bool>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum IntroductionSettlementPhase {
    Active,
    Queued,
    Joining,
    Failed,
}

/// A move-out reservation, not a second owner registry. On cancellation the
/// still-joinable handle goes back to the SAME funded record before its phase
/// becomes eligible for another command or shutdown's synchronous drain.
struct IntroductionJoinReservation<'a> {
    pool: &'a Mutex<DemandLinkPool>,
    key: [u8; 32],
    ticket: super::hub_introduction::IntroductionTicket,
    generation: u64,
    pump: Option<JoinHandle<()>>,
}

impl Drop for IntroductionJoinReservation<'_> {
    fn drop(&mut self) {
        let mut pool = self.pool.lock();
        let link = pool
            .links
            .get_mut(&self.key)
            .filter(|link| link.introduction == self.ticket && link.generation == self.generation)
            .expect("a joining introduction retains its original funded record");
        if let Some(pump) = self.pump.take() {
            assert!(
                link.pump.is_none(),
                "one introduction has one receiver pump"
            );
            link.pump = Some(pump);
        }
        if link.settlement == IntroductionSettlementPhase::Joining {
            link.settlement = IntroductionSettlementPhase::Active;
        }
    }
}

struct DemandLinkPool {
    links: LeasedMap<[u8; 32], DemandOwnedLink>,
    reserved: usize,
    next_generation: u64,
    cursor: Option<[u8; 32]>,
    policy: crate::config::HubIntroductionPolicyConfig,
    resources: LocalApplicationResourceScope,
    _root: ResourceLease,
}

impl DemandLinkPool {
    fn root_claim() -> Result<ResourceClaim> {
        ResourceClaim::try_from_entries([(
            ResourceClass::AccountedMemoryBytes,
            std::mem::size_of::<Self>() as u64,
        )])
        .map_err(|_| Error::Network("demand link root claim overflow".into()))
    }

    fn entry_claim() -> Result<ResourceClaim> {
        LeasedMap::<[u8; 32], DemandOwnedLink>::entry_claim()
            .map_err(|_| Error::Network("demand link entry claim overflow".into()))
    }

    fn new(
        policy: crate::config::HubIntroductionPolicyConfig,
        resources: LocalApplicationResourceScope,
    ) -> Result<Self> {
        let policy = policy.checked()?;
        let root = resources.acquire(Self::root_claim()?)?;
        Ok(Self {
            links: LeasedMap::new(),
            reserved: 0,
            next_generation: 1,
            cursor: None,
            policy,
            resources,
            _root: root,
        })
    }
}

/// A link slot is reserved before native construction. Cancellation returns
/// both the finite slot and the real map-entry funding; no placeholder peer
/// or permanent configuration pin is manufactured by this reservation.
pub(super) struct DemandLinkReservation<'a> {
    pool: &'a Mutex<DemandLinkPool>,
    entry: Option<ResourceLease>,
}

impl DemandLinkReservation<'_> {
    /// Called only for the freshly created, exact current worker, before its
    /// first offer. Existing/borrowed usable peers must never be adopted.
    pub(super) fn bind(
        mut self,
        owner: PeerOwnerToken,
        introduction: super::hub_introduction::IntroductionTicket,
        now: std::time::Instant,
    ) -> Result<()> {
        let key = DeviceId::canonical_key_bytes(owner.device_id())
            .map_err(|_| Error::Network("demand owner is not canonical".into()))?;
        let mut pool = self.pool.lock();
        if pool.links.get(&key).is_some() || owner.worker().is_none() {
            return Err(Error::Network("demand owner is not a fresh worker".into()));
        }
        let generation = pool.next_generation;
        if generation == 0 {
            return Err(Error::Network("demand link generation exhausted".into()));
        }
        pool.next_generation = generation.checked_add(1).unwrap_or(0);
        let entry = self
            .entry
            .take()
            .expect("reservation retains its one map lease");
        pool.reserved -= 1;
        pool.links
            .insert(
                key,
                DemandOwnedLink {
                    owner,
                    introduction,
                    generation,
                    activity: super::connection::DemandLinkActivity::new(now),
                    settlement: IntroductionSettlementPhase::Active,
                    detached: None,
                    pump: None,
                    pump_registered: false,
                    pump_joined: None,
                    native_closed: None,
                },
                entry,
            )
            .map_err(|_| Error::Network("demand link insertion refused".into()))
    }
}

impl Drop for DemandLinkReservation<'_> {
    fn drop(&mut self) {
        if self.entry.is_some() {
            let mut pool = self.pool.lock();
            pool.reserved -= 1;
        }
    }
}

/// One caller-held operation, charged by its existing command/flow owner.
/// Its fixed-size guard updates only the generation captured at admission.
pub(super) struct DemandLinkUse<'a> {
    pool: &'a Mutex<DemandLinkPool>,
    key: [u8; 32],
    generation: u64,
}

impl Drop for DemandLinkUse<'_> {
    fn drop(&mut self) {
        if let Some(link) = self.pool.lock().links.get_mut(&self.key) {
            if link.generation == self.generation {
                link.activity.finish(std::time::Instant::now());
            }
        }
    }
}

/// A single maintenance pass owns this exact idle reservation. Cancellation
/// may reopen only that record, never an installation which reused its key.
struct DemandIdleReservation<'a> {
    pool: &'a Mutex<DemandLinkPool>,
    key: [u8; 32],
    generation: u64,
}

impl Drop for DemandIdleReservation<'_> {
    fn drop(&mut self) {
        if let Some(link) = self.pool.lock().links.get_mut(&self.key) {
            if link.generation == self.generation {
                link.activity.cancel_idle();
            }
        }
    }
}

/// The same exact-generation use carried by an admitted responder task.
/// The caller prices this inline value before constructing it; the Arc shares
/// the existing network root and creates no allocation or second link table.
pub(super) struct OwnedDemandLinkUse {
    state: Arc<NetworkState>,
    key: [u8; 32],
    generation: u64,
}

impl Drop for OwnedDemandLinkUse {
    fn drop(&mut self) {
        let Some(pool) = self.state.demand_links.as_ref() else {
            return;
        };
        if let Some(link) = pool.lock().links.get_mut(&self.key) {
            if link.generation == self.generation {
                link.activity.finish(std::time::Instant::now());
            }
        }
    }
}

fn same_demand_owner(left: &PeerOwnerToken, right: &PeerOwnerToken) -> bool {
    left.same_exact_owner(right)
}

impl ConnectWaitShared {
    fn claim(device_id: &str) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let bytes = std::mem::size_of::<Self>()
            .checked_add(device_id.len())
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        let string_allocation = u64::from(!device_id.is_empty());
        // One broad residual covers the dependency-private metadata of the
        // FundedArc value/control blocks and oneshot channel state; the String
        // buffer is separately countable.  The residual is intentionally a
        // source-based dependency allowance, not a claim that those private
        // allocations have one fixed implementation shape.
        let opaque =
            string_allocation
                .checked_add(2)
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, opaque),
        ])
        .map_err(|error| ResourceUnavailable::ProviderInvariant {
            dimension: match error {
                ResourceClaimArithmeticError::Overflow { dimension }
                | ResourceClaimArithmeticError::Underflow { dimension } => dimension,
            },
        })
    }

    fn new(id: u64, device_id: String) -> Self {
        Self {
            id,
            device_id,
            cancelled: AtomicBool::new(false),
            introduction: Mutex::new(None),
            outcome: Mutex::new(ChannelDemandOutcome::Unsettled),
            settlement_queued: AtomicBool::new(false),
        }
    }
}

pub struct ConnectWaiterRegistration {
    reply: Mutex<Option<oneshot::Sender<Result<()>>>>,
    pub(super) shared: FundedArc<ConnectWaitShared>,
}

impl ConnectWaiterRegistration {
    pub(super) fn finish(&self, result: Result<()>) {
        if let Some(reply) = self.reply.lock().take() {
            let _ = reply.send(result);
        }
    }
}

pub(super) struct ConnectWaitCancellation<'a> {
    pub(super) state: &'a NetworkState,
    pub(super) shared: FundedArc<ConnectWaitShared>,
    pub(super) armed: bool,
}

impl Drop for ConnectWaitCancellation<'_> {
    fn drop(&mut self) {
        if self.armed {
            self.shared.cancelled.store(true, Ordering::Release);
            self.state
                .cancel_connect_waiter(&self.shared.device_id, self.shared.id);
        }
    }
}

struct ConnectWaiterBucket {
    waiters: LeasedQueue<ConnectWaiterRegistration>,
    _name: ResourceLease,
}

/// Inbound signaling messages from the signaling task.
#[derive(Debug)]
pub enum SignalingInbound {
    PeerAnnounced {
        device_id: String,
    },
    Offer {
        device_id: String,
        /// The sender's attempt correlation, preserved from the carrier frame.
        ///
        /// Kept because discarding it here is what left de-duplication unable
        /// to tell one attempt from the next: a host candidate with no
        /// `username_fragment` recurs verbatim on a replacement attempt, and a
        /// key built from content alone suppressed the live copy on the
        /// strength of a retired one. Unauthenticated and used for correlation
        /// only.
        attempt: String,
        sdp: String,
    },
    Answer {
        device_id: String,
        /// The attempt correlation this answer echoes — see [`Self::Offer`].
        attempt: String,
        sdp: String,
    },
    Candidate {
        device_id: String,
        /// The attempt correlation this candidate belongs to — see
        /// [`Self::Offer`]. Empty when the sender did not stamp one.
        attempt: String,
        candidate: LocalIceCandidate,
    },
    PeerLeft {
        device_id: String,
    },
}

impl SignalingInbound {
    /// Variant name for driver-liveness traces — cheap, no payload.
    pub fn kind_name(&self) -> &'static str {
        match self {
            SignalingInbound::PeerAnnounced { .. } => "peer_announced",
            SignalingInbound::Offer { .. } => "offer",
            SignalingInbound::Answer { .. } => "answer",
            SignalingInbound::Candidate { .. } => "candidate",
            SignalingInbound::PeerLeft { .. } => "peer_left",
        }
    }
}

impl SignalingInbound {
    /// Everything this value reaches, measured for the owner that will hold it.
    ///
    /// Deliberately not a [`ResourceMailboxItem`] impl. What the engine's
    /// inbound mailbox carries is a
    /// [`super::signaling_ingress::EphemeralIngress`] — an admitted input with its
    /// lane and carrier provenance — and that is the type whose footprint the
    /// claim has to be priced against. Splitting the measurement out means the
    /// owner supplies `size_of::<Self>()` while this stays the one description
    /// of what a `SignalingInbound` reaches, rather than the two drifting.
    pub(super) fn string_measure(
        &self,
    ) -> std::result::Result<(usize, usize, usize), ResourceMailboxItemError> {
        match self {
            Self::PeerAnnounced { device_id } | Self::PeerLeft { device_id } => {
                strings_measure([device_id.as_str()])
            }
            Self::Offer {
                device_id,
                attempt,
                sdp,
            }
            | Self::Answer {
                device_id,
                attempt,
                sdp,
            } => strings_measure([device_id.as_str(), attempt.as_str(), sdp.as_str()]),
            Self::Candidate {
                device_id,
                attempt,
                candidate,
            } => strings_measure(
                [
                    Some(device_id.as_str()),
                    Some(attempt.as_str()),
                    Some(candidate.candidate.as_str()),
                    candidate.sdp_mid.as_deref(),
                    candidate.username_fragment.as_deref(),
                ]
                .into_iter()
                .flatten(),
            ),
        }
    }
}

/// Outbound signaling messages from the engine to the signaling task.
/// `Clone` so the bridge's fan-out can hand one engine emission to
/// several concurrently-attached drivers (Nostr + mDNS).
///
/// Crate-private, with the rest of the raw signaling surface. Nothing outside
/// `engine` constructs one, and a `pub` emission type is exactly the generic
/// message bus `FORMAL-PROOFS.md` Theorem 11.2 turns on application code not
/// having.
#[derive(Clone)]
pub(crate) enum SignalingOutbound {
    Announce,
    /// A recovery-scoped announce carrying the exact publication generation.
    /// Ordinary [`Announce`] values never participate in recovery admission.
    RecoveryAnnounce {
        id: RecoveryPublishId,
    },
    /// Carrier departure observation — the dual of [`Announce`]. This is a
    /// sender-claimed reachability hint, not an authenticated session terminal
    /// and not durable participation or authorization. A receiver may use it
    /// to update carrier availability, cancel speculative work, or trigger
    /// exact connector/liveness validation; it must not tear down a healthy
    /// authenticated session solely because this hint names its Device.
    /// Authenticated departure travels over the exact live session instead.
    Leave,
    Offer {
        device_id: String,
        /// The attempt this offer opens, minted once by the attempt's owner.
        ///
        /// Carried here rather than invented per carrier, which is what the
        /// three translations used to do: each stamped its own id, so the two
        /// copies of one fanned-out offer disagreed about which attempt they
        /// belonged to and the value was useless for correlating anything.
        attempt: String,
        sdp: String,
        owner: Option<PeerOwnerToken>,
    },
    Answer {
        device_id: String,
        /// The offerer's correlation, echoed verbatim — see [`Self::Offer`].
        attempt: String,
        sdp: String,
        owner: Option<PeerOwnerToken>,
    },
    Candidate {
        device_id: String,
        /// The attempt this candidate belongs to — see [`Self::Offer`].
        attempt: String,
        candidate: LocalIceCandidate,
        owner: Option<PeerOwnerToken>,
    },
}

impl std::fmt::Debug for SignalingOutbound {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Announce => formatter.write_str("Announce"),
            Self::RecoveryAnnounce { id } => formatter
                .debug_struct("RecoveryAnnounce")
                .field("id", id)
                .finish(),
            Self::Leave => formatter.write_str("Leave"),
            Self::Offer {
                device_id,
                attempt,
                sdp,
                owner,
            } => formatter
                .debug_struct("Offer")
                .field("device_id", device_id)
                .field("attempt", attempt)
                .field("sdp", sdp)
                .field("owner", &owner.is_some())
                .finish(),
            Self::Answer {
                device_id,
                attempt,
                sdp,
                owner,
            } => formatter
                .debug_struct("Answer")
                .field("device_id", device_id)
                .field("attempt", attempt)
                .field("sdp", sdp)
                .field("owner", &owner.is_some())
                .finish(),
            Self::Candidate {
                device_id,
                attempt,
                candidate,
                owner,
            } => formatter
                .debug_struct("Candidate")
                .field("device_id", device_id)
                .field("attempt", attempt)
                .field("candidate", candidate)
                .field("owner", &owner.is_some())
                .finish(),
        }
    }
}

unsafe impl ResourceMailboxItem for SignalingOutbound {
    fn measured_claim(
        &self,
    ) -> std::result::Result<MailboxMeasurement<Self>, ResourceMailboxItemError> {
        let measure = match self {
            Self::Announce | Self::RecoveryAnnounce { .. } | Self::Leave => (0, 0, 0),
            Self::Offer {
                device_id,
                attempt,
                sdp,
                ..
            }
            | Self::Answer {
                device_id,
                attempt,
                sdp,
                ..
            } => strings_measure([device_id.as_str(), attempt.as_str(), sdp.as_str()])?,
            Self::Candidate {
                device_id,
                attempt,
                candidate,
                ..
            } => strings_measure(
                [
                    Some(device_id.as_str()),
                    Some(attempt.as_str()),
                    Some(candidate.candidate.as_str()),
                    candidate.sdp_mid.as_deref(),
                    candidate.username_fragment.as_deref(),
                ]
                .into_iter()
                .flatten(),
            )?,
        };
        MailboxMeasurement::from_parts(measure.0, measure.1, measure.2)
    }
}

type DurableAdmissionResponse = Result<crate::semantic::Admission>;

pub(crate) struct DurableAdmissionBatch {
    pub(crate) outcomes: Vec<DurableAdmissionResponse>,
    pub(crate) changed_admitted: Vec<crate::semantic::SignedFact>,
    pub(crate) delta: crate::semantic::SemanticDelta,
}

#[cfg(test)]
struct DurableAdmissionActivityGuard<'a> {
    state: &'a NetworkState,
}

#[cfg(test)]
impl Drop for DurableAdmissionActivityGuard<'_> {
    fn drop(&mut self) {
        self.state
            .durable_admission_active
            .fetch_sub(1, Ordering::SeqCst);
    }
}

/// The shared state for a single joined network. Every long-lived
/// subsystem (driver loop, channels, rpc, handle) holds an
/// `Arc<NetworkState>`. Independent ownership domains use their own narrow
/// locks and notification points rather than one process-wide state lock.
pub struct NetworkState {
    pub network_id: String,
    /// The exact semantic bootstrap accepted before any peer or signaling
    /// surface is assembled.
    verified_bootstrap: crate::semantic::VerifiedBootstrap,
    mesh_context_id: crate::semantic::MeshContextId,
    pub identity: Arc<Identity>,
    pub transport: Transport,
    resource_scope: NetworkInstanceResourceScope,
    local_resources: LocalApplicationResourceScope,
    demand_links: Option<Mutex<DemandLinkPool>>,
    pub(super) hub_introductions: Option<Mutex<super::hub_introduction::HubIntroduction>>,
    // One fresh logical endpoint root per NetworkState, independent of the
    // forwarding carrier. Graph publication always precedes this mutex.
    hub_signaling_carrier: Mutex<Option<super::signaling_ingress::HubSignalingCarrier>>,
    /// The one owner of session promotion for this network instance.
    ///
    /// `None` when the process owner installed no resource provider. That is
    /// fail-closed: there is no post-authentication capacity to reserve, so no
    /// session promotes and no application operation runs. It is deliberately
    /// not a compatibility mode — nothing falls back to a peer string.
    ///
    /// `pub(super)` so the engine's own send path can hand it to the fence, and
    /// no wider: promotion itself happens inside the registry mutation lock,
    /// which is the only place the policy conjunct is true of an installation
    /// rather than of a device id. Nothing outside the engine can reach it, and
    /// there is no public accessor.
    pub(crate) session_broker: Option<SessionBroker>,

    pub config: RwLock<NetworkConfig>,
    /// The validated semantic envelope is fixed for this live owner.  It is
    /// retained separately from the mutable network configuration so a
    /// shutdown purge reacquires the exact same process StorageBytes claim
    /// that was admitted before the durable slot was opened.
    semantic_storage_claim: ResourceClaim,
    pub topology: RwLock<TopologyMode>,
    pub topology_impl: RwLock<Box<dyn Topology>>,
    /// The one bounded route planner and replay owner for this network.
    /// Its child resource scope makes every retained replay identity part of
    /// this network's provider-funded lifetime rather than an unfunded cache.
    pub(crate) hub_dial_cursor: AtomicUsize,

    /// Optional owner-funded hub advertisement scheduler. Spokes retain this
    /// controller for exact inbound owner/replay checks even when they do not
    /// emit advertisements themselves.
    pub(crate) hub: Option<Mutex<super::hub::HubController>>,
    /// Optional funded HubTree relation owner.  Its local policy and digest
    /// are fixed for this NetworkState lifetime; topology replacement must
    /// restart the owner before changing either.
    parenting:
        Option<Mutex<super::parenting::ParentingState<super::parenting::MonotonicParentingClock>>>,
    parenting_local: Option<super::parenting::ParentDeviceKey>,
    parenting_root: Option<super::parenting::ParentDeviceKey>,
    parenting_hubs: Box<[DeviceId]>,
    _parenting_backup_candidates: u32,
    parenting_digest: Option<[u8; 32]>,
    parenting_role: Option<super::parenting::ParentingRole>,
    parenting_next_sequence: AtomicU64,
    /// One bounded rendezvous-order cursor for paced parent alternatives.
    /// It is a selector cursor only; relation admission still requires the
    /// exact authenticated owner and a ParentingState ticket.
    parenting_target_after: Mutex<Option<DeviceId>>,
    parenting_pending: Mutex<Option<PendingParentAttach>>,
    /// Declared after the retained parenting payload so the root reservation
    /// remains live until those payloads have been dropped.
    _parenting_root_lease: Option<ResourceLease>,
    /// Optional node-local observation aggregate. It is diagnostic-only and
    /// cannot affect semantic admission, routing, or wire behavior.
    local_observation: Option<
        Mutex<
            super::local_observation::LocalObservationGraph<
                super::local_observation::MonotonicObservationClock,
            >,
        >,
    >,
    /// Fixed inline graph custody, separate from per-entry map reservations.
    /// This lease is acquired before the graph or its child scope is created.
    _local_observation_root_lease: Option<ResourceLease>,

    pub(crate) peers: PeerRegistry,
    pub roster: RwLock<Roster>,
    /// The one authoritative semantic graph for this joined network.
    ///
    /// This is persistent for the lifetime of the shared `NetworkState`: all
    /// durable-fact ingress paths must borrow this exact graph rather than
    /// constructing a transient `FactGraph::new()`. Its context and authority
    /// roots come only from `verified_bootstrap`; pinned peers and
    /// carrier/session identities are selectors and never become semantic
    /// authority.
    pub(crate) fact_graph: Arc<RwLock<crate::semantic::FactGraph>>,
    /// Production per-peer event pumps are retained by the network owner until
    /// their exact worker retirement path has completed.  Keeping the handles
    /// here prevents a pump's worker `Arc` (and its transport observation)
    /// from outliving `NetworkState::shutdown`.
    peer_event_pumps: Mutex<PeerEventPumpRegistry>,
    peer_event_pump_ready: Notify,
    peer_event_pump_shutdown_waiting: Notify,
    peer_event_pump_shutdown_started: AtomicBool,
    /// The one durable owner for this instance's canonical graph, projection
    /// commitment, and provisional semantic custody.  Its slot is local
    /// (`config.id`) while the snapshot itself is bound to the immutable
    /// bootstrap context, so two instances may share a wire network id while
    /// retaining independent on-disk state.
    durable_semantic_owner: Arc<DurableSemanticOwner>,
    /// Serializes the synchronous publication/validation portion of durable
    /// semantic work.  The guard is never held across an async transport
    /// await; callers receive a funded, exact send witness instead.
    durable_publication_gate: Mutex<()>,
    /// Bounds blocking durable requests before they enter the executor. Each
    /// request is already a policy-bounded batch and becomes one graph journal
    /// plus one SQLite transaction on the existing storage worker.
    durable_admission_lane: Arc<Semaphore>,
    #[cfg(test)]
    durable_admission_active: AtomicU64,
    #[cfg(test)]
    durable_admission_max: AtomicU64,
    durable_provisional: Mutex<Vec<ProvisionalCustody>>,
    durable_proof_outbox: DurableProofOutbox,
    pub current_phase: RwLock<MeshPhase>,

    pub events_tx: broadcast::Sender<MeshEvent>,
    pub(crate) application_gateway: crate::application_gateway::ApplicationGateway,

    pub(crate) signaling_tx: ResourceMailboxSender<SignalingOutbound>,
    /// Where every attached carrier delivers, and it takes a classified value
    /// rather than a bare [`SignalingInbound`]: the lane and the carrier
    /// provenance ride with the message to the engine instead of being computed
    /// and dropped at the bridge.
    pub(crate) signaling_inbound_tx: ResourceMailboxSender<EphemeralIngress>,
    /// The network's signaling runtime, once a carrier has attached one.
    ///
    /// Published here so the peer lifecycle can reach the single owner of
    /// de-duplication. The runtime is built by the bridge — it is the bridge
    /// that knows how many carriers share one — but "this attempt is over"
    /// is known here, and a key scoped to an attempt has to be released when
    /// that attempt ends or the scoping only defers the problem.
    ///
    /// `None` before any attach and after the last one is replaced. Nothing
    /// fails without it: releasing early is an optimization over waiting for
    /// provider pressure, so an unattached network simply has nothing to tell.
    signaling_runtime: parking_lot::RwLock<Option<Arc<super::signaling_ingress::SignalingRuntime>>>,
    /// Exact Nostr delivery settlement for this network's current driver.
    /// The bridge installs a closure over the retained driver handle; engine
    /// lifecycle code supplies only the exact attempt correlation and terminal
    /// outcome, never a device-id fallback.
    attempt_settlement: Mutex<Option<AttemptSettlement>>,
    pub cmd_tx: ResourceMailboxSender<NetworkCmd>,
    /// Dedicated provider-backed lane for manual ConnectPeer requests.  Its
    /// receiver is consumed by the supervisor's connection actor, leaving the
    /// ordered command lane free for governance, RPC, and transport events.
    connection_cmd_tx: ResourceMailboxSender<NetworkCmd>,
    connection_cmd_rx: Mutex<Option<ResourceMailboxReceiver<NetworkCmd>>>,
    pub(super) speculative_promotion_tx: ResourceMailboxSender<SpeculativePromotionCmd>,
    speculative_promotion_rx: Mutex<Option<ResourceMailboxReceiver<SpeculativePromotionCmd>>>,

    /// Receiving end of `signaling_tx` — held here so callers can
    /// drain it via [`Self::take_signaling_outbound_rx`] when they
    /// bring up their signaling task.
    signaling_outbound_rx: Mutex<Option<ResourceMailboxReceiver<SignalingOutbound>>>,
    /// Joinable forwarders created by the in-process signaling bridge. `Some`
    /// means registration is open; shutdown takes the option under this mutex
    /// before awaiting the handles, so a concurrent late attach cannot become
    /// an untracked task.
    #[cfg(feature = "transport-lab")]
    local_signaling_forwarders: Mutex<Option<Vec<JoinHandle<()>>>>,
    /// Controls that do not run an engine driver still need the command
    /// mailbox to be live: session promotion announces on it, and a closed
    /// receiver truthfully means the driver is gone. Parking the receiver in
    /// the state models an unread queue without turning it into a dead queue.
    #[cfg(test)]
    parked_command_receiver: Mutex<Option<ResourceMailboxReceiver<NetworkCmd>>>,
    shutdown_requested: AtomicBool,
    /// Counts mutation witnesses which may still be registering a task.  The
    /// shutdown path waits for this count before closing `shutdown_tasks`, so
    /// an admitted producer cannot lose its JoinHandle at the handoff.
    shutdown_mutations: Mutex<usize>,
    shutdown_mutations_ready: Notify,
    shutdown_tasks: Mutex<Option<ShutdownTaskRegistry>>,
    /// Set only after the shutdown path has released the durable writer
    /// owner. This is stronger than `shutdown_requested`: callers must not
    /// purge while teardown is still draining live state.
    shutdown_complete: std::sync::atomic::AtomicBool,
    shutdown_ready: Notify,

    /// Offerer-side reconnect intents (see [`ReconnectIntent`]). Keyed by
    /// device id; an entry lives from the moment we drop a peer we owe an
    /// offer to until the link is re-established or the reconnecting grace
    /// expires. Events re-offer these immediately (relay reconnect, the
    /// peer's announce); the state-watch tick is the backstop that retries
    /// on a backoff for the cases no event covers.
    pub reconnect_intents: Mutex<std::collections::HashMap<String, ReconnectIntent>>,

    /// One provider-owned answerer recovery cohort. Causes are exact owner
    /// tokens, while the collection itself has one retained provider lease and
    /// one in-flight publish generation. A later cause waits for the next
    /// generation rather than mutating a cohort already admitted for publish.
    recovery_cohort: Mutex<RecoveryCohort>,
    /// Exact carrier admission for ordinary attempt publications. The map is
    /// keyed by the authenticated attempt correlation; each entry is a finite
    /// attach cohort and is removed once every carrier refuses or the attempt
    /// is settled.
    carrier_state: CarrierState,

    /// Peers this node maintains a standing dial for (config
    /// `pinned_peers` plus runtime `connect_peer(…, sticky)`). On a
    /// Silent network a pinned peer is dialed whenever it announces —
    /// the one exception to "Silent never auto-dials" — and its
    /// reconnect intent never expires. See `handle_signaling_inbound`.
    pub sticky_peers: Mutex<std::collections::HashSet<String>>,

    /// Whether this network's **signed governance** has evicted *this
    /// device* — the cached verdict of
    /// [`super::governance::refresh_self_evicted`], recomputed at startup
    /// and after every log adoption/ratification. While true the engine
    /// stands down on this network: no announces out, no dialing on
    /// announces in (every member would deny us anyway — with proof).
    /// Derived state, never persisted: the adopted signed log IS the
    /// durable record, so a restart recomputes the same verdict.
    pub self_evicted: std::sync::atomic::AtomicBool,

    /// Per-network traffic accounting (see [`super::traffic`]) —
    /// written from the frame chokepoints, read by the status surface.
    pub traffic: super::traffic::TrafficCounters,

    /// Callers waiting for a specific peer to reach ACTIVE (the
    /// `connect_peer_wait` contract). Resolved on the mutual-approve
    /// transition; failed on terminal drops and shutdown.
    connect_waiters: Mutex<LeasedMap<String, ConnectWaiterBucket>>,
    #[cfg(test)]
    connect_waiter_registered: Notify,
    #[cfg(test)]
    connect_waiter_terminal: Notify,
    #[cfg(test)]
    connect_waiter_terminal_seen: AtomicBool,
    next_connect_waiter: std::sync::atomic::AtomicU64,

    /// Last time we reflected a peer's announce with one of our
    /// own. Rate-limited so a room with N peers all reacting to
    /// each other's announces doesn't degenerate into a publish
    /// storm — one outbound reactive announce per
    /// [`crate::config::SchedulerPolicyConfig::reactive_announce_min_interval_ms`]
    /// coalesces any number
    /// of inbound announces in that window. See the comment on
    /// the call site in `engine::mod::handle_signaling_inbound`
    /// for the discovery rationale.
    pub last_reactive_announce_at: Mutex<Option<std::time::Instant>>,

    /// Latched state of the passive clock-skew diagnostic — warn once when
    /// this device's wall clock has disagreed with its peers' (measured off
    /// the heartbeat pings they already send) for several consecutive
    /// ticks, clear once when it resolves. See `heartbeat::watch_clock_skew`.
    pub clock_skew_watch: Mutex<super::heartbeat::ClockSkewWatch>,

    /// Controls only: how many reliable acknowledgements this runtime has
    /// *attempted* to send.
    ///
    /// Incremented immediately before the send in `reliable::on_channel_seq_admitted`,
    /// so it counts the decision to acknowledge rather than a completed write —
    /// the same reading as [`crate::transport::diag::PeerDiag::hellos_sent`],
    /// and for the same reason. The lab fixture has no remote peer, so no write
    /// there can complete; a control measuring completions could not tell an
    /// acknowledgement this node refused to send from one it sent into a link
    /// with no far end, which is exactly the distinction the acceptance rule is
    /// about.
    ///
    /// It is test observation and nothing else. Nothing admits, accounts,
    /// retains or refuses on this value, and it does not exist in a production
    /// build.
    #[cfg(test)]
    pub(crate) channel_ack_attempts: std::sync::atomic::AtomicU64,

    /// Controls only: one action to run at the instant every exact-session
    /// retirement site has captured its `(owner, witness)` and has not yet
    /// retired anything.
    ///
    /// It exists for one property, which cannot be observed from outside the
    /// engine at all: that retirement names the session that failed rather than
    /// whichever session holds the device id when it runs. Driving a refusal and
    /// then replacing the session afterwards does not test that — a retirement
    /// keyed by device id passes it too. The replacement has to land *inside*
    /// the window, and this is the only point at which a control can put it
    /// there without a race of its own.
    ///
    /// One shot: it is taken before it is run, so a staged action fires for the
    /// first refusal that reaches a barrier and never for a later one. A control
    /// that stages it and observes it did not fire has learned that its refusal
    /// never reached the retirement it was aimed at, which is worth as much as
    /// the positive observation.
    ///
    /// Constraints on what may be staged, both of which every use below honours:
    /// it runs on the engine's own thread with no registry lock held, so it may
    /// promote or file state through the ordinary registry entry points; and it
    /// may not await, because these sites are not all async.
    ///
    /// Test observation and staging only. Nothing admits, accounts, retains or
    /// refuses on it, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) exact_retirement_barrier: Mutex<Option<Box<dyn FnOnce() + Send>>>,

    /// The park an armed control puts at the RPC reply's send boundary.
    ///
    /// Sibling of the barrier above and there for the same kind of reason: the
    /// property is about what happens *during* an operation, and no control can
    /// reach the inside of a spawned run from outside it. Revoking before the
    /// run starts and revoking after it finishes are both easy and neither is
    /// the case the finding names.
    ///
    /// Test observation and staging only. Nothing admits, accounts, retains or
    /// refuses on it, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) rpc_send_boundary: RpcSendBoundary,

    /// The instant between a handler run's fenced start and the embedder's
    /// closure being entered.
    ///
    /// The other half of the same problem `rpc_send_boundary` solves, at the
    /// other end of the run. A control asserting that a *started* run cannot be
    /// un-started has to deliver revocation after the start commits and before
    /// the closure is called, and that window is otherwise two adjacent
    /// statements with nothing between them.
    ///
    /// The same type, because it is the same mechanism and a second one could
    /// drift from it. Test observation and staging only; it does not exist in a
    /// production build.
    #[cfg(test)]
    pub(crate) rpc_handler_start_boundary: RpcSendBoundary,

    /// Controls only: park the next production DepartObserved receipt after
    /// it has been admitted, so a control can prove the receipt is in flight
    /// before allowing the exact send/retirement path to continue.
    ///
    /// Test and transport-lab observation only. It is absent from ordinary
    /// production builds and has no effect on receipt admission or custody.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) depart_observed_gate: DepartObservedGate,

    /// One action to run inside a handler run's start, between its early
    /// validity read and the fenced commit.
    ///
    /// A staged **synchronous** action rather than a park, because that instant
    /// is inside a synchronous decision: the run is not a future there, it is a
    /// function that has not returned yet, and there is nothing for an async
    /// boundary to hold. What a control needs to do there is act — revoke — and
    /// acting is exactly what a `FnOnce` can do.
    ///
    /// It is reached through the production call path rather than by a control
    /// calling the fenced begin itself. That distinction is the whole point: a
    /// control that called `begin` directly could observe the refusal and prove
    /// nothing about whether `on_rpc_request`'s spawned arm honours it.
    ///
    /// Test staging only, and it does not exist in a production build.
    #[cfg(test)]
    pub(crate) rpc_handler_precommit_action: Mutex<Option<Box<dyn FnOnce() + Send>>>,

    /// Force-reconnect handle for the signaling driver, stashed by
    /// [`crate::handle::JoinedNetwork::attach_signaling`] call is made, once the
    /// Nostr driver is up. Bumping the generation makes every relay
    /// drop its socket and redial immediately (see the driver's
    /// `force_reconnect`); the engine triggers it on resume-from-sleep
    /// so a zombie relay socket is replaced at once rather than after
    /// the kernel's multi-minute TCP timeout. `None` when no driver is
    /// attached (e.g. the in-process local broker used in tests).
    relay_reconnect: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// The signaling driver's relay-connected generation (its
    /// `relay_connected`); bumped on every fresh relay session. After a
    /// network change asks for a redial, the change handler waits for the
    /// next bump before renegotiating ICE, so the offer isn't published into
    /// a relay that hasn't reconnected yet. `None` when no driver is attached.
    relay_connected: Mutex<Option<Arc<watch::Sender<u64>>>>,

    /// Last time the ICE-failure path forced a relay redial via
    /// [`request_relay_reconnect_throttled`]. Gates the "no remote
    /// candidates arrived" rescue (see
    /// `ice_watchdog::on_checking_timeout`) so a peer that keeps timing
    /// out every `ICE_CHECKING_TIMEOUT_MS` can't redial the relays on
    /// every cycle — one redial per
    /// configured rescue interval is enough to recover a
    /// genuinely-wedged signaling socket without churning healthy ones.
    last_relay_rescue_at: Mutex<Option<std::time::Instant>>,

    /// Set by the network watcher when the OS reports *no* primary
    /// outbound IP (neither v4 nor v6) — i.e. the host is fully
    /// offline, the state macOS lands in for a second or two on wake
    /// before the interface comes back. While true, the ICE machinery
    /// holds off re-gathering and tearing down peers: a `restart_ice()`
    /// in this window can't bind a socket (the `Network is unreachable`
    /// wall in the logs) and would only burn a checking-timeout on a
    /// doomed attempt. Cleared the moment an interface returns, at which
    /// point the network-change handler drives a clean restart fan-out.
    offline: std::sync::atomic::AtomicBool,

    /// Broadcast of per-peer connection-state transitions for the
    /// Phase-0 connection tracer (`engine::conn_trace`). Kept separate
    /// from `events_tx` so trace volume can never evict real Peer /
    /// Phase events from the GUI's subscriber, and so `receiver_count()`
    /// cleanly reflects whether anyone is watching — which is what gates
    /// the sweep's cost in the driver loop.
    pub conn_trace_tx: broadcast::Sender<ConnTrace>,
    /// When true, the connection tracer emits even with no live
    /// subscriber, so daemon file logs capture transitions. Read once
    /// from `MYOWNMESH_CONN_TRACE` at construction (any non-empty value
    /// other than `0` enables it).
    conn_trace_force_on: bool,
}

/// A linearization witness for work that may mutate peer state or publish a
/// reactive announce.  The witness is acquired with one atomic observation of
/// the lifecycle flag; shutdown's store is the corresponding transition.  A
/// witness acquired before that transition may finish, but no later caller
/// can enter the operation.  It carries no lock and is therefore safe to hold
/// across an async cleanup await.
pub(crate) struct ShutdownMutationPermit<'a> {
    state: &'a NetworkState,
}

impl Drop for ShutdownMutationPermit<'_> {
    fn drop(&mut self) {
        let mut admitted = self.state.shutdown_mutations.lock();
        *admitted = admitted
            .checked_sub(1)
            .expect("shutdown mutation permit released twice");
        if *admitted == 0 {
            self.state.shutdown_mutations_ready.notify_waiters();
        }
    }
}

impl NetworkState {
    fn funded_carrier_instances<I>(
        &self,
        instances: I,
    ) -> std::result::Result<CarrierInstanceList, ResourceUnavailable>
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        let claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(std::mem::size_of::<CarrierInstanceNode>()).map_err(|_| {
                    ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::AccountedMemoryBytes,
                    }
                })?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
        let mut list = CarrierInstanceList::default();
        let mut unique = 0usize;
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if duplicate {
                continue;
            }
            unique = unique
                .checked_add(1)
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            let lease = self.local_resources.acquire(claim)?;
            list.push_front(Box::new(CarrierInstanceNode {
                instance,
                _lease: lease,
                next: None,
            }));
        }
        if unique == 0 {
            return Err(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            });
        }
        Ok(list)
    }

    #[allow(clippy::type_complexity)]
    pub(crate) fn new_in_mesh_scope_with_instance_root(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        verified_bootstrap: crate::semantic::VerifiedBootstrap,
        mesh_scope: &MeshRuntimeResourceScope,
        local_resources: &LocalApplicationResourceScope,
        instance_root: Option<std::path::PathBuf>,
    ) -> Result<(
        Arc<Self>,
        ResourceMailboxReceiver<EphemeralIngress>,
        ResourceMailboxReceiver<NetworkCmd>,
    )> {
        Self::new_in_resource_scope(
            config,
            identity,
            transport,
            mesh_scope.network_instance_scope(),
            local_resources.child()?,
            verified_bootstrap,
            instance_root,
        )
    }

    #[allow(clippy::type_complexity)]
    fn new_in_resource_scope(
        config: NetworkConfig,
        identity: Arc<Identity>,
        transport: Transport,
        resource_scope: NetworkInstanceResourceScope,
        local_resources: LocalApplicationResourceScope,
        verified_bootstrap: crate::semantic::VerifiedBootstrap,
        instance_root: Option<std::path::PathBuf>,
    ) -> Result<(
        Arc<Self>,
        ResourceMailboxReceiver<EphemeralIngress>,
        ResourceMailboxReceiver<NetworkCmd>,
    )> {
        // Standing dials survive restarts by riding the network config —
        // the daemon re-joins with the same `pinned_peers`, and this seed
        // re-arms them without any runtime re-pinning.
        verified_bootstrap
            .validate()
            .map_err(|error| Error::Network(format!("verified bootstrap rejected: {error}")))?;
        if verified_bootstrap.context().scope != config.network_id {
            return Err(Error::Network(format!(
                "verified bootstrap scope {} does not match network id {}",
                verified_bootstrap.context().scope,
                config.network_id
            )));
        }
        let bootstrap_is_closed = matches!(
            verified_bootstrap.policy(),
            crate::semantic::VerifiedProjectPolicy::Closed(_)
        );
        let config_is_closed = matches!(config.kind, crate::config::NetworkKind::Closed);
        if bootstrap_is_closed != config_is_closed {
            return Err(Error::Network(format!(
                "verified bootstrap policy shape does not match configured network kind {:?}",
                config.kind
            )));
        }
        let semantic_policy = config
            .semantic_policy()
            .map_err(|error| Error::Network(format!("semantic policy rejected: {error}")))?;
        config
            .scheduler_policy()
            .map_err(|error| Error::Network(format!("scheduler policy rejected: {error}")))?;
        let mesh_context_id = verified_bootstrap.context_id();

        // Storage is one process-owned claim for the complete semantic slot
        // envelope (database, WAL, SHM, and emergency reserve).  Acquire it
        // before any semantic path, VFS, or writer lock can be touched.  A
        // provider refusal therefore remains the typed resource-pressure
        // error and leaves no partially-created durable slot behind.
        let pinned: std::collections::HashSet<String> =
            config.pinned_peers.iter().cloned().collect();
        let persistence_root = instance_root.as_deref();
        // The roster is advisory metadata only.  Start with an empty keyed
        // projection and restore canonical semantic state before consulting
        // any on-disk labels or timestamps.
        let roster = crate::roster::empty_for_at(persistence_root, &config.network_id);
        // Topology is connector/deployment policy, not a canonical
        // authority-bearing fact. It therefore remains local configuration.
        let effective_topology = config.topology.clone();
        let topology_impl = crate::topology::from_mode(&effective_topology);
        let event_capacity = config.event_capacity_usize()?;
        let trace_capacity = config.connection_trace_capacity_usize()?;
        let (events_tx, _) = broadcast::channel(event_capacity);
        // Deep enough to ride out a transition storm (a sleep/wake
        // fan-out re-handshaking every peer) without the watcher lagging;
        // lossy past that, with a `lagged` marker surfaced to the stream.
        let (conn_trace_tx, _) = broadcast::channel(trace_capacity);
        let conn_trace_force_on =
            std::env::var("MYOWNMESH_CONN_TRACE").is_ok_and(|v| !v.is_empty() && v != "0");
        let (signaling_tx, signaling_outbound_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let (cmd_tx, cmd_rx) = crate::resource::resource_mailbox(local_resources.child()?)?;
        let (connection_cmd_tx, connection_cmd_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let (speculative_promotion_tx, speculative_promotion_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let (signaling_inbound_tx, signaling_inbound_rx) =
            crate::resource::resource_mailbox(local_resources.child()?)?;
        let session_broker = transport.session_broker();
        let local_device_id = identity.public_id().to_string();
        let (
            parenting,
            parenting_root_lease,
            parenting_local,
            parenting_root,
            parenting_hubs,
            parenting_backup_candidates,
            parenting_digest,
            parenting_role,
        ) = match &effective_topology {
            TopologyMode::HubTree {
                root,
                hubs,
                backup_candidates,
            } => {
                let tree = config.tree.ok_or_else(|| {
                    Error::Network("HubTree requires an explicit local tree policy".into())
                })?;
                let hub_policy = config.hub.ok_or_else(|| {
                    Error::Network("HubTree requires an explicit hub timing/profile policy".into())
                })?;
                let max_children = usize::try_from(tree.max_children).map_err(|_| {
                    Error::Network("HubTree max_children does not fit usize".into())
                })?;
                let max_backups = usize::try_from(tree.max_backups)
                    .map_err(|_| Error::Network("HubTree max_backups does not fit usize".into()))?;
                let max_pending = usize::try_from(tree.max_pending)
                    .map_err(|_| Error::Network("HubTree max_pending does not fit usize".into()))?;
                // Semantic DeviceId interning retains canonical identity
                // backing that is not represented by size_of::<DeviceId>().
                // Charge the raw canonical text before parsing/interning it;
                // the fixed handle slice and pending wrapper are charged in
                // the same root lease, while the child scope is charged by
                // LocalApplicationResourceScope::child below.
                let identity_bytes = hubs
                    .iter()
                    .try_fold(root.len(), |bytes, hub| bytes.checked_add(hub.len()))
                    .and_then(|bytes| bytes.checked_add(local_device_id.len()))
                    .ok_or_else(|| Error::Network("HubTree identity backing overflows".into()))?;
                let hub_backing_bytes = hubs
                    .len()
                    .checked_mul(std::mem::size_of::<DeviceId>())
                    .ok_or_else(|| Error::Network("HubTree hub backing overflows".into()))?;
                let pending_backing_bytes = max_pending
                    .checked_mul(std::mem::size_of::<PendingParentAttach>())
                    .ok_or_else(|| Error::Network("HubTree pending backing overflows".into()))?;
                let root_bytes = std::mem::size_of::<
                    super::parenting::ParentingState<super::parenting::MonotonicParentingClock>,
                >()
                .checked_add(hub_backing_bytes)
                .and_then(|bytes| bytes.checked_add(pending_backing_bytes))
                .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Mutex<Option<DeviceId>>>()))
                .and_then(|bytes| bytes.checked_add(identity_bytes))
                .and_then(|bytes| u64::try_from(bytes).ok())
                .ok_or_else(|| Error::Network("HubTree root size overflows u64".into()))?;
                let root_claim =
                    ResourceClaim::single(ResourceClass::AccountedMemoryBytes, root_bytes);
                let root_lease = local_resources.acquire(root_claim).map_err(|error| {
                    Error::Network(format!("HubTree root resource refusal: {error}"))
                })?;
                let local = DeviceId::from_canonical_str(&local_device_id)
                    .map_err(|_| Error::Network("local identity is not canonical".into()))?;
                let root_device = DeviceId::from_canonical_str(root)
                    .map_err(|_| Error::Network("HubTree root is not canonical".into()))?;
                let mut local_is_hub = false;
                for hub in hubs {
                    let hub = DeviceId::from_canonical_str(hub)
                        .map_err(|_| Error::Network("HubTree hub is not canonical".into()))?;
                    if hub == root_device {
                        return Err(Error::Network(
                            "HubTree root cannot also be a configured hub".into(),
                        ));
                    }
                    local_is_hub |= hub == local;
                }
                let role = if local == root_device {
                    super::parenting::ParentingRole::Root
                } else if local_is_hub {
                    super::parenting::ParentingRole::Hub(1)
                } else {
                    super::parenting::ParentingRole::Leaf
                };
                let role_root = super::parenting::ParentDeviceKey::from_device(&root_device);
                let role_local = super::parenting::ParentDeviceKey::from_device(&local);
                let trickle = crate::protocol::HubTrickleProfile::new(
                    hub_policy.trickle_imin_ms,
                    hub_policy.trickle_imax_ms,
                    u64::from(hub_policy.trickle_redundancy),
                    hub_policy.trickle_reset_window_ms,
                    u64::from(hub_policy.trickle_max_resets_per_window),
                );
                let mut policy = super::parenting::ParentingPolicy {
                    local: role_local,
                    root: role_root,
                    role,
                    max_hub_tier: 1,
                    max_children,
                    max_backups,
                    max_pending,
                    max_age_ticks: tree.max_age_ms,
                    context_id: *mesh_context_id.as_bytes(),
                    configuration_digest: [0; 32],
                };
                let planned = super::parenting::ParentingState::<
                    super::parenting::MonotonicParentingClock,
                >::planned_retained_claim(policy)
                .map_err(|error| Error::Network(format!("HubTree claim rejected: {error}")))?;
                // `planned` is the pure shape check for future per-relation
                // leases.  Those leases are acquired by ParentingState on
                // insertion; including them here would reserve the same
                // dynamic custody twice.
                let _ = root_claim
                    .checked_add(planned)
                    .map_err(|_| Error::Network("HubTree planned claim overflows".into()))?;
                let scope = local_resources.child().map_err(|error| {
                    Error::Network(format!("HubTree resource scope refused: {error}"))
                })?;
                let mut configured_hubs = hubs
                    .iter()
                    .map(|hub| {
                        DeviceId::from_canonical_str(hub)
                            .map_err(|_| Error::Network("HubTree hub is not canonical".into()))
                    })
                    .collect::<Result<Vec<_>>>()?;
                configured_hubs.sort();
                configured_hubs.dedup();
                let digest = crate::protocol::hub_tree_configuration_digest(
                    mesh_context_id,
                    crate::protocol::HubTreeTopologyKind::ShallowV1,
                    &root_device,
                    &configured_hubs,
                    *backup_candidates,
                    trickle,
                );
                policy.configuration_digest = digest;
                let state = super::parenting::ParentingState::new(
                    scope,
                    policy,
                    super::parenting::MonotonicParentingClock::new(),
                )
                .map_err(|error| Error::Network(format!("HubTree policy rejected: {error}")))?;
                (
                    Some(Mutex::new(state)),
                    Some(root_lease),
                    Some(role_local),
                    Some(role_root),
                    configured_hubs.into_boxed_slice(),
                    *backup_candidates,
                    Some(digest),
                    Some(role),
                )
            }
            _ => (
                None,
                None,
                None,
                None,
                Vec::new().into_boxed_slice(),
                0,
                None,
                None,
            ),
        };
        let demand_links = config
            .introduction
            .map(|policy| DemandLinkPool::new(policy, local_resources.clone()))
            .transpose()?
            .map(Mutex::new);
        let hub_introductions = config
            .introduction
            .map(|policy| {
                let local = DeviceId::from_canonical_str(&local_device_id)
                    .map_err(|_| Error::Network("local introduction identity is invalid".into()))?;
                super::hub_introduction::HubIntroduction::new(
                    policy,
                    local_resources.clone(),
                    mesh_context_id,
                    &local,
                )
                .map(Mutex::new)
                .map_err(|error| Error::Network(format!("introduction root refused: {error}")))
            })
            .transpose()?;
        let hub = match config.hub {
            Some(policy) => {
                let local_device = crate::semantic::DeviceId::from_canonical_str(&local_device_id)
                    .map_err(|_| {
                        Error::Network("local identity is not a canonical DeviceId".into())
                    })?;
                super::hub::HubController::new(
                    policy,
                    &effective_topology,
                    mesh_context_id,
                    local_device,
                    &local_resources,
                )?
                .map(Mutex::new)
            }
            None => None,
        };
        let (local_observation, local_observation_root_lease) = match config.local_observations {
            Some(policy) => {
                let limits = super::local_observation::LocalObservationLimits {
                    max_records: usize::try_from(policy.max_records).map_err(|_| {
                        Error::Network("local observation max_records does not fit usize".into())
                    })?,
                    max_records_per_subject: usize::try_from(policy.max_records_per_subject)
                        .map_err(|_| {
                            Error::Network(
                                "local observation max_records_per_subject does not fit usize"
                                    .into(),
                            )
                        })?,
                    max_age_ticks: policy.max_age_ms,
                    max_maintenance_work: usize::try_from(policy.max_maintenance_per_tick)
                        .map_err(|_| {
                            Error::Network(
                                "local observation max_maintenance_per_tick does not fit usize"
                                    .into(),
                            )
                        })?,
                };
                type LocalObservationGraph = super::local_observation::LocalObservationGraph<
                    super::local_observation::MonotonicObservationClock,
                >;
                let graph_bytes = u64::try_from(std::mem::size_of::<LocalObservationGraph>())
                    .map_err(|_| {
                        Error::Network("local observation graph size overflows u64".into())
                    })?;
                let graph_lease = local_resources
                    .acquire(ResourceClaim::single(
                        ResourceClass::AccountedMemoryBytes,
                        graph_bytes,
                    ))
                    .map_err(|error| {
                        Error::Network(format!("local observation graph resource refusal: {error}"))
                    })?;
                let scope = local_resources.child().map_err(|error| {
                    Error::Network(format!("local observation resource scope refused: {error}"))
                })?;
                (
                    Some(Mutex::new(
                        super::local_observation::LocalObservationGraph::new(
                            scope,
                            limits,
                            super::local_observation::MonotonicObservationClock::new(),
                        )
                        .map_err(|error| {
                            Error::Network(format!("local observation policy rejected: {error}"))
                        })?,
                    )),
                    Some(graph_lease),
                )
            }
            None => (None, None),
        };
        let durable_root = instance_root
            .clone()
            .unwrap_or(crate::dirs::data_dir()?.join("mesh"));
        let durable_semantic_store =
            DurableSemanticStore::with_policy(durable_root, &config.id, semantic_policy);
        let semantic_storage_claim = durable_semantic_store
            .storage_claim()
            .map_err(|error| Error::Network(format!("semantic storage envelope: {error}")))?;
        let semantic_storage_lease = local_resources.acquire(semantic_storage_claim)?;
        let durable_semantic_owner = Arc::new(
            durable_semantic_store
                .open_writable_funded(semantic_storage_lease)
                .map_err(|error| Error::Network(format!("open semantic slot: {error}")))?,
        );
        let durable_proof_outbox = DurableProofOutbox::from_owner_with_policy(
            Arc::clone(&durable_semantic_owner),
            semantic_policy,
        )
        .map_err(|error| Error::Network(format!("open semantic proof outbox: {error}")))?;
        let (initial_graph, durable_provisional) =
            match durable_semantic_owner.restore(&verified_bootstrap) {
                Ok(restored) => restored.into_parts(),
                Err(crate::semantic::store::DurableStoreError::Missing { .. }) => {
                    let graph = crate::semantic::FactGraph::from_bootstrap_with_policy(
                        &verified_bootstrap,
                        semantic_policy,
                    );
                    durable_semantic_owner
                        .commit(&graph, Vec::new())
                        .map_err(|error| {
                            Error::Network(format!("initial semantic snapshot: {error}"))
                        })?;
                    (graph, Vec::new())
                }
                Err(error) => {
                    return Err(Error::Network(format!(
                        "restoring semantic snapshot: {error}"
                    )))
                }
            };
        let fact_graph = Arc::new(RwLock::new(initial_graph));
        let state = Arc::new(Self {
            network_id: config.network_id.clone(),
            verified_bootstrap,
            mesh_context_id,
            identity,
            transport,
            resource_scope,
            session_broker,
            config: RwLock::new(config.clone()),
            semantic_storage_claim,
            topology: RwLock::new(effective_topology),
            topology_impl: RwLock::new(topology_impl),
            hub_dial_cursor: AtomicUsize::new(0),
            hub,
            demand_links,
            hub_introductions,
            hub_signaling_carrier: Mutex::new(None),
            parenting,
            _parenting_root_lease: parenting_root_lease,
            parenting_local,
            parenting_root,
            parenting_hubs,
            _parenting_backup_candidates: parenting_backup_candidates,
            parenting_digest,
            parenting_role,
            parenting_next_sequence: AtomicU64::new(1),
            parenting_target_after: Mutex::new(None),
            parenting_pending: Mutex::new(None),
            local_observation,
            _local_observation_root_lease: local_observation_root_lease,
            peers: PeerRegistry::new(local_device_id),
            roster: RwLock::new(roster),
            fact_graph,
            peer_event_pumps: Mutex::new(PeerEventPumpRegistry::new()),
            peer_event_pump_ready: Notify::new(),
            peer_event_pump_shutdown_waiting: Notify::new(),
            peer_event_pump_shutdown_started: AtomicBool::new(false),
            durable_semantic_owner,
            durable_publication_gate: Mutex::new(()),
            durable_admission_lane: Arc::new(Semaphore::new(1)),
            #[cfg(test)]
            durable_admission_active: AtomicU64::new(0),
            #[cfg(test)]
            durable_admission_max: AtomicU64::new(0),
            durable_provisional: Mutex::new(durable_provisional),
            durable_proof_outbox,
            current_phase: RwLock::new(MeshPhase::Joining),
            events_tx,
            application_gateway: crate::application_gateway::ApplicationGateway::new(
                local_resources.clone(),
            ),
            local_resources,
            signaling_tx,
            signaling_inbound_tx,
            signaling_runtime: parking_lot::RwLock::new(None),
            attempt_settlement: Mutex::new(None),
            cmd_tx,
            connection_cmd_tx,
            connection_cmd_rx: Mutex::new(Some(connection_cmd_rx)),
            speculative_promotion_tx,
            speculative_promotion_rx: Mutex::new(Some(speculative_promotion_rx)),
            signaling_outbound_rx: Mutex::new(Some(signaling_outbound_rx)),
            #[cfg(feature = "transport-lab")]
            local_signaling_forwarders: Mutex::new(Some(Vec::new())),
            #[cfg(test)]
            parked_command_receiver: Mutex::new(None),
            shutdown_requested: AtomicBool::new(false),
            shutdown_mutations: Mutex::new(0),
            shutdown_mutations_ready: Notify::new(),
            shutdown_tasks: Mutex::new(Some(ShutdownTaskRegistry::new())),
            shutdown_complete: std::sync::atomic::AtomicBool::new(false),
            shutdown_ready: Notify::new(),
            reconnect_intents: Mutex::new(std::collections::HashMap::new()),
            recovery_cohort: Mutex::new(RecoveryCohort::new()),
            carrier_state: CarrierState::default(),
            sticky_peers: Mutex::new(pinned),
            self_evicted: std::sync::atomic::AtomicBool::new(false),
            traffic: super::traffic::TrafficCounters::default(),
            connect_waiters: Mutex::new(LeasedMap::new()),
            #[cfg(test)]
            connect_waiter_registered: Notify::new(),
            #[cfg(test)]
            connect_waiter_terminal: Notify::new(),
            #[cfg(test)]
            connect_waiter_terminal_seen: AtomicBool::new(false),
            next_connect_waiter: std::sync::atomic::AtomicU64::new(1),
            last_reactive_announce_at: Mutex::new(None),
            clock_skew_watch: Mutex::new(super::heartbeat::ClockSkewWatch::default()),
            #[cfg(test)]
            channel_ack_attempts: std::sync::atomic::AtomicU64::new(0),
            #[cfg(test)]
            exact_retirement_barrier: Mutex::new(None),
            #[cfg(test)]
            rpc_send_boundary: RpcSendBoundary::default(),
            #[cfg(test)]
            rpc_handler_start_boundary: RpcSendBoundary::default(),
            #[cfg(all(test, feature = "transport-lab"))]
            depart_observed_gate: DepartObservedGate::default(),
            #[cfg(test)]
            rpc_handler_precommit_action: Mutex::new(None),
            relay_reconnect: Mutex::new(None),
            relay_connected: Mutex::new(None),
            last_relay_rescue_at: Mutex::new(None),
            offline: std::sync::atomic::AtomicBool::new(false),
            conn_trace_tx,
            conn_trace_force_on,
        });
        // Read advisory labels only after the canonical graph/store has been
        // restored. Corrupt or unavailable metadata becomes an empty cache and
        // cannot block authority startup.
        *state.roster.write() =
            crate::roster::load_advisory_at(persistence_root, &state.network_id);
        // Rebuild the compatibility roster from the restored canonical graph
        // before the state becomes observable. The roster is UI metadata only;
        // no admission decision may depend on its persisted bytes.
        super::governance::apply_canonical_projection_checked(&state)?;
        // A restored canonical eviction must be visible before this state can
        // escape to callers.  The driver repeats this refresh before any
        // announce or dial, but it is spawned asynchronously; deferring the
        // first refresh to that task leaves a window where an already-evicted
        // installation reports itself live immediately after reopen.
        super::governance::refresh_self_evicted(&state);
        // The registry announces a newly minted session on this same queue, so
        // the driver handles it once every fence lock has been released. Bound
        // here because this is the one place that owns both the registry and the
        // queue; the registry cannot construct it and the driver cannot reach
        // inside the fence.
        state.peers.bind_canonical_authority(
            state.verified_bootstrap().clone(),
            state.authoritative_fact_graph(),
        );
        state.peers.bind_command_sink(state.cmd_tx.clone());
        state
            .peers
            .bind_speculative_promotion_sink(state.speculative_promotion_tx.clone());
        Ok((state, signaling_inbound_rx, cmd_rx))
    }

    /// The exact semantic identity selected by the verified bootstrap.
    pub fn mesh_context_id(&self) -> crate::semantic::MeshContextId {
        self.mesh_context_id
    }

    /// The canonical, wire-safe spelling of this state's semantic context.
    ///
    /// This is derived from the immutable [`crate::semantic::MeshContextId`]
    /// selected by the
    /// verified bootstrap; it is never reconstructed from a carrier, peer, or
    /// mutable network configuration.
    pub fn mesh_context_id_string(&self) -> String {
        self.mesh_context_id.to_string()
    }

    /// The validated bootstrap that owns this network state's semantic policy.
    pub fn verified_bootstrap(&self) -> &crate::semantic::VerifiedBootstrap {
        &self.verified_bootstrap
    }

    /// The sealed policy projected by the validated bootstrap.
    ///
    /// Callers may inspect this immutable projection when deciding whether a
    /// canonical semantic commit can affect a policy-owned path. They cannot
    /// supply roots or mutate the bootstrap through this reference.
    pub fn verified_policy(&self) -> &crate::semantic::VerifiedProjectPolicy {
        self.verified_bootstrap.policy()
    }

    pub fn verified_authority_root(&self) -> Option<&str> {
        match self.verified_policy() {
            crate::semantic::VerifiedProjectPolicy::Open => None,
            crate::semantic::VerifiedProjectPolicy::Closed(policy) => Some(policy.authority_root()),
        }
    }

    /// The exact persisted bootstrap record, exposed read-only for durable
    /// handoff and diagnostics without exposing mutable authority state.
    pub fn verified_bootstrap_record(&self) -> &crate::semantic::BootstrapRecord {
        self.verified_bootstrap.record()
    }

    pub(crate) fn peer_connection_resource_scope(
        &self,
    ) -> crate::resource::PeerConnectionResourceScope {
        self.resource_scope.peer_connection_scope()
    }

    pub(super) fn reserve_introduction_placeholder(&self, target: &str) -> Result<ResourceLease> {
        Ok(self
            .local_resources
            .acquire(PeerRegistry::introduction_placeholder_claim(target.len())?)?)
    }

    pub(super) fn reserve_demand_link(&self) -> Result<DemandLinkReservation<'_>> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(Error::Network("network is shutting down".into()));
        }
        let pool = self
            .demand_links
            .as_ref()
            .ok_or_else(|| Error::Network("application introduction is disabled".into()))?;
        let entry = {
            let mut state = pool.lock();
            let total = state
                .links
                .len()
                .checked_add(state.reserved)
                .ok_or_else(|| Error::Network("demand link count overflow".into()))?;
            let limit = usize::try_from(state.policy.max_transient_links)
                .map_err(|_| Error::Network("demand link limit is unrepresentable".into()))?;
            if total >= limit {
                return Err(Error::Network("demand link capacity refused".into()));
            }
            let entry = state.resources.acquire(DemandLinkPool::entry_claim()?)?;
            state.reserved += 1;
            entry
        };
        Ok(DemandLinkReservation {
            pool,
            entry: Some(entry),
        })
    }

    pub(super) fn begin_demand_link_use(
        &self,
        owner: &PeerOwnerToken,
    ) -> Result<Option<DemandLinkUse<'_>>> {
        let Some(pool) = self.demand_links.as_ref() else {
            return Ok(None);
        };
        let key = DeviceId::canonical_key_bytes(owner.device_id())
            .map_err(|_| Error::Network("application peer is not canonical".into()))?;
        let mut state = pool.lock();
        let Some(link) = state.links.get_mut(&key) else {
            return Ok(None);
        };
        if !same_demand_owner(&link.owner, owner) {
            // A new, independently installed connection is borrowed. An old
            // demand entry cannot take ownership of it or reset its activity.
            return Ok(None);
        }
        if !link.activity.begin(std::time::Instant::now()) {
            return Err(Error::Network("demand connection is retiring".into()));
        }
        Ok(Some(DemandLinkUse {
            pool,
            key,
            generation: link.generation,
        }))
    }

    pub(super) fn forget_demand_link(&self, owner: &PeerOwnerToken) {
        let Some(pool) = self.demand_links.as_ref() else {
            return;
        };
        let Ok(key) = DeviceId::canonical_key_bytes(owner.device_id()) else {
            return;
        };
        let mut pool = pool.lock();
        if pool.links.get(&key).is_some_and(|link| {
            same_demand_owner(&link.owner, owner)
                && link.settlement == IntroductionSettlementPhase::Active
                && link.detached.is_none()
                && link.pump.is_none()
                && link.pump_registered
                && link.pump_joined.is_some()
        }) {
            pool.links.remove(&key);
        }
    }

    /// Called inside the handler's exact logical-session admission, after
    /// funding its task and before it can be queued or invoke application code.
    pub(super) fn begin_owned_demand_link_use(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
    ) -> Result<Option<OwnedDemandLinkUse>> {
        let Some(pool) = self.demand_links.as_ref() else {
            return Ok(None);
        };
        let key = DeviceId::canonical_key_bytes(owner.device_id())
            .map_err(|_| Error::Network("application peer is not canonical".into()))?;
        let mut pool = pool.lock();
        let Some(link) = pool.links.get_mut(&key) else {
            return Ok(None);
        };
        if !same_demand_owner(&link.owner, owner) {
            return Ok(None);
        }
        if !link.activity.begin(std::time::Instant::now()) {
            return Err(Error::Network("demand connection is retiring".into()));
        }
        Ok(Some(OwnedDemandLinkUse {
            state: Arc::clone(self),
            key,
            generation: link.generation,
        }))
    }

    pub(super) fn introduction_native_owner(
        &self,
        target: &str,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> Option<PeerOwnerToken> {
        let key = DeviceId::canonical_key_bytes(target).ok()?;
        let pool = self.demand_links.as_ref()?.lock();
        let entry = pool.links.get(&key)?;
        (entry.introduction == ticket).then(|| entry.owner.clone())
    }

    pub(super) fn queue_failed_introduction(
        &self,
        key: [u8; 32],
        ticket: super::hub_introduction::IntroductionTicket,
        generation: u64,
    ) {
        let Some(pool) = self.demand_links.as_ref() else {
            return;
        };
        let mut pool = pool.lock();
        let Some(link) = pool.links.get_mut(&key).filter(|link| {
            link.introduction == ticket
                && link.generation == generation
                && link.settlement == IntroductionSettlementPhase::Active
        }) else {
            return;
        };
        // Holding the record lock makes successful mailbox admission and its
        // phase publication one transition to the consumer. A refused enqueue
        // leaves the original record eligible for the next bounded tick.
        if self
            .connection_cmd_tx
            .send(NetworkCmd::SettleIntroduction {
                key,
                ticket,
                generation,
            })
            .is_ok()
        {
            link.settlement = IntroductionSettlementPhase::Queued;
        }
    }

    pub(super) fn queue_introduction_ticket(
        &self,
        target: &str,
        ticket: super::hub_introduction::IntroductionTicket,
    ) {
        if let (Some(pool), Ok(key)) = (
            self.demand_links.as_ref(),
            DeviceId::canonical_key_bytes(target),
        ) {
            let generation = pool
                .lock()
                .links
                .get(&key)
                .filter(|link| link.introduction == ticket)
                .map(|link| link.generation);
            if let Some(generation) = generation {
                self.queue_failed_introduction(key, ticket, generation);
                return;
            }
        }
        let mut waiters = self.connect_waiters.lock();
        let Some(bucket) = waiters.get_mut(target) else {
            return;
        };
        for waiter in bucket.waiters.iter_mut() {
            if waiter
                .shared
                .introduction
                .lock()
                .as_ref()
                .is_some_and(|binding| binding.ticket == ticket)
            {
                if !waiter.shared.settlement_queued.load(Ordering::Acquire)
                    && self
                        .connection_cmd_tx
                        .send(NetworkCmd::SettleIntroductionWait(
                            super::command::IntroductionWaitTransfer {
                                shared: waiter.shared.clone(),
                            },
                        ))
                        .is_ok()
                {
                    waiter
                        .shared
                        .settlement_queued
                        .store(true, Ordering::Release);
                }
                return;
            }
        }
    }

    pub(super) async fn settle_introduction_wait(
        &self,
        wait: super::command::IntroductionWaitTransfer,
    ) {
        use super::hub_introduction::IntroductionLifetime;
        let Some(_permit) = self.try_admit_shutdown_mutation() else {
            return;
        };
        let Some(binding) = *wait.shared.introduction.lock() else {
            return;
        };
        wait.shared
            .settlement_queued
            .store(false, Ordering::Release);
        let Some(controller) = self.hub_introductions.as_ref() else {
            return;
        };
        let never_bound = {
            let mut controller = controller.lock();
            match controller.lifetime(binding.ticket, std::time::Instant::now()) {
                IntroductionLifetime::Live { .. } => return,
                IntroductionLifetime::Elapsed { .. } => {
                    controller.failed(binding.ticket);
                }
                IntroductionLifetime::Terminal { .. } => {}
                IntroductionLifetime::Missing => {
                    drop(controller);
                    self.resolve_introduction_waiters(
                        &wait.shared.device_id,
                        binding.ticket,
                        false,
                    );
                    return;
                }
            }
            // The same controller guard terminalizes before checking its
            // historical native binding. This actor serializes constructors;
            // no future BeginIntroducedPeer can start this terminal ticket.
            controller.native_was_bound(binding.ticket) == Some(false)
        };
        if never_bound {
            self.resolve_bound_connect_waiters(
                &wait.shared.device_id,
                binding.ticket,
                ChannelDemandOutcome::NoOwnedAttemptRefused,
            );
            return;
        }
        let record = self.demand_links.as_ref().and_then(|pool| {
            let key = DeviceId::canonical_key_bytes(&wait.shared.device_id).ok()?;
            pool.lock()
                .links
                .get(&key)
                .filter(|link| link.introduction == binding.ticket)
                .map(|link| (key, link.generation))
        });
        if let Some((key, generation)) = record {
            self.settle_failed_introduction(key, binding.ticket, generation)
                .await;
        } else {
            self.resolve_introduction_waiters(&wait.shared.device_id, binding.ticket, false);
        }
    }

    /// Registry -> protection -> demand -> connection is the shared terminal
    /// order. Protection survives callback return and optional installation
    /// removal. No lock escapes this synchronous function.
    fn claim_introduction_retirement(
        &self,
        owner: &PeerOwnerToken,
        key: [u8; 32],
        ticket: super::hub_introduction::IntroductionTicket,
        generation: u64,
        terminal: Option<super::connection::IntroductionTerminalDisposition>,
    ) -> bool {
        let Some(pool) = self.demand_links.as_ref() else {
            return false;
        };
        let already_detached = pool.lock().links.get(&key).is_some_and(|link| {
            link.introduction == ticket
                && link.generation == generation
                && same_demand_owner(&link.owner, owner)
                && link.detached.is_some()
        });
        // The first detach owns the cause, including ordinary expiry. Its
        // retirement EOF cannot replace that cause or resolve a successor.
        {
            let mut protection = None;
            let detached = already_detached
                || self.peers.with_introduction_installation(owner, |peer| {
                    let sticky = self.sticky_peers.lock();
                    let config = self.config.read();
                    let topology = self.topology_impl.read();
                    let mut parenting = self.parenting.as_ref().map(|parenting| parenting.lock());
                    let relation_retained = if let Some(parenting) = parenting.as_mut() {
                        match super::parenting::ParentOwnerWitness::from_owner(owner) {
                            Ok(witness) => parenting.has_live_owner(&witness).unwrap_or(true),
                            Err(_) => true,
                        }
                    } else {
                        false
                    };
                    let may_remove = !sticky.contains(owner.device_id())
                        && !config.pinned_peers.iter().any(|id| id == owner.device_id())
                        && !topology.edge(self.identity.public_id(), owner.device_id(), &[])
                        && !relation_retained;
                    protection = Some((sticky, config, topology, parenting));
                    let mut pool = pool.lock();
                    let link = pool.links.get_mut(&key).filter(|link| {
                        link.introduction == ticket
                            && link.generation == generation
                            && same_demand_owner(&link.owner, owner)
                            && matches!(
                                link.settlement,
                                IntroductionSettlementPhase::Active
                                    | IntroductionSettlementPhase::Queued
                            )
                    })?;
                    let worker = owner.worker()?;
                    if link.detached.is_some() {
                        return Some(false);
                    }
                    let detached = match terminal {
                        Some(terminal) => {
                            peer.detach_terminal_introduction(worker, ticket, terminal)
                        }
                        None => peer.detach_failed_introduction(worker, ticket),
                    }?;
                    link.detached = Some(detached);
                    Some(may_remove)
                });
            drop(protection);
            detached
        }
    }

    /// Claim an explicit terminal synchronously, then ask the existing actor
    /// to join it. An unclaimed terminal retains the caller's exact fallback
    /// path; only custody actually transferred here may consume the request.
    pub(super) fn request_failed_introduction(
        &self,
        owner: &PeerOwnerToken,
        correlation: Option<&str>,
        reason: &crate::events::DropReason,
    ) -> bool {
        let (Some(pool), Some(controller), Ok(key)) = (
            self.demand_links.as_ref(),
            self.hub_introductions.as_ref(),
            DeviceId::canonical_key_bytes(owner.device_id()),
        ) else {
            return false;
        };
        let exact = pool
            .lock()
            .links
            .get(&key)
            .filter(|link| {
                same_demand_owner(&link.owner, owner)
                    && correlation.is_none_or(|attempt| link.introduction.matches_attempt(attempt))
            })
            .map(|link| (link.introduction, link.generation));
        let Some((ticket, generation)) = exact else {
            return false;
        };
        if !self.claim_introduction_retirement(
            owner,
            key,
            ticket,
            generation,
            Some(super::connection::IntroductionTerminalDisposition::from_drop_reason(reason)),
        ) {
            // Promotion winning the registry fence is handled by the caller's
            // existing exact channel-terminal path, never swallowed here.
            return false;
        }
        controller.lock().failed(ticket);
        self.queue_failed_introduction(key, ticket, generation);
        true
    }

    /// Called by the constructor guard only for a record already bound to its
    /// exact worker. Locals (including an unspawned receiver) have unwound;
    /// either its registered pump is retained, or no pump was constructed.
    pub(super) fn cancel_bound_introduction_construction(
        &self,
        owner: &PeerOwnerToken,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> bool {
        let (Some(pool), Ok(key)) = (
            self.demand_links.as_ref(),
            DeviceId::canonical_key_bytes(owner.device_id()),
        ) else {
            return false;
        };
        let mut pool = pool.lock();
        let Some(link) = pool
            .links
            .get_mut(&key)
            .filter(|link| link.introduction == ticket && same_demand_owner(&link.owner, owner))
        else {
            return false;
        };
        if !link.pump_registered {
            link.pump_registered = true;
            link.pump_joined = Some(true);
        }
        true
    }

    pub(super) async fn settle_failed_introduction(
        &self,
        key: [u8; 32],
        ticket: super::hub_introduction::IntroductionTicket,
        generation: u64,
    ) {
        let Some(_permit) = self.try_admit_shutdown_mutation() else {
            return;
        };
        self.settle_failed_introduction_inner(key, ticket, generation)
            .await;
    }

    /// Shutdown calls this only after mutation permits have drained and the
    /// actor's cancellation reservations have restored their record custody.
    async fn settle_failed_introduction_inner(
        &self,
        key: [u8; 32],
        ticket: super::hub_introduction::IntroductionTicket,
        generation: u64,
    ) {
        use super::hub_introduction::IntroductionLifetime;
        let (Some(pool), Some(controller)) =
            (self.demand_links.as_ref(), self.hub_introductions.as_ref())
        else {
            return;
        };
        let lifetime = controller
            .lock()
            .lifetime(ticket, std::time::Instant::now());
        let owner = {
            let mut pool = pool.lock();
            let Some(link) = pool
                .links
                .get_mut(&key)
                .filter(|link| link.introduction == ticket && link.generation == generation)
            else {
                return;
            };
            if link.settlement == IntroductionSettlementPhase::Queued {
                link.settlement = IntroductionSettlementPhase::Active;
            }
            if link.settlement != IntroductionSettlementPhase::Active
                || !link.pump_registered
                || (!matches!(
                    lifetime,
                    IntroductionLifetime::Elapsed { .. } | IntroductionLifetime::Terminal { .. }
                ) && link.detached.is_none()
                    && link
                        .owner
                        .worker()
                        .is_none_or(|worker| worker.live_connector_incarnation().is_some()))
            {
                return;
            }
            link.owner.clone()
        };
        let already_detached = pool.lock().links.get(&key).is_some_and(|link| {
            link.introduction == ticket && link.generation == generation && link.detached.is_some()
        });
        // Promotion is independently authenticated authority; Terminal alone
        // can never classify a successful introduction as a failed attempt.
        if !already_detached && self.peers.has_usable_authenticated_current(&owner) {
            self.resolve_bound_connect_waiters(
                owner.device_id(),
                ticket,
                ChannelDemandOutcome::Ready,
            );
            return;
        }
        let detached_here = already_detached
            || self.claim_introduction_retirement(&owner, key, ticket, generation, None);
        if !detached_here {
            // Busy, promoted, replaced, or unknown is NOT clean fallback and
            // does not authorize closing whichever worker now uses the key.
            self.resolve_introduction_waiters(owner.device_id(), ticket, false);
            // Ordinary replacement may already have permanently retired W0.
            // Joining that captured retired worker is safe; starting close on
            // a still-live/reused worker is not. This path never reports clean
            // fallback even if the old native and receiver joins succeed.
            if owner
                .worker()
                .is_none_or(|worker| worker.live_connector_incarnation().is_some())
            {
                return;
            }
        }
        controller.lock().failed(ticket);
        let (worker, native_closed, mut reservation) = {
            let mut pool_guard = pool.lock();
            let Some(link) = pool_guard.links.get_mut(&key).filter(|link| {
                link.introduction == ticket
                    && link.generation == generation
                    && link.settlement == IntroductionSettlementPhase::Active
            }) else {
                return;
            };
            let Some(worker) = link
                .detached
                .as_ref()
                .map(|detached| &detached.worker)
                .or_else(|| link.owner.worker())
            else {
                return;
            };
            let worker = Arc::clone(worker);
            link.settlement = IntroductionSettlementPhase::Joining;
            (
                worker,
                link.native_closed,
                IntroductionJoinReservation {
                    pool,
                    key,
                    ticket,
                    generation,
                    pump: link.pump.take(),
                },
            )
        };
        let native_ok = match native_closed {
            Some(ok) => ok,
            None => worker.retire_and_close().await.is_ok(),
        };
        pool.lock()
            .links
            .get_mut(&key)
            .expect("joining record retains its native custody")
            .native_closed = Some(native_ok);
        if let Some(pump) = reservation.pump.as_mut() {
            let joined = pump.await.is_ok();
            reservation.pump.take();
            pool.lock()
                .links
                .get_mut(&key)
                .expect("joining record retains its receiver custody")
                .pump_joined = Some(joined);
        }
        let joined_ok = pool
            .lock()
            .links
            .get(&key)
            .is_some_and(|link| link.pump_joined == Some(true));
        let terminal = {
            let mut pool = pool.lock();
            let link = pool
                .links
                .get_mut(&key)
                .expect("terminal join retains its record through token release");
            link.settlement = IntroductionSettlementPhase::Failed;
            let terminal = link
                .detached
                .as_ref()
                .and_then(|detached| detached.terminal);
            if let Some(detached) = link.detached.take() {
                detached.release_after_join(owner.connection());
            }
            terminal
        };
        // Failed is non-requeueable and forget_demand_link cannot remove it.
        // Drop may restore Joining, never Failed; no await follows this point.
        drop(reservation);
        // Failed native cleanup retains its provider's conservative failed
        // ledger. It never becomes permission to send through fallback.
        let clean = detached_here
            && native_ok
            && joined_ok
            && !self.shutdown_requested.load(Ordering::Acquire);
        // Registry -> exact demand record -> connection, never pool -> registry.
        // The record protects the full generation while the original joined
        // retained installation is reset. Independent/successor owners refuse
        // reset; a missing old installation still releases only its own row.
        self.peers.with_introduction_installation(&owner, |peer| {
            let mut pool = pool.lock();
            let link = pool.links.get(&key).filter(|link| {
                link.introduction == ticket
                    && link.generation == generation
                    && same_demand_owner(&link.owner, &owner)
                    && link.settlement == IntroductionSettlementPhase::Failed
                    && link.detached.is_none()
                    && link.native_closed == Some(native_ok)
                    && link.pump_joined.is_some()
            })?;
            let _ = link;
            if detached_here {
                peer.finish_retained_introduction(ticket, clean);
            }
            // Publish reusable and vacate its original demand slot under the
            // same fence, before a fresh Begin can acquire either one.
            pool.links.remove(&key);
            Some(false)
        });
        self.resolve_bound_connect_waiters(
            owner.device_id(),
            ticket,
            if !clean {
                ChannelDemandOutcome::Unsettled
            } else if terminal.is_some() {
                ChannelDemandOutcome::TerminalRefused
            } else {
                ChannelDemandOutcome::FailedSettlementJoined
            },
        );
        let mut pool = pool.lock();
        if pool.links.get(&key).is_some_and(|link| {
            link.introduction == ticket
                && link.generation == generation
                && same_demand_owner(&link.owner, &owner)
                && link.settlement == IntroductionSettlementPhase::Failed
        }) {
            pool.links.remove(&key);
        }
    }

    /// Join an introduced receiver after an existing owner has already
    /// completed native retirement. Cancellation restores the same handle;
    /// neither ordinary peer cleanup nor shutdown may drop it by map removal.
    async fn join_introduction_pump_after_native(&self, owner: &PeerOwnerToken) -> bool {
        let (Some(pool), Ok(key)) = (
            self.demand_links.as_ref(),
            DeviceId::canonical_key_bytes(owner.device_id()),
        ) else {
            return true;
        };
        let mut reservation = {
            let mut guard = pool.lock();
            let Some(link) = guard
                .links
                .get_mut(&key)
                .filter(|link| same_demand_owner(&link.owner, owner))
            else {
                return true;
            };
            if link.settlement == IntroductionSettlementPhase::Joining || !link.pump_registered {
                return false;
            }
            link.settlement = IntroductionSettlementPhase::Joining;
            IntroductionJoinReservation {
                pool,
                key,
                ticket: link.introduction,
                generation: link.generation,
                pump: link.pump.take(),
            }
        };
        if let Some(pump) = reservation.pump.as_mut() {
            let ok = pump.await.is_ok();
            reservation.pump.take();
            pool.lock()
                .links
                .get_mut(&key)
                .expect("receiver join retains its record")
                .pump_joined = Some(ok);
        }
        let ok = pool
            .lock()
            .links
            .get(&key)
            .is_some_and(|link| link.pump_joined == Some(true));
        drop(reservation);
        ok
    }

    /// Advance bounded monotonic record maintenance without collecting a peer
    /// vector or retaining a registry guard. Expiry cancels only its original
    /// ticket; caller-held connect waiters have their own bounded deadline.
    /// Native retirement is a separate exact-owner operation, never a lookup
    /// of whichever peer happens to reuse an expired target's name.
    pub(super) async fn maintain_hub_introductions(self: &Arc<Self>) {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return;
        }
        let (Some(controller), Some(pool)) =
            (self.hub_introductions.as_ref(), self.demand_links.as_ref())
        else {
            return;
        };
        let quantum = pool.lock().policy.max_maintenance_per_tick;
        let now = std::time::Instant::now();
        for _ in 0..quantum {
            let expired = {
                let mut controller = controller.lock();
                controller.poll_expired(now).and_then(|ticket| {
                    controller
                        .coordinates(ticket)
                        .map(|coordinates| (ticket, coordinates))
                })
            };
            if let Some((ticket, coordinates)) = expired {
                let local = DeviceId::canonical_key_bytes(self.identity.public_id()).ok();
                let key = if local == Some(coordinates.source) {
                    coordinates.destination
                } else {
                    coordinates.source
                };
                let generation = pool
                    .lock()
                    .links
                    .get(&key)
                    .filter(|link| link.introduction == ticket)
                    .map(|link| link.generation);
                if let Some(generation) = generation {
                    self.queue_failed_introduction(key, ticket, generation);
                }
            }
            let next = {
                let mut pool = pool.lock();
                let next = pool
                    .links
                    .successor_after(pool.cursor.as_ref())
                    .map(|(key, link)| {
                        (
                            *key,
                            link.owner.clone(),
                            link.introduction,
                            link.generation,
                            link.detached.is_some(),
                        )
                    });
                pool.cursor = next.as_ref().map(|(key, _, _, _, _)| *key);
                next
            };
            let Some((key, owner, ticket, generation, detached)) = next else {
                continue;
            };
            if detached {
                // Explicit terminal custody survives controller pruning and
                // cannot be reinterpreted as a successor's Ready state.
                self.queue_failed_introduction(key, ticket, generation);
            } else if self.peers.has_usable_authenticated_current(&owner) {
                // Promotion is already proved by the existing peer registry;
                // this only settles its old signaling transaction. It does
                // not grant authority or move the link's last-app-use clock.
                controller.lock().promoted(ticket);
                self.retire_idle_demand_link(&owner).await;
            } else if matches!(
                controller.lock().lifetime(ticket, now),
                super::hub_introduction::IntroductionLifetime::Elapsed { .. }
                    | super::hub_introduction::IntroductionLifetime::Terminal { .. }
            ) {
                self.queue_failed_introduction(key, ticket, generation);
            }
        }
    }

    async fn retire_idle_demand_link(self: &Arc<Self>, owner: &PeerOwnerToken) {
        let (Some(pool), Some(worker)) = (self.demand_links.as_ref(), owner.worker()) else {
            return;
        };
        let Ok(key) = DeviceId::canonical_key_bytes(owner.device_id()) else {
            return;
        };
        let reservation = {
            let mut state = pool.lock();
            let idle = std::time::Duration::from_millis(state.policy.idle_timeout_ms);
            let Some(link) = state.links.get_mut(&key) else {
                return;
            };
            if !same_demand_owner(&link.owner, owner)
                || !link.activity.reserve_idle(std::time::Instant::now(), idle)
            {
                return;
            }
            DemandIdleReservation {
                pool,
                key,
                generation: link.generation,
            }
        };
        // This async read is of the captured worker, not a peer-label lookup.
        // The exclusive activity reservation forbids new application work
        // while the native buffered amounts are sampled.
        let native_timeout = match self.config.read().scheduler_policy() {
            Ok(policy) => std::time::Duration::from_millis(policy.peer_send_timeout_ms),
            Err(_) => return,
        };
        if !matches!(
            tokio::time::timeout(native_timeout, worker.native_application_backlog_empty()).await,
            Ok(true)
        ) {
            return;
        }
        let removed = {
            // Keep the pin/topology guards until the registry has detached the
            // exact entry, not merely until its eligibility callback returns.
            let mut protection = None;
            let removed = self.peers.remove_demand_owner_if(owner, |peer| {
                if self.shutdown_requested.load(Ordering::Acquire) {
                    return false;
                }
                let sticky = self.sticky_peers.lock();
                let config = self.config.read();
                let topology = self.topology_impl.read();
                let mut parenting = self.parenting.as_ref().map(|parenting| parenting.lock());
                let relation_retained = if let Some(parenting) = parenting.as_mut() {
                    match super::parenting::ParentOwnerWitness::from_owner(owner) {
                        Ok(witness) => parenting.has_live_owner(&witness).unwrap_or(true),
                        Err(_) => true,
                    }
                } else {
                    false
                };
                let excluded = sticky.contains(owner.device_id())
                    || config.pinned_peers.iter().any(|id| id == owner.device_id())
                    || topology.edge(self.identity.public_id(), owner.device_id(), &[])
                    || relation_retained;
                protection = Some((sticky, config, topology, parenting));
                if excluded {
                    return false;
                }
                let state = pool.lock();
                let reserved = state.links.get(&key).is_some_and(|link| {
                    link.generation == reservation.generation
                        && same_demand_owner(&link.owner, owner)
                        && link.activity.idle_reserved()
                });
                if !reserved || !peer.demand_queues_quiescent(worker) {
                    return false;
                }
                // Advisory only and still under the exact admitted owner
                // fence. This hook never re-enters the peer registry.
                self.note_hub_authenticated_owner_change(owner);
                true
            });
            drop(protection);
            removed
        };
        let Some(removed) = removed else {
            return;
        };
        self.forget_demand_link(owner);
        drop(reservation);
        // The existing cleanup path owns and joins all original native close
        // work. Topology pruning records no reconnect intent or fresh demand.
        super::finish_drop_peer(
            self,
            owner.device_id(),
            crate::events::DropReason::TopologyPruned,
            Some(removed),
        )
        .await;
        self.join_introduction_pump_after_native(owner).await;
        self.forget_demand_link(owner);
    }

    pub(super) fn demand_link_protects_peer(
        &self,
        peer: &Arc<super::connection::PeerConnection>,
    ) -> bool {
        let Ok(key) = DeviceId::canonical_key_bytes(&peer.device_id) else {
            return false;
        };
        let owner = self
            .demand_links
            .as_ref()
            .and_then(|pool| pool.lock().links.get(&key).map(|entry| entry.owner.clone()));
        let Some(owner) = owner else {
            return false;
        };
        if !Arc::ptr_eq(owner.connection(), peer) {
            return false;
        }
        match (owner.worker(), peer.current_worker()) {
            (Some(expected), Some(current)) => Arc::ptr_eq(expected, &current),
            _ => false,
        }
    }

    pub(crate) fn local_application_resource_scope(&self) -> Result<LocalApplicationResourceScope> {
        Ok(self.local_resources.child()?)
    }

    /// owner and witness it will retire under and before it retires anything.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test it runs whatever a control staged with
    /// [`stage_exact_retirement_barrier`](Self::stage_exact_retirement_barrier),
    /// once, and never re-enters: the action is taken out from under the lock
    /// before it is called, so an action that itself reached a retirement site
    /// would find the barrier already empty rather than recurse.
    pub(crate) fn reach_exact_retirement_barrier(&self) {
        #[cfg(test)]
        {
            let staged = self.exact_retirement_barrier.lock().take();
            if let Some(staged) = staged {
                staged();
            }
        }
    }

    /// Stage the one action the next retirement site will run in its capture →
    /// retire window. See [`exact_retirement_barrier`](Self::exact_retirement_barrier).
    #[cfg(test)]
    pub(crate) fn stage_exact_retirement_barrier(&self, staged: impl FnOnce() + Send + 'static) {
        let displaced = self
            .exact_retirement_barrier
            .lock()
            .replace(Box::new(staged));
        assert!(
            displaced.is_none(),
            "a control staged a second retirement barrier over one that never fired"
        );
    }

    /// Whether the staged action is still waiting, i.e. no retirement site has
    /// been reached since it was staged.
    #[cfg(test)]
    pub(crate) fn exact_retirement_barrier_pending(&self) -> bool {
        self.exact_retirement_barrier.lock().is_some()
    }

    /// The point in an RPC handler run at which the reply is about to reach the
    /// wire, and the last point at which revocation can still take it back.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test, and only while a control has armed it, a run that
    /// reaches here parks until that control releases it — which is what lets a
    /// control revoke the authority *while the send is in flight* rather than
    /// before it starts or after it finished. Those are the two states an
    /// unassisted control can reach, and neither is the one the finding is
    /// about.
    ///
    /// No timer is involved on either side. The park ends when the control
    /// releases it or when the run is cancelled, and the cancellation is what
    /// the control observes.
    pub(crate) async fn reach_rpc_send_boundary(&self) {
        #[cfg(test)]
        self.rpc_send_boundary.reach().await;
    }

    /// The point in an RPC handler run at which the start has committed under
    /// the registry fence and the embedder's closure has not yet been called.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist. Under test, and only while a control has armed it, a run that
    /// reaches here parks until that control releases it — which is what lets a
    /// control revoke the authority in the one instant the contract is about:
    /// after the start is committed, before the closure is entered.
    ///
    /// What must be observed there is that the closure is entered anyway,
    /// exactly once, because the start was already ordered before that
    /// revocation. Everything the run does *afterwards* is still cancelled by
    /// the witness, which is the other half of the same assertion.
    pub(crate) async fn reach_rpc_handler_start_boundary(&self) {
        #[cfg(test)]
        self.rpc_handler_start_boundary.reach().await;
    }

    /// Reach the one-shot DepartObserved control gate. In an ordinary build
    /// this compiles to no behavior because the gate is not part of the state.
    pub(crate) async fn reach_depart_observed_gate(&self) {
        #[cfg(all(test, feature = "transport-lab"))]
        self.depart_observed_gate.reach().await;
    }

    /// The point inside a handler run's start, after its early validity read and
    /// before the fenced commit.
    ///
    /// In a production build this is an empty function over a field that does
    /// not exist, called with nothing staged, and it compiles away. Under test
    /// it runs whatever a control staged, exactly once — which is how a control
    /// revokes *in that instant* rather than before or after it.
    ///
    /// Taken rather than borrowed, so one staging fires once. A second run
    /// reaching the same point finds nothing and proceeds, which is what makes
    /// "the action was consumed" a usable non-vacuity check for the control that
    /// staged it.
    pub(crate) fn reach_rpc_handler_precommit_point(&self) {
        #[cfg(test)]
        if let Some(staged) = self.rpc_handler_precommit_action.lock().take() {
            staged();
        }
    }

    /// Stage the action the next handler run will perform at its pre-commit
    /// point.
    #[cfg(test)]
    pub(crate) fn stage_rpc_handler_precommit_action(
        &self,
        staged: impl FnOnce() + Send + 'static,
    ) {
        let displaced = self
            .rpc_handler_precommit_action
            .lock()
            .replace(Box::new(staged));
        assert!(
            displaced.is_none(),
            "a control staged a second handler pre-commit action over one that never fired"
        );
    }

    /// Whether the staged action is still waiting — i.e. no handler run has
    /// reached its pre-commit point since it was staged.
    ///
    /// The non-vacuity half. A control asserting "the closure was never entered"
    /// has to know the run got as far as the point that refused it; without
    /// this, the same assertion passes for a run that never started.
    #[cfg(test)]
    pub(crate) fn rpc_handler_precommit_action_pending(&self) -> bool {
        self.rpc_handler_precommit_action.lock().is_some()
    }
}

/// One-shot control gate for the exact DepartObserved receipt path.
///
/// The release future is subscribed before the arm is consumed. That ordering
/// makes a release concurrent with arrival observable rather than a lost
/// `Notify` wake. Consuming the arm before announcing entry makes only one
/// receipt park, even if several receipt tasks reach the hook together.
#[cfg(all(test, feature = "transport-lab"))]
#[derive(Default)]
pub(crate) struct DepartObservedGate {
    armed: std::sync::atomic::AtomicBool,
    entered_notify: tokio::sync::Notify,
    release_notify: tokio::sync::Notify,
}

#[cfg(all(test, feature = "transport-lab"))]
impl DepartObservedGate {
    pub(crate) async fn reach(&self) {
        use std::sync::atomic::Ordering;

        let release = self.release_notify.notified();
        tokio::pin!(release);
        release.as_mut().enable();
        if !self.armed.swap(false, Ordering::AcqRel) {
            return;
        }
        self.entered_notify.notify_waiters();
        release.await;
    }

    /// Arm exactly one future receipt. A second arm before arrival is a
    /// control mistake rather than a silently displaced observation.
    pub(crate) fn arm(&self) {
        assert!(
            !self.armed.swap(true, std::sync::atomic::Ordering::AcqRel),
            "a DepartObserved gate was armed twice"
        );
    }

    /// Subscribe before causing the receipt so entry cannot be missed.
    pub(crate) fn entered(&self) -> tokio::sync::futures::Notified<'_> {
        self.entered_notify.notified()
    }

    /// Alias matching the other engine controls' arrival terminology.
    pub(crate) fn arrival(&self) -> tokio::sync::futures::Notified<'_> {
        self.entered()
    }

    /// Release the one receipt currently parked at the gate.
    pub(crate) fn release(&self) {
        self.release_notify.notify_waiters();
    }
}

/// A control-armed park at the RPC send boundary, and the record of what
/// happened to every run that reached it.
///
/// The three counters are what make the observation causal rather than
/// circumstantial. `entered` says a run got as far as the boundary at all —
/// without it, "no frame was sent" is equally true of a run that never started.
/// `abandoned` is written by a guard living *inside* the parked future, so it is
/// incremented by the cancellation itself: a run whose task is dropped at the
/// boundary records that fact as it unwinds, and the task lease held beside it
/// is released in the same drop. `passed` is the post-boundary effect, and it
/// staying at zero is the assertion.
#[cfg(test)]
#[derive(Default)]
pub(crate) struct RpcSendBoundary {
    armed: std::sync::atomic::AtomicBool,
    entered: std::sync::atomic::AtomicUsize,
    passed: std::sync::atomic::AtomicUsize,
    abandoned: std::sync::atomic::AtomicUsize,
    finished: std::sync::atomic::AtomicUsize,
    reached: tokio::sync::Notify,
    release: tokio::sync::Notify,
}

/// Records, on drop, that the run holding it left the boundary without passing
/// it — which for a parked run means its task was cancelled here.
#[cfg(test)]
struct RpcSendBoundaryVisit<'a> {
    boundary: &'a RpcSendBoundary,
    passed: bool,
}

#[cfg(test)]
impl Drop for RpcSendBoundaryVisit<'_> {
    fn drop(&mut self) {
        if !self.passed {
            self.boundary
                .abandoned
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

#[cfg(test)]
impl RpcSendBoundary {
    async fn reach(&self) {
        use std::sync::atomic::Ordering;

        // Unarmed is the whole of production and the whole of every other
        // control: one load and a return, with nothing to park on.
        if !self.armed.load(Ordering::Acquire) {
            return;
        }
        // Subscribed *before* the arrival is announced. A control that released
        // the boundary the instant it saw the arrival would otherwise race a
        // notification against a subscription that had not happened yet, and
        // `Notify` does not keep one for a waiter that is not yet waiting.
        let release = self.release.notified();
        tokio::pin!(release);
        release.as_mut().enable();

        let mut visit = RpcSendBoundaryVisit {
            boundary: self,
            passed: false,
        };
        self.entered.fetch_add(1, Ordering::SeqCst);
        self.reached.notify_waiters();
        release.await;
        visit.passed = true;
        self.passed.fetch_add(1, Ordering::SeqCst);
    }

    /// Park every run that reaches the boundary from here on.
    pub(crate) fn arm(&self) {
        self.armed.store(true, std::sync::atomic::Ordering::Release);
    }

    /// Let every currently parked run continue past the boundary.
    ///
    /// The other exit, and the one a control needs when the point of the
    /// control is what happens *after* the boundary rather than instead of it:
    /// revoke while the run is parked, then release, and observe what the run
    /// does with an authority that ended while it was standing still.
    ///
    /// `notify_waiters` rather than `notify_one`, and it wakes only runs already
    /// parked — a run that arrives later parks as usual, because arming is not
    /// undone by releasing. That is what keeps one release from silently
    /// disarming the boundary for every run after it.
    pub(crate) fn release(&self) {
        self.release.notify_waiters();
    }

    /// A future that resolves when a run arrives at the boundary.
    ///
    /// Handed out as a future rather than polled for, so a control can subscribe
    /// before it delivers the frame and cannot miss the arrival.
    pub(crate) fn arrival(&self) -> tokio::sync::futures::Notified<'_> {
        self.reached.notified()
    }

    /// How many runs reached the boundary.
    pub(crate) fn entered(&self) -> usize {
        self.entered.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many runs got past it — the post-boundary effect.
    pub(crate) fn passed(&self) -> usize {
        self.passed.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many runs were dropped while parked on it.
    pub(crate) fn abandoned(&self) -> usize {
        self.abandoned.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// How many handler tasks have finished **and released their lease**.
    ///
    /// The one that answers "the task ended", as against
    /// [`Self::abandoned`], which answers "the run left the boundary". Those are
    /// not the same instant: the boundary guard is dropped inside the run
    /// future, and the task's own epilogue — the task lease among it — runs
    /// afterwards. A control that read `abandoned` and concluded the lease was
    /// released would be racing that epilogue.
    ///
    /// See [`RpcRunEpilogue`] for why this is ordered after the lease and not
    /// merely near it.
    pub(crate) fn finished(&self) -> usize {
        self.finished.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// Records one handler task's end, **after** that task's lease has been
/// released.
///
/// The ordering is the whole value of this type and it is structural, not
/// hopeful: locals drop in reverse declaration order, so the spawned run
/// declares this guard *before* it rebinds `_task_lease`. The lease is therefore
/// released first and this increment happens strictly afterwards — which makes
/// the count an observation of "the task is gone and has stopped costing its
/// owner", rather than of "the run stopped running", which is an earlier and
/// weaker fact.
///
/// Test-only. It exists because task completion is otherwise unobservable from
/// outside a spawned task: a cancelled run sends nothing, and its absence is
/// equally true of a run that never started.
#[cfg(test)]
pub(crate) struct RpcRunEpilogue(std::sync::Arc<NetworkState>);

#[cfg(test)]
impl RpcRunEpilogue {
    pub(crate) fn new(state: std::sync::Arc<NetworkState>) -> Self {
        Self(state)
    }
}

#[cfg(test)]
impl Drop for RpcRunEpilogue {
    fn drop(&mut self) {
        self.0
            .rpc_send_boundary
            .finished
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl NetworkState {
    /// Borrow the single semantic authority graph for this network instance.
    /// Callers must use this shared graph for admission and projection; a new
    /// default graph would silently bypass the trusted-root boundary.
    pub(crate) fn authoritative_fact_graph(&self) -> Arc<RwLock<crate::semantic::FactGraph>> {
        Arc::clone(&self.fact_graph)
    }

    /// Build a large valid history with ordinary semantic validation and
    /// publish it in bounded durable batches. This transport-lab fixture avoids
    /// timing hundreds of thousands of setup fsyncs so scale tests can measure
    /// the public hot path at a chosen ledger size.
    #[cfg(feature = "transport-lab")]
    pub(crate) async fn seed_semantic_scale_history_for_lab(
        self: &Arc<Self>,
        target: crate::semantic::DeviceId,
        count: usize,
    ) -> Result<()> {
        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let author = crate::semantic::DeviceId::from_canonical_str(state.identity.public_id())
                .map_err(|error| Error::Other(format!("noncanonical local DeviceId: {error}")))?;
            let _publication = state.durable_publication_gate.lock();
            let mut live = state.fact_graph.write();
            if !live.is_empty() {
                return Err(Error::Other(
                    "semantic scale graph changed while the seed was prepared".into(),
                ));
            }
            state.ensure_durable_owner_mutation_allowed()?;
            // The graph write fence excludes concurrent epoch creation. This
            // fixture does not silently preserve keys across its special
            // restore/seed path or relax ordinary publication invalidation.

            // The fixture uses the same bounded semantic delta transaction as
            // production, grouping at most one ready-batch worth of rows per
            // fsync. It never constructs a history-sized in-memory graph.
            // Stay well below the default 1,024 dirty-page transaction bound:
            // these compact fact rows average multiple rows per 4 KiB page.
            // A 1,024-row batch keeps transient memory small while avoiding
            // nearly a thousand fsync boundaries in the 250K control.
            const SEED_BATCH_ROWS: usize = 1_024;
            let mut next_index = 0usize;
            while next_index < count {
                let batch_end = next_index.saturating_add(SEED_BATCH_ROWS).min(count);
                let before_batch = live.clone();
                let previous_projection = live.projection();
                let expected_base_projection = previous_projection.commitment_root();
                let mut batch_delta = crate::semantic::SemanticDelta::default();
                live.begin_deferred_projection_commitment();

                let prepared = (|| -> Result<()> {
                    for index in next_index..batch_end {
                        let body = crate::semantic::FactBody::RoleGrant {
                            target: target.clone(),
                            role: if index % 2 == 0 {
                                crate::semantic::Role::Member
                            } else {
                                crate::semantic::Role::Owner
                            },
                        };
                        let witness = live.authoring_witness(&body, &author);
                        let mut authority_parents = Vec::new();
                        for subject in body.authority_use_subjects(&author) {
                            authority_parents
                                .extend(live.authority_lineage(&subject).heads().iter().copied());
                        }
                        let content = crate::semantic::FactContent::from_authoring_witness(
                            &live,
                            body,
                            &witness,
                            authority_parents,
                        );
                        let fact = crate::semantic::SignedFact::sign(
                            content,
                            state.identity.signing_key(),
                        )
                        .map_err(|error| {
                            Error::Other(format!("semantic seed fact rejected: {error}"))
                        })?;
                        let journal = live.admit_journaled(fact).map_err(|error| {
                            Error::Other(format!("semantic seed admission failed: {error}"))
                        })?;
                        if !matches!(journal.admission(), crate::semantic::Admission::Inserted) {
                            return Err(Error::Other(format!(
                                "semantic seed produced unexpected admission {:?}",
                                journal.admission()
                            )));
                        }
                        batch_delta.append_seed_delta(journal.delta().clone());
                        journal.commit();
                        live.retire_cold_history();
                    }
                    Ok(())
                })();
                if let Err(error) = prepared {
                    *live = before_batch;
                    return Err(error);
                }

                let batch_delta = live.finish_deferred_seed_delta(previous_projection, batch_delta);
                let projection_commitment = live.projection_commitment_root();
                if let Err(error) = state
                    .durable_semantic_owner
                    .commit_semantic_seed_delta_for_lab(
                        state.mesh_context_id,
                        &batch_delta,
                        expected_base_projection,
                        projection_commitment,
                        SEED_BATCH_ROWS,
                    )
                {
                    *live = before_batch;
                    return Err(Error::Network(format!("semantic seed commit: {error}")));
                }
                next_index = batch_end;
            }
            state
                .durable_semantic_owner
                .checkpoint_scale_seed_for_lab()
                .map_err(|error| Error::Network(format!("semantic seed checkpoint: {error}")))?;
            Ok(())
        })
        .await
        .map_err(|error| Error::Network(format!("semantic seed worker failed: {error}")))?
    }

    fn ensure_durable_owner_mutation_allowed(&self) -> Result<()> {
        if self.shutdown_requested.load(Ordering::Acquire) {
            return Err(Error::Network(
                "durable semantic owner is fenced by shutdown".to_string(),
            ));
        }
        self.durable_semantic_owner
            .ensure_live()
            .map_err(|error| Error::Network(format!("durable semantic owner unavailable: {error}")))
    }

    /// Arm one owner-scoped semantic commit fault for the next non-empty
    /// durable delta.  The store owns the one-shot state and exact commit
    /// boundary; this facade does not duplicate or bypass that custody.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn arm_semantic_commit_fault_for_lab(
        &self,
        fault: crate::semantic::store::SemanticCommitFaultForLab,
    ) -> Result<()> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .arm_commit_injection(fault)
            .map_err(|error| Error::Network(format!("semantic commit fault arm: {error}")))
    }

    /// Admit one policy-bounded request through the existing single-writer
    /// lane. The caller supplies the batch boundary (one fact, fact page, or
    /// proof delivery); the request becomes one causal journal and one SQLite
    /// transaction. There is no second scheduler or cross-request coalescing.
    pub(crate) async fn admit_fact_durably_with_delta_async(
        self: &Arc<Self>,
        fact: crate::semantic::SignedFact,
    ) -> Result<(
        crate::semantic::Admission,
        Vec<crate::semantic::SignedFact>,
        crate::semantic::SemanticDelta,
    )> {
        let batch = self
            .admit_facts_durably_with_delta_async(vec![fact])
            .await?;
        if batch.outcomes.len() != 1 {
            return Err(Error::Network(
                "single durable admission returned an invalid result count".into(),
            ));
        }
        let admission = batch
            .outcomes
            .into_iter()
            .next()
            .expect("single durable admission result count was checked")?;
        Ok((admission, batch.changed_admitted, batch.delta))
    }

    pub(crate) async fn admit_facts_durably_with_delta_async(
        self: &Arc<Self>,
        facts: Vec<crate::semantic::SignedFact>,
    ) -> Result<DurableAdmissionBatch> {
        #[cfg(feature = "transport-lab")]
        let _envelope_phase =
            AdmissionPhaseGuard::new(AdmissionPhase::AsyncAdmissionEnvelopeInclusive);
        if matches!(
            self.verified_bootstrap.policy(),
            crate::semantic::VerifiedProjectPolicy::Open
        ) {
            return Err(Error::Other(
                "Open networks do not admit durable semantic facts".into(),
            ));
        }
        if facts.is_empty() {
            return Err(Error::Other(
                "durable admission request cannot be empty".into(),
            ));
        }
        #[cfg(feature = "transport-lab")]
        let lane_wait_phase =
            AdmissionPhaseGuard::new(AdmissionPhase::AsyncLanePermitWaitExclusive);
        let permit = self
            .durable_admission_lane
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| Error::Network("durable admission lane closed".into()))?;
        #[cfg(feature = "transport-lab")]
        drop(lane_wait_phase);

        let state = Arc::clone(self);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            #[cfg(test)]
            let _activity = {
                let active = state
                    .durable_admission_active
                    .fetch_add(1, Ordering::SeqCst)
                    .saturating_add(1);
                state
                    .durable_admission_max
                    .fetch_max(active, Ordering::SeqCst);
                DurableAdmissionActivityGuard { state: &state }
            };
            state.process_durable_admission_batch(facts)
        })
        .await
        .map_err(|error| Error::Network(format!("durable admission worker failed: {error}")))?
    }

    fn process_durable_admission_batch(
        &self,
        facts: Vec<crate::semantic::SignedFact>,
    ) -> Result<DurableAdmissionBatch> {
        let batch_limit = usize::try_from(self.config.read().semantic_policy.max_ready_batch)
            .map_err(|_| Error::Network("durable admission batch limit exceeds usize".into()))?;
        if facts.len() > batch_limit {
            return Err(Error::Other(
                "durable admission request exceeds semantic batch envelope".into(),
            ));
        }

        #[cfg(feature = "transport-lab")]
        let publication_phase =
            AdmissionPhaseGuard::new(AdmissionPhase::PublicationGraphReplayColdLookup);
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        let mut live = self.fact_graph.write();

        // A retired hot row is still an exact durable duplicate. Classify it
        // before causal admission so replay remains a zero-write operation.
        let mut outcomes = facts.iter().map(|_| None).collect::<Vec<_>>();
        let mut candidates = Vec::with_capacity(facts.len());
        let mut candidate_positions = Vec::with_capacity(facts.len());
        for (position, fact) in facts.into_iter().enumerate() {
            if live.get(&fact.id).is_some() {
                candidate_positions.push(position);
                candidates.push(fact);
                continue;
            }
            match self
                .durable_semantic_owner
                .admitted_fact(fact.id)
                .map_err(|error| Error::Network(format!("durable fact lookup: {error}")))?
            {
                Some(existing) if existing == fact => {
                    outcomes[position] = Some(Ok(crate::semantic::Admission::AlreadyPresent));
                }
                Some(_) => {
                    outcomes[position] = Some(Err(Error::Other(format!(
                        "semantic fact rejected: duplicate fact id {}",
                        fact.id
                    ))));
                }
                None => {
                    candidate_positions.push(position);
                    candidates.push(fact);
                }
            }
        }

        if candidates.is_empty() {
            return Ok(DurableAdmissionBatch {
                outcomes: outcomes
                    .into_iter()
                    .map(|outcome| outcome.expect("every duplicate was classified"))
                    .collect(),
                changed_admitted: Vec::new(),
                delta: crate::semantic::SemanticDelta::default(),
            });
        }

        let candidate_ids = candidates
            .iter()
            .map(|fact| fact.id)
            .collect::<std::collections::BTreeSet<_>>();
        let dependency_roots = candidates
            .iter()
            .flat_map(crate::semantic::causal::dependencies)
            .filter(|id| live.get(id).is_none())
            .chain(live.selector_provenance_history_roots(&candidates))
            // In-batch facts are supplied by the journal's candidate overlay,
            // not by the already-admitted durable history snapshot.
            .filter(|id| !candidate_ids.contains(id))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let causal_history = if dependency_roots.is_empty() {
            Vec::new()
        } else {
            self.admitted_semantic_causal_history(dependency_roots)?
        };
        let expected_base_projection = live.projection_commitment_root();
        #[cfg(feature = "transport-lab")]
        drop(publication_phase);
        #[cfg(feature = "transport-lab")]
        let causal_phase = AdmissionPhaseGuard::new(AdmissionPhase::CausalJournalApply);
        let journal = live
            .admit_journaled_batch_with_history(candidates, causal_history)
            .map_err(|error| {
                Error::Other(format!("aggregate semantic admission rejected: {error}"))
            })?;
        #[cfg(feature = "transport-lab")]
        drop(causal_phase);

        for (position, result) in candidate_positions.into_iter().zip(journal.results()) {
            outcomes[position] = Some(match result.outcome() {
                crate::semantic::causal::AggregateAdmissionOutcome::Inserted { .. } => {
                    Ok(crate::semantic::Admission::Inserted)
                }
                crate::semantic::causal::AggregateAdmissionOutcome::AlreadyPresent { .. } => {
                    Ok(crate::semantic::Admission::AlreadyPresent)
                }
                crate::semantic::causal::AggregateAdmissionOutcome::Quarantined {
                    missing, ..
                } => Ok(crate::semantic::Admission::Quarantined {
                    missing: missing.clone(),
                }),
                crate::semantic::causal::AggregateAdmissionOutcome::Refused { error, .. } => {
                    Err(Error::Other(format!("semantic fact rejected: {error}")))
                }
            });
        }

        let aggregate_delta = journal.delta().clone();
        let changed = !aggregate_delta.rows().is_empty()
            || !aggregate_delta.removed().is_empty()
            || !aggregate_delta.provisional_added().is_empty()
            || !aggregate_delta.provisional_removed().is_empty();
        if !changed {
            journal.commit();
            return Ok(DurableAdmissionBatch {
                outcomes: outcomes
                    .into_iter()
                    .map(|outcome| outcome.expect("every aggregate input was classified"))
                    .collect(),
                changed_admitted: Vec::new(),
                delta: crate::semantic::SemanticDelta::default(),
            });
        }

        let projection_commitment = aggregate_delta
            .projection_delta()
            .map(|delta| delta.commitment())
            .unwrap_or(expected_base_projection);
        let provisional_additions: Vec<ProvisionalCustody> = aggregate_delta
            .provisional_added()
            .iter()
            .copied()
            .map(|fact_id| ProvisionalCustody::new(fact_id, "semantic-ingress"))
            .collect();

        if let Err(error) = self.durable_semantic_owner.commit_semantic_delta(
            self.mesh_context_id,
            &aggregate_delta,
            expected_base_projection,
            projection_commitment,
            &provisional_additions,
        ) {
            if matches!(
                &error,
                crate::semantic::store::DurableStoreError::OutcomeUnknown
            ) {
                journal.commit();
                // An unknown durable outcome can replace this graph inside
                // the same Arc. Invalidate before restore even if it later
                // reports not-applied; local graph generation is not an epoch.
                if self
                    .reconcile_unknown_admission(&mut live, &aggregate_delta, projection_commitment)
                    .is_none()
                {
                    self.shutdown_requested.store(true, Ordering::Release);
                }
            } else {
                journal.rollback();
            }
            return Err(Error::Network(format!(
                "durable aggregate semantic commit: {error}"
            )));
        }

        let changed_admitted = aggregate_delta
            .rows()
            .iter()
            .filter(|row| row.status() == crate::semantic::SemanticFactStatus::Admitted)
            .map(|row| row.fact().clone())
            .collect();
        let provisional_removed = aggregate_delta.provisional_removed().to_vec();
        journal.commit();
        live.retire_cold_history();

        {
            let mut provisional = self.durable_provisional.lock();
            for fact_id in provisional_removed {
                provisional.retain(|claim| claim.fact_id != fact_id);
            }
            for claim in &provisional_additions {
                if !provisional
                    .iter()
                    .any(|current| current.fact_id == claim.fact_id)
                {
                    provisional.push(claim.clone());
                }
            }
        }

        Ok(DurableAdmissionBatch {
            outcomes: outcomes
                .into_iter()
                .map(|outcome| outcome.expect("every aggregate input was classified"))
                .collect(),
            changed_admitted,
            delta: aggregate_delta,
        })
    }
    fn reconcile_unknown_admission(
        &self,
        live: &mut crate::semantic::FactGraph,
        delta: &crate::semantic::SemanticDelta,
        expected_projection: [u8; 32],
    ) -> Option<bool> {
        let Ok(restored) = self
            .durable_semantic_owner
            .restore(&self.verified_bootstrap)
        else {
            return None;
        };
        let graph = restored.graph();
        let verified = delta.rows().iter().all(|row| match row.status() {
            crate::semantic::SemanticFactStatus::Admitted => graph
                .get(&row.fact().id)
                .is_some_and(|fact| fact == row.fact()),
            crate::semantic::SemanticFactStatus::Quarantined => graph
                .quarantined()
                .any(|(id, fact)| *id == row.fact().id && fact == row.fact()),
        }) && delta.removed().iter().all(|id| {
            graph.get(id).is_none() && !graph.quarantined().any(|(current, _)| current == id)
        });
        let applied = graph.projection_commitment_root() == expected_projection && verified;
        let (restored_graph, restored_provisional) = restored.into_parts();
        *live = restored_graph;
        *self.durable_provisional.lock() = restored_provisional;
        Some(applied)
    }

    #[cfg(test)]
    pub(crate) fn durable_admission_max_for_test(&self) -> u64 {
        self.durable_admission_max.load(Ordering::SeqCst)
    }

    /// Checkpoint the production-owned semantic database without rebuilding
    /// or replacing the already-authoritative live graph.
    pub(crate) fn compact_durable_semantic_state(&self) -> Result<()> {
        // Admission and checkpointing share this publication fence so the
        // checkpoint observes a transaction boundary. SQLite remains the
        // durable authority; compaction does not deserialize history.
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .compact()
            .map_err(|error| Error::Network(format!("semantic snapshot compact: {error}")))
    }

    /// Purge this network instance's canonical semantic snapshot.  This is
    /// intentionally available only after shutdown has been requested: the
    /// lifecycle owner must first quiesce the engine and release its writer
    /// lease, after which the same owner performs the exact-slot purge.
    pub(crate) fn purge_durable_semantic_state(&self) -> Result<()> {
        if !self
            .shutdown_complete
            .load(std::sync::atomic::Ordering::Acquire)
        {
            return Err(Error::Network(
                "durable semantic purge requires completed network shutdown".into(),
            ));
        }
        // The startup claim was deliberately released at the shutdown
        // fence.  Purge gets a fresh exact B claim and transfers it directly
        // into the owner operation, which holds it together with WriterLease
        // for the complete slot purge.  There is no release/reacquire gap
        // while the semantic path is being removed.
        let storage_lease = self.local_resources.acquire(self.semantic_storage_claim)?;
        let _publication = self.durable_publication_gate.lock();
        let _semantic_fence = self.fact_graph.write();
        self.durable_semantic_owner
            .purge_funded(storage_lease)
            .map_err(|error| Error::Network(format!("semantic snapshot purge: {error}")))
    }

    /// Checkpoint this network's canonical semantic database through the same
    /// owner used by admission and restart. The live graph is untouched.
    pub fn compact_semantic_state(&self) -> Result<()> {
        self.compact_durable_semantic_state()
    }

    /// Number of admitted facts currently restored in the authoritative graph.
    /// This observation is useful to diagnostics and restart controls; it does
    /// not expose or alter semantic authority.
    pub fn semantic_fact_count(&self) -> usize {
        self.fact_graph.read().len()
    }

    /// Number of unresolved canonical facts retained by the durable snapshot.
    pub fn semantic_unresolved_count(&self) -> usize {
        self.fact_graph.read().quarantined().count()
    }

    /// Resolve one admitted fact from the canonical durable history. The live
    /// graph intentionally retains only the bounded continuation set.
    pub(crate) fn admitted_semantic_fact(
        &self,
        fact_id: crate::semantic::FactId,
    ) -> Result<Option<crate::semantic::SignedFact>> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .admitted_fact(fact_id)
            .map_err(|error| Error::Network(format!("durable fact read: {error}")))
    }

    pub(crate) fn admitted_semantic_fact_ids_after(
        &self,
        cursor: Option<crate::semantic::FactId>,
        limit: usize,
    ) -> Result<Vec<crate::semantic::FactId>> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .admitted_fact_ids_after(cursor, limit)
            .map_err(|error| Error::Network(format!("durable fact inventory: {error}")))
    }

    pub(crate) fn admitted_semantic_facts(
        &self,
        fact_ids: Vec<crate::semantic::FactId>,
    ) -> Result<Vec<Option<crate::semantic::SignedFact>>> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .admitted_facts(fact_ids)
            .map_err(|error| Error::Network(format!("durable fact page: {error}")))
    }

    pub(crate) fn semantic_state_digest(&self) -> Result<(u64, u64, [u8; 32])> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .state_identity_digest(self.mesh_context_id)
            .map_err(|error| Error::Network(format!("durable semantic identity: {error}")))
    }

    fn admitted_semantic_causal_history(
        &self,
        roots: Vec<crate::semantic::FactId>,
    ) -> Result<Vec<crate::semantic::SignedFact>> {
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .admitted_causal_history(roots)
            .map_err(|error| Error::Network(format!("durable causal history: {error}")))
    }

    /// Number of exact provisional custody claims paired with unresolved facts.
    pub fn semantic_provisional_custody_count(&self) -> usize {
        self.durable_provisional.lock().len()
    }

    /// Return all Pending records restored from the exact semantic store
    /// slot. The caller schedules these same delivery ids; it never invents a
    /// replacement id after restart.
    pub(crate) fn pending_durable_proof_outbox(&self) -> Result<Vec<ProofRecord>> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_proof_outbox
            .pending(self.mesh_context_id)
            .map_err(|error| Error::Network(format!("durable proof replay: {error}")))
    }

    /// Observe every exact durable proof record, including terminal tombstones,
    /// for this live mesh context. The owner/liveness fence prevents a stale
    /// state facade from observing a released slot as if it were still live.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn durable_proof_records(&self) -> Result<Vec<ProofRecord>> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.durable_semantic_owner
            .proof_records(self.mesh_context_id)
            .map_err(|error| Error::Network(format!("durable proof records: {error}")))
    }

    /// Build a record from facts already admitted by this network's
    /// authoritative graph and bind it to the exact current owner.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn new_durable_proof_outbox_record(
        &self,
        owner: &PeerOwnerToken,
        fact_ids: &[crate::semantic::FactId],
    ) -> Result<ProofRecord> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        let target = crate::semantic::DeviceId::from_canonical_str(owner.device_id())
            .map_err(|error| Error::Network(format!("durable proof target rejected: {error}")))?;
        for fact_id in fact_ids {
            if self.admitted_semantic_fact(*fact_id)?.is_none() {
                return Err(Error::Network(format!(
                    "durable proof fact {fact_id} is absent"
                )));
            }
        }
        ProofRecord::pending(
            self.mesh_context_id,
            target,
            fact_ids.to_vec(),
            owner.device_id(),
            owner.binding_key(),
        )
        .map_err(|error| Error::Network(format!("durable proof record: {error}")))
    }

    /// Rebuild the exact typed wire delivery for a persisted Pending record.
    /// Records retain canonical FactIds rather than duplicate signed bodies;
    /// replay therefore resolves every body from the authoritative graph and
    /// rechecks the stable context/target/content-derived delivery identity.
    pub(crate) fn materialize_durable_proof_delivery(
        &self,
        record: &ProofRecord,
    ) -> Result<crate::protocol::ProofDeliveryMessage> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.materialize_durable_proof_delivery_under_publication(record)
    }

    fn materialize_durable_proof_delivery_under_publication(
        &self,
        record: &ProofRecord,
    ) -> Result<crate::protocol::ProofDeliveryMessage> {
        if record.context_id != self.mesh_context_id || !record.is_pending() {
            return Err(Error::Network(
                "durable proof record is not Pending in this mesh context".to_string(),
            ));
        }
        let mut facts = Vec::with_capacity(record.fact_ids.len());
        for fact_id in &record.fact_ids {
            let fact = self
                .admitted_semantic_fact(*fact_id)?
                .ok_or_else(|| Error::Network(format!("durable proof fact {fact_id} is absent")))?;
            facts.push(fact);
        }

        let delivery = crate::protocol::ProofDeliveryMessage::new(
            record.context_id,
            record.target.clone(),
            facts,
        )
        .map_err(|error| Error::Network(format!("durable proof delivery: {error}")))?;
        if delivery.delivery_id != record.delivery_id {
            return Err(Error::Network(
                "durable proof delivery identity changed during replay".to_string(),
            ));
        }
        Ok(delivery)
    }

    /// Derive the exact current canonical eviction proof from the authoritative
    /// graph.  This is deliberately projection-based rather than a boolean
    /// `log_evicted` check: the returned record carries the complete causal
    /// closure and stable delivery identity that the publication fence admits.
    pub(crate) fn canonical_durable_eviction_proof_record(
        &self,
        owner: &PeerOwnerToken,
    ) -> Result<Option<ProofRecord>> {
        let target = crate::semantic::DeviceId::from_canonical_str(owner.device_id())
            .map_err(|error| Error::Network(format!("durable proof target rejected: {error}")))?;
        let graph = self.fact_graph.read();
        let projection = graph.projection();
        // A closed-network eviction is canonically represented by the
        // membership cell selecting `false`.  A plain `Evict` fact has not
        // necessarily produced a self-stand-down proof on the denying node;
        // requiring that optional projection would strand the offline target
        // before its first proof delivery.  Keep the canonical membership
        // decision as the gate and include stand-down evidence when present.
        if graph.evaluator().effective_membership(&target) != Some(false) {
            return Ok(None);
        }
        let mut pending = graph.cell_heads(&crate::semantic::ExclusiveCell::role(target.clone()));
        pending
            .extend(graph.cell_heads(&crate::semantic::ExclusiveCell::membership(target.clone())));
        if let Some(stand_down) = projection.stand_down(&target) {
            pending.push(stand_down.proof);
        }
        drop(graph);
        let mut ids = std::collections::BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !ids.insert(id) {
                continue;
            }
            let Some(fact) = self.admitted_semantic_fact(id)? else {
                return Err(Error::Network(
                    "durable eviction proof closure is incomplete".to_string(),
                ));
            };
            pending.extend(crate::semantic::causal::dependencies(&fact));
        }
        let fact_ids = ids.into_iter().collect::<Vec<_>>();
        ProofRecord::pending(
            self.mesh_context_id,
            target,
            fact_ids,
            owner.device_id(),
            owner.binding_key(),
        )
        .map(Some)
        .map_err(|error| Error::Network(format!("durable eviction proof record: {error}")))
    }

    /// Reconcile every still-pending proof obligation for one authenticated
    /// evicted owner before the proof send is admitted. The current canonical
    /// closure is derived once, then the exact owner fence encloses every
    /// same-target outbox mutation: obsolete records become non-replayable
    /// Superseded tombstones and exactly one current canonical record remains
    /// Pending. No transport or async work runs under this fence.
    pub(crate) fn reconcile_durable_eviction_proofs(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
    ) -> Result<Option<ProofRecord>> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        let canonical = self.canonical_durable_eviction_proof_record(owner)?;
        let context = self.mesh_context_id;
        let target = crate::semantic::DeviceId::from_canonical_str(owner.device_id())
            .map_err(|error| Error::Network(format!("durable proof target rejected: {error}")))?;
        let reconciled = self.peers.with_current_durable_outbox(owner, || {
            let pending = self
                .durable_proof_outbox
                .pending(context)
                .map_err(|error| {
                    Error::Network(format!("durable proof reconciliation: {error}"))
                })?;
            let mut current = None;
            for record in pending {
                if record.context_id != context || record.target != target {
                    continue;
                }
                let is_canonical = canonical.as_ref().is_some_and(|expected| {
                    expected.context_id == record.context_id
                        && expected.target == record.target
                        && expected.delivery_id == record.delivery_id
                        && expected.fact_ids == record.fact_ids
                });
                if is_canonical {
                    current = Some(record);
                } else {
                    self.durable_proof_outbox
                        .supersede(context, record.delivery_id, &target, None)
                        .map_err(|error| {
                            Error::Network(format!("durable proof supersession: {error}"))
                        })?;
                }
            }
            match canonical {
                Some(canonical) => match current {
                    Some(current) => Ok(Some(current)),
                    None => self
                        .durable_proof_outbox
                        .enqueue(canonical)
                        .map(Some)
                        .map_err(|error| {
                            Error::Network(format!("durable proof canonical enqueue: {error}"))
                        }),
                },
                None => Ok(None),
            }
        });
        match reconciled {
            Some(result) => result,
            None => Err(Error::Network(
                "durable proof owner is no longer current".to_string(),
            )),
        }
    }

    /// Admit the final synchronous portion of an eviction-proof send.
    ///
    /// This is the state-owned boundary between canonical eviction and an
    /// async transport write.  It serializes the final graph/outbox decision
    /// with durable fact publication, rechecks the exact current owner, and
    /// funds the pending semantic operation before returning.  The returned
    /// record must already be durably enqueued (the idempotent enqueue seam is
    /// [`Self::admit_durable_proof_outbox`]); this method performs the final
    /// rebind and send admission as one fenced synchronous step.  The returned
    /// witness carries the exact worker and provider claim; callers must drop
    /// it (or consume its parts) before awaiting transport, so no graph or
    /// publication lock crosses an await.
    pub(crate) fn prepare_durable_eviction_proof_send(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
        delivery: &crate::protocol::ProofDeliveryMessage,
    ) -> Result<DurableProofSendPreparation> {
        self.prepare_durable_eviction_proof_send_with_candidate(
            owner, None, "", record, delivery, 0,
        )
    }

    /// Prepare the same canonical proof for a fresh authenticated speculative
    /// candidate while policy still denies promotion.  The candidate is only
    /// a transport carrier: no session, application route, or status change
    /// is made.  `deny_bytes` is included in the single bounded work claim so
    /// the ordered ProofDelivery followed by Deny cannot overrun custody.
    pub(crate) fn prepare_durable_eviction_proof_send_for_speculative(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        record: &ProofRecord,
        delivery: &crate::protocol::ProofDeliveryMessage,
        deny_bytes: usize,
    ) -> Result<DurableProofSendPreparation> {
        self.prepare_durable_eviction_proof_send_with_candidate(
            owner,
            Some(candidate),
            correlation,
            record,
            delivery,
            deny_bytes,
        )
    }

    fn prepare_durable_eviction_proof_send_with_candidate(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        candidate: Option<&Arc<crate::transport::WebRtcConnectorWorker>>,
        correlation: &str,
        record: &ProofRecord,
        delivery: &crate::protocol::ProofDeliveryMessage,
        deny_bytes: usize,
    ) -> Result<DurableProofSendPreparation> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        if record.context_id != self.mesh_context_id
            || !record.is_pending()
            || record.target.to_string() != owner.device_id()
            || record.owner != owner.device_id()
        {
            return Err(Error::Network(
                "durable eviction proof owner or identity is stale".to_string(),
            ));
        }

        let canonical = self.canonical_durable_eviction_proof_record(owner)?;
        let same_identity = canonical.as_ref().is_some_and(|canonical| {
            canonical.context_id == record.context_id
                && canonical.target == record.target
                && canonical.delivery_id == record.delivery_id
                && canonical.fact_ids == record.fact_ids
        });
        let (record, delivery) = if same_identity {
            (record.clone(), delivery.clone())
        } else {
            let Some(canonical) = canonical else {
                let superseded =
                    self.supersede_durable_proof_outbox_under_publication(owner, record, None)?;
                if !superseded {
                    return Err(Error::Network(
                        "durable eviction proof stale record was not superseded".to_string(),
                    ));
                }
                return Ok(DurableProofSendPreparation::Superseded);
            };
            let Some(record) =
                self.supersede_and_enqueue_canonical_under_publication(owner, record, canonical)?
            else {
                return Err(Error::Network(
                    "durable eviction proof stale record was not superseded".to_string(),
                ));
            };
            let delivery = self.materialize_durable_proof_delivery_under_publication(&record)?;
            (record, delivery)
        };

        if delivery.context_id != self.mesh_context_id
            || delivery.target != record.target
            || delivery.delivery_id != record.delivery_id
        {
            return Err(Error::Network(
                "durable eviction proof delivery identity is stale".to_string(),
            ));
        }
        delivery
            .validate()
            .map_err(|error| Error::Network(format!("durable eviction proof: {error}")))?;
        let delivery_fact_ids: Vec<_> = delivery.facts.iter().map(|fact| fact.id).collect();
        if delivery_fact_ids != record.fact_ids {
            return Err(Error::Network(
                "durable eviction proof facts are not the recorded canonical set".to_string(),
            ));
        }
        {
            let graph = self.fact_graph.read();
            if delivery
                .facts
                .iter()
                .any(|fact| graph.get(&fact.id) != Some(fact))
            {
                return Err(Error::Network(
                    "durable eviction proof fact is absent or changed".to_string(),
                ));
            }
        }

        let bytes = Bytes::from(
            serde_json::to_vec(&crate::protocol::MeshMessage::ProofDelivery(
                delivery.clone(),
            ))
            .map_err(Error::Serde)?,
        );
        let operation = if let Some(candidate) = candidate {
            let total_bytes = bytes.len().checked_add(deny_bytes).ok_or_else(|| {
                Error::Network("durable proof send accounting overflow".to_string())
            })?;
            let admitted = self.peers.with_current_speculative_proof_bound(
                owner,
                candidate,
                correlation,
                record.delivery_id,
                &self.mesh_context_id.to_string(),
                total_bytes,
                |operation| match self.durable_proof_outbox.rebind(
                    record.context_id,
                    record.delivery_id,
                    &record.owner,
                    &record.binding,
                    owner.device_id(),
                    owner.binding_key(),
                ) {
                    Ok(_) => Ok(operation),
                    Err(error) => Err(Error::Network(format!("durable proof rebind: {error}"))),
                },
            );
            match admitted {
                Some(result) => result?,
                None => {
                    return Err(Error::Network(
                        "durable proof speculative candidate is no longer current".to_string(),
                    ));
                }
            }
        } else {
            let rebound = self.peers.with_current_durable_outbox(owner, || {
                self.durable_proof_outbox.rebind(
                    record.context_id,
                    record.delivery_id,
                    &record.owner,
                    &record.binding,
                    owner.device_id(),
                    owner.binding_key(),
                )
            });
            match rebound {
                Some(Ok(_)) => {}
                Some(Err(error)) => {
                    return Err(Error::Network(format!("durable proof rebind: {error}")));
                }
                None => {
                    return Err(Error::Network(
                        "durable proof owner is no longer current".to_string(),
                    ));
                }
            }
            self.peers
                .admit_pending_semantic_operation(owner, &self.mesh_context_id.to_string(), &bytes)
                .ok_or_else(|| Error::Network("durable proof send owner is not current".into()))?
        };
        let (captured_owner, worker, endpoint_auth, mesh_context, work) = operation.into_parts();
        Ok(DurableProofSendPreparation::Ready(Box::new(
            DurableProofSendAdmission {
                owner: captured_owner,
                worker,
                endpoint_auth,
                mesh_context,
                bytes,
                work,
            },
        )))
    }

    /// Persist one exact canonical proof record before send admission.
    /// Duplicate delivery ids return the existing record idempotently.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn admit_durable_proof_outbox(&self, record: ProofRecord) -> Result<ProofRecord> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        if record.context_id != self.mesh_context_id {
            return Err(Error::Network(
                "durable proof context does not match this network".to_string(),
            ));
        }
        self.durable_proof_outbox
            .enqueue(record)
            .map_err(|error| Error::Network(format!("durable proof enqueue: {error}")))
    }

    /// CAS-rebind a Pending record to the exact authenticated installation.
    /// The registry mutation fence encloses the durable mutation, so a
    /// replacement cannot race the binding decision and the id is retained.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn rebind_durable_proof_outbox(
        &self,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
    ) -> Result<bool> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        if record.context_id != self.mesh_context_id
            || record.target.to_string() != owner.device_id()
            || !record.is_pending()
        {
            return Ok(false);
        }
        let new_binding = owner.binding_key();
        match self.peers.with_current_durable_outbox(owner, || {
            self.durable_proof_outbox.rebind(
                record.context_id,
                record.delivery_id,
                &record.owner,
                &record.binding,
                owner.device_id(),
                new_binding,
            )
        }) {
            Some(result) => result
                .map(|_| true)
                .map_err(|error| Error::Network(format!("durable proof rebind: {error}"))),
            None => Ok(false),
        }
    }

    /// Retire an obsolete exact-target proof delivery without fabricating an
    /// acknowledgement. The durable record remains as a non-replayable
    /// Superseded terminal until normal compaction.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn supersede_durable_proof_outbox(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
        replacement_delivery_id: Option<ProofDeliveryId>,
    ) -> Result<bool> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.supersede_durable_proof_outbox_under_publication(
            owner,
            record,
            replacement_delivery_id,
        )
    }

    pub(crate) fn supersede_durable_proof_if_noncanonical(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
    ) -> Result<DurableProofSendPreparation> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        self.supersede_durable_proof_if_noncanonical_under_publication(owner, record)
    }

    fn supersede_durable_proof_if_noncanonical_under_publication(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
    ) -> Result<DurableProofSendPreparation> {
        let canonical = self.canonical_durable_eviction_proof_record(owner)?;
        let same_identity = canonical.as_ref().is_some_and(|canonical| {
            canonical.context_id == record.context_id
                && canonical.target == record.target
                && canonical.delivery_id == record.delivery_id
                && canonical.fact_ids == record.fact_ids
        });
        if same_identity {
            return Err(Error::Network(
                "durable eviction proof remains currently canonical".to_string(),
            ));
        }
        let superseded =
            self.supersede_durable_proof_outbox_under_publication(owner, record, None)?;
        if superseded {
            if let Some(canonical) = canonical {
                self.durable_proof_outbox
                    .enqueue(canonical)
                    .map_err(|error| {
                        Error::Network(format!("durable proof successor enqueue: {error}"))
                    })?;
            }
            Ok(DurableProofSendPreparation::Superseded)
        } else {
            Err(Error::Network(
                "durable eviction proof supersession was not admitted".to_string(),
            ))
        }
    }

    fn supersede_durable_proof_outbox_under_publication(
        &self,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
        replacement_delivery_id: Option<ProofDeliveryId>,
    ) -> Result<bool> {
        if record.context_id != self.mesh_context_id {
            return Ok(false);
        }
        if record.target.to_string() != owner.device_id() || record.owner != owner.device_id() {
            return Ok(false);
        }
        match self.peers.with_current_durable_outbox(owner, || {
            self.durable_proof_outbox.supersede(
                self.mesh_context_id,
                record.delivery_id,
                &record.target,
                replacement_delivery_id,
            )
        }) {
            Some(result) => {
                result.map_err(|error| Error::Network(format!("durable proof supersede: {error}")))
            }
            None => Ok(false),
        }
    }

    /// Supersede one stale obligation and enqueue its exact canonical successor
    /// while the same current-owner registry fence is held. Materialization is
    /// performed immediately after this synchronous fence, still under the
    /// publication gate and before any transport await.
    fn supersede_and_enqueue_canonical_under_publication(
        &self,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
        canonical: ProofRecord,
    ) -> Result<Option<ProofRecord>> {
        if record.context_id != self.mesh_context_id
            || record.target.to_string() != owner.device_id()
            || record.owner != owner.device_id()
        {
            return Ok(None);
        }
        match self.peers.with_current_durable_outbox(owner, || {
            let superseded = self
                .durable_proof_outbox
                .supersede(
                    self.mesh_context_id,
                    record.delivery_id,
                    &record.target,
                    None,
                )
                .map_err(|error| Error::Network(format!("durable proof supersede: {error}")))?;
            if !superseded {
                return Ok(None);
            }
            self.durable_proof_outbox
                .enqueue(canonical)
                .map(Some)
                .map_err(|error| {
                    Error::Network(format!("durable proof successor enqueue: {error}"))
                })
        }) {
            Some(result) => result,
            None => Ok(None),
        }
    }

    /// Settle only an exact ACK while the owner installation and binding
    /// remain current. The semantic outbox retains its Settled tombstone, so
    /// an identical ACK is idempotent while stale owners remain no-ops.
    pub(crate) fn settle_durable_proof_outbox_ack(
        &self,
        owner: &PeerOwnerToken,
        record: &ProofRecord,
        delivery_id: ProofDeliveryId,
    ) -> Result<bool> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        if record.context_id != self.mesh_context_id
            || record.delivery_id != delivery_id
            || record.target.to_string() != owner.device_id()
            || record.owner != owner.device_id()
            || record.binding != owner.binding_key()
            || !record.is_pending()
        {
            return Ok(false);
        }
        match self
            .peers
            .with_current_durable_outbox_unclaimed(owner, delivery_id, || {
                self.durable_proof_outbox
                    .settle(self.mesh_context_id, delivery_id)
            }) {
            Some(result) => {
                result.map_err(|error| Error::Network(format!("durable proof settle: {error}")))
            }
            None => Ok(false),
        }
    }

    /// Settle an ACK received by the exact speculative candidate that carried
    /// this delivery.  Unlike the native owner-only path, the publication gate
    /// and registry mutation fence jointly cover the binding check and the
    /// durable transition, so a replacement or promotion cannot redirect it.
    pub(crate) fn settle_durable_proof_outbox_ack_for_speculative(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        record: &ProofRecord,
        delivery_id: ProofDeliveryId,
    ) -> Result<bool> {
        let _publication = self.durable_publication_gate.lock();
        self.ensure_durable_owner_mutation_allowed()?;
        if record.context_id != self.mesh_context_id
            || record.delivery_id != delivery_id
            || record.target.to_string() != owner.device_id()
            || record.owner != owner.device_id()
            || record.binding != owner.binding_key()
            || !record.is_pending()
        {
            return Ok(false);
        }
        match self.peers.settle_current_speculative_proof(
            owner,
            candidate,
            correlation,
            delivery_id,
            || {
                self.durable_proof_outbox
                    .settle(self.mesh_context_id, delivery_id)
                    .map_err(|error| Error::Network(format!("durable proof settle: {error}")))
            },
        ) {
            Some(result) => result,
            None => Ok(false),
        }
    }

    /// Read observations for this live joined network instance.
    pub fn resource_report(&self) -> ResourceReport {
        self.resource_scope.report()
    }

    /// Take the outbound signaling receiver so the signaling task
    /// can drain it. Only one consumer is supported; subsequent
    /// calls return `None`.
    /// Publish the signaling runtime this network's carriers share.
    ///
    /// Called by the bridge at every attach. A later attach replaces the
    /// earlier value, which is correct: the replaced runtime is dropped with
    /// every key it held, and the keys of a runtime nothing is delivering
    /// through describe attempts nothing can arrive for.
    pub(crate) fn publish_signaling_runtime(
        &self,
        runtime: &Arc<super::signaling_ingress::SignalingRuntime>,
    ) {
        let Some(_shutdown_permit) = self.try_admit_shutdown_mutation() else {
            return;
        };
        let replaced = self.signaling_runtime.write().replace(Arc::clone(runtime));
        if let Some(replaced) = replaced.filter(|replaced| !Arc::ptr_eq(replaced, runtime)) {
            // A reattach supersedes the old runtime.  Release its exact guard
            // custody before the old driver tasks happen to observe the
            // replacement; otherwise self-eviction could only find the new
            // runtime and leave stale old-carrier records live.
            replaced.detach_guards();
        }
        self.peers.bind_signaling_runtime(Arc::downgrade(runtime));
        // A carrier attach/restore is an explicit recovery trigger.  This
        // path intentionally bypasses the ordinary presence floor; if the
        // carrier cannot admit the queued copy, the exact cohort remains
        // pending for the next attach.
        let _ = self.queue_recovery_announce();
    }

    /// The signaling runtime, if a carrier has attached one.
    pub(crate) fn signaling_runtime(
        &self,
    ) -> Option<Arc<super::signaling_ingress::SignalingRuntime>> {
        self.signaling_runtime.read().clone()
    }

    pub(crate) fn detach_signaling_guards(&self) {
        if let Some(runtime) = self.signaling_runtime() {
            runtime.detach_guards();
        }
    }

    pub(crate) fn set_attempt_settlement(&self, settlement: AttemptSettlement) {
        *self.attempt_settlement.lock() = Some(settlement);
    }

    pub(crate) fn clear_attempt_settlement(&self) {
        self.attempt_settlement.lock().take();
    }

    #[cfg(test)]
    pub(crate) fn begin_carrier_emission<I>(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        instances: I,
    ) -> bool
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        self.begin_carrier_emission_inner(emission, attempt, None, instances)
            .is_admitted()
    }

    pub(crate) fn begin_carrier_emission_for_owner_result<I>(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        owner: PeerOwnerToken,
        instances: I,
    ) -> CarrierEmissionAdmission
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        self.begin_carrier_emission_inner(emission, attempt, Some(owner), instances)
    }

    /// Begin an exact carrier emission only while the captured peer owner is
    /// current.  The registry mutation fence encloses both the owner check and
    /// the carrier find/create operation, so replacement orders atomically
    /// before or after this admission; no stale callback can create custody for
    /// a successor and no await or graph lock is taken under the fence.
    pub(crate) fn begin_carrier_emission_for_current_owner<I>(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        owner: PeerOwnerToken,
        instances: I,
    ) -> CarrierEmissionAdmission
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        self.peers
            .with_current_durable_outbox(&owner, || {
                self.begin_carrier_emission_for_owner_result(
                    emission,
                    attempt,
                    owner.clone(),
                    instances,
                )
            })
            .unwrap_or(CarrierEmissionAdmission::Stale)
    }

    fn begin_carrier_emission_inner<I>(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        owner: Option<PeerOwnerToken>,
        instances: I,
    ) -> CarrierEmissionAdmission
    where
        I: IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    {
        if attempt.is_empty() {
            return CarrierEmissionAdmission::Refused;
        }
        let mut expected = 0usize;
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if !duplicate {
                expected = match expected.checked_add(1) {
                    Some(expected) => expected,
                    None => return CarrierEmissionAdmission::Refused,
                };
            }
        }
        if expected == 0 {
            return CarrierEmissionAdmission::Refused;
        }
        let Some(bytes) = std::mem::size_of::<CarrierAttemptNode>()
            .checked_add(attempt.len())
            .and_then(|bytes| {
                bytes.checked_add(
                    expected.checked_mul(std::mem::size_of::<CarrierAttemptCarrier>())?,
                )
            })
        else {
            return CarrierEmissionAdmission::Refused;
        };
        let Ok(bytes) = u64::try_from(bytes) else {
            return CarrierEmissionAdmission::Refused;
        };
        let Some(residual_count) = expected.checked_add(1) else {
            return CarrierEmissionAdmission::Refused;
        };
        let Ok(residuals) = u64::try_from(residual_count) else {
            return CarrierEmissionAdmission::Refused;
        };
        let Ok(claim) = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, residuals),
        ]) else {
            return CarrierEmissionAdmission::Refused;
        };
        let mut attempts = self.carrier_state.attempts.lock();
        if let Some(existing) = attempts.find_emission_mut(emission, attempt) {
            if existing.terminal.is_some() {
                return CarrierEmissionAdmission::Stale;
            }
            if existing.owner.is_none() {
                existing.owner = owner;
            }
            return CarrierEmissionAdmission::Existing;
        }
        // Hold the aggregate lock across the exact existing check and its
        // provider claim.  A concurrent source must not both observe absence,
        // acquire pressure, and then race to create a second cohort for the
        // same opaque emission.
        let Ok(entry_lease) = self.local_resources.acquire(claim) else {
            return CarrierEmissionAdmission::Refused;
        };
        let mut carriers = None;
        for (index, instance) in instances.clone().into_iter().enumerate() {
            let duplicate = instances
                .clone()
                .into_iter()
                .take(index)
                .any(|prior| prior == instance);
            if !duplicate {
                carriers = Some(Box::new(CarrierAttemptCarrier {
                    instance,
                    resolved: false,
                    accepted: false,
                    next: carriers.take(),
                }));
            }
        }
        attempts.push_front(Box::new(CarrierAttemptNode {
            emission,
            attempt: attempt.to_string(),
            owner,
            _entry_lease: Some(entry_lease),
            carriers,
            expected,
            resolved: 0,
            accepted: false,
            claimed: false,
            fenced: false,
            terminal: None,
            next: None,
        }));
        CarrierEmissionAdmission::Admitted
    }

    /// Record an exact carrier's source admission without creating custody.
    /// Stale callbacks are distinguishable from a pending refusal, an accepted
    /// callback, and the one final refusal that may be routed to the owner.
    pub(crate) fn record_carrier_emission(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        instance: RecoveryCarrierInstance,
        accepted: bool,
    ) -> CarrierEmissionRecord {
        self.record_carrier_emission_with_owner(emission, attempt, instance, accepted)
            .record
    }

    pub(crate) fn record_carrier_emission_with_owner(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        instance: RecoveryCarrierInstance,
        accepted: bool,
    ) -> CarrierEmissionSettlement {
        let mut attempts = self.carrier_state.attempts.lock();
        let result = {
            let Some(state) = attempts.find_emission_mut(emission, attempt) else {
                return CarrierEmissionSettlement {
                    record: CarrierEmissionRecord::Stale,
                    owner: None,
                };
            };
            if state.terminal.is_some() {
                return CarrierEmissionSettlement {
                    record: CarrierEmissionRecord::Stale,
                    owner: None,
                };
            }
            if accepted {
                let Some(carrier) = state.carrier_mut(instance) else {
                    return CarrierEmissionSettlement {
                        record: CarrierEmissionRecord::Stale,
                        owner: None,
                    };
                };
                if carrier.resolved || carrier.accepted {
                    return CarrierEmissionSettlement {
                        record: CarrierEmissionRecord::Stale,
                        owner: None,
                    };
                }
                carrier.accepted = true;
                state.accepted = true;
                CarrierEmissionRecord::Accepted
            } else {
                let already_resolved = {
                    let Some(carrier) = state.carrier_mut(instance) else {
                        return CarrierEmissionSettlement {
                            record: CarrierEmissionRecord::Stale,
                            owner: None,
                        };
                    };
                    if carrier.resolved || carrier.accepted {
                        true
                    } else {
                        carrier.resolved = true;
                        false
                    }
                };
                if already_resolved {
                    return CarrierEmissionSettlement {
                        record: CarrierEmissionRecord::Stale,
                        owner: None,
                    };
                }
                state.resolved += 1;
                if !state.accepted && state.resolved == state.expected {
                    CarrierEmissionRecord::FinalRefusal
                } else {
                    CarrierEmissionRecord::Pending
                }
            }
        };
        let terminal = result == CarrierEmissionRecord::Accepted
            || result == CarrierEmissionRecord::FinalRefusal;
        let owner = if terminal {
            attempts
                .find_emission_mut(emission, attempt)
                .and_then(|node| {
                    if result != CarrierEmissionRecord::Stale {
                        // The callback has consumed this exact physical copy.
                        // Remove only its carrier node now; the aggregate
                        // counters remain authoritative for a later sibling
                        // and the compact node remains as the late-callback
                        // fence until lifecycle settlement.
                        node.remove_carrier(instance);
                        node.resize_tombstone_lease();
                    }
                    node.terminal = Some(result);
                    // Accepted is terminal for this exact carrier copy, but
                    // other physical copies may still arrive late. Keep the
                    // immutable lifecycle owner on the compact funded
                    // node/attempt tombstone until displacement or lifecycle
                    // settlement can fence the aggregate by exact installation
                    // and binding.
                    node.owner.clone()
                })
        } else {
            if let Some(node) = attempts.find_emission_mut(emission, attempt) {
                node.remove_carrier(instance);
                node.resize_tombstone_lease();
            }
            None
        };
        CarrierEmissionSettlement {
            record: result,
            owner,
        }
    }

    pub(crate) fn mark_carrier_emission_claimed(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) {
        let mut attempts = self.carrier_state.attempts.lock();
        if let Some(node) = attempts.find_emission_mut(emission, attempt) {
            node.claimed = true;
        }
    }

    pub(crate) fn carrier_emission_is_fenced(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) -> bool {
        self.carrier_state
            .attempts
            .lock()
            .find_emission_mut(emission, attempt)
            .is_some_and(|node| node.fenced)
    }

    pub(crate) fn carrier_emission_is_terminal(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) -> bool {
        self.carrier_state
            .attempts
            .lock()
            .find_emission_mut(emission, attempt)
            .is_some_and(|node| node.terminal.is_some())
    }

    pub(crate) fn acknowledge_terminal_carrier_emission(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
        instance: RecoveryCarrierInstance,
    ) {
        self.carrier_state
            .attempts
            .lock()
            .acknowledge_terminal(emission, attempt, instance);
    }

    /// Release one carrier copy after its exact carrier set has reached the
    /// terminal refusal.  This is deliberately narrower than
    /// [`Self::settle_attempt`]: a carrier refusal must not finish the whole
    /// Nostr attempt, because another emission may share the same attempt
    /// correlation and still own live provider custody.  Accepted terminals
    /// remain as stale tombstones for delayed carrier callbacks.
    pub(crate) fn settle_final_refusal_carrier(
        &self,
        emission: SignalingEmissionId,
        attempt: &str,
    ) -> bool {
        let mut attempts = self.carrier_state.attempts.lock();
        let is_final_refusal = attempts
            .find_emission_mut(emission, attempt)
            .is_some_and(|node| node.terminal == Some(CarrierEmissionRecord::FinalRefusal));
        if !is_final_refusal {
            return false;
        }
        attempts.remove_emission(emission, attempt).is_some()
    }

    pub(crate) fn clear_carrier_attempt(&self, attempt: &str) {
        self.carrier_state.attempts.lock().remove_unfenced(attempt);
    }

    /// Settle only signaling emissions owned by a displaced peer installation.
    /// A replacement may reuse the same device and attempt correlation, so
    /// broad attempt settlement here would incorrectly retire the successor's
    /// carrier custody.
    pub(crate) fn settle_displaced_owner_emissions(&self, owner: &PeerOwnerToken) -> usize {
        let emissions = self
            .carrier_state
            .attempts
            .lock()
            .emissions_for_owner(owner);
        if emissions.is_empty() {
            return 0;
        }

        let settled = {
            let mut attempts = self.carrier_state.attempts.lock();
            emissions
                .iter()
                .filter(|(emission, attempt)| attempts.settle_emission(*emission, attempt))
                .count()
        };

        // Runtime guards have their own lock and provider custody. Keep this
        // call outside the state carrier lock: exact runtime settlement is the
        // corresponding physical-copy operation and cannot touch a successor
        // that reused the same attempt correlation.
        if let Some(runtime) = self.signaling_runtime() {
            for (emission, attempt) in emissions {
                runtime.settle_emission(emission, &attempt);
            }
        }
        settled
    }

    pub(crate) fn settle_attempt(
        &self,
        attempt: &str,
        terminal: myownmesh_signaling::nostr::delivery::DeliveryTerminal,
    ) -> usize {
        let runtime = self.signaling_runtime();
        if let Some(runtime) = runtime.as_ref() {
            runtime.fence_attempt(attempt);
        }
        self.carrier_state.attempts.lock().fence_attempt(attempt);
        let settlement = self.attempt_settlement.lock().clone();
        let settled = settlement.map_or(0, |settlement| settlement(attempt, terminal));
        self.clear_carrier_attempt(attempt);
        if let Some(runtime) = runtime {
            runtime.clear_attempt(attempt);
        }
        settled
    }

    pub(crate) fn take_signaling_outbound_rx(
        self: &Arc<Self>,
    ) -> Option<ResourceMailboxReceiver<SignalingOutbound>> {
        self.signaling_outbound_rx.lock().take()
    }

    pub(super) fn take_connection_cmd_rx(&self) -> Option<ResourceMailboxReceiver<NetworkCmd>> {
        self.connection_cmd_rx.lock().take()
    }

    pub(super) fn take_speculative_promotion_rx(
        &self,
    ) -> Option<ResourceMailboxReceiver<SpeculativePromotionCmd>> {
        self.speculative_promotion_rx.lock().take()
    }

    /// Keep an otherwise undriven fixture's command receiver alive until the
    /// fixture state drops. A production driver always owns this receiver.
    #[cfg(test)]
    pub(crate) fn park_command_receiver_for_test(
        &self,
        receiver: ResourceMailboxReceiver<NetworkCmd>,
    ) {
        let replaced = self.parked_command_receiver.lock().replace(receiver);
        assert!(
            replaced.is_none(),
            "a fixture parks its command receiver once"
        );
    }

    pub fn request_shutdown(&self) {
        self.shutdown_requested.store(true, Ordering::SeqCst);
        self.shutdown_ready.notify_waiters();
        self.cmd_tx.close();
        self.connection_cmd_tx.close();
        self.speculative_promotion_tx.close();
        self.signaling_inbound_tx.close();
        self.signaling_tx.close();
    }

    /// Emit a bounded shutdown breadcrumb for transport-lab qualification.
    /// The identity disambiguates several fixtures that intentionally share a
    /// network id; counts expose custody at the exact await without retaining
    /// any history or changing shutdown behavior.
    fn log_shutdown_phase(&self, _phase: &'static str) {
        #[cfg(feature = "transport-lab")]
        {
            let phase = _phase;
            let shutdown_mutations = *self.shutdown_mutations.lock();
            let shutdown_tasks = self
                .shutdown_tasks
                .lock()
                .as_ref()
                .map_or(0, |tasks| tasks.handles.len());
            let (event_pumps, pending_registrations) = {
                let pumps = self.peer_event_pumps.lock();
                (pumps.handles.len(), pumps.pending_registrations)
            };
            self.log_diag_with(
                crate::events::DiagLevel::Info,
                "shutdown",
                format!(
                    "shutdown phase {phase} local_device={} peers={} mutations={shutdown_mutations} tasks={shutdown_tasks} pumps={event_pumps} pending_pumps={pending_registrations}",
                    self.identity.public_id(),
                    self.peers.len(),
                ),
                serde_json::json!({
                    "local_device": self.identity.public_id(),
                    "phase": phase,
                    "peer_count": self.peers.len(),
                    "shutdown_mutations": shutdown_mutations,
                    "shutdown_tasks": shutdown_tasks,
                    "event_pumps": event_pumps,
                    "pending_event_pump_registrations": pending_registrations,
                }),
            );
        }
    }

    async fn await_shutdown_mutations(&self) {
        loop {
            let notified = self.shutdown_mutations_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if *self.shutdown_mutations.lock() == 0 {
                return;
            }
            notified.await;
        }
    }

    /// Admit one peer mutation or reactive announcement at the shutdown
    /// linearization point.  Callers must retain the returned witness until
    /// the admitted operation has completed; it is an ownership marker, not a
    /// mutex, so no lock is held across async cleanup.
    pub(crate) fn try_admit_shutdown_mutation(&self) -> Option<ShutdownMutationPermit<'_>> {
        let mut admitted = self.shutdown_mutations.lock();
        if self.shutdown_requested.load(Ordering::SeqCst) {
            None
        } else {
            *admitted = admitted
                .checked_add(1)
                .expect("shutdown mutation admission count exhausted");
            Some(ShutdownMutationPermit { state: self })
        }
    }

    /// Register one spawned task while holding a shutdown mutation witness.
    /// The witness makes the registry's close transition wait until this
    /// synchronous registration has completed.
    pub(crate) fn register_shutdown_task(
        &self,
        permit: &ShutdownMutationPermit<'_>,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> bool {
        self.register_shutdown_task_with_policy(permit, false, start)
    }

    /// Register a delayed/probe task whose remaining work has no meaning once
    /// shutdown begins. Shutdown aborts these exact handles first and still
    /// awaits each terminal result; no task is detached or silently dropped.
    pub(crate) fn register_cancellable_shutdown_task(
        &self,
        permit: &ShutdownMutationPermit<'_>,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> bool {
        self.register_shutdown_task_with_policy(permit, true, start)
    }

    fn register_shutdown_task_with_policy(
        &self,
        _permit: &ShutdownMutationPermit<'_>,
        cancel_on_shutdown: bool,
        start: impl FnOnce() -> JoinHandle<()>,
    ) -> bool {
        let mut tasks = self.shutdown_tasks.lock();
        let Some(tasks) = tasks.as_mut() else {
            return false;
        };
        if tasks.closed {
            return false;
        }
        tasks.push(start(), cancel_on_shutdown);
        true
    }

    async fn await_shutdown_tasks(&self) {
        let handles = {
            let mut tasks = self.shutdown_tasks.lock();
            let Some(mut tasks) = tasks.take() else {
                return;
            };
            tasks.take_for_shutdown()
        };
        for task in &handles {
            if task.cancel_on_shutdown {
                task.handle.abort();
            }
        }
        for task in handles {
            if let Err(error) = task.handle.await {
                if task.cancel_on_shutdown && error.is_cancelled() {
                    continue;
                }
                tracing::warn!(%error, "engine shutdown task failed");
            }
        }
    }

    /// Run one local signaling attach while holding the registration fence.
    /// The closure must return the exact spawned forwarder; keeping spawn and
    /// registration in this critical section prevents shutdown from taking the
    /// registry between those two operations.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn with_local_signaling_forwarder<R>(
        &self,
        start: impl FnOnce() -> (R, JoinHandle<()>),
    ) -> Option<R> {
        let mut forwarders = self.local_signaling_forwarders.lock();
        if self.shutdown_requested.load(Ordering::Acquire) {
            return None;
        }
        let handles = forwarders.as_mut()?;
        let (result, handle) = start();
        handles.push(handle);
        Some(result)
    }

    #[cfg(feature = "transport-lab")]
    fn take_local_signaling_forwarders(&self) -> Vec<JoinHandle<()>> {
        self.local_signaling_forwarders
            .lock()
            .take()
            .unwrap_or_default()
    }

    pub(crate) async fn wait_for_shutdown(&self) {
        loop {
            let notified = self.shutdown_ready.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.shutdown_requested.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    /// Remember that we owe `device_id` a fresh offer after a recoverable
    /// drop, so the engine self-drives the reconnect instead of waiting for
    /// the peer's slow steady-state announce. The *first* drop opens the
    /// grace window; subsequent drops while the intent is still live (a failed
    /// rebuild that never opened a channel) deliberately do NOT extend it, so
    /// a peer that never comes back ages out at the grace instead of spinning
    /// forever. A genuine reconnect clears the intent
    /// ([`clear_reconnect_intent`](Self::clear_reconnect_intent) on
    /// `DataChannelOpen`), so the next loss opens a fresh window.
    pub fn record_reconnect_intent(&self, device_id: &str, sticky: bool) {
        let policy = match self.config.read().scheduler_policy() {
            Ok(policy) => policy,
            Err(_) => return,
        };
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        let Some(give_up_at) = now.checked_add(std::time::Duration::from_millis(
            policy.reconnecting_grace_ms,
        )) else {
            return;
        };
        let intent = map.entry(device_id.to_string()).or_insert(ReconnectIntent {
            give_up_at,
            next_retry_at: now,
            attempt: 0,
            sticky,
        });
        // A pin arriving while a plain intent is mid-backoff upgrades it —
        // stickiness must not be lost to entry order.
        intent.sticky = intent.sticky || sticky;
    }

    /// Forget a reconnect intent — the link is back (or the peer was
    /// explicitly removed). Cheap no-op if none was held.
    pub fn clear_reconnect_intent(&self, device_id: &str) {
        self.reconnect_intents.lock().remove(device_id);
    }

    /// Whether we're currently holding a reconnect intent for this peer.
    pub fn has_reconnect_intent(&self, device_id: &str) -> bool {
        self.reconnect_intents.lock().contains_key(device_id)
    }

    pub(super) fn same_recovery_owner(left: &PeerOwnerToken, right: &PeerOwnerToken) -> bool {
        if !Arc::ptr_eq(left.connection(), right.connection()) {
            return false;
        }
        match (left.worker(), right.worker()) {
            (None, None) => true,
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }

    fn recovery_cohort_cause_claim(
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        let bytes = u64::try_from(std::mem::size_of::<RecoveryCohortCause>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Publish one exact-owner cause into the network's single provider-owned
    /// cohort after its terminal mutation succeeds. Repeated publication of
    /// the same exact owner coalesces without replacing a captured generation.
    pub(crate) fn retain_recovery_demand(
        &self,
        owner: PeerOwnerToken,
        demand: crate::runtime::peer_session::RecoveryDemandHandle,
    ) {
        let owner_for_check = owner.clone();
        let mut cohort = self.recovery_cohort.lock();
        if cohort.pending.contains_owner(&owner)
            || cohort
                .in_flight
                .as_ref()
                .is_some_and(|generation| generation.causes.contains_owner(&owner))
        {
            return;
        }
        let Ok(claim) = Self::recovery_cohort_cause_claim() else {
            demand.cancel();
            return;
        };
        let Ok(collection_lease) = self.local_resources.acquire(claim) else {
            demand.cancel();
            return;
        };
        cohort.pending.push_front(Box::new(RecoveryCohortCause {
            owner,
            demand,
            collection_lease,
            next: None,
        }));

        // A successor may have committed between its one-time cancellation
        // check and this terminal publication. Release the cohort lock before
        // the registry query to preserve the registry-then-cohort lock order;
        // either ordering still gets a second cancellation check.
        drop(cohort);
        let successor = self
            .peers
            .owner(owner_for_check.device_id())
            .filter(|current| self.peers.has_usable_authenticated_current(current));
        if successor.is_some() {
            self.cancel_recovery_demands_for_device(owner_for_check.device_id());
        }
    }

    /// Capture the current pending causes as one publish generation. The
    /// captured set is immutable until its matching outcome settles.
    pub(crate) fn capture_recovery_cohort(&self) -> Option<RecoveryPublishId> {
        let mut cohort = self.recovery_cohort.lock();
        if cohort.in_flight.is_some() || cohort.pending.is_empty() {
            return None;
        }
        let next_generation = cohort.next_generation.checked_add(1)?;
        cohort.next_generation = next_generation;
        let id = RecoveryPublishId {
            generation: cohort.next_generation,
        };
        let causes = std::mem::take(&mut cohort.pending);
        cohort.in_flight = Some(RecoveryCohortGeneration { id, causes });
        Some(id)
    }

    /// Queue one recovery announce behind the engine mailbox.  Unlike an
    /// ordinary reactive presence announce this path has no presence floor:
    /// the exact captured cohort remains in-flight until a carrier source has
    /// admitted at least one copy.  The queue marker is installed before the
    /// mailbox send so a concurrently running carrier cannot consume an
    /// unmarked publication.
    pub(crate) fn queue_recovery_announce(&self) -> Option<RecoveryPublishId> {
        let id = self.capture_recovery_cohort()?;
        {
            let mut cohort = self.recovery_cohort.lock();
            if cohort
                .in_flight
                .as_ref()
                .is_none_or(|generation| generation.id != id)
                || cohort.queued_publication.is_some()
            {
                return None;
            }
            cohort.queued_publication = Some(id);
        }
        if self
            .signaling_tx
            .send(SignalingOutbound::RecoveryAnnounce { id })
            .is_err()
        {
            let mut cohort = self.recovery_cohort.lock();
            if cohort.queued_publication == Some(id) {
                cohort.queued_publication = None;
                drop(cohort);
                self.settle_recovery_cohort(
                    id,
                    crate::runtime::peer_session::RecoveryAttempt::Refused,
                );
            }
            return None;
        }
        Some(id)
    }

    pub(crate) fn recovery_publication_in_flight(&self) -> bool {
        let cohort = self.recovery_cohort.lock();
        cohort.in_flight.is_some()
    }

    /// Snapshot recovery custody for deterministic lifecycle controls. The
    /// tuple reports pending causes, captured generation, queued mailbox
    /// publication, and attached carrier publication respectively.
    #[cfg(test)]
    pub(crate) fn recovery_custody_snapshot_for_test(&self) -> (bool, bool, bool, bool) {
        let cohort = self.recovery_cohort.lock();
        (
            !cohort.pending.is_empty(),
            cohort.in_flight.is_some(),
            cohort.queued_publication.is_some(),
            cohort.publication.is_some(),
        )
    }

    #[cfg(test)]
    pub(crate) fn recovery_generation_for_test(&self) -> Option<RecoveryPublishId> {
        self.recovery_cohort
            .lock()
            .in_flight
            .as_ref()
            .map(|generation| generation.id)
    }

    /// Admit one exact queued generation to a finite carrier cohort and
    /// return the typed outcome for bridge/driver integration. Funding is
    /// acquired before publication insertion; any refusal clears only this
    /// queued generation and returns its causes to pending.
    pub(crate) fn begin_recovery_publication_result(
        &self,
        id: RecoveryPublishId,
        instances: impl IntoIterator<Item = RecoveryCarrierInstance> + Clone,
    ) -> RecoveryPublicationStart {
        let valid = {
            let cohort = self.recovery_cohort.lock();
            cohort.queued_publication == Some(id)
                && cohort
                    .in_flight
                    .as_ref()
                    .is_some_and(|generation| generation.id == id)
                && cohort.publication.is_none()
        };
        if !valid {
            return RecoveryPublicationStart::Stale;
        }
        let remaining = match self.funded_carrier_instances(instances) {
            Ok(remaining) => remaining,
            Err(error) => {
                self.rollback_recovery_publication(id);
                return RecoveryPublicationStart::Refused(error);
            }
        };
        let mut cohort = self.recovery_cohort.lock();
        if cohort.queued_publication != Some(id)
            || cohort
                .in_flight
                .as_ref()
                .is_none_or(|generation| generation.id != id)
            || cohort.publication.is_some()
        {
            return RecoveryPublicationStart::Stale;
        }
        cohort.queued_publication = None;
        cohort.publication = Some(RecoveryPublication { id, remaining });
        RecoveryPublicationStart::Started(id)
    }

    fn rollback_recovery_publication(&self, id: RecoveryPublishId) {
        let matching = {
            let mut cohort = self.recovery_cohort.lock();
            if cohort.queued_publication != Some(id)
                || cohort
                    .in_flight
                    .as_ref()
                    .is_none_or(|generation| generation.id != id)
            {
                false
            } else {
                cohort.queued_publication = None;
                true
            }
        };
        if matching {
            self.settle_recovery_cohort(id, crate::runtime::peer_session::RecoveryAttempt::Refused);
        }
    }

    pub(crate) fn begin_recovery_for_carrier(
        &self,
        expected_id: RecoveryPublishId,
        instance: RecoveryCarrierInstance,
    ) -> Option<RecoveryPublishId> {
        let queued_id = { self.recovery_cohort.lock().queued_publication };
        if let Some(id) = queued_id {
            if id != expected_id {
                return None;
            }
            return self
                .begin_recovery_publication_result(id, [instance])
                .into_started();
        }
        let cohort = self.recovery_cohort.lock();
        cohort.publication.as_ref().and_then(|publication| {
            (publication.id == expected_id && publication.remaining.contains(instance))
                .then_some(publication.id)
        })
    }

    pub(crate) fn refuse_empty_recovery_publication(&self, id: RecoveryPublishId) {
        let should_refuse =
            {
                let mut cohort = self.recovery_cohort.lock();
                cohort.publication.as_ref().is_some_and(|publication| {
                    publication.id == id && publication.remaining.is_empty()
                }) && cohort.publication.take().is_some()
            };
        if should_refuse {
            self.settle_recovery_cohort(id, crate::runtime::peer_session::RecoveryAttempt::Refused);
        }
    }

    /// Record one exact carrier admission.  One accepted carrier settles the
    /// captured generation immediately; refusals only settle as refused after
    /// every carrier in the finite attach cohort has refused.  Reports from a
    /// replaced publication or an instance outside the captured cohort are
    /// ignored.
    pub(crate) fn record_recovery_carrier(
        &self,
        id: RecoveryPublishId,
        instance: RecoveryCarrierInstance,
        accepted: bool,
    ) {
        let outcome = {
            let mut cohort = self.recovery_cohort.lock();
            let Some(publication) = cohort.publication.as_mut() else {
                return;
            };
            if publication.id != id || publication.remaining.remove(instance).is_none() {
                return;
            }
            let terminal = accepted || publication.remaining.is_empty();
            let outcome = if accepted {
                crate::runtime::peer_session::RecoveryAttempt::Accepted
            } else {
                crate::runtime::peer_session::RecoveryAttempt::Refused
            };
            if terminal {
                cohort.publication.take();
                Some(outcome)
            } else {
                None
            }
        };
        if let Some(outcome) = outcome {
            self.settle_recovery_cohort(id, outcome);
        }
    }

    pub(crate) fn next_recovery_carrier_instance(&self) -> Option<RecoveryCarrierInstance> {
        static NEXT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
        next_non_wrapping(&NEXT).map(RecoveryCarrierInstance)
    }

    /// Apply one provider outcome only to the exact captured generation.
    /// Refusal/rate-limit returns that generation's causes to the pending
    /// cohort; accepted consumes only those causes, leaving later causes for a
    /// subsequent generation.
    pub(crate) fn settle_recovery_cohort(
        &self,
        generation_id: RecoveryPublishId,
        attempt: crate::runtime::peer_session::RecoveryAttempt,
    ) {
        let detached_publication = {
            let mut cohort = self.recovery_cohort.lock();
            let Some(mut generation) = cohort.in_flight.take() else {
                return;
            };
            if generation.id != generation_id {
                cohort.in_flight = Some(generation);
                return;
            }
            if cohort.queued_publication == Some(generation_id) {
                cohort.queued_publication = None;
            }
            let detached_publication = cohort
                .publication
                .as_ref()
                .is_some_and(|publication| publication.id == generation_id)
                .then(|| cohort.publication.take().expect("matching publication"));
            let mut retry = RecoveryCohortCauseList::default();
            let mut causes = std::mem::take(&mut generation.causes);
            while let Some(cause) = causes.pop_front() {
                let outcome = cause.demand.settle_post_terminal(attempt);
                if matches!(
                    outcome,
                    crate::runtime::peer_session::RecoveryDemandSettlement::Unsatisfied
                        | crate::runtime::peer_session::RecoveryDemandSettlement::PreTerminal
                ) {
                    retry.push_front(cause);
                } else {
                    let cause = *cause;
                    cause.release();
                }
            }
            cohort.pending.append(&mut retry);
            detached_publication
        };
        drop(detached_publication);
    }

    /// A usable replacement for this device supersedes every older exact
    /// demand.  The removal is keyed by device only for cancellation; no
    /// device lookup is used to settle a terminal demand.
    pub(crate) fn cancel_recovery_demands_for_device(&self, device_id: &str) {
        let (mut cancelled, detached_publication) = {
            let mut cohort = self.recovery_cohort.lock();
            let mut cancelled = RecoveryCohortCauseList::default();
            let mut pending = std::mem::take(&mut cohort.pending);
            let mut retained = RecoveryCohortCauseList::default();
            while let Some(cause) = pending.pop_front() {
                if cause.owner.device_id() == device_id {
                    cancelled.push_front(cause);
                } else {
                    retained.push_front(cause);
                }
            }
            cohort.pending = retained;
            if let Some(generation) = cohort.in_flight.as_mut() {
                let mut causes = std::mem::take(&mut generation.causes);
                let mut retained = RecoveryCohortCauseList::default();
                while let Some(cause) = causes.pop_front() {
                    if cause.owner.device_id() == device_id {
                        cancelled.push_front(cause);
                    } else {
                        retained.push_front(cause);
                    }
                }
                generation.causes = retained;
            }
            let empty_generation = cohort
                .in_flight
                .as_ref()
                .is_some_and(|generation| generation.causes.is_empty());
            let generation_id = empty_generation.then(|| {
                cohort
                    .in_flight
                    .take()
                    .expect("empty recovery generation")
                    .id
            });
            if let Some(id) = generation_id {
                if cohort.queued_publication == Some(id) {
                    cohort.queued_publication = None;
                }
            }
            let detached_publication = generation_id.and_then(|id| {
                cohort
                    .publication
                    .as_ref()
                    .is_some_and(|publication| publication.id == id)
                    .then(|| cohort.publication.take().expect("matching publication"))
            });
            (cancelled, detached_publication)
        };
        drop(detached_publication);
        while let Some(cause) = cancelled.pop_front() {
            let cause = *cause;
            cause.cancel();
        }
    }

    /// Shutdown owns all remaining provider custody and releases it exactly
    /// once, outside the pending-map lock.
    pub(crate) fn cancel_all_recovery_demands(&self) {
        let (mut demands, detached_publication) = {
            let mut cohort = self.recovery_cohort.lock();
            let mut demands = std::mem::take(&mut cohort.pending);
            if let Some(mut generation) = cohort.in_flight.take() {
                let mut causes = std::mem::take(&mut generation.causes);
                demands.append(&mut causes);
            }
            cohort.queued_publication = None;
            (demands, cohort.publication.take())
        };
        drop(detached_publication);
        while let Some(cause) = demands.pop_front() {
            let cause = *cause;
            cause.cancel();
        }
    }

    /// Intent ids whose backoff is due now. Drops expired intents (past the
    /// reconnecting grace) and advances the backoff of the ones returned, so
    /// the state-watch tick re-offers each at most once per backoff step.
    #[cfg(test)]
    pub fn due_reconnect_intents(&self) -> Vec<String> {
        let policy = match self.config.read().scheduler_policy() {
            Ok(policy) => policy,
            Err(_) => return Vec::new(),
        };
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| i.sticky || now < i.give_up_at);
        let mut due = Vec::new();
        for (id, intent) in map.iter_mut() {
            if now < intent.next_retry_at {
                continue;
            }
            // A sticky intent past its active schedule parks: the entry
            // stays (so the peer's next announce dials immediately) but
            // the tick stops issuing blind offers into the void.
            if intent.sticky && intent.attempt >= policy.reconnect_retry_backoff_ms.len() + 2 {
                continue;
            }
            if advance_backoff(intent, now, &policy.reconnect_retry_backoff_ms) {
                due.push(id.clone());
            }
        }
        due
    }

    /// All live intent ids, with their backoff advanced. Used when a strong
    /// event — a relay reconnect after a network shift — makes it worth
    /// re-offering everything we owe at once, rather than waiting for each
    /// one's backoff to come due on the tick.
    pub fn flush_reconnect_intents(&self) -> Vec<String> {
        let policy = match self.config.read().scheduler_policy() {
            Ok(policy) => policy,
            Err(_) => return Vec::new(),
        };
        let now = std::time::Instant::now();
        let mut map = self.reconnect_intents.lock();
        map.retain(|_, i| i.sticky || now < i.give_up_at);
        map.iter_mut()
            .filter_map(|(id, intent)| {
                advance_backoff(intent, now, &policy.reconnect_retry_backoff_ms).then(|| id.clone())
            })
            .collect()
    }

    /// Register the signaling driver's force-reconnect signal. Called
    /// once when the Nostr driver is attached.
    pub fn set_relay_reconnect(&self, signal: Arc<watch::Sender<u64>>) {
        let Some(_shutdown_permit) = self.try_admit_shutdown_mutation() else {
            return;
        };
        *self.relay_reconnect.lock() = Some(signal);
    }

    /// Register the signaling driver's relay-connected signal (its
    /// `relay_connected` generation). Called once when the Nostr driver is
    /// attached, alongside [`set_relay_reconnect`].
    pub fn set_relay_connected_signal(&self, signal: Arc<watch::Sender<u64>>) {
        let Some(_shutdown_permit) = self.try_admit_shutdown_mutation() else {
            return;
        };
        *self.relay_connected.lock() = Some(signal);
    }

    /// A receiver for the relay-connected generation, or `None` when no
    /// driver is attached (tests, the in-process broker). Callers
    /// `borrow_and_update()` to set a baseline, then `changed()` to wait for
    /// the next fresh relay session.
    pub fn relay_connected_rx(&self) -> Option<watch::Receiver<u64>> {
        self.relay_connected.lock().as_ref().map(|s| s.subscribe())
    }

    /// Ask every relay to drop its socket and redial immediately,
    /// skipping the backoff. Returns `true` if a driver was attached
    /// to receive the request. Used on resume-from-sleep so the node
    /// stops being invisible the moment it wakes instead of waiting
    /// for a stale socket to time out. Cheap and idempotent — bumps a
    /// `watch` generation the relay tasks observe.
    pub fn request_relay_reconnect(&self) -> bool {
        let Some(_shutdown_permit) = self.try_admit_shutdown_mutation() else {
            return false;
        };
        match self.relay_reconnect.lock().as_ref() {
            Some(signal) => {
                signal.send_modify(|gen| *gen = gen.wrapping_add(1));
                let _ = self.queue_recovery_announce();
                true
            }
            None => {
                let _ = self.queue_recovery_announce();
                false
            }
        }
    }

    /// Like [`request_relay_reconnect`], but throttled to at most one
    /// redial per the configured rescue interval. This is the rescue
    /// path for the "ICE timed out with zero remote candidates"
    /// fingerprint — the peer's candidates never crossed the relay, which
    /// is almost always a relay socket that went stale after a network
    /// blip (held open for minutes because the kernel never saw a
    /// FIN/RST). Unlike the bare redial, this fires *even when other peers
    /// are still up*: a wedged relay socket starves candidate delivery for
    /// every peer, not just one, so gating on "no other live peer" (the
    /// old behavior) left the wedge in place whenever the room wasn't
    /// completely dark. The throttle is what makes that safe — a peer
    /// stuck re-timing-out every `ICE_CHECKING_TIMEOUT_MS` can still only
    /// bounce the relays once per window.
    ///
    /// Returns `true` when a redial was actually issued (driver attached
    /// *and* past the throttle), `false` when suppressed — callers log the
    /// distinction so the rescue's decisions are visible in diagnostics.
    pub fn request_relay_reconnect_throttled(&self) -> bool {
        let Some(_shutdown_permit) = self.try_admit_shutdown_mutation() else {
            return false;
        };
        let policy = match self.config.read().scheduler_policy() {
            Ok(policy) => policy,
            Err(_) => return false,
        };
        let now = std::time::Instant::now();
        {
            let mut guard = self.last_relay_rescue_at.lock();
            let due = guard.is_none_or(|prev| {
                now.duration_since(prev)
                    >= std::time::Duration::from_millis(policy.relay_rescue_min_interval_ms)
            });
            if !due {
                return false;
            }
            *guard = Some(now);
        }
        self.request_relay_reconnect()
    }

    /// Record whether the host currently has any primary outbound IP.
    /// Called by the network watcher each time the snapshot changes.
    /// Returns the previous value so the caller can detect the
    /// online→offline / offline→online edges.
    pub fn set_offline(&self, offline: bool) -> bool {
        self.offline
            .swap(offline, std::sync::atomic::Ordering::Relaxed)
    }

    /// True while the host has no primary outbound IP. The ICE
    /// machinery checks this to avoid re-gathering or dropping peers
    /// during a brief network outage (see `set_offline`).
    pub fn is_offline(&self) -> bool {
        self.offline.load(std::sync::atomic::Ordering::Relaxed)
    }

    /// Emit a top-level mesh event. Silently drops if no
    /// subscribers — the broadcast channel returns an error on
    /// every send-with-zero-listeners, and we'd rather log nothing
    /// than spam on every emit.
    pub fn emit(&self, event: MeshEvent) {
        let _ = self.events_tx.send(event);
    }

    /// Subscribe to this network's connection-state transition trace.
    /// The control socket's `trace_subscribe` op hands the receiver to
    /// a `ctl trace` client; subscribing is also what flips
    /// [`conn_trace_enabled`](Self::conn_trace_enabled) on, so the
    /// driver's sweep starts emitting.
    pub fn subscribe_conn_trace(&self) -> broadcast::Receiver<ConnTrace> {
        self.conn_trace_tx.subscribe()
    }

    /// Whether the connection tracer should do any work this sweep.
    /// True when forced on via `MYOWNMESH_CONN_TRACE`, or when at least
    /// one subscriber is attached. The driver loop checks this first so
    /// the production path with no observer pays only one atomic load.
    pub fn conn_trace_enabled(&self) -> bool {
        self.conn_trace_force_on || self.conn_trace_tx.receiver_count() > 0
    }

    /// Emit one connection-state trace record. Lossy like
    /// [`emit`](Self::emit) — drops if there is no subscriber.
    pub fn emit_conn_trace(&self, trace: ConnTrace) {
        let _ = self.conn_trace_tx.send(trace);
    }

    /// Emit a structured diagnostic — both to the tracing layer
    /// (visible in daemon stderr) and to the broadcast channel as
    /// a [`MeshEvent::Diag`] (consumed by the GUI's Activity tab).
    /// Prefer this over a bare `tracing::info!`/`warn!` for events
    /// the user should see in the UI; the helper writes to both
    /// surfaces so operators reading logs and users watching the
    /// GUI stay in sync.
    pub fn log_diag(&self, level: DiagLevel, category: &str, message: impl Into<String>) {
        self.log_diag_with(level, category, message, serde_json::Value::Null);
    }

    /// Variant of [`log_diag`] that carries a structured `detail`
    /// payload alongside the message. Use for events where the GUI
    /// might want to drill into fields (peer id, error code, etc.)
    /// rather than just render the human-readable line.
    pub fn log_diag_with(
        &self,
        level: DiagLevel,
        category: &str,
        message: impl Into<String>,
        detail: serde_json::Value,
    ) {
        let message = message.into();
        // Console line reads "category: message" — clean, demo-like, no
        // field-suffix clutter. The structured network_id + category still
        // ride the MeshEvent::Diag below for the GUI; only the console
        // rendering is simplified.
        match level {
            DiagLevel::Debug => tracing::debug!("{category}: {message}"),
            DiagLevel::Info => tracing::info!("{category}: {message}"),
            DiagLevel::Warn => tracing::warn!("{category}: {message}"),
            DiagLevel::Error => tracing::error!("{category}: {message}"),
        }
        self.emit(MeshEvent::Diag(DiagEntry {
            ts: now_unix_ms(),
            network_id: self.network_id.clone(),
            level,
            category: category.to_string(),
            message,
            detail,
        }));
    }

    /// Update the per-network phase and emit on change.
    pub fn set_phase(&self, next: MeshPhase) {
        let mut current = self.current_phase.write();
        let prev = *current;
        if prev == next {
            return;
        }
        *current = next;
        drop(current);
        self.emit(MeshEvent::Phase(PhaseEvent::Changed {
            network_id: self.network_id.clone(),
            prev,
            next,
        }));
        self.log_diag(DiagLevel::Info, "phase", format!("{prev:?} → {next:?}"));
    }

    /// Open one realtime flow on `peer`'s current session, native half included.
    ///
    /// Takes an already-validated connector spec: the provider's own
    /// configuration is parsed and refused at the public boundary, before any
    /// session is resolved, so an unusable request never reaches the fence and
    /// the engine never inspects what a provider's vocabulary means.
    ///
    /// **This is the only realtime operation that resolves a Device selector,
    /// and it resolves it exactly once.** `peer` names an installation to look
    /// up; everything that authorizes the open is produced inside the fence at
    /// the moment of use. From the first line onwards the operation carries the
    /// [`PeerOwnerToken`] that resolution produced, and phase 3 and the
    /// abandonment path re-enter the fence with *that* rather than with the
    /// name — so a replacement landing mid-open fails a pointer check instead of
    /// being resolved to and quietly committed onto.
    ///
    /// A resolution failure is reported as `SessionNotCurrent` rather than a
    /// distinct "no such peer" — an unknown selector, a replaced installation
    /// and an unpromoted peer are the same fact from the caller's side, and
    /// separating them would leak peer-existence to a caller that has proved
    /// nothing.
    ///
    /// Three phases, because the fence is a synchronous lock that connector
    /// replacement also takes and the native operations await. Nothing is held
    /// across an await, and nothing is trusted across one either — the handle
    /// carried through phase 2 grants nothing, and phase 3 re-proves the same
    /// facts rather than assuming they survived.
    ///
    /// 1. **In the fence:** claim the label, capture the exact flow record it
    ///    produced, and for an inbound flow mint the track identity and bind it,
    ///    so the claim and the binding are one atomic step. That ordering is
    ///    what removes the start window: any track that can arrive under that
    ///    identity has a binding before the transceiver carrying it exists.
    ///    Capture the worker and the flow-set identity, then release.
    /// 2. **No locks:** create the native transceiver or track.
    /// 3. **Back in the fence, against the same owner:** prove it is the same
    ///    flow set, then attach the outbound track. An inbound flow has nothing
    ///    left to commit.
    ///
    /// The flow-set check in phase 3 is not redundant with having carried the
    /// owner. The owner proves the installation is the one this open started
    /// against; the flow set proves the *session* is, which is the finer
    /// question and the one the committed track actually belongs to. Same window
    /// as the one the arrivals stream check closes, one call earlier.
    ///
    /// Answers a [`crate::realtime::RealtimeFlowHandle`], and only from facts
    /// captured inside the fence: the owner, the flow-set identity and the flow
    /// record. The name travels in it as a wire coordinate. Nothing in the
    /// handle can be re-derived afterwards from a selector, which is the whole
    /// difference from the coordinate-based API it replaces.
    ///
    /// Every refusal releases both halves: the flow and its label through the
    /// fence, the native object through the connector. Nothing is retried and
    /// nothing is timed.
    /// Takes `&Arc<Self>` rather than `&self` for one reason: the handle this
    /// mints closes its flow when it is dropped, and the only honest way to
    /// reach this engine from a `Drop` that owns nothing is a weak reference to
    /// it. Downgrading requires the `Arc`, and every caller already has one.
    pub(crate) async fn open_realtime_negotiated(
        self: &Arc<Self>,
        peer: &str,
        spec: RealtimeFlowSpec,
    ) -> std::result::Result<crate::realtime::RealtimeFlowHandle, crate::realtime::RealtimeRefusal>
    {
        let encoding = spec.encoding.clone();
        // The one resolution. Everything after this names the installation it
        // produced, never the bytes it was produced from.
        let Some(owner) = self.peers.owner(peer) else {
            return Err(crate::realtime::RealtimeRefusal::SessionNotCurrent);
        };

        // Phase 1.
        let (name, flow, worker, flow_set, identity, validity) = self
            .with_owned_realtime_flows_and_worker(&owner, |session, flows, live, worker| {
                let inbound = spec.direction == RealtimeDirection::Inbound;
                let name = flows.open(session, Some(live), spec)?;
                // Taken from the record `open` just filed, not from the name it
                // spells, and taken here so it exists before anything below can
                // release the fence. A handle built from a later lookup would
                // name whatever held the name at that later moment, which is the
                // defect this whole path exists to remove.
                let Some(flow) = flows.flow_identity(&name) else {
                    let _ = flows.close(session, Some(live), &name);
                    return Err(RealtimeFlowError::FlowRefused);
                };
                let identity = if inbound {
                    // Minted by the connector, not here. The identity is a
                    // connector-scoped allocation and the engine has no scope to
                    // fund one; asking for it is all this side does.
                    let Ok(identity) = worker.mint_inbound_realtime_identity() else {
                        let _ = flows.close(session, Some(live), &name);
                        return Err(RealtimeFlowError::FlowRefused);
                    };
                    // Minted here and moved into the flow, so from the bind
                    // onwards the flow — not this function, and not a later
                    // caller who remembers — is what owes the transceiver its
                    // retirement.
                    //
                    // It can refuse, and refusing here is the point: the
                    // retirement's cleanup is funded at this moment, so a
                    // connector that could not afford to retire the transceiver
                    // never negotiates one. The flow and its name go back the
                    // same way a refused bind returns them.
                    let retirement = match worker.inbound_realtime_retirement(Arc::clone(&identity))
                    {
                        Ok(retirement) => retirement,
                        Err(_) => {
                            let _ = flows.close(session, Some(live), &name);
                            return Err(RealtimeFlowError::FlowRefused);
                        }
                    };
                    // A bind that fails leaves a flow holding a name against a
                    // negotiation that will never happen, so the name goes back
                    // now rather than at the next open that collides with it.
                    if let Err(error) = flows.bind_inbound(
                        session,
                        Some(live),
                        &name,
                        Arc::clone(&identity),
                        retirement,
                    ) {
                        let _ = flows.close(session, Some(live), &name);
                        return Err(error);
                    }
                    Some(identity)
                } else {
                    None
                };
                Ok((
                    name,
                    flow,
                    Arc::clone(worker),
                    flows.identity(),
                    identity,
                    session.validity_witness(),
                ))
            })?;
        let owner = owner.for_worker(Arc::clone(&worker));

        // Phase 2. Branching on the minted identity rather than re-deriving the
        // direction: the two must not be able to disagree.
        let native = tokio::select! {
            biased;
            () = validity.revoked() => Err(crate::error::Error::Transport(
                "the session authorizing this realtime open was revoked".into(),
            )),
            native = async {
                match identity.as_ref() {
                    Some(identity) => worker
                        .open_inbound_realtime_transceiver(identity, &encoding)
                        .await
                        .map(|()| None),
                    None => worker
                        .open_outbound_realtime_track(&encoding)
                        .await
                        .map(Some),
                }
            } => native,
        };
        let Ok(mut track) = native else {
            // The connector cleaned up its own failed construction; what is
            // left is the flow, its name, and — for an inbound open — a
            // binding to an identity nothing will ever present.
            self.abandon_realtime_open(&owner, &flow_set, &name).await;
            return Err(crate::realtime::RealtimeRefusal::FlowRefused);
        };

        // Phase 3. The track is taken from `track` only on the path that
        // attaches it, so whatever remains afterwards is a native object this
        // side still owns and must release.
        let committed = self.with_owned_realtime_flows(&owner, |session, flows, live| {
            if !flows.is_same(&flow_set) {
                return Err(RealtimeFlowError::SessionNotCurrent);
            }
            match track.take() {
                Some(outbound) => flows
                    .attach_outbound(session, Some(live), &name, outbound)
                    .map_err(|(error, outbound)| {
                        track = Some(outbound);
                        error
                    }),
                // Inbound: bound in phase 1, so there is nothing to commit and
                // nothing that could half-commit.
                None => Ok(()),
            }
        });

        if let Some(outbound) = track {
            worker.close_outbound_realtime_track(outbound).await;
        }
        match committed {
            // Built only now, and only from values phase 1 captured under the
            // fence: the owner that resolution produced, the flow set that
            // answered, and the record `open` filed. None of the three is
            // re-derivable from the selector this call was given.
            Ok(()) => Ok(crate::realtime::RealtimeFlowHandle::new(
                owner,
                flow_set,
                flow,
                name,
                Arc::downgrade(self),
            )),
            Err(error) => {
                // Ordered so the caller does not return before the transceiver
                // is retired. If the flow set is still ours, `abandon` closed
                // the flow and the close handed the retirement back, so it has
                // already been retired and awaited. If it is not ours, the flow
                // died with the set that owned it — and its retirement went
                // with it, which submits, but fire-and-forget. This awaits the
                // same retirement through the identity minted in phase 1, and
                // the claim makes the two the same single stop.
                if !self.abandon_realtime_open(&owner, &flow_set, &name).await {
                    if let Some(identity) = identity.as_ref() {
                        worker.close_inbound_realtime_transceiver(identity).await;
                    }
                }
                Err(error.into())
            }
        }
    }

    /// Capture the existing exact promoted logical session before preparing
    /// a control. The subsequent flow fence also checks this witness is live;
    /// a replacement between captures cannot inherit the operation.
    fn opaque_control_dispatch(
        &self,
        owner: &PeerOwnerToken,
    ) -> std::result::Result<
        super::peer_registry::AdmittedInboundDispatch,
        crate::realtime::RealtimeRefusal,
    > {
        self.peers
            .with_admitted_current_or_refused(
                owner,
                self.session_broker.as_ref(),
                &self.mesh_context_id().to_string(),
                |operation| Some(operation.capture_inbound_dispatch()),
                |_| None,
            )
            .flatten()
            .ok_or(crate::realtime::RealtimeRefusal::SessionNotCurrent)
    }

    /// Called while the caller holds its exact flow fence. Every control uses
    /// this one FIFO; no caller awaits native I/O under that fence. Failure
    /// returns before label release, so a new Open cannot overtake a Close
    /// which was never admitted.
    fn queue_opaque_control(
        self: &Arc<Self>,
        dispatch: super::peer_registry::AdmittedInboundDispatch,
        worker: Arc<crate::transport::WebRtcConnectorWorker>,
        wire: crate::application_gateway::FundedOpaqueControl,
        completion: FundedArc<super::command::OpaqueControlCompletion>,
    ) -> std::result::Result<(), RealtimeFlowError> {
        // A queued Close still uses the exact link after its flow record is
        // gone. Carry activity through the command's actual terminal write;
        // a map-empty snapshot must not retire it while cleanup is queued.
        let demand_use = self
            .begin_owned_demand_link_use(&dispatch.owner().for_worker(Arc::clone(&worker)))
            .map_err(|_| RealtimeFlowError::SessionNotCurrent)?;
        self.cmd_tx
            .send(NetworkCmd::OpaqueControl(
                super::command::OpaqueControlTransfer {
                    dispatch,
                    worker,
                    wire,
                    completion,
                    _demand_use: demand_use,
                },
            ))
            .map_err(|_| RealtimeFlowError::FlowRefused)
    }

    /// Reduce an already-decoded control on the same serial peer event pump.
    /// Every mutation re-enters the original logical/session/worker fence;
    /// responses enter the one command writer without awaiting it here.
    pub(super) async fn on_opaque_control(
        self: &Arc<Self>,
        dispatch: &super::peer_registry::AdmittedInboundDispatch,
        control: crate::protocol::ApplicationFlowControl,
    ) {
        use crate::application_gateway::{FundedOpaqueControl, OpaqueControlView};
        use crate::protocol::application_flow::ApplicationFlowRefusal;
        use crate::protocol::ApplicationFlowControl as Control;
        use crate::realtime::RealtimeFlowDirection::{Inbound, Outbound};
        if control.validate().is_err() {
            return;
        }
        let logical = dispatch.logical_reply_operation();
        let mut failed_write_admission = false;
        // Capturing a response does not refresh the input's logical witness.
        let response_dispatch = self
            .peers
            .with_same_session(dispatch.logical_reply_operation(), |operation| {
                operation.capture_inbound_dispatch()
            });
        let Some(response_dispatch) = response_dispatch else {
            return;
        };
        let mut response_dispatch = Some(response_dispatch);
        let respond =
            |worker: &Arc<crate::transport::WebRtcConnectorWorker>,
             view: OpaqueControlView<'_>,
             response_dispatch: &mut Option<super::peer_registry::AdmittedInboundDispatch>,
             failed: &mut bool| {
                let result = (|| {
                    let wire = FundedOpaqueControl::encode(&self.local_resources, &view)
                        .map_err(|_| RealtimeFlowError::FlowRefused)?;
                    let completion =
                        super::command::OpaqueControlCompletion::new(&self.local_resources)
                            .map_err(|_| RealtimeFlowError::FlowRefused)?;
                    self.queue_opaque_control(
                        response_dispatch
                            .take()
                            .ok_or(RealtimeFlowError::FlowRefused)?,
                        Arc::clone(worker),
                        wire,
                        completion,
                    )
                })();
                if result.is_err() {
                    *failed = true;
                }
                result
            };
        let result = self.with_owned_realtime_flows_and_worker(
            dispatch.owner(),
            |session, flows, live, worker| {
                if !logical.witness().is_live() {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                match control {
                    Control::Open {
                        coordinate,
                        label,
                        direction,
                        mode,
                        max_body_bytes,
                    } => {
                        let local_mode = match opaque_local_mode(mode) {
                            Ok(mode) => mode,
                            Err(_) => {
                                respond(
                                    worker,
                                    OpaqueControlView::Refuse {
                                        coordinate,
                                        reason: ApplicationFlowRefusal::UnsupportedMode,
                                    },
                                    &mut response_dispatch,
                                    &mut failed_write_admission,
                                )?;
                                return Ok(None);
                            }
                        };
                        if !worker.opaque_native_mode_ready(local_mode) {
                            respond(
                                worker,
                                OpaqueControlView::Refuse {
                                    coordinate,
                                    reason: ApplicationFlowRefusal::NotAdmitted,
                                },
                                &mut response_dispatch,
                                &mut failed_write_admission,
                            )?;
                            return Ok(None);
                        }
                        // The decoded frame still funds the borrowed label. The
                        // response encoding is acquired before any retained copy.
                        let accepted = FundedOpaqueControl::encode(
                            &self.local_resources,
                            &OpaqueControlView::Accept {
                                coordinate,
                                label: &label,
                                direction,
                                mode,
                                max_body_bytes,
                            },
                        )
                        .map_err(|_| RealtimeFlowError::FlowRefused)?;
                        let completion =
                            super::command::OpaqueControlCompletion::new(&self.local_resources)
                                .map_err(|_| RealtimeFlowError::FlowRefused)?;
                        let spec = crate::transport::webrtc::OpaqueFlowSpec {
                            direction: match direction {
                                Inbound => RealtimeDirection::Outbound,
                                Outbound => RealtimeDirection::Inbound,
                            },
                            opener_direction: direction,
                            mode: local_mode,
                            max_unit_bytes: usize::try_from(max_body_bytes)
                                .map_err(|_| RealtimeFlowError::FlowRefused)?,
                            name: RealtimeFlowName::new(label)
                                .ok_or(RealtimeFlowError::FlowRefused)?,
                        };
                        let name = match flows.open_opaque_with_coordinate(
                            session,
                            Some(live),
                            spec,
                            coordinate,
                            None,
                        ) {
                            Ok(name) => name,
                            Err(_) => {
                                respond(
                                    worker,
                                    OpaqueControlView::Refuse {
                                        coordinate,
                                        reason: ApplicationFlowRefusal::NotAdmitted,
                                    },
                                    &mut response_dispatch,
                                    &mut failed_write_admission,
                                )?;
                                return Ok(None);
                            }
                        };
                        // Remote Open creates transport state only. It does not
                        // attach an app claim, sender handle or outbound pump.
                        let commit = (|| {
                            self.queue_opaque_control(
                                response_dispatch
                                    .take()
                                    .ok_or(RealtimeFlowError::FlowRefused)?,
                                Arc::clone(worker),
                                accepted,
                                completion,
                            )?;
                            flows.accept_opaque(
                                session,
                                Some(live),
                                &name,
                                coordinate,
                                local_mode,
                                max_body_bytes as usize,
                            )
                        })();
                        if let Err(error) = commit {
                            failed_write_admission = true;
                            drop(flows.close(session, Some(live), &name));
                            return Err(error);
                        }
                        Ok(None)
                    }
                    Control::Accept {
                        coordinate,
                        label,
                        direction,
                        mode,
                        max_body_bytes,
                    } => {
                        let local_mode = opaque_local_mode(mode)?;
                        if !worker.opaque_native_mode_ready(local_mode) {
                            return Err(RealtimeFlowError::FlowRefused);
                        }
                        let name = match flows.opaque_name_for_control(coordinate, direction) {
                            Some(name) => name,
                            None => {
                                let previous = crate::protocol::ApplicationFlowCoordinate {
                                    flow_id: coordinate.flow_id,
                                    generation: coordinate
                                        .generation
                                        .checked_sub(1)
                                        .ok_or(RealtimeFlowError::FlowRefused)?,
                                };
                                let name = flows
                                    .opaque_name_for_control(previous, direction)
                                    .ok_or(RealtimeFlowError::SessionNotCurrent)?;
                                if name.as_bytes() != label.as_slice()
                                    || flows.opaque_is_claimed(&name) != Some(true)
                                {
                                    return Err(RealtimeFlowError::FlowRefused);
                                }
                                flows.confirm_opaque_change(
                                    session,
                                    Some(live),
                                    &name,
                                    previous,
                                    coordinate,
                                    direction,
                                    local_mode,
                                    max_body_bytes as usize,
                                )?;
                                return Ok(None);
                            }
                        };
                        if name.as_bytes() != label.as_slice()
                            || flows.opaque_is_claimed(&name) != Some(true)
                            || flows.opaque_ready(&name, coordinate) != Some(false)
                        {
                            return Err(RealtimeFlowError::FlowRefused);
                        }
                        flows.accept_opaque(
                            session,
                            Some(live),
                            &name,
                            coordinate,
                            local_mode,
                            max_body_bytes as usize,
                        )?;
                        Ok(None)
                    }
                    Control::Close {
                        coordinate,
                        direction,
                    } => {
                        let Some(name) = flows.opaque_name_for_control(coordinate, direction)
                        else {
                            return Ok(None);
                        };
                        let remains = flows.close(session, Some(live), &name)?;
                        Ok(Some((Arc::clone(worker), remains)))
                    }
                    Control::Refuse { coordinate, .. } => {
                        // Refuse carries no direction. An ambiguous coordinate
                        // cannot authorize choosing either existing record.
                        let inbound = flows.opaque_name_for_control(coordinate, Inbound);
                        let outbound = flows.opaque_name_for_control(coordinate, Outbound);
                        let name = match (inbound, outbound) {
                            (Some(name), None) | (None, Some(name)) => name,
                            _ => return Ok(None),
                        };
                        if flows.opaque_is_claimed(&name) != Some(true) {
                            return Ok(None);
                        }
                        let remains =
                            flows.cancel_opaque(session, Some(live), &name, coordinate)?;
                        Ok(Some((Arc::clone(worker), remains)))
                    }
                    Control::Change {
                        previous_generation,
                        coordinate,
                        label,
                        direction,
                        mode,
                        max_body_bytes,
                    } => {
                        let previous = crate::protocol::ApplicationFlowCoordinate {
                            flow_id: coordinate.flow_id,
                            generation: previous_generation,
                        };
                        let local_mode = opaque_local_mode(mode)?;
                        let Some(name) = flows.opaque_name_for_control(previous, direction) else {
                            return Ok(None);
                        };
                        // This two-message Change is initiated by the actual sender.
                        // A receiver can install its new bound before Accept without
                        // emitting data across an independently ordered native lane.
                        // Receiver-initiated Change needs another phase and is not
                        // silently represented by this wire transaction.
                        if name.as_bytes() != label.as_slice()
                            || !worker.opaque_native_mode_ready(local_mode)
                            || flows
                                .opaque_name_for_coordinate(previous, direction, local_mode, 0)
                                .is_none()
                        {
                            respond(
                                worker,
                                OpaqueControlView::Refuse {
                                    coordinate,
                                    reason: ApplicationFlowRefusal::NotAdmitted,
                                },
                                &mut response_dispatch,
                                &mut failed_write_admission,
                            )?;
                            return Ok(None);
                        }
                        let mut change = match flows.prepare_opaque_change(
                            session,
                            Some(live),
                            &name,
                            previous,
                            coordinate,
                            direction,
                            local_mode,
                            max_body_bytes as usize,
                        ) {
                            Ok(change) => change,
                            Err(_) => {
                                respond(
                                    worker,
                                    OpaqueControlView::Refuse {
                                        coordinate,
                                        reason: ApplicationFlowRefusal::NotAdmitted,
                                    },
                                    &mut response_dispatch,
                                    &mut failed_write_admission,
                                )?;
                                return Ok(None);
                            }
                        };
                        let result = (|| {
                            respond(
                                worker,
                                OpaqueControlView::Accept {
                                    coordinate,
                                    label: &label,
                                    direction,
                                    mode,
                                    max_body_bytes,
                                },
                                &mut response_dispatch,
                                &mut failed_write_admission,
                            )?;
                            flows.confirm_opaque_change(
                                session,
                                Some(live),
                                &name,
                                previous,
                                coordinate,
                                direction,
                                local_mode,
                                max_body_bytes as usize,
                            )?;
                            flows.commit_opaque_change(session, Some(live), &name, &mut change)
                        })();
                        if result.is_err() {
                            // If Accept was admitted, rollback is not evidence that
                            // the peer kept its predecessor. Retire this exact
                            // logical session after releasing all flow locks.
                            failed_write_admission = true;
                            let _ = flows.rollback_opaque_change(
                                session,
                                Some(live),
                                &name,
                                &mut change,
                            );
                            return Err(RealtimeFlowError::FlowRefused);
                        }
                        Ok(None)
                    }
                }
            },
        );
        if failed_write_admission {
            super::finish_exact_logical_retirement(self, logical).await;
        } else if let Ok(Some((worker, remains))) = result {
            retire_realtime_remains(&worker, remains).await;
        }
    }

    /// Negotiate one data-only flow without awaiting inside the network
    /// supervisor. The existing provider record is both the pending transaction
    /// and the sole eventual application claim; no second label table exists.
    pub(crate) async fn open_opaque_flow(
        self: &Arc<Self>,
        peer: &str,
        open: &crate::realtime::OpaqueFlowOpen,
    ) -> std::result::Result<crate::realtime::RealtimeFlowHandle, crate::realtime::RealtimeRefusal>
    {
        use crate::application_gateway::{FundedOpaqueControl, OpaqueControlView};
        use crate::realtime::{RealtimeFlowDirection, RealtimeRefusal as Refusal};
        if !open.is_well_formed()
            || matches!(open.mode,
            crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits } if max_retransmits != 0)
        {
            return Err(Refusal::ProviderConfigurationInvalid);
        }
        if self.application_peer_needs_demand(peer) {
            // Explicit caller demand, outside the serial command supervisor.
            // The request stays caller-owned; no payload/flow registry exists
            // before the ordinary authenticated connection completes.
            self.connect_peer_wait(peer, false)
                .await
                .map_err(|_| Refusal::SessionNotCurrent)?;
        }
        let owner = self.peers.owner(peer).ok_or(Refusal::SessionNotCurrent)?;
        let dispatch = self.opaque_control_dispatch(&owner)?;
        let logical = dispatch.logical_reply_operation();
        let completion = super::command::OpaqueControlCompletion::new(&self.local_resources)?;
        // Fund the borrowed DTO's requested name copy before converting it to
        // the provider's validated request. Provider admission separately owns
        // the persistent label/map/flow backing.
        let input_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(open.label.len()).map_err(|_| Refusal::FlowRefused)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
        .map_err(|_| Refusal::FlowRefused)?;
        let _input = self
            .local_resources
            .acquire(input_claim)
            .map_err(|_| Refusal::FlowRefused)?;
        let spec = crate::transport::webrtc::OpaqueFlowSpec::try_from(open.clone())?;
        let mut dispatch = Some(dispatch);
        let prepared =
            self.with_owned_realtime_flows_and_worker(&owner, |session, flows, live, worker| {
                if !logical.witness().is_live() {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                if !worker.opaque_native_mode_ready(open.mode) {
                    return Err(RealtimeFlowError::FlowRefused);
                }
                let demand_use = self
                    .begin_demand_link_use(&owner.for_worker(Arc::clone(worker)))
                    .map_err(|_| RealtimeFlowError::SessionNotCurrent)?;
                let (name, claimed) = flows.prepare_or_claim_opaque(session, Some(live), spec)?;
                let result = (|| {
                    let coordinate = flows
                        .opaque_coordinate(&name)
                        .ok_or(RealtimeFlowError::FlowRefused)?;
                    let flow = flows
                        .flow_identity(&name)
                        .ok_or(RealtimeFlowError::FlowRefused)?;
                    if !claimed {
                        let wire = FundedOpaqueControl::encode(
                            &self.local_resources,
                            &OpaqueControlView::Open {
                                coordinate,
                                label: &open.label,
                                direction: open.direction,
                                mode: opaque_wire_mode(open.mode),
                                max_body_bytes: open.max_unit_bytes,
                            },
                        )
                        .map_err(|_| RealtimeFlowError::FlowRefused)?;
                        self.queue_opaque_control(
                            dispatch.take().ok_or(RealtimeFlowError::FlowRefused)?,
                            Arc::clone(worker),
                            wire,
                            completion.clone(),
                        )?;
                    }
                    Ok((
                        name.clone(),
                        coordinate,
                        flow,
                        flows.identity(),
                        Arc::clone(worker),
                        session.validity_witness(),
                        claimed,
                        demand_use,
                    ))
                })();
                if result.is_err() {
                    drop(flows.close(session, Some(live), &name));
                }
                result
            })?;
        let (name, coordinate, flow, flow_set, worker, validity, claimed, _demand_use) = prepared;
        let handle = crate::realtime::RealtimeFlowHandle::new(
            owner.for_worker(Arc::clone(&worker)),
            flow_set,
            flow,
            name,
            Arc::downgrade(self),
        );
        // From this point cancellation drops this exact handle and queues its
        // reciprocal Close through the same writer. It never retries an Open.
        let wait = async {
            if !claimed {
                completion.wait().await?;
            }
            loop {
                let pending = self
                    .with_owned_realtime_flows(handle.owner(), |_session, flows, _live| {
                        Self::handle_names_live_flow(flows, &handle)?;
                        match flows.opaque_ready(handle.name(), coordinate) {
                            Some(true) => Ok(None),
                            Some(false) => flows
                                .opaque_pending_wait(handle.name(), coordinate)
                                .map(Some)
                                .ok_or(RealtimeFlowError::FlowRefused),
                            None => Err(RealtimeFlowError::SessionNotCurrent),
                        }
                    })
                    .map_err(Refusal::from)?;
                let Some(pending) = pending else {
                    break;
                };
                let notified = pending.wait();
                tokio::pin!(notified);
                // Register the provider wake BEFORE rechecking readiness.
                // notify_waiters does not retain a permit for a future which
                // has not yet been polled.
                let already_notified = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(
                        std::future::Future::poll(notified.as_mut(), cx).is_ready(),
                    )
                })
                .await;
                let ready = self
                    .with_owned_realtime_flows(handle.owner(), |_session, flows, _live| {
                        Self::handle_names_live_flow(flows, &handle)?;
                        flows
                            .opaque_ready(handle.name(), coordinate)
                            .ok_or(RealtimeFlowError::SessionNotCurrent)
                    })
                    .map_err(Refusal::from)?;
                if ready {
                    break;
                }
                if !already_notified {
                    notified.await;
                }
            }
            if open.direction == RealtimeFlowDirection::Outbound {
                self.with_owned_realtime_flows_and_worker(
                    handle.owner(),
                    |session, flows, live, worker| {
                        Self::handle_names_live_flow(flows, &handle)?;
                        let (pump, retired) =
                            flows.attach_opaque_pump(session, Some(live), handle.name())?;
                        worker.spawn_opaque_outbound_pump(pump, retired);
                        Ok(())
                    },
                )
                .map_err(Refusal::from)?;
            }
            Ok(())
        };
        let timeout = std::time::Duration::from_millis(
            self.config
                .read()
                .scheduler_policy()
                .map_err(|_| Refusal::FlowRefused)?
                .offer_build_timeout_ms,
        );
        let result = tokio::select! {
            biased;
            () = validity.revoked() => Err(Refusal::SessionNotCurrent),
            result = tokio::time::timeout(timeout, wait) => result.unwrap_or(Err(Refusal::FlowRefused)),
        };
        result?;
        // Readiness can disappear while a confirmation or pump is queued.
        // Re-enter the same handle fence; never resolve a replacement lane.
        self.with_owned_realtime_flows_and_worker(
            handle.owner(),
            |_session, flows, _live, worker| {
                Self::handle_names_live_flow(flows, &handle)?;
                if !worker.opaque_native_mode_ready(open.mode) {
                    return Err(RealtimeFlowError::FlowRefused);
                }
                Ok(())
            },
        )
        .map_err(Refusal::from)?;
        Ok(handle)
    }

    /// Change a quiescent sender's ceiling on the same exact flow. Other DTO
    /// fields must match; no codec, mode or direction transition is inferred.
    /// Queue admission transfers the token to the existing connection actor.
    pub(crate) async fn change_opaque_flow(
        self: &Arc<Self>,
        handle: &crate::realtime::RealtimeFlowHandle,
        open: &crate::realtime::OpaqueFlowOpen,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        use crate::application_gateway::{FundedOpaqueControl, OpaqueControlView};
        use crate::realtime::{RealtimeFlowDirection, RealtimeRefusal as Refusal};
        if !open.is_well_formed()
            || open.direction != RealtimeFlowDirection::Outbound
            || open.label.as_slice() != handle.name().as_bytes()
        {
            return Err(Refusal::FlowRefused);
        }
        let dispatch = self.opaque_control_dispatch(handle.owner())?;
        let logical = dispatch.logical_reply_operation();
        let completion = super::command::OpaqueControlCompletion::new(&self.local_resources)?;
        let duration = std::time::Duration::from_millis(
            self.config
                .read()
                .scheduler_policy()
                .map_err(|_| Refusal::FlowRefused)?
                .offer_build_timeout_ms,
        );
        let deadline = std::time::Instant::now()
            .checked_add(duration)
            .ok_or(Refusal::FlowRefused)?;
        // One retained command label and one transient exact-record lookup.
        // Every clone is made only after this requested-capacity reservation.
        let name_claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                (open.label.len() as u64)
                    .checked_mul(2)
                    .ok_or(Refusal::FlowRefused)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
        .map_err(|_| Refusal::FlowRefused)?;
        let name_work = self
            .local_resources
            .acquire(name_claim)
            .map_err(|_| Refusal::FlowRefused)?;
        let (reply, receive) = oneshot::channel();
        self.with_owned_realtime_flows_and_worker(
            handle.owner(),
            |session, flows, live, worker| {
                Self::handle_names_live_flow(flows, handle)?;
                if !logical.witness().is_live() || !worker.opaque_native_mode_ready(open.mode) {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                let previous = flows
                    .opaque_coordinate(handle.name())
                    .ok_or(RealtimeFlowError::FlowRefused)?;
                let direction = flows
                    .opaque_opener_direction(handle.name())
                    .ok_or(RealtimeFlowError::FlowRefused)?;
                if flows
                    .opaque_name_for_coordinate(previous, direction, open.mode, 0)
                    .is_some()
                {
                    return Err(RealtimeFlowError::FlowRefused); // actual local Inbound
                }
                let coordinate = crate::protocol::ApplicationFlowCoordinate {
                    flow_id: previous.flow_id,
                    generation: previous
                        .generation
                        .checked_add(1)
                        .ok_or(RealtimeFlowError::FlowRefused)?,
                };
                let wire = FundedOpaqueControl::encode(
                    &self.local_resources,
                    &OpaqueControlView::Change {
                        previous_generation: previous.generation,
                        coordinate,
                        label: &open.label,
                        direction,
                        mode: opaque_wire_mode(open.mode),
                        max_body_bytes: open.max_unit_bytes,
                    },
                )
                .map_err(|_| RealtimeFlowError::FlowRefused)?;
                let demand_use = self
                    .begin_owned_demand_link_use(&handle.owner().for_worker(Arc::clone(worker)))
                    .map_err(|_| RealtimeFlowError::SessionNotCurrent)?;
                let change = flows.prepare_opaque_change(
                    session,
                    Some(live),
                    handle.name(),
                    previous,
                    coordinate,
                    direction,
                    open.mode,
                    open.max_unit_bytes as usize,
                )?;
                let transfer = super::command::OpaqueChangeTransfer {
                    dispatch,
                    worker: Arc::clone(worker),
                    name: handle.name().clone(),
                    change,
                    wire,
                    completion,
                    deadline,
                    reply,
                    _name_work: name_work,
                    _demand_use: demand_use,
                };
                match self
                    .connection_cmd_tx
                    .send(NetworkCmd::OpaqueChange(transfer))
                {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        let NetworkCmd::OpaqueChange(mut transfer) = error.into_value() else {
                            unreachable!()
                        };
                        let _ = flows.rollback_opaque_change(
                            session,
                            Some(live),
                            &transfer.name,
                            &mut transfer.change,
                        );
                        Err(RealtimeFlowError::FlowRefused)
                    }
                }
            },
        )?;
        receive.await.map_err(|_| Refusal::SessionNotCurrent)?
    }

    pub(super) async fn run_opaque_change(
        self: &Arc<Self>,
        transfer: super::command::OpaqueChangeTransfer,
    ) {
        use crate::realtime::RealtimeRefusal as Refusal;
        let super::command::OpaqueChangeTransfer {
            dispatch,
            worker,
            name,
            mut change,
            wire,
            completion,
            deadline,
            reply,
            _name_work,
            _demand_use,
        } = transfer;
        let logical = dispatch.logical_reply_operation();
        let owner = dispatch.owner().for_worker(Arc::clone(&worker));
        if reply.is_closed() || std::time::Instant::now() >= deadline {
            let _ = self.with_owned_realtime_flows(&owner, |session, flows, live| {
                flows.rollback_opaque_change(session, Some(live), &name, &mut change)
            });
            let _ = reply.send(Err(Refusal::FlowRefused));
            return;
        }
        // Arming outside locks covers actor cancellation after publication.
        // The caller owns no token and cannot silently roll back this phase.
        let mut terminal = super::OpaqueControlWriteGuard {
            state: self,
            failed: Some(logical),
        };
        let published = self.with_owned_realtime_flows(&owner, |_session, flows, _live| {
            if flows.opaque_change_wait(&name, &change).is_none() {
                return Err(RealtimeFlowError::SessionNotCurrent);
            }
            self.queue_opaque_control(dispatch, Arc::clone(&worker), wire, completion.clone())
        });
        if published.is_err() {
            let _ = self.with_owned_realtime_flows(&owner, |session, flows, live| {
                flows.rollback_opaque_change(session, Some(live), &name, &mut change)
            });
            terminal.failed = None; // no wire was admitted
            let _ = reply.send(Err(Refusal::FlowRefused));
            return;
        }
        let transaction = async {
            completion.wait().await?;
            loop {
                let waiting = self
                    .with_owned_realtime_flows(&owner, |session, flows, live| {
                        if let Some(waiting) = flows.opaque_change_wait(&name, &change) {
                            return Ok(Some(waiting));
                        }
                        flows.commit_opaque_change(session, Some(live), &name, &mut change)?;
                        Ok(None)
                    })
                    .map_err(Refusal::from)?;
                let Some(waiting) = waiting else {
                    return Ok(());
                };
                let notified = waiting.wait();
                tokio::pin!(notified);
                let already = std::future::poll_fn(|cx| {
                    std::task::Poll::Ready(
                        std::future::Future::poll(notified.as_mut(), cx).is_ready(),
                    )
                })
                .await;
                let committed = self
                    .with_owned_realtime_flows(&owner, |session, flows, live| {
                        if flows.opaque_change_wait(&name, &change).is_some() {
                            return Ok(false);
                        }
                        flows.commit_opaque_change(session, Some(live), &name, &mut change)?;
                        Ok(true)
                    })
                    .map_err(Refusal::from)?;
                if committed {
                    return Ok(());
                }
                if !already {
                    notified.await;
                }
            }
        };
        let result = tokio::time::timeout_at(tokio::time::Instant::from_std(deadline), transaction)
            .await
            .unwrap_or(Err(Refusal::FlowRefused));
        if result.is_ok() {
            terminal.failed = None;
        } else if let Some(logical) = terminal.failed.take() {
            super::finish_exact_logical_retirement(self, logical).await;
        }
        let _ = reply.send(result);
        // Provider token, command label and link activity remain owned through
        // final commit or joined exact-session teardown, including lost reply.
    }

    /// Hand one unit to the outbound flow a handle names.
    ///
    /// Takes the connector's unit, already converted at the public boundary:
    /// the engine moves bytes between a handle and a flow and never reads what a
    /// unit carries.
    ///
    /// **Borrows the handle and resolves nothing.** The fence is entered with
    /// the installation the flow was opened on, then the handle's two identities
    /// are proved against the set that answered. A caller whose session has been
    /// replaced, or whose label has been closed and reopened, is refused here.
    /// Resolving by name instead would enqueue into the successor's flow of the
    /// same name and tell nobody, because nothing on this path is acknowledged
    /// per unit.
    pub(crate) fn send_realtime(
        &self,
        handle: &crate::realtime::RealtimeFlowHandle,
        unit: RealtimeSendUnit,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
            Self::handle_names_live_flow(flows, handle)?;
            flows.send(session, Some(live), handle.name(), unit)
        })
        .map_err(Into::into)
    }

    /// Admit one opaque unit to the existing exact flow queue. Success is
    /// local queue custody, not a native write or remote acknowledgement.
    /// The owned provider pump retains output funding through its native send.
    pub(crate) fn send_opaque(
        &self,
        handle: &crate::realtime::RealtimeFlowHandle,
        bytes: Bytes,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        let _use = self
            .begin_demand_link_use(handle.owner())
            .map_err(|_| crate::realtime::RealtimeRefusal::SessionNotCurrent)?;
        self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
            Self::handle_names_live_flow(flows, handle)?;
            flows.send_opaque(session, Some(live), handle.name(), bytes)
        })
        .map_err(Into::into)
    }

    pub(super) fn deliver_opaque_application_unit(
        &self,
        owner: &PeerOwnerToken,
        coordinate: crate::protocol::application_flow::ApplicationFlowCoordinate,
        direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        bytes: Bytes,
    ) -> bool {
        let Ok(_use) = self.begin_demand_link_use(owner) else {
            return false;
        };
        self.with_owned_realtime_flows(owner, |_session, flows, _live| {
            Ok(flows.deliver_opaque(coordinate, direction, mode, bytes))
        })
        .unwrap_or(false)
    }

    /// The one existing reader owns both RTP and opaque queue custody. It
    /// cannot be reacquired by peer/label after a session replacement.
    pub(crate) async fn recv_opaque(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> std::result::Result<
        Option<crate::realtime::OpaqueInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        inbound.next_opaque().await
    }

    /// The tagged reader consumes either kind exactly once and retains the
    /// provider's funded arrival through the caller's terminal handoff.
    pub(crate) async fn recv_realtime_arrival(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> Option<crate::transport::webrtc::RealtimeInboundArrival> {
        inbound.next_arrival().await
    }

    /// Close one flow and retire the native half it was standing on.
    ///
    /// The mirror of [`Self::open_realtime_negotiated`], and async for the same
    /// reason: releasing a transceiver or a sender awaits, and the fence is a
    /// synchronous lock. Phase 1 closes the flow and carries out both the exact
    /// worker and whatever the flow still owned; phase 2 retires it with no
    /// lock held.
    ///
    /// **Whole-connector retirement is deliberately not relied on.** The same
    /// worker may host a replacement session, so a flow's native half can
    /// outlive the flow while the connector it belongs to stays perfectly
    /// healthy. Retiring per flow is the only thing that tracks the flow's own
    /// lifetime.
    ///
    /// The label is released at the end of phase 1, so a re-open can claim it
    /// before the stop lands. That is safe rather than merely tolerated: the
    /// new flow mints its own identity and `close` has already removed the old
    /// one from the bindings table, so a track arriving on the stale
    /// transceiver has nothing to attach to and is refused. What it still costs
    /// until phase 2 finishes is an m-line and bandwidth — which is why the
    /// caller awaits this rather than being told the flow is gone while it is
    /// not.
    /// **Consumes the handle**, because a close is the end of the thing the
    /// handle names. Taking it by value is what makes "closed twice" and "closed
    /// then sent on" unrepresentable rather than merely refused, and it is why
    /// closing A cannot close B after an immediate reuse of A's label: the
    /// identities travelled with the handle, and B's flow is a different record.
    pub(crate) async fn close_realtime_negotiated(
        self: &Arc<Self>,
        mut handle: crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        // Before anything, and unconditionally. This call is the close, so the
        // handle's own drop-close must not run behind it — on the success path
        // it would be a second close of a record this one removed, and on the
        // refusal path there is nothing to close: every way this refuses is a
        // way the flow was already not ours.
        handle.disarm();
        if self.handle_is_opaque(&handle) {
            let (worker, remains, completion) = self.close_opaque_local(&handle)?;
            retire_realtime_remains(&worker, remains).await;
            return completion.wait().await;
        }
        let (worker, remains) = self.with_owned_realtime_flows_and_worker(
            handle.owner(),
            |session, flows, live, worker| {
                Self::handle_names_live_flow(flows, &handle)?;
                let remains = flows.close(session, Some(live), handle.name())?;
                Ok((Arc::clone(worker), remains))
            },
        )?;
        retire_realtime_remains(&worker, remains).await;
        Ok(())
    }

    /// Close the flow an abandoned handle named, telling nobody.
    ///
    /// The drop half of [`Self::close_realtime_negotiated`], and deliberately
    /// only its phase 1. Phase 2 is an await this cannot perform and does not
    /// need to: `close` hands back a [`RealtimeFlowRemains`], and both of its
    /// arms retire what they hold when they are dropped — which is what happens
    /// to the value below. The difference between this and an explicit close is
    /// therefore the acknowledgement, not the retirement.
    ///
    /// Every refusal is discarded, because each one means the flow is already
    /// gone: a stale owner, a session that has been replaced, a label closed and
    /// reopened. There is no caller left to tell, and nothing here to undo.
    pub(crate) fn abandon_realtime_flow(
        self: &Arc<Self>,
        handle: &crate::realtime::RealtimeFlowHandle,
    ) {
        if self.handle_is_opaque(handle) {
            // The command, not this caller, owns the exact control write. Its
            // admission precedes freeing the label even when no caller waits.
            drop(self.close_opaque_local(handle));
            return;
        }
        // Dropped, not ignored: this value *is* the retirement, and naming it
        // is how that reads as the retirement happening rather than as a result
        // being thrown away.
        drop(
            self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
                Self::handle_names_live_flow(flows, handle)?;
                flows.close(session, Some(live), handle.name())
            }),
        );
    }

    fn handle_is_opaque(&self, handle: &crate::realtime::RealtimeFlowHandle) -> bool {
        self.with_owned_realtime_flows(handle.owner(), |_session, flows, _live| {
            Self::handle_names_live_flow(flows, handle)?;
            Ok(flows.opaque_coordinate(handle.name()).is_some())
        })
        .unwrap_or(false)
    }

    fn close_opaque_local(
        self: &Arc<Self>,
        handle: &crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<
        (
            Arc<crate::transport::WebRtcConnectorWorker>,
            RealtimeFlowRemains,
            FundedArc<super::command::OpaqueControlCompletion>,
        ),
        crate::realtime::RealtimeRefusal,
    > {
        use crate::application_gateway::{FundedOpaqueControl, OpaqueControlView};
        let dispatch = self.opaque_control_dispatch(handle.owner())?;
        let logical = dispatch.logical_reply_operation();
        let mut failed_cleanup = false;
        let result = self.with_owned_realtime_flows_and_worker(
            handle.owner(),
            |session, flows, live, worker| {
                Self::handle_names_live_flow(flows, handle)?;
                if !logical.witness().is_live() {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                let coordinate = flows
                    .opaque_coordinate(handle.name())
                    .ok_or(RealtimeFlowError::SessionNotCurrent)?;
                let direction = flows
                    .opaque_opener_direction(handle.name())
                    .ok_or(RealtimeFlowError::SessionNotCurrent)?;
                let admitted = (|| {
                    let completion =
                        super::command::OpaqueControlCompletion::new(&self.local_resources)
                            .map_err(|_| RealtimeFlowError::FlowRefused)?;
                    let wire = FundedOpaqueControl::encode(
                        &self.local_resources,
                        &OpaqueControlView::Close {
                            coordinate,
                            direction,
                        },
                    )
                    .map_err(|_| RealtimeFlowError::FlowRefused)?;
                    self.queue_opaque_control(
                        dispatch,
                        Arc::clone(worker),
                        wire,
                        completion.clone(),
                    )?;
                    Ok(completion)
                })();
                let completion = match admitted {
                    Ok(completion) => completion,
                    Err(error) => {
                        failed_cleanup = true;
                        return Err(error);
                    }
                };
                // Still under the same mutation/flow fence: no later same-label
                // Open can be inserted before the Close which is now in the FIFO.
                let remains = match flows.close(session, Some(live), handle.name()) {
                    Ok(remains) => remains,
                    Err(error) => {
                        failed_cleanup = true;
                        return Err(error);
                    }
                };
                Ok((Arc::clone(worker), remains, completion))
            },
        );
        if failed_cleanup {
            // The label was never released. Retire only the captured logical
            // session outside its fence, so provider refusal cannot orphan a
            // reciprocal record and then admit a successor on that session.
            self.peers.retire_exact_session(logical);
        }
        result.map_err(Into::into)
    }

    /// Whether that handle still names a usable flow.
    ///
    /// Borrows rather than consumes: asking is not using, and a caller that
    /// learns `false` still has to drop its handle, which costs nothing.
    pub(crate) fn realtime_is_current(&self, handle: &crate::realtime::RealtimeFlowHandle) -> bool {
        self.with_owned_realtime_flows(handle.owner(), |session, flows, live| {
            Self::handle_names_live_flow(flows, handle)?;
            Ok(flows.is_current(session, Some(live), handle.name()))
        })
        .unwrap_or(false)
    }

    /// Deliver one inbound realtime unit onto the flow it names.
    ///
    /// The connector half resolved which flow the track belongs to and
    /// assembled the unit; this half proves the flow set is still one this
    /// engine may write to. Both halves are needed and neither substitutes for
    /// the other: a binding table says *which* flow, and only the fence says
    /// *whether* — the exact owner installation, the current session, and a
    /// freshly acquired live incarnation, all under the mutation lock the
    /// replacement path also takes.
    ///
    /// Synchronous throughout. Nothing here awaits, so the currency proof and
    /// the enqueue are one step against connector replacement rather than two
    /// with a window between them.
    ///
    /// Every failure drops the unit and releases its payload reservation, and
    /// does so without a branch: the delivery moves into the closure, so a fence
    /// that refuses before running it drops it, and `deliver_inbound` drops it
    /// itself when the flow is gone or when it carries no lease. Answers whether
    /// the unit was taken — `false` for a stale owner, an ended session, an
    /// absent flow, or an unaccounted delivery, which are one fact to the
    /// connector: it has nothing left to do either way.
    ///
    /// **The delivery is carried whole and never split here.** Its three parts
    /// include a payload lease, which is a `transport::webrtc` type and stays
    /// one: an engine holding a bare lease could release the bytes' accounting
    /// separately from the unit they belong to, and there is no reason for this
    /// layer to be able to. What crosses is one opaque value that either lands
    /// on a flow or is dropped intact.
    pub(crate) fn deliver_realtime_unit(
        &self,
        owner: &PeerOwnerToken,
        delivery: crate::transport::webrtc::RealtimeInboundDelivery,
    ) -> bool {
        self.peers
            .with_live_session_flow(
                owner,
                self.session_broker.as_ref(),
                &self.mesh_context_id().to_string(),
                move |_session, flows, _live| flows.deliver_inbound(delivery),
            )
            .unwrap_or(false)
    }

    /// Claim the inbound stream of `peer`'s current session.
    ///
    /// `None` covers both "no live session" and "already claimed", for the same
    /// reason every other operation collapses resolution failures: the caller
    /// has proved nothing, so it learns only that it does not have the stream.
    ///
    /// Synchronous on purpose. The claim happens inside the fence, and the
    /// reader it produces borrows nothing from the flow set, so the caller
    /// leaves the lock behind before it ever awaits.
    pub(crate) fn claim_realtime_inbound(
        &self,
        peer: &str,
    ) -> Option<crate::realtime::RealtimeInboundStream> {
        let reader = self
            .with_realtime_flows(peer, |_session, flows, _live| Ok(flows.inbound_arrivals()))
            .ok()
            .flatten()?;
        // Only the reader crosses. The selector did its work resolving the
        // session here and has nothing left to say: the reader already names the
        // one queue that session's flow set owns, so carrying the bytes along
        // would be a second copy of a binding the handle already has.
        Some(crate::realtime::RealtimeInboundStream::new(reader))
    }

    /// The next unit to arrive on any inbound flow of that session.
    ///
    /// **Nothing is held, and no fence is entered.** The reader takes whole
    /// units from the one queue its own flow set owns, so there is nothing left
    /// for a fence to establish: the unit was funded, retained and handed over
    /// by that set, and no session but that one can put anything into it.
    ///
    /// That is what makes this a single step rather than a loop. Awaiting a
    /// *name* and resolving it afterwards left a window a replacement could land
    /// in — the same bytes name a different flow on a different session, and the
    /// fence would resolve the replacement quite correctly and hand back a real
    /// unit belonging to something else. There is no name to resolve here.
    ///
    /// `None` is terminal and means the session ended: the flow set was dropped,
    /// so its queue was, so the reader is done. There is no retirement event to
    /// consume; a caller that gets `None` closes.
    ///
    /// The provider's guarded arrival crosses this bridge unchanged. An
    /// opaque head is a typed refusal without dequeue, not a terminal stream
    /// and not a label/body copy whose original custody has already ended.
    pub(crate) async fn next_realtime_arrival(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> std::result::Result<
        Option<crate::transport::webrtc::WebRtcRealtimeInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        inbound.reader().next_rtp().await
    }

    /// The worker-lending fence, entered against an owner the caller already
    /// holds.
    ///
    /// **No selector is resolved here, and there is no variant that does.**
    /// [`Self::with_realtime_flows`] is the only realtime fence that turns a
    /// Device name into whichever installation answers to it now, and only two
    /// operations may do that: opening a flow, and claiming a session's inbound
    /// stream. Everything with a native half enters here instead, with the
    /// installation the operation started against, so a replacement fails a
    /// pointer check rather than being resolved to.
    fn with_owned_realtime_flows_and_worker<T>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<crate::transport::WebRtcConnectorWorker>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        self.peers
            .with_live_session_flow_and_worker(
                owner,
                self.session_broker.as_ref(),
                &self.mesh_context_id().to_string(),
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
    }

    /// The flow-set-only fence, entered against an owner the caller already
    /// holds.
    ///
    /// The synchronous twin of [`Self::with_owned_realtime_flows_and_worker`],
    /// for the send path — which must not await and has no native half to reach.
    fn with_owned_realtime_flows<T>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        self.peers
            .with_live_session_flow(
                owner,
                self.session_broker.as_ref(),
                &self.mesh_context_id().to_string(),
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
    }

    /// Prove a handle still names a live flow, inside a fence already entered.
    ///
    /// Two questions, both against identity and neither against bytes.
    ///
    /// The flow set names the **exact promoted session**. The owner the fence
    /// was entered with names the installation, and those are not the same
    /// statement: one installation promotes one session today — the entry
    /// admits a single endpoint-auth task, that task a single capability, and
    /// promotion consumes it — but that is a property of the promotion path,
    /// not of this one. Asking the direct question costs a pointer comparison
    /// and does not have to be revisited when the promotion path changes.
    ///
    /// The flow record rules out a **replacement flow inside the same session**,
    /// which the flow-set check cannot see at all: closing a name and reopening
    /// it changes neither the session nor the set, only the record.
    ///
    /// Both refusals are `SessionNotCurrent`, which is the honest answer in both
    /// cases and deliberately the same one. A caller holding a stale handle has
    /// no live flow, and telling it *why* would report on a flow it has no
    /// standing to learn about — the one that took the name.
    fn handle_names_live_flow(
        flows: &SessionRealtimeFlows,
        handle: &crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<(), RealtimeFlowError> {
        if !flows.is_same(handle.flow_set()) || !flows.is_same_flow(handle.name(), handle.flow()) {
            return Err(RealtimeFlowError::SessionNotCurrent);
        }
        Ok(())
    }

    /// Close a flow whose native half never came up, releasing its label and
    /// retiring whatever the flow still owned.
    ///
    /// Answers whether it did the retiring, so a caller holding its own handle
    /// on the native object knows not to retire it a second time.
    ///
    /// `false` also covers the case where the fence no longer resolves the same
    /// flow set. The flow and its label went with the session that owned them —
    /// which is the state this was trying to reach — but the native half did
    /// not, so the caller still has work to do.
    ///
    /// Enters against the **owner the open resolved**, never the selector it was
    /// given. Cleaning up after a failed open by re-resolving a Device name
    /// would be the same defect as sending by one: the flow this is trying to
    /// release belongs to a particular installation, and a replacement that has
    /// since taken the name is not it. The flow-set check below then narrows
    /// that installation to the exact session.
    async fn abandon_realtime_open(
        &self,
        owner: &PeerOwnerToken,
        flow_set: &RealtimeFlowSetIdentity,
        name: &RealtimeFlowName,
    ) -> bool {
        let closed =
            self.with_owned_realtime_flows_and_worker(owner, |session, flows, live, worker| {
                if !flows.is_same(flow_set) {
                    return Err(RealtimeFlowError::SessionNotCurrent);
                }
                let remains = flows.close(session, Some(live), name)?;
                Ok((Arc::clone(worker), remains))
            });
        let Ok((worker, remains)) = closed else {
            return false;
        };
        retire_realtime_remains(&worker, remains).await;
        true
    }

    /// Resolve a Device selector to its live session and flow set, once.
    ///
    /// **The only realtime fence that resolves a name, and it has exactly one
    /// caller left**: claiming a session's inbound stream, which is a fresh
    /// question about whoever is current rather than an operation on something
    /// already open. (Opening a flow resolves too, but resolves for itself and
    /// keeps the owner, because it has two more fence acquisitions to make and
    /// must make them against the same installation.)
    ///
    /// The resolution rule is stated once, here: no live session means
    /// `SessionNotCurrent`, and the fence — not the caller — supplies both the
    /// session and the freshly acquired incarnation.
    fn with_realtime_flows<T>(
        &self,
        peer: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> std::result::Result<T, RealtimeFlowError>,
    ) -> std::result::Result<T, RealtimeFlowError> {
        let Some(owner) = self.peers.owner(peer) else {
            return Err(RealtimeFlowError::SessionNotCurrent);
        };
        self.peers
            .with_live_session_flow(
                &owner,
                self.session_broker.as_ref(),
                &self.mesh_context_id().to_string(),
                effect,
            )
            .unwrap_or(Err(RealtimeFlowError::SessionNotCurrent))
    }

    /// Send a channel frame to one peer via the command queue.
    /// Used by [`crate::Channel::send_to`].
    pub async fn send_channel_frame(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        if self.application_peer_needs_demand(peer) {
            // The caller retains its payload while the separately joined
            // connection lane works. No establishment await enters the serial
            // supervisor. Demand either produces a direct WebRTC/TURN session
            // for the caller's send or returns a refusal; it never carries
            // application bytes through signaling or a fallback relay.
            match self.connect_peer_wait_inner(peer, false, true).await? {
                ChannelDemandOutcome::Ready
                | ChannelDemandOutcome::NoOwnedAttemptRefused
                | ChannelDemandOutcome::FailedSettlementJoined => {}
                ChannelDemandOutcome::Unsettled | ChannelDemandOutcome::TerminalRefused => {
                    return Err(Error::Network(
                        "application demand has not completed exact settlement".into(),
                    ))
                }
            }
        }
        let directly_admitted = self.peers.owner(peer).is_some_and(|owner| {
            self.peers
                .with_live_session(
                    &owner,
                    self.session_broker.as_ref(),
                    &self.mesh_context_id().to_string(),
                    |_| (),
                )
                .is_some()
        });
        if !directly_admitted {
            return Err(Error::Network(
                "application peer has no authenticated direct WebRTC session".into(),
            ));
        }
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelFrame {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped reply".into()))?
    }

    /// Broadcast a channel frame to every active peer. Returns
    /// the count of peers it was dispatched to.
    pub async fn broadcast_channel_frame(
        &self,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<usize> {
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::BroadcastChannelFrame {
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped broadcast reply".into()))
    }

    /// Refresh the compatibility roster after canonical admission. It does NOT
    /// transition any active session — call
    /// It never emits a transport approval frame.
    pub(super) fn refresh_roster_projection(&self, device_id: &str, label: &str) -> Result<()> {
        self.refresh_roster_projection_with(device_id, label, |candidate| {
            let mut affected = std::collections::BTreeSet::new();
            affected.insert(crate::signing::pubkey_part(device_id).to_string());
            crate::roster::save_affected(candidate, &affected)
        })
    }

    fn refresh_roster_projection_with<F>(&self, device_id: &str, label: &str, save: F) -> Result<()>
    where
        F: FnOnce(&crate::roster::Roster) -> Result<()>,
    {
        let graph = self.fact_graph.read();
        let target = crate::semantic::DeviceId::from_canonical_str(device_id)
            .map_err(|error| Error::Network(format!("noncanonical roster projection: {error}")))?;
        let local = crate::semantic::DeviceId::from_canonical_str(self.identity.public_id())
            .map_err(|error| Error::Network(format!("noncanonical local identity: {error}")))?;
        let admitted = graph.admits_policy_session(self.verified_bootstrap(), &local, &target);
        drop(graph);
        if !admitted {
            return Err(Error::Network(
                "canonical projection does not admit roster projection".into(),
            ));
        }
        // Save a detached candidate before publishing it in memory. The
        // production closure above writes only the affected keyed record; a
        // failed atomic write must not leave this process claiming a
        // projection that a restart cannot recover.
        let mut roster = self.roster.write();
        let mut candidate = roster.clone();
        crate::roster::add_peer_in(&mut candidate, device_id, label);
        save(&candidate)?;
        *roster = candidate;
        Ok(())
    }

    // Defense in depth behind the handshake's eviction gate: on a
    // closed network a device the signed state evicted can't be
    // rostered by ANY path — not mutual-ACTIVE persistence, not a
    // manual approve from a stale UI. Re-admission is a signed member
    // grant (the owner re-claiming it), which flips the verdict first.

    /// True if the canonical projection currently admits the peer.
    ///
    /// This compatibility query is read-only and non-authoritative. The
    /// persisted roster is only a UI cache and is intentionally not consulted.
    pub fn is_rostered(&self, device_id: &str) -> bool {
        let Ok(target) = crate::semantic::DeviceId::from_canonical_str(device_id) else {
            return false;
        };
        let Ok(local) = crate::semantic::DeviceId::from_canonical_str(self.identity.public_id())
        else {
            return false;
        };
        let graph = self.fact_graph.read();
        graph.admits_policy_session(self.verified_bootstrap(), &local, &target)
    }

    /// Return the compatibility/UI roster filtered by the canonical graph.
    /// Persisted rows provide display metadata only and never authorize.
    pub(crate) fn canonical_roster_view(&self) -> Vec<crate::roster::AuthorizedPeer> {
        let mut view = self
            .roster
            .read()
            .authorized_devices
            .iter()
            .filter(|peer| self.is_rostered(&peer.device_id))
            .cloned()
            .collect::<Vec<_>>();
        view.sort_by(|left, right| left.device_id.cmp(&right.device_id));
        view
    }

    /// Total count of peers in any state.
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }

    /// Snapshot the current per-peer view as an owned list. The
    /// engine drops behind the lock during this call; callers
    /// should treat the snapshot as instantaneous and re-fetch
    /// for fresh data.
    pub fn peer_snapshot(&self) -> Vec<crate::handle::PeerInfo> {
        self.peers
            .collect_map(|peer| Some(peer.with_peer_view(Self::peer_info_from_view)))
    }

    /// Build one [`crate::handle::PeerInfo`] from a single coherent observation.
    ///
    /// Both public snapshot paths go through here, so they cannot drift and
    /// neither can pair a stale advert with fresh state — the view's session and
    /// data halves were read together.
    ///
    /// Reads exactly the fields `PeerInfo` publishes. The shape this replaces
    /// went through `PeerStateSnapshot`, which cloned the whole `PeerDiag` so
    /// that two of its counters could be projected and the rest discarded; the
    /// wire result is identical and the clone is gone.
    fn peer_info_from_view(view: super::connection::PeerView<'_>) -> crate::handle::PeerInfo {
        let data = view.data;
        let pubkey = crate::signing::pubkey_part(view.device_id);
        crate::handle::PeerInfo {
            device_id: view.device_id.to_string(),
            status: data.status,
            tier: data.tier,
            rtt_ms: data.rtt_ms,
            clock_skew_ms: data.clock_skew_ms,
            label: data.label.clone(),
            capabilities: view.session.and_then(|app| app.capabilities()),
            local_shelved: data.local_shelved,
            remote_shelved: data.remote_shelved,
            authenticated: data.authenticated,
            device_suffix: crate::identity::display_suffix(pubkey.as_bytes()),
            verification_code_received: data.verification_code_received.clone(),
            verification_code_sent: data.verification_code_sent.clone(),
            local_approve_sent: data.local_approve_sent,
            remote_approve_seen: data.remote_approve_seen,
            needs_turn: data.no_turn_diag_emitted,
            // Cloned because `IceCandidateStats` is not `Copy`. It is five
            // `u32`s with no heap under them, so the clone is the copy the
            // compiler would have made — and still strictly less than the shape
            // this replaced, which cloned the whole `PeerDiag` to project two
            // of its fields.
            local_candidates: data.diag.local_candidates.clone(),
            remote_candidates: data.diag.remote_candidates.clone(),
            selected_pair: data.selected_pair,
        }
    }

    /// Plan a funded peers snapshot.
    /// Per-peer detail. Returns `None` if the peer is not in the
    /// engine's map.
    pub fn peer_info(&self, device_id: &str) -> Option<crate::handle::PeerInfo> {
        Some(
            self.peers
                .get(device_id)?
                .with_peer_view(Self::peer_info_from_view),
        )
    }

    /// Prepare and send one bounded local hub advertisement page. The
    /// controller lock is held only while advancing Trickle and the recipient
    /// cursor; every owner check and transport await occurs outside it.
    pub(crate) async fn poll_hub(self: &Arc<Self>) {
        if let Some((advertisement, limit)) = self
            .hub
            .as_ref()
            .and_then(|controller| controller.lock().prepare_poll())
        {
            let recipient_after = self
                .hub
                .as_ref()
                .and_then(|controller| controller.lock().recipient_after());
            let mut selected: Vec<(bool, DeviceId, PeerOwnerToken)> = Vec::with_capacity(limit);
            self.peers.visit_owners(|owner| {
                if !self.peers.has_usable_authenticated_current(&owner)
                    || !self.hub.as_ref().is_some_and(|controller| {
                        controller.lock().configured_hub(owner.device_id())
                    })
                {
                    return;
                }
                let Ok(key) = DeviceId::from_canonical_str(owner.device_id()) else {
                    return;
                };
                if recipient_after.as_ref().is_some_and(|after| &key <= after) {
                    return;
                }
                let position =
                    match selected.binary_search_by(|(_, existing, _)| existing.cmp(&key)) {
                        Ok(_) => return,
                        Err(position) => position,
                    };
                if selected.len() == limit
                    && selected
                        .last()
                        .is_some_and(|(_, existing, _)| existing <= &key)
                {
                    return;
                }
                if selected.len() == limit {
                    selected.pop();
                }
                selected.insert(position, (false, key, owner));
            });
            if selected.len() < limit && recipient_after.is_some() {
                self.peers.visit_owners(|owner| {
                    if !self.peers.has_usable_authenticated_current(&owner)
                        || !self.hub.as_ref().is_some_and(|controller| {
                            controller.lock().configured_hub(owner.device_id())
                        })
                    {
                        return;
                    }
                    let Ok(key) = DeviceId::from_canonical_str(owner.device_id()) else {
                        return;
                    };
                    if recipient_after.as_ref().is_none_or(|after| &key > after) {
                        return;
                    }
                    let prefix_len = selected
                        .iter()
                        .position(|(is_wrap, _, _)| *is_wrap)
                        .unwrap_or(selected.len());
                    let position = match selected[prefix_len..]
                        .binary_search_by(|(_, existing, _)| existing.cmp(&key))
                    {
                        Ok(_) => return,
                        Err(position) => prefix_len + position,
                    };
                    if selected.len() == limit
                        && selected
                            .last()
                            .is_some_and(|(_, existing, _)| existing <= &key)
                    {
                        return;
                    }
                    if selected.len() == limit {
                        selected.pop();
                    }
                    selected.insert(position, (true, key, owner));
                });
            }
            if let Some((_, last, _)) = selected.last() {
                if let Some(controller) = self.hub.as_ref() {
                    controller.lock().advance_recipient_after(last.clone());
                }
            }
            let mut delivered = false;
            for (_, _, owner) in selected {
                if super::send_to_peer_owner(
                    self,
                    &owner,
                    &crate::protocol::MeshMessage::HubAdvertisement(advertisement.clone()),
                )
                .await
                .is_ok()
                {
                    delivered = true;
                }
            }
            if delivered {
                if let Some(controller) = self.hub.as_ref() {
                    controller.lock().acknowledge_delivery();
                }
            }
        }
        if let Some((target, request)) = self
            .hub
            .as_ref()
            .and_then(|controller| controller.lock().prepare_discovery())
        {
            let target_id = target.to_string();
            let mut owner = None;
            self.peers.visit_owners(|candidate| {
                if owner.is_none()
                    && candidate.device_id() == target_id.as_str()
                    && self.peers.has_usable_authenticated_current(&candidate)
                {
                    owner = Some(candidate);
                }
            });
            if let Some(owner) = owner {
                let bound = self
                    .peers
                    .with_current(&owner, |peer| {
                        self.usable_tree_owner(&owner, peer)
                            && self.hub.as_ref().is_some_and(|controller| {
                                controller.lock().bind_discovery_request(&target, &owner)
                            })
                    })
                    .unwrap_or(false);
                if !bound {
                    return;
                }
                let _ = super::send_to_peer_owner(
                    self,
                    &owner,
                    &crate::protocol::MeshMessage::HubDiscoveryRequest(request),
                )
                .await;
            }
        }
    }

    /// Answer one exact-owner directory request with a sorted, bounded page
    /// of currently authenticated/promoted peer identities. No address,
    /// authority, forwarding, or recursive query state is exposed.
    pub(crate) async fn handle_hub_discovery_request(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        request: crate::protocol::HubDiscoveryRequest,
    ) {
        let Some(controller) = self.hub.as_ref() else {
            return;
        };
        let admitted = self
            .peers
            .with_current(owner, |peer| {
                if !self.usable_tree_owner(owner, peer)
                    || request.context_id() != self.mesh_context_id
                {
                    return false;
                }
                let mut controller = controller.lock();
                controller.local_is_hub() && controller.accept_discovery_request()
            })
            .unwrap_or(false);
        if !admitted {
            return;
        }
        let max = usize::from(request.max_peers());
        let retain = max
            .checked_add(1)
            .expect("protocol discovery page bound is small");
        let after = request.after();
        let mut peers = Vec::with_capacity(retain);
        self.peers.visit_owners(|candidate| {
            if !self.peers.has_usable_authenticated_current(&candidate)
                || candidate.device_id() == self.identity.public_id()
            {
                return;
            }
            let Ok(peer) = DeviceId::from_canonical_str(candidate.device_id()) else {
                return;
            };
            if after.is_some_and(|after| &peer <= after) {
                return;
            }
            let position = match peers.binary_search(&peer) {
                Ok(_) => return,
                Err(position) => position,
            };
            if peers.len() == retain && peers.last().is_some_and(|existing| existing <= &peer) {
                return;
            }
            if peers.len() == retain {
                peers.pop();
            }
            peers.insert(position, peer);
        });
        let has_more = peers.len() > max;
        let page = peers.into_iter().take(max).collect::<Vec<_>>();
        let next_after = has_more.then(|| page[max - 1].clone());
        let Ok(response) =
            crate::protocol::HubDiscoveryResponse::for_request(&request, page, next_after)
        else {
            return;
        };
        let _ = super::send_to_peer_owner(
            self,
            owner,
            &crate::protocol::MeshMessage::HubDiscoveryResponse(response),
        )
        .await;
    }

    /// Consume one response only for its exact outstanding request owner and
    /// sequence. Returned identities become ordinary Sighted hints and never
    /// create a session or modify hub configuration.
    pub(crate) fn handle_hub_discovery_response(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        response: crate::protocol::HubDiscoveryResponse,
    ) {
        let Some(controller) = self.hub.as_ref() else {
            return;
        };
        let Some(Some((peers, referrer))) = self.peers.with_current(owner, |peer| {
            if !self.usable_tree_owner(owner, peer) {
                return None;
            }
            let peers = controller
                .lock()
                .observe_discovery_response(owner, &response)?;
            let referrer = DeviceId::from_canonical_str(owner.device_id()).ok()?;
            Some((peers, referrer))
        }) else {
            return;
        };
        let Ok(observer) = DeviceId::from_canonical_str(self.identity.public_id()) else {
            return;
        };
        for peer in peers {
            if peer.to_string() == self.identity.public_id() {
                continue;
            }
            super::note_sighted_without_dialing(self, &peer.to_string(), "hub exploration");
            if let Some(graph) = self.local_observation.as_ref() {
                let provenance = super::local_observation::ObservationProvenance {
                    observer: super::local_observation::ObservationDeviceKey::from_device(
                        &observer,
                    ),
                    referrer: Some(super::local_observation::ObservationDeviceKey::from_device(
                        &referrer,
                    )),
                    subject: super::local_observation::ObservationDeviceKey::from_device(&peer),
                };
                let locator = super::local_observation::ObservationLocator::ViaPeer(
                    super::local_observation::ObservationDeviceKey::from_device(&referrer),
                );
                // Receiving a valid directory page is only a referral
                // sighting.  Do not manufacture a successful referred
                // operation for a target that has not authenticated.
                let _ = graph.lock().record_referral(provenance, locator);
            }
        }
    }

    fn tree_wire_rejection(
        refusal: super::parenting::ParentingRefusal,
    ) -> crate::protocol::HubTreeAttachRejection {
        use crate::protocol::HubTreeAttachRejection as Wire;
        match refusal {
            super::parenting::ParentingRefusal::ContextMismatch => Wire::InvalidContext,
            super::parenting::ParentingRefusal::ConfigurationMismatch => Wire::InvalidConfiguration,
            super::parenting::ParentingRefusal::Capacity => Wire::RelationCapacity,
            super::parenting::ParentingRefusal::UnsupportedRole => Wire::UnsupportedDepth,
            super::parenting::ParentingRefusal::OwnerMismatch
            | super::parenting::ParentingRefusal::InvalidOwner => Wire::OwnerMismatch,
            super::parenting::ParentingRefusal::StaleRequest
            | super::parenting::ParentingRefusal::PendingMismatch => Wire::StaleRequest,
            _ => Wire::ParentUnavailable,
        }
    }

    /// Recheck the complete promoted-owner usability predicate while the
    /// registry's exact-owner mutation fence is held.  Callers must not split
    /// this check from the synchronous relation/replay mutation.
    fn usable_tree_owner(
        &self,
        owner: &PeerOwnerToken,
        peer: &super::connection::PeerConnection,
    ) -> bool {
        let phase_admits = {
            let data = peer.state.read();
            matches!(
                data.status,
                super::connection::PeerStatus::Active | super::connection::PeerStatus::Shelved
            )
        };
        let Ok(device) = DeviceId::from_canonical_str(owner.device_id()) else {
            return false;
        };
        phase_admits
            && peer.holds_promoted_session()
            && peer.has_usable_session_for_recovery()
            && self.peers.routed_origin_policy_admits(&device)
    }

    fn tree_parent_rejection(
        rejection: crate::protocol::HubTreeAttachRejection,
    ) -> super::parenting::ParentAttachRejection {
        use super::parenting::ParentAttachRejection as Parent;
        use crate::protocol::HubTreeAttachRejection as Wire;
        match rejection {
            Wire::InvalidContext => Parent::ContextMismatch,
            Wire::InvalidConfiguration => Parent::ConfigurationMismatch,
            Wire::RelationCapacity => Parent::Capacity,
            Wire::UnsupportedDepth => Parent::UnsupportedRole,
            Wire::OwnerMismatch => Parent::NotCurrentOwner,
            Wire::StaleRequest => Parent::StaleRequest,
            Wire::ParentUnavailable | Wire::AlreadyAttached => Parent::Capacity,
        }
    }

    fn tree_parent_target(&self) -> Option<DeviceId> {
        let role = self.parenting_role?;
        let topology = self.topology.read();
        let TopologyMode::HubTree { root, hubs, .. } = &*topology else {
            return None;
        };
        match role {
            super::parenting::ParentingRole::Root => None,
            super::parenting::ParentingRole::Hub(1) => DeviceId::from_canonical_str(root).ok(),
            super::parenting::ParentingRole::Leaf => {
                let after = self
                    .parenting_target_after
                    .lock()
                    .as_ref()
                    .map(ToString::to_string);
                let candidate = crate::topology::tree::next_parent_candidate(
                    root,
                    hubs,
                    self.identity.public_id(),
                    after.as_deref(),
                )?;
                let candidate = DeviceId::from_canonical_str(candidate).ok()?;
                *self.parenting_target_after.lock() = Some(candidate.clone());
                Some(candidate)
            }
            super::parenting::ParentingRole::Hub(_) => None,
        }
    }

    fn tree_child_role(&self, child: &DeviceId) -> Option<super::parenting::ParentingRole> {
        let role = self.parenting_role?;
        let topology = self.topology.read();
        let TopologyMode::HubTree { root, .. } = &*topology else {
            return None;
        };
        let root = DeviceId::from_canonical_str(root).ok()?;
        match role {
            super::parenting::ParentingRole::Root
                if self.parenting_hubs.iter().any(|hub| hub == child) =>
            {
                Some(super::parenting::ParentingRole::Hub(1))
            }
            super::parenting::ParentingRole::Hub(1)
                if child != &root && !self.parenting_hubs.iter().any(|hub| hub == child) =>
            {
                Some(super::parenting::ParentingRole::Leaf)
            }
            _ => None,
        }
    }

    /// One bounded HubTree maintenance pass.  A non-root node keeps at most
    /// one outstanding primary registration, and all transport work happens
    /// after the parenting mutex is released.
    pub(crate) async fn poll_parenting(self: &Arc<Self>) {
        let Some(parenting) = self.parenting.as_ref() else {
            return;
        };
        let _ = parenting.lock().maintain_now();
        if self
            .parenting_role
            .is_some_and(|role| !matches!(role, super::parenting::ParentingRole::Root))
            && parenting
                .lock()
                .primary_parent_at_now()
                .ok()
                .flatten()
                .is_some()
        {
            return;
        }
        // Parent attempts have their own hard minimum and jitter. Consume
        // the paced opportunity before selecting a candidate or starting
        // any owner-bound work; replies cannot accelerate this clock.
        let attempt_due = self.hub.as_ref().is_some_and(|controller| {
            matches!(controller.lock().prepare_parent_attempt(), Ok(true))
        });
        if !attempt_due {
            return;
        }
        let Some(target) = self.tree_parent_target() else {
            return;
        };
        let pending_owner_is_current = {
            let pending = self.parenting_pending.lock();
            pending
                .as_ref()
                .is_none_or(|pending| self.peers.has_usable_authenticated_current(&pending.owner))
        };
        if !pending_owner_is_current {
            let pending = self.parenting_pending.lock().take();
            if let Some(pending) = pending {
                let _ = parenting
                    .lock()
                    .cancel_child_attach(&pending.witness, pending.ticket);
            }
            return;
        }
        let Some(owner) = self.peers.owner(&target.to_string()) else {
            return;
        };
        let Some(local) = self.parenting_local else {
            return;
        };
        let Some(sequence) = next_non_wrapping(&self.parenting_next_sequence) else {
            return;
        };
        let Some(_) = self.parenting_root else {
            return;
        };
        let Some(digest) = self.parenting_digest else {
            return;
        };
        let Ok(local_device) = DeviceId::from_canonical_str(self.identity.public_id()) else {
            return;
        };
        let child_role = self
            .parenting_role
            .unwrap_or(super::parenting::ParentingRole::Leaf);
        let root = {
            let topology = self.topology.read();
            let TopologyMode::HubTree { root, .. } = &*topology else {
                return;
            };
            let Ok(root) = DeviceId::from_canonical_str(root) else {
                return;
            };
            root
        };
        let parent_role = if target == root {
            super::parenting::ParentingRole::Root
        } else {
            super::parenting::ParentingRole::Hub(1)
        };
        let Ok(request) = super::parenting::ParentAttachRequest::new(
            *self.mesh_context_id.as_bytes(),
            digest,
            sequence,
            local,
            super::parenting::ParentDeviceKey::from_device(&target),
            child_role,
            parent_role,
            super::parenting::ParentingRelationKind::Primary,
        ) else {
            return;
        };
        let Some(Some((witness, ticket))) = self.peers.with_current(&owner, |peer| {
            if !self.usable_tree_owner(&owner, peer) {
                return None;
            }
            let witness = super::parenting::ParentOwnerWitness::from_owner(&owner).ok()?;
            let ticket = parenting
                .lock()
                .begin_child_attach(&witness, request)
                .ok()?;
            Some((witness, ticket))
        }) else {
            return;
        };
        let Ok(wire_request) = crate::protocol::HubTreeAttachRequest::new(
            self.mesh_context_id,
            digest,
            sequence,
            local_device,
            target.clone(),
        ) else {
            let _ = parenting.lock().cancel_child_attach(&witness, ticket);
            return;
        };
        *self.parenting_pending.lock() = Some(PendingParentAttach {
            owner: owner.clone(),
            witness,
            ticket,
            request,
            wire_request: wire_request.clone(),
        });
        if super::send_to_peer_owner(
            self,
            &owner,
            &crate::protocol::MeshMessage::HubTreeAttachRequest(wire_request),
        )
        .await
        .is_err()
        {
            if let Some(pending) = self.parenting_pending.lock().take() {
                let _ = parenting
                    .lock()
                    .cancel_child_attach(&pending.witness, pending.ticket);
            }
        }
    }

    pub(crate) async fn handle_hub_tree_attach_request(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        request: crate::protocol::HubTreeAttachRequest,
    ) {
        let Some(parenting) = self.parenting.as_ref() else {
            return;
        };
        let Some(response) = self.peers.with_current(owner, |peer| {
            let Ok(owner_device) = DeviceId::from_canonical_str(owner.device_id()) else {
                return None;
            };
            if !self.usable_tree_owner(owner, peer)
                || &owner_device != request.child()
                || request.context_id() != self.mesh_context_id
                || self.parenting_digest != Some(request.configuration_digest())
            {
                return None;
            }
            let Some(child_role) = self.tree_child_role(request.child()) else {
                return Some(crate::protocol::HubTreeAttachResponse::rejected(
                    &request,
                    crate::protocol::HubTreeAttachRejection::UnsupportedDepth,
                ));
            };
            let local = self.parenting_local?;
            let Ok(local_device) = DeviceId::from_canonical_str(self.identity.public_id()) else {
                return None;
            };
            if request.parent() != &local_device {
                return None;
            }
            let parent_role = self.parenting_role?;
            let Ok(witness) = super::parenting::ParentOwnerWitness::from_owner(owner) else {
                return None;
            };
            let Ok(internal) = super::parenting::ParentAttachRequest::new(
                *self.mesh_context_id.as_bytes(),
                request.configuration_digest(),
                request.request_sequence(),
                super::parenting::ParentDeviceKey::from_device(request.child()),
                local,
                child_role,
                parent_role,
                super::parenting::ParentingRelationKind::Primary,
            ) else {
                return None;
            };
            let result = parenting.lock().accept_request(&witness, internal);
            match result {
                Ok(super::parenting::ParentAttachResponse::Accepted {
                    relation_generation,
                    ..
                }) => {
                    crate::protocol::HubTreeAttachResponse::accepted(&request, relation_generation)
                        .ok()
                }
                Ok(super::parenting::ParentAttachResponse::Rejected { reason, .. }) => {
                    use super::parenting::ParentAttachRejection as Parent;
                    use crate::protocol::HubTreeAttachRejection as Wire;
                    let reason = match reason {
                        Parent::UnsupportedRole => Wire::UnsupportedDepth,
                        Parent::NotCurrentOwner => Wire::OwnerMismatch,
                        Parent::Capacity => Wire::RelationCapacity,
                        Parent::StaleRequest => Wire::StaleRequest,
                        Parent::ContextMismatch => Wire::InvalidContext,
                        Parent::ConfigurationMismatch => Wire::InvalidConfiguration,
                    };
                    Some(crate::protocol::HubTreeAttachResponse::rejected(
                        &request, reason,
                    ))
                }
                Err(refusal) => Some(crate::protocol::HubTreeAttachResponse::rejected(
                    &request,
                    Self::tree_wire_rejection(refusal),
                )),
            }
        }) else {
            return;
        };
        if let Some(response) = response {
            let _ = super::send_to_peer_owner(
                self,
                owner,
                &crate::protocol::MeshMessage::HubTreeAttachResponse(response),
            )
            .await;
        }
    }

    pub(crate) fn handle_hub_tree_attach_response(
        self: &Arc<Self>,
        owner: &PeerOwnerToken,
        response: crate::protocol::HubTreeAttachResponse,
    ) {
        let Some(Some(())) = self.peers.with_current(owner, |peer| {
            let Ok(owner_device) = DeviceId::from_canonical_str(owner.device_id()) else {
                return None;
            };
            if !self.usable_tree_owner(owner, peer) || &owner_device != response.parent() {
                return None;
            }
            let matches = self
                .parenting_pending
                .lock()
                .as_ref()
                .is_some_and(|pending| {
                    pending.owner.binding_coordinate() == owner.binding_coordinate()
                        && pending.wire_request.context_id() == response.context_id()
                        && pending.wire_request.configuration_digest()
                            == response.configuration_digest()
                        && pending.wire_request.request_sequence() == response.request_sequence()
                        && pending.wire_request.child() == response.child()
                        && pending.wire_request.parent() == response.parent()
                });
            if !matches {
                return None;
            }
            let pending = self.parenting_pending.lock().take()?;
            let internal = match response.relation_generation() {
                Some(generation) => super::parenting::ParentAttachResponse::Accepted {
                    request: pending.request,
                    relation_generation: generation,
                },
                None => super::parenting::ParentAttachResponse::Rejected {
                    request: pending.request,
                    reason: Self::tree_parent_rejection(
                        response
                            .rejection()
                            .unwrap_or(crate::protocol::HubTreeAttachRejection::StaleRequest),
                    ),
                },
            };
            if let Some(parenting) = self.parenting.as_ref() {
                if parenting
                    .lock()
                    .adopt_response(&pending.witness, &pending.ticket, internal)
                    .is_err()
                {
                    let _ = parenting
                        .lock()
                        .cancel_child_attach(&pending.witness, pending.ticket);
                }
            }
            Some(())
        }) else {
            return;
        };
    }

    /// Read the bounded local parenting table without exposing authority or
    /// session state.  The handle-only transport-lab facade converts this
    /// tuple into its public fixed snapshot type.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn parenting_snapshot_for_lab(&self) -> Option<ParentingSnapshotForLab> {
        self.parenting.as_ref().map(|parenting| {
            let mut parenting = parenting.lock();
            let snapshot = parenting.snapshot_for_lab();
            (
                snapshot.primary_parent,
                snapshot.accepted_children,
                snapshot.pending,
                snapshot.generation,
            )
        })
    }

    /// Advance only this network's transport-lab parenting clock. The
    /// production monotonic clock remains the source used by relation expiry;
    /// no wall-clock, scheduler, authentication, or peer clock is modified.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn advance_parenting_clock_for_lab(&self, delta_ms: u64) -> Result<()> {
        let Some(parenting) = self.parenting.as_ref() else {
            return Err(Error::Network(
                "HubTree parenting clock is unavailable".into(),
            ));
        };
        parenting
            .lock()
            .advance_clock(delta_ms)
            .map_err(|error| Error::Network(format!("HubTree parenting clock: {error}")))
    }

    /// Advance this network's parenting clock and take the effective relation
    /// snapshot under one parenting lock.  This keeps a transport-lab expiry
    /// observation ahead of the scheduler's next paced reattachment attempt;
    /// it does not alter any production clock or routing authority.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn advance_parenting_clock_and_snapshot_for_lab(
        &self,
        delta_ms: u64,
    ) -> Result<Option<ParentingSnapshotForLab>> {
        let Some(parenting) = self.parenting.as_ref() else {
            return Err(Error::Network(
                "HubTree parenting clock is unavailable".into(),
            ));
        };
        let mut parenting = parenting.lock();
        parenting
            .advance_clock(delta_ms)
            .map_err(|error| Error::Network(format!("HubTree parenting clock: {error}")))?;
        let snapshot = parenting.snapshot_for_lab();
        Ok(Some((
            snapshot.primary_parent,
            snapshot.accepted_children,
            snapshot.pending,
            snapshot.generation,
        )))
    }

    /// Return aggregate discovery progress from the exact HubController.  The
    /// controller keeps cursor identities private; this seam exposes only
    /// bounded counters and the last page shape for transport-lab evidence.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn hub_discovery_diagnostics_for_lab(
        &self,
    ) -> Option<super::hub::HubDiscoveryDiagnostics> {
        self.hub
            .as_ref()
            .map(|controller| controller.lock().discovery_diagnostics())
    }

    /// Notify the optional advertisement clock of a genuine local owner
    /// transition. The caller must already hold the exact current admitted
    /// owner fence; this method deliberately never re-enters the registry.
    /// A refused reset cannot veto promotion, retirement, or application work.
    pub(crate) fn note_hub_authenticated_owner_change(&self, owner: &PeerOwnerToken) {
        if let Some(controller) = self.hub.as_ref() {
            let _ = controller
                .lock()
                .note_local_authenticated_owner_change(owner);
        }
    }

    /// Called only after a genuine locally committed topology change.
    pub(crate) fn note_hub_local_topology_change(&self) {
        if let Some(controller) = self.hub.as_ref() {
            let _ = controller.lock().note_local_topology_change();
        }
    }

    pub(crate) fn retire_parenting_owner(&self, owner: &PeerOwnerToken) {
        if let (Some(parenting), Ok(witness)) = (
            self.parenting.as_ref(),
            super::parenting::ParentOwnerWitness::from_owner(owner),
        ) {
            let _ = parenting.lock().retire_owner(&witness);
        }
        // Retire local diagnostic sightings only while this captured owner is
        // still the installed coordinate (or has no successor).  A displaced
        // owner must not erase a replacement's same-device aggregate; the
        // observation ticket fence handles stale callbacks after this guard.
        let captured_owner_is_current = self
            .peers
            .owner(owner.device_id())
            .is_none_or(|current| current.binding_coordinate() == owner.binding_coordinate());
        if captured_owner_is_current {
            if let (Some(graph), Ok(peer)) = (
                self.local_observation.as_ref(),
                crate::semantic::DeviceId::from_canonical_str(owner.device_id()),
            ) {
                let _ = graph.lock().retire_peer(
                    super::local_observation::ObservationDeviceKey::from_device(&peer),
                );
            }
        }
    }

    /// Record a successful current authenticated pong in the optional local
    /// diagnostic graph. Every failure is intentionally ignored so this cache
    /// can never block or alter the mesh path.
    pub(crate) fn observe_authenticated_peer(&self, owner: &PeerOwnerToken) {
        if !self.peers.has_usable_authenticated_current(owner) {
            return;
        }
        let Ok(observer) = crate::semantic::DeviceId::from_canonical_str(self.identity.public_id())
        else {
            return;
        };
        let Ok(subject) = crate::semantic::DeviceId::from_canonical_str(owner.device_id()) else {
            return;
        };
        let Some(graph) = self.local_observation.as_ref() else {
            return;
        };
        let provenance = super::local_observation::ObservationProvenance {
            observer: super::local_observation::ObservationDeviceKey::from_device(&observer),
            referrer: None,
            subject: super::local_observation::ObservationDeviceKey::from_device(&subject),
        };
        let locator = super::local_observation::ObservationLocator::ViaPeer(
            super::local_observation::ObservationDeviceKey::from_device(&subject),
        );
        let ticket = graph.lock().record_sighting(
            provenance,
            locator,
            super::local_observation::ObservationSighting::Authenticated,
        );
        if let Ok(ticket) = ticket {
            // The pong reached this exact current authenticated owner, so this
            // is a genuine successful operation outcome rather than a second
            // synthetic sighting.  Any stale/retired refusal remains advisory.
            let _ = graph.lock().record_authenticated_outcome(
                ticket,
                super::local_observation::ObservationOutcome::Succeeded,
            );
        }
    }

    /// Apply a HubAdvertisement only after the exact current authenticated
    /// owner fence. The advisory result is deliberately not routed into
    /// topology, authorization, or configuration.
    pub(crate) fn observe_hub_advertisement(
        &self,
        owner: &PeerOwnerToken,
        advertisement: &crate::protocol::HubAdvertisement,
    ) -> bool {
        let Some(controller) = self.hub.as_ref() else {
            return false;
        };
        self.peers
            .with_current(owner, |peer| {
                self.usable_tree_owner(owner, peer)
                    && controller
                        .lock()
                        .observe_advertisement(owner, advertisement)
            })
            .unwrap_or(false)
    }

    pub(crate) fn maintain_local_observation(&self) {
        if let Some(graph) = self.local_observation.as_ref() {
            let _ = graph.lock().maintain_now();
        }
    }

    /// Tear down every active peer session. Called from the
    /// driver's shutdown path.
    pub(crate) async fn shutdown(self: &Arc<Self>) {
        self.log_shutdown_phase("begin");
        if let (Some(parenting), Some(pending)) = (
            self.parenting.as_ref(),
            self.parenting_pending.lock().take(),
        ) {
            let _ = parenting
                .lock()
                .cancel_child_attach(&pending.witness, pending.ticket);
        }
        self.log_shutdown_phase("before-request-shutdown");
        self.request_shutdown();
        self.log_shutdown_phase("after-request-shutdown");
        self.await_shutdown_mutations().await;
        self.log_shutdown_phase("mutations-drained");
        self.cancel_all_recovery_demands();
        // Keep the published runtime alive while every retired connector has
        // finished releasing its exact de-duplication custody.  The field is
        // cleared only after this is the last shutdown consumer of it.
        let runtime = self.signaling_runtime();
        // The connection actor has been dropped before this function runs.
        // Its move-out reservations have restored any exact introduced pump.
        // First resume detached/failed introductions while registry identity
        // and the signaling token owner are still present.
        if let (Some(pool), Some(controller)) =
            (self.demand_links.as_ref(), self.hub_introductions.as_ref())
        {
            let mut cursor = None;
            loop {
                let next = pool
                    .lock()
                    .links
                    .successor_after(cursor.as_ref())
                    .map(|(key, link)| {
                        (*key, link.introduction, link.generation, link.owner.clone())
                    });
                let Some((key, ticket, generation, owner)) = next else {
                    break;
                };
                cursor = Some(key);
                if !self.peers.has_usable_authenticated_current(&owner) {
                    controller.lock().failed(ticket);
                    self.settle_failed_introduction_inner(key, ticket, generation)
                        .await;
                }
            }
        }
        self.log_shutdown_phase("peer-retire-begin");
        let retired = self.peers.prepare_for_shutdown();
        for peer in &retired {
            self.settle_attempt(
                &peer.attempt(),
                myownmesh_signaling::nostr::delivery::DeliveryTerminal::Cancelled,
            );
            if let Err(error) = peer.retire_and_close().await {
                tracing::warn!(%error, peer = %peer.device_id, "peer cleanup failed during shutdown");
            }
            let _ = self.peers.complete_shutdown_peer(peer);
            if let Some(runtime) = runtime.as_ref() {
                for token in peer.take_retired_dedup() {
                    runtime.forget_token(token);
                }
            }
        }
        self.log_shutdown_phase("peer-retire-drained");
        self.log_shutdown_phase("replaced-close-begin");
        self.peers.await_replaced_closes().await;
        self.log_shutdown_phase("replaced-close-drained");
        self.log_shutdown_phase("shutdown-task-begin");
        self.await_shutdown_tasks().await;
        self.log_shutdown_phase("shutdown-tasks-drained");
        self.peer_event_pump_shutdown_started
            .store(true, Ordering::Release);
        self.peer_event_pump_shutdown_waiting.notify_waiters();
        self.log_shutdown_phase("event-pump-begin");
        let event_pumps = loop {
            let notified = self.peer_event_pump_ready.notified();
            let drained = {
                let mut registry = self.peer_event_pumps.lock();
                if registry.pending_registrations == 0 {
                    registry.closed = true;
                    Some(std::mem::take(&mut registry.handles))
                } else {
                    None
                }
            };
            if let Some(event_pumps) = drained {
                break event_pumps;
            }
            notified.await;
        };
        for pump in event_pumps {
            if let Err(error) = pump.await {
                tracing::warn!(%error, "peer event pump failed during shutdown");
            }
        }
        // Original registration completion publishes either into that Vec or
        // directly into an exact demand record under its SAME lifecycle lock.
        // With registration now closed there can be no late record handoff.
        if let Some(pool) = self.demand_links.as_ref() {
            loop {
                let next = pool
                    .lock()
                    .links
                    .successor_after(None)
                    .map(|(key, link)| (*key, link.owner.clone(), link.introduction));
                let Some((key, owner, ticket)) = next else {
                    break;
                };
                // close_waiter itself starts native close; it is NOT a passive
                // observation. Global shutdown has retired its owned peers
                // above. A still-live reused/successor-owned worker is not ours
                // to close merely because an old demand record names it.
                if let Some(worker) = owner.worker() {
                    if worker.live_connector_incarnation().is_some() {
                        self.resolve_introduction_waiters(owner.device_id(), ticket, false);
                        tracing::warn!("shutdown retains an unsettled introduction with a live successor worker");
                        return;
                    }
                    let _ = worker.retire_and_close().await;
                }
                let _ = self.join_introduction_pump_after_native(&owner).await;
                // A failed JoinHandle result is still a terminal join. An
                // absent handle with NO terminal result is not. Never clear
                // such a record merely because shutdown attempted the join.
                let terminal = pool.lock().links.get(&key).is_some_and(|link| {
                    same_demand_owner(&link.owner, &owner)
                        && link.introduction == ticket
                        && link.pump_registered
                        && link.pump.is_none()
                        && link.pump_joined.is_some()
                        && link.settlement != IntroductionSettlementPhase::Joining
                });
                if !terminal {
                    self.resolve_introduction_waiters(owner.device_id(), ticket, false);
                    tracing::warn!(
                        "shutdown retains introduction custody without a terminal receiver join"
                    );
                    return;
                }
                {
                    let mut guard = pool.lock();
                    if let Some(link) = guard.links.get_mut(&key) {
                        if let Some(detached) = link.detached.take() {
                            detached.release_after_join(owner.connection());
                        }
                    }
                }
                // Shutdown, stale ownership, or any error never authorizes
                // fallback even when shutdown's eventual joins succeeded.
                self.resolve_introduction_waiters(owner.device_id(), ticket, false);
                pool.lock().links.remove(&key);
            }
        }
        self.log_shutdown_phase("event-pump-drained");
        drop(retired);
        drop(runtime);
        self.signaling_runtime.write().take();
        self.clear_attempt_settlement();
        #[cfg(feature = "transport-lab")]
        for forwarder in self.take_local_signaling_forwarders() {
            if let Err(error) = forwarder.await {
                tracing::warn!(%error, "local signaling forwarder failed during shutdown");
            }
        }
        // Nothing outlives the engine: parked connect waits resolve with the
        // truth instead of hanging.
        //
        // Queued reliable sends need no pass of their own here, and that is the
        // point of moving them. `retire_and_close` above drops each peer's
        // promoted session, which drops the record that retained them, which
        // resolves every waiting caller — before this function even reaches the
        // connect waiters. A separate shutdown sweep would be a second place
        // that has to remember, and the one that is forgotten is the one that
        // leaves a caller hanging.
        loop {
            let removed = self.connect_waiters.lock().pop_first_entry();
            let Some((peer, mut bucket)) = removed else {
                break;
            };
            while let Some(waiter) = bucket.waiters.pop_front() {
                waiter.finish(Err(Error::Network(format!(
                    "connect {peer}: network shut down"
                ))));
            }
            // The bucket's `_name` lease funds this key's retained bytes;
            // release the returned key explicitly before the value drops.
            drop(peer);
        }
        self.application_gateway.close();
        if let Some(controller) = self.hub_introductions.as_ref() {
            controller.lock().shutdown();
        }
        drop(self.hub_signaling_carrier.lock().take());
        if let Some(pool) = self.demand_links.as_ref() {
            // In-flight guards retain their exact caller/worker custody. They
            // cannot update a removed generation or adopt a successor.
            let links = std::mem::take(&mut pool.lock().links);
            drop(links);
        }
        if let Some(graph) = self.local_observation.as_ref() {
            let _ = graph.lock().retire_owner();
        }
        // Join the same synchronous publication fence used by durable graph
        // and proof work before releasing the owner.  The shutdown flag stops
        // new work immediately; this second fence lets one already-admitted
        // send-preparation finish its exact owner/store step before the slot
        // becomes permanently unavailable to stale state facades.
        let _publication = self.durable_publication_gate.lock();
        let mut semantic_graph = self.fact_graph.write();
        semantic_graph.seal_live_checkpoint();
        let provisional = self.durable_provisional.lock().clone();
        if let Err(error) = self
            .durable_semantic_owner
            .persist_live_checkpoint(&semantic_graph, &provisional)
        {
            // The ledger transaction remains authoritative. A failed or
            // interrupted checkpoint only makes the next startup take the
            // existing full crash-recovery path.
            tracing::warn!(%error, "durable semantic live checkpoint failed during shutdown");
        }
        drop(provisional);
        match self.durable_semantic_owner.release() {
            Ok(()) => {
                // `shutdown(&self)` is deliberately borrow-based, and the
                // mesh registry or another facade may therefore retain this
                // retired NetworkState after its worker and storage lease
                // have terminated.  Keeping the complete fact history here
                // would make an ordinary same-process reopen hold both the
                // old and restored ledgers.  Once the durable owner has
                // joined successfully no operation may use this state again,
                // so retain only the immutable bootstrap/policy boundary and
                // release the history before publishing shutdown completion.
                *semantic_graph = crate::semantic::FactGraph::from_bootstrap_with_policy(
                    &self.verified_bootstrap,
                    self.config.read().semantic_policy,
                );
                self.durable_provisional.lock().clear();
                self.shutdown_complete
                    .store(true, std::sync::atomic::Ordering::Release);
            }
            Err(error) => {
                tracing::warn!(%error, "durable semantic owner release failed during shutdown");
            }
        }
    }

    #[cfg(test)]
    pub(super) fn peer_event_pump_counts_for_test(&self) -> (usize, usize) {
        let pumps = self.peer_event_pumps.lock();
        (pumps.pending_registrations, pumps.handles.len())
    }

    /// Begin registering one production peer-event pump.  Shutdown closes the
    /// registry only after all begun registrations have handed in their
    /// handles, so a pump can never race into detached custody.
    pub(crate) fn begin_peer_event_pump_registration(&self) -> bool {
        let mut pumps = self.peer_event_pumps.lock();
        if pumps.closed {
            return false;
        }
        let Some(pending) = pumps.pending_registrations.checked_add(1) else {
            return false;
        };
        pumps.pending_registrations = pending;
        true
    }

    /// Complete a previously begun registration.  If the lifecycle has
    /// already closed, this method remains the exact runtime owner and awaits
    /// the handle itself instead of aborting or dropping it.
    pub(crate) async fn finish_peer_event_pump_registration(&self, pump: JoinHandle<()>) {
        let mut pump = Some(pump);
        let await_here = {
            let mut registry = self.peer_event_pumps.lock();
            debug_assert!(registry.pending_registrations > 0);
            registry.pending_registrations -= 1;
            if registry.closed {
                true
            } else {
                registry
                    .handles
                    .push(pump.take().expect("open registration owns its pump"));
                false
            }
        };
        self.peer_event_pump_ready.notify_waiters();
        if await_here {
            if let Err(error) = pump
                .take()
                .expect("closed registration retains its pump")
                .await
            {
                tracing::warn!(%error, "late peer event pump failed during registration");
            }
        }
    }

    /// Complete an introduced pump registration directly into its existing
    /// demand record. The pending count is decremented under the SAME lifecycle
    /// lock as this transfer; shutdown cannot miss both owners in between.
    /// A non-introduced owner leaves the original registration unchanged.
    pub(super) fn finish_introduced_pump_registration(
        &self,
        owner: &PeerOwnerToken,
        pump: JoinHandle<()>,
    ) -> std::result::Result<(), JoinHandle<()>> {
        let (Some(pool), Ok(key)) = (
            self.demand_links.as_ref(),
            DeviceId::canonical_key_bytes(owner.device_id()),
        ) else {
            return Err(pump);
        };
        let mut lifecycle = self.peer_event_pumps.lock();
        let mut pool = pool.lock();
        let Some(link) = pool
            .links
            .get_mut(&key)
            .filter(|link| same_demand_owner(&link.owner, owner) && !link.pump_registered)
        else {
            return Err(pump);
        };
        assert!(lifecycle.pending_registrations > 0);
        assert!(
            !lifecycle.closed,
            "pending registration precedes lifecycle close"
        );
        link.pump = Some(pump);
        link.pump_registered = true;
        lifecycle.pending_registrations -= 1;
        drop(pool);
        drop(lifecycle);
        self.peer_event_pump_ready.notify_waiters();
        Ok(())
    }

    /// Transport-lab-only access to the production peer-pump registration
    /// fence. The integration control uses the same begin/finish ownership
    /// path as the engine and cannot install an unregistered worker.
    #[cfg(feature = "transport-lab")]
    pub fn begin_peer_event_pump_registration_for_lab(&self) -> bool {
        self.begin_peer_event_pump_registration()
    }

    #[cfg(feature = "transport-lab")]
    pub async fn finish_peer_event_pump_registration_for_lab(&self, pump: JoinHandle<()>) {
        self.finish_peer_event_pump_registration(pump).await;
    }

    /// Wait until shutdown has reached its exact peer-pump drain barrier.
    /// This is a lifecycle observation, not a timer or a readiness guess.
    #[cfg(feature = "transport-lab")]
    pub async fn wait_peer_event_pump_shutdown_for_lab(&self) {
        loop {
            let notified = self.peer_event_pump_shutdown_waiting.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .peer_event_pump_shutdown_started
                .load(Ordering::Acquire)
            {
                return;
            }
            notified.await;
        }
    }

    /// Publish a carrier departure observation. Fire-and-forget, like every
    /// other signaling publish: the message is handed to the signaling driver
    /// and rides the relays best-effort. This does not own or retire any peer
    /// session; [`crate::JoinedNetwork::announce_leave`] first performs the
    /// authenticated-session departure protocol, then publishes this hint
    /// while the signaling driver still exists.
    pub fn announce_departure(&self) {
        if let Err(error) = self.signaling_tx.send(SignalingOutbound::Leave) {
            tracing::warn!(error = %error.into_admission_error(), "departure announcement was refused");
        }
    }

    /// Queue an in-place reconnect on the engine driver — redial signaling and
    /// renegotiate ICE without leaving the room. `peer == None` reconnects
    /// every peer on this network; `peer == Some(id)` reconnects just that one.
    /// The non-destructive twin of [`Self::announce_departure`] + rejoin: no
    /// `Leave` is announced and no session is torn down, so peers keep their
    /// connections and app-level state. The actual work runs on the driver via
    /// [`NetworkCmd::Reconnect`] so it's serialized with every other per-peer
    /// mutation. See [`super::network_watch::reconnect_all_in_place`].
    pub fn reconnect(&self, peer: Option<String>) {
        if let Err(error) = self.cmd_tx.send(NetworkCmd::Reconnect { peer }) {
            tracing::warn!(error = %error.into_admission_error(), "reconnect command was refused");
        }
    }

    /// Queue a deliberate offerer-side dial of exactly one peer on the engine
    /// driver. The manual-connect primitive a `Silent` network needs: on a
    /// Silent mesh the engine never auto-dials on presence, so a session is
    /// opened only here (or by answering an inbound offer). Fire-and-forget,
    /// like [`Self::reconnect`]; the work runs on the driver via
    /// [`NetworkCmd::ConnectPeer`]. Backs [`crate::JoinedNetwork::connect_peer`].
    pub fn connect_peer(&self, device_id: &str) {
        if let Err(error) = self.request_connect_peer(device_id.to_string(), false, None) {
            tracing::warn!(error = %error.into_admission_error(), peer = %device_id, "connect command was refused");
        }
    }

    pub(super) fn application_peer_needs_demand(&self, peer: &str) -> bool {
        let enabled = {
            let config = self.config.read();
            config.introduction.is_some()
                && matches!(
                    &config.topology,
                    TopologyMode::Star { .. }
                        | TopologyMode::Hubs { .. }
                        | TopologyMode::HubTree { .. }
                )
        };
        enabled
            && !self
                .peers
                .owner(peer)
                .is_some_and(|owner| self.peers.has_usable_authenticated_current(&owner))
    }

    // Refusal returns the original funded command and waiter custody, without a new box.
    #[allow(clippy::result_large_err)]
    pub(crate) fn request_connect_peer(
        &self,
        device_id: String,
        sticky: bool,
        reply: Option<ConnectWaiterRegistration>,
    ) -> std::result::Result<(), ResourceMailboxSendError<NetworkCmd>> {
        self.connection_cmd_tx.send(NetworkCmd::ConnectPeer {
            device_id,
            sticky,
            reply,
        })
    }

    pub(super) fn queue_introduced_peer(
        &self,
        device_id: String,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> Result<()> {
        self.connection_cmd_tx
            .send(NetworkCmd::BeginIntroducedPeer { device_id, ticket })
            .map_err(|error| Error::from(error.into_admission_error()))
    }

    pub(super) fn queue_introduction_signal(&self, signal: EphemeralIngress) -> Result<()> {
        self.connection_cmd_tx
            .send(NetworkCmd::IntroducedSignaling(
                super::command::IntroducedSignaling(signal),
            ))
            .map_err(|error| Error::from(error.into_admission_error()))
    }

    /// One advisory route over the configured sparse infrastructure. Retained
    /// scratch is funded before building the bounded candidate spelling list;
    /// no directory sighting creates a connector or an authorization here.
    pub(super) fn introduction_carrier(
        &self,
        target: &str,
        excluded: Option<&PeerOwnerToken>,
    ) -> Option<PeerOwnerToken> {
        let eligible = |id: &str| {
            let owner = self.peers.owner(id)?;
            let owner = self.peers.capture_current_worker_owner(&owner)?;
            if excluded.is_some_and(|previous| previous.device_id() == id)
                || !self.peers.has_usable_authenticated_current(&owner)
            {
                return None;
            }
            Some(owner)
        };
        if let Some(direct) = eligible(target) {
            return Some(direct);
        }
        let config = self.config.read();
        let (root, hubs): (Option<&String>, &[String]) = match &config.topology {
            TopologyMode::HubTree { root, hubs, .. } => (Some(root), hubs),
            TopologyMode::Hubs { hubs, .. } => (None, hubs),
            TopologyMode::Star { hub } => (Some(hub), &[]),
            _ => return None,
        };
        let count = hubs.len().checked_add(usize::from(root.is_some()))?;
        let mut string_bytes = 0usize;
        let mut max_string = 0usize;
        for id in root.into_iter().chain(hubs.iter()) {
            let length = id.len();
            string_bytes = string_bytes.checked_add(length)?;
            max_string = max_string.max(length);
        }
        let bytes = count
            .checked_add(1)?
            .checked_mul(std::mem::size_of::<String>())?
            .checked_add(string_bytes)?
            .checked_add(max_string)?;
        let claim = ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(bytes).ok()?,
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                u64::try_from(count.checked_add(3)?).ok()?,
            ),
        ])
        .ok()?;
        let _scratch = self.local_resources.acquire(claim).ok()?;
        let mut connected = Vec::with_capacity(count);
        for id in root.into_iter().chain(hubs.iter()) {
            if eligible(id.as_str()).is_some() {
                connected.push(id.clone());
            }
        }
        let selected =
            self.topology_impl
                .read()
                .next_hops(self.identity.public_id(), target, &connected, 1);
        selected.first().and_then(|id| eligible(id))
    }

    pub(super) fn introduction_work(&self) -> Result<ResourceLease> {
        let claim = crate::protocol::hub_introduction::introduction_work_claim(
            crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_WIRE_BYTES,
        )
        .map_err(|_| Error::Network("introduction work shape refused".into()))?;
        Ok(self.local_resources.acquire(claim)?)
    }

    pub(super) async fn send_introduction_body(
        self: &Arc<Self>,
        ticket: super::hub_introduction::IntroductionTicket,
        body: crate::protocol::HubIntroductionBody,
        native: Option<&PeerOwnerToken>,
    ) -> Result<()> {
        let _work = self.introduction_work()?;
        let controller = self
            .hub_introductions
            .as_ref()
            .ok_or_else(|| Error::Network("application introduction disabled".into()))?;
        let (carrier, envelope) = {
            let mut intro = controller.lock();
            let coords = intro
                .coordinates(ticket)
                .ok_or_else(|| Error::Network("introduction ticket is stale".into()))?;
            let local = self.identity.signing_key().verifying_key().to_bytes();
            let reverse = coords.destination == local;
            if !reverse && coords.source != local {
                return Err(Error::Network(
                    "introduction is not locally originated".into(),
                ));
            }
            let (source, destination) = if reverse {
                (coords.destination, coords.source)
            } else {
                (coords.source, coords.destination)
            };
            let sequence = intro
                .next_sequence(ticket)
                .ok_or_else(|| Error::Network("introduction sequence exhausted".into()))?;
            // These coordinates can come from a previously unknown remote
            // Request. Reconstruct only frame-owned backing under _work,
            // never process-global interner occupancy.
            let bounded_id = |key: &[u8; 32]| -> Result<DeviceId> {
                let mut spelling = [0u8; 52];
                data_encoding::BASE32_NOPAD.encode_mut(key, &mut spelling);
                spelling.make_ascii_lowercase();
                DeviceId::from_canonical_str_uninterned(
                    std::str::from_utf8(&spelling)
                        .map_err(|_| Error::Network("introduction identity invalid".into()))?,
                )
                .map_err(|_| Error::Network("introduction identity invalid".into()))
            };
            let envelope = crate::protocol::HubIntroductionEnvelope::new(
                self.mesh_context_id(),
                bounded_id(&source)?,
                bounded_id(&destination)?,
                coords.introduction_id,
                sequence,
                coords.challenge,
                crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_HOPS,
                body,
                self.identity.signing_key(),
            )
            .map_err(|_| Error::Network("introduction encoding refused".into()))?;
            intro
                .observe_outbound(ticket, native, &envelope, std::time::Instant::now())
                .map_err(|_| Error::Network("introduction outbound refused".into()))?;
            let carrier = intro
                .route(ticket, reverse)
                .ok_or_else(|| Error::Network("introduction has no captured route".into()))?;
            (carrier, envelope)
        };
        let result = match envelope.encode_complete() {
            Ok(bytes) => {
                super::send_application_bytes_inner(
                    self,
                    &carrier,
                    Bytes::from(bytes),
                    super::traffic::FrameClass::Control,
                )
                .await
            }
            Err(_) => Err(Error::Network("introduction wire refused".into())),
        };
        if result.is_err() {
            controller.lock().failed(ticket);
        }
        // No reroute/resequence after an ambiguous write. The work lease is
        // held through encoding and the terminal native enqueue result.
        result
    }

    /// Interception is by a retained exact attempt record, not hex spelling.
    /// A matching terminal/refused attempt is still consumed, so it can never
    /// leak into Nostr/mDNS fanout after local introduction cancellation.
    pub(crate) async fn try_send_hub_introduction_signal(
        self: &Arc<Self>,
        outbound: &SignalingOutbound,
    ) -> bool {
        use crate::protocol::HubIntroductionBody;
        let (target, attempt, native) = match outbound {
            SignalingOutbound::Offer {
                device_id,
                attempt,
                owner,
                ..
            }
            | SignalingOutbound::Answer {
                device_id,
                attempt,
                owner,
                ..
            }
            | SignalingOutbound::Candidate {
                device_id,
                attempt,
                owner,
                ..
            } => (device_id.as_str(), attempt.as_str(), owner.as_ref()),
            _ => return false,
        };
        let Some(controller) = self.hub_introductions.as_ref() else {
            return false;
        };
        let Some(ticket) = controller.lock().ticket_for_attempt(target, attempt) else {
            return false;
        };
        let Some(native) = native else {
            controller.lock().failed(ticket);
            return true;
        };
        // The controller retains the original installation before native
        // construction. Only this demand's captured stamped worker may emit
        // its negotiation; a later worker on the same connection is not a
        // refinement of the old demand, even when its attempt text matches.
        if !self
            .introduction_native_owner(target, ticket)
            .is_some_and(|captured| captured.same_exact_owner(native))
            || self
                .peers
                .with_current_transport_worker(native, |_| ())
                .is_none()
        {
            controller.lock().failed(ticket);
            return true;
        }
        let Ok(_translation) = self.introduction_work() else {
            controller.lock().failed(ticket);
            return true;
        };
        let representable = match outbound {
            SignalingOutbound::Offer { sdp, .. } | SignalingOutbound::Answer { sdp, .. } => {
                sdp.len() <= crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_SDP_BYTES
            }
            SignalingOutbound::Candidate { candidate, .. } => {
                candidate.candidate.len()
                    <= crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_CANDIDATE_BYTES
                    && candidate
                        .sdp_mid
                        .as_ref()
                        .is_none_or(|value| value.len() <= 64)
                    && candidate
                        .username_fragment
                        .as_ref()
                        .is_none_or(|value| value.len() <= 64)
            }
            _ => false,
        };
        if !representable {
            controller.lock().failed(ticket);
            return true;
        }
        let body = match outbound {
            SignalingOutbound::Offer { sdp, .. } => HubIntroductionBody::Offer { sdp: sdp.clone() },
            SignalingOutbound::Answer { sdp, .. } => {
                HubIntroductionBody::Answer { sdp: sdp.clone() }
            }
            SignalingOutbound::Candidate { candidate, .. } => {
                hub_introduction_candidate_body(candidate)
            }
            _ => return true,
        };
        let _ = self
            .send_introduction_body(ticket, body, Some(native))
            .await;
        true
    }

    pub(super) fn deliver_introduction_signal(
        self: &Arc<Self>,
        ticket: super::hub_introduction::IntroductionTicket,
        carrier: &PeerOwnerToken,
        frame: &crate::protocol::HubIntroductionEnvelope,
    ) -> bool {
        let Some(controller) = self.hub_introductions.as_ref() else {
            return false;
        };
        let mut attached = self.hub_signaling_carrier.lock();
        if attached.is_none() {
            *attached = super::signaling_ingress::HubSignalingCarrier::new(self);
        }
        let Some(bridge) = attached.as_ref() else {
            return false;
        };
        matches!(
            bridge.admit(
                self,
                &mut controller.lock(),
                ticket,
                carrier,
                frame,
                std::time::Instant::now()
            ),
            super::signaling_ingress::Delivered::Accepted
        )
    }

    /// Deliberately dial one peer and resolve when the link reaches
    /// ACTIVE (or fail with the terminal reason). `sticky` records a
    /// standing dial: the engine re-dials on every announce and holds a
    /// never-expiring reconnect intent — the "support session" contract
    /// on a Silent network. With application introduction enabled, the local
    /// policy bounds the wait as well as any earlier caller cancellation.
    pub async fn connect_peer_wait(&self, device_id: &str, sticky: bool) -> Result<()> {
        match self
            .connect_peer_wait_inner(device_id, sticky, false)
            .await?
        {
            ChannelDemandOutcome::Ready => Ok(()),
            _ => Err(Error::Network(
                "connection demand did not become ready".into(),
            )),
        }
    }

    async fn connect_peer_wait_inner(
        &self,
        device_id: &str,
        sticky: bool,
        settlement_required: bool,
    ) -> Result<ChannelDemandOutcome> {
        let id = next_non_wrapping(&self.next_connect_waiter)
            .ok_or_else(|| Error::Network("connect waiter identity exhausted".into()))?;
        let shared_lease = self
            .local_resources
            .acquire(ConnectWaitShared::claim(device_id)?)?;
        let shared = FundedArc::new(
            ConnectWaitShared::new(id, device_id.to_string()),
            shared_lease,
        )
        .expect("an admitted connect waiter allocation is never speculative");
        // Declare the caller guard before the receiver so cancellation drops
        // the receiver first, then the final shared funding handle. The
        // registration takes the other strong handle below.
        let mut cancellation = ConnectWaitCancellation {
            state: self,
            shared,
            armed: false,
        };
        let (reply, mut rx) = oneshot::channel();
        self.request_connect_peer(
            device_id.to_string(),
            sticky,
            Some(ConnectWaiterRegistration {
                reply: Mutex::new(Some(reply)),
                shared: cancellation.shared.clone(),
            }),
        )
        .map_err(|error| error.into_admission_error())?;
        cancellation.armed = true;
        let introduction_timeout = self
            .config
            .read()
            .introduction
            .map(|policy| std::time::Duration::from_millis(policy.attempt_timeout_ms));
        let received = if let Some(timeout) = introduction_timeout {
            match tokio::time::timeout(timeout, &mut rx).await {
                Ok(received) => received,
                Err(_) => {
                    let binding = *cancellation.shared.introduction.lock();
                    if !settlement_required || binding.is_none() {
                        return Err(Error::Network(
                            "application connection demand expired".into(),
                        ));
                    }
                    let binding = binding.expect("bound settlement caller was checked");
                    // A command may have waited for the actor before binding.
                    // Never expire that shared ticket at this caller's earlier
                    // timeout: retain its original, unrenewed deadline.
                    tokio::select! {
                        received = &mut rx => received,
                        _ = tokio::time::sleep_until(tokio::time::Instant::from_std(binding.deadline)) => {
                            self.connection_cmd_tx.send(NetworkCmd::SettleIntroductionWait(
                                super::command::IntroductionWaitTransfer {
                                    shared: cancellation.shared.clone(),
                                },
                            )).map_err(|error| error.into_admission_error())?;
                            rx.await
                        }
                    }
                }
            }
        } else {
            rx.await
        };
        let result =
            received.map_err(|_| Error::Network("engine dropped the connect wait".into()))?;
        cancellation.armed = false;
        if result.is_ok() {
            return Ok(ChannelDemandOutcome::Ready);
        }
        let outcome = *cancellation.shared.outcome.lock();
        match outcome {
            ChannelDemandOutcome::NoOwnedAttemptRefused
            | ChannelDemandOutcome::FailedSettlementJoined => Ok(outcome),
            _ => result.map(|()| ChannelDemandOutcome::Ready),
        }
    }

    /// Retain a frame for acknowledged delivery to `peer` — see
    /// [`NetworkCmd::SendChannelReliable`] for the contract. Resolves on the
    /// peer's cumulative acknowledgement; errs on refusal at submission, or when
    /// the session retaining it ends before the peer acknowledges.
    pub async fn send_channel_reliable(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        if self.application_peer_needs_demand(peer) {
            self.connect_peer_wait(peer, false).await?;
        }
        let (reply, rx) = oneshot::channel();
        self.cmd_tx
            .send(NetworkCmd::SendChannelReliable {
                peer: peer.to_string(),
                channel: channel.to_string(),
                payload,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        rx.await
            .map_err(|_| Error::Network("engine dropped the reliable send".into()))?
    }

    /// Point-in-time traffic accounting for this network, with the
    /// acked-delivery backlog folded in — the number an operator (or a
    /// topology experiment) compares across configurations.
    pub fn traffic_snapshot(&self) -> super::traffic::TrafficSnapshot {
        let mut snap = self.traffic.snapshot();
        snap.reliable_pending = self.peers.reliable_pending_total() as u64;
        snap
    }

    /// Whether `device_id` has a standing dial (config pin or runtime
    /// `connect_peer(…, sticky)`).
    pub fn is_sticky(&self, device_id: &str) -> bool {
        self.sticky_peers.lock().contains(device_id)
    }

    /// Record a standing dial for `device_id`, mirrored into the live
    /// config's `pinned_peers` so a config read-back (and the daemon's
    /// persistence of it) carries the pin across restarts.
    pub fn add_sticky(&self, device_id: &str) {
        self.sticky_peers.lock().insert(device_id.to_string());
        let mut cfg = self.config.write();
        if !cfg.pinned_peers.iter().any(|p| p == device_id) {
            cfg.pinned_peers.push(device_id.to_string());
        }
    }

    /// Drop a standing dial (and its never-expiring intent), e.g. when
    /// the app "forgets" the peer.
    pub fn remove_sticky(&self, device_id: &str) {
        self.sticky_peers.lock().remove(device_id);
        self.config.write().pinned_peers.retain(|p| p != device_id);
        self.reconnect_intents.lock().remove(device_id);
    }

    /// Park a waiter to be resolved when `device_id` reaches ACTIVE. False
    /// means cancellation or funding/capacity refused before registration;
    /// an attached request must not proceed to create native demand then.
    pub(crate) fn register_connect_waiter(
        &self,
        device_id: &str,
        waiter: ConnectWaiterRegistration,
    ) -> bool {
        let limit = self
            .config
            .read()
            .introduction
            .map(|policy| policy.max_waiters_per_target);
        let mut waiters = self.connect_waiters.lock();
        if waiter.shared.cancelled.load(Ordering::Acquire) {
            return false;
        }
        if limit.is_some_and(|limit| {
            waiters.get(device_id).is_some_and(|bucket| {
                u64::try_from(bucket.waiters.len()).map_or(true, |count| count >= limit)
            })
        }) {
            waiter.finish(Err(Error::Network(
                "application connection waiter capacity exhausted".into(),
            )));
            return false;
        }
        let queue_node = match self.local_resources.acquire(
            LeasedQueue::<ConnectWaiterRegistration>::entry_claim()
                .expect("connect waiter queue entry claim is representable"),
        ) {
            Ok(lease) => lease,
            Err(error) => {
                waiter.finish(Err(Error::ResourceUnavailable(error)));
                return false;
            }
        };
        let fresh_bucket = if waiters.contains_key(device_id) {
            None
        } else {
            let name_bytes = u64::try_from(device_id.len()).map_err(|_| ()).ok();
            let name_claim = name_bytes.and_then(|bytes| {
                ResourceClaim::try_from_entries([
                    (ResourceClass::AccountedMemoryBytes, bytes),
                    (
                        ResourceClass::OpaqueDependencyResidual,
                        u64::from(!device_id.is_empty()),
                    ),
                ])
                .ok()
            });
            let Some(name_claim) = name_claim else {
                waiter.finish(Err(Error::Network(
                    "connect waiter peer identity is not representable".into(),
                )));
                return false;
            };
            let name_lease = match self.local_resources.acquire(name_claim) {
                Ok(lease) => lease,
                Err(error) => {
                    waiter.finish(Err(Error::ResourceUnavailable(error)));
                    return false;
                }
            };
            let node_claim = LeasedMap::<String, ConnectWaiterBucket>::entry_claim()
                .expect("connect waiter map entry claim is representable");
            let node = match self.local_resources.acquire(node_claim) {
                Ok(lease) => lease,
                Err(error) => {
                    waiter.finish(Err(Error::ResourceUnavailable(error)));
                    return false;
                }
            };
            Some((name_lease, node))
        };
        // Cancellation may race the provider acquisitions above. Re-check
        // while still holding the registry lock; if cancellation wins first,
        // it cannot be followed by an insertion, and if registration wins,
        // the cancellation path removes the entry after this lock is freed.
        if waiter.shared.cancelled.load(Ordering::Acquire) {
            return false;
        }
        if let Some((name_lease, node)) = fresh_bucket {
            waiters
                .insert(
                    device_id.to_string(),
                    ConnectWaiterBucket {
                        waiters: LeasedQueue::new(),
                        _name: name_lease,
                    },
                    node,
                )
                .expect("connect waiter bucket absence was checked under its lock");
        }
        waiters
            .get_mut(device_id)
            .expect("connect waiter bucket was installed before its queue entry")
            .waiters
            .push(waiter, queue_node);
        #[cfg(test)]
        self.connect_waiter_registered.notify_waiters();
        true
    }

    fn cancel_connect_waiter(&self, device_id: &str, id: u64) {
        let mut waiters = self.connect_waiters.lock();
        if let Some(bucket) = waiters.get_mut(device_id) {
            bucket.waiters.retain(|waiter| waiter.shared.id != id);
            if bucket.waiters.is_empty() {
                waiters.remove(device_id);
            }
        }
    }

    /// Bind registrations before the Request can leave the local actor. A
    /// previously bound caller is never rebound to a successor ticket.
    pub(super) fn bind_introduction_waiters(
        &self,
        device_id: &str,
        ticket: super::hub_introduction::IntroductionTicket,
    ) -> Result<()> {
        use super::hub_introduction::IntroductionLifetime;
        let deadline = {
            let root = self
                .hub_introductions
                .as_ref()
                .ok_or_else(|| Error::Network("introduction root is absent".into()))?;
            let root = root.lock();
            let coordinates = root
                .coordinates(ticket)
                .ok_or_else(|| Error::Network("introduction ticket is not current".into()))?;
            let local = DeviceId::canonical_key_bytes(self.identity.public_id()).ok();
            let target = DeviceId::canonical_key_bytes(device_id).ok();
            if !((local == Some(coordinates.source) && target == Some(coordinates.destination))
                || (local == Some(coordinates.destination) && target == Some(coordinates.source)))
            {
                return Err(Error::Network(
                    "waiter does not name this introduction endpoint".into(),
                ));
            }
            match root.lifetime(ticket, std::time::Instant::now()) {
                IntroductionLifetime::Live { deadline } => deadline,
                _ => {
                    return Err(Error::Network(
                        "introduction is not live before waiter binding".into(),
                    ))
                }
            }
        };
        if let Some(bucket) = self.connect_waiters.lock().get_mut(device_id) {
            for waiter in bucket.waiters.iter_mut() {
                let mut binding = waiter.shared.introduction.lock();
                if binding.is_none() && !waiter.shared.cancelled.load(Ordering::Acquire) {
                    *binding = Some(IntroductionWaitBinding { ticket, deadline });
                }
            }
        }
        Ok(())
    }

    pub(super) fn resolve_introduction_waiters(
        &self,
        device_id: &str,
        ticket: super::hub_introduction::IntroductionTicket,
        clean: bool,
    ) {
        self.resolve_bound_connect_waiters(
            device_id,
            ticket,
            if clean {
                ChannelDemandOutcome::FailedSettlementJoined
            } else {
                ChannelDemandOutcome::Unsettled
            },
        );
    }

    fn resolve_bound_connect_waiters(
        &self,
        device_id: &str,
        ticket: super::hub_introduction::IntroductionTicket,
        outcome: ChannelDemandOutcome,
    ) {
        let mut waiters = self.connect_waiters.lock();
        if let Some(bucket) = waiters.get_mut(device_id) {
            for waiter in bucket.waiters.iter_mut() {
                if waiter
                    .shared
                    .introduction
                    .lock()
                    .as_ref()
                    .is_some_and(|binding| binding.ticket == ticket)
                {
                    *waiter.shared.outcome.lock() = outcome;
                    waiter.finish(if outcome == ChannelDemandOutcome::Ready {
                        Ok(())
                    } else {
                        Err(Error::Network(
                            "exact introduction terminal settlement".into(),
                        ))
                    });
                }
            }
            bucket
                .waiters
                .retain(|waiter| waiter.reply.lock().is_some());
            if bucket.waiters.is_empty() {
                waiters.remove(device_id);
            }
        }
    }

    /// Invoked inside the caller's already-held exact authenticated registry
    /// fence. This hook performs no registry lookup or admission of its own.
    pub(super) fn resolve_authenticated_connect_waiters(&self, owner: &PeerOwnerToken) {
        let ticket = self.demand_links.as_ref().and_then(|pool| {
            let key = DeviceId::canonical_key_bytes(owner.device_id()).ok()?;
            let pool = pool.lock();
            pool.links
                .get(&key)
                .filter(|link| same_demand_owner(&link.owner, owner) && link.detached.is_none())
                .map(|link| link.introduction)
        });
        if let Some(ticket) = ticket {
            self.resolve_bound_connect_waiters(
                owner.device_id(),
                ticket,
                ChannelDemandOutcome::Ready,
            );
        }
        self.resolve_connect_waiters(owner.device_id(), None);
    }

    #[cfg(test)]
    pub(super) fn connect_waiter_count_for_test(&self, device_id: &str) -> usize {
        self.connect_waiters
            .lock()
            .get(device_id)
            .map_or(0, |bucket| bucket.waiters.len())
    }

    #[cfg(test)]
    pub(super) async fn wait_for_connect_waiter_registration_for_test(&self) {
        loop {
            let notified = self.connect_waiter_registered.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self
                .connect_waiters
                .lock()
                .any_value(|bucket| !bucket.waiters.is_empty())
            {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(super) fn connect_waiter_retained_claim_for_test(device_id: &str) -> ResourceClaim {
        let name_bytes =
            u64::try_from(device_id.len()).expect("test connect waiter identity fits in u64");
        let name_claim = ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, name_bytes),
            (
                ResourceClass::OpaqueDependencyResidual,
                u64::from(!device_id.is_empty()),
            ),
        ])
        .expect("test connect waiter name claim is representable");
        [
            ConnectWaitShared::claim(device_id)
                .expect("test connect waiter shared claim is representable"),
            name_claim,
            LeasedMap::<String, ConnectWaiterBucket>::entry_claim()
                .expect("test connect waiter map claim is representable"),
            LeasedQueue::<ConnectWaiterRegistration>::entry_claim()
                .expect("test connect waiter queue claim is representable"),
        ]
        .into_iter()
        .try_fold(ResourceClaim::ZERO, |total, claim| {
            total.checked_add(
                crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
                    .expect("test connect waiter reservation charge is representable"),
            )
        })
        .expect("test connect waiter retained claim is representable")
    }

    #[cfg(test)]
    pub(super) fn connect_waiter_shared_claim_for_test(device_id: &str) -> ResourceClaim {
        crate::resource::FiniteResourceProvider::reservation_charge_for_test(
            ConnectWaitShared::claim(device_id)
                .expect("test connect waiter shared claim is representable"),
        )
        .expect("test connect waiter shared reservation is representable")
    }

    #[cfg(test)]
    pub(super) fn notify_connect_waiter_terminal_for_test(&self) {
        self.connect_waiter_terminal_seen
            .store(true, Ordering::Release);
        self.connect_waiter_terminal.notify_waiters();
    }

    #[cfg(test)]
    pub(super) async fn wait_for_connect_waiter_terminal_for_test(&self) {
        loop {
            let notified = self.connect_waiter_terminal.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.connect_waiter_terminal_seen.load(Ordering::Acquire) {
                return;
            }
            notified.await;
        }
    }

    #[cfg(test)]
    pub(super) fn connect_waiter_registration_for_test<'a>(
        &'a self,
        device_id: &str,
        id: u64,
        reply: oneshot::Sender<Result<()>>,
    ) -> (ConnectWaiterRegistration, ConnectWaitCancellation<'a>) {
        let shared_lease = self
            .local_resources
            .acquire(
                ConnectWaitShared::claim(device_id)
                    .expect("test connect waiter identity is representable"),
            )
            .expect("test connect waiter shared state is funded");
        let shared = FundedArc::new(
            ConnectWaitShared::new(id, device_id.to_string()),
            shared_lease,
        )
        .expect("an admitted test waiter allocation is never speculative");
        let registration = ConnectWaiterRegistration {
            reply: Mutex::new(Some(reply)),
            shared: shared.clone(),
        };
        let cancellation = ConnectWaitCancellation {
            state: self,
            shared,
            armed: true,
        };
        (registration, cancellation)
    }

    /// Legacy ordinary-connect completion applies only to unbound waiters.
    /// An introduction needs its exact ticket and terminal ownership proof.
    pub(crate) fn resolve_connect_waiters(&self, device_id: &str, error: Option<&str>) {
        let mut waiters = self.connect_waiters.lock();
        let Some(bucket) = waiters.get_mut(device_id) else {
            return;
        };
        for waiter in bucket.waiters.iter_mut() {
            if waiter.shared.introduction.lock().is_some() {
                continue;
            }
            let result = match error {
                None => Ok(()),
                Some(e) => Err(Error::Network(format!("connect {device_id}: {e}"))),
            };
            waiter.finish(result);
        }
        bucket
            .waiters
            .retain(|waiter| waiter.reply.lock().is_some());
        if bucket.waiters.is_empty() {
            waiters.remove(device_id);
        }
    }

    /// True when this network uses local `Silent` connection policy.
    pub fn is_silent(&self) -> bool {
        matches!(self.config.read().kind, crate::config::NetworkKind::Silent)
    }
}

#[cfg(all(test, feature = "transport-lab"))]
mod introduction_settlement_controls {
    use super::super::hub_introduction::{HubIntroduction, IntroductionLifetime};
    use super::*;
    use crate::resource::FiniteResourceProvider;

    fn policy() -> crate::config::HubIntroductionPolicyConfig {
        crate::config::HubIntroductionPolicyConfig {
            max_records: 2,
            max_waiters_per_target: 2,
            max_signaling_bytes: 65_536,
            max_candidates_per_attempt: 2,
            attempt_timeout_ms: 10_000,
            terminal_retention_ms: 1_000,
            max_transient_links: 2,
            idle_timeout_ms: 1_000,
            max_maintenance_per_tick: 2,
        }
    }

    /// Explicit simultaneously retained owners: the two bounded controller
    /// and demand entries, one external wire builder plus its separately
    /// admitted verification, and one two-caller bucket.
    /// Each raw acquisition is normalized separately; this is planning only.
    fn retained_plan(target: &str) -> ResourceClaim {
        let policy = policy();
        let charge = |raw| FiniteResourceProvider::reservation_planning_charge(raw).unwrap();
        let bound = crate::protocol::hub_introduction::HUB_INTRODUCTION_MAX_WIRE_BYTES;
        let controller = policy
            .planned_records_claim(
                HubIntroduction::root_claim().unwrap(),
                HubIntroduction::entry_claim().unwrap(),
            )
            .unwrap();
        let links = policy
            .planned_demand_links_claim(
                DemandLinkPool::root_claim().unwrap(),
                DemandLinkPool::entry_claim().unwrap(),
            )
            .unwrap();
        [
            controller,
            links,
            charge(crate::protocol::hub_introduction::introduction_work_claim(bound).unwrap()),
            charge(HubIntroduction::frame_work_claim(bound).unwrap()),
            NetworkState::connect_waiter_retained_claim_for_test(target),
            charge(ConnectWaitShared::claim(target).unwrap()),
            charge(LeasedQueue::<ConnectWaiterRegistration>::entry_claim().unwrap()),
        ]
        .into_iter()
        .try_fold(ResourceClaim::ZERO, |sum, next| sum.checked_add(next))
        .unwrap()
    }

    const AUTH_LOCAL_BINDING: &str = "intro-local-fp";
    const AUTH_REMOTE_BINDING: &str = "intro-remote-fp";

    /// Test-only local exchange ledger, independent of controller wire work.
    /// Context/record strings and the task Arc stay charged through teardown;
    /// scratch is a conservative simultaneous envelope of the three sequential
    /// transcript builds and their bounded encoding/verification temporaries.
    /// No second native handoff, identity backing, or inline demand capability
    /// is charged here. The capability Box below is the actual temporary
    /// PeerProofAcceptance box, not the eventual inline record storage.
    fn authenticated_fixture_claim() -> ResourceClaim {
        let ids = 3usize * 52; // canonical base32 mesh + two raw Device IDs
        let fields = [
            52usize,
            "ed25519-dtls-v1".len(),
            "initiator".len(),
            52,
            52,
            52,
            52,
            AUTH_LOCAL_BINDING.len(),
            AUTH_REMOTE_BINDING.len(),
        ];
        let transcript = fields.into_iter().fold(
            crate::endpoint_auth::ENDPOINT_AUTH_DOMAIN_TAG.len(),
            |sum, len| sum + len + len.to_string().len() + 1,
        );
        let retained = std::mem::size_of::<crate::endpoint_auth::EndpointAuthTask>()
            + 2 * std::mem::size_of::<usize>() // Arc strong/weak counters
            + ids * 2 + AUTH_LOCAL_BINDING.len() + AUTH_REMOTE_BINDING.len()
            + 2 * 52 + 103 + 2 * 52; // local/peer draw, cached proof, two digests
        let scratch = std::mem::size_of::<crate::endpoint_auth::AuthenticatedChannelCapability>()
            + 2 * 52 // uppercase/lowercase mesh rendering before context copies it
            + 4 * 52 + 32 // peer draw/canonical decode and verification clones
            + 4 * 103 + 64 + 52 + 32 // proof copies, case conversion, signature/key decode
            + 52 // digest uppercase encoding before lowercase output
            + 3 * transcript + 3; // Vec old+new growth bound and decimal prefix
                                  // At most one allocation per extend/push plus one decimal string per
                                  // field: 1 + 9*4 per transcript, three sequential builds. Remaining
                                  // named mesh/binding/context/task/draw/parser/clone/sign/verify/record/
                                  // digest/box allocations: 2+2+3+1+2+2+5+1+3+2+6+3+4+1 = 37.
                                  // Two draws, two signatures, verification/key validation and one
                                  // digest add seven opaque operations; no expanded-key erasure claim.
        ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                (retained + scratch) as u64,
            ),
            (
                ResourceClass::ParsingOrCpuWork,
                (3 * transcript + retained + scratch) as u64,
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                3 * (1 + 9 * 4) + 37 + 7,
            ),
        ])
        .unwrap()
    }

    fn configure_carrier_topology(state: &NetworkState, hub: &str) {
        let mode = crate::config::TopologyMode::Star {
            hub: hub.to_owned(),
        };
        *state.topology_impl.write() = crate::topology::from_mode(&mode);
        state.config.write().topology = mode;
    }

    fn admit_carrier(state: &NetworkState, carrier: &PeerOwnerToken) -> Result<()> {
        state
            .peers
            .with_admitted_current(
                carrier,
                state.session_broker.as_ref(),
                &state.mesh_context_id().to_string(),
                |_| (),
            )
            .ok_or_else(|| Error::Network("actual carrier promotion/admission refused".into()))
    }

    struct PumpTerminalGate {
        entered: AtomicBool,
        opened: AtomicBool,
        changed: tokio::sync::Notify,
    }

    impl PumpTerminalGate {
        fn claim() -> ResourceClaim {
            fn tail_bytes<F: std::future::Future<Output = ()>>(
                _: impl FnOnce(FundedArc<PumpTerminalGate>) -> F,
            ) -> usize {
                std::mem::size_of::<F>()
            }
            let bytes = std::mem::size_of::<Self>()
                .checked_add(tail_bytes(hold_pump_terminal))
                .unwrap();
            ResourceClaim::try_from_entries([
                // Gate backing plus the actual additional terminal future
                // retained inside the existing spawned receiver task.
                (ResourceClass::AccountedMemoryBytes, bytes as u64),
                // FundedArc's dependency-private control/value metadata.
                (ResourceClass::OpaqueDependencyResidual, 1),
            ])
            .unwrap()
        }

        async fn hold(&self) {
            self.entered.store(true, Ordering::Release);
            self.changed.notify_waiters();
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.opened.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        async fn wait_entered(&self) {
            loop {
                let notified = self.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if self.entered.load(Ordering::Acquire) {
                    return;
                }
                notified.await;
            }
        }

        fn open(&self) {
            self.opened.store(true, Ordering::Release);
            self.changed.notify_waiters();
        }
    }

    async fn hold_pump_terminal(gate: FundedArc<PumpTerminalGate>) {
        gate.hold().await;
    }

    #[tokio::test]
    #[ignore = "opens an actual local carrier; run in the isolated native harness"]
    async fn introduction_two_waiters_one_cancel_preserves_ticket_deadline_and_sticky_demand() {
        let target_identity = crate::identity::Identity::ephemeral();
        let target = target_identity.public_id();
        let (state, signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-two-waiters",
                None,
                2,
                Some(retained_plan(target)),
                None,
                Some(policy()),
            );
        let carrier_identity = crate::identity::Identity::ephemeral();
        configure_carrier_topology(&state, carrier_identity.public_id());
        let fixture =
            super::super::insert_promoted_peer(&state, carrier_identity.public_id()).await;
        let worker = fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(carrier_identity.public_id())
            .unwrap()
            .for_worker(Arc::clone(&worker));
        let (reply0, mut received0) = oneshot::channel();
        let (reply1, mut received1) = oneshot::channel();
        let (waiter0, cancel0) = state.connect_waiter_registration_for_test(target, 70, reply0);
        let (waiter1, mut cancel1) = state.connect_waiter_registration_for_test(target, 71, reply1);
        let shared = waiter1.shared.clone();
        let observations = (|| -> Result<_> {
            admit_carrier(&state, &carrier)?;
            let remote = DeviceId::from_canonical_str(target)
                .map_err(|_| Error::Network("valid fixture target required".into()))?;
            let root = state.hub_introductions.as_ref().unwrap();
            let admitted = root
                .lock()
                .begin_demand(&remote, &carrier, std::time::Instant::now())
                .map_err(|_| Error::Network("real controller demand refused".into()))?;
            if !state.register_connect_waiter(target, waiter0)
                || !state.register_connect_waiter(target, waiter1)
            {
                return Err(Error::Network(
                    "two genuine waiters must be admitted".into(),
                ));
            }
            state.bind_introduction_waiters(target, admitted.ticket)?;
            let original = root
                .lock()
                .lifetime(admitted.ticket, std::time::Instant::now());
            let coalesced = root
                .lock()
                .begin_demand(&remote, &carrier, std::time::Instant::now())
                .map_err(|_| Error::Network("coalesced demand refused".into()))?;
            state.bind_introduction_waiters(target, coalesced.ticket)?;
            state.add_sticky(target);
            Ok((
                admitted.ticket,
                original,
                coalesced.coalesced,
                coalesced.ticket == admitted.ticket,
            ))
        })();
        let first_was_waiting = matches!(
            received0.try_recv(),
            Err(oneshot::error::TryRecvError::Empty)
        );
        drop(received0);
        drop(cancel0);
        let one_left = state.connect_waiter_count_for_test(target) == 1;
        let canceled_only = first_was_waiting
            && matches!(
                received1.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            );
        let followup: Result<_> = async {
            let (ticket, original, _, _) = observations
                .as_ref()
                .map_err(|_| Error::Network("initial waiter setup refused".into()))?;
            let root = state.hub_introductions.as_ref().unwrap();
            let unchanged = root.lock().lifetime(*ticket, std::time::Instant::now()) == *original;
            root.lock().failed(*ticket);
            let remote = DeviceId::from_canonical_str(target)
                .map_err(|_| Error::Network("valid successor target required".into()))?;
            let successor = root
                .lock()
                .begin_demand(&remote, &carrier, std::time::Instant::now())
                .map_err(|_| Error::Network("successor demand setup refused".into()))?;
            let (reply2, mut received2) = oneshot::channel();
            let (waiter2, mut cancel2) =
                state.connect_waiter_registration_for_test(target, 72, reply2);
            let shared2 = waiter2.shared.clone();
            let registered2 = state.register_connect_waiter(target, waiter2);
            let bound2 = state
                .bind_introduction_waiters(target, successor.ticket)
                .is_ok();
            let successor_lifetime = root
                .lock()
                .lifetime(successor.ticket, std::time::Instant::now());
            // Legacy label cleanup and the OLD terminal must not resolve the
            // newly bound caller, nor rebind the earlier surviving caller.
            state.resolve_connect_waiters(target, Some("stale label terminal"));
            state
                .settle_introduction_wait(super::super::command::IntroductionWaitTransfer {
                    shared: shared.clone(),
                })
                .await;
            let ended = matches!(received1.try_recv(), Ok(Err(_)))
                && *shared.outcome.lock() == ChannelDemandOutcome::NoOwnedAttemptRefused;
            let preserved = registered2
                && bound2
                && successor.ticket != *ticket
                && shared
                    .introduction
                    .lock()
                    .is_some_and(|binding| binding.ticket == *ticket)
                && shared2
                    .introduction
                    .lock()
                    .is_some_and(|binding| binding.ticket == successor.ticket)
                && matches!(
                    received2.try_recv(),
                    Err(oneshot::error::TryRecvError::Empty)
                )
                && root
                    .lock()
                    .lifetime(successor.ticket, std::time::Instant::now())
                    == successor_lifetime;
            root.lock().failed(successor.ticket);
            state
                .settle_introduction_wait(super::super::command::IntroductionWaitTransfer {
                    shared: shared2.clone(),
                })
                .await;
            let successor_ended = matches!(received2.try_recv(), Ok(Err(_)));
            cancel2.armed = false;
            drop((received2, cancel2, shared2));
            cancel1.armed = false;
            Ok((
                unchanged,
                ended,
                state.is_sticky(target),
                preserved && successor_ended,
            ))
        }
        .await;
        drop((received1, cancel1, shared));
        let close = worker.retire_and_close().await;
        state.shutdown().await;
        drop((carrier, worker, fixture, commands, signals, state));
        let (ticket, original, coalesced, same_ticket) =
            observations.expect("fixture body admitted");
        let (same_deadline, terminal_outcome, sticky_survives, stale_preserved) =
            followup.expect("successor waiter body admitted");
        let _ = ticket;
        assert!(matches!(original, IntroductionLifetime::Live { .. }));
        assert!(coalesced && same_ticket && one_left && canceled_only && same_deadline);
        assert!(terminal_outcome && sticky_survives && stale_preserved && close.is_ok());
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
        assert_eq!(provider.in_use(), provider.retained_after_failed_cleanup());
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    fn prepare_native_settlement_fixture(
        state: &Arc<NetworkState>,
        remote: &crate::identity::Identity,
        hub: &crate::identity::Identity,
        carrier: &PeerOwnerToken,
        worker: &Arc<crate::transport::WebRtcConnectorWorker>,
        registration: ConnectWaiterRegistration,
        authenticated: bool,
    ) -> Result<(
        PeerOwnerToken,
        super::super::hub_introduction::IntroductionTicket,
        [u8; 32],
        u64,
    )> {
        use super::super::hub_introduction::IntroductionAction;
        use crate::protocol::{HubIntroductionBody, HubIntroductionEnvelope};
        admit_carrier(state, carrier)?;
        let _wire_work = state.introduction_work()?;
        let local_id = DeviceId::from_canonical_str(state.identity.public_id()).unwrap();
        let remote_id = DeviceId::from_canonical_str(remote.public_id()).unwrap();
        let hub_id = DeviceId::from_canonical_str(hub.public_id()).unwrap();
        let root = state.hub_introductions.as_ref().unwrap();
        let now = std::time::Instant::now();
        let ticket = root
            .lock()
            .begin_demand(&remote_id, carrier, now)
            .map_err(|_| Error::Network("controller demand setup refused".into()))?
            .ticket;
        let coordinates = root.lock().coordinates(ticket).unwrap();
        let request = HubIntroductionEnvelope::new(
            state.mesh_context_id(),
            local_id.clone(),
            remote_id.clone(),
            coordinates.introduction_id,
            0,
            None,
            4,
            HubIntroductionBody::Request {},
            state.identity.signing_key(),
        )
        .map_err(|_| Error::Network("signed request setup refused".into()))?;
        root.lock()
            .observe_outbound(ticket, None, &request, now)
            .map_err(|_| Error::Network("actual request observation refused".into()))?;
        let challenge = crate::protocol::hub_introduction::IntroductionChallenge {
            request_hash: request.request_digest().unwrap(),
            responder_challenge: [0x53; 32],
        };
        drop(request); // one externally retained wire owner, not two
        let mut accept = HubIntroductionEnvelope::new(
            state.mesh_context_id(),
            remote_id.clone(),
            local_id,
            coordinates.introduction_id,
            0,
            Some(challenge),
            4,
            HubIntroductionBody::Accept {},
            remote.signing_key(),
        )
        .map_err(|_| Error::Network("signed Accept setup refused".into()))?;
        accept
            .append_hop(hub_id, hub.signing_key())
            .map_err(|_| Error::Network("actual Hub hop setup refused".into()))?;
        if !matches!(super::super::receive_current_hub_introduction(
            state, root, carrier, &accept, None),
            Some(IntroductionAction::BeginOffer(current)) if current == ticket)
        {
            return Err(Error::Network(
                "real challenge/Accept controller path refused".into(),
            ));
        }
        let backing = state.reserve_introduction_placeholder(remote.public_id())?;
        let peer = Arc::new(super::super::connection::PeerConnection::new_introduction(
            remote.public_id().to_owned(),
            ticket.attempt(),
            backing,
        ));
        if !peer.bind_initial_introduction(ticket) {
            return Err(Error::Network(
                "original full ticket binding refused".into(),
            ));
        }
        let owner = state
            .peers
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .ok_or_else(|| Error::Network("fresh original installation refused".into()))?;
        root.lock()
            .bind_native_owner(ticket, &owner)
            .map_err(|_| Error::Network("original native binding refused".into()))?;
        if state.peers.with_current(&owner, |peer| {
            peer.attach_introduction_worker(Arc::clone(worker), Some(ticket))
        }) != Some(true)
        {
            return Err(Error::Network("original W0 attach refused".into()));
        }
        let owner = owner.for_worker(Arc::clone(worker));
        state
            .reserve_demand_link()?
            .bind(owner.clone(), ticket, now)?;
        let handoff = match worker.confirm_data_channel_open() {
            crate::transport::DataChannelOpenOwnership::Connected(handoff) => handoff,
            _ => return Err(Error::Network("real connected handoff refused".into())),
        };
        if authenticated {
            // One real handoff, one actual task, and its issued capability.
            // The channel binding and peer proof are generated locally by
            // this fixture: this is NOT a remote/native auth qualification.
            let binding = crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                AUTH_LOCAL_BINDING,
                AUTH_REMOTE_BINDING,
            )
            .ok_or_else(|| Error::Network("fixture binding missing".into()))?;
            let context = crate::endpoint_auth::EndpointAuthContext::new(
                &state.mesh_context_id().base32(),
                state.identity.public_id(),
                remote.public_id(),
                binding,
            )
            .map_err(|_| Error::Network("fixture context refused".into()))?;
            let task = Arc::new(crate::endpoint_auth::EndpointAuthTask::begin(
                context,
                handoff
                    .into_generic()
                    .ok_or_else(|| Error::Network("connected handoff became stale".into()))?,
                crate::endpoint_auth::LocalIdentitySigner::for_identity(Arc::clone(
                    &state.identity,
                )),
            ));
            if !peer.install_endpoint_auth(Arc::clone(&task)) {
                return Err(Error::Network("original auth task install refused".into()));
            }
            let contribution = crate::endpoint_auth::PeerContribution::from_wire(
                crate::endpoint_auth::LocalContribution::generate().as_str(),
            )
            .map_err(|_| Error::Network("fixture contribution refused".into()))?;
            task.accept_peer_hello(contribution.clone())
                .map_err(|_| Error::Network("original task Hello refused".into()))?;
            let proof = crate::endpoint_auth::peer_proof_for_test(
                &task,
                &contribution,
                remote.signing_key(),
            );
            let capability = task
                .accept_peer_proof(&proof)
                .map_err(|_| Error::Network("original task proof refused".into()))?
                .into_promoted()
                .ok_or_else(|| Error::Network("original task did not issue a capability".into()))?;
            if !peer.install_authenticated_channel(&task, capability) {
                return Err(Error::Network(
                    "same task-issued capability install refused".into(),
                ));
            }
            let mut data = peer.state.write();
            data.authenticated = true;
            data.status = super::super::connection::PeerStatus::PendingApproval;
        } else {
            let task = Arc::new(crate::endpoint_auth::task_for_test(
                handoff
                    .into_generic()
                    .ok_or_else(|| Error::Network("connected handoff became stale".into()))?,
            ));
            if !peer.install_endpoint_auth(task) {
                return Err(Error::Network(
                    "pending exact auth task was not installed".into(),
                ));
            }
        }
        if !state.register_connect_waiter(remote.public_id(), registration) {
            return Err(Error::Network("genuine waiter admission refused".into()));
        }
        state.bind_introduction_waiters(remote.public_id(), ticket)?;
        let key = remote_id.as_bytes();
        let generation = state
            .demand_links
            .as_ref()
            .unwrap()
            .lock()
            .links
            .get(&key)
            .unwrap()
            .generation;
        Ok((owner, ticket, key, generation))
    }

    /// A fresh, independently signed transaction, without installing a peer.
    /// The caller must drive BeginIntroducedPeer through the actual actor.
    fn prepare_reuse_ticket(
        state: &Arc<NetworkState>,
        remote: &crate::identity::Identity,
        hub: &crate::identity::Identity,
        carrier: &PeerOwnerToken,
    ) -> Result<super::super::hub_introduction::IntroductionTicket> {
        use super::super::hub_introduction::IntroductionAction;
        use crate::protocol::{HubIntroductionBody, HubIntroductionEnvelope};
        admit_carrier(state, carrier)?;
        let _wire_work = state.introduction_work()?;
        let local = DeviceId::from_canonical_str(state.identity.public_id()).unwrap();
        let remote_id = DeviceId::from_canonical_str(remote.public_id()).unwrap();
        let hub_id = DeviceId::from_canonical_str(hub.public_id()).unwrap();
        let root = state.hub_introductions.as_ref().unwrap();
        let now = std::time::Instant::now();
        let ticket = root
            .lock()
            .begin_demand(&remote_id, carrier, now)
            .map_err(|error| Error::Network(format!("fresh demand setup: {error}")))?
            .ticket;
        let coordinates = root.lock().coordinates(ticket).unwrap();
        let request = HubIntroductionEnvelope::new(
            state.mesh_context_id(),
            local.clone(),
            remote_id.clone(),
            coordinates.introduction_id,
            0,
            None,
            4,
            HubIntroductionBody::Request {},
            state.identity.signing_key(),
        )
        .map_err(|error| Error::Network(format!("fresh signed Request: {error}")))?;
        root.lock()
            .observe_outbound(ticket, None, &request, now)
            .map_err(|error| Error::Network(format!("fresh Request observation: {error}")))?;
        let challenge = crate::protocol::hub_introduction::IntroductionChallenge {
            request_hash: request.request_digest().unwrap(),
            responder_challenge: [0x74; 32],
        };
        drop(request); // same single external wire-owner envelope as W0 setup
        let mut accept = HubIntroductionEnvelope::new(
            state.mesh_context_id(),
            remote_id,
            local,
            coordinates.introduction_id,
            0,
            Some(challenge),
            4,
            HubIntroductionBody::Accept {},
            remote.signing_key(),
        )
        .map_err(|error| Error::Network(format!("fresh signed Accept: {error}")))?;
        accept
            .append_hop(hub_id, hub.signing_key())
            .map_err(|error| Error::Network(format!("fresh signed Hub hop: {error}")))?;
        if !matches!(super::super::receive_current_hub_introduction(
            state, root, carrier, &accept, None),
            Some(IntroductionAction::BeginOffer(current)) if current == ticket)
        {
            return Err(Error::Network(
                "fresh challenge/Accept setup refused".into(),
            ));
        }
        Ok(ticket)
    }

    #[derive(Debug)]
    struct ProtectedReuseObservations {
        sticky: bool,
        pinned: bool,
        registered: bool,
        claimed: bool,
        native_pending: bool,
        native_entered: bool,
        native_custody: bool,
        pump_entered: bool,
        pump_custody: bool,
        terminal_refused: bool,
        old_joined: bool,
        tokens_released: bool,
        old_task_released: bool,
        installation_retained: bool,
        old_truth_cleared: bool,
        ticket_distinct: bool,
        fresh_preflight: bool,
        actor_drained: bool,
        new_worker: bool,
        new_binding: bool,
        new_truth: bool,
        fresh_lifetime: IntroductionLifetime,
    }

    #[tokio::test]
    #[ignore = "protected genuine-capability Deny followed by fresh signed BeginIntroducedPeer; isolated native harness"]
    async fn protected_authenticated_introduction_reuses_retained_installation() {
        let remote = crate::identity::Identity::ephemeral();
        let hub = crate::identity::Identity::ephemeral();
        let charge = |raw| FiniteResourceProvider::reservation_planning_charge(raw).unwrap();
        // Carrier, retained original W0 wrapper, and actual fresh W1. The
        // existing three-connector planner accounts these concrete holders.
        // Two placeholder leases overlap: the retained installation and the
        // newly reserved replacement backing. Each is separately normalized.
        let placeholder =
            PeerRegistry::introduction_placeholder_claim(remote.public_id().len()).unwrap();
        let retained = [
            retained_plan(remote.public_id()),
            charge(PumpTerminalGate::claim()),
            charge(authenticated_fixture_claim()),
            charge(placeholder),
            charge(placeholder),
        ]
        .into_iter()
        .try_fold(ResourceClaim::ZERO, |sum, next| sum.checked_add(next))
        .unwrap();
        let (state, mut signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-protected-reuse",
                None,
                3,
                Some(retained),
                None,
                Some(policy()),
            );
        let auth_work = state
            .local_resources
            .acquire(authenticated_fixture_claim())
            .unwrap();
        let terminal_gate = FundedArc::new(
            PumpTerminalGate {
                entered: AtomicBool::new(false),
                opened: AtomicBool::new(false),
                changed: tokio::sync::Notify::new(),
            },
            state
                .local_resources
                .acquire(PumpTerminalGate::claim())
                .unwrap(),
        )
        .unwrap();
        let fixture = super::super::insert_promoted_peer(&state, hub.public_id()).await;
        configure_carrier_topology(&state, hub.public_id());
        let hub_worker = fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(hub.public_id())
            .unwrap()
            .for_worker(Arc::clone(&hub_worker));
        let runtime = super::super::signaling_ingress::SignalingRuntime::new(
            state.signaling_inbound_tx.clone(),
            state.local_application_resource_scope().unwrap(),
        );
        state.publish_signaling_runtime(&runtime);
        let ingress = super::super::signaling_ingress::SignalingRuntime::attach(
            &runtime,
            super::super::signaling_ingress::SignalingCarrier::Nostr,
        );
        let (reply, mut received) = oneshot::channel();
        let (registration, mut cancellation) =
            state.connect_waiter_registration_for_test(remote.public_id(), 90, reply);
        let shared = registration.shared.clone();
        let mut original = None;
        let mut native_gate = None;
        let mut successor = None;
        let observations = async {
            let (worker, events) = state.transport.open_connector_peer(
                crate::transport::Role::Answerer, &[], &[], state.peer_connection_resource_scope(),
            ).await.map_err(|error| Error::Network(format!("W0 native setup: {error}")))?;
            let worker = Arc::new(worker);
            original = Some(Arc::clone(&worker));
            native_gate = Some(worker.install_native_close_gate_for_test());
            let gate = native_gate.as_ref().unwrap();
            let (owner, ticket, key, _) = prepare_native_settlement_fixture(
                &state, &remote, &hub, &carrier, &worker, registration, true,
            )?;
            let task = owner.connection().endpoint_auth_task()
                .ok_or_else(|| Error::Network("genuine task setup missing".into()))?;
            let task_weak = Arc::downgrade(&task);
            drop(task);
            state.add_sticky(remote.public_id());
            let sticky = state.is_sticky(remote.public_id());
            let pinned = state.config.read().pinned_peers.iter().any(|id| id == remote.public_id());
            if !state.begin_peer_event_pump_registration() {
                drop(events);
                return Err(Error::Network("original pump registration setup refused".into()));
            }
            let pump = super::super::spawn_peer_event_pump_with_terminal(
                Arc::clone(&state), remote.public_id().to_owned(), Arc::clone(&worker),
                events, Some(owner.clone()), hold_pump_terminal(terminal_gate.clone()),
            );
            if let Err(pump) = state.finish_introduced_pump_registration(&owner, pump) {
                gate.open();
                terminal_gate.open();
                let _ = worker.retire_and_close().await;
                state.finish_peer_event_pump_registration(pump).await;
                return Err(Error::Network("exact pump transfer setup refused".into()));
            }
            let registered = state.demand_links.as_ref().unwrap().lock().links.get(&key)
                .is_some_and(|link| link.pump_registered && link.pump.is_some());
            let attempt = ticket.attempt();
            let candidate = myownmesh_signaling::SignalingMessage::Candidate {
                peer_id: remote.public_id().to_owned(), offer_id: attempt.clone(),
                candidate: "candidate:reuse 1 udp 2113937151 192.0.2.1 5000 typ host".into(),
                sdp_mid: Some("0".into()), sdp_mline_index: Some(0), username_fragment: None,
            };
            if !ingress.deliver(ingress.directed(remote.public_id().to_owned(), candidate)) {
                return Err(Error::Network("real Candidate ingress setup refused".into()));
            }
            let token = signals.try_recv().and_then(|delivery| delivery.value().dedup_token())
                .ok_or_else(|| Error::Network("real Candidate token setup missing".into()))?;
            let weak = token.weak();
            let retained_token = state.peers.with_current(&owner, |peer| {
                if peer.holds_promoted_session() || peer.attempt() != attempt
                    || !peer.current_worker().is_some_and(|current| Arc::ptr_eq(&current, &worker)) {
                    return false;
                }
                peer.retain_current_dedup(token);
                true
            }) == Some(true) && weak.strong_count() == 1;
            if !retained_token {
                return Err(Error::Network("exact unpromoted token insertion setup refused".into()));
            }
            super::super::handshake::on_deny(
                &state, &owner, crate::protocol::DenyMessage { reason: None },
            ).await;
            let claimed = state.demand_links.as_ref().unwrap().lock().links.get(&key)
                .is_some_and(|link| link.introduction == ticket
                    && link.detached.as_ref().is_some_and(|detached|
                        detached.authenticated_custody_for_test()
                        && detached.terminal == Some(super::super::connection::IntroductionTerminalDisposition::Denied)));
            let receiver = state.take_connection_cmd_rx()
                .ok_or_else(|| Error::Network("actual connection actor receiver missing".into()))?;
            let actor = super::super::supervisor::run_connection_commands(Arc::clone(&state), receiver);
            tokio::pin!(actor);
            let native_pending = futures::poll!(&mut actor).is_pending();
            let native_entered = tokio::time::timeout(
                std::time::Duration::from_secs(10), gate.wait_for_entry(),
            ).await.is_ok();
            let native_custody = weak.strong_count() == 1 && task_weak.strong_count() > 0
                && runtime.remembers_attempt_for_test(&attempt);
            gate.open();
            let pump_entered = tokio::select! {
                _ = &mut actor => false,
                result = tokio::time::timeout(std::time::Duration::from_secs(10), terminal_gate.wait_entered()) => result.is_ok(),
            };
            let native_closed = worker.retire_and_close().await.is_ok();
            let pump_custody = pump_entered && native_closed && weak.strong_count() == 1
                && task_weak.strong_count() > 0
                && state.demand_links.as_ref().unwrap().lock().links.get(&key)
                    .is_some_and(|link| link.detached.is_some() && link.pump_joined.is_none());
            terminal_gate.open();
            if !native_pending || !native_entered || !pump_entered {
                return Err(Error::Network(format!("W0 gate setup failed: pending={native_pending} native={native_entered} pump={pump_entered}")));
            }
            let reply = tokio::select! {
                reply = &mut received => reply,
                _ = &mut actor => return Err(Error::Network("actor ended before Deny completion".into())),
                _ = tokio::time::sleep(std::time::Duration::from_secs(10)) =>
                    return Err(Error::Network("Deny settlement did not resolve its waiter".into())),
            };
            let terminal_refused = matches!(reply, Ok(Err(_)))
                && *shared.outcome.lock() == ChannelDemandOutcome::TerminalRefused;
            let old_joined = !state.demand_links.as_ref().unwrap().lock().links.contains_key(&key)
                && gate.entries() == 1;
            let tokens_released = weak.strong_count() == 0 && !runtime.remembers_attempt_for_test(&attempt);
            let old_task_released = task_weak.strong_count() == 0;
            let mut old_truth_cleared = false;
            let installation_retained = state.peers.with_introduction_installation(&owner, |peer| {
                let empty = !peer.has_current_worker() && !peer.has_authenticated_channel()
                    && peer.endpoint_auth_task().is_none() && !peer.holds_promoted_session();
                let data = peer.state.read();
                old_truth_cleared = !data.authenticated && !data.local_approve_sent
                    && !data.remote_approve_seen && !data.data_channel_open
                    && data.hello_retention.is_none()
                    && data.verification_code_sent.is_none() && data.verification_code_received.is_none()
                    && data.session_started_at.is_none() && data.handshake_started_at.is_none()
                    && empty
                    && matches!(data.status, super::super::connection::PeerStatus::Sighted
                        | super::super::connection::PeerStatus::Offline);
                Some(false)
            });
            let fresh = prepare_reuse_ticket(&state, &remote, &hub, &carrier)?;
            let root = state.hub_introductions.as_ref().unwrap();
            let ticket_distinct = fresh != ticket && fresh.attempt() != attempt;
            // Probe the EXACT pre-adoption claims together after W0 joins.
            // A refusal here is setup/funding failure, never the reuse red.
            {
                let work = state.introduction_work().map_err(|error|
                    Error::Network(format!("fresh work preflight: {error}")))?;
                let slot = state.reserve_demand_link().map_err(|error|
                    Error::Network(format!("fresh demand-slot preflight: {error}")))?;
                let backing = state.reserve_introduction_placeholder(remote.public_id()).map_err(|error|
                    Error::Network(format!("fresh placeholder preflight: {error}")))?;
                let target = DeviceId::from_canonical_str(remote.public_id()).unwrap();
                if !state.peers.routed_origin_policy_admits(&target)
                    || !root.lock().is_current(fresh, std::time::Instant::now()) {
                    return Err(Error::Network("fresh canonical/lifetime preflight refused".into()));
                }
                drop((backing, slot, work));
            }
            state.connection_cmd_tx.send(NetworkCmd::BeginIntroducedPeer {
                device_id: remote.public_id().to_owned(), ticket: fresh,
            }).map_err(|error| Error::Network(format!("fresh Begin command admission: {}", error.into_admission_error())))?;
            state.connection_cmd_tx.close();
            actor.await; // both actual commands finished, not a direct adopt call
            let mut new_worker = false;
            let mut new_truth = false;
            let same_installation = state.peers.with_introduction_installation(&owner, |peer| {
                successor = peer.current_worker();
                new_worker = successor.as_ref().is_some_and(|w1|
                    !Arc::ptr_eq(w1, &worker) && w1.live_connector_incarnation().is_some())
                    && peer.attempt() == fresh.attempt();
                let unauthenticated = !peer.has_authenticated_channel()
                    && peer.endpoint_auth_task().is_none() && !peer.holds_promoted_session();
                let data = peer.state.read();
                new_truth = !data.authenticated && !data.local_approve_sent && !data.remote_approve_seen
                    && !data.data_channel_open && unauthenticated
                    && matches!(data.status, super::super::connection::PeerStatus::Sighted
                        | super::super::connection::PeerStatus::Handshaking);
                Some(false)
            });
            let new_binding = same_installation && state.demand_links.as_ref().unwrap().lock().links.get(&key)
                .is_some_and(|link| link.introduction == fresh && link.pump_registered
                    && link.owner.worker().zip(successor.as_ref())
                        .is_some_and(|(bound, w1)| Arc::ptr_eq(bound, w1)));
            Ok(ProtectedReuseObservations {
                sticky: sticky && state.is_sticky(remote.public_id()),
                pinned: pinned && state.config.read().pinned_peers.iter().any(|id| id == remote.public_id()),
                registered, claimed, native_pending, native_entered, native_custody,
                pump_entered, pump_custody, terminal_refused, old_joined, tokens_released,
                old_task_released, installation_retained, old_truth_cleared, ticket_distinct,
                fresh_preflight: true, actor_drained: true, new_worker, new_binding, new_truth,
                fresh_lifetime: root.lock().lifetime(fresh, std::time::Instant::now()),
            })
        }.await;
        // No failed observation can bypass original or fresh native ownership.
        // The actor future above has ended/dropped before shutdown resumes its
        // exact record-owned joins. Keep all event receivers and roots alive.
        if let Some(gate) = native_gate.as_ref() {
            gate.open();
        }
        terminal_gate.open();
        state.connection_cmd_tx.close();
        let original_close = if let Some(worker) = original.as_ref() {
            worker.retire_and_close().await.is_ok()
        } else {
            true
        };
        let successor_close = if let Some(worker) = successor.as_ref() {
            worker.retire_and_close().await.is_ok()
        } else {
            true
        };
        state.shutdown().await;
        let carrier_close = hub_worker.retire_and_close().await;
        cancellation.armed = false;
        drop((
            received,
            cancellation,
            shared,
            ingress,
            runtime,
            commands,
            signals,
            carrier,
            hub_worker,
            fixture,
            original,
            successor,
            native_gate,
            terminal_gate,
        ));
        drop(state);
        drop(auth_work);
        assert!(original_close && successor_close && carrier_close.is_ok(),
            "owned cleanup: original={original_close} successor={successor_close} carrier={carrier_close:?}; setup_error={:?}", observations.as_ref().err());
        assert_eq!(
            provider.active_reservations(),
            0,
            "setup_error={:?}",
            observations.as_ref().err()
        );
        assert_eq!(
            provider.active_scopes(),
            0,
            "setup_error={:?}",
            observations.as_ref().err()
        );
        assert_eq!(
            provider.in_use(),
            ResourceClaim::ZERO,
            "setup_error={:?}",
            observations.as_ref().err()
        );
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO,
            "setup_error={:?}",
            observations.as_ref().err()
        );
        let observed = observations
            .expect("protected reuse setup/actor/funding failed, not the target reuse assertion");
        assert!(
            observed.sticky
                && observed.pinned
                && observed.registered
                && observed.claimed
                && observed.native_pending
                && observed.native_entered
                && observed.native_custody
                && observed.pump_entered
                && observed.pump_custody
                && observed.terminal_refused
                && observed.old_joined
                && observed.tokens_released
                && observed.old_task_released
                && observed.installation_retained
                && observed.ticket_distinct
                && observed.fresh_preflight
                && observed.actor_drained,
            "protected W0/fresh transaction prerequisites: {observed:?}"
        );
        assert!(observed.old_truth_cleared && observed.new_worker && observed.new_binding && observed.new_truth
            && matches!(observed.fresh_lifetime, IntroductionLifetime::Live { .. }),
            "fresh BeginIntroducedPeer must reuse the protected SAME installation without old authentication: {observed:?}");
    }

    /// Boundary companion: the unchanged protected-reuse test drives the
    /// actual Begin actor. Here the adoption/attachment interval is deliberately
    /// held open to run the REAL old constructor Drop against the new ticket.
    #[tokio::test]
    #[ignore = "real joined W0, funded readoption, stale constructor and exact W1 attachment"]
    async fn stale_introduction_constructor_preserves_readopted_ticket_and_worker() {
        let remote = crate::identity::Identity::ephemeral();
        let hub = crate::identity::Identity::ephemeral();
        let charge = |raw| FiniteResourceProvider::reservation_planning_charge(raw).unwrap();
        let placeholder =
            PeerRegistry::introduction_placeholder_claim(remote.public_id().len()).unwrap();
        let retained = [
            retained_plan(remote.public_id()),
            charge(authenticated_fixture_claim()),
            charge(placeholder),
            charge(placeholder),
        ]
        .into_iter()
        .try_fold(ResourceClaim::ZERO, |sum, next| sum.checked_add(next))
        .unwrap();
        let (state, signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-stale-constructor",
                None,
                3,
                Some(retained),
                None,
                Some(policy()),
            );
        let auth_work = state
            .local_resources
            .acquire(authenticated_fixture_claim())
            .unwrap();
        let fixture = super::super::insert_promoted_peer(&state, hub.public_id()).await;
        configure_carrier_topology(&state, hub.public_id());
        let hub_worker = fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(hub.public_id())
            .unwrap()
            .for_worker(Arc::clone(&hub_worker));
        let (reply, mut received) = oneshot::channel();
        let (registration, mut cancellation) =
            state.connect_waiter_registration_for_test(remote.public_id(), 91, reply);
        let shared = registration.shared.clone();
        let mut original = None;
        let mut successor = None;
        let observations: Result<_> = async {
            let (w0, events0) = state
                .transport
                .open_connector_peer(
                    crate::transport::Role::Answerer,
                    &[],
                    &[],
                    state.peer_connection_resource_scope(),
                )
                .await?;
            let w0 = Arc::new(w0);
            original = Some(Arc::clone(&w0));
            let (owner0, ticket0, key, generation0) = prepare_native_settlement_fixture(
                &state,
                &remote,
                &hub,
                &carrier,
                &w0,
                registration,
                true,
            )?;
            let unstarted_owner = state
                .peers
                .owner(remote.public_id())
                .ok_or_else(|| Error::Network("original installation missing".into()))?;
            state.add_sticky(remote.public_id());
            super::super::spawn_registered_peer_event_pump(
                &state,
                Arc::clone(&state),
                remote.public_id().to_owned(),
                Arc::clone(&w0),
                events0,
                Some(owner0.clone()),
            )
            .await;
            super::super::handshake::on_deny(
                &state,
                &owner0,
                crate::protocol::DenyMessage { reason: None },
            )
            .await;
            state.connection_cmd_tx.close();
            let receiver = state
                .take_connection_cmd_rx()
                .ok_or_else(|| Error::Network("actual actor receiver missing".into()))?;
            super::super::supervisor::run_connection_commands(Arc::clone(&state), receiver).await;
            let joined = matches!(received.try_recv(), Ok(Err(_)))
                && *shared.outcome.lock() == ChannelDemandOutcome::TerminalRefused
                && state
                    .demand_links
                    .as_ref()
                    .unwrap()
                    .lock()
                    .links
                    .get(&key)
                    .is_none();
            let old_constructor_retired = !owner0.connection().introduction_ticket_matches(ticket0);
            let ticket1 = prepare_reuse_ticket(&state, &remote, &hub, &carrier)?;
            let incoming = state.reserve_introduction_placeholder(remote.public_id())?;
            let with_two_backings = provider.in_use();
            let (displaced, old_backing) = state
                .peers
                .with_current(&unstarted_owner, |peer| {
                    peer.adopt_empty_introduction(ticket1, incoming)
                })
                .ok_or_else(|| Error::Network("same installation adoption fence refused".into()))?
                .map_err(|_| Error::Network("joined storage readoption refused".into()))?;
            let old_charge = old_backing.as_ref().map(|lease| lease.claim());
            let two_backings_held = old_backing.is_some() && provider.in_use() == with_two_backings;
            if let Some(displaced) = displaced {
                super::super::forget_displacement(&state, displaced);
            }
            drop(old_backing);
            let released = with_two_backings.checked_sub(provider.in_use());
            let expected_release = old_charge
                .map(|claim| FiniteResourceProvider::reservation_planning_charge(claim).unwrap());
            let exchanged = released.ok() == expected_release && expected_release.is_some();
            let root = state.hub_introductions.as_ref().unwrap();
            let lifetime1 = root.lock().lifetime(ticket1, std::time::Instant::now());
            {
                let permit = state
                    .try_admit_shutdown_mutation()
                    .ok_or_else(|| Error::Network("constructor control permit refused".into()))?;
                drop(super::super::IntroductionConstruction {
                    state: &state,
                    permit: &permit,
                    owner: unstarted_owner.clone(),
                    ticket: ticket0,
                    armed: true,
                });
            }
            let stale_drop_refused = state.peers.with_current(&unstarted_owner, |peer| {
                peer.introduction_ticket_matches(ticket1)
                    && !peer.introduction_ticket_matches(ticket0)
            }) == Some(true)
                && root.lock().lifetime(ticket1, std::time::Instant::now()) == lifetime1;
            root.lock()
                .bind_native_owner(ticket1, &unstarted_owner)
                .map_err(|_| Error::Network("fresh native binding refused".into()))?;
            let (w1, events1) = state
                .transport
                .open_connector_peer(
                    crate::transport::Role::Answerer,
                    &[],
                    &[],
                    state.peer_connection_resource_scope(),
                )
                .await?;
            let w1 = Arc::new(w1);
            successor = Some(Arc::clone(&w1));
            let stale_attach_refused = state.peers.with_current(&unstarted_owner, |peer| {
                !peer.attach_introduction_worker(Arc::clone(&w1), Some(ticket0))
            }) == Some(true);
            let attached = state.peers.with_current(&unstarted_owner, |peer| {
                peer.attach_introduction_worker(Arc::clone(&w1), Some(ticket1))
            }) == Some(true);
            let owner1 = unstarted_owner.for_worker(Arc::clone(&w1));
            state.reserve_demand_link()?.bind(
                owner1.clone(),
                ticket1,
                std::time::Instant::now(),
            )?;
            super::super::spawn_registered_peer_event_pump(
                &state,
                Arc::clone(&state),
                remote.public_id().to_owned(),
                Arc::clone(&w1),
                events1,
                Some(owner1.clone()),
            )
            .await;
            state
                .settle_failed_introduction(key, ticket0, generation0)
                .await;
            let preserved = state.peers.with_current(&owner1, |peer| {
                peer.introduction_ticket_matches(ticket1)
                    && !peer.has_authenticated_channel()
                    && !peer.state.read().authenticated
            }) == Some(true)
                && state
                    .demand_links
                    .as_ref()
                    .unwrap()
                    .lock()
                    .links
                    .get(&key)
                    .is_some_and(|link| link.introduction == ticket1)
                && state.is_sticky(remote.public_id())
                && state
                    .config
                    .read()
                    .pinned_peers
                    .iter()
                    .any(|id| id == remote.public_id());
            Ok((
                joined,
                old_constructor_retired,
                two_backings_held,
                exchanged,
                stale_drop_refused,
                stale_attach_refused,
                attached,
                preserved,
                ticket0 != ticket1,
            ))
        }
        .await;
        state.connection_cmd_tx.close();
        let original_close = if let Some(worker) = original.as_ref() {
            worker.retire_and_close().await.is_ok()
        } else {
            true
        };
        let successor_close = if let Some(worker) = successor.as_ref() {
            worker.retire_and_close().await.is_ok()
        } else {
            true
        };
        state.shutdown().await;
        let carrier_close = hub_worker.retire_and_close().await;
        cancellation.armed = false;
        drop((
            received,
            cancellation,
            shared,
            commands,
            signals,
            carrier,
            hub_worker,
            fixture,
            original,
            successor,
        ));
        drop(state);
        drop(auth_work);
        assert!(
            original_close && successor_close && carrier_close.is_ok(),
            "native cleanup; setup={:?}",
            observations.as_ref().err()
        );
        assert_eq!(
            provider.active_reservations(),
            0,
            "setup={:?}",
            observations.as_ref().err()
        );
        assert_eq!(provider.active_scopes(), 0);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
        let (
            joined,
            retired,
            held,
            exchanged,
            drop_refused,
            attach_refused,
            attached,
            preserved,
            distinct,
        ) = observations.expect("actual joined-original and fresh-adoption setup");
        assert!(joined && retired && held && exchanged && drop_refused && attach_refused && attached && preserved && distinct,
            "joined={joined} retired={retired} held={held} exchanged={exchanged} drop_refused={drop_refused} attach_refused={attach_refused} attached={attached} preserved={preserved} distinct={distinct}");
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum AuthenticatedTerminalControl {
        Deny,
        ControllerTerminalThenDeny,
        RetiredClosed,
        QueueRefused,
        ReplacementAfterClaim,
    }

    async fn native_settlement_control(expired: bool, native_failure: bool, cancel_actor: bool) {
        native_settlement_control_with_terminal(expired, native_failure, cancel_actor, None).await;
    }

    async fn native_settlement_control_with_terminal(
        expired: bool,
        native_failure: bool,
        cancel_actor: bool,
        explicit: Option<AuthenticatedTerminalControl>,
    ) {
        eprintln!("settlement-stage: entry expired={expired} native_failure={native_failure} cancel_actor={cancel_actor}");
        let remote = crate::identity::Identity::ephemeral();
        let hub = crate::identity::Identity::ephemeral();
        let (state, mut signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-native-settlement",
                None,
                // Only the successor discriminator owns a third simultaneous
                // actual connector (carrier + original W0 + replacement W1).
                if explicit == Some(AuthenticatedTerminalControl::ReplacementAfterClaim) {
                    3
                } else {
                    2
                },
                Some(
                    retained_plan(remote.public_id())
                        .checked_add(
                            FiniteResourceProvider::reservation_planning_charge(
                                PumpTerminalGate::claim(),
                            )
                            .unwrap(),
                        )
                        .unwrap()
                        .checked_add(if explicit.is_some() {
                            FiniteResourceProvider::reservation_planning_charge(
                                authenticated_fixture_claim(),
                            )
                            .unwrap()
                        } else {
                            ResourceClaim::ZERO
                        })
                        .unwrap(),
                ),
                None,
                Some(policy()),
            );
        let auth_work = if explicit.is_some() {
            Some(
                state
                    .local_resources
                    .acquire(authenticated_fixture_claim())
                    .expect("named local exchange work is admitted before task construction"),
            )
        } else {
            None
        };
        let terminal_gate = FundedArc::new(
            PumpTerminalGate {
                entered: AtomicBool::new(false),
                opened: AtomicBool::new(false),
                changed: tokio::sync::Notify::new(),
            },
            state
                .local_resources
                .acquire(PumpTerminalGate::claim())
                .unwrap(),
        )
        .unwrap();
        let fixture = super::super::insert_promoted_peer(&state, hub.public_id()).await;
        eprintln!("settlement-stage: carrier-ready");
        configure_carrier_topology(&state, hub.public_id());
        let hub_worker = fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(hub.public_id())
            .unwrap()
            .for_worker(Arc::clone(&hub_worker));
        let (worker, events) = state
            .transport
            .open_connector_peer(
                crate::transport::Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("the named fixture profile admits the original W0");
        eprintln!("settlement-stage: original-worker-ready");
        let worker = Arc::new(worker);
        let gate = worker.install_native_close_gate_for_test();
        if native_failure {
            gate.inject_close_failure();
        }
        let runtime = super::super::signaling_ingress::SignalingRuntime::new(
            state.signaling_inbound_tx.clone(),
            state.local_application_resource_scope().unwrap(),
        );
        state.publish_signaling_runtime(&runtime);
        let ingress = super::super::signaling_ingress::SignalingRuntime::attach(
            &runtime,
            super::super::signaling_ingress::SignalingCarrier::Nostr,
        );
        let (reply, mut received) = oneshot::channel();
        let (registration, mut cancellation) =
            state.connect_waiter_registration_for_test(remote.public_id(), 80, reply);
        let shared = registration.shared.clone();
        let setup = prepare_native_settlement_fixture(
            &state,
            &remote,
            &hub,
            &carrier,
            &worker,
            registration,
            explicit.is_some(),
        );
        match &setup {
            Ok(_) => eprintln!("settlement-stage: setup-ok"),
            Err(error) => eprintln!("settlement-stage: setup-error {error}"),
        }
        let mut observations = None;
        let mut authenticated_observations = None;
        let mut successor = None;
        let mut successor_observed =
            explicit != Some(AuthenticatedTerminalControl::ReplacementAfterClaim);
        let mut registration_observed = !cancel_actor;
        let mut pump_boundary_observed = cancel_actor;
        let mut duplicate_observed = cancel_actor;
        if let Ok((owner, ticket, key, generation)) = &setup {
            if state.begin_peer_event_pump_registration() {
                let (pending, before_handles) = state.peer_event_pump_counts_for_test();
                let held_terminal = terminal_gate.clone();
                let pump = super::super::spawn_peer_event_pump_with_terminal(
                    Arc::clone(&state),
                    remote.public_id().to_owned(),
                    Arc::clone(&worker),
                    events,
                    Some(owner.clone()),
                    hold_pump_terminal(held_terminal),
                );
                let transferred = match state.finish_introduced_pump_registration(owner, pump) {
                    Ok(()) => true,
                    Err(pump) => {
                        state.finish_peer_event_pump_registration(pump).await;
                        false
                    }
                };
                let (after_pending, after_handles) = state.peer_event_pump_counts_for_test();
                registration_observed = transferred
                    && pending == 1
                    && after_pending == 0
                    && before_handles == after_handles
                    && state
                        .demand_links
                        .as_ref()
                        .unwrap()
                        .lock()
                        .links
                        .get(key)
                        .is_some_and(|link| link.pump_registered && link.pump.is_some());
            } else {
                super::super::spawn_registered_peer_event_pump(
                    &state,
                    Arc::clone(&state),
                    remote.public_id().to_owned(),
                    Arc::clone(&worker),
                    events,
                    Some(owner.clone()),
                )
                .await;
            }
            eprintln!(
                "settlement-stage: pump-registration-complete observed={registration_observed}"
            );
            let attempt = ticket.attempt();
            let candidate = myownmesh_signaling::SignalingMessage::Candidate {
                peer_id: remote.public_id().to_owned(),
                offer_id: attempt.clone(),
                candidate: "candidate:settlement 1 udp 2113937151 192.0.2.1 5000 typ host".into(),
                sdp_mid: Some("0".into()),
                sdp_mline_index: Some(0),
                username_fragment: None,
            };
            let admitted =
                ingress.deliver(ingress.directed(remote.public_id().to_owned(), candidate));
            let token = if admitted {
                signals
                    .try_recv()
                    .and_then(|delivery| delivery.value().dedup_token())
            } else {
                None
            };
            let weak = token.as_ref().map(|token| token.weak());
            let retained = token.is_some_and(|token| {
                state.peers.with_current(owner, |peer| {
                    if peer.holds_promoted_session()
                        || peer.attempt() != attempt
                        || !peer
                            .current_worker()
                            .is_some_and(|current| Arc::ptr_eq(&current, &worker))
                    {
                        return false;
                    }
                    peer.retain_current_dedup(token);
                    true
                }) == Some(true)
            }) && weak.as_ref().is_some_and(|weak| weak.strong_count() == 1);
            let deadline = shared.introduction.lock().unwrap().deadline;
            if expired {
                tokio::time::sleep_until(tokio::time::Instant::from_std(deadline)).await;
                state.maintain_hub_introductions().await;
            } else if explicit.is_none()
                || explicit == Some(AuthenticatedTerminalControl::ControllerTerminalThenDeny)
            {
                state
                    .hub_introductions
                    .as_ref()
                    .unwrap()
                    .lock()
                    .failed(*ticket);
            }
            if let Some(disposition) = explicit {
                // A controller tombstone/deadline is not explicit terminal
                // authority over a genuinely authenticated unpromoted W0.
                let protected =
                    !state.claim_introduction_retirement(owner, *key, *ticket, *generation, None)
                        && state.peers.with_current(owner, |peer| {
                            peer.has_authenticated_channel()
                                && !peer.holds_promoted_session()
                                && peer.state.read().status
                                    == super::super::connection::PeerStatus::PendingApproval
                                && worker.live_connector_incarnation().is_some()
                        }) == Some(true);
                if disposition == AuthenticatedTerminalControl::QueueRefused {
                    // Real closed-mailbox refusal: accepted commands, if any,
                    // still belong to the original receiver until teardown.
                    state.connection_cmd_tx.close();
                }
                let retired_before = if disposition == AuthenticatedTerminalControl::RetiredClosed {
                    let task_retired =
                        owner.connection().endpoint_auth_task().is_some_and(|task| {
                            task.retire();
                            task.is_retired()
                                && worker
                                    .matches_connector_identity_for_retirement(task.incarnation())
                                && !task.belongs_to(task.incarnation())
                        });
                    worker.retire();
                    super::super::drop_peer_if_current(
                        &state,
                        owner,
                        crate::events::DropReason::TransportError {
                            message: "fixture original connector closed".into(),
                        },
                    )
                    .await;
                    task_retired
                } else {
                    super::super::handshake::on_deny(
                        &state,
                        owner,
                        crate::protocol::DenyMessage { reason: None },
                    )
                    .await;
                    true
                };
                let expected_cause = if disposition == AuthenticatedTerminalControl::RetiredClosed {
                    super::super::connection::IntroductionTerminalDisposition::TransportError
                } else {
                    super::super::connection::IntroductionTerminalDisposition::Denied
                };
                let claimed = retired_before
                    && state
                        .demand_links
                        .as_ref()
                        .unwrap()
                        .lock()
                        .links
                        .get(key)
                        .is_some_and(|link| {
                            link.introduction == *ticket
                                && link.generation == *generation
                                && link.detached.as_ref().is_some_and(|detached| {
                                    detached.terminal == Some(expected_cause)
                                        && detached.authenticated_custody_for_test()
                                })
                                && link.settlement
                                    == if disposition == AuthenticatedTerminalControl::QueueRefused
                                    {
                                        IntroductionSettlementPhase::Active
                                    } else {
                                        IntroductionSettlementPhase::Queued
                                    }
                        });
                let duplicate_kept_cause = state.request_failed_introduction(
                    owner,
                    Some(&attempt),
                    &crate::events::DropReason::HeartbeatTimeout,
                ) && state
                    .demand_links
                    .as_ref()
                    .unwrap()
                    .lock()
                    .links
                    .get(key)
                    .and_then(|link| link.detached.as_ref())
                    .is_some_and(|detached| detached.terminal == Some(expected_cause));
                // Exact original installation, not a selected successor.
                let promotion_refused = state
                    .peers
                    .with_admitted_current(
                        owner,
                        state.session_broker.as_ref(),
                        &state.mesh_context_id().to_string(),
                        |_| (),
                    )
                    .is_none();
                authenticated_observations = Some((
                    protected,
                    claimed && duplicate_kept_cause,
                    promotion_refused,
                    false,
                ));
                if disposition == AuthenticatedTerminalControl::ReplacementAfterClaim {
                    let replacement =
                        super::super::insert_promoted_peer(&state, remote.public_id()).await;
                    let w1 = replacement.peer.current_worker().unwrap();
                    let owner1 = state
                        .peers
                        .owner(remote.public_id())
                        .unwrap()
                        .for_worker(Arc::clone(&w1));
                    let admitted = admit_carrier(&state, &owner1).is_ok();
                    // An incorrect generation cannot start the old native
                    // close or acquire the live replacement installation.
                    state
                        .settle_failed_introduction(
                            *key,
                            *ticket,
                            generation.checked_add(1).unwrap(),
                        )
                        .await;
                    successor_observed = admitted
                        && gate.entries() == 0
                        && !owner.same_exact_owner(&owner1)
                        && !Arc::ptr_eq(&worker, &w1)
                        && state.request_failed_introduction(
                            owner,
                            Some(&attempt),
                            &crate::events::DropReason::Denied,
                        )
                        && state.peers.has_usable_authenticated_current(&owner1);
                    successor = Some((replacement, w1, owner1));
                }
                state.connection_cmd_tx.close();
            }
            let actor_receiver = if cancel_actor
                || (explicit.is_some()
                    && explicit != Some(AuthenticatedTerminalControl::QueueRefused))
            {
                if explicit.is_none() {
                    state.queue_failed_introduction(*key, *ticket, *generation);
                }
                Some(
                    state
                        .take_connection_cmd_rx()
                        .expect("control owns the actual connection actor"),
                )
            } else {
                None
            };
            let finish = async {
                if let Some(receiver) = actor_receiver {
                    super::super::supervisor::run_connection_commands(Arc::clone(&state), receiver)
                        .await;
                } else {
                    // Closed-admission companion drives the same settlement
                    // handler directly; it does not pretend a refused command
                    // ran. The canceled-actor companion covers shutdown drain.
                    state
                        .settle_failed_introduction(*key, *ticket, *generation)
                        .await;
                }
            };
            tokio::pin!(finish);
            eprintln!("settlement-stage: before-first-poll");
            let was_pending = futures::poll!(&mut finish).is_pending();
            eprintln!("settlement-stage: after-first-poll pending={was_pending}");
            let entered =
                tokio::time::timeout(std::time::Duration::from_secs(10), gate.wait_for_entry())
                    .await
                    .is_ok();
            eprintln!("settlement-stage: native-gate-wait entered={entered}");
            let scope_refusal = owner
                .connection()
                .reserve_closing_entry_for_test(&worker)
                .err();
            let no_entry = owner.connection().retired_worker_count_for_test() == 0;
            let held = weak.as_ref().is_some_and(|weak| weak.strong_count() == 1)
                && runtime.remembers_attempt_for_test(&attempt);
            let waiter_pending = matches!(
                received.try_recv(),
                Err(oneshot::error::TryRecvError::Empty)
            );
            let no_current =
                if explicit == Some(AuthenticatedTerminalControl::ReplacementAfterClaim) {
                    // The replacement is intentionally current; ORIGINAL W0 is
                    // no longer current, and cannot be lifted to successor Ready.
                    state.peers.with_current(owner, |_| ()).is_none()
                } else {
                    state.peers.owner(remote.public_id()).is_none()
                };
            if let Some((_, _, _, custody)) = authenticated_observations.as_mut() {
                *custody = state
                    .demand_links
                    .as_ref()
                    .unwrap()
                    .lock()
                    .links
                    .get(key)
                    .and_then(|link| link.detached.as_ref())
                    .is_some_and(|detached| detached.authenticated_custody_for_test());
            }
            if !cancel_actor {
                gate.open();
                eprintln!("settlement-stage: native-gate-open");
                let reached = tokio::select! {
                    _ = &mut finish => false,
                    result = tokio::time::timeout(std::time::Duration::from_secs(10),
                        terminal_gate.wait_entered()) => result.is_ok(),
                };
                eprintln!("settlement-stage: terminal-gate-wait reached={reached}");
                let native_terminal = tokio::time::timeout(
                    std::time::Duration::from_secs(10),
                    worker.retire_and_close(),
                )
                .await
                .is_ok();
                eprintln!(
                    "settlement-stage: independent-native-completion returned={native_terminal}"
                );
                let still_joining = if reached {
                    futures::poll!(&mut finish).is_pending()
                } else {
                    false
                };
                pump_boundary_observed = reached
                    && native_terminal
                    && still_joining
                    && matches!(
                        received.try_recv(),
                        Err(oneshot::error::TryRecvError::Empty)
                    )
                    && weak.as_ref().is_some_and(|weak| weak.strong_count() == 1)
                    && state
                        .demand_links
                        .as_ref()
                        .unwrap()
                        .lock()
                        .links
                        .get(key)
                        .is_some_and(|link| link.detached.is_some() && link.pump_joined.is_none());
                if let Some((_, _, _, custody)) = authenticated_observations.as_mut() {
                    *custody &= state
                        .demand_links
                        .as_ref()
                        .unwrap()
                        .lock()
                        .links
                        .get(key)
                        .and_then(|link| link.detached.as_ref())
                        .is_some_and(|detached| detached.authenticated_custody_for_test());
                }
                terminal_gate.open();
                eprintln!("settlement-stage: terminal-gate-open");
                if reached {
                    eprintln!("settlement-stage: before-finish");
                    finish.await;
                    eprintln!("settlement-stage: after-finish");
                    let before = *shared.outcome.lock();
                    state.queue_failed_introduction(*key, *ticket, *generation);
                    state.maintain_hub_introductions().await;
                    state
                        .settle_failed_introduction(*key, *ticket, *generation)
                        .await;
                    duplicate_observed = gate.entries() == 1
                        && *shared.outcome.lock() == before
                        && state
                            .demand_links
                            .as_ref()
                            .unwrap()
                            .lock()
                            .links
                            .get(key)
                            .is_none();
                }
            }
            observations = Some((
                retained,
                was_pending,
                entered,
                scope_refusal,
                no_entry,
                held,
                waiter_pending,
                no_current,
                weak,
                attempt,
            ));
            // In the cancellation branch the actual pinned future (not just
            // its Pin reference) drops at this lexical boundary, before open.
        } else {
            drop(events);
            gate.open();
        }
        eprintln!("settlement-stage: body-ended");
        if let Some((_, w1, owner1)) = successor.as_ref() {
            successor_observed &= state.peers.has_usable_authenticated_current(owner1)
                && w1.live_connector_incarnation().is_some();
        }
        let restored = !cancel_actor
            || setup.as_ref().is_ok_and(|(_, ticket, key, generation)| {
                state
                    .demand_links
                    .as_ref()
                    .unwrap()
                    .lock()
                    .links
                    .get(key)
                    .is_some_and(|link| {
                        link.introduction == *ticket
                            && link.generation == *generation
                            && link.settlement == IntroductionSettlementPhase::Active
                            && link.detached.is_some()
                            && (explicit.is_none()
                                || link.detached.as_ref().is_some_and(|detached| {
                                    detached.authenticated_custody_for_test()
                                }))
                            && link.pump.is_some()
                    })
            });
        gate.open();
        terminal_gate.open();
        eprintln!("settlement-stage: before-original-close");
        let original_close = worker.retire_and_close().await;
        eprintln!(
            "settlement-stage: after-original-close error={}",
            original_close.is_err()
        );
        eprintln!("settlement-stage: before-state-shutdown");
        state.shutdown().await;
        eprintln!("settlement-stage: after-state-shutdown");
        let successor_close_ok = if let Some((_, w1, _)) = successor.as_ref() {
            w1.retire_and_close().await.is_ok()
        } else {
            true
        };
        let outcome = *shared.outcome.lock();
        let ended = matches!(received.try_recv(), Ok(Err(_)));
        cancellation.armed = false;
        let native_once = gate.entries() == 1;
        let token_released =
            observations
                .as_ref()
                .is_some_and(|(_, _, _, _, _, _, _, _, weak, attempt)| {
                    weak.as_ref().is_some_and(|weak| weak.strong_count() == 0)
                        && !runtime.remembers_attempt_for_test(attempt)
                });
        let scope_refusal = observations
            .as_mut()
            .and_then(|observation| observation.3.take());
        eprintln!("settlement-stage: before-carrier-close");
        let carrier_close = hub_worker.retire_and_close().await;
        eprintln!(
            "settlement-stage: after-carrier-close error={}",
            carrier_close.is_err()
        );
        eprintln!("settlement-stage: before-fixture-drop");
        drop((
            received,
            cancellation,
            shared,
            ingress,
            runtime,
            commands,
            signals,
            carrier,
            hub_worker,
            fixture,
            worker,
            gate,
            terminal_gate,
            setup,
            successor,
        ));
        drop(state);
        drop(auth_work);
        eprintln!("settlement-stage: after-fixture-drop");
        let (
            retained,
            pending,
            entered,
            _,
            no_entry,
            held,
            waiter_pending,
            no_current,
            weak,
            attempt,
        ) = observations.expect("actual original introduction setup completed");
        drop((weak, attempt));
        assert!(
            retained && pending && entered && no_entry && held && waiter_pending && no_current,
            "retained={retained} pending={pending} entered={entered} no_entry={no_entry} held={held} waiter_pending={waiter_pending} no_current={no_current}"
        );
        assert!(
            matches!(
                scope_refusal,
                Some(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::WorkerOrTask,
                })
            ),
            "exact withdrawn-work-scope refusal: {scope_refusal:?}"
        );
        assert!(
            ended
                && native_once
                && token_released
                && restored
                && registration_observed
                && pump_boundary_observed
                && duplicate_observed,
            "ended={ended} native_once={native_once} token_released={token_released} restored={restored} registration_observed={registration_observed} pump_boundary_observed={pump_boundary_observed} duplicate_observed={duplicate_observed}"
        );
        assert_eq!(
            outcome,
            if native_failure || cancel_actor {
                ChannelDemandOutcome::Unsettled
            } else if explicit.is_some() {
                ChannelDemandOutcome::TerminalRefused
            } else {
                ChannelDemandOutcome::FailedSettlementJoined
            }
        );
        if explicit.is_some() {
            let (protected, claimed, promotion_refused, custody) = authenticated_observations
                .expect("real authenticated original was installed and terminal was exercised");
            assert!(protected && claimed && promotion_refused && custody,
                "protected={protected} claimed={claimed} promotion_refused={promotion_refused} custody={custody}");
            assert!(
                successor_observed && successor_close_ok,
                "successor_observed={successor_observed} successor_close_ok={successor_close_ok}"
            );
        }
        assert_eq!(original_close.is_err(), native_failure);
        assert!(
            carrier_close.is_ok(),
            "captured carrier close: {carrier_close:?}"
        );
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
        let failed = provider.retained_after_failed_cleanup();
        assert_eq!(provider.in_use(), failed);
        assert_eq!(failed == ResourceClaim::ZERO, !native_failure);
    }

    #[tokio::test]
    #[ignore = "opens native W0/carrier and observes the original deadline; isolated harness"]
    async fn expired_introduction_joins_native_and_engine_pump_before_fallback() {
        native_settlement_control(true, false, false).await;
    }

    #[tokio::test]
    #[ignore = "opens native W0/carrier; isolated harness"]
    async fn already_terminal_introduction_keeps_tokens_without_closing_entry() {
        native_settlement_control(false, false, false).await;
    }

    #[tokio::test]
    #[ignore = "opens native W0/carrier with post-native failure; isolated harness"]
    async fn failed_introduction_native_error_refuses_fallback_and_retains_failed_ledger() {
        native_settlement_control(false, true, false).await;
    }

    #[tokio::test]
    #[ignore = "opens native W0/carrier and cancels actor work; isolated harness"]
    async fn canceled_introduction_settlement_restores_record_for_shutdown_drain() {
        native_settlement_control(false, false, true).await;
    }

    #[tokio::test]
    #[ignore = "genuine original capability, Deny actor, native and engine-pump gates"]
    async fn authenticated_unpromoted_deny_joins_before_terminal_refusal() {
        native_settlement_control_with_terminal(
            false,
            false,
            false,
            Some(AuthenticatedTerminalControl::Deny),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "controller Terminal alone preserves genuine capability until actual Deny"]
    async fn authenticated_unpromoted_controller_terminal_preserves_until_deny() {
        native_settlement_control_with_terminal(
            false,
            false,
            false,
            Some(AuthenticatedTerminalControl::ControllerTerminalThenDeny),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "genuine original capability survives retirement identity; isolated native harness"]
    async fn authenticated_retired_closed_keeps_exact_terminal_custody() {
        native_settlement_control_with_terminal(
            false,
            false,
            false,
            Some(AuthenticatedTerminalControl::RetiredClosed),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "original deadline is observed without retiring live authenticated W0"]
    async fn authenticated_unpromoted_expiry_preserves_until_explicit_deny() {
        native_settlement_control_with_terminal(
            true,
            false,
            false,
            Some(AuthenticatedTerminalControl::Deny),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "reported native error, not physical native failure; isolated native harness"]
    async fn authenticated_unpromoted_deny_error_never_allows_fallback() {
        native_settlement_control_with_terminal(
            false,
            true,
            false,
            Some(AuthenticatedTerminalControl::Deny),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "actual actor cancellation restores genuine capability for shutdown join"]
    async fn authenticated_unpromoted_deny_actor_cancel_restores_custody() {
        native_settlement_control_with_terminal(
            false,
            false,
            true,
            Some(AuthenticatedTerminalControl::Deny),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "closed mailbox refusal followed by shared settlement handler, not accepted actor work"]
    async fn authenticated_unpromoted_deny_queue_refusal_retains_custody() {
        native_settlement_control_with_terminal(
            false,
            false,
            false,
            Some(AuthenticatedTerminalControl::QueueRefused),
        )
        .await;
    }

    #[tokio::test]
    #[ignore = "three named native owners; exact W0 terminal and independent promoted W1"]
    async fn authenticated_terminal_join_preserves_replacement_installation() {
        native_settlement_control_with_terminal(
            false,
            false,
            false,
            Some(AuthenticatedTerminalControl::ReplacementAfterClaim),
        )
        .await;
    }

    /// The opposite linearization from the detached-before-promotion controls:
    /// a real logical promotion wins on the original introduced installation.
    /// This is the existing exact channel-terminal path, not an assertion that
    /// its ClosingWorker entry always admits or that it uses detached custody.
    #[tokio::test]
    #[ignore = "actual introduced task/capability promoted before exact Deny"]
    async fn authenticated_promotion_before_deny_keeps_original_channel_terminal() {
        let remote = crate::identity::Identity::ephemeral();
        let hub = crate::identity::Identity::ephemeral();
        let plan = retained_plan(remote.public_id())
            .checked_add(
                FiniteResourceProvider::reservation_planning_charge(authenticated_fixture_claim())
                    .unwrap(),
            )
            .unwrap();
        let (state, signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-promotion-before-deny",
                None,
                2,
                Some(plan),
                None,
                Some(policy()),
            );
        let auth_work = state
            .local_resources
            .acquire(authenticated_fixture_claim())
            .unwrap();
        let fixture = super::super::insert_promoted_peer(&state, hub.public_id()).await;
        configure_carrier_topology(&state, hub.public_id());
        let hub_worker = fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(hub.public_id())
            .unwrap()
            .for_worker(Arc::clone(&hub_worker));
        let (worker, events) = state
            .transport
            .open_connector_peer(
                crate::transport::Role::Answerer,
                &[],
                &[],
                state.peer_connection_resource_scope(),
            )
            .await
            .expect("named original W0 slot");
        let worker = Arc::new(worker);
        let (reply, mut received) = oneshot::channel();
        let (registration, mut cancellation) =
            state.connect_waiter_registration_for_test(remote.public_id(), 81, reply);
        let shared = registration.shared.clone();
        let setup = prepare_native_settlement_fixture(
            &state,
            &remote,
            &hub,
            &carrier,
            &worker,
            registration,
            true,
        );
        let mut observations = None;
        if let Ok((owner, ticket, key, generation)) = &setup {
            let registered = if state.begin_peer_event_pump_registration() {
                let pump = super::super::spawn_peer_event_pump(
                    Arc::clone(&state),
                    remote.public_id().to_owned(),
                    Arc::clone(&worker),
                    events,
                    Some(owner.clone()),
                );
                match state.finish_introduced_pump_registration(owner, pump) {
                    Ok(()) => true,
                    Err(pump) => {
                        state.finish_peer_event_pump_registration(pump).await;
                        false
                    }
                }
            } else {
                drop(events);
                false
            };
            owner.connection().state.write().status = super::super::connection::PeerStatus::Active;
            let promoted = admit_carrier(&state, owner).is_ok()
                && owner.connection().holds_promoted_session()
                && state.peers.has_usable_authenticated_current(owner);
            let unclaimed = !state.request_failed_introduction(
                owner,
                Some(&ticket.attempt()),
                &crate::events::DropReason::Denied,
            );
            let intact = state
                .demand_links
                .as_ref()
                .unwrap()
                .lock()
                .links
                .get(key)
                .is_some_and(|link| {
                    link.introduction == *ticket
                        && link.generation == *generation
                        && link.detached.is_none()
                        && link.settlement == IntroductionSettlementPhase::Active
                })
                && worker.live_connector_incarnation().is_some()
                && state.peers.has_usable_authenticated_current(owner);
            super::super::handshake::on_deny(
                &state,
                owner,
                crate::protocol::DenyMessage { reason: None },
            )
            .await;
            let terminal = !state.peers.has_usable_authenticated_current(owner)
                && worker.live_connector_incarnation().is_none();
            observations = Some((registered, promoted, unclaimed, intact, terminal));
        } else {
            drop(events);
        }
        // Never assert before every original native/engine/fixture owner has
        // completed. Shutdown owns the registered original receiver join.
        let close = worker.retire_and_close().await;
        state.shutdown().await;
        let hub_close = hub_worker.retire_and_close().await;
        let ended = matches!(received.try_recv(), Ok(Err(_)));
        let no_fallback = *shared.outcome.lock() == ChannelDemandOutcome::Unsettled;
        let drained = state.demand_links.as_ref().unwrap().lock().links.len() == 0;
        cancellation.armed = false;
        drop((
            received,
            cancellation,
            shared,
            commands,
            signals,
            carrier,
            hub_worker,
            fixture,
            worker,
            setup,
        ));
        drop(state);
        drop(auth_work);
        let (registered, promoted, unclaimed, intact, terminal) =
            observations.expect("actual introduced auth setup");
        assert!(registered && promoted && unclaimed && intact && terminal,
            "registered={registered} promoted={promoted} unclaimed={unclaimed} intact={intact} terminal={terminal}");
        assert!(
            ended && no_fallback && drained,
            "ended={ended} no_fallback={no_fallback} drained={drained}"
        );
        assert!(
            close.is_ok() && hub_close.is_ok(),
            "original={close:?} carrier={hub_close:?}"
        );
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
        assert_eq!(provider.in_use(), provider.retained_after_failed_cleanup());
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    /// Exact registry/slot boundary control, not a fabricated unpromoted W0
    /// coexisting with a selected promoted W1 in the single unpromoted slot.
    /// Promotion of W0 wins first (L1), then a real different installation W1
    /// wins; the old ticket may detach neither. All three native owners have
    /// named simultaneous profile slots and remain held through cleanup.
    #[tokio::test]
    #[ignore = "opens actual carrier/W0/W1; isolated native harness"]
    async fn failed_introduction_detach_preserves_promoted_and_replacement_owners() {
        let remote = crate::identity::Identity::ephemeral();
        let hub = crate::identity::Identity::ephemeral();
        let (state, signals, commands, provider, _) =
            super::super::build_test_state_parts_metered_with_application(
                "intro-detach-successors",
                None,
                3,
                Some(retained_plan(remote.public_id())),
                None,
                Some(policy()),
            );
        configure_carrier_topology(&state, hub.public_id());
        let carrier_fixture = super::super::insert_promoted_peer(&state, hub.public_id()).await;
        let carrier_worker = carrier_fixture.peer.current_worker().unwrap();
        let carrier = state
            .peers
            .owner(hub.public_id())
            .unwrap()
            .for_worker(Arc::clone(&carrier_worker));
        let first = super::super::insert_promoted_peer(&state, remote.public_id()).await;
        let w0 = first.peer.current_worker().unwrap();
        let owner0 = state
            .peers
            .owner(remote.public_id())
            .unwrap()
            .for_worker(Arc::clone(&w0));
        let setup: Result<_> = (|| {
            admit_carrier(&state, &carrier)?;
            let remote_id = DeviceId::from_canonical_str(remote.public_id())
                .map_err(|_| Error::Network("valid target required".into()))?;
            let root = state.hub_introductions.as_ref().unwrap();
            let ticket = root
                .lock()
                .begin_demand(&remote_id, &carrier, std::time::Instant::now())
                .map_err(|_| Error::Network("original ticket admission refused".into()))?
                .ticket;
            first.peer.adopt_attempt(&ticket.attempt());
            admit_carrier(&state, &owner0)?; // actual promotion wins before failure
            root.lock().failed(ticket);
            Ok(ticket)
        })();
        let mut unexpected = None;
        let promoted_refused = setup.as_ref().is_ok_and(|ticket| {
            !state.peers.with_introduction_installation(&owner0, |peer| {
                unexpected = peer.detach_failed_introduction(&w0, *ticket);
                unexpected.as_ref().map(|_| false)
            }) && state.peers.has_usable_authenticated_current(&owner0)
        });
        let replacement = super::super::insert_promoted_peer(&state, remote.public_id()).await;
        let w1 = replacement.peer.current_worker().unwrap();
        let owner1 = state
            .peers
            .owner(remote.public_id())
            .unwrap()
            .for_worker(Arc::clone(&w1));
        let successor_admitted = admit_carrier(&state, &owner1);
        let mut stale_callback_ran = false;
        let replacement_refused = setup.as_ref().is_ok_and(|ticket| {
            !state.peers.with_introduction_installation(&owner0, |peer| {
                stale_callback_ran = true;
                peer.detach_failed_introduction(&w0, *ticket)
                    .map(|detached| {
                        unexpected = Some(detached);
                        false
                    })
            })
        });
        let survived = !owner0.same_exact_owner(&owner1)
            && !Arc::ptr_eq(&w0, &w1)
            && state.peers.has_usable_authenticated_current(&owner1)
            && w1.live_connector_incarnation().is_some();
        let close0 = w0.retire_and_close().await;
        state.shutdown().await;
        let close1 = w1.retire_and_close().await;
        let carrier_close = carrier_worker.retire_and_close().await;
        drop((first, replacement, carrier_fixture));
        if let Some(detached) = unexpected.take() {
            detached.release_after_join(owner0.connection());
        }
        drop((
            owner0,
            owner1,
            carrier,
            w0,
            w1,
            carrier_worker,
            commands,
            signals,
            state,
        ));
        setup.expect("actual ticket and first promotion admitted");
        successor_admitted.expect("actual replacement promotion admitted");
        assert!(promoted_refused && replacement_refused && !stale_callback_ran && survived);
        assert!(close0.is_ok() && close1.is_ok() && carrier_close.is_ok());
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
        assert_eq!(provider.in_use(), provider.retained_after_failed_cleanup());
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }
}

/// Called only after the existing introduction translation work is admitted.
/// Native ICE represents absent optional metadata with either None or Some("");
/// the strict signed Hub body uses None. Preserve every nonempty value (even a
/// conflicting credential) and the exact candidate line/index for native checks.
fn hub_introduction_candidate_body(
    candidate: &crate::transport::LocalIceCandidate,
) -> crate::protocol::HubIntroductionBody {
    crate::protocol::HubIntroductionBody::Candidate {
        candidate: candidate.candidate.clone(),
        sdp_mid: candidate
            .sdp_mid
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned(),
        sdp_mline_index: candidate.sdp_mline_index,
        username_fragment: candidate
            .username_fragment
            .as_ref()
            .filter(|value| !value.is_empty())
            .cloned(),
    }
}

/// Unix epoch milliseconds. Stamped on every [`DiagEntry`] so the
/// GUI's Activity log can render a per-entry HH:MM:SS clock — wall
/// time, not monotonic: the user cares what time it actually was
/// when something happened, not how long after process start.
pub(crate) fn now_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_millis() as u64)
}

#[cfg(test)]
mod introduction_candidate_translation_tests {
    use super::hub_introduction_candidate_body;
    use crate::protocol::hub_introduction::{
        HubIntroductionBody, HubIntroductionEnvelope, HubIntroductionError, IntroductionChallenge,
    };
    use crate::semantic::{DeviceId, MeshContextId};
    use crate::transport::LocalIceCandidate;
    use ed25519_dalek::SigningKey;

    fn bundled_candidate() -> LocalIceCandidate {
        use webrtc::ice_transport::{
            ice_candidate::RTCIceCandidate, ice_candidate_type::RTCIceCandidateType,
            ice_protocol::RTCIceProtocol,
        };
        // Actual bundled serializer, without sockets, gathering, or native tasks.
        let init = RTCIceCandidate {
            foundation: "1".into(),
            priority: 2_130_706_431,
            address: "127.0.0.1".into(),
            port: 5000,
            protocol: RTCIceProtocol::Udp,
            typ: RTCIceCandidateType::Host,
            component: 1,
            ..Default::default()
        }
        .to_json()
        .expect("bounded host candidate serializes");
        LocalIceCandidate {
            candidate: init.candidate,
            sdp_mid: init.sdp_mid,
            sdp_mline_index: init.sdp_mline_index,
            username_fragment: init.username_fragment,
        }
    }

    fn envelope(
        body: HubIntroductionBody,
    ) -> Result<HubIntroductionEnvelope, HubIntroductionError> {
        let key = SigningKey::from_bytes(&[31; 32]);
        let other = SigningKey::from_bytes(&[32; 32]);
        // Wire-shape/signature fixture, not a live controller's admitted challenge.
        HubIntroductionEnvelope::new(
            MeshContextId::from_bytes([33; 32]),
            DeviceId::from_public_key_bytes(key.verifying_key().to_bytes()).unwrap(),
            DeviceId::from_public_key_bytes(other.verifying_key().to_bytes()).unwrap(),
            [34; 16],
            2,
            Some(IntroductionChallenge {
                request_hash: [35; 32],
                responder_challenge: [36; 32],
            }),
            4,
            body,
            &key,
        )
    }

    #[test]
    fn bundled_native_empty_mid_normalizes_into_signed_hub_candidate() {
        let candidate = bundled_candidate();
        assert_eq!(candidate.sdp_mid.as_deref(), Some(""));
        assert_eq!(candidate.sdp_mline_index, Some(0));
        assert_eq!(candidate.username_fragment, None);
        assert!(!candidate.candidate.is_empty());
        let original = candidate.clone();
        let unnormalized = HubIntroductionBody::Candidate {
            candidate: candidate.candidate.clone(),
            sdp_mid: candidate.sdp_mid.clone(),
            sdp_mline_index: candidate.sdp_mline_index,
            username_fragment: candidate.username_fragment.clone(),
        };
        assert_eq!(
            envelope(unnormalized),
            Err(HubIntroductionError::Body),
            "control exposes the original production adapter mismatch"
        );
        let body = hub_introduction_candidate_body(&candidate);
        assert_eq!(
            body,
            HubIntroductionBody::Candidate {
                candidate: candidate.candidate.clone(),
                sdp_mid: None,
                sdp_mline_index: Some(0),
                username_fragment: None,
            }
        );
        assert_eq!(
            candidate, original,
            "borrowed native input remains unchanged"
        );
        let signed = envelope(body.clone()).unwrap();
        let bytes = signed.encode_complete().unwrap();
        let decoded: crate::protocol::MeshMessage = serde_json::from_slice(&bytes).unwrap();
        let crate::protocol::MeshMessage::HubIntroduction(decoded) = decoded else {
            panic!("complete envelope must remain an introduction");
        };
        decoded
            .verify_for_previous_hop(signed.source(), signed.context_id())
            .unwrap();
        decoded
            .validate_challenge_binding(signed.challenge().unwrap())
            .unwrap();
        assert_eq!(decoded.body(), &body);
        assert_eq!(
            decoded.sequence(),
            2,
            "wire sequence only, not controller advancement"
        );
        assert_eq!(decoded.encode_complete().unwrap(), bytes);
    }

    #[test]
    fn hub_candidate_translation_preserves_nonempty_and_missing_metadata() {
        let mut candidate = bundled_candidate();
        candidate.candidate.push_str(" ufrag line-credential");
        candidate.sdp_mid = Some("audio-0".into());
        candidate.sdp_mline_index = Some(7);
        candidate.username_fragment = Some("different-structured-credential".into());
        let original = candidate.clone();
        assert_eq!(
            hub_introduction_candidate_body(&candidate),
            HubIntroductionBody::Candidate {
                candidate: candidate.candidate.clone(),
                sdp_mid: candidate.sdp_mid.clone(),
                sdp_mline_index: Some(7),
                username_fragment: candidate.username_fragment.clone(),
            },
            "conflicting nonempty metadata is preserved for native credential refusal"
        );
        assert_eq!(candidate, original);
        for optional in [None, Some(String::new())] {
            candidate.sdp_mid = optional.clone();
            candidate.username_fragment = optional;
            candidate.sdp_mline_index = None;
            assert_eq!(
                hub_introduction_candidate_body(&candidate),
                HubIntroductionBody::Candidate {
                    candidate: candidate.candidate.clone(),
                    sdp_mid: None,
                    sdp_mline_index: None,
                    username_fragment: None,
                },
                "normalization never invents a location or credential"
            );
        }
    }

    #[test]
    fn hub_candidate_translation_keeps_strict_metadata_and_body_limits() {
        let mut candidate = bundled_candidate();
        candidate.sdp_mid = Some("m".repeat(64));
        candidate.username_fragment = Some("u".repeat(64));
        let maximum_metadata = hub_introduction_candidate_body(&candidate);
        assert_eq!(
            envelope(maximum_metadata.clone()).unwrap().body(),
            &maximum_metadata
        );
        candidate.sdp_mid = Some("m".repeat(65));
        assert_eq!(
            envelope(hub_introduction_candidate_body(&candidate)),
            Err(HubIntroductionError::Body)
        );
        candidate.sdp_mid = Some("m".repeat(64));
        candidate.username_fragment = Some("u".repeat(65));
        assert_eq!(
            envelope(hub_introduction_candidate_body(&candidate)),
            Err(HubIntroductionError::Body)
        );
        candidate.username_fragment = None;
        candidate.candidate = "c".repeat(2048);
        assert!(envelope(hub_introduction_candidate_body(&candidate)).is_ok());
        candidate.candidate.push('c');
        assert_eq!(
            envelope(hub_introduction_candidate_body(&candidate)),
            Err(HubIntroductionError::Body)
        );
        candidate.candidate.clear();
        assert_eq!(
            envelope(hub_introduction_candidate_body(&candidate)),
            Err(HubIntroductionError::Body),
            "empty required candidate text is not repaired or accepted"
        );
    }
}

#[cfg(test)]
mod opaque_control_funding_tests {
    #[tokio::test]
    async fn opaque_control_output_and_completion_keep_disjoint_funding_until_last_owner() {
        let (state, _signaling, command_rx, provider, _grant) =
            crate::engine::build_test_state_parts_metered("opaque-control-custody", None, 2, None);
        state.park_command_receiver_for_test(command_rx);
        let baseline = provider.in_use();
        let completion =
            super::super::command::OpaqueControlCompletion::new(&state.local_resources).unwrap();
        let caller = completion.clone();
        let completion_charge = provider.in_use();
        assert_ne!(completion_charge, baseline);
        let wire = crate::application_gateway::FundedOpaqueControl::encode(
            &state.local_resources,
            &crate::application_gateway::OpaqueControlView::Close {
                coordinate: crate::protocol::ApplicationFlowCoordinate {
                    flow_id: 1,
                    generation: 1,
                },
                direction: crate::realtime::RealtimeFlowDirection::Outbound,
            },
        )
        .unwrap();
        assert_ne!(provider.in_use(), completion_charge);
        let decoded: crate::protocol::MeshMessage = serde_json::from_slice(wire.bytes()).unwrap();
        assert!(matches!(
            decoded,
            crate::protocol::MeshMessage::ApplicationFlowControl(
                crate::protocol::ApplicationFlowControl::Close { .. }
            )
        ));
        completion.finish(Ok(()));
        drop(completion);
        assert_ne!(
            provider.in_use(),
            baseline,
            "caller and output still own their real leases"
        );
        drop(wire);
        assert_eq!(
            provider.in_use(),
            completion_charge,
            "output charge leaves independently"
        );
        assert_eq!(caller.wait().await, Ok(()));
        drop(caller);
        let released = provider.in_use() == baseline;
        state.shutdown().await;
        assert!(released);
    }
}

#[cfg(test)]
mod shutdown_task_registry_tests {
    use super::ShutdownTaskRegistry;
    use std::sync::{Arc, Mutex};

    #[tokio::test]
    async fn v4_shutdown_task_registry_joins_and_observes_each_terminal_result() {
        let finished = Arc::new(Mutex::new(Vec::new()));
        let mut registry = ShutdownTaskRegistry::new();
        let first = Arc::clone(&finished);
        registry.push(
            tokio::spawn(async move {
                first.lock().expect("test witness lock").push("completed");
            }),
            false,
        );
        registry.push(
            tokio::spawn(async { panic!("test panic is observed") }),
            false,
        );

        let handles = registry.take_for_shutdown();
        assert!(registry.closed);
        assert!(registry.handles.is_empty());
        let mut outcomes = Vec::new();
        for task in handles {
            outcomes.push(task.handle.await);
        }
        assert!(outcomes[0].is_ok());
        assert!(outcomes[1]
            .as_ref()
            .expect_err("panic must be observed")
            .is_panic());
        assert_eq!(*finished.lock().expect("test witness lock"), ["completed"]);
    }

    #[tokio::test]
    async fn v4_shutdown_task_registry_cancels_and_observes_delayed_terminal() {
        let mut registry = ShutdownTaskRegistry::new();
        registry.push(
            tokio::spawn(async {
                std::future::pending::<()>().await;
            }),
            true,
        );

        let tasks = registry.take_for_shutdown();
        assert_eq!(tasks.len(), 1);
        for task in &tasks {
            if task.cancel_on_shutdown {
                task.handle.abort();
            }
        }
        let error = tasks
            .into_iter()
            .next()
            .expect("one delayed task")
            .handle
            .await
            .expect_err("shutdown cancellation is observed");
        assert!(error.is_cancelled());
    }
}

#[cfg(test)]
mod roster_projection_tests {
    #[test]
    fn v4_projection_refresh_persists_only_the_affected_key() {
        let state =
            crate::engine::build_test_closed_state("projection-save-before-commit", [0x2b; 32]);
        let device_id = state.identity.public_id().to_string();
        state.roster.write().authorized_devices.clear();
        state
            .refresh_roster_projection(&device_id, "owner")
            .expect("canonical projection should persist its keyed metadata");
        let roster = state.roster.read();
        assert!(roster
            .authorized_devices
            .iter()
            .any(|entry| entry.device_id == device_id));
    }
}

#[cfg(test)]
mod arc03_peer_registry_tests {
    use super::*;
    use crate::engine::connection::{PeerConnection, PeerStatus};
    use std::hint::black_box;
    use std::time::{Duration, Instant};

    #[test]
    fn v4_arc03_registry_scan_releases_map_guard_before_peer_callback() {
        let registry = Arc::new(PeerRegistry::default());
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-lock-order-peer".to_string(),
                None,
            )))
            .is_none());
        let scan = Arc::clone(&registry);
        let (finished_tx, finished_rx) = std::sync::mpsc::channel();

        std::thread::spawn(move || {
            let _: Vec<()> = scan.collect_map(|_| {
                assert!(scan
                    .install(Arc::new(PeerConnection::new(
                        "arc03-lock-order-peer".to_string(),
                        None,
                    )))
                    .is_some());
                None
            });
            let _ = finished_tx.send(());
        });

        finished_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("peer callback must run after every DashMap guard is released");
    }

    #[test]
    fn v4_arc03_stale_owner_cannot_remove_replacement_peer() {
        let registry = PeerRegistry::default();
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-owner-peer".to_string(),
                None,
            )))
            .is_none());
        let stale_owner = registry
            .owner("arc03-owner-peer")
            .expect("first owner is installed");
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "arc03-owner-peer".to_string(),
                None,
            )))
            .is_some());
        let replacement = registry
            .owner("arc03-owner-peer")
            .expect("replacement owner is installed");

        assert!(registry.remove_if_current(&stale_owner).is_none());
        assert!(registry.get_if_current(&stale_owner).is_none());
        assert!(registry.get_if_current(&replacement).is_some());
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn v4_r3_durable_owner_epoch_rejects_replacement() {
        let registry = PeerRegistry::default();
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "r3-owner-epoch".to_string(),
                None,
            )))
            .is_none());
        let first = registry
            .owner("r3-owner-epoch")
            .expect("first exact owner exists");
        let first_binding = first.binding_coordinate();
        assert!(registry
            .with_current_durable_outbox(&first, || ())
            .is_some());

        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "r3-owner-epoch".to_string(),
                None,
            )))
            .is_some());
        let replacement = registry
            .owner("r3-owner-epoch")
            .expect("replacement exact owner exists");
        assert_ne!(
            first_binding,
            replacement.binding_coordinate(),
            "replacement must have a distinct serializable binding coordinate"
        );
        let persisted = serde_json::to_string(&first.binding_coordinate()).expect("encode binding");
        let restored: crate::engine::peer_registry::PeerBindingCoordinate =
            serde_json::from_str(&persisted).expect("decode binding");
        assert_eq!(restored, first.binding_coordinate());
        assert!(registry
            .with_current_durable_outbox(&first, || ())
            .is_none());
        assert!(registry
            .with_current_durable_outbox(&replacement, || ())
            .is_some());
    }

    #[test]
    fn v4_r3_displaced_owner_settles_only_its_emission() {
        let registry = PeerRegistry::default();
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "r3-displaced-emission".to_string(),
                None,
            )))
            .is_none());
        let displaced = registry
            .owner("r3-displaced-emission")
            .expect("predecessor owner exists");
        assert!(registry
            .install(Arc::new(PeerConnection::new(
                "r3-displaced-emission".to_string(),
                None,
            )))
            .is_some());
        let successor = registry
            .owner("r3-displaced-emission")
            .expect("successor owner exists");

        let mut attempts = CarrierAttemptList::default();
        for (emission, owner) in [
            (SignalingEmissionId(1), displaced.clone()),
            (SignalingEmissionId(2), successor),
        ] {
            attempts.push_front(Box::new(CarrierAttemptNode {
                emission,
                attempt: "shared-attempt".to_string(),
                owner: Some(owner),
                _entry_lease: None,
                carriers: None,
                expected: 0,
                resolved: 0,
                accepted: false,
                claimed: false,
                fenced: false,
                terminal: None,
                next: None,
            }));
        }

        assert_eq!(
            attempts.emissions_for_owner(&displaced),
            vec![(SignalingEmissionId(1), "shared-attempt".to_string())]
        );
        assert!(attempts.settle_emission(SignalingEmissionId(1), "shared-attempt"));
        assert!(attempts
            .find_emission_mut(SignalingEmissionId(1), "shared-attempt")
            .is_none());
        assert!(attempts
            .find_emission_mut(SignalingEmissionId(2), "shared-attempt")
            .is_some());
    }

    #[test]
    fn v4_arc03_current_effect_linearizes_before_replacement() {
        let registry = Arc::new(PeerRegistry::default());
        let first = Arc::new(PeerConnection::new("arc03-effect-owner".to_string(), None));
        assert!(registry.install(Arc::clone(&first)).is_none());
        let owner = registry
            .owner("arc03-effect-owner")
            .expect("first installation has an owner stamp");
        let (effect_entered_tx, effect_entered_rx) = std::sync::mpsc::channel();
        let (release_effect_tx, release_effect_rx) = std::sync::mpsc::channel();
        let effect_registry = Arc::clone(&registry);
        let effect = std::thread::spawn(move || {
            effect_registry.with_current(&owner, |peer| {
                effect_entered_tx
                    .send(())
                    .expect("test observes the exact-owner effect");
                release_effect_rx
                    .recv()
                    .expect("test releases the exact-owner effect");
                peer.state.write().data_channel_open = true;
            })
        });
        effect_entered_rx
            .recv()
            .expect("exact-owner effect holds the registry transition");

        let replacement_registry = Arc::clone(&registry);
        let (replacement_done_tx, replacement_done_rx) = std::sync::mpsc::channel();
        let replacement = std::thread::spawn(move || {
            let replaced = replacement_registry.install(Arc::new(PeerConnection::new(
                "arc03-effect-owner".to_string(),
                None,
            )));
            replacement_done_tx
                .send(replaced.is_some())
                .expect("replacement reports completion");
        });
        assert!(
            replacement_done_rx.try_recv().is_err(),
            "replacement cannot pass an in-progress exact-owner effect"
        );

        release_effect_tx
            .send(())
            .expect("release the exact-owner effect");
        assert!(effect.join().expect("effect thread joins").is_some());
        assert!(replacement_done_rx
            .recv()
            .expect("replacement completes after the effect"));
        replacement.join().expect("replacement thread joins");

        assert!(first.state.read().data_channel_open);
        assert!(
            !registry
                .get("arc03-effect-owner")
                .expect("replacement remains installed")
                .state
                .read()
                .data_channel_open
        );
    }

    #[test]
    fn v4_arc03_retired_peer_arc_cannot_be_reinstalled() {
        let registry = PeerRegistry::default();
        let peer = Arc::new(PeerConnection::new(
            "arc03-reinstalled-owner".to_string(),
            None,
        ));
        assert!(registry.install(Arc::clone(&peer)).is_none());
        let stale_owner = registry
            .owner("arc03-reinstalled-owner")
            .expect("first installation has an owner stamp");
        assert!(registry.remove("arc03-reinstalled-owner").is_some());
        assert!(registry.install(peer).is_none());

        assert!(registry.get_if_current(&stale_owner).is_none());
        assert!(registry.remove_if_current(&stale_owner).is_none());
        assert!(registry.is_empty());
    }

    #[test]
    fn v4_arc03_installing_current_peer_arc_is_idempotent() {
        let registry = PeerRegistry::default();
        let peer = Arc::new(PeerConnection::new(
            "arc03-idempotent-owner".to_string(),
            None,
        ));
        assert!(registry.install(Arc::clone(&peer)).is_none());
        let owner = registry
            .owner("arc03-idempotent-owner")
            .expect("first installation has an owner stamp");

        assert!(registry.install(peer).is_none());
        assert!(registry.get_if_current(&owner).is_some());
        assert_eq!(registry.len(), 1);
    }

    fn scan_counts() -> Vec<usize> {
        std::env::var("MYOWNMESH_ARC03_PEER_SCAN_COUNTS")
            .expect("set MYOWNMESH_ARC03_PEER_SCAN_COUNTS to comma-separated sample counts")
            .split(',')
            .map(|value| {
                value
                    .trim()
                    .parse::<usize>()
                    .expect("every peer scan count must be a positive integer")
            })
            .inspect(|count| assert!(*count > 0, "peer scan counts must be positive"))
            .collect()
    }

    fn scan_rounds() -> usize {
        let rounds = std::env::var("MYOWNMESH_ARC03_PEER_SCAN_ROUNDS")
            .expect("set MYOWNMESH_ARC03_PEER_SCAN_ROUNDS")
            .parse::<usize>()
            .expect("peer scan rounds must be a positive integer");
        assert!(rounds > 0, "peer scan rounds must be positive");
        rounds
    }

    #[test]
    #[ignore = "manual release-mode scaling observation; requires explicit sample counts"]
    fn v4_arc03_peer_registry_scan_scaling() {
        let rounds = scan_rounds();
        for count in scan_counts() {
            let registry = PeerRegistry::default();
            for index in 0..count {
                let device_id = format!("arc03-scan-peer-{index:08}");
                let peer = Arc::new(PeerConnection::new(device_id.clone(), None));
                peer.state.write().status = PeerStatus::Active;
                assert!(registry.install(peer).is_none());
            }
            assert_eq!(registry.len(), count, "benchmark input cardinality");

            let old_started = Instant::now();
            for _ in 0..rounds {
                // The shape this harness exists to measure against: materialize a
                // keyed pair for every peer, then filter. Its cost is one id clone
                // per peer whether or not the peer survives the filter, plus the
                // intermediate vector. Reconstructed from `values_snapshot` rather
                // than read out of the map directly — the registry key *is* the
                // peer's device id, so cloning the field is the same work as
                // cloning the key, and the comparison stays honest without the
                // benchmark reaching into registry internals.
                let snapshot: Vec<(String, Arc<PeerConnection>)> = registry
                    .values_snapshot()
                    .into_iter()
                    .map(|peer| (peer.device_id.clone(), peer))
                    .collect();
                let active: Vec<String> = snapshot
                    .into_iter()
                    .filter(|(_, peer)| peer.state.read().status == PeerStatus::Active)
                    .map(|(key, _)| key)
                    .collect();
                assert_eq!(active.len(), count, "legacy scan output cardinality");
                black_box(active);
            }
            let old_elapsed = old_started.elapsed();

            let specialized_started = Instant::now();
            for _ in 0..rounds {
                let active = registry.collect_map(|peer| {
                    (peer.state.read().status == PeerStatus::Active).then(|| peer.device_id.clone())
                });
                assert_eq!(active.len(), count, "specialized scan output cardinality");
                black_box(active);
            }
            let specialized_elapsed = specialized_started.elapsed();

            println!(
                "arc03_peer_scan count={count} rounds={rounds} legacy_total_ns={} specialized_total_ns={} legacy_ns_per_peer={:.3} specialized_ns_per_peer={:.3}",
                old_elapsed.as_nanos(),
                specialized_elapsed.as_nanos(),
                old_elapsed.as_nanos() as f64 / (count * rounds) as f64,
                specialized_elapsed.as_nanos() as f64 / (count * rounds) as f64,
            );
        }
    }
}
