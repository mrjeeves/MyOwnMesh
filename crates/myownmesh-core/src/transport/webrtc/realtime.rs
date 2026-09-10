//! Codec-neutral connector-local real-time flow ownership and accounting.

use super::*;
use crate::resource::{
    ResourceAuthorityClass, ResourceClaim, ResourceClaimArithmeticError, ResourceClass,
    ResourceLease, ResourceUnavailable,
};
use crate::runtime::attempt::ConnectorWorkResourceScope;

/// Opaque process-local identity for one connector real-time flow.
///
/// The key is scheduling identity only. It is not serialized and grants no
/// authority. Codec, lane, and application-purpose names stay in the WebRTC
/// compatibility adapter that owns the corresponding flow port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(super) struct RealtimeFlowKey(usize);

/// Allocation-backed process-local identity for one admitted flow.
///
/// Its address is used only while this token remains alive. The flow lease is
/// acquired before this token is allocated, and the token remains inside the
/// flow lifetime until after the registry entry is removed. Refused opens
/// therefore consume no monotonic identity space.
struct RealtimeFlowIdentity;

/// Shared funding and cancellation state for one staged opaque Change.  Both
/// the flow record and its caller token retain this same object, so retirement
/// of either owner cannot leave the atomic marker's allocation unpriced.
pub(super) struct OpaqueChangeMarker {
    pub(super) active: std::sync::atomic::AtomicBool,
    pub(super) _root: ResourceLease,
}

impl OpaqueChangeMarker {
    pub(super) fn is_active(&self) -> bool {
        self.active.load(std::sync::atomic::Ordering::Acquire)
    }

    pub(super) fn cancel(&self) {
        self.active
            .store(false, std::sync::atomic::Ordering::Release);
    }
}

impl RealtimeFlowKey {
    fn from_identity(identity: &Arc<RealtimeFlowIdentity>) -> Self {
        Self(Arc::as_ptr(identity) as usize)
    }
}

/// Why one real-time acquisition was refused.
///
/// Seven owner-ceiling refusals used to stand beside these four: an active-flow
/// ceiling, a fragment byte and a fragment count ceiling, a unit byte ceiling, a
/// per-flow in-progress ceiling, a per-domain aggregate byte ceiling, and a
/// per-flow queue depth. Every one of them was reachable only on a registry the
/// owner had handed a local ceiling, and none of them is reachable now that no
/// owner can state one. They are deleted rather than kept as never-returned
/// names, because a refusal reason no code path can produce is a claim about
/// behaviour that does not happen.
///
/// What refuses real-time work now is what refused it on every elastic registry
/// already: an exact `ResourceClaim` the provider could not fund
/// (`ResourceUnavailable`), a registry with no connector scope at all
/// (`OwnerPolicyMissing`), a retired registry, and an ownership mismatch.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowDropReason {
    OwnerPolicyMissing,
    Retired,
    OwnershipMismatch,
    ResourceUnavailable(ResourceUnavailable),
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
pub(super) enum RealtimeObservedQuantity {
    Exact(usize),
    Inexact,
}

impl PartialEq<usize> for RealtimeObservedQuantity {
    fn eq(&self, other: &usize) -> bool {
        matches!(self, Self::Exact(value) if value == other)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum RealtimeFlowObservation {
    Flow {
        key: RealtimeFlowKey,
        domain: RealtimeFlowDomain,
        active_flows: RealtimeObservedQuantity,
    },
    Assembly {
        key: RealtimeFlowKey,
        in_progress_units: RealtimeObservedQuantity,
        retained_bytes: RealtimeObservedQuantity,
    },
    Queue {
        key: RealtimeFlowKey,
        units: usize,
        retained_bytes: RealtimeObservedQuantity,
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
    /// Exact ownership of the logical queued bytes. The queue node has its own
    /// lease and is released on dequeue; this lease follows the returned value
    /// until its transition to delivered payload completes.
    _queue_lease: ResourceLease,
    #[cfg(test)]
    _drop_probe: Option<TestQueuedRealtimeEventDropProbe>,
}

#[cfg(test)]
struct TestQueuedRealtimeEventDropProbe(Arc<std::sync::atomic::AtomicUsize>);

#[cfg(test)]
impl Drop for TestQueuedRealtimeEventDropProbe {
    fn drop(&mut self) {
        self.0.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
    }
}

impl QueuedRealtimeEvent {
    fn transition_to_delivered_payload(
        &mut self,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let reservation = match &mut self.event.event {
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_mut(),
            _ => None,
        }
        .ok_or(RealtimeFlowDropReason::OwnershipMismatch)?;
        reservation.transition_to_retained_payload()
    }
}

#[derive(Default)]
pub(super) struct RealtimeReadyQueue {
    head: Option<RealtimeFlowKey>,
    tail: Option<RealtimeFlowKey>,
    len: usize,
}

impl RealtimeReadyQueue {
    #[cfg(test)]
    pub(super) const fn is_empty(&self) -> bool {
        self.len == 0
    }

    #[cfg(test)]
    pub(super) const fn len(&self) -> usize {
        self.len
    }
}

/// One link of the retained-fragment list: the allocation, and the lease that
/// funds it.
///
/// The lease is a **sibling of** the `Box`, declared after it, and that order is
/// the whole point. A lease stored *inside* the node would be released by the
/// node's own drop glue — that is, before the allocation it is paying for is
/// freed — leaving a window in which the provider believes the bytes are back
/// while they are still held. Declared here and after `node`, the allocation is
/// freed first and the lease is returned second, which is the order the claim
/// describes.
struct FundedFragmentLeaseLink {
    node: Box<RealtimeFragmentLeaseNode>,
    _fragment: ResourceLease,
}

struct RealtimeFragmentLeaseNode {
    next: Option<FundedFragmentLeaseLink>,
}

#[derive(Default)]
struct RealtimeFragmentLeases {
    head: Option<FundedFragmentLeaseLink>,
}

impl RealtimeFragmentLeases {
    /// Retain one admitted fragment's lease for the assembly's lifetime.
    ///
    /// Each push allocates exactly one node, so the list holds as many
    /// allocations as it holds leases; the link the new lease joins is the one
    /// that owns the allocation made for it.
    fn push(&mut self, lease: ResourceLease) {
        self.head = Some(FundedFragmentLeaseLink {
            node: Box::new(RealtimeFragmentLeaseNode {
                next: self.head.take(),
            }),
            _fragment: lease,
        });
    }
}

impl Drop for RealtimeFragmentLeases {
    fn drop(&mut self) {
        // Avoid recursive destruction when a generic provider admits many
        // fragments. Provider capacity bounds every node even when no local
        // compatibility ceiling is installed.
        //
        // Unlinking first and letting `link` fall at the end of the iteration
        // keeps the per-node order: this node's allocation is freed, and only
        // then is the lease that funded it released.
        while let Some(mut link) = self.head.take() {
            self.head = link.node.next.take();
        }
    }
}

pub(super) struct RealtimeFlowQueue {
    domain: RealtimeFlowDomain,
    events: crate::resource::LeasedQueue<QueuedRealtimeEvent>,
    scheduled: bool,
    ready_previous: Option<RealtimeFlowKey>,
    ready_next: Option<RealtimeFlowKey>,
    ready_lease: Option<ResourceLease>,
    in_progress_units: usize,
}

pub(super) struct RealtimeFlowRegistryState {
    pub(super) flows: crate::resource::LeasedMap<RealtimeFlowKey, RealtimeFlowQueue>,
    pub(super) ready: RealtimeReadyQueue,
    pub(super) active_flows_by_domain: [usize; 2],
    pub(super) retained_bytes_by_domain: [usize; 2],
    pub(super) in_progress_units_by_domain: [usize; 2],
    pub(super) accounting_poisoned_by_domain: [bool; 2],
    pub(super) retired: bool,
    #[cfg(test)]
    fail_next_ready_push: bool,
    #[cfg(test)]
    next_queued_event_drop_probe: Option<Arc<std::sync::atomic::AtomicUsize>>,
}

pub(super) struct RealtimeFlowRegistry {
    /// Presence of this exact connector scope enables generic real-time work.
    /// It grants no capacity by itself.
    resources: Option<ConnectorWorkResourceScope>,
    // An optional owner ceiling and a per-unit byte maximum derived from it
    // used to sit here. Both are gone. Every branch that consulted them was
    // guarded on the ceiling being present, so a registry an owner left elastic
    // — the only kind an owner can build now — took none of them, and admission
    // is exactly what it already was on that path: the provider's leases.
    pub(super) state: SyncMutex<RealtimeFlowRegistryState>,
    pub(super) ready: tokio::sync::Notify,
    observer: Option<Arc<dyn RealtimeFlowObserver>>,
}

/// The resource objects an elastic control registry stands on.
///
/// Held by the control for as long as the registry is used. They are never
/// read — dropping them would retire the scope the registry acquires against,
/// so a control that discarded them would be measuring a dead provider rather
/// than an elastic one.
///
/// `cfg(test)` rather than the lab feature: every caller is an in-crate
/// control, and the lab controls are `#[test]`s too, so a feature-only library
/// build has nothing that could construct one.
#[cfg(test)]
pub(super) struct ElasticControlResources {
    /// The provider underneath, so a control can read what its registry is
    /// actually holding. Without it an elastic control could only assert that
    /// operations succeed — which is exactly what a path that charged nothing
    /// would also do.
    provider: crate::resource::FiniteResourceProvider,
    /// Retention, and nothing else. Dropping any of these retires the scope the
    /// registry acquires against, so a control that discarded them would be
    /// measuring a dead provider.
    _owner: crate::runtime::attempt::ConnectorResourceOwnerPort,
    _candidate: ConnectorCandidateCapability,
    _attempt: AttemptLifetime,
}

#[cfg(test)]
impl ElasticControlResources {
    /// How many accounted bytes the provider is currently holding out.
    ///
    /// One dimension rather than the whole claim, because what an elastic
    /// control needs to distinguish is "charged something" from "charged
    /// nothing", and bytes is the dimension every real-time lease touches.
    pub(super) fn accounted_bytes(&self) -> u64 {
        self.provider
            .in_use()
            .amount(ResourceClass::AccountedMemoryBytes)
    }

    pub(super) fn in_use(&self) -> ResourceClaim {
        self.provider.in_use()
    }
}

/// Exact finite ownership of the work one inbound RTP packet costs.
///
/// Held by the pump for the whole of that packet's iteration — classification,
/// reassembly, framing — and released when the iteration ends, whatever the
/// outcome. Retention that outlives the packet takes its own longer-lived
/// lease, so this one measures work rather than storage.
pub(super) struct RealtimeSessionPacketWorkLease {
    _lease: ResourceLease,
}

/// Exact ownership of one in-flight read from the opaque native RTP source.
///
/// The dependency chooses the returned packet size, so this guard owns the
/// read operation and one opaque dependency result until the caller replaces
/// it with the exact content-byte work lease.
pub(super) struct RealtimeNativeReadLease {
    _lease: ResourceLease,
}

impl RealtimeFlowRegistry {
    pub(super) fn new(resources: Option<ConnectorWorkResourceScope>) -> Arc<Self> {
        Self::with_observer(resources, None)
    }

    /// An elastic registry over a real provider.
    ///
    /// The only deployment there is. Controls that mint a label or move a unit
    /// against this are proving the elastic path admits through real leases —
    /// absence of a ceiling is not absence of accounting — rather than proving
    /// that admission was skipped.
    #[cfg(test)]
    pub(super) fn elastic_for_control(
        grant: ResourceClaim,
    ) -> (Arc<Self>, ElasticControlResources) {
        use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
        use crate::runtime::attempt::{
            admit_single_connector_candidate, ConnectorResourceOwnerPort,
        };
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the control grant accounts for the process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh_scope = owner
            .issue_mesh_scope()
            .expect("the control grant accounts for the Mesh scope");
        let (permit, attempt, claim) =
            admit_single_connector_candidate(crate::runtime::RuntimeIncarnation::new(), mesh_scope);
        let candidate = permit
            .reserve_connector_candidate_checked(claim)
            .expect("the control grant has no provider invariant failure")
            .expect("the exact attempt remains active");
        let registry = Self::new(Some(candidate.work_resource_scope()));
        (
            registry,
            ElasticControlResources {
                provider,
                _owner: owner,
                _candidate: candidate,
                _attempt: attempt,
            },
        )
    }

    pub(super) fn with_observer(
        resources: Option<ConnectorWorkResourceScope>,
        observer: Option<Arc<dyn RealtimeFlowObserver>>,
    ) -> Arc<Self> {
        Arc::new(Self {
            resources,
            state: SyncMutex::new(RealtimeFlowRegistryState {
                flows: crate::resource::LeasedMap::new(),
                ready: RealtimeReadyQueue::default(),
                active_flows_by_domain: [0; 2],
                retained_bytes_by_domain: [0; 2],
                in_progress_units_by_domain: [0; 2],
                accounting_poisoned_by_domain: [false; 2],
                retired: false,
                #[cfg(test)]
                fail_next_ready_push: false,
                #[cfg(test)]
                next_queued_event_drop_probe: None,
            }),
            ready: tokio::sync::Notify::new(),
            observer,
        })
    }

    fn record(&self, observation: RealtimeFlowObservation) {
        if let Some(observer) = self.observer.as_ref() {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                observer.observe(observation);
            }));
        }
    }

    fn claim_arithmetic_unavailable(error: ResourceClaimArithmeticError) -> ResourceUnavailable {
        let dimension = match error {
            ResourceClaimArithmeticError::Overflow { dimension }
            | ResourceClaimArithmeticError::Underflow { dimension } => dimension,
        };
        ResourceUnavailable::ProviderInvariant { dimension }
    }

    fn measured_bytes(bytes: usize) -> std::result::Result<u64, ResourceUnavailable> {
        u64::try_from(bytes).map_err(|_| ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        })
    }

    fn claim(
        entries: impl IntoIterator<Item = (ResourceClass, u64)>,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        ResourceClaim::try_from_entries(entries).map_err(Self::claim_arithmetic_unavailable)
    }

    pub(super) fn flow_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let record_bytes = std::mem::size_of::<RealtimeFlowLifetime>()
            .checked_add(std::mem::size_of::<RealtimeFlowIdentity>())
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(record_bytes)?,
            ),
            // One live flow owns one scheduling or pump obligation. Generic
            // flows may satisfy it without a dedicated task, but no provider
            // can admit the obligation without finite worker capacity.
            (ResourceClass::WorkerOrTask, 1),
            // The identity and lifetime allocations belong to the flow value.
            // The registry map node is a separate exact LeasedMap allocation.
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    /// The claim held by an application-owned opaque handle on the existing
    /// flow record.  The record already prices the inline `Option` through its
    /// map-node claim; this lease prices the one additional retained
    /// application claim and keeps remote-created dormant records from being
    /// used without an owner-funded local claim.
    pub(super) fn opaque_application_claim(
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(std::mem::size_of::<Option<ResourceLease>>())?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(super) fn acquire_opaque_application_claim(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::opaque_application_claim())
    }

    /// The one cancellation marker owned by a staged opaque Change.  The
    /// marker is shared with the caller token so dropping either owner keeps
    /// the marker allocation funded until the final holder goes away.
    pub(super) fn opaque_change_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::flow_root_claim(std::mem::size_of::<OpaqueChangeMarker>())
    }

    pub(super) fn acquire_opaque_change(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::opaque_change_claim())
    }

    pub(super) fn flow_map_node_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        crate::resource::LeasedMap::<RealtimeFlowKey, RealtimeFlowQueue>::entry_claim()
            .map_err(Self::claim_arithmetic_unavailable)
    }

    /// What one node of a [`crate::resource::LeasedQueue`] costs this owner.
    ///
    /// Split out from [`Self::acquire_queue_record`] so that the acquisition and
    /// any caller that needs to *predict* the acquisition read one expression.
    /// A control that restated the claim would keep passing after the queue's
    /// calibration changed, which is the failure a resource control exists to
    /// catch. Computing a claim charges nothing — only `acquire` does — so the
    /// two callers cannot bill the same node twice.
    pub(super) fn queue_node_claim<T>() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        crate::resource::LeasedQueue::<T>::entry_claim().map_err(Self::claim_arithmetic_unavailable)
    }

    /// The queue node one enqueued real-time event costs, for callers that must
    /// fund an enqueue without being able to name its element type.
    ///
    /// [`QueuedRealtimeEvent`] is private to this module and stays that way —
    /// its shape is this owner's business. A fixture building an exact grant
    /// still has to fund the node an enqueue allocates, and restating the claim
    /// on its side would keep passing after the queue's calibration changed,
    /// which is the failure a resource control exists to catch. So the type
    /// stays in and the number comes out.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(super) fn queued_event_node_claim(
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::queue_node_claim::<QueuedRealtimeEvent>()
    }

    /// Fund one node of a caller-owned [`crate::resource::LeasedMap`] against
    /// this owner.
    ///
    /// Generic over the map's key and value rather than taking a byte count, so
    /// the node's size is read from the concrete node type by the map's own
    /// calibration and is never restated here. One entry is one allocation and
    /// this lease lives in it — which is the property an ordered map of shared
    /// nodes cannot offer, because there an entry's departure says nothing about
    /// whether an allocation departed with it.
    pub(super) fn acquire_map_entry<K, V>(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(
            crate::resource::LeasedMap::<K, V>::entry_claim()
                .map_err(Self::claim_arithmetic_unavailable),
        )
    }

    /// Fund one node of a caller-owned [`crate::resource::LeasedQueue`] against
    /// this owner.
    ///
    /// Generic over the queue's element rather than taking a byte count, so the
    /// node's size is read from the concrete node type by the queue's own
    /// calibration and is never restated here. Nothing is added for what the
    /// element points at off-heap: those allocations hold their own leases
    /// already, and charging them again would bill one allocation twice and
    /// release it once.
    pub(super) fn acquire_queue_record<T>(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::queue_node_claim::<T>())
    }

    pub(super) fn ready_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        // Ready links are embedded in the map value and funded by its exact map
        // node. This lease owns only the live scheduling obligation.
        Self::claim([(ResourceClass::CallbackOrScheduledWork, 1)])
    }

    pub(super) fn assembly_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(std::mem::size_of::<RealtimeAssemblyReservation>())?,
            ),
            (ResourceClass::CallbackOrScheduledWork, 1),
        ])
    }

    /// The cost of retaining one inbound fragment until its unit completes.
    ///
    /// Two dependency nodes: the retained-lease list node this fragment pushes,
    /// and the ordered payload entry the assembler keeps it in. Both persist for
    /// exactly the assembly lifetime.
    ///
    /// The byte term is the boxed node's own shape, which is what a push
    /// allocates — exactly one node per fragment. The lease that funds that
    /// allocation is not inside it: it sits beside the pointer in
    /// [`FundedFragmentLeaseLink`], so it is still held when the node is freed.
    pub(super) fn ordered_fragment_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimeFragmentLeaseNode>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::ParsingOrCpuWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    pub(super) fn output_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimePayloadReservation>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// The exact allocation claim for a provider custody box.  The queue entry
    /// inside the box already carries its own node and payload leases; this
    /// prices only the wrapper allocation itself so dequeue cannot expose an
    /// unfunded move-only arrival.
    pub(super) fn boxed_claim<T>() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(std::mem::size_of::<T>())?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(super) fn acquire_boxed<T>(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::boxed_claim::<T>())
    }

    pub(super) fn retained_payload_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let retained_bytes = std::mem::size_of::<RealtimePayloadReservation>()
            .checked_add(content_bytes)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    pub(super) fn queue_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([(
            ResourceClass::QueuedBytes,
            Self::measured_bytes(content_bytes)?,
        )])
    }

    /// The per-packet cost of classifying and framing one inbound RTP payload.
    ///
    /// Sized by the payload it covers, so a large packet costs more than a small
    /// one and the provider is the thing that says no. Retained fragments and
    /// complete outputs acquire their own longer-lived leases on top of this.
    pub(super) fn session_packet_work_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(content_bytes)?,
            ),
            (ResourceClass::ParsingOrCpuWork, 1),
        ])
    }

    /// One shared block a flow's constructors allocate, and the counters the
    /// `Arc` around it puts beside the contents.
    ///
    /// Deliberately per block rather than per flow. The blocks an open
    /// allocates do not share a lifetime: the outbound queue is reached only
    /// through the flow's own strong pointer, while both wakes are handed to a
    /// pump strongly *because* they have to outlive the thing whose death they
    /// announce. A combined claim would have to be released at whichever of
    /// those moments the caller chose, and either choice is wrong for the other
    /// blocks — early for the wakes, or late for the queue. One claim per block
    /// lets each lease live inside the block it funds and be released by that
    /// block's last holder.
    ///
    /// Three terms, the same shape as [`Self::label_claim`] and for the same
    /// reason: the record itself, the strong/weak counter pair the `Arc` puts
    /// beside it, and one residual for the one allocation. There is no separate
    /// content term because these records point at nothing further — anything
    /// they do point at holds its own lease and would otherwise be charged
    /// twice.
    pub(super) fn flow_root_claim(
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let overflow = || ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        };
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let retained_bytes = content_bytes
            .checked_add(arc_counters)
            .ok_or_else(overflow)?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Take the lease that owns one such block, before the block exists.
    ///
    /// Separate from the flow's own admission because the lifetimes are
    /// separate: this lease is stored inside the record it funds and released
    /// when the last holder of that record drops, which for a wake is later
    /// than the close and for the queue is exactly the close.
    pub(super) fn acquire_flow_root(
        &self,
        content_bytes: usize,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::flow_root_claim(content_bytes))
            .map_err(|reason| self.record_drop(None, reason, 0))
    }

    /// One native pump/retirement's scheduling obligation.  It is acquired
    /// before the asynchronous owner is published and travels with that owner
    /// until its native work reaches a terminal result.
    pub(super) fn native_tail_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([(ResourceClass::WorkerOrTask, 1)])
    }

    pub(super) fn acquire_native_tail(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::native_tail_claim())
    }

    /// Fund the one shared counter block used by a promoted session's native
    /// tail witness. Its lease is retained by that block while delayed owners
    /// still hold an `Arc` to it.
    pub(super) fn acquire_native_tail_state(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        let counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::AccountedMemoryBytes,
            })
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        let bytes =
            std::mem::size_of::<crate::transport::webrtc::session_flow::RealtimeNativeTailState>()
                .checked_add(counters)
                .ok_or(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::AccountedMemoryBytes,
                })
                .map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        let measured =
            Self::measured_bytes(bytes).map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        self.acquire(Self::claim([
            (ResourceClass::AccountedMemoryBytes, measured),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ]))
    }

    pub(super) fn native_read_claim() -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        Self::claim([
            (ResourceClass::CallbackOrScheduledWork, 1),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Everything one shared label record costs, for as long as anything holds
    /// it.
    ///
    /// `record_bytes` is `size_of::<LeasedLabel>()` — the struct itself, which
    /// contains the name's boxed-slice header and the lease handle.
    /// `content_bytes` is the byte buffer that header points at, and it is
    /// exact rather than approximate: the name is a `Box<[u8]>`, so it has no
    /// spare capacity and its length *is* its allocation. `arc_counters` is the
    /// strong/weak pair the `Arc` puts beside the record. Three terms because
    /// the allocation genuinely has three parts, and stating fewer would
    /// under-charge by whichever was omitted.
    ///
    /// The residual is 2 because the representation retains two allocations:
    /// the `Arc` block and the byte buffer. It follows the representation — an
    /// inline single-allocation DST would make it 1 — and it counts allocator
    /// overhead, which has no portable size. It is a count, never a substitute
    /// for the bytes above.
    ///
    /// Charged once against the record every copy of the label shares, so a
    /// label sitting simultaneously in the held set, the flows map, a queued
    /// arrival, an inbound binding and a close event is paid for once and paid
    /// for until the *last* of those drops, not until the flow does.
    pub(super) fn label_claim(
        record_bytes: usize,
        content_bytes: usize,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let overflow = || ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        };
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let retained_bytes = record_bytes
            .checked_add(content_bytes)
            .and_then(|bytes| bytes.checked_add(arc_counters))
            .ok_or_else(overflow)?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    /// Take the lease that owns one label's bytes.
    ///
    /// Separate from every other acquisition here because a label is not a
    /// flow: it is minted when a session accepts the name and released when the
    /// last retained copy drops, and those are different moments from the
    /// flow's open and close. Refusal is the ordinary typed refusal — a
    /// provider under pressure declines the name and the open fails closed,
    /// rather than retaining bytes nothing accounted for.
    pub(super) fn acquire_label_lease(
        &self,
        record_bytes: usize,
        content_bytes: usize,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::label_claim(record_bytes, content_bytes))
            .map_err(|reason| self.record_drop(None, reason, 0))
    }

    /// Everything one shared real-time profile costs on the heap.
    ///
    /// A profile is deep: a `Vec` of codecs, each carrying a `mime` and `fmtp`
    /// `String` and a `Vec` of feedback entries with two `String`s apiece.
    /// Deep enough that cloning it per promotion would cost more than any
    /// promotion accounts for, so it is shared behind an `Arc`: charged once, by
    /// the connector that registered it, and a promotion clones a pointer.
    ///
    /// Measured by walking the actual strings and vectors rather than by any
    /// per-codec estimate: the deployed profile is five H.264 variants whose
    /// `fmtp` lines differ in length, so an average would be wrong in both
    /// directions.
    /// Three terms, the same shape as [`Self::label_claim`] and for the same
    /// reason: the record itself, the heap it points at, and the strong/weak
    /// counter pair the `Arc` puts beside the record. The counters are not
    /// optional bookkeeping — they are retained for exactly as long as the
    /// record is — and omitting them here while charging them for a label
    /// would have made two shared records of the same shape cost differently.
    pub(super) fn profile_claim(
        record_bytes: usize,
        content_bytes: usize,
        allocations: u64,
    ) -> std::result::Result<ResourceClaim, ResourceUnavailable> {
        let overflow = || ResourceUnavailable::ProviderInvariant {
            dimension: ResourceClass::AccountedMemoryBytes,
        };
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let retained_bytes = record_bytes
            .checked_add(content_bytes)
            .and_then(|bytes| bytes.checked_add(arc_counters))
            .ok_or_else(overflow)?;
        Self::claim([
            (
                ResourceClass::AccountedMemoryBytes,
                Self::measured_bytes(retained_bytes)?,
            ),
            (ResourceClass::OpaqueDependencyResidual, allocations),
        ])
    }

    /// Take the lease that owns one shared profile record.
    ///
    /// Separate from every other acquisition here for the same reason the
    /// label's is: a profile is minted when the connector accepts the
    /// application's registration and released when the last session holding it
    /// drops, and neither moment is a flow's open or close.
    pub(super) fn acquire_profile_lease(
        &self,
        record_bytes: usize,
        content_bytes: usize,
        allocations: u64,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.acquire(Self::profile_claim(
            record_bytes,
            content_bytes,
            allocations,
        ))
        .map_err(|reason| self.record_drop(None, reason, 0))
    }

    fn acquire(
        &self,
        claim: std::result::Result<ResourceClaim, ResourceUnavailable>,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        let claim = claim.map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        let resources = self
            .resources
            .as_ref()
            .ok_or(RealtimeFlowDropReason::OwnerPolicyMissing)?;
        resources
            .acquire(ResourceAuthorityClass::Speculative, claim)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)
    }

    fn record_drop(
        &self,
        key: Option<RealtimeFlowKey>,
        reason: RealtimeFlowDropReason,
        payload_bytes: usize,
    ) -> RealtimeFlowDropReason {
        self.record(RealtimeFlowObservation::Drop {
            key,
            reason,
            queue_age: Duration::ZERO,
            payload_bytes,
        });
        reason
    }

    #[allow(
        clippy::result_large_err,
        reason = "the failure returns the exact move-only ready-node lease without allocating under pressure"
    )]
    fn push_ready_locked(
        state: &mut RealtimeFlowRegistryState,
        key: RealtimeFlowKey,
        lease: ResourceLease,
    ) -> std::result::Result<(), ResourceLease> {
        #[cfg(test)]
        if std::mem::take(&mut state.fail_next_ready_push) {
            return Err(lease);
        }
        let previous = state.ready.tail;
        let can_link = state
            .flows
            .get(&key)
            .is_some_and(|flow| !flow.scheduled && flow.ready_lease.is_none())
            && previous.is_none_or(|previous| state.flows.contains_key(&previous));
        let Some(next_len) = state.ready.len.checked_add(1) else {
            return Err(lease);
        };
        if !can_link {
            return Err(lease);
        }

        if let Some(previous) = previous {
            state
                .flows
                .get_mut(&previous)
                .expect("the ready predecessor was validated")
                .ready_next = Some(key);
        } else {
            state.ready.head = Some(key);
        }
        let flow = state
            .flows
            .get_mut(&key)
            .expect("the ready flow was validated");
        flow.scheduled = true;
        flow.ready_previous = previous;
        flow.ready_next = None;
        flow.ready_lease = Some(lease);
        state.ready.tail = Some(key);
        state.ready.len = next_len;
        Ok(())
    }

    #[cfg(test)]
    fn fail_next_ready_push_for_test(&self, drop_probe: Arc<std::sync::atomic::AtomicUsize>) {
        let mut state = self.state.lock();
        state.fail_next_ready_push = true;
        state.next_queued_event_drop_probe = Some(drop_probe);
    }

    fn pop_ready_locked(
        state: &mut RealtimeFlowRegistryState,
    ) -> Option<(RealtimeFlowKey, ResourceLease)> {
        let key = state.ready.head?;
        let (next, lease) = {
            let flow = state.flows.get_mut(&key)?;
            let lease = flow.ready_lease.take()?;
            let next = flow.ready_next.take();
            flow.ready_previous = None;
            flow.scheduled = false;
            (next, lease)
        };
        state.ready.head = next;
        if let Some(next) = next {
            state
                .flows
                .get_mut(&next)
                .expect("a ready successor remains in the registry")
                .ready_previous = None;
        } else {
            state.ready.tail = None;
        }
        state.ready.len = state
            .ready
            .len
            .checked_sub(1)
            .expect("a ready head contributes one ready entry");
        Some((key, lease))
    }

    fn unlink_ready_locked(
        state: &mut RealtimeFlowRegistryState,
        key: RealtimeFlowKey,
    ) -> Option<ResourceLease> {
        let (previous, next, lease) = {
            let flow = state.flows.get_mut(&key)?;
            if !flow.scheduled {
                return None;
            }
            let lease = flow.ready_lease.take()?;
            let previous = flow.ready_previous.take();
            let next = flow.ready_next.take();
            flow.scheduled = false;
            (previous, next, lease)
        };
        if let Some(previous) = previous {
            state
                .flows
                .get_mut(&previous)
                .expect("a ready predecessor remains in the registry")
                .ready_next = next;
        } else {
            state.ready.head = next;
        }
        if let Some(next) = next {
            state
                .flows
                .get_mut(&next)
                .expect("a ready successor remains in the registry")
                .ready_previous = previous;
        } else {
            state.ready.tail = previous;
        }
        state.ready.len = state
            .ready
            .len
            .checked_sub(1)
            .expect("a linked flow contributes one ready entry");
        Some(lease)
    }

    fn open_flow_checked(
        self: &Arc<Self>,
        domain: RealtimeFlowDomain,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        if self.resources.is_none() {
            return Err(self.record_drop(None, RealtimeFlowDropReason::OwnerPolicyMissing, 0));
        }
        // Admission happens before either the flow owner or its registry entry
        // is allocated. The lease follows the flow lifetime through removal.
        let lease = self
            .acquire(Self::flow_claim())
            .map_err(|reason| self.record_drop(None, reason, 0))?;
        let map_node = self
            .acquire(Self::flow_map_node_claim())
            .map_err(|reason| self.record_drop(None, reason, 0))?;
        let identity = Arc::new(RealtimeFlowIdentity);
        let key = RealtimeFlowKey::from_identity(&identity);
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        let active_in_domain = state.active_flows_by_domain[domain.index()];
        if state
            .flows
            .insert(
                key,
                RealtimeFlowQueue {
                    domain,
                    events: crate::resource::LeasedQueue::new(),
                    scheduled: false,
                    ready_previous: None,
                    ready_next: None,
                    ready_lease: None,
                    in_progress_units: 0,
                },
                map_node,
            )
            .is_err()
        {
            return Err(RealtimeFlowDropReason::OwnershipMismatch);
        }
        let Some(active_flows) = active_in_domain.checked_add(1) else {
            self.poison_domain_locked(&mut state, domain);
            state.flows.remove_entry(&key);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            ));
        };
        state.active_flows_by_domain[domain.index()] = active_flows;
        drop(state);
        self.record(RealtimeFlowObservation::Flow {
            key,
            domain,
            active_flows: RealtimeObservedQuantity::Exact(active_flows),
        });
        Ok(RealtimeFlowPort {
            lifetime: Arc::new(RealtimeFlowLifetime {
                key,
                registry: Arc::clone(self),
                _identity: identity,
                _lease: lease,
            }),
        })
    }

    pub(super) fn open_inbound_flow_checked(
        self: &Arc<Self>,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        self.open_flow_checked(RealtimeFlowDomain::InboundQuarantine)
    }

    #[cfg(test)]
    pub(super) fn open_inbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_inbound_flow_checked().ok()
    }

    pub(super) fn open_outbound_flow_checked(
        self: &Arc<Self>,
    ) -> std::result::Result<RealtimeFlowPort, RealtimeFlowDropReason> {
        self.open_flow_checked(RealtimeFlowDomain::OutboundCompatibility)
    }

    #[cfg(test)]
    pub(super) fn open_outbound_flow(self: &Arc<Self>) -> Option<RealtimeFlowPort> {
        self.open_outbound_flow_checked().ok()
    }

    fn remove_flow(&self, key: RealtimeFlowKey) {
        let mut state = self.state.lock();
        let ready_lease = Self::unlink_ready_locked(&mut state, key);
        if let Some((_stored_key, flow)) = state.flows.remove_entry(&key) {
            let domain = flow.domain;
            let active_flows = match state.active_flows_by_domain[domain.index()].checked_sub(1) {
                Some(active) => {
                    state.active_flows_by_domain[domain.index()] = active;
                    RealtimeObservedQuantity::Exact(active)
                }
                None => {
                    self.poison_domain_locked(&mut state, domain);
                    RealtimeObservedQuantity::Inexact
                }
            };
            drop(state);
            self.record(RealtimeFlowObservation::Flow {
                key,
                domain,
                active_flows,
            });
            // Drop queued payloads after releasing the registry mutex. Their
            // exact byte leases return capacity through the same registry.
            drop(ready_lease);
            drop(flow);
        }
    }

    fn retained_bytes(state: &RealtimeFlowRegistryState) -> RealtimeObservedQuantity {
        if state
            .accounting_poisoned_by_domain
            .into_iter()
            .any(|poisoned| poisoned)
        {
            return RealtimeObservedQuantity::Inexact;
        }
        state.retained_bytes_by_domain[0]
            .checked_add(state.retained_bytes_by_domain[1])
            .map(RealtimeObservedQuantity::Exact)
            .unwrap_or(RealtimeObservedQuantity::Inexact)
    }

    pub(super) fn in_progress_units(state: &RealtimeFlowRegistryState) -> RealtimeObservedQuantity {
        if state
            .accounting_poisoned_by_domain
            .into_iter()
            .any(|poisoned| poisoned)
        {
            return RealtimeObservedQuantity::Inexact;
        }
        state.in_progress_units_by_domain[0]
            .checked_add(state.in_progress_units_by_domain[1])
            .map(RealtimeObservedQuantity::Exact)
            .unwrap_or(RealtimeObservedQuantity::Inexact)
    }

    /// Mark one domain's local observation untrustworthy.
    ///
    /// It used to also pin the domain's retained-byte counter to the owner's
    /// ceiling, so that a damaged domain refused every later admission against
    /// that ceiling. There is no ceiling to pin it to any more, and there is
    /// nothing to refuse against: what admits real-time work is the provider,
    /// which does its own exact accounting and is unaffected by this flag. So
    /// this now does the one thing it always did on an elastic registry —
    /// stop reporting a number that would be wrong.
    fn poison_domain_locked(
        &self,
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
    ) {
        state.accounting_poisoned_by_domain[domain.index()] = true;
    }

    fn release_bytes_locked(
        &self,
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
                self.poison_domain_locked(state, domain);
                false
            }
        }
    }

    fn release_unit_locked(
        &self,
        state: &mut RealtimeFlowRegistryState,
        domain: RealtimeFlowDomain,
    ) -> bool {
        if state.accounting_poisoned_by_domain[domain.index()] {
            return false;
        }
        let index = domain.index();
        match state.in_progress_units_by_domain[index].checked_sub(1) {
            Some(units) => {
                state.in_progress_units_by_domain[index] = units;
                true
            }
            None => {
                self.poison_domain_locked(state, domain);
                false
            }
        }
    }

    pub(super) fn begin_unit_checked(
        self: &Arc<Self>,
        lifetime: Arc<RealtimeFlowLifetime>,
    ) -> std::result::Result<RealtimeAssemblyReservation, RealtimeFlowDropReason> {
        let key = lifetime.key;
        let lease = self
            .acquire(Self::assembly_claim())
            .map_err(|reason| self.record_drop(Some(key), reason, 0))?;
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        let domain = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .domain;
        let current_flow_units = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .in_progress_units;
        let Some(next_flow_units) = current_flow_units.checked_add(1) else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                },
            ));
        };
        let index = domain.index();
        let Some(next_domain_units) = state.in_progress_units_by_domain[index].checked_add(1)
        else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                },
            ));
        };
        let Some(flow) = state.flows.get_mut(&key) else {
            self.poison_domain_locked(&mut state, domain);
            return Err(RealtimeFlowDropReason::Retired);
        };
        flow.in_progress_units = next_flow_units;
        state.in_progress_units_by_domain[index] = next_domain_units;
        let in_progress_units = Self::in_progress_units(&state);
        let retained_bytes = Self::retained_bytes(&state);
        drop(state);
        self.record(RealtimeFlowObservation::Assembly {
            key,
            in_progress_units,
            retained_bytes,
        });
        Ok(RealtimeAssemblyReservation {
            registry: Arc::clone(self),
            key,
            domain,
            _lifetime: lifetime,
            fragment_leases: RealtimeFragmentLeases::default(),
            retained_bytes: 0,
            retained_fragments: 0,
            active: true,
            _lease: lease,
        })
    }

    /// Admit the work of classifying one inbound RTP packet on an open flow.
    ///
    /// **Accounting, not admission.** The caller is the pump for a track that
    /// already attached to a binding the promoted session established, so the
    /// question of whether this packet may be processed at all was answered
    /// before this pump existed. What is decided here is whether the provider
    /// can currently afford the work.
    ///
    /// There is deliberately no cumulative packet or byte envelope. A ceiling
    /// that latches would end a long-lived session at an arbitrary packet
    /// count, and one that resets would be a timer by another name. Sustained
    /// inbound pressure is bounded where it is actually held — the exact
    /// per-packet claim below, and the exact claim every fragment, unit and
    /// queued event takes after it — each of which releases as the work
    /// completes.
    pub(super) fn admit_session_packet_checked(
        &self,
        payload_bytes: usize,
    ) -> std::result::Result<RealtimeSessionPacketWorkLease, RealtimeFlowDropReason> {
        let work = self
            .acquire(Self::session_packet_work_claim(payload_bytes))
            .map_err(|reason| self.record_drop(None, reason, payload_bytes))?;
        if self.state.lock().retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        Ok(RealtimeSessionPacketWorkLease { _lease: work })
    }

    pub(super) fn begin_native_read_checked(
        &self,
    ) -> std::result::Result<RealtimeNativeReadLease, RealtimeFlowDropReason> {
        let lease = self
            .acquire(Self::native_read_claim())
            .map_err(|reason| self.record_drop(None, reason, 0))?;
        if self.state.lock().retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        Ok(RealtimeNativeReadLease { _lease: lease })
    }

    #[cfg(test)]
    pub(super) fn admit_session_packet(&self, payload_bytes: usize) -> bool {
        self.admit_session_packet_checked(payload_bytes).is_ok()
    }

    pub(super) fn reserve_output_checked(
        self: &Arc<Self>,
        key: RealtimeFlowKey,
        bytes: usize,
    ) -> std::result::Result<RealtimeOutputReservation, RealtimeFlowDropReason> {
        // There is no oversize refusal in front of this: the lease below is the
        // admission, and a provider under pressure is what says no.
        let lease = self
            .acquire(Self::output_claim(bytes))
            .map_err(|reason| self.record_drop(Some(key), reason, bytes))?;
        let mut state = self.state.lock();
        if state.retired {
            return Err(RealtimeFlowDropReason::Retired);
        }
        let domain = state
            .flows
            .get(&key)
            .ok_or(RealtimeFlowDropReason::Retired)?
            .domain;
        let index = domain.index();
        match state.retained_bytes_by_domain[index].checked_add(bytes) {
            Some(next) => state.retained_bytes_by_domain[index] = next,
            None => {
                // Provider accounting remains authoritative. Mark the local
                // observation inexact without inventing a replacement value.
                self.poison_domain_locked(&mut state, domain);
            }
        }
        drop(state);
        Ok(RealtimeOutputReservation {
            registry: Arc::clone(self),
            key,
            domain,
            lease: Some(lease),
            bytes,
            active: true,
        })
    }

    pub(super) fn enqueue_checked(
        &self,
        key: RealtimeFlowKey,
        mut event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        if !std::ptr::eq(self, Arc::as_ref(&reservation.registry))
            || reservation.key != key
            || !reservation.active
        {
            return Err(RealtimeFlowDropReason::OwnershipMismatch);
        }
        // The queue record and queued-byte claim are separate from the payload
        // lease. Dequeue releases this lease while payload clones retain theirs.
        let queue_lease = self
            .acquire(Self::queue_claim(reservation.bytes))
            .map_err(|reason| self.record_drop(Some(key), reason, reservation.bytes))?;
        let queue_node = self.acquire_queue_record::<QueuedRealtimeEvent>()?;
        let now = Instant::now();
        let domain = reservation.domain;
        let payload_bytes = reservation.bytes;
        let reservation = reservation.into_payload_lease();
        if let Err(reservation) = event.attach_realtime_reservation(reservation) {
            drop(reservation);
            return Err(RealtimeFlowDropReason::OwnershipMismatch);
        }
        let mut event = Some(event);
        let mut queue_lease = Some(queue_lease);
        let mut queue_node = Some(queue_node);
        let mut ready_lease = None;
        let (units, retained_bytes) = loop {
            let mut state = self.state.lock();
            if state.retired {
                return Err(RealtimeFlowDropReason::Retired);
            }
            let Some(flow) = state.flows.get(&key) else {
                drop(state);
                return Err(self.record_drop(
                    Some(key),
                    RealtimeFlowDropReason::Retired,
                    payload_bytes,
                ));
            };
            if flow.domain != domain {
                self.poison_domain_locked(&mut state, domain);
                return Err(RealtimeFlowDropReason::OwnershipMismatch);
            }
            // No per-flow queue depth stands here, and therefore no overflow
            // rule choosing which admitted event to destroy. What bounds this
            // queue is that every event in it holds an exact queue record and
            // an exact byte lease, both taken above against the provider: a
            // queue that cannot be funded cannot grow, and the refusal names
            // the resource rather than a number the owner picked.
            let needs_ready = flow.events.is_empty() && !flow.scheduled;
            if needs_ready && ready_lease.is_none() {
                drop(state);
                ready_lease = Some(
                    self.acquire(Self::ready_claim())
                        .map_err(|reason| self.record_drop(Some(key), reason, payload_bytes))?,
                );
                continue;
            }

            #[cfg(test)]
            let drop_probe = state
                .next_queued_event_drop_probe
                .take()
                .map(TestQueuedRealtimeEventDropProbe);
            state
                .flows
                .get_mut(&key)
                .expect("the validated flow remains under the registry lock")
                .events
                .push(
                    QueuedRealtimeEvent {
                        event: event
                            .take()
                            .expect("the event is moved exactly once into its admitted queue"),
                        queued_at: now,
                        payload_bytes,
                        _queue_lease: queue_lease
                            .take()
                            .expect("the queue lease is moved with its exact queue record"),
                        #[cfg(test)]
                        _drop_probe: drop_probe,
                    },
                    queue_node
                        .take()
                        .expect("the node lease moves with its exact node"),
                );
            if needs_ready {
                let lease = ready_lease
                    .take()
                    .expect("ready admission acquired the exact scheduling lease");
                if let Err(lease) = Self::push_ready_locked(&mut state, key, lease) {
                    let event = state
                        .flows
                        .get_mut(&key)
                        .and_then(|flow| flow.events.pop_back());
                    drop(state);
                    drop(lease);
                    drop(event);
                    return Err(RealtimeFlowDropReason::OwnershipMismatch);
                }
            }
            let units = state.flows.get(&key).map_or(0, |flow| flow.events.len());
            let retained_bytes = Self::retained_bytes(&state);
            break (units, retained_bytes);
        };
        drop(ready_lease);
        self.record(RealtimeFlowObservation::Queue {
            key,
            units,
            retained_bytes,
        });
        self.ready.notify_one();
        Ok(())
    }

    pub(super) fn try_recv(&self) -> Option<QueuedTransportEvent> {
        loop {
            let now = Instant::now();
            let mut state = self.state.lock();
            if state.retired {
                return None;
            }
            let (key, ready_lease) = Self::pop_ready_locked(&mut state)?;
            let Some(flow) = state.flows.get_mut(&key) else {
                drop(state);
                drop(ready_lease);
                continue;
            };
            let Some(mut event) = flow.events.pop_front() else {
                drop(state);
                drop(ready_lease);
                continue;
            };
            let unused_ready_lease = if !flow.events.is_empty() {
                if let Err(lease) = Self::push_ready_locked(&mut state, key, ready_lease) {
                    drop(state);
                    drop(lease);
                    drop(event);
                    self.record_drop(Some(key), RealtimeFlowDropReason::OwnershipMismatch, 0);
                    continue;
                }
                None
            } else {
                Some(ready_lease)
            };
            drop(state);
            drop(unused_ready_lease);
            if let Err(reason) = event.transition_to_delivered_payload() {
                self.record_drop(Some(key), reason, event.payload_bytes);
                drop(event);
                continue;
            }
            self.record(RealtimeFlowObservation::Service {
                key,
                queue_age: now.saturating_duration_since(event.queued_at),
                payload_bytes: event.payload_bytes,
            });
            return Some(event.event);
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        !self
            .state
            .lock()
            .flows
            .any_value(|flow| !flow.events.is_empty())
    }

    /// Stop all later flow work and release every queued complete unit.
    /// In-progress assembly reservations remain with their exact owners and
    /// release when those owners return or are cancelled.
    pub(super) fn retire(&self) {
        {
            let mut state = self.state.lock();
            if state.retired {
                return;
            }
            state.retired = true;
        }
        loop {
            let ready_lease = {
                let mut state = self.state.lock();
                Self::pop_ready_locked(&mut state).map(|(_, lease)| lease)
            };
            let Some(ready_lease) = ready_lease else {
                break;
            };
            drop(ready_lease);
        }
        loop {
            let queued = {
                let mut state = self.state.lock();
                state
                    .flows
                    .find_value_mut(|flow| !flow.events.is_empty())
                    .and_then(|flow| flow.events.pop_front())
            };
            let Some(queued) = queued else {
                break;
            };
            drop(queued);
        }
        self.ready.notify_waiters();
    }
}

pub(super) struct RealtimeFlowLifetime {
    key: RealtimeFlowKey,
    pub(super) registry: Arc<RealtimeFlowRegistry>,
    _identity: Arc<RealtimeFlowIdentity>,
    _lease: ResourceLease,
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

    pub(super) fn begin_unit_checked(
        &self,
    ) -> std::result::Result<RealtimeAssemblyReservation, RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .begin_unit_checked(Arc::clone(&self.lifetime))
    }

    pub(super) fn begin_unit(&self) -> Option<RealtimeAssemblyReservation> {
        self.begin_unit_checked().ok()
    }

    pub(super) fn reserve_output_checked(
        &self,
        bytes: usize,
    ) -> std::result::Result<RealtimeOutputReservation, RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .reserve_output_checked(self.key(), bytes)
    }

    pub(super) fn reserve_output(&self, bytes: usize) -> Option<RealtimeOutputReservation> {
        self.reserve_output_checked(bytes).ok()
    }

    pub(super) fn enqueue_checked(
        &self,
        event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        self.lifetime
            .registry
            .enqueue_checked(self.key(), event, reservation)
    }

    pub(super) fn enqueue(
        &self,
        event: QueuedTransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        self.enqueue_checked(event, reservation).is_ok()
    }

    /// Fund one node of a caller-owned [`crate::resource::LeasedQueue`] against
    /// the owner this flow was admitted by.
    pub(super) fn reserve_queue_record_checked<T>(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.lifetime.registry.acquire_queue_record::<T>()
    }

    /// Fund one provider-owned wrapper allocation before it is boxed.
    pub(super) fn reserve_boxed_checked<T>(
        &self,
    ) -> std::result::Result<ResourceLease, RealtimeFlowDropReason> {
        self.lifetime.registry.acquire_boxed::<T>()
    }
}

/// One in-progress assembly and the funding for the whole of it.
///
/// **`_lease` is declared last, and that is deliberate.**
/// [`RealtimeFlowRegistry::assembly_claim`] prices
/// `size_of::<RealtimeAssemblyReservation>()` — the complete inline shape of
/// this value, including whatever `fragment_leases` holds inline and the
/// lifetime handle above it. Fields are destroyed in declaration order, so a
/// lease sitting in the middle would be handed back while the rest of the state
/// it paid for was still standing. Last, it is released only once every field
/// it funds is gone.
///
/// The explicit [`Drop`] below does not weaken this: an explicit `drop` body
/// runs before any field is destroyed, so the registry bookkeeping there still
/// sees a fully intact reservation.
pub(super) struct RealtimeAssemblyReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    _lifetime: Arc<RealtimeFlowLifetime>,
    fragment_leases: RealtimeFragmentLeases,
    retained_bytes: usize,
    retained_fragments: usize,
    active: bool,
    /// Last, because it funds every field above it.
    _lease: ResourceLease,
}

impl RealtimeAssemblyReservation {
    fn poison_domain(&self) {
        let mut state = self.registry.state.lock();
        self.registry.poison_domain_locked(&mut state, self.domain);
    }

    pub(super) fn retain_ordered_fragment_checked(
        &mut self,
        bytes: usize,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let claim = RealtimeFlowRegistry::ordered_fragment_claim(bytes);
        // No fragment byte ceiling, no fragment count ceiling and no unit byte
        // ceiling in front of this. Each accepted fragment takes one exact
        // claim sized to its actual bytes, and the unit it builds is bounded by
        // the sum of those claims against the owner's real grant.
        let Some(fragment_count) = self.retained_fragments.checked_add(1) else {
            self.poison_domain();
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::ParsingOrCpuWork,
                },
            ));
        };
        let Some(unit_bytes) = self.retained_bytes.checked_add(bytes) else {
            self.poison_domain();
            return Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::AccountedMemoryBytes,
                },
            ));
        };
        // Acquire before the compatibility assembler retains its payload
        // clone. Each accepted fragment keeps one distinct finite lease until
        // the complete unit, cancellation, replacement, or flow retirement
        // drops this assembly owner.
        let fragment_lease = self
            .registry
            .acquire(claim)
            .map_err(|reason| self.registry.record_drop(Some(self.key), reason, bytes))?;
        let mut state = self.registry.state.lock();
        let index = self.domain.index();
        match state.retained_bytes_by_domain[index].checked_add(bytes) {
            Some(next) => state.retained_bytes_by_domain[index] = next,
            None => self.registry.poison_domain_locked(&mut state, self.domain),
        }
        self.fragment_leases.push(fragment_lease);
        self.retained_bytes = unit_bytes;
        self.retained_fragments = fragment_count;
        let in_progress_units = RealtimeFlowRegistry::in_progress_units(&state);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Assembly {
            key: self.key,
            in_progress_units,
            retained_bytes,
        });
        Ok(())
    }

    pub(super) fn retain_ordered_fragment(&mut self, bytes: usize) -> bool {
        self.retain_ordered_fragment_checked(bytes).is_ok()
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
            self.registry.poison_domain_locked(&mut state, self.domain);
        }
        self.registry
            .release_bytes_locked(&mut state, self.domain, self.retained_bytes);
        self.registry.release_unit_locked(&mut state, self.domain);
        let in_progress_units = RealtimeFlowRegistry::in_progress_units(&state);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
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
    lease: Option<ResourceLease>,
    bytes: usize,
    active: bool,
}

impl RealtimeOutputReservation {
    pub(super) fn into_payload_lease(mut self) -> RealtimePayloadLease {
        self.active = false;
        let funding = self
            .lease
            .take()
            .expect("an active output reservation owns one provider lease");
        RealtimePayloadLease {
            reservation: Box::new(RealtimePayloadReservation {
                registry: Arc::clone(&self.registry),
                key: self.key,
                domain: self.domain,
                bytes: self.bytes,
            }),
            funding,
        }
    }
}

impl Drop for RealtimeOutputReservation {
    fn drop(&mut self) {
        if self.active {
            let mut state = self.registry.state.lock();
            self.registry
                .release_bytes_locked(&mut state, self.domain, self.bytes);
        }
    }
}

/// The registry bookkeeping for one delivered payload — and deliberately not
/// its funding.
///
/// The provider lease that pays for this allocation lives in
/// [`RealtimePayloadLease`], beside the pointer rather than inside it. A lease
/// held here would be returned by this value's own drop glue, before the
/// allocation it funds is freed.
struct RealtimePayloadReservation {
    registry: Arc<RealtimeFlowRegistry>,
    key: RealtimeFlowKey,
    domain: RealtimeFlowDomain,
    bytes: usize,
}

impl Drop for RealtimePayloadReservation {
    fn drop(&mut self) {
        let mut state = self.registry.state.lock();
        self.registry
            .release_bytes_locked(&mut state, self.domain, self.bytes);
        let retained_bytes = RealtimeFlowRegistry::retained_bytes(&state);
        drop(state);
        self.registry.record(RealtimeFlowObservation::Queue {
            key: self.key,
            units: 0,
            retained_bytes,
        });
    }
}

/// Exclusive ownership of one delivered payload's bytes.
///
/// **Not `Clone`, and not an `Arc`.** One delivery's bytes have exactly one
/// owner: the queue mints this, the delivery carries it, and whoever takes the
/// unit takes it. A shared owner would make "who releases these bytes" a
/// question with more than one answer, and it would put the funding lease inside
/// the shared allocation, where it would be returned before that allocation was
/// freed.
///
/// Field order carries the same weight as the choice of `Box`. `reservation` is
/// destroyed first — running the registry bookkeeping in its [`Drop`] and then
/// freeing the allocation — and `funding` is returned to the provider only after
/// that. There is no accessor that hands out either half alone: a raw split
/// would let the bytes' accounting be dropped separately from the payload it
/// accounts for.
pub(super) struct RealtimePayloadLease {
    reservation: Box<RealtimePayloadReservation>,
    funding: ResourceLease,
}

impl RealtimePayloadLease {
    /// Reserve one additional provider-owned copy derived from this exact
    /// flow. Used for the public label copy made at inbound handoff; the
    /// returned lease must travel with that copy and is not a second flow
    /// admission or registry.
    pub(super) fn reserve_supplemental_output(&self, bytes: usize) -> Option<RealtimePayloadLease> {
        self.reservation
            .registry
            .reserve_output_checked(self.reservation.key, bytes)
            .ok()
            .map(RealtimeOutputReservation::into_payload_lease)
    }

    fn transition_to_retained_payload(
        &mut self,
    ) -> std::result::Result<(), RealtimeFlowDropReason> {
        let replacement = RealtimeFlowRegistry::retained_payload_claim(self.reservation.bytes)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)?;
        self.funding
            .transition(replacement)
            .map_err(RealtimeFlowDropReason::ResourceUnavailable)
    }

    #[cfg(test)]
    fn claim(&self) -> ResourceClaim {
        self.funding.claim()
    }
}

impl std::fmt::Debug for RealtimePayloadLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealtimePayloadLease")
            .field("key", &self.reservation.key)
            .field("bytes", &self.reservation.bytes)
            .finish()
    }
}

#[cfg(test)]
mod elastic_resource_tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
    use crate::runtime::attempt::ConnectorResourceOwnerPort;

    struct TestContext {
        provider: FiniteResourceProvider,
        registry: Arc<RealtimeFlowRegistry>,
        _owner: ConnectorResourceOwnerPort,
        _candidate: ConnectorCandidateCapability,
        _attempt: AttemptLifetime,
    }

    /// The name every delivery in these controls arrives on.
    fn fixture_flow_name() -> RealtimeFlowName {
        RealtimeFlowName::new(b"fixture".to_vec()).expect("the fixture name is within the bound")
    }

    /// Four payload bytes on a label, leaseless — `enqueue_checked` attaches
    /// the output reservation these controls are actually measuring.
    ///
    /// The label is a real minted one, cloned per delivery. A hand-built label
    /// would be bytes nothing had paid for, and the exact grants below would
    /// then be exact about everything except the one thing the delivery carries
    /// for as long as it is queued.
    fn fixture_realtime_unit(label: &RealtimeFlowLabel) -> TransportEvent {
        TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
            label.clone(),
            RealtimeRecvUnit {
                timestamp: 0,
                marker: true,
                data: Bytes::from_static(b"test"),
            },
        ))
    }

    /// Derive the finite test grant from the exact claims exercised by one
    /// scenario. `explicit_test_grant` also reserves capacity for one connector
    /// operation. This fixture owns none, so remove that claim and the provider
    /// reservation record paired with it before adding the exact real-time
    /// leases under test.
    ///
    /// The remaining residuals account for the process, Mesh, and connector
    /// scope records, cleanup and candidate reservations, and one provider
    /// reservation record for each real-time lease. They are test accounting,
    /// not a product cardinality or production policy value.
    fn grant_for(realtime_claims: &[ResourceClaim]) -> ResourceClaim {
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_sub(crate::runtime::attempt::connector_operation_claim())
            .and_then(|grant| {
                grant.checked_sub(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    1,
                ))
            })
            .expect("the broad fixture contains the unused claim and its reservation record");
        add_provider_reservations(grant, realtime_claims)
    }

    fn add_provider_reservations(
        mut base: ResourceClaim,
        leased_claims: &[ResourceClaim],
    ) -> ResourceClaim {
        for claim in leased_claims {
            base = base
                .checked_add(*claim)
                .and_then(|base| {
                    base.checked_add(ResourceClaim::single(
                        ResourceClass::OpaqueDependencyResidual,
                        1,
                    ))
                })
                .expect("fixture real-time bookkeeping is representable");
        }
        base
    }

    fn context(realtime_claims: &[ResourceClaim]) -> TestContext {
        let provider = FiniteResourceProvider::new(grant_for(realtime_claims));
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the derived grant accounts for the process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh_scope = owner
            .issue_mesh_scope()
            .expect("the derived grant accounts for the Mesh scope");
        let (permit, attempt, claim) =
            admit_single_connector_candidate(crate::runtime::RuntimeIncarnation::new(), mesh_scope);
        let candidate = permit
            .reserve_connector_candidate_checked(claim)
            .expect("the derived grant has no provider invariant failure")
            .expect("the exact attempt remains active");
        let registry = RealtimeFlowRegistry::new(Some(candidate.work_resource_scope()));
        TestContext {
            provider,
            registry,
            _owner: owner,
            _candidate: candidate,
            _attempt: attempt,
        }
    }

    fn assert_claim_dimensions(actual: ResourceClaim, expected: ResourceClaim) {
        for dimension in ResourceClass::ALL {
            assert_eq!(
                actual.amount(dimension),
                expected.amount(dimension),
                "resource mismatch in {dimension:?}"
            );
        }
    }

    #[test]
    fn elastic_flow_admission_uses_provider_capacity_not_a_product_count() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let fixture = context(&[flow_claim, map_node, flow_claim, map_node]);

        let first = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the first exact flow claim is available");
        let _second = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the second exact flow claim is available");
        let refusal = match fixture.registry.open_inbound_flow_checked() {
            Err(refusal) => refusal,
            Ok(_) => panic!("a third flow must not exceed the finite provider grant"),
        };
        assert!(matches!(
            refusal,
            RealtimeFlowDropReason::ResourceUnavailable(ResourceUnavailable::Pressure(
                crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                }
            ))
        ));

        drop(first);
        fixture
            .registry
            .open_inbound_flow_checked()
            .expect("dropping the exact flow lease restores provider capacity");
    }

    #[test]
    fn every_retained_fragment_keeps_its_exact_provider_lease() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let assembly_claim =
            RealtimeFlowRegistry::assembly_claim().expect("assembly claim is representable");
        let fragment_claim = RealtimeFlowRegistry::ordered_fragment_claim(4)
            .expect("fragment claim is representable");
        let fixture = context(&[flow_claim, map_node, assembly_claim, fragment_claim]);
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let before_assembly = fixture.provider.in_use();
        let mut assembly = flow
            .begin_unit_checked()
            .expect("the unit claim is available");
        assembly
            .retain_ordered_fragment_checked(4)
            .expect("the exact fragment claim is available");
        let with_fragment = fixture.provider.in_use();
        assert_eq!(
            with_fragment.amount(ResourceClass::AccountedMemoryBytes),
            grant_for(&[flow_claim, map_node, assembly_claim, fragment_claim])
                .amount(ResourceClass::AccountedMemoryBytes)
        );
        assert!(matches!(
            assembly.retain_ordered_fragment_checked(1),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                })
            ))
        ));

        drop(assembly);
        assert_eq!(fixture.provider.in_use(), before_assembly);
    }

    #[test]
    fn session_packet_work_guard_holds_capacity_through_the_caller_iteration() {
        let work_claim = RealtimeFlowRegistry::session_packet_work_claim(4)
            .expect("work claim is representable");
        let fixture = context(&[work_claim]);
        let before_work = fixture.provider.in_use();
        let work = fixture
            .registry
            .admit_session_packet_checked(4)
            .expect("the exact packet work claim is available");
        assert!(matches!(
            fixture.registry.admit_session_packet_checked(1),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::AccountedMemoryBytes,
                    ..
                })
            ))
        ));

        drop(work);
        assert_eq!(fixture.provider.in_use(), before_work);
        fixture
            .registry
            .admit_session_packet_checked(1)
            .expect("dropping the exact work guard restores provider capacity");
    }

    #[test]
    fn native_read_guard_owns_the_opaque_result_until_content_admission() {
        let read_claim =
            RealtimeFlowRegistry::native_read_claim().expect("read claim is representable");
        let fixture = context(&[read_claim]);
        let before_read = fixture.provider.in_use();
        let read = fixture
            .registry
            .begin_native_read_checked()
            .expect("the exact native-read claim is available");
        assert!(matches!(
            fixture.registry.begin_native_read_checked(),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(crate::resource::ResourcePressure {
                    dimension: ResourceClass::CallbackOrScheduledWork,
                    ..
                })
            ))
        ));

        drop(read);
        assert_claim_dimensions(fixture.provider.in_use(), before_read);
        fixture
            .registry
            .begin_native_read_checked()
            .expect("dropping the native-read guard restores its exact capacity");
    }

    #[test]
    fn slow_fragment_owner_does_not_expire_without_an_owner_transition() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let assembly_claim =
            RealtimeFlowRegistry::assembly_claim().expect("assembly claim is representable");
        let fragment_claim = RealtimeFlowRegistry::ordered_fragment_claim(4)
            .expect("ordered fragment claim is representable");
        let fixture = context(&[flow_claim, map_node, assembly_claim, fragment_claim]);
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let mut assembly = flow
            .begin_unit_checked()
            .expect("the assembly claim is available");
        assembly
            .retain_ordered_fragment_checked(4)
            .expect("the ordered fragment claim is available");

        let (owner_waiting_tx, owner_waiting_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let owner = std::thread::spawn(move || {
            owner_waiting_tx
                .send(())
                .expect("the test owner reports that it is waiting");
            release_rx
                .recv()
                .expect("the test controls the concrete release transition");
            drop(assembly);
        });
        owner_waiting_rx
            .recv()
            .expect("the fragment owner reached its owner-controlled wait");
        assert!(matches!(
            fixture
                .registry
                .acquire(RealtimeFlowRegistry::ordered_fragment_claim(1)),
            Err(RealtimeFlowDropReason::ResourceUnavailable(
                ResourceUnavailable::Pressure(_)
            ))
        ));
        release_tx
            .send(())
            .expect("the test explicitly releases the slow owner");
        owner.join().expect("the slow owner exits without a timer");
        let _lease = fixture
            .registry
            .acquire(RealtimeFlowRegistry::ordered_fragment_claim(1))
            .expect("only the concrete owner drop restores fragment capacity");
    }

    #[test]
    fn dequeue_releases_queue_ownership_but_payload_clones_keep_content_ownership() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let output_claim =
            RealtimeFlowRegistry::output_claim(4).expect("output claim is representable");
        let queue_claim =
            RealtimeFlowRegistry::queue_claim(4).expect("queue claim is representable");
        let queue_node = RealtimeFlowRegistry::queue_node_claim::<QueuedRealtimeEvent>()
            .expect("queue node claim is representable");
        let ready_claim =
            RealtimeFlowRegistry::ready_claim().expect("ready claim is representable");
        let retained_payload_claim = RealtimeFlowRegistry::retained_payload_claim(4)
            .expect("retained payload claim is representable");
        let name = fixture_flow_name();
        let label_claim = RealtimeFlowLabel::mint_claim(name.as_bytes().len())
            .expect("label claim is representable");
        let fixture = context(&[
            flow_claim,
            map_node,
            output_claim,
            queue_claim,
            queue_node,
            ready_claim,
            label_claim,
        ]);
        // Minted ahead of the baseline, so the label's own lease is part of the
        // constant this control measures its deltas against. It is held for the
        // whole test on purpose: a label outlives the units that carry it.
        let label =
            RealtimeFlowLabel::mint(name, &fixture.registry).expect("the label claim is available");
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let flow_only = fixture.provider.in_use();
        let output = flow
            .reserve_output_checked(4)
            .expect("the complete output claim is available");
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(flow_only, &[output_claim]),
            "the output reservation owns its exact provider claim",
        );
        flow.enqueue_checked(
            QueuedTransportEvent {
                event: fixture_realtime_unit(&label),
                observation: None,
                callback_work: None,
            },
            output,
        )
        .expect("the queue claim is available");
        {
            // `get_mut`, and the guard is `mut` for it: `LeasedQueue::front`
            // may reverse the push chain into the pop chain before returning
            // the head. That is structural mutation only; it neither moves nor
            // releases any lease or changes any accounting.
            let mut state = fixture.registry.state.lock();
            let queued = state
                .flows
                .get_mut(&flow.key())
                .and_then(|flow| flow.events.front())
                .expect("the exact payload is queued");
            assert_eq!(queued._queue_lease.claim(), queue_claim);
            let payload = match &queued.event.event {
                TransportEvent::RealtimeUnit(delivery) => delivery
                    .payload
                    .as_ref()
                    .expect("the queued payload owns its output lease"),
                _ => panic!("the fixture queues one real-time unit"),
            };
            assert_eq!(payload.claim(), output_claim);
            assert_eq!(
                state
                    .flows
                    .get(&flow.key())
                    .and_then(|flow| flow.ready_lease.as_ref())
                    .expect("the queued flow owns its ready lease")
                    .claim(),
                ready_claim
            );
        }
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(
                flow_only,
                &[output_claim, queue_claim, queue_node, ready_claim],
            ),
            "the queued unit owns output, value-retention, node, and ready claims",
        );

        let event = fixture
            .registry
            .try_recv()
            .expect("the queued event remains available");
        let retained = match &event.event {
            TransportEvent::RealtimeUnit(delivery) => delivery
                .payload
                .as_ref()
                .expect("the delivered payload retains its exact lease"),
            _ => panic!("the fixture delivers one real-time unit"),
        };
        assert_eq!(retained.claim(), retained_payload_claim);
        assert_eq!(
            fixture.provider.in_use(),
            add_provider_reservations(flow_only, &[retained_payload_claim]),
            "dequeue retains only the delivered payload claim",
        );
        drop(event);
        assert_eq!(
            fixture.provider.in_use(),
            flow_only,
            "dropping the delivered payload restores the flow-only baseline",
        );
    }

    #[test]
    fn failed_post_insertion_ready_transition_unwinds_event_and_every_queue_lease() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let output_claim =
            RealtimeFlowRegistry::output_claim(4).expect("output claim is representable");
        let queue_claim =
            RealtimeFlowRegistry::queue_claim(4).expect("queue claim is representable");
        let queue_node = RealtimeFlowRegistry::queue_node_claim::<QueuedRealtimeEvent>()
            .expect("queue node claim is representable");
        let ready_claim =
            RealtimeFlowRegistry::ready_claim().expect("ready claim is representable");
        let name = fixture_flow_name();
        let label_claim = RealtimeFlowLabel::mint_claim(name.as_bytes().len())
            .expect("label claim is representable");
        let fixture = context(&[
            flow_claim,
            map_node,
            output_claim,
            queue_claim,
            queue_node,
            ready_claim,
            label_claim,
        ]);
        let label =
            RealtimeFlowLabel::mint(name, &fixture.registry).expect("the label claim is available");
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let flow_only = fixture.provider.in_use();
        let output = flow
            .reserve_output_checked(4)
            .expect("the output claim is available");
        let drops = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        fixture
            .registry
            .fail_next_ready_push_for_test(Arc::clone(&drops));

        assert_eq!(
            flow.enqueue_checked(
                QueuedTransportEvent {
                    event: fixture_realtime_unit(&label),
                    observation: None,
                    callback_work: None,
                },
                output,
            ),
            Err(RealtimeFlowDropReason::OwnershipMismatch),
            "the injected failure is reached only after queue insertion",
        );
        {
            let state = fixture.registry.state.lock();
            assert!(
                state
                    .flows
                    .get(&flow.key())
                    .is_some_and(|flow| flow.events.is_empty()),
                "the inserted queue node and value are removed on refusal",
            );
            assert!(state.ready.is_empty(), "no ready node was linked");
        }
        assert_claim_dimensions(fixture.provider.in_use(), flow_only);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the inserted payload/event wrapper is destroyed exactly once",
        );
    }

    #[test]
    fn dropping_a_scheduled_flow_releases_its_embedded_ready_node() {
        let flow_claim = RealtimeFlowRegistry::flow_claim().expect("flow claim is representable");
        let map_node = RealtimeFlowRegistry::flow_map_node_claim()
            .expect("flow map node claim is representable");
        let output_claim =
            RealtimeFlowRegistry::output_claim(4).expect("output claim is representable");
        let queue_claim =
            RealtimeFlowRegistry::queue_claim(4).expect("queue claim is representable");
        let queue_node = RealtimeFlowRegistry::queue_node_claim::<QueuedRealtimeEvent>()
            .expect("queue node claim is representable");
        let ready_claim =
            RealtimeFlowRegistry::ready_claim().expect("ready claim is representable");
        let name = fixture_flow_name();
        let label_claim = RealtimeFlowLabel::mint_claim(name.as_bytes().len())
            .expect("label claim is representable");
        let fixture = context(&[
            flow_claim,
            map_node,
            output_claim,
            queue_claim,
            queue_node,
            ready_claim,
            label_claim,
        ]);
        // Minted before the baseline and held past the flow drop: the label is
        // not the flow's, so a flow going away must not be what releases it.
        let label =
            RealtimeFlowLabel::mint(name, &fixture.registry).expect("the label claim is available");
        let before_flow = fixture.provider.in_use();
        let flow = fixture
            .registry
            .open_inbound_flow_checked()
            .expect("the flow claim is available");
        let output = flow
            .reserve_output_checked(4)
            .expect("the output claim is available");
        flow.enqueue_checked(
            QueuedTransportEvent {
                event: fixture_realtime_unit(&label),
                observation: None,
                callback_work: None,
            },
            output,
        )
        .expect("the queue and ready claims are available");
        assert_eq!(fixture.registry.state.lock().ready.len(), 1);

        drop(flow);
        assert!(fixture.registry.state.lock().ready.is_empty());
        assert_claim_dimensions(fixture.provider.in_use(), before_flow);
    }
}
