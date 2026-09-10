//! The current peer installation map and the authorities minted under its
//! fence.
//!
//! One state class: which `PeerConnection` is installed under each device id
//! right now, and who is allowed to act on it. Three things live here and
//! nothing else does.
//!
//! * **The map.** [`PeerRegistry`] is the only owner that can install, replace,
//!   remove or retire a peer. Every ownership exit ends the connector worker,
//!   even when another task still holds an `Arc<PeerConnection>`.
//! * **The exact owner token.** [`PeerOwnerToken`] names one *installation*,
//!   not one device. A device id is a re-resolution key; a token is not, which
//!   is why every peer-reaching helper takes one.
//! * **The one-operation witnesses.** [`LogicalSessionOperation`],
//!   [`AdmittedInboundApplicationOperation`], [`AdmittedInboundDispatch`],
//!   [`AdmittedApplicationOperation`] and [`AdmittedRenegotiation`] are minted
//!   under the mutation lock and bind the exact installation they were admitted
//!   for. An admission answer never becomes a boolean that outlives the
//!   acquisition that decided it.
//!
//! The mutation lock is the linearization point. A fence holds it across the
//! whole effect, so replacement orders strictly before or after and never
//! between a check and the act it authorized. Everything run under it must be
//! synchronous, non-reentrant, and free to hand a value off but not to await.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Weak,
};

use serde::{Deserialize, Serialize};
use tokio::task::JoinHandle;

use crate::error::{Error, Result};
use crate::resource::ResourceMailboxSender;
use crate::runtime::session_broker::SessionBroker;
use dashmap::DashMap;
use parking_lot::Mutex;

use super::connection::PeerConnection;

/// Narrow owner of the current peer set.
///
/// Callers can take owned read snapshots, but only this registry can install,
/// replace, remove, or retire peers. Every ownership exit explicitly ends the
/// connector worker even when another task retains an external
/// `Arc<PeerConnection>`.
pub(crate) struct PeerRegistry {
    peers: DashMap<String, PeerRegistryEntry>,
    mutation: Mutex<()>,
    canonical_bootstrap: parking_lot::RwLock<Option<crate::semantic::VerifiedBootstrap>>,
    canonical_fact_graph:
        parking_lot::RwLock<Option<Arc<parking_lot::RwLock<crate::semantic::FactGraph>>>>,
    local_device_id: String,
    binding_namespace: [u8; 16],
    next_binding_epoch: AtomicU64,
    /// Where a newly minted session is announced.
    ///
    /// The engine's own command queue, so the announcement is handled by the
    /// driver after every lock here has been released — nothing runs, awaits or
    /// re-enters under the fence. A `OnceLock` because the queue is created
    /// alongside this registry and bound once during state construction, and
    /// because reading it costs no lock on a path that already holds one.
    ///
    /// Unbound in a bare registry, which is what the unit fixtures build: those
    /// promote and exercise the fence without a driver, and an announcement with
    /// nowhere to go is correctly dropped rather than being an error.
    command_tx: std::sync::OnceLock<ResourceMailboxSender<super::state::NetworkCmd>>,
    speculative_promotion_tx:
        std::sync::OnceLock<ResourceMailboxSender<super::state::SpeculativePromotionCmd>>,
    close_tasks: Arc<CloseTaskTracker>,
    signaling_runtime:
        parking_lot::RwLock<Option<Weak<super::signaling_ingress::SignalingRuntime>>>,
}

/// Close tasks own their exact peer until transport cleanup settles.  Their
/// handles remain here so shutdown observes each terminal result exactly once.
struct CloseTaskTracker {
    handles: Mutex<Vec<JoinHandle<()>>>,
}

impl CloseTaskTracker {
    fn new() -> Self {
        Self {
            handles: Mutex::new(Vec::new()),
        }
    }

    fn add(&self, handle: JoinHandle<()>) {
        self.handles.lock().push(handle);
    }

    async fn wait(&self) {
        loop {
            let handles = std::mem::take(&mut *self.handles.lock());
            if handles.is_empty() {
                return;
            }
            for handle in handles {
                if let Err(error) = handle.await {
                    tracing::warn!(%error, "replaced peer cleanup task failed");
                }
            }
        }
    }
}

struct PeerRegistryEntry {
    peer: Arc<PeerConnection>,
    installation: Arc<()>,
    binding_epoch: u64,
}

/// The exact installation displaced by a replacement. The owner token keeps
/// the old `Arc<()>` installation identity and binding epoch paired with the
/// old connection, so delayed cleanup can distinguish it from the successor
/// that reused the same device id.
pub(super) struct DisplacedPeerInstallation {
    pub(super) peer: Arc<PeerConnection>,
    pub(super) owner: PeerOwnerToken,
}

/// Unforgeable process-local identity for one installed peer owner.
///
/// This is carried by delayed engine work so a timer or callback created for
/// peer A cannot mutate or remove replacement peer B under the same device id.
/// It is not authentication, application, or durable mesh authority.
#[doc(hidden)]
#[derive(Clone)]
pub struct PeerOwnerToken {
    peer: Arc<PeerConnection>,
    installation: Arc<()>,
    binding_namespace: [u8; 16],
    binding_epoch: u64,
    worker: Option<Arc<crate::transport::WebRtcConnectorWorker>>,
}

/// Weak delayed-work witness for one exact peer installation.
///
/// Unlike [`PeerOwnerToken`], this carries no custody while a timer is
/// asleep. Upgrade reconstructs the exact token only while the peer,
/// installation marker, and (when stamped) worker are all still alive; the
/// normal registry fences then perform the currentness and replacement checks.
#[derive(Clone)]
pub(super) struct WeakPeerOwnerToken {
    peer: Weak<PeerConnection>,
    installation: Weak<()>,
    binding_namespace: [u8; 16],
    binding_epoch: u64,
    worker: Option<Weak<crate::transport::WebRtcConnectorWorker>>,
}

/// A restart-serializable coordinate for one exact peer installation.  The
/// Arc installation identity is deliberately not persisted; this value is
/// only a durable witness that must be re-bound to a live owner under the
/// registry mutation fence before it can authorize an acknowledgement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct PeerBindingCoordinate {
    pub(crate) device_id: String,
    pub(crate) binding_namespace: [u8; 16],
    pub(crate) binding_epoch: u64,
}

impl PeerBindingCoordinate {
    pub(crate) fn key(&self) -> String {
        format!(
            "{}:{}",
            hex::encode(self.binding_namespace),
            self.binding_epoch
        )
    }
}

impl PeerOwnerToken {
    /// Allocation-free equality for an already captured installation and
    /// optional worker. An unstamped token never equals a worker-stamped one.
    /// This compares witnesses only; it does not establish current admission.
    pub(crate) fn same_exact_owner(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.installation, &other.installation)
            && match (&self.worker, &other.worker) {
                (None, None) => true,
                (Some(left), Some(right)) => Arc::ptr_eq(left, right),
                _ => false,
            }
    }

    pub(crate) fn device_id(&self) -> &str {
        &self.peer.device_id
    }

    /// The exact installed connection this token names.
    ///
    /// For deciding *about* an installation and then acting on that same one.
    /// Looking the device id up twice — once to read a predicate, once to take a
    /// token — can straddle a replacement and act on B's behalf using A's state;
    /// reading through the token cannot, because the token is what the action
    /// resolves against. The carrier-withdrawal arm in `engine/mod.rs` is the
    /// caller: it reads session liveness here and hands this same token to
    /// [`super::drop_peer_if_current`].
    pub(crate) fn connection(&self) -> &Arc<PeerConnection> {
        &self.peer
    }

    /// Stamp this installation token with the exact worker that accepted one
    /// transport callback. The stamp is process-local custody: every registry
    /// fence using it also proves that worker is still the current session.
    pub(super) fn for_worker(&self, worker: Arc<crate::transport::WebRtcConnectorWorker>) -> Self {
        Self {
            peer: Arc::clone(&self.peer),
            installation: Arc::clone(&self.installation),
            binding_namespace: self.binding_namespace,
            binding_epoch: self.binding_epoch,
            worker: Some(worker),
        }
    }

    /// Downgrade delayed work to an exact witness that carries no peer,
    /// installation, or worker ownership while it waits.
    pub(super) fn downgrade(&self) -> WeakPeerOwnerToken {
        WeakPeerOwnerToken {
            peer: Arc::downgrade(&self.peer),
            installation: Arc::downgrade(&self.installation),
            binding_namespace: self.binding_namespace,
            binding_epoch: self.binding_epoch,
            worker: self.worker.as_ref().map(Arc::downgrade),
        }
    }

    pub(super) fn worker(&self) -> Option<&Arc<crate::transport::WebRtcConnectorWorker>> {
        self.worker.as_ref()
    }

    pub(crate) fn binding_coordinate(&self) -> PeerBindingCoordinate {
        PeerBindingCoordinate {
            device_id: self.device_id().to_string(),
            binding_namespace: self.binding_namespace,
            binding_epoch: self.binding_epoch,
        }
    }

    pub(crate) fn binding_key(&self) -> String {
        self.binding_coordinate().key()
    }

    fn worker_matches(&self, peer: &PeerConnection) -> bool {
        self.worker
            .as_ref()
            .is_none_or(|worker| peer.owns_authenticated_worker(worker))
    }

    /// A token naming a peer that is installed nowhere.
    ///
    /// For the one control seam that needs a [`RealtimeFlowHandle`] outside this
    /// crate — see [`crate::realtime::transport_lab_retired_flow_handle`]. The
    /// installation marker is this token's own and matches no registry entry, so
    /// it authorizes nothing: every operation that takes an owner resolves it
    /// against the installed peer first and finds nothing to act on.
    ///
    /// That is the point. It is not a weaker version of an admitted token; it is
    /// a token for a peer that is gone, which is a state production reaches and
    /// production code already answers correctly.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn detached_for_control(device_id: &str) -> Self {
        Self {
            peer: Arc::new(super::connection::PeerConnection::new(
                device_id.to_string(),
                None,
            )),
            installation: Arc::new(()),
            binding_namespace: [0u8; 16],
            binding_epoch: 0,
            worker: None,
        }
    }
}

impl WeakPeerOwnerToken {
    /// Reconstitute strong exact custody only for a still-live installation.
    /// A stamped worker is mandatory when its original worker is stamped; a
    /// timer can therefore never silently fall back to an un-stamped owner.
    pub(super) fn upgrade(&self) -> Option<PeerOwnerToken> {
        let worker = match self.worker.as_ref() {
            Some(worker) => Some(worker.upgrade()?),
            None => None,
        };
        Some(PeerOwnerToken {
            peer: self.peer.upgrade()?,
            installation: self.installation.upgrade()?,
            binding_namespace: self.binding_namespace,
            binding_epoch: self.binding_epoch,
            worker,
        })
    }
}

pub(super) enum SpeculativeWorkerRoute {
    Speculative,
    Promoted,
    Stale,
}

pub(super) enum SpeculativeTerminalCleanup {
    Candidate(super::connection::SpeculativeRetirement),
    Promoted {
        peer: Arc<PeerConnection>,
        removed: crate::runtime::peer_session::RemovedPromotedChannel,
    },
}

pub(super) enum ChannelTerminal {
    Stale,
    Channel {
        channel: crate::runtime::peer_session::RemovedPromotedChannel,
    },
    Peer {
        peer: Arc<PeerConnection>,
        channel: crate::runtime::peer_session::RemovedPromotedChannel,
    },
}

pub(super) enum LogicalSessionTerminal {
    Stale,
    Removed(Arc<PeerConnection>),
}

/// Exact local-departure custody minted under the registry fence.  The worker
/// stamp is retained only for the send; the waiter is funded by the logical
/// session witness and therefore survives carrying-channel replacement.
pub(super) struct AdmittedLocalDeparture {
    owner: PeerOwnerToken,
    witness: crate::runtime::peer_session::LogicalSessionValidityWitness,
    waiter: crate::runtime::peer_session::DepartureWaiter,
}

impl AdmittedLocalDeparture {
    pub(super) fn owner(&self) -> &PeerOwnerToken {
        &self.owner
    }

    pub(super) fn witness(&self) -> &crate::runtime::peer_session::LogicalSessionValidityWitness {
        &self.witness
    }

    pub(super) fn waiter(&self) -> &crate::runtime::peer_session::DepartureWaiter {
        &self.waiter
    }
}

// A receipt send started on the exact authenticated channel that carried a
// remote departure. The peer remains current until the receipt has settled so
// a simultaneous local departure can observe it on its own exact witness.
fn remote_departure_receipt_claim(
    frame_len: usize,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let frame = u64::try_from(frame_len).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::QueuedBytes,
        }
    })?;
    let bytes = u64::try_from(
        std::mem::size_of::<RemoteDepartureReceipt>()
            .checked_add(frame_len)
            .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            })?,
    )
    .map_err(
        |_| crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    crate::resource::ResourceClaim::try_from_entries([
        (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
        (crate::resource::ResourceClass::QueuedBytes, frame),
        (crate::resource::ResourceClass::ParsingOrCpuWork, frame),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 1),
    ])
}

/// The exact carrying-channel send permit and its exact serialized receipt
/// lease. Serialization is owned by the protocol caller after admission.
pub(super) struct RemoteDepartureReceipt {
    send: crate::transport::StartedConnectorSend,
    frame_len: usize,
    /// Explicitly funds the exact serialized receipt buffer in addition to
    /// the connector operation permit. Dropping it on send failure/cancel
    /// returns the exact receipt claim to the logical provider scope.
    _frame_lease: crate::resource::ResourceLease,
}

impl RemoteDepartureReceipt {
    pub(super) async fn send(self, data: bytes::Bytes) -> Result<usize> {
        if data.len() != self.frame_len {
            return Err(Error::Transport(
                "departure receipt length differed from its funded exact count".into(),
            ));
        }
        self.send.send(data).await
    }
}

pub(super) enum RemoteDepartureAdmission {
    Stale,
    Accepted {
        receipt: Option<Box<RemoteDepartureReceipt>>,
        operation: LogicalSessionOperation,
        /// A local departure is already waiting for this receipt. Its existing
        /// waiter owns the matching retirement edge; retiring here first would
        /// invalidate that witness before `DepartObserved` can be admitted.
        defer_retirement: bool,
    },
}

fn departure_carrier(
    worker: &Arc<crate::transport::WebRtcConnectorWorker>,
) -> Option<crate::runtime::peer_session::DepartureCarrier> {
    worker
        .live_connector_incarnation()
        .cloned()
        .map(crate::runtime::peer_session::DepartureCarrier::new)
}

impl Default for PeerRegistry {
    fn default() -> Self {
        Self::new(String::new())
    }
}

impl PeerRegistry {
    pub(super) fn new(local_device_id: String) -> Self {
        let mut binding_namespace = [0u8; 16];
        if getrandom::getrandom(&mut binding_namespace).is_err() {
            use rand::RngCore;
            rand::thread_rng().fill_bytes(&mut binding_namespace);
        }
        Self {
            peers: DashMap::new(),
            mutation: Mutex::new(()),
            canonical_bootstrap: parking_lot::RwLock::new(None),
            canonical_fact_graph: parking_lot::RwLock::new(None),
            local_device_id,
            binding_namespace,
            next_binding_epoch: AtomicU64::new(1),
            command_tx: std::sync::OnceLock::new(),
            speculative_promotion_tx: std::sync::OnceLock::new(),
            close_tasks: Arc::new(CloseTaskTracker::new()),
            signaling_runtime: parking_lot::RwLock::new(None),
        }
    }

    pub(super) fn bind_signaling_runtime(
        &self,
        runtime: Weak<super::signaling_ingress::SignalingRuntime>,
    ) {
        *self.signaling_runtime.write() = Some(Weak::clone(&runtime));
        for entry in self.peers.iter() {
            entry
                .value()
                .peer
                .bind_signaling_runtime(Weak::clone(&runtime));
        }
    }

    /// Retain one synchronously replaced peer until its detached native close
    /// owner completes. The custody is process-local and narrowly tied to
    /// replacement; shutdown drains it rather than guessing which removed
    /// peer tasks still exist.
    pub(super) fn track_replaced_close(&self, peer: Arc<PeerConnection>) {
        self.close_tasks.add(tokio::spawn(async move {
            if let Err(error) = peer.retire_and_close().await {
                tracing::warn!(%error, "replaced peer cleanup did not complete successfully");
            }
        }));
    }

    pub(super) async fn await_replaced_closes(&self) {
        self.close_tasks.wait().await;
    }

    /// Bind the verified bootstrap and the one authoritative FactGraph used
    /// by every registry policy fence. The engine calls this once after state
    /// construction; a missing binding fails closed for Closed policy.
    pub(crate) fn bind_canonical_authority(
        &self,
        bootstrap: crate::semantic::VerifiedBootstrap,
        fact_graph: Arc<parking_lot::RwLock<crate::semantic::FactGraph>>,
    ) {
        *self.canonical_bootstrap.write() = Some(bootstrap);
        *self.canonical_fact_graph.write() = Some(fact_graph);
    }

    fn policy_admits(&self, remote_device_id: &str) -> bool {
        // All registry fences consume the one bootstrap-bound semantic
        // evaluator. Compatibility NetworkState roles and kind are never
        // consulted here.
        let Some(bootstrap) = self.canonical_bootstrap.read().clone() else {
            return false;
        };
        let Some(graph) = self.canonical_fact_graph.read().clone() else {
            return false;
        };
        let graph = graph.read();
        super::governance::canonical_policy_admits_from(
            &bootstrap,
            &graph,
            &self.local_device_id,
            remote_device_id,
        )
    }

    /// Check whether a canonical routed origin is admitted by this network's
    /// bound semantic policy. This performs no peer lookup, session promotion,
    /// or installation change; the bootstrap-bound FactGraph evaluator remains
    /// the sole authority for the decision.
    pub(super) fn routed_origin_policy_admits(&self, origin: &crate::semantic::DeviceId) -> bool {
        let Some(bootstrap) = self.canonical_bootstrap.read().clone() else {
            return false;
        };
        let Some(graph) = self.canonical_fact_graph.read().clone() else {
            return false;
        };
        // This is the startup-owned local identity, not the cold routed key.
        // Borrow origin unchanged so a wire check cannot populate the global
        // interner before its endpoint signature/policy has been admitted.
        let Ok(local) = crate::semantic::DeviceId::from_canonical_str(&self.local_device_id) else {
            return false;
        };
        let graph = graph.read();
        super::governance::canonical_policy_admits_devices(&bootstrap, &graph, &local, origin)
    }

    /// Bind the queue newly minted sessions are announced on.
    ///
    /// Called once, during state construction, by the owner of both this
    /// registry and the command queue. Later calls are ignored rather than
    /// panicking: the binding is an identity this registry holds for its whole
    /// life, so a second one could only be the same queue again or a mistake,
    /// and neither is worth taking a process down for.
    pub(super) fn bind_command_sink(&self, tx: ResourceMailboxSender<super::state::NetworkCmd>) {
        let _ = self.command_tx.set(tx);
    }

    pub(super) fn bind_speculative_promotion_sink(
        &self,
        tx: ResourceMailboxSender<super::state::SpeculativePromotionCmd>,
    ) {
        let _ = self.speculative_promotion_tx.set(tx);
    }

    /// Promote if needed, announcing a session this call minted.
    ///
    /// **The one place promotion is reached from the fence**, so no entry point
    /// can promote without announcing. That is the whole reason it exists: the
    /// alternative is seven call sites that each have to remember, and the
    /// failure mode of forgetting one is a peer that never receives what its
    /// session was owed, silently and only on that path.
    ///
    /// The announcement is enqueued **synchronously, before returning**, so it
    /// cannot be lost to a task that never runs, and it carries the exact owner
    /// rather than a device id — a replacement resolves to a different token, so
    /// a command cannot be applied to a session that did not mint it.
    ///
    /// Nothing executes under the fence. Resource-backed admission stores the
    /// command and wakes the driver; it does not run the handler or await. If
    /// the provider refuses that one pending callback, the newly minted session
    /// is revoked before this fence reports it usable: a session that silently
    /// skipped its first application replay would not be the session callers
    /// were promised.
    fn promote_and_announce(
        &self,
        peer: &Arc<PeerConnection>,
        owner: &PeerOwnerToken,
        broker: &SessionBroker,
        mesh_context: &str,
    ) -> bool {
        // Every production caller currently enters through the mutation
        // fence, but keep the install boundary self-enforcing as well.  A
        // delayed W0 owner must not promote against the W1 installation that
        // reused its device id, even if a future caller forgets to repeat this
        // check before reaching the common promotion funnel.  The map entry,
        // installation marker, binding coordinate and optional worker are one
        // exact identity; no device-only lookup can substitute a successor.
        let Some(current) = self.peers.get(owner.device_id()) else {
            return false;
        };
        let exact_owner = Arc::ptr_eq(&current.value().peer, peer)
            && Arc::ptr_eq(&current.value().installation, &owner.installation)
            && current.value().binding_epoch == owner.binding_epoch
            && self.binding_namespace == owner.binding_namespace
            && owner.worker_matches(&current.value().peer);
        drop(current);
        if !exact_owner {
            return false;
        }
        let durable_policy = self.policy_admits(owner.device_id());
        let phase_admits = {
            let data = peer.state.read();
            matches!(
                data.status,
                super::connection::PeerStatus::Active | super::connection::PeerStatus::Shelved
            )
        };
        let policy_admits = durable_policy
            && (peer.holds_promoted_session()
                || (peer.has_authenticated_channel() && phase_admits));
        // The exact peer fence receives the canonical verdict even for an
        // already-promoted slot. A false verdict is intentionally not merely
        // a refusal hint: `promote_session_if_needed` clears retained session
        // authority before it can return `Promotion::Current`.
        let promotion = peer.promote_session_if_needed(broker, mesh_context, policy_admits);
        if promotion == super::connection::Promotion::NewlyPromoted {
            if let Some(tx) = self.command_tx.get() {
                if tx
                    .send(super::state::NetworkCmd::ReplayCapabilities {
                        owner: owner.clone(),
                    })
                    .is_err()
                {
                    peer.revoke_promoted_session();
                    return false;
                }
            }
        }
        promotion.is_usable()
    }

    /// Promote the exact authenticated speculative candidate while holding
    /// the registry fence.  Replacement is one linearized map operation: the
    /// predecessor is returned to the caller for retirement only after the
    /// candidate owns the promoted session.
    pub(super) fn queue_speculative_promotion(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
    ) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return false;
        };
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return false;
        }
        let peer = &current.value().peer;
        if !peer.speculative_is_exact(correlation, candidate) {
            return false;
        }
        let Some(tx) = self.speculative_promotion_tx.get() else {
            candidate.retire();
            return false;
        };
        if tx
            .send(super::state::SpeculativePromotionCmd {
                owner: owner.clone(),
                candidate: Arc::clone(candidate),
                correlation: correlation.to_string(),
            })
            .is_err()
        {
            candidate.retire();
            return false;
        }
        true
    }

    /// Retire only the exact speculative worker owned by `owner`.
    ///
    /// Terminal transport cleanup and promotion take this same mutation fence:
    /// whichever reaches it first consumes the candidate, while the other sees
    /// an exact-slot mismatch and leaves the predecessor or successor alone.
    pub(super) fn take_speculative_exact(
        &self,
        owner: &PeerOwnerToken,
        correlation: &str,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
    ) -> Option<super::connection::SpeculativeRetirement> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || self.binding_namespace != owner.binding_namespace
            || current.value().binding_epoch != owner.binding_epoch
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        current
            .value()
            .peer
            .take_speculative_exact(correlation, candidate)
    }

    pub(super) fn retain_dedup_for_worker(
        &self,
        owner: &PeerOwnerToken,
        correlation: &str,
        worker: &Arc<crate::transport::WebRtcConnectorWorker>,
        token: crate::runtime::peer_session::DedupToken,
    ) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return false;
        };
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return false;
        }
        current
            .value()
            .peer
            .retain_dedup_for_worker(correlation, worker, token)
    }

    /// Classify a pump's exact worker under the registry mutation fence. The
    /// result is only a routing snapshot; terminal cleanup below re-enters the
    /// same fence for its linearized take/removal.
    pub(super) fn speculative_worker_route(
        &self,
        owner: &PeerOwnerToken,
        correlation: &str,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
    ) -> SpeculativeWorkerRoute {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return SpeculativeWorkerRoute::Stale;
        };
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return SpeculativeWorkerRoute::Stale;
        }
        let peer = &current.value().peer;
        if peer.speculative_is_exact(correlation, candidate) {
            return SpeculativeWorkerRoute::Speculative;
        }
        if peer.owns_authenticated_worker(candidate) && peer.holds_promoted_session() {
            SpeculativeWorkerRoute::Promoted
        } else {
            SpeculativeWorkerRoute::Stale
        }
    }

    /// Linearize terminal candidate cleanup against speculative promotion.
    /// Terminal-first consumes only the speculative slot. Promotion-first
    /// removes and retires the exact current installation. A stale pump or a
    /// later successor returns `None` and is never redirected by device id.
    pub(super) fn terminal_speculative_cleanup(
        &self,
        owner: &PeerOwnerToken,
        correlation: &str,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
    ) -> Option<SpeculativeTerminalCleanup> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if let Some(candidate) = peer.take_speculative_exact(correlation, candidate) {
            return Some(SpeculativeTerminalCleanup::Candidate(candidate));
        }
        let promoted = peer.owns_authenticated_worker(candidate) && peer.holds_promoted_session();
        if !promoted {
            return None;
        }
        let peer_arc = Arc::clone(peer);
        let removed = peer.retire_authenticated_worker(candidate)?;
        drop(current);
        if removed.session_empty {
            let (_, entry) = self.peers.remove(owner.device_id())?;
            let peer = entry.peer;
            peer.retire_connector();
            Some(SpeculativeTerminalCleanup::Promoted { peer, removed })
        } else {
            Some(SpeculativeTerminalCleanup::Promoted {
                peer: peer_arc,
                removed,
            })
        }
    }

    pub(super) fn promote_speculative_command(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        broker: &SessionBroker,
        mesh_context: &str,
    ) -> Option<super::connection::SpeculativePromotion> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        if peer.unpromoted_offer_in_flight() {
            return None;
        }
        if !peer.speculative_is_exact(correlation, candidate) {
            return None;
        }
        let policy_admits = self.policy_admits(owner.device_id());
        // Reaching this command proves only the exact candidate's fresh Auth
        // and owner custody. It must join the logical session without making
        // this reducer an implicit transport selector; channel selection is a
        // separate local policy decision.
        peer.promote_speculative_if_needed(
            correlation,
            candidate,
            broker,
            mesh_context,
            policy_admits,
        )
    }

    pub(super) fn get(&self, device_id: &str) -> Option<Arc<PeerConnection>> {
        self.peers
            .get(device_id)
            .map(|entry| Arc::clone(&entry.value().peer))
    }

    /// Whether an exact current installation is a valid recovery successor.
    /// A live connector alone is not enough: the promoted session must still
    /// hold a usable capability, the peer must be authenticated/admitted, and
    /// the canonical policy must admit this exact device.
    pub(super) fn has_usable_authenticated_current(&self, owner: &PeerOwnerToken) -> bool {
        let peer = {
            let current = match self.peers.get(owner.device_id()) {
                Some(current) => current,
                None => return false,
            };
            if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
                return false;
            }
            if !owner.worker_matches(&current.value().peer) {
                return false;
            }
            Arc::clone(&current.value().peer)
        };
        let phase_admits = {
            let data = peer.state.read();
            matches!(
                data.status,
                super::connection::PeerStatus::Active | super::connection::PeerStatus::Shelved
            )
        };
        phase_admits
            && peer.holds_promoted_session()
            && peer.has_usable_session_for_recovery()
            && self.policy_admits(owner.device_id())
    }

    /// Run a synchronous durable-effect operation under the exact owner
    /// fence.  This named seam exists so durable outbox integrations cannot
    /// accidentally substitute a device-only lookup for a current-owner
    /// check.
    pub(crate) fn with_current_durable_outbox<R>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce() -> R,
    ) -> Option<R> {
        self.with_current(owner, |_| effect())
    }

    /// Run a generic durable settlement only when no speculative sidecar owns
    /// the exact delivery. The installation and sidecar check share this
    /// mutation fence, so a promoted owner cannot settle a delivery after a
    /// candidate has bound it, nor can a stale owner redirect the operation.
    pub(super) fn with_current_durable_outbox_unclaimed<R>(
        &self,
        owner: &PeerOwnerToken,
        delivery_id: crate::semantic::ProofDeliveryId,
        effect: impl FnOnce() -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
            || current
                .value()
                .peer
                .speculative_proof_delivery_owned(delivery_id)
        {
            return None;
        }
        Some(effect())
    }

    pub(crate) fn owner(&self, device_id: &str) -> Option<PeerOwnerToken> {
        self.peers.get(device_id).map(|entry| PeerOwnerToken {
            peer: Arc::clone(&entry.value().peer),
            installation: Arc::clone(&entry.value().installation),
            binding_namespace: self.binding_namespace,
            binding_epoch: entry.value().binding_epoch,
            worker: None,
        })
    }

    /// Admit a logical terminal for a captured session witness while allowing
    /// the channel that carried it to have disappeared. The installation is
    /// still exact, but the owner worker is deliberately ignored: this seam
    /// never selects, promotes or re-resolves a channel.
    pub(super) fn admit_logical_terminal_for_witness(
        &self,
        owner: &PeerOwnerToken,
        expected: &crate::runtime::peer_session::LogicalSessionValidityWitness,
    ) -> Option<AdmittedInboundDispatch> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) || !expected.is_live() {
            return None;
        }
        let peer = &current.value().peer;
        if peer.with_logical_session_state(|logical| expected.same_validity(logical.validity()))
            != Some(true)
        {
            return None;
        }
        Some(AdmittedInboundDispatch {
            peer: Arc::clone(peer),
            owner: PeerOwnerToken {
                peer: Arc::clone(peer),
                installation: Arc::clone(&current.value().installation),
                binding_namespace: self.binding_namespace,
                binding_epoch: current.value().binding_epoch,
                worker: None,
            },
            witness: expected.clone(),
        })
    }

    pub(super) fn get_if_current(&self, owner: &PeerOwnerToken) -> Option<Arc<PeerConnection>> {
        self.peers.get(owner.device_id()).and_then(|entry| {
            (Arc::ptr_eq(&entry.value().installation, &owner.installation)
                && owner.worker_matches(&entry.value().peer))
            .then(|| Arc::clone(&entry.value().peer))
        })
    }

    /// Begin one exact-owner legacy untrusted-signaling mutation while the
    /// installation is still unpromoted. Both normal and speculative
    /// promotion refuse while the returned witness is alive, so the
    /// classification cannot be separated from the later awaited effect by a
    /// candidate handoff.
    pub(super) fn begin_unpromoted_negotiation(
        &self,
        owner: &PeerOwnerToken,
    ) -> Option<super::connection::UnpromotedNegotiation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = Arc::clone(&current.value().peer);
        if !peer.begin_unpromoted_negotiation() {
            return None;
        }
        Some(super::connection::UnpromotedNegotiation::new(peer))
    }

    /// Run one synchronous effect only while `owner` is still the installed
    /// peer. Registry replacement and removal take the same mutation lock, so
    /// the effect cannot cross from an accepted callback for peer A into a
    /// replacement peer B that reused the same device id.
    pub(super) fn with_current<R>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        Some(effect(&current.value().peer))
    }

    /// Capture the exact currently selected worker while holding the same
    /// mutation fence used by every owner-bound operation.  The returned
    /// owner is stamped with that worker, so a later replacement cannot be
    /// mistaken for the captured transport session.
    pub(super) fn capture_current_worker_owner(
        &self,
        owner: &PeerOwnerToken,
    ) -> Option<PeerOwnerToken> {
        self.with_current(owner, |peer| {
            let worker = peer.current_worker()?;
            if owner
                .worker()
                .is_some_and(|stamped| !Arc::ptr_eq(stamped, &worker))
            {
                return None;
            }
            Some(owner.for_worker(worker))
        })
        .flatten()
    }

    /// Apply a synchronous witness check to the exact current worker.  No
    /// registry lock is held across an await; callers retain the stamped
    /// worker and re-enter this fence afterwards to validate it again.
    pub(super) fn with_current_transport_worker<R>(
        &self,
        owner: &PeerOwnerToken,
        effect: impl FnOnce(&Arc<crate::transport::WebRtcConnectorWorker>) -> R,
    ) -> Option<R> {
        self.with_current(owner, |peer| {
            let stamped = owner.worker()?;
            let current = peer.current_worker()?;
            Arc::ptr_eq(stamped, &current).then(|| effect(stamped))
        })
        .flatten()
    }

    /// Admit the one durable semantic frame allowed from an authenticated
    /// endpoint that is still awaiting policy approval.
    ///
    /// This is deliberately separate from the application admission helpers:
    /// it never promotes the peer, lends a session capability, or creates a
    /// logical application route.  The worker stamp, endpoint-auth task,
    /// authenticated-channel proof, exact mesh context, and bounded parse
    /// claim are all decided under the mutation fence.  The returned
    /// operation is the only value that carries that decision out of the
    /// fence, and dropping it releases the exact claim on every refusal or
    /// cancellation path.
    pub(super) fn admit_pending_semantic_operation(
        &self,
        owner: &PeerOwnerToken,
        mesh_context: &str,
        bytes: &bytes::Bytes,
    ) -> Option<AdmittedPendingSemanticOperation> {
        let classified = crate::protocol::classify_frame(bytes)?;
        if !matches!(
            classified.admission,
            crate::protocol::FrameAdmission::DurableFact
        ) {
            return None;
        }

        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        let worker = owner.worker()?.clone();
        if !owner.worker_matches(peer)
            || peer
                .current_worker()
                .is_none_or(|current| !Arc::ptr_eq(&current, &worker))
        {
            return None;
        }
        {
            let data = peer.state.read();
            if !data.authenticated
                || !matches!(data.status, super::connection::PeerStatus::PendingApproval)
            {
                return None;
            }
        }
        let endpoint_auth = peer.endpoint_auth_task_for(Some(&worker))?;
        if !pending_semantic_endpoint_is_current(peer, &worker, &endpoint_auth, mesh_context) {
            return None;
        }
        let claim =
            crate::application_gateway::AdmittedApplicationFrame::claim(bytes.len()).ok()?;
        let work = worker.reserve_attempt_work(claim).ok()?;
        Some(AdmittedPendingSemanticOperation {
            owner: owner.clone(),
            worker,
            endpoint_auth,
            mesh_context: mesh_context.to_owned(),
            work,
        })
    }

    /// Admit the narrowly scoped proof exception for an authenticated,
    /// unpromoted speculative candidate.  The registry mutation fence covers
    /// candidate identity, installation identity, endpoint-auth provenance,
    /// and the finite send claim in one synchronous decision.  The callback
    /// is used by the publication owner to rebind the durable record while
    /// this same fence is still held; it must not await or re-resolve by
    /// device id.
    pub(super) fn with_current_speculative_proof<R>(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        mesh_context: &str,
        total_bytes: usize,
        effect: impl FnOnce(AdmittedPendingSemanticOperation) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        let peer = &current.value().peer;
        let (endpoint_auth, work) =
            peer.speculative_proof_admission(correlation, candidate, mesh_context, total_bytes)?;
        Some(effect(AdmittedPendingSemanticOperation {
            owner: owner.clone(),
            worker: Arc::clone(candidate),
            endpoint_auth,
            mesh_context: mesh_context.to_owned(),
            work,
        }))
    }

    /// Bind a durable proof while the exact candidate fence is held.  The
    /// binding is installed before the callback and rolled back if the
    /// publication-side mutation refuses, so no ACK can observe a half-bound
    /// candidate after this method returns.
    // Each identity and accounting witness is independently checked under the
    // registry fence; combining them would obscure the exact candidate,
    // delivery, context, and provider charge being authorized.
    #[allow(clippy::too_many_arguments)]
    pub(super) fn with_current_speculative_proof_bound<R>(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        delivery_id: crate::semantic::ProofDeliveryId,
        mesh_context: &str,
        total_bytes: usize,
        effect: impl FnOnce(AdmittedPendingSemanticOperation) -> Result<R>,
    ) -> Option<Result<R>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        if owner
            .worker()
            .is_some_and(|stamped| !Arc::ptr_eq(stamped, candidate))
        {
            return None;
        }
        let peer = &current.value().peer;
        let (endpoint_auth, work) =
            peer.speculative_proof_admission(correlation, candidate, mesh_context, total_bytes)?;
        if !peer.bind_speculative_proof_delivery(correlation, candidate, delivery_id) {
            return None;
        }
        let result = effect(AdmittedPendingSemanticOperation {
            owner: owner.clone(),
            worker: Arc::clone(candidate),
            endpoint_auth,
            mesh_context: mesh_context.to_owned(),
            work,
        });
        if result.is_err() {
            let _ = peer.clear_speculative_proof_delivery(correlation, candidate, delivery_id);
        }
        Some(result)
    }

    /// Run the durable ACK mutation only while the delivery is bound to the
    /// same exact speculative owner, correlation, and worker.  Publication
    /// locking is supplied by the caller; this registry fence is the
    /// linearization point against replacement, promotion, and candidate
    /// retirement.  A successful settlement clears the binding before the
    /// fence is released.
    pub(super) fn settle_current_speculative_proof(
        &self,
        owner: &PeerOwnerToken,
        candidate: &Arc<crate::transport::WebRtcConnectorWorker>,
        correlation: &str,
        delivery_id: crate::semantic::ProofDeliveryId,
        effect: impl FnOnce() -> Result<bool>,
    ) -> Option<Result<bool>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation) {
            return None;
        }
        if owner
            .worker()
            .is_some_and(|stamped| !Arc::ptr_eq(stamped, candidate))
        {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.speculative_proof_delivery_matches(correlation, candidate, delivery_id) {
            return None;
        }
        let result = effect();
        if matches!(&result, Ok(true)) {
            let _ = peer.clear_speculative_proof_delivery(correlation, candidate, delivery_id);
        }
        Some(result)
    }

    /// Resolve an exact installation without requiring a worker stamp.
    ///
    /// This is deliberately narrower than `with_current`: it is only for a
    /// logical-session operation whose admission already established the
    /// channel witness. A worker belongs to a channel, not to the logical
    /// session, so requiring it again here would let a channel replacement
    /// erase a valid post-admission session commit.
    fn with_current_logical_locked<R>(
        &self,
        operation: &LogicalSessionOperation,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let current = self.peers.get(operation.owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &operation.owner.installation)
            || !operation.witness.is_live()
        {
            return None;
        }
        let peer = &current.value().peer;
        if peer.with_logical_session_state(|logical| {
            operation.witness.same_validity(logical.validity())
        }) != Some(true)
        {
            return None;
        }
        Some(effect(peer))
    }

    fn with_current_logical<R>(
        &self,
        operation: &LogicalSessionOperation,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        self.with_current_logical_locked(operation, effect)
    }

    /// Run one synchronous application operation, only while `owner` is the
    /// installed peer **and** that peer holds a live promoted session.
    ///
    /// This is the one admission linearization point. The owner check and the
    /// promotion — which itself proves the exact current connector, current
    /// policy, the local principal, and a held post-authentication reservation —
    /// are evaluated together under the registry mutation lock, and the witness
    /// that proves them is minted inside it. Replacement takes the same lock, so
    /// it orders strictly before or after the whole effect.
    ///
    /// `None` means the operation was not authorized. The caller deliberately
    /// cannot tell whether the owner was stale or the session was absent: an
    /// admission answer that escaped as a value would be exactly the transient
    /// boolean this replaces.
    ///
    /// Production callers all need one of the specialized arms below — the
    /// refusal arm, an owned witness, or a lent session — so this bare form
    /// exists only for controls that must ask the fence's question and nothing
    /// else. Widening it to a production entry point would be a way to observe
    /// admission without acting on it under the same acquisition.
    #[cfg(test)]
    pub(super) fn with_admitted_current<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(&LogicalSessionOperation) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        let witness = peer.with_logical_session_state(|logical| logical.validity().clone())?;
        Some(effect(&LogicalSessionOperation::new(
            owner.clone(),
            witness,
        )))
    }

    /// The same fence, session-gated, with an explicit refusal arm.
    ///
    /// Inbound application delivery is authorized by the same promoted session
    /// as outbound: a frame reaches the application only once this exact
    /// installation has a live session, so "the application receives no data
    /// before promotion" is enforced by the delivery path itself.
    ///
    /// `refused` receives the exact current peer and may only *record* — it
    /// authorizes nothing, because no witness exists on that arm. It exists so
    /// the inbound path can count a refused application frame under the same
    /// acquisition that refused it, instead of re-entering the registry and
    /// racing its own refusal. A missing broker refuses rather than returning
    /// `None`, because the peer is still the installed one: what failed is
    /// authorization, and the refusal arm is where that is counted. `None`
    /// means the owner is stale.
    pub(super) fn with_admitted_current_or_refused<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        admitted: impl FnOnce(&LogicalSessionOperation) -> R,
        refused: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        let promoted = broker
            .is_some_and(|broker| self.promote_and_announce(peer, owner, broker, mesh_context));
        if !promoted {
            return Some(refused(peer));
        }
        let witness = peer.with_logical_session_state(|logical| logical.validity().clone())?;
        Some(admitted(&LogicalSessionOperation::new_inbound(
            owner.clone(),
            witness,
        )))
    }

    /// Re-enter the fence to commit work an earlier acquisition funded, only if
    /// the exact session that funded it is still this peer's live one.
    ///
    /// This is the second half of a deliberately split admission. Work whose
    /// cost is bounded but whose *duration* is set by peer-supplied input — a
    /// JSON parse over an admitted frame is the case that motivated this — must
    /// not run under the registry's single mutation lock, because that lock
    /// orders every peer's promotion, replacement and dispatch. One peer's
    /// pathological payload would otherwise stall the whole mesh for as long as
    /// the parse takes, and the admission that authorized the parse is exactly
    /// what makes the payload's shape adversary-chosen.
    ///
    /// So the first acquisition admits, records, and *funds*; the work happens
    /// outside every lock; and this commits the result. What that costs is one
    /// extra check, and it is the check the split makes necessary: the session
    /// may have been revoked or replaced while the work ran, and work funded by
    /// a session that is gone authorizes nothing. `witness` is matched by
    /// identity against the peer's current session rather than merely tested for
    /// liveness, so a *replacement* that promoted in the interval refuses here
    /// instead of inheriting the predecessor's admitted frame.
    ///
    /// No refusal arm and no counting. A frame that reaches here was already
    /// admitted and already counted; failing this test means the session went
    /// away underneath it, which is this side's lifecycle and not the peer's
    /// misbehaviour. `None` covers all three ways that happens — stale owner,
    /// no live session, different session — because none of them authorizes the
    /// commit and telling them apart out here would be a distinction the caller
    /// could only misuse.
    pub(super) fn with_same_session<R>(
        &self,
        operation: LogicalSessionOperation,
        committed: impl FnOnce(&LogicalSessionOperation) -> R,
    ) -> Option<R> {
        self.with_current_logical(&operation, |_peer| committed(&operation))
    }

    /// End **exactly** the session `witness` names, and nothing else.
    ///
    /// For the two ways an admitted frame dies after its session has already
    /// been proved current: the owner refuses to fund it, and it does not
    /// decode. Both mean this side is holding a session it cannot use — the
    /// first because the peer's traffic costs more than the owner will pay for,
    /// the second because what arrived over an authenticated channel was not a
    /// message at all — and in both the honest answer is to stop having that
    /// session rather than to drop the frame and wait for the next one.
    ///
    /// **Exactly, and the exactness is the whole design.** Three things are
    /// checked under the mutation lock before anything is torn down: the peer is
    /// still installed under this device id, its installation is still the one
    /// the captured owner names, and its live session is the very one the
    /// witness was minted from. A replacement that promoted while the frame was
    /// being decoded fails the third and is left completely alone — it did not
    /// send this frame, it did not refuse to fund it, and it is not the session
    /// being ended. Removing by device id would have taken it; that is the
    /// device-only removal this deliberately is not.
    ///
    /// **What ending it does.** Only the session slot is cleared. That is
    /// sufficient because of what the session owns: dropping it resolves the
    /// `SessionRpcState` it holds — every pending local call settles, every open
    /// stream is finished — and releases its reliable pending state, all through
    /// `Drop` rather than through a sweep this function would have to perform.
    /// And it cannot come back: promotion **moved** the authenticated channel
    /// into the session, so the slot it came from is already spent and a
    /// re-promotion has nothing to promote until the peer authenticates again.
    ///
    /// No timer, no grace period, no retry. The session either is the one that
    /// failed or is not.
    pub(super) fn retire_exact_session(&self, operation: LogicalSessionOperation) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(operation.owner.device_id()) else {
            return false;
        };
        if !Arc::ptr_eq(&current.value().installation, &operation.owner.installation)
            || !operation.witness.is_live()
        {
            return false;
        }
        let peer = &current.value().peer;
        // Identity, not liveness. "This peer has *a* live session" would retire
        // a successor for its predecessor's failure.
        if peer.with_logical_session_state(|logical| {
            operation.witness.same_validity(logical.validity())
        }) != Some(true)
        {
            return false;
        }
        peer.revoke_promoted_session();
        true
    }

    /// Mint one owned authority for an application operation that will cross an
    /// await, **gated on a live promoted session**.
    ///
    /// Built under the same fence as `with_admitted_current`. Promotion
    /// is what authorizes the send: it proves the exact current connector,
    /// current policy, the authenticated local principal, and a held
    /// post-authentication reservation in one atomic transition under this same
    /// mutation lock, so an operation that cannot name its exact connector has
    /// nothing to write through.
    ///
    /// A `None` broker means the process owner installed no resource provider,
    /// so no session can exist and nothing is authorized. That is fail-closed,
    /// not a compatibility mode: there is deliberately no arm that falls back to
    /// the peer string.
    pub(super) fn admit_application_operation(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
    ) -> Option<AdmittedApplicationOperation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        // A worker-stamped owner selects that exact authenticated channel, not
        // the peer's currently selected connector. This is what lets an
        // existing realtime flow renegotiate on W0 after W1 becomes the
        // preferred application path without sending W0's control through W1.
        // `worker_matches` above already proved the stamped worker belongs to
        // this installation's promoted logical session.
        let session = owner.worker().cloned().or_else(|| peer.current_worker())?;
        let validity = peer.with_logical_session_state(|logical| logical.validity().clone())?;
        let logical = LogicalSessionOperation::new(owner.clone(), validity);
        Some(AdmittedApplicationOperation {
            channel: logical.into_exact_channel(session),
        })
    }

    /// Admit one durable logical reply for the exact operation that funded it,
    /// and bind the resulting send to the session's already-selected channel.
    ///
    /// The logical operation deliberately carries no worker: its L0 witness
    /// must remain usable after the channel that delivered the request is
    /// retired. This fence is the only point that projects that logical
    /// authority back into a transport send. It verifies the exact
    /// installation, the live/current logical validity, and current durable
    /// application policy, then reads the slot's explicitly selected worker.
    /// There is no implicit selection, device-only re-resolution, or fallback
    /// to the compatibility worker mirror. A same-installation L1 witness and
    /// an unselected or no-longer-owned channel both refuse.
    pub(super) fn admit_logical_reply_application_operation(
        &self,
        operation: &LogicalSessionOperation,
    ) -> Option<AdmittedApplicationOperation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(operation.owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &operation.owner.installation)
            || !operation.witness.is_live()
        {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.holds_promoted_session()
            || !self.policy_admits(operation.owner.device_id())
            || peer.with_logical_session_state(|logical| {
                operation.witness.same_validity(logical.validity())
            }) != Some(true)
        {
            return None;
        }
        let worker = peer.current_worker()?;
        if !peer.owns_authenticated_worker(&worker) {
            return None;
        }
        let logical =
            LogicalSessionOperation::new(operation.owner.clone(), operation.witness.clone());
        Some(AdmittedApplicationOperation {
            channel: logical.into_exact_channel(worker),
        })
    }

    /// Admit a queued control on its originally captured authenticated channel.
    /// No selected-channel lookup and no replacement logical witness is minted.
    pub(super) fn admit_exact_channel_application_operation(
        &self,
        mut channel: ExactChannelOperation,
    ) -> Option<AdmittedApplicationOperation> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(channel.owner().device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &channel.owner().installation)
            || !channel.witness().is_live()
        {
            return None;
        }
        let peer = &current.value().peer;
        if !peer.holds_promoted_session()
            || !self.policy_admits(channel.owner().device_id())
            || !peer.owns_authenticated_worker(channel.worker())
            || peer.with_logical_session_state(|logical| {
                channel.witness().same_validity(logical.validity())
            }) != Some(true)
        {
            return None;
        }
        // ExactChannelOperation already carries the captured worker, while
        // its logical owner is deliberately workerless. Stamp that SAME worker
        // so begin() also rechecks channel ownership after its native permit
        // acquisition. A preferred W1 is never substituted for an owned W0.
        channel.logical.owner = channel
            .logical
            .owner
            .for_worker(Arc::clone(&channel.worker));
        Some(AdmittedApplicationOperation { channel })
    }

    /// Run one realtime-flow operation against a live promoted session and a
    /// freshly acquired live connector incarnation.
    ///
    /// This is the engine-side bridge a Device selector resolves through. The
    /// selector names an installation; everything the operation is authorized by
    /// is produced inside this fence, under the mutation lock, at the moment of
    /// use — the session by promotion, the incarnation by fresh acquisition from
    /// the current worker.
    ///
    /// The session is **lent**, never handed out. It is not `Clone`, the borrow
    /// ends with the closure, and nothing here is serializable, so no session
    /// authority can escape to IPC or outlive the fence that authorized it.
    /// Run one operation against a live promoted session, lending the session
    /// and nothing else.
    ///
    /// The generic form of the fence below, for operations that must prove a
    /// current session authorized them but have no business touching the
    /// realtime flow set. Same conjuncts, same `None` on any failure: current
    /// installation, promotion, live incarnation, session belongs to it.
    ///
    /// The session is **lent**, never handed out — not `Clone`, borrow ends with
    /// the closure, nothing serializable — so no session authority escapes to
    /// IPC or outlives the fence that authorized it.
    pub(super) fn with_live_session<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(&crate::runtime::session_broker::SessionCapability) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session(effect)
    }

    /// Run one operation against a live promoted session and the application
    /// state that session owns.
    ///
    /// The same fence, projected to the application side. What `effect` mutates
    /// is a field of the session it is handed, so the state cannot outlive the
    /// authority that admitted it and a replacement cannot reach its
    /// predecessor's — there is no key by which to name one.
    pub(crate) fn with_live_session_state<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        peer.with_live_session_state(effect)
    }

    /// The installations whose live session still holds frames that have not
    /// reached the wire.
    ///
    /// Owner tokens, not device ids: the flush that follows must reach the exact
    /// installation whose record was read, and a device id re-resolved after
    /// this snapshot could name a replacement. Non-promoting, like the backlog
    /// count below — a tick that promoted sessions in order to decide whether to
    /// flush them would create the very thing it was checking for.
    pub(super) fn owners_with_unsent_reliable_frames(&self) -> Vec<PeerOwnerToken> {
        let _mutation = self.mutation.lock();
        self.owners_snapshot(|peer| {
            self.policy_admits(&peer.device_id)
                && peer
                    .with_live_session_state(|_session, record| record.has_unsent())
                    .unwrap_or(false)
        })
    }

    /// Frames retained and unacknowledged across every peer holding a live
    /// session — the acked-delivery backlog the status surface reports.
    ///
    /// Deliberately **non-promoting**: it reads the sessions that exist and
    /// creates none. A diagnostic read that promoted would make observing the
    /// backlog change what the backlog is, and would take a post-authentication
    /// reservation on behalf of a caller that asked for a number. A peer with no
    /// live session contributes nothing, which is exact rather than approximate
    /// — with no session there is nothing retained.
    pub(super) fn reliable_pending_total(&self) -> usize {
        let _mutation = self.mutation.lock();
        self.collect_map(|peer| {
            self.policy_admits(&peer.device_id)
                .then(|| peer.with_live_session_state(|_session, app| app.pending()))
                .flatten()
        })
        .into_iter()
        .sum()
    }

    pub(super) fn with_live_session_flow<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        match owner.worker() {
            Some(worker) => peer.with_live_session_flow_and_exact_worker(
                worker,
                |session, flows, live, _worker| effect(session, flows, live),
            ),
            None => peer.with_live_session_flow(effect),
        }
    }

    /// The same fence, additionally lending the connector worker.
    ///
    /// Used only by the two-phase native-negotiation path, which has to reach
    /// the connector from outside the lock. See
    /// [`PeerConnection::with_live_session_flow_and_worker`] for why the handle
    /// is not authority.
    pub(super) fn with_live_session_flow_and_worker<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<crate::transport::WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        match owner.worker() {
            Some(worker) => peer.with_live_session_flow_and_exact_worker(worker, effect),
            None => peer.with_live_session_flow_and_worker(effect),
        }
    }

    fn with_live_session_flow_and_exact_worker_with_correlation<R>(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::connector::ConnectorIncarnation>,
            &Arc<crate::transport::WebRtcConnectorWorker>,
            &str,
        ) -> R,
    ) -> Option<R> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        if !self.promote_and_announce(peer, owner, broker?, mesh_context) {
            return None;
        }
        let worker = owner.worker()?;
        peer.with_live_session_flow_and_exact_worker_with_correlation(worker, effect)
    }

    /// Claim the pending renegotiation for `owner`, if there is one to claim.
    ///
    /// Renegotiation drives SDP on the connector and opens no flow, so what it
    /// needs is the connector this session was promoted from — proved live at
    /// the moment of the claim, not carried in from an earlier decision. That
    /// is exactly what [`Self::with_live_session_flow_and_worker`] establishes:
    /// the owner is current, the session is promoted, the incarnation is
    /// freshly acquired from the current worker, and the session belongs to it.
    /// A superseded connector satisfies none of those and yields `None`.
    ///
    /// **An empty flow set is not a refusal.** The flow set is lent and
    /// deliberately not inspected: a track-set change that *removed* the last
    /// flow is precisely the case that most needs an offer, and keying the
    /// claim off flow presence would strand that peer holding a track set its
    /// peer never learns about.
    ///
    /// The claim is taken **inside** the fence, after validation, and never by
    /// a separate call before it. `media_reneg_inflight` is cleared only by the
    /// spawned renegotiation task, so latching it and then failing validation
    /// would leave the single-flight guard set and that peer would never
    /// renegotiate again.
    ///
    /// The returned value carries the exact owner captured here. Re-resolving
    /// it by device id afterwards would reopen the window this exists to close:
    /// a replacement installed between the claim and that lookup would answer
    /// it, and the spawned task's completion bookkeeping would land on the
    /// replacement instead of the peer whose renegotiation actually ran.
    pub(super) fn claim_renegotiation(
        &self,
        owner: &PeerOwnerToken,
        broker: Option<&SessionBroker>,
        mesh_context: &str,
    ) -> Option<AdmittedRenegotiation> {
        let peer = self.get_if_current(owner)?;
        let worker = peer.media_renegotiation_worker()?;
        let exact_owner = owner.for_worker(Arc::clone(&worker));
        let logical_witness =
            peer.with_logical_session_state(|logical| logical.validity().clone())?;
        self.with_live_session_flow_and_exact_worker_with_correlation(
            &exact_owner,
            broker,
            mesh_context,
            |_session, _flows, _live, worker, correlation| {
                let mut data = peer.state.write();
                // Pending is a coalesced debt bit, while inflight is the
                // single-flight latch.  Both must be decided under this
                // state lock: a callback may re-arm pending after the first
                // claim but it must not mint a second operation until the
                // captured one has completed.
                if !data.media_reneg_pending || data.media_reneg_inflight {
                    return None;
                }
                data.media_reneg_inflight = true;
                data.media_reneg_pending = false;
                drop(data);
                Some(AdmittedRenegotiation {
                    channel: LogicalSessionOperation::new(
                        exact_owner.clone(),
                        logical_witness.clone(),
                    )
                    .into_exact_channel(Arc::clone(worker)),
                    correlation: correlation.to_string(),
                })
            },
        )
        .flatten()
    }

    /// Snapshot owner tokens for the entries `select` accepts.
    ///
    /// The token-shaped counterpart to [`Self::values_snapshot`], for any work
    /// that picks peers now and acts on them later — a fanout, and the departure
    /// sweep in `depart_authenticated_sessions`, which passes
    /// `PeerConnection::holds_promoted_session` as its selector.
    ///
    /// Owner tokens rather than device id **strings**, because a string has to
    /// be re-resolved at the moment of action: between the collection and the
    /// send a peer can be replaced, and the replacement answers the lookup and
    /// receives the effect chosen for its predecessor. An owner token names one
    /// *installation*, so after replacement it names nothing and that element
    /// simply drops.
    ///
    /// Selection stays a policy read — it is not authority. Each element is
    /// still individually authorized by the session gate when it is sent, and a
    /// selector that accepts everything (`|_| true`) is a legitimate whole-map
    /// snapshot rather than a second helper.
    pub(super) fn owners_snapshot(
        &self,
        mut select: impl FnMut(&PeerConnection) -> bool,
    ) -> Vec<PeerOwnerToken> {
        self.peers
            .iter()
            .filter(|entry| select(&entry.value().peer))
            .map(|entry| PeerOwnerToken {
                peer: Arc::clone(&entry.value().peer),
                installation: Arc::clone(&entry.value().installation),
                binding_namespace: self.binding_namespace,
                binding_epoch: entry.value().binding_epoch,
                worker: None,
            })
            .collect()
    }

    /// Visit current installation tokens without retaining a whole-registry
    /// snapshot. Consumers may keep a bounded page of selected tokens; this
    /// method itself retains only one temporary token per iteration.
    ///
    /// This remains an O(registry size) scan, not an indexed page lookup.
    /// Selection is not authorization: callers must recheck the exact owner
    /// through the normal session gate before acting on a retained token.
    /// The synchronous visitor must not mutate this registry or await work.
    pub(super) fn visit_owners(&self, mut visit: impl FnMut(PeerOwnerToken)) {
        for entry in self.peers.iter() {
            let owner = PeerOwnerToken {
                peer: Arc::clone(&entry.value().peer),
                installation: Arc::clone(&entry.value().installation),
                binding_namespace: self.binding_namespace,
                binding_epoch: entry.value().binding_epoch,
                worker: None,
            };
            drop(entry);
            visit(owner);
        }
    }

    pub(super) fn contains_key(&self, device_id: &str) -> bool {
        self.peers.contains_key(device_id)
    }

    pub(super) fn len(&self) -> usize {
        self.peers.len()
    }

    pub(super) fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// Snapshot peer owners without duplicating registry keys. The peer already
    /// owns its device id, so value-oriented scans need one `Arc` clone only.
    pub(super) fn values_snapshot(&self) -> Vec<Arc<PeerConnection>> {
        self.peers
            .iter()
            .map(|entry| Arc::clone(&entry.value().peer))
            .collect()
    }

    /// Build one output vector from an `Arc`-only snapshot. The DashMap guards
    /// are released before the callback can take a peer-state lock, so no key
    /// is cloned and no registry-to-peer lock order is introduced.
    pub(super) fn collect_map<T>(
        &self,
        mut map: impl FnMut(&PeerConnection) -> Option<T>,
    ) -> Vec<T> {
        self.values_snapshot()
            .into_iter()
            .filter_map(|peer| map(peer.as_ref()))
            .collect()
    }

    /// Visit an `Arc`-only snapshot after releasing every DashMap guard.
    pub(super) fn visit(&self, mut visit: impl FnMut(&PeerConnection)) {
        for peer in self.values_snapshot() {
            visit(peer.as_ref());
        }
    }

    pub(super) fn count_where(&self, mut predicate: impl FnMut(&PeerConnection) -> bool) -> usize {
        self.values_snapshot()
            .into_iter()
            .filter(|peer| predicate(peer.as_ref()))
            .count()
    }

    /// Snapshot only registry keys for topology code that does not need peer
    /// state or connector ownership.
    pub(super) fn device_ids_snapshot(&self) -> Vec<String> {
        self.peers.iter().map(|entry| entry.key().clone()).collect()
    }

    /// Install a peer and retain the exact predecessor identity when this is
    /// a same-device replacement. The mutation fence covers the map swap and
    /// owner capture together; no caller needs to re-resolve the displaced
    /// device after the replacement.
    pub(super) fn install_with_displaced_owner(
        &self,
        peer: Arc<PeerConnection>,
    ) -> Option<DisplacedPeerInstallation> {
        let device_id = peer.device_id.clone();
        let _mutation = self.mutation.lock();
        // Whole-network shutdown deliberately leaves retired originals in the
        // map until their native joins finish. Do not replace one while its
        // exact pointer is still retained for completion.
        if self
            .peers
            .get(&device_id)
            .is_some_and(|current| current.value().peer.registry_retired())
        {
            return None;
        }
        if self
            .peers
            .get(&device_id)
            .is_some_and(|current| Arc::ptr_eq(&current.value().peer, &peer))
        {
            return None;
        }
        if peer.registry_retired() {
            return None;
        }
        let binding_epoch = self
            .next_binding_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value == 0 || value == u64::MAX {
                    None
                } else {
                    Some(value + 1)
                }
            })
            .ok()?;
        let replaced = self
            .peers
            .insert(
                device_id,
                PeerRegistryEntry {
                    peer: Arc::clone(&peer),
                    installation: Arc::new(()),
                    binding_epoch,
                },
            )
            .map(|entry| {
                let owner = PeerOwnerToken {
                    peer: Arc::clone(&entry.peer),
                    installation: Arc::clone(&entry.installation),
                    binding_namespace: self.binding_namespace,
                    binding_epoch: entry.binding_epoch,
                    worker: None,
                };
                DisplacedPeerInstallation {
                    peer: entry.peer,
                    owner,
                }
            });
        if let Some(runtime) = self.signaling_runtime.read().as_ref() {
            peer.bind_signaling_runtime(runtime.clone());
        }
        if let Some(replaced) = replaced.as_ref() {
            replaced.peer.retire_connector();
        }
        replaced
    }

    /// Install only a fresh, empty introduction placeholder. The caller funds
    /// its peer/key/map backing before entry. This never displaces an owner or
    /// promotes/authenticates a session; native construction happens later.
    pub(super) fn introduction_placeholder_claim(
        device_bytes: usize,
    ) -> Result<crate::resource::ResourceClaim> {
        let bytes = std::mem::size_of::<PeerConnection>()
            .checked_add(std::mem::size_of::<PeerRegistryEntry>())
            .and_then(|n| n.checked_add(device_bytes.checked_mul(2)?))
            .and_then(|n| n.checked_add(32))
            .ok_or_else(|| Error::Network("introduction peer backing overflow".into()))?;
        crate::resource::ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                u64::try_from(bytes)
                    .map_err(|_| Error::Network("introduction peer backing overflow".into()))?,
            ),
            // Two strings, exact 32-byte attempt, Arc connection/installation
            // controls and the dependency-private map node representation.
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 6),
        ])
        .map_err(|_| Error::Network("introduction peer claim overflow".into()))
    }

    pub(super) fn install_unpromoted_if_absent(
        &self,
        peer: Arc<PeerConnection>,
    ) -> Option<PeerOwnerToken> {
        let _mutation = self.mutation.lock();
        if self.peers.contains_key(&peer.device_id)
            || peer.registry_retired()
            || peer.has_current_worker()
            || peer.holds_promoted_session()
            || peer.has_authenticated_channel()
            || peer.state.read().authenticated
        {
            return None;
        }
        let binding_epoch = self
            .next_binding_epoch
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |value| {
                if value == 0 || value == u64::MAX {
                    None
                } else {
                    Some(value + 1)
                }
            })
            .ok()?;
        let installation = Arc::new(());
        let owner = PeerOwnerToken {
            peer: Arc::clone(&peer),
            installation: Arc::clone(&installation),
            binding_namespace: self.binding_namespace,
            binding_epoch,
            worker: None,
        };
        if let Some(runtime) = self.signaling_runtime.read().as_ref() {
            peer.bind_signaling_runtime(runtime.clone());
        }
        self.peers.insert(
            peer.device_id.clone(),
            PeerRegistryEntry {
                peer,
                installation,
                binding_epoch,
            },
        );
        Some(owner)
    }

    /// Compatibility projection for callers that only need the displaced
    /// connection. New replacement-aware callers should use
    /// [`Self::install_with_displaced_owner`].
    pub(super) fn install(&self, peer: Arc<PeerConnection>) -> Option<Arc<PeerConnection>> {
        self.install_with_displaced_owner(peer)
            .map(|replaced| replaced.peer)
    }

    pub(super) fn remove(
        &self,
        device_id: &str,
    ) -> Option<(
        Arc<PeerConnection>,
        Option<Arc<crate::transport::WebRtcConnectorWorker>>,
    )> {
        let _mutation = self.mutation.lock();
        let (_, entry) = self.peers.remove(device_id)?;
        let peer = entry.peer;
        let worker = peer.current_worker();
        peer.retire_connector();
        Some((peer, worker))
    }

    #[cfg(test)]
    pub(super) fn remove_if_current(&self, owner: &PeerOwnerToken) -> Option<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        if owner
            .worker()
            .is_some_and(|_| current.value().peer.promoted_channel_count() > 1)
        {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    /// Remove one exact authenticated channel while retaining the logical peer
    /// session. This is the channel-terminal half of [`super::drop_peer_if_current`];
    /// the caller awaits the returned worker and releases only its exact dedup
    /// custody after this fence is dropped.
    /// Remove one exact terminal owner, or the whole peer when it is the last
    /// authenticated channel, under one mutation fence. The caller receives a
    /// typed outcome so a channel added before this fence cannot make the first
    /// exact retirement disappear into a later whole-peer check.
    pub(super) fn remove_current_channel_for_terminal(
        &self,
        operation: ExactChannelOperation,
    ) -> ChannelTerminal {
        let _mutation = self.mutation.lock();
        let owner = operation.owner().clone();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return ChannelTerminal::Stale;
        };
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !operation.witness().is_live()
        {
            return ChannelTerminal::Stale;
        }
        let peer = &current.value().peer;
        if peer.with_logical_session_state(|logical| {
            operation.witness().same_validity(logical.validity())
        }) != Some(true)
            || !peer.owns_authenticated_worker(operation.worker())
        {
            return ChannelTerminal::Stale;
        }
        let Some(removed) = peer.retire_authenticated_worker(operation.worker()) else {
            return ChannelTerminal::Stale;
        };
        if let Some(carrier) = departure_carrier(operation.worker()) {
            peer.with_logical_session_state(|logical| {
                logical.cancel_departure_for_carrier(carrier)
            });
        }
        if removed.session_empty {
            drop(current);
            let Some((_, entry)) = self.peers.remove(owner.device_id()) else {
                return ChannelTerminal::Stale;
            };
            let peer = entry.peer;
            peer.retire_connector();
            return ChannelTerminal::Peer {
                peer,
                channel: removed,
            };
        }
        ChannelTerminal::Channel { channel: removed }
    }

    pub(super) fn remove_current_logical_session_for_terminal(
        &self,
        operation: LogicalSessionOperation,
    ) -> LogicalSessionTerminal {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(operation.owner.device_id()) else {
            return LogicalSessionTerminal::Stale;
        };
        if !Arc::ptr_eq(&current.value().installation, &operation.owner.installation)
            || !operation.witness.is_live()
        {
            return LogicalSessionTerminal::Stale;
        }
        let peer = &current.value().peer;
        if peer.with_logical_session_state(|logical| {
            operation.witness.same_validity(logical.validity())
        }) != Some(true)
        {
            return LogicalSessionTerminal::Stale;
        }
        drop(current);
        let Some((_, entry)) = self.peers.remove(operation.owner.device_id()) else {
            return LogicalSessionTerminal::Stale;
        };
        let peer = entry.peer;
        peer.retire_connector();
        LogicalSessionTerminal::Removed(peer)
    }

    /// Begin one local graceful departure against the exact installed
    /// logical session and its sole currently usable carrying channel.
    ///
    /// Selection and pending-observation admission share this mutation fence,
    /// so a channel terminal or replacement cannot slip between the two.  The
    /// returned worker stamp is used only for the departure frame; the waiter
    /// itself is funded by the logical validity lineage.
    pub(super) fn begin_local_departure(
        &self,
        owner: &PeerOwnerToken,
        correlation: &crate::protocol::DepartureCorrelation,
    ) -> Option<
        std::result::Result<
            AdmittedLocalDeparture,
            crate::runtime::peer_session::DepartureAdmissionError,
        >,
    > {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !owner.worker_matches(&current.value().peer)
        {
            return None;
        }
        let peer = &current.value().peer;
        let worker = peer.select_unique_usable_channel()?;
        let carrier = departure_carrier(&worker)?;
        let witness_and_waiter = peer.with_logical_session_state(|logical| {
            let witness = logical.validity().clone();
            logical
                .begin_departure(correlation.clone(), carrier)
                .map(|waiter| (witness, waiter))
        })?;
        Some(
            witness_and_waiter.map(|(witness, waiter)| AdmittedLocalDeparture {
                owner: owner.for_worker(worker),
                witness,
                waiter,
            }),
        )
    }

    /// Cancel every currently installed logical session's one pending local
    /// departure. Shutdown calls this before awaiting a departure sweep, so a
    /// missing remote receipt cannot keep daemon shutdown parked forever. The
    /// mutation fence preserves exact installation/validity custody while the
    /// runtime state releases only its own observation lease.
    pub(super) fn cancel_pending_departures_for_shutdown(&self) -> usize {
        let _mutation = self.mutation.lock();
        self.peers
            .iter()
            .filter_map(|entry| {
                entry
                    .value()
                    .peer
                    .with_logical_session_state(|logical| logical.cancel_departure_for_shutdown())
            })
            .filter(|cancelled| *cancelled)
            .count()
    }

    /// Read the number of exact logical records currently holding a pending
    /// departure observation. This is an observation for shutdown controls;
    /// it does not admit, select, or retain any session.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn pending_departure_count(&self) -> usize {
        let _mutation = self.mutation.lock();
        self.peers
            .iter()
            .filter_map(|entry| {
                entry
                    .value()
                    .peer
                    .with_logical_session_state(|logical| logical.departure_pending())
            })
            .filter(|pending| *pending)
            .count()
    }

    /// Admit a remote Depart only on the exact authenticated carrying channel
    /// that delivered it and retain the send permit for its receipt. The exact
    /// logical retirement is deferred until the receipt has settled outside the
    /// fence; if a local departure is pending, its matching waiter owns that
    /// final edge. No await occurs while the fence is held, and a duplicate or
    /// stale dispatch cannot remove a successor installation.
    pub(super) fn accept_remote_departure(
        &self,
        dispatch: &AdmittedInboundDispatch,
        correlation: &crate::protocol::DepartureCorrelation,
        receipt_frame_len: usize,
    ) -> RemoteDepartureAdmission {
        let _mutation = self.mutation.lock();
        let Some(worker) = dispatch.owner.worker().cloned() else {
            return RemoteDepartureAdmission::Stale;
        };
        let Some(current) = self.peers.get(dispatch.owner.device_id()) else {
            return RemoteDepartureAdmission::Stale;
        };
        if !Arc::ptr_eq(&current.value().installation, &dispatch.owner.installation)
            || !dispatch.witness.is_live()
            || !dispatch.owner.worker_matches(&current.value().peer)
        {
            return RemoteDepartureAdmission::Stale;
        }
        let peer = &current.value().peer;
        // Acquire the exact receipt custody before committing remote-terminal
        // state. If the logical admission below rejects as stale, this value
        // drops without publishing a terminal transition or retaining a
        // provider lease.
        let receipt = remote_departure_receipt_claim(receipt_frame_len)
            .ok()
            .and_then(|claim| dispatch.witness.reserve_retained(claim).ok())
            .and_then(|_frame_lease| {
                worker.begin_send().ok().map(|send| {
                    Box::new(RemoteDepartureReceipt {
                        send,
                        frame_len: receipt_frame_len,
                        _frame_lease,
                    })
                })
            });
        let Some(defer_retirement) = peer
            .with_logical_session_state(|logical| {
                if !dispatch.witness.same_validity(logical.validity())
                    || !logical.accept_remote_departure(correlation)
                {
                    return None;
                }
                Some(logical.departure_pending())
            })
            .flatten()
        else {
            return RemoteDepartureAdmission::Stale;
        };
        let defer_retirement = defer_retirement && receipt.is_some();
        RemoteDepartureAdmission::Accepted {
            receipt,
            operation: dispatch.logical_reply_operation(),
            defer_retirement,
        }
    }

    /// Remove one stamped demand-owned installation at the same mutation
    /// fence as application admission. The caller's bounded eligibility
    /// closure must retain its idle-use reservation and must not re-enter this
    /// registry or await. It checks policy exclusions and actual queue state;
    /// the token check here can never substitute a successor worker.
    ///
    /// Native close belongs to the returned peer's caller, outside this lock.
    /// Existing general-purpose removal semantics are deliberately unchanged.
    pub(super) fn remove_demand_owner_if(
        &self,
        owner: &PeerOwnerToken,
        eligible: impl FnOnce(&Arc<PeerConnection>) -> bool,
    ) -> Option<Arc<PeerConnection>> {
        let stamped = owner.worker()?;
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !Arc::ptr_eq(&current.value().peer, owner.connection())
            || current
                .value()
                .peer
                .current_worker()
                .is_none_or(|worker| !Arc::ptr_eq(&worker, stamped))
            || current.value().peer.registry_retired()
            || !eligible(&current.value().peer)
        {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    /// The callback acquires the existing demand-record lock, checks its full
    /// ticket/generation, and stores detached custody before returning. This
    /// fence intentionally does not use worker_matches/current_worker: W0 may
    /// still be the unpromoted owner while an independent W1 is selected.
    pub(super) fn with_introduction_installation(
        &self,
        owner: &PeerOwnerToken,
        detach: impl FnOnce(&Arc<PeerConnection>) -> Option<bool>,
    ) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(owner.device_id()) else {
            return false;
        };
        let peer = &current.value().peer;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !Arc::ptr_eq(peer, owner.connection())
            || peer.registry_retired()
        {
            return false;
        }
        // Some(false) still detached the exact failed worker, but preserves
        // an independently pinned/infrastructure installation. The caller
        // retains its eligibility guards through this synchronous removal.
        let Some(may_remove) = detach(peer) else {
            return false;
        };
        let remove = may_remove && peer.retire_empty_introduction_installation();
        drop(current);
        if remove {
            // Still the same installation under the original mutation guard.
            // No broad retire_connector: independent owners were excluded.
            self.peers.remove(owner.device_id());
        }
        true
    }

    /// Cancel only the original introduction placeholder before it acquired
    /// any worker or independent negotiation. The caller additionally proves
    /// its original ticket/attempt synchronously, without re-entering this
    /// registry. No successor, even on the same connection Arc, is removable.
    pub(super) fn remove_unstarted_introduction_if(
        &self,
        owner: &PeerOwnerToken,
        eligible: impl FnOnce(&Arc<PeerConnection>) -> bool,
    ) -> Option<Arc<PeerConnection>> {
        if owner.worker().is_some() {
            return None;
        }
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        let peer = &current.value().peer;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || !Arc::ptr_eq(peer, owner.connection())
            || peer.current_worker().is_some()
            || peer.registry_retired()
            || peer.holds_promoted_session()
            || peer.has_authenticated_channel()
            || peer.state.read().authenticated
            || peer.unpromoted_offer_in_flight()
            || peer.has_speculative()
            || peer.endpoint_auth_task().is_some()
            || peer.media_renegotiation_worker().is_some()
            || !eligible(peer)
        {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    pub(super) fn remove_if_current_unpromoted(
        &self,
        owner: &PeerOwnerToken,
    ) -> Option<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || current.value().peer.holds_promoted_session()
            || current.value().peer.unpromoted_offer_in_flight()
        {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    pub(super) fn remove_if_current_unpromoted_offer(
        &self,
        owner: &PeerOwnerToken,
    ) -> Option<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let current = self.peers.get(owner.device_id())?;
        if !Arc::ptr_eq(&current.value().installation, &owner.installation)
            || current.value().peer.holds_promoted_session()
        {
            return None;
        }
        drop(current);
        let (_, entry) = self.peers.remove(owner.device_id())?;
        let peer = entry.peer;
        peer.retire_connector();
        Some(peer)
    }

    /// Remove every current owner after retiring its connector worker.
    /// Returned peers let shutdown close sessions after map ownership ends.
    pub(super) fn retire_all(&self) -> Vec<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let retired: Vec<_> = self
            .peers
            .iter()
            .map(|entry| Arc::clone(&entry.value().peer))
            .collect();
        for peer in &retired {
            peer.retire_connector();
        }
        self.peers.clear();
        retired
    }

    /// Prepare every current peer for asynchronous whole-network shutdown
    /// without clearing the registry's original owners.  The mutation fence
    /// makes the snapshot and authority revocation one operation; callers
    /// remove each exact pointer only after its native close has joined.
    pub(super) fn prepare_for_shutdown(&self) -> Vec<Arc<PeerConnection>> {
        let _mutation = self.mutation.lock();
        let peers: Vec<_> = self
            .peers
            .iter()
            .map(|entry| Arc::clone(&entry.value().peer))
            .collect();
        for peer in &peers {
            peer.prepare_for_shutdown();
        }
        peers
    }

    /// Remove one prepared peer only when the registry still owns that exact
    /// installation.  A replacement or stale pointer cannot consume it.
    pub(super) fn complete_shutdown_peer(&self, peer: &Arc<PeerConnection>) -> bool {
        let _mutation = self.mutation.lock();
        let Some(current) = self.peers.get(&peer.device_id) else {
            return false;
        };
        if !Arc::ptr_eq(&current.value().peer, peer) {
            return false;
        }
        drop(current);
        self.peers.remove(&peer.device_id).is_some()
    }
}

impl Drop for PeerRegistry {
    fn drop(&mut self) {
        let retired = self.retire_all();
        drop(retired);
    }
}

/// Proof that one exact peer installation held a live promoted session, valid
/// only for the body of one synchronous effect.
///
/// Named for the invariant it carries and nothing else: a live session for
/// *this* installation. That is the whole of what the fence establishes, and it
/// is what every operation below relies on. Current policy is proved *inside*
/// promotion and consumed by it, so the witness stands alone: no second
/// connector-side capability and no delivery boolean sits behind it to be kept
/// in step.
///
/// Minted only inside the registry fence, so possessing one *is* the proof that
/// the owner was current and admission held at a single linearization point.
/// The peer is bound internally and reached through the operations below rather
/// than handed out, so a witness for peer A cannot be presented alongside peer
/// B's connection. [`Self::record_inbound`] is the one exception: it lends the
/// exact admitted peer to a closure. That `Arc` conveys no admission authority —
/// it is the same handle any registry read yields — and the borrow ends with the
/// closure, inside the fence.
///
/// `PhantomData<*const ()>` makes it `!Send`: it cannot be moved into a task,
/// and the lifetime keeps it inside the closure, so it can never be held across
/// an await or outlive the fence that minted it.
pub(super) struct LogicalSessionOperation {
    owner: PeerOwnerToken,
    witness: crate::runtime::peer_session::LogicalSessionValidityWitness,
    /// A channel stamp retained only long enough to construct the inbound
    /// dispatch. It is deliberately absent from ordinary logical operations;
    /// no logical lender or delayed commit consults this field.
    inbound_worker: Option<Arc<crate::transport::WebRtcConnectorWorker>>,
}

impl LogicalSessionOperation {
    fn new(
        mut owner: PeerOwnerToken,
        witness: crate::runtime::peer_session::LogicalSessionValidityWitness,
    ) -> Self {
        // A logical operation names only the installed lineage and its
        // validity witness. Channel identity is retained solely by the
        // ExactChannelOperation worker field; allowing this owner stamp to
        // survive would make a later logical commit stale after channel
        // replacement within the same session.
        owner.worker = None;
        Self {
            owner,
            witness,
            inbound_worker: None,
        }
    }

    fn new_inbound(
        owner: PeerOwnerToken,
        witness: crate::runtime::peer_session::LogicalSessionValidityWitness,
    ) -> Self {
        let inbound_worker = owner.worker.clone();
        let mut operation = Self::new(owner, witness);
        operation.inbound_worker = inbound_worker;
        operation
    }

    pub(super) fn owner(&self) -> &PeerOwnerToken {
        &self.owner
    }

    pub(super) fn witness(&self) -> &crate::runtime::peer_session::LogicalSessionValidityWitness {
        &self.witness
    }

    pub(super) fn session_witness(
        &self,
    ) -> crate::runtime::peer_session::LogicalSessionValidityWitness {
        self.witness.clone()
    }

    /// The exact admitted peer's device id.
    ///
    /// Production dispatch reads the id off the owner token it already carries,
    /// so this exists for controls that must name the peer the fence admitted
    /// without holding a witness for anything else.
    #[cfg(test)]
    pub(super) fn device_id(&self) -> &str {
        self.owner.device_id()
    }

    /// Record inbound liveness and traffic on the exact admitted peer.
    pub(super) fn record_inbound(&self, effect: impl FnOnce(&Arc<PeerConnection>)) {
        effect(self.owner.connection());
    }

    /// Lend the live session this fence admitted, and the application state it
    /// owns.
    ///
    /// No further locking: this fence already holds the mutation lock and has
    /// already promoted, so the session it lends is the one the admission was
    /// decided on. `None` only if the promoted session was invalidated by its
    /// connector between promotion and here, which is the same answer every
    /// other operation gives in that case.
    ///
    /// Used by the inbound acknowledgement path, which must settle retained
    /// frames under the very acquisition that admitted the acknowledgement — an
    /// acknowledgement applied after the fence could settle frames a
    /// replacement's session had merely numbered the same way.
    pub(super) fn with_session_state<R>(
        &self,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        self.owner.connection().with_live_session_state(effect)
    }

    /// Lend only the one logical application state this witness names.
    ///
    /// This is the delayed-commit surface: it carries no SessionCapability and
    /// performs no selected-channel lookup. The connection layer supplies the
    /// logical-session lender.
    pub(super) fn with_logical_state<R>(
        &self,
        effect: impl FnOnce(&mut crate::runtime::peer_session::LogicalSessionOperation<'_>) -> R,
    ) -> Option<R> {
        self.owner.connection().with_logical_session_state(effect)
    }

    /// Capture the admitted inbound installation, accepted channel and logical
    /// witness without carrying any decoded frame state.
    pub(super) fn capture_inbound_dispatch(&self) -> AdmittedInboundDispatch {
        let owner = self.inbound_worker.as_ref().map_or_else(
            || self.owner.clone(),
            |worker| self.owner.for_worker(Arc::clone(worker)),
        );
        AdmittedInboundDispatch {
            peer: Arc::clone(self.owner.connection()),
            owner,
            witness: self.witness.clone(),
        }
    }

    /// Take one admitted inbound frame as an owned, move-only operation.
    ///
    /// The message is moved *in* to the fence by the caller and comes back out
    /// only here, on the admitted arm, bound to the exact dispatch captured
    /// above. The binding is what lets the dispatch name *this* installation
    /// instead of re-resolving a device id a replacement may have taken over.
    pub(super) fn inbound_application_operation(
        &self,
        frame: crate::application_gateway::DecodedApplicationFrame,
    ) -> AdmittedInboundApplicationOperation {
        AdmittedInboundApplicationOperation {
            frame,
            dispatch: self.capture_inbound_dispatch(),
        }
    }

    pub(super) fn into_exact_channel(
        self,
        worker: Arc<crate::transport::WebRtcConnectorWorker>,
    ) -> ExactChannelOperation {
        ExactChannelOperation {
            logical: self,
            worker,
        }
    }
}

pub(super) struct ExactChannelOperation {
    logical: LogicalSessionOperation,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
}

/// Move-only custody for one authenticated pre-approval durable semantic
/// frame.  It proves an exact installation and connector, but intentionally
/// contains no promoted-session or general application authority.
#[must_use = "dropping an admitted semantic operation releases its exact parse claim"]
pub(super) struct AdmittedPendingSemanticOperation {
    owner: PeerOwnerToken,
    worker: Arc<crate::transport::WebRtcConnectorWorker>,
    endpoint_auth: Arc<crate::endpoint_auth::EndpointAuthTask>,
    mesh_context: String,
    work: crate::resource::ResourceLease,
}

impl AdmittedPendingSemanticOperation {
    /// Validate the already-funded decode result without lending any session
    /// or application capability. Every fact page must name the exact mesh
    /// context captured at admission.
    pub(super) fn accepts_message(&self, message: &crate::protocol::MeshMessage) -> bool {
        match message {
            crate::protocol::MeshMessage::FactPage(page) => {
                page.context_id.base32() == self.mesh_context.as_str() && page.validate().is_ok()
            }
            crate::protocol::MeshMessage::ProofDelivery(delivery) => {
                delivery.context_id.base32() == self.mesh_context.as_str()
                    && delivery.validate().is_ok()
                    && delivery.facts.iter().all(|fact| {
                        fact.content.mesh_context.base32() == self.mesh_context.as_str()
                    })
            }
            crate::protocol::MeshMessage::ProofAck(ack) => {
                ack.context_id.base32() == self.mesh_context.as_str()
            }
            // Inventory/request are exact-context Application-phase
            // coordination, never pending durable semantic input.
            crate::protocol::MeshMessage::FactInventory(_)
            | crate::protocol::MeshMessage::FactRequest(_) => false,
            _ => false,
        }
    }

    /// Re-prove the exact endpoint after parsing and before reduction.  The
    /// operation remains usable only for this installation; a replacement,
    /// worker retirement, endpoint-auth retirement, status change, or context
    /// change answers false and the caller drops the operation.
    pub(super) fn is_current(&self, registry: &PeerRegistry) -> bool {
        registry
            .with_current(&self.owner, |peer| {
                pending_semantic_endpoint_is_current(
                    peer,
                    &self.worker,
                    &self.endpoint_auth,
                    &self.mesh_context,
                )
            })
            .unwrap_or(false)
    }

    /// Move out the exact witness and provider custody for a reducer that must
    /// retain the claim across an await.  The returned worker/task are still
    /// provenance witnesses; they do not grant application authority.
    pub(super) fn into_parts(
        self,
    ) -> (
        PeerOwnerToken,
        Arc<crate::transport::WebRtcConnectorWorker>,
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        String,
        crate::resource::ResourceLease,
    ) {
        (
            self.owner,
            self.worker,
            self.endpoint_auth,
            self.mesh_context,
            self.work,
        )
    }
}

fn pending_semantic_endpoint_is_current(
    peer: &Arc<PeerConnection>,
    worker: &Arc<crate::transport::WebRtcConnectorWorker>,
    endpoint_auth: &Arc<crate::endpoint_auth::EndpointAuthTask>,
    mesh_context: &str,
) -> bool {
    if peer.registry_retired()
        || peer
            .current_worker()
            .is_none_or(|current| !Arc::ptr_eq(&current, worker))
        || !peer.has_authenticated_channel()
        || endpoint_auth.is_retired()
        || !worker.owns_endpoint_auth(endpoint_auth)
        || !endpoint_auth
            .context_matches(mesh_context, crate::signing::pubkey_part(&peer.device_id))
    {
        return false;
    }
    let data = peer.state.read();
    data.authenticated && matches!(data.status, super::connection::PeerStatus::PendingApproval)
}

impl ExactChannelOperation {
    pub(super) fn owner(&self) -> &PeerOwnerToken {
        self.logical.owner()
    }

    pub(super) fn witness(&self) -> &crate::runtime::peer_session::LogicalSessionValidityWitness {
        self.logical.witness()
    }

    pub(super) fn worker(&self) -> &Arc<crate::transport::WebRtcConnectorWorker> {
        &self.worker
    }
}

/// Move-only authority to dispatch exactly one already-parsed inbound
/// application frame against one exact peer installation.
///
/// An authority rather than an `Option<bool>`, because a boolean outlives the
/// fence that produced it: every dispatch arm would then re-resolve the peer *by
/// device id*, so a replacement installed during the await would answer the
/// lookup and receive the effect, the liveness touch, the counters, and the
/// delivery. An authority cannot be re-resolved — it names one installation, and
/// after replacement it names nothing.
///
/// Carries all three things one admission decided, as a single value: the
/// exact owner, the exact captured peer, and the one parsed frame. Deliberately
/// not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and consumed by
/// value, so one admission dispatches exactly one frame.
#[must_use = "an admitted inbound frame authorizes exactly one dispatch and must be consumed"]
pub(super) struct AdmittedInboundApplicationOperation {
    frame: crate::application_gateway::DecodedApplicationFrame,
    dispatch: AdmittedInboundDispatch,
}

impl AdmittedInboundApplicationOperation {
    /// Split into the one frame this admission authorized and the installation
    /// binding that outlives it for the dispatch.
    ///
    /// Consuming by value is the single-dispatch rule: the frame cannot be
    /// dispatched twice, and it cannot be paired with a different admission.
    pub(super) fn into_dispatch(
        self,
    ) -> (
        crate::application_gateway::DecodedApplicationMessage,
        crate::resource::ResourceClaim,
        crate::resource::ResourceLease,
        AdmittedInboundDispatch,
    ) {
        let (message, claim, work) = self.frame.into_parts();
        (message, claim, work, self.dispatch)
    }
}

/// The installation binding an admitted inbound frame dispatches against.
///
/// There is deliberately **no device-id accessor here**. The device id is the
/// re-resolution key this witness exists to remove, so a handler that needs
/// mesh identity for attribution takes it from [`Self::owner`], which names one
/// *installation* and not merely one device — and which every peer-reaching
/// helper (`get_if_current`, `send_to_peer_owner`) already accepts directly.
///
/// Dropping one is harmless: unlike [`AdmittedRenegotiation`] it latches
/// nothing, so an arm that decides the frame needs no effect simply drops it.
///
/// Strictly `pub(super)`. Every inbound handler that takes one is reachable
/// only from the engine's own dispatch, so they are narrowed to `pub(super)`
/// too rather than this witness being widened to fit them — an admission
/// authority that had to become a public item to be usable would be the wrong
/// trade, and `#[doc(hidden)]` is a documentation flag, not a visibility one.
pub(super) struct AdmittedInboundDispatch {
    peer: Arc<PeerConnection>,
    owner: PeerOwnerToken,
    witness: crate::runtime::peer_session::LogicalSessionValidityWitness,
}

impl AdmittedInboundDispatch {
    /// The exact owner this frame was admitted for. Never a fresh
    /// `owner(device_id)` lookup — that is the escape being closed.
    pub(super) fn owner(&self) -> &PeerOwnerToken {
        &self.owner
    }

    /// Reify the durable semantic-reply authority carried by this dispatch.
    ///
    /// The operation owns only the captured installation and logical witness;
    /// it deliberately carries no worker stamp. A semantic reply may outlive
    /// the channel that delivered its request, so channel replacement must not
    /// revoke a same-lineage logical commit. Conversely, the installation and
    /// witness remain exact, so the operation cannot affect a replacement
    /// logical session.
    pub(super) fn logical_reply_operation(&self) -> LogicalSessionOperation {
        LogicalSessionOperation::new(self.owner.clone(), self.witness.clone())
    }

    /// Bind the worker captured by the accepting callback to this same
    /// logical witness. The terminal path must use this exact pair; it may
    /// not manufacture a fresh logical witness after the callback returns.
    pub(super) fn exact_channel_operation(
        &self,
        worker: Arc<crate::transport::WebRtcConnectorWorker>,
    ) -> ExactChannelOperation {
        self.logical_reply_operation().into_exact_channel(worker)
    }

    /// Run one synchronous application effect on the exact captured peer,
    /// **inside** the registry fence, and answer with whatever it produced.
    ///
    /// This delegates to [`PeerRegistry::with_current`], which holds the
    /// mutation lock across the whole effect. That is the point, and it is the
    /// difference between this and a currency *check*: replacement takes the
    /// same lock, so it orders strictly before or after the entire effect and
    /// there is no instant at which "still current" has been established but
    /// the effect has not yet run. A `get_if_current` guard followed by the
    /// effect would be exactly the check-then-act shape this witness exists to
    /// remove — the boolean would simply have moved inside the type.
    ///
    /// Everything the effect needs must therefore be synchronous and
    /// non-reentrant: it runs under the registry mutation lock. It must not
    /// await, and it must not call back into [`PeerRegistry`] (the lock is not
    /// reentrant). Broadcast sends are fine — they hand off a value and wake
    /// tasks without running them inline — which is what lets a state change
    /// and the event announcing it happen as one atomic step.
    ///
    /// The effect receives the *captured* handle rather than the registry's.
    /// They are the same object whenever the fence admits, and naming the
    /// captured one states the invariant: this operation writes to the
    /// installation that was admitted, or to nothing at all.
    ///
    /// `None` means the captured installation is no longer the installed one,
    /// so nothing ran.
    pub(super) fn with_captured_peer<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce(&Arc<PeerConnection>) -> R,
    ) -> Option<R> {
        peers.with_current_logical(
            &LogicalSessionOperation::new(self.owner.clone(), self.witness.clone()),
            effect,
        )
    }

    /// The same fence, additionally lending the live session this frame was
    /// admitted under and the application state that session owns.
    ///
    /// The one shape the reliable receive path needs: the high-water mark, the
    /// delivery and the currency proof are a single step, and the mark now lives
    /// inside the session rather than in a device-keyed map, so all three are
    /// reachable at once or not at all. `None` if the captured installation was
    /// replaced or holds no live session — in which case nothing moved, nothing
    /// was delivered, and the caller owes the sender no acknowledgement.
    ///
    /// Carries [`Self::with_captured_peer`]'s rule unchanged: `effect` runs
    /// under the registry mutation lock, so it must not await, must not re-enter
    /// the registry, and may only hand values off.
    pub(super) fn with_captured_session_state<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce(
            &crate::runtime::session_broker::SessionCapability,
            &mut crate::runtime::peer_session::PeerSessionState,
        ) -> R,
    ) -> Option<R> {
        peers
            .with_current_logical(
                &LogicalSessionOperation::new(self.owner.clone(), self.witness.clone()),
                |_current| self.peer.with_live_session_state(effect),
            )
            .flatten()
    }

    pub(super) fn with_captured_logical_state<R>(
        &self,
        peers: &PeerRegistry,
        effect: impl FnOnce(&mut crate::runtime::peer_session::LogicalSessionOperation<'_>) -> R,
    ) -> Option<R> {
        peers
            .with_current_logical(
                &LogicalSessionOperation::new(self.owner.clone(), self.witness.clone()),
                |_current| self.peer.with_logical_session_state(effect),
            )
            .flatten()
    }
}

/// Move-only authority to perform exactly one application send on one exact
/// peer installation, minted only from a live promoted session.
///
/// Carries the peer and the connector worker captured **at admission**, under
/// the registry fence. The send writes through that captured worker and records
/// against that captured peer; nothing here re-resolves a device id, so a
/// replacement installed during the await cannot receive this operation or its
/// accounting.
///
/// Before the native future is first polled, [`Self::begin`] takes the
/// connector's own send authority and then re-enters the registry mutation
/// fence to prove both the captured installation and its session witness are
/// live. Crossing that synchronous point orders the effect before any later
/// replacement or governance commit, and the held connector authority makes
/// that ordering effective rather than merely recorded: revocation may retire
/// and close the connector immediately afterwards, and the send still lands.
/// The await then holds no registry lock and makes no impossible claim that
/// cancellation can retract bytes already handed to the native sender.
///
/// Deliberately not `Clone`, `Copy`, `Debug`, `Default`, or serializable, and
/// consumed by value, so one admission authorizes one operation.
#[must_use = "an admitted operation authorizes exactly one send and must be consumed"]
pub(super) struct AdmittedApplicationOperation {
    channel: ExactChannelOperation,
}

impl AdmittedApplicationOperation {
    /// Cite the channel already captured by admission. This does not select a
    /// current worker or renew policy; begin still rechecks the same channel.
    pub(super) fn captured_owner(&self) -> PeerOwnerToken {
        self.channel
            .logical
            .owner
            .for_worker(Arc::clone(&self.channel.worker))
    }

    /// Send one serialized frame through the exact captured connector, then
    /// record it against the exact captured peer.
    ///
    /// Both halves use the captured values, so a send and its accounting can
    /// never land on different installations.
    pub(super) async fn send_frame(
        self,
        peers: &PeerRegistry,
        bytes: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        self.begin(peers)?.send_frame(bytes, timeout).await
    }

    /// Cross the application effect's synchronous linearization point.
    ///
    /// Governance revocation takes the same mutation lock before invalidating
    /// the session. Therefore this either refuses without ever constructing a
    /// native send future, or returns an operation ordered before any later
    /// commit. No registry or parking_lot guard escapes this method.
    fn begin(self, peers: &PeerRegistry) -> Result<StartedApplicationOperation> {
        self.begin_after(peers, || {})
    }

    /// [`Self::begin`], with one observable instant inside it.
    ///
    /// `after_precheck` runs between the early validity precheck and the
    /// connector acquisition, which is the one window a caller cannot otherwise
    /// reach: everything before it is a single atomic read and everything after
    /// it is this method's own. A control that must revoke *there* — after the
    /// precheck has already passed, before the connector is asked — has no
    /// other way to say so, and that interleaving is exactly what the refusal
    /// translation below exists to answer correctly.
    ///
    /// Production passes an empty closure, so this costs a call to a closure
    /// that does nothing and compiles away. The hook is deliberately given no
    /// arguments and no return: it can observe and act on the wider system, but
    /// it cannot inspect or influence this operation's own decision.
    fn begin_after(
        self,
        peers: &PeerRegistry,
        after_precheck: impl FnOnce(),
    ) -> Result<StartedApplicationOperation> {
        // Policy before resources. A witness already known dead takes nothing
        // and is refused for the reason it is actually dead.
        //
        // This is not the linearization point — the authoritative check is the
        // one under the mutation lock below, and this one cannot replace it
        // because it reads no registry state. It exists for two production
        // reasons. A revoked session must not acquire a connector operation
        // permit: that permit joins the connector's active-operation count and
        // holds up the close drain, so a peer that has just lost its authority
        // could still delay teardown. And the refusal must name revocation
        // rather than whatever the transport happened to fail first — a caller
        // that cannot tell a policy refusal from a broken connector has lost
        // the distinction this whole gate exists to draw.
        if !self.channel.witness().is_live() {
            return Err(Self::revoked());
        }
        after_precheck();
        // Connector authority next, and outside the registry lock.
        //
        // First, because the send is awaited long after this method returns: a
        // connector permit taken at await time can find a close already
        // committed, which is a refusal of an effect this fence has already
        // ordered as permitted. Held from here, the connector cannot close
        // until the send resolves or the value is dropped.
        //
        // Outside, because acquiring it touches a resource provider and the
        // connector's own fence, and neither belongs inside the registry-wide
        // critical section that every peer mutation contends on. Ordering is
        // unaffected: revocation commits under the mutation lock below, so a
        // validation that passes proves no revocation had committed while this
        // permit was already held.
        let send = match self.channel.worker().begin_send() {
            Ok(send) => send,
            // The connector refused. Which answer is truthful depends on
            // whether this witness survived, because revocation closes this
            // connector too: a caller told only "the close fence has
            // committed" would be told about the symptom while the cause —
            // that it no longer has authority to send at all — went unnamed.
            //
            // Re-reading validity here is sound in one direction, which is the
            // direction used. The flag is monotonic — set true once at
            // construction and false once in `SessionValidity::invalidate`,
            // with no path back — so a `false` now proves revocation happened
            // at or before this refusal and cannot be a value about to change
            // its mind. A `true` proves only that no revocation had been
            // observed by this load; one may begin immediately after it. That
            // is enough, because it leaves the connector's own error as the
            // only cause established at the moment of answering, and the
            // authoritative check under the mutation lock is not reached on
            // this path at all.
            Err(native) => {
                return Err(if self.channel.witness().is_live() {
                    native
                } else {
                    Self::revoked()
                })
            }
        };
        let _mutation = peers.mutation.lock();
        let current = peers
            .peers
            .get(self.channel.owner().device_id())
            .filter(|current| {
                Arc::ptr_eq(
                    &current.value().installation,
                    &self.channel.owner().installation,
                ) && self.channel.owner().worker_matches(&current.value().peer)
            });
        if current.is_none() || !self.channel.witness().is_live() {
            return Err(Self::revoked());
        }
        Ok(StartedApplicationOperation {
            peer: Arc::clone(self.channel.owner().connection()),
            send,
        })
    }

    /// The one refusal a revoked application send gives, from either check.
    ///
    /// Built in one place so the two cannot drift apart: a caller is entitled
    /// to the same answer whether the witness was already dead on entry or was
    /// revoked while this operation was being admitted, and a divergence would
    /// leak which of the two happened.
    fn revoked() -> Error {
        Error::Transport("the session authorizing this send was revoked".into())
    }

    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn begin_for_test(
        self,
        peers: &PeerRegistry,
    ) -> Result<StartedApplicationOperation> {
        self.begin(peers)
    }

    /// Begin, with `revoke` run at the one instant the precheck cannot cover.
    ///
    /// The production entry point is [`Self::begin`] and its closure is empty;
    /// this exists only so a control can be the concurrency rather than race
    /// against it. Nothing here is reachable from production, and the closure
    /// still cannot reach this operation's own state.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(super) fn begin_racing_revocation_for_test(
        self,
        peers: &PeerRegistry,
        revoke: impl FnOnce(),
    ) -> Result<StartedApplicationOperation> {
        self.begin_after(peers, revoke)
    }
}

/// An application effect that crossed the registry-fenced begin point.
/// Revocation after this value exists is ordered after the admitted effect and
/// does not claim to roll back bytes a native sender may already own.
pub(super) struct StartedApplicationOperation {
    peer: Arc<PeerConnection>,
    /// Connector authority already taken, not a worker to ask again later.
    ///
    /// Holding the started send rather than the worker is what makes this type
    /// honest: its documented claim is that the effect is ordered before any
    /// later revocation, and that is only true if the connector cannot close
    /// underneath the await. Dropping this value before the send resolves
    /// releases the connector, which is the cancellation this type does allow.
    send: crate::transport::StartedConnectorSend,
}

impl StartedApplicationOperation {
    pub(super) async fn send_frame(
        self,
        bytes: bytes::Bytes,
        timeout: std::time::Duration,
    ) -> Result<usize> {
        let sent = tokio::time::timeout(timeout, self.send.send(bytes))
            .await
            .map_err(|_| Error::Transport("peer send timed out".into()))??;
        let mut data = self.peer.state.write();
        data.diag.bytes_out += sent as u64;
        data.diag.frames_out += 1;
        Ok(sent)
    }
}

/// Authority to *start* one inbound handler run, before the embedder's code is
/// entered.
///
/// The same shape as [`AdmittedApplicationOperation`] and for the same reason,
/// with one difference that decides everything about it: there is no connector
/// to hold. A send's begin point can take native authority and so can promise
/// the effect lands; a handler run cannot promise anything about what the
/// handler will later do. What it can establish — and what the whole type
/// exists for — is *when the run started*, as a synchronous point ordered
/// against every peer mutation and every governance commit.
///
/// **Why a fenced point at all, rather than the outer race.** The run is
/// already raced against its witness, and a biased select answers revocation
/// first at every poll. That makes revocation win every tie, including ties it
/// should lose: a run whose authority was live when it was admitted, and which
/// was revoked in the instant before its first poll, would silently never enter
/// the embedder's closure — the select would erase a start that had already been
/// authorized. Bias is a scheduling artefact, not a commit. This is the commit,
/// and it is reached exactly once.
///
/// After it, revocation may cancel every await the run has left — the handler's
/// own future, the terminal send — but it cannot retract the fact that the
/// closure was called. Before it, revocation refuses the run outright and the
/// closure is never called at all. Those are the only two outcomes.
///
/// Deliberately not `Clone`, `Copy`, `Debug` or `Default`, and consumed by
/// value, so one admission starts one run.
#[must_use = "an admitted handler run authorizes exactly one start and must be consumed"]
pub(super) struct AdmittedHandlerRun {
    logical: LogicalSessionOperation,
}

impl AdmittedHandlerRun {
    /// Capture the exact installation and session a dispatched call was
    /// admitted under.
    ///
    /// Both are captured rather than resolved later, for the reason the whole
    /// owner-token pattern exists: a device id re-resolved at start time can
    /// name a replacement installation, and a run would then be started under
    /// authority that never asked for it.
    pub(super) fn new(
        owner: PeerOwnerToken,
        validity: crate::runtime::peer_session::LogicalSessionValidityWitness,
    ) -> Self {
        Self {
            logical: LogicalSessionOperation::new(owner, validity),
        }
    }

    /// Cross the run's synchronous start point.
    ///
    /// Governance revocation takes the same mutation lock before invalidating
    /// the session, so this either refuses without the embedder's closure ever
    /// being entered, or returns a start ordered before any later commit. No
    /// registry or `parking_lot` guard escapes this method — the caller invokes
    /// user code only after it has returned, and never under a lock.
    ///
    /// `at_precommit` runs between the early validity read and the fenced
    /// commit, which is the one window nothing else can reach: everything
    /// before it is a single atomic read and everything after it is this
    /// method's own. There is one caller and it passes
    /// [`crate::engine::state::NetworkState::reach_rpc_handler_precommit_point`],
    /// which is empty in a production build and runs a control's staged action
    /// under test. Deliberately **not** a second test-only entry point: a
    /// control calling its own variant would observe this refusal without
    /// proving the production arm honours it, which is the only thing worth
    /// proving here.
    ///
    /// The hook takes nothing and returns nothing, so it can act on the wider
    /// system but cannot inspect or influence this run's own decision.
    pub(super) fn begin(
        self,
        peers: &PeerRegistry,
        at_precommit: impl FnOnce(),
    ) -> Result<StartedHandlerRun> {
        // An already-dead witness is refused for the reason it is actually
        // dead, and without touching the registry-wide lock every peer mutation
        // contends on. Not the linearization point: it reads no registry state,
        // and the authoritative check is the one under the fence below.
        if !self.logical.witness().is_live() {
            return Err(Self::revoked());
        }
        at_precommit();
        let _mutation = peers.mutation.lock();
        let current = peers
            .peers
            .get(self.logical.owner().device_id())
            .filter(|current| {
                Arc::ptr_eq(
                    &current.value().installation,
                    &self.logical.owner().installation,
                )
            });
        if current.is_none() || !self.logical.witness().is_live() {
            return Err(Self::revoked());
        }
        Ok(StartedHandlerRun { _started: () })
    }

    /// The one refusal a revoked start gives, from either check, built in one
    /// place so the two cannot drift apart or leak which of them fired.
    fn revoked() -> Error {
        Error::Transport("the session authorizing this handler run was revoked".into())
    }
}

/// A handler run that crossed its fenced start point.
///
/// Opaque and empty on purpose. It carries no connector, no lock and no lease,
/// because it makes no claim about any of them: it is the *evidence* that the
/// start was ordered before any later revocation, and evidence is all the
/// caller needs to know it may enter the embedder's closure exactly once.
///
/// Held by the run for its whole life rather than dropped at the start, so the
/// authority to have started and the running work end together.
#[must_use = "a started handler run is the evidence the closure may be entered"]
pub(super) struct StartedHandlerRun {
    _started: (),
}

/// One claimed renegotiation: the connector to drive, plus the exact owner it
/// was claimed for, as a single move-only value.
///
/// The pairing is the point. `complete` takes **no owner argument**, so the
/// caller cannot substitute a freshly resolved one — a regression to
/// `peers.owner(device_id)` after the claim would have to abandon this API and
/// hand-roll the bookkeeping, which is a visible deletion rather than a silent
/// misattribution. `media_reneg_inflight` is already latched by the time this
/// exists, so a still-current installation must be completed: dropping it while
/// its peer is current would leave the single-flight guard set and that peer
/// would never renegotiate again. Dropping it once the installation has been
/// replaced is safe — `complete` would find nothing current and write nothing.
#[must_use = "a claimed renegotiation must be completed, or its in-flight guard stays latched"]
pub(super) struct AdmittedRenegotiation {
    channel: ExactChannelOperation,
    correlation: String,
}

impl AdmittedRenegotiation {
    pub(super) fn is_live(&self) -> bool {
        self.channel.witness().is_live()
    }

    pub(super) async fn revoked(&self) {
        self.channel.witness().revoked().await;
    }

    /// The connector this renegotiation drives. Its own liveness and close
    /// fence stays authoritative for every SDP call.
    pub(super) fn session(&self) -> &Arc<crate::transport::WebRtcConnectorWorker> {
        self.channel.worker()
    }

    /// The exact installation and worker captured with this claim.
    pub(super) fn owner(&self) -> &PeerOwnerToken {
        self.channel.owner()
    }

    /// The captured owner's device id, for logging and signaling attribution.
    pub(super) fn device_id(&self) -> &str {
        self.channel.owner().device_id()
    }

    pub(super) fn correlation(&self) -> &str {
        &self.correlation
    }

    /// Record the outcome against the exact captured installation.
    ///
    /// A peer replaced while the offer was in flight fails `get_if_current`, so
    /// every write here becomes a no-op: the result is dropped rather than
    /// attributed to the replacement.
    ///
    /// Returns an exact follow-up owner only when a successor debt is still
    /// present on this logical installation. A retired worker may therefore
    /// hand off to a different still-authenticated worker, while a failure on
    /// the same worker returns no follow-up and leaves the debt for its next
    /// authenticated/stable wake.
    pub(super) fn complete(
        self,
        peers: &PeerRegistry,
        outcome: std::result::Result<(), String>,
    ) -> Option<PeerOwnerToken> {
        // Callback marking also enters through the registry mutation fence.
        // Keep that fence through state settlement and worker-slot cleanup so
        // a callback cannot install a newer debt between those two writes.
        let _mutation = peers.mutation.lock();
        let peer = peers.with_current_logical_locked(&self.channel.logical, Arc::clone)?;
        let mut data = peer.state.write();
        data.media_reneg_inflight = false;
        match outcome {
            Ok(()) => {
                // A later track-set event may have re-armed the same worker
                // after this claim was taken. Completing the older exchange
                // must not erase that newer debt.
                let rearmed = data.media_reneg_pending;
                let worker_is_owned = peer.owns_authenticated_worker(self.channel.worker());
                if worker_is_owned
                    && self.channel.worker().role() == crate::transport::Role::Offerer
                {
                    data.last_offer_sent_at = Some(std::time::Instant::now());
                }
                if !rearmed {
                    peer.clear_media_renegotiation_worker(self.channel.worker());
                }
                let worker_pending = peer.has_pending_media_renegotiation();
                // Do not overwrite a callback that re-armed the debt in the
                // gap between the first state snapshot and worker cleanup.
                // The mutation fence makes the worker observation and this
                // state update one ordered operation relative to callbacks.
                data.media_reneg_pending |= rearmed || worker_pending;
                let follow_up = peer
                    .media_renegotiation_worker()
                    .filter(|worker| peer.owns_authenticated_worker(worker))
                    .map(|worker| self.channel.owner().for_worker(worker));
                drop(data);
                // A successful completion may immediately hand any rearmed
                // debt to the next operation. A failed/non-stable operation
                // only hands off when a different authenticated worker is
                // already pending; retrying the same worker here would spin.
                follow_up
            }
            Err(error) => {
                // Leave the work owed: a later native/authenticated wake-up or
                // the recovery pass can retry it without losing the track-set
                // change.
                data.media_reneg_pending = true;
                let follow_up = peer
                    .media_renegotiation_worker()
                    .filter(|worker| !Arc::ptr_eq(worker, self.channel.worker()))
                    .filter(|worker| peer.owns_authenticated_worker(worker))
                    .map(|worker| self.channel.owner().for_worker(worker));
                drop(data);
                tracing::debug!(peer = %self.channel.owner().device_id(), "renegotiation deferred: {error}");
                follow_up
            }
        }
    }
}

#[cfg(test)]
mod introduction_vacant_install_controls {
    use super::*;

    #[test]
    fn introduction_vacant_install_preserves_existing_owner_and_epoch() {
        let registry = PeerRegistry::new("local".into());
        let first = Arc::new(PeerConnection::new("target".into(), None));
        let captured = registry
            .install_unpromoted_if_absent(Arc::clone(&first))
            .unwrap();
        assert!(captured.worker().is_none());
        assert!(!first.state.read().authenticated);
        let epoch = registry.next_binding_epoch.load(Ordering::Acquire);
        assert!(registry
            .install_unpromoted_if_absent(Arc::clone(&first))
            .is_none());
        let newcomer = Arc::new(PeerConnection::new("target".into(), None));
        assert!(registry.install_unpromoted_if_absent(newcomer).is_none());
        assert_eq!(registry.next_binding_epoch.load(Ordering::Acquire), epoch);
        assert!(registry
            .owner("target")
            .unwrap()
            .same_exact_owner(&captured));
        assert!(!first.registry_retired());
    }

    #[test]
    fn introduction_vacant_install_refuses_retired_authenticated_and_exhausted() {
        let registry = PeerRegistry::new("local".into());
        let retired = Arc::new(PeerConnection::new("retired".into(), None));
        retired.retire_connector();
        assert!(registry.install_unpromoted_if_absent(retired).is_none());
        // A negative precondition, not a fabricated authenticated session.
        let diagnostic_auth = Arc::new(PeerConnection::new("auth".into(), None));
        diagnostic_auth.state.write().authenticated = true;
        assert!(registry
            .install_unpromoted_if_absent(diagnostic_auth)
            .is_none());
        assert_eq!(registry.next_binding_epoch.load(Ordering::Acquire), 1);
        registry
            .next_binding_epoch
            .store(u64::MAX, Ordering::Release);
        assert!(registry
            .install_unpromoted_if_absent(Arc::new(PeerConnection::new("exhausted".into(), None),))
            .is_none());
        assert!(!registry.contains_key("exhausted"));
        assert_eq!(
            registry.next_binding_epoch.load(Ordering::Acquire),
            u64::MAX
        );
    }

    #[test]
    fn introduction_vacant_install_never_replaces_a_successor() {
        let registry = PeerRegistry::new("local".into());
        let old = registry
            .install_unpromoted_if_absent(Arc::new(PeerConnection::new("target".into(), None)))
            .unwrap();
        registry.install(Arc::new(PeerConnection::new("target".into(), None)));
        let successor = registry.owner("target").unwrap();
        assert!(!old.same_exact_owner(&successor));
        let epoch = registry.next_binding_epoch.load(Ordering::Acquire);
        assert!(registry
            .install_unpromoted_if_absent(Arc::new(PeerConnection::new("target".into(), None),))
            .is_none());
        assert!(registry
            .owner("target")
            .unwrap()
            .same_exact_owner(&successor));
        assert_eq!(registry.next_binding_epoch.load(Ordering::Acquire), epoch);
    }

    #[test]
    fn unstarted_cleanup_removes_only_original_matching_attempt() {
        let registry = PeerRegistry::new("local".into());
        let peer = Arc::new(PeerConnection::new("target".into(), None));
        peer.adopt_attempt(&hex::encode([7u8; 16]));
        let owner = registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        let epoch = registry.next_binding_epoch.load(Ordering::Acquire);
        assert!(registry
            .remove_unstarted_introduction_if(&owner, |peer| {
                peer.unstarted_introduction_matches(&[8; 16])
            })
            .is_none());
        assert!(!peer.registry_retired());
        assert!(registry.owner("target").unwrap().same_exact_owner(&owner));
        let removed = registry
            .remove_unstarted_introduction_if(&owner, |peer| {
                peer.unstarted_introduction_matches(&[7; 16])
            })
            .expect("matching vacant construction is detached");
        assert!(Arc::ptr_eq(&removed, &peer));
        assert!(removed.registry_retired());
        assert!(!registry.contains_key("target"));
        assert_eq!(registry.next_binding_epoch.load(Ordering::Acquire), epoch);
    }

    #[test]
    fn unstarted_cleanup_rejects_same_arc_reinstallation_and_auth_state() {
        let registry = PeerRegistry::new("local".into());
        let peer = Arc::new(PeerConnection::new("target".into(), None));
        let original = registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        // Diagnostic auth alone is a refusal, never a positive auth fixture.
        peer.state.write().authenticated = true;
        let called = std::cell::Cell::new(false);
        assert!(registry
            .remove_unstarted_introduction_if(&original, |_| {
                called.set(true);
                true
            })
            .is_none());
        assert!(!called.get());
        assert!(!peer.registry_retired());
        peer.state.write().authenticated = false;
        assert!(registry.install(Arc::clone(&peer)).is_none());
        let successor_peer = Arc::new(PeerConnection::new("target".into(), None));
        registry.install(Arc::clone(&successor_peer));
        let replacement = registry.owner("target").unwrap();
        let epoch = registry.next_binding_epoch.load(Ordering::Acquire);
        assert!(!original.same_exact_owner(&replacement));
        assert!(registry
            .remove_unstarted_introduction_if(&original, |_| {
                called.set(true);
                true
            })
            .is_none());
        assert!(!called.get());
        assert!(registry
            .owner("target")
            .unwrap()
            .same_exact_owner(&replacement));
        assert_eq!(registry.next_binding_epoch.load(Ordering::Acquire), epoch);
    }

    #[test]
    fn unstarted_cleanup_old_ticket_cannot_remove_retagged_placeholder() {
        let registry = PeerRegistry::new("local".into());
        let peer = Arc::new(PeerConnection::new("target".into(), None));
        peer.adopt_attempt(&hex::encode([7u8; 16]));
        let original = registry
            .install_unpromoted_if_absent(Arc::clone(&peer))
            .unwrap();
        registry
            .with_current(&original, |peer| {
                peer.adopt_attempt(&hex::encode([8u8; 16]));
            })
            .unwrap();
        assert!(registry
            .remove_unstarted_introduction_if(&original, |peer| {
                peer.unstarted_introduction_matches(&[7; 16])
            })
            .is_none());
        assert!(registry
            .owner("target")
            .unwrap()
            .same_exact_owner(&original));
        assert!(!peer.registry_retired());
        assert!(peer.unstarted_introduction_matches(&[8; 16]));
    }
}
