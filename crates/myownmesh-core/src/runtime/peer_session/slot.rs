//! The promoted session itself, and the one slot a peer entry holds it in.
//!
//! Installation, reuse and revocation live here together because they are one
//! rule seen from three sides: a session is usable exactly while every use-time
//! conjunct still holds, and one that fails a conjunct is destroyed rather than
//! merely refused.

use std::sync::Arc;

use crate::resource::{
    LeasedMap, ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceUnavailable,
};
use crate::runtime::session_broker::SessionCapability;

use super::{LogicalSessionOperation, LogicalSessionRecord, PeerSessionState};

use super::DedupToken;

/// One promoted session and everything promotion built under it.
///
/// Bundled rather than adjacent so their lifetimes cannot separate. The flow
/// set's name namespace and the reliable stream's sequence space are only
/// meaningful for the exact session that owns them, and the session is only
/// reachable while its connector is current — so the three die together or two
/// of them outlive their meaning.
///
/// The fields are private and are lent in pairs, never handed out. An operation
/// therefore cannot pair one session's authority with another session's state:
/// it receives the authority and the state from the same borrow of the same
/// bundle.
pub(crate) struct PromotedChannel {
    session: SessionCapability,
    /// Opaque to the engine. Constructed by the worker the session was promoted
    /// from, so the flows draw on that exact connector's registry; the engine
    /// never names a label table, a flow, or a port.
    flows: crate::transport::webrtc::SessionRealtimeFlows,
    worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    /// The exact Endpoint Auth task that minted this channel's capability.
    ///
    /// Production promotions always install `Some`. The `None` form exists only
    /// for the transport-lab helper that installs an already-authenticated
    /// capability directly so legacy admission controls can exercise the
    /// promotion fence without counterfeiting an Endpoint Auth exchange.
    endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    correlation: String,
    dedup: Option<DedupToken>,
    additional_dedup: PromotedDedupSet,
    /// Funds the heap storage owned by `correlation`. Additional dedup tokens
    /// are individually funded by `PromotedDedupSet` map-node leases.
    _correlation: crate::resource::ResourceLease,
}

/// Exact provider-backed custody for dedup tokens retained after promotion.
/// Each token is one leased map node, so later growth allocates only after its
/// own provider reservation succeeds; there is no spare-capacity vector or
/// fixed candidate ceiling to underfund a subsequent Answer/Candidate.
pub(crate) struct PromotedDedupSet {
    entries: LeasedMap<usize, DedupToken>,
    next: usize,
}

impl PromotedDedupSet {
    pub(crate) fn new() -> Self {
        Self {
            entries: LeasedMap::new(),
            next: 0,
        }
    }

    pub(crate) fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedMap::<usize, DedupToken>::entry_claim()
    }

    fn try_push(
        &mut self,
        session: &SessionCapability,
        token: DedupToken,
    ) -> Result<(), DedupToken> {
        let claim = Self::entry_claim().expect("dedup entry claim is fixed-size arithmetic");
        let lease = match session.reserve_retained(claim) {
            Ok(lease) => lease,
            Err(_) => return Err(token),
        };
        let key = match self.next.checked_add(1) {
            Some(next) => {
                let key = self.next;
                self.next = next;
                key
            }
            None => return Err(token),
        };
        self.entries
            .insert(key, token, lease)
            .expect("dedup retention keys are unique");
        Ok(())
    }

    pub(crate) fn try_push_speculative(
        &mut self,
        worker: &crate::transport::webrtc::WebRtcConnectorWorker,
        token: DedupToken,
    ) -> Result<(), DedupToken> {
        let claim = Self::entry_claim().expect("dedup entry claim is fixed-size arithmetic");
        let lease = match worker.reserve_attempt_work(claim) {
            Ok(lease) => lease,
            Err(_) => return Err(token),
        };
        let key = match self.next.checked_add(1) {
            Some(next) => {
                let key = self.next;
                self.next = next;
                key
            }
            None => return Err(token),
        };
        self.entries
            .insert(key, token, lease)
            .expect("dedup retention keys are unique");
        Ok(())
    }

    pub(crate) fn drain_tokens(self) -> PromotedDedupDrain {
        PromotedDedupDrain { set: Some(self) }
    }
}

pub(crate) struct PromotedDedupDrain {
    set: Option<PromotedDedupSet>,
}

impl Iterator for PromotedDedupDrain {
    type Item = DedupToken;

    fn next(&mut self) -> Option<Self::Item> {
        let set = self.set.as_mut()?;
        let token = set.entries.pop_first_entry().map(|(_, token)| token);
        if token.is_none() {
            drop(self.set.take());
        }
        token
    }
}

/// Exact identity and lifecycle custody for one promoted channel. Grouping the
/// fields keeps promotion/install call sites from accidentally separating the
/// worker, Endpoint Auth task, correlation, and their dedup ownership.
pub(crate) struct PromotedChannelBinding {
    pub(crate) worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    pub(crate) endpoint_auth: Option<Arc<crate::endpoint_auth::EndpointAuthTask>>,
    pub(crate) correlation: String,
    pub(crate) dedup: Option<DedupToken>,
    pub(crate) additional_dedup: PromotedDedupSet,
}

/// Process-local exact identity for one worker. The value in the map retains
/// the corresponding `Arc`, so an address cannot be recycled while its key is
/// live and an old key cannot address a replacement worker.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
struct WorkerKey(usize);

impl WorkerKey {
    fn of(worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>) -> Self {
        Self(Arc::as_ptr(worker) as usize)
    }
}

pub(crate) struct PromotedSession {
    /// Exact selected-channel identity, never a `Vec` position.
    selected: Option<Arc<crate::transport::webrtc::WebRtcConnectorWorker>>,
    channels: LeasedMap<WorkerKey, PromotedChannel>,
    logical: LogicalSessionRecord,
}

impl PromotedSession {
    /// The logical reservation is owned by [`SessionCapability`] and its joined
    /// validity witness. The slot must not mint or charge a second allocation.
    ///
    /// It lives here, beside [`PromotedSessionSlot::install`], because this is
    /// the module that allocates the thing being paid for. A claim written
    /// anywhere else would be a second statement of this record's shape, and the
    /// two would drift the first time a field is added.
    ///
    /// This is the singular logical record/root owned by the slot. The
    /// capability's validity allocation is separate and is never duplicated.
    ///
    /// Any later queue, flow, or payload retention is funded at the moment it
    /// is taken, by [`SessionCapability::reserve_retained`], and released when
    /// it is not. Promotion therefore does not pre-pay for a fixed capacity.
    ///
    /// Two exclusions are by design. The flow registry the set holds is the
    /// connector's own and preexisting — promotion clones a handle, it does not
    /// allocate the registry — so charging it would bill a session for something
    /// that outlives it. And every per-flow, queue and payload lease is charged
    /// where it is taken; a session that opens no flow must not pre-pay for
    /// flows.
    ///
    /// Deliberately not derived from anything measured before authentication: a
    /// pre-authentication lease is not proof that this capacity exists.
    pub(crate) fn logical_claim() -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError>
    {
        let record = u64::try_from(std::mem::size_of::<LogicalSessionRecord>()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// The exact allocation owned by the channel outside its leased-map node.
    /// The map node itself is charged only by the slot insertion seam.
    pub(crate) fn channel_claim() -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError>
    {
        crate::transport::webrtc::SessionRealtimeFlows::promotion_root_claim()
    }

    /// The exact funded node required for one channel-map insertion.
    ///
    /// The key representation remains private so callers cannot restate worker
    /// identity as a guessed integer or create a second accounting formula.
    pub(crate) fn channel_map_entry_claim(
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        LeasedMap::<WorkerKey, PromotedChannel>::entry_claim()
    }

    /// The input-sized String allocation retained by one promoted channel.
    /// Additional dedup tokens use individually leased map nodes rather than
    /// a spare-capacity Vec, so later growth is charged at insertion.
    pub(crate) fn channel_correlation_claim(
        correlation: &String,
    ) -> std::result::Result<ResourceClaim, ResourceClaimArithmeticError> {
        let correlation_bytes = u64::try_from(correlation.capacity()).map_err(|_| {
            ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes,
            }
        })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, correlation_bytes),
            (
                ResourceClass::StorageObject,
                u64::from(correlation_bytes != 0),
            ),
        ])
    }

    fn selected_mut(&mut self) -> Option<&mut PromotedChannel> {
        let selected = Arc::clone(self.selected.as_ref()?);
        self.channels
            .get_mut(&WorkerKey::of(&selected))
            .filter(|channel| Arc::ptr_eq(&channel.worker, &selected))
    }

    pub(crate) fn selected_worker(
        &self,
    ) -> Option<&Arc<crate::transport::webrtc::WebRtcConnectorWorker>> {
        self.selected.as_ref()
    }

    fn has_usable_channel(&self) -> bool {
        if !self.logical.validity().is_live() {
            return false;
        }
        let mut usable = false;
        self.channels.for_each(|_, channel| {
            if channel
                .worker
                .live_connector_incarnation()
                .is_some_and(|live| channel.session.belongs_to(live))
            {
                usable = true;
            }
        });
        usable
    }

    /// Lend the exact selected channel authority with the singular logical
    /// application state. The two borrows are field-split: selection is read
    /// from the channel map, while state remains owned by the logical record.
    pub(crate) fn app_mut(&mut self) -> Option<(&SessionCapability, &mut PeerSessionState)> {
        let selected = self.selected.as_ref()?;
        let channel = self
            .channels
            .get(&WorkerKey::of(selected))
            .filter(|channel| Arc::ptr_eq(&channel.worker, selected))?;
        Some((&channel.session, &mut self.logical.state))
    }

    pub(crate) fn contains_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        self.channels
            .get(&WorkerKey::of(worker))
            .is_some_and(|channel| Arc::ptr_eq(&channel.worker, worker))
    }

    fn select_channel(
        &mut self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        if worker.live_connector_incarnation().is_none() || !self.contains_worker(worker) {
            return false;
        }
        self.selected = Some(Arc::clone(worker));
        true
    }

    fn select_unique_usable(
        &mut self,
    ) -> Option<Arc<crate::transport::webrtc::WebRtcConnectorWorker>> {
        if let Some(selected) = self.selected.as_ref() {
            let usable = self
                .channels
                .get(&WorkerKey::of(selected))
                .is_some_and(|channel| {
                    Arc::ptr_eq(&channel.worker, selected)
                        && channel
                            .worker
                            .live_connector_incarnation()
                            .is_some_and(|live| channel.session.belongs_to(live))
                });
            if usable {
                return Some(Arc::clone(selected));
            }
        }

        let mut count = 0usize;
        let mut candidate = None;
        self.channels.for_each(|_, channel| {
            if channel
                .worker
                .live_connector_incarnation()
                .is_some_and(|live| channel.session.belongs_to(live))
            {
                count += 1;
                candidate = Some(Arc::clone(&channel.worker));
            }
        });
        if count == 1 {
            self.selected = candidate.clone();
            candidate
        } else {
            self.selected = None;
            None
        }
    }

    pub(crate) fn endpoint_auth_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.channels
            .get(&WorkerKey::of(worker))
            .filter(|channel| Arc::ptr_eq(&channel.worker, worker))
            .and_then(|channel| channel.endpoint_auth.as_ref().map(Arc::clone))
    }

    pub(crate) fn correlation_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<String> {
        self.channels
            .get(&WorkerKey::of(worker))
            .filter(|channel| Arc::ptr_eq(&channel.worker, worker))
            .map(|channel| channel.correlation.clone())
    }

    pub(crate) fn flows_mut(
        &mut self,
    ) -> Option<(
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    )> {
        let channel = self.selected_mut()?;
        Some((&channel.session, &mut channel.flows, &channel.worker))
    }

    pub(crate) fn flows_for_worker_mut(
        &mut self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<(
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    )> {
        let channel = self
            .channels
            .get_mut(&WorkerKey::of(worker))
            .filter(|channel| Arc::ptr_eq(&channel.worker, worker))?;
        Some((&channel.session, &mut channel.flows, &channel.worker))
    }

    pub(crate) fn flows_for_worker_with_correlation_mut(
        &mut self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<(
        &SessionCapability,
        &mut crate::transport::webrtc::SessionRealtimeFlows,
        &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        &str,
    )> {
        let channel = self
            .channels
            .get_mut(&WorkerKey::of(worker))
            .filter(|channel| Arc::ptr_eq(&channel.worker, worker))?;
        Some((
            &channel.session,
            &mut channel.flows,
            &channel.worker,
            channel.correlation.as_str(),
        ))
    }
}

pub(crate) struct RemovedPromotedChannel {
    pub(crate) worker: Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    pub(crate) dedup: Option<DedupToken>,
    pub(crate) additional_dedup: PromotedDedupSet,
    pub(crate) selection_needed: bool,
    pub(crate) session_empty: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PromotedSessionAdmissionRefusalReason {
    SlotUnavailable,
    LogicalSessionUnavailable,
    DuplicateWorker,
    ResourceUnavailable(ResourceUnavailable),
    ClaimArithmetic(ResourceClaimArithmeticError),
}

pub(crate) struct PromotedSessionAdmissionRefusal {
    pub(crate) reason: PromotedSessionAdmissionRefusalReason,
    pub(crate) session: Box<SessionCapability>,
    pub(crate) flows: Box<crate::transport::webrtc::SessionRealtimeFlows>,
    pub(crate) binding: Box<PromotedChannelBinding>,
}

impl PromotedSessionAdmissionRefusal {
    pub(crate) fn into_parts(
        self,
    ) -> (
        PromotedSessionAdmissionRefusalReason,
        Box<SessionCapability>,
        Box<crate::transport::webrtc::SessionRealtimeFlows>,
        Box<PromotedChannelBinding>,
    ) {
        (self.reason, self.session, self.flows, self.binding)
    }
}

pub(crate) type PromotedSessionInstallRefusal = PromotedSessionAdmissionRefusal;

fn admission_refusal(
    reason: PromotedSessionAdmissionRefusalReason,
    session: SessionCapability,
    flows: crate::transport::webrtc::SessionRealtimeFlows,
    binding: PromotedChannelBinding,
) -> PromotedSessionAdmissionRefusal {
    PromotedSessionAdmissionRefusal {
        reason,
        session: Box::new(session),
        flows: Box::new(flows),
        binding: Box::new(binding),
    }
}

/// The one slot a peer entry holds its promoted session in, and the use and
/// revocation rules that govern it.
///
/// The rules live here rather than at each call site because there is exactly
/// one of them and it must be identical everywhere: a session is usable only
/// while every use-time conjunct still holds, and a session that fails one is
/// **dropped**, not merely refused. Refusing alone would leave a revoked session
/// holding its post-authentication reservation and its retained frames, waiting
/// on a peer that will never acknowledge them, until some unrelated path
/// happened to notice.
///
/// Dropping the bundle is also the only retirement signal there is: it closes
/// the flow-owned queues, resolves every caller still waiting on a retained
/// frame, and releases the reservation. There is no separate retirement event
/// and no second place that has to remember.
pub(crate) struct PromotedSessionSlot {
    slot: parking_lot::Mutex<Option<PromotedSession>>,
}

impl PromotedSessionSlot {
    pub(crate) fn new() -> Self {
        Self {
            slot: parking_lot::Mutex::new(None),
        }
    }

    /// Whether a session is installed at all.
    ///
    /// Says nothing about whether it is still usable — that question is only
    /// answerable together with the conjuncts, which is what [`Self::with_live`]
    /// is for. Callers wanting "is this peer past promotion" want this; callers
    /// wanting to *do* something want the lender.
    pub(crate) fn is_installed(&self) -> bool {
        self.slot.lock().is_some()
    }

    pub(crate) fn channel_count(&self) -> usize {
        let slot = self.slot.lock();
        let Some(session) = slot.as_ref() else {
            return 0;
        };
        let mut count = 0;
        session.channels.for_each(|_, _| {
            count += 1;
        });
        count
    }

    /// Drop whatever is installed.
    ///
    /// The connector-retirement and entry-teardown edge. A session promoted
    /// under a retired connector must not survive into its replacement, and
    /// dropping it is what releases its reservation and answers its callers.
    pub(crate) fn clear(&self) {
        drop(self.slot.lock().take());
    }

    pub(crate) fn take_workers_with_dedup(
        &self,
    ) -> Vec<(
        Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        Option<DedupToken>,
        PromotedDedupDrain,
    )> {
        let Some(mut session) = self.slot.lock().take() else {
            return Vec::new();
        };
        let mut workers = Vec::new();
        while let Some((_key, channel)) = session.channels.pop_first_entry() {
            if let Some(task) = channel.endpoint_auth {
                task.retire();
            }
            workers.push((
                channel.worker,
                channel.dedup,
                channel.additional_dedup.drain_tokens(),
            ));
        }
        workers
    }

    /// Install a freshly promoted session, replacing anything present.
    ///
    /// Replacement is correct rather than merely tolerated: the only caller
    /// promotes after this slot was found empty or revoked under the registry's
    /// mutation lock, which serializes promotion, and anything that appeared in
    /// the meantime would be a session this one supersedes.
    ///
    /// Logical-session admission can still refuse while the authenticated
    /// channel is being installed. Callers retain ownership of the candidate
    /// and its cleanup obligations when this returns an error.
    pub(crate) fn install(
        &self,
        session: SessionCapability,
        flows: crate::transport::webrtc::SessionRealtimeFlows,
        binding: PromotedChannelBinding,
    ) -> Result<(), PromotedSessionInstallRefusal> {
        let PromotedChannelBinding {
            worker,
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
        } = binding;
        let logical_claim = match PromotedSession::logical_claim() {
            Ok(claim) => claim,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ClaimArithmetic(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let logical_lease = match session.reserve_retained(logical_claim) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ResourceUnavailable(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let entry_claim = match PromotedSession::channel_map_entry_claim() {
            Ok(claim) => claim,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ClaimArithmetic(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let entry_lease = match session.reserve_retained(entry_claim) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ResourceUnavailable(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let retained_claim = match PromotedSession::channel_correlation_claim(&correlation) {
            Ok(claim) => claim,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ClaimArithmetic(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let retained_lease = match session.reserve_retained(retained_claim) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ResourceUnavailable(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let logical = LogicalSessionRecord::new(session.validity_witness(), logical_lease);
        let channel = PromotedChannel {
            session,
            flows,
            worker: Arc::clone(&worker),
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
            _correlation: retained_lease,
        };
        let mut channels = LeasedMap::new();
        channels
            .insert(WorkerKey::of(&worker), channel, entry_lease)
            .expect("a fresh promoted slot cannot contain its worker key");
        let promoted = PromotedSession {
            selected: None,
            channels,
            logical,
        };
        *self.slot.lock() = Some(promoted);
        Ok(())
    }

    pub(crate) fn add_channel(
        &self,
        session: SessionCapability,
        flows: crate::transport::webrtc::SessionRealtimeFlows,
        binding: PromotedChannelBinding,
    ) -> Result<(), PromotedSessionAdmissionRefusal> {
        let PromotedChannelBinding {
            worker,
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
        } = binding;
        let mut slot = self.slot.lock();
        let Some(promoted) = slot.as_mut() else {
            return Err(admission_refusal(
                PromotedSessionAdmissionRefusalReason::SlotUnavailable,
                session,
                flows,
                PromotedChannelBinding {
                    worker,
                    endpoint_auth,
                    correlation,
                    dedup,
                    additional_dedup,
                },
            ));
        };
        if !promoted.logical.validity().is_live()
            || !promoted.logical.validity().witnesses(&session)
        {
            return Err(admission_refusal(
                PromotedSessionAdmissionRefusalReason::LogicalSessionUnavailable,
                session,
                flows,
                PromotedChannelBinding {
                    worker,
                    endpoint_auth,
                    correlation,
                    dedup,
                    additional_dedup,
                },
            ));
        }
        if promoted.contains_worker(&worker) {
            return Err(admission_refusal(
                PromotedSessionAdmissionRefusalReason::DuplicateWorker,
                session,
                flows,
                PromotedChannelBinding {
                    worker,
                    endpoint_auth,
                    correlation,
                    dedup,
                    additional_dedup,
                },
            ));
        }
        let entry_claim = match PromotedSession::channel_map_entry_claim() {
            Ok(claim) => claim,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ClaimArithmetic(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let entry_lease = match session.reserve_retained(entry_claim) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ResourceUnavailable(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let retained_claim = match PromotedSession::channel_correlation_claim(&correlation) {
            Ok(claim) => claim,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ClaimArithmetic(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let retained_lease = match session.reserve_retained(retained_claim) {
            Ok(lease) => lease,
            Err(error) => {
                return Err(admission_refusal(
                    PromotedSessionAdmissionRefusalReason::ResourceUnavailable(error),
                    session,
                    flows,
                    PromotedChannelBinding {
                        worker,
                        endpoint_auth,
                        correlation,
                        dedup,
                        additional_dedup,
                    },
                ));
            }
        };
        let channel = PromotedChannel {
            session,
            flows,
            worker: Arc::clone(&worker),
            endpoint_auth,
            correlation,
            dedup,
            additional_dedup,
            _correlation: retained_lease,
        };
        promoted
            .channels
            .insert(WorkerKey::of(&worker), channel, entry_lease)
            .expect("duplicate worker was rejected under the slot lock");
        Ok(())
    }

    /// Select an exact installed channel. A failed lookup leaves the current
    /// selection unchanged; it never guesses from channel order.
    pub(crate) fn select_channel(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        let mut slot = self.slot.lock();
        slot.as_mut()
            .is_some_and(|promoted| promoted.select_channel(worker))
    }

    /// Preserve a usable exact selection, or select only one channel that
    /// proves both live connector identity and capability membership. Zero or
    /// multiple usable channels leave the slot unselected.
    pub(crate) fn select_unique_usable(
        &self,
    ) -> Option<Arc<crate::transport::webrtc::WebRtcConnectorWorker>> {
        let mut slot = self.slot.lock();
        slot.as_mut()
            .and_then(PromotedSession::select_unique_usable)
    }

    /// Return the exact selected worker, if this slot currently has one.
    /// Selection is copied as an `Arc`; no borrowed worker escapes the slot lock.
    pub(crate) fn selected_worker(
        &self,
    ) -> Option<Arc<crate::transport::webrtc::WebRtcConnectorWorker>> {
        self.slot
            .lock()
            .as_ref()
            .and_then(|promoted| promoted.selected_worker().cloned())
    }

    /// Whether at least one promoted channel still has both a live connector
    /// incarnation and its capability bound to that incarnation. This is an
    /// observation-only predicate: unlike unique selection it never changes
    /// the slot, so multiple usable channels remain ambiguous and untouched.
    pub(crate) fn has_usable_channel(&self) -> bool {
        self.slot
            .lock()
            .as_ref()
            .is_some_and(PromotedSession::has_usable_channel)
    }

    /// Lend one established capability synchronously without exposing map
    /// storage or changing selection. Every channel in this bundle is joined to
    /// the same logical validity lineage, so this is an authority anchor, not a
    /// transport-selection decision.
    pub(crate) fn with_established_session<R>(
        &self,
        effect: impl FnOnce(&SessionCapability) -> R,
    ) -> Option<R> {
        let slot = self.slot.lock();
        let promoted = slot.as_ref()?;
        if !promoted.logical.validity().is_live() {
            return None;
        }
        let (_, channel) = promoted.channels.successor_after(None)?;
        Some(effect(&channel.session))
    }

    pub(crate) fn contains_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> bool {
        self.slot
            .lock()
            .as_ref()
            .is_some_and(|session| session.contains_worker(worker))
    }

    pub(crate) fn endpoint_auth_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<Arc<crate::endpoint_auth::EndpointAuthTask>> {
        self.slot
            .lock()
            .as_ref()
            .and_then(|session| session.endpoint_auth_for(worker))
    }

    pub(crate) fn correlation_for(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<String> {
        self.slot
            .lock()
            .as_ref()
            .and_then(|session| session.correlation_for(worker))
    }

    pub(crate) fn retain_dedup_for_worker(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        token: DedupToken,
    ) -> bool {
        let mut slot = self.slot.lock();
        let Some(session) = slot.as_mut() else {
            return false;
        };
        let Some(channel) = session
            .channels
            .get_mut(&WorkerKey::of(worker))
            .filter(|channel| Arc::ptr_eq(&channel.worker, worker))
        else {
            return false;
        };
        channel
            .additional_dedup
            .try_push(&channel.session, token)
            .is_ok()
    }

    pub(crate) fn remove_channel(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
    ) -> Option<RemovedPromotedChannel> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        let key = WorkerKey::of(worker);
        let channel_ref = promoted.channels.get(&key)?;
        if !Arc::ptr_eq(&channel_ref.worker, worker) {
            return None;
        }
        let selection_needed = promoted
            .selected
            .as_ref()
            .is_some_and(|selected| Arc::ptr_eq(selected, worker));
        let (_, channel) = promoted.channels.remove_entry(&key)?;
        if let Some(task) = channel.endpoint_auth {
            task.retire();
        }
        if promoted.channels.successor_after(None).is_none() {
            drop(slot.take());
            return Some(RemovedPromotedChannel {
                worker: channel.worker,
                dedup: channel.dedup,
                additional_dedup: channel.additional_dedup,
                selection_needed: false,
                session_empty: true,
            });
        }
        if selection_needed {
            // Removing the selected channel makes selection ambiguous. The
            // caller must explicitly choose a surviving exact worker.
            promoted.selected = None;
        }
        Some(RemovedPromotedChannel {
            worker: channel.worker,
            dedup: channel.dedup,
            additional_dedup: channel.additional_dedup,
            selection_needed,
            session_empty: false,
        })
    }

    /// Whether the installed session may still be reused, dropping it if not.
    ///
    /// Logical reuse is decided only by the established validity witness. Exact
    /// worker currentness belongs to the worker-specific lenders below.
    pub(crate) fn reuse_or_revoke(&self) -> Reuse {
        let mut slot = self.slot.lock();
        match slot.as_ref() {
            None => Reuse::Vacant,
            Some(bundle) if bundle.logical.validity().is_live() => Reuse::Current,
            Some(_) => {
                drop(slot.take());
                Reuse::Revoked
            }
        }
    }

    /// Lend the singular logical state independently of channel selection.
    ///
    /// The operation carries the established validity witness across the
    /// callback and never clears the slot when an exact channel is unusable.
    pub(crate) fn with_logical_operation<R>(
        &self,
        effect: impl FnOnce(&mut LogicalSessionOperation<'_>) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        let mut operation = promoted.logical.operation()?;
        Some(effect(&mut operation))
    }

    /// Lend logical state while its established validity witness is live.
    ///
    /// This lender is non-promoting and non-clearing; exact worker currentness
    /// belongs to the worker-specific lenders below.
    ///
    /// Non-promoting: it uses what exists and creates nothing, so a diagnostic
    /// read cannot bring a session into being. It is still not passive — a
    /// revoked session is destroyed here, because observing that a session is no
    /// longer admitted and leaving it installed is what lets a revocation take
    /// effect at a time no caller controls.
    ///
    /// `effect` runs under this slot's lock. Anything it reads that is not in
    /// the bundle must be lockable *after* this slot, never before.
    pub(crate) fn with_live<R>(&self, effect: impl FnOnce(&mut PromotedSession) -> R) -> Option<R> {
        let mut slot = self.slot.lock();
        let bundle = slot.as_mut()?;
        if !bundle.logical.validity().is_live() {
            return None;
        }
        Some(effect(bundle))
    }

    pub(crate) fn with_live_worker<R>(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(
            &SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        ) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        if !promoted.logical.validity().is_live() {
            return None;
        }
        let (session, flows, worker) = promoted.flows_for_worker_mut(worker)?;
        if !current(session) {
            return None;
        }
        Some(effect(session, flows, worker))
    }

    /// Lend one exact channel together with the correlation that names it.
    ///
    /// The correlation is borrowed from the same [`PromotedChannel`] as the
    /// capability, flow set and worker, while this slot guard is held.  A
    /// caller must not reacquire the slot from its effect closure: doing so is
    /// a non-reentrant self-deadlock and, more importantly, would split the
    /// channel identity from the authority that proved it current.
    pub(crate) fn with_live_worker_and_correlation<R>(
        &self,
        worker: &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
        current: impl FnOnce(&SessionCapability) -> bool,
        effect: impl FnOnce(
            &SessionCapability,
            &mut crate::transport::webrtc::SessionRealtimeFlows,
            &Arc<crate::transport::webrtc::WebRtcConnectorWorker>,
            &str,
        ) -> R,
    ) -> Option<R> {
        let mut slot = self.slot.lock();
        let promoted = slot.as_mut()?;
        if !promoted.logical.validity().is_live() {
            return None;
        }
        let (session, flows, channel_worker, correlation) =
            promoted.flows_for_worker_with_correlation_mut(worker)?;
        if !current(session) {
            return None;
        }
        Some(effect(session, flows, channel_worker, correlation))
    }
}

/// What [`PromotedSessionSlot::reuse_or_revoke`] found.
///
/// Three answers rather than a boolean, because the caller acts differently on
/// each: a current session is reused, a vacant slot is promoted into, and a
/// revoked one is refused outright — attempting to re-promote a peer whose
/// admission was just withdrawn would take a fresh reservation for authority the
/// mesh has already refused.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Reuse {
    /// A session is installed and every conjunct still holds.
    Current,
    /// Nothing was installed.
    Vacant,
    /// Something was installed, failed a conjunct, and has been dropped.
    Revoked,
}
