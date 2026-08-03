//! WebRTC peer connection wrapper. Bridges webrtc-rs's callback-
//! driven API to one bounded mailbox per connector worker.
//!
//! Lifecycle per peer:
//!
//! 1. The engine admits one connector candidate and calls
//!    [`Transport::open_connector_peer`] with [`Role::Offerer`] or
//!    [`Role::Answerer`]. A fresh [`WebRtcConnectorWorker`] owns the session.
//! 2. The worker creates and applies offers, answers, and remote descriptions;
//!    the engine moves the resulting transport control through signaling.
//! 3. ICE candidates flow both ways via signaling; the engine moves inbound
//!    candidates through its connector worker and the worker owns raw apply.
//! 4. A data-channel open promotes the exact connector candidate and hands its
//!    connected-channel capability to the Endpoint Auth Task.
//! 5. Connector retirement fences callbacks, drains owned work, and explicitly
//!    closes the native peer connection.

use std::future::Future;
use std::mem::size_of;
use std::num::NonZeroUsize;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::{mpsc, oneshot, watch, Mutex};
use tracing::{debug, info, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::{MediaEngine, MIME_TYPE_H264, MIME_TYPE_OPUS};
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::signaling_state::RTCSignalingState;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTPCodecType};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use crate::error::{Error, Result};
use crate::resource::{
    ObservationLease, PeerConnectionResourceScope, PreAuthResourceFamily, ProcessResourceRoot,
    ResourceMeasurement, ResourceUse,
};
use crate::runtime::attempt::{
    admit_single_connector_candidate, AttemptLifetime, AttemptLiveness, ConnectorCallbackPolicy,
    ConnectorCallbackServiceWeights, ConnectorCandidateCapability, ConnectorCapableResourcePolicy,
    ConnectorResourceOwnerReport, EnabledRealtimeConnectorPolicy, MeshConnectorResourceReport,
    MeshConnectorResourceScope, RealtimeConnectorPolicy,
};

use super::ice::build_rtc_configuration;

mod callback;
mod cleanup;
mod h264;
mod media;
mod realtime;
use callback::*;
use cleanup::*;
use h264::*;
pub use media::*;
use realtime::*;

/// Interface-name prefixes for virtual / container / overlay networks
/// whose host addresses can never be reached by a remote peer. Gathering
/// ICE host candidates on them only bloats the candidate set and slows
/// the connectivity-check phase — a storage box running Docker routinely
/// carries three or more bridge gateways (`docker0`, `br-…`), each adding
/// a dead `172.x.0.1` host candidate that every peer then has to pair and
/// time out against. Real interfaces — physical NICs, Wi-Fi, and the
/// Tailscale tunnel (`tailscale0` / `utun*` / `wg*`), which is a
/// legitimate peer path — are deliberately *not* listed, so they keep
/// gathering candidates.
const VIRTUAL_IFACE_PREFIXES: &[&str] = &[
    "docker",  // docker0 and the default bridge
    "br-",     // docker user-defined bridge networks
    "veth",    // per-container veth pairs
    "virbr",   // libvirt
    "vmnet",   // vmware / parallels host-only nets
    "cni",     // container network interface plugins (k8s)
    "flannel", // flannel overlay
    "cali",    // calico
    "kube",    // kube-* bridges
];

/// True when `name` is a virtual interface we exclude from ICE gathering
/// (see [`VIRTUAL_IFACE_PREFIXES`]). Prefix match: `docker0`, `br-abc123`,
/// and `veth9f2` all hit; `eth0`, `wlan0`, `enp3s0`, and `tailscale0`
/// don't.
pub(crate) fn is_virtual_interface(name: &str) -> bool {
    VIRTUAL_IFACE_PREFIXES
        .iter()
        .any(|prefix| name.starts_with(prefix))
}

/// Stable label for the application data channel. Receivers can
/// filter the incoming [`on_data_channel`] event on this so other
/// channels (e.g. browser-initiated debug) don't get routed into
/// the mesh frame path.
pub const APP_DATA_CHANNEL_LABEL: &str = "myownmesh";

/// Who initiated this peer pairing. Drives whether we create the
/// data channel pre-offer (offerer) or wait for the peer to open
/// it (answerer).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Offerer,
    Answerer,
}

/// Transport-layer event surfaced to the engine. The engine pumps
/// these on the network's main loop; nothing here lives across
/// tokio runtime ticks.
#[derive(Debug)]
pub enum TransportEvent {
    /// A locally-gathered ICE candidate the engine should ship to
    /// the peer over signaling. `None` after gathering completes.
    LocalIceCandidate(Option<LocalIceCandidate>),
    /// ICE connection state changed.
    IceConnectionStateChanged(RTCIceConnectionState),
    /// PeerConnection state changed (covers the full DTLS+ICE
    /// lifecycle, including `Failed` and `Closed`).
    PeerConnectionStateChanged(RTCPeerConnectionState),
    /// The data channel works and its exact connector is eligible for
    /// Endpoint Auth. This is not proof of application reachability.
    DataChannelOpen,
    /// Inbound application frame.
    Message(Bytes),
    /// Data channel closed (peer initiated or local error).
    DataChannelClosed,
    /// The local track set changed (a media lane opened or closed) and
    /// the SDP no longer matches — the engine should renegotiate in
    /// place (fresh offer, same DTLS fingerprint). Coalesced by the
    /// engine per peer, so a burst of lane changes costs one offer.
    RenegotiationNeeded,
    /// One assembled access unit from the peer's video track lane.
    VideoSample(VideoSample),
    /// One encoded audio frame from the peer's audio track lane.
    AudioSample(AudioSample),
}

/// Exact process-local identity for one WebRTC connector worker.
///
/// This is a stale-callback guard, not authority. Only a
/// `ConnectorCandidateCapability` can authorize an admitted candidate.
pub(crate) struct WebRtcConnectorIncarnation {
    active: AtomicBool,
    retired: watch::Sender<bool>,
}

impl WebRtcConnectorIncarnation {
    fn new() -> Self {
        let (retired, _receiver) = watch::channel(false);
        Self {
            active: AtomicBool::new(true),
            retired,
        }
    }

    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.retired.send_replace(true);
    }

    pub(crate) fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    fn subscribe_retirement(&self) -> watch::Receiver<bool> {
        self.retired.subscribe()
    }
}

async fn await_until_connector_retirement<T>(
    mut retirement: watch::Receiver<bool>,
    work: impl Future<Output = T>,
) -> Option<T> {
    if *retirement.borrow() {
        return None;
    }
    tokio::pin!(work);
    tokio::select! {
        biased;
        _ = retirement.changed() => None,
        result = &mut work => Some(result),
    }
}

/// One callback value stamped with the exact worker that received it.
pub struct WebRtcConnectorEvent {
    incarnation: Arc<WebRtcConnectorIncarnation>,
    event: TransportEvent,
    _queue_observation: Option<ObservationLease>,
}

struct QueuedTransportEvent {
    event: TransportEvent,
    observation: Option<ObservationLease>,
}

impl QueuedTransportEvent {
    fn attach_realtime_reservation(
        &mut self,
        reservation: RealtimePayloadLease,
    ) -> std::result::Result<(), RealtimePayloadLease> {
        match &mut self.event {
            TransportEvent::VideoSample(sample) => {
                sample._reservation = Some(reservation);
                Ok(())
            }
            TransportEvent::AudioSample(sample) => {
                sample._reservation = Some(reservation);
                Ok(())
            }
            _ => Err(reservation),
        }
    }
}

fn callback_payload_limit(
    policy: ConnectorCallbackPolicy,
    class: ConnectorCallbackClass,
) -> Option<usize> {
    match class {
        ConnectorCallbackClass::Control => None,
        ConnectorCallbackClass::EndpointData => Some(crate::engine::MAX_ENDPOINT_FRAME_BYTES),
        ConnectorCallbackClass::Realtime => match policy.realtime() {
            RealtimeConnectorPolicy::Disabled => None,
            RealtimeConnectorPolicy::Enabled(enabled) => Some(enabled.max_unit_bytes().get()),
        },
    }
}

#[derive(Clone)]
struct ConnectorEventMailboxes {
    control: mpsc::Sender<QueuedTransportEvent>,
    endpoint_data: mpsc::Sender<QueuedTransportEvent>,
}

impl ConnectorEventMailboxes {
    fn sender(&self, class: ConnectorCallbackClass) -> Option<&mpsc::Sender<QueuedTransportEvent>> {
        match class {
            ConnectorCallbackClass::Control => Some(&self.control),
            ConnectorCallbackClass::EndpointData => Some(&self.endpoint_data),
            ConnectorCallbackClass::Realtime => None,
        }
    }
}

#[derive(Clone)]
struct ConnectorEventSink {
    events: ConnectorEventMailboxes,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    resource_scope: Option<PeerConnectionResourceScope>,
    realtime_delivery: Arc<AtomicBool>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_policy: ConnectorCallbackPolicy,
    data_channel_fence: Arc<DataChannelCallbackFence>,
}

impl ConnectorEventSink {
    fn open_inbound_realtime_flow(&self) -> Option<RealtimeFlowPort> {
        self.realtime_flows.open_inbound_flow()
    }

    fn open_outbound_realtime_flow(&self) -> Option<RealtimeFlowPort> {
        self.realtime_flows.open_outbound_flow()
    }

    fn observe_realtime_payload(&self, payload_bytes: usize) -> Option<ObservationLease> {
        self.resource_scope.as_ref().map(|scope| {
            scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::MediaQuarantine,
                ResourceMeasurement::inexact(ResourceUse::observed(
                    1,
                    u64::try_from(payload_bytes).unwrap_or(u64::MAX),
                    u64::try_from(payload_bytes).unwrap_or(u64::MAX),
                    0,
                )),
            )
        })
    }

    fn emit_realtime(
        &self,
        flow: &RealtimeFlowPort,
        event: TransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        if !self.realtime_delivery.load(Ordering::Acquire) || !self.callback_gate.is_active() {
            return true;
        }
        let payload_bytes = match &event {
            TransportEvent::VideoSample(sample) => sample.data.len(),
            TransportEvent::AudioSample(sample) => sample.data.len(),
            _ => return false,
        };
        let observation = self.observe_realtime_payload(payload_bytes);
        flow.enqueue(QueuedTransportEvent { event, observation }, reservation)
    }

    async fn emit_data_channel(&self, event: TransportEvent) -> bool {
        if matches!(event, TransportEvent::DataChannelClosed) {
            if !self.data_channel_fence.begin_close() {
                return true;
            }
            return self.emit_inner(event, false).await;
        }
        self.emit_inner(event, true).await
    }

    async fn emit(&self, event: TransportEvent) -> bool {
        self.emit_inner(event, false).await
    }

    async fn emit_inner(&self, event: TransportEvent, fence_data_channel: bool) -> bool {
        if fence_data_channel && self.data_channel_fence.is_closed() {
            return true;
        }
        let callback_class = ConnectorCallbackClass::for_event(&event);
        let payload_bytes = match &event {
            TransportEvent::Message(bytes) => bytes.len(),
            TransportEvent::VideoSample(sample) => sample.data.len(),
            TransportEvent::AudioSample(sample) => sample.data.len(),
            _ => 0,
        };
        if matches!(
            &event,
            TransportEvent::VideoSample(_) | TransportEvent::AudioSample(_)
        ) && !self.realtime_delivery.load(Ordering::Acquire)
        {
            return true;
        }
        let payload_limit = callback_payload_limit(self.callback_policy, callback_class);
        if let Some(limit) = payload_limit.filter(|limit| payload_bytes > *limit) {
            warn!(
                payload_bytes,
                limit,
                callback_class = ?callback_class,
                "dropping oversized connector callback payload"
            );
            return true;
        }
        let family = match &event {
            TransportEvent::Message(_) => PreAuthResourceFamily::FrameBytes,
            TransportEvent::VideoSample(_) | TransportEvent::AudioSample(_) => {
                PreAuthResourceFamily::MediaQuarantine
            }
            _ => PreAuthResourceFamily::ConnectorSpecificWork,
        };
        let observation = self.resource_scope.as_ref().map(|scope| {
            scope.observe_pre_authentication_measurement(
                family,
                ResourceMeasurement::inexact(ResourceUse::observed(
                    1,
                    u64::try_from(payload_bytes).unwrap_or(u64::MAX),
                    u64::try_from(payload_bytes).unwrap_or(u64::MAX),
                    0,
                )),
            )
        });
        let mut queued = Some(QueuedTransportEvent { event, observation });
        let Some(mailbox) = self.events.sender(callback_class) else {
            // Real-time units must enter through an exact RealtimeFlowPort.
            // A connector-wide compatibility mailbox would let one flow
            // consume or reorder another flow's admitted queue.
            return false;
        };
        let mut data_channel_close = self.data_channel_fence.subscribe();
        let send = async {
            loop {
                let mut connector_retirement = self.callback_gate.subscribe_retirement();
                let Some(liveness) = self.attempt_liveness.as_ref() else {
                    if *connector_retirement.borrow() || !self.callback_gate.is_active() {
                        return false;
                    }
                    let permit = tokio::select! {
                        biased;
                        _ = connector_retirement.changed() => return false,
                        _ = data_channel_close.changed(), if fence_data_channel => return true,
                        result = mailbox.reserve() => result,
                    };
                    let Ok(permit) = permit else {
                        return false;
                    };
                    if *connector_retirement.borrow() || !self.callback_gate.is_active() {
                        return false;
                    }
                    let Some(event) = queued.take() else {
                        return false;
                    };
                    if fence_data_channel {
                        let closed = self.data_channel_fence.closed.lock();
                        if *closed {
                            return true;
                        }
                        permit.send(event);
                    } else {
                        permit.send(event);
                    }
                    return true;
                };
                let mut retirement = liveness.subscribe_retirement();
                if (*connector_retirement.borrow() || !self.callback_gate.is_active())
                    || ((*retirement.borrow() || !liveness.is_active())
                        && !self.candidate_promoted.load(Ordering::Acquire))
                {
                    return false;
                }
                tokio::select! {
                    biased;
                    _ = connector_retirement.changed() => return false,
                    _ = data_channel_close.changed(), if fence_data_channel => return true,
                    _ = retirement.changed(), if !self.candidate_promoted.load(Ordering::Acquire) => {
                        if !self.candidate_promoted.load(Ordering::Acquire) {
                            return false;
                        }
                    }
                    result = mailbox.reserve() => {
                        let Ok(permit) = result else {
                            return false;
                        };
                        if *connector_retirement.borrow() || !self.callback_gate.is_active() {
                            return false;
                        }
                        if (*retirement.borrow() || !liveness.is_active())
                            && !self.candidate_promoted.load(Ordering::Acquire)
                        {
                            return false;
                        }
                        let Some(event) = queued.take() else {
                            return false;
                        };
                        if fence_data_channel {
                            let closed = self.data_channel_fence.closed.lock();
                            if *closed {
                                return true;
                            }
                            permit.send(event);
                        } else {
                            permit.send(event);
                        }
                        return true;
                    }
                }
            }
        };

        send.await
    }
}

/// Receiver half owned by the connector callback pump.
pub(crate) struct WebRtcConnectorEventReceiver {
    ownership: ConnectorOwnership,
    retirement: watch::Receiver<bool>,
    attempt_retirement: Option<watch::Receiver<bool>>,
    raw: TransportEventReceiver,
    attempt_lifetime: Option<AttemptLifetime>,
    remote_candidates: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
    data_channel_open_committed: bool,
    data_channel_closed: bool,
}

/// Lab/test receiver for raw WebRTC behavior. Production wraps it in the
/// connector owner before any event can reach the engine.
pub struct TransportEventReceiver {
    control: mpsc::Receiver<QueuedTransportEvent>,
    endpoint_data: mpsc::Receiver<QueuedTransportEvent>,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    scheduler: ConnectorCallbackScheduler,
}

impl TransportEventReceiver {
    fn try_scheduled_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        for _ in 0..3 {
            let class = self.scheduler.current();
            if class == ConnectorCallbackClass::EndpointData && !allow_endpoint_data {
                self.scheduler.skip_current();
                continue;
            }
            let event = if class == ConnectorCallbackClass::Realtime {
                self.realtime_flows.try_recv()
            } else {
                match class {
                    ConnectorCallbackClass::Control => self.control.try_recv().ok(),
                    ConnectorCallbackClass::EndpointData => self.endpoint_data.try_recv().ok(),
                    ConnectorCallbackClass::Realtime => unreachable!(),
                }
            };
            match event {
                Some(event) => {
                    self.scheduler.delivered(class);
                    return Some(event);
                }
                None => {
                    self.scheduler.skip_current();
                }
            }
        }
        None
    }

    fn try_scheduled(&mut self) -> Option<QueuedTransportEvent> {
        self.try_scheduled_filtered(true)
    }

    async fn recv_queued_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        loop {
            if let Some(event) = self.try_scheduled_filtered(allow_endpoint_data) {
                return Some(event);
            }
            if self.control.is_closed()
                && self.control.is_empty()
                && (!allow_endpoint_data
                    || (self.endpoint_data.is_closed() && self.endpoint_data.is_empty()))
                && self.realtime_flows.is_empty()
            {
                return None;
            }
            tokio::select! {
                event = self.control.recv(), if !self.control.is_closed() || !self.control.is_empty() => {
                    if let Some(event) = event {
                        self.scheduler.delivered(ConnectorCallbackClass::Control);
                        return Some(event);
                    }
                }
                event = self.endpoint_data.recv(), if allow_endpoint_data && (!self.endpoint_data.is_closed() || !self.endpoint_data.is_empty()) => {
                    if let Some(event) = event {
                        self.scheduler.delivered(ConnectorCallbackClass::EndpointData);
                        return Some(event);
                    }
                }
                _ = self.realtime_flows.ready.notified() => {
                    continue;
                }
            }
        }
    }

    async fn recv_queued(&mut self) -> Option<QueuedTransportEvent> {
        self.recv_queued_filtered(true).await
    }

    pub async fn recv(&mut self) -> Option<TransportEvent> {
        self.recv_queued().await.map(|queued| queued.event)
    }

    pub fn try_recv(&mut self) -> std::result::Result<TransportEvent, mpsc::error::TryRecvError> {
        if let Some(queued) = self.try_scheduled() {
            return Ok(queued.event);
        }
        if self.control.is_closed()
            && self.endpoint_data.is_closed()
            && self.realtime_flows.is_empty()
        {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }
}

impl WebRtcConnectorEventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<WebRtcConnectorEvent> {
        loop {
            if self.data_channel_closed {
                return None;
            }
            if *self.retirement.borrow() {
                return None;
            }
            if self
                .attempt_retirement
                .as_ref()
                .is_some_and(|retirement| *retirement.borrow())
                && self.reclaim_retired_attempt_candidate()
            {
                return None;
            }
            let queued = tokio::select! {
                biased;
                _ = self.retirement.changed() => return None,
                _ = wait_for_optional_retirement(&mut self.attempt_retirement) => {
                    if self.reclaim_retired_attempt_candidate() {
                        return None;
                    }
                    continue;
                }
                queued = self.raw.recv_queued_filtered(self.data_channel_open_committed) => queued,
            };
            if let Some(queued) = queued {
                if self.ownership.incarnation.is_active() {
                    if matches!(&queued.event, TransportEvent::DataChannelClosed) {
                        self.data_channel_closed = true;
                    }
                    return Some(WebRtcConnectorEvent {
                        incarnation: Arc::clone(&self.ownership.incarnation),
                        event: queued.event,
                        _queue_observation: queued.observation,
                    });
                }
            }
            return None;
        }
    }

    /// Release bounded endpoint-protocol callbacks only after the engine has
    /// committed the exact connector's working-channel ownership transition.
    /// Delivering the control event is insufficient because its owner may be
    /// stale or may reject the transition.
    pub(crate) fn commit_data_channel_open(&mut self) {
        self.data_channel_open_committed = true;
    }

    fn reclaim_retired_attempt_candidate(&mut self) -> bool {
        self.attempt_retirement = None;
        if !self.ownership.retire_if_unconnected() {
            return false;
        }
        drain_remote_candidates(&self.remote_candidates);
        if let Some(close_owner) = self.close_owner.as_ref() {
            close_owner.start();
        } else {
            self.ownership.complete_cleanup();
        }
        true
    }

    #[cfg(test)]
    fn retire_attempt_for_test(&self) {
        self.attempt_lifetime
            .as_ref()
            .expect("test receiver owns its attempt")
            .retire();
    }
}

impl Drop for WebRtcConnectorEventReceiver {
    fn drop(&mut self) {
        if let Some(lifetime) = self.attempt_lifetime.take() {
            lifetime.retire();
        }
        self.ownership.retire();
        drain_remote_candidates(&self.remote_candidates);
        if let Some(close_owner) = self.close_owner.as_ref() {
            close_owner.start();
        } else {
            self.ownership.complete_cleanup();
        }
    }
}

async fn wait_for_optional_retirement(retirement: &mut Option<watch::Receiver<bool>>) {
    match retirement {
        Some(retirement) => {
            let _ = retirement.changed().await;
        }
        None => std::future::pending::<()>().await,
    }
}

fn drain_remote_candidates(remote_candidates: &SyncMutex<RemoteCandidateState>) {
    let pending = remote_candidates.lock().pending.take();
    drop(pending);
}

/// Result of applying an inbound candidate through the connector owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteCandidateDisposition {
    Applied,
    QueuedUntilRemoteDescription,
}

/// Outcome of the data-channel-open ownership transition.
#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only capability would add an unaccounted allocation"
)]
pub(crate) enum DataChannelOpenOwnership {
    /// Exact admitted candidate produced a capability for Endpoint Auth Task.
    Connected(EndpointAuthHandoff),
    /// The exact worker has already handed its one capability onward.
    AlreadyConnected,
    /// Worker, attempt, or candidate was no longer live.
    Rejected,
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only cleanup claim would add an unaccounted allocation"
)]
enum DataChannelOpenTransition {
    Connected(crate::connector::ConnectedChannelCapability),
    AlreadyConnected,
    Rejected,
}

/// Candidate failures observed while a newly applied remote description drains
/// the connector-owned pre-SDP queue.
pub(crate) struct RemoteDescriptionApplyReport {
    pub(crate) queued_candidate_count: usize,
    pub(crate) candidate_failures: Vec<Error>,
}

/// One remote candidate paired with the observation that follows its owner.
/// Moving this value moves the observation. Dropping it ends the observation.
#[derive(Debug)]
struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    observation: CandidateObservationLease,
}

impl PendingRemoteCandidate {
    fn observe(candidate: LocalIceCandidate, resource_scope: &PeerConnectionResourceScope) -> Self {
        let observation = CandidateObservationLease {
            _observation: resource_scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::CandidateObject,
                candidate_resource_measurement(&candidate),
            ),
        };
        Self {
            candidate,
            observation,
        }
    }
}

/// Apply an observed candidate while retaining its lease across the await.
/// Cancellation drops both the future and its observation.
async fn apply_pending_remote_candidate<F, Fut, T>(pending: PendingRemoteCandidate, apply: F) -> T
where
    F: FnOnce(LocalIceCandidate) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let PendingRemoteCandidate {
        candidate,
        observation,
    } = pending;
    let result = apply(candidate).await;
    drop(observation);
    result
}

#[derive(Debug)]
struct CandidateObservationLease {
    _observation: ObservationLease,
}

#[derive(Debug, Default)]
struct PendingRemoteCandidateQueue {
    entries: Vec<PendingRemoteCandidate>,
    container_observation: Option<ObservationLease>,
}

impl PendingRemoteCandidateQueue {
    fn push(&mut self, candidate: LocalIceCandidate, resource_scope: &PeerConnectionResourceScope) {
        self.entries
            .push(PendingRemoteCandidate::observe(candidate, resource_scope));
        let measurement = queue_container_resource_measurement(&self.entries);
        match self.container_observation.as_mut() {
            Some(observation) => observation.replace_measurement(measurement),
            None => {
                self.container_observation =
                    Some(resource_scope.observe_pre_authentication_measurement(
                        PreAuthResourceFamily::CandidateObject,
                        measurement,
                    ));
            }
        }
    }

    fn take(&mut self) -> PendingRemoteCandidateDrain {
        let queue = std::mem::take(self);
        PendingRemoteCandidateDrain {
            entries: queue.entries.into_iter(),
            _container_observation: queue.container_observation,
        }
    }
}

#[derive(Debug)]
struct PendingRemoteCandidateDrain {
    entries: std::vec::IntoIter<PendingRemoteCandidate>,
    _container_observation: Option<ObservationLease>,
}

impl Default for PendingRemoteCandidateDrain {
    fn default() -> Self {
        Self {
            entries: Vec::new().into_iter(),
            _container_observation: None,
        }
    }
}

impl PendingRemoteCandidateDrain {
    fn len(&self) -> usize {
        self.entries.len()
    }
}

impl Iterator for PendingRemoteCandidateDrain {
    type Item = PendingRemoteCandidate;

    fn next(&mut self) -> Option<Self::Item> {
        self.entries.next()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.entries.size_hint()
    }
}

impl ExactSizeIterator for PendingRemoteCandidateDrain {}

#[derive(Default)]
struct RemoteCandidateState {
    remote_description_set: bool,
    pending: PendingRemoteCandidateQueue,
}

#[allow(
    clippy::large_enum_variant,
    reason = "boxing the move-only candidate would add an unaccounted allocation"
)]
enum ConnectorAuthorityState {
    Awaiting {
        candidate: ConnectorCandidateCapability,
        liveness: AttemptLiveness,
    },
    /// The candidate has left the connector mutex and is being promoted under
    /// the attempt transition. No connector event is accepted in this state.
    Promoting,
    Connected,
    Retired {
        /// An unpromoted child claim remains owned until native cleanup has
        /// completed. Promotion can lose a race with retirement, so the slot
        /// may be filled after cleanup starts.
        candidate: Option<ConnectorCandidateCapability>,
    },
}

#[derive(Clone)]
struct ConnectorOwnership {
    incarnation: Arc<WebRtcConnectorIncarnation>,
    authority: Arc<SyncMutex<ConnectorAuthorityState>>,
    realtime_delivery: Arc<AtomicBool>,
    candidate_promoted: Arc<AtomicBool>,
    cleanup_complete: Arc<AtomicBool>,
    cleanup_failed: Arc<AtomicBool>,
}

impl ConnectorOwnership {
    fn admitted(
        candidate: ConnectorCandidateCapability,
        realtime_delivery: Arc<AtomicBool>,
        candidate_promoted: Arc<AtomicBool>,
        incarnation: Arc<WebRtcConnectorIncarnation>,
    ) -> Self {
        let attempt = candidate.liveness();
        Self {
            incarnation,
            authority: Arc::new(SyncMutex::new(ConnectorAuthorityState::Awaiting {
                candidate,
                liveness: attempt,
            })),
            realtime_delivery,
            candidate_promoted,
            cleanup_complete: Arc::new(AtomicBool::new(false)),
            cleanup_failed: Arc::new(AtomicBool::new(false)),
        }
    }

    fn accepts(&self, event: &WebRtcConnectorEvent) -> bool {
        if !Arc::ptr_eq(&self.incarnation, &event.incarnation) || !self.incarnation.is_active() {
            return false;
        }
        match (&*self.authority.lock(), &event.event) {
            (ConnectorAuthorityState::Retired { .. }, _) => false,
            (
                ConnectorAuthorityState::Awaiting { liveness, .. },
                TransportEvent::Message(_)
                | TransportEvent::VideoSample(_)
                | TransportEvent::AudioSample(_),
            ) => {
                let _ = liveness;
                false
            }
            (ConnectorAuthorityState::Awaiting { liveness, .. }, _) => liveness.is_active(),
            (ConnectorAuthorityState::Promoting, _) => false,
            (
                ConnectorAuthorityState::Connected,
                TransportEvent::VideoSample(_) | TransportEvent::AudioSample(_),
            ) => self.realtime_delivery.load(Ordering::Acquire),
            (ConnectorAuthorityState::Connected, _) => true,
        }
    }

    fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.incarnation.is_active() && task.belongs_to(&self.incarnation)
    }

    fn owns_realtime_flow(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
    ) -> bool {
        capability.belongs_to(&self.incarnation)
    }

    fn mark_data_channel_open(&self) -> DataChannelOpenTransition {
        self.mark_data_channel_open_after_extract(|| {})
    }

    /// Promote without nesting the connector-authority mutex and attempt
    /// transition mutex.
    ///
    /// The candidate first moves into a private `Promoting` state under the
    /// connector mutex. That mutex is released before `mark_connected` enters
    /// the attempt transition. The connector mutex is then reacquired only to
    /// publish the result. Attempt retirement may therefore notify connector
    /// retirement after releasing its own transition mutex without creating a
    /// reverse lock edge.
    fn mark_data_channel_open_after_extract(
        &self,
        after_extract: impl FnOnce(),
    ) -> DataChannelOpenTransition {
        let candidate = {
            let mut authority = self.authority.lock();
            if !self.incarnation.is_active() {
                return DataChannelOpenTransition::Rejected;
            }
            match std::mem::replace(
                &mut *authority,
                ConnectorAuthorityState::Retired { candidate: None },
            ) {
                ConnectorAuthorityState::Awaiting {
                    candidate,
                    liveness: _,
                } => {
                    *authority = ConnectorAuthorityState::Promoting;
                    candidate
                }
                ConnectorAuthorityState::Promoting => {
                    *authority = ConnectorAuthorityState::Promoting;
                    return DataChannelOpenTransition::Rejected;
                }
                ConnectorAuthorityState::Connected => {
                    *authority = ConnectorAuthorityState::Connected;
                    return DataChannelOpenTransition::AlreadyConnected;
                }
                ConnectorAuthorityState::Retired { candidate } => {
                    *authority = ConnectorAuthorityState::Retired { candidate };
                    self.incarnation.retire();
                    return DataChannelOpenTransition::Rejected;
                }
            }
        };

        after_extract();
        let promoted = crate::connector::try_mark_connected(candidate);
        let mut authority = self.authority.lock();
        match (
            std::mem::replace(
                &mut *authority,
                ConnectorAuthorityState::Retired { candidate: None },
            ),
            promoted,
        ) {
            (ConnectorAuthorityState::Promoting, Ok(capability))
                if self.incarnation.is_active() =>
            {
                *authority = ConnectorAuthorityState::Connected;
                self.candidate_promoted.store(true, Ordering::Release);
                DataChannelOpenTransition::Connected(capability)
            }
            (state, promoted) => {
                let candidate = match promoted {
                    Ok(capability) => capability.into_candidate(),
                    Err(candidate) => candidate,
                };
                *authority = match state {
                    ConnectorAuthorityState::Retired {
                        candidate: existing,
                    } => ConnectorAuthorityState::Retired {
                        candidate: existing.or(Some(candidate)),
                    },
                    _ => ConnectorAuthorityState::Retired {
                        candidate: Some(candidate),
                    },
                };
                self.incarnation.retire();
                if self.cleanup_failed.load(Ordering::Acquire) {
                    Self::retain_failed_candidate_locked(&mut authority);
                } else if self.cleanup_complete.load(Ordering::Acquire) {
                    Self::release_cleanup_candidate_locked(&mut authority);
                }
                DataChannelOpenTransition::Rejected
            }
        }
    }

    fn retire(&self) {
        let mut authority = self.authority.lock();
        self.realtime_delivery.store(false, Ordering::Release);
        self.incarnation.retire();
        let candidate = match std::mem::replace(
            &mut *authority,
            ConnectorAuthorityState::Retired { candidate: None },
        ) {
            ConnectorAuthorityState::Awaiting { candidate, .. } => Some(candidate),
            ConnectorAuthorityState::Retired { candidate } => candidate,
            ConnectorAuthorityState::Promoting | ConnectorAuthorityState::Connected => None,
        };
        *authority = ConnectorAuthorityState::Retired { candidate };
        if self.cleanup_failed.load(Ordering::Acquire) {
            Self::retain_failed_candidate_locked(&mut authority);
        } else if self.cleanup_complete.load(Ordering::Acquire) {
            Self::release_cleanup_candidate_locked(&mut authority);
        }
    }

    /// Attempt retirement reclaims only candidates that have not promoted.
    /// A connected winner has already transferred into Endpoint Auth Task and
    /// is retired by its peer installation owner instead.
    fn retire_if_unconnected(&self) -> bool {
        let mut authority = self.authority.lock();
        if matches!(&*authority, ConnectorAuthorityState::Connected) {
            return false;
        }
        self.realtime_delivery.store(false, Ordering::Release);
        self.incarnation.retire();
        let candidate = match std::mem::replace(
            &mut *authority,
            ConnectorAuthorityState::Retired { candidate: None },
        ) {
            ConnectorAuthorityState::Awaiting { candidate, .. } => Some(candidate),
            ConnectorAuthorityState::Retired { candidate } => candidate,
            ConnectorAuthorityState::Promoting | ConnectorAuthorityState::Connected => None,
        };
        *authority = ConnectorAuthorityState::Retired { candidate };
        if self.cleanup_failed.load(Ordering::Acquire) {
            Self::retain_failed_candidate_locked(&mut authority);
        } else if self.cleanup_complete.load(Ordering::Acquire) {
            Self::release_cleanup_candidate_locked(&mut authority);
        }
        true
    }

    fn complete_cleanup(&self) {
        self.cleanup_complete.store(true, Ordering::Release);
        let mut authority = self.authority.lock();
        Self::release_cleanup_candidate_locked(&mut authority);
    }

    fn retain_after_cleanup_failure(&self) {
        self.cleanup_failed.store(true, Ordering::Release);
        let mut authority = self.authority.lock();
        Self::retain_failed_candidate_locked(&mut authority);
    }

    fn retain_failed_candidate_locked(authority: &mut ConnectorAuthorityState) {
        if let ConnectorAuthorityState::Retired {
            candidate: Some(candidate),
        } = authority
        {
            candidate.retain_after_cleanup_failure();
        }
    }

    fn release_cleanup_candidate_locked(authority: &mut ConnectorAuthorityState) {
        if let ConnectorAuthorityState::Retired { candidate } = authority {
            drop(candidate.take());
        }
    }

    #[cfg(test)]
    fn cleanup_candidate_reserved_for_test(&self) -> bool {
        match &*self.authority.lock() {
            ConnectorAuthorityState::Retired {
                candidate: Some(candidate),
            } => candidate.reservation_is_active_for_test(),
            _ => false,
        }
    }
}

fn candidate_resource_measurement(candidate: &LocalIceCandidate) -> ResourceMeasurement {
    let (logical_bytes, logical_inexact) = measured_sum([
        candidate.candidate.len(),
        candidate.sdp_mid.as_ref().map_or(0, String::len),
        candidate.username_fragment.as_ref().map_or(0, String::len),
    ]);
    let (retained_bytes, retained_inexact) = measured_sum([
        candidate.candidate.capacity(),
        candidate.sdp_mid.as_ref().map_or(0, String::capacity),
        candidate
            .username_fragment
            .as_ref()
            .map_or(0, String::capacity),
    ]);
    let observed = ResourceUse::observed(1, logical_bytes, retained_bytes, 0);
    if logical_inexact || retained_inexact {
        ResourceMeasurement::inexact(observed)
    } else {
        ResourceMeasurement::exact(observed)
    }
}

fn queue_container_resource_measurement(
    entries: &Vec<PendingRemoteCandidate>,
) -> ResourceMeasurement {
    let bytes = entries
        .capacity()
        .checked_mul(size_of::<PendingRemoteCandidate>());
    let (retained_bytes, inexact) = measured_usize(bytes);
    let observed = ResourceUse::observed(0, 0, retained_bytes, 0);
    if inexact {
        ResourceMeasurement::inexact(observed)
    } else {
        ResourceMeasurement::exact(observed)
    }
}

fn measured_usize(value: Option<usize>) -> (u64, bool) {
    match value.and_then(|value| u64::try_from(value).ok()) {
        Some(value) => (value, false),
        None => (u64::MAX, true),
    }
}

fn measured_sum<const N: usize>(values: [usize; N]) -> (u64, bool) {
    let mut sum = 0_u64;
    let mut inexact = false;
    for value in values {
        let (value, conversion_inexact) = measured_usize(Some(value));
        inexact |= conversion_inexact;
        match sum.checked_add(value) {
            Some(next) => sum = next,
            None => {
                sum = u64::MAX;
                inexact = true;
            }
        }
    }
    (sum, inexact)
}

/// Observe one explicitly owned connector item. Retained memory remains
/// inexact until the underlying webrtc-rs owner exposes an allocation report.
fn observe_inexact_item(
    scope: &PeerConnectionResourceScope,
    family: PreAuthResourceFamily,
    items: u64,
    tasks: u64,
) -> ObservationLease {
    scope.observe_pre_authentication_measurement(
        family,
        ResourceMeasurement::inexact(ResourceUse::observed(items, 0, 0, tasks)),
    )
}

fn observe_inexact_item_if(
    scope: Option<&PeerConnectionResourceScope>,
    family: PreAuthResourceFamily,
    items: u64,
    tasks: u64,
) -> Option<ObservationLease> {
    scope.map(|scope| observe_inexact_item(scope, family, items, tasks))
}

/// One move-only handoff from the exact connector incarnation to Endpoint
/// Auth Task.
pub(crate) struct EndpointAuthHandoff {
    capability: Option<crate::connector::ConnectedChannelCapability>,
    incarnation: Arc<WebRtcConnectorIncarnation>,
    close_owner: Arc<ConnectorCloseOwner>,
}

impl EndpointAuthHandoff {
    fn new(
        capability: crate::connector::ConnectedChannelCapability,
        incarnation: Arc<WebRtcConnectorIncarnation>,
        close_owner: Arc<ConnectorCloseOwner>,
    ) -> Self {
        Self {
            capability: Some(capability),
            incarnation,
            close_owner,
        }
    }

    pub(crate) fn belongs_to(&self, incarnation: &Arc<WebRtcConnectorIncarnation>) -> bool {
        Arc::ptr_eq(&self.incarnation, incarnation)
    }
}

impl Drop for EndpointAuthHandoff {
    fn drop(&mut self) {
        if let Some(capability) = self.capability.take() {
            self.close_owner.retain_connected_claim(capability);
        }
    }
}

/// Narrow owner of one RTCPeerConnection, its ICE agent, callback identity,
/// and pending remote-candidate queue.
///
/// Production construction requires an admitted connector-candidate capability.
/// The worker cannot mint admission from a peer label or native transport value.
pub(crate) struct WebRtcConnectorWorker {
    session: Arc<PeerSession>,
    ownership: ConnectorOwnership,
    remote_candidates: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Arc<ConnectorCloseOwner>,
    resource_scope: PeerConnectionResourceScope,
    _transport_observation: ObservationLease,
}

struct AdmittedConnectorOwnership {
    ownership: ConnectorOwnership,
    attempt_lifetime: AttemptLifetime,
    attempt_liveness: AttemptLiveness,
    close_owner: Arc<ConnectorCloseOwner>,
    resource_scope: PeerConnectionResourceScope,
    transport_observation: ObservationLease,
}

impl WebRtcConnectorWorker {
    fn admitted(
        session: PeerSession,
        raw: TransportEventReceiver,
        admitted: AdmittedConnectorOwnership,
    ) -> Result<(Self, WebRtcConnectorEventReceiver)> {
        let AdmittedConnectorOwnership {
            ownership,
            attempt_lifetime,
            attempt_liveness,
            close_owner,
            resource_scope,
            transport_observation,
        } = admitted;
        let attempt_retirement = attempt_liveness.subscribe_retirement();
        let session = Arc::new(session);
        let remote_candidates = Arc::new(SyncMutex::new(RemoteCandidateState::default()));
        if !close_owner.attach_remote_candidates(Arc::clone(&remote_candidates)) {
            close_owner.start();
            return Err(Error::Transport(
                "remote-candidate owner installation was refused".to_string(),
            ));
        }
        let receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw,
            attempt_lifetime: Some(attempt_lifetime),
            remote_candidates: Arc::clone(&remote_candidates),
            close_owner: Some(Arc::clone(&close_owner)),
            data_channel_open_committed: false,
            data_channel_closed: false,
        };
        Ok((
            Self {
                session,
                ownership,
                remote_candidates,
                close_owner,
                resource_scope,
                _transport_observation: transport_observation,
            },
            receiver,
        ))
    }

    /// Consume an event only when it came from this still-active worker.
    pub(crate) fn accept_event(&self, event: WebRtcConnectorEvent) -> Option<TransportEvent> {
        self.ownership.accepts(&event).then_some(event.event)
    }

    #[cfg(test)]
    pub(crate) fn stamp_event_for_test(&self, event: TransportEvent) -> WebRtcConnectorEvent {
        WebRtcConnectorEvent {
            incarnation: Arc::clone(&self.ownership.incarnation),
            event,
            _queue_observation: None,
        }
    }

    /// Apply or retain one inbound candidate under this worker's ownership.
    pub(crate) async fn add_remote_candidate(
        &self,
        candidate: LocalIceCandidate,
    ) -> Result<RemoteCandidateDisposition> {
        let pending = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport("connector worker is retired".to_string()));
            }
            if !state.remote_description_set {
                state.pending.push(candidate, &self.resource_scope);
                return Ok(RemoteCandidateDisposition::QueuedUntilRemoteDescription);
            }
            PendingRemoteCandidate::observe(candidate, &self.resource_scope)
        };
        self.apply_remote_candidate(pending).await?;
        Ok(RemoteCandidateDisposition::Applied)
    }

    /// Apply remote SDP, transfer queue ownership into the async drain, and
    /// apply every retained candidate through the connector-private raw API.
    pub(crate) async fn apply_remote_description(
        &self,
        description: RTCSessionDescription,
    ) -> Result<RemoteDescriptionApplyReport> {
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _work_observation = observe_inexact_item(
            &self.resource_scope,
            PreAuthResourceFamily::ConnectorSpecificWork,
            1,
            0,
        );
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.set_remote_description(description),
        )
        .await
        .ok_or_else(|| {
            Error::Transport("connector worker retired during SDP apply".to_string())
        })??;
        let pending = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport(
                    "connector worker retired during SDP apply".to_string(),
                ));
            }
            state.remote_description_set = true;
            state.pending.take()
        };
        let queued_candidate_count = pending.len();
        let mut candidate_failures = Vec::new();
        for candidate in pending {
            if let Err(error) = self.apply_remote_candidate(candidate).await {
                candidate_failures.push(error);
            }
        }
        Ok(RemoteDescriptionApplyReport {
            queued_candidate_count,
            candidate_failures,
        })
    }

    async fn apply_remote_candidate(&self, pending: PendingRemoteCandidate) -> Result<()> {
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _ice_observation =
            observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::IceWork, 1, 0);
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            apply_pending_remote_candidate(pending, |candidate| async move {
                self.session.add_ice_candidate(candidate).await
            }),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during ICE apply".to_string()))?
    }

    pub(crate) fn observe_owned_task(&self) -> ObservationLease {
        observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::Task, 1, 1)
    }

    pub(crate) async fn send_owned(&self, data: Bytes) -> Result<usize> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.send(data),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during send".to_string()))?
    }

    pub(crate) async fn create_offer(&self) -> Result<RTCSessionDescription> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_offer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during offer".to_string()))?
    }

    pub(crate) async fn create_answer(&self) -> Result<RTCSessionDescription> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_answer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during answer".to_string()))?
    }

    pub(crate) async fn remote_fingerprint(&self) -> Option<String> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.remote_fingerprint(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn local_fingerprint(&self) -> Option<String> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.local_fingerprint(),
        )
        .await
        .flatten()
    }

    pub(crate) fn awaiting_answer(&self) -> bool {
        self.ownership.incarnation.is_active() && self.session.awaiting_answer()
    }

    pub(crate) fn owns_realtime_flow(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
    ) -> bool {
        self.ownership.owns_realtime_flow(capability)
    }

    pub(crate) async fn open_media_lane(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        kind: LaneKind,
    ) -> Result<u8> {
        if !self.owns_realtime_flow(capability) {
            return Err(Error::Transport(
                "real-time flow capability does not own this connector".to_string(),
            ));
        }
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.open_media_lane(kind),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during lane open".to_string()))?
    }

    pub(crate) async fn close_media_lane(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        kind: LaneKind,
        lane: u8,
    ) -> Result<()> {
        if !self.owns_realtime_flow(capability) {
            return Err(Error::Transport(
                "real-time flow capability does not own this connector".to_string(),
            ));
        }
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.close_media_lane(kind, lane),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during lane close".to_string()))?
    }

    pub(crate) async fn send_video(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        lane: u8,
        data: Bytes,
        duration: Duration,
    ) -> Result<()> {
        if !self.owns_realtime_flow(capability) {
            return Err(Error::Transport(
                "real-time flow capability does not own this connector".to_string(),
            ));
        }
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.send_video(lane, data, duration),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during video send".to_string()))?
    }

    pub(crate) async fn send_audio(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        lane: u8,
        data: Bytes,
        duration: Duration,
    ) -> Result<()> {
        if !self.owns_realtime_flow(capability) {
            return Err(Error::Transport(
                "real-time flow capability does not own this connector".to_string(),
            ));
        }
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.send_audio(lane, data, duration),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during audio send".to_string()))?
    }

    pub(crate) fn has_reapable_lanes(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        grace: Duration,
    ) -> bool {
        self.owns_realtime_flow(capability) && self.session.has_reapable_lanes(grace)
    }

    pub(crate) async fn reap_drained_lanes(
        &self,
        capability: &crate::connector::ConnectorRealtimeFlowCapability,
        grace: Duration,
    ) -> usize {
        if !self.owns_realtime_flow(capability) {
            return 0;
        }
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.reap_drained_lanes(grace),
        )
        .await
        .unwrap_or(0)
    }

    pub(crate) fn signaling_state(&self) -> RTCSignalingState {
        self.session.signaling_state()
    }

    pub(crate) fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.session.ice_connection_state()
    }

    pub(crate) fn connection_state(&self) -> RTCPeerConnectionState {
        self.session.connection_state()
    }

    pub(crate) async fn restart_ice(&self) -> Result<()> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.restart_ice(),
        )
        .await
        .ok_or_else(|| {
            Error::Transport("connector worker retired during ICE restart".to_string())
        })?
    }

    pub(crate) async fn selected_candidate_pair(
        &self,
    ) -> Option<super::diag::SelectedCandidatePair> {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.selected_candidate_pair(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.ice_check_snapshot(),
        )
        .await
        .unwrap_or_default()
    }

    pub(crate) fn confirm_data_channel_open(&self) -> DataChannelOpenOwnership {
        match self.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => {
                DataChannelOpenOwnership::Connected(EndpointAuthHandoff::new(
                    capability,
                    Arc::clone(&self.ownership.incarnation),
                    Arc::clone(&self.close_owner),
                ))
            }
            DataChannelOpenTransition::AlreadyConnected => {
                DataChannelOpenOwnership::AlreadyConnected
            }
            DataChannelOpenTransition::Rejected => DataChannelOpenOwnership::Rejected,
        }
    }

    /// Revoke callback acceptance and release every connector-owned candidate.
    pub(crate) fn retire(&self) {
        self.close_owner.retire_local();
    }

    pub(crate) fn admit_legacy_realtime_flow(
        &self,
        task: &crate::endpoint_auth::EndpointAuthTask,
    ) -> Option<Arc<crate::connector::ConnectorRealtimeFlowCapability>> {
        if !self.owns_endpoint_auth(task)
            || !self.ownership.incarnation.is_active()
            || !self.session.realtime_enabled()
        {
            return None;
        }
        self.ownership
            .realtime_delivery
            .store(true, Ordering::Release);
        Some(Arc::new(
            crate::connector::ConnectorRealtimeFlowCapability::new(Arc::clone(
                &self.ownership.incarnation,
            )),
        ))
    }

    pub(crate) fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.ownership.owns_endpoint_auth(task)
    }

    /// Retire local ownership first, then close the native peer connection.
    /// This is the only operation intentionally allowed to continue after
    /// retirement. The local proof is limited to requesting and awaiting the
    /// dependency's idempotent peer-connection close operation.
    pub(crate) async fn retire_and_close(&self) -> Result<()> {
        self.close_owner.wait().await
    }
}

impl Drop for WebRtcConnectorWorker {
    fn drop(&mut self) {
        self.close_owner.start();
    }
}

/// One H.264 access unit off a peer's video track. This compatibility-adapter
/// value contains Annex-B bytes ready for a decoder. `rtp_timestamp` ticks at
/// the 90 kHz video clock, `key` marks an IDR, and `lane` identifies the
/// adapter lane on which it arrived.
#[derive(Debug, Clone)]
pub struct VideoSample {
    pub rtp_timestamp: u32,
    pub key: bool,
    pub lane: u8,
    pub data: Bytes,
    _reservation: Option<RealtimePayloadLease>,
}

/// One Opus frame off a peer's audio track — exactly one frame per
/// RTP packet (RFC 7587), so there is no reassembly: the payload is
/// decoder-ready as it arrives. `rtp_timestamp` ticks at the 48 kHz
/// Opus clock; `lane` is which of the peer's audio lanes it arrived on.
/// Frames are surfaced in arrival order; a reordered packet (rare on
/// the paths this rides) costs one frame of fidelity, never a wedged
/// stream.
#[derive(Debug, Clone)]
pub struct AudioSample {
    pub rtp_timestamp: u32,
    pub lane: u8,
    pub data: Bytes,
    _reservation: Option<RealtimePayloadLease>,
}

/// Ceiling on independent media lanes (RTP tracks) a peer connection
/// may hold per kind, video and audio alike. Lanes are **not**
/// provisioned up front: a fresh connection carries exactly
/// [`PRE_PROVISIONED_LANES`] (lane 0 — the original single lane, so a
/// pre-lifecycle peer negotiates just it and everything still works),
/// and lanes 1+ come into being on demand — an explicit
/// `open_*_lane`, or transparently on the first write to a lane that
/// doesn't exist yet. Each open adds one track (id `video-N` /
/// `audio-N`) and renegotiates in place; a close *drains* — the track
/// stays attached through [`LANE_DRAIN_GRACE`] so an immediate reopen
/// is free, and only a drain that outlives the grace is actually torn
/// down (one renegotiation per reap sweep). Media capacity is still
/// paid only while a session actually uses it.
///
/// `MYOWNMESH_MEDIA_LANES` still caps the ceiling per device (clamped
/// to `1..=MEDIA_LANES`): a data-only appliance sets `1` and no lane
/// beyond 0 can ever be opened toward it locally, exactly as before —
/// except the SDP no longer hauls idle m-lines for anyone.
pub const MEDIA_LANES: usize = 8;

/// Lanes created at connection setup, before any media flows: lane 0
/// only. Everything else is lifecycle-managed (see [`MEDIA_LANES`]).
///
/// These pre-provisioned lanes are also **pinned**: once negotiated they
/// are never reaped for the connection's life. A close still drains them
/// (silent — no RTP), but the track stays attached indefinitely, so a
/// re-open always takes the zero-SDP free-revive path instead of the
/// recycled-m-line renegotiation that does not reliably re-`ontrack` on
/// the viewer. [`LANE_DRAIN_GRACE`] governs only the transient lanes
/// (1+); the pinned lane needs no timer. This costs one always-present
/// m-line per connection — the one that was pre-provisioned anyway — and
/// removes the per-stop→start reap↔re-add churn on the common
/// single-stream path (screen share, CEC console).
pub const PRE_PROVISIONED_LANES: usize = 1;

/// How long a closed lane keeps its track attached before the reaper
/// finalizes the teardown (`remove_track` + one in-place renegotiation).
///
/// This grace is what makes a stop→start cycle — a settings change, a
/// stream restart, a viewer toggling a feed — cost **zero SDP work**:
/// the close only marks the slot draining, and a reopen inside the
/// grace revives the same negotiated track, so samples flow again on
/// the first write. That is exactly the smoothness the pre-lifecycle
/// transport had (every lane always open); the grace buys it back
/// without re-paying the always-on SDP tax.
///
/// The window has to cover a *human* stop→start, not just an app-level
/// reconfigure: a technician closing a console and re-opening it seconds
/// later must land on the free-revive path, because the alternative —
/// reaping the track and negotiating a fresh recycled m-line — does not
/// reliably re-`ontrack` on the viewer (screen re-opens sat at "connecting"
/// with no frames arriving, fixed only by a full peer restart). 5s missed
/// that by a mile (a real re-open is 8–15s), so widen to 90s.
///
/// This costs nothing on the wire: a draining lane is *silent* — the app
/// writes no samples, so no RTP flows; the grace only keeps the (already
/// negotiated) m-line alive a little longer before the reaper removes it.
/// A genuinely-abandoned lane is still reaped, just after a session-sized
/// window instead of a machine-sized one — quiet network intact, and one
/// fewer reap↔re-add renegotiation churn per stop→start cycle. Override
/// with `MYOWNMESH_LANE_DRAIN_SECS` (clamped 1..=600) for tuning.
pub static LANE_DRAIN_GRACE: std::sync::LazyLock<Duration> = std::sync::LazyLock::new(|| {
    let secs = std::env::var("MYOWNMESH_LANE_DRAIN_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(90)
        .clamp(1, 600);
    Duration::from_secs(secs)
});

/// Per-device media-lane ceiling, resolved once at transport
/// construction. `MYOWNMESH_MEDIA_LANES` overrides the [`MEDIA_LANES`]
/// default; clamped to `1..=MEDIA_LANES` so track-id parsing (capped at
/// [`MEDIA_LANES`]) stays coherent and lane 0 always exists.
fn resolve_media_lanes() -> usize {
    match std::env::var("MYOWNMESH_MEDIA_LANES") {
        Ok(v) => match v.trim().parse::<usize>() {
            Ok(n) => n.clamp(1, MEDIA_LANES),
            Err(_) => MEDIA_LANES,
        },
        Err(_) => MEDIA_LANES,
    }
}

/// The process-wide resolved lane ceiling — how many simultaneous
/// lanes a client may hold toward one peer on this device. Public so
/// the control plane's Status can report it: apps size their
/// concurrent streams to this. (Lanes open on demand up to it; nothing
/// is pre-provisioned beyond lane 0.)
pub fn resolved_media_lanes() -> usize {
    resolve_media_lanes()
}

fn lane_of_track_id(id: &str) -> u8 {
    id.rsplit_once('-')
        .and_then(|(_, n)| n.parse::<u8>().ok())
        .filter(|n| (*n as usize) < MEDIA_LANES)
        .unwrap_or(0)
}

/// One locally-gathered ICE candidate, in the form the signaling
/// layer needs (matches the webrtc-rs `RTCIceCandidateInit` shape).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LocalIceCandidate {
    pub candidate: String,
    pub sdp_mid: Option<String>,
    pub sdp_mline_index: Option<u16>,
    pub username_fragment: Option<String>,
}

impl LocalIceCandidate {
    fn into_init(self) -> RTCIceCandidateInit {
        RTCIceCandidateInit {
            candidate: self.candidate,
            sdp_mid: self.sdp_mid,
            sdp_mline_index: self.sdp_mline_index,
            username_fragment: self.username_fragment,
        }
    }
}

/// Engine-owned WebRTC factory. Construct once per [`crate::Mesh`]
/// instance; cheap to clone.
#[derive(Clone)]
pub struct Transport {
    api: Arc<webrtc::api::API>,
    runtime: crate::runtime::RuntimeIncarnation,
    ice_transport_policy: RTCIceTransportPolicy,
    /// Media lanes provisioned per peer connection (see [`resolve_media_lanes`]).
    media_lanes: usize,
    connector_resource_scope: Option<MeshConnectorResourceScope>,
    #[cfg(test)]
    construction_hook: Option<Arc<ConstructionTestHook>>,
}

struct PeerOpenOwnership {
    resource_scope: Option<PeerConnectionResourceScope>,
    realtime_delivery: Arc<AtomicBool>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_policy: ConnectorCallbackPolicy,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstructionPause {
    AfterNativeAllocation,
    AfterNativeAllocationWithCloseError,
    AfterResultDelivery,
    FailAfterNativeAllocation,
}

#[cfg(test)]
struct ConstructionTestHook {
    pause: ConstructionPause,
    created: Semaphore,
    resume: Semaphore,
    peer_connection: SyncMutex<Option<Arc<RTCPeerConnection>>>,
}

#[cfg(test)]
impl ConstructionTestHook {
    fn new(pause: ConstructionPause) -> Arc<Self> {
        Arc::new(Self {
            pause,
            created: Semaphore::new(0),
            resume: Semaphore::new(0),
            peer_connection: SyncMutex::new(None),
        })
    }

    async fn pause_after_native_allocation(&self, pc: &Arc<RTCPeerConnection>) {
        if self.pause == ConstructionPause::FailAfterNativeAllocation {
            *self.peer_connection.lock() = Some(Arc::clone(pc));
            panic!("injected connector construction task failure");
        }
        if matches!(
            self.pause,
            ConstructionPause::AfterNativeAllocation
                | ConstructionPause::AfterNativeAllocationWithCloseError
        ) {
            self.pause_at(pc).await;
        }
    }

    async fn pause_after_result_delivery(&self, pc: &Arc<RTCPeerConnection>) {
        if self.pause == ConstructionPause::AfterResultDelivery {
            self.pause_at(pc).await;
        }
    }

    async fn pause_at(&self, pc: &Arc<RTCPeerConnection>) {
        *self.peer_connection.lock() = Some(Arc::clone(pc));
        self.created.add_permits(1);
        let permit = self
            .resume
            .acquire()
            .await
            .expect("construction test hook remains open");
        permit.forget();
    }

    fn inject_native_close_error(&self) -> bool {
        self.pause == ConstructionPause::AfterNativeAllocationWithCloseError
    }
}

/// Private construction result that retains the child reservation until the
/// outer connector owner accepts it. If the caller is cancelled after result
/// delivery, dropping this value closes the native peer before releasing the
/// candidate claim.
struct ConstructedConnectorResult {
    session: Option<PeerSession>,
    events: Option<TransportEventReceiver>,
    close_owner: Arc<ConnectorCloseOwner>,
}

/// Cancels connector construction when the awaiting caller is dropped. Any
/// native object already returned to the task is then retired by its
/// `PeerConstructionGuard` during future cancellation.
struct AbortConstructionOnDrop<T>(tokio::task::JoinHandle<T>);

impl<T> Drop for AbortConstructionOnDrop<T> {
    fn drop(&mut self) {
        self.0.abort();
    }
}

/// Starts the one connector cleanup owner if the outer construction future is
/// cancelled or fails before the admitted worker takes ownership.
struct StartConnectorCleanupOnDrop(Option<Arc<ConnectorCloseOwner>>);

impl StartConnectorCleanupOnDrop {
    fn new(owner: Arc<ConnectorCloseOwner>) -> Self {
        Self(Some(owner))
    }

    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for StartConnectorCleanupOnDrop {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.start();
        }
    }
}

impl ConstructedConnectorResult {
    fn new(
        session: PeerSession,
        events: TransportEventReceiver,
        close_owner: Arc<ConnectorCloseOwner>,
    ) -> Self {
        Self {
            session: Some(session),
            events: Some(events),
            close_owner,
        }
    }

    #[cfg(test)]
    fn peer_connection(&self) -> &Arc<RTCPeerConnection> {
        &self
            .session
            .as_ref()
            .expect("constructed result retains its session")
            .pc
    }

    fn into_parts(
        mut self,
    ) -> (
        PeerSession,
        TransportEventReceiver,
        Arc<ConnectorCloseOwner>,
    ) {
        (
            self.session.take().expect("constructed session exists"),
            self.events.take().expect("constructed event owner exists"),
            Arc::clone(&self.close_owner),
        )
    }
}

impl Drop for ConstructedConnectorResult {
    fn drop(&mut self) {
        let (Some(session), Some(events)) = (self.session.take(), self.events.take()) else {
            return;
        };
        drop(session);
        drop(events);
        self.close_owner.start();
    }
}

impl Transport {
    /// Build a fresh transport with the default media engine and
    /// interceptors. The webrtc-rs defaults cover everything we
    /// need for data-channel-only operation.
    pub fn new() -> Result<Self> {
        let mut media_engine = MediaEngine::default();
        media_engine
            .register_default_codecs()
            .map_err(|e| Error::Transport(format!("register codecs: {e}")))?;
        let mut registry = Registry::new();
        registry = register_default_interceptors(registry, &mut media_engine)
            .map_err(|e| Error::Transport(format!("register interceptors: {e}")))?;

        // Trim ICE candidate gathering to interfaces that can actually
        // carry peer traffic. Without this the agent gathers a host
        // candidate on every up interface — including Docker bridges and
        // other virtual nets whose `172.x.0.1`-style gateway addresses no
        // remote peer can ever reach — which bloats the candidate set and
        // drags out the connectivity-check phase. The Tailscale tunnel is
        // intentionally *kept* (it's a real path); only the dead virtual
        // interfaces in `VIRTUAL_IFACE_PREFIXES` are dropped.
        let mut setting_engine = SettingEngine::default();
        setting_engine.set_interface_filter(Box::new(|name: &str| {
            let keep = !is_virtual_interface(name);
            // Instrumentation: a one-liner per excluded interface so a log
            // (with our crate at DEBUG) confirms exactly which interfaces
            // the filter pruned — the direct check that the candidate
            // explosion is actually being trimmed on a given box.
            if !keep {
                debug!(
                    interface = name,
                    "ICE: excluding virtual interface from candidate gathering"
                );
            }
            keep
        }));
        // Drop link-local addresses (v6 `fe80::/10`, v4 `169.254/16`) from
        // gathering. They can't be bound without a scope/zone id, so the
        // agent's bind fails on every one — a dozen per gather on a typical
        // macOS box — flooding the log with `could not listen udp fe80::… :
        // Can't assign requested address` while producing zero usable
        // candidates. Returning `false` excludes the address; routable host
        // addresses (global v4/v6, RFC-1918, ULA `fc00::/7`) and the
        // STUN/TURN base addresses are all kept. Loopback is already
        // excluded upstream unless explicitly enabled.
        setting_engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| !is_link_local_ip(&ip)));

        let api = APIBuilder::new()
            .with_media_engine(media_engine)
            .with_interceptor_registry(registry)
            .with_setting_engine(setting_engine)
            .build();
        // One startup line. The excluded prefixes live in the structured
        // field for anyone who needs them; the message stays a clean
        // one-liner rather than dumping the whole array into the stream.
        info!(
            excluded = VIRTUAL_IFACE_PREFIXES.len(),
            "ICE interface filter active — Docker/virtual interfaces excluded from candidate gathering"
        );
        let media_lanes = resolve_media_lanes();
        // A malformed override must be LOUD: it silently resolves to the
        // 8-lane default, which on a slow single-core device silently restores
        // the exact 16-m-line connect churn the variable exists to prevent —
        // and because resolved == default, the override info-line below never
        // fires either. A typo in an init script would otherwise be invisible
        // until the device wedges.
        if let Ok(v) = std::env::var("MYOWNMESH_MEDIA_LANES") {
            if v.trim().parse::<usize>().is_err() {
                warn!(
                    value = %v,
                    default = MEDIA_LANES,
                    "MYOWNMESH_MEDIA_LANES is set but not a number — using the default lane count"
                );
            }
        }
        if media_lanes != MEDIA_LANES {
            info!(
                media_lanes,
                default = MEDIA_LANES,
                "media-lane pool overridden via MYOWNMESH_MEDIA_LANES"
            );
        }
        // Surface the resolved drain grace once at startup. It governs how
        // long a closed media lane stays re-openable onto its already-
        // negotiated track (the free-revive path) before the reaper removes
        // it — the difference between a console re-open that resumes silently
        // and one forced into a fresh renegotiation. Logging it means field
        // logs self-verify which grace a daemon is actually running, instead
        // of guessing whether the new binary is live. Traffic-neutral: a
        // draining lane sends no RTP; this only sets the reap deadline.
        info!(
            secs = LANE_DRAIN_GRACE.as_secs(),
            overridden = std::env::var("MYOWNMESH_LANE_DRAIN_SECS").is_ok(),
            "media-lane drain grace active"
        );
        Ok(Self {
            api: Arc::new(api),
            runtime: crate::runtime::RuntimeIncarnation::new(),
            ice_transport_policy: RTCIceTransportPolicy::All,
            media_lanes,
            connector_resource_scope: None,
            #[cfg(test)]
            construction_hook: None,
        })
    }

    /// Bind this transport to an explicitly configured process resource owner.
    /// Connector construction is refused until this port is present.
    pub(crate) fn with_connector_resource_scope(
        mut self,
        scope: MeshConnectorResourceScope,
    ) -> Self {
        self.connector_resource_scope = Some(scope);
        self
    }

    /// Bind this transport to the one connector admission owner held by the
    /// process resource root. A second Mesh runtime shares the same owner and
    /// cannot multiply the process limit.
    pub fn with_connector_resource_policy(
        self,
        policy: ConnectorCapableResourcePolicy,
    ) -> Result<Self> {
        let root = ProcessResourceRoot::global();
        root.install_connector_policy(policy.process())?;
        let scope = root.issue_mesh_connector_scope(policy.mesh())?;
        Ok(self.with_connector_resource_scope(scope))
    }

    pub fn connector_resource_report(&self) -> Option<ConnectorResourceOwnerReport> {
        self.connector_resource_scope
            .as_ref()
            .map(|scope| scope.process_report())
    }

    pub fn mesh_connector_resource_report(&self) -> Option<MeshConnectorResourceReport> {
        self.connector_resource_scope
            .as_ref()
            .map(MeshConnectorResourceScope::report)
    }

    /// Build a lab transport that rejects host and server-reflexive candidate
    /// pairs. This is available only with `transport-lab` so production callers
    /// cannot accidentally make relay-only behavior the default.
    #[cfg(feature = "transport-lab")]
    pub fn new_relay_only_for_lab() -> Result<Self> {
        let mut transport = Self::new()?;
        transport.ice_transport_policy = RTCIceTransportPolicy::Relay;
        Ok(transport)
    }

    /// Open a new [`PeerSession`] for the given peer with the
    /// supplied STUN/TURN configuration. The session immediately
    /// installs all webrtc callbacks; events flow out the returned
    /// receiver until the session is dropped.
    #[cfg(any(test, feature = "transport-lab"))]
    pub async fn open_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let mut config = build_rtc_configuration(stun, turn);
        config.ice_transport_policy = self.ice_transport_policy;
        self.open_peer_with_config(role, config).await
    }

    /// Open the engine-owned connector wrapper around the existing WebRTC
    /// machinery. Arc 03 keeps the old transport behavior inside this owner.
    pub(crate) async fn open_connector_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
        resource_scope: PeerConnectionResourceScope,
    ) -> Result<(WebRtcConnectorWorker, WebRtcConnectorEventReceiver)> {
        let resource_owner = self
            .connector_resource_scope
            .clone()
            .ok_or(Error::ConnectorPolicyRequired)?;
        let transport_observation = observe_inexact_item(
            &resource_scope,
            PreAuthResourceFamily::TransportObject,
            1,
            0,
        );
        let mut config = build_rtc_configuration(stun, turn);
        config.ice_transport_policy = self.ice_transport_policy;
        let (permit, attempt_lifetime, claim) =
            admit_single_connector_candidate(self.runtime.clone(), resource_owner.clone());
        let candidate = permit.reserve_connector_candidate(claim).ok_or_else(|| {
            Error::Transport("connector candidate reservation refused".to_string())
        })?;
        let liveness = candidate.liveness();
        let transport = self.clone();
        let construction_scope = resource_scope.clone();
        let realtime_delivery = Arc::new(AtomicBool::new(false));
        let construction_realtime_delivery = Arc::clone(&realtime_delivery);
        let candidate_promoted = Arc::new(AtomicBool::new(false));
        let construction_candidate_promoted = Arc::clone(&candidate_promoted);
        let construction_liveness = liveness.clone();
        let result_liveness = liveness.clone();
        let incarnation = Arc::new(WebRtcConnectorIncarnation::new());
        let construction_incarnation = Arc::clone(&incarnation);
        let ownership = ConnectorOwnership::admitted(
            candidate,
            Arc::clone(&realtime_delivery),
            Arc::clone(&candidate_promoted),
            Arc::clone(&incarnation),
        );
        let close_owner = ConnectorCloseOwner::new(ownership.clone(), resource_owner.clone());
        let mut outer_cleanup = StartConnectorCleanupOnDrop::new(Arc::clone(&close_owner));
        let construction_close_owner = Arc::clone(&close_owner);
        let (construction_tx, construction_rx) = oneshot::channel();
        let construction_task = AbortConstructionOnDrop(tokio::spawn(async move {
            let result = transport
                .open_peer_with_config_observed(
                    role,
                    config,
                    PeerOpenOwnership {
                        resource_scope: Some(construction_scope),
                        realtime_delivery: construction_realtime_delivery,
                        attempt_liveness: Some(construction_liveness),
                        candidate_promoted: construction_candidate_promoted,
                        callback_gate: construction_incarnation,
                        callback_policy: resource_owner.callbacks(),
                        close_owner: Some(Arc::clone(&construction_close_owner)),
                    },
                )
                .await;
            match result {
                Ok((session, events)) if result_liveness.is_active() => {
                    let _ = construction_tx.send(Ok(ConstructedConnectorResult::new(
                        session,
                        events,
                        construction_close_owner,
                    )));
                }
                Ok((session, events)) => {
                    drop(events);
                    drop(session);
                    construction_close_owner.start();
                    let _ = construction_tx.send(Err(Error::Transport(
                        "connector attempt retired during construction".to_string(),
                    )));
                }
                Err(error) => {
                    let _ = construction_tx.send(Err(error));
                }
            }
        }));
        let constructed = construction_rx
            .await
            .map_err(|_| Error::Transport("connector construction owner stopped".to_string()))??;
        drop(construction_task);
        #[cfg(test)]
        if let Some(hook) = self.construction_hook.as_ref() {
            hook.pause_after_result_delivery(constructed.peer_connection())
                .await;
        }
        let (session, events, constructed_close_owner) = constructed.into_parts();
        if !Arc::ptr_eq(&constructed_close_owner, &close_owner) {
            close_owner.start();
            constructed_close_owner.start();
            return Err(Error::Transport(
                "connector construction returned a different close owner".to_string(),
            ));
        }
        let admitted = WebRtcConnectorWorker::admitted(
            session,
            events,
            AdmittedConnectorOwnership {
                ownership,
                attempt_lifetime,
                attempt_liveness: liveness,
                close_owner,
                resource_scope,
                transport_observation,
            },
        );
        if admitted.is_ok() {
            outer_cleanup.disarm();
        }
        admitted
    }

    /// Lower-level entry point that takes an explicit
    /// `RTCConfiguration`. Tests can use this to short-circuit
    /// the user-config path.
    #[cfg(any(test, feature = "transport-lab"))]
    pub async fn open_peer_with_config(
        &self,
        role: Role,
        config: RTCConfiguration,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let one = std::num::NonZeroUsize::new(1)
            .ok_or_else(|| Error::Transport("invalid lab callback capacity".to_string()))?;
        self.open_peer_with_config_observed(
            role,
            config,
            PeerOpenOwnership {
                resource_scope: None,
                realtime_delivery: Arc::new(AtomicBool::new(true)),
                attempt_liveness: None,
                candidate_promoted: Arc::new(AtomicBool::new(true)),
                callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
                callback_policy: ConnectorCallbackPolicy::unrestricted_lab(one),
                close_owner: None,
            },
        )
        .await
    }

    async fn open_peer_with_config_observed(
        &self,
        role: Role,
        config: RTCConfiguration,
        ownership: PeerOpenOwnership,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let PeerOpenOwnership {
            resource_scope,
            realtime_delivery,
            attempt_liveness,
            candidate_promoted,
            callback_gate,
            callback_policy,
            close_owner,
        } = ownership;
        let pc = self
            .api
            .new_peer_connection(config)
            .await
            .map_err(|e| Error::Transport(format!("new_peer_connection: {e}")))?;
        let pc = Arc::new(pc);
        let attached_close_owner = match close_owner {
            Some(owner)
                if {
                    #[cfg(test)]
                    if self
                        .construction_hook
                        .as_ref()
                        .is_some_and(|hook| hook.inject_native_close_error())
                    {
                        owner.attach_native_port(Arc::new(WebRtcNativeCloseErrorPort {
                            peer: Arc::clone(&pc),
                        }))
                    } else {
                        owner.attach_native(Arc::clone(&pc))
                    }
                    #[cfg(not(test))]
                    {
                        owner.attach_native(Arc::clone(&pc))
                    }
                } =>
            {
                Some(owner)
            }
            Some(owner) => {
                let mut rejected =
                    PeerConstructionGuard::new(Arc::clone(&pc), Arc::clone(&callback_gate), None);
                rejected.close().await;
                owner.start();
                return Err(Error::Transport(
                    "native peer installation into close owner was refused".to_string(),
                ));
            }
            None => None,
        };
        let mut construction = PeerConstructionGuard::new(
            Arc::clone(&pc),
            Arc::clone(&callback_gate),
            attached_close_owner,
        );
        let result = async {
            #[cfg(test)]
            if let Some(hook) = self.construction_hook.as_ref() {
                hook.pause_after_native_allocation(&pc).await;
            }

            let mailboxes = callback_policy.mailboxes();
            let (control_tx, control_rx) = mpsc::channel(mailboxes.control().get());
            let (endpoint_data_tx, endpoint_data_rx) =
                mpsc::channel(mailboxes.endpoint_data().get());
            let realtime_flows = RealtimeFlowRegistry::new(callback_policy);
            let event_sink = ConnectorEventSink {
                events: ConnectorEventMailboxes {
                    control: control_tx,
                    endpoint_data: endpoint_data_tx,
                },
                realtime_flows: Arc::clone(&realtime_flows),
                resource_scope: resource_scope.clone(),
                realtime_delivery,
                attempt_liveness,
                candidate_promoted,
                callback_gate: Arc::clone(&callback_gate),
                callback_policy,
                data_channel_fence: Arc::new(DataChannelCallbackFence::default()),
            };
            let data_channel = Arc::new(Mutex::new(None::<Arc<RTCDataChannel>>));

            register_callbacks(&pc, &event_sink, &data_channel, resource_scope.clone());

            // Media lanes are lifecycle-managed: only lane 0 exists at
            // setup (the original single lane, so pre-lifecycle peers
            // negotiate exactly what they always did), and lanes 1+ are
            // added on demand — an explicit open, or the first write to a
            // lane that doesn't exist yet — with an in-place renegotiation
            // carrying the new m-line. Slots are pre-sized to the device
            // ceiling so a lane index is stable for the session's life.
            let mut video_tracks: Vec<Option<LaneSlot>> = vec![None; self.media_lanes];
            let mut audio_tracks: Vec<Option<LaneSlot>> = vec![None; self.media_lanes];
            let mut outbound_realtime_flows = std::collections::BTreeMap::new();
            if realtime_flows.is_enabled() {
                for lane in 0..PRE_PROVISIONED_LANES.min(self.media_lanes) {
                    for kind in [LaneKind::Video, LaneKind::Audio] {
                        let key = (kind == LaneKind::Video, lane as u8);
                        let flow = realtime_flows.open_outbound_flow().ok_or_else(|| {
                            Error::Transport(
                                "enabled real-time policy cannot own every pre-provisioned compatibility flow"
                                    .to_string(),
                            )
                        })?;
                        outbound_realtime_flows.insert(key, flow);
                        let track = make_media_track(kind, lane as u8);
                        attach_track(&pc, &track, resource_scope.as_ref()).await?;
                        match kind {
                            LaneKind::Video => video_tracks[lane] = Some(LaneSlot::Open(track)),
                            LaneKind::Audio => audio_tracks[lane] = Some(LaneSlot::Open(track)),
                        }
                    }
                }
            }

            // Offerer creates the data channel synchronously so the
            // resulting SDP includes it. Answerer waits for the
            // `on_data_channel` callback that fires when the peer's
            // offer is applied.
            if role == Role::Offerer {
                let dc = pc
                    .create_data_channel(
                        APP_DATA_CHANNEL_LABEL,
                        Some(RTCDataChannelInit {
                            ordered: Some(true),
                            ..Default::default()
                        }),
                    )
                    .await
                    .map_err(|e| Error::Transport(format!("create_data_channel: {e}")))?;
                install_data_channel_handlers(
                    dc.clone(),
                    event_sink.clone(),
                    resource_scope.as_ref(),
                );
                *data_channel.lock().await = Some(dc);
            }

            let session = PeerSession {
                pc,
                data_channel,
                video_tracks: std::sync::Mutex::new(video_tracks),
                audio_tracks: std::sync::Mutex::new(audio_tracks),
                max_lanes: self.media_lanes,
                events_tx: event_sink,
                outbound_realtime_flows: SyncMutex::new(outbound_realtime_flows),
                lane_operations: Mutex::new(()),
                #[cfg(test)]
                fail_next_track_attach: AtomicBool::new(false),
                callback_gate,
                role,
                resource_scope,
            };
            Ok((
                session,
                TransportEventReceiver {
                    control: control_rx,
                    endpoint_data: endpoint_data_rx,
                    realtime_flows,
                    scheduler: ConnectorCallbackScheduler::new(callback_policy.service_weights()),
                },
            ))
        }
        .await;

        match result {
            Ok(result) => {
                construction.disarm();
                Ok(result)
            }
            Err(error) => {
                construction.close().await;
                Err(error)
            }
        }
    }
}

/// Closes a native peer connection when construction errors or its owned task
/// is cancelled after the dependency returned the object but before the
/// complete `PeerSession` can be handed to its connector owner.
struct PeerConstructionGuard {
    pc: Option<Arc<RTCPeerConnection>>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
}

impl PeerConstructionGuard {
    fn new(
        pc: Arc<RTCPeerConnection>,
        callback_gate: Arc<WebRtcConnectorIncarnation>,
        close_owner: Option<Arc<ConnectorCloseOwner>>,
    ) -> Self {
        Self {
            pc: Some(pc),
            callback_gate,
            close_owner,
        }
    }

    fn disarm(&mut self) {
        self.pc = None;
        self.close_owner = None;
    }

    async fn close(&mut self) {
        if let Some(owner) = self.close_owner.as_ref() {
            self.pc = None;
            let _ = owner.wait().await;
            return;
        }
        let Some(pc) = self.pc.take() else {
            return;
        };
        self.callback_gate.retire();
        let _ = pc.close().await;
    }
}

impl Drop for PeerConstructionGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.close_owner.as_ref() {
            self.pc = None;
            owner.start();
            return;
        }
        let Some(pc) = self.pc.take() else {
            return;
        };
        self.callback_gate.retire();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                let _ = pc.close().await;
            });
            return;
        }
        let _ = std::thread::Builder::new()
            .name("myownmesh-webrtc-construction-close".to_string())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    return;
                };
                runtime.block_on(async move {
                    let _ = pc.close().await;
                });
            });
    }
}

fn register_callbacks(
    pc: &Arc<RTCPeerConnection>,
    events_tx: &ConnectorEventSink,
    data_channel: &Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    resource_scope: Option<PeerConnectionResourceScope>,
) {
    let remote_tracks = Arc::new(SyncMutex::new(
        std::collections::HashSet::<(bool, u8)>::new(),
    ));
    // Local ICE candidate gathered — ship via signaling.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_ice_candidate(Box::new(move |cand| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                let msg = match cand {
                    Some(c) => match c.to_json() {
                        Ok(init) => Some(LocalIceCandidate {
                            candidate: init.candidate,
                            sdp_mid: init.sdp_mid,
                            sdp_mline_index: init.sdp_mline_index,
                            username_fragment: init.username_fragment,
                        }),
                        Err(e) => {
                            warn!("ice_candidate to_json: {e}");
                            return;
                        }
                    },
                    None => None,
                };
                tx.emit(TransportEvent::LocalIceCandidate(msg)).await;
            })
        }));
    }

    // ICE connection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_ice_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                tx.emit(TransportEvent::IceConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // PeerConnection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                tx.emit(TransportEvent::PeerConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // Answerer side: data channel arrives via callback.
    {
        let tx = events_tx.clone();
        let dc_slot = data_channel.clone();
        let handler_scope = resource_scope.clone();
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_data_channel(Box::new(move |dc| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            let dc_slot = dc_slot.clone();
            let handler_scope = handler_scope.clone();
            Box::pin(async move {
                if dc.label() != APP_DATA_CHANNEL_LABEL {
                    trace!(label = dc.label(), "ignoring non-app data channel");
                    let _ = dc.close().await;
                    return;
                }
                {
                    let mut slot = dc_slot.lock().await;
                    if slot.is_some() {
                        drop(slot);
                        let _ = dc.close().await;
                        return;
                    }
                    *slot = Some(dc.clone());
                }
                install_data_channel_handlers(dc.clone(), tx, handler_scope.as_ref());
            })
        }));
    }

    // A peer track lane went live — pump its RTP until the track
    // (i.e. the connection) ends: video into assembled access units,
    // audio straight through (one Opus frame per packet).
    {
        let tx = events_tx.clone();
        let task_scope = resource_scope.clone();
        let remote_tracks = Arc::clone(&remote_tracks);
        let callback_observation = observe_inexact_item_if(
            resource_scope.as_ref(),
            PreAuthResourceFamily::Callback,
            1,
            0,
        );
        pc.on_track(Box::new(move |track, _receiver, transceiver| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            let remote_tracks = Arc::clone(&remote_tracks);
            let flow = tx.open_inbound_realtime_flow();
            let task_observation =
                observe_inexact_item_if(task_scope.as_ref(), PreAuthResourceFamily::Task, 1, 1);
            Box::pin(async move {
                let Some(flow) = flow else {
                    let _ = transceiver.stop().await;
                    return;
                };
                let lane = lane_of_track_id(&track.id());
                let key = match track.kind() {
                    RTPCodecType::Video => Some((true, lane)),
                    RTPCodecType::Audio => Some((false, lane)),
                    _ => None,
                };
                let Some(key) = key else {
                    let _ = transceiver.stop().await;
                    return;
                };
                if !remote_tracks.lock().insert(key) {
                    let _ = transceiver.stop().await;
                    return;
                }
                match track.kind() {
                    RTPCodecType::Video => {
                        tokio::spawn(pump_video_track(
                            track,
                            tx,
                            task_observation,
                            remote_tracks,
                            key,
                            flow,
                        ));
                    }
                    RTPCodecType::Audio => {
                        tokio::spawn(pump_audio_track(
                            track,
                            tx,
                            task_observation,
                            remote_tracks,
                            key,
                            flow,
                        ));
                    }
                    _ => unreachable!("track kind was classified above"),
                }
            })
        }));
    }
}

fn install_data_channel_handlers(
    dc: Arc<RTCDataChannel>,
    tx: ConnectorEventSink,
    resource_scope: Option<&PeerConnectionResourceScope>,
) {
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_open(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                tx.emit_data_channel(TransportEvent::DataChannelOpen).await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_close(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                tx.emit_data_channel(TransportEvent::Message(msg.data))
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation =
            observe_inexact_item_if(resource_scope, PreAuthResourceFamily::Callback, 1, 0);
        dc.on_error(Box::new(move |err| {
            let _keep_callback_observation = &callback_observation;
            let tx = tx.clone();
            Box::pin(async move {
                warn!("data channel error: {err}");
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
}

/// True if `ip` is a private / local-scope address — RFC1918 v4
/// (`10/8`, `172.16/12`, `192.168/16`), v4 link-local (`169.254/16`),
/// v6 unique-local (`fc00::/7`), or v6 link-local (`fe80::/10`).
/// Carrier-grade NAT space (`100.64/10`) is deliberately excluded: it's
/// reachable only via the carrier, not a LAN. Used to classify a
/// connected ICE pair as a direct local link from its endpoint address
/// rather than trusting the ICE candidate type alone — a peer-reflexive
/// candidate on a `192.168.x.x` address is still the LAN.
fn is_private_lan_ip(ip: &str) -> bool {
    use std::net::IpAddr;
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => v4.is_private() || v4.is_link_local(),
        Ok(IpAddr::V6(v6)) => {
            let seg = v6.segments();
            // fc00::/7 (unique-local) or fe80::/10 (link-local).
            (seg[0] & 0xfe00) == 0xfc00 || (seg[0] & 0xffc0) == 0xfe80
        }
        Err(_) => false,
    }
}

/// True for v4 link-local (`169.254/16`) or v6 link-local (`fe80::/10`)
/// addresses. These can't be bound for ICE gathering without a
/// scope/zone id, so the agent's bind fails on every one; we filter them
/// out of gathering up front (see the `set_ip_filter` call in
/// [`Transport::new`]) instead of letting each fail and log. Unlike
/// [`is_private_lan_ip`], unique-local (`fc00::/7`) is deliberately *not*
/// matched — ULAs are bindable, routable on the local network, and make
/// perfectly good host candidates.
pub(crate) fn is_link_local_ip(ip: &std::net::IpAddr) -> bool {
    use std::net::IpAddr;
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        // fe80::/10 — the first 10 bits are 1111 1110 10.
        IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) == 0xfe80,
    }
}

/// Render an ICE candidate as a compact `kind net addr:port` string
/// for the connectivity-check snapshot — e.g. `host udp4
/// 192.168.1.50:54321`. Keeps the log line readable while still
/// showing the exact address so the user can spot a wrong subnet, a
/// link-local IPv6 that won't route, or a srflx that resolved to an
/// unexpected public IP.
fn fmt_candidate(
    t: webrtc::ice::candidate::CandidateType,
    net: webrtc::ice::network_type::NetworkType,
    ip: &str,
    port: u16,
) -> String {
    use webrtc::ice::candidate::CandidateType;
    let kind = match t {
        CandidateType::Host => "host",
        CandidateType::ServerReflexive => "srflx",
        CandidateType::PeerReflexive => "prflx",
        CandidateType::Relay => "relay",
        CandidateType::Unspecified => "?",
    };
    format!("{kind} {net} {ip}:{port}")
}

/// Lower-case wire name for a candidate-pair check state, matching the
/// strings [`super::diag::IceCheckSnapshot`] compares against.
fn pair_state_str(s: webrtc::ice::candidate::CandidatePairState) -> String {
    use webrtc::ice::candidate::CandidatePairState as S;
    match s {
        S::Waiting => "waiting",
        S::InProgress => "in-progress",
        S::Failed => "failed",
        S::Succeeded => "succeeded",
        S::Unspecified => "unspecified",
    }
    .to_string()
}

/// One peer's WebRTC session — peer connection, application data
/// channel, the provisioned pool of video + audio track lanes (see
/// [`MEDIA_LANES`]), and transport-level event sink.
/// Extract the DTLS fingerprint (`a=fingerprint:<hash> <value>`) from an SDP
/// blob, lowercased for stable comparison. Returns the first one found —
/// session-level or the first media section; for our single-bundle sessions
/// they're identical. Used to tell a peer's in-place ICE restart (same
/// fingerprint) from a full rebuild (new fingerprint) on the answerer side.
pub(crate) fn sdp_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("a=fingerprint:"))
        .map(|v| v.trim().to_ascii_lowercase())
}

pub struct PeerSession {
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<Mutex<Option<Arc<RTCDataChannel>>>>,
    /// Lifecycle-managed lane slots, index = lane id. `None` = lane
    /// never opened (or fully reaped); see [`LaneSlot`] for the
    /// open/draining split. Slot count is fixed at
    /// [`PeerSession::max_lanes`] so ids stay stable; a std Mutex
    /// because holders only clone the Arc out (never held across an
    /// await).
    video_tracks: std::sync::Mutex<Vec<Option<LaneSlot>>>,
    audio_tracks: std::sync::Mutex<Vec<Option<LaneSlot>>>,
    /// Device lane ceiling (see [`resolve_media_lanes`]).
    max_lanes: usize,
    events_tx: ConnectorEventSink,
    /// Codec-neutral flow owners used by the WebRTC compatibility adapter.
    /// The `(is_video_adapter, lane)` key never leaves this adapter.
    outbound_realtime_flows: SyncMutex<std::collections::BTreeMap<(bool, u8), RealtimeFlowPort>>,
    lane_operations: Mutex<()>,
    #[cfg(test)]
    fail_next_track_attach: AtomicBool,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    role: Role,
    resource_scope: Option<PeerConnectionResourceScope>,
}

impl PeerSession {
    pub fn role(&self) -> Role {
        self.role
    }

    fn realtime_enabled(&self) -> bool {
        self.events_tx.realtime_flows.is_enabled()
    }

    /// True once the data channel is established on this side
    /// (open and `on_open` fired).
    pub async fn has_data_channel(&self) -> bool {
        self.data_channel.lock().await.is_some()
    }

    /// Build an offer SDP. Offerer-only (answerer never calls this).
    ///
    /// The stage logs exist because this pair is the engine's
    /// inline-on-the-driver excursion into webrtc-rs: it wedges on the NanoKVM
    /// with nothing inside logging, so knowing *which* stage stopped is what
    /// turns an invisible freeze into a diagnosis.
    ///
    /// They were INFO on the premise that they "fire once per connect attempt —
    /// negligible in a healthy log". That premise is what broke: an unhealthy
    /// mesh renegotiates constantly, and at ~12 lines per peer per attempt
    /// across 20+ peers this became the single largest contributor to a
    /// multi-gigabyte syslog. Precisely when the daemon is sickest, its logs
    /// grow fastest — and the disk that fills takes the diagnosis with it.
    ///
    /// So they are DEBUG now, and the field workflow is unchanged in substance:
    /// `MYOWNMESH_LOG_EXTRA=myownmesh_core=debug` (what `just serve-trace`
    /// already sets) brings every one of them back verbatim.
    pub async fn create_offer(&self) -> Result<RTCSessionDescription> {
        debug!("create_offer: building SDP (pc.create_offer)");
        let offer = self
            .pc
            .create_offer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_offer: {e}")))?;
        debug!(
            sdp_bytes = offer.sdp.len(),
            "create_offer: applying local description (starts ICE gathering)"
        );
        self.pc
            .set_local_description(offer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (offer): {e}")))?;
        debug!("create_offer: local description applied");
        Ok(offer)
    }

    /// Apply the remote SDP. Both sides call this — offerer with
    /// the answer they got back, answerer with the offer they
    /// received first. Stage-logged like create_offer: the answer path runs
    /// the same inline-on-the-driver webrtc-rs machinery (and processes the
    /// REMOTE side's media sections regardless of our own lane count), so it
    /// is equally capable of freezing the engine invisibly.
    pub async fn set_remote_description(&self, desc: RTCSessionDescription) -> Result<()> {
        debug!(
            sdp_type = %desc.sdp_type,
            sdp_bytes = desc.sdp.len(),
            "set_remote_description: applying remote SDP"
        );
        self.pc
            .set_remote_description(desc)
            .await
            .map_err(|e| Error::Transport(format!("set_remote_description: {e}")))
    }

    /// DTLS fingerprint of the currently-applied remote description, if any.
    /// A *restart* offer keeps this fingerprint (same peer connection, new ICE
    /// ufrag); a *rebuild* offer carries a new one (the peer tore its PC down
    /// and built fresh). The answerer compares the incoming offer's fingerprint
    /// to this to decide between renegotiating in place and dropping for a
    /// clean rebuild — applying a rebuild offer onto the stale PC deadlocks
    /// (it lands on a corpse and no candidates ever flow). `None` before any
    /// remote description is set.
    pub async fn remote_fingerprint(&self) -> Option<String> {
        sdp_fingerprint(&self.pc.remote_description().await?.sdp)
    }

    /// DTLS fingerprint of our *local* description — the fingerprint of the
    /// certificate THIS side presents on the DTLS channel. WebRTC verifies a
    /// peer's presented certificate against the `a=fingerprint:` in the SDP it
    /// received, so on an un-intercepted channel a peer's
    /// [`Self::remote_fingerprint`] equals its counterpart's
    /// `local_fingerprint`. The auth handshake folds this value into the signed
    /// ed25519 payload (see [`crate::signing::handshake_payload`]) so a
    /// signaling-path man-in-the-middle — which must present its own
    /// certificate on each leg it terminates — is detected: the victim's
    /// observed remote fingerprint no longer matches the one the real peer
    /// signed. `None` before the local description is set.
    pub async fn local_fingerprint(&self) -> Option<String> {
        sdp_fingerprint(&self.pc.local_description().await?.sdp)
    }

    /// True when the peer connection is awaiting a remote Answer — i.e. we
    /// have a local offer outstanding (`have-local-offer`). An Answer that
    /// arrives in any other state is stale (a duplicate from relay redundancy,
    /// or the answer to an offer we've since superseded); applying it throws
    /// webrtc-rs's "invalid proposed signaling state transition from stable"
    /// error and wedges the negotiation, so the engine drops it instead.
    pub fn awaiting_answer(&self) -> bool {
        self.pc.signaling_state() == RTCSignalingState::HaveLocalOffer
    }

    /// Build an answer SDP. Answerer-only; call after
    /// [`Self::set_remote_description`]. Stage-logged like create_offer —
    /// same inline-on-the-driver machinery, same invisible-freeze potential.
    pub async fn create_answer(&self) -> Result<RTCSessionDescription> {
        debug!("create_answer: building SDP (pc.create_answer)");
        let answer = self
            .pc
            .create_answer(None)
            .await
            .map_err(|e| Error::Transport(format!("create_answer: {e}")))?;
        debug!(
            sdp_bytes = answer.sdp.len(),
            "create_answer: applying local description (starts ICE gathering)"
        );
        self.pc
            .set_local_description(answer.clone())
            .await
            .map_err(|e| Error::Transport(format!("set_local_description (answer): {e}")))?;
        debug!("create_answer: local description applied");
        Ok(answer)
    }

    /// Add an ICE candidate the peer sent us. The peer's nominal
    /// `null` (gathering complete) is also acceptable.
    ///
    /// The raw port is private to `WebRtcConnectorWorker`. External and engine
    /// callers must use the worker so queue, lifetime, and observation owners
    /// cannot be bypassed.
    async fn add_ice_candidate(&self, cand: LocalIceCandidate) -> Result<()> {
        self.pc
            .add_ice_candidate(cand.into_init())
            .await
            .map_err(|e| Error::Transport(format!("add_ice_candidate: {e}")))
    }

    /// Send bytes on the data channel. Returns the number of bytes
    /// queued for transmission (matches webrtc-rs's contract).
    pub async fn send(&self, payload: Bytes) -> Result<usize> {
        let dc = self.data_channel.lock().await;
        let dc = dc
            .as_ref()
            .ok_or_else(|| Error::Transport("data channel not open".into()))?;
        dc.send(&payload)
            .await
            .map_err(|e| Error::Transport(format!("data channel send: {e}")))
    }

    /// Write one encoded H.264 access unit (Annex-B) onto `lane` of this
    /// peer's video pool. `duration` paces the RTP timestamp advance
    /// (1/fps). Before the lane's negotiation completes, webrtc-rs treats
    /// the write as a no-op (the track has no bound sender yet) — callers
    /// can simply start writing once the peer is up. A lane past the pool
    /// (or one a pre-pool peer never negotiated) errors rather than writing
    /// to the wrong stream.
    pub async fn send_video(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Video, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("video write_sample (lane {lane}): {e}")))
    }

    /// Write one encoded Opus frame onto `lane` of this peer's audio pool.
    /// `duration` paces the RTP timestamp advance (the frame length —
    /// 20 ms for the canonical Opus frame). Same pre-negotiation no-op and
    /// out-of-range semantics as [`Self::send_video`].
    pub async fn send_audio(
        &self,
        lane: u8,
        data: Bytes,
        duration: std::time::Duration,
    ) -> Result<()> {
        let (track, flow) = self.ensure_owned_lane(LaneKind::Audio, lane).await?;
        let _reservation = flow.reserve_output(data.len()).ok_or_else(|| {
            Error::Transport(
                "outbound real-time unit was refused by its owner-selected byte envelope"
                    .to_string(),
            )
        })?;
        track
            .write_sample(&Sample {
                data,
                duration,
                ..Default::default()
            })
            .await
            .map_err(|e| Error::Transport(format!("audio write_sample (lane {lane}): {e}")))
    }

    fn acquire_outbound_realtime_flow(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(RealtimeFlowPort, bool)> {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if let Some(flow) = flows.get(&key) {
            return Ok((flow.clone(), false));
        }
        let flow = self
            .events_tx
            .open_outbound_realtime_flow()
            .ok_or_else(|| {
                Error::Transport(
                    "outbound real-time flow was refused by its owner-selected flow envelope"
                        .to_string(),
                )
            })?;
        flows.insert(key, flow.clone());
        Ok((flow, true))
    }

    fn rollback_outbound_realtime_flow(&self, kind: LaneKind, lane: u8, flow: &RealtimeFlowPort) {
        let key = (kind == LaneKind::Video, lane);
        let mut flows = self.outbound_realtime_flows.lock();
        if flows
            .get(&key)
            .is_some_and(|owned| Arc::ptr_eq(&owned.lifetime, &flow.lifetime))
        {
            flows.remove(&key);
        }
    }

    fn lane_has_track(&self, kind: LaneKind, lane: u8) -> bool {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .get(lane as usize)
            .is_some_and(Option::is_some)
    }

    async fn ensure_owned_lane(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<(Arc<TrackLocalStaticSample>, RealtimeFlowPort)> {
        let _operation = self.lane_operations.lock().await;
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        match self.ensure_lane_after_owner(kind, lane).await {
            Ok(track) => Ok((track, flow)),
            Err(error) => {
                if newly_owned && !self.lane_has_track(kind, lane) {
                    self.rollback_outbound_realtime_flow(kind, lane, &flow);
                }
                Err(error)
            }
        }
    }

    fn pool(&self, kind: LaneKind) -> &std::sync::Mutex<Vec<Option<LaneSlot>>> {
        match kind {
            LaneKind::Video => &self.video_tracks,
            LaneKind::Audio => &self.audio_tracks,
        }
    }

    /// The lane's track, opening it on demand: the first write to a
    /// lane that doesn't exist yet creates the track, attaches it, and
    /// flags a renegotiation — writes are no-ops until the new m-line
    /// negotiates, exactly the semantics callers already tolerate at
    /// stream start. A *draining* lane revives in place: the track
    /// never left the SDP, so the write flows immediately and nothing
    /// is renegotiated — this is the settings stop→start fast path. A
    /// lane at or past the device ceiling errors.
    async fn ensure_lane_after_owner(
        &self,
        kind: LaneKind,
        lane: u8,
    ) -> Result<Arc<TrackLocalStaticSample>> {
        if lane as usize >= self.max_lanes {
            let k = if kind == LaneKind::Video {
                "video"
            } else {
                "audio"
            };
            return Err(Error::Transport(format!("no {k} lane {lane}")));
        }
        {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                Some(LaneSlot::Open(track)) => return Ok(track.clone()),
                Some(LaneSlot::Draining { track, .. }) => {
                    let track = track.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    return Ok(track);
                }
                None => {}
            }
        }
        let track = make_media_track(kind, lane);
        #[cfg(test)]
        if self.fail_next_track_attach.swap(false, Ordering::AcqRel) {
            return Err(Error::Transport(
                "injected native track attachment failure".to_string(),
            ));
        }
        attach_track(&self.pc, &track, self.resource_scope.as_ref()).await?;
        // First writer wins if two racers opened the same lane; the
        // loser's track was attached too, but the slot's track is the
        // one everyone writes — the duplicate is harmless and gone on
        // the next renegotiation sweep. (In practice lane opens are
        // serialized by the engine driver.)
        let stored = {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            match &pool[lane as usize] {
                None => {
                    pool[lane as usize] = Some(LaneSlot::Open(track.clone()));
                    track
                }
                Some(LaneSlot::Open(winner)) => winner.clone(),
                Some(LaneSlot::Draining { track: winner, .. }) => {
                    let winner = winner.clone();
                    pool[lane as usize] = Some(LaneSlot::Open(winner.clone()));
                    winner
                }
            }
        };
        if !self
            .events_tx
            .emit(TransportEvent::RenegotiationNeeded)
            .await
        {
            return Err(Error::Transport(
                "connector event queue overloaded during renegotiation".to_string(),
            ));
        }
        Ok(stored)
    }

    /// Open a lane of `kind`, returning its id. The explicit twin of
    /// the write-time auto-open, for callers that want to reserve a
    /// lane before producing media. Prefers reviving a draining lane
    /// (its track is still negotiated — the open costs zero SDP work)
    /// over claiming a fresh slot (one in-place renegotiation); errors
    /// only when every slot is genuinely open.
    pub async fn open_media_lane(&self, kind: LaneKind) -> Result<u8> {
        let _operation = self.lane_operations.lock().await;
        let target = {
            let pool = self.pool(kind).lock().expect("lane pool");
            pool.iter()
                .position(|slot| matches!(slot, Some(LaneSlot::Draining { .. })))
                .or_else(|| pool.iter().position(|slot| slot.is_none()))
        };
        let Some(lane) = target else {
            return Err(Error::Transport(format!(
                "all {} media lanes are open (device ceiling)",
                self.max_lanes
            )));
        };
        let lane = lane as u8;
        let (flow, newly_owned) = self.acquire_outbound_realtime_flow(kind, lane)?;
        if let Err(error) = self.ensure_lane_after_owner(kind, lane).await {
            if newly_owned && !self.lane_has_track(kind, lane) {
                self.rollback_outbound_realtime_flow(kind, lane, &flow);
            }
            return Err(error);
        }
        Ok(lane)
    }

    /// Close an open lane — as a **drain**: the slot is marked closed
    /// but the track stays attached through [`LANE_DRAIN_GRACE`], so a
    /// quick reopen (a settings change's stop→start, a stream restart)
    /// revives it with zero SDP work and the feed never freezes behind
    /// a renegotiation. Nothing is signaled here — a close is instant
    /// and free; only the reaper ([`Self::reap_drained_lanes`])
    /// finalizes teardowns, for drains that outlived the grace.
    /// Closing a lane that isn't open (or is already draining) is a
    /// no-op — idempotent by design, so teardown paths can't
    /// double-fault.
    pub async fn close_media_lane(&self, kind: LaneKind, lane: u8) -> Result<()> {
        let _operation = self.lane_operations.lock().await;
        if lane as usize >= self.max_lanes {
            return Ok(());
        }
        let mut pool = self.pool(kind).lock().expect("lane pool");
        if let Some(LaneSlot::Open(track)) = &pool[lane as usize] {
            pool[lane as usize] = Some(LaneSlot::Draining {
                track: track.clone(),
                since: Instant::now(),
            });
        }
        Ok(())
    }

    /// Whether any drained lane has outlived `grace` and owes the
    /// connection a teardown. Cheap sync scan — the engine's tick uses
    /// it to decide whether this peer needs a renegotiation pass at
    /// all.
    pub fn has_reapable_lanes(&self, grace: Duration) -> bool {
        let pinned = PRE_PROVISIONED_LANES.min(self.max_lanes);
        [LaneKind::Video, LaneKind::Audio].iter().any(|kind| {
            self.pool(*kind)
                .lock()
                .expect("lane pool")
                .iter()
                .enumerate()
                .any(|(idx, slot)| {
                    idx >= pinned
                        && matches!(slot, Some(LaneSlot::Draining { since, .. }) if since.elapsed() >= grace)
                })
        })
    }

    /// Finalize every drain that outlived `grace`: free the slots and
    /// remove their tracks from the connection, so the caller's next
    /// offer drops the m-lines' send side. Returns how many lanes were
    /// reaped. Slots free first, under the lock, then the webrtc-rs
    /// `remove_track` calls run outside it — a concurrent revive can't
    /// resurrect a slot the reaper already committed to tearing down.
    pub async fn reap_drained_lanes(&self, grace: Duration) -> usize {
        let _operation = self.lane_operations.lock().await;
        let pinned = PRE_PROVISIONED_LANES.min(self.max_lanes);
        let mut victims: Vec<(LaneKind, u8, Arc<TrackLocalStaticSample>)> = Vec::new();
        for kind in [LaneKind::Video, LaneKind::Audio] {
            let mut pool = self.pool(kind).lock().expect("lane pool");
            for (idx, slot) in pool.iter_mut().enumerate() {
                // The pre-provisioned lane is pinned: it drains silent but
                // never loses its track, so a re-open always hits the
                // zero-SDP free-revive path instead of a recycled-m-line
                // renegotiation (which doesn't reliably re-`ontrack` on the
                // viewer — the CEC console re-open hang). Only transient
                // lanes (1+) are reaped once past the grace.
                if idx < pinned {
                    continue;
                }
                let due = matches!(slot, Some(LaneSlot::Draining { since, .. }) if since.elapsed() >= grace);
                if due {
                    if let Some(LaneSlot::Draining { track, .. }) = slot.take() {
                        victims.push((kind, idx as u8, track));
                    }
                }
            }
        }
        if victims.is_empty() {
            return 0;
        }
        // A victim absent from `get_senders` is already detached. A failed
        // `remove_track` is the only case that must retain its flow claim.
        let mut failed_reaps = Vec::new();
        for sender in self.pc.get_senders().await {
            let victim = sender.track().await.and_then(|sender_track| {
                victims
                    .iter()
                    .find(|(_, _, track)| sender_track.id() == track.id())
                    .map(|(kind, lane, _)| (*kind, *lane))
            });
            if let Some((kind, lane)) = victim {
                if let Err(e) = self.pc.remove_track(&sender).await {
                    warn!("reap: remove_track failed: {e}");
                    failed_reaps.push((kind, lane));
                }
            }
        }
        let fully_reaped = victims
            .iter()
            .map(|(kind, lane, _)| (*kind, *lane))
            .filter(|victim| !failed_reaps.contains(victim))
            .collect::<Vec<_>>();
        let mut flows = self.outbound_realtime_flows.lock();
        for (kind, lane) in &fully_reaped {
            flows.remove(&(*kind == LaneKind::Video, *lane));
        }
        fully_reaped.len()
    }

    /// The peer connection's signaling state. The media-renegotiation
    /// pass gates its in-place offers on `Stable` so it never stacks
    /// an offer onto a negotiation that's still settling (glare).
    pub fn signaling_state(&self) -> RTCSignalingState {
        self.pc.signaling_state()
    }

    /// How many lanes of `kind` are currently occupied — surfaced in
    /// status so an operator can see media capacity in use. Draining
    /// lanes count: they still hold their m-line until reaped.
    pub fn open_lane_count(&self, kind: LaneKind) -> usize {
        self.pool(kind)
            .lock()
            .expect("lane pool")
            .iter()
            .filter(|slot| slot.is_some())
            .count()
    }

    /// Force ICE restart. Used by the engine's Tier 2.5 / Tier 3
    /// recovery path.
    pub async fn restart_ice(&self) -> Result<()> {
        self.pc
            .restart_ice()
            .await
            .map_err(|e| Error::Transport(format!("restart_ice: {e}")))
    }

    /// Read the peer connection's current ICE state. Useful for
    /// the ICE watchdog without subscribing to every transition.
    pub fn ice_connection_state(&self) -> RTCIceConnectionState {
        self.pc.ice_connection_state()
    }

    /// Read the overall connection state (DTLS + ICE composite).
    pub fn connection_state(&self) -> RTCPeerConnectionState {
        self.pc.connection_state()
    }

    /// Ask the underlying ICE agent which candidate pair it actually
    /// selected for sending packets. This is the authoritative
    /// answer to "is this a LAN link or going through STUN/TURN" —
    /// gathered candidate counts only tell us what was tried, not
    /// what's in use. Returns `None` until ICE has settled
    /// (Connected / Completed) and the agent has nominated a pair.
    ///
    /// Implementation note: webrtc-rs's `get_selected_candidate_pair`
    /// returns a struct with private fields and no accessors (as of
    /// 0.13), so we go through the stats API instead — the candidate-
    /// pair stats expose `nominated` plus ids that resolve to local /
    /// remote candidate stats with public `candidate_type` fields.
    pub async fn selected_candidate_pair(&self) -> Option<super::diag::SelectedCandidatePair> {
        use webrtc::ice::candidate::{CandidatePairState, CandidateType};
        use webrtc::stats::StatsReportType;
        let report = self.pc.get_stats().await;
        // Find the nominated pair. There can be several pair entries
        // (one per checklist combination); only the nominated one is
        // currently carrying packets.
        //
        // Fallback: webrtc-rs doesn't always flip `nominated=true` on
        // the controlling (Offerer) side — the field can stay false
        // even after ICE is solidly Connected and bytes are flowing.
        // When no pair is marked nominated, fall back to the
        // Succeeded pair with the most bytes_received (the one
        // actually carrying traffic); if multiple have zero bytes,
        // any Succeeded pair classifies the same way for our
        // purposes (LAN / STUN / TURN). Without this fallback the
        // Offerer side stays unclassified on a healthy LAN pair —
        // packets flow, GUI never paints the link type.
        let (local_id, remote_id) = {
            let nominated = report.reports.values().find_map(|r| match r {
                StatsReportType::CandidatePair(p) if p.nominated => {
                    Some((p.local_candidate_id.clone(), p.remote_candidate_id.clone()))
                }
                _ => None,
            });
            match nominated {
                Some(ids) => ids,
                None => report
                    .reports
                    .values()
                    .filter_map(|r| match r {
                        StatsReportType::CandidatePair(p)
                            if p.state == CandidatePairState::Succeeded =>
                        {
                            Some(p)
                        }
                        _ => None,
                    })
                    .max_by_key(|p| p.bytes_received)
                    .map(|p| (p.local_candidate_id.clone(), p.remote_candidate_id.clone()))?,
            }
        };
        // Classify from the candidate's actual address first, falling
        // back to the ICE type. A *working* pair whose endpoint is a
        // private/RFC1918 address is, by definition, a direct
        // local-network link: those ranges aren't routable across the
        // internet, so if packets are flowing the two devices share a
        // LAN. We report it as `Host` even when ICE labelled the
        // candidate `prflx` (peer-reflexive) — which happens routinely
        // when the remote's host candidate arrived a beat before its
        // SDP and was learned from a STUN binding rather than the
        // candidate list, the exact reason a genuinely-local peer was
        // mis-painted as "STUN / over the internet". `Relay` always
        // wins (a TURN relay is a relay even on a private address).
        fn classify(t: CandidateType, ip: &str) -> super::diag::IceCandidateKind {
            use super::diag::IceCandidateKind;
            match t {
                CandidateType::Relay => IceCandidateKind::Relay,
                _ if is_private_lan_ip(ip) => IceCandidateKind::Host,
                CandidateType::Host => IceCandidateKind::Host,
                CandidateType::ServerReflexive => IceCandidateKind::ServerReflexive,
                CandidateType::PeerReflexive => IceCandidateKind::PeerReflexive,
                CandidateType::Unspecified => IceCandidateKind::Unknown,
            }
        }
        let local = report.reports.values().find_map(|r| match r {
            StatsReportType::LocalCandidate(c) if c.id == local_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
            _ => None,
        })?;
        let remote = report.reports.values().find_map(|r| match r {
            StatsReportType::RemoteCandidate(c) if c.id == remote_id => {
                Some(classify(c.candidate_type, &c.ip))
            }
            _ => None,
        })?;
        Some(super::diag::SelectedCandidatePair { local, remote })
    }

    /// Capture a full connectivity-check snapshot from the ICE agent's
    /// stats. Where [`Self::selected_candidate_pair`] only reports the
    /// *winning* pair once ICE is Connected, this returns **every**
    /// candidate pair and its live STUN check counters at any point in
    /// the lifecycle — the data you need to answer "why is this peer
    /// stuck in Checking / why did it go Failed". The engine logs it on
    /// ICE failure and periodically while a peer is still checking.
    pub async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        use std::collections::HashMap;
        use webrtc::stats::StatsReportType;

        let report = self.pc.get_stats().await;

        // First pass: build candidate-id → "kind net addr:port" so the
        // pairs below can render real addresses instead of opaque ids,
        // and collect the flat local/remote candidate lists.
        let mut by_id: HashMap<String, String> = HashMap::new();
        let mut local_candidates = Vec::new();
        let mut remote_candidates = Vec::new();
        for r in report.reports.values() {
            match r {
                StatsReportType::LocalCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    local_candidates.push(s);
                }
                StatsReportType::RemoteCandidate(c) => {
                    let s = fmt_candidate(c.candidate_type, c.network_type, &c.ip, c.port);
                    by_id.insert(c.id.clone(), s.clone());
                    remote_candidates.push(s);
                }
                _ => {}
            }
        }

        // Second pass: the candidate pairs and their check counters.
        let mut pairs = Vec::new();
        for r in report.reports.values() {
            if let StatsReportType::CandidatePair(p) = r {
                let resolve = |id: &str| by_id.get(id).cloned().unwrap_or_else(|| id.to_string());
                pairs.push(super::diag::IcePairSnapshot {
                    local: resolve(&p.local_candidate_id),
                    remote: resolve(&p.remote_candidate_id),
                    state: pair_state_str(p.state),
                    nominated: p.nominated,
                });
            }
        }

        // Stable ordering so successive snapshots diff cleanly in the log
        // and a capped dump shows the pairs that matter: nominated first,
        // then succeeded, then everything else. (We can't rank by check
        // activity — webrtc-ice 0.13 never populates the per-pair STUN
        // counters, so they're all zero; see `diag::IcePairSnapshot`.)
        let rank = |p: &super::diag::IcePairSnapshot| -> u8 {
            match (p.nominated, p.state.as_str()) {
                (true, _) => 0,
                (_, "succeeded") => 1,
                (_, "in-progress") => 2,
                (_, "waiting") => 3,
                _ => 4,
            }
        };
        pairs.sort_by_key(rank);
        local_candidates.sort();
        remote_candidates.sort();
        super::diag::IceCheckSnapshot {
            local_candidates,
            remote_candidates,
            pairs,
        }
    }

    /// Close the connection. Idempotent — subsequent close calls
    /// The callback gate retires before the native close is awaited so a full
    /// callback queue cannot deadlock shutdown.
    pub async fn close(&self) -> Result<()> {
        debug!("closing peer connection");
        self.callback_gate.retire();
        self.pc
            .close()
            .await
            .map_err(|e| Error::Transport(format!("close: {e}")))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        ProcessResourceRoot, ResourceFamilyReport, PRE_AUTH_RESOURCE_FAMILY_COUNT,
    };
    use crate::runtime::attempt::{
        ConnectorRealtimeFlowCapacities, ConnectorRealtimeFlowPolicy,
        ConnectorRealtimeInboundLimits,
    };
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};

    fn test_resource_owner(
        max_active_candidates: usize,
        callback_capacity: usize,
        native_close_observation_limit: Duration,
    ) -> MeshConnectorResourceScope {
        let max_active_candidates = std::num::NonZeroUsize::new(max_active_candidates)
            .expect("fixture has a nonzero candidate bound");
        let callback_capacity = std::num::NonZeroUsize::new(callback_capacity)
            .expect("fixture has nonzero callback bounds");
        let callbacks = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(
                callback_capacity,
                callback_capacity,
            ),
            ConnectorCallbackServiceWeights::data_only(callback_capacity, callback_capacity),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("fixture callback policy is valid");
        let policy = crate::runtime::attempt::ConnectorResourcePolicy::new(
            max_active_candidates,
            callbacks,
            native_close_observation_limit,
        )
        .expect("fixture has a nonzero close observation limit");
        crate::runtime::attempt::ConnectorResourceOwnerPort::new(policy)
            .issue_mesh_scope(crate::runtime::attempt::MeshConnectorResourcePolicy::new(
                max_active_candidates,
            ))
            .expect("fixture process owner issues one explicit Mesh scope")
    }

    fn close_owner_fixture(
        owner: &MeshConnectorResourceScope,
    ) -> (Arc<ConnectorCloseOwner>, AttemptLifetime) {
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("fixture owner admits one candidate");
        let ownership = admitted_ownership(candidate);
        (ConnectorCloseOwner::new(ownership, owner.clone()), lifetime)
    }

    fn connected_claim_fixture(
        owner: &MeshConnectorResourceScope,
    ) -> (
        crate::connector::ConnectedChannelCapability,
        AttemptLifetime,
    ) {
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("fixture owner admits connected candidate");
        let connected = crate::connector::mark_connected(candidate)
            .expect("fixture attempt remains live through promotion");
        (connected, lifetime)
    }

    #[derive(Clone, Copy)]
    enum TestNativeCloseResult {
        Success,
        Error,
        Pending,
    }

    struct TestNativeClosePort {
        result: TestNativeCloseResult,
        calls: Arc<AtomicUsize>,
    }

    impl NativeConnectorClosePort for TestNativeClosePort {
        fn close(&self) -> NativeCloseFuture<'_> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                match self.result {
                    TestNativeCloseResult::Success => Ok(()),
                    TestNativeCloseResult::Error => Err(Error::Transport(
                        "injected native close failure".to_string(),
                    )),
                    TestNativeCloseResult::Pending => std::future::pending().await,
                }
            })
        }
    }

    fn candidate_report(
        reports: &[ResourceFamilyReport<PreAuthResourceFamily>; PRE_AUTH_RESOURCE_FAMILY_COUNT],
    ) -> ResourceFamilyReport<PreAuthResourceFamily> {
        *reports
            .iter()
            .find(|report| report.family == PreAuthResourceFamily::CandidateObject)
            .expect("candidate family is present")
    }

    fn observed_candidate() -> LocalIceCandidate {
        let candidate_fixture = "candidate:foundation 1 udp host";
        let mut candidate =
            String::with_capacity(candidate_fixture.len() + "candidate-slack".len());
        candidate.push_str(candidate_fixture);

        let mid_fixture = "data";
        let mut sdp_mid = String::with_capacity(mid_fixture.len() + "mid-slack".len());
        sdp_mid.push_str(mid_fixture);

        let username_fixture = "remote-fragment";
        let mut username_fragment =
            String::with_capacity(username_fixture.len() + "fragment-slack".len());
        username_fragment.push_str(username_fixture);

        LocalIceCandidate {
            candidate,
            sdp_mid: Some(sdp_mid),
            sdp_mline_index: None,
            username_fragment: Some(username_fragment),
        }
    }

    fn admitted_ownership(candidate: ConnectorCandidateCapability) -> ConnectorOwnership {
        ConnectorOwnership::admitted(
            candidate,
            Arc::new(AtomicBool::new(false)),
            Arc::new(AtomicBool::new(false)),
            Arc::new(WebRtcConnectorIncarnation::new()),
        )
    }

    fn test_event_mailboxes(capacity: usize) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let capacity =
            std::num::NonZeroUsize::new(capacity).expect("fixture callback capacity is nonzero");
        test_event_mailboxes_with_policy(ConnectorCallbackPolicy::unrestricted_lab(capacity))
    }

    fn test_event_mailboxes_with_policy(
        policy: ConnectorCallbackPolicy,
    ) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let capacities = policy.mailboxes();
        let (control, control_rx) = mpsc::channel(capacities.control().get());
        let (endpoint_data, endpoint_data_rx) = mpsc::channel(capacities.endpoint_data().get());
        let realtime_flows = RealtimeFlowRegistry::new(policy);
        (
            ConnectorEventMailboxes {
                control,
                endpoint_data,
            },
            TransportEventReceiver {
                control: control_rx,
                endpoint_data: endpoint_data_rx,
                realtime_flows,
                scheduler: ConnectorCallbackScheduler::new(policy.service_weights()),
            },
        )
    }

    fn test_event_sink(
        events: ConnectorEventMailboxes,
        policy: ConnectorCallbackPolicy,
        resource_scope: Option<PeerConnectionResourceScope>,
    ) -> ConnectorEventSink {
        ConnectorEventSink {
            events,
            realtime_flows: RealtimeFlowRegistry::new(policy),
            resource_scope,
            realtime_delivery: Arc::new(AtomicBool::new(true)),
            attempt_liveness: None,
            candidate_promoted: Arc::new(AtomicBool::new(true)),
            callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
            callback_policy: policy,
            data_channel_fence: Arc::new(DataChannelCallbackFence::default()),
        }
    }

    fn test_event_sink_for_receiver(
        events: ConnectorEventMailboxes,
        policy: ConnectorCallbackPolicy,
        resource_scope: Option<PeerConnectionResourceScope>,
        receiver: &TransportEventReceiver,
    ) -> ConnectorEventSink {
        let mut sink = test_event_sink(events, policy, resource_scope);
        sink.realtime_flows = Arc::clone(&receiver.realtime_flows);
        sink
    }

    fn explicit_callback_policy(
        capacity: usize,
        control_weight: usize,
        endpoint_data_weight: usize,
        realtime_weight: usize,
        realtime: RealtimeConnectorPolicy,
    ) -> ConnectorCallbackPolicy {
        let capacity =
            std::num::NonZeroUsize::new(capacity).expect("fixture callback capacity is nonzero");
        ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(capacity, capacity),
            ConnectorCallbackServiceWeights::new(
                std::num::NonZeroUsize::new(control_weight)
                    .expect("fixture control weight is nonzero"),
                std::num::NonZeroUsize::new(endpoint_data_weight)
                    .expect("fixture endpoint-data weight is nonzero"),
                std::num::NonZeroUsize::new(realtime_weight)
                    .expect("fixture real-time weight is nonzero"),
            ),
            realtime,
        )
        .expect("fixture callback policy is valid")
    }

    fn explicit_realtime_callback_policy(
        max_unit_bytes: usize,
        max_active_flows_per_domain: usize,
        queue_capacity_per_flow: usize,
        max_inbound_fragment_bytes: usize,
        max_in_progress_units_per_flow: usize,
        max_accounted_bytes: usize,
    ) -> ConnectorCallbackPolicy {
        let nonzero = |value, name| {
            std::num::NonZeroUsize::new(value)
                .unwrap_or_else(|| panic!("fixture {name} must be nonzero"))
        };
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(
                nonzero(max_active_flows_per_domain, "inbound flow count"),
                nonzero(max_active_flows_per_domain, "outbound flow count"),
                nonzero(queue_capacity_per_flow, "per-flow queue capacity"),
            ),
            ConnectorRealtimeInboundLimits::new(
                nonzero(max_inbound_fragment_bytes, "fragment limit"),
                nonzero(MAX_AU_PARTS, "compatibility per-unit fragment count"),
                nonzero(
                    max_in_progress_units_per_flow,
                    "per-flow in-progress unit limit",
                ),
            ),
            nonzero(max_accounted_bytes, "accounted-byte limit"),
            crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime =
            RealtimeConnectorPolicy::enabled(nonzero(max_unit_bytes, "unit limit"), flows)
                .expect("fixture real-time policy can carry one guarded assembly");
        explicit_callback_policy(1, 1, 1, 1, realtime)
    }

    #[derive(Default)]
    struct TestRealtimeObserver {
        observations: SyncMutex<Vec<RealtimeFlowObservation>>,
    }

    impl RealtimeFlowObserver for TestRealtimeObserver {
        fn observe(&self, observation: RealtimeFlowObservation) {
            self.observations.lock().push(observation);
        }
    }

    fn stamped_event(
        ownership: &ConnectorOwnership,
        event: TransportEvent,
    ) -> WebRtcConnectorEvent {
        WebRtcConnectorEvent {
            incarnation: Arc::clone(&ownership.incarnation),
            event,
            _queue_observation: None,
        }
    }

    async fn assert_callback_class_has_independent_capacity(
        first: TransportEvent,
        second: TransportEvent,
    ) {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = ConnectorCallbackPolicy::unrestricted_lab(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(sink.emit(first).await);
        let mut retained_flow = None;
        match second {
            event @ (TransportEvent::AudioSample(_) | TransportEvent::VideoSample(_)) => {
                let payload_bytes = match &event {
                    TransportEvent::AudioSample(sample) => sample.data.len(),
                    TransportEvent::VideoSample(sample) => sample.data.len(),
                    _ => unreachable!(),
                };
                let flow = sink
                    .open_inbound_realtime_flow()
                    .expect("fixture admits one exact real-time flow");
                let reservation = flow
                    .reserve_output(payload_bytes)
                    .expect("fixture reserves the exact complete unit");
                assert!(sink.emit_realtime(&flow, event, reservation));
                retained_flow = Some(flow);
            }
            event => assert!(sink.emit(event).await),
        }
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_ok());
        drop(retained_flow);
    }

    #[tokio::test]
    async fn v4_arc03_control_and_data_callback_capacity_are_independent() {
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            TransportEvent::Message(Bytes::from_static(b"endpoint-data")),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_control_and_audio_callback_capacity_are_independent() {
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            TransportEvent::AudioSample(AudioSample {
                rtp_timestamp: 0,
                lane: 0,
                data: Bytes::from_static(b"audio-fixture"),
                _reservation: None,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_control_and_video_callback_capacity_are_independent() {
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            TransportEvent::VideoSample(VideoSample {
                rtp_timestamp: 0,
                key: true,
                lane: 0,
                data: Bytes::from_static(b"video-fixture"),
                _reservation: None,
            }),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_data_and_realtime_callback_capacity_are_independent() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = ConnectorCallbackPolicy::unrestricted_lab(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"data")))
                .await
        );
        let audio_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the audio compatibility flow");
        let audio = TransportEvent::AudioSample(AudioSample {
            rtp_timestamp: 0,
            lane: 0,
            data: Bytes::from_static(b"audio"),
            _reservation: None,
        });
        let audio_reservation = audio_flow
            .reserve_output(5)
            .expect("fixture reserves the audio unit");
        assert!(sink.emit_realtime(&audio_flow, audio, audio_reservation));
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_ok());
        let video_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the video compatibility flow");
        let video = TransportEvent::VideoSample(VideoSample {
            rtp_timestamp: 0,
            key: true,
            lane: 0,
            data: Bytes::from_static(b"video"),
            _reservation: None,
        });
        let video_reservation = video_flow
            .reserve_output(5)
            .expect("fixture reserves the video unit");
        assert!(sink.emit_realtime(&video_flow, video, video_reservation));
        assert!(receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn v4_arc03f_close_fence_rejects_a_blocked_causally_later_message() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"before-close")))
                .await
        );
        let later_sink = sink.clone();
        let later = tokio::spawn(async move {
            later_sink
                .emit_data_channel(TransportEvent::Message(Bytes::from_static(b"after-close")))
                .await
        });
        tokio::task::yield_now().await;
        assert!(
            !later.is_finished(),
            "the later callback is blocked by the full mailbox"
        );

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(later.await.expect("later callback task joins"));

        receiver.scheduler.cursor = ConnectorCallbackClass::EndpointData.index();
        receiver.scheduler.remaining = 1;
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(bytes)) if bytes == Bytes::from_static(b"before-close")
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03f_close_fence_rejects_callback_invoked_after_close_commit() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(one, one),
            ConnectorCallbackServiceWeights::data_only(one, one),
            RealtimeConnectorPolicy::Disabled,
        )
        .expect("data-only fixture policy is valid");
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"after-close")))
                .await
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn() {
        let capacity = 3;
        let (events, mut receiver) = test_event_mailboxes(capacity);
        receiver.scheduler = ConnectorCallbackScheduler::new(ConnectorCallbackServiceWeights::new(
            std::num::NonZeroUsize::new(2).expect("fixture weight is nonzero"),
            std::num::NonZeroUsize::new(1).expect("fixture weight is nonzero"),
            std::num::NonZeroUsize::new(1).expect("fixture weight is nonzero"),
        ));
        for event in [
            TransportEvent::DataChannelOpen,
            TransportEvent::DataChannelClosed,
            TransportEvent::RenegotiationNeeded,
        ] {
            events
                .control
                .try_send(QueuedTransportEvent {
                    event,
                    observation: None,
                })
                .expect("fixture control mailbox has capacity");
        }
        events
            .endpoint_data
            .try_send(QueuedTransportEvent {
                event: TransportEvent::Message(Bytes::from_static(b"endpoint")),
                observation: None,
            })
            .expect("fixture endpoint-data mailbox has capacity");
        let realtime_flow = receiver
            .realtime_flows
            .open_inbound_flow()
            .expect("fixture admits one exact real-time flow");
        let reservation = realtime_flow
            .reserve_output(0)
            .expect("zero-byte fixture unit is admitted");
        assert!(realtime_flow.enqueue(
            QueuedTransportEvent {
                event: TransportEvent::VideoSample(VideoSample {
                    rtp_timestamp: 0,
                    key: true,
                    lane: 0,
                    data: Bytes::new(),
                    _reservation: None,
                }),
                observation: None,
            },
            reservation,
        ));

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelOpen)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::VideoSample(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RenegotiationNeeded)
        ));
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_protocol_waits_for_committed_open_despite_scheduler_cursor() {
        let (events, mut receiver) = test_event_mailboxes(3);
        receiver.scheduler.cursor = ConnectorCallbackClass::EndpointData.index();
        receiver.scheduler.remaining = 1;
        let first_handshake = Bytes::from(
            serde_json::to_vec(&crate::protocol::MeshMessage::Hello(
                crate::protocol::HelloMessage {
                    protocol: crate::PROTOCOL_VERSION,
                    device_id: "lifecycle-peer".to_string(),
                    label: "Lifecycle fixture".to_string(),
                    nonce: "nonce".to_string(),
                    verification_code: "code".to_string(),
                    capabilities: None,
                    max_connections: None,
                    features: Vec::new(),
                    app_version: None,
                },
            ))
            .expect("fixture Hello serializes"),
        );
        events
            .endpoint_data
            .try_send(QueuedTransportEvent {
                event: TransportEvent::Message(first_handshake.clone()),
                observation: None,
            })
            .expect("fixture endpoint mailbox has capacity");
        events
            .control
            .try_send(QueuedTransportEvent {
                event: TransportEvent::DataChannelOpen,
                observation: None,
            })
            .expect("fixture control mailbox has capacity");

        let before_commit = receiver
            .recv_queued_filtered(false)
            .await
            .expect("open control event is deliverable");
        assert!(matches!(
            before_commit.event,
            TransportEvent::DataChannelOpen
        ));

        let after_commit = receiver
            .recv_queued_filtered(true)
            .await
            .expect("retained handshake is released after commitment");
        assert!(matches!(
            after_commit.event,
            TransportEvent::Message(bytes) if bytes == first_handshake
        ));
    }

    #[tokio::test]
    async fn v4_arc03_close_can_retire_before_uncommitted_endpoint_protocol() {
        let (events, mut receiver) = test_event_mailboxes(2);
        receiver.scheduler.cursor = ConnectorCallbackClass::EndpointData.index();
        receiver.scheduler.remaining = 1;
        events
            .endpoint_data
            .try_send(QueuedTransportEvent {
                event: TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                observation: None,
            })
            .expect("fixture endpoint mailbox has capacity");
        events
            .control
            .try_send(QueuedTransportEvent {
                event: TransportEvent::DataChannelClosed,
                observation: None,
            })
            .expect("fixture control mailbox has capacity");

        let event = receiver
            .recv_queued_filtered(false)
            .await
            .expect("close remains deliverable before open commitment");
        assert!(matches!(event.event, TransportEvent::DataChannelClosed));
        assert!(matches!(
            receiver.endpoint_data.try_recv(),
            Ok(QueuedTransportEvent {
                event: TransportEvent::Message(bytes),
                ..
            }) if bytes == Bytes::from_static(b"stale-handshake")
        ));
    }

    #[tokio::test]
    async fn v4_arc03_retirement_drops_uncommitted_endpoint_protocol_and_its_observation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let resource_scope = context.peer_connection_scope();
        let observation = resource_scope.observe_pre_authentication(
            PreAuthResourceFamily::FrameBytes,
            ResourceUse::observed(1, 15, 15, 0),
        );
        let active_frame_bytes = || {
            context
                .report()
                .pre_authentication
                .iter()
                .find(|report| report.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame-byte family is present")
                .active
        };
        assert_ne!(active_frame_bytes(), ResourceUse::ZERO);

        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let (events, raw) = test_event_mailboxes(2);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(RemoteCandidateState::default())),
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
        };
        events
            .endpoint_data
            .try_send(QueuedTransportEvent {
                event: TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                observation: Some(observation),
            })
            .expect("fixture endpoint mailbox has capacity");
        events
            .control
            .try_send(QueuedTransportEvent {
                event: TransportEvent::DataChannelClosed,
                observation: None,
            })
            .expect("fixture control mailbox has capacity");

        let close = receiver
            .recv()
            .await
            .expect("close control event remains deliverable before open");
        assert!(matches!(close.event, TransportEvent::DataChannelClosed));
        drop(close);

        ownership.retire();
        assert!(receiver.recv().await.is_none());
        drop(receiver);
        assert_eq!(active_frame_bytes(), ResourceUse::ZERO);
    }

    #[test]
    fn v4_arc03_realtime_flows_have_independent_bounded_queues() {
        let policy = explicit_realtime_callback_policy(16, 2, 1, 16, 2, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = RealtimeFlowRegistry::with_observer(
            policy,
            Some(observer.clone() as Arc<dyn RealtimeFlowObserver>),
        );
        let video = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let audio = registry
            .open_inbound_flow()
            .expect("second flow is admitted");

        let video_unit = |timestamp| {
            TransportEvent::VideoSample(VideoSample {
                rtp_timestamp: timestamp,
                key: false,
                lane: 0,
                data: Bytes::from_static(b"video"),
                _reservation: None,
            })
        };
        let audio_unit = TransportEvent::AudioSample(AudioSample {
            rtp_timestamp: 1,
            lane: 0,
            data: Bytes::from_static(b"audio"),
            _reservation: None,
        });

        assert!(video.enqueue(
            QueuedTransportEvent {
                event: video_unit(1),
                observation: None,
            },
            video.reserve_output(5).expect("video unit is reserved"),
        ));
        assert!(video.enqueue(
            QueuedTransportEvent {
                event: video_unit(2),
                observation: None,
            },
            video
                .reserve_output(5)
                .expect("full-queue unit is still measured before refusal"),
        ));
        assert!(audio.enqueue(
            QueuedTransportEvent {
                event: audio_unit,
                observation: None,
            },
            audio.reserve_output(5).expect("audio unit is reserved"),
        ));

        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::VideoSample(sample)) if sample.rtp_timestamp == 1
        ));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::AudioSample(sample)) if sample.rtp_timestamp == 1
        ));
        assert!(registry.try_recv().is_none());
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert!(!state.accounting_poisoned);
        drop(state);
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::FlowQueueFull,
                    ..
                }
            )
        }));
    }

    #[test]
    fn v4_arc03f_inbound_and_outbound_flow_slots_cannot_starve_each_other() {
        let policy = explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16);
        let registry = RealtimeFlowRegistry::new(policy);

        let inbound = registry
            .open_inbound_flow()
            .expect("the inbound quarantine owns its slot");
        assert!(registry.open_inbound_flow().is_none());
        let outbound = registry
            .open_outbound_flow()
            .expect("inbound saturation cannot consume the outbound slot");
        assert!(registry.open_outbound_flow().is_none());

        drop(inbound);
        assert!(registry.open_inbound_flow().is_some());
        drop(outbound);
        assert!(registry.open_outbound_flow().is_some());
    }

    #[test]
    fn v4_arc03f_realtime_bytes_follow_payload_clones_through_downstream_queues() {
        let policy = explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16);
        let registry = RealtimeFlowRegistry::new(policy);
        let flow = registry
            .open_inbound_flow()
            .expect("fixture inbound flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: TransportEvent::AudioSample(AudioSample {
                    rtp_timestamp: 1,
                    lane: 0,
                    data: Bytes::from_static(b"owned"),
                    _reservation: None,
                }),
                observation: None,
            },
            flow.reserve_output(5).expect("payload bytes are reserved"),
        ));

        let queued = registry.try_recv().expect("queued payload is serviceable");
        assert_eq!(registry.state.lock().retained_bytes, 5);
        let TransportEvent::AudioSample(sample) = queued.event else {
            panic!("fixture receives its audio unit");
        };
        let downstream_clone = sample.clone();
        drop(sample);
        assert_eq!(registry.state.lock().retained_bytes, 5);
        drop(downstream_clone);
        assert_eq!(registry.state.lock().retained_bytes, 0);
    }

    #[tokio::test]
    async fn v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry() {
        let policy = explicit_realtime_callback_policy(16, 1, 2, 16, 1, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = RealtimeFlowRegistry::with_observer(
            policy,
            Some(observer.clone() as Arc<dyn RealtimeFlowObserver>),
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: TransportEvent::AudioSample(AudioSample {
                    rtp_timestamp: 7,
                    lane: 0,
                    data: Bytes::from_static(b"stale"),
                    _reservation: None,
                }),
                observation: None,
            },
            flow.reserve_output(5).expect("unit is reserved"),
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let queued = registry
            .try_recv()
            .expect("elapsed time cannot revoke a structurally bounded complete unit");
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 5);
        assert!(!state.accounting_poisoned);
        drop(state);
        drop(queued);
        assert_eq!(registry.state.lock().retained_bytes, 0);
        assert!(!observer
            .observations
            .lock()
            .iter()
            .any(|observation| { matches!(observation, RealtimeFlowObservation::Drop { .. }) }));
    }

    #[test]
    fn v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention() {
        let policy = explicit_realtime_callback_policy(4, 1, 1, 4, 1, 8);
        let registry = RealtimeFlowRegistry::new(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("first unit is admitted");
        assert!(flow.begin_unit().is_none(), "in-progress limit is exact");
        assert!(assembly.retain_fragment(4));
        assert!(
            !assembly.retain_fragment(3),
            "unit ceiling is checked first"
        );
        let concurrent_output = flow
            .reserve_output(4)
            .expect("one complete output fits beside the guarded input");
        assert!(
            flow.reserve_output(1).is_none(),
            "the next byte is refused at the connector aggregate"
        );
        drop(concurrent_output);
        drop(assembly);

        let first_output = flow.reserve_output(4).expect("first output is admitted");
        let second_output = flow
            .reserve_output(4)
            .expect("the exact aggregate ceiling is admitted");
        assert!(flow.reserve_output(1).is_none());
        drop(first_output);
        drop(second_output);
        assert!(
            flow.reserve_output(5).is_none(),
            "oversized output is refused"
        );

        let mut oversized_fragment = flow.begin_unit().expect("unit slot was released");
        assert!(!oversized_fragment.retain_fragment(5));
        drop(oversized_fragment);
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert_eq!(state.in_progress_units, 0);
        assert!(!state.accounting_poisoned);
    }

    #[test]
    fn v4_arc03f_realtime_fragment_count_is_structurally_bounded() {
        let nonzero = |value| NonZeroUsize::new(value).expect("fixture value is nonzero");
        let flows = ConnectorRealtimeFlowPolicy::new(
            ConnectorRealtimeFlowCapacities::new(nonzero(1), nonzero(1), nonzero(1)),
            ConnectorRealtimeInboundLimits::new(nonzero(4), nonzero(1), nonzero(1)),
            nonzero(8),
            crate::runtime::attempt::RealtimeQueueOverflowRule::DropNewest,
        );
        let realtime = RealtimeConnectorPolicy::enabled(nonzero(4), flows)
            .expect("fixture can hold one guarded input and output");
        let policy = ConnectorCallbackPolicy::new(
            crate::runtime::attempt::ConnectorCallbackMailboxCapacities::new(
                nonzero(1),
                nonzero(1),
            ),
            ConnectorCallbackServiceWeights::new(nonzero(1), nonzero(1), nonzero(1)),
            realtime,
        )
        .expect("fixture callback policy is valid");
        let registry = RealtimeFlowRegistry::new(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("unit is admitted");

        assert!(assembly.retain_fragment(1));
        assert!(!assembly.retain_fragment(1));
        assert_eq!(registry.state.lock().retained_bytes, 1);

        drop(assembly);
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert_eq!(state.in_progress_units, 0);
        assert!(!state.accounting_poisoned);
    }

    #[test]
    fn v4_arc03_realtime_accounting_corruption_fails_closed() {
        let policy = explicit_realtime_callback_policy(4, 1, 1, 4, 1, 8);
        let registry = RealtimeFlowRegistry::new(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let reservation = flow.reserve_output(4).expect("output is admitted");
        registry.state.lock().retained_bytes = 0;
        drop(reservation);

        let state = registry.state.lock();
        assert!(state.accounting_poisoned);
        drop(state);
        assert!(registry.open_inbound_flow().is_none());
        assert!(flow.reserve_output(1).is_none());
    }

    #[tokio::test]
    async fn v4_arc03_cancelled_realtime_output_work_releases_its_claim() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _reservation = flow.reserve_output(8).expect("output is admitted");
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("fixture reserved output");
        assert_eq!(registry.state.lock().retained_bytes, 8);
        task.abort();
        assert!(task
            .await
            .expect_err("fixture task is cancelled")
            .is_cancelled());
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert!(!state.accounting_poisoned);
    }

    #[test]
    fn v4_arc03_realtime_flow_retirement_drains_its_owned_queue() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(8, 1, 2, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: TransportEvent::AudioSample(AudioSample {
                    rtp_timestamp: 1,
                    lane: 0,
                    data: Bytes::from_static(b"owned"),
                    _reservation: None,
                }),
                observation: None,
            },
            flow.reserve_output(5).expect("unit is admitted"),
        ));
        assert_eq!(registry.state.lock().retained_bytes, 5);
        drop(flow);
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert!(state.flows.is_empty());
        assert!(state.ready.is_empty());
        assert!(!state.accounting_poisoned);
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_and_realtime_units_have_independent_limits() {
        let realtime_limit = 4;
        let policy = explicit_realtime_callback_policy(realtime_limit, 1, 2, realtime_limit, 1, 16);
        assert_eq!(
            callback_payload_limit(policy, ConnectorCallbackClass::EndpointData),
            Some(crate::engine::MAX_ENDPOINT_FRAME_BYTES)
        );
        assert_eq!(
            callback_payload_limit(policy, ConnectorCallbackClass::Realtime),
            Some(realtime_limit)
        );

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
        let sink = test_event_sink_for_receiver(events, policy, Some(scope.clone()), &receiver);

        let flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits one exact real-time flow");
        assert!(flow.reserve_output(5).is_none());
        assert!(receiver.try_recv().is_err());

        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"12345")))
                .await
        );
        let video = TransportEvent::VideoSample(VideoSample {
            rtp_timestamp: 1,
            key: true,
            lane: 0,
            data: Bytes::from_static(b"1234"),
            _reservation: None,
        });
        let reservation = flow
            .reserve_output(4)
            .expect("fixture reserves the complete real-time unit");
        assert!(sink.emit_realtime(&flow, video, reservation));

        let report = scope.report();
        let frame = report
            .pre_authentication
            .iter()
            .find(|entry| entry.family == PreAuthResourceFamily::FrameBytes)
            .expect("frame-byte family is present");
        let realtime = report
            .pre_authentication
            .iter()
            .find(|entry| entry.family == PreAuthResourceFamily::MediaQuarantine)
            .expect("real-time quarantine family is present");
        assert_eq!(frame.active.logical_bytes(), 5);
        assert_eq!(realtime.active.logical_bytes(), 4);
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::VideoSample(_))
        ));
    }

    #[tokio::test]
    async fn v4_arc03_native_close_success_releases_exact_candidate_claim() {
        let owner = test_resource_owner(1, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        close_owner
            .wait()
            .await
            .expect("fixture native close succeeds");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    async fn v4_arc03_native_close_error_retains_only_its_exact_claim() {
        let owner = test_resource_owner(2, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::clone(&calls),
            }))
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("native close failure is fail closed");
        assert!(error.to_string().contains("native close failure"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);

        drop(close_owner);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);

        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let unrelated = permit
            .reserve_connector_candidate(claim)
            .expect("a known failed close does not poison the remaining slot");
        assert_eq!(owner.report().active_candidates, 2);
        drop(unrelated);
        assert_eq!(owner.report().active_candidates, 1);
    }

    #[tokio::test]
    async fn v4_arc03f_native_close_observation_limit_does_not_prove_failure() {
        let owner = test_resource_owner(2, 1, Duration::from_millis(20));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Pending,
                calls: Arc::clone(&calls),
            }))
        );

        let error = tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("owner observation limit bounds waiting on the dependency")
            .expect_err("elapsed time leaves cleanup unproven");
        assert!(error.to_string().contains("remains unproven"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    async fn v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed() {
        let owner = test_resource_owner(2, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.fail_background_start_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("background start failure retains this cleanup claim");
        assert!(error.to_string().contains("failed to start"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    async fn v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start() {
        let owner = test_resource_owner(2, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        close_owner.fail_cleanup("fixture terminal cleanup failure".to_string());

        let error = close_owner
            .wait()
            .await
            .expect_err("a prior cleanup failure remains terminal");

        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the terminal failure does not suppress native close");

        assert!(error
            .to_string()
            .contains("fixture terminal cleanup failure"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
    }

    #[test]
    fn v4_arc03_cleanup_owner_outlives_caller_runtime_shutdown() {
        let owner = test_resource_owner(1, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        let caller_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture caller runtime");
        caller_runtime.block_on(async { close_owner.start() });
        drop(caller_runtime);

        let verifier_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture verifier runtime");
        verifier_runtime
            .block_on(close_owner.wait())
            .expect("dedicated close owner survives caller runtime shutdown");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_duplicate_connected_claims_remain_exact_and_local() {
        let owner = test_resource_owner(4, 1, Duration::from_secs(1));
        let (close_owner, _owner_lifetime) = close_owner_fixture(&owner);
        let (first, _first_lifetime) = connected_claim_fixture(&owner);
        let (second, _second_lifetime) = connected_claim_fixture(&owner);
        close_owner.fail_background_start_for_test();

        close_owner.retain_connected_claim(first);
        close_owner.retain_connected_claim(second);

        assert!(close_owner.wait().await.is_err());
        assert_eq!(close_owner.retained_connected_claims_for_test(), 2);
        assert_eq!(owner.report().active_candidates, 3);
        assert_eq!(owner.report().failed_cleanup_candidates, 3);
        assert!(!owner.report().accounting_poisoned);
        drop(close_owner);
        assert_eq!(owner.report().active_candidates, 3);
        assert_eq!(owner.report().failed_cleanup_candidates, 3);
        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_handoff_release_before_native_close_releases_once() {
        let owner = test_resource_owner(1, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = crate::endpoint_auth::EndpointAuthTask::begin(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        drop(task);
        close_owner
            .wait()
            .await
            .expect("native close follows released handoff");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_native_close_before_endpoint_handoff_release_keeps_claim_visible() {
        let owner = test_resource_owner(1, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = crate::endpoint_auth::EndpointAuthTask::begin(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        close_owner
            .wait()
            .await
            .expect("native close completes while handoff owns the claim");
        assert_eq!(owner.report().active_candidates, 1);
        drop(task);

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_failed_native_close_before_endpoint_handoff_release_retains_exact_claim() {
        let owner = test_resource_owner(2, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = crate::endpoint_auth::EndpointAuthTask::begin(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        ));

        close_owner
            .wait()
            .await
            .expect_err("native close failure remains terminal while Endpoint Auth owns the claim");
        let before_handoff_release = owner.report();
        assert_eq!(before_handoff_release.active_candidates, 1);
        assert_eq!(before_handoff_release.failed_cleanup_candidates, 0);
        assert!(!before_handoff_release.accounting_poisoned);

        drop(task);
        let after_handoff_release = owner.report();
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(after_handoff_release.active_candidates, 1);
        assert_eq!(after_handoff_release.failed_cleanup_candidates, 1);
        assert!(!after_handoff_release.accounting_poisoned);

        drop(close_owner);
        let after_owner_drop = owner.report();
        assert_eq!(after_owner_drop.active_candidates, 1);
        assert_eq!(after_owner_drop.failed_cleanup_candidates, 1);
        assert!(!after_owner_drop.accounting_poisoned);

        let (permit, _unrelated_lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[test]
    fn v4_arc03_cross_connector_endpoint_auth_and_realtime_capabilities_are_rejected() {
        let owner = test_resource_owner(2, 1, Duration::from_secs(1));
        let (first_close_owner, _first_lifetime) = close_owner_fixture(&owner);
        let (second_close_owner, _second_lifetime) = close_owner_fixture(&owner);
        let connected = match first_close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let first_task = crate::endpoint_auth::EndpointAuthTask::begin(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&first_close_owner.ownership.incarnation),
            Arc::clone(&first_close_owner),
        ));

        assert!(first_close_owner.ownership.owns_endpoint_auth(&first_task));
        assert!(!second_close_owner.ownership.owns_endpoint_auth(&first_task));

        let first_flow = crate::connector::ConnectorRealtimeFlowCapability::new(Arc::clone(
            &first_close_owner.ownership.incarnation,
        ));
        assert!(first_close_owner.ownership.owns_realtime_flow(&first_flow));
        assert!(!second_close_owner.ownership.owns_realtime_flow(&first_flow));

        first_close_owner.retire_local();
        assert!(!first_close_owner.ownership.owns_endpoint_auth(&first_task));
        assert!(!first_close_owner.ownership.owns_realtime_flow(&first_flow));
        drop((first_task, first_flow));
    }

    #[tokio::test]
    async fn v4_arc03_connector_retirement_before_promotion_rejects_and_cleans() {
        let owner = test_resource_owner(1, 1, Duration::from_secs(1));
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );

        close_owner.retire_local();
        assert!(matches!(
            close_owner.ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        close_owner
            .wait()
            .await
            .expect("retired unpromoted connector cleans exactly once");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[test]
    fn v4_arc03_candidate_queue_is_connector_owned_and_observed() {
        let process = ProcessResourceRoot::isolated();
        let mesh = process.mesh_runtime_scope();
        let context = mesh.network_instance_scope();
        let scope = context.peer_connection_scope();
        let candidate = observed_candidate();
        let candidate_use = candidate_resource_measurement(&candidate).observed();
        let mut queue = PendingRemoteCandidateQueue::default();
        queue.push(candidate, &scope);
        let container_use = queue_container_resource_measurement(&queue.entries).observed();

        let active = candidate_report(&context.report().pre_authentication);
        assert_eq!(active.active.items(), candidate_use.items());
        assert_eq!(active.active.logical_bytes(), candidate_use.logical_bytes());
        assert_eq!(
            active.active.retained_bytes(),
            candidate_use.retained_bytes() + container_use.retained_bytes()
        );
        assert_eq!(active.active_lease_count, 2);

        let mut drain = queue.take();
        let candidate = drain.next().expect("queued candidate transfers to drain");
        drop(candidate);
        assert_eq!(
            candidate_report(&context.report().pre_authentication)
                .active
                .retained_bytes(),
            container_use.retained_bytes()
        );
        drop(drain);
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 2);
    }

    #[test]
    fn v4_arc03_candidate_apply_observation_survives_await_and_cancellation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let scope = context.peer_connection_scope();
        let pending = PendingRemoteCandidate::observe(observed_candidate(), &scope);
        let mut application = Box::pin(apply_pending_remote_candidate(pending, |_| {
            std::future::pending::<std::result::Result<(), ()>>()
        }));
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);

        assert_eq!(application.as_mut().poll(&mut task_context), Poll::Pending);
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            1
        );
        drop(application);
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 1);
    }

    #[tokio::test]
    async fn v4_arc03_retirement_cancels_inflight_candidate_observation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let scope = context.peer_connection_scope();
        let pending = PendingRemoteCandidate::observe(observed_candidate(), &scope);
        let incarnation = Arc::new(WebRtcConnectorIncarnation::new());
        let retirement = incarnation.subscribe_retirement();
        let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
        let application = tokio::spawn(async move {
            await_until_connector_retirement(
                retirement,
                apply_pending_remote_candidate(pending, |_| async move {
                    let _ = entered_tx.send(());
                    std::future::pending::<std::result::Result<(), ()>>().await
                }),
            )
            .await
        });

        entered_rx
            .await
            .expect("candidate application was polled before retirement");
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            1
        );
        incarnation.retire();
        assert!(application.await.expect("application task joins").is_none());
        let completed = candidate_report(&context.report().pre_authentication);
        assert_eq!(completed.active, ResourceUse::ZERO);
        assert_eq!(completed.completed_lease_count, 1);
    }

    #[test]
    fn v4_arc03_callback_stamp_requires_exact_live_worker() {
        let (first_candidate, first_lifetime) =
            crate::runtime::attempt::connector_candidate_for_test(
                crate::runtime::runtime_for_test(),
            );
        let (second_candidate, second_lifetime) =
            crate::runtime::attempt::connector_candidate_for_test(
                crate::runtime::runtime_for_test(),
            );
        let first = admitted_ownership(first_candidate);
        let second = admitted_ownership(second_candidate);
        let event = stamped_event(&first, TransportEvent::DataChannelClosed);
        assert!(first.accepts(&event));
        assert!(!second.accepts(&event));
        first.retire();
        assert!(!first.accepts(&event));
        drop((first_lifetime, second_lifetime));
    }

    #[test]
    fn v4_arc03_retired_candidate_claim_waits_for_cleanup_completion() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);

        ownership.retire();
        assert!(ownership.cleanup_candidate_reserved_for_test());
        ownership.complete_cleanup();
        assert!(!ownership.cleanup_candidate_reserved_for_test());
        drop(lifetime);
    }

    #[tokio::test]
    async fn v4_arc03_retirement_stops_event_pump_before_stale_callback_queueing() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let (events_tx, events) = test_event_mailboxes(1);
        let remote_candidates = Arc::new(SyncMutex::new(RemoteCandidateState::default()));
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates,
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
        };

        ownership.retire();
        events_tx
            .control
            .try_send(QueuedTransportEvent {
                event: TransportEvent::DataChannelClosed,
                observation: None,
            })
            .expect("retained callback sender still has a bounded raw receiver");

        assert!(receiver.recv().await.is_none());
    }

    fn assert_callback_class_backpressure(first: TransportEvent, second: TransportEvent) {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = ConnectorCallbackPolicy::unrestricted_lab(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink(events, policy, None);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        let mut first = Box::pin(sink.emit(first));
        assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(true));

        let mut second = Box::pin(sink.emit(second));
        assert_eq!(second.as_mut().poll(&mut context), Poll::Pending);
        drop(
            receiver
                .try_recv()
                .expect("first callback occupies the queue"),
        );
        assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(true));
        drop(
            receiver
                .try_recv()
                .expect("second callback enters after drain"),
        );
    }

    fn assert_realtime_flow_backpressure(first: TransportEvent, second: TransportEvent) {
        let policy = explicit_realtime_callback_policy(16, 1, 1, 16, 1, 32);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = RealtimeFlowRegistry::with_observer(
            policy,
            Some(observer.clone() as Arc<dyn RealtimeFlowObserver>),
        );
        let flow = registry
            .open_inbound_flow()
            .expect("fixture admits one exact real-time flow");
        let payload_bytes = |event: &TransportEvent| match event {
            TransportEvent::AudioSample(sample) => sample.data.len(),
            TransportEvent::VideoSample(sample) => sample.data.len(),
            _ => panic!("fixture event must be a real-time compatibility unit"),
        };
        let first_reservation = flow
            .reserve_output(payload_bytes(&first))
            .expect("fixture reserves the first complete unit");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: first,
                observation: None,
            },
            first_reservation,
        ));
        let second_reservation = flow
            .reserve_output(payload_bytes(&second))
            .expect("aggregate bytes admit the competing unit before queue pressure");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: second,
                observation: None,
            },
            second_reservation,
        ));
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::FlowQueueFull,
                    ..
                }
            )
        }));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::AudioSample(_) | TransportEvent::VideoSample(_))
        ));
        assert!(registry.try_recv().is_none());
    }

    #[test]
    fn v4_arc03_control_callback_contention_honors_configured_bound() {
        assert_callback_class_backpressure(
            TransportEvent::DataChannelOpen,
            TransportEvent::DataChannelClosed,
        );
    }

    #[test]
    fn v4_arc03_data_callback_contention_honors_configured_bound() {
        assert_callback_class_backpressure(
            TransportEvent::Message(Bytes::from_static(b"first")),
            TransportEvent::Message(Bytes::from_static(b"second")),
        );
    }

    #[test]
    fn v4_arc03_audio_callback_contention_honors_configured_bound() {
        assert_realtime_flow_backpressure(
            TransportEvent::AudioSample(AudioSample {
                rtp_timestamp: 0,
                lane: 0,
                data: Bytes::from_static(b"first"),
                _reservation: None,
            }),
            TransportEvent::AudioSample(AudioSample {
                rtp_timestamp: 1,
                lane: 0,
                data: Bytes::from_static(b"second"),
                _reservation: None,
            }),
        );
    }

    #[test]
    fn v4_arc03_video_callback_contention_honors_configured_bound() {
        assert_realtime_flow_backpressure(
            TransportEvent::VideoSample(VideoSample {
                rtp_timestamp: 0,
                key: true,
                lane: 0,
                data: Bytes::from_static(b"first"),
                _reservation: None,
            }),
            TransportEvent::VideoSample(VideoSample {
                rtp_timestamp: 1,
                key: false,
                lane: 0,
                data: Bytes::from_static(b"second"),
                _reservation: None,
            }),
        );
    }

    #[tokio::test]
    #[ignore = "owner-run observation; requires only workload-shape inputs"]
    async fn v4_arc03_measure_callback_classes_without_selecting_a_budget() {
        fn workload_nonzero(name: &str) -> std::num::NonZeroUsize {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("observation scenario supplies {name}"))
                .parse::<usize>()
                .ok()
                .and_then(std::num::NonZeroUsize::new)
                .unwrap_or_else(|| panic!("{name} must be a nonzero integer"))
        }
        let samples = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_SAMPLES");
        let flows = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_FLOWS");
        let payload_bytes = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES");
        let total_realtime_units = samples
            .get()
            .checked_mul(flows.get())
            .expect("observation workload unit count fits usize");
        let callback_capacity =
            std::num::NonZeroUsize::new(samples.get().max(total_realtime_units))
                .expect("derived observation queue is nonzero");
        // This raw laboratory envelope is derived only to hold the requested
        // finite observation workload. It is not a production policy or a
        // proposed default.
        let policy = ConnectorCallbackPolicy::unrestricted_lab(callback_capacity);

        for class in [
            ConnectorCallbackClass::Control,
            ConnectorCallbackClass::EndpointData,
        ] {
            let (events, mut receiver) = test_event_mailboxes_with_policy(policy);
            let sink = test_event_sink(events, policy, None);
            let mut queued_at = std::collections::VecDeque::new();
            for index in 0..samples.get() {
                let event = match class {
                    ConnectorCallbackClass::Control => TransportEvent::DataChannelClosed,
                    ConnectorCallbackClass::EndpointData => {
                        TransportEvent::Message(Bytes::from(index.to_le_bytes().to_vec()))
                    }
                    ConnectorCallbackClass::Realtime => unreachable!(),
                };
                let observed_at = Instant::now();
                assert!(sink.emit(event).await);
                queued_at.push_back(observed_at);
            }
            for index in 0..samples.get() {
                receiver.recv().await.expect("observed callback arrives");
                let queue_age = queued_at
                    .pop_front()
                    .expect("one timestamp exists per observed callback")
                    .elapsed();
                println!(
                    "arc03_callback_raw class={class:?} index={index} queue_age_ns={}",
                    queue_age.as_nanos()
                );
            }
        }

        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = RealtimeFlowRegistry::with_observer(
            policy,
            Some(observer.clone() as Arc<dyn RealtimeFlowObserver>),
        );
        let mut admitted_flows = Vec::with_capacity(flows.get());
        for _ in 0..flows.get() {
            admitted_flows.push(
                registry
                    .open_inbound_flow()
                    .expect("raw observation envelope admits the requested flow"),
            );
        }
        for (flow_index, flow) in admitted_flows.iter().enumerate() {
            for unit_index in 0..samples.get() {
                let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
                let reservation = flow
                    .reserve_output(payload.len())
                    .expect("raw observation envelope retains the requested unit");
                assert!(flow.enqueue(
                    QueuedTransportEvent {
                        event: TransportEvent::VideoSample(VideoSample {
                            rtp_timestamp: unit_index as u32,
                            key: false,
                            lane: u8::try_from(flow_index).unwrap_or(u8::MAX),
                            data: payload,
                            _reservation: None,
                        }),
                        observation: None,
                    },
                    reservation,
                ));
            }
        }
        for _ in 0..total_realtime_units {
            registry
                .try_recv()
                .expect("raw real-time observation unit remains serviceable");
        }
        for observation in observer.observations.lock().iter() {
            println!("arc03_realtime_raw observation={observation:?}");
        }
        drop(admitted_flows);
    }

    #[tokio::test]
    async fn v4_arc03_retirement_wakes_producer_blocked_by_full_callback_queue() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let callback_gate = Arc::new(WebRtcConnectorIncarnation::new());
        let policy = ConnectorCallbackPolicy::unrestricted_lab(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let mut sink = test_event_sink(events, policy, None);
        sink.callback_gate = Arc::clone(&callback_gate);

        assert!(sink.emit(TransportEvent::DataChannelOpen).await);
        let blocked =
            tokio::spawn(async move { sink.emit(TransportEvent::DataChannelClosed).await });
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !blocked.is_finished(),
            "the first event keeps the queue full"
        );

        callback_gate.retire();
        assert!(!tokio::time::timeout(Duration::from_secs(1), blocked)
            .await
            .expect("retirement wakes the blocked producer")
            .expect("blocked callback task joins"));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelOpen)
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[tokio::test]
    async fn v4_arc03_event_receiver_adds_no_hidden_engine_queue() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let attempt_retirement = candidate.liveness().subscribe_retirement();
        let ownership = admitted_ownership(candidate);
        let (events_tx, events) = test_event_mailboxes(1);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(RemoteCandidateState::default())),
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
        };
        events_tx
            .control
            .send(QueuedTransportEvent {
                event: TransportEvent::DataChannelOpen,
                observation: None,
            })
            .await
            .expect("first callback is queued");
        let first = receiver.recv().await.expect("first event reaches engine");
        events_tx
            .control
            .send(QueuedTransportEvent {
                event: TransportEvent::DataChannelClosed,
                observation: None,
            })
            .await
            .expect("second callback is queued behind the engine handoff");

        let mut second_receive = Box::pin(receiver.recv());
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        assert!(matches!(
            second_receive.as_mut().poll(&mut context),
            Poll::Ready(Some(_))
        ));
        drop(first);
    }

    #[tokio::test]
    async fn v4_arc03_attempt_retirement_wakes_and_reclaims_silent_candidate() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let resource_scope = context.peer_connection_scope();
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let attempt_retirement = candidate.liveness().subscribe_retirement();
        let ownership = admitted_ownership(candidate);
        let remote_candidates = Arc::new(SyncMutex::new(RemoteCandidateState::default()));
        remote_candidates
            .lock()
            .pending
            .push(observed_candidate(), &resource_scope);
        let (_events_tx, events) = test_event_mailboxes(1);
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: Some(attempt_retirement),
            raw: events,
            attempt_lifetime: Some(lifetime),
            remote_candidates,
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
        };
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active_lease_count,
            2
        );

        receiver.retire_attempt_for_test();
        assert!(receiver.recv().await.is_none());
        assert!(!ownership.incarnation.is_active());
        assert_eq!(
            candidate_report(&context.report().pre_authentication).active,
            ResourceUse::ZERO
        );
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_closes_partial_native_peer() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(test_resource_owner(1, 4, Duration::from_secs(10)));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let created = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("native peer exists at the cancellation point");

        construction.abort();
        assert!(construction.await.is_err());
        hook.resume.add_permits(1);

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned construction closes the partial native peer");
        drop(native);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = context.report();
                let callbacks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Callback)
                    .expect("callback family exists");
                let tasks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Task)
                    .expect("task family exists");
                if callbacks.active == ResourceUse::ZERO && tasks.active == ResourceUse::ZERO {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("partial construction releases callback and task observations");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim() {
        let owner = test_resource_owner(2, 4, Duration::from_secs(10));
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone());
        let hook =
            ConstructionTestHook::new(ConstructionPause::AfterNativeAllocationWithCloseError);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let created = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("native peer exists at the cancellation point");

        construction.abort();
        assert!(construction.await.is_err());
        hook.resume.add_permits(1);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = owner.report();
                if native.connection_state() == RTCPeerConnectionState::Closed
                    && report.active_candidates == 1
                    && report.failed_cleanup_candidates == 1
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled construction closes the native peer and retains its exact failed claim");
        let report = owner.report();
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(report.active_candidates, 1);
        assert_eq!(report.failed_cleanup_candidates, 1);
        assert!(!report.accounting_poisoned);

        let (permit, _unrelated_lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        assert!(permit.reserve_connector_candidate(claim).is_some());
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_delivered_result_closes_native_peer_before_release() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(test_resource_owner(1, 4, Duration::from_secs(10)));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterResultDelivery);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let delivered = hook
            .created
            .acquire()
            .await
            .expect("result-delivery hook remains open");
        delivered.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("delivered result still owns its native peer");

        construction.abort();
        assert!(construction.await.is_err());

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled delivered result closes its native peer");
        drop(native);

        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let report = context.report();
                let callbacks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Callback)
                    .expect("callback family exists");
                let tasks = report
                    .pre_authentication
                    .iter()
                    .find(|entry| entry.family == PreAuthResourceFamily::Task)
                    .expect("task family exists");
                if callbacks.active == ResourceUse::ZERO && tasks.active == ResourceUse::ZERO {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cancelled delivered result releases callback and task observations");
    }

    #[test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    fn v4_arc03_construction_runtime_shutdown_is_bounded_and_fail_closed() {
        let owner = test_resource_owner(1, 4, Duration::from_secs(2));
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone());
        let hook = ConstructionTestHook::new(ConstructionPause::AfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let process = ProcessResourceRoot::isolated();
        let construction_scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let caller_runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_all()
            .build()
            .expect("fixture caller runtime");
        let construction = caller_runtime.spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });
        let created = caller_runtime
            .block_on(hook.created.acquire())
            .expect("construction reaches native allocation");
        created.forget();
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("partial native peer exists");
        construction.abort();
        let cancelled = caller_runtime.block_on(construction);
        assert!(
            cancelled.is_err_and(|error| error.is_cancelled()),
            "runtime owner cancels and joins construction before shutdown"
        );
        drop(caller_runtime);

        let verifier_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture verifier runtime");
        let terminal = verifier_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(5), async {
                loop {
                    let report = owner.report();
                    let released =
                        report.active_candidates == 0 && report.failed_cleanup_candidates == 0;
                    let retained =
                        report.active_candidates == 1 && report.failed_cleanup_candidates == 1;
                    if native.connection_state() == RTCPeerConnectionState::Closed
                        && (released || retained)
                    {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            })
            .await
        });
        assert!(
            terminal.is_ok(),
            "runtime shutdown did not reach a bounded cleanup outcome: state={:?}, report={:?}",
            native.connection_state(),
            owner.report()
        );
        let report = owner.report();
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert!(
            (report.active_candidates == 0 && report.failed_cleanup_candidates == 0)
                || (report.active_candidates == 1 && report.failed_cleanup_candidates == 1),
            "confirmed close releases the claim; an unconfirmed close retains only its exact claim: {report:?}"
        );
        assert!(!report.accounting_poisoned);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_background_construction_failure_closes_partial_native_peer() {
        let owner = test_resource_owner(1, 4, Duration::from_secs(10));
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone());
        let hook = ConstructionTestHook::new(ConstructionPause::FailAfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let process = ProcessResourceRoot::isolated();
        let construction_scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();

        let result = transport
            .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
            .await;
        assert!(
            result.is_err(),
            "injected construction task failure reaches the caller"
        );
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("failed construction returned a native peer to its guard");

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed
                || owner.report().active_candidates != 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("failed construction closes its native peer before releasing the claim");
        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[test]
    fn v4_arc03_data_channel_open_requires_live_exact_candidate() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let connected = match ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("live exact candidate must produce one connected capability"),
        };
        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::AlreadyConnected
        ));
        ownership.retire();
        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        drop(connected);
        drop(lifetime);
    }

    #[test]
    fn v4_arc03_promotion_does_not_nest_connector_and_attempt_transitions() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = Arc::new(admitted_ownership(candidate));
        let (extracted_tx, extracted_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let promoting = Arc::clone(&ownership);

        let open = std::thread::spawn(move || {
            promoting.mark_data_channel_open_after_extract(|| {
                extracted_tx
                    .send(())
                    .expect("test observes the connector extraction point");
                continue_rx
                    .recv()
                    .expect("test releases candidate promotion");
            })
        });

        extracted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("promotion releases connector authority before entering attempt transition");
        lifetime.retire();
        ownership.retire();
        continue_tx
            .send(())
            .expect("promotion thread remains available");

        assert!(matches!(
            open.join().expect("promotion thread joins"),
            DataChannelOpenTransition::Rejected
        ));
    }

    #[test]
    fn v4_arc03_admitted_worker_rejects_protocol_bytes_before_channel_capability() {
        let (candidate, _lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let before_open = stamped_event(
            &ownership,
            TransportEvent::Message(Bytes::from_static(b"not-connected")),
        );

        assert!(!ownership.accepts(&before_open));
        let _connected = match ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("live exact candidate must produce one connected capability"),
        };
        assert!(ownership.accepts(&before_open));
        let media = stamped_event(
            &ownership,
            TransportEvent::AudioSample(AudioSample {
                rtp_timestamp: 0,
                lane: 0,
                data: Bytes::new(),
                _reservation: None,
            }),
        );
        assert!(
            !ownership.accepts(&media),
            "connected-channel authority is not application-media authority"
        );
    }

    #[test]
    fn v4_arc03_rejected_open_retires_callback_admission() {
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        lifetime.retire();

        assert!(matches!(
            ownership.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        let after_rejection = stamped_event(
            &ownership,
            TransportEvent::Message(Bytes::from_static(b"retired")),
        );
        assert!(!ownership.accepts(&after_rejection));
    }

    #[test]
    fn v4_arc03_attempt_retirement_preserves_winner_and_invalidates_awaiting_loser() {
        let (first, second, lifetime) = crate::runtime::attempt::two_connector_candidates_for_test(
            crate::runtime::runtime_for_test(),
        );
        let first = admitted_ownership(first);
        let second = admitted_ownership(second);

        let connected = match first.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("the first live candidate must promote"),
        };

        lifetime.retire();

        let winner_message = stamped_event(
            &first,
            TransportEvent::Message(Bytes::from_static(b"promoted-winner")),
        );
        let awaiting_control = stamped_event(&second, TransportEvent::DataChannelClosed);
        assert!(first.accepts(&winner_message));
        assert!(!second.accepts(&awaiting_control));
        assert!(matches!(
            first.mark_data_channel_open(),
            DataChannelOpenTransition::AlreadyConnected
        ));
        assert!(matches!(
            second.mark_data_channel_open(),
            DataChannelOpenTransition::Rejected
        ));
        assert!(first.incarnation.is_active());
        assert!(!second.incarnation.is_active());
        drop(connected);
    }

    #[test]
    fn v4_arc03_unsupported_candidate_measurement_is_inexact_not_a_panic() {
        assert_eq!(measured_usize(None), (u64::MAX, true));
    }

    #[test]
    #[ignore = "manual candidate-observer metadata measurement"]
    fn v4_arc03_candidate_observer_metadata_measurement() {
        println!(
            "arc03_candidate_metadata_bytes local_candidate={} observation_lease={} pending_candidate={} queue={} drain={} vec_header={}",
            size_of::<LocalIceCandidate>(),
            size_of::<CandidateObservationLease>(),
            size_of::<PendingRemoteCandidate>(),
            size_of::<PendingRemoteCandidateQueue>(),
            size_of::<PendingRemoteCandidateDrain>(),
            size_of::<Vec<PendingRemoteCandidate>>()
        );
    }

    #[test]
    fn sdp_fingerprint_extracts_and_normalises() {
        let sdp = "v=0\r\n\
                   o=- 1 2 IN IP4 127.0.0.1\r\n\
                   a=group:BUNDLE 0\r\n\
                   a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n";
        assert_eq!(
            sdp_fingerprint(sdp).as_deref(),
            Some("sha-256 aa:bb:cc:dd"),
            "the fingerprint is extracted and lowercased for stable comparison"
        );

        // A rebuild carries a different fingerprint; a restart keeps it.
        let restart = sdp.replace("a=ice-ufrag:x", "a=ice-ufrag:y");
        assert_eq!(
            sdp_fingerprint(&restart),
            sdp_fingerprint(sdp),
            "same PC (restart) → same fingerprint"
        );
        let rebuilt = sdp.replace("AA:BB:CC:DD", "11:22:33:44");
        assert_ne!(
            sdp_fingerprint(&rebuilt),
            sdp_fingerprint(sdp),
            "fresh PC (rebuild) → different fingerprint"
        );

        // No fingerprint line → None (glare / not-yet-applied).
        assert_eq!(sdp_fingerprint("v=0\r\nm=application 9\r\n"), None);
    }

    #[test]
    fn track_id_carries_its_lane() {
        // The id a lane's track advertises round-trips to its index…
        assert_eq!(lane_of_track_id("video-0"), 0);
        assert_eq!(lane_of_track_id("video-3"), 3);
        assert_eq!(lane_of_track_id("audio-7"), 7);
        // …a bare id from a pre-pool peer is lane 0…
        assert_eq!(lane_of_track_id("video"), 0);
        assert_eq!(lane_of_track_id("audio"), 0);
        // …and anything out of range or unparseable falls back to 0 rather
        // than indexing a lane that doesn't exist.
        assert_eq!(lane_of_track_id(&format!("video-{MEDIA_LANES}")), 0);
        assert_eq!(lane_of_track_id("video-x"), 0);
        assert_eq!(lane_of_track_id("weird"), 0);
    }

    // ---- ICE interface filter -----------------------------------------

    #[test]
    fn virtual_interfaces_are_excluded_real_ones_kept() {
        // Docker / container / overlay interfaces — the dead-candidate
        // sources we trim. `br-…` and `veth…` carry hashed suffixes.
        for name in [
            "docker0",
            "br-1a2b3c4d5e6f",
            "veth9f2a1b",
            "virbr0",
            "vmnet8",
            "cni0",
            "flannel.1",
            "cali1234abcd",
            "kube-bridge",
        ] {
            assert!(
                is_virtual_interface(name),
                "{name} should be excluded from ICE gathering"
            );
        }

        // Real interfaces — physical NICs, Wi-Fi, and the Tailscale tunnel
        // (a legitimate peer path the user asked us to keep).
        for name in [
            "eth0",
            "enp3s0",
            "eno1",
            "wlan0",
            "wlp2s0",
            "en0",
            "tailscale0",
            "utun3",
            "wg0",
            "lo",
        ] {
            assert!(
                !is_virtual_interface(name),
                "{name} should keep gathering ICE candidates"
            );
        }
    }

    #[test]
    fn link_local_ips_are_filtered_routable_ones_kept() {
        use std::net::IpAddr;
        // Link-local — the unbindable addresses we drop from gathering.
        for s in ["fe80::1", "fe80::ce81:b1c:bd2c:69e", "169.254.10.20"] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(is_link_local_ip(&ip), "{s} should be filtered");
        }
        // Kept: RFC-1918, CGNAT, ULA, and globals all make usable host
        // candidates. ULA (`fdb8::`/`fd…`) in particular must survive —
        // it's bindable and routes on the local network.
        for s in [
            "192.168.88.15",
            "10.0.0.5",
            "172.20.10.2",
            "100.64.0.7",
            "fdb8:7b28:9cfa:0:1c5f:1ecb:63c0:1a03",
            "2600:382:2187:2bf1::1",
            "127.0.0.1",
            "::1",
        ] {
            let ip: IpAddr = s.parse().unwrap();
            assert!(!is_link_local_ip(&ip), "{s} should be kept");
        }
    }

    // ---- the H.264 access-unit assembler ------------------------------

    fn rtp_pkt(seq: u16, ts: u32, marker: bool, payload: &[u8]) -> webrtc::rtp::packet::Packet {
        webrtc::rtp::packet::Packet {
            header: webrtc::rtp::header::Header {
                sequence_number: seq,
                timestamp: ts,
                marker,
                ..Default::default()
            },
            payload: Bytes::copy_from_slice(payload),
        }
    }

    /// A single-NAL IDR payload (type 5) — emits as one whole unit.
    const IDR_NAL: &[u8] = &[0x65, 0xAA, 0xBB];
    /// The same IDR as three FU-A fragments (start / middle / end).
    const FU_S: &[u8] = &[0x7C, 0x85, 0x11];
    const FU_M: &[u8] = &[0x7C, 0x05, 0x22];
    const FU_E: &[u8] = &[0x7C, 0x45, 0x33];

    #[test]
    fn v4_arc03_guarded_video_refuses_fragment_before_retention() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(8, 1, 1, 2, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler = H264AuAssembler::guarded(flow);
        assert!(assembler
            .push_guarded(&rtp_pkt(1, 100, true, IDR_NAL))
            .is_err());
        assert!(assembler.parts.is_empty());
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert_eq!(state.in_progress_units, 0);
        assert!(!state.accounting_poisoned);
    }

    #[test]
    fn v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(8, 1, 1, 8, 1, 16));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler = H264AuAssembler::guarded(flow);
        assert!(assembler
            .push_guarded(&rtp_pkt(1, 100, false, FU_S))
            .expect("the bounded fragment is valid")
            .is_none());
        {
            let state = registry.state.lock();
            assert_eq!(state.retained_bytes, FU_S.len());
            assert_eq!(state.in_progress_units, 1);
        }

        drop(assembler);
        let state = registry.state.lock();
        assert_eq!(state.retained_bytes, 0);
        assert_eq!(state.in_progress_units, 0);
        assert!(!state.accounting_poisoned);
    }

    #[test]
    fn v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(32, 1, 1, 8, 1, 64));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler = H264AuAssembler::guarded(flow);
        let anchor = assembler
            .push_guarded(&rtp_pkt(9, 100, true, IDR_NAL))
            .expect("anchor is valid")
            .expect("anchor emits");
        drop(anchor);
        assert!(assembler
            .push_guarded(&rtp_pkt(10, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(assembler
            .push_guarded(&rtp_pkt(12, 200, true, FU_E))
            .unwrap()
            .is_none());
        let sample = assembler
            .push_guarded(&rtp_pkt(11, 200, false, FU_M))
            .expect("late middle is valid")
            .expect("whole reordered unit emits");
        assert_eq!(
            sample.sample.data.as_ref(),
            &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]
        );
        assert_eq!(
            registry.state.lock().retained_bytes,
            sample.sample.data.len()
        );
        drop(sample);
        assert_eq!(registry.state.lock().retained_bytes, 0);
    }

    #[test]
    fn v4_arc03f_guarded_video_in_progress_limit_is_independent_per_flow() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(32, 2, 1, 8, 1, 64));
        let first_flow = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second_flow = registry
            .open_inbound_flow()
            .expect("second flow is admitted");
        let mut first = H264AuAssembler::guarded(first_flow);
        let mut second = H264AuAssembler::guarded(second_flow);
        assert!(first
            .push_guarded(&rtp_pkt(1, 100, false, FU_S))
            .unwrap()
            .is_none());
        assert!(second
            .push_guarded(&rtp_pkt(2, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert_eq!(second.parts.len(), 1);
        assert_eq!(registry.state.lock().in_progress_units, 2);
        drop(first);
        assert_eq!(registry.state.lock().in_progress_units, 1);
        drop(second);
        assert_eq!(registry.state.lock().in_progress_units, 0);
    }

    #[test]
    fn v4_arc03f_in_progress_unit_limit_is_enforced_per_flow() {
        let registry =
            RealtimeFlowRegistry::new(explicit_realtime_callback_policy(32, 2, 1, 8, 1, 64));
        let first_flow = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second_flow = registry
            .open_inbound_flow()
            .expect("second flow is admitted");

        let first_unit = first_flow.begin_unit().expect("first unit is admitted");
        assert!(
            first_flow.begin_unit().is_none(),
            "the same flow cannot exceed its unit ceiling"
        );
        let second_unit = second_flow
            .begin_unit()
            .expect("another flow retains its independent unit slot");
        assert_eq!(registry.state.lock().in_progress_units, 2);

        drop(first_unit);
        assert!(first_flow.begin_unit().is_some());
        drop(second_unit);
    }

    #[test]
    fn single_packet_units_emit_in_order() {
        let mut asm = H264AuAssembler::default();
        let s1 = asm.push(&rtp_pkt(1, 100, true, IDR_NAL)).unwrap().unwrap();
        assert!(s1.key, "type-5 NAL is a key unit");
        assert_eq!(&s1.data[..], &[0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
        let s2 = asm.push(&rtp_pkt(2, 200, true, IDR_NAL)).unwrap();
        assert!(s2.is_some(), "the anchored next unit emits too");
    }

    #[test]
    fn fragments_reassemble_even_when_reordered() {
        let mut asm = H264AuAssembler::default();
        // Anchor with a complete first unit.
        asm.push(&rtp_pkt(9, 100, true, IDR_NAL)).unwrap().unwrap();
        // Fragments arrive start, END (marker), middle — out of order.
        assert!(asm.push(&rtp_pkt(10, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(12, 200, true, FU_E)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(11, 200, false, FU_M))
            .unwrap()
            .expect("contiguous after the late middle arrives");
        // Reconstructed: start code + NAL header (idc|type) + fragments.
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
        assert!(s.key);
    }

    #[test]
    fn a_hole_mid_unit_drops_that_unit_never_a_torn_one() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(20, 100, true, IDR_NAL)).unwrap().unwrap();
        // Unit 2 loses its middle fragment for good.
        assert!(asm.push(&rtp_pkt(21, 200, false, FU_S)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(23, 200, true, FU_E)).unwrap().is_none());
        // Unit 3 arrives — unit 2 is abandoned, and unit 3 (which starts
        // an AU) emits despite the lost anchor.
        let s = asm
            .push(&rtp_pkt(24, 300, true, IDR_NAL))
            .unwrap()
            .expect("the stream re-syncs on the next unit");
        assert_eq!(s.rtp_timestamp, 300);
    }

    #[test]
    fn an_anchored_hole_waits_for_the_retransmit() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(29, 100, true, IDR_NAL)).unwrap().unwrap();
        // The unit's *first* packet is missing; the marker alone must not
        // emit a headless tail.
        assert!(asm.push(&rtp_pkt(31, 200, false, FU_M)).unwrap().is_none());
        assert!(asm.push(&rtp_pkt(32, 200, true, FU_E)).unwrap().is_none());
        // The NACK retransmit fills the hole late — the unit completes.
        let s = asm
            .push(&rtp_pkt(30, 200, false, FU_S))
            .unwrap()
            .expect("retransmit completes the chain");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn late_retransmit_of_an_abandoned_unit_cannot_clobber_the_live_one() {
        let mut asm = H264AuAssembler::default();
        // Unit at ts 100 never completes (tail lost)…
        assert!(asm.push(&rtp_pkt(40, 100, false, FU_S)).unwrap().is_none());
        // …the next unit begins…
        assert!(asm.push(&rtp_pkt(42, 200, false, FU_S)).unwrap().is_none());
        // …a stale retransmit for ts 100 arrives and must be ignored…
        assert!(asm.push(&rtp_pkt(41, 100, true, FU_E)).unwrap().is_none());
        // …and the live unit still completes intact.
        let s = asm
            .push(&rtp_pkt(43, 200, true, FU_E))
            .unwrap()
            .expect("live unit unaffected by the stale packet");
        assert_eq!(s.rtp_timestamp, 200);
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x33]);
    }

    #[test]
    fn a_headless_tail_never_emits_without_an_anchor() {
        let mut asm = H264AuAssembler::default();
        // Fresh stream joined mid-unit: middle + end fragments only.
        assert!(asm.push(&rtp_pkt(50, 100, false, FU_M)).unwrap().is_none());
        assert!(
            asm.push(&rtp_pkt(51, 100, true, FU_E)).unwrap().is_none(),
            "a contiguous-looking run that doesn't *start* a unit stays dropped"
        );
    }

    #[test]
    fn sequence_wraparound_is_transparent() {
        let mut asm = H264AuAssembler::default();
        asm.push(&rtp_pkt(65534, 100, true, IDR_NAL))
            .unwrap()
            .unwrap();
        assert!(asm
            .push(&rtp_pkt(65535, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(asm.push(&rtp_pkt(0, 200, false, FU_M)).unwrap().is_none());
        let s = asm
            .push(&rtp_pkt(1, 200, true, FU_E))
            .unwrap()
            .expect("the chain is contiguous across the wrap");
        assert_eq!(&s.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
    }

    #[test]
    fn au_start_detection_matches_rtp_payload_shapes() {
        assert!(payload_starts_au(&Bytes::from_static(IDR_NAL)));
        assert!(payload_starts_au(&Bytes::from_static(FU_S)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_M)));
        assert!(!payload_starts_au(&Bytes::from_static(FU_E)));
        // STAP-A aggregates start units too.
        assert!(payload_starts_au(&Bytes::from_static(&[0x78, 0x00, 0x01])));
    }

    #[test]
    fn private_lan_ips_recognised_public_ones_not() {
        // RFC1918 + link-local → LAN.
        assert!(is_private_lan_ip("192.168.1.50"));
        assert!(is_private_lan_ip("10.0.0.3"));
        assert!(is_private_lan_ip("172.16.4.9"));
        assert!(is_private_lan_ip("169.254.10.20"));
        assert!(is_private_lan_ip("fe80::1"));
        assert!(is_private_lan_ip("fd12:3456::1"));
        // Public, CGNAT, and junk → not LAN.
        assert!(!is_private_lan_ip("1.2.3.4"));
        assert!(!is_private_lan_ip("100.64.0.1")); // carrier-grade NAT, not a LAN
        assert!(!is_private_lan_ip("2606:4700::1111"));
        assert!(!is_private_lan_ip("not-an-ip"));
    }

    #[tokio::test]
    async fn loopback_handshake_opens_data_channel() {
        // Bring up two peer sessions on the same in-process
        // Transport. No STUN / TURN — they exchange host
        // candidates over the same loopback interface. Verifies
        // the entire offer/answer/candidate cycle plus the
        // data-channel handshake without external dependencies.
        let observed_at = Instant::now();
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();

        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone())
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg)
            .await
            .expect("answerer");

        let offer = offerer.create_offer().await.expect("create_offer");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        offerer
            .set_remote_description(answer)
            .await
            .expect("offerer.set_remote");

        // Pump ICE candidates between the two sides for up to 10s.
        // Either order is fine — we just need both to see the
        // DataChannelOpen event before the deadline.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(15);
        let mut off_open = false;
        let mut ans_open = false;

        while (!off_open || !ans_open) && tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        answerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to answerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { off_open = true; }
                }
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        offerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to offerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { ans_open = true; }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(100)) => {}
            }
        }

        assert!(off_open, "offerer never saw DataChannelOpen");
        assert!(ans_open, "answerer never saw DataChannelOpen");

        offerer
            .send(Bytes::from_static(b"hello"))
            .await
            .expect("send");
        // Drain answerer events for the message.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(5);
        let mut got = false;
        while tokio::time::Instant::now() < deadline {
            tokio::select! {
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::Message(b) = ev {
                        assert_eq!(b.as_ref(), b"hello");
                        got = true;
                        break;
                    }
                }
                _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
            }
        }
        assert!(got, "answerer never received the app frame");

        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw handshake_and_data_ns={}",
                observed_at.elapsed().as_nanos()
            );
        }
        let offerer_close_at = Instant::now();
        offerer.close().await.expect("close offerer");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw endpoint=offerer close_ns={}",
                offerer_close_at.elapsed().as_nanos()
            );
        }
        let answerer_close_at = Instant::now();
        answerer.close().await.expect("close answerer");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_direct_raw endpoint=answerer close_ns={}",
                answerer_close_at.elapsed().as_nanos()
            );
        }
    }

    #[test]
    fn annexb_nal_scan_finds_types_across_both_start_codes() {
        // 4-byte start code SPS (7), 3-byte start code PPS (8), then IDR (5).
        let au = [
            0, 0, 0, 1, 0x67, 0xAA, // SPS
            0, 0, 1, 0x68, 0xBB, // PPS
            0, 0, 0, 1, 0x65, 0x11, 0x22, // IDR slice
        ];
        let types: Vec<u8> = annexb_nal_types(&au).collect();
        assert_eq!(types, vec![7, 8, 5]);
        assert!(au_has_idr(&au));

        // A delta slice (type 1) alone is not a key.
        let p = [0, 0, 0, 1, 0x41, 0x99];
        assert!(!au_has_idr(&p));

        // Degenerate inputs scan to nothing without panicking.
        assert_eq!(annexb_nal_types(&[]).count(), 0);
        assert_eq!(annexb_nal_types(&[0, 0, 1]).count(), 0);
    }

    #[test]
    fn au_assembler_groups_by_timestamp_and_drops_torn_units() {
        let mut asm = H264AuAssembler::default();
        // Two single-NAL packets of one frame; marker closes it.
        assert!(asm
            .push(&rtp_pkt(1, 1000, false, &[0x41, 1, 1, 1]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(2, 1000, true, &[0x65, 2, 2, 2]))
            .unwrap()
            .expect("marker completes the unit");
        assert!(s.key, "an IDR NAL anywhere in the unit marks it key");
        assert_eq!(s.rtp_timestamp, 1000);
        // Depacketized single NALs come back with start codes attached.
        assert_eq!(
            s.data.as_ref(),
            &[0, 0, 0, 1, 0x41, 1, 1, 1, 0, 0, 0, 1, 0x65, 2, 2, 2]
        );

        // A unit whose marker never arrived is dropped when the next
        // timestamp starts; the new unit is unaffected.
        assert!(asm
            .push(&rtp_pkt(3, 2000, false, &[0x41, 7, 7, 7]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(4, 3000, true, &[0x41, 9, 9, 9]))
            .unwrap()
            .expect("fresh unit completes");
        assert_eq!(s.rtp_timestamp, 3000);
        assert!(!s.key);
        assert_eq!(s.data.as_ref(), &[0, 0, 0, 1, 0x41, 9, 9, 9]);
    }

    #[tokio::test]
    async fn loopback_video_lane_carries_h264_samples() {
        // Same loopback bring-up as the data-channel test, but the
        // assertion is on the provisioned video lane: an Annex-B access
        // unit written on the offerer's track arrives at the answerer as
        // one assembled VideoSample, byte-equal and key-flagged. This is
        // the negotiation-without-renegotiation property end to end:
        // m-line in the one offer/answer, RTP, depacketize, reassembly.
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();

        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone())
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg)
            .await
            .expect("answerer");

        // Lifecycle era: lane 3 doesn't exist until someone asks for
        // it. Prime it with one pre-negotiation write — the write
        // no-ops, but the auto-open attaches the track so the initial
        // offer negotiates it (the engine-driven path renegotiates
        // in place instead; transport tests have no engine).
        offerer
            .send_video(
                3,
                Bytes::from_static(b"\x00"),
                std::time::Duration::from_millis(33),
            )
            .await
            .expect("prime video lane 3");

        let offer = offerer.create_offer().await.expect("create_offer");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        offerer
            .set_remote_description(answer)
            .await
            .expect("offerer.set_remote");

        // One synthetic IDR access unit. The H264 payloader parses
        // Annex-B, so the bytes must be a plausible NAL stream.
        let au: Vec<u8> = {
            let mut v = vec![0u8, 0, 0, 1, 0x65];
            v.extend((0..400u32).map(|i| (i % 251) as u8));
            v
        };

        // The track binds only once negotiation + ICE complete, and
        // writes before that are silent no-ops — so keep (re)sending
        // the unit at frame cadence until the far side reports it.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut received: Option<VideoSample> = None;
        let mut send_tick = tokio::time::interval(std::time::Duration::from_millis(50));
        while received.is_none() && tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = send_tick.tick() => {
                    // A non-zero lane proves the whole pool negotiates and the
                    // far side recovers the lane from the track id (not just
                    // lane 0): write on lane 3, expect it back tagged lane 3.
                    let _ = offerer
                        .send_video(3, Bytes::from(au.clone()), std::time::Duration::from_millis(33))
                        .await;
                }
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        answerer.add_ice_candidate(c.clone()).await.expect("ice → answerer");
                    }
                }
                Some(ev) = ans_rx.recv() => {
                    match ev {
                        TransportEvent::LocalIceCandidate(Some(c)) => {
                            offerer.add_ice_candidate(c.clone()).await.expect("ice → offerer");
                        }
                        TransportEvent::VideoSample(s) => received = Some(s),
                        _ => {}
                    }
                }
            }
        }

        let sample = received.expect("answerer never received a video sample");
        assert_eq!(sample.data.as_ref(), &au[..], "AU survives byte-exact");
        assert!(sample.key, "IDR unit arrives key-flagged");
        assert_eq!(sample.lane, 3, "the lane survives the round-trip");

        offerer.close().await.expect("close offerer");
        answerer.close().await.expect("close answerer");
    }

    #[tokio::test]
    async fn loopback_audio_lane_carries_opus_frames() {
        // The audio twin of the video lane test: an Opus frame written
        // on the offerer's audio track arrives at the answerer as one
        // AudioSample, byte-equal — the same single offer/answer
        // negotiates both lanes, and no reassembly exists to get wrong
        // (one frame per RTP packet, RFC 7587).
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();

        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone())
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg)
            .await
            .expect("answerer");

        // Lifecycle era: lane 5 doesn't exist until someone asks for
        // it. Prime it with one pre-negotiation write — the write
        // no-ops, but the auto-open attaches the track so the initial
        // offer negotiates it (the engine-driven path renegotiates
        // in place instead; transport tests have no engine).
        offerer
            .send_audio(
                5,
                Bytes::from_static(b"\x00"),
                std::time::Duration::from_millis(20),
            )
            .await
            .expect("prime audio lane 5");

        let offer = offerer.create_offer().await.expect("create_offer");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        offerer
            .set_remote_description(answer)
            .await
            .expect("offerer.set_remote");

        // One synthetic Opus frame: a valid TOC byte then arbitrary
        // payload — the lane ships bytes, it never parses them.
        let frame: Vec<u8> = {
            let mut v = vec![0x78u8];
            v.extend((0..160u32).map(|i| (i % 251) as u8));
            v
        };

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(20);
        let mut received: Option<AudioSample> = None;
        let mut send_tick = tokio::time::interval(std::time::Duration::from_millis(20));
        while received.is_none() && tokio::time::Instant::now() < deadline {
            tokio::select! {
                _ = send_tick.tick() => {
                    // A different non-zero lane (audio pool is independent):
                    // write on lane 5, expect it back tagged lane 5.
                    let _ = offerer
                        .send_audio(5, Bytes::from(frame.clone()), std::time::Duration::from_millis(20))
                        .await;
                }
                Some(ev) = off_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        answerer.add_ice_candidate(c.clone()).await.expect("ice → answerer");
                    }
                }
                Some(ev) = ans_rx.recv() => {
                    match ev {
                        TransportEvent::LocalIceCandidate(Some(c)) => {
                            offerer.add_ice_candidate(c.clone()).await.expect("ice → offerer");
                        }
                        TransportEvent::AudioSample(s) => received = Some(s),
                        _ => {}
                    }
                }
            }
        }

        let sample = received.expect("answerer never received an audio sample");
        assert_eq!(
            sample.data.as_ref(),
            &frame[..],
            "frame survives byte-exact"
        );
        assert_eq!(sample.lane, 5, "the lane survives the round-trip");

        offerer.close().await.expect("close offerer");
        answerer.close().await.expect("close answerer");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03f_data_only_connector_allocates_no_realtime_tracks() {
        let owner = test_resource_owner(1, 4, Duration::from_secs(10));
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner);
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");

        assert_eq!(worker.session.open_lane_count(LaneKind::Video), 0);
        assert_eq!(worker.session.open_lane_count(LaneKind::Audio), 0);
        assert!(worker
            .session
            .send_video(0, Bytes::from_static(b"unit"), Duration::ZERO)
            .await
            .expect_err("data-only policy refuses a real-time flow")
            .to_string()
            .contains("flow was refused"));

        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03f_track_attach_failure_rolls_back_outbound_flow_owner() {
        let transport = Transport::new().expect("transport");
        let (session, _events) = transport
            .open_peer(Role::Offerer, &[], &[])
            .await
            .expect("open");
        let baseline = session.outbound_realtime_flows.lock().len();
        session
            .fail_next_track_attach
            .store(true, Ordering::Release);

        let error = session
            .send_video(1, Bytes::from_static(b"unit"), Duration::ZERO)
            .await
            .expect_err("injected native track attachment fails");
        assert!(error.to_string().contains("injected native track"));
        assert_eq!(session.open_lane_count(LaneKind::Video), 1);
        assert_eq!(session.outbound_realtime_flows.lock().len(), baseline);
        assert!(!session
            .outbound_realtime_flows
            .lock()
            .contains_key(&(true, 1)));

        session.close().await.expect("close");
    }

    #[tokio::test]
    async fn lanes_are_lifecycle_managed_not_pre_pooled() {
        let transport = Transport::new().expect("transport");
        let (session, mut events) = transport
            .open_peer(Role::Offerer, &[], &[])
            .await
            .expect("open");

        // Setup provisions lane 0 only — no 8-lane SDP tax.
        assert_eq!(
            session.open_lane_count(LaneKind::Video),
            PRE_PROVISIONED_LANES
        );
        assert_eq!(
            session.open_lane_count(LaneKind::Audio),
            PRE_PROVISIONED_LANES
        );

        // First write to a closed lane opens it transparently and flags
        // a renegotiation; the write itself is a pre-negotiation no-op.
        session
            .send_video(
                3,
                Bytes::from_static(b"x"),
                std::time::Duration::from_millis(33),
            )
            .await
            .expect("auto-open write");
        assert_eq!(session.open_lane_count(LaneKind::Video), 2);
        let mut saw_reneg = false;
        while let Ok(ev) = events.try_recv() {
            if matches!(ev, TransportEvent::RenegotiationNeeded) {
                saw_reneg = true;
            }
        }
        assert!(saw_reneg, "lane open must flag a renegotiation");

        // A second write to the same lane is quiet — no new flag.
        session
            .send_video(
                3,
                Bytes::from_static(b"y"),
                std::time::Duration::from_millis(33),
            )
            .await
            .expect("write on open lane");
        assert!(
            events.try_recv().is_err(),
            "an already-open lane never re-flags"
        );

        // Explicit open takes the lowest free slot (1: 0 is pre-opened,
        // 3 is auto-opened) — a fresh slot, so it flags a renegotiation.
        // Drain the flag so the close/revive checks below observe
        // silence.
        let lane = session
            .open_media_lane(LaneKind::Video)
            .await
            .expect("explicit open");
        assert_eq!(lane, 1);
        let mut saw_reneg = false;
        while let Ok(ev) = events.try_recv() {
            if matches!(ev, TransportEvent::RenegotiationNeeded) {
                saw_reneg = true;
            }
        }
        assert!(saw_reneg, "a fresh explicit open flags a renegotiation");

        // Close is a *drain*: the slot keeps its m-line, nothing is
        // signaled, and it's idempotent.
        session
            .close_media_lane(LaneKind::Video, 3)
            .await
            .expect("close");
        assert_eq!(
            session.open_lane_count(LaneKind::Video),
            3,
            "a draining lane still holds its m-line"
        );
        assert!(
            events.try_recv().is_err(),
            "a drain is silent — no renegotiation on close"
        );
        session
            .close_media_lane(LaneKind::Video, 3)
            .await
            .expect("double close is a no-op");

        // Reopen within the grace revives the drained lane — same id,
        // zero SDP work. This is the settings stop→start fast path.
        let lane = session
            .open_media_lane(LaneKind::Video)
            .await
            .expect("reopen");
        assert_eq!(lane, 3, "reopen revives the draining lane");
        assert!(
            events.try_recv().is_err(),
            "a revival is free — no renegotiation"
        );

        // A drain past the grace is reaped: slot freed, track removed.
        // The reaper's caller carries the removal in its own offer, so
        // no event fires here either.
        session
            .close_media_lane(LaneKind::Video, 3)
            .await
            .expect("re-close");
        assert!(session.has_reapable_lanes(Duration::ZERO));
        assert!(
            !session.has_reapable_lanes(Duration::from_secs(3600)),
            "a fresh drain is not yet due"
        );
        assert_eq!(session.reap_drained_lanes(Duration::ZERO).await, 1);
        assert_eq!(session.open_lane_count(LaneKind::Video), 2);
        assert!(!session
            .outbound_realtime_flows
            .lock()
            .contains_key(&(true, 3)));
        assert!(!session.has_reapable_lanes(Duration::ZERO));

        // With nothing draining, an explicit open claims the lowest
        // free slot again.
        let lane = session
            .open_media_lane(LaneKind::Video)
            .await
            .expect("fresh open after reap");
        assert_eq!(lane, 2, "explicit open takes the lowest free slot");

        // The device ceiling still errors rather than mis-routing.
        let err = session
            .send_video(
                MEDIA_LANES as u8,
                Bytes::from_static(b"z"),
                std::time::Duration::from_millis(33),
            )
            .await
            .expect_err("past-ceiling lane must error");
        assert!(err.to_string().contains("no video lane"));

        session.close().await.expect("close");
    }

    #[tokio::test]
    async fn pinned_lane_drains_but_is_never_reaped() {
        let transport = Transport::new().expect("transport");
        let (session, mut events) = transport
            .open_peer(Role::Offerer, &[], &[])
            .await
            .expect("open");

        // Lane 0 is pre-provisioned. Closing it drains the lane (keeps its
        // track) but — being pinned — it is never eligible for reaping, no
        // matter how far past the grace. A re-open therefore always revives
        // the same negotiated track (zero SDP) instead of recycling an
        // m-line, which is the reliable path. This is the CEC console
        // stop→start fast path made durable rather than time-boxed.
        session
            .close_media_lane(LaneKind::Video, 0)
            .await
            .expect("close lane 0");
        assert!(
            events.try_recv().is_err(),
            "a drain is silent — no renegotiation on close"
        );

        // Even at zero grace (maximally eager reaping) the pinned lane is
        // neither counted nor reaped, and it keeps its m-line.
        assert!(
            !session.has_reapable_lanes(Duration::ZERO),
            "the pinned lane never counts as reapable"
        );
        assert_eq!(
            session.reap_drained_lanes(Duration::ZERO).await,
            0,
            "the pinned lane is never reaped"
        );
        assert_eq!(
            session.open_lane_count(LaneKind::Video),
            PRE_PROVISIONED_LANES,
            "the pinned lane keeps its m-line through the drain"
        );

        // Re-open revives the same lane in place, free.
        let lane = session
            .open_media_lane(LaneKind::Video)
            .await
            .expect("reopen pinned lane");
        assert_eq!(lane, 0, "reopen revives the pinned lane in place");
        assert!(
            events.try_recv().is_err(),
            "reviving the pinned lane is free — no renegotiation"
        );

        // Contrast: a transient lane (1+) still reaps past its grace, so the
        // pin is narrowly scoped to the pre-provisioned lane.
        session
            .send_video(
                1,
                Bytes::from_static(b"x"),
                std::time::Duration::from_millis(33),
            )
            .await
            .expect("auto-open transient lane 1");
        while events.try_recv().is_ok() {}
        session
            .close_media_lane(LaneKind::Video, 1)
            .await
            .expect("close lane 1");
        assert!(
            session.has_reapable_lanes(Duration::ZERO),
            "a transient lane past grace is reapable"
        );
        assert_eq!(
            session.reap_drained_lanes(Duration::ZERO).await,
            1,
            "the transient lane is reaped"
        );
        assert!(!session
            .outbound_realtime_flows
            .lock()
            .contains_key(&(true, 1)));

        session.close().await.expect("close");
    }
}
