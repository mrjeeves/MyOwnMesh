//! WebRTC peer connection wrapper. Bridges webrtc-rs's callback-driven
//! API to one bounded mailbox per connector worker.
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
#[cfg(any(test, feature = "transport-lab"))]
use std::num::NonZeroUsize;
use std::pin::Pin;
#[cfg(feature = "transport-lab")]
use std::sync::atomic::AtomicU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use bytes::Bytes;
use futures_util::stream::FuturesUnordered;
use futures_util::StreamExt;
use parking_lot::Mutex as SyncMutex;
use serde::{Deserialize, Serialize};
#[cfg(test)]
use sha2::{Digest, Sha256};
#[cfg(test)]
use tokio::sync::mpsc;
#[cfg(test)]
use tokio::sync::Semaphore;
use tokio::sync::{oneshot, watch};
use tracing::{debug, info, trace, warn};
use webrtc::api::interceptor_registry::register_default_interceptors;
use webrtc::api::media_engine::MediaEngine;
use webrtc::api::setting_engine::SettingEngine;
use webrtc::api::APIBuilder;
use webrtc::data_channel::data_channel_init::RTCDataChannelInit;
use webrtc::data_channel::data_channel_message::DataChannelMessage;
use webrtc::data_channel::data_channel_state::RTCDataChannelState;
use webrtc::data_channel::RTCDataChannel;
use webrtc::ice_transport::ice_candidate::RTCIceCandidateInit;
use webrtc::ice_transport::ice_connection_state::RTCIceConnectionState;
use webrtc::interceptor::registry::Registry;
use webrtc::media::Sample;
use webrtc::peer_connection::configuration::RTCConfiguration;
use webrtc::peer_connection::peer_connection_state::RTCPeerConnectionState;
use webrtc::peer_connection::policy::ice_transport_policy::RTCIceTransportPolicy;
use webrtc::peer_connection::sdp::sdp_type::RTCSdpType;
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;
use webrtc::peer_connection::signaling_state::RTCSignalingState;
use webrtc::peer_connection::RTCPeerConnection;
use webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecCapability;
use webrtc::rtp_transceiver::rtp_codec::RTPCodecType;
use webrtc::rtp_transceiver::rtp_sender::RTCRtpSender;
use webrtc::rtp_transceiver::rtp_transceiver_direction::RTCRtpTransceiverDirection;
use webrtc::rtp_transceiver::{RTCRtpTransceiver, RTCRtpTransceiverInit};
use webrtc::track::track_local::track_local_static_sample::TrackLocalStaticSample;
use webrtc::track::track_local::TrackLocal;
use webrtc::track::track_remote::TrackRemote;

use crate::error::{Error, Result};
use crate::resource::{
    ObservationLease, PeerConnectionResourceScope, PreAuthResourceFamily, ProcessResourceRoot,
    ResourceMeasurement, ResourceUnavailable, ResourceUse,
};
use crate::runtime::attempt::{
    admit_single_connector_candidate, AttemptLifetime, AttemptLiveness, ConnectorCallbackPolicy,
    ConnectorCandidateCapability, ConnectorResourceOwnerReport, ConnectorWorkResourceScope,
    MeshConnectorResourceReport, MeshConnectorResourceScope,
    OwnedRemoteCandidate as ElasticRemoteCandidateLease, RealtimeConnectorPolicy,
    RemoteCandidateAdmission as ElasticRemoteCandidateAdmission,
    RemoteCandidateAdmissionError as ElasticRemoteCandidateAdmissionError,
    RemoteCandidateApplyError as ElasticRemoteCandidateApplyError,
    RemoteCandidateAttempt as ElasticRemoteCandidateAttempt,
    RemoteCandidateDigestDecision as ElasticRemoteCandidateDigestDecision,
    RemoteCandidateInput as ElasticRemoteCandidateInput,
    RemoteCandidateTerminalReason as ElasticRemoteCandidateTerminalReason,
    WebRtcConnectorCapablePolicy,
};

use super::ice::{build_rtc_configuration, IceCandidatePath};

mod callback;

/// The callback grant a scope-less lab connector states for itself.
///
/// Published only where a scope-less connector can be built at all. Production
/// never names it: a production connector has a real work scope and acquires
/// against the owner's provider, so there is nothing for it to state.
#[cfg(feature = "transport-lab")]
pub use callback::TransportLabCallbackGrant;
mod cleanup;
mod h264;
mod inbound;
mod policy;
mod provider;
mod realtime;
mod session_flow;
/// The application-facing WebRTC realtime vocabulary.
///
/// Public, and public *here* rather than in `crate::realtime`, because every
/// one of these carries something only a negotiated RTP clock makes readable.
/// The basal module holds what is true of any flow; this holds what is true of
/// a WebRTC one, and [`crate::JoinedNetwork`]'s `*_webrtc_realtime` methods are
/// where the two meet.
///
/// The four DTOs come from [`provider`] and the RTP kind from [`session_flow`],
/// which is a split worth stating: the kind is a *negotiation* primitive the
/// flow machinery selects capabilities with, so it lives beside that machinery
/// and is published from there; the DTOs exist only to cross the application
/// boundary and have no business inside the flow set.
pub use provider::{
    RealtimeInboundArrival, WebRtcRealtimeFlowOpen, WebRtcRealtimeInboundArrival,
    WebRtcRealtimeInboundUnit, WebRtcRealtimeOutboundUnit,
};
/// The connector's own short spelling of the profile.
///
/// Private, so it changes nothing for a caller. It exists because the public
/// name is qualified for the benefit of code that can see more than one
/// provider, and this module can see exactly one.
///
/// Only the profile. The other four qualified types above are constructed by
/// the daemon and validated by `RealtimeProfile::new`; nothing in the connector
/// names them outside the module that defines them, so importing them here
/// would be four names that document an expectation rather than a use.
use session_flow::RealtimeProfile;
pub use session_flow::WebRtcRtpKind;
/// The per-session flow vocabulary, and nothing else from that module.
///
/// A re-export rather than `pub(crate) mod`: the engine stores the flow set in
/// the promoted-session bundle and converts the rest at its DTO boundary, but
/// `RealtimeFlow` and `RealtimeFlowPort` must stay unreachable from outside the
/// connector. Widening the module would have exposed both.
pub(crate) use session_flow::{
    OpaqueFlowChange, OpaqueFlowSpec, OpaqueOutboundPump, OpaqueOutboundUnit, OpaquePumpStep,
    RealtimeDirection, RealtimeEncoding, RealtimeFlowError, RealtimeFlowIdentity,
    RealtimeFlowLabel, RealtimeFlowRemains, RealtimeFlowSetIdentity, RealtimeFlowSpec,
    RealtimeInboundArrivals, RealtimeRecvUnit, RealtimeSendUnit, RealtimeTrackIdentity,
    SessionRealtimeFlows,
};
/// The application's real-time configuration, and only that.
///
/// One of two public re-exports from this module. `crates/myownmesh` is a
/// separate crate, so the daemon cannot name anything `pub(crate)` here — but
/// the only thing it needs to name is the profile it parsed at startup. These
/// five types are inert plain data plus one validating constructor: they carry
/// no session, no incarnation, no label and no port, so publishing them hands
/// out no authority. Everything that *is* authority stays in the `pub(crate)`
/// list below.
///
/// **Published under qualified names, and that is not cosmetic.** A codec, a
/// framing strategy, an RTCP feedback mechanism and the profile that holds them
/// are WebRTC facts; an unqualified `RealtimeProfile` at the crate root reads as
/// *the* realtime profile, which invites an application to treat it as the
/// generic layer's concept and a second provider to believe it must fit into it.
/// There is no unqualified public spelling and no compatibility alias — a caller
/// updates the name or does not compile, which is the only signal strong enough
/// to relocate a concept.
///
/// Aliased rather than renamed at the definition because inside the connector
/// there is nothing to disambiguate from: `RealtimeProfile` is unambiguous in a
/// module that has no other kind of profile, and the qualification is only owed
/// to callers who see it next to other providers' vocabularies.
pub use session_flow::{
    RealtimeCodec as WebRtcRealtimeCodec, RealtimeFlowName,
    RealtimeFraming as WebRtcRealtimeFraming, RealtimeProfile as WebRtcRealtimeProfile,
    RealtimeProfileError as WebRtcRealtimeProfileError,
    RealtimeRtcpFeedback as WebRtcRealtimeRtcpFeedback,
};
mod unit_assembly;
use callback::*;
use cleanup::*;
use h264::*;
/// The session-gated inbound pump, and nothing public.
///
/// Private because there is no application vocabulary here to publish: an
/// inbound track's destination and framing are both facts this side
/// established, so nothing an application names is involved.
use inbound::*;
pub use policy::*;
use realtime::*;
/// Private, not added to the `pub(crate)` re-export above, and deliberately so.
///
/// All four are connector-internal: the binding table decides which flow a
/// negotiated track may attach to, the port handle is a pump's non-owning claim
/// on an already-open flow, the unit policy is how a flow's framing reaches it,
/// and the leased wake is the funded block a pump parks on. Re-exporting any of
/// them would put it in the engine's vocabulary, and the engine has no business
/// naming a demux table it must not write to — still less a route to a flow's
/// accounting that skips the session gate. A private `use` makes them nameable
/// here and in this module's children — which is exactly the connector — and
/// nowhere else.
///
/// That reach is the whole reason `LeasedWake` is listed. `session_flow`
/// re-exports it at connector visibility, but a re-export is reachable by path
/// rather than by a sibling's `use super::*`: the inbound pump's owner names the
/// type in a field, and this line is what puts it in the namespace that
/// sibling globs.
///
/// `RealtimeInboundAttachment` is deliberately absent even though this module
/// uses one. `on_track` never writes the name: it binds the value `admit`
/// returns and destructures it into the pump's owner. Importing a type only to
/// leave it unwritten is an import that documents an intention rather than a
/// dependency, and it goes stale silently the moment the intention changes.
use session_flow::{
    LeasedWake, RealtimeFlowPortHandle, RealtimeInboundBindings, RealtimeUnitPolicy,
};
use unit_assembly::*;

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
const OPAQUE_RELIABLE_DATA_CHANNEL_LABEL: &str = "myownmesh-opaque-reliable";
const OPAQUE_PARTIAL_DATA_CHANNEL_LABEL: &str = "myownmesh-opaque-partial";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum OpaqueNativeLaneMode {
    ReliableOrdered,
    PartialUnordered,
}

impl OpaqueNativeLaneMode {
    const fn label(self) -> &'static str {
        match self {
            Self::ReliableOrdered => OPAQUE_RELIABLE_DATA_CHANNEL_LABEL,
            Self::PartialUnordered => OPAQUE_PARTIAL_DATA_CHANNEL_LABEL,
        }
    }

    fn from_label(label: &str) -> Option<Self> {
        match label {
            OPAQUE_RELIABLE_DATA_CHANNEL_LABEL => Some(Self::ReliableOrdered),
            OPAQUE_PARTIAL_DATA_CHANNEL_LABEL => Some(Self::PartialUnordered),
            _ => None,
        }
    }

    const fn mode_tag(self) -> u8 {
        match self {
            Self::ReliableOrdered => 0,
            Self::PartialUnordered => 1,
        }
    }

    /// Validate the native channel's negotiated reliability, rather than
    /// trusting its label.  A label is application data; these getters are
    /// the provider's authenticated lane provenance.
    fn matches_channel(self, channel: &RTCDataChannel) -> bool {
        opaque_native_parameters_match(
            self,
            channel.ordered(),
            channel.max_retransmits(),
            channel.max_packet_lifetime(),
        )
    }
}

/// The provider's fixed reliability contract, factored so its source-level
/// controls can exercise every mismatch without fabricating a native channel.
fn opaque_native_parameters_match(
    mode: OpaqueNativeLaneMode,
    ordered: bool,
    max_retransmits: Option<u16>,
    max_packet_lifetime: Option<u16>,
) -> bool {
    match mode {
        OpaqueNativeLaneMode::ReliableOrdered => {
            ordered && max_retransmits.is_none() && max_packet_lifetime.is_none()
        }
        OpaqueNativeLaneMode::PartialUnordered => {
            !ordered && max_retransmits == Some(0) && max_packet_lifetime.is_none()
        }
    }
}

impl From<OpaqueNativeLaneMode> for crate::realtime::OpaqueFlowMode {
    fn from(mode: OpaqueNativeLaneMode) -> Self {
        match mode {
            OpaqueNativeLaneMode::ReliableOrdered => Self::ReliableOrdered,
            // The provider's fixed partial lane intentionally supports only
            // the explicitly negotiated zero-retransmit profile.
            OpaqueNativeLaneMode::PartialUnordered => Self::PartialUnordered { max_retransmits: 0 },
        }
    }
}

struct OpaqueNativeLane {
    channel: Arc<RTCDataChannel>,
    _lease: crate::resource::ResourceLease,
}

#[derive(Default)]
struct OpaqueNativeLanes {
    reliable: Option<OpaqueNativeLane>,
    partial: Option<OpaqueNativeLane>,
}

impl OpaqueNativeLanes {
    fn get(&self, mode: OpaqueNativeLaneMode) -> Option<&OpaqueNativeLane> {
        match mode {
            OpaqueNativeLaneMode::ReliableOrdered => self.reliable.as_ref(),
            OpaqueNativeLaneMode::PartialUnordered => self.partial.as_ref(),
        }
    }

    fn insert(&mut self, mode: OpaqueNativeLaneMode, lane: OpaqueNativeLane) -> bool {
        let slot = match mode {
            OpaqueNativeLaneMode::ReliableOrdered => &mut self.reliable,
            OpaqueNativeLaneMode::PartialUnordered => &mut self.partial,
        };
        if slot.is_some() {
            return false;
        }
        *slot = Some(lane);
        true
    }
}

fn opaque_native_lane_claim(
) -> std::result::Result<crate::resource::ResourceClaim, ResourceUnavailable> {
    RealtimeFlowRegistry::flow_root_claim(size_of::<OpaqueNativeLane>())
}

fn opaque_frame_matches_lane(bytes: &Bytes, mode: OpaqueNativeLaneMode) -> bool {
    bytes.len() > 5 && bytes.as_ref()[5] == mode.mode_tag()
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum NativeDataChannelAdmission {
    Install,
    Violation(&'static str),
}

fn admit_native_data_channel(
    label: &str,
    application_channel_installed: bool,
) -> NativeDataChannelAdmission {
    if label != APP_DATA_CHANNEL_LABEL {
        return NativeDataChannelAdmission::Violation("unexpected application data-channel label");
    }
    if application_channel_installed {
        return NativeDataChannelAdmission::Violation("duplicate application data channel");
    }
    NativeDataChannelAdmission::Install
}

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
    /// Inbound application-owned opaque-flow frame. The mode is stamped by
    /// the authenticated native lane callback; it is provenance, not a value
    /// learned from the untrusted frame header.
    ApplicationFlowMessage {
        mode: crate::realtime::OpaqueFlowMode,
        bytes: Bytes,
    },
    /// Data channel closed (peer initiated or local error).
    DataChannelClosed,
    /// The local track set changed (a media lane opened or closed) and
    /// the SDP no longer matches — the engine should renegotiate in
    /// place (fresh offer, same DTLS fingerprint). Coalesced by the
    /// engine per peer, so a burst of lane changes costs one offer.
    RenegotiationNeeded,
    /// One assembled unit from a negotiated inbound real-time flow.
    ///
    /// The one inbound real-time crossing, reusing this queue rather than a
    /// second channel: two inbound paths would be two things that can stall
    /// independently, and an ordering between them to reason about.
    ///
    /// Codec-opaque and authority-free. It carries a label, a timestamp, a
    /// marker and bytes — no session reference, no capability, no peer
    /// identity. The admission decision was made before this existed, by
    /// matching the negotiated track against a binding this side established;
    /// an event that reached the engine cannot grant what the connector
    /// already refused.
    RealtimeUnit(RealtimeInboundDelivery),
}

/// One inbound realtime unit in transit from the connector to the engine.
///
/// Codec-opaque and authority-free by construction. Every field is private, so
/// nothing outside this crate can read the label back, reach the unit, or hold
/// the payload reservation — and nothing inside it can build one of these
/// except the connector's own inbound path.
///
/// It rides the existing inbound event stream rather than a second channel:
/// one inbound path means one thing that can stall, and no ordering to reason
/// about between two. Which of that stream's sources feeds it — the realtime
/// flow queue or a callback mailbox — decides how it is charged and capped, and
/// is settled at the emit site rather than here.
///
/// The label is demux data, not a handle. It names a flow *within one session*,
/// and the engine resolves that session at the fence before it delivers — so a
/// unit that arrives for a session that has since gone is dropped, and its
/// payload reservation is released with it rather than stranded.
pub struct RealtimeInboundDelivery {
    label: RealtimeFlowLabel,
    unit: RealtimeRecvUnit,
    /// Attached by the queue, then moved out with the unit and never released
    /// separately: whoever takes the unit takes responsibility for the bytes it
    /// occupies, and a delivery dropped undelivered releases them by dropping
    /// this.
    ///
    /// `Option` because the queue is what mints it. `enqueue_checked` validates
    /// the output reservation against its own registry, key and liveness before
    /// converting it to a lease, so a delivery that arrived holding one would
    /// mean either that conversion happened early and unvalidated, or that a
    /// second lease is about to be attached and the bytes counted twice.
    ///
    /// The property this gives up at the constructor is regained downstream:
    /// nothing but `enqueue_checked` puts one of these on the event stream, and
    /// it attaches before it queues. A delivery reaching the engine without a
    /// lease did not come through the accounting path at all.
    payload: Option<RealtimePayloadLease>,
}

/// Written out rather than derived, and it redacts.
///
/// [`TransportEvent`] is `Debug`, so this has to be — but a derive would print
/// the payload, and the payload is the peer's media. A unit that reaches a log
/// or a panic message is application content leaving the process through a
/// diagnostic channel that nothing audits. What is printed instead is what a
/// diagnostic actually needs: which flow it was for, how many bytes it carried,
/// and whether it is still holding a lease for them.
///
/// The byte count is not content. It is already visible to the resource owner
/// that admitted the unit, so reporting it here discloses nothing that side of
/// the boundary did not already account for.
impl std::fmt::Debug for RealtimeInboundDelivery {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RealtimeInboundDelivery")
            .field("label", &self.label)
            .field("bytes", &self.unit.data.len())
            .field("leased", &self.payload.is_some())
            .finish()
    }
}

impl RealtimeInboundDelivery {
    /// Bind an assembled unit to the flow the connector's binding table
    /// resolved for the track it arrived on.
    pub(crate) fn new(label: RealtimeFlowLabel, unit: RealtimeRecvUnit) -> Self {
        Self {
            label,
            unit,
            payload: None,
        }
    }

    /// **Controls only.** A delivery for `name` that never passed the
    /// accounting path.
    ///
    /// The engine's unaccounted-delivery negative needs exactly one thing that
    /// production cannot produce: a delivery naming a live flow while carrying
    /// no payload lease. It is named for that, rather than reached by widening
    /// [`RealtimeFlowLabel::mint`] — a caller able to mint could make a *real*
    /// label outside admission, which is the opposite of what this proves.
    ///
    /// What is unaccounted is the **payload**. The label itself takes a real
    /// lease, against a control-only elastic scope created once here, because
    /// there is no such thing as an unleased label and a fixture that faked one
    /// would be proving something about a shape that cannot exist. That is also
    /// why the scope is never retired: a fixture label may outlive the control
    /// that made it.
    /// `pub(crate)`, matching [`RealtimeRecvUnit`]'s own visibility. The
    /// engine's lab control is in this crate, so that is the whole audience;
    /// a `pub` signature naming a `pub(crate)` type would be a private
    /// interface, and widening the unit to reach for `pub` would publish an
    /// inbound unit type nothing outside core has any use for.
    ///
    /// Gated on **both**, because its one caller is. The engine's negative is a
    /// `#[tokio::test]` that is itself `cfg(feature = "transport-lab")`, so
    /// `test` alone leaves this uncalled in a default-feature test build and
    /// the lab feature alone leaves it uncallable in a library build. The
    /// conjunction is the exact audience.
    ///
    /// The helper it calls stays plain `cfg(test)` on purpose: that one has a
    /// second caller in this module's own controls, which do not need the lab.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn unaccounted_for_test(name: &RealtimeFlowName, unit: RealtimeRecvUnit) -> Self {
        Self::new(control_label_for_test(name), unit)
    }

    /// How many payload bytes this delivery carries.
    ///
    /// Read at callback admission, which charges the delivery against the
    /// pump's class budget. Borrowing rather than consuming, because admission
    /// happens before the decision to take the event. Read from the unit rather
    /// than the lease, so it answers the same before and after attachment.
    pub(crate) fn payload_bytes(&self) -> usize {
        self.unit.data.len()
    }

    /// Take custody of the lease the queue minted for this delivery.
    ///
    /// Refuses a second attachment rather than overwriting, and hands the
    /// refused lease back so it is released rather than stranded. Overwriting
    /// would drop a live lease silently and leave the bytes it accounted for
    /// charged to nothing.
    #[expect(
        clippy::result_large_err,
        reason = "the Err is the refused lease itself, returned by value so the caller drops it and the bytes it accounted for are released. Boxing it would allocate on the refusal path, and any smaller error would mean this fn keeps the lease it just declined — stranding exactly the accounting the refusal exists to prevent"
    )]
    fn attach(
        &mut self,
        payload: RealtimePayloadLease,
    ) -> std::result::Result<(), RealtimePayloadLease> {
        if self.payload.is_some() {
            return Err(payload);
        }
        self.payload = Some(payload);
        Ok(())
    }

    /// The lease, for the dequeue-time transition from queued to delivered.
    fn payload_mut(&mut self) -> Option<&mut RealtimePayloadLease> {
        self.payload.as_mut()
    }

    /// The flow this arrival is bound to, borrowed.
    ///
    /// Every question a flow set asks before it accepts an arrival — is there
    /// such a flow, is it inbound, is there capacity for a node — is a question
    /// about this label, and none of them needs the delivery taken apart. A
    /// borrowed answer is what lets those refusals happen while the delivery is
    /// still whole, so a refused arrival drops its unit and its payload lease
    /// together instead of releasing one while the other is still standing.
    fn label(&self) -> &RealtimeFlowLabel {
        &self.label
    }
}

/// A real leased label for a control, over a scope that is never retired.
///
/// One shared elastic registry for every fixture label in the crate. Controls
/// and lab harnesses need labels that are *real* — minted at admission, holding
/// a real lease — without owning a session to mint them from, and a per-call
/// provider stack would be both slower and a second thing to keep in step.
///
/// The scope is created once and deliberately leaked. A fixture label can be
/// retained by a queued event that outlives the control that made it, so tying
/// the scope to any one control's lifetime would retire it under a live lease.
#[cfg(test)]
fn control_label_for_test(name: &RealtimeFlowName) -> RealtimeFlowLabel {
    static CONTROL_REGISTRY: std::sync::OnceLock<Arc<RealtimeFlowRegistry>> =
        std::sync::OnceLock::new();
    let registry = CONTROL_REGISTRY.get_or_init(|| {
        let (registry, resources) =
            RealtimeFlowRegistry::elastic_for_control(elastic_control_grant());
        std::mem::forget(resources);
        registry
    });
    RealtimeFlowLabel::mint(name.clone(), registry)
        .expect("the control grant admits one fixture label")
}

/// The grant every elastic control registry in this crate stands on.
///
/// **Two halves, and only one of them is a number anyone chose.** The
/// structural half is `explicit_test_grant(1, 1)` — the same mechanical
/// derivation the rest of the fixtures use, covering the process cleanup
/// infrastructure, one Mesh scope and one connector candidate with its
/// operation and reservation bookkeeping. That is what
/// [`RealtimeFlowRegistry::elastic_for_control`] actually builds, so listing
/// its dimensions by hand meant omitting whichever one nobody thought of; a
/// missing `SocketOrHandle` was exactly that.
///
/// The second half is deliberate headroom for the real-time leases the elastic
/// controls take — labels, profiles, flows, output and queued bytes, ready
/// records and packet work. It is generous on purpose and states nothing about
/// policy: an elastic control is about what the path *charges*, not about where
/// it stops, and the controls that care about stopping derive their own grant
/// exactly from the claim under test.
///
/// **The entries are the six dimensions the real-time claim constructors in
/// `realtime.rs` actually name**, not a list of the ones that happened to be
/// needed when it was written — the two byte-denominated classes
/// (`AccountedMemoryBytes` for retention, `QueuedBytes` for what
/// `queue_claim` charges) and the four counted ones. A dimension omitted here
/// is not a smaller grant, it is a zero, so the way this goes wrong is a
/// control failing on a class nobody thought to list. Re-derive by grepping
/// `ResourceClass::` in `realtime.rs` if a claim gains a term.
#[cfg(test)]
fn elastic_control_grant() -> crate::resource::ResourceClaim {
    crate::runtime::attempt::explicit_test_grant(1, 1)
        .checked_add(
            crate::resource::ResourceClaim::try_from_entries([
                (
                    crate::resource::ResourceClass::AccountedMemoryBytes,
                    1 << 24,
                ),
                (crate::resource::ResourceClass::QueuedBytes, 1 << 24),
                (crate::resource::ResourceClass::WorkerOrTask, 64),
                (crate::resource::ResourceClass::CallbackOrScheduledWork, 64),
                (crate::resource::ResourceClass::ParsingOrCpuWork, 64),
                (
                    crate::resource::ResourceClass::OpaqueDependencyResidual,
                    4_096,
                ),
            ])
            .expect("the elastic control headroom is representable"),
        )
        .expect("the elastic control grant is representable")
}

/// A connector work scope granted exactly `identities` track identities and
/// `completion_cells` retirement completion cells.
///
/// Two counts rather than one, because the two are held by different things and
/// the controls take them in different combinations — the losing-retirer control
/// holds one completion cell and no identity at all. Pairing them would hand
/// that control an identity nothing in it holds, and capacity a control does not
/// consume is what stops its refusals from meaning anything.
///
/// Each count counts *reservations*, and each is charged as one: the claim plus
/// the record the provider keeps for it. Summing the claims and charging once
/// would leave the records unfunded without changing any claim, so the shortfall
/// would belong to no term here and surface only as an unrelated-looking refusal.
///
/// At module level rather than inside `mod tests` because the session-flow
/// controls need it too, and a second copy over there could only match this one
/// by luck. The retention comes back with the scope: dropping the candidate
/// would retire the reservation the scope draws from, and a control that
/// discarded it would be minting against a dead provider.
#[cfg(test)]
fn identity_test_scope(
    identities: u64,
    completion_cells: u64,
) -> (
    ConnectorCandidateCapability,
    AttemptLifetime,
    ConnectorWorkResourceScope,
) {
    let per_identity = crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        RealtimeTrackIdentity::mint_claim().expect("the identity claim is representable"),
    )
    .expect("the fixture identity reservation charge is representable");
    let per_completion_cell = crate::resource::FiniteResourceProvider::reservation_charge_for_test(
        RealtimeRetirementSignal::mint_claim().expect("the completion claim is representable"),
    )
    .expect("the fixture completion reservation charge is representable");
    let reservation_work = (0..identities)
        .map(|_| per_identity)
        .chain((0..completion_cells).map(|_| per_completion_cell))
        .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
            total.checked_add(claim)
        })
        .expect("the fixture reservation grant is representable");
    let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
        .checked_add(reservation_work)
        .expect("the fixture provider grant is representable");
    let port = crate::resource::ResourceProviderPort::new(
        crate::resource::FiniteResourceProvider::new(grant),
    )
    .expect("the fixture grant accounts for its process scope");
    let mesh = crate::runtime::attempt::ConnectorResourceOwnerPort::new(port)
        .issue_mesh_scope()
        .expect("the fixture grant accounts for its Mesh scope");
    let (permit, lifetime, claim) = crate::runtime::attempt::admit_single_connector_candidate(
        crate::runtime::runtime_for_test(),
        mesh,
    );
    let candidate = permit
        .reserve_connector_candidate(claim)
        .expect("the fixture grant admits its connector candidate");
    let work_scope = candidate.work_resource_scope();
    (candidate, lifetime, work_scope)
}

/// One negotiated native track for an outbound session flow.
///
/// Opaque to the engine on purpose: it is created by the connector, carried
/// across one await by the engine's negotiation phase, and handed either to
/// [`SessionRealtimeFlows::attach_outbound`] or straight back to the connector
/// for release. The engine can do nothing else with one — it holds no session,
/// no label and no capability, so possession authorizes nothing.
///
/// It carries the connector's own liveness handle alongside the track because
/// the pump needs both and they must not be able to drift: the incarnation is
/// the single authoritative source for whether this connector is still live,
/// and pairing it with the track here means a pump cannot be constructed
/// holding one without the other.
pub(crate) struct RealtimeOutboundTrack {
    track: Arc<TrackLocalStaticSample>,
    /// The only handle the peer connection accepts for detaching this track.
    ///
    /// Dropping it detaches nothing: `remove_track` is what flips the
    /// transceiver's direction and stops the sender, and until it runs the
    /// connection still holds and still offers to send on this m-line.
    sender: Arc<RTCRtpSender>,
    /// Held so whoever owns this value can actually retire it. Removal needs
    /// the connection, not just the sender, so carrying one without the other
    /// would make this type look retirable when it is not.
    pc: Arc<RTCPeerConnection>,
    /// The exact connector this track was negotiated on.
    incarnation: Arc<WebRtcConnectorIncarnation>,
    /// The connector cleanup owner retains the pump until it has observed its
    /// terminal result and the native sender has been removed.
    close_owner: Arc<ConnectorCloseOwner>,
}

impl RealtimeOutboundTrack {
    /// Detach this track from its connection.
    ///
    /// Consuming, because a detached track must not be detachable again. The
    /// pump is the single owner and calls this on **every** exit, so there is
    /// no second caller to race with.
    async fn retire(self) {
        if let Err(error) = self.pc.remove_track(&self.sender).await {
            warn!(?error, "detaching an outbound realtime track");
        }
    }
}

/// A flow's promise that its native half has actually been retired.
///
/// Completed by the pump after `remove_track` returns, so an awaiting close ack
/// means "the sender is gone", not "someone has been asked to remove it".
///
/// **Awaiting it is optional and that is the design.** The pump retires
/// unconditionally on every exit; this only reports when it finished. An
/// explicit close takes the receiver and awaits it outside the fence, so the
/// daemon's ack is truthful. An implicit session drop takes nothing and awaits
/// nothing — the queue dies with the flow set, the pump wakes on that, retires,
/// and completes into a receiver nobody holds. That is why the drop case needs
/// no engine hook and no async `Drop`: the cleanup owner is the pump either
/// way, and only the *reporting* differs.
pub(crate) type RealtimeNativeRetired = tokio::sync::oneshot::Receiver<()>;

/// The connector's view of the **current** session's inbound realtime wiring.
///
/// Two facts, held together because they are only ever meaningful together: the
/// session's binding table, and the transceivers this side created against the
/// tokens on it. Splitting them would allow a transceiver record to outlive the
/// table that gives its token meaning.
///
/// Shared by the worker, which writes it during negotiation, and the `on_track`
/// callback, which reads it when a track arrives.
pub(super) struct RealtimeSessionTracks {
    /// The current session's table, **weakly**.
    ///
    /// Weak is the correctness property, not hygiene. The table's whole job is
    /// to stop admitting media the moment its session ends; a strong reference
    /// here would keep it alive past the `PromotedSession` that owns the flows
    /// it names, leaving a table that still resolves tokens to labels in a flow
    /// set that no longer exists. A failed upgrade is the answer we want, and
    /// it arrives without anything having to be told.
    bindings: SyncMutex<std::sync::Weak<RealtimeInboundBindings>>,
    /// Transceivers created here, each against the token the fence bound before
    /// the transceiver existed.
    ///
    /// A node-leased queue rather than a `Vec`, and the difference is exactness
    /// rather than taste. A `Vec` owns one shared capacity: removing an element
    /// gives back nothing, so a per-record charge released at `forget` would
    /// claim a release the allocator never made, and a growth that reallocated
    /// would move bytes nobody was charged for. One node per entry makes
    /// "recorded" and "one funded allocation" the same event, and makes removal
    /// a release the provider can be told about truthfully.
    negotiated: SyncMutex<crate::resource::LeasedQueue<RealtimeNegotiatedTrack>>,
    /// Runtime-owned observation for every task retained by a negotiated
    /// record or supersession sweep.
    #[cfg(any(test, feature = "transport-lab"))]
    task_reaper: SyncMutex<Option<TaskReaper>>,
    /// The connector owner for production task custody.  A weak reference is
    /// intentional: this table must not keep the connector alive after close.
    cleanup_owner: SyncMutex<Option<Weak<ConnectorCloseOwner>>>,
}

/// One transceiver this side created for a realtime flow.
///
/// It stays on the list from the moment it is created until its stop has
/// *completed*, and the two states are distinguished by `claimed` rather than by
/// presence. That is two properties at once, and neither survives if the record
/// is simply removed when someone decides to retire it:
///
/// - **Exactly one retirer.** Three parties can reach the same transceiver — an
///   explicit close, the pump that was feeding it, and the install that replaces
///   a session — and `claimed` is what makes the second and third arrivals
///   no-ops instead of a second `stop` on a stopped transceiver.
/// - **Classification survives retirement.** `on_track` decides whether a track
///   is realtime-owned by looking this list up. A record removed at the start of
///   a retirement would make a track arriving during it look like a track this
///   side never negotiated — a track the peer named — when in fact it is one we
///   solicited and are in the middle of taking back.
pub(super) type NativeTransceiverStopFuture<'a> =
    Pin<Box<dyn Future<Output = Result<()>> + Send + 'a>>;

/// Owner-private stop boundary for one negotiated inbound transceiver.
///
/// It exists for one reason: a stop that *refuses* is the case the claim
/// retention below is built for, and a real `RTCRtpTransceiver` cannot be made
/// to refuse on demand. Production wraps the dependency's transceiver and does
/// nothing else; a control supplies a twin whose stop reports a failure that has
/// no other way to be reached.
///
/// **The demux question is asked through this trait but is never answered by
/// it.** `matches_native` takes the dependency's own `Arc` and compares it
/// against the dependency's own `Arc`, so the identity a track is classified by
/// is still the pointer to a transceiver this side created — unforgeable,
/// unnameable by the peer, absent from SDP. The port allocation is deliberately
/// *not* the identity: comparing these trait-object `Arc`s would make the wrapper
/// the key, which is one indirection away from the property this whole boundary
/// exists to hold.
pub(super) trait NativeRealtimeTransceiverPort: Send + Sync {
    fn stop(&self) -> NativeTransceiverStopFuture<'_>;

    /// Whether the track that just arrived is carried by *this* transceiver.
    fn matches_native(&self, transceiver: &Arc<RTCRtpTransceiver>) -> bool;
}

/// The production port: the dependency's transceiver and nothing added.
struct WebRtcNativeTransceiverPort {
    transceiver: Arc<RTCRtpTransceiver>,
}

impl NativeRealtimeTransceiverPort for WebRtcNativeTransceiverPort {
    fn stop(&self) -> NativeTransceiverStopFuture<'_> {
        Box::pin(async {
            self.transceiver.stop().await.map_err(|error| {
                Error::Transport(format!("inbound realtime transceiver stop: {error}"))
            })
        })
    }

    fn matches_native(&self, transceiver: &Arc<RTCRtpTransceiver>) -> bool {
        Arc::ptr_eq(&self.transceiver, transceiver)
    }
}

struct RealtimeNegotiatedTrack {
    identity: Arc<RealtimeTrackIdentity>,
    transceiver: Arc<dyn NativeRealtimeTransceiverPort>,
    retirement: RealtimeRetirement,
    /// This transceiver's own exact claim, held for as long as the transceiver
    /// is on the peer connection.
    ///
    /// Separate from everything the *flow* funds, and deliberately so: the flow's
    /// label, port and map node are logical objects whose lifetime ends at the
    /// close, while this names a native object that is still on the connection
    /// after the close returns and until a `stop` has completed. Charging it to
    /// the flow would release it at the wrong moment and would double-bill the
    /// session-flow port besides.
    ///
    /// `Option` because the claim is *moved into the claim that stops it* — the
    /// same reason the transceiver is: the right to release it goes with the
    /// right to stop it, so there is no path that releases a claim for a
    /// transceiver it did not retire.
    native: Option<crate::resource::ResourceLease>,
    /// The callback pump's exact task handle, retained until the same
    /// retirement owner observes its terminal result.
    task: Option<tokio::task::JoinHandle<()>>,
}

/// What the **native half** of one negotiated inbound transceiver costs, for
/// exactly as long as the native object exists.
///
/// Two claims fund a negotiated track, not one, because they have two different
/// lifetimes and two different release conditions:
///
/// - The **record node** is `LeasedQueue::<RealtimeNegotiatedTrack>::entry_claim()`,
///   acquired beside this one and released when the record is forgotten. It is
///   not derived here, and deliberately: the container states its own node cost,
///   so nothing outside it ever writes a node size that could drift from the
///   type.
/// - **This claim** covers what survives until a `stop` completes, and only
///   that. Its release is an observation about the native world; the node's is
///   an observation about this table. Merging them would tie one to the other's
///   evidence.
///
/// Derived from the wrapper allocation this call site actually creates:
///
/// - **Bytes:** `size_of::<WebRtcNativeTransceiverPort>()` plus the counter pair
///   of the `Arc` it lives in — the content of that one block, stated exactly.
///   The record's own bytes are the node's business, not this claim's, and the
///   transceiver's are not a number Rust can state at all.
/// - **Residual, four:** the wrapper `Arc` block itself, then the dependency's
///   transceiver, its RTP receiver, and the media description it adds to the
///   local session. The wrapper is counted honestly as an allocation rather than
///   folded into the bytes above; the other three have no exposed size, and all
///   four are what a completed `stop` gives back.
/// - **Scheduled work, one:** the receiver's read activity. A `recvonly`
///   transceiver is not inert — it goes on running after an implicit teardown —
///   and it is exactly what `stop` retires.
///
/// Nothing here names the flow, the label, the port or the map node. Those are
/// the logical session-flow objects, they are charged where they are allocated,
/// and a transceiver outliving its flow is precisely why the two must not share
/// one claim.
fn negotiated_inbound_transceiver_claim() -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let counters = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let bytes = std::mem::size_of::<WebRtcNativeTransceiverPort>()
        .checked_add(counters)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    crate::resource::ResourceClaim::try_from_entries([
        (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 4),
    ])
}

/// What one record on this table's node-leased queue costs.
///
/// One line, and it exists so no caller ever writes the node's size: the
/// container is the single calibration point for its own representation.
fn negotiated_inbound_record_claim() -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    crate::resource::LeasedQueue::<RealtimeNegotiatedTrack>::entry_claim()
}

/// Who stops one native object, and what everyone else is told.
///
/// Deliberately holds no native object of its own. The two hard parts of this
/// are the claim and the completion, and neither has anything to do with what is
/// being stopped — keeping them separate is what lets a control exercise the
/// race directly instead of standing up a peer connection to reach it.
/// One retirement attempt's terminal state, and the charge for saying so.
///
/// **It states that the attempt ended, not that the transceiver stopped.** Those
/// came apart the moment a refused stop and a refused cleanup submission both
/// became outcomes this connector survives: in either case the native object is
/// still there, its charge has moved to failed-cleanup retention, and no further
/// attempt will be made. A waiter still has to be released — it is waiting to
/// find out whether the work is over, not whether it succeeded — so the cell
/// carries exactly that and nothing a caller could mistake for success.
///
/// Waiters take `()` deliberately. Every party that can park here is one that
/// would do the same thing with either answer: an explicit close returns to its
/// caller, a superseding install moves to the next record. Handing them an
/// outcome would be handing them a decision none of them makes.
///
/// **A flag plus a wake, not a channel.** Completion is a *state*: a waiter that
/// arrives after the stop has already finished must still see it, which a bare
/// notification cannot promise. A `watch` would give that, but a `watch` is two
/// allocations this module would then be funding — the sender's `Arc` and the
/// channel's own shared state — and the second is not a size Rust will state.
/// An `AtomicBool` read before and after registering gives the same guarantee in
/// one allocation whose bytes are exact.
///
/// **The funding must outlive every waiter, and the allocation too.** Every
/// claimant and every waiter holds a handle to this cell and any of them can
/// outlive the table's record, so a lease held by the record would tell the
/// provider this allocation was gone while a loser was still parked on it. That
/// is why the funding is not on the record — and keeping it *inside* this
/// struct would only move the problem: a lease among these fields is released
/// by this value's own drop glue, while the allocation is still there.
///
/// [`FundedArc`] answers both at once. Every handle shares the one reservation,
/// so the charge spans every waiter; and the token sits beside the pointer, so
/// it is released only after the allocation is genuinely gone.
struct RealtimeRetirementSignal {
    /// Flips once the responsibility has been *discharged*.
    done: AtomicBool,
    /// Wakes everyone parked, exactly once, after `done` is already `true`.
    wake: tokio::sync::Notify,
}

impl RealtimeRetirementSignal {
    /// Exactly what one completion cell costs.
    fn mint_claim() -> std::result::Result<
        crate::resource::ResourceClaim,
        crate::resource::ResourceClaimArithmeticError,
    > {
        let counters = std::mem::size_of::<usize>().checked_mul(2).ok_or(
            crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            },
        )?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(counters)
            .and_then(|bytes| u64::try_from(bytes).ok())
            .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
                dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
            })?;
        // Two residuals: this `Arc` block, and the `Notify` wait list the
        // dependency grows on demand and whose size it does not expose.
        crate::resource::ResourceClaim::try_from_entries([
            (crate::resource::ResourceClass::AccountedMemoryBytes, bytes),
            (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
        ])
    }

    fn mint(lease: crate::resource::ResourceLease) -> crate::resource::FundedArc<Self> {
        crate::resource::FundedArc::new(
            Self {
                done: AtomicBool::new(false),
                wake: tokio::sync::Notify::new(),
            },
            lease,
        )
        .expect("an admitted completion-cell lease may be shared")
    }

    /// Announce that the retirement attempt has ended, however it ended.
    ///
    /// The flag is set *before* the wake, so a waiter that races the wake finds
    /// the state already true on its recheck rather than parking on a
    /// notification that has been and gone.
    fn finish(&self) {
        self.done.store(true, Ordering::Release);
        self.wake.notify_waiters();
    }

    fn is_done(&self) -> bool {
        self.done.load(Ordering::Acquire)
    }
}

struct RealtimeRetirement {
    /// Whether someone has already taken responsibility.
    claimed: bool,
    /// What everyone else is told once that responsibility is discharged.
    ///
    /// Single ownership decides who acts; this decides what the others learn. A
    /// caller that loses the claim must not return as though the work were done
    /// — on an explicit close that return is the daemon's acknowledgement, and
    /// answering while the winner's attempt is still outstanding would let a
    /// reopen on the same label race a transceiver still offering to receive. So
    /// a loser waits here instead of no-opping.
    ///
    /// Whoever takes the claim owes this announcement on **every** path that
    /// ends the attempt, including the ones that end it without stopping
    /// anything. A claimant that returned without announcing would leave every
    /// later loser parked on a completion nobody is left to make.
    done: crate::resource::FundedArc<RealtimeRetirementSignal>,
}

/// What a won claim carries out of the lock: the right to stop this one thing,
/// the obligation to announce that it is stopped, and the exact claim that
/// answers for it until then.
struct RealtimeTrackClaim {
    identity: Arc<RealtimeTrackIdentity>,
    transceiver: Arc<dyn NativeRealtimeTransceiverPort>,
    done: crate::resource::FundedArc<RealtimeRetirementSignal>,
    /// Taken out of the record with the claim, so the transceiver's own charge
    /// travels with the one party that may retire it.
    ///
    /// `None` only for a record negotiated before this claim existed, which
    /// production cannot produce — every recorded transceiver is recorded with
    /// its lease — and which is therefore a release of nothing rather than a
    /// branch anyone has to reason about.
    native: Option<crate::resource::ResourceLease>,
    task: Option<tokio::task::JoinHandle<()>>,
}

impl RealtimeRetirement {
    fn new(signal: crate::resource::ResourceLease) -> Self {
        Self {
            claimed: false,
            done: RealtimeRetirementSignal::mint(signal),
        }
    }

    /// Take responsibility, or find out who already has.
    ///
    /// `Ok` is the claim and comes with the cell to announce on. `Err` is a
    /// subscription to the winner's announcement — not a refusal, and never to
    /// be treated as "already done". Both arms are the same allocation, which is
    /// what makes a loser's wait and a winner's announcement the same fact.
    fn claim(
        &mut self,
    ) -> std::result::Result<
        crate::resource::FundedArc<RealtimeRetirementSignal>,
        crate::resource::FundedArc<RealtimeRetirementSignal>,
    > {
        if self.claimed {
            return Err(self.done.clone());
        }
        self.claimed = true;
        Ok(self.done.clone())
    }
}

/// One negotiated inbound transceiver's retirement, owned by whatever holds the
/// flow it belongs to.
///
/// **It submits on drop, and that is the whole point.** An explicit close takes
/// the submission out and awaits the receipt. Every other way a flow ends —
/// policy revocation, peer replacement, shutdown, the promoted session simply
/// going — reaches only this drop, and starting nothing here would leave an `m`
/// line, a `recvonly` transceiver and its read activity on a connector that may
/// well go on hosting another session. The superseding install does sweep
/// those, but only when a *next* session is promoted, so on a connector that
/// hosts no further session such a leak would have no end.
///
/// **Exactly-once is the existing claim, not a new flag.** Four parties can
/// reach one transceiver — an explicit close, the pump that was feeding it, the
/// install that supersedes the session, and now this drop — and all four go
/// through `RealtimeRetirement::claim`. Whichever arrives first is the only one
/// that attempts a stop, and the claim carries the *outcome* through as well: an
/// attempt that ends without stopping the transceiver announces itself as ended
/// so no later party is left waiting, moves the native charge into failed-cleanup
/// retention rather than releasing it, and leaves the record in place so an
/// arriving track is still classified as one this side solicited. Exactly one
/// attempt, and no path that quietly pretends it worked.
///
/// The table is held **weakly**, for the same reason the bindings are: a
/// remainder must not keep a connector's track table alive past the connector.
/// A failed upgrade means the whole peer connection is already gone, which
/// retires every transceiver on it — so there is nothing left to submit.
///
/// **Nothing here depends on a runtime being present.** The submission goes to
/// the process cleanup executor, which owns its own thread and its own runtime,
/// through a port that is a synchronous send. A destructor running during an
/// unwind, on a bare thread, or after the local runtime has already gone reaches
/// exactly the same executor as one running inside a task. That is the whole
/// reason the port is carried rather than looked up: by the time this drops
/// there is nobody left to ask.
pub(crate) struct RealtimeInboundRetirement {
    identity: Arc<RealtimeTrackIdentity>,
    /// The submission, taken by an explicit close that will await the receipt
    /// itself. `None` afterwards, so the drop below submits nothing and the two
    /// paths cannot both enqueue for one transceiver.
    tracks: Option<std::sync::Weak<RealtimeSessionTracks>>,
    /// Where a retirement goes to be performed.
    submission: crate::runtime::attempt::ConnectorCleanupSubmissionPort,
    /// This retirement's queue slot, acquired when the flow was bound rather
    /// than when it ended.
    ///
    /// Reserve-before-need, and the timing is the point: a submission that had
    /// to acquire at drop time could be refused at the one moment its caller has
    /// no way to react and no way to report. Paying for the slot up front turns
    /// "can this connector afford to clean up?" into a question answered while
    /// the flow is still being opened, where a refusal is an ordinary refusal.
    ///
    /// `None` once submitted or once taken by an explicit close, which is what
    /// makes the slot fund exactly one submission.
    slot: Option<crate::resource::ResourceLease>,
    /// Shared flow-set witness retained by the actual cleanup owner until the
    /// native retirement reaches a terminal result, even if the close waiter
    /// is dropped.
    tail: Option<session_flow::RealtimeNativeTail>,
}

impl RealtimeInboundRetirement {
    /// Take the submission for a caller that will retire the transceiver itself
    /// and await the receipt.
    ///
    /// Disarms the drop, so an explicit close is still the single submitter on
    /// its own path. The token comes back because the caller needs it to name
    /// what it is closing.
    pub(crate) fn take_for_explicit_close(&mut self) -> Arc<RealtimeTrackIdentity> {
        self.tracks = None;
        // The queue slot goes back with it. An explicit close runs the
        // retirement on the caller's own task and queues nothing, so holding a
        // slot for a submission that will never be made would charge this
        // connector for an empty seat.
        self.slot = None;
        Arc::clone(&self.identity)
    }

    fn attach_native_tail(&mut self, tail: session_flow::RealtimeNativeTail) {
        debug_assert!(self.tail.is_none(), "inbound retirement received two tails");
        self.tail = Some(tail);
    }

    /// Which token this retirement is for, for controls that need to say *which*
    /// transceiver a close handed back.
    ///
    /// Read-only and test-only on purpose: production has no reason to ask,
    /// because every production path either takes the submission or drops it.
    #[cfg(test)]
    pub(crate) fn identity(&self) -> &Arc<RealtimeTrackIdentity> {
        &self.identity
    }

    /// Whether this retirement will still submit when it is dropped.
    ///
    /// The observable half of the exactly-once property: a close that took the
    /// submission must leave this `false`, so a control can tell "the drop was
    /// disarmed" from "the drop happened to find nothing".
    #[cfg(test)]
    pub(crate) fn submits_on_drop(&self) -> bool {
        self.tracks.is_some()
    }
}

impl Drop for RealtimeInboundRetirement {
    fn drop(&mut self) {
        let Some(tracks) = self
            .tracks
            .take()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            // Either an explicit close took the submission, or the connector
            // that owned the transceiver is gone and took it along.
            return;
        };
        let Some(slot) = self.slot.take() else {
            // The slot and the table are set and cleared together, so this is
            // unreachable; if it were reached, submitting without the slot the
            // job is funded by would be the one thing worse than not
            // submitting, because it would queue work this connector never paid
            // for.
            warn!("an inbound realtime retirement reached its drop with no submission slot");
            return;
        };
        let identity = Arc::clone(&self.identity);
        let tail = self.tail.take();
        let failed = Arc::clone(&tracks);
        let failed_identity = Arc::clone(&identity);
        // Synchronous. The executor owns the thread and the runtime that will
        // await this future, so nothing here needs one — which is what makes the
        // implicit-teardown path work from an unwind, from a bare thread, and
        // from a runtime that is itself shutting down.
        let submitted = self.submission.submit_subordinate(
            slot,
            Box::pin(async move {
                let _tail = tail;
                tracks.stop_claimed(&identity).await;
            }),
            Box::new(|| {}),
            Box::new(move |reason| {
                // The executor refused or died, so this transceiver will not be
                // stopped by anyone. Nothing observed the native object go, so
                // its exact charge is moved to the provider's failed-cleanup
                // retention rather than released — the same conservative
                // direction the connector's own close takes, and for the same
                // reason: an unprovable release is not a release.
                warn!(
                    %reason,
                    "the process cleanup executor refused an inbound realtime retirement"
                );
                failed.retain_after_failed_submission(&failed_identity);
            }),
        );
        // A refused submission retains the job in this answer, and dropping the
        // answer drops the job and runs the failure callback above. Explicit
        // rather than implicit so the retention is not an accident of where a
        // value happened to fall out of scope.
        drop(submitted);
    }
}

/// Wait for the caller who won a claim to finish trying.
///
/// Returns when the winning attempt is over, whichever way it went. It is not a
/// success signal and nothing downstream treats it as one.
///
/// Check, register, recheck — the standard shape, and it is the reason the flag
/// and the wake are separate. Registering before the second read is what makes a
/// completion that lands in between impossible to miss; reading before
/// registering is what makes a completion that already happened return
/// immediately. Neither alone is sufficient and this is not a retry loop: it
/// goes round only when a spurious wake arrives.
async fn await_retirement(done: crate::resource::FundedArc<RealtimeRetirementSignal>) {
    loop {
        if done.is_done() {
            return;
        }
        let notified = done.wake.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if done.is_done() {
            return;
        }
        notified.await;
    }
}

impl Default for RealtimeSessionTracks {
    fn default() -> Self {
        Self {
            bindings: SyncMutex::new(std::sync::Weak::new()),
            negotiated: SyncMutex::new(crate::resource::LeasedQueue::new()),
            #[cfg(any(test, feature = "transport-lab"))]
            task_reaper: SyncMutex::new(None),
            cleanup_owner: SyncMutex::new(None),
        }
    }
}

impl RealtimeSessionTracks {
    #[cfg(any(test, feature = "transport-lab"))]
    fn with_task_reaper(task_reaper: TaskReaper) -> Self {
        Self {
            bindings: SyncMutex::new(std::sync::Weak::new()),
            negotiated: SyncMutex::new(crate::resource::LeasedQueue::new()),
            task_reaper: SyncMutex::new(Some(task_reaper)),
            cleanup_owner: SyncMutex::new(None),
        }
    }

    fn bind_cleanup_owner(&self, owner: &Arc<ConnectorCloseOwner>) {
        *self.cleanup_owner.lock() = Some(Arc::downgrade(owner));
    }

    fn submit_tasks(&self, tasks: Vec<tokio::task::JoinHandle<()>>) {
        if tasks.is_empty() {
            return;
        }
        #[cfg(not(any(test, feature = "transport-lab")))]
        {
            let owner = self
                .cleanup_owner
                .lock()
                .as_ref()
                .and_then(Weak::upgrade)
                .expect("production realtime tracks are bound to their close owner");
            for task in tasks {
                owner.retain_transport_task(task);
            }
        }
        #[cfg(any(test, feature = "transport-lab"))]
        {
            if let Some(owner) = self.cleanup_owner.lock().as_ref().and_then(Weak::upgrade) {
                for task in tasks {
                    owner.retain_transport_task(task);
                }
                return;
            }
            let reaper = self.task_reaper.lock();
            let reaper = reaper
                .as_ref()
                .expect("raw transport tracks require pre-existing task custody");
            let sender = reaper
                .sender()
                .expect("raw transport task custody is still open while submitting");
            submit_task_batch(sender, tasks);
        }
    }

    /// Point at a newly promoted session's table, replacing any previous one,
    /// and retire everything the old session left behind.
    ///
    /// **Retire, not clear.** The old records' tokens were bound in a table that
    /// died with its session, so none of them will ever admit a track again —
    /// but the transceivers are still on the peer connection, still `recvonly`,
    /// and dropping the records would leave nothing able to name them. That is
    /// the leak for the case with no other owner at all: a flow whose transceiver
    /// was created and whose track never arrived has no pump, so the pump's own
    /// cleanup never runs and this is the only sweep that reaches it.
    ///
    /// Claimed synchronously, stopped asynchronously. The claim is what makes
    /// this disjoint from an old pump racing the same edge — whichever gets
    /// there first is the only one that stops — and it happens under the same
    /// lock acquisition that replaces the table, so there is no window in which
    /// a record is neither this install's responsibility nor its previous
    /// owner's. The records stay on the list until their stops complete, so a
    /// late track arriving on one is still classified as realtime-owned and
    /// refused for the reason it was actually refused for.
    fn install(self: &Arc<Self>, bindings: std::sync::Weak<RealtimeInboundBindings>) {
        // Order matters only in that both are replaced before anything can
        // observe a half-installed pair; each lock is taken and released on its
        // own, and `on_track` reads them in the opposite order, so no caller
        // can hold one while waiting on the other.
        *self.bindings.lock() = bindings;
        // Claimed *and* taken in one locked pass. Marking here and re-claiming
        // on the task would find every record already claimed and stop nothing,
        // so the transceiver comes out with the claim rather than being looked
        // up again from a token whose record now says someone else owns it.
        let superseded: Vec<RealtimeTrackClaim> = {
            let mut negotiated = self.negotiated.lock();
            negotiated
                .iter_mut()
                .filter_map(|track| {
                    let done = track.retirement.claim().ok()?;
                    Some(RealtimeTrackClaim {
                        identity: Arc::clone(&track.identity),
                        transceiver: Arc::clone(&track.transceiver),
                        done,
                        // Taken, not cloned: a lease is move-only, and the
                        // sweep that wins the claim is the party that will
                        // answer for this charge.
                        native: track.native.take(),
                        task: track.task.take(),
                    })
                })
                .collect()
        };
        if superseded.is_empty() {
            return;
        }
        let tracks = Arc::clone(self);
        // Nobody acknowledges a superseded session's teardown, so the bounded
        // reaper observes this sweep instead of making the install await it.
        let sweep = tokio::spawn(async move {
            for claim in superseded {
                tracks.stop_owned(claim).await;
            }
        });
        self.submit_tasks(vec![sweep]);
    }

    /// The current table, if its session is still alive.
    fn current(&self) -> Option<Arc<RealtimeInboundBindings>> {
        self.bindings.lock().upgrade()
    }

    /// Record one transceiver this side created, together with the two claims
    /// that answer for it.
    ///
    /// Both leases arrive already acquired, because both acquisitions happen
    /// *before* the transceiver exists: a connector that cannot fund the record
    /// or the native object must refuse to create one rather than create it and
    /// then discover it cannot pay.
    ///
    /// `record` funds the queue node and is released when the record is
    /// forgotten. `signal` funds the completion cell and is released when the
    /// last claimant or waiter drops it, which can be later. `native` funds the
    /// wrapper and the dependency's own objects and is released only when a
    /// `stop` has completed. Three leases and not a sum, because those are three
    /// different moments proved by three different observations.
    ///
    /// The identity's own lease is not among them: it was acquired where the
    /// identity was minted, before this table ever saw it, and it lives inside
    /// that allocation.
    fn record(
        &self,
        identity: Arc<RealtimeTrackIdentity>,
        transceiver: Arc<dyn NativeRealtimeTransceiverPort>,
        record: crate::resource::ResourceLease,
        signal: crate::resource::ResourceLease,
        native: crate::resource::ResourceLease,
    ) {
        self.negotiated.lock().push(
            RealtimeNegotiatedTrack {
                identity,
                transceiver,
                retirement: RealtimeRetirement::new(signal),
                native: Some(native),
                task: None,
            },
            record,
        );
    }

    /// Attach the callback task to the same bounded record that owns its
    /// transceiver. A claimed or missing record returns the handle so the
    /// caller can abort and route it through the reaper rather than dropping it.
    fn attach_task(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
        task: tokio::task::JoinHandle<()>,
    ) -> std::result::Result<(), tokio::task::JoinHandle<()>> {
        let mut negotiated = self.negotiated.lock();
        let Some(track) = negotiated
            .iter_mut()
            .find(|track| Arc::ptr_eq(&track.identity, identity))
        else {
            return Err(task);
        };
        if track.retirement.claimed || track.task.is_some() {
            return Err(task);
        }
        track.task = Some(task);
        Ok(())
    }

    /// The token a track arriving on `transceiver` was negotiated against.
    ///
    /// **Pointer identity against a transceiver this side created**, which is
    /// the strongest form the demux key can take: the peer cannot produce one,
    /// cannot name one, and nothing about it appears in SDP.
    ///
    /// If a future `webrtc` release stopped handing `on_track` the same `Arc`
    /// the connection stores, this answers `None` and the track is dropped.
    /// That is the intended degradation — a refusal, never a misattachment.
    /// The obvious fallback, comparing MIDs, is deliberately absent: a MID is a
    /// string that appears in SDP, and reintroducing it as a key is exactly the
    /// property this token was minted to remove.
    /// Answers for a retiring record as readily as for a live one. The question
    /// it exists to settle is "did this side create this transceiver for a
    /// realtime flow", and the answer to that does not change when someone
    /// starts stopping it.
    /// Asked through the port, answered by the native pointer. A port is a stop
    /// boundary and never a key: `matches_native` compares the dependency's own
    /// `Arc` against the one `on_track` was handed, so what identifies a track
    /// is unchanged by the wrapper existing. A control's twin holds no native
    /// transceiver and therefore matches nothing, which is the right answer —
    /// a fixture record must never be able to claim a real arriving track.
    fn resolve(&self, transceiver: &Arc<RTCRtpTransceiver>) -> Option<Arc<RealtimeTrackIdentity>> {
        // Bound rather than chained: iterating this queue may merge its two
        // chains, which is a change to the representation and therefore takes
        // `&mut`. The guard has to be a named place for that borrow to be taken
        // from.
        let mut negotiated = self.negotiated.lock();
        negotiated
            .iter()
            .find(|track| track.transceiver.matches_native(transceiver))
            .map(|track| Arc::clone(&track.identity))
    }

    /// Whether this table would still classify a track negotiated against
    /// `identity` as one this side solicited.
    ///
    /// The record-presence half of [`Self::resolve`], which is the half a
    /// control can reach: the other half compares against a real
    /// `Arc<RTCRtpTransceiver>`, and only a live peer connection can produce
    /// one. Same lookup, same lock, same list — so a record this answers `false`
    /// for is one `resolve` could not find either.
    #[cfg(test)]
    fn classifies(&self, identity: &Arc<RealtimeTrackIdentity>) -> bool {
        let mut negotiated = self.negotiated.lock();
        negotiated
            .iter()
            .any(|track| Arc::ptr_eq(&track.identity, identity))
    }

    /// The drop-safe retirement owner for one token this table will negotiate.
    ///
    /// Minted before the transceiver exists and handed to the flow, so the flow
    /// carries its own retirement from the moment it has one to carry. Every way
    /// that flow can end therefore ends with a submission, rather than only the
    /// one way that remembered to make it.
    ///
    /// It arrives complete: the port it will submit through and the queue slot
    /// that submission is funded by are both fixed here, while there is still a
    /// caller able to hear a refusal.
    fn retirement(
        self: &Arc<Self>,
        identity: Arc<RealtimeTrackIdentity>,
        submission: crate::runtime::attempt::ConnectorCleanupSubmissionPort,
        slot: crate::resource::ResourceLease,
    ) -> RealtimeInboundRetirement {
        RealtimeInboundRetirement {
            identity,
            tracks: Some(Arc::downgrade(self)),
            submission,
            slot: Some(slot),
            tail: None,
        }
    }

    /// Drop one record, once its transceiver really is stopped.
    ///
    /// Called from exactly one place and only on a completed stop, because the
    /// record is what classifies an arriving track and a transceiver that is
    /// still there must stay classifiable.
    ///
    /// The node goes with it, and that is a real release rather than a
    /// bookkeeping one: one entry is one allocation here, so removing it hands
    /// its exact claim back to the provider at the moment the memory is freed.
    fn forget(&self, identity: &Arc<RealtimeTrackIdentity>) {
        self.negotiated
            .lock()
            .retain(|track| !Arc::ptr_eq(&track.identity, identity));
    }

    /// Retire one token's transceiver, and do not return until the attempt is
    /// over.
    ///
    /// The whole retirement path, and the only one. Four parties reach it — an
    /// explicit close, the pump that was feeding the flow, the install that
    /// supersedes the session, and a dropped [`RealtimeInboundRetirement`] — and
    /// none can know which of the others got there first, so the answer comes
    /// from the record rather than from an ordering rule each of them has to
    /// remember.
    ///
    /// All three outcomes end with the retirement **settled** by the time this
    /// returns: the caller that wins the claim attempts the stop, a caller that
    /// loses waits for the winner, and a caller that finds no record at all is
    /// looking at a retirement that already completed and was forgotten. That
    /// uniformity is what makes it safe for the daemon to acknowledge a close as
    /// soon as this returns.
    ///
    /// **Settled is not the same as stopped**, and the difference is deliberate
    /// rather than hidden. A stop the dependency refuses leaves the transceiver
    /// in place, its charge in failed-cleanup retention, and its record on this
    /// table so an arriving track is still classified correctly. What a caller
    /// learns is that nothing further will be attempted — which is the honest
    /// answer, and the only one that keeps a close from hanging on a refusal
    /// nobody can retry.
    async fn stop_claimed(&self, identity: &Arc<RealtimeTrackIdentity>) {
        // Claimed under the lock, stopped outside it: `stop` awaits and the
        // record list is guarded by a sync mutex.
        let claim = {
            let mut negotiated = self.negotiated.lock();
            let Some(track) = negotiated
                .iter_mut()
                .find(|track| Arc::ptr_eq(&track.identity, identity))
            else {
                // No record: already stopped and forgotten.
                return;
            };
            match track.retirement.claim() {
                Ok(done) => Ok(RealtimeTrackClaim {
                    identity: Arc::clone(identity),
                    transceiver: Arc::clone(&track.transceiver),
                    done,
                    // Moves with the claim, so the winner is the only party
                    // that can release or retain it. A loser waits for the
                    // winner's announcement and holds nothing.
                    native: track.native.take(),
                    task: track.task.take(),
                }),
                Err(waiting) => Err(waiting),
            }
        };
        match claim {
            Ok(claim) => self.stop_owned(claim).await,
            Err(waiting) => await_retirement(waiting).await,
        }
    }

    /// Give up on retiring one transceiver, keeping its charge counted.
    ///
    /// The end of the only path that cannot be completed: the cleanup executor
    /// refused or died, so nothing will ever run this record's `stop`. The
    /// record is claimed exactly as a real retirement would claim it — so a
    /// party that later reaches the same token finds it taken rather than
    /// starting a stop that has already been abandoned — and its exact charge
    /// goes to the provider's failed-cleanup retention instead of being
    /// released.
    ///
    /// **The attempt is announced as ended**, and that is not a claim that the
    /// transceiver stopped — nothing here stops anything. The completion cell
    /// states that the retirement attempt reached a terminal outcome, which is
    /// all any waiter needs and all any waiter is told. Leaving it unannounced
    /// would park every later loser forever: this claim is the winning attempt,
    /// so nobody else will ever announce, and a `stop_claimed` arriving
    /// afterwards would wait on a completion that cannot come.
    ///
    /// Announced **after** the charge is retained, so a waiter released by it
    /// cannot observe the accounting mid-transition.
    ///
    /// The record stays on the list. Classification survives an abandoned
    /// retirement for the same reason it survives a running one: a track
    /// arriving on that transceiver is still one this side negotiated, and this
    /// transceiver is demonstrably still there.
    fn retain_after_failed_submission(&self, identity: &Arc<RealtimeTrackIdentity>) {
        let mut negotiated = self.negotiated.lock();
        let Some(track) = negotiated
            .iter_mut()
            .find(|track| Arc::ptr_eq(&track.identity, identity))
        else {
            return;
        };
        let Ok(done) = track.retirement.claim() else {
            // Someone else owns this retirement and will finish it — and will
            // announce it. Their claim carries the charge, so there is nothing
            // here to retain and nothing here to say.
            return;
        };
        let task = track.task.take();
        if let Some(native) = track.native.take() {
            let _ = native.retain_after_failed_cleanup();
        }
        drop(negotiated);
        if let Some(task) = task {
            task.abort();
            self.submit_tasks(vec![task]);
        }
        done.finish();
    }

    /// Finish a retirement whose claim the caller already holds.
    ///
    /// Taking the claim by value is what says the right to stop came with it:
    /// there is no path here that looks a token up and stops whatever it finds.
    ///
    /// **Removal is success-only.** A record is what makes an arriving track
    /// classifiable as one this side negotiated, and a stop that *refused* has
    /// left the transceiver on the peer connection — still `recvonly`, still
    /// able to deliver. Deleting the record there would strip the classification
    /// off a live transceiver and turn its next track into one this side appears
    /// never to have solicited. So a failed stop keeps the record, and keeps its
    /// node charged, for the same reason it keeps the native claim: nothing
    /// observed the object go.
    ///
    /// The retained record stays *claimed*, so no later party starts a second
    /// stop on it. There is no second retirement owner and no retry.
    async fn stop_owned(&self, claim: RealtimeTrackClaim) {
        let RealtimeTrackClaim {
            identity,
            transceiver,
            done,
            native,
            task,
        } = claim;
        if let Some(task) = task {
            task.abort();
            join_task_batch(vec![task]).await;
        }
        let stopped = transceiver.stop().await;
        match stopped {
            // The stop returned, so the native object it named is gone and its
            // charge is released here — after the stop, never before it. A
            // release ahead of the stop would let the next admission be granted
            // capacity this connector had not actually given back yet.
            Ok(()) => drop(native),
            Err(ref error) => {
                // The flow is going away regardless, and a teardown is not worth
                // failing over a stop that refused — but the charge must not be
                // released, because nothing observed the native object go. It
                // moves to the provider's failed-cleanup retention instead,
                // where it stays counted against this process and is never
                // handed out again. Conservative in exactly the direction the
                // rest of this connector's cleanup is: an unprovable release is
                // treated as no release.
                warn!(%error, "stopping a negotiated inbound realtime transceiver");
                if let Some(native) = native {
                    let _ = native.retain_after_failed_cleanup();
                }
            }
        }
        // Announced either way, because what this states is that the *attempt*
        // has ended — not that the transceiver stopped. A loser that parked on
        // this must be released whichever way the winner's stop went; leaving it
        // parked on a refusal would wedge an explicit close forever, which is a
        // worse answer than an honest one.
        done.finish();
        if stopped.is_ok() {
            // Last, and only here, so the record stays resolvable for the whole
            // of the stop — and permanently if the stop refused.
            self.forget(&identity);
        }
    }

    /// Extract every callback pump before the connector close owner is allowed
    /// to publish terminal status. The operation fence is drained by the
    /// caller first, so no callback can attach a successor after this pass.
    fn prepare_for_close(&self) {
        let tasks = {
            let mut negotiated = self.negotiated.lock();
            negotiated
                .iter_mut()
                .filter_map(|track| track.task.take())
                .collect::<Vec<_>>()
        };
        self.submit_tasks(tasks);
    }

    /// Seal production task admission after the operation fence and record
    /// extraction have completed. This is the final barrier before native
    /// close; a task arriving afterwards is a diagnosed invariant violation,
    /// never silently detached.
    fn seal_for_close(&self) {
        if let Some(owner) = self.cleanup_owner.lock().as_ref().and_then(Weak::upgrade) {
            owner.seal_transport_tasks();
        }
    }

    /// Close the task handoff and await its runtime-owned reaper. The sender
    /// is taken before the await, so no registry lock crosses a suspension
    /// point and no later callback can enqueue after the fence closes.
    async fn wait_for_tasks(&self) {
        #[cfg(not(any(test, feature = "transport-lab")))]
        return;
        #[cfg(any(test, feature = "transport-lab"))]
        let Some(reaper) = self.task_reaper.lock().take() else {
            return;
        };
        #[cfg(any(test, feature = "transport-lab"))]
        reaper.wait().await;
    }
}

impl Drop for RealtimeSessionTracks {
    fn drop(&mut self) {
        let tasks = {
            let mut negotiated = self.negotiated.lock();
            negotiated
                .iter_mut()
                .filter_map(|track| track.task.take())
                .collect::<Vec<_>>()
        };
        if !tasks.is_empty() {
            for task in &tasks {
                task.abort();
            }
            self.submit_tasks(tasks);
        }
        // A worker dropped without an async close still has to close the
        // production admission window.  The owner will already have fenced
        // operations; sealing here publishes the exact end of this registry's
        // task custody before the owner performs its final join/native close.
        if let Some(owner) = self.cleanup_owner.lock().as_ref().and_then(Weak::upgrade) {
            owner.seal_transport_tasks();
        }
        // Sender drop closes the reaper after the moved batch has been joined.
        #[cfg(any(test, feature = "transport-lab"))]
        self.task_reaper.lock().take();
    }
}

/// The RTP transceiver primitive one encoding negotiates.
///
/// A total map, and the only place this module turns the application's declared
/// media kind into the library's. It reads no MIME name.
fn native_codec_type(kind: WebRtcRtpKind) -> RTPCodecType {
    match kind {
        WebRtcRtpKind::Audio => RTPCodecType::Audio,
        WebRtcRtpKind::Video => RTPCodecType::Video,
    }
}

/// The declared media kind a negotiated track carries.
///
/// The inverse of [`native_codec_type`], for the admission comparison. The
/// library's enum is `non_exhaustive` in practice — it carries an
/// `Unspecified` — and anything that is neither audio nor video is mapped to
/// `None` rather than guessed: an unspecified kind matches no binding, and a
/// track that matches no binding is dropped.
fn native_rtp_kind(kind: RTPCodecType) -> Option<WebRtcRtpKind> {
    match kind {
        RTPCodecType::Audio => Some(WebRtcRtpKind::Audio),
        RTPCodecType::Video => Some(WebRtcRtpKind::Video),
        _ => None,
    }
}

/// Drain one outbound session flow onto its negotiated native track, and retire
/// that track when the flow ends.
///
/// **The pump is the single owner of the native half.** It holds the track, the
/// sender and the connection, and on *every* exit — closed queue, retired
/// connector, failed write — it awaits `remove_track` before returning. Nothing
/// else may detach, so there is no double-remove to prevent and no flag to keep
/// in step.
///
/// That ownership is what closes the implicit case as well as the explicit one.
/// Dropping a `SessionRealtimeFlows` with live flows drops their queues; each
/// pump wakes on that, retires its track, and completes. No async `Drop` is
/// needed anywhere, and session retirement does not have to be distinguished
/// from an application close — the pump cannot tell them apart and does not
/// need to.
///
/// Dropping the sender `Arc` is **not** a detach. `remove_track` is what flips
/// the transceiver direction and stops the sender
/// (`peer_connection/mod.rs:1786-1791` in the vendored crate); until it runs the
/// connection still offers to send on that m-line. An earlier version of this
/// pump held the sender as `_sender` and returned, which retired nothing.
///
/// Two rechecks per unit, and both are needed:
///
/// - the queue upgrade, which is the **session** check. The queue is owned by
///   the flow, the flow by the flow set, the flow set by `PromotedSession`, so
///   a failed upgrade means the session that authorized this flow is gone.
///   Nothing else has to be consulted, and nothing else could be — the pump
///   runs outside the registry fence and cannot take it.
/// - `is_active`, which is the **connector** check. A connector can retire
///   while its session is still promoted, and writing to a retired
///   connector's track would push bytes through a transport this side has
///   already given up.
///
/// The write itself happens here rather than under the fence because it awaits,
/// and the fence is a sync mutex that connector replacement also takes.
///
/// Private, matching its parameter. `RealtimeOutboundPump` is `pub(super)` in
/// the flow module — visible exactly within the connector — so a `pub(super)`
/// here would have published a function whose argument type its own audience
/// could not name. Module privacy already reaches the one caller,
/// `attach_outbound`, which is a descendant of this module; nothing wider ever
/// needed it, and narrowing the function is the fix rather than widening the
/// pump, which would hand out a way to write to a flow's queue.
fn spawn_outbound_realtime_pump(
    pump: session_flow::RealtimeOutboundPump,
    track: RealtimeOutboundTrack,
    retired: tokio::sync::oneshot::Sender<()>,
) {
    let close_owner = Arc::clone(&track.close_owner);
    let task = tokio::spawn(async move {
        // One exit point, so "retire on every exit" is structural rather than a
        // rule each `return` has to remember. The inner block produces nothing;
        // everything after it runs however it ended.
        let incarnation = Arc::clone(&track.incarnation);
        let native = Arc::clone(&track.track);
        async {
            loop {
                match pump.next() {
                    session_flow::RealtimePumpStep::Unit(unit) => {
                        // Checked per unit rather than once at attach. A pump
                        // that proved liveness only when it started would keep
                        // writing for as long as the application kept feeding
                        // it.
                        if !incarnation.is_active() {
                            return;
                        }
                        if native
                            .write_sample(&Sample {
                                data: unit.data,
                                duration: unit.pace,
                                ..Default::default()
                            })
                            .await
                            .is_err()
                        {
                            // The native track is gone. Ending is the whole
                            // response; the retirement below still runs.
                            return;
                        }
                    }
                    // Nothing queued on a live flow is idle, not closed. Park.
                    session_flow::RealtimePumpStep::Empty => pump.ready().await,
                    // Terminal. The flow, and so the session, is gone. This is
                    // the implicit case too: a dropped flow set drops the
                    // queue, which lands here.
                    session_flow::RealtimePumpStep::Closed => return,
                }
            }
        }
        .await;
        // However that ended, the native half goes back. `retire` consumes the
        // track, so this cannot run twice.
        track.retire().await;
        // Last, and only after the detach has completed, so a waiting closer
        // that observes this has observed a finished retirement rather than a
        // scheduled one. Nobody may be waiting — implicit drop has no closer —
        // and that is why the error is discarded.
        let _ = retired.send(());
    });
    close_owner.retain_transport_task(task);
}

/// Exact process-local identity for one WebRTC connector worker.
///
/// This is a stale-callback guard, not authority. Only a
/// `ConnectorCandidateCapability` can authorize an admitted candidate.
pub(crate) struct WebRtcConnectorIncarnation {
    active: AtomicBool,
    retired: watch::Sender<bool>,
    /// The transport-independent identity for this same incarnation.
    ///
    /// Owned here rather than replacing this type, so the WebRTC worker keeps
    /// its native retirement plumbing while endpoint authentication and any
    /// other downstream owner name only the generic identity. The generic token
    /// carries identity alone: this type stays the single authoritative source
    /// of whether the connector is still live, so there is no second liveness
    /// flag that could disagree with `active`.
    generic: Arc<crate::connector::ConnectorIncarnation>,
}

impl WebRtcConnectorIncarnation {
    fn new() -> Self {
        let (retired, _receiver) = watch::channel(false);
        Self {
            active: AtomicBool::new(true),
            retired,
            generic: crate::connector::ConnectorIncarnation::new(),
        }
    }

    fn retire(&self) {
        self.active.store(false, Ordering::Release);
        self.retired.send_replace(true);
    }

    /// The transport-independent identity for this exact incarnation.
    pub(crate) fn generic(&self) -> &Arc<crate::connector::ConnectorIncarnation> {
        &self.generic
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
    _callback_work: Option<CallbackWorkLease>,
    #[cfg(feature = "route-flow-diagnostics")]
    route_flow_receipt: Option<crate::route_flow::NativeReceipt>,
}

impl WebRtcConnectorEvent {
    /// Move the receipt with the accepted leases, only after the worker's
    /// existing incarnation and real-time ownership checks have succeeded.
    fn into_accepted(self) -> AcceptedWebRtcConnectorEvent {
        AcceptedWebRtcConnectorEvent {
            event: self.event,
            resources: AcceptedWebRtcConnectorEventResources {
                _queue_observation: self._queue_observation,
                _callback_work: self._callback_work,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: self.route_flow_receipt,
            },
        }
    }

    /// Whether this is the data-channel-open callback. **Controls only.**
    ///
    /// A control that must hand the *genuine* native open event to the
    /// production engine arm has to recognise it without consuming it first —
    /// `accept_event` takes the event by value, so classifying through that
    /// would spend the very event the control needs to deliver. Read-only, and
    /// it exposes no payload: the answer is a bool, and the event's resources
    /// and its incarnation stay unreachable.
    ///
    /// Gated to match its only caller: the live pre-open fixture, which is
    /// gated on `transport-lab` alone. `test` is deliberately not part of the
    /// condition — gating on `test` alone would leave this with no caller in a
    /// default-feature test build, and requiring `test` as well would leave the
    /// fixture without it in the feature-only build another crate's controls
    /// compile against.
    #[cfg(feature = "transport-lab")]
    pub(crate) fn is_data_channel_open(&self) -> bool {
        matches!(self.event, TransportEvent::DataChannelOpen)
    }
}

/// Resource ownership retained while the engine handles one accepted native
/// callback. The fields are intentionally opaque outside this module.
pub(crate) struct AcceptedWebRtcConnectorEventResources {
    _queue_observation: Option<ObservationLease>,
    _callback_work: Option<CallbackWorkLease>,
    #[cfg(feature = "route-flow-diagnostics")]
    route_flow_receipt: Option<crate::route_flow::NativeReceipt>,
}

#[cfg(feature = "route-flow-diagnostics")]
impl AcceptedWebRtcConnectorEventResources {
    /// Observation only: the engine reads this after exact-worker admission.
    /// The callback leases, not a copied receipt, retain the event's custody.
    pub(crate) fn route_flow_receipt(&self) -> Option<crate::route_flow::NativeReceipt> {
        self.route_flow_receipt
    }
}

/// One stale-owner-checked callback and the resources that remain owned until
/// its engine handler completes.
pub(crate) struct AcceptedWebRtcConnectorEvent {
    event: TransportEvent,
    resources: AcceptedWebRtcConnectorEventResources,
}

impl AcceptedWebRtcConnectorEvent {
    pub(crate) fn into_parts(self) -> (TransportEvent, AcceptedWebRtcConnectorEventResources) {
        (self.event, self.resources)
    }
}

struct QueuedTransportEvent {
    event: TransportEvent,
    observation: Option<ObservationLease>,
    callback_work: Option<CallbackWorkLease>,
    // callback.rs prices this inline field through size_of::<Self>(), and
    // prices its executing counterpart through size_of::<WebRtcConnectorEvent>().
    // It allocates nothing and is absent from no-feature layouts.
    #[cfg(feature = "route-flow-diagnostics")]
    route_flow_receipt: Option<crate::route_flow::NativeReceipt>,
}

impl QueuedTransportEvent {
    #[expect(
        clippy::result_large_err,
        reason = "same by-value refusal as [`RealtimeDelivery::attach`], which this forwards to: both arms hand the reservation back intact — the second-attachment arm and the wrong-event-kind arm alike — so a refusal releases rather than strands. Boxing would allocate on the refusal path"
    )]
    fn attach_realtime_reservation(
        &mut self,
        reservation: RealtimePayloadLease,
    ) -> std::result::Result<(), RealtimePayloadLease> {
        match &mut self.event {
            // Refuses a second attachment rather than overwriting: overwriting
            // would drop a live lease silently and leave the bytes it accounted
            // for charged to nothing, whereas handing the lease back means a
            // double attachment releases rather than strands.
            TransportEvent::RealtimeUnit(delivery) => delivery.attach(reservation),
            _ => Err(reservation),
        }
    }
}

// A per-class callback payload limit used to be looked up here. Control and
// endpoint data never had one, and the real-time class had one only when the
// owner had stated a unit-byte ceiling. That ceiling is gone, so the lookup
// could only ever answer "no limit" and the two callers that consulted it are
// simpler without it. Every callback is still admitted at its actual payload
// size against the provider immediately below where this check used to stand.

#[derive(Clone)]
struct ConnectorEventMailboxes {
    control: Arc<ResourceBackedCallbackMailbox>,
    endpoint_data: Arc<ResourceBackedCallbackMailbox>,
    lifecycle: Arc<ConnectorLifecycleOwner>,
    #[cfg(test)]
    callback_producer: CallbackProducerOwner,
}

impl ConnectorEventMailboxes {
    fn mailbox(&self, class: ConnectorCallbackClass) -> Option<&ResourceBackedCallbackMailbox> {
        match class {
            ConnectorCallbackClass::Control => Some(self.control.as_ref()),
            ConnectorCallbackClass::EndpointData => Some(self.endpoint_data.as_ref()),
            ConnectorCallbackClass::Realtime => None,
        }
    }

    #[cfg(test)]
    fn try_insert_for_test(
        &self,
        event: TransportEvent,
        observation: Option<ObservationLease>,
    ) -> std::result::Result<(), ConnectorCallbackInsertResult> {
        if matches!(&event, TransportEvent::DataChannelOpen) {
            return self
                .lifecycle
                .record_open()
                .accepted()
                .then_some(())
                .ok_or(ConnectorCallbackInsertResult::PolicyRefused);
        }
        if matches!(&event, TransportEvent::DataChannelClosed) {
            return self
                .lifecycle
                .record_close(false)
                .accepted()
                .then_some(())
                .ok_or(ConnectorCallbackInsertResult::PolicyRefused);
        }
        let class = ConnectorCallbackClass::for_event(&event);
        let (payload_bytes, retained_slack) = match &event {
            TransportEvent::Message(bytes) => (bytes.len(), 0),
            TransportEvent::ApplicationFlowMessage { bytes, .. } => (bytes.len(), 0),
            // The payload lease it carries bounds *registry* retention; this
            // bounds the callback pump's own class budget, which is what
            // decides whether the event is admitted to the callback queue at
            // all. Two ceilings over two different resources, so leaving this
            // at zero would not avoid a double count — it would let real-time
            // units bypass the callback ceiling that bounds them.
            TransportEvent::RealtimeUnit(delivery) => (delivery.payload_bytes(), 0),
            TransportEvent::LocalIceCandidate(candidate) => {
                let Some(sizes) = candidate_callback_sizes(candidate) else {
                    return Err(ConnectorCallbackInsertResult::PolicyRefused);
                };
                sizes
            }
            _ => (0, 0),
        };
        let work = self
            .callback_producer
            .try_admit_with_accounted_slack(class, payload_bytes, retained_slack)
            .map_err(|_| ConnectorCallbackInsertResult::Overloaded)?;
        let result = match event {
            TransportEvent::DataChannelOpen | TransportEvent::DataChannelClosed => unreachable!(
                "data-channel lifecycle events return before ordinary callback admission"
            ),
            TransportEvent::RenegotiationNeeded => self.lifecycle.record_renegotiation(work),
            TransportEvent::IceConnectionStateChanged(state) => {
                self.lifecycle.record_ice_state(state, work)
            }
            TransportEvent::PeerConnectionStateChanged(state) => {
                self.lifecycle.record_peer_state(state, work)
            }
            event => {
                let Some(mailbox) = self.mailbox(class) else {
                    return Err(ConnectorCallbackInsertResult::WrongOwnerPath);
                };
                return mailbox
                    .try_insert(QueuedTransportEvent {
                        event,
                        observation,
                        callback_work: Some(work),
                        #[cfg(feature = "route-flow-diagnostics")]
                        route_flow_receipt: None,
                    })
                    .map_err(|error| match error.kind() {
                        CallbackMailboxInsertErrorKind::Closed => {
                            ConnectorCallbackInsertResult::ReceiverClosed
                        }
                        CallbackMailboxInsertErrorKind::MissingLease
                        | CallbackMailboxInsertErrorKind::WrongClass
                        | CallbackMailboxInsertErrorKind::WrongPhase => {
                            ConnectorCallbackInsertResult::PolicyRefused
                        }
                    });
            }
        };
        result
            .accepted()
            .then_some(())
            .ok_or(ConnectorCallbackInsertResult::PolicyRefused)
    }
}

#[derive(Clone)]
struct ConnectorEventSink {
    events: ConnectorEventMailboxes,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    resource_scope: Option<PeerConnectionResourceScope>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_violation_reported: Arc<AtomicBool>,
    callback_producer: CallbackProducerOwner,
    operation_fence: Arc<ConnectorOperationFence>,
    close_owner: Option<Weak<ConnectorCloseOwner>>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectorCallbackInsertResult {
    Queued,
    DiscardedAfterClose,
    Overloaded,
    ReceiverClosed,
    PolicyRefused,
    WrongOwnerPath,
}

impl ConnectorCallbackInsertResult {
    const fn accepted(self) -> bool {
        matches!(self, Self::Queued | Self::DiscardedAfterClose)
    }
}

fn callback_admission_error(context: &'static str, error: CallbackProducerOverload) -> Error {
    match error {
        CallbackProducerOverload::ResourceUnavailable { unavailable, .. } => {
            Error::ResourceUnavailable(unavailable)
        }
        other => Error::Transport(format!("{context}: {other:?}")),
    }
}

/// Controls-only discriminator for the production Closed-relay probe. This
/// deliberately records neither payload bytes nor endpoint identity: the
/// bounded leading tag is enough to tell the relay frame from every other
/// native message without parsing peer-controlled content a second time.
#[cfg(feature = "transport-lab")]
fn transport_lab_message_kind(bytes: &[u8]) -> &'static str {
    if bytes.starts_with(br#"{"kind":"closed_relay_data"#) {
        "closed-relay-data"
    } else {
        "other"
    }
}

#[cfg(feature = "transport-lab")]
fn transport_lab_message_marker(stage: &'static str, kind: &'static str) {
    eprintln!("closed-relay-transport-stage:{stage} kind={kind}");
}

/// Bounded transport counters for one exact native data channel.  These are
/// intentionally lower-level observations, not delivery authority: the
/// per-channel sent counters stop at SCTP queue admission, while the optional
/// association/candidate counters describe aggregate network progress.
#[cfg(feature = "transport-lab")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct TransportLabChannelSnapshot {
    pub(crate) channel_id: u16,
    pub(crate) messages_sent: usize,
    pub(crate) bytes_sent: usize,
    pub(crate) messages_received: usize,
    pub(crate) bytes_received: usize,
    pub(crate) buffered_amount: usize,
    pub(crate) association_bytes_sent: Option<usize>,
    pub(crate) association_bytes_received: Option<usize>,
    pub(crate) selected_pair_bytes_sent: Option<u64>,
    pub(crate) selected_pair_bytes_received: Option<u64>,
    pub(crate) selected_pair: Option<super::diag::SelectedCandidatePair>,
    pub(crate) state: u8,
}

#[cfg(feature = "transport-lab")]
impl PeerSession {
    async fn transport_lab_channel_snapshot(&self) -> Option<TransportLabChannelSnapshot> {
        let channel = self.data_channel.lock().clone()?;
        let channel_id = channel.id();
        let report = self.pc.get_stats().await;
        let data_channel = report.reports.values().find_map(|report| match report {
            webrtc::stats::StatsReportType::DataChannel(stats)
                if stats.data_channel_identifier == channel_id =>
            {
                Some(stats)
            }
            _ => None,
        })?;
        let association = report.reports.values().find_map(|report| match report {
            webrtc::stats::StatsReportType::SCTPTransport(stats) => Some(stats),
            _ => None,
        });
        // Only a nominated pair is an authoritative selected-pair report.
        // The succeeded-pair fallback used for path classification is not
        // valid evidence for attributing this channel's traffic.
        let selected_pair_stats = report.reports.values().find_map(|report| match report {
            webrtc::stats::StatsReportType::CandidatePair(stats) if stats.nominated => Some(stats),
            _ => None,
        });
        let selected_pair = selected_pair_stats.and_then(|stats| {
            fn classify(
                candidate_type: webrtc::ice::candidate::CandidateType,
                ip: &str,
            ) -> super::diag::IceCandidateKind {
                use super::diag::IceCandidateKind;
                match candidate_type {
                    webrtc::ice::candidate::CandidateType::Relay => IceCandidateKind::Relay,
                    _ if is_private_lan_ip(ip) => IceCandidateKind::Host,
                    webrtc::ice::candidate::CandidateType::Host => IceCandidateKind::Host,
                    webrtc::ice::candidate::CandidateType::ServerReflexive => {
                        IceCandidateKind::ServerReflexive
                    }
                    webrtc::ice::candidate::CandidateType::PeerReflexive => {
                        IceCandidateKind::PeerReflexive
                    }
                    webrtc::ice::candidate::CandidateType::Unspecified => IceCandidateKind::Unknown,
                }
            }
            let local = report.reports.values().find_map(|report| match report {
                webrtc::stats::StatsReportType::LocalCandidate(candidate)
                    if candidate.id == stats.local_candidate_id =>
                {
                    Some(classify(candidate.candidate_type, &candidate.ip))
                }
                _ => None,
            })?;
            let remote = report.reports.values().find_map(|report| match report {
                webrtc::stats::StatsReportType::RemoteCandidate(candidate)
                    if candidate.id == stats.remote_candidate_id =>
                {
                    Some(classify(candidate.candidate_type, &candidate.ip))
                }
                _ => None,
            })?;
            Some(super::diag::SelectedCandidatePair { local, remote })
        });
        Some(TransportLabChannelSnapshot {
            channel_id,
            messages_sent: data_channel.messages_sent,
            bytes_sent: data_channel.bytes_sent,
            messages_received: data_channel.messages_received,
            bytes_received: data_channel.bytes_received,
            buffered_amount: channel.buffered_amount().await,
            association_bytes_sent: association.map(|stats| stats.bytes_sent),
            association_bytes_received: association.map(|stats| stats.bytes_received),
            selected_pair_bytes_sent: selected_pair_stats.map(|stats| stats.bytes_sent),
            selected_pair_bytes_received: selected_pair_stats.map(|stats| stats.bytes_received),
            selected_pair,
            state: channel.ready_state() as u8,
        })
    }
}

impl ConnectorEventSink {
    fn begin_native_callback_operation(
        &self,
        class: ConnectorCallbackClass,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        self.begin_native_callback_operation_with_payload(class, 0, 0)
    }

    fn begin_native_callback_operation_with_payload(
        &self,
        class: ConnectorCallbackClass,
        payload_bytes: usize,
        retained_slack: usize,
    ) -> std::result::Result<CallbackWorkLease, CallbackProducerOverload> {
        let mut work = self.callback_producer.try_admit_with_accounted_slack(
            class,
            payload_bytes,
            retained_slack,
        )?;
        work.begin_execution()?;
        Ok(work)
    }

    #[cfg(test)]
    fn open_inbound_realtime_flow(&self) -> Option<RealtimeFlowPort> {
        self.realtime_flows.open_inbound_flow()
    }

    fn observe_realtime_payload(&self, payload_bytes: usize) -> Option<ObservationLease> {
        self.resource_scope.as_ref().map(|scope| {
            let measurement = match u64::try_from(payload_bytes) {
                Ok(bytes) => {
                    ResourceMeasurement::inexact(ResourceUse::observed(1, bytes, bytes, 0))
                }
                Err(_) => ResourceMeasurement::inexact(ResourceUse::ZERO),
            };
            scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::MediaQuarantine,
                measurement,
            )
        })
    }

    fn emit_realtime(
        &self,
        flow: &RealtimeFlowPort,
        event: TransportEvent,
        reservation: RealtimeOutputReservation,
    ) -> bool {
        let Some(_operation) = self.operation_fence.try_enter() else {
            return true;
        };
        if !self.callback_gate.is_active() {
            return true;
        }
        let payload_bytes = match &event {
            // The route a real-time unit must take. Down here it is charged
            // against the real-time class, observed as media quarantine, and
            // gated by the operation fence above — all of which the general
            // callback route loses.
            //
            // What authorizes the unit is not checked here and deliberately
            // never was a flag: `flow` is a port on a flow the promoted session
            // opened, and a unit can only reach this call if a track attached to
            // a binding that session established. A connector with no promoted
            // session has no flow to pass, so there is nothing for a boolean to
            // add.
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_bytes(),
            _ => return false,
        };
        let observation = self.observe_realtime_payload(payload_bytes);
        flow.enqueue(
            QueuedTransportEvent {
                event,
                observation,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            reservation,
        )
    }

    async fn emit_data_channel(&self, event: TransportEvent) -> bool {
        let endpoint_protocol = matches!(
            &event,
            TransportEvent::Message(_) | TransportEvent::ApplicationFlowMessage { .. }
        );
        let result = self.try_emit_data_channel(event).await;
        self.finish_data_channel_insert(endpoint_protocol, result)
    }

    #[cfg(all(test, feature = "route-flow-diagnostics"))]
    async fn emit_observed_message(
        &self,
        bytes: Bytes,
        receipt: Option<crate::route_flow::NativeReceipt>,
    ) -> bool {
        let result = self
            .emit_inner(TransportEvent::Message(bytes), true, receipt)
            .await;
        self.finish_data_channel_insert(true, result)
    }

    /// Enter a native Message callback synchronously. In particular, neither
    /// the diagnostic clock nor native callback admission waits for first poll.
    /// The returned future owns the admitted native work even if never polled.
    fn begin_message_callback(
        &self,
        bytes: Bytes,
        callback_observation: &Option<CallbackObservationLease>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ConnectorCallbackInsertResult, CallbackProducerOverload>,
    > + Send
           + 'static {
        #[cfg(feature = "route-flow-diagnostics")]
        let route_flow_receipt = crate::route_flow::capture_native_receipt();
        let _keep_callback_observation = callback_observation;
        #[cfg(feature = "transport-lab")]
        let message_kind = transport_lab_message_kind(&bytes);
        #[cfg(feature = "transport-lab")]
        transport_lab_message_marker("native-message-enter", message_kind);
        let admitted = match self.begin_native_callback_operation_with_payload(
            ConnectorCallbackClass::EndpointData,
            bytes.len(),
            0,
        ) {
            Ok(work) => Ok((self.clone(), work, bytes)),
            Err(error) => {
                warn!(
                    ?error,
                    "refusing native endpoint-data callback under resource pressure"
                );
                #[cfg(feature = "transport-lab")]
                transport_lab_message_marker("native-message-refused", message_kind);
                self.retire_after_callback_violation();
                // Match native entry's early return: a refused payload must
                // not become unfunded retention in an unpolled future.
                drop(bytes);
                Err(error)
            }
        };
        async move {
            let (tx, _callback_work, bytes) = admitted?;
            let result = tx
                .emit_inner(
                    TransportEvent::Message(bytes),
                    true,
                    #[cfg(feature = "route-flow-diagnostics")]
                    route_flow_receipt,
                )
                .await;
            // Keep the native accepted-discard convention and its retirement
            // side effects, but retain the precise disposition for controls.
            let _accepted = tx.finish_data_channel_insert(true, result);
            #[cfg(feature = "transport-lab")]
            transport_lab_message_marker(
                if _accepted {
                    "native-message-mailbox-accepted"
                } else {
                    "native-message-mailbox-refused"
                },
                message_kind,
            );
            Ok(result)
        }
    }

    /// Enter a native opaque-lane callback. The lane mode is supplied by the
    /// callback installation that authenticated the native channel; the frame
    /// header is checked before this function is called and cannot select its
    /// own reliability semantics.
    fn begin_application_flow_callback(
        &self,
        mode: crate::realtime::OpaqueFlowMode,
        bytes: Bytes,
        callback_observation: &Option<CallbackObservationLease>,
    ) -> impl std::future::Future<
        Output = std::result::Result<ConnectorCallbackInsertResult, CallbackProducerOverload>,
    > + Send
           + 'static {
        let _keep_callback_observation = callback_observation;
        let admitted = match self.begin_native_callback_operation_with_payload(
            ConnectorCallbackClass::EndpointData,
            bytes.len(),
            0,
        ) {
            Ok(work) => Ok((self.clone(), work, bytes)),
            Err(error) => {
                warn!(
                    ?error,
                    "refusing native opaque-flow callback under resource pressure"
                );
                drop(bytes);
                Err(error)
            }
        };
        async move {
            let (tx, _callback_work, bytes) = admitted?;
            let result = tx
                .emit_inner(
                    TransportEvent::ApplicationFlowMessage { mode, bytes },
                    true,
                    #[cfg(feature = "route-flow-diagnostics")]
                    None,
                )
                .await;
            let _accepted = tx.finish_data_channel_insert(true, result);
            Ok(result)
        }
    }

    #[cfg(all(test, feature = "route-flow-diagnostics"))]
    fn enqueue_funded_message_for_test(
        &self,
        ownership: &ConnectorOwnership,
        bytes: Bytes,
    ) -> impl std::future::Future<Output = std::result::Result<(), FundedCallbackTestRefusal>>
           + Send
           + 'static {
        // This guard supplies no authority; native and engine admission remain
        // responsible for races after this exact connected-owner precondition.
        let prepared = if !Arc::ptr_eq(&self.callback_gate, &ownership.incarnation)
            || !ownership.incarnation.is_active()
            || !matches!(
                &*ownership.authority.lock(),
                ConnectorAuthorityState::Connected
            ) {
            Err(FundedCallbackTestRefusal::NotConnected)
        } else if self.resource_scope.is_none() {
            Err(FundedCallbackTestRefusal::ObservationUnavailable)
        } else {
            Ok(self.begin_message_callback(bytes, &None))
        };
        async move {
            match prepared?.await {
                Ok(ConnectorCallbackInsertResult::Queued) => Ok(()),
                Ok(_) => Err(FundedCallbackTestRefusal::NotQueued),
                Err(_) => Err(FundedCallbackTestRefusal::NativeAdmission),
            }
        }
    }

    #[cfg(all(test, feature = "route-flow-diagnostics"))]
    async fn enqueue_open_for_test(
        &self,
        ownership: &ConnectorOwnership,
    ) -> std::result::Result<(), FundedCallbackTestRefusal> {
        if !Arc::ptr_eq(&self.callback_gate, &ownership.incarnation)
            || !ownership.incarnation.is_active()
            || !matches!(
                &*ownership.authority.lock(),
                ConnectorAuthorityState::Connected
            )
        {
            return Err(FundedCallbackTestRefusal::NotConnected);
        }
        if self.operation_fence.is_closed() {
            return Err(FundedCallbackTestRefusal::NotQueued);
        }
        // Uses the original reserved lifecycle lease. No new Open capability
        // is minted and no receiver commitment or authentication is performed.
        let result = self
            .emit_inner(TransportEvent::DataChannelOpen, true, None)
            .await;
        let _ = self.finish_data_channel_insert(false, result);
        match result {
            ConnectorCallbackInsertResult::Queued => Ok(()),
            _ => Err(FundedCallbackTestRefusal::NotQueued),
        }
    }

    fn finish_data_channel_insert(
        &self,
        endpoint_protocol: bool,
        result: ConnectorCallbackInsertResult,
    ) -> bool {
        if endpoint_protocol
            && matches!(
                result,
                ConnectorCallbackInsertResult::Overloaded
                    | ConnectorCallbackInsertResult::PolicyRefused
                    | ConnectorCallbackInsertResult::ReceiverClosed
            )
        {
            self.retire_after_callback_violation();
        }
        result.accepted()
    }

    async fn try_emit_data_channel(&self, event: TransportEvent) -> ConnectorCallbackInsertResult {
        if matches!(event, TransportEvent::DataChannelClosed) {
            self.operation_fence.begin_close();
            self.realtime_flows.retire();
            return self
                .events
                .lifecycle
                .record_close(self.callback_gate.is_active());
        }
        self.emit_inner(
            event,
            true,
            #[cfg(feature = "route-flow-diagnostics")]
            None,
        )
        .await
    }

    async fn emit(&self, event: TransportEvent) -> bool {
        let candidate_obligation = matches!(&event, TransportEvent::LocalIceCandidate(_));
        let result = self
            .emit_inner(
                event,
                true,
                #[cfg(feature = "route-flow-diagnostics")]
                None,
            )
            .await;
        if candidate_obligation
            && matches!(
                result,
                ConnectorCallbackInsertResult::Overloaded
                    | ConnectorCallbackInsertResult::PolicyRefused
                    | ConnectorCallbackInsertResult::ReceiverClosed
            )
        {
            self.retire_after_callback_violation();
        }
        result.accepted()
    }

    fn retire_after_callback_violation(&self) {
        self.operation_fence.begin_close();
        self.realtime_flows.retire();
        self.events
            .lifecycle
            .record_close(self.callback_gate.is_active());
        if let Some(owner) = self.close_owner.as_ref().and_then(Weak::upgrade) {
            owner.start();
        }
    }

    fn structural_violation(&self, reason: &'static str) {
        if self
            .callback_violation_reported
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            warn!(
                reason,
                "retiring connector after native callback shape violation"
            );
            self.retire_after_callback_violation();
        }
    }

    async fn emit_inner(
        &self,
        event: TransportEvent,
        fence_operation: bool,
        #[cfg(feature = "route-flow-diagnostics")] route_flow_receipt: Option<
            crate::route_flow::NativeReceipt,
        >,
    ) -> ConnectorCallbackInsertResult {
        let _operation = if fence_operation {
            match self.operation_fence.try_enter() {
                Some(operation) => Some(operation),
                None => return ConnectorCallbackInsertResult::DiscardedAfterClose,
            }
        } else {
            None
        };
        let event = match event {
            TransportEvent::DataChannelOpen => {
                return self.events.lifecycle.record_open();
            }
            TransportEvent::DataChannelClosed => {
                return self
                    .events
                    .lifecycle
                    .record_close(self.callback_gate.is_active());
            }
            TransportEvent::RenegotiationNeeded => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_renegotiation(work);
            }
            TransportEvent::IceConnectionStateChanged(state) => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_ice_state(state, work);
            }
            TransportEvent::PeerConnectionStateChanged(state) => {
                let work = match self
                    .callback_producer
                    .try_admit(ConnectorCallbackClass::Control, 0)
                {
                    Ok(work) => work,
                    Err(_) => return ConnectorCallbackInsertResult::Overloaded,
                };
                return self.events.lifecycle.record_peer_state(state, work);
            }
            event => event,
        };
        // Refused here rather than at the mailbox lookup below, which would
        // reach the same answer only after admitting callback work and taking
        // an observation for it. A real-time unit on the general route is a
        // routing error in every state — it must enter through an exact
        // `RealtimeFlowPort`, because a connector-wide mailbox would let one
        // flow consume or reorder another flow's admitted queue — so nothing
        // should be charged on the way to saying so.
        if matches!(&event, TransportEvent::RealtimeUnit(_)) {
            return ConnectorCallbackInsertResult::WrongOwnerPath;
        }
        let callback_class = ConnectorCallbackClass::for_event(&event);
        let (payload_bytes, retained_slack) = match &event {
            TransportEvent::Message(bytes) => (bytes.len(), 0),
            TransportEvent::ApplicationFlowMessage { bytes, .. } => (bytes.len(), 0),
            // Same reasoning as the other admission site: charged here as well
            // as against its payload lease, because the two bound different
            // resources.
            TransportEvent::RealtimeUnit(delivery) => (delivery.payload_bytes(), 0),
            TransportEvent::LocalIceCandidate(candidate) => {
                let Some(sizes) = candidate_callback_sizes(candidate) else {
                    return ConnectorCallbackInsertResult::PolicyRefused;
                };
                sizes
            }
            _ => (0, 0),
        };
        let callback_work = match self.callback_producer.try_admit_with_accounted_slack(
            callback_class,
            payload_bytes,
            retained_slack,
        ) {
            Ok(lease) => Some(lease),
            Err(error) => {
                warn!(
                    ?error,
                    ?callback_class,
                    "connector callback resource pressure"
                );
                return ConnectorCallbackInsertResult::Overloaded;
            }
        };
        let family = match &event {
            TransportEvent::Message(_) | TransportEvent::ApplicationFlowMessage { .. } => {
                PreAuthResourceFamily::FrameBytes
            }
            TransportEvent::RealtimeUnit(_) => PreAuthResourceFamily::MediaQuarantine,
            _ => PreAuthResourceFamily::ConnectorSpecificWork,
        };
        let observation = self.resource_scope.as_ref().map(|scope| {
            let measurement = payload_bytes
                .checked_add(retained_slack)
                .and_then(|retained| {
                    Some((
                        u64::try_from(payload_bytes).ok()?,
                        u64::try_from(retained).ok()?,
                    ))
                })
                .map_or_else(
                    || ResourceMeasurement::inexact(ResourceUse::ZERO),
                    |(logical, retained)| {
                        ResourceMeasurement::inexact(ResourceUse::observed(1, logical, retained, 0))
                    },
                );
            scope.observe_pre_authentication_measurement(family, measurement)
        });
        let queued = QueuedTransportEvent {
            event,
            observation,
            callback_work,
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt,
        };
        let Some(mailbox) = self.events.mailbox(callback_class) else {
            // Real-time units must enter through an exact RealtimeFlowPort.
            // A connector-wide compatibility mailbox would let one flow
            // consume or reorder another flow's admitted queue.
            return ConnectorCallbackInsertResult::WrongOwnerPath;
        };
        if fence_operation && self.operation_fence.is_closed() {
            return ConnectorCallbackInsertResult::DiscardedAfterClose;
        }
        if !self.callback_gate.is_active()
            || self.attempt_liveness.as_ref().is_some_and(|liveness| {
                !liveness.is_active() && !self.candidate_promoted.load(Ordering::Acquire)
            })
        {
            return ConnectorCallbackInsertResult::ReceiverClosed;
        }
        // Sample only an opted-in native Message, after all admission/fence
        // checks and immediately before the actual bounded mailbox attempt.
        #[cfg(feature = "route-flow-diagnostics")]
        let queued = {
            let mut queued = queued;
            if let Some(receipt) = queued.route_flow_receipt.as_mut() {
                receipt.mark_mailbox_attempt();
            }
            queued
        };
        match mailbox.try_insert(queued) {
            Ok(()) => ConnectorCallbackInsertResult::Queued,
            Err(error) => match error.kind() {
                CallbackMailboxInsertErrorKind::Closed => {
                    ConnectorCallbackInsertResult::ReceiverClosed
                }
                CallbackMailboxInsertErrorKind::MissingLease
                | CallbackMailboxInsertErrorKind::WrongClass
                | CallbackMailboxInsertErrorKind::WrongPhase => {
                    ConnectorCallbackInsertResult::PolicyRefused
                }
            },
        }
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
    operation_fence: Arc<ConnectorOperationFence>,
}

/// Lab/test receiver for raw WebRTC behavior. Production wraps it in the
/// connector owner before any event can reach the engine.
pub struct TransportEventReceiver {
    control: Arc<ResourceBackedCallbackMailbox>,
    endpoint_data: Arc<ResourceBackedCallbackMailbox>,
    lifecycle: Arc<ConnectorLifecycleOwner>,
    lifecycle_closed: bool,
    callback_ready: Arc<tokio::sync::Notify>,
    callback_failed: bool,
    realtime_flows: Arc<RealtimeFlowRegistry>,
    scheduler: ConnectorCallbackScheduler,
    control_cursor: ConnectorControlSourceCursor,
}

impl TransportEventReceiver {
    fn begin_callback_execution(
        &mut self,
        mut event: QueuedTransportEvent,
    ) -> Option<QueuedTransportEvent> {
        if let Some(work) = event.callback_work.as_mut() {
            if let Err(error) = work.begin_execution() {
                warn!(
                    ?error,
                    "connector callback execution resource transition failed"
                );
                self.callback_failed = true;
                return None;
            }
        }
        Some(event)
    }

    fn try_scheduled_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        if self.lifecycle_closed {
            return None;
        }
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
                    ConnectorCallbackClass::Control => {
                        self.control_cursor.try_take(&self.lifecycle, &self.control)
                    }
                    ConnectorCallbackClass::EndpointData => self.endpoint_data.try_take(),
                    ConnectorCallbackClass::Realtime => unreachable!(),
                }
            };
            match event {
                Some(event) => {
                    if matches!(event.event, TransportEvent::DataChannelClosed) {
                        self.lifecycle_closed = true;
                    }
                    self.scheduler.delivered(class);
                    if let Some(event) = self.begin_callback_execution(event) {
                        return Some(event);
                    }
                    continue;
                }
                None => {
                    self.scheduler.skip_current();
                }
            }
        }
        None
    }

    fn try_terminal_close(&mut self) -> Option<QueuedTransportEvent> {
        if self.lifecycle_closed {
            return None;
        }
        let event = self.lifecycle.try_take_close_event()?;
        self.lifecycle_closed = true;
        self.begin_callback_execution(event)
    }

    async fn recv_queued_filtered(
        &mut self,
        allow_endpoint_data: bool,
    ) -> Option<QueuedTransportEvent> {
        loop {
            if self.callback_failed {
                return None;
            }
            if let Some(event) = self.try_scheduled_filtered(allow_endpoint_data) {
                return Some(event);
            }
            if self.control.is_closed()
                && self.control.is_empty()
                && (!allow_endpoint_data
                    || (self.endpoint_data.is_closed() && self.endpoint_data.is_empty()))
                && self.realtime_flows.is_empty()
                && !self.lifecycle.has_pending()
            {
                return None;
            }
            tokio::select! {
                _ = self.lifecycle.notified() => {
                    continue;
                }
                _ = self.callback_ready.notified() => {
                    continue;
                }
                _ = self.realtime_flows.ready.notified() => {
                    continue;
                }
            }
        }
    }

    #[cfg(test)]
    pub async fn recv(&mut self) -> Option<TransportEvent> {
        self.recv_queued_filtered(true)
            .await
            .map(|queued| queued.event)
    }

    #[cfg(test)]
    pub fn try_recv(&mut self) -> std::result::Result<TransportEvent, mpsc::error::TryRecvError> {
        if let Some(queued) = self.try_scheduled_filtered(true) {
            return Ok(queued.event);
        }
        if self.control.is_closed()
            && self.endpoint_data.is_closed()
            && self.realtime_flows.is_empty()
            && !self.lifecycle.has_pending()
        {
            Err(mpsc::error::TryRecvError::Disconnected)
        } else {
            Err(mpsc::error::TryRecvError::Empty)
        }
    }
}

impl Drop for TransportEventReceiver {
    fn drop(&mut self) {
        self.control.close();
        self.endpoint_data.close();
    }
}

impl WebRtcConnectorEventReceiver {
    fn expose_queued(&mut self, queued: QueuedTransportEvent) -> Option<WebRtcConnectorEvent> {
        let terminal_close = matches!(&queued.event, TransportEvent::DataChannelClosed);
        if self.operation_fence.is_closed() && !terminal_close {
            return None;
        }
        let incarnation_active = self.ownership.incarnation.is_active();
        if terminal_close && !incarnation_active && !self.raw.lifecycle.close_survives_retirement()
        {
            self.data_channel_closed = true;
            return None;
        }
        if !terminal_close && !incarnation_active {
            return None;
        }
        if terminal_close {
            self.data_channel_closed = true;
        }
        #[cfg(feature = "route-flow-diagnostics")]
        let receipt = queued.route_flow_receipt.map(|mut receipt| {
            receipt.mark_dequeued();
            receipt
        });
        Some(WebRtcConnectorEvent {
            incarnation: Arc::clone(&self.ownership.incarnation),
            event: queued.event,
            _queue_observation: queued.observation,
            _callback_work: queued.callback_work,
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt: receipt,
        })
    }

    fn expose_recorded_close(&mut self) -> Option<WebRtcConnectorEvent> {
        let queued = self.raw.try_terminal_close()?;
        self.expose_queued(queued)
    }

    pub(crate) async fn recv(&mut self) -> Option<WebRtcConnectorEvent> {
        loop {
            if self.data_channel_closed {
                return None;
            }
            if let Some(close) = self.expose_recorded_close() {
                return Some(close);
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
                _ = self.retirement.changed() => {
                    if let Some(close) = self.expose_recorded_close() {
                        return Some(close);
                    }
                    return None;
                },
                _ = wait_for_optional_retirement(&mut self.attempt_retirement) => {
                    if self.reclaim_retired_attempt_candidate() {
                        return None;
                    }
                    continue;
                }
                queued = self.raw.recv_queued_filtered(self.data_channel_open_committed) => {
                    queued
                },
            };
            if let Some(queued) = queued {
                if let Some(event) = self.expose_queued(queued) {
                    return Some(event);
                }
                continue;
            }
            return None;
        }
    }

    /// Pop one event that is already ready without waiting for a notification.
    ///
    /// This test-only seam follows [`Self::recv`] through the same recorded
    /// close, retirement, candidate-reclamation, raw filtering, and callback
    /// custody transitions. It consumes an event only when the raw receiver
    /// has one ready; an empty receiver performs no allocation or scheduling.
    #[cfg(test)]
    pub(crate) fn try_recv_nonblocking(&mut self) -> Option<WebRtcConnectorEvent> {
        loop {
            if self.data_channel_closed {
                return None;
            }
            if let Some(close) = self.expose_recorded_close() {
                return Some(close);
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
            let queued = self
                .raw
                .try_scheduled_filtered(self.data_channel_open_committed)?;
            if let Some(event) = self.expose_queued(queued) {
                return Some(event);
            }
        }
    }

    /// Release bounded endpoint-protocol callbacks only after the engine has
    /// committed the exact connector's working-channel ownership transition.
    /// Delivering the control event is insufficient because its owner may be
    /// stale or may reject the transition.
    pub(crate) fn commit_data_channel_open(&mut self) {
        if self.raw.lifecycle.commit_open() {
            self.data_channel_open_committed = true;
        }
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
    let mut state = remote_candidates.lock();
    state.current.retire();
    if let Some(provisional) = state.provisional.as_mut() {
        provisional.envelope.retire();
    }
}

/// Result of applying an inbound candidate through the connector owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RemoteCandidateDisposition {
    Applied,
    QueuedUntilRemoteDescription,
    DuplicateIgnored,
    InvalidBinding(CandidateUsernameFragmentError),
    RefusedByOwner,
    AttemptRetired,
}

pub(crate) struct RemoteCandidateAdmissionReport {
    pub(crate) disposition: RemoteCandidateDisposition,
    pub(crate) kind: Option<super::diag::IceCandidateKind>,
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
    pub(crate) candidate_failure_count: usize,
}

/// One remote candidate paired with the observation that follows its owner.
/// Moving this value moves the observation. Dropping it ends the observation.
#[derive(Debug)]
struct PendingRemoteCandidate {
    candidate: LocalIceCandidate,
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    observation: CandidateObservationLease,
    _queue_reservation: Option<PendingRemoteCandidateReservation>,
    _elastic_lease: Option<ElasticRemoteCandidateLease>,
    _production_queue_lease: Option<crate::resource::ResourceLease>,
}

impl PendingRemoteCandidate {
    fn observe(
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
    ) -> Self {
        let observation = CandidateObservationLease {
            _observation: resource_scope.observe_pre_authentication_measurement(
                PreAuthResourceFamily::CandidateObject,
                candidate_resource_measurement(&candidate),
            ),
        };
        Self {
            candidate,
            attempt,
            observation,
            _queue_reservation: None,
            _elastic_lease: None,
            _production_queue_lease: None,
        }
    }

    fn retained(
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
        queue_reservation: PendingRemoteCandidateReservation,
        elastic_lease: ElasticRemoteCandidateLease,
        production_queue_lease: crate::resource::ResourceLease,
    ) -> Self {
        let mut pending = Self::observe(candidate, attempt, resource_scope);
        pending._queue_reservation = Some(queue_reservation);
        pending._elastic_lease = Some(elastic_lease);
        pending._production_queue_lease = Some(production_queue_lease);
        pending
    }
}

/// Apply an observed candidate while retaining its lease across the await.
/// Cancellation drops both the future and its observation.
#[cfg(test)]
async fn apply_pending_remote_candidate<F, Fut, T>(pending: PendingRemoteCandidate, apply: F) -> T
where
    F: FnOnce(LocalIceCandidate) -> Fut,
    Fut: std::future::Future<Output = T>,
{
    let PendingRemoteCandidate {
        candidate,
        attempt: _,
        observation,
        _queue_reservation,
        _elastic_lease,
        _production_queue_lease,
    } = pending;
    let _elastic_application = _elastic_lease.and_then(|lease| lease.begin_apply().ok());
    let result = apply(candidate).await;
    drop(observation);
    drop(_queue_reservation);
    result
}

#[derive(Debug)]
struct CandidateObservationLease {
    _observation: ObservationLease,
}

#[derive(Debug)]
struct PendingRemoteCandidateQueue {
    entries: std::collections::LinkedList<PendingRemoteCandidate>,
    container_observation: Option<ObservationLease>,
}

impl PendingRemoteCandidateQueue {
    fn new() -> Self {
        Self {
            entries: std::collections::LinkedList::new(),
            container_observation: None,
        }
    }

    fn push(
        &mut self,
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
        work_resources: &ConnectorWorkResourceScope,
        reservation: PendingRemoteCandidateReservation,
        elastic_lease: ElasticRemoteCandidateLease,
    ) -> PendingRemoteCandidateQueuePush {
        let production_queue_claim = match pending_remote_candidate_queue_claim(&candidate) {
            Ok(claim) => claim,
            Err(error) => {
                warn!(?error, "remote-candidate queue ownership claim overflowed");
                return PendingRemoteCandidateQueuePush::ResourceUnavailable(
                    ResourceUnavailable::ProviderInvariant {
                        dimension: match error {
                            crate::resource::ResourceClaimArithmeticError::Overflow {
                                dimension,
                            }
                            | crate::resource::ResourceClaimArithmeticError::Underflow {
                                dimension,
                            } => dimension,
                        },
                    },
                );
            }
        };
        let production_queue_lease = match work_resources.acquire(
            crate::resource::ResourceAuthorityClass::Speculative,
            production_queue_claim,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                warn!(?error, "remote-candidate queue wrapper was refused");
                return PendingRemoteCandidateQueuePush::ResourceUnavailable(error);
            }
        };
        self.entries.push_back(PendingRemoteCandidate::retained(
            candidate,
            attempt,
            resource_scope,
            reservation,
            elastic_lease,
            production_queue_lease,
        ));
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
        PendingRemoteCandidateQueuePush::Queued
    }

    #[cfg(test)]
    fn push_observed_for_test(
        &mut self,
        candidate: LocalIceCandidate,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        if candidate_content_bytes(&candidate).is_none() {
            return PendingRemoteCandidateQueuePush::Refused;
        }
        let mut pending = PendingRemoteCandidate::observe(candidate, attempt, resource_scope);
        pending._queue_reservation = Some(PendingRemoteCandidateReservation::default());
        self.entries.push_back(pending);
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
        PendingRemoteCandidateQueuePush::Queued
    }

    fn take(&mut self) -> PendingRemoteCandidateDrain {
        let entries = std::mem::take(&mut self.entries);
        let container_observation = self.container_observation.take();
        PendingRemoteCandidateDrain {
            entries: entries.into_iter(),
            _container_observation: container_observation,
        }
    }

    fn retain_candidates(&mut self, mut keep: impl FnMut(&PendingRemoteCandidate) -> bool) {
        let mut retained = std::collections::LinkedList::new();
        while let Some(pending) = self.entries.pop_front() {
            if keep(&pending) {
                retained.push_back(pending);
            }
        }
        self.entries = retained;
        if self.entries.is_empty() {
            self.container_observation = None;
        } else if let Some(observation) = self.container_observation.as_mut() {
            observation.replace_measurement(queue_container_resource_measurement(&self.entries));
        }
    }

    fn retain_matching_remote_credentials(&mut self, credentials: &RemoteIceCredentials) {
        self.retain_candidates(|pending| {
            candidate_matches_remote_credentials(&pending.candidate, credentials)
        });
    }

    fn retain_remote_restart_migratable_candidates(&mut self, credentials: &RemoteIceCredentials) {
        self.retain_candidates(|pending| {
            matches!(candidate_username_fragment(&pending.candidate), Ok(Some(_)))
                && candidate_matches_remote_credentials(&pending.candidate, credentials)
        });
    }

    fn pop_last_for_application(
        &mut self,
        resource_scope: &PeerConnectionResourceScope,
    ) -> Option<PendingRemoteCandidate> {
        let pending = self.entries.pop_back()?;
        if self.entries.is_empty() {
            self.container_observation = None;
        } else if let Some(observation) = self.container_observation.as_mut() {
            observation.replace_measurement(queue_container_resource_measurement(&self.entries));
        } else {
            self.container_observation =
                Some(resource_scope.observe_pre_authentication_measurement(
                    PreAuthResourceFamily::CandidateObject,
                    queue_container_resource_measurement(&self.entries),
                ));
        }
        Some(pending)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PendingRemoteCandidateQueuePush {
    Queued,
    Duplicate,
    InvalidBinding(CandidateUsernameFragmentError),
    ResourceUnavailable(ResourceUnavailable),
    Refused,
    Retired,
}

// A four-dimensional owner-selected candidate budget used to stand here: unique
// items, cumulative content bytes, duplicate submissions and native application
// work, each with its own ceiling, its own counter, and a shared poison flag.
// All of it is gone.
//
// Every one of those counters shadowed an exact claim the candidate path
// already takes: the queue wrapper, the retained strings, the queued content
// bytes and the digest node are each admitted against the process provider at
// their real size, and the native application is admitted against the elastic
// attempt. A second count in front of those could only refuse a candidate the
// owner's real grant would have funded, in units the owner never chose — and
// the poison flag existed only to stop the shadow arithmetic being read after
// it had gone wrong, which is not a condition that can arise once nothing keeps
// the shadow.

/// What a queued candidate keeps once it has reached native application.
///
/// It no longer reserves anything at queue time — the queue's own leases do
/// that — so an unapplied candidate carries the default. The one thing it still
/// owns is the elastic attempt's post-application ownership, which the envelope
/// retains for the life of the attempt.
#[derive(Debug, Default)]
struct PendingRemoteCandidateReservation {
    application: Option<crate::runtime::attempt::ApplyingRemoteCandidate>,
}

fn applied_remote_candidate_retained_claim() -> Result<crate::resource::ResourceClaim> {
    let retained_bytes = std::mem::size_of::<PendingRemoteCandidateReservation>()
        .checked_add(std::mem::size_of::<[u8; 32]>())
        .ok_or_else(|| {
            Error::Transport("applied remote-candidate ownership size overflowed".to_string())
        })?;
    let retained_bytes = u64::try_from(retained_bytes).map_err(|_| {
        Error::Transport("applied remote-candidate ownership size is not representable".to_string())
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            retained_bytes,
        ),
        (crate::resource::ResourceClass::StorageObject, 2),
        // One ordered-set node, one linked-list node, and the native
        // ICE-agent copy whose byte shape is hidden by webrtc-rs. The
        // residual remains owned until this exact attempt retires.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 3),
    ])
    .map_err(|error| {
        Error::Transport(format!(
            "applied remote-candidate ownership claim overflowed: {error}"
        ))
    })
}

#[cfg(test)]
pub(crate) fn applied_remote_candidate_reservation_charge_for_test(
) -> crate::resource::ResourceClaim {
    crate::resource::FiniteResourceProvider::reservation_planning_charge(
        applied_remote_candidate_retained_claim()
            .expect("applied remote-candidate claim is representable"),
    )
    .expect("applied remote-candidate reservation charge is representable")
}

/// Exact Rust-owned production queue contribution for one candidate.
///
/// The connector-neutral elastic lease owns its digest state. This separate
/// lease moves with the `LocalIceCandidate` and owns the production wrapper,
/// exact retained String capacities, logical queued content bytes, the second
/// digest key, and the two allocator domains used by LinkedList and BTreeSet.
/// Allocator metadata remains an explicit opaque residual.
fn pending_remote_candidate_queue_claim(
    candidate: &LocalIceCandidate,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let string_capacity = candidate
        .candidate
        .capacity()
        .checked_add(candidate.sdp_mid.as_ref().map_or(0, String::capacity))
        .and_then(|bytes| {
            let username = candidate
                .username_fragment
                .as_ref()
                .map_or(0, String::capacity);
            bytes.checked_add(username)
        })
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let string_capacity = u64::try_from(string_capacity).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    let content_bytes = candidate_content_bytes(candidate)
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::QueuedBytes,
        })?;
    pending_remote_candidate_queue_claim_with_content(string_capacity, content_bytes)
}

fn pending_remote_candidate_queue_claim_with_content(
    string_capacity: u64,
    content_bytes: u64,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let accounted_bytes = std::mem::size_of::<PendingRemoteCandidate>()
        .checked_add(std::mem::size_of::<[u8; 32]>())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .and_then(|bytes| bytes.checked_add(string_capacity))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted_bytes,
        ),
        (crate::resource::ResourceClass::QueuedBytes, content_bytes),
        (crate::resource::ResourceClass::StorageObject, 2),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

/// Fund the temporary bounded planner before any of its vectors or future
/// nodes are materialized. The queue's candidate leases remain separate; this
/// claim covers only the scheduler-owned path metadata and container nodes.
fn remote_candidate_drain_plan_claim(
    candidate_count: usize,
) -> Result<crate::resource::ResourceClaim> {
    let count = u64::try_from(candidate_count).map_err(|_| {
        Error::Transport("remote-candidate planner count is not representable".to_string())
    })?;
    let path_bytes = count
        .checked_mul(
            u64::try_from(std::mem::size_of::<IceCandidatePath>()).map_err(|_| {
                Error::Transport("remote-candidate path size is not representable".to_string())
            })?,
        )
        .ok_or_else(|| Error::Transport("remote-candidate path claim overflowed".to_string()))?;
    let pending_bytes = count
        .checked_mul(
            u64::try_from(std::mem::size_of::<Option<PendingRemoteCandidate>>()).map_err(|_| {
                Error::Transport("pending candidate size is not representable".to_string())
            })?,
        )
        .ok_or_else(|| Error::Transport("pending candidate claim overflowed".to_string()))?;
    let scheduler_bytes = u64::try_from(std::mem::size_of::<WebRtcCandidatePathPlanner>())
        .map_err(|_| Error::Transport("candidate planner size is not representable".to_string()))?;
    let accounted_bytes = path_bytes
        .checked_add(pending_bytes)
        .and_then(|bytes| bytes.checked_add(scheduler_bytes))
        .ok_or_else(|| Error::Transport("candidate planner claim overflowed".to_string()))?;
    let residual_nodes = count
        .checked_mul(3)
        .and_then(|nodes| nodes.checked_add(1))
        .ok_or_else(|| Error::Transport("candidate planner residual overflowed".to_string()))?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted_bytes,
        ),
        (
            crate::resource::ResourceClass::OpaqueDependencyResidual,
            residual_nodes,
        ),
    ])
    .map_err(|error| Error::Transport(format!("candidate planner claim overflowed: {error}")))
}

fn candidate_content_bytes(candidate: &LocalIceCandidate) -> Option<usize> {
    let strings = candidate
        .candidate
        .len()
        .checked_add(candidate.sdp_mid.as_ref().map_or(0, String::len))?
        .checked_add(candidate.username_fragment.as_ref().map_or(0, String::len))?;
    strings.checked_add(
        candidate
            .sdp_mline_index
            .map_or(0, |_| std::mem::size_of::<u16>()),
    )
}

fn candidate_callback_sizes(candidate: &Option<LocalIceCandidate>) -> Option<(usize, usize)> {
    let Some(candidate) = candidate.as_ref() else {
        return Some((0, 0));
    };
    let content = candidate_content_bytes(candidate)?;
    let slack = candidate
        .candidate
        .capacity()
        .checked_sub(candidate.candidate.len())?
        .checked_add(
            candidate
                .sdp_mid
                .as_ref()
                .map_or(0, |value| value.capacity().saturating_sub(value.len())),
        )?
        .checked_add(
            candidate
                .username_fragment
                .as_ref()
                .map_or(0, |value| value.capacity().saturating_sub(value.len())),
        )?;
    Some((content, slack))
}

#[derive(Debug)]
struct PendingRemoteCandidateDrain {
    entries: std::collections::linked_list::IntoIter<PendingRemoteCandidate>,
    _container_observation: Option<ObservationLease>,
}

impl Default for PendingRemoteCandidateDrain {
    fn default() -> Self {
        Self {
            entries: std::collections::LinkedList::new().into_iter(),
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

struct RemoteCandidateAttemptEnvelope {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    elastic_attempt: ElasticRemoteCandidateAttempt,
    work_resources: ConnectorWorkResourceScope,
    remote_description_set: bool,
    pending: PendingRemoteCandidateQueue,
    seen: std::collections::BTreeSet<[u8; 32]>,
    retained_reservations: std::collections::LinkedList<PendingRemoteCandidateReservation>,
    remote_ice_credentials: Option<RemoteIceCredentials>,
    remote_description_in_flight: bool,
    /// A provisional replacement owns a second root claim until commit drops
    /// the retiring root. The connector floor then resumes ownership of the
    /// one current root.
    provisional_root_lease: Option<crate::resource::ResourceLease>,
}

impl RemoteCandidateAttemptEnvelope {
    fn new(work_resources: ConnectorWorkResourceScope) -> Self {
        let elastic_attempt = ElasticRemoteCandidateAttempt::new(work_resources.clone());
        Self {
            attempt: Arc::new(RemoteCandidateAttemptIdentity::default()),
            elastic_attempt,
            work_resources,
            remote_description_set: false,
            pending: PendingRemoteCandidateQueue::new(),
            seen: std::collections::BTreeSet::new(),
            retained_reservations: std::collections::LinkedList::new(),
            remote_ice_credentials: None,
            remote_description_in_flight: false,
            provisional_root_lease: None,
        }
    }

    fn new_provisional(work_resources: ConnectorWorkResourceScope) -> Result<Self> {
        let root_lease = work_resources
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::runtime::attempt::remote_candidate_attempt_root_claim().map_err(
                    |error| {
                        Error::Transport(format!(
                            "replacement candidate-attempt root claim overflowed: {error}"
                        ))
                    },
                )?,
            )
            .map_err(Error::from)?;
        let mut replacement = Self::new(work_resources);
        replacement.provisional_root_lease = Some(root_lease);
        Ok(replacement)
    }

    #[cfg(test)]
    fn admit(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        self.admit_observed(candidate, resource_scope).0
    }

    fn admit_observed(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> (
        PendingRemoteCandidateQueuePush,
        Option<super::diag::IceCandidateKind>,
    ) {
        if !self.attempt.is_active() {
            return (PendingRemoteCandidateQueuePush::Retired, None);
        }
        let elastic_input = ElasticRemoteCandidateInput {
            candidate: candidate.candidate.as_bytes(),
            sdp_mid: candidate.sdp_mid.as_deref().map(str::as_bytes),
            sdp_mline_index: candidate.sdp_mline_index,
            username_fragment: candidate.username_fragment.as_deref().map(str::as_bytes),
        };
        if candidate_content_bytes(&candidate).is_none() {
            self.retire();
            return (PendingRemoteCandidateQueuePush::Refused, None);
        }
        let mut kind = None;
        let mut binding = None;
        let seen = &self.seen;
        let admitted = self.elastic_attempt.admit_with_digest_decision(
            elastic_input,
            || {
                kind = Some(super::ice::classify_candidate_sdp(&candidate.candidate));
                let parsed = candidate_username_fragment(&candidate);
                let valid = parsed.is_ok();
                binding = Some(parsed);
                valid
            },
            |digest| {
                if seen.contains(&digest) {
                    ElasticRemoteCandidateDigestDecision::Duplicate
                } else {
                    ElasticRemoteCandidateDigestDecision::Retain
                }
            },
        );
        if let Some(Err(error)) = binding {
            self.retire();
            return (PendingRemoteCandidateQueuePush::InvalidBinding(error), kind);
        }
        let elastic_lease = match admitted {
            Ok(ElasticRemoteCandidateAdmission::Retained(lease)) => lease,
            Ok(ElasticRemoteCandidateAdmission::Duplicate) => {
                return (PendingRemoteCandidateQueuePush::Duplicate, kind);
            }
            Err(ElasticRemoteCandidateAdmissionError::Provider(error))
            | Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::Provider(error),
            )) => {
                warn!(?error, "remote-candidate provider retired the ICE attempt");
                self.retire();
                return (
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(error),
                    kind,
                );
            }
            Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::AccountingInexact,
            )) => {
                self.retire();
                return (
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(
                        ResourceUnavailable::ProviderInvariant {
                            dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                        },
                    ),
                    kind,
                );
            }
            Err(ElasticRemoteCandidateAdmissionError::Terminal(
                ElasticRemoteCandidateTerminalReason::Retired,
            )) => {
                self.retire();
                return (PendingRemoteCandidateQueuePush::Retired, kind);
            }
            Err(error) => {
                warn!(
                    ?error,
                    "remote-candidate local wrapper retired the ICE attempt"
                );
                self.retire();
                return (PendingRemoteCandidateQueuePush::Refused, kind);
            }
        };
        let kind = kind.expect("successful candidate validation records its classification");
        let Some(digest) = elastic_lease.digest() else {
            self.retire();
            return (
                PendingRemoteCandidateQueuePush::ResourceUnavailable(
                    ResourceUnavailable::ProviderInvariant {
                        dimension: crate::resource::ResourceClass::StorageObject,
                    },
                ),
                Some(kind),
            );
        };
        let result = self.pending.push(
            candidate,
            Arc::clone(&self.attempt),
            resource_scope,
            &self.work_resources,
            PendingRemoteCandidateReservation::default(),
            elastic_lease,
        );
        if result == PendingRemoteCandidateQueuePush::Queued {
            self.seen.insert(digest);
        } else if matches!(
            result,
            PendingRemoteCandidateQueuePush::Refused
                | PendingRemoteCandidateQueuePush::ResourceUnavailable(_)
        ) {
            self.retire();
        }
        (result, Some(kind))
    }

    fn retire(&mut self) {
        self.attempt.retire();
        self.elastic_attempt.retire();
        self.pending.entries.clear();
        self.pending.container_observation = None;
        self.seen.clear();
        self.retained_reservations.clear();
    }

    fn owns_attempt(&self, attempt: &Arc<RemoteCandidateAttemptIdentity>) -> bool {
        Arc::ptr_eq(&self.attempt, attempt) && attempt.is_active()
    }

    fn last_candidate_matches_remote_credentials(&self) -> bool {
        let Some(credentials) = self.remote_ice_credentials.as_ref() else {
            return true;
        };
        self.pending.entries.back().is_none_or(|pending| {
            candidate_matches_remote_credentials(&pending.candidate, credentials)
        })
    }

    fn adopt_queued_candidates_for_remote_restart(
        &mut self,
        source: &mut Self,
        credentials: &RemoteIceCredentials,
    ) -> bool {
        self.pending.entries = std::mem::take(&mut source.pending.entries);
        self.pending.container_observation = source.pending.container_observation.take();
        // The retiring set no longer owns any queued candidate after the list
        // moves. Release those digest nodes before the replacement set is
        // populated so migration never retains two uncharged copies.
        source.seen.clear();
        self.pending
            .retain_remote_restart_migratable_candidates(credentials);

        for pending in &mut self.pending.entries {
            if candidate_content_bytes(&pending.candidate).is_none() {
                self.retire();
                return false;
            }
            let input = ElasticRemoteCandidateInput {
                candidate: pending.candidate.candidate.as_bytes(),
                sdp_mid: pending.candidate.sdp_mid.as_deref().map(str::as_bytes),
                sdp_mline_index: pending.candidate.sdp_mline_index,
                username_fragment: pending
                    .candidate
                    .username_fragment
                    .as_deref()
                    .map(str::as_bytes),
            };
            let elastic_lease = match self.elastic_attempt.admit(input) {
                Ok(lease) => lease,
                Err(error) => {
                    warn!(
                        ?error,
                        "replacement ICE attempt refused migrated candidate work"
                    );
                    self.retire();
                    return false;
                }
            };
            let Some(digest) = elastic_lease.digest() else {
                self.retire();
                return false;
            };
            pending.attempt = Arc::clone(&self.attempt);
            pending._queue_reservation = Some(PendingRemoteCandidateReservation::default());
            pending._elastic_lease = Some(elastic_lease);
            self.seen.insert(digest);
        }
        true
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum IceRestartDirection {
    Local,
    Remote,
}

struct ProvisionalRemoteCandidateAttempt {
    direction: IceRestartDirection,
    envelope: RemoteCandidateAttemptEnvelope,
}

// The owner's four candidate ceilings used to be translated here into the
// elastic attempt's optional cumulative ceilings. Both ends of that translation
// are gone: there is no owner ceiling to read, and the primitive no longer
// carries an optional one to write. What the attempt enforces is what it always
// enforced without them — an exact claim per submission, per digest node, and
// per native application.

/// The candidate work one raw candidate-state control intends to fund.
///
/// Not a policy and not a ceiling: nothing reads these two numbers at run time.
/// They size the fixture's *grant*, so a control that says "one candidate of
/// this many content bytes" gets a provider that can fund exactly that and
/// refuses the next one — which is the only mechanism left that can refuse a
/// candidate, and therefore the one these controls have to exercise.
#[cfg(test)]
#[derive(Clone, Copy, Debug)]
struct RemoteCandidateFixtureWork {
    unique: u64,
    content: u64,
}

#[cfg(test)]
impl RemoteCandidateFixtureWork {
    fn new(unique: usize, content: usize) -> Self {
        Self {
            unique: u64::try_from(unique).expect("fixture candidate count fits u64"),
            content: u64::try_from(content).expect("fixture candidate content fits u64"),
        }
    }
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope(
    work: RemoteCandidateFixtureWork,
) -> ConnectorWorkResourceScope {
    elastic_remote_candidate_test_scope_with_additional(work, crate::resource::ResourceClaim::ZERO)
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope_with_restart_overlap(
    work: RemoteCandidateFixtureWork,
) -> ConnectorWorkResourceScope {
    let unique = work.unique;
    let reservation_records = unique
        .checked_add(1)
        .expect("fixture restart reservation records fit");
    let overlap = crate::runtime::attempt::remote_candidate_attempt_root_claim()
        .and_then(|claim| {
            claim.checked_add(
                crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)?,
            )
        })
        .and_then(|claim| {
            claim.checked_add(crate::resource::ResourceClaim::single(
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                reservation_records,
            ))
        })
        .expect("fixture restart overlap claim is representable");
    elastic_remote_candidate_test_scope_with_additional(work, overlap)
}

#[cfg(test)]
fn elastic_remote_candidate_test_scope_with_additional(
    work: RemoteCandidateFixtureWork,
    additional: crate::resource::ResourceClaim,
) -> ConnectorWorkResourceScope {
    let (_provider, _owner, _candidate, _lifetime, work_scope) =
        elastic_remote_candidate_test_resources_with_additional(work, additional);
    work_scope
}

#[cfg(test)]
fn elastic_remote_candidate_test_resources_with_additional(
    work: RemoteCandidateFixtureWork,
    additional: crate::resource::ResourceClaim,
) -> (
    crate::resource::FiniteResourceProvider,
    crate::runtime::attempt::ConnectorResourceOwnerPort,
    crate::runtime::attempt::ConnectorCandidateCapability,
    AttemptLifetime,
    ConnectorWorkResourceScope,
) {
    let RemoteCandidateFixtureWork { unique, content } = work;
    let parsing = content
        .checked_add(crate::runtime::attempt::REMOTE_CANDIDATE_MAX_DIGEST_OVERHEAD_BYTES)
        .expect("fixture parsing work fits");
    let candidate_work =
        crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)
            .and_then(|claim| {
                claim.checked_add(crate::resource::ResourceClaim::try_from_entries([
                    (crate::resource::ResourceClass::ParsingOrCpuWork, parsing),
                    (
                        crate::resource::ResourceClass::OpaqueDependencyResidual,
                        unique
                            .checked_add(1)
                            .expect("fixture reservation records fit"),
                    ),
                ])?)
            })
            .and_then(|claim| {
                let queue = pending_remote_candidate_queue_claim_with_content(0, 0)?
                    .checked_scale(unique)?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::AccountedMemoryBytes,
                        content,
                    ))?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::QueuedBytes,
                        content,
                    ))?
                    .checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::OpaqueDependencyResidual,
                        unique,
                    ))?;
                claim.checked_add(queue)
            })
            .expect("fixture candidate-work grant is representable");
    let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
        .checked_add(candidate_work)
        .and_then(|grant| grant.checked_add(additional))
        .expect("fixture resource grant is representable");
    let provider = crate::resource::FiniteResourceProvider::new(grant);
    let port = crate::resource::ResourceProviderPort::new(provider.clone())
        .expect("fixture provider admits its process scope");
    let owner = crate::runtime::attempt::ConnectorResourceOwnerPort::new(port);
    let mesh = owner
        .issue_mesh_scope()
        .expect("fixture provider admits its Mesh scope");
    let (permit, lifetime, claim) =
        admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
    let candidate = permit
        .reserve_connector_candidate(claim)
        .expect("fixture provider admits its connector candidate");
    let work_scope = candidate.work_resource_scope();
    (provider, owner, candidate, lifetime, work_scope)
}

struct RemoteCandidateState {
    current: RemoteCandidateAttemptEnvelope,
    provisional: Option<ProvisionalRemoteCandidateAttempt>,
}

impl RemoteCandidateState {
    fn with_resources(work_resources: ConnectorWorkResourceScope) -> Self {
        Self {
            current: RemoteCandidateAttemptEnvelope::new(work_resources),
            provisional: None,
        }
    }

    #[cfg(test)]
    fn new(work: RemoteCandidateFixtureWork) -> Self {
        Self::with_resources(elastic_remote_candidate_test_scope(work))
    }

    #[cfg(test)]
    fn new_with_restart_overlap(work: RemoteCandidateFixtureWork) -> Self {
        Self::with_resources(elastic_remote_candidate_test_scope_with_restart_overlap(
            work,
        ))
    }

    fn admission_target(&mut self) -> &mut RemoteCandidateAttemptEnvelope {
        self.provisional
            .as_mut()
            .map_or(&mut self.current, |provisional| &mut provisional.envelope)
    }

    #[cfg(test)]
    fn admit(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> PendingRemoteCandidateQueuePush {
        self.admission_target().admit(candidate, resource_scope)
    }

    fn admit_observed(
        &mut self,
        candidate: LocalIceCandidate,
        resource_scope: &PeerConnectionResourceScope,
    ) -> (
        PendingRemoteCandidateQueuePush,
        Option<super::diag::IceCandidateKind>,
    ) {
        self.admission_target()
            .admit_observed(candidate, resource_scope)
    }

    fn begin_local_ice_restart(
        &mut self,
    ) -> Result<(
        Arc<RemoteCandidateAttemptIdentity>,
        Arc<RemoteCandidateAttemptIdentity>,
    )> {
        if self.provisional.is_some() {
            return Err(Error::Transport(
                "an ICE restart transaction is already provisional".to_string(),
            ));
        }
        if self.current.remote_description_in_flight {
            return Err(Error::Transport(
                "cannot begin local ICE restart while a remote description is in flight"
                    .to_string(),
            ));
        }
        let retiring = Arc::clone(&self.current.attempt);
        let replacement =
            RemoteCandidateAttemptEnvelope::new_provisional(self.current.work_resources.clone())?;
        self.current.retire();
        let replacement_attempt = Arc::clone(&replacement.attempt);
        self.provisional = Some(ProvisionalRemoteCandidateAttempt {
            direction: IceRestartDirection::Local,
            envelope: replacement,
        });
        Ok((retiring, replacement_attempt))
    }

    fn owns_attempt(&self, attempt: &Arc<RemoteCandidateAttemptIdentity>) -> bool {
        self.current.owns_attempt(attempt)
            || self
                .provisional
                .as_ref()
                .is_some_and(|provisional| provisional.envelope.owns_attempt(attempt))
    }

    fn candidate_matches_attempt(
        &self,
        attempt: &Arc<RemoteCandidateAttemptIdentity>,
        candidate: &LocalIceCandidate,
    ) -> bool {
        let envelope = if Arc::ptr_eq(&self.current.attempt, attempt) {
            Some(&self.current)
        } else {
            self.provisional.as_ref().and_then(|provisional| {
                Arc::ptr_eq(&provisional.envelope.attempt, attempt).then_some(&provisional.envelope)
            })
        };
        let Some(credentials) =
            envelope.and_then(|envelope| envelope.remote_ice_credentials.as_ref())
        else {
            return envelope.is_some();
        };
        candidate_matches_remote_credentials(candidate, credentials)
    }

    fn commit_local_ice_restart(
        &mut self,
        attempt: &Arc<RemoteCandidateAttemptIdentity>,
    ) -> Result<()> {
        let mut provisional = self.provisional.take().ok_or_else(|| {
            Error::Transport("local ICE restart lost its provisional attempt".to_string())
        })?;
        if provisional.direction != IceRestartDirection::Local
            || !provisional.envelope.owns_attempt(attempt)
        {
            provisional.envelope.retire();
            return Err(Error::Transport(
                "local ICE restart provisional attempt was replaced".to_string(),
            ));
        }
        let mut replacement = provisional.envelope;
        let provisional_root_lease = replacement.provisional_root_lease.take();
        self.current = replacement;
        drop(provisional_root_lease);
        Ok(())
    }

    #[cfg(test)]
    fn fail_provisional(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if self
            .provisional
            .as_ref()
            .is_some_and(|provisional| Arc::ptr_eq(&provisional.envelope.attempt, attempt))
        {
            if let Some(mut provisional) = self.provisional.take() {
                provisional.envelope.retire();
            }
        }
    }

    /// Abort an ICE transaction whose native outcome was never proven and
    /// leave no reusable candidate-attempt state behind.
    ///
    /// This method is intentionally synchronous so a dropped async operation
    /// can fence its exact process-local attempt before the connector close
    /// owner drains the remaining native state.
    fn abort_unproven_transaction(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if Arc::ptr_eq(&self.current.attempt, attempt) {
            self.current.remote_description_in_flight = false;
            self.current.retire();
            return;
        }
        if self
            .provisional
            .as_ref()
            .is_some_and(|provisional| Arc::ptr_eq(&provisional.envelope.attempt, attempt))
        {
            if let Some(mut provisional) = self.provisional.take() {
                provisional.envelope.retire();
            }
        }
    }

    fn has_no_viable_attempt(&self) -> bool {
        !self.current.attempt.is_active()
            && self
                .provisional
                .as_ref()
                .is_none_or(|provisional| !provisional.envelope.attempt.is_active())
    }

    fn prepare_remote_description(
        &mut self,
        credentials: RemoteIceCredentials,
    ) -> Result<RemoteDescriptionAttempt> {
        if let Some(provisional) = self.provisional.as_mut() {
            if provisional.direction == IceRestartDirection::Local {
                return Err(Error::Transport(
                    "replacement remote description arrived before native local ICE restart committed"
                        .to_string(),
                ));
            }
            if provisional.envelope.remote_description_in_flight {
                return Err(Error::Transport(
                    "replacement remote description is already in flight".to_string(),
                ));
            }
            if let Some(expected) = provisional.envelope.remote_ice_credentials.as_ref() {
                if expected != &credentials {
                    provisional.envelope.retire();
                    return Err(Error::Transport(
                        "replacement remote description changed ICE credentials during the provisional transaction"
                            .to_string(),
                    ));
                }
            } else {
                provisional.envelope.remote_ice_credentials = Some(credentials.clone());
            }
            provisional.envelope.remote_description_in_flight = true;
            return Ok(RemoteDescriptionAttempt {
                attempt: Arc::clone(&provisional.envelope.attempt),
                provisional: true,
                retiring: None,
                credentials,
            });
        }

        if self.current.remote_description_in_flight {
            return Err(Error::Transport(
                "remote description is already in flight for this ICE attempt".to_string(),
            ));
        }

        let is_restart = self
            .current
            .remote_ice_credentials
            .as_ref()
            .is_some_and(|current| current.proves_restart_to(&credentials));
        if !is_restart {
            self.current.remote_description_in_flight = true;
            return Ok(RemoteDescriptionAttempt {
                attempt: Arc::clone(&self.current.attempt),
                provisional: false,
                retiring: None,
                credentials,
            });
        }

        let mut replacement =
            RemoteCandidateAttemptEnvelope::new_provisional(self.current.work_resources.clone())?;
        replacement.remote_ice_credentials = Some(credentials.clone());
        replacement.remote_description_in_flight = true;
        let migrated =
            replacement.adopt_queued_candidates_for_remote_restart(&mut self.current, &credentials);
        let retiring = Arc::clone(&self.current.attempt);
        self.current.retire();
        let attempt = Arc::clone(&replacement.attempt);
        self.provisional = Some(ProvisionalRemoteCandidateAttempt {
            direction: IceRestartDirection::Remote,
            envelope: replacement,
        });
        if !migrated {
            return Err(Error::Transport(
                "remote ICE restart could not conservatively transfer its bounded pre-description candidates"
                    .to_string(),
            ));
        }
        Ok(RemoteDescriptionAttempt {
            attempt,
            provisional: true,
            retiring: Some(retiring),
            credentials,
        })
    }

    fn commit_remote_description(
        &mut self,
        prepared: &RemoteDescriptionAttempt,
    ) -> Result<PendingRemoteCandidateDrain> {
        if prepared.provisional {
            let mut provisional = self.provisional.take().ok_or_else(|| {
                Error::Transport("remote description lost its provisional ICE attempt".to_string())
            })?;
            if !provisional.envelope.owns_attempt(&prepared.attempt) {
                provisional.envelope.retire();
                return Err(Error::Transport(
                    "remote description provisional ICE attempt was replaced".to_string(),
                ));
            }
            let mut replacement = provisional.envelope;
            let provisional_root_lease = replacement.provisional_root_lease.take();
            self.current = replacement;
            drop(provisional_root_lease);
        } else if !self.current.owns_attempt(&prepared.attempt) {
            return Err(Error::Transport(
                "remote description belongs to a retired ICE attempt".to_string(),
            ));
        }
        if !self.current.remote_description_in_flight {
            self.current.retire();
            return Err(Error::Transport(
                "remote description commit lost its in-flight transaction".to_string(),
            ));
        }
        self.current.remote_description_in_flight = false;
        self.current.remote_ice_credentials = Some(prepared.credentials.clone());
        self.current.remote_description_set = true;
        self.current
            .pending
            .retain_matching_remote_credentials(&prepared.credentials);
        Ok(self.current.pending.take())
    }

    fn retire_attempt(&mut self, attempt: &Arc<RemoteCandidateAttemptIdentity>) {
        if Arc::ptr_eq(&self.current.attempt, attempt) {
            self.current.retire();
            return;
        }
        if let Some(provisional) = self.provisional.as_mut() {
            if Arc::ptr_eq(&provisional.envelope.attempt, attempt) {
                provisional.envelope.retire();
            }
        }
    }

    #[cfg(test)]
    fn fail_remote_description(&mut self, prepared: &RemoteDescriptionAttempt) {
        if prepared.provisional {
            self.fail_provisional(&prepared.attempt);
        } else if Arc::ptr_eq(&self.current.attempt, &prepared.attempt) {
            self.current.remote_description_in_flight = false;
        }
    }
}

impl Drop for RemoteCandidateState {
    fn drop(&mut self) {
        self.current.retire();
        if let Some(provisional) = self.provisional.as_mut() {
            provisional.envelope.retire();
        }
    }
}

struct RemoteDescriptionAttempt {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    provisional: bool,
    retiring: Option<Arc<RemoteCandidateAttemptIdentity>>,
    credentials: RemoteIceCredentials,
}

/// Drop guard for an ICE mutation that has changed process-local ownership but
/// has not yet proven both native success and the exact state commit.
struct UncommittedIceTransaction {
    state: Arc<SyncMutex<RemoteCandidateState>>,
    close_owner: Arc<ConnectorCloseOwner>,
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    armed: bool,
}

impl UncommittedIceTransaction {
    fn new(
        state: Arc<SyncMutex<RemoteCandidateState>>,
        close_owner: Arc<ConnectorCloseOwner>,
        attempt: Arc<RemoteCandidateAttemptIdentity>,
    ) -> Self {
        Self {
            state,
            close_owner,
            attempt,
            armed: true,
        }
    }

    fn disarm(&mut self) {
        self.armed = false;
    }
}

impl Drop for UncommittedIceTransaction {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        {
            self.state.lock().abort_unproven_transaction(&self.attempt);
        }
        // `start` drains the candidate state, so it must run after the state
        // lock above has been released.
        self.close_owner.start();
    }
}

#[derive(Debug)]
struct RemoteCandidateAttemptState {
    active_operations: usize,
    accounting_poisoned: bool,
}

/// Process-local identity and cancellation fence for one ICE candidate attempt.
#[derive(Debug)]
struct RemoteCandidateAttemptIdentity {
    active: AtomicBool,
    state: SyncMutex<RemoteCandidateAttemptState>,
    active_signal: watch::Sender<usize>,
}

impl Default for RemoteCandidateAttemptIdentity {
    fn default() -> Self {
        let (active_signal, _receiver) = watch::channel(0);
        Self {
            active: AtomicBool::new(true),
            state: SyncMutex::new(RemoteCandidateAttemptState {
                active_operations: 0,
                accounting_poisoned: false,
            }),
            active_signal,
        }
    }
}

impl RemoteCandidateAttemptIdentity {
    fn try_enter(self: &Arc<Self>) -> Option<RemoteCandidateAttemptPermit> {
        let mut state = self.state.lock();
        if !self.active.load(Ordering::Acquire) || state.accounting_poisoned {
            return None;
        }
        let Some(active_operations) = state.active_operations.checked_add(1) else {
            state.accounting_poisoned = true;
            self.active.store(false, Ordering::Release);
            return None;
        };
        state.active_operations = active_operations;
        self.active_signal.send_replace(active_operations);
        Some(RemoteCandidateAttemptPermit {
            attempt: Arc::clone(self),
            active: true,
        })
    }

    fn retire(&self) {
        self.active.store(false, Ordering::Release);
    }

    fn is_active(&self) -> bool {
        self.active.load(Ordering::Acquire)
    }

    async fn wait_for_operations(&self) {
        let mut active = self.active_signal.subscribe();
        loop {
            if *active.borrow() == 0 {
                return;
            }
            if active.changed().await.is_err() {
                return;
            }
        }
    }
}

struct RemoteCandidateAttemptPermit {
    attempt: Arc<RemoteCandidateAttemptIdentity>,
    active: bool,
}

impl Drop for RemoteCandidateAttemptPermit {
    fn drop(&mut self) {
        if !self.active {
            return;
        }
        let mut state = self.attempt.state.lock();
        let Some(active_operations) = state.active_operations.checked_sub(1) else {
            state.accounting_poisoned = true;
            self.attempt.active.store(false, Ordering::Release);
            return;
        };
        state.active_operations = active_operations;
        self.attempt.active_signal.send_replace(active_operations);
        self.active = false;
    }
}

#[cfg(test)]
fn candidate_content_digest(candidate: &LocalIceCandidate) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash_candidate_string(&mut hash, Some(&candidate.candidate));
    hash_candidate_string(&mut hash, candidate.sdp_mid.as_ref());
    match candidate.sdp_mline_index {
        Some(value) => {
            hash.update([1]);
            hash.update(value.to_be_bytes());
        }
        None => hash.update([0]),
    }
    hash_candidate_string(&mut hash, candidate.username_fragment.as_ref());
    hash.finalize().into()
}

#[cfg(test)]
fn hash_candidate_string(hash: &mut Sha256, value: Option<&String>) {
    match value {
        Some(value) => {
            hash.update([1]);
            hash.update(value.len().to_be_bytes());
            hash.update(value.as_bytes());
        }
        None => {
            hash.update([0]);
        }
    }
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
    operation_fence: Arc<ConnectorOperationFence>,
    work_resource_scope: Arc<SyncMutex<Option<ConnectorWorkResourceScope>>>,
    candidate_promoted: Arc<AtomicBool>,
    cleanup_complete: Arc<AtomicBool>,
    cleanup_failed: Arc<AtomicBool>,
}

impl ConnectorOwnership {
    fn admitted(
        candidate: ConnectorCandidateCapability,
        operation_fence: Arc<ConnectorOperationFence>,
        work_resource_scope: ConnectorWorkResourceScope,
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
            operation_fence,
            work_resource_scope: Arc::new(SyncMutex::new(Some(work_resource_scope))),
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
            // Application bytes and real-time units are both refused before the
            // channel is connected, and for the same reason: neither can be
            // authorized by anything this state holds. The real-time arm is
            // structurally unreachable — a unit exists only for a flow a
            // promoted session opened, and promotion cannot happen before
            // `Connected` — and it is written out rather than folded into the
            // liveness arm below so that reachability is a property of this
            // match rather than an inference about a caller.
            (
                ConnectorAuthorityState::Awaiting { liveness, .. },
                TransportEvent::Message(_)
                | TransportEvent::ApplicationFlowMessage { .. }
                | TransportEvent::RealtimeUnit(_),
            ) => {
                let _ = liveness;
                false
            }
            (ConnectorAuthorityState::Awaiting { liveness, .. }, _) => liveness.is_active(),
            (ConnectorAuthorityState::Promoting, _) => false,
            (ConnectorAuthorityState::Connected, _) => true,
        }
    }

    /// Whether `task` is the endpoint-authentication owner for this exact
    /// connector incarnation.
    ///
    /// Two conjuncts, and both are load-bearing. The WebRTC liveness flag is
    /// this adapter's own retirement state; the identity comparison is made
    /// against the transport-independent identity, because that is the only one
    /// the task holds. The task names a `ConnectorIncarnation` and knows nothing
    /// about WebRTC — the translation belongs on this side of the boundary, not
    /// in `endpoint_auth`, and `belongs_to` stays an exact identity check rather
    /// than being widened to accept a transport type.
    fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.incarnation.is_active() && task.belongs_to(self.incarnation.generic())
    }

    /// This worker's transport-independent connector identity, but only while
    /// the connector is still live.
    ///
    /// Both conjuncts, from their one authoritative source each: the identity is
    /// the incarnation's, and the liveness is `is_active`, which this type owns.
    /// A retired worker answers `None`, so a promotion cannot name a connector
    /// that has already gone.
    pub(crate) fn live_connector_incarnation(
        &self,
    ) -> Option<&Arc<crate::connector::ConnectorIncarnation>> {
        self.incarnation
            .is_active()
            .then(|| self.incarnation.generic())
    }

    fn enter_operation(&self) -> Result<ConnectorOwnedOperationPermit> {
        let work_resource_scope = self
            .work_resource_scope()
            .ok_or_else(|| Error::Transport("connector work scope was relinquished".to_string()))?;
        let resources = work_resource_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::runtime::attempt::connector_operation_claim(),
            )
            .map_err(Error::from)?;
        let fence = self
            .operation_fence
            .try_enter()
            .ok_or_else(|| Error::Transport("connector close fence has committed".to_string()))?;
        Ok(ConnectorOwnedOperationPermit {
            _fence: fence,
            _resources: resources,
        })
    }

    fn relinquish_work_resource_scope(&self) {
        self.work_resource_scope.lock().take();
    }

    fn work_resource_scope(&self) -> Option<ConnectorWorkResourceScope> {
        self.work_resource_scope.lock().clone()
    }

    fn begin_close(&self) {
        self.operation_fence.begin_close();
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
        self.begin_close();
        let mut authority = self.authority.lock();
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
        self.begin_close();
        let mut authority = self.authority.lock();
        if matches!(&*authority, ConnectorAuthorityState::Connected) {
            return false;
        }
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
            if let Some(candidate) = candidate.as_mut() {
                candidate.release_after_cleanup_success();
            }
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

struct ConnectorOwnedOperationPermit {
    _fence: ConnectorOperationPermit,
    _resources: crate::resource::ResourceLease,
}

/// Connector send authority taken at one instant and spent at a later one.
///
/// A caller that must decide "may this send happen?" under a lock it cannot
/// hold across an await takes this value there, and awaits the send afterwards.
/// The permit inside is the whole authority: it is acquired before the decision
/// and held until the send resolves, so the connector cannot close in between.
///
/// This is deliberately *not* `send_owned` with a later await. `send_owned`
/// enters the fence at await time, which is too late for such a caller — the
/// close may already have committed — and it also cancels on retirement.
/// Retirement is not close: `WebRtcConnectorIncarnation::retire` only flips the
/// active flag and the retirement watch, and cleanup runs it *before* draining
/// the operation fence (`cleanup::run`), so a send that watched retirement
/// would abort in exactly the window this permit exists to protect. The native
/// session is untouched until `native.close()`, which the drain orders after
/// this permit drops.
pub(crate) struct StartedConnectorSend {
    session: Arc<PeerSession>,
    /// The authority itself. Dropping this value — including by dropping the
    /// send future before it resolves — releases the connector to close, which
    /// is the cancellation contract every other permit holder here has.
    ///
    /// Named without an underscore because `send` really does read it: the
    /// permit's drop point is the invariant, so it is spelled out rather than
    /// left to whatever the enclosing value's capture happens to imply.
    permit: ConnectorOwnedOperationPermit,
}

impl StartedConnectorSend {
    /// Spend the authority taken at `begin_send`.
    ///
    /// No fence re-entry and no retirement watch: re-entering could fail after
    /// a close began, which would discard an authority already granted, and
    /// watching retirement would cancel a send the fence has promised to wait
    /// for.
    ///
    /// The permit is bound and dropped explicitly around the await. Moving
    /// `self` into the future would already keep it alive, but that is an
    /// inference about capture; the whole close-drain invariant rests on this
    /// one lifetime, so it is written where a reader checks it.
    pub(crate) async fn send(self, data: Bytes) -> Result<usize> {
        let Self { session, permit } = self;
        let sent = session.send(data).await;
        drop(permit);
        sent
    }
}

fn candidate_resource_measurement(candidate: &LocalIceCandidate) -> ResourceMeasurement {
    let (logical_bytes, _) = measured_sum([
        candidate.candidate.len(),
        candidate.sdp_mid.as_ref().map_or(0, String::len),
        candidate
            .sdp_mline_index
            .map_or(0, |_| std::mem::size_of::<u16>()),
        candidate.username_fragment.as_ref().map_or(0, String::len),
    ]);
    let (retained_bytes, _) = measured_sum([
        candidate.candidate.capacity(),
        candidate.sdp_mid.as_ref().map_or(0, String::capacity),
        candidate
            .username_fragment
            .as_ref()
            .map_or(0, String::capacity),
    ]);
    let observed = ResourceUse::observed(1, logical_bytes, retained_bytes, 0);
    // String capacities and the content fields are observable, but allocator
    // overhead and storage retained inside webrtc-rs are not. This must not be
    // reported as exact retained memory.
    ResourceMeasurement::inexact(observed)
}

fn queue_container_resource_measurement(
    entries: &std::collections::LinkedList<PendingRemoteCandidate>,
) -> ResourceMeasurement {
    let bytes = entries
        .len()
        .checked_mul(size_of::<PendingRemoteCandidate>());
    let (retained_bytes, _) = measured_usize(bytes);
    let observed = ResourceUse::observed(0, 0, retained_bytes, 0);
    // Each linked-list node is paired with the candidate's provider-backed
    // storage-object claim. Allocator overhead remains observationally
    // inexact.
    ResourceMeasurement::inexact(observed)
}

fn measured_usize(value: Option<usize>) -> (u64, bool) {
    match value.and_then(|value| u64::try_from(value).ok()) {
        Some(value) => (value, false),
        None => (0, true),
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
                sum = 0;
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

#[cfg(feature = "transport-lab")]
static NEXT_CALLBACK_OBSERVATION_ID: AtomicU64 = AtomicU64::new(1);

#[cfg(feature = "transport-lab")]
struct CallbackObservationLease {
    id: u64,
    site: &'static str,
    lease: Option<ObservationLease>,
}

#[cfg(feature = "transport-lab")]
impl Drop for CallbackObservationLease {
    fn drop(&mut self) {
        drop(self.lease.take());
        eprintln!(
            "[transport-lab] callback-observation dropped id={} site={}",
            self.id, self.site
        );
    }
}

#[cfg(not(feature = "transport-lab"))]
type CallbackObservationLease = ObservationLease;

fn observe_callback_if(
    scope: Option<&PeerConnectionResourceScope>,
    site: &'static str,
) -> Option<CallbackObservationLease> {
    scope.map(|scope| {
        let lease = observe_inexact_item(scope, PreAuthResourceFamily::Callback, 1, 0);
        #[cfg(feature = "transport-lab")]
        {
            let id = NEXT_CALLBACK_OBSERVATION_ID.fetch_add(1, Ordering::Relaxed);
            eprintln!("[transport-lab] callback-observation constructed id={id} site={site}");
            CallbackObservationLease {
                id,
                site,
                lease: Some(lease),
            }
        }
        #[cfg(not(feature = "transport-lab"))]
        {
            let _ = site;
            lease
        }
    })
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

    // No accessors for the incarnation or the borrowed capability. This type is
    // now a one-way staging step: a connector builds it and immediately moves it
    // into its transport-independent form. Endpoint authentication inspects and
    // validates the *generic* handoff, so exposing a WebRTC-shaped identity or
    // capability borrow here would only offer a second, transport-specific way
    // to reach facts that already have one owner.

    // Deliberately no `take`/`restore` of the bare capability. Promotion moves
    // the *whole* handoff, because this type is what carries the connector
    // incarnation and the close owner, and its `Drop` is what re-retains the
    // connected claim until native close succeeds. Extracting the capability
    // alone would strip that retention, so an authenticated capability dropped
    // on retirement or on a refused install would release the claim early.

    /// Move this handoff into its transport-independent form.
    ///
    /// The whole ownership triple moves together: the capability, the generic
    /// identity for this exact incarnation, and this close owner as the
    /// retention obligation. Nothing is copied and nothing is left behind — the
    /// consumed WebRTC handoff drops with no capability, so the claim is
    /// retained exactly once, by the generic handoff's `Drop`, through this same
    /// close owner.
    ///
    /// Returns `None` only if the capability was already moved out — the same
    /// condition under which this handoff's own `Drop` retains nothing.
    pub(crate) fn into_generic(mut self) -> Option<crate::connector::ConnectedChannelHandoff> {
        let capability = self.capability.take()?;
        Some(crate::connector::ConnectedChannelHandoff::new(
            capability,
            Arc::clone(self.incarnation.generic()),
            self.close_owner.generic_retention(),
        ))
    }
}

/// One fixture task over a WebRTC handoff, for the connector lifecycle
/// controls.
///
/// Those controls exercise retirement, replacement, and admission around a
/// task; they do not exercise the exchange. This converts the handoff to its
/// generic form and defers to the endpoint-authentication fixture constructor,
/// so the cryptographic context is defined in exactly one place rather than
/// re-stated at every call site.
#[cfg(test)]
fn task_from_handoff(handoff: EndpointAuthHandoff) -> crate::endpoint_auth::EndpointAuthTask {
    crate::endpoint_auth::task_for_test(
        handoff
            .into_generic()
            .expect("a freshly built handoff still carries its capability"),
    )
}

/// The same conversion, forcing this endpoint's contribution to a prior value.
///
/// Only the same-certificate replay control needs it, to build the one case the
/// freshness rule prevents. See `endpoint_auth::task_reusing_contribution_for_test`.
#[cfg(test)]
fn task_from_handoff_reusing(
    handoff: EndpointAuthHandoff,
    local_contribution: &str,
) -> crate::endpoint_auth::EndpointAuthTask {
    crate::endpoint_auth::task_reusing_contribution_for_test(
        handoff
            .into_generic()
            .expect("a freshly built handoff still carries its capability"),
        crate::endpoint_auth::LocalContribution::reuse_for_test(local_contribution),
    )
}

impl Drop for EndpointAuthHandoff {
    fn drop(&mut self) {
        if let Some(capability) = self.capability.take() {
            self.close_owner.retain_connected_claim(capability);
        }
    }
}

/// One component of the endpoint-authentication channel binding this connector
/// can be made to withhold. **Controls only.**
///
/// A live native link whose data channel is open always presents both DTLS
/// fingerprints, so the condition the production supplier fails closed on —
/// half a pair — cannot be reached by driving the stack. Naming the component
/// here is what lets the two missing-side controls be exact twins that differ in
/// one value, rather than one control that proves "something was missing".
///
/// The whole withheld-binding surface is gated on `transport-lab` as well as
/// `test`, because the only thing that can arm it is the live two-connector
/// fixture, and that needs a real WebRTC link. Gating it on `test` alone leaves
/// every item here uncalled in a default-feature test build.
#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WithheldBindingComponent {
    Local,
    Remote,
}

#[cfg(all(test, feature = "transport-lab"))]
impl WithheldBindingComponent {
    /// The armed marker for this component. Never zero: zero is "withholding
    /// nothing", which is the state every connector is constructed in.
    fn marker(self) -> u8 {
        match self {
            Self::Local => 1,
            Self::Remote => 2,
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
    /// The flow registry this worker's sessions open against.
    ///
    /// Retained here rather than reached through `close_owner`, which already
    /// holds a handle for teardown. A teardown owner that also handed out live
    /// registries for constructing new things would carry two jobs that can
    /// disagree about which is authoritative during a close.
    realtime_flows: Arc<RealtimeFlowRegistry>,
    resource_scope: PeerConnectionResourceScope,
    /// Which single binding component this connector withholds from its own
    /// supplier. **Controls only**, compiled out of production entirely.
    ///
    /// Withhold-only and monotonic: there is no operation that supplies a
    /// component, restores one, or names both, so a fixture can remove material
    /// the live link genuinely stated and can never inject material it did not.
    /// That direction is the safety property — a seam that could supply a
    /// fingerprint would be the substitution this whole boundary exists to
    /// refuse, dressed as a test helper.
    #[cfg(all(test, feature = "transport-lab"))]
    withheld_binding_component: std::sync::atomic::AtomicU8,
    #[cfg(test)]
    native_candidate_apply_calls: Arc<std::sync::atomic::AtomicUsize>,
    #[cfg(test)]
    native_candidate_apply_gate: Option<Arc<NativeCandidateApplyGate>>,
}

struct AdmittedConnectorOwnership {
    ownership: ConnectorOwnership,
    attempt_lifetime: AttemptLifetime,
    attempt_liveness: AttemptLiveness,
    close_owner: Arc<ConnectorCloseOwner>,
    resource_scope: PeerConnectionResourceScope,
    work_resource_scope: ConnectorWorkResourceScope,
}

/// The session side of the realtime flow binding.
///
/// Placed here rather than in `runtime::session_broker` so the session type
/// stays transport-independent: it never names a WebRTC incarnation, and this
/// module already knows both vocabularies.
///
/// `is_current_on` answers **identity only**, and that is not a gap. The
/// liveness half is carried by how the caller obtains its argument: the only
/// production source of an incarnation to pass here is
/// [`WebRtcConnectorWorker::live_connector_incarnation`], which yields `None`
/// once the connector is retired. So a retired connector cannot produce an
/// argument for this call at all, and the pair of conjuncts holds without the
/// session caching a liveness flag that could disagree with the connector.
impl session_flow::RealtimeSessionBinding for crate::runtime::session_broker::SessionCapability {
    fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
        self.belongs_to(incarnation)
    }
}

/// Fixed, payload-free refusal vocabulary for the funded callback control.
#[cfg(all(test, feature = "route-flow-diagnostics"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FundedCallbackTestRefusal {
    NotConnected,
    ObservationUnavailable,
    NativeAdmission,
    NotQueued,
}

impl WebRtcConnectorWorker {
    /// Prepare the original receiver's lifecycle in an already-connected
    /// fixture. The caller must expose and accept this exact Open, then call
    /// the existing receiver commit. This is not native Open/auth qualification.
    #[cfg(all(test, feature = "route-flow-diagnostics"))]
    pub(crate) async fn enqueue_data_channel_open_callback_for_test(
        &self,
    ) -> std::result::Result<(), FundedCallbackTestRefusal> {
        self.session
            ._events_tx
            .enqueue_open_for_test(&self.ownership)
            .await
    }

    /// Inject through this worker's original native callback producer and
    /// receiver. No event stamp, observation, or provider is supplied by callers.
    /// This proves callback custody, not arrival over an actual SCTP connection.
    #[cfg(all(test, feature = "route-flow-diagnostics"))]
    pub(crate) fn enqueue_funded_message_callback_for_test(
        &self,
        bytes: Bytes,
    ) -> impl std::future::Future<Output = std::result::Result<(), FundedCallbackTestRefusal>>
           + Send
           + 'static {
        self.session
            ._events_tx
            .enqueue_funded_message_for_test(&self.ownership, bytes)
    }

    /// Reserve exact finite work against this connector's attempt owner before
    /// parsing an endpoint protocol frame.
    pub(crate) fn reserve_attempt_work(
        &self,
        claim: crate::resource::ResourceClaim,
    ) -> std::result::Result<crate::resource::ResourceLease, crate::resource::ResourceUnavailable>
    {
        let Some(work_resource_scope) = self.ownership.work_resource_scope() else {
            return Err(crate::resource::ResourceUnavailable::ProviderInvariant {
                dimension: crate::resource::ResourceClass::WorkerOrTask,
            });
        };
        work_resource_scope.acquire(crate::resource::ResourceAuthorityClass::Speculative, claim)
    }

    /// Build the flow set one promoted session owns.
    ///
    /// The engine calls this at promotion and stores the result beside the
    /// capability, so the set is bound to the exact worker the session was
    /// promoted from. Constructing it here is what keeps `RealtimeFlowRegistry`
    /// unnameable by the engine — the opaque set is the only thing that crosses.
    pub(crate) fn new_session_flows(&self) -> session_flow::SessionRealtimeFlows {
        let flows = session_flow::SessionRealtimeFlows::new(
            Arc::clone(&self.realtime_flows),
            self.session.realtime_profile.clone(),
        );
        // Point the connector's `on_track` handler at this session's table, and
        // at no other. Installed here rather than by the engine because the
        // engine must not name `RealtimeInboundBindings` at all — this accessor
        // is the one place both vocabularies are already in scope.
        //
        // Weak, so the table cannot outlive the `PromotedSession` about to own
        // this set: when that drops, the upgrade in `on_track` fails and an
        // arriving track is refused, with nothing having to be told.
        self.session
            .realtime_tracks
            .install(flows.inbound_bindings());
        flows
    }

    /// Whether this connector may still do native realtime work, and the
    /// profile that says what it may do.
    ///
    /// One helper for the two conjuncts every method below opens with, so the
    /// order cannot drift between them: the connector is still live, and the
    /// application registered the family being asked for. The second is the
    /// **registered-profile selection** rule — core has no opinion about
    /// codecs, only about whether this one was offered, so an unregistered
    /// family is refused here rather than negotiated and then found
    /// unframeable at admission.
    fn realtime_negotiation_guard(&self, encoding: &RealtimeEncoding) -> Result<()> {
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport(
                "connector retired before realtime negotiation".to_string(),
            ));
        }
        let registered = self
            .session
            .realtime_profile
            .as_ref()
            .is_some_and(|profile| profile.profile().admits_encoding(encoding).is_some());
        if !registered {
            return Err(Error::Transport(
                "realtime encoding names no registered capability".to_string(),
            ));
        }
        Ok(())
    }

    /// Create the receive-only transceiver an inbound session flow attaches to.
    ///
    /// `identity` is minted and **already bound** by the engine's fence before
    /// this is called. That ordering is the whole design: the transceiver that
    /// could carry a track is created against a token that already resolves, so
    /// no track can arrive ahead of its binding and no start-of-flow media is
    /// lost to a race.
    ///
    /// This does not drive renegotiation. Adding a transceiver raises
    /// `RenegotiationNeeded`, which the engine already coalesces into one
    /// offer; a second path here would be a second offer for the same change.
    ///
    /// **Funded before it is created.** The transceiver's own claim is acquired
    /// from this connector's work scope ahead of the native call, so a connector
    /// out of capacity refuses to add an `m` line rather than adding one and
    /// then failing to account for it. Reserve-before-allocate, the same
    /// ordering every other native allocation on this connector uses; the lease
    /// is released only when a completed `stop` proves the object is gone.
    pub(crate) async fn open_inbound_realtime_transceiver(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
        encoding: &RealtimeEncoding,
    ) -> Result<()> {
        // Held across the whole call so a close cannot commit underneath a
        // half-created transceiver.
        let _operation = self.ownership.enter_operation()?;
        self.realtime_negotiation_guard(encoding)?;
        self.session.ensure_media_negotiation_callback();
        // Before the native call, and dropped by every `?` between here and the
        // record below — so a refused guard, a refused provider or a failed
        // `add_transceiver_from_kind` all leave this connector charged for
        // nothing.
        //
        // Two independent claims because they end at two different moments: the
        // record's node when the record is forgotten, the native half when a
        // `stop` has completed. A failed cleanup retains the second while the
        // first is still released normally, which is only expressible if they
        // were never one number.
        let record_claim = negotiated_inbound_record_claim()
            .map_err(|error| Error::Transport(format!("inbound realtime record claim: {error}")))?;
        let signal_claim = RealtimeRetirementSignal::mint_claim().map_err(|error| {
            Error::Transport(format!("inbound realtime completion claim: {error}"))
        })?;
        let native_claim = negotiated_inbound_transceiver_claim().map_err(|error| {
            Error::Transport(format!("inbound realtime transceiver claim: {error}"))
        })?;
        // A session with no connector reservation behind it cannot fund a native
        // object, and refusing is the only honest answer: creating one anyway
        // would put an unaccounted `m` line on the connection, which is the
        // defect this claim exists to make impossible.
        let Some(work_scope) = self.session.work_resource_scope.as_ref() else {
            return Err(Error::Transport(
                "inbound realtime negotiation has no connector work scope to fund a transceiver"
                    .to_string(),
            ));
        };
        // `Admitted`, not `Speculative`: a negotiated transceiver belongs to a
        // promoted session and is not candidate work that may be reclaimed
        // underneath the media it is carrying.
        let record_lease = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                record_claim,
            )
            .map_err(Error::ResourceUnavailable)?;
        let signal_lease = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                signal_claim,
            )
            .map_err(Error::ResourceUnavailable)?;
        let native_lease = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                native_claim,
            )
            .map_err(Error::ResourceUnavailable)?;
        let transceiver = self
            .session
            .pc
            .add_transceiver_from_kind(
                native_codec_type(encoding.kind()),
                Some(RTCRtpTransceiverInit {
                    // Receive only. A sendrecv transceiver would offer to send
                    // on a flow the application opened to receive, advertising
                    // a direction nothing here will ever write to.
                    direction: RTCRtpTransceiverDirection::Recvonly,
                    send_encodings: Vec::new(),
                }),
            )
            .await
            .map_err(|error| {
                Error::Transport(format!("inbound realtime add_transceiver: {error}"))
            })?;
        self.session.realtime_tracks.record(
            Arc::clone(identity),
            Arc::new(WebRtcNativeTransceiverPort { transceiver }),
            record_lease,
            signal_lease,
            native_lease,
        );
        Ok(())
    }

    /// Mint the exact identity one inbound flow will be negotiated against.
    ///
    /// Here rather than in the engine, and fallible for the same reason the
    /// retirement is: the allocation is funded from this connector's work scope,
    /// and the acquisition happens before the allocation exists. An engine that
    /// minted its own would be allocating a connector-scoped object it has no
    /// scope to pay for.
    ///
    /// The lease goes inside the identity, so it follows every holder — the
    /// binding, the retirement, a claim taken during a sweep — rather than
    /// ending when whichever of them happens to be dropped first goes.
    pub(crate) fn mint_inbound_realtime_identity(&self) -> Result<Arc<RealtimeTrackIdentity>> {
        let Some(work_scope) = self.session.work_resource_scope.as_ref() else {
            return Err(Error::Transport(
                "inbound realtime negotiation has no connector work scope to fund an identity"
                    .to_string(),
            ));
        };
        let claim = RealtimeTrackIdentity::mint_claim().map_err(|error| {
            Error::Transport(format!("inbound realtime identity claim: {error}"))
        })?;
        let lease = work_scope
            .acquire(crate::resource::ResourceAuthorityClass::Admitted, claim)
            .map_err(Error::ResourceUnavailable)?;
        Ok(RealtimeTrackIdentity::mint(lease))
    }

    /// Release a transceiver whose commit fence refused.
    ///
    /// Safe for a token that never recorded one — the engine calls this on
    /// paths where negotiation may not have got that far, and a caller should
    /// not have to know which. Answers nothing for the same reason: there is no
    /// action left for the caller either way.
    /// It is also the retirement path for a token handed back by
    /// `SessionRealtimeFlows::close`, which is the ordinary case rather than the
    /// exceptional one. Both go through the same claim, so a close racing the
    /// pump that was feeding the same flow cannot stop one transceiver twice.
    pub(crate) async fn close_inbound_realtime_transceiver(
        &self,
        identity: &Arc<RealtimeTrackIdentity>,
    ) {
        self.session.realtime_tracks.stop_claimed(identity).await;
    }

    /// Forward the exact persistent-lane readiness read to engine callers.
    /// Logical flow readiness cannot substitute for the native channel's
    /// current ready state when completing an Open/Accept transaction.
    pub(crate) fn opaque_native_mode_ready(&self, mode: crate::realtime::OpaqueFlowMode) -> bool {
        self.session.opaque_native_mode_ready(mode)
    }

    /// Observe actual native application backlog after the caller has
    /// released the flow-set lock and reserved its retirement operation.
    pub(crate) async fn native_application_backlog_empty(&self) -> bool {
        self.session.native_application_backlog_empty().await
    }

    /// Start the single persistent-lane pump claimed by one exact opaque flow.
    /// The pump owns each dequeued unit until the native write resolves and
    /// reports completion through the flow's captured native remainder.
    pub(crate) fn spawn_opaque_outbound_pump(
        &self,
        pump: OpaqueOutboundPump,
        retired: tokio::sync::oneshot::Sender<()>,
    ) {
        let session = Arc::clone(&self.session);
        let incarnation = Arc::clone(&self.ownership.incarnation);
        let close_owner = Arc::clone(&self.close_owner);
        let task = tokio::spawn(async move {
            loop {
                match pump.next() {
                    OpaquePumpStep::Unit(unit) => {
                        if !incarnation.is_active() {
                            pump.mark_failed();
                            break;
                        }
                        if !pump
                            .native_write_finished(session.send_opaque_native(unit).await.is_ok())
                        {
                            // A failed native write is terminal for this
                            // logical queue.  Keep later sends from being
                            // accepted behind a pump that cannot drain them.
                            break;
                        }
                    }
                    OpaquePumpStep::Empty => pump.ready().await,
                    OpaquePumpStep::Closed => break,
                }
            }
            let _ = retired.send(());
        });
        close_owner.retain_transport_task(task);
    }

    /// The retirement this connector will honour for one token, for the flow
    /// that is about to be bound to it.
    ///
    /// Handed to the flow rather than kept here, because the flow is what knows
    /// when the transceiver stops being wanted — and a flow can stop being
    /// wanted without anyone calling anything, which is exactly the case this
    /// exists for. Minting it here is what keeps the engine out of the track
    /// table: it names a token and receives an owner, and never learns what
    /// stopping one involves.
    ///
    /// **Fallible, because the cleanup it promises is paid for here.** The
    /// retirement's queue slot on the process cleanup executor is acquired now,
    /// against this connector's work scope, so that the submission it will make
    /// later — from a destructor, with no caller to tell — cannot be refused for
    /// want of capacity. A connector that cannot afford to clean the flow up
    /// refuses to open it, which is the only ordering under which "every way
    /// this flow ends retires its transceiver" is a statement about resources
    /// rather than a hope.
    pub(crate) fn inbound_realtime_retirement(
        &self,
        identity: Arc<RealtimeTrackIdentity>,
    ) -> Result<RealtimeInboundRetirement> {
        let Some(work_scope) = self.session.work_resource_scope.as_ref() else {
            return Err(Error::Transport(
                "inbound realtime binding has no connector work scope to fund a retirement"
                    .to_string(),
            ));
        };
        let slot_claim = crate::runtime::attempt::cleanup_job_claim().map_err(|error| {
            Error::Transport(format!("inbound realtime retirement slot claim: {error}"))
        })?;
        let slot = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                slot_claim,
            )
            .map_err(Error::ResourceUnavailable)?;
        Ok(self.session.realtime_tracks.retirement(
            identity,
            work_scope.cleanup_submission().clone(),
            slot,
        ))
    }

    /// Create and attach the native sender for an outbound session flow.
    ///
    /// The track's MIME is the one the application registered, taken from the
    /// encoding rather than from a constant: this module has no codec table and
    /// must not acquire one.
    pub(crate) async fn open_outbound_realtime_track(
        &self,
        encoding: &RealtimeEncoding,
    ) -> Result<RealtimeOutboundTrack> {
        let _operation = self.ownership.enter_operation()?;
        self.realtime_negotiation_guard(encoding)?;
        self.session.ensure_media_negotiation_callback();
        let track = Arc::new(TrackLocalStaticSample::new(
            RTCRtpCodecCapability {
                mime_type: encoding.mime().to_string(),
                clock_rate: encoding.clock_rate(),
                channels: encoding.channels(),
                ..Default::default()
            },
            // Ids the peer never routes on. Inbound demux is by the transceiver
            // this side created, never by a name off the wire, so these exist
            // for traces and for the library's own bookkeeping.
            format!("flow-{}", encoding.mime()),
            "myownmesh".to_string(),
        ));
        let sender = self
            .session
            .pc
            .add_track(Arc::clone(&track) as Arc<dyn TrackLocal + Send + Sync>)
            .await
            .map_err(|error| Error::Transport(format!("outbound realtime add_track: {error}")))?;
        Ok(RealtimeOutboundTrack {
            track,
            sender,
            // Carried on the track rather than looked up at retirement time,
            // because the pump that ends up owning this has no worker to ask.
            pc: Arc::clone(&self.session.pc),
            incarnation: Arc::clone(&self.ownership.incarnation),
            close_owner: Arc::clone(&self.close_owner),
        })
    }

    /// Release a track the commit fence refused.
    ///
    /// Taken by value: a released track must not be attachable afterwards, and
    /// consuming it is what makes that structural rather than a rule.
    ///
    /// This exists for exactly one case — negotiation succeeded and the fence
    /// then refused, so the caller is holding a track that was never attached
    /// and therefore has no pump and no completion lease. Once
    /// `attach_outbound` accepts, the pump is the only owner and this path is
    /// unreachable for that track.
    pub(crate) async fn close_outbound_realtime_track(&self, track: RealtimeOutboundTrack) {
        track.retire().await;
    }

    /// This worker's transport-independent connector identity, while live.
    ///
    /// Forwards to the ownership that actually holds the incarnation, so there
    /// is one implementation of the identity-and-liveness pair rather than two
    /// that could drift.
    pub(crate) fn live_connector_incarnation(
        &self,
    ) -> Option<&Arc<crate::connector::ConnectorIncarnation>> {
        self.ownership.live_connector_incarnation()
    }

    /// Whether `incarnation` names this worker's exact connector identity.
    ///
    /// This is deliberately an identity-only predicate.  Retirement callers
    /// establish the lifecycle/terminal fence separately; consulting the
    /// worker's liveness here would reject the historical identity that the
    /// terminal custody path must still be able to match.
    pub(crate) fn matches_connector_identity_for_retirement(
        &self,
        incarnation: &Arc<crate::connector::ConnectorIncarnation>,
    ) -> bool {
        self.ownership.incarnation.generic().is_same(incarnation)
    }

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
            work_resource_scope,
        } = admitted;
        let attempt_retirement = attempt_liveness.subscribe_retirement();
        let session = Arc::new(session);
        let remote_candidates = Arc::new(SyncMutex::new(RemoteCandidateState::with_resources(
            work_resource_scope,
        )));
        if !close_owner.attach_remote_candidates(Arc::clone(&remote_candidates)) {
            close_owner.start();
            return Err(Error::Transport(
                "remote-candidate owner installation was refused".to_string(),
            ));
        }
        if !close_owner.attach_realtime_flows(Arc::clone(&raw.realtime_flows)) {
            close_owner.start();
            return Err(Error::Transport(
                "real-time registry owner installation was refused".to_string(),
            ));
        }
        // Cloned before `raw` moves into the receiver below.
        let realtime_flows = Arc::clone(&raw.realtime_flows);
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
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        Ok((
            Self {
                session,
                ownership,
                realtime_flows,
                remote_candidates,
                close_owner,
                resource_scope,
                #[cfg(all(test, feature = "transport-lab"))]
                withheld_binding_component: std::sync::atomic::AtomicU8::new(0),
                #[cfg(test)]
                native_candidate_apply_calls: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                #[cfg(test)]
                native_candidate_apply_gate: None,
            },
            receiver,
        ))
    }

    /// Consume an event only when it came from this still-active worker, and —
    /// for a real-time unit — only while this session still owns a binding
    /// table for it to have come from.
    ///
    /// Two questions, asked by the two owners that can actually answer them.
    /// `ownership.accepts` answers the connector one: same incarnation, still
    /// live, past the states in which nothing can be authorized. It cannot
    /// answer the second, because the session's binding table is not the
    /// connector's to know about — a connector stays `Connected` across the
    /// whole life of a peer connection, including after a promoted session's
    /// table has died with it.
    ///
    /// The second is asked here because this is the first point that holds
    /// both. A `RealtimeUnit` exists only for a flow some session opened, so
    /// once `realtime_tracks.current()` is `None` there is no live table that
    /// unit could belong to: it was minted against a table that has since been
    /// dropped, or against a session this worker no longer serves. Refusing it
    /// here means the refusal lands *before* delivery and before any
    /// consumer-side work or accounting is charged for it. The connector-side
    /// flow and output leases the unit already carries are not undone by that —
    /// they were taken when the unit was assembled and are simply released when
    /// the refused event drops, which is the same path any dropped unit takes.
    ///
    /// Deliberately not the callback-work lease: that a callback was afforded
    /// says the provider had capacity, not that the event is authorized, and
    /// reading capacity as authority is how a resource decision becomes a
    /// security one.
    pub(crate) fn accept_event(
        &self,
        event: WebRtcConnectorEvent,
    ) -> Option<AcceptedWebRtcConnectorEvent> {
        if !self.ownership.accepts(&event) {
            return None;
        }
        if matches!(&event.event, TransportEvent::RealtimeUnit(_))
            && self.session.realtime_tracks.current().is_none()
        {
            return None;
        }
        Some(event.into_accepted())
    }

    #[cfg(test)]
    pub(crate) fn stamp_event_for_test(&self, event: TransportEvent) -> WebRtcConnectorEvent {
        WebRtcConnectorEvent {
            incarnation: Arc::clone(&self.ownership.incarnation),
            event,
            _queue_observation: None,
            _callback_work: None,
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt: None,
        }
    }

    /// Apply or retain one inbound candidate under this worker's ownership.
    #[cfg(test)]
    pub(crate) async fn add_remote_candidate(
        &self,
        candidate: LocalIceCandidate,
    ) -> Result<RemoteCandidateDisposition> {
        Ok(self
            .add_remote_candidate_observed(candidate)
            .await?
            .disposition)
    }

    pub(crate) async fn add_remote_candidate_observed(
        &self,
        candidate: LocalIceCandidate,
    ) -> Result<RemoteCandidateAdmissionReport> {
        let _operation = self.ownership.enter_operation()?;
        let (pending, kind) = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport("connector worker is retired".to_string()));
            }
            let (admitted, kind) = state.admit_observed(candidate, &self.resource_scope);
            let target = state.admission_target();
            if !target.remote_description_set
                || (admitted == PendingRemoteCandidateQueuePush::Queued
                    && !target.last_candidate_matches_remote_credentials())
            {
                let disposition = match admitted {
                    PendingRemoteCandidateQueuePush::Queued => {
                        RemoteCandidateDisposition::QueuedUntilRemoteDescription
                    }
                    PendingRemoteCandidateQueuePush::Duplicate => {
                        RemoteCandidateDisposition::DuplicateIgnored
                    }
                    PendingRemoteCandidateQueuePush::InvalidBinding(error) => {
                        RemoteCandidateDisposition::InvalidBinding(error)
                    }
                    PendingRemoteCandidateQueuePush::ResourceUnavailable(error) => {
                        return Err(Error::ResourceUnavailable(error));
                    }
                    PendingRemoteCandidateQueuePush::Refused => {
                        RemoteCandidateDisposition::RefusedByOwner
                    }
                    PendingRemoteCandidateQueuePush::Retired => {
                        RemoteCandidateDisposition::AttemptRetired
                    }
                };
                return Ok(RemoteCandidateAdmissionReport { disposition, kind });
            }
            let pending = match admitted {
                PendingRemoteCandidateQueuePush::Queued => target
                    .pending
                    .pop_last_for_application(&self.resource_scope)
                    .ok_or_else(|| {
                        Error::Transport(
                            "remote-candidate admission lost its exact queued value".to_string(),
                        )
                    })?,
                PendingRemoteCandidateQueuePush::Duplicate => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::DuplicateIgnored,
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::InvalidBinding(error) => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::InvalidBinding(error),
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::ResourceUnavailable(error) => {
                    return Err(Error::ResourceUnavailable(error));
                }
                PendingRemoteCandidateQueuePush::Refused => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::RefusedByOwner,
                        kind,
                    })
                }
                PendingRemoteCandidateQueuePush::Retired => {
                    return Ok(RemoteCandidateAdmissionReport {
                        disposition: RemoteCandidateDisposition::AttemptRetired,
                        kind,
                    })
                }
            };
            (pending, kind)
        };
        self.apply_remote_candidate(pending).await?;
        Ok(RemoteCandidateAdmissionReport {
            disposition: RemoteCandidateDisposition::Applied,
            kind,
        })
    }

    /// Admit raw remote SDP before the native dependency parses or retains it.
    pub(crate) async fn apply_remote_sdp(
        &self,
        sdp_type: RTCSdpType,
        sdp: String,
    ) -> Result<RemoteDescriptionApplyReport> {
        let _operation = self.ownership.enter_operation()?;
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _work_observation = observe_inexact_item(
            &self.resource_scope,
            PreAuthResourceFamily::ConnectorSpecificWork,
            1,
            0,
        );
        let work_resources = self
            .remote_candidates
            .lock()
            .admission_target()
            .work_resources
            .clone();
        let credentials = sdp_ice_credentials_owned(&sdp, sdp.capacity(), &work_resources)?;
        let description = match sdp_type {
            RTCSdpType::Offer => RTCSessionDescription::offer(sdp),
            RTCSdpType::Answer => RTCSessionDescription::answer(sdp),
            _ => {
                return Err(Error::Transport(
                    "only offer and answer remote descriptions are supported".to_string(),
                ));
            }
        }
        .map_err(|error| Error::Transport(format!("parse remote SDP: {error}")))?;
        self.apply_remote_description_owned(description, credentials)
            .await
    }

    /// Apply remote SDP, transfer queue ownership into the async drain, and
    /// apply every retained candidate through the connector-private raw API.
    /// The caller must retain the exact connector operation permit.
    async fn apply_remote_description_owned(
        &self,
        description: RTCSessionDescription,
        credentials: RemoteIceCredentials,
    ) -> Result<RemoteDescriptionApplyReport> {
        let prepared = {
            let mut state = self.remote_candidates.lock();
            match state.prepare_remote_description(credentials) {
                Ok(prepared) => prepared,
                Err(error) => {
                    let must_retire_connector = state.has_no_viable_attempt();
                    drop(state);
                    if must_retire_connector {
                        self.close_owner.start();
                    }
                    return Err(error);
                }
            }
        };
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&self.remote_candidates),
            Arc::clone(&self.close_owner),
            Arc::clone(&prepared.attempt),
        );
        if let Some(resources) = prepared.credentials.resource_owner() {
            // The native dependency may retain a parsed description even when
            // its future is cancelled or returns an error. Transfer the exact
            // residual owner to the connector close owner before entering the
            // native operation.
            self.close_owner
                .retain_remote_description_resources(resources);
        }
        if let Some(retiring) = prepared.retiring.as_ref() {
            retiring.wait_for_operations().await;
        }
        let _attempt_operation = match prepared.attempt.try_enter() {
            Some(operation) => operation,
            None => {
                if prepared.provisional {
                    self.close_owner.start();
                }
                return Err(Error::Transport(
                    "remote-candidate attempt is retired".to_string(),
                ));
            }
        };
        let native_result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.set_remote_description(description),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during SDP apply".to_string()))?;
        native_result?;
        prepared.credentials.finish_native_commit()?;
        let pending = {
            let mut state = self.remote_candidates.lock();
            if !self.ownership.incarnation.is_active() {
                return Err(Error::Transport(
                    "connector worker retired during SDP apply".to_string(),
                ));
            }
            match state.commit_remote_description(&prepared) {
                Ok(pending) => pending,
                Err(error) => {
                    drop(state);
                    self.close_owner.start();
                    return Err(error);
                }
            }
        };
        transaction.disarm();
        let queued_candidate_count = pending.len();
        let mut candidate_failure_count = 0_usize;
        if queued_candidate_count == 0 {
            return Ok(RemoteDescriptionApplyReport {
                queued_candidate_count,
                candidate_failure_count,
            });
        }

        // The queue is already the exact owner-funded admission boundary. Use
        // its finite size as the parallelism bound instead of adding a hidden
        // scheduler constant. IDs are local opaque ordinals, so ranking cannot
        // expose candidate contents or manufacture application capability.
        let work_resources = self.remote_candidates.lock().current.work_resources.clone();
        let planner_claim = match remote_candidate_drain_plan_claim(queued_candidate_count) {
            Ok(claim) => claim,
            Err(error) => {
                self.close_owner.start();
                return Err(error);
            }
        };
        let planner_lease = match work_resources.acquire(
            crate::resource::ResourceAuthorityClass::Speculative,
            planner_claim,
        ) {
            Ok(lease) => lease,
            Err(error) => {
                self.close_owner.start();
                return Err(Error::from(error));
            }
        };
        let mut paths = Vec::with_capacity(queued_candidate_count);
        let mut pending_by_id = Vec::with_capacity(queued_candidate_count);
        for (index, candidate) in pending.enumerate() {
            let path_id = match u64::try_from(index) {
                Ok(path_id) => path_id,
                Err(_) => {
                    self.close_owner.start();
                    return Err(Error::Transport(
                        "remote-candidate path ID is not representable".to_string(),
                    ));
                }
            };
            paths.push(IceCandidatePath::new(
                path_id,
                super::diag::IceCandidateKind::Unknown,
                super::ice::classify_candidate_sdp(&candidate.candidate.candidate),
                0,
            ));
            pending_by_id.push(Some(candidate));
        }
        let parallelism = match std::num::NonZeroUsize::new(queued_candidate_count) {
            Some(parallelism) => parallelism,
            None => {
                self.close_owner.start();
                return Err(Error::Transport(
                    "non-empty remote-candidate queue lost its size".to_string(),
                ));
            }
        };
        let mut planner = match WebRtcCandidatePathPlanner::new(paths, parallelism, parallelism) {
            Ok(planner) => planner,
            Err(error) => {
                self.close_owner.start();
                return Err(Error::Transport(format!(
                    "remote-candidate path planning refused: {error}"
                )));
            }
        };
        let mut applications = FuturesUnordered::new();
        let mut planner_terminal = false;
        loop {
            for path_id in planner.start_parallel_paths() {
                let pending_index = match usize::try_from(path_id) {
                    Ok(pending_index) => pending_index,
                    Err(_) => {
                        self.close_owner.start();
                        return Err(Error::Transport(
                            "remote-candidate path ID is not representable".to_string(),
                        ));
                    }
                };
                let pending = match pending_by_id.get_mut(pending_index).and_then(Option::take) {
                    Some(pending) => pending,
                    None => {
                        self.close_owner.start();
                        return Err(Error::Transport(
                            "remote-candidate planner lost its exact admitted candidate"
                                .to_string(),
                        ));
                    }
                };
                applications
                    .push(async move { (path_id, self.apply_remote_candidate(pending).await) });
            }

            let Some((path_id, result)) = applications.next().await else {
                break;
            };
            if let Err(error) = result {
                candidate_failure_count =
                    candidate_failure_count
                        .checked_add(1)
                        .ok_or(Error::ResourceUnavailable(
                            ResourceUnavailable::ProviderInvariant {
                                dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                            },
                        ))?;
                warn!(
                    ?error,
                    path_id, "queued remote-candidate application failed"
                );
                if !planner_terminal {
                    let decision = match planner.observe(path_id, false) {
                        Ok(decision) => decision,
                        Err(error) => {
                            self.close_owner.start();
                            return Err(Error::Transport(format!(
                                "remote-candidate path observation refused: {error}"
                            )));
                        }
                    };
                    planner_terminal = matches!(decision, WebRtcCandidatePathDecision::Exhausted);
                }
            } else if !planner_terminal {
                let decision = match planner.observe(path_id, true) {
                    Ok(decision) => decision,
                    Err(error) => {
                        self.close_owner.start();
                        return Err(Error::Transport(format!(
                            "remote-candidate path observation refused: {error}"
                        )));
                    }
                };
                planner_terminal = matches!(decision, WebRtcCandidatePathDecision::Selected(_));
            }
        }
        drop(planner_lease);
        Ok(RemoteDescriptionApplyReport {
            queued_candidate_count,
            candidate_failure_count,
        })
    }

    async fn apply_remote_candidate(&self, pending: PendingRemoteCandidate) -> Result<()> {
        // Both callers already hold the exact connector operation lease. This
        // helper remains private so one native candidate application cannot
        // manufacture a nested claim or bypass the outer close fence.
        if !self.ownership.incarnation.is_active() {
            return Err(Error::Transport("connector worker is retired".to_string()));
        }
        let _attempt_operation = pending.attempt.try_enter().ok_or_else(|| {
            Error::Transport("remote candidate belongs to a retired ICE attempt".to_string())
        })?;
        let candidate_matches_attempt = {
            let state = self.remote_candidates.lock();
            state.owns_attempt(&pending.attempt)
                && state.candidate_matches_attempt(&pending.attempt, &pending.candidate)
        };
        if !candidate_matches_attempt {
            self.remote_candidates
                .lock()
                .retire_attempt(&pending.attempt);
            return Err(Error::Transport(
                "remote candidate does not match the exact current ICE attempt".to_string(),
            ));
        }
        if pending._queue_reservation.is_none() {
            self.remote_candidates
                .lock()
                .retire_attempt(&pending.attempt);
            return Err(Error::Transport(
                "remote candidate reached production application without queue ownership"
                    .to_string(),
            ));
        }
        // The elastic attempt first admits its own candidate claim, then the
        // exact retained post-native claim is atomically charged before the
        // irreversible native mutation. A refusal therefore cannot strand
        // native ICE state without its retained ownership.
        let _ice_observation =
            observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::IceWork, 1, 0);
        let PendingRemoteCandidate {
            candidate,
            attempt,
            observation,
            _queue_reservation,
            _elastic_lease,
            _production_queue_lease,
        } = pending;
        let retained_claim = match applied_remote_candidate_retained_claim() {
            Ok(claim) => claim,
            Err(error) => {
                self.remote_candidates.lock().retire_attempt(&attempt);
                return Err(error);
            }
        };
        let mut elastic_application = match _elastic_lease {
            Some(lease) => lease.begin_apply().map_err(|error| {
                self.remote_candidates.lock().retire_attempt(&attempt);
                match error {
                    ElasticRemoteCandidateApplyError::Provider(unavailable) => {
                        Error::ResourceUnavailable(unavailable)
                    }
                    other => Error::Transport(format!(
                        "remote-candidate application ownership transition failed: {other}"
                    )),
                }
            })?,
            None => {
                self.remote_candidates.lock().retire_attempt(&attempt);
                return Err(Error::Transport(
                    "remote candidate reached production application without elastic ownership"
                        .to_string(),
                ));
            }
        };
        if let Err(error) = elastic_application.transition_after_application(retained_claim) {
            self.remote_candidates.lock().retire_attempt(&attempt);
            return Err(Error::ResourceUnavailable(error));
        }
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&self.remote_candidates),
            Arc::clone(&self.close_owner),
            Arc::clone(&attempt),
        );
        #[cfg(test)]
        self.native_candidate_apply_calls
            .fetch_add(1, Ordering::AcqRel);
        #[cfg(test)]
        let native_operation = {
            let native_operation = self.session.add_ice_candidate(candidate);
            let native_apply_gate = self.native_candidate_apply_gate.clone();
            async move {
                if let Some(gate) = native_apply_gate {
                    gate.entered.add_permits(1);
                    gate.resume
                        .acquire()
                        .await
                        .expect("native candidate apply gate remains open")
                        .forget();
                }
                native_operation.await
            }
        };
        #[cfg(not(test))]
        let native_operation = self.session.add_ice_candidate(candidate);
        let result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            native_operation,
        )
        .await;
        let result = match result {
            Some(Ok(())) => Ok(()),
            Some(Err(error)) => Err(error),
            None => Err(Error::Transport(
                "connector worker retired during ICE apply".to_string(),
            )),
        };
        if let Err(error) = result {
            self.remote_candidates.lock().retire_attempt(&attempt);
            return Err(error);
        }
        if !attempt.is_active() || !self.remote_candidates.lock().owns_attempt(&attempt) {
            return Err(Error::Transport(
                "remote candidate completed after its ICE attempt retired".to_string(),
            ));
        }
        drop(observation);
        let Some(mut reservation) = _queue_reservation else {
            return Err(Error::Transport(
                "remote candidate completed without its custody reservation".to_string(),
            ));
        };
        let mut state = self.remote_candidates.lock();
        if !state.current.owns_attempt(&attempt) {
            return Err(Error::Transport(
                "remote candidate completed after its ICE attempt drifted".to_string(),
            ));
        }
        reservation.application = Some(elastic_application);
        state.current.retained_reservations.push_back(reservation);
        drop(state);
        transaction.disarm();
        Ok(())
    }

    pub(crate) fn observe_owned_task(&self) -> ObservationLease {
        observe_inexact_item(&self.resource_scope, PreAuthResourceFamily::Task, 1, 1)
    }

    /// Take send authority now for a send awaited later.
    ///
    /// Synchronous on purpose: the caller is under a lock, or about to take
    /// one, and needs the connector's answer before it decides. Acquiring here
    /// rather than at await time is the whole point — see `StartedConnectorSend`.
    pub(crate) fn begin_send(&self) -> Result<StartedConnectorSend> {
        Ok(StartedConnectorSend {
            session: Arc::clone(&self.session),
            permit: self.ownership.enter_operation()?,
        })
    }

    pub(crate) async fn send_owned(&self, data: Bytes) -> Result<usize> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.send(data),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during send".to_string()))?
    }

    pub(crate) async fn create_offer(&self) -> Result<RTCSessionDescription> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_offer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during offer".to_string()))?
    }

    pub(crate) async fn create_answer(&self) -> Result<RTCSessionDescription> {
        let _operation = self.ownership.enter_operation()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.create_answer(),
        )
        .await
        .ok_or_else(|| Error::Transport("connector worker retired during answer".to_string()))?
    }

    pub(crate) async fn remote_fingerprint(&self) -> Option<String> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.remote_fingerprint(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn local_fingerprint(&self) -> Option<String> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.local_fingerprint(),
        )
        .await
        .flatten()
    }

    /// Supply the accepted channel binding for this exact live connector.
    ///
    /// This is the WebRTC adapter's whole contribution to endpoint
    /// authentication: it reads its own two native fingerprints and hands them
    /// over as endpoint-relative components. It selects no role, applies no
    /// canonical ordering, and states nothing about what the pair proves —
    /// those belong to the endpoint authentication owner.
    ///
    /// Fail-closed: a missing local or missing remote fingerprint yields no
    /// binding, so a caller cannot proceed with half a pair.
    pub(crate) async fn endpoint_auth_binding(
        &self,
    ) -> Option<crate::connector::EndpointAuthBinding> {
        let local = self.local_fingerprint().await?;
        let remote = self.remote_fingerprint().await?;
        // Controls only, compiled out of production. Both genuine components
        // have been read by this point and are discarded unread when one is
        // withheld — the refusal is the absence of a component, never a blank
        // or defaulted one, so the constructor below is never reached with an
        // empty string and no fallback value exists anywhere on this path.
        //
        // The gate is exactly the one on the field and the helper below. It has
        // to be: a build where those are absent and this line is present would
        // not compile at all.
        #[cfg(all(test, feature = "transport-lab"))]
        self.refuse_withheld_binding_component_for_test()?;
        crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(&local, &remote)
    }

    /// Arm this connector to withhold one binding component. **Controls only.**
    ///
    /// Set-only and monotonic: there is no clearing operation, so an armed
    /// connector stays armed for its whole life and the positive twin has to be
    /// a fixture that was never armed rather than the same one disarmed. That
    /// keeps the twins genuinely independent — a control cannot arrange the
    /// failure, observe it, and then arrange the success on the same connector.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn withhold_binding_component_for_test(&self, component: WithheldBindingComponent) {
        self.withheld_binding_component
            .store(component.marker(), Ordering::Release);
    }

    /// `None` when a component is withheld, so the caller's `?` refuses.
    ///
    /// Returns `Some(())` and nothing else: this cannot hand back material, only
    /// stop material that was genuinely read from being assembled into a pair.
    #[cfg(all(test, feature = "transport-lab"))]
    fn refuse_withheld_binding_component_for_test(&self) -> Option<()> {
        (self.withheld_binding_component.load(Ordering::Acquire) == 0).then_some(())
    }

    pub(crate) fn awaiting_answer(&self) -> bool {
        self.ownership.incarnation.is_active() && self.session.awaiting_answer()
    }

    /// The role this connector's peer connection was opened for.
    ///
    /// Fixed when the session is constructed and never recomputed. A caller
    /// deciding whether it may offer on an existing connection has to ask the
    /// connection, not re-derive a role from identifiers: identifier ordering
    /// describes which side would *open* a connection that does not exist yet,
    /// and is not a fact about one that does.
    pub(crate) fn role(&self) -> Role {
        self.session.role()
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
        let _operation = self.ownership.enter_operation()?;
        let (retiring_attempt, replacement_attempt) =
            self.remote_candidates.lock().begin_local_ice_restart()?;
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&self.remote_candidates),
            Arc::clone(&self.close_owner),
            Arc::clone(&replacement_attempt),
        );
        retiring_attempt.wait_for_operations().await;
        let native_result = await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.restart_ice(),
        )
        .await
        .ok_or_else(|| {
            Error::Transport("connector worker retired during ICE restart".to_string())
        })?;
        native_result?;
        let commit_result = {
            self.remote_candidates
                .lock()
                .commit_local_ice_restart(&replacement_attempt)
        };
        if let Err(error) = commit_result {
            self.close_owner.start();
            return Err(error);
        }
        transaction.disarm();
        Ok(())
    }

    pub(crate) async fn selected_candidate_pair(
        &self,
    ) -> Option<super::diag::SelectedCandidatePair> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.selected_candidate_pair(),
        )
        .await
        .flatten()
    }

    #[cfg(feature = "transport-lab")]
    pub(crate) async fn transport_lab_channel_snapshot(
        &self,
    ) -> Option<TransportLabChannelSnapshot> {
        let _operation = self.ownership.enter_operation().ok()?;
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.transport_lab_channel_snapshot(),
        )
        .await
        .flatten()
    }

    pub(crate) async fn ice_check_snapshot(&self) -> super::diag::IceCheckSnapshot {
        let Ok(_operation) = self.ownership.enter_operation() else {
            return super::diag::IceCheckSnapshot::default();
        };
        await_until_connector_retirement(
            self.ownership.incarnation.subscribe_retirement(),
            self.session.ice_check_snapshot(),
        )
        .await
        .unwrap_or_default()
    }

    pub(crate) fn confirm_data_channel_open(&self) -> DataChannelOpenOwnership {
        let Some(_operation) = self.ownership.operation_fence.try_enter() else {
            return DataChannelOpenOwnership::Rejected;
        };
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

    /// Fence this connector for an open that must never be authenticated over.
    ///
    /// The caller has already decided that nothing can be proved about this
    /// channel — the connector could not state its endpoint-auth binding — so
    /// the channel must not merely go unpromoted, it must be closed, and the
    /// connector's finite claim must be held until that close is observed to
    /// have succeeded.
    ///
    /// The order is load-bearing and is the whole reason this is a method
    /// rather than two calls at the call site:
    ///
    /// 1. `confirm_data_channel_open()` first. On a live connector this takes
    ///    the connected claim and hands back a handoff; dropping that handoff
    ///    immediately is the *normal* Connected path's `Drop`, which returns the
    ///    claim to the close owner's conservative retention and starts the
    ///    close. The brief promotion exists for exactly that reason — to return
    ///    the claim to connected retention rather than to use the channel. No
    ///    task is built, no capability escapes, and nothing is ever sent: the
    ///    handoff is dropped in the same expression that produced it.
    /// 2. `close_owner.start()` second, unconditionally. `retain_connected_claim`
    ///    already started the close on the path above, so this is an idempotent
    ///    second call there. It is not redundant: when `confirm` answers
    ///    `Rejected` — a connector already stale or retired, so there is no
    ///    handoff to drop — this is the only thing that starts a close owner, and
    ///    the refusal must still start exactly one.
    ///
    /// Never retire before confirming. `retire()` would fence the operation
    /// before `confirm` could take the claim, so the claim would sit outside
    /// the close owner's retention and the connector would be torn down with a
    /// claim nobody was holding conservatively.
    ///
    /// This makes no statement about certificates, exporters, or any keying
    /// material: it is ownership and cleanup only.
    pub(crate) fn refuse_data_channel_open(&self) {
        drop(self.confirm_data_channel_open());
        self.close_owner.start();
    }

    /// Revoke callback acceptance and release every connector-owned candidate.
    pub(crate) fn retire(&self) {
        self.close_owner.retire_local();
    }

    /// Start the funded native close owner without requiring an async caller.
    /// The owner remains independently awaitable through `retire_and_close`.
    pub(crate) fn start_close(&self) {
        self.close_owner.start();
    }

    /// Install this connector's native-close hold point. **Controls only.**
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn install_native_close_gate_for_test(&self) -> NativeCloseGateHandle {
        self.close_owner.install_native_close_gate_for_test()
    }

    /// Commit this connector's operation close fence, and nothing else.
    /// **Controls only.**
    ///
    /// Deliberately narrower than every production path that closes a fence:
    /// it does not retire the incarnation, does not start the close owner, and
    /// touches no session, promotion, or governance state. That is the whole
    /// point — it isolates "this connector will accept no further operations"
    /// from "this peer lost its authority", which production always causes
    /// together and which a caller must never confuse.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn begin_close_for_test(&self) {
        self.ownership.begin_close();
    }

    /// How many connected claims this connector's close owner is holding in
    /// conservative retention right now. **Controls only.**
    ///
    /// Non-zero means the claim has been taken but not released: the close has
    /// not yet reported success, or reported failure and is retaining it. Zero
    /// after a successful close is the release; zero before any promotion is
    /// simply that no claim has moved into retention yet.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn retained_connected_claims_for_test(&self) -> usize {
        self.close_owner.retained_connected_claims_for_test()
    }

    pub(crate) fn owns_endpoint_auth(&self, task: &crate::endpoint_auth::EndpointAuthTask) -> bool {
        self.ownership.owns_endpoint_auth(task)
    }

    /// Retire local ownership first, then close the native peer connection.
    /// This is the only operation intentionally allowed to continue after
    /// retirement. The local proof is limited to requesting and awaiting the
    /// dependency's idempotent peer-connection close operation.
    pub(crate) async fn retire_and_close(&self) -> Result<()> {
        self.close_owner.start();
        self.ownership.operation_fence.wait_for_operations().await;
        self.session.realtime_tracks.prepare_for_close();
        self.session.realtime_tracks.seal_for_close();
        let result = self.close_owner.wait().await;
        self.session.realtime_tracks.wait_for_tasks().await;
        result
    }

    /// Return an owned waiter for the connector's existing close owner.
    ///
    /// The future retains only the funded close-owner state, not this worker's
    /// Arc. Engine callback supervisors use it after dropping their strong
    /// worker identity so a concurrent direct close join can release the
    /// worker-owned resource observations immediately on completion.
    pub(crate) fn close_waiter(&self) -> impl Future<Output = Result<()>> + Send + 'static {
        let close_owner = Arc::clone(&self.close_owner);
        let operation_fence = Arc::clone(&self.ownership.operation_fence);
        let realtime_tracks = Arc::clone(&self.session.realtime_tracks);
        async move {
            close_owner.start();
            operation_fence.wait_for_operations().await;
            realtime_tracks.prepare_for_close();
            realtime_tracks.seal_for_close();
            close_owner.wait().await
        }
    }
}

impl Drop for WebRtcConnectorWorker {
    fn drop(&mut self) {
        // Drop is synchronous, so commit the operation fence and task seal
        // before starting the asynchronous owner. The native peer keeps the
        // callback closures alive until its close completes; waiting for the
        // tracks' Drop to publish this seal would therefore deadlock the
        // owner before it could reach native close.
        self.close_owner.retire_local();
        self.session.realtime_tracks.prepare_for_close();
        self.session.realtime_tracks.seal_for_close();
        self.close_owner.start();
    }
}

/// One locally-gathered ICE candidate, in the form the signaling
/// layer needs (matches the webrtc-rs `RTCIceCandidateInit` shape).
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
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
    connector_resource_scope: Option<MeshConnectorResourceScope>,
    webrtc_profile: Option<WebRtcConnectorProfile>,
    #[cfg(test)]
    construction_hook: Option<Arc<ConstructionTestHook>>,
}

struct PeerOpenOwnership {
    resource_scope: Option<PeerConnectionResourceScope>,
    work_resource_scope: Option<ConnectorWorkResourceScope>,
    attempt_liveness: Option<AttemptLiveness>,
    candidate_promoted: Arc<AtomicBool>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    callback_policy: ConnectorCallbackPolicy,
    /// The explicit callback grant a scope-less lab connector mints its own
    /// provider from.
    ///
    /// Present only on the lab entry points, and only because they are the one
    /// way to build a connector with no connector work scope at all. A
    /// production connector always carries a scope and acquires against it, so
    /// there is nothing here for a deployment to state — and nothing core
    /// could invent on its behalf: the fixture names its own numbers.
    #[cfg(any(test, feature = "transport-lab"))]
    local_lab_callback_grant: Option<callback::TransportLabCallbackGrant>,
    /// Raw lab construction has no connector owner, so it must create its
    /// close custodian before entering the native constructor.
    #[cfg(any(test, feature = "transport-lab"))]
    construction_custodian: Option<Arc<PeerConstructionCloseCustodian>>,
    operation_fence: Arc<ConnectorOperationFence>,
    /// The application's registered codecs, carried through to the session so
    /// a flow set can resolve framing without re-reading the connector profile.
    ///
    /// Unlike its two neighbours this is not `Copy`, so it is cloned once here
    /// rather than being read out of the profile at each use.
    realtime_profile: Option<RealtimeProfile>,
    close_owner: Option<Arc<ConnectorCloseOwner>>,
}

#[cfg(test)]
#[derive(Clone, Copy, PartialEq, Eq)]
enum ConstructionPause {
    BeforeNativeConstructor,
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
struct NativeCandidateApplyGate {
    entered: Semaphore,
    resume: Semaphore,
}

#[cfg(test)]
impl NativeCandidateApplyGate {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            entered: Semaphore::new(0),
            resume: Semaphore::new(0),
        })
    }
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

    async fn pause_before_native_constructor(&self) {
        if self.pause != ConstructionPause::BeforeNativeConstructor {
            return;
        }
        self.created.add_permits(1);
        let permit = self
            .resume
            .acquire()
            .await
            .expect("construction test hook remains open");
        permit.forget();
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

#[cfg(test)]
fn arc03_construction_stage(stage: &'static str) {
    if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
        eprintln!("arc03_construction_stage:{stage}");
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
struct AbortConstructionOnDrop {
    task: Option<tokio::task::JoinHandle<()>>,
    close_owner: Arc<ConnectorCloseOwner>,
}

impl AbortConstructionOnDrop {
    fn new(task: tokio::task::JoinHandle<()>, close_owner: Arc<ConnectorCloseOwner>) -> Self {
        Self {
            task: Some(task),
            close_owner,
        }
    }
}

impl Drop for AbortConstructionOnDrop {
    fn drop(&mut self) {
        let Some(task) = self.task.take() else {
            return;
        };
        task.abort();
        self.close_owner.retain_transport_task(task);
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

/// Retains an exact failed connector claim if dependency construction is
/// cancelled or panics after native allocation may have begun but before a
/// close port is returned. Successful return disarms the guard before the
/// native object is handed to its ordinary construction owner.
struct PendingNativeConstructorGuard(Option<Arc<ConnectorCloseOwner>>);

impl PendingNativeConstructorGuard {
    fn new(owner: Option<Arc<ConnectorCloseOwner>>) -> Self {
        Self(owner)
    }

    fn disarm(&mut self) {
        self.0 = None;
    }

    fn fail(mut self, reason: String) {
        if let Some(owner) = self.0.take() {
            owner.finish_native_allocation_without_close_port(reason);
        }
    }
}

impl Drop for PendingNativeConstructorGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.0.take() {
            owner.finish_native_allocation_without_close_port(
                "native construction was cancelled before returning a close port".to_string(),
            );
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

/// The application's registered codecs, translated into what the transport
/// library wants.
///
/// A total translation, not a selection: every registration is passed
/// through, in the order supplied. Deployed H.264 is five entries agreeing on
/// MIME, clock rate and channels and differing only in payload type and
/// fmtp — all five must reach the media engine, because the offer advertises
/// all five and the answerer picks one. Registering fewer would silently
/// narrow what a peer can choose.
///
/// Nothing here reads a MIME name. This is the whole of core's knowledge of
/// the application's codecs: copy the fields across and register them.
fn realtime_media_codecs(
    profile: &RealtimeProfile,
) -> Vec<(
    webrtc::rtp_transceiver::rtp_codec::RTCRtpCodecParameters,
    RTPCodecType,
)> {
    use webrtc::rtp_transceiver::rtp_codec::{RTCRtpCodecCapability, RTCRtpCodecParameters};
    use webrtc::rtp_transceiver::RTCPFeedback;

    profile
        .codecs()
        .iter()
        .map(|codec| {
            (
                RTCRtpCodecParameters {
                    capability: RTCRtpCodecCapability {
                        mime_type: codec.mime.clone(),
                        clock_rate: codec.clock_rate,
                        channels: codec.channels,
                        sdp_fmtp_line: codec.fmtp.clone(),
                        rtcp_feedback: codec
                            .rtcp_feedback
                            .iter()
                            .map(|feedback| RTCPFeedback {
                                typ: feedback.mechanism.clone(),
                                parameter: feedback.parameter.clone(),
                            })
                            .collect(),
                    },
                    payload_type: codec.payload_type,
                    ..Default::default()
                },
                // `codec.kind` is already a `WebRtcRtpKind`, so a `from` around
                // it would be an identity conversion. Matching the value
                // directly keeps the total map — every variant names its
                // `RTPCodecType`, so adding one is a compile error here —
                // without the round trip.
                match codec.kind {
                    WebRtcRtpKind::Audio => RTPCodecType::Audio,
                    WebRtcRtpKind::Video => RTPCodecType::Video,
                },
            )
        })
        .collect()
}

fn build_realtime_media_api(profile: &RealtimeProfile) -> Result<webrtc::api::API> {
    let mut media_engine = MediaEngine::default();
    for (codec, kind) in realtime_media_codecs(profile) {
        media_engine.register_codec(codec, kind).map_err(|error| {
            Error::Transport(format!("register application real-time codec: {error}"))
        })?;
    }
    let mut registry = Registry::new();
    registry = register_default_interceptors(registry, &mut media_engine)
        .map_err(|error| Error::Transport(format!("register real-time interceptors: {error}")))?;
    let mut setting_engine = SettingEngine::default();
    setting_engine.set_interface_filter(Box::new(|name: &str| !is_virtual_interface(name)));
    setting_engine.set_ip_filter(Box::new(|ip: std::net::IpAddr| !is_link_local_ip(&ip)));
    Ok(APIBuilder::new()
        .with_media_engine(media_engine)
        .with_interceptor_registry(registry)
        .with_setting_engine(setting_engine)
        .build())
}

impl Transport {
    /// Build a fresh transport with the default media engine and
    /// interceptors. The webrtc-rs defaults cover everything we
    /// need for data-channel-only operation.
    pub fn new() -> Result<Self> {
        let mut media_engine = MediaEngine::default();
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
        Ok(Self {
            api: Arc::new(api),
            runtime: crate::runtime::RuntimeIncarnation::new(),
            ice_transport_policy: RTCIceTransportPolicy::All,
            connector_resource_scope: None,
            webrtc_profile: None,
            #[cfg(test)]
            construction_hook: None,
        })
    }

    /// Bind this transport to an explicitly configured process resource owner.
    /// Connector construction is refused until this port is present.
    pub(crate) fn with_connector_resource_scope(
        mut self,
        scope: MeshConnectorResourceScope,
        profile: WebRtcConnectorProfile,
    ) -> Self {
        self.connector_resource_scope = Some(scope);
        self.webrtc_profile = Some(profile);
        self
    }

    /// Test-only counterpart that installs the profile's codecs into the
    /// media engine before binding the connector scope. The ordinary policy
    /// constructor performs this step; explicit test scopes must do the same
    /// or a negotiated outbound track reaches SDP with an empty media-engine
    /// codec set and is refused as an RTPSender with no codecs.
    #[cfg(test)]
    pub(crate) fn with_connector_resource_scope_for_test(
        self,
        scope: MeshConnectorResourceScope,
        profile: WebRtcConnectorProfile,
    ) -> Result<Self> {
        let installed = match profile.realtime() {
            Some(realtime) => self.with_realtime_media_api(realtime)?,
            None => self,
        };
        Ok(installed.with_connector_resource_scope(scope, profile))
    }

    /// Bind this transport to the one resource provider held by the process
    /// root. A second Mesh runtime shares the same provider grant and scope
    /// creation cannot multiply capacity.
    pub fn with_connector_resource_policy(
        self,
        policy: WebRtcConnectorCapablePolicy,
    ) -> Result<Self> {
        let root = ProcessResourceRoot::global();
        root.install_resource_provider(policy.resources())?;
        let scope = root.issue_mesh_connector_scope()?;
        let profile = policy.webrtc().clone();
        // Codec registration is a property of the media engine a peer
        // connection is built from, so the application's profile has to be
        // installed here, before any connection exists. There is no later
        // point at which a codec can be added, and therefore no point at
        // which core could fall back to a list of its own.
        let installed = match profile.realtime() {
            Some(realtime) => self.with_realtime_media_api(realtime)?,
            None => self,
        };
        Ok(installed.with_connector_resource_scope(scope, profile))
    }

    /// Replace the data-only media engine with one carrying exactly the
    /// codecs the application registered.
    ///
    /// Exactly those and no others: `MediaEngine::default()` starts empty, so
    /// what the profile lists is the complete negotiable set. A codec core
    /// was never told about cannot be offered, which is what makes inbound
    /// admission answerable by "did the application register this family"
    /// rather than by recognising a name.
    fn with_realtime_media_api(mut self, profile: &RealtimeProfile) -> Result<Self> {
        self.api = Arc::new(build_realtime_media_api(profile)?);
        Ok(self)
    }

    /// Install the Session Broker for this transport's runtime, if the process
    /// owner selected a resource provider.
    ///
    /// `None` when no provider is installed, and that is fail-closed by
    /// construction: without a provider there is no post-authentication capacity
    /// to reserve, so no session can be promoted and no application operation
    /// can run. A connector-capable policy is what installs one.
    ///
    /// The runtime is taken from this transport rather than minted fresh: it
    /// must be the same incarnation the connector's channel capabilities are
    /// bound to, or every promotion would refuse on runtime mismatch.
    pub(crate) fn session_broker(&self) -> Option<crate::runtime::session_broker::SessionBroker> {
        self.connector_resource_scope.as_ref().map(|scope| {
            crate::runtime::session_broker::SessionBroker::new(self.runtime.clone(), scope.clone())
        })
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
    pub(crate) async fn open_peer(
        &self,
        role: Role,
        stun: &[crate::config::StunServer],
        turn: &[crate::config::TurnServer],
        callback_policy: ConnectorCallbackPolicy,
        callback_grant: callback::TransportLabCallbackGrant,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let mut config = build_rtc_configuration(stun, turn);
        config.ice_transport_policy = self.ice_transport_policy;
        self.open_peer_with_config(role, config, callback_policy, callback_grant)
            .await
    }

    /// Open the engine-owned connector wrapper around the WebRTC machinery.
    /// Transport behaviour lives inside this owner.
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
        // Borrowed, not moved: the profile stopped being `Copy` when it took
        // on the application's codec registrations, and it is read again after
        // the construction task is spawned.
        let webrtc_profile = self
            .webrtc_profile
            .as_ref()
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
        let mut candidate = permit
            .reserve_connector_candidate_checked(claim)
            .map_err(Error::from)?
            .ok_or_else(|| {
                Error::Transport("connector attempt retired before admission".to_string())
            })?;
        candidate = candidate
            .prepare_late_transport_custodian()
            .map_err(Error::from)?;
        let cleanup_capability = candidate
            .issue_cleanup_capability()
            .map_err(|error| Error::Transport(error.to_string()))?;
        let late_transport_lease = candidate.take_late_transport_lease();
        let late_transport_custodian =
            LateTransportCustodian::new(late_transport_lease).map_err(|error| {
                Error::Transport(format!(
                    "late transport terminal custodian could not start: {error}"
                ))
            })?;
        let liveness = candidate.liveness();
        let work_resource_scope = candidate.work_resource_scope();
        let construction_work_resource_scope = work_resource_scope.clone();
        let transport = self.clone();
        let construction_scope = resource_scope.clone();
        let candidate_promoted = Arc::new(AtomicBool::new(false));
        let construction_candidate_promoted = Arc::clone(&candidate_promoted);
        let construction_liveness = liveness.clone();
        let result_liveness = liveness.clone();
        let incarnation = Arc::new(WebRtcConnectorIncarnation::new());
        let construction_incarnation = Arc::clone(&incarnation);
        let operation_fence = Arc::new(ConnectorOperationFence::default());
        let ownership = ConnectorOwnership::admitted(
            candidate,
            Arc::clone(&operation_fence),
            work_resource_scope.clone(),
            Arc::clone(&candidate_promoted),
            Arc::clone(&incarnation),
        );
        let close_owner = ConnectorCloseOwner::new(
            ownership.clone(),
            resource_owner.clone(),
            cleanup_capability,
            Some(transport_observation),
            late_transport_custodian,
        );
        let mut outer_cleanup = StartConnectorCleanupOnDrop::new(Arc::clone(&close_owner));
        let construction_close_owner = Arc::clone(&close_owner);
        let (construction_tx, construction_rx) = oneshot::channel();
        // The profile answer the construction task needs, taken before it is
        // spawned. It is `Copy`, so the task owns it and the profile itself
        // never crosses into the task.
        let construction_callback_policy = webrtc_profile.callbacks();
        // Cloned rather than taken by reference: the profile itself still never
        // crosses into the task, and the codec list is registration data the
        // session keeps for the lifetime of the connection anyway.
        let construction_realtime_profile = webrtc_profile.realtime().cloned();
        let construction_task = AbortConstructionOnDrop::new(
            tokio::spawn(async move {
                let construction = transport.open_peer_with_config_observed(
                    role,
                    config,
                    PeerOpenOwnership {
                        resource_scope: Some(construction_scope),
                        work_resource_scope: Some(construction_work_resource_scope),
                        attempt_liveness: Some(construction_liveness),
                        candidate_promoted: construction_candidate_promoted,
                        callback_gate: construction_incarnation,
                        callback_policy: construction_callback_policy,
                        #[cfg(any(test, feature = "transport-lab"))]
                        local_lab_callback_grant: None,
                        #[cfg(any(test, feature = "transport-lab"))]
                        construction_custodian: None,
                        operation_fence,
                        realtime_profile: construction_realtime_profile,
                        close_owner: Some(Arc::clone(&construction_close_owner)),
                    },
                );
                let result = construction.await;
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
            }),
            Arc::clone(&close_owner),
        );
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
                work_resource_scope,
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
    pub(crate) async fn open_peer_with_config(
        &self,
        role: Role,
        config: RTCConfiguration,
        callback_policy: ConnectorCallbackPolicy,
        callback_grant: callback::TransportLabCallbackGrant,
    ) -> Result<(PeerSession, TransportEventReceiver)> {
        let construction_custodian = PeerConstructionCloseCustodian::new().map_err(|error| {
            Error::Transport(format!(
                "lab native close custodian could not start: {error}"
            ))
        })?;
        self.open_peer_with_config_observed(
            role,
            config,
            PeerOpenOwnership {
                resource_scope: None,
                work_resource_scope: None,
                attempt_liveness: None,
                candidate_promoted: Arc::new(AtomicBool::new(true)),
                callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
                callback_policy,
                local_lab_callback_grant: Some(callback_grant),
                construction_custodian: Some(construction_custodian),
                operation_fence: Arc::new(ConnectorOperationFence::default()),
                realtime_profile: None,
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
            work_resource_scope,
            attempt_liveness,
            candidate_promoted,
            callback_gate,
            callback_policy,
            #[cfg(any(test, feature = "transport-lab"))]
            local_lab_callback_grant,
            #[cfg(any(test, feature = "transport-lab"))]
            mut construction_custodian,
            operation_fence,
            realtime_profile,
            close_owner,
        } = ownership;
        let api = Arc::clone(&self.api);
        if let Some(owner) = close_owner.as_ref() {
            owner.mark_native_allocation_started();
        }
        let mut pending_native_constructor =
            PendingNativeConstructorGuard::new(close_owner.as_ref().map(Arc::clone));
        #[cfg(test)]
        if let Some(hook) = self.construction_hook.as_ref() {
            hook.pause_before_native_constructor().await;
        }
        let callback_close_owner = close_owner.as_ref().map(Arc::downgrade);
        let pc = match api.new_peer_connection(config).await {
            Ok(pc) => {
                pending_native_constructor.disarm();
                pc
            }
            Err(error) => {
                pending_native_constructor.fail(format!(
                    "native construction returned without a close port: {error}"
                ));
                return Err(Error::Transport(format!("new_peer_connection: {error}")));
            }
        };
        let pc = Arc::new(pc);
        let realtime_close_owner = close_owner.as_ref().map(Arc::clone);
        let construction_owner = match close_owner {
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
                PeerConstructionOwner::Connector(owner)
            }
            Some(owner) => {
                callback_gate.retire();
                let _ = pc.close().await;
                owner.start();
                return Err(Error::Transport(
                    "native peer installation into close owner was refused".to_string(),
                ));
            }
            None => {
                #[cfg(any(test, feature = "transport-lab"))]
                {
                    let custodian = construction_custodian
                        .take()
                        .expect("raw lab construction has pre-existing close custody");
                    if !custodian.attach_native(Arc::clone(&pc)) {
                        callback_gate.retire();
                        let _ = pc.close().await;
                        return Err(Error::Transport(
                            "lab native peer installation into close custodian was refused"
                                .to_string(),
                        ));
                    }
                    PeerConstructionOwner::Lab(custodian)
                }
                #[cfg(not(any(test, feature = "transport-lab")))]
                {
                    unreachable!("a non-lab raw peer cannot omit its close owner")
                }
            }
        };
        let mut construction = PeerConstructionGuard::new(
            Arc::clone(&pc),
            Arc::clone(&callback_gate),
            construction_owner,
        );
        let result = async {
            #[cfg(test)]
            if let Some(hook) = self.construction_hook.as_ref() {
                hook.pause_after_native_allocation(&pc).await;
            }

            let callback_producer = match work_resource_scope.clone() {
                Some(scope) => CallbackProducerOwner::new(
                    scope,
                    crate::resource::ResourceAuthorityClass::Speculative,
                    CallbackProducerClaims::structural_only(),
                ),
                #[cfg(any(test, feature = "transport-lab"))]
                None => {
                    let grant = local_lab_callback_grant.ok_or_else(|| {
                        Error::Transport(
                            "a scope-less lab connector must state its own callback grant"
                                .to_string(),
                        )
                    })?;
                    CallbackProducerOwner::for_local_lab_grant(grant).map_err(|error| {
                        Error::Transport(format!(
                            "raw transport callback resource policy is unavailable: {error:?}"
                        ))
                    })?
                }
                #[cfg(not(any(test, feature = "transport-lab")))]
                None => return Err(Error::ConnectorPolicyRequired),
            };
            let callback_ready = Arc::new(tokio::sync::Notify::new());
            let control = callback_producer
                .create_mailbox(ConnectorCallbackClass::Control, Arc::clone(&callback_ready))
                .map_err(|error| {
                    callback_admission_error(
                        "control callback mailbox resource admission failed",
                        error,
                    )
                })?;
            let endpoint_data = callback_producer
                .create_mailbox(
                    ConnectorCallbackClass::EndpointData,
                    Arc::clone(&callback_ready),
                )
                .map_err(|error| {
                    callback_admission_error(
                        "endpoint callback mailbox resource admission failed",
                        error,
                    )
                })?;
            let reserved_open_work =
                callback_producer
                    .reserve_lifecycle_delivery()
                    .map_err(|error| {
                        callback_admission_error(
                            "connector open callback resource admission failed",
                            error,
                        )
                    })?;
            let reserved_close_work =
                callback_producer
                    .reserve_lifecycle_delivery()
                    .map_err(|error| {
                        callback_admission_error(
                            "connector close callback resource admission failed",
                            error,
                        )
                    })?;
            let realtime_resources = match callback_policy.realtime() {
                RealtimeConnectorPolicy::Disabled => None,
                RealtimeConnectorPolicy::Enabled => work_resource_scope.clone(),
            };
            let realtime_flows = RealtimeFlowRegistry::new(realtime_resources);
            // The application's codecs become a shared, leased record here —
            // once, against this connector's own work scope — and every session
            // promoted on this connector then holds a pointer to it. Deep-
            // cloning the codec vector per promotion, both `String`s per codec
            // and every feedback entry, would be retention nothing pays for.
            //
            // Refusal is ordinary and fails the connector rather than the
            // session: registering codecs whose retention nothing accounted for
            // is the state this exists to make unreachable.
            let realtime_profile = match realtime_profile {
                Some(profile) => Some(
                    session_flow::LeasedRealtimeProfile::mint(profile, &realtime_flows).map_err(
                        |_| {
                            Error::Transport(
                                "connector resources refused the real-time profile".to_string(),
                            )
                        },
                    )?,
                ),
                None => None,
            };
            let lifecycle = Arc::new(ConnectorLifecycleOwner::with_reserved_lifecycle_work(
                reserved_open_work,
                reserved_close_work,
            ));
            let event_sink = ConnectorEventSink {
                events: ConnectorEventMailboxes {
                    control: Arc::clone(&control),
                    endpoint_data: Arc::clone(&endpoint_data),
                    lifecycle: Arc::clone(&lifecycle),
                    #[cfg(test)]
                    callback_producer: callback_producer.clone(),
                },
                realtime_flows: Arc::clone(&realtime_flows),
                resource_scope: resource_scope.clone(),
                attempt_liveness,
                candidate_promoted,
                callback_gate: Arc::clone(&callback_gate),
                callback_violation_reported: Arc::new(AtomicBool::new(false)),
                callback_producer,
                operation_fence: Arc::clone(&operation_fence),
                close_owner: callback_close_owner,
            };
            let data_channel = Arc::new(SyncMutex::new(None::<Arc<RTCDataChannel>>));
            let opaque_data_channels = Arc::new(SyncMutex::new(OpaqueNativeLanes::default()));

            // Built before the callbacks so the `on_track` handler and the
            // session share one object rather than two that could diverge.
            #[cfg(any(test, feature = "transport-lab"))]
            let realtime_tracks = if realtime_close_owner.is_none() {
                Arc::new(RealtimeSessionTracks::with_task_reaper(TaskReaper::new()))
            } else {
                Arc::new(RealtimeSessionTracks::default())
            };
            #[cfg(not(any(test, feature = "transport-lab")))]
            let realtime_tracks = Arc::new(RealtimeSessionTracks::default());
            if let Some(owner) = realtime_close_owner.as_ref() {
                realtime_tracks.bind_cleanup_owner(owner);
            }

            // Register the standard callback before the offerer's initial
            // data-channel mutation. webrtc-rs intentionally does not reset
            // its internal negotiation-needed operation state when no handler
            // is installed, so late registration can strand every later media
            // notification. The gate suppresses that setup-only notification;
            // the first RTP mutation arms ordinary event-driven negotiation.
            let media_negotiation_callback = Arc::new(MediaNegotiationCallback {
                armed: AtomicBool::new(false),
                events_tx: event_sink.clone(),
                _callback_observation: observe_callback_if(
                    resource_scope.as_ref(),
                    "media-negotiation",
                ),
            });
            register_media_negotiation_callback(&pc, Arc::downgrade(&media_negotiation_callback));

            register_callbacks(
                &pc,
                &event_sink,
                &data_channel,
                &opaque_data_channels,
                resource_scope.clone(),
                work_resource_scope.clone(),
                Arc::clone(&realtime_tracks),
            );

            // Offerer creates the data channel synchronously so the
            // resulting SDP includes it. Answerer waits for the
            // `on_data_channel` callback that fires when the peer's
            // offer is applied.
            if role == Role::Offerer {
                let _operation = operation_fence.try_enter().ok_or_else(|| {
                    Error::Transport(
                        "connector close fence committed during data-channel construction"
                            .to_string(),
                    )
                })?;
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
                *data_channel.lock() = Some(dc);

                if matches!(
                    callback_policy.realtime(),
                    RealtimeConnectorPolicy::Enabled
                ) {
                    // Opaque capabilities are fixed native lanes, established
                    // with the initial offer. Logical application flows later
                    // multiplex on these lanes and never allocate channels of
                    // their own. Each lane's wrapper is funded before the native
                    // object is created and retained until peer teardown.
                    let Some(scope) = work_resource_scope.as_ref() else {
                        return Err(Error::Transport(
                            "enabled opaque lanes require a connector work scope".to_string(),
                        ));
                    };
                    for mode in [
                    OpaqueNativeLaneMode::ReliableOrdered,
                    OpaqueNativeLaneMode::PartialUnordered,
                    ] {
                    let claim = opaque_native_lane_claim().map_err(|error| {
                        Error::Transport(format!("opaque native lane claim overflowed: {error:?}"))
                    })?;
                    let lease = scope
                        .acquire(crate::resource::ResourceAuthorityClass::Admitted, claim)
                        .map_err(Error::ResourceUnavailable)?;
                    let init = match mode {
                        OpaqueNativeLaneMode::ReliableOrdered => RTCDataChannelInit {
                            ordered: Some(true),
                            ..Default::default()
                        },
                        OpaqueNativeLaneMode::PartialUnordered => RTCDataChannelInit {
                            ordered: Some(false),
                            max_retransmits: Some(0),
                            ..Default::default()
                        },
                    };
                    let lane = pc
                        .create_data_channel(mode.label(), Some(init))
                        .await
                        .map_err(|e| Error::Transport(format!("create opaque data channel: {e}")))?;
                    if !mode.matches_channel(&lane) {
                        return Err(Error::Transport(
                            "created opaque native data-channel reliability disagrees with its fixed lane"
                                .to_string(),
                        ));
                    }
                    install_opaque_data_channel_handlers(
                        lane.clone(),
                        event_sink.clone(),
                        resource_scope.as_ref(),
                        mode,
                    );
                    if !opaque_data_channels.lock().insert(
                        mode,
                        OpaqueNativeLane {
                            channel: lane,
                            _lease: lease,
                        },
                    ) {
                        return Err(Error::Transport(
                            "duplicate opaque native lane during construction".to_string(),
                        ));
                    }
                }
                }
            }

            let session = PeerSession {
                pc,
                data_channel,
                opaque_data_channels,
                realtime_profile,
                realtime_tracks,
                _events_tx: event_sink,
                media_negotiation_callback,
                operation_fence,
                callback_gate,
                role,
                #[cfg(any(test, feature = "transport-lab"))]
                raw_close_owner: None,
                _resource_scope: resource_scope,
                work_resource_scope,
            };
            Ok((
                session,
                TransportEventReceiver {
                    control,
                    endpoint_data,
                    lifecycle,
                    lifecycle_closed: false,
                    callback_ready,
                    callback_failed: false,
                    realtime_flows,
                    scheduler: ConnectorCallbackScheduler::new(callback_policy),
                    control_cursor: ConnectorControlSourceCursor::default(),
                },
            ))
        }
        .await;

        match result {
            Ok((session, events)) => {
                #[cfg(any(test, feature = "transport-lab"))]
                let mut session = session;
                #[cfg(not(any(test, feature = "transport-lab")))]
                let session = session;
                let owner = construction.take_owner().ok_or_else(|| {
                    Error::Transport(
                        "native construction owner was lost before handoff".to_string(),
                    )
                })?;
                #[cfg(any(test, feature = "transport-lab"))]
                if let PeerConstructionOwner::Lab(custodian) = owner {
                    session.raw_close_owner = Some(custodian);
                }
                #[cfg(not(any(test, feature = "transport-lab")))]
                drop(owner);
                Ok((session, events))
            }
            Err(error) => {
                construction.close().await;
                Err(error)
            }
        }
    }
}

enum PeerConstructionOwner {
    Connector(Arc<ConnectorCloseOwner>),
    #[cfg(any(test, feature = "transport-lab"))]
    Lab(Arc<PeerConstructionCloseCustodian>),
}

impl PeerConstructionOwner {
    fn start(&self) {
        match self {
            Self::Connector(owner) => owner.start(),
            #[cfg(any(test, feature = "transport-lab"))]
            Self::Lab(custodian) => custodian.start(),
        }
    }

    async fn wait(&self) -> Result<()> {
        match self {
            Self::Connector(owner) => owner.wait().await,
            #[cfg(any(test, feature = "transport-lab"))]
            Self::Lab(custodian) => custodian.wait().await,
        }
    }
}

/// Closes a native peer connection when construction errors or its owned task
/// is cancelled after the dependency returned the object but before the
/// complete `PeerSession` can be handed to its connector owner. The owner is
/// mandatory: production uses the connector close owner and raw lab use has a
/// pre-existing [`PeerConstructionCloseCustodian`].
struct PeerConstructionGuard {
    pc: Option<Arc<RTCPeerConnection>>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    owner: Option<PeerConstructionOwner>,
}

impl PeerConstructionGuard {
    fn new(
        pc: Arc<RTCPeerConnection>,
        callback_gate: Arc<WebRtcConnectorIncarnation>,
        owner: PeerConstructionOwner,
    ) -> Self {
        Self {
            pc: Some(pc),
            callback_gate,
            owner: Some(owner),
        }
    }

    fn take_owner(&mut self) -> Option<PeerConstructionOwner> {
        self.pc = None;
        self.owner.take()
    }

    async fn close(&mut self) {
        let Some(owner) = self.owner.as_ref() else {
            return;
        };
        self.pc = None;
        self.callback_gate.retire();
        owner.start();
        let _ = owner.wait().await;
    }
}

impl Drop for PeerConstructionGuard {
    fn drop(&mut self) {
        if let Some(owner) = self.owner.take() {
            self.pc = None;
            self.callback_gate.retire();
            owner.start();
        }
    }
}

fn register_callbacks(
    pc: &Arc<RTCPeerConnection>,
    events_tx: &ConnectorEventSink,
    data_channel: &Arc<SyncMutex<Option<Arc<RTCDataChannel>>>>,
    opaque_data_channels: &Arc<SyncMutex<OpaqueNativeLanes>>,
    resource_scope: Option<PeerConnectionResourceScope>,
    work_resource_scope: Option<ConnectorWorkResourceScope>,
    realtime_tracks: Arc<RealtimeSessionTracks>,
) {
    // Local ICE candidate gathered — ship via signaling.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_callback_if(resource_scope.as_ref(), "ice-candidate");
        pc.on_ice_candidate(Box::new(move |cand| {
            let _keep_callback_observation = &callback_observation;
            let mut callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native ICE callback before candidate conversion"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let candidate = match cand {
                Some(candidate) => match candidate.to_json() {
                    Ok(init) => Some(LocalIceCandidate {
                        candidate: init.candidate,
                        sdp_mid: init.sdp_mid,
                        sdp_mline_index: init.sdp_mline_index,
                        username_fragment: init.username_fragment,
                    }),
                    Err(error) => {
                        warn!("ice_candidate to_json: {error}");
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                },
                None => None,
            };
            let Some((payload_bytes, retained_slack)) = candidate_callback_sizes(&candidate) else {
                tx.retire_after_callback_violation();
                return Box::pin(async {});
            };
            if let Err(error) = tx.callback_producer.account_executing_payload(
                &mut callback_work,
                payload_bytes,
                retained_slack,
            ) {
                warn!(
                    ?error,
                    "refusing converted native ICE callback under resource pressure"
                );
                tx.retire_after_callback_violation();
                return Box::pin(async {});
            }
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::LocalIceCandidate(candidate)).await;
            })
        }));
    }

    // ICE connection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_callback_if(resource_scope.as_ref(), "ice-state");
        pc.on_ice_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native ICE-state callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::IceConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // PeerConnection state changed.
    {
        let tx = events_tx.clone();
        let callback_observation = observe_callback_if(resource_scope.as_ref(), "peer-state");
        pc.on_peer_connection_state_change(Box::new(move |state| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native peer-state callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit(TransportEvent::PeerConnectionStateChanged(state))
                    .await;
            })
        }));
    }

    // Answerer side: data channel arrives via callback.
    {
        let tx = events_tx.clone();
        let dc_slot = data_channel.clone();
        let opaque_slots = opaque_data_channels.clone();
        let handler_scope = resource_scope.clone();
        let handler_work_scope = work_resource_scope.clone();
        let callback_observation =
            observe_callback_if(resource_scope.as_ref(), "data-channel-arrival");
        pc.on_data_channel(Box::new(move |dc| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            let dc_slot = dc_slot.clone();
            let opaque_slots = opaque_slots.clone();
            let handler_scope = handler_scope.clone();
            let handler_work_scope = handler_work_scope.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                let Some(_operation) = tx.operation_fence.try_enter() else {
                    return;
                };
                if let Some(mode) = OpaqueNativeLaneMode::from_label(dc.label()) {
                    let Some(scope) = handler_work_scope.as_ref() else {
                        tx.structural_violation(
                            "opaque native data-channel arrived without connector funding",
                        );
                        return;
                    };
                    if !mode.matches_channel(&dc) {
                        tx.structural_violation(
                            "opaque native data-channel reliability disagrees with its fixed lane",
                        );
                        return;
                    }
                    let claim = match opaque_native_lane_claim() {
                        Ok(claim) => claim,
                        Err(_) => {
                            tx.structural_violation("opaque native data-channel claim overflowed");
                            return;
                        }
                    };
                    let lease = match scope
                        .acquire(crate::resource::ResourceAuthorityClass::Admitted, claim)
                    {
                        Ok(lease) => lease,
                        Err(_) => {
                            tx.structural_violation(
                                "opaque native data-channel refused by connector funding",
                            );
                            return;
                        }
                    };
                    let installed = opaque_slots.lock().insert(
                        mode,
                        OpaqueNativeLane {
                            channel: dc.clone(),
                            _lease: lease,
                        },
                    );
                    if !installed {
                        tx.structural_violation("duplicate opaque native data-channel");
                        return;
                    }
                    install_opaque_data_channel_handlers(
                        dc.clone(),
                        tx,
                        handler_scope.as_ref(),
                        mode,
                    );
                    return;
                }
                {
                    let mut slot = dc_slot.lock();
                    match admit_native_data_channel(dc.label(), slot.is_some()) {
                        NativeDataChannelAdmission::Install => *slot = Some(dc.clone()),
                        NativeDataChannelAdmission::Violation(reason) => {
                            drop(slot);
                            tx.structural_violation(reason);
                            return;
                        }
                    }
                }
                install_data_channel_handlers(dc.clone(), tx, handler_scope.as_ref());
            })
        }));
    }

    // A negotiated inbound real-time track went live — pump its RTP until the
    // flow it feeds ends, or the track (i.e. the connection) does.
    {
        let tx = events_tx.clone();
        let task_scope = resource_scope.clone();
        let session_tracks = Arc::clone(&realtime_tracks);
        let callback_observation = observe_callback_if(resource_scope.as_ref(), "track");
        pc.on_track(Box::new(move |track, _receiver, transceiver| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Realtime) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native track callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            let session_tracks = Arc::clone(&session_tracks);
            let task_observation =
                observe_inexact_item_if(task_scope.as_ref(), PreAuthResourceFamily::Task, 1, 1);
            Box::pin(async move {
                let _callback_work = callback_work;
                let Some(_operation) = tx.operation_fence.try_enter() else {
                    return;
                };
                if !tx.callback_gate.is_active() {
                    return;
                }

                // **Classified by transceiver identity, and by nothing else.**
                // A track that arrived on a transceiver *this side* created for
                // a realtime flow is realtime-owned, permanently and regardless
                // of what has happened to the session since. A track on any
                // other transceiver is one the peer opened the m-line for, and
                // there is nothing here it can be attached to: a destination is
                // a fact this side established at bind time, so a track we did
                // not solicit has none.
                //
                // Every refusal below drops the track and returns. None of them
                // calls `structural_violation` or `retire_after_callback_
                // violation`: a track we did not offer is the peer doing
                // something we simply do not accept, not this connector having
                // broken its own invariants, and tearing the connection down
                // would let a peer end a session by offering one unsolicited
                // track.
                let Some(identity) = session_tracks.resolve(&transceiver) else {
                    trace!("dropping a track on a transceiver this side did not negotiate");
                    return;
                };
                // Our transceiver, but the session that gave its token meaning
                // is gone. Refused, and deliberately not passed on.
                let Some(bindings) = session_tracks.current() else {
                    return;
                };
                // An unspecified kind is not guessed at: it matches no binding,
                // and a track matching no binding is dropped.
                let Some(kind) = native_rtp_kind(track.kind()) else {
                    return;
                };
                let capability = &track.codec().capability;
                let Some(attachment) = bindings.admit(
                    &identity,
                    kind,
                    &capability.mime_type,
                    capability.clock_rate,
                    capability.channels,
                ) else {
                    // Our transceiver, a shape we did not open the flow for —
                    // or one whose flow has since closed. Attaching would feed
                    // a decoder configured for something else.
                    return;
                };
                // No second flow open here, and that is the point of the weak
                // port handle the admission carried. The
                // application already opened this flow and it already holds the
                // one active-flow lease it is entitled to; taking a second for
                // the same flow would halve the configured capacity and let a
                // refusal land on a flow whose open had already succeeded.
                let task = tokio::spawn(pump_session_flow_track(
                    track,
                    tx,
                    SessionInboundTrackOwner {
                        task_observation,
                        port: attachment.port,
                        end: attachment.end,
                        tracks: Arc::clone(&session_tracks),
                        identity: Arc::clone(&identity),
                        label: attachment.label,
                        policy: attachment.policy,
                    },
                ));
                if let Err(task) = session_tracks.attach_task(&identity, task) {
                    task.abort();
                    session_tracks.submit_tasks(vec![task]);
                }
            })
        }));
    }
}

/// Install the standard WebRTC renegotiation callback during peer construction.
///
/// The initial data channel is negotiated explicitly by the connection setup
/// path, so its notification is suppressed by `armed`. The first RTP mutation
/// flips that gate. This preserves the dependency's operations-chain and
/// stable-state coalescing without asking elapsed time to discover a change.
fn register_media_negotiation_callback(
    pc: &Arc<RTCPeerConnection>,
    callback: std::sync::Weak<MediaNegotiationCallback>,
) {
    pc.on_negotiation_needed(Box::new(move || {
        let Some(callback) = callback.upgrade() else {
            return Box::pin(async {});
        };
        if !callback.armed.load(Ordering::Acquire) {
            return Box::pin(async {});
        }
        let callback_work = match callback
            .events_tx
            .begin_native_callback_operation(ConnectorCallbackClass::Control)
        {
            Ok(work) => work,
            Err(error) => {
                warn!(
                    ?error,
                    "refusing native negotiation-needed callback under resource pressure"
                );
                callback.events_tx.retire_after_callback_violation();
                return Box::pin(async {});
            }
        };
        let tx = callback.events_tx.clone();
        Box::pin(async move {
            let _callback = callback;
            let _callback_work = callback_work;
            tx.emit(TransportEvent::RenegotiationNeeded).await;
        })
    }));
}

/// Session-owned state behind the peer connection's weak native callback.
/// Keeping the handler weak prevents the dependency callback table from
/// extending the lifetime of event mailboxes, resource scopes, or connector
/// custody after the session owner is gone.
struct MediaNegotiationCallback {
    armed: AtomicBool,
    events_tx: ConnectorEventSink,
    _callback_observation: Option<CallbackObservationLease>,
}

fn install_data_channel_handlers(
    dc: Arc<RTCDataChannel>,
    tx: ConnectorEventSink,
    resource_scope: Option<&PeerConnectionResourceScope>,
) {
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "data-channel-open");
        dc.on_open(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-open callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::DataChannelOpen).await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "data-channel-close");
        dc.on_close(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-close callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "data-channel-message");
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            let callback = tx.begin_message_callback(msg.data, &callback_observation);
            Box::pin(async move {
                let _ = callback.await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "data-channel-error");
        dc.on_error(Box::new(move |err| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing native data-channel-error callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                warn!("data channel error: {err}");
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
}

/// Install handlers for one authenticated persistent opaque lane. Its mode is
/// captured from the native channel label/negotiation, so a frame header cannot
/// claim a different reliability class. Lane lifecycle is connector lifecycle:
/// if a native lane closes, the existing data-channel close path retires the
/// session rather than silently leaving logical flows stranded.
fn install_opaque_data_channel_handlers(
    dc: Arc<RTCDataChannel>,
    tx: ConnectorEventSink,
    resource_scope: Option<&PeerConnectionResourceScope>,
    mode: OpaqueNativeLaneMode,
) {
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "opaque-lane-close");
        dc.on_close(Box::new(move || {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing opaque-lane close callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                tx.emit_data_channel(TransportEvent::DataChannelClosed)
                    .await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "opaque-lane-message");
        dc.on_message(Box::new(move |msg: DataChannelMessage| {
            if !opaque_frame_matches_lane(&msg.data, mode) {
                tx.structural_violation("opaque native frame mode disagrees with its lane");
                return Box::pin(async {});
            }
            let callback =
                tx.begin_application_flow_callback(mode.into(), msg.data, &callback_observation);
            Box::pin(async move {
                let _ = callback.await;
            })
        }));
    }
    {
        let tx = tx.clone();
        let callback_observation = observe_callback_if(resource_scope, "opaque-lane-error");
        dc.on_error(Box::new(move |err| {
            let _keep_callback_observation = &callback_observation;
            let callback_work =
                match tx.begin_native_callback_operation(ConnectorCallbackClass::Control) {
                    Ok(work) => work,
                    Err(error) => {
                        warn!(
                            ?error,
                            "refusing opaque-lane error callback under resource pressure"
                        );
                        tx.retire_after_callback_violation();
                        return Box::pin(async {});
                    }
                };
            let tx = tx.clone();
            Box::pin(async move {
                let _callback_work = callback_work;
                warn!("opaque data channel error: {err}");
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

/// Extract the DTLS fingerprint (`a=fingerprint:<hash> <value>`) from an SDP
/// blob and lowercase it for stable comparison. This is endpoint-authentication
/// binding and diagnostic input. ICE restart detection uses the exact effective
/// ICE credentials instead of this fingerprint.
pub(crate) fn sdp_fingerprint(sdp: &str) -> Option<String> {
    sdp.lines()
        .map(str::trim)
        .find_map(|line| line.strip_prefix("a=fingerprint:"))
        .map(|v| v.trim().to_ascii_lowercase())
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct RemoteIceCredentialBinding {
    media_index: usize,
    mid: Option<String>,
    username_fragment: String,
    password: String,
}

/// Exact effective remote ICE credentials for every SDP media section.
///
/// Session-level credentials are inherited by a media section only when that
/// section does not override them. MID, or media index when MID is absent,
/// identifies an existing ICE transport across renegotiation. Adding or
/// removing a media section does not manufacture an ICE restart. A changed
/// credential pair on the same transport does.
#[derive(Debug)]
struct RemoteIceCredentialsInner {
    bindings: Vec<RemoteIceCredentialBinding>,
    resources: Option<Arc<RemoteDescriptionResourceOwner>>,
}

#[derive(Debug)]
struct RemoteDescriptionResourceOwner {
    lease: SyncMutex<Option<crate::resource::ResourceLease>>,
    post_native_claim: crate::resource::ResourceClaim,
}

impl RemoteDescriptionResourceOwner {
    fn new(
        lease: crate::resource::ResourceLease,
        post_native_claim: crate::resource::ResourceClaim,
    ) -> Arc<Self> {
        Arc::new(Self {
            lease: SyncMutex::new(Some(lease)),
            post_native_claim,
        })
    }

    fn finish_native_commit(&self) -> Result<()> {
        let mut lease = self.lease.lock();
        let Some(lease) = lease.as_mut() else {
            return Err(Error::ResourceUnavailable(
                ResourceUnavailable::ProviderInvariant {
                    dimension: crate::resource::ResourceClass::OpaqueDependencyResidual,
                },
            ));
        };
        lease
            .transition(self.post_native_claim)
            .map_err(Error::ResourceUnavailable)
    }

    fn retain_after_cleanup_failure(&self) {
        if let Some(lease) = self.lease.lock().take() {
            let _ = lease.retain_after_failed_cleanup();
        }
    }
}

#[derive(Debug, Clone)]
struct RemoteIceCredentials {
    inner: Arc<RemoteIceCredentialsInner>,
}

impl RemoteIceCredentials {
    fn new(
        bindings: Vec<RemoteIceCredentialBinding>,
        resources: Option<Arc<RemoteDescriptionResourceOwner>>,
    ) -> Self {
        Self {
            inner: Arc::new(RemoteIceCredentialsInner {
                bindings,
                resources,
            }),
        }
    }

    fn finish_native_commit(&self) -> Result<()> {
        let Some(resources) = self.resources.as_ref() else {
            return Ok(());
        };
        resources.finish_native_commit()
    }

    fn resource_owner(&self) -> Option<Arc<RemoteDescriptionResourceOwner>> {
        self.resources.as_ref().map(Arc::clone)
    }
}

impl std::ops::Deref for RemoteIceCredentials {
    type Target = RemoteIceCredentialsInner;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl PartialEq for RemoteIceCredentials {
    fn eq(&self, other: &Self) -> bool {
        self.bindings == other.bindings
    }
}

impl Eq for RemoteIceCredentials {}

impl RemoteIceCredentials {
    fn has_unambiguous_credential_pair(&self, username_fragment: &str) -> bool {
        let mut matching = self
            .bindings
            .iter()
            .filter(|binding| binding.username_fragment == username_fragment);
        let Some(first) = matching.next() else {
            return false;
        };
        matching.all(|binding| binding.password == first.password)
    }

    fn proves_restart_to(&self, replacement: &Self) -> bool {
        let mut overlapping_transport = false;
        for current in &self.bindings {
            let next = match current.mid.as_deref() {
                Some(mid) => replacement
                    .bindings
                    .iter()
                    .find(|binding| binding.mid.as_deref() == Some(mid)),
                None => replacement.bindings.iter().find(|binding| {
                    binding.mid.is_none() && binding.media_index == current.media_index
                }),
            };
            let Some(next) = next else {
                continue;
            };
            overlapping_transport = true;
            if current.username_fragment != next.username_fragment
                || current.password != next.password
            {
                return true;
            }
        }
        if overlapping_transport {
            return false;
        }

        let mut current_pairs: Vec<(&str, &str)> = self
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.username_fragment.as_str(),
                    binding.password.as_str(),
                )
            })
            .collect();
        let mut replacement_pairs: Vec<(&str, &str)> = replacement
            .bindings
            .iter()
            .map(|binding| {
                (
                    binding.username_fragment.as_str(),
                    binding.password.as_str(),
                )
            })
            .collect();
        current_pairs.sort_unstable();
        current_pairs.dedup();
        replacement_pairs.sort_unstable();
        replacement_pairs.dedup();
        current_pairs != replacement_pairs
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CandidateUsernameFragmentError {
    MissingCandidateLineValue,
    DuplicateCandidateLineDeclaration,
    ConflictingDeclarations,
}

impl CandidateUsernameFragmentError {
    pub(crate) const fn description(self) -> &'static str {
        match self {
            Self::MissingCandidateLineValue => "candidate-line ufrag has no value",
            Self::DuplicateCandidateLineDeclaration => {
                "candidate line declares ufrag more than once"
            }
            Self::ConflictingDeclarations => {
                "structured and candidate-line username fragments conflict"
            }
        }
    }
}

fn candidate_line_username_fragment(
    candidate_line: &str,
) -> std::result::Result<Option<&str>, CandidateUsernameFragmentError> {
    let mut fields = candidate_line.split_ascii_whitespace();
    for _ in 0..8 {
        if fields.next().is_none() {
            return Ok(None);
        }
    }

    let mut username_fragment = None;
    while let Some(extension) = fields.next() {
        let value = fields.next();
        if !extension.eq_ignore_ascii_case("ufrag") {
            continue;
        }
        let Some(value) = value else {
            return Err(CandidateUsernameFragmentError::MissingCandidateLineValue);
        };
        if username_fragment.replace(value).is_some() {
            return Err(CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration);
        }
    }
    Ok(username_fragment)
}

fn candidate_username_fragment(
    candidate: &LocalIceCandidate,
) -> std::result::Result<Option<&str>, CandidateUsernameFragmentError> {
    let structured = candidate
        .username_fragment
        .as_deref()
        .filter(|username_fragment| !username_fragment.is_empty());
    let candidate_line = candidate_line_username_fragment(&candidate.candidate)?;
    match (structured, candidate_line) {
        (Some(structured), Some(candidate_line)) if structured != candidate_line => {
            Err(CandidateUsernameFragmentError::ConflictingDeclarations)
        }
        (Some(structured), _) => Ok(Some(structured)),
        (None, candidate_line) => Ok(candidate_line),
    }
}

fn candidate_matches_remote_credentials(
    candidate: &LocalIceCandidate,
    credentials: &RemoteIceCredentials,
) -> bool {
    // webrtc-rs currently serializes a gathered candidate with `Some("")` for
    // an unavailable MID while still supplying the exact media-line index.
    // An empty MID carries no identity. A nonempty MID and an index, when both
    // exist, must still resolve to the same credential binding.
    let candidate_mid = candidate.sdp_mid.as_deref().filter(|mid| !mid.is_empty());
    let declares_location = candidate.sdp_mline_index.is_some() || candidate_mid.is_some();
    let Ok(username_fragment) = candidate_username_fragment(candidate) else {
        return false;
    };
    if !declares_location && username_fragment.is_none() {
        return false;
    }
    let exact_binding = declares_location.then(|| {
        credentials.bindings.iter().find(|binding| {
            candidate
                .sdp_mline_index
                .is_none_or(|media_index| usize::from(media_index) == binding.media_index)
                && candidate_mid.is_none_or(|mid| binding.mid.as_deref() == Some(mid))
        })
    });
    let exact_binding = exact_binding.flatten();
    if declares_location && exact_binding.is_none() {
        return false;
    }
    match (exact_binding, username_fragment) {
        (Some(binding), Some(username_fragment)) => binding.username_fragment == username_fragment,
        (Some(_), None) => true,
        (None, Some(username_fragment)) => {
            credentials.has_unambiguous_credential_pair(username_fragment)
        }
        (None, None) => false,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RemoteIceCredentialAllocationPlan {
    media_count: usize,
    binding_count: usize,
    string_bytes: usize,
}

#[derive(Default)]
struct PlannedIceMediaSection<'a> {
    media_index: usize,
    rejected: bool,
    mid: Option<&'a str>,
    username_fragment: Option<&'a str>,
    password: Option<&'a str>,
}

fn finish_planned_ice_media_section(
    section: PlannedIceMediaSection<'_>,
    session_username_fragment: Option<&str>,
    session_password: Option<&str>,
    binding_count: &mut usize,
    string_bytes: &mut usize,
) -> Result<()> {
    if section.rejected {
        return Ok(());
    }
    let username_fragment = section
        .username_fragment
        .or(session_username_fragment)
        .ok_or_else(|| {
            Error::Transport(format!(
                "remote SDP media section {} has no effective ICE username fragment",
                section.media_index
            ))
        })?;
    let password = section.password.or(session_password).ok_or_else(|| {
        Error::Transport(format!(
            "remote SDP media section {} has no effective ICE password",
            section.media_index
        ))
    })?;
    *binding_count = binding_count.checked_add(1).ok_or_else(|| {
        Error::Transport("remote SDP credential binding count overflowed".to_string())
    })?;
    *string_bytes = string_bytes
        .checked_add(section.mid.map_or(0, str::len))
        .and_then(|total| total.checked_add(username_fragment.len()))
        .and_then(|total| total.checked_add(password.len()))
        .ok_or_else(|| {
            Error::Transport("remote SDP credential string size overflowed".to_string())
        })?;
    Ok(())
}

/// Inspect the exact retained credential shape without allocating parser
/// records or credential strings. The retained output claim is acquired from
/// this plan before the allocating parser runs. Parser scratch, allocator
/// slack, and the dependency-owned native description remain named opaque
/// residual domains.
fn plan_sdp_ice_credential_allocations(sdp: &str) -> Result<RemoteIceCredentialAllocationPlan> {
    let mut session_username_fragment = None;
    let mut session_password = None;
    let mut current = None::<PlannedIceMediaSection<'_>>;
    let mut media_count = 0_usize;
    let mut binding_count = 0_usize;
    let mut string_bytes = 0_usize;

    for raw_line in sdp.lines() {
        let line = raw_line.trim().trim_end_matches('\r');
        if let Some(media) = line.strip_prefix("m=") {
            if let Some(section) = current.take() {
                finish_planned_ice_media_section(
                    section,
                    session_username_fragment,
                    session_password,
                    &mut binding_count,
                    &mut string_bytes,
                )?;
            }
            let media_index = media_count;
            media_count = media_count.checked_add(1).ok_or_else(|| {
                Error::Transport("remote SDP media section count overflowed".to_string())
            })?;
            let rejected = media
                .split_ascii_whitespace()
                .nth(1)
                .and_then(|port| port.split('/').next())
                .is_some_and(|port| port == "0");
            current = Some(PlannedIceMediaSection {
                media_index,
                rejected,
                ..Default::default()
            });
            continue;
        }
        if let Some(value) = line.strip_prefix("a=mid:") {
            if let Some(section) = current.as_mut() {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Error::Transport(
                        "remote SDP carries an empty MID".to_string(),
                    ));
                }
                if section.mid.replace(value).is_some() {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one MID".to_string(),
                    ));
                }
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE username fragment".to_string(),
                ));
            }
            match current.as_mut() {
                Some(section) => {
                    if section.username_fragment.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP media section carries more than one ICE username fragment"
                                .to_string(),
                        ));
                    }
                }
                None => {
                    if session_username_fragment.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP session carries more than one ICE username fragment"
                                .to_string(),
                        ));
                    }
                }
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE password".to_string(),
                ));
            }
            match current.as_mut() {
                Some(section) => {
                    if section.password.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP media section carries more than one ICE password"
                                .to_string(),
                        ));
                    }
                }
                None => {
                    if session_password.replace(value).is_some() {
                        return Err(Error::Transport(
                            "remote SDP session carries more than one ICE password".to_string(),
                        ));
                    }
                }
            }
        }
    }

    let Some(section) = current else {
        return Err(Error::Transport(
            "remote SDP has no media section for exact ICE credentials".to_string(),
        ));
    };
    finish_planned_ice_media_section(
        section,
        session_username_fragment,
        session_password,
        &mut binding_count,
        &mut string_bytes,
    )?;
    if binding_count == 0 {
        return Err(Error::Transport(
            "remote SDP has no active media section with exact ICE credentials".to_string(),
        ));
    }
    Ok(RemoteIceCredentialAllocationPlan {
        media_count,
        binding_count,
        string_bytes,
    })
}

#[derive(Default)]
struct ParsedIceMediaSection {
    rejected: bool,
    mid: Option<String>,
    username_fragment: Option<String>,
    password: Option<String>,
}

fn parse_sdp_ice_credential_bindings_with_plan(
    sdp: &str,
    plan: RemoteIceCredentialAllocationPlan,
) -> Result<Vec<RemoteIceCredentialBinding>> {
    let mut session_username_fragment = None;
    let mut session_password = None;
    let mut sections = Vec::<ParsedIceMediaSection>::with_capacity(plan.media_count);

    for raw_line in sdp.lines() {
        let line = raw_line.trim().trim_end_matches('\r');
        if let Some(media) = line.strip_prefix("m=") {
            let rejected = media
                .split_ascii_whitespace()
                .nth(1)
                .and_then(|port| port.split('/').next())
                .is_some_and(|port| port == "0");
            sections.push(ParsedIceMediaSection {
                rejected,
                ..Default::default()
            });
            continue;
        }
        let target = sections.last_mut();
        if let Some(value) = line.strip_prefix("a=mid:") {
            if let Some(section) = target {
                let value = value.trim();
                if value.is_empty() {
                    return Err(Error::Transport(
                        "remote SDP carries an empty MID".to_string(),
                    ));
                }
                if section.mid.is_some() {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one MID".to_string(),
                    ));
                }
                section.mid = Some(value.to_string());
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-ufrag:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE username fragment".to_string(),
                ));
            }
            match target {
                Some(section) if section.username_fragment.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one ICE username fragment"
                            .to_string(),
                    ));
                }
                Some(section) => section.username_fragment = Some(value.to_string()),
                None if session_username_fragment.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP session carries more than one ICE username fragment"
                            .to_string(),
                    ));
                }
                None => session_username_fragment = Some(value.to_string()),
            }
            continue;
        }
        if let Some(value) = line.strip_prefix("a=ice-pwd:") {
            let value = value.trim();
            if value.is_empty() {
                return Err(Error::Transport(
                    "remote SDP carries an empty ICE password".to_string(),
                ));
            }
            match target {
                Some(section) if section.password.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP media section carries more than one ICE password".to_string(),
                    ));
                }
                Some(section) => section.password = Some(value.to_string()),
                None if session_password.is_some() => {
                    return Err(Error::Transport(
                        "remote SDP session carries more than one ICE password".to_string(),
                    ));
                }
                None => session_password = Some(value.to_string()),
            }
        }
    }

    if sections.is_empty() {
        return Err(Error::Transport(
            "remote SDP has no media section for exact ICE credentials".to_string(),
        ));
    }

    let mut bindings = Vec::with_capacity(plan.binding_count);
    let mut active_mids = std::collections::HashSet::with_capacity(plan.binding_count);
    for (media_index, section) in sections.into_iter().enumerate() {
        if section.rejected {
            continue;
        }
        if let Some(mid) = section.mid.as_ref() {
            if !active_mids.insert(mid.clone()) {
                return Err(Error::Transport(format!(
                    "remote SDP repeats active MID {mid}"
                )));
            }
        }
        let username_fragment = section
            .username_fragment
            .or_else(|| session_username_fragment.clone())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "remote SDP media section {media_index} has no effective ICE username fragment"
                ))
            })?;
        let password = section
            .password
            .or_else(|| session_password.clone())
            .ok_or_else(|| {
                Error::Transport(format!(
                    "remote SDP media section {media_index} has no effective ICE password"
                ))
            })?;
        bindings.push(RemoteIceCredentialBinding {
            media_index,
            mid: section.mid,
            username_fragment,
            password,
        });
    }
    if bindings.is_empty() {
        return Err(Error::Transport(
            "remote SDP has no active media section with exact ICE credentials".to_string(),
        ));
    }
    Ok(bindings)
}

#[cfg(test)]
fn parse_sdp_ice_credential_bindings(sdp: &str) -> Result<Vec<RemoteIceCredentialBinding>> {
    let plan = plan_sdp_ice_credential_allocations(sdp)?;
    parse_sdp_ice_credential_bindings_with_plan(sdp, plan)
}

#[cfg(test)]
fn sdp_ice_credentials(sdp: &str) -> Result<RemoteIceCredentials> {
    parse_sdp_ice_credential_bindings(sdp).map(|bindings| RemoteIceCredentials::new(bindings, None))
}

fn remote_description_operation_claim(
    input_capacity: usize,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let input_capacity = u64::try_from(input_capacity).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            input_capacity,
        ),
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (
            crate::resource::ResourceClass::ParsingOrCpuWork,
            input_capacity,
        ),
        // Credential-extraction scratch and the dependency-owned parsed/native
        // remote-description tree are explicit non-byte residual domains.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

fn remote_description_registry_entry_claim() -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let arc_counters = std::mem::size_of::<usize>().checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let accounted = std::mem::size_of::<Arc<RemoteDescriptionResourceOwner>>()
        .checked_add(std::mem::size_of::<RemoteDescriptionResourceOwner>())
        .and_then(|value| value.checked_add(arc_counters))
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let accounted = u64::try_from(accounted).map_err(|_| {
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        }
    })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::StorageObject, 1),
        // Arc and linked-list allocation metadata, padding, and allocator
        // behavior are two named residual domains.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])
}

#[cfg(any(test, feature = "transport-lab"))]
fn retained_remote_description_claim_from_plan(
    plan: RemoteIceCredentialAllocationPlan,
    input_capacity: usize,
    native_work_in_flight: bool,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = plan
        .binding_count
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(plan.string_bytes))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let mut claim = crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)?;
    if native_work_in_flight {
        claim = claim.checked_add(crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::CallbackOrScheduledWork,
            1,
        ))?;
    }
    Ok(claim)
}

fn retained_remote_description_claim(
    bindings: &[RemoteIceCredentialBinding],
    binding_capacity: usize,
    input_capacity: usize,
    native_work_in_flight: bool,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = binding_capacity
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let string_capacities = bindings.iter().try_fold(0_usize, |total, binding| {
        total
            .checked_add(binding.mid.as_ref().map_or(0, String::capacity))
            .and_then(|total| total.checked_add(binding.username_fragment.capacity()))
            .and_then(|total| total.checked_add(binding.password.capacity()))
    });
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(string_capacities?))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let mut claim = crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)?;
    if native_work_in_flight {
        claim = claim.checked_add(crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::CallbackOrScheduledWork,
            1,
        ))?;
    }
    Ok(claim)
}

fn planned_remote_description_claim(
    plan: RemoteIceCredentialAllocationPlan,
    input_capacity: usize,
) -> std::result::Result<
    crate::resource::ResourceClaim,
    crate::resource::ResourceClaimArithmeticError,
> {
    let binding_records = plan
        .binding_count
        .checked_mul(std::mem::size_of::<RemoteIceCredentialBinding>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_sections = plan
        .media_count
        .checked_mul(std::mem::size_of::<ParsedIceMediaSection>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_mid_keys = plan
        .binding_count
        .checked_mul(std::mem::size_of::<String>())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    let parser_string_copies = input_capacity.checked_mul(2).ok_or(
        crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        },
    )?;
    let accounted = std::mem::size_of::<RemoteIceCredentialsInner>()
        .checked_add(std::mem::size_of::<Vec<RemoteIceCredentialBinding>>())
        .and_then(|total| total.checked_add(std::mem::size_of::<Vec<ParsedIceMediaSection>>()))
        .and_then(|total| {
            total.checked_add(std::mem::size_of::<std::collections::HashSet<String>>())
        })
        .and_then(|total| total.checked_add(binding_records))
        .and_then(|total| total.checked_add(parser_sections))
        .and_then(|total| total.checked_add(parser_mid_keys))
        .and_then(|total| total.checked_add(plan.string_bytes))
        .and_then(|total| total.checked_add(parser_string_copies))
        .and_then(|total| total.checked_add(input_capacity))
        .and_then(|total| u64::try_from(total).ok())
        .ok_or(crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        })?;
    crate::resource::ResourceClaim::try_from_entries([
        (
            crate::resource::ResourceClass::AccountedMemoryBytes,
            accounted,
        ),
        (crate::resource::ResourceClass::CallbackOrScheduledWork, 1),
        (
            crate::resource::ResourceClass::ParsingOrCpuWork,
            u64::try_from(input_capacity).map_err(|_| {
                crate::resource::ResourceClaimArithmeticError::Overflow {
                    dimension: crate::resource::ResourceClass::ParsingOrCpuWork,
                }
            })?,
        ),
        // One unit protects HashSet and allocator slack. The other protects
        // the dependency-owned parsed/native remote description.
        (crate::resource::ResourceClass::OpaqueDependencyResidual, 2),
    ])?
    .checked_add(remote_description_registry_entry_claim()?)
}

fn sdp_ice_credentials_owned(
    sdp: &str,
    input_capacity: usize,
    work_resources: &ConnectorWorkResourceScope,
) -> Result<RemoteIceCredentials> {
    let initial_claim = remote_description_operation_claim(input_capacity).map_err(|error| {
        Error::Transport(format!(
            "remote-description operation claim overflowed: {error}"
        ))
    })?;
    let mut lease = work_resources
        .acquire(
            crate::resource::ResourceAuthorityClass::Speculative,
            initial_claim,
        )
        .map_err(Error::ResourceUnavailable)?;
    let plan = plan_sdp_ice_credential_allocations(sdp)?;
    let planned_claim =
        planned_remote_description_claim(plan, input_capacity).map_err(|error| {
            Error::Transport(format!(
                "remote-description planned claim overflowed: {error}"
            ))
        })?;
    lease
        .transition(planned_claim)
        .map_err(Error::ResourceUnavailable)?;
    let bindings = parse_sdp_ice_credential_bindings_with_plan(sdp, plan)?;
    let retained_claim =
        retained_remote_description_claim(&bindings, bindings.capacity(), input_capacity, true)
            .map_err(|error| {
                Error::Transport(format!(
                    "remote-description retained claim overflowed: {error}"
                ))
            })?;
    lease
        .transition(retained_claim)
        .map_err(Error::ResourceUnavailable)?;
    let post_native_claim =
        retained_remote_description_claim(&bindings, bindings.capacity(), input_capacity, false)
            .map_err(|error| {
                Error::Transport(format!(
                    "remote-description post-native claim overflowed: {error}"
                ))
            })?;
    Ok(RemoteIceCredentials::new(
        bindings,
        Some(RemoteDescriptionResourceOwner::new(
            lease,
            post_native_claim,
        )),
    ))
}

pub struct PeerSession {
    pc: Arc<RTCPeerConnection>,
    data_channel: Arc<SyncMutex<Option<Arc<RTCDataChannel>>>>,
    opaque_data_channels: Arc<SyncMutex<OpaqueNativeLanes>>,
    /// The application's registered codecs, retained past media-engine
    /// construction.
    ///
    /// The API build asks "what do I register"; binding an inbound flow asks
    /// "which framing does this family want". Re-deriving the second from the
    /// first is not possible — the media engine keeps no framing — so the
    /// profile is held rather than consumed.
    ///
    /// Leased and shared: this is the connector's one charged copy, and a
    /// promoted session's flow set holds a pointer to the same record rather
    /// than a deep clone of it.
    realtime_profile: Option<session_flow::LeasedRealtimeProfile>,
    /// The current session's inbound realtime wiring, shared with the
    /// `on_track` callback that reads it when a track arrives.
    realtime_tracks: Arc<RealtimeSessionTracks>,
    /// Retention, not a send path. Every native handler installed on this peer
    /// connection holds its own clone of the sink and reports through that one;
    /// nothing reads this field. It exists so the mailboxes, the callback
    /// producer's reserved lifecycle work, and the close owner outlive the last
    /// native handler rather than the other way round — a dependency callback
    /// that fires while its owner is being torn down must find a live sink to
    /// be refused by, not a freed one.
    _events_tx: ConnectorEventSink,
    /// Arms delivery from the native renegotiation callback. Initial
    /// data-channel negotiation has a separate explicit owner and must never be
    /// mistaken for a post-promotion RTP track-set change.
    media_negotiation_callback: Arc<MediaNegotiationCallback>,
    /// The operation fence is part of the session's close custody.  Raw
    /// sessions do not have a connector worker to retire this fence for them;
    /// retaining it here lets close drain callback admission before the native
    /// peer owner is terminalized.
    operation_fence: Arc<ConnectorOperationFence>,
    callback_gate: Arc<WebRtcConnectorIncarnation>,
    role: Role,
    /// Raw/test peers retain the exact native close owner for their complete
    /// successful lifetime. Production peers are owned by their connector
    /// close owner instead.
    #[cfg(any(test, feature = "transport-lab"))]
    raw_close_owner: Option<Arc<PeerConstructionCloseCustodian>>,
    /// The observation scope this session's pre-authentication measurements are
    /// attributed to. Held rather than read: the accountant is reference
    /// counted, so keeping a clone for exactly the session's lifetime is what
    /// keeps the scope from being torn down while a native callback can still
    /// observe into it.
    _resource_scope: Option<PeerConnectionResourceScope>,
    /// The connector work scope every lease under this session was acquired
    /// from. `ResourceScope` deregisters itself from the provider when its last
    /// clone drops, so this clone is what keeps the scope registered for as
    /// long as the session can still acquire — and what releases it exactly
    /// when the session goes.
    ///
    /// Read as well as held, now that a negotiated inbound transceiver is funded
    /// from it. `None` is the fixture shape — a session stood up without a
    /// connector reservation behind it — and it refuses native realtime
    /// negotiation rather than performing it unfunded.
    work_resource_scope: Option<ConnectorWorkResourceScope>,
}

impl PeerSession {
    fn ensure_media_negotiation_callback(&self) {
        self.media_negotiation_callback
            .armed
            .store(true, Ordering::Release);
    }

    fn retire_media_negotiation_callback(&self) {
        self.media_negotiation_callback
            .armed
            .store(false, Ordering::Release);
    }
}

impl PeerSession {
    pub fn role(&self) -> Role {
        self.role
    }

    /// True once the data channel is established on this side
    /// (open and `on_open` fired).
    pub async fn has_data_channel(&self) -> bool {
        self.data_channel.lock().is_some()
    }

    /// Return the authenticated persistent native lane for an opaque mode.
    ///
    /// The lane is retained by this exact peer session and is never created by
    /// a logical flow open. Partial reliability is intentionally fixed at zero
    /// retransmits; other values are refused by the provider DTO conversion.
    pub(crate) fn opaque_native_lane(
        &self,
        mode: crate::realtime::OpaqueFlowMode,
    ) -> Option<Arc<RTCDataChannel>> {
        let mode = match mode {
            crate::realtime::OpaqueFlowMode::ReliableOrdered => {
                OpaqueNativeLaneMode::ReliableOrdered
            }
            crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits: 0 } => {
                OpaqueNativeLaneMode::PartialUnordered
            }
            crate::realtime::OpaqueFlowMode::PartialUnordered { .. } => return None,
        };
        self.opaque_data_channels
            .lock()
            .get(mode)
            .map(|lane| Arc::clone(&lane.channel))
    }

    /// Read actual native readiness for the fixed persistent lane. Logical
    /// flow readiness is not enough: an Open/Accept may only expose a handle
    /// once the represented channel itself is open.
    pub(crate) fn opaque_native_mode_ready(&self, mode: crate::realtime::OpaqueFlowMode) -> bool {
        self.opaque_native_lane(mode)
            .is_some_and(|channel| channel.ready_state() == RTCDataChannelState::Open)
    }

    /// Write one already-admitted opaque unit to its persistent native lane.
    ///
    /// The unit carries the queue/output lease, so moving it into this future
    /// keeps the provider custody live until the native write resolves. The
    /// frame coordinate and negotiated body ceiling come from the current flow
    /// record; callers cannot supply a replacement coordinate or silently use
    /// the other lane's reliability mode.
    pub(crate) async fn send_opaque_native(&self, unit: OpaqueOutboundUnit) -> Result<usize> {
        let channel = self
            .opaque_native_lane(unit.mode)
            .ok_or_else(|| Error::Transport("opaque native lane unavailable".to_string()))?;
        let frame_bytes = crate::protocol::application_flow::APPLICATION_FLOW_HEADER_BYTES
            .checked_add(unit.data.len())
            .ok_or_else(|| Error::Transport("opaque frame size overflowed".to_string()))?;
        // The body lease belongs to the logical flow. This separate operation
        // lease prices the encoded MOMF Vec (and its owned provider metadata)
        // before `encode_application_flow` allocates it; it remains live until
        // the native send future has completed.
        let frame_claim = RealtimeFlowRegistry::output_claim(frame_bytes)
            .map_err(|error| Error::Transport(format!("opaque frame claim: {error}")))?;
        let Some(work_scope) = self.work_resource_scope.as_ref() else {
            return Err(Error::Transport(
                "opaque frame has no connector work scope to fund".to_string(),
            ));
        };
        let _frame_lease = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                frame_claim,
            )
            .map_err(|error| Error::Transport(format!("opaque frame lease: {error}")))?;
        let wire = crate::protocol::application_flow::encode_application_flow(
            unit.coordinate,
            unit.direction,
            match unit.mode {
                crate::realtime::OpaqueFlowMode::ReliableOrdered => {
                    crate::protocol::application_flow::ApplicationFlowMode::ReliableOrdered
                }
                crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits } => {
                    crate::protocol::application_flow::ApplicationFlowMode::PartialUnordered {
                        max_retransmits,
                    }
                }
            },
            &unit.data,
            unit.max_unit_bytes,
        )
        .map_err(|error| Error::Transport(format!("opaque frame encoding refused: {error}")))?;
        let wire = Bytes::from(wire);
        let sent = channel
            .send(&wire)
            .await
            .map_err(|error| Error::Transport(format!("opaque data-channel send: {error}")))?;
        drop(unit);
        Ok(sent)
    }

    /// Read the native application backlog for idle-retirement planning.
    ///
    /// This observes actual SCTP buffered bytes on the ordinary application
    /// channel and both persistent opaque lanes. Logical flow queues and their
    /// leases are checked separately by the flow-set owner.
    pub(crate) async fn native_application_backlog_empty(&self) -> bool {
        let channels = [
            self.data_channel.lock().clone(),
            self.opaque_native_lane(crate::realtime::OpaqueFlowMode::ReliableOrdered),
            self.opaque_native_lane(crate::realtime::OpaqueFlowMode::PartialUnordered {
                max_retransmits: 0,
            }),
        ];
        for channel in channels.into_iter().flatten() {
            if channel.buffered_amount().await != 0 {
                return false;
            }
        }
        true
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
    /// `local_fingerprint`. The auth handshake folds this value — together
    /// with [`Self::remote_fingerprint`], so the transcript commits to the
    /// pair rather than to the signer alone — into the signed Arc 04
    /// endpoint-auth transcript (see [`crate::endpoint_auth`]), so a
    /// signaling-path man-in-the-middle — which must present its own
    /// certificate on each leg it terminates — is detected: the victim's
    /// observed remote fingerprint no longer matches the one the real peer
    /// signed. `None` before the local description is set.
    ///
    /// A fingerprint identifies the certificate, not the session, so this is
    /// not a session-unique exporter and does not separate two channels that
    /// reuse the same certificates; per-attempt contributions and
    /// connector-incarnation ownership carry that.
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
        let dc = self
            .data_channel
            .lock()
            .clone()
            .ok_or_else(|| Error::Transport("data channel not open".into()))?;
        dc.send(&payload)
            .await
            .map_err(|e| Error::Transport(format!("data channel send: {e}")))
    }

    /// The peer connection's signaling state. The media-renegotiation
    /// pass gates its in-place offers on `Stable` so it never stacks
    /// an offer onto a negotiation that's still settling (glare).
    pub fn signaling_state(&self) -> RTCSignalingState {
        self.pc.signaling_state()
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
        self.retire_media_negotiation_callback();
        self.operation_fence.begin_close();
        self.callback_gate.retire();
        self.operation_fence.wait_for_operations().await;
        self.realtime_tracks.prepare_for_close();
        self.realtime_tracks.seal_for_close();
        #[cfg(any(test, feature = "transport-lab"))]
        if let Some(owner) = self.raw_close_owner.as_ref() {
            owner.start();
            let result = owner.wait().await;
            self.realtime_tracks.wait_for_tasks().await;
            return result;
        }
        let result = self
            .pc
            .close()
            .await
            .map_err(|e| Error::Transport(format!("close: {e}")));
        self.realtime_tracks.wait_for_tasks().await;
        result.map(|_| ())
    }
}

/// The real-time work one lab fixture intends to fund, stated by the fixture.
///
/// These numbers used to be read off the owner's real-time ceilings, which is
/// how a fixture could stay silent about what it was going to do and still get
/// a grant. There are no ceilings to read now, so a fixture that wants a
/// real-time envelope says how much of it: nothing is derived from a policy and
/// nothing is defaulted, because a grant core picked would be a ceiling core
/// picked, one indirection later.
#[cfg(any(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug)]
pub struct TransportLabRealtimeWorkload {
    pub inbound_flows: usize,
    pub outbound_flows: usize,
    pub queued_units_per_flow: usize,
    pub in_progress_units_per_inbound_flow: usize,
    pub fragments_per_unit: usize,
    pub max_fragment_bytes: usize,
    pub max_unit_bytes: usize,
}

#[cfg(any(test, feature = "transport-lab"))]
fn realtime_fixture_provider_grant(
    workload: TransportLabRealtimeWorkload,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::FiniteResourceProvider;

    fn add_lease(
        total: &mut crate::resource::ResourceClaim,
        claim: crate::resource::ResourceClaim,
    ) -> Result<()> {
        *total = total
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(claim).map_err(Error::from)?,
            )
            .map_err(|error| {
                Error::Transport(format!("fixture real-time claim overflowed: {error}"))
            })?;
        Ok(())
    }

    let inbound_flows = workload.inbound_flows;
    let outbound_flows = workload.outbound_flows;
    let total_flows = inbound_flows
        .checked_add(outbound_flows)
        .ok_or_else(|| Error::Transport("fixture flow total overflowed".to_string()))?;
    let queue_slots = total_flows
        .checked_mul(workload.queued_units_per_flow)
        .ok_or_else(|| Error::Transport("fixture queue-slot total overflowed".to_string()))?;
    let inbound_units = inbound_flows
        .checked_mul(workload.in_progress_units_per_inbound_flow)
        .ok_or_else(|| Error::Transport("fixture assembly total overflowed".to_string()))?;
    let fragments = inbound_units
        .checked_mul(workload.fragments_per_unit)
        .ok_or_else(|| Error::Transport("fixture fragment total overflowed".to_string()))?;

    let mut grant = crate::resource::ResourceClaim::ZERO;
    for _ in 0..total_flows {
        add_lease(&mut grant, RealtimeFlowRegistry::flow_claim()?)?;
        add_lease(&mut grant, RealtimeFlowRegistry::flow_map_node_claim()?)?;
        add_lease(&mut grant, RealtimeFlowRegistry::ready_claim()?)?;
        // One label per flow, sized by the longest name the frame can carry.
        // The fixture cannot know what an application will call its flows, and
        // a grant derived from a shorter guess would refuse opens the policy
        // itself admits.
        add_lease(
            &mut grant,
            session_flow::RealtimeFlowLabel::mint_claim(
                crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES,
            )?,
        )?;
    }
    for _ in 0..inbound_flows {
        add_lease(&mut grant, RealtimeFlowRegistry::native_read_claim()?)?;
    }
    for _ in 0..inbound_units {
        add_lease(&mut grant, RealtimeFlowRegistry::assembly_claim()?)?;
    }
    for _ in 0..fragments {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::ordered_fragment_claim(workload.max_fragment_bytes)?,
        )?;
    }
    for _ in 0..queue_slots {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::output_claim(workload.max_unit_bytes)?,
        )?;
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::queue_claim(workload.max_unit_bytes)?,
        )?;
        add_lease(&mut grant, RealtimeFlowRegistry::queued_event_node_claim()?)?;
    }
    // One packet-work lease per inbound pump, because each holds exactly one
    // for the duration of the packet it is classifying and releases it before
    // reading the next.
    //
    // Sized by the largest payload either inbound shape can present: a
    // fragmented unit is bounded per fragment, a whole-payload unit by the unit
    // ceiling, and the pump takes this lease before it knows which shape it
    // holds. Taking the larger of the two is what keeps the lab grant from
    // refusing work the policy actually admits.
    let max_packet_bytes = workload.max_fragment_bytes.max(workload.max_unit_bytes);
    for _ in 0..inbound_flows {
        add_lease(
            &mut grant,
            RealtimeFlowRegistry::session_packet_work_claim(max_packet_bytes)?,
        )?;
    }
    Ok(grant)
}

/// The callback work one lab fixture intends to fund, stated by the fixture.
///
/// The per-class payload ceilings used to be read off the profile's mailbox
/// capacities, and a profile that declared mailboxes without stating what they
/// could carry was refused here. Neither the capacities nor the ceilings exist
/// any more, so the fixture states its own two numbers — the largest payload it
/// will fund per class — and this function derives nothing.
///
/// The two are stated separately on purpose. One number shared by both classes
/// funds each at `max(control, endpoint)`, so the generously-sized class pays
/// for the other; and a limit borrowed from another layer — a signaling or
/// endpoint frame maximum standing in for an ICE candidate's bytes — is how the
/// original underfunding stayed invisible until every gathered candidate was
/// refused for want of `QueuedBytes`.
#[cfg(any(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug)]
pub struct TransportLabCallbackWorkload {
    pub control_slots: std::num::NonZeroUsize,
    pub endpoint_slots: std::num::NonZeroUsize,
    pub control_payload_bytes: u64,
    pub endpoint_payload_bytes: u64,
    /// The real-time envelope this fixture funds, if it opens any flows.
    pub realtime: Option<TransportLabRealtimeWorkload>,
}

/// Derive a finite resource grant for an explicit transport-lab fixture.
///
/// The caller supplies the exact connector profiles, the concurrent Mesh scope
/// count, and the callback and real-time work each connector will actually do.
/// This function selects no production value and is unavailable without the
/// `transport-lab` feature.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_connector_fixture_grant(
    profiles: &[WebRtcConnectorProfile],
    mesh_scope_count: std::num::NonZeroU64,
    workload: TransportLabCallbackWorkload,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::FiniteResourceProvider;

    fn add(
        total: &mut crate::resource::ResourceClaim,
        claim: crate::resource::ResourceClaim,
        context: &'static str,
    ) -> Result<()> {
        *total = total.checked_add(claim).map_err(|error| {
            Error::Transport(format!(
                "fixture resource claim overflowed while adding {context}: {error}"
            ))
        })?;
        Ok(())
    }

    let structural = crate::runtime::attempt::connector_resource_structural_claims();
    let mut grant = FiniteResourceProvider::scope_record_charge_for_test();
    add(
        &mut grant,
        FiniteResourceProvider::reservation_charge_for_test(structural.process_infrastructure())
            .map_err(Error::from)?,
        "process cleanup infrastructure",
    )?;
    for _ in 0..mesh_scope_count.get() {
        add(
            &mut grant,
            FiniteResourceProvider::scope_record_charge_for_test(),
            "Mesh resource scope",
        )?;
    }

    for profile in profiles {
        add(
            &mut grant,
            FiniteResourceProvider::child_scope_with_reservation_charge_for_test(
                structural.connector_opening(),
            )
            .map_err(Error::from)?,
            "connector opening scope and reservation",
        )?;
        add(
            &mut grant,
            FiniteResourceProvider::reservation_charge_for_test(structural.connector_operation())
                .map_err(Error::from)?,
            "one fixture connector operation",
        )?;
        for callback_claim in callback::connector_construction_claims().map_err(|error| {
            Error::Transport(format!("fixture callback claim overflowed: {error}"))
        })? {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(callback_claim)
                    .map_err(Error::from)?,
                "connector callback construction",
            )?;
        }

        for callback_claim in callback::connector_fixture_operation_claims(
            Some((workload.control_slots, workload.endpoint_slots)),
            0,
            workload.control_payload_bytes,
            workload.endpoint_payload_bytes,
        )
        .map_err(|error| {
            Error::Transport(format!(
                "fixture callback operation claim overflowed: {error}"
            ))
        })? {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(callback_claim)
                    .map_err(Error::from)?,
                "connector callback operation",
            )?;
        }

        if let (RealtimeConnectorPolicy::Enabled, Some(realtime)) =
            (profile.callbacks().realtime(), workload.realtime)
        {
            add(
                &mut grant,
                realtime_fixture_provider_grant(realtime)?,
                "connector real-time fixture envelope",
            )?;
        }

        // The connector's one shared, leased copy of the application's codecs.
        // Charged per profile that registers any, and only once each: a
        // promotion clones the pointer rather than the codecs.
        if let Some(realtime) = profile.realtime() {
            add(
                &mut grant,
                FiniteResourceProvider::reservation_charge_for_test(
                    session_flow::LeasedRealtimeProfile::mint_claim(realtime)
                        .map_err(Error::from)?,
                )
                .map_err(Error::from)?,
                "connector real-time profile record",
            )?;
        }
    }
    Ok(grant)
}

/// Derive a conservative finite grant for an explicit remote-candidate fixture.
///
/// Every bound comes from the caller's test workload. The result covers the
/// connector-neutral digest owner, production queue owner, parsing work, and
/// each provider reservation record. It selects no production value.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_remote_candidate_fixture_grant(
    max_unique_candidates: std::num::NonZeroU64,
    max_concurrent_digest_work: std::num::NonZeroU64,
    max_total_string_capacity: std::num::NonZeroU64,
    max_total_content_bytes: std::num::NonZeroU64,
    max_single_candidate_content_bytes: std::num::NonZeroU64,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::{FiniteResourceProvider, ResourceClaim, ResourceClass};

    let unique = max_unique_candidates.get();
    let digest_retention =
        crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(unique)
            .and_then(|claim| {
                claim.checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    unique,
                ))
            })
            .map_err(|error| {
                Error::Transport(format!(
                    "fixture candidate digest retention overflowed: {error}"
                ))
            })?;
    let digest_work = FiniteResourceProvider::reservation_charge_for_test(
        crate::runtime::attempt::remote_candidate_max_digest_work_claim(
            max_single_candidate_content_bytes.get(),
        )
        .map_err(|error| {
            Error::Transport(format!("fixture candidate digest work overflowed: {error}"))
        })?,
    )
    .map_err(Error::from)?
    .checked_scale(max_concurrent_digest_work.get())
    .map_err(|error| {
        Error::Transport(format!(
            "fixture concurrent candidate digest work overflowed: {error}"
        ))
    })?;
    let queue = pending_remote_candidate_queue_claim_with_content(0, 0)
        .and_then(|claim| claim.checked_scale(unique))
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::AccountedMemoryBytes,
                max_total_string_capacity.get(),
            ))
        })
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::QueuedBytes,
                max_total_content_bytes.get(),
            ))
        })
        .and_then(|claim| {
            claim.checked_add(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                unique,
            ))
        })
        .map_err(|error| {
            Error::Transport(format!("fixture candidate queue claim overflowed: {error}"))
        })?;
    digest_retention
        .checked_add(digest_work)
        .and_then(|claim| claim.checked_add(queue))
        .map_err(|error| Error::Transport(format!("fixture candidate grant overflowed: {error}")))
}

/// Derive a conservative finite grant for explicit remote-SDP fixture shapes.
///
/// The caller supplies the maximum raw input, media-section, active-binding,
/// and retained credential-string shape for each concurrent connector. This
/// helper is unavailable from the default V4 API and selects no production
/// value.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_remote_description_fixture_grant(
    concurrent_connectors: std::num::NonZeroU64,
    max_input_capacity: std::num::NonZeroU64,
    max_media_sections: std::num::NonZeroU64,
    max_active_bindings: std::num::NonZeroU64,
    max_retained_credential_string_bytes: std::num::NonZeroU64,
) -> Result<crate::resource::ResourceClaim> {
    use crate::resource::{FiniteResourceProvider, ResourceClaim, ResourceClass};

    let input_capacity = usize::try_from(max_input_capacity.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP input capacity does not fit usize".to_string())
    })?;
    let media_count = usize::try_from(max_media_sections.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP media count does not fit usize".to_string())
    })?;
    let binding_count = usize::try_from(max_active_bindings.get()).map_err(|_| {
        Error::Transport("fixture remote-SDP binding count does not fit usize".to_string())
    })?;
    if binding_count > media_count {
        return Err(Error::Transport(
            "fixture active remote-SDP bindings exceed its media sections".to_string(),
        ));
    }
    let string_bytes =
        usize::try_from(max_retained_credential_string_bytes.get()).map_err(|_| {
            Error::Transport(
                "fixture remote-SDP credential string size does not fit usize".to_string(),
            )
        })?;
    let plan = RemoteIceCredentialAllocationPlan {
        media_count,
        binding_count,
        string_bytes,
    };
    let claims = [
        remote_description_operation_claim(input_capacity),
        planned_remote_description_claim(plan, input_capacity),
        retained_remote_description_claim_from_plan(plan, input_capacity, true),
        retained_remote_description_claim_from_plan(plan, input_capacity, false),
    ];
    let mut peak = ResourceClaim::ZERO;
    for claim in claims {
        let claim = claim.map_err(|error| {
            Error::Transport(format!("fixture remote-SDP claim overflowed: {error}"))
        })?;
        peak = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|dimension| {
            (
                dimension,
                peak.amount(dimension).max(claim.amount(dimension)),
            )
        }))
        .map_err(|error| {
            Error::Transport(format!("fixture remote-SDP peak overflowed: {error}"))
        })?;
    }
    FiniteResourceProvider::reservation_charge_for_test(peak)
        .map_err(Error::from)?
        .checked_scale(concurrent_connectors.get())
        .map_err(|error| Error::Transport(format!("fixture remote-SDP grant overflowed: {error}")))
}

#[cfg(test)]
pub(crate) fn one_mesh_connector_fixture_grant(
    profiles: &[WebRtcConnectorProfile],
    workload: TransportLabCallbackWorkload,
) -> Result<crate::resource::ResourceClaim> {
    transport_lab_connector_fixture_grant(
        profiles,
        std::num::NonZeroU64::new(1).expect("one Mesh fixture scope is nonzero"),
        workload,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ProcessResourceRoot, ResourceFamilyReport, ResourceProviderPort,
        PRE_AUTH_RESOURCE_FAMILY_COUNT,
    };
    use crate::runtime::attempt::ConnectorResourceOwnerPort;
    use std::future::Future;
    use std::sync::atomic::AtomicUsize;
    use std::task::{Context, Poll, Waker};

    // Explicit fixture input shared by the native loopback controls. It is
    // not a production default or an operational sufficiency claim.
    const NATIVE_LOOPBACK_CALLBACK_CAPACITY: usize = 32;

    // The largest single payload the fixtures below will fund, per class.
    // Explicit because the raw transport-lab path mints its own finite provider
    // from the policy and has nothing else to derive a byte grant from, and
    // separate per class so neither pays for the other. Both are fixture
    // numbers and state no product limit.
    //
    // Control covers one gathered ICE candidate's JSON — an SDP candidate line
    // plus its `sdpMid`, `sdpMLineIndex` and ufrag envelope. Endpoint covers the
    // small application payloads these controls send.
    const FIXTURE_CONTROL_PAYLOAD_CEILING: usize = 4_096;
    const FIXTURE_ENDPOINT_PAYLOAD_CEILING: usize = 4_096;

    /// The callback grant for a fixture whose connector funds itself.
    ///
    /// Every fixture that reaches `CallbackProducerOwner::for_local_lab_grant`
    /// goes through here, so no fixture can silently rely on one class's byte
    /// grant paying for another's. Fixtures that install a real connector
    /// resource scope need none of this: they draw on a provider they did not
    /// mint, and state nothing.
    fn lab_callback_grant(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
    ) -> callback::TransportLabCallbackGrant {
        lab_callback_grant_exact(
            control,
            endpoint_data,
            FIXTURE_CONTROL_PAYLOAD_CEILING,
            FIXTURE_ENDPOINT_PAYLOAD_CEILING,
            lab_observation_slots(),
        )
    }

    /// Every lifecycle delivery the general fixtures can produce: the reserved
    /// open and close, plus renegotiation, ICE state and peer-connection state.
    fn lab_observation_slots() -> NonZeroUsize {
        NonZeroUsize::new(5).expect("the fixture lifecycle slot count is nonzero")
    }

    /// The same grant, with every number the control cares about stated by the
    /// control.
    ///
    /// A control that asserts the *next* insert is refused cannot use the
    /// general grant above. That one funds each class at a 4 KiB payload ceiling
    /// and five lifecycle deliveries at a payload of zero, and a fixture reserves
    /// only two of those five. What is left over is real capacity in exactly the
    /// two dimensions an insert spends — spare `QueuedBytes` under the class
    /// ceiling, and spare count from the unreserved lifecycle slots — sitting in
    /// the same pool the insert draws from. So the insert that was supposed to
    /// be refused is admitted out of capacity nothing declared and nothing
    /// consumes, and the control passes while proving the opposite of its name.
    ///
    /// Callers here state the exact payload each class will queue and the exact
    /// number of lifecycle deliveries they will reserve, so the pool is empty at
    /// the moment the refusal is asserted.
    fn lab_callback_grant_exact(
        control: NonZeroUsize,
        endpoint_data: NonZeroUsize,
        control_payload_bytes: usize,
        endpoint_payload_bytes: usize,
        observation_slots: NonZeroUsize,
    ) -> callback::TransportLabCallbackGrant {
        callback::TransportLabCallbackGrant {
            control_slots: control,
            endpoint_slots: endpoint_data,
            control_payload_bytes: NonZeroUsize::new(control_payload_bytes)
                .expect("the fixture control payload size is nonzero"),
            endpoint_payload_bytes: NonZeroUsize::new(endpoint_payload_bytes)
                .expect("the fixture endpoint payload size is nonzero"),
            observation_slots,
        }
    }

    /// The same numbers as [`lab_callback_grant`], for the fixture-grant helper.
    fn lab_callback_workload(capacity: NonZeroUsize) -> TransportLabCallbackWorkload {
        let grant = lab_callback_grant(capacity, capacity);
        TransportLabCallbackWorkload {
            control_slots: grant.control_slots,
            endpoint_slots: grant.endpoint_slots,
            control_payload_bytes: u64::try_from(grant.control_payload_bytes.get())
                .expect("the fixture control payload ceiling fits u64"),
            endpoint_payload_bytes: u64::try_from(grant.endpoint_payload_bytes.get())
                .expect("the fixture endpoint payload ceiling fits u64"),
            realtime: None,
        }
    }

    fn test_resource_owner(
        max_active_candidates: usize,
        callback_capacity: usize,
    ) -> MeshConnectorResourceScope {
        test_resource_owner_with_additional(
            max_active_candidates,
            callback_capacity,
            crate::resource::ResourceClaim::ZERO,
        )
    }

    fn test_resource_owner_with_provider(
        max_active_candidates: usize,
        callback_capacity: usize,
        additional: crate::resource::ResourceClaim,
    ) -> (FiniteResourceProvider, MeshConnectorResourceScope) {
        let max_active_candidates = std::num::NonZeroUsize::new(max_active_candidates)
            .expect("fixture has a nonzero candidate bound");
        let profiles = vec![test_webrtc_profile(callback_capacity); max_active_candidates.get()];
        let connector_grant = transport_lab_connector_fixture_grant(
            &profiles,
            std::num::NonZeroU64::new(1).expect("the fixture Mesh scope count is nonzero"),
            lab_callback_workload(
                NonZeroUsize::new(callback_capacity).expect("fixture callback capacity is nonzero"),
            ),
        )
        .expect("fixture connector and callback claims are representable")
        .checked_add(additional)
        .expect("fixture connector additional claim is representable");
        let provider = FiniteResourceProvider::new(connector_grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("fixture provider accounts for its process scope");
        let owner = ConnectorResourceOwnerPort::new(port)
            .issue_mesh_scope()
            .expect("fixture process owner issues one explicit Mesh scope");
        (provider, owner)
    }

    fn test_resource_owner_with_additional(
        max_active_candidates: usize,
        callback_capacity: usize,
        additional: crate::resource::ResourceClaim,
    ) -> MeshConnectorResourceScope {
        test_resource_owner_with_provider(max_active_candidates, callback_capacity, additional).1
    }

    fn test_webrtc_profile(_callback_capacity: usize) -> WebRtcConnectorProfile {
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only())
    }

    fn test_generic_realtime_webrtc_profile(_callback_capacity: usize) -> WebRtcConnectorProfile {
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_realtime())
    }

    fn close_owner_fixture(
        owner: &MeshConnectorResourceScope,
    ) -> (Arc<ConnectorCloseOwner>, AttemptLifetime) {
        close_owner_fixture_with_observation(owner, None)
    }

    /// A close-owner fixture with an optional real transport observation.
    ///
    /// Production installs this observation before the native connector is
    /// admitted and keeps it on the close owner until native close succeeds.
    /// The transport terminal controls use an isolated observation scope so
    /// they can inspect that exact family without depending on process-global
    /// accounting from other tests.
    fn close_owner_fixture_with_observation(
        owner: &MeshConnectorResourceScope,
        observation_scope: Option<&PeerConnectionResourceScope>,
    ) -> (Arc<ConnectorCloseOwner>, AttemptLifetime) {
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let mut candidate = permit
            .reserve_connector_candidate(claim)
            .expect("fixture owner admits one candidate");
        candidate = candidate
            .prepare_late_transport_custodian()
            .expect("fixture candidate reserves late terminal custodian");
        let cleanup_capability = candidate
            .issue_cleanup_capability()
            .expect("fixture candidate issues one cleanup capability");
        let late_transport_lease = candidate.take_late_transport_lease();
        let late_transport_custodian = LateTransportCustodian::new(late_transport_lease)
            .expect("fixture late terminal custodian starts");
        let ownership = admitted_ownership(candidate);
        let transport_observation = observation_scope
            .map(|scope| observe_inexact_item(scope, PreAuthResourceFamily::TransportObject, 1, 0));
        (
            ConnectorCloseOwner::new(
                ownership,
                owner.clone(),
                cleanup_capability,
                transport_observation,
                late_transport_custodian,
            ),
            lifetime,
        )
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

    /// A native-close hold point for controls, built on stored state.
    ///
    /// `Notify` is the wrong primitive for this seam. `TestNativeClosePort`
    /// records its call *synchronously*, before the future it returns is ever
    /// polled, so the call counter goes up while the close is still short of the
    /// hold point. A control that keys off that counter can therefore release in
    /// the window between "call recorded" and "close actually parked", and
    /// `notify_waiters` stores nothing: a release landing in that window is
    /// dropped and the control waits forever instead of failing.
    ///
    /// Both halves here are `watch` channels, which carry their value rather
    /// than only waking whoever is already parked. A release published before
    /// the close parks is still observed, and an entry published before the
    /// control looks is still counted, so no scheduling order can lose either
    /// signal. This mirrors the production-side `NativeCloseGate` for the same
    /// reason.
    struct TestNativeCloseGate {
        /// How many closes have reached the hold point. A `watch` rather than a
        /// bare counter so a control can await the first entry deterministically
        /// instead of spinning on a load.
        entries: watch::Sender<usize>,
        /// The stored permit. Held closes proceed once this is `true`.
        open: watch::Sender<bool>,
    }

    impl TestNativeCloseGate {
        fn new() -> Arc<Self> {
            let (entries, _entries_receiver) = watch::channel(0usize);
            let (open, _open_receiver) = watch::channel(false);
            Arc::new(Self { entries, open })
        }

        /// Record this entry, then park until a control opens the gate.
        ///
        /// The subscription is taken *before* the entry is published, so a
        /// control that observes the entry is observing a close that is already
        /// able to see the release. The permit is stored regardless, so the
        /// ordering here is belt and braces rather than the correctness
        /// argument.
        async fn hold(&self) {
            let mut open = self.open.subscribe();
            self.entries.send_modify(|count| *count += 1);
            loop {
                // The borrow is released before the await: holding a `watch`
                // guard across a suspension point would block every sender.
                if *open.borrow() {
                    return;
                }
                if open.changed().await.is_err() {
                    return;
                }
            }
        }

        /// How many closes have reached the hold point.
        fn entries(&self) -> usize {
            *self.entries.borrow()
        }

        /// Park until at least one close has reached the hold point.
        ///
        /// Resolves on the entry itself rather than by polling a counter.
        /// Callers bound it with a deadline so a close that never arrives fails
        /// the control rather than hanging it.
        async fn wait_for_entry(&self) {
            let mut entries = self.entries.subscribe();
            loop {
                if *entries.borrow() > 0 {
                    return;
                }
                if entries.changed().await.is_err() {
                    return;
                }
            }
        }

        /// Let every held close proceed. Idempotent, and the permit is stored,
        /// so this can never be published too early to be observed.
        fn open(&self) {
            self.open.send_replace(true);
        }
    }

    enum TestNativeCloseResult {
        Success,
        Error,
        Gate(Arc<TestNativeCloseGate>),
    }

    struct TestNativeClosePort {
        result: TestNativeCloseResult,
        calls: Arc<AtomicUsize>,
    }

    impl NativeConnectorClosePort for TestNativeClosePort {
        fn close(&self) -> NativeCloseFuture<'_> {
            self.calls.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                match &self.result {
                    TestNativeCloseResult::Success => Ok(()),
                    TestNativeCloseResult::Error => Err(Error::Transport(
                        "injected native close failure".to_string(),
                    )),
                    TestNativeCloseResult::Gate(gate) => {
                        gate.hold().await;
                        Ok(())
                    }
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

    fn transport_object_report(
        scope: &PeerConnectionResourceScope,
    ) -> ResourceFamilyReport<PreAuthResourceFamily> {
        *scope
            .report()
            .pre_authentication
            .iter()
            .find(|report| report.family == PreAuthResourceFamily::TransportObject)
            .expect("transport-object family is present")
    }

    fn transport_observation_scope() -> PeerConnectionResourceScope {
        ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope()
    }

    fn observed_candidate() -> LocalIceCandidate {
        let candidate_fixture = "candidate:foundation 1 udp 2113937151 192.0.2.1 5000 typ host";
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

    fn exact_ice_sdp(username_fragment: &str, password: &str, fingerprint: &str) -> String {
        format!(
            "v=0\r\n\
             o=- 1 2 IN IP4 127.0.0.1\r\n\
             a=group:BUNDLE data\r\n\
             a=ice-ufrag:{username_fragment}\r\n\
             a=ice-pwd:{password}\r\n\
             a=fingerprint:sha-256 {fingerprint}\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n"
        )
    }

    fn test_candidate_fixture_work() -> RemoteCandidateFixtureWork {
        test_candidate_fixture_work_for(&[])
    }

    fn test_candidate_fixture_work_for(
        additional_inputs: &[LocalIceCandidate],
    ) -> RemoteCandidateFixtureWork {
        let candidate_bytes = std::iter::once(observed_candidate())
            .chain(additional_inputs.iter().cloned())
            .filter_map(|candidate| candidate_content_bytes(&candidate))
            .max()
            .expect("fixture candidate has nonzero representable content");
        RemoteCandidateFixtureWork::new(1, candidate_bytes)
    }

    fn test_remote_candidate_state() -> RemoteCandidateState {
        RemoteCandidateState::new(test_candidate_fixture_work())
    }

    /// Build a finite test provider from the local fixture envelope. This is
    /// test accounting only. It is not a product cardinality or a production
    /// policy value.
    fn test_realtime_resource_scope(
        workload: TransportLabRealtimeWorkload,
    ) -> ConnectorWorkResourceScope {
        // One control profile per fixture registry, charged here rather than in
        // the shared envelope helper: the envelope describes flows, and which
        // profile a fixture registers is this module's fact.
        let profile_claim = FiniteResourceProvider::reservation_charge_for_test(
            session_flow::LeasedRealtimeProfile::mint_claim(
                &session_flow::control_realtime_profile(),
            )
            .expect("the control profile claim is representable"),
        )
        .expect("the control profile reservation is representable");
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_add(
                realtime_fixture_provider_grant(workload)
                    .expect("fixture real-time envelope is representable"),
            )
            .and_then(|grant| grant.checked_add(profile_claim))
            .expect("fixture provider grant is representable");

        let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the derived fixture grant accounts for its process scope");
        let mesh = ConnectorResourceOwnerPort::new(provider)
            .issue_mesh_scope()
            .expect("the derived fixture grant accounts for its Mesh scope");
        let (permit, _attempt, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("the derived fixture grant admits its connector candidate");
        candidate.work_resource_scope()
    }

    /// A real connector work scope granted exactly `transceivers` negotiated
    /// inbound transceivers and `slots` retirement queue slots, and nothing
    /// else.
    ///
    /// The two are counted separately rather than paired because the controls
    /// use them separately, and a control that was handed headroom it does not
    /// consume cannot state a refusal: spare slot capacity would satisfy a
    /// transceiver acquisition that was supposed to be refused.
    ///
    /// **Exact rather than generous, because the observable is the provider.**
    /// These controls state what the native retirement path charges and what it
    /// gives back, and both readings come from asking this provider what is
    /// still held. A grant with headroom would let "released" and "retained
    /// after a failed cleanup" look the same from outside.
    ///
    /// The candidate and its lifetime come back with the scope because both must
    /// outlive it: dropping the candidate would release the reservation the work
    /// scope draws from, and the control would then be measuring a torn-down
    /// connector rather than a live one.
    fn realtime_native_test_scope(
        transceivers: u64,
        slots: u64,
        identities: u64,
    ) -> (
        FiniteResourceProvider,
        ConnectorResourceOwnerPort,
        crate::runtime::attempt::MeshConnectorResourceScope,
        ConnectorCandidateCapability,
        AttemptLifetime,
        ConnectorWorkResourceScope,
    ) {
        // One recorded transceiver is three independent reservations — its queue
        // node, its completion cell, and its native half — and each is charged
        // on its own, because a reservation is the unit the provider bills.
        // Adding the three claims first and charging the sum once looks
        // equivalent and is not: it funds one bookkeeping record where three are
        // taken, and the grant is then short by two records that no claim here
        // names. Granting their sum would also let a control pass while any two
        // of the three were confused for each other, which is the other defect
        // these grants are derived to catch.
        let per_transceiver = [
            negotiated_inbound_record_claim().expect("the fixture record claim is representable"),
            RealtimeRetirementSignal::mint_claim()
                .expect("the fixture completion claim is representable"),
            negotiated_inbound_transceiver_claim()
                .expect("the fixture transceiver claim is representable"),
        ]
        .into_iter()
        .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
            total.checked_add(
                FiniteResourceProvider::reservation_charge_for_test(claim)
                    .expect("the fixture transceiver reservation charge is representable"),
            )
        })
        .expect("the fixture per-transceiver grant is representable");
        let per_slot = FiniteResourceProvider::reservation_charge_for_test(
            crate::runtime::attempt::cleanup_job_claim()
                .expect("the fixture retirement-slot claim is representable"),
        )
        .expect("the fixture retirement-slot reservation charge is representable");
        let per_identity = FiniteResourceProvider::reservation_charge_for_test(
            RealtimeTrackIdentity::mint_claim().expect("the identity claim is representable"),
        )
        .expect("the fixture identity reservation charge is representable");
        let native_work = (0..transceivers)
            .map(|_| per_transceiver)
            .chain((0..slots).map(|_| per_slot))
            .chain((0..identities).map(|_| per_identity))
            .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
                total.checked_add(claim)
            })
            .expect("the fixture native-work grant is representable");
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_add(native_work)
            .expect("the fixture provider grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant accounts for its process scope");
        let owner = ConnectorResourceOwnerPort::new(port);
        let mesh = owner
            .issue_mesh_scope()
            .expect("the fixture grant accounts for its Mesh scope");
        let (permit, lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh.clone());
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("the fixture grant admits its connector candidate");
        let work_scope = candidate.work_resource_scope();
        (provider, owner, mesh, candidate, lifetime, work_scope)
    }

    /// How many cleanup jobs this process owner has ever been handed, in any
    /// state.
    ///
    /// The sum, rather than one counter, because a submitted job moves queued →
    /// active → completed and a refused one lands in failed, so no single
    /// counter can be read at an arbitrary moment and mean "was it submitted".
    ///
    /// **Not an immediate monotone reading, and a control must not treat it as
    /// one.** The four counters are separate atomics moved at separate moments
    /// by the executor's own thread, so the sum has two windows where it is
    /// momentarily wrong in both directions: the dequeue decrements `queued`
    /// before the task it spawns increments `active`, which reads one *short*,
    /// and a finishing task increments `completed` before it decrements
    /// `active`, which reads one *long*. Both are handoffs rather than states,
    /// and neither is observable once the executor has settled — no counter
    /// moves again unless something else is submitted.
    ///
    /// So a control asserting "the drop submitted exactly one" waits for the
    /// executor to settle — nothing queued, nothing active — and reads this
    /// then, where it is exact and stable. Reading it immediately after the
    /// drop is what made this control fail intermittently rather than a fact
    /// about the submission, which is synchronous and has already happened by
    /// the time the destructor returns.
    fn submitted_cleanup_jobs(owner: &ConnectorResourceOwnerPort) -> u64 {
        let cleanup = owner.report().cleanup;
        let live = u64::try_from(cleanup.queued_jobs)
            .and_then(|queued| Ok(queued + u64::try_from(cleanup.active_jobs)?))
            .expect("fixture job counts fit u64");
        live + cleanup.completed_jobs + cleanup.failed_jobs
    }

    /// A negotiated transceiver whose stop answers on demand. **Controls only.**
    ///
    /// The one thing a real `RTCRtpTransceiver` cannot be asked to do is refuse
    /// to stop, and a refused stop is precisely the case the claim retention
    /// exists for. Everything else about it is deliberately inert.
    ///
    /// `matches_native` answers `false` unconditionally, and that is a safety
    /// property rather than a stub: a fixture record must never be able to claim
    /// a track that arrived on a transceiver this side really created. The twin
    /// can therefore be recorded in a live table without becoming reachable from
    /// `on_track` at all.
    struct TestRealtimeTransceiverPort {
        stops: Arc<AtomicUsize>,
        refuse: bool,
    }

    impl NativeRealtimeTransceiverPort for TestRealtimeTransceiverPort {
        fn stop(&self) -> NativeTransceiverStopFuture<'_> {
            self.stops.fetch_add(1, Ordering::AcqRel);
            Box::pin(async move {
                if self.refuse {
                    return Err(Error::Transport(
                        "injected inbound realtime transceiver stop failure".to_string(),
                    ));
                }
                Ok(())
            })
        }

        fn matches_native(&self, _transceiver: &Arc<RTCRtpTransceiver>) -> bool {
            false
        }
    }

    /// Record one transceiver twin against `tracks`, funded exactly as
    /// production funds one.
    ///
    /// Returns the token it was recorded under and the counter its stop
    /// increments, so a control can say both "the stop ran" and "the stop ran
    /// once".
    fn record_test_transceiver(
        tracks: &Arc<RealtimeSessionTracks>,
        scope: &ConnectorWorkResourceScope,
        refuse: bool,
    ) -> (Arc<RealtimeTrackIdentity>, Arc<AtomicUsize>) {
        // Acquired separately, exactly as production acquires them, so a control
        // can watch one come back while the others do not.
        let record = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                negotiated_inbound_record_claim().expect("the record claim is representable"),
            )
            .expect("the fixture grant funds this record's node");
        let signal = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                RealtimeRetirementSignal::mint_claim()
                    .expect("the completion claim is representable"),
            )
            .expect("the fixture grant funds this record's completion cell");
        let native = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                negotiated_inbound_transceiver_claim()
                    .expect("the transceiver claim is representable"),
            )
            .expect("the fixture grant funds this transceiver");
        let identity = RealtimeTrackIdentity::mint_for_test(scope);
        let stops = Arc::new(AtomicUsize::new(0));
        tracks.record(
            Arc::clone(&identity),
            Arc::new(TestRealtimeTransceiverPort {
                stops: Arc::clone(&stops),
                refuse,
            }),
            record,
            signal,
            native,
        );
        (identity, stops)
    }

    /// One retirement minted the way production mints one, against a real work
    /// scope.
    ///
    /// Not a shortcut around the funding: the slot is acquired from `scope`
    /// exactly as [`WebRtcConnectorWorker::inbound_realtime_retirement`] acquires
    /// it, so a control that exhausts the grant sees the same refusal production
    /// would.
    fn test_inbound_retirement(
        tracks: &Arc<RealtimeSessionTracks>,
        identity: &Arc<RealtimeTrackIdentity>,
        scope: &ConnectorWorkResourceScope,
    ) -> RealtimeInboundRetirement {
        let slot = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                crate::runtime::attempt::cleanup_job_claim()
                    .expect("the retirement slot claim is representable"),
            )
            .expect("the fixture grant funds this retirement's queue slot");
        tracks.retirement(
            Arc::clone(identity),
            scope.cleanup_submission().clone(),
            slot,
        )
    }

    /// A registry over a provider funded for exactly the stated workload.
    ///
    /// The workload used to be an owner ceiling the registry then enforced, so
    /// a control could be refused either by the ceiling or by the provider and
    /// the two were sized together. Only the provider refuses now, and this
    /// states what it is funded for — so a control that expects a refusal gets
    /// one from the only thing that can still give it.
    fn test_realtime_registry(workload: TransportLabRealtimeWorkload) -> Arc<RealtimeFlowRegistry> {
        RealtimeFlowRegistry::new(Some(test_realtime_resource_scope(workload)))
    }

    fn test_realtime_registry_with_observer(
        workload: TransportLabRealtimeWorkload,
        observer: Arc<dyn RealtimeFlowObserver>,
    ) -> Arc<RealtimeFlowRegistry> {
        RealtimeFlowRegistry::with_observer(
            Some(test_realtime_resource_scope(workload)),
            Some(observer),
        )
    }

    /// A work scope funded for exactly the listed claims and nothing else.
    ///
    /// The shared workload grant cannot state scarcity for one claim. It funds
    /// every claim a flow of that shape *could* take — a native read per inbound
    /// flow, an assembly and its fragments per in-progress unit, a packet work
    /// lease per pump — and those claims overlap in the dimensions that matter:
    /// a fragment and a packet work both spend `ParsingOrCpuWork`, a native read
    /// and an output both spend `CallbackOrScheduledWork`. So a control that
    /// funds one of a thing and expects the second to be refused is instead
    /// afforded it out of capacity granted for work the control never does, and
    /// the refusal it asserts is unreachable. Scarcity has to be built for the
    /// claim under test or it is not scarcity at all.
    ///
    /// Callers enumerate every claim the control actually takes, including the
    /// ones an open quietly needs — a flow is its own record *and* a separate
    /// `LeasedMap` node — so the grant is a statement about the control rather
    /// than about whatever slack a shape-derived envelope happened to leave.
    /// Everything an exact-grant fixture has to keep alive for its refusals to
    /// mean anything.
    ///
    /// A work scope does not own the things that were charged to build it. The
    /// candidate holds the connector-opening reservation, and the Mesh scope
    /// token behind it holds the owner, which owns the cleanup executor and the
    /// infrastructure lease that executor took. Let any of them drop and the
    /// provider gets that capacity back — so a control that then asserts "the
    /// next acquisition is refused" is asking a pool that has quietly been
    /// refilled with whatever its own setup returned.
    ///
    /// That is not hypothetical: an earlier version of this helper returned the
    /// scope alone, dropping the candidate and the attempt lifetime as it
    /// returned. The released `CallbackOrScheduledWork` — one from the executor
    /// infrastructure, one from the cleanup job inside the opening claim — is
    /// exactly what was paying for the output reservations three controls
    /// expected to be refused. Holding this guard for the length of the control
    /// is what makes the ledger add up.
    struct ExactRealtimeGrant {
        _owner: ConnectorResourceOwnerPort,
        _candidate: ConnectorCandidateCapability,
        _attempt: AttemptLifetime,
    }

    fn exact_realtime_work_scope(
        claims: impl IntoIterator<Item = crate::resource::ResourceClaim>,
    ) -> (ConnectorWorkResourceScope, ExactRealtimeGrant) {
        // The base is every record this scope reserves, and the guard below is
        // what keeps each of them reserved.
        //
        // `issue_mesh_scope` calls `cleanup_executor.prepare`, so the executor
        // starts and takes its infrastructure lease eagerly, at Mesh issuance
        // rather than at the first cleanup job. It has to be funded. What it
        // must *not* do is come back: that lease and the opening claim are held
        // for as long as the owner and the candidate live, which is why both
        // travel out of here in `ExactRealtimeGrant` instead of dying with this
        // function.
        //
        // `explicit_test_grant` is deliberately not the base. It adds a spare
        // `connector_operation_claim` per fixture candidate — one
        // `ParsingOrCpuWork`, the only dimension a retained fragment competes
        // for — which nothing here ever holds.
        let structural = crate::runtime::attempt::connector_resource_structural_claims();
        let mut grant = FiniteResourceProvider::scope_record_charge_for_test()
            .checked_add(FiniteResourceProvider::scope_record_charge_for_test())
            .expect("the fixture scope records are representable")
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(
                    structural.process_infrastructure(),
                )
                .expect("the cleanup infrastructure charge is representable"),
            )
            .expect("the fixture infrastructure grant is representable")
            .checked_add(
                FiniteResourceProvider::child_scope_with_reservation_charge_for_test(
                    structural.connector_opening(),
                )
                .expect("the connector opening charge is representable"),
            )
            .expect("the exact fixture base grant is representable");
        for claim in claims {
            grant = grant
                .checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(claim)
                        .expect("the fixture reservation charge is representable"),
                )
                .expect("the exact fixture grant is representable");
        }
        let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
            .expect("the exact grant accounts for its process scope");
        let owner = ConnectorResourceOwnerPort::new(provider);
        let mesh = owner
            .issue_mesh_scope()
            .expect("the exact grant accounts for its Mesh scope and cleanup executor");
        let (permit, attempt, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), mesh);
        let candidate = permit
            .reserve_connector_candidate(claim)
            .expect("the exact grant admits its connector candidate");
        let scope = candidate.work_resource_scope();
        (
            scope,
            ExactRealtimeGrant {
                _owner: owner,
                _candidate: candidate,
                _attempt: attempt,
            },
        )
    }

    /// A registry on an exact grant, with the guard the caller must hold.
    ///
    /// Returned as a pair rather than hidden inside the registry so that
    /// dropping the guard early is something a caller has to write down.
    fn exact_realtime_registry(
        claims: impl IntoIterator<Item = crate::resource::ResourceClaim>,
    ) -> (Arc<RealtimeFlowRegistry>, ExactRealtimeGrant) {
        let (scope, grant) = exact_realtime_work_scope(claims);
        (RealtimeFlowRegistry::new(Some(scope)), grant)
    }

    fn exact_realtime_registry_with_observer(
        claims: impl IntoIterator<Item = crate::resource::ResourceClaim>,
        observer: Arc<dyn RealtimeFlowObserver>,
    ) -> (Arc<RealtimeFlowRegistry>, ExactRealtimeGrant) {
        let (scope, grant) = exact_realtime_work_scope(claims);
        (
            RealtimeFlowRegistry::with_observer(Some(scope), Some(observer)),
            grant,
        )
    }

    /// Exactly what one `open_inbound_flow` or `open_outbound_flow` acquires.
    ///
    /// Two, not one and not three: the flow's own record, and the registry map
    /// node it is filed under — an independent `LeasedMap` allocation with its
    /// own lifetime. A grant naming only the first funds half of an open and
    /// refuses the open itself, which reads as the control's own refusal and is
    /// not one.
    ///
    /// The ready obligation is deliberately *not* here. `open_flow_checked`
    /// does not take one — a ready lease is acquired by `enqueue`, when a unit
    /// actually becomes serviceable. Funding it at open hands the pool a spare
    /// `CallbackOrScheduledWork`, which is the dimension an output reservation
    /// is scarce in, so the reservation a control expects to be refused gets
    /// paid for by a lease that open never took. Controls that enqueue add one
    /// `ready_claim` per unit they enqueue, beside the queue claims.
    fn exact_realtime_open_claims() -> [crate::resource::ResourceClaim; 2] {
        [
            RealtimeFlowRegistry::flow_claim().expect("the flow claim is representable"),
            RealtimeFlowRegistry::flow_map_node_claim()
                .expect("the flow map node claim is representable"),
        ]
    }

    /// The one real-time payload the shared callback fixture is sized for.
    ///
    /// `test_realtime_workload` funds its unit, its fragment and its queued
    /// bytes from this exact length, so a control that emits any *other* payload
    /// through that fixture is either refused for want of capacity or silently
    /// given slack the fixture never funded. Both are arrangement failures
    /// wearing the costume of a result, which is why there is one constant
    /// rather than a literal at each site.
    const FIXTURE_REALTIME_PAYLOAD: &[u8] = b"realtime-unit";

    /// The real-time workload the shared callback fixture funds.
    ///
    /// Sized from [`FIXTURE_REALTIME_PAYLOAD`] for the same reason the ceilings
    /// it replaces were: a control that emits any *other* payload through this
    /// fixture is either refused for want of capacity or silently handed slack
    /// the fixture never funded, and both are arrangement failures wearing the
    /// costume of a result.
    fn test_realtime_workload(capacity: NonZeroUsize) -> TransportLabRealtimeWorkload {
        let unit_bytes = FIXTURE_REALTIME_PAYLOAD.len();
        TransportLabRealtimeWorkload {
            inbound_flows: 2,
            outbound_flows: 2,
            queued_units_per_flow: capacity.get(),
            in_progress_units_per_inbound_flow: 1,
            fragments_per_unit: 1,
            max_fragment_bytes: unit_bytes,
            max_unit_bytes: unit_bytes,
        }
    }

    fn retained_realtime_bytes(state: &RealtimeFlowRegistryState) -> usize {
        state
            .retained_bytes_by_domain
            .into_iter()
            .try_fold(0usize, usize::checked_add)
            .expect("fixture real-time accounting total is representable")
    }

    fn realtime_accounting_is_clean(state: &RealtimeFlowRegistryState) -> bool {
        state.accounting_poisoned_by_domain == [false, false]
    }

    fn admitted_ownership(candidate: ConnectorCandidateCapability) -> ConnectorOwnership {
        let work_resource_scope = candidate.work_resource_scope();
        ConnectorOwnership::admitted(
            candidate,
            Arc::new(ConnectorOperationFence::default()),
            work_resource_scope,
            Arc::new(AtomicBool::new(false)),
            Arc::new(WebRtcConnectorIncarnation::new()),
        )
    }

    fn test_event_mailboxes(capacity: usize) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let capacity =
            std::num::NonZeroUsize::new(capacity).expect("fixture callback capacity is nonzero");
        test_event_mailboxes_with_workload(capacity, test_realtime_workload(capacity))
    }

    fn test_event_mailboxes_with_workload(
        capacity: NonZeroUsize,
        realtime: TransportLabRealtimeWorkload,
    ) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        test_event_mailboxes_with_grant(lab_callback_grant(capacity, capacity), realtime)
    }

    /// The same fixture, on a callback grant the control states itself.
    ///
    /// Only the controls that assert a refusal need this. Everything else is
    /// better served by the general grant, which funds enough slack that an
    /// arrangement step cannot fail for a reason the control was not written to
    /// be about.
    fn test_event_mailboxes_with_grant(
        grant: callback::TransportLabCallbackGrant,
        realtime: TransportLabRealtimeWorkload,
    ) -> (ConnectorEventMailboxes, TransportEventReceiver) {
        let callback_producer = CallbackProducerOwner::for_local_lab_grant(grant)
            .expect("fixture callback resources are derivable from its stated grant");
        let realtime_flows = test_realtime_registry(realtime);
        let callback_ready = Arc::new(tokio::sync::Notify::new());
        let control = callback_producer
            .create_mailbox(ConnectorCallbackClass::Control, Arc::clone(&callback_ready))
            .expect("fixture control mailbox is admitted");
        let endpoint_data = callback_producer
            .create_mailbox(
                ConnectorCallbackClass::EndpointData,
                Arc::clone(&callback_ready),
            )
            .expect("fixture endpoint mailbox is admitted");
        let open_work = callback_producer
            .reserve_lifecycle_delivery()
            .expect("fixture open lifecycle work is reserved");
        let close_work = callback_producer
            .reserve_lifecycle_delivery()
            .expect("fixture close lifecycle work is reserved");
        let lifecycle = Arc::new(ConnectorLifecycleOwner::with_reserved_lifecycle_work(
            open_work, close_work,
        ));
        (
            ConnectorEventMailboxes {
                control: Arc::clone(&control),
                endpoint_data: Arc::clone(&endpoint_data),
                lifecycle: Arc::clone(&lifecycle),
                callback_producer,
            },
            TransportEventReceiver {
                control,
                endpoint_data,
                lifecycle,
                lifecycle_closed: false,
                callback_ready,
                callback_failed: false,
                realtime_flows,
                scheduler: ConnectorCallbackScheduler::new(
                    ConnectorCallbackPolicy::elastic_realtime(),
                ),
                control_cursor: ConnectorControlSourceCursor::default(),
            },
        )
    }

    fn test_event_sink(
        events: ConnectorEventMailboxes,
        realtime: TransportLabRealtimeWorkload,
        resource_scope: Option<PeerConnectionResourceScope>,
    ) -> ConnectorEventSink {
        let callback_producer = events.callback_producer.clone();
        ConnectorEventSink {
            events,
            realtime_flows: test_realtime_registry(realtime),
            resource_scope,
            attempt_liveness: None,
            candidate_promoted: Arc::new(AtomicBool::new(true)),
            callback_gate: Arc::new(WebRtcConnectorIncarnation::new()),
            callback_violation_reported: Arc::new(AtomicBool::new(false)),
            callback_producer,
            operation_fence: Arc::new(ConnectorOperationFence::default()),
            close_owner: None,
        }
    }

    fn test_event_sink_for_receiver(
        events: ConnectorEventMailboxes,
        realtime: TransportLabRealtimeWorkload,
        resource_scope: Option<PeerConnectionResourceScope>,
        receiver: &TransportEventReceiver,
    ) -> ConnectorEventSink {
        let mut sink = test_event_sink(events, realtime, resource_scope);
        sink.realtime_flows = Arc::clone(&receiver.realtime_flows);
        sink
    }

    /// The real-time work one control funds, in the shape the grant needs.
    ///
    /// This replaces a helper that built an owner ceiling out of the same six
    /// numbers. They meant "refuse past here" and now mean "fund exactly this",
    /// which is the same arithmetic pointed at the only thing left that can
    /// refuse. The per-unit fragment count stays at the value these controls
    /// were written against.
    fn explicit_realtime_workload(
        max_unit_bytes: usize,
        max_active_flows_per_domain: usize,
        queue_capacity_per_flow: usize,
        max_inbound_fragment_bytes: usize,
        max_in_progress_units_per_flow: usize,
    ) -> TransportLabRealtimeWorkload {
        TransportLabRealtimeWorkload {
            inbound_flows: max_active_flows_per_domain,
            outbound_flows: max_active_flows_per_domain,
            queued_units_per_flow: queue_capacity_per_flow,
            in_progress_units_per_inbound_flow: max_in_progress_units_per_flow,
            fragments_per_unit: 2_048,
            max_fragment_bytes: max_inbound_fragment_bytes,
            max_unit_bytes,
        }
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

    struct PanickingRealtimeObserver;

    impl RealtimeFlowObserver for PanickingRealtimeObserver {
        fn observe(&self, _observation: RealtimeFlowObservation) {
            panic!("injected observation-only callback failure");
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
            _callback_work: None,
            #[cfg(feature = "route-flow-diagnostics")]
            route_flow_receipt: None,
        }
    }

    /// A leased label for one fixture flow.
    ///
    /// The controls in this module care *which* flow a delivery is on rather
    /// than what its name spells, so they keep naming flows by number — but
    /// what they get back is a real minted label over a shared elastic control
    /// registry, because a hand-built label is not the shape production ever
    /// produces. Two calls with the same number compare equal, which is what
    /// the demultiplexing assertions rely on.
    ///
    /// It stands on the crate's shared control scope, which is deliberately
    /// never retired: a fixture label can be retained by a queued event that
    /// outlives the control that made it.
    fn test_label(number: u8) -> RealtimeFlowLabel {
        control_label_for_test(
            &RealtimeFlowName::new(format!("flow-{number}").into_bytes())
                .expect("a fixture name is within the frame bound"),
        )
    }

    /// The raw name a fixture flow is opened under, before any session has
    /// accepted it and minted a lease for it.
    fn fixture_flow_name() -> RealtimeFlowName {
        RealtimeFlowName::new(b"fixture-flow".to_vec())
            .expect("the fixture name is within the frame bound")
    }

    /// One inbound delivery shaped exactly as the session pump builds one: a
    /// label this side minted and an opaque unit, with no lease attached —
    /// the queue mints that at enqueue.
    fn test_realtime_event(label: u8, timestamp: u32, data: &'static [u8]) -> TransportEvent {
        TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
            test_label(label),
            RealtimeRecvUnit {
                timestamp,
                marker: true,
                data: Bytes::from_static(data),
            },
        ))
    }

    async fn assert_callback_class_has_independent_capacity(
        first: TransportEvent,
        second: TransportEvent,
    ) {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(sink.emit(first).await);
        let mut retained_flow = None;
        match second {
            event @ TransportEvent::RealtimeUnit(_) => {
                let TransportEvent::RealtimeUnit(delivery) = &event else {
                    unreachable!("the arm matched a real-time unit");
                };
                let payload_bytes = delivery.payload_bytes();
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
    async fn v4_arc03_control_and_realtime_callback_capacity_are_independent() {
        // The payload the shared policy is sized for. A longer one would be
        // refused as oversize before the two classes were ever compared, and
        // this control would report a capacity conclusion it had not reached.
        assert_callback_class_has_independent_capacity(
            TransportEvent::DataChannelOpen,
            test_realtime_event(0, 0, FIXTURE_REALTIME_PAYLOAD),
        )
        .await;
    }

    #[tokio::test]
    async fn v4_arc03_endpoint_data_and_realtime_callback_capacity_are_independent() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(
            std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero"),
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"data")))
                .await
        );
        let first_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the first real-time flow");
        let first_reservation = first_flow
            .reserve_output(5)
            .expect("fixture reserves the first unit");
        assert!(sink.emit_realtime(
            &first_flow,
            test_realtime_event(0, 0, b"first"),
            first_reservation
        ));
        assert!(receiver.try_recv().is_ok());
        assert!(receiver.try_recv().is_ok());
        let second_flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits the second real-time flow");
        let second_reservation = second_flow
            .reserve_output(5)
            .expect("fixture reserves the second unit");
        assert!(sink.emit_realtime(
            &second_flow,
            test_realtime_event(1, 0, b"secnd"),
            second_reservation
        ));
        assert!(receiver.try_recv().is_ok());
    }

    #[tokio::test]
    async fn v4_arc03i_close_supersedes_prequeued_endpoint_data_without_hidden_producers() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = test_realtime_workload(one);
        const PREQUEUED: &[u8] = b"before-close";
        // Exactly one endpoint payload of the prequeued size, and no spare
        // control bytes or unreserved lifecycle slots for the overload below to
        // be admitted out of.
        let (events, mut receiver) = test_event_mailboxes_with_grant(
            lab_callback_grant_exact(
                one,
                one,
                1,
                PREQUEUED.len(),
                NonZeroUsize::new(2).expect("the two reserved lifecycle deliveries are nonzero"),
            ),
            policy,
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(PREQUEUED)))
                .await
        );
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::Message(Bytes::from_static(b"overload")))
                .await,
            ConnectorCallbackInsertResult::Overloaded,
            "a full mailbox returns typed overload without parking a producer"
        );

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(
            sink.emit_data_channel(TransportEvent::Message(Bytes::from_static(b"after-close")))
                .await,
            "a causally later message is discarded after the close commit"
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

    #[tokio::test]
    async fn v4_arc03i_open_and_close_remain_ordered_with_other_callbacks_queued() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = test_realtime_workload(one);
        let (events, mut receiver) = test_event_mailboxes_with_workload(one, policy);
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(sink.emit(TransportEvent::LocalIceCandidate(None)).await);
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelOpen)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelOpen)
        ));
        assert!(receiver.lifecycle.commit_open());

        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelClosed)
                .await,
            ConnectorCallbackInsertResult::Queued
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

    #[tokio::test]
    async fn v4_arc03i_close_supersedes_an_uncommitted_open_exactly_once() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelOpen)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert_eq!(
            sink.try_emit_data_channel(TransportEvent::DataChannelClosed)
                .await,
            ConnectorCallbackInsertResult::Queued
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(!receiver.lifecycle.commit_open());
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_candidate_overload_retires_the_connector() {
        let one = NonZeroUsize::new(1).expect("one is nonzero");
        let policy = test_realtime_workload(one);
        let candidate_bytes = candidate_content_bytes(&observed_candidate())
            .expect("the fixture candidate has representable content");
        // Exactly one candidate's worth of control `QueuedBytes`, endpoint
        // starved to a byte, and no unreserved lifecycle slot — so the second
        // candidate meets an empty pool.
        let (events, mut receiver) = test_event_mailboxes_with_grant(
            lab_callback_grant_exact(
                one,
                one,
                candidate_bytes,
                1,
                NonZeroUsize::new(2).expect("the two reserved lifecycle deliveries are nonzero"),
            ),
            policy,
        );
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(
            sink.emit(TransportEvent::LocalIceCandidate(
                Some(observed_candidate())
            ))
            .await
        );
        // The second candidate rather than the gathering-complete signal this
        // used to use. Completion carries no payload at all, and the only bound
        // that could have refused a zero-byte control callback was the deleted
        // item ceiling: a pool cannot refuse something that costs nothing, and
        // the smallest grant the other class can be given is still one whole
        // slot. A second real candidate is refused on its own `QueuedBytes`,
        // which keeps the claim — a candidate that cannot be queued reports
        // overload rather than vanishing, and the connector retires — pointed at
        // the thing that still refuses.
        assert!(
            !sink
                .emit(TransportEvent::LocalIceCandidate(
                    Some(observed_candidate())
                ))
                .await,
            "an unqueueable candidate reports overload instead of disappearing"
        );
        assert_eq!(
            receiver.lifecycle.phase(),
            ConnectorLifecyclePhase::ClosedPending
        );
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
    }

    #[tokio::test]
    async fn v4_arc03i_renegotiation_and_state_observations_are_coalesced() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        assert!(sink.emit(TransportEvent::RenegotiationNeeded).await);
        assert!(sink.emit(TransportEvent::RenegotiationNeeded).await);
        assert!(
            sink.emit(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Checking,
            ))
            .await
        );
        assert!(
            sink.emit(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Connected,
            ))
            .await
        );

        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RenegotiationNeeded)
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::IceConnectionStateChanged(
                RTCIceConnectionState::Connected
            ))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    #[test]
    fn v4_arc03i_first_structural_violation_retires_once() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);

        sink.structural_violation("first fixture violation");
        sink.structural_violation("second fixture violation");
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
    async fn v4_arc03_structural_violation_starts_native_cleanup_without_receiver_polling() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let close_calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&close_calls),
            }))
        );
        let (events, receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let mut sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        sink.close_owner = Some(Arc::downgrade(&close_owner));

        sink.structural_violation("fixture violation");
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("cleanup completes without consuming the lifecycle event")
            .expect("the deterministic native close succeeds");
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert_eq!(
            receiver.lifecycle.phase(),
            ConnectorLifecyclePhase::ClosedPending,
            "the proof does not depend on polling the close event"
        );
    }

    #[tokio::test]
    async fn v4_arc03_recorded_close_survives_connector_retirement_to_engine_delivery() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, lifetime) = close_owner_fixture(&owner);
        let close_calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&close_calls),
            }))
        );
        let ownership = close_owner.ownership.clone();
        let (events, raw) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let mut sink = test_event_sink_for_receiver(events, policy, None, &raw);
        sink.close_owner = Some(Arc::downgrade(&close_owner));
        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: Some(Arc::clone(&close_owner)),
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };

        sink.structural_violation("fixture violation");
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("cleanup reaches its terminal state")
            .expect("the deterministic native close succeeds");
        assert!(!ownership.incarnation.is_active());
        let delivered = receiver
            .recv()
            .await
            .expect("the recorded close survives retirement");
        assert!(matches!(delivered.event, TransportEvent::DataChannelClosed));
        assert_eq!(close_calls.load(Ordering::Acquire), 1);
        assert!(receiver.recv().await.is_none());
    }

    #[test]
    fn v4_arc03i_native_data_channel_shape_is_fixed_and_violation_work_is_coalesced() {
        assert_eq!(
            admit_native_data_channel(APP_DATA_CHANNEL_LABEL, false),
            NativeDataChannelAdmission::Install
        );
        assert_eq!(
            admit_native_data_channel(APP_DATA_CHANNEL_LABEL, true),
            NativeDataChannelAdmission::Violation("duplicate application data channel")
        );

        let (events, mut receiver) = test_event_mailboxes(1);
        let policy = test_realtime_workload(NonZeroUsize::new(1).expect("one is nonzero"));
        let sink = test_event_sink_for_receiver(events, policy, None, &receiver);
        for _ in 0..32 {
            let NativeDataChannelAdmission::Violation(reason) =
                admit_native_data_channel("unexpected", true)
            else {
                panic!("unexpected label cannot become an application channel");
            };
            sink.structural_violation(reason);
        }
        sink.structural_violation("duplicate application data channel");

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
        let policy = test_realtime_workload(one);
        let (events, mut receiver) = test_event_mailboxes_with_workload(one, policy);
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

    #[tokio::test]
    async fn v4_arc03g_close_retires_realtime_before_forced_realtime_dispatch() {
        let policy = explicit_realtime_workload(8, 1, 2, 8, 1);
        let (events, mut raw) = test_event_mailboxes_with_workload(
            NonZeroUsize::new(1).expect("one is nonzero"),
            policy,
        );
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let mut sink = test_event_sink_for_receiver(events, policy, None, &raw);
        sink.operation_fence = Arc::clone(&ownership.operation_fence);
        sink.callback_gate = Arc::clone(&ownership.incarnation);

        let flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits one inbound flow");
        let queued = test_realtime_event(0, 1, b"queued");
        let queued_reservation = flow
            .reserve_output(6)
            .expect("queued unit reserves its exact bytes");
        assert!(sink.emit_realtime(&flow, queued, queued_reservation));
        let invoked_after_close = flow
            .reserve_output(5)
            .expect("later invocation reserves before close commits");
        raw.scheduler.cursor = ConnectorCallbackClass::Realtime.index();
        raw.scheduler.remaining = 1;

        assert!(
            sink.emit_data_channel(TransportEvent::DataChannelClosed)
                .await
        );
        assert!(sink.emit_realtime(
            &flow,
            test_realtime_event(0, 2, b"later"),
            invoked_after_close,
        ));
        {
            let state = raw.realtime_flows.state.lock();
            assert!(state.retired);
            assert_eq!(retained_realtime_bytes(&state), 0);
        }
        assert!(raw.realtime_flows.is_empty());

        let mut receiver = WebRtcConnectorEventReceiver {
            ownership: ownership.clone(),
            retirement: ownership.incarnation.subscribe_retirement(),
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            data_channel_open_committed: true,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        let event = receiver
            .recv()
            .await
            .expect("the exact close event reaches engine dispatch");
        assert!(matches!(event.event, TransportEvent::DataChannelClosed));
        assert!(receiver.recv().await.is_none());
        assert!(flow.reserve_output(1).is_none());
    }

    #[test]
    fn v4_arc03_scheduler_gives_each_ready_class_a_bounded_service_turn() {
        let capacity = 3;
        let (events, mut receiver) = test_event_mailboxes(capacity);
        receiver.scheduler =
            ConnectorCallbackScheduler::new(ConnectorCallbackPolicy::elastic_realtime());
        for candidate in ["candidate-1", "candidate-2", "candidate-3"] {
            events
                .try_insert_for_test(
                    TransportEvent::LocalIceCandidate(Some(LocalIceCandidate {
                        candidate: candidate.to_string(),
                        sdp_mid: Some("0".to_string()),
                        sdp_mline_index: Some(0),
                        username_fragment: Some("fixture".to_string()),
                    })),
                    None,
                )
                .expect("fixture control mailbox has capacity");
        }
        events
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"endpoint")),
                None,
            )
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
                event: test_realtime_event(0, 0, b""),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            reservation,
        ));

        // One quantum per ready class, so the rotation visits each ready class
        // once before returning to control. The leading pair of control
        // deliveries this used to assert was the owner-selected service weight
        // for that class; with the weights gone every class scores one, and the
        // property the control is named for is the rotation itself: each ready
        // class gets a turn, and the two control deliveries at the end are the
        // work-conserving half — an empty class is skipped rather than waited
        // on, so control is served again immediately instead of the rotation
        // stalling on the two classes that have drained.
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::RealtimeUnit(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
        ));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::LocalIceCandidate(_))
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
                    features: Vec::new(),
                },
            ))
            .expect("fixture Hello serializes"),
        );
        events
            .try_insert_for_test(TransportEvent::Message(first_handshake.clone()), None)
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelOpen, None)
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
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                None,
            )
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("fixture control mailbox has capacity");

        let event = receiver
            .recv_queued_filtered(false)
            .await
            .expect("close remains deliverable before open commitment");
        assert!(matches!(event.event, TransportEvent::DataChannelClosed));
        assert!(matches!(
            receiver.endpoint_data.try_take(),
            Some(QueuedTransportEvent {
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
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        events
            .try_insert_for_test(
                TransportEvent::Message(Bytes::from_static(b"stale-handshake")),
                Some(observation),
            )
            .expect("fixture endpoint mailbox has capacity");
        events
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
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
    fn v4_arc03_observer_panic_cannot_poison_realtime_resource_ownership() {
        let registry = test_realtime_registry_with_observer(
            explicit_realtime_workload(16, 1, 1, 16, 1),
            Arc::new(PanickingRealtimeObserver) as Arc<dyn RealtimeFlowObserver>,
        );
        let first = registry
            .open_inbound_flow()
            .expect("observation failure cannot refuse an admitted flow");
        drop(first);
        let second = registry
            .open_inbound_flow()
            .expect("the exact released flow claim remains reusable");
        drop(second);
        assert!(realtime_accounting_is_clean(&registry.state.lock()));
    }

    #[test]
    /// Two flows queue independently, and one exhausting the grant does not
    /// take capacity from the other.
    ///
    /// The bound used to be a per-flow queue count, and the control drove one
    /// flow into it. There is no count now, so the fixture funds exactly two
    /// queued units across two flows and the third reservation is refused by
    /// the provider — which is the same shape of refusal aimed at the thing
    /// that actually still refuses.
    fn v4_arc03_realtime_flows_have_independent_bounded_queues() {
        // Two flows, two queued units, and nothing else. The shared envelope
        // cannot state this: it funds a native read per inbound flow and an
        // assembly per in-progress unit, and both spend the same
        // `CallbackOrScheduledWork` an output reservation does, so the third
        // reservation below is afforded out of capacity for work this control
        // never performs.
        let unit_bytes = 5usize;
        let mut claims = Vec::new();
        for _ in 0..2 {
            claims.extend(exact_realtime_open_claims());
            claims.push(
                RealtimeFlowRegistry::output_claim(unit_bytes)
                    .expect("the output claim is representable"),
            );
            claims.push(
                RealtimeFlowRegistry::queue_claim(unit_bytes)
                    .expect("the queued-byte claim is representable"),
            );
            claims.push(
                RealtimeFlowRegistry::queued_event_node_claim()
                    .expect("the queue node claim is representable"),
            );
            // The ready obligation belongs to the enqueue, not to the open.
            claims.push(
                RealtimeFlowRegistry::ready_claim().expect("the ready claim is representable"),
            );
        }
        let observer = Arc::new(TestRealtimeObserver::default());
        let (registry, _grant) = exact_realtime_registry_with_observer(
            claims,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let first = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second = registry
            .open_inbound_flow()
            .expect("second flow is admitted");

        assert!(first.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"first"),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            first.reserve_output(5).expect("first unit is reserved"),
        ));
        assert!(second.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(1, 1, b"secnd"),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            second.reserve_output(5).expect("second unit is reserved"),
        ));
        assert!(
            first.reserve_output(5).is_none(),
            "the grant funds two queued units, and the third is refused"
        );

        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(delivery))
                if delivery.label == test_label(0)
                    && delivery.unit.timestamp == 1
        ));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(delivery))
                if delivery.label == test_label(1)
                    && delivery.unit.timestamp == 1
        ));
        assert!(registry.try_recv().is_none());
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
        drop(state);
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::ResourceUnavailable(_),
                    ..
                }
            )
        }));
    }

    // A control asserting that inbound saturation cannot consume the outbound
    // slot used to live here. Its premise was the owner-selected per-domain flow
    // partition, and that partition is gone: what funds a flow now is one pooled
    // provider grant with no domain in it, so a second inbound open legitimately
    // spends what a fixture intended for an outbound flow. No choice of grant
    // size restores the guarantee — a pool cannot express a partition — and
    // rebuilding one out of per-domain scopes would be reintroducing the policy
    // under a new name. The property is not weakened here, it no longer exists.

    /// The bytes follow the delivery, whole, into whatever holds it next.
    ///
    /// This used to move the lease by *cloning* it, when the payload owner was
    /// an `Arc`, and asserted the bytes stayed charged until the last of several
    /// owners went away. There is no last-of-several now, and no way to reach
    /// the lease at all: the delivery has no accessor that hands its parts back,
    /// so the only thing a downstream holder can be given is the whole value.
    ///
    /// That is what this proves, and it is the strongest statement the shape
    /// admits: moving the delivery downstream moves the charge with it — the
    /// place it came from releases nothing — and the bytes come back exactly
    /// when the downstream holder drops it. A control that took the delivery
    /// apart to watch one part would be exercising an escape production does not
    /// have.
    #[test]
    fn v4_arc03f_realtime_bytes_follow_the_payload_owner_through_downstream_queues() {
        let policy = explicit_realtime_workload(8, 1, 1, 8, 1);
        let registry = test_realtime_registry(policy);
        let flow = registry
            .open_inbound_flow()
            .expect("fixture inbound flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"owned"),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            flow.reserve_output(5).expect("payload bytes are reserved"),
        ));

        let queued = registry.try_recv().expect("queued payload is serviceable");
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 5);
        let TransportEvent::RealtimeUnit(delivery) = queued.event else {
            panic!("fixture receives its real-time unit");
        };
        assert!(
            format!("{delivery:?}").contains("leased: true"),
            "non-vacuity: the delivery really is holding the payload owner, so \
             the release below is caused by dropping it rather than by there \
             being nothing to release"
        );

        // Downstream: the delivery moves on as one value, which is the only way
        // it can move at all.
        let downstream = vec![delivery];
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            5,
            "the charge travelled with the delivery instead of being released \
             where it came from"
        );
        drop(downstream);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
    }

    #[tokio::test]
    async fn v4_arc03f_complete_realtime_unit_has_no_wall_clock_expiry() {
        let policy = explicit_realtime_workload(16, 1, 2, 16, 1);
        let observer = Arc::new(TestRealtimeObserver::default());
        let registry = test_realtime_registry_with_observer(
            policy,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 7, b"stale"),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            flow.reserve_output(5).expect("unit is reserved"),
        ));
        tokio::time::sleep(Duration::from_millis(10)).await;

        let queued = registry
            .try_recv()
            .expect("elapsed time cannot revoke a structurally bounded complete unit");
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 5);
        assert!(realtime_accounting_is_clean(&state));
        drop(state);
        drop(queued);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
        assert!(!observer
            .observations
            .lock()
            .iter()
            .any(|observation| { matches!(observation, RealtimeFlowObservation::Drop { .. }) }));
    }

    /// A byte claim is taken before the bytes are recorded, so a refusal leaves
    /// the accounting exactly where it was.
    ///
    /// Most of what this control used to assert was ceiling arithmetic — that a
    /// unit ceiling was consulted before a fragment ceiling, that the next byte
    /// was refused at a connector aggregate, that an oversized output and an
    /// oversized fragment were rejected on sight. None of those checks exist:
    /// there is no unit ceiling, no aggregate, and no oversize refusal standing
    /// in front of the claim. The claim *is* the admission.
    ///
    /// What survives is the ordering the name states, and it is the part that
    /// actually protects the accounting: the provider is asked first, and the
    /// domain's retained-byte total moves only if the answer was yes. A refused
    /// fragment and a refused output each leave the total untouched, which is
    /// what makes a refusal safe to retry rather than a silent leak.
    #[test]
    fn v4_arc03_realtime_byte_claims_precede_fragment_and_output_retention() {
        let bytes = 4usize;
        let (registry, _grant) = exact_realtime_registry(
            exact_realtime_open_claims().into_iter().chain([
                RealtimeFlowRegistry::assembly_claim()
                    .expect("the assembly claim is representable"),
                RealtimeFlowRegistry::ordered_fragment_claim(bytes)
                    .expect("the ordered fragment claim is representable"),
                RealtimeFlowRegistry::output_claim(bytes)
                    .expect("the output claim is representable"),
            ]),
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("the funded unit is admitted");

        assert!(assembly.retain_ordered_fragment(bytes));
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), bytes);
        assert!(
            !assembly.retain_ordered_fragment(bytes),
            "the grant funds one retained fragment, and the second is refused"
        );
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            bytes,
            "the refused fragment retained nothing: the claim came first, so the \
             total is exactly where the successful fragment left it"
        );

        let output = flow
            .reserve_output(bytes)
            .expect("the funded output is admitted beside the guarded input");
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), bytes * 2);
        assert!(
            flow.reserve_output(bytes).is_none(),
            "the grant funds one output reservation, and the second is refused"
        );
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            bytes * 2,
            "and the refused output retained nothing either"
        );

        drop(output);
        drop(assembly);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert_eq!(state.accounting_poisoned_by_domain, [false, false]);
    }

    /// How many fragments one unit may retain is a funding question now.
    ///
    /// It used to be a `fragments_per_unit` ceiling the assembler counted
    /// against. That number is gone, and what stops an unbounded fragment
    /// stream is that each retained fragment holds an exact claim for as long as
    /// the assembly lives: fund one and the second is refused, and the refusal
    /// is the provider's rather than a counter's. Still structural in the sense
    /// the name claims — no timer, no cumulative tally, and the capacity comes
    /// back exactly when the assembly drops.
    ///
    /// The grant is enumerated rather than shaped, because the shared envelope
    /// funds a packet-work lease per inbound pump and a fragment and a packet
    /// work both spend `ParsingOrCpuWork`. Under that envelope the second
    /// fragment is afforded out of pump capacity this control never uses.
    #[test]
    fn v4_arc03f_realtime_fragment_count_is_structurally_bounded() {
        let fragment_bytes = 1usize;
        let (registry, _grant) = exact_realtime_registry(
            exact_realtime_open_claims().into_iter().chain([
                RealtimeFlowRegistry::assembly_claim()
                    .expect("the assembly claim is representable"),
                RealtimeFlowRegistry::ordered_fragment_claim(fragment_bytes)
                    .expect("the ordered fragment claim is representable"),
            ]),
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembly = flow.begin_unit().expect("unit is admitted");

        assert!(assembly.retain_ordered_fragment(fragment_bytes));
        assert!(
            !assembly.retain_ordered_fragment(fragment_bytes),
            "the grant funds one retained fragment, and the second is refused"
        );
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            fragment_bytes
        );

        drop(assembly);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    /// Damaged local accounting is contained to the domain that suffered it.
    ///
    /// This used to assert that corruption *failed closed*: the damaged domain
    /// was pinned to the owner's byte ceiling, so every later admission was
    /// refused against a number the registry had invented for itself. There is
    /// no ceiling to pin it to now, and — more to the point — nothing for the
    /// registry to refuse against: what admits real-time work is the provider,
    /// whose accounting is exact and entirely unaffected by a local counter
    /// going wrong. Refusing here would mean refusing work the provider has
    /// already funded, on the strength of a number this registry itself knows is
    /// untrustworthy.
    ///
    /// What survives is the containment, which is the part that was ever this
    /// registry's to promise: the damaged domain stops reporting a figure rather
    /// than reporting a wrong one, and the independent domain is untouched and
    /// still admits work.
    #[test]
    fn v4_arc03_realtime_accounting_corruption_is_contained_per_domain() {
        let policy = explicit_realtime_workload(4, 1, 1, 4, 1);
        let registry = test_realtime_registry(policy);
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let reservation = flow.reserve_output(4).expect("output is admitted");
        registry.state.lock().retained_bytes_by_domain
            [RealtimeFlowDomain::InboundQuarantine.index()] = 0;
        drop(reservation);

        let state = registry.state.lock();
        assert!(state.accounting_poisoned_by_domain[RealtimeFlowDomain::InboundQuarantine.index()]);
        assert!(
            !state.accounting_poisoned_by_domain[RealtimeFlowDomain::OutboundCompatibility.index()]
        );
        drop(state);
        assert!(
            registry.open_outbound_flow().is_some(),
            "inbound accounting corruption does not poison the independent outbound owner"
        );
    }

    /// Sustained inbound RTP is bounded by the per-packet work claim rather
    /// than by any cumulative counter: a packet is admitted only while the
    /// provider still owns capacity for the classification and framing it is
    /// about to cost, and that capacity returns when the packet's work does.
    #[test]
    fn v4_arc03h_sustained_inbound_rtp_is_bounded_by_its_exact_packet_work() {
        // The shared shaped envelope cannot state this. It funds one
        // ordered-fragment claim per admissible fragment, and a fragment claim
        // spends `ParsingOrCpuWork` — the only dimension the packet claim is
        // scarce in — so under it the second packet below is afforded out of
        // fragment capacity this control never retains a fragment against, and
        // the refusal is unreachable. Scarcity has to be built for the claim
        // under test or it is not scarcity at all.
        //
        // This used to build that grant inline on `explicit_test_grant(1, 1)`,
        // and the comment above it claimed the enumeration was what kept the
        // refusal honest. It was not: that base adds one spare
        // `connector_operation_claim` per fixture candidate, carrying exactly
        // one `ParsingOrCpuWork` that nothing here holds — so the second packet
        // was afforded after all, and this control was passing on capacity it
        // had never named. It shares `exact_realtime_work_scope` now, which
        // funds only the records the scope genuinely reserves.
        //
        // The ready obligation is gone from the list for the same reason: a
        // ready lease belongs to an enqueue, and this control never enqueues.
        let packet_bytes = 8usize;
        let (registry, _grant) = exact_realtime_registry(
            exact_realtime_open_claims().into_iter().chain([
                RealtimeFlowRegistry::session_packet_work_claim(packet_bytes)
                    .expect("the packet work claim is representable"),
            ]),
        );

        let _flow = registry
            .open_inbound_flow()
            .expect("the exact grant owns one speculative inbound flow");

        let packet = registry
            .admit_session_packet_checked(packet_bytes)
            .expect("and one inbound pump's packet work");
        assert!(
            !registry.admit_session_packet(packet_bytes),
            "a second concurrent packet has no unowned work capacity"
        );

        drop(packet);
        assert!(
            registry.admit_session_packet(packet_bytes),
            "and completing the packet returns exactly that capacity"
        );
    }

    #[tokio::test]
    async fn v4_arc03_cancelled_realtime_output_work_releases_its_claim() {
        let registry = test_realtime_registry(explicit_realtime_workload(8, 1, 1, 8, 1));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let (ready_tx, ready_rx) = oneshot::channel();
        let task = tokio::spawn(async move {
            let _reservation = flow.reserve_output(8).expect("output is admitted");
            let _ = ready_tx.send(());
            std::future::pending::<()>().await;
        });
        ready_rx.await.expect("fixture reserved output");
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 8);
        task.abort();
        assert!(task
            .await
            .expect_err("fixture task is cancelled")
            .is_cancelled());
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    #[test]
    fn v4_arc03_realtime_flow_retirement_drains_its_owned_queue() {
        let registry = test_realtime_registry(explicit_realtime_workload(8, 1, 2, 8, 1));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: test_realtime_event(0, 1, b"owned"),
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            flow.reserve_output(5).expect("unit is admitted"),
        ));
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 5);
        drop(flow);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        // `len() == 0` rather than `is_empty()`: a `LeasedMap` deliberately has
        // no `is_empty`, because emptiness there is a claim about released
        // leases and not merely about entry count, and one method answering
        // both would let a caller read the weaker fact as the stronger one.
        assert_eq!(state.flows.len(), 0, "every flow record is gone");
        assert!(state.ready.is_empty());
        assert!(realtime_accounting_is_clean(&state));
    }

    #[tokio::test]
    /// Each payload is admitted at the size it actually is, in its own family.
    ///
    /// This used to also assert that the owner's real-time unit ceiling did not
    /// reach the endpoint class — a real-time payload ceiling could be stated,
    /// and the control's job was to show it stopped where it should. No ceiling
    /// of either kind exists now, so what is left to hold is the part that was
    /// always load-bearing: an endpoint frame and a real-time unit are admitted
    /// separately, against their own families, at their own real sizes.
    async fn v4_arc03_endpoint_and_realtime_payloads_are_admitted_at_their_actual_size() {
        let realtime_limit = 4;
        let policy = explicit_realtime_workload(realtime_limit, 1, 2, realtime_limit, 1);

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let (events, mut receiver) = test_event_mailboxes_with_workload(
            NonZeroUsize::new(1).expect("one is nonzero"),
            policy,
        );
        let sink = test_event_sink_for_receiver(events, policy, Some(scope.clone()), &receiver);

        let flow = sink
            .open_inbound_realtime_flow()
            .expect("fixture admits one exact real-time flow");
        assert!(receiver.try_recv().is_err());

        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(b"12345")))
                .await
        );
        let unit = test_realtime_event(0, 1, b"1234");
        let reservation = flow
            .reserve_output(4)
            .expect("fixture reserves the complete real-time unit");
        assert!(sink.emit_realtime(&flow, unit, reservation));

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
            Ok(TransportEvent::RealtimeUnit(_))
        ));
    }

    #[tokio::test]
    async fn v4_arc03_native_close_success_releases_exact_candidate_claim() {
        let owner = test_resource_owner(1, 1);
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
    async fn v4_arc03_close_before_native_attach_closes_late_port_and_releases_claim() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        close_owner.mark_native_allocation_started();

        close_owner.start();
        tokio::task::yield_now().await;
        assert_eq!(calls.load(Ordering::Acquire), 0);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);

        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Success,
                calls: Arc::clone(&calls),
            }))
        );
        close_owner
            .wait()
            .await
            .expect("the exact late close port completes the pending close owner");

        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    async fn v4_arc03_native_constructor_without_close_port_retains_exact_claim() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.mark_native_allocation_started();
        close_owner.finish_native_allocation_without_close_port(
            "native construction ended without an observable close owner".to_string(),
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("unobservable constructor cleanup must retain its exact claim");
        assert!(error
            .to_string()
            .contains("native construction ended without an observable close owner"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);

        let (permit, _lifetime, claim) =
            admit_single_connector_candidate(crate::runtime::runtime_for_test(), owner.clone());
        let unrelated = permit
            .reserve_connector_candidate(claim)
            .expect("the failed constructor retains only its own exact claim");
        assert_eq!(owner.report().active_candidates, 2);
        drop(unrelated);
    }

    #[tokio::test]
    async fn v4_arc03_native_close_error_retains_only_its_exact_claim() {
        let owner = test_resource_owner(2, 1);
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
    async fn v4_arc03g_native_close_has_no_timer_and_waiter_cancellation_does_not_cancel_owner() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = TestNativeCloseGate::new();
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(Arc::clone(&gate)),
                calls: Arc::clone(&calls),
            }))
        );
        let in_flight = close_owner
            .ownership
            .operation_fence
            .try_enter()
            .expect("fixture operation enters before close");

        close_owner.start();
        tokio::task::yield_now().await;
        assert_eq!(
            close_owner
                .ownership
                .operation_fence
                .active_operations_for_test(),
            1
        );
        assert_eq!(calls.load(Ordering::Acquire), 0);
        drop(in_flight);
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the process cleanup executor polls native close");
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "test observation time cannot turn Closing into a terminal state"
        );
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 0);
        assert!(!owner.report().accounting_poisoned);

        gate.open();
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("released native dependency completes")
            .expect("confirmed native close releases the exact claim");
        assert_eq!(owner.report().active_candidates, 0);
    }

    #[tokio::test]
    async fn v4_arc03_cleanup_thread_start_failure_is_visible_and_fail_closed() {
        let owner = test_resource_owner(2, 1);
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
    async fn v4_arc03h_cleanup_future_panic_marks_exact_owner_failed() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.panic_cleanup_future_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("cleanup panic must retain this exact claim");
        assert!(error.to_string().contains("panicked"));
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.process_report().cleanup.failed_jobs == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup health observes the panic");
        let report = owner.process_report();
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert_eq!(report.cleanup.failed_jobs, 1);
        assert!(!report.cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03i_cleanup_panic_retains_claim_after_last_external_owner_drops() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        close_owner.panic_cleanup_future_for_test();
        close_owner.start();
        drop(close_owner);

        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.report().failed_cleanup_candidates != 1
                || owner.process_report().cleanup.failed_jobs != 1
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("the cleanup job retains its exact failure owner");
        let mesh = owner.report();
        let process = owner.process_report();
        assert_eq!(mesh.active_candidates, 1);
        assert_eq!(mesh.failed_cleanup_candidates, 1);
        assert_eq!(process.active_candidates, 1);
        assert_eq!(process.failed_cleanup_candidates, 1);
        assert_eq!(process.cleanup.failed_jobs, 1);
    }

    #[tokio::test]
    async fn v4_arc03i_executor_termination_retains_active_job_without_external_owner() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        let gate = TestNativeCloseGate::new();
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(gate),
                calls: Arc::clone(&calls),
            }))
        );
        close_owner.start();
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("cleanup future is active before executor termination");
        drop(close_owner);

        owner.fail_cleanup_executor_for_test();
        tokio::time::timeout(Duration::from_secs(1), async {
            while owner.report().failed_cleanup_candidates != 1 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("executor termination invokes the job-owned failure capability");
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.process_report().failed_cleanup_candidates, 1);
        assert!(owner.process_report().cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03h_cleanup_executor_failure_refuses_job_and_fails_exact_owner() {
        let owner = test_resource_owner(2, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        owner.fail_cleanup_executor_for_test();

        let error = close_owner
            .wait()
            .await
            .expect_err("failed executor must retain this exact claim");
        assert!(error
            .to_string()
            .contains("cleanup executor is unavailable"));
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(owner.process_report().cleanup.executor_failed);
    }

    #[tokio::test]
    async fn v4_arc03_terminal_cleanup_failure_cannot_be_overwritten_by_start() {
        let owner = test_resource_owner(2, 1);
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
        let owner = test_resource_owner(1, 1);
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

    #[test]
    fn v4_arc03_cleanup_executor_is_joined_after_non_runtime_owner_drop() {
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1);
        let provider = FiniteResourceProvider::new(grant);
        let process_port = ResourceProviderPort::new(provider.clone())
            .expect("fixture provider admits its process scope");
        let process_owner = ConnectorResourceOwnerPort::new(process_port);
        let mesh = process_owner
            .issue_mesh_scope()
            .expect("fixture process owner issues its Mesh scope");
        let (close_owner, _lifetime) = close_owner_fixture(&mesh);
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
            .expect("native close is observed by the executor");
        assert_eq!(calls.load(Ordering::Acquire), 1);

        // These final drops happen on this ordinary thread, after the caller
        // runtime is gone. The process root must be released synchronously,
        // which requires observing the executor thread rather than detaching
        // its JoinHandle.
        drop(close_owner);
        drop(mesh);
        drop(process_owner);
        assert_eq!(provider.active_scopes(), 0);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.in_use(), crate::resource::ResourceClaim::ZERO);
    }

    #[tokio::test]
    async fn v4_arc03_duplicate_connected_claims_remain_exact_and_local() {
        let owner = test_resource_owner(4, 1);
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
        let owner = test_resource_owner(1, 1);
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
        let task = task_from_handoff(EndpointAuthHandoff::new(
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

    // ---- Arc 04 endpoint-authentication controls -------------------------
    //
    // These live here rather than in `endpoint_auth` because the ownership
    // half of the property needs real connector incarnations and a real close
    // owner, which is exactly what `close_owner_fixture` provides. The
    // transcript half is covered by the controls in `endpoint_auth::tests`.

    /// The fixture Device keys. Seed 1 is this endpoint, seed 2 the expected
    /// remote; both match the identities the fixture task is constructed with,
    /// so a proof signed by seed 2 is the one it will accept. Any other seed is
    /// an impostor by construction.
    fn auth_key(seed: u8) -> (ed25519_dalek::SigningKey, String) {
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&[seed; 32]);
        let device_id = data_encoding::BASE32_NOPAD
            .encode(signing_key.verifying_key().as_bytes())
            .to_lowercase();
        (signing_key, device_id)
    }

    type AuthTaskFixture = (
        Arc<crate::endpoint_auth::EndpointAuthTask>,
        Arc<ConnectorCloseOwner>,
        AttemptLifetime,
        Arc<AtomicUsize>,
    );

    /// One live endpoint-auth task over a fresh connector incarnation.
    fn auth_task_fixture(owner: &MeshConnectorResourceScope) -> AuthTaskFixture {
        auth_task_fixture_with(owner, None, TestNativeCloseResult::Success)
    }

    /// The same fixture with the native close held open by a caller's gate.
    ///
    /// Only the refused-proof control uses it, and only because the property it
    /// asserts is a *during*: the connected claim stays owned while the one
    /// native close is in flight. With the ungated port that window is not
    /// observable — the dedicated cleanup thread may finish the close before
    /// any assertion runs, so the same assertion would be a race rather than a
    /// control. The gate makes the window exact instead of timed.
    fn auth_task_fixture_gated(
        owner: &MeshConnectorResourceScope,
        gate: Arc<TestNativeCloseGate>,
    ) -> AuthTaskFixture {
        auth_task_fixture_with(owner, None, TestNativeCloseResult::Gate(gate))
    }

    /// The same fixture, forcing this endpoint's contribution to a prior value.
    ///
    /// Only the same-certificate control uses it, and only to build the case
    /// production freshness makes unreachable.
    fn auth_task_fixture_reusing(
        owner: &MeshConnectorResourceScope,
        local_contribution: &str,
    ) -> AuthTaskFixture {
        auth_task_fixture_with(
            owner,
            Some(local_contribution),
            TestNativeCloseResult::Success,
        )
    }

    fn auth_task_fixture_with(
        owner: &MeshConnectorResourceScope,
        reuse: Option<&str>,
        native_close: TestNativeCloseResult,
    ) -> AuthTaskFixture {
        auth_task_fixture_with_scope(owner, None, reuse, native_close)
    }

    fn auth_task_fixture_with_scope(
        owner: &MeshConnectorResourceScope,
        observation_scope: Option<&PeerConnectionResourceScope>,
        reuse: Option<&str>,
        native_close: TestNativeCloseResult,
    ) -> AuthTaskFixture {
        let (close_owner, lifetime) =
            close_owner_fixture_with_observation(owner, observation_scope);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: native_close,
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let handoff = EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        );
        let task = Arc::new(match reuse {
            Some(value) => task_from_handoff_reusing(handoff, value),
            None => task_from_handoff(handoff),
        });
        (task, close_owner, lifetime, calls)
    }

    /// One fresh peer contribution, as the wire would carry it.
    fn peer_draw() -> crate::endpoint_auth::PeerContribution {
        crate::endpoint_auth::PeerContribution::from_wire(
            crate::endpoint_auth::LocalContribution::generate().as_str(),
        )
        .expect("a generated draw is canonical")
    }

    /// What the exchange drivers return.
    ///
    /// Spelled through `std::result::Result` on purpose. This module has the
    /// crate-wide `Result<T>` alias in scope, which fixes the error type to
    /// `crate::Error`, so a bare `Result<Capability, EndpointAuthError>` here is
    /// not a two-parameter `Result` at all — it silently resolves to the alias.
    /// These drivers must surface the exact `EndpointAuthError` the typed
    /// assertions below match on, so the error type is named explicitly rather
    /// than left to whichever `Result` happens to be in scope.
    ///
    /// The success side is the task's own closed outcome, not a bare capability.
    /// An attempt that has already promoted is not a failure of this exchange,
    /// so it does not appear on the error side at all: `Err` here means the task
    /// terminalized, which is exactly what the refusal controls below assert.
    type ExchangeResult = std::result::Result<
        crate::endpoint_auth::PeerProofAcceptance,
        crate::endpoint_auth::EndpointAuthError,
    >;

    /// Drive one task through its exchange using typed inputs only.
    ///
    /// The mesh, the profile, the Device pair, the channel binding, this
    /// endpoint's own contribution and its own local proof all belong to the
    /// task and none of them is supplied here. A control chooses exactly two
    /// things: the peer contribution that binds the attempt, and which key signs
    /// the peer's half. The signature itself is built inside `endpoint_auth`
    /// from the task's own context, so no control can make a proof verify by
    /// describing an exchange the task does not hold — which is precisely what
    /// the deleted all-facts entry point allowed.
    fn drive_exchange(
        task: &crate::endpoint_auth::EndpointAuthTask,
        peer: &crate::endpoint_auth::PeerContribution,
        peer_key: &ed25519_dalek::SigningKey,
    ) -> ExchangeResult {
        task.accept_peer_hello(peer.clone())?;
        let proof = crate::endpoint_auth::peer_proof_for_test(task, peer, peer_key);
        task.accept_peer_proof(&proof)
    }

    /// The same two typed steps, with the peer's half supplied verbatim.
    ///
    /// Only for the replay control, which must offer a signature captured from
    /// a different channel rather than one built for this task.
    fn drive_exchange_with_signature(
        task: &crate::endpoint_auth::EndpointAuthTask,
        peer: &crate::endpoint_auth::PeerContribution,
        peer_signature: &str,
    ) -> ExchangeResult {
        task.accept_peer_hello(peer.clone())?;
        task.accept_peer_proof(peer_signature)
    }

    #[tokio::test]
    async fn v4_arc04_complete_transcript_promotes_the_exact_channel() {
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        let authenticated = drive_exchange(&task, &remote_c, &remote_key)
            .expect("a complete mutual proof over the exact channel promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        drop(authenticated);

        // The handoff is consumed exactly once: replaying the whole exchange
        // against this task finds no channel left to move. The Hello is an exact
        // duplicate and is still answered from the cached proof, and promotion
        // states that it already happened — so the replay yields no second
        // capability, without the intact task being reported as terminal.
        assert!(
            matches!(
                drive_exchange(&task, &remote_c, &remote_key)
                    .expect("a replay against a promoted attempt is not a refusal"),
                crate::endpoint_auth::PeerProofAcceptance::AlreadyPromoted
            ),
            "one channel yields at most one authenticated capability"
        );
    }

    #[tokio::test]
    async fn v4_arc04_refused_remote_half_is_terminal_and_drives_exactly_one_native_close() {
        // The failure path that positive-only tests miss. A refusal is terminal
        // and drops the handoff there and then — which is what runs connector
        // retention — so the refused attempt neither strands the claim nor
        // releases it behind the close it is supposed to drive. The native
        // close is held on a gate so each of those is asserted at a point where
        // it is actually decided, rather than wherever the dedicated cleanup
        // thread happened to be.
        let owner = test_resource_owner(1, 1);
        let gate = TestNativeCloseGate::new();
        let (task, close_owner, _lifetime, calls) =
            auth_task_fixture_gated(&owner, Arc::clone(&gate));
        // Signed by a key that is not the expected remote Device.
        let (impostor_key, _) = auth_key(9);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        // Non-vacuity: the channel is claimed and nothing has closed yet, so
        // every transition below is one this refusal caused.
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(calls.load(Ordering::Acquire), 0);

        assert_eq!(
            drive_exchange(&task, &remote_c, &impostor_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "an impostor's half is refused with the exact typed cause"
        );
        assert_eq!(
            task.terminal_error(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "and the refusal is terminal for this exact task"
        );

        // No retry, and no promotion by a later genuine half. The task keeps the
        // cause that actually refused it rather than reporting whichever
        // lifecycle event reached it next, so a refused channel cannot be
        // reopened by supplying the key it was expecting all along.
        assert_eq!(
            drive_exchange(&task, &peer_draw(), &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "the first cause stands and the genuine remote cannot promote it"
        );

        // Exactly one native close begins, driven by the terminal release
        // itself: the task is still alive here, so nothing but the refusal put
        // this connector into close.
        tokio::time::timeout(Duration::from_secs(1), async {
            while calls.load(Ordering::Acquire) == 0 {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("terminal release drives the connector's native close");
        assert_eq!(calls.load(Ordering::Acquire), 1);

        // While that close is in flight the connected claim is still owned. An
        // unheld close could complete before this line, which is why the gate
        // exists: the claim releases on the confirmed close, never ahead of it.
        assert_eq!(
            owner.report().active_candidates,
            1,
            "the refusal must leave the channel claim owned while close is in flight"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "and the close cannot be terminal while the native dependency is held"
        );

        // Release the gate: the one native close succeeds and the claim goes
        // back with it.
        gate.open();
        tokio::time::timeout(Duration::from_secs(1), close_owner.wait())
            .await
            .expect("released native dependency completes")
            .expect("native close follows the terminal release");
        assert_eq!(calls.load(Ordering::Acquire), 1);
        assert_eq!(owner.report().active_candidates, 0);
        drop(task);
    }

    #[tokio::test]
    async fn v4_arc04_production_retirement_invalidates_the_endpoint_auth_task() {
        // Drives the *production* replacement path, `retire_connector`, rather
        // than calling `task.retire()` directly. Before this was wired, the
        // task survived replacement with `is_retired() == false` and its
        // handoff intact, so a late proof could still mint a capability —
        // install would reject it, but only after the fact. Retirement must
        // fail closed at the source.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let peer = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "retiring-peer".to_string(),
            Arc::clone(&task),
        );
        *peer.state.write() = admitted_legacy_state();
        peer.install_authenticated_channel_for_test();

        // Non-vacuity: everything is live and admitted before replacement.
        assert!(!task.is_retired());
        assert!(task.belongs_to(task.incarnation()));
        assert!(peer.has_authenticated_channel());

        // The exact production replacement call.
        peer.retire_connector();

        assert!(
            task.is_retired(),
            "replacement must retire the task at the source"
        );
        assert!(
            !task.belongs_to(task.incarnation()),
            "a retired task belongs to no connector"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "the channel authority must be gone immediately after replacement, which is what leaves nothing for the session gate to promote from"
        );

        // An exchange that would otherwise promote is now refused with the exact
        // typed cause, before any capability can be minted.
        let (remote_key, _remote_id) = auth_key(2);
        assert_eq!(
            drive_exchange(&task, &peer_draw(), &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent),
            "a superseded connector must refuse promotion, not merely fail to install"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "and no capability is installed by the attempt"
        );
    }

    #[tokio::test]
    async fn v4_arc04_retired_task_cannot_authenticate() {
        // Replacement invalidation is a security control here, not
        // housekeeping: with a certificate-fingerprint binding that is not
        // session-unique, exact incarnation ownership is what separates two
        // channels between the same pair.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);
        let remote_c = peer_draw();

        // The channel is replaced/retired before the proof arrives.
        task.retire();

        assert_eq!(
            drive_exchange(&task, &remote_c, &remote_key).err(),
            Some(crate::endpoint_auth::EndpointAuthError::ChannelNotCurrent),
            "a proof that would otherwise verify must not promote a retired channel"
        );
    }

    #[tokio::test]
    async fn v4_arc04_same_certificate_two_channels_bind_capabilities_to_distinct_incarnations() {
        // C5. Two channels between one device pair reusing the same
        // certificates, so the channel binding is identical by construction.
        let owner = test_resource_owner(3, 3);
        let (channel_one, _co1, _l1, _c1) = auth_task_fixture(&owner);
        let (channel_two, _co2, _l2, _c2) = auth_task_fixture(&owner);
        let (remote_key, _remote_id) = auth_key(2);

        // (a) NON-VACUITY. Both channels are built by the same fixture, so they
        // share one Device pair and one channel binding by construction — the
        // context is fixed inside `endpoint_auth`, identically for both. Nothing
        // cryptographic separates these two channels; if the fixture ever varied
        // the binding per channel this control would silently become a no-op
        // that passes while proving nothing.
        //
        // Channel 1 authenticates normally.
        let one_remote = peer_draw();
        let promoted = drive_exchange(&channel_one, &one_remote, &remote_key)
            .expect("channel 1 authenticates")
            .into_promoted()
            .expect("channel 1's promotion issues the capability");
        // The exact proof channel 1 accepted, captured for replay below.
        let one_remote_sig =
            crate::endpoint_auth::peer_proof_for_test(&channel_one, &one_remote, &remote_key);

        // (b) ORDINARY REPLAY. Channel 2 binds its own fresh peer contribution,
        // and its task drew its own local one, so channel 1's captured
        // signature does not cover channel 2's transcript. This is freshness
        // doing the work, not the binding.
        assert_eq!(
            drive_exchange_with_signature(&channel_two, &peer_draw(), &one_remote_sig).err(),
            Some(crate::endpoint_auth::EndpointAuthError::SignatureInvalid),
            "a replayed proof must not authenticate a channel with fresh contributions"
        );

        // (c) THE DISCRIMINATING CASE, stated honestly. Force a third channel to
        // reuse channel 1's exact contribution pair — its local draw as well as
        // the peer value, because forcing only the peer half leaves the local
        // halves different and this degenerates back into (b). With the binding
        // already equal, the two transcripts are now byte-identical and channel
        // 1's signature is cryptographically VALID over this one. Ownership
        // cannot and does not change that; asserting otherwise would be an
        // overclaim, so this asserts that it DOES promote.
        let (forced, _co3, _l3, _c3) =
            auth_task_fixture_reusing(&owner, &channel_one.local_contribution());
        let forced_capability =
            drive_exchange_with_signature(&forced, &one_remote, &one_remote_sig)
                .expect(
                    "with identical certificates and identical contributions the replayed proof \
                     is genuinely valid, and the task cannot tell where it was signed",
                )
                .into_promoted()
                .expect("the replayed proof genuinely promotes this third channel");

        // Two distinct mechanisms carry this, and they must not be conflated:
        //
        //  * Cross-channel *proof* replay is prevented by per-attempt
        //    contribution uniqueness, and by that alone — which is exactly what
        //    (c) just demonstrated by removing it. In production that case does
        //    not arise: the task draws its own contribution at `begin` and
        //    `LocalContribution` has no constructor that rebuilds one from bytes
        //    outside `cfg(test)`. Non-`Clone` prevents casual duplication; it is
        //    not by itself the guarantee.
        //
        //  * Ownership prevents *already-issued authority* from transferring
        //    across channels or surviving replacement. That is what the
        //    assertions below cover, and what
        //    `v4_arc04_install_refuses_a_capability_from_another_incarnation`
        //    exercises through the real install path.
        //
        // So even where the proof replays, the authority does not: the
        // capability minted from the replayed proof belongs to the channel that
        // ran the exchange, never to channel 1.
        assert!(
            forced_capability.belongs_to(forced.incarnation()),
            "a replayed-but-valid proof mints authority bound to the channel that ran it"
        );
        assert!(
            !forced_capability.belongs_to(channel_one.incarnation()),
            "and that authority is not channel 1's, valid proof or not"
        );
        assert!(
            promoted.belongs_to(channel_one.incarnation()),
            "non-vacuity: the predicate is not constantly false"
        );
        assert!(
            !promoted.belongs_to(channel_two.incarnation()),
            "a capability promoted on channel 1 must not be installable against \
             channel 2, valid proof or not"
        );
        assert!(
            !Arc::ptr_eq(channel_one.incarnation(), channel_two.incarnation()),
            "the two fixtures really are distinct incarnations"
        );
        drop(forced_capability);
        drop(promoted);
    }

    /// Promote one channel to an authenticated capability, for install tests.
    fn promote_for_install(
        task: &Arc<crate::endpoint_auth::EndpointAuthTask>,
    ) -> crate::endpoint_auth::AuthenticatedChannelCapability {
        let (remote_key, _remote_id) = auth_key(2);
        drive_exchange(task, &peer_draw(), &remote_key)
            .expect("the fixture proof promotes")
            .into_promoted()
            .expect("the promotion issues the capability")
    }

    /// Peer state that legacy policy would call admitted.
    fn admitted_legacy_state() -> crate::engine::connection::PeerStateData {
        crate::engine::connection::PeerStateData {
            authenticated: true,
            status: crate::engine::connection::PeerStatus::Active,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn v4_arc04_application_admission_requires_a_live_capability_not_just_the_legacy_bool() {
        // The enforcement half. Storing the capability is not the same as
        // gating on it: `authenticated` records policy history and survives
        // channel replacement, so a gate reading only the bool would keep
        // admitting application traffic after the authority artifact is gone.
        let owner = test_resource_owner(1, 1);
        let (task, _close_owner, _lifetime, _calls) = auth_task_fixture(&owner);
        let peer = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "gate-peer".to_string(),
            Arc::clone(&task),
        );

        // This control owns the *channel-authority* half of admission. The
        // policy half moved to the broker, where `CurrentPolicyAdmission` is a
        // promotion conjunct with its own negative control — this fixture holds
        // no registry and no broker, so it cannot promote and must not pretend
        // to test policy.

        // (1) Legacy bool set, no capability installed → no channel authority.
        *peer.state.write() = admitted_legacy_state();
        assert!(
            peer.state.read().is_admitted(),
            "non-vacuity: legacy policy really does consider this admitted"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "the legacy bool alone establishes no channel authority, so there is \
             nothing for the session gate to promote from"
        );

        // (2) Capability installed on the current connector → authority present.
        let capability = promote_for_install(&task);
        assert!(peer.install_authenticated_channel(&task, capability));
        assert!(peer.has_authenticated_channel());

        // (3) Replacement invalidates immediately, while the registry entry and
        // the legacy bool are both untouched.
        peer.retire_connector();
        assert!(
            peer.state.read().is_admitted(),
            "the legacy bool is deliberately left set, which is why it could \
             never have been the gate"
        );
        assert!(
            !peer.has_authenticated_channel(),
            "retiring the connector drops the channel authority at once"
        );
    }

    #[tokio::test]
    async fn v4_arc04_install_refuses_a_capability_from_another_incarnation() {
        // The install-path half of C5, and the one that actually fails if the
        // capability/incarnation binding is removed from
        // `install_authenticated_channel`. Both channels share device
        // identities and certificate fingerprints, so nothing cryptographic
        // separates them — only provenance does.
        let owner = test_resource_owner(3, 3);
        let (task_one, _co1, _l1, _c1) = auth_task_fixture(&owner);
        let (task_two, _co2, _l2, _c2) = auth_task_fixture(&owner);
        // A third live channel, so the negative case uses a capability this
        // test still owns rather than one already moved into `peer_one`.
        let (task_three, _co3, _l3, _c3) = auth_task_fixture(&owner);
        assert!(
            !Arc::ptr_eq(task_one.incarnation(), task_two.incarnation()),
            "non-vacuity: the fixtures are genuinely distinct incarnations"
        );

        // POSITIVE: a capability installs on the peer whose current task
        // promoted it. Without this the negative case below could pass simply
        // because install always refuses.
        let cap_one = promote_for_install(&task_one);
        let peer_one = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "peer-one".to_string(),
            Arc::clone(&task_one),
        );
        assert!(
            peer_one.install_authenticated_channel(&task_one, cap_one),
            "a capability must install against the task that promoted it"
        );
        assert!(peer_one.has_authenticated_channel());

        // NEGATIVE: channel 2's task is current on its own peer, but the
        // capability came from channel 1. Checking only that the *task* is
        // current would accept this, which is the cross-channel relay.
        let relayed = promote_for_install(&task_three);
        let peer_two = crate::engine::connection::PeerConnection::with_endpoint_auth_for_test(
            "peer-two".to_string(),
            Arc::clone(&task_two),
        );
        assert!(
            !peer_two.install_authenticated_channel(&task_two, relayed),
            "a capability promoted on another connector incarnation must not \
             install, even with the current task supplied alongside it"
        );
        assert!(
            !peer_two.has_authenticated_channel(),
            "and nothing is left installed after the refusal"
        );
    }

    #[tokio::test]
    async fn v4_arc04_promoted_capability_retains_the_connected_claim_until_native_close() {
        // Promotion must carry the *whole* handoff. If it moved only the
        // connected capability, dropping the authenticated capability — on
        // retirement, or on a refused install — would release the claim
        // directly and defeat Arc 03's "retained until native close succeeds".
        let owner = test_resource_owner(1, 1);
        // A *gated* native close, so the interval between "close entered" and
        // "close succeeded" is observable. With an immediate close, an early
        // release would produce the same before/after readings and the control
        // would not discriminate.
        let gate = TestNativeCloseGate::new();
        let (close_owner, _lifetime) = close_owner_fixture(&owner);
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(Arc::clone(&gate)),
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = Arc::new(task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        )));
        let (remote_key, _remote_id) = auth_key(2);
        let promoted = drive_exchange(&task, &peer_draw(), &remote_key)
            .expect("promotes")
            .into_promoted()
            .expect("the promotion issues the capability");
        assert_eq!(
            owner.report().active_candidates,
            1,
            "promotion does not release the connected claim"
        );

        // Dropping the authenticated capability is what a retirement or a
        // refused install does. The claim must survive into native close.
        drop(promoted);
        drop(task);

        // Native close has now been entered but is blocked on the gate. This
        // is the load-bearing interval: if promotion had stripped the handoff
        // and the capability released the claim directly, the claim would
        // already be gone here.
        let closing = tokio::spawn({
            let close_owner = Arc::clone(&close_owner);
            async move { close_owner.wait().await }
        });
        // Wait on the gate's own entry rather than on the port's call counter.
        // The counter is bumped before the returned future is polled, so it
        // reports a close that has been *submitted*; the gate publishes from
        // inside the held future, so it reports one that has genuinely reached
        // the hold point. Every wait below is bounded, so a regression that
        // reintroduces a lost wake fails this named control at its deadline
        // instead of hanging the suite.
        tokio::time::timeout(Duration::from_secs(1), gate.wait_for_entry())
            .await
            .expect("the promoted claim's native close reaches the hold point");
        assert_eq!(
            gate.entries(),
            1,
            "native close is entered exactly once, and is still held here"
        );
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "and that entry is the one submitted close, not a second port call"
        );
        assert_eq!(
            owner.report().active_candidates,
            1,
            "the connected claim must still be retained while native close is in flight"
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(20), close_owner.wait())
                .await
                .is_err(),
            "and the close cannot be terminal while the gate still holds it"
        );

        // Release. The permit is stored, so it is observed even if it is
        // published before the held close parks — the exact window in which a
        // wake-only primitive would drop it and strand this control.
        gate.open();
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .expect("the released native close completes")
            .expect("close task joins")
            .expect("native close succeeds once released");
        assert_eq!(
            calls.load(Ordering::Acquire),
            1,
            "exactly one native close: no double retention, no missed release"
        );
        assert_eq!(
            gate.entries(),
            1,
            "and the release drove that one close through, not a repeat of it"
        );
        assert_eq!(
            owner.report().active_candidates,
            0,
            "and the claim is released only after close succeeded"
        );
    }

    #[tokio::test]
    async fn v4_arc03_transport_object_stays_charged_until_gated_native_close_succeeds() {
        let owner = test_resource_owner(1, 1);
        let observation_scope = transport_observation_scope();
        let gate = TestNativeCloseGate::new();
        let (close_owner, _lifetime) =
            close_owner_fixture_with_observation(&owner, Some(&observation_scope));
        let calls = Arc::new(AtomicUsize::new(0));
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Gate(Arc::clone(&gate)),
                calls: Arc::clone(&calls),
            }))
        );
        let connected = match close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let task = Arc::new(task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        )));

        let before = transport_object_report(&observation_scope);
        assert_eq!(before.active.items(), 1);
        assert_eq!(before.active_lease_count, 1);
        assert!(before.oldest_active_lifetime.is_some());
        assert!(!before.oldest_active_lifetime_inexact);
        assert!(Arc::strong_count(&task) >= 1, "worker Arc remains retained");

        let closing = tokio::spawn({
            let close_owner = Arc::clone(&close_owner);
            async move { close_owner.wait().await }
        });
        tokio::time::timeout(Duration::from_secs(1), gate.wait_for_entry())
            .await
            .expect("native close reaches the exact gate");
        let during = transport_object_report(&observation_scope);
        assert_eq!(during.active.items(), 1);
        assert_eq!(during.active_lease_count, 1);
        assert!(during.oldest_active_lifetime.is_some());
        assert!(!during.oldest_active_lifetime_inexact);
        assert_eq!(calls.load(Ordering::Acquire), 1);

        gate.open();
        tokio::time::timeout(Duration::from_secs(1), closing)
            .await
            .expect("gated close completes")
            .expect("close task joins")
            .expect("native close succeeds");
        let after = transport_object_report(&observation_scope);
        assert_eq!(after.active, ResourceUse::ZERO);
        assert_eq!(after.active_lease_count, 0);
        assert!(after.oldest_active_lifetime.is_none());
        assert!(!after.oldest_active_lifetime_inexact);
        assert!(
            Arc::strong_count(&task) >= 1,
            "worker Arc remains after terminal"
        );
    }

    #[tokio::test]
    async fn v4_arc03_transport_object_fail_close_retains_charge_until_owner_drop() {
        let owner = test_resource_owner(2, 1);
        let observation_scope = transport_observation_scope();
        let (close_owner, _lifetime) =
            close_owner_fixture_with_observation(&owner, Some(&observation_scope));
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
        let task = Arc::new(task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&close_owner.ownership.incarnation),
            Arc::clone(&close_owner),
        )));

        let error = close_owner
            .wait()
            .await
            .expect_err("native close failure is fail closed");
        assert!(error.to_string().contains("injected native close failure"));
        assert_eq!(calls.load(Ordering::Acquire), 1);
        let failed = transport_object_report(&observation_scope);
        assert_eq!(failed.active.items(), 1);
        assert_eq!(failed.active_lease_count, 1);
        assert!(failed.oldest_active_lifetime.is_some());
        assert!(!failed.oldest_active_lifetime_inexact);
        assert!(
            Arc::strong_count(&task) >= 1,
            "worker Arc remains on failure"
        );

        drop(task);
        let retained = transport_object_report(&observation_scope);
        assert_eq!(retained.active.items(), 1);
        assert_eq!(retained.active_lease_count, 1);
        drop(close_owner);
        let released = transport_object_report(&observation_scope);
        assert_eq!(released.active, ResourceUse::ZERO);
        assert_eq!(released.active_lease_count, 0);
        assert!(released.oldest_active_lifetime.is_none());
        assert!(!released.oldest_active_lifetime_inexact);
    }

    #[tokio::test]
    async fn v4_arc03_native_close_before_endpoint_handoff_release_keeps_claim_visible() {
        let owner = test_resource_owner(1, 1);
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
        let task = task_from_handoff(EndpointAuthHandoff::new(
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
        let owner = test_resource_owner(2, 1);
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
        let task = task_from_handoff(EndpointAuthHandoff::new(
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
    fn v4_arc03_cross_connector_endpoint_auth_capabilities_are_rejected() {
        let owner = test_resource_owner(2, 1);
        let (first_close_owner, _first_lifetime) = close_owner_fixture(&owner);
        let (second_close_owner, _second_lifetime) = close_owner_fixture(&owner);
        let connected = match first_close_owner.ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("fixture connector promotes"),
        };
        let first_task = task_from_handoff(EndpointAuthHandoff::new(
            connected,
            Arc::clone(&first_close_owner.ownership.incarnation),
            Arc::clone(&first_close_owner),
        ));

        assert!(first_close_owner.ownership.owns_endpoint_auth(&first_task));
        assert!(!second_close_owner.ownership.owns_endpoint_auth(&first_task));

        first_close_owner.retire_local();
        assert!(!first_close_owner.ownership.owns_endpoint_auth(&first_task));
        drop(first_task);
    }

    #[test]
    fn v4_arc03_connector_operations_require_and_release_exact_work_claims() {
        let owner = test_resource_owner(1, 1);
        let (close_owner, _lifetime) = close_owner_fixture(&owner);

        let first = close_owner
            .ownership
            .enter_operation()
            .expect("fixture provider grants one connector operation");
        let pressure = match close_owner.ownership.enter_operation() {
            Ok(_) => panic!("a second operation has no unowned work capacity"),
            Err(error) => error,
        };
        assert!(pressure.to_string().contains("resource pressure"));

        drop(first);
        let replacement = close_owner
            .ownership
            .enter_operation()
            .expect("dropping the exact operation restores its work capacity");
        drop(replacement);
    }

    #[tokio::test]
    async fn v4_arc03_connector_retirement_before_promotion_rejects_and_cleans() {
        let owner = test_resource_owner(1, 1);
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
        let mut queue = PendingRemoteCandidateQueue::new();
        assert_eq!(
            queue.push_observed_for_test(
                candidate,
                Arc::new(RemoteCandidateAttemptIdentity::default()),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
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
    fn v4_arc03_candidate_queue_reserves_actual_string_capacity_before_node_insertion() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut candidate = observed_candidate();
        let mut state = RemoteCandidateState::new(test_candidate_fixture_work());
        let pressure = state
            .current
            .work_resources
            .pressure(
                crate::resource::ResourceAuthorityClass::Speculative,
                crate::resource::ResourceClass::AccountedMemoryBytes,
            )
            .expect("fixture provider reports its exact remaining capacity");
        let remaining = pressure
            .capacity
            .checked_sub(pressure.in_use)
            .and_then(|bytes| usize::try_from(bytes).ok())
            .expect("fixture remaining capacity is representable");
        let mut inflated = String::with_capacity(
            candidate
                .candidate
                .len()
                .checked_add(remaining)
                .and_then(|capacity| capacity.checked_add(1))
                .expect("fixture capacity is representable"),
        );
        inflated.push_str(&candidate.candidate);
        candidate.candidate = inflated;

        assert!(matches!(
            state.admit(candidate, &scope),
            PendingRemoteCandidateQueuePush::ResourceUnavailable(ResourceUnavailable::Pressure(_))
        ));
        assert!(state.current.pending.entries.is_empty());
        assert!(state.current.seen.is_empty());
        assert!(!state.current.attempt.is_active());
    }

    #[test]
    fn v4_arc03_applied_candidate_pressure_refuses_before_native_mutation() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let candidate = observed_candidate();
        let content =
            candidate_content_bytes(&candidate).expect("fixture content is representable");
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge =
            crate::resource::FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                .expect("applied candidate reservation charge is representable");
        let held_claim_fixture_slack = crate::resource::ResourceClaim::single(
            crate::resource::ResourceClass::AccountedMemoryBytes,
            64,
        );
        let fixture_additional = retained_charge
            .checked_add(held_claim_fixture_slack)
            .expect("held retained-claim fixture slack is representable");
        let (_provider, _owner, _candidate, _lifetime, work_resources) =
            elastic_remote_candidate_test_resources_with_additional(
                RemoteCandidateFixtureWork::new(1, content),
                fixture_additional,
            );
        let mut state = RemoteCandidateState::with_resources(work_resources.clone());
        assert_eq!(
            state.admit(candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let mut pending = state
            .current
            .pending
            .pop_last_for_application(&scope)
            .expect("the funded candidate reaches application");
        let mut application = pending
            ._elastic_lease
            .take()
            .expect("the queued candidate retains its elastic lease")
            .begin_apply()
            .expect("the queued candidate enters application ownership");
        let _held_retained_claim = work_resources
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                retained_claim,
            )
            .expect("the fixture holds the exact retained claim to create pressure");
        let mut native_called = false;
        let transition = match application.transition_after_application(retained_claim) {
            Ok(()) => {
                native_called = true;
                Ok(())
            }
            Err(error) => Err(error),
        };
        assert!(
            matches!(transition, Err(ResourceUnavailable::Pressure(_))),
            "the exact retained claim is refused while its capacity is held"
        );
        assert!(
            !native_called,
            "native mutation follows successful custody admission"
        );
        state.current.retire();
    }

    #[test]
    fn v4_arc03_applied_candidate_success_moves_ownership_into_attempt_custody() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let candidate = observed_candidate();
        let content =
            candidate_content_bytes(&candidate).expect("fixture content is representable");
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge =
            crate::resource::FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                .expect("applied candidate reservation charge is representable");
        let (_provider, _owner, _candidate, _lifetime, work_resources) =
            elastic_remote_candidate_test_resources_with_additional(
                RemoteCandidateFixtureWork::new(1, content),
                retained_charge,
            );
        let mut state = RemoteCandidateState::with_resources(work_resources);
        assert_eq!(
            state.admit(candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let mut pending = state
            .current
            .pending
            .pop_last_for_application(&scope)
            .expect("the funded candidate reaches application");
        let mut application = pending
            ._elastic_lease
            .take()
            .expect("the queued candidate retains its elastic lease")
            .begin_apply()
            .expect("the queued candidate enters application ownership");
        application
            .transition_after_application(retained_claim)
            .expect("the exact retained claim is admitted before native success");
        let mut reservation = pending
            ._queue_reservation
            .take()
            .expect("the queued candidate retains its custody slot");
        reservation.application = Some(application);
        state.current.retained_reservations.push_back(reservation);
        assert_eq!(state.current.retained_reservations.len(), 1);
        assert!(state
            .current
            .retained_reservations
            .front()
            .and_then(|reservation| reservation.application.as_ref())
            .is_some());
        state.current.retire();
    }

    #[test]
    /// One digest, one retention: a repeat submission is refused before it can
    /// take a second retention lease.
    ///
    /// The control used to also drive an item ceiling and a content-byte
    /// ceiling to refusal. Neither exists, so what is left is the half that was
    /// never a ceiling at all — the digest set — plus the fact that a candidate
    /// the fixture's grant cannot fund is refused by the provider.
    fn v4_arc03g_candidate_queue_deduplicates_before_retention() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let first = observed_candidate();
        let content_bytes =
            candidate_content_bytes(&first).expect("fixture content is representable");
        let two_candidates = content_bytes
            .checked_mul(2)
            .expect("two candidate contents are representable");

        let mut item_bounded =
            RemoteCandidateState::new(RemoteCandidateFixtureWork::new(2, two_candidates));
        assert_eq!(
            item_bounded.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(
            item_bounded.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        assert_eq!(item_bounded.current.seen.len(), 1);
        let mut distinct = first.clone();
        distinct.candidate.replace_range(0..1, "C");
        assert_eq!(
            candidate_content_bytes(&distinct),
            Some(content_bytes),
            "fixture variation keeps the byte test independent from item count"
        );
        assert_eq!(
            item_bounded.admit(distinct.clone(), &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "a distinct candidate the grant funds is retained, not refused by a count"
        );
        assert_eq!(item_bounded.current.seen.len(), 2);

        // A grant funded for exactly one candidate refuses the second, and the
        // refusal comes from the provider rather than from a number beside it.
        let mut exactly_one =
            RemoteCandidateState::new(RemoteCandidateFixtureWork::new(1, content_bytes));
        assert_eq!(
            exactly_one.admit(first, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        // A provider refusal is terminal for the attempt, and the digest set goes
        // with it. Every refusal path in `RemoteCandidateAttemptEnvelope::admit`
        // calls `retire()` before returning, and `retire()` clears `seen` along
        // with the queue and the retained reservations. So there is no outcome
        // in which the second candidate is refused and the first candidate's
        // digest survives — an earlier version of this control asserted exactly
        // that, and it was asserting a state the type cannot reach.
        //
        // This is deliberate rather than a leak: a candidate the owner's grant
        // cannot fund ends the ICE attempt, and the caller restarts. Retaining
        // digests for an attempt that is already dead would be keeping dedup
        // state for submissions that can only ever be answered `Retired`.
        assert!(
            matches!(
                exactly_one.admit(distinct, &scope),
                PendingRemoteCandidateQueuePush::ResourceUnavailable(_)
                    | PendingRemoteCandidateQueuePush::Retired
            ),
            "the second candidate is refused by the provider"
        );
        assert!(
            !exactly_one.current.attempt.is_active(),
            "the refusal retired the attempt"
        );
        assert!(
            exactly_one.current.seen.is_empty(),
            "and released its digests with it, rather than retaining dedup state \
             for an attempt that can only answer `Retired`"
        );
    }

    #[test]
    fn v4_arc03h_candidate_content_bytes_cover_every_candidate_content_field() {
        let candidate = LocalIceCandidate {
            candidate: "candidate-content".to_string(),
            sdp_mid: Some("mid".to_string()),
            sdp_mline_index: Some(7),
            username_fragment: Some("ufrag".to_string()),
        };
        assert_eq!(
            candidate_content_bytes(&candidate),
            Some("candidate-content".len() + "mid".len() + size_of::<u16>() + "ufrag".len())
        );
    }

    #[test]
    fn v4_arc03h_candidate_digest_is_structurally_unambiguous() {
        let mut first = observed_candidate();
        first.candidate = "a".to_string();
        first.sdp_mid = Some("b\0".to_string());
        first.sdp_mline_index = None;
        first.username_fragment = None;
        let mut second = first.clone();
        second.candidate = "a\0b".to_string();
        second.sdp_mid = None;

        assert_ne!(first, second);
        assert_ne!(
            candidate_content_digest(&first),
            candidate_content_digest(&second),
            "field boundaries participate in duplicate identity"
        );
    }

    #[test]
    fn v4_arc03i_candidate_digest_distinguishes_absent_and_maximum_mline_index() {
        let mut absent = observed_candidate();
        absent.sdp_mline_index = None;
        let mut maximum = absent.clone();
        maximum.sdp_mline_index = Some(u16::MAX);

        assert_ne!(
            candidate_content_digest(&absent),
            candidate_content_digest(&maximum),
            "option presence participates in duplicate identity"
        );
    }

    #[test]
    fn v4_arc03h_candidate_attempt_envelope_survives_delayed_apply_and_cancellation() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let candidate = observed_candidate();
        let mut queue = PendingRemoteCandidateQueue::new();
        assert_eq!(
            queue.push_observed_for_test(
                candidate,
                Arc::new(RemoteCandidateAttemptIdentity::default()),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
        let mut drain = queue.take();
        let pending = drain
            .next()
            .expect("delayed SDP drains the queued candidate");
        let mut application = Box::pin(apply_pending_remote_candidate(pending, |_| {
            std::future::pending::<std::result::Result<(), ()>>()
        }));
        let waker = Waker::noop();
        let mut task_context = Context::from_waker(waker);
        assert_eq!(application.as_mut().poll(&mut task_context), Poll::Pending);

        drop(application);
        drop(drain);
    }

    #[test]
    fn v4_arc03h_new_attempt_gets_a_fresh_candidate_envelope() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let work = test_candidate_fixture_work();
        let mut state = RemoteCandidateState::new(work);
        assert_eq!(
            state.current.pending.push_observed_for_test(
                observed_candidate(),
                Arc::clone(&state.current.attempt),
                &scope,
            ),
            PendingRemoteCandidateQueuePush::Queued
        );
        assert_eq!(state.current.pending.entries.len(), 1);

        let displaced = std::mem::replace(&mut state, RemoteCandidateState::new(work));
        drop(displaced);
        assert!(state.current.pending.entries.is_empty());
        assert!(state.current.seen.is_empty());
    }

    #[tokio::test]
    async fn v4_arc03j_local_ice_restart_is_provisional_until_explicit_commit() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state = RemoteCandidateState::new(test_candidate_fixture_work());
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let old_attempt = Arc::clone(&state.current.attempt);
        let old_operation = old_attempt
            .try_enter()
            .expect("old attempt admits work before restart");
        let (retiring, replacement) = state
            .begin_local_ice_restart()
            .expect("one local restart becomes provisional");

        assert!(Arc::ptr_eq(&old_attempt, &retiring));
        assert!(!old_attempt.is_active());
        assert!(Arc::ptr_eq(&old_attempt, &state.current.attempt));
        assert!(!state.current.attempt.is_active());
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement is provisional");
        assert!(Arc::ptr_eq(&replacement, &provisional.envelope.attempt));
        assert!(provisional.envelope.attempt.is_active());
        assert!(!provisional.envelope.remote_description_set);
        assert!(provisional.envelope.pending.entries.is_empty());

        let replacement_candidate = observed_candidate();
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement remains provisional");
        assert_eq!(provisional.envelope.pending.entries.len(), 1);
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &replacement
        ));
        assert!(
            !provisional.envelope.remote_description_set,
            "replacement candidates remain held until replacement SDP commits"
        );

        let mut waiting = Box::pin(retiring.wait_for_operations());
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err()
        );
        drop(old_operation);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("restart barrier releases after old work retires");

        state
            .commit_local_ice_restart(&replacement)
            .expect("native success commits the exact provisional replacement");
        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &replacement));
        assert_eq!(state.current.pending.entries.len(), 1);
        assert!(
            state.current.provisional_root_lease.is_none(),
            "steady state cannot retain the provisional overlap root"
        );
    }

    #[test]
    fn v4_arc03_local_restart_overlap_charge_releases_on_commit_and_failure() {
        let policy = test_candidate_fixture_work();
        let root_claim = crate::runtime::attempt::remote_candidate_attempt_root_claim()
            .expect("fixture restart root claim is representable");
        let overlap_charge = FiniteResourceProvider::reservation_charge_for_test(root_claim)
            .expect("fixture restart reservation charge is representable");
        let (provider, _owner, _candidate, _lifetime, work_scope) =
            elastic_remote_candidate_test_resources_with_additional(policy, overlap_charge);
        let mut state = RemoteCandidateState::with_resources(work_scope);
        let baseline = provider.in_use();

        let (_, replacement) = state
            .begin_local_ice_restart()
            .expect("the exact overlap charge admits one provisional restart");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(overlap_charge)
                .expect("fixture overlap total is representable")
        );
        state
            .commit_local_ice_restart(&replacement)
            .expect("commit installs the replacement attempt");
        assert_eq!(provider.in_use(), baseline);

        let (_, failed_replacement) = state
            .begin_local_ice_restart()
            .expect("the restored capacity admits another provisional restart");
        assert_eq!(
            provider.in_use(),
            baseline
                .checked_add(overlap_charge)
                .expect("fixture overlap total is representable")
        );
        state.fail_provisional(&failed_replacement);
        assert_eq!(provider.in_use(), baseline);
    }

    #[tokio::test]
    async fn v4_arc03_dropped_ice_transaction_fences_attempt_and_starts_exact_close_owner() {
        let policy = test_candidate_fixture_work();
        let state = Arc::new(SyncMutex::new(
            RemoteCandidateState::new_with_restart_overlap(policy),
        ));
        let resource_owner = test_resource_owner(1, 1);
        let (close_owner, _attempt_lifetime) = close_owner_fixture(&resource_owner);
        assert!(close_owner.attach_remote_candidates(Arc::clone(&state)));

        let replacement = {
            let mut candidate_state = state.lock();
            let (_, replacement) = candidate_state
                .begin_local_ice_restart()
                .expect("fixture local restart becomes provisional");
            replacement
        };
        let transaction = UncommittedIceTransaction::new(
            Arc::clone(&state),
            Arc::clone(&close_owner),
            Arc::clone(&replacement),
        );

        drop(transaction);

        {
            let candidate_state = state.lock();
            assert!(candidate_state.provisional.is_none());
            assert!(!candidate_state.current.attempt.is_active());
            assert!(!replacement.is_active());
        }
        close_owner
            .wait()
            .await
            .expect("the exact close owner completes after cancellation");
    }

    #[tokio::test]
    async fn v4_arc03_disarmed_ice_transaction_preserves_committed_attempt() {
        let state = Arc::new(SyncMutex::new(RemoteCandidateState::new(
            test_candidate_fixture_work(),
        )));
        let resource_owner = test_resource_owner(1, 1);
        let (close_owner, _attempt_lifetime) = close_owner_fixture(&resource_owner);
        assert!(close_owner.attach_remote_candidates(Arc::clone(&state)));
        let attempt = Arc::clone(&state.lock().current.attempt);
        let mut transaction = UncommittedIceTransaction::new(
            Arc::clone(&state),
            Arc::clone(&close_owner),
            Arc::clone(&attempt),
        );

        transaction.disarm();
        drop(transaction);

        assert!(
            state.lock().current.attempt.is_active(),
            "disarming after the exact reservation commit preserves the attempt"
        );
        close_owner.start();
        close_owner
            .wait()
            .await
            .expect("the explicit cleanup completes after the disarmed proof");
    }

    #[tokio::test]
    async fn v4_arc03_dropped_remote_description_cannot_leave_reusable_inflight_state() {
        let state = Arc::new(SyncMutex::new(RemoteCandidateState::new(
            test_candidate_fixture_work(),
        )));
        let resource_owner = test_resource_owner(1, 1);
        let (close_owner, _attempt_lifetime) = close_owner_fixture(&resource_owner);
        assert!(close_owner.attach_remote_candidates(Arc::clone(&state)));
        let prepared = state
            .lock()
            .prepare_remote_description(
                sdp_ice_credentials(&exact_ice_sdp("cancel-u", "cancel-p", "AA:BB:CC:DD"))
                    .expect("fixture remote credentials are exact"),
            )
            .expect("fixture remote description enters its transaction");
        assert!(state.lock().current.remote_description_in_flight);
        let transaction = UncommittedIceTransaction::new(
            Arc::clone(&state),
            Arc::clone(&close_owner),
            Arc::clone(&prepared.attempt),
        );

        drop(transaction);

        {
            let candidate_state = state.lock();
            assert!(!candidate_state.current.remote_description_in_flight);
            assert!(!candidate_state.current.attempt.is_active());
        }
        close_owner
            .wait()
            .await
            .expect("remote-description cancellation closes the exact connector");
    }

    #[test]
    fn v4_arc03j_local_restart_failure_discards_replacement_without_rollback() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state = RemoteCandidateState::new(test_candidate_fixture_work());
        let old_attempt = Arc::clone(&state.current.attempt);
        let (_retiring, replacement) = state
            .begin_local_ice_restart()
            .expect("local restart becomes provisional");
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );

        state.fail_provisional(&replacement);

        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &old_attempt));
        assert!(!state.current.attempt.is_active());
        assert!(!replacement.is_active());
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Retired,
            "failure cannot publish or renew a candidate envelope"
        );
    }

    #[tokio::test]
    async fn v4_arc03j_remote_same_fingerprint_credential_change_is_transactional() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut replacement_candidate = observed_candidate();
        replacement_candidate.username_fragment = Some("second-fragment".to_string());
        let candidate_bytes = candidate_content_bytes(&replacement_candidate)
            .expect("fixture candidate content is representable");
        let mut state =
            RemoteCandidateState::new(RemoteCandidateFixtureWork::new(2, candidate_bytes * 2));
        let fingerprint = "AA:BB:CC:DD";
        let initial_sdp = exact_ice_sdp("remote-fragment", "old-password", fingerprint);
        let initial = state
            .prepare_remote_description(
                sdp_ice_credentials(&initial_sdp).expect("initial credentials are exact"),
            )
            .expect("initial description uses the current attempt");
        assert!(!initial.provisional);
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial description commits"),
        );
        let old_attempt = Arc::clone(&state.current.attempt);
        let old_operation = old_attempt
            .try_enter()
            .expect("old candidate work can be in flight");

        let replacement_sdp = exact_ice_sdp("second-fragment", "new-password", fingerprint);
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "a replacement candidate may arrive before its replacement SDP"
        );
        assert_eq!(state.current.pending.entries.len(), 1);
        assert_eq!(
            sdp_fingerprint(&initial_sdp),
            sdp_fingerprint(&replacement_sdp),
            "DTLS identity is unchanged for an in-place remote ICE restart"
        );
        let prepared = state
            .prepare_remote_description(
                sdp_ice_credentials(&replacement_sdp).expect("replacement credentials are exact"),
            )
            .expect("changed ICE credentials create a provisional replacement");
        assert!(prepared.provisional);
        assert!(!old_attempt.is_active());
        assert!(Arc::ptr_eq(&state.current.attempt, &old_attempt));
        assert!(state.provisional.is_some());

        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement stays provisional");
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));

        let mut waiting = Box::pin(
            prepared
                .retiring
                .as_ref()
                .expect("remote restart retires the previous attempt")
                .wait_for_operations(),
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(10), &mut waiting)
                .await
                .is_err(),
            "a delayed old-attempt completion holds the replacement barrier"
        );
        drop(old_operation);
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("old-attempt work eventually drains");

        let pending = state
            .commit_remote_description(&prepared)
            .expect("native SDP success commits the exact replacement");
        assert_eq!(pending.len(), 1);
        assert!(state.provisional.is_none());
        assert!(Arc::ptr_eq(&state.current.attempt, &prepared.attempt));

        let mut old_candidate = observed_candidate();
        old_candidate.username_fragment = Some("remote-fragment".to_string());
        assert_eq!(
            state.admit(old_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "a delayed old candidate is retained only as bounded future-SDP work"
        );
        assert!(state.current.attempt.is_active());
        assert!(!state.current.last_candidate_matches_remote_credentials());
    }

    #[test]
    fn v4_arc03j_remote_restart_migrates_only_explicit_replacement_candidates() {
        fn initialized_state() -> RemoteCandidateState {
            let mut state =
                RemoteCandidateState::new_with_restart_overlap(test_candidate_fixture_work());
            let initial = state
                .prepare_remote_description(
                    sdp_ice_credentials(&exact_ice_sdp("old-u", "old-p", "AA:BB:CC:DD"))
                        .expect("initial credentials are exact"),
                )
                .expect("initial remote description starts");
            drop(
                state
                    .commit_remote_description(&initial)
                    .expect("initial remote description commits"),
            );
            state
        }

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let replacement = sdp_ice_credentials(&exact_ice_sdp("new-u", "new-p", "AA:BB:CC:DD"))
            .expect("replacement credentials are exact");

        let mut state = initialized_state();
        let mut location_only = observed_candidate();
        location_only.username_fragment = None;
        assert_eq!(
            state.admit(location_only, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        assert!(
            state
                .provisional
                .as_ref()
                .expect("replacement stays provisional")
                .envelope
                .pending
                .entries
                .is_empty(),
            "a location-only candidate owned by the old attempt cannot migrate"
        );
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let mut replacement_candidate = observed_candidate();
        replacement_candidate.username_fragment = Some("new-u".to_string());
        assert_eq!(
            state.admit(replacement_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        let migrated = &state
            .provisional
            .as_ref()
            .expect("replacement stays provisional")
            .envelope
            .pending
            .entries;
        assert_eq!(migrated.len(), 1);
        assert!(Arc::ptr_eq(
            &migrated
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let mut old_candidate = observed_candidate();
        old_candidate.username_fragment = Some("old-u".to_string());
        assert_eq!(
            state.admit(old_candidate, &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let prepared = state
            .prepare_remote_description(replacement.clone())
            .expect("changed credentials create a replacement attempt");
        assert!(
            state
                .provisional
                .as_ref()
                .expect("replacement stays provisional")
                .envelope
                .pending
                .entries
                .is_empty(),
            "an old-credential candidate cannot migrate into the replacement attempt"
        );
        state.fail_remote_description(&prepared);

        let mut state = initialized_state();
        let prepared = state
            .prepare_remote_description(replacement)
            .expect("changed credentials create a replacement attempt");
        let mut replacement_owned_location = observed_candidate();
        replacement_owned_location.username_fragment = None;
        assert_eq!(
            state.admit(replacement_owned_location, &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "the exact provisional owner may admit a location-only candidate"
        );
        let provisional = state
            .provisional
            .as_ref()
            .expect("replacement stays provisional");
        assert_eq!(provisional.envelope.pending.entries.len(), 1);
        assert!(Arc::ptr_eq(
            &provisional
                .envelope
                .pending
                .entries
                .front()
                .expect("replacement queue contains its candidate")
                .attempt,
            &prepared.attempt
        ));
        assert_eq!(
            state
                .commit_remote_description(&prepared)
                .expect("replacement description commits")
                .len(),
            1,
            "a location-only candidate admitted by the replacement owner survives commit"
        );
    }

    #[test]
    fn v4_arc03j_media_renegotiation_cannot_mint_a_candidate_attempt() {
        let mut state = RemoteCandidateState::new(test_candidate_fixture_work());
        let initial_sdp = exact_ice_sdp("data-u", "data-p", "AA:BB:CC:DD");
        let initial = state
            .prepare_remote_description(
                sdp_ice_credentials(&initial_sdp).expect("initial credentials are exact"),
            )
            .expect("initial remote description starts");
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial remote description commits"),
        );
        let exact_attempt = Arc::clone(&state.current.attempt);

        let added_media = "v=0\r\n\
                           a=fingerprint:sha-256 AA:BB:CC:DD\r\n\
                           m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                           a=mid:data\r\n\
                           a=ice-ufrag:data-u\r\n\
                           a=ice-pwd:data-p\r\n\
                           m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                           a=mid:audio\r\n\
                           a=ice-ufrag:audio-u\r\n\
                           a=ice-pwd:audio-p\r\n";
        let renegotiation = state
            .prepare_remote_description(
                sdp_ice_credentials(added_media).expect("added media credentials are exact"),
            )
            .expect("ordinary media renegotiation stays on the current attempt");
        assert!(!renegotiation.provisional);
        assert!(Arc::ptr_eq(&renegotiation.attempt, &exact_attempt));
        drop(
            state
                .commit_remote_description(&renegotiation)
                .expect("renegotiation updates bindings without renewing capacity"),
        );
        assert!(Arc::ptr_eq(&state.current.attempt, &exact_attempt));
    }

    #[test]
    fn v4_arc03j_terminal_candidate_exhaustion_stops_later_hash_and_work_admission() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut over_limit = observed_candidate();
        over_limit.candidate.push_str(" distinct");
        let mut state =
            RemoteCandidateState::new(test_candidate_fixture_work_for(&[over_limit.clone()]));
        assert_eq!(
            state.admit(observed_candidate(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        // The provider refuses, and says so in its own vocabulary. This used to
        // read `Refused`, which was the owner's answer under the deleted
        // cumulative envelope — a candidate the grant could have funded, turned
        // away by a number beside the grant. There is no such answer now: the
        // only thing that declines a candidate is the provider running out, and
        // it reports which dimension and by how much.
        assert!(
            matches!(
                state.admit(over_limit, &scope),
                PendingRemoteCandidateQueuePush::ResourceUnavailable(_)
            ),
            "the exhausting candidate is refused by the provider, not by a ceiling"
        );
        let terminal_queue_len = state.current.pending.entries.len();
        let terminal_digest_len = state.current.seen.len();
        for index in 0..1024 {
            let mut hostile = observed_candidate();
            hostile.candidate.push_str(&format!(" hostile-{index}"));
            assert_eq!(
                state.admit(hostile, &scope),
                PendingRemoteCandidateQueuePush::Retired
            );
        }
        assert_eq!(
            (
                state.current.pending.entries.len(),
                state.current.seen.len()
            ),
            (terminal_queue_len, terminal_digest_len),
            "terminal attempts perform no later digest work and take no later retention"
        );
    }

    /// Post-SDP candidates draw on one envelope, and exhausting it retires the
    /// attempt for everything that follows.
    ///
    /// The envelope used to be *cumulative*: it counted submissions, so
    /// resubmitting one candidate three times consumed it and the third repeat
    /// was refused. That tally is gone, and with it the only thing that made a
    /// duplicate cost anything — a repeat is now recognised by the digest set
    /// and turned away before it can take a lease, so it is free and can never
    /// exhaust anything. Draining the envelope needs candidates that are
    /// actually distinct, which is what this now does.
    ///
    /// The sharing claim itself is untouched and is the reason the control
    /// survives: one funded envelope backs every post-SDP candidate on the
    /// attempt, so the one that finds it empty retires the attempt and every
    /// later submission — unique or not — is a constant-work refusal until an
    /// explicit restart mints a fresh envelope.
    #[test]
    fn v4_arc03h_post_sdp_candidates_share_one_attempt_envelope() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let first = observed_candidate();
        let content_bytes = candidate_content_bytes(&first).expect("fixture content is finite");
        let mut state =
            RemoteCandidateState::new(RemoteCandidateFixtureWork::new(2, content_bytes * 2));
        state.current.remote_description_set = true;

        assert_eq!(
            state.admit(first.clone(), &scope),
            PendingRemoteCandidateQueuePush::Queued
        );
        let first_pending = state
            .current
            .pending
            .pop_last_for_application(&scope)
            .expect("post-SDP candidate moves directly to application");
        let first_reservation = first_pending
            ._queue_reservation
            .expect("a queued candidate carries its post-application ownership slot");
        state
            .current
            .retained_reservations
            .push_back(first_reservation);

        assert_eq!(
            state.admit(first, &scope),
            PendingRemoteCandidateQueuePush::Duplicate,
            "a repeat is recognised before it can take a lease, so it costs the \
             shared envelope nothing"
        );

        let distinct = |replacement: &str| {
            let mut candidate = observed_candidate();
            candidate.candidate.replace_range(0..1, replacement);
            candidate
        };
        assert_eq!(
            state.admit(distinct("C"), &scope),
            PendingRemoteCandidateQueuePush::Queued,
            "the second distinct candidate draws on the same envelope the first did"
        );
        assert!(
            matches!(
                state.admit(distinct("D"), &scope),
                PendingRemoteCandidateQueuePush::ResourceUnavailable(_)
                    | PendingRemoteCandidateQueuePush::Retired
            ),
            "and the one that finds the shared envelope empty is refused"
        );

        assert!(!state.current.attempt.is_active());

        assert_eq!(
            state.admit(distinct("E"), &scope),
            PendingRemoteCandidateQueuePush::Retired,
            "the envelope refusal makes later unique submissions constant-work refusals"
        );
        let (retiring_attempt, replacement_attempt) = state
            .begin_local_ice_restart()
            .expect("only an explicit restart creates a fresh envelope");
        assert!(!retiring_attempt.is_active());
        let replacement = state
            .provisional
            .as_ref()
            .expect("replacement is provisional");
        assert!(Arc::ptr_eq(
            &replacement.envelope.attempt,
            &replacement_attempt
        ));
        assert!(replacement.envelope.pending.entries.is_empty());
        assert!(replacement.envelope.seen.is_empty());
    }

    #[test]
    #[ignore = "owner-run observation; requires an explicit candidate-burst workload shape"]
    fn v4_arc03g_measure_candidate_burst_without_selecting_budget() {
        let candidate_count = std::env::var("MYOWNMESH_ARC03_OBSERVE_CANDIDATES")
            .expect("candidate-burst observation supplies a candidate count")
            .parse::<usize>()
            .ok()
            .and_then(NonZeroUsize::new)
            .expect("candidate-burst count is a nonzero integer");
        let mut candidates = Vec::with_capacity(candidate_count.get());
        let mut total_content_bytes = 0usize;
        for index in 0..candidate_count.get() {
            let mut candidate = observed_candidate();
            candidate.candidate.push_str(&format!(" {index}"));
            let content_bytes = candidate_content_bytes(&candidate)
                .expect("finite observation candidate content is representable");
            total_content_bytes = total_content_bytes
                .checked_add(content_bytes)
                .expect("finite observation burst content is representable");
            candidates.push(candidate);
        }
        assert!(
            candidates.iter().any(|candidate| {
                candidate.candidate.capacity() > candidate.candidate.len()
                    || candidate
                        .sdp_mid
                        .as_ref()
                        .is_some_and(|value| value.capacity() > value.len())
                    || candidate
                        .username_fragment
                        .as_ref()
                        .is_some_and(|value| value.capacity() > value.len())
            }),
            "candidate burst includes retained string capacity beyond content"
        );
        let mut retained_capacity_claim = crate::resource::ResourceClaim::ZERO;
        let mut planned_queue_claim = crate::resource::ResourceClaim::ZERO;
        for candidate in &candidates {
            let content = u64::try_from(
                candidate_content_bytes(candidate)
                    .expect("finite observation candidate content is representable"),
            )
            .expect("finite observation candidate content fits u64");
            let baseline = pending_remote_candidate_queue_claim_with_content(0, 0)
                .expect("candidate queue baseline claim is representable")
                .checked_add(crate::resource::ResourceClaim::single(
                    crate::resource::ResourceClass::AccountedMemoryBytes,
                    content,
                ))
                .and_then(|claim| {
                    claim.checked_add(crate::resource::ResourceClaim::single(
                        crate::resource::ResourceClass::QueuedBytes,
                        content,
                    ))
                })
                .expect("candidate queue baseline content claim is representable");
            let planned = pending_remote_candidate_queue_claim(candidate)
                .expect("candidate queue retained-capacity claim is representable");
            planned_queue_claim = planned_queue_claim
                .checked_add(planned)
                .expect("candidate queue planned aggregate is representable");
            let retained = planned
                .checked_sub(baseline)
                .expect("production retained capacity covers the fixture baseline");
            retained_capacity_claim = retained_capacity_claim
                .checked_add(retained)
                .expect("candidate queue retained-capacity total is representable");
        }
        let duplicate = candidates
            .first()
            .cloned()
            .expect("candidate burst has one equality-only duplicate");
        assert_eq!(
            duplicate, candidates[0],
            "duplicate probe has exactly equal candidate content"
        );
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let work = RemoteCandidateFixtureWork::new(candidate_count.get(), total_content_bytes);
        let (provider, _owner, _candidate, _lifetime, work_scope) =
            elastic_remote_candidate_test_resources_with_additional(work, retained_capacity_claim);
        let baseline = provider.in_use();
        let mut state = RemoteCandidateState::with_resources(work_scope);
        let started = Instant::now();
        for (index, candidate) in candidates.into_iter().enumerate() {
            let pushed_at = Instant::now();
            assert_eq!(
                state.admit(candidate, &scope),
                PendingRemoteCandidateQueuePush::Queued
            );
            let items = state.current.pending.entries.len();
            println!(
                "arc03_candidate_burst_raw index={index} push_ns={} items={items}",
                pushed_at.elapsed().as_nanos()
            );
        }
        let retained_queue_claim = state
            .current
            .pending
            .entries
            .iter()
            .try_fold(crate::resource::ResourceClaim::ZERO, |claim, pending| {
                claim.checked_add(
                    pending_remote_candidate_queue_claim(&pending.candidate)
                        .expect("retained candidate queue claim is representable"),
                )
            })
            .expect("retained candidate queue aggregate is representable");
        assert_eq!(
            retained_queue_claim, planned_queue_claim,
            "moved candidates retain exactly their planned production capacities"
        );
        let before_duplicate = (
            provider.in_use(),
            state.current.pending.entries.len(),
            state.current.seen.len(),
            provider.active_reservations(),
            provider.active_scopes(),
        );
        let duplicate_at = Instant::now();
        assert_eq!(
            state.admit(duplicate, &scope),
            PendingRemoteCandidateQueuePush::Duplicate
        );
        assert_eq!(
            (
                provider.in_use(),
                state.current.pending.entries.len(),
                state.current.seen.len(),
                provider.active_reservations(),
                provider.active_scopes(),
            ),
            before_duplicate,
            "duplicate changes no provider, queue, digest, reservation, or scope state"
        );
        println!(
            "arc03_candidate_burst_raw duplicate_ns={} total_push_ns={}",
            duplicate_at.elapsed().as_nanos(),
            started.elapsed().as_nanos()
        );
        assert_eq!(state.current.pending.entries.len(), candidate_count.get());
        let per_candidate_digest_charge =
            crate::resource::FiniteResourceProvider::reservation_charge_for_test(
                crate::runtime::attempt::remote_candidate_digest_retention_aggregate_claim(1)
                    .expect("one-candidate retention aggregate is representable"),
            )
            .expect("one-candidate retention reservation charge is representable");
        let expected_live_charge = state
            .current
            .pending
            .entries
            .iter()
            .try_fold(crate::resource::ResourceClaim::ZERO, |charge, pending| {
                let queue_charge =
                    crate::resource::FiniteResourceProvider::reservation_charge_for_test(
                        pending_remote_candidate_queue_claim(&pending.candidate)
                            .expect("retained candidate queue claim is representable"),
                    )
                    .expect("retained candidate queue reservation charge is representable");
                charge
                    .checked_add(per_candidate_digest_charge)
                    .and_then(|charge| charge.checked_add(queue_charge))
            })
            .expect("per-candidate live reservation charges are representable");
        assert_eq!(
            provider
                .in_use()
                .checked_sub(baseline)
                .expect("candidate live usage includes the provider baseline"),
            expected_live_charge,
            "provider usage is exactly the planned retained per-reservation charges with no unused grant"
        );
        state.current.retire();
        assert_eq!(
            provider.in_use(),
            baseline,
            "retiring the production-shaped attempt restores provider baseline"
        );
        assert!(
            total_content_bytes > 0,
            "the observed burst carried real candidate content"
        );
    }

    #[test]
    fn v4_arc03_candidate_apply_observation_survives_await_and_cancellation() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let scope = context.peer_connection_scope();
        let pending = PendingRemoteCandidate::observe(
            observed_candidate(),
            Arc::new(RemoteCandidateAttemptIdentity::default()),
            &scope,
        );
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
        let pending = PendingRemoteCandidate::observe(
            observed_candidate(),
            Arc::new(RemoteCandidateAttemptIdentity::default()),
            &scope,
        );
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

    #[cfg(feature = "route-flow-diagnostics")]
    fn route_flow_mailbox_fixture(
        payload_bytes: usize,
        scope: Option<PeerConnectionResourceScope>,
    ) -> (
        crate::connector::ConnectedChannelCapability,
        ConnectorEventSink,
        WebRtcConnectorEventReceiver,
    ) {
        let one = NonZeroUsize::new(1).expect("one callback");
        let policy = test_realtime_workload(one);
        let (events, raw) = test_event_mailboxes_with_grant(
            lab_callback_grant_exact(
                one,
                one,
                1,
                payload_bytes,
                NonZeroUsize::new(2).expect("open and close reservations"),
            ),
            policy,
        );
        let (candidate, lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        // A candidate stamp alone cannot admit Message events. Exercise the
        // same live candidate-to-connected transition as the existing channel
        // ownership controls, and retain its move-only capability in the caller.
        let before_open = stamped_event(
            &ownership,
            TransportEvent::Message(Bytes::from_static(b"connection-precondition")),
        );
        assert!(!ownership.accepts(&before_open));
        let connected = match ownership.mark_data_channel_open() {
            DataChannelOpenTransition::Connected(capability) => capability,
            _ => panic!("route-flow fixture requires a live connected candidate"),
        };
        assert!(ownership.accepts(&before_open));
        drop(before_open);
        let mut sink = test_event_sink_for_receiver(events, policy, scope, &raw);
        sink.callback_gate = Arc::clone(&ownership.incarnation);
        sink.operation_fence = Arc::clone(&ownership.operation_fence);
        let receiver = WebRtcConnectorEventReceiver {
            retirement: ownership.incarnation.subscribe_retirement(),
            operation_fence: Arc::clone(&ownership.operation_fence),
            ownership,
            attempt_retirement: None,
            raw,
            attempt_lifetime: Some(lifetime),
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
        };
        (connected, sink, receiver)
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_receipt_held_mailbox_order_and_exact_phase_pricing() {
        use crate::resource::ResourceClass;
        use crate::route_flow::NativeReceipt;

        const DATA: &[u8] = b"receipt";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let active = || {
            context
                .report()
                .pre_authentication
                .into_iter()
                .find(|report| report.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame family exists")
                .active
        };
        let (_connected, sink, mut receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let baseline = active();
        let entered = Instant::now();
        println!(
            "route_flow_event_sizes receipt={} queued={} links={} executing={} accepted_resources={}",
            size_of::<Option<NativeReceipt>>(),
            size_of::<QueuedTransportEvent>(),
            2 * size_of::<usize>(),
            size_of::<WebRtcConnectorEvent>(),
            size_of::<AcceptedWebRtcConnectorEventResources>(),
        );
        assert!(
            sink.emit_observed_message(
                Bytes::from_static(DATA),
                Some(NativeReceipt::for_test(entered)),
            )
            .await
        );
        assert_ne!(active(), baseline, "queued event owns a real observation");

        // The engine has not polled its receiver. Inspect the actual funded
        // queue item, then return that same item before its production dequeue.
        let queued = receiver
            .raw
            .endpoint_data
            .try_take()
            .expect("one held item");
        let receipt = queued.route_flow_receipt.expect("native receipt retained");
        let (callback, attempt, dequeued) = receipt.timestamps_for_test();
        assert_eq!(callback, entered);
        assert!(attempt.is_some_and(|at| at >= callback));
        assert!(
            dequeued.is_none(),
            "holding a queue item is not dequeue exposure"
        );
        let work = queued
            .callback_work
            .as_ref()
            .expect("queued callback lease");
        assert_eq!(work.phase(), callback::CallbackWorkPhase::Queued);
        assert_eq!(
            work.claim().amount(ResourceClass::QueuedBytes),
            DATA.len() as u64
        );
        assert_eq!(
            work.claim().amount(ResourceClass::AccountedMemoryBytes),
            (DATA.len() + size_of::<QueuedTransportEvent>() + 2 * size_of::<usize>()) as u64
        );
        assert!(receiver.raw.endpoint_data.try_insert(queued).is_ok());

        let queued = receiver
            .raw
            .try_scheduled_filtered(true)
            .expect("real dequeue");
        let event = receiver.expose_queued(queued).expect("live exact worker");
        assert!(receiver.ownership.accepts(&event));
        let (payload, resources) = event.into_accepted().into_parts();
        assert!(matches!(payload, TransportEvent::Message(ref bytes) if bytes.as_ref() == DATA));
        let work = resources
            ._callback_work
            .as_ref()
            .expect("executing callback lease");
        assert_eq!(work.phase(), callback::CallbackWorkPhase::Executing);
        assert_eq!(work.claim().amount(ResourceClass::QueuedBytes), 0);
        assert_eq!(
            work.claim().amount(ResourceClass::AccountedMemoryBytes),
            (DATA.len() + size_of::<WebRtcConnectorEvent>()) as u64
        );
        let (callback, inserted, dequeued) = resources
            .route_flow_receipt()
            .expect("receipt moved with accepted leases")
            .timestamps_for_test();
        assert_eq!(callback, entered);
        assert_eq!(
            inserted, attempt,
            "exposure cannot replace the insertion point"
        );
        assert!(dequeued.is_some_and(|at| at >= inserted.expect("insertion exists")));
        assert!(
            receiver.raw.endpoint_data.try_take().is_none(),
            "no extra event"
        );
        assert_ne!(
            active(),
            baseline,
            "accepted lease remains held by the handler"
        );
        drop(payload);
        drop(resources);
        assert_eq!(
            active(),
            baseline,
            "handler completion releases the exact observation"
        );
        assert!(
            sink.callback_producer
                .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
                .is_ok(),
            "released callback claim is reusable without a larger grant"
        );
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_receipt_stale_worker_never_reassigns_and_drop_releases() {
        const DATA: &[u8] = b"stale";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let active = || {
            context
                .report()
                .pre_authentication
                .into_iter()
                .find(|report| report.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame family exists")
                .active
        };
        let (_first_connected, sink, mut first) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let (_successor_connected, _successor_sink, successor) =
            route_flow_mailbox_fixture(DATA.len(), None);
        let baseline = active();
        let entered = Instant::now();
        assert!(
            sink.emit_observed_message(
                Bytes::from_static(DATA),
                Some(crate::route_flow::NativeReceipt::for_test(entered))
            )
            .await
        );
        let queued = first
            .raw
            .try_scheduled_filtered(true)
            .expect("queued native message");
        let event = first.expose_queued(queued).expect("W0 is live at exposure");
        assert!(first.ownership.accepts(&event));
        assert!(
            !successor.ownership.accepts(&event),
            "W1 cannot adopt W0's receipt/event"
        );
        assert_eq!(
            event
                .route_flow_receipt
                .expect("receipt")
                .timestamps_for_test()
                .0,
            entered
        );
        first.ownership.retire();
        assert!(
            !first.ownership.accepts(&event),
            "retirement refuses the old event"
        );
        assert!(!successor.ownership.accepts(&event));
        assert_ne!(active(), baseline);
        // Same drop as a refused event, or cancellation before handler admission.
        drop(event);
        assert_eq!(active(), baseline);
        assert!(sink
            .callback_producer
            .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
            .is_ok());
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_receipt_pressure_close_and_cancel_preserve_lease_release() {
        const DATA: &[u8] = b"retained";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let active = || {
            context
                .report()
                .pre_authentication
                .into_iter()
                .find(|report| report.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame family exists")
                .active
        };
        let (_connected, sink, mut receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let baseline = active();
        let receipt = || Some(crate::route_flow::NativeReceipt::for_test(Instant::now()));
        assert!(
            sink.emit_observed_message(Bytes::from_static(DATA), receipt())
                .await
        );
        let held = active();
        assert_ne!(held, baseline);
        assert!(
            !sink
                .emit_observed_message(Bytes::from_static(DATA), receipt())
                .await,
            "second callback meets the same finite provider pressure"
        );
        assert_eq!(
            active(),
            held,
            "refused callback retained no extra observation"
        );
        let close = receiver
            .raw
            .try_terminal_close()
            .expect("pressure retires the connector");
        assert!(
            close.route_flow_receipt.is_none(),
            "close never fabricates a message receipt"
        );
        drop(close);
        assert!(
            sink.emit_observed_message(Bytes::from_static(DATA), receipt())
                .await,
            "post-close callback keeps the existing accepted-discard convention"
        );
        assert_eq!(active(), held);
        let queued = receiver
            .raw
            .endpoint_data
            .try_take()
            .expect("only original message remains");
        assert!(
            receiver.expose_queued(queued).is_none(),
            "closed operation fence refuses exposure"
        );
        assert_eq!(active(), baseline);
        assert!(receiver.raw.endpoint_data.try_take().is_none());

        let (_cancel_connected, sink, receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let unpolled = Box::pin(sink.emit_observed_message(Bytes::from_static(DATA), receipt()));
        // Drop before polling must neither enqueue nor acquire observation work.
        drop(unpolled);
        assert!(receiver.raw.endpoint_data.try_take().is_none());
        assert_eq!(active(), baseline);
        assert!(
            sink.emit_observed_message(Bytes::from_static(DATA), receipt())
                .await
        );
        drop(receiver);
        drop(sink);
        assert_eq!(
            active(),
            baseline,
            "queued cancellation releases callback and observation"
        );
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_disabled_gate_has_no_clock_receipt_or_extra_event() {
        let receipt = crate::route_flow::capture_native_receipt_with_gate_for_test(false, || {
            panic!("disabled observation must never sample a clock");
        });
        assert!(receipt.is_none());
        let (_connected, sink, mut receiver) = route_flow_mailbox_fixture(4, None);
        assert!(
            sink.emit_observed_message(Bytes::from_static(b"data"), receipt)
                .await
        );
        let queued = receiver
            .raw
            .try_scheduled_filtered(true)
            .expect("ordinary message queued");
        assert!(queued.route_flow_receipt.is_none());
        let event = receiver
            .expose_queued(queued)
            .expect("ordinary exact worker exposure");
        assert!(receiver.ownership.accepts(&event));
        let (event, resources) = event.into_accepted().into_parts();
        assert!(resources.route_flow_receipt().is_none());
        assert!(matches!(event, TransportEvent::Message(_)));
        assert!(receiver.raw.endpoint_data.try_take().is_none());
        drop(resources);
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_funded_callback_uses_original_owner_queue_and_leases() {
        const DATA: &[u8] = b"funded-callback";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let active = || {
            context
                .report()
                .pre_authentication
                .into_iter()
                .find(|row| row.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame observation exists")
                .active
        };
        let (_connected, sink, mut first) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let (_successor_connected, _, successor) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let baseline = active();
        assert_eq!(
            sink.enqueue_funded_message_for_test(&successor.ownership, Bytes::from_static(DATA))
                .await,
            Err(FundedCallbackTestRefusal::NotConnected),
            "a different connected owner cannot borrow this callback producer",
        );
        assert!(first.raw.endpoint_data.try_take().is_none());
        assert_eq!(active(), baseline);

        // Exercise the reserved lifecycle delivery rather than setting the
        // receiver's endpoint-data filter flag. Ownership is already connected.
        assert_eq!(
            sink.enqueue_open_for_test(&successor.ownership).await,
            Err(FundedCallbackTestRefusal::NotConnected)
        );
        assert!(
            first.try_recv_nonblocking().is_none(),
            "wrong worker recorded no Open"
        );
        assert_eq!(sink.enqueue_open_for_test(&first.ownership).await, Ok(()));
        assert_eq!(
            sink.enqueue_open_for_test(&first.ownership).await,
            Err(FundedCallbackTestRefusal::NotQueued),
            "duplicate is not queued"
        );
        first.commit_data_channel_open();
        assert!(
            !first.data_channel_open_committed,
            "Open must be exposed before commit"
        );
        let open = first.try_recv_nonblocking().expect("real reserved Open");
        assert!(first.ownership.accepts(&open));
        assert!(!successor.ownership.accepts(&open));
        assert!(matches!(&open.event, TransportEvent::DataChannelOpen));
        drop(open);

        let receipt_enabled = crate::route_flow::capture_native_receipt().is_some();
        let callback =
            sink.enqueue_funded_message_for_test(&first.ownership, Bytes::from_static(DATA));
        assert!(
            first.raw.endpoint_data.try_take().is_none(),
            "not polled yet"
        );
        assert_eq!(active(), baseline, "payload observation starts at enqueue");
        assert_eq!(callback.await, Ok(()));
        assert_ne!(active(), baseline, "original queue holds real observation");
        assert!(
            first.try_recv_nonblocking().is_none(),
            "Message remains filtered before commit"
        );
        assert_ne!(
            active(),
            baseline,
            "filtered Message keeps its funded custody"
        );
        first.commit_data_channel_open();
        assert!(first.data_channel_open_committed);
        let event = first
            .try_recv_nonblocking()
            .expect("production filtered dequeue");
        assert!(first.ownership.accepts(&event));
        assert!(!successor.ownership.accepts(&event));
        let work = event._callback_work.as_ref().expect("real executing work");
        assert_eq!(work.phase(), callback::CallbackWorkPhase::Executing);
        assert_eq!(
            work.claim()
                .amount(crate::resource::ResourceClass::QueuedBytes),
            0
        );
        assert_eq!(
            work.claim()
                .amount(crate::resource::ResourceClass::AccountedMemoryBytes),
            (DATA.len() + size_of::<WebRtcConnectorEvent>()) as u64,
        );
        assert!(event._queue_observation.is_some());
        assert_eq!(event.route_flow_receipt.is_some(), receipt_enabled);
        if let Some(receipt) = event.route_flow_receipt {
            let (entered, inserted, dequeued) = receipt.timestamps_for_test();
            let inserted = inserted.expect("shared enqueue sampled insertion");
            let dequeued = dequeued.expect("actual receiver sampled dequeue");
            assert!(entered <= inserted && inserted <= dequeued);
        }
        first.ownership.incarnation.retire();
        assert_eq!(
            sink.enqueue_open_for_test(&first.ownership).await,
            Err(FundedCallbackTestRefusal::NotConnected),
            "retired worker cannot reopen"
        );
        assert!(!first.ownership.accepts(&event));
        assert!(!successor.ownership.accepts(&event), "W0 never becomes W1");
        assert_ne!(
            active(),
            baseline,
            "stale event still owns its actual leases"
        );
        drop(event);
        assert_eq!(active(), baseline);
        assert!(first.raw.endpoint_data.try_take().is_none());
        assert!(sink
            .callback_producer
            .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
            .is_ok());
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_funded_callback_synchronous_pressure_and_unpolled_cancel() {
        const DATA: &[u8] = b"funded-callback";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let active = || {
            context
                .report()
                .pre_authentication
                .into_iter()
                .find(|row| row.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame observation exists")
                .active
        };
        let (_connected, sink, receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let baseline = active();
        // This consumes the actual queued-byte budget. Native entry must try
        // admission and retire on refusal BEFORE its future is ever polled.
        let held = sink
            .callback_producer
            .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
            .expect("the one queued payload is funded");
        let refused =
            sink.enqueue_funded_message_for_test(&receiver.ownership, Bytes::from_static(DATA));
        assert!(
            sink.operation_fence.is_closed(),
            "native admission ran synchronously"
        );
        assert_eq!(
            refused.await,
            Err(FundedCallbackTestRefusal::NativeAdmission)
        );
        assert_eq!(active(), baseline);
        assert!(receiver.raw.endpoint_data.try_take().is_none());
        drop(held);
        assert!(sink
            .callback_producer
            .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
            .is_ok());

        let (_cancel_connected, sink, receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let callback =
            sink.enqueue_funded_message_for_test(&receiver.ownership, Bytes::from_static(DATA));
        assert!(!sink.operation_fence.is_closed());
        drop(callback); // releases the already-admitted native executing lease
        assert_eq!(active(), baseline);
        assert!(receiver.raw.endpoint_data.try_take().is_none());
        assert_eq!(
            sink.enqueue_funded_message_for_test(&receiver.ownership, Bytes::from_static(DATA))
                .await,
            Ok(())
        );
        assert_ne!(active(), baseline);
        drop(receiver); // cancellation before handler ownership
        assert_eq!(active(), baseline);
    }

    #[cfg(feature = "route-flow-diagnostics")]
    #[tokio::test]
    async fn route_flow_funded_callback_closed_discard_is_not_queued() {
        const DATA: &[u8] = b"funded-callback";
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let (_connected, sink, receiver) =
            route_flow_mailbox_fixture(DATA.len(), Some(context.peer_connection_scope()));
        let baseline = context.report();
        sink.operation_fence.begin_close();
        assert_eq!(
            sink.enqueue_open_for_test(&receiver.ownership).await,
            Err(FundedCallbackTestRefusal::NotQueued),
            "closed worker records no Open"
        );
        assert!(!receiver.raw.lifecycle.has_pending());
        assert_eq!(
            sink.enqueue_funded_message_for_test(&receiver.ownership, Bytes::from_static(DATA))
                .await,
            Err(FundedCallbackTestRefusal::NotQueued),
            "the native accepted-discard convention is not an enqueue witness",
        );
        assert!(receiver.raw.endpoint_data.try_take().is_none());
        let frame = |report: crate::resource::ResourceReport| {
            report
                .pre_authentication
                .into_iter()
                .find(|row| row.family == PreAuthResourceFamily::FrameBytes)
                .expect("frame observation exists")
                .active
        };
        assert_eq!(frame(context.report()), frame(baseline));
        assert!(sink
            .callback_producer
            .try_admit(ConnectorCallbackClass::EndpointData, DATA.len())
            .is_ok());

        let (_unobserved_connected, unobserved, receiver) =
            route_flow_mailbox_fixture(DATA.len(), None);
        assert_eq!(
            unobserved
                .enqueue_funded_message_for_test(&receiver.ownership, Bytes::from_static(DATA))
                .await,
            Err(FundedCallbackTestRefusal::ObservationUnavailable)
        );
        assert!(receiver.raw.endpoint_data.try_take().is_none());
    }

    #[cfg(not(feature = "route-flow-diagnostics"))]
    #[test]
    fn route_flow_disabled_feature_preserves_event_layouts() {
        #[allow(dead_code)]
        struct OriginalQueued {
            event: TransportEvent,
            observation: Option<ObservationLease>,
            callback_work: Option<CallbackWorkLease>,
        }
        #[allow(dead_code)]
        struct OriginalStamped {
            incarnation: Arc<WebRtcConnectorIncarnation>,
            event: TransportEvent,
            _queue_observation: Option<ObservationLease>,
            _callback_work: Option<CallbackWorkLease>,
        }
        #[allow(dead_code)]
        struct OriginalResources {
            _queue_observation: Option<ObservationLease>,
            _callback_work: Option<CallbackWorkLease>,
        }
        assert_eq!(
            size_of::<QueuedTransportEvent>(),
            size_of::<OriginalQueued>()
        );
        assert_eq!(
            size_of::<WebRtcConnectorEvent>(),
            size_of::<OriginalStamped>()
        );
        assert_eq!(
            size_of::<AcceptedWebRtcConnectorEventResources>(),
            size_of::<OriginalResources>()
        );
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
        let remote_candidates = Arc::new(SyncMutex::new(test_remote_candidate_state()));
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
            operation_fence: Arc::clone(&ownership.operation_fence),
        };

        ownership.retire();
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
            .expect("retained callback sender still has a bounded raw receiver");

        assert!(receiver.recv().await.is_none());
    }

    fn assert_callback_class_backpressure(first: TransportEvent, second: TransportEvent) {
        let TransportEvent::Message(ref first_payload) = first else {
            panic!("fixture class backpressure is arranged out of endpoint data");
        };
        let endpoint_bytes = first_payload.len();
        let one = std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero");
        let policy = test_realtime_workload(one);
        // One endpoint payload of exactly the size the first event carries, the
        // control class starved to a single byte so it cannot pay for endpoint
        // work, and only the two lifecycle deliveries this fixture actually
        // reserves. The second insert therefore meets an empty pool rather than
        // the slack a general fixture grant would have left it.
        let (events, mut receiver) = test_event_mailboxes_with_grant(
            lab_callback_grant_exact(
                one,
                one,
                1,
                endpoint_bytes,
                std::num::NonZeroUsize::new(2)
                    .expect("the two reserved lifecycle deliveries are nonzero"),
            ),
            policy,
        );
        let sink = test_event_sink(events, policy, None);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        let mut first = Box::pin(sink.emit(first));
        assert_eq!(first.as_mut().poll(&mut context), Poll::Ready(true));

        let mut second = Box::pin(sink.emit(second));
        assert_eq!(second.as_mut().poll(&mut context), Poll::Ready(false));
        drop(
            receiver
                .try_recv()
                .expect("first callback occupies the queue"),
        );
        assert!(
            receiver.try_recv().is_err(),
            "overload creates no hidden queue"
        );
    }

    fn assert_realtime_flow_backpressure(first: TransportEvent, second: TransportEvent) {
        let payload_bytes = |event: &TransportEvent| match event {
            TransportEvent::RealtimeUnit(delivery) => delivery.payload_bytes(),
            _ => panic!("fixture event must be a real-time unit"),
        };
        // One flow and exactly one queued unit of the first event's size. The
        // shaped envelope funds a queue slot per flow per domain and a native
        // read per inbound flow, and those spend the same
        // `CallbackOrScheduledWork` a second output reservation needs — so under
        // it the competing unit is admitted out of capacity for work this
        // control never does.
        let first_bytes = payload_bytes(&first);
        let observer = Arc::new(TestRealtimeObserver::default());
        let (registry, _grant) = exact_realtime_registry_with_observer(
            exact_realtime_open_claims().into_iter().chain([
                RealtimeFlowRegistry::output_claim(first_bytes)
                    .expect("the output claim is representable"),
                RealtimeFlowRegistry::queue_claim(first_bytes)
                    .expect("the queued-byte claim is representable"),
                RealtimeFlowRegistry::queued_event_node_claim()
                    .expect("the queue node claim is representable"),
                // Taken by the enqueue below, not by the open above.
                RealtimeFlowRegistry::ready_claim().expect("the ready claim is representable"),
            ]),
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
        );
        let flow = registry
            .open_inbound_flow()
            .expect("fixture admits one exact real-time flow");
        let first_reservation = flow
            .reserve_output(payload_bytes(&first))
            .expect("fixture reserves the first complete unit");
        assert!(flow.enqueue(
            QueuedTransportEvent {
                event: first,
                observation: None,
                callback_work: None,
                #[cfg(feature = "route-flow-diagnostics")]
                route_flow_receipt: None,
            },
            first_reservation,
        ));
        // The competing unit is refused where the refusal now lives: the
        // fixture funds one queued unit, so the second reservation cannot be
        // admitted at all. It used to be reserved and then dropped by a per-flow
        // queue count, which is a bound that no longer exists.
        assert!(flow.reserve_output(payload_bytes(&second)).is_none());
        drop(second);
        assert!(observer.observations.lock().iter().any(|observation| {
            matches!(
                observation,
                RealtimeFlowObservation::Drop {
                    reason: RealtimeFlowDropReason::ResourceUnavailable(_),
                    ..
                }
            )
        }));
        assert!(matches!(
            registry.try_recv().map(|queued| queued.event),
            Some(TransportEvent::RealtimeUnit(_))
        ));
        assert!(registry.try_recv().is_none());
    }

    #[test]
    fn v4_arc03i_lifecycle_control_does_not_compete_for_mailbox_capacity() {
        let (events, mut receiver) = test_event_mailboxes(1);
        let policy =
            test_realtime_workload(NonZeroUsize::new(1).expect("fixture capacity is nonzero"));
        let sink = test_event_sink(events, policy, None);
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);

        let mut open = Box::pin(sink.emit(TransportEvent::DataChannelOpen));
        assert_eq!(open.as_mut().poll(&mut context), Poll::Ready(true));
        let mut close = Box::pin(sink.emit(TransportEvent::DataChannelClosed));
        assert_eq!(close.as_mut().poll(&mut context), Poll::Ready(true));
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::DataChannelClosed)
        ));
        assert!(receiver.try_recv().is_err());
    }

    #[test]
    fn v4_arc03_data_callback_contention_honors_configured_bound() {
        assert_callback_class_backpressure(
            TransportEvent::Message(Bytes::from_static(b"first")),
            TransportEvent::Message(Bytes::from_static(b"second")),
        );
    }

    #[test]
    fn v4_arc03_realtime_callback_contention_honors_configured_bound() {
        assert_realtime_flow_backpressure(
            test_realtime_event(0, 0, b"first"),
            test_realtime_event(0, 1, b"second"),
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
        let realtime_workload = TransportLabRealtimeWorkload {
            inbound_flows: flows.get(),
            outbound_flows: 0,
            queued_units_per_flow: samples.get(),
            in_progress_units_per_inbound_flow: 1,
            fragments_per_unit: 1,
            max_fragment_bytes: payload_bytes.get(),
            max_unit_bytes: payload_bytes.get(),
        };

        for class in [
            ConnectorCallbackClass::Control,
            ConnectorCallbackClass::EndpointData,
        ] {
            let (events, mut receiver) =
                test_event_mailboxes_with_workload(callback_capacity, realtime_workload);
            let sink = test_event_sink(events, realtime_workload, None);
            let mut queued_at = std::collections::VecDeque::new();
            for index in 0..samples.get() {
                let event = match class {
                    ConnectorCallbackClass::Control => TransportEvent::LocalIceCandidate(None),
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
        let registry = test_realtime_registry_with_observer(
            realtime_workload,
            observer.clone() as Arc<dyn RealtimeFlowObserver>,
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
                        event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                            test_label(u8::try_from(flow_index).unwrap_or(u8::MAX)),
                            RealtimeRecvUnit {
                                timestamp: unit_index as u32,
                                marker: false,
                                data: payload,
                            },
                        )),
                        observation: None,
                        callback_work: None,
                        #[cfg(feature = "route-flow-diagnostics")]
                        route_flow_receipt: None,
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

    #[test]
    #[ignore = "owner-run observation; requires explicit saturation workload inputs"]
    fn v4_arc03g_measure_saturated_flow_fairness_without_selecting_budget() {
        let workload_nonzero = |name: &str| {
            std::env::var(name)
                .unwrap_or_else(|_| panic!("observation scenario supplies {name}"))
                .parse::<usize>()
                .ok()
                .and_then(NonZeroUsize::new)
                .unwrap_or_else(|| panic!("{name} must be a nonzero integer"))
        };
        let saturated_units = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_SATURATED_UNITS");
        let latency_units = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_LATENCY_UNITS");
        let payload_bytes = workload_nonzero("MYOWNMESH_ARC03_OBSERVE_PAYLOAD_BYTES");
        assert!(
            latency_units.get() <= saturated_units.get(),
            "the latency-sensitive observation flow must fit the saturated flow's explicit queue shape"
        );
        let total_units = saturated_units
            .get()
            .checked_add(latency_units.get())
            .expect("finite observation unit count is representable");
        let policy = explicit_realtime_workload(
            payload_bytes.get(),
            2,
            saturated_units.get(),
            payload_bytes.get(),
            1,
        );
        let registry = test_realtime_registry(policy);
        let saturated_label = test_label(0);
        let latency_label = test_label(1);
        let saturated = registry
            .open_inbound_flow()
            .expect("observation admits the saturated flow");
        let latency = registry
            .open_inbound_flow()
            .expect("observation admits the latency-sensitive flow");
        let mut saturated_at = std::collections::VecDeque::new();
        let mut latency_at = std::collections::VecDeque::new();

        for index in 0..saturated_units.get() {
            let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
            let reservation = saturated
                .reserve_output(payload.len())
                .expect("observation reserves saturated-flow output");
            saturated_at.push_back(Instant::now());
            assert!(saturated.enqueue(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        saturated_label.clone(),
                        RealtimeRecvUnit {
                            timestamp: u32::try_from(index).unwrap_or(u32::MAX),
                            marker: false,
                            data: payload,
                        },
                    )),
                    observation: None,
                    callback_work: None,
                    #[cfg(feature = "route-flow-diagnostics")]
                    route_flow_receipt: None,
                },
                reservation,
            ));
        }
        for index in 0..latency_units.get() {
            let payload = Bytes::from(vec![0u8; payload_bytes.get()]);
            let reservation = latency
                .reserve_output(payload.len())
                .expect("observation reserves latency-flow output");
            latency_at.push_back(Instant::now());
            assert!(latency.enqueue(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        latency_label.clone(),
                        RealtimeRecvUnit {
                            timestamp: u32::try_from(index).unwrap_or(u32::MAX),
                            marker: false,
                            data: payload,
                        },
                    )),
                    observation: None,
                    callback_work: None,
                    #[cfg(feature = "route-flow-diagnostics")]
                    route_flow_receipt: None,
                },
                reservation,
            ));
        }

        let mut first_latency_service_index = None;
        for service_index in 0..total_units {
            let event = registry
                .try_recv()
                .expect("every admitted observation unit remains serviceable")
                .event;
            let TransportEvent::RealtimeUnit(delivery) = event else {
                panic!("observation registry returned a non-real-time event");
            };
            // The label is the only thing that says which flow served this
            // turn, and it is a fact this observation minted rather than
            // anything read back out of the unit.
            if delivery.label == saturated_label {
                let queued_at = saturated_at
                    .pop_front()
                    .expect("one timestamp exists per saturated unit");
                println!(
                    "arc03_flow_fairness_raw class=saturated service_index={service_index} queue_age_ns={}",
                    queued_at.elapsed().as_nanos()
                );
            } else {
                first_latency_service_index.get_or_insert(service_index);
                let queued_at = latency_at
                    .pop_front()
                    .expect("one timestamp exists per latency-sensitive unit");
                println!(
                    "arc03_flow_fairness_raw class=latency service_index={service_index} queue_age_ns={}",
                    queued_at.elapsed().as_nanos()
                );
            }
        }
        assert!(
            first_latency_service_index.is_some_and(|index| index <= 1),
            "a ready latency-sensitive flow must receive a turn after at most one saturated-flow unit"
        );
    }

    #[tokio::test]
    async fn v4_arc03h_callback_producer_flood_cannot_queue_behind_full_mailbox() {
        const RETAINED: &[u8] = b"retained";
        let one = std::num::NonZeroUsize::new(1).expect("fixture capacity is nonzero");
        let policy = test_realtime_workload(one);
        // Exactly one endpoint payload, so the flood below meets an empty pool
        // rather than the slack a general fixture grant leaves in the two
        // dimensions an insert spends.
        let (events, mut receiver) = test_event_mailboxes_with_grant(
            lab_callback_grant_exact(
                one,
                one,
                1,
                RETAINED.len(),
                std::num::NonZeroUsize::new(2)
                    .expect("the two reserved lifecycle deliveries are nonzero"),
            ),
            policy,
        );
        let sink = test_event_sink(events, policy, None);

        assert!(
            sink.emit(TransportEvent::Message(Bytes::from_static(RETAINED)))
                .await
        );
        let mut producers = tokio::task::JoinSet::new();
        for _ in 0..128 {
            let producer = sink.clone();
            producers.spawn(async move {
                producer
                    .emit(TransportEvent::Message(Bytes::from_static(b"refused")))
                    .await
            });
        }
        tokio::time::timeout(Duration::from_secs(1), async {
            while let Some(result) = producers.join_next().await {
                assert!(!result.expect("producer task joins"));
            }
        })
        .await
        .expect("all overloaded producers finish without a hidden queue");
        assert!(matches!(
            receiver.try_recv(),
            Ok(TransportEvent::Message(bytes)) if bytes == Bytes::from_static(RETAINED)
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
            remote_candidates: Arc::new(SyncMutex::new(test_remote_candidate_state())),
            close_owner: None,
            data_channel_open_committed: false,
            data_channel_closed: false,
            operation_fence: Arc::clone(&ownership.operation_fence),
        };
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelOpen, None)
            .expect("first callback is queued");
        let first = receiver.recv().await.expect("first event reaches engine");
        events_tx
            .try_insert_for_test(TransportEvent::DataChannelClosed, None)
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
        let remote_candidates = Arc::new(SyncMutex::new(test_remote_candidate_state()));
        {
            let mut candidates = remote_candidates.lock();
            let attempt = Arc::clone(&candidates.current.attempt);
            candidates.current.pending.push_observed_for_test(
                observed_candidate(),
                attempt,
                &resource_scope,
            );
        }
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
            operation_fence: Arc::clone(&ownership.operation_fence),
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

    fn native_remote_candidate_fixture_additional(
        retained_charge: crate::resource::ResourceClaim,
        slack: u64,
    ) -> crate::resource::ResourceClaim {
        let candidate = observed_candidate();
        let string_capacity = candidate
            .candidate
            .capacity()
            .checked_add(candidate.sdp_mid.as_ref().map_or(0, String::capacity))
            .and_then(|bytes| {
                bytes.checked_add(
                    candidate
                        .username_fragment
                        .as_ref()
                        .map_or(0, String::capacity),
                )
            })
            .expect("native candidate fixture string capacity is representable");
        let content = candidate_content_bytes(&candidate)
            .expect("native candidate fixture content is representable");
        let candidate_grant = transport_lab_remote_candidate_fixture_grant(
            std::num::NonZeroU64::new(1).expect("one candidate is nonzero"),
            std::num::NonZeroU64::new(1).expect("one digest operation is nonzero"),
            std::num::NonZeroU64::new(
                u64::try_from(string_capacity).expect("candidate string capacity fits u64"),
            )
            .expect("candidate string capacity is nonzero"),
            std::num::NonZeroU64::new(u64::try_from(content).expect("candidate content fits u64"))
                .expect("candidate content is nonzero"),
            std::num::NonZeroU64::new(u64::try_from(content).expect("candidate content fits u64"))
                .expect("candidate content is nonzero"),
        )
        .expect("native candidate fixture grant is representable");
        candidate_grant
            .checked_add(retained_charge)
            .and_then(|claim| {
                claim.checked_add(crate::resource::ResourceClaim::single(
                    crate::resource::ResourceClass::AccountedMemoryBytes,
                    slack,
                ))
            })
            .expect("native candidate retained fixture grant is representable")
    }

    async fn native_remote_candidate_worker_fixture(
        additional: crate::resource::ResourceClaim,
    ) -> (
        WebRtcConnectorWorker,
        WebRtcConnectorEventReceiver,
        PeerConnectionResourceScope,
    ) {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let resource_scope = context.peer_connection_scope();
        let transport = Transport::new()
            .expect("native candidate fixture transport")
            .with_connector_resource_scope(
                test_resource_owner_with_additional(1, 4, additional),
                test_webrtc_profile(4),
            );
        let (worker, events) = transport
            .open_connector_peer(Role::Offerer, &[], &[], resource_scope.clone())
            .await
            .expect("native candidate fixture connector is constructed");
        (worker, events, resource_scope)
    }

    async fn native_remote_candidate_paired_worker_fixture(
        additional: crate::resource::ResourceClaim,
    ) -> (
        WebRtcConnectorWorker,
        WebRtcConnectorEventReceiver,
        WebRtcConnectorWorker,
        WebRtcConnectorEventReceiver,
        PeerConnectionResourceScope,
    ) {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let offerer_scope = context.peer_connection_scope();
        let answerer_scope = context.peer_connection_scope();
        let transport = Transport::new().expect("paired native candidate fixture transport");
        let offerer_transport = transport.clone().with_connector_resource_scope(
            test_resource_owner_with_additional(1, 4, additional),
            test_webrtc_profile(4),
        );
        let answerer_transport = transport.with_connector_resource_scope(
            test_resource_owner_with_additional(1, 4, additional),
            test_webrtc_profile(4),
        );
        let (offerer, offerer_events) = offerer_transport
            .open_connector_peer(Role::Offerer, &[], &[], offerer_scope)
            .await
            .expect("paired offerer is constructed");
        let (answerer, answerer_events) = answerer_transport
            .open_connector_peer(Role::Answerer, &[], &[], answerer_scope)
            .await
            .expect("paired answerer is constructed");
        let offer = offerer
            .create_offer()
            .await
            .expect("paired offer is created");
        answerer
            .session
            .set_remote_description(offer)
            .await
            .expect("paired answerer accepts the offer");
        let answer = answerer
            .create_answer()
            .await
            .expect("paired answer is created");
        offerer
            .session
            .set_remote_description(answer)
            .await
            .expect("paired offerer accepts the answer");
        (
            offerer,
            offerer_events,
            answerer,
            answerer_events,
            context.peer_connection_scope(),
        )
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_production_candidate_pressure_refuses_before_native_mutation() {
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge = FiniteResourceProvider::reservation_charge_for_test(retained_claim)
            .expect("applied candidate reservation charge is representable");
        let (worker, _events, resource_scope) = native_remote_candidate_worker_fixture(
            native_remote_candidate_fixture_additional(retained_charge, 64),
        )
        .await;
        let candidate = observed_candidate();
        let attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        let pending = {
            let mut state = worker.remote_candidates.lock();
            assert_eq!(
                state.admit(candidate, &resource_scope),
                PendingRemoteCandidateQueuePush::Queued
            );
            state
                .current
                .pending
                .pop_last_for_application(&resource_scope)
                .expect("production candidate reaches application")
        };
        let work_scope = worker
            .ownership
            .work_resource_scope()
            .expect("production worker retains its live work scope");
        let _held = work_scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Speculative,
                retained_claim,
            )
            .expect("production fixture admits one held retained claim");
        let result = worker.apply_remote_candidate(pending).await;
        assert!(matches!(
            result,
            Err(Error::ResourceUnavailable(ResourceUnavailable::Pressure(_)))
        ));
        assert_eq!(
            worker.native_candidate_apply_calls.load(Ordering::Acquire),
            0,
            "provider pressure is rejected before the production native call"
        );
        assert!(!attempt.is_active(), "pressure retires the exact attempt");
        worker
            .retire_and_close()
            .await
            .expect("pressure control closes the production worker");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_production_candidate_error_after_native_entry_aborts_transaction() {
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge = FiniteResourceProvider::reservation_charge_for_test(retained_claim)
            .expect("applied candidate reservation charge is representable");
        let (worker, _events, resource_scope) = native_remote_candidate_worker_fixture(
            native_remote_candidate_fixture_additional(retained_charge, 64),
        )
        .await;
        let candidate = observed_candidate();
        let attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        let pending = {
            let mut state = worker.remote_candidates.lock();
            assert_eq!(
                state.admit(candidate, &resource_scope),
                PendingRemoteCandidateQueuePush::Queued
            );
            state
                .current
                .pending
                .pop_last_for_application(&resource_scope)
                .expect("production candidate reaches application")
        };
        worker
            .session
            .pc
            .close()
            .await
            .expect("native fixture closes before the forced apply error");
        let result = worker.apply_remote_candidate(pending).await;
        assert!(
            result.is_err(),
            "closed native peer rejects candidate apply"
        );
        assert_eq!(
            worker.native_candidate_apply_calls.load(Ordering::Acquire),
            1,
            "the production native path was entered before its error"
        );
        assert!(
            !attempt.is_active(),
            "post-native error aborts the exact attempt"
        );
        worker
            .close_owner
            .wait()
            .await
            .expect("armed transaction starts exact close after native error");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_production_candidate_cancellation_aborts_armed_transaction() {
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge = FiniteResourceProvider::reservation_charge_for_test(retained_claim)
            .expect("applied candidate reservation charge is representable");
        let (mut worker, _events, resource_scope) = native_remote_candidate_worker_fixture(
            native_remote_candidate_fixture_additional(retained_charge, 64),
        )
        .await;
        let candidate = observed_candidate();
        let attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        let pending = {
            let mut state = worker.remote_candidates.lock();
            assert_eq!(
                state.admit(candidate, &resource_scope),
                PendingRemoteCandidateQueuePush::Queued
            );
            state
                .current
                .pending
                .pop_last_for_application(&resource_scope)
                .expect("production candidate reaches application")
        };
        let gate = NativeCandidateApplyGate::new();
        worker.native_candidate_apply_gate = Some(Arc::clone(&gate));
        let close_owner = Arc::clone(&worker.close_owner);
        let native_calls = Arc::clone(&worker.native_candidate_apply_calls);
        let application = tokio::spawn(async move { worker.apply_remote_candidate(pending).await });

        let _entered = gate
            .entered
            .acquire()
            .await
            .expect("production native candidate await entered");
        assert_eq!(native_calls.load(Ordering::Acquire), 1);
        assert!(
            close_owner.ownership.incarnation.is_active(),
            "the connector remains live while native apply is in flight"
        );
        application.abort();
        assert!(
            application.await.is_err(),
            "production apply future is cancelled"
        );
        assert!(
            !close_owner.ownership.incarnation.is_active(),
            "cancellation retires the exact connector incarnation"
        );
        assert!(
            !attempt.is_active(),
            "cancellation aborts the exact ICE attempt"
        );
        close_owner
            .wait()
            .await
            .expect("armed transaction settles exact close after cancellation");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_production_candidate_success_commits_and_disarms_transaction() {
        let retained_claim = applied_remote_candidate_retained_claim()
            .expect("applied candidate claim is representable");
        let retained_charge = FiniteResourceProvider::reservation_charge_for_test(retained_claim)
            .expect("applied candidate reservation charge is representable");
        let (worker, _offerer_events, answerer, _answerer_events, resource_scope) =
            native_remote_candidate_paired_worker_fixture(
                native_remote_candidate_fixture_additional(retained_charge, 64),
            )
            .await;
        let candidate = observed_candidate();
        let attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        let pending = {
            let mut state = worker.remote_candidates.lock();
            assert_eq!(
                state.admit(candidate, &resource_scope),
                PendingRemoteCandidateQueuePush::Queued
            );
            state
                .current
                .pending
                .pop_last_for_application(&resource_scope)
                .expect("production candidate reaches application")
        };
        worker
            .apply_remote_candidate(pending)
            .await
            .expect("native candidate application succeeds");
        assert_eq!(
            worker.native_candidate_apply_calls.load(Ordering::Acquire),
            1
        );
        {
            let state = worker.remote_candidates.lock();
            assert!(
                attempt.is_active(),
                "successful apply keeps the exact attempt live"
            );
            assert_eq!(state.current.retained_reservations.len(), 1);
            assert!(state
                .current
                .retained_reservations
                .front()
                .and_then(|reservation| reservation.application.as_ref())
                .is_some());
        }
        worker
            .retire_and_close()
            .await
            .expect("successful production apply closes through its owner");
        answerer
            .retire_and_close()
            .await
            .expect("paired answerer closes through its owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03j_native_local_ice_restart_commits_exact_replacement() {
        // Transactional restart retains the old candidate-attempt claim until
        // the replacement attempt commits.
        let owner = test_resource_owner(2, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Offerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");
        worker
            .create_offer()
            .await
            .expect("local description starts the native ICE agent");
        let previous_attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);

        worker
            .restart_ice()
            .await
            .expect("native local restart succeeds");

        {
            let state = worker.remote_candidates.lock();
            assert!(state.provisional.is_none());
            assert!(!Arc::ptr_eq(&state.current.attempt, &previous_attempt));
            assert!(!previous_attempt.is_active());
            assert!(state.current.attempt.is_active());
        }
        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03j_native_local_ice_restart_failure_retires_connector() {
        // The failure interleaving exercises the same provisional two-attempt
        // ownership overlap as the successful restart.
        let owner = test_resource_owner(2, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Offerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");
        worker
            .create_offer()
            .await
            .expect("local description starts the native ICE agent");
        let previous_attempt = Arc::clone(&worker.remote_candidates.lock().current.attempt);
        worker
            .session
            .pc
            .close()
            .await
            .expect("fixture closes the native peer without retiring its V4 owner");

        worker
            .restart_ice()
            .await
            .expect_err("native restart failure cannot publish replacement capacity");

        {
            let state = worker.remote_candidates.lock();
            assert!(state.provisional.is_none());
            assert!(Arc::ptr_eq(&state.current.attempt, &previous_attempt));
            assert!(!state.current.attempt.is_active());
        }
        assert!(!worker.ownership.incarnation.is_active());
        worker
            .retire_and_close()
            .await
            .expect("idempotent final cleanup owns the already closed native peer");
    }

    #[tokio::test]
    async fn v4_arc03_cancelled_pending_native_constructor_retains_exact_claim() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::BeforeNativeConstructor);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        let construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        let entered = hook
            .created
            .acquire()
            .await
            .expect("construction hook remains open");
        entered.forget();
        construction.abort();
        assert!(construction.await.is_err());

        for _ in 0..32 {
            if owner.report().failed_cleanup_candidates == 1 {
                break;
            }
            tokio::task::yield_now().await;
        }
        assert_eq!(owner.report().active_candidates, 1);
        assert_eq!(owner.report().failed_cleanup_candidates, 1);
        assert!(!owner.report().accounting_poisoned);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_closes_partial_native_peer() {
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let (provider, owner) =
            test_resource_owner_with_provider(1, 4, crate::resource::ResourceClaim::ZERO);
        let baseline = provider.in_use();
        let baseline_reservations = provider.active_reservations();
        let baseline_scopes = provider.active_scopes();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let hook = ConstructionTestHook::new(ConstructionPause::AfterNativeAllocation);
        transport.construction_hook = Some(Arc::clone(&hook));
        let construction_scope = context.peer_connection_scope();
        arc03_construction_stage("before-construction-spawn");
        let mut construction = tokio::spawn(async move {
            transport
                .open_connector_peer(Role::Answerer, &[], &[], construction_scope)
                .await
        });

        arc03_construction_stage("waiting-hook");
        let mut completed_before_hook = None;
        let hook_wait = tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                permit = hook.created.acquire() => {
                    permit.expect("construction hook remains open").forget();
                    true
                }
                result = &mut construction => {
                    completed_before_hook = Some(result);
                    false
                }
            }
        })
        .await;
        match hook_wait {
            Ok(true) => {
                arc03_construction_stage("hook-acquired");
            }
            Ok(false) => {
                arc03_construction_stage("constructor-completed-before-hook");
                match completed_before_hook
                    .expect("construction completion is recorded by the race")
                {
                    Ok(Ok(result)) => {
                        drop(result);
                        panic!("connector constructor completed successfully before its hook");
                    }
                    Ok(Err(error)) => {
                        panic!("connector constructor failed before its hook: {error}");
                    }
                    Err(error) => {
                        panic!("connector construction task joined before its hook: {error}");
                    }
                }
            }
            Err(_) => {
                arc03_construction_stage("hook-wait-deadline");
                construction.abort();
                arc03_construction_stage("abort-requested");
                hook.resume.add_permits(1);
                arc03_construction_stage("resume");
                let joined = tokio::time::timeout(Duration::from_secs(10), &mut construction).await;
                match joined {
                    Ok(Ok(Ok(result))) => {
                        drop(result);
                        panic!("connector constructor completed after its hook deadline");
                    }
                    Ok(Ok(Err(error))) => {
                        panic!("connector constructor returned after its hook deadline: {error}");
                    }
                    Ok(Err(error)) => {
                        panic!(
                            "connector construction task joined after its hook deadline: {error}"
                        );
                    }
                    Err(_) => {
                        panic!("connector construction did not join after abort/resume");
                    }
                }
            }
        }
        let native = hook
            .peer_connection
            .lock()
            .take()
            .expect("native peer exists at the cancellation point");
        arc03_construction_stage("native-extracted");

        let close_observed_at = Instant::now();
        construction.abort();
        arc03_construction_stage("abort-requested");
        let cancelled = match tokio::time::timeout(Duration::from_secs(10), &mut construction).await
        {
            Ok(result) => result,
            Err(error) => {
                arc03_construction_stage("abort-join-deadline");
                hook.resume.add_permits(1);
                panic!("connector construction did not join after cancellation: {error}");
            }
        };
        assert!(cancelled.is_err());
        arc03_construction_stage("join-observed");
        hook.resume.add_permits(1);
        arc03_construction_stage("resume");

        tokio::time::timeout(Duration::from_secs(10), async {
            while native.connection_state() != RTCPeerConnectionState::Closed {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned construction closes the partial native peer");
        arc03_construction_stage("native-closed");
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_native_close_raw disposition=success close_ns={}",
                close_observed_at.elapsed().as_nanos()
            );
        }
        drop(native);
        arc03_construction_stage("native-dropped");

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
                let cleanup = owner.process_report();
                if callbacks.active == ResourceUse::ZERO
                    && tasks.active == ResourceUse::ZERO
                    && cleanup.active_candidates == 0
                    && cleanup.failed_cleanup_candidates == 0
                    && cleanup.cleanup.queued_jobs == 0
                    && cleanup.cleanup.active_jobs == 0
                    && provider.in_use() == baseline
                    && provider.active_reservations() == baseline_reservations
                    && provider.active_scopes() == baseline_scopes
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("partial construction releases callback and task observations");
        let report = owner.process_report();
        assert_eq!(report.active_candidates, 0);
        assert_eq!(report.failed_cleanup_candidates, 0);
        assert_eq!(report.cleanup.queued_jobs, 0);
        assert_eq!(report.cleanup.active_jobs, 0);
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_reservations(), baseline_reservations);
        assert_eq!(provider.active_scopes(), baseline_scopes);
        drop(owner);
        assert_eq!(provider.in_use(), crate::resource::ResourceClaim::ZERO);
        assert_eq!(provider.active_reservations(), 0);
        assert_eq!(provider.active_scopes(), 0);
        arc03_construction_stage("observation-terminal");
        arc03_construction_stage("test-body-done");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_cancelled_construction_with_native_close_error_retains_exact_claim() {
        let owner = test_resource_owner(2, 4);
        let process = ProcessResourceRoot::isolated();
        let context = process.mesh_runtime_scope().network_instance_scope();
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
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

        let close_observed_at = Instant::now();
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
        if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
            println!(
                "arc03_native_close_raw disposition=returned_error close_ns={}",
                close_observed_at.elapsed().as_nanos()
            );
        }
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
            .with_connector_resource_scope(test_resource_owner(1, 4), test_webrtc_profile(4));
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
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
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
        let owner = test_resource_owner(1, 4);
        let mut transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
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
    }

    /// Connector authority refuses a real-time unit before the channel is
    /// connected, and that refusal is the connector's own to make: nothing this
    /// state holds could authorize one.
    ///
    /// What it deliberately does **not** claim is the converse. Once connected,
    /// this type answers `true`, and it should — the session's binding table is
    /// not the connector's to know about. Whether a unit belongs to a live
    /// session is asked one layer up, by
    /// `v4_arc03_realtime_unit_requires_a_live_session_binding_table`.
    #[test]
    fn v4_arc03_connector_authority_refuses_realtime_units_before_connection() {
        let (candidate, _lifetime) = crate::runtime::attempt::connector_candidate_for_test(
            crate::runtime::runtime_for_test(),
        );
        let ownership = admitted_ownership(candidate);
        let unit = stamped_event(&ownership, test_realtime_event(0, 0, b""));

        assert!(
            !ownership.accepts(&unit),
            "an unconnected connector authorizes no real-time unit"
        );
        // Non-vacuity: the refusal is about the state, not about this event
        // being unacceptable to the type in general.
        let lifecycle = stamped_event(&ownership, TransportEvent::DataChannelClosed);
        assert!(
            ownership.accepts(&lifecycle),
            "the same awaiting connector still carries its own lifecycle events"
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
        assert_eq!(measured_usize(None), (0, true));
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
    fn v4_arc03j_sdp_ice_credentials_apply_session_inheritance_and_media_overrides() {
        let sdp = "v=0\r\n\
                   a=ice-ufrag:session-u\r\n\
                   a=ice-pwd:session-p\r\n\
                   m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                   a=mid:data\r\n\
                   m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
                   a=mid:audio\r\n\
                   a=ice-ufrag:audio-u\r\n\
                   a=ice-pwd:audio-p\r\n";
        let credentials = sdp_ice_credentials(sdp).expect("every section has exact credentials");
        assert_eq!(credentials.bindings.len(), 2);
        assert_eq!(credentials.bindings[0].mid.as_deref(), Some("data"));
        assert_eq!(credentials.bindings[0].username_fragment, "session-u");
        assert_eq!(credentials.bindings[0].password, "session-p");
        assert_eq!(credentials.bindings[1].mid.as_deref(), Some("audio"));
        assert_eq!(credentials.bindings[1].username_fragment, "audio-u");
        assert_eq!(credentials.bindings[1].password, "audio-p");

        let reordered = sdp_ice_credentials(
            "v=0\r\n\
             a=ice-ufrag:session-u\r\n\
             a=ice-pwd:session-p\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:audio-u\r\n\
             a=ice-pwd:audio-p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n",
        )
        .expect("reordered media sections keep exact credentials");
        assert!(
            !credentials.proves_restart_to(&reordered),
            "media reordering cannot manufacture an ICE restart"
        );

        let data_restart = sdp_ice_credentials(
            "v=0\r\n\
             a=ice-ufrag:replacement-u\r\n\
             a=ice-pwd:replacement-p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:audio-u\r\n\
             a=ice-pwd:audio-p\r\n",
        )
        .expect("replacement data credentials are exact");
        assert!(
            credentials.proves_restart_to(&data_restart),
            "changed credentials on one stable MID prove a restart"
        );

        let incomplete =
            "v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:u\r\n";
        assert!(
            sdp_ice_credentials(incomplete).is_err(),
            "a partial credential pair is not exact restart evidence"
        );

        for ambiguous in [
            "v=0\r\n\
             a=ice-ufrag:first\r\n\
             a=ice-ufrag:second\r\n\
             a=ice-pwd:password\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n",
            "v=0\r\n\
             a=ice-ufrag:u\r\n\
             a=ice-pwd:p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             a=mid:other\r\n",
            "v=0\r\n\
             a=ice-ufrag:u\r\n\
             a=ice-pwd:p\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:duplicate\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:duplicate\r\n",
        ] {
            assert!(
                sdp_ice_credentials(ambiguous).is_err(),
                "duplicate credential or MID input cannot choose a parser interpretation"
            );
        }

        let rejected_without_credentials = "v=0\r\n\
                                            a=ice-ufrag:session-u\r\n\
                                            a=ice-pwd:session-p\r\n\
                                            m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
                                            a=mid:data\r\n\
                                            m=audio 0 UDP/TLS/RTP/SAVPF 111\r\n\
                                            a=mid:rejected-audio\r\n";
        let active = sdp_ice_credentials(rejected_without_credentials)
            .expect("a rejected media section needs no effective ICE credential pair");
        assert_eq!(active.bindings.len(), 1);

        let rejected_port_range = rejected_without_credentials.replace(
            "m=audio 0 UDP/TLS/RTP/SAVPF 111",
            "m=audio 0/2 UDP/TLS/RTP/SAVPF 111",
        );
        assert_eq!(
            sdp_ice_credentials(&rejected_port_range)
                .expect("a zero-based rejected port range needs no credentials")
                .bindings
                .len(),
            1
        );

        let mut candidate = observed_candidate();
        candidate.username_fragment = None;
        assert!(
            candidate_matches_remote_credentials(&candidate, &active),
            "a candidate without a declared ufrag is bound by its exact active MID"
        );
        candidate.candidate.push_str(" ufrag session-u");
        assert!(candidate_matches_remote_credentials(&candidate, &active));
        candidate.candidate = candidate.candidate.replace("session-u", "other-u");
        assert!(!candidate_matches_remote_credentials(&candidate, &active));

        let mut native_candidate = observed_candidate();
        native_candidate.sdp_mid = Some(String::new());
        native_candidate.sdp_mline_index = Some(0);
        native_candidate.username_fragment = Some("session-u".to_string());
        assert!(
            candidate_matches_remote_credentials(&native_candidate, &active),
            "webrtc-rs empty-MID candidates bind through their exact media-line index"
        );
        native_candidate.sdp_mline_index = Some(1);
        assert!(
            !candidate_matches_remote_credentials(&native_candidate, &active),
            "an empty native MID cannot excuse an invalid media-line index"
        );

        let mut audio_candidate = observed_candidate();
        audio_candidate.sdp_mid = Some("audio".to_string());
        audio_candidate.sdp_mline_index = Some(1);
        audio_candidate.username_fragment = Some("audio-u".to_string());
        assert!(candidate_matches_remote_credentials(
            &audio_candidate,
            &credentials
        ));
        audio_candidate.sdp_mline_index = Some(0);
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "a username fragment from another media section cannot satisfy the declared index"
        );
        audio_candidate.sdp_mline_index = Some(1);
        audio_candidate.sdp_mid = Some("data".to_string());
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "MID and media-line index must identify the same exact credential binding"
        );
        audio_candidate.username_fragment = None;
        audio_candidate.sdp_mline_index = None;
        audio_candidate.sdp_mid = Some("unknown".to_string());
        assert!(
            !candidate_matches_remote_credentials(&audio_candidate, &credentials),
            "process-local attempt ownership cannot excuse an invalid declared media location"
        );
    }

    #[test]
    fn v4_arc03j_remote_candidates_require_an_exact_or_unambiguous_binding() {
        let credentials = sdp_ice_credentials(
            "v=0\r\n\
             m=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\n\
             a=mid:data\r\n\
             a=ice-ufrag:shared-u\r\n\
             a=ice-pwd:data-p\r\n\
             m=audio 9 UDP/TLS/RTP/SAVPF 111\r\n\
             a=mid:audio\r\n\
             a=ice-ufrag:shared-u\r\n\
             a=ice-pwd:audio-p\r\n",
        )
        .expect("fixture has two exact active credential pairs");

        let mut unbound = observed_candidate();
        unbound.sdp_mid = None;
        unbound.sdp_mline_index = None;
        unbound.username_fragment = None;
        assert!(
            !candidate_matches_remote_credentials(&unbound, &credentials),
            "a wholly unbound candidate cannot enter an active or replacement attempt"
        );

        let mut mismatched_location = observed_candidate();
        mismatched_location.sdp_mid = Some("data".to_string());
        mismatched_location.sdp_mline_index = Some(1);
        mismatched_location.username_fragment = Some("shared-u".to_string());
        assert!(
            !candidate_matches_remote_credentials(&mismatched_location, &credentials),
            "MID and media-line index must select the same active SDP binding"
        );

        let mut ambiguous_username = observed_candidate();
        ambiguous_username.sdp_mid = None;
        ambiguous_username.sdp_mline_index = None;
        ambiguous_username.username_fragment = Some("shared-u".to_string());
        assert!(
            !candidate_matches_remote_credentials(&ambiguous_username, &credentials),
            "a username fragment reused by distinct credential pairs is ambiguous"
        );

        let unique_credentials =
            sdp_ice_credentials(&exact_ice_sdp("unique-u", "unique-p", "AA:BB:CC:DD"))
                .expect("one exact active credential pair");
        ambiguous_username.username_fragment = Some("unique-u".to_string());
        assert!(
            candidate_matches_remote_credentials(&ambiguous_username, &unique_credentials),
            "a username-fragment-only candidate may select one unambiguous credential pair"
        );
    }

    #[test]
    fn v4_arc03j_candidate_username_fragment_declarations_must_agree() {
        let credentials =
            sdp_ice_credentials(&exact_ice_sdp("session-u", "session-p", "AA:BB:CC:DD"))
                .expect("one exact active credential pair");

        let mut matching = observed_candidate();
        matching.username_fragment = Some("session-u".to_string());
        matching.candidate.push_str(" ufrag session-u");
        assert_eq!(
            candidate_username_fragment(&matching),
            Ok(Some("session-u"))
        );
        assert!(candidate_matches_remote_credentials(
            &matching,
            &credentials
        ));

        let mut conflicting = matching.clone();
        conflicting.username_fragment = Some("other-u".to_string());
        assert_eq!(
            candidate_username_fragment(&conflicting),
            Err(CandidateUsernameFragmentError::ConflictingDeclarations)
        );
        assert!(!candidate_matches_remote_credentials(
            &conflicting,
            &credentials
        ));

        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let mut state =
            RemoteCandidateState::new(test_candidate_fixture_work_for(&[conflicting.clone()]));
        assert_eq!(
            state.admit(conflicting, &scope),
            PendingRemoteCandidateQueuePush::InvalidBinding(
                CandidateUsernameFragmentError::ConflictingDeclarations
            ),
            "conflicting declarations are rejected before hashing or retention"
        );
        assert!(state.current.pending.entries.is_empty());
        assert!(!state.current.attempt.is_active());

        let mut empty_structured = matching.clone();
        empty_structured.username_fragment = Some(String::new());
        assert_eq!(
            candidate_username_fragment(&empty_structured),
            Ok(Some("session-u")),
            "an empty structured value is absent and cannot hide the candidate-line declaration"
        );
        assert!(candidate_matches_remote_credentials(
            &empty_structured,
            &credentials
        ));

        let mut duplicate_line = matching;
        duplicate_line.candidate.push_str(" ufrag session-u");
        assert_eq!(
            candidate_username_fragment(&duplicate_line),
            Err(CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration),
            "duplicate line declarations are rejected even when their text agrees"
        );
        assert!(!candidate_matches_remote_credentials(
            &duplicate_line,
            &credentials
        ));
    }

    #[test]
    fn v4_arc03_remote_sdp_credentials_share_one_exact_retention_lease() {
        let sdp = exact_ice_sdp("shared-u", "shared-p", "AA:BB:CC:DD");
        let bindings = parse_sdp_ice_credential_bindings(&sdp)
            .expect("fixture SDP has one exact credential binding");
        let initial_claim = remote_description_operation_claim(sdp.capacity())
            .expect("fixture operation claim is representable");
        let plan = plan_sdp_ice_credential_allocations(&sdp)
            .expect("fixture allocation plan is representable");
        let planned_claim = planned_remote_description_claim(plan, sdp.capacity())
            .expect("fixture planned claim is representable");
        let retained_claim =
            retained_remote_description_claim(&bindings, bindings.capacity(), sdp.capacity(), true)
                .expect("fixture retained claim is representable");
        let post_native_claim = retained_remote_description_claim(
            &bindings,
            bindings.capacity(),
            sdp.capacity(),
            false,
        )
        .expect("fixture post-native claim is representable");
        let additional = FiniteResourceProvider::reservation_charge_for_test(initial_claim)
            .expect("fixture operation reservation is representable")
            .checked_add(
                FiniteResourceProvider::reservation_charge_for_test(planned_claim)
                    .expect("fixture planned reservation is representable"),
            )
            .and_then(|claim| {
                claim.checked_add(
                    FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                        .expect("fixture retained reservation is representable"),
                )
            })
            .expect("fixture description grant is representable");
        let policy = test_candidate_fixture_work_for(&[observed_candidate()]);
        let (provider, _owner, _candidate, _lifetime, work_scope) =
            elastic_remote_candidate_test_resources_with_additional(policy, additional);
        let baseline = provider.in_use();

        let credentials = sdp_ice_credentials_owned(&sdp, sdp.capacity(), &work_scope)
            .expect("the exact remote-description claim is admitted");
        assert_eq!(
            provider
                .in_use()
                .checked_sub(baseline)
                .expect("the live description charge includes the baseline"),
            FiniteResourceProvider::reservation_charge_for_test(retained_claim)
                .expect("fixture retained reservation is representable")
        );

        let shared_charge = provider.in_use();
        let clone = credentials.clone();
        assert_eq!(
            provider.in_use(),
            shared_charge,
            "a process-local credential clone shares the original lease"
        );

        credentials
            .finish_native_commit()
            .expect("native commit releases only the scheduled-work claim");
        let post_native_charge = provider.in_use();
        assert_eq!(
            post_native_charge
                .checked_sub(baseline)
                .expect("the post-native charge includes the baseline"),
            FiniteResourceProvider::reservation_charge_for_test(post_native_claim)
                .expect("fixture post-native reservation is representable")
        );
        drop(credentials);
        assert_eq!(
            provider.in_use(),
            post_native_charge,
            "dropping one shared owner cannot release the credential lease"
        );
        drop(clone);
        assert_eq!(provider.in_use(), baseline);
    }

    #[tokio::test]
    async fn v4_arc03_remote_sdp_residual_survives_failed_native_close() {
        let sdp = exact_ice_sdp("failure-u", "failure-p", "AA:BB:CC:DD");
        let bindings = parse_sdp_ice_credential_bindings(&sdp)
            .expect("fixture SDP has one exact credential binding");
        let plan = plan_sdp_ice_credential_allocations(&sdp)
            .expect("fixture allocation plan is representable");
        let initial_claim = remote_description_operation_claim(sdp.capacity())
            .expect("fixture operation claim is representable");
        let planned_claim = planned_remote_description_claim(plan, sdp.capacity())
            .expect("fixture planned claim is representable");
        let retained_claim =
            retained_remote_description_claim(&bindings, bindings.capacity(), sdp.capacity(), true)
                .expect("fixture retained claim is representable");
        let post_native_claim = retained_remote_description_claim(
            &bindings,
            bindings.capacity(),
            sdp.capacity(),
            false,
        )
        .expect("fixture post-native claim is representable");
        let additional = [initial_claim, planned_claim, retained_claim]
            .into_iter()
            .map(|claim| {
                FiniteResourceProvider::reservation_charge_for_test(claim)
                    .expect("fixture description reservation is representable")
            })
            .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
                total.checked_add(claim)
            })
            .expect("fixture description grant is representable");
        let grant = crate::runtime::attempt::explicit_test_grant(1, 1)
            .checked_add(additional)
            .expect("fixture process grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("fixture provider admits its process scope");
        let process_owner = ConnectorResourceOwnerPort::new(port);
        let mesh = process_owner
            .issue_mesh_scope()
            .expect("fixture process owner issues one Mesh scope");
        let (close_owner, _lifetime) = close_owner_fixture(&mesh);
        let work_scope = close_owner
            .ownership
            .work_resource_scope()
            .expect("close-owner fixture retains its work scope before start");
        let credentials = sdp_ice_credentials_owned(&sdp, sdp.capacity(), &work_scope)
            .expect("the exact remote-description claim is admitted");
        close_owner.retain_remote_description_resources(
            credentials
                .resource_owner()
                .expect("owned credentials expose one residual owner"),
        );
        credentials
            .finish_native_commit()
            .expect("native commit releases only the scheduled-work claim");
        assert!(
            close_owner.attach_native_port(Arc::new(TestNativeClosePort {
                result: TestNativeCloseResult::Error,
                calls: Arc::new(AtomicUsize::new(0)),
            }))
        );

        let error = close_owner
            .wait()
            .await
            .expect_err("injected native close failure remains terminal");
        assert!(error.to_string().contains("retained its exact claim"));
        let expected = crate::runtime::attempt::connector_resource_structural_claims()
            .connector_opening()
            .checked_add(post_native_claim)
            .expect("fixture retained claims are representable");
        assert_eq!(provider.retained_after_failed_cleanup(), expected);

        drop(credentials);
        drop(close_owner);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            expected,
            "no external owner drop can make failed native state reusable"
        );
    }

    #[test]
    fn v4_arc03j_invalid_candidate_bindings_terminally_retire_the_attempt() {
        let mut conflicting = observed_candidate();
        conflicting.username_fragment = Some("structured-u".to_string());
        conflicting.candidate.push_str(" ufrag line-u");

        let mut duplicate = observed_candidate();
        duplicate
            .candidate
            .push_str(" ufrag remote-fragment ufrag remote-fragment");

        let mut missing_value = observed_candidate();
        missing_value.candidate.push_str(" ufrag");

        let cases = [
            (
                conflicting,
                CandidateUsernameFragmentError::ConflictingDeclarations,
            ),
            (
                duplicate,
                CandidateUsernameFragmentError::DuplicateCandidateLineDeclaration,
            ),
            (
                missing_value,
                CandidateUsernameFragmentError::MissingCandidateLineValue,
            ),
        ];

        for (invalid, expected_error) in cases {
            let process = ProcessResourceRoot::isolated();
            let scope = process
                .mesh_runtime_scope()
                .network_instance_scope()
                .peer_connection_scope();
            let mut state =
                RemoteCandidateState::new(test_candidate_fixture_work_for(&[invalid.clone()]));
            assert_eq!(
                state.admit(observed_candidate(), &scope),
                PendingRemoteCandidateQueuePush::Queued,
                "the terminal snapshot includes one already retained candidate"
            );
            let (first, first_kind) = state.admit_observed(invalid.clone(), &scope);
            assert_eq!(
                first,
                PendingRemoteCandidateQueuePush::InvalidBinding(expected_error)
            );
            assert!(
                first_kind.is_some(),
                "the one terminal result is classified"
            );
            assert!(!state.current.attempt.is_active());

            let terminal_queue_len = state.current.pending.entries.len();
            let terminal_digest_len = state.current.seen.len();
            let terminal_resources = candidate_report(&process.report().pre_authentication);
            let terminal_resource_counters = (
                terminal_resources.active,
                terminal_resources.peak_active,
                terminal_resources.active_lease_count,
                terminal_resources.peak_active_lease_count,
                terminal_resources.completed_lease_count,
                terminal_resources.completed_total_use,
                terminal_resources.completed_total_lifetime,
                terminal_resources.measurement_inexact,
            );
            let mut classified_results = usize::from(first_kind.is_some());

            for index in 0..1024 {
                let mut later = invalid.clone();
                later.candidate.push_str(&format!(" later-{index}"));
                let (disposition, kind) = state.admit_observed(later, &scope);
                assert_eq!(disposition, PendingRemoteCandidateQueuePush::Retired);
                assert!(
                    kind.is_none(),
                    "a retired attempt performs no later diagnostic classification"
                );
                classified_results += usize::from(kind.is_some());
            }

            assert_eq!(classified_results, 1);
            assert_eq!(state.current.pending.entries.len(), terminal_queue_len);
            assert_eq!(state.current.seen.len(), terminal_digest_len);
            let later_resources = candidate_report(&process.report().pre_authentication);
            assert_eq!(
                (
                    later_resources.active,
                    later_resources.peak_active,
                    later_resources.active_lease_count,
                    later_resources.peak_active_lease_count,
                    later_resources.completed_lease_count,
                    later_resources.completed_total_use,
                    later_resources.completed_total_lifetime,
                    later_resources.measurement_inexact,
                ),
                terminal_resource_counters
            );
        }
    }

    #[test]
    fn v4_arc03j_restart_transactions_reject_ambiguous_interleavings() {
        let mut state = RemoteCandidateState::new(test_candidate_fixture_work());
        let credentials = sdp_ice_credentials(&exact_ice_sdp(
            "remote-fragment",
            "remote-password",
            "AA:BB:CC:DD",
        ))
        .expect("fixture credentials are exact");
        let initial = state
            .prepare_remote_description(credentials.clone())
            .expect("initial remote description starts");
        assert!(state.begin_local_ice_restart().is_err());
        assert!(state
            .prepare_remote_description(credentials.clone())
            .is_err());
        state.fail_remote_description(&initial);

        let (_retiring, local_replacement) = state
            .begin_local_ice_restart()
            .expect("local restart begins after the remote transaction ends");
        assert!(state.prepare_remote_description(credentials).is_err());
        state.fail_provisional(&local_replacement);
    }

    #[test]
    fn v4_arc03j_corrupt_restart_migration_leaves_no_viable_attempt() {
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        // Eight, and the count is deliberately a wide margin rather than the
        // smallest number that fails.
        //
        // The submission ceiling that used to refuse this migration is gone, so
        // the refusal has to come from the replacement attempt's grant running
        // out. How many candidates that grant actually holds is not one number:
        // the restart-overlap fixture funds a second attempt's worth of digest
        // retention on purpose — that overlap is the whole point, it is what
        // lets a legitimate migration carry its queue across — and on top of it
        // the per-candidate queue claim and the fixture's `content` term each
        // leave room for another candidate or two in a different dimension.
        // Picking the exact first count that tips it would tie this control to
        // three separate constants and quietly stop testing anything the day one
        // of them moves. A queue several times larger than any of those terms is
        // refused whichever dimension binds first.
        let corrupt_candidates = [
            "one", "two", "three", "four", "five", "six", "seven", "eight",
        ]
        .map(|suffix| {
            let mut candidate = observed_candidate();
            candidate.username_fragment = Some("replacement-fragment".to_string());
            candidate.candidate.push_str(suffix);
            candidate
        });
        let candidate_bytes = corrupt_candidates
            .iter()
            .filter_map(candidate_content_bytes)
            .max()
            .and_then(NonZeroUsize::new)
            .expect("corrupt fixture candidates have finite nonzero content");
        let mut state = RemoteCandidateState::new_with_restart_overlap(
            RemoteCandidateFixtureWork::new(1, candidate_bytes.get()),
        );
        let initial_credentials = sdp_ice_credentials(&exact_ice_sdp(
            "initial-fragment",
            "initial-password",
            "AA:BB:CC:DD",
        ))
        .expect("initial credentials are exact");
        let initial = state
            .prepare_remote_description(initial_credentials)
            .expect("initial remote description starts");
        drop(
            state
                .commit_remote_description(&initial)
                .expect("initial remote description commits"),
        );

        for candidate in corrupt_candidates {
            state
                .current
                .pending
                .entries
                .push_back(PendingRemoteCandidate::observe(
                    candidate,
                    Arc::clone(&state.current.attempt),
                    &scope,
                ));
        }
        let replacement_credentials = sdp_ice_credentials(&exact_ice_sdp(
            "replacement-fragment",
            "replacement-password",
            "AA:BB:CC:DD",
        ))
        .expect("replacement credentials are exact");
        assert!(state
            .prepare_remote_description(replacement_credentials)
            .is_err());
        assert!(
            state.has_no_viable_attempt(),
            "a corrupt over-limit migration must fence both attempts so the caller retires the connector"
        );
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

    /// The framing every assembler control below drives.
    ///
    /// The assembly machinery is codec-neutral and the fragmentation rules are
    /// not, so a control that exercises reordering, loss or the fragment stop
    /// has to name one framing. H.264 is the one with real fragment shapes to
    /// build a chain out of.
    fn h264_framing() -> Arc<dyn RealtimeUnitFraming> {
        Arc::new(H264Framing)
    }

    /// A single-NAL IDR payload (type 5) — emits as one whole unit.
    const IDR_NAL: &[u8] = &[0x65, 0xAA, 0xBB];
    /// The same IDR as three FU-A fragments (start / middle / end).
    const FU_S: &[u8] = &[0x7C, 0x85, 0x11];
    const FU_M: &[u8] = &[0x7C, 0x05, 0x22];
    const FU_E: &[u8] = &[0x7C, 0x45, 0x33];

    /// A guarded assembler whose fragment the provider will not fund rolls the
    /// unit back rather than retaining half of it.
    ///
    /// The refusal used to be a fragment-byte ceiling: the payload was three
    /// bytes, the owner's fragment maximum was two, and the assembler rejected
    /// it on sight. There is no maximum to compare against now, so the refusal
    /// has to come from the provider — and *which* acquisition it lands on
    /// decides what the caller sees, which an earlier version of this control
    /// got wrong by funding neither.
    ///
    /// `RealtimeUnitAssembler::push` has two refusal exits and they are not
    /// interchangeable. A refused `begin_unit` leaves `self.assembly` at `None`,
    /// clears the current parts and returns `Ok(None)` — the packet is dropped
    /// quietly, because nothing was ever begun. Only a refused
    /// `retain_ordered_fragment`, on an assembly that already exists, clears the
    /// parts *and* `prev_end` and returns `Err`. This control is named for the
    /// second one, so the grant funds the assembly and stops there: the unit
    /// begins, the fragment is refused, and the error is the caller's signal
    /// that the stream lost its anchor.
    ///
    /// Funding the assembly is also what keeps the ledger assertions from being
    /// vacuous. `in_progress_units` really does reach one before the refusal, so
    /// reading zero afterwards is a rollback rather than a state that was never
    /// entered — and the refused fragment retaining no bytes is the ordering
    /// property the name claims.
    #[test]
    fn v4_arc03_guarded_video_refuses_fragment_before_retention() {
        let (registry, _grant) = exact_realtime_registry(
            exact_realtime_open_claims()
                .into_iter()
                .chain([RealtimeFlowRegistry::assembly_claim()
                    .expect("the assembly claim is representable")]),
        );
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        assert!(assembler.push(&rtp_pkt(1, 100, true, IDR_NAL)).is_err());
        assert_eq!(assembler.fragments_held(), 0);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    #[test]
    fn v4_arc03f_silent_partial_unit_retains_only_its_finite_claim_until_owner_drop() {
        let registry = test_realtime_registry(explicit_realtime_workload(8, 1, 1, 8, 1));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        assert!(assembler
            .push(&rtp_pkt(1, 100, false, FU_S))
            .expect("the bounded fragment is valid")
            .is_none());
        {
            let state = registry.state.lock();
            assert_eq!(retained_realtime_bytes(&state), FU_S.len());
            assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 1);
        }

        drop(assembler);
        let state = registry.state.lock();
        assert_eq!(retained_realtime_bytes(&state), 0);
        assert_eq!(RealtimeFlowRegistry::in_progress_units(&state), 0);
        assert!(realtime_accounting_is_clean(&state));
    }

    /// Replacing a session frees its labels and its resources, and the
    /// replaced session's label stops working.
    ///
    /// The single control for the bundle-drop invariant. One name throughout on
    /// purpose: it is the name an application is most likely to ask for again
    /// the instant it reconnects, so a retired session's hold on it outliving
    /// the session would show here first.
    ///
    /// The fixture admits exactly one active flow per domain and exactly one
    /// queued unit. That is what makes the last assertion a proof rather than
    /// a formality — the fresh session can only open at all if the replaced
    /// session's flow was genuinely released, not merely forgotten.
    #[test]
    fn v4_macro1_a_replacing_a_session_frees_label_zero_and_its_resources() {
        struct FixtureSession {
            incarnation: Arc<crate::connector::ConnectorIncarnation>,
        }

        impl session_flow::RealtimeSessionBinding for FixtureSession {
            fn is_current_on(
                &self,
                incarnation: &Arc<crate::connector::ConnectorIncarnation>,
            ) -> bool {
                Arc::ptr_eq(&self.incarnation, incarnation)
            }
        }

        fn fixture_unit() -> RealtimeSendUnit {
            RealtimeSendUnit {
                pace: Duration::from_millis(20),
                data: Bytes::from_static(b"unit"),
            }
        }

        let registry = test_realtime_registry(explicit_realtime_workload(16, 1, 1, 16, 1));
        let name = fixture_flow_name();
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding names a shape a flow can carry");

        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: encoding.clone(),
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the application names its own flow and this side claims it exactly"
        );
        flows
            .send(&session, Some(&incarnation), &name, fixture_unit())
            .expect("a live flow of a current session takes a unit");

        let queued = {
            let state = registry.state.lock();
            retained_realtime_bytes(&state)
        };
        assert!(
            queued > 0,
            "a queued unit holds its payload lease while it is queued — without \
             this the release assertion below would pass vacuously"
        );

        // Retirement: the worker no longer has a live incarnation to offer.
        assert_eq!(
            flows.send(&session, None, &name, fixture_unit()),
            Err(RealtimeFlowError::SessionNotCurrent),
            "a retired connector cannot keep feeding a torn-down peer"
        );

        // Replacement: a different incarnation is a different connector, and
        // the session's own belief that it is current is not enough.
        let replacement = crate::connector::ConnectorIncarnation::new();
        assert_eq!(
            flows.send(&session, Some(&replacement), &name, fixture_unit()),
            Err(RealtimeFlowError::SessionNotCurrent),
            "the replaced session's label is unusable against the connector \
             that replaced it"
        );

        // The drop of the bundle is the release. Nothing announces it.
        drop(flows);
        {
            let state = registry.state.lock();
            assert_eq!(
                retained_realtime_bytes(&state),
                0,
                "the queued unit's bytes went with the session that owned it"
            );
            assert!(
                realtime_accounting_is_clean(&state),
                "and they were released rather than lost, which would poison \
                 the domain instead"
            );
        }

        // A freshly promoted session claims exactly the label the replaced one
        // held. Under a one-flow-per-domain ceiling this is only possible if
        // the flow itself was released, not just its name.
        let next_session = FixtureSession {
            incarnation: Arc::clone(&replacement),
        };
        let mut next = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );
        assert_eq!(
            next.open(
                &next_session,
                Some(&replacement),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the name an application is most likely to reuse is available again"
        );
    }

    /// A fixture session bound to one connector incarnation.
    ///
    /// Hoisted out of the controls that declare their own copy, because three
    /// of the flow-lifecycle controls below need one and a fourth definition
    /// would be the point at which they start disagreeing.
    struct FlowFixtureSession {
        incarnation: Arc<crate::connector::ConnectorIncarnation>,
    }

    impl session_flow::RealtimeSessionBinding for FlowFixtureSession {
        fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
            Arc::ptr_eq(&self.incarnation, incarnation)
        }
    }

    /// One inbound application flow consumes exactly one active-flow slot, and
    /// the admitted track's handle on it is not a second owner.
    ///
    /// **The discriminating case is a one-flow ceiling.** Under it, the two
    /// defects this control exists for are each a hard failure rather than a
    /// degradation:
    ///
    /// - The connector used to open a *second* registry flow when the negotiated
    ///   track arrived, for a flow the application had already opened. At
    ///   capacity one that second acquisition refuses, so a flow whose open had
    ///   succeeded would silently carry no media; at capacity *n* it would
    ///   simply halve the configured capacity, which is the same defect wearing
    ///   a number that looks deliberate.
    /// - A strong port on the pump would keep the flow's lease alive past its
    ///   close, so the replacement open below would refuse.
    ///
    /// The positive half is not decoration: an attachment that resolved to
    /// nothing would satisfy the capacity assertion vacuously, so the control
    /// proves the admitted handle really does reach *this* flow's accounting
    /// while it is open, and really does stop after the close.
    #[test]
    fn v4_macro1_one_inbound_flow_holds_exactly_one_active_flow_slot() {
        let registry = test_realtime_registry(explicit_realtime_workload(16, 1, 1, 16, 1));
        let name = fixture_flow_name();
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding names a shape a flow can carry");
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FlowFixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: encoding.clone(),
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the one inbound slot this fixture has is taken by the application's \
             own open"
        );

        // Exactly what the fence does: mint, then bind, then negotiate. The
        // retirement is minted against its own funded work scope because this
        // control is about *flow-slot* accounting; what it needs from the
        // retirement is only that the flow, rather than this caller, ends up
        // holding it.
        let (
            _native_provider,
            _native_owner,
            _native_mesh,
            _native_candidate,
            _native_lifetime,
            native_scope,
        ) = realtime_native_test_scope(0, 1, 1);
        let tracks = Arc::new(RealtimeSessionTracks::default());
        let identity = RealtimeTrackIdentity::mint_for_test(&native_scope);
        flows
            .bind_inbound(
                &session,
                Some(&incarnation),
                &name,
                Arc::clone(&identity),
                test_inbound_retirement(&tracks, &identity, &native_scope),
            )
            .expect("an open inbound flow of a current session takes a binding");

        // Exactly what `on_track` does. No second open anywhere on this path.
        let bindings = flows
            .inbound_bindings()
            .upgrade()
            .expect("the set that just bound is still alive");
        let attachment = bindings
            .admit(&identity, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
            .expect("the track this side negotiated is admitted to its own flow");
        assert_eq!(attachment.label.name(), &name);

        // Positive: the handle reaches this flow's accounting while it is open.
        // Without this the capacity assertion below could pass because the
        // attachment pointed at nothing at all.
        assert!(
            attachment.port.port().is_some(),
            "an admitted track's handle resolves to the flow it was admitted to"
        );

        // The attachment stays alive across the close, exactly as a running pump
        // would be. If it owned a lease, this is where the leak would start.
        let remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        assert!(
            matches!(
                remains,
                RealtimeFlowRemains::Inbound(ref retirement)
                    if Arc::ptr_eq(retirement.identity(), &identity)
            ),
            "closing a bound inbound flow hands back the retirement for the exact \
             token whose transceiver is still to be stopped"
        );
        assert!(
            attachment.port.port().is_none(),
            "and the pump's handle stops resolving, which is the whole of how it \
             learns the flow is gone"
        );

        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the one slot is free again while the closed flow's attachment is \
             still held — so the attachment never owned one"
        );
    }

    /// An outbound open for a family the application never registered is
    /// refused as such, and costs nothing.
    ///
    /// The defect this replaces was silent in the way that matters: the open
    /// succeeded, took a label and a flow slot, and the refusal surfaced later
    /// from native negotiation as `FlowRefused` — which tells a caller to back
    /// off and retry something that can never succeed. Inbound already answered
    /// at bind time; outbound had no such point.
    ///
    /// Proved by consequence rather than by the error alone: under a one-flow
    /// ceiling and on the same label, a registered open immediately afterwards
    /// can only succeed if the refusal consumed neither.
    #[test]
    fn v4_macro1_an_unregistered_outbound_open_costs_no_label_and_no_capacity() {
        let registry = test_realtime_registry(explicit_realtime_workload(16, 1, 1, 16, 1));
        let name = fixture_flow_name();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FlowFixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );

        let unregistered = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/VP8", 90_000, 0)
            .expect("an encoding naming a family the control profile never registered");
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: unregistered,
                    name: name.clone(),
                },
            ),
            Err(RealtimeFlowError::EncodingInvalid),
            "an unregistered family has no codec to negotiate and no framer to \
             install, which is a property of the request and not of what the \
             transport later makes of it"
        );

        let registered = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("an encoding naming a family the control profile registers");
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: registered,
                    name: name.clone(),
                },
            ),
            Ok(name),
            "the same name and the only outbound slot are both still free, so \
             the refusal above acquired neither"
        );
    }

    /// A second party to one retirement waits for the first to finish, and is
    /// never told the work is done before it is.
    ///
    /// Three parties can reach the same native object — an explicit close, the
    /// pump that was feeding the flow, and the install that supersedes the
    /// session — and single ownership is only half the answer. The other half
    /// is what the losers are told. A loser that returned immediately would let
    /// the daemon acknowledge a close while the transceiver was still being
    /// stopped, and a reopen on that label would then race a transceiver still
    /// offering to receive.
    ///
    /// Exercised on [`RealtimeRetirement`] directly, which is why that state is
    /// a type of its own and holds no transceiver: the race is in the claim and
    /// the completion, and standing up a peer connection to reach it would test
    /// `webrtc`'s `stop` rather than this decision. The assertion that matters
    /// is the *negative* one — that the waiter is still waiting — because a
    /// completion that fired early would satisfy every positive assertion here.
    ///
    /// The **late** subscriber is the second load-bearing case, and it is what
    /// the completion cell is shaped for: a party that arrives after the stop has
    /// already finished must be told so immediately rather than parking on a
    /// notification that has been and gone. Completion is a state read before
    /// registering, not an edge.
    #[tokio::test]
    async fn v4_macro1_a_losing_retirer_waits_for_the_winner_to_finish() {
        // No identity and exactly one completion cell: this control never mints
        // a track, and an identity it does not hold would be capacity standing
        // behind the completion cell it does.
        let (_candidate, _lifetime, scope) = identity_test_scope(0, 1);
        let signal = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                RealtimeRetirementSignal::mint_claim()
                    .expect("the completion claim is representable"),
            )
            .expect("the fixture grant funds one completion cell");
        let mut retirement = RealtimeRetirement::new(signal);

        // `let ... else` rather than `expect`/`expect_err`. Both arms of
        // `claim` are `FundedArc<RealtimeRetirementSignal>`, and that type has no
        // `Debug` — deliberately, because a completion cell's contents are not
        // a thing to print — so the panicking helpers cannot name it. Giving it
        // one to satisfy a test would put a formatting surface on a
        // synchronisation primitive for the sake of a message these panics
        // already carry.
        let Ok(done) = retirement.claim() else {
            panic!("the first caller takes responsibility")
        };
        let Err(waiting) = retirement.claim() else {
            panic!("a second caller does not get a second claim on one object")
        };
        let Err(third) = retirement.claim() else {
            panic!("nor does any later one")
        };

        let mut waiter = tokio::spawn(await_retirement(waiting));
        // Not `is_finished`, which would be a race against the spawn itself.
        // A timed poll that expires is the honest form of "still waiting".
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(50), &mut waiter)
                .await
                .is_err(),
            "the loser is still waiting while the winner's stop is outstanding — \
             without this the assertion below would pass on a completion that \
             had fired immediately"
        );
        assert!(
            !third.is_done(),
            "and nothing observing the state reports it as retired yet"
        );

        // What `stop_owned` does once `stop` has returned.
        done.finish();

        waiter
            .await
            .expect("the loser is released once the winner has finished");
        assert!(third.is_done());
        // The late arrival. It registers nothing that could have been missed,
        // because it reads the state first — so this returns rather than parking
        // forever on a wake that fired before it existed.
        tokio::time::timeout(
            std::time::Duration::from_millis(50),
            await_retirement(third),
        )
        .await
        .expect("a party that arrives after the stop is told immediately");
    }

    /// A unit that arrives for a label with no open inbound flow is dropped at
    /// arrival, and its bytes go with it.
    ///
    /// The discriminating case for the early-arrival race: a peer's first
    /// units can outrun the application-level announcement that would have
    /// caused this side to open the flow. Nothing queues them against a
    /// future open — there is no place to put them that is not an unbounded,
    /// unaccounted buffer keyed on a label the session does not yet use, and
    /// a label is not a reservation.
    ///
    /// So the answer is refuse-and-release, and the second half is the part
    /// worth a control: the caller's lease is consumed by the drop, which
    /// returns the bytes rather than stranding them. A drop that leaked its
    /// lease would look identical from the caller's side and would exhaust
    /// the envelope one unarrived flow at a time.
    #[test]
    fn v4_macro1_a_unit_for_an_unopened_flow_is_dropped_and_its_bytes_released() {
        let registry = test_realtime_registry(explicit_realtime_workload(16, 1, 1, 16, 1));
        let flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );
        let data = Bytes::from_static(b"unit");

        // A lease taken exactly as the inbound pump would take it.
        let port = registry
            .open_inbound_flow()
            .expect("the fixture admits one inbound flow");
        let output = port
            .reserve_output(data.len())
            .expect("the fixture envelope admits one unit");
        let payload = output.into_payload_lease();
        {
            let state = registry.state.lock();
            assert!(
                retained_realtime_bytes(&state) > 0,
                "the lease is really holding bytes before the drop — without \
                 this the release assertion below would pass vacuously"
            );
        }

        // Assembled exactly as the inbound pump assembles one: a leaseless
        // delivery, with the queue's lease attached afterwards. Passed intact,
        // because that is the only shape the engine can hand over — it cannot
        // name the lease inside, let alone separate it.
        let mut delivery = RealtimeInboundDelivery::new(
            test_label(7),
            RealtimeRecvUnit {
                timestamp: 90_000,
                marker: true,
                data,
            },
        );
        delivery
            .attach(payload)
            .expect("a freshly built delivery has no lease to displace");

        assert!(
            !flows.deliver_inbound(delivery),
            "a label this session holds no flow for takes nothing"
        );

        drop(port);
        let state = registry.state.lock();
        assert_eq!(
            retained_realtime_bytes(&state),
            0,
            "the refused unit's lease was consumed by the drop, not stranded"
        );
        assert!(
            realtime_accounting_is_clean(&state),
            "and released rather than lost, which would poison the domain"
        );
    }

    #[test]
    fn v4_arc03_guarded_video_reordered_unit_transfers_exact_output_claim() {
        let registry = test_realtime_registry(explicit_realtime_workload(32, 1, 1, 8, 1));
        let flow = registry.open_inbound_flow().expect("flow is admitted");
        let mut assembler =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&flow));
        let anchor = assembler
            .push(&rtp_pkt(9, 100, true, IDR_NAL))
            .expect("anchor is valid")
            .expect("anchor emits");
        drop(anchor);
        assert!(assembler
            .push(&rtp_pkt(10, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert!(assembler
            .push(&rtp_pkt(12, 200, true, FU_E))
            .unwrap()
            .is_none());
        let unit = assembler
            .push(&rtp_pkt(11, 200, false, FU_M))
            .expect("late middle is valid")
            .expect("whole reordered unit emits");
        assert_eq!(unit.data.as_ref(), &[0, 0, 0, 1, 0x65, 0x11, 0x22, 0x33]);
        assert_eq!(
            retained_realtime_bytes(&registry.state.lock()),
            unit.data.len()
        );
        drop(unit);
        assert_eq!(retained_realtime_bytes(&registry.state.lock()), 0);
    }

    #[test]
    fn v4_arc03f_guarded_video_in_progress_limit_is_independent_per_flow() {
        let registry = test_realtime_registry(explicit_realtime_workload(32, 2, 1, 8, 1));
        let first_flow = registry
            .open_inbound_flow()
            .expect("first flow is admitted");
        let second_flow = registry
            .open_inbound_flow()
            .expect("second flow is admitted");
        let mut first =
            RealtimeUnitAssembler::guarded(h264_framing(), RealtimeFlowPortHandle::of(&first_flow));
        let mut second = RealtimeUnitAssembler::guarded(
            h264_framing(),
            RealtimeFlowPortHandle::of(&second_flow),
        );
        assert!(first.push(&rtp_pkt(1, 100, false, FU_S)).unwrap().is_none());
        assert!(second
            .push(&rtp_pkt(2, 200, false, FU_S))
            .unwrap()
            .is_none());
        assert_eq!(second.fragments_held(), 1);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            2
        );
        drop(first);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            1
        );
        drop(second);
        assert_eq!(
            RealtimeFlowRegistry::in_progress_units(&registry.state.lock()),
            0
        );
    }

    // A control asserting that one flow could not exceed *its own* in-progress
    // unit ceiling while a second flow kept an independent slot used to live
    // here. Both halves were the owner-selected per-flow unit ceiling: there is
    // no per-flow limit now, and the capacity that admits an assembly is one
    // pooled provider grant with no flow in it, so a second unit on the first
    // flow legitimately spends what a fixture intended for the second flow. No
    // grant size expresses "per flow" out of a pool — funding one assembly
    // refuses the second flow too, which is not the claim. What survives is that
    // in-progress units are counted and released per flow, and
    // `v4_arc03f_guarded_video_in_progress_limit_is_independent_per_flow` above
    // already proves exactly that, on two flows, without a ceiling.

    #[test]
    fn single_packet_units_emit_in_order() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        let s1 = asm.push(&rtp_pkt(1, 100, true, IDR_NAL)).unwrap().unwrap();
        assert!(s1.entry_point, "type-5 NAL is a decoder entry point");
        assert_eq!(&s1.data[..], &[0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
        let s2 = asm.push(&rtp_pkt(2, 200, true, IDR_NAL)).unwrap();
        assert!(s2.is_some(), "the anchored next unit emits too");
    }

    #[test]
    fn fragments_reassemble_even_when_reordered() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
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
        assert!(s.entry_point);
    }

    #[test]
    fn a_hole_mid_unit_drops_that_unit_never_a_torn_one() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
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
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
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
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
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
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Fresh stream joined mid-unit: middle + end fragments only.
        assert!(asm.push(&rtp_pkt(50, 100, false, FU_M)).unwrap().is_none());
        assert!(
            asm.push(&rtp_pkt(51, 100, true, FU_E)).unwrap().is_none(),
            "a contiguous-looking run that doesn't *start* a unit stays dropped"
        );
    }

    #[test]
    fn sequence_wraparound_is_transparent() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
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

    /// The connector's binding slot dies with the session that owns it, and a
    /// replacement points only at the new one.
    ///
    /// This is the `Weak` doing the whole job. The slot exists so `on_track`
    /// can find the table that says which flow a negotiated track may attach
    /// to, and the one thing it must never do is keep answering after the
    /// `PromotedSession` that owned those flows is gone — a table that outlived
    /// its session would resolve tokens to labels in a flow set that no longer
    /// exists.
    ///
    /// Three cases, and the middle one is the discriminating one: a strong
    /// slot would pass "install works" and "replacement points at the new set"
    /// identically, and would fail only here.
    #[test]
    fn v4_macro1_the_connector_binding_slot_cannot_outlive_its_session() {
        // No resources and no ceiling, and **no profile either**. What this
        // control exercises is the slot's `Weak`, which never consults codecs:
        // nothing here opens a flow or admits a track. A registry with no
        // resources could not pay for a profile record in any case — the
        // acquisition answers `OwnerPolicyMissing` before capacity is even a
        // question — so asking for one would make the fixture, rather than the
        // slot, the thing under test.
        let registry = RealtimeFlowRegistry::new(None);
        // Shared, because the table owns the retirement of the transceivers it
        // records and hands a clone of itself to whichever task performs one.
        // This control negotiates none, so that sweep has nothing to do here.
        let tracks = Arc::new(RealtimeSessionTracks::default());

        // Nothing installed yet: an arriving track has nothing to consult.
        assert!(
            tracks.current().is_none(),
            "a connector with no promoted session admits no inbound track"
        );

        let flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        tracks.install(flows.inbound_bindings());
        let installed = tracks
            .current()
            .expect("the installed table upgrades while its flow set is alive");
        assert!(
            flows.owns_bindings(&installed),
            "and it is *that* flow set's table, not merely some table"
        );
        // Released before the session ends, and that is load-bearing rather
        // than tidy: `current()` hands back a *strong* reference, so a control
        // still holding one is itself a second owner and the slot below would
        // upgrade for that reason alone. The premise of the next assertion is
        // that the flow set is the only strong holder.
        drop(installed);

        // The session ends. This is the case a strong slot would fail: the
        // flow set is the only strong holder, so dropping it must make the
        // connector's slot unupgradable.
        drop(flows);
        assert!(
            tracks.current().is_none(),
            "the table died with the session that owned the flows it names — a \
             strong slot here would have kept it resolving into a flow set that \
             no longer exists"
        );

        // A replacement session installs its own, and the slot points only at
        // the new one.
        let replacement = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        tracks.install(replacement.inbound_bindings());
        let current = tracks
            .current()
            .expect("the replacement's table upgrades in its turn");
        assert!(
            replacement.owns_bindings(&current),
            "the slot names the replacement's table and not a survivor of the \
             session it replaced"
        );
        drop(current);

        // And the replacement's own drop clears it again, so the slot is not
        // merely correct once.
        drop(replacement);
        assert!(tracks.current().is_none());
    }

    /// A flow that ends with nobody calling anything still submits its inbound
    /// transceiver's retirement, and a flow that is closed submits exactly one.
    ///
    /// **The gap.** The close path used to be the only submitter: it handed back
    /// a bare `Arc<RealtimeTrackIdentity>` and the engine stopped the
    /// transceiver against it. Every other way a flow ends — a revoked policy, a
    /// replaced peer, a shutdown, the promoted session simply being dropped —
    /// dropped that token and started nothing, leaving a `recvonly` transceiver
    /// and its `m` line on a connector that may well go on hosting another
    /// session. The superseding install does sweep those, but only when a *next*
    /// session is promoted, so on a connector that hosts no further session the
    /// leak has no end.
    ///
    /// **The observable is the track table's weak count**, which is exactly "how
    /// many retirements are still owed on it". That is what makes both legs
    /// discriminating rather than restatements of the code: a design that kept
    /// handing back a bare token would leave the count at zero throughout and
    /// satisfy nothing here, and a design that submitted on drop *and* on close
    /// would leave the explicit leg still owing a second stop for one
    /// transceiver, which the disarm assertion rejects.
    ///
    /// The implicit leg then separates *submitted* from *discarded*, which the
    /// weak count alone cannot: it reads the **process cleanup executor's own
    /// job count** across the drop. A retirement that reaches its submission
    /// adds a job there and can add one no other way, and the reading is the sum
    /// across every job state, so no single counter's transition can be mistaken
    /// for one. The sum is exact on a *settled* executor rather than at an
    /// arbitrary instant — see [`submitted_cleanup_jobs`] — so the leg waits for
    /// the executor's own thread to finish moving its counters and then asserts
    /// the total. That wait is about this fixture's reading, not about the
    /// submission: the submission is synchronous and has already happened when
    /// the destructor returns.
    ///
    /// **No runtime is required and that is the third property under test.** The
    /// review requires a drop-safe submission owner; a design that submitted
    /// through `tokio::runtime::Handle::try_current` would retire nothing when a
    /// flow set is dropped during a shutdown, an unwind, or on a bare thread. So
    /// the implicit leg runs on a plain `#[test]` with no runtime in scope at
    /// all, and a `try_current`-based submitter fails it outright.
    #[test]
    fn v4_arc05_an_implicitly_ended_inbound_flow_submits_its_retirement() {
        let registry = test_realtime_registry(explicit_realtime_workload(16, 1, 1, 16, 1));
        let name = fixture_flow_name();
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding names a shape a flow can carry");
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = FlowFixtureSession {
            incarnation: Arc::clone(&incarnation),
        };
        // Two retirements' worth of native funding, one per leg. Exact, so a
        // leg that leaked a queue slot would refuse the next mint rather than
        // pass quietly.
        let (
            _native_provider,
            native_owner,
            _native_mesh,
            _native_candidate,
            _native_lifetime,
            native_scope,
        ) = realtime_native_test_scope(0, 2, 2);
        // The cleanup owner both legs mint from. No transceiver is negotiated
        // against either token: what is under test is who owes the stop and
        // where the stop is submitted, not what performing one does.
        let tracks = Arc::new(RealtimeSessionTracks::default());
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(session_flow::leased_control_profile(&registry)),
        );
        let submitted_before = submitted_cleanup_jobs(&native_owner);

        // Leg one: an explicit close, which takes the submission and is then the
        // only party that will make one.
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: encoding.clone(),
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the fixture's one inbound slot opens"
        );
        let closed = RealtimeTrackIdentity::mint_for_test(&native_scope);
        flows
            .bind_inbound(
                &session,
                Some(&incarnation),
                &name,
                Arc::clone(&closed),
                test_inbound_retirement(&tracks, &closed, &native_scope),
            )
            .expect("an open inbound flow of a current session takes a binding");
        assert_eq!(
            Arc::weak_count(&tracks),
            1,
            "the flow, not the caller that minted it, is what owes this \
             transceiver its stop"
        );
        let remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        let RealtimeFlowRemains::Inbound(mut retirement) = remains else {
            panic!("closing a bound inbound flow hands back its retirement");
        };
        assert!(
            retirement.submits_on_drop(),
            "until the close takes it, this is still the thing that would submit"
        );
        assert!(
            Arc::ptr_eq(&retirement.take_for_explicit_close(), &closed),
            "and it names the exact token this flow was bound to"
        );
        assert!(
            !retirement.submits_on_drop(),
            "taking it disarms the drop, so the caller that will await the \
             receipt stays the single submitter on its own path"
        );
        drop(retirement);
        assert_eq!(
            Arc::weak_count(&tracks),
            0,
            "and a taken retirement leaves nothing behind that would stop one \
             transceiver a second time"
        );
        assert_eq!(
            submitted_cleanup_jobs(&native_owner),
            submitted_before,
            "an explicit close queues nothing: it runs the retirement on its own \
             task so it can await the receipt, and a job here would be a second \
             stop for one transceiver"
        );

        // Leg two: nobody closes anything. This is the case a bare token lost
        // outright.
        assert_eq!(
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding,
                    name: name.clone(),
                },
            ),
            Ok(name.clone()),
            "the slot the close released takes the second flow"
        );
        let ended = RealtimeTrackIdentity::mint_for_test(&native_scope);
        flows
            .bind_inbound(
                &session,
                Some(&incarnation),
                &name,
                Arc::clone(&ended),
                test_inbound_retirement(&tracks, &ended, &native_scope),
            )
            .expect("the replacement flow takes its binding too");

        drop(flows);
        assert_eq!(
            Arc::weak_count(&tracks),
            0,
            "the session's end consumed the retirement rather than leaving it \
             owed by something that no longer exists"
        );
        // The submission itself is synchronous and is already done — what is
        // not yet done is the executor's own bookkeeping, whose counters move
        // one at a time on its thread. So this waits for that thread to settle
        // rather than for the submission, and then reads the total where it is
        // exact. Bounded rather than slept: the deadline exists to fail an
        // executor that never took the work at all, and a correct one is past
        // this in the first few yields.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let cleanup = native_owner.report().cleanup;
            if cleanup.queued_jobs == 0
                && cleanup.active_jobs == 0
                && submitted_cleanup_jobs(&native_owner) == submitted_before + 1
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the dropped flow set never reached the process cleanup executor \
                 with its retirement, so nothing will ever stop that transceiver"
            );
            std::thread::yield_now();
        }
        assert_eq!(
            submitted_cleanup_jobs(&native_owner),
            submitted_before + 1,
            "and consumed it by submitting exactly one retirement to the process \
             cleanup executor — from a plain test with no runtime in scope, which \
             is the case a `Handle::try_current` submitter loses outright. Exact \
             on a settled executor: one more than before, and not two, which is \
             what a design that submitted on drop *and* on close would leave"
        );
    }

    /// A connector that cannot fund a retirement does not negotiate the
    /// transceiver that would need one.
    ///
    /// **Reserve-before-need, and the "before" is the whole assertion.** The
    /// submission a retirement makes happens in a destructor, where there is no
    /// caller to refuse and nothing to report a refusal to. So the queue slot it
    /// will use is acquired while the flow is still being bound, which is the
    /// one moment a refusal is an ordinary refusal.
    ///
    /// The discriminating shape is a grant for exactly one. A design that
    /// acquired the slot lazily at drop time passes every liveness assertion and
    /// fails only here — and in production it would fail nowhere at all, it would
    /// just stop retiring transceivers on exactly the connectors that are already
    /// under pressure.
    ///
    /// The second queue-slot acquisition is the load-bearing half; the first is
    /// what proves the grant was not simply too small for anything, which would
    /// make the refusal true for the wrong reason.
    #[test]
    fn v4_arc05_a_connector_that_cannot_fund_a_retirement_refuses_it_at_bind() {
        let (_provider, owner, _mesh, _candidate, _lifetime, scope) =
            realtime_native_test_scope(0, 1, 1);
        let tracks = Arc::new(RealtimeSessionTracks::default());
        let slot_claim = crate::runtime::attempt::cleanup_job_claim()
            .expect("the retirement slot claim is representable");

        let funded = RealtimeTrackIdentity::mint_for_test(&scope);
        let first = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                slot_claim,
            )
            .expect("the grant funds the one retirement it was derived for");
        let retirement = tracks.retirement(
            Arc::clone(&funded),
            scope.cleanup_submission().clone(),
            first,
        );

        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    slot_claim,
                )
                .is_err(),
            "a second retirement has no queue slot to stand on, so the bind that \
             would have needed it refuses instead of negotiating a transceiver \
             nothing could later retire"
        );

        // And the refusal is capacity, not a permanently poisoned scope: the
        // slot comes back, so the next flow on this connector can be bound.
        // Without this the assertion above would also pass for a scope that had
        // simply stopped working.
        //
        // **It comes back when the retirement's job finishes, not when the
        // retirement drops.** The destructor does not release the slot; it hands
        // it to `submit_subordinate`, where it becomes the accepted job's own
        // funding and is released only when that job ends. That is the same
        // reserve-before-need asymmetry this control exists to state, seen from
        // the other end, and the earlier reading of it — "the slot comes back
        // when its retirement does" — was the reason this control failed under
        // load rather than a fact about the design.
        //
        // A *refused* submission is the other case and it is not this one: no
        // job survives to fund, so the slot is released the ordinary way, and
        // what moves to failed-cleanup retention there is the native charge —
        // the transceiver nobody could prove stopped — never the queue slot.
        // Stated in
        // `v4_arc05_a_refused_cleanup_executor_retains_the_transceivers_exact_claim`;
        // the executor here is live, so the accepted path is what runs.
        //
        // Deliberately still a plain `#[test]`. The cleanup executor owns the
        // thread and the runtime that await the job, which is what lets a
        // destructor submit from a bare thread at all, and it is observable from
        // here without one.
        let submitted_before = submitted_cleanup_jobs(&owner);
        let completed_before = owner.report().cleanup.completed_jobs;
        drop(retirement);

        // The earliest reading first, because it is the only one that can catch
        // a destructor releasing to the pool: an immediate re-acquisition may or
        // may not have raced the executor, and asserting either outcome outright
        // would be asserting a timing. What is invariant is the pairing —
        // capacity may only reappear once the job it was funding has finished. A
        // design that released at drop time shows up here as a grant with no
        // completion behind it, and it has to be asked *now*, before anything
        // below waits for that completion and makes the pairing trivially true.
        let early = scope.acquire(
            crate::resource::ResourceAuthorityClass::Admitted,
            slot_claim,
        );
        assert!(
            early.is_err() || owner.report().cleanup.completed_jobs > completed_before,
            "the slot was grantable again before the job it funds had run, so the \
             destructor released capacity it had already committed"
        );
        drop(early);

        // Now to actual completion, and to a job total that can be read exactly.
        // Both need the same thing — the executor's own thread to have finished
        // moving its counters — so it is one wait rather than two. The submission
        // is synchronous and already happened; what has not is the bookkeeping,
        // which crosses two handoffs where the total is momentarily wrong in
        // either direction (see [`submitted_cleanup_jobs`]). A timeout rather
        // than an unbounded spin, so an executor that never runs the job fails as
        // a failed control instead of a hung one.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            let cleanup = owner.report().cleanup;
            if cleanup.completed_jobs > completed_before
                && cleanup.queued_jobs == 0
                && cleanup.active_jobs == 0
                && submitted_cleanup_jobs(&owner) == submitted_before + 1
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the process cleanup executor never completed the submitted \
                 retirement, so the slot it funds could never come back"
            );
            std::thread::yield_now();
        }

        // The drop handed the slot to a job rather than to the pool. Asserted on
        // the settled executor, where the total is exact and nothing further can
        // move it: a destructor that had released instead of submitting leaves
        // the total where it was, and fails the wait above at its deadline.
        assert_eq!(
            submitted_cleanup_jobs(&owner),
            submitted_before + 1,
            "the dropped retirement submitted its slot as a cleanup job instead of \
             releasing it, which is the reserve-before-need asymmetry the bind \
             refusal above depends on"
        );

        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    slot_claim,
                )
                .is_ok(),
            "the completed job released its slot, so the refusal above was this \
             connector being full rather than this connector being broken"
        );
    }

    /// A stop that refuses moves the transceiver's exact claim into failed-
    /// cleanup retention; a stop that returns releases it.
    ///
    /// **The asymmetry is the whole property.** A completed `stop` is an
    /// observation that the native object is gone, and only then may its charge
    /// be handed back. A refused `stop` observes nothing, so releasing would
    /// grant this connector's next admission capacity it never actually
    /// recovered — the accounting equivalent of assuming a cleanup worked
    /// because it was attempted. The old path did exactly that: it logged the
    /// error, announced success, forgot the record and released everything.
    ///
    /// **Both readings come from the provider**, not from a tally this module
    /// keeps, because a local counter could agree with itself while the provider
    /// had already released the claim. And both are stated twice over — once as
    /// the retention total, once as whether the capacity can be granted again —
    /// so "retained" cannot be confused with "released and separately counted".
    ///
    /// The success leg is not decoration. Without it a design that retained
    /// unconditionally, and therefore leaked capacity on every ordinary close,
    /// would satisfy the failure leg perfectly.
    ///
    /// The grant is exactly two transceivers and no slots, so the acquisition
    /// assertions are about this control's own two records and nothing else.
    #[tokio::test]
    async fn v4_arc05_a_refused_native_stop_retains_the_transceivers_exact_claim() {
        let (provider, _owner, _mesh, _candidate, _lifetime, scope) =
            realtime_native_test_scope(2, 0, 2);
        let tracks = Arc::new(RealtimeSessionTracks::default());
        let transceiver_claim =
            negotiated_inbound_transceiver_claim().expect("the transceiver claim is representable");
        let record_claim =
            negotiated_inbound_record_claim().expect("the record claim is representable");
        let signal_claim =
            RealtimeRetirementSignal::mint_claim().expect("the completion claim is representable");

        // Both recorded before either is retired, so the grant is exhausted and
        // every acquisition below is a statement about what a retirement gave
        // back rather than about spare headroom.
        let (stopped, stopped_calls) = record_test_transceiver(&tracks, &scope, false);
        let (refused, refused_calls) = record_test_transceiver(&tracks, &scope, true);
        let retained_before = provider.retained_after_failed_cleanup();

        // The success leg.
        tracks.stop_claimed(&stopped).await;
        assert_eq!(
            stopped_calls.load(Ordering::Acquire),
            1,
            "the retirement reached the native stop exactly once"
        );
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            retained_before,
            "a stop that returned proves the object is gone, so nothing is \
             retained for it"
        );
        // Held, not dropped: this is the capacity the successful retirement gave
        // back, and holding it is what makes the refusal below mean "the failed
        // one is still charged" rather than "something was free".
        let recovered_record = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                record_claim,
            )
            .expect("forgetting the record freed its node, one allocation exactly");
        let recovered_native = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                transceiver_claim,
            )
            .expect("and the stopped transceiver's own claim is grantable again");
        let recovered_signal = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                signal_claim,
            )
            .expect("and so is the completion cell of the retirement that ended");

        // The failure leg.
        tracks.stop_claimed(&refused).await;
        assert_eq!(
            refused_calls.load(Ordering::Acquire),
            1,
            "the refused stop was genuinely attempted, once"
        );
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            retained_before
                .checked_add(transceiver_claim)
                .expect("the retained total is representable"),
            "and its exact NATIVE claim moved to failed-cleanup retention — this \
             claim alone, not the record's node with it, not a rounded one, and \
             not a different dimension"
        );
        // **Classification survives the refusal.** This is the assertion the
        // whole success-only removal exists for: the transceiver is still on the
        // peer connection, so a track arriving on it must still read as one this
        // side solicited. A design that forgot the record on every path would
        // pass every accounting assertion here and turn that track into one the
        // peer appears to have named.
        assert!(
            tracks.classifies(&refused),
            "a transceiver whose stop refused is still there, so its record is \
             still here to classify what arrives on it"
        );
        assert!(
            !tracks.classifies(&stopped),
            "while the one that really stopped is gone from the table — without \
             this the assertion above would pass on a table that never forgets \
             anything"
        );
        // And the record it kept is still charged for, exactly. The node is not
        // a bookkeeping entry that can be quietly released while the allocation
        // it names is still live.
        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    record_claim,
                )
                .is_err(),
            "so its node is still held too: the record is retained, not swept"
        );
        // The completion cell is likewise still held, because the retained
        // record still owns its retirement. Only the finished one came back.
        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    signal_claim,
                )
                .is_err(),
            "and so is its completion cell — one cell came back, from the record \
             that was actually forgotten"
        );
        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    transceiver_claim,
                )
                .is_err(),
            "and the retained native claim is still counted against this \
             connector, so the capacity behind a transceiver nobody could stop is \
             not handed out again"
        );
        // A later party reaching the retained record loses the claim and must
        // still be released. The winning attempt announced its end even though
        // the stop refused; without that this call would park forever on a
        // completion nobody is left to make. Bounded rather than slept: the
        // timeout is a deadline for a hang, not a wait for a scheduler.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tracks.stop_claimed(&refused),
        )
        .await
        .expect("a loser on a refused retirement is released rather than wedged");
        assert_eq!(
            refused_calls.load(Ordering::Acquire),
            1,
            "and it started no second stop: the claim is still taken, so the \
             refusal is not retried by whoever arrives next"
        );
        drop((recovered_record, recovered_native, recovered_signal));
    }

    /// A cleanup executor that refuses a retirement retains the transceiver's
    /// exact claim rather than dropping it on the floor.
    ///
    /// The other end of the same obligation. Blocker one moved the submission
    /// off `Handle::try_current` and onto the process cleanup executor, which
    /// makes the submission itself the thing that can fail — the executor can be
    /// unavailable, poisoned, or already torn down. A refused submission means
    /// **nobody will ever stop this transceiver**, which is exactly the state
    /// failed-cleanup retention exists to describe.
    ///
    /// Discriminating in two directions at once. A design that ignored the
    /// submission result would leave the retention total unmoved while the
    /// transceiver leaked; a design that treated refusal as completion would
    /// release the claim and hand the capacity straight back out. The stop
    /// counter rules out a third: nothing was stopped here, so the retention is
    /// not a successful cleanup being miscounted.
    ///
    /// The last leg is the one this control was extended for. Abandoning a
    /// retirement takes the claim, so **nobody else will ever announce** — and a
    /// party arriving afterwards through the ordinary path must still be
    /// released rather than parking on a completion that cannot come. That is a
    /// hang, not a wrong answer, so it is asserted with a deadline rather than
    /// with a sleep: the timeout exists to fail a wedge, and a correct
    /// implementation returns without ever reaching it.
    #[tokio::test]
    async fn v4_arc05_a_refused_cleanup_executor_retains_the_transceivers_exact_claim() {
        let (provider, owner, mesh, _candidate, _lifetime, scope) =
            realtime_native_test_scope(1, 1, 1);
        let tracks = Arc::new(RealtimeSessionTracks::default());
        let transceiver_claim =
            negotiated_inbound_transceiver_claim().expect("the transceiver claim is representable");
        let (identity, stops) = record_test_transceiver(&tracks, &scope, false);
        let retirement = test_inbound_retirement(&tracks, &identity, &scope);
        let retained_before = provider.retained_after_failed_cleanup();

        // The connector is fine; its process's cleanup executor is not.
        mesh.fail_cleanup_executor_for_test();

        // Settle before measuring anything. `fail_cleanup_executor_for_test`
        // terminates the executor thread, and that thread is what owns the
        // executor's infrastructure reservation: the lease is released as it
        // unwinds, asynchronously with respect to this one. A baseline taken
        // before that release counts a charge the final snapshot will not, and
        // the exact vector relation at the end of this control would then fail
        // on a dimension nothing here is about.
        //
        // `SocketOrHandle` is the exact predicate because that infrastructure
        // claim is the only Socket holder in this scope. Its reaching zero is
        // precisely "the executor's own lease is gone" and nothing else, so it
        // puts the baseline and the final snapshot on the same side of the
        // release rather than merely allowing time to pass.
        //
        // Bounded and yielded rather than slept: a correct teardown is past
        // this within the first few yields, and the deadline is here to fail an
        // executor that never releases at all, not to wait out a slow one.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        loop {
            if provider
                .in_use()
                .amount(crate::resource::ResourceClass::SocketOrHandle)
                == 0
            {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the failed cleanup executor never released its infrastructure \
                 reservation, so no baseline taken here could be compared with a \
                 total taken after the drop"
            );
            tokio::task::yield_now().await;
        }

        // Read before the drop, because a refusal does two different things to
        // two different charges — one retained, one returned — and stating
        // either against a total taken afterwards would let them stand in for
        // each other.
        let in_use_before = provider.in_use();
        let failed_before = owner.report().cleanup.failed_jobs;

        // The implicit end, into an executor that will not take the work.
        drop(retirement);
        assert_eq!(
            stops.load(Ordering::Acquire),
            0,
            "a refused submission stops nothing, which is why the claim cannot \
             be released"
        );
        // Provenance, so the retention below is the *executor* refusing rather
        // than a retirement that was never submitted at all. A drop that
        // returned early — no table, no slot — would retain nothing and count
        // nothing, and without this the accounting assertions could not tell
        // that apart from a refusal.
        assert_eq!(
            owner.report().cleanup.failed_jobs,
            failed_before + 1,
            "the retirement really reached the executor and the executor really \
             refused it"
        );
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            retained_before
                .checked_add(transceiver_claim)
                .expect("the retained total is representable"),
            "so the transceiver's exact native claim moved to failed-cleanup \
             retention at the moment the submission was refused"
        );

        // The queue slot is the one charge a refusal genuinely gives back, and
        // it is not the native one: there is no job left to fund, so its lease
        // is released the ordinary way while the native claim — the thing
        // nobody could prove gone — stays held. Taken back here and **held to
        // the end of this control**, because that returned capacity is exactly
        // what the refusals below would otherwise be satisfied by: they are
        // statements about an exhausted grant, and a spare slot would let them
        // pass while measuring a dimension nobody asked about.
        let returned_slot = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                crate::runtime::attempt::cleanup_job_claim()
                    .expect("the retirement slot claim is representable"),
            )
            .expect(
                "a refused submission has no job left to fund, so the queue slot it \
                 was carrying came back",
            );
        // And with it back the provider holds what it held before the drop,
        // less exactly one of its own reservation records. That subtraction is
        // the whole precision of this assertion rather than a fudge factor:
        // `retain_after_failed_cleanup` keeps the transceiver's raw claim in
        // use — that is what retention *is* — while the reservation it was held
        // under stops existing, and a reservation record is itself charged
        // against the same envelope it records. So the exact expected shape
        // after re-taking the slot is "one record lighter, native claim
        // untouched", stated as one vector relation.
        //
        // Still stronger than either half alone: a design that released the
        // native claim shows up here as a shortfall far larger than one record,
        // one that also retained the queue slot shows up at the acquire above,
        // and one that leaked the record shows up as no shortfall at all.
        let expected_in_use = in_use_before
            .checked_sub(FiniteResourceProvider::scope_record_charge_for_test())
            .expect("the in-use total covers the record the retention removed");
        assert_eq!(
            provider.in_use(),
            expected_in_use,
            "the refusal returned this retirement's queue slot and dropped the \
             refused reservation's own record, and did neither of those things \
             to the transceiver's raw claim, which stayed exactly where it was"
        );

        // A second returned charge, sealed the same way the queue slot is.
        //
        // Terminating the executor releases the infrastructure lease its thread
        // owned, and that capacity comes back to the one grant every
        // acquisition here draws on. It covers a whole transceiver claim on
        // every dimension a transceiver claim uses — CallbackOrScheduledWork
        // 1 >= 1, OpaqueDependencyResidual 4 >= 4, and a tokio runtime plus
        // three handles against one native port — so left standing it, and not
        // the retention under test, is what the probes below would be
        // measuring.
        //
        // This value is a control-owned pressure seal shaped like that
        // infrastructure claim. It is not a live executor, and holding it
        // asserts nothing about ownership: no thread, runtime or queue exists
        // behind it. Its only job is to occupy the capacity a terminated
        // executor handed back, so the refusals below are about the
        // transceiver's retained claim and nothing else.
        //
        // Placed *after* the ledger assertion above, deliberately. Taken any
        // earlier it would be inside the totals that assertion compares, and
        // could then stand in for retention or for a returned record — the two
        // things that assertion exists to tell apart. After it, the exact
        // vector relation is already proved and this cannot participate in it.
        //
        // The `expect` is the discriminator rather than a formality: an
        // executor that leaked its infrastructure on termination leaves this
        // capacity unavailable and fails here by name, instead of quietly
        // satisfying the probes below.
        let infrastructure_seal = scope
            .acquire(
                crate::resource::ResourceAuthorityClass::Admitted,
                crate::runtime::attempt::cleanup_executor_infrastructure_claim()
                    .expect("the executor infrastructure claim is representable"),
            )
            .expect(
                "a terminated cleanup executor released the exact infrastructure \
                 capacity its thread was holding",
            );
        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    transceiver_claim,
                )
                .is_err(),
            "and it is still counted, so this connector cannot admit another \
             transceiver on capacity a failed cleanup never returned"
        );
        // The record is deliberately still on the table, so its node is still
        // charged. Classification has to survive an abandoned retirement for the
        // same reason it survives a running one: a track arriving on that
        // transceiver is still one this side negotiated, and a table that had
        // dropped the record would call it a track the peer named.
        assert!(
            scope
                .acquire(
                    crate::resource::ResourceAuthorityClass::Admitted,
                    negotiated_inbound_record_claim().expect("the record claim is representable"),
                )
                .is_err(),
            "and the record's node is still held too, because the record itself \
             was kept rather than swept along with the failed submission"
        );

        // The abandoned retirement took the claim, so this caller loses it and
        // waits — on a completion the abandoning path is the only one left to
        // make. Before that path announced, this hung forever.
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            tracks.stop_claimed(&identity),
        )
        .await
        .expect("a party arriving after an abandoned retirement is released, not wedged");
        assert_eq!(
            stops.load(Ordering::Acquire),
            0,
            "and it started no stop of its own: the abandoned retirement is \
             terminal, not a slot the next caller may retry into"
        );
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            retained_before
                .checked_add(transceiver_claim)
                .expect("the retained total is representable"),
            "and the accounting is unchanged by that visit — a loser retains \
             nothing, because it was never holding the charge"
        );
        // Both held all the way to here on purpose: released any earlier and
        // every refusal above would have had returned capacity standing behind
        // it — the queue slot the refusal gave back, and the infrastructure the
        // terminated executor gave back. The terminal visit above is inside
        // that span for the same reason, so it observes the same exhausted
        // grant the probes did rather than one that quietly refilled underneath
        // it.
        drop(returned_slot);
        drop(infrastructure_seal);
    }

    /// An FU-B start fragment is not an anchor, because this side cannot frame
    /// one.
    ///
    /// The two halves of the assembler have to agree about which payloads it
    /// can act on. `annexb_output_len` handles single NAL, STAP-A and FU-A and
    /// errors on everything else, so anchoring on an FU-B (type 29) commits to
    /// a chain the framing then always rejects. `try_emit` treats a framing
    /// error as a *consumed* unit — it advances `prev_end` and clears — so the
    /// cost is the whole unit, repeated for as long as the peer sends FU-B,
    /// rather than one refused packet.
    ///
    /// The discriminating comparison is against FU-A, which is byte-identical
    /// apart from the NAL type and must still anchor: a fix that refused both
    /// would stop the deployed H.264 path dead and would pass a test that only
    /// asserted the FU-B negative.
    #[test]
    fn v4_macro1_an_fu_b_fragment_is_not_an_anchor_the_framing_would_reject() {
        // 0x7D = FU-B (type 29) with the same start bit and NAL header the
        // FU-A fixtures use, so the only difference from `FU_S` is the type.
        const FU_B_S: &[u8] = &[0x7D, 0x85, 0x11];

        assert!(
            payload_starts_au(&Bytes::from_static(FU_S)),
            "FU-A still anchors — this is the deployed shape and refusing it \
             would be worse than the defect"
        );
        assert!(
            !payload_starts_au(&Bytes::from_static(FU_B_S)),
            "FU-B does not, because the framing has no case for type 29"
        );

        // The reason, stated against the framing itself rather than restated:
        // an FU-B chain really is unframeable, so admitting it as an anchor
        // could only ever produce the error path.
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(0i64, Bytes::from_static(FU_B_S));
        assert!(
            H264Framing
                .framed_len(UnitFragments::new(
                    &parts,
                    FragmentCursor::for_test(0),
                    FragmentCursor::for_test(0)
                ))
                .is_err(),
            "type 29 has no framing case, which is what makes anchoring on it \
             a guaranteed lost unit"
        );
    }

    /// A retransmit arriving after a successful emit does not rewind the
    /// assembler or cost the next unit its anchor.
    ///
    /// The steady state between two units is `parts` empty and `prev_end`
    /// holding the last marker. Testing emptiness to decide whether a
    /// timestamp may be adopted therefore accepts an *older* timestamp in
    /// exactly that state — the assembler rewinds, files the stale packet as
    /// the start of a new unit, and the next genuine packet then sees a
    /// non-empty `parts`, discards `prev_end` as an abandoned unit, and forces
    /// the unit after it to re-anchor.
    ///
    /// So the visible damage is one unit *later* than the stale packet, which
    /// is what makes it worth a control: the retransmit itself is correctly
    /// swallowed either way, and only the third unit shows the difference.
    #[test]
    fn v4_macro1_a_retransmit_after_an_emit_does_not_rewind_the_assembler() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());

        // Unit one emits and anchors the stream at seq 10.
        let first = asm
            .push(&rtp_pkt(10, 100, true, IDR_NAL))
            .unwrap()
            .expect("a single-packet unit emits immediately");
        assert_eq!(first.rtp_timestamp, 100);

        // A duplicate of that same unit arrives late, in the window where
        // `parts` is empty because the emit cleared it.
        assert!(
            asm.push(&rtp_pkt(10, 100, true, IDR_NAL))
                .unwrap()
                .is_none(),
            "the stale copy emits nothing, which is true before and after the \
             fix and is therefore not the discriminating assertion"
        );

        // The next unit is fragmented, so it can only emit if `prev_end`
        // survived: its first fragment is an FU-A start, and re-anchoring
        // would work here too — so make the unit after it the real test.
        assert!(asm.push(&rtp_pkt(11, 200, false, FU_S)).unwrap().is_none());
        let second = asm
            .push(&rtp_pkt(12, 200, true, FU_E))
            .unwrap()
            .expect("the anchor survived the stale retransmit");
        assert_eq!(second.rtp_timestamp, 200);
        assert_eq!(&second.data[..], &[0, 0, 0, 1, 0x65, 0x11, 0x33]);

        // And a headless unit — one with no start fragment — still emits,
        // which it can do only from a live anchor. This is the assertion that
        // separates the two implementations: with the rewind, `prev_end` is
        // gone by now and this unit is dropped for want of something
        // `payload_starts_au` accepts.
        assert!(asm.push(&rtp_pkt(13, 300, false, FU_M)).unwrap().is_none());
        let third = asm
            .push(&rtp_pkt(14, 300, true, FU_E))
            .unwrap()
            .expect("a headless unit emits from the surviving anchor");
        assert_eq!(third.rtp_timestamp, 300);
    }

    /// A stream whose first packet carries a high random RTP timestamp still
    /// starts.
    ///
    /// The companion to the control above, and the reason the fix cannot
    /// simply compare timestamps. `self.timestamp` initialises to 0 while a
    /// real sender picks a random 32-bit start, so for roughly half of all
    /// streams the first packet is "older than zero" under shortest-distance
    /// comparison. Without an explicit uninitialised case those streams would
    /// never produce a single unit.
    #[test]
    fn v4_macro1_a_stream_starting_past_the_wrap_point_still_emits() {
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Greater than 2^31, so `newer_rtp_ts(ts, 0)` is false.
        let high = 0x9000_0000u32;
        assert!(
            !crate::transport::webrtc::unit_assembly::newer_rtp_ts(high, 0),
            "the fixture really is on the far side of the wrap, or this test \
             proves nothing"
        );
        let unit = asm
            .push(&rtp_pkt(7, high, true, IDR_NAL))
            .unwrap()
            .expect("the first packet of a stream is adopted whatever its timestamp");
        assert_eq!(unit.rtp_timestamp, high);
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

    /// Build a lab producer from a policy stating exactly these per-class
    /// ceilings, at an explicit slot count.
    fn lab_producer(
        slots: usize,
        control_ceiling: usize,
        endpoint_ceiling: usize,
    ) -> CallbackProducerOwner {
        let slots = NonZeroUsize::new(slots).expect("the control states a nonzero slot count");
        CallbackProducerOwner::for_local_lab_grant(callback::TransportLabCallbackGrant {
            control_slots: slots,
            endpoint_slots: slots,
            control_payload_bytes: NonZeroUsize::new(control_ceiling)
                .expect("the control states a nonzero control ceiling"),
            endpoint_payload_bytes: NonZeroUsize::new(endpoint_ceiling)
                .expect("the control states a nonzero endpoint ceiling"),
            observation_slots: lab_observation_slots(),
        })
        .expect("a grant that states both ceilings derives a lab provider")
    }

    // The size of a host candidate actually gathered on the native loopback
    // path, not a round number. These controls exist because candidates of about
    // this size were refused for want of `QueuedBytes`.
    const GATHERED_CANDIDATE_BYTES: usize = 69;

    /// The native peak, exactly: one executing control callback still retaining
    /// its converted payload while the handoff behind it takes a queued lease at
    /// the same size. That is the moment the native pump reaches, and the moment
    /// that was refused.
    ///
    /// Built from the real transitions in the real order — structural admission,
    /// `begin_execution`, `account_executing_payload` with the measured bytes,
    /// then the queued admission — rather than from two independent admissions,
    /// because two independent admissions never put both phases in flight at
    /// once and so cannot tell a grant that funds both from one that funds
    /// either.
    ///
    /// Non-vacuity is structural rather than hoped for. The policy states one
    /// control slot, one endpoint slot, a control ceiling of exactly the
    /// candidate size and an endpoint ceiling of one byte, so the pool holds
    /// `QueuedBytes` for exactly one control handoff plus one byte. A build
    /// whose formula funded only the executing phase would grant zero
    /// `QueuedBytes` and fail at the handoff; one that funded only the queued
    /// phase would fail at `account_executing_payload`; one still cross-funding
    /// classes, or handing the five lifecycle reservations payload surplus,
    /// would pass the third admission, which must be refused. Each of those is a
    /// separate assertion below.
    #[test]
    fn v4_f8_one_executing_control_payload_and_its_queued_handoff_coexist_at_the_stated_ceiling() {
        // Endpoint deliberately starved to one byte: if this control passes, it
        // passed on control's own ceiling and not on endpoint's.
        let producer = lab_producer(1, GATHERED_CANDIDATE_BYTES, 1);

        // Admission is structural — the candidate has not been converted yet and
        // its size is not known.
        let mut executing = producer
            .try_admit_with_accounted_slack(ConnectorCallbackClass::Control, 0, 0)
            .expect("the structural control admission is funded");
        executing
            .begin_execution()
            .expect("the executing phase of one control callback is funded");
        producer
            .account_executing_payload(&mut executing, GATHERED_CANDIDATE_BYTES, 0)
            .expect("the executing lease retains the converted candidate's measured bytes");
        assert!(
            executing
                .claim()
                .amount(crate::resource::ResourceClass::AccountedMemoryBytes)
                >= GATHERED_CANDIDATE_BYTES as u64,
            "the executing lease must retain the measured payload, not the structural claim it was admitted with"
        );

        // The peak: the handoff is admitted while the lease above is still held
        // and still retaining its payload.
        let queued = producer
            .try_admit_with_accounted_slack(
                ConnectorCallbackClass::Control,
                GATHERED_CANDIDATE_BYTES,
                0,
            )
            .expect("the queued handoff is funded while the executing payload is still retained");
        assert!(
            queued
                .claim()
                .amount(crate::resource::ResourceClass::QueuedBytes)
                >= GATHERED_CANDIDATE_BYTES as u64,
            "the queued handoff must charge the candidate's bytes against QueuedBytes"
        );

        // One control slot was stated, so a second handoff must be refused while
        // the first two leases are live. Without this the assertions above could
        // be passing on surplus — cross-funded from the endpoint class, or from
        // the lifecycle reservations.
        let Err(CallbackProducerOverload::ResourceUnavailable { class, unavailable }) = producer
            .try_admit_with_accounted_slack(
                ConnectorCallbackClass::Control,
                GATHERED_CANDIDATE_BYTES,
                0,
            )
        else {
            panic!(
                "a one-slot control ceiling must not fund a second queued handoff beside the peak"
            )
        };
        assert_eq!(class, ConnectorCallbackClass::Control);
        // The dimension is the load-bearing half. A refusal on slots or on a
        // bookkeeping dimension would satisfy the class check while saying
        // nothing about the bytes the stated ceiling exists to fund, and this
        // control would then pass for the wrong reason.
        assert_eq!(
            unavailable.dimension(),
            Some(crate::resource::ResourceClass::QueuedBytes),
            "the refusal must land on the byte dimension the control ceiling funds"
        );

        // Both held to the end: releasing either would let the refusal above
        // pass against capacity the peak had already returned.
        drop((executing, queued));
    }

    /// Each class is funded from its own stated ceiling, and neither pays for
    /// the other.
    ///
    /// The two halves differ in nothing but which class was given the bytes, so
    /// a build funding both from one shared number — `max(control, endpoint)`,
    /// the softer form of the original defect — would admit both admissions in
    /// both halves and fail this.
    #[test]
    fn v4_f8_a_generous_ceiling_on_one_callback_class_does_not_fund_the_other() {
        let control_only = lab_producer(1, GATHERED_CANDIDATE_BYTES, 1);
        let held = control_only
            .try_admit_with_accounted_slack(
                ConnectorCallbackClass::Control,
                GATHERED_CANDIDATE_BYTES,
                0,
            )
            .expect("control's own stated ceiling funds a control callback");
        assert!(
            matches!(
                control_only.try_admit_with_accounted_slack(
                    ConnectorCallbackClass::EndpointData,
                    GATHERED_CANDIDATE_BYTES,
                    0,
                ),
                Err(CallbackProducerOverload::ResourceUnavailable {
                    class: ConnectorCallbackClass::EndpointData,
                    ..
                })
            ),
            "a one-byte endpoint ceiling must not be rescued by control's generous one"
        );
        drop(held);

        let endpoint_only = lab_producer(1, 1, GATHERED_CANDIDATE_BYTES);
        let held = endpoint_only
            .try_admit_with_accounted_slack(
                ConnectorCallbackClass::EndpointData,
                GATHERED_CANDIDATE_BYTES,
                0,
            )
            .expect("endpoint's own stated ceiling funds an endpoint callback");
        assert!(
            matches!(
                endpoint_only.try_admit_with_accounted_slack(
                    ConnectorCallbackClass::Control,
                    GATHERED_CANDIDATE_BYTES,
                    0,
                ),
                Err(CallbackProducerOverload::ResourceUnavailable {
                    class: ConnectorCallbackClass::Control,
                    ..
                })
            ),
            "a one-byte control ceiling must not be rescued by endpoint's generous one"
        );
        drop(held);
    }

    // Two controls stood here proving that a self-funding fixture which stated
    // no per-class payload ceiling was refused by name rather than having its
    // payload priced at zero. Both are gone, and the property is stronger for
    // it: the ceilings are now required fields on `TransportLabCallbackGrant`
    // and `TransportLabCallbackWorkload`, so a fixture that omits one does not
    // compile. There is no run-time state left for a control to observe.

    #[tokio::test]
    async fn loopback_handshake_opens_data_channel() {
        // Bring up two peer sessions on the same in-process
        // Transport. No STUN / TURN, so the pairing is whatever
        // host candidate gathering produces — and that is *not*
        // loopback. Nothing in this crate calls
        // `SettingEngine::set_include_loopback_candidate`, which
        // is off by default, so `127.0.0.1` is never offered. The
        // two sides pair over this machine's own routable
        // interface addresses, whichever survive the virtual-
        // interface and link-local filters installed in
        // `Transport::new`. This host must therefore accept its
        // own UDP on that address for the pairing to complete.
        // Verifies the entire offer/answer/candidate cycle plus
        // the data-channel handshake without external
        // dependencies.
        let observed_at = Instant::now();
        let transport = Transport::new().expect("transport");
        let cfg = RTCConfiguration::default();
        let callback_policy = test_webrtc_profile(NATIVE_LOOPBACK_CALLBACK_CAPACITY).callbacks();
        let callback_grant = lab_callback_grant(
            NonZeroUsize::new(NATIVE_LOOPBACK_CALLBACK_CAPACITY)
                .expect("the loopback fixture callback capacity is nonzero"),
            NonZeroUsize::new(NATIVE_LOOPBACK_CALLBACK_CAPACITY)
                .expect("the loopback fixture callback capacity is nonzero"),
        );
        let (offerer, mut off_rx) = transport
            .open_peer_with_config(Role::Offerer, cfg.clone(), callback_policy, callback_grant)
            .await
            .expect("offerer");
        let (answerer, mut ans_rx) = transport
            .open_peer_with_config(Role::Answerer, cfg, callback_policy, callback_grant)
            .await
            .expect("answerer");

        let offer = offerer.create_offer().await.expect("create_offer");
        let offer_credentials =
            sdp_ice_credentials(&offer.sdp).expect("native offer exposes exact ICE credentials");
        answerer
            .set_remote_description(offer)
            .await
            .expect("answerer.set_remote");
        let answer = answerer.create_answer().await.expect("create_answer");
        let answer_credentials =
            sdp_ice_credentials(&answer.sdp).expect("native answer exposes exact ICE credentials");
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
                        assert!(
                            candidate_matches_remote_credentials(c, &offer_credentials),
                            "native offer candidate {c:?} must identify its exact SDP binding {offer_credentials:?}"
                        );
                        answerer
                            .add_ice_candidate(c.clone())
                            .await
                            .expect("add ice to answerer");
                    }
                    if matches!(ev, TransportEvent::DataChannelOpen) { off_open = true; }
                }
                Some(ev) = ans_rx.recv() => {
                    if let TransportEvent::LocalIceCandidate(Some(c)) = &ev {
                        assert!(
                            candidate_matches_remote_credentials(c, &answer_credentials),
                            "native answer candidate {c:?} must identify its exact SDP binding {answer_credentials:?}"
                        );
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
        assert!(
            !offerer
                .media_negotiation_callback
                .armed
                .load(Ordering::Acquire)
                && !answerer
                    .media_negotiation_callback
                    .armed
                    .load(Ordering::Acquire),
            "initial data-channel setup must not arm the post-promotion media renegotiation lane"
        );

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
        let mut asm = RealtimeUnitAssembler::new(h264_framing());
        // Two single-NAL packets of one frame; marker closes it.
        assert!(asm
            .push(&rtp_pkt(1, 1000, false, &[0x41, 1, 1, 1]))
            .unwrap()
            .is_none());
        let s = asm
            .push(&rtp_pkt(2, 1000, true, &[0x65, 2, 2, 2]))
            .unwrap()
            .expect("marker completes the unit");
        assert!(
            s.entry_point,
            "an IDR NAL anywhere in the unit marks it a decoder entry point"
        );
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
        assert!(!s.entry_point);
        assert_eq!(s.data.as_ref(), &[0, 0, 0, 1, 0x41, 9, 9, 9]);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03h_data_only_and_generic_realtime_without_flows_allocate_no_media_lines() {
        for (profile_name, profile) in [
            ("disabled", test_webrtc_profile(4)),
            (
                "generic-without-open-flow",
                test_generic_realtime_webrtc_profile(4),
            ),
        ] {
            let observed_at = Instant::now();
            let grant = one_mesh_connector_fixture_grant(
                &[profile.clone()],
                lab_callback_workload(NonZeroUsize::new(4).expect("four is nonzero")),
            )
            .expect("the codec-neutral fixture claim is representable");
            let provider = ResourceProviderPort::new(FiniteResourceProvider::new(grant))
                .expect("the codec-neutral fixture accounts for its process scope");
            let owner = ConnectorResourceOwnerPort::new(provider)
                .issue_mesh_scope()
                .expect("the codec-neutral fixture accounts for its Mesh scope");
            let process = ProcessResourceRoot::isolated();
            let scope = process
                .mesh_runtime_scope()
                .network_instance_scope()
                .peer_connection_scope();
            let transport = Transport::new()
                .expect("test transport")
                .with_connector_resource_scope(owner, profile);
            let (worker, _events) = transport
                .open_connector_peer(Role::Offerer, &[], &[], scope)
                .await
                .expect("data-only connector is constructed");

            let offer = worker
                .create_offer()
                .await
                .expect("data-only connector creates an offer");
            assert!(offer
                .sdp
                .lines()
                .any(|line| line.starts_with("m=application")));
            assert!(!offer.sdp.lines().any(|line| line.starts_with("m=audio")));
            assert!(!offer.sdp.lines().any(|line| line.starts_with("m=video")));
            if std::env::var_os("MYOWNMESH_ARC03_OBSERVE_RAW").is_some() {
                println!(
                    "arc03_data_only_raw profile={} constructed_ns={} media_lines=0",
                    profile_name,
                    observed_at.elapsed().as_nanos()
                );
            }

            worker
                .retire_and_close()
                .await
                .expect("native peer closes through its exact owner");
        }
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_production_worker_drop_joins_sole_cleanup_owner() {
        let (provider, owner) =
            test_resource_owner_with_provider(1, 4, crate::resource::ResourceClaim::ZERO);
        let baseline = provider.in_use();
        let baseline_reservations = provider.active_reservations();
        let baseline_scopes = provider.active_scopes();
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner.clone(), test_webrtc_profile(4));
        let (worker, events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("the provider-funded connector is constructed");
        let native = Arc::clone(&worker.session.pc);
        let weak_native = Arc::downgrade(&native);
        let weak_control = Arc::downgrade(&events.raw.control);
        let weak_endpoint_data = Arc::downgrade(&events.raw.endpoint_data);
        let weak_lifecycle = Arc::downgrade(&events.raw.lifecycle);
        let mut retirement = worker.ownership.incarnation.subscribe_retirement();
        let (task_started_tx, task_started_rx) = oneshot::channel();
        let task_finished = Arc::new(AtomicBool::new(false));
        let task_finished_in_task = Arc::clone(&task_finished);
        let task = tokio::spawn(async move {
            task_started_tx
                .send(())
                .expect("the Drop control still owns its start witness");
            retirement
                .changed()
                .await
                .expect("the worker retirement signal remains live through Drop");
            task_finished_in_task.store(true, Ordering::Release);
        });
        task_started_rx
            .await
            .expect("the retained task started before the worker was dropped");
        assert!(
            !task_finished.load(Ordering::Acquire),
            "non-vacuity: the retained task is parked on the worker retirement signal"
        );
        worker.close_owner.retain_transport_task(task);

        // The waiter owns the cleanup observation while the worker is the sole
        // public owner. Dropping the worker must therefore start exactly this
        // close path rather than detaching the native peer or its task.
        let waiter = worker.close_waiter();
        drop(worker);
        tokio::time::timeout(Duration::from_secs(10), waiter)
            .await
            .expect("hang guard: Drop must signal and join the retained task")
            .expect("the dropped worker's native close is observed");
        drop(events);

        assert_eq!(native.connection_state(), RTCPeerConnectionState::Closed);
        assert!(
            task_finished.load(Ordering::Acquire),
            "the close owner sealed and joined the retained transport task"
        );

        // The native peer deliberately remains alive for this first phase.
        // Its callback closures therefore retain the four construction
        // reservations that survive after the receiver is dropped. Derive
        // that delta from the canonical callback claims rather than baking in
        // allocator-dependent byte totals. The child connector scope carries
        // its own one-record bookkeeping charge.
        let construction_claims = callback::connector_construction_claims()
            .expect("connector construction claims are representable");
        let retained_delta = construction_claims
            .iter()
            .take(4)
            .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
                let reservation =
                    crate::resource::FiniteResourceProvider::reservation_charge_for_test(*claim)
                        .expect("callback reservation charge is representable");
                total.checked_add(reservation)
            })
            .expect("retained callback delta is representable")
            .checked_add(crate::resource::FiniteResourceProvider::scope_record_charge_for_test())
            .expect("retained callback scope delta is representable");
        let retained_in_use = baseline
            .checked_add(retained_delta)
            .expect("retained callback usage is representable");
        assert_eq!(provider.in_use(), retained_in_use);
        assert_eq!(
            provider.active_reservations(),
            baseline_reservations
                .checked_add(4)
                .expect("retained callback reservations are countable")
        );
        assert_eq!(
            provider.active_scopes(),
            baseline_scopes
                .checked_add(1)
                .expect("retained callback scope is countable")
        );
        assert!(weak_native.upgrade().is_some());
        assert!(weak_control.upgrade().is_some());
        assert!(weak_endpoint_data.upgrade().is_some());
        assert!(weak_lifecycle.upgrade().is_some());
        let report = owner.report();
        assert_eq!(report.active_candidates, 0);
        assert_eq!(report.failed_cleanup_candidates, 0);

        // Only the deliberately retained native owner is dropped here. The
        // transport and resource owner stay unchanged while callback closures
        // release their final funded owners.
        drop(native);
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                if weak_native.upgrade().is_none()
                    && weak_control.upgrade().is_none()
                    && weak_endpoint_data.upgrade().is_none()
                    && weak_lifecycle.upgrade().is_none()
                    && provider.in_use() == baseline
                    && provider.active_reservations() == baseline_reservations
                    && provider.active_scopes() == baseline_scopes
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("hang guard: retained native owner releases callback owners");

        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_reservations(), baseline_reservations);
        assert_eq!(provider.active_scopes(), baseline_scopes);
        let report = owner.report();
        assert_eq!(report.active_candidates, 0);
        assert_eq!(report.failed_cleanup_candidates, 0);
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03g_close_fence_rejects_endpoint_send() {
        let owner = test_resource_owner(1, 4);
        let process = ProcessResourceRoot::isolated();
        let scope = process
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");

        worker.retire();

        let error = worker
            .send_owned(Bytes::from_static(b"endpoint"))
            .await
            .expect_err("endpoint send is fenced after close");
        assert!(
            error
                .to_string()
                .contains("connector close fence has committed"),
            "the operation reached its native owner after close: {error}"
        );

        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03h_close_wins_before_open_promotion() {
        let owner = test_resource_owner(1, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("data-only connector is constructed");

        worker.retire();
        assert!(matches!(
            worker.confirm_data_channel_open(),
            DataChannelOpenOwnership::Rejected
        ));
        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    /// A retired connector can no longer be named by a promotion, so nothing
    /// downstream of promotion — including every real-time flow — can be opened
    /// against it. Close wins the race by removing the only identity the
    /// admission fence is allowed to bind.
    async fn v4_arc03h_close_wins_before_connector_naming() {
        let owner = test_resource_owner(1, 4);
        let owner_observation = owner.clone();
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_generic_realtime_webrtc_profile(4));
        let (worker, events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("real-time connector is constructed");
        let handoff = match worker.confirm_data_channel_open() {
            DataChannelOpenOwnership::Connected(handoff) => handoff,
            _ => panic!("live connector produces one Endpoint Auth handoff"),
        };
        let task = task_from_handoff(handoff);
        let exact_incarnation = worker
            .live_connector_incarnation()
            .cloned()
            .expect("non-vacuity: the connector exposes its live identity");
        let foreign_incarnation = crate::connector::ConnectorIncarnation::new();
        let exact_strong_count = Arc::strong_count(&exact_incarnation);
        let report_before_identity = owner_observation.report();
        let live_identity_before = worker.live_connector_incarnation().is_some();
        let mut exact_identity_before = true;
        let mut foreign_identity_before = true;
        for _ in 0..3 {
            exact_identity_before = worker
                .matches_connector_identity_for_retirement(&exact_incarnation)
                && exact_identity_before;
            foreign_identity_before = !worker
                .matches_connector_identity_for_retirement(&foreign_incarnation)
                && foreign_identity_before;
        }
        let exact_strong_count_unchanged_before =
            Arc::strong_count(&exact_incarnation) == exact_strong_count;
        let report_after_identity = owner_observation.report();
        let identity_reads_preserve_owner_state = report_before_identity.active_candidates
            == report_after_identity.active_candidates
            && report_before_identity.failed_cleanup_candidates
                == report_after_identity.failed_cleanup_candidates
            && report_before_identity.accounting_poisoned
                == report_after_identity.accounting_poisoned;
        let owns_endpoint_auth_before = worker.owns_endpoint_auth(&task);

        worker.retire();
        let live_identity_after = worker.live_connector_incarnation().is_none();
        task.retire();
        let task_identity_matches_after_retire =
            worker.matches_connector_identity_for_retirement(task.incarnation());
        let task_belongs_after_retire = task.belongs_to(task.incarnation());
        let retired_strong_count = Arc::strong_count(&exact_incarnation);
        let report_before_retired_identity = owner_observation.report();
        let mut exact_identity_after = true;
        let mut foreign_identity_after = true;
        for _ in 0..3 {
            exact_identity_after = worker
                .matches_connector_identity_for_retirement(&exact_incarnation)
                && exact_identity_after;
            foreign_identity_after = !worker
                .matches_connector_identity_for_retirement(&foreign_incarnation)
                && foreign_identity_after;
        }
        let exact_strong_count_unchanged_after =
            Arc::strong_count(&exact_incarnation) == retired_strong_count;
        let report_after_retired_identity = owner_observation.report();
        let retired_identity_reads_preserve_owner_state = report_before_retired_identity
            .active_candidates
            == report_after_retired_identity.active_candidates
            && report_before_retired_identity.failed_cleanup_candidates
                == report_after_retired_identity.failed_cleanup_candidates
            && report_before_retired_identity.accounting_poisoned
                == report_after_retired_identity.accounting_poisoned;
        let owns_endpoint_auth_after = worker.owns_endpoint_auth(&task);
        let close_result = worker.retire_and_close().await;
        drop(task);
        drop(events);
        drop(worker);
        drop(transport);
        drop(exact_incarnation);
        drop(foreign_incarnation);
        let final_report = owner_observation.report();
        assert!(live_identity_before);
        assert!(exact_identity_before);
        assert!(foreign_identity_before);
        assert!(exact_strong_count_unchanged_before);
        assert!(owns_endpoint_auth_before);
        assert!(live_identity_after);
        assert!(exact_identity_after);
        assert!(foreign_identity_after);
        assert!(exact_strong_count_unchanged_after);
        assert!(task_identity_matches_after_retire);
        assert!(!task_belongs_after_retire);
        assert!(!owns_endpoint_auth_after);
        assert!(identity_reads_preserve_owner_state);
        assert!(retired_identity_reads_preserve_owner_state);
        assert!(
            close_result.is_ok(),
            "native peer closes through its exact owner"
        );
        assert_eq!(final_report.active_candidates, 0);
        assert_eq!(final_report.failed_cleanup_candidates, 0);
        assert!(!final_report.accounting_poisoned);
    }

    /// A real-time unit is admitted only while the session that could have
    /// produced it still owns a live binding table.
    ///
    /// Driven through `accept_event`, which is the production entry point the
    /// engine's connector pump calls — not through `ConnectorOwnership::accepts`
    /// underneath it, which answers the connector question only and answers
    /// `true` for a connected connector however long ago its session died.
    ///
    /// The connector is held at `Connected` and untouched for the whole body,
    /// so every transition below is the session table's alone.
    #[tokio::test]
    #[ignore = "opens a native peer connection; run explicitly in the isolated WSL harness"]
    async fn v4_arc03_realtime_unit_requires_a_live_session_binding_table() {
        let owner = test_resource_owner(1, 4);
        let scope = ProcessResourceRoot::isolated()
            .mesh_runtime_scope()
            .network_instance_scope()
            .peer_connection_scope();
        let transport = Transport::new()
            .expect("test transport")
            .with_connector_resource_scope(owner, test_generic_realtime_webrtc_profile(4));
        let (worker, _events) = transport
            .open_connector_peer(Role::Answerer, &[], &[], scope)
            .await
            .expect("real-time connector is constructed");
        let _task = match worker.confirm_data_channel_open() {
            DataChannelOpenOwnership::Connected(handoff) => task_from_handoff(handoff),
            _ => panic!("live connector produces one Endpoint Auth handoff"),
        };

        // BEFORE PROMOTION. Connector authority is fully satisfied — the
        // connector is live, connected, and stamped these events itself — so a
        // refusal here is attributable to the session gate and to nothing else.
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(TransportEvent::DataChannelClosed))
                .is_some(),
            "non-vacuity: connector authority admits this worker's own events"
        );
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 0, b"early")))
                .is_none(),
            "a unit with no live session table behind it is refused before delivery"
        );

        // PROMOTED. The same event on the same connector is now admitted, which
        // is what makes the refusals on either side of it discriminating rather
        // than a path that never accepts a unit at all.
        let flows = worker.new_session_flows();
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 1, b"live")))
                .is_some(),
            "a promoted session's table is what admits a unit"
        );

        // SESSION GONE, CONNECTOR UNCHANGED. The table is held weakly, so
        // dropping the flow set is exactly what a `PromotedSession` dropping
        // does — no retirement, no close, no connector state change.
        drop(flows);
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(test_realtime_event(0, 2, b"late")))
                .is_none(),
            "and a unit outliving its session's table is refused again"
        );
        assert!(
            worker
                .accept_event(worker.stamp_event_for_test(TransportEvent::DataChannelClosed))
                .is_some(),
            "while the connector itself is untouched — the gate is the session's, not a retirement"
        );

        worker
            .retire_and_close()
            .await
            .expect("native peer closes through its exact owner");
    }

    #[test]
    fn v4_opaque_partial_request_rejects_nonzero_retransmit_profile() {
        let request = crate::realtime::OpaqueFlowOpen::new(
            b"unsupported-partial".to_vec(),
            crate::realtime::RealtimeFlowDirection::Outbound,
            crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits: 1 },
            128,
        )
        .expect("the label and body are representable; the mode is the rejected part");
        assert!(matches!(
            OpaqueFlowSpec::try_from(request),
            Err(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)
        ));
    }

    #[test]
    fn v4_opaque_native_lane_parameter_predicate_rejects_mismatch() {
        // This is a deterministic source-level control for the predicate used
        // by both real RTCDataChannel creation and the incoming callback. The
        // callback/runtime controls remain responsible for exercising actual
        // native getter values.
        assert!(opaque_native_parameters_match(
            OpaqueNativeLaneMode::ReliableOrdered,
            true,
            None,
            None,
        ));
        assert!(!opaque_native_parameters_match(
            OpaqueNativeLaneMode::ReliableOrdered,
            false,
            None,
            None,
        ));
        assert!(!opaque_native_parameters_match(
            OpaqueNativeLaneMode::ReliableOrdered,
            true,
            Some(0),
            None,
        ));
        assert!(!opaque_native_parameters_match(
            OpaqueNativeLaneMode::ReliableOrdered,
            true,
            None,
            Some(1),
        ));
        assert!(opaque_native_parameters_match(
            OpaqueNativeLaneMode::PartialUnordered,
            false,
            Some(0),
            None,
        ));
        assert!(!opaque_native_parameters_match(
            OpaqueNativeLaneMode::PartialUnordered,
            false,
            Some(1),
            None,
        ));
        assert!(!opaque_native_parameters_match(
            OpaqueNativeLaneMode::PartialUnordered,
            false,
            Some(0),
            Some(1),
        ));
    }
}
