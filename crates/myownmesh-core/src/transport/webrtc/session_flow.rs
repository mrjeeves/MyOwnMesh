//! Session-bound, codec-opaque real-time flows.
//!
//! The outward half of the connector-local flow registry. The registry owns
//! admission, queueing and resource accounting and says nothing about codecs;
//! this module adds the two things an application needs and the registry
//! deliberately does not have: a binding to one authenticated session, and a
//! name both ends can say out loud.
//!
//! **Two names, two jobs, never substituted.** A flow has a process-local
//! identity (`RealtimeFlowKey`, an allocation address that is never serialized
//! and grants nothing) and a session-scoped label ([`RealtimeFlowLabel`]) that
//! does cross the wire. The identity answers "is this the same flow object";
//! the label answers "which of this session's flows do these bytes belong to".
//! Neither is ever used for the other's question, for the same reason the RPC
//! layer keeps a pending operation's identity apart from its binding.
//!
//! **Nothing here is authority.** Opening a flow and sending on one both
//! require a live [`RealtimeSessionBinding`]; a label gets a holder nothing at
//! all, because the receiving side has already been handed the bytes by the
//! time it reads one. That is what makes the label safe to publish and safe to
//! cite back after a restart.

use super::*;

/// This module's own result.
///
/// Spelled out rather than reusing the crate-wide `Result<T>` alias that
/// `super::*` brings in: a flow refusal is not a crate error. Every variant of
/// [`RealtimeFlowError`] is a typed answer this layer's callers match on and
/// act differently for — a stale session is retried on a new one, an exhausted
/// label space is not — and flattening them into `crate::Error` would turn
/// that distinction into a string.
type FlowResult<T> = std::result::Result<T, RealtimeFlowError>;

/// What a flow is called, and what holding that name costs.
///
/// Its two exports are split by reach, not for tidiness. `RealtimeFlowName` is
/// the one name in the pair an application outside the crate constructs, so it
/// is re-exported at the visibility it is declared with; narrowing it to the
/// crate would make it unre-exportable from the connector module above and the
/// daemon would lose the only flow vocabulary it is meant to have. The label is
/// authority — it carries the lease that funds the name — and stays inside.
mod name;

pub use name::RealtimeFlowName;
pub(crate) use name::{RealtimeFlowIdentity, RealtimeFlowLabel};

/// What an application declares it can carry, and what holding that costs.
///
/// Split by reach the same way. The five plain-data types a daemon parses its
/// configuration into are published from the connector module above, so they
/// keep the visibility they are declared with rather than being narrowed to the
/// crate. The leased record and the two internal vocabularies are authority and
/// machinery, and stay in.
mod profile;

pub(crate) use profile::{LeasedRealtimeProfile, RealtimeEncoding, RealtimeUnitPolicy};
pub use profile::{
    RealtimeCodec, RealtimeFraming, RealtimeProfile, RealtimeProfileError, RealtimeRtcpFeedback,
    WebRtcRtpKind,
};

/// Which way units travel on a flow.
///
/// One direction per flow. A bidirectional application opens two, which keeps
/// each one's label, encoding and accounting its own — a display feed and a
/// return audio path have no reason to share a ceiling.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeDirection {
    /// This endpoint sends; the peer receives.
    Outbound,
    /// This endpoint receives; the peer sends.
    Inbound,
}

/// One unit handed to a flow for sending.
///
/// Carries the pacing duration the application already has rather than an
/// absolute timestamp it would have to synthesise. The control surface these
/// applications use today supplies a per-frame duration — canonically 20 ms
/// for an Opus frame — and the RTP clock is advanced from it at the connector
/// edge, which is where the clock lives.
///
/// **No marker, deliberately, and the asymmetry with [`RealtimeRecvUnit`] is
/// the point.** On the wire the marker bit is a statement about packetization —
/// last packet of an access unit, first packet of a talkspurt — which this
/// flow's framing policy decides and the packetizer is the only thing
/// positioned to get right. An outbound marker would let a caller contradict
/// the packetizer that is about to run, producing a stream whose marker bits
/// disagree with its own fragmentation. It is also unimplementable: the native
/// send API carries no marker field, so a value accepted here could only ever
/// be discarded.
///
/// Inbound keeps one because there it is a *report* rather than an
/// instruction — the bit the sender set, carried through unchanged.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeSendUnit {
    /// How long this unit occupies, which is what advances the RTP clock.
    pub(crate) pace: Duration,
    pub(crate) data: Bytes,
}

/// One application-owned opaque unit waiting for a persistent native lane.
/// The payload remains provider-neutral and its existing lease stays attached
/// until the worker has completed the native send.
#[derive(Clone, Debug)]
pub(crate) struct OpaqueSendUnit {
    pub(crate) data: Bytes,
    pub(crate) mode: crate::realtime::OpaqueFlowMode,
    pub(crate) direction: crate::realtime::RealtimeFlowDirection,
    pub(crate) coordinate: crate::protocol::ApplicationFlowCoordinate,
    pub(crate) max_unit_bytes: usize,
}

/// A dequeued opaque unit whose payload accounting remains live through the
/// native write. It cannot be forged by the engine because the payload lease
/// is minted only by the flow's queue.
pub(crate) struct OpaqueOutboundUnit {
    pub(crate) data: Bytes,
    pub(crate) mode: crate::realtime::OpaqueFlowMode,
    pub(crate) direction: crate::realtime::RealtimeFlowDirection,
    pub(crate) coordinate: crate::protocol::ApplicationFlowCoordinate,
    pub(crate) max_unit_bytes: usize,
    in_flight: Arc<queue::InFlightCounter>,
    _entry: crate::resource::queue::LeasedQueueEntry<queue::QueuedUnit<OpaqueSendUnit>>,
}

impl Drop for OpaqueOutboundUnit {
    fn drop(&mut self) {
        self.in_flight.finish();
    }
}

/// One unit received on a flow.
///
/// Deliberately *not* the same type as [`RealtimeSendUnit`]. Inbound really
/// does carry an absolute RTP timestamp at the flow's declared clock rate, and
/// outbound really does carry a duration; one type with a field meaning two
/// different things by direction is exactly the overload the applications
/// already suffer, where a single `u32` is documented as "µs for audio, RTP ts
/// for video". Two types cost one struct and remove the ambiguity entirely.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeRecvUnit {
    /// Absolute, ticking at [`RealtimeEncoding::clock_rate`].
    pub(crate) timestamp: u32,
    /// The significance bit the sender set, carried through unchanged.
    pub(crate) marker: bool,
    pub(crate) data: Bytes,
}

/// What opening or sending on a flow can refuse.
///
/// Every variant is a refusal of *this* operation. None of them retire a flow
/// or a session on their own; a flow whose session has gone answers
/// [`Self::SessionNotCurrent`] for as long as anything still holds it, and is
/// reclaimed when its holder drops it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RealtimeFlowError {
    /// The session no longer names a live connector incarnation: it was
    /// replaced, retired, or the process restarted. Never re-bound — the
    /// application promotes a new session and opens new flows.
    SessionNotCurrent,
    /// This session already holds a flow under the requested label.
    ///
    /// Also what a full namespace looks like from here. The application is the
    /// sole allocator, so this side only ever claims one exact value: there is
    /// no path that inspects the whole space and no separate exhaustion
    /// answer, because nothing here could produce one.
    LabelInUse,
    /// The connector refused the flow: its own ceiling, or resources.
    FlowRefused,
    /// The encoding was not usable — empty mime or zero clock rate.
    EncodingInvalid,
}

/// What a real-time flow needs from a promoted session.
///
/// Stated as a trait on this side of the transport boundary on purpose. The
/// session type is transport-independent and must not learn about WebRTC
/// incarnations; this is the narrow question the flow path actually asks, so
/// the session owner satisfies it without either module importing the other's
/// vocabulary.
///
/// Both halves of currentness are asked together and neither is cached. The
/// identity is the session's — it privately retains the exact incarnation it
/// was promoted from — and the liveness is the connector's, which is the one
/// authoritative source for it. A flag on the session that answered the second
/// question would be a second source that could disagree with the first.
pub(crate) trait RealtimeSessionBinding {
    /// Whether this session was promoted from exactly `incarnation`, and that
    /// incarnation is still live.
    fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool;

    // One method, and a `remote_device_id` was deliberately removed from beside
    // it. It was offered for attribution and nothing ever read it — which is the
    // right outcome rather than a gap to fill: this trait is the *gate* a flow
    // operation passes, and a gate that also hands out the peer's identity
    // invites a caller to route on what it was given instead of presenting the
    // session again. A diagnostic that wants the Device asks the session
    // directly, where reading it is not adjacent to being authorized.
}

/// One shared wake, and the lease that owns the block it lives in.
///
/// Reachable across the connector because a pump holds one: the inbound pump
/// awaits a flow's end and the outbound pump awaits its queue's ready, and both
/// of those tasks live outside this module.
mod wake;

pub(super) use wake::LeasedWake;

/// Where an outbound flow's units wait, and what wakes the pump that drains
/// them.
mod queue;

pub(super) use queue::RealtimePumpStep;
use queue::{FlowQueue, QueuedUnit, RealtimeFlowQueue};
pub(crate) use queue::{OpaqueOutboundPump, OpaquePumpStep, RealtimeOutboundPump};

/// A crate-visible waiter backed by the pending flow record's funded wake.
/// The wake's implementation and lease remain provider-private; callers can
/// only await the one readiness transition.
pub(crate) struct OpaquePendingWait(Arc<LeasedWake>);

impl OpaquePendingWait {
    pub(crate) async fn wait(self) {
        let wake = self.0;
        wake.notify().notified().await;
    }
}

/// One open flow: what it binds, what may still reach it, and what its close
/// leaves behind.
///
/// Split by reach for the third time in this file. The flow, what its close
/// leaves and what an open asks for are named by the engine, so they keep the
/// crate visibility they are declared with. The weak port handle and the
/// admitted-track bundle are the connector's and stop there, and the opener
/// belongs to this module alone.
mod flow;

use flow::{open_opaque_flow, open_session_flow, OpaqueFlowPendingChange, RealtimeFlowKind};
pub(crate) use flow::{
    OpaqueFlowChange, OpaqueFlowSpec, RealtimeFlow, RealtimeFlowRemains, RealtimeFlowSpec,
};
pub(super) use flow::{RealtimeFlowPortHandle, RealtimeInboundAttachment};

/// One session-scoped signal, and the single consumer that holds it.
mod session_stream;

use session_stream::SessionStream;
pub(crate) use session_stream::SessionStreamReader;

/// A connector drop reason, as the refusal this layer reports.
///
/// Every reason but one is a capacity answer — a ceiling, an oversize unit, a
/// poisoned domain — and they are all `FlowRefused`, because the caller's flow
/// could succeed later and the connector's vocabulary has no business in this
/// layer's error.
///
/// `Retired` is the exception and is the reason this function exists. The
/// registry retires with its connector, so a retired registry means the
/// session this flow belonged to is already gone. Reporting that as
/// `FlowRefused` would tell a caller to back off and retry a flow that can
/// never come back, and would hide a replacement behind what looks like
/// pressure. `SessionNotCurrent` is terminal, which is what it actually is.
fn realtime_drop_refusal(reason: RealtimeFlowDropReason) -> RealtimeFlowError {
    match reason {
        RealtimeFlowDropReason::Retired => RealtimeFlowError::SessionNotCurrent,
        _ => RealtimeFlowError::FlowRefused,
    }
}

/// The profile the controls in this module and its parent open flows against.
///
/// Two families, one of each framing, so both unit policies are reachable
/// without a control having to build a profile of its own.
///
/// It exists because `open` now refuses an unregistered family *before* it
/// acquires a label or a flow slot. A control passing no profile would have
/// every open answer `EncodingInvalid`, which would make the assertions after
/// it vacuous rather than failing — the exact shape of silent test rot this
/// module's controls are written to avoid.
#[cfg(test)]
pub(super) fn control_realtime_profile() -> RealtimeProfile {
    RealtimeProfile::new(vec![
        RealtimeCodec {
            kind: WebRtcRtpKind::Video,
            payload_type: 102,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
            fmtp: "packetization-mode=1".to_string(),
            framing: RealtimeFraming::AnnexB,
            rtcp_feedback: Vec::new(),
        },
        RealtimeCodec {
            kind: WebRtcRtpKind::Audio,
            payload_type: 111,
            mime: "audio/opus".to_string(),
            clock_rate: 48_000,
            channels: 2,
            fmtp: "minptime=10".to_string(),
            framing: RealtimeFraming::Whole,
            rtcp_feedback: Vec::new(),
        },
    ])
    .expect("the control profile registers two well-formed families")
}

/// The control profile as a session actually holds it: shared, and leased.
///
/// Minted rather than hand-built for the same reason a control label is. A
/// profile with no lease is not the shape a flow set ever carries, and a
/// fixture that built one would be proving something about a state production
/// cannot reach.
#[cfg(test)]
pub(super) fn leased_control_profile(registry: &RealtimeFlowRegistry) -> LeasedRealtimeProfile {
    LeasedRealtimeProfile::mint(control_realtime_profile(), registry)
        .expect("the fixture grant accounts for one control profile")
}

/// Which negotiated track may attach to which already-open inbound flow.
mod inbound_binding;

use inbound_binding::RealtimeInboundEntry;
pub(crate) use inbound_binding::{
    RealtimeInboundBinding, RealtimeInboundBindings, RealtimeTrackIdentity,
};

/// One arrived unit, whole, waiting where this session's consumer reads.
///
/// The three things an arrival is, in one entry that lives or dies together:
/// which flow it came in on, the unit, and the lease over its bytes. Splitting
/// them across two places — the unit and its lease on the flow, a notice of it
/// on the session — lets the two disagree, because closing the flow takes the
/// unit away and leaves the notice behind.
///
/// The label is the leased label rather than a copy of its name, so it is an
/// `Arc` clone and not a second allocation of the same bytes. It also settles
/// what a queued arrival means after its flow closes: the name stays paid for
/// and stays spelled by this entry until the entry is taken, so the unit that
/// comes out names the flow it actually arrived on.
pub(super) struct QueuedInboundUnit {
    label: RealtimeFlowLabel,
    unit: RealtimeRecvUnit,
    opaque: Option<(
        crate::realtime::OpaqueFlowMode,
        crate::protocol::ApplicationFlowCoordinate,
    )>,
    _payload: RealtimePayloadLease,
    /// Reserved before the public label copy is allocated. The queue entry
    /// keeps this lease attached through dequeue and arrival consumption.
    _label_copy: RealtimePayloadLease,
    /// Prices the provider-owned custody wrapper before it is boxed after
    /// dequeue.  The lease travels inside the same queued entry, so legacy
    /// consumers release it on pop and guarded consumers retain it through
    /// arrival consumption.
    _custody: crate::resource::ResourceLease,
}

/// Provider custody moved with an opaque arrival. The marker keeps the
/// provider-specific lease private while making the public arrival move-only
/// and lifetime-coupled to its accounting.
struct WebRtcInboundCustody {
    _entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
}

impl crate::realtime::OpaqueInboundCustody for WebRtcInboundCustody {}

impl QueuedInboundUnit {
    /// Turn one whole delivery into one whole queue entry.
    ///
    /// **A move, not a split.** There is no accessor anywhere that hands back a
    /// delivery's parts — no tuple, no bare payload lease — because a shape that
    /// produces three bindings is a shape in which some later refusal can drop
    /// one of them while the others are still standing. This reads the parent
    /// module's private fields directly, which a child module may do, and the
    /// only fallible step is the last expression: once it succeeds the entry
    /// exists, and nothing after it can refuse.
    ///
    /// A delivery with no lease is refused here, and refusing costs nothing that
    /// matters — the label and unit bound above it fall together at the same
    /// return, and there is no lease among them to strand. Only the realtime
    /// queue mints one and it attaches before it queues, so this is a shape
    /// production cannot produce in the first place.
    ///
    /// Every check a caller wants to make *before* this is a question about the
    /// label, which it can borrow while the delivery is still whole.
    fn from_delivery(
        delivery: RealtimeInboundDelivery,
        custody: crate::resource::ResourceLease,
    ) -> Option<Self> {
        let RealtimeInboundDelivery {
            label,
            unit,
            payload,
        } = delivery;
        let payload = payload?;
        let label_copy = payload.reserve_supplemental_output(label.name().as_bytes().len())?;
        Some(Self {
            label,
            unit,
            opaque: None,
            _payload: payload,
            _label_copy: label_copy,
            _custody: custody,
        })
    }

    fn from_opaque(
        label: RealtimeFlowLabel,
        mode: crate::realtime::OpaqueFlowMode,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        bytes: Bytes,
        payload: RealtimePayloadLease,
        custody: crate::resource::ResourceLease,
    ) -> Option<Self> {
        let label_copy = payload.reserve_supplemental_output(label.name().as_bytes().len())?;
        Some(Self {
            label,
            // The opaque reader consumes `bytes` directly and never exposes
            // RTP timestamp/marker fields. These inert values retain the one
            // existing inbound queue type without fabricating media meaning.
            unit: RealtimeRecvUnit {
                timestamp: 0,
                marker: false,
                data: bytes,
            },
            opaque: Some((mode, coordinate)),
            _payload: payload,
            _label_copy: label_copy,
            _custody: custody,
        })
    }
}

/// The reader an inbound consumer awaits: one whole unit per arrival.
///
/// A wrapper rather than the raw stream reader, so the payload and label-copy
/// leases inside a queued arrival remain attached to the move-only provider
/// arrival until that arrival is dropped.
/// One item from the session's single inbound consumer.
///
/// The queue entry stays attached to the opaque variant until the application
/// drops its arrival. RTP keeps the historical provider handoff (the unit is
/// copied into the provider DTO), while the opaque path must retain its queue
/// node because its public arrival is move-only and can outlive dequeue.
pub(super) enum SessionInboundArrival {
    Rtp {
        entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    },
    Opaque {
        entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    },
}

impl SessionInboundArrival {
    pub(super) fn into_provider_event(self) -> crate::transport::webrtc::RealtimeInboundArrival {
        match self {
            Self::Rtp { entry } => crate::transport::webrtc::RealtimeInboundArrival::Rtp(
                RealtimeInboundArrivals::into_rtp_arrival(entry)
                    .expect("tagged RTP entry carries RTP metadata"),
            ),
            Self::Opaque { entry } => {
                // The entry becomes the opaque arrival's private custody. It
                // is not dropped at this handoff, so queue-node and payload
                // leases cover the public Bytes/label copies until consume.
                crate::transport::webrtc::RealtimeInboundArrival::Opaque(
                    RealtimeInboundArrivals::into_opaque(entry)
                        .expect("tagged opaque entry carries opaque metadata"),
                )
            }
        }
    }
}

pub(crate) struct RealtimeInboundArrivals(SessionStreamReader<QueuedInboundUnit>);

impl RealtimeInboundArrivals {
    fn entry_is_opaque(
        entry: &crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    ) -> bool {
        entry.value().opaque.is_some()
    }

    #[cfg(test)]
    fn into_rtp(
        entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    ) -> Option<(RealtimeFlowLabel, RealtimeRecvUnit)> {
        if Self::entry_is_opaque(&entry) {
            return None;
        }
        let value = entry.value();
        Some((
            value.label.clone(),
            RealtimeRecvUnit {
                timestamp: value.unit.timestamp,
                marker: value.unit.marker,
                data: value.unit.data.clone(),
            },
        ))
    }

    fn into_rtp_arrival(
        entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    ) -> Option<crate::transport::webrtc::WebRtcRealtimeInboundArrival> {
        if Self::entry_is_opaque(&entry) {
            return None;
        }
        let value = entry.value();
        Some(
            crate::transport::webrtc::WebRtcRealtimeInboundArrival::with_custody(
                value.label.name().as_bytes().to_vec(),
                crate::transport::webrtc::WebRtcRealtimeInboundUnit {
                    rtp_timestamp: value.unit.timestamp,
                    marker: value.unit.marker,
                    data: value.unit.data.clone(),
                },
                Box::new(WebRtcInboundCustody { _entry: entry }),
            ),
        )
    }

    fn into_opaque(
        entry: crate::resource::queue::LeasedQueueEntry<QueuedInboundUnit>,
    ) -> Option<crate::realtime::OpaqueInboundArrival> {
        let value = entry.value();
        value.opaque.as_ref()?;
        // The queue entry is deliberately moved into custody before the
        // provider-facing Bytes copy escapes. Its payload and node leases
        // therefore remain live for the complete arrival lifetime.
        let label = value.label.name().as_bytes().to_vec();
        let bytes = value.unit.data.clone();
        Some(crate::realtime::OpaqueInboundArrival {
            label,
            bytes,
            _custody: Some(Box::new(WebRtcInboundCustody { _entry: entry })),
        })
    }

    /// Consume the next item without filtering either kind. This is the
    /// lossless seam for mixed RTP/opaque sessions.
    pub(super) async fn next_arrival(&self) -> Option<SessionInboundArrival> {
        let entry = self.0.next_owned().await?;
        if Self::entry_is_opaque(&entry) {
            Some(SessionInboundArrival::Opaque { entry })
        } else {
            Some(SessionInboundArrival::Rtp { entry })
        }
    }

    /// Cross the provider boundary only after converting the private tagged
    /// queue entry into the public, custody-carrying arrival type.
    pub(crate) async fn next_provider_arrival(
        &self,
    ) -> Option<crate::transport::webrtc::RealtimeInboundArrival> {
        self.next_arrival()
            .await
            .map(SessionInboundArrival::into_provider_event)
    }

    /// The next unit to arrive on any inbound flow of this session.
    ///
    /// `None` is terminal and means the flow set is gone. Nothing else can
    /// produce it: the queue this reads is the flow set's own, so a reader held
    /// past a replacement observes that end rather than the replacement's
    /// units. There is no name to re-resolve and therefore no window in which a
    /// name could resolve to something else.
    #[cfg(test)]
    pub(crate) async fn next(&self) -> Option<(RealtimeFlowLabel, RealtimeRecvUnit)> {
        let entry = self
            .0
            .next_owned_if(|item| item.opaque.is_none())
            .await
            .ok()
            .flatten()?;
        Self::into_rtp(entry)
    }

    /// The next RTP item, refusing without dequeue when an opaque item is at
    /// the head. The queue's predicate and pop run under one lock.
    pub(crate) async fn next_rtp(
        &self,
    ) -> std::result::Result<
        Option<crate::transport::webrtc::WebRtcRealtimeInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        let entry = self
            .0
            .next_owned_if(|item| item.opaque.is_none())
            .await
            .map_err(|_| crate::realtime::RealtimeRefusal::FlowRefused)?;
        Ok(entry.and_then(Self::into_rtp_arrival))
    }

    /// The next opaque body from this same session-owned stream. An RTP head is
    /// a typed mismatch and remains queued for the tagged reader; it is never
    /// skipped or discarded.
    pub(crate) async fn next_opaque(
        &self,
    ) -> std::result::Result<
        Option<crate::realtime::OpaqueInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        let entry = self
            .0
            .next_owned_if(|item| item.opaque.is_some())
            .await
            .map_err(|_| crate::realtime::RealtimeRefusal::FlowRefused)?;
        Ok(entry.and_then(Self::into_opaque))
    }

    /// Take whatever is queued right now, without waiting.
    ///
    /// The same take from the same queue as [`Self::next`] — it removes one
    /// unit and creates no notification of its own, so it is not a second way
    /// to consume. What it adds is the ability to observe an *empty* queue,
    /// which awaiting cannot do: a control proving that a unit was not
    /// delivered to a session that must not have received it would otherwise
    /// have to wait for something that is never coming.
    ///
    /// **`None` here does not distinguish empty from ended.** A live queue with
    /// nothing in it and a queue whose flow set is gone both answer `None`,
    /// because neither involves waiting for a wake. A control asserting the
    /// terminal end uses [`Self::next`], which can only answer `None` for the
    /// end; a control asserting absence uses this, on a set it is holding.
    ///
    /// Gated to the exact conjunction its one consumer is compiled under, which
    /// is neither half on its own. Production has a single consumer and it
    /// awaits — a non-blocking take in the deployed path would be a poll loop,
    /// which is the thing the single wake exists to avoid — and the only caller
    /// is an engine control that needs a real promoted session over a live link,
    /// so it is a `#[test]` *inside* a `transport-lab` fixture. Gating on `test`
    /// alone compiles this into a default test build that has no caller for it;
    /// gating on the feature alone compiles it into a library build that has
    /// none either.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn try_next(&self) -> Option<(RealtimeFlowLabel, RealtimeRecvUnit)> {
        let entry = self
            .0
            .try_next_owned_if(|item| item.opaque.is_none())
            .ok()
            .flatten()?;
        Self::into_rtp(entry)
    }
}

/// Shared, funded witness for native work that outlives a logical flow record.
/// The state is rooted in the existing flow-set lifetime; each actual pump or
/// retirement carries one task lease and drops it only after native work ends.
pub(crate) struct RealtimeNativeTailState {
    outstanding: std::sync::atomic::AtomicUsize,
    _root: crate::resource::ResourceLease,
}

/// One native tail's owned scheduling claim.  It is deliberately move-only:
/// dropping a caller's close receipt must not make an in-flight native task
/// disappear from the flow-set quiescence proof.
pub(super) struct RealtimeNativeTail {
    state: Arc<RealtimeNativeTailState>,
    _task: crate::resource::ResourceLease,
}

impl Drop for RealtimeNativeTail {
    fn drop(&mut self) {
        let previous = self
            .state
            .outstanding
            .fetch_sub(1, std::sync::atomic::Ordering::AcqRel);
        debug_assert!(previous > 0, "native tail witness count underflow");
    }
}

/// The allocation whose address *is* one flow set's identity.
///
/// Its own type rather than reusing the arrivals stream, which is the other
/// per-set allocation to hand. Overloading that one would tie the identity of
/// a session's flows to an implementation detail of how its units are
/// delivered, and the two have no reason to change together.
struct RealtimeFlowSetToken;

/// A token naming one flow set, for a caller that has to prove it is
/// committing to the set it started against.
///
/// What it names is the flow set itself, and therefore the promoted session
/// that owns it. That is deliberately a *direct* statement rather than one
/// inferred from the peer entry or the connector incarnation: a caller that
/// opened a flow, released the fence to do async work, and re-entered has to
/// prove the same set answered, and the label cannot say it — labels are
/// session-scoped and freely reused — while the incarnation says only that the
/// transport is the same one, which is a weaker fact than the caller needs.
///
/// It is also the only one of the three that carries the set's own liveness. A
/// `Weak` that no longer upgrades means the set is gone, which is the true
/// answer for a session that ended even where every coarser identity around it
/// still resolves.
///
/// Holds a `Weak` deliberately: a token must never keep a flow set alive, or
/// the retirement it exists to detect could not happen while one was
/// outstanding.
pub(crate) struct RealtimeFlowSetIdentity(std::sync::Weak<RealtimeFlowSetToken>);

#[cfg(feature = "transport-lab")]
impl RealtimeFlowSetIdentity {
    /// An identity for a flow set that is gone.
    ///
    /// A `Weak` that never upgrades is exactly what a retired session's identity
    /// becomes, so this is not a fabricated authority — it is the state every
    /// identity here reaches, minted directly. Used only by
    /// [`crate::realtime::transport_lab_retired_flow_handle`].
    pub(crate) fn detached_for_control() -> Self {
        Self(std::sync::Weak::new())
    }
}

/// Every real-time flow one promoted session holds, and the label namespace
/// they are drawn from.
///
/// One opaque bundle, stored with the peer's promoted-session state and
/// dropped with it. That placement is the whole design: session replacement or
/// retirement drops this set, which releases every label and every flow at
/// once, so there is no separate invalidation step that could be missed and no
/// label that can outlive the incarnation its flow was opened on.
///
/// The engine never reaches the label namespace. It calls the operations
/// below, each of which borrows the current session and takes the connector's
/// freshly acquired live incarnation; the namespace itself is not reachable
/// from outside this module. No durable id, no generation, no timer.
/// `pub(crate)` so the peer entry can hold one, and no wider. What is worth
/// protecting stays private: the flow map is a field, not API, and every method
/// answers a name or a unit — never a `RealtimeFlowPort`, which stays private to
/// the connector.
///
/// **The flow map is the namespace, and there is no second one.** A name is in
/// use exactly when this session has a flow keyed by it, so "is this free",
/// "does this session hold that" and "which flow does that name" are one lookup
/// in one place. A separate table of held names would be a second fact about the
/// same thing, agreeing until it did not — and the moment it disagreed, one of
/// them would be answering for a flow that no longer existed.
pub(crate) struct SessionRealtimeFlows {
    /// Keyed by the leased label, so the map entry is one of the shared copies
    /// rather than a second allocation of the same bytes. Lookups take raw
    /// bytes through `Borrow<[u8]>`, so asking about a name costs no lease.
    ///
    /// A [`crate::resource::LeasedMap`] because this grows with what a session
    /// opens, and one entry has to be one funded allocation for a close to
    /// release exactly what that flow was occupying.
    flows: crate::resource::LeasedMap<RealtimeFlowLabel, RealtimeFlow>,
    /// This set's identity. Nothing reads it but [`SessionRealtimeFlows::identity`]
    /// and [`SessionRealtimeFlows::is_same`]; it exists to be an address that
    /// belongs to exactly one flow set and dies with it.
    identity: Arc<RealtimeFlowSetToken>,
    /// This session's one inbound queue: every unit that arrived on any of its
    /// inbound flows, in arrival order, each still holding its own bytes.
    ///
    /// The single retained copy, deliberately. One entry per unit, and the
    /// entry *is* the unit — not a notice that one is waiting somewhere else.
    /// Splitting those two makes one arrival retained twice, released at two
    /// different moments, and reportable by whichever half the other has
    /// already dropped; here an arrival and what a consumer receives cannot
    /// come apart, because they are the same object.
    arrivals: Arc<SessionStream<QueuedInboundUnit>>,
    /// What the connector negotiated for this session's inbound flows.
    ///
    /// Held here rather than on the connector so it dies with the session that
    /// owns the flows it names. A binding that outlived its session would be
    /// an identity still admitting media into a flow set that no longer
    /// exists, which is the one thing this table must never do.
    bindings: Arc<RealtimeInboundBindings>,
    /// Held from construction rather than passed per call, so the engine never
    /// names a connector-local type. The registry is the connector's; a set
    /// built against one connector cannot be used with another.
    registry: Arc<RealtimeFlowRegistry>,
    /// The application's registered codecs, for the one question binding a
    /// flow asks of them: which framing to install.
    ///
    /// Held here because the answer has to be available *inside* the fence, at
    /// the moment the label is claimed and the binding recorded, and the engine
    /// has no profile and must not learn about framing. `None` is a connector
    /// with no registered profile, which can hold no inbound bindings at all —
    /// a flow whose family nothing registered has no framer to install, so
    /// refusing is the only available answer.
    ///
    /// Shared and leased rather than owned outright: promotion clones the
    /// pointer, and the charge for the codecs behind it is paid once by the
    /// connector that registered them and released by whichever holder drops
    /// last.
    profile: Option<LeasedRealtimeProfile>,
    /// Lazily allocated only when a native tail exists. The state allocation
    /// owns its lease, and each tail owns a separate worker/task lease.
    native_tail_state: Option<Arc<RealtimeNativeTailState>>,
    /// Monotonic wire-coordinate source for logical opaque flows. It is a
    /// scalar on the existing flow set, not an index or authority table;
    /// closed records cannot be rebound by a stale coordinate.
    next_opaque_flow_id: u64,
}

impl SessionRealtimeFlows {
    /// An empty set for a session just promoted on `registry`'s connector.
    ///
    /// Deliberately not `Default`: a set with no registry could be constructed
    /// in a state that can never open a flow, and the peer entry would hold it
    /// looking valid.
    /// `pub(super)`, not `pub(crate)`: it names the connector-local registry,
    /// so exposing it crate-wide would leak that type into the engine's
    /// vocabulary. The engine constructs one through the worker accessor,
    /// which is the whole reason that accessor exists.
    pub(super) fn new(
        registry: Arc<RealtimeFlowRegistry>,
        profile: Option<LeasedRealtimeProfile>,
    ) -> Self {
        Self {
            flows: crate::resource::LeasedMap::new(),
            identity: Arc::new(RealtimeFlowSetToken),
            registry,
            profile,
            arrivals: Arc::new(SessionStream::new()),
            bindings: Arc::new(RealtimeInboundBindings::default()),
            next_opaque_flow_id: 1,
            native_tail_state: None,
        }
    }

    /// Acquire the exact native tail witness before publishing a pump or
    /// retirement. The state allocation is shared by this flow set and any
    /// delayed native owner; the task lease remains with the actual owner.
    fn acquire_native_tail(&mut self) -> FlowResult<RealtimeNativeTail> {
        let state = if let Some(state) = self.native_tail_state.as_ref() {
            Arc::clone(state)
        } else {
            let root = self
                .registry
                .acquire_native_tail_state()
                .map_err(realtime_drop_refusal)?;
            let state = Arc::new(RealtimeNativeTailState {
                outstanding: std::sync::atomic::AtomicUsize::new(0),
                _root: root,
            });
            self.native_tail_state = Some(Arc::clone(&state));
            state
        };
        let task = self
            .registry
            .acquire_native_tail()
            .map_err(realtime_drop_refusal)?;
        state
            .outstanding
            .fetch_add(1, std::sync::atomic::Ordering::AcqRel);
        Ok(RealtimeNativeTail { state, _task: task })
    }

    /// The heap roots one promotion allocates for a session's flow set.
    ///
    /// Exactly what [`Self::new`] creates and the session then owns for its
    /// whole life: the flow-set token, the inbound stream, and the inbound
    /// bindings, each with the two counter words its `Arc` carries.
    ///
    /// It lives here, next to the constructor, because two of the three types
    /// are private to this module and the third is `pub(crate)`. A caller
    /// outside this file could only account for them by copying their sizes
    /// into its own arithmetic, and a field added to `SessionStream` would then
    /// stop being paid for without anything saying so. Adding a root to `new`
    /// and not to this function is a mistake the compiler cannot catch, so the
    /// two sit adjacent and the omission is at least visible.
    ///
    /// Two exclusions, both deliberate. `registry` is cloned, not allocated —
    /// it is the connector's and predates the session, so charging it here
    /// would bill one object to every session standing on it. And nothing
    /// per-flow, per-queue or per-payload appears: those are taken as their own
    /// leases where the work happens, which is what lets a session's cost track
    /// what it is actually carrying rather than what it might.
    pub(crate) fn promotion_root_claim() -> std::result::Result<
        crate::resource::ResourceClaim,
        crate::resource::ResourceClaimArithmeticError,
    > {
        let overflow = || crate::resource::ResourceClaimArithmeticError::Overflow {
            dimension: crate::resource::ResourceClass::AccountedMemoryBytes,
        };
        // Two words per `Arc`: strong and weak. The same pattern the connector
        // uses for its own `Arc`-rooted claims.
        let arc_counters = std::mem::size_of::<usize>()
            .checked_mul(2)
            .ok_or_else(overflow)?;
        let root = |contents: usize| contents.checked_add(arc_counters);
        let accounted = root(std::mem::size_of::<RealtimeFlowSetToken>())
            .and_then(|bytes| {
                bytes.checked_add(root(
                    std::mem::size_of::<SessionStream<QueuedInboundUnit>>(),
                )?)
            })
            .and_then(|bytes| {
                bytes.checked_add(root(std::mem::size_of::<RealtimeInboundBindings>())?)
            })
            .ok_or_else(overflow)?;
        crate::resource::ResourceClaim::try_from_entries([
            (
                crate::resource::ResourceClass::AccountedMemoryBytes,
                u64::try_from(accounted).map_err(|_| overflow())?,
            ),
            // One residual per allocation, matching the connector's own
            // `Arc`-rooted claims. The byte term above measures what the roots
            // *contain*; this counts the allocations themselves, whose
            // allocator overhead has no portable size. Charging only the bytes
            // would state that the roots are fully represented when the
            // per-allocation cost is exactly what is missing.
            (
                crate::resource::ResourceClass::OpaqueDependencyResidual,
                Self::PROMOTION_ROOT_ALLOCATIONS,
            ),
        ])
    }

    /// How many separate allocations [`Self::new`] makes for a session's flow
    /// set: the flow-set token, the inbound stream, and the inbound bindings.
    ///
    /// Named beside the claim that spends it so the two cannot drift silently,
    /// and stated as a count rather than derived from the byte arithmetic
    /// above, because the two answer different questions — how much the roots
    /// hold, and how many objects the allocator is holding it in.
    const PROMOTION_ROOT_ALLOCATIONS: u64 = 3;

    /// A token naming this exact flow set.
    pub(crate) fn identity(&self) -> RealtimeFlowSetIdentity {
        RealtimeFlowSetIdentity(Arc::downgrade(&self.identity))
    }

    /// Whether `identity` names *this* flow set.
    ///
    /// Compares the caller's `Weak` against this set's **live strong**
    /// reference, never `Weak` against `Weak`. `Weak::as_ptr` keeps answering
    /// its old address after the allocation is freed, so a dead-versus-dead
    /// comparison can match a recycled allocation and report two unrelated
    /// sets as the same one. Comparing against a strong reference the callee is
    /// holding cannot: that address is occupied for as long as the comparison
    /// takes. Same construction as [`SessionStreamReader::names`].
    pub(crate) fn is_same(&self, identity: &RealtimeFlowSetIdentity) -> bool {
        std::ptr::eq(identity.0.as_ptr(), Arc::as_ptr(&self.identity))
    }

    /// The exact identity of the flow `name` currently resolves to.
    ///
    /// Handed out once, at open, so a caller can present it back instead of
    /// presenting a name and hoping the name still means what it meant.
    pub(crate) fn flow_identity(&self, name: &RealtimeFlowName) -> Option<RealtimeFlowIdentity> {
        self.flows
            .get(name.as_bytes())
            .map(|flow| flow.label().identity())
    }

    /// Whether `name` currently names the exact flow `identity` was taken from.
    ///
    /// The second half of a handle's proof, and it is not redundant with
    /// [`Self::is_same`]. The flow-set check rules out a *replacement session*
    /// answering for a name; this rules out a **replacement flow inside the same
    /// session**. A label may be closed and claimed again without the session
    /// changing at all, and at that moment the name, the session and the flow set
    /// are all identical — only the record differs.
    ///
    /// Answers `false` for a name that no longer resolves, so a caller cannot
    /// tell "closed" from "replaced" and does not need to.
    pub(crate) fn is_same_flow(
        &self,
        name: &RealtimeFlowName,
        identity: &RealtimeFlowIdentity,
    ) -> bool {
        self.flows
            .get(name.as_bytes())
            .is_some_and(|flow| flow.label().is_identity(identity))
    }

    /// The negotiated-track table for this session, as a **`Weak`**.
    ///
    /// `pub(super)`: the connector reads it when a track arrives. The engine
    /// never touches it, and the application cannot reach it at all — which is
    /// what keeps a token on it a fact this side established rather than a
    /// value a peer supplied.
    ///
    /// Weak, and that is a correctness property rather than a hygiene
    /// preference. The table's whole job is to stop admitting media the moment
    /// its session ends; a connector holding a strong reference would keep it
    /// alive past the `PromotedSession` that owns the flows it names, leaving
    /// a table that still resolves tokens to labels in a flow set that no
    /// longer exists. With a `Weak` the connector's upgrade simply fails, and
    /// the arriving track is dropped — which is the answer that was wanted.
    pub(super) fn inbound_bindings(&self) -> std::sync::Weak<RealtimeInboundBindings> {
        Arc::downgrade(&self.bindings)
    }

    /// The awaitable inbound stream for this whole session.
    ///
    /// `None` while another reader is live. Not `None` forever: the claim is
    /// an RAII lease, so a consumer that dies and reconnects takes it back and
    /// resumes on the same queue. A second *simultaneous* reader is what is
    /// refused, because closure is one stored permit and the second waiter
    /// would never wake — the same invariant as the outbound pump.
    ///
    /// A reclaiming reader drains what accumulated in the gap before it parks:
    /// `next` takes first and only awaits when there was nothing to take, so a
    /// reconnect never sleeps on a queue that already has work in it.
    ///
    /// The reader is detached by construction. A caller takes it while holding
    /// the registry mutation lock, releases the lock, and only then awaits, so
    /// the lock is never held across a suspension point. That is not a
    /// convention the caller has to remember: the reader borrows nothing from
    /// the flow set, so there is nothing it could still be holding.
    pub(crate) fn inbound_arrivals(&self) -> Option<RealtimeInboundArrivals> {
        self.arrivals.claim().then(|| {
            RealtimeInboundArrivals(SessionStreamReader {
                stream: Arc::downgrade(&self.arrivals),
                ready: Arc::clone(&self.arrivals.ready),
            })
        })
    }

    /// Open one flow under the label the application chose.
    ///
    /// The application is the sole allocator: it owns route binding and the
    /// dead-flow recovery path, so it is the only side that can name a flow
    /// after losing its route table. This side validates rather than
    /// allocates — an already-held label answers `LabelInUse`, which is also
    /// what makes the application's own view self-correcting when it drifts.
    /// Two allocators over one space would agree until they did not, and the
    /// failure would be a collision on a live flow rather than an error here.
    pub(crate) fn open(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: RealtimeFlowSpec,
    ) -> FlowResult<RealtimeFlowName> {
        // Asked here, before anything is acquired, and for both directions.
        //
        // `open` is the contract boundary: an encoding the application never
        // registered has no framing to install and no codec to negotiate, and
        // that is a property of the *request*, not of what the transport later
        // makes of it. Inbound already learned this at `bind_inbound`, but
        // outbound had no such point — it claimed a label, opened a registry
        // flow, and only failed once the worker's negotiation guard refused,
        // which the engine then reports as `FlowRefused`. That tells a caller
        // to retry something that can never succeed. `EncodingInvalid` is what
        // it actually is, and answering it before the acquisitions means a
        // refused open costs neither a label nor a flow slot.
        //
        // `bind_inbound` still resolves framing from this same profile rather
        // than caching it here: this answers whether the family is registered,
        // that one answers what its framing is, and both come from one place.
        if self
            .profile
            .as_ref()
            .is_none_or(|profile| profile.profile().admits_encoding(&spec.encoding).is_none())
        {
            return Err(RealtimeFlowError::EncodingInvalid);
        }
        // The one namespace, asked once and before anything is minted. This map
        // is keyed by the live label, so "is this name in use" and "does this
        // session have a flow called that" are the same question — and asking
        // it here means a collision costs neither a lease nor a flow slot.
        if self.flows.contains_key(spec.name.as_bytes()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        let registry = Arc::clone(&self.registry);
        let (flow, map_entry) = open_session_flow(session, live, &registry, spec)?;
        // A refcount on the flow's own label record, not a second name: the key
        // and the flow's field are the same leased bytes, so the map costs one
        // Arc counter rather than another accounted allocation.
        let label = flow.label().clone();
        let name = label.name().clone();
        // `map_entry` was acquired by the open, beside the label and the port,
        // and is handed to the map that will hold the node it paid for.
        // `insert` refuses rather than replaces, and the name was checked free at
        // the top of this call under this same borrow — so this branch is
        // unreachable, and if it were ever reached nothing live would have been
        // destroyed and the refused flow would release everything it held. A
        // defensive branch has to refuse without mutating, or it is not
        // defensive.
        if self.flows.insert(label, flow, map_entry).is_err() {
            return Err(RealtimeFlowError::LabelInUse);
        }
        // No event. The caller asked for this flow and is being handed the
        // name right now; telling it again on a stream would be a second
        // account of the same fact.
        Ok(name)
    }

    /// Open one logical opaque flow against the same leased flow map used by
    /// RTP. The native reliable/partial lane is selected by the worker; this
    /// operation allocates only the logical flow record and its existing flow
    /// leases.
    pub(crate) fn prepare_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: OpaqueFlowSpec,
    ) -> FlowResult<RealtimeFlowName> {
        if self.flows.contains_key(spec.name.as_bytes()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        let coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: self.next_opaque_flow_id,
            generation: 1,
        };
        coordinate
            .validate()
            .map_err(|_| RealtimeFlowError::FlowRefused)?;
        let registry = Arc::clone(&self.registry);
        let application_claim = registry
            .acquire_opaque_application_claim()
            .map_err(realtime_drop_refusal)?;
        self.open_opaque_with_coordinate(session, live, spec, coordinate, Some(application_claim))
    }

    /// Prepare a local opaque flow, or claim a matching transport-only record
    /// created by the peer, using the one authoritative flow map. A remote
    /// Open is not application authority: its record has no application claim
    /// until this exact current-session operation supplies one.
    ///
    /// `true` means an existing record was claimed; `false` means a new local
    /// pending record was created with its claim already attached. Matching is
    /// against the existing record's raw label, local direction, mode and
    /// ceiling. The retained opener-relative direction is deliberately not
    /// compared with the local request.
    pub(crate) fn prepare_or_claim_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: OpaqueFlowSpec,
    ) -> FlowResult<(RealtimeFlowName, bool)> {
        if let Some(flow) = self.flows.get(spec.name.as_bytes()) {
            flow.port_if_current(session, live)?;
            if flow.opaque_mode() != Some(spec.mode)
                || flow.opaque_max_unit_bytes() != Some(spec.max_unit_bytes)
                || flow.direction() != spec.direction
                || flow.opaque_application_claim.is_some()
            {
                return Err(RealtimeFlowError::FlowRefused);
            }
            let name = flow.label().name().clone();
            let claim = self
                .registry
                .acquire_opaque_application_claim()
                .map_err(realtime_drop_refusal)?;
            let flow = self
                .flows
                .get_mut(name.as_bytes())
                .ok_or(RealtimeFlowError::FlowRefused)?;
            if flow.opaque_application_claim.is_some()
                || flow.port_if_current(session, live).is_err()
            {
                return Err(RealtimeFlowError::FlowRefused);
            }
            flow.opaque_application_claim = Some(claim);
            return Ok((name, true));
        }

        let name = self.prepare_opaque(session, live, spec)?;
        // A newly prepared local record has already reserved its application
        // claim in `prepare_opaque`; the bool distinguishes it from the
        // existing-record branch without exposing another identity table.
        Ok((name, false))
    }

    /// Convenience for a locally committed flow where the surrounding engine
    /// has already completed its control transaction. The explicit prepare /
    /// accept methods are used when Open/Accept crosses the wire.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn open_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: OpaqueFlowSpec,
    ) -> FlowResult<RealtimeFlowName> {
        let mode = spec.mode;
        let max_unit_bytes = spec.max_unit_bytes;
        let name = self.prepare_opaque(session, live, spec)?;
        let coordinate = self
            .opaque_coordinate(&name)
            .ok_or(RealtimeFlowError::FlowRefused)?;
        self.accept_opaque(session, live, &name, coordinate, mode, max_unit_bytes)?;
        Ok(name)
    }

    /// Open a logical opaque record with a control-plane coordinate already
    /// selected by the authenticated session's Open/Change transaction.
    /// Coordinate lookup remains on the existing flow records; this method
    /// does not create a second map.
    pub(crate) fn open_opaque_with_coordinate(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        spec: OpaqueFlowSpec,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        application_claim: Option<crate::resource::ResourceLease>,
    ) -> FlowResult<RealtimeFlowName> {
        coordinate
            .validate()
            .map_err(|_| RealtimeFlowError::FlowRefused)?;
        if self.flows.contains_key(spec.name.as_bytes()) {
            return Err(RealtimeFlowError::LabelInUse);
        }
        let mut coordinate_in_use = false;
        self.flows.for_each(|_, flow| {
            if flow.opaque_coordinate() == Some(coordinate)
                && flow.opaque_opener_direction() == Some(spec.opener_direction)
            {
                coordinate_in_use = true;
            }
        });
        if coordinate_in_use {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let next_opaque_flow_id = if coordinate.flow_id >= self.next_opaque_flow_id {
            Some(
                coordinate
                    .flow_id
                    .checked_add(1)
                    .ok_or(RealtimeFlowError::FlowRefused)?,
            )
        } else {
            None
        };
        let registry = Arc::clone(&self.registry);
        let (flow, map_entry) = open_opaque_flow(
            session,
            live,
            &registry,
            spec,
            coordinate,
            application_claim,
        )?;
        let label = flow.label().clone();
        let name = label.name().clone();
        // The coordinate is part of the flow record's kind. The constructor
        // receives it through the provider helper, so this check prevents a
        // future caller from accidentally inserting a differently-coordinate
        // record under the accepted label.
        if flow.opaque_coordinate() != Some(coordinate) {
            return Err(RealtimeFlowError::FlowRefused);
        }
        if self.flows.insert(label, flow, map_entry).is_err() {
            return Err(RealtimeFlowError::LabelInUse);
        }
        if let Some(next_opaque_flow_id) = next_opaque_flow_id {
            self.next_opaque_flow_id = next_opaque_flow_id;
        }
        Ok(name)
    }

    /// Return the exact wire coordinate stored on this flow record.
    pub(crate) fn opaque_coordinate(
        &self,
        name: &RealtimeFlowName,
    ) -> Option<crate::protocol::ApplicationFlowCoordinate> {
        self.flows
            .get(name.as_bytes())
            .and_then(RealtimeFlow::opaque_coordinate)
    }

    /// Return the opener-relative direction from the exact existing record.
    /// This is a copied scalar read and does not reverse-index by allocating a
    /// temporary label, so close/control paths cannot mistake a successor for
    /// the captured flow.
    pub(crate) fn opaque_opener_direction(
        &self,
        name: &RealtimeFlowName,
    ) -> Option<crate::realtime::RealtimeFlowDirection> {
        self.flows
            .get(name.as_bytes())
            .and_then(RealtimeFlow::opaque_opener_direction)
    }

    /// The exact readiness wake owned by one pending flow record.
    /// Return a safe awaitable for the exact pending record without exposing
    /// the provider's raw funded wake or its Notify operation.
    pub(crate) fn opaque_pending_wait(
        &self,
        name: &RealtimeFlowName,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
    ) -> Option<OpaquePendingWait> {
        let flow = self.flows.get(name.as_bytes())?;
        if flow.opaque_coordinate()? != coordinate || flow.opaque_is_ready()? {
            return None;
        }
        Some(OpaquePendingWait(flow.end.watch()))
    }

    /// Return the existing flow-end wake for one exact staged Change.  A
    /// Change keeps its predecessor logically ready, so the ordinary Open
    /// pending wait cannot represent this state.  The token identity and all
    /// staged fields are checked before borrowing the wake; a confirmed or
    /// canceled token returns `None` so callers commit/reconcile immediately
    /// rather than registering a waiter that can never be notified.
    pub(crate) fn opaque_change_wait(
        &self,
        name: &RealtimeFlowName,
        change: &OpaqueFlowChange,
    ) -> Option<OpaquePendingWait> {
        if change.finished {
            return None;
        }
        let flow = self.flows.get(name.as_bytes())?;
        if !flow.label().is_identity(&change.identity)
            || flow.opaque_coordinate() != Some(change.previous)
            || flow.opaque_mode() != Some(change.mode)
            || flow.opaque_opener_direction() != Some(change.opener_direction)
            || flow.opaque_is_ready() != Some(true)
        {
            return None;
        }
        let pending = flow.opaque_pending_change.as_ref()?;
        if !pending.active.is_active()
            || pending.confirmed
            || pending.previous != change.previous
            || pending.coordinate != change.coordinate
            || pending.opener_direction != change.opener_direction
            || pending.mode != change.mode
            || pending.max_unit_bytes != change.max_unit_bytes
        {
            return None;
        }
        Some(OpaquePendingWait(flow.end.watch()))
    }

    /// Read exact readiness without conflating a missing record with a
    /// pending one. The coordinate is checked against the existing flow record
    /// before the state is returned.
    pub(crate) fn opaque_ready(
        &self,
        name: &RealtimeFlowName,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
    ) -> Option<bool> {
        let flow = self.flows.get(name.as_bytes())?;
        if flow.opaque_coordinate() == Some(coordinate) {
            flow.opaque_is_ready()
        } else {
            None
        }
    }

    /// Read the one application-claim bit on the existing flow record.
    /// Remote transport admission leaves this false; only the exact local
    /// claim operation may turn it on.
    pub(crate) fn opaque_is_claimed(&self, name: &RealtimeFlowName) -> Option<bool> {
        self.flows
            .get(name.as_bytes())
            .map(|flow| flow.opaque_application_claim.is_some())
    }

    /// Locate an exact control record, including a still-pending Open. This is
    /// intentionally separate from frame lookup, which admits only ready
    /// records and also checks mode/body bounds.
    pub(crate) fn opaque_name_for_control(
        &self,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
    ) -> Option<RealtimeFlowName> {
        let mut found = None;
        self.flows.for_each(|label, flow| {
            if found.is_none()
                && flow.opaque_coordinate() == Some(coordinate)
                && flow.opaque_opener_direction() == Some(opener_direction)
            {
                found = Some(label.name().clone());
            }
        });
        found
    }

    /// Commit an echoed Accept to the exact pending record. The mode and body
    /// ceiling must match the prepared record; no new lease or flow is created.
    pub(crate) fn accept_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        mode: crate::realtime::OpaqueFlowMode,
        max_unit_bytes: usize,
    ) -> FlowResult<()> {
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        let Some(pending) = flow.opaque_pending.as_ref() else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        if pending.coordinate != coordinate
            || pending.mode != mode
            || pending.max_unit_bytes != max_unit_bytes
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        if let Some(pending) = flow.opaque_pending.as_mut() {
            pending.ready = true;
            flow.end.notify().notify().notify_waiters();
            Ok(())
        } else {
            Err(RealtimeFlowError::FlowRefused)
        }
    }

    /// Claim the one persistent outbound pump for a ready opaque record. The
    /// caller receives the pump and its completion sender, while the flow
    /// retains the matching receiver as its ordinary native remainder.
    pub(crate) fn attach_opaque_pump(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
    ) -> FlowResult<(OpaqueOutboundPump, tokio::sync::oneshot::Sender<()>)> {
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if flow.opaque_is_ready() != Some(true)
            || flow.opaque_application_claim.is_none()
            || flow
                .opaque_pending_change
                .as_ref()
                .is_some_and(|pending| pending.active.is_active())
            || flow.direction() != RealtimeDirection::Outbound
            || !matches!(flow.native, RealtimeFlowRemains::None)
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let FlowQueue::OpaqueOutbound(queue) = &flow.queue else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let queue = Arc::clone(queue);
        let tail = self.acquire_native_tail()?;
        if !queue.claim_pump() {
            drop(tail);
            return Err(RealtimeFlowError::FlowRefused);
        }
        let pump = OpaqueOutboundPump {
            queue: Arc::downgrade(&queue),
            ready: queue.ready(),
            _tail: tail,
        };
        let (retired, remains) = tokio::sync::oneshot::channel();
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.native = RealtimeFlowRemains::Outbound(remains);
        Ok((pump, retired))
    }

    /// Cancel only the exact still-pending record. A ready flow must use the
    /// normal handle close path so its ownership and native remainder follow
    /// the same fence as every other flow.
    pub(crate) fn cancel_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
    ) -> FlowResult<RealtimeFlowRemains> {
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if flow.opaque_coordinate() != Some(coordinate) || flow.opaque_is_ready() != Some(false) {
            return Err(RealtimeFlowError::FlowRefused);
        }
        self.close(session, live, name)
    }

    /// Stage a provider-side Change on the exact predecessor record.
    ///
    /// The pending scalar lives on the flow itself, while the returned token
    /// carries the record identity across the asynchronous control exchange.
    /// A label reuse therefore cannot make a delayed Accept operate on a
    /// successor.  A claimed outbound pump may remain attached, but the
    /// queue and its actual in-flight counter must be quiescent; changing a
    /// record never discards accepted work.
    // Keep session, incarnation, predecessor, staged coordinate, direction,
    // mode, and ceiling explicit at this authority boundary.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_opaque_change(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        previous: crate::protocol::ApplicationFlowCoordinate,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        max_unit_bytes: usize,
    ) -> FlowResult<OpaqueFlowChange> {
        // A dropped caller token marks its record state canceled. Reap that
        // inert state lazily under this same map fence before preparing a new
        // transaction; an abandoned token therefore cannot block the label
        // forever or be mistaken for a live Change.
        let canceled = self
            .flows
            .get(name.as_bytes())
            .and_then(|flow| flow.opaque_pending_change.as_ref())
            .is_some_and(|pending| !pending.active.is_active());
        if canceled {
            if let Some(flow) = self.flows.get_mut(name.as_bytes()) {
                flow.opaque_pending_change = None;
            }
        }
        coordinate
            .validate()
            .map_err(|_| RealtimeFlowError::FlowRefused)?;
        if coordinate.flow_id != previous.flow_id
            || previous.generation.checked_add(1) != Some(coordinate.generation)
            || max_unit_bytes == 0
            || max_unit_bytes > crate::realtime::MAX_OPAQUE_FLOW_UNIT_BYTES
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if !matches!(
            &flow.kind,
            RealtimeFlowKind::Opaque {
                coordinate: current,
                mode: current_mode,
                opener_direction: current_opener,
                ..
            } if *current == previous && *current_mode == mode && *current_opener == opener_direction
        ) || flow.opaque_is_ready() != Some(true)
            || flow
                .opaque_pending_change
                .as_ref()
                .is_some_and(|pending| pending.active.is_active())
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let queue = match &flow.queue {
            FlowQueue::OpaqueOutbound(queue) => queue,
            FlowQueue::Inbound => {
                let identity = flow.label().identity();
                if self
                    .arrivals
                    .contains(|item| item.opaque.is_some() && item.label.is_identity(&identity))
                {
                    return Err(RealtimeFlowError::FlowRefused);
                }
                let active = flow
                    .opaque_pending_change
                    .as_ref()
                    .is_some_and(|pending| pending.active.is_active());
                if active {
                    return Err(RealtimeFlowError::FlowRefused);
                }
                let identity = flow.label().identity();
                let claim = self
                    .registry
                    .acquire_opaque_change()
                    .map_err(realtime_drop_refusal)?;
                // The marker's allocation is part of the change claim.  Take
                // that claim before constructing the Arc so a refusal cannot
                // leave an unfunded cancellation state behind.
                let active = Arc::new(OpaqueChangeMarker {
                    active: std::sync::atomic::AtomicBool::new(true),
                    _root: claim,
                });
                let flow = self
                    .flows
                    .get_mut(name.as_bytes())
                    .ok_or(RealtimeFlowError::FlowRefused)?;
                if flow.opaque_pending_change.is_some() {
                    return Err(RealtimeFlowError::FlowRefused);
                }
                flow.opaque_pending_change = Some(OpaqueFlowPendingChange {
                    previous,
                    coordinate,
                    opener_direction,
                    mode,
                    max_unit_bytes,
                    active: Arc::clone(&active),
                    confirmed: false,
                });
                return Ok(OpaqueFlowChange {
                    identity,
                    previous,
                    coordinate,
                    opener_direction,
                    mode,
                    max_unit_bytes,
                    active,
                    finished: false,
                });
            }
            FlowQueue::Outbound(_) => return Err(RealtimeFlowError::FlowRefused),
        };
        if !queue.is_empty() || queue.in_flight() != 0 || queue.is_failed() {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let identity = flow.label().identity();
        let claim = self
            .registry
            .acquire_opaque_change()
            .map_err(realtime_drop_refusal)?;
        // The marker's allocation is part of the change claim.  Take that
        // claim before constructing the Arc so a refusal cannot leave an
        // unfunded cancellation state behind.
        let active = Arc::new(OpaqueChangeMarker {
            active: std::sync::atomic::AtomicBool::new(true),
            _root: claim,
        });
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        if flow
            .opaque_pending_change
            .as_ref()
            .is_some_and(|pending| pending.active.is_active())
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        flow.opaque_pending_change = Some(OpaqueFlowPendingChange {
            previous,
            coordinate,
            opener_direction,
            mode,
            max_unit_bytes,
            active: Arc::clone(&active),
            confirmed: false,
        });
        Ok(OpaqueFlowChange {
            identity,
            previous,
            coordinate,
            opener_direction,
            mode,
            max_unit_bytes,
            active,
            finished: false,
        })
    }

    /// Commit a previously staged Change after the peer's exact Accept.
    /// Revalidates session, record identity, mode, queue and in-flight state
    /// before changing the existing record's coordinate and ceiling.
    pub(crate) fn commit_opaque_change(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        change: &mut OpaqueFlowChange,
    ) -> FlowResult<()> {
        if change.finished {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if !flow.label().is_identity(&change.identity)
            || !matches!(
                &flow.kind,
                RealtimeFlowKind::Opaque {
                    coordinate: current,
                    mode,
                    opener_direction,
                    ..
                } if *current == change.previous
                    && *mode == change.mode
                    && *opener_direction == change.opener_direction
            )
            || flow.opaque_is_ready() != Some(true)
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        match &flow.queue {
            FlowQueue::OpaqueOutbound(queue)
                if !queue.is_empty() || queue.in_flight() != 0 || queue.is_failed() =>
            {
                return Err(RealtimeFlowError::FlowRefused);
            }
            // An inbound record has no per-flow outbound queue. Recheck its
            // shared arrival queue at the terminal commit as well as during
            // prepare: a predecessor can arrive in the interleaving window,
            // and changing the coordinate must never silently discard it.
            FlowQueue::Inbound => {
                let identity = flow.label().identity();
                if self
                    .arrivals
                    .contains(|item| item.opaque.is_some() && item.label.is_identity(&identity))
                {
                    return Err(RealtimeFlowError::FlowRefused);
                }
            }
            FlowQueue::OpaqueOutbound(_) => {}
            FlowQueue::Outbound(_) => return Err(RealtimeFlowError::FlowRefused),
        }
        if !matches!(
            flow.opaque_pending_change.as_ref(),
            Some(pending)
                if pending.previous == change.previous
                    && pending.coordinate == change.coordinate
                    && pending.mode == change.mode
                    && pending.max_unit_bytes == change.max_unit_bytes
                    && pending.opener_direction == change.opener_direction
                    && pending.confirmed
        ) {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        if let RealtimeFlowKind::Opaque {
            coordinate: current,
            max_unit_bytes: ceiling,
            ..
        } = &mut flow.kind
        {
            *current = change.coordinate;
            *ceiling = change.max_unit_bytes;
        } else {
            return Err(RealtimeFlowError::FlowRefused);
        }
        if let Some(pending) = flow.opaque_pending_change.as_mut() {
            pending.active.cancel();
        }
        flow.opaque_pending_change = None;
        change.finished = true;
        Ok(())
    }

    /// Confirm the exact staged Change from the authenticated peer control
    /// path.  The reducer does not receive the caller's move-only token, so
    /// confirmation is recorded on the same flow record; the token's commit
    /// must still revalidate that tuple and identity before mutation.
    // Keep the authenticated tuple explicit at this reducer boundary; these
    // are the fields that must be compared before confirmation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn confirm_opaque_change(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        previous: crate::protocol::ApplicationFlowCoordinate,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        max_unit_bytes: usize,
    ) -> FlowResult<()> {
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if !matches!(
            &flow.kind,
            RealtimeFlowKind::Opaque {
                coordinate: current,
                mode: current_mode,
                opener_direction: current_opener,
                ..
            } if *current == previous
                && *current_mode == mode
                && *current_opener == opener_direction
        ) || flow.opaque_is_ready() != Some(true)
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        match &flow.queue {
            FlowQueue::OpaqueOutbound(queue)
                if !queue.is_empty() || queue.in_flight() != 0 || queue.is_failed() =>
            {
                return Err(RealtimeFlowError::FlowRefused);
            }
            FlowQueue::Inbound => {}
            FlowQueue::OpaqueOutbound(_) => {}
            FlowQueue::Outbound(_) => return Err(RealtimeFlowError::FlowRefused),
        }
        let Some(pending) = flow.opaque_pending_change.as_ref() else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        if !pending.active.is_active()
            || pending.confirmed
            || pending.previous != previous
            || pending.coordinate != coordinate
            || pending.opener_direction != opener_direction
            || pending.mode != mode
            || pending.max_unit_bytes != max_unit_bytes
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        let Some(pending) = flow.opaque_pending_change.as_mut() else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        pending.confirmed = true;
        flow.end.notify().notify().notify_waiters();
        Ok(())
    }

    /// Cancel a staged Change without mutating the predecessor. Exact flow
    /// identity and pending values are checked before the record is cleared.
    pub(crate) fn rollback_opaque_change(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        change: &mut OpaqueFlowChange,
    ) -> FlowResult<()> {
        if change.finished {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        flow.port_if_current(session, live)?;
        if !flow.label().is_identity(&change.identity)
            || !matches!(
                &flow.kind,
                RealtimeFlowKind::Opaque {
                    coordinate: current,
                    mode,
                    opener_direction,
                    ..
                } if *current == change.previous
                    && *mode == change.mode
                    && *opener_direction == change.opener_direction
            )
            || !matches!(
                flow.opaque_pending_change.as_ref(),
                Some(pending)
                    if pending.previous == change.previous
                        && pending.coordinate == change.coordinate
                        && pending.mode == change.mode
                    && pending.max_unit_bytes == change.max_unit_bytes
                    && pending.opener_direction == change.opener_direction
            )
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let flow = self
            .flows
            .get_mut(name.as_bytes())
            .ok_or(RealtimeFlowError::FlowRefused)?;
        if let Some(pending) = flow.opaque_pending_change.as_ref() {
            pending.active.cancel();
        }
        flow.opaque_pending_change = None;
        change.finished = true;
        Ok(())
    }

    /// Compatibility wrapper for callers that already hold the fence for the
    /// entire operation. New wire controls should use explicit prepare,
    /// commit and rollback so a peer refusal cannot leave a staged record.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn change_opaque(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        previous: crate::protocol::ApplicationFlowCoordinate,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        max_unit_bytes: usize,
    ) -> FlowResult<()> {
        let mode = self
            .flows
            .get(name.as_bytes())
            .and_then(RealtimeFlow::opaque_mode)
            .ok_or(RealtimeFlowError::FlowRefused)?;
        let opener_direction = self
            .flows
            .get(name.as_bytes())
            .and_then(RealtimeFlow::opaque_opener_direction)
            .ok_or(RealtimeFlowError::FlowRefused)?;
        let mut change = self.prepare_opaque_change(
            session,
            live,
            name,
            previous,
            coordinate,
            opener_direction,
            mode,
            max_unit_bytes,
        )?;
        self.confirm_opaque_change(
            session,
            live,
            name,
            previous,
            coordinate,
            opener_direction,
            mode,
            max_unit_bytes,
        )?;
        self.commit_opaque_change(session, live, name, &mut change)
    }

    /// Resolve an incoming coordinate by scanning the one authoritative flow
    /// map and validate its negotiated mode/body/direction before admission.
    /// A stale coordinate cannot reach a successor that reused the label.
    pub(crate) fn opaque_name_for_coordinate(
        &self,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        body_len: usize,
    ) -> Option<RealtimeFlowName> {
        let mut found = None;
        self.flows.for_each(|label, flow| {
            if found.is_some()
                || flow.opaque_coordinate() != Some(coordinate)
                || flow.opaque_is_ready() != Some(true)
                || flow.opaque_mode() != Some(mode)
                || flow
                    .opaque_max_unit_bytes()
                    .is_none_or(|max| max < body_len)
                || flow.direction() != RealtimeDirection::Inbound
            {
                return;
            }
            if flow.opaque_opener_direction() == Some(opener_direction) {
                found = Some(label.name().clone());
            }
        });
        found
    }

    /// Record what the connector is about to negotiate for an already-open
    /// inbound flow.
    ///
    /// Called in the **same fence acquisition** that claimed the label, before
    /// the transceiver exists. That ordering is the point: any track that can
    /// ever present this token is carried by a transceiver created against it
    /// afterwards, so the binding is never later than the media it admits.
    /// Binding after negotiation would only *usually* precede the first track,
    /// and a starved task would turn "usually" into lost units at flow start.
    ///
    /// A binding that briefly exists with no transceiver behind it is inert —
    /// nothing can present its token — so the failure direction is harmless.
    ///
    /// Gated like every other use, and additionally refused for a flow this
    /// side did not open inbound: an outbound flow has nothing to attach, and
    /// a binding on one could only ever be a mistake this table would then make
    /// look deliberate.
    ///
    /// Takes the token's [`RealtimeInboundRetirement`] by value, which is what
    /// makes the flow — rather than a caller who remembers — the thing that owes
    /// the transceiver its stop. Whether this succeeds or refuses, the
    /// retirement ends up somewhere that submits it.
    pub(crate) fn bind_inbound(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        identity: Arc<RealtimeTrackIdentity>,
        mut retirement: RealtimeInboundRetirement,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        if flow.direction() != RealtimeDirection::Inbound {
            return Err(RealtimeFlowError::FlowRefused);
        }
        // The framing is resolved here, from the application's own profile,
        // rather than carried in by the caller. The engine has no profile and
        // must not learn what framing means; and a family the profile never
        // registered has no framer to install, which is a refusal rather than
        // a default. This is the same question `admits_encoding` answers for
        // an arriving track, asked once at bind time so both ends of the
        // decision come from one place.
        let Some(encoding) = flow.encoding() else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let Some(framing) = self
            .profile
            .as_ref()
            .and_then(|profile| profile.profile().admits_encoding(encoding))
        else {
            return Err(RealtimeFlowError::EncodingInvalid);
        };
        // Cloned from the map's own key, so the binding shares the label's one
        // allocation and its one lease rather than minting a second.
        let binding = RealtimeInboundBinding::new(flow.label().clone(), encoding.clone(), framing);
        // The pump's two handles on this flow, taken here because this is the
        // last point at which the flow and the table are both in hand. Both are
        // non-owning in the sense that matters: the port claim cannot keep the
        // flow's registry lease alive, and the wake is a signal rather than a
        // reference to anything.
        let port = flow.port_handle();
        let end = flow.end.watch();
        // The entry this binding will occupy, funded against the flow it names
        // before the table retains anything. A refusal below drops it, so a
        // refused bind holds nothing.
        let record = flow
            .port
            .reserve_queue_record_checked::<RealtimeInboundEntry>()
            .map_err(realtime_drop_refusal)?;
        // The retirement may outlive this flow record and even a cancelled
        // close waiter.  Acquire its provider-owned tail before publication,
        // then keep it inside the retirement token that owns the native stop.
        // Explicit and implicit teardown therefore share one quiescence fact.
        let native_tail = self.acquire_native_tail()?;
        retirement.attach_native_tail(native_tail);
        if !self.bindings.bind(
            Arc::clone(&identity),
            RealtimeDirection::Inbound,
            binding,
            port,
            end,
            record,
        ) {
            // `retirement` is dropped by this return, as it is by every refusal
            // above it. That submits a retirement for a token whose transceiver
            // does not exist yet, which is not a wasted stop but the exactly
            // correct one: it finds no record and completes. Were the ordering
            // ever to change so that it did exist, the same drop would retire
            // it, which is why the retirement is taken by value here rather
            // than being handed over only on the success path.
            return Err(RealtimeFlowError::FlowRefused);
        }
        // Recorded only once the table has accepted, so a refused bind leaves
        // nothing for close to hand back. Reached by a second lookup because the
        // checks above hold the flow immutably; the entry is known to exist.
        //
        // From here the flow owns the retirement, so every way the flow can end
        // ends with a submission — including the ways that call nothing.
        if let Some(flow) = self.flows.get_mut(name.as_bytes()) {
            flow.native = RealtimeFlowRemains::Inbound(retirement);
        }
        Ok(())
    }

    /// Attach the negotiated native track to an already-open outbound flow and
    /// start the flow-owned pump.
    ///
    /// **Hands the track back on every refusal.** Releasing a native track is
    /// async and this runs under the fence, which cannot await — so a refusal
    /// that swallowed the track would leak a native object with nothing left
    /// able to free it. Returning it puts it in the one place that can await:
    /// the caller, once it has left the fence.
    ///
    /// The pump claim is taken last, after every other check has passed, so a
    /// refusal never consumes the one pump a queue can issue.
    ///
    /// **The pump and the track are claimed in one step, and this is the only
    /// step that issues either.** A pump cannot exist without the track it
    /// writes to, and a track cannot exist without a pump to release it, so
    /// "was a native track ever attached to this flow" is never a separate fact
    /// a caller has to keep in step with anything.
    pub(crate) fn attach_outbound(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        track: RealtimeOutboundTrack,
    ) -> std::result::Result<(), (RealtimeFlowError, RealtimeOutboundTrack)> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err((RealtimeFlowError::FlowRefused, track));
        };
        if let Err(refusal) = flow.port_if_current(session, live) {
            return Err((refusal, track));
        }
        let FlowQueue::Outbound(queue) = &flow.queue else {
            return Err((RealtimeFlowError::FlowRefused, track));
        };
        let queue = Arc::clone(queue);
        // Acquire the tail before consuming the queue's one pump claim.  A
        // refusal must return the native track with both provider and pump
        // ownership untouched.
        let tail = match self.acquire_native_tail() {
            Ok(tail) => tail,
            Err(_) => return Err((RealtimeFlowError::FlowRefused, track)),
        };
        // Last, and only once nothing else can refuse: a queue issues exactly
        // one pump, and a consumed claim cannot be handed back with the track.
        if !queue.claim_pump() {
            drop(tail);
            return Err((RealtimeFlowError::FlowRefused, track));
        }
        let pump = RealtimeOutboundPump {
            queue: Arc::downgrade(&queue),
            ready: queue.ready(),
            _tail: Some(tail),
        };
        // The pump task owns the track from here, and is the only thing that
        // may retire it. That is what makes teardown mechanical: the flow drops,
        // its queue drops, the pump's upgrade fails, it removes its own track
        // and completes the lease below. No retirement event, and no second
        // owner that could remove the same track twice or keep a sender alive
        // past its session.
        let (retired, remains) = tokio::sync::oneshot::channel();
        spawn_outbound_realtime_pump(pump, track, retired);
        // Recorded after the spawn, so the lease on the flow always names a pump
        // that exists. `attach_outbound` is reached once per flow — the pump
        // claim above is single-issue — so this cannot overwrite an earlier one.
        if let Some(flow) = self.flows.get_mut(name.as_bytes()) {
            flow.native = RealtimeFlowRemains::Outbound(remains);
        }
        Ok(())
    }

    /// Close one flow, release its label, and hand back its native remainder.
    ///
    /// Gated like every other use: a caller whose session is no longer current
    /// cannot close a flow, because it can no longer prove the flow is one of
    /// *its* flows. The set is dropped wholesale when the session goes, so a
    /// refused close never strands anything.
    ///
    /// **The return value is not optional bookkeeping.** A flow's native half
    /// outlives this call — retiring either kind awaits, and this runs under a
    /// sync fence — so the caller has to finish it outside.
    ///
    /// Discarding the [`RealtimeFlowRemains`] is no longer a leak in either
    /// direction: both arms retire what they hold when they are dropped. What it
    /// costs is the *acknowledgement* — a caller that drops it has told someone
    /// the flow is closed while the transceiver or the sender may still be
    /// coming down, which is exactly what an explicit close exists to avoid.
    pub(crate) fn close(
        &mut self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
    ) -> FlowResult<RealtimeFlowRemains> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        flow.port_if_current(session, live)?;
        if flow
            .opaque_pending_change
            .as_ref()
            .is_some_and(|pending| pending.active.is_active())
        {
            // A live Change token owns the only safe terminal decision.  Do
            // not drop its record and release its marker funding underneath
            // the pending control exchange.
            return Err(RealtimeFlowError::FlowRefused);
        }
        // Order matters: take the flow out first, then release the label. The
        // label is only free once nothing holds the flow it named. The gate
        // above has already passed, so this removal cannot be the mutation of a
        // refused close.
        // The map key is one of the label's shared copies, so taking it out here
        // is what hands this scope a leased label to release below — no mint,
        // no second allocation of the same bytes.
        let (label, mut flow) = self
            .flows
            .remove_entry(name.as_bytes())
            .expect("the flow was just read under this same borrow");
        // Taken before the drop, because the drop is what makes it unreachable.
        let remains = std::mem::take(&mut flow.native);
        // Explicit, and the ordering matters twice over: dropping the flow
        // closes its queue, which wakes an outbound pump, and drops the end
        // guard, which wakes an inbound one. Both happen before this returns,
        // so a caller that then awaits the outbound receipt is waiting on a pump
        // that has already been told to stop.
        drop(flow);
        // Before the label is free: a negotiated identity still pointing at
        // this label after the label could be reclaimed would attach a peer's
        // media to whatever flow took the name next.
        self.bindings.release(&label);
        // And for the same reason, nothing already queued may survive the name.
        //
        // Arrivals wait on one session-wide queue and carry the label they
        // arrived on. A unit queued for this flow and still undrained when the
        // flow closes is addressed to a name this call is about to make
        // claimable again, so a consumer reading it afterwards would attribute
        // the old flow's media to whatever flow took the name next — the exact
        // misattribution the single-queue design removed everywhere else.
        //
        // Compared on the leased record rather than on the bytes: two flows can
        // spell their name the same way, and only one of them is this one.
        // Dropping each matched item here is what releases its payload lease and
        // its queue-record lease, at the moment it stops being deliverable.
        self.arrivals
            .purge(|queued| RealtimeFlowLabel::is_same_record(&queued.label, &label));
        // The last strong reference this scope holds, dropped here. Nothing
        // outlives the close carrying the name: the caller is handed the
        // outcome by this very return, so the name is free to claim again the
        // moment this returns and no later report can contradict that.
        drop(label);
        Ok(remains)
    }

    /// Queue one unit for sending on an outbound flow.
    ///
    /// **Synchronous, and it must stay so.** This runs under the registry
    /// mutation lock, which connector replacement also takes — that is what
    /// makes "the session is still current" and "the unit is queued" one
    /// atomic step rather than a check followed by an act. An await here would
    /// hold that lock across a suspension point and deadlock against the very
    /// replacement it is meant to be atomic with. The write to the native
    /// track happens on the pump's task, outside the lock.
    ///
    /// The unit is accounted before it is queued, so a flow cannot grow an
    /// unbounded backlog: a refused reservation refuses the send. That is
    /// correct for real-time — paced and lossy, freshness over delivery — and
    /// it uses the owner's existing byte budget rather than a new queue-depth
    /// constant.
    pub(crate) fn send(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        unit: RealtimeSendUnit,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let port = flow.port_if_current(session, live)?;
        // Sending on an inbound flow is a caller error, refused rather than
        // silently dropped — the queues are separate types precisely so this
        // cannot be a runtime coin-flip about which one a unit lands in.
        let FlowQueue::Outbound(queue) = &flow.queue else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let output = port
            .reserve_output_checked(unit.data.len())
            .map_err(realtime_drop_refusal)?;
        // The node this unit will wait in, funded before it exists. Acquired
        // after the payload so that a refusal here releases the payload
        // reservation on the way out rather than stranding it.
        let record = port
            .reserve_queue_record_checked::<QueuedUnit<RealtimeSendUnit>>()
            .map_err(realtime_drop_refusal)?;
        queue.push(unit, output.into_payload_lease(), record);
        Ok(())
    }

    /// Queue one application-owned opaque body on an exact current flow.
    /// Admission is synchronous under the flow-set fence: the body and queue
    /// record are funded before the unit is retained, and a stale handle or a
    /// body above the negotiated ceiling is refused without mutation.
    pub(crate) fn send_opaque(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
        bytes: Bytes,
    ) -> FlowResult<()> {
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        let port = flow.port_if_current(session, live)?;
        let Some(max_unit_bytes) = flow.opaque_max_unit_bytes() else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        if flow.opaque_is_ready() != Some(true)
            || flow.opaque_application_claim.is_none()
            || flow.direction() != RealtimeDirection::Outbound
            || bytes.len() > max_unit_bytes
            || flow
                .opaque_pending_change
                .as_ref()
                .is_some_and(|pending| pending.active.is_active())
        {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let FlowQueue::OpaqueOutbound(queue) = &flow.queue else {
            return Err(RealtimeFlowError::FlowRefused);
        };
        if queue.is_failed() {
            return Err(RealtimeFlowError::FlowRefused);
        }
        let output = port
            .reserve_output_checked(bytes.len())
            .map_err(realtime_drop_refusal)?;
        let record = port
            .reserve_queue_record_checked::<QueuedUnit<OpaqueSendUnit>>()
            .map_err(realtime_drop_refusal)?;
        let mode = flow.opaque_mode().ok_or(RealtimeFlowError::FlowRefused)?;
        let coordinate = flow
            .opaque_coordinate()
            .ok_or(RealtimeFlowError::FlowRefused)?;
        let opener_direction = flow
            .opaque_opener_direction()
            .ok_or(RealtimeFlowError::FlowRefused)?;
        queue.push(
            OpaqueSendUnit {
                data: bytes,
                mode,
                direction: opener_direction,
                coordinate,
                max_unit_bytes,
            },
            output.into_payload_lease(),
            record,
        );
        Ok(())
    }

    /// Admit a body received from a trusted native opaque lane. The coordinate
    /// is matched against the current flow record, not its reusable label, so a
    /// frame from a closed predecessor cannot reach a successor.
    pub(crate) fn deliver_opaque(
        &self,
        coordinate: crate::protocol::ApplicationFlowCoordinate,
        opener_direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        bytes: Bytes,
    ) -> bool {
        let Some(name) =
            self.opaque_name_for_coordinate(coordinate, opener_direction, mode, bytes.len())
        else {
            return false;
        };
        let Some(flow) = self.flows.get(name.as_bytes()) else {
            return false;
        };
        let Ok(custody) = flow.port.reserve_boxed_checked::<WebRtcInboundCustody>() else {
            return false;
        };
        let label = flow.label().clone();
        let Some(payload) = flow.port.reserve_output(bytes.len()) else {
            return false;
        };
        let Ok(record) = flow
            .port
            .reserve_queue_record_checked::<QueuedInboundUnit>()
        else {
            return false;
        };
        let Some(queued) = QueuedInboundUnit::from_opaque(
            label.clone(),
            mode,
            coordinate,
            bytes,
            payload.into_payload_lease(),
            custody,
        ) else {
            return false;
        };
        self.arrivals.push(queued, record);
        true
    }

    /// **Controls only.** One delivery accounted against `label`'s flow,
    /// exactly as the inbound pump accounts one.
    ///
    /// A control outside this module cannot build a deliverable unit. A
    /// `RealtimeInboundDelivery` assembled from its public constructor carries
    /// no payload lease, and [`Self::deliver_inbound`] refuses a leaseless
    /// delivery before it looks anything up — so a control that built one would
    /// observe that refusal rather than whatever it meant to test. Minting the
    /// lease itself is not open to it either, and deliberately: the lease type
    /// stays inside `transport::webrtc` so nothing upstream can hold an
    /// accounting claim apart from the unit it belongs to.
    ///
    /// So the mint happens here, through the same reservation the assembler's
    /// output takes, and hands back only the opaque delivery. The bytes are
    /// charged the way the real path charges them, which is the only reason a
    /// control driving this proves anything about the real path.
    ///
    /// `None` when the label names no flow of this set, or when the flow's
    /// envelope refuses the bytes — both of which a control should read as a
    /// fixture that cannot express what it wanted, not as the answer.
    ///
    /// Gated to the same audience as its callers: every control that mints one
    /// needs a real promoted session over a live link, which only the
    /// `transport-lab` harness builds.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn accounted_delivery_for_test(
        &self,
        name: &RealtimeFlowName,
        unit: RealtimeRecvUnit,
    ) -> Option<RealtimeInboundDelivery> {
        let (label, flow) = self.flows.get_key_value(name.as_bytes())?;
        // The real reservation, taken from the flow's own port against the
        // owner's envelope — not a mint. A caller that has bypassed the session
        // flow has no port to reserve against and gets `None` here, which is
        // what makes a control built on this fail rather than pass on a fiction.
        let payload = flow
            .port
            .reserve_output(unit.data.len())?
            .into_payload_lease();
        let mut delivery = RealtimeInboundDelivery::new(label.clone(), unit);
        delivery
            .attach(payload)
            .expect("a freshly built delivery has no lease to displace");
        Some(delivery)
    }

    /// **Controls only.** One delivery taken through the *whole* accounting
    /// path: reserved on the flow's own port, enqueued by `enqueue_checked`,
    /// and taken back off the registry exactly as the connector's event loop
    /// takes it.
    ///
    /// This is the seam [`Self::accounted_delivery_for_test`] cannot be. That
    /// one reserves and converts by hand, which skips the three things
    /// `enqueue_checked` alone does: validating the reservation against this
    /// registry, this key and this flow's liveness; taking the queue and ready
    /// claims; and performing the queued-to-delivered lease transition on the
    /// way back out. A control built on this is therefore standing on the real
    /// path rather than on a faithful imitation of it.
    ///
    /// It is deliberately **not** the lab seam. `try_recv` is the connector
    /// event loop's call, and in a fixture with a live connector this would
    /// race that loop for the event it just queued — sometimes losing it, and
    /// sometimes taking one the loop was about to deliver. It is gated to plain
    /// `test` for that reason: the controls that use it own their registry
    /// outright and nothing else is draining it.
    ///
    /// `None` when the name holds no flow, when the envelope refuses the bytes,
    /// or when the enqueue is refused — all of which a control should read as a
    /// fixture that cannot express what it wanted.
    #[cfg(test)]
    pub(super) fn enqueued_delivery_for_test(
        &self,
        name: &RealtimeFlowName,
        unit: RealtimeRecvUnit,
    ) -> Option<RealtimeInboundDelivery> {
        let (label, flow) = self.flows.get_key_value(name.as_bytes())?;
        let reservation = flow.port.reserve_output(unit.data.len())?;
        flow.port
            .enqueue_checked(
                QueuedTransportEvent {
                    event: TransportEvent::RealtimeUnit(RealtimeInboundDelivery::new(
                        label.clone(),
                        unit,
                    )),
                    observation: None,
                    callback_work: None,
                },
                reservation,
            )
            .ok()?;
        match self.registry.try_recv()?.event {
            TransportEvent::RealtimeUnit(delivery) => Some(delivery),
            _ => None,
        }
    }

    /// Deliver one assembled unit onto an inbound flow.
    ///
    /// Called by the connector's inbound track pump, which has already
    /// accounted the bytes through the assembler's output reservation and hands
    /// that lease over inside the delivery. Answers whether the flow was there
    /// to take it; a unit for a flow that has gone is dropped with its lease,
    /// which releases the bytes rather than stranding them.
    ///
    /// **Takes the delivery whole, and never holds it in pieces.** The engine
    /// drives this — it is where the promoted session's flow set lives, and the
    /// connector cannot deliver anything because it holds no session — but the
    /// engine must never hold the three parts separately. A
    /// `RealtimePayloadLease` in the engine's hands is an accounting claim it
    /// could drop independently of the unit it belongs to, so the type stays
    /// inside `transport::webrtc`. `pub(crate)` on this method exposes only the
    /// opaque delivery.
    ///
    /// **Every refusal happens while the delivery is still whole.** The flow
    /// lookup, the direction check and the queue-record reservation all read a
    /// borrowed label, so a refusal here drops one value — unit and payload
    /// lease together — rather than dropping a lease whose unit is still bound
    /// in a local. The conversion is the last step and cannot fail after it
    /// starts, which is what makes "the parts exist separately" untrue rather
    /// than merely unlikely.
    ///
    /// A delivery that arrives without a lease is refused by that conversion,
    /// which is the only thing that can see it. Only the realtime queue mints
    /// one and it attaches before it queues, so a leaseless delivery did not come
    /// through the accounting path at all; it costs a queue record that is
    /// released on the way out, on a path that cannot occur.
    pub(crate) fn deliver_inbound(&self, delivery: RealtimeInboundDelivery) -> bool {
        let Some(flow) = self.flows.get(delivery.label().name().as_bytes()) else {
            return false;
        };
        if !matches!(flow.queue, FlowQueue::Inbound) {
            return false;
        }
        let Ok(custody) = flow.port.reserve_boxed_checked::<WebRtcInboundCustody>() else {
            return false;
        };
        // The node this arrival will wait in, funded against the flow that
        // received it. An owner with nothing left to give refuses here, and the
        // whole delivery is dropped — which releases the bytes with the unit
        // they belong to rather than queueing them unaccounted.
        let Ok(record) = flow
            .port
            .reserve_queue_record_checked::<QueuedInboundUnit>()
        else {
            return false;
        };
        let Some(queued) = QueuedInboundUnit::from_delivery(delivery, custody) else {
            return false;
        };
        self.arrivals.push(queued, record);
        true
    }

    /// Whether `label` names a live flow of this session that may still be
    /// used right now.
    pub(crate) fn is_current(
        &self,
        session: &impl RealtimeSessionBinding,
        live: Option<&Arc<crate::connector::ConnectorIncarnation>>,
        name: &RealtimeFlowName,
    ) -> bool {
        self.flows
            .get(name.as_bytes())
            .is_some_and(|flow| flow.port_if_current(session, live).is_ok())
    }

    /// Whether this exact flow set has no logical records, queued inbound
    /// arrivals, or provider-owned native tails. A close receipt may be
    /// dropped while its pump/retirement is still running, so map and queue
    /// emptiness alone is not a proof that demand-link retirement is safe.
    pub(crate) fn is_quiescent(&self) -> bool {
        let mut has_flow = false;
        self.flows.for_each(|_, _| has_flow = true);
        let native_tails_done = self
            .native_tail_state
            .as_ref()
            .is_none_or(|state| state.outstanding.load(std::sync::atomic::Ordering::Acquire) == 0);
        !has_flow && self.arrivals.is_empty() && native_tails_done
    }

    /// Whether `bindings` is *this* flow set's negotiated-track table.
    ///
    /// The connector holds the table weakly and upgrades it when a track
    /// arrives; this is how a control states which set an upgraded handle came
    /// from. Compared against the live strong reference this set holds, for the
    /// same reason as [`Self::is_same`].
    ///
    /// **Controls only, and gated rather than merely documented as such.**
    /// Production never asks: `on_track` upgrades the weak slot and uses
    /// whatever it gets, because that slot is installed by the same call that
    /// builds the set and there is no second candidate to distinguish from. An
    /// ungated accessor would read as a check production could be expected to
    /// make, and the next reader would wonder why it does not.
    /// Whether this session currently has a flow by that name.
    ///
    /// **Controls only, and gated rather than merely documented as such.**
    /// Production never asks: `open` answers "was this free" as part of taking
    /// it, and every other question about a name is really a question about the
    /// flow behind it, which the caller already has. An ungated predicate reads
    /// as a check production could be expected to make first, and a caller that
    /// asked and then acted would be acting on an answer that could have changed
    /// in between.
    ///
    /// It reads the flow map because that map *is* the namespace. There is no
    /// second collection of held names for it to disagree with.
    #[cfg(test)]
    pub(crate) fn holds(&self, name: &RealtimeFlowName) -> bool {
        self.flows.contains_key(name.as_bytes())
    }

    #[cfg(test)]
    pub(super) fn owns_bindings(&self, bindings: &Arc<RealtimeInboundBindings>) -> bool {
        Arc::ptr_eq(&self.bindings, bindings)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A name from a literal, for controls that care about identity rather
    /// than about the bytes.
    fn control_name(bytes: &[u8]) -> RealtimeFlowName {
        RealtimeFlowName::new(bytes.to_vec()).expect("a control name is within the frame bound")
    }

    /// An elastic registry: a real provider scope, and **no** owner ceilings.
    ///
    /// This is `Enabled(None)` as a deployment actually states it, and it is
    /// the arrangement the label controls run against on purpose. A label still
    /// takes a real lease here — absence of a ceiling is not absence of
    /// accounting — so a control that mints one is proving the elastic path
    /// admits, not that admission was skipped.
    fn control_label_registry() -> (
        Arc<RealtimeFlowRegistry>,
        super::super::realtime::ElasticControlResources,
    ) {
        RealtimeFlowRegistry::elastic_for_control(control_label_grant())
    }

    /// Generous enough that nothing in the label controls is refused for
    /// capacity. Admission under pressure has its own controls; these are about
    /// what a label *is*.
    ///
    /// One definition for the whole crate, in the parent module: the structural
    /// half has to match the scope stack `elastic_for_control` really builds,
    /// and a per-file copy could only match it by luck.
    fn control_label_grant() -> crate::resource::ResourceClaim {
        super::super::elastic_control_grant()
    }

    /// A name is held for its flow's lifetime and reusable only after.
    ///
    /// The positive half of the label contract, asked of the one namespace that
    /// answers it: exact claim, exact reclaim, and the reuse ordering that stops
    /// a stale peer report from freeing a live flow's name. A name is in use
    /// exactly when this session has a flow keyed by it, so every assertion here
    /// reads the same map the open and the close write.
    #[test]
    fn v4_macro1_a_label_is_held_for_its_flows_lifetime_and_reusable_only_after() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let alpha = control_name(b"alpha");
        let beta = control_name(b"beta");
        let open = |flows: &mut SessionRealtimeFlows, name: &RealtimeFlowName| {
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: control_encoding(),
                    name: name.clone(),
                },
            )
        };

        let first = open(&mut flows, &alpha).expect("the space starts empty");
        let second = open(&mut flows, &beta).expect("a second flow takes the name chosen for it");
        assert_ne!(first, second, "two live flows never share a name");

        // While held, the exact name is refused rather than quietly aliased.
        assert_eq!(
            open(&mut flows, &alpha).err(),
            Some(RealtimeFlowError::LabelInUse),
            "a live flow's name cannot be taken from under it"
        );
        assert!(flows.holds(&alpha));

        // Released only when the flow itself is gone; then, and not before,
        // the name is available again.
        let _remains = flows
            .close(&session, Some(&incarnation), &alpha)
            .expect("the session that opened this flow may close it");
        assert!(!flows.holds(&alpha));
        let reused = open(&mut flows, &alpha).expect("the freed name is available again");
        assert_eq!(reused, alpha, "and it is the same name, not a new one");
        assert!(
            flows.holds(&beta),
            "releasing one flow's name never disturbs another's"
        );
    }

    /// A fixture session bound to one connector incarnation.
    struct ControlSession {
        incarnation: Arc<crate::connector::ConnectorIncarnation>,
    }

    impl RealtimeSessionBinding for ControlSession {
        fn is_current_on(&self, incarnation: &Arc<crate::connector::ConnectorIncarnation>) -> bool {
            Arc::ptr_eq(&self.incarnation, incarnation)
        }
    }

    /// The encoding the elastic controls open against.
    fn control_encoding() -> RealtimeEncoding {
        RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the control encoding names a family the control profile registers")
    }

    #[cfg(feature = "transport-lab")]
    fn control_opaque_spec(
        label: &[u8],
        direction: RealtimeDirection,
        opener_direction: crate::realtime::RealtimeFlowDirection,
        mode: crate::realtime::OpaqueFlowMode,
        max_unit_bytes: usize,
    ) -> OpaqueFlowSpec {
        OpaqueFlowSpec {
            direction,
            opener_direction,
            mode,
            max_unit_bytes,
            name: control_name(label),
        }
    }

    /// An elastic session — `Enabled(None)`, no owner ceilings anywhere — opens
    /// a flow and carries a unit all the way through the accounting path.
    ///
    /// **The discriminating positive for the elastic case.** Every ceiling this
    /// registry could consult is `None`, so nothing here is admitted by a limit
    /// comparison: the label, the flow, the output bytes, the queue slot and the
    /// ready node are each a real provider lease or they do not exist. A build
    /// that treated absent ceilings as zero would refuse at the first
    /// acquisition, and one that treated them as unlimited would skip the leases
    /// entirely — and the release assertion at the end is what tells those two
    /// apart, because an unaccounted path has nothing to give back.
    ///
    /// It goes through `enqueue_checked` rather than around it. That call is
    /// where the reservation is validated against this registry and this flow,
    /// where the queue and ready claims are taken, and where the queued lease
    /// becomes a delivered one, so a control that reserved and converted by hand
    /// would be proving something about its own arithmetic.
    #[tokio::test]
    async fn v4_macro1_an_elastic_session_moves_a_unit_through_real_leases_end_to_end() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        let name = flows
            .open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: control_encoding(),
                    name: control_name(b"elastic"),
                },
            )
            .expect("an owner that selected no ceiling still admits a flow");

        let idle = resources.accounted_bytes();
        assert!(
            idle > 0,
            "the open really did take leases — without this every assertion \
             below would be about a path that charges nothing"
        );

        let delivery = flows
            .enqueued_delivery_for_test(
                &name,
                RealtimeRecvUnit {
                    timestamp: 90_000,
                    marker: true,
                    data: Bytes::from_static(b"unit"),
                },
            )
            .expect("the elastic flow reserves, enqueues and delivers one unit");
        assert!(
            resources.accounted_bytes() > idle,
            "the delivered unit is holding its own payload lease, so the \
             elastic path accounted for the bytes rather than waving them \
             through"
        );

        let arrivals = flows
            .inbound_arrivals()
            .expect("a fresh flow set issues its inbound reader once");
        assert!(
            flows.deliver_inbound(delivery),
            "and the flow set takes a delivery the accounting path built"
        );
        assert_eq!(
            arrivals
                .next()
                .await
                .map(|(arrived, unit)| (arrived.name().clone(), unit.data)),
            Some((name.clone(), Bytes::from_static(b"unit"))),
            "exactly the unit that was delivered comes off the session's one \
             inbound queue, naming the flow it arrived on"
        );

        // The release half. Closing returns everything the flow took.
        let _remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        assert!(
            resources.accounted_bytes() < idle,
            "closing gave the flow's leases back — an elastic path that had \
             skipped accounting would have nothing to return here"
        );
    }

    /// A provider under pressure refuses, and the refusal is the only thing
    /// that happened.
    ///
    /// The negative half of the elastic pair, and it discriminates in both
    /// directions. Absent ceilings do not mean unlimited: with the provider
    /// exhausted, the next acquisition is refused as a typed refusal rather
    /// than admitted. And the refusal is not a leak: releasing the holder makes
    /// the very same acquisition succeed, so what refused was pressure rather
    /// than a claim that had gone missing.
    #[test]
    fn v4_macro1_an_elastic_registry_refuses_under_provider_pressure_and_recovers() {
        let name = control_name(b"pressure");
        // A grant sized for exactly one label and nothing more, derived from the
        // claim itself rather than chosen. Anything larger would leave the
        // refusal below to some other exhaustion.
        let grant = control_label_grant()
            .checked_add(
                RealtimeFlowLabel::mint_claim(name.as_bytes().len())
                    .expect("the label claim is representable"),
            )
            .expect("the pressure grant is representable");
        let (registry, _resources) = RealtimeFlowRegistry::elastic_for_control(grant);

        // Drain everything the grant will give, so the provider is genuinely at
        // its ceiling rather than merely busy. The mint is what this control is
        // about — the acquisition a name costs — so it is exercised directly
        // rather than through an open that would exhaust some other claim first.
        let mut held = Vec::new();
        while let Ok(label) = RealtimeFlowLabel::mint(
            control_name(format!("fill-{}", held.len()).as_bytes()),
            &registry,
        ) {
            held.push(label);
        }
        assert!(
            !held.is_empty(),
            "the fixture admitted something before it refused — without this \
             the refusal below could be a registry that refuses everything"
        );

        assert_eq!(
            RealtimeFlowLabel::mint(name.clone(), &registry).err(),
            Some(RealtimeFlowError::FlowRefused),
            "an elastic registry under provider pressure refuses the name \
             rather than retaining bytes nothing accounted for"
        );

        // Release exactly one holder and the same mint succeeds. This is what
        // makes the refusal above pressure rather than a lost claim. Dropping
        // the label *is* the release: the record holds its own lease, so there
        // is no table to take it out of first.
        drop(held.pop().expect("the fill loop admitted at least one"));
        let recovered = RealtimeFlowLabel::mint(name.clone(), &registry)
            .expect("the released charge is available again to the next mint");
        assert_eq!(recovered.name(), &name);
    }

    /// A close takes its flow's queued arrivals with it, so a name reused
    /// afterwards never delivers the previous flow's media.
    ///
    /// Arrivals wait on one session-wide queue, which is what removed the
    /// duplicate retained notification — but it also means a unit outlives the
    /// flow it was addressed to unless the close says otherwise. Within one
    /// session a name is releasable and immediately re-claimable, so an
    /// undrained unit from A is a unit a consumer would read *after* B has taken
    /// A's name, and would attribute to B.
    ///
    /// Three assertions, and each fails for a different omission. The provider
    /// reading after the close proves the purged unit's payload and queue-record
    /// leases went back rather than the item merely being skipped. The delivered
    /// unit proves the purge is scoped to the closing flow and did not empty the
    /// queue. And the fresh unit arriving at all proves the reused name is fully
    /// live rather than collaterally broken by the purge.
    #[tokio::test]
    async fn v4_arc05_a_close_purges_the_units_queued_for_the_name_it_frees() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let x = control_name(b"x");
        let open = |flows: &mut SessionRealtimeFlows| {
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: control_encoding(),
                    name: x.clone(),
                },
            )
        };
        let queue_one = |flows: &mut SessionRealtimeFlows, payload: &'static [u8]| {
            let delivery = flows
                .enqueued_delivery_for_test(
                    &x,
                    RealtimeRecvUnit {
                        timestamp: 90_000,
                        marker: true,
                        data: Bytes::from_static(payload),
                    },
                )
                .expect("the flow reserves, enqueues and delivers one unit");
            assert!(
                flows.deliver_inbound(delivery),
                "the unit lands on this session's one inbound queue"
            );
        };

        let empty = resources.accounted_bytes();

        // A takes the name, and one unit is queued for it and left undrained.
        open(&mut flows).expect("the space starts empty");
        let a_open = resources.accounted_bytes();
        queue_one(&mut flows, b"from-A");
        assert!(
            resources.accounted_bytes() > a_open,
            "the queued unit really is retained — without this the release \
             assertion below would pass on a queue that holds nothing"
        );

        // A closes. Its queued unit is not deliverable to anything, so it goes.
        let _remains = flows
            .close(&session, Some(&incarnation), &x)
            .expect("the session that opened this flow may close it");
        assert_eq!(
            resources.accounted_bytes(),
            empty,
            "the close released A's own leases and the payload and queue-record \
             leases of the unit still queued for it — a skipped item would have \
             left both behind"
        );

        // B takes the very same name and gets its own unit.
        open(&mut flows).expect("the freed name is available again");
        queue_one(&mut flows, b"from-B");

        let arrivals = flows
            .inbound_arrivals()
            .expect("this session's consumer claims its reader");
        let (arrived, unit) = arrivals.next().await.expect("B's unit is queued");
        assert_eq!(
            unit.data,
            Bytes::from_static(b"from-B"),
            "the first unit a consumer reads after the reuse is B's — A's would \
             have been ahead of it in this queue and would have been read as B's"
        );
        assert_eq!(arrived.name(), &x, "and it arrived on the reused name");
    }

    /// A name is bytes, and the two shapes that are not a name are refused
    /// before anything can be charged for them.
    ///
    /// Both refusals matter for the same reason: they happen ahead of the mint,
    /// so a peer sending them drives no retention at all. The upper bound is
    /// the frame's own length prefix rather than a number chosen here, and the
    /// positive case sits between them so neither refusal can be passing
    /// because nothing is ever accepted.
    #[test]
    fn v4_macro1_a_flow_name_is_bounded_by_the_frame_and_never_empty() {
        assert!(
            RealtimeFlowName::new(Vec::new()).is_none(),
            "an empty name is not a degenerate name, it is not a name"
        );
        assert!(
            RealtimeFlowName::new(vec![b'x'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES])
                .is_some(),
            "the largest name the length prefix can carry is a name"
        );
        assert!(
            RealtimeFlowName::new(vec![
                b'x';
                crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES + 1
            ])
            .is_none(),
            "one byte past what the frame can encode could never have arrived"
        );
    }

    /// Reusing a name cannot make an old close describe the new flow, and a
    /// close retains nothing that could later claim to.
    ///
    /// **Close A, immediately reopen the same name as B**, and then look for
    /// anything A's close could still be holding or could still be delivered
    /// as. There is nothing to look at, and that is the proof: a
    /// close reports its outcome only through its own return value, so the
    /// window in which a delayed report could be misread as B's closure does
    /// not exist rather than being closed by a comparison someone has to make.
    ///
    /// The accounting half is what makes the first half non-vacuous. If A's
    /// close had retained the name anywhere — a queued event, a pending report,
    /// a tombstone — the charge for those bytes would still be outstanding
    /// while B is open. Returning to the exact one-flow baseline is the
    /// observable that says nothing survived.
    #[test]
    fn v4_macro1_reusing_a_name_cannot_make_an_old_close_describe_the_new_flow() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        let empty = resources.accounted_bytes();
        let open_one = |flows: &mut SessionRealtimeFlows| {
            flows
                .open(
                    &session,
                    Some(&incarnation),
                    RealtimeFlowSpec {
                        direction: RealtimeDirection::Outbound,
                        encoding: control_encoding(),
                        name: control_name(b"reused"),
                    },
                )
                .expect("the name is available")
        };

        // A.
        let name = open_one(&mut flows);
        let one_flow = resources.accounted_bytes();
        assert!(
            one_flow > empty,
            "the open really did take leases — without this the release \
             assertion below would pass on a path that charges nothing"
        );

        let _remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the session that opened this flow may close it");
        assert_eq!(
            resources.accounted_bytes(),
            empty,
            "A's close retained nothing at all — no queued event, no pending \
             report, nothing still naming the flow that could later be \
             delivered and read as a close of whatever takes the name next"
        );

        // B, under the very same name, with nothing in between.
        let reused = open_one(&mut flows);
        assert_eq!(reused, name, "B really is the same name, not a fresh one");
        assert_eq!(
            resources.accounted_bytes(),
            one_flow,
            "and B costs exactly what A did — the session is carrying one flow, \
             not one flow plus a residue of the closed one"
        );

        // The only report of A's close was A's own return value, which this
        // scope already consumed. There is no stream to await, no event to
        // dequeue, and therefore no notification that could name B.
        let _remains = flows
            .close(&session, Some(&incarnation), &reused)
            .expect("B closes on its own terms");
        assert_eq!(resources.accounted_bytes(), empty);
    }

    /// A pump distinguishes "nothing queued yet" from "the flow is gone", and
    /// the second is caused by the drop itself.
    ///
    /// This is the lifecycle ruling made mechanical: there is no retirement
    /// event and no `closed` flag. Dropping the session bundle drops the flow
    /// set, the flows, and their queues; the pump holds only a `Weak`, so the
    /// drop is what ends it. The discriminating half is the first assertion —
    /// a pump that reported `Closed` whenever it had nothing to do would pass
    /// a closure test trivially and would stop every idle flow.
    #[tokio::test]
    async fn v4_macro1_a_pump_ends_because_its_queue_dropped_not_because_it_was_told() {
        let (registry, _resources) = control_label_registry();
        let queue = RealtimeFlowQueue::<RealtimeSendUnit>::mint(&registry)
            .expect("the elastic control grant funds one queue and its wake");
        let pump = queue
            .claim_pump()
            .then(|| RealtimeOutboundPump {
                queue: Arc::downgrade(&queue),
                ready: queue.ready(),
                _tail: None,
            })
            .expect("the first pump claims the queue");

        assert!(
            matches!(pump.next(), RealtimePumpStep::Empty),
            "a live flow with an empty queue is idle, not closed — a pump that \
             confused the two would stop the first time it caught up"
        );

        // The exact gap. The pump has just observed Empty and has NOT yet
        // parked; retirement lands here. A wake that only reached tasks
        // already registered would be lost in this window and the pump would
        // park on a queue that no longer exists, forever.
        drop(queue);

        // So the wake has to have been stored, and the park has to return
        // without anything further happening. `biased` polls the wait first:
        // if the permit is there it completes now, and the ready-branch never
        // runs. No timer, no polling, and no dependence on scheduling.
        tokio::select! {
            biased;
            _ = pump.ready() => {}
            _ = std::future::ready(()) => panic!(
                "the pump parked after the drop and was never woken — the \
                 closing wake was lost in the gap between observing Empty and \
                 registering"
            ),
        }

        assert!(
            matches!(pump.next(), RealtimePumpStep::Closed),
            "and having woken, the pump learns the flow is gone from the \
             failed upgrade, with no flag anyone had to remember to set"
        );
        assert!(
            matches!(pump.next(), RealtimePumpStep::Closed),
            "terminally — a closed pump never reports itself merely idle again"
        );
    }

    /// A queue issues one pump, which is what makes the single closing permit
    /// sufficient.
    #[test]
    fn v4_macro1_a_queue_issues_at_most_one_pump() {
        let (registry, _resources) = control_label_registry();
        let queue = RealtimeFlowQueue::<RealtimeSendUnit>::mint(&registry)
            .expect("the elastic control grant funds one queue and its wake");
        assert!(queue.claim_pump(), "the first claim succeeds");
        assert!(
            !queue.claim_pump(),
            "and the second is refused — a second pump would be the waiter the \
             single closing permit can never reach"
        );
    }

    /// Every block a flow's own constructors allocate is funded before it
    /// exists, and each is released by whatever lets go of it last — which is
    /// not always the flow.
    ///
    /// Three legs, and each one fails for a different omission.
    ///
    /// **Direction.** An outbound open allocates four blocks and an inbound
    /// open allocates one, so the difference between what the two cost is
    /// exactly the queue, its wake, and its in-flight counter. Every other claim
    /// an open takes is identical across the two — the names are the same length, both
    /// directions take the same `flow_claim`, and the map node is the same type
    /// — so that difference is the root arithmetic and nothing else. Omit the
    /// root claims entirely, or charge one direction-blind constant, and this
    /// difference is zero.
    ///
    /// **Survival.** A wake is `Arc`-shared with a pump on purpose, because it
    /// has to outlive the thing whose death it announces. Cloning the handle and
    /// dropping the minter must leave the block still charged. This is the leg
    /// that fails if the lease is held *beside* the `Arc` rather than inside the
    /// record: the reading would fall back to empty while the surviving clone
    /// still held the allocation.
    ///
    /// **Release.** The last holder's drop takes it back to empty, so nothing is
    /// retained once every holder has gone — and a close releases the flow's own
    /// blocks rather than leaving them behind the map entry.
    #[test]
    fn v4_arc05_a_flows_root_blocks_are_funded_before_they_exist() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        let empty = resources.accounted_bytes();
        let open = |flows: &mut SessionRealtimeFlows, direction, name: &[u8]| {
            flows
                .open(
                    &session,
                    Some(&incarnation),
                    RealtimeFlowSpec {
                        direction,
                        encoding: control_encoding(),
                        name: control_name(name),
                    },
                )
                .expect("the elastic control grant admits one flow")
        };

        // Same-length names, so the only thing that differs between the two
        // opens is the direction.
        let inbound = open(&mut flows, RealtimeDirection::Inbound, b"aaaa");
        let with_inbound = resources.accounted_bytes();
        let outbound = open(&mut flows, RealtimeDirection::Outbound, b"bbbb");
        let with_both = resources.accounted_bytes();

        assert!(
            with_inbound > empty,
            "an inbound open charges something at all — without this the \
             difference below could be right for a path that charges nothing"
        );
        let queue_blocks = u64::try_from(
            std::mem::size_of::<RealtimeFlowQueue<RealtimeSendUnit>>()
                + std::mem::size_of::<LeasedWake>()
                + std::mem::size_of::<queue::InFlightCounter>()
                // Three `Arc`s, two counters apiece.
                + 6 * std::mem::size_of::<usize>(),
        )
        .expect("three block sizes are representable");
        assert_eq!(
            (with_both - with_inbound) - (with_inbound - empty),
            queue_blocks,
            "an outbound flow costs exactly three more blocks than an inbound \
             one: its queue, the pump's wake, and the in-flight counter"
        );

        // A wake outlives the flow that minted it, still paid for.
        let surviving = LeasedWake::mint(&registry).expect("the grant funds one wake");
        let held_by_two = resources.accounted_bytes();
        let watcher = Arc::clone(&surviving);
        assert_eq!(
            resources.accounted_bytes(),
            held_by_two,
            "a second handle on one block is not a second block"
        );
        drop(surviving);
        assert_eq!(
            resources.accounted_bytes(),
            held_by_two,
            "and the block stays charged while the watcher holds it — a lease \
             kept beside the `Arc` would have gone back here, with the \
             allocation still alive"
        );
        drop(watcher);
        assert_eq!(
            resources.accounted_bytes(),
            with_both,
            "the last holder's drop is the release"
        );

        let _remains = flows
            .close(&session, Some(&incarnation), &inbound)
            .expect("the session that opened this flow may close it");
        let _remains = flows
            .close(&session, Some(&incarnation), &outbound)
            .expect("the session that opened this flow may close it");
        assert_eq!(
            resources.accounted_bytes(),
            empty,
            "and closing both flows retains none of their blocks"
        );
    }

    /// The root block is acquired **before** it is allocated, and a refusal
    /// there leaves nothing behind.
    ///
    /// The delta control above cannot tell fund-then-allocate from
    /// allocate-then-fund: both end at the same reading. What separates them is
    /// what happens when the provider says no, so this squeezes the grant until
    /// the *only* acquisition an open can still be refused at is the root one.
    ///
    /// **Nothing here is guessed and nothing loops to find a limit.** The
    /// headroom left is computed from the four claims an open takes before it
    /// reaches a root — the label, the connector flow, the connector-flow map
    /// node, and the session-flow map node — each read from the same `claim`
    /// expression production uses. Those include two distinct map nodes; there
    /// is no held-name table. The filler consumes the remaining accounted bytes
    /// in one exact acquisition. Other dimensions are not artificially filled:
    /// they are checked only for sufficient headroom for those four production
    /// charges, while bytes are the exact ceiling that makes the root refuse.
    ///
    /// The recovery leg is what makes the refusal *pressure* rather than a
    /// fixture that refuses everything: releasing the filler makes the very same
    /// open succeed, under the very same name — which also proves the refused
    /// open handed its label back rather than burning it.
    #[test]
    fn v4_arc05_a_refused_root_block_leaves_no_label_port_map_or_block_behind() {
        let bytes = |claim: crate::resource::ResourceClaim| {
            claim.amount(crate::resource::ResourceClass::AccountedMemoryBytes)
        };
        let name = control_name(b"root-refusal");
        let pre_root_claims = [
            RealtimeFlowLabel::mint_claim(name.as_bytes().len())
                .expect("the label claim is representable"),
            RealtimeFlowRegistry::flow_claim().expect("the flow claim is representable"),
            RealtimeFlowRegistry::flow_map_node_claim()
                .expect("the connector flow node claim is representable"),
            crate::resource::LeasedMap::<RealtimeFlowLabel, RealtimeFlow>::entry_claim()
                .expect("the session-flow node claim is representable"),
        ];
        let before_the_root =
            pre_root_claims
                .iter()
                .fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
                    total
                        .checked_add(
                            crate::resource::FiniteResourceProvider::reservation_charge_for_test(
                                *claim,
                            )
                            .expect("the pre-root reservation charge is representable"),
                        )
                        .expect("the four pre-root reservation charges compose")
                });

        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );

        // Consume all accounted bytes except those four claims, in one exact
        // acquisition. The filler's own `Arc` counters are subtracted because
        // `acquire_flow_root` adds them to whatever it is asked for.
        let arc_counters =
            2 * u64::try_from(std::mem::size_of::<usize>()).expect("a counter pair is small");
        let filler = bytes(control_label_grant())
            .checked_sub(resources.accounted_bytes())
            .and_then(|free| free.checked_sub(bytes(before_the_root)))
            .and_then(|free| free.checked_sub(arc_counters))
            .expect("the control grant is larger than one open's pre-root claims");
        let filler = registry
            .acquire_flow_root(usize::try_from(filler).expect("the filler is representable"))
            .expect("the control grant funds the filler");
        let at_ceiling = resources.in_use();
        let remaining = control_label_grant()
            .checked_sub(at_ceiling)
            .expect("the in-use claim remains within the provider grant");
        for dimension in crate::resource::ResourceClass::ALL {
            assert!(
                remaining.amount(dimension) >= before_the_root.amount(dimension),
                "the provider has sufficient headroom for every pre-root reservation charge in {dimension:?}",
            );
        }
        assert_eq!(
            remaining.amount(crate::resource::ResourceClass::AccountedMemoryBytes),
            before_the_root.amount(crate::resource::ResourceClass::AccountedMemoryBytes),
            "the provider now holds exactly enough accounted memory for the label, two map \
             nodes and the connector flow — and nothing for a root block"
        );

        let open = |flows: &mut SessionRealtimeFlows| {
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: control_encoding(),
                    name: name.clone(),
                },
            )
        };

        assert_eq!(
            open(&mut flows).err(),
            Some(RealtimeFlowError::FlowRefused),
            "the open gets through every claim it takes before the root and is \
             refused at the one it cannot fund — so the block is acquired \
             before it is allocated, not after"
        );
        assert_eq!(
            resources.in_use(),
            at_ceiling,
            "and the refusal retained nothing: not the label, not the connector flow, \
             not either map node, and no block"
        );

        drop(filler);
        let opened = open(&mut flows).expect("the released headroom funds the same open");
        assert_eq!(
            opened, name,
            "under the very same name, so the refused open handed its label \
             back rather than burning it — and what refused above was pressure \
             rather than a fixture that refuses everything"
        );
    }

    /// A label a peer cites back grants nothing on its own.
    ///
    /// The discriminating negative: reconstructing a label from a peer-supplied
    /// byte is a question about this session's table, not a claim on a flow. A
    /// label naming no live flow answers false, and one naming a live flow
    /// answers true without conferring anything — the caller still has to hold
    /// the session to do anything with the answer.
    #[test]
    fn v4_macro1_a_peer_cited_label_is_a_lookup_not_a_claim() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let held = control_name(b"held");
        let cited = control_name(b"cited");
        let open = |flows: &mut SessionRealtimeFlows, name: &RealtimeFlowName| {
            flows.open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Outbound,
                    encoding: control_encoding(),
                    name: name.clone(),
                },
            )
        };
        open(&mut flows, &held).expect("the space starts empty");

        // Any bytes within the frame bound are a syntactically valid name, so
        // nothing is rejected here — which is exactly why the answer has to be
        // a lookup rather than a judgement.
        assert!(
            flows.holds(&held),
            "a peer can name a flow this session really does hold"
        );
        assert!(
            !flows.holds(&cited),
            "and naming one it does not hold finds nothing"
        );
        assert!(
            !flows.holds(&control_name(
                &[b'z'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES]
            )),
            "including the largest name the frame can carry"
        );

        // The cited name did not become held by being mentioned.
        let claimed = open(&mut flows, &cited)
            .expect("a name a peer said is still free until this side opens it");
        assert_eq!(claimed, cited);
    }

    /// A reader is a lease, not a one-shot: one holder at a time, returned on
    /// drop, and a reconnect resumes on the same queue.
    ///
    /// The discriminating case is the middle one. A one-shot claim would pass
    /// "second reader refused" and "reader ends on session drop" identically,
    /// and would still make a session permanently unreadable the first time a
    /// consumer pipe hung up. What separates the two designs is whether the
    /// lease comes back, and whether the item that arrived while nobody was
    /// listening is still there when someone is.
    ///
    /// Both readers are the same type, so this covers the flow-event reader
    /// as well as the arrival reader.
    ///
    /// The item is pushed on a record lease taken from the same registry a
    /// producer takes one from, not on a fixture stand-in. What accumulates
    /// across a reader gap is a *funded* node, and a control that manufactured
    /// the node some other way would prove the reconnect while saying nothing
    /// about whether the queue an owner is paying for is the one it resumes on.
    #[tokio::test]
    async fn v4_macro1_a_a_stream_reader_is_a_lease_a_reconnect_can_take_back() {
        let (registry, _resources) = control_label_registry();
        let stream = Arc::new(SessionStream::<u32>::new());
        let take_reader = |stream: &Arc<SessionStream<u32>>| {
            stream.claim().then(|| SessionStreamReader {
                stream: Arc::downgrade(stream),
                ready: Arc::clone(&stream.ready),
            })
        };

        let first = take_reader(&stream).expect("the first consumer takes the lease");
        assert!(
            take_reader(&stream).is_none(),
            "a second simultaneous reader is refused — closure is one stored \
             permit, so the second waiter would never wake"
        );

        // An item arrives, and then the consumer's pipe dies before it drains.
        // The node it lands in is funded through the registry's own queue-record
        // claim, so the elastic path is shown admitting rather than skipped.
        let record = registry
            .acquire_queue_record::<u32>()
            .expect("the elastic control grant funds one queued item");
        stream.push(7, record);
        drop(first);

        let second = take_reader(&stream).expect("the lease comes back with the reader");
        assert_eq!(
            second.next().await,
            Some(7),
            "the reconnect drains what accumulated while nobody was listening, \
             and drains it before parking rather than sleeping on a queue that \
             already has work in it"
        );

        // Session retirement.
        let ghost = Arc::downgrade(&stream);
        drop(stream);
        assert_eq!(
            second.next().await,
            None,
            "the reader ends because the stream went, not because it was told"
        );
        assert!(
            ghost.upgrade().is_none(),
            "and there is no stream left to lease from — re-claim after \
             retirement is not refused, it is unreachable"
        );
    }

    /// A reader takes units from the flow set it was claimed on and from no
    /// other — including the set that replaced it under the same name.
    ///
    /// This is the property that replaced the ownership predicate. While a
    /// consumer awaited a *name* and then re-entered the fence to resolve it, a
    /// session replaced in that window resolved the same name on the new set
    /// entirely correctly and handed back a live unit belonging to something
    /// else; a separate check had to be remembered at the call site to prevent
    /// it. A reader now takes whole units from one set's own queue, so the
    /// misattribution is not prevented by a check — it has nowhere to happen.
    ///
    /// Everything that could be mistaken for the discriminator is held
    /// *identical*: one registry allocation, and the same name live as an
    /// inbound flow in every set. If delivery were routed by name, or by
    /// registry, every negative here would fail.
    #[tokio::test]
    async fn v4_macro1_a_reader_takes_units_only_from_the_session_that_issued_it() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let open_shared = |flows: &mut SessionRealtimeFlows| {
            flows
                .open(
                    &session,
                    Some(&incarnation),
                    RealtimeFlowSpec {
                        direction: RealtimeDirection::Inbound,
                        encoding: control_encoding(),
                        name: control_name(b"shared"),
                    },
                )
                .expect("each session's label space is its own")
        };

        let mut first = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        // Allocated while `first` is still alive, so the two queues cannot
        // share an address and the replacement case below cannot pass by
        // accident.
        let mut second = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let name = open_shared(&mut first);
        open_shared(&mut second);

        let from_first = first
            .inbound_arrivals()
            .expect("a fresh flow set issues its inbound reader once");
        let from_second = second
            .inbound_arrivals()
            .expect("and each flow set has its own to issue");

        let deliver = |flows: &SessionRealtimeFlows, bytes: &'static [u8]| {
            let delivery = flows
                .enqueued_delivery_for_test(
                    &name,
                    RealtimeRecvUnit {
                        timestamp: 90_000,
                        marker: false,
                        data: Bytes::from_static(bytes),
                    },
                )
                .expect("the elastic flow reserves and enqueues one unit");
            assert!(flows.deliver_inbound(delivery));
        };

        // Both positives first. Without them every negative below would be
        // satisfied by a reader that had simply stopped receiving anything.
        deliver(&second, b"second");
        assert_eq!(
            from_second.next().await.map(|(_, unit)| unit.data),
            Some(Bytes::from_static(b"second")),
            "a reader receives what was delivered on its own session"
        );
        deliver(&first, b"first");
        assert_eq!(
            from_first.next().await.map(|(_, unit)| unit.data),
            Some(Bytes::from_static(b"first")),
            "and each session's units reach only its own reader — the name is \
             the same on both, so a name-routed delivery would have crossed"
        );

        // The replacement shape, which is the one the race actually took: the
        // session that issued the reader is gone, a replacement holds the same
        // name, and it is delivering on it.
        drop(second);
        let mut replacement = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        open_shared(&mut replacement);
        deliver(&replacement, b"replacement");
        assert!(
            from_second.next().await.is_none(),
            "a reader that outlived its session is ended, not re-pointed at the \
             session that replaced it"
        );

        // Non-vacuity for the replacement: it really is delivering, so the
        // `None` above is the retired reader and not a set with nothing in it.
        let from_replacement = replacement
            .inbound_arrivals()
            .expect("the replacement issues its own reader");
        assert_eq!(
            from_replacement.next().await.map(|(_, unit)| unit.data),
            Some(Bytes::from_static(b"replacement"))
        );
    }

    /// A negotiated inbound track attaches only to a flow this side already
    /// opened, and only if it is the shape that flow was opened for.
    ///
    /// The discriminating control for peer-unilateral open. A peer cannot mint
    /// a flow here; the most it can do is name one we created. The three
    /// negatives are the ways it might try: an identity we never bound, an
    /// identity we bound for a different codec family, and an identity whose
    /// flow has since closed.
    ///
    /// The positive half matters just as much — a table that refused
    /// everything would pass all three negatives and deliver no media at all.
    ///
    /// The fixture uses **minted tokens**, which is the point rather than a
    /// detail. The identities here are `Arc` allocations this side created; a
    /// peer cannot produce one, cannot name one, and nothing about one appears
    /// in SDP. The "identity we never bound" negative is therefore literally
    /// unforgeable rather than merely unguessable — which is what replacing the
    /// old MID-string key bought.
    #[test]
    fn v4_macro1_a_a_negotiated_track_attaches_only_to_a_flow_we_opened() {
        let bindings = RealtimeInboundBindings::default();
        // Minted, not hand-built: a binding retains its label for as long as it
        // exists, so the copy it holds is one the session paid for.
        let (registry, _resources) = control_label_registry();
        let label = RealtimeFlowLabel::mint(control_name(b"bound"), &registry)
            .expect("the elastic control grant admits one label");
        let encoding = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/H264", 90_000, 0)
            .expect("the fixture encoding is one a flow can carry");
        // Cloned into the binding, exactly as `bind_inbound` clones from the
        // flows map's own key: the binding and the releasing scope name the
        // same record and the same lease, not two copies of the bytes.
        let binding = RealtimeInboundBinding::new(label.clone(), encoding, RealtimeFraming::AnnexB);

        // The token for the transceiver this side negotiated, and one for a
        // transceiver it never did. Funded from a real scope, because an
        // identity is a leased allocation and a fixture that skipped the lease
        // would be exercising a constructor production does not have.
        let (_identity_candidate, _identity_lifetime, identity_scope) =
            super::super::identity_test_scope(2, 0);
        let ours = RealtimeTrackIdentity::mint_for_test(&identity_scope);
        let never_offered = RealtimeTrackIdentity::mint_for_test(&identity_scope);

        // Detached handles, and honestly so: what this control exercises is the
        // demux decision, which never upgrades the port. That one flow feeds one
        // flow — and holds no lease of its own — is what the capacity control
        // below proves, on a real registry.
        let (port, end) = detached_attachment_handles(&registry);
        // Real per-entry funding, from the same registry: a binding occupies a
        // node it paid for, and the refused calls below release theirs rather
        // than retaining anything.
        let entry_record = || {
            registry
                .acquire_queue_record::<RealtimeInboundEntry>()
                .expect("the elastic control grant funds one binding entry")
        };

        assert!(
            !bindings.bind(
                Arc::clone(&ours),
                RealtimeDirection::Outbound,
                binding.clone(),
                port.clone(),
                Arc::clone(&end),
                entry_record(),
            ),
            "nothing outbound is attachable, so an outbound entry is refused \
             rather than stored where it would later look deliberate"
        );
        assert!(bindings.bind(
            Arc::clone(&ours),
            RealtimeDirection::Inbound,
            binding.clone(),
            port.clone(),
            Arc::clone(&end),
            entry_record(),
        ));
        assert!(
            !bindings.bind(
                Arc::clone(&ours),
                RealtimeDirection::Inbound,
                binding,
                port,
                end,
                entry_record(),
            ),
            "a second binding on one token would make attachment ambiguous, \
             and taking the newer one would move a live flow's media"
        );

        // Positive: the exact token we bound, in the exact shape we bound it.
        assert_eq!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
                .map(|admitted| admitted.label),
            Some(label.clone()),
            "the track this side negotiated reaches the flow it was negotiated for"
        );

        // Negative: a token we never bound. This is the peer-mint case, and
        // with a minted token it is unforgeable rather than merely unguessed.
        assert!(
            bindings
                .admit(
                    &never_offered,
                    WebRtcRtpKind::Video,
                    "video/h264",
                    90_000,
                    0
                )
                .is_none(),
            "a track on a transceiver we never negotiated has nothing to attach to"
        );

        // Negative: our token, a shape we did not open the flow for.
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Audio, "video/h264", 90_000, 0)
                .is_none(),
            "a kind we did not open for is not this flow's media"
        );
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/VP8", 90_000, 0)
                .is_none(),
            "nor is a codec family we did not open for — attaching it would \
             feed a decoder configured for something else"
        );

        // Negative: the flow closed, so the binding is gone with it.
        bindings.release(&label);
        assert!(
            bindings
                .admit(&ours, WebRtcRtpKind::Video, "video/h264", 90_000, 0)
                .is_none(),
            "a closed flow's negotiated token stops admitting anything"
        );
    }

    /// A binding fixture's two runtime handles, pointing at no flow.
    ///
    /// Only for controls that exercise the admission decision itself. A handle
    /// that upgrades to nothing is exactly what a pump would be left holding
    /// after its flow closed, so it is not a weaker fixture — it is the closed
    /// case, and admission is indifferent to it by design.
    /// The wake is minted against the caller's registry rather than built bare,
    /// because a wake is a funded block everywhere else and a fixture that could
    /// make an unfunded one would be exercising a shape production cannot
    /// produce.
    fn detached_attachment_handles(
        registry: &RealtimeFlowRegistry,
    ) -> (RealtimeFlowPortHandle, Arc<LeasedWake>) {
        (
            RealtimeFlowPortHandle::detached(),
            LeasedWake::mint(registry).expect("the elastic control grant funds one wake"),
        )
    }

    /// One registration of the deployed H.264 shape.
    fn h264_variant(payload_type: u8, fmtp: &str) -> RealtimeCodec {
        RealtimeCodec {
            kind: WebRtcRtpKind::Video,
            payload_type,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
            fmtp: fmtp.to_string(),
            framing: RealtimeFraming::AnnexB,
            rtcp_feedback: Vec::new(),
        }
    }

    /// A flow names an encoding *family*, and every payload variant of that
    /// family survives to the media engine.
    ///
    /// The discriminating case, because resolving the four fields to one
    /// registration is both plausible and silent: the offer advertises all
    /// five variants, the answerer picks one, and picking on our side would
    /// send RTP with a payload type the far end is not decoding. That does not
    /// surface as a refusal — it surfaces as black video.
    #[test]
    fn v4_macro1_a_an_encoding_names_a_family_not_a_payload_type() {
        let profile = RealtimeProfile::new(vec![
            h264_variant(102, "packetization-mode=1;profile-level-id=42001f"),
            h264_variant(127, "packetization-mode=0;profile-level-id=42001f"),
            h264_variant(125, "packetization-mode=1;profile-level-id=42e01f"),
            h264_variant(108, "packetization-mode=0;profile-level-id=42e01f"),
            h264_variant(123, "packetization-mode=1;profile-level-id=640032"),
        ])
        .expect("the deployed five-variant H.264 profile is a shape core can act on");

        assert_eq!(
            profile.codecs().len(),
            5,
            "every variant reaches the media engine; registering fewer would \
             silently narrow what a peer is allowed to choose"
        );

        let named = RealtimeEncoding::new(WebRtcRtpKind::Video, "video/h264", 90_000, 0)
            .expect("an encoding naming that family");
        assert_eq!(
            profile.admits_encoding(&named),
            Some(RealtimeFraming::AnnexB),
            "the family resolves — case-insensitively, because SDP is — to the \
             one framing its variants agree on, with no payload type chosen"
        );

        let unregistered = RealtimeEncoding::new(WebRtcRtpKind::Audio, "audio/opus", 48_000, 2)
            .expect("an encoding naming a family this profile never registered");
        assert_eq!(
            profile.admits_encoding(&unregistered),
            None,
            "and a family nothing registered is refused, which is the only \
             judgement core makes about a codec"
        );
    }

    /// The profile refuses what it cannot act on, and nothing else.
    #[test]
    fn v4_macro1_a_profile_refuses_only_the_shapes_it_cannot_act_on() {
        assert_eq!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(102, "b")]),
            Err(RealtimeProfileError::DuplicatePayloadType { payload_type: 102 }),
            "two registrations on one payload type make negotiation ambiguous"
        );

        let mut disagrees = h264_variant(127, "b");
        disagrees.framing = RealtimeFraming::Whole;
        assert_eq!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), disagrees]),
            Err(RealtimeProfileError::FamilyFramingConflict {
                mime: "video/H264".to_string(),
                clock_rate: 90_000,
            }),
            "a flow opens against the family before a payload type exists, so a \
             family whose variants disagree on framing has no framer to install"
        );

        assert!(
            RealtimeProfile::new(vec![h264_variant(102, "a"), h264_variant(127, "b")]).is_ok(),
            "but two variants of one family are exactly the deployed shape and \
             must not be refused"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    async fn v4_opaque_local_outbound_delivery_refused_matching_inbound_accepted() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;

        let outbound = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"opaque-outbound",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    64,
                ),
            )
            .expect("the local outbound record is admitted by the real provider");
        let outbound_coordinate = flows
            .opaque_coordinate(&outbound)
            .expect("the outbound record retains its wire coordinate");
        assert!(
            !flows.deliver_opaque(
                outbound_coordinate,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                Bytes::from_static(b"must-not-arrive"),
            ),
            "a local outbound record cannot be used as an inbound arrival target"
        );

        let inbound_coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: outbound_coordinate.flow_id + 1,
            generation: 1,
        };
        let inbound = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"opaque-inbound",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    64,
                ),
                inbound_coordinate,
                None,
            )
            .expect("the matching remote-owned inbound record is admitted");
        flows
            .accept_opaque(
                &session,
                Some(&incarnation),
                &inbound,
                inbound_coordinate,
                mode,
                64,
            )
            .expect("the exact inbound record becomes ready");
        let reader = flows
            .inbound_arrivals()
            .expect("the session has one funded inbound reader");
        assert!(flows.deliver_opaque(
            inbound_coordinate,
            crate::realtime::RealtimeFlowDirection::Outbound,
            mode,
            Bytes::from_static(b"accepted"),
        ));
        let arrival = reader
            .next_opaque()
            .await
            .expect("the provider returns the funded opaque arrival")
            .expect("the inbound stream is still live");
        assert_eq!(arrival.bytes, Bytes::from_static(b"accepted"));
        assert!(arrival.has_custody(), "dequeue retained provider custody");
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_reciprocal_claim_is_single_exact_record_operation() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: 41,
            generation: 1,
        };
        let spec = control_opaque_spec(
            b"reciprocal",
            RealtimeDirection::Inbound,
            crate::realtime::RealtimeFlowDirection::Outbound,
            mode,
            32,
        );
        let name = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                spec.clone(),
                coordinate,
                None,
            )
            .expect("the peer Open creates one transport-only record");
        assert_eq!(flows.opaque_is_claimed(&name), Some(false));

        let (claimed_name, claimed_existing) = flows
            .prepare_or_claim_opaque(&session, Some(&incarnation), spec.clone())
            .expect("the exact local request claims the existing record");
        assert!(claimed_existing);
        assert_eq!(claimed_name, name);
        assert_eq!(flows.opaque_is_claimed(&name), Some(true));
        assert_eq!(flows.opaque_coordinate(&name), Some(coordinate));
        assert_eq!(
            flows.opaque_opener_direction(&name),
            Some(crate::realtime::RealtimeFlowDirection::Outbound)
        );
        assert_eq!(
            flows.prepare_or_claim_opaque(&session, Some(&incarnation), spec),
            Err(RealtimeFlowError::FlowRefused),
            "a second local claimant cannot mint another handle"
        );

        let mismatched = control_opaque_spec(
            b"reciprocal",
            RealtimeDirection::Inbound,
            crate::realtime::RealtimeFlowDirection::Outbound,
            crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits: 0 },
            32,
        );
        assert_eq!(
            flows.prepare_or_claim_opaque(&session, Some(&incarnation), mismatched),
            Err(RealtimeFlowError::FlowRefused),
            "a mode mismatch cannot inherit the predecessor claim"
        );
        assert_eq!(flows.opaque_coordinate(&name), Some(coordinate));
        assert_eq!(flows.opaque_is_claimed(&name), Some(true));

        assert_eq!(
            flows.open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"other-label",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    32,
                ),
                coordinate,
                None,
            ),
            Err(RealtimeFlowError::FlowRefused),
            "the same coordinate and opener direction cannot alias another label"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_change_refuses_queued_predecessor_without_discarding_it() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"change-queue",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    crate::realtime::OpaqueFlowMode::ReliableOrdered,
                    32,
                ),
            )
            .expect("the outbound opaque flow is ready");
        let predecessor = flows.opaque_coordinate(&name).expect("coordinate exists");
        flows
            .send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(b"accepted-before-change"),
            )
            .expect("the real flow queue admits the predecessor unit");
        assert_eq!(
            flows.change_opaque(
                &session,
                Some(&incarnation),
                &name,
                predecessor,
                crate::protocol::ApplicationFlowCoordinate {
                    flow_id: predecessor.flow_id,
                    generation: predecessor.generation + 1,
                },
                32,
            ),
            Err(RealtimeFlowError::FlowRefused),
            "Change cannot silently invalidate accepted reliable queue work"
        );
        assert_eq!(flows.opaque_coordinate(&name), Some(predecessor));
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_change_prepare_commit_rollback_is_exact_and_blocks_send() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"change-transaction",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    32,
                ),
            )
            .expect("the exact outbound record is ready");
        let previous = flows.opaque_coordinate(&name).expect("coordinate exists");
        let next = crate::protocol::ApplicationFlowCoordinate {
            flow_id: previous.flow_id,
            generation: previous.generation + 1,
        };
        let mut staged = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                16,
            )
            .expect("a quiescent exact record can stage Change");
        assert_eq!(flows.opaque_coordinate(&name), Some(previous));
        assert_eq!(
            flows.send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(b"blocked-while-staged"),
            ),
            Err(RealtimeFlowError::FlowRefused),
            "a staged Change cannot admit predecessor-generation sends"
        );
        flows
            .rollback_opaque_change(&session, Some(&incarnation), &name, &mut staged)
            .expect("exact refusal/cancel restores the predecessor");
        assert_eq!(flows.opaque_coordinate(&name), Some(previous));
        // Completion transfers the marker funding into the terminal token;
        // release that caller-owned token before staging the next operation.
        drop(staged);

        let mut committed = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                16,
            )
            .expect("the restored exact record can be prepared again");
        assert_eq!(
            flows.commit_opaque_change(&session, Some(&incarnation), &name, &mut committed),
            Err(RealtimeFlowError::FlowRefused),
            "a staged Change cannot commit before the authenticated Accept"
        );
        flows
            .confirm_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                16,
            )
            .expect("the exact echoed Accept confirms the staged Change");
        flows
            .commit_opaque_change(&session, Some(&incarnation), &name, &mut committed)
            .expect("the exact echoed Accept commits the staged Change");
        assert_eq!(flows.opaque_coordinate(&name), Some(next));
        assert_eq!(
            flows.rollback_opaque_change(&session, Some(&incarnation), &name, &mut committed),
            Err(RealtimeFlowError::FlowRefused),
            "a completed token cannot roll back a newer record state"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_change_marker_funding_survives_flow_set_and_token_drop_orders() {
        let marker_claim = crate::resource::FiniteResourceProvider::reservation_charge_for_test(
            RealtimeFlowRegistry::opaque_change_claim().expect("the marker claim is representable"),
        )
        .expect("the marker reservation is representable");

        // First ordering: the promoted flow set is retired while the caller's
        // Change token is still alive.  The token must retain the marker's
        // exact provider claim after the record and set have gone away.
        let (registry, resources) = control_label_registry();
        let empty = resources.in_use();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"change-set-first",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    crate::realtime::OpaqueFlowMode::ReliableOrdered,
                    32,
                ),
            )
            .expect("the exact opaque record is ready");
        let previous = flows.opaque_coordinate(&name).expect("coordinate exists");
        let next = crate::protocol::ApplicationFlowCoordinate {
            flow_id: previous.flow_id,
            generation: previous.generation + 1,
        };
        let change = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                crate::realtime::OpaqueFlowMode::ReliableOrdered,
                16,
            )
            .expect("the provider stages one funded Change");
        drop(flows);
        assert_eq!(
            resources.in_use(),
            empty
                .checked_add(marker_claim)
                .expect("the marker and control baseline compose"),
            "retiring the whole flow set leaves exactly the token-owned marker claim"
        );
        drop(change);
        assert_eq!(
            resources.in_use(),
            empty,
            "the final Change-token drop releases the marker and nothing else"
        );

        // Second ordering: dropping the token first cancels the record-owned
        // marker but must not release it while the flow record still retains
        // the shared Arc.  Closing that exact record then returns the set to
        // its pre-open baseline.
        let (registry, resources) = control_label_registry();
        let empty = resources.in_use();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"change-token-first",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    crate::realtime::OpaqueFlowMode::ReliableOrdered,
                    32,
                ),
            )
            .expect("the exact opaque record is ready");
        let previous = flows.opaque_coordinate(&name).expect("coordinate exists");
        let next = crate::protocol::ApplicationFlowCoordinate {
            flow_id: previous.flow_id,
            generation: previous.generation + 1,
        };
        let before_change = resources.in_use();
        let change = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                crate::realtime::OpaqueFlowMode::ReliableOrdered,
                16,
            )
            .expect("the provider stages one funded Change");
        assert_eq!(
            resources.in_use(),
            before_change
                .checked_add(marker_claim)
                .expect("the Change marker composes with the live flow"),
            "staging charges the marker before its shared Arc is published"
        );
        drop(change);
        assert_eq!(
            resources.in_use(),
            before_change
                .checked_add(marker_claim)
                .expect("the record still owns the marker claim"),
            "canceling the token leaves the canceled marker funded by the record"
        );
        let _remains = flows
            .close(&session, Some(&incarnation), &name)
            .expect("the canceled exact record can close");
        assert_eq!(
            resources.in_use(),
            empty,
            "closing the canceled record releases the marker and flow claims"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_inbound_change_confirms_and_commits_same_record() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: 9,
            generation: 1,
        };
        let name = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"inbound-change",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    32,
                ),
                coordinate,
                None,
            )
            .expect("the exact inbound transport record is created");
        flows
            .accept_opaque(&session, Some(&incarnation), &name, coordinate, mode, 32)
            .expect("the inbound record becomes ready after its Open");
        let next = crate::protocol::ApplicationFlowCoordinate {
            flow_id: coordinate.flow_id,
            generation: 2,
        };
        let mut change = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                coordinate,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                16,
            )
            .expect("an inbound record can stage a quiescent Change");
        flows
            .confirm_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                coordinate,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                16,
            )
            .expect("the inbound Accept confirms the exact staged record");
        flows
            .commit_opaque_change(&session, Some(&incarnation), &name, &mut change)
            .expect("the inbound Change commits without an outbound queue");
        assert_eq!(flows.opaque_coordinate(&name), Some(next));
    }

    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    async fn v4_opaque_inbound_change_commit_rechecks_arrival_interleaving() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let previous = crate::protocol::ApplicationFlowCoordinate {
            flow_id: 17,
            generation: 1,
        };
        let name = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"inbound-change-arrival",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    64,
                ),
                previous,
                None,
            )
            .expect("the exact inbound transport record is admitted");
        flows
            .accept_opaque(&session, Some(&incarnation), &name, previous, mode, 64)
            .expect("the inbound record is ready before Change staging");
        let next = crate::protocol::ApplicationFlowCoordinate {
            flow_id: previous.flow_id,
            generation: previous.generation + 1,
        };
        let mut change = flows
            .prepare_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                32,
            )
            .expect("the inbound record stages while its arrival queue is empty");
        flows
            .confirm_opaque_change(
                &session,
                Some(&incarnation),
                &name,
                previous,
                next,
                crate::realtime::RealtimeFlowDirection::Outbound,
                mode,
                32,
            )
            .expect("the exact staged Change is confirmed before the interleaving");
        let reader = flows
            .inbound_arrivals()
            .expect("the session has one tagged inbound reader");
        assert!(flows.deliver_opaque(
            previous,
            crate::realtime::RealtimeFlowDirection::Outbound,
            mode,
            Bytes::from_static(b"arrived-after-prepare"),
        ));
        assert_eq!(
            flows.commit_opaque_change(&session, Some(&incarnation), &name, &mut change),
            Err(RealtimeFlowError::FlowRefused),
            "a predecessor arrival in the prepare-to-commit window blocks mutation"
        );
        assert_eq!(
            flows.opaque_coordinate(&name),
            Some(previous),
            "the refused terminal commit preserves the predecessor coordinate"
        );
        match reader
            .next_arrival()
            .await
            .expect("the refused Change did not discard the predecessor arrival")
            .into_provider_event()
        {
            crate::transport::webrtc::RealtimeInboundArrival::Opaque(arrival) => {
                assert_eq!(arrival.bytes, Bytes::from_static(b"arrived-after-prepare"));
                assert_eq!(arrival.label, b"inbound-change-arrival".to_vec());
            }
            crate::transport::webrtc::RealtimeInboundArrival::Rtp(_) => {
                panic!("an opaque predecessor arrival changed kind")
            }
        }
        flows
            .commit_opaque_change(&session, Some(&incarnation), &name, &mut change)
            .expect("draining the predecessor arrival leaves the exact Change quiescent");
        assert_eq!(
            flows.opaque_coordinate(&name),
            Some(next),
            "the same confirmed Change commits after its predecessor is drained"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_actual_pump_terminal_failure_refuses_next_send() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"pump-terminal",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    64,
                ),
            )
            .expect("the exact outbound record is ready");
        flows
            .send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(b"held-until-native-terminal"),
            )
            .expect("the real flow queue admits the first unit");
        let (pump, _retired) = flows
            .attach_opaque_pump(&session, Some(&incarnation), &name)
            .expect("the flow owns one funded production pump");
        let unit = match pump.next() {
            OpaquePumpStep::Unit(unit) => unit,
            _ => panic!("the production pump dequeues the admitted unit"),
        };
        assert!(!pump.native_write_finished(false));
        drop(unit);
        assert_eq!(
            flows.send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(b"must-refuse-after-failed-pump"),
            ),
            Err(RealtimeFlowError::FlowRefused),
            "a failed production pump cannot accept work behind its terminal error"
        );
        assert_eq!(flows.opaque_coordinate(&name).unwrap().generation, 1);
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_failed_pump_keeps_detached_unit_funded_through_set_drop() {
        let (registry, resources) = control_label_registry();
        let empty = resources.in_use();
        let held_body = b"held-through-set-retirement";
        let retained_claim = [
            RealtimeFlowRegistry::output_claim(held_body.len())
                .expect("the detached payload claim is representable"),
            RealtimeFlowRegistry::queue_node_claim::<QueuedUnit<OpaqueSendUnit>>()
                .expect("the detached queue-node claim is representable"),
            RealtimeFlowRegistry::flow_root_claim(std::mem::size_of::<queue::InFlightCounter>())
                .expect("the detached in-flight counter claim is representable"),
        ]
        .into_iter()
        .map(|claim| {
            crate::resource::FiniteResourceProvider::reservation_charge_for_test(claim)
                .expect("the detached claim is reservable")
        })
        .try_fold(crate::resource::ResourceClaim::ZERO, |total, claim| {
            total.checked_add(claim)
        })
        .expect("the detached claims compose without arithmetic overflow");
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let name = flows
            .open_opaque(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"pump-held-set-drop",
                    RealtimeDirection::Outbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    crate::realtime::OpaqueFlowMode::ReliableOrdered,
                    64,
                ),
            )
            .expect("the exact outbound opaque flow is ready");
        flows
            .send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(held_body),
            )
            .expect("the provider admits the first unit");
        let (pump, retired) = flows
            .attach_opaque_pump(&session, Some(&incarnation), &name)
            .expect("the flow owns one production opaque pump");
        let unit = match pump.next() {
            OpaquePumpStep::Unit(unit) => unit,
            _ => panic!("the production pump detaches the admitted unit"),
        };
        let with_unit = resources.in_use();
        assert!(
            with_unit != empty,
            "a detached unit keeps its queue-node, payload, and in-flight claims"
        );
        assert!(!pump.native_write_finished(false));
        assert_eq!(
            flows.send_opaque(
                &session,
                Some(&incarnation),
                &name,
                Bytes::from_static(b"must-not-follow-terminal-failure"),
            ),
            Err(RealtimeFlowError::FlowRefused),
            "a terminal pump failure remains a sticky admission refusal"
        );

        // The actual flow set and pump are gone before the detached unit.  Its
        // queue entry and shared in-flight counter must still pay for the
        // outstanding native handoff until the unit reaches its terminal drop.
        drop(pump);
        drop(flows);
        assert_eq!(
            resources.in_use(),
            empty
                .checked_add(retained_claim)
                .expect("the empty baseline and detached claims compose"),
            "set retirement leaves exactly the detached payload, node, and in-flight claims"
        );
        drop(unit);
        drop(retired);
        assert_eq!(
            resources.in_use(),
            empty,
            "the final detached-unit drop releases every provider claim"
        );
    }

    #[cfg(feature = "transport-lab")]
    #[tokio::test]
    async fn v4_opaque_mixed_head_refusal_then_tagged_drain_preserves_order_and_custody() {
        let (registry, _resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(
            Arc::clone(&registry),
            Some(leased_control_profile(&registry)),
        );
        let mode = crate::realtime::OpaqueFlowMode::ReliableOrdered;
        let opaque_coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: 51,
            generation: 1,
        };
        let opaque = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"mixed-opaque",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    mode,
                    64,
                ),
                opaque_coordinate,
                None,
            )
            .expect("the opaque inbound record is admitted");
        flows
            .accept_opaque(
                &session,
                Some(&incarnation),
                &opaque,
                opaque_coordinate,
                mode,
                64,
            )
            .expect("the opaque record is ready");
        let rtp = flows
            .open(
                &session,
                Some(&incarnation),
                RealtimeFlowSpec {
                    direction: RealtimeDirection::Inbound,
                    encoding: control_encoding(),
                    name: control_name(b"mixed-rtp"),
                },
            )
            .expect("the RTP inbound record is admitted");
        let reader = flows
            .inbound_arrivals()
            .expect("the mixed session has one tagged reader");
        assert!(flows.deliver_opaque(
            opaque_coordinate,
            crate::realtime::RealtimeFlowDirection::Outbound,
            mode,
            Bytes::from_static(b"opaque-first"),
        ));
        let delivery = flows
            .accounted_delivery_for_test(
                &rtp,
                RealtimeRecvUnit {
                    timestamp: 7,
                    marker: true,
                    data: Bytes::from_static(b"rtp-second"),
                },
            )
            .expect("the RTP payload is reserved through the real flow port");
        assert!(flows.deliver_inbound(delivery));

        assert!(
            matches!(
                reader.next_rtp().await,
                Err(crate::realtime::RealtimeRefusal::FlowRefused)
            ),
            "typed mismatch refuses without consuming the opaque head"
        );
        match reader
            .next_arrival()
            .await
            .expect("the opaque head remains available")
            .into_provider_event()
        {
            crate::transport::webrtc::RealtimeInboundArrival::Opaque(arrival) => {
                assert_eq!(arrival.bytes, Bytes::from_static(b"opaque-first"));
                assert!(arrival.has_custody());
            }
            crate::transport::webrtc::RealtimeInboundArrival::Rtp(_) => {
                panic!("the tagged reader reordered the mixed queue")
            }
        }
        match reader
            .next_arrival()
            .await
            .expect("the RTP item follows the opaque item")
            .into_provider_event()
        {
            crate::transport::webrtc::RealtimeInboundArrival::Rtp(arrival) => {
                assert_eq!(arrival.unit.data, Bytes::from_static(b"rtp-second"));
            }
            crate::transport::webrtc::RealtimeInboundArrival::Opaque(_) => {
                panic!("the tagged reader duplicated or reordered the RTP item")
            }
        }
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_native_tail_witness_keeps_quiescence_false_until_terminal_drop() {
        let (registry, _resources) = control_label_registry();
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        assert!(flows.is_quiescent());
        let tail = flows
            .acquire_native_tail()
            .expect("the finite provider funds one native retirement tail");
        assert!(
            !flows.is_quiescent(),
            "map and arrival emptiness cannot hide an outstanding native task"
        );
        drop(tail);
        assert!(flows.is_quiescent());
    }

    #[cfg(feature = "transport-lab")]
    #[test]
    fn v4_opaque_wrapper_pressure_refuses_before_queueing_or_dequeue() {
        let (registry, resources) = control_label_registry();
        let incarnation = crate::connector::ConnectorIncarnation::new();
        let session = ControlSession {
            incarnation: Arc::clone(&incarnation),
        };
        let mut flows = SessionRealtimeFlows::new(Arc::clone(&registry), None);
        let coordinate = crate::protocol::ApplicationFlowCoordinate {
            flow_id: 61,
            generation: 1,
        };
        let name = flows
            .open_opaque_with_coordinate(
                &session,
                Some(&incarnation),
                control_opaque_spec(
                    b"wrapper-pressure",
                    RealtimeDirection::Inbound,
                    crate::realtime::RealtimeFlowDirection::Outbound,
                    crate::realtime::OpaqueFlowMode::ReliableOrdered,
                    64,
                ),
                coordinate,
                None,
            )
            .expect("the exact inbound record is admitted before pressure is applied");
        flows
            .accept_opaque(
                &session,
                Some(&incarnation),
                &name,
                coordinate,
                crate::realtime::OpaqueFlowMode::ReliableOrdered,
                64,
            )
            .expect("the exact inbound record is ready");

        let wrapper = RealtimeFlowRegistry::boxed_claim::<WebRtcInboundCustody>()
            .expect("the custody wrapper claim is representable");
        let remaining = control_label_grant()
            .checked_sub(resources.in_use())
            .expect("the open remains within the finite control grant");
        let counters = u64::try_from(2 * std::mem::size_of::<usize>())
            .expect("the Arc counter pair is representable");
        let filler_bytes = remaining
            .amount(crate::resource::ResourceClass::AccountedMemoryBytes)
            .checked_sub(wrapper.amount(crate::resource::ResourceClass::AccountedMemoryBytes))
            .and_then(|bytes| bytes.checked_sub(counters))
            .and_then(|bytes| bytes.checked_add(1))
            .and_then(|bytes| usize::try_from(bytes).ok())
            .expect("the grant leaves enough exact headroom to make the wrapper refuse");
        let filler = registry
            .acquire_flow_root(filler_bytes)
            .expect("the filler consumes the exact pre-wrapper byte headroom");
        let at_pressure = resources.in_use();
        assert!(
            !flows.deliver_opaque(
                coordinate,
                crate::realtime::RealtimeFlowDirection::Outbound,
                crate::realtime::OpaqueFlowMode::ReliableOrdered,
                Bytes::from_static(b"wrapper-must-refuse"),
            ),
            "custody wrapper pressure refuses before payload or queue admission"
        );
        assert_eq!(
            resources.in_use(),
            at_pressure,
            "the refused wrapper does not dequeue, retain bytes, or alter the queue"
        );
        drop(filler);
    }
}
