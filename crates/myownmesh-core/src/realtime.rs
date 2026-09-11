//! The **basal** realtime vocabulary: what is true of any flow, on any provider.
//!
//! A basal flow is a labelled, directed stream of opaque byte units inside a
//! session. Direction, refusal, and the lease on a session's inbound stream
//! need no clock, no codec and no transport to mean something.
//!
//! A flow ending is not among them, and that is a contract rather than an
//! omission. A close is the result of the local operation that performed it,
//! returned to that caller; a session ending is the inbound stream ending. So
//! there is nothing left for a lifecycle event to say that its reader was not
//! already told, and an event naming only a reusable name could not say it
//! unambiguously anyway.
//!
//! Anything that does — media kind, MIME, clock rate, channels, pacing
//! duration, RTP timestamp, marker — belongs to the provider that negotiates
//! the clock making it readable. [`crate::transport::webrtc`] declares those,
//! and they cross at the `*_webrtc_realtime` methods on
//! [`crate::JoinedNetwork`].
//!
//! The invariant here is about vocabulary, not dependencies: nothing public in
//! this module exposes or interprets provider metadata, and nothing here
//! converts between the two vocabularies. The stream leases do hold a
//! provider's reader in a private field — that is the generic claim-once
//! lifetime mechanism, carrying no media meaning of its own.
//!
//! There is therefore no configuration channel here: no opaque blob, no
//! key-value map, no purpose or authority string. A provider declares its types
//! rather than describing itself at runtime, and the method carrying them says
//! whose they are in its name — so nothing is left to validate and nothing in a
//! payload can name an authority.
//!
//! A label here is a bounded opaque name: 1..=255 bytes the application chose,
//! carried verbatim and never interpreted. Bounded because that is what the
//! encoded frame can spell, opaque because nothing on this side reads it, and
//! session-scoped because it means something only against the flow set that
//! accepted it.
//!
//! Publishing the connector's leased label, flow handles or ports would invite
//! reading one as a handle that grants something. What crosses instead is a
//! copy of the bytes, and it grants nothing: every operation resolves a live
//! session first, and the copy owns no part of the session's accounting for the
//! name it spells.

use serde::{Deserialize, Serialize};

/// The largest application-owned opaque unit that can fit in one application
/// flow frame.  The value is a wire-representation limit, not an owner policy
/// or a queue ceiling: an application may negotiate any smaller positive
/// value, while the provider still accounts each actual body through its
/// existing resource leases.
pub const MAX_OPAQUE_FLOW_UNIT_BYTES: usize = 65_535 - 28;

/// Alias used by the application-flow wire adapter for the same fixed frame
/// body ceiling. It is an alias, not another tunable limit.
pub const MAX_APPLICATION_FLOW_BODY_BYTES: usize = MAX_OPAQUE_FLOW_UNIT_BYTES;

/// Reliability semantics of one application-owned opaque flow.
///
/// These are the only native lane distinctions the WebRTC provider needs.  A
/// provider may retain one persistent lane for each supported variant; logical
/// flows are multiplexed on those lanes and do not create a new native channel
/// per open.  The enum carries no codec identity, digest, queue capacity or
/// authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OpaqueFlowMode {
    /// Ordered, fully reliable delivery.
    ReliableOrdered,
    /// Unordered delivery with a bounded retransmit count.
    PartialUnordered { max_retransmits: u16 },
}

/// Provider-neutral request for one logical opaque byte flow.
///
/// `label` is session-scoped application data and is bounded by the existing
/// flow-name representation. `max_unit_bytes` is a negotiated per-unit upper
/// bound and must not exceed [`MAX_OPAQUE_FLOW_UNIT_BYTES`]. It is not a second
/// resource budget: flow count, queue depth and retained bytes are admitted by
/// the provider's existing leases.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OpaqueFlowOpen {
    pub label: Vec<u8>,
    pub direction: RealtimeFlowDirection,
    pub mode: OpaqueFlowMode,
    pub max_unit_bytes: u32,
}

impl OpaqueFlowOpen {
    /// Construct a well-formed request, refusing invalid label or unit bounds
    /// before session lookup or any provider allocation.
    pub fn new(
        label: Vec<u8>,
        direction: RealtimeFlowDirection,
        mode: OpaqueFlowMode,
        max_unit_bytes: u32,
    ) -> Option<Self> {
        if label.is_empty()
            || label.len() > MAX_REALTIME_FLOW_LABEL_BYTES
            || max_unit_bytes == 0
            || usize::try_from(max_unit_bytes).ok()? > MAX_OPAQUE_FLOW_UNIT_BYTES
        {
            return None;
        }
        Some(Self {
            label,
            direction,
            mode,
            max_unit_bytes,
        })
    }

    /// Whether this request satisfies only the representation constraints.
    /// Admission and resource pressure remain provider decisions.
    pub fn is_well_formed(&self) -> bool {
        !self.label.is_empty()
            && self.label.len() <= MAX_REALTIME_FLOW_LABEL_BYTES
            && self.max_unit_bytes > 0
            && usize::try_from(self.max_unit_bytes)
                .is_ok_and(|bytes| bytes <= MAX_OPAQUE_FLOW_UNIT_BYTES)
    }
}

/// Private custody retained by an inbound opaque arrival until the application
/// drops or consumes that arrival. Providers implement this marker with their
/// real payload/queue leases; no provider handle or authority is exposed.
pub(crate) trait OpaqueInboundCustody: Send {}

/// One opaque unit taken from a session's shared inbound stream.
///
/// The bytes and label are the application view, while `custody` keeps the
/// provider's transferred payload (and, where supported, queue-record) claim
/// alive for the same move-only arrival. No codec parser is involved.
pub struct OpaqueInboundArrival {
    pub label: Vec<u8>,
    pub bytes: bytes::Bytes,
    pub(crate) _custody: Option<Box<dyn OpaqueInboundCustody>>,
}

impl std::fmt::Debug for OpaqueInboundArrival {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("OpaqueInboundArrival")
            .field("label", &self.label)
            .field("bytes", &self.bytes)
            .finish_non_exhaustive()
    }
}

impl PartialEq for OpaqueInboundArrival {
    fn eq(&self, other: &Self) -> bool {
        self.label == other.label && self.bytes == other.bytes
    }
}

impl Eq for OpaqueInboundArrival {}

impl OpaqueInboundArrival {
    /// Whether provider custody is still attached to this arrival.
    ///
    /// This is crate-visible observation for adapters/tests; applications own
    /// custody structurally by holding the arrival and need no lease API.
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn has_custody(&self) -> bool {
        self._custody.is_some()
    }
}

/// The largest label the encoded frame can carry.
///
/// **A representation fact, not a policy ceiling and not tunable.** The frame's
/// label is prefixed by one length byte, so this is the width of that field and
/// nothing more. It bounds one label's size and says nothing about how many
/// labels may exist at once — that is admission's question, and admission
/// answers it with leases.
///
/// It lives in the basal vocabulary because the daemon, the provider edge and
/// the connector all have to agree on it, and three copies of `255` would agree
/// until one of them was changed. Anything that speaks the wire refers to this
/// one constant.
pub const MAX_REALTIME_FLOW_LABEL_BYTES: usize = u8::MAX as usize;

/// Which way units travel on one flow.
///
/// One direction per flow. A bidirectional application opens two.
///
/// Serialized because the daemon's control request carries it verbatim. One
/// definition rather than a daemon-local mirror: two enums over the same two
/// cases would agree until one gained a variant, and the wire spelling is the
/// contract, so it belongs beside the type it names.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RealtimeFlowDirection {
    /// This endpoint sends; the peer receives.
    Outbound,
    /// This endpoint receives; the peer sends.
    Inbound,
}

/// An exclusive lease on one session's whole inbound stream.
///
/// One consumer at a time, held for as long as the handle is: a request made
/// while another handle is alive answers `None`, because two consumers parked
/// on one signal would each take wakes meant for the other.
///
/// Dropping the handle releases the lease, and the stream can be claimed again
/// while the session is still current. That is deliberate rather than
/// incidental — a consumer that panics or is cancelled would otherwise make its
/// session unreadable for the rest of its life, with no way to recover short of
/// tearing down a session that is working. Nothing is lost across the gap that
/// would not also have been lost with the consumer stalled: a fresh handle
/// drains what is already queued before it awaits anything.
///
/// The session ending is still terminal and is not a release. There is no
/// handle to re-claim with, because there is no stream.
///
/// The handle grants nothing. It cannot reach a flow, a port, or a session; the
/// only thing it can do is be handed back to
/// [`JoinedNetwork::recv_webrtc_realtime_any`](crate::JoinedNetwork::recv_webrtc_realtime_any),
/// which takes from the one queue this handle already names.
///
/// **Naming the stream is what binds it, and nothing else needs to.** The reader
/// holds a weak reference to the exact queue the claiming session's flow set
/// owns, so a handle can only ever take units that set put there: not another
/// peer's, and not those of a session that replaced it under the same selector.
/// A retained copy of the selector would be a second fact saying the same thing,
/// and the two could only ever agree or be a bug.
///
/// Holding one does not keep a session alive. When the session ends the stream
/// ends — the awaiting call answers `None`, permanently — and that is the only
/// notification of the end there is.
pub struct RealtimeInboundStream {
    reader: crate::transport::webrtc::RealtimeInboundArrivals,
}

impl RealtimeInboundStream {
    pub(crate) fn new(reader: crate::transport::webrtc::RealtimeInboundArrivals) -> Self {
        Self { reader }
    }

    pub(crate) fn reader(&self) -> &crate::transport::webrtc::RealtimeInboundArrivals {
        &self.reader
    }

    /// Receive the next application-owned opaque body from this exact stream.
    /// A queued RTP item is a typed mismatch and remains at the head for the
    /// tagged reader; `None` therefore remains the terminal stream result.
    pub(crate) async fn next_opaque(
        &self,
    ) -> std::result::Result<Option<OpaqueInboundArrival>, RealtimeRefusal> {
        self.reader.next_opaque().await
    }

    /// Receive the next item without filtering RTP or opaque flows. This is
    /// the lossless API for sessions carrying both kinds of flow.
    pub async fn next_arrival(&self) -> Option<crate::transport::webrtc::RealtimeInboundArrival> {
        self.reader.next_provider_arrival().await
    }
}

/// One open flow, and the only thing that authorizes operating on it.
///
/// **The coordinate-based API this replaces had an ABA hole.** A caller kept a
/// Device selector and a label; send and close re-resolved the selector into
/// whichever session was current at that moment and looked the label up there.
/// Labels are session-scoped and freely reused, so a caller whose session had
/// ended and been replaced would have its units accepted by the *replacement's*
/// flow of the same name — silently, since nothing on a realtime path is
/// acknowledged per unit. `screen` meant one thing to the session that opened it
/// and whatever the successor chose to it.
///
/// So a handle names three things, all of them established at open and none of
/// them re-derivable afterwards:
///
/// - the **exact session owner**, so no Device selector is ever resolved again;
/// - the **exact flow set**, so a replacement session cannot answer for it;
/// - the **exact flow record**, so a reopen of the same name inside the *same*
///   session cannot answer for it either.
///
/// The label is a **wire coordinate and nothing more**. It still travels, still
/// names the flow in the application's own control messages, and still grants
/// nothing on its own.
///
/// **Move-only, not `Clone`, not serializable.** Two copies would let one be
/// closed while the other still looked valid, which is the same class of bug one
/// layer up; and a handle that could be written to a socket would be authority
/// crossing a boundary it means nothing on the far side of. Nothing here is
/// serialized, and nothing is transmissible.
///
/// **Holding one keeps no session alive.** Both identities are non-owning, so a
/// handle for a flow that has closed simply stops resolving — it does not fund
/// the flow, the label, or the session it came from.
///
/// This carries a provider's identities in private fields, exactly as
/// [`RealtimeInboundStream`] carries a provider's reader: they are lifetime and
/// identity mechanisms with no media meaning, and nothing about them is exposed
/// or interpreted here.
pub struct RealtimeFlowHandle {
    /// The exact installation this flow was opened on. Re-resolving a selector
    /// is what the review's ABA path did; carrying the owner is how this one
    /// does not.
    owner: crate::engine::peer_registry::PeerOwnerToken,
    /// The exact flow set — which is to say the exact promoted session, named
    /// directly rather than inferred from the installation that holds it.
    ///
    /// The owner above proves the *installation*. Reading a session's identity
    /// off it would be sound only while one installation can promote only one
    /// session, and that property is real but lives three modules away, in the
    /// endpoint-auth and promotion refusals. A handle that depended on it would
    /// be silently wrong the day any of those changed. This says what it means.
    flow_set: crate::transport::webrtc::RealtimeFlowSetIdentity,
    /// The exact flow record. Closing a name and reopening it in the same
    /// session produces a different record, so this fails a same-session reuse
    /// that every other check would pass.
    flow: crate::transport::webrtc::RealtimeFlowIdentity,
    /// The application's own coordinate, kept so operations can name the flow to
    /// the session that owns it. It proves nothing; the two identities above do.
    name: crate::transport::webrtc::RealtimeFlowName,
    /// Where an abandoned flow goes to be closed.
    ///
    /// **Weak, and that is the whole of "holding one keeps no session alive".**
    /// It funds nothing and keeps nothing open; if the engine has gone, so has
    /// every flow it owned, and there is nothing left to close.
    ///
    /// `None` once [`Self::disarm`] has taken it, which is what makes an
    /// explicit close the single closer on its own path.
    closer: Option<std::sync::Weak<crate::engine::state::NetworkState>>,
}

impl RealtimeFlowHandle {
    pub(crate) fn new(
        owner: crate::engine::peer_registry::PeerOwnerToken,
        flow_set: crate::transport::webrtc::RealtimeFlowSetIdentity,
        flow: crate::transport::webrtc::RealtimeFlowIdentity,
        name: crate::transport::webrtc::RealtimeFlowName,
        closer: std::sync::Weak<crate::engine::state::NetworkState>,
    ) -> Self {
        Self {
            owner,
            flow_set,
            flow,
            name,
            closer: Some(closer),
        }
    }

    /// Give up the drop-close, for a caller that is closing this flow itself.
    ///
    /// Disarming rather than racing: an explicit close awaits the native
    /// retirement so it can acknowledge truthfully, and a drop that also closed
    /// behind it would be a second close of a record the first one removed.
    pub(crate) fn disarm(&mut self) {
        self.closer = None;
    }

    /// Whether dropping this handle would still close the flow.
    ///
    /// The observable half of the exactly-once property, on the same pattern as
    /// `RealtimeInboundRetirement::submits_on_drop`: a control can tell "the
    /// explicit close disarmed the drop" from "the drop ran and happened to find
    /// nothing".
    #[cfg(all(test, feature = "transport-lab"))]
    pub(crate) fn closes_on_drop(&self) -> bool {
        self.closer.is_some()
    }

    /// The label this flow was opened under.
    ///
    /// For the wire and for logs. A caller that has this handle does not need it
    /// to operate on the flow, and a caller that has only this cannot.
    pub fn label(&self) -> &[u8] {
        self.name.as_bytes()
    }

    pub(crate) fn owner(&self) -> &crate::engine::peer_registry::PeerOwnerToken {
        &self.owner
    }

    pub(crate) fn flow_set(&self) -> &crate::transport::webrtc::RealtimeFlowSetIdentity {
        &self.flow_set
    }

    pub(crate) fn flow(&self) -> &crate::transport::webrtc::RealtimeFlowIdentity {
        &self.flow
    }

    pub(crate) fn name(&self) -> &crate::transport::webrtc::RealtimeFlowName {
        &self.name
    }
}

impl Drop for RealtimeFlowHandle {
    /// A flow whose handle is gone is a flow nobody can operate on, so it is
    /// closed here.
    ///
    /// The handle is the only thing that authorizes sending on this flow and it
    /// is move-only, so losing it is not a state anyone recovers from — the
    /// label cannot be re-resolved into the record, by design. Without this, an
    /// abandoned handle left the flow, its label, its m-line and its bandwidth
    /// held until the whole session ended, and the application had no way to ask
    /// for them back.
    ///
    /// Caller `Drop` is the whole signal. Nothing here is timed, counted, or
    /// polled, and nothing above has to remember to close.
    ///
    /// **Phase 1 only, and that is sufficient.** Removing the flow from its set
    /// is synchronous; the native half comes back as `RealtimeFlowRemains`,
    /// which retires what it holds when it is dropped in both directions. What
    /// an explicit close still buys is the *acknowledgement* — it awaits the
    /// retirement, so a caller can say the flow is down and be telling the
    /// truth. A drop has nobody to tell.
    ///
    /// Every refusal is silent on purpose. A stale owner, a replaced session and
    /// a reopened label all mean this flow is already gone, and there is no
    /// caller left to report that to.
    fn drop(&mut self) {
        let Some(state) = self
            .closer
            .take()
            .as_ref()
            .and_then(std::sync::Weak::upgrade)
        else {
            // Either an explicit close took it, or the engine that owned the
            // flow is gone and took the flow with it.
            return;
        };
        state.abandon_realtime_flow(self);
    }
}

impl std::fmt::Debug for RealtimeFlowHandle {
    /// Names the flow and says nothing about what authorizes it.
    ///
    /// Hand-written rather than derived: a derived form would print the two
    /// identities, and a pointer address in a log is both meaningless to a
    /// reader and a hint about process layout that nothing needs.
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RealtimeFlowHandle")
            .field("label", &self.name)
            .finish_non_exhaustive()
    }
}

/// One real [`RealtimeFlowHandle`] for a flow that is already gone.
///
/// **Why this exists, and why nothing smaller would do.** The daemon installs a
/// flow into one client's table and answers with the capability naming it, and
/// the property under test is what happens to that installation when the answer
/// is never written. That property is entirely the daemon's, and it is about the
/// handle it was given — which it cannot construct, because every field of a
/// handle is core's and every production path to one runs through a promoted
/// session on a live connector. A control that opened a real flow to test a
/// rollback would be a two-node WebRTC test of a table lookup.
///
/// **It is a real handle, not a lookalike.** The type, the move-only ownership,
/// the `Drop` and `close_realtime` behaviour are all production's. What is
/// arranged is only *which* flow it names: all three identities are `Weak`s that
/// never upgrade, which is exactly what a retired session's identities become,
/// and the closer is a `Weak` to no engine. So this handle is one whose flow set
/// and record are gone — a state production reaches routinely, and one every
/// operation here already answers by refusing silently. `Drop` takes its first
/// early return; [`crate::JoinedNetwork::close_realtime`] finds no current owner
/// and refuses with [`RealtimeRefusal::SessionNotCurrent`].
///
/// **What that bounds.** A control using this can prove the daemon takes the
/// exact flow out of the exact client and hands it to the close path, and that
/// it does not when the answer was delivered. It cannot prove the native
/// retirement that a live flow's close performs — that is core's own, and core
/// tests it against real sessions.
///
/// Behind `transport-lab` and `#[doc(hidden)]`: not part of the published
/// surface, not reachable from a default build, and there is no production
/// caller.
#[cfg(feature = "transport-lab")]
#[doc(hidden)]
pub fn transport_lab_retired_flow_handle(device_id: &str, label: &[u8]) -> RealtimeFlowHandle {
    RealtimeFlowHandle {
        owner: crate::engine::peer_registry::PeerOwnerToken::detached_for_control(device_id),
        flow_set: crate::transport::webrtc::RealtimeFlowSetIdentity::detached_for_control(),
        flow: crate::transport::webrtc::RealtimeFlowIdentity::detached_for_control(),
        name: crate::transport::webrtc::RealtimeFlowName::new(label.to_vec())
            .expect("a control's flow label is 1..=255 bytes"),
        closer: None,
    }
}

/// Why a realtime operation was refused.
///
/// Four cases, each a distinct fact a client can act on. There is deliberately
/// no "unknown peer" variant: an unknown selector, a replaced installation and
/// an unpromoted peer are one fact from the caller's side — there is no live
/// session — and separating them would report peer existence to a caller that
/// has proved nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum RealtimeRefusal {
    /// No live session for that selector: absent, replaced, retired, or the
    /// process restarted. Never re-bound — open a flow on a fresh session.
    #[error("no current session for this peer")]
    SessionNotCurrent,
    /// The session already holds a flow under that label.
    #[error("flow label is already in use on this session")]
    LabelInUse,
    /// The connector refused the flow: its own ceiling, or resources.
    #[error("the connector refused the flow")]
    FlowRefused,
    /// The provider's own configuration for the flow was unusable, or matched
    /// nothing it had registered.
    ///
    /// Basal deliberately says nothing about *what* was wrong. Core does not
    /// know what a provider's configuration means — that is the whole point of
    /// the split — so naming an encoding here would be core claiming knowledge
    /// it does not have. The provider validates its own vocabulary and this
    /// reports only that it refused.
    #[error("the provider's configuration for this flow is not usable")]
    ProviderConfigurationInvalid,
}

/// The stable machine-readable code for one refusal.
///
/// Separate from the `Display` message, which is for humans and is never parsed.
impl RealtimeRefusal {
    pub fn code(self) -> &'static str {
        match self {
            Self::SessionNotCurrent => "session_not_current",
            Self::LabelInUse => "label_in_use",
            Self::FlowRefused => "flow_refused",
            Self::ProviderConfigurationInvalid => "provider_configuration_invalid",
        }
    }
}

// ---- provider values becoming basal values ----------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc05_the_daemon_wire_spelling_of_direction_is_pinned() {
        // These two strings are the control-request wire contract for the one
        // field of it that is basal. A rename is silently accepted by a
        // Rust-side refactor and breaks every client already speaking the old
        // spelling, so they are asserted literally rather than round-tripped.
        // The provider's own field is pinned beside its own type.
        for (value, spelling) in [
            (RealtimeFlowDirection::Outbound, "\"outbound\""),
            (RealtimeFlowDirection::Inbound, "\"inbound\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), spelling);
            assert_eq!(
                serde_json::from_str::<RealtimeFlowDirection>(spelling).unwrap(),
                value
            );
        }

        // Non-vacuity: the spellings really are distinguishing, and an
        // unrecognised one is refused rather than defaulted onto a variant.
        assert!(serde_json::from_str::<RealtimeFlowDirection>("\"both\"").is_err());
        assert!(serde_json::from_str::<RealtimeFlowDirection>("\"Inbound\"").is_err());
    }
}
