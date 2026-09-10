//! The WebRTC provider's application-facing realtime vocabulary.
//!
//! Everything here is a fact about **RTP over WebRTC** and nothing here is
//! generic. An RTP media kind, a MIME name, a clock rate, a channel count, an
//! RTP timestamp, a marker bit — each is meaningful only against a negotiated
//! RTP session, so each belongs to the provider that negotiates one and not to
//! [`crate::realtime`], whose contract is that it names no codec and no media.
//!
//! **Why a whole vocabulary and not a generic one with provider fields.** The
//! cheaper shape is a generic unit carrying an opaque stamp the provider
//! interprets. That is provider metadata wearing a generic type: the bytes still
//! cross the generic layer, the generic layer still has to size and copy them,
//! and the only thing it gains is the inability to say what they are. A value
//! that cannot be interpreted where it lives does not belong there. So the units
//! are whole here, and the generic layer carries what is actually generic — a
//! session binding, a direction, a label, leases, and bytes.
//!
//! The outbound duration belongs here for the same reason, and it is worth being
//! exact about because it looks generic. It is not a rate limit and nothing
//! enforces it; it is the quantity the packetizer advances the negotiated RTP
//! clock by. Its unit of meaning is the flow's `clock_rate`, which is a value on
//! this side of the boundary — so a generic layer holding it would be holding a
//! number it could not check, convert, or explain.
//!
//! What stays generic and is imported rather than duplicated:
//! [`RealtimeFlowDirection`], because which way a flow runs is true of any
//! transport, and a second provider-local spelling would be two enums for one
//! fact.
//!
//! ## Where the conversions live
//!
//! At this edge, both ways, and nowhere else. An application value becomes a
//! connector value here; a connector value becomes an application value here.
//! Constructing a [`RealtimeEncoding`] — a connector type — is possible only on
//! this side, so no generic module can assemble one out of fields it holds.

use super::*;
/// The one generic fact a provider flow still names.
///
/// Imported rather than re-spelled here. Which way a flow runs is true of any
/// transport, so a provider-local copy would be the two-enums-for-one-fact
/// mistake this module exists to undo, in the opposite direction.
use crate::realtime::{OpaqueFlowOpen, RealtimeFlowDirection, MAX_APPLICATION_FLOW_BODY_BYTES};

/// What an application asks the WebRTC provider for when it opens one flow.
///
/// `label` is the application's own choice and the application is the sole
/// allocator: the connector claims it exactly or refuses. It is scoped to one
/// session — the same number means a different flow on a different session, and
/// means nothing at all once that session ends.
///
/// `kind`, `mime`, `clock_rate` and `channels` together select **one exact
/// registered capability** out of the profile. All four are needed and none is
/// derived from another: a lookup on `mime` alone folds Opus's channel counts
/// and any two clock rates into one entry, and inferring `kind` from a `video/`
/// prefix is the codec-name branch this whole cutover removes. None of the four
/// is parsed — they are compared for equality against what was registered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WebRtcRealtimeFlowOpen {
    /// The application's opaque name for this flow, as raw bytes.
    ///
    /// Unowned and unleased here on purpose: nothing has agreed to keep it
    /// until the session accepts it, so a refused open retains nothing. Bounds
    /// are checked when it is converted, not when it is built.
    pub label: Vec<u8>,
    pub direction: RealtimeFlowDirection,
    pub kind: WebRtcRtpKind,
    /// Compared for equality against a registered capability. Not parsed.
    pub mime: String,
    /// The rate inbound timestamps tick at.
    pub clock_rate: u32,
    pub channels: u16,
}

/// One unit an application hands to an outbound WebRTC realtime flow.
///
/// Deliberately not the same type as [`WebRtcRealtimeInboundUnit`], and neither
/// carries a field named `timestamp`. Outbound supplies a `duration` that paces
/// the RTP clock; inbound reports an absolute `rtp_timestamp` that ticks at the
/// flow's clock rate. One overloaded field would let a caller pass the wrong
/// quantity with no type error, and the two quantities are not comparable: a
/// duration is elapsed time and a timestamp is a position on a clock whose tick
/// rate the flow negotiated.
///
/// There is deliberately **no outbound marker**, and the asymmetry with the
/// inbound unit is the point rather than an oversight. On the wire the marker
/// bit is a statement about packetization — last packet of an access unit, first
/// packet of a talkspurt — which the flow's framing policy decides and the
/// packetizer is the only thing positioned to get right. An application that
/// could set it could contradict the packetizer that is about to run, producing
/// a stream whose marker bits disagree with its own fragmentation.
///
/// Inbound keeps its marker because there it is a report, not an instruction.
#[derive(Clone, Debug)]
pub struct WebRtcRealtimeOutboundUnit {
    /// How long this unit occupies, which is what advances the RTP clock.
    ///
    /// Not a rate limit and not enforced anywhere: it is the packetizer's clock
    /// increment, interpreted against the flow's negotiated `clock_rate`.
    pub duration: Duration,
    pub data: Bytes,
}

/// One unit an application takes from an inbound WebRTC realtime flow.
#[derive(Clone, Debug)]
pub struct WebRtcRealtimeInboundUnit {
    /// Absolute, ticking at the flow's declared clock rate.
    pub rtp_timestamp: u32,
    /// The significance bit the sender set, carried through unchanged.
    pub marker: bool,
    pub data: Bytes,
}

/// One unit that arrived on an inbound flow, with the flow it arrived on.
///
/// The pairing is the point: a consumer awaiting every inbound flow of a session
/// at once needs to know which one produced each unit, and the label is the only
/// thing that distinguishes them. It is still not authority — it names a flow
/// within one session and means nothing outside it.
pub struct WebRtcRealtimeInboundArrival {
    /// A copy of the flow's name. The leased label stays inside the connector.
    pub label: Vec<u8>,
    pub unit: WebRtcRealtimeInboundUnit,
    /// Provider custody stays private to the crate while the public arrival
    /// remains move-only. The tagged receive path attaches the exact funded
    /// queue entry here before any application copy escapes.
    pub(crate) _custody: Option<Box<dyn crate::realtime::OpaqueInboundCustody>>,
}

impl std::fmt::Debug for WebRtcRealtimeInboundArrival {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WebRtcRealtimeInboundArrival")
            .field("label", &self.label)
            .field("unit", &self.unit)
            .finish_non_exhaustive()
    }
}

impl WebRtcRealtimeInboundArrival {
    pub(crate) fn with_custody(
        label: Vec<u8>,
        unit: WebRtcRealtimeInboundUnit,
        custody: Box<dyn crate::realtime::OpaqueInboundCustody>,
    ) -> Self {
        Self {
            label,
            unit,
            _custody: Some(custody),
        }
    }
}

/// One item from a promoted session's single inbound consumer.
///
/// This tagged surface is the lossless receive API when RTP and application
/// opaque flows coexist. The older typed helpers remain compatibility views;
/// they never consume the other variant and return no item when their next
/// queued item has the opposite kind.
pub enum RealtimeInboundArrival {
    Rtp(WebRtcRealtimeInboundArrival),
    Opaque(crate::realtime::OpaqueInboundArrival),
}

// ---- conversions at the provider edge ---------------------------------------
//
// Kept here beside the public types rather than at each call site, so there is
// exactly one place the two vocabularies meet and one place to check when either
// moves.

impl From<RealtimeFlowDirection> for RealtimeDirection {
    /// The one generic→provider mapping, and it lives here for the same reason
    /// the rest do: the generic module must not name a connector type, so a
    /// conversion *into* one cannot be written there.
    ///
    /// Two enums over the same two cases, and they stay two. The generic one is
    /// serialized and is part of the daemon's published request; the connector's
    /// is an internal value that participates in queue and gate selection. One
    /// shared enum would tie the wire spelling to a connector-internal type, so
    /// that a rename inside the connector would be a wire break.
    fn from(direction: RealtimeFlowDirection) -> Self {
        match direction {
            RealtimeFlowDirection::Outbound => Self::Outbound,
            RealtimeFlowDirection::Inbound => Self::Inbound,
        }
    }
}

impl TryFrom<WebRtcRealtimeFlowOpen> for RealtimeFlowSpec {
    type Error = crate::realtime::RealtimeRefusal;

    /// The one refusal this conversion can produce is
    /// `ProviderConfigurationInvalid`: an empty MIME or a zero clock rate is
    /// refused before any session is resolved, so an unusable request costs no
    /// fence acquisition.
    ///
    /// Note which direction the refusal is spelled in. The connector's own
    /// vocabulary calls this `EncodingInvalid`, which is right *there* — the
    /// connector does know what an encoding is. The generic answer cannot say
    /// "encoding", because the generic layer has no such concept; what it can
    /// truthfully say is that the provider was asked for something its
    /// configuration does not describe. The mapping happens here, at the edge,
    /// which is the only place both spellings are legitimate.
    fn try_from(open: WebRtcRealtimeFlowOpen) -> std::result::Result<Self, Self::Error> {
        let encoding = RealtimeEncoding::new(open.kind, &open.mime, open.clock_rate, open.channels)
            .ok_or(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)?;
        // Refused here, at the edge, before anything has agreed to keep the
        // bytes: an empty or over-long name could not have crossed the frame,
        // so it is a shape defect rather than a flow that fails later.
        let name = crate::transport::webrtc::RealtimeFlowName::new(open.label)
            .ok_or(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)?;
        Ok(RealtimeFlowSpec {
            direction: open.direction.into(),
            name,
            encoding,
        })
    }
}

impl TryFrom<OpaqueFlowOpen> for OpaqueFlowSpec {
    type Error = crate::realtime::RealtimeRefusal;

    /// Validate representation bounds before session resolution or provider
    /// acquisition. Capacity remains the existing registry/provider decision;
    /// this conversion only produces the connector-local request shape.
    fn try_from(open: OpaqueFlowOpen) -> std::result::Result<Self, Self::Error> {
        let max_unit_bytes = usize::try_from(open.max_unit_bytes)
            .map_err(|_| crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)?;
        if !open.is_well_formed() || max_unit_bytes > MAX_APPLICATION_FLOW_BODY_BYTES {
            return Err(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid);
        }
        if matches!(
            open.mode,
            crate::realtime::OpaqueFlowMode::PartialUnordered { max_retransmits } if max_retransmits != 0
        ) {
            return Err(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid);
        }
        let name = crate::transport::webrtc::RealtimeFlowName::new(open.label)
            .ok_or(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)?;
        Ok(OpaqueFlowSpec {
            direction: open.direction.into(),
            opener_direction: open.direction,
            mode: open.mode,
            max_unit_bytes,
            name,
        })
    }
}

impl From<WebRtcRealtimeOutboundUnit> for RealtimeSendUnit {
    fn from(unit: WebRtcRealtimeOutboundUnit) -> Self {
        // No marker assignment: the bit is the packetizer's to set from the
        // flow's framing policy, so there is nothing here for an application
        // value to carry into it.
        Self {
            pace: unit.duration,
            data: unit.data,
        }
    }
}

impl From<RealtimeRecvUnit> for WebRtcRealtimeInboundUnit {
    fn from(unit: RealtimeRecvUnit) -> Self {
        Self {
            rtp_timestamp: unit.timestamp,
            marker: unit.marker,
            data: unit.data,
        }
    }
}

impl From<RealtimeFlowError> for crate::realtime::RealtimeRefusal {
    /// The connector's refusals, in the generic vocabulary.
    ///
    /// Three of the four are the same fact under both spellings. The fourth is
    /// not, and the difference is the whole reason this conversion is a
    /// conversion rather than one shared enum: the connector says
    /// `EncodingInvalid`, which it is entitled to because it knows what an
    /// encoding is, and the generic layer says `ProviderConfigurationInvalid`,
    /// because all it can truthfully report is that the provider was asked for
    /// something its configuration does not describe. A generic layer naming an
    /// encoding would be claiming knowledge it does not have.
    fn from(error: RealtimeFlowError) -> Self {
        match error {
            RealtimeFlowError::SessionNotCurrent => Self::SessionNotCurrent,
            RealtimeFlowError::LabelInUse => Self::LabelInUse,
            RealtimeFlowError::FlowRefused => Self::FlowRefused,
            RealtimeFlowError::EncodingInvalid => Self::ProviderConfigurationInvalid,
        }
    }
}

// There is deliberately no constructor for [`WebRtcRealtimeInboundArrival`].
//
// Its two fields are public and the engine hands out a
// `(RealtimeFlowName, RealtimeRecvUnit)` pair, so the boundary assembles one
// with a struct literal and a `.into()`.
// A constructor taking a [`RealtimeFlowLabel`] would be the only reason that
// connector-local type had to travel any further than it does — and it must not,
// because it participates in the connector's ownership checks and reads like a
// handle that grants something.

#[cfg(test)]
mod tests {
    use super::*;

    /// The daemon wire spelling of the provider's RTP kind is pinned.
    ///
    /// These two strings are the control-request wire contract and they did not
    /// change when the type moved out of the generic vocabulary. A rename here
    /// is silently accepted by a Rust-side refactor and breaks every client that
    /// already speaks the old spelling, so they are asserted literally rather
    /// than round-tripped alone.
    #[test]
    fn v4_macro1_the_provider_rtp_kind_keeps_its_published_wire_spelling() {
        for (value, spelling) in [
            (WebRtcRtpKind::Audio, "\"audio\""),
            (WebRtcRtpKind::Video, "\"video\""),
        ] {
            assert_eq!(serde_json::to_string(&value).unwrap(), spelling);
            assert_eq!(
                serde_json::from_str::<WebRtcRtpKind>(spelling).unwrap(),
                value
            );
        }

        // Non-vacuity: the spellings really are distinguishing, and an
        // unrecognised one is refused rather than defaulted onto a variant.
        assert!(serde_json::from_str::<WebRtcRtpKind>("\"Audio\"").is_err());
        assert!(serde_json::from_str::<WebRtcRtpKind>("\"media\"").is_err());
    }

    /// An unusable encoding or label is refused at the provider edge, before any
    /// session is resolved, and reported in the generic vocabulary.
    #[test]
    fn v4_macro1_an_unusable_provider_open_is_refused_before_any_session() {
        let open = WebRtcRealtimeFlowOpen {
            label: b"named".to_vec(),
            direction: RealtimeFlowDirection::Outbound,
            kind: WebRtcRtpKind::Video,
            mime: String::new(),
            clock_rate: 90_000,
            channels: 0,
        };
        assert_eq!(
            RealtimeFlowSpec::try_from(open).err(),
            Some(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)
        );

        // The label is refused here too, and by the same code. An empty label
        // could not have crossed the frame — its length prefix says one byte at
        // least — so it is a shape defect this edge answers rather than a flow
        // that fails somewhere further in.
        let empty_label = WebRtcRealtimeFlowOpen {
            label: Vec::new(),
            direction: RealtimeFlowDirection::Outbound,
            kind: WebRtcRtpKind::Video,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
        };
        assert_eq!(
            RealtimeFlowSpec::try_from(empty_label).err(),
            Some(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)
        );

        // And so is one longer than the frame's single length byte can spell.
        let over_long_label = WebRtcRealtimeFlowOpen {
            label: vec![b'x'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES + 1],
            direction: RealtimeFlowDirection::Outbound,
            kind: WebRtcRtpKind::Video,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
        };
        assert_eq!(
            RealtimeFlowSpec::try_from(over_long_label).err(),
            Some(crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid)
        );

        // Non-vacuity: the same request with a usable MIME and a label of the
        // longest admissible length converts, so the three refusals above are
        // the defects named and not the fixture.
        let usable = WebRtcRealtimeFlowOpen {
            label: vec![b'x'; crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES],
            direction: RealtimeFlowDirection::Outbound,
            kind: WebRtcRtpKind::Video,
            mime: "video/H264".to_string(),
            clock_rate: 90_000,
            channels: 0,
        };
        assert!(RealtimeFlowSpec::try_from(usable).is_ok());
    }

    /// An arrival carries the exact flow it arrived on, and the unit's two RTP
    /// facts survive the crossing unchanged.
    ///
    /// The label half is what a consumer of a whole session's inbound stream
    /// demultiplexes on, so reporting the wrong one would hand a decoder another
    /// flow's bytes. The timestamp and marker halves are the reason these units
    /// moved to the provider at all — a generic unit could carry them only as an
    /// uninterpretable blob.
    #[test]
    fn v4_macro1_an_arrival_names_its_flow_and_preserves_its_rtp_facts() {
        // Assembled exactly as the public boundary assembles one, from the
        // `(Vec<u8>, RealtimeRecvUnit)` pair the engine hands out.
        let arrival = WebRtcRealtimeInboundArrival {
            label: b"seven".to_vec(),
            unit: RealtimeRecvUnit {
                timestamp: 90_000,
                marker: true,
                data: Bytes::from_static(b"unit"),
            }
            .into(),
            _custody: None,
        };
        assert_eq!(arrival.label, b"seven".to_vec());
        assert_eq!(arrival.unit.rtp_timestamp, 90_000);
        assert!(arrival.unit.marker);
        assert_eq!(arrival.unit.data, Bytes::from_static(b"unit"));

        // Non-vacuity: a cleared marker and a different timestamp really do
        // cross differently, so the equalities above are the conversion carrying
        // its values and not a fixture that matches anything.
        let other = WebRtcRealtimeInboundUnit::from(RealtimeRecvUnit {
            timestamp: 90_001,
            marker: false,
            data: Bytes::from_static(b"unit"),
        });
        assert_eq!(other.rtp_timestamp, 90_001);
        assert!(!other.marker);
    }

    /// An outbound unit's duration reaches the pump, and no marker is invented
    /// for it on the way.
    #[test]
    fn v4_macro1_an_outbound_unit_carries_only_its_pace_and_its_bytes() {
        let send = RealtimeSendUnit::from(WebRtcRealtimeOutboundUnit {
            duration: Duration::from_millis(20),
            data: Bytes::from_static(b"frame"),
        });
        assert_eq!(send.pace, Duration::from_millis(20));
        assert_eq!(send.data, Bytes::from_static(b"frame"));
    }

    /// Every connector refusal reaches the generic vocabulary as exactly one
    /// distinct public code.
    ///
    /// The four codes are the contract a client matches on. This fails if a
    /// variant is added connector-side with no generic answer, and the
    /// distinctness assertion fails if two ever collapse onto one string —
    /// which would silently merge "retry on a fresh session" with "never retry
    /// this request".
    #[test]
    fn v4_macro1_every_connector_refusal_has_exactly_one_generic_code() {
        let codes = [
            RealtimeFlowError::SessionNotCurrent,
            RealtimeFlowError::LabelInUse,
            RealtimeFlowError::FlowRefused,
            RealtimeFlowError::EncodingInvalid,
        ]
        .map(|error| crate::realtime::RealtimeRefusal::from(error).code());

        let distinct: std::collections::BTreeSet<_> = codes.iter().collect();
        assert_eq!(distinct.len(), codes.len());

        // The one variant whose spelling differs across the boundary, asserted
        // by name rather than only by distinctness: the connector is entitled to
        // say "encoding" and the generic layer is not, so a conversion that
        // quietly carried the connector's word through would be the leak this
        // whole boundary exists to close.
        assert_eq!(
            crate::realtime::RealtimeRefusal::from(RealtimeFlowError::EncodingInvalid),
            crate::realtime::RealtimeRefusal::ProviderConfigurationInvalid
        );
    }
}
