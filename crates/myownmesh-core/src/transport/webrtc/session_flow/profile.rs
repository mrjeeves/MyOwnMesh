//! What an application declares it can carry, and what holding that
//! declaration costs.
//!
//! Everything here is registration data: plain, immutable, and never
//! interpreted. Core does not know what `video/H264` means and must not learn —
//! a flow selects a registered capability by equality on four fields, and the
//! framing it installs is the strategy the application named rather than
//! anything inferred from a codec name. That is the whole reason this module has
//! no branch on a MIME string.
//!
//! The one runtime concern that belongs here is retention. A profile is deep —
//! a vector of codecs, each with two `String`s and a vector of feedback entries
//! with two more apiece — so it is shared behind an `Arc` with its lease inside
//! the shared record, and its cost is walked rather than estimated.

use super::*;

/// What an application says it will put on a flow.
///
/// The mime string is carried, compared for equality when a peer describes its
/// own flow, and otherwise never interpreted. Core does not know what
/// `video/H264` means and must not learn: the deployed set already includes
/// H.264 and Opus plus MJPEG and PCM fallbacks that exist to survive an older
/// daemon, and a core that branched on any of them would have to change to
/// admit the fifth.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RealtimeEncoding {
    kind: WebRtcRtpKind,
    mime: String,
    clock_rate: u32,
    channels: u16,
}

/// One RTCP feedback mechanism, as plain data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeRtcpFeedback {
    pub mechanism: String,
    pub parameter: String,
}

/// How a flow's RTP payloads become whole application units.
///
/// The application names a *strategy*; core resolves the strategy to one of
/// the framing adapters it implements. That resolution is a total map over
/// this enum, so it is not a codec-name branch and adding a codec never
/// touches core. The distinction is deliberately not inferable: two codecs
/// with the same MIME family could in principle be packetised either way, and
/// a wrong guess negotiates cleanly and then decodes to nothing — which is
/// exactly the failure that is hardest to attribute. So there is no default.
///
/// `non_exhaustive` because a third packetisation mode is a core capability,
/// and an application matching on this should be forced to say what it does
/// with one it has never heard of.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RealtimeFraming {
    /// Payloads are fragments carrying their own fragmentation headers, and
    /// the assembled unit is emitted as a start-code-delimited byte stream.
    AnnexB,
    /// Each payload is already one whole unit, carried through untouched.
    Whole,
}

/// What core does with a flow's RTP payloads, resolved from the strategy the
/// application declared.
///
/// Two policies rather than two framing adapters, because the difference is
/// not only *how* fragments are framed but *whether there is reassembly at
/// all*. [`RealtimeUnitAssembler`] completes a unit on the RTP marker bit; a
/// stream whose payloads are each already whole does not reliably set it —
/// Opus marks a talkspurt start and nothing after — so routing whole payloads
/// through the assembler would emit the first unit of each talkspurt and
/// silently swallow the rest. That failure is inaudible as an error and
/// audible as broken audio, which is the worst combination, so the two cases
/// stay structurally distinct instead of sharing a path with a flag.
pub(crate) enum RealtimeUnitPolicy {
    /// Payloads are fragments; reassemble, then frame with this adapter.
    Assembled(Arc<dyn RealtimeUnitFraming>),
    /// Each payload is one unit; hand it through with no reassembly state.
    PayloadPerUnit,
}

impl RealtimeFraming {
    /// The total map from declared strategy to core's implementation of it.
    ///
    /// Exhaustive by construction: a new strategy is a compile error here
    /// rather than a silent fallback. Nothing in this function reads a MIME
    /// name — the application chose the strategy, and core only supplies the
    /// machinery for the strategy it chose.
    pub(super) fn unit_policy(self) -> RealtimeUnitPolicy {
        match self {
            // Named for the codec it was written for, because it implements
            // that codec's fragmentation exactly. It is selected here by the
            // strategy the application named, never by recognising a codec.
            Self::AnnexB => RealtimeUnitPolicy::Assembled(Arc::new(H264Framing)),
            Self::Whole => RealtimeUnitPolicy::PayloadPerUnit,
        }
    }
}

/// One codec the application registers, complete enough to negotiate.
///
/// Plain data on purpose: no `webrtc` crate type appears here, so the
/// application boundary does not depend on the transport library. Core
/// converts these into registration parameters and never inspects what they
/// mean — there is no MIME-name branch anywhere on this path.
///
/// The fields are public because this is an input DTO with nothing to
/// protect: it grants nothing on its own, and the only way to turn a pile of
/// these into something the connector will use is [`RealtimeProfile::new`],
/// which validates and then owns an immutable copy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeCodec {
    /// Spelled in the provider's own vocabulary, which is the only one this
    /// concept has. A generic spelling would put a fixed audio/video taxonomy in
    /// the layer that must not have one, and a connector type reaching back into
    /// the generic vocabulary for its media kind is what would make it
    /// load-bearing there.
    pub kind: WebRtcRtpKind,
    pub payload_type: u8,
    pub mime: String,
    pub clock_rate: u32,
    pub channels: u16,
    pub fmtp: String,
    /// Stated per registration, but see [`RealtimeProfile::new`]: every
    /// variant of one encoding family must agree, because a flow opens
    /// against the family before a payload type has been negotiated.
    pub framing: RealtimeFraming,
    pub rtcp_feedback: Vec<RealtimeRtcpFeedback>,
}

impl RealtimeCodec {
    /// The four fields a flow selects on. Not the payload type: five H.264
    /// registrations differing only in `payload_type` and `fmtp` are one
    /// family, and a flow names the family.
    fn family(&self) -> (WebRtcRtpKind, String, u32, u16) {
        (
            self.kind,
            self.mime.to_ascii_lowercase(),
            self.clock_rate,
            self.channels,
        )
    }
}

/// Why an application profile was refused.
///
/// Every variant is a shape defect that would make negotiation or selection
/// ambiguous. None of them is a judgement about a codec: core does not have
/// an opinion about which codecs are acceptable, only about whether the
/// registration it was handed can be acted on unambiguously.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum RealtimeProfileError {
    #[error("real-time profile registers no codecs")]
    NoCodecs,
    #[error("real-time codec with payload type {payload_type} has an empty MIME name")]
    EmptyMime { payload_type: u8 },
    #[error("real-time codec {mime} with payload type {payload_type} has a zero clock rate")]
    ZeroClockRate { mime: String, payload_type: u8 },
    #[error("real-time payload type {payload_type} is registered more than once")]
    DuplicatePayloadType { payload_type: u8 },
    #[error(
        "real-time codecs {mime} at {clock_rate} Hz disagree on framing, so a flow opened against \
         that family would have no framer to install"
    )]
    FamilyFramingConflict { mime: String, clock_rate: u32 },
}

/// The application's complete real-time profile, supplied before the peer
/// connection exists.
///
/// The single place the connector knows codecs from. Both the registration
/// list and the inbound track admission test consult this, and both do it by
/// equality against what the application registered rather than by comparing a
/// MIME string to a constant — a constant is a codec the connector would be
/// claiming to know, which is exactly what it must not do.
///
/// It must be supplied before `PeerConnection` creation because codec
/// registration is a property of the media engine the connection is built
/// from — there is no point after which a codec can be added to an existing
/// connection, so there is no point at which core could fall back to a
/// built-in list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RealtimeProfile {
    codecs: Vec<RealtimeCodec>,
}

impl RealtimeProfile {
    /// Validate and accept one application profile.
    ///
    /// The refusals are all shape, never codec judgement: something to
    /// register, no duplicate payload type (which would make negotiation
    /// ambiguous), no empty MIME or zero clock rate (which would make a
    /// capability unmatchable), and no encoding family whose variants disagree
    /// on framing.
    ///
    /// A profile says **which encodings this application can carry** and
    /// nothing about how many flows may exist at once. Concurrency is the
    /// owner's, stated by its resource envelope and enforced by the registry;
    /// a capacity here would be the application stating a second number for
    /// something the envelope already decides, and it would leave an elastic
    /// deployment — codecs, no fixed ceiling — with nothing it could truthfully
    /// say.
    ///
    /// Note what is deliberately *not* refused: two registrations agreeing on
    /// all four family fields. Deployed H.264 is five registrations differing
    /// only in payload type and fmtp, and rejecting that would reject the
    /// profile the daemon actually ships.
    pub fn new(codecs: Vec<RealtimeCodec>) -> std::result::Result<Self, RealtimeProfileError> {
        if codecs.is_empty() {
            return Err(RealtimeProfileError::NoCodecs);
        }
        let mut payload_types = std::collections::BTreeSet::new();
        let mut families: std::collections::BTreeMap<
            (WebRtcRtpKind, String, u32, u16),
            RealtimeFraming,
        > = std::collections::BTreeMap::new();
        for codec in &codecs {
            if codec.mime.trim().is_empty() {
                return Err(RealtimeProfileError::EmptyMime {
                    payload_type: codec.payload_type,
                });
            }
            if codec.clock_rate == 0 {
                return Err(RealtimeProfileError::ZeroClockRate {
                    mime: codec.mime.clone(),
                    payload_type: codec.payload_type,
                });
            }
            if !payload_types.insert(codec.payload_type) {
                return Err(RealtimeProfileError::DuplicatePayloadType {
                    payload_type: codec.payload_type,
                });
            }
            match families.entry(codec.family()) {
                std::collections::btree_map::Entry::Vacant(slot) => {
                    slot.insert(codec.framing);
                }
                std::collections::btree_map::Entry::Occupied(slot) => {
                    if *slot.get() != codec.framing {
                        return Err(RealtimeProfileError::FamilyFramingConflict {
                            mime: codec.mime.clone(),
                            clock_rate: codec.clock_rate,
                        });
                    }
                }
            }
        }
        Ok(Self { codecs })
    }

    /// Everything to register with the media engine, in the order supplied.
    pub(crate) fn codecs(&self) -> &[RealtimeCodec] {
        &self.codecs
    }

    /// Every registered variant of the family an encoding names, in
    /// registration order.
    ///
    /// A family, not a tuple. The four fields answer "which transceiver, and
    /// did we register this at all"; they cannot answer "which payload type",
    /// because the offer advertises every variant and the *answerer* chooses.
    /// Resolving them to a single registration would pick a payload type the
    /// peer may not have selected, and that failure is silent: the track
    /// negotiates and then carries RTP the far side does not decode.
    fn variants<'a>(
        &'a self,
        encoding: &'a RealtimeEncoding,
    ) -> impl Iterator<Item = &'a RealtimeCodec> + 'a {
        self.family_of(
            encoding.kind(),
            encoding.mime(),
            encoding.clock_rate(),
            encoding.channels(),
        )
    }

    /// The lifetimes are named and unified rather than elided: the returned
    /// iterator borrows both the registration list and the MIME it is
    /// filtering against, and an edition-2021 opaque return type captures only
    /// lifetimes it can name.
    fn family_of<'a>(
        &'a self,
        kind: WebRtcRtpKind,
        mime: &'a str,
        clock_rate: u32,
        channels: u16,
    ) -> impl Iterator<Item = &'a RealtimeCodec> + 'a {
        self.codecs.iter().filter(move |codec| {
            codec.kind == kind
                && codec.clock_rate == clock_rate
                && codec.channels == channels
                && codec.mime.eq_ignore_ascii_case(mime)
        })
    }

    /// The framing to install for a flow, if this profile registered the
    /// family it names.
    ///
    /// One lookup answers both questions a flow open has: is this encoding
    /// registered at all (otherwise refuse), and which framer does the
    /// application want on it. `new` has already established that every
    /// variant of a family agrees, so taking the first is exact rather than
    /// first-wins.
    pub(crate) fn admits_encoding(&self, encoding: &RealtimeEncoding) -> Option<RealtimeFraming> {
        self.variants(encoding).next().map(|codec| codec.framing)
    }

    /// Everything this profile holds on the heap, walked rather than estimated.
    ///
    /// Three levels, because the profile has three: the codec vector's own
    /// buffer, each codec's two `String`s and its feedback vector's buffer, and
    /// each feedback entry's two `String`s. The deployed profile is five H.264
    /// variants whose `fmtp` lines differ in length, so any per-codec average
    /// would be wrong in both directions.
    ///
    /// `capacity`, not `len`, for every buffer: what is held is what was
    /// allocated, and a `Vec` built by `push` routinely holds more than it uses.
    fn heap_bytes(&self) -> usize {
        let codec_records = self.codecs.capacity() * std::mem::size_of::<RealtimeCodec>();
        self.codecs.iter().fold(codec_records, |total, codec| {
            let feedback_records =
                codec.rtcp_feedback.capacity() * std::mem::size_of::<RealtimeRtcpFeedback>();
            let feedback_strings = codec
                .rtcp_feedback
                .iter()
                .map(|entry| entry.mechanism.capacity() + entry.parameter.capacity())
                .sum::<usize>();
            total
                + codec.mime.capacity()
                + codec.fmtp.capacity()
                + feedback_records
                + feedback_strings
        })
    }

    /// How many separate allocations those bytes are spread across.
    ///
    /// Counted because allocator overhead has no portable size and the byte
    /// total cannot express it — the same arithmetic the label claim uses.
    ///
    /// **By capacity, not by presence.** An empty `String` or `Vec` owns no
    /// buffer, so counting one per field would charge a residual for something
    /// that was never allocated. That matters here rather than being pedantry:
    /// `fmtp` is routinely empty and `rtcp_feedback` usually is, so a
    /// per-field count would over-charge every ordinary profile — and an
    /// arithmetic that says "exact" while being conservative is worse than one
    /// that admits which it is.
    fn heap_allocations(&self) -> u64 {
        /// One allocation exists exactly when a container owns a buffer.
        fn allocated(capacity: usize) -> u64 {
            u64::from(capacity != 0)
        }

        let codec_vector = allocated(self.codecs.capacity());
        self.codecs.iter().fold(codec_vector, |total, codec| {
            let feedback_strings = codec
                .rtcp_feedback
                .iter()
                .map(|entry| {
                    allocated(entry.mechanism.capacity()) + allocated(entry.parameter.capacity())
                })
                .sum::<u64>();
            total
                + allocated(codec.mime.capacity())
                + allocated(codec.fmtp.capacity())
                + allocated(codec.rtcp_feedback.capacity())
                + feedback_strings
        })
    }

    // An `admits(kind, mime, clock_rate, channels)` was here and is deliberately
    // gone rather than wired up. It asked whether a *shape* was registered,
    // which is a strictly weaker question than the one inbound admission
    // actually asks: `RealtimeInboundBindings::admit` compares an arriving
    // track against the exact binding this side recorded for the token it
    // arrived on, so a track can be the right shape and still be refused
    // because it is not the track we negotiated. Keeping a second, weaker gate
    // beside the exact one invites a future caller to reach for whichever it
    // finds first, and the weaker one answers `Some` for media the exact one
    // would refuse.
}

/// One application profile, and the lease that owns its heap.
///
/// **The lease lives inside the shared record, beside the profile it pays
/// for.** A promoted session's flow set holds one of these, and a set can
/// outlive the connector field it was cloned from; a lease held as a sibling of
/// an `Arc<RealtimeProfile>` would release at the moment that *field* dropped
/// while the profile itself was still retained. Here the charge and the bytes
/// are one object, so the release is the last clone's drop and cannot be
/// anything else.
///
/// Minted once, by the connector, at the point the profile becomes the
/// session's. Every promotion after that is a refcount: a profile is immutable
/// registration data, so there is nothing for two sessions to disagree about
/// and no reason for either to hold its own deep copy. A per-promotion clone
/// would duplicate the codec vector, both `String`s per codec and every
/// feedback entry — an unbounded cost recurring at the one moment nothing is
/// positioned to account for it.
///
/// Charged on the same three terms as a leased label — record, content, and
/// the `Arc`'s counter pair — because it is the same shape of object. Two
/// shared records costing differently would be an accident of which one was
/// written first.
#[derive(Clone, Debug)]
pub(crate) struct LeasedRealtimeProfile(Arc<LeasedProfile>);

/// The record a [`LeasedRealtimeProfile`] shares: one immutable profile and the
/// one lease that owns its bytes.
///
/// `_lease` is never read. Its whole job is to exist for exactly as long as the
/// profile beside it and to release when this record drops.
#[derive(Debug)]
struct LeasedProfile {
    profile: RealtimeProfile,
    _lease: crate::resource::ResourceLease,
}

impl LeasedRealtimeProfile {
    /// Take the lease that owns one profile's heap, or refuse it.
    ///
    /// Refusal is ordinary: a provider under pressure declines the profile and
    /// the connector fails to come up, rather than registering codecs whose
    /// retention nothing accounted for.
    ///
    /// Reachable across the connector's own modules and no further: the
    /// connector mints one when a profile becomes a session's, and the engine
    /// cannot.
    pub(in crate::transport::webrtc) fn mint(
        profile: RealtimeProfile,
        registry: &RealtimeFlowRegistry,
    ) -> FlowResult<Self> {
        let (record_bytes, content_bytes, allocations) = Self::record_terms(&profile);
        let lease = registry
            .acquire_profile_lease(record_bytes, content_bytes, allocations)
            .map_err(realtime_drop_refusal)?;
        Ok(Self(Arc::new(LeasedProfile {
            profile,
            _lease: lease,
        })))
    }

    /// The profile this record carries.
    pub(crate) fn profile(&self) -> &RealtimeProfile {
        &self.0.profile
    }

    /// Everything the claim for one shared profile record is built from.
    ///
    /// **One expression, two callers.** The live mint and the fixture claim
    /// have to agree exactly or a derived grant is wrong by however much they
    /// differ, and two copies of this arithmetic would agree only until one of
    /// them was edited. So neither computes it: both ask here.
    ///
    /// The record term is the `LeasedProfile` struct; the content term is every
    /// buffer the profile points at; the allocation count is the `Arc` block,
    /// which always exists, plus each buffer the profile actually owns —
    /// counted by capacity, so an empty `fmtp` or an empty feedback list costs
    /// nothing rather than costing a residual for a buffer that was never
    /// allocated. The `Arc`'s strong/weak counter pair is added by
    /// `profile_claim`, in the same place and the same way the label's is.
    fn record_terms(profile: &RealtimeProfile) -> (usize, usize, u64) {
        (
            std::mem::size_of::<LeasedProfile>(),
            profile.heap_bytes(),
            1 + profile.heap_allocations(),
        )
    }

    /// Exactly what minting this profile will cost, for fixtures that derive a
    /// finite grant from the claims they exercise.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(in crate::transport::webrtc) fn mint_claim(
        profile: &RealtimeProfile,
    ) -> std::result::Result<crate::resource::ResourceClaim, crate::resource::ResourceUnavailable>
    {
        let (record_bytes, content_bytes, allocations) = Self::record_terms(profile);
        RealtimeFlowRegistry::profile_claim(record_bytes, content_bytes, allocations)
    }
}

/// Which RTP media kind a flow negotiates.
///
/// An RTP transport primitive, not a codec name. A transceiver is audio or
/// video before any codec is chosen, so this is the one media distinction the
/// connector legitimately makes — and it is supplied by the application rather
/// than inferred from a MIME string, because inferring it would be the
/// codec-name branch this cutover removes.
///
/// **Named for its provider, and that is the whole point of the spelling.**
/// There is exactly one enum for this concept, it lives at the WebRTC edge, and
/// an application naming it is unambiguously naming a WebRTC fact. An
/// unqualified public spelling in the generic vocabulary would put a fixed
/// audio/video taxonomy in the layer that is supposed to know nothing about
/// media, and would make an application choose between two identical enums.
///
/// Serialized because the daemon's control request carries it verbatim, and
/// `"audio"` / `"video"` are the published wire contract. Relocating a type
/// across a boundary must not silently relocate the strings a client already
/// sends, so the spelling is pinned by a control rather than left to the derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WebRtcRtpKind {
    Audio,
    Video,
}

impl RealtimeEncoding {
    /// An encoding an application declares for one flow.
    ///
    /// Refuses only what would make the flow meaningless to *either* end: an
    /// empty mime, which names nothing a peer could match, and a zero clock
    /// rate, which would make every inbound timestamp incomparable. Neither
    /// refusal is a codec judgement.
    ///
    /// Carries everything profile lookup needs to select one exact registered
    /// capability: the RTP kind, the MIME name, the clock rate, and the
    /// channel count. Nothing here is interpreted — the four are compared for
    /// equality against what the application registered, and a flow opens only
    /// if exactly one registered capability matches.
    pub(crate) fn new(
        kind: WebRtcRtpKind,
        mime: &str,
        clock_rate: u32,
        channels: u16,
    ) -> Option<Self> {
        (!mime.trim().is_empty() && clock_rate != 0).then(|| Self {
            kind,
            mime: mime.to_string(),
            clock_rate,
            channels,
        })
    }

    pub(crate) fn kind(&self) -> WebRtcRtpKind {
        self.kind
    }

    pub(crate) fn mime(&self) -> &str {
        &self.mime
    }

    /// Channel count. Zero is legitimate and means "not applicable", which is
    /// what a video capability carries — so it is deliberately not refused by
    /// [`Self::new`] the way an empty MIME or a zero clock rate are.
    pub(crate) fn channels(&self) -> u16 {
        self.channels
    }

    /// The rate inbound timestamps tick at. Supplied by the application, not
    /// derived from the mime, so a profile can carry a non-default clock
    /// without core holding a table of codec defaults.
    pub(crate) fn clock_rate(&self) -> u32 {
        self.clock_rate
    }
}
