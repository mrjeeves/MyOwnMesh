//! What a flow is called, and what holding that name costs.
//!
//! Two types and one boundary between them. [`RealtimeFlowName`] is bytes that
//! have been checked for shape and nothing more — it owns no lease, grants
//! nothing, and is what crosses in and out. [`RealtimeFlowLabel`] is a name a
//! session has *accepted*: one shared record, one lease, and every copy naming
//! the same charge.
//!
//! They are separate types because the moment between them is the moment
//! admission happens, and a single type would make that moment invisible.

use super::*;

/// Which of one session's flows a unit belongs to.
///
/// This is the existing media lane coordinate generalized: assigned by the
/// opening side, pinned for the flow's lifetime, and published in the
/// application's own control messages so a receiver demultiplexes by explicit
/// binding rather than by inferring from arrival order. That inference was a
/// real bug — several concurrent feeds put one display's frames in another's
/// window — and the explicit label is what fixed it.
///
/// **Not a route or path identity, not a generation, not authority.** It names
/// one flow inside one authenticated session and nothing outside it. It is
/// never persisted. Session or connector-incarnation invalidation destroys the
/// whole label space with the session, and a value may be handed out again
/// only once the flow that held it is gone. Nothing orders two labels or
/// advances one.
///
/// **Opaque bytes, not a number.** What bounds a name's *size* is the frame
/// that carries it — [`crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES`], the
/// width of the encoded length prefix. What bounds how many exist at once is
/// admission, which answers with leases rather than with a fixed space. Those
/// are separate questions and neither is allowed to stand in for the other: a
/// numeric label makes the name's width into a concurrency ceiling, and a
/// concurrency ceiling stated anywhere but the owner's envelope is a second
/// number to drift from the first. The `Ord` below exists to key a map, not to
/// rank: nothing orders two labels meaningfully and nothing advances one.
///
/// The one property that is easy to lose and is load-bearing: a receiver that
/// has lost its entire route table can still cite a label back to the sender,
/// and the sender can resolve it. That is the only way to report a dead flow
/// whose name is exactly what was lost, so a label must stay meaningful to the
/// *peer*, not merely inside the process that minted it.
///
/// **One shared record and one lease, carried by every copy.** Not one
/// allocation: the record is an `Arc` block and the name is a `Box<[u8]>`
/// beside it, which is two, and `label_claim` charges both. What is singular
/// here is the record and the lease it holds, which is the property that
/// matters — cloning a label clones an `Arc`, so the held set, the flows map, a
/// queued arrival and an inbound binding all name the same bytes and the same
/// charge — released when the last of them drops, which is deliberately *not*
/// when the flow closes. A queued arrival outlives its flow; charging the
/// flow's own lease for the label would have released bytes that were still
/// retained.
///
/// Equality, ordering and hashing are by bytes, never by allocation address:
/// two labels naming the same bytes are the same label, which is what lets a
/// peer cite one back after this side has rebuilt everything else.
#[derive(Clone, Debug)]
pub(crate) struct RealtimeFlowLabel(Arc<LeasedLabel>);

/// The one *record* behind every copy of a label — two allocations, one
/// lifetime.
///
/// The `Arc` block holds this struct; the name's `Box<[u8]>` is a second
/// allocation it points at. Both die together when the last copy drops, which
/// is why one lease covers both, and `label_claim` counts two residuals.
///
/// `_lease` is never read. Its whole job is to exist for exactly as long as the
/// name beside it and to release when this record drops.
#[derive(Debug)]
struct LeasedLabel {
    name: RealtimeFlowName,
    _lease: crate::resource::ResourceLease,
}

impl RealtimeFlowLabel {
    /// Mint the leased label for a name a session is accepting.
    ///
    /// The only way one is made, and it is made *at admission*. Before this
    /// point a name is unowned bytes costing a decode buffer and nothing else,
    /// so a refused open — a malformed name, a name already held, a provider
    /// under pressure — retains nothing this side accounted for. Minting first
    /// and refusing afterwards would let a peer drive retention with opens that
    /// never succeed.
    ///
    /// Reachable across the connector's own modules and no further: the
    /// provider edge and the registry's fixtures mint, the engine cannot.
    pub(in crate::transport::webrtc) fn mint(
        name: RealtimeFlowName,
        registry: &RealtimeFlowRegistry,
    ) -> FlowResult<Self> {
        let content_bytes = name.as_bytes().len();
        let lease = registry
            .acquire_label_lease(std::mem::size_of::<LeasedLabel>(), content_bytes)
            .map_err(realtime_drop_refusal)?;
        Ok(Self(Arc::new(LeasedLabel {
            name,
            _lease: lease,
        })))
    }

    /// The name this label carries.
    ///
    /// Only the application control path reads it; nothing in the flow path
    /// treats a label as authority.
    pub(crate) fn name(&self) -> &RealtimeFlowName {
        &self.0.name
    }

    /// Exactly what minting a name of this length will cost.
    ///
    /// Fixtures that derive a finite grant from the claims they exercise need
    /// this number, and `size_of::<LeasedLabel>()` is not theirs to compute —
    /// the record is private to this module, which is what keeps the production
    /// arithmetic and the fixture arithmetic the same expression rather than
    /// two that agree until the record gains a field.
    #[cfg(any(test, feature = "transport-lab"))]
    pub(in crate::transport::webrtc) fn mint_claim(
        content_bytes: usize,
    ) -> std::result::Result<crate::resource::ResourceClaim, crate::resource::ResourceUnavailable>
    {
        RealtimeFlowRegistry::label_claim(std::mem::size_of::<LeasedLabel>(), content_bytes)
    }
}

impl RealtimeFlowLabel {
    /// Whether these two labels are copies of the *same* leased record, rather
    /// than two records that merely spell the same name.
    ///
    /// Deliberately not `Eq`, which compares the bytes and must keep doing so:
    /// a peer citing a name, a map lookup and an ordered key all ask the byte
    /// question, and that is the right one for them. This asks the identity
    /// question, and there is exactly one caller — a close, deciding which
    /// queued arrivals belonged to *this* flow. A name may be released and
    /// claimed again within one session, so at that moment the bytes cannot
    /// distinguish the flow that is going from the flow that will take its
    /// name, and only the record can.
    pub(super) fn is_same_record(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }

    /// A non-owning citation of *this* flow's record, for a holder outside the
    /// session to present later.
    ///
    /// The same identity question [`Self::is_same_record`] asks, in the form a
    /// caller can keep. **Weak on purpose, twice over.** It must not fund the
    /// record — an application holding a flow handle would otherwise keep a
    /// closed flow's label charged for as long as it felt like — and a dead
    /// record must answer *nothing* rather than answering by address, which an
    /// allocator is free to reuse. `Weak` gives both: the control block outlives
    /// the record, so a citation of a freed flow is distinguishable from a
    /// citation of whatever was allocated there next.
    pub(crate) fn identity(&self) -> RealtimeFlowIdentity {
        RealtimeFlowIdentity(Arc::downgrade(&self.0))
    }

    /// Whether this label is the exact record `identity` was taken from.
    ///
    /// `false` for a record that has since been dropped, which is the whole
    /// point: a flow that closed cannot be named again, not even by a caller
    /// holding the same bytes and asking inside the same session.
    pub(crate) fn is_identity(&self, identity: &RealtimeFlowIdentity) -> bool {
        identity
            .0
            .upgrade()
            .is_some_and(|record| Arc::ptr_eq(&self.0, &record))
    }
}

/// One flow's exact identity, without owning it.
///
/// Carries no name, no session and no authority, and answers exactly one
/// question: "is this the flow I was given?". It answers against the *record*
/// rather than the bytes, because a name may be released and claimed again
/// inside one session and the bytes cannot tell those two flows apart. That is
/// the ABA the public flow handle exists to close.
///
/// Opaque and not constructible from outside this module: the only way to hold
/// one is to have been handed it by the session that admitted the flow.
#[derive(Debug)]
pub(crate) struct RealtimeFlowIdentity(std::sync::Weak<LeasedLabel>);

#[cfg(feature = "transport-lab")]
impl RealtimeFlowIdentity {
    /// An identity for a flow record that is gone, on the same reasoning as
    /// [`super::RealtimeFlowSetIdentity::detached_for_control`].
    pub(crate) fn detached_for_control() -> Self {
        Self(std::sync::Weak::new())
    }
}

impl std::borrow::Borrow<[u8]> for RealtimeFlowLabel {
    /// Lets a collection keyed by label be looked up with the raw bytes a peer
    /// sent, without minting a lease merely to ask a question. Consistent with
    /// `Eq`, `Ord` and `Hash` because all four read the same bytes.
    fn borrow(&self) -> &[u8] {
        self.0.name.as_bytes()
    }
}

impl PartialEq for RealtimeFlowLabel {
    fn eq(&self, other: &Self) -> bool {
        self.0.name == other.0.name
    }
}

impl Eq for RealtimeFlowLabel {}

impl PartialOrd for RealtimeFlowLabel {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RealtimeFlowLabel {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.name.cmp(&other.0.name)
    }
}

impl std::hash::Hash for RealtimeFlowLabel {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.0.name.hash(state);
    }
}

/// A label's bytes before anything has agreed to keep them.
///
/// This is what crosses the boundary in both directions: an application names
/// one to open or address a flow, and one comes back out on an arrival. It owns
/// no lease and is not authority — it is a question, and resolving it to a flow
/// is a lookup in one session's own table, where a name matching nothing simply
/// finds nothing.
///
/// The bound is the frame's, not this type's invention:
/// [`crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES`] is the width of the
/// encoded label's single length byte, so a name is 1..=255 bytes and anything
/// longer could not have been transmitted. That constant lives in the basal
/// vocabulary because the daemon and this module must not each spell it. Empty
/// is refused rather than accepted as a degenerate name, so the binary and JSON
/// paths cannot disagree about what an absent label means.
///
/// `Box<[u8]>`, not `Vec<u8>`, and the difference is the accounting: a boxed
/// slice has no spare capacity, so its allocation is exactly its length and the
/// claim can charge the length rather than guess at a capacity the caller
/// happened to hand over.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RealtimeFlowName(Box<[u8]>);

impl RealtimeFlowName {
    /// Accept bytes as a name, or refuse them.
    ///
    /// Both refusals are shape, and both are cheap: they happen before any
    /// lease exists, so a peer sending unusable names pays for a decode buffer
    /// and nothing this side retains.
    pub fn new(bytes: Vec<u8>) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > crate::realtime::MAX_REALTIME_FLOW_LABEL_BYTES {
            return None;
        }
        // Boxing drops any spare capacity, so what the lease is later asked to
        // charge is what is actually held.
        Some(Self(bytes.into_boxed_slice()))
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}
