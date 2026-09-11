//! Codec-neutral RTP unit assembly.
//!
//! The loss- and reorder-aware half of what used to be the H.264 assembler,
//! with every H.264 fact removed. What remains is RTP machinery and belongs at
//! the connector edge: sequence unwrapping across wraparound, timestamp
//! ordering, and the marker-bit contiguity rule that decides when a unit is
//! whole. None of it reads a payload byte.
//!
//! What it cannot decide for itself is supplied by a [`RealtimeUnitFraming`]
//! implementation: whether a payload can *begin* a unit, how a contiguous
//! fragment chain becomes one output unit, and whether that output is a
//! decoder entry point. Those are the only three questions here that have a
//! codec-specific answer, and each one is asked rather than assumed.

use super::*;

/// Opaque position of one fragment within a single unit's chain.
///
/// Ordering only, and only inside the unit that produced it. It is derived
/// from the unwrapped RTP sequence number, but a framing implementation cannot
/// read that number, do arithmetic on it, or carry one of these across units —
/// it can only hand a cursor back to [`UnitFragments::between`] to re-read a
/// run it has already walked.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct FragmentCursor(i64);

#[cfg(test)]
impl FragmentCursor {
    /// A cursor at a known sequence position, for controls that hand-build a
    /// fragment map rather than driving RTP packets through the assembler.
    ///
    /// Controls only: production cursors are minted by [`UnitFragments::iter`]
    /// over a chain the assembler has already proved contiguous, so nothing
    /// outside a control ever needs to name a position directly.
    pub(crate) fn for_test(sequence: i64) -> Self {
        Self(sequence)
    }
}

/// Borrowed view of exactly one unit's contiguous fragment chain.
///
/// The chain is already known to be complete — every sequence number from the
/// unit's first packet through its marker packet is present — so a framing
/// implementation never has to reason about holes, and never sees the storage
/// the assembler holds them in.
pub(crate) struct UnitFragments<'a> {
    parts: &'a std::collections::BTreeMap<i64, Bytes>,
    start: i64,
    end: i64,
}

impl<'a> UnitFragments<'a> {
    pub(crate) fn new(
        parts: &'a std::collections::BTreeMap<i64, Bytes>,
        start: FragmentCursor,
        end: FragmentCursor,
    ) -> Self {
        Self {
            parts,
            start: start.0,
            end: end.0,
        }
    }

    /// Every fragment of this unit, in sequence order, with its cursor.
    ///
    /// The map and the bounds are read out of `self` before the iterator is
    /// built, so the result borrows only the fragment storage and not this
    /// view — which is what lets a framing hold the iterator across its own
    /// calls back into [`Self::between`].
    pub(crate) fn iter(&self) -> impl Iterator<Item = (FragmentCursor, &'a Bytes)> + 'a {
        let parts = self.parts;
        let (start, end) = (self.start, self.end);
        parts
            .range(start..=end)
            .map(|(&sequence, payload)| (FragmentCursor(sequence), payload))
    }

    /// The fragments from `from` through `to`, inclusive and clamped to this
    /// unit, for a framing whose output depends on a run it has already
    /// walked — a fragmented payload copied only once its end is seen.
    ///
    /// An inverted or out-of-unit range yields nothing rather than panicking,
    /// so a framing implementation cannot turn a cursor mistake into an abort
    /// on the inbound path.
    pub(crate) fn between(
        &self,
        from: FragmentCursor,
        to: FragmentCursor,
    ) -> impl Iterator<Item = &'a Bytes> + 'a {
        let parts = self.parts;
        let low = from.0.max(self.start);
        let high = to.0.min(self.end);
        (low <= high)
            .then(move || parts.range(low..=high))
            .into_iter()
            .flatten()
            .map(|(_, payload)| payload)
    }
}

/// The codec-specific half of unit assembly.
///
/// Deliberately three questions and a ceiling, not a pipeline: the assembler
/// owns when a unit is whole, and an implementation of this trait owns only
/// what the bytes mean.
///
/// Crate-internal for now. It becomes the application-facing profile seam once
/// the two alpha applications' framing needs are confirmed; publishing it
/// before then would fix a shape against one codec's requirements.
pub(crate) trait RealtimeUnitFraming: Send + Sync {
    /// Whether this payload can be the *first* packet of a unit.
    ///
    /// Asked only when the assembler has no anchor — at stream start, or after
    /// a unit was abandoned — to decide whether the lowest fragment it holds
    /// begins a unit or is a mid-unit tail that should wait for the next one.
    /// A framing that answers `true` unconditionally gets headless units after
    /// loss; that is the cost of the answer, and it is the framing's to pay.
    fn payload_starts_unit(&self, payload: &Bytes) -> bool;

    /// Validate the chain and answer the exact output length, allocating no
    /// output storage.
    ///
    /// Phase one of two, and the split is load-bearing rather than stylistic:
    /// the assembler acquires the complete-output resource claim against this
    /// number *before* any output buffer exists. Collapsing the two phases
    /// into one call that returns bytes would allocate the output before it
    /// was accounted for, which is the accounting the reservation system
    /// exists to make exact.
    fn framed_len(&self, fragments: UnitFragments<'_>) -> Result<usize>;

    /// Build the output that [`Self::framed_len`] validated and measured.
    ///
    /// Phase two. It is given the length its own first phase answered, so a
    /// framing that produces a different one can say so rather than silently
    /// exceeding the claim already granted for it.
    fn write_framed(&self, fragments: UnitFragments<'_>, framed_len: usize) -> Result<Vec<u8>>;

    /// Whether the assembled unit is a decoder entry point — a unit a receiver
    /// can begin decoding from without prior units.
    ///
    /// Advisory. Nothing in the assembler branches on it; it travels with the
    /// unit for whoever consumes it.
    fn is_entry_point(&self, framed: &[u8]) -> bool;
}

/// One complete unit, with the output claim that covers its bytes.
pub(crate) struct AssembledUnit {
    pub(crate) rtp_timestamp: u32,
    pub(crate) entry_point: bool,
    pub(crate) data: Bytes,
    pub(crate) output: Option<RealtimeOutputReservation>,
}

/// Reassembles units from RTP, loss- and reorder-aware: payloads collect per
/// RTP timestamp keyed by *unwrapped sequence number*, and a unit is emitted
/// only when the chain from its first packet to its marker packet is
/// **contiguous** — so a packet lost mid-unit can never splice the survivors
/// into a corrupt unit that reaches a decoder (the bug shape: at streaming
/// bitrates a keyframe spans hundreds of packets, and one hole per keyframe
/// means a decode error every time). A hole simply waits — the NACK
/// interceptor's retransmit fills it out of order and the unit still emits —
/// and a unit whose hole never fills is dropped whole when the next timestamp
/// arrives. Late retransmits of an abandoned unit can't clobber the live one.
/// Framing runs per unit in sequence order over a chain already known to be
/// complete, so fragment state never straddles a loss.
pub(crate) struct RealtimeUnitAssembler {
    /// RTP timestamp of the unit being collected.
    timestamp: u32,
    /// Unwrapped seq → raw RTP payload, for the current timestamp only.
    parts: std::collections::BTreeMap<i64, Bytes>,
    /// Unwrapped seq of the current unit's marker packet, once seen.
    marker_seq: Option<i64>,
    /// Unwrapped seq of the last *emitted* unit's marker — the next unit must
    /// start at exactly +1, which is what makes the contiguity check exact.
    /// `None` after an abandoned unit (the anchor is lost); the next unit then
    /// re-anchors on a payload the framing says *starts* a unit.
    prev_end: Option<i64>,
    /// Sequence unwrapper state: (last raw seq, its unwrapped value).
    last_seq: Option<(u16, i64)>,
    /// The flow whose envelope this assembler accounts against, **weakly**.
    ///
    /// A strong port here would be a second owner of the flow's one active-flow
    /// lease, held for as long as the pump ran — so closing the flow would
    /// release its label and its queue but not its registry slot, and the
    /// capacity would come back only when the peer stopped sending. Upgraded per
    /// fragment instead; the reservation that comes out holds the flow strongly
    /// for the in-progress unit, which is the one window where it must not
    /// vanish under work already accounted for.
    flow: Option<RealtimeFlowPortHandle>,
    assembly: Option<RealtimeAssemblyReservation>,
    framing: Arc<dyn RealtimeUnitFraming>,
}

impl RealtimeUnitAssembler {
    /// The shared empty state. Private, because an assembler's retention bound
    /// comes entirely from the flow it accounts against: the two constructors
    /// below differ only in whether they supply one, and that difference is the
    /// whole of the difference between bounded and unbounded.
    fn empty(framing: Arc<dyn RealtimeUnitFraming>) -> Self {
        Self {
            timestamp: 0,
            parts: std::collections::BTreeMap::new(),
            marker_seq: None,
            prev_end: None,
            last_seq: None,
            flow: None,
            assembly: None,
            framing,
        }
    }

    /// An assembler with no flow, and so no resource accounting at all.
    ///
    /// `#[cfg(test)]` deliberately. Retention is bounded by the flow's own
    /// fragment admission and by nothing else, so an assembler without a flow
    /// is an assembler without a bound — it will retain whatever a peer sends
    /// for one timestamp. That is acceptable for a control feeding it a
    /// scripted packet sequence and is not acceptable anywhere a peer chooses
    /// the input, so the production path cannot construct one: the compiler
    /// enforces that rather than a comment asking.
    #[cfg(test)]
    pub(crate) fn new(framing: Arc<dyn RealtimeUnitFraming>) -> Self {
        Self::empty(framing)
    }

    /// The production constructor: every fragment is admitted against `flow`.
    pub(crate) fn guarded(
        framing: Arc<dyn RealtimeUnitFraming>,
        flow: RealtimeFlowPortHandle,
    ) -> Self {
        Self {
            flow: Some(flow),
            ..Self::empty(framing)
        }
    }

    /// How many fragments of an incomplete unit are currently retained.
    ///
    /// Observation only, for controls that assert an abandoned unit really was
    /// dropped rather than left holding memory. No production path asks, so it
    /// is not compiled into one.
    #[cfg(test)]
    pub(crate) fn fragments_held(&self) -> usize {
        self.parts.len()
    }

    pub(crate) fn push(
        &mut self,
        pkt: &webrtc::rtp::packet::Packet,
    ) -> Result<Option<AssembledUnit>> {
        if pkt.payload.is_empty() {
            return Ok(None); // padding / probe
        }
        // Read *before* `unwrap_seq`, which is what initialises `last_seq`.
        // This is the only signal that separates "this assembler has never
        // seen a packet" from "it has, and this one is older", and the two
        // need opposite answers below.
        let uninitialised = self.last_seq.is_none();
        let seq = self.unwrap_seq(pkt.header.sequence_number);
        let ts = pkt.header.timestamp;
        if ts != self.timestamp {
            // Deliberately **not** `self.parts.is_empty()`. `try_emit` clears
            // `parts` on every successful emit, so that test is true in exactly
            // the steady state between units — and a late retransmit of the
            // unit just emitted would then pass it, rewind `self.timestamp` to
            // the older value, and be inserted as if it began a new unit. The
            // next genuine packet would find `parts` non-empty, discard
            // `prev_end` as an abandoned unit, and force the following unit to
            // re-anchor through `payload_starts_unit` — so one stale
            // retransmit after an emit costs the anchor and usually the next
            // unit too.
            //
            // The uninitialised case still has to advance, and cannot be
            // folded into the comparison: `self.timestamp` starts at 0 while a
            // real stream picks a random initial RTP timestamp, so roughly half
            // of all streams would have their first packet read as "older than
            // zero" and every subsequent one rejected with it.
            if uninitialised || newer_rtp_ts(ts, self.timestamp) {
                // The next unit begins; an unfinished current one is dropped
                // whole (its hole is now hopeless) and the exact start anchor
                // is gone with it.
                if !self.parts.is_empty() {
                    self.prev_end = None;
                }
                self.clear_current();
                self.marker_seq = None;
                self.timestamp = ts;
            } else {
                // An older timestamp on an initialised assembler is a late
                // retransmit — of a unit already emitted, or of one already
                // abandoned. Either way it belongs to no unit this assembler
                // is still collecting, and the anchor it would disturb is one
                // the live stream still needs.
                return Ok(None);
            }
        }
        if self.parts.contains_key(&seq) {
            if pkt.header.marker {
                self.marker_seq = Some(seq);
            }
            return self.try_emit();
        }
        if let Some(flow) = self.flow.as_ref() {
            // A closed flow answers `None` here, and the fragment goes with its
            // state. That is the same response as a refused reservation, for the
            // same reason: there is nothing left to account it against.
            let Some(port) = flow.port() else {
                self.clear_current();
                return Ok(None);
            };
            if self.assembly.is_none() {
                self.assembly = port.begin_unit();
            }
            let Some(assembly) = self.assembly.as_mut() else {
                self.clear_current();
                return Ok(None);
            };
            if !assembly.retain_ordered_fragment(pkt.payload.len()) {
                self.clear_current();
                self.prev_end = None;
                return Err(Error::Transport(
                    "real-time unit exceeded its owner-selected byte envelope".into(),
                ));
            }
        }
        self.parts.insert(seq, pkt.payload.clone());
        if pkt.header.marker {
            self.marker_seq = Some(seq);
        }
        self.try_emit()
    }

    fn clear_current(&mut self) {
        self.parts.clear();
        self.assembly = None;
    }

    fn try_emit(&mut self) -> Result<Option<AssembledUnit>> {
        // Held for the whole emit so the framing calls below borrow nothing of
        // `self`, which is what lets the failure paths clear state in place.
        let framing = Arc::clone(&self.framing);
        let Some(end) = self.marker_seq else {
            return Ok(None);
        };
        let start = match self.prev_end {
            Some(prev) => prev + 1,
            None => {
                // No anchor (stream start, or the previous unit was
                // abandoned): accept the lowest packet we hold only if the
                // framing says it plausibly *begins* a unit — a mid-unit join
                // waits for the next one instead of emitting a headless tail.
                let Some((&lo, first)) = self.parts.iter().next() else {
                    return Ok(None);
                };
                if !framing.payload_starts_unit(first) {
                    return Ok(None);
                }
                lo
            }
        };
        if end < start {
            return Ok(None); // a stale marker from before the anchor
        }
        let need = (end - start + 1) as usize;
        if self.parts.range(start..=end).count() < need {
            return Ok(None); // a hole — wait for the retransmit
        }
        let span = (FragmentCursor(start), FragmentCursor(end));
        let framed_len = match framing.framed_len(UnitFragments::new(&self.parts, span.0, span.1)) {
            Ok(framed_len) => framed_len,
            Err(error) => {
                self.prev_end = Some(end);
                self.clear_current();
                self.marker_seq = None;
                return Err(error);
            }
        };
        // Acquire the exact complete-output claim before allocating any output
        // storage. The provider owns the logical bytes and one opaque residual
        // covers allocator-managed storage beyond that logical length.
        let output = match self.flow.as_ref() {
            // Upgraded here, not held from the fragment that started this unit.
            // A flow that closed mid-assembly takes the same exit as a refused
            // reservation, and it has to: there is no envelope left to charge
            // the output to, and the anchor is dropped so the next unit
            // re-anchors rather than continuing a chain the flow no longer has.
            Some(flow) if framed_len != 0 => {
                match flow.port().and_then(|port| port.reserve_output(framed_len)) {
                    Some(output) => Some(output),
                    None => {
                        self.clear_current();
                        self.marker_seq = None;
                        self.prev_end = None;
                        return Ok(None);
                    }
                }
            }
            _ => None,
        };
        let data =
            framing.write_framed(UnitFragments::new(&self.parts, span.0, span.1), framed_len);
        // Either way this unit is consumed and the next one anchors right
        // after it.
        self.prev_end = Some(end);
        self.clear_current();
        self.marker_seq = None;
        let data = data?;
        if data.is_empty() {
            return Ok(None);
        }
        let data = Bytes::from(data);
        Ok(Some(AssembledUnit {
            rtp_timestamp: self.timestamp,
            entry_point: framing.is_entry_point(&data),
            data,
            output,
        }))
    }

    /// Map a raw 16-bit RTP sequence number onto an unbounded line, so
    /// ordering survives wraparound. The anchor only advances forward; older
    /// arrivals (retransmits) resolve to their original position.
    fn unwrap_seq(&mut self, raw: u16) -> i64 {
        match self.last_seq {
            None => {
                let unwrapped = i64::from(raw);
                self.last_seq = Some((raw, unwrapped));
                unwrapped
            }
            Some((last_raw, last_unwrapped)) => {
                let delta = i64::from(raw.wrapping_sub(last_raw) as i16);
                let unwrapped = last_unwrapped + delta;
                if delta > 0 {
                    self.last_seq = Some((raw, unwrapped));
                }
                unwrapped
            }
        }
    }
}

/// RTP timestamp `a` is newer than `b` (mod 2³², shortest distance).
///
/// `pub(super)` only so a control can state which side of the wrap point its
/// fixture timestamp falls on. A stream-start control that merely *assumed*
/// its fixture was past the wrap would pass whether or not the uninitialised
/// case in [`RealtimeUnitAssembler::push`] still exists.
pub(super) fn newer_rtp_ts(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < u32::MAX / 2
}
