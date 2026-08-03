#![allow(
    deprecated,
    reason = "this module is the frozen H.264 compatibility implementation"
)]

//! Structurally bounded H.264 compatibility assembly.

use super::*;

/// Reassembles H.264 access units from RTP, loss- and reorder-aware:
/// payloads collect per RTP timestamp keyed by *unwrapped sequence
/// number*, and a unit is emitted only when the chain from its first
/// packet to its marker packet is **contiguous** — so a packet lost
/// mid-unit can never splice the survivors into a corrupt unit that
/// reaches a decoder (the bug shape: at streaming bitrates a keyframe
/// spans hundreds of packets, and one hole per keyframe means a decode
/// error every time). A hole simply waits — the NACK interceptor's
/// retransmit fills it out of order and the unit still emits — and a
/// unit whose hole never fills is dropped whole when the next timestamp
/// arrives. Late retransmits of an abandoned unit can't clobber the
/// live one. Depacketization runs per-unit in sequence order, so FU-A
/// fragment state never straddles a loss.
#[derive(Default)]
pub(super) struct H264AuAssembler {
    /// RTP timestamp of the unit being collected.
    timestamp: u32,
    /// Unwrapped seq → raw RTP payload, for the current timestamp only.
    pub(super) parts: std::collections::BTreeMap<i64, Bytes>,
    /// Unwrapped seq of the current unit's marker packet, once seen.
    marker_seq: Option<i64>,
    /// Unwrapped seq of the last *emitted* unit's marker — the next unit
    /// must start at exactly +1, which is what makes the contiguity
    /// check exact. `None` after an abandoned unit (the anchor is lost);
    /// the next unit then re-anchors on a payload that *starts* an AU.
    prev_end: Option<i64>,
    /// Sequence unwrapper state: (last raw seq, its unwrapped value).
    last_seq: Option<(u16, i64)>,
    flow: Option<RealtimeFlowPort>,
    assembly: Option<RealtimeAssemblyReservation>,
}

pub(super) struct GuardedVideoSample {
    pub(super) sample: VideoSample,
    pub(super) output: Option<RealtimeOutputReservation>,
}

/// More packets than any sane unit (a 40 Mbps keyframe is ~400): a unit
/// this size means the stream is wedged — drop it rather than balloon.
pub(super) const MAX_AU_PARTS: usize = 2048;

impl H264AuAssembler {
    pub(super) fn guarded(flow: RealtimeFlowPort) -> Self {
        Self {
            flow: Some(flow),
            ..Self::default()
        }
    }

    #[cfg(test)]
    pub(super) fn push(
        &mut self,
        pkt: &webrtc::rtp::packet::Packet,
    ) -> Result<Option<VideoSample>> {
        self.push_guarded(pkt)
            .map(|sample| sample.map(|sample| sample.sample))
    }

    pub(super) fn push_guarded(
        &mut self,
        pkt: &webrtc::rtp::packet::Packet,
    ) -> Result<Option<GuardedVideoSample>> {
        if pkt.payload.is_empty() {
            return Ok(None); // padding / probe
        }
        let seq = self.unwrap_seq(pkt.header.sequence_number);
        let ts = pkt.header.timestamp;
        if ts != self.timestamp {
            if self.parts.is_empty() || newer_rtp_ts(ts, self.timestamp) {
                // The next unit begins; an unfinished current one is
                // dropped whole (its hole is now hopeless) and the exact
                // start anchor is gone with it.
                if !self.parts.is_empty() {
                    self.prev_end = None;
                }
                self.clear_current();
                self.marker_seq = None;
                self.timestamp = ts;
            } else {
                // A late retransmit of a unit we already abandoned —
                // never let it wipe the one being collected.
                return Ok(None);
            }
        }
        if self.parts.len() >= MAX_AU_PARTS {
            self.clear_current();
            self.marker_seq = None;
            self.prev_end = None;
            return Err(Error::Transport("video unit overflowed reassembly".into()));
        }
        if self.parts.contains_key(&seq) {
            if pkt.header.marker {
                self.marker_seq = Some(seq);
            }
            return self.try_emit_guarded();
        }
        if let Some(flow) = self.flow.as_ref() {
            if self.assembly.is_none() {
                self.assembly = flow.begin_unit();
            }
            let Some(assembly) = self.assembly.as_mut() else {
                self.clear_current();
                return Ok(None);
            };
            if !assembly.retain_fragment(pkt.payload.len()) {
                self.clear_current();
                self.prev_end = None;
                return Err(Error::Transport(
                    "video unit exceeded its owner-selected byte envelope".into(),
                ));
            }
        }
        self.parts.insert(seq, pkt.payload.clone());
        if pkt.header.marker {
            self.marker_seq = Some(seq);
        }
        self.try_emit_guarded()
    }

    fn clear_current(&mut self) {
        self.parts.clear();
        self.assembly = None;
    }

    fn try_emit_guarded(&mut self) -> Result<Option<GuardedVideoSample>> {
        let Some(end) = self.marker_seq else {
            return Ok(None);
        };
        let start = match self.prev_end {
            Some(prev) => prev + 1,
            None => {
                // No anchor (stream start, or the previous unit was
                // abandoned): accept the lowest packet we hold only if it
                // plausibly *begins* a unit — a mid-unit join waits for
                // the next one instead of emitting a headless tail.
                let Some((&lo, first)) = self.parts.iter().next() else {
                    return Ok(None);
                };
                if !payload_starts_au(first) {
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
        // Reserve the full owner-selected output ceiling before the
        // depacketizer allocates. The reservation shrinks to the exact output
        // length before it enters the flow queue.
        let mut output = match self.flow.as_ref() {
            Some(flow) => match flow.reserve_output(flow.lifetime.registry.max_unit_bytes) {
                Some(output) => Some(output),
                None => {
                    self.clear_current();
                    self.marker_seq = None;
                    self.prev_end = None;
                    return Ok(None);
                }
            },
            None => None,
        };
        // Complete: depacketize in sequence order with fresh FU state.
        use webrtc::rtp::packetizer::Depacketizer;
        let mut depacketizer = webrtc::rtp::codecs::h264::H264Packet::default();
        let mut data = Vec::new();
        let mut failed = None;
        let output_limit = self
            .flow
            .as_ref()
            .map_or(usize::MAX, |flow| flow.lifetime.registry.max_unit_bytes);
        for (_, payload) in self.parts.range(start..=end) {
            match depacketizer.depacketize(payload) {
                Ok(part) => {
                    let Some(next_len) = data.len().checked_add(part.len()) else {
                        failed = Some("video unit output length overflowed".to_string());
                        break;
                    };
                    if next_len > output_limit {
                        failed =
                            Some("video unit exceeded its owner-selected output limit".to_string());
                        break;
                    }
                    data.extend_from_slice(&part);
                }
                Err(e) => {
                    failed = Some(format!("h264 depacketize: {e}"));
                    break;
                }
            }
        }
        // Either way this unit is consumed and the next one anchors
        // right after it.
        self.prev_end = Some(end);
        self.clear_current();
        self.marker_seq = None;
        if let Some(e) = failed {
            return Err(Error::Transport(e));
        }
        if data.is_empty() {
            return Ok(None);
        }
        if let Some(output) = output.as_mut() {
            if !output.shrink_to(data.len()) {
                return Err(Error::Transport(
                    "video output reservation could not represent the assembled unit".into(),
                ));
            }
        }
        let data = Bytes::from(data);
        Ok(Some(GuardedVideoSample {
            sample: VideoSample {
                rtp_timestamp: self.timestamp,
                key: au_has_idr(&data),
                // The pump that owns the track stamps the real lane; the
                // assembler is lane-agnostic.
                lane: 0,
                data,
                _reservation: None,
            },
            output,
        }))
    }

    /// Map a raw 16-bit RTP sequence number onto an unbounded line, so
    /// ordering survives wraparound. The anchor only advances forward;
    /// older arrivals (retransmits) resolve to their original position.
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
fn newer_rtp_ts(a: u32, b: u32) -> bool {
    a != b && a.wrapping_sub(b) < u32::MAX / 2
}

/// Whether an RTP payload can be the *first* packet of an access unit:
/// a single NAL (types 1–23), a STAP-A aggregate (24), or a fragment
/// with its start bit set (FU-A/FU-B, 28/29). Mid-unit fragments fail.
pub(super) fn payload_starts_au(payload: &Bytes) -> bool {
    let Some(&b0) = payload.first() else {
        return false;
    };
    match b0 & 0x1F {
        1..=23 => true,
        24 => true,
        28 | 29 => payload.get(1).is_some_and(|b1| b1 & 0x80 != 0),
        _ => false,
    }
}

/// Whether an Annex-B access unit contains an IDR slice (NAL type 5)
/// — a safe decoder entry point. (SPS/PPS ride along with IDRs but
/// don't make a frame decodable by themselves.)
pub(super) fn au_has_idr(data: &[u8]) -> bool {
    annexb_nal_types(data).any(|t| t == 5)
}

/// Iterate the NAL unit types of an Annex-B stream (both 3- and
/// 4-byte start codes).
pub(super) fn annexb_nal_types(data: &[u8]) -> impl Iterator<Item = u8> + '_ {
    let mut i = 0usize;
    std::iter::from_fn(move || {
        while i + 3 <= data.len() {
            if data[i] == 0 && data[i + 1] == 0 {
                if data[i + 2] == 1 {
                    if i + 3 < data.len() {
                        let t = data[i + 3] & 0x1F;
                        i += 4;
                        return Some(t);
                    }
                    i += 3;
                    continue;
                }
                if i + 4 <= data.len() && data[i + 2] == 0 && data[i + 3] == 1 {
                    if i + 4 < data.len() {
                        let t = data[i + 4] & 0x1F;
                        i += 5;
                        return Some(t);
                    }
                    i += 4;
                    continue;
                }
            }
            i += 1;
        }
        None
    })
}
