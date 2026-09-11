//! H.264 Annex-B framing for the codec-neutral unit assembler.
//!
//! One implementation of [`RealtimeUnitFraming`], selected when an application
//! registers a codec whose framing strategy is `AnnexB`. It is named for the
//! codec it implements the fragmentation of, and it is reached by that
//! registered strategy — never by anything here recognising a MIME name.
//!
//! What is left here is only what is true of H.264: Annex-B start codes, NAL
//! type meaning, STAP-A aggregation, FU-A fragmentation, and the IDR test that
//! marks a decoder entry point. The loss- and reorder-aware assembly that used
//! to sit alongside it is codec-neutral RTP machinery and now lives in
//! [`super::unit_assembly`]; this module supplies that assembler with the four
//! answers only a codec can give, through [`RealtimeUnitFraming`].
//!
//! Nothing about the assembly behaviour changed in that move. The functions
//! below are the same ones, reading the same bytes, in the same order.

use super::*;

/// The H.264 answers to the codec-specific questions unit assembly asks.
///
/// A unit struct because H.264 framing is fully determined by the standard —
/// there is no per-connection state to carry, and no owner-selected value that
/// belongs here rather than in the profile.
pub(super) struct H264Framing;

impl RealtimeUnitFraming for H264Framing {
    fn payload_starts_unit(&self, payload: &Bytes) -> bool {
        payload_starts_au(payload)
    }

    fn framed_len(&self, fragments: UnitFragments<'_>) -> Result<usize> {
        annexb_output_len(fragments)
    }

    fn write_framed(&self, fragments: UnitFragments<'_>, framed_len: usize) -> Result<Vec<u8>> {
        write_annexb_output(fragments, framed_len)
    }

    fn is_entry_point(&self, framed: &[u8]) -> bool {
        au_has_idr(framed)
    }
}

const ANNEXB_START_CODE: [u8; 4] = [0, 0, 0, 1];

fn output_length_overflow() -> Error {
    Error::Transport("video unit output length overflowed".into())
}

fn add_output_len(total: usize, bytes: usize) -> Result<usize> {
    total.checked_add(bytes).ok_or_else(output_length_overflow)
}

/// Validate the exact webrtc-rs H.264 compatibility shape and compute the
/// complete Annex-B output length without allocating output storage.
fn annexb_output_len(fragments: UnitFragments<'_>) -> Result<usize> {
    let mut output_len = 0usize;
    let mut fua_content_bytes = None;
    for (_, payload) in fragments.iter() {
        if payload.len() <= 2 {
            return Err(Error::Transport("h264 depacketize: short packet".into()));
        }
        match payload[0] & 0x1f {
            1..=23 => {
                output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                output_len = add_output_len(output_len, payload.len())?;
            }
            24 => {
                let mut offset = 1usize;
                while offset < payload.len() {
                    let length_end = offset.checked_add(2).ok_or_else(output_length_overflow)?;
                    if length_end > payload.len() {
                        return Err(Error::Transport(
                            "h264 depacketize: truncated STAP-A length".into(),
                        ));
                    }
                    let nalu_len =
                        (usize::from(payload[offset]) << 8) | usize::from(payload[offset + 1]);
                    let nalu_end = length_end
                        .checked_add(nalu_len)
                        .ok_or_else(output_length_overflow)?;
                    if nalu_end > payload.len() {
                        return Err(Error::Transport(
                            "h264 depacketize: STAP-A unit exceeds packet".into(),
                        ));
                    }
                    output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                    output_len = add_output_len(output_len, nalu_len)?;
                    offset = nalu_end;
                }
            }
            28 => {
                let accumulated = fua_content_bytes
                    .unwrap_or(0usize)
                    .checked_add(payload.len() - 2)
                    .ok_or_else(output_length_overflow)?;
                if payload[1] & 0x40 != 0 {
                    output_len = add_output_len(output_len, ANNEXB_START_CODE.len())?;
                    output_len = add_output_len(output_len, 1)?;
                    output_len = add_output_len(output_len, accumulated)?;
                    fua_content_bytes = None;
                } else {
                    fua_content_bytes = Some(accumulated);
                }
            }
            nalu_type => {
                return Err(Error::Transport(format!(
                    "h264 depacketize: NAL type {nalu_type} is not handled"
                )));
            }
        }
    }
    Ok(output_len)
}

/// Build the exact output validated by `annexb_output_len`. FU-A contents are
/// copied only when their end fragment is encountered, matching webrtc-rs
/// ordering without retaining a second dependency-owned assembly buffer.
fn write_annexb_output(fragments: UnitFragments<'_>, output_len: usize) -> Result<Vec<u8>> {
    let mut output = Vec::with_capacity(output_len);
    let mut fua_start = None;
    for (cursor, payload) in fragments.iter() {
        match payload[0] & 0x1f {
            1..=23 => {
                output.extend_from_slice(&ANNEXB_START_CODE);
                output.extend_from_slice(payload);
            }
            24 => {
                let mut offset = 1usize;
                while offset < payload.len() {
                    let nalu_len =
                        (usize::from(payload[offset]) << 8) | usize::from(payload[offset + 1]);
                    offset += 2;
                    let nalu_end = offset + nalu_len;
                    output.extend_from_slice(&ANNEXB_START_CODE);
                    output.extend_from_slice(&payload[offset..nalu_end]);
                    offset = nalu_end;
                }
            }
            28 => {
                let chain_start = *fua_start.get_or_insert(cursor);
                if payload[1] & 0x40 != 0 {
                    output.extend_from_slice(&ANNEXB_START_CODE);
                    output.push((payload[0] & 0x60) | (payload[1] & 0x1f));
                    for fragment in fragments.between(chain_start, cursor) {
                        if fragment[0] & 0x1f == 28 {
                            output.extend_from_slice(&fragment[2..]);
                        }
                    }
                    fua_start = None;
                }
            }
            _ => {
                return Err(Error::Transport(
                    "validated H.264 payload changed during assembly".into(),
                ));
            }
        }
    }
    if output.len() != output_len {
        return Err(Error::Transport(
            "validated H.264 output length changed during assembly".into(),
        ));
    }
    Ok(output)
}

/// Whether an RTP payload can be the *first* packet of an access unit:
/// a single NAL (types 1–23), a STAP-A aggregate (24), or an **FU-A**
/// fragment (28) with its start bit set. Mid-unit fragments fail, and so
/// does FU-B (29) — see the refusal argued at that arm below.
pub(super) fn payload_starts_au(payload: &Bytes) -> bool {
    let Some(&b0) = payload.first() else {
        return false;
    };
    match b0 & 0x1F {
        1..=23 => true,
        24 => true,
        // FU-A only. Type 29 is FU-B, and this side cannot frame one:
        // `annexb_output_len` handles 1..=23, 24 and 28 and returns an error
        // for everything else, so admitting an FU-B as an anchor would anchor
        // every such unit onto a chain the framing then always rejects. The
        // cost is not one refused packet — `try_emit` treats a framing error
        // as a consumed unit, so the whole unit is lost and the next one
        // re-anchors, for as long as the peer keeps sending FU-B.
        //
        // Refusing it as an anchor is the smallest correct answer: the
        // assembler simply waits for a payload it can actually frame, rather
        // than claiming one it cannot. Supporting FU-B would mean teaching
        // `annexb_output_len` and `write_annexb_output` its two-byte DON
        // header, and nothing deployed here sends it.
        28 => payload.get(1).is_some_and(|b1| b1 & 0x80 != 0),
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

#[cfg(test)]
mod exact_output_tests {
    use super::*;
    use webrtc::rtp::packetizer::Depacketizer;

    /// Span the whole of a hand-built fragment map, the way the assembler
    /// spans a complete chain.
    fn whole(
        parts: &std::collections::BTreeMap<i64, Bytes>,
    ) -> Option<(FragmentCursor, FragmentCursor)> {
        let start = *parts.keys().next()?;
        let end = *parts.keys().next_back()?;
        Some((
            FragmentCursor::for_test(start),
            FragmentCursor::for_test(end),
        ))
    }

    #[test]
    fn planned_output_exactly_matches_single_stap_and_fu_assembly() {
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(1, Bytes::from_static(&[0x65, 0x11, 0x12]));
        parts.insert(
            2,
            Bytes::from_static(&[0x78, 0x00, 0x02, 0x67, 0x21, 0x00, 0x03, 0x68, 0x31, 0x32]),
        );
        parts.insert(3, Bytes::from_static(&[0x7c, 0x85, 0x41]));
        parts.insert(4, Bytes::from_static(&[0x7c, 0x45, 0x42]));

        let (start, end) = whole(&parts).expect("the test unit is non-empty");
        let planned = annexb_output_len(UnitFragments::new(&parts, start, end))
            .expect("the test unit is valid");
        let output = write_annexb_output(UnitFragments::new(&parts, start, end), planned)
            .expect("the validated unit is stable");
        let mut dependency = webrtc::rtp::codecs::h264::H264Packet::default();
        let mut dependency_output = Vec::new();
        for payload in parts.values() {
            dependency_output.extend_from_slice(
                &dependency
                    .depacketize(payload)
                    .expect("the dependency accepts the test unit"),
            );
        }
        assert_eq!(output.len(), planned);
        assert_eq!(output, dependency_output);
        assert_eq!(
            output,
            [
                &[0, 0, 0, 1, 0x65, 0x11, 0x12][..],
                &[0, 0, 0, 1, 0x67, 0x21][..],
                &[0, 0, 0, 1, 0x68, 0x31, 0x32][..],
                &[0, 0, 0, 1, 0x65, 0x41, 0x42][..],
            ]
            .concat()
        );
    }

    #[test]
    fn malformed_stap_is_rejected_before_output_allocation() {
        let mut parts = std::collections::BTreeMap::new();
        parts.insert(1, Bytes::from_static(&[0x78, 0x00, 0x04, 0x67]));
        let (start, end) = whole(&parts).expect("the test unit is non-empty");
        assert!(annexb_output_len(UnitFragments::new(&parts, start, end)).is_err());
    }
}
