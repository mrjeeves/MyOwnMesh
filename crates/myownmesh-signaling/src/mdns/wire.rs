//! Pure wire-format logic for the mDNS signaling driver: the DNS-SD
//! service shape (type, instance naming, TXT records) and the JSON
//! frame exchanged over the unicast TCP connection that carries the
//! SDP/candidate traffic (far too large for TXT records).
//!
//! Everything here is deterministic and socket-free so it can be unit
//! tested in any environment, including CI containers with no
//! multicast. The socket lifecycle lives in [`super::driver`].

use serde::{Deserialize, Serialize};

use crate::SignalingMessage;

/// DNS-SD service type every MyOwnMesh mDNS driver registers and
/// browses. One type for all networks — the TXT `room` record is the
/// authoritative network discriminator, mirroring how the Nostr
/// driver scopes a relay subscription by room tag.
pub const SERVICE_TYPE: &str = "_myownmesh._tcp.local.";

/// mDNS claim-signaling protocol version, carried in TXT `v` and in
/// every TCP frame. Bump on incompatible changes; receivers drop
/// frames/records from other versions.
pub const PROTOCOL_VERSION: u8 = 1;

/// TXT record keys.
pub const TXT_VERSION: &str = "v";
pub const TXT_ROOM: &str = "room";
pub const TXT_PEER: &str = "peer";

/// Upper bound on one TCP frame line. An SDP with a full candidate
/// set is a few KB; 256 KiB is far above any legitimate payload while
/// bounding what a misbehaving LAN peer can make us buffer.
pub const MAX_FRAME_BYTES: usize = 256 * 1024;

/// DNS-SD instance name for our registration. DNS labels cap at 63
/// bytes, so the 64-hex room handle cannot be the instance name —
/// truncated prefixes of the room and device id keep the label short
/// and unique-in-practice, and the full values ride in TXT (which is
/// authoritative for matching). Collisions only cost an mDNS
/// name-conflict rename, never a mis-match.
pub fn instance_name(room_handle: &str, device_id: &str) -> String {
    format!(
        "mom-{}-{}",
        sanitize_label(room_handle, 8),
        sanitize_label(device_id, 8)
    )
}

/// Keep at most `n` leading `[a-z0-9]` characters (lowercased) so the
/// result is always a valid DNS-label fragment.
fn sanitize_label(s: &str, n: usize) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_lowercase())
        .take(n)
        .collect()
}

/// TXT properties for our registration.
pub fn txt_properties(room_handle: &str, device_id: &str) -> Vec<(String, String)> {
    vec![
        (TXT_VERSION.into(), PROTOCOL_VERSION.to_string()),
        (TXT_ROOM.into(), room_handle.to_string()),
        (TXT_PEER.into(), device_id.to_string()),
    ]
}

/// A resolved peer advertisement, parsed out of TXT records.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerAdvert {
    pub room: String,
    pub peer: String,
}

/// Parse and validate the TXT side of a resolved service. Returns
/// `None` for records that aren't ours to act on: wrong protocol
/// version, a different room, or our own registration echoed back.
pub fn parse_advert(
    txt: impl Fn(&str) -> Option<String>,
    our_room: &str,
    our_device_id: &str,
) -> Option<PeerAdvert> {
    let v = txt(TXT_VERSION)?;
    if v != PROTOCOL_VERSION.to_string() {
        return None;
    }
    let room = txt(TXT_ROOM)?;
    if room != our_room {
        return None;
    }
    let peer = txt(TXT_PEER)?;
    if peer.is_empty() || peer == our_device_id {
        return None;
    }
    Some(PeerAdvert { room, peer })
}

/// One newline-delimited JSON frame on the unicast TCP exchange.
///
/// Trust model: identical to a public Nostr room — anything on the
/// LAN can send these, so nothing here is authenticated. The engine's
/// ed25519 mutual-auth handshake over the DTLS channel the SDP
/// bootstraps remains the real gate; a forged frame can at worst
/// waste a handshake attempt.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Frame {
    pub v: u8,
    /// Room handle — receivers drop frames for rooms they aren't in,
    /// so one listener port never leaks traffic across networks.
    pub room: String,
    pub from: String,
    pub to: String,
    pub msg: SignalingMessage,
}

/// Encode a frame as one JSON line (no trailing newline — the writer
/// appends it, the reader strips it).
pub fn encode_frame(frame: &Frame) -> String {
    serde_json::to_string(frame).expect("frame serializes")
}

/// Decode one line into a frame. Callers should have already bounded
/// the line length at [`MAX_FRAME_BYTES`].
pub fn decode_frame(line: &str) -> Result<Frame, serde_json::Error> {
    serde_json::from_str(line)
}

/// Whether an inbound frame should be delivered to the engine:
/// protocol version, room, and recipient must all match.
pub fn frame_is_for_us(frame: &Frame, our_room: &str, our_device_id: &str) -> bool {
    frame.v == PROTOCOL_VERSION && frame.room == our_room && frame.to == our_device_id
}

#[cfg(test)]
mod tests {
    use super::*;

    fn txt_of<'a>(pairs: &'a [(&'a str, &'a str)]) -> impl Fn(&str) -> Option<String> + 'a {
        move |k| {
            pairs
                .iter()
                .find(|(key, _)| *key == k)
                .map(|(_, v)| v.to_string())
        }
    }

    #[test]
    fn instance_name_fits_dns_label_and_sanitizes() {
        let room = "AB12cd34ef56aa77bb88cc99dd00ee11ff22aa33bb44cc55dd66ee77ff88aa99";
        let dev = "PubKey!!-With-Junk-0123456789abcdef";
        let name = instance_name(room, dev);
        assert_eq!(name, "mom-ab12cd34-pubkeywi");
        assert!(name.len() <= 63, "instance name must fit one DNS label");
    }

    #[test]
    fn advert_parses_when_room_and_version_match() {
        let txt = txt_of(&[("v", "1"), ("room", "roomA"), ("peer", "peer-1")]);
        let advert = parse_advert(txt, "roomA", "self").expect("valid advert");
        assert_eq!(
            advert,
            PeerAdvert {
                room: "roomA".into(),
                peer: "peer-1".into()
            }
        );
    }

    #[test]
    fn advert_rejects_other_room_own_echo_and_bad_version() {
        // Different room — a co-located device on another network.
        assert!(parse_advert(
            txt_of(&[("v", "1"), ("room", "roomB"), ("peer", "peer-1")]),
            "roomA",
            "self"
        )
        .is_none());
        // Our own registration echoed back by the daemon.
        assert!(parse_advert(
            txt_of(&[("v", "1"), ("room", "roomA"), ("peer", "self")]),
            "roomA",
            "self"
        )
        .is_none());
        // Future protocol version.
        assert!(parse_advert(
            txt_of(&[("v", "2"), ("room", "roomA"), ("peer", "peer-1")]),
            "roomA",
            "self"
        )
        .is_none());
        // Missing keys entirely.
        assert!(parse_advert(txt_of(&[("v", "1")]), "roomA", "self").is_none());
    }

    #[test]
    fn frame_round_trips_with_signaling_message() {
        let frame = Frame {
            v: PROTOCOL_VERSION,
            room: "roomA".into(),
            from: "peer-1".into(),
            to: "peer-2".into(),
            msg: SignalingMessage::Offer {
                peer_id: "peer-1".into(),
                offer_id: "off-1".into(),
                sdp: "v=0\r\no=- 42 2 IN IP4 127.0.0.1\r\n".into(),
            },
        };
        let line = encode_frame(&frame);
        assert!(!line.contains('\n'), "frame must be a single line");
        let back = decode_frame(&line).expect("decodes");
        assert_eq!(back, frame);
    }

    #[test]
    fn frame_wire_shape_is_stable() {
        // The `msg` field carries the existing SignalingMessage serde
        // shape (tag = "kind") — the same bytes the Nostr envelope
        // uses, so the two transports never drift.
        let frame = Frame {
            v: 1,
            room: "r".into(),
            from: "a".into(),
            to: "b".into(),
            msg: SignalingMessage::Announce {
                peer_id: "a".into(),
            },
        };
        let value: serde_json::Value = serde_json::from_str(&encode_frame(&frame)).unwrap();
        assert_eq!(value["v"], 1);
        assert_eq!(value["room"], "r");
        assert_eq!(value["msg"]["kind"], "announce");
        assert_eq!(value["msg"]["peer_id"], "a");
    }

    #[test]
    fn frames_for_other_recipients_rooms_or_versions_are_dropped() {
        let mut frame = Frame {
            v: PROTOCOL_VERSION,
            room: "roomA".into(),
            from: "peer-1".into(),
            to: "peer-2".into(),
            msg: SignalingMessage::Announce {
                peer_id: "peer-1".into(),
            },
        };
        assert!(frame_is_for_us(&frame, "roomA", "peer-2"));
        assert!(!frame_is_for_us(&frame, "roomA", "peer-3"), "wrong to");
        assert!(!frame_is_for_us(&frame, "roomB", "peer-2"), "wrong room");
        frame.v = 99;
        assert!(!frame_is_for_us(&frame, "roomA", "peer-2"), "wrong version");
    }
}
