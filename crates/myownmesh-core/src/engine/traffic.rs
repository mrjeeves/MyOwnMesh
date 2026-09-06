//! Per-network traffic accounting — the measurement layer that turns
//! "quieter" from a claim into a number.
//!
//! Two chokepoints count every mesh frame ([`super::send_to_peer`] and
//! the inbound dispatcher), classed by what the frame is *for*; the
//! signaling handler counts discovery/negotiation events the same way.
//! Everything is a relaxed atomic — counting must never contend with
//! the driver — and the snapshot is a plain serializable struct the
//! status surface exposes, so a topology experiment reads as a diff of
//! two snapshots instead of a feeling.

use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::protocol::MeshMessage;

/// What a mesh frame is for — the accounting class.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameClass {
    /// `ping` / `pong`.
    Keepalive,
    /// Handshake + topology negotiation (`hello`, `auth_response`,
    /// `approve`, `deny`, `shelve`, `unshelve`, capabilities).
    Control,
    /// Governance anti-entropy.
    Gossip,
    /// Application frames: typed channels (plain and acked) + RPC.
    App,
    /// Frames that don't fit (future revisions land here).
    Other,
}

/// Classify one wire frame.
pub fn class_of(msg: &MeshMessage) -> FrameClass {
    match msg {
        MeshMessage::Ping(_) | MeshMessage::Pong(_) => FrameClass::Keepalive,
        MeshMessage::Hello(_)
        | MeshMessage::AuthResponse(_)
        | MeshMessage::Approve(_)
        | MeshMessage::Deny(_)
        | MeshMessage::Shelve(_)
        | MeshMessage::Unshelve(_)
        | MeshMessage::SessionControl(_)
        | MeshMessage::CapabilitiesUpdate(_)
        | MeshMessage::ClosedRelayControl(_) => FrameClass::Control,
        MeshMessage::Fact(_)
        | MeshMessage::FactPage(_)
        | MeshMessage::FactInventory(_)
        | MeshMessage::FactRequest(_)
        | MeshMessage::ProofDelivery(_)
        | MeshMessage::ProofAck(_) => FrameClass::Gossip,
        MeshMessage::Channel { .. }
        | MeshMessage::ChannelSeq { .. }
        | MeshMessage::ChannelAck { .. }
        | MeshMessage::ClosedRelayData(_)
        | MeshMessage::HubAdvertisement(_)
        | MeshMessage::HubDiscoveryRequest(_)
        | MeshMessage::HubDiscoveryResponse(_)
        | MeshMessage::HubTreeAttachRequest(_)
        | MeshMessage::HubTreeAttachResponse(_)
        | MeshMessage::RoutedApplication(_)
        | MeshMessage::RpcRequest(_)
        | MeshMessage::RpcResponse(_)
        | MeshMessage::RpcStreamChunk(_)
        | MeshMessage::RpcStreamEnd(_) => FrameClass::App,
    }
}

/// One direction's counters for one class.
#[derive(Default)]
struct Lane {
    frames: AtomicU64,
    bytes: AtomicU64,
}

impl Lane {
    fn record(&self, bytes: usize) {
        self.frames.fetch_add(1, Ordering::Relaxed);
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
    }
    fn read(&self) -> LaneSnapshot {
        LaneSnapshot {
            frames: self.frames.load(Ordering::Relaxed),
            bytes: self.bytes.load(Ordering::Relaxed),
        }
    }
}

/// Live counters for one network. Held on `NetworkState`; written from
/// the frame chokepoints and the signaling handler.
#[derive(Default)]
pub struct TrafficCounters {
    keepalive_tx: Lane,
    keepalive_rx: Lane,
    control_tx: Lane,
    control_rx: Lane,
    gossip_tx: Lane,
    gossip_rx: Lane,
    app_tx: Lane,
    app_rx: Lane,
    other_tx: Lane,
    other_rx: Lane,
    /// Signaling events, by discovery vs pairwise negotiation.
    announces_rx: AtomicU64,
    negotiation_rx: AtomicU64,
    announces_tx: AtomicU64,
    negotiation_tx: AtomicU64,
}

impl TrafficCounters {
    fn lane(&self, class: FrameClass, tx: bool) -> &Lane {
        match (class, tx) {
            (FrameClass::Keepalive, true) => &self.keepalive_tx,
            (FrameClass::Keepalive, false) => &self.keepalive_rx,
            (FrameClass::Control, true) => &self.control_tx,
            (FrameClass::Control, false) => &self.control_rx,
            (FrameClass::Gossip, true) => &self.gossip_tx,
            (FrameClass::Gossip, false) => &self.gossip_rx,
            (FrameClass::App, true) => &self.app_tx,
            (FrameClass::App, false) => &self.app_rx,
            (FrameClass::Other, true) => &self.other_tx,
            (FrameClass::Other, false) => &self.other_rx,
        }
    }

    pub fn record_tx(&self, class: FrameClass, bytes: usize) {
        self.lane(class, true).record(bytes);
    }

    pub fn record_rx(&self, class: FrameClass, bytes: usize) {
        self.lane(class, false).record(bytes);
    }

    pub fn record_signaling_rx(&self, announce: bool) {
        if announce {
            self.announces_rx.fetch_add(1, Ordering::Relaxed);
        } else {
            self.negotiation_rx.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn record_signaling_tx(&self, announce: bool) {
        if announce {
            self.announces_tx.fetch_add(1, Ordering::Relaxed);
        } else {
            self.negotiation_tx.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// A serializable point-in-time read of every counter.
    pub fn snapshot(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            keepalive_tx: self.keepalive_tx.read(),
            keepalive_rx: self.keepalive_rx.read(),
            control_tx: self.control_tx.read(),
            control_rx: self.control_rx.read(),
            gossip_tx: self.gossip_tx.read(),
            gossip_rx: self.gossip_rx.read(),
            app_tx: self.app_tx.read(),
            app_rx: self.app_rx.read(),
            other_tx: self.other_tx.read(),
            other_rx: self.other_rx.read(),
            announces_rx: self.announces_rx.load(Ordering::Relaxed),
            negotiation_rx: self.negotiation_rx.load(Ordering::Relaxed),
            announces_tx: self.announces_tx.load(Ordering::Relaxed),
            negotiation_tx: self.negotiation_tx.load(Ordering::Relaxed),
            reliable_pending: 0, // filled by the caller, which can see the outboxes
        }
    }
}

/// Frames + bytes for one class in one direction.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneSnapshot {
    pub frames: u64,
    pub bytes: u64,
}

/// The status-surface shape — everything an operator (or a topology
/// experiment) needs to compare two configurations honestly.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficSnapshot {
    pub keepalive_tx: LaneSnapshot,
    pub keepalive_rx: LaneSnapshot,
    pub control_tx: LaneSnapshot,
    pub control_rx: LaneSnapshot,
    pub gossip_tx: LaneSnapshot,
    pub gossip_rx: LaneSnapshot,
    pub app_tx: LaneSnapshot,
    pub app_rx: LaneSnapshot,
    pub other_tx: LaneSnapshot,
    pub other_rx: LaneSnapshot,
    /// Signaling: presence announces seen / published.
    pub announces_rx: u64,
    pub announces_tx: u64,
    /// Signaling: pairwise negotiation events (offer/answer/candidate/
    /// leave) seen / published.
    pub negotiation_rx: u64,
    pub negotiation_tx: u64,
    /// Acked-delivery frames currently queued across all peers.
    pub reliable_pending: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::keepalive::PingMessage;
    use ed25519_dalek::SigningKey;

    #[test]
    fn classes_cover_the_wire() {
        assert_eq!(
            class_of(&MeshMessage::Ping(PingMessage { t: 0 })),
            FrameClass::Keepalive
        );
        assert_eq!(
            class_of(&MeshMessage::Channel {
                channel: "c".into(),
                payload: serde_json::json!(1)
            }),
            FrameClass::App
        );
        let origin_key = SigningKey::from_bytes(&[31; 32]);
        let destination_key = SigningKey::from_bytes(&[32; 32]);
        let origin = crate::semantic::DeviceId::from_public_key_bytes(
            *origin_key.verifying_key().as_bytes(),
        )
        .expect("origin device id");
        let destination = crate::semantic::DeviceId::from_public_key_bytes(
            *destination_key.verifying_key().as_bytes(),
        )
        .expect("destination device id");
        let routed = crate::protocol::RoutedApplicationEnvelope::new(
            crate::semantic::MeshContextId::from_bytes([33; 32]),
            origin,
            destination,
            [34; 16],
            1,
            crate::protocol::ClosedRoutedPayload::ChannelFrame {
                channel: "traffic-test".into(),
                payload: serde_json::json!({"probe": true}),
            },
            &origin_key,
        )
        .expect("routed application envelope");
        assert_eq!(
            class_of(&MeshMessage::RoutedApplication(routed)),
            FrameClass::App
        );
    }

    #[test]
    fn counters_accumulate_and_snapshot() {
        let t = TrafficCounters::default();
        t.record_tx(FrameClass::App, 100);
        t.record_tx(FrameClass::App, 50);
        t.record_rx(FrameClass::Keepalive, 10);
        t.record_signaling_rx(true);
        t.record_signaling_tx(false);
        let s = t.snapshot();
        assert_eq!(
            s.app_tx,
            LaneSnapshot {
                frames: 2,
                bytes: 150
            }
        );
        assert_eq!(s.keepalive_rx.frames, 1);
        assert_eq!(s.announces_rx, 1);
        assert_eq!(s.negotiation_tx, 1);
    }
}
