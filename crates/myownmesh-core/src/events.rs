//! Events surfaced from the mesh engine to embedders. Carried on a
//! `tokio::sync::broadcast` channel so multiple subscribers (CLI,
//! GUI, programmatic clients) can observe without blocking each
//! other. Slow subscribers may miss events when the channel lags —
//! the engine prioritises forward progress over delivery
//! guarantees here. Embedders that need every event should drain
//! eagerly.

use serde::{Deserialize, Serialize};

use crate::identity::DeviceId;
use crate::protocol::CapabilityAdvert;

/// Coarse-grained per-network status. Aggregated from individual
/// peer state — see [`crate::protocol::topology`] for the per-peer
/// view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MeshPhase {
    /// No signaling connection yet, or just (re)joined and waiting
    /// for the first announce.
    Joining,
    /// Connected to signaling, no peers discovered.
    Alone,
    /// At least one peer discovered, none authenticated yet.
    Discovering,
    /// At least one peer authenticated and approved; app traffic
    /// flowing.
    Active,
    /// All peers transient or shelved; engine is reconnecting.
    Degraded,
    /// Stop requested or fatal error; no more events will fire on
    /// this network until rejoined.
    Stopped,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiagLevel {
    Debug,
    Info,
    Warn,
    Error,
}

/// One structured log entry from the engine's per-network state
/// machine. Surfaced via [`MeshEvent::Diag`] so an embedder can
/// render the Activity log directly from the event stream without
/// duplicating the engine's classification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiagEntry {
    /// Unix epoch milliseconds when the entry was produced. The GUI
    /// renders this as HH:MM:SS in the Activity log so a user can
    /// correlate entries with what they were doing.
    pub ts: u64,
    pub network_id: String,
    pub level: DiagLevel,
    /// Short categorical tag, e.g. `"signaling"`, `"ice"`,
    /// `"handshake"`, `"topology"`, `"rpc"`, `"update"`. Compared
    /// as exact strings by UI filters.
    pub category: String,
    /// Human-readable message. Format is informational; embedders
    /// shouldn't parse it.
    pub message: String,
    /// Optional structured detail. Embedders may pull specific
    /// fields out (peer id, error code, etc.) for UI rendering.
    #[serde(default)]
    pub detail: serde_json::Value,
}

/// Reason a connection went down. Surfaced in [`MeshEvent::PeerDropped`]
/// so the UI can distinguish a clean leave from a transient blip.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum DropReason {
    /// Peer sent a `deny` or we explicitly removed them.
    Denied,
    /// ICE failed and reconnection attempts exhausted.
    IceFailed,
    /// Peer authenticated but failed signature verification on
    /// re-handshake.
    AuthFailed,
    /// User-requested disconnect (network leave, app shutdown).
    UserLeft,
    /// The topology selector closed a both-sides-shelved connection
    /// its shape doesn't want (a non-edge under star / hubs / ring
    /// connection-shaping). Not a failure: the member stays Sighted
    /// and reachable through the shape's forwarders, and a later
    /// shape change redials it.
    TopologyPruned,
    /// Peer went silent past the heartbeat grace; transport
    /// considered dead.
    HeartbeatTimeout,
    /// Catch-all for unanticipated transport errors.
    TransportError { message: String },
}

/// Reactive view of one peer event. The engine emits these on
/// every state transition; embedders use them to render the peers
/// list and trigger UI side effects (notifications, sounds, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PeerEvent {
    /// First sight of a peer in this network — they've completed
    /// signaling but haven't yet sent `hello`. Surfaced so the UI
    /// can prepare a "pending" slot.
    Sighted {
        network_id: String,
        device_id: DeviceId,
    },
    /// Peer sent a valid `hello` + `auth_response`; signatures
    /// verify. The user has not yet been asked to approve them.
    Authenticated {
        network_id: String,
        device_id: DeviceId,
        label: String,
        verification_code: String,
        capabilities: CapabilityAdvert,
        /// True when the peer is in the roster and will auto-approve
        /// without prompting.
        rostered: bool,
    },
    /// Both sides have exchanged `approve`; the connection is live
    /// for app traffic.
    Approved {
        network_id: String,
        device_id: DeviceId,
        label: String,
    },
    /// Topology selector demoted this peer from the preferred set;
    /// data channel stays open as a heartbeat but no app traffic
    /// flows toward them from us.
    Shelved {
        network_id: String,
        device_id: DeviceId,
        #[serde(default)]
        reason: Option<String>,
        /// True = we shelved them; false = they shelved us.
        by_us: bool,
    },
    Unshelved {
        network_id: String,
        device_id: DeviceId,
        by_us: bool,
    },
    /// Peer's capability advertisement changed. Receivers refresh
    /// their cached copy.
    CapabilitiesChanged {
        network_id: String,
        device_id: DeviceId,
        capabilities: CapabilityAdvert,
    },
    /// Connection torn down. After this the peer may reappear via
    /// `Sighted` if they reconnect.
    Dropped {
        network_id: String,
        device_id: DeviceId,
        reason: DropReason,
        /// Grace window during which a fresh reconnect from the
        /// same peer skips the user-approval prompt (if they were
        /// previously approved).
        grace_window_ms: u64,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum PhaseEvent {
    Changed {
        network_id: String,
        prev: MeshPhase,
        next: MeshPhase,
    },
}

/// Top-level event stream. Embedders consume via
/// `MeshHandle::events()`.
///
/// Tagged with `event_kind` (not `kind`) so the discriminator
/// doesn't collide with the inner `PeerEvent` / `PhaseEvent` tags —
/// those use `kind`, and a single `kind` for both layers produced
/// JSON with duplicate keys (the inner one would win on
/// `JSON.parse`, dropping the outer discriminator on the floor).
/// The two-layer shape lets a consumer dispatch on event family
/// (`event_kind`) and then on the specific variant (`kind`) without
/// ambiguity.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "event_kind")]
pub enum MeshEvent {
    Peer(PeerEvent),
    Phase(PhaseEvent),
    Diag(DiagEntry),
}

#[cfg(test)]
mod wire_tests {
    use super::*;
    use crate::protocol::CapabilityAdvert;

    /// Pin the outer tag name so adding a new event family doesn't
    /// silently collide with the inner `kind` tag again. The GUI's
    /// `mesh-client.svelte.ts` dispatches on `event_kind`; flipping
    /// this would silently route every event to the fallback branch.
    #[test]
    fn outer_tag_is_event_kind_no_kind_collision() {
        let ev = MeshEvent::Peer(PeerEvent::Sighted {
            network_id: "home".into(),
            device_id: "abc".into(),
        });
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("event_kind").and_then(|v| v.as_str()), Some("peer"));
        assert_eq!(obj.get("kind").and_then(|v| v.as_str()), Some("sighted"));
    }

    /// Diag has no inner enum, so only the outer `event_kind` tag
    /// shows up. The inner `category` field is plain data, not a
    /// discriminator.
    #[test]
    fn diag_carries_only_event_kind() {
        let ev = MeshEvent::Diag(DiagEntry {
            ts: 0,
            network_id: "home".into(),
            level: DiagLevel::Info,
            category: "ice".into(),
            message: "hi".into(),
            detail: serde_json::Value::Null,
        });
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(obj.get("event_kind").and_then(|v| v.as_str()), Some("diag"));
        assert!(obj.get("kind").is_none());
        assert_eq!(obj.get("category").and_then(|v| v.as_str()), Some("ice"));
    }

    /// Phase's inner `Changed` variant lands at `kind` alongside the
    /// outer `event_kind` — both visible, no clobbering.
    #[test]
    fn phase_changed_serializes_both_tags() {
        let ev = MeshEvent::Phase(PhaseEvent::Changed {
            network_id: "home".into(),
            prev: MeshPhase::Alone,
            next: MeshPhase::Active,
        });
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        let obj = v.as_object().unwrap();
        assert_eq!(
            obj.get("event_kind").and_then(|v| v.as_str()),
            Some("phase")
        );
        assert_eq!(obj.get("kind").and_then(|v| v.as_str()), Some("changed"));
    }

    /// Authenticated carries the verification code the GUI shows in
    /// the approval tile. Pin its presence so dropping the field
    /// from PeerEvent is caught here.
    #[test]
    fn authenticated_carries_verification_code() {
        let ev = MeshEvent::Peer(PeerEvent::Authenticated {
            network_id: "home".into(),
            device_id: "abc".into(),
            label: "Phone".into(),
            verification_code: "ab12cd".into(),
            capabilities: CapabilityAdvert::default(),
            rostered: false,
        });
        let v: serde_json::Value = serde_json::to_value(&ev).unwrap();
        assert_eq!(
            v.get("verification_code").and_then(|v| v.as_str()),
            Some("ab12cd")
        );
    }
}
