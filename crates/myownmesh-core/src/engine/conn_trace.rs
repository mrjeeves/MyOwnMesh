//! Connection-state transition tracing — Phase-0 observability.
//!
//! The reliability work starts from a single principle: *you cannot
//! fix what you cannot see, and you cannot see a cross-machine timing
//! bug from three plain-text logs you can't line up.* This module is
//! the answer. It captures every per-peer connection-state transition
//! as one structured [`ConnTrace`] record, emitted from a single hook
//! in the driver loop ([`ConnTracer::sweep`]).
//!
//! Why a diffing sweep instead of instrumenting the ~8 scattered
//! status-mutation sites: it is purely *additive* — it observes the
//! engine's existing state without touching the field-tested ladder or
//! any of its constants — and it captures the exact failure this whole
//! effort is chasing: the moments when the several independent
//! liveness signals (`status`, `tier`, ICE state, peer-connection
//! state, the selected candidate pair) *disagree*. Each `ConnTrace`
//! carries all of them at once, so a record where `status = active`
//! but `ice = Disconnected` is the drift, visible and timestamped.
//!
//! Cost is zero unless someone is watching: [`sweep`](ConnTracer::sweep)
//! returns immediately when [`NetworkState::conn_trace_enabled`] is
//! false (no `ctl trace` subscriber and `MYOWNMESH_CONN_TRACE` unset).
//!
//! Each record carries both a monotonic clock (`t_mono_ms`, immune to
//! NTP steps and sleep/wake — use it for intra-machine ordering) and a
//! wall clock (`ts_wall_ms`, for cross-machine correlation via
//! `scripts/merge-traces.py`). See `docs/DEBUGGING-CONNECTIONS.md`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::transport::{IceCandidateKind, SelectedCandidatePair};

use super::connection::PeerStatus;
use super::ladder::ConnectionTier;
use super::state::NetworkState;

/// One per-peer connection-state transition, emitted whenever any
/// discrete liveness field changes. Streamed live over the control
/// socket (`ctl trace`) as one JSON object per line, and mirrored to
/// the `tracing` layer under the `conn_trace` target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnTrace {
    /// Unix epoch milliseconds (wall clock). Cross-machine
    /// correlation key — the merge tool orders the combined timeline
    /// by this. Subject to NTP skew between machines; the tool notes
    /// per-host offsets.
    pub ts_wall_ms: u64,
    /// Milliseconds since this engine's driver started (monotonic).
    /// Immune to NTP steps and sleep/wake discontinuities — use this
    /// for ordering events *within* one machine.
    pub t_mono_ms: u64,
    pub network_id: String,
    pub device_id: String,
    /// Session epoch — bumps on every peer-session rebuild, so a flap
    /// shows as epoch churn even when `status` looks stable. The
    /// single best signal that "this peer is being torn down and
    /// rebuilt under you."
    pub epoch: u64,
    /// Which discrete fields changed since the previous trace for this
    /// peer. Special markers `"appeared"` / `"vanished"` bracket a
    /// peer's lifetime in the engine's map.
    pub changed: Vec<String>,

    // ---- the full liveness snapshot at emit time ----
    /// Engine's app-level status enum.
    pub status: PeerStatus,
    /// Reconnection-ladder tier kind tag (`steady`, `ice_watchdog`, …).
    pub tier: String,
    /// Raw `RTCIceConnectionState` (`Connected`, `Disconnected`, …).
    /// `None` when no transport session exists yet.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ice_state: Option<String>,
    /// Raw `RTCPeerConnectionState` (DTLS+ICE composite).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pc_state: Option<String>,
    /// How traffic is actually flowing once ICE nominates a pair:
    /// `lan` / `stun` / `turn`. `None` until ICE reaches Connected.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pair_class: Option<String>,
    /// Age of the most recent inbound frame, in ms. Context only (it
    /// changes continuously, so it does not by itself trigger a
    /// trace).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_recv_age_ms: Option<u64>,
    /// Last measured application-level round-trip, in ms.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rtt_ms: Option<u32>,
    pub authenticated: bool,
    pub local_shelved: bool,
    pub remote_shelved: bool,
}

/// The discrete subset of a peer's state we diff on. Continuously
/// varying values (`last_recv_age`, `rtt`) are deliberately excluded
/// so the tracer fires on real transitions, not on every sweep.
#[derive(Clone, Debug, PartialEq)]
struct Snapshot {
    epoch: u64,
    status: PeerStatus,
    tier: &'static str,
    ice_state: Option<String>,
    pc_state: Option<String>,
    pair_class: Option<&'static str>,
    authenticated: bool,
    local_shelved: bool,
    remote_shelved: bool,
}

/// Maps a [`ConnectionTier`] to a stable snake_case tag, dropping the
/// per-variant timing payload (which is internal scheduling state, not
/// something a trace consumer should diff on).
fn tier_kind(t: &ConnectionTier) -> &'static str {
    match t {
        ConnectionTier::Steady => "steady",
        ConnectionTier::WakeProbe => "wake_probe",
        ConnectionTier::IceWatchdog { .. } => "ice_watchdog",
        ConnectionTier::IceRestart { .. } => "ice_restart",
        ConnectionTier::Rehandshake { .. } => "rehandshake",
        ConnectionTier::RoomRejoin { .. } => "room_rejoin",
        ConnectionTier::StopStart => "stop_start",
    }
}

/// Classify how a peer's data is actually flowing from the nominated
/// candidate pair. Mirrors the authoritative rule in `transport::diag`:
/// any relay candidate ⇒ TURN; any srflx/prflx ⇒ STUN; host↔host ⇒ LAN.
fn classify_pair(p: &SelectedCandidatePair) -> &'static str {
    use IceCandidateKind as K;
    if p.local == K::Relay || p.remote == K::Relay {
        "turn"
    } else if matches!(p.local, K::ServerReflexive | K::PeerReflexive)
        || matches!(p.remote, K::ServerReflexive | K::PeerReflexive)
    {
        "stun"
    } else if p.local == K::Host && p.remote == K::Host {
        "lan"
    } else {
        "unknown"
    }
}

/// List the field names that differ between two snapshots.
fn diff_fields(prev: &Snapshot, cur: &Snapshot) -> Vec<String> {
    let mut v = Vec::new();
    if prev.epoch != cur.epoch {
        v.push("epoch".to_string());
    }
    if prev.status != cur.status {
        v.push("status".to_string());
    }
    if prev.tier != cur.tier {
        v.push("tier".to_string());
    }
    if prev.ice_state != cur.ice_state {
        v.push("ice".to_string());
    }
    if prev.pc_state != cur.pc_state {
        v.push("pc".to_string());
    }
    if prev.pair_class != cur.pair_class {
        v.push("pair".to_string());
    }
    if prev.authenticated != cur.authenticated {
        v.push("auth".to_string());
    }
    if prev.local_shelved != cur.local_shelved {
        v.push("local_shelved".to_string());
    }
    if prev.remote_shelved != cur.remote_shelved {
        v.push("remote_shelved".to_string());
    }
    if v.is_empty() {
        // Snapshots compared unequal but no tracked field differs —
        // shouldn't happen, but never emit an empty `changed`.
        v.push("changed".to_string());
    }
    v
}

/// Per-driver-loop connection tracer. Holds the last-emitted snapshot
/// per peer so it can emit only on change. One instance lives for the
/// lifetime of a network's driver task.
pub struct ConnTracer {
    start: Instant,
    last: HashMap<String, Snapshot>,
}

impl ConnTracer {
    pub fn new() -> Self {
        Self {
            start: Instant::now(),
            last: HashMap::new(),
        }
    }

    /// Diff every peer's discrete connection state against the last
    /// emission and emit a [`ConnTrace`] for any that changed (plus
    /// `appeared` / `vanished` for entries entering or leaving the
    /// map). Synchronous and allocation-light; returns immediately
    /// when tracing is disabled so the production hot path pays only a
    /// single atomic load.
    ///
    /// Called once per driver-loop iteration, after the event that may
    /// have mutated state has been fully handled — so the snapshot
    /// reflects the post-event truth and no per-peer lock is held
    /// across it.
    pub fn sweep(&mut self, state: &Arc<NetworkState>) {
        if !state.conn_trace_enabled() {
            return;
        }
        let t_mono_ms = self.start.elapsed().as_millis() as u64;
        let ts_wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);

        let mut seen: HashSet<String> = HashSet::with_capacity(state.peers.len());

        for entry in state.peers.iter() {
            let device_id = entry.key().clone();
            seen.insert(device_id.clone());
            let peer = entry.value();
            let epoch = peer.epoch;

            // Transport-derived states — sync reads, lock released
            // before we touch the per-peer RwLock below.
            let (ice_state, pc_state) = {
                let guard = peer.session.lock();
                match guard.as_ref() {
                    Some(s) => (
                        Some(format!("{:?}", s.ice_connection_state())),
                        Some(format!("{:?}", s.connection_state())),
                    ),
                    None => (None, None),
                }
            };

            let (snap, last_recv_age_ms, rtt_ms) = {
                let data = peer.state.read();
                let snap = Snapshot {
                    epoch,
                    status: data.status,
                    tier: tier_kind(&data.tier),
                    ice_state: ice_state.clone(),
                    pc_state: pc_state.clone(),
                    pair_class: data.selected_pair.as_ref().map(classify_pair),
                    authenticated: data.authenticated,
                    local_shelved: data.local_shelved,
                    remote_shelved: data.remote_shelved,
                };
                let age = data.last_recv_at.map(|t| t.elapsed().as_millis() as u64);
                (snap, age, data.rtt_ms)
            };

            let changed = match self.last.get(&device_id) {
                None => vec!["appeared".to_string()],
                Some(prev) if *prev == snap => continue,
                Some(prev) => diff_fields(prev, &snap),
            };
            self.last.insert(device_id.clone(), snap.clone());

            emit(
                state,
                ConnTrace {
                    ts_wall_ms,
                    t_mono_ms,
                    network_id: state.network_id.clone(),
                    device_id,
                    epoch,
                    changed,
                    status: snap.status,
                    tier: snap.tier.to_string(),
                    ice_state,
                    pc_state,
                    pair_class: snap.pair_class.map(|s| s.to_string()),
                    last_recv_age_ms,
                    rtt_ms,
                    authenticated: snap.authenticated,
                    local_shelved: snap.local_shelved,
                    remote_shelved: snap.remote_shelved,
                },
            );
        }

        // Anything we held last sweep but the engine has since dropped.
        let gone: Vec<String> = self
            .last
            .keys()
            .filter(|k| !seen.contains(*k))
            .cloned()
            .collect();
        for device_id in gone {
            let Some(prev) = self.last.remove(&device_id) else {
                continue;
            };
            emit(
                state,
                ConnTrace {
                    ts_wall_ms,
                    t_mono_ms,
                    network_id: state.network_id.clone(),
                    device_id,
                    epoch: prev.epoch,
                    changed: vec!["vanished".to_string()],
                    status: prev.status,
                    tier: prev.tier.to_string(),
                    ice_state: None,
                    pc_state: None,
                    pair_class: None,
                    last_recv_age_ms: None,
                    rtt_ms: None,
                    authenticated: prev.authenticated,
                    local_shelved: prev.local_shelved,
                    remote_shelved: prev.remote_shelved,
                },
            );
        }
    }
}

impl Default for ConnTracer {
    fn default() -> Self {
        Self::new()
    }
}

/// Emit one trace to both surfaces: the `conn_trace`-targeted tracing
/// event (so file logs — plain or `MYOWNMESH_LOG_FORMAT=json` — carry
/// it) and the per-network broadcast that `ctl trace` drains.
fn emit(state: &Arc<NetworkState>, trace: ConnTrace) {
    tracing::info!(
        target: "conn_trace",
        network = %trace.network_id,
        peer = %trace.device_id,
        epoch = trace.epoch,
        changed = %trace.changed.join(","),
        status = ?trace.status,
        tier = %trace.tier,
        ice = trace.ice_state.as_deref().unwrap_or("-"),
        pc = trace.pc_state.as_deref().unwrap_or("-"),
        pair = trace.pair_class.as_deref().unwrap_or("-"),
        rtt_ms = ?trace.rtt_ms,
        last_recv_age_ms = ?trace.last_recv_age_ms,
        t_mono_ms = trace.t_mono_ms,
        "conn-trace"
    );
    state.emit_conn_trace(trace);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::IceCandidateKind as K;

    fn pair(local: K, remote: K) -> SelectedCandidatePair {
        SelectedCandidatePair { local, remote }
    }

    #[test]
    fn classify_pair_lan_stun_turn() {
        assert_eq!(classify_pair(&pair(K::Host, K::Host)), "lan");
        assert_eq!(classify_pair(&pair(K::Host, K::ServerReflexive)), "stun");
        assert_eq!(classify_pair(&pair(K::PeerReflexive, K::Host)), "stun");
        assert_eq!(classify_pair(&pair(K::Relay, K::Host)), "turn");
        assert_eq!(classify_pair(&pair(K::Relay, K::Relay)), "turn");
        // Relay dominates even when the other side is reflexive.
        assert_eq!(classify_pair(&pair(K::ServerReflexive, K::Relay)), "turn");
    }

    #[test]
    fn tier_kind_tags() {
        assert_eq!(tier_kind(&ConnectionTier::Steady), "steady");
        assert_eq!(tier_kind(&ConnectionTier::WakeProbe), "wake_probe");
        assert_eq!(
            tier_kind(&ConnectionTier::IceWatchdog {
                since: Instant::now()
            }),
            "ice_watchdog"
        );
        assert_eq!(
            tier_kind(&ConnectionTier::Rehandshake {
                attempt: 1,
                next_at: Instant::now()
            }),
            "rehandshake"
        );
        assert_eq!(tier_kind(&ConnectionTier::StopStart), "stop_start");
    }

    fn snap() -> Snapshot {
        Snapshot {
            epoch: 1,
            status: PeerStatus::Active,
            tier: "steady",
            ice_state: Some("Connected".to_string()),
            pc_state: Some("Connected".to_string()),
            pair_class: Some("lan"),
            authenticated: true,
            local_shelved: false,
            remote_shelved: false,
        }
    }

    #[test]
    fn diff_reports_only_changed_fields() {
        let a = snap();
        let mut b = a.clone();
        b.ice_state = Some("Disconnected".to_string());
        b.tier = "ice_watchdog";
        let d = diff_fields(&a, &b);
        assert!(d.contains(&"ice".to_string()));
        assert!(d.contains(&"tier".to_string()));
        assert!(!d.contains(&"status".to_string()));
        assert!(!d.contains(&"pc".to_string()));
    }

    #[test]
    fn diff_catches_the_drift_case() {
        // The exact failure this tooling exists to surface: the engine
        // still thinks the peer is Active, but ICE has gone away.
        let a = snap();
        let mut b = a.clone();
        b.ice_state = Some("Disconnected".to_string()); // status stays Active
        let d = diff_fields(&a, &b);
        assert_eq!(d, vec!["ice".to_string()]);
    }

    #[test]
    fn epoch_bump_is_a_change() {
        let a = snap();
        let mut b = a.clone();
        b.epoch = 2;
        assert_eq!(diff_fields(&a, &b), vec!["epoch".to_string()]);
        assert_ne!(a, b);
    }

    #[test]
    fn trace_serializes_to_one_json_object() {
        let t = ConnTrace {
            ts_wall_ms: 1,
            t_mono_ms: 2,
            network_id: "home".into(),
            device_id: "abc".into(),
            epoch: 3,
            changed: vec!["status".into()],
            status: PeerStatus::Active,
            tier: "steady".into(),
            ice_state: Some("Connected".into()),
            pc_state: Some("Connected".into()),
            pair_class: Some("lan".into()),
            last_recv_age_ms: Some(10),
            rtt_ms: Some(25),
            authenticated: true,
            local_shelved: false,
            remote_shelved: false,
        };
        let v: serde_json::Value = serde_json::to_value(&t).unwrap();
        assert_eq!(v.get("status").and_then(|s| s.as_str()), Some("active"));
        assert_eq!(v.get("pair_class").and_then(|s| s.as_str()), Some("lan"));
        assert_eq!(v.get("epoch").and_then(|s| s.as_u64()), Some(3));
    }
}
