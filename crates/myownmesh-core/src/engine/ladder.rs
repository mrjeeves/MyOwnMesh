//! Connection tiers + topology reevaluation.
//!
//! [`ConnectionTier`] is the per-peer recovery-state tag surfaced in
//! diagnostics and the GUI. The recovery *logic* itself lives where the
//! reliable signals are: in-place ICE restart in [`super::ice_watchdog`]
//! and [`super::network_watch`], traffic-confirmed promotion back to
//! `Steady` in the engine's inbound path, and rebuild-on-silence in
//! [`super::heartbeat`]. See `CONNECTION-ENGINE-FIELD-NOTES.md` for the model. This
//! module also owns the topology selector pass ([`reevaluate_topology`]).

use std::sync::Arc;

use futures_util::{stream::FuturesUnordered, StreamExt};
use serde::{Deserialize, Serialize};
use tracing::debug;

use crate::config::TopologyMode;
use crate::events::MeshEvent;

use super::connection::PeerStatus;
use super::state::NetworkState;

#[derive(Copy, Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", tag = "kind")]
pub enum ConnectionTier {
    /// Tier 1 — receiving app traffic; nothing to do.
    Steady,
    /// Tier 2 — wake event observed; ping all peers + wait.
    WakeProbe,
    /// Tier 2.5 — ICE went disconnected; per-peer watchdog
    /// scheduled. `since` is when the watchdog started.
    IceWatchdog {
        #[serde(skip, default = "now")]
        since: std::time::Instant,
    },
    /// Tier 3 — `pc.restart_ice()` running; awaiting traffic
    /// confirmation. `started` is re-stamped when ICE reconnects, so the
    /// restart-verify watchdog measures "time since the path should be
    /// carrying frames".
    IceRestart {
        #[serde(skip, default = "now")]
        started: std::time::Instant,
    },
    /// Tier 6 — signaling / STUN / TURN config edit forced
    /// stop+start.
    StopStart,
}

/// `serde(default)` helper for the skipped `Instant` fields.
fn now() -> std::time::Instant {
    std::time::Instant::now()
}

impl Default for ConnectionTier {
    fn default() -> Self {
        Self::Steady
    }
}

/// Re-run the topology selector and apply any preferred-set diff
/// as shelve / unshelve frames.
pub async fn reevaluate_topology(state: &Arc<NetworkState>) {
    // A stood-down engine (signed-evicted from this network) plans no
    // links: peers are dropping us and every dial would be denied.
    if state.self_evicted.load(std::sync::atomic::Ordering::SeqCst) {
        return;
    }
    let me = state.identity.public_id().to_string();
    let active_peers: Vec<String> = state.peers.collect_map(|peer| {
        matches!(
            peer.state.read().status,
            PeerStatus::Active | PeerStatus::Shelved
        )
        .then(|| peer.device_id.clone())
    });
    if active_peers.is_empty() {
        return;
    }
    // Compute the preferred set with the lock held just long
    // enough to call the selector; drop before any awaits.
    let preferred = {
        let topology = state.topology_impl.read();
        topology.select_preferred(&me, &active_peers)
    };

    for peer_id in &active_peers {
        // A sticky (pinned) peer outranks the shape here exactly as it does
        // in the announce-dial and prune passes. The pin lives on one side
        // only, and pruning a non-edge needs BOTH sides shelved — so the
        // pin-holder must never send its half of that agreement. Without
        // this, a technician's pinned support session was shelved by its
        // own daemon, the customer's pinless daemon saw both-sides-shelved
        // and pruned the link, the pin redialed it, and the session dropped
        // on a loop every few seconds. Marking a pinned peer preferred also
        // heals one shelved before the pin existed (it unshelves below).
        let shape_wants_shelved = !preferred.contains(peer_id) && !state.is_sticky(peer_id);
        let (needs_shelve, should_be_shelved) = {
            let Some(peer) = state.peers.get(peer_id) else {
                continue;
            };
            let should_be_shelved = shape_wants_shelved && !state.demand_link_protects_peer(&peer);
            let mut data = peer.state.write();
            let prev = data.local_shelved;
            data.local_shelved = should_be_shelved;
            if should_be_shelved && data.status == PeerStatus::Active {
                data.status = PeerStatus::Shelved;
            } else if !should_be_shelved && data.status == PeerStatus::Shelved {
                data.status = PeerStatus::Active;
            }
            (prev != should_be_shelved, should_be_shelved)
        };
        if needs_shelve {
            send_shelve_unshelve(state, peer_id, should_be_shelved).await;
        }
    }
}

/// The connection-shaping pass for pruning topologies — the second
/// half of what [`reevaluate_topology`] starts. Where the shelve pass
/// only marks links, this one changes the connection set:
///
/// * **Prune** a connected non-edge once BOTH sides have shelved it —
///   the deterministic signal that both nodes computed "not preferred"
///   from their own view, which is the coordination-free agreement to
///   close. The member is re-recorded as Sighted, so it stays visible
///   and a later shape change redials it.
/// * **Dial** a Sighted-but-unconnected member the shape wants an edge
///   to, lex-lower side initiating (both sides agree the edge exists;
///   exactly one may offer or they'd glare).
///
/// Runs on the state-watch tick (see `engine::tick`) rather than
/// inside [`reevaluate_topology`]: the shelve handshake this keys on
/// completes asynchronously, and drop-driven reevaluation calling back
/// into drops would recurse. Idempotent and cheap when the shape is
/// settled; a no-op entirely for non-pruning modes.
pub(crate) async fn shape_connections(state: &Arc<NetworkState>) {
    if !state.topology_impl.read().prunes() {
        return;
    }
    // HubTree is a preferred sparse forwarding shape, not a permission
    // boundary for independently authenticated direct links.  Such a link
    // may be established by an explicit peer action or another admissible
    // route; retaining it does not auto-dial non-edges or grant forwarding.
    // The routed application and session-provider fences enforce the separate
    // accepted-parent requirement when the link is used as tree transit.
    let hub_tree = matches!(&*state.topology.read(), TopologyMode::HubTree { .. });
    let silent = state.is_silent();
    let me = state.identity.public_id().to_string();
    let mut known = state.peers.device_ids_snapshot();
    known.push(me.clone());

    let mut to_prune: Vec<String> = Vec::new();
    let mut to_dial: Vec<String> = Vec::new();
    {
        let topo = state.topology_impl.read();
        for peer in state.peers.values_snapshot() {
            let id = &peer.device_id;
            let has_session = peer.has_current_worker();
            let edge = topo.edge(&me, id, &known);
            if has_session {
                let demand_owned = state.demand_link_protects_peer(&peer);
                let data = peer.state.read();
                let both_shelved = data.local_shelved && data.remote_shelved;
                let settled = matches!(data.status, PeerStatus::Shelved);
                if !hub_tree
                    && !edge
                    && both_shelved
                    && settled
                    && !state.is_sticky(id)
                    && !demand_owned
                {
                    to_prune.push(id.clone());
                }
            } else if (edge || state.is_sticky(id)) && (!silent || state.is_sticky(id)) && me < *id
            {
                to_dial.push(id.clone());
            }
        }
    }

    // The peer registry is keyed by Device ID, but keep the edge plan's
    // uniqueness and ordering explicit: a concurrent state-watch tick must
    // not schedule duplicate carriers for one exact edge.
    to_prune.sort_unstable();
    to_prune.dedup();
    to_dial.sort_unstable();
    to_dial.dedup();

    // Hub mode is explicitly owner-selected: rotate the finite wanted-edge
    // list each pass and fill only the configured number of concurrent dials.
    // This prevents an unavailable early edge from starving later edges while
    // preserving the existing unbounded-by-policy path for other topologies.
    let hub_limits = state.config.read().hub.map(|policy| {
        (
            usize::try_from(policy.max_parallel_dials).unwrap_or(usize::MAX),
            usize::try_from(policy.max_dials_per_pass).unwrap_or(usize::MAX),
        )
    });
    if let Some((_, max_per_pass)) = hub_limits {
        if !to_dial.is_empty() {
            let start = state
                .hub_dial_cursor
                .load(std::sync::atomic::Ordering::Acquire)
                % to_dial.len();
            to_dial.rotate_left(start);
            let advance = max_per_pass.min(to_dial.len());
            state.hub_dial_cursor.store(
                (start + advance) % to_dial.len(),
                std::sync::atomic::Ordering::Release,
            );
            to_dial.truncate(advance);
        }
    }

    for id in to_prune {
        // A demanded exact worker may have been installed since planning.
        // Its independent idle owner, not ordinary shape pruning, retires it.
        if state
            .peers
            .get(&id)
            .is_some_and(|peer| state.demand_link_protects_peer(&peer))
        {
            continue;
        }
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "topology",
            format!(
                "closing shaped-out connection to {} (stays reachable via forwarders)",
                super::short_peer(&id)
            ),
            serde_json::json!({ "peer": id }),
        );
        super::drop_peer(state, &id, crate::events::DropReason::TopologyPruned).await;
        // Keep the member on the map: visible, and redialable the
        // moment the shape wants it again.
        super::note_sighted_without_dialing(state, &id, "topology pruned");
    }
    // The plan is finite because it was derived from one peer-registry
    // snapshot, so the number of in-flight dials is explicitly bounded by
    // the number of unique wanted edges. Each future owns one edge and a
    // failure is contained by ensure_peer_session; it cannot cancel sibling
    // carriers. The transport worker may be created here, but it remains
    // Sighted/pending until the existing signed handshake and approval path
    // promotes it to Active or a usable application session.
    let mut pending = to_dial.into_iter();
    let parallel = hub_limits
        .map(|(max_parallel, _)| max_parallel)
        .unwrap_or(usize::MAX);
    let mut dials = FuturesUnordered::new();
    for _ in 0..parallel {
        let Some(id) = pending.next() else {
            break;
        };
        dials.push(dial_shape_edge(Arc::clone(state), id));
    }
    while dials.next().await.is_some() {
        let Some(id) = pending.next() else {
            continue;
        };
        dials.push(dial_shape_edge(Arc::clone(state), id));
    }
}

async fn dial_shape_edge(state: Arc<NetworkState>, id: String) {
    // Recheck after earlier planned work awaited. Silent limits automatic
    // initiation only; pruning and explicit/inbound connection paths remain
    // separate, and a standing pin still permits this recovery dial.
    if state.is_silent() && !state.is_sticky(&id) {
        return;
    }
    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "topology",
        format!("dialing shape edge to {}", super::short_peer(&id)),
        serde_json::json!({ "peer": id }),
    );
    super::ensure_peer_session(&state, &id, crate::transport::Role::Offerer).await;
}

async fn send_shelve_unshelve(state: &Arc<NetworkState>, device_id: &str, shelved: bool) {
    use crate::protocol::topology::{ShelveMessage, UnshelveMessage};
    use crate::protocol::MeshMessage;
    let msg = if shelved {
        MeshMessage::Shelve(ShelveMessage {
            reason: Some("topology-rebalance".into()),
        })
    } else {
        MeshMessage::Unshelve(UnshelveMessage {})
    };
    if let Err(e) = super::send_to_peer(state, device_id, &msg).await {
        debug!(peer = %device_id, "shelve/unshelve send failed: {e}");
    }
    state.emit(if shelved {
        MeshEvent::Peer(crate::events::PeerEvent::Shelved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            reason: Some("topology-rebalance".into()),
            by_us: true,
        })
    } else {
        MeshEvent::Peer(crate::events::PeerEvent::Unshelved {
            network_id: state.network_id.clone(),
            device_id: device_id.to_string(),
            by_us: true,
        })
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkKind, TopologyMode};
    use crate::engine::tick::{Ticker, TopologyShapeTicker};
    use crate::engine::{build_test_state, insert_session_less_peer};
    use crate::topology::from_mode;

    fn wanted_shape_state(name: &str, kind: NetworkKind) -> Arc<NetworkState> {
        let state = build_test_state(name);
        // Reuse the existing high-sorting wanted-edge fixture: this tests
        // carrier initiation, never peer authentication or promotion.
        let mode = TopologyMode::Star { hub: "~hub".into() };
        {
            let mut config = state.config.write();
            config.kind = kind;
            config.topology = mode.clone();
        }
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        insert_session_less_peer(&state, "~hub", None);
        state
    }

    async fn finish_shape_control(state: &Arc<NetworkState>) {
        tokio::time::timeout(std::time::Duration::from_secs(10), state.shutdown())
            .await
            .expect("shape control drains owned workers before releasing the state");
    }

    #[tokio::test]
    async fn silent_shape_tick_preserves_sighted_wanted_edge_without_dialing() {
        let state = wanted_shape_state("silent-shape-no-dial", NetworkKind::Silent);
        let me = state.identity.public_id().to_string();
        let wanted = state
            .topology_impl
            .read()
            .edge(&me, "~hub", &[me.clone(), "~hub".into()]);
        let mut ticker = TopologyShapeTicker;
        let tick =
            tokio::time::timeout(std::time::Duration::from_secs(10), ticker.tick(&state)).await;
        let observed = state.peers.get("~hub").map(|peer| {
            let has_worker = peer.has_current_worker();
            let data = peer.state.read();
            (has_worker, data.status, data.authenticated)
        });
        finish_shape_control(&state).await;
        assert!(
            wanted && me.as_str() < "~hub",
            "the ordinary shape path must want and initiate this edge"
        );
        assert!(
            tick.is_ok(),
            "shape pass completed without a startup-time guess"
        );
        assert_eq!(
            observed,
            Some((false, PeerStatus::Sighted, false)),
            "a real shape tick must not upgrade an unpinned Silent discovery placeholder"
        );
    }

    #[tokio::test]
    async fn silent_sticky_and_open_shape_ticks_still_start_unpromoted_carriers() {
        for (name, kind, sticky) in [
            ("silent-shape-sticky", NetworkKind::Silent, true),
            ("open-shape-unchanged", NetworkKind::Open, false),
        ] {
            let state = wanted_shape_state(name, kind);
            if sticky {
                state.add_sticky("~hub");
            }
            let mut ticker = TopologyShapeTicker;
            let tick =
                tokio::time::timeout(std::time::Duration::from_secs(10), ticker.tick(&state)).await;
            let observed = state
                .peers
                .get("~hub")
                .map(|peer| (peer.has_current_worker(), peer.state.read().authenticated));
            finish_shape_control(&state).await;
            assert!(tick.is_ok(), "positive shape tick completed: {name}");
            assert_eq!(observed, Some((true, false)),
                "standing Silent intent and ordinary Open shaping still dial, never grant admission: {name}");
        }
    }

    #[tokio::test]
    async fn silent_explicit_connect_still_upgrades_a_wanted_shape_placeholder() {
        let state = wanted_shape_state("silent-shape-explicit", NetworkKind::Silent);
        let dial = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::engine::connect_peer(&state, "~hub", false, None),
        )
        .await;
        let observed = state
            .peers
            .get("~hub")
            .map(|peer| (peer.has_current_worker(), peer.state.read().authenticated));
        finish_shape_control(&state).await;
        assert!(dial.is_ok(), "explicit connection command completed");
        assert_eq!(
            observed,
            Some((true, false)),
            "explicit intent still starts a carrier, not authority"
        );
    }

    #[tokio::test]
    async fn silent_shape_dispatch_rechecks_a_withdrawn_pin() {
        let state = wanted_shape_state("silent-shape-unpinned-plan", NetworkKind::Silent);
        state.add_sticky("~hub");
        let planned_id = "~hub".to_string();
        let was_pinned = state.is_sticky(&planned_id);
        // A previous dial/prune await can separate planning from dispatch.
        // Exercise that exact dispatch boundary without a global test gate.
        state.remove_sticky(&planned_id);
        let dispatch = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            dial_shape_edge(Arc::clone(&state), planned_id),
        )
        .await;
        let undialed = state
            .peers
            .get("~hub")
            .is_some_and(|peer| !peer.has_current_worker());
        finish_shape_control(&state).await;
        assert!(was_pinned && dispatch.is_ok());
        assert!(
            undialed,
            "a withdrawn standing intent cannot use a stale automatic dial plan"
        );
    }

    #[tokio::test]
    async fn silent_shape_tick_still_prunes_only_the_mutually_shelved_nonedge() {
        let state = wanted_shape_state("silent-shape-prune", NetworkKind::Silent);
        let opened = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            crate::engine::ensure_peer_session(&state, "spoke-b", crate::transport::Role::Offerer),
        )
        .await;
        if let Some(peer) = state.peers.get("spoke-b") {
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
            data.remote_shelved = false;
        }
        let mut ticker = TopologyShapeTicker;
        let first_tick =
            tokio::time::timeout(std::time::Duration::from_secs(10), ticker.tick(&state)).await;
        let one_sided_retained = state
            .peers
            .get("spoke-b")
            .is_some_and(|peer| peer.has_current_worker());
        if let Some(peer) = state.peers.get("spoke-b") {
            peer.state.write().remote_shelved = true;
        }
        let second_tick =
            tokio::time::timeout(std::time::Duration::from_secs(10), ticker.tick(&state)).await;
        let pruned = state
            .peers
            .get("spoke-b")
            .is_some_and(|peer| !peer.has_current_worker());
        let wanted_still_undialed = state
            .peers
            .get("~hub")
            .is_some_and(|peer| !peer.has_current_worker());
        finish_shape_control(&state).await;
        assert!(opened.is_ok() && first_tick.is_ok() && second_tick.is_ok());
        assert!(
            one_sided_retained,
            "Silent must not eagerly close an existing one-sided-shelved link"
        );
        assert!(
            pruned,
            "Silent must still retire the mutually shelved non-edge"
        );
        assert!(
            wanted_still_undialed,
            "cleanup must not initiate an unrelated Silent edge"
        );
    }

    // Preserve only value snapshots across cleanup, never a registry owner
    // or peer-state guard. These deadlines cannot preempt a synchronous
    // native destructor; the fixed markers localize that outer-run ceiling.
    async fn legacy_shape_step(
        phase: &'static str,
        work: impl std::future::Future<Output = ()>,
    ) -> bool {
        eprintln!("ladder-control phase={phase} boundary=begin");
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(10);
        let outcome = tokio::time::timeout_at(deadline, work).await;
        // A synchronous poll can return Ready after the timer expired.
        let completed = outcome.is_ok() && tokio::time::Instant::now() < deadline;
        eprintln!("ladder-control phase={phase} boundary=end completed={completed}");
        completed
    }

    async fn finish_legacy_shape_control(state: Arc<NetworkState>) -> bool {
        let drained = legacy_shape_step("shutdown", state.shutdown()).await;
        eprintln!("ladder-control phase=state-drop boundary=begin");
        drop(state);
        eprintln!("ladder-control phase=state-drop boundary=end");
        drained
    }

    #[tokio::test]
    async fn full_mesh_shape_pass_is_a_noop() {
        let state = build_test_state("shape-noop");
        insert_session_less_peer(&state, "peer-a", None);
        let shaped = legacy_shape_step("shape", shape_connections(&state)).await;
        let retained = state.peers.contains_key("peer-a");
        let drained = finish_legacy_shape_control(state).await;
        assert!(shaped && drained);
        assert!(retained, "non-pruning mode touches nothing");
    }

    #[tokio::test]
    async fn shape_pass_dials_missing_edges_lex_lower_first() {
        let state = build_test_state("shape-dial");
        // Star with the placeholder itself as hub: the edge exists, and
        // '~' sorts above every base32 identity char so we are lex-lower
        // and must initiate.
        *state.topology.write() = TopologyMode::Star { hub: "~hub".into() };
        *state.topology_impl.write() = from_mode(&TopologyMode::Star { hub: "~hub".into() });
        insert_session_less_peer(&state, "~hub", None);
        let initially_session_less = state
            .peers
            .get("~hub")
            .is_some_and(|peer| !peer.has_current_worker());
        let shaped = legacy_shape_step("shape", shape_connections(&state)).await;
        let dialed = state
            .peers
            .get("~hub")
            .is_some_and(|peer| peer.has_current_worker());
        let drained = finish_legacy_shape_control(state).await;
        assert!(initially_session_less && shaped && drained);
        assert!(
            dialed,
            "the shape pass upgrades a wanted placeholder to a real dial"
        );
    }

    #[tokio::test]
    async fn shape_pass_dials_each_unique_edge_without_promotion() {
        let state = build_test_state("shape-dial-parallel");
        let mode = TopologyMode::Ring {
            n_preferred: Some(3),
        };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        // These two high-sorting placeholders are both wanted by the ring
        // and the local test identity sorts below them. The control therefore
        // exercises one finite two-edge plan, not a serial single-edge path.
        insert_session_less_peer(&state, "~edge-a", None);
        insert_session_less_peer(&state, "~edge-b", None);

        let shaped = legacy_shape_step("shape", shape_connections(&state)).await;
        let observed = ["~edge-a", "~edge-b"].map(|id| {
            state.peers.get(id).map(|peer| {
                let has_worker = peer.has_current_worker();
                let status = peer.state.read().status;
                (has_worker, status)
            })
        });
        let drained = finish_legacy_shape_control(state).await;
        assert!(shaped && drained);
        for (id, observed) in ["~edge-a", "~edge-b"].into_iter().zip(observed) {
            let (has_worker, status) = observed.expect("planned edge remains visible");
            assert!(
                has_worker,
                "every unique wanted edge starts a carrier: {id}"
            );
            assert_ne!(
                status,
                PeerStatus::Active,
                "carrier creation alone cannot promote an application session: {id}"
            );
        }
    }

    #[tokio::test]
    async fn shape_pass_prunes_only_when_both_sides_shelved() {
        let state = build_test_state("shape-prune");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        // A spoke↔spoke connection (no edge under Star): built as a real
        // session so the prune has something to close.
        let opened = legacy_shape_step(
            "open",
            crate::engine::ensure_peer_session(&state, "spoke-b", crate::transport::Role::Offerer),
        )
        .await;
        if let Some(peer) = state.peers.get("spoke-b") {
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
            data.remote_shelved = false; // remote hasn't agreed yet
        }
        let first = legacy_shape_step("shape-one-sided", shape_connections(&state)).await;
        let one_sided_retained = state
            .peers
            .get("spoke-b")
            .is_some_and(|peer| peer.has_current_worker());
        if let Some(peer) = state.peers.get("spoke-b") {
            peer.state.write().remote_shelved = true;
        }
        let second = legacy_shape_step("shape-both-sides", shape_connections(&state)).await;
        let pruned = state
            .peers
            .get("spoke-b")
            .is_some_and(|peer| !peer.has_current_worker());
        let drained = finish_legacy_shape_control(state).await;
        assert!(opened && first && second && drained);
        assert!(one_sided_retained, "one-sided shelve must NOT prune");
        assert!(
            pruned,
            "both-sides-shelved non-edge closes, member stays Sighted"
        );
    }

    #[tokio::test]
    async fn reevaluate_never_shelves_a_pinned_peer() {
        let state = build_test_state("shelve-sticky");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        // A live spoke↔spoke session (no edge under Star) held by a pin —
        // a technician's standing support dial.
        let opened = legacy_shape_step(
            "open",
            crate::engine::ensure_peer_session(&state, "spoke-b", crate::transport::Role::Offerer),
        )
        .await;
        state.add_sticky("spoke-b");
        if let Some(peer) = state.peers.get("spoke-b") {
            peer.state.write().status = PeerStatus::Active;
        }
        let reevaluated = legacy_shape_step("reevaluate", reevaluate_topology(&state)).await;
        let observed = state.peers.get("spoke-b").map(|peer| {
            let data = peer.state.read();
            (data.local_shelved, data.status)
        });
        let drained = finish_legacy_shape_control(state).await;
        assert!(opened && reevaluated && drained);
        let (local_shelved, status) = observed.expect("pinned peer remains visible");
        assert!(
            !local_shelved,
            "the pin-holder must not shelve its pinned peer — its Shelve is \
             the far (pinless) side's missing half of the prune agreement"
        );
        assert_eq!(status, PeerStatus::Active, "the link stays Active");
    }

    #[tokio::test]
    async fn reevaluate_unshelves_a_peer_that_became_pinned() {
        let state = build_test_state("unshelve-sticky");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        let opened = legacy_shape_step(
            "open",
            crate::engine::ensure_peer_session(&state, "spoke-b", crate::transport::Role::Offerer),
        )
        .await;
        // Shelved before the pin existed (the dial raced the shelve pass) —
        // the next reevaluation must heal it back to Active.
        if let Some(peer) = state.peers.get("spoke-b") {
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
        }
        state.add_sticky("spoke-b");
        let reevaluated = legacy_shape_step("reevaluate", reevaluate_topology(&state)).await;
        let observed = state.peers.get("spoke-b").map(|peer| {
            let data = peer.state.read();
            (data.local_shelved, data.status)
        });
        let drained = finish_legacy_shape_control(state).await;
        assert!(opened && reevaluated && drained);
        let (local_shelved, status) = observed.expect("pinned peer remains visible");
        assert!(!local_shelved, "the pin un-shelves the link");
        assert_eq!(status, PeerStatus::Active);
    }

    #[tokio::test]
    async fn shape_pass_never_prunes_a_pinned_peer() {
        let state = build_test_state("shape-sticky");
        let mode = TopologyMode::Star { hub: "~hub".into() };
        *state.topology.write() = mode.clone();
        *state.topology_impl.write() = from_mode(&mode);
        let opened = legacy_shape_step(
            "open",
            crate::engine::ensure_peer_session(&state, "spoke-b", crate::transport::Role::Offerer),
        )
        .await;
        state.add_sticky("spoke-b");
        if let Some(peer) = state.peers.get("spoke-b") {
            let mut data = peer.state.write();
            data.status = PeerStatus::Shelved;
            data.local_shelved = true;
            data.remote_shelved = true;
        }
        let shaped = legacy_shape_step("shape", shape_connections(&state)).await;
        let retained = state
            .peers
            .get("spoke-b")
            .is_some_and(|peer| peer.has_current_worker());
        let drained = finish_legacy_shape_control(state).await;
        assert!(opened && shaped && drained);
        assert!(retained, "a standing dial outranks the shape");
    }
}
