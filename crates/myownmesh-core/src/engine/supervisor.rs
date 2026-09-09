//! Runtime supervisor for one joined network.
//!
//! The supervisor owns the driver loop and its event fan-in.  Construction,
//! semantic authority, and per-peer lifecycle remain in their dedicated
//! engine modules; this module only coordinates their narrow ports.

use std::sync::Arc;
use std::time::{Duration, Instant};

use tracing::{debug, trace, warn};

use crate::events::DropReason;

use super::signaling_ingress::EphemeralIngress;
use super::state::{NetworkCmd, NetworkState};
use super::{network_watch, reliable};

#[cfg(all(test, feature = "transport-lab"))]
struct ConnectionCommandGateInner {
    entered: std::sync::atomic::AtomicBool,
    released: std::sync::atomic::AtomicBool,
    entered_notify: tokio::sync::Notify,
    released_notify: tokio::sync::Notify,
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct ConnectionCommandGate(Arc<ConnectionCommandGateInner>);

#[cfg(all(test, feature = "transport-lab"))]
fn connection_command_gate_slot(
) -> &'static parking_lot::Mutex<Option<Arc<ConnectionCommandGateInner>>> {
    static SLOT: std::sync::OnceLock<parking_lot::Mutex<Option<Arc<ConnectionCommandGateInner>>>> =
        std::sync::OnceLock::new();
    SLOT.get_or_init(|| parking_lot::Mutex::new(None))
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn install_connection_command_gate_for_test() -> ConnectionCommandGate {
    let gate = Arc::new(ConnectionCommandGateInner {
        entered: std::sync::atomic::AtomicBool::new(false),
        released: std::sync::atomic::AtomicBool::new(false),
        entered_notify: tokio::sync::Notify::new(),
        released_notify: tokio::sync::Notify::new(),
    });
    assert!(connection_command_gate_slot()
        .lock()
        .replace(Arc::clone(&gate))
        .is_none());
    ConnectionCommandGate(gate)
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) async fn wait_connection_command_gate_for_test(gate: &ConnectionCommandGate) {
    loop {
        let notified = gate.0.entered_notify.notified();
        tokio::pin!(notified);
        notified.as_mut().enable();
        if gate.0.entered.load(std::sync::atomic::Ordering::Acquire) {
            return;
        }
        notified.await;
    }
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn release_connection_command_gate_for_test(gate: &ConnectionCommandGate) {
    gate.0
        .released
        .store(true, std::sync::atomic::Ordering::Release);
    gate.0.released_notify.notify_waiters();
    let removed = connection_command_gate_slot().lock().take();
    assert!(
        removed.is_some(),
        "connection command gate was not installed"
    );
}

#[cfg(all(test, feature = "transport-lab"))]
async fn hold_connection_command_gate() {
    let Some(gate) = connection_command_gate_slot().lock().clone() else {
        return;
    };
    let released = gate.released_notify.notified();
    tokio::pin!(released);
    released.as_mut().enable();
    gate.entered
        .store(true, std::sync::atomic::Ordering::Release);
    gate.entered_notify.notify_waiters();
    if !gate.released.load(std::sync::atomic::Ordering::Acquire) {
        released.await;
    }
}

pub(super) async fn run_connection_commands(
    state: Arc<NetworkState>,
    mut receiver: crate::resource::ResourceMailboxReceiver<NetworkCmd>,
) {
    while let Some(delivery) = receiver.recv().await {
        let command_state = Arc::clone(&state);
        delivery
            .run_terminal_effect(|command| async move {
                match command {
                    NetworkCmd::ConnectPeer {
                        device_id,
                        sticky,
                        reply,
                    } => {
                        #[cfg(all(test, feature = "transport-lab"))]
                        hold_connection_command_gate().await;
                        connect_peer(&command_state, &device_id, sticky, reply).await;
                    }
                    NetworkCmd::BeginIntroducedPeer { device_id, ticket } => {
                        super::begin_introduced_peer(&command_state, &device_id, ticket).await;
                    }
                    NetworkCmd::SettleIntroduction {
                        key,
                        ticket,
                        generation,
                    } => {
                        command_state
                            .settle_failed_introduction(key, ticket, generation)
                            .await;
                    }
                    NetworkCmd::SettleIntroductionWait(wait) => {
                        command_state.settle_introduction_wait(wait).await;
                    }
                    NetworkCmd::IntroducedSignaling(signal) => {
                        super::handle_signaling_inbound(&command_state, signal.0).await;
                    }
                    NetworkCmd::OpaqueChange(change) => {
                        command_state.run_opaque_change(change).await;
                    }
                    _ => {
                        // The sender is private to NetworkState; this is a
                        // defensive terminal path that still settles a
                        // delivery if an internal caller violates that seam.
                        warn!("non-connection command reached connection lane");
                    }
                }
            })
            .await;
        #[cfg(test)]
        state.notify_connect_waiter_terminal_for_test();
    }
}

/// The engine's main loop. Owns the per-network state and the
/// fan-in mpsc that consolidates signaling, transport, and
/// command events.
pub(crate) async fn run_driver(
    state: Arc<NetworkState>,
    mut signaling_inbound: crate::resource::ResourceMailboxReceiver<EphemeralIngress>,
    mut cmd_rx: crate::resource::ResourceMailboxReceiver<NetworkCmd>,
) {
    let mut speculative_promotion_rx = state
        .take_speculative_promotion_rx()
        .expect("the network driver takes its speculative-promotion receiver once");
    let connection_cmd_rx = state
        .take_connection_cmd_rx()
        .expect("the network driver takes its connection receiver once");
    state.log_diag(crate::events::DiagLevel::Info, "engine", "driver starting");
    // Settle the signed-eviction verdict from the persisted governance
    // state before anything announces or dials: a device evicted in a
    // previous run must come up stood-down (and re-emit the event so an
    // embedding app that missed it can clean up), not spend another
    // session redialing into denials.
    super::governance::refresh_self_evicted(&state);
    if state.self_evicted.load(std::sync::atomic::Ordering::SeqCst) {
        // A terminal recovery cohort is a carrier-owned retry, not a
        // re-admission mechanism.  A persisted self-eviction therefore
        // releases it at startup; only a later signed lifecycle event may
        // make the device live again.
        state.cancel_all_recovery_demands();
    }
    // Surface the ICE-server configuration so users can confirm at
    // a glance whether they have any relay coverage. Mirrors
    // MyOwnLLM's pattern: when peers get stuck at ICE-checking with
    // 0 relay candidates, this line is the first thing to point at.
    {
        let cfg = state.config.read();
        let stun_count: usize = cfg.stun_servers.iter().map(|s| s.urls.len()).sum();
        let turn_count: usize = cfg.turn_servers.iter().map(|s| s.urls.len()).sum();
        let turn_summary = if turn_count == 0 {
            "no TURN configured (CGNAT / phone-hotspot will fail to connect)".to_string()
        } else {
            format!("{turn_count} TURN URL(s)")
        };
        state.log_diag_with(
            crate::events::DiagLevel::Info,
            "engine",
            format!("ICE servers: {stun_count} STUN URL(s), {turn_summary}"),
            serde_json::json!({
                "stun_count": stun_count,
                "turn_count": turn_count,
                "auto_approve": cfg.auto_approve,
            }),
        );
        drop(cfg);
    }

    let scheduler_policy = state
        .config
        .read()
        .scheduler_policy()
        .expect("scheduler policy is validated before engine side effects");

    // Top-level interval ticks. We hold them across the loop so
    // sleeping happens inside `tokio::select!` — no separate
    // task means a wake-event after a long-sleep tick gap is
    // observable here without coordination.
    let mut heartbeat = tokio::time::interval(Duration::from_millis(
        scheduler_policy.heartbeat_interval_ms,
    ));
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // One periodic pass covers ICE watchdog and network watch together.
    // Recovery is event-driven first; this is the secondary safety-net tick
    // (see the checked `NetworkConfig::scheduler.state_watch_interval_ms`)
    // that confirms state and
    // handles the inherently time-based conditions.
    let mut state_watch = tokio::time::interval(Duration::from_millis(
        scheduler_policy.state_watch_interval_ms,
    ));
    state_watch.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // The secondary control path: a registry of time-based subsystems run on
    // each state-watch tick. Events drive state; these confirm and repair the
    // conditions no event can signal. New network-intelligence systems plug in
    // here — see `engine::tick`.
    let mut tick_registry = super::tick::TickRegistry::new()
        .register(super::tick::IceWatchdogTicker)
        .register(super::tick::NetworkWatchTicker::new().await)
        .register(super::tick::FactInventoryTicker)
        .register(super::tick::ReliableSendTicker)
        .register(super::tick::TopologyShapeTicker)
        .register(super::tick::MediaRenegotiationTicker);
    state.log_diag_with(
        crate::events::DiagLevel::Debug,
        "engine",
        format!("state-watch tick registry: {:?}", tick_registry.names()),
        serde_json::json!({ "tickers": tick_registry.names() }),
    );
    let mut wake_detector = super::wake::WakeDetector::new();
    // Phase-0 connection tracer. Observes per-peer connection-state
    // transitions after each driver-loop iteration. Zero cost unless a
    // `ctl trace` subscriber is attached or `MYOWNMESH_CONN_TRACE` is
    // set — see `engine::conn_trace`.
    let mut conn_tracer = super::conn_trace::ConnTracer::new();

    // Why the loop below exits — surfaced in the "driver stopping" line so a
    // restart's *cause* is greppable. A network re-join (leave + re-join) is
    // the only way a fresh `run_driver`/Nostr driver appears mid-run, and
    // chasing one in the field is otherwise guesswork: "shutdown command" is a
    // deliberate leave/`network_update`/`network_remove`, "command channel
    // closed" is the registry dropping us, "signaling channel closed" is the
    // relay/signaling feed dying.
    // This is one concrete, parent-owned actor future rather than one boxed
    // allocation per command. Its receiver and current delivery therefore
    // remain owned by this lexical block and are dropped before state shutdown.
    let stop_reason: &str = {
        let connection_actor = run_connection_commands(Arc::clone(&state), connection_cmd_rx);
        tokio::pin!(connection_actor);
        let mut connection_actor_done = false;
        loop {
            tokio::select! {
                _ = state.wait_for_shutdown() => {
                    break "shutdown requested";
                }

                _ = &mut connection_actor, if !connection_actor_done => {
                    connection_actor_done = true;
                }

                cmd = cmd_rx.recv() => {
                    let Some(cmd) = cmd else { break "command channel closed" };
                    // A command is handled, not read: fifteen `NetworkCmd` variants
                    // carry a `oneshot::Sender` that answering consumes, so this is
                    // the one path that cannot work from a borrow. The terminal
                    // effect releases the delivery's funding only after
                    // `handle_command` has finished, and can return nothing, so
                    // neither the command nor anything derived from it outlives
                    // the claim.
                    cmd.run_terminal_effect(|cmd| handle_command(&state, cmd)).await;
                }

                promotion = speculative_promotion_rx.recv() => {
                    let Some(promotion) = promotion else {
                        break "speculative promotion channel closed";
                    };
                    promotion
                        .run_terminal_effect(|promotion| {
                            super::handle_speculative_promotion(&state, promotion)
                        })
                        .await;
                }

                sig = signaling_inbound.recv() => {
                    let Some(sig) = sig else {
                        warn!(network = %state.network_id, "signaling channel closed");
                        break "signaling channel closed";
                    };
                    // Same shape as the command arm above, for the same reason:
                    // the delivery's payloads are consumed by
                    // value downstream — `apply_remote_sdp` takes an owned `String`
                    // and `add_remote_candidate_observed` takes an owned
                    // `LocalIceCandidate`. Handling from a borrow would mean
                    // cloning two multi-kilobyte SDP bodies and an ICE candidate
                    // outside the claim that funded them, so the whole delivery
                    // rides into the handler and its funding is released only after
                    // the handler has finished.
                    sig.run_terminal_effect(|sig| async {
                        if sig.introduction_ticket().is_some() {
                            // Re-admit retained ownership before releasing this
                            // mailbox delivery. Native Offer/Answer work then
                            // runs on the existing separately joined lane.
                            let _ = state.queue_introduction_signal(sig);
                        } else {
                            super::handle_signaling_inbound(&state, sig).await;
                        }
                    }).await;
                }

                _ = heartbeat.tick() => {
                    wake_detector.observe_with_policy(
                        Instant::now(),
                        scheduler_policy.heartbeat_interval_ms,
                        &scheduler_policy,
                    );
                    super::heartbeat::tick(&state).await;
                    if wake_detector.take_wake_event() {
                        debug!(network = %state.network_id, "wake event observed");
                        super::wake::on_wake(&state).await;
                    }
                }

                _ = state_watch.tick() => {
                    // Secondary safety net only — events drive recovery. Each
                    // registered ticker confirms its slice of state and repairs
                    // the time-based conditions no event can signal. The trace doubles
                    // as the driver's liveness heartbeat in debug captures: when
                    // the driver wedges, this is the line that stops.
                    trace!(network = %state.network_id, "driver: state-watch tick");
                    tick_registry.run(&state).await;
                }
            }

            // Observe the post-event connection state. Cheap no-op unless
            // someone is watching; never holds a per-peer lock across an
            // await (the handler above has already returned).
            conn_tracer.sweep(&state);
        }
    };

    state.log_diag_with(
        crate::events::DiagLevel::Info,
        "engine",
        format!("driver stopping ({stop_reason})"),
        serde_json::json!({ "reason": stop_reason }),
    );
    // Resolve exact departure waiters before peer teardown.  A connected but
    // silent remote cannot be allowed to keep shutdown behind an observation
    // that will never arrive; the peer-session cancellation edge is the
    // authority that settles the waiter, not a timer or a synthetic receipt.
    state.peers.cancel_pending_departures_for_shutdown();
    // The connection actor's lexical owner has ended before this point, so
    // its current delivery and queued mailbox entries settled before state
    // shutdown without a detached task or a second task grant.
    state.shutdown().await;
}

use super::{
    broadcast_capabilities, broadcast_channel_frame, connect_peer,
    drop_carrier_if_current_with_correlation, drop_peer, drop_peer_if_current, governance, ladder,
    replay_local_capabilities_to_owner, replay_pending_durable_proofs,
    retire_speculative_carrier_attempt_if_current, send_channel_frame, send_rpc_request,
};

pub(crate) async fn handle_command(state: &Arc<NetworkState>, cmd: NetworkCmd) {
    match cmd {
        NetworkCmd::OpaqueControl(transfer) => super::write_opaque_control(state, transfer).await,
        NetworkCmd::EndpointControls(transfer) => {
            super::write_endpoint_controls(state, transfer).await
        }
        NetworkCmd::OpaqueChange(change) => {
            // This variant is admitted only to the separately owned connection
            // lane. A misplaced command fails closed without publishing it.
            drop(change);
        }
        NetworkCmd::SetTopology(mode) => {
            // A funded Hub controller retains configuration-bound replay and
            // discovery state. The public API checks this too, but commands
            // admitted before a configuration change must not bypass it.
            let requires_replacement = {
                let config = state.config.read();
                super::reconcile::topology_requires_restart(&config, &mode)
            };
            if requires_replacement {
                tracing::warn!("topology command refused: funded Hub or tree state requires runtime replacement");
                return;
            }
            // Topology is explicit connector/deployment policy, not a
            // governance authority-bearing fact.  Apply the local command
            // directly; canonical governance projection never derives a
            // topology selector from the compatibility DTO.
            let changed = {
                let mut current = state.topology.write();
                let changed = *current != mode;
                *current = mode.clone();
                changed
            };
            *state.topology_impl.write() = crate::topology::from_mode(&mode);
            if changed {
                state.note_hub_local_topology_change();
            }
            ladder::reevaluate_topology(state).await;
        }
        // A successful approval changed our roster — advertise the new
        NetworkCmd::DropPeer { device_id, reason } => {
            drop_peer(state, &device_id, reason).await;
        }
        NetworkCmd::DropPeerIfCurrent {
            owner,
            attempt,
            reason,
        } => {
            drop_carrier_if_current_with_correlation(state, &owner, reason, &attempt).await;
        }
        NetworkCmd::AttemptRefused { owner, refusal } => {
            if retire_speculative_carrier_attempt_if_current(state, &owner, &refusal.attempt).await
            {
                return;
            }
            let current = state.peers.get_if_current(&owner).is_some_and(|peer| {
                owner.worker().map_or_else(
                    || peer.attempt() == refusal.attempt,
                    |worker| {
                        peer.attempt_for_worker(worker).as_deref() == Some(refusal.attempt.as_str())
                    },
                )
            });
            if current {
                let reason = match refusal.refusal {
                    myownmesh_signaling::NegotiationRefusal::DuplicateLiveEvent => {
                        "Nostr attempt was refused as a duplicate live event".to_string()
                    }
                    myownmesh_signaling::NegotiationRefusal::Provider(reason) => reason,
                };
                drop_peer_if_current(
                    state,
                    &owner,
                    DropReason::TransportError { message: reason },
                )
                .await;
            }
        }
        NetworkCmd::AttemptOutcome { owner, outcome } => {
            if matches!(
                &outcome.kind,
                myownmesh_signaling::AttemptOutcomeKind::TypedRefused(_)
                    | myownmesh_signaling::AttemptOutcomeKind::CarrierUnavailable
            ) && retire_speculative_carrier_attempt_if_current(state, &owner, &outcome.attempt)
                .await
            {
                return;
            }
            let current = state.peers.get_if_current(&owner).is_some_and(|peer| {
                owner.worker().map_or_else(
                    || peer.attempt() == outcome.attempt,
                    |worker| {
                        peer.attempt_for_worker(worker).as_deref() == Some(outcome.attempt.as_str())
                    },
                )
            });
            if !current {
                return;
            }
            match outcome.kind {
                myownmesh_signaling::AttemptOutcomeKind::Accepted { .. }
                | myownmesh_signaling::AttemptOutcomeKind::Cancelled
                | myownmesh_signaling::AttemptOutcomeKind::Replaced => {
                    // Accepted is provider observation only: the engine's
                    // transport success path owns completion settlement, and
                    // Cancelled/Replaced were already settled by that owner.
                }
                myownmesh_signaling::AttemptOutcomeKind::TypedRefused(reason) => {
                    drop_peer_if_current(
                        state,
                        &owner,
                        DropReason::TransportError {
                            message: format!("Nostr attempt refused: {reason}"),
                        },
                    )
                    .await;
                }
                myownmesh_signaling::AttemptOutcomeKind::CarrierUnavailable => {
                    drop_peer_if_current(
                        state,
                        &owner,
                        DropReason::TransportError {
                            message: "Nostr signaling carrier unavailable".to_string(),
                        },
                    )
                    .await;
                }
            }
        }
        NetworkCmd::Reconnect { peer } => match peer {
            Some(device_id) => network_watch::reconnect_peer_in_place(state, &device_id).await,
            None => network_watch::reconnect_all_in_place(state).await,
        },
        NetworkCmd::ConnectPeer {
            device_id,
            sticky,
            reply,
        } => connect_peer(state, &device_id, sticky, reply).await,
        NetworkCmd::BeginIntroducedPeer { device_id, ticket } => {
            // Establishment belongs to the separately joined connection lane.
            let _ = state.queue_introduced_peer(device_id, ticket);
        }
        NetworkCmd::IntroducedSignaling(signal) => {
            let _ = state.queue_introduction_signal(signal.0);
        }
        NetworkCmd::SettleIntroduction {
            key,
            ticket,
            generation,
        } => {
            state.queue_failed_introduction(key, ticket, generation);
        }
        NetworkCmd::SettleIntroductionWait(_) => {
            // Only the private connection sender admits this transfer. A
            // misrouted transfer is not authority to drive cleanup here.
            warn!("introduction settlement waiter reached wrong command lane");
        }
        NetworkCmd::SendChannelReliable {
            peer,
            channel,
            payload,
            reply,
        } => {
            reliable::submit(state, &peer, &channel, payload, reply).await;
        }
        NetworkCmd::SendChannelFrame {
            peer,
            channel,
            payload,
            reply,
        } => {
            if state
                .peers
                .owner(&peer)
                .is_some_and(|owner| state.peers.has_usable_authenticated_current(&owner))
            {
                let result = send_channel_frame(state, &peer, &channel, payload).await;
                let _ = reply.send(result);
            } else {
                let mut reply = Some(reply);
                let result =
                    super::queue_routed_channel_frame(state, &peer, &channel, payload, &mut reply);
                if let Some(reply) = reply {
                    let _ = reply.send(result);
                }
            }
        }
        NetworkCmd::BroadcastChannelFrame {
            channel,
            payload,
            reply,
        } => {
            let count = broadcast_channel_frame(state, &channel, payload).await;
            let _ = reply.send(count);
        }
        NetworkCmd::SendRpcRequest {
            peer,
            request,
            reply,
        } => {
            let result = send_rpc_request(state, &peer, request).await;
            let _ = reply.send(result);
        }
        // Nobody to answer. `Rpc::advertise` committed the value locally and
        // returned; this is the fan-out it did not wait for.
        // Reaching zero peers is not a failure — a node with no live session has
        // nothing to push, and the value is replayed to each session as it is
        // established — so the count is discarded rather than reported.
        NetworkCmd::FanoutCapabilities { caps } => {
            let _ = broadcast_capabilities(state, caps).await;
        }
        // The registry fence enqueued this at the moment it minted a session, and
        // it is handled here because the send awaits and no fence lock may be held
        // across it. Nothing is answered to a caller: the command carries no reply
        // channel because no local caller is waiting on it — the session it names
        // is what asked, by coming into existence owing an advertisement.
        NetworkCmd::ReplayCapabilities { owner } => {
            // Reconcile and persist every exact proof obligation before the
            // unrelated capability replay can yield on transport. Preparation
            // owns the current-owner/binding fence and releases its guard
            // before the proof send; a reconnect therefore cannot observe an
            // unprepared Pending record or race a stale replay behind this
            // capability await.
            replay_pending_durable_proofs(state, &owner).await;
            replay_local_capabilities_to_owner(state, &owner).await;
        }
        // ---- governance ops ----
        NetworkCmd::ProposeRoleGrant {
            target,
            role,
            mfa_code,
            reply,
        } => {
            let result =
                governance::propose_role_grant(state, &target, role, mfa_code.as_deref()).await;
            let _ = reply.send(result);
        }
        NetworkCmd::ProposeRoleRevoke {
            target,
            mfa_code,
            reply,
        } => {
            let result = governance::propose_role_revoke(state, &target, mfa_code.as_deref()).await;
            let _ = reply.send(result);
        }
        NetworkCmd::ProposeEvict {
            target,
            mfa_code,
            reply,
        } => {
            let result = governance::propose_evict(state, &target, mfa_code.as_deref()).await;
            let _ = reply.send(result);
        }
    }
}
