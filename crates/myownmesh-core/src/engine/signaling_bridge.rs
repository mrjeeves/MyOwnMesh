//! Adapter that connects an [`crate::engine::state::NetworkState`]
//! to one or more signaling drivers. The signaling crate emits its
//! own generic [`myownmesh_signaling::SignalingMessage`] type; this
//! module translates between that shape and the engine's
//! `SignalingInbound` / `SignalingOutbound` enums.
//!
//! Entry points:
//!
//! - [`attach_signaling`] — the production path: reads the network's
//!   `SignalingConfig` and attaches the remote strategy (`"nostr"` /
//!   `"none"`) plus, when `mdns` is on (the default), the LAN mDNS
//!   driver. With both attached, a fan-out task clones each engine
//!   emission to every driver (the engine's outbound receiver is
//!   single-consumer) and an [`InboundGate`] drops the cross-driver
//!   duplicate Offer/Answer/Candidate deliveries — applying the same
//!   remote description twice wedges WebRTC permanently, the exact
//!   failure the Nostr driver's per-event dedup guards against
//!   within one transport.
//! - [`attach_nostr`] / [`attach_mdns`] — single-driver attaches for
//!   embedders that pick a transport directly.
//! - [`attach_local`] — an in-process
//!   [`myownmesh_signaling::local::LocalBroker`] (tests and
//!   single-process apps).

use std::collections::VecDeque;
use std::hash::{Hash, Hasher};
use std::sync::Arc;

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::mdns::{
    self as mdns_driver, MdnsDriverConfig, MdnsDriverHandle, MdnsInbound, MdnsOutbound,
};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::SignalingMessage;
use parking_lot::Mutex;
use tokio::sync::mpsc;
use tracing::{trace, warn};

use crate::transport::LocalIceCandidate;

use super::state::{NetworkState, SignalingInbound, SignalingOutbound};

/// Attach an existing [`NetworkState`] to a [`LocalBroker`] room.
/// Spawns two pump tasks (outbound engine → broker, inbound
/// broker → engine) that live until either side closes its
/// queue. Returns once both pumps are spawned.
pub fn attach_local(state: &Arc<NetworkState>, broker: &LocalBroker) {
    let room = myownmesh_signaling::nostr::handle::derive_room_handle(
        &resolve_app_id(),
        &state.network_id,
    );
    let device_id = state.identity.public_id().to_string();
    let (out_tx, mut in_rx) = broker.join(&room, &device_id);

    // Outbound: engine → broker.
    let Some(mut outbound_rx) = state.take_signaling_outbound_rx() else {
        // Only one consumer is allowed; if someone else already
        // attached, the second attach is a no-op.
        return;
    };
    let device_id_for_out = device_id.clone();
    tokio::spawn(async move {
        // Announce ourselves on join so peers learn we're here
        // even if the engine doesn't emit anything immediately.
        let _ = out_tx.send(LocalOutbound::Announce {
            device_id: device_id_for_out.clone(),
        });
        while let Some(outbound) = outbound_rx.recv().await {
            let msg = match outbound {
                SignalingOutbound::Announce => LocalOutbound::Announce {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Leave => LocalOutbound::Leave {
                    device_id: device_id_for_out.clone(),
                },
                SignalingOutbound::Offer { device_id: to, sdp } => LocalOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Offer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: new_short_id(),
                        sdp,
                    },
                },
                SignalingOutbound::Answer { device_id: to, sdp } => LocalOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Answer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: String::new(),
                        sdp,
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    candidate,
                } => LocalOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Candidate {
                        peer_id: device_id_for_out.clone(),
                        candidate: candidate.candidate,
                        sdp_mid: candidate.sdp_mid,
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment,
                    },
                },
            };
            if out_tx.send(msg).is_err() {
                break;
            }
        }
        trace!("outbound pump exiting");
    });

    // Inbound: broker → engine.
    let inbound_tx = state.signaling_inbound_tx.clone();
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let translated = match inbound {
                LocalInbound::PeerAnnounced { device_id } => {
                    SignalingInbound::PeerAnnounced { device_id }
                }
                LocalInbound::PeerLeft { device_id } => SignalingInbound::PeerLeft { device_id },
                LocalInbound::Message { from, msg } => match msg {
                    SignalingMessage::Announce { peer_id } => {
                        let _ = peer_id; // peer id is informational; we use `from`
                        SignalingInbound::PeerAnnounced { device_id: from }
                    }
                    SignalingMessage::Leave { peer_id } => {
                        SignalingInbound::PeerLeft { device_id: peer_id }
                    }
                    SignalingMessage::Offer { sdp, .. } => SignalingInbound::Offer {
                        device_id: from,
                        sdp,
                    },
                    SignalingMessage::Answer { sdp, .. } => SignalingInbound::Answer {
                        device_id: from,
                        sdp,
                    },
                    SignalingMessage::Candidate {
                        candidate,
                        sdp_mid,
                        sdp_mline_index,
                        username_fragment,
                        ..
                    } => SignalingInbound::Candidate {
                        device_id: from,
                        candidate: LocalIceCandidate {
                            candidate,
                            sdp_mid,
                            sdp_mline_index,
                            username_fragment,
                        },
                    },
                },
            };
            if inbound_tx.send(translated).is_err() {
                break;
            }
        }
        trace!("inbound pump exiting");
    });
}

fn resolve_app_id() -> String {
    std::env::var("MYOWNMESH_TRYSTERO_APP_ID")
        .unwrap_or_else(|_| crate::TRYSTERO_APP_ID.to_string())
}

fn new_short_id() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let bytes: [u8; 8] = rng.gen();
    data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase()
}

/// Window of the cross-driver dedup ring. Same order of magnitude as
/// the Nostr driver's per-event ring — comfortably covers the
/// busiest realistic mesh without unbounded growth.
const GATE_SEEN_CAPACITY: usize = 2048;

/// Engine-facing delivery gate shared by every driver pump attached
/// to one network. Announces and departures pass through untouched
/// (the engine is idempotent on those — repeats are its retry
/// pacing). Offer/Answer/Candidate are deduped **by content**: with
/// Nostr and mDNS attached concurrently, one engine emission fans
/// out to both transports and arrives twice at the peer, and each
/// driver stamps its own envelope (different Nostr event id,
/// different offer_id) — so only the payload identifies the
/// duplicate, and applying it twice via `set_remote_description`
/// wedges WebRTC permanently.
struct InboundGate {
    tx: mpsc::UnboundedSender<SignalingInbound>,
    seen: Mutex<VecDeque<u64>>,
}

impl InboundGate {
    fn new(tx: mpsc::UnboundedSender<SignalingInbound>) -> Arc<Self> {
        Arc::new(Self {
            tx,
            seen: Mutex::new(VecDeque::with_capacity(GATE_SEEN_CAPACITY)),
        })
    }

    /// Deliver to the engine unless it's a cross-driver duplicate.
    /// Returns `false` once the engine side is gone (pump exits).
    fn deliver(&self, msg: SignalingInbound) -> bool {
        if let Some(key) = dedup_key(&msg) {
            let mut seen = self.seen.lock();
            if seen.contains(&key) {
                trace!(kind = msg.kind_name(), "cross-driver duplicate dropped");
                return true;
            }
            if seen.len() >= GATE_SEEN_CAPACITY {
                seen.pop_front();
            }
            seen.push_back(key);
        }
        self.tx.send(msg).is_ok()
    }
}

/// Content key for the gate. `None` = never deduped.
fn dedup_key(msg: &SignalingInbound) -> Option<u64> {
    let mut h = std::collections::hash_map::DefaultHasher::new();
    match msg {
        SignalingInbound::Offer { device_id, sdp } => {
            (1u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Answer { device_id, sdp } => {
            (2u8, device_id, sdp).hash(&mut h);
        }
        SignalingInbound::Candidate {
            device_id,
            candidate,
        } => {
            (
                3u8,
                device_id,
                &candidate.candidate,
                &candidate.sdp_mid,
                &candidate.sdp_mline_index,
                &candidate.username_fragment,
            )
                .hash(&mut h);
        }
        SignalingInbound::PeerAnnounced { .. } | SignalingInbound::PeerLeft { .. } => return None,
    }
    Some(h.finish())
}

/// Translate one driver-level directed message into the engine's
/// inbound shape — shared by every driver pump so the transports
/// can't drift.
fn translate_message(from: String, msg: SignalingMessage) -> SignalingInbound {
    match msg {
        SignalingMessage::Announce { peer_id } => {
            let _ = peer_id; // peer id is informational; we use `from`
            SignalingInbound::PeerAnnounced { device_id: from }
        }
        SignalingMessage::Leave { peer_id } => SignalingInbound::PeerLeft { device_id: peer_id },
        SignalingMessage::Offer { sdp, .. } => SignalingInbound::Offer {
            device_id: from,
            sdp,
        },
        SignalingMessage::Answer { sdp, .. } => SignalingInbound::Answer {
            device_id: from,
            sdp,
        },
        SignalingMessage::Candidate {
            candidate,
            sdp_mid,
            sdp_mline_index,
            username_fragment,
            ..
        } => SignalingInbound::Candidate {
            device_id: from,
            candidate: LocalIceCandidate {
                candidate,
                sdp_mid,
                sdp_mline_index,
                username_fragment,
            },
        },
    }
}

/// Attach the engine to the production Nostr signaling driver.
/// Returns the driver handle — drop or call `.stop()` to detach.
/// Prefer [`attach_signaling`] unless you specifically want Nostr
/// regardless of the network's configured strategy.
pub fn attach_nostr(state: &Arc<NetworkState>) -> Option<NostrDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());
    Some(attach_nostr_with(state, outbound_rx, gate))
}

/// [`attach_nostr`] with an explicit outbound receiver + delivery
/// gate, so [`attach_signaling`]'s fan-out can feed several drivers
/// from the one engine receiver.
fn attach_nostr_with(
    state: &Arc<NetworkState>,
    mut outbound_rx: mpsc::UnboundedReceiver<SignalingOutbound>,
    gate: Arc<InboundGate>,
) -> NostrDriverHandle {
    let cfg = state.config.read();
    let nostr_cfg = NostrDriverConfig {
        app_id: resolve_app_id(),
        network_id: cfg.network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        servers: cfg.signaling.servers.clone(),
        denylist: cfg.signaling.denylist.clone(),
        redundancy: cfg.signaling.redundancy as usize,
        public_fallback: cfg.signaling.public_fallback,
    };
    let redundancy = nostr_cfg.redundancy;
    drop(cfg);

    let room_handle = myownmesh_signaling::nostr::handle::derive_room_handle(
        &nostr_cfg.app_id,
        &nostr_cfg.network_id,
    );
    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        format!(
            "online — listening for peers in room {}… ({} relays)",
            &room_handle[..room_handle.len().min(12)],
            redundancy,
        ),
    );

    let (out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<NostrInbound>();

    let device_id = state.identity.public_id().to_string();

    // Outbound pump: engine SignalingOutbound → NostrOutbound.
    let device_id_for_out = device_id.clone();
    tokio::spawn(async move {
        // No explicit startup announce here — the Nostr driver's
        // `run_announcer` fires immediately at t=0 and then follows
        // the adaptive backoff schedule (see
        // `upstream.rs` item 7). A second announce from the bridge
        // would just publish a duplicate event (different timestamp
        // → distinct sha256 id, so receiver-side dedup wouldn't
        // collapse it) — wasted relay bandwidth for no benefit.
        while let Some(outbound) = outbound_rx.recv().await {
            let translated = match outbound {
                SignalingOutbound::Announce => NostrOutbound::Announce,
                SignalingOutbound::Leave => NostrOutbound::Leave,
                SignalingOutbound::Offer { device_id: to, sdp } => NostrOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Offer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: new_short_id(),
                        sdp,
                    },
                },
                SignalingOutbound::Answer { device_id: to, sdp } => NostrOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Answer {
                        peer_id: device_id_for_out.clone(),
                        offer_id: String::new(),
                        sdp,
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    candidate,
                } => NostrOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Candidate {
                        peer_id: device_id_for_out.clone(),
                        candidate: candidate.candidate,
                        sdp_mid: candidate.sdp_mid,
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment,
                    },
                },
            };
            if out_tx.send(translated).is_err() {
                break;
            }
        }
        trace!("nostr outbound pump exiting");
    });

    // Inbound pump: NostrInbound → engine SignalingInbound, through
    // the shared gate (cross-driver dedup when mDNS is also attached).
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let translated = match inbound {
                NostrInbound::PeerAnnounced { device_id } => {
                    SignalingInbound::PeerAnnounced { device_id }
                }
                // An intelligent relay told us the peer's signaling socket
                // dropped — tear the peer down now rather than waiting for
                // the heartbeat timeout.
                NostrInbound::PeerLeft { device_id } => SignalingInbound::PeerLeft { device_id },
                NostrInbound::Message { from, msg } => translate_message(from, msg),
            };
            if !gate.deliver(translated) {
                break;
            }
        }
        trace!("nostr inbound pump exiting");
    });

    let handle = nostr_driver::start(nostr_cfg, out_rx, in_tx);
    // Hand the engine the force-reconnect signal so resume-from-sleep
    // (and any other recovery path) can make every relay redial at
    // once instead of waiting out a zombie socket. See
    // `wake::on_wake` and `NetworkState::request_relay_reconnect`.
    state.set_relay_reconnect(handle.reconnect_signal());
    // …and the relay-connected signal, so a network-change renegotiation can
    // wait for signaling to actually come back before it offers (see
    // `network_watch::on_network_change`).
    state.set_relay_connected_signal(handle.connected_signal());
    handle
}

/// Attach the engine to the LAN mDNS signaling driver. Returns the
/// driver handle — drop or call `.stop()` to withdraw the DNS-SD
/// advertisement and detach. `None` if another consumer already took
/// the engine's outbound receiver, or if the mDNS daemon / exchange
/// listener couldn't come up (no usable socket, no multicast).
/// Prefer [`attach_signaling`] unless you specifically want mDNS
/// regardless of the network's configured strategy.
pub fn attach_mdns(state: &Arc<NetworkState>) -> Option<MdnsDriverHandle> {
    let outbound_rx = state.take_signaling_outbound_rx()?;
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());
    attach_mdns_with(state, outbound_rx, gate)
}

/// [`attach_mdns`] with an explicit outbound receiver + delivery
/// gate — the fan-out building block. On driver-start failure the
/// receiver is dropped (a fan-out sender to it becomes a no-op) and
/// a warning names the network.
fn attach_mdns_with(
    state: &Arc<NetworkState>,
    mut outbound_rx: mpsc::UnboundedReceiver<SignalingOutbound>,
    gate: Arc<InboundGate>,
) -> Option<MdnsDriverHandle> {
    let mdns_cfg = MdnsDriverConfig {
        app_id: resolve_app_id(),
        network_id: state.config.read().network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        service_port: 0,
    };

    let (out_tx, out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (in_tx, mut in_rx) = mpsc::unbounded_channel::<MdnsInbound>();

    // Start the driver before consuming anything else — its setup is
    // synchronously fallible (mDNS daemon, TCP listener), unlike
    // Nostr's lazy socket dials.
    let handle = match mdns_driver::start(mdns_cfg, out_rx, in_tx) {
        Ok(h) => h,
        Err(e) => {
            warn!(network = %state.network_id, "mdns signaling unavailable: {e}");
            return None;
        }
    };

    state.log_diag(
        crate::events::DiagLevel::Info,
        "signaling",
        "LAN signaling online — advertising on this network via mDNS".to_string(),
    );

    let device_id = state.identity.public_id().to_string();

    // Outbound pump: engine SignalingOutbound → MdnsOutbound. The
    // driver's registration doubles as the announce, so Announce is
    // a cheap idempotent nudge.
    tokio::spawn(async move {
        while let Some(outbound) = outbound_rx.recv().await {
            let translated = match outbound {
                SignalingOutbound::Announce => MdnsOutbound::Announce,
                SignalingOutbound::Leave => MdnsOutbound::Leave,
                SignalingOutbound::Offer { device_id: to, sdp } => MdnsOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Offer {
                        peer_id: device_id.clone(),
                        offer_id: new_short_id(),
                        sdp,
                    },
                },
                SignalingOutbound::Answer { device_id: to, sdp } => MdnsOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Answer {
                        peer_id: device_id.clone(),
                        offer_id: String::new(),
                        sdp,
                    },
                },
                SignalingOutbound::Candidate {
                    device_id: to,
                    candidate,
                } => MdnsOutbound::DirectedToPeer {
                    to,
                    msg: SignalingMessage::Candidate {
                        peer_id: device_id.clone(),
                        candidate: candidate.candidate,
                        sdp_mid: candidate.sdp_mid,
                        sdp_mline_index: candidate.sdp_mline_index,
                        username_fragment: candidate.username_fragment,
                    },
                },
            };
            if out_tx.send(translated).is_err() {
                break;
            }
        }
        trace!("mdns outbound pump exiting");
    });

    // Inbound pump: MdnsInbound → engine, through the shared gate.
    tokio::spawn(async move {
        while let Some(inbound) = in_rx.recv().await {
            let translated = match inbound {
                MdnsInbound::PeerAnnounced { device_id } => {
                    SignalingInbound::PeerAnnounced { device_id }
                }
                MdnsInbound::PeerLeft { device_id } => SignalingInbound::PeerLeft { device_id },
                MdnsInbound::Message { from, msg } => translate_message(from, msg),
            };
            if !gate.deliver(translated) {
                break;
            }
        }
        trace!("mdns inbound pump exiting");
    });

    Some(handle)
}

/// Every signaling driver attached to one network, plus the fan-out
/// task feeding them. Stop-on-drop: the fan-out is aborted and each
/// driver handle's own `Drop` detaches it — so the registry tears
/// signaling down for a network by dropping this value, exactly as
/// it did with the bare Nostr handle before mDNS existed.
pub struct SignalingDrivers {
    nostr: Option<NostrDriverHandle>,
    mdns: Option<MdnsDriverHandle>,
    fanout: Option<tokio::task::JoinHandle<()>>,
}

impl SignalingDrivers {
    /// Which drivers are live — for logs/diagnostics.
    pub fn describe(&self) -> String {
        match (&self.nostr, &self.mdns) {
            (Some(_), Some(_)) => "nostr+mdns".into(),
            (Some(_), None) => "nostr".into(),
            (None, Some(_)) => "mdns".into(),
            (None, None) => "none".into(),
        }
    }
}

impl Drop for SignalingDrivers {
    fn drop(&mut self) {
        if let Some(fanout) = self.fanout.take() {
            fanout.abort();
        }
        // nostr / mdns handles stop via their own Drop impls.
    }
}

/// Attach the signaling driver(s) a network's `SignalingConfig`
/// selects — the production entry point used by the daemon:
///
/// - `strategy`: `""`/`"nostr"` → the Nostr relay driver; `"none"` →
///   no remote driver; anything else → **no remote driver, loudly**
///   (never a silent Nostr fallback).
/// - `mdns: true` (default) additionally attaches the LAN mDNS
///   driver.
///
/// With two drivers, a fan-out task clones each engine emission to
/// both (the engine's outbound receiver is single-consumer) and the
/// shared [`InboundGate`] drops cross-driver duplicate deliveries.
///
/// Returns `None` when the outbound receiver was already taken by an
/// earlier attach. A `Some` whose every driver failed (e.g. mdns-only
/// config in a multicast-less environment) still drains the engine's
/// outbound queue so it can't grow unboundedly — the network is
/// simply unreachable, and warnings say so.
pub fn attach_signaling(state: &Arc<NetworkState>) -> Option<SignalingDrivers> {
    let (strategy, mdns_on) = {
        let cfg = state.config.read();
        (cfg.signaling.strategy.clone(), cfg.signaling.mdns)
    };
    let want_nostr = match strategy.as_str() {
        "" | "nostr" => true,
        "none" => false,
        other => {
            warn!(
                network = %state.network_id,
                strategy = %other,
                "unknown signaling strategy — attaching NO remote driver \
                 (no silent Nostr fallback); check the network's signaling config"
            );
            false
        }
    };

    let outbound_rx = state.take_signaling_outbound_rx()?;
    let gate = InboundGate::new(state.signaling_inbound_tx.clone());

    let drivers = match (want_nostr, mdns_on) {
        (true, true) => {
            let (nostr_tx, nostr_rx) = mpsc::unbounded_channel::<SignalingOutbound>();
            let (mdns_tx, mdns_rx) = mpsc::unbounded_channel::<SignalingOutbound>();
            let fanout = spawn_fanout(outbound_rx, vec![nostr_tx, mdns_tx]);
            let nostr = attach_nostr_with(state, nostr_rx, gate.clone());
            let mdns = attach_mdns_with(state, mdns_rx, gate);
            SignalingDrivers {
                nostr: Some(nostr),
                mdns,
                fanout: Some(fanout),
            }
        }
        (true, false) => SignalingDrivers {
            nostr: Some(attach_nostr_with(state, outbound_rx, gate)),
            mdns: None,
            fanout: None,
        },
        (false, true) => {
            let mdns = attach_mdns_with(state, outbound_rx, gate);
            if mdns.is_none() {
                warn!(
                    network = %state.network_id,
                    "mdns-only signaling failed to start — this network has NO signaling \
                     and is invisible to peers until it is re-joined"
                );
            }
            SignalingDrivers {
                nostr: None,
                mdns,
                fanout: None,
            }
        }
        (false, false) => {
            warn!(
                network = %state.network_id,
                "signaling fully disabled (strategy off and mdns off) — \
                 this network is invisible to peers"
            );
            // Drain the engine's outbound queue so it can't grow
            // unboundedly against a receiver nobody holds.
            SignalingDrivers {
                nostr: None,
                mdns: None,
                fanout: Some(spawn_fanout(outbound_rx, Vec::new())),
            }
        }
    };
    Some(drivers)
}

/// Clone every engine emission to each driver's queue. A closed
/// driver queue is skipped silently (its driver failed or detached);
/// the task exits when the engine side closes.
fn spawn_fanout(
    mut outbound_rx: mpsc::UnboundedReceiver<SignalingOutbound>,
    driver_txs: Vec<mpsc::UnboundedSender<SignalingOutbound>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        while let Some(msg) = outbound_rx.recv().await {
            for tx in &driver_txs {
                let _ = tx.send(msg.clone());
            }
        }
        trace!("signaling fan-out exiting");
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate_with_rx() -> (Arc<InboundGate>, mpsc::UnboundedReceiver<SignalingInbound>) {
        let (tx, rx) = mpsc::unbounded_channel();
        (InboundGate::new(tx), rx)
    }

    fn offer(from: &str, sdp: &str) -> SignalingInbound {
        SignalingInbound::Offer {
            device_id: from.into(),
            sdp: sdp.into(),
        }
    }

    /// The cross-driver wedge case: the same offer content delivered
    /// once per transport must reach the engine exactly once —
    /// applying it twice via `set_remote_description` wedges WebRTC.
    #[test]
    fn duplicate_offer_content_is_delivered_once() {
        let (gate, mut rx) = gate_with_rx();
        assert!(gate.deliver(offer("peer-a", "sdp-1")));
        assert!(gate.deliver(offer("peer-a", "sdp-1"))); // via the other driver
        assert!(rx.try_recv().is_ok(), "first delivery lands");
        assert!(rx.try_recv().is_err(), "duplicate swallowed");
    }

    /// Distinct negotiations (different SDP — every ICE restart or
    /// renegotiation changes it) must all pass.
    #[test]
    fn distinct_offers_all_pass() {
        let (gate, mut rx) = gate_with_rx();
        assert!(gate.deliver(offer("peer-a", "sdp-1")));
        assert!(gate.deliver(offer("peer-a", "sdp-2")));
        assert!(gate.deliver(offer("peer-b", "sdp-1"))); // same sdp, other peer
        for _ in 0..3 {
            rx.try_recv().expect("each distinct offer delivered");
        }
    }

    /// Announces and departures are the engine's retry pacing —
    /// repeats must never be swallowed.
    #[test]
    fn announces_and_leaves_are_never_deduped() {
        let (gate, mut rx) = gate_with_rx();
        for _ in 0..3 {
            assert!(gate.deliver(SignalingInbound::PeerAnnounced {
                device_id: "peer-a".into(),
            }));
        }
        assert!(gate.deliver(SignalingInbound::PeerLeft {
            device_id: "peer-a".into(),
        }));
        for _ in 0..4 {
            rx.try_recv().expect("every announce/leave delivered");
        }
    }

    /// Candidates dedup on their full content, not just the string.
    #[test]
    fn candidate_dedup_keys_on_full_content() {
        let (gate, mut rx) = gate_with_rx();
        let cand = |mid: Option<&str>| SignalingInbound::Candidate {
            device_id: "peer-a".into(),
            candidate: LocalIceCandidate {
                candidate: "candidate:1 1 UDP 1 10.0.0.1 5000 typ host".into(),
                sdp_mid: mid.map(str::to_string),
                sdp_mline_index: Some(0),
                username_fragment: None,
            },
        };
        assert!(gate.deliver(cand(Some("0"))));
        assert!(gate.deliver(cand(Some("0")))); // exact duplicate — dropped
        assert!(gate.deliver(cand(Some("1")))); // differing mid — passes
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_ok());
        assert!(rx.try_recv().is_err());
    }

    /// The seen-ring is bounded; ancient entries roll off and may
    /// legitimately re-deliver.
    #[test]
    fn gate_ring_is_bounded() {
        let (gate, _rx) = gate_with_rx();
        for i in 0..(GATE_SEEN_CAPACITY + 10) {
            gate.deliver(offer("peer-a", &format!("sdp-{i}")));
        }
        assert_eq!(gate.seen.lock().len(), GATE_SEEN_CAPACITY);
    }
}
