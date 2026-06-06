//! Adapter that connects an [`crate::engine::state::NetworkState`]
//! to a signaling driver. The signaling crate emits its own
//! generic [`myownmesh_signaling::SignalingMessage`] type; this
//! module translates between that shape and the engine's
//! `SignalingInbound` / `SignalingOutbound` enums.
//!
//! Embedders can call [`attach_local`] to wire the engine to an
//! in-process [`myownmesh_signaling::local::LocalBroker`] (used by
//! tests and by single-process apps); a future `attach_nostr`
//! will do the same for the concrete Nostr driver.

use std::sync::Arc;

use myownmesh_signaling::local::{LocalBroker, LocalInbound, LocalOutbound};
use myownmesh_signaling::nostr::driver::{
    self as nostr_driver, NostrDriverConfig, NostrDriverHandle, NostrInbound, NostrOutbound,
};
use myownmesh_signaling::SignalingMessage;
use tokio::sync::mpsc;
use tracing::trace;

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

/// Attach the engine to the production Nostr signaling driver.
/// Returns the driver handle — drop or call `.stop()` to detach.
pub fn attach_nostr(state: &Arc<NetworkState>) -> Option<NostrDriverHandle> {
    let cfg = state.config.read();
    let nostr_cfg = NostrDriverConfig {
        app_id: resolve_app_id(),
        network_id: cfg.network_id.clone(),
        device_id: state.identity.public_id().to_string(),
        servers: cfg.signaling.servers.clone(),
        denylist: cfg.signaling.denylist.clone(),
        redundancy: cfg.signaling.redundancy as usize,
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
    let mut outbound_rx = state.take_signaling_outbound_rx()?;
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

    // Inbound pump: NostrInbound → engine SignalingInbound.
    let inbound_tx = state.signaling_inbound_tx.clone();
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
                NostrInbound::Message { from, msg } => match msg {
                    SignalingMessage::Announce { peer_id } => {
                        let _ = peer_id;
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
        trace!("nostr inbound pump exiting");
    });

    Some(nostr_driver::start(nostr_cfg, out_rx, in_tx))
}
