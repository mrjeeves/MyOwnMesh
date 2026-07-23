//! Topology-aware frame routing — how application frames cross a
//! shaped network (star / hubs / ring) between members that don't hold
//! a direct connection.
//!
//! Rides the existing relay wire ([`crate::services::relay`]): a routed
//! frame is a [`RelayEnvelope`] on [`RELAY_CHANNEL`] whose payload
//! carries the transparent-channel wrapper (`__channel` / `__body` /
//! `__ttl` / `__id`). Legacy envelopes (application users of the
//! standalone `RelayService`) don't carry the wrapper and pass through
//! to channel subscribers untouched — the two uses of the wire
//! coexist.
//!
//! Semantics:
//! * **Directed** (`dst` set): forwarders move the envelope toward
//!   `dst` via [`Topology::next_hops`], decrementing `__ttl`; the
//!   destination unwraps and delivers to its channel router with the
//!   *origin* as the sender. Handed-to-forwarder is the delivery
//!   guarantee (best-effort beyond the first hop) — callers who need
//!   acknowledged delivery still use a direct edge.
//! * **Broadcast** (`dst` empty): flood with per-node dedup — every
//!   node delivers once; forwarders re-fan to their connected peers
//!   (minus the arrival edge and the origin) while `__ttl` lasts.
//!
//! Trust: a forwarded envelope's `src` (origin) is asserted by whoever
//! carries it. Two gates bound that: the carrier must be an
//! authenticated, connected peer (every frame already rides a
//! mutually-authenticated channel), and an envelope whose `src ≠ from`
//! is accepted only when the *carrier* is a forwarder under the
//! current topology — spokes cannot launder origins, only the hubs the
//! network's owner designated (on a ring, any member — flood trust
//! there is membership trust). End-to-end origin signatures can layer
//! on later without changing this wire.

use std::sync::Arc;

use serde_json::{json, Value};
use tracing::{debug, trace};

use crate::error::{Error, Result};
use crate::services::relay::{RelayEnvelope, RELAY_CHANNEL};

use super::connection::PeerStatus;
use super::state::NetworkState;

/// Dedup-ring capacity for `(origin, frame id)` pairs. Sized like the
/// signaling dedup ring: far beyond any realistic in-flight window.
pub(crate) const ROUTING_SEEN_CAPACITY: usize = 2048;

/// The wrapper a routed frame carries inside `RelayEnvelope::payload`.
struct Wrapper {
    channel: String,
    body: Value,
    ttl: u8,
    id: u64,
}

fn parse_wrapper(payload: &Value) -> Option<Wrapper> {
    let obj = payload.as_object()?;
    let channel = obj.get("__channel")?.as_str()?.to_string();
    // A wrapper naming the relay channel itself would recurse the
    // router; nothing legitimate produces it.
    if channel == RELAY_CHANNEL {
        return None;
    }
    Some(Wrapper {
        channel,
        body: obj.get("__body").cloned().unwrap_or(Value::Null),
        ttl: obj.get("__ttl").and_then(Value::as_u64).unwrap_or(0) as u8,
        id: obj.get("__id").and_then(Value::as_u64).unwrap_or(0),
    })
}

fn wrap(channel: &str, body: &Value, ttl: u8, id: u64) -> Value {
    json!({
        "__channel": channel,
        "__body": body,
        "__ttl": ttl,
        "__id": id,
    })
}

fn fresh_frame_id() -> u64 {
    use rand::Rng;
    rand::thread_rng().gen::<u64>() | 1
}

/// Record `(origin, id)` in the dedup ring; `false` = already seen.
fn first_sighting(state: &NetworkState, origin: &str, id: u64) -> bool {
    if id == 0 {
        // No id (shouldn't happen from our senders) — deliver, never
        // re-forward; the ttl guard below keeps it bounded anyway.
        return true;
    }
    let mut seen = state.routing_seen.lock();
    if seen.iter().any(|(o, i)| *i == id && o == origin) {
        return false;
    }
    if seen.len() >= ROUTING_SEEN_CAPACITY {
        seen.pop_front();
    }
    seen.push_back((origin.to_string(), id));
    true
}

/// Peers whose data channel can carry frames right now (Active or
/// Shelved — a shelved link is still a live path for routed frames,
/// exactly as the standalone relay treats it).
fn connected_ids(state: &NetworkState) -> Vec<String> {
    state
        .peers
        .iter()
        .filter(|e| {
            let d = e.value().state.read();
            matches!(d.status, PeerStatus::Active | PeerStatus::Shelved) && d.data_channel_open
        })
        .map(|e| e.key().clone())
        .collect()
}

/// Try to consume an inbound `RELAY_CHANNEL` frame as a routed
/// envelope. Returns `false` when the frame isn't wrapper-shaped —
/// the caller passes it through to channel subscribers (the legacy
/// `RelayService` flow).
pub(crate) async fn on_relay_frame(state: &Arc<NetworkState>, from: &str, payload: &Value) -> bool {
    let Ok(env) = serde_json::from_value::<RelayEnvelope>(payload.clone()) else {
        return false;
    };
    let Some(w) = parse_wrapper(&env.payload) else {
        return false;
    };
    // The carrier is guaranteed admitted here: `on_relay_frame` is only reached
    // via `on_channel_frame` for an inbound `Channel` frame, which the
    // admission gate in `handle_inbound_frame` already drops from an unadmitted
    // peer — so no separate carrier check is needed (or wanted per-frame).
    let me = state.identity.public_id().to_string();
    let origin = if env.src.is_empty() {
        from.to_string()
    } else {
        env.src.clone()
    };

    // Origin laundering gate: an envelope claiming someone else's
    // origin is only honoured from a carrier the topology designates
    // as a forwarder.
    if origin != from {
        let carrier_forwards = {
            let known = connected_ids(state);
            state.topology_impl.read().forwards(from, &known)
        };
        if !carrier_forwards {
            debug!(
                from = %super::short_peer(from),
                origin = %super::short_peer(&origin),
                "dropping routed frame: carrier is not a forwarder"
            );
            return true; // consumed (and dropped)
        }
    }

    if !first_sighting(state, &origin, w.id) {
        return true; // duplicate along another path — already handled
    }

    let broadcast = env.dst.is_empty();
    let for_me = broadcast || env.dst == me;

    if for_me {
        // Deliver with the origin as the sender — the application sees
        // who actually said it, not which hub carried it.
        super::on_channel_frame(state, &origin, w.channel.clone(), w.body.clone()).await;
    }
    if !broadcast && env.dst == me {
        return true;
    }

    // Onward duty — forwarders only, while the hop budget lasts.
    let (i_forward, connected) = {
        let connected = connected_ids(state);
        let f = state.topology_impl.read().forwards(&me, &connected);
        (f, connected)
    };
    if !i_forward || w.ttl == 0 {
        if !broadcast && !i_forward {
            trace!(
                dst = %super::short_peer(&env.dst),
                "routed frame reached a non-forwarder that isn't its destination — dropped"
            );
        }
        return true;
    }
    state.traffic.record_forwarded();
    let onward = RelayEnvelope {
        dst: env.dst.clone(),
        src: origin.clone(),
        payload: wrap(&w.channel, &w.body, w.ttl - 1, w.id),
    };
    let onward_value = match serde_json::to_value(&onward) {
        Ok(v) => v,
        Err(_) => return true,
    };

    if broadcast {
        // Re-fan to everyone connected except the arrival edge and the
        // origin; per-node dedup absorbs any cross-paths.
        for peer in connected {
            if peer == from || peer == origin {
                continue;
            }
            let _ = send_envelope(state, &peer, &onward_value).await;
        }
    } else {
        // Directed: straight to the destination when it's ours, else
        // toward it. First hop that accepts wins.
        let hops = if connected.iter().any(|c| c == &env.dst) {
            vec![env.dst.clone()]
        } else {
            state
                .topology_impl
                .read()
                .next_hops(&me, &env.dst, &connected)
        };
        for hop in hops {
            if hop == from {
                continue;
            }
            if send_envelope(state, &hop, &onward_value).await.is_ok() {
                break;
            }
        }
    }
    true
}

async fn send_envelope(state: &Arc<NetworkState>, peer: &str, envelope: &Value) -> Result<()> {
    super::send_to_peer(
        state,
        peer,
        &crate::protocol::MeshMessage::Channel {
            channel: RELAY_CHANNEL.to_string(),
            payload: envelope.clone(),
        },
    )
    .await
}

/// Send a directed frame to a member we hold no direct connection to,
/// by handing it to the topology's next hop(s). `Ok` means a forwarder
/// accepted it — the routed-delivery guarantee, weaker than an ack and
/// said so in the docs.
pub(crate) async fn send_routed(
    state: &Arc<NetworkState>,
    dest: &str,
    channel: &str,
    payload: &Value,
) -> Result<()> {
    let me = state.identity.public_id().to_string();
    let (hops, ttl) = {
        let connected = connected_ids(state);
        let topo = state.topology_impl.read();
        (topo.next_hops(&me, dest, &connected), topo.flood_ttl())
    };
    if hops.is_empty() {
        return Err(Error::Network(format!(
            "no route to {dest}: not directly connected and the topology names no next hop"
        )));
    }
    let id = fresh_frame_id();
    // Our own sighting: if the shape ever loops the frame back, drop it.
    first_sighting(state, &me, id);
    let env = RelayEnvelope {
        dst: dest.to_string(),
        src: me,
        payload: wrap(channel, payload, ttl, id),
    };
    let env_value = serde_json::to_value(&env).map_err(Error::Serde)?;
    let mut last_err: Option<Error> = None;
    for hop in hops {
        match send_envelope(state, &hop, &env_value).await {
            Ok(()) => return Ok(()),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err
        .unwrap_or_else(|| Error::Network(format!("no forwarder accepted the frame for {dest}"))))
}

/// Broadcast under a shaped topology: one wrapped envelope to every
/// connected, unshelved peer; forwarders re-fan it across the shape.
/// Returns how many first-hop peers accepted the frame.
pub(crate) async fn broadcast_flood(
    state: &Arc<NetworkState>,
    channel: &str,
    payload: &Value,
) -> usize {
    let me = state.identity.public_id().to_string();
    let ttl = state.topology_impl.read().flood_ttl();
    let id = fresh_frame_id();
    first_sighting(state, &me, id);
    let env = RelayEnvelope {
        dst: String::new(),
        src: me,
        payload: wrap(channel, payload, ttl, id),
    };
    let Ok(env_value) = serde_json::to_value(&env) else {
        return 0;
    };
    let targets: Vec<String> = state
        .peers
        .iter()
        .filter(|e| {
            let d = e.value().state.read();
            matches!(d.status, PeerStatus::Active)
                && !d.local_shelved
                && !d.remote_shelved
                && d.data_channel_open
        })
        .map(|e| e.key().clone())
        .collect();
    let mut delivered = 0usize;
    for peer in targets {
        if send_envelope(state, &peer, &env_value).await.is_ok() {
            delivered += 1;
        }
    }
    delivered
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wrapper_round_trips_and_rejects_relay_channel_recursion() {
        let w = wrap("app.control", &json!({"k": 1}), 3, 42);
        let parsed = parse_wrapper(&w).expect("parses");
        assert_eq!(parsed.channel, "app.control");
        assert_eq!(parsed.ttl, 3);
        assert_eq!(parsed.id, 42);
        assert_eq!(parsed.body, json!({"k": 1}));

        let bad = wrap(RELAY_CHANNEL, &json!(1), 3, 42);
        assert!(
            parse_wrapper(&bad).is_none(),
            "self-referential wrapper rejected"
        );
    }

    #[test]
    fn legacy_envelope_payloads_are_not_wrappers() {
        // A plain RelayService payload (no __channel) must pass through
        // to channel subscribers, not be consumed by the router.
        assert!(parse_wrapper(&json!({"hi": 1})).is_none());
        assert!(parse_wrapper(&json!("string")).is_none());
    }

    #[tokio::test]
    async fn dedup_ring_drops_replays_and_is_bounded() {
        let state = crate::engine::build_test_state("route-dedup");
        assert!(first_sighting(&state, "origin-a", 7));
        assert!(
            !first_sighting(&state, "origin-a", 7),
            "same (origin,id) drops"
        );
        assert!(
            first_sighting(&state, "origin-b", 7),
            "different origin is fresh"
        );
        for i in 0..(ROUTING_SEEN_CAPACITY as u64 + 10) {
            first_sighting(&state, "origin-c", 1000 + i);
        }
        assert!(
            state.routing_seen.lock().len() <= ROUTING_SEEN_CAPACITY,
            "ring stays bounded"
        );
    }

    #[tokio::test]
    async fn non_wrapper_relay_frame_is_left_to_subscribers() {
        let state = crate::engine::build_test_state("route-passthru");
        let legacy = serde_json::to_value(RelayEnvelope {
            dst: String::new(),
            src: String::new(),
            payload: json!({"app": "data"}),
        })
        .unwrap();
        let consumed = on_relay_frame(&state, "peer-x", &legacy).await;
        assert!(
            !consumed,
            "legacy envelope passes through to the channel layer"
        );
    }

    #[tokio::test]
    async fn spoke_cannot_launder_origins() {
        // Default test topology is FullMesh: forwards() == false for
        // everyone, so an envelope claiming a foreign origin from any
        // carrier is consumed-and-dropped.
        let state = crate::engine::build_test_state("route-launder");
        let env = serde_json::to_value(RelayEnvelope {
            dst: String::new(),
            src: "claimed-origin".into(),
            payload: wrap("app.control", &json!(1), 2, 99),
        })
        .unwrap();
        let consumed = on_relay_frame(&state, "carrier-spoke", &env).await;
        assert!(consumed, "wrapper-shaped frame is always consumed");
        assert!(
            state.routing_seen.lock().is_empty(),
            "dropped before the dedup ring — never treated as delivered"
        );
    }
}
