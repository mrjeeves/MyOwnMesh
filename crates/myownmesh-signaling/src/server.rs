//! Self-hosted signaling relay — a minimal Nostr relay (NIP-01 over
//! WebSocket) that mesh peers point their `signaling.servers` at to run
//! a network with no dependency on the public Nostr relay pool.
//!
//! The win is interoperability: the [`crate::nostr`] driver already
//! speaks NIP-01 to public relays, so a peer adopts a self-hosted relay
//! by adding `ws://this-host:port` to its config — *zero* client
//! changes. Two mesh peers both pointed at the same self-hosted relay
//! discover each other and negotiate WebRTC exactly as they would over
//! `nos.lol`, which is what makes a fully internet-isolated network
//! practical.
//!
//! ## What it implements
//!
//! The slice of NIP-01 the mesh needs, plus enough to be a polite
//! general relay:
//!
//! - `REQ` — register a subscription, replay matching *stored* events,
//!   then `EOSE`.
//! - `EVENT` — fan out to every matching live subscription on every
//!   connection, store it if it's a replayable kind, and `OK` the
//!   publisher.
//! - `CLOSE` — drop a subscription.
//! - Filters: `ids`, `authors`, `kinds`, `since`, `until`, `limit`, and
//!   single-letter tag filters (`#r`, `#e`, …). Unknown filter keys are
//!   ignored per spec.
//!
//! ## What it deliberately skips
//!
//! Signature verification. The relay is a dumb forwarder; the mesh runs
//! its own ed25519 mutual authentication over the WebRTC channel on top
//! of whatever signaling carries the offer, so a forged Nostr event
//! buys an attacker nothing but a failed handshake. Skipping Schnorr
//! verification keeps the relay light and dependency-free beyond what
//! the crate already links. (Public relays verify; a hardened
//! deployment can put this behind one.)
//!
//! Event kinds follow NIP-01: ephemeral events (`20000..=29999`, e.g.
//! the mesh's `21077` negotiation traffic) are forwarded but never
//! stored, so a stale offer can't be replayed onto a fresh peer
//! connection; everything else (e.g. the mesh's `1077` presence) is
//! retained for late-joiner replay.

use std::collections::{HashMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, trace, warn};

use crate::nostr::event::NostrEvent;
use crate::{Error, Result};

/// Max stored (replayable) events retained across all rooms. Presence is
/// low-volume; this is a generous ceiling that still bounds memory.
const MAX_STORED_EVENTS: usize = 8192;

/// How long a stored event stays replayable. The mesh driver only asks
/// for the last 5 minutes (`since = now - 300`), so 15 minutes covers it
/// with headroom while keeping the buffer fresh.
const STORED_RETENTION: Duration = Duration::from_secs(15 * 60);

/// Hard cap on how many stored events a single `REQ` can replay, so a
/// broad filter can't dump the whole buffer onto a new subscriber.
const MAX_REPLAY_PER_REQ: usize = 500;

/// A running signaling relay. Constructed via [`SignalingServer::start`].
pub struct SignalingServer;

/// Handle to a running signaling relay. Drop it (or call
/// [`SignalingServerHandle::stop`]) to shut the listener down.
pub struct SignalingServerHandle {
    task: JoinHandle<()>,
    local_addr: SocketAddr,
}

impl SignalingServerHandle {
    /// The address the relay actually bound (resolves an ephemeral port
    /// to the real one — used in tests).
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Stop the relay, aborting its accept loop and connection tasks.
    pub fn stop(self) {
        self.task.abort();
    }
}

impl Drop for SignalingServerHandle {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl SignalingServer {
    /// Bind a TCP listener and start accepting WebSocket signaling
    /// connections. Returns once the socket is bound; the accept loop
    /// runs in a spawned task.
    pub async fn start(bind: &str, port: u16) -> Result<SignalingServerHandle> {
        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        info!(%local_addr, "signaling relay listening (NIP-01 over WebSocket)");
        let hub = Hub::new();
        let task = tokio::spawn(accept_loop(listener, hub));
        Ok(SignalingServerHandle { task, local_addr })
    }
}

async fn accept_loop(listener: TcpListener, hub: Hub) {
    loop {
        match listener.accept().await {
            Ok((stream, peer)) => {
                let hub = hub.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_conn(stream, hub).await {
                        trace!(%peer, "signaling conn ended: {e}");
                    }
                });
            }
            Err(e) => warn!("signaling accept error: {e}"),
        }
    }
}

async fn handle_conn(stream: TcpStream, hub: Hub) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| Error::Socket(e.to_string()))?;
    let (mut write, mut read) = ws.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsMessage>();
    let conn_id = hub.register(out_tx.clone());

    // Writer task: drains the per-connection outbound queue to the
    // socket. The hub pushes frames onto `out_tx` from any thread.
    let writer = tokio::spawn(async move {
        while let Some(msg) = out_rx.recv().await {
            if write.send(msg).await.is_err() {
                break;
            }
        }
    });

    while let Some(frame) = read.next().await {
        match frame {
            Ok(WsMessage::Text(txt)) => hub.handle_client_message(conn_id, &txt),
            // Keep long-lived idle connections alive — split streams
            // don't auto-pong, so we answer pings ourselves.
            Ok(WsMessage::Ping(p)) => {
                let _ = out_tx.send(WsMessage::Pong(p));
            }
            Ok(WsMessage::Close(_)) => break,
            // Binary / pong frames aren't part of NIP-01; ignore.
            Ok(_) => {}
            Err(_) => break,
        }
    }

    hub.unregister(conn_id);
    writer.abort();
    Ok(())
}

/// Shared relay state. Cheap to clone — wraps an `Arc<Mutex<…>>`.
#[derive(Clone)]
struct Hub {
    inner: Arc<Mutex<HubInner>>,
}

struct HubInner {
    next_id: u64,
    conns: HashMap<u64, ConnEntry>,
    stored: VecDeque<StoredEvent>,
}

struct ConnEntry {
    out: mpsc::UnboundedSender<WsMessage>,
    /// subscription id → its filter set. An event matches the
    /// subscription if it matches *any* filter (NIP-01 OR semantics).
    subs: HashMap<String, Vec<Value>>,
}

struct StoredEvent {
    received_at: Instant,
    event: NostrEvent,
}

impl Hub {
    fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                next_id: 1,
                conns: HashMap::new(),
                stored: VecDeque::new(),
            })),
        }
    }

    fn register(&self, out: mpsc::UnboundedSender<WsMessage>) -> u64 {
        let mut g = self.inner.lock();
        let id = g.next_id;
        g.next_id += 1;
        g.conns.insert(
            id,
            ConnEntry {
                out,
                subs: HashMap::new(),
            },
        );
        id
    }

    fn unregister(&self, id: u64) {
        self.inner.lock().conns.remove(&id);
    }

    fn handle_client_message(&self, conn_id: u64, txt: &str) {
        let arr: Vec<Value> = match serde_json::from_str(txt) {
            Ok(a) => a,
            Err(e) => {
                trace!("signaling: undecodable client frame: {e}");
                return;
            }
        };
        let Some(verb) = arr.first().and_then(|v| v.as_str()) else {
            return;
        };
        match verb {
            "REQ" => self.handle_req(conn_id, &arr),
            "EVENT" => self.handle_event(conn_id, &arr),
            "CLOSE" => self.handle_close(conn_id, &arr),
            other => trace!("signaling: ignoring verb {other}"),
        }
    }

    /// `["REQ", subid, filter, filter, …]` — register the subscription,
    /// replay matching stored events oldest→newest, then `EOSE`.
    fn handle_req(&self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        let subid = subid.to_string();
        let filters: Vec<Value> = arr.get(2..).map(|s| s.to_vec()).unwrap_or_default();

        let (out, mut replay) = {
            let mut g = self.inner.lock();
            let replay: Vec<NostrEvent> = g
                .stored
                .iter()
                .filter(|s| matches_any(&filters, &s.event))
                .map(|s| s.event.clone())
                .collect();
            let Some(conn) = g.conns.get_mut(&conn_id) else {
                return;
            };
            conn.subs.insert(subid.clone(), filters);
            (conn.out.clone(), replay)
        };

        // Keep only the most recent matches if a broad filter pulled too
        // many — the buffer is time-ordered, so the tail is newest.
        if replay.len() > MAX_REPLAY_PER_REQ {
            let drop_n = replay.len() - MAX_REPLAY_PER_REQ;
            replay.drain(0..drop_n);
        }
        let replayed = replay.len();
        for ev in replay {
            let ev_value = serde_json::to_value(&ev).unwrap_or(Value::Null);
            let _ = out.send(WsMessage::Text(
                json!(["EVENT", subid, ev_value]).to_string(),
            ));
        }
        let _ = out.send(WsMessage::Text(json!(["EOSE", subid]).to_string()));
        trace!(%subid, replayed, "signaling REQ");
    }

    /// `["EVENT", event]` — fan out to matching subscriptions, store if
    /// replayable, and `OK` the publisher.
    fn handle_event(&self, conn_id: u64, arr: &[Value]) {
        let Some(ev_val) = arr.get(1) else {
            return;
        };
        let event: NostrEvent = match serde_json::from_value(ev_val.clone()) {
            Ok(e) => e,
            Err(e) => {
                trace!("signaling: bad EVENT: {e}");
                return;
            }
        };

        let mut g = self.inner.lock();
        if is_stored_kind(event.kind) {
            g.stored.push_back(StoredEvent {
                received_at: Instant::now(),
                event: event.clone(),
            });
            prune(&mut g.stored);
        }

        // Fan out verbatim — forward the original event JSON so ids /
        // sigs survive untouched for any peer that does verify.
        let mut delivered = 0usize;
        for conn in g.conns.values() {
            for (subid, filters) in &conn.subs {
                if matches_any(filters, &event) {
                    let frame = json!(["EVENT", subid, ev_val]).to_string();
                    if conn.out.send(WsMessage::Text(frame)).is_ok() {
                        delivered += 1;
                    }
                }
            }
        }
        if let Some(conn) = g.conns.get(&conn_id) {
            let _ = conn.out.send(WsMessage::Text(
                json!(["OK", event.id, true, ""]).to_string(),
            ));
        }
        trace!(kind = event.kind, delivered, "signaling EVENT");
    }

    /// `["CLOSE", subid]` — drop the subscription.
    fn handle_close(&self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        if let Some(conn) = self.inner.lock().conns.get_mut(&conn_id) {
            conn.subs.remove(subid);
        }
    }
}

/// True when *any* filter in the set matches (NIP-01 OR semantics). An
/// empty filter set, or a `REQ` with no filters at all, matches
/// everything.
fn matches_any(filters: &[Value], ev: &NostrEvent) -> bool {
    filters.is_empty() || filters.iter().any(|f| filter_matches(f, ev))
}

/// Match one NIP-01 filter object against an event. Every present
/// constraint must hold (AND within a filter); unknown keys are ignored.
fn filter_matches(filter: &Value, ev: &NostrEvent) -> bool {
    let Some(obj) = filter.as_object() else {
        return false;
    };
    for (key, val) in obj {
        match key.as_str() {
            "ids" => {
                if !str_list_contains(val, &ev.id) {
                    return false;
                }
            }
            "authors" => {
                if !str_list_contains(val, &ev.pubkey) {
                    return false;
                }
            }
            "kinds" => {
                let ok = val
                    .as_array()
                    .map(|a| a.iter().any(|k| k.as_u64() == Some(ev.kind as u64)))
                    .unwrap_or(false);
                if !ok {
                    return false;
                }
            }
            "since" => {
                if let Some(s) = val.as_u64() {
                    if ev.created_at < s {
                        return false;
                    }
                }
            }
            "until" => {
                if let Some(u) = val.as_u64() {
                    if ev.created_at > u {
                        return false;
                    }
                }
            }
            // Replay-time only; not a match constraint.
            "limit" => {}
            // Single-letter tag filter, e.g. "#r" matches events with a
            // tag ["r", <value-in-list>].
            tag if tag.len() == 2 && tag.starts_with('#') => {
                let letter = &tag[1..];
                let ok = ev
                    .tags
                    .iter()
                    .any(|t| t.len() >= 2 && t[0] == letter && str_list_contains(val, &t[1]));
                if !ok {
                    return false;
                }
            }
            _ => {}
        }
    }
    true
}

fn str_list_contains(val: &Value, needle: &str) -> bool {
    val.as_array()
        .map(|a| a.iter().any(|x| x.as_str() == Some(needle)))
        .unwrap_or(false)
}

/// NIP-01: ephemeral events (`20000..=29999`) are never stored; every
/// other kind is replayable. This is exactly the split the mesh relies
/// on — presence (`1077`) is retained for late joiners, negotiation
/// (`21077`) is forward-only so a stale offer can't bind a fresh
/// connection.
fn is_stored_kind(kind: u16) -> bool {
    !(20000..=29999).contains(&kind)
}

fn prune(stored: &mut VecDeque<StoredEvent>) {
    let now = Instant::now();
    while let Some(front) = stored.front() {
        if now.duration_since(front.received_at) > STORED_RETENTION {
            stored.pop_front();
        } else {
            break;
        }
    }
    while stored.len() > MAX_STORED_EVENTS {
        stored.pop_front();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ev(kind: u16, room: &str, created_at: u64) -> NostrEvent {
        NostrEvent {
            id: format!("id-{kind}-{created_at}"),
            pubkey: "pk".into(),
            created_at,
            kind,
            tags: vec![vec!["r".into(), room.into()]],
            content: "{}".into(),
            sig: "sig".into(),
        }
    }

    #[test]
    fn kind_storage_split_matches_nip01() {
        assert!(is_stored_kind(1077)); // presence: stored
        assert!(!is_stored_kind(21077)); // negotiation: ephemeral
        assert!(is_stored_kind(0));
        assert!(!is_stored_kind(20000));
        assert!(!is_stored_kind(29999));
        assert!(is_stored_kind(30000));
    }

    #[test]
    fn filter_matches_room_and_kind() {
        let e = ev(1077, "room-a", 1000);
        let f = json!({ "kinds": [1077, 21077], "#r": ["room-a"] });
        assert!(filter_matches(&f, &e));
        // Wrong room.
        assert!(!filter_matches(&json!({ "#r": ["room-b"] }), &e));
        // Wrong kind.
        assert!(!filter_matches(&json!({ "kinds": [9999] }), &e));
    }

    #[test]
    fn filter_since_until() {
        let e = ev(1077, "r", 1000);
        assert!(filter_matches(&json!({ "since": 999 }), &e));
        assert!(filter_matches(&json!({ "since": 1000 }), &e));
        assert!(!filter_matches(&json!({ "since": 1001 }), &e));
        assert!(filter_matches(&json!({ "until": 1000 }), &e));
        assert!(!filter_matches(&json!({ "until": 999 }), &e));
    }

    #[test]
    fn empty_filter_matches_everything() {
        let e = ev(1077, "r", 1000);
        assert!(matches_any(&[], &e));
        assert!(matches_any(&[json!({})], &e));
    }

    #[test]
    fn unknown_filter_keys_ignored() {
        let e = ev(1077, "r", 1000);
        // A future filter field this relay doesn't understand must not
        // exclude the event (NIP-01: relays MAY ignore unknown fields).
        assert!(filter_matches(&json!({ "futurefield": ["x"] }), &e));
    }
}
