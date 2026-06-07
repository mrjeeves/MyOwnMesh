//! Self-hosted signaling relay — a Nostr relay (NIP-01 over WebSocket)
//! that mesh peers point their `signaling.servers` at to run a network
//! with no dependency on the public Nostr relay pool.
//!
//! It speaks plain NIP-01, so the [`crate::nostr`] driver and even public
//! relays interoperate unchanged. On top of that baseline it adds
//! **stateful coordination** — the "intelligent relay" behaviour — all as
//! optional accelerators that degrade gracefully to plain NIP-01:
//!
//! - **Live presence.** The relay learns `(connection → device, room)`
//!   from the announces a peer publishes, so it tracks who is actually
//!   connected right now. A peer subscribing gets the *live* member set
//!   replayed instantly, not just the time-windowed store — near-instant
//!   discovery even if a member's last announce is old.
//! - **Instant departure.** When a member's socket closes, the relay
//!   emits a `leave` ([`SignalingMessage::Leave`](crate::SignalingMessage))
//!   to the room so peers tear the connection down promptly instead of
//!   waiting out a heartbeat timeout. Public relays never send this;
//!   peers that don't get it fall back to timeout detection.
//! - **Flood limits.** Per-connection token buckets, per-IP connection
//!   caps, subscription / filter / message-size caps, and strike-based
//!   disconnection — so the relay is safe to stand up publicly.
//!
//! ## What it deliberately skips
//!
//! Signature verification. The relay is a forwarder; the mesh runs its
//! own ed25519 mutual authentication over the resulting WebRTC channel,
//! so a forged Nostr event only buys a failed handshake. (It does hold a
//! Nostr keypair, but only to *sign its own* synthesized `leave` events
//! so they're well-formed for any peer that does verify.)
//!
//! Event kinds follow NIP-01: ephemeral events (`20000..=29999`, e.g. the
//! mesh's `21077` negotiation + `leave` traffic) are forwarded but never
//! stored; everything else (e.g. `1077` presence) is retained for
//! late-joiner replay.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use futures_util::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{info, trace, warn};

use crate::nostr::event::{
    make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EPHEMERAL_KIND, SIGNALING_EVENT_KIND,
};
use crate::{Error, Result};

/// Max stored (replayable) events retained across all rooms. Presence is
/// low-volume; this is a generous ceiling that still bounds memory.
const MAX_STORED_EVENTS: usize = 8192;

/// How long a stored event stays replayable. The mesh driver only asks
/// for the last 5 minutes (`since = now - 300`), so 15 minutes covers it
/// with headroom while keeping the buffer fresh.
const STORED_RETENTION: Duration = Duration::from_secs(15 * 60);

/// Hard cap on how many events a single `REQ` can replay, so a broad
/// filter can't dump the whole buffer onto a new subscriber.
const MAX_REPLAY_PER_REQ: usize = 500;

/// How many rate-limit violations a connection may rack up before the
/// relay closes it. Generous enough to ride out a legitimate burst,
/// tight enough to evict a persistent abuser.
const STRIKE_LIMIT: u32 = 50;

/// Flood-protection limits for the signaling relay. Tunable so a busy
/// public deployment can loosen them and a locked-down private one can
/// tighten them. `0` means "no limit" for every field.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Limits {
    /// Max `EVENT` publishes per second per connection (token bucket,
    /// 1-second burst).
    pub max_event_rate: u32,
    /// Max `REQ` subscriptions per second per connection.
    pub max_req_rate: u32,
    /// Max concurrent subscriptions a single connection may hold.
    pub max_subscriptions: u32,
    /// Max filters in a single `REQ` (extra filters are dropped).
    pub max_filters_per_req: u32,
    /// Max size of a single client frame in bytes.
    pub max_message_bytes: u32,
    /// Max concurrent connections from one IP address.
    pub max_connections_per_ip: u32,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_event_rate: 50,
            max_req_rate: 20,
            max_subscriptions: 64,
            max_filters_per_req: 16,
            max_message_bytes: 65_536,
            max_connections_per_ip: 64,
        }
    }
}

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
    pub async fn start(bind: &str, port: u16, limits: Limits) -> Result<SignalingServerHandle> {
        let addr = format!("{bind}:{port}");
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        let local_addr = listener
            .local_addr()
            .map_err(|e| Error::Bind(addr.clone(), e))?;
        info!(%local_addr, "signaling relay listening (NIP-01 over WebSocket)");
        let hub = Hub::new(limits);
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
                    if let Err(e) = handle_conn(stream, peer, hub).await {
                        trace!(%peer, "signaling conn ended: {e}");
                    }
                });
            }
            Err(e) => warn!("signaling accept error: {e}"),
        }
    }
}

async fn handle_conn(stream: TcpStream, peer: SocketAddr, hub: Hub) -> Result<()> {
    let ws = tokio_tungstenite::accept_async(stream)
        .await
        .map_err(|e| Error::Socket(e.to_string()))?;
    let (mut write, mut read) = ws.split();
    let (out_tx, mut out_rx) = mpsc::unbounded_channel::<WsMessage>();

    // Per-IP admission control happens at register time.
    let Some(conn_id) = hub.register(out_tx.clone(), peer.ip()) else {
        let _ = write
            .send(WsMessage::Text(
                json!(["NOTICE", "too many connections from your address"]).to_string(),
            ))
            .await;
        let _ = write.close().await;
        return Ok(());
    };

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
            // `on_client_message` returns false when the connection has
            // earned a disconnect (sustained rate-limit abuse).
            Ok(WsMessage::Text(txt)) => {
                if !hub.on_client_message(conn_id, &txt) {
                    break;
                }
            }
            // Keep long-lived idle connections alive — split streams
            // don't auto-pong, so we answer pings ourselves.
            Ok(WsMessage::Ping(p)) => {
                let _ = out_tx.send(WsMessage::Pong(p));
            }
            Ok(WsMessage::Close(_)) => break,
            Ok(_) => {}
            Err(_) => break,
        }
    }

    hub.unregister(conn_id);
    writer.abort();
    Ok(())
}

/// Shared relay state. Cheap to clone — wraps an `Arc<Mutex<…>>`. All the
/// real logic lives on [`HubInner`] so it runs under a single lock with
/// no re-entrancy.
#[derive(Clone)]
struct Hub {
    inner: Arc<Mutex<HubInner>>,
}

struct HubInner {
    next_id: u64,
    conns: HashMap<u64, ConnEntry>,
    stored: VecDeque<StoredEvent>,
    /// room → device → live presence. The relay's view of who is
    /// connected right now, drives instant discovery + departure.
    presence: HashMap<String, HashMap<String, Presence>>,
    /// Concurrent connection count per source IP, for admission control.
    ip_counts: HashMap<IpAddr, u32>,
    limits: Limits,
    /// Keypair used only to sign the relay's own synthesized `leave`
    /// events so they're well-formed for verifying peers.
    identity: NostrIdentity,
}

struct ConnEntry {
    out: mpsc::UnboundedSender<WsMessage>,
    /// subscription id → its filter set (OR semantics across filters).
    subs: HashMap<String, Vec<Value>>,
    ip: IpAddr,
    /// `(room, device)` pairs this connection is the live presence owner
    /// of — used to emit departures when it closes.
    present: Vec<(String, String)>,
    event_bucket: TokenBucket,
    req_bucket: TokenBucket,
    strikes: u32,
}

struct StoredEvent {
    received_at: Instant,
    event: NostrEvent,
}

/// One live member, as the relay sees it: which connection owns it and
/// its latest announce (replayed verbatim for instant discovery).
struct Presence {
    conn_id: u64,
    announce: NostrEvent,
}

impl Hub {
    fn new(limits: Limits) -> Self {
        Self {
            inner: Arc::new(Mutex::new(HubInner {
                next_id: 1,
                conns: HashMap::new(),
                stored: VecDeque::new(),
                presence: HashMap::new(),
                ip_counts: HashMap::new(),
                limits,
                identity: NostrIdentity::generate(),
            })),
        }
    }

    fn register(&self, out: mpsc::UnboundedSender<WsMessage>, ip: IpAddr) -> Option<u64> {
        self.inner.lock().register(out, ip)
    }

    fn unregister(&self, id: u64) {
        self.inner.lock().unregister(id);
    }

    fn on_client_message(&self, id: u64, txt: &str) -> bool {
        self.inner.lock().on_client_message(id, txt)
    }
}

impl HubInner {
    fn register(&mut self, out: mpsc::UnboundedSender<WsMessage>, ip: IpAddr) -> Option<u64> {
        if self.limits.max_connections_per_ip > 0 {
            let n = self.ip_counts.get(&ip).copied().unwrap_or(0);
            if n >= self.limits.max_connections_per_ip {
                return None;
            }
        }
        *self.ip_counts.entry(ip).or_insert(0) += 1;
        let id = self.next_id;
        self.next_id += 1;
        self.conns.insert(
            id,
            ConnEntry {
                out,
                subs: HashMap::new(),
                ip,
                present: Vec::new(),
                event_bucket: TokenBucket::new(self.limits.max_event_rate),
                req_bucket: TokenBucket::new(self.limits.max_req_rate),
                strikes: 0,
            },
        );
        Some(id)
    }

    fn unregister(&mut self, id: u64) {
        let Some(entry) = self.conns.remove(&id) else {
            return;
        };
        if let Some(c) = self.ip_counts.get_mut(&entry.ip) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                self.ip_counts.remove(&entry.ip);
            }
        }
        // Emit a departure for each device this connection was the live
        // owner of (skip any that a newer connection has since taken
        // over — presence holds only the latest owner per device).
        for (room, device) in &entry.present {
            let is_owner = self
                .presence
                .get(room)
                .and_then(|m| m.get(device))
                .map(|p| p.conn_id == id)
                .unwrap_or(false);
            if !is_owner {
                continue;
            }
            if let Some(m) = self.presence.get_mut(room) {
                m.remove(device);
                if m.is_empty() {
                    self.presence.remove(room);
                }
            }
            // Drop the departed peer's stored announces so a new
            // subscriber doesn't discover a ghost.
            self.stored.retain(|s| {
                presence_of(&s.event)
                    .map(|(r, d)| !(r == *room && d == *device))
                    .unwrap_or(true)
            });
            let leave = build_leave_event(&self.identity, room, device);
            let leave_value = serde_json::to_value(&leave).unwrap_or(Value::Null);
            fanout(&self.conns, &leave_value, &leave, None);
            trace!(%device, %room, "signaling: emitted leave");
        }
    }

    /// Returns false when the connection should be dropped.
    fn on_client_message(&mut self, conn_id: u64, txt: &str) -> bool {
        if self.limits.max_message_bytes > 0 && txt.len() as u32 > self.limits.max_message_bytes {
            return self.strike(conn_id);
        }
        let arr: Vec<Value> = match serde_json::from_str(txt) {
            Ok(a) => a,
            Err(e) => {
                trace!("signaling: undecodable client frame: {e}");
                return true;
            }
        };
        let Some(verb) = arr.first().and_then(|v| v.as_str()) else {
            return true;
        };
        match verb {
            "REQ" => {
                if !self.take_token(conn_id, true) {
                    return self.strike(conn_id);
                }
                self.handle_req(conn_id, &arr);
                true
            }
            "EVENT" => {
                if !self.take_token(conn_id, false) {
                    return self.strike(conn_id);
                }
                self.handle_event(conn_id, &arr);
                true
            }
            "CLOSE" => {
                self.handle_close(conn_id, &arr);
                true
            }
            other => {
                trace!("signaling: ignoring verb {other}");
                true
            }
        }
    }

    fn take_token(&mut self, conn_id: u64, is_req: bool) -> bool {
        match self.conns.get_mut(&conn_id) {
            Some(conn) => {
                let bucket = if is_req {
                    &mut conn.req_bucket
                } else {
                    &mut conn.event_bucket
                };
                bucket.allow()
            }
            None => false,
        }
    }

    fn strike(&mut self, conn_id: u64) -> bool {
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.strikes += 1;
            if conn.strikes > STRIKE_LIMIT {
                let _ = conn.out.send(WsMessage::Text(
                    json!(["NOTICE", "rate limit exceeded — closing"]).to_string(),
                ));
                return false;
            }
        }
        true
    }

    /// `["REQ", subid, filter, …]` — register the subscription, then
    /// replay matching stored events *and* the live presence set
    /// (deduped), then `EOSE`.
    fn handle_req(&mut self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        let subid = subid.to_string();
        let mut filters: Vec<Value> = arr.get(2..).map(|s| s.to_vec()).unwrap_or_default();
        if self.limits.max_filters_per_req > 0 {
            filters.truncate(self.limits.max_filters_per_req as usize);
        }

        // Enforce the per-connection subscription ceiling for new ids.
        if self.limits.max_subscriptions > 0 {
            if let Some(conn) = self.conns.get(&conn_id) {
                if !conn.subs.contains_key(&subid)
                    && conn.subs.len() >= self.limits.max_subscriptions as usize
                {
                    if let Some(conn) = self.conns.get(&conn_id) {
                        let _ = conn.out.send(WsMessage::Text(
                            json!(["CLOSED", subid, "rate-limited: too many subscriptions"])
                                .to_string(),
                        ));
                    }
                    return;
                }
            }
        }

        // Candidate replay set: stored matches ∪ live-presence announces,
        // deduped by event id. Presence catches members whose announce
        // aged out of the store — that's the "instant discovery" win.
        let mut replay: Vec<NostrEvent> = Vec::new();
        let mut seen: HashSet<String> = HashSet::new();
        for s in &self.stored {
            if matches_any(&filters, &s.event) && seen.insert(s.event.id.clone()) {
                replay.push(s.event.clone());
            }
        }
        for room in self.presence.values() {
            for p in room.values() {
                if matches_any(&filters, &p.announce) && seen.insert(p.announce.id.clone()) {
                    replay.push(p.announce.clone());
                }
            }
        }
        if replay.len() > MAX_REPLAY_PER_REQ {
            let drop_n = replay.len() - MAX_REPLAY_PER_REQ;
            replay.drain(0..drop_n);
        }

        let Some(conn) = self.conns.get_mut(&conn_id) else {
            return;
        };
        conn.subs.insert(subid.clone(), filters);
        let out = conn.out.clone();
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

    /// `["EVENT", event]` — track presence, store if replayable, fan out
    /// to matching subscriptions, and `OK` the publisher.
    fn handle_event(&mut self, conn_id: u64, arr: &[Value]) {
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

        // Live presence: an announce makes this connection the owner of
        // (room, device). Best-effort — only well-formed mesh announces
        // parse; generic NIP-01 traffic is ignored here.
        if let Some((room, device)) = presence_of(&event) {
            self.presence.entry(room.clone()).or_default().insert(
                device.clone(),
                Presence {
                    conn_id,
                    announce: event.clone(),
                },
            );
            if let Some(conn) = self.conns.get_mut(&conn_id) {
                if !conn.present.iter().any(|(r, d)| r == &room && d == &device) {
                    conn.present.push((room, device));
                }
            }
        }

        if is_stored_kind(event.kind) {
            self.stored.push_back(StoredEvent {
                received_at: Instant::now(),
                event: event.clone(),
            });
            prune(&mut self.stored);
        }

        let delivered = fanout(&self.conns, ev_val, &event, None);
        if let Some(conn) = self.conns.get(&conn_id) {
            let _ = conn.out.send(WsMessage::Text(
                json!(["OK", event.id, true, ""]).to_string(),
            ));
        }
        trace!(kind = event.kind, delivered, "signaling EVENT");
    }

    /// `["CLOSE", subid]` — drop the subscription.
    fn handle_close(&mut self, conn_id: u64, arr: &[Value]) {
        let Some(subid) = arr.get(1).and_then(|v| v.as_str()) else {
            return;
        };
        if let Some(conn) = self.conns.get_mut(&conn_id) {
            conn.subs.remove(subid);
        }
    }
}

/// Fan an event out to every matching subscription on every connection
/// (optionally skipping one). Returns the number of frames delivered.
fn fanout(
    conns: &HashMap<u64, ConnEntry>,
    ev_value: &Value,
    ev: &NostrEvent,
    skip: Option<u64>,
) -> usize {
    let mut delivered = 0usize;
    for (id, conn) in conns {
        if Some(*id) == skip {
            continue;
        }
        for (subid, filters) in &conn.subs {
            if matches_any(filters, ev) {
                let frame = json!(["EVENT", subid, ev_value]).to_string();
                if conn.out.send(WsMessage::Text(frame)).is_ok() {
                    delivered += 1;
                }
            }
        }
    }
    delivered
}

/// Extract `(room, device)` from an event if it's a well-formed mesh
/// presence announce: kind 1077, an `r` tag, and a content envelope
/// whose `kind` is `announce` carrying `from`. Returns `None` for
/// anything else (generic NIP-01 traffic, negotiation frames, etc.).
fn presence_of(ev: &NostrEvent) -> Option<(String, String)> {
    if ev.kind != SIGNALING_EVENT_KIND {
        return None;
    }
    let room = ev
        .tags
        .iter()
        .find(|t| t.len() >= 2 && t[0] == "r")
        .map(|t| t[1].clone())?;
    let content: Value = serde_json::from_str(&ev.content).ok()?;
    if content.get("kind").and_then(|k| k.as_str()) != Some("announce") {
        return None;
    }
    let from = content.get("from")?.as_str()?.to_string();
    Some((room, from))
}

/// Build a signed `leave` event for a departed device in a room. Mirrors
/// the envelope shape the driver expects: `{from, kind:"leave", peer_id}`
/// on the ephemeral kind.
fn build_leave_event(identity: &NostrIdentity, room: &str, device: &str) -> NostrEvent {
    let envelope = json!({ "from": device, "kind": "leave", "peer_id": device });
    make_event(
        identity,
        SIGNALING_EPHEMERAL_KIND,
        vec![vec!["r".to_string(), room.to_string()]],
        envelope.to_string(),
        now_secs(),
    )
}

/// Token bucket for per-connection rate limiting. A `rate` of 0 disables
/// the limit (always allows).
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(rate: u32) -> Self {
        let capacity = rate.max(1) as f64;
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec: rate as f64,
            last: Instant::now(),
        }
    }

    fn allow(&mut self) -> bool {
        if self.refill_per_sec <= 0.0 {
            return true; // unlimited
        }
        let now = Instant::now();
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
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
            "limit" => {}
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
/// other kind is replayable.
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
        assert!(is_stored_kind(1077));
        assert!(!is_stored_kind(21077));
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
        assert!(!filter_matches(&json!({ "#r": ["room-b"] }), &e));
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
        assert!(filter_matches(&json!({ "futurefield": ["x"] }), &e));
    }

    #[test]
    fn presence_extracted_only_from_real_announces() {
        // A real mesh announce: kind 1077, r tag, content envelope.
        let mut a = ev(1077, "room-a", 1000);
        a.content = json!({ "from": "devA", "kind": "announce", "peer_id": "devA" }).to_string();
        assert_eq!(presence_of(&a), Some(("room-a".into(), "devA".into())));

        // Negotiation traffic (ephemeral kind) is not presence.
        let mut o = ev(21077, "room-a", 1000);
        o.content = json!({ "from": "devA", "kind": "offer", "peer_id": "devA" }).to_string();
        assert_eq!(presence_of(&o), None);

        // A simplified event with non-envelope content is not presence.
        assert_eq!(presence_of(&ev(1077, "room-a", 1000)), None);
    }

    #[test]
    fn token_bucket_zero_is_unlimited() {
        let mut b = TokenBucket::new(0);
        for _ in 0..1000 {
            assert!(b.allow());
        }
    }

    #[test]
    fn token_bucket_limits_burst() {
        // Capacity == rate, so the first `rate` calls pass and the next
        // is denied (no time elapsed to refill).
        let mut b = TokenBucket::new(5);
        let mut passed = 0;
        for _ in 0..20 {
            if b.allow() {
                passed += 1;
            }
        }
        assert_eq!(passed, 5);
    }

    #[test]
    fn build_leave_event_is_parseable_envelope() {
        let id = NostrIdentity::generate();
        let leave = build_leave_event(&id, "room-a", "devA");
        assert_eq!(leave.kind, SIGNALING_EPHEMERAL_KIND);
        let content: Value = serde_json::from_str(&leave.content).unwrap();
        assert_eq!(content["kind"], "leave");
        assert_eq!(content["peer_id"], "devA");
        assert_eq!(content["from"], "devA");
        assert!(leave
            .tags
            .iter()
            .any(|t| t.len() >= 2 && t[0] == "r" && t[1] == "room-a"));
    }
}
