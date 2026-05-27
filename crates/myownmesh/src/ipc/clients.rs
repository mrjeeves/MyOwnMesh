//! Per-connection state and the daemon-wide indices that route
//! inbound RPCs / channel messages to the right client.
//!
//! One `ClientHandle` per event-subscribed socket. The handle
//! owns the mpsc sender that pushes [`super::wire::ServerOut`]
//! lines back to that socket; the read side of the same socket
//! drives `RpcRespond` / `RpcStreamChunk` / `RpcStreamEnd` /
//! `RpcUnregister` / `ChannelUnsubscribe` back through
//! `dispatch`.
//!
//! The registry maintains four indices:
//!
//! - `clients` — every connected event-subscribed client, keyed
//!   by `ClientId`. Dropped on disconnect.
//! - `handler_claims` — which client owns each method name on
//!   each network. Last-claim-wins: a re-register evicts the
//!   prior owner with a `HandlerDisplaced` event.
//! - `channel_subs` — set of subscribed clients per (network,
//!   channel). Channel inbound events fan out to every member.
//! - `pending_inbound` — engine-side `oneshot::Sender` /
//!   `mpsc::Sender` keyed by request id, awaiting an
//!   `RpcRespond` (or stream chunks) from whichever client owns
//!   the originating handler. The client identity isn't part of
//!   the key — any client may resolve any in-flight id (this
//!   keeps stream chunks decoupled from a single connection if
//!   it bounces).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use dashmap::{DashMap, DashSet};
use parking_lot::Mutex;
use tokio::sync::{mpsc, oneshot};

use super::wire::ServerOut;

/// Process-unique identifier for a connected client.
///
/// Just a monotonic counter; the daemon never reuses ids, so a
/// stale reference in a forwarder task that races with
/// disconnect resolves to a `None` lookup instead of routing to
/// a different client.
///
/// Wire form is the `Display` shape `c<n>` — clients pass it
/// back verbatim on subsequent RPC/channel-management requests
/// to identify which event-subscribed connection a handler
/// claim belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ClientId(pub u64);

impl std::fmt::Display for ClientId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "c{}", self.0)
    }
}

impl std::str::FromStr for ClientId {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let n_str = s
            .strip_prefix('c')
            .ok_or_else(|| format!("ClientId must start with 'c', got '{s}'"))?;
        let n: u64 = n_str.parse().map_err(|e| format!("ClientId parse: {e}"))?;
        Ok(ClientId(n))
    }
}

impl serde::Serialize for ClientId {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> serde::Deserialize<'de> for ClientId {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

/// Per-network handler-claim key. `network` is the
/// configuration id (matching the rest of the control surface).
pub type ClaimKey = (String, String);

/// Engine-side awaiter for an in-flight inbound RPC. The
/// synthetic handler installed by [`super::bridge`] returns the
/// receive side to the engine; the daemon stores the sender
/// here so a later `RpcRespond` from the client resolves it.
pub enum PendingInbound {
    /// Single-shot — resolved by exactly one `RpcRespond`.
    Single(oneshot::Sender<Result<serde_json::Value, String>>),
    /// Streaming — fed by `RpcStreamChunk`s and closed by
    /// `RpcStreamEnd` (drop the sender; engine sees the
    /// receiver yield `None`).
    Stream(mpsc::Sender<serde_json::Value>),
}

/// State for a single connected event-subscribed client.
#[derive(Clone)]
pub struct ClientHandle {
    pub id: ClientId,
    /// Mpsc the read loop and bridge code push outbound frames
    /// into; a writer task on the same connection drains it.
    pub writer_tx: mpsc::UnboundedSender<ServerOut>,
    /// Method claims this client currently holds. Tracked for
    /// O(1) cleanup on disconnect; the authoritative routing
    /// table is on the registry.
    pub method_claims: Arc<DashSet<ClaimKey>>,
    /// Channel subscriptions this client currently holds.
    /// Same disconnect-cleanup rationale.
    pub channel_subs: Arc<DashSet<ClaimKey>>,
}

impl ClientHandle {
    pub fn send(&self, frame: ServerOut) {
        // Best effort: a dropped writer means the connection is
        // gone; the registry will clean up the handle shortly.
        let _ = self.writer_tx.send(frame);
    }
}

/// Daemon-wide registry of connected clients + their
/// registrations.
#[derive(Clone, Default)]
pub struct ClientRegistry {
    inner: Arc<RegistryInner>,
}

#[derive(Default)]
struct RegistryInner {
    next_id: AtomicU64,
    next_call_stream_id: AtomicU64,
    clients: DashMap<ClientId, Arc<ClientHandle>>,
    handler_claims: DashMap<ClaimKey, ClientId>,
    channel_subs: DashMap<ClaimKey, Arc<Mutex<Vec<ClientId>>>>,
    pending_inbound: DashMap<String, PendingInbound>,
    /// Streaming methods that have a synthetic handler
    /// installed on the engine. `(network, method) → ()` —
    /// the value side is unused; we only need set semantics.
    /// Tracked so we can ask the bridge to forget the handler
    /// on the last unclaim.
    installed_handlers: DashMap<ClaimKey, HandlerMode>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandlerMode {
    Single,
    Stream,
}

impl ClientRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    /// Allocate a fresh `ClientId` and register the client's
    /// outbound writer. Returns the handle the read loop should
    /// keep alongside its socket.
    pub fn register(&self, writer_tx: mpsc::UnboundedSender<ServerOut>) -> Arc<ClientHandle> {
        let id = ClientId(self.inner.next_id.fetch_add(1, Ordering::Relaxed));
        let handle = Arc::new(ClientHandle {
            id,
            writer_tx,
            method_claims: Arc::new(DashSet::new()),
            channel_subs: Arc::new(DashSet::new()),
        });
        self.inner.clients.insert(id, handle.clone());
        handle
    }

    /// Drop a client on disconnect: remove its method claims
    /// (notify peers that called them? not yet — we let the
    /// in-flight ids time out at the peer), drop its channel
    /// subscriptions, and any pending inbound RPCs that were
    /// keyed against this client.
    ///
    /// Pending inbound RPCs are *not* keyed by client (any
    /// client may answer any id), so we don't have to scan them
    /// here — they'll be reaped naturally if no `RpcRespond`
    /// ever lands and the peer side hits its own timeout.
    pub fn unregister(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        let (_, handle) = self.inner.clients.remove(&id)?;
        // Drop method claims this client owned. Note: we don't
        // tear down the synthetic handler on the engine — a
        // future claimant might re-take the same method
        // immediately and we'd save the install. The handler
        // gracefully errors with `no claim` if invoked with no
        // current owner.
        for entry in handle.method_claims.iter() {
            let key = entry.key().clone();
            // Only drop if we still own it (a displacing client
            // might have already taken over).
            self.inner
                .handler_claims
                .remove_if(&key, |_, owner| *owner == id);
        }
        // Drop channel subscriptions. The fan-out task running
        // for this (network, channel) will notice the empty
        // subscriber list and exit on its next iteration.
        for entry in handle.channel_subs.iter() {
            let key = entry.key().clone();
            if let Some(subs) = self.inner.channel_subs.get(&key) {
                subs.lock().retain(|c| *c != id);
            }
        }
        Some(handle)
    }

    pub fn client(&self, id: ClientId) -> Option<Arc<ClientHandle>> {
        self.inner.clients.get(&id).map(|e| e.value().clone())
    }

    /// Claim a method on a network. Returns the previously
    /// claiming client if any (so the caller can notify them
    /// with `HandlerDisplaced`).
    pub fn claim_method(
        &self,
        key: ClaimKey,
        new_owner: ClientId,
        mode: HandlerMode,
    ) -> Option<ClientId> {
        // Update the per-client cache first so on-disconnect
        // cleanup sees the new claim.
        if let Some(client) = self.client(new_owner) {
            client.method_claims.insert(key.clone());
        }
        let prev = self.inner.handler_claims.insert(key.clone(), new_owner);
        self.inner.installed_handlers.insert(key.clone(), mode);
        if let Some(prev_owner) = prev {
            if prev_owner != new_owner {
                if let Some(prev_client) = self.client(prev_owner) {
                    prev_client.method_claims.remove(&key);
                }
                return Some(prev_owner);
            }
        }
        None
    }

    /// Release a method claim. Returns the prior owner if the
    /// caller did own it.
    pub fn release_method(&self, key: &ClaimKey, owner: ClientId) -> bool {
        if let Some(client) = self.client(owner) {
            client.method_claims.remove(key);
        }
        self.inner
            .handler_claims
            .remove_if(key, |_, current| *current == owner)
            .is_some()
    }

    pub fn handler_owner(&self, key: &ClaimKey) -> Option<ClientId> {
        self.inner.handler_claims.get(key).map(|e| *e.value())
    }

    #[allow(dead_code)]
    pub fn handler_mode(&self, key: &ClaimKey) -> Option<HandlerMode> {
        self.inner.installed_handlers.get(key).map(|e| *e.value())
    }

    /// Returns `true` on the FIRST subscriber for this
    /// (network, channel) — caller uses that signal to spawn a
    /// new pump task.
    pub fn subscribe_channel(&self, key: ClaimKey, client: ClientId) -> bool {
        if let Some(c) = self.client(client) {
            c.channel_subs.insert(key.clone());
        }
        let entry = self
            .inner
            .channel_subs
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(Vec::new())));
        let mut subs = entry.lock();
        let was_empty = subs.is_empty();
        if !subs.contains(&client) {
            subs.push(client);
        }
        was_empty
    }

    /// Release a subscription. Returns `true` if no clients
    /// remain on this channel — caller uses that signal to tear
    /// down the pump task.
    pub fn unsubscribe_channel(&self, key: &ClaimKey, client: ClientId) -> bool {
        if let Some(c) = self.client(client) {
            c.channel_subs.remove(key);
        }
        let Some(subs) = self.inner.channel_subs.get(key) else {
            return true;
        };
        let mut subs = subs.lock();
        subs.retain(|c| *c != client);
        subs.is_empty()
    }

    /// Snapshot the current set of subscribers — used by the
    /// channel pump task each iteration.
    pub fn channel_subscribers(&self, key: &ClaimKey) -> Vec<ClientId> {
        self.inner
            .channel_subs
            .get(key)
            .map(|subs| subs.lock().clone())
            .unwrap_or_default()
    }

    pub fn put_pending_inbound(&self, request_id: String, entry: PendingInbound) {
        self.inner.pending_inbound.insert(request_id, entry);
    }

    pub fn take_pending_inbound(&self, request_id: &str) -> Option<PendingInbound> {
        self.inner
            .pending_inbound
            .remove(request_id)
            .map(|(_, v)| v)
    }

    /// Resolve a single-shot in-flight RPC with success.
    /// Returns true if the id was pending and resolved.
    pub fn resolve_inbound_single(&self, request_id: &str, payload: serde_json::Value) -> bool {
        if let Some(PendingInbound::Single(tx)) = self.take_pending_inbound(request_id) {
            let _ = tx.send(Ok(payload));
            return true;
        }
        false
    }

    /// Resolve a single-shot in-flight RPC with failure.
    pub fn reject_inbound_single(&self, request_id: &str, error: String) -> bool {
        if let Some(PendingInbound::Single(tx)) = self.take_pending_inbound(request_id) {
            let _ = tx.send(Err(error));
            return true;
        }
        false
    }

    /// Push a streaming chunk to an in-flight stream handler.
    /// Returns true if the id was pending and the chunk was
    /// accepted (the engine receiver may be closed if the peer
    /// already moved on).
    pub async fn push_inbound_stream_chunk(
        &self,
        request_id: &str,
        payload: serde_json::Value,
    ) -> bool {
        let tx = {
            let entry = self.inner.pending_inbound.get(request_id);
            match entry.as_deref() {
                Some(PendingInbound::Stream(tx)) => tx.clone(),
                _ => return false,
            }
        };
        tx.send(payload).await.is_ok()
    }

    /// Close an in-flight stream handler. Drops the sender —
    /// the engine sees the receiver yield `None` and ships
    /// `RpcStreamEnd` to the peer.
    pub fn close_inbound_stream(&self, request_id: &str) -> bool {
        matches!(
            self.take_pending_inbound(request_id),
            Some(PendingInbound::Stream(_))
        )
    }

    /// Monotonic counter used to tag outbound stream calls.
    /// The lib's `Rpc::call_stream` allocates its own request
    /// id internally but doesn't expose it; the IPC layer
    /// generates its own correlation id so clients can match
    /// chunks back to their originating call.
    pub fn next_call_stream_id(&self) -> u64 {
        self.inner
            .next_call_stream_id
            .fetch_add(1, Ordering::Relaxed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_client(
        registry: &ClientRegistry,
    ) -> (Arc<ClientHandle>, mpsc::UnboundedReceiver<ServerOut>) {
        let (tx, rx) = mpsc::unbounded_channel();
        let handle = registry.register(tx);
        (handle, rx)
    }

    #[test]
    fn client_id_roundtrips_through_string() {
        let id = ClientId(42);
        assert_eq!(id.to_string(), "c42");
        let parsed: ClientId = "c42".parse().expect("parse");
        assert_eq!(parsed, id);
        assert!("not-an-id".parse::<ClientId>().is_err());
        assert!("c-99".parse::<ClientId>().is_err());
    }

    #[test]
    fn ids_are_monotonic_and_unique() {
        let reg = ClientRegistry::new();
        let (a, _ra) = fresh_client(&reg);
        let (b, _rb) = fresh_client(&reg);
        let (c, _rc) = fresh_client(&reg);
        assert_eq!(a.id, ClientId(0));
        assert_eq!(b.id, ClientId(1));
        assert_eq!(c.id, ClientId(2));
        assert!(reg.client(a.id).is_some());
        assert!(reg.client(ClientId(99)).is_none());
    }

    #[test]
    fn claim_method_takes_ownership_and_displaces_prior() {
        let reg = ClientRegistry::new();
        let (a, _ra) = fresh_client(&reg);
        let (b, _rb) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        let prev = reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(prev.is_none());
        assert_eq!(reg.handler_owner(&key), Some(a.id));
        assert!(a.method_claims.contains(&key));

        let prev = reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(prev.is_none());

        let prev = reg.claim_method(key.clone(), b.id, HandlerMode::Stream);
        assert_eq!(prev, Some(a.id));
        assert_eq!(reg.handler_owner(&key), Some(b.id));
        assert!(b.method_claims.contains(&key));
        assert!(!a.method_claims.contains(&key));
    }

    #[test]
    fn release_method_only_succeeds_for_current_owner() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        assert!(!reg.release_method(&key, b.id));
        assert_eq!(reg.handler_owner(&key), Some(a.id));
        assert!(reg.release_method(&key, a.id));
        assert!(reg.handler_owner(&key).is_none());
        assert!(!a.method_claims.contains(&key));
    }

    #[test]
    fn unregister_drops_claims_and_subscriptions() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let method_key = ("net".to_string(), "infer".to_string());
        let channel_key = ("net".to_string(), "catalog".to_string());

        reg.claim_method(method_key.clone(), a.id, HandlerMode::Single);
        reg.subscribe_channel(channel_key.clone(), a.id);

        assert_eq!(reg.handler_owner(&method_key), Some(a.id));
        assert_eq!(reg.channel_subscribers(&channel_key), vec![a.id]);

        reg.unregister(a.id);

        assert!(reg.handler_owner(&method_key).is_none());
        assert!(reg.channel_subscribers(&channel_key).is_empty());
        assert!(reg.client(a.id).is_none());
    }

    #[test]
    fn unregister_doesnt_collateral_drop_a_displacing_claim() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "infer".to_string());

        reg.claim_method(key.clone(), a.id, HandlerMode::Single);
        reg.claim_method(key.clone(), b.id, HandlerMode::Single);
        assert_eq!(reg.handler_owner(&key), Some(b.id));

        reg.unregister(a.id);
        assert_eq!(reg.handler_owner(&key), Some(b.id));
    }

    #[test]
    fn channel_subscribe_first_subscriber_flag() {
        let reg = ClientRegistry::new();
        let (a, _) = fresh_client(&reg);
        let (b, _) = fresh_client(&reg);
        let key = ("net".to_string(), "catalog".to_string());

        assert!(reg.subscribe_channel(key.clone(), a.id), "first sub");
        assert!(!reg.subscribe_channel(key.clone(), b.id), "second sub");

        assert!(!reg.unsubscribe_channel(&key, b.id));
        assert!(reg.unsubscribe_channel(&key, a.id));
    }

    #[tokio::test]
    async fn resolve_single_inbound_sends_payload_back() {
        let reg = ClientRegistry::new();
        let (tx, rx) = oneshot::channel();
        reg.put_pending_inbound("req-1".into(), PendingInbound::Single(tx));
        assert!(reg.resolve_inbound_single("req-1", serde_json::json!({"hi": true})));
        let got = rx.await.expect("oneshot").expect("ok");
        assert_eq!(got, serde_json::json!({"hi": true}));

        // Second resolve is a no-op.
        assert!(!reg.resolve_inbound_single("req-1", serde_json::Value::Null));
    }

    #[tokio::test]
    async fn reject_single_inbound_passes_error_through() {
        let reg = ClientRegistry::new();
        let (tx, rx) = oneshot::channel();
        reg.put_pending_inbound("req-x".into(), PendingInbound::Single(tx));
        assert!(reg.reject_inbound_single("req-x", "nope".into()));
        let got = rx.await.expect("oneshot");
        assert!(got.is_err());
    }

    #[tokio::test]
    async fn stream_chunks_then_end_closes_receiver() {
        let reg = ClientRegistry::new();
        let (tx, mut rx) = mpsc::channel::<serde_json::Value>(4);
        reg.put_pending_inbound("req-s".into(), PendingInbound::Stream(tx));

        assert!(
            reg.push_inbound_stream_chunk("req-s", serde_json::json!(1))
                .await
        );
        assert!(
            reg.push_inbound_stream_chunk("req-s", serde_json::json!(2))
                .await
        );
        assert!(reg.close_inbound_stream("req-s"));

        assert_eq!(rx.recv().await, Some(serde_json::json!(1)));
        assert_eq!(rx.recv().await, Some(serde_json::json!(2)));
        assert_eq!(rx.recv().await, None);
    }
}
