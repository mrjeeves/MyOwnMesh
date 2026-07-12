//! Engine ↔ IPC bridge: synthetic `Rpc::serve` / `serve_stream`
//! handlers that route inbound peer RPCs to whichever IPC
//! client currently holds the matching method claim, plus the
//! per-channel pump task that fans `Channel::subscribe()`
//! frames out to subscribed IPC clients.
//!
//! Lifetime model:
//!
//! - **Handlers** are installed lazily on first claim of a
//!   `(network, method)` pair and left in place forever. After
//!   the last claim is released the synthetic handler still
//!   sits in the engine's `Rpc` dispatch table; if invoked
//!   with no current owner it answers with a "no handler"
//!   error to the peer rather than panicking. This avoids the
//!   complexity of safely tearing handlers down across
//!   re-claims and matches how the library-level `Rpc::serve`
//!   semantics work (overwrite on re-register).
//!
//! - **Channel pumps** are scoped to subscribers: the first
//!   subscribe spawns a forwarder task, the last unsubscribe
//!   drops the receiver and the task exits on its next loop
//!   iteration. Each task holds an
//!   `mpsc::Receiver<broadcast::Receiver<...>>`-shaped weak
//!   reference so a swept-away registry doesn't keep tasks
//!   alive.

use myownmesh_core::JoinedNetwork;
use serde_json::Value;
use tokio::sync::mpsc;
use tracing::{debug, warn};

use super::clients::{ClientRegistry, HandlerMode, PendingInbound};
use super::wire::ServerOut;

/// Install (or re-install) a synthetic single-shot RPC handler
/// for `(network_id, method)` on this network's `Rpc`
/// dispatcher. The handler emits `RpcInbound` to whichever
/// client currently owns the claim and awaits an `RpcRespond`
/// to resolve.
pub fn install_single_handler(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    registry: ClientRegistry,
) {
    let rpc = network.rpc();
    let key = (network_key.clone(), method.clone());
    rpc.serve(&method, move |call| {
        let registry = registry.clone();
        let key = key.clone();
        async move {
            let Some(owner_id) = registry.handler_owner(&key) else {
                return Err(format!(
                    "no IPC client holds method '{}' on '{}'",
                    key.1, key.0
                ));
            };
            let Some(client) = registry.client(owner_id) else {
                return Err("handler owner client disconnected".into());
            };
            let (tx, rx) = tokio::sync::oneshot::channel();
            registry.put_pending_inbound(call.request_id.clone(), PendingInbound::Single(tx));
            client.send(ServerOut::RpcInbound {
                network: key.0.clone(),
                from: call.from.clone(),
                request_id: call.request_id.clone(),
                method: call.method.clone(),
                payload: call.payload.clone(),
                streaming: call.streaming,
            });
            // Await the client's `RpcRespond`. If the client
            // disconnects mid-flight, the registry's
            // `unregister` path doesn't actively cancel inbound
            // RPCs (deliberate — another client may still
            // answer for this method on the next claim wave),
            // so we lean on the peer's own RPC timeout to
            // unwedge. If the oneshot resolves to a dropped
            // sender (PendingInbound replaced), return a clear
            // error so the peer sees a reasonable failure
            // instead of hanging forever.
            match rx.await {
                Ok(Ok(payload)) => Ok(value_to_response(payload)),
                Ok(Err(e)) => Err(e),
                Err(_) => Err("IPC handler dropped without responding".into()),
            }
        }
    });
}

/// Install (or re-install) a synthetic streaming RPC handler.
/// Mirrors [`install_single_handler`] but stashes an
/// `mpsc::Sender<Value>` in the pending table instead of a
/// `oneshot`; chunks land via `RpcStreamChunk` and the stream
/// closes on `RpcStreamEnd` (drop the sender, engine sees
/// `None`).
pub fn install_stream_handler(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    registry: ClientRegistry,
) {
    let rpc = network.rpc();
    let key = (network_key.clone(), method.clone());
    rpc.serve_stream(&method, move |call| {
        let registry = registry.clone();
        let key = key.clone();
        async move {
            let Some(owner_id) = registry.handler_owner(&key) else {
                return Err(format!(
                    "no IPC client holds streaming method '{}' on '{}'",
                    key.1, key.0
                ));
            };
            let Some(client) = registry.client(owner_id) else {
                return Err("handler owner client disconnected".into());
            };
            // 32-slot buffer matches the rough back-pressure
            // shape used by the engine's outgoing peer queues;
            // streaming responses that exceed it block the IPC
            // client until the engine drains, which is the
            // right back-pressure direction. The send side is
            // stashed in `pending_inbound`; chunks land via
            // `RpcStreamChunk`. Dropping the sender (via
            // `RpcStreamEnd` removing the pending entry) closes
            // the receiver and the engine ships
            // `RpcStreamEndMessage` to the peer.
            let (tx, rx) = mpsc::channel::<Value>(32);
            registry.put_pending_inbound(call.request_id.clone(), PendingInbound::Stream(tx));
            client.send(ServerOut::RpcInbound {
                network: key.0.clone(),
                from: call.from.clone(),
                request_id: call.request_id.clone(),
                method: call.method.clone(),
                payload: call.payload.clone(),
                streaming: call.streaming,
            });
            Ok(rx)
        }
    });
}

/// Spawn the per-channel fan-out task for an IPC subscription
/// on `(network_id, channel)`. Idempotent at the registry
/// level — the caller is expected to spawn this only when
/// `subscribe_channel(...)` returns true (the first
/// subscriber). On the last `unsubscribe_channel(...)`
/// returning true (no remaining subscribers), the task ends on
/// its next loop iteration when it sees an empty subscriber
/// list.
///
/// The task lives by polling the channel's broadcast receiver.
/// If the network is torn down (`recv` returns `Closed`) or
/// the subscriber set becomes empty between frames, it exits.
pub fn spawn_channel_pump(
    network: &JoinedNetwork,
    network_key: String,
    channel_name: String,
    registry: ClientRegistry,
) {
    let channel = network.channel::<Value>(&channel_name);
    let mut sub = channel.subscribe();
    let key = (network_key.clone(), channel_name.clone());
    tokio::spawn(async move {
        loop {
            // Exit early if no subscribers remain.
            let subscribers = registry.channel_subscribers(&key);
            if subscribers.is_empty() {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (no subscribers)"
                );
                break;
            }
            let Some(next) = sub.recv().await else {
                debug!(
                    network = %key.0,
                    channel = %key.1,
                    "channel pump exiting (channel closed)"
                );
                break;
            };
            match next {
                Ok(msg) => {
                    let frame = ServerOut::ChannelInbound {
                        network: key.0.clone(),
                        from: msg.from,
                        channel: key.1.clone(),
                        payload: msg.body,
                    };
                    for client_id in subscribers {
                        if let Some(client) = registry.client(client_id) {
                            client.send(frame.clone());
                        }
                    }
                }
                Err(e) => {
                    warn!(
                        network = %key.0,
                        channel = %key.1,
                        "channel deserialize error: {e}"
                    );
                }
            }
        }
    });
}

/// Spawn the per-network video fan-out for IPC subscribers.
/// Caller spawns this only on the FIRST `subscribe_video(...)`;
/// the task exits once the subscriber list empties (same passive
/// teardown as the channel pump) or the network is torn down.
///
/// The engine's video broadcast is shallow by design: if this
/// pump (or a slow client socket) lags, old samples are dropped
/// at the broadcast and the stream resumes from the freshest one
/// — video is freshness, never a backlog.
pub fn spawn_video_pump(network: &JoinedNetwork, network_key: String, registry: ClientRegistry) {
    let mut sub = network.state().subscribe_video();
    tokio::spawn(async move {
        loop {
            let subscribers = registry.video_subscribers(&network_key);
            if subscribers.is_empty() {
                debug!(network = %network_key, "video pump exiting (no subscribers)");
                break;
            }
            let inbound = match sub.recv().await {
                Ok(s) => s,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    debug!(network = %network_key, "video pump lagged; dropped {n} samples");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    debug!(network = %network_key, "video pump exiting (network closed)");
                    break;
                }
            };
            // Binary body for clients on a media-source pipe; built once.
            let body = crate::control::encode_inbound_frame(
                crate::control::MEDIA_KIND_VIDEO,
                inbound.sample.key,
                inbound.sample.lane,
                inbound.sample.rtp_timestamp,
                &inbound.from,
                &inbound.sample.data,
            );
            for client_id in subscribers {
                if let Some(client) = registry.client(client_id) {
                    if let Some(sink) = client.media_sink() {
                        let _ = sink.send(body.clone());
                    } else {
                        client.send(ServerOut::VideoInbound {
                            network: network_key.clone(),
                            from: inbound.from.clone(),
                            stream: inbound.sample.lane,
                            rtp_timestamp: inbound.sample.rtp_timestamp,
                            key: inbound.sample.key,
                            data: data_encoding::BASE64.encode(&inbound.sample.data),
                        });
                    }
                }
            }
        }
    });
}

/// Spawn the per-network audio fan-out for IPC subscribers — the
/// audio twin of [`spawn_video_pump`], with the same passive
/// teardown (exits once the subscriber list empties) and the same
/// lag policy (a slow client sheds the oldest frames; live audio
/// is freshness, never a backlog).
pub fn spawn_audio_pump(network: &JoinedNetwork, network_key: String, registry: ClientRegistry) {
    let mut sub = network.state().subscribe_audio();
    tokio::spawn(async move {
        loop {
            let subscribers = registry.audio_subscribers(&network_key);
            if subscribers.is_empty() {
                debug!(network = %network_key, "audio pump exiting (no subscribers)");
                break;
            }
            let inbound = match sub.recv().await {
                Ok(s) => s,
                Err(tokio::sync::broadcast::error::RecvError::Lagged(n)) => {
                    debug!(network = %network_key, "audio pump lagged; dropped {n} frames");
                    continue;
                }
                Err(tokio::sync::broadcast::error::RecvError::Closed) => {
                    debug!(network = %network_key, "audio pump exiting (network closed)");
                    break;
                }
            };
            // Binary body for clients on a media-source pipe; built once.
            let body = crate::control::encode_inbound_frame(
                crate::control::MEDIA_KIND_AUDIO,
                false,
                inbound.sample.lane,
                inbound.sample.rtp_timestamp,
                &inbound.from,
                &inbound.sample.data,
            );
            for client_id in subscribers {
                if let Some(client) = registry.client(client_id) {
                    if let Some(sink) = client.media_sink() {
                        let _ = sink.send(body.clone());
                    } else {
                        client.send(ServerOut::AudioInbound {
                            network: network_key.clone(),
                            from: inbound.from.clone(),
                            stream: inbound.sample.lane,
                            rtp_timestamp: inbound.sample.rtp_timestamp,
                            data: data_encoding::BASE64.encode(&inbound.sample.data),
                        });
                    }
                }
            }
        }
    });
}

/// `myownmesh-core`'s `Rpc::serve` wants an
/// `Ok(RpcResponse)` — wrap a raw `Value` so callers don't
/// reach across crate-private types.
pub fn value_to_response(v: Value) -> myownmesh_core::rpc::RpcResponse {
    myownmesh_core::rpc::RpcResponse::from_value(v)
}

/// Helper used by `dispatch` when an IPC client releases or
/// has been disconnected: notify the now-displaced client.
pub fn notify_displaced(
    registry: &ClientRegistry,
    prev_owner: super::clients::ClientId,
    by: super::clients::ClientId,
    network: String,
    method: String,
) {
    if let Some(client) = registry.client(prev_owner) {
        client.send(ServerOut::HandlerDisplaced {
            network,
            method,
            by: by.to_string(),
        });
    }
}

/// Public helper for the dispatch layer: install whichever
/// handler shape matches the requested mode. Idempotent —
/// re-claiming an existing method just replaces the synthetic
/// handler (and `Rpc::serve` itself does the same).
pub fn install_handler_for_mode(
    network: &JoinedNetwork,
    network_key: String,
    method: String,
    mode: HandlerMode,
    registry: ClientRegistry,
) {
    match mode {
        HandlerMode::Single => install_single_handler(network, network_key, method, registry),
        HandlerMode::Stream => install_stream_handler(network, network_key, method, registry),
    }
}

#[cfg(test)]
mod tests {
    //! End-to-end engine-bridge tests. Two engines wired
    //! through `LocalBroker`; one side simulates an IPC client
    //! by holding the receiver end of a `ClientHandle` and
    //! manually feeding `RpcRespond`s back through the
    //! registry — same path the dispatch layer takes when a
    //! real socket client posts `RpcRespond`.

    use crate::ipc::clients::{ClientRegistry, HandlerMode};
    use crate::ipc::wire::ServerOut;
    use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
    use myownmesh_core::engine::{attach_local, spawn_network};
    use myownmesh_core::events::{MeshEvent, PeerEvent};
    use myownmesh_core::identity::Identity;
    use myownmesh_core::transport::Transport;
    use myownmesh_signaling::local::LocalBroker;
    use std::sync::Arc;
    use std::time::Duration;
    use tokio::time::Instant;

    fn fresh_network(id: &str, wire_id: &str) -> NetworkConfig {
        NetworkConfig {
            id: id.to_string(),
            network_id: wire_id.to_string(),
            label: id.to_string(),
            kind: Default::default(),
            topology: TopologyMode::FullMesh,
            signaling: SignalingConfig::default(),
            stun_servers: Vec::new(),
            turn_servers: Vec::new(),
            roster_path: None,
        pinned_peers: Vec::new(),
            auto_approve: true,
        }
    }

    async fn wait_for_approval(
        rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
        peer_id: &str,
    ) {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if Instant::now() > deadline {
                panic!("never saw PeerApproved for {peer_id}");
            }
            let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
            match next {
                Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                    if device_id == peer_id =>
                {
                    return;
                }
                _ => continue,
            }
        }
    }

    /// Build two engines + a Rpc dispatcher pair sharing one
    /// LocalBroker. Returns `(alice_state, bob_state, alice_rpc,
    /// bob_rpc, alice_id, bob_id)`. Driver join handles are
    /// leaked — the tests don't depend on clean shutdown.
    #[allow(clippy::type_complexity)]
    async fn two_peer_rpc(
        wire_id: &str,
    ) -> (
        Arc<myownmesh_core::engine::NetworkState>,
        Arc<myownmesh_core::engine::NetworkState>,
        Arc<myownmesh_core::rpc::Rpc>,
        Arc<myownmesh_core::rpc::Rpc>,
        Arc<Identity>,
        Arc<Identity>,
    ) {
        let tmp = tempfile::tempdir().expect("tempdir");
        std::env::set_var("MYOWNMESH_HOME", tmp.path());
        std::mem::forget(tmp); // leak — test scope only

        let broker = LocalBroker::new();
        let transport = Transport::new().expect("transport");

        let alice_id = Arc::new(Identity::ephemeral());
        let bob_id = Arc::new(Identity::ephemeral());

        let alice_cfg = fresh_network("alice", wire_id);
        let bob_cfg = fresh_network("bob", wire_id);

        let (alice_state, alice_driver) =
            spawn_network(alice_cfg, alice_id.clone(), transport.clone())
                .await
                .expect("alice engine");
        let (bob_state, bob_driver) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
            .await
            .expect("bob engine");
        // Leak the driver handles — keeps them running for the
        // life of the test process.
        std::mem::forget(alice_driver);
        std::mem::forget(bob_driver);

        let alice_rpc = Arc::new(myownmesh_core::rpc::Rpc::attach(&alice_state));
        let bob_rpc = Arc::new(myownmesh_core::rpc::Rpc::attach(&bob_state));

        let mut alice_events = alice_state.events_tx.subscribe();
        let mut bob_events = bob_state.events_tx.subscribe();
        attach_local(&alice_state, &broker);
        attach_local(&bob_state, &broker);

        wait_for_approval(&mut alice_events, bob_id.public_id()).await;
        wait_for_approval(&mut bob_events, alice_id.public_id()).await;

        (alice_state, bob_state, alice_rpc, bob_rpc, alice_id, bob_id)
    }

    /// Single-shot RPC routed via the IPC bridge. Alice's
    /// network registers a synthetic handler bound to a
    /// simulated IPC client; Bob calls the method; the
    /// "client" receives `RpcInbound`, posts `RpcRespond` back
    /// via the registry, and Bob's call resolves with the
    /// returned payload.
    #[tokio::test]
    async fn single_shot_rpc_round_trip_through_bridge() {
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id) =
            two_peer_rpc("ipc-bridge-single").await;

        // Simulate an IPC client on Alice's side.
        let registry = ClientRegistry::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerOut>();
        let client = registry.register(tx);
        let net_key = "alice".to_string();
        let method = "echo".to_string();
        let key = (net_key.clone(), method.clone());
        registry.claim_method(key.clone(), client.id, HandlerMode::Single);

        // The bridge needs a `JoinedNetwork` — but we have the
        // state directly. The synthetic handler only needs to
        // call `Rpc::serve` on the network's Rpc, which we can
        // do via the lower-level `attach` path mirroring what
        // `install_single_handler` does, but inlined here so
        // we don't need a `JoinedNetwork` facade.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::rpc::Rpc::attach(&alice_state).serve("echo", move |call| {
            let registry = registry_for_handler.clone();
            let key = key_for_handler.clone();
            async move {
                let owner = registry
                    .handler_owner(&key)
                    .ok_or_else(|| "no claim".to_string())?;
                let client = registry
                    .client(owner)
                    .ok_or_else(|| "owner gone".to_string())?;
                let (resp_tx, resp_rx) = tokio::sync::oneshot::channel();
                registry.put_pending_inbound(
                    call.request_id.clone(),
                    crate::ipc::clients::PendingInbound::Single(resp_tx),
                );
                client.send(ServerOut::RpcInbound {
                    network: key.0.clone(),
                    from: call.from.clone(),
                    request_id: call.request_id.clone(),
                    method: call.method.clone(),
                    payload: call.payload.clone(),
                    streaming: call.streaming,
                });
                match resp_rx.await {
                    Ok(Ok(p)) => Ok(myownmesh_core::rpc::RpcResponse::from_value(p)),
                    Ok(Err(e)) => Err(e),
                    Err(_) => Err("handler dropped".into()),
                }
            }
        });

        // Bob calls the method.
        let alice_did = alice_id.public_id().to_string();
        let call_handle = tokio::spawn(async move {
            bob_rpc
                .call(&alice_did, "echo", serde_json::json!({"n": 7}))
                .await
        });

        // Pull the RpcInbound off the simulated client mpsc.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        let (request_id, payload) = match inbound {
            ServerOut::RpcInbound {
                request_id,
                payload,
                method,
                ..
            } => {
                assert_eq!(method, "echo");
                (request_id, payload)
            }
            other => panic!("expected RpcInbound, got {other:?}"),
        };
        assert_eq!(payload, serde_json::json!({"n": 7}));

        // Respond via the registry (same path dispatch takes).
        let resolved =
            registry.resolve_inbound_single(&request_id, serde_json::json!({"n_squared": 49}));
        assert!(resolved);

        let bob_response = tokio::time::timeout(Duration::from_secs(5), call_handle)
            .await
            .expect("call timeout")
            .expect("join")
            .expect("rpc ok");
        assert_eq!(bob_response.body, serde_json::json!({"n_squared": 49}));
    }

    /// Streaming RPC: Alice's "client" pushes three chunks
    /// via `push_inbound_stream_chunk` + closes via
    /// `close_inbound_stream`; Bob's `call_stream` drains the
    /// receiver and sees all three plus the end-of-stream.
    #[tokio::test]
    async fn streaming_rpc_round_trip_through_bridge() {
        let (alice_state, _bob_state, _alice_rpc, bob_rpc, alice_id, _bob_id) =
            two_peer_rpc("ipc-bridge-stream").await;

        let registry = ClientRegistry::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerOut>();
        let client = registry.register(tx);
        let key = ("alice".to_string(), "stream_echo".to_string());
        registry.claim_method(key.clone(), client.id, HandlerMode::Stream);

        // Wire the synthetic stream handler. Identical to the
        // single-shot test but uses `serve_stream` + the
        // `PendingInbound::Stream` arm.
        let registry_for_handler = registry.clone();
        let key_for_handler = key.clone();
        myownmesh_core::rpc::Rpc::attach(&alice_state).serve_stream("stream_echo", move |call| {
            let registry = registry_for_handler.clone();
            let key = key_for_handler.clone();
            async move {
                let owner = registry
                    .handler_owner(&key)
                    .ok_or_else(|| "no claim".to_string())?;
                let client = registry
                    .client(owner)
                    .ok_or_else(|| "owner gone".to_string())?;
                let (tx, rx) = tokio::sync::mpsc::channel::<serde_json::Value>(32);
                registry.put_pending_inbound(
                    call.request_id.clone(),
                    crate::ipc::clients::PendingInbound::Stream(tx),
                );
                client.send(ServerOut::RpcInbound {
                    network: key.0.clone(),
                    from: call.from.clone(),
                    request_id: call.request_id.clone(),
                    method: call.method.clone(),
                    payload: call.payload.clone(),
                    streaming: call.streaming,
                });
                Ok(rx)
            }
        });

        let alice_did = alice_id.public_id().to_string();
        let bob_rpc_clone = bob_rpc.clone();
        let stream_handle = tokio::spawn(async move {
            bob_rpc_clone
                .call_stream(&alice_did, "stream_echo", serde_json::json!("start"))
                .await
        });

        // Pull RpcInbound to get the request_id.
        let inbound = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        let request_id = match inbound {
            ServerOut::RpcInbound { request_id, .. } => request_id,
            other => panic!("expected RpcInbound, got {other:?}"),
        };

        // Push three chunks then close.
        for n in 1..=3 {
            assert!(
                registry
                    .push_inbound_stream_chunk(&request_id, serde_json::json!(n))
                    .await,
                "chunk {n} push"
            );
        }
        assert!(registry.close_inbound_stream(&request_id));

        // Bob drains his receiver — three chunks then close.
        let mut bob_rx = tokio::time::timeout(Duration::from_secs(5), stream_handle)
            .await
            .expect("stream timeout")
            .expect("join")
            .expect("call_stream ok");
        for n in 1..=3 {
            let chunk = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
                .await
                .expect("chunk timeout")
                .expect("chunk recv")
                .expect("chunk ok");
            assert_eq!(chunk, serde_json::json!(n));
        }
        // End-of-stream: receiver returns None.
        let end = tokio::time::timeout(Duration::from_secs(5), bob_rx.recv())
            .await
            .expect("end timeout");
        assert!(end.is_none(), "expected stream end, got {end:?}");
    }

    /// Channel pub/sub: subscribe Alice's "IPC client" to a
    /// channel, Bob sends a frame on the same name, the
    /// client receives a `ChannelInbound` event with the
    /// correct payload and sender.
    #[tokio::test]
    async fn channel_inbound_round_trip_through_bridge() {
        let (alice_state, bob_state, _alice_rpc, _bob_rpc, _alice_id, bob_id) =
            two_peer_rpc("ipc-bridge-channel").await;

        let registry = ClientRegistry::new();
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<ServerOut>();
        let client = registry.register(tx);
        let net_key = "alice".to_string();
        let chan_key = "catalog".to_string();
        let key = (net_key.clone(), chan_key.clone());

        // Subscribe and spawn the pump. The pump only needs
        // the engine state to build a `Channel<Value>` —
        // bypass the JoinedNetwork facade here for the same
        // reason the bridge module itself takes
        // `&JoinedNetwork` in production.
        let was_first = registry.subscribe_channel(key.clone(), client.id);
        assert!(was_first);

        // Spawn a pump that mirrors `bridge::spawn_channel_pump`
        // but uses the engine state directly.
        let chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::Channel::new(chan_key.clone(), alice_state.clone());
        let mut sub = chan.subscribe();
        let registry_for_pump = registry.clone();
        let key_for_pump = key.clone();
        tokio::spawn(async move {
            loop {
                let subscribers = registry_for_pump.channel_subscribers(&key_for_pump);
                if subscribers.is_empty() {
                    break;
                }
                let Some(next) = sub.recv().await else {
                    break;
                };
                let Ok(msg) = next else {
                    continue;
                };
                let frame = ServerOut::ChannelInbound {
                    network: key_for_pump.0.clone(),
                    from: msg.from,
                    channel: key_for_pump.1.clone(),
                    payload: msg.body,
                };
                for cid in subscribers {
                    if let Some(c) = registry_for_pump.client(cid) {
                        c.send(frame.clone());
                    }
                }
            }
        });

        // Bob sends to Alice on the channel.
        let bob_chan: myownmesh_core::Channel<serde_json::Value> =
            myownmesh_core::Channel::new(chan_key.clone(), bob_state.clone());
        bob_chan
            .send_to(
                _alice_id_arg(&alice_state),
                &serde_json::json!({"hello": "from bob"}),
            )
            .await
            .expect("bob send");

        let frame = tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("inbound timeout")
            .expect("inbound recv");
        match frame {
            ServerOut::ChannelInbound {
                network,
                from,
                channel,
                payload,
            } => {
                assert_eq!(network, net_key);
                assert_eq!(channel, chan_key);
                assert_eq!(from, bob_id.public_id());
                assert_eq!(payload, serde_json::json!({"hello": "from bob"}));
            }
            other => panic!("expected ChannelInbound, got {other:?}"),
        }
    }

    fn _alice_id_arg(state: &Arc<myownmesh_core::engine::NetworkState>) -> &str {
        state.identity.public_id()
    }
}
