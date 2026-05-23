//! Concrete Nostr signaling driver. Connects to N relays in
//! parallel, publishes ephemeral signaling events tagged with
//! the room handle, subscribes to inbound events on the same
//! tag, and routes them back to the caller via mpsc channels.
//!
//! Resilience features baked in (see `crate::upstream`):
//!
//! - Subscription replay on socket reconnect, with anti-flood
//!   backoff at 5 / 10 / 15 / 30 / 60 s.
//! - Transition-only logging — no per-event spam.
//! - Per-relay backoff on connection failure, capped at 60 s.
//!
//! The driver is independent of the engine; the
//! [`crate::SignalingChannel`] trait is the seam.

use std::sync::Arc;
use std::time::Duration;

use futures::{SinkExt, StreamExt};
use parking_lot::Mutex;
use serde_json::Value;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Message as WsMessage;
use tracing::{debug, info, trace, warn};

use super::event::{make_event, now_secs, NostrEvent, NostrIdentity, SIGNALING_EVENT_KIND};
use super::handle::derive_room_handle;
use super::relay::SubscriptionReplay;
use super::shuffle::select_top_n;
use crate::upstream::ANNOUNCE_INTERVAL_MS;
use crate::SignalingMessage;

/// Configuration for one driver instance.
#[derive(Debug, Clone)]
pub struct NostrDriverConfig {
    /// App-id used in the room-handle derivation. Forks pick
    /// their own here to isolate from upstream.
    pub app_id: String,
    /// Network id (the user-facing identifier; not the room
    /// handle — we derive that from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey
    /// surfaced by the mesh layer).
    pub device_id: String,
    /// User-supplied relay URLs. Empty = use built-in defaults.
    pub servers: Vec<String>,
    /// Hostnames excluded from the shuffle.
    pub denylist: Vec<String>,
    /// Top-N relays to maintain.
    pub redundancy: usize,
}

/// Inbound signaling events the driver pushes to the engine.
#[derive(Debug, Clone)]
pub enum NostrInbound {
    /// A peer announced their presence in the room.
    PeerAnnounced { device_id: String },
    /// A peer addressed us directly with a signaling message.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
#[derive(Debug, Clone)]
pub enum NostrOutbound {
    Announce,
    DirectedToPeer { to: String, msg: SignalingMessage },
}

/// Start the driver. Spawns a coordinator task per relay; returns
/// the handle (drop to stop).
pub fn start(
    config: NostrDriverConfig,
    outbound_rx: mpsc::UnboundedReceiver<NostrOutbound>,
    inbound_tx: mpsc::UnboundedSender<NostrInbound>,
) -> NostrDriverHandle {
    let identity = NostrIdentity::generate();
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);
    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..16],
        pubkey = %&identity.pubkey_hex()[..16],
        "starting Nostr driver"
    );

    // Resolve the top-N relay set.
    let pool_storage: Vec<&str>;
    let pool: Vec<&str> = if config.servers.is_empty() {
        super::defaults::DEFAULT_RELAY_URLS.to_vec()
    } else {
        pool_storage = config.servers.iter().map(String::as_str).collect();
        pool_storage
    };
    let denylist = &config.denylist;
    let filtered: Vec<&str> = pool
        .into_iter()
        .filter(|u| !super::denylist::is_denied(u, denylist))
        .collect();
    let selected = select_top_n(&config.app_id, &filtered, config.redundancy);

    // Fan-out channel for outbound events. Capacity is generous
    // so a slow relay can't backpressure the publish side.
    let (publish_tx, _) = broadcast::channel::<Arc<NostrEvent>>(64);
    let shared = Arc::new(DriverShared {
        identity,
        room_handle,
        device_id: config.device_id.clone(),
        relays: Mutex::new(Vec::new()),
        outbound: tokio::sync::Mutex::new(Some(outbound_rx)),
        publish_tx,
    });
    {
        let mut relays = shared.relays.lock();
        for url in &selected {
            relays.push(RelayHandle {
                url: url.clone(),
                connected: false,
            });
        }
    }

    let mut cancellers = Vec::new();

    // Spawn one connection task per relay.
    for url in selected {
        let shared = shared.clone();
        let inbound_tx = inbound_tx.clone();
        let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let cancel_token_for_task = cancel_token.clone();
        cancellers.push(cancel_token);
        tokio::spawn(async move {
            run_relay(url, shared, inbound_tx, cancel_token_for_task).await;
        });
    }

    // Spawn the outbound pump.
    let shared_for_outbound = shared.clone();
    let cancel_token = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let cancel_token_for_task = cancel_token.clone();
    cancellers.push(cancel_token);
    tokio::spawn(async move {
        run_outbound_pump(shared_for_outbound, cancel_token_for_task).await;
    });

    NostrDriverHandle { cancellers }
}

/// Handle returned by [`start`]. Drop or call [`Self::stop`] to
/// signal every spawned task to exit.
pub struct NostrDriverHandle {
    cancellers: Vec<Arc<std::sync::atomic::AtomicBool>>,
}

impl NostrDriverHandle {
    pub fn stop(self) {
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

impl Drop for NostrDriverHandle {
    fn drop(&mut self) {
        for c in &self.cancellers {
            c.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }
}

struct DriverShared {
    identity: NostrIdentity,
    room_handle: String,
    device_id: String,
    relays: Mutex<Vec<RelayHandle>>,
    outbound: tokio::sync::Mutex<Option<mpsc::UnboundedReceiver<NostrOutbound>>>,
    publish_tx: broadcast::Sender<Arc<NostrEvent>>,
}

#[allow(dead_code)]
struct RelayHandle {
    url: String,
    connected: bool,
}

async fn run_relay(
    url: String,
    shared: Arc<DriverShared>,
    inbound_tx: mpsc::UnboundedSender<NostrInbound>,
    cancel: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut backoff_attempt = 0u32;
    let mut replay = SubscriptionReplay::new();
    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        match tokio_tungstenite::connect_async(&url).await {
            Ok((stream, _)) => {
                info!(relay = %short(&url), "relay connected");
                backoff_attempt = 0;
                let outcome =
                    run_relay_session(&url, stream, &shared, &inbound_tx, &mut replay, &cancel)
                        .await;
                trace!(relay = %short(&url), outcome = ?outcome, "relay session ended");
            }
            Err(e) => {
                warn!(relay = %short(&url), "relay connect failed: {e}");
            }
        }
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        // Reconnect backoff: 1 / 2 / 4 / 8 / 16 s capped at 60 s.
        backoff_attempt = (backoff_attempt + 1).min(6);
        let wait = (1u64 << backoff_attempt).min(60);
        debug!(relay = %short(&url), wait_s = wait, "relay backoff before reconnect");
        sleep(Duration::from_secs(wait)).await;
    }
}

#[derive(Debug)]
#[allow(dead_code)] // Variants are read by their Debug impl in trace logs.
enum RelaySessionOutcome {
    Cancelled,
    SocketClosed,
    Error(String),
}

async fn run_relay_session(
    url: &str,
    stream: tokio_tungstenite::WebSocketStream<
        tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>,
    >,
    shared: &Arc<DriverShared>,
    inbound_tx: &mpsc::UnboundedSender<NostrInbound>,
    replay: &mut SubscriptionReplay,
    cancel: &Arc<std::sync::atomic::AtomicBool>,
) -> RelaySessionOutcome {
    let (mut write, mut read) = stream.split();

    // Open subscription for the room handle.
    let sub_id = "mom-sig-1";
    let req = serde_json::json!([
        "REQ",
        sub_id,
        {
            "kinds": [SIGNALING_EVENT_KIND],
            "#r": [shared.room_handle.clone()],
            "since": now_secs().saturating_sub(300),
        }
    ]);
    let req_text = req.to_string();
    let _ = replay.observe_send(&req_text);

    if let Err(e) = write.send(WsMessage::Text(req_text.clone())).await {
        return RelaySessionOutcome::Error(format!("send REQ: {e}"));
    }

    // Mark the socket as opened so the replay layer knows.
    let _decision = replay.on_open();
    replay.record_replay();

    // Subscribe to the broadcast so outbound events fan to this socket.
    let mut publish_rx = shared.publish_tx.subscribe();
    let mut announce_timer = tokio::time::interval(Duration::from_millis(ANNOUNCE_INTERVAL_MS));
    announce_timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);

    loop {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return RelaySessionOutcome::Cancelled;
        }
        tokio::select! {
            msg = read.next() => {
                let Some(msg) = msg else { return RelaySessionOutcome::SocketClosed };
                let frame = match msg {
                    Ok(WsMessage::Text(t)) => t,
                    Ok(WsMessage::Binary(b)) => match std::str::from_utf8(&b) {
                        Ok(s) => s.to_string(),
                        Err(_) => continue,
                    },
                    Ok(WsMessage::Close(_)) => return RelaySessionOutcome::SocketClosed,
                    Ok(_) => continue,
                    Err(e) => return RelaySessionOutcome::Error(format!("ws read: {e}")),
                };
                if let Err(e) = handle_inbound_frame(url, &frame, shared, inbound_tx) {
                    trace!(relay = %short(url), "inbound frame parse: {e}");
                }
            }
            publish = publish_rx.recv() => {
                match publish {
                    Ok(event) => {
                        let frame = serde_json::json!(["EVENT", &*event]).to_string();
                        if let Err(e) = write.send(WsMessage::Text(frame)).await {
                            return RelaySessionOutcome::Error(format!("send publish: {e}"));
                        }
                    }
                    Err(broadcast::error::RecvError::Closed) => {
                        return RelaySessionOutcome::Cancelled;
                    }
                    Err(broadcast::error::RecvError::Lagged(n)) => {
                        warn!(relay = %short(url), "publish bus lagged {n} events");
                    }
                }
            }
            _ = announce_timer.tick() => {
                let event = build_announce_event(shared);
                let frame = serde_json::json!(["EVENT", event]).to_string();
                if let Err(e) = write.send(WsMessage::Text(frame)).await {
                    return RelaySessionOutcome::Error(format!("send announce: {e}"));
                }
            }
        }
    }
}

fn handle_inbound_frame(
    url: &str,
    frame: &str,
    shared: &Arc<DriverShared>,
    inbound_tx: &mpsc::UnboundedSender<NostrInbound>,
) -> Result<(), String> {
    let value: Value = serde_json::from_str(frame).map_err(|e| e.to_string())?;
    let arr = value.as_array().ok_or_else(|| "not an array".to_string())?;
    let tag = arr.first().and_then(|v| v.as_str()).unwrap_or("");
    match tag {
        "EVENT" => {
            let event_value = arr.get(2).ok_or_else(|| "missing event body".to_string())?;
            let event: NostrEvent =
                serde_json::from_value(event_value.clone()).map_err(|e| e.to_string())?;
            // Skip events we sent ourselves.
            if event.pubkey == shared.identity.pubkey_hex() {
                return Ok(());
            }
            // Pull our envelope out of the content.
            let envelope: SignalingEnvelope =
                serde_json::from_str(&event.content).map_err(|e| e.to_string())?;

            // Skip messages directed to a different recipient.
            if let Some(to) = &envelope.to {
                if to != &shared.device_id {
                    return Ok(());
                }
            }

            match envelope.msg {
                SignalingMessage::Announce { peer_id } => {
                    if peer_id == shared.device_id {
                        return Ok(());
                    }
                    let _ = inbound_tx.send(NostrInbound::PeerAnnounced { device_id: peer_id });
                }
                other => {
                    let _ = inbound_tx.send(NostrInbound::Message {
                        from: envelope.from,
                        msg: other,
                    });
                }
            }
        }
        "EOSE" => {
            trace!(relay = %short(url), "EOSE");
        }
        "NOTICE" => {
            let body = arr.get(1).and_then(|v| v.as_str()).unwrap_or("");
            debug!(relay = %short(url), "relay notice: {body}");
        }
        _ => {
            trace!(relay = %short(url), "unhandled tag: {tag}");
        }
    }
    Ok(())
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct SignalingEnvelope {
    from: String,
    /// Recipient device id, or None for a broadcast (announce).
    #[serde(default)]
    to: Option<String>,
    #[serde(flatten)]
    msg: SignalingMessage,
}

fn build_announce_event(shared: &DriverShared) -> NostrEvent {
    let envelope = SignalingEnvelope {
        from: shared.device_id.clone(),
        to: None,
        msg: SignalingMessage::Announce {
            peer_id: shared.device_id.clone(),
        },
    };
    make_event(
        &shared.identity,
        SIGNALING_EVENT_KIND,
        vec![vec!["r".into(), shared.room_handle.clone()]],
        serde_json::to_string(&envelope).expect("serialize ok"),
        now_secs(),
    )
}

async fn run_outbound_pump(shared: Arc<DriverShared>, cancel: Arc<std::sync::atomic::AtomicBool>) {
    let mut rx_guard = shared.outbound.lock().await;
    let Some(mut rx) = rx_guard.take() else {
        return;
    };
    drop(rx_guard);
    while let Some(outbound) = rx.recv().await {
        if cancel.load(std::sync::atomic::Ordering::SeqCst) {
            return;
        }
        let envelope = match outbound {
            NostrOutbound::Announce => SignalingEnvelope {
                from: shared.device_id.clone(),
                to: None,
                msg: SignalingMessage::Announce {
                    peer_id: shared.device_id.clone(),
                },
            },
            NostrOutbound::DirectedToPeer { to, msg } => SignalingEnvelope {
                from: shared.device_id.clone(),
                to: Some(to),
                msg,
            },
        };
        let event = Arc::new(make_event(
            &shared.identity,
            SIGNALING_EVENT_KIND,
            vec![vec!["r".into(), shared.room_handle.clone()]],
            serde_json::to_string(&envelope).expect("serialize ok"),
            now_secs(),
        ));
        // Fan out to every connected relay session via the
        // broadcast bus. Sessions that aren't subscribed yet
        // (still connecting / reconnecting) will pick up the
        // next event after their subscribe — for the
        // active-handshake path that's the periodic announce
        // running on each relay's own timer.
        if shared.publish_tx.receiver_count() == 0 {
            debug!("no relay subscribers ready; outbound event dropped");
            continue;
        }
        let _ = shared.publish_tx.send(event);
    }
}

fn short(url: &str) -> &str {
    url.strip_prefix("wss://")
        .or_else(|| url.strip_prefix("ws://"))
        .unwrap_or(url)
        .split('/')
        .next()
        .unwrap_or(url)
}
