//! Integration tests for the self-hosted signaling relay.
//!
//! Two levels of proof:
//!  1. Raw NIP-01 over the wire — a subscriber receives an event a
//!     publisher posts to the same room, plus `EOSE`.
//!  2. The headline feature — two real [`nostr`](myownmesh_signaling::nostr)
//!     drivers, pointed only at a self-hosted relay (no public Nostr),
//!     discover each other. This is the "use it in place of Nostr" claim
//!     under test.

use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use myownmesh_signaling::server::{Limits, SignalingServer};

/// Read frames until a text frame arrives (skipping pings/pongs),
/// failing the test on timeout or close.
async fn next_text(ws: &mut (impl Stream<Item = Result<Message, WsError>> + Unpin)) -> String {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(5), ws.next())
            .await
            .expect("ws read timed out")
            .expect("ws closed unexpectedly")
            .expect("ws error");
        if let Message::Text(t) = msg {
            return t;
        }
    }
}

fn parse(frame: &str) -> Vec<Value> {
    serde_json::from_str(frame).expect("relay frame is a JSON array")
}

#[tokio::test]
async fn relay_forwards_event_to_matching_subscriber() {
    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let (mut sub, _) = connect_async(&url).await.unwrap();
    let (mut pubr, _) = connect_async(&url).await.unwrap();

    // Subscriber asks for room1 / kind 1077.
    sub.send(Message::Text(
        json!(["REQ", "sub1", {"kinds": [1077], "#r": ["room1"]}]).to_string(),
    ))
    .await
    .unwrap();

    // Nothing stored yet → immediate EOSE.
    let eose = parse(&next_text(&mut sub).await);
    assert_eq!(eose[0], "EOSE");
    assert_eq!(eose[1], "sub1");

    // Publisher posts a matching event.
    let event = json!({
        "id": "e1", "pubkey": "pk", "created_at": 1000, "kind": 1077,
        "tags": [["r", "room1"]], "content": "hello", "sig": "s"
    });
    pubr.send(Message::Text(json!(["EVENT", event]).to_string()))
        .await
        .unwrap();

    // Publisher gets an OK; subscriber gets the event.
    let ok = parse(&next_text(&mut pubr).await);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[2], true);

    let delivered = parse(&next_text(&mut sub).await);
    assert_eq!(delivered[0], "EVENT");
    assert_eq!(delivered[1], "sub1");
    assert_eq!(delivered[2]["content"], "hello");

    server.stop();
}

#[tokio::test]
async fn relay_replays_stored_presence_to_late_subscriber() {
    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    // Publisher posts presence BEFORE anyone subscribes.
    let (mut pubr, _) = connect_async(&url).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = json!({
        "id": "p1", "pubkey": "pk", "created_at": now, "kind": 1077,
        "tags": [["r", "roomX"]], "content": "present", "sig": "s"
    });
    pubr.send(Message::Text(json!(["EVENT", event]).to_string()))
        .await
        .unwrap();
    let _ok = next_text(&mut pubr).await;

    // A subscriber joining afterwards still discovers the presence via
    // stored-event replay (kind 1077 is retained).
    let (mut sub, _) = connect_async(&url).await.unwrap();
    sub.send(Message::Text(
        json!(["REQ", "late", {"kinds": [1077], "#r": ["roomX"], "since": now - 60}]).to_string(),
    ))
    .await
    .unwrap();

    let replayed = parse(&next_text(&mut sub).await);
    assert_eq!(replayed[0], "EVENT");
    assert_eq!(replayed[2]["content"], "present");
    let eose = parse(&next_text(&mut sub).await);
    assert_eq!(eose[0], "EOSE");

    server.stop();
}

#[tokio::test]
async fn ephemeral_events_are_not_stored() {
    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let (mut pubr, _) = connect_async(&url).await.unwrap();
    // Ephemeral kind 21077 (mesh negotiation) — forwarded live, never
    // retained for replay.
    let event = json!({
        "id": "n1", "pubkey": "pk", "created_at": 1000, "kind": 21077,
        "tags": [["r", "roomE"]], "content": "offer", "sig": "s"
    });
    pubr.send(Message::Text(json!(["EVENT", event]).to_string()))
        .await
        .unwrap();
    let _ok = next_text(&mut pubr).await;

    // A later subscriber sees only EOSE — the ephemeral event wasn't
    // stored, so there's nothing to replay.
    let (mut sub, _) = connect_async(&url).await.unwrap();
    sub.send(Message::Text(
        json!(["REQ", "s", {"kinds": [21077], "#r": ["roomE"]}]).to_string(),
    ))
    .await
    .unwrap();
    let first = parse(&next_text(&mut sub).await);
    assert_eq!(first[0], "EOSE", "ephemeral event must not be replayed");

    server.stop();
}

// The headline test: two real Nostr drivers, pointed ONLY at a
// self-hosted relay, discover each other — proving the relay works "in
// place of Nostr" with zero driver changes.
#[tokio::test]
async fn two_drivers_discover_via_self_hosted_relay() {
    use myownmesh_signaling::nostr::driver::{
        start, NostrDriverConfig, NostrInbound, NostrOutbound,
    };
    use tokio::sync::mpsc;

    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let mk = |device: &str| NostrDriverConfig {
        app_id: "myownmesh-test".into(),
        network_id: "isolated-net".into(),
        device_id: device.into(),
        servers: vec![url.clone()],
        denylist: vec![],
        redundancy: 1,
        // No public fallback in tests — keep the driver strictly on the
        // local test relay so it never reaches for real public relays.
        public_fallback: false,
    };

    // Keep the outbound senders and driver handles bound for the whole
    // test — dropping either tears the driver down.
    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let _driver_a = start(mk("device-aaa"), out_rx_a, in_tx_a);

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let _driver_b = start(mk("device-bbb"), out_rx_b, in_tx_b);

    // Drivers auto-announce on start; B should learn about A through the
    // self-hosted relay (live forward or stored replay).
    let found = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if let NostrInbound::PeerAnnounced { device_id } = ev {
                if device_id == "device-aaa" {
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("timed out before discovering peer via self-hosted relay");
    assert!(found, "driver B never saw driver A's announce");

    // Hold the senders/handles until here.
    drop(out_tx_a);
    drop(out_tx_b);
    server.stop();
}

// End-to-end: a driver that makes a *deliberate* exit announces its own
// `leave`, and a peer surfaces it as `NostrInbound::PeerLeft` — no
// intelligent relay required. This is the path that makes the app's
// "reconnect" (leave-then-rejoin) come back promptly on the default public
// relays, which never synthesise a leave for us.
#[tokio::test]
async fn driver_self_announced_leave_reaches_peer() {
    use myownmesh_signaling::nostr::driver::{
        start, NostrDriverConfig, NostrInbound, NostrOutbound,
    };
    use tokio::sync::mpsc;

    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let mk = |device: &str| NostrDriverConfig {
        app_id: "myownmesh-test".into(),
        network_id: "self-leave-net".into(),
        device_id: device.into(),
        servers: vec![url.clone()],
        denylist: vec![],
        redundancy: 1,
        public_fallback: false,
    };

    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let _driver_a = start(mk("device-aaa"), out_rx_a, in_tx_a);

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let _driver_b = start(mk("device-bbb"), out_rx_b, in_tx_b);

    // B discovers A first.
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerAnnounced { device_id } if device_id == "device-aaa")
            {
                return;
            }
        }
        panic!("B never discovered A");
    })
    .await
    .expect("discovery timed out");

    // A announces a graceful departure while still connected. The driver
    // stays alive (we don't drop it) — the leave rides the relay like any
    // other publish, and B surfaces it as PeerLeft.
    out_tx_a
        .send(NostrOutbound::Leave)
        .expect("queue A's leave");

    let saw_leave = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerLeft { device_id } if device_id == "device-aaa") {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for self-announced PeerLeft");
    assert!(saw_leave, "B never saw A's self-announced leave");

    drop(out_tx_a);
    drop(out_tx_b);
    server.stop();
}

// Intelligent-relay behaviour: when a member's socket drops, the relay
// emits a `leave` to the room so others tear down promptly.
#[tokio::test]
async fn relay_emits_leave_when_member_disconnects() {
    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    // Subscriber watches the room for presence + departures.
    let (mut sub, _) = connect_async(&url).await.unwrap();
    sub.send(Message::Text(
        json!(["REQ", "s", {"kinds": [1077, 21077], "#r": ["leaveroom"]}]).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(parse(&next_text(&mut sub).await)[0], "EOSE");

    // A member announces with a real mesh envelope, so the relay tracks
    // its presence against this connection.
    let (mut member, _) = connect_async(&url).await.unwrap();
    let envelope = json!({ "from": "devA", "kind": "announce", "peer_id": "devA" }).to_string();
    let announce = json!({
        "id": "a1", "pubkey": "pk", "created_at": 1000, "kind": 1077,
        "tags": [["r", "leaveroom"]], "content": envelope, "sig": "s"
    });
    member
        .send(Message::Text(json!(["EVENT", announce]).to_string()))
        .await
        .unwrap();
    // Drain the member's OK so we know the relay has recorded presence.
    assert_eq!(parse(&next_text(&mut member).await)[0], "OK");
    // Subscriber sees the announce.
    assert_eq!(parse(&next_text(&mut sub).await)[0], "EVENT");

    // Member drops — the relay should synthesize a leave to the room.
    drop(member);

    let leave = parse(&next_text(&mut sub).await);
    assert_eq!(leave[0], "EVENT");
    let content: Value =
        serde_json::from_str(leave[2]["content"].as_str().expect("content is a string")).unwrap();
    assert_eq!(content["kind"], "leave");
    assert_eq!(content["peer_id"], "devA");

    server.stop();
}

// End-to-end: a driver learns a peer left soon after the relay sees the
// peer's socket drop. Proves the smart-relay departure path lights up
// `NostrInbound::PeerLeft` through the real driver, staying plain NIP-01.
//
// This relies on a *dropped* driver closing its relay socket promptly.
// The driver's read loop now wakes every `RELAY_CANCEL_POLL_MS` (≈250 ms)
// to re-check its cancel flag and sends a clean Close on teardown, so the
// socket closes within a fraction of a second of the handle dropping —
// well inside this test's window on every platform. (Before that fix the
// loop could stay parked in `read.next()` on an idle socket, which made
// this flaky on the macOS / Windows CI runners.)
#[tokio::test]
async fn driver_gets_peer_left_when_peer_disconnects() {
    use myownmesh_signaling::nostr::driver::{
        start, NostrDriverConfig, NostrInbound, NostrOutbound,
    };
    use tokio::sync::mpsc;

    let server = SignalingServer::start("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let mk = |device: &str| NostrDriverConfig {
        app_id: "myownmesh-test".into(),
        network_id: "leave-net".into(),
        device_id: device.into(),
        servers: vec![url.clone()],
        denylist: vec![],
        redundancy: 1,
        public_fallback: false,
    };

    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_a = start(mk("device-aaa"), out_rx_a, in_tx_a);

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let _driver_b = start(mk("device-bbb"), out_rx_b, in_tx_b);

    // First B discovers A.
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerAnnounced { device_id } if device_id == "device-aaa")
            {
                return;
            }
        }
        panic!("B never discovered A");
    })
    .await
    .expect("discovery timed out");

    // Now A leaves. Dropping the handle + outbound sender closes A's
    // relay socket; the relay emits a leave; B's driver surfaces PeerLeft.
    drop(driver_a);
    drop(out_tx_a);

    let saw_leave = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerLeft { device_id } if device_id == "device-aaa") {
                return true;
            }
        }
        false
    })
    .await
    .expect("timed out waiting for PeerLeft");
    assert!(saw_leave, "B never saw A's departure");

    drop(out_tx_b);
    server.stop();
}
