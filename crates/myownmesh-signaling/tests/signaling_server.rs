//! Integration tests for the self-hosted signaling relay.
//!
//! Two levels of proof:
//!  1. Raw NIP-01 over the wire — a subscriber receives an event a
//!     publisher posts to the same room, plus `EOSE`.
//!  2. The headline feature — two real [`nostr`](myownmesh_signaling::nostr)
//!     drivers, pointed only at a self-hosted relay (no public Nostr),
//!     discover each other. This is the "use it in place of Nostr" claim
//!     under test.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use myownmesh_signaling::nostr::delivery::{
    DeliveryLease, DeliveryProvider, DeliveryRefusal, DeliveryRetention, DeliveryTerminal,
    RelaySessionId, SessionRetention,
};
use myownmesh_signaling::nostr::driver::{derive_task_custody_plan, NostrDriverConfig};
use myownmesh_signaling::server::{Limits, SignalingServer};
use myownmesh_signaling::{
    AttemptOutcome, AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, DedicatedTaskCustodian,
    InboundSink, TaskCustodian, UnboundedSource,
};

struct NoopAttemptRefusalSink;

impl AttemptRefusalSink for NoopAttemptRefusalSink {
    fn refused(&self, _refusal: AttemptRefusal) {}
}

struct NoopAttemptOutcomeSink;

impl AttemptOutcomeSink for NoopAttemptOutcomeSink {
    fn outcome(&self, _outcome: AttemptOutcome) {}
}

const SIGNALLING_TEST_DELIVERY_CAPACITY: usize = 256;

async fn start_test_server(
    bind: &str,
    port: u16,
    limits: Limits,
) -> Result<myownmesh_signaling::server::SignalingServerHandle, myownmesh_signaling::Error> {
    let capacity = SignalingServer::required_task_custody_slots(&limits)?;
    let owner = DedicatedTaskCustodian::new(capacity)
        .map_err(|error| myownmesh_signaling::Error::Other(format!("test custodian: {error:?}")))?;
    SignalingServer::start_with_custodian(bind, port, limits, owner).await
}

fn test_nostr_timing() -> myownmesh_signaling::nostr::driver::NostrTimingConfig {
    myownmesh_signaling::nostr::driver::NostrTimingConfig {
        connect_timeout: Duration::from_secs(30),
        reconnect_initial: Duration::from_secs(2),
        reconnect_max: Duration::from_secs(60),
        reconnect_max_attempts: 6,
        jitter_percent: 15,
        fallback_poll: Duration::from_secs(3),
        fallback_activation_grace: Duration::from_secs(20),
        session_close_timeout: Duration::from_secs(1),
        announcer_cancel_quantum: Duration::from_secs(1),
    }
}

fn test_task_custodians(
    config: &NostrDriverConfig,
) -> (Arc<dyn TaskCustodian>, Arc<dyn TaskCustodian>) {
    assert!(
        !config.public_fallback,
        "fixture fallback count is explicitly zero"
    );
    assert!(
        config.denylist.is_empty(),
        "fixture denylist is explicitly empty"
    );
    let pool = config
        .servers
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let selected =
        myownmesh_signaling::nostr::shuffle::select_top_n(&config.app_id, &pool, config.redundancy);
    let plan = derive_task_custody_plan(selected.len(), 0)
        .expect("fixture relay counts produce a finite custody plan");
    (
        DedicatedTaskCustodian::new(plan.primary_observer_slots).expect("primary fixture custodian")
            as Arc<dyn TaskCustodian>,
        DedicatedTaskCustodian::new(plan.reaper_observer_slots).expect("reaper fixture custodian")
            as Arc<dyn TaskCustodian>,
    )
}

fn start_test_driver<S>(
    config: NostrDriverConfig,
    outbound: S,
    inbound: InboundSink<myownmesh_signaling::nostr::driver::NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
) -> Result<myownmesh_signaling::nostr::driver::NostrDriverHandle, myownmesh_signaling::Error>
where
    S: myownmesh_signaling::OutboundSource<myownmesh_signaling::nostr::driver::NostrOutbound>
        + Send
        + 'static,
    S::Owner: Sync + 'static,
{
    let (custodian_owner, reaper_custodian_owner) = test_task_custodians(&config);
    myownmesh_signaling::nostr::driver::start_with_delivery_provider_and_sinks_with_custodian(
        config,
        outbound,
        inbound,
        provider,
        Arc::new(NoopAttemptRefusalSink),
        Arc::new(NoopAttemptOutcomeSink),
        myownmesh_signaling::nostr::driver::NostrTaskCustodyOwners {
            primary: custodian_owner,
            reaper: reaper_custodian_owner,
        },
    )
}

struct FiniteTestProvider {
    live: Arc<AtomicUsize>,
}

struct FiniteTestLease {
    live: Arc<AtomicUsize>,
}

impl FiniteTestProvider {
    fn new() -> Self {
        Self {
            live: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn reserve_one(&self) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        loop {
            let current = self.live.load(Ordering::Acquire);
            if current >= SIGNALLING_TEST_DELIVERY_CAPACITY {
                return Err(DeliveryRefusal::Provider(
                    "finite signaling test provider exhausted".into(),
                ));
            }
            if self
                .live
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Ok(Box::new(FiniteTestLease {
                    live: Arc::clone(&self.live),
                }));
            }
        }
    }
}

impl DeliveryLease for FiniteTestLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
        self.live.fetch_sub(1, Ordering::AcqRel);
    }
}

impl DeliveryProvider for FiniteTestProvider {
    fn reserve_inbound_frame(
        &self,
        _frame_bytes: usize,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_admission_source(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_session_identity(
        &self,
        _retention: SessionRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }

    fn reserve_attempt_correlation(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> std::result::Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.reserve_one()
    }
}

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

/// Build a properly signed NIP-01 event JSON. The relay now verifies the id +
/// BIP-340 signature, so tests post real events (forged ones are rejected).
fn signed_event(kind: u16, room: &str, content: &str, created_at: u64) -> Value {
    use myownmesh_signaling::nostr::event::{make_event, NostrIdentity};
    let id = NostrIdentity::generate();
    let ev = make_event(
        &id,
        kind,
        vec![vec!["r".into(), room.into()]],
        content.into(),
        created_at,
    );
    serde_json::to_value(&ev).expect("event serializes")
}

#[tokio::test]
async fn relay_forwards_event_to_matching_subscriber() {
    let server = start_test_server("127.0.0.1", 0, Limits::default())
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
    let event = signed_event(1077, "room1", "hello", 1000);
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

    server
        .stop_and_wait()
        .await
        .expect("raw event server shutdown succeeds");
}

#[tokio::test]
async fn relay_replays_stored_presence_to_late_subscriber() {
    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    // Publisher posts presence BEFORE anyone subscribes.
    let (mut pubr, _) = connect_async(&url).await.unwrap();
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let event = signed_event(1077, "roomX", "present", now);
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

    server
        .stop_and_wait()
        .await
        .expect("presence replay server shutdown succeeds");
}

#[tokio::test]
async fn ephemeral_events_are_not_stored() {
    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());

    let (mut pubr, _) = connect_async(&url).await.unwrap();
    // Ephemeral kind 21077 (mesh negotiation) — forwarded live, never
    // retained for replay.
    let event = signed_event(21077, "roomE", "offer", 1000);
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

    server
        .stop_and_wait()
        .await
        .expect("ephemeral event server shutdown succeeds");
}

#[tokio::test]
async fn unadvertised_profile_kind_is_excluded_from_matching_stream() {
    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let (mut sub, _) = connect_async(&url).await.unwrap();
    let (mut pubr, _) = connect_async(&url).await.unwrap();
    sub.send(Message::Text(
        json!(["REQ", "profile", {"kinds": [1077, 21077], "#r": ["profile-room"]}]).to_string(),
    ))
    .await
    .unwrap();
    assert_eq!(parse(&next_text(&mut sub).await)[0], "EOSE");

    let unsupported = signed_event(1078, "profile-room", "unsupported", 2000);
    pubr.send(Message::Text(json!(["EVENT", unsupported]).to_string()))
        .await
        .unwrap();
    assert_eq!(parse(&next_text(&mut pubr).await)[0], "OK");

    let received = tokio::time::timeout(Duration::from_millis(250), async {
        while let Some(message) = sub.next().await {
            if let Message::Text(text) = message.unwrap() {
                let frame = parse(&text);
                if frame[0] == "EVENT" {
                    return true;
                }
            }
        }
        false
    })
    .await
    .unwrap_or(false);
    assert!(
        !received,
        "only the advertised presence/negotiation profiles match"
    );
    server
        .stop_and_wait()
        .await
        .expect("profile filter server shutdown succeeds");
}

// The headline test: two real Nostr drivers, pointed ONLY at a
// self-hosted relay, discover each other — proving the relay works "in
// place of Nostr" with zero driver changes.
#[tokio::test]
async fn two_drivers_discover_via_self_hosted_relay() {
    use myownmesh_signaling::nostr::driver::{NostrDriverConfig, NostrInbound, NostrOutbound};
    use tokio::sync::mpsc;

    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let provider: Arc<dyn DeliveryProvider> = Arc::new(FiniteTestProvider::new());

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
        timing: test_nostr_timing(),
    };

    // Keep the outbound senders and driver handles bound for the whole
    // test — dropping either tears the driver down.
    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_a = start_test_driver(
        mk("device-aaa"),
        Box::new(UnboundedSource::new(out_rx_a)),
        InboundSink::from_unbounded(in_tx_a),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_b = start_test_driver(
        mk("device-bbb"),
        Box::new(UnboundedSource::new(out_rx_b)),
        InboundSink::from_unbounded(in_tx_b),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    // Drivers auto-announce on start; B should learn about A through the
    // self-hosted relay (live forward or stored replay).
    let found = tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if let NostrInbound::PeerAnnounced { device_id, .. } = ev {
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
    driver_a.stop_and_join().await;
    driver_b.stop_and_join().await;
    server
        .stop_and_wait()
        .await
        .expect("Nostr discovery server shutdown succeeds");
}

// End-to-end: a driver that makes a *deliberate* exit announces its own
// `leave`, and a peer surfaces it as `NostrInbound::PeerLeft` — no
// intelligent relay required. This is the path that makes the app's
// "reconnect" (leave-then-rejoin) come back promptly on the default public
// relays, which never synthesise a leave for us.
#[tokio::test]
async fn driver_self_announced_leave_reaches_peer() {
    use myownmesh_signaling::nostr::driver::{NostrDriverConfig, NostrInbound, NostrOutbound};
    use tokio::sync::mpsc;

    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let provider: Arc<dyn DeliveryProvider> = Arc::new(FiniteTestProvider::new());

    let mk = |device: &str| NostrDriverConfig {
        app_id: "myownmesh-test".into(),
        network_id: "self-leave-net".into(),
        device_id: device.into(),
        servers: vec![url.clone()],
        denylist: vec![],
        redundancy: 1,
        public_fallback: false,
        timing: test_nostr_timing(),
    };

    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_a = start_test_driver(
        mk("device-aaa"),
        Box::new(UnboundedSource::new(out_rx_a)),
        InboundSink::from_unbounded(in_tx_a),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_b = start_test_driver(
        mk("device-bbb"),
        Box::new(UnboundedSource::new(out_rx_b)),
        InboundSink::from_unbounded(in_tx_b),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    // B discovers A first.
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerAnnounced { device_id, .. } if device_id == "device-aaa")
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
            if matches!(ev, NostrInbound::PeerLeft { device_id, .. } if device_id == "device-aaa") {
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
    driver_a.stop_and_join().await;
    driver_b.stop_and_join().await;
    server
        .stop_and_wait()
        .await
        .expect("leave propagation server shutdown succeeds");
}

// Intelligent-relay behaviour: when a member's socket drops, the relay emits a
// `leave` to the room as a *reachability hint*. A receiver may stop pacing a
// dial or cancel speculative work on it; it may not tear a promoted session
// down on it, because the socket that dropped is the relay's, not the peer's,
// and a peer reachable by another carrier is still there. Prompt teardown is
// the authenticated `SessionControl::Depart` over the session itself.
#[tokio::test]
async fn relay_emits_leave_when_member_disconnects() {
    let server = start_test_server("127.0.0.1", 0, Limits::default())
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
    let announce = signed_event(1077, "leaveroom", &envelope, 1000);
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
    let signed_leave: myownmesh_signaling::nostr::event::NostrEvent =
        serde_json::from_value(leave[2].clone()).expect("relay leave is a typed Nostr event");
    assert!(signed_leave.verify(), "relay leave signature verifies");
    assert_eq!(signed_leave.kind, 21077);
    let content: Value =
        serde_json::from_str(leave[2]["content"].as_str().expect("content is a string")).unwrap();
    assert_eq!(content["kind"], "leave");
    assert_eq!(content["peer_id"], "devA");
    assert_eq!(content["from"], "devA");
    assert_eq!(content["to"], "leaveroom");

    server
        .stop_and_wait()
        .await
        .expect("relay departure server shutdown succeeds");
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
    use myownmesh_signaling::nostr::driver::{NostrDriverConfig, NostrInbound, NostrOutbound};
    use tokio::sync::mpsc;

    let server = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let provider: Arc<dyn DeliveryProvider> = Arc::new(FiniteTestProvider::new());

    let mk = |device: &str| NostrDriverConfig {
        app_id: "myownmesh-test".into(),
        network_id: "leave-net".into(),
        device_id: device.into(),
        servers: vec![url.clone()],
        denylist: vec![],
        redundancy: 1,
        public_fallback: false,
        timing: test_nostr_timing(),
    };

    let (out_tx_a, out_rx_a) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_a, _in_rx_a) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_a = start_test_driver(
        mk("device-aaa"),
        Box::new(UnboundedSource::new(out_rx_a)),
        InboundSink::from_unbounded(in_tx_a),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    let (out_tx_b, out_rx_b) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx_b, mut in_rx_b) = mpsc::unbounded_channel::<NostrInbound>();
    let driver_b = start_test_driver(
        mk("device-bbb"),
        Box::new(UnboundedSource::new(out_rx_b)),
        InboundSink::from_unbounded(in_tx_b),
        Arc::clone(&provider),
    )
    .expect("valid Nostr timing configuration");

    // First B discovers A.
    tokio::time::timeout(Duration::from_secs(20), async {
        while let Some(ev) = in_rx_b.recv().await {
            if matches!(ev, NostrInbound::PeerAnnounced { device_id, .. } if device_id == "device-aaa")
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
            if let NostrInbound::PeerLeft {
                device_id,
                attribution,
            } = ev
            {
                if device_id == "device-aaa" {
                    assert_eq!(
                        attribution,
                        myownmesh_signaling::CarrierAttribution::SenderClaimed,
                        "relay departure remains a sender-claimed reachability hint"
                    );
                    return true;
                }
            }
        }
        false
    })
    .await
    .expect("timed out waiting for PeerLeft");
    assert!(saw_leave, "B never saw A's departure");

    drop(out_tx_b);
    driver_b.stop_and_join().await;
    server
        .stop_and_wait()
        .await
        .expect("peer-left server shutdown succeeds");
}

#[tokio::test]
async fn zero_limit_configuration_is_rejected_before_binding() {
    let limits = Limits {
        max_connections: 0,
        ..Limits::default()
    };
    let error = start_test_server("127.0.0.1", 0, limits)
        .await
        .err()
        .expect("an unlimited global admission must be rejected");
    assert!(error.to_string().contains("max_connections"));
}

#[tokio::test]
async fn global_admission_cap_applies_before_websocket_handshake() {
    let limits = Limits {
        max_connections: 1,
        ..Limits::default()
    };
    let server = start_test_server("127.0.0.1", 0, limits).await.unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let (first, _) = connect_async(&url).await.unwrap();
    let second = tokio::time::timeout(Duration::from_secs(2), connect_async(&url))
        .await
        .expect("second handshake should be refused promptly");
    assert!(
        second.is_err(),
        "global admission must refuse the second peer"
    );
    assert_eq!(server.stats().connections, 1);
    drop(first);
    server
        .stop_and_wait()
        .await
        .expect("zero-limit server shutdown succeeds");
}

#[tokio::test]
async fn normal_connection_completion_releases_admission_before_shutdown() {
    let server = start_test_server(
        "127.0.0.1",
        0,
        Limits {
            max_connections: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let url = format!("ws://{}", server.local_addr());
    let (first, _) = connect_async(&url).await.unwrap();
    drop(first);

    tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            if server.stats().connections == 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("normal connection completion should release admission");
    assert_eq!(server.stats().connections, 0);
    server
        .stop_and_wait()
        .await
        .expect("normal completion server shutdown succeeds");
}

#[tokio::test]
async fn stalled_peer_stays_admitted_until_writer_settlement_then_allows_successor() {
    let server = start_test_server(
        "127.0.0.1",
        0,
        Limits {
            max_connections: 1,
            writer_stop_timeout_secs: 1,
            ..Limits::default()
        },
    )
    .await
    .unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let (mut w0, _) = connect_async(&url).await.unwrap();

    let refused = tokio::time::timeout(Duration::from_secs(2), connect_async(&url))
        .await
        .expect("successor admission should be decided within the configured bound");
    assert!(refused.is_err(), "W1 must be refused while W0 is admitted");

    // W0 ends its reader while the peer deliberately does not consume the
    // server's close frame. The server must settle and join W0's writer
    // before releasing the sole connection slot.
    w0.send(Message::Close(None)).await.unwrap();
    drop(w0);
    let hub_was_idle_before_registry_reap =
        tokio::time::timeout(Duration::from_secs(2), server.wait_for_registry_idle())
            .await
            .expect("W0 registry terminal observation should complete");
    assert!(
        hub_was_idle_before_registry_reap,
        "Hub admission must reach zero before W0 registry retirement"
    );
    assert_eq!(server.stats().connections, 0);

    let (w1, _) = connect_async(&url).await.unwrap();
    drop(w1);
    tokio::time::timeout(Duration::from_secs(2), server.wait_for_registry_idle())
        .await
        .expect("W1 registry terminal observation should complete");
    assert_eq!(server.stats().connections, 0);
    server
        .stop_and_wait()
        .await
        .expect("stalled peer server shutdown succeeds");
}

#[tokio::test]
async fn handshake_bytes_are_bounded_before_websocket_parser() {
    let limits = Limits {
        max_handshake_bytes: 64,
        ..Limits::default()
    };
    let server = start_test_server("127.0.0.1", 0, limits).await.unwrap();
    let mut stream = TcpStream::connect(server.local_addr()).await.unwrap();
    stream.write_all(b"GET / HTTP/1.1\r\nHost: ").await.unwrap();
    stream.write_all(&[b'x'; 128]).await.unwrap();
    let mut response = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut response))
        .await
        .expect("oversized handshake should be closed promptly");
    assert_eq!(server.stats().connections, 0);
    server
        .stop_and_wait()
        .await
        .expect("handshake bound server shutdown succeeds");
}

#[tokio::test]
async fn websocket_frame_and_message_limits_refuse_before_json_parse() {
    let limits = Limits {
        max_message_bytes: 32,
        max_frame_bytes: 32,
        ..Limits::default()
    };
    let server = start_test_server("127.0.0.1", 0, limits).await.unwrap();
    let url = format!("ws://127.0.0.1:{}", server.local_addr().port());
    let (mut ws, _) = connect_async(&url).await.unwrap();
    ws.send(Message::Text("x".repeat(128))).await.unwrap();
    let outcome = tokio::time::timeout(Duration::from_secs(2), ws.next())
        .await
        .expect("oversized message should produce a bounded protocol close");
    assert!(matches!(
        outcome,
        Some(Err(_)) | Some(Ok(Message::Close(_)))
    ));
    assert_eq!(server.stats().connections, 0);
    server
        .stop_and_wait()
        .await
        .expect("websocket limit server shutdown succeeds");
}
