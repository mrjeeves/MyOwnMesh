//! Dedicated multi-relay delivery controls.

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use futures_util::{SinkExt, Stream, StreamExt};
use serde_json::{json, Value};
use tokio::sync::{mpsc, Notify};
use tokio_tungstenite::connect_async;
use tokio_tungstenite::tungstenite::{Error as WsError, Message};

use myownmesh_signaling::nostr::delivery::{
    AdmissionRefusal, AdmissionSource, DeliveryLease, DeliveryProvider, DeliveryRefusal,
    DeliveryRetention, DeliveryStore, DeliveryTerminal, RelaySessionId, SessionRetention,
};
use myownmesh_signaling::nostr::driver::{
    derive_task_custody_plan, start_with_delivery_provider_and_sinks_with_custodian,
    NostrDriverConfig, NostrInbound, NostrOutbound, NostrTaskCustodyOwners, NostrTimingConfig,
};
use myownmesh_signaling::nostr::handle::derive_room_handle;
use myownmesh_signaling::nostr::shuffle::select_top_n;
use myownmesh_signaling::server::{Limits, SignalingServer};
use myownmesh_signaling::{
    AttemptOutcome, AttemptOutcomeSink, AttemptRefusal, AttemptRefusalSink, DedicatedTaskCustodian,
    ErasedOwner, InboundSink, OwnedSignal, TaskCustodian, UnboundedSource,
};

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

struct NoopAttemptRefusalSink;

impl AttemptRefusalSink for NoopAttemptRefusalSink {
    fn refused(&self, _refusal: AttemptRefusal) {}
}

struct NoopAttemptOutcomeSink;

impl AttemptOutcomeSink for NoopAttemptOutcomeSink {
    fn outcome(&self, _outcome: AttemptOutcome) {}
}

fn test_nostr_timing() -> NostrTimingConfig {
    NostrTimingConfig {
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
    let selected = select_top_n(&config.app_id, &pool, config.redundancy);
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
    inbound: InboundSink<NostrInbound>,
    provider: Arc<dyn DeliveryProvider>,
) -> Result<myownmesh_signaling::nostr::driver::NostrDriverHandle, myownmesh_signaling::Error>
where
    S: myownmesh_signaling::OutboundSource<NostrOutbound> + Send + 'static,
    S::Owner: Sync + 'static,
{
    let (custodian_owner, reaper_custodian_owner) = test_task_custodians(&config);
    start_with_delivery_provider_and_sinks_with_custodian(
        config,
        outbound,
        inbound,
        provider,
        Arc::new(NoopAttemptRefusalSink),
        Arc::new(NoopAttemptOutcomeSink),
        NostrTaskCustodyOwners {
            primary: custodian_owner,
            reaper: reaper_custodian_owner,
        },
    )
}

fn open_test_session(store: &DeliveryStore) -> (RelaySessionId, Vec<AttemptRefusal>) {
    let (session, session_refusal, refused) = store.open_session_with_refusals();
    assert!(
        session_refusal.is_none(),
        "test session admission must succeed"
    );
    (session, refused)
}

struct DeliveryStats {
    refuse_first_session: AtomicBool,
    refused: AtomicUsize,
    accepted: AtomicUsize,
    finished: AtomicUsize,
    accepted_terminal: AtomicUsize,
    cancelled: AtomicUsize,
    shutdown: AtomicUsize,
}

struct CountingProvider {
    stats: Arc<DeliveryStats>,
    source_live: Arc<AtomicUsize>,
}

struct CountingLease {
    stats: Arc<DeliveryStats>,
}

struct NoopLease;

struct SourceLease {
    live: Arc<AtomicUsize>,
}

struct AccountingProvider {
    live: Arc<AtomicUsize>,
    refuse_relays: Arc<AtomicBool>,
}

struct AlwaysRefuseSessionProvider {
    refusals: Arc<AtomicUsize>,
    refused: Arc<Notify>,
}

struct AccountingLease {
    live: Arc<AtomicUsize>,
}

impl AccountingProvider {
    fn lease(&self) -> Box<dyn DeliveryLease> {
        self.live.fetch_add(1, Ordering::SeqCst);
        Box::new(AccountingLease {
            live: Arc::clone(&self.live),
        })
    }
}

impl AlwaysRefuseSessionProvider {
    fn new() -> Self {
        Self {
            refusals: Arc::new(AtomicUsize::new(0)),
            refused: Arc::new(Notify::new()),
        }
    }

    fn refuse_session(&self) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.refusals.fetch_add(1, Ordering::SeqCst);
        self.refused.notify_one();
        Err(DeliveryRefusal::Provider("session custody refused".into()))
    }
}

impl DeliveryLease for NoopLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {}
}

impl DeliveryLease for SourceLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl DeliveryLease for AccountingLease {
    fn finish(self: Box<Self>, _terminal: DeliveryTerminal) {
        self.live.fetch_sub(1, Ordering::SeqCst);
    }
}

impl DeliveryLease for CountingLease {
    fn finish(self: Box<Self>, terminal: DeliveryTerminal) {
        self.stats.finished.fetch_add(1, Ordering::SeqCst);
        match terminal {
            DeliveryTerminal::Accepted => {
                self.stats.accepted_terminal.fetch_add(1, Ordering::SeqCst);
            }
            DeliveryTerminal::Cancelled => {
                self.stats.cancelled.fetch_add(1, Ordering::SeqCst);
            }
            DeliveryTerminal::Shutdown => {
                self.stats.shutdown.fetch_add(1, Ordering::SeqCst);
            }
            _ => {}
        }
    }
}

macro_rules! noop_inbound_and_correlation {
    () => {
        fn reserve_inbound_frame(
            &self,
            _frame_bytes: usize,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(Box::new(NoopLease))
        }

        fn reserve_attempt_correlation(
            &self,
            _attempt: &str,
            _event: &myownmesh_signaling::nostr::event::NostrEvent,
            _retention: DeliveryRetention,
        ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
            Ok(Box::new(NoopLease))
        }
    };
}

impl DeliveryProvider for AccountingProvider {
    fn reserve_inbound_frame(
        &self,
        _frame_bytes: usize,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_attempt_correlation(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_admission_source(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_session_identity(
        &self,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(self.lease())
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        if self.refuse_relays.load(Ordering::SeqCst) {
            Err(DeliveryRefusal::Provider("remote pressure".into()))
        } else {
            Ok(self.lease())
        }
    }
}

impl DeliveryProvider for AlwaysRefuseSessionProvider {
    noop_inbound_and_correlation!();

    fn reserve_admission_source(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_identity(
        &self,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.refuse_session()
    }

    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }
}

impl DeliveryProvider for CountingProvider {
    noop_inbound_and_correlation!();
    fn reserve_admission_source(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        self.source_live.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(SourceLease {
            live: Arc::clone(&self.source_live),
        }))
    }

    fn reserve_session_identity(
        &self,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_record(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_set_node(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_session_entry(
        &self,
        _session: RelaySessionId,
        _retention: SessionRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_record(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_key(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_attempt_entry(
        &self,
        _attempt: &str,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve_relay_entry(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        Ok(Box::new(NoopLease))
    }

    fn reserve(
        &self,
        _attempt: &str,
        _session: RelaySessionId,
        _event: &myownmesh_signaling::nostr::event::NostrEvent,
        _retention: DeliveryRetention,
    ) -> Result<Box<dyn DeliveryLease>, DeliveryRefusal> {
        if self
            .stats
            .refuse_first_session
            .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            self.stats.refused.fetch_add(1, Ordering::SeqCst);
            return Err(DeliveryRefusal::Provider("dedicated refusal".into()));
        }
        self.stats.accepted.fetch_add(1, Ordering::SeqCst);
        Ok(Box::new(CountingLease {
            stats: Arc::clone(&self.stats),
        }))
    }
}

async fn next_text(ws: &mut (impl Stream<Item = Result<Message, WsError>> + Unpin)) -> String {
    loop {
        let msg = tokio::time::timeout(Duration::from_secs(10), ws.next())
            .await
            .expect("relay frame timed out")
            .expect("relay closed unexpectedly")
            .expect("relay frame is valid");
        if let Message::Text(text) = msg {
            return text.to_string();
        }
    }
}

fn parse(frame: &str) -> Vec<Value> {
    serde_json::from_str(frame).expect("relay frame is a JSON array")
}

#[test]
fn inbound_frame_admission_is_funded_and_released_exactly() {
    let live = Arc::new(AtomicUsize::new(0));
    let provider = AccountingProvider {
        live: live.clone(),
        refuse_relays: Arc::new(AtomicBool::new(false)),
    };
    let store = DeliveryStore::new(Arc::new(provider));

    let lease = store
        .reserve_inbound_frame(4 * 1024)
        .expect("provider admits the bounded parse frame");
    assert_eq!(live.load(Ordering::SeqCst), 1);
    lease.finish(DeliveryTerminal::AttemptCompleted);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn closed_store_refuses_new_reservations_before_provider_admission() {
    let live = Arc::new(AtomicUsize::new(0));
    let provider = AccountingProvider {
        live: live.clone(),
        refuse_relays: Arc::new(AtomicBool::new(false)),
    };
    let store = DeliveryStore::new(Arc::new(provider));

    assert_eq!(store.shutdown(), 0);
    assert!(matches!(
        store.reserve_inbound_frame(4 * 1024),
        Err(DeliveryRefusal::Provider(reason)) if reason == "delivery store is closed"
    ));
    let (_, session_refusal, refusals) = store.open_session_with_refusals();
    assert!(matches!(
        session_refusal,
        Some(DeliveryRefusal::Provider(reason)) if reason == "delivery store is closed"
    ));
    assert!(refusals.is_empty());
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        1077,
        Vec::new(),
        String::new(),
        1,
    );
    let report = store.admit(
        "closed-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert!(matches!(
        report.attempt_refusal,
        Some(AdmissionRefusal::Provider(DeliveryRefusal::Provider(reason)))
            if reason == "delivery store is closed"
    ));
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

async fn subscribe(
    url: &str,
    subscription: &str,
    room: &str,
    kinds: &[u16],
) -> impl Stream<Item = Result<Message, WsError>> + Unpin {
    let (mut socket, _) = connect_async(url).await.expect("subscriber connects");
    socket
        .send(Message::Text(
            json!(["REQ", subscription, {"kinds": kinds, "#r": [room]}]).to_string(),
        ))
        .await
        .expect("subscriber sends REQ");
    socket
}

async fn next_event_kind(
    ws: &mut (impl Stream<Item = Result<Message, WsError>> + Unpin),
    kind: u64,
) -> Vec<Value> {
    loop {
        let frame = parse(&next_text(ws).await);
        if frame[0] == "EVENT" && frame[2]["kind"] == kind {
            return frame;
        }
    }
}

#[tokio::test]
async fn two_relays_replay_presence_but_never_replay_departure() {
    let relay_a = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .expect("relay A starts");
    let relay_b = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .expect("relay B starts");
    let url_a = format!("ws://127.0.0.1:{}", relay_a.local_addr().port());
    let url_b = format!("ws://127.0.0.1:{}", relay_b.local_addr().port());
    let room = derive_room_handle("nostr-delivery-controls", "relay-separation");

    let (out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx, _in_rx) = mpsc::unbounded_channel::<NostrInbound>();
    let stats = Arc::new(DeliveryStats {
        refuse_first_session: AtomicBool::new(true),
        refused: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        accepted_terminal: AtomicUsize::new(0),
        cancelled: AtomicUsize::new(0),
        shutdown: AtomicUsize::new(0),
    });
    let config = NostrDriverConfig {
        app_id: "nostr-delivery-controls".into(),
        network_id: "relay-separation".into(),
        device_id: "device-a".into(),
        servers: vec![url_a.clone(), url_b.clone()],
        denylist: Vec::new(),
        redundancy: 2,
        public_fallback: false,
        timing: test_nostr_timing(),
    };
    let driver = start_test_driver(
        config,
        Box::new(UnboundedSource::new(out_rx)),
        InboundSink::from_unbounded(in_tx),
        Arc::new(CountingProvider {
            stats: Arc::clone(&stats),
            source_live: Arc::new(AtomicUsize::new(0)),
        }),
    )
    .expect("valid Nostr timing and task-custody configuration");
    let reconnect = driver.reconnect_signal();
    let mut reconnect_seen = reconnect.subscribe();
    let previous_generation = *reconnect_seen.borrow();
    reconnect.send_modify(|generation| *generation = generation.wrapping_add(1));
    reconnect_seen
        .changed()
        .await
        .expect("reconnect generation remains live");
    assert_ne!(*reconnect_seen.borrow(), previous_generation);
    let mut sub_a = subscribe(&url_a, "sub-a", &room, &[1077, 21077]).await;
    let mut sub_b = subscribe(&url_b, "sub-b", &room, &[1077, 21077]).await;
    for sub in [&mut sub_a, &mut sub_b] {
        loop {
            let event = parse(&next_text(sub).await);
            if event[0] == "EVENT" {
                assert_eq!(event[2]["kind"], 1077, "presence is stored on both relays");
                break;
            }
            assert_eq!(event[0], "EOSE", "only replay completion precedes presence");
        }
    }

    out_tx
        .send(NostrOutbound::DirectedToPeer {
            to: "device-b".into(),
            msg: myownmesh_signaling::SignalingMessage::Offer {
                peer_id: "device-b".into(),
                offer_id: "attempt-a".into(),
                sdp: "v=0".into(),
            },
        })
        .expect("queue directed delivery");
    let directed = tokio::select! {
        frame = next_event_kind(&mut sub_a, 21077) => frame,
        frame = next_event_kind(&mut sub_b, 21077) => frame,
    };
    assert_eq!(directed[0], "EVENT");
    assert_eq!(stats.refused.load(Ordering::SeqCst), 1);
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);

    stats.refuse_first_session.store(false, Ordering::SeqCst);
    out_tx.send(NostrOutbound::Leave).expect("queue departure");
    for sub in [&mut sub_a, &mut sub_b] {
        let event = parse(&next_text(sub).await);
        assert_eq!(event[0], "EVENT");
        assert_eq!(event[2]["kind"], 21077, "departure is live on both relays");
        let content: Value = serde_json::from_str(event[2]["content"].as_str().unwrap())
            .expect("departure content is JSON");
        assert_eq!(content["kind"], "leave");
    }

    // A late subscriber asks only for ephemeral negotiation. EOSE is the
    // decisive boundary: the live departure was delivered, but not retained.
    let mut late = subscribe(&url_a, "late", &room, &[21077]).await;
    assert_eq!(parse(&next_text(&mut late).await)[0], "EOSE");

    driver.stop_and_join().await;
    drop(out_tx);
    assert!(stats.finished.load(Ordering::SeqCst) > 0);
    relay_a
        .stop_and_wait()
        .await
        .expect("primary relay shutdown succeeds");
    relay_b
        .stop_and_wait()
        .await
        .expect("secondary relay shutdown succeeds");
}

#[tokio::test]
async fn session_provider_refusal_is_backoff_bounded_and_shutdown_is_prompt() {
    let relay = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .expect("relay starts");
    let url = format!("ws://127.0.0.1:{}", relay.local_addr().port());
    let provider = Arc::new(AlwaysRefuseSessionProvider::new());
    let first_refusal = provider.refused.notified();
    let (out_tx, out_rx) = mpsc::unbounded_channel::<NostrOutbound>();
    let (in_tx, _in_rx) = mpsc::unbounded_channel::<NostrInbound>();
    let config = NostrDriverConfig {
        app_id: "nostr-session-refusal-control".into(),
        network_id: "session-refusal-control".into(),
        device_id: "device-refusal".into(),
        servers: vec![url],
        denylist: Vec::new(),
        redundancy: 1,
        public_fallback: false,
        timing: test_nostr_timing(),
    };
    let driver = start_test_driver(
        config,
        Box::new(UnboundedSource::new(out_rx)),
        InboundSink::from_unbounded(in_tx),
        provider.clone(),
    )
    .expect("valid Nostr timing and task-custody configuration");

    tokio::time::timeout(Duration::from_secs(10), first_refusal)
        .await
        .expect("first session provider refusal is observed");
    let second_refusal = provider.refused.notified();
    let immediate_retry = tokio::time::timeout(Duration::from_secs(1), second_refusal).await;

    tokio::time::timeout(Duration::from_secs(2), driver.stop_and_join())
        .await
        .expect("driver shutdown remains prompt after refusal");
    drop(out_tx);
    tokio::time::timeout(Duration::from_secs(2), relay.stop_and_wait())
        .await
        .expect("relay shutdown remains prompt after refusal")
        .expect("relay shutdown completes after refusal");

    assert!(
        immediate_retry.is_err(),
        "session refusal must enter reconnect backoff rather than spin"
    );
    assert_eq!(
        provider.refusals.load(Ordering::SeqCst),
        1,
        "no second session admission occurs during the bounded backoff window"
    );
}

#[tokio::test]
async fn relay_returns_exact_nip01_ok_for_accepted_event() {
    use myownmesh_signaling::nostr::event::{make_event, NostrIdentity};

    let relay = start_test_server("127.0.0.1", 0, Limits::default())
        .await
        .expect("relay starts");
    let url = format!("ws://127.0.0.1:{}", relay.local_addr().port());
    let (mut publisher, _) = connect_async(url).await.expect("publisher connects");
    let event = make_event(
        &NostrIdentity::generate(),
        1077,
        vec![vec!["r".into(), "ok-room".into()]],
        "ok".into(),
        1,
    );
    let id = event.id.clone();
    publisher
        .send(Message::Text(json!(["EVENT", event]).to_string()))
        .await
        .expect("publisher sends event");
    let ok = parse(&next_text(&mut publisher).await);
    assert_eq!(ok.len(), 4);
    assert_eq!(ok[0], "OK");
    assert_eq!(ok[1], id);
    assert_eq!(ok[2], true);
    assert!(ok[3].is_string());
    relay
        .stop_and_wait()
        .await
        .expect("refusal-control relay shutdown succeeds");
}

#[test]
fn old_relay_session_cannot_settle_a_reconnected_attempt() {
    let stats = Arc::new(DeliveryStats {
        refuse_first_session: AtomicBool::new(false),
        refused: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        accepted_terminal: AtomicUsize::new(0),
        cancelled: AtomicUsize::new(0),
        shutdown: AtomicUsize::new(0),
    });
    let store = DeliveryStore::new(Arc::new(CountingProvider {
        stats: Arc::clone(&stats),
        source_live: Arc::new(AtomicUsize::new(0)),
    }));
    let (old, _) = open_test_session(&store);
    let (other, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "attempt".into(),
        1,
    );
    let id = event.id.clone();
    let report = store.admit(
        "attempt-aba".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_eq!(report.accepted_sessions, 2);
    assert!(report.refused.is_empty());
    assert!(store.settle(&old, &id, DeliveryTerminal::Accepted));
    store.close_session(other, DeliveryTerminal::Cancelled);
    let (fresh, _) = open_test_session(&store);
    assert_eq!(store.next_pending(&fresh), Some(id.clone()));
    assert!(!store.settle(&old, &id, DeliveryTerminal::Accepted));
    assert_eq!(
        store.finish_attempt("attempt-aba", DeliveryTerminal::Shutdown),
        1
    );
    assert_eq!(stats.finished.load(Ordering::SeqCst), 3);
    assert_eq!(stats.accepted_terminal.load(Ordering::SeqCst), 1);
    assert_eq!(stats.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(stats.shutdown.load(Ordering::SeqCst), 1);
}

#[test]
fn partial_refusal_has_one_live_entry_and_exact_cancel_terminal() {
    let stats = Arc::new(DeliveryStats {
        refuse_first_session: AtomicBool::new(true),
        refused: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        accepted_terminal: AtomicUsize::new(0),
        cancelled: AtomicUsize::new(0),
        shutdown: AtomicUsize::new(0),
    });
    let store = DeliveryStore::new(Arc::new(CountingProvider {
        stats: Arc::clone(&stats),
        source_live: Arc::new(AtomicUsize::new(0)),
    }));
    let (first, _) = open_test_session(&store);
    let (second, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "partial-refusal".into(),
        1,
    );
    let report = store.admit(
        "attempt-partial".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_eq!(report.accepted_sessions, 1);
    assert_eq!(report.refused.len(), 1);
    assert_eq!(stats.refused.load(Ordering::SeqCst), 1);
    assert_eq!(stats.accepted.load(Ordering::SeqCst), 1);
    let accepted_session = if report.refused[0].0 == first {
        &second
    } else {
        &first
    };
    let refused_session = &report.refused[0].0;
    assert!(store.next_pending(accepted_session).is_some());
    assert!(store.next_pending(refused_session).is_none());
    assert_eq!(
        store.finish_attempt("attempt-partial", DeliveryTerminal::Cancelled),
        1
    );
    assert_eq!(stats.cancelled.load(Ordering::SeqCst), 1);
    assert_eq!(stats.finished.load(Ordering::SeqCst), 1);
}

#[test]
fn identical_live_event_same_attempt_is_source_scoped() {
    let stats = Arc::new(DeliveryStats {
        refuse_first_session: AtomicBool::new(false),
        refused: AtomicUsize::new(0),
        accepted: AtomicUsize::new(0),
        finished: AtomicUsize::new(0),
        accepted_terminal: AtomicUsize::new(0),
        cancelled: AtomicUsize::new(0),
        shutdown: AtomicUsize::new(0),
    });
    let source_live = Arc::new(AtomicUsize::new(0));
    let store = DeliveryStore::new(Arc::new(CountingProvider {
        stats: Arc::clone(&stats),
        source_live: Arc::clone(&source_live),
    }));
    let (session, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "same-attempt".into(),
        1,
    );
    let event_id = event.id.clone();
    let first = store.admit(
        "same-attempt".into(),
        OwnedSignal::new(event.clone(), Box::new(()) as ErasedOwner),
    );
    assert_eq!(source_live.load(Ordering::SeqCst), 1);
    let second = store.admit(
        "same-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_ne!(first.source, second.source);
    assert_eq!(
        second.attempt_refusal,
        Some(AdmissionRefusal::DuplicateLiveEvent)
    );
    assert_eq!(
        source_live.load(Ordering::SeqCst),
        1,
        "duplicate source custody is released immediately"
    );
    assert_eq!(store.next_pending(&session), Some(event_id.clone()));
    assert!(!store.settle_source(
        second.source,
        &session,
        &event_id,
        DeliveryTerminal::Accepted,
    ));
    assert!(store.settle_source(
        first.source,
        &session,
        &event_id,
        DeliveryTerminal::Accepted,
    ));
    assert_eq!(stats.accepted_terminal.load(Ordering::SeqCst), 1);
    assert_eq!(source_live.load(Ordering::SeqCst), 0);
    assert!(!store.settle_source(
        AdmissionSource::Unavailable,
        &session,
        &event_id,
        DeliveryTerminal::Accepted,
    ));
}

#[test]
fn relay_selection_and_reconnect_generation_are_explicit_controls() {
    let pool = ["wss://a.example", "wss://b.example", "wss://c.example"];
    let selected = select_top_n("delivery-controls", &pool, 2);
    assert_eq!(
        selected.len(),
        2,
        "redundancy selects exactly the requested top-N"
    );
    assert_eq!(select_top_n("delivery-controls", &pool, 0).len(), 0);

    let room_a = derive_room_handle("delivery-controls", "session-a");
    let room_b = derive_room_handle("delivery-controls", "session-b");
    assert_ne!(
        room_a, room_b,
        "a successor network cannot reuse the old room ABA"
    );
}

#[test]
fn remote_pressure_refusal_releases_all_attempt_custody() {
    let live = Arc::new(AtomicUsize::new(0));
    let refuse_relays = Arc::new(AtomicBool::new(true));
    let store = DeliveryStore::new(Arc::new(AccountingProvider {
        live: Arc::clone(&live),
        refuse_relays: Arc::clone(&refuse_relays),
    }));
    let (session, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "pressure-refusal".into(),
        1,
    );
    let report = store.admit(
        "pressure-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );

    assert_eq!(report.accepted_sessions, 0);
    assert_eq!(report.refused.len(), 1);
    assert!(report.attempt_refusal.is_some());
    assert!(store.next_pending(&session).is_none());
    assert!(
        live.load(Ordering::SeqCst) > 0,
        "the live attempt is retryable"
    );
    assert_eq!(
        store.finish_attempt("pressure-attempt", DeliveryTerminal::Cancelled),
        0
    );
    store.close_session(session, DeliveryTerminal::Shutdown);
    assert_eq!(
        live.load(Ordering::SeqCst),
        0,
        "a refused remote emission leaves no provider-owned attacker work"
    );
}

#[test]
fn refused_emission_reconnects_and_drains_after_pressure_clears() {
    let live = Arc::new(AtomicUsize::new(0));
    let refuse_relays = Arc::new(AtomicBool::new(true));
    let store = DeliveryStore::new(Arc::new(AccountingProvider {
        live: Arc::clone(&live),
        refuse_relays: Arc::clone(&refuse_relays),
    }));
    let (old, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "retry-after-pressure".into(),
        2,
    );
    let event_id = event.id.clone();
    let report = store.admit(
        "retry-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_eq!(report.accepted_sessions, 0);
    store.close_session(old, DeliveryTerminal::Cancelled);
    refuse_relays.store(false, Ordering::SeqCst);

    let (fresh, refusals) = open_test_session(&store);
    assert!(refusals.is_empty());
    assert_eq!(store.next_pending(&fresh), Some(event_id.clone()));
    assert!(store.settle(&fresh, &event_id, DeliveryTerminal::Accepted));
    store.close_session(fresh, DeliveryTerminal::Shutdown);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn last_carrier_copy_releases_provider_custody_exactly_once() {
    let live = Arc::new(AtomicUsize::new(0));
    let store = DeliveryStore::new(Arc::new(AccountingProvider {
        live: Arc::clone(&live),
        refuse_relays: Arc::new(AtomicBool::new(false)),
    }));
    let (first, _) = open_test_session(&store);
    let (second, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "last-copy".into(),
        3,
    );
    let event_id = event.id.clone();
    let report = store.admit(
        "last-copy-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_eq!(report.accepted_sessions, 2);
    assert!(store.settle(&first, &event_id, DeliveryTerminal::Accepted));
    assert!(
        live.load(Ordering::SeqCst) > 0,
        "the second relay still owns a copy"
    );
    assert!(store.settle(&second, &event_id, DeliveryTerminal::Accepted));
    store.close_session(first, DeliveryTerminal::Shutdown);
    store.close_session(second, DeliveryTerminal::Shutdown);
    assert_eq!(live.load(Ordering::SeqCst), 0);
}

#[test]
fn source_closure_cancels_pending_attempt_and_releases_custody() {
    let live = Arc::new(AtomicUsize::new(0));
    let store = DeliveryStore::new(Arc::new(AccountingProvider {
        live: Arc::clone(&live),
        refuse_relays: Arc::new(AtomicBool::new(false)),
    }));
    let (session, _) = open_test_session(&store);
    let event = myownmesh_signaling::nostr::event::make_event(
        &myownmesh_signaling::nostr::event::NostrIdentity::generate(),
        21077,
        Vec::new(),
        "source-closure".into(),
        4,
    );
    let event_id = event.id.clone();
    let report = store.admit(
        "source-closure-attempt".into(),
        OwnedSignal::new(event, Box::new(()) as ErasedOwner),
    );
    assert_eq!(report.accepted_sessions, 1);
    assert_eq!(store.next_pending(&session), Some(event_id));
    assert!(live.load(Ordering::SeqCst) > 0);

    assert_eq!(
        store.shutdown(),
        1,
        "source closure cancels the live carrier"
    );
    assert_eq!(live.load(Ordering::SeqCst), 0);
}
