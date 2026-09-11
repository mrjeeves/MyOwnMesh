use std::sync::Arc;

use super::state::{NetworkCmd, NetworkState};
use crate::resource::{
    resource_mailbox, FiniteResourceProvider, ProcessResourceRoot, ResourceMailboxSendError,
    ResourceMailboxSender, ResourceProviderPort,
};

fn connect_command(peer: &str) -> NetworkCmd {
    NetworkCmd::ConnectPeer {
        device_id: peer.to_string(),
        sticky: false,
        reply: None,
    }
}

#[tokio::test]
async fn connect_lane_pressure_is_lossless_and_terminally_releases() {
    let first = connect_command("peer-a");
    let scopes = FiniteResourceProvider::scope_record_charge_for_test()
        .checked_scale(2)
        .expect("process and local scope records fit");
    let root = FiniteResourceProvider::reservation_charge_for_test(
        ResourceMailboxSender::<NetworkCmd>::root_claim().expect("connection mailbox root fits"),
    )
    .expect("connection mailbox root reservation fits");
    // This helper already prices the payload and node as two reservations.
    let item = ResourceMailboxSender::<NetworkCmd>::accepted_item_charge_for_test(&first);
    let grant = scopes
        .checked_add(root)
        .and_then(|claim| claim.checked_add(item))
        .expect("connection lane fixture grant fits");
    let provider = FiniteResourceProvider::new(grant);
    let observed = provider.clone();
    let port = ResourceProviderPort::new(provider).expect("connection provider scope fits");
    let process = ProcessResourceRoot::isolated();
    process
        .install_local_application_provider(port)
        .expect("connection provider installs");
    let scope = process
        .issue_local_application_scope()
        .expect("connection local scope issues");
    let (sender, mut receiver) = resource_mailbox(scope).expect("connection mailbox is funded");
    let baseline = observed.in_use();

    sender
        .send(first)
        .map_err(|error| error.into_admission_error())
        .expect("first connection is funded");
    let occupied = observed.in_use();
    let refused = sender
        .send(connect_command("peer-b"))
        .expect_err("the second connection has no funded item claim");
    assert!(matches!(
        &refused,
        ResourceMailboxSendError::Pressure { .. }
    ));
    assert_eq!(
        observed.in_use(),
        occupied,
        "refusal has no accounting delta"
    );
    assert!(matches!(
        refused.into_value(),
        NetworkCmd::ConnectPeer { .. }
    ));

    let delivery = receiver.recv().await.expect("first connection is queued");
    delivery
        .run_terminal_effect(|command| async move {
            assert!(matches!(command, NetworkCmd::ConnectPeer { .. }));
        })
        .await;
    assert_eq!(
        observed.in_use(),
        baseline,
        "terminal delivery releases its claim"
    );
}

#[test]
fn connect_lane_is_one_parent_owned_actor_without_per_command_boxing() {
    let source = include_str!("supervisor.rs");
    assert!(source.contains("async fn run_connection_commands"));
    assert!(source.contains("tokio::pin!(connection_actor)"));
    assert!(!source.contains("Box<dyn Future"));
}

#[cfg(feature = "transport-lab")]
#[tokio::test]
async fn blocked_connect_lane_does_not_hold_main_command_lane_and_shutdown_drops_it() {
    let gate = super::supervisor::install_connection_command_gate_for_test();
    let (state, signaling_inbound, cmd_rx, _provider, _grant) =
        super::build_test_state_parts_metered("connection-lane-hol", None, 1, None);
    let driver = tokio::spawn(super::run_driver(state.clone(), signaling_inbound, cmd_rx));

    assert!(state
        .request_connect_peer("blocked-peer".to_string(), false, None)
        .is_ok());
    super::supervisor::wait_connection_command_gate_for_test(&gate).await;

    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    assert!(state
        .cmd_tx
        .send(NetworkCmd::SendChannelFrame {
            peer: "missing-peer".to_string(),
            channel: "control".to_string(),
            payload: serde_json::Value::Null,
            reply,
        })
        .is_ok());
    assert!(reply_rx
        .await
        .expect("main-lane command retains its terminal reply")
        .is_err());

    // The connection future remains parked while the unrelated command has
    // completed, proving the two lanes are independently making progress.
    // Leave the connection future parked while shutdown is requested. The
    // lexical actor owner must drop it before state.shutdown joins storage.
    state.request_shutdown();
    driver
        .await
        .expect("driver joins after connection cancellation");
    super::supervisor::release_connection_command_gate_for_test(&gate);
}

#[cfg(feature = "transport-lab")]
#[tokio::test]
async fn actor_reply_waiter_keeps_shared_funding_until_caller_terminal() {
    let gate = super::supervisor::install_connection_command_gate_for_test();
    let (state, signaling_inbound, cmd_rx, provider, _grant) =
        super::build_test_state_parts_metered("connect-wait-shared", None, 1, None);
    drop(
        state
            .take_signaling_outbound_rx()
            .expect("the test closes the undriven outbound signaling receiver"),
    );
    let baseline = provider.in_use();
    let baseline_reservations = provider.active_reservations();
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    let (registration, cancellation) =
        state.connect_waiter_registration_for_test("parked-peer", 1, reply);
    assert!(state
        .request_connect_peer("parked-peer".to_string(), false, Some(registration))
        .is_ok());
    let driver = tokio::spawn(super::run_driver(state.clone(), signaling_inbound, cmd_rx));
    super::supervisor::wait_connection_command_gate_for_test(&gate).await;
    // Refuse the connector at its existing provider boundary after the
    // mailbox has delivered the command. This leaves no unrelated connector
    // custody in the exact waiter accounting below.
    provider.script_pressure(crate::resource::ResourceClass::NativeTransportObject);
    super::supervisor::release_connection_command_gate_for_test(&gate);
    state.wait_for_connect_waiter_registration_for_test().await;
    assert_eq!(state.connect_waiter_count_for_test("parked-peer"), 1);
    state.wait_for_connect_waiter_terminal_for_test().await;

    let retained =
        super::state::NetworkState::connect_waiter_retained_claim_for_test("parked-peer");
    assert_eq!(provider.in_use(), baseline.checked_add(retained).unwrap());
    assert_eq!(
        provider.active_reservations(),
        baseline_reservations + 4,
        "actor terminal leaves exactly the shared, key, map, and queue reservations"
    );

    // Resolve the registry side while deliberately leaving the caller's
    // receiver and cancellation guard unpolled. The shared FundedArc must
    // remain charged after the registration is removed.
    state.resolve_connect_waiters("parked-peer", Some("control test"));
    let after_resolve = provider.in_use();
    let shared = super::state::NetworkState::connect_waiter_shared_claim_for_test("parked-peer");
    assert_eq!(
        after_resolve,
        baseline.checked_add(shared).unwrap(),
        "resolution drops registry ownership but keeps the parked caller's shared funding"
    );
    assert_eq!(provider.active_reservations(), baseline_reservations + 1);
    drop(reply_rx);
    drop(cancellation);
    assert_eq!(provider.in_use(), baseline);
    assert_eq!(provider.active_reservations(), baseline_reservations);
    state.request_shutdown();
    driver
        .await
        .expect("driver joins after shared waiter terminal cleanup");
    drop(state);
    assert!(provider.in_use().is_zero());
    assert_eq!(provider.active_reservations(), 0);
}

#[test]
fn connect_waiter_registry_claim_covers_every_retained_entry() {
    let (state, _signaling_inbound, _cmd_rx, provider, _grant) =
        super::build_test_state_parts_metered("connect-waiter-exact", None, 1, None);
    let baseline = provider.in_use();
    let baseline_reservations = provider.active_reservations();
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    let (registration, cancellation) =
        state.connect_waiter_registration_for_test("exact-peer", 1, reply);
    state.register_connect_waiter("exact-peer", registration);

    let expected = super::state::NetworkState::connect_waiter_retained_claim_for_test("exact-peer");
    assert_eq!(
        provider.in_use(),
        baseline
            .checked_add(expected)
            .expect("exact waiter claim fits the fixture"),
        "shared value, peer key, map node, and queue node are all funded"
    );
    assert_eq!(
        provider.active_reservations(),
        baseline_reservations + 4,
        "the four retained waiter allocations have distinct reservations"
    );
    assert_eq!(state.connect_waiter_count_for_test("exact-peer"), 1);

    state.resolve_connect_waiters("exact-peer", Some("exact-control"));
    drop(reply_rx);
    drop(cancellation);
    assert_eq!(provider.in_use(), baseline);
    assert_eq!(provider.active_reservations(), baseline_reservations);
}

#[cfg(feature = "transport-lab")]
#[tokio::test]
async fn connect_peer_wait_cancel_before_actor_terminal_releases_all_funding() {
    let gate = super::supervisor::install_connection_command_gate_for_test();
    let (state, signaling_inbound, cmd_rx, provider, _grant) =
        super::build_test_state_parts_metered("connect-wait-cancel", None, 1, None);
    drop(
        state
            .take_signaling_outbound_rx()
            .expect("the test closes the undriven outbound signaling receiver"),
    );
    let baseline = provider.in_use();
    let baseline_reservations = provider.active_reservations();
    let caller_state = state.clone();
    let caller = tokio::spawn(async move {
        caller_state
            .connect_peer_wait("cancelled-peer", false)
            .await
    });
    let driver = tokio::spawn(super::run_driver(state.clone(), signaling_inbound, cmd_rx));
    super::supervisor::wait_connection_command_gate_for_test(&gate).await;

    // The actor has consumed the command but is parked before registration.
    // Aborting the real public wait future must cancel its shared owner; the
    // actor then observes the cancellation and refuses registry insertion.
    caller.abort();
    let _ = caller.await;
    provider.script_pressure(crate::resource::ResourceClass::NativeTransportObject);
    super::supervisor::release_connection_command_gate_for_test(&gate);
    state.wait_for_connect_waiter_terminal_for_test().await;
    assert_eq!(state.connect_waiter_count_for_test("cancelled-peer"), 0);
    assert_eq!(provider.in_use(), baseline);
    assert_eq!(provider.active_reservations(), baseline_reservations);
    state.request_shutdown();
    driver
        .await
        .expect("driver joins after cancelled connect waiter");
    drop(state);
    assert!(provider.in_use().is_zero());
    assert_eq!(provider.active_reservations(), 0);
}

#[test]
fn connect_waiter_provider_refusal_keeps_existing_registry_unchanged() {
    let (state, _signaling_inbound, _cmd_rx, provider, _grant) =
        super::build_test_state_parts_metered("connect-waiter-pressure", None, 1, None);
    let baseline = provider.in_use();
    let (reply_a, reply_a_rx) = tokio::sync::oneshot::channel();
    let (registration_a, cancellation_a) =
        state.connect_waiter_registration_for_test("pressure-peer", 1, reply_a);
    state.register_connect_waiter("pressure-peer", registration_a);
    let (reply_b, reply_b_rx) = tokio::sync::oneshot::channel();
    let (registration_b, cancellation_b) =
        state.connect_waiter_registration_for_test("pressure-peer", 2, reply_b);
    let (reply_c, reply_c_rx) = tokio::sync::oneshot::channel();
    let (registration_c, cancellation_c) =
        state.connect_waiter_registration_for_test("pressure-peer-2", 3, reply_c);
    let before_refusal = provider.in_use();
    provider.script_pressure(crate::resource::ResourceClass::AccountedMemoryBytes);
    state.register_connect_waiter("pressure-peer", registration_b);
    assert_eq!(
        state.connect_waiter_count_for_test("pressure-peer"),
        1,
        "provider refusal does not disturb the admitted peer bucket"
    );
    assert_eq!(provider.in_use(), before_refusal);
    provider.script_pressure(crate::resource::ResourceClass::AccountedMemoryBytes);
    state.register_connect_waiter("pressure-peer-2", registration_c);
    assert_eq!(state.connect_waiter_count_for_test("pressure-peer-2"), 0);
    assert_eq!(provider.in_use(), before_refusal);
    drop(reply_b_rx);
    drop(cancellation_b);
    drop(reply_c_rx);
    drop(cancellation_c);
    state.resolve_connect_waiters("pressure-peer", Some("pressure-control"));
    drop(reply_a_rx);
    drop(cancellation_a);
    assert_eq!(provider.in_use(), baseline);
}

#[tokio::test]
async fn connect_waiter_shutdown_sends_terminal_error_and_releases_funding() {
    let (state, signaling_inbound, cmd_rx, provider, _grant) =
        super::build_test_state_parts_metered("connect-waiter-shutdown", None, 1, None);
    let (reply, reply_rx) = tokio::sync::oneshot::channel();
    let (registration, cancellation) =
        state.connect_waiter_registration_for_test("shutdown-peer", 1, reply);
    state.register_connect_waiter("shutdown-peer", registration);
    state.shutdown().await;
    assert!(
        matches!(reply_rx.await, Ok(Err(_))),
        "shutdown resolves an unserved waiter with a terminal error"
    );
    drop(cancellation);
    drop(signaling_inbound);
    drop(cmd_rx);
    drop(state);
    assert!(provider.in_use().is_zero());
    assert_eq!(provider.active_reservations(), 0);
}

#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum B2Stage {
    DataChannelOpen,
    AuthStarted,
    PeerProofAccepted,
    PromotionQueued,
    MediaOfferApplied,
    MediaAnswerApplied,
    MediaOfferSent,
}

#[cfg(all(test, feature = "transport-lab"))]
#[derive(Clone, Debug)]
struct B2StageEvent {
    local_device_id: String,
    correlation: String,
    stage: B2Stage,
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) struct B2StageProbe {
    events: parking_lot::Mutex<Vec<B2StageEvent>>,
    wake: tokio::sync::Notify,
}

#[cfg(all(test, feature = "transport-lab"))]
impl B2StageProbe {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(Self {
            events: parking_lot::Mutex::new(Vec::new()),
            wake: tokio::sync::Notify::new(),
        })
    }

    fn record(&self, event: B2StageEvent) {
        eprintln!(
            "B2_STAGE local={} correlation={} stage={:?}",
            event.local_device_id, event.correlation, event.stage
        );
        tracing::info!(
            target: "b2_stage",
            local_device = %event.local_device_id,
            correlation = %event.correlation,
            stage = ?event.stage,
            "B2 speculative handoff stage"
        );
        self.events.lock().push(event);
        self.wake.notify_waiters();
    }

    pub(crate) async fn wait_for(&self, local_device_id: &str, correlation: &str, stage: B2Stage) {
        loop {
            let notified = self.wake.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if self.events.lock().iter().any(|event| {
                event.local_device_id == local_device_id
                    && event.correlation == correlation
                    && event.stage == stage
            }) {
                return;
            }
            notified.await;
        }
    }
}

#[cfg(all(test, feature = "transport-lab"))]
static B2_STAGE_PROBE: std::sync::OnceLock<parking_lot::Mutex<Option<Arc<B2StageProbe>>>> =
    std::sync::OnceLock::new();

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn install_b2_stage_probe(probe: Arc<B2StageProbe>) {
    *B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = Some(probe);
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn clear_b2_stage_probe() {
    *B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock() = None;
}

#[cfg(all(test, feature = "transport-lab"))]
pub(crate) fn record_b2_stage(state: &Arc<NetworkState>, correlation: &str, stage: B2Stage) {
    if let Some(probe) = B2_STAGE_PROBE
        .get_or_init(|| parking_lot::Mutex::new(None))
        .lock()
        .clone()
    {
        probe.record(B2StageEvent {
            local_device_id: state.identity.public_id().to_string(),
            correlation: correlation.to_string(),
            stage,
        });
    }
}
