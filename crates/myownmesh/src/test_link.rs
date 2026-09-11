//! One real two-peer link, for every daemon family that needs one.
//!
//! Nothing here is a stand-in: two engines are spawned, attached to one
//! [`LocalBroker`], and awaited until each has genuinely approved the other, so
//! a control built on this is exercising the same handshake, the same
//! dispatcher pair and the same connector budget production uses.
//!
//! **It lives at the crate root because two families need the same link, not
//! because it is general.** It was `ipc::bridge`'s private fixture, and the
//! second caller — the control dispatcher's streaming tests — needs a link
//! indistinguishable from the one the bridge controls run on. Copying it would
//! have produced two fixtures free to drift apart while both claimed to be "a
//! real two-peer link", and the drift would show up as a control passing
//! against a link its sibling no longer builds. So it moved rather than
//! multiplied, and `ipc::bridge` now calls exactly what it used to define.
//!
//! `#[cfg(test)]` and `pub(crate)`: it is reachable from any test in this
//! binary and from nothing else. No production path can name it, and no
//! production build contains it.
//!
//! **Serialization is not here and must not be added here.** Every caller takes
//! [`crate::exclusive_connector_fixture`] first, because building a `Transport`
//! at all draws on the one process-global connector budget that `embedded`,
//! `registry` and the bridge families all share. A mutex local to this module
//! would only stop this module's callers racing each other, which was never the
//! problem.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SchedulerPolicyConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::transport_lab::{attach_local, spawn_network};
use myownmesh_core::events::{MeshEvent, PeerEvent};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackPolicy, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn log_resource_ledger(phase: &str, wire_id: &str) {
    eprintln!(
        "two-peer ledger phase={phase} wire={wire_id} in_use={:?}",
        crate::test_resource_pair().1.in_use()
    );
}

/// The two engines' driver tasks, and the shutdown that really ends them.
pub(crate) struct TwoPeerDrivers {
    alice: Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    bob: Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    drivers: Vec<tokio::task::JoinHandle<()>>,
}

impl TwoPeerDrivers {
    pub(crate) async fn shutdown(self) {
        // The owner-held coalesced signal, not a queued command: it sets the
        // flag, wakes the waiters and closes both queues itself, so it
        // cannot be dropped or outranked by payload traffic the way a
        // command competing in the same mailbox could be.
        let _ = self.shutdown_with_report().await;
    }

    /// Shut down every owned driver and retain the first join failure for a
    /// setup error to report alongside its primary cause.  The loop remains
    /// exhaustive: one failed join never discards the other owned handle.
    async fn shutdown_with_report(mut self) -> Option<String> {
        self.alice.request_shutdown();
        self.bob.request_shutdown();
        let mut first_error = None;
        while let Some(driver) = self.drivers.pop() {
            if let Err(error) = driver.await {
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
        first_error
    }
}

impl Drop for TwoPeerDrivers {
    fn drop(&mut self) {
        // Idempotent by construction, so the explicit `shutdown` above and
        // this backstop can both run: the flag is a store and the queue
        // closes are already-closed no-ops on the second call.
        self.alice.request_shutdown();
        self.bob.request_shutdown();
    }
}

pub(crate) fn fresh_network(id: &str, wire_id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: wire_id.to_string(),
        event_capacity: NetworkConfig::from_network_id("", "").event_capacity,
        connection_trace_capacity: NetworkConfig::from_network_id("", "").connection_trace_capacity,
        label: id.to_string(),
        kind: Default::default(),
        scheduler: SchedulerPolicyConfig::default(),
        tree: None,
        hub: None,
        local_observations: None,
        introduction: None,
        semantic_policy: myownmesh_core::config::SemanticPolicyConfig::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

pub(crate) fn test_transport() -> Transport {
    let webrtc_profile = WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only());
    let policy = WebRtcConnectorCapablePolicy::new(crate::test_resource_provider(), webrtc_profile);
    Transport::new()
        .expect("transport")
        .with_connector_resource_policy(policy)
        .expect("test process connector policy is consistent")
}

#[cfg(unix)]
pub(crate) async fn wait_for_approval(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) {
    wait_for_approval_diagnosed(rx, peer_id)
        .await
        .unwrap_or_else(|error| panic!("{error}"));
}

/// Wait for approval while preserving the first useful reason when the
/// broadcast or its producer has already failed.  The short timeout is only a
/// poll interval; the absolute approval deadline remains the fixture's
/// twenty-second contract.
async fn wait_for_approval_diagnosed(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
) -> Result<(), String> {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_event = "none";
    let mut last_error = "none";
    let mut poll_timeouts = 0_u32;
    let mut lagged_events = 0_u64;
    loop {
        if Instant::now() > deadline {
            return Err(format!(
                "approval/timeout peer={peer_id} last_event={last_event} \
                 last_error={last_error} poll_timeouts={poll_timeouts} \
                 lagged_events={lagged_events}"
            ));
        }
        let next = tokio::time::timeout(Duration::from_millis(200), rx.recv()).await;
        match next {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { device_id, .. })))
                if device_id == peer_id =>
            {
                return Ok(());
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Approved { .. }))) => {
                last_event = "approved-other-peer";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Sighted { .. }))) => {
                last_event = "peer-sighted";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { .. }))) => {
                last_event = "peer-authenticated";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Shelved { .. }))) => {
                last_event = "peer-shelved";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Unshelved { .. }))) => {
                last_event = "peer-unshelved";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::CapabilitiesChanged { .. }))) => {
                last_event = "peer-capabilities-changed";
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Dropped { .. }))) => {
                last_event = "peer-dropped";
            }
            Ok(Ok(_)) => {
                last_event = "mesh-event-other";
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Lagged(skipped))) => {
                last_error = "lagged";
                lagged_events = lagged_events.saturating_add(skipped);
            }
            Ok(Err(tokio::sync::broadcast::error::RecvError::Closed)) => {
                return Err(format!("approval/closed peer={peer_id}"));
            }
            Err(_) => {
                last_error = "poll-timeout";
                poll_timeouts = poll_timeouts.saturating_add(1);
            }
        }
    }
}

/// Build two engines and an RPC dispatcher pair sharing one LocalBroker.
/// The returned driver owner performs a real shutdown so one process-global
/// connector budget is reusable by the next test.
#[allow(clippy::type_complexity)]
pub(crate) async fn two_peer_rpc(
    wire_id: &str,
) -> (
    Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    Arc<myownmesh_core::rpc::Rpc>,
    Arc<myownmesh_core::rpc::Rpc>,
    Arc<Identity>,
    Arc<Identity>,
    TwoPeerDrivers,
) {
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());
    std::mem::forget(tmp); // leak — test scope only

    let broker = LocalBroker::new();
    let transport = test_transport();
    log_resource_ledger("entry", wire_id);

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let alice_cfg = fresh_network("alice", wire_id);
    let bob_cfg = fresh_network("bob", wire_id);

    let (alice_state, alice_driver) = spawn_network(alice_cfg, alice_id.clone(), transport.clone())
        .await
        .map_err(|error| format!("setup/alice-engine: {error}"))
        .unwrap_or_else(|error| panic!("{error}"));
    let (bob_state, bob_driver) =
        match spawn_network(bob_cfg, bob_id.clone(), transport.clone()).await {
            Ok(result) => result,
            Err(error) => {
                alice_state.request_shutdown();
                eprintln!("two-peer setup failed for {wire_id}: setup/bob-engine: {error}");
                log_resource_ledger("failure", wire_id);
                eprintln!("two-peer cleanup begin for {wire_id}");
                let cleanup_error = alice_driver.await.err().map(|error| error.to_string());
                eprintln!("two-peer cleanup complete for {wire_id}");
                log_resource_ledger("cleanup-complete", wire_id);
                if let Some(cleanup_error) = cleanup_error {
                    panic!("setup/bob-engine: {error}; cleanup failed: {cleanup_error}");
                }
                panic!("setup/bob-engine: {error}");
            }
        };

    // Own both drivers before any attach or approval wait.  If the checked
    // setup path below refuses, it can perform the real async shutdown rather
    // than dropping raw JoinHandles and leaving their connector custody to a
    // detached task.
    let mut drivers = Some(TwoPeerDrivers {
        alice: Arc::clone(&alice_state),
        bob: Arc::clone(&bob_state),
        drivers: vec![alice_driver, bob_driver],
    });

    let setup = async {
        let alice_rpc = Arc::new(
            myownmesh_core::engine::transport_lab::rpc(&alice_state)
                .map_err(|error| format!("setup/alice-rpc: {error:?}"))?,
        );
        let bob_rpc = Arc::new(
            myownmesh_core::engine::transport_lab::rpc(&bob_state)
                .map_err(|error| format!("setup/bob-rpc: {error:?}"))?,
        );

        let mut alice_events = alice_state.events_tx.subscribe();
        let mut bob_events = bob_state.events_tx.subscribe();
        attach_local(&alice_state, &broker);
        attach_local(&bob_state, &broker);
        log_resource_ledger("after-attach", wire_id);

        wait_for_approval_diagnosed(&mut alice_events, bob_id.public_id())
            .await
            .map_err(|error| format!("setup/alice-approval-after-local-attach: {error}"))?;
        wait_for_approval_diagnosed(&mut bob_events, alice_id.public_id())
            .await
            .map_err(|error| format!("setup/bob-approval-after-local-attach: {error}"))?;

        Ok::<_, String>((alice_rpc, bob_rpc))
    }
    .await;

    let (alice_rpc, bob_rpc) = match setup {
        Ok(rpcs) => rpcs,
        Err(error) => {
            if let Some(drivers) = drivers.take() {
                eprintln!("two-peer setup failed for {wire_id}: {error}");
                log_resource_ledger("failure", wire_id);
                eprintln!("two-peer cleanup begin for {wire_id}");
                let cleanup_error = drivers.shutdown_with_report().await;
                eprintln!("two-peer cleanup complete for {wire_id}");
                log_resource_ledger("cleanup-complete", wire_id);
                if let Some(cleanup_error) = cleanup_error {
                    panic!(
                        "two-peer setup failed for {wire_id}: {error}; cleanup failed: {cleanup_error}"
                    );
                }
            }
            panic!("two-peer setup failed for {wire_id}: {error}");
        }
    };
    let drivers = drivers.take().expect("setup retains the driver owner");
    (
        alice_state,
        bob_state,
        alice_rpc,
        bob_rpc,
        alice_id,
        bob_id,
        drivers,
    )
}
