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

use myownmesh_core::config::{
    NetworkConfig, RoutingPolicyConfig, SchedulerPolicyConfig, SignalingConfig, TopologyMode,
};
use myownmesh_core::engine::transport_lab::{attach_local, spawn_network};
use myownmesh_core::events::{MeshEvent, PeerEvent};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{
    ConnectorCallbackPolicy, WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

/// The two engines' driver tasks, and the shutdown that really ends them.
pub(crate) struct TwoPeerDrivers {
    alice: Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    bob: Arc<myownmesh_core::engine::transport_lab::NetworkState>,
    drivers: Vec<tokio::task::JoinHandle<()>>,
}

impl TwoPeerDrivers {
    pub(crate) async fn shutdown(mut self) {
        // The owner-held coalesced signal, not a queued command: it sets the
        // flag, wakes the waiters and closes both queues itself, so it
        // cannot be dropped or outranked by payload traffic the way a
        // command competing in the same mailbox could be.
        self.alice.request_shutdown();
        self.bob.request_shutdown();
        while let Some(driver) = self.drivers.pop() {
            let _ = driver.await;
        }
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
        routing_policy: RoutingPolicyConfig::default(),
        tree: None,
        hub: None,
        local_observations: None,
        application_transport: None,
        semantic_policy: myownmesh_core::config::SemanticPolicyConfig::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig::default(),
        closed_relay: Default::default(),
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

pub(crate) async fn wait_for_approval(
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

    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let alice_cfg = fresh_network("alice", wire_id);
    let bob_cfg = fresh_network("bob", wire_id);

    let (alice_state, alice_driver) = spawn_network(alice_cfg, alice_id.clone(), transport.clone())
        .await
        .expect("alice engine");
    let (bob_state, bob_driver) = spawn_network(bob_cfg, bob_id.clone(), transport.clone())
        .await
        .expect("bob engine");
    let alice_rpc = Arc::new(
        myownmesh_core::engine::transport_lab::rpc(&alice_state)
            .expect("Alice's live gateway admits its RPC owner"),
    );
    let bob_rpc = Arc::new(
        myownmesh_core::engine::transport_lab::rpc(&bob_state)
            .expect("Bob's live gateway admits its RPC owner"),
    );

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();
    attach_local(&alice_state, &broker);
    attach_local(&bob_state, &broker);

    wait_for_approval(&mut alice_events, bob_id.public_id()).await;
    wait_for_approval(&mut bob_events, alice_id.public_id()).await;

    let drivers = TwoPeerDrivers {
        alice: Arc::clone(&alice_state),
        bob: Arc::clone(&bob_state),
        drivers: vec![alice_driver, bob_driver],
    };
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
