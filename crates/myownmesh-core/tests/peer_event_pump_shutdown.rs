#![cfg(feature = "transport-lab")]

mod support;

use std::sync::Arc;

use myownmesh_core::config::NetworkConfig;
use myownmesh_core::engine::transport_lab::spawn_network_in_instance_root;
use myownmesh_core::identity::Identity;
use myownmesh_core::resource::ResourceReport;

fn assert_resource_baseline(before: &ResourceReport, after: &ResourceReport) {
    for (before, after) in before
        .pre_authentication
        .iter()
        .zip(after.pre_authentication.iter())
    {
        assert_eq!(after.active, before.active, "resource activity baseline");
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "resource lease baseline"
        );
    }
    for (before, after) in before
        .post_authentication
        .iter()
        .zip(after.post_authentication.iter())
    {
        assert_eq!(after.active, before.active, "resource activity baseline");
        assert_eq!(
            after.active_lease_count, before.active_lease_count,
            "resource lease baseline"
        );
    }
}

#[tokio::test]
async fn shutdown_joins_a_late_peer_event_pump() {
    let root = tempfile::tempdir().expect("per-instance persistence root");
    let mut config = NetworkConfig::from_network_id("peer-pump-shutdown", "peer-pump-shutdown");
    config.stun_servers.clear();
    config.turn_servers.clear();
    let identity = Arc::new(Identity::ephemeral());
    let transport = support::test_transport();
    let (state, driver) =
        spawn_network_in_instance_root(config, identity, transport, root.path().to_path_buf())
            .await
            .expect("spawn Open network");
    let baseline = state.resource_report();

    assert!(state.begin_peer_event_pump_registration_for_lab());
    state.request_shutdown();
    let driver = tokio::spawn(driver);
    state.wait_peer_event_pump_shutdown_for_lab().await;

    let (start_tx, start_rx) = tokio::sync::oneshot::channel();
    let (entered_tx, entered_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = tokio::sync::oneshot::channel();
    let pump = tokio::spawn(async move {
        start_rx.await.expect("pump start");
        entered_tx.send(()).expect("pump entered barrier");
        release_rx.await.expect("pump release");
    });

    state
        .finish_peer_event_pump_registration_for_lab(pump)
        .await;
    start_tx.send(()).expect("start pump");
    entered_rx.await.expect("pump entered");
    assert!(!driver.is_finished(), "shutdown must own the blocked pump");

    release_tx.send(()).expect("release pump");
    driver
        .await
        .expect("shutdown task join")
        .expect("network driver shutdown");
    assert_resource_baseline(&baseline, &state.resource_report());
}
