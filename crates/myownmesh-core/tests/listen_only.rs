//! End-to-end engine integration test for a **listen-only** signaling join
//! (`SignalingConfig::listen_only`) on a Silent network — the queue-watcher
//! shape: the watcher subscribes to the room and sees every member, while
//! the room never learns the watcher exists. A deliberate `connect_peer`
//! from the watcher still works (directed signaling passes), revealing the
//! watcher to exactly the one peer it dialed.
//!
//! Mirrors `silent_network.rs`: real engine + WebRTC transport over the
//! in-process `LocalBroker`.

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_local, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, NetworkKind, PeerEvent};
use myownmesh_signaling::local::LocalBroker;
use tokio::time::Instant;

fn network(id: &str, listen_only: bool) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: "listen-only-room".into(),
        label: id.to_string(),
        kind: NetworkKind::Silent,
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig {
            listen_only,
            ..SignalingConfig::default()
        },
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

/// Drain `events` until `peer` is Sighted (or the deadline passes), panicking
/// if any authentication fires on the way — Silent must not auto-connect.
async fn wait_sighted(
    events: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer: &str,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(remaining > Duration::ZERO, "{what}: never sighted {peer}");
        match tokio::time::timeout(remaining, events.recv()).await {
            Ok(Ok(MeshEvent::Peer(PeerEvent::Sighted { device_id, .. }))) if device_id == peer => {
                return;
            }
            Ok(Ok(MeshEvent::Peer(PeerEvent::Authenticated { device_id, .. })))
                if device_id == peer =>
            {
                panic!("{what}: {peer} authenticated without a deliberate dial");
            }
            Ok(Ok(_)) => continue,
            Ok(Err(e)) => panic!("{what}: event stream closed: {e}"),
            Err(_) => continue,
        }
    }
}

async fn wait_authenticated(
    state: &Arc<myownmesh_core::engine::state::NetworkState>,
    peer: &str,
    what: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if state
            .peer_info(peer)
            .map(|p| p.authenticated)
            .unwrap_or(false)
        {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "{what}: {peer} never authenticated"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listen_only_watcher_sees_without_being_seen_and_can_still_dial() {
    let tmp = tempfile::tempdir().expect("tempdir");
    // SAFETY: single-threaded MYOWNMESH_HOME mutation per test binary; the
    // one test in this file owns the var for the process lifetime.
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    let broker = LocalBroker::new();
    let transport = Transport::new().expect("transport");

    let asker_id = Arc::new(Identity::ephemeral());
    let watcher_id = Arc::new(Identity::ephemeral());

    // The watcher attaches FIRST, so the asker's arrival exercises the
    // live-announce path (not just the join-time backfill).
    let (watcher_state, _watcher_driver) = spawn_network(
        network("watcher", true),
        watcher_id.clone(),
        transport.clone(),
    )
    .await
    .expect("watcher engine");
    let mut watcher_events = watcher_state.events_tx.subscribe();
    attach_local(&watcher_state, &broker);

    let (asker_state, _asker_driver) =
        spawn_network(network("asker", false), asker_id.clone(), transport.clone())
            .await
            .expect("asker engine");
    let mut asker_events = asker_state.events_tx.subscribe();
    attach_local(&asker_state, &broker);

    let asker_pub = asker_id.public_id().to_string();
    let watcher_pub = watcher_id.public_id().to_string();

    // The watcher sees the asker arrive (Sighted — Silent, so no session).
    wait_sighted(&mut watcher_events, &asker_pub, "watcher").await;

    // The asker must NOT learn the watcher exists: no announce was ever
    // published for it. Give the room a generous settle window, then check
    // both the event stream and the peer table stayed empty of the watcher.
    tokio::time::sleep(Duration::from_secs(3)).await;
    assert!(
        asker_state.peer_info(&watcher_pub).is_none(),
        "a listen-only watcher must be invisible to the room"
    );
    while let Ok(ev) = asker_events.try_recv() {
        if let MeshEvent::Peer(p) = ev {
            let seen = match &p {
                PeerEvent::Sighted { device_id, .. }
                | PeerEvent::Authenticated { device_id, .. }
                | PeerEvent::Approved { device_id, .. } => device_id == &watcher_pub,
                _ => false,
            };
            assert!(!seen, "asker surfaced the lurking watcher: {p:?}");
        }
    }

    // The watcher can still deliberately dial the asker — directed
    // signaling passes a listen-only join — and the dial is what reveals
    // it, to exactly that one peer.
    watcher_state.connect_peer(&asker_pub);
    wait_authenticated(&watcher_state, &asker_pub, "watcher→asker").await;
    wait_authenticated(&asker_state, &watcher_pub, "asker→watcher").await;
}
