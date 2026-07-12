//! Engine-level integration tests for mDNS signaling and the
//! multi-driver fan-out.
//!
//! - `two_peers_handshake_over_mdns_only`: a LAN-only network
//!   (`strategy: "none", mdns: true`) — the local-claiming shape —
//!   completes a full engine handshake with SDP exchanged over the
//!   mDNS driver's TCP exchange. Skips loudly when the environment
//!   has no working multicast (probed with two raw drivers first).
//! - `two_peers_handshake_with_nostr_and_mdns_fanout`: both drivers
//!   attached (`strategy: "nostr"` against a self-hosted relay, plus
//!   `mdns: true`). Every offer/answer/candidate is emitted through
//!   BOTH transports, so the handshake completing at all proves the
//!   bridge's cross-driver dedup gate works — a duplicate
//!   `set_remote_description` wedges WebRTC permanently. This test
//!   passes with or without multicast (the relay path suffices).

use std::sync::Arc;
use std::time::Duration;

use myownmesh_core::config::{NetworkConfig, SignalingConfig, TopologyMode};
use myownmesh_core::engine::{attach_signaling, spawn_network};
use myownmesh_core::identity::Identity;
use myownmesh_core::transport::Transport;
use myownmesh_core::{MeshEvent, PeerEvent};
use tokio::time::Instant;

/// Serializes the tests in this file — they mutate the process-wide
/// `MYOWNMESH_HOME`. Async-aware so holding it across the tests'
/// await points is well-defined.
static HOME_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

fn network_config(id: &str, network_id: &str, signaling: SignalingConfig) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: network_id.to_string(),
        label: id.to_string(),
        kind: Default::default(),
        topology: TopologyMode::FullMesh,
        signaling,
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        roster_path: None,
        pinned_peers: Vec::new(),
        auto_approve: true,
    }
}

/// Probe whether this environment supports same-host mDNS discovery
/// at all, using two raw drivers. CI containers frequently block
/// multicast; the driver- and engine-level mdns tests skip there.
async fn multicast_available() -> bool {
    use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
    use tokio::sync::mpsc;

    let network = format!("mdns-probe-{}", std::process::id());
    let cfg = |device: &str| MdnsDriverConfig {
        app_id: "myownmesh-mdns-probe".into(),
        network_id: network.clone(),
        device_id: device.into(),
        service_port: 0,
    };
    let (_a_out_tx, a_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (a_in_tx, mut a_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let (_b_out_tx, b_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (b_in_tx, _b_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let Ok(_a) = mdns::start(cfg("probe-a"), a_out_rx, a_in_tx) else {
        return false;
    };
    let Ok(_b) = mdns::start(cfg("probe-b"), b_out_rx, b_in_tx) else {
        return false;
    };
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_millis(200), a_in_rx.recv()).await {
            Ok(Some(MdnsInbound::PeerAnnounced { device_id })) if device_id == "probe-b" => {
                return true;
            }
            Ok(Some(_)) => continue,
            Ok(None) => return false,
            Err(_) => continue,
        }
    }
    false
}

async fn wait_for_approval(
    rx: &mut tokio::sync::broadcast::Receiver<MeshEvent>,
    peer_id: &str,
    deadline: Duration,
) {
    let deadline = Instant::now() + deadline;
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

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_handshake_over_mdns_only() {
    let _guard = HOME_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    if !multicast_available().await {
        eprintln!(
            "SKIP two_peers_handshake_over_mdns_only: no same-host mDNS discovery here \
             (multicast blocked) — driver logic is covered by unit tests"
        );
        return;
    }

    let lan_only = SignalingConfig {
        strategy: "none".into(),
        mdns: true,
        ..SignalingConfig::default()
    };
    let network_id = format!("mdns-only-handshake-{}", std::process::id());

    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) = spawn_network(
        network_config("alice", &network_id, lan_only.clone()),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(
        network_config("bob", &network_id, lan_only),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    let alice_drivers = attach_signaling(&alice_state).expect("alice signaling");
    let bob_drivers = attach_signaling(&bob_state).expect("bob signaling");
    assert_eq!(alice_drivers.describe(), "mdns");
    assert_eq!(bob_drivers.describe(), "mdns");

    // Full engine handshake — discovery, SDP over the TCP exchange,
    // WebRTC, ed25519 mutual auth — with zero remote infrastructure.
    wait_for_approval(
        &mut alice_events,
        bob_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
    wait_for_approval(
        &mut bob_events,
        alice_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn two_peers_handshake_with_nostr_and_mdns_fanout() {
    let _guard = HOME_LOCK.lock().await;
    let tmp = tempfile::tempdir().expect("tempdir");
    std::env::set_var("MYOWNMESH_HOME", tmp.path());

    // Self-hosted relay so the Nostr driver needs no public
    // infrastructure either.
    let relay = myownmesh_signaling::server::SignalingServer::start(
        "127.0.0.1",
        0,
        myownmesh_signaling::server::Limits::default(),
    )
    .await
    .expect("relay");
    let relay_url = format!("ws://127.0.0.1:{}", relay.local_addr().port());

    let both = SignalingConfig {
        strategy: "nostr".into(),
        mdns: true,
        servers: vec![relay_url],
        public_fallback: false,
        ..SignalingConfig::default()
    };
    let network_id = format!("fanout-handshake-{}", std::process::id());

    let transport = Transport::new().expect("transport");
    let alice_id = Arc::new(Identity::ephemeral());
    let bob_id = Arc::new(Identity::ephemeral());

    let (alice_state, _alice_driver) = spawn_network(
        network_config("alice", &network_id, both.clone()),
        alice_id.clone(),
        transport.clone(),
    )
    .await
    .expect("alice engine");
    let (bob_state, _bob_driver) = spawn_network(
        network_config("bob", &network_id, both),
        bob_id.clone(),
        transport.clone(),
    )
    .await
    .expect("bob engine");

    let mut alice_events = alice_state.events_tx.subscribe();
    let mut bob_events = bob_state.events_tx.subscribe();

    let alice_drivers = attach_signaling(&alice_state).expect("alice signaling");
    let bob_drivers = attach_signaling(&bob_state).expect("bob signaling");
    // mDNS may or may not come up depending on the environment; the
    // Nostr side must. Either way the handshake has to complete —
    // and when both are up, completing proves the cross-driver dedup
    // gate (a doubly-applied offer wedges WebRTC).
    assert!(
        alice_drivers.describe().contains("nostr"),
        "nostr driver must attach, got {}",
        alice_drivers.describe()
    );
    let _ = &bob_drivers;

    wait_for_approval(
        &mut alice_events,
        bob_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
    wait_for_approval(
        &mut bob_events,
        alice_id.public_id(),
        Duration::from_secs(60),
    )
    .await;
}
