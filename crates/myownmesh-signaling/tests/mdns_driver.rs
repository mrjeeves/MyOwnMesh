//! Two mDNS drivers on one host discover each other and exchange a
//! directed signaling message — the driver-level proof that LAN
//! signaling works end to end (DNS-SD resolve → PeerAnnounced →
//! TCP exchange → Message).
//!
//! Multicast is not available in every environment (CI containers
//! frequently block it). When discovery doesn't happen inside the
//! grace window the test SKIPS — loudly — instead of failing, so the
//! suite stays deterministic; the wire-format logic is covered by
//! always-run unit tests in `mdns::wire`.

use std::time::Duration;

use myownmesh_signaling::mdns::{self, MdnsDriverConfig, MdnsInbound, MdnsOutbound};
use myownmesh_signaling::SignalingMessage;
use tokio::sync::mpsc;
use tokio::time::timeout;

/// How long we give same-host multicast discovery before deciding the
/// environment doesn't support it. Generous — resolution normally
/// lands in well under two seconds.
const DISCOVERY_GRACE: Duration = Duration::from_secs(15);

fn driver_config(network: &str, device: &str) -> MdnsDriverConfig {
    MdnsDriverConfig {
        app_id: "myownmesh-mdns-test".into(),
        network_id: network.into(),
        device_id: device.into(),
        service_port: 0,
    }
}

async fn wait_for_announce(
    rx: &mut mpsc::UnboundedReceiver<MdnsInbound>,
    expect_peer: &str,
) -> Option<()> {
    loop {
        match timeout(DISCOVERY_GRACE, rx.recv()).await {
            Ok(Some(MdnsInbound::PeerAnnounced { device_id })) if device_id == expect_peer => {
                return Some(());
            }
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => return None,
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_drivers_discover_and_exchange() {
    let network = format!("mdns-driver-test-{}", std::process::id());

    let (a_out_tx, a_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (a_in_tx, mut a_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();
    let (b_out_tx, b_out_rx) = mpsc::unbounded_channel::<MdnsOutbound>();
    let (b_in_tx, mut b_in_rx) = mpsc::unbounded_channel::<MdnsInbound>();

    let a = match mdns::start(driver_config(&network, "device-a"), a_out_rx, a_in_tx) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver A failed to start ({e}) — no mDNS here");
            return;
        }
    };
    let b = match mdns::start(driver_config(&network, "device-b"), b_out_rx, b_in_tx) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("SKIP mdns_driver test: driver B failed to start ({e}) — no mDNS here");
            return;
        }
    };

    // Mutual discovery. If multicast is blocked in this environment,
    // neither side ever resolves the other — skip.
    if wait_for_announce(&mut a_in_rx, "device-b").await.is_none() {
        eprintln!(
            "SKIP mdns_driver test: no discovery within {DISCOVERY_GRACE:?} — \
             multicast appears unavailable in this environment"
        );
        return;
    }
    wait_for_announce(&mut b_in_rx, "device-a")
        .await
        .expect("B discovers A once A has discovered B");

    // Directed exchange: A offers B over the TCP exchange.
    let offer = SignalingMessage::Offer {
        peer_id: "device-a".into(),
        offer_id: "offer-1".into(),
        sdp: "v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\n".into(),
    };
    a_out_tx
        .send(MdnsOutbound::DirectedToPeer {
            to: "device-b".into(),
            msg: offer.clone(),
        })
        .expect("outbound channel open");

    let got = loop {
        match timeout(DISCOVERY_GRACE, b_in_rx.recv()).await {
            Ok(Some(MdnsInbound::Message { from, msg })) => break (from, msg),
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("offer never arrived over the mdns TCP exchange"),
        }
    };
    assert_eq!(got.0, "device-a");
    assert_eq!(got.1, offer);

    // Withdrawal: B leaves; A hears PeerLeft via the mDNS goodbye.
    b_out_tx.send(MdnsOutbound::Leave).expect("channel open");
    let left = loop {
        match timeout(DISCOVERY_GRACE, a_in_rx.recv()).await {
            Ok(Some(MdnsInbound::PeerLeft { device_id })) => break device_id,
            Ok(Some(_)) => continue,
            Ok(None) | Err(_) => panic!("goodbye never surfaced as PeerLeft"),
        }
    };
    assert_eq!(left, "device-b");

    a.stop();
    b.stop();
}
