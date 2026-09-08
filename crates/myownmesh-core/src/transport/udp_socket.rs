//! Socket admission capacity, not a playout buffer: readers still drain immediately.

use std::sync::Arc;

use tokio::net::UdpSocket;
use tracing::{debug, warn};
use webrtc::util::vnet::net::Net;

// Windows defaults to 64 KiB, below AMS's 96 KiB immediate media burst.
// Leave bounded headroom for that burst plus packets arriving while the
// receive task is scheduled. No timer, watermark, or delayed read is added.
pub(super) const RECEIVE_CAPACITY_BYTES: usize = 1024 * 1024;

fn configure(socket: &UdpSocket) -> std::io::Result<()> {
    let socket_ref = socket2::SockRef::from(socket);
    let before = socket_ref.recv_buffer_size()?;
    if before < RECEIVE_CAPACITY_BYTES {
        socket_ref.set_recv_buffer_size(RECEIVE_CAPACITY_BYTES)?;
    }
    let actual = socket_ref.recv_buffer_size()?;
    if actual < RECEIVE_CAPACITY_BYTES {
        warn!(
            requested = RECEIVE_CAPACITY_BYTES,
            actual, "UDP receive capacity clamped by operating system"
        );
    }
    debug!(local = ?socket.local_addr()?, before, actual,
        "UDP receive admission capacity configured");
    Ok(())
}

pub(super) fn real_network() -> Net {
    Net::new(None).with_udp_socket_config(Arc::new(configure))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, SocketAddr};

    #[cfg(windows)]
    #[tokio::test]
    async fn udp_socket_admits_existing_media_burst_before_reader_is_scheduled() {
        async fn burst(receiver: &UdpSocket) -> usize {
            let sender = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
            let addr = receiver.local_addr().unwrap();
            // The existing 96 KiB burst, packetized at the live RTP size.
            const COUNT: usize = 81;
            for seq in 0..COUNT {
                let mut packet = [0u8; 1216];
                packet[..4].copy_from_slice(&(seq as u32).to_be_bytes());
                sender.send_to(&packet, addr).await.unwrap();
            }
            let mut unique = std::collections::HashSet::new();
            let mut packet = [0u8; 1216];
            while let Ok(Ok(n)) = tokio::time::timeout(
                std::time::Duration::from_millis(50),
                receiver.recv(&mut packet),
            )
            .await
            {
                assert_eq!(n, packet.len());
                unique.insert(u32::from_be_bytes(packet[..4].try_into().unwrap()));
                if unique.len() == COUNT {
                    break;
                }
            }
            unique.len()
        }
        let baseline = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        socket2::SockRef::from(&baseline)
            .set_recv_buffer_size(65536)
            .unwrap();
        let old_count = burst(&baseline).await;
        assert!(
            old_count < 81,
            "64 KiB baseline unexpectedly admitted the entire burst"
        );
        let net = real_network();
        let conn = net
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let receiver = conn.as_any().downcast_ref::<UdpSocket>().unwrap();
        assert_eq!(
            burst(receiver).await,
            81,
            "configured socket dropped media burst"
        );
        eprintln!("UDP burst: baseline={old_count}/81, configured=81/81");
    }

    #[tokio::test]
    async fn udp_socket_policy_reaches_bound_and_connected_sockets() {
        let net = real_network();
        assert!(!net.is_virtual());
        let bound = net
            .bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
            .await
            .unwrap();
        let connected = net
            .dail(true, &bound.local_addr().unwrap().to_string())
            .await
            .unwrap();
        for conn in [&bound, &connected] {
            let socket = conn.as_any().downcast_ref::<UdpSocket>().unwrap();
            let capacity = socket2::SockRef::from(socket).recv_buffer_size().unwrap();
            // Some Unix hosts clamp at their sysctl limit. Windows must receive
            // the full requested capacity; no system-wide setting is changed.
            #[cfg(windows)]
            assert!(capacity >= RECEIVE_CAPACITY_BYTES, "actual={capacity}");
            assert!(capacity >= 96 * 1024, "actual={capacity}");
        }
        connected.send(b"fresh").await.unwrap();
        let mut bytes = [0; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(1), bound.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&bytes[..n], b"fresh");
    }
}
