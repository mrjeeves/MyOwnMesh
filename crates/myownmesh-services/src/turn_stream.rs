//! TURN-over-TCP stream front-end for the UDP TURN allocation engine.
//!
//! TURN messages are self-framing on streams: STUN carries its body length in
//! bytes 2-3, while ChannelData carries its payload length there and is padded
//! to a four-byte boundary on TCP. One connected UDP socket per TCP client
//! preserves a stable five-tuple at the existing TURN server, so allocation,
//! authentication, permissions, relay sockets, and QoS stay in one engine.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;
use tracing::{debug, info, warn};

const MAX_TURN_FRAME: usize = 65_556;
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

pub(crate) struct TurnTcpBridge {
    cancel: CancellationToken,
    task: JoinHandle<()>,
}

impl TurnTcpBridge {
    pub(crate) async fn start(bind: SocketAddr, udp_target: SocketAddr) -> io::Result<Self> {
        let listener = TcpListener::bind(bind).await?;
        let local_addr = listener.local_addr()?;
        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();
        let task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = task_cancel.cancelled() => break,
                    accepted = listener.accept() => match accepted {
                        Ok((stream, peer)) => {
                            let child = task_cancel.child_token();
                            tokio::spawn(async move {
                                if let Err(error) = bridge_connection(stream, udp_target, child).await {
                                    debug!(%peer, %error, "TURN TCP client closed");
                                }
                            });
                        }
                        Err(error) => {
                            warn!(%error, "TURN TCP accept failed");
                            break;
                        }
                    }
                }
            }
        });
        info!(%local_addr, %udp_target, "TURN TCP listening");
        Ok(Self { cancel, task })
    }

    pub(crate) async fn stop(self) {
        self.cancel.cancel();
        let _ = self.task.await;
    }
}

async fn bridge_connection(
    stream: TcpStream,
    udp_target: SocketAddr,
    cancel: CancellationToken,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let udp_bind = match udp_target.ip() {
        IpAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0),
        IpAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0),
    };
    let udp = UdpSocket::bind(udp_bind).await?;
    udp.connect(udp_target).await?;
    let (mut reader, mut writer) = stream.into_split();
    let mut datagram = vec![0u8; MAX_TURN_FRAME];
    let idle = tokio::time::sleep(CLIENT_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return Ok(()),
            result = read_turn_stream_frame(&mut reader) => {
                udp.send(&result?).await?;
            },
            result = udp.recv(&mut datagram) => {
                let received = result?;
                write_turn_stream_frame(&mut writer, &datagram[..received]).await?;
            },
            _ = &mut idle => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "TURN TCP idle timeout"));
            }
        }
        idle.as_mut().reset(Instant::now() + CLIENT_IDLE_TIMEOUT);
    }
}

pub(crate) async fn read_turn_stream_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let body_len = u16::from_be_bytes([header[2], header[3]]) as usize;
    let channel_data = header[0] & 0b1100_0000 == 0b0100_0000;
    let message_len = if channel_data {
        4usize.checked_add(body_len)
    } else if header[0] & 0b1100_0000 == 0 {
        20usize.checked_add(body_len)
    } else {
        None
    }
    .filter(|len| *len >= 4 && *len <= MAX_TURN_FRAME)
    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "invalid TURN stream frame"))?;
    let padded_len = if channel_data {
        (message_len + 3) & !3
    } else {
        message_len
    };
    let mut frame = vec![0u8; padded_len];
    frame[..4].copy_from_slice(&header);
    reader.read_exact(&mut frame[4..]).await?;
    frame.truncate(message_len);
    Ok(frame)
}

pub(crate) async fn write_turn_stream_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> io::Result<()> {
    writer.write_all(frame).await?;
    if frame
        .first()
        .is_some_and(|b| b & 0b1100_0000 == 0b0100_0000)
    {
        let padding = (4 - frame.len() % 4) % 4;
        if padding != 0 {
            writer.write_all(&[0u8; 3][..padding]).await?;
        }
    }
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn stream_frames_stun_and_padded_channel_data() {
        let stun = [
            0x00, 0x01, 0x00, 0x04, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4,
        ];
        let channel = [0x40, 0x01, 0x00, 0x03, 7, 8, 9];
        let mut wire = Vec::new();
        write_turn_stream_frame(&mut wire, &stun).await.unwrap();
        write_turn_stream_frame(&mut wire, &channel).await.unwrap();
        assert_eq!(wire.len(), stun.len() + 8);

        let mut cursor = std::io::Cursor::new(wire);
        assert_eq!(read_turn_stream_frame(&mut cursor).await.unwrap(), stun);
        assert_eq!(read_turn_stream_frame(&mut cursor).await.unwrap(), channel);
    }
}
