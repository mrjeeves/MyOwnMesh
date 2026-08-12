//! Local TURN stream adapters for webrtc-rs.
//!
//! webrtc-rs 0.13 only gathers relay candidates from UDP TURN URLs. This
//! adapter exposes each configured TCP/TLS TURN endpoint as a loopback UDP
//! listener, then carries the same TURN messages over a persistent RFC 8656
//! stream. The peer connection still receives a normal relayed candidate;
//! only the client-to-TURN-server transport is adapted.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};
use tokio::sync::mpsc::error::TrySendError;
use tokio::sync::{mpsc, Mutex};
use tokio::task::JoinHandle;
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::TlsConnector;
use tracing::{debug, warn};

use crate::config::TurnServer;

const MAX_TURN_FRAME: usize = 65_556;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(10 * 60);

trait TurnStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TurnStream for T {}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct StreamEndpoint {
    host: String,
    port: u16,
    tls: bool,
}

struct LocalBridge {
    addr: SocketAddr,
    _task: JoinHandle<()>,
}

#[derive(Default)]
pub(crate) struct TurnStreamBridges {
    bridges: Mutex<HashMap<StreamEndpoint, Arc<LocalBridge>>>,
}

impl TurnStreamBridges {
    pub(crate) async fn rewrite(&self, servers: &[TurnServer]) -> Vec<TurnServer> {
        let mut rewritten = Vec::with_capacity(servers.len());
        for server in servers {
            let mut urls = Vec::with_capacity(server.urls.len());
            for url in &server.urls {
                let Some(endpoint) = parse_stream_url(url) else {
                    urls.push(url.clone());
                    continue;
                };
                match self.ensure(endpoint).await {
                    Ok(addr) => urls.push(format!("turn:{addr}?transport=udp")),
                    Err(error) => warn!(%url, %error, "TURN stream fallback unavailable"),
                }
            }
            if !urls.is_empty() {
                rewritten.push(TurnServer {
                    urls,
                    username: server.username.clone(),
                    credential: server.credential.clone(),
                });
            }
        }
        rewritten
    }

    async fn ensure(&self, endpoint: StreamEndpoint) -> io::Result<SocketAddr> {
        let mut bridges = self.bridges.lock().await;
        if let Some(existing) = bridges.get(&endpoint) {
            return Ok(existing.addr);
        }
        let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
        let addr = socket.local_addr()?;
        let task_endpoint = endpoint.clone();
        let task = tokio::spawn(async move {
            if let Err(error) = run_local_bridge(socket, task_endpoint.clone()).await {
                warn!(host = %task_endpoint.host, port = task_endpoint.port, %error, "TURN stream bridge stopped");
            }
        });
        bridges.insert(endpoint, Arc::new(LocalBridge { addr, _task: task }));
        Ok(addr)
    }
}

fn parse_stream_url(url: &str) -> Option<StreamEndpoint> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("turns:") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("turn:") {
        (false, rest)
    } else {
        return None;
    };
    let (authority, query) = rest
        .trim_start_matches("//")
        .split_once('?')
        .unwrap_or((rest, ""));
    let is_tcp = tls
        || query
            .split('&')
            .any(|part| part.eq_ignore_ascii_case("transport=tcp"));
    if !is_tcp {
        return None;
    }
    let default_port = if tls { 5349 } else { 3478 };
    let (host, port) = if let Some(after) = authority.strip_prefix('[') {
        let (host, suffix) = after.split_once(']')?;
        let port = suffix
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        (host.to_string(), port)
    } else if let Some((host, port)) = authority.rsplit_once(':') {
        (host.to_string(), port.parse().ok()?)
    } else {
        (authority.to_string(), default_port)
    };
    (!host.is_empty()).then_some(StreamEndpoint { host, port, tls })
}

async fn run_local_bridge(socket: Arc<UdpSocket>, endpoint: StreamEndpoint) -> io::Result<()> {
    let clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let mut datagram = vec![0u8; MAX_TURN_FRAME];
    loop {
        let (n, client) = socket.recv_from(&mut datagram).await?;
        let packet = datagram[..n].to_vec();
        let mut clients_guard = clients.lock().await;
        if let Some(tx) = clients_guard.get(&client) {
            match tx.try_send(packet) {
                Ok(()) => continue,
                // Congestion should drop a datagram, like ordinary UDP,
                // rather than replacing a live stream and orphaning it.
                Err(TrySendError::Full(_)) => {
                    warn!(%client, "TURN stream bridge queue full; dropping datagram");
                    continue;
                }
                Err(TrySendError::Closed(packet)) => {
                    clients_guard.remove(&client);
                    let (tx, rx) = mpsc::channel(128);
                    tx.try_send(packet)
                        .map_err(|_| io::Error::other("TURN stream bridge queue closed"))?;
                    let cleanup_tx = tx.clone();
                    clients_guard.insert(client, tx);
                    drop(clients_guard);
                    spawn_client_bridge(
                        socket.clone(),
                        clients.clone(),
                        client,
                        endpoint.clone(),
                        rx,
                        cleanup_tx,
                    );
                    continue;
                }
            }
        }
        let (tx, rx) = mpsc::channel(128);
        tx.try_send(packet)
            .map_err(|_| io::Error::other("TURN stream bridge queue closed"))?;
        let cleanup_tx = tx.clone();
        clients_guard.insert(client, tx);
        drop(clients_guard);
        spawn_client_bridge(
            socket.clone(),
            clients.clone(),
            client,
            endpoint.clone(),
            rx,
            cleanup_tx,
        );
    }
}

fn spawn_client_bridge(
    socket: Arc<UdpSocket>,
    clients: Arc<Mutex<HashMap<SocketAddr, mpsc::Sender<Vec<u8>>>>>,
    client: SocketAddr,
    endpoint: StreamEndpoint,
    rx: mpsc::Receiver<Vec<u8>>,
    cleanup_tx: mpsc::Sender<Vec<u8>>,
) {
    tokio::spawn(async move {
        if let Err(error) = bridge_client(socket, client, endpoint, rx).await {
            debug!(%client, %error, "TURN stream connection ended");
        }
        let mut clients = clients.lock().await;
        if clients
            .get(&client)
            .is_some_and(|current| current.same_channel(&cleanup_tx))
        {
            clients.remove(&client);
        }
    });
}

async fn bridge_client(
    udp: Arc<UdpSocket>,
    client: SocketAddr,
    endpoint: StreamEndpoint,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TURN TCP connect timed out"))??;
    tcp.set_nodelay(true)?;
    let stream: Box<dyn TurnStream> = if endpoint.tls {
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let name = ServerName::try_from(endpoint.host.clone())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid TURN TLS name"))?;
        Box::new(
            timeout(
                CONNECT_TIMEOUT,
                TlsConnector::from(Arc::new(config)).connect(name, tcp),
            )
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "TURN TLS timed out"))??,
        )
    } else {
        Box::new(tcp)
    };
    let (mut reader, mut writer) = tokio::io::split(stream);
    let idle = tokio::time::sleep(CLIENT_IDLE_TIMEOUT);
    tokio::pin!(idle);
    loop {
        tokio::select! {
            packet = packets.recv() => match packet {
                Some(packet) => write_frame(&mut writer, &packet).await?,
                None => return Ok(()),
            },
            result = read_frame(&mut reader) => {
                let frame = result?;
                udp.send_to(&frame, client).await?;
            },
            _ = &mut idle => {
                return Err(io::Error::new(io::ErrorKind::TimedOut, "TURN stream idle timeout"));
            }
        }
        idle.as_mut().reset(Instant::now() + CLIENT_IDLE_TIMEOUT);
    }
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0u8; 4];
    reader.read_exact(&mut header).await?;
    let body = u16::from_be_bytes([header[2], header[3]]) as usize;
    let channel = header[0] & 0xc0 == 0x40;
    let len = if channel {
        4 + body
    } else if header[0] & 0xc0 == 0 {
        20 + body
    } else {
        0
    };
    if !(4..=MAX_TURN_FRAME).contains(&len) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid TURN stream frame",
        ));
    }
    let padded = if channel { (len + 3) & !3 } else { len };
    let mut frame = vec![0; padded];
    frame[..4].copy_from_slice(&header);
    reader.read_exact(&mut frame[4..]).await?;
    frame.truncate(len);
    Ok(frame)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    writer.write_all(frame).await?;
    if frame.first().is_some_and(|b| b & 0xc0 == 0x40) {
        let pad = (4 - frame.len() % 4) % 4;
        writer.write_all(&[0u8; 3][..pad]).await?;
    }
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

    #[test]
    fn parses_tcp_and_tls_turn_urls_only() {
        assert!(parse_stream_url("turn:host:3478").is_none());
        assert_eq!(
            parse_stream_url("turn:host:3478?transport=tcp")
                .unwrap()
                .port,
            3478
        );
        let tls = parse_stream_url("turns:turn.example.com:5349?transport=tcp").unwrap();
        assert!(tls.tls);
        assert_eq!(tls.host, "turn.example.com");
    }

    #[tokio::test]
    async fn rewritten_tcp_url_round_trips_a_turn_frame() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let remote = listener.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let frame = read_frame(&mut stream).await.unwrap();
            write_frame(&mut stream, &frame).await.unwrap();
        });

        let bridges = TurnStreamBridges::default();
        let rewritten = bridges
            .rewrite(&[TurnServer {
                urls: vec![format!("turn:{remote}?transport=tcp")],
                username: Some("guest".into()),
                credential: Some("password".into()),
            }])
            .await;
        let local: SocketAddr = rewritten[0].urls[0]
            .trim_start_matches("turn:")
            .trim_end_matches("?transport=udp")
            .parse()
            .unwrap();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let request = [
            0x00, 0x01, 0x00, 0x00, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
        ];
        client.send_to(&request, local).await.unwrap();
        let mut response = [0u8; 64];
        let (received, _) = timeout(Duration::from_secs(2), client.recv_from(&mut response))
            .await
            .expect("local TURN stream bridge timed out")
            .unwrap();
        assert_eq!(&response[..received], &request);
        responder.await.unwrap();

        for bridge in bridges.bridges.lock().await.values() {
            bridge._task.abort();
        }
    }
}
