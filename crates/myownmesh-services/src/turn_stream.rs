//! Bounded TURN-over-TCP front end to the existing UDP allocation engine.
//!
//! The service's private runtime drives the accept loop. Client JoinHandles
//! and leases remain in outside-root-backed storage until joined; runtime
//! destruction precedes that storage's release on exceptional lifecycle exit.

use std::future::{poll_fn, Future};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Mutex;
use std::task::Poll;
use std::time::Duration;

use myownmesh_core::{
    FundedArc, LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::{Error, Result, ServiceCleanupError};

const MAX_TURN_FRAME: usize = 65_556;
// Local structural ceiling, checked before reading any variable-length header.
const MAX_PROXY_BODY: usize = 512;

struct ClientEntry {
    id: u64,
    proxy: bool,
    peer_ip: Option<IpAddr>,
    task: Option<JoinHandle<io::Result<()>>>,
    // Stored outside the task, so panic/abort cannot refund before its join.
    _lease: ResourceLease,
}

pub(crate) struct BridgeState {
    clients: Mutex<Vec<ClientEntry>>,
    max_connections: usize,
    max_per_ip: usize,
    idle_timeout: Duration,
    auth_timeout: Duration,
    paired: bool,
}

impl BridgeState {
    pub(crate) fn join_after_runtime_destroyed(&self) {
        // Only the outside service custodian calls this after the private OS
        // worker has joined. Runtime::drop already destroyed every task future.
        // Still consume each exact JoinHandle result before refunding its node.
        let mut clients = self
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut context = std::task::Context::from_waker(std::task::Waker::noop());
        for client in clients.iter_mut() {
            if let Some(mut task) = client.task.take() {
                if Pin::new(&mut task).poll(&mut context).is_pending() {
                    // Contradicts the private-runtime terminal boundary. No
                    // detach, retry loop, early refund or unowned reaper.
                    std::process::abort();
                }
            }
        }
        clients.clear();
    }
}

pub(crate) fn root_claim(
    max_connections: usize,
    listeners: u64,
) -> std::result::Result<ResourceClaim, ServiceCleanupError> {
    let slots = max_connections
        .checked_mul(std::mem::size_of::<ClientEntry>())
        .ok_or_else(super::turn::byte_overflow)?;
    let bytes = slots
        .checked_add(std::mem::size_of::<TurnTcpBridge>())
        .and_then(|n| n.checked_add(std::mem::size_of::<TcpStream>()))
        .ok_or_else(super::turn::byte_overflow)?;
    crate::cleanup::record_claim::<BridgeState>()?
        .checked_add(super::turn::claim_bytes(bytes, 1)?)?
        // Listener plus one bounded just-accepted socket, before its peer IP
        // is known and before per-client admission. Refused sockets drop now.
        .checked_add(ResourceClaim::single(
            ResourceClass::SocketOrHandle,
            listeners + 1,
        ))
        .map_err(Into::into)
}

pub(crate) fn client_claim() -> std::result::Result<ResourceClaim, ServiceCleanupError> {
    fn future_bytes<F: Future>(
        _: impl FnOnce(TcpStream, SocketAddr, bool, FundedArc<BridgeState>, u64, Instant) -> F,
    ) -> usize {
        std::mem::size_of::<F>()
    }
    let bytes = (2 * MAX_TURN_FRAME)
        .checked_add(future_bytes(admitted_client))
        .ok_or_else(super::turn::byte_overflow)?;
    super::turn::claim_bytes(bytes, 1)?
        .checked_add(ResourceClaim::single(ResourceClass::SocketOrHandle, 2))?
        .checked_add(ResourceClaim::single(ResourceClass::WorkerOrTask, 1))
        .map_err(Into::into)
}

pub(crate) fn reserve(
    scope: &LocalApplicationResourceScope,
    max_connections: usize,
    max_per_ip: usize,
    idle_timeout: Duration,
    auth_timeout: Duration,
    listeners: u64,
) -> Result<FundedArc<BridgeState>> {
    if listeners == 2 && (max_connections < 2 || max_per_ip < 2) {
        return Err(Error::TurnConfig(
            "two TURN stream listener classes require at least two total and per-IP slots".into(),
        ));
    }
    let lease = scope
        .acquire(root_claim(max_connections, listeners)?)
        .map_err(ServiceCleanupError::from)?;
    let mut clients = Vec::new();
    clients
        .try_reserve_exact(max_connections)
        .map_err(|_| Error::Resource("TURN TCP slot storage unavailable".into()))?;
    Ok(crate::cleanup::funded(
        BridgeState {
            clients: Mutex::new(clients),
            max_connections,
            max_per_ip,
            idle_timeout,
            auth_timeout,
            paired: listeners == 2,
        },
        lease,
    ))
}

pub(crate) struct TurnTcpBridge {
    direct: Option<TcpListener>,
    proxy: Option<TcpListener>,
    state: FundedArc<BridgeState>,
    udp_target: SocketAddr,
    scope: LocalApplicationResourceScope,
}

impl TurnTcpBridge {
    pub(crate) async fn bind(
        udp_addr: SocketAddr,
        state: FundedArc<BridgeState>,
        scope: LocalApplicationResourceScope,
        direct_enabled: bool,
        proxy_port: Option<u16>,
    ) -> Result<Self> {
        let direct = if direct_enabled {
            Some(
                TcpListener::bind(udp_addr)
                    .await
                    .map_err(|e| Error::Bind(udp_addr.to_string(), e))?,
            )
        } else {
            None
        };
        let proxy = if let Some(port) = proxy_port {
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port);
            Some(
                TcpListener::bind(addr)
                    .await
                    .map_err(|e| Error::Bind(addr.to_string(), e))?,
            )
        } else {
            None
        };
        let ip = match udp_addr.ip() {
            IpAddr::V4(ip) if ip.is_unspecified() => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(ip) if ip.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
            ip => ip,
        };
        Ok(Self {
            direct,
            proxy,
            state,
            udp_target: SocketAddr::new(ip, udp_addr.port()),
            scope,
        })
    }

    // No accept task is spawned: this loop is awaited by the already-admitted
    // service lifecycle task on its private runtime.
    pub(crate) async fn run(self, stop: impl Future<Output = ()>) -> Result<()> {
        let Self {
            direct,
            proxy,
            state,
            udp_target,
            scope,
        } = self;
        tokio::pin!(stop);
        let mut first_failure = None;
        let mut next_id = 0u64;
        loop {
            tokio::select! {
                biased;
                () = &mut stop => break,
                result = next_completed(&state) => record_failure(&mut first_failure, result, false),
                accepted = accept_one(&direct, &proxy) => {
                    let (stream, peer, is_proxy) = match accepted {
                        Ok(accepted) => accepted,
                        Err(error) => { first_failure.get_or_insert(error); break; }
                    };
                    let mut clients = state.clients.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                    let peer_ip = normalize_ip(peer.ip());
                    let accepted_at = Instant::now();
                    if (is_proxy && !peer_ip.is_loopback())
                        || !has_capacity(&clients, (!is_proxy).then_some(peer_ip), is_proxy, &state) {
                        drop(stream);
                        continue;
                    }
                    let claim = match client_claim() {
                        Ok(claim) => claim,
                        Err(_) => { drop(stream); first_failure.get_or_insert(io::Error::from(io::ErrorKind::InvalidInput)); break; }
                    };
                    let lease = match scope.acquire(claim) {
                        Ok(lease) => lease,
                        Err(_) => { drop(stream); continue; }
                    };
                    // No await between spawn and filing the exact handle. The
                    // slot vector was preallocated before listener creation.
                    let Some(id) = next_id.checked_add(1) else {
                        drop(stream);
                        first_failure.get_or_insert(io::Error::from(io::ErrorKind::Other));
                        break;
                    };
                    next_id = id;
                    // Registration (including pending PROXY headers) precedes
                    // spawn. Pending headers consume the SAME global cap and
                    // client grant; original-IP admission precedes UDP creation.
                    clients.push(ClientEntry { id, proxy: is_proxy, peer_ip: (!is_proxy).then_some(peer_ip), task: None, _lease: lease });
                    let task = tokio::spawn(admitted_client(stream, udp_target, is_proxy, state.clone(), id, accepted_at));
                    clients.last_mut().expect("just registered").task = Some(task);
                }
            }
        }
        drop((direct, proxy));
        {
            let clients = state
                .clients
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            for client in clients.iter() {
                if let Some(task) = &client.task {
                    task.abort();
                }
            }
        }
        while !state
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_empty()
        {
            record_failure(&mut first_failure, next_completed(&state).await, true);
        }
        match first_failure {
            Some(error) => Err(Error::Turn(format!("TCP bridge: {error}"))),
            None => Ok(()),
        }
    }
}

fn class_limit(limit: usize, proxy: bool, paired: bool) -> usize {
    if !paired {
        limit
    } else if proxy {
        limit - limit / 2
    } else {
        limit / 2
    }
}

fn has_capacity(
    clients: &[ClientEntry],
    ip: Option<IpAddr>,
    proxy: bool,
    state: &BridgeState,
) -> bool {
    // Non-borrowable class reservations prevent unauthenticated plaintext
    // clients from consuming the TLS backend's slots (including per-IP quota).
    clients.len() < state.max_connections
        && clients
            .iter()
            .filter(|client| client.proxy == proxy)
            .count()
            < class_limit(state.max_connections, proxy, state.paired)
        && ip.is_none_or(|ip| {
            clients
                .iter()
                .filter(|client| client.proxy == proxy && client.peer_ip == Some(ip))
                .count()
                < class_limit(state.max_per_ip, proxy, state.paired)
        })
}

async fn accept_one(
    direct: &Option<TcpListener>,
    proxy: &Option<TcpListener>,
) -> io::Result<(TcpStream, SocketAddr, bool)> {
    async fn accept(listener: &Option<TcpListener>) -> io::Result<(TcpStream, SocketAddr)> {
        match listener {
            Some(listener) => listener.accept().await,
            None => std::future::pending().await,
        }
    }
    tokio::select! {
        result = accept(direct) => result.map(|(stream, peer)| (stream, peer, false)),
        result = accept(proxy) => result.map(|(stream, peer)| (stream, peer, true)),
    }
}

fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(ip) => ip
            .to_ipv4_mapped()
            .map(IpAddr::V4)
            .unwrap_or(IpAddr::V6(ip)),
        ip => ip,
    }
}

async fn admitted_client(
    mut stream: TcpStream,
    target: SocketAddr,
    proxy: bool,
    state: FundedArc<BridgeState>,
    id: u64,
    accepted_at: Instant,
) -> io::Result<()> {
    let deadline = accepted_at
        .checked_add(state.auth_timeout)
        .ok_or(io::ErrorKind::InvalidInput)?;
    if proxy {
        let source = match tokio::time::timeout_at(deadline, read_proxy_v2(&mut stream)).await {
            Ok(Ok(source)) => source,
            Ok(Err(error)) => return peer_end(error),
            Err(_) => return Ok(()),
        };
        let mut clients = state
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if clients
            .iter()
            .filter(|client| client.proxy && client.peer_ip == Some(source))
            .count()
            >= class_limit(state.max_per_ip, true, state.paired)
        {
            return Ok(());
        }
        clients
            .iter_mut()
            .find(|client| client.id == id)
            .expect("admitted node remains registered")
            .peer_ip = Some(source);
    }
    if Instant::now() >= deadline {
        return Ok(());
    }
    bridge_connection(stream, target, state.idle_timeout, deadline).await
}

async fn read_proxy_v2<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<IpAddr> {
    let mut header = [0u8; 16];
    reader.read_exact(&mut header).await?;
    if &header[..12] != b"\r\n\r\n\0\r\nQUIT\n" || header[12] != 0x21 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let len = usize::from(u16::from_be_bytes([header[14], header[15]]));
    let address_len = match header[13] {
        0x11 => 12,
        0x21 => 36,
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    if !(address_len..=MAX_PROXY_BODY).contains(&len) {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let mut body = [0u8; MAX_PROXY_BODY];
    reader.read_exact(&mut body[..len]).await?;
    let source = if address_len == 12 {
        IpAddr::V4(Ipv4Addr::new(body[0], body[1], body[2], body[3]))
    } else {
        let mut ip = [0u8; 16];
        ip.copy_from_slice(&body[..16]);
        normalize_ip(IpAddr::V6(Ipv6Addr::from(ip)))
    };
    // TLVs may be present, but each must fit wholly in the bounded envelope.
    let mut cursor = address_len;
    while cursor < len {
        if len - cursor < 3 {
            return Err(io::ErrorKind::InvalidData.into());
        }
        let value_len = usize::from(u16::from_be_bytes([body[cursor + 1], body[cursor + 2]]));
        cursor += 3;
        if value_len > len - cursor {
            return Err(io::ErrorKind::InvalidData.into());
        }
        cursor += value_len;
    }
    if source.is_unspecified() || source.is_multicast() {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok(source)
}

async fn next_completed(
    state: &BridgeState,
) -> std::result::Result<io::Result<()>, tokio::task::JoinError> {
    poll_fn(|cx| {
        let mut clients = state
            .clients
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for index in 0..clients.len() {
            let Some(task) = clients[index].task.as_mut() else {
                continue;
            };
            if let Poll::Ready(result) = Pin::new(task).poll(cx) {
                // Poll Ready is the task join, not an is_finished guess. Its
                // buffers/sockets are gone before this entry refunds its lease.
                drop(clients.swap_remove(index));
                return Poll::Ready(result);
            }
        }
        Poll::Pending
    })
    .await
}

fn record_failure(
    first: &mut Option<io::Error>,
    result: std::result::Result<io::Result<()>, tokio::task::JoinError>,
    requested_abort: bool,
) {
    let error = match result {
        Ok(Ok(())) => return,
        Ok(Err(error)) => error,
        Err(error) if requested_abort && error.is_cancelled() => return,
        Err(_) => io::Error::from(io::ErrorKind::Other),
    };
    first.get_or_insert(error);
}

fn peer_end(error: io::Error) -> io::Result<()> {
    match error.kind() {
        io::ErrorKind::InvalidData
        | io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::BrokenPipe
        | io::ErrorKind::TimedOut => Ok(()),
        _ => Err(error),
    }
}

async fn bridge_connection(
    mut stream: TcpStream,
    udp_target: SocketAddr,
    idle_timeout: Duration,
    auth_deadline: Instant,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    let loopback = match udp_target.ip() {
        IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
        IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
    };
    let udp = UdpSocket::bind(SocketAddr::new(loopback, 0)).await?;
    udp.connect(udp_target).await?;
    let (mut reader, mut writer) = stream.split();
    let activity = Mutex::new(Instant::now());
    let authenticated = std::sync::atomic::AtomicBool::new(false);
    let auth_changed = tokio::sync::Notify::new();
    let mut inbound = vec![0u8; MAX_TURN_FRAME].into_boxed_slice();
    let mut outbound = vec![0u8; MAX_TURN_FRAME].into_boxed_slice();
    let to_udp = async {
        loop {
            let len = match read_turn_stream_frame(&mut reader, &mut inbound).await {
                Ok(Some(len)) => len,
                Ok(None) => return Ok::<(), io::Error>(()),
                Err(error) => return peer_end(error),
            };
            // The bridge target is ordinary UDP, not a jumbo datagram
            // transport. Oversized TCP frames are a client-local refusal,
            // never a remotely induced sticky service send failure.
            if len > 65_507 {
                return Ok(());
            }
            if udp.send(&inbound[..len]).await? != len {
                return Err(io::Error::from(io::ErrorKind::WriteZero));
            }
            *activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        }
    };
    let to_tcp = async {
        loop {
            let received = udp.recv(&mut outbound).await?;
            validate_datagram(&outbound[..received])?;
            if Instant::now() < auth_deadline && is_allocate_success(&outbound[..received]) {
                authenticated.store(true, std::sync::atomic::Ordering::Release);
                auth_changed.notify_one();
            }
            if let Err(error) = write_turn_stream_frame(&mut writer, &outbound[..received]).await {
                return peer_end(error);
            }
            *activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        }
    };
    let idle = async {
        loop {
            if !authenticated.load(std::sync::atomic::Ordering::Acquire) {
                tokio::select! {
                    () = tokio::time::sleep_until(auth_deadline) => {
                        if !authenticated.load(std::sync::atomic::Ordering::Acquire) { return; }
                    },
                    () = auth_changed.notified() => {},
                }
                continue;
            }
            let last = *activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            tokio::time::sleep_until(last + idle_timeout).await;
            if activity
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .elapsed()
                >= idle_timeout
            {
                return;
            }
        }
    };
    // Both directional futures are constructed once. Incoming UDP never
    // cancels an in-progress TCP header/body read (or a partial TCP write).
    // Only terminal EOF/error/idle/owner abort cancels the other direction.
    tokio::select! {
        result = to_udp => result,
        result = to_tcp => result,
        () = idle => Ok(()),
    }
}

fn frame_lengths(header: &[u8]) -> io::Result<(usize, usize)> {
    if header.len() < 4 {
        return Err(io::ErrorKind::InvalidData.into());
    }
    let body = usize::from(u16::from_be_bytes([header[2], header[3]]));
    let (len, padded) = match header[0] & 0xc0 {
        0 if body % 4 == 0 => (20 + body, 20 + body),
        0x40 => (4 + body, (4 + body + 3) & !3),
        _ => return Err(io::ErrorKind::InvalidData.into()),
    };
    if padded > MAX_TURN_FRAME {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((len, padded))
}

async fn read_turn_stream_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    buffer: &mut [u8],
) -> io::Result<Option<usize>> {
    if buffer.len() < MAX_TURN_FRAME {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    if reader.read(&mut buffer[..1]).await? == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut buffer[1..4]).await?;
    let (len, padded) = frame_lengths(&buffer[..4])?;
    if buffer[0] & 0xc0 == 0 {
        reader.read_exact(&mut buffer[4..20]).await?;
        if buffer[4..8] != [0x21, 0x12, 0xa4, 0x42] {
            return Err(io::ErrorKind::InvalidData.into());
        }
        reader.read_exact(&mut buffer[20..padded]).await?;
    } else {
        reader.read_exact(&mut buffer[4..padded]).await?;
    }
    Ok(Some(len))
}

fn validate_datagram(frame: &[u8]) -> io::Result<(usize, usize)> {
    let (len, padded) = frame_lengths(frame)?;
    // The UDP engine's ChannelData encoder includes four-byte alignment
    // padding. Accept exactly the encoded payload or its rounded length,
    // never a partial padding tail or another concatenated frame.
    if (frame.len() != len && frame.len() != padded)
        || (frame[0] & 0xc0 == 0 && frame[4..8] != [0x21, 0x12, 0xa4, 0x42])
    {
        return Err(io::ErrorKind::InvalidData.into());
    }
    Ok((len, padded))
}

fn is_allocate_success(frame: &[u8]) -> bool {
    if validate_datagram(frame).is_err() || frame[..2] != [0x01, 0x03] {
        return false;
    }
    let mut cursor = 20;
    while cursor < frame.len() {
        if frame.len() - cursor < 4 {
            return false;
        }
        let len = usize::from(u16::from_be_bytes([frame[cursor + 2], frame[cursor + 3]]));
        cursor += 4;
        let padded = (len + 3) & !3;
        if padded > frame.len() - cursor {
            return false;
        }
        cursor += padded;
    }
    true
}

async fn write_turn_stream_frame<W: AsyncWrite + Unpin>(
    writer: &mut W,
    frame: &[u8],
) -> io::Result<()> {
    let (len, padded) = validate_datagram(frame)?;
    writer.write_all(&frame[..len]).await?;
    writer.write_all(&[0u8; 3][..padded - len]).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn stun(typ: u16) -> Vec<u8> {
        let mut frame = vec![0; 20];
        frame[..2].copy_from_slice(&typ.to_be_bytes());
        frame[4..8].copy_from_slice(&[0x21, 0x12, 0xa4, 0x42]);
        frame
    }

    #[tokio::test]
    async fn framed_stun_and_padded_channel_preserve_coalesced_boundaries() {
        let binding = stun(1);
        let channel = [0x40, 1, 0, 3, 7, 8, 9];
        let mut wire = Vec::new();
        write_turn_stream_frame(&mut wire, &binding).await.unwrap();
        write_turn_stream_frame(&mut wire, &channel).await.unwrap();
        write_turn_stream_frame(&mut wire, &binding).await.unwrap();
        assert_eq!(wire.len(), 48);
        let mut reader = std::io::Cursor::new(wire);
        let mut buffer = vec![0; MAX_TURN_FRAME];
        for expected in [&binding[..], &channel[..], &binding[..]] {
            let len = read_turn_stream_frame(&mut reader, &mut buffer)
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..len], expected);
        }
        assert_eq!(
            read_turn_stream_frame(&mut reader, &mut buffer)
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn framing_refuses_partial_headers_bad_cookie_alignment_and_trailing_bytes() {
        let mut buffer = vec![0; MAX_TURN_FRAME];
        for frame in [vec![0], vec![0, 1, 0, 1], vec![0x80, 0, 0, 0], vec![0; 20]] {
            assert!(
                read_turn_stream_frame(&mut std::io::Cursor::new(frame), &mut buffer)
                    .await
                    .is_err()
            );
        }
        let mut trailing = stun(1);
        trailing.push(0);
        assert!(validate_datagram(&trailing).is_err());
        assert!(validate_datagram(&[0x40, 0, 0, 1, 3, 0]).is_err());
        assert!(validate_datagram(&[0x40, 0, 0, 1, 3, 0, 0, 0, 0]).is_err());
        assert_eq!(
            frame_lengths(&[0x40, 0, 0xff, 0xff]).unwrap(),
            (65_539, 65_540)
        );
        assert!(frame_lengths(&[0, 1, 0xff, 0xff]).is_err());
    }

    #[tokio::test]
    async fn vendor_padded_udp_channel_is_normalized_once_before_next_frame() {
        let mut channel = turn::proto::chandata::ChannelData {
            number: turn::proto::channum::ChannelNumber(0x4001),
            data: vec![1, 2, 3],
            raw: vec![],
        };
        channel.encode();
        assert_eq!(channel.raw, [0x40, 1, 0, 3, 1, 2, 3, 0]);
        let binding = stun(1);
        let mut wire = Vec::new();
        write_turn_stream_frame(&mut wire, &channel.raw)
            .await
            .unwrap();
        write_turn_stream_frame(&mut wire, &binding).await.unwrap();
        assert_eq!(wire.len(), 28);
        let mut reader = std::io::Cursor::new(wire);
        let mut buffer = vec![0; MAX_TURN_FRAME];
        let len = read_turn_stream_frame(&mut reader, &mut buffer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], &channel.raw[..7]);
        let len = read_turn_stream_frame(&mut reader, &mut buffer)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..len], &binding);
    }

    #[tokio::test]
    async fn proxy_v2_is_strict_bounded_and_normalizes_mapped_addresses() {
        let mut header = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
        header.extend_from_slice(&[0x21, 0x21, 0, 36]);
        let mapped: Ipv6Addr = "::ffff:192.0.2.1".parse().unwrap();
        header.extend_from_slice(&mapped.octets());
        header.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        header.extend_from_slice(&[0, 1, 0, 2]);
        assert_eq!(
            read_proxy_v2(&mut std::io::Cursor::new(&header))
                .await
                .unwrap(),
            "192.0.2.1".parse::<IpAddr>().unwrap()
        );
        let mut direct_buffer = vec![0; MAX_TURN_FRAME];
        assert!(
            read_turn_stream_frame(&mut std::io::Cursor::new(&header), &mut direct_buffer)
                .await
                .is_err()
        );
        header[12] = 0x20; // LOCAL is not an asserted remote identity.
        assert!(read_proxy_v2(&mut std::io::Cursor::new(&header))
            .await
            .is_err());
        header[12] = 0x21;
        header[14..16].copy_from_slice(&513u16.to_be_bytes());
        assert!(read_proxy_v2(&mut std::io::Cursor::new(&header))
            .await
            .is_err());
        header[14..16].copy_from_slice(&38u16.to_be_bytes());
        header.extend_from_slice(&[1, 0]); // truncated TLV envelope
        assert!(read_proxy_v2(&mut std::io::Cursor::new(&header))
            .await
            .is_err());
    }

    #[test]
    fn only_well_formed_allocate_success_can_end_preauthentication() {
        assert!(is_allocate_success(&stun(0x0103)));
        for typ in [0x0001, 0x0101, 0x0113, 0x0003] {
            assert!(!is_allocate_success(&stun(typ)));
        }
        let mut broken = stun(0x0103);
        broken[2..4].copy_from_slice(&4u16.to_be_bytes());
        broken.extend_from_slice(&[0, 1, 0, 8]);
        assert!(!is_allocate_success(&broken));
    }
}
