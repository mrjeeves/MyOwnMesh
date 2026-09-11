//! Peer-owned UDP-to-TURN-stream adaptation. No TURN credentials are consumed
//! here: the ICE client's authenticated packets pass through unchanged.
//!
//! One joined endpoint task multiplexes client futures. A client has a single
//! queued datagram; pressure drops UDP input, never replaces a live stream.
//! Provider residuals explicitly name dependency allocators/TLS/DNS/kernel state;
//! the byte claims below are owned buffers, not an estimate of process RSS.

use std::{future::Future, io, mem::size_of, net::SocketAddr, pin::Pin, sync::Arc};

use futures_util::{stream::FuturesUnordered, StreamExt};
use rustls::{pki_types::ServerName, ClientConfig, RootCertStore};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    sync::mpsc,
    task::JoinHandle,
    time::{timeout, timeout_at, Duration, Instant},
};
use tokio_rustls::TlsConnector;
use tokio_util::sync::CancellationToken;
use webrtc::peer_connection::configuration::RTCConfiguration;

use crate::{
    resource::{
        LeasedMap, LeasedQueue, ResourceAuthorityClass, ResourceClaim,
        ResourceClaimArithmeticError, ResourceClass, ResourceLease, ResourceUnavailable,
    },
    runtime::attempt::ConnectorWorkResourceScope,
};

pub(crate) const MAX_TURN_FRAME: usize = 65_556;
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

#[derive(Debug)]
pub(crate) enum TurnStreamError {
    InvalidUrl(&'static str),
    ResourcesRequired,
    Resources(ResourceUnavailable),
    Arithmetic(ResourceClaimArithmeticError),
    Io(io::Error),
}

impl std::fmt::Display for TurnStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidUrl(reason) => write!(f, "invalid TURN stream URL: {reason}"),
            Self::ResourcesRequired => f.write_str("TURN stream requires connector resources"),
            Self::Resources(error) => write!(f, "TURN stream admission: {error:?}"),
            Self::Arithmetic(error) => write!(f, "TURN stream claim: {error:?}"),
            Self::Io(error) => write!(f, "TURN stream: {error}"),
        }
    }
}
impl std::error::Error for TurnStreamError {}
impl From<io::Error> for TurnStreamError {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ResourceUnavailable> for TurnStreamError {
    fn from(e: ResourceUnavailable) -> Self {
        Self::Resources(e)
    }
}
impl From<ResourceClaimArithmeticError> for TurnStreamError {
    fn from(e: ResourceClaimArithmeticError) -> Self {
        Self::Arithmetic(e)
    }
}
impl From<TurnStreamError> for crate::error::Error {
    fn from(error: TurnStreamError) -> Self {
        match error {
            TurnStreamError::Resources(error) => Self::ResourceUnavailable(error),
            TurnStreamError::ResourcesRequired => Self::ConnectorPolicyRequired,
            TurnStreamError::Io(error) => Self::IoBare(error),
            error => Self::IoBare(io::Error::new(io::ErrorKind::InvalidInput, error)),
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct StreamEndpoint<'a> {
    host: &'a str,
    port: u16,
    tls: bool,
}

/// Borrowed validation, before listeners, owned host strings or tasks exist.
/// Ordinary UDP URLs pass through byte-for-byte; unsupported stream parameters
/// are errors rather than a silent downgrade or removal from the ICE list.
pub(crate) fn parse_stream_url(url: &str) -> Result<Option<StreamEndpoint<'_>>, TurnStreamError> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("turns:") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("turn:") {
        (false, rest)
    } else {
        return Ok(None);
    };
    let (authority, query) = rest.split_once('?').unwrap_or((rest, ""));
    if !tls && (query.is_empty() || query == "transport=udp") {
        return Ok(None);
    }
    if !(query == "transport=tcp" || (tls && query.is_empty())) {
        return Err(TurnStreamError::InvalidUrl(
            "unsupported transport parameters",
        ));
    }
    if authority.is_empty()
        || authority.len() > 259
        || authority
            .bytes()
            .any(|b| b.is_ascii_whitespace() || matches!(b, b'/' | b'@' | b'#' | b'%' | b'\\'))
    {
        return Err(TurnStreamError::InvalidUrl("invalid authority"));
    }
    let default_port = if tls { 5349 } else { 3478 };
    let (host, port_text) = if let Some(ipv6) = authority.strip_prefix('[') {
        let (host, suffix) = ipv6
            .split_once(']')
            .ok_or(TurnStreamError::InvalidUrl("unclosed IPv6 address"))?;
        host.parse::<std::net::Ipv6Addr>()
            .map_err(|_| TurnStreamError::InvalidUrl("invalid IPv6 address"))?;
        let port = if suffix.is_empty() {
            None
        } else {
            Some(
                suffix
                    .strip_prefix(':')
                    .ok_or(TurnStreamError::InvalidUrl("invalid port separator"))?,
            )
        };
        (host, port)
    } else if let Some((host, port)) = authority.split_once(':') {
        (host, Some(port))
    } else {
        (authority, None)
    };
    if host.is_empty() || host.len() > 253 || ServerName::try_from(host).is_err() {
        return Err(TurnStreamError::InvalidUrl("invalid server name"));
    }
    let port = match port_text {
        None => default_port,
        Some(text) if !text.is_empty() && text.bytes().all(|b| b.is_ascii_digit()) => text
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or(TurnStreamError::InvalidUrl("invalid port"))?,
        _ => return Err(TurnStreamError::InvalidUrl("invalid port")),
    };
    Ok(Some(StreamEndpoint { host, port, tls }))
}

#[derive(Clone)]
enum Resources {
    Connector(ConnectorWorkResourceScope),
    #[cfg(test)]
    Test(
        crate::resource::ResourceProviderPort,
        crate::resource::ResourceScope,
    ),
}
impl Resources {
    fn acquire(&self, claim: ResourceClaim) -> Result<ResourceLease, TurnStreamError> {
        Ok(match self {
            Self::Connector(scope) => scope.acquire(ResourceAuthorityClass::Speculative, claim)?,
            #[cfg(test)]
            Self::Test(provider, scope) => {
                provider.acquire(scope, ResourceAuthorityClass::Speculative, claim)?
            }
        })
    }
}

struct Endpoint {
    host: String,
    port: u16,
    tls: Option<Arc<ClientConfig>>,
}
struct Prepared {
    socket: Arc<UdpSocket>,
    endpoint: Arc<Endpoint>,
    resources: Resources,
}
struct BridgeSlot {
    prepared: Option<Prepared>,
    task: Option<JoinHandle<()>>,
    cancel: CancellationToken,
    // Lives outside the task allocation, through its JoinHandle terminal.
    _funding: ResourceLease,
}

pub(crate) struct TurnStreamBridges {
    slots: LeasedQueue<BridgeSlot>,
    // Joining one endpoint consumes its JoinError. Keep the first failure on
    // the owner, not the close future, while later endpoints are still pending.
    close_failure: Option<tokio::task::JoinError>,
}

pub(crate) fn endpoint_claim(
    host_bytes: usize,
) -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    // Datagram + host + rewritten URL + inline adapter and root anchor array.
    let fixed = MAX_TURN_FRAME
        + 64
        + size_of::<Prepared>()
        + size_of::<Reactor>()
        + size_of::<Endpoint>()
        + size_of::<ClientConfig>()
        + size_of::<Option<tokio::task::JoinError>>()
        + 4 * size_of::<usize>()
        + std::mem::size_of_val(webpki_roots::TLS_SERVER_ROOTS);
    // TCP deliberately uses the same conservative endpoint claim as TLS; no
    // default capacity is minted and no native/TLS heap is asserted to be RSS.
    let bytes = host_bytes
        .checked_add(fixed)
        .and_then(|n| u64::try_from(n).ok())
        .ok_or(ResourceClaimArithmeticError::Overflow {
            dimension: ResourceClass::AccountedMemoryBytes,
        })?;
    ResourceClaim::try_from_entries([
        (ResourceClass::AccountedMemoryBytes, bytes),
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 1),
        // Socket/kernel, Tokio task, cancellation tree, TLS config, two Arcs,
        // datagram allocation and FuturesUnordered's sentinel allocation.
        (ResourceClass::OpaqueDependencyResidual, 8),
    ])
}

pub(crate) fn client_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    ResourceClaim::try_from_entries([
        // One queued datagram, one writing datagram, one reading padded frame.
        (
            ResourceClass::AccountedMemoryBytes,
            (3 * MAX_TURN_FRAME + 253) as u64,
        ),
        (ResourceClass::QueuedBytes, MAX_TURN_FRAME as u64),
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::NativeTransportObject, 1),
        // A scheduled client future, NOT another spawned runtime task.
        (ResourceClass::WorkerOrTask, 1),
        // TCP/kernel, DNS, TLS state, channel, future box, future-list node,
        // I/O split, TLS server-name allocation and the three buffers.
        // The extra 253 bytes above bound the validated owned TLS server name.
        // No RSS equivalence.
        (ResourceClass::OpaqueDependencyResidual, 11),
    ])
}

pub(crate) fn endpoint_node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    LeasedQueue::<BridgeSlot>::entry_claim()
}

fn client_node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
    LeasedMap::<SocketAddr, ClientRecord>::entry_claim()
}

/// Additional finite-provider grant for a stated TURN stream fixture workload.
///
/// Each connector gets one endpoint per stream URL occurrence (duplicates are
/// not coalesced). Each endpoint acquires backing and a queue node separately;
/// each simultaneous local UDP client acquires backing and a map node separately.
/// Reservation metadata is therefore charged FOUR separate times for one
/// endpoint with one client, not once on their combined raw claim.
///
/// This is bridge-only planning, not admission or a production policy. Add the
/// result to the fixture's existing connector/scope/callback grant; it includes
/// no provider scope or base-connector charges. UDP URLs contribute zero. Both
/// TCP and TLS use the adapter's existing conservative endpoint claim.
///
/// The caller must count overlapping connectors and local UDP sources, including
/// any ICE restart overlap. The native initial relay gather binds once per URL,
/// but that is not a bound on repeated gathering over an endpoint's lifetime.
#[cfg(any(test, feature = "transport-lab"))]
pub fn transport_lab_turn_stream_fixture_grant(
    turn_servers: &[crate::config::TurnServer],
    concurrent_connectors: u64,
    clients_per_endpoint: u64,
) -> crate::Result<ResourceClaim> {
    use crate::resource::FiniteResourceProvider;

    let plan = || -> Result<ResourceClaim, TurnStreamError> {
        let mut total = ResourceClaim::ZERO;
        for server in turn_servers {
            for url in &server.urls {
                let Some(endpoint) = parse_stream_url(url)? else {
                    continue;
                };
                if concurrent_connectors == 0 {
                    continue;
                }
                let endpoint_backing = FiniteResourceProvider::reservation_planning_charge(
                    endpoint_claim(endpoint.host.len())?,
                )?;
                let endpoint_node =
                    FiniteResourceProvider::reservation_planning_charge(endpoint_node_claim()?)?;
                let client_backing =
                    FiniteResourceProvider::reservation_planning_charge(client_claim()?)?;
                let client_node =
                    FiniteResourceProvider::reservation_planning_charge(client_node_claim()?)?;
                let per_endpoint = endpoint_backing.checked_add(endpoint_node)?.checked_add(
                    client_backing
                        .checked_add(client_node)?
                        .checked_scale(clients_per_endpoint)?,
                )?;
                total = total.checked_add(per_endpoint.checked_scale(concurrent_connectors)?)?;
            }
        }
        Ok(total)
    };
    plan().map_err(crate::Error::from)
}

impl TurnStreamBridges {
    pub(crate) async fn prepare(
        config: &mut RTCConfiguration,
        scope: Option<&ConnectorWorkResourceScope>,
    ) -> Result<Option<Self>, TurnStreamError> {
        // Validate the complete set before any side effects, including a later
        // malformed URL following an otherwise valid stream URL.
        let mut has_stream = false;
        for server in &config.ice_servers {
            for url in &server.urls {
                has_stream |= parse_stream_url(url)?.is_some();
            }
        }
        if !has_stream {
            return Ok(None);
        }
        let resources =
            Resources::Connector(scope.ok_or(TurnStreamError::ResourcesRequired)?.clone());
        Self::prepare_with_resources(config, resources, None)
            .await
            .map(Some)
    }

    async fn prepare_with_resources(
        config: &mut RTCConfiguration,
        resources: Resources,
        test_tls: Option<Arc<ClientConfig>>,
    ) -> Result<Self, TurnStreamError> {
        let mut bridges = Self {
            slots: LeasedQueue::new(),
            close_failure: None,
        };
        for server in &mut config.ice_servers {
            for url in &mut server.urls {
                let Some(parsed) = parse_stream_url(url)? else {
                    continue;
                };
                let funding = resources.acquire(endpoint_claim(parsed.host.len())?)?;
                let node = resources.acquire(endpoint_node_claim()?)?;
                let tls = if parsed.tls {
                    // Test injection is accepted only by this private helper;
                    // production prepare always supplies None.
                    #[cfg(test)]
                    let override_config = test_tls.clone();
                    #[cfg(not(test))]
                    let override_config: Option<Arc<ClientConfig>> = {
                        let _ = &test_tls;
                        None
                    };
                    Some(override_config.unwrap_or_else(|| {
                        let mut roots = RootCertStore::empty();
                        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                        Arc::new(
                            ClientConfig::builder_with_provider(Arc::new(
                                rustls::crypto::ring::default_provider(),
                            ))
                            .with_safe_default_protocol_versions()
                            .expect("ring supports the default TLS versions")
                            .with_root_certificates(roots)
                            .with_no_client_auth(),
                        )
                    }))
                } else {
                    None
                };
                let endpoint = Arc::new(Endpoint {
                    host: parsed.host.to_owned(),
                    port: parsed.port,
                    tls,
                });
                let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await?);
                let rewritten = format!("turn:{}?transport=udp", socket.local_addr()?);
                bridges.slots.push(
                    BridgeSlot {
                        prepared: Some(Prepared {
                            socket,
                            endpoint,
                            resources: resources.clone(),
                        }),
                        task: None,
                        cancel: CancellationToken::new(),
                        _funding: funding,
                    },
                    node,
                );
                *url = rewritten;
            }
        }
        Ok(bridges)
    }

    /// Called synchronously only after this value belongs to the cleanup owner.
    pub(crate) fn start(&mut self) {
        for slot in self.slots.iter_mut() {
            if let Some(prepared) = slot.prepared.take() {
                let cancel = slot.cancel.clone();
                slot.task = Some(tokio::spawn(async move {
                    if let Err(error) = run_endpoint(prepared, cancel).await {
                        tracing::debug!(%error, "TURN stream endpoint stopped");
                    }
                }));
            }
        }
    }

    pub(crate) fn cancel(&mut self) {
        for slot in self.slots.iter_mut() {
            slot.cancel.cancel();
        }
    }

    /// Cancellation-safe join: the handle stays in its funded slot across await.
    pub(crate) async fn close(&mut self) -> Result<(), tokio::task::JoinError> {
        self.cancel();
        for slot in self.slots.iter_mut() {
            if let Some(task) = slot.task.as_mut() {
                if let Err(failure) = task.await {
                    if !failure.is_cancelled() && self.close_failure.is_none() {
                        self.close_failure = Some(failure);
                    }
                }
                slot.task.take();
            }
        }
        self.slots = LeasedQueue::new();
        // No await separates taking the latch from returning the completed
        // close result. Cancellation before this point leaves it on the owner.
        match self.close_failure.take() {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }

    /// Existing terminal-custodian thread calls this only on the Drop fallback.
    /// All handles and their funding move together; none is ever detached.
    pub(crate) fn close_blocking(
        mut self,
        mut join: impl FnMut(JoinHandle<()>),
        mut report_failure: impl FnMut(tokio::task::JoinError),
    ) {
        self.cancel();
        for slot in self.slots.iter_mut() {
            if let Some(task) = slot.task.take() {
                task.abort();
                join(task);
            }
        }
        // A cancelled asynchronous close may already have consumed a failed
        // handle. Its failure must reach the terminal recorder as well as the
        // results of the handles still present. This path has no cancellation
        // points between consuming the latch and reporting it.
        if let Some(failure) = self.close_failure.take() {
            report_failure(failure);
        }
    }
}

type ClientFuture = Pin<Box<dyn Future<Output = (SocketAddr, io::Result<()>)> + Send>>;
struct ClientRecord {
    sender: mpsc::Sender<Vec<u8>>,
    _funding: ResourceLease,
}
struct Reactor {
    // Declaration order is custody: futures (sockets/buffers) disappear before
    // map records release their client leases on cancellation or panic.
    clients: FuturesUnordered<ClientFuture>,
    records: LeasedMap<SocketAddr, ClientRecord>,
}

async fn run_endpoint(prepared: Prepared, cancel: CancellationToken) -> io::Result<()> {
    let Prepared {
        socket,
        endpoint,
        resources,
    } = prepared;
    let mut reactor = Reactor {
        clients: FuturesUnordered::new(),
        records: LeasedMap::new(),
    };
    let mut datagram = vec![0; MAX_TURN_FRAME];
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => return Ok(()),
            Some((client, result)) = reactor.clients.next(), if !reactor.clients.is_empty() => {
                drop(result);
                reactor.records.remove(&client);
            }
            received = socket.recv_from(&mut datagram) => {
                let (length, client) = received?;
                if !client.ip().is_loopback() || validate_datagram(&datagram[..length]).is_err() { continue; }
                if let Some(record) = reactor.records.get(&client) {
                    if let Ok(permit) = record.sender.try_reserve() { permit.send(datagram[..length].to_vec()); }
                    continue;
                }
                let funding = match client_claim().map_err(TurnStreamError::from).and_then(|claim| resources.acquire(claim)) { Ok(lease) => lease, Err(_) => continue };
                let node = match client_node_claim().map_err(TurnStreamError::from).and_then(|claim| resources.acquire(claim)) { Ok(lease) => lease, Err(_) => continue };
                let (sender, receiver) = mpsc::channel(1);
                // First send cannot be full; perform it only after all backing
                // has been admitted and before publishing this client's future.
                if sender.try_send(datagram[..length].to_vec()).is_err() { continue; }
                reactor.records.insert(client, ClientRecord { sender, _funding: funding }, node).expect("new local client key");
                let endpoint = Arc::clone(&endpoint);
                let socket = Arc::clone(&socket);
                reactor.clients.push(Box::pin(async move { (client, bridge_client(socket, client, endpoint, receiver).await) }));
            }
        }
    }
}

trait TurnIo: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TurnIo for T {}

async fn bridge_client(
    udp: Arc<UdpSocket>,
    client: SocketAddr,
    endpoint: Arc<Endpoint>,
    mut packets: mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let stream = connect_endpoint(&endpoint).await?;
    pump_client(stream, udp, client, &mut packets).await
}

async fn connect_endpoint(endpoint: &Endpoint) -> io::Result<Box<dyn TurnIo>> {
    let tcp = timeout(
        CONNECT_TIMEOUT,
        TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| timed_out())??;
    tcp.set_nodelay(true)?;
    let stream: Box<dyn TurnIo> = if let Some(config) = endpoint.tls.as_ref() {
        let name = ServerName::try_from(endpoint.host.clone()).map_err(|_| invalid_frame())?;
        let tls = TlsConnector::from(Arc::clone(config)).connect_with(name, tcp, |connection| {
            connection.set_buffer_limit(Some(MAX_TURN_FRAME))
        });
        Box::new(
            timeout(CONNECT_TIMEOUT, tls)
                .await
                .map_err(|_| timed_out())??,
        )
    } else {
        Box::new(tcp)
    };
    Ok(stream)
}

async fn pump_client(
    stream: Box<dyn TurnIo>,
    udp: Arc<UdpSocket>,
    client: SocketAddr,
    packets: &mut mpsc::Receiver<Vec<u8>>,
) -> io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut deadline = Instant::now() + CLIENT_IDLE_TIMEOUT;
    loop {
        // Keep this read future alive across every outgoing packet. Restarting
        // read_exact in select would silently discard partial stream headers.
        let incoming = read_frame(&mut reader);
        tokio::pin!(incoming);
        let frame = loop {
            tokio::select! {
                result = &mut incoming => break result?,
                packet = packets.recv() => match packet {
                    None => return Ok(()),
                    Some(packet) => {
                        timeout_at(deadline, write_frame(&mut writer, &packet)).await.map_err(|_| timed_out())??;
                        deadline = Instant::now() + CLIENT_IDLE_TIMEOUT;
                    }
                },
                _ = tokio::time::sleep_until(deadline) => return Err(timed_out()),
            }
        };
        timeout_at(deadline, udp.send_to(&frame, client))
            .await
            .map_err(|_| timed_out())??;
        deadline = Instant::now() + CLIENT_IDLE_TIMEOUT;
    }
}

fn invalid_frame() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "invalid TURN stream frame")
}
fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "TURN stream timeout")
}

fn frame_lengths(header: &[u8]) -> io::Result<(usize, usize)> {
    if header.len() < 4 {
        return Err(invalid_frame());
    }
    let body = u16::from_be_bytes([header[2], header[3]]) as usize;
    let (length, padded) = match header[0] & 0xc0 {
        0 if body % 4 == 0 => (20 + body, 20 + body),
        0x40 => (4 + body, (4 + body + 3) & !3),
        _ => return Err(invalid_frame()),
    };
    if padded > MAX_TURN_FRAME {
        return Err(invalid_frame());
    }
    Ok((length, padded))
}

fn validate_datagram(frame: &[u8]) -> io::Result<()> {
    let (length, padded) = frame_lengths(frame)?;
    if frame.len() != length && !(frame[0] & 0xc0 == 0x40 && frame.len() == padded) {
        return Err(invalid_frame());
    }
    if frame[0] & 0xc0 == 0 && frame.get(4..8) != Some(&[0x21, 0x12, 0xa4, 0x42]) {
        return Err(invalid_frame());
    }
    Ok(())
}

async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut header = [0; 4];
    reader.read_exact(&mut header).await?;
    let (length, padded) = frame_lengths(&header)?;
    let mut frame = vec![0; padded];
    frame[..4].copy_from_slice(&header);
    reader.read_exact(&mut frame[4..]).await?;
    validate_datagram(&frame)?;
    frame.truncate(length);
    Ok(frame)
}

async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, frame: &[u8]) -> io::Result<()> {
    validate_datagram(frame)?;
    let (length, padded) = frame_lengths(frame)?;
    writer.write_all(&frame[..length]).await?;
    writer.write_all(&[0; 3][..padded - length]).await?;
    writer.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{FiniteResourceProvider, ResourceProviderPort};
    use tokio::net::TcpListener;
    use webrtc::ice_transport::ice_server::RTCIceServer;

    const STUN: [u8; 20] = [
        0, 1, 0, 0, 0x21, 0x12, 0xa4, 0x42, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
    ];

    fn resources(host: &str, clients: u64) -> (FiniteResourceProvider, Resources, ResourceClaim) {
        let charged = |claim| FiniteResourceProvider::reservation_planning_charge(claim).unwrap();
        let baseline = FiniteResourceProvider::scope_planning_charge();
        let grant = baseline
            .checked_add(charged(endpoint_claim(host.len()).unwrap()))
            .unwrap()
            .checked_add(charged(LeasedQueue::<BridgeSlot>::entry_claim().unwrap()))
            .unwrap()
            .checked_add(
                charged(client_claim().unwrap())
                    .checked_scale(clients)
                    .unwrap(),
            )
            .unwrap()
            .checked_add(
                charged(LeasedMap::<SocketAddr, ClientRecord>::entry_claim().unwrap())
                    .checked_scale(clients)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = port.process_scope();
        assert_eq!(provider.in_use(), baseline);
        (provider, Resources::Test(port, scope), baseline)
    }

    fn config(url: String) -> RTCConfiguration {
        RTCConfiguration {
            ice_servers: vec![RTCIceServer {
                urls: vec![url],
                username: "alice".into(),
                credential: "unchanged-secret".into(),
            }],
            ..Default::default()
        }
    }
    fn local(config: &RTCConfiguration) -> SocketAddr {
        config.ice_servers[0].urls[0]
            .strip_prefix("turn:")
            .unwrap()
            .strip_suffix("?transport=udp")
            .unwrap()
            .parse()
            .unwrap()
    }

    fn planner_servers() -> Vec<crate::config::TurnServer> {
        vec![crate::config::TurnServer {
            // Duplicate URLs are two listeners in the actual prepare loop.
            urls: vec![
                "turn:127.0.0.1:3478?transport=tcp".into(),
                "turn:127.0.0.1:3478?transport=tcp".into(),
                "turn:127.0.0.1:3478?transport=udp".into(),
            ],
            username: None,
            credential: None,
        }]
    }

    async fn acquire_planner_workload(
        servers: &[crate::config::TurnServer],
        funding: &Resources,
        connectors: u64,
        clients_per_endpoint: u64,
    ) -> Result<(Vec<TurnStreamBridges>, Vec<ResourceLease>), TurnStreamError> {
        let mut endpoints = Vec::new();
        let mut clients = Vec::new();
        for _ in 0..connectors {
            let mut config = crate::transport::ice::build_rtc_configuration(&[], servers);
            // Actual constructor acquisitions/listeners; do not spawn tasks.
            let mut bridge =
                TurnStreamBridges::prepare_with_resources(&mut config, funding.clone(), None)
                    .await?;
            for _ in bridge.slots.iter() {
                for _ in 0..clients_per_endpoint {
                    // Exercise the runtime's separate client acquisition pair,
                    // not an aggregate acquire of the planner's grant. This
                    // control prices admission, not native client execution.
                    clients.push(funding.acquire(client_claim()?)?);
                    clients.push(funding.acquire(client_node_claim()?)?);
                }
            }
            endpoints.push(bridge);
        }
        Ok((endpoints, clients))
    }

    #[tokio::test]
    async fn lab_grant_exact_fit_matches_each_endpoint_and_client_reservation() {
        let servers = planner_servers();
        let planned = transport_lab_turn_stream_fixture_grant(&servers, 2, 2).unwrap();
        let baseline = FiniteResourceProvider::scope_planning_charge();
        let full = baseline.checked_add(planned).unwrap();
        let provider = FiniteResourceProvider::new(full);
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let funding = Resources::Test(port.clone(), port.process_scope());
        let held = acquire_planner_workload(&servers, &funding, 2, 2)
            .await
            .unwrap();
        assert_eq!(provider.in_use(), full);
        // 4 endpoint backings + 4 endpoint nodes + 8 client backings + 8 nodes.
        assert_eq!(provider.active_reservations(), 24);
        assert!(matches!(
            funding.acquire(ResourceClaim::single(
                ResourceClass::OpaqueDependencyResidual,
                1
            )),
            Err(TurnStreamError::Resources(ResourceUnavailable::Pressure(_)))
        ));
        drop(held);
        assert_eq!(provider.in_use(), baseline);
        drop(funding);
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[tokio::test]
    async fn lab_grant_minus_one_refuses_in_each_charged_dimension_and_unwinds() {
        let servers = planner_servers();
        let planned = transport_lab_turn_stream_fixture_grant(&servers, 2, 2).unwrap();
        let baseline = FiniteResourceProvider::scope_planning_charge();
        for dimension in ResourceClass::ALL {
            if planned.amount(dimension) == 0 {
                continue;
            }
            let short = baseline
                .checked_add(planned)
                .unwrap()
                .checked_sub(ResourceClaim::single(dimension, 1))
                .unwrap();
            let provider = FiniteResourceProvider::new(short);
            let port = ResourceProviderPort::new(provider.clone()).unwrap();
            let funding = Resources::Test(port.clone(), port.process_scope());
            let result = acquire_planner_workload(&servers, &funding, 2, 2).await;
            assert!(
                matches!(result, Err(TurnStreamError::Resources(ResourceUnavailable::Pressure(pressure))) if pressure.dimension == dimension),
                "{dimension:?}"
            );
            assert_eq!(
                provider.in_use(),
                baseline,
                "refusal releases partial listener/client admission"
            );
            assert_eq!(provider.active_reservations(), 0);
            drop(funding);
            drop(port);
            assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        }
    }

    #[test]
    fn lab_grant_counts_duplicates_ignores_udp_and_checks_zero_overflow_and_urls() {
        let servers = planner_servers();
        let one = vec![crate::config::TurnServer {
            urls: vec![servers[0].urls[0].clone()],
            username: None,
            credential: None,
        }];
        let single = transport_lab_turn_stream_fixture_grant(&one, 1, 1).unwrap();
        let charged = |claim| FiniteResourceProvider::reservation_planning_charge(claim).unwrap();
        let expected = charged(endpoint_claim(9).unwrap())
            .checked_add(charged(endpoint_node_claim().unwrap()))
            .unwrap()
            .checked_add(charged(client_claim().unwrap()))
            .unwrap()
            .checked_add(charged(client_node_claim().unwrap()))
            .unwrap();
        assert_eq!(single, expected);
        assert_eq!(
            transport_lab_turn_stream_fixture_grant(&servers, 3, 1).unwrap(),
            single.checked_scale(6).unwrap()
        );
        assert_eq!(
            transport_lab_turn_stream_fixture_grant(&servers, 0, u64::MAX).unwrap(),
            ResourceClaim::ZERO
        );
        let udp = vec![crate::config::TurnServer {
            urls: vec![servers[0].urls[2].clone()],
            username: None,
            credential: None,
        }];
        assert_eq!(
            transport_lab_turn_stream_fixture_grant(&udp, u64::MAX, u64::MAX).unwrap(),
            ResourceClaim::ZERO
        );
        assert!(transport_lab_turn_stream_fixture_grant(&one, u64::MAX, 1).is_err());
        assert!(transport_lab_turn_stream_fixture_grant(&one, 1, u64::MAX).is_err());
        assert_eq!(
            transport_lab_turn_stream_fixture_grant(&one, 1, 0).unwrap(),
            charged(endpoint_claim(9).unwrap())
                .checked_add(charged(endpoint_node_claim().unwrap()))
                .unwrap()
        );
        let malformed = vec![crate::config::TurnServer {
            urls: vec!["turns:host:0".into()],
            username: None,
            credential: None,
        }];
        assert!(
            transport_lab_turn_stream_fixture_grant(&malformed, 0, 0).is_err(),
            "zero workload does not hide malformed URLs"
        );
    }

    #[test]
    fn stream_url_validation_preserves_udp_and_refuses_bad_stream_authorities() {
        for url in [
            "turn:host",
            "turn:host:3478?transport=udp",
            "stun:host:3478",
        ] {
            assert!(parse_stream_url(url).unwrap().is_none());
        }
        assert_eq!(
            parse_stream_url("turn:example.com?transport=tcp").unwrap(),
            Some(StreamEndpoint {
                host: "example.com",
                port: 3478,
                tls: false
            })
        );
        assert_eq!(
            parse_stream_url("turns:[::1]:5349").unwrap(),
            Some(StreamEndpoint {
                host: "::1",
                port: 5349,
                tls: true
            })
        );
        assert_eq!(
            parse_stream_url("turns:localhost").unwrap().unwrap().port,
            5349
        );
        for url in [
            "turns:",
            "turns:host:0",
            "turns:host:65536",
            "turns:host:",
            "turns:[::1]junk",
            "turns:[::1]:no",
            "turns:user@host",
            "turns:host/path",
            "turns:host?transport=udp",
            "turn:host?transport=tcp&x=1",
            "turns://host",
            "turns:host#x",
        ] {
            assert!(
                matches!(parse_stream_url(url), Err(TurnStreamError::InvalidUrl(_))),
                "{url}"
            );
        }
    }

    #[tokio::test]
    async fn invalid_stream_refuses_before_native_or_listener_and_udp_needs_no_scope() {
        let mut udp = config("turn:127.0.0.1?transport=udp".into());
        let original = udp.ice_servers[0].urls.clone();
        assert!(TurnStreamBridges::prepare(&mut udp, None)
            .await
            .unwrap()
            .is_none());
        assert_eq!(udp.ice_servers[0].urls, original);
        let mut bad = config("turns:host:0".into());
        assert!(matches!(
            TurnStreamBridges::prepare(&mut bad, None).await,
            Err(TurnStreamError::InvalidUrl(_))
        ));
        let mut stream = config("turn:localhost?transport=tcp".into());
        assert!(matches!(
            TurnStreamBridges::prepare(&mut stream, None).await,
            Err(TurnStreamError::ResourcesRequired)
        ));
    }

    #[tokio::test]
    async fn forced_tcp_roundtrip_and_partial_header_survive_outbound_selection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (provider, funding, baseline) = resources("127.0.0.1", 1);
        let mut cfg = config(format!(
            "turn:{}?transport=tcp",
            listener.local_addr().unwrap()
        ));
        let mut bridge = TurnStreamBridges::prepare_with_resources(&mut cfg, funding.clone(), None)
            .await
            .unwrap();
        assert_eq!(cfg.ice_servers[0].username, "alice");
        assert_eq!(cfg.ice_servers[0].credential, "unchanged-secret");
        bridge.start();
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let (partial_tx, partial_rx) = tokio::sync::oneshot::channel();
        let server = async {
            let (mut stream, _) = listener.accept().await?;
            let first = read_frame(&mut stream).await?;
            stream.write_all(&first[..2]).await?;
            let _ = partial_tx.send(());
            // The client's second packet wins a select while the first response
            // header is incomplete. Its arrival is the barrier, not a sleep.
            let second = read_frame(&mut stream).await?;
            stream.write_all(&first[2..]).await?;
            write_frame(&mut stream, &second).await?;
            Ok::<_, io::Error>(())
        };
        let exchange = async {
            client.send_to(&STUN, local(&cfg)).await?;
            partial_rx.await.map_err(|_| invalid_frame())?;
            client.send_to(&[0x40, 1, 0, 1, 7], local(&cfg)).await?;
            let mut bytes = [0; 64];
            let (n, _) = client.recv_from(&mut bytes).await?;
            if bytes[..n] != STUN {
                return Err(invalid_frame());
            }
            let (n, _) = client.recv_from(&mut bytes).await?;
            if bytes[..n] != [0x40, 1, 0, 1, 7] {
                return Err(invalid_frame());
            }
            Ok::<_, io::Error>(())
        };
        let result = timeout(Duration::from_secs(3), async {
            tokio::try_join!(server, exchange)
        })
        .await;
        bridge.close().await.unwrap();
        assert_eq!(provider.in_use(), baseline);
        result.unwrap().unwrap();
    }

    fn tls_configs(name: &str, trust: bool) -> (Arc<rustls::ServerConfig>, Arc<ClientConfig>) {
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec![name.to_owned()]).unwrap();
        let mut roots = RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if trust {
            roots.add(cert.der().clone()).unwrap();
        }
        let key = rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());
        let server = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key.into())
        .unwrap();
        let client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        (Arc::new(server), Arc::new(client))
    }

    #[tokio::test]
    async fn forced_tls_roundtrip_checks_dns_name_with_test_only_root() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (server_config, client_config) = tls_configs("localhost", true);
        let (provider, funding, baseline) = resources("localhost", 1);
        let mut cfg = config(format!(
            "turns:localhost:{}",
            listener.local_addr().unwrap().port()
        ));
        let mut bridge = TurnStreamBridges::prepare_with_resources(
            &mut cfg,
            funding.clone(),
            Some(client_config),
        )
        .await
        .unwrap();
        bridge.start();
        let server = async {
            let (tcp, _) = listener.accept().await?;
            let mut tls = tokio_rustls::TlsAcceptor::from(server_config)
                .accept(tcp)
                .await?;
            if tls.get_ref().1.server_name() != Some("localhost") {
                return Err(invalid_frame());
            }
            let frame = read_frame(&mut tls).await?;
            write_frame(&mut tls, &frame).await
        };
        let exchange = async {
            let udp = UdpSocket::bind("127.0.0.1:0").await?;
            udp.send_to(&STUN, local(&cfg)).await?;
            let mut bytes = [0; 64];
            let (n, _) = udp.recv_from(&mut bytes).await?;
            if bytes[..n] != STUN {
                return Err(invalid_frame());
            }
            Ok::<_, io::Error>(())
        };
        let result = timeout(Duration::from_secs(3), async {
            tokio::try_join!(server, exchange)
        })
        .await;
        bridge.close().await.unwrap();
        assert_eq!(provider.in_use(), baseline);
        result.unwrap().unwrap();
    }

    #[tokio::test]
    async fn tls_refuses_wrong_name_and_untrusted_certificate() {
        for (name, trust) in [("other.invalid", true), ("localhost", false)] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let (server_config, client_config) = tls_configs(name, trust);
            let (_provider, funding, _) = resources("localhost", 1);
            let _lease = funding.acquire(client_claim().unwrap()).unwrap();
            let endpoint = Endpoint {
                host: "localhost".into(),
                port: listener.local_addr().unwrap().port(),
                tls: Some(client_config),
            };
            let server = async {
                let (tcp, _) = listener.accept().await.unwrap();
                tokio_rustls::TlsAcceptor::from(server_config)
                    .accept(tcp)
                    .await
                    .is_err()
            };
            let client = async { connect_endpoint(&endpoint).await.err().map(|e| e.kind()) };
            let (server_failed, client_error) = timeout(Duration::from_secs(3), async {
                tokio::join!(server, client)
            })
            .await
            .unwrap();
            assert!(server_failed);
            assert_eq!(client_error, Some(io::ErrorKind::InvalidData));
        }
    }

    #[tokio::test]
    async fn finite_capacity_refuses_client_before_tcp_and_close_releases_listener() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (provider, funding, baseline) = resources("127.0.0.1", 0);
        let mut cfg = config(format!(
            "turn:{}?transport=tcp",
            listener.local_addr().unwrap()
        ));
        let mut bridge = TurnStreamBridges::prepare_with_resources(&mut cfg, funding.clone(), None)
            .await
            .unwrap();
        let retained = provider.in_use();
        assert!(matches!(
            funding.acquire(client_claim().unwrap()),
            Err(TurnStreamError::Resources(_))
        ));
        bridge.start();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&STUN, local(&cfg)).await.unwrap();
        let connected = timeout(Duration::from_millis(100), listener.accept()).await;
        assert_eq!(provider.in_use(), retained);
        bridge.close().await.unwrap();
        assert!(connected.is_err());
        assert_eq!(provider.in_use(), baseline);
        // Native listener really closed, not just an empty accounting record.
        let rebound = UdpSocket::bind(local(&cfg)).await.unwrap();
        drop(rebound);
    }

    #[tokio::test]
    async fn close_joins_client_with_partial_frame_and_releases_exact_claims() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let (provider, funding, baseline) = resources("127.0.0.1", 1);
        let mut cfg = config(format!(
            "turn:{}?transport=tcp",
            listener.local_addr().unwrap()
        ));
        let mut bridge = TurnStreamBridges::prepare_with_resources(&mut cfg, funding.clone(), None)
            .await
            .unwrap();
        bridge.start();
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(&STUN, local(&cfg)).await.unwrap();
        let (mut tcp, _) = timeout(Duration::from_secs(2), listener.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(read_frame(&mut tcp).await.unwrap(), STUN);
        tcp.write_all(&STUN[..2]).await.unwrap();
        timeout(Duration::from_secs(2), bridge.close())
            .await
            .unwrap()
            .unwrap();
        let mut byte = [0];
        let terminal = timeout(Duration::from_secs(2), tcp.read(&mut byte))
            .await
            .unwrap();
        assert!(
            matches!(terminal, Ok(0))
                || terminal.as_ref().err().is_some_and(|e| matches!(
                    e.kind(),
                    io::ErrorKind::ConnectionReset | io::ErrorKind::ConnectionAborted
                ))
        );
        assert_eq!(provider.in_use(), baseline);
    }

    #[tokio::test]
    async fn frame_limits_padding_and_truncated_frames_are_strict() {
        let mut max_stun = vec![0; 20 + 65_532];
        max_stun[..4].copy_from_slice(&[0, 1, 0xff, 0xfc]);
        max_stun[4..8].copy_from_slice(&STUN[4..8]);
        assert!(validate_datagram(&max_stun).is_ok());
        max_stun.push(0);
        assert!(validate_datagram(&max_stun).is_err());
        assert!(frame_lengths(&[0, 1, 0xff, 0xff]).is_err());
        assert!(frame_lengths(&[0x80, 0, 0, 0]).is_err());
        let mut input = &b"\x40\x01\x00\x01\x07\0\0\0"[..];
        assert_eq!(read_frame(&mut input).await.unwrap(), [0x40, 1, 0, 1, 7]);
        for bytes in [&STUN[..2], &STUN[..10], &b"\x40\x01\x00\x01\x07"[..]] {
            let mut input = bytes;
            assert_eq!(
                read_frame(&mut input).await.unwrap_err().kind(),
                io::ErrorKind::UnexpectedEof
            );
        }
    }

    #[tokio::test]
    async fn cancelled_close_future_keeps_join_handle_and_endpoint_funding() {
        let (_provider, funding, _) = resources("127.0.0.1", 0);
        let mut cfg = config("turn:127.0.0.1:3478?transport=tcp".into());
        let mut bridge = TurnStreamBridges::prepare_with_resources(&mut cfg, funding, None)
            .await
            .unwrap();
        bridge.start();
        {
            let close = bridge.close();
            tokio::pin!(close);
            // Current-thread runtime: the newly spawned endpoint cannot have
            // terminated before this first poll. Drop the join future, not its
            // handle, then resume the same owner below.
            std::future::poll_fn(|cx| {
                assert!(close.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(bridge.slots.iter().all(|slot| slot.task.is_some()));
        timeout(Duration::from_secs(2), bridge.close())
            .await
            .unwrap()
            .unwrap();
        assert!(bridge.slots.iter().next().is_none());
    }

    #[test]
    fn endpoint_claim_overflow_refuses_instead_of_wrapping() {
        assert!(matches!(
            endpoint_claim(usize::MAX),
            Err(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::AccountedMemoryBytes
            })
        ));
    }

    #[tokio::test]
    async fn cancelled_close_retains_consumed_failure_until_second_slot_joins() {
        assert_cancelled_close_retains_failure(false).await;
    }

    #[tokio::test]
    async fn cancelled_close_terminal_handoff_records_consumed_failure() {
        assert_cancelled_close_retains_failure(true).await;
    }

    async fn assert_cancelled_close_retains_failure(terminal_handoff: bool) {
        let charged = |claim| FiniteResourceProvider::reservation_planning_charge(claim).unwrap();
        let baseline = FiniteResourceProvider::scope_planning_charge();
        let pair_claim = charged(endpoint_claim(0).unwrap())
            .checked_add(charged(endpoint_node_claim().unwrap()))
            .unwrap()
            .checked_scale(2)
            .unwrap();
        let provider = FiniteResourceProvider::new(baseline.checked_add(pair_claim).unwrap());
        let port = ResourceProviderPort::new(provider.clone()).unwrap();
        let funding = Resources::Test(port.clone(), port.process_scope());
        let mut bridge = TurnStreamBridges {
            slots: LeasedQueue::new(),
            close_failure: None,
        };

        let first_funding = funding.acquire(endpoint_claim(0).unwrap()).unwrap();
        let first_node = funding.acquire(endpoint_node_claim().unwrap()).unwrap();
        let first = tokio::spawn(async { panic!("first TURN endpoint failed") });
        let first_id = first.id();
        bridge.slots.push(
            BridgeSlot {
                prepared: None,
                task: Some(first),
                cancel: CancellationToken::new(),
                _funding: first_funding,
            },
            first_node,
        );

        let second_funding = funding.acquire(endpoint_claim(0).unwrap()).unwrap();
        let second_node = funding.acquire(endpoint_node_claim().unwrap()).unwrap();
        let (release, pending) = tokio::sync::oneshot::channel::<()>();
        let second = tokio::spawn(async move {
            let _ = pending.await;
        });
        bridge.slots.push(
            BridgeSlot {
                prepared: None,
                task: Some(second),
                cancel: CancellationToken::new(),
                _funding: second_funding,
            },
            second_node,
        );
        let retained = provider.in_use();
        assert_eq!(retained, baseline.checked_add(pair_claim).unwrap());

        // Observe completion without consuming A's JoinHandle result. Only
        // close below is allowed to consume the panic; B cannot finish until
        // the test sends its explicit release after cancelling that close.
        timeout(Duration::from_secs(2), async {
            while !bridge
                .slots
                .front()
                .unwrap()
                .task
                .as_ref()
                .unwrap()
                .is_finished()
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        {
            let close = bridge.close();
            tokio::pin!(close);
            std::future::poll_fn(|cx| {
                assert!(close.as_mut().poll(cx).is_pending());
                std::task::Poll::Ready(())
            })
            .await;
        }
        assert!(
            bridge.slots.front().unwrap().task.is_none(),
            "A was consumed by close"
        );
        assert_eq!(bridge.close_failure.as_ref().unwrap().id(), first_id);
        assert!(bridge.close_failure.as_ref().unwrap().is_panic());
        assert_eq!(
            bridge
                .slots
                .iter()
                .filter(|slot| slot.task.is_some())
                .count(),
            1
        );
        assert_eq!(
            provider.in_use(),
            retained,
            "cancellation releases neither funded slot"
        );

        if terminal_handoff {
            // Model the existing terminal thread, not an async retry. B stays
            // blocked until close_blocking aborts and joins its exact handle;
            // the recorder must also receive A's already-consumed panic.
            let terminal = tokio::task::spawn_blocking(move || {
                let mut joined = 0;
                let mut recorded = Vec::new();
                bridge.close_blocking(
                    |task| {
                        let result = futures::executor::block_on(task);
                        assert!(result.unwrap_err().is_cancelled());
                        joined += 1;
                    },
                    |failure| {
                        assert!(failure.is_panic());
                        recorded.push(failure.id());
                    },
                );
                (joined, recorded)
            });
            let (joined, recorded) = terminal.await.unwrap();
            assert_eq!(joined, 1, "only B's handle remained to join");
            assert_eq!(
                recorded,
                vec![first_id],
                "terminal recorder receives A exactly once"
            );
            assert_eq!(provider.in_use(), baseline);
            assert!(
                release.send(()).is_err(),
                "B's receiver was destroyed by the joined abort"
            );
        } else {
            release.send(()).unwrap();
            let failure = timeout(Duration::from_secs(2), bridge.close())
                .await
                .unwrap()
                .unwrap_err();
            assert!(failure.is_panic());
            assert_eq!(
                failure.id(),
                first_id,
                "retry returns the original consumed failure"
            );
            assert!(
                bridge.slots.iter().next().is_none(),
                "B joined before slots were released"
            );
            assert!(
                bridge.close_failure.is_none(),
                "completed close transferred the latch"
            );
            assert_eq!(provider.in_use(), baseline);
            drop(failure);
            bridge.close().await.unwrap();
            drop(bridge);
        }
        drop(funding);
        drop(port);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[tokio::test]
    async fn consumed_partial_header_is_not_restarted_by_outbound_packet() {
        struct ObservedRead {
            io: tokio::io::DuplexStream,
            consumed: Option<tokio::sync::oneshot::Sender<()>>,
        }
        impl AsyncRead for ObservedRead {
            fn poll_read(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &mut tokio::io::ReadBuf<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                let before = buf.filled().len();
                let result = Pin::new(&mut self.io).poll_read(cx, buf);
                if buf.filled().len() > before {
                    if let Some(signal) = self.consumed.take() {
                        let _ = signal.send(());
                    }
                }
                result
            }
        }
        impl AsyncWrite for ObservedRead {
            fn poll_write(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
                buf: &[u8],
            ) -> std::task::Poll<io::Result<usize>> {
                Pin::new(&mut self.io).poll_write(cx, buf)
            }
            fn poll_flush(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                Pin::new(&mut self.io).poll_flush(cx)
            }
            fn poll_shutdown(
                mut self: Pin<&mut Self>,
                cx: &mut std::task::Context<'_>,
            ) -> std::task::Poll<io::Result<()>> {
                Pin::new(&mut self.io).poll_shutdown(cx)
            }
        }
        let (local_io, mut remote_io) = tokio::io::duplex(128);
        let (consumed_tx, consumed_rx) = tokio::sync::oneshot::channel();
        let (tx, mut rx) = mpsc::channel(1);
        let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let stream = ObservedRead {
            io: local_io,
            consumed: Some(consumed_tx),
        };
        let pump = pump_client(Box::new(stream), udp, client.local_addr().unwrap(), &mut rx);
        let control = async {
            remote_io.write_all(&STUN[..2]).await?;
            consumed_rx.await.map_err(|_| invalid_frame())?;
            // Actual poll_read consumed only the first two header bytes. The
            // old cancel/recreate-read implementation loses them here.
            tx.send(STUN.to_vec()).await.map_err(|_| invalid_frame())?;
            if read_frame(&mut remote_io).await? != STUN {
                return Err(invalid_frame());
            }
            remote_io.write_all(&STUN[2..]).await?;
            let mut bytes = [0; 64];
            let (n, _) = client.recv_from(&mut bytes).await?;
            if bytes[..n] != STUN {
                return Err(invalid_frame());
            }
            drop(tx);
            Ok::<_, io::Error>(())
        };
        timeout(Duration::from_secs(2), async {
            tokio::try_join!(pump, control)
        })
        .await
        .unwrap()
        .unwrap();
    }
}
