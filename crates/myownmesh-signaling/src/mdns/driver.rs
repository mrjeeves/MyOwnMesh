//! Concrete mDNS/DNS-SD signaling driver — the LAN-local counterpart
//! of [`crate::nostr::driver`]. Discovery rides DNS-SD (one
//! [`wire::SERVICE_TYPE`] service instance per driver, room handle in
//! TXT); the SDP/candidate exchange rides a unicast TCP connection to
//! the port advertised in SRV, because an SDP with its candidate set
//! is far too large for TXT records.
//!
//! Deliberate properties:
//!
//! - **Clock-free.** No TLS, no timestamps — signaling works on a
//!   host whose wall clock is still at the epoch (a NanoKVM before
//!   its NTP sync), which is exactly the window local claiming has
//!   to cover.
//! - **Untrusted, like a public Nostr room.** Anything on the LAN
//!   can observe the advertisement or inject frames. The engine's
//!   ed25519 mutual-auth handshake over the DTLS channel that this
//!   signaling bootstraps remains the real authentication gate; a
//!   forged frame can at worst waste a handshake attempt.
//! - **Per-driver `ServiceDaemon`.** Each driver (one per joined
//!   network) owns its own mDNS socket set; the OS delivers each
//!   multicast packet to all of them (SO_REUSEADDR/SO_REUSEPORT +
//!   multicast), which also lets the driver coexist with a system
//!   avahi/Bonjour daemon. If per-network daemons ever measure as
//!   too heavy, a process-global daemon can be introduced behind
//!   this module without changing the driver API.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use mdns_sd::{ServiceDaemon, ServiceEvent, ServiceInfo};
use parking_lot::Mutex;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tracing::{debug, info, trace, warn};

use super::wire::{self, Frame};
use crate::nostr::handle::derive_room_handle;
use crate::{Error, SignalingMessage};

/// Configuration for one driver instance.
#[derive(Debug, Clone)]
pub struct MdnsDriverConfig {
    /// App-id used in the room-handle derivation — same value the
    /// Nostr driver uses, so both transports converge on one room
    /// per `(app_id, network_id)`.
    pub app_id: String,
    /// Network id (the user-facing identifier; the room handle is
    /// derived from `(app_id, network_id)`).
    pub network_id: String,
    /// Our peer's wire-level device id (the ed25519 pubkey surfaced
    /// by the mesh layer).
    pub device_id: String,
    /// Port for the TCP exchange listener. 0 (the default) binds an
    /// ephemeral port; the actual port is advertised via SRV.
    pub service_port: u16,
}

/// Inbound signaling events the driver pushes to the engine.
/// Mirrors [`crate::nostr::driver::NostrInbound`].
#[derive(Debug, Clone)]
pub enum MdnsInbound {
    /// A peer's advertisement resolved (or refreshed) in our room.
    PeerAnnounced { device_id: String },
    /// A peer's advertisement was withdrawn (mDNS goodbye) or its
    /// record expired from the cache.
    PeerLeft { device_id: String },
    /// A peer addressed us directly over the TCP exchange.
    Message { from: String, msg: SignalingMessage },
}

/// Outbound signaling messages the engine emits.
/// Mirrors [`crate::nostr::driver::NostrOutbound`].
#[derive(Debug, Clone)]
pub enum MdnsOutbound {
    /// Ensure our advertisement is registered. The registration is
    /// the announce — mDNS handles repetition and query responses —
    /// so repeats are cheap no-ops.
    Announce,
    /// Withdraw the advertisement (sends the mDNS goodbye, which
    /// surfaces as `PeerLeft` on every browser).
    Leave,
    DirectedToPeer {
        to: String,
        msg: SignalingMessage,
    },
}

/// How long a dial to a peer's advertised exchange port may take
/// before we try its next address (or give up).
const DIAL_TIMEOUT: Duration = Duration::from_secs(5);

/// An outbound exchange connection is closed after this much idle —
/// signaling for one handshake is bursty; anything longer-lived than
/// a burst should re-dial.
const CONN_IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Inbound exchange connections are dropped after this much idle.
const INBOUND_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Cadence of the local re-announce tick: every interval, each peer
/// still present in the mDNS cache is re-surfaced to the engine as a
/// `PeerAnnounced`. This mirrors the Nostr driver's ~60 s steady
/// announce heartbeat, which the engine's re-offer pacing expects —
/// a peer stuck at Sighted is re-offered on announce arrivals.
const REANNOUNCE_INTERVAL: Duration = Duration::from_secs(60);

/// Start the driver. Fails fast if the mDNS daemon or the TCP
/// listener can't come up (unlike Nostr, the fallible setup here is
/// synchronous) — callers keep their engine-side receiver and can
/// fall back to other transports.
pub fn start(
    config: MdnsDriverConfig,
    outbound_rx: mpsc::UnboundedReceiver<MdnsOutbound>,
    inbound_tx: mpsc::UnboundedSender<MdnsInbound>,
) -> crate::Result<MdnsDriverHandle> {
    let room_handle = derive_room_handle(&config.app_id, &config.network_id);

    // TCP exchange listener first — its port goes into the SRV record.
    let std_listener = std::net::TcpListener::bind(("0.0.0.0", config.service_port))
        .map_err(|e| Error::Bind(format!("0.0.0.0:{}", config.service_port), e))?;
    let port = std_listener
        .local_addr()
        .map_err(|e| Error::Bind("local_addr".into(), e))?
        .port();
    std_listener
        .set_nonblocking(true)
        .map_err(|e| Error::Bind("set_nonblocking".into(), e))?;

    let daemon = ServiceDaemon::new().map_err(|e| Error::Other(format!("mdns daemon: {e}")))?;

    let instance = wire::instance_name(&room_handle, &config.device_id);
    let host_name = format!("{instance}.local.");
    let props: HashMap<String, String> = wire::txt_properties(&room_handle, &config.device_id)
        .into_iter()
        .collect();
    let service_info = ServiceInfo::new(wire::SERVICE_TYPE, &instance, &host_name, "", port, props)
        .map_err(|e| Error::Other(format!("mdns service info: {e}")))?
        .enable_addr_auto();
    let fullname = service_info.get_fullname().to_string();

    // Browse before registering so we never miss a burst of resolves
    // racing our own announce.
    let browse_rx = daemon
        .browse(wire::SERVICE_TYPE)
        .map_err(|e| Error::Other(format!("mdns browse: {e}")))?;

    let registered = match daemon.register(service_info.clone()) {
        Ok(()) => true,
        Err(e) => {
            // Soft failure (e.g. no usable interface yet) — the
            // re-announce tick retries registration.
            warn!("mdns register failed (will retry): {e}");
            false
        }
    };

    info!(
        network = %config.network_id,
        room_handle = %&room_handle[..room_handle.len().min(16)],
        port,
        "starting mDNS driver"
    );

    let shared = Arc::new(Shared {
        room_handle,
        device_id: config.device_id,
        daemon: daemon.clone(),
        service_info,
        fullname: fullname.clone(),
        registered: AtomicBool::new(registered),
        peers: Mutex::new(HashMap::new()),
        fullname_to_peer: Mutex::new(HashMap::new()),
        conns: Mutex::new(HashMap::new()),
        conn_gen: AtomicU64::new(0),
        inbound_tx,
    });

    let mut tasks = Vec::new();

    // Browse pump: mDNS resolutions → peer table + PeerAnnounced/PeerLeft.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_browse(shared, browse_rx).await;
            trace!("mdns browse pump exiting");
        }));
    }

    // Outbound pump: engine events → registration changes + TCP frames.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_outbound(shared, outbound_rx).await;
            trace!("mdns outbound pump exiting");
        }));
    }

    // Accept loop for the TCP exchange.
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_accept(shared, std_listener).await;
            trace!("mdns accept loop exiting");
        }));
    }

    // Re-announce tick — see [`REANNOUNCE_INTERVAL`].
    {
        let shared = shared.clone();
        tasks.push(tokio::spawn(async move {
            run_reannounce(shared).await;
        }));
    }

    Ok(MdnsDriverHandle {
        daemon,
        fullname,
        tasks,
        stopped: AtomicBool::new(false),
    })
}

/// Handle returned by [`start`]. Drop or call [`Self::stop`] to
/// withdraw the advertisement and stop every spawned task.
pub struct MdnsDriverHandle {
    daemon: ServiceDaemon,
    fullname: String,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    stopped: AtomicBool,
}

impl MdnsDriverHandle {
    pub fn stop(&self) {
        if self.stopped.swap(true, Ordering::SeqCst) {
            return;
        }
        // Goodbye first (peers get PeerLeft promptly), then shut the
        // daemon down (closes the browse channel), then abort the
        // tokio tasks parked on accept/recv.
        let _ = self.daemon.unregister(&self.fullname);
        let _ = self.daemon.shutdown();
        for t in &self.tasks {
            t.abort();
        }
    }
}

impl Drop for MdnsDriverHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

struct Shared {
    room_handle: String,
    device_id: String,
    daemon: ServiceDaemon,
    service_info: ServiceInfo,
    fullname: String,
    registered: AtomicBool,
    /// Peers resolved in our room: device id → exchange endpoint.
    peers: Mutex<HashMap<String, PeerEntry>>,
    /// DNS-SD fullname → device id, so a `ServiceRemoved` (which only
    /// carries the fullname) maps back to the peer it withdraws.
    fullname_to_peer: Mutex<HashMap<String, String>>,
    /// Cached outbound exchange connections: device id → writer.
    conns: Mutex<HashMap<String, ConnHandle>>,
    conn_gen: AtomicU64,
    inbound_tx: mpsc::UnboundedSender<MdnsInbound>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct PeerEntry {
    addrs: Vec<IpAddr>,
    port: u16,
}

#[derive(Clone)]
struct ConnHandle {
    generation: u64,
    tx: mpsc::UnboundedSender<String>,
}

async fn run_browse(shared: Arc<Shared>, browse_rx: mdns_sd::Receiver<ServiceEvent>) {
    loop {
        let event = match browse_rx.recv_async().await {
            Ok(e) => e,
            // Channel closes when the daemon shuts down.
            Err(_) => return,
        };
        match event {
            ServiceEvent::ServiceResolved(resolved) => {
                if !resolved.is_valid() {
                    continue;
                }
                let advert = wire::parse_advert(
                    |k| resolved.get_property_val_str(k).map(str::to_string),
                    &shared.room_handle,
                    &shared.device_id,
                );
                let Some(advert) = advert else { continue };
                let mut addrs: Vec<IpAddr> = resolved
                    .get_addresses_v4()
                    .into_iter()
                    .map(IpAddr::V4)
                    .collect();
                if addrs.is_empty() {
                    trace!(peer = %advert.peer, "mdns advert without IPv4 address — skipped");
                    continue;
                }
                addrs.sort();
                let entry = PeerEntry {
                    addrs,
                    port: resolved.get_port(),
                };
                shared
                    .fullname_to_peer
                    .lock()
                    .insert(resolved.get_fullname().to_string(), advert.peer.clone());
                shared.peers.lock().insert(advert.peer.clone(), entry);
                debug!(peer = %&advert.peer[..advert.peer.len().min(16)], "mdns peer resolved");
                // Every resolve (first sight or cache refresh) surfaces as
                // an announce; the engine is idempotent on repeats, same
                // as with periodic Nostr announces.
                let _ = shared.inbound_tx.send(MdnsInbound::PeerAnnounced {
                    device_id: advert.peer,
                });
            }
            ServiceEvent::ServiceRemoved(_ty, fullname) => {
                let peer = shared.fullname_to_peer.lock().remove(&fullname);
                if let Some(peer) = peer {
                    shared.peers.lock().remove(&peer);
                    shared.conns.lock().remove(&peer);
                    debug!(peer = %&peer[..peer.len().min(16)], "mdns peer withdrew");
                    let _ = shared
                        .inbound_tx
                        .send(MdnsInbound::PeerLeft { device_id: peer });
                }
            }
            _ => {}
        }
    }
}

async fn run_outbound(shared: Arc<Shared>, mut outbound_rx: mpsc::UnboundedReceiver<MdnsOutbound>) {
    while let Some(outbound) = outbound_rx.recv().await {
        match outbound {
            MdnsOutbound::Announce => {
                if !shared.registered.load(Ordering::SeqCst) {
                    register(&shared);
                }
                // Already registered: the daemon re-announces and
                // answers queries on its own — nothing to do.
            }
            MdnsOutbound::Leave => {
                if shared.registered.swap(false, Ordering::SeqCst) {
                    let _ = shared.daemon.unregister(&shared.fullname);
                }
            }
            MdnsOutbound::DirectedToPeer { to, msg } => {
                send_directed(&shared, to, msg).await;
            }
        }
    }
}

fn register(shared: &Shared) {
    match shared.daemon.register(shared.service_info.clone()) {
        Ok(()) => {
            shared.registered.store(true, Ordering::SeqCst);
        }
        Err(e) => {
            debug!("mdns register retry failed: {e}");
        }
    }
}

async fn send_directed(shared: &Arc<Shared>, to: String, msg: SignalingMessage) {
    let line = wire::encode_frame(&Frame {
        v: wire::PROTOCOL_VERSION,
        room: shared.room_handle.clone(),
        from: shared.device_id.clone(),
        to: to.clone(),
        msg,
    });

    // Fast path: an existing writer for this peer.
    if let Some(handle) = shared.conns.lock().get(&to).cloned() {
        if handle.tx.send(line.clone()).is_ok() {
            return;
        }
    }

    // Dial. Snapshot the endpoint before awaiting anything.
    let Some(entry) = shared.peers.lock().get(&to).cloned() else {
        debug!(peer = %&to[..to.len().min(16)], "mdns directed message for unknown peer dropped");
        return;
    };
    for addr in &entry.addrs {
        match timeout(DIAL_TIMEOUT, TcpStream::connect((*addr, entry.port))).await {
            Ok(Ok(stream)) => {
                let generation = shared.conn_gen.fetch_add(1, Ordering::SeqCst);
                let (tx, rx) = mpsc::unbounded_channel::<String>();
                let _ = tx.send(line);
                shared
                    .conns
                    .lock()
                    .insert(to.clone(), ConnHandle { generation, tx });
                let shared_for_task = shared.clone();
                let to_for_task = to.clone();
                tokio::spawn(async move {
                    run_writer(stream, rx).await;
                    // Only unregister our own generation — a newer
                    // dial may have replaced this entry already.
                    let mut conns = shared_for_task.conns.lock();
                    if conns
                        .get(&to_for_task)
                        .is_some_and(|h| h.generation == generation)
                    {
                        conns.remove(&to_for_task);
                    }
                });
                return;
            }
            Ok(Err(e)) => {
                trace!(%addr, "mdns dial failed: {e}");
            }
            Err(_) => {
                trace!(%addr, "mdns dial timed out");
            }
        }
    }
    debug!(peer = %&to[..to.len().min(16)], "mdns peer unreachable on every advertised address");
}

async fn run_writer(mut stream: TcpStream, mut rx: mpsc::UnboundedReceiver<String>) {
    loop {
        match timeout(CONN_IDLE_TIMEOUT, rx.recv()).await {
            Ok(Some(line)) => {
                if stream.write_all(line.as_bytes()).await.is_err() {
                    return;
                }
                if stream.write_all(b"\n").await.is_err() {
                    return;
                }
            }
            // Sender dropped (driver stopping / conn replaced) or idle.
            Ok(None) | Err(_) => return,
        }
    }
}

async fn run_accept(shared: Arc<Shared>, std_listener: std::net::TcpListener) {
    let listener = match TcpListener::from_std(std_listener) {
        Ok(l) => l,
        Err(e) => {
            warn!("mdns exchange listener unusable: {e}");
            return;
        }
    };
    loop {
        match listener.accept().await {
            Ok((stream, remote)) => {
                let shared = shared.clone();
                tokio::spawn(async move {
                    run_reader(shared, stream).await;
                    trace!(%remote, "mdns exchange connection closed");
                });
            }
            Err(e) => {
                debug!("mdns accept error: {e}");
                sleep(Duration::from_millis(100)).await;
            }
        }
    }
}

async fn run_reader(shared: Arc<Shared>, stream: TcpStream) {
    let mut reader = BufReader::new(stream);
    let mut buf: Vec<u8> = Vec::new();
    loop {
        buf.clear();
        let read = timeout(
            INBOUND_IDLE_TIMEOUT,
            read_bounded_line(&mut reader, &mut buf),
        )
        .await;
        match read {
            Ok(Ok(true)) => {}
            // EOF, oversized/garbage frame, io error, or idle timeout —
            // drop the connection; the peer re-dials if it needs us.
            Ok(Ok(false)) | Ok(Err(_)) | Err(_) => return,
        }
        let Ok(line) = std::str::from_utf8(&buf) else {
            return;
        };
        if line.trim().is_empty() {
            continue;
        }
        let frame = match wire::decode_frame(line) {
            Ok(f) => f,
            Err(e) => {
                trace!("mdns frame parse failed: {e}");
                return;
            }
        };
        if !wire::frame_is_for_us(&frame, &shared.room_handle, &shared.device_id) {
            trace!("mdns frame for another room/recipient dropped");
            continue;
        }
        let inbound = match frame.msg {
            SignalingMessage::Announce { .. } => MdnsInbound::PeerAnnounced {
                device_id: frame.from,
            },
            SignalingMessage::Leave { peer_id } => MdnsInbound::PeerLeft { device_id: peer_id },
            other => MdnsInbound::Message {
                from: frame.from,
                msg: other,
            },
        };
        if shared.inbound_tx.send(inbound).is_err() {
            return;
        }
    }
}

/// Read one `\n`-terminated line into `buf` (newline excluded).
/// Returns `Ok(true)` on a full line, `Ok(false)` on clean EOF, and
/// errors if the line exceeds [`wire::MAX_FRAME_BYTES`] — bounding
/// what an unauthenticated LAN peer can make us buffer.
async fn read_bounded_line(
    reader: &mut BufReader<TcpStream>,
    buf: &mut Vec<u8>,
) -> std::io::Result<bool> {
    loop {
        let chunk = reader.fill_buf().await?;
        if chunk.is_empty() {
            return Ok(false);
        }
        if let Some(pos) = chunk.iter().position(|&b| b == b'\n') {
            buf.extend_from_slice(&chunk[..pos]);
            reader.consume(pos + 1);
            return Ok(true);
        }
        buf.extend_from_slice(chunk);
        let n = chunk.len();
        reader.consume(n);
        if buf.len() > wire::MAX_FRAME_BYTES {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "mdns frame exceeds size cap",
            ));
        }
    }
}

async fn run_reannounce(shared: Arc<Shared>) {
    loop {
        sleep(REANNOUNCE_INTERVAL).await;
        // Registration retry — covers a register() that failed at
        // start (no usable interface yet) or a transient daemon error.
        if !shared.registered.load(Ordering::SeqCst) {
            register(&shared);
        }
        // Re-surface every cached peer so the engine's announce-paced
        // retry logic (re-offers for Sighted-stuck peers) keeps
        // working without Nostr's relay heartbeat. A crashed peer
        // that never sent its goodbye lingers until its record TTL
        // expires — the engine tolerates announces for unreachable
        // peers, so this is noise, not harm.
        let peers: Vec<String> = shared.peers.lock().keys().cloned().collect();
        for device_id in peers {
            let _ = shared
                .inbound_tx
                .send(MdnsInbound::PeerAnnounced { device_id });
        }
    }
}
