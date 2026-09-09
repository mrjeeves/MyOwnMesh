//! Client half of the daemon's control protocol — see
//! `MyOwnMesh/crates/myownmesh/src/control.rs` for the
//! request/response shapes. Wire format is line-delimited JSON over a
//! local socket (unix-domain socket on Unix, named pipe on Windows).
//!
//! Two access shapes:
//!
//! - [`ControlClient::request`]: short-lived round trip. Opens a
//!   socket, writes one request, reads one response, closes. Used by
//!   every Tauri command except the event stream.
//!
//! - [`ControlClient::subscribe_events`]: long-lived stream. Opens a
//!   socket, writes `EventsSubscribe`, then keeps reading JSON lines
//!   and forwarding them to the caller's channel until the daemon
//!   disconnects.
//!
//! We intentionally don't pool connections — each round trip is cheap
//! against a local socket, and pooling makes the failure semantics
//! (daemon restart mid-session) harder for an embedder to reason
//! about.

use std::fmt;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use interprocess::local_socket::tokio::prelude::*;
#[cfg(unix)]
use interprocess::local_socket::GenericFilePath;
#[cfg(not(unix))]
use interprocess::local_socket::GenericNamespaced;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::mpsc;

/// GUI-used subset of `myownmesh::control::Request`.
///
/// This is a wire schema: every field and tag
/// below must match the daemon's current control protocol. Requests not used
/// by the GUI stay on the daemon/CLI surface and are intentionally absent.
/// The complete schema is retained so serialization and commit-policy
/// controls cover every supported operation, including daemon/CLI-only ones.
#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum Request {
    Status,
    NetworksList,
    PeersList {
        network: String,
    },
    RosterList {
        network: String,
    },
    TopologySet {
        network: String,
        topology: String,
        hub: Option<String>,
    },
    IdentityShow,
    IdentitySetLabel {
        label: String,
    },
    NetworkIdGenerate,
    NetworkIdNormalize {
        input: String,
    },
    ConfigShow,
    NetworkAdd {
        config: serde_json::Value,
    },
    NetworkCreateClosed {
        config: serde_json::Value,
    },
    NetworkImportClosed {
        config: serde_json::Value,
        expected_context_id: serde_json::Value,
        bootstrap: serde_json::Value,
    },
    NetworkBootstrapExport {
        network: String,
    },
    SemanticFactPageExport {
        network: String,
        request: serde_json::Value,
    },
    SemanticFactPageImport {
        network: String,
        page: serde_json::Value,
    },
    SemanticStateIdentity {
        network: String,
    },
    /// Render a bounded diagnostic view of the newest facts retained in
    /// the live hot-history cache.
    SemanticRecentFacts {
        network: String,
        request: serde_json::Value,
    },
    NetworkRemove {
        network: String,
        #[serde(default)]
        purge: bool,
    },
    /// Forget every joined network at once (purges each network's signed state +
    /// roster; keeps the device identity). The daemon exits afterward so it
    /// reloads clean — the GUI restarts the stack.
    ForgetAllNetworks,
    /// Wipe this device's entire state directory (identity, config, all
    /// networks) and exit for a fresh start — a factory reset.
    FactoryReset,
    /// Atomic in-place edit of an already-joined network. Hot-applies
    /// label / topology / auto-approve without dropping peers; restarts
    /// transport only for signaling/STUN/TURN edits. Preserves the roster
    /// either way; edits use `NetworkUpdate` so the daemon can preserve the
    /// joined network's durable state.
    NetworkUpdate {
        config: serde_json::Value,
    },
    NetworkReconnect {
        network: String,
        #[serde(default)]
        peer: Option<String>,
    },
    NetworkConnectPeer {
        network: String,
        peer: String,
        #[serde(default)]
        pin: bool,
        #[serde(default)]
        wait_ms: u64,
    },
    /// Snapshot which infrastructure services this device hosts plus the
    /// persisted config. The daemon answers with `{ status, config }`.
    ServicesStatus,
    /// Replace the device's services config. Passed as raw JSON (built
    /// by the frontend) the same way `NetworkAdd` carries its config, so
    /// the GUI doesn't have to re-derive the full `ServicesConfig` shape
    /// in Rust.
    ServicesSet {
        services: serde_json::Value,
    },
    EventsSubscribe,
    TraceSubscribe {
        network: String,
    },

    RpcRegister {
        client_id: String,
        client_capability: String,
        network: String,
        method: String,
        streaming: bool,
    },
    RpcUnregister {
        client_id: String,
        client_capability: String,
        network: String,
        method: String,
    },
    RpcRespond {
        client_id: String,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        ok: Option<serde_json::Value>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    RpcStreamChunk {
        client_id: String,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        payload: serde_json::Value,
    },
    RpcStreamEnd {
        client_id: String,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        request_id: String,
        operation_id: u64,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        error: Option<String>,
    },
    RpcCall {
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    RpcCallStream {
        client_id: String,
        client_capability: String,
        network: String,
        peer: String,
        method: String,
        payload: serde_json::Value,
    },
    ChannelSubscribe {
        client_id: String,
        client_capability: String,
        network: String,
        channel: String,
    },
    ChannelUnsubscribe {
        client_id: String,
        client_capability: String,
        network: String,
        channel: String,
    },
    ChannelSendTo {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
    },
    ChannelSendReliable {
        network: String,
        channel: String,
        peer: String,
        payload: serde_json::Value,
    },
    ChannelSendAll {
        network: String,
        channel: String,
        payload: serde_json::Value,
    },
    CapabilitiesSet {
        network: String,
        capabilities: CapabilityAdvert,
    },

    RealtimeFlowOpen {
        network: String,
        peer: String,
        flow_label: String,
        client_id: String,
        client_capability: String,
        direction: RealtimeFlowDirection,
        rtp_kind: WebRtcRtpKind,
        mime: String,
        clock_rate: u32,
        channels: u16,
    },
    RealtimeFlowClose {
        client_id: String,
        client_capability: String,
        flow_capability: String,
    },
    RealtimePipe {
        direction: RealtimePipeDirection,
        network: String,
        #[serde(default)]
        peer: Option<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_capability: Option<String>,
        #[serde(default)]
        flow_capability: Option<String>,
    },
    OpaqueFlowOpen {
        network: String,
        peer: String,
        label: Vec<u8>,
        client_id: String,
        client_capability: String,
        direction: RealtimeFlowDirection,
        mode: OpaqueFlowMode,
        max_unit_bytes: u32,
    },
    OpaqueFlowChange {
        network: String,
        label: Vec<u8>,
        client_id: String,
        client_capability: String,
        flow_capability: String,
        direction: RealtimeFlowDirection,
        mode: OpaqueFlowMode,
        max_unit_bytes: u32,
    },
    OpaqueFlowClose {
        client_id: String,
        client_capability: String,
        flow_capability: String,
    },
    OpaquePipe {
        direction: RealtimePipeDirection,
        network: String,
        #[serde(default)]
        peer: Option<String>,
        #[serde(default)]
        client_id: Option<String>,
        #[serde(default)]
        client_capability: Option<String>,
        #[serde(default)]
        flow_capability: Option<String>,
    },

    // ---- closed-network governance --------------------------------
    GovernanceProposeRoleGrant {
        network: String,
        target: String,
        role: Role,
        #[serde(skip_serializing_if = "Option::is_none")]
        mfa_code: Option<String>,
    },
    GovernanceProposeRoleRevoke {
        network: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mfa_code: Option<String>,
    },
    GovernanceProposeEvict {
        network: String,
        target: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        mfa_code: Option<String>,
    },
    GovernanceMfaPrepare {
        network: String,
    },
    GovernanceMfaQuery {
        network: String,
        transaction_id: String,
    },
    GovernanceMfaRedeliver {
        network: String,
        transaction_id: String,
    },
    GovernanceMfaCommit {
        network: String,
        transaction_id: String,
    },
    GovernanceMfaAbort {
        network: String,
        transaction_id: String,
    },
    /// Whether this device holds a custody enrollment for `network`.
    GovernanceMfaStatus {
        network: String,
    },
    /// Remove the custody lock for `network` (requires a valid code).
    GovernanceMfaDisable {
        network: String,
        code: String,
    },

    ClosedRelayOpen {
        network: String,
        relay: String,
        target: String,
    },
    ClosedRelayAccept {
        network: String,
        wait_ms: u64,
    },
    ClosedRelaySend {
        handle: String,
        payload: Vec<u8>,
    },
    ClosedRelayRecv {
        handle: String,
        wait_ms: u64,
    },
    ClosedRelayClose {
        handle: String,
    },
    ClosedRelayState {
        handle: String,
    },

    // ---- self-update ----------------------------------------------
    UpdateStatus,
    UpdateCheck,
    UpdateApply,
    UpdateSetPrefs {
        prefs: serde_json::Value,
    },
}

impl Request {
    /// Whether dispatching this request may commit durable or remote state.
    ///
    /// Mutations keep an explicit uncertainty result if the daemon becomes
    /// unreachable after the request may have been written. Read-only probes
    /// retain their bounded response deadline.
    pub(crate) fn may_commit(&self) -> bool {
        !matches!(
            self,
            Self::Status
                | Self::NetworksList
                | Self::PeersList { .. }
                | Self::RosterList { .. }
                | Self::IdentityShow
                | Self::NetworkIdGenerate
                | Self::NetworkIdNormalize { .. }
                | Self::ConfigShow
                | Self::NetworkBootstrapExport { .. }
                | Self::SemanticFactPageExport { .. }
                | Self::SemanticStateIdentity { .. }
                | Self::SemanticRecentFacts { .. }
                | Self::ServicesStatus
                | Self::EventsSubscribe
                | Self::TraceSubscribe { .. }
                | Self::GovernanceMfaQuery { .. }
                | Self::GovernanceMfaStatus { .. }
                | Self::UpdateStatus
        )
    }
}

/// Exact wire representation of the daemon's semantic governance role.
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum Role {
    Owner,
    Controller,
    Member,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RealtimeFlowDirection {
    Outbound,
    Inbound,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum RealtimePipeDirection {
    Outbound,
    Inbound,
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum OpaqueFlowMode {
    ReliableOrdered,
    PartialUnordered { max_retransmits: u16 },
}

#[allow(dead_code)]
#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub(crate) enum WebRtcRtpKind {
    Audio,
    Video,
}

#[derive(Debug, Serialize)]
pub(crate) struct CapabilityAdvert {
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default)]
    pub app_version: Option<String>,
    #[serde(default)]
    pub extra: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct Response {
    pub ok: bool,
    #[serde(default)]
    pub error: Option<String>,
    #[serde(default)]
    pub data: Option<serde_json::Value>,
}

/// Cancellation shared by the owned GUI event pump and its one socket reader.
/// The atomic check closes the notify race; the notification wakes both the
/// outer retry loop and the inner read/send loop without aborting either task.
#[derive(Clone)]
pub(crate) struct EventPumpCancellation {
    stopped: Arc<AtomicBool>,
    notify: Arc<tokio::sync::Notify>,
}

impl EventPumpCancellation {
    pub(crate) fn new() -> Self {
        Self {
            stopped: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(tokio::sync::Notify::new()),
        }
    }

    pub(crate) fn cancel(&self) {
        self.stopped.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.stopped.load(Ordering::Acquire)
    }

    pub(crate) async fn cancelled(&self) {
        while !self.is_cancelled() {
            let notified = self.notify.notified();
            if self.is_cancelled() {
                break;
            }
            notified.await;
        }
    }
}

/// Outcome of one control request from the GUI's perspective.
///
/// Once a mutating request may have been written, a lost response cannot be
/// reported as a definite failure: the daemon may have committed it before
/// the connection failed. Callers must query authoritative daemon state before
/// retrying an [`OutcomeUnknown`](Self::OutcomeUnknown) request.
#[derive(Debug)]
pub enum RequestError {
    OutcomeUnknown,
    Transport(anyhow::Error),
}

impl fmt::Display for RequestError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::OutcomeUnknown => write!(
                formatter,
                "outcome unknown: the daemon may have committed the request; query state before retrying"
            ),
            Self::Transport(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RequestError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::OutcomeUnknown => None,
            Self::Transport(error) => Some(error.as_ref()),
        }
    }
}

impl From<anyhow::Error> for RequestError {
    fn from(error: anyhow::Error) -> Self {
        Self::Transport(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RequestFailureStage {
    Write,
    Flush,
    Read,
    Eof,
    Parse,
    Timeout,
}

fn classify_request_failure(
    may_commit: bool,
    _stage: RequestFailureStage,
    error: anyhow::Error,
) -> RequestError {
    if may_commit {
        RequestError::OutcomeUnknown
    } else {
        RequestError::Transport(error)
    }
}

/// Where the daemon's control socket lives. Unix uses a filesystem
/// path under `~/.myownmesh/`; Windows uses a namespaced pipe segment
/// in the local namespace. Mirrors `myownmesh::control::SocketTarget`
/// so error messages and connect logic line up with the daemon side.
///
/// Each variant is dead code on exactly one platform — `Path` is
/// never built on Windows, `Name` is never built on Unix — so each
/// gets its own conditional `allow(dead_code)` to keep the build
/// warning-free on both sides.
#[derive(Debug, Clone)]
enum SocketAddr {
    #[cfg_attr(not(unix), allow(dead_code))]
    Path(PathBuf),
    #[cfg_attr(unix, allow(dead_code))]
    Name(String),
}

impl fmt::Display for SocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SocketAddr::Path(p) => write!(f, "{}", p.display()),
            SocketAddr::Name(n) => write!(f, "named pipe {n}"),
        }
    }
}

pub struct ControlClient {
    addr: SocketAddr,
}

impl ControlClient {
    /// Build a client bound to the default daemon socket location.
    /// Mirrors `myownmesh::control::resolve_socket`: a unix-domain
    /// socket file under `~/.myownmesh/` on Unix, a namespaced pipe
    /// `myownmesh.sock` on Windows. We recompute the address locally
    /// rather than depending on myownmesh-core so the GUI's build
    /// stays independent of the engine workspace.
    pub fn new() -> Result<Self> {
        #[cfg(unix)]
        {
            let home = dirs::home_dir().context("no home dir")?;
            let socket_path = home.join(".myownmesh").join("daemon.sock");
            Ok(Self {
                addr: SocketAddr::Path(socket_path),
            })
        }
        #[cfg(not(unix))]
        {
            Ok(Self {
                addr: SocketAddr::Name("myownmesh.sock".to_string()),
            })
        }
    }

    /// One-shot request → response. The daemon writes exactly one
    /// JSON line in reply, then keeps the connection open for
    /// further requests; we close after the first response since
    /// pooling isn't worth the complexity.
    pub async fn request(&self, req: &Request) -> std::result::Result<Response, RequestError> {
        let stream = self.connect().await?;
        request_stream(req, stream, Duration::from_secs(5)).await
    }

    /// Whether the daemon's control listener currently accepts a connection.
    ///
    /// This deliberately does not issue a request: lifecycle code uses it to
    /// distinguish an endpoint that has terminated from one that is merely
    /// slow to produce a status response.
    pub async fn listener_reachable(&self) -> bool {
        self.connect().await.is_ok()
    }

    /// Subscribe to the daemon's event stream. Spawns a task that
    /// forwards each incoming line to `tx`. Returns immediately
    /// after the initial ack so the caller can wire `rx` into a
    /// Tauri event emitter.
    pub async fn subscribe_events(
        &self,
        tx: mpsc::Sender<serde_json::Value>,
        cancellation: EventPumpCancellation,
    ) -> Result<tokio::task::JoinHandle<()>> {
        if cancellation.is_cancelled() {
            bail!("event subscription cancelled");
        }
        let stream = tokio::select! {
            biased;
            () = cancellation.cancelled() => bail!("event subscription cancelled"),
            result = self.connect() => result?,
        };
        let (reader, mut writer) = stream.split();
        let mut reader = BufReader::new(reader);

        let line = serde_json::to_string(&Request::EventsSubscribe)? + "\n";
        tokio::select! {
            biased;
            () = cancellation.cancelled() => bail!("event subscription cancelled"),
            result = writer.write_all(line.as_bytes()) => result.context("write subscribe")?,
        }
        tokio::select! {
            biased;
            () = cancellation.cancelled() => bail!("event subscription cancelled"),
            result = writer.flush() => result.context("flush subscribe")?,
        }

        // Read the initial ack — Response { ok: true, data: { subscribed: true } }.
        let mut ack = String::new();
        let n = tokio::select! {
            biased;
            () = cancellation.cancelled() => bail!("event subscription cancelled"),
            result = reader.read_line(&mut ack) => result.context("read ack")?,
        };
        if n == 0 {
            bail!("daemon closed connection before sending subscribe ack");
        }
        let parsed: Response =
            serde_json::from_str(ack.trim()).with_context(|| format!("parse ack: {ack}"))?;
        if !parsed.ok {
            return Err(anyhow!(
                "subscribe rejected: {}",
                parsed.error.unwrap_or_else(|| "(no error)".into())
            ));
        }

        // Spawn the forwarding loop. The writer goes with the stream
        // — its lifetime is tied to `reader` via the `split`. We
        // keep it on the stack here to keep the connection open.
        let join = tokio::spawn(async move {
            // Keep `writer` alive for the duration of the read loop;
            // dropping it closes the half-duplex on the server side
            // (the daemon then exits its write loop too).
            let _writer_keepalive = writer;
            let mut buf = String::new();
            loop {
                buf.clear();
                let read = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break,
                    result = reader.read_line(&mut buf) => result,
                };
                match read {
                    Ok(0) => break, // daemon disconnected
                    Ok(_) => {}
                    Err(e) => {
                        tracing::warn!("event stream read failed: {e}");
                        break;
                    }
                }
                let value: serde_json::Value = match serde_json::from_str(buf.trim()) {
                    Ok(v) => v,
                    Err(e) => {
                        tracing::warn!("malformed event line: {e} — {buf}");
                        continue;
                    }
                };
                let sent = tokio::select! {
                    biased;
                    () = cancellation.cancelled() => break,
                    result = tx.send(value) => result,
                };
                if sent.is_err() {
                    break; // GUI side dropped the channel
                }
            }
        });

        Ok(join)
    }

    async fn connect(&self) -> Result<LocalSocketStream> {
        let name = match &self.addr {
            SocketAddr::Path(p) => {
                #[cfg(unix)]
                {
                    p.as_path()
                        .to_fs_name::<GenericFilePath>()
                        .context("socket path → fs_name")?
                }
                #[cfg(not(unix))]
                {
                    let _ = p; // Path variant never constructed on non-Unix.
                    unreachable!("SocketAddr::Path on non-Unix")
                }
            }
            SocketAddr::Name(n) => {
                #[cfg(not(unix))]
                {
                    n.as_str()
                        .to_ns_name::<GenericNamespaced>()
                        .context("socket name → ns_name")?
                }
                #[cfg(unix)]
                {
                    let _ = n; // Name variant never constructed on Unix.
                    unreachable!("SocketAddr::Name on Unix")
                }
            }
        };
        LocalSocketStream::connect(name).await.context(format!(
            "connect daemon socket at {} — is `myownmesh serve` running?",
            self.addr
        ))
    }
}

async fn request_stream<S>(
    req: &Request,
    stream: S,
    response_deadline: Duration,
) -> std::result::Result<Response, RequestError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let may_commit = req.may_commit();
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = BufReader::new(reader);

    let line = serde_json::to_string(req)
        .map_err(|error| RequestError::Transport(anyhow!(error).context("serialize request")))?
        + "\n";
    writer.write_all(line.as_bytes()).await.map_err(|error| {
        classify_request_failure(
            may_commit,
            RequestFailureStage::Write,
            anyhow!(error).context("write request"),
        )
    })?;
    writer.flush().await.map_err(|error| {
        classify_request_failure(
            may_commit,
            RequestFailureStage::Flush,
            anyhow!(error).context("flush request"),
        )
    })?;

    let mut buf = String::new();
    let n = match tokio::time::timeout(response_deadline, reader.read_line(&mut buf)).await {
        Ok(result) => result.map_err(|error| {
            classify_request_failure(
                may_commit,
                RequestFailureStage::Read,
                anyhow!(error).context("read daemon response"),
            )
        })?,
        Err(_) => {
            return Err(classify_request_failure(
                may_commit,
                RequestFailureStage::Timeout,
                anyhow!("daemon response timed out"),
            ))
        }
    };
    if n == 0 {
        return Err(classify_request_failure(
            may_commit,
            RequestFailureStage::Eof,
            anyhow!("daemon closed connection without a response"),
        ));
    }
    let resp: Response = serde_json::from_str(buf.trim()).map_err(|error| {
        classify_request_failure(
            may_commit,
            RequestFailureStage::Parse,
            anyhow!(error).context(format!("parse response: {buf}")),
        )
    })?;
    Ok(resp)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn event_pump_cancellation_is_latched_and_wakes_waiters() {
        let cancellation = EventPumpCancellation::new();
        cancellation.cancel();
        cancellation.cancelled().await;
        assert!(cancellation.is_cancelled());
    }
    use std::io;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    enum FakeRead {
        Bytes(Vec<u8>),
        Error,
        Eof,
        Pending,
    }

    struct FakeSocket {
        fail_write: bool,
        fail_flush: bool,
        read: FakeRead,
    }

    impl FakeSocket {
        fn response(read: FakeRead) -> Self {
            Self {
                fail_write: false,
                fail_flush: false,
                read,
            }
        }

        fn write_failure() -> Self {
            Self {
                fail_write: true,
                fail_flush: false,
                read: FakeRead::Eof,
            }
        }

        fn flush_failure() -> Self {
            Self {
                fail_write: false,
                fail_flush: true,
                read: FakeRead::Eof,
            }
        }
    }

    impl AsyncRead for FakeSocket {
        fn poll_read(
            mut self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            buffer: &mut tokio::io::ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            match std::mem::replace(&mut self.read, FakeRead::Eof) {
                FakeRead::Bytes(bytes) => {
                    buffer.put_slice(&bytes);
                    Poll::Ready(Ok(()))
                }
                FakeRead::Error => Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    "fake read failure",
                ))),
                FakeRead::Eof => Poll::Ready(Ok(())),
                FakeRead::Pending => {
                    self.read = FakeRead::Pending;
                    Poll::Pending
                }
            }
        }
    }

    impl AsyncWrite for FakeSocket {
        fn poll_write(
            self: Pin<&mut Self>,
            _context: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.fail_write {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fake write failure",
                )))
            } else {
                Poll::Ready(Ok(bytes.len()))
            }
        }

        fn poll_flush(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            if self.fail_flush {
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "fake flush failure",
                )))
            } else {
                Poll::Ready(Ok(()))
            }
        }

        fn poll_shutdown(self: Pin<&mut Self>, _context: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }

    #[test]
    fn mutating_requests_are_explicitly_outcome_uncertain() {
        assert!(Request::FactoryReset.may_commit());
        assert!(Request::NetworkUpdate {
            config: serde_json::json!({})
        }
        .may_commit());
        assert!(!Request::Status.may_commit());
        assert!(!Request::GovernanceMfaStatus {
            network: "net".into()
        }
        .may_commit());
        assert!(RequestError::OutcomeUnknown
            .to_string()
            .starts_with("outcome unknown:"));
    }

    #[test]
    fn fake_socket_failures_preserve_mutation_uncertainty() {
        let stages = [
            RequestFailureStage::Write,
            RequestFailureStage::Flush,
            RequestFailureStage::Read,
            RequestFailureStage::Eof,
            RequestFailureStage::Parse,
            RequestFailureStage::Timeout,
        ];
        for stage in stages {
            assert!(matches!(
                classify_request_failure(true, stage, anyhow!("held fake socket")),
                RequestError::OutcomeUnknown
            ));
            assert!(matches!(
                classify_request_failure(false, stage, anyhow!("held fake socket")),
                RequestError::Transport(_)
            ));
        }
    }

    #[tokio::test]
    async fn fake_socket_request_path_covers_each_mutation_failure_stage() {
        let sockets = [
            FakeSocket::write_failure(),
            FakeSocket::flush_failure(),
            FakeSocket::response(FakeRead::Error),
            FakeSocket::response(FakeRead::Eof),
            FakeSocket::response(FakeRead::Bytes(b"not-json\n".to_vec())),
            FakeSocket::response(FakeRead::Pending),
        ];
        for socket in sockets {
            assert!(matches!(
                request_stream(&Request::FactoryReset, socket, Duration::from_millis(1),).await,
                Err(RequestError::OutcomeUnknown)
            ));
        }
        assert!(matches!(
            request_stream(
                &Request::Status,
                FakeSocket::response(FakeRead::Pending),
                Duration::from_millis(1),
            )
            .await,
            Err(RequestError::Transport(_))
        ));
    }

    #[test]
    fn request_policy_is_exhaustive_over_wire_fixture() {
        let read_only = [
            "status",
            "networks_list",
            "peers_list",
            "roster_list",
            "identity_show",
            "network_id_generate",
            "network_id_normalize",
            "config_show",
            "network_bootstrap_export",
            "semantic_fact_page_export",
            "semantic_state_identity",
            "semantic_recent_facts",
            "services_status",
            "events_subscribe",
            "trace_subscribe",
            "governance_mfa_query",
            "governance_mfa_status",
            "update_status",
        ];
        let requests = fixture_requests();
        assert_eq!(requests.len(), 68);
        for request in requests {
            let encoded = serde_json::to_value(&request).expect("request serializes");
            let tag = encoded
                .get("op")
                .and_then(serde_json::Value::as_str)
                .expect("request has wire tag");
            assert_eq!(request.may_commit(), !read_only.contains(&tag), "{tag}");
        }
    }

    fn fixture_requests() -> Vec<Request> {
        vec![
            Request::Status,
            Request::NetworksList,
            Request::PeersList {
                network: "net".into(),
            },
            Request::RosterList {
                network: "net".into(),
            },
            Request::TopologySet {
                network: "net".into(),
                topology: "full_mesh".into(),
                hub: None,
            },
            Request::IdentityShow,
            Request::IdentitySetLabel { label: "me".into() },
            Request::NetworkIdGenerate,
            Request::NetworkIdNormalize {
                input: "net".into(),
            },
            Request::ConfigShow,
            Request::NetworkAdd {
                config: serde_json::json!({"id":"local","network_id":"net"}),
            },
            Request::NetworkCreateClosed {
                config: serde_json::json!({"id":"local","network_id":"net"}),
            },
            Request::NetworkImportClosed {
                config: serde_json::json!({"id":"local","network_id":"net"}),
                expected_context_id: serde_json::json!(vec![0u8; 32]),
                bootstrap: serde_json::json!({}),
            },
            Request::NetworkBootstrapExport {
                network: "net".into(),
            },
            Request::SemanticFactPageExport {
                network: "net".into(),
                request: serde_json::json!({"cursor":null,"limit":1}),
            },
            Request::SemanticFactPageImport {
                network: "net".into(),
                page: serde_json::json!({"facts":[]}),
            },
            Request::SemanticStateIdentity {
                network: "net".into(),
            },
            Request::SemanticRecentFacts {
                network: "net".into(),
                request: serde_json::json!({"max_facts":1,"max_encoded_bytes":1024}),
            },
            Request::NetworkRemove {
                network: "net".into(),
                purge: false,
            },
            Request::ForgetAllNetworks,
            Request::FactoryReset,
            Request::NetworkUpdate {
                config: serde_json::json!({"id":"local","network_id":"net"}),
            },
            Request::NetworkReconnect {
                network: "net".into(),
                peer: Some("peer".into()),
            },
            Request::NetworkConnectPeer {
                network: "net".into(),
                peer: "peer".into(),
                pin: true,
                wait_ms: 10,
            },
            Request::ServicesStatus,
            Request::ServicesSet {
                services: serde_json::json!({}),
            },
            Request::EventsSubscribe,
            Request::TraceSubscribe {
                network: "net".into(),
            },
            Request::RpcRegister {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                method: "method".into(),
                streaming: false,
            },
            Request::RpcUnregister {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                method: "method".into(),
            },
            Request::RpcRespond {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                peer: "peer".into(),
                method: "method".into(),
                request_id: "req".into(),
                operation_id: 1,
                ok: Some(serde_json::json!({"done":true})),
                error: None,
            },
            Request::RpcStreamChunk {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                peer: "peer".into(),
                method: "method".into(),
                request_id: "req".into(),
                operation_id: 1,
                payload: serde_json::json!({"chunk":1}),
            },
            Request::RpcStreamEnd {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                peer: "peer".into(),
                method: "method".into(),
                request_id: "req".into(),
                operation_id: 1,
                error: None,
            },
            Request::RpcCall {
                network: "net".into(),
                peer: "peer".into(),
                method: "method".into(),
                payload: serde_json::json!({"arg":1}),
            },
            Request::RpcCallStream {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                peer: "peer".into(),
                method: "method".into(),
                payload: serde_json::json!({"arg":1}),
            },
            Request::ChannelSubscribe {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                channel: "updates".into(),
            },
            Request::ChannelUnsubscribe {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                network: "net".into(),
                channel: "updates".into(),
            },
            Request::ChannelSendTo {
                network: "net".into(),
                channel: "updates".into(),
                peer: "peer".into(),
                payload: serde_json::json!({"value":1}),
            },
            Request::ChannelSendReliable {
                network: "net".into(),
                channel: "updates".into(),
                peer: "peer".into(),
                payload: serde_json::json!({"value":1}),
            },
            Request::ChannelSendAll {
                network: "net".into(),
                channel: "updates".into(),
                payload: serde_json::json!({"value":1}),
            },
            Request::CapabilitiesSet {
                network: "net".into(),
                capabilities: CapabilityAdvert {
                    tags: vec!["tag".into()],
                    app_version: Some("0.3".into()),
                    extra: serde_json::json!({"extra":true}),
                },
            },
            Request::RealtimeFlowOpen {
                network: "net".into(),
                peer: "peer".into(),
                flow_label: "screen".into(),
                client_id: "c1".into(),
                client_capability: "cap".into(),
                direction: RealtimeFlowDirection::Outbound,
                rtp_kind: WebRtcRtpKind::Video,
                mime: "video/H264".into(),
                clock_rate: 90_000,
                channels: 0,
            },
            Request::RealtimeFlowClose {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                flow_capability: "flow".into(),
            },
            Request::RealtimePipe {
                direction: RealtimePipeDirection::Inbound,
                network: "net".into(),
                peer: Some("peer".into()),
                client_id: Some("c1".into()),
                client_capability: Some("cap".into()),
                flow_capability: None,
            },
            Request::OpaqueFlowOpen {
                network: "net".into(),
                peer: "peer".into(),
                label: vec![0xff, 0x00, 0x7f],
                client_id: "c1".into(),
                client_capability: "cap".into(),
                direction: RealtimeFlowDirection::Outbound,
                mode: OpaqueFlowMode::PartialUnordered { max_retransmits: 3 },
                max_unit_bytes: 1024,
            },
            Request::OpaqueFlowChange {
                network: "net".into(),
                label: vec![0xff, 0x00, 0x7f],
                client_id: "c1".into(),
                client_capability: "cap".into(),
                flow_capability: "flow".into(),
                direction: RealtimeFlowDirection::Outbound,
                mode: OpaqueFlowMode::PartialUnordered { max_retransmits: 3 },
                max_unit_bytes: 2048,
            },
            Request::OpaqueFlowClose {
                client_id: "c1".into(),
                client_capability: "cap".into(),
                flow_capability: "flow".into(),
            },
            Request::OpaquePipe {
                direction: RealtimePipeDirection::Inbound,
                network: "net".into(),
                peer: Some("peer".into()),
                client_id: Some("c1".into()),
                client_capability: Some("cap".into()),
                flow_capability: None,
            },
            Request::GovernanceProposeRoleGrant {
                network: "net".into(),
                target: "peer".into(),
                role: Role::Owner,
                mfa_code: Some("123456".into()),
            },
            Request::GovernanceProposeRoleRevoke {
                network: "net".into(),
                target: "peer".into(),
                mfa_code: None,
            },
            Request::GovernanceProposeEvict {
                network: "net".into(),
                target: "peer".into(),
                mfa_code: None,
            },
            Request::GovernanceMfaPrepare {
                network: "net".into(),
            },
            Request::GovernanceMfaQuery {
                network: "net".into(),
                transaction_id: "tx".into(),
            },
            Request::GovernanceMfaRedeliver {
                network: "net".into(),
                transaction_id: "tx".into(),
            },
            Request::GovernanceMfaCommit {
                network: "net".into(),
                transaction_id: "tx".into(),
            },
            Request::GovernanceMfaAbort {
                network: "net".into(),
                transaction_id: "tx".into(),
            },
            Request::GovernanceMfaStatus {
                network: "net".into(),
            },
            Request::GovernanceMfaDisable {
                network: "net".into(),
                code: "123456".into(),
            },
            Request::ClosedRelayOpen {
                network: "net".into(),
                relay: "relay".into(),
                target: "target".into(),
            },
            Request::ClosedRelayAccept {
                network: "net".into(),
                wait_ms: 10,
            },
            Request::ClosedRelaySend {
                handle: "handle".into(),
                payload: vec![1, 2, 3],
            },
            Request::ClosedRelayRecv {
                handle: "handle".into(),
                wait_ms: 10,
            },
            Request::ClosedRelayClose {
                handle: "handle".into(),
            },
            Request::ClosedRelayState {
                handle: "handle".into(),
            },
            Request::UpdateStatus,
            Request::UpdateCheck,
            Request::UpdateApply,
            Request::UpdateSetPrefs {
                prefs: serde_json::json!({"channel":"stable"}),
            },
        ]
    }

    #[test]
    fn every_current_request_variant_has_exact_wire_tag() {
        let expected = [
            "status",
            "networks_list",
            "peers_list",
            "roster_list",
            "topology_set",
            "identity_show",
            "identity_set_label",
            "network_id_generate",
            "network_id_normalize",
            "config_show",
            "network_add",
            "network_create_closed",
            "network_import_closed",
            "network_bootstrap_export",
            "semantic_fact_page_export",
            "semantic_fact_page_import",
            "semantic_state_identity",
            "semantic_recent_facts",
            "network_remove",
            "forget_all_networks",
            "factory_reset",
            "network_update",
            "network_reconnect",
            "network_connect_peer",
            "services_status",
            "services_set",
            "events_subscribe",
            "trace_subscribe",
            "rpc_register",
            "rpc_unregister",
            "rpc_respond",
            "rpc_stream_chunk",
            "rpc_stream_end",
            "rpc_call",
            "rpc_call_stream",
            "channel_subscribe",
            "channel_unsubscribe",
            "channel_send_to",
            "channel_send_reliable",
            "channel_send_all",
            "capabilities_set",
            "realtime_flow_open",
            "realtime_flow_close",
            "realtime_pipe",
            "opaque_flow_open",
            "opaque_flow_change",
            "opaque_flow_close",
            "opaque_pipe",
            "governance_propose_role_grant",
            "governance_propose_role_revoke",
            "governance_propose_evict",
            "governance_mfa_prepare",
            "governance_mfa_query",
            "governance_mfa_redeliver",
            "governance_mfa_commit",
            "governance_mfa_abort",
            "governance_mfa_status",
            "governance_mfa_disable",
            "closed_relay_open",
            "closed_relay_accept",
            "closed_relay_send",
            "closed_relay_recv",
            "closed_relay_close",
            "closed_relay_state",
            "update_status",
            "update_check",
            "update_apply",
            "update_set_prefs",
        ];
        let mut requests = fixture_requests();
        assert_eq!(requests.len(), expected.len());
        for (request, op) in requests.drain(..).zip(expected) {
            let encoded = serde_json::to_value(request).expect("request serializes");
            assert_eq!(encoded["op"], op);
        }
    }

    #[test]
    fn exact_identity_fields_are_not_dropped_by_serialization() {
        let request = Request::GovernanceProposeRoleGrant {
            network: "net".into(),
            target: "peer".into(),
            role: Role::Member,
            mfa_code: Some("123456".into()),
        };
        let encoded = serde_json::to_value(request).expect("request serializes");
        assert_eq!(encoded["role"], "member");
        assert_eq!(encoded["mfa_code"], "123456");

        let remove = serde_json::to_value(Request::NetworkRemove {
            network: "net".into(),
            purge: true,
        })
        .expect("request serializes");
        assert_eq!(remove["purge"], true);
    }
}
