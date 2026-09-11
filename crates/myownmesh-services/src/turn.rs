//! Standalone TURN server (RFC 5766).
//!
//! Relays media / data for peers that can't establish a direct path
//! (symmetric NAT). A TURN server also answers STUN Binding requests, so
//! a single TURN listener covers both jobs in an ICE flow.
//!
//! This is a thin wrapper over the webrtc-rs `turn` crate's
//! [`Server`](turn::server::Server), wired to a single UDP listener and
//! a static long-term-credential auth handler driven by
//! [`TurnServiceConfig`]. Credentials are configured up front (mirror
//! them into each peer's `turn_servers` config); there's no dynamic
//! REST-style credential issuance.

use std::collections::HashMap;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::panic::AssertUnwindSafe;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex as SyncMutex};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Notify};
use tracing::info;
use turn::auth::{generate_auth_key, AuthHandler};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::relay::RelayAddressGenerator;
use turn::resource::{ResourceAdmission, ResourceAdmissionError, ResourceCharge, ResourceKind};
use turn::server::config::{ConnConfig, ServerConfig};
use turn::server::Server;
use turn::Error as TurnError;
use webrtc_util::vnet::net::Net;
use webrtc_util::Conn;

use myownmesh_core::config::{TurnCredential, TurnServiceConfig};
use myownmesh_core::{LocalApplicationResourceScope, ResourceClaim, ResourceClass, ResourceLease};

use crate::{Error, Result};

/// Token bucket over bytes, for per-allocation bandwidth shaping. A cap
/// of 0 is never wrapped (see [`ThrottledRelayGenerator`]), so `rate` is
/// always > 0 here.
struct ByteBucket {
    tokens: f64,
    capacity: f64,
    rate: f64,
    last: Instant,
}

impl ByteBucket {
    fn new(bps: u64) -> Self {
        // The configured rate is also the initial burst. There is no hidden
        // floor: workload capacity comes solely from the provider's explicit
        // per-connection configuration.
        let capacity = bps as f64;
        Self {
            tokens: capacity,
            capacity,
            rate: bps as f64,
            last: Instant::now(),
        }
    }

    /// Refill for elapsed time and try to consume `n` bytes. Returns
    /// `None` if consumed now, or `Some(wait)` if the caller must wait
    /// that long and retry. Pure (takes `now`) so it's unit-testable
    /// without real time. `n` is clamped to capacity so an oversized
    /// datagram still drains through.
    fn try_consume(&mut self, n: usize, now: Instant) -> Option<Duration> {
        let dt = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
        let need = (n as f64).min(self.capacity);
        if self.tokens >= need {
            self.tokens -= need;
            None
        } else {
            Some(Duration::from_secs_f64((need - self.tokens) / self.rate))
        }
    }
}

async fn consume(bucket: &AsyncMutex<ByteBucket>, n: usize) {
    loop {
        let wait = {
            let mut b = bucket.lock().await;
            b.try_consume(n, Instant::now())
        };
        match wait {
            None => return,
            Some(w) => tokio::time::sleep(w).await,
        }
    }
}

/// Wraps an allocation's relay [`Conn`] to shape its throughput to a
/// per-connection byte/sec cap, independently in each direction.
struct ThrottledConn {
    inner: Arc<dyn Conn + Send + Sync>,
    send_bucket: AsyncMutex<ByteBucket>,
    recv_bucket: AsyncMutex<ByteBucket>,
}

/// Adapts the dependency-neutral vendored TURN admission port to the
/// owner-selected core scope. Every returned vendor lease owns exactly one
/// core lease and is retained by the native object/task it funded.
struct TurnResourceLease {
    _lease: Option<ResourceLease>,
}

impl turn::resource::ResourceLease for TurnResourceLease {}

struct TurnResourceAdmission {
    scope: LocalApplicationResourceScope,
}

#[cfg(test)]
struct AllocationLeaseConn {
    inner: Arc<dyn Conn + Send + Sync>,
    lease: SyncMutex<Option<ResourceLease>>,
}

#[cfg(test)]
impl AllocationLeaseConn {
    fn new(inner: Arc<dyn Conn + Send + Sync>, lease: ResourceLease) -> Self {
        Self {
            inner,
            lease: SyncMutex::new(Some(lease)),
        }
    }
}

#[cfg(test)]
#[async_trait]
impl Conn for AllocationLeaseConn {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), webrtc_util::Error> {
        self.inner.connect(addr).await
    }

    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, webrtc_util::Error> {
        self.inner.recv(buf).await
    }

    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), webrtc_util::Error> {
        self.inner.recv_from(buf).await
    }

    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, webrtc_util::Error> {
        self.inner.send(buf).await
    }

    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::result::Result<usize, webrtc_util::Error> {
        self.inner.send_to(buf, target).await
    }

    fn local_addr(&self) -> std::result::Result<SocketAddr, webrtc_util::Error> {
        self.inner.local_addr()
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }

    async fn close(&self) -> std::result::Result<(), webrtc_util::Error> {
        let result = self.inner.close().await;
        self.lease
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        result
    }

    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

fn turn_resource_claim(
    kind: ResourceKind,
    charge: ResourceCharge,
) -> std::result::Result<ResourceClaim, myownmesh_core::ResourceClaimArithmeticError> {
    let unit = match kind {
        ResourceKind::Allocation => ResourceClaim::try_from_entries([
            (ResourceClass::RelayOrProviderAllocation, 1),
            (ResourceClass::SocketOrHandle, 1),
            (ResourceClass::WorkerOrTask, 2),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])?,
        ResourceKind::ReadLoop
        | ResourceKind::CommandLoop
        | ResourceKind::AllocationTimer
        | ResourceKind::PacketPump => ResourceClaim::single(ResourceClass::WorkerOrTask, 1),
        ResourceKind::Permission
        | ResourceKind::ChannelBind
        | ResourceKind::Reservation
        | ResourceKind::Nonce
        | ResourceKind::Queue
        | ResourceKind::CleanupRecord => {
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        }
        ResourceKind::RelayProbe => ResourceClaim::single(ResourceClass::SocketOrHandle, 1),
    };
    let bytes_class = if kind == ResourceKind::CleanupRecord {
        ResourceClass::AccountedMemoryBytes
    } else {
        ResourceClass::QueuedBytes
    };
    unit.checked_scale(charge.units)?
        .checked_add(ResourceClaim::single(bytes_class, charge.retained_bytes))
}

impl ResourceAdmission for TurnResourceAdmission {
    fn acquire(
        &self,
        kind: ResourceKind,
        charge: ResourceCharge,
    ) -> std::result::Result<Box<dyn turn::resource::ResourceLease>, ResourceAdmissionError> {
        let claim = turn_resource_claim(kind, charge).map_err(|_| ResourceAdmissionError)?;
        let lease = self
            .scope
            .acquire(claim)
            .map_err(|_| ResourceAdmissionError)?;
        Ok(Box::new(TurnResourceLease {
            _lease: Some(lease),
        }))
    }
}

impl ThrottledConn {
    fn new(inner: Arc<dyn Conn + Send + Sync>, bps: u64) -> Self {
        Self {
            inner,
            send_bucket: AsyncMutex::new(ByteBucket::new(bps)),
            recv_bucket: AsyncMutex::new(ByteBucket::new(bps)),
        }
    }
}

#[async_trait]
impl Conn for ThrottledConn {
    async fn connect(&self, addr: SocketAddr) -> std::result::Result<(), webrtc_util::Error> {
        self.inner.connect(addr).await
    }
    async fn recv(&self, buf: &mut [u8]) -> std::result::Result<usize, webrtc_util::Error> {
        let n = self.inner.recv(buf).await?;
        consume(&self.recv_bucket, n).await;
        Ok(n)
    }
    async fn recv_from(
        &self,
        buf: &mut [u8],
    ) -> std::result::Result<(usize, SocketAddr), webrtc_util::Error> {
        let (n, addr) = self.inner.recv_from(buf).await?;
        consume(&self.recv_bucket, n).await;
        Ok((n, addr))
    }
    async fn send(&self, buf: &[u8]) -> std::result::Result<usize, webrtc_util::Error> {
        consume(&self.send_bucket, buf.len()).await;
        self.inner.send(buf).await
    }
    async fn send_to(
        &self,
        buf: &[u8],
        target: SocketAddr,
    ) -> std::result::Result<usize, webrtc_util::Error> {
        consume(&self.send_bucket, buf.len()).await;
        self.inner.send_to(buf, target).await
    }
    fn local_addr(&self) -> std::result::Result<SocketAddr, webrtc_util::Error> {
        self.inner.local_addr()
    }
    fn remote_addr(&self) -> Option<SocketAddr> {
        self.inner.remote_addr()
    }
    async fn close(&self) -> std::result::Result<(), webrtc_util::Error> {
        self.inner.close().await
    }
    fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
        self
    }
}

/// Relay-address generator that delegates allocation to the static
/// generator, then wraps each allocation's relay socket in a
/// [`ThrottledConn`] when a per-connection cap is configured. The cap is
/// global (every allocation gets the same limit).
struct ThrottledRelayGenerator {
    inner: RelayAddressGeneratorStatic,
    max_bps: u64,
    /// Relay sockets are bound from this inclusive port window instead of
    /// the OS ephemeral range, so operators open one small, predictable
    /// UDP range at the firewall. `min <= max` is guaranteed at
    /// construction.
    min_port: u16,
    max_port: u16,
    /// Round-robin starting point so we don't rescan held low ports on
    /// every allocation — just a spread hint, not load-bearing.
    cursor: std::sync::atomic::AtomicU16,
    allocation_scope: LocalApplicationResourceScope,
}

impl ThrottledRelayGenerator {
    /// Bind a relay socket on the first free port in `[min_port, max_port]`,
    /// scanning from a rotating cursor. Returns the same `(conn, addr)`
    /// the static generator would, so the caller can wrap it.
    async fn allocate_in_range(
        &self,
        use_ipv4: bool,
    ) -> std::result::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), TurnError> {
        let span = (self.max_port - self.min_port) as u32 + 1;
        let start = self
            .cursor
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed) as u32;
        let mut last_err: Option<TurnError> = None;
        for i in 0..span {
            let port = self.min_port + ((start + i) % span) as u16;
            match self.inner.allocate_conn(use_ipv4, port).await {
                Ok(pair) => return Ok(pair),
                Err(e) => last_err = Some(e),
            }
        }
        // `span >= 1` is guaranteed at construction (min <= max), so the
        // loop always ran at least once and set `last_err` on failure.
        Err(last_err.expect("relay port range is non-empty"))
    }
}

#[async_trait]
impl RelayAddressGenerator for ThrottledRelayGenerator {
    fn validate(&self) -> std::result::Result<(), TurnError> {
        self.inner.validate()
    }

    async fn allocate_conn(
        &self,
        use_ipv4: bool,
        requested_port: u16,
    ) -> std::result::Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), TurnError> {
        // The generator retains the owner scope for the lifetime of the
        // server; allocation admission itself is performed by the vendored
        // Manager immediately before this bind.
        let _ = &self.allocation_scope;
        #[cfg(test)]
        let allocation_lease = self
            .allocation_scope
            .acquire(turn_allocation_claim())
            .map_err(|_| TurnError::ErrTryAgain)?;
        // The TURN server passes 0 for normal allocations. With a fixed
        // window configured (min_port != 0) pick from it so relay traffic
        // lands on a small firewall-able range; otherwise (min_port == 0,
        // the default) fall through to the OS ephemeral range — unbounded.
        // A non-zero requested_port (e.g. EVEN-PORT) is always honored.
        let (conn, addr) = if requested_port == 0 && self.min_port != 0 {
            self.allocate_in_range(use_ipv4).await?
        } else {
            self.inner.allocate_conn(use_ipv4, requested_port).await?
        };
        if self.max_bps == 0 {
            #[cfg(test)]
            {
                return Ok((
                    Arc::new(AllocationLeaseConn::new(conn, allocation_lease)),
                    addr,
                ));
            }
            #[cfg(not(test))]
            return Ok((conn, addr));
        }
        let throttled: Arc<dyn Conn + Send + Sync> = Arc::new(ThrottledConn::new(
            {
                #[cfg(test)]
                {
                    Arc::new(AllocationLeaseConn::new(conn, allocation_lease))
                }
                #[cfg(not(test))]
                {
                    conn
                }
            },
            self.max_bps,
        ));
        Ok((throttled, addr))
    }
}

/// Long-term credential auth handler backed by a static username → key
/// map. The key is the MD5 digest `generate_auth_key` computes from
/// `username:realm:password`, which is what the TURN message-integrity
/// check compares against — so we never store the plaintext password
/// past startup.
struct StaticAuthHandler {
    cred_map: HashMap<String, Vec<u8>>,
}

impl StaticAuthHandler {
    fn new(realm: &str, creds: &[TurnCredential]) -> Self {
        let mut cred_map = HashMap::with_capacity(unique_credentials(creds));
        for c in creds {
            cred_map.insert(
                c.username.clone(),
                generate_auth_key(&c.username, realm, &c.password),
            );
        }
        Self { cred_map }
    }
}

impl AuthHandler for StaticAuthHandler {
    fn auth_handle(
        &self,
        username: &str,
        _realm: &str,
        _src_addr: SocketAddr,
    ) -> std::result::Result<Vec<u8>, TurnError> {
        self.cred_map
            .get(username)
            .cloned()
            .ok_or(TurnError::ErrNoSuchUser)
    }
}

/// A running TURN server. Constructed via
/// [`TurnServer::start_with_resource_scope`].
pub struct TurnServer;

/// Actual normalized acquisitions at the no-client startup peak and Ready.
pub struct TurnStartupResourcePlan {
    pub startup_peak: ResourceClaim,
    pub ready_retained: ResourceClaim,
    pub transient_peak: ResourceClaim,
}

struct StartRequest {
    bind: String,
    realm: String,
    credentials: Vec<TurnCredential>,
    port: u16,
    relay_ip: IpAddr,
    relay_port_min: u16,
    relay_port_max: u16,
    max_bps: u64,
    scope: LocalApplicationResourceScope,
    tcp: Option<myownmesh_core::FundedArc<crate::turn_stream::BridgeState>>,
    tcp_enabled: bool,
    tls_proxy_port: Option<u16>,
}

// The password-bearing Box is freed before releasing its transient lease.
struct OwnedStartRequest {
    request: Box<StartRequest>,
    lease: ResourceLease,
}

pub(crate) struct TurnControl {
    state: SyncMutex<TurnControlState>,
    ready: Notify,
    stop: Notify,
    stopping: AtomicBool,
    #[cfg(test)]
    probe: Option<turn::resource::CleanupProbe>,
}

struct TurnControlState {
    request: Option<OwnedStartRequest>,
    ready: Option<SocketAddr>,
    startup_finished: bool,
    result: Option<Result<()>>,
    runtime_destroyed: bool,
}

pub(crate) struct TurnBacking {
    control: myownmesh_core::FundedArc<TurnControl>,
    runtime: ResourceLease,
    derived: ResourceLease,
    tcp: Option<myownmesh_core::FundedArc<crate::turn_stream::BridgeState>>,
}

impl TurnBacking {
    pub(crate) fn release_after_join(self, unobserved: bool) {
        let Self {
            control,
            runtime,
            derived,
            tcp,
        } = self;
        // Even a lifecycle panic cannot release client/task backing before
        // private runtime destruction and the outside worker join.
        if unobserved && tcp.is_some() {
            // There is no safe detach/refund fallback for an unobserved runtime.
            std::process::abort();
        } else {
            if let Some(state) = &tcp {
                state.join_after_runtime_destroyed();
            }
            drop(tcp);
        }
        drop(control);
        for lease in [runtime, derived] {
            if unobserved {
                if lease.retain_after_failed_cleanup().is_err() {
                    std::process::abort();
                }
            } else {
                drop(lease);
            }
        }
    }
}

impl TurnControl {
    fn request_stop(&self) {
        self.stopping.store(true, Ordering::Release);
        self.stop.notify_one();
    }

    async fn stopped(&self) {
        loop {
            let wake = self.stop.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            if self.stopping.load(Ordering::Acquire) {
                return;
            }
            wake.await;
        }
    }

    async fn ready_result(&self) -> Result<SocketAddr> {
        loop {
            let wake = self.ready.notified();
            tokio::pin!(wake);
            wake.as_mut().enable();
            {
                let mut state = self
                    .state
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if let Some(addr) = state.ready {
                    return Ok(addr);
                }
                if state.startup_finished {
                    return Err(match state.result.take() {
                        Some(Err(error)) => error,
                        _ => Error::Cleanup(crate::ServiceCleanupError::WorkerJoin),
                    });
                }
            }
            wake.await;
        }
    }
}

/// The outside root retains these allocations through the worker join. Caller
/// cancellation signals only; it cannot abort the private lifecycle task.
pub struct TurnServerHandle {
    control: myownmesh_core::FundedArc<TurnControl>,
    terminal: myownmesh_core::FundedArc<crate::cleanup::ServiceCompletion>,
    custody: crate::cleanup::ServiceCustody,
    local_addr: SocketAddr,
    relay_ip: IpAddr,
    tcp_local_addr: Option<SocketAddr>,
    tls_proxy_local_addr: Option<SocketAddr>,
}

impl TurnServerHandle {
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }
    pub fn relay_ip(&self) -> IpAddr {
        self.relay_ip
    }

    /// Successfully bound TCP control listener, when explicitly enabled.
    pub fn tcp_local_addr(&self) -> Option<SocketAddr> {
        self.tcp_local_addr
    }

    /// Loopback-only PROXYv2 backend; not evidence of external TLS readiness.
    pub fn tls_proxy_local_addr(&self) -> Option<SocketAddr> {
        self.tls_proxy_local_addr
    }

    pub async fn stop(mut self) -> Result<()> {
        self.control.request_stop();
        self.custody.submit();
        self.terminal.wait_joined().await;
        self.custody.observe_disposition();
        let mut state = self
            .control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state
            .result
            .take()
            .unwrap_or(Err(Error::Cleanup(crate::ServiceCleanupError::WorkerJoin)))
    }
}

impl Drop for TurnServerHandle {
    fn drop(&mut self) {
        self.control.request_stop();
        self.custody.submit();
    }
}

// Armed before the first constructor await. No owned task, join, new thread or
// allocation occurs in this Drop; the existing private worker sees the signal.
struct TurnStartGuard {
    control: myownmesh_core::FundedArc<TurnControl>,
    custody: Option<crate::cleanup::ServiceCustody>,
}

impl Drop for TurnStartGuard {
    fn drop(&mut self) {
        if self.custody.is_some() {
            self.control.request_stop();
        }
        // ServiceCustody's Drop submits the already registered entry.
    }
}

struct WorkerExitGuard {
    control: myownmesh_core::FundedArc<TurnControl>,
    completed: bool,
}

impl Drop for WorkerExitGuard {
    fn drop(&mut self) {
        if self.completed {
            return;
        }
        let mut state = self
            .control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.result.is_none() {
            state.result = Some(Err(Error::Cleanup(crate::ServiceCleanupError::WorkerJoin)));
        }
        state.startup_finished = true;
        drop(state);
        self.control.ready.notify_waiters();
    }
}

fn run_turn_worker(
    control: myownmesh_core::FundedArc<TurnControl>,
) -> crate::cleanup::WorkerOutcome {
    let mut exit = WorkerExitGuard {
        control: control.clone(),
        completed: false,
    };
    let mut runtime_started = false;
    // Runtime is owned OUTSIDE block_on, so both normal return and unwind
    // destroy it on this independent worker, never on the caller's runtime.
    let observed = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .map_err(|error| Error::Cleanup(crate::ServiceCleanupError::WorkerStart(error)))?;
        runtime_started = true;
        let child_control = control.clone();
        let result = runtime.block_on(async move {
            let lifecycle = tokio::spawn(run_turn_lifecycle(child_control));
            match lifecycle.await {
                Ok(result) => result,
                Err(error) => Err(Error::TaskJoin(error.to_string())),
            }
        });
        drop(runtime);
        control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .runtime_destroyed = true;
        result
    }));
    let mut state = control
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    let result = match observed {
        Ok(result) => result,
        Err(_) => Err(Error::Cleanup(crate::ServiceCleanupError::WorkerJoin)),
    };
    let failed = result.is_err();
    let unobserved = runtime_started && !state.runtime_destroyed;
    let runtime_destroyed = state.runtime_destroyed;
    state.result = Some(result);
    state.startup_finished = true;
    exit.completed = true;
    drop(state);
    control.ready.notify_waiters();
    crate::cleanup::WorkerOutcome {
        task_failed: failed,
        cleanup_unobserved: unobserved,
        runtime_destroyed,
    }
}

async fn run_turn_lifecycle(control: myownmesh_core::FundedArc<TurnControl>) -> Result<()> {
    #[cfg(test)]
    if let Some(probe) = &control.probe {
        probe.before_startup_request().await;
    }
    let owned = control
        .state
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .request
        .take()
        .expect("one-shot funded TURN startup request");
    #[cfg(test)]
    if let Some(probe) = &control.probe {
        probe.mark_request_taken();
    }
    let OwnedStartRequest {
        request,
        lease: transient_lease,
    } = owned;
    let StartRequest {
        bind,
        realm,
        credentials,
        port,
        relay_ip,
        relay_port_min,
        relay_port_max,
        max_bps,
        scope,
        tcp,
        tcp_enabled,
        tls_proxy_port,
    } = *request;
    let bind_addr = format!("{bind}:{port}");
    drop(bind);
    // Native bind and reactor registration both happen on this private runtime.
    let conn = Arc::new(
        UdpSocket::bind(&bind_addr)
            .await
            .map_err(|error| Error::Bind(bind_addr.clone(), error))?,
    );
    let local_addr = conn
        .local_addr()
        .map_err(|error| Error::Bind(bind_addr.clone(), error))?;
    let credential_count = credentials.len();
    let auth_handler = Arc::new(StaticAuthHandler::new(&realm, &credentials));
    drop(credentials); // no plaintext password in any Ready/control/handle owner
    #[cfg(test)]
    if let Some(probe) = &control.probe {
        probe.mark_plaintext_dropped();
    }
    let relay_ports = if relay_port_min == 0 {
        "OS ephemeral range".to_string()
    } else {
        format!("{relay_port_min}-{relay_port_max}")
    };
    let log_realm = realm.clone();
    let config = ServerConfig {
        conn_configs: vec![ConnConfig {
            conn,
            relay_addr_generator: Box::new(ThrottledRelayGenerator {
                inner: RelayAddressGeneratorStatic {
                    relay_address: relay_ip,
                    address: "0.0.0.0".to_owned(),
                    net: Arc::new(Net::new(None)),
                },
                max_bps,
                min_port: relay_port_min,
                max_port: relay_port_max,
                cursor: std::sync::atomic::AtomicU16::new(0),
                allocation_scope: scope.clone(),
            }),
        }],
        realm,
        auth_handler,
        channel_bind_timeout: Duration::from_secs(0),
        alloc_close_notify: None,
    };
    let admission = Arc::new(TurnResourceAdmission {
        scope: scope.clone(),
    });
    #[cfg(test)]
    let server = match &control.probe {
        Some(probe) => {
            Server::new_with_resource_admission_and_cleanup_probe(config, admission, probe.clone())
                .await
        }
        None => Server::new_with_resource_admission(config, admission).await,
    };
    #[cfg(not(test))]
    let server = Server::new_with_resource_admission(config, admission).await;
    let server = server.map_err(|error| Error::Turn(error.to_string()))?;
    let bridge = match tcp {
        Some(state) => match crate::turn_stream::TurnTcpBridge::bind(
            local_addr,
            state,
            scope,
            tcp_enabled,
            tls_proxy_port,
        )
        .await
        {
            Ok(bridge) => Some(bridge),
            Err(error) => {
                // Retain the first bind error, but close the already-running
                // UDP server before publishing failed startup.
                let _ = server.close().await;
                return Err(error);
            }
        },
        None => None,
    };
    info!(
        %local_addr, %relay_ip, realm = %log_realm, credentials = credential_count,
        relay_ports = %relay_ports,
        "TURN listening — open UDP {} (control) and the relay ports ({}) at the firewall AND your cloud/provider security group",
        port, relay_ports
    );
    drop((bind_addr, log_realm, relay_ports));
    #[cfg(test)]
    if let Some(probe) = &control.probe {
        probe.before_startup_ready().await;
    }
    drop(transient_lease);
    #[cfg(test)]
    if let Some(probe) = &control.probe {
        probe.mark_transient_released();
    }
    {
        let mut state = control
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.ready = Some(local_addr);
        state.startup_finished = true;
    }
    control.ready.notify_waiters();
    let bridge_result = match bridge {
        Some(bridge) => bridge.run(control.stopped()).await,
        None => {
            control.stopped().await;
            Ok(())
        }
    };
    let udp_result = server
        .close()
        .await
        .map_err(|error| Error::Turn(error.to_string()));
    bridge_result.and(udp_result)
}

pub(crate) fn claim_bytes(
    bytes: usize,
    residual: u64,
) -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
    Ok(ResourceClaim::try_from_entries([
        (
            ResourceClass::AccountedMemoryBytes,
            u64::try_from(bytes).map_err(|_| byte_overflow())?,
        ),
        (ResourceClass::OpaqueDependencyResidual, residual),
    ])?)
}

pub(crate) fn byte_overflow() -> crate::ServiceCleanupError {
    myownmesh_core::ResourceClaimArithmeticError::Overflow {
        dimension: ResourceClass::AccountedMemoryBytes,
    }
    .into()
}

fn add_bytes(left: usize, right: usize) -> std::result::Result<usize, crate::ServiceCleanupError> {
    left.checked_add(right).ok_or_else(byte_overflow)
}

fn mul_bytes(left: usize, right: usize) -> std::result::Result<usize, crate::ServiceCleanupError> {
    left.checked_mul(right).ok_or_else(byte_overflow)
}

fn unique_credentials(credentials: &[TurnCredential]) -> usize {
    credentials
        .iter()
        .enumerate()
        .filter(|(index, credential)| {
            !credentials[..*index]
                .iter()
                .any(|earlier| earlier.username == credential.username)
        })
        .count()
}

fn runtime_claim() -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
    // Private runtime representation plus a declared platform-dependent
    // Poll/Waker/reactor opaque residual; NOT exact native handle containment.
    Ok(
        claim_bytes(std::mem::size_of::<tokio::runtime::Runtime>(), 1)?
            .checked_add(ResourceClaim::single(ResourceClass::WorkerOrTask, 1))?,
    )
}

fn derived_claim(
    config: &TurnServiceConfig,
) -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
    let mut bytes = std::mem::size_of::<StaticAuthHandler>();
    bytes = add_bytes(bytes, std::mem::size_of::<ThrottledRelayGenerator>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<Net>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<TurnResourceAdmission>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<Server>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<UdpSocket>())?;
    bytes = add_bytes(bytes, "0.0.0.0".len())?;
    bytes = add_bytes(bytes, mul_bytes(config.realm.len(), 2)?)?;
    for (index, credential) in config.credentials.iter().enumerate() {
        if config.credentials[..index]
            .iter()
            .any(|earlier| earlier.username == credential.username)
        {
            continue;
        }
        bytes = add_bytes(bytes, std::mem::size_of::<(String, Vec<u8>)>())?;
        bytes = add_bytes(bytes, credential.username.len())?;
        bytes = add_bytes(bytes, turn::auth::auth_key_len())?;
    }
    // One persistent derived object graph: logical bytes above are explicit;
    // hash buckets/Arc/allocator control remain dependency-private residual.
    claim_bytes(bytes, 1)
}

fn transient_claim(
    config: &TurnServiceConfig,
) -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
    let mut bytes = std::mem::size_of::<StartRequest>();
    bytes = add_bytes(bytes, std::mem::size_of::<ServerConfig>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<ConnConfig>())?;
    bytes = add_bytes(bytes, std::mem::size_of::<tokio::runtime::Builder>())?;
    bytes = add_bytes(
        bytes,
        mul_bytes(
            config.credentials.len(),
            std::mem::size_of::<TurnCredential>(),
        )?,
    )?;
    bytes = add_bytes(bytes, config.bind.len())?;
    bytes = add_bytes(bytes, config.realm.len())?;
    let mut derivation_peak = 0;
    for credential in &config.credentials {
        bytes = add_bytes(bytes, credential.username.len())?;
        bytes = add_bytes(bytes, credential.password.len())?;
        let formatted = add_bytes(
            add_bytes(credential.username.len(), config.realm.len())?,
            add_bytes(credential.password.len(), ":".len() * 2)?,
        )?;
        let insertion = add_bytes(credential.username.len(), turn::auth::auth_key_len())?;
        derivation_peak = derivation_peak.max(add_bytes(formatted, insertion)?);
    }
    bytes = add_bytes(bytes, derivation_peak)?;
    let bind_format = add_bytes(
        add_bytes(config.bind.len(), ":".len())?,
        decimal_len(config.port),
    )?;
    bytes = add_bytes(bytes, bind_format)?;
    bytes = add_bytes(bytes, config.realm.len())?; // startup log copy
    let relay_format = if config.relay_port_min == 0 {
        "OS ephemeral range".len()
    } else {
        add_bytes(
            add_bytes(decimal_len(config.relay_port_min), "-".len())?,
            decimal_len(config.relay_port_max.max(config.relay_port_min)),
        )?
    };
    bytes = add_bytes(bytes, relay_format)?;
    claim_bytes(bytes, 1)
}

fn decimal_len(mut value: u16) -> usize {
    let mut count = 1;
    while value >= 10 {
        value /= 10;
        count += 1;
    }
    count
}

impl TurnServer {
    pub fn startup_resource_plan(
        config: &TurnServiceConfig,
    ) -> std::result::Result<TurnStartupResourcePlan, crate::ServiceCleanupError> {
        use crate::cleanup::{planned, record_claim};
        let cleanup_charge =
            turn::resource::CleanupStatus::charge().map_err(|_| byte_overflow())?;
        let mut ready_retained = planned(turn_startup_claim())?
            .checked_add(crate::ServiceCleanupPort::entry_planning_charge()?)?
            .checked_add(planned(record_claim::<TurnControl>()?)?)?
            .checked_add(planned(runtime_claim()?)?)?
            .checked_add(planned(derived_claim(config)?)?)?
            .checked_add(planned(turn_resource_claim(
                ResourceKind::CleanupRecord,
                cleanup_charge,
            )?)?)?
            .checked_add(planned(turn_resource_claim(
                ResourceKind::ReadLoop,
                ResourceCharge::units(1),
            )?)?)?
            .checked_add(planned(turn_resource_claim(
                ResourceKind::CommandLoop,
                ResourceCharge::units(1),
            )?)?)?;
        if config.tcp_enabled || config.tls_proxy_enabled {
            ready_retained =
                ready_retained.checked_add(planned(crate::turn_stream::root_claim(
                    config.tcp_max_connections,
                    u64::from(config.tcp_enabled) + u64::from(config.tls_proxy_enabled),
                )?)?)?;
        }
        let transient_peak = planned(transient_claim(config)?)?;
        let startup_peak = ready_retained.checked_add(transient_peak)?;
        Ok(TurnStartupResourcePlan {
            startup_peak,
            ready_retained,
            transient_peak,
        })
    }

    pub fn startup_planning_charge(
        config: &TurnServiceConfig,
    ) -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
        Ok(Self::startup_resource_plan(config)?.startup_peak)
    }

    /// Normalized custody for one TCP client, excluding the shared bridge root
    /// and any independently admitted TURN allocations created by its traffic.
    pub fn tcp_client_planning_charge(
    ) -> std::result::Result<ResourceClaim, crate::ServiceCleanupError> {
        crate::cleanup::planned(crate::turn_stream::client_claim()?)
    }

    /// Unscoped startup remains nonbinding; no implicit root or grant exists.
    pub async fn start(config: &TurnServiceConfig) -> Result<TurnServerHandle> {
        let _ = config;
        Err(Error::Resource(
            "owner-selected resource scope required; use start_with_resource_scope".into(),
        ))
    }

    pub async fn start_with_resource_scope(
        config: &TurnServiceConfig,
        scope: LocalApplicationResourceScope,
        cleanup: crate::ServiceCleanupPort,
    ) -> Result<TurnServerHandle> {
        Self::start_inner(
            config,
            scope,
            cleanup,
            #[cfg(test)]
            None,
        )
        .await
    }

    async fn start_inner(
        config: &TurnServiceConfig,
        scope: LocalApplicationResourceScope,
        cleanup: crate::ServiceCleanupPort,
        #[cfg(test)] probe: Option<turn::resource::CleanupProbe>,
    ) -> Result<TurnServerHandle> {
        config
            .validate_tcp()
            .map_err(|error| Error::TurnConfig(error.to_string()))?;
        if config.credentials.is_empty() {
            return Err(Error::TurnConfig(
                "TURN requires at least one username/password credential".into(),
            ));
        }
        let relay_ip = resolve_relay_ip(config)?;
        let tcp = if config.tcp_enabled || config.tls_proxy_enabled {
            Some(crate::turn_stream::reserve(
                &scope,
                config.tcp_max_connections,
                config.tcp_max_connections_per_ip,
                config
                    .tcp_idle_timeout()
                    .map_err(|error| Error::TurnConfig(error.to_string()))?,
                config
                    .tcp_auth_timeout()
                    .map_err(|error| Error::TurnConfig(error.to_string()))?,
                u64::from(config.tcp_enabled) + u64::from(config.tls_proxy_enabled),
            )?)
        } else {
            None
        };
        // Every acquisition precedes the allocations it protects and the
        // outstanding-node registration; normalization is per acquisition.
        let service_lease = scope
            .acquire(turn_startup_claim())
            .map_err(|error| Error::Resource(error.to_string()))?;
        let control_lease = scope
            .acquire(crate::cleanup::record_claim::<TurnControl>()?)
            .map_err(crate::ServiceCleanupError::from)?;
        let runtime_lease = scope
            .acquire(runtime_claim()?)
            .map_err(crate::ServiceCleanupError::from)?;
        let derived_lease = scope
            .acquire(derived_claim(config)?)
            .map_err(crate::ServiceCleanupError::from)?;
        let transient_lease = scope
            .acquire(transient_claim(config)?)
            .map_err(crate::ServiceCleanupError::from)?;
        let request = OwnedStartRequest {
            request: Box::new(StartRequest {
                bind: config.bind.clone(),
                realm: config.realm.clone(),
                credentials: config.credentials.clone(),
                port: config.port,
                relay_ip,
                relay_port_min: config.relay_port_min,
                relay_port_max: config.relay_port_max.max(config.relay_port_min),
                max_bps: config.max_bps_per_connection,
                scope: scope.clone(),
                tcp: tcp.clone(),
                tcp_enabled: config.tcp_enabled,
                tls_proxy_port: config.tls_proxy_enabled.then_some(config.tls_proxy_port),
            }),
            lease: transient_lease,
        };
        let control = crate::cleanup::funded(
            TurnControl {
                state: SyncMutex::new(TurnControlState {
                    request: Some(request),
                    ready: None,
                    startup_finished: false,
                    result: None,
                    runtime_destroyed: false,
                }),
                ready: Notify::new(),
                stop: Notify::new(),
                stopping: AtomicBool::new(false),
                #[cfg(test)]
                probe,
            },
            control_lease,
        );
        let mut custody = cleanup.reserve(&scope, service_lease)?;
        let terminal = custody.completion();
        custody.set_turn_backing(TurnBacking {
            control: control.clone(),
            runtime: runtime_lease,
            derived: derived_lease,
            tcp,
        });
        let mut guard = TurnStartGuard {
            control: control.clone(),
            custody: Some(custody),
        };
        let worker_control = control.clone();
        if let Err(error) = guard
            .custody
            .as_mut()
            .expect("armed startup")
            .spawn_worker(move || run_turn_worker(worker_control))
        {
            guard.control.request_stop();
            guard.custody.as_mut().expect("armed startup").submit();
            terminal.wait_joined().await;
            guard
                .custody
                .as_ref()
                .expect("armed startup")
                .observe_disposition();
            return Err(error.into());
        }
        let local_addr = match control.ready_result().await {
            Ok(addr) => addr,
            Err(error) => {
                guard.control.request_stop();
                guard.custody.as_mut().expect("armed startup").submit();
                terminal.wait_joined().await;
                guard
                    .custody
                    .as_ref()
                    .expect("armed startup")
                    .observe_disposition();
                return Err(error);
            }
        };
        let custody = guard.custody.take().expect("one startup handoff");
        Ok(TurnServerHandle {
            control,
            terminal,
            custody,
            local_addr,
            relay_ip,
            tcp_local_addr: config.tcp_enabled.then_some(local_addr),
            tls_proxy_local_addr: config
                .tls_proxy_enabled
                .then_some(SocketAddr::from(([127, 0, 0, 1], config.tls_proxy_port))),
        })
    }
}

fn turn_startup_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 4),
        // One bounded final-custody channel/worker handoff residual.
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
    .expect("fixed TURN startup claim is representable")
}

#[cfg(test)]
fn turn_allocation_claim() -> ResourceClaim {
    ResourceClaim::try_from_entries([
        (ResourceClass::RelayOrProviderAllocation, 1),
        (ResourceClass::SocketOrHandle, 1),
        (ResourceClass::WorkerOrTask, 2),
        // Bounded dependency state retained by one relay allocation.
        (ResourceClass::OpaqueDependencyResidual, 1),
    ])
    .expect("fixed TURN allocation claim is representable")
}

/// Resolve the IP a TURN allocation should advertise. Prefers
/// `public_ip`; falls back to the bind address; rejects a wildcard
/// (clients can't connect to 0.0.0.0).
fn resolve_relay_ip(config: &TurnServiceConfig) -> Result<IpAddr> {
    let candidate = if config.public_ip.trim().is_empty() {
        config.bind.trim()
    } else {
        config.public_ip.trim()
    };
    let ip: IpAddr = candidate
        .parse()
        .map_err(|_| Error::TurnConfig(format!("relay address '{candidate}' is not a valid IP")))?;
    if ip.is_unspecified() {
        return Err(Error::TurnConfig(
            "TURN public_ip must be set to the server's routable address when bind is a wildcard \
             (0.0.0.0 / ::)"
                .into(),
        ));
    }
    Ok(ip)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cleanup::test_support::{with_runtime, TestRoot};

    fn turn_child_panic_control(command_panics: bool) {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        let root = TestRoot::new();
        let config = loopback_config();
        let plan = TurnServer::startup_resource_plan(&config).unwrap();
        let probe_plan = crate::cleanup::planned(
            turn_resource_claim(
                ResourceKind::CleanupRecord,
                turn::resource::CleanupProbe::charge(),
            )
            .unwrap(),
        )
        .unwrap();
        let grant = plan
            .startup_peak
            .checked_add(probe_plan)
            .unwrap()
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let probe = turn::resource::CleanupProbe::new(&TurnResourceAdmission {
            scope: scope.clone(),
        })
        .unwrap();
        if command_panics {
            probe.panic_command_on_close();
        } else {
            probe.panic_read_after_command_join();
        }
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let observed = runtime.block_on(async {
            let server =
                TurnServer::start_inner(&config, scope.clone(), root.port(), Some(probe.clone()))
                    .await?;
            let terminal = server.terminal.clone();
            let control = server.control.clone();
            drop(server);
            probe.wait_command_held().await;
            probe.wait_parent_before_abort().await;
            probe.wait_vec_taken().await;
            Ok::<_, Error>((terminal, control))
        });
        drop(runtime);
        probe.release_vec();
        probe.release_parent();
        let report = root.close();
        let observed = observed.map(|(terminal, control)| {
            let joined = terminal.is_joined() && terminal.runtime_destroyed();
            let failed = terminal.task_failed();
            let result = control
                .state
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .result
                .take();
            drop((terminal, control));
            (joined, failed, result)
        });
        let both_joined = probe.command_terminal() && probe.command_joined() && probe.read_joined();
        drop((probe, scope, provider_port));
        let (joined, failed, result) =
            observed.expect("real TURN startup before injected child panic");
        let expected = if command_panics {
            "ServerCommand"
        } else {
            "ServerRead"
        };
        assert!(joined && failed && both_joined);
        assert!(
            matches!(result, Some(Err(Error::Turn(error))) if error.contains(expected)),
            "the actual descendant layer must reach the wrapper result"
        );
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 1);
        assert_eq!(report.worker_failures, 0);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn turn_command_panic_propagates_after_read_runtime_and_worker_join() {
        turn_child_panic_control(true);
    }

    #[test]
    fn turn_read_panic_propagates_after_command_runtime_and_worker_join() {
        turn_child_panic_control(false);
    }

    fn startup_custody_control(
        before_ready: bool,
        cancel_constructor: bool,
        panic_lifecycle: bool,
    ) {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        use std::future::Future;
        use std::task::Poll;
        let root = TestRoot::new();
        let mut config = loopback_config();
        // Distinct derived names plus duplicate replacement and long borrowed
        // input exercise config-dependent claims without a numeric grant bump.
        config.realm = "owned-realm".repeat(37);
        config.credentials = vec![
            cred("alice", &"old-password".repeat(41)),
            cred(&"long-user".repeat(29), &"password".repeat(53)),
            cred("alice", "replacement"),
        ];
        let plan = TurnServer::startup_resource_plan(&config).unwrap();
        let probe_plan = crate::cleanup::planned(
            turn_resource_claim(
                ResourceKind::CleanupRecord,
                turn::resource::CleanupProbe::charge(),
            )
            .unwrap(),
        )
        .unwrap();
        let grant = plan
            .startup_peak
            .checked_add(probe_plan)
            .unwrap()
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let probe = turn::resource::CleanupProbe::new(&TurnResourceAdmission {
            scope: scope.clone(),
        })
        .unwrap();
        if before_ready {
            probe.hold_startup_before_ready();
        } else {
            probe.hold_startup_before_request();
        }
        if panic_lifecycle {
            probe.panic_startup_before_request();
        }
        let baseline = provider.in_use();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let (pending, held, requests_held, plaintext_held, transient_held, completed) = runtime
            .block_on(async {
                let starting = TurnServer::start_inner(
                    &config,
                    scope.clone(),
                    root.port(),
                    Some(probe.clone()),
                );
                tokio::pin!(starting);
                let pending =
                    std::future::poll_fn(|cx| Poll::Ready(starting.as_mut().poll(cx).is_pending()))
                        .await;
                probe.wait_startup_held().await;
                let held = provider.in_use().checked_sub(baseline);
                let requests = probe.requests_taken();
                let plaintext = probe.plaintext_dropped();
                let transient = probe.transient_released();
                let completed = if cancel_constructor {
                    None
                } else {
                    probe.release_startup();
                    Some(starting.await.map(|server| {
                        let ready = provider.in_use().checked_sub(baseline);
                        let request_empty = server
                            .control
                            .state
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner)
                            .request
                            .is_none();
                        let transient_released = probe.transient_released();
                        let terminal = server.terminal.clone();
                        drop(server);
                        (ready, request_empty, transient_released, terminal)
                    }))
                };
                (pending, held, requests, plaintext, transient, completed)
                // Cancellation destroys the actual pinned constructor here; its
                // registered guard signals the already existing private worker.
            });
        drop(runtime);
        if cancel_constructor {
            probe.release_startup();
        }
        // Permits may precede entry: no success depends on scheduling a lab
        // alternate command terminator. The real abort remains the terminator.
        probe.release_vec();
        probe.release_parent();
        let report = root.close();
        let completed = completed.map(|result| {
            result.map(|(ready, request_empty, transient_released, terminal)| {
                let joined = terminal.is_joined() && terminal.runtime_destroyed();
                drop(terminal);
                (ready, request_empty, transient_released, joined)
            })
        });
        let requests_final = probe.requests_taken();
        let plaintext_final = probe.plaintext_dropped();
        let transient_final = probe.transient_released();
        drop((probe, scope, provider_port));
        assert!(pending && !transient_held);
        assert_eq!(requests_held, usize::from(before_ready));
        assert_eq!(plaintext_held, before_ready);
        if before_ready {
            assert_eq!(held.unwrap(), plan.startup_peak);
        } else {
            assert!(held.unwrap().amount(ResourceClass::AccountedMemoryBytes) > 0);
        }
        assert_eq!(
            plan.startup_peak,
            plan.ready_retained
                .checked_add(plan.transient_peak)
                .unwrap()
        );
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, u64::from(panic_lifecycle));
        assert_eq!(report.worker_failures, 0);
        if panic_lifecycle {
            assert!(matches!(completed, Some(Err(Error::TaskJoin(_)))));
            assert_eq!(requests_final, 0);
        } else {
            assert_eq!(requests_final, 1);
            assert!(plaintext_final && transient_final);
            if cancel_constructor {
                assert!(completed.is_none());
            } else {
                let (ready, request_empty, transient_released, joined) =
                    completed.unwrap().expect("exact planned Ready");
                assert_eq!(ready.unwrap(), plan.ready_retained);
                assert!(request_empty && transient_released && joined);
            }
        }
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    fn turn_constructor_cancel_before_request_keeps_registered_custody() {
        startup_custody_control(false, true, false);
    }

    #[test]
    fn turn_constructor_cancel_after_native_startup_joins_same_worker() {
        startup_custody_control(true, true, false);
    }

    #[test]
    fn turn_config_peak_and_ready_split_releases_one_shot_plaintext() {
        startup_custody_control(true, false, false);
    }

    #[test]
    fn turn_lifecycle_startup_panic_wakes_constructor_and_preserves_failure() {
        startup_custody_control(false, false, true);
    }

    mod dynamic_wire {
        use super::*;
        use myownmesh_core::FundedArc;
        use stun::agent::TransactionId;
        use stun::message::{
            Getter, Message, MessageType, CLASS_REQUEST, CLASS_SUCCESS_RESPONSE,
            METHOD_CHANNEL_BIND,
        };

        pub(super) const CHANNEL_REPLY: &[u8] = b"owned-channel-return";

        #[derive(Clone, Copy, PartialEq, Eq)]
        struct BindDescriptor {
            transaction: TransactionId,
            channel: u16,
            peer: SocketAddr,
        }

        #[derive(Default)]
        struct WireState {
            server: Option<SocketAddr>,
            peer: Option<SocketAddr>,
            bind: Option<BindDescriptor>,
            sent: bool,
            accepted: bool,
            channel_data: bool,
            failure: Option<&'static str>,
        }

        struct WireObservation {
            state: SyncMutex<WireState>,
            changed: Notify,
        }

        impl WireObservation {
            fn fail(&self, reason: &'static str) {
                self.state.lock().unwrap().failure.get_or_insert(reason);
                self.changed.notify_waiters();
            }

            async fn wait_bound(&self) -> std::result::Result<(), String> {
                loop {
                    let changed = self.changed.notified();
                    tokio::pin!(changed);
                    changed.as_mut().enable();
                    {
                        let state = self.state.lock().unwrap();
                        if let Some(error) = state.failure {
                            return Err(error.into());
                        }
                        if state.sent && state.accepted {
                            return Ok(());
                        }
                    }
                    changed.await;
                }
            }

            fn sending(&self, packet: &[u8], to: SocketAddr) -> Option<BindDescriptor> {
                let mut message = Message::new();
                if message.unmarshal_binary(packet).is_err()
                    || message.typ != MessageType::new(METHOD_CHANNEL_BIND, CLASS_REQUEST)
                {
                    return None;
                }
                let mut channel = turn::proto::channum::ChannelNumber::default();
                let mut peer = turn::proto::peeraddr::PeerAddress::default();
                if channel.get_from(&message).is_err()
                    || peer.get_from(&message).is_err()
                    || !channel.valid()
                {
                    self.fail("malformed actual ChannelBind request");
                    return None;
                }
                let descriptor = BindDescriptor {
                    transaction: message.transaction_id,
                    channel: channel.0,
                    peer: SocketAddr::new(peer.ip, peer.port),
                };
                let mut state = self.state.lock().unwrap();
                if state.server != Some(to)
                    || state.peer != Some(descriptor.peer)
                    || state.bind.is_some_and(|prior| prior != descriptor)
                {
                    state.failure.get_or_insert(
                        "ChannelBind did not name the original server/peer/transaction",
                    );
                } else {
                    // Installed before forwarding: an immediate reply cannot
                    // race an absent descriptor. Actual send success is separate.
                    state.bind = Some(descriptor);
                }
                drop(state);
                self.changed.notify_waiters();
                Some(descriptor)
            }

            fn received(&self, packet: &[u8], from: SocketAddr) {
                let mut message = Message::new();
                if message.unmarshal_binary(packet).is_ok() {
                    let mut state = self.state.lock().unwrap();
                    if state
                        .bind
                        .is_some_and(|bind| bind.transaction == message.transaction_id)
                    {
                        if state.server == Some(from)
                            && message.typ
                                == MessageType::new(METHOD_CHANNEL_BIND, CLASS_SUCCESS_RESPONSE)
                        {
                            state.accepted = true;
                        } else {
                            state.failure.get_or_insert(
                                "original ChannelBind transaction refused or mismatched",
                            );
                        }
                    }
                } else if turn::proto::chandata::ChannelData::is_channel_data(packet) {
                    let mut data = turn::proto::chandata::ChannelData {
                        raw: packet.to_vec(),
                        ..Default::default()
                    };
                    let decoded = data.decode().is_ok();
                    let mut state = self.state.lock().unwrap();
                    if decoded
                        && state.server == Some(from)
                        && state.accepted
                        && state.bind.is_some_and(|bind| bind.channel == data.number.0)
                        && data.data.as_slice() == CHANNEL_REPLY
                    {
                        state.channel_data = true;
                    } else {
                        state.failure.get_or_insert(
                            "raw ChannelData did not match the admitted channel/payload",
                        );
                    }
                }
                self.changed.notify_waiters();
            }
        }

        struct ObservedConn {
            socket: UdpSocket,
            observation: FundedArc<WireObservation>,
        }

        #[async_trait]
        impl Conn for ObservedConn {
            async fn connect(&self, addr: SocketAddr) -> webrtc_util::Result<()> {
                Conn::connect(&self.socket, addr).await
            }
            async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
                Conn::recv(&self.socket, buf).await
            }
            async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
                let result = Conn::recv_from(&self.socket, buf).await;
                match &result {
                    Ok((len, from)) => self.observation.received(&buf[..*len], *from),
                    Err(_) => self.observation.fail("original client receive failed"),
                }
                result
            }
            async fn send(&self, buf: &[u8]) -> webrtc_util::Result<usize> {
                Conn::send(&self.socket, buf).await
            }
            async fn send_to(&self, buf: &[u8], to: SocketAddr) -> webrtc_util::Result<usize> {
                let descriptor = self.observation.sending(buf, to);
                let result = Conn::send_to(&self.socket, buf, to).await;
                if descriptor.is_some() {
                    let mut state = self.observation.state.lock().unwrap();
                    if matches!(&result, Ok(len) if *len == buf.len()) {
                        state.sent = true;
                    } else {
                        state
                            .failure
                            .get_or_insert("original ChannelBind send failed or was short");
                    }
                    drop(state);
                    self.observation.changed.notify_waiters();
                } else if result.is_err() {
                    self.observation.fail("original client send failed");
                }
                result
            }
            fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
                Conn::local_addr(&self.socket)
            }
            fn remote_addr(&self) -> Option<SocketAddr> {
                Conn::remote_addr(&self.socket)
            }
            async fn close(&self) -> webrtc_util::Result<()> {
                self.observation.fail("original client socket closed");
                Conn::close(&self.socket).await
            }
            fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
                self
            }
        }

        /// The client API requires Arc<dyn Conn>. Keep its allocation lease
        /// OUTSIDE that Arc until the exact last strong AND weak owner is gone.
        /// This guard lives outside the caller runtime; no client task owns it.
        pub(super) struct WireFixture {
            observation: FundedArc<WireObservation>,
            delegate: Option<std::sync::Weak<ObservedConn>>,
            delegate_lease: Option<ResourceLease>,
        }

        impl WireFixture {
            pub(super) fn new(
                scope: &LocalApplicationResourceScope,
            ) -> std::result::Result<Self, String> {
                let observation_claim =
                    crate::cleanup::record_claim::<WireObservation>().map_err(|e| e.to_string())?;
                let delegate_claim =
                    crate::cleanup::record_claim::<ObservedConn>().map_err(|e| e.to_string())?;
                let observation_lease = scope
                    .acquire(observation_claim)
                    .map_err(|e| e.to_string())?;
                let delegate_lease = scope.acquire(delegate_claim).map_err(|e| e.to_string())?;
                Ok(Self {
                    observation: crate::cleanup::funded(
                        WireObservation {
                            state: SyncMutex::new(WireState::default()),
                            changed: Notify::new(),
                        },
                        observation_lease,
                    ),
                    delegate: None,
                    delegate_lease: Some(delegate_lease),
                })
            }

            pub(super) fn wrap(
                &mut self,
                socket: UdpSocket,
                server: SocketAddr,
            ) -> std::result::Result<Arc<dyn Conn + Send + Sync>, String> {
                if self.delegate.is_some() {
                    return Err("one exact client delegate already installed".into());
                }
                self.observation.state.lock().unwrap().server = Some(server);
                let conn = Arc::new(ObservedConn {
                    socket,
                    observation: self.observation.clone(),
                });
                self.delegate = Some(Arc::downgrade(&conn));
                Ok(conn)
            }

            pub(super) fn expect_peer(&self, peer: SocketAddr) {
                self.observation.state.lock().unwrap().peer = Some(peer);
            }

            pub(super) async fn wait_bound(&self) -> std::result::Result<(), String> {
                self.observation.wait_bound().await
            }

            pub(super) fn channel_data_seen(&self) -> bool {
                let state = self.observation.state.lock().unwrap();
                state.sent && state.accepted && state.channel_data && state.failure.is_none()
            }

            fn release_delegate(&mut self) -> bool {
                let deallocated = self
                    .delegate
                    .as_ref()
                    .is_none_or(|weak| weak.strong_count() == 0);
                drop(self.delegate.take()); // last Weak allocation owner before lease
                if let Some(lease) = self.delegate_lease.take() {
                    if deallocated {
                        drop(lease);
                    } else if lease.retain_after_failed_cleanup().is_err() {
                        std::process::abort();
                    }
                }
                deallocated
            }

            pub(super) fn finish(mut self) -> bool {
                self.release_delegate()
            }
        }

        impl Drop for WireFixture {
            fn drop(&mut self) {
                self.release_delegate();
            }
        }

        async fn exchange(
            socket: &UdpSocket,
            server: SocketAddr,
            request: Message,
        ) -> std::result::Result<Message, String> {
            let sent = socket
                .send_to(&request.raw, server)
                .await
                .map_err(|e| e.to_string())?;
            if sent != request.raw.len() {
                return Err("short reservation request send".into());
            }
            let mut packet = [0; 1500];
            let (len, from) = socket
                .recv_from(&mut packet)
                .await
                .map_err(|e| e.to_string())?;
            let mut response = Message::new();
            response
                .unmarshal_binary(&packet[..len])
                .map_err(|e| e.to_string())?;
            if from != server || response.transaction_id != request.transaction_id {
                return Err("reservation response source/transaction mismatch".into());
            }
            Ok(response)
        }

        pub(super) struct ReservedWire {
            // Field order closes the original socket before its separate lease.
            socket: UdpSocket,
            _socket_lease: ResourceLease,
            pub(super) relay_addr: SocketAddr,
        }

        impl ReservedWire {
            pub(super) fn original_client_addr(&self) -> std::result::Result<SocketAddr, String> {
                self.socket.local_addr().map_err(|e| e.to_string())
            }
        }

        /// Exactly two real transactions, sharing the caller's existing total
        /// workload deadline: challenge, then authenticated EVEN-PORT Allocate.
        pub(super) async fn reserve_even_port(
            server: SocketAddr,
            realm: &str,
            scope: &LocalApplicationResourceScope,
        ) -> std::result::Result<ReservedWire, String> {
            use stun::attributes::{ATTR_NONCE, ATTR_REALM, ATTR_USERNAME};
            use stun::error_code::{ErrorCodeAttribute, CODE_UNAUTHORIZED};
            use stun::fingerprint::FINGERPRINT;
            use stun::integrity::MessageIntegrity;
            use stun::message::{CLASS_ERROR_RESPONSE, METHOD_ALLOCATE};
            use stun::textattrs::{Nonce, Realm, Username};
            use turn::proto::{
                evenport::EvenPort, relayaddr::RelayedAddress, reqtrans::RequestedTransport,
                rsrvtoken::ReservationToken, PROTO_UDP,
            };

            fn reserve_next_port() -> std::result::Result<EvenPort, String> {
                let mut attribute = Message::new();
                attribute.add(stun::attributes::ATTR_EVEN_PORT, &[0b10000000]);
                let mut even_port = EvenPort::default();
                even_port.get_from(&attribute).map_err(|e| e.to_string())?;
                Ok(even_port)
            }

            let socket_lease = scope
                .acquire(ResourceClaim::single(ResourceClass::SocketOrHandle, 1))
                .map_err(|e| e.to_string())?;
            let socket = UdpSocket::bind("127.0.0.1:0")
                .await
                .map_err(|e| e.to_string())?;
            let mut initial = Message::new();
            initial
                .build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
                    Box::new(RequestedTransport {
                        protocol: PROTO_UDP,
                    }),
                    Box::new(reserve_next_port()?),
                    Box::new(FINGERPRINT),
                ])
                .map_err(|e| e.to_string())?;
            let challenge = exchange(&socket, server, initial).await?;
            let mut code = ErrorCodeAttribute::default();
            code.get_from(&challenge).map_err(|e| e.to_string())?;
            if challenge.typ != MessageType::new(METHOD_ALLOCATE, CLASS_ERROR_RESPONSE)
                || code.code != CODE_UNAUTHORIZED
            {
                return Err(
                    "reservation request did not receive the real authentication challenge".into(),
                );
            }
            let nonce = Nonce::get_from_as(&challenge, ATTR_NONCE).map_err(|e| e.to_string())?;
            let returned_realm =
                Realm::get_from_as(&challenge, ATTR_REALM).map_err(|e| e.to_string())?;
            if returned_realm.text != realm {
                return Err("reservation challenge realm mismatch".into());
            }
            let integrity = MessageIntegrity::new_long_term_integrity(
                "alice".into(),
                realm.into(),
                "s3cret".into(),
            );
            let mut authenticated = Message::new();
            authenticated
                .build(&[
                    Box::new(TransactionId::new()),
                    Box::new(MessageType::new(METHOD_ALLOCATE, CLASS_REQUEST)),
                    Box::new(RequestedTransport {
                        protocol: PROTO_UDP,
                    }),
                    Box::new(reserve_next_port()?),
                    Box::new(Username::new(ATTR_USERNAME, "alice".into())),
                    Box::new(returned_realm),
                    Box::new(nonce),
                    Box::new(integrity.clone()),
                    Box::new(FINGERPRINT),
                ])
                .map_err(|e| e.to_string())?;
            let mut response = exchange(&socket, server, authenticated).await?;
            if response.typ != MessageType::new(METHOD_ALLOCATE, CLASS_SUCCESS_RESPONSE) {
                return Err("authenticated reservation Allocate refused".into());
            }
            integrity.check(&mut response).map_err(|e| e.to_string())?;
            let mut token = ReservationToken::default();
            token.get_from(&response).map_err(|e| e.to_string())?;
            let mut relayed = RelayedAddress::default();
            relayed.get_from(&response).map_err(|e| e.to_string())?;
            let addr = SocketAddr::new(relayed.ip, relayed.port);
            if token.0.is_empty()
                || !addr.ip().is_loopback()
                || addr.port() == 0
                || addr.port() % 2 != 0
            {
                return Err(
                    "reservation success did not carry the actual token/even relay address".into(),
                );
            }
            // Getter validates the owning protocol token width. Never consume
            // it in a later Allocate or send Refresh(0) before service teardown.
            Ok(ReservedWire {
                socket,
                _socket_lease: socket_lease,
                relay_addr: addr,
            })
        }
    }

    #[test]
    #[ignore = "real TURN allocation/channel/reservation and caller-runtime destruction; external watchdog required"]
    fn dynamic_turn_allocation_descendants_end_with_private_runtime_before_root_refund() {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        use turn::client::{Client, ClientConfig};
        let root = TestRoot::new();
        // Same pre-existing bounded service-fixture grant. This is not a
        // maximum-workload or exact dynamic-capacity qualification.
        let provider = FiniteResourceProvider::new(test_grant());
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let probe = turn::resource::CleanupProbe::new(&TurnResourceAdmission {
            scope: scope.clone(),
        })
        .unwrap();
        let mut wire =
            dynamic_wire::WireFixture::new(&scope).expect("exact observer/delegate claims");
        let baseline = provider.in_use();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let observed = runtime.block_on(async {
            let mut config = loopback_config();
            config.relay_port_min = 0;
            config.relay_port_max = 0;
            let server =
                TurnServer::start_inner(&config, scope.clone(), root.port(), Some(probe.clone()))
                    .await?;
            let ready = provider.in_use();
            let traffic = tokio::time::timeout(Duration::from_secs(3), async {
                let conn = wire.wrap(
                    UdpSocket::bind("127.0.0.1:0")
                        .await
                        .map_err(|e| e.to_string())?,
                    server.local_addr(),
                )?;
                let client = Client::new(ClientConfig {
                    stun_serv_addr: String::new(),
                    turn_serv_addr: server.local_addr().to_string(),
                    username: "alice".into(),
                    password: "s3cret".into(),
                    realm: config.realm.clone(),
                    software: String::new(),
                    rto_in_ms: 0,
                    conn,
                    vnet: None,
                })
                .await
                .map_err(|e| e.to_string())?;
                client.listen().await.map_err(|e| e.to_string())?;
                let relay = client.allocate().await.map_err(|e| e.to_string())?;
                let peer = UdpSocket::bind("127.0.0.1:0")
                    .await
                    .map_err(|e| e.to_string())?;
                let peer_addr = peer.local_addr().map_err(|e| e.to_string())?;
                wire.expect_peer(peer_addr);
                // The first send returns SendIndication wire bytes, not payload bytes.
                let _wire_sent = relay
                    .send_to(b"owned-descendants", peer_addr)
                    .await
                    .map_err(|e| e.to_string())?;
                let mut packet = [0; 32];
                let (received, from) = peer
                    .recv_from(&mut packet)
                    .await
                    .map_err(|e| e.to_string())?;
                let actual_relay = relay.local_addr().map_err(|e| e.to_string())?;
                let traffic_ok = received == b"owned-descendants".len()
                    && &packet[..received] == b"owned-descendants"
                    && from == actual_relay;
                // The first send can be SendIndication. Await the exact server
                // ChannelBind success, not a guessed client Binding READY.
                wire.wait_bound().await?;
                let reply_sent = peer
                    .send_to(dynamic_wire::CHANNEL_REPLY, actual_relay)
                    .await
                    .map_err(|e| e.to_string())?;
                let (reply_len, reply_from) = relay
                    .recv_from(&mut packet)
                    .await
                    .map_err(|e| e.to_string())?;
                let channel_ok = reply_sent == dynamic_wire::CHANNEL_REPLY.len()
                    && &packet[..reply_len] == dynamic_wire::CHANNEL_REPLY
                    && reply_from == peer_addr
                    && wire.channel_data_seen();
                let reservation =
                    dynamic_wire::reserve_even_port(server.local_addr(), &config.realm, &scope)
                        .await?;
                let reservation_ok = reservation.relay_addr != actual_relay
                    && reservation.original_client_addr()?.port() != 0;
                // Do not send Refresh(0) via relay.close(): the server's actual
                // allocation/permission/channel/reservation remain for teardown.
                // The second client socket closes before its own lease; server
                // reservation/token/timer remain independent of that UDP close.
                drop((relay, client, peer, reservation));
                let dynamic = provider.in_use().checked_sub(ready);
                Ok::<_, String>((traffic_ok, channel_ok, reservation_ok, dynamic))
            })
            .await;
            Ok::<_, Error>((server, traffic))
        });
        drop(runtime); // client runtime and its tasks cannot own the service reactor
        let observed = observed.map(|(server, traffic)| {
            let terminal = server.terminal.clone();
            drop(server);
            (terminal, traffic)
        });
        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if observed.is_ok() {
            observer.block_on(async {
                probe.wait_command_held().await;
                probe.wait_parent_before_abort().await;
                probe.wait_vec_taken().await;
            });
        }
        drop(observer);
        let held = observed
            .as_ref()
            .is_ok_and(|(terminal, _)| !terminal.is_joined())
            && provider.in_use().amount(ResourceClass::WorkerOrTask)
                > baseline.amount(ResourceClass::WorkerOrTask);
        probe.release_vec();
        probe.release_parent();
        let report = root.close();
        let observed = observed.map(|(terminal, traffic)| {
            let joined = terminal.is_joined() && terminal.runtime_destroyed();
            drop(terminal);
            (joined, traffic)
        });
        let vendor_joined =
            probe.command_terminal() && probe.command_joined() && probe.read_joined();
        let delegate_freed = wire.finish();
        drop((probe, scope, provider_port));
        let (joined, traffic) = observed.expect("real TURN service startup");
        let (traffic_ok, channel_ok, reservation_ok, dynamic) = traffic
            .expect("existing bounded wire deadline")
            .expect("real allocation/permission/channel/reservation traffic");
        let dynamic = dynamic.expect("retained server dynamic claims");
        assert!(
            traffic_ok && held && joined && vendor_joined,
            "traffic_ok={traffic_ok}, held={held}, joined={joined}, vendor_joined={vendor_joined}"
        );
        assert!(channel_ok && reservation_ok && delegate_freed);
        assert!(dynamic.amount(ResourceClass::SocketOrHandle) > 0);
        assert!(dynamic.amount(ResourceClass::WorkerOrTask) > 0);
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 0);
        assert_eq!(report.worker_failures, 0);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
        assert_eq!(
            provider.retained_after_failed_cleanup(),
            ResourceClaim::ZERO
        );
    }

    #[test]
    #[ignore = "real private TURN runtime and three native close gates; external watchdog required"]
    fn caller_runtime_drop_joins_held_turn_command_read_and_private_runtime() {
        use myownmesh_core::{FiniteResourceProvider, ResourceProviderPort};
        use std::future::Future;
        use std::task::Poll;
        let root = TestRoot::new();
        let config = loopback_config();
        let plan = TurnServer::startup_resource_plan(&config).expect("actual config plan");
        let probe_plan = crate::cleanup::planned(
            turn_resource_claim(
                ResourceKind::CleanupRecord,
                turn::resource::CleanupProbe::charge(),
            )
            .unwrap(),
        )
        .unwrap();
        let grant = plan
            .startup_peak
            .checked_add(probe_plan)
            .unwrap()
            .checked_add(
                FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap();
        let provider = FiniteResourceProvider::new(grant);
        let provider_port = ResourceProviderPort::new(provider.clone()).unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&provider_port).unwrap();
        let probe = turn::resource::CleanupProbe::new(&TurnResourceAdmission {
            scope: scope.clone(),
        })
        .unwrap();
        let baseline = provider.in_use();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let observations = runtime.block_on(async {
            let server =
                TurnServer::start_inner(&config, scope.clone(), root.port(), Some(probe.clone()))
                    .await?;
            let ready_delta = provider.in_use().checked_sub(baseline);
            let terminal = server.terminal.clone();
            let port = server.local_addr().port();
            let stopping = server.stop();
            tokio::pin!(stopping);
            let first_pending =
                std::future::poll_fn(|cx| Poll::Ready(stopping.as_mut().poll(cx).is_pending()))
                    .await;
            probe.wait_command_held().await;
            probe.wait_parent_before_abort().await;
            probe.wait_vec_taken().await;
            let all_held = !terminal.is_joined() && !probe.command_terminal();
            // The actual stop future is destroyed at this lexical boundary.
            Ok::<_, Error>((terminal, port, first_pending, all_held, ready_delta))
        });
        eprintln!("turn-custody/v1 before-caller-runtime-drop");
        drop(runtime);
        eprintln!("turn-custody/v1 after-caller-runtime-drop");
        // Release Vec only. Observe the real read-await entry before checking
        // that the separately held parent/command still prevent completion.
        probe.release_vec();
        let observer = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        if observations.is_ok() {
            observer.block_on(probe.wait_read_join_started());
        }
        drop(observer);
        let held_after_vec = observations
            .as_ref()
            .is_ok_and(|(terminal, _, _, _, _)| !terminal.is_joined() && !probe.command_terminal());
        let held_delta = provider.in_use().checked_sub(baseline);
        probe.release_parent(); // real production abort terminates the child
        let report = root.close();
        let observed =
            observations.map(|(terminal, port, first_pending, all_held, ready_delta)| {
                let joined = terminal.is_joined();
                let runtime_destroyed = terminal.runtime_destroyed();
                drop(terminal);
                (
                    port,
                    first_pending,
                    all_held,
                    ready_delta,
                    joined,
                    runtime_destroyed,
                )
            });
        let command_terminal = probe.command_terminal();
        let command_joined = probe.command_joined();
        let read_joined = probe.read_joined();
        drop((probe, scope, provider_port));
        let final_use = provider.in_use();
        let failed = provider.retained_after_failed_cleanup();
        let (port, first_pending, all_held, ready_delta, joined, runtime_destroyed) =
            observed.expect("real TURN setup");
        assert!(first_pending && all_held && held_after_vec);
        assert_eq!(ready_delta.unwrap(), plan.ready_retained);
        assert_eq!(held_delta.unwrap(), plan.ready_retained);
        assert!(command_terminal && command_joined && read_joined && runtime_destroyed && joined);
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 0);
        assert_eq!(report.worker_failures, 0);
        assert_eq!(final_use, ResourceClaim::ZERO);
        assert_eq!(failed, ResourceClaim::ZERO);
        with_runtime(|cleanup| async move {
            let mut config = loopback_config();
            config.port = port;
            start_with_scope(&cleanup, &config)
                .await
                .expect("same TURN port reusable")
                .stop()
                .await
                .unwrap();
        });
    }

    fn test_grant() -> ResourceClaim {
        ResourceClaim::try_from_entries(
            ResourceClass::ALL
                .into_iter()
                .map(|class| (class, 1_000_000)),
        )
        .expect("test provider grant is representable")
    }

    fn test_scope() -> LocalApplicationResourceScope {
        let port = myownmesh_core::ResourceProviderPort::new(
            myownmesh_core::FiniteResourceProvider::new(test_grant()),
        )
        .expect("test provider is valid");
        LocalApplicationResourceScope::transport_lab_child_of(&port)
            .expect("test application scope is valid")
    }

    fn allocation_fixture_grant(raw: ResourceClaim) -> ResourceClaim {
        crate::cleanup::planned(raw)
            .unwrap()
            .checked_add(
                myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                    .checked_scale(2)
                    .unwrap(),
            )
            .unwrap()
    }

    async fn start_with_scope(
        cleanup: &crate::ServiceCleanupPort,
        config: &TurnServiceConfig,
    ) -> Result<TurnServerHandle> {
        TurnServer::start_with_resource_scope(config, test_scope(), cleanup.clone()).await
    }

    fn cred(u: &str, p: &str) -> TurnCredential {
        TurnCredential {
            username: u.into(),
            password: p.into(),
        }
    }

    fn loopback_config() -> TurnServiceConfig {
        TurnServiceConfig {
            enabled: true,
            bind: "127.0.0.1".into(),
            port: 0,
            public_ip: "127.0.0.1".into(),
            realm: "myownmesh".into(),
            credentials: vec![cred("alice", "s3cret")],
            max_bps_per_connection: 0,
            relay_port_min: 49152,
            relay_port_max: 50151,
            ..Default::default()
        }
    }

    #[test]
    fn rejects_missing_credentials() {
        with_runtime(|cleanup| async move {
            let mut cfg = loopback_config();
            cfg.credentials.clear();
            assert!(matches!(
                start_with_scope(&cleanup, &cfg).await,
                Err(Error::TurnConfig(_))
            ));
        });
    }

    #[test]
    fn rejects_wildcard_bind_without_public_ip() {
        with_runtime(|cleanup| async move {
            let cfg = TurnServiceConfig {
                enabled: true,
                bind: "0.0.0.0".into(),
                port: 0,
                public_ip: "".into(),
                realm: "myownmesh".into(),
                credentials: vec![cred("alice", "pw")],
                max_bps_per_connection: 0,
                relay_port_min: 49152,
                relay_port_max: 50151,
                ..Default::default()
            };
            assert!(matches!(
                start_with_scope(&cleanup, &cfg).await,
                Err(Error::TurnConfig(_))
            ));
        });
    }

    #[test]
    fn starts_and_stops_on_loopback() {
        with_runtime(|cleanup| async move {
            let server = start_with_scope(&cleanup, &loopback_config())
                .await
                .unwrap();
            assert_ne!(server.local_addr().port(), 0);
            assert_eq!(server.relay_ip().to_string(), "127.0.0.1");
            server.stop().await.unwrap();
        });
    }

    #[test]
    fn runtime_ended_before_drop_is_reaped_without_runtime_reentry() {
        let root = TestRoot::new();
        let (server, terminal) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let server = start_with_scope(&root.port(), &loopback_config())
                    .await
                    .unwrap();
                let terminal = server.terminal.clone();
                (server, terminal)
            })
        };
        drop(server);
        let report = root.close();
        assert!(terminal.is_joined());
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 0);
        assert_eq!(report.worker_failures, 0);
    }

    #[test]
    fn current_thread_drop_observes_worker_before_runtime_destruction() {
        // Drop returns first; the outside owner, not caller-runtime progress,
        // supplies the actual private runtime/worker terminal observation.
        let root = TestRoot::new();
        let (terminal, port) = {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            runtime.block_on(async {
                let server = start_with_scope(&root.port(), &loopback_config())
                    .await
                    .unwrap();
                let terminal = server.terminal.clone();
                let port = server.local_addr().port();
                drop(server);
                (terminal, port)
            })
        };
        let report = root.close();
        assert!(terminal.is_joined());
        assert_eq!(report.completed, 1);
        assert_eq!(report.worker_failures, 0);
        with_runtime(|cleanup| async move {
            let mut config = loopback_config();
            config.port = port;
            start_with_scope(&cleanup, &config)
                .await
                .expect("exact port reusable")
                .stop()
                .await
                .unwrap();
        });
    }

    #[test]
    fn failed_final_submission_runs_the_owned_job_without_detach() {
        // The repaired interface has no fallible submission or caller-thread
        // fallback. Close refuses NEW entries but accepts this admitted one.
        let root = TestRoot::new();
        let scope = test_scope();
        let port = root.port();
        let mut custody = port
            .reserve(&scope, scope.acquire(turn_startup_claim()).unwrap())
            .unwrap();
        let terminal = custody.completion();
        custody.spawn_stun_observer().unwrap();
        root.begin_close();
        let refused = port.reserve(&scope, scope.acquire(turn_startup_claim()).unwrap());
        let closed = matches!(refused, Err(crate::ServiceCleanupError::Closed));
        drop(refused);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let task = tokio::spawn(async {});
            custody.finish_stun(Some(task), false);
            terminal.wait_joined().await;
            custody.observe_disposition();
        });
        drop(runtime);
        drop((custody, port));
        let report = root.close();
        assert!(closed);
        assert!(
            terminal.is_joined(),
            "the admitted original job was not detached"
        );
        assert_eq!(report.completed, 1);
        assert_eq!(report.task_failures, 0);
        assert_eq!(report.worker_failures, 0);
    }

    #[test]
    fn stopped_turn_releases_the_exact_control_port_for_reuse() {
        with_runtime(|cleanup| async move {
            let mut config = loopback_config();
            let first = start_with_scope(&cleanup, &config).await.unwrap();
            let port = first.local_addr().port();
            first.stop().await.unwrap();

            config.port = port;
            let second = start_with_scope(&cleanup, &config).await.unwrap();
            assert_eq!(second.local_addr().port(), port);
            second.stop().await.unwrap();
        });
    }

    #[test]
    fn exact_startup_grant_rejects_n_plus_one_and_reuses_after_stop() {
        with_runtime(|cleanup| async move {
            let insufficient_port = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(
                    crate::cleanup::planned(
                        turn_startup_claim()
                            .checked_sub(ResourceClaim::single(ResourceClass::WorkerOrTask, 1))
                            .unwrap(),
                    )
                    .unwrap()
                    .checked_add(
                        myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                            .checked_scale(2)
                            .unwrap(),
                    )
                    .unwrap(),
                ),
            )
            .unwrap();
            let insufficient_scope =
                LocalApplicationResourceScope::transport_lab_child_of(&insufficient_port).unwrap();
            assert!(matches!(
                TurnServer::start_with_resource_scope(
                    &loopback_config(),
                    insufficient_scope,
                    cleanup.clone()
                )
                .await,
                Err(Error::Resource(_))
            ));

            let port = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(
                    TurnServer::startup_planning_charge(&loopback_config())
                        .unwrap()
                        .checked_add(
                            myownmesh_core::FiniteResourceProvider::scope_planning_charge()
                                .checked_scale(2)
                                .unwrap(),
                        )
                        .unwrap(),
                ),
            )
            .unwrap();
            let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
            let config = loopback_config();
            let first =
                TurnServer::start_with_resource_scope(&config, scope.clone(), cleanup.clone())
                    .await
                    .unwrap();
            let refused =
                TurnServer::start_with_resource_scope(&config, scope.clone(), cleanup.clone())
                    .await;
            assert!(matches!(refused, Err(Error::Resource(_))));
            first.stop().await.unwrap();
            TurnServer::start_with_resource_scope(&config, scope, cleanup.clone())
                .await
                .unwrap()
                .stop()
                .await
                .unwrap();
        });
    }

    #[test]
    fn active_stop_observes_turn_close_terminal() {
        with_runtime(|cleanup| async move {
            let server = start_with_scope(&cleanup, &loopback_config())
                .await
                .unwrap();
            let terminal = server.terminal.clone();

            server.stop().await.unwrap();

            assert!(terminal.is_joined());
        });
    }

    #[test]
    fn final_task_custody_observes_exact_reaper_handle() {
        with_runtime(|cleanup| async move {
            let before = cleanup.report_for_test().completed;
            let scope = test_scope();
            let mut custody = cleanup
                .reserve(&scope, scope.acquire(turn_startup_claim()).unwrap())
                .unwrap();
            let terminal = custody.completion();
            custody.spawn_stun_observer().unwrap();
            let task = tokio::spawn(async {});
            custody.finish_stun(Some(task), false);
            terminal.wait_joined().await;
            custody.observe_disposition();
            assert_eq!(
                cleanup.report_for_test().completed,
                before + 1,
                "the exact original task and final worker are joined"
            );
            assert!(
                cleanup.accepting_for_test(),
                "the outside root remains alive for another entry"
            );
            assert!(!terminal.task_failed());
        });
    }

    #[test]
    fn drop_outside_runtime_is_reaped_by_runtime_owner() {
        with_runtime(|cleanup| async move {
            let server = start_with_scope(&cleanup, &loopback_config())
                .await
                .unwrap();
            let terminal = server.terminal.clone();
            let notified = terminal.wait_joined();

            std::thread::spawn(move || drop(server))
                .join()
                .expect("drop thread panicked");
            notified.await;

            assert!(terminal.is_joined());
        });
    }

    #[test]
    fn relay_allocations_land_in_configured_range() {
        with_runtime(|_cleanup| async move {
            // An allocation with no requested port must draw from the bounded
            // relay range, so operators can open one small UDP window.
            let generator = ThrottledRelayGenerator {
                inner: RelayAddressGeneratorStatic {
                    relay_address: "127.0.0.1".parse().unwrap(),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(Net::new(None)),
                },
                max_bps: 0,
                min_port: 50500,
                max_port: 50519,
                cursor: std::sync::atomic::AtomicU16::new(0),
                allocation_scope: test_scope(),
            };
            match generator.allocate_conn(true, 0).await {
                Ok((_conn, addr)) => assert!(
                    (50500..=50519).contains(&addr.port()),
                    "relay port {} is outside the configured range",
                    addr.port()
                ),
                // The whole 20-port window can be unbindable in a sandboxed CI
                // host, and that is not a logic failure. Windows reserves dynamic
                // "excluded port ranges" (Hyper-V/WinNAT) that shift per boot and
                // can swallow a small window entirely — the bind then returns
                // WSAEACCES (os error 10013); a hardened Linux sandbox can deny a
                // bind the same way. The allocator's contract is exactly what ran:
                // scan the range, surface an error only when nothing binds. So
                // accept an OS bind refusal instead of flaking CI over it, while
                // still failing on any *other* error (a real allocator bug).
                Err(e) => {
                    let msg = e.to_string().to_lowercase();
                    assert!(
                        msg.contains("permission")
                            || msg.contains("forbidden")
                            || msg.contains("denied")
                            || msg.contains("access"),
                        "relay allocation failed for a non-environmental reason: {e}"
                    );
                    eprintln!(
                        "relay_allocations_land_in_configured_range: host refused the whole \
                     50500-50519 window ({e}); skipping the range assertion"
                    );
                }
            }
        });
    }

    #[test]
    fn exact_allocation_grant_rejects_n_plus_one_and_reuses_after_close() {
        with_runtime(|_cleanup| async move {
            let port = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(allocation_fixture_grant(
                    turn_allocation_claim(),
                )),
            )
            .unwrap();
            let generator = ThrottledRelayGenerator {
                inner: RelayAddressGeneratorStatic {
                    relay_address: "127.0.0.1".parse().unwrap(),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(Net::new(None)),
                },
                max_bps: 0,
                min_port: 0,
                max_port: 0,
                cursor: std::sync::atomic::AtomicU16::new(0),
                allocation_scope: LocalApplicationResourceScope::transport_lab_child_of(&port)
                    .unwrap(),
            };
            let (first, _) = generator.allocate_conn(true, 0).await.unwrap();
            assert!(matches!(
                generator.allocate_conn(true, 0).await,
                Err(TurnError::ErrTryAgain)
            ));
            first.close().await.unwrap();
            let (reused, _) = generator.allocate_conn(true, 0).await.unwrap();
            reused.close().await.unwrap();
        });
    }

    #[test]
    fn vendor_admission_charges_exact_subtree_before_publication() {
        let port =
            myownmesh_core::ResourceProviderPort::new(myownmesh_core::FiniteResourceProvider::new(
                allocation_fixture_grant(turn_allocation_claim()),
            ))
            .unwrap();
        let scope = LocalApplicationResourceScope::transport_lab_child_of(&port).unwrap();
        let admission = TurnResourceAdmission {
            scope: scope.clone(),
        };

        let first = admission
            .acquire(ResourceKind::Allocation, ResourceCharge::units(1))
            .expect("the exact allocation subtree is funded");
        assert!(
            admission
                .acquire(ResourceKind::Allocation, ResourceCharge::units(1))
                .is_err(),
            "a second allocation must refuse before relay bind"
        );
        drop(first);
        admission
            .acquire(ResourceKind::Allocation, ResourceCharge::units(1))
            .expect("dropping the exact lease restores the allocation grant");
    }

    #[test]
    fn vendor_admission_refuses_each_allocation_dimension_before_bind() {
        for dimension in [
            ResourceClass::RelayOrProviderAllocation,
            ResourceClass::SocketOrHandle,
            ResourceClass::WorkerOrTask,
            ResourceClass::OpaqueDependencyResidual,
        ] {
            let grant = myownmesh_core::ResourceProviderPort::new(
                myownmesh_core::FiniteResourceProvider::new(allocation_fixture_grant(
                    turn_allocation_claim()
                        .checked_sub(ResourceClaim::single(dimension, 1))
                        .unwrap(),
                )),
            )
            .unwrap();
            let scope = LocalApplicationResourceScope::transport_lab_child_of(&grant).unwrap();
            let admission = TurnResourceAdmission { scope };
            assert!(
                admission
                    .acquire(ResourceKind::Allocation, ResourceCharge::units(1))
                    .is_err(),
                "allocation must refuse when {dimension:?} is one below its exact grant"
            );
        }
    }

    #[test]
    fn unbounded_range_falls_back_to_os_ephemeral() {
        with_runtime(|_cleanup| async move {
            // min_port == 0 is the default: no fixed window, allocation still
            // succeeds on an OS-assigned port (just not constrained).
            let generator = ThrottledRelayGenerator {
                inner: RelayAddressGeneratorStatic {
                    relay_address: "127.0.0.1".parse().unwrap(),
                    address: "127.0.0.1".to_owned(),
                    net: Arc::new(Net::new(None)),
                },
                max_bps: 0,
                min_port: 0,
                max_port: 0,
                cursor: std::sync::atomic::AtomicU16::new(0),
                allocation_scope: test_scope(),
            };
            let (_conn, addr) = generator.allocate_conn(true, 0).await.unwrap();
            assert_ne!(addr.port(), 0);
        });
    }

    #[test]
    fn byte_bucket_shapes_to_rate() {
        // rate 100_000 B/s → the configured rate is the burst capacity.
        let mut b = ByteBucket::new(100_000);
        let t0 = Instant::now();
        // First 100KB fits in the burst — no wait.
        assert!(b.try_consume(100_000, t0).is_none());
        // Immediately asking for 50KB more must wait ~0.5s (no refill).
        let wait = b.try_consume(50_000, t0).expect("should need to wait");
        assert!(
            wait.as_millis() >= 400 && wait.as_millis() <= 600,
            "got {wait:?}"
        );
        // After 1s of refill, the bucket is full again.
        assert!(b.try_consume(50_000, t0 + Duration::from_secs(1)).is_none());
    }

    #[test]
    fn byte_bucket_oversized_datagram_never_deadlocks() {
        // A datagram larger than a tiny cap's per-second budget still
        // drains (clamped to capacity) rather than waiting forever.
        let mut b = ByteBucket::new(1_000); // no hidden burst floor
        let t0 = Instant::now();
        // Drain the burst, then a full datagram is clamped to capacity.
        assert!(b.try_consume(65_536, t0).is_none());
        let wait = b
            .try_consume(65_536, t0)
            .expect("should wait but not forever");
        assert!(wait.as_secs_f64().is_finite());
    }

    #[test]
    fn turn_with_bandwidth_cap_starts() {
        with_runtime(|cleanup| async move {
            // A configured cap must not break startup or allocation wiring.
            let mut cfg = loopback_config();
            cfg.max_bps_per_connection = 256_000;
            let server = start_with_scope(&cleanup, &cfg).await.unwrap();
            assert_ne!(server.local_addr().port(), 0);
            server.stop().await.unwrap();
        });
    }

    #[test]
    fn auth_handler_keys_known_users_only() {
        let handler = StaticAuthHandler::new("myownmesh", &[cred("alice", "pw")]);
        let src: SocketAddr = "127.0.0.1:5000".parse().unwrap();
        let key = handler.auth_handle("alice", "myownmesh", src).unwrap();
        assert_eq!(key, generate_auth_key("alice", "myownmesh", "pw"));
        assert!(handler.auth_handle("mallory", "myownmesh", src).is_err());
    }

    // Proves the server actually serves on the wire: a real TURN client
    // sends a STUN Binding request through the TURN listener and gets a
    // reflexive address back. (A TURN server answers Binding requests as
    // part of being a TURN server.)
    #[test]
    fn answers_binding_request_through_turn_listener() {
        with_runtime(|cleanup| async move {
            use turn::client::{Client, ClientConfig};

            let server = start_with_scope(&cleanup, &loopback_config())
                .await
                .unwrap();
            let server_port = server.local_addr().port();

            let conn = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
            let client = Client::new(ClientConfig {
                stun_serv_addr: String::new(),
                turn_serv_addr: String::new(),
                username: String::new(),
                password: String::new(),
                realm: String::new(),
                software: String::new(),
                rto_in_ms: 0,
                conn,
                vnet: None,
            })
            .await
            .unwrap();
            client.listen().await.unwrap();

            let mapped = tokio::time::timeout(
                std::time::Duration::from_secs(3),
                client.send_binding_request_to(&format!("127.0.0.1:{server_port}")),
            )
            .await
            .expect("TURN binding request timed out")
            .expect("binding request failed");
            // The server saw us come from loopback.
            assert_eq!(mapped.ip().to_string(), "127.0.0.1");

            client.close().await.unwrap();
            server.stop().await.unwrap();
        });
    }
}
