//! User-facing facade — what embedders actually call.
//!
//! - [`Mesh`] is the entry constructor. One per process.
//! - [`MeshHandle`] is the device-level handle: identity,
//!   network join/leave, event stream.
//! - [`JoinedNetwork`] is the per-network handle: channels,
//!   RPC, topology, roster.

use std::sync::Arc;

use rand_core::RngCore;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, Mutex as AsyncMutex};
use tracing::info;

use crate::channels::Channel;
use crate::config::{MeshConfig, NetworkConfig, TopologyMode};
use crate::engine::connection::PeerStatus;
use crate::engine::ladder::ConnectionTier;
use crate::engine::state::{NetworkCmd, NetworkState};
use crate::engine::{
    create_network_in_mesh_scope, import_network_in_mesh_scope, spawn_network_in_mesh_scope,
};
use crate::error::{ClosedRelayError, Error, Result};
use crate::events::{MeshEvent, MeshPhase};
use crate::identity::Identity;
use crate::protocol::CapabilityAdvert;
use crate::resource::{
    LocalApplicationResourceScope, MeshRuntimeResourceScope, ProcessResourceRoot,
    ResourceProviderPort, ResourceReport,
};
use crate::roster::AuthorizedPeer;
use crate::rpc::Rpc;
use crate::runtime::attempt::{
    ConnectorResourceOwnerReport, MeshConnectorResourceReport, WebRtcConnectorCapablePolicy,
};
use crate::transport::{IceCandidateStats, SelectedCandidatePair, Transport};

#[cfg(feature = "transport-lab")]
pub use crate::engine::transport_lab::SemanticCommitFaultForLab;

/// One mesh instance bound to a single device identity. Constructs
/// the local identity on first call and shares the WebRTC API
/// across all joined networks.
pub struct Mesh {
    inner: Arc<MeshInner>,
}

struct MeshInner {
    identity: Arc<Identity>,
    transport: Transport,
    resource_scope: MeshRuntimeResourceScope,
    local_application_resources: LocalApplicationResourceScope,
    events_tx: broadcast::Sender<MeshEvent>,
}

/// The complete configuration classification used by network replacement.
/// Fields are named so callers cannot mistake a capacity or policy change for
/// an ordinary hot update.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[doc(hidden)]
pub struct ReconcileStatus {
    pub needs_restart: bool,
    pub network_id_changed: bool,
    pub signaling_changed: bool,
    pub closed_relay_changed: bool,
    pub semantic_policy_changed: bool,
    pub scheduler_changed: bool,
    pub hub_policy_changed: bool,
    pub tree_policy_changed: bool,
    pub local_observations_changed: bool,
    pub event_capacity_changed: bool,
    pub connection_trace_capacity_changed: bool,
}

struct JoinedNetworkLifecycle {
    /// The async mutex is intentionally held across the join: concurrent
    /// shutdown callers then wait for the same exact driver completion instead
    /// of the second caller observing an empty slot and returning early.
    driver: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Terminal result of the one driver join. Concurrent shutdown callers
    /// wait for the same driver lock and then observe this exact outcome
    /// rather than treating an already-consumed handle as success.
    shutdown_result: tokio::sync::Mutex<Option<std::result::Result<(), String>>>,
    fanout: AsyncMutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Mesh {
    /// Build an identity and infrastructure-only `Mesh` without connector
    /// authority.
    ///
    /// This form can host non-participating infrastructure services, but its
    /// handle cannot join a network or allocate a native peer connector. A
    /// network-capable owner must use [`Self::open_connector_capable`]
    /// and provide the reviewed process policy explicitly.
    pub async fn open_infrastructure_only(
        config: MeshConfig,
        resources: ResourceProviderPort,
    ) -> Result<MeshHandle> {
        let identity = Arc::new(crate::identity::load_or_create()?);
        Self::open_infrastructure_only_with_identity(config, identity, resources).await
    }

    /// Build a `Mesh` whose native connector allocations are admitted by the
    /// caller's process resource owner. Arc 03 supplies no fallback policy or
    /// inferred capacity.
    pub async fn open_connector_capable(
        config: MeshConfig,
        policy: WebRtcConnectorCapablePolicy,
    ) -> Result<MeshHandle> {
        let identity = Arc::new(crate::identity::load_or_create()?);
        Self::open_connector_capable_with_identity(config, identity, policy).await
    }

    /// Build a connector-capable lab mesh whose ICE agent accepts relay
    /// candidates only. The explicit feature-gated constructor prevents a
    /// benchmark control from silently changing the shipped daemon policy.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub async fn open_connector_capable_relay_only_for_lab(
        config: MeshConfig,
        policy: WebRtcConnectorCapablePolicy,
    ) -> Result<MeshHandle> {
        let identity = Arc::new(crate::identity::load_or_create()?);
        let event_capacity = config.event_capacity_usize()?;
        let transport =
            Transport::new_relay_only_for_lab()?.with_connector_resource_policy(policy)?;
        Self::open_with_identity_and_transport(identity, transport, event_capacity)
    }

    /// Build an infrastructure-only `Mesh` with a **caller-supplied identity**,
    /// for embedders
    /// that manage their own key storage rather than the on-disk anchor — e.g.
    /// a mobile app holding its ed25519 seed in the iOS Keychain / Android
    /// Keystore, or any host that has already loaded a key. Pair with
    /// [`Identity::from_signing_key`](crate::identity::Identity::from_signing_key).
    /// Otherwise identical to [`Mesh::open_infrastructure_only`]. It has no connector authority;
    /// use [`Self::open_connector_capable_with_identity`] for
    /// network participation.
    pub async fn open_infrastructure_only_with_identity(
        config: MeshConfig,
        identity: Arc<Identity>,
        resources: ResourceProviderPort,
    ) -> Result<MeshHandle> {
        let event_capacity = config.event_capacity_usize()?;
        ProcessResourceRoot::global().install_local_application_provider(resources)?;
        let transport = Transport::new()?;
        Self::open_with_identity_and_transport(identity, transport, event_capacity)
    }

    /// Identity-injected form of [`Self::open_connector_capable`].
    pub async fn open_connector_capable_with_identity(
        config: MeshConfig,
        identity: Arc<Identity>,
        policy: WebRtcConnectorCapablePolicy,
    ) -> Result<MeshHandle> {
        let event_capacity = config.event_capacity_usize()?;
        let transport = Transport::new()?.with_connector_resource_policy(policy)?;
        Self::open_with_identity_and_transport(identity, transport, event_capacity)
    }

    fn open_with_identity_and_transport(
        identity: Arc<Identity>,
        transport: Transport,
        event_capacity: usize,
    ) -> Result<MeshHandle> {
        let resource_scope = ProcessResourceRoot::global().mesh_runtime_scope();
        let local_application_resources =
            ProcessResourceRoot::global().issue_local_application_scope()?;
        let (events_tx, _) = broadcast::channel(event_capacity);
        let inner = Arc::new(MeshInner {
            identity,
            transport,
            resource_scope,
            local_application_resources,
            events_tx,
        });
        info!(
            device_id = %inner.identity.display_id(),
            "mesh opened"
        );
        Ok(MeshHandle {
            mesh: Mesh { inner },
        })
    }
}

/// Clonable handle to the mesh. Created by one of the explicitly named
/// [`Mesh`] constructors.
#[derive(Clone)]
pub struct MeshHandle {
    mesh: Mesh,
}

impl Clone for Mesh {
    fn clone(&self) -> Self {
        Self {
            inner: self.inner.clone(),
        }
    }
}

impl MeshHandle {
    /// Device identity loaded on first construction.
    pub fn identity(&self) -> &Arc<Identity> {
        &self.mesh.inner.identity
    }

    /// Convenience: bare-pubkey device id.
    pub fn device_id(&self) -> String {
        self.mesh.inner.identity.public_id().to_string()
    }

    /// Current connector resource-owner state. `None` means connector
    /// allocation is disabled for this process instance.
    pub fn connector_resource_report(&self) -> Option<ConnectorResourceOwnerReport> {
        self.mesh.inner.transport.connector_resource_report()
    }

    /// Current connector accounting for this exact live Mesh runtime.
    pub fn mesh_connector_resource_report(&self) -> Option<MeshConnectorResourceReport> {
        self.mesh.inner.transport.mesh_connector_resource_report()
    }

    /// Subscribe to mesh-wide events (every joined network's
    /// PeerEvent / PhaseEvent / Diag stream is fanned into this
    /// single broadcaster).
    pub fn events(&self) -> broadcast::Receiver<MeshEvent> {
        self.mesh.inner.events_tx.subscribe()
    }

    /// Read observations aggregated for this live Mesh runtime.
    pub fn resource_report(&self) -> ResourceReport {
        self.mesh.inner.resource_scope.report()
    }

    /// Issue one child of this Mesh runtime's exact local-application owner.
    /// Daemon IPC and joined-network application state share the selected
    /// process provider without borrowing connector authority.
    pub fn local_application_resource_scope(&self) -> Result<LocalApplicationResourceScope> {
        self.mesh
            .inner
            .local_application_resources
            .child()
            .map_err(Error::from)
    }

    /// Join a network. Returns a [`JoinedNetwork`] handle for
    /// channels / RPC / roster. The driver task keeps running
    /// until [`JoinedNetwork::leave`] is called (or the
    /// `JoinedNetwork` is dropped).
    pub async fn join(&self, mut config: NetworkConfig) -> Result<JoinedNetwork> {
        self.require_connector_capable()?;
        // Normalize the network id so signaling derivation is
        // case-insensitive on the user input.
        config.network_id = crate::identity::normalize_network_id(&config.network_id)?;

        let (state, driver) = spawn_network_in_mesh_scope(
            config.clone(),
            self.mesh.inner.identity.clone(),
            self.mesh.inner.transport.clone(),
            &self.mesh.inner.resource_scope,
            &self.mesh.inner.local_application_resources,
        )
        .await?;
        self.finish_joined_network(config, state, driver).await
    }

    /// Create and join a new Closed network through the Mesh-owned authority.
    ///
    /// The creation record is signed and persisted before the engine becomes
    /// observable. `creation_id` is caller-owned semantic input; it does not
    /// select a resource provider or bypass the Mesh's existing scopes.
    pub async fn create_network(
        &self,
        mut config: NetworkConfig,
        creation_id: [u8; 32],
    ) -> Result<JoinedNetwork> {
        self.require_connector_capable()?;
        config.network_id = crate::identity::normalize_network_id(&config.network_id)?;
        let (state, driver) = create_network_in_mesh_scope(
            config.clone(),
            self.mesh.inner.identity.clone(),
            self.mesh.inner.transport.clone(),
            &self.mesh.inner.resource_scope,
            &self.mesh.inner.local_application_resources,
            creation_id,
        )
        .await?;
        self.finish_joined_network(config, state, driver).await
    }

    /// Import and join an existing Closed network through the Mesh-owned
    /// authority. The expected context fences the import; the supplied record
    /// remains the only authority-bearing bootstrap input.
    pub async fn import_network(
        &self,
        mut config: NetworkConfig,
        expected_context_id: crate::semantic::MeshContextId,
        record: crate::semantic::BootstrapRecord,
    ) -> Result<JoinedNetwork> {
        self.require_connector_capable()?;
        config.network_id = crate::identity::normalize_network_id(&config.network_id)?;
        let (state, driver) = import_network_in_mesh_scope(
            config.clone(),
            self.mesh.inner.identity.clone(),
            self.mesh.inner.transport.clone(),
            &self.mesh.inner.resource_scope,
            &self.mesh.inner.local_application_resources,
            expected_context_id,
            record,
        )
        .await?;
        self.finish_joined_network(config, state, driver).await
    }

    fn require_connector_capable(&self) -> Result<()> {
        if self
            .mesh
            .inner
            .transport
            .connector_resource_report()
            .is_none()
        {
            return Err(Error::ConnectorPolicyRequired);
        }
        Ok(())
    }

    async fn finish_joined_network(
        &self,
        config: NetworkConfig,
        state: Arc<NetworkState>,
        driver: tokio::task::JoinHandle<()>,
    ) -> Result<JoinedNetwork> {
        let rpc = match Rpc::attach(&state) {
            Ok(rpc) => rpc,
            Err(error) => {
                state.request_shutdown();
                return match driver.await {
                    Ok(()) => Err(error.into()),
                    Err(join_error) => Err(Error::Other(format!(
                        "{error}; network driver cleanup failed: {join_error}"
                    ))),
                };
            }
        };

        // Fan-out per-network events into the mesh-wide broadcaster.
        let mesh_events_tx = self.mesh.inner.events_tx.clone();
        let mut net_events_rx = state.events_tx.subscribe();
        let fanout = tokio::spawn(async move {
            loop {
                match net_events_rx.recv().await {
                    Ok(ev) => {
                        let _ = mesh_events_tx.send(ev);
                    }
                    Err(broadcast::error::RecvError::Closed) => break,
                    Err(broadcast::error::RecvError::Lagged(_)) => continue,
                }
            }
        });

        Ok(JoinedNetwork {
            state,
            rpc: Arc::new(rpc),
            config_id: config.id,
            label: config.label,
            lifecycle: Arc::new(JoinedNetworkLifecycle {
                driver: tokio::sync::Mutex::new(Some(driver)),
                shutdown_result: tokio::sync::Mutex::new(None),
                fanout: AsyncMutex::new(Some(fanout)),
            }),
        })
    }
}

/// The owner of one real link installed by
/// [`JoinedNetwork::install_promoted_peer_over_real_link`].
///
/// Opaque on purpose. It answers the peer's exact device id and releases the
/// link; it exposes no network state, no peer object, and no channel authority,
/// so a control outside this crate cannot reach past the seam and promote,
/// retire, or send on its own.
#[cfg(feature = "transport-lab")]
pub struct TransportLabPromotedPeer {
    linked: crate::engine::LinkedPromotedSession,
}

#[cfg(feature = "transport-lab")]
impl TransportLabPromotedPeer {
    /// The device id the two networks know each other's session by — the far
    /// network's own identity, read back from the installed peer rather than
    /// from a copy the caller passed in.
    ///
    /// This is the id to address an RPC call at: a call filed against it is
    /// filed against the session on this exact link, and it arrives at a handler
    /// the far network's own [`JoinedNetwork::rpc`] served.
    pub fn peer_device_id(&self) -> &str {
        self.linked.peer_device_id()
    }

    /// Close both connectors of the link, wait for the far side's pump to
    /// finish, and hand back what each close reported.
    ///
    /// Call this after the control's last assertion. Neither installed peer is
    /// retired here: retiring them belongs to each network's own shutdown, which
    /// is the behaviour a control asserting on withdrawal is measuring.
    pub async fn retire(self) -> Vec<Result<()>> {
        self.linked.close_outcomes().await
    }
}

/// Opt-in real-link owner that explicitly retires its original two channels.
/// This is a lab cleanup/control operation, not an engine withdrawal event
/// oracle. Other channels and replacement installations are not selected.
#[cfg(feature = "transport-lab")]
pub struct TransportLabRetirableSession {
    linked: crate::engine::LinkedRetirableSession,
}

#[cfg(feature = "transport-lab")]
impl TransportLabRetirableSession {
    pub fn peer_device_id(&self) -> &str {
        self.linked.peer_device_id()
    }

    /// Retire both captured channels before awaiting native close, then join
    /// both event pumps and already-retired close owners. Every returned result
    /// must be inspected. Await to completion; dropping this future is not a
    /// successful cleanup. This does not change `TransportLabPromotedPeer::retire`.
    pub async fn retire_sessions(self) -> Vec<Result<()>> {
        self.linked.retire_sessions().await
    }
}

/// Current retained introduction phase; Terminal is not last-success evidence.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransportLabIntroductionPhase {
    Requested,
    Accepted,
    Offered,
    Answered,
    Terminal,
}

/// Scalar observation, with no ticket, ownership, signature or challenge bytes.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLabIntroductionRecord {
    pub introduction_id: [u8; 16],
    pub phase: TransportLabIntroductionPhase,
    pub sequences: [Option<u64>; 2],
    pub request_sent: bool,
    pub challenge_present: bool,
    pub signal_pending: [bool; 2],
    pub forward_pending: [bool; 2],
    /// A weak upgrade succeeded, NOT current registry or authentication proof.
    pub native_upgraded: bool,
    pub native_worker_present: bool,
    pub expired: bool,
}

/// Dense introduction-ID-ordered prefix for one ordered source/destination pair.
/// Missing rows are absence, not success; truncation means a seventeenth match.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TransportLabIntroductionSnapshot {
    pub records: [Option<TransportLabIntroductionRecord>; 16],
    pub truncated: bool,
}

/// One joined network's user-facing handle.
pub struct JoinedNetwork {
    state: Arc<NetworkState>,
    rpc: Arc<Rpc>,
    config_id: String,
    label: String,
    lifecycle: Arc<JoinedNetworkLifecycle>,
}

fn peer_registry_key(device_id: &str) -> &str {
    crate::signing::pubkey_part(device_id)
}

/// Aggregate timing for one bounded phase of durable semantic admission.
///
/// Counts and nanoseconds are process-local instrumentation for the
/// `transport-lab` scale controls. They intentionally contain no per-fact
/// samples or retained operation data.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SemanticAdmissionPhaseTiming {
    pub count: u64,
    pub total_nanos: u64,
    pub max_nanos: u64,
}

/// Aggregate phase timings emitted by the semantic-ledger scale control.
#[cfg(feature = "transport-lab")]
#[derive(Debug, Clone, Copy, Default, Serialize)]
pub struct SemanticAdmissionProfile {
    /// Time waiting for the bounded durable-admission permit; this excludes
    /// blocking graph/store work measured by `async_envelope_inclusive`.
    pub async_lane_wait_exclusive: SemanticAdmissionPhaseTiming,
    /// Inclusive async request envelope: permit wait, blocking graph/store
    /// work, and completion.
    pub async_envelope_inclusive: SemanticAdmissionPhaseTiming,
    pub publication_graph_replay_cold_lookup: SemanticAdmissionPhaseTiming,
    pub causal_journal_apply: SemanticAdmissionPhaseTiming,
    pub store_worker_handoff: SemanticAdmissionPhaseTiming,
    pub store_plan: SemanticAdmissionPhaseTiming,
    pub capacity_preflight: SemanticAdmissionPhaseTiming,
    pub begin_immediate: SemanticAdmissionPhaseTiming,
    pub sql_apply: SemanticAdmissionPhaseTiming,
    pub commit_wal_terminal: SemanticAdmissionPhaseTiming,
    pub author_witness_sign: SemanticAdmissionPhaseTiming,
    pub projection_roster_publish: SemanticAdmissionPhaseTiming,
    pub post_commit_broadcast: SemanticAdmissionPhaseTiming,
}

/// A move-only opaque endpoint channel for a Closed-member relay route.
///
/// The relay and session identifiers are descriptive metadata only. Endpoint
/// key material, authenticated peer ownership, and the bounded relay route
/// remain inside the engine; callers can only exchange plaintext through this
/// handle and close the exact endpoint session that opened it.
pub struct ClosedRelayChannel {
    session: crate::engine::closed_relay::EndpointSession,
    peer: String,
    relay: String,
    session_id: [u8; 16],
}

impl ClosedRelayChannel {
    /// The remote endpoint's canonical device id.
    pub fn peer_device_id(&self) -> &str {
        &self.peer
    }

    /// The canonical device id of the member forwarding this route.
    pub fn relay_device_id(&self) -> &str {
        &self.relay
    }

    /// The opaque session coordinate assigned to this exact endpoint pair.
    pub fn session_id(&self) -> [u8; 16] {
        self.session_id
    }

    /// The exact allocation epoch captured by this endpoint session.
    ///
    /// This is an observation coordinate for replacement-generation controls,
    /// not authority or key material.  A stale endpoint may still retain its
    /// original number, which lets a caller prove that a later allocation did
    /// not accept work from the earlier generation.
    pub fn allocation_epoch(&self) -> u64 {
        self.session.metadata().allocation_epoch
    }

    /// Encrypt and send one plaintext through the exact endpoint session.
    pub async fn send(&self, plaintext: &[u8]) -> Result<()> {
        self.session
            .send(plaintext)
            .await
            .map_err(|error| Error::ClosedRelay(ClosedRelayError::from_refusal(&error)))
    }

    /// Receive and decrypt one plaintext from the exact endpoint session.
    pub async fn recv(&self) -> Result<Vec<u8>> {
        self.session
            .recv()
            .await
            .map_err(|error| Error::ClosedRelay(ClosedRelayError::from_refusal(&error)))
    }

    /// Close this exact endpoint session and release its bounded custody.
    pub async fn close(self) -> Result<()> {
        self.session
            .close()
            .await
            .map_err(|error| Error::ClosedRelay(ClosedRelayError::from_refusal(&error)))
    }
}

impl JoinedNetwork {
    /// Reset process-local aggregate admission phase counters for a scale
    /// measurement. This is deliberately hidden from the stable application
    /// API and exists only with the transport-lab feature enabled.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn reset_semantic_admission_profile_for_lab(&self) {
        crate::semantic::store::reset_admission_phase_profile();
    }

    /// Snapshot process-local aggregate admission phase counters for a scale
    /// measurement. The returned value is a fixed-size, serializable report.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn semantic_admission_profile_for_lab(&self) -> SemanticAdmissionProfile {
        let (counts, nanos, max_nanos) = crate::semantic::store::admission_phase_profile_snapshot();
        let phase = |index: usize| SemanticAdmissionPhaseTiming {
            count: counts[index],
            total_nanos: nanos[index],
            max_nanos: max_nanos[index],
        };
        SemanticAdmissionProfile {
            async_lane_wait_exclusive: phase(1),
            async_envelope_inclusive: phase(0),
            publication_graph_replay_cold_lookup: phase(2),
            causal_journal_apply: phase(3),
            store_worker_handoff: phase(4),
            store_plan: phase(5),
            capacity_preflight: phase(6),
            begin_immediate: phase(7),
            sql_apply: phase(8),
            commit_wal_terminal: phase(9),
            author_witness_sign: phase(10),
            projection_roster_publish: phase(11),
            post_commit_broadcast: phase(12),
        }
    }

    /// Prepare a validated large-history fixture for transport-lab scale
    /// measurements, then leave subsequent admissions on the public path.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub async fn seed_semantic_scale_history_for_lab(
        &self,
        target: crate::semantic::DeviceId,
        count: usize,
    ) -> Result<()> {
        self.state
            .seed_semantic_scale_history_for_lab(target, count)
            .await
    }

    /// Import one bounded semantic fact page through the durable reducer and
    /// return the resulting deterministic graph identity.
    ///
    /// The page is checked for its exact protocol byte/count bounds, canonical
    /// signatures, and verified bootstrap context before it enters the
    /// reducer. Semantic authorization, dependency quarantine, custody, and
    /// projection remain owned by the canonical `FactGraph`.
    pub async fn import_semantic_fact_page(
        &self,
        page: crate::semantic::SemanticFactPage,
    ) -> Result<crate::semantic::SemanticStateIdentity> {
        crate::engine::lifecycle::import_semantic_fact_page(&self.state, page).await
    }

    /// Export one provider-funded page of canonical signed facts in stable
    /// FactId order. The exclusive cursor and protocol-derived bounds make
    /// every retained response finite and resumable.
    pub fn export_semantic_fact_page(
        &self,
        request: crate::semantic::SemanticFactPageRequest,
    ) -> Result<crate::semantic::SemanticFactPage> {
        crate::engine::lifecycle::export_semantic_fact_page(&self.state, request)
    }

    /// Inspect the deterministic identity of this network's canonical graph,
    /// including unresolved custody and the projected authority commitment.
    pub fn semantic_state_identity(&self) -> Result<crate::semantic::SemanticStateIdentity> {
        crate::engine::lifecycle::semantic_state_identity(&self.state)
    }

    /// Render a bounded diagnostic view of the newest signed facts already
    /// retained in the live hot-history cache. The returned JSON shape is not
    /// a storage format and is never consumed by the engine.
    pub fn recent_semantic_facts(
        &self,
        request: crate::semantic::SemanticRecentFactsRequest,
    ) -> Result<crate::semantic::SemanticRecentFacts> {
        crate::engine::lifecycle::recent_semantic_facts(&self.state, request)
    }

    /// Transport-lab observation of the live in-memory semantic history.
    /// Retired states report zero after their durable owner has terminated.
    #[cfg(feature = "transport-lab")]
    pub fn semantic_fact_count_for_lab(&self) -> usize {
        self.state.semantic_fact_count()
    }

    /// Arm one owner-scoped fault at the next non-empty semantic commit.
    /// This is a transport-lab control over the real durable store boundary;
    /// it does not alter authority validation or provide an ambiguous retry.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn arm_semantic_commit_fault_for_lab(
        &self,
        fault: crate::engine::transport_lab::SemanticCommitFaultForLab,
    ) -> Result<()> {
        self.state.arm_semantic_commit_fault_for_lab(fault)
    }

    /// Checkpoint the exact durable semantic database owned by this network.
    /// This never reloads or replaces the already-authoritative live graph.
    pub fn compact_semantic_state(&self) -> Result<()> {
        self.state.compact_semantic_state()
    }

    /// Export the verified Closed bootstrap record that owns this network.
    /// Open and Silent networks deliberately refuse because they have no
    /// authority-bearing bootstrap record to export.
    pub fn export_bootstrap_record(&self) -> Result<crate::semantic::BootstrapRecord> {
        match self.state.verified_bootstrap().policy() {
            crate::semantic::VerifiedProjectPolicy::Closed(_) => {
                Ok(self.state.verified_bootstrap_record().clone())
            }
            crate::semantic::VerifiedProjectPolicy::Open => Err(Error::Other(
                "open network has no Closed bootstrap record".into(),
            )),
        }
    }

    pub fn network_id(&self) -> &str {
        &self.state.network_id
    }

    /// User-chosen config record id (distinguishes multiple
    /// saved entries for the same wire-level network).
    pub fn config_id(&self) -> &str {
        &self.config_id
    }

    /// Cosmetic display name. Empty when the user didn't pick one
    /// at create time — the GUI falls back to `network_id`.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Read observations for this live joined network instance.
    ///
    /// This runtime rollup is not bound to an immutable context identity.
    pub fn resource_report(&self) -> ResourceReport {
        self.state.resource_report()
    }

    /// Snapshot the per-network rollup.
    pub fn current_phase(&self) -> MeshPhase {
        *self.state.current_phase.read()
    }

    pub fn current_topology(&self) -> TopologyMode {
        self.state.topology.read().clone()
    }

    /// Subscribe to the connection diagnostics for this exact joined
    /// runtime. The engine state remains behind the handle boundary.
    pub fn subscribe_conn_trace(
        &self,
    ) -> broadcast::Receiver<crate::engine::conn_trace::ConnTrace> {
        self.state.subscribe_conn_trace()
    }

    /// Attach an in-process signaling broker to this joined runtime.
    ///
    /// This is an explicit supported carrier for applications that can place
    /// both endpoints in one process. It traverses the same bounded ingress,
    /// authentication, and promotion path as the configured carriers; the
    /// broker is only the transport between those production boundaries.
    #[cfg(feature = "transport-lab")]
    pub fn attach_local(&self, broker: &myownmesh_signaling::local::LocalBroker) {
        crate::engine::attach_local(&self.state, broker);
    }

    /// Attach the signaling drivers selected by this network's configuration.
    ///
    /// Driver ownership stays inside the joined-network handle: callers do
    /// not need to borrow or retain the engine state in order to start the
    /// configured signaling path. `Ok(None)` means another in-process owner
    /// already took the outbound receiver; it is not an attach failure.
    pub fn attach_signaling(&self) -> Result<Option<crate::engine::SignalingDrivers>> {
        crate::engine::attach_signaling(&self.state)
    }

    /// Return the restart decision and every construction-time config
    /// dimension used by the daemon's lifecycle log without exposing the
    /// engine state.
    #[doc(hidden)]
    pub fn reconcile_status(&self, next: &NetworkConfig) -> ReconcileStatus {
        let current = self.state.config.read();
        ReconcileStatus {
            needs_restart: crate::engine::reconcile::requires_restart(&current, next),
            network_id_changed: current.network_id != next.network_id,
            signaling_changed: current.signaling != next.signaling,
            closed_relay_changed: current.closed_relay != next.closed_relay,
            semantic_policy_changed: current.semantic_policy != next.semantic_policy,
            scheduler_changed: current.scheduler != next.scheduler,
            hub_policy_changed: current.hub != next.hub,
            tree_policy_changed: current.tree != next.tree,
            local_observations_changed: current.local_observations != next.local_observations,
            event_capacity_changed: current.event_capacity != next.event_capacity,
            connection_trace_capacity_changed: current.connection_trace_capacity
                != next.connection_trace_capacity,
        }
    }

    /// Snapshot the exact live configuration owned by this handle.
    ///
    /// The daemon uses this only to restore the predecessor when a
    /// transport-config replacement is refused after teardown has begun.
    #[doc(hidden)]
    pub fn config_snapshot(&self) -> NetworkConfig {
        self.state.config.read().clone()
    }

    /// Apply the config fields that are safe to change while this exact
    /// joined runtime remains current.
    #[doc(hidden)]
    pub fn apply_hot(&self, next: NetworkConfig) -> Result<()> {
        crate::engine::reconcile::apply_hot(&self.state, next)
    }

    /// Lend the allocation-free fields of one daemon network summary as one
    /// ordered observation.
    ///
    /// Traffic is sampled first because its reliable-pending term enters the
    /// peer/session registries. The phase guard is then taken, copied, and
    /// released before topology is borrowed for the callback. Keeping topology
    /// last avoids a topology-to-peer-registry nesting that no writer needs.
    /// The callback must copy or measure only: it must not await, acquire a
    /// provider resource, emit an event, or re-enter the daemon registry.
    ///
    /// This is hidden rather than crate-private because the daemon is a
    /// separate crate and needs the borrow to price a prepared reply without
    /// first cloning its strings or topology.
    #[doc(hidden)]
    pub fn with_network_summary_view<R>(
        &self,
        effect: impl FnOnce(
            &str,
            &str,
            &str,
            MeshPhase,
            &TopologyMode,
            crate::engine::traffic::TrafficSnapshot,
        ) -> R,
    ) -> R {
        let traffic = self.state.traffic_snapshot();
        let phase = *self.state.current_phase.read();
        let topology = self.state.topology.read();
        effect(
            &self.config_id,
            &self.state.network_id,
            &self.label,
            phase,
            &topology,
            traffic,
        )
    }

    /// Reconfigure the topology selector at runtime. Triggers
    /// a synchronous re-evaluation of preferred peers and emits
    /// any necessary shelve / unshelve frames.
    pub async fn set_topology(&self, mode: TopologyMode) -> Result<()> {
        {
            let config = self.state.config.read();
            if crate::engine::reconcile::topology_requires_restart(&config, &mode) {
                return Err(crate::error::Error::Config(
                    "changing topology with funded Hub or tree control requires an exact runtime replacement"
                        .into(),
                ));
            }
        }
        self.state
            .cmd_tx
            .send(NetworkCmd::SetTopology(mode))
            .map_err(|error| error.into_admission_error())?;
        Ok(())
    }

    /// Type-safe publish/subscribe channel. The same `name` on
    /// two peers binds their `Channel<T>` senders to receivers.
    pub fn channel<T>(&self, name: &str) -> Channel<T>
    where
        T: serde::Serialize + serde::de::DeserializeOwned + Send + Sync + 'static,
    {
        Channel::new(name.to_string(), self.state.clone())
    }

    /// RPC dispatcher for this network. Cheap to clone; multiple
    /// holders can call / serve independently.
    pub fn rpc(&self) -> Arc<Rpc> {
        self.rpc.clone()
    }

    /// Snapshot every peer the engine is currently tracking.
    pub fn peers(&self) -> Vec<PeerInfo> {
        self.state.peer_snapshot()
    }
    /// Single-peer detail.
    pub fn peer(&self, device_id: &str) -> Option<PeerInfo> {
        self.state.peer_info(device_id)
    }

    /// Return a fixed, read-only observation of this node's local HubTree
    /// relation table.  The parent is a raw routing key, not an authority or
    /// session witness; traffic must still pass the exact current-owner fence.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn parenting_snapshot_for_lab(&self) -> Option<ParentingSnapshotForLab> {
        let (primary_parent, accepted_children, pending, generation) =
            self.state.parenting_snapshot_for_lab()?;
        Some(ParentingSnapshotForLab {
            primary_parent,
            accepted_children,
            pending,
            generation,
        })
    }

    /// Advance only this network's transport-lab parenting clock. This is a
    /// deterministic expiry control and does not affect any other clock.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn advance_parenting_clock_for_lab(&self, delta_ms: u64) -> Result<()> {
        self.state.advance_parenting_clock_for_lab(delta_ms)
    }

    /// Advance the parenting clock and return the effective relation snapshot
    /// before a scheduler tick can begin paced reattachment.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn advance_parenting_clock_and_snapshot_for_lab(
        &self,
        delta_ms: u64,
    ) -> Result<Option<ParentingSnapshotForLab>> {
        let (primary_parent, accepted_children, pending, generation) = self
            .state
            .advance_parenting_clock_and_snapshot_for_lab(delta_ms)?
            .expect("parenting clock snapshot exists when the clock is available");
        Ok(Some(ParentingSnapshotForLab {
            primary_parent,
            accepted_children,
            pending,
            generation,
        }))
    }

    /// Return bounded aggregate discovery progress without exposing cursor
    /// identities, peer payloads, or an event history.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn hub_discovery_diagnostics_for_lab(&self) -> Option<HubDiscoveryDiagnosticsForLab> {
        let snapshot = self.state.hub_discovery_diagnostics_for_lab()?;
        Some(HubDiscoveryDiagnosticsForLab {
            configured_hubs: snapshot.configured_hubs,
            pending_requests: snapshot.pending_requests,
            requests_started: snapshot.requests_started,
            requests_bound: snapshot.requests_bound,
            responses_accepted: snapshot.responses_accepted,
            responses_rejected: snapshot.responses_rejected,
            pages_accepted: snapshot.pages_accepted,
            continuation_pages_accepted: snapshot.continuation_pages_accepted,
            cursor_advances: snapshot.cursor_advances,
            cursors_with_after: snapshot.cursors_with_after,
            exploration_cursor: snapshot.exploration_cursor,
            last_page_len: snapshot.last_page_len,
            last_page_has_more: snapshot.last_page_has_more,
            last_request_after: snapshot.last_request_after,
            last_accepted_request_after: snapshot.last_accepted_request_after,
            last_accepted_first: snapshot.last_accepted_first,
            last_accepted_last: snapshot.last_accepted_last,
            exploration_sequence: snapshot.exploration_sequence,
            next_exploration_ms: snapshot.next_exploration_ms,
        })
    }

    /// Capture the exact current transport owner for one peer for a bounded
    /// transport-lab observation. The device id is used only for this initial
    /// lookup; the returned witness carries the installation and worker that
    /// the registry proved current.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub fn capture_transport_channel_for_lab(
        &self,
        device_id: &str,
    ) -> Option<crate::engine::transport_lab::TransportChannelWitness> {
        let device_id = peer_registry_key(device_id);
        let owner = crate::engine::transport_lab::proof_owner_for_device(&self.state, device_id)?;
        crate::engine::transport_lab::capture_transport_channel(&self.state, &owner)
    }

    /// Snapshot one previously captured exact transport owner. Replacement or
    /// retirement returns `None`; no device-id lookup occurs after capture.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub async fn transport_channel_snapshot_for_lab(
        &self,
        witness: &crate::engine::transport_lab::TransportChannelWitness,
    ) -> Option<crate::engine::transport_lab::ChannelSnapshot> {
        crate::engine::transport_lab::transport_channel_snapshot(&self.state, witness).await
    }

    /// Request exact transport-channel terminal notification for a previously
    /// captured owner.  Capture the witness before closing the link; this
    /// method keeps the witness binding and delegates to the production
    /// terminal fence.  Replacement, stale, and already-retired witnesses are
    /// harmless.  Another live channel may preserve the logical session.  The
    /// request does not promise synchronous registry removal; use the exact
    /// snapshot helper to observe the terminal state.
    #[cfg(feature = "transport-lab")]
    #[doc(hidden)]
    pub async fn retire_transport_channel_for_lab(
        &self,
        witness: &crate::engine::transport_lab::TransportChannelWitness,
    ) {
        crate::engine::transport_lab::retire_transport_channel_for_lab(&self.state, witness).await;
    }

    /// Open an opaque endpoint channel from this member to `target` through
    /// the exact authenticated member `relay`. The session coordinate is
    /// generated here and never accepted from a caller, while the engine
    /// retains endpoint keys and current-owner checks behind this facade.
    pub async fn open_closed_relay(&self, relay: &str, target: &str) -> Result<ClosedRelayChannel> {
        let relay = crate::semantic::DeviceId::from_canonical_str(relay)
            .map_err(|_| Error::ClosedRelay(ClosedRelayError::InvalidPacket))?;
        let target = crate::semantic::DeviceId::from_canonical_str(target)
            .map_err(|_| Error::ClosedRelay(ClosedRelayError::InvalidPacket))?;
        let mut session_id = [0u8; 16];
        rand_core::OsRng.fill_bytes(&mut session_id);
        if session_id.iter().all(|byte| *byte == 0) {
            return Err(Error::ClosedRelay(ClosedRelayError::InvalidPacket));
        }
        let session = crate::engine::closed_relay::open_endpoint(
            &self.state,
            relay.clone(),
            target.clone(),
            session_id,
        )
        .await
        .map_err(|error| Error::ClosedRelay(ClosedRelayError::from_refusal(&error)))?;
        Ok(ClosedRelayChannel {
            session,
            peer: target.base32(),
            relay: relay.base32(),
            session_id,
        })
    }

    /// Accept the next authenticated endpoint Offer delivered to this
    /// network. The engine selects the exact bounded FIFO entry and supplies
    /// its observed requester, relay, and session metadata; callers cannot
    /// inject or reconstruct a route identifier.
    pub async fn accept_closed_relay(&self) -> Result<ClosedRelayChannel> {
        let session = self
            .state
            .await_next_closed_relay_target_accept()
            .await
            .map_err(|error| Error::ClosedRelay(ClosedRelayError::from_refusal(&error)))?;
        let metadata = session.metadata();
        Ok(ClosedRelayChannel {
            session,
            peer: metadata.requester.base32(),
            relay: metadata.relay.base32(),
            session_id: metadata.session_id,
        })
    }

    /// Propose a canonical member/controller/owner grant.
    pub async fn propose_role_grant(
        &self,
        target: &str,
        role: crate::semantic::Role,
        mfa_code: Option<String>,
    ) -> Result<crate::semantic::FactId> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::ProposeRoleGrant {
                target: target.to_string(),
                role,
                mfa_code,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        receiver
            .await
            .map_err(|_| Error::Network("engine dropped governance proposal reply".into()))?
    }

    /// Propose demoting a device to the canonical member role.
    pub async fn propose_role_revoke(
        &self,
        target: &str,
        mfa_code: Option<String>,
    ) -> Result<crate::semantic::FactId> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::ProposeRoleRevoke {
                target: target.to_string(),
                mfa_code,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        receiver
            .await
            .map_err(|_| Error::Network("engine dropped governance proposal reply".into()))?
    }

    /// Propose canonical eviction of a device.
    pub async fn propose_evict(
        &self,
        target: &str,
        mfa_code: Option<String>,
    ) -> Result<crate::semantic::FactId> {
        let (reply, receiver) = tokio::sync::oneshot::channel();
        self.state
            .cmd_tx
            .send(NetworkCmd::ProposeEvict {
                target: target.to_string(),
                mfa_code,
                reply,
            })
            .map_err(|error| error.into_admission_error())?;
        receiver
            .await
            .map_err(|_| Error::Network("engine dropped governance proposal reply".into()))?
    }

    /// How many RPC operations are filed against `device_id`'s current
    /// session, or `None` if that peer has no live session at all.
    ///
    /// **The filed/withdrawn barrier, for a control that has to park a real
    /// call.** A control proving that shutdown withdraws an outstanding
    /// operation has to know the operation is genuinely *filed* first —
    /// otherwise it races its own setup and passes for the wrong reason. This
    /// is that observation point: wait for `Some(1)`, then act, then assert
    /// `Some(0)`.
    ///
    /// The two negative answers are different facts and both matter. A retired
    /// session answers `None`; a live session with nothing outstanding answers
    /// `Some(0)`. A control that conflated them could not tell "the peer went
    /// away" from "the peer settled everything", which is exactly the
    /// distinction a shutdown control exists to make.
    ///
    /// A count and nothing else: no identity, no effect, and no way to reach an
    /// entry, so it cannot become a settling path by accident. It delegates to
    /// the existing per-session count rather than adding a second witness that
    /// could disagree with the first.
    ///
    /// **Gated on `transport-lab`, not `test`.** `cfg(test)` is set only while
    /// compiling *this* crate's own tests, so a `cfg(test)` item here would be
    /// invisible to another crate's tests — which is precisely where this is
    /// needed. The feature is the repo's existing answer for a seam that has to
    /// cross a crate boundary without existing in a production build.
    #[cfg(any(test, feature = "transport-lab"))]
    pub fn pending_call_count_for_test(&self, device_id: &str) -> Option<usize> {
        let owner = self.state.peers.owner(device_id)?;
        self.state.peers.with_live_session_state(
            &owner,
            self.state.session_broker.as_ref(),
            &self.state.mesh_context_id().to_string(),
            |_session, app| app.rpc_mut().pending_len(),
        )
    }

    /// Promote a session between this network and `far` over a real linked
    /// connector pair, and hand back the owner of that link.
    ///
    /// **The prerequisite a cross-crate control cannot build for itself.**
    /// [`Self::pending_call_count_for_test`] observes a session; it cannot
    /// create one. Creating one means a genuine offer/answer/ICE/DTLS/SCTP
    /// exchange and the production `DataChannelOpen` consumption of the near
    /// connector's own open callback, which is exactly what this crate's
    /// real-link fixture already does. Re-deriving that outside this crate
    /// would be a second connector setup that could drift from the first.
    ///
    /// **Both directions, not one.** `far` installs this network as a peer too,
    /// and every raw event from its end of the link is driven into its engine
    /// through the same seam a transport driver feeds. That is what makes a call
    /// filed here *reach* a handler `far` served on its own
    /// [`JoinedNetwork::rpc`] — a fixture that only promoted the near side would
    /// let a control observe a pending call that nothing on the other end could
    /// ever have received, which is a witness with no cause behind it.
    ///
    /// Both networks are ordinary [`JoinedNetwork`]s with their own real
    /// drivers, deliberately: the control that asserts shutdown withdraws an
    /// outstanding operation needs `self`'s own engine to be the thing that
    /// retires the session. Nothing here stands in for that lifecycle.
    ///
    /// No signaling is involved. The link is built connector-to-connector from
    /// the two networks' own transports, so neither network needs to reach a
    /// signaling server for the peer to exist.
    ///
    /// The returned owner holds both peers and the far side's pump. It must
    /// outlive the assertions, and so must `far`: dropping either stops that end
    /// of the link, and the link the control is asserting on would stop being
    /// the link that was up. Release it with
    /// [`TransportLabPromotedPeer::retire`] after the control's last assertion —
    /// dropping it instead starts each connector's close without awaiting it or
    /// the pump.
    ///
    /// **Gated on `transport-lab`, not `test`,** for the reason given on
    /// [`Self::pending_call_count_for_test`].
    #[cfg(feature = "transport-lab")]
    pub async fn install_promoted_peer_over_real_link(
        &self,
        far: &JoinedNetwork,
    ) -> TransportLabPromotedPeer {
        TransportLabPromotedPeer {
            linked: crate::engine::install_promoted_session_over_real_link(&self.state, &far.state)
                .await,
        }
    }

    /// The explicit-retirement alternative to the historical real-link fixture.
    /// Captures original installation/session/channel witnesses at construction;
    /// retiring it never resolves a peer label into a replacement. Use this for
    /// controls that intentionally invalidate live flows, not event withdrawal.
    #[cfg(feature = "transport-lab")]
    pub async fn install_retirable_session_over_real_link(
        &self,
        far: &JoinedNetwork,
    ) -> TransportLabRetirableSession {
        TransportLabRetirableSession {
            linked: crate::engine::install_retirable_session_over_real_link(
                &self.state,
                &far.state,
            )
            .await,
        }
    }

    /// One immediate post-demand observation of existing records, without
    /// mutation, polling, ID reconstruction or ownership escape. `None` means
    /// introduction is disabled; an empty `Some` has no matching retained row.
    #[cfg(feature = "transport-lab")]
    pub fn introduction_snapshot_for_lab(
        &self,
        source: [u8; 32],
        destination: [u8; 32],
    ) -> Option<TransportLabIntroductionSnapshot> {
        crate::engine::introduction_snapshot_for_lab(&self.state, source, destination)
    }

    /// List approved peers from the on-disk roster.
    pub async fn roster_list(&self) -> Result<Vec<AuthorizedPeer>> {
        Ok(self.state.canonical_roster_view())
    }

    /// Set the capability advertisement this node publishes. It crosses only as
    /// a `capabilities_update` frame, to peers with a live session — see
    /// [`crate::rpc::Rpc::advertise`] for when each peer is told.
    ///
    /// Answers whether the value was committed. Discarding this is discarding
    /// the fact that the node is still advertising its previous capabilities.
    pub fn advertise(
        &self,
        caps: CapabilityAdvert,
    ) -> std::result::Result<(), crate::rpc::RpcError> {
        self.rpc.advertise(caps)
    }

    /// Leave deliberately: depart every authenticated session, then drop the
    /// carrier hint on the way out.
    ///
    /// **The departure travels on the authenticated sessions, and only the
    /// carrier hint rides signaling.** Each live session is told over itself,
    /// awaited, and then retired locally; the room-wide `leave` that follows is
    /// reachability evidence with no teardown authority, because no carrier
    /// supplies a Device-authenticated goodbye and a receiver will not retire a
    /// healthy session on one.
    ///
    /// Call this on the *live* handle **before** the signaling driver is
    /// dropped (the registry drops it inside `remove`): once the driver is gone
    /// there is no socket left to publish the hint on, and no data channel left
    /// to depart over.
    ///
    /// Nothing is acknowledged, retried, or timed. What replaced the old fixed
    /// flush window is not a shorter wait but a real one: this returns when the
    /// sessions have actually been told, rather than after a duration chosen to
    /// be probably-long-enough for a publish it never watched.
    pub async fn announce_leave(&self) {
        crate::engine::depart_authenticated_sessions(&self.state).await;
        self.request_departure();
    }

    /// Emit the carrier departure hint alone, without departing any session.
    ///
    /// **Hint only.** This publishes a room-wide `leave` on signaling, which a
    /// receiver may use as reachability evidence — to update availability, to
    /// stop speculative work that never became a session, or to go look at a
    /// connector — and may not use to retire a session holding a promoted
    /// `SessionCapability`.
    /// On a network carrier the receiver reads it as sender-claimed, which
    /// retires nothing in any session state.
    ///
    /// **Private, because there is nothing here for a caller to want.** It was
    /// `pub` while the hint *was* the departure; now that
    /// [`Self::announce_leave`] departs each session over itself first, a caller
    /// reaching for this alone would be asking to publish an announcement with
    /// no authority behind it and no session left in a different state for it to
    /// describe. `announce_leave` is the deliberate exit and its only caller.
    /// `TRANSITION-PLAYBOOK.md` §7.3 admits no dead public surface, and a repo
    /// scan finds no other caller in or outside this crate.
    fn request_departure(&self) {
        self.state.announce_departure();
    }

    /// Reconnect in place — the non-destructive twin of a leave-then-rejoin.
    /// `peer == None` redials signaling and renegotiates ICE with every peer on
    /// this network; `peer == Some(id)` reconnects just that one peer (for a
    /// per-node refresh). Nothing is torn down and no `Leave` is announced, so
    /// peers keep their sessions and app-level state — the gentle recovery a
    /// "refresh / reconnect" control should drive instead of removing and
    /// re-adding the network. Fire-and-forget: the work runs on the engine
    /// driver so it's serialized with every other per-peer mutation.
    pub fn reconnect(&self, peer: Option<String>) {
        self.state.reconnect(peer);
    }

    /// Deliberately dial exactly one signaling-discovered peer by device id,
    /// opening the WebRTC session on demand. This is the manual-connect
    /// primitive a [`Silent`](crate::config::NetworkKind::Silent) network needs: on a
    /// Silent mesh the engine never dials just because a peer announced (a
    /// co-present peer surfaces as [`crate::PeerEvent::Sighted`] / in
    /// [`Self::peers`] with no session), so a connection is initiated only
    /// here or by answering an inbound offer. The local side always takes the
    /// offerer role, so a Silent peer — which never auto-dials — is reached by
    /// our offer and answers normally. Idempotent: a no-op if a live session
    /// already exists. Fire-and-forget past the queue hand-off — the dial runs
    /// on the engine driver, serialized with every other per-peer mutation.
    ///
    /// On a non-Silent network this still works (dials the peer if not already
    /// connected), but there it is rarely needed: those networks auto-dial on
    /// presence. `Ok(())` means the command was queued, not that the peer
    /// connected — observe [`crate::PeerEvent`]s for the outcome.
    pub async fn connect_peer(&self, device_id: &str) -> Result<()> {
        let device_id = peer_registry_key(device_id);
        self.state
            .request_connect_peer(device_id.to_string(), false, None)
            .map_err(|error| error.into_admission_error())?;
        Ok(())
    }

    /// Dial one peer and resolve when the link is genuinely ACTIVE (or
    /// fail with the terminal reason) — the observable twin of
    /// [`Self::connect_peer`], which only queues the dial. Bounded by
    /// `timeout`. `sticky` records a standing dial: the engine keeps a
    /// never-expiring reconnect intent for the peer and — the one
    /// exception to Silent's no-auto-dial rule — redials it whenever it
    /// announces, which is what lets a remote-support session survive
    /// the far end sleeping, moving networks, or rebooting without the
    /// application re-driving the dial.
    pub async fn connect_peer_wait(
        &self,
        device_id: &str,
        sticky: bool,
        timeout: std::time::Duration,
    ) -> Result<()> {
        let device_id = peer_registry_key(device_id);
        match tokio::time::timeout(timeout, self.state.connect_peer_wait(device_id, sticky)).await {
            Ok(result) => result,
            Err(_) => Err(Error::Network(format!(
                "connect to {device_id} still pending after {timeout:?} (the dial keeps going{})",
                if sticky { "; the pin stays armed" } else { "" }
            ))),
        }
    }

    /// Point-in-time traffic accounting for this network: frames and
    /// bytes by class (keepalive / control / gossip / app), signaling
    /// publish and receive counts split into presence vs pairwise
    /// negotiation, forwarding duty, and the acked-delivery backlog.
    /// Two snapshots around an experiment are the honest comparison of
    /// two topologies.
    pub fn traffic(&self) -> crate::engine::traffic::TrafficSnapshot {
        self.state.traffic_snapshot()
    }

    /// Remove a standing dial recorded by `connect_peer_wait(…, sticky
    /// = true)` (or a config `pinned_peers` entry) — the peer stops
    /// being redialed on announce and its never-expiring intent is
    /// dropped. Does not tear down a live session.
    pub fn unpin_peer(&self, device_id: &str) {
        self.state.remove_sticky(device_id);
    }

    /// Send an application frame with the acknowledged-delivery contract: the
    /// frame is retained by the peer's current session and this resolves when
    /// the peer's engine has delivered it to the application layer.
    ///
    /// Fail-closed at submission. It errs immediately when the peer has no live
    /// session and when the resource provider will not fund retaining the frame,
    /// which is what backpressure is. There is no queue-until-later: a frame is
    /// retained under a session or not at all.
    ///
    /// It also errs, rather than retransmitting, if that session ends before the
    /// peer acknowledges — a rebuild, a policy revocation, a peer replacement or
    /// shutdown. The caller learns the frame was not delivered and decides
    /// whether the payload still means anything, which it is in a position to
    /// know and this layer is not.
    pub async fn send_reliable(
        &self,
        peer: &str,
        channel: &str,
        payload: serde_json::Value,
    ) -> Result<()> {
        self.state
            .send_channel_reliable(peer, channel, payload)
            .await
    }

    /// Stop the network. Tears down all peer sessions, signals
    /// the driver to exit, and drops the entry. After leave, the
    /// `JoinedNetwork` is no longer usable.
    pub async fn leave(self) -> Result<()> {
        self.shutdown().await
    }

    /// Initiate and await shutdown without requiring unique ownership of the
    /// facade. Idempotent: every concurrent caller observes the same driver
    /// retirement before it returns.
    pub async fn shutdown(&self) -> Result<()> {
        self.state.request_shutdown();
        // Cancel and join the mesh-wide event fan-out before waiting for the
        // driver. A departure or terminal peer event can otherwise keep this
        // lifecycle task retaining the network state while the driver waits
        // for its final peer cleanup, which is a shutdown-only deadlock for a
        // silently connected peer.
        let mut driver = self.lifecycle.driver.lock().await;
        let fanout_failure = if let Some(fanout) = self.lifecycle.fanout.lock().await.take() {
            fanout.abort();
            match fanout.await {
                Ok(()) => None,
                Err(error) if error.is_cancelled() => None,
                Err(error) => Some(format!(
                    "network event fan-out task failed during shutdown: {error}"
                )),
            }
        } else {
            None
        };
        let driver_failure = if let Some(driver) = driver.take() {
            match driver.await {
                Ok(()) => None,
                Err(error) => Some(format!(
                    "network driver task failed during shutdown: {error}"
                )),
            }
        } else {
            self.lifecycle
                .shutdown_result
                .lock()
                .await
                .clone()
                .and_then(|result| result.err())
        };
        let outcome = match (driver_failure, fanout_failure) {
            (None, None) => Ok(()),
            (Some(error), None) | (None, Some(error)) => Err(Error::Other(error)),
            (Some(driver), Some(fanout)) => Err(Error::Other(format!("{driver}; {fanout}"))),
        };
        *self.lifecycle.shutdown_result.lock().await =
            Some(outcome.as_ref().map(|_| ()).map_err(ToString::to_string));
        outcome
    }

    /// Remove this joined network's canonical semantic snapshot after its
    /// engine shutdown has completed. The state-owned owner and exact slot
    /// remain behind this narrow daemon-control seam; callers cannot select a
    /// persistence root or local slot of their own.
    #[doc(hidden)]
    pub fn purge_durable_semantic_state(&self) -> Result<()> {
        self.state.purge_durable_semantic_state()
    }

    /// the API surface for embedders — the engine reaches across
    /// Open one WebRTC realtime flow to `peer` on this network.
    ///
    /// **Named for its provider on purpose.** It carries WebRTC's own
    /// vocabulary — RTP kind, MIME, clock rate, channels — which is meaningless
    /// without a negotiated RTP clock and therefore is not a MyOwnMesh fact. A
    /// caller reading this name knows which provider it has bound itself to;
    /// the basal operations beside it carry no provider name because they carry
    /// no provider vocabulary.
    ///
    /// `peer` is a Device **selector**, not authority: it names an installation
    /// to resolve, and every fact that authorizes the flow — the promoted
    /// session, the exact live connector, the local principal — is produced
    /// inside the engine at the moment of use and never travels out here.
    ///
    /// `label` is the application's own choice and the application is the sole
    /// allocator. It is scoped to one session and **grants nothing** — it is a
    /// wire coordinate, readable back off the returned handle for the
    /// application's own control messages, and there is no operation that will
    /// accept it in place of one. Core neither allocates a label nor enforces a
    /// capacity: the bounded namespace refuses a duplicate as
    /// [`RealtimeRefusal::LabelInUse`], and the application sizes its own pool
    /// from the profile capacity it supplied at startup.
    ///
    /// **Answers a [`RealtimeFlowHandle`](crate::realtime::RealtimeFlowHandle),
    /// which is the only thing that authorizes operating on this flow.** It
    /// names the exact session and the exact flow record, is move-only, and is
    /// not serializable. That replaces a `peer + label` pair whose every use
    /// re-resolved the Device selector — so a caller whose session had ended
    /// and been replaced had its units accepted by the replacement's flow of
    /// the same name, silently, since nothing on a realtime path is
    /// acknowledged per unit.
    ///
    /// The provider's configuration is validated **here**, before any session
    /// is resolved, so an unusable request is refused as
    /// [`RealtimeRefusal::ProviderConfigurationInvalid`] without costing a
    /// fence acquisition — and the engine below never sees provider vocabulary
    /// at all.
    ///
    /// Async because opening a flow brings its native half up with it: a
    /// transceiver for an inbound flow, a sender and its pump for an outbound
    /// one. Those await, and the fence they must be proved against is a
    /// synchronous lock, so the operation is split around them rather than
    /// holding anything across.
    ///
    /// Still one call and still all-or-nothing from the caller's side. A
    /// refusal has released both halves — the label through the fence, the
    /// native object through the connector — so a failed open leaves nothing
    /// behind to collide with the next one.
    pub async fn open_webrtc_realtime(
        &self,
        peer: &str,
        open: crate::transport::webrtc::WebRtcRealtimeFlowOpen,
    ) -> std::result::Result<crate::realtime::RealtimeFlowHandle, crate::realtime::RealtimeRefusal>
    {
        let spec = crate::transport::webrtc::RealtimeFlowSpec::try_from(open)?;
        self.state.open_realtime_negotiated(peer, spec).await
    }

    /// Open one provider-backed application flow carrying opaque bytes.
    ///
    /// The label, reliability mode and unit ceiling are application-owned
    /// coordinates.  The returned move-only handle is the only authority for
    /// later operations; `peer` is resolved once here and never re-resolved by
    /// a send or pipe after the session changes.
    pub async fn open_opaque_flow(
        &self,
        peer: &str,
        open: &crate::realtime::OpaqueFlowOpen,
    ) -> std::result::Result<crate::realtime::RealtimeFlowHandle, crate::realtime::RealtimeRefusal>
    {
        self.state.open_opaque_flow(peer, open).await
    }

    /// Send one opaque application body through the exact flow handle.
    ///
    /// Core does not inspect, decode or reinterpret the bytes.  The provider
    /// enforces the negotiated finite unit ceiling and exact session
    /// incarnation before queueing them.
    pub fn send_opaque_flow(
        &self,
        flow: &crate::realtime::RealtimeFlowHandle,
        bytes: bytes::Bytes,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.state.send_opaque(flow, bytes)
    }

    /// Change the negotiated ceiling of one exact outbound opaque flow.
    ///
    /// The handle is borrowed, never taken, cloned, or reinstalled.  Its
    /// session and flow identities remain the authority while the existing
    /// connection-command actor performs the funded change transaction.  The
    /// label, direction, and mode in `open` must describe that same flow; only
    /// its unit ceiling may change.  A refusal before control publication
    /// rolls the prepared record back.  After publication, the actor either
    /// commits the change or performs the exact-session retirement required by
    /// the existing ambiguity fence; callers must not retry an ambiguous
    /// result.
    pub async fn change_opaque_flow(
        &self,
        flow: &crate::realtime::RealtimeFlowHandle,
        open: &crate::realtime::OpaqueFlowOpen,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.state.change_opaque_flow(flow, open).await
    }

    /// Hand one unit to an outbound WebRTC flow. Synchronous: it queues and
    /// returns, and the connector drains to the native track on its own task.
    ///
    /// **Borrows the handle and resolves nothing.** The unit reaches the flow
    /// that handle names or it reaches nothing: a session that has been replaced
    /// since the open, or a label that has been closed and reopened, is refused
    /// as [`RealtimeRefusal::SessionNotCurrent`] rather than silently accepted
    /// by whatever holds the name now.
    pub fn send_webrtc_realtime(
        &self,
        flow: &crate::realtime::RealtimeFlowHandle,
        unit: crate::transport::webrtc::WebRtcRealtimeOutboundUnit,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.state.send_realtime(flow, unit.into())
    }

    /// Close one flow and release its label back to that session's namespace.
    /// Async, and the await is the point: it returns after the flow's native
    /// half has been asked to go, not merely after the label was released.
    ///
    /// A caller that pins a label and re-opens it is entitled to assume the
    /// previous occupant is gone when this returns. Acking before the
    /// retirement was attempted would make that assumption false in exactly the
    /// case it matters — an immediate re-open onto the same label — so the ack
    /// follows the attempt.
    ///
    /// Whole-connector retirement is not relied on anywhere in this path: the
    /// same connector may host a replacement session, so a flow's native half
    /// can outlive the flow while the connector stays healthy.
    ///
    /// **Consumes the handle**, because a close is the end of the thing the
    /// handle names. Taking it by value is what makes "closed twice" and "closed
    /// then sent on" unrepresentable rather than merely refused — the compiler
    /// rejects them — and it is why closing one flow cannot close the flow that
    /// immediately reuses its label: the identities travelled with the handle,
    /// and the reuse is a different record.
    pub async fn close_realtime(
        &self,
        flow: crate::realtime::RealtimeFlowHandle,
    ) -> std::result::Result<(), crate::realtime::RealtimeRefusal> {
        self.state.close_realtime_negotiated(flow).await
    }

    /// Whether that handle still names a usable flow.
    ///
    /// Borrows rather than consumes: asking is not using, and a caller that
    /// learns `false` still owns its handle and drops it, which costs nothing.
    ///
    /// Answers `false` for every not-usable reason, because the question is only
    /// ever "may I use this". A caller is not told whether its session was
    /// replaced or its label was reopened by something else — both mean it has
    /// no flow, and the difference is about a flow it has no standing to learn
    /// about.
    pub fn realtime_is_current(&self, flow: &crate::realtime::RealtimeFlowHandle) -> bool {
        self.state.realtime_is_current(flow)
    }

    /// Claim the inbound stream of `peer`'s current session.
    ///
    /// One consumer at a time. `None` if a handle is already outstanding, and
    /// `None` for a peer with no live session — the caller has proved nothing,
    /// so it learns only that it does not have the stream. Dropping the
    /// outstanding handle releases the claim and this answers `Some` again while
    /// the session is still current.
    ///
    /// Poll-free receiving for an application with many flows — one task awaits
    /// the whole session instead of one per flow, which is why the arrival
    /// carries the label it arrived on.
    pub fn realtime_inbound(&self, peer: &str) -> Option<crate::realtime::RealtimeInboundStream> {
        self.state.claim_realtime_inbound(peer)
    }

    /// The next unit to arrive on any inbound flow of that session.
    ///
    /// The one way to receive. There is deliberately no per-flow receive beside
    /// it: a second one would be a second place the same arrival could be
    /// waiting, and the two could then disagree about whether it was still
    /// there. One session, one inbound queue, one consumer — which is why the
    /// arrival carries the label it came in on.
    ///
    /// `None` is terminal: the session ended, and the caller should close. That
    /// is the only end-of-session signal there is — deliberately, because a
    /// retirement flag would be a second fact that could disagree with the
    /// first, and something would have to outlive the session to deliver it.
    pub async fn recv_webrtc_realtime_any(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> std::result::Result<
        Option<crate::transport::webrtc::WebRtcRealtimeInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        self.state.next_realtime_arrival(inbound).await
    }

    /// Receive the next opaque body from one exact inbound session stream.
    /// `None` means that session's stream ended; no peer selector is resolved
    /// after the stream is claimed.
    pub async fn recv_opaque_flow(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> std::result::Result<
        Option<crate::realtime::OpaqueInboundArrival>,
        crate::realtime::RealtimeRefusal,
    > {
        self.state.recv_opaque(inbound).await
    }

    /// Receive the next item from one exact session stream without filtering
    /// its RTP and opaque kinds. The tagged API is the only mixed-kind reader;
    /// typed readers refuse an opposite-kind head without consuming it.
    pub async fn recv_realtime_arrival(
        &self,
        inbound: &crate::realtime::RealtimeInboundStream,
    ) -> Option<crate::transport::webrtc::RealtimeInboundArrival> {
        self.state.recv_realtime_arrival(inbound).await
    }
}

/// Fixed transport-lab observation of the local HubTree relation table.
/// `primary_parent` contains the raw Ed25519 routing key; this type carries no
/// authority, owner, or session capability and is unavailable in production.
#[cfg(feature = "transport-lab")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ParentingSnapshotForLab {
    pub primary_parent: Option<[u8; 32]>,
    pub accepted_children: usize,
    pub pending: usize,
    pub generation: u64,
}

/// Fixed transport-lab observation of bounded HubController discovery
/// progress. Cursor identities and directory payloads remain private.
#[cfg(feature = "transport-lab")]
#[doc(hidden)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct HubDiscoveryDiagnosticsForLab {
    pub configured_hubs: u64,
    pub pending_requests: u64,
    pub requests_started: u64,
    pub requests_bound: u64,
    pub responses_accepted: u64,
    pub responses_rejected: u64,
    pub pages_accepted: u64,
    pub continuation_pages_accepted: u64,
    pub cursor_advances: u64,
    pub cursors_with_after: u64,
    pub exploration_cursor: u64,
    pub last_page_len: u16,
    pub last_page_has_more: bool,
    pub last_request_after: Option<[u8; 32]>,
    pub last_accepted_request_after: Option<[u8; 32]>,
    pub last_accepted_first: Option<[u8; 32]>,
    pub last_accepted_last: Option<[u8; 32]>,
    pub exploration_sequence: u64,
    pub next_exploration_ms: u64,
}

/// User-facing snapshot of a peer's current view in the engine.
/// All fields are immutable copies; re-fetch for fresh data.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub device_id: String,
    pub status: PeerStatus,
    pub tier: ConnectionTier,
    pub rtt_ms: Option<u32>,
    /// How far this peer's wall clock reads from ours (ms; positive = the
    /// peer is ahead), estimated passively from the heartbeat pings it
    /// already sends (RTT-corrected median over a short window). `None`
    /// until its first inbound ping. The current status schema requires this
    /// field, including when its value is `None`.
    pub clock_skew_ms: Option<i64>,
    pub label: String,
    pub capabilities: Option<CapabilityAdvert>,
    pub local_shelved: bool,
    pub remote_shelved: bool,
    pub authenticated: bool,
    /// 5-char UPPERCASE-HEX display tag derived from the peer's
    /// pubkey. Same scheme as `Identity::display_id` — peers compare
    /// suffixes to confirm "yes, this is the right device" without
    /// reading the full pubkey aloud. Surfaced separately so the GUI
    /// can render it in a distinct tile during pending-approval.
    pub device_suffix: String,
    /// Verification code the peer sent us in their `hello` — i.e.
    /// the peer's own code that we should be displaying as "theirs"
    /// in the approval UI. `None` until we receive a hello.
    pub verification_code_received: Option<String>,
    /// Verification code WE sent the peer in our `hello` — i.e. our
    /// own code that we should be displaying as "ours" in the
    /// approval UI. Both ends generate one (independent random
    /// strings), and the bilateral approval flow asks each user to
    /// confirm all four values match what the other side reads
    /// back: this device's suffix + code, the peer's suffix + code.
    /// `None` until our handshake has fired.
    pub verification_code_sent: Option<String>,
    /// True once this peer's exact current data channel has accepted our
    /// `Approve` bytes for transmission, either via the user clicking Approve
    /// in the GUI or via roster auto-approval. This does not prove remote
    /// receipt. Surfaced so the
    /// approval UI can flip the row from "review and approve" to
    /// "waiting for peer to approve their side" — the connection
    /// doesn't transition to Active until both ends have approved.
    pub local_approve_sent: bool,
    /// True once we've received an `Approve` from this peer. Pairs
    /// with `local_approve_sent`: when both are true the engine
    /// transitions the peer to Active. Either alone means the
    /// handshake is half-complete and waiting on the other end.
    pub remote_approve_seen: bool,
    /// True when the engine has decided this peer is unreachable
    /// without a TURN relay (multiple ICE failures, zero relay
    /// candidates on either side). Mirrors the one-shot
    /// `no_turn_diag_emitted` flag the ICE watchdog sets — the GUI
    /// uses it to surface "we can see them on signaling but the data
    /// pipe never comes up" without making the user grep the
    /// Activity log. Reset when the peer recovers to Active.
    pub needs_turn: bool,
    /// Counts of locally-gathered ICE candidates by type. The GUI
    /// uses these to infer the link kind for the layout: `host`-only
    /// pairs are LAN neighbours and sit directly next to "you",
    /// while `server_reflexive` / `relay` pairs sit on the far side
    /// of the Internet node. Zeroed until ICE starts gathering.
    pub local_candidates: IceCandidateStats,
    /// Counts of ICE candidates the peer sent us. Same layout role
    /// as `local_candidates` — both sides have to surface a host
    /// candidate before we treat the link as LAN-direct.
    pub remote_candidates: IceCandidateStats,
    /// The ICE candidate pair the agent actually selected for
    /// sending packets, once known. Authoritative input for the
    /// graph's LAN/STUN/TURN classification — the counts above only
    /// describe what was tried, this describes what's in use. `None`
    /// until ICE reaches Connected/Completed.
    pub selected_pair: Option<SelectedCandidatePair>,
}

/// Redacted, immutable description of the one authenticated wire profile.
///
/// The profile is derived from the local authenticated observation rather than
/// copied from peer input. Its presence is the authentication bit; it carries
/// no peer-supplied identifiers, capabilities, or mutable engine state.
#[derive(Debug, Clone, Copy, Deserialize, Eq, PartialEq, Serialize)]
pub struct AuthenticatedProfile {
    pub protocol_version: u32,
    pub endpoint_auth_v1: bool,
}

impl PeerInfo {
    /// Return the fixed authenticated profile only after this peer is locally
    /// authenticated. The current protocol has exactly one endpoint-auth
    /// profile, so no peer-controlled profile selector is exposed.
    pub fn authenticated_profile(&self) -> Option<AuthenticatedProfile> {
        self.authenticated.then_some(AuthenticatedProfile {
            protocol_version: crate::PROTOCOL_VERSION,
            endpoint_auth_v1: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::Identity;
    use crate::resource::ResourceClaim;

    fn infrastructure_resources() -> ResourceProviderPort {
        static PROVIDER: std::sync::OnceLock<ResourceProviderPort> = std::sync::OnceLock::new();
        PROVIDER
            .get_or_init(|| {
                let grant = ResourceClaim::try_from_entries(
                    crate::resource::ResourceClass::ALL
                        .into_iter()
                        .map(|dimension| (dimension, 1_000_000)),
                )
                .expect("fixture grant is representable");
                ResourceProviderPort::new(crate::resource::FiniteResourceProvider::new(grant))
                    .expect("fixture grant funds its process record")
            })
            .clone()
    }

    #[test]
    fn public_display_device_id_dials_the_bare_signaling_registry_key() {
        assert_eq!(
            peer_registry_key("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst-24842"),
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
        );
        assert_eq!(
            peer_registry_key("abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"),
            "abcdefghijklmnopqrstuvwxyz234567abcdefghijklmnopqrst"
        );
    }

    /// The injection seam adopts the caller's identity rather than the
    /// on-disk anchor: the opened mesh's device id is the injected key's
    /// public id. This is the path a phone uses to open the engine with a
    /// key from its Keychain/Keystore (built via `Identity::from_signing_key`,
    /// which `ephemeral()` also uses).
    #[tokio::test]
    async fn open_with_identity_adopts_the_injected_key() {
        let identity = Arc::new(Identity::ephemeral());
        let want = identity.public_id().to_string();

        let mesh = Mesh::open_infrastructure_only_with_identity(
            MeshConfig::default(),
            identity,
            infrastructure_resources(),
        )
        .await
        .expect("open_with_identity");

        // The mesh's wire id derives from the injected key, not a disk anchor.
        assert_eq!(mesh.device_id(), want);
    }

    #[tokio::test]
    async fn ownerless_mesh_rejects_network_join_with_typed_policy_error() {
        let identity = Arc::new(Identity::ephemeral());
        let mesh = Mesh::open_infrastructure_only_with_identity(
            MeshConfig::default(),
            identity,
            infrastructure_resources(),
        )
        .await
        .expect("open infrastructure-only mesh");

        let error = match mesh
            .join(NetworkConfig::from_network_id("ownerless", "ownerless"))
            .await
        {
            Ok(_) => panic!("ownerless mesh must not join a network"),
            Err(error) => error,
        };
        assert!(matches!(error, Error::ConnectorPolicyRequired));
    }

    #[test]
    fn peer_info_requires_the_current_clock_skew_field() {
        let snapshot = PeerInfo {
            device_id: "peer".into(),
            status: PeerStatus::Offline,
            tier: ConnectionTier::Steady,
            rtt_ms: None,
            clock_skew_ms: None,
            label: String::new(),
            capabilities: None,
            local_shelved: false,
            remote_shelved: false,
            authenticated: false,
            device_suffix: String::new(),
            verification_code_received: None,
            verification_code_sent: None,
            local_approve_sent: false,
            remote_approve_seen: false,
            needs_turn: false,
            local_candidates: IceCandidateStats::default(),
            remote_candidates: IceCandidateStats::default(),
            selected_pair: None,
        };
        let mut value = serde_json::to_value(snapshot).expect("peer snapshot serializes");
        value
            .as_object_mut()
            .expect("peer snapshot is an object")
            .remove("clock_skew_ms");
        assert!(serde_json::from_value::<PeerInfo>(value).is_err());
    }
}
