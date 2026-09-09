#![cfg(feature = "transport-lab")]

//! Operator-selected semantic-ledger scaling controls.
//!
//! These tests deliberately drive the public `JoinedNetwork` admission path
//! and the durable store used by production startup.  They are ignored so a
//! normal test run does not claim a performance result or allocate the 500k
//! workload.  The scale selectors are exact and bounded at the test entry
//! points below.  JSON reports label process-lifetime VmHWM and current-process
//! read/write-byte observations as such; they are not restore-only or
//! database-only metrics. Timing samples are retained only within the fixed
//! window bound; the top-level p50/p95/p99 fields summarize the bounded
//! deterministic sample. Percentiles use the one-based nearest-rank rule:
//! `ceil(n * percentile / 100)` (with the resulting rank converted to a
//! zero-based index).

use std::fs;
use std::path::Path;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc, Mutex, MutexGuard, OnceLock,
};
use std::time::{Duration, Instant};

use ed25519_dalek::SigningKey;
use myownmesh_core::config::{
    ClosedRelayPolicyConfig, NetworkConfig, NetworkKind, RoutingPolicyConfig, SemanticPolicyConfig,
    SemanticStorageEnvelope, SignalingConfig, TopologyMode,
};
use myownmesh_core::resource::{
    FiniteResourceProvider, ResourceClaim, ResourceClass, ResourceProviderPort,
};
use myownmesh_core::semantic::SemanticFactPageRequest;
use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactDomain, FactId, SemanticFactPage, SignedFact,
    VerifiedBootstrap,
};
use myownmesh_core::{
    handle::SemanticAdmissionProfile, ConnectorCallbackPolicy, Identity, Mesh, MeshConfig,
    WebRtcConnectorCapablePolicy, WebRtcConnectorProfile,
};
use serde::Serialize;
use tokio::sync::Barrier;
use tokio::task::JoinSet;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
struct DbFootprint {
    main_bytes: u64,
    wal_bytes: u64,
    shm_bytes: u64,
    journal_bytes: u64,
    temp_bytes: u64,
}

impl DbFootprint {
    fn total_bytes(self) -> u64 {
        self.main_bytes
            .checked_add(self.wal_bytes)
            .and_then(|bytes| bytes.checked_add(self.shm_bytes))
            .and_then(|bytes| bytes.checked_add(self.journal_bytes))
            .and_then(|bytes| bytes.checked_add(self.temp_bytes))
            .expect("database footprint fits u64")
    }

    fn observe_peak(&mut self, current: Self) {
        self.main_bytes = self.main_bytes.max(current.main_bytes);
        self.wal_bytes = self.wal_bytes.max(current.wal_bytes);
        self.shm_bytes = self.shm_bytes.max(current.shm_bytes);
        self.journal_bytes = self.journal_bytes.max(current.journal_bytes);
        self.temp_bytes = self.temp_bytes.max(current.temp_bytes);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
struct ProviderSnapshot {
    owner_active_candidates: usize,
    owner_failed_cleanup_candidates: usize,
    owner_accounting_poisoned: bool,
    owner_queued_jobs: usize,
    owner_active_jobs: usize,
    owner_completed_jobs: u64,
    owner_failed_jobs: u64,
    owner_executor_failed: bool,
    mesh_active_candidates: usize,
    mesh_failed_cleanup_candidates: usize,
    mesh_accounting_poisoned: bool,
}

#[derive(Debug, Serialize)]
struct ScaleMetrics {
    selector: &'static str,
    root: String,
    platform: &'static str,
    scale_n: usize,
    admitted_delta: u64,
    seeded_admissions: usize,
    timed_admissions: usize,
    seed_total_ms: f64,
    unresolved: u64,
    admission_total_ms: f64,
    admission_end_to_end_total_ms: f64,
    admissions_per_sec: f64,
    admission_p50_ms: f64,
    admission_p95_ms: f64,
    admission_p99_ms: f64,
    early_window_average_ms_per_admission: Option<f64>,
    late_window_average_ms_per_admission: Option<f64>,
    early_late_normalized_slope_ms_per_admission: Option<f64>,
    tail_fact: Option<TailFactEvidence>,
    no_op: Option<NoOpEvidence>,
    progress_checkpoint_count: usize,
    progress_sample_interval: usize,
    window_admission_target: usize,
    window_sample_limit: usize,
    window_evidence: Vec<ScaleWindowEvidence>,
    db_main_bytes_peak: u64,
    db_wal_bytes_peak: u64,
    db_shm_bytes_peak: u64,
    db_journal_bytes_peak: u64,
    db_total_bytes_peak: u64,
    wal_hard_frame_limit: u64,
    wal_hard_byte_limit: u64,
    wal_checkpoint_threshold_bytes: u64,
    compaction_ms: f64,
    db_main_bytes_after_compaction: u64,
    db_wal_bytes_after_compaction: u64,
    db_shm_bytes_after_compaction: u64,
    db_total_bytes_after: u64,
    startup_plus_restore_ms: f64,
    cache_state: &'static str,
    process_scope_cpu_time_ms: Option<f64>,
    process_scope_read_bytes_delta: Option<u64>,
    process_lifetime_peak_vmhwm_bytes: Option<u64>,
    process_rss_after_seed_bytes: Option<u64>,
    process_rss_after_workload_bytes: Option<u64>,
    process_rss_after_compaction_bytes: Option<u64>,
    process_rss_after_restore_bytes: Option<u64>,
    process_scope_write_bytes_delta: Option<u64>,
    process_scope_write_bytes_per_admission: Option<f64>,
    admission_phases: serde_json::Value,
    provider_baseline: ProviderSnapshot,
    provider_final: ProviderSnapshot,
}

#[derive(Debug, Serialize)]
struct ScaleWindowEvidence {
    start_admitted: usize,
    end_admitted: usize,
    admission_count: usize,
    admission_total_ms: f64,
    elapsed_ms: f64,
    average_admission_ms: f64,
    max_admission_ms: f64,
    p50_ms: f64,
    p95_ms: f64,
    p99_ms: f64,
    average_slope_ms_per_admission: Option<f64>,
    db_main_bytes: u64,
    db_wal_bytes: u64,
    db_shm_bytes: u64,
    db_total_bytes: u64,
}

const SCALE_WINDOW_TARGETS: usize = 128;
const WINDOW_SAMPLE_LIMIT: usize = 64;
const MAX_TIMING_SAMPLES: usize = SCALE_WINDOW_TARGETS * WINDOW_SAMPLE_LIMIT;
// Large-scale controls validate the whole durable history, then measure enough
// individual production admissions for stable percentile/window evidence.
// More samples only add fsync wall time; they do not improve the scale proof.
const LARGE_SCALE_TIMED_ADMISSIONS: usize = 2_000;

#[derive(Debug, Serialize)]
struct TailFactEvidence {
    elapsed_ms: f64,
    admitted_before: u64,
    admitted_after: u64,
    db_before: DbFootprint,
    db_after: DbFootprint,
    provider_before: ProviderSnapshot,
    provider_after: ProviderSnapshot,
}

#[derive(Debug, Serialize)]
struct NoOpEvidence {
    db_before: DbFootprint,
    db_after: DbFootprint,
    provider_before: ProviderSnapshot,
    provider_after: ProviderSnapshot,
}

#[derive(Debug, Serialize)]
struct OpenMetrics {
    selector: &'static str,
    root: String,
    platform: &'static str,
    cycles: usize,
    db_baseline: DbFootprint,
    db_final: DbFootprint,
    provider_baseline: ProviderSnapshot,
    provider_final: ProviderSnapshot,
}

#[derive(Debug, Serialize)]
struct ConcurrentProducerMetrics {
    selector: &'static str,
    group_size: usize,
    max_inflight_callers: usize,
    producer_count: usize,
    admitted_count: u64,
    durable_commit_count: u64,
    causal_journal_count: u64,
    mean_facts_per_durable_commit: f64,
    elapsed_ms: f64,
    throughput_per_sec: f64,
    latency_p50_ms: f64,
    latency_p95_ms: f64,
    latency_p99_ms: f64,
    completion_order: Vec<usize>,
    sequential_provider_baseline: ProviderSnapshot,
    sequential_provider_final: ProviderSnapshot,
    concurrent_provider_baseline: ProviderSnapshot,
    concurrent_provider_final: ProviderSnapshot,
    sequential_admission_phases: SemanticAdmissionProfile,
    concurrent_admission_phases: SemanticAdmissionProfile,
}

#[derive(Debug, Serialize)]
struct GroupCommitHotpathMetrics {
    selector: &'static str,
    group_size: usize,
    admitted_count: u64,
    durable_commit_count: u64,
    causal_journal_count: u64,
    facts_per_durable_commit: f64,
    elapsed_ms: f64,
    throughput_per_sec: f64,
    db_before: DbFootprint,
    db_after: DbFootprint,
    admission_phases: SemanticAdmissionProfile,
    provider_baseline: ProviderSnapshot,
    provider_final: ProviderSnapshot,
}

#[derive(Debug, Clone, Copy)]
struct ScaleCapacity {
    admitted_bytes: u64,
    database_bytes: u64,
    provider_per_class: u64,
    semantic_policy: SemanticPolicyConfig,
    storage_envelope: SemanticStorageEnvelope,
}

fn representative_fact_bytes(network_id: &str, parents: Vec<FactId>) -> u64 {
    let author = SigningKey::from_bytes(&[0x71; 32]);
    let bootstrap = VerifiedBootstrap::create_closed(network_id, [author.clone()], [0x71; 32])
        .expect("representative bootstrap verifies");
    let target = myownmesh_core::semantic::DeviceId::from_canonical_str(&target_id(0))
        .expect("representative target id is canonical");
    let fact = SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::RoleGrant {
                target,
                role: myownmesh_core::semantic::Role::Member,
            },
            myownmesh_core::semantic::DeviceId::from_public_key_bytes(
                *author.verifying_key().as_bytes(),
            )
            .expect("representative author id is valid"),
            parents,
        ),
        &author,
    )
    .expect("representative role grant signs");
    u64::try_from(
        serde_json::to_vec(&fact)
            .expect("representative fact serializes")
            .len(),
    )
    .expect("representative fact bytes fit u64")
}

fn scale_capacity(scale: usize, network_id: &str) -> ScaleCapacity {
    scale_capacity_with_ready_batch(scale, network_id, 1)
}

fn scale_capacity_with_ready_batch(
    scale: usize,
    network_id: &str,
    max_ready_batch: usize,
) -> ScaleCapacity {
    assert!(
        max_ready_batch > 0,
        "the selected ready-batch bound is finite and nonzero"
    );
    let scale_u64 = u64::try_from(scale).expect("scale fits u64");
    let first_fact_bytes = representative_fact_bytes(network_id, Vec::new());
    let chained_fact_bytes =
        representative_fact_bytes(network_id, vec![FactId::from_bytes([0; 32])]);
    let admitted_bytes = first_fact_bytes
        .checked_add(
            chained_fact_bytes
                .checked_mul(
                    scale_u64
                        .checked_sub(1)
                        .expect("qualified scale has a first fact"),
                )
                .expect("scaled chained fact bytes fit u64"),
        )
        .expect("scaled admitted fact bytes fit u64");
    let max_fact_encoded_bytes = first_fact_bytes.max(chained_fact_bytes);
    let mut policy = SemanticPolicyConfig {
        max_fact_encoded_bytes,
        ..SemanticPolicyConfig::default()
    };
    policy.max_dependencies_per_fact = 1;
    policy.max_authority_uses_per_fact = 2;
    policy.max_authority_predecessors_per_use = 1;
    policy.max_admitted_facts = scale_u64;
    policy.max_admitted_bytes = admitted_bytes;
    // The workload has no durable quarantine or proof records, but the
    // production policy requires nonzero lifecycle bounds.  Reserve exactly
    // one refused fact and one each of the proof/provisional rows; these are
    // explicit admission/refusal lifecycle maxima, not storage multipliers.
    policy.max_quarantined_facts = 1;
    policy.max_quarantined_bytes = max_fact_encoded_bytes;
    policy.max_quarantined_facts_per_author = 1;
    policy.max_quarantined_bytes_per_author = max_fact_encoded_bytes;
    policy.max_retained_facts_per_author = scale_u64;
    policy.max_retained_bytes_per_author = admitted_bytes;
    let first_dependency_edges = 2u64; // two RoleGrant authority uses
    let chained_dependency_edges = 5u64; // parent + two uses + two predecessors
    policy.max_dependency_edges = first_dependency_edges
        .checked_add(
            chained_dependency_edges
                .checked_mul(
                    scale_u64
                        .checked_sub(1)
                        .expect("qualified scale has a first fact"),
                )
                .expect("scaled dependency edges fit u64"),
        )
        .expect("dependency edge workload fits u64");
    policy.max_ready_batch =
        u64::try_from(max_ready_batch).expect("the selected ready-batch bound fits u64");
    let batch_bound = u64::try_from(max_ready_batch)
        .expect("the selected ready-batch bound fits the semantic policy");
    policy.max_pending_proofs = batch_bound;
    policy.max_pending_proof_bytes = max_fact_encoded_bytes
        .checked_mul(batch_bound)
        .expect("the selected proof-delivery envelope fits u64");
    policy.max_proof_records = batch_bound;
    policy.max_proof_bytes = policy.max_pending_proof_bytes;
    policy.max_proof_links = batch_bound;
    policy.max_author_usage_rows = 1;
    policy.max_provisional_rows = 1;
    policy.max_freelist_pages = 1;
    policy.max_fragmented_pages = 1;
    let page_size = myownmesh_core::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES;
    // Compute through the same checked production planner used by semantic
    // store startup.  The temporary ceiling only permits this first checked
    // calculation; the selected policy is immediately reduced to the exact
    // returned finite envelope below.
    policy.max_database_bytes = u64::MAX;
    let workload = policy.storage_workload();
    let storage_envelope = policy
        .checked_storage_envelope(page_size, workload)
        .expect("production storage envelope fits u64");
    policy.max_database_bytes = storage_envelope.total_bytes;
    let storage_envelope = policy
        .checked_storage_envelope(page_size, policy.storage_workload())
        .expect("selected production storage envelope remains valid");
    assert!(
        policy.validate(),
        "scale policy must pass production validation"
    );
    // The connector owner also admits the protocol's finite callback
    // envelope while each real fact is proposed.  Price the larger of that
    // protocol bound and the measured real fact, once per workload item.
    let one_fact_resource_bytes = max_fact_encoded_bytes
        .max(myownmesh_core::protocol::relay::CLOSED_RELAY_WEBRTC_CALLBACK_BYTES);
    let provider_per_class = one_fact_resource_bytes
        .checked_mul(scale_u64)
        .expect("scaled provider capacity fits u64");
    ScaleCapacity {
        admitted_bytes,
        database_bytes: storage_envelope.total_bytes,
        provider_per_class,
        semantic_policy: policy,
        storage_envelope,
    }
}

fn finite_provider(capacity: ScaleCapacity) -> FiniteResourceProvider {
    let per_class = capacity.provider_per_class;
    let grant = ResourceClaim::try_from_entries(ResourceClass::ALL.into_iter().map(|class| {
        let amount = if class == ResourceClass::StorageBytes {
            capacity.database_bytes
        } else {
            per_class
        };
        (class, amount)
    }))
    .expect("finite scaling resource grant");
    FiniteResourceProvider::new(grant)
}

fn connector_policy_for_resources(resources: ResourceProviderPort) -> WebRtcConnectorCapablePolicy {
    WebRtcConnectorCapablePolicy::new(
        resources,
        WebRtcConnectorProfile::new(ConnectorCallbackPolicy::elastic_data_only()),
    )
}

fn connector_policy(
    capacity: ScaleCapacity,
) -> (WebRtcConnectorCapablePolicy, FiniteResourceProvider) {
    let provider = finite_provider(capacity);
    let resources =
        ResourceProviderPort::new(provider.clone()).expect("finite scaling resource provider");
    let connector = connector_policy_for_resources(resources);
    (connector, provider)
}

fn assert_footprint_within(policy: &SemanticPolicyConfig, footprint: DbFootprint, label: &str) {
    let envelope = policy
        .checked_storage_envelope(
            myownmesh_core::config::SQLITE_DEFAULT_PAGE_SIZE_BYTES,
            policy.storage_workload(),
        )
        .expect("selected database envelope is valid");
    assert!(
        footprint.main_bytes <= envelope.main_bytes,
        "{label}: main database exceeds selected M envelope"
    );
    assert!(
        footprint.journal_bytes <= envelope.main_journal_bytes,
        "{label}: main journal exceeds selected J envelope"
    );
    assert!(
        footprint.wal_bytes <= envelope.wal_bytes,
        "{label}: WAL exceeds selected W envelope"
    );
    assert!(
        footprint.shm_bytes <= envelope.shm_bytes,
        "{label}: SHM exceeds selected S envelope"
    );
    assert!(
        footprint.temp_bytes <= envelope.emergency_reserve_bytes,
        "{label}: temporary files exceed selected R envelope"
    );
    assert!(
        footprint.total_bytes() <= envelope.total_bytes,
        "{label}: total database footprint exceeds selected envelope"
    );
}

fn provider_snapshot(mesh: &myownmesh_core::MeshHandle) -> ProviderSnapshot {
    let owner = mesh
        .connector_resource_report()
        .expect("scaling mesh retains its connector provider");
    let mesh_report = mesh
        .mesh_connector_resource_report()
        .expect("scaling mesh retains its connector scope");
    ProviderSnapshot {
        owner_active_candidates: owner.active_candidates,
        owner_failed_cleanup_candidates: owner.failed_cleanup_candidates,
        owner_accounting_poisoned: owner.accounting_poisoned,
        owner_queued_jobs: owner.cleanup.queued_jobs,
        owner_active_jobs: owner.cleanup.active_jobs,
        owner_completed_jobs: owner.cleanup.completed_jobs,
        owner_failed_jobs: owner.cleanup.failed_jobs,
        owner_executor_failed: owner.cleanup.executor_failed,
        mesh_active_candidates: mesh_report.active_candidates,
        mesh_failed_cleanup_candidates: mesh_report.failed_cleanup_candidates,
        mesh_accounting_poisoned: mesh_report.accounting_poisoned,
    }
}

fn platform() -> &'static str {
    std::env::consts::OS
}

static HOME_ENV_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

struct ScopedMeshHome {
    _lock: MutexGuard<'static, ()>,
    previous: Option<std::ffi::OsString>,
}

impl ScopedMeshHome {
    fn new(path: &Path) -> Self {
        let lock = HOME_ENV_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("mesh-home environment lock");
        let previous = std::env::var_os("MYOWNMESH_HOME");
        std::env::set_var("MYOWNMESH_HOME", path);
        Self {
            _lock: lock,
            previous,
        }
    }
}

impl Drop for ScopedMeshHome {
    fn drop(&mut self) {
        if let Some(previous) = self.previous.take() {
            std::env::set_var("MYOWNMESH_HOME", previous);
        } else {
            std::env::remove_var("MYOWNMESH_HOME");
        }
    }
}

fn semantic_policy(scale: usize, capacity: ScaleCapacity) -> SemanticPolicyConfig {
    let policy = capacity.semantic_policy;
    assert_eq!(
        policy.max_admitted_facts,
        u64::try_from(scale).expect("scale fits u64")
    );
    assert_eq!(policy.max_admitted_bytes, capacity.admitted_bytes);
    assert_eq!(policy.max_database_bytes, capacity.database_bytes);
    assert_eq!(
        policy.max_database_bytes,
        capacity.storage_envelope.total_bytes
    );
    assert!(
        policy.validate(),
        "scale policy must be accepted by production validation"
    );
    policy
}

fn closed_config(id: &str, scale: usize, capacity: ScaleCapacity) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: id.to_string(),
        event_capacity: 256,
        connection_trace_capacity: 512,
        label: id.to_string(),
        kind: NetworkKind::Closed,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        application_transport: None,
        tree: None,
        scheduler: Default::default(),
        semantic_policy: semantic_policy(scale, capacity),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig {
            strategy: "none".to_string(),
            mdns: false,
            ..SignalingConfig::default()
        },
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn open_config(id: &str) -> NetworkConfig {
    NetworkConfig {
        id: id.to_string(),
        network_id: id.to_string(),
        event_capacity: 256,
        connection_trace_capacity: 512,
        label: id.to_string(),
        kind: NetworkKind::Open,
        routing_policy: RoutingPolicyConfig::default(),
        hub: None,
        local_observations: None,
        application_transport: None,
        tree: None,
        scheduler: Default::default(),
        semantic_policy: SemanticPolicyConfig::default(),
        topology: TopologyMode::FullMesh,
        signaling: SignalingConfig {
            strategy: "none".to_string(),
            mdns: false,
            ..SignalingConfig::default()
        },
        closed_relay: ClosedRelayPolicyConfig::default(),
        stun_servers: Vec::new(),
        turn_servers: Vec::new(),
        pinned_peers: Vec::new(),
        auto_approve: false,
    }
}

fn target_id(index: usize) -> String {
    let mut seed = [0xa5u8; 32];
    seed[..8].copy_from_slice(
        &u64::try_from(index)
            .expect("target index fits u64")
            .checked_add(1)
            .expect("target index is bounded")
            .to_le_bytes(),
    );
    let signing_key = SigningKey::from_bytes(&seed);
    myownmesh_core::semantic::DeviceId::from_public_key_bytes(
        *signing_key.verifying_key().as_bytes(),
    )
    .expect("deterministic target id")
    .to_string()
}

fn db_footprint(root: &Path) -> DbFootprint {
    fn visit(path: &Path, footprint: &mut DbFootprint) {
        let entries = fs::read_dir(path).expect("owned instance root is readable");
        for entry in entries {
            let entry = entry.expect("owned database directory entry");
            let entry_path = entry.path();
            let file_type = entry.file_type().expect("database entry type");
            if file_type.is_dir() {
                visit(&entry_path, footprint);
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let size = entry.metadata().expect("database entry metadata").len();
            if name.ends_with("-store.sqlite3") {
                footprint.main_bytes = footprint
                    .main_bytes
                    .checked_add(size)
                    .expect("main database footprint fits u64");
            } else if name.ends_with("-store.sqlite3-wal") {
                footprint.wal_bytes = footprint
                    .wal_bytes
                    .checked_add(size)
                    .expect("WAL footprint fits u64");
            } else if name.ends_with("-store.sqlite3-shm") {
                footprint.shm_bytes = footprint
                    .shm_bytes
                    .checked_add(size)
                    .expect("SHM footprint fits u64");
            } else if name.ends_with("-store.sqlite3-journal") {
                footprint.journal_bytes = footprint
                    .journal_bytes
                    .checked_add(size)
                    .expect("journal footprint fits u64");
            } else if name.contains("-store.sqlite3") {
                footprint.temp_bytes = footprint
                    .temp_bytes
                    .checked_add(size)
                    .expect("database temporary footprint fits u64");
            }
        }
    }

    let mut footprint = DbFootprint::default();
    visit(root, &mut footprint);
    footprint
}

#[cfg(target_os = "linux")]
fn process_io_bytes() -> Option<(u64, u64)> {
    let status = fs::read_to_string("/proc/self/io").ok()?;
    let mut read_bytes = None;
    let mut write_bytes = None;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("read_bytes:") {
            read_bytes = Some(value.trim().parse().ok()?);
        } else if let Some(value) = line.strip_prefix("write_bytes:") {
            write_bytes = Some(value.trim().parse().ok()?);
        }
    }
    Some((read_bytes?, write_bytes?))
}

#[cfg(not(target_os = "linux"))]
fn process_io_bytes() -> Option<(u64, u64)> {
    None
}

#[cfg(target_os = "linux")]
fn process_cpu_time_ms() -> Option<f64> {
    let status = fs::read_to_string("/proc/self/stat").ok()?;
    let command_end = status.rfind(')')?;
    let mut fields = status.get(command_end + 2..)?.split_whitespace();
    let user_ticks = fields.nth(11)?.parse::<u64>().ok()?;
    let system_ticks = fields.next()?.parse::<u64>().ok()?;
    let total_ticks = user_ticks.checked_add(system_ticks)?;
    let ticks_per_second = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (ticks_per_second > 0).then(|| total_ticks as f64 * 1_000.0 / ticks_per_second as f64)
}

#[cfg(not(target_os = "linux"))]
fn process_cpu_time_ms() -> Option<f64> {
    None
}

#[cfg(target_os = "linux")]
fn process_vmhwm_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line
            .strip_prefix("VmHWM:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?;
        value.checked_mul(1024)
    })
}

#[cfg(not(target_os = "linux"))]
fn process_vmhwm_bytes() -> Option<u64> {
    None
}

#[cfg(target_os = "linux")]
fn process_vmrss_bytes() -> Option<u64> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    status.lines().find_map(|line| {
        let value = line
            .strip_prefix("VmRSS:")?
            .split_whitespace()
            .next()?
            .parse::<u64>()
            .ok()?;
        value.checked_mul(1024)
    })
}

#[cfg(not(target_os = "linux"))]
fn process_vmrss_bytes() -> Option<u64> {
    None
}

fn percentile_ms_sorted(samples: &[Duration], percentile: usize) -> f64 {
    assert!(
        !samples.is_empty(),
        "nearest-rank requires a nonempty sample"
    );
    assert!(percentile > 0 && percentile <= 100);
    let rank = samples
        .len()
        .checked_mul(percentile)
        .and_then(|value| value.checked_add(99))
        .expect("nearest-rank arithmetic fits usize")
        / 100;
    let index = rank.checked_sub(1).expect("nearest-rank is one-based");
    samples[index].as_secs_f64() * 1_000.0
}

#[cfg(test)]
mod metric_controls {
    use super::*;

    #[test]
    fn nearest_rank_percentiles_are_one_based() {
        let samples: Vec<_> = (1..=10).map(Duration::from_millis).collect();
        assert_eq!(percentile_ms_sorted(&samples, 50), 5.0);
        assert_eq!(percentile_ms_sorted(&samples, 95), 10.0);
        assert_eq!(percentile_ms_sorted(&samples, 99), 10.0);
    }

    #[test]
    fn timing_sample_bound_is_explicit() {
        assert_eq!(
            MAX_TIMING_SAMPLES,
            SCALE_WINDOW_TARGETS * WINDOW_SAMPLE_LIMIT
        );
        const _: () = {
            if MAX_TIMING_SAMPLES > 8_192 {
                panic!("timing sample bound exceeds the fixed diagnostic ceiling");
            }
        };
    }
}

/// Read the concurrent-producer selector as an explicit operator choice.
/// There is intentionally no production/default group size: the finite
/// resource grant and this selector together define the diagnostic run.
fn selected_concurrent_group() -> myownmesh_core::Result<Option<usize>> {
    let Some(raw) = std::env::var_os("MYOWNMESH_SCALE_CONCURRENT_GROUP") else {
        return Ok(None);
    };
    let raw = raw.to_str().ok_or_else(|| {
        myownmesh_core::Error::Other("MYOWNMESH_SCALE_CONCURRENT_GROUP must be UTF-8".to_string())
    })?;
    let value = raw.parse::<u64>().map_err(|error| {
        myownmesh_core::Error::Other(format!(
            "MYOWNMESH_SCALE_CONCURRENT_GROUP must be an integer: {error}"
        ))
    })?;
    let value = usize::try_from(value).map_err(|_| {
        myownmesh_core::Error::Other(
            "MYOWNMESH_SCALE_CONCURRENT_GROUP does not fit usize".to_string(),
        )
    })?;
    if !(2..=64).contains(&value) {
        return Err(myownmesh_core::Error::Other(
            "MYOWNMESH_SCALE_CONCURRENT_GROUP must be between 2 and 64".to_string(),
        ));
    }
    Ok(Some(value))
}

async fn run_public_producer_case(
    home: &Path,
    network_id: &str,
    targets: &[String],
    concurrent: bool,
    provider: &FiniteResourceProvider,
    connector: &WebRtcConnectorCapablePolicy,
) -> myownmesh_core::Result<(
    myownmesh_core::semantic::SemanticStateIdentity,
    Vec<Duration>,
    Vec<usize>,
    usize,
    ProviderSnapshot,
    ProviderSnapshot,
    SemanticAdmissionProfile,
    Duration,
)> {
    let _home_env = ScopedMeshHome::new(home);
    let capacity = scale_capacity_with_ready_batch(targets.len(), network_id, targets.len());
    let identity = Arc::new(Identity::from_signing_key(
        SigningKey::from_bytes(&[0x43; 32]),
        "semantic-scale-concurrent",
    ));
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        identity,
        connector.clone(),
    )
    .await?;
    let provider_baseline_claim = provider.in_use();
    let provider_baseline = provider_snapshot(&mesh);
    let network = mesh
        .create_network(
            closed_config(network_id, targets.len(), capacity),
            [0x71; 32],
        )
        .await?;
    assert_eq!(provider_snapshot(&mesh), provider_baseline);
    let network = Arc::new(network);
    network.reset_semantic_admission_profile_for_lab();
    let producer_started = Instant::now();
    let (latencies, replay_order, peak_producers) = if concurrent {
        let barrier = Arc::new(Barrier::new(targets.len()));
        let active_producers = Arc::new(AtomicUsize::new(0));
        let peak_producers = Arc::new(AtomicUsize::new(0));
        let mut producers = JoinSet::new();
        for (index, target) in targets.iter().cloned().enumerate() {
            let barrier = Arc::clone(&barrier);
            let active_producers = Arc::clone(&active_producers);
            let peak_producers = Arc::clone(&peak_producers);
            let network = Arc::clone(&network);
            producers.spawn(async move {
                barrier.wait().await;
                let active = active_producers.fetch_add(1, Ordering::AcqRel) + 1;
                peak_producers.fetch_max(active, Ordering::AcqRel);
                let started = Instant::now();
                let outcome = network
                    .propose_role_grant(&target, myownmesh_core::semantic::Role::Member, None)
                    .await
                    .map(|_| (index, started.elapsed()));
                active_producers.fetch_sub(1, Ordering::AcqRel);
                outcome
            });
        }
        let mut completed = Vec::with_capacity(targets.len());
        while let Some(result) = producers.join_next().await {
            let result = result.map_err(|error| {
                myownmesh_core::Error::Other(format!(
                    "concurrent semantic producer task failed: {error}"
                ))
            })??;
            completed.push(result);
        }
        let latencies = completed.iter().map(|(_, elapsed)| *elapsed).collect();
        let replay_order = completed.iter().map(|(index, _)| *index).collect();
        (
            latencies,
            replay_order,
            peak_producers.load(Ordering::Acquire),
        )
    } else {
        let mut latencies = Vec::with_capacity(targets.len());
        let mut replay_order = Vec::with_capacity(targets.len());
        for (index, target) in targets.iter().enumerate() {
            let started = Instant::now();
            network
                .propose_role_grant(target, myownmesh_core::semantic::Role::Member, None)
                .await?;
            latencies.push(started.elapsed());
            replay_order.push(index);
        }
        (latencies, replay_order, 1)
    };
    let producer_elapsed = producer_started.elapsed();
    let admission_phases = network.semantic_admission_profile_for_lab();
    // SemanticStateIdentity carries a provider lease while it is live.  The
    // benchmark needs only its scalar observation fields across teardown, so
    // exercise the public diagnostic representation and release that lease
    // before asserting the provider baseline.
    let identity: myownmesh_core::semantic::SemanticStateIdentity = serde_json::from_value(
        serde_json::to_value(network.semantic_state_identity()?)
            .expect("semantic producer identity serializes"),
    )
    .expect("semantic producer identity diagnostic representation round-trips");
    assert_eq!(
        identity.admitted_fact_count(),
        u64::try_from(targets.len()).expect("concurrent producer count fits u64")
    );
    let network = Arc::try_unwrap(network).map_err(|_| {
        myownmesh_core::Error::Other("producer tasks retained the network owner".to_string())
    })?;
    network.shutdown().await?;
    drop(network);
    let provider_final = provider_snapshot(&mesh);
    assert_eq!(
        provider_final, provider_baseline,
        "producer case releases all funded resources"
    );
    assert_eq!(
        provider.in_use(),
        provider_baseline_claim,
        "producer case restores the exact finite provider grant"
    );
    Ok((
        identity,
        latencies,
        replay_order,
        peak_producers,
        provider_baseline,
        provider_final,
        admission_phases,
        producer_elapsed,
    ))
}

async fn run_concurrent_producers(group_size: usize) -> myownmesh_core::Result<()> {
    let network_id = format!("semantic-ledger-scale-concurrent-{group_size}");
    let targets: Vec<_> = (0..group_size).map(target_id).collect();
    let provider = finite_provider(scale_capacity_with_ready_batch(
        targets.len(),
        &network_id,
        targets.len(),
    ));
    let resources =
        ResourceProviderPort::new(provider.clone()).expect("concurrent scaling resource provider");
    let connector = connector_policy_for_resources(resources);
    let sequential_home = tempfile::tempdir().expect("sequential producer instance root");
    let (
        sequential_identity,
        _,
        sequential_order,
        _,
        sequential_provider_baseline,
        sequential_provider_final,
        sequential_admission_phases,
        _,
    ) = run_public_producer_case(
        sequential_home.path(),
        &network_id,
        &targets,
        false,
        &provider,
        &connector,
    )
    .await?;
    assert_eq!(
        sequential_order,
        (0..group_size).collect::<Vec<_>>(),
        "the comparison run is the explicit deterministic target order"
    );

    let concurrent_home = tempfile::tempdir().expect("concurrent producer instance root");
    let (
        concurrent_identity,
        mut latencies,
        observed_order,
        concurrent_peak_producers,
        concurrent_provider_baseline,
        concurrent_provider_final,
        concurrent_admission_phases,
        concurrent_elapsed,
    ) = run_public_producer_case(
        concurrent_home.path(),
        &network_id,
        &targets,
        true,
        &provider,
        &connector,
    )
    .await?;
    let elapsed_ms = concurrent_elapsed.as_secs_f64() * 1_000.0;
    // Independently authored facts sign the current causal parents, so a
    // concurrent authoring order is not expected to have the same FactIds or
    // commitments as a different sequential authoring order.  Exact restart
    // and cross-node replay identity are covered by the group-commit controls;
    // this workload compares the order-independent public outcomes.
    assert_eq!(
        concurrent_identity.context_id(),
        sequential_identity.context_id()
    );
    assert_eq!(
        concurrent_identity.admitted_fact_count(),
        sequential_identity.admitted_fact_count(),
        "concurrent and sequential public producers admit the same bounded fact count"
    );
    assert_eq!(
        concurrent_identity.unresolved_fact_count(),
        0,
        "concurrent public producers leave no unresolved custody"
    );
    let durable_commit_count = concurrent_admission_phases.commit_wal_terminal.count;
    let causal_journal_count = concurrent_admission_phases.causal_journal_apply.count;
    assert!(
        durable_commit_count > 0 && durable_commit_count <= group_size as u64,
        "the profiled producer run must perform a bounded nonzero number of durable commits"
    );
    assert_eq!(
        causal_journal_count, durable_commit_count,
        "each committed producer group is represented by one aggregate causal journal"
    );
    let mean_facts_per_durable_commit = group_size as f64 / durable_commit_count as f64;
    latencies.sort_unstable();
    let throughput_per_sec = if elapsed_ms > 0.0 {
        group_size as f64 * 1_000.0 / elapsed_ms
    } else {
        0.0
    };
    let metrics = ConcurrentProducerMetrics {
        selector: "semantic_ledger_scale_concurrent_producers",
        group_size,
        max_inflight_callers: concurrent_peak_producers,
        producer_count: group_size,
        admitted_count: concurrent_identity.admitted_fact_count(),
        durable_commit_count,
        causal_journal_count,
        mean_facts_per_durable_commit,
        elapsed_ms,
        throughput_per_sec,
        latency_p50_ms: percentile_ms_sorted(&latencies, 50),
        latency_p95_ms: percentile_ms_sorted(&latencies, 95),
        latency_p99_ms: percentile_ms_sorted(&latencies, 99),
        completion_order: observed_order,
        sequential_provider_baseline,
        sequential_provider_final,
        concurrent_provider_baseline,
        concurrent_provider_final,
        sequential_admission_phases,
        concurrent_admission_phases,
    };
    println!(
        "{}",
        serde_json::to_string(&metrics).expect("concurrent producer metrics serialize")
    );
    Ok(())
}

fn semantic_fact_page(
    context_id: myownmesh_core::semantic::MeshContextId,
    mut facts: Vec<SignedFact>,
) -> SemanticFactPage {
    facts.sort_by_key(|fact| fact.id);
    serde_json::from_value(serde_json::json!({
        "context_id": context_id,
        "facts": facts,
        "next_cursor": null,
        "complete": true,
    }))
    .expect("group-commit benchmark page is canonical")
}

/// Measure the production multi-fact boundary separately from local command
/// authoring. Each fact is already signed before the clock starts; the timed
/// path still performs the complete replay/context/signature/causal/resource
/// validation, one aggregate graph journal, one FULL/WAL transaction, sparse
/// projection publication, and semantic ingress reduction.
async fn run_group_commit_hotpath(group_size: usize) -> myownmesh_core::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .with_test_writer()
        .try_init();
    let home = tempfile::tempdir().expect("group-commit hotpath instance root");
    let _home_env = ScopedMeshHome::new(home.path());
    let network_id = format!("semantic-ledger-group-hotpath-{group_size}");
    let capacity = scale_capacity_with_ready_batch(group_size, &network_id, group_size);
    let (connector, provider) = connector_policy(capacity);
    let signer = Arc::new(Identity::from_signing_key(
        SigningKey::from_bytes(&[0x43; 32]),
        "semantic-scale-group-hotpath",
    ));
    let author =
        DeviceId::from_canonical_str(signer.public_id()).expect("group-commit author is canonical");
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        Arc::clone(&signer),
        connector,
    )
    .await?;
    let provider_baseline_claim = provider.in_use();
    let provider_baseline = provider_snapshot(&mesh);
    let network = mesh
        .create_network(closed_config(&network_id, group_size, capacity), [0x71; 32])
        .await?;
    let before_identity = network.semantic_state_identity()?;
    let context_id = before_identity.context_id();
    let before_count = before_identity.admitted_fact_count();
    drop(before_identity);
    let facts = (0..group_size)
        .map(|index| {
            let target = DeviceId::from_canonical_str(&target_id(index))
                .expect("group-commit target is canonical");
            SignedFact::sign(
                FactContent::new(
                    FactDomain::Governance,
                    context_id,
                    FactBody::RoleGrant {
                        target,
                        role: myownmesh_core::semantic::Role::Member,
                    },
                    author.clone(),
                    Vec::new(),
                ),
                signer.signing_key(),
            )
            .expect("group-commit fact signs")
        })
        .collect::<Vec<_>>();
    let page = semantic_fact_page(context_id, facts);
    let db_before = db_footprint(home.path());
    network.reset_semantic_admission_profile_for_lab();
    let started = Instant::now();
    let observed = network.import_semantic_fact_page(page).await?;
    let elapsed = started.elapsed();
    let admission_phases = network.semantic_admission_profile_for_lab();
    let admitted_count = observed
        .admitted_fact_count()
        .checked_sub(before_count)
        .expect("admitted group count is ordered");
    drop(observed);
    assert_eq!(
        admitted_count,
        u64::try_from(group_size).expect("group size fits u64"),
        "the timed page admits every signed fact"
    );
    let durable_commit_count = admission_phases.commit_wal_terminal.count;
    let causal_journal_count = admission_phases.causal_journal_apply.count;
    assert_eq!(
        durable_commit_count, 1,
        "one bounded page crosses one FULL/WAL commit"
    );
    assert_eq!(
        causal_journal_count, 1,
        "one bounded page uses one aggregate graph journal"
    );
    let db_after = db_footprint(home.path());
    network.shutdown().await?;
    drop(network);
    let provider_final = provider_snapshot(&mesh);
    assert_eq!(provider_final, provider_baseline);
    assert_eq!(provider.in_use(), provider_baseline_claim);
    let elapsed_ms = elapsed.as_secs_f64() * 1_000.0;
    let metrics = GroupCommitHotpathMetrics {
        selector: "semantic_ledger_scale_group_commit_hotpath",
        group_size,
        admitted_count,
        durable_commit_count,
        causal_journal_count,
        facts_per_durable_commit: group_size as f64 / durable_commit_count as f64,
        elapsed_ms,
        throughput_per_sec: if elapsed_ms > 0.0 {
            group_size as f64 * 1_000.0 / elapsed_ms
        } else {
            0.0
        },
        db_before,
        db_after,
        admission_phases,
        provider_baseline,
        provider_final,
    };
    println!(
        "{}",
        serde_json::to_string(&metrics).expect("group-commit hotpath metrics serialize")
    );
    Ok(())
}

async fn run_scale(scale: usize, selector: &'static str) -> myownmesh_core::Result<()> {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new("warn"))
        .with_test_writer()
        .try_init();
    let home = tempfile::tempdir().expect("scaling instance root");
    let _home_env = ScopedMeshHome::new(home.path());
    let network_id = format!("semantic-ledger-scale-{scale}");
    let capacity = scale_capacity(scale, &network_id);
    let identity = Arc::new(Identity::ephemeral());
    let (connector, provider) = connector_policy(capacity);
    let mesh =
        Mesh::open_connector_capable_with_identity(MeshConfig::default(), identity, connector)
            .await?;
    let provider_baseline_claim = provider.in_use();
    assert_eq!(
        provider_baseline_claim.amount(ResourceClass::StorageBytes),
        0,
        "semantic storage is not leased before network construction"
    );
    let provider_baseline = provider_snapshot(&mesh);
    let config = closed_config(&network_id, scale, capacity);
    let network = mesh.create_network(config.clone(), [0x71; 32]).await?;
    assert_eq!(
        provider.in_use().amount(ResourceClass::StorageBytes),
        provider_baseline_claim
            .amount(ResourceClass::StorageBytes)
            .checked_add(capacity.database_bytes)
            .expect("semantic storage lease delta fits u64"),
        "the Closed network leases its selected semantic database envelope"
    );
    assert_eq!(provider_snapshot(&mesh), provider_baseline);
    let selected_policy = config.semantic_policy;
    let initial_identity = network.semantic_state_identity()?;
    let initial_db = db_footprint(home.path());
    assert_footprint_within(&selected_policy, initial_db, "initial");
    let timed_admissions = if scale >= 250_000 {
        LARGE_SCALE_TIMED_ADMISSIONS.min(scale)
    } else {
        scale
    };
    let seeded_admissions = scale
        .checked_sub(timed_admissions)
        .expect("timed admissions fit selected scale");
    let fixed_target = target_id(0);
    let seed_started = Instant::now();
    if seeded_admissions > 0 {
        let seed_target = myownmesh_core::semantic::DeviceId::from_canonical_str(&fixed_target)
            .expect("fixed scale target is canonical");
        network
            .seed_semantic_scale_history_for_lab(seed_target, seeded_admissions)
            .await?;
    }
    let seed_total_ms = seed_started.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(
        network.semantic_state_identity()?.admitted_fact_count(),
        u64::try_from(seeded_admissions).expect("seed count fits u64"),
        "the bulk fixture publishes exactly the requested validated prefix"
    );
    let seeded_db = db_footprint(home.path());
    let process_rss_after_seed_bytes = process_vmrss_bytes();
    assert_footprint_within(&selected_policy, seeded_db, "seeded");
    let initial_io_bytes = process_io_bytes();
    let initial_cpu_time_ms = process_cpu_time_ms();
    network.reset_semantic_admission_profile_for_lab();
    let sample_every = (timed_admissions / 100).max(1);
    let mut peak_db = initial_db;
    peak_db.observe_peak(seeded_db);
    let workload_started = Instant::now();
    let mut progress_checkpoint_count = 0usize;
    let window_size = if timed_admissions == 0 {
        1
    } else {
        timed_admissions
            .checked_add(SCALE_WINDOW_TARGETS - 1)
            .expect("scale window arithmetic fits usize")
            / SCALE_WINDOW_TARGETS
    };
    let window_sample_stride = window_size
        .checked_add(WINDOW_SAMPLE_LIMIT - 1)
        .expect("window sample arithmetic fits usize")
        / WINDOW_SAMPLE_LIMIT;
    let mut window_start_admitted = seeded_admissions;
    let mut window_started = Instant::now();
    let mut window_admission_total_ms = 0.0;
    let mut window_max_admission_ms: f64 = 0.0;
    let mut admission_total_ms = 0.0;
    let mut window_evidence: Vec<ScaleWindowEvidence> =
        Vec::with_capacity(SCALE_WINDOW_TARGETS.min(timed_admissions.max(1)));
    let mut window_samples = Vec::with_capacity(WINDOW_SAMPLE_LIMIT.min(window_size));
    let mut bounded_samples = Vec::with_capacity(MAX_TIMING_SAMPLES.min(timed_admissions));
    let mut tail_evidence = None;
    let no_op_evidence;
    // Failure diagnostics are deliberately opt-in: normal successful scale
    // admissions must not pay a filesystem walk.  When enabled for a
    // reproduction run, retain the pre-call footprint so the error reports
    // both sides of the failed durable commit.
    let capture_failure_diagnostics =
        std::env::var_os("MYOWNMESH_SCALE_FAILURE_DIAGNOSTICS").is_some();
    assert_eq!(
        fixed_target,
        target_id(0),
        "scale workload target must remain the deterministic index-0 identity"
    );

    for index in seeded_admissions..scale {
        let measured_index = index
            .checked_sub(seeded_admissions)
            .expect("measured index follows the seeded prefix");
        // Keep the projected roster bounded while extending the canonical fact
        // history. Alternating effective roles on one subject makes each
        // proposal a distinct signed fact with the prior fact as its causal
        // head, rather than turning the scale into a roster-capacity test.
        let target = fixed_target.clone();
        let role = if index % 2 == 0 {
            myownmesh_core::semantic::Role::Member
        } else {
            myownmesh_core::semantic::Role::Owner
        };
        let pre_proposal_db = capture_failure_diagnostics.then(|| db_footprint(home.path()));
        let is_tail = index + 1 == scale;
        let tail_before = is_tail.then(|| {
            (
                network
                    .semantic_state_identity()
                    .expect("tail identity before admission"),
                db_footprint(home.path()),
                provider_snapshot(&mesh),
            )
        });
        // Start immediately at the public admission call.  Window timing is
        // deliberately independent of duplicate/no-op checks and footprint
        // or progress instrumentation below.
        let started = Instant::now();
        let _fact_id = network
            .propose_role_grant(&target, role, None)
            .await
            .map_err(|error| {
                let error_db = db_footprint(home.path());
                let pre_proposal_db = pre_proposal_db.unwrap_or(error_db);
                myownmesh_core::Error::Other(format!(
                    "semantic scale proposal index {index} fixed_target_index=0 target {target} role {role:?} failed: {error}; pre_proposal_db={pre_proposal_db:?} error_db={error_db:?} db_unchanged={}",
                    pre_proposal_db == error_db
                ))
            })?;
        let elapsed = started.elapsed();
        let admission_ms = elapsed.as_secs_f64() * 1_000.0;
        admission_total_ms += admission_ms;
        window_admission_total_ms += admission_ms;
        window_max_admission_ms = window_max_admission_ms.max(admission_ms);
        let window_position = index
            .checked_sub(window_start_admitted)
            .expect("window position is ordered");
        if window_position % window_sample_stride == 0 {
            window_samples.push(elapsed);
            bounded_samples.push(elapsed);
            assert!(
                window_samples.len() <= WINDOW_SAMPLE_LIMIT,
                "window timing samples remain within the fixed bound"
            );
            assert!(
                bounded_samples.len() <= MAX_TIMING_SAMPLES,
                "total timing samples remain within the fixed bound"
            );
        }
        if let Some((before_identity, before_db, before_provider)) = tail_before {
            let after_identity = network
                .semantic_state_identity()
                .expect("tail identity after admission");
            let after_db = db_footprint(home.path());
            let after_provider = provider_snapshot(&mesh);
            assert_eq!(
                after_identity.admitted_fact_count(),
                before_identity
                    .admitted_fact_count()
                    .checked_add(1)
                    .expect("tail admitted count fits u64"),
                "final tail admits exactly one fact"
            );
            assert_eq!(
                after_provider, before_provider,
                "one admitted tail fact does not churn connector resources"
            );
            tail_evidence = Some(TailFactEvidence {
                elapsed_ms: elapsed.as_secs_f64() * 1_000.0,
                admitted_before: before_identity.admitted_fact_count(),
                admitted_after: after_identity.admitted_fact_count(),
                db_before: before_db,
                db_after: after_db,
                provider_before: before_provider,
                provider_after: after_provider,
            });
        }
        let progress_checkpoint = measured_index % sample_every == 0 || index + 1 == scale;
        let measured_count = measured_index + 1;
        let window_checkpoint = measured_count % window_size == 0 || index + 1 == scale;
        if progress_checkpoint || window_checkpoint {
            if progress_checkpoint {
                progress_checkpoint_count = progress_checkpoint_count
                    .checked_add(1)
                    .expect("bounded progress checkpoint count");
                eprintln!(
                    "{selector}: admitted={} scale={} elapsed_ms={:.3}",
                    index + 1,
                    scale,
                    workload_started.elapsed().as_secs_f64() * 1_000.0
                );
            }
            let footprint = db_footprint(home.path());
            assert_footprint_within(&selected_policy, footprint, "admission window");
            peak_db.observe_peak(footprint);
            if window_checkpoint {
                let end_admitted = index + 1;
                let admitted_in_window = end_admitted
                    .checked_sub(window_start_admitted)
                    .expect("window admission range is ordered");
                let admission_total_ms = window_admission_total_ms;
                let average_admission_ms = admission_total_ms / admitted_in_window as f64;
                window_samples.sort_unstable();
                assert!(
                    !window_samples.is_empty(),
                    "each nonempty scale window has a deterministic timing sample"
                );
                let p50_ms = percentile_ms_sorted(&window_samples, 50);
                let p95_ms = percentile_ms_sorted(&window_samples, 95);
                let p99_ms = percentile_ms_sorted(&window_samples, 99);
                let average_slope_ms_per_admission = window_evidence.last().map(|previous| {
                    let admitted_delta = end_admitted
                        .checked_sub(previous.end_admitted)
                        .expect("window endpoints are ordered");
                    (average_admission_ms - previous.average_admission_ms) / admitted_delta as f64
                });
                window_evidence.push(ScaleWindowEvidence {
                    start_admitted: window_start_admitted + 1,
                    end_admitted,
                    admission_count: admitted_in_window,
                    admission_total_ms,
                    elapsed_ms: window_started.elapsed().as_secs_f64() * 1_000.0,
                    average_admission_ms,
                    max_admission_ms: window_max_admission_ms,
                    p50_ms,
                    p95_ms,
                    p99_ms,
                    average_slope_ms_per_admission,
                    db_main_bytes: footprint.main_bytes,
                    db_wal_bytes: footprint.wal_bytes,
                    db_shm_bytes: footprint.shm_bytes,
                    db_total_bytes: footprint.total_bytes(),
                });
                window_samples = Vec::with_capacity(WINDOW_SAMPLE_LIMIT.min(window_size));
                window_admission_total_ms = 0.0;
                window_max_admission_ms = 0.0;
                window_start_admitted = end_admitted;
                window_started = Instant::now();
            }
        }
    }
    let expected_progress_checkpoints = if timed_admissions == 0 {
        0
    } else {
        let regular = (timed_admissions - 1) / sample_every + 1;
        regular + usize::from((timed_admissions - 1) % sample_every != 0)
    };
    assert_eq!(
        progress_checkpoint_count, expected_progress_checkpoints,
        "scale progress checkpoints must cover the complete workload at the derived interval"
    );
    assert!(
        window_evidence.len() <= SCALE_WINDOW_TARGETS,
        "scale window evidence remains bounded"
    );
    if scale > 0 {
        assert_eq!(
            window_evidence.last().map(|window| window.end_admitted),
            Some(scale),
            "scale window evidence covers the complete workload"
        );
    }
    assert!(
        tail_evidence.is_some(),
        "the bounded workload records its final admitted fact"
    );
    // Snapshot the production phase profile before the deliberate duplicate
    // probe.  The probe is intentionally outside both the wall-clock timing
    // interval and this reset/profile interval, so its rejection cannot
    // masquerade as admission work.
    let admission_phases = serde_json::to_value(network.semantic_admission_profile_for_lab())
        .expect("admission phase profile serializes");
    // Keep the deliberate duplicate probe outside the timed/profiled
    // admission interval.  It remains a real no-write control, but its
    // rejection and observation work cannot contaminate admission latency.
    {
        let target = fixed_target.clone();
        let final_index = scale
            .checked_sub(1)
            .expect("the scale workload always admits at least one fact");
        let role = if final_index % 2 == 0 {
            myownmesh_core::semantic::Role::Member
        } else {
            myownmesh_core::semantic::Role::Owner
        };
        let before_identity = network
            .semantic_state_identity()
            .expect("no-op identity before duplicate");
        let before_db = db_footprint(home.path());
        let before_provider = provider_snapshot(&mesh);
        let duplicate = network
            .propose_role_grant(&target, role, None)
            .await
            .expect_err("repeating an effective grant is a semantic no-op");
        match duplicate {
            myownmesh_core::Error::Other(message) => assert!(
                message.to_ascii_lowercase().contains("no-op"),
                "duplicate grant identifies a semantic no-op: {message}"
            ),
            other => panic!("duplicate grant must be a semantic no-op: {other:?}"),
        }
        let after_identity = network.semantic_state_identity()?;
        let after_db = db_footprint(home.path());
        let after_provider = provider_snapshot(&mesh);
        assert_eq!(after_identity, before_identity);
        assert_eq!(
            after_db, before_db,
            "duplicate grant causes no durable churn"
        );
        assert_eq!(
            after_provider, before_provider,
            "duplicate grant causes no provider churn"
        );
        no_op_evidence = Some(NoOpEvidence {
            db_before: before_db,
            db_after: after_db,
            provider_before: before_provider,
            provider_after: after_provider,
        });
    }
    assert!(
        no_op_evidence.is_some(),
        "the bounded workload records a real duplicate no-op"
    );
    assert_footprint_within(&selected_policy, peak_db, "measured peak");

    let final_identity = network.semantic_state_identity()?;
    let admitted_delta = final_identity
        .admitted_fact_count()
        .checked_sub(initial_identity.admitted_fact_count())
        .expect("admitted count cannot shrink during scale workload");
    assert_eq!(
        admitted_delta,
        u64::try_from(scale).expect("scale fits u64")
    );
    assert_eq!(final_identity.unresolved_fact_count(), 0);

    // The workload reaches the configured fact ceiling exactly.  A further
    // distinct candidate must be refused before graph, durable-store, or
    // provider state changes; this is the hard N+1 boundary for each scale.
    let before_capacity_db = db_footprint(home.path());
    let before_capacity_provider = provider_snapshot(&mesh);
    let refusal = network
        .propose_role_grant(
            &target_id(scale),
            myownmesh_core::semantic::Role::Member,
            None,
        )
        .await
        .expect_err("the exact N+1 fact is refused");
    match refusal {
        myownmesh_core::Error::Other(message) => assert!(
            message.contains("RetainedFactsPerAuthor"),
            "N+1 refusal identifies the per-author retained-fact capacity: {message}"
        ),
        other => panic!("N+1 refusal must be a semantic capacity error: {other:?}"),
    }
    assert_eq!(
        network.semantic_state_identity()?,
        final_identity,
        "N+1 refusal preserves semantic identity"
    );
    assert_eq!(
        db_footprint(home.path()),
        before_capacity_db,
        "N+1 refusal preserves database/WAL/SHM/journal footprint"
    );
    assert_eq!(
        provider_snapshot(&mesh),
        before_capacity_provider,
        "N+1 refusal preserves provider accounting"
    );
    let final_io_bytes = process_io_bytes();
    let process_scope_read_bytes_delta = initial_io_bytes
        .and_then(|(before, _)| final_io_bytes.and_then(|(after, _)| after.checked_sub(before)));
    let process_write_delta = initial_io_bytes
        .and_then(|(_, before)| final_io_bytes.and_then(|(_, after)| after.checked_sub(before)));
    let process_write_per_admission = process_write_delta.map(|bytes| {
        bytes as f64
            / f64::from(u32::try_from(timed_admissions).expect("timed admissions fit f64 divisor"))
    });
    let process_scope_cpu_time_ms = initial_cpu_time_ms.and_then(|before| {
        process_cpu_time_ms().and_then(|after| {
            if before.is_finite() && after.is_finite() && after >= before {
                Some(after - before)
            } else {
                None
            }
        })
    });
    let process_rss_after_workload_bytes = process_vmrss_bytes();

    let compaction_started = Instant::now();
    network.compact_semantic_state()?;
    let compaction_ms = compaction_started.elapsed().as_secs_f64() * 1_000.0;
    let after_compaction = db_footprint(home.path());
    let process_rss_after_compaction_bytes = process_vmrss_bytes();
    assert_footprint_within(&selected_policy, after_compaction, "compaction");
    assert_eq!(
        network.semantic_state_identity()?,
        final_identity,
        "checkpoint-only compaction preserves the exact semantic identity"
    );
    let before_shutdown = after_compaction;
    network.shutdown().await?;
    assert_eq!(
        network.semantic_fact_count_for_lab(),
        0,
        "a retired state releases its in-memory ledger before same-process reopen"
    );
    drop(network);
    let restore_started = Instant::now();
    let reopened = mesh.join(config).await?;
    let startup_plus_restore_ms = restore_started.elapsed().as_secs_f64() * 1_000.0;
    assert_eq!(provider_snapshot(&mesh), provider_baseline);
    let restored_identity = reopened.semantic_state_identity()?;
    assert_eq!(restored_identity, final_identity);
    let after_restore = db_footprint(home.path());
    let process_rss_after_restore_bytes = process_vmrss_bytes();
    assert_footprint_within(&selected_policy, after_restore, "restore");
    assert_eq!(after_restore.main_bytes, before_shutdown.main_bytes);
    assert!(
        after_restore.wal_bytes <= before_shutdown.wal_bytes,
        "restore must not grow the WAL without admissions"
    );
    reopened.shutdown().await?;
    let after_shutdown = db_footprint(home.path());
    assert_footprint_within(&selected_policy, after_shutdown, "shutdown");
    let restored_unresolved = restored_identity.unresolved_fact_count();
    drop(restored_identity);
    drop(final_identity);
    drop(initial_identity);
    drop(reopened);
    let provider_final = provider_snapshot(&mesh);
    assert_eq!(provider_final, provider_baseline);
    assert_eq!(
        provider.in_use(),
        provider_baseline_claim,
        "final shutdown releases the exact semantic storage lease"
    );
    bounded_samples.sort_unstable();
    let admission_p50_ms = percentile_ms_sorted(&bounded_samples, 50);
    let admission_p95_ms = percentile_ms_sorted(&bounded_samples, 95);
    let admission_p99_ms = percentile_ms_sorted(&bounded_samples, 99);
    let admissions_per_sec = if admission_total_ms > 0.0 {
        timed_admissions as f64 * 1_000.0 / admission_total_ms
    } else {
        0.0
    };
    let early_window_average_ms_per_admission = window_evidence
        .first()
        .map(|window| window.average_admission_ms);
    let late_window_average_ms_per_admission = window_evidence
        .last()
        .map(|window| window.average_admission_ms);
    let early_late_normalized_slope_ms_per_admission =
        match (window_evidence.first(), window_evidence.last()) {
            (Some(early), Some(late)) => {
                let admitted_delta = late
                    .end_admitted
                    .checked_sub(early.start_admitted)
                    .expect("early and late window endpoints are ordered");
                (admitted_delta > 0).then(|| {
                    (late.average_admission_ms - early.average_admission_ms) / admitted_delta as f64
                })
            }
            _ => None,
        };
    let metrics = ScaleMetrics {
        selector,
        root: home.path().display().to_string(),
        platform: platform(),
        scale_n: scale,
        admitted_delta,
        seeded_admissions,
        timed_admissions,
        seed_total_ms,
        unresolved: restored_unresolved,
        admission_total_ms,
        admission_end_to_end_total_ms: admission_total_ms,
        admissions_per_sec,
        admission_p50_ms,
        admission_p95_ms,
        admission_p99_ms,
        early_window_average_ms_per_admission,
        late_window_average_ms_per_admission,
        early_late_normalized_slope_ms_per_admission,
        tail_fact: tail_evidence,
        no_op: no_op_evidence,
        progress_checkpoint_count,
        progress_sample_interval: sample_every,
        window_admission_target: window_size,
        window_sample_limit: WINDOW_SAMPLE_LIMIT,
        window_evidence,
        db_main_bytes_peak: peak_db.main_bytes,
        db_wal_bytes_peak: peak_db.wal_bytes,
        db_shm_bytes_peak: peak_db.shm_bytes,
        db_journal_bytes_peak: peak_db.journal_bytes,
        db_total_bytes_peak: peak_db.total_bytes(),
        wal_hard_frame_limit: capacity.storage_envelope.wal_frames,
        wal_hard_byte_limit: capacity.storage_envelope.wal_bytes,
        wal_checkpoint_threshold_bytes: selected_policy.wal_checkpoint_threshold_bytes,
        compaction_ms,
        db_main_bytes_after_compaction: after_compaction.main_bytes,
        db_wal_bytes_after_compaction: after_compaction.wal_bytes,
        db_shm_bytes_after_compaction: after_compaction.shm_bytes,
        db_total_bytes_after: after_shutdown.total_bytes(),
        startup_plus_restore_ms,
        cache_state: "mixed_process_cache_no_flush",
        process_scope_cpu_time_ms,
        process_scope_read_bytes_delta,
        process_lifetime_peak_vmhwm_bytes: process_vmhwm_bytes(),
        process_rss_after_seed_bytes,
        process_rss_after_workload_bytes,
        process_rss_after_compaction_bytes,
        process_rss_after_restore_bytes,
        process_scope_write_bytes_delta: process_write_delta,
        process_scope_write_bytes_per_admission: process_write_per_admission,
        admission_phases,
        provider_baseline,
        provider_final,
    };
    println!(
        "{}",
        serde_json::to_string(&metrics).expect("scale metrics serialize")
    );
    Ok(())
}

async fn export_is_empty(network: &myownmesh_core::JoinedNetwork) -> myownmesh_core::Result<()> {
    let identity = network.semantic_state_identity()?;
    let page = network.export_semantic_fact_page(SemanticFactPageRequest {
        context_id: identity.context_id(),
        cursor: None,
        max_facts: 64,
        max_encoded_bytes: myownmesh_core::protocol::relay::CLOSED_RELAY_WEBRTC_CALLBACK_BYTES
            as u32,
    })?;
    assert!(page.is_complete());
    assert!(page.facts().is_empty(), "Open presence cannot create facts");
    Ok(())
}

async fn run_open_presence_zero() -> myownmesh_core::Result<()> {
    let home = tempfile::tempdir().expect("Open scaling instance root");
    let _home_env = ScopedMeshHome::new(home.path());
    let capacity = scale_capacity(5, "semantic-ledger-scale-open");
    let (connector, provider) = connector_policy(capacity);
    let mesh = Mesh::open_connector_capable_with_identity(
        MeshConfig::default(),
        Arc::new(Identity::ephemeral()),
        connector,
    )
    .await?;
    let provider_baseline_claim = provider.in_use();
    let provider_baseline = provider_snapshot(&mesh);
    let config = open_config("semantic-ledger-scale-open");
    let mut network = Some(mesh.join(config.clone()).await?);
    let baseline_identity = network
        .as_ref()
        .expect("Open network exists before the first cycle")
        .semantic_state_identity()?;
    export_is_empty(
        network
            .as_ref()
            .expect("Open network exists before the first export"),
    )
    .await?;
    let baseline_db = db_footprint(home.path());

    for cycle in 0..5 {
        let current = network
            .as_ref()
            .expect("Open network is restored at every cycle entry");
        current.reconnect(None);
        current.announce_leave().await;
        assert_eq!(provider_snapshot(&mesh), provider_baseline);
        assert_eq!(current.semantic_state_identity()?, baseline_identity);
        export_is_empty(current).await?;
        assert_eq!(
            db_footprint(home.path()),
            baseline_db,
            "Open presence byte delta"
        );
        current.shutdown().await?;
        drop(
            network
                .take()
                .expect("the completed cycle owns its network"),
        );
        if cycle != 4 {
            network = Some(mesh.join(config.clone()).await?);
            let current = network
                .as_ref()
                .expect("Open network is restored before restart checks");
            assert_eq!(provider_snapshot(&mesh), provider_baseline);
            assert_eq!(current.semantic_state_identity()?, baseline_identity);
            export_is_empty(current).await?;
            assert_eq!(
                db_footprint(home.path()),
                baseline_db,
                "Open restart byte delta"
            );
        }
    }
    assert!(
        network.is_none(),
        "the fifth cycle leaves no joined network owner"
    );
    let db_final = db_footprint(home.path());
    let provider_final = provider_snapshot(&mesh);
    assert_eq!(db_final, baseline_db, "Open final shutdown byte delta");
    assert_eq!(provider_final, provider_baseline);
    assert_eq!(
        provider.in_use(),
        provider_baseline_claim,
        "Open final shutdown preserves the exact provider baseline"
    );
    let metrics = OpenMetrics {
        selector: "semantic_ledger_scale_open_presence_zero",
        root: home.path().display().to_string(),
        platform: platform(),
        cycles: 5,
        db_baseline: baseline_db,
        db_final,
        provider_baseline,
        provider_final,
    };
    println!(
        "{}",
        serde_json::to_string(&metrics).expect("Open metrics serialize")
    );
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_1k() -> myownmesh_core::Result<()> {
    run_scale(1_000, "semantic_ledger_scale_n_1k").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_10k() -> myownmesh_core::Result<()> {
    run_scale(10_000, "semantic_ledger_scale_n_10k").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_100k() -> myownmesh_core::Result<()> {
    run_scale(100_000, "semantic_ledger_scale_n_100k").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_250k() -> myownmesh_core::Result<()> {
    run_scale(250_000, "semantic_ledger_scale_n_250k").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_500k() -> myownmesh_core::Result<()> {
    run_scale(500_000, "semantic_ledger_scale_n_500k").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_n_1m() -> myownmesh_core::Result<()> {
    run_scale(1_000_000, "semantic_ledger_scale_n_1m").await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected concurrent producer evidence; set MYOWNMESH_SCALE_CONCURRENT_GROUP"]
async fn semantic_ledger_scale_concurrent_producers() -> myownmesh_core::Result<()> {
    let Some(group_size) = selected_concurrent_group()? else {
        eprintln!(
            "semantic_ledger_scale_concurrent_producers: selector is unset; no production batch default"
        );
        return Ok(());
    };
    run_concurrent_producers(group_size).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected group-commit evidence; set MYOWNMESH_SCALE_CONCURRENT_GROUP"]
async fn semantic_ledger_scale_group_commit_hotpath() -> myownmesh_core::Result<()> {
    let Some(group_size) = selected_concurrent_group()? else {
        eprintln!(
            "semantic_ledger_scale_group_commit_hotpath: selector is unset; no production batch default"
        );
        return Ok(());
    };
    run_group_commit_hotpath(group_size).await
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "operator-selected scaling evidence"]
async fn semantic_ledger_scale_open_presence_zero() -> myownmesh_core::Result<()> {
    run_open_presence_zero().await
}
