use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::config::NetworkConfig;
use crate::error::{Error, Result};
use crate::identity::Identity;
use crate::protocol::{FactPageMessage, MeshMessage};
use crate::resource::{LocalApplicationResourceScope, MeshRuntimeResourceScope};
use crate::semantic::{
    BootstrapRecord, ClosedProfileId, ExpectedMeshContext, FactId, MeshContextId, SignedFact,
    VerifiedBootstrap, VerifiedProjectPolicy,
};
use crate::transport::Transport;
use serde::ser::{Serialize, SerializeSeq, SerializeStruct, Serializer};
use sha2::{Digest, Sha256};

use super::state::NetworkState;

#[cfg(feature = "transport-lab")]
use crate::resource::ProcessResourceRoot;

/// Spawn the engine for a single joined network. Returns the
/// shared [`NetworkState`] handle plus the join handle of the
/// driver task (waitable for clean shutdown).
#[cfg(feature = "transport-lab")]
pub(crate) async fn spawn_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    spawn_network_impl(config, identity, transport).await
}

#[cfg(feature = "transport-lab")]
async fn spawn_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, None)?;
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Create and durably install the local Closed bootstrap before exposing an
/// engine for it. The creation id is caller-owned semantic input; the local
/// signing key is the only authority root accepted by this profile.
#[cfg(feature = "transport-lab")]
pub(crate) async fn create_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    create_network_impl(config, identity, transport, creation_id).await
}

#[cfg(feature = "transport-lab")]
async fn create_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, None, creation_id)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, None, bootstrap).await
}

/// Transport-lab variant of [`create_network`] with instance-owned bootstrap
/// persistence. The record is verified and durably installed before the
/// engine becomes observable, so a second node can import the exact same
/// semantic context into a distinct root.
#[cfg(feature = "transport-lab")]
pub(crate) async fn create_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: PathBuf,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, Some(root.as_path()), creation_id)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, Some(root), bootstrap).await
}

/// Import and durably install a caller-provided bootstrap only after it has
/// matched the locally expected semantic context. The expected context id is
/// an import constraint, never a replacement for record verification.
#[cfg(feature = "transport-lab")]
pub(crate) async fn import_network(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    import_network_impl(config, identity, transport, expected_context_id, record).await
}

#[cfg(feature = "transport-lab")]
async fn import_network_impl(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = import_local_bootstrap(&config, None, expected_context_id, record)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, None, bootstrap).await
}

/// Transport-lab variant of [`import_network`] that verifies and persists the
/// supplied record below one explicit instance root before exposing the
/// imported engine.
#[cfg(feature = "transport-lab")]
pub(crate) async fn import_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: PathBuf,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap =
        import_local_bootstrap(&config, Some(root.as_path()), expected_context_id, record)?;
    spawn_network_with_verified_bootstrap(config, identity, transport, Some(root), bootstrap).await
}

/// Spawn a transport-lab node with instance-owned on-disk projections.
///
/// The supplied root is local custody only: the config's wire-level
/// `network_id` is preserved exactly. The root is passed through a private
/// constructor seam, which derives the normal `states/` and `rosters/`
/// layouts. Ordinary production callers continue through [`spawn_network`]
/// and retain the default root.
#[cfg(feature = "transport-lab")]
pub(crate) async fn spawn_network_in_instance_root(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    root: std::path::PathBuf,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, Some(root.as_path()))?;
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        Some(root),
    )
    .await
}

pub(crate) async fn spawn_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = bootstrap_for_spawn(&config, None)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Create a Closed network below the already-issued Mesh scopes.
///
/// This is the handle facade's only creation seam. Keeping bootstrap
/// verification and driver construction below the caller's exact scopes means
/// creation cannot silently install a second process authority owner.
pub(crate) async fn create_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    creation_id: [u8; 32],
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = create_local_bootstrap(&config, &identity, None, creation_id)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

/// Import a Closed network below the already-issued Mesh scopes.
///
/// The expected context is an import constraint; the persisted record remains
/// the authority-bearing input and is verified before the driver is exposed.
pub(crate) async fn import_network_in_mesh_scope(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let bootstrap = import_local_bootstrap(&config, None, expected_context_id, record)?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        mesh_scope,
        local_resources,
        bootstrap,
        None,
    )
    .await
}

#[cfg(feature = "transport-lab")]
async fn spawn_network_with_verified_bootstrap(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    instance_root: Option<PathBuf>,
    bootstrap: VerifiedBootstrap,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let mesh_scope = ProcessResourceRoot::global().mesh_runtime_scope();
    let local_resources = ProcessResourceRoot::global().issue_local_application_scope()?;
    spawn_network_in_mesh_scope_with_verified_bootstrap(
        config,
        identity,
        transport,
        &mesh_scope,
        &local_resources,
        bootstrap,
        instance_root,
    )
    .await
}

async fn spawn_network_in_mesh_scope_with_verified_bootstrap(
    config: NetworkConfig,
    identity: Arc<Identity>,
    transport: Transport,
    mesh_scope: &MeshRuntimeResourceScope,
    local_resources: &LocalApplicationResourceScope,
    bootstrap: VerifiedBootstrap,
    instance_root: Option<std::path::PathBuf>,
) -> Result<(Arc<NetworkState>, tokio::task::JoinHandle<()>)> {
    let mesh_scope = mesh_scope.clone();
    let local_resources = local_resources.clone();
    let (state, signaling_inbound_rx, cmd_rx) = tokio::task::spawn_blocking(move || {
        NetworkState::new_in_mesh_scope_with_instance_root(
            config,
            identity,
            transport,
            bootstrap,
            &mesh_scope,
            &local_resources,
            instance_root,
        )
    })
    .await
    .map_err(|error| Error::Network(format!("semantic startup worker failed: {error}")))??;
    let driver_state = state.clone();
    let handle = tokio::spawn(async move {
        super::run_driver(driver_state, signaling_inbound_rx, cmd_rx).await;
    });
    Ok((state, handle))
}

/// Ingest one authenticated canonical fact through the production semantic
/// reducer. Carrier/session identity is deliberately absent: the signed fact
/// supplies its own authority and the reducer supplies durable admission,
/// quarantine custody, projection, and broadcast ordering.
pub(crate) async fn ingest_semantic_fact(state: &Arc<NetworkState>, fact: SignedFact) {
    let Ok(exchange) = super::semantic_ingress::DurableSemanticPort::admit(MeshMessage::Fact(fact))
    else {
        return;
    };
    super::semantic_ingress::reduce(state, exchange, None).await;
}

async fn reduce_verified_facts(
    state: &Arc<NetworkState>,
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    next_cursor: Option<FactId>,
    complete: bool,
) -> Result<()> {
    let page = FactPageMessage::new(context_id, facts, next_cursor, complete)
        .map_err(|error| Error::Other(format!("signed fact page refused: {error}")))?;
    let exchange = super::semantic_ingress::DurableSemanticPort::admit(MeshMessage::FactPage(page))
        .map_err(|_| Error::Other("signed fact page was not a durable exchange".into()))?;
    super::semantic_ingress::reduce(state, exchange, None).await;
    Ok(())
}

#[derive(serde::Serialize)]
struct SemanticFactPageOwnedWire<'a> {
    context_id: crate::semantic::MeshContextId,
    facts: &'a [SignedFact],
    next_cursor: Option<crate::semantic::FactId>,
    complete: bool,
}

#[derive(serde::Serialize)]
struct SemanticPageMetadataWire {
    context_id: crate::semantic::MeshContextId,
    facts: EmptyFacts,
    next_cursor: Option<crate::semantic::FactId>,
    complete: bool,
}

#[derive(serde::Serialize)]
struct SemanticStateIdentityWire {
    context_id: crate::semantic::MeshContextId,
    admitted_fact_count: u64,
    unresolved_fact_count: u64,
    projection_commitment: [u8; 32],
    state_commitment: [u8; 32],
}

struct EmptyFacts;

impl Serialize for EmptyFacts {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_seq(Some(0))?.end()
    }
}

struct FactIdsWire<'a> {
    facts: &'a [SignedFact],
}

impl Serialize for FactIdsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.facts.len()))?;
        for fact in self.facts {
            sequence.serialize_element(&fact.id)?;
        }
        sequence.end()
    }
}

struct SelectedFacts<'a> {
    facts: &'a [SignedFact],
}

impl Serialize for SelectedFacts<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut sequence = serializer.serialize_seq(Some(self.facts.len()))?;
        for fact in self.facts {
            sequence.serialize_element(fact)?;
        }
        sequence.end()
    }
}

struct SelectedPageWire<'a> {
    facts: &'a [SignedFact],
    context_id: crate::semantic::MeshContextId,
    next_cursor: Option<crate::semantic::FactId>,
    complete: bool,
}

struct RecentFactsWire<'a> {
    context_id: crate::semantic::MeshContextId,
    total_admitted_fact_count: u64,
    cached_fact_count: u64,
    facts: &'a [&'a SignedFact],
}

impl Serialize for RecentFactsWire<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SemanticRecentFacts", 4)?;
        state.serialize_field("context_id", &self.context_id)?;
        state.serialize_field("total_admitted_fact_count", &self.total_admitted_fact_count)?;
        state.serialize_field("cached_fact_count", &self.cached_fact_count)?;
        state.serialize_field("facts", &self.facts)?;
        state.end()
    }
}

impl Serialize for SelectedPageWire<'_> {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("SemanticFactPage", 4)?;
        state.serialize_field("context_id", &self.context_id)?;
        state.serialize_field("facts", &SelectedFacts { facts: self.facts })?;
        state.serialize_field("next_cursor", &self.next_cursor)?;
        state.serialize_field("complete", &self.complete)?;
        state.end()
    }
}

fn serialized_len(value: &impl Serialize) -> Result<usize> {
    let mut writer = JsonLengthWriter(0);
    serde_json::to_writer(&mut writer, value)
        .map_err(|error| Error::Other(format!("semantic page measurement failed: {error}")))?;
    Ok(writer.0)
}

struct JsonLengthWriter(usize);

impl std::io::Write for JsonLengthWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0 = self
            .0
            .checked_add(bytes.len())
            .ok_or_else(|| std::io::Error::other("JSON length overflow"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Export one provider-funded page of canonical facts.  Selection and exact
/// wire measurement borrow the graph; signed bodies are cloned only after the
/// page's full retained/queued claim has been acquired.
pub(crate) fn export_semantic_fact_page(
    state: &Arc<NetworkState>,
    request: crate::semantic::SemanticFactPageRequest,
) -> Result<crate::semantic::SemanticFactPage> {
    let max_facts = checked_page_limit(request.max_facts, "max_facts")?;
    let max_encoded_bytes = checked_page_limit(request.max_encoded_bytes, "max_encoded_bytes")?;
    if request.context_id != state.mesh_context_id() {
        return Err(Error::Other(format!(
            "semantic page belongs to foreign mesh context {}",
            request.context_id
        )));
    }
    let cursor = request.cursor;
    let fetch_limit = max_facts
        .checked_add(1)
        .ok_or_else(|| Error::Other("semantic page limit overflow".into()))?;
    let admitted_ids = state.admitted_semantic_fact_ids_after(cursor, fetch_limit)?;
    let admitted_rows = state.admitted_semantic_facts(admitted_ids.clone())?;
    let admitted = admitted_ids
        .iter()
        .copied()
        .zip(admitted_rows)
        .map(|(id, fact)| {
            fact.map(|fact| (id, fact)).ok_or_else(|| {
                Error::Other(format!(
                    "admitted semantic fact {id} disappeared during paging"
                ))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let quarantined = state
        .authoritative_fact_graph()
        .read()
        .quarantined()
        .filter(move |(id, _)| cursor.is_none_or(|cursor| **id > cursor))
        .take(fetch_limit)
        .map(|(id, fact)| (*id, fact.clone()))
        .collect::<Vec<_>>();
    let mut admitted_index = 0usize;
    let mut quarantined_index = 0usize;
    let mut facts = Vec::with_capacity(max_facts);
    let mut fact_bytes = 0usize;
    let mut next_cursor = None;
    let mut stopped_for_bytes = false;

    while facts.len() < max_facts {
        let next_admitted = admitted.get(admitted_index);
        let next_quarantined = quarantined.get(quarantined_index);
        let (id, fact, from_admitted) = match (next_admitted, next_quarantined) {
            (None, None) => break,
            (Some((id, fact)), None) => (*id, fact, true),
            (None, Some((id, fact))) => (*id, fact, false),
            (Some((admitted_id, admitted_fact)), Some((quarantined_id, quarantined_fact))) => {
                if admitted_id < quarantined_id {
                    (*admitted_id, admitted_fact, true)
                } else {
                    (*quarantined_id, quarantined_fact, false)
                }
            }
        };
        if next_cursor == Some(id) {
            return Err(Error::Other("duplicate semantic page id".into()));
        }
        let one_fact_bytes = serialized_len(fact)?;
        let candidate_fact_bytes = fact_bytes
            .checked_add(one_fact_bytes)
            .and_then(|bytes| bytes.checked_add(usize::from(!facts.is_empty())))
            .ok_or_else(|| Error::Other("semantic page length overflow".into()))?;
        let metadata_bytes = serialized_len(&SemanticPageMetadataWire {
            context_id: request.context_id,
            next_cursor: Some(id),
            complete: false,
            facts: EmptyFacts,
        })?;
        let encoded = metadata_bytes
            .checked_add(candidate_fact_bytes)
            .ok_or_else(|| Error::Other("semantic page length overflow".into()))?;
        if encoded > max_encoded_bytes {
            stopped_for_bytes = true;
            break;
        }
        facts.push(fact.clone());
        fact_bytes = candidate_fact_bytes;
        next_cursor = Some(id);
        if from_admitted {
            admitted_index += 1;
        } else {
            quarantined_index += 1;
        }
    }

    let has_loaded_remainder =
        admitted_index < admitted.len() || quarantined_index < quarantined.len();
    if facts.is_empty() && (has_loaded_remainder || stopped_for_bytes) {
        return Err(Error::Other(
            "first semantic fact does not fit the requested page bound".into(),
        ));
    }
    let complete = !stopped_for_bytes
        && !has_loaded_remainder
        && admitted_ids.len() < fetch_limit
        && quarantined.len() < fetch_limit;
    if complete {
        next_cursor = None;
    }
    let metadata_bytes = serialized_len(&SemanticPageMetadataWire {
        context_id: request.context_id,
        next_cursor,
        complete,
        facts: EmptyFacts,
    })?;
    let encoded = metadata_bytes
        .checked_add(fact_bytes)
        .and_then(|bytes| bytes.checked_add(facts.len().saturating_sub(1)))
        .ok_or_else(|| Error::Other("semantic page length overflow".into()))?;
    if encoded > max_encoded_bytes {
        return Err(Error::Other(
            "semantic page metadata does not fit the requested bound".into(),
        ));
    }

    let wire = SelectedPageWire {
        facts: &facts,
        context_id: request.context_id,
        next_cursor,
        complete,
    };
    let measurement = crate::resource::measure_serialized_mailbox_item::<
        crate::semantic::SemanticFactPage,
    >(&wire)
    .map_err(|error| Error::Other(format!("semantic page measurement refused: {error}")))?;
    let claim = measurement.into_claim();
    let scope = state
        .local_application_resource_scope()
        .map_err(|error| Error::Other(format!("semantic page resource scope refused: {error}")))?;
    let funding = scope
        .acquire(claim)
        .map_err(|error| Error::Other(format!("semantic page admission refused: {error}")))?;
    Ok(crate::semantic::SemanticFactPage::new(
        request.context_id,
        facts,
        next_cursor,
        complete,
        funding,
    ))
}

/// Materialize a bounded, human-readable view of the newest facts already in
/// the machine-governed hot-history cache. This never reads the cold ledger,
/// creates a mirror database, or feeds the result back into admission.
pub(crate) fn recent_semantic_facts(
    state: &Arc<NetworkState>,
    request: crate::semantic::SemanticRecentFactsRequest,
) -> Result<crate::semantic::SemanticRecentFacts> {
    let max_facts = checked_page_limit(request.max_facts, "max_facts")?;
    let max_encoded_bytes = checked_page_limit(request.max_encoded_bytes, "max_encoded_bytes")?;
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    let total_admitted_fact_count = graph.admitted_fact_count();
    let cached_fact_count = u64::try_from(graph.hot_fact_count())
        .map_err(|_| Error::Other("semantic hot-history count is not representable".into()))?;
    let context_id = state.mesh_context_id();
    let empty: [&SignedFact; 0] = [];
    let metadata_bytes = serialized_len(&RecentFactsWire {
        context_id,
        total_admitted_fact_count,
        cached_fact_count,
        facts: &empty,
    })?;
    if metadata_bytes > max_encoded_bytes {
        return Err(Error::Other(
            "semantic recent-facts metadata does not fit the requested bound".into(),
        ));
    }

    // Grow only as facts actually fit the requested encoded-byte ceiling. A
    // very large count bound must not itself reserve a large pointer array.
    let mut facts = Vec::new();
    let mut fact_bytes = 0usize;
    for fact in graph.hot_facts_in_admission_order().rev().take(max_facts) {
        let one_fact_bytes = serialized_len(fact)?;
        let candidate_fact_bytes = fact_bytes
            .checked_add(one_fact_bytes)
            .and_then(|bytes| bytes.checked_add(usize::from(!facts.is_empty())))
            .ok_or_else(|| Error::Other("semantic recent-facts length overflow".into()))?;
        if metadata_bytes
            .checked_add(candidate_fact_bytes)
            .is_none_or(|bytes| bytes > max_encoded_bytes)
        {
            break;
        }
        facts.push(fact);
        fact_bytes = candidate_fact_bytes;
    }
    if facts.is_empty() && cached_fact_count != 0 {
        return Err(Error::Other(
            "newest semantic fact does not fit the requested bound".into(),
        ));
    }
    facts.reverse();

    let wire = RecentFactsWire {
        context_id,
        total_admitted_fact_count,
        cached_fact_count,
        facts: &facts,
    };
    let measurement = crate::resource::measure_serialized_mailbox_item::<
        crate::semantic::SemanticRecentFacts,
    >(&wire)
    .map_err(|error| {
        Error::Other(format!(
            "semantic recent-facts measurement refused: {error}"
        ))
    })?;
    let claim = measurement.into_claim();
    let scope = state
        .local_application_resource_scope()
        .map_err(|error| Error::Other(format!("semantic recent-facts scope refused: {error}")))?;
    let funding = scope.acquire(claim).map_err(|error| {
        Error::Other(format!("semantic recent-facts admission refused: {error}"))
    })?;
    let facts = facts.into_iter().cloned().collect();
    Ok(crate::semantic::SemanticRecentFacts::new(
        context_id,
        total_admitted_fact_count,
        cached_fact_count,
        facts,
        funding,
    ))
}

fn checked_page_limit(value: u32, name: &str) -> Result<usize> {
    let value = usize::try_from(value)
        .map_err(|_| Error::Other(format!("semantic page {name} is not representable")))?;
    if value == 0 || value > crate::protocol::RECEIVE_FRAME_BYTES {
        return Err(Error::Other(format!(
            "semantic page {name} must be between 1 and {}",
            crate::protocol::RECEIVE_FRAME_BYTES
        )));
    }
    Ok(value)
}

/// Import one bounded canonical page through the same durable reducer used by
/// authenticated wire delivery.  The page's provider lease remains held
/// through preflight, reduction, and exact retention checks.
pub(crate) async fn import_semantic_fact_page(
    state: &Arc<NetworkState>,
    page: crate::semantic::SemanticFactPage,
) -> Result<crate::semantic::SemanticStateIdentity> {
    if page.facts().is_empty() {
        return Err(Error::Other("signed fact import cannot be empty".into()));
    }
    if page.facts().len() > crate::protocol::RECEIVE_FRAME_BYTES {
        return Err(Error::Other(
            "signed fact page exceeds protocol fact bound".into(),
        ));
    }
    if page.context_id() != state.mesh_context_id() {
        return Err(Error::Other(format!(
            "signed fact page belongs to foreign mesh context {}",
            page.context_id()
        )));
    }
    let wire = SemanticFactPageOwnedWire {
        context_id: page.context_id(),
        facts: page.facts(),
        next_cursor: page.next_cursor(),
        complete: page.is_complete(),
    };
    let encoded = crate::resource::mailbox_measure_serialized(&wire)
        .map_err(|error| Error::Other(format!("semantic page measurement failed: {error}")))?
        .1;
    if encoded > crate::protocol::RECEIVE_FRAME_BYTES {
        return Err(Error::Other(
            "signed fact page exceeds protocol byte bound".into(),
        ));
    }
    let page_measurement = crate::resource::measure_serialized_mailbox_item::<
        crate::semantic::SemanticFactPage,
    >(&wire)
    .map_err(|error| Error::Other(format!("semantic page measurement refused: {error}")))?;
    for fact in page.facts() {
        if fact.content.mesh_context != page.context_id() {
            return Err(Error::Other(format!(
                "signed fact {} belongs to a foreign mesh context",
                fact.id
            )));
        }
        fact.verify()
            .map_err(|error| Error::Other(format!("signed fact {} rejected: {error}", fact.id)))?;
    }
    let ids_measurement =
        crate::resource::measure_serialized_mailbox_item::<Vec<FactId>>(&FactIdsWire {
            facts: page.facts(),
        })
        .map_err(|error| Error::Other(format!("semantic page id measurement refused: {error}")))?;
    let ids_scope = state
        .local_application_resource_scope()
        .map_err(|error| Error::Other(format!("semantic page id scope refused: {error}")))?;
    let _submitted_ids_funding = ids_scope
        .acquire(ids_measurement.into_claim())
        .map_err(|error| Error::Other(format!("semantic page id admission refused: {error}")))?;
    let submitted_facts_commitment = signed_facts_commitment(page.facts())?;
    let submitted_ids = page.facts().iter().map(|fact| fact.id).collect::<Vec<_>>();
    let (wire_page, funding) = page
        .into_fact_page_message()
        .map_err(|error| Error::Other(format!("signed fact page refused: {error}")))?;
    let FactPageMessage {
        context_id: page_context_id,
        facts,
        next_cursor,
        complete,
    } = wire_page;
    let _funding = match funding {
        Some(funding) => funding,
        None => {
            let scope = state.local_application_resource_scope().map_err(|error| {
                Error::Other(format!("semantic page resource scope refused: {error}"))
            })?;
            scope
                .acquire(page_measurement.into_claim())
                .map_err(|error| {
                    Error::Other(format!("semantic page admission refused: {error}"))
                })?
        }
    };
    reduce_verified_facts(state, page_context_id, facts, next_cursor, complete).await?;

    let mut retained = Sha256::new();
    for fact_id in &submitted_ids {
        let fact = state.admitted_semantic_fact(*fact_id)?.or_else(|| {
            state
                .authoritative_fact_graph()
                .read()
                .quarantined()
                .find(|(id, _)| **id == *fact_id)
                .map(|(_, fact)| fact.clone())
        });
        let Some(fact) = fact else {
            return Err(Error::Other(format!(
                "signed fact {fact_id} was not retained by the semantic reducer"
            )));
        };
        serde_json::to_writer(DigestWriter(&mut retained), &fact)
            .map_err(|error| Error::Other(format!("retained fact encoding failed: {error}")))?;
        retained.update([0]);
    }
    let retained_digest = retained.finalize();
    if retained_digest.as_slice() != submitted_facts_commitment.as_slice() {
        return Err(Error::Other(
            "semantic reducer changed a submitted signed fact".into(),
        ));
    }
    let graph = state.authoritative_fact_graph();
    let identity = identity_for_graph(state, &graph.read());
    identity
}

/// Return a stable identity for the live graph and its projected authority
/// state.  The state commitment covers signed bodies and signatures, while
/// the projection commitment is the exact transcript sealed by the durable
/// semantic store.
pub(crate) fn semantic_state_identity(
    state: &Arc<NetworkState>,
) -> Result<crate::semantic::SemanticStateIdentity> {
    let graph = state.authoritative_fact_graph();
    let graph = graph.read();
    identity_for_graph(state, &graph)
}

fn identity_for_graph(
    state: &Arc<NetworkState>,
    graph: &crate::semantic::FactGraph,
) -> Result<crate::semantic::SemanticStateIdentity> {
    let context_id = graph.context_id();
    let live_admitted_fact_count = u64::try_from(graph.len())
        .map_err(|_| Error::Other("semantic admitted fact count overflow".into()))?;
    let live_unresolved_fact_count = graph.quarantined().try_fold(0u64, |count, _| {
        count
            .checked_add(1)
            .ok_or_else(|| Error::Other("semantic unresolved fact count overflow".into()))
    })?;
    let (admitted_fact_count, unresolved_fact_count, state_commitment) =
        state.semantic_state_digest()?;
    if admitted_fact_count != live_admitted_fact_count
        || unresolved_fact_count != live_unresolved_fact_count
    {
        return Err(Error::Other(
            "live semantic counters do not match durable history".into(),
        ));
    }
    let wire = SemanticStateIdentityWire {
        context_id,
        admitted_fact_count,
        unresolved_fact_count,
        projection_commitment: crate::semantic::store::projection_commitment_for_graph(graph),
        state_commitment,
    };
    let measurement = crate::resource::measure_serialized_mailbox_item::<
        crate::semantic::SemanticStateIdentity,
    >(&wire)
    .map_err(|error| Error::Other(format!("semantic identity measurement refused: {error}")))?;
    let scope = state.local_application_resource_scope().map_err(|error| {
        Error::Other(format!("semantic identity resource scope refused: {error}"))
    })?;
    let funding = scope
        .acquire(measurement.into_claim())
        .map_err(|error| Error::Other(format!("semantic identity admission refused: {error}")))?;
    Ok(crate::semantic::SemanticStateIdentity::new(
        context_id,
        admitted_fact_count,
        unresolved_fact_count,
        wire.projection_commitment,
        wire.state_commitment,
        funding,
    ))
}

fn signed_facts_commitment(facts: &[SignedFact]) -> Result<[u8; 32]> {
    let mut hasher = Sha256::new();
    for fact in facts {
        serde_json::to_writer(DigestWriter(&mut hasher), fact)
            .map_err(|error| Error::Other(format!("submitted fact encoding failed: {error}")))?;
        hasher.update([0]);
    }
    let digest = hasher.finalize();
    let mut commitment = [0; 32];
    commitment.copy_from_slice(&digest);
    Ok(commitment)
}

struct DigestWriter<'a>(&'a mut Sha256);

impl std::io::Write for DigestWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn bootstrap_root(instance_root: Option<&Path>) -> Result<PathBuf> {
    match instance_root {
        Some(root) => Ok(root.to_path_buf()),
        None => Ok(crate::dirs::data_dir()?.join("mesh")),
    }
}

fn bootstrap_store(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
) -> Result<crate::semantic::store::BootstrapStore> {
    Ok(crate::semantic::store::BootstrapStore::new(
        bootstrap_root(instance_root)?,
        &config.id,
    ))
}

fn local_bootstrap_principal() -> crate::application_gateway::LocalPrincipalCapability {
    crate::application_gateway::LocalPrincipalCapability::for_local_process(
        crate::runtime::RuntimeIncarnation::new(),
    )
}

fn bootstrap_error(action: &str, error: impl std::fmt::Display) -> Error {
    Error::Other(format!("{action} bootstrap: {error}"))
}

fn ensure_bootstrap_for_config(
    config: &NetworkConfig,
    bootstrap: VerifiedBootstrap,
) -> Result<VerifiedBootstrap> {
    if bootstrap.context().scope != config.network_id {
        return Err(bootstrap_error(
            "rejecting",
            format!(
                "semantic scope {} does not match network_id {}",
                bootstrap.context().scope,
                config.network_id
            ),
        ));
    }

    let valid_shape = match config.kind {
        crate::config::NetworkKind::Closed => matches!(
            bootstrap.policy(),
            VerifiedProjectPolicy::Closed(policy)
                if policy.profile() == ClosedProfileId::SingleRootSignedMemberLogV1
        ),
        crate::config::NetworkKind::Open | crate::config::NetworkKind::Silent => {
            matches!(bootstrap.policy(), VerifiedProjectPolicy::Open)
        }
    };
    if !valid_shape {
        return Err(bootstrap_error(
            "rejecting",
            format!(
                "bootstrap policy does not match configured kind {:?}",
                config.kind
            ),
        ));
    }
    Ok(bootstrap)
}

fn bootstrap_for_spawn(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
) -> Result<VerifiedBootstrap> {
    let bootstrap = match config.kind {
        crate::config::NetworkKind::Open | crate::config::NetworkKind::Silent => {
            VerifiedBootstrap::open(config.network_id.clone())
                .map_err(|error| bootstrap_error("creating founderless", error))?
        }
        crate::config::NetworkKind::Closed => bootstrap_store(config, instance_root)?
            .restore()
            .map_err(|error| bootstrap_error("restoring Closed", error))?,
    };
    ensure_bootstrap_for_config(config, bootstrap)
}

fn create_local_bootstrap(
    config: &NetworkConfig,
    identity: &Identity,
    instance_root: Option<&Path>,
    creation_id: [u8; 32],
) -> Result<VerifiedBootstrap> {
    if config.kind != crate::config::NetworkKind::Closed {
        return Err(bootstrap_error(
            "creating",
            "explicit local creation requires Closed network kind",
        ));
    }
    let bootstrap = VerifiedBootstrap::create_closed(
        config.network_id.clone(),
        [identity.signing_key()],
        creation_id,
    )
    .map_err(|error| bootstrap_error("creating", error))?;
    let principal = local_bootstrap_principal();
    let stored = bootstrap_store(config, instance_root)?
        .persist_new(&principal, bootstrap.record())
        .map_err(|error| bootstrap_error("persisting created", error))?;
    ensure_bootstrap_for_config(config, stored)
}

fn import_local_bootstrap(
    config: &NetworkConfig,
    instance_root: Option<&Path>,
    expected_context_id: MeshContextId,
    record: BootstrapRecord,
) -> Result<VerifiedBootstrap> {
    if config.kind != crate::config::NetworkKind::Closed {
        return Err(bootstrap_error(
            "importing",
            "explicit bootstrap import requires Closed network kind",
        ));
    }
    let principal = local_bootstrap_principal();
    let expected = ExpectedMeshContext::for_local_import(&principal, expected_context_id);
    let imported = bootstrap_store(config, instance_root)?
        .import_expected(&expected, record)
        .map_err(|error| bootstrap_error("importing", error))?;
    ensure_bootstrap_for_config(config, imported)
}

#[cfg(test)]
mod semantic_page_tests {
    use super::checked_page_limit;

    #[test]
    fn page_limits_are_nonzero_and_protocol_bounded() {
        let protocol_limit = crate::protocol::RECEIVE_FRAME_BYTES as u32;
        assert!(checked_page_limit(0, "max_facts").is_err());
        assert_eq!(
            checked_page_limit(protocol_limit, "max_encoded_bytes").unwrap(),
            crate::protocol::RECEIVE_FRAME_BYTES
        );
        assert!(checked_page_limit(protocol_limit + 1, "max_facts").is_err());
    }
}
