//! Deterministic causal admission for canonical semantic facts.

#[cfg(test)]
use std::cell::Cell;
use std::collections::{BTreeMap, BTreeSet};
use std::mem::size_of;
use std::ops::Bound;
use std::sync::Arc;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

#[cfg(test)]
thread_local! {
    static RESIDENCY_SCAN_COUNT: Cell<usize> = const { Cell::new(0) };
    static INDEX_REBUILD_COUNT: Cell<usize> = const { Cell::new(0) };
    // Diagnostic-only counters for graph-work scaling probes.  These are
    // deliberately not performance gates: they expose the work performed by
    // the current implementation so a later optimization can be measured
    // against fixed signed transcripts.
    static GRAPH_WORK_COUNT: Cell<GraphWorkCounts> = Cell::new(GraphWorkCounts::default());
}

#[cfg(test)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct GraphWorkCounts {
    authority_fact_rows: usize,
    authority_uses_examined: usize,
    authority_edges_followed: usize,
    authority_branch_nodes: usize,
    aggregate_ready_entries: usize,
    aggregate_waiter_edges: usize,
    aggregate_waiter_nodes: usize,
}

#[cfg(test)]
fn reset_graph_work() {
    GRAPH_WORK_COUNT.with(|counter| counter.set(GraphWorkCounts::default()));
}

#[cfg(test)]
fn graph_work() -> GraphWorkCounts {
    GRAPH_WORK_COUNT.with(Cell::get)
}

#[cfg(test)]
fn record_graph_work(update: impl FnOnce(&mut GraphWorkCounts)) {
    GRAPH_WORK_COUNT.with(|counter| {
        let mut value = counter.get();
        update(&mut value);
        counter.set(value);
    });
}

use super::content::{DeviceId, ExclusiveCell, FactBody, Role};
#[cfg(feature = "transport-lab")]
use super::projection::ProjectionDelta;
use super::{
    FactId, MeshContextId, Projection, SemanticError, SignedFact, VerifiedBootstrap,
    VerifiedProjectPolicy,
};

/// Failure to resolve canonical proof ancestry, never an authority-negative
/// boolean that could select a partial frontier or the raw-conflict fallback.
#[derive(Debug)]
pub(crate) enum ProofAncestryError<E> {
    Invalid(&'static str),
    Read(E),
}

impl<E: std::fmt::Display> std::fmt::Display for ProofAncestryError<E> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Invalid(reason) => f.write_str(reason),
            Self::Read(error) => write!(f, "ancestry read: {error}"),
        }
    }
}

/// Owner-selected aggregate semantic admission limits.  The daemon's
/// `SemanticPolicyConfig` can be converted to this value at its boundary; the
/// graph keeps the checked snapshot so admission never consults mutable global
/// configuration.  The default exists for existing unit-test constructors and
/// is intentionally finite.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SemanticAdmissionPolicy {
    pub max_fact_encoded_bytes: u64,
    pub max_dependencies_per_fact: u64,
    pub max_authority_uses_per_fact: u64,
    pub max_authority_predecessors_per_use: u64,
    pub max_admitted_facts: u64,
    pub max_admitted_bytes: u64,
    pub max_quarantined_facts: u64,
    pub max_quarantined_bytes: u64,
    pub max_quarantined_facts_per_author: u64,
    pub max_quarantined_bytes_per_author: u64,
    pub max_retained_facts_per_author: u64,
    pub max_retained_bytes_per_author: u64,
    pub max_hot_history_facts: u64,
    pub max_dependency_edges: u64,
    pub max_ready_batch: u64,
    pub max_pending_proofs: u64,
    pub max_pending_proof_bytes: u64,
    pub max_database_bytes: u64,
    pub wal_checkpoint_threshold_bytes: u64,
    pub emergency_reserve_bytes: u64,
}

#[cfg(any(test, feature = "transport-lab"))]
impl Default for SemanticAdmissionPolicy {
    fn default() -> Self {
        Self {
            max_fact_encoded_bytes: 65_535,
            max_dependencies_per_fact: 64,
            max_authority_uses_per_fact: 32,
            max_authority_predecessors_per_use: 64,
            max_admitted_facts: 100_000,
            max_admitted_bytes: 128 * 1024 * 1024,
            max_quarantined_facts: 4_096,
            max_quarantined_bytes: 16 * 1024 * 1024,
            max_quarantined_facts_per_author: 256,
            max_quarantined_bytes_per_author: 4 * 1024 * 1024,
            max_retained_facts_per_author: 10_000,
            max_retained_bytes_per_author: 16 * 1024 * 1024,
            max_hot_history_facts: 64,
            max_dependency_edges: 1_000_000,
            max_ready_batch: 256,
            max_pending_proofs: 10_000,
            max_pending_proof_bytes: 16 * 1024 * 1024,
            max_database_bytes: 256 * 1024 * 1024,
            wal_checkpoint_threshold_bytes: 4 * 1024 * 1024,
            emergency_reserve_bytes: 8 * 1024 * 1024,
        }
    }
}

impl SemanticAdmissionPolicy {
    // Keep the existing scalar configuration boundary explicit and one-to-one;
    // regrouping these limits would change the public constructor contract.
    #[allow(clippy::too_many_arguments)]
    pub fn from_config_values(
        max_fact_encoded_bytes: u64,
        max_dependencies_per_fact: u64,
        max_authority_uses_per_fact: u64,
        max_authority_predecessors_per_use: u64,
        max_admitted_facts: u64,
        max_admitted_bytes: u64,
        max_quarantined_facts: u64,
        max_quarantined_bytes: u64,
        max_quarantined_facts_per_author: u64,
        max_quarantined_bytes_per_author: u64,
        max_retained_facts_per_author: u64,
        max_retained_bytes_per_author: u64,
        max_hot_history_facts: u64,
        max_dependency_edges: u64,
        max_ready_batch: u64,
        max_pending_proofs: u64,
        max_pending_proof_bytes: u64,
        max_database_bytes: u64,
        wal_checkpoint_threshold_bytes: u64,
        emergency_reserve_bytes: u64,
    ) -> Self {
        Self {
            max_fact_encoded_bytes,
            max_dependencies_per_fact,
            max_authority_uses_per_fact,
            max_authority_predecessors_per_use,
            max_admitted_facts,
            max_admitted_bytes,
            max_quarantined_facts,
            max_quarantined_bytes,
            max_quarantined_facts_per_author,
            max_quarantined_bytes_per_author,
            max_retained_facts_per_author,
            max_retained_bytes_per_author,
            max_hot_history_facts,
            max_dependency_edges,
            max_ready_batch,
            max_pending_proofs,
            max_pending_proof_bytes,
            max_database_bytes,
            wal_checkpoint_threshold_bytes,
            emergency_reserve_bytes,
        }
    }
}

impl From<crate::config::SemanticPolicyConfig> for SemanticAdmissionPolicy {
    fn from(config: crate::config::SemanticPolicyConfig) -> Self {
        Self::from_config_values(
            config.max_fact_encoded_bytes,
            config.max_dependencies_per_fact,
            config.max_authority_uses_per_fact,
            config.max_authority_predecessors_per_use,
            config.max_admitted_facts,
            config.max_admitted_bytes,
            config.max_quarantined_facts,
            config.max_quarantined_bytes,
            config.max_quarantined_facts_per_author,
            config.max_quarantined_bytes_per_author,
            config.max_retained_facts_per_author,
            config.max_retained_bytes_per_author,
            config.max_hot_history_facts,
            config.max_dependency_edges,
            config.max_ready_batch,
            config.max_pending_proofs,
            config.max_pending_proof_bytes,
            config.max_database_bytes,
            config.wal_checkpoint_threshold_bytes,
            config.emergency_reserve_bytes,
        )
    }
}

impl From<&crate::config::SemanticPolicyConfig> for SemanticAdmissionPolicy {
    fn from(config: &crate::config::SemanticPolicyConfig) -> Self {
        (*config).into()
    }
}

/// Return the complete canonical dependency set for one fact.  Every caller
/// that decides whether a fact is ready must use this function: parents,
/// durable evidence, attestation inputs, and explicitly cited resolution
/// heads are all causal inputs, regardless of their arrival order.
pub fn dependencies(fact: &SignedFact) -> Vec<FactId> {
    let mut dependencies = fact.content.parents.clone();
    for authority_use in &fact.content.authority_uses {
        dependencies.extend(authority_use.predecessors.iter().copied());
    }
    match &fact.content.body {
        FactBody::EvictionProof { evidence, .. } | FactBody::SelfStandDown { evidence, .. } => {
            dependencies.extend(evidence.iter().copied())
        }
        FactBody::Attestation {
            proposal,
            contributions,
            ..
        } => {
            dependencies.push(*proposal);
            dependencies.extend(contributions.iter().copied());
        }
        FactBody::Resolution { cited_heads, .. }
        | FactBody::AuthorityLineageResolution { cited_heads, .. } => {
            dependencies.extend(cited_heads.iter().copied())
        }
        _ => {}
    }
    dependencies.sort();
    dependencies.dedup();
    dependencies
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Admission {
    Inserted,
    AlreadyPresent,
    Quarantined { missing: Vec<FactId> },
}

/// The causal inputs a caller must carry when authoring a fact.
///
/// Exclusive-cell predecessors are derived from the graph rather than guessed
/// by a caller.  Evidence and other non-cell dependencies remain explicit in
/// the signed body and are added by [`dependencies`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthoringWitness {
    author: DeviceId,
    parents: Vec<FactId>,
    required_tier: Option<Role>,
}

impl AuthoringWitness {
    pub fn author(&self) -> &DeviceId {
        &self.author
    }

    pub fn parents(&self) -> &[FactId] {
        &self.parents
    }

    pub fn required_tier(&self) -> Option<Role> {
        self.required_tier
    }

    pub fn into_parents(self) -> Vec<FactId> {
        self.parents
    }
}

/// Read-only relations proved from admitted signed ancestry. All equalities
/// are inclusive; in particular a losing cited head is not post-selector.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuthoritySelectorRelation {
    selected: FactId,
    post_selector: bool,
    selected_before: bool,
    before_selected: bool,
}

type AuthorityProvenanceRow = BTreeMap<FactId, AuthoritySelectorRelation>;
type AuthorityProvenance = BTreeMap<FactId, AuthorityProvenanceRow>;

/// An arrival-order-independent set of verified canonical facts.
#[derive(Debug)]
pub struct FactGraph {
    pub(crate) facts: BTreeMap<FactId, SignedFact>,
    /// Total admitted history, including rows whose signed bodies have been
    /// retired from the live continuation set after durable publication.
    /// SQLite remains the canonical owner of those cold rows.
    admitted_fact_count: u64,
    /// Canonical admission order. Durable snapshots persist this as `seq`,
    /// allowing restart to rebuild in one streaming pass without allocating a
    /// second graph-sized topological sort.
    pub(crate) admission_order: Vec<FactId>,
    pub(crate) quarantined: BTreeMap<FactId, SignedFact>,
    policy_limits: SemanticAdmissionPolicy,
    admitted_bytes: u64,
    /// Owner-funded residency for the derived causal/projection indexes.  It
    /// is charged against the same checked database envelope as durable facts
    /// so an index can never outlive the policy that funded its source fact.
    derived_index_bytes: u64,
    quarantined_bytes: u64,
    admitted_dependency_edges: u64,
    quarantined_dependency_edges: u64,
    quarantined_by_author: BTreeMap<DeviceId, (u64, u64)>,
    retained_by_author: BTreeMap<DeviceId, (u64, u64)>,
    quarantine_missing: BTreeMap<FactId, BTreeSet<FactId>>,
    waiting_by_dependency: BTreeMap<FactId, BTreeSet<FactId>>,
    ready_quarantine: BTreeSet<FactId>,
    context_id: MeshContextId,
    authority_roots: BTreeSet<DeviceId>,
    policy: VerifiedProjectPolicy,
    /// Incremental indexes for the admitted graph.  These are derived state:
    /// durable facts remain the sole authority and the indexes are rebuilt on
    /// restore or whenever an external loader has populated `facts` directly.
    cell_heads_index: BTreeMap<ExclusiveCell, BTreeSet<FactId>>,
    authority_heads_index: BTreeMap<DeviceId, BTreeSet<FactId>>,
    /// Reverse authority-witness edges.  A key is scoped by subject so an
    /// identical fact ID carried in two independent AuthorityUse relations
    /// cannot cross-invalidate the other subject's cells.  Values are the
    /// authority-bearing facts that directly cite that predecessor; walking
    /// this index reaches only the branch whose authority validity changed.
    /// Test-only mirror used to assert the on-demand predecessor traversal.
    /// Production retains only the compact subject index below and derives
    /// predecessor edges for one resolution when needed.
    #[cfg(test)]
    authority_dependents_index: BTreeMap<(DeviceId, FactId), BTreeSet<FactId>>,
    /// Subject-scoped authority-use rows.  Unlike the test-only predecessor
    /// reverse mirror above, this compact index is retained in production so
    /// a rare resolution does not prewalk unrelated hot facts.
    authority_facts_index: BTreeMap<DeviceId, BTreeSet<FactId>>,
    authority_selector_index: BTreeMap<DeviceId, BTreeSet<(FactId, FactId)>>,
    /// Sparse per-retained-row selector reachability, derived while canonical
    /// ancestry is available. Selector and selected IDs name retained signed
    /// witnesses; no arbitrary ancestor of a current head confers authority.
    authority_provenance: AuthorityProvenance,
    /// Test-only mirror of dependencies already present in each signed fact.
    /// Retaining a second graph-sized copy in production wastes memory.
    #[cfg(test)]
    dependency_index: BTreeMap<FactId, Vec<FactId>>,
    cells_index: BTreeSet<ExclusiveCell>,
    stand_down_index: BTreeMap<DeviceId, BTreeSet<FactId>>,
    indexed_fact_count: usize,
    facts_revision: u64,
    indexed_revision: u64,
    /// Local in-process projection/index revision. It is deliberately not
    /// the durable semantic write revision (`semantic_usage.generation`):
    /// restore starts this counter from the fresh graph's zero and validates
    /// identity through facts, canonical dependencies, and the v2 root
    /// instead of comparing counters across process lifetimes.
    generation: u64,
    defer_projection_commitment: bool,
    cold_history_since_retirement: usize,
    staged_cold_pending: usize,
    projection_cache: Arc<Mutex<Option<(u64, Projection)>>>,
}

/// Exact bounded continuation state persisted at a clean publication fence.
/// Historical signed bodies remain in SQLite; this record contains only the
/// live authority state that the next process needs before accepting work.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct LiveFactGraphCheckpoint {
    version: u16,
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    admission_order: Vec<FactId>,
    quarantined: Vec<SignedFact>,
    admitted_fact_count: u64,
    admitted_bytes: u64,
    derived_index_bytes: u64,
    quarantined_bytes: u64,
    admitted_dependency_edges: u64,
    quarantined_dependency_edges: u64,
    quarantined_by_author: Vec<(DeviceId, (u64, u64))>,
    retained_by_author: Vec<(DeviceId, (u64, u64))>,
    quarantine_missing: Vec<(FactId, Vec<FactId>)>,
    waiting_by_dependency: Vec<(FactId, Vec<FactId>)>,
    ready_quarantine: Vec<FactId>,
    cell_heads: Vec<(ExclusiveCell, Vec<FactId>)>,
    authority_heads: Vec<(DeviceId, Vec<FactId>)>,
    authority_selectors: Vec<(DeviceId, Vec<(FactId, FactId)>)>,
    #[serde(default)]
    authority_provenance: Vec<(FactId, Vec<(FactId, AuthoritySelectorRelation)>)>,
    cells: Vec<ExclusiveCell>,
    stand_down_heads: Vec<(DeviceId, Vec<FactId>)>,
    facts_revision: u64,
    indexed_revision: u64,
    generation: u64,
    projection_cells: Vec<(ExclusiveCell, super::CellProjection)>,
    projection_stand_down: Vec<(DeviceId, super::StandDown)>,
    projection_root: [u8; 32],
}

impl Clone for FactGraph {
    fn clone(&self) -> Self {
        Self {
            facts: self.facts.clone(),
            admitted_fact_count: self.admitted_fact_count,
            admission_order: self.admission_order.clone(),
            quarantined: self.quarantined.clone(),
            policy_limits: self.policy_limits,
            admitted_bytes: self.admitted_bytes,
            derived_index_bytes: self.derived_index_bytes,
            quarantined_bytes: self.quarantined_bytes,
            admitted_dependency_edges: self.admitted_dependency_edges,
            quarantined_dependency_edges: self.quarantined_dependency_edges,
            quarantined_by_author: self.quarantined_by_author.clone(),
            retained_by_author: self.retained_by_author.clone(),
            quarantine_missing: self.quarantine_missing.clone(),
            waiting_by_dependency: self.waiting_by_dependency.clone(),
            ready_quarantine: self.ready_quarantine.clone(),
            context_id: self.context_id,
            authority_roots: self.authority_roots.clone(),
            policy: self.policy.clone(),
            cell_heads_index: self.cell_heads_index.clone(),
            authority_heads_index: self.authority_heads_index.clone(),
            #[cfg(test)]
            authority_dependents_index: self.authority_dependents_index.clone(),
            authority_facts_index: self.authority_facts_index.clone(),
            authority_selector_index: self.authority_selector_index.clone(),
            authority_provenance: self.authority_provenance.clone(),
            #[cfg(test)]
            dependency_index: self.dependency_index.clone(),
            cells_index: self.cells_index.clone(),
            stand_down_index: self.stand_down_index.clone(),
            indexed_fact_count: self.indexed_fact_count,
            facts_revision: self.facts_revision,
            indexed_revision: self.indexed_revision,
            generation: self.generation,
            defer_projection_commitment: self.defer_projection_commitment,
            cold_history_since_retirement: self.cold_history_since_retirement,
            staged_cold_pending: self.staged_cold_pending,
            projection_cache: Arc::new(Mutex::new(self.projection_cache.lock().clone())),
        }
    }
}

#[derive(Debug, Clone)]
struct FactCost {
    encoded_bytes: u64,
    derived_index_bytes: u64,
    _authority_dependents_index_bytes: u64,
    dependency_edges: u64,
    missing: Vec<FactId>,
}

#[derive(Debug, Clone, Copy, Default)]
struct IndexResidencyDelta {
    added: u64,
    removed: u64,
}

fn insert_maximal_head(
    facts: &BTreeMap<FactId, SignedFact>,
    heads: &mut BTreeSet<FactId>,
    candidate: FactId,
) {
    let Some(fact) = facts.get(&candidate) else {
        return;
    };
    let direct_dependencies = dependencies(fact);
    heads.retain(|head| !signed_head_is_dominated(facts, &direct_dependencies, head));
    heads.insert(candidate);
}

fn signed_head_is_dominated(
    facts: &BTreeMap<FactId, SignedFact>,
    direct_dependencies: &[FactId],
    head: &FactId,
) -> bool {
    // Normal current-head authoring removes heads by the direct edge alone.
    // Projected authoring may omit a raw head hidden by a typed selector;
    // only those unmatched heads need the exceptional signed-ancestry walk.
    // The same predicate prices the exact removal before mutation. Missing
    // ingress parents are not errors here: quarantine is classified by cost,
    // and admission validates/loads the candidate's required causal history.
    if direct_dependencies.contains(head) {
        return true;
    }
    let mut pending = direct_dependencies.to_vec();
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        if let Some(fact) = facts.get(&id) {
            let parents = dependencies(fact);
            if parents.contains(head) {
                return true;
            }
            pending.extend(parents);
        }
    }
    false
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SemanticFactStatus {
    Admitted,
    Quarantined,
}

/// One bounded row changed by an admission. The row owns only the changed
/// signed fact; it is deliberately not a snapshot of the surrounding graph.
#[derive(Debug, Clone)]
pub(crate) struct SemanticFactRow {
    fact: SignedFact,
    status: SemanticFactStatus,
}

impl SemanticFactRow {
    pub(crate) fn fact(&self) -> &SignedFact {
        &self.fact
    }

    pub(crate) fn status(&self) -> SemanticFactStatus {
        self.status
    }

    #[cfg(test)]
    pub(crate) fn for_test(fact: SignedFact, status: SemanticFactStatus) -> Self {
        Self { fact, status }
    }
}

/// The exact bounded durable changes produced by one journaled admission.
/// Store code can persist these rows and IDs without rebuilding the graph.
#[derive(Debug, Clone, Default)]
pub(crate) struct SemanticDelta {
    rows: Vec<SemanticFactRow>,
    promoted: Vec<FactId>,
    removed: Vec<FactId>,
    provisional_added: Vec<FactId>,
    provisional_removed: Vec<FactId>,
    affected_cells: BTreeSet<ExclusiveCell>,
    affected_subjects: BTreeSet<DeviceId>,
    projection_delta: Option<super::projection::ProjectionDelta>,
}

impl SemanticDelta {
    pub(crate) fn rows(&self) -> &[SemanticFactRow] {
        &self.rows
    }

    pub(crate) fn promoted(&self) -> &[FactId] {
        &self.promoted
    }

    pub(crate) fn removed(&self) -> &[FactId] {
        &self.removed
    }

    pub(crate) fn provisional_added(&self) -> &[FactId] {
        &self.provisional_added
    }

    pub(crate) fn provisional_removed(&self) -> &[FactId] {
        &self.provisional_removed
    }

    pub(crate) fn affected_cells(&self) -> &BTreeSet<ExclusiveCell> {
        &self.affected_cells
    }

    pub(crate) fn affected_subjects(&self) -> &BTreeSet<DeviceId> {
        &self.affected_subjects
    }

    pub(crate) fn projection_delta(&self) -> Option<&super::projection::ProjectionDelta> {
        self.projection_delta.as_ref()
    }

    #[cfg(test)]
    pub(crate) fn push_row_for_test(&mut self, row: SemanticFactRow) {
        self.rows.push(row);
    }

    #[cfg(test)]
    pub(crate) fn push_promoted_for_test(&mut self, id: FactId) {
        self.promoted.push(id);
    }

    #[cfg(test)]
    pub(crate) fn push_removed_for_test(&mut self, id: FactId) {
        self.removed.push(id);
    }

    #[cfg(test)]
    pub(crate) fn push_provisional_added_for_test(&mut self, id: FactId) {
        self.provisional_added.push(id);
    }

    #[cfg(test)]
    pub(crate) fn push_provisional_removed_for_test(&mut self, id: FactId) {
        self.provisional_removed.push(id);
    }

    pub(crate) fn changed_ids(&self) -> impl Iterator<Item = FactId> + '_ {
        self.rows
            .iter()
            .map(|row| row.fact.id)
            .chain(self.removed.iter().copied())
    }

    fn is_bounded_and_unique(&self, max_ready_batch: u64) -> bool {
        let unique =
            |ids: &[FactId]| ids.iter().copied().collect::<BTreeSet<_>>().len() == ids.len();
        let Some(max_ready_batch) = usize::try_from(max_ready_batch).ok() else {
            return false;
        };
        let row_ids = self
            .rows
            .iter()
            .map(|row| row.fact.id)
            .collect::<BTreeSet<_>>();
        row_ids.len() == self.rows.len()
            && unique(&self.promoted)
            && unique(&self.removed)
            && unique(&self.provisional_added)
            && unique(&self.provisional_removed)
            && self.rows.len() <= max_ready_batch.saturating_add(1)
            && self.promoted.len() <= max_ready_batch
            && self.removed.len() <= max_ready_batch
    }

    #[cfg(feature = "transport-lab")]
    pub(crate) fn append_seed_delta(&mut self, mut next: Self) {
        if self.projection_delta.is_none() {
            self.projection_delta = next.projection_delta.take();
        }
        self.rows.append(&mut next.rows);
        self.promoted.append(&mut next.promoted);
        self.removed.append(&mut next.removed);
        self.provisional_added.append(&mut next.provisional_added);
        self.provisional_removed
            .append(&mut next.provisional_removed);
        self.affected_cells.append(&mut next.affected_cells);
        self.affected_subjects.append(&mut next.affected_subjects);
    }
}

#[derive(Debug)]
pub(crate) struct AdmissionPreflight {
    admission: Admission,
    cost: Option<FactCost>,
    fact_id: FactId,
    content_id: FactId,
    signature: String,
    facts_revision: u64,
    generation: u64,
}

impl AdmissionPreflight {
    fn new(
        graph: &FactGraph,
        fact: &SignedFact,
        admission: Admission,
        cost: Option<FactCost>,
    ) -> Self {
        Self {
            admission,
            cost,
            fact_id: fact.id,
            content_id: FactId::from_content(&fact.content),
            signature: fact.signature.clone(),
            facts_revision: graph.facts_revision,
            generation: graph.generation,
        }
    }

    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    #[cfg(test)]
    pub(crate) fn encoded_bytes(&self) -> Option<u64> {
        self.cost.as_ref().map(|cost| cost.encoded_bytes)
    }

    fn validate_for(&self, graph: &FactGraph, fact: &SignedFact) -> Result<(), SemanticError> {
        if self.fact_id != fact.id
            || self.content_id != FactId::from_content(&fact.content)
            || self.signature.as_str() != fact.signature.as_str()
            || self.facts_revision != graph.facts_revision
            || self.generation != graph.generation
        {
            return Err(SemanticError::NoOp("stale admission preflight"));
        }
        Ok(())
    }
}

#[derive(Debug)]
struct GraphRollback {
    authority_provenance: BTreeMap<FactId, Option<AuthorityProvenanceRow>>,
    authority_heads: BTreeMap<DeviceId, Option<BTreeSet<FactId>>>,
    cell_heads: BTreeMap<ExclusiveCell, Option<BTreeSet<FactId>>>,
    facts: BTreeMap<FactId, Option<SignedFact>>,
    quarantined: BTreeMap<FactId, Option<SignedFact>>,
    quarantine_missing: BTreeMap<FactId, Option<BTreeSet<FactId>>>,
    waiting_by_dependency: BTreeMap<FactId, Option<BTreeSet<FactId>>>,
    ready_quarantine: BTreeMap<FactId, bool>,
    quarantined_by_author: BTreeMap<DeviceId, Option<(u64, u64)>>,
    retained_by_author: BTreeMap<DeviceId, Option<(u64, u64)>>,
    admitted_bytes: u64,
    admitted_fact_count: u64,
    derived_index_bytes: u64,
    quarantined_bytes: u64,
    admitted_dependency_edges: u64,
    quarantined_dependency_edges: u64,
    generation: u64,
    facts_revision: u64,
    admission_order_len: usize,
    indexed_fact_count: usize,
    indexed_revision: u64,
    cold_history_since_retirement: usize,
    staged_cold_pending: usize,
    /// Only the cache fence is retained. Holding a cloned Projection here
    /// would share its Arc maps with the update path and force Arc::make_mut
    /// to copy the complete projection on every successful admission.
    projection_cache_fence: Option<(u64, [u8; 32])>,
    /// Cold-history hydration is already an exceptional closure-sized path.
    /// Retain its complete pre-admission projection so rollback does not have
    /// to reconstruct SQLite-owned history from the bounded hot graph.
    projection_full: Option<Projection>,
    projection_cells: BTreeMap<ExclusiveCell, Option<super::CellProjection>>,
    projection_stand_down: BTreeMap<DeviceId, Option<super::StandDown>>,
}

impl GraphRollback {
    fn new(graph: &FactGraph) -> Self {
        Self {
            facts: BTreeMap::new(),
            quarantined: BTreeMap::new(),
            quarantine_missing: BTreeMap::new(),
            waiting_by_dependency: BTreeMap::new(),
            ready_quarantine: BTreeMap::new(),
            quarantined_by_author: BTreeMap::new(),
            retained_by_author: BTreeMap::new(),
            admitted_bytes: graph.admitted_bytes,
            admitted_fact_count: graph.admitted_fact_count,
            derived_index_bytes: graph.derived_index_bytes,
            quarantined_bytes: graph.quarantined_bytes,
            admitted_dependency_edges: graph.admitted_dependency_edges,
            quarantined_dependency_edges: graph.quarantined_dependency_edges,
            generation: graph.generation,
            facts_revision: graph.facts_revision,
            admission_order_len: graph.admission_order.len(),
            indexed_fact_count: graph.indexed_fact_count,
            indexed_revision: graph.indexed_revision,
            cold_history_since_retirement: graph.cold_history_since_retirement,
            staged_cold_pending: graph.staged_cold_pending,
            authority_provenance: BTreeMap::new(),
            authority_heads: BTreeMap::new(),
            cell_heads: BTreeMap::new(),
            projection_cache_fence: graph
                .projection_cache
                .lock()
                .as_ref()
                .map(|(generation, projection)| (*generation, projection.commitment_root())),
            projection_full: None,
            projection_cells: BTreeMap::new(),
            projection_stand_down: BTreeMap::new(),
        }
    }

    fn capture_projection_sparse(
        &mut self,
        cells: &BTreeMap<ExclusiveCell, Option<super::CellProjection>>,
        stand_down: &BTreeMap<DeviceId, Option<super::StandDown>>,
    ) {
        for (cell, value) in cells {
            self.projection_cells
                .entry(cell.clone())
                .or_insert_with(|| value.clone());
        }
        for (subject, value) in stand_down {
            self.projection_stand_down
                .entry(subject.clone())
                .or_insert_with(|| value.clone());
        }
    }

    fn capture_projection_full(&mut self, generation: u64, projection: &Projection) {
        let root = projection.commitment_root();
        if let Some((cached_generation, cached_root)) = self.projection_cache_fence {
            debug_assert_eq!(cached_generation, generation);
            debug_assert_eq!(cached_root, root);
        } else {
            // Cold-history staging can deliberately make the hot indexes
            // incomplete, so GraphRollback may be created without a cache
            // fence even though the caller materialized the complete logical
            // projection immediately before staging. Preserve that explicit
            // pre-staging projection as the rollback fence.
            self.projection_cache_fence = Some((generation, root));
        }
        self.projection_full = Some(projection.clone());
    }

    fn capture_admission(&mut self, graph: &FactGraph, fact: &SignedFact) {
        self.capture_fact(graph, fact.id);
        self.capture_author(graph, &fact.content.author);
        self.capture_provenance_admission(graph, fact);
        self.capture_dependency(graph, fact.id);
        for dependency in dependencies(fact) {
            self.capture_dependency(graph, dependency);
        }
    }

    fn capture_fact(&mut self, graph: &FactGraph, id: FactId) {
        self.facts
            .entry(id)
            .or_insert_with(|| graph.facts.get(&id).cloned());
        self.quarantined
            .entry(id)
            .or_insert_with(|| graph.quarantined.get(&id).cloned());
        self.quarantine_missing
            .entry(id)
            .or_insert_with(|| graph.quarantine_missing.get(&id).cloned());
        self.ready_quarantine
            .entry(id)
            .or_insert_with(|| graph.ready_quarantine.contains(&id));
        if let Some(fact) = graph.facts.get(&id).or_else(|| graph.quarantined.get(&id)) {
            self.capture_provenance_admission(graph, fact);
        }
    }

    /// Mark rows attached by a cold-history overlay as absent in the
    /// pre-overlay baseline.  This is used only when preflight discovers an
    /// AlreadyPresent candidate after staging; the normal admission path does
    /// not retain a graph-sized rollback snapshot.
    fn capture_staged_absence(&mut self, staged: &[FactId]) {
        for id in staged {
            self.facts.insert(*id, None);
            self.quarantined.insert(*id, None);
            self.quarantine_missing.insert(*id, None);
            self.ready_quarantine.insert(*id, false);
        }
    }

    fn capture_dependency(&mut self, graph: &FactGraph, dependency: FactId) {
        self.waiting_by_dependency
            .entry(dependency)
            .or_insert_with(|| graph.waiting_by_dependency.get(&dependency).cloned());
        if let Some(waiters) = graph.waiting_by_dependency.get(&dependency) {
            for waiter in waiters {
                self.capture_fact(graph, *waiter);
                if let Some(fact) = graph.quarantined.get(waiter) {
                    self.capture_author(graph, &fact.content.author);
                }
            }
        }
    }

    /// Capture the complete bounded waiter closure that can be touched when
    /// any of `seeds` becomes available. Quarantine policy bounds this walk;
    /// retaining the closure is required because each retry can make another
    /// waiter ready in the same journal.
    fn capture_waiter_closure(&mut self, graph: &FactGraph, seeds: &[FactId]) {
        self.capture_waiter_closure_with_ids(graph, seeds);
    }

    fn capture_waiter_closure_with_ids(
        &mut self,
        graph: &FactGraph,
        seeds: &[FactId],
    ) -> Vec<FactId> {
        let mut pending = seeds.to_vec();
        let mut seen = BTreeSet::new();
        let mut closure = Vec::new();
        while let Some(dependency) = pending.pop() {
            if !seen.insert(dependency) {
                continue;
            }
            closure.push(dependency);
            // A ready seed is itself a mutable row: retry may promote or
            // terminally remove it.  Capture its row and author before
            // following descendants so rollback/Drop restores the complete
            // pre-mutation boundary, including leaf seeds with no waiters.
            self.capture_fact(graph, dependency);
            if let Some(fact) = graph.facts.get(&dependency) {
                self.capture_author(graph, &fact.content.author);
            }
            if let Some(fact) = graph.quarantined.get(&dependency) {
                self.capture_author(graph, &fact.content.author);
            }
            self.capture_dependency(graph, dependency);
            if let Some(waiters) = graph.waiting_by_dependency.get(&dependency) {
                for waiter in waiters {
                    self.capture_fact(graph, *waiter);
                    pending.push(*waiter);
                }
            }
        }
        closure
    }

    fn capture_author(&mut self, graph: &FactGraph, author: &DeviceId) {
        self.quarantined_by_author
            .entry(author.clone())
            .or_insert_with(|| graph.quarantined_by_author.get(author).copied());
        self.retained_by_author
            .entry(author.clone())
            .or_insert_with(|| graph.retained_by_author.get(author).copied());
    }

    fn capture_provenance_admission(&mut self, graph: &FactGraph, fact: &SignedFact) {
        self.authority_provenance
            .entry(fact.id)
            .or_insert_with(|| graph.authority_provenance.get(&fact.id).cloned());
        if graph.staged_cold_pending != 0
            || matches!(
                fact.content.body,
                FactBody::AuthorityLineageResolution { .. }
            )
        {
            for id in graph.facts.keys() {
                self.authority_provenance
                    .entry(*id)
                    .or_insert_with(|| graph.authority_provenance.get(id).cloned());
            }
        }
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            self.authority_heads
                .entry(subject.clone())
                .or_insert_with(|| graph.authority_heads_index.get(&subject).cloned());
        }
        for cell in fact.content.body.exclusive_cells() {
            self.cell_heads
                .entry(cell.clone())
                .or_insert_with(|| graph.cell_heads_index.get(&cell).cloned());
        }
    }

    fn restore(self, graph: &mut FactGraph) {
        let mut append_only_order = std::mem::take(&mut graph.admission_order);
        append_only_order.truncate(self.admission_order_len);
        let rollback_projection = graph
            .projection_cache
            .lock()
            .take()
            .map(|(_, projection)| projection);
        let admitted_bytes = self.admitted_bytes;
        let derived_index_bytes = self.derived_index_bytes;
        let quarantined_bytes = self.quarantined_bytes;
        let admitted_dependency_edges = self.admitted_dependency_edges;
        let quarantined_dependency_edges = self.quarantined_dependency_edges;
        graph.admitted_bytes = self.admitted_bytes;
        graph.admitted_fact_count = self.admitted_fact_count;
        graph.derived_index_bytes = self.derived_index_bytes;
        graph.quarantined_bytes = self.quarantined_bytes;
        graph.admitted_dependency_edges = self.admitted_dependency_edges;
        graph.quarantined_dependency_edges = self.quarantined_dependency_edges;
        for (id, value) in self.facts {
            match value {
                Some(fact) => {
                    graph.facts.insert(id, fact);
                }
                None => {
                    graph.facts.remove(&id);
                }
            }
        }
        for (id, value) in self.quarantined {
            match value {
                Some(fact) => {
                    graph.quarantined.insert(id, fact);
                }
                None => {
                    graph.quarantined.remove(&id);
                }
            }
        }
        for (id, value) in self.quarantine_missing {
            match value {
                Some(missing) => {
                    graph.quarantine_missing.insert(id, missing);
                }
                None => {
                    graph.quarantine_missing.remove(&id);
                }
            }
        }
        for (dependency, value) in self.waiting_by_dependency {
            match value {
                Some(waiters) => {
                    graph.waiting_by_dependency.insert(dependency, waiters);
                }
                None => {
                    graph.waiting_by_dependency.remove(&dependency);
                }
            }
        }
        for (id, was_ready) in self.ready_quarantine {
            if was_ready {
                graph.ready_quarantine.insert(id);
            } else {
                graph.ready_quarantine.remove(&id);
            }
        }
        for (author, value) in self.quarantined_by_author {
            match value {
                Some(counts) => {
                    graph.quarantined_by_author.insert(author, counts);
                }
                None => {
                    graph.quarantined_by_author.remove(&author);
                }
            }
        }
        for (author, value) in self.retained_by_author {
            match value {
                Some(counts) => {
                    graph.retained_by_author.insert(author, counts);
                }
                None => {
                    graph.retained_by_author.remove(&author);
                }
            }
        }
        graph.generation = self.generation;
        graph.facts_revision = self.facts_revision;
        for (id, value) in self.authority_provenance {
            match value {
                Some(row) => {
                    graph.authority_provenance.insert(id, row);
                }
                None => {
                    graph.authority_provenance.remove(&id);
                }
            }
        }
        for (subject, value) in self.authority_heads {
            match value {
                Some(heads) => {
                    graph.authority_heads_index.insert(subject, heads);
                }
                None => {
                    graph.authority_heads_index.remove(&subject);
                }
            }
        }
        for (cell, value) in self.cell_heads {
            match value {
                Some(heads) => {
                    graph.cell_heads_index.insert(cell, heads);
                }
                None => {
                    graph.cell_heads_index.remove(&cell);
                }
            }
        }
        graph.rebuild_indexes();
        // Rebuilding indexes derives a dependency order, which is suitable
        // for loader repair but is not the journal's exact pre-mutation
        // admission order. Staged-history cleanup preserves the current
        // append-only order before this rebuild; ordinary rollback keeps its
        // original prefix without a hot-path full snapshot.
        graph.admission_order = append_only_order;
        // Rebuilding derived maps also reconciles canonical scalar totals. A
        // journal rollback must nevertheless restore the exact pre-journal
        // scalar snapshot, including a loader-provided value that was being
        // validated by the caller.
        graph.admitted_bytes = admitted_bytes;
        graph.admitted_fact_count = self.admitted_fact_count;
        graph.derived_index_bytes = derived_index_bytes;
        graph.quarantined_bytes = quarantined_bytes;
        graph.admitted_dependency_edges = admitted_dependency_edges;
        graph.quarantined_dependency_edges = quarantined_dependency_edges;
        graph.indexed_fact_count = self.indexed_fact_count;
        graph.indexed_revision = self.indexed_revision;
        graph.cold_history_since_retirement = self.cold_history_since_retirement;
        graph.staged_cold_pending = self.staged_cold_pending;
        let restored_cache = match self.projection_full {
            // This snapshot was materialized immediately before cold rows
            // were attached. It is the complete logical projection even when
            // the intentionally incomplete hot indexes had no usable cache
            // fence of their own.
            Some(projection) => {
                // Staged cold rows have already been removed above. Restore a
                // current hot-index fence so projection() may use the complete
                // logical cache captured before staging.
                graph.indexed_fact_count = graph.facts.len();
                graph.indexed_revision = graph.facts_revision;
                Some((self.generation, projection))
            }
            None => self.projection_cache_fence.and_then(|(generation, root)| {
                let mut projection =
                    rollback_projection.unwrap_or_else(|| Projection::from_graph(graph));
                projection
                    .restore_sparse_entries(&self.projection_cells, &self.projection_stand_down);
                (projection.commitment_root() == root).then_some((generation, projection))
            }),
        };
        *graph.projection_cache.lock() = restored_cache;
    }
}

/// A move-only graph mutation record. The caller should commit it only after
/// the durable delta succeeds or explicitly consume it with `rollback`.
/// Dropping an uncommitted journal automatically restores the exact captured
/// graph state, so a failed owner handoff cannot silently retain a mutation.
#[must_use = "commit or explicitly roll back this admission journal"]
#[derive(Debug)]
pub(crate) struct AdmissionJournal<'graph> {
    graph: &'graph mut FactGraph,
    rollback: Option<GraphRollback>,
    staged_cold: Vec<FactId>,
    delta: SemanticDelta,
    admission: Admission,
}

impl<'graph> AdmissionJournal<'graph> {
    pub(crate) fn graph(&self) -> &FactGraph {
        self.graph
    }

    pub(crate) fn admission(&self) -> &Admission {
        &self.admission
    }

    pub(crate) fn delta(&self) -> &SemanticDelta {
        &self.delta
    }

    #[cfg(test)]
    pub(crate) fn rollback(mut self) {
        self.graph.remove_staged_cold(&self.staged_cold);
        if let Some(rollback) = self.rollback.take() {
            rollback.restore(self.graph);
        }
        self.staged_cold.clear();
    }

    pub(crate) fn commit(mut self) {
        self.rollback.take();
        let hydrated_cold_history = !self.staged_cold.is_empty();
        self.staged_cold.clear();
        if hydrated_cold_history {
            // A committed candidate may still need its hydrated ancestors
            // while its projection is finalized, but they must not escape
            // the journal as a second in-memory copy of SQLite history.
            self.graph.retire_cold_history();
        }
    }
}

impl Drop for AdmissionJournal<'_> {
    fn drop(&mut self) {
        let staged_cold = std::mem::take(&mut self.staged_cold);
        self.graph.remove_staged_cold(&staged_cold);
        if let Some(rollback) = self.rollback.take() {
            rollback.restore(self.graph);
        }
    }
}

/// The deterministic result for one input in an aggregate admission. A
/// semantic refusal is isolated to its input; it does not discard mutations
/// from earlier valid inputs in the same journal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum AggregateAdmissionOutcome {
    Inserted {
        fact_id: FactId,
    },
    AlreadyPresent {
        fact_id: FactId,
    },
    Quarantined {
        fact_id: FactId,
        missing: Vec<FactId>,
    },
    Refused {
        fact_id: FactId,
        error: SemanticError,
    },
}

/// One externally committed aggregate graph mutation. Each input is applied
/// in enqueue order against the graph produced by earlier inputs. The outer
/// rollback is the only durable batch owner; per-input journals are committed
/// immediately after their isolated mutation succeeds and therefore cannot
/// roll back an earlier valid input.
#[must_use = "commit or explicitly roll back this aggregate admission journal"]
#[derive(Debug)]
pub(crate) struct AggregateAdmissionJournal<'graph> {
    graph: &'graph mut FactGraph,
    rollback: Option<GraphRollback>,
    staged_cold: Vec<FactId>,
    results: Vec<AggregateAdmissionResult>,
    delta: SemanticDelta,
}

#[derive(Debug)]
pub(crate) struct AggregateAdmissionResult {
    outcome: AggregateAdmissionOutcome,
    _delta: SemanticDelta,
}

impl AggregateAdmissionResult {
    pub(crate) fn outcome(&self) -> &AggregateAdmissionOutcome {
        &self.outcome
    }

    #[cfg(test)]
    pub(crate) fn delta(&self) -> &SemanticDelta {
        &self._delta
    }
}

impl<'graph> AggregateAdmissionJournal<'graph> {
    #[cfg(test)]
    pub(crate) fn graph(&self) -> &FactGraph {
        self.graph
    }

    pub(crate) fn results(&self) -> &[AggregateAdmissionResult] {
        &self.results
    }

    pub(crate) fn delta(&self) -> &SemanticDelta {
        &self.delta
    }

    pub(crate) fn commit(mut self) {
        self.rollback.take();
        let hydrated_cold_history = !self.staged_cold.is_empty();
        self.staged_cold.clear();
        if hydrated_cold_history {
            self.graph.retire_cold_history();
        }
    }

    pub(crate) fn rollback(mut self) {
        self.graph.remove_staged_cold(&self.staged_cold);
        if let Some(rollback) = self.rollback.take() {
            rollback.restore(self.graph);
        }
        self.staged_cold.clear();
    }
}

impl Drop for AggregateAdmissionJournal<'_> {
    fn drop(&mut self) {
        let staged_cold = std::mem::take(&mut self.staged_cold);
        self.graph.remove_staged_cold(&staged_cold);
        if let Some(rollback) = self.rollback.take() {
            rollback.restore(self.graph);
        }
    }
}

/// Candidate-relative read view used during admission.  A candidate whose
/// causal closure already covers the admitted graph can borrow that graph
/// directly; unrelated candidates retain an owned, exact closure.  This keeps
/// the authority boundary unchanged while avoiding a full graph clone on the
/// normal current-head path.
// Preserve the inline owned closure and borrowed fast path. Boxing Scoped would
// add an allocation and change admission custody/layout merely to shrink a tag.
#[allow(clippy::large_enum_variant)]
enum CausalAdmissionGraph<'a> {
    Full(&'a FactGraph),
    Scoped(FactGraph),
}

impl CausalAdmissionGraph<'_> {
    fn graph(&self) -> &FactGraph {
        match self {
            Self::Full(graph) => graph,
            Self::Scoped(graph) => graph,
        }
    }

    fn contains(&self, id: &FactId) -> bool {
        self.graph().facts.contains_key(id)
    }

    fn get(&self, id: &FactId) -> Option<&SignedFact> {
        self.graph().facts.get(id)
    }

    fn raw_cell_heads(&self, cell: &ExclusiveCell) -> Vec<FactId> {
        self.graph().raw_cell_heads(cell)
    }

    fn evaluator(&self) -> SemanticEvaluator<'_> {
        self.graph().evaluator()
    }

    fn authority_lineage(&self, subject: &DeviceId) -> super::content::AuthorityLineage {
        self.graph().authority_lineage(subject)
    }

    fn validate_authority_lineage(
        &self,
        fact: &SignedFact,
        error: SemanticError,
    ) -> Result<(), SemanticError> {
        self.graph().validate_authority_lineage(fact, error)
    }

    fn is_authorized_for(&self, body: &FactBody, author: &DeviceId) -> bool {
        self.graph().is_authorized_for(body, author)
    }

    fn validate_eviction_proof(
        &self,
        target: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        self.graph()
            .validate_eviction_proof(target, evidence, author)
    }

    fn validate_self_stand_down(
        &self,
        device_id: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        self.graph()
            .validate_self_stand_down(device_id, evidence, author)
    }
}

impl FactGraph {
    /// Construct the graph from the verified, exact bootstrap context. The
    /// graph owns the policy snapshot, so callers cannot supply an unrelated
    /// root set or leave the graph context unbound.
    #[cfg(any(test, feature = "transport-lab"))]
    pub fn from_bootstrap(bootstrap: &VerifiedBootstrap) -> Self {
        Self::from_bootstrap_with_policy(bootstrap, crate::config::SemanticPolicyConfig::default())
    }

    /// Construct a graph with an immutable, owner-selected aggregate budget.
    /// All retained fact and dependency accounting is initialized before the
    /// first admission, so a refusal cannot leave a partially funded graph.
    pub fn from_bootstrap_with_policy<P>(bootstrap: &VerifiedBootstrap, policy_limits: P) -> Self
    where
        P: Into<SemanticAdmissionPolicy>,
    {
        let policy_limits = policy_limits.into();
        Self {
            facts: BTreeMap::new(),
            admitted_fact_count: 0,
            admission_order: Vec::new(),
            quarantined: BTreeMap::new(),
            policy_limits,
            admitted_bytes: 0,
            derived_index_bytes: 0,
            quarantined_bytes: 0,
            admitted_dependency_edges: 0,
            quarantined_dependency_edges: 0,
            quarantined_by_author: BTreeMap::new(),
            retained_by_author: BTreeMap::new(),
            quarantine_missing: BTreeMap::new(),
            waiting_by_dependency: BTreeMap::new(),
            ready_quarantine: BTreeSet::new(),
            context_id: bootstrap.context_id(),
            authority_roots: bootstrap.authority_roots().iter().cloned().collect(),
            policy: bootstrap.policy().clone(),
            cell_heads_index: BTreeMap::new(),
            authority_heads_index: BTreeMap::new(),
            #[cfg(test)]
            authority_dependents_index: BTreeMap::new(),
            authority_facts_index: BTreeMap::new(),
            authority_selector_index: BTreeMap::new(),
            authority_provenance: BTreeMap::new(),
            #[cfg(test)]
            dependency_index: BTreeMap::new(),
            cells_index: BTreeSet::new(),
            stand_down_index: BTreeMap::new(),
            indexed_fact_count: 0,
            facts_revision: 0,
            indexed_revision: 0,
            generation: 0,
            defer_projection_commitment: false,
            cold_history_since_retirement: 0,
            staged_cold_pending: 0,
            projection_cache: Arc::new(Mutex::new(None)),
        }
    }

    pub fn context_id(&self) -> MeshContextId {
        self.context_id
    }

    pub(crate) fn begin_deferred_projection_commitment(&mut self) {
        self.defer_projection_commitment = true;
    }

    pub(crate) fn finish_deferred_projection_commitment(&mut self) {
        self.defer_projection_commitment = false;
        let mut projection_cache = self.projection_cache.lock();
        if let Some((generation, projection)) = projection_cache.take() {
            *projection_cache = Some((generation, projection.rebuild_commitment()));
        }
    }

    #[cfg(feature = "transport-lab")]
    pub(crate) fn finish_deferred_seed_delta(
        &mut self,
        previous: Projection,
        mut delta: SemanticDelta,
    ) -> SemanticDelta {
        let base_generation = delta
            .projection_delta
            .as_ref()
            .map(ProjectionDelta::base_generation)
            .unwrap_or(self.generation);
        self.finish_deferred_projection_commitment();
        let current = self.projection();
        delta.projection_delta = Some(current.delta_from(
            &previous,
            base_generation,
            self.generation,
            &delta.affected_cells,
            &delta.affected_subjects,
        ));
        delta
    }

    /// Return the versioned canonical projection root maintained by the graph.
    /// The cached projection contains immutable Merkle paths, so this accessor
    /// does not rebuild or enumerate the ledger on the current-head path.
    pub(crate) fn projection_commitment_root(&self) -> [u8; 32] {
        self.projection().commitment_root()
    }

    pub(crate) fn verify_projection_commitment(&self, expected: [u8; 32]) -> bool {
        self.projection_commitment_root() == expected
    }

    pub(crate) fn live_checkpoint(&self) -> LiveFactGraphCheckpoint {
        let projection = self.projection();
        let (projection_cells, projection_stand_down) = projection.checkpoint_parts();
        LiveFactGraphCheckpoint {
            version: 1,
            context_id: self.context_id,
            facts: self.facts.values().cloned().collect(),
            admission_order: self.admission_order.clone(),
            quarantined: self.quarantined.values().cloned().collect(),
            admitted_fact_count: self.admitted_fact_count,
            admitted_bytes: self.admitted_bytes,
            derived_index_bytes: self.derived_index_bytes,
            quarantined_bytes: self.quarantined_bytes,
            admitted_dependency_edges: self.admitted_dependency_edges,
            quarantined_dependency_edges: self.quarantined_dependency_edges,
            quarantined_by_author: self
                .quarantined_by_author
                .iter()
                .map(|(author, counts)| (author.clone(), *counts))
                .collect(),
            retained_by_author: self
                .retained_by_author
                .iter()
                .map(|(author, counts)| (author.clone(), *counts))
                .collect(),
            quarantine_missing: self
                .quarantine_missing
                .iter()
                .map(|(id, missing)| (*id, missing.iter().copied().collect()))
                .collect(),
            waiting_by_dependency: self
                .waiting_by_dependency
                .iter()
                .map(|(id, waiting)| (*id, waiting.iter().copied().collect()))
                .collect(),
            ready_quarantine: self.ready_quarantine.iter().copied().collect(),
            cell_heads: self
                .cell_heads_index
                .iter()
                .map(|(cell, heads)| (cell.clone(), heads.iter().copied().collect()))
                .collect(),
            authority_heads: self
                .authority_heads_index
                .iter()
                .map(|(subject, heads)| (subject.clone(), heads.iter().copied().collect()))
                .collect(),
            authority_selectors: self
                .authority_selector_index
                .iter()
                .map(|(subject, selectors)| (subject.clone(), selectors.iter().copied().collect()))
                .collect(),
            authority_provenance: self
                .authority_provenance
                .iter()
                .map(|(fact, row)| {
                    (
                        *fact,
                        row.iter()
                            .map(|(selector, relation)| (*selector, *relation))
                            .collect(),
                    )
                })
                .collect(),
            cells: self.cells_index.iter().cloned().collect(),
            stand_down_heads: self
                .stand_down_index
                .iter()
                .map(|(subject, heads)| (subject.clone(), heads.iter().copied().collect()))
                .collect(),
            facts_revision: self.facts_revision,
            indexed_revision: self.indexed_revision,
            generation: self.generation,
            projection_cells,
            projection_stand_down,
            projection_root: projection.commitment_root(),
        }
    }

    pub(crate) fn durable_usage_counters(&self) -> (u64, u64, u64, u64, u64) {
        (
            self.admitted_fact_count,
            self.admitted_bytes,
            self.quarantined.len() as u64,
            self.quarantined_bytes,
            self.admitted_dependency_edges
                .saturating_add(self.quarantined_dependency_edges),
        )
    }

    #[cfg(test)]
    pub(crate) fn from_live_checkpoint(
        bootstrap: &VerifiedBootstrap,
        policy: crate::config::SemanticPolicyConfig,
        checkpoint: LiveFactGraphCheckpoint,
    ) -> Result<Self, String> {
        let history = checkpoint.facts.clone();
        Self::from_live_checkpoint_with_history(bootstrap, policy, checkpoint, move |_| {
            Ok(history.clone())
        })
    }

    pub(crate) fn from_live_checkpoint_with_history<F>(
        bootstrap: &VerifiedBootstrap,
        policy: crate::config::SemanticPolicyConfig,
        checkpoint: LiveFactGraphCheckpoint,
        mut resolve: F,
    ) -> Result<Self, String>
    where
        F: FnMut(&[FactId]) -> Result<Vec<SignedFact>, String>,
    {
        // Roots come from signed live rows, never the claimed cache coverage.
        let roots = checkpoint
            .facts
            .iter()
            .map(|fact| fact.id)
            .collect::<Vec<_>>();
        let history = resolve(&roots)?;
        let mut canonical = Self::from_bootstrap_with_policy(bootstrap, policy);
        for fact in history {
            fact.verify().map_err(|error| error.to_string())?;
            if fact.content.mesh_context != bootstrap.context_id() {
                return Err("canonical provenance context mismatch".into());
            }
            let id = fact.id;
            if canonical.facts.insert(id, fact).is_some() {
                return Err("duplicate canonical provenance row".into());
            }
        }
        for fact in canonical.facts.values() {
            if dependencies(fact)
                .iter()
                .any(|id| !canonical.facts.contains_key(id))
            {
                return Err("canonical provenance dependency closure is incomplete".into());
            }
        }
        for fact in &checkpoint.facts {
            if canonical.facts.get(&fact.id) != Some(fact) {
                return Err("checkpoint signed row differs from canonical history".into());
            }
        }
        let graph = Self::decode_live_checkpoint(bootstrap, policy, checkpoint)?;
        // Cache coverage cannot be hidden by also dropping a live-head index
        // entry. Every canonical authority/cell use must reach a declared
        // maximal head, and no declared head may dominate another.
        for fact in canonical.facts.values() {
            for subject in Self::indexed_authority_subjects(fact) {
                if !graph
                    .authority_heads_index
                    .get(&subject)
                    .is_some_and(|heads| {
                        heads
                            .iter()
                            .any(|head| fact.id == *head || canonical.is_ancestor(&fact.id, head))
                    })
                {
                    return Err("checkpoint authority-head coverage is incomplete".into());
                }
            }
            for cell in fact.content.body.exclusive_cells() {
                if !graph.cell_heads_index.get(&cell).is_some_and(|heads| {
                    heads
                        .iter()
                        .any(|head| fact.id == *head || canonical.is_ancestor(&fact.id, head))
                }) {
                    return Err("checkpoint cell-head coverage is incomplete".into());
                }
            }
        }
        for (subject, heads) in &graph.authority_heads_index {
            for head in heads {
                if !canonical
                    .facts
                    .get(head)
                    .is_some_and(|fact| Self::indexed_authority_subjects(fact).contains(subject))
                    || heads
                        .iter()
                        .any(|other| head != other && canonical.is_ancestor(head, other))
                {
                    return Err("checkpoint authority head is not canonical maximal use".into());
                }
            }
        }
        for (cell, heads) in &graph.cell_heads_index {
            for head in heads {
                if !canonical
                    .facts
                    .get(head)
                    .is_some_and(|fact| fact.content.body.exclusive_cells().contains(cell))
                    || heads
                        .iter()
                        .any(|other| head != other && canonical.is_ancestor(head, other))
                {
                    return Err("checkpoint cell head is not canonical maximal use".into());
                }
            }
        }
        let contexts = graph
            .authority_provenance
            .values()
            .flat_map(|row| row.keys().copied())
            .collect::<BTreeSet<_>>();
        // Verify every required predecessor context from canonical ancestry,
        // not just maxima: a later selector cannot erase an older exclusion
        // merely by citing a descendant of that selector's losing edge.
        // Do this without constructing
        // a second history-sized derived index. Scratch is one bounded closure
        // at a time; only the existing live cache is retained after validation.
        for id in graph.provenance_live_roots() {
            let mut ancestors = canonical
                .complete_ancestors(id, None)
                .map_err(|error| error.to_string())?;
            ancestors.insert(id);
            let mut by_subject = BTreeMap::<DeviceId, Vec<FactId>>::new();
            for ancestor in ancestors {
                if let Some(fact) = canonical.facts.get(&ancestor) {
                    if let FactBody::AuthorityLineageResolution { subject, .. } = &fact.content.body
                    {
                        by_subject
                            .entry(subject.clone())
                            .or_default()
                            .push(ancestor);
                    }
                }
            }
            for selectors in by_subject.values() {
                for selector in selectors {
                    if !contexts.contains(selector) {
                        return Err("checkpoint omits required selector provenance".into());
                    }
                }
            }
        }
        for id in graph.facts.keys() {
            let mut ancestors = canonical
                .complete_ancestors(*id, None)
                .map_err(|error| error.to_string())?;
            ancestors.insert(*id);
            for selector in &contexts {
                let Some(SignedFact { content, .. }) = canonical.facts.get(selector) else {
                    return Err("canonical selector is missing".into());
                };
                let FactBody::AuthorityLineageResolution { selected_head, .. } = &content.body
                else {
                    return Err("canonical selector is not typed".into());
                };
                let before_selected = *id == *selected_head
                    || canonical
                        .complete_ancestors(*selected_head, None)
                        .map_err(|error| error.to_string())?
                        .contains(id);
                let expected = AuthoritySelectorRelation {
                    selected: *selected_head,
                    post_selector: ancestors.contains(selector),
                    selected_before: ancestors.contains(selected_head),
                    before_selected,
                };
                let expected = (expected.post_selector
                    || expected.selected_before
                    || expected.before_selected)
                    .then_some(expected);
                if graph
                    .authority_provenance
                    .get(id)
                    .and_then(|row| row.get(selector))
                    .copied()
                    != expected
                {
                    return Err("checkpoint provenance differs from canonical ancestry".into());
                }
            }
        }
        Ok(graph)
    }

    fn decode_live_checkpoint(
        bootstrap: &VerifiedBootstrap,
        policy: crate::config::SemanticPolicyConfig,
        checkpoint: LiveFactGraphCheckpoint,
    ) -> Result<Self, String> {
        if checkpoint.version != 1 || checkpoint.context_id != bootstrap.context_id() {
            return Err("live checkpoint version or context mismatch".into());
        }
        let fact_count = checkpoint.facts.len();
        let quarantine_count = checkpoint.quarantined.len();
        let mut facts = BTreeMap::new();
        for fact in checkpoint.facts {
            fact.verify().map_err(|error| error.to_string())?;
            if fact.content.mesh_context != checkpoint.context_id
                || facts.insert(fact.id, fact).is_some()
            {
                return Err("invalid or duplicate live checkpoint fact".into());
            }
        }
        let mut quarantined = BTreeMap::new();
        for fact in checkpoint.quarantined {
            fact.verify().map_err(|error| error.to_string())?;
            if fact.content.mesh_context != checkpoint.context_id
                || facts.contains_key(&fact.id)
                || quarantined.insert(fact.id, fact).is_some()
            {
                return Err("invalid or duplicate live checkpoint quarantine".into());
            }
        }
        if facts.len() != fact_count
            || quarantined.len() != quarantine_count
            || checkpoint.admitted_fact_count < fact_count as u64
            || checkpoint.admitted_fact_count > policy.max_admitted_facts
            || quarantined.len() as u64 > policy.max_quarantined_facts
            || checkpoint.admitted_bytes > policy.max_admitted_bytes
            || checkpoint.quarantined_bytes > policy.max_quarantined_bytes
            || checkpoint
                .admitted_dependency_edges
                .checked_add(checkpoint.quarantined_dependency_edges)
                .is_none_or(|edges| edges > policy.max_dependency_edges)
        {
            return Err("live checkpoint exceeds semantic policy".into());
        }

        fn unique_map<K: Ord, V>(values: Vec<(K, V)>) -> Option<BTreeMap<K, V>> {
            let count = values.len();
            let map = values.into_iter().collect::<BTreeMap<_, _>>();
            (map.len() == count).then_some(map)
        }
        fn unique_set<T: Ord>(values: Vec<T>) -> Option<BTreeSet<T>> {
            let count = values.len();
            let set = values.into_iter().collect::<BTreeSet<_>>();
            (set.len() == count).then_some(set)
        }
        fn set_map<K: Ord, V: Ord>(values: Vec<(K, Vec<V>)>) -> Option<BTreeMap<K, BTreeSet<V>>> {
            let mut result = BTreeMap::new();
            for (key, values) in values {
                let values = unique_set(values)?;
                if result.insert(key, values).is_some() {
                    return None;
                }
            }
            Some(result)
        }

        let admission_order = checkpoint.admission_order;
        let admission_ids = unique_set(admission_order.clone())
            .ok_or_else(|| "duplicate live checkpoint admission id".to_string())?;
        if admission_ids.len() != facts.len()
            || admission_ids.iter().any(|id| !facts.contains_key(id))
        {
            return Err("live checkpoint admission order is incomplete".into());
        }
        let quarantined_by_author = unique_map(checkpoint.quarantined_by_author)
            .ok_or_else(|| "duplicate checkpoint quarantined author".to_string())?;
        let retained_by_author = unique_map(checkpoint.retained_by_author)
            .ok_or_else(|| "duplicate checkpoint retained author".to_string())?;
        let quarantine_missing = set_map(checkpoint.quarantine_missing)
            .ok_or_else(|| "invalid checkpoint missing-dependency index".to_string())?;
        let waiting_by_dependency = set_map(checkpoint.waiting_by_dependency)
            .ok_or_else(|| "invalid checkpoint waiting index".to_string())?;
        let ready_quarantine = unique_set(checkpoint.ready_quarantine)
            .ok_or_else(|| "duplicate checkpoint ready id".to_string())?;
        if ready_quarantine
            .iter()
            .any(|id| !quarantined.contains_key(id))
            || quarantine_missing
                .keys()
                .any(|id| !quarantined.contains_key(id))
        {
            return Err("checkpoint quarantine index names a non-quarantined fact".into());
        }
        let cell_heads_index = set_map(checkpoint.cell_heads)
            .ok_or_else(|| "invalid checkpoint cell heads".to_string())?;
        let authority_heads_index = set_map(checkpoint.authority_heads)
            .ok_or_else(|| "invalid checkpoint authority heads".to_string())?;
        let authority_selector_index = set_map(checkpoint.authority_selectors)
            .ok_or_else(|| "invalid checkpoint authority selectors".to_string())?;
        let mut authority_provenance = BTreeMap::new();
        for (id, entries) in checkpoint.authority_provenance {
            let row = unique_map(entries)
                .ok_or_else(|| "duplicate checkpoint selector provenance".to_string())?;
            if row.is_empty() || !facts.contains_key(&id) || authority_provenance.contains_key(&id)
            {
                return Err("invalid checkpoint provenance row coverage".into());
            }
            for (selector, relation) in &row {
                if !(relation.post_selector || relation.selected_before || relation.before_selected)
                    || !facts.contains_key(&relation.selected)
                    || !facts.get(selector).is_some_and(|fact| matches!(&fact.content.body,
                        FactBody::AuthorityLineageResolution { selected_head, cited_heads, .. }
                        if *selected_head == relation.selected && cited_heads.contains(selected_head)))
                { return Err("checkpoint provenance lacks signed typed witnesses".into()); }
            }
            authority_provenance.insert(id, row);
        }
        let cells_index =
            unique_set(checkpoint.cells).ok_or_else(|| "duplicate checkpoint cell".to_string())?;
        let stand_down_index = set_map(checkpoint.stand_down_heads)
            .ok_or_else(|| "invalid checkpoint stand-down heads".to_string())?;
        if cell_heads_index
            .values()
            .chain(authority_heads_index.values())
            .chain(stand_down_index.values())
            .flatten()
            .any(|id| !facts.contains_key(id))
        {
            return Err("checkpoint head index names a non-resident fact".into());
        }
        let projection = Projection::from_checkpoint_parts(
            checkpoint.projection_cells,
            checkpoint.projection_stand_down,
        )
        .ok_or_else(|| "duplicate checkpoint projection entry".to_string())?;
        if projection.commitment_root() != checkpoint.projection_root {
            return Err("checkpoint projection commitment mismatch".into());
        }
        let projected_ids_are_resident = projection.cells().all(|(_, value)| match value {
            super::CellProjection::Value(id) => facts.contains_key(id),
            super::CellProjection::Conflict(ids) => {
                !ids.is_empty() && ids.iter().all(|id| facts.contains_key(id))
            }
        }) && projection.stand_down_targets().all(|target| {
            projection
                .stand_down(target)
                .is_some_and(|value| facts.contains_key(&value.proof))
        });
        if !projected_ids_are_resident {
            return Err("checkpoint projection names a non-resident fact".into());
        }

        let mut graph = Self {
            facts,
            admitted_fact_count: checkpoint.admitted_fact_count,
            admission_order,
            quarantined,
            policy_limits: policy.into(),
            admitted_bytes: checkpoint.admitted_bytes,
            derived_index_bytes: checkpoint.derived_index_bytes,
            quarantined_bytes: checkpoint.quarantined_bytes,
            admitted_dependency_edges: checkpoint.admitted_dependency_edges,
            quarantined_dependency_edges: checkpoint.quarantined_dependency_edges,
            quarantined_by_author,
            retained_by_author,
            quarantine_missing,
            waiting_by_dependency,
            ready_quarantine,
            context_id: checkpoint.context_id,
            authority_roots: bootstrap.authority_roots().iter().cloned().collect(),
            policy: bootstrap.policy().clone(),
            cell_heads_index,
            authority_heads_index,
            #[cfg(test)]
            authority_dependents_index: BTreeMap::new(),
            authority_facts_index: BTreeMap::new(),
            authority_selector_index,
            authority_provenance,
            #[cfg(test)]
            dependency_index: BTreeMap::new(),
            cells_index,
            stand_down_index,
            indexed_fact_count: fact_count,
            facts_revision: checkpoint.facts_revision,
            indexed_revision: checkpoint.indexed_revision,
            generation: checkpoint.generation,
            defer_projection_commitment: false,
            cold_history_since_retirement: 0,
            staged_cold_pending: 0,
            projection_cache: Arc::new(Mutex::new(Some((checkpoint.generation, projection)))),
        };

        graph.rebuild_authority_facts_index();
        let derived_index_bytes = graph
            .logical_index_residency_bytes()
            .map_err(|error| error.to_string())?;
        if derived_index_bytes != graph.derived_index_bytes {
            return Err("checkpoint derived-index residency mismatch".into());
        }
        if graph.indexed_revision != graph.facts_revision {
            return Err("checkpoint index revision mismatch".into());
        }
        Ok(graph)
    }

    /// Retire signed bodies that are no longer needed by the live semantic
    /// continuation. The canonical rows remain in SQLite and the logical
    /// counters continue to describe the complete retained history.
    ///
    /// Current heads, one direct witness layer, active stand-down evidence,
    /// and unresolved quarantine support stay resident. This is enough for
    /// the normal continuation path; cold proof material and anti-entropy are
    /// resolved by the durable owner instead of turning the process heap into
    /// a second database.
    fn provenance_live_roots(&self) -> BTreeSet<FactId> {
        let mut roots = BTreeSet::new();
        roots.extend(self.cell_heads_index.values().flatten().copied());
        roots.extend(self.authority_heads_index.values().flatten().copied());
        roots.extend(self.stand_down_index.values().flatten().copied());
        roots.extend(
            self.quarantine_missing
                .values()
                .flatten()
                .copied()
                .filter(|id| self.facts.contains_key(id)),
        );
        roots
    }

    pub(crate) fn retire_cold_history(&mut self) {
        if self.staged_cold_pending == 0
            && (self.cold_history_since_retirement as u64)
                < self.policy_limits.max_hot_history_facts
        {
            return;
        }
        self.ensure_indexes_current();
        // Seal the complete projection before any historical body leaves the
        // map. Incremental updates carry unchanged cells forward from here.
        let projection = self.projection();
        let mut retained = BTreeSet::new();
        for ids in self.cell_heads_index.values() {
            retained.extend(ids.iter().copied());
        }
        for ids in self.authority_heads_index.values() {
            retained.extend(ids.iter().copied());
        }
        for subject in self.stand_down_index.keys() {
            if let Some(stand_down) = projection.stand_down(subject) {
                retained.insert(stand_down.proof);
            }
        }

        for missing in self.quarantine_missing.values() {
            retained.extend(missing.iter().copied());
        }

        // Context roots are live authority/projection rows, not auxiliary
        // selector witnesses. Otherwise retaining a selector's old selected
        // witness would recursively pin every obsolete selector forever.
        let mut active_selectors = BTreeSet::new();
        for id in &retained {
            let subjects = self
                .authority_provenance
                .get(id)
                .into_iter()
                .flatten()
                .filter_map(|(selector, _)| self.facts.get(selector))
                .filter_map(|fact| match &fact.content.body {
                    FactBody::AuthorityLineageResolution { subject, .. } => Some(subject.clone()),
                    _ => None,
                })
                .collect::<BTreeSet<_>>();
            for subject in subjects {
                active_selectors.extend(self.ancestral_typed_selectors(&subject, &[*id]));
            }
        }
        for selector in &active_selectors {
            retained.insert(*selector);
            if let Some(SignedFact { content, .. }) = self.facts.get(selector) {
                if let FactBody::AuthorityLineageResolution { selected_head, .. } = &content.body {
                    retained.insert(*selected_head);
                }
            }
        }

        // Keep the direct signed witness layer needed to validate the next
        // continuation. Do not recursively retain ancestry: that history is
        // precisely what SQLite owns.
        let direct_witnesses = retained
            .iter()
            .filter_map(|id| self.facts.get(id))
            .flat_map(dependencies)
            .collect::<BTreeSet<_>>();
        retained.extend(direct_witnesses);
        if self.facts.keys().all(|id| retained.contains(id)) {
            // A still-complete resident graph needs no context retirement.
            // Keep its complete provenance even when all bodies happen to be
            // live heads or direct witnesses at this threshold.
            active_selectors.extend(
                self.authority_provenance
                    .values()
                    .flat_map(|row| row.keys().copied()),
            );
        }

        self.facts.retain(|id, _| retained.contains(id));
        self.admission_order.retain(|id| retained.contains(id));
        self.rebuild_authority_facts_index();
        #[cfg(test)]
        self.rebuild_test_only_indexes();
        self.stand_down_index.retain(|_, ids| {
            ids.retain(|id| retained.contains(id));
            !ids.is_empty()
        });
        self.authority_selector_index.clear();
        for selector in &active_selectors {
            if let Some(fact) = self.facts.get(selector) {
                if let FactBody::AuthorityLineageResolution {
                    subject,
                    selected_head,
                    ..
                } = &fact.content.body
                {
                    self.authority_selector_index
                        .entry(subject.clone())
                        .or_default()
                        .insert((*selector, *selected_head));
                }
            }
        }
        self.authority_provenance.retain(|id, row| {
            row.retain(|selector, _| active_selectors.contains(selector));
            retained.contains(id) && !row.is_empty()
        });
        self.derived_index_bytes = self
            .logical_index_residency_bytes()
            .expect("retained live semantic indexes remain measurable");
        self.indexed_fact_count = self.facts.len();
        self.facts_revision = self
            .facts_revision
            .checked_add(1)
            .expect("FactGraph revision exhausted while retiring cold history");
        self.indexed_revision = self.facts_revision;
        self.cold_history_since_retirement = 0;
        self.staged_cold_pending = 0;
        *self.projection_cache.lock() = Some((self.generation, projection));
    }

    /// Seal the smallest exact continuation state for a durable restart.
    /// Unlike the amortized admission sweep, shutdown must not leave a
    /// partially filled retirement batch in the checkpoint.
    pub(crate) fn seal_live_checkpoint(&mut self) {
        self.cold_history_since_retirement =
            usize::try_from(self.policy_limits.max_hot_history_facts).unwrap_or(usize::MAX);
        self.retire_cold_history();
    }

    /// Temporarily attach an already-verified durable causal closure while a
    /// single candidate is checked. These rows are deliberately not added to
    /// the live-head indexes or logical usage counters: SQLite remains their
    /// owner and the rows exist here only for candidate-relative validation.
    fn stage_cold_history(
        &mut self,
        history: Vec<SignedFact>,
    ) -> Result<Vec<FactId>, SemanticError> {
        for fact in &history {
            fact.verify()?;
            if fact.content.mesh_context != self.context_id {
                return Err(SemanticError::ContextMismatch {
                    expected: self.context_id,
                    found: fact.content.mesh_context.to_string(),
                });
            }
        }
        let mut staged = Vec::with_capacity(history.len());
        for fact in history {
            let id = fact.id;
            if let Some(existing) = self.facts.get(&id) {
                if existing != &fact {
                    self.remove_staged_cold(&staged);
                    return Err(SemanticError::DuplicateFact(id));
                }
                continue;
            }
            if self.quarantined.contains_key(&id) {
                self.remove_staged_cold(&staged);
                return Err(SemanticError::DuplicateFact(id));
            }
            self.facts.insert(id, fact);
            staged.push(id);
        }

        // The live indexes intentionally continue to describe only the hot
        // working set. Mark that state current so admission falls through to
        // its candidate-relative causal traversal when cold rows are needed.
        self.indexed_fact_count = self.facts.len();
        self.staged_cold_pending = self.staged_cold_pending.saturating_add(staged.len());
        Ok(staged)
    }

    fn remove_staged_cold(&mut self, staged: &[FactId]) {
        if staged.is_empty() {
            return;
        }
        // Staged cleanup is the exceptional path where rebuilding indexes
        // can reorder the hot roster. Preserve the current append-only order
        // by moving its backing here; ordinary journal construction remains allocation-free with
        // respect to admission history.
        let mut admission_order = std::mem::take(&mut self.admission_order);
        let admitted_fact_count = self.admitted_fact_count;
        let admitted_bytes = self.admitted_bytes;
        let derived_index_bytes = self.derived_index_bytes;
        let admitted_dependency_edges = self.admitted_dependency_edges;
        let quarantined_bytes = self.quarantined_bytes;
        let quarantined_dependency_edges = self.quarantined_dependency_edges;
        let projection_cache = self.projection_cache.lock().clone();

        for id in staged {
            self.facts.remove(id);
        }
        self.staged_cold_pending = self.staged_cold_pending.saturating_sub(staged.len());
        admission_order.retain(|id| !staged.contains(id));
        self.facts_revision = self
            .facts_revision
            .checked_add(1)
            .expect("FactGraph revision exhausted while releasing cold history");
        self.rebuild_indexes();
        self.admission_order = admission_order;

        // Rebuilding repairs only the hot indexes. The logical counters and
        // projection still describe the complete SQLite-owned history.
        self.admitted_fact_count = admitted_fact_count;
        self.admitted_bytes = admitted_bytes;
        self.derived_index_bytes = derived_index_bytes;
        self.admitted_dependency_edges = admitted_dependency_edges;
        self.quarantined_bytes = quarantined_bytes;
        self.quarantined_dependency_edges = quarantined_dependency_edges;
        *self.projection_cache.lock() = projection_cache;
    }

    pub fn len(&self) -> usize {
        usize::try_from(self.admitted_fact_count).unwrap_or(usize::MAX)
    }

    pub(crate) fn admitted_fact_count(&self) -> u64 {
        self.admitted_fact_count
    }

    pub fn is_empty(&self) -> bool {
        self.admitted_fact_count == 0
    }

    pub fn get(&self, id: &FactId) -> Option<&SignedFact> {
        self.facts.get(id)
    }

    /// Visit the currently cached signed bodies in admission order. Cold
    /// history is deliberately absent: SQLite owns it, while this bounded hot
    /// set exists only to continue admission and support diagnostics.
    pub(crate) fn hot_facts_in_admission_order(
        &self,
    ) -> impl DoubleEndedIterator<Item = &SignedFact> {
        self.admission_order
            .iter()
            .filter_map(|id| self.facts.get(id))
    }

    pub(crate) fn hot_fact_count(&self) -> usize {
        self.facts.len()
    }

    fn indexes_current(&self) -> bool {
        self.indexed_fact_count == self.facts.len() && self.indexed_revision == self.facts_revision
    }

    /// Rebuild derived indexes in deterministic FactId order.  Loaders and
    /// compaction may populate the durable map directly; those paths never
    /// get to make an index authoritative without this repair step.
    pub(crate) fn rebuild_indexes(&mut self) {
        let preserve_cold = self.admitted_fact_count > self.facts.len() as u64;
        let prior_provenance = std::mem::take(&mut self.authority_provenance);
        let prior_selectors = if preserve_cold {
            Some(std::mem::take(&mut self.authority_selector_index))
        } else {
            None
        };
        let prior_authority_heads = if preserve_cold {
            Some(std::mem::take(&mut self.authority_heads_index))
        } else {
            None
        };
        let prior_cell_heads = if preserve_cold {
            Some(std::mem::take(&mut self.cell_heads_index))
        } else {
            None
        };
        #[cfg(test)]
        INDEX_REBUILD_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        self.cell_heads_index.clear();
        self.authority_heads_index.clear();
        #[cfg(test)]
        self.authority_dependents_index.clear();
        self.authority_facts_index.clear();
        self.authority_selector_index.clear();
        #[cfg(test)]
        self.dependency_index.clear();
        self.cells_index.clear();
        self.stand_down_index.clear();
        let ids = self.facts.keys().copied().collect::<Vec<_>>();
        for id in &ids {
            self.index_fact_metadata(*id);
        }
        // Rebuild heads in deterministic causal order.  Fact IDs are content
        // addresses, not timestamps, so ordering by ID can repeatedly walk a
        // long chain.  Kahn's bounded ready set gives restore/compaction a
        // linear dependency pass before the local head updates.
        self.cell_heads_index.clear();
        self.authority_heads_index.clear();
        let mut indegree = BTreeMap::new();
        let mut dependents = BTreeMap::<FactId, BTreeSet<FactId>>::new();
        for id in &ids {
            let fact_dependencies = self.facts.get(id).map(dependencies).unwrap_or_default();
            let count = fact_dependencies
                .iter()
                .filter(|dependency| self.facts.contains_key(dependency))
                .count();
            indegree.insert(*id, count);
            for dependency in fact_dependencies {
                if self.facts.contains_key(&dependency) {
                    dependents.entry(dependency).or_default().insert(*id);
                }
            }
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, count)| (*count == 0).then_some(*id))
            .collect::<BTreeSet<_>>();
        let mut ordered = Vec::with_capacity(ids.len());
        while let Some(id) = ready.iter().next().copied() {
            ready.remove(&id);
            ordered.push(id);
            for dependent in dependents.get(&id).into_iter().flatten() {
                let count = indegree
                    .get_mut(dependent)
                    .expect("dependency index has every admitted fact");
                *count = count
                    .checked_sub(1)
                    .expect("bulk restore dependency indegree remains positive");
                if *count == 0 {
                    ready.insert(*dependent);
                }
            }
        }
        if ordered.len() != ids.len() {
            // A corrupt loader graph remains deterministic and authority
            // negative; index the residual IDs rather than trusting a partial
            // cache.
            let ordered_ids = ordered.iter().copied().collect::<BTreeSet<_>>();
            ordered.extend(ids.iter().copied().filter(|id| !ordered_ids.contains(id)));
        }
        self.admission_order = ordered.clone();
        for id in ordered {
            self.index_fact_heads(id);
        }
        if preserve_cold {
            self.authority_provenance = prior_provenance;
            self.authority_provenance
                .retain(|id, _| self.facts.contains_key(id));
            self.authority_heads_index = prior_authority_heads.expect("cold heads moved once");
            self.cell_heads_index = prior_cell_heads.expect("cold cells moved once");
            self.authority_selector_index =
                prior_selectors.expect("cold selector index moved once");
            self.authority_selector_index.retain(|_, selectors| {
                selectors.retain(|(id, _)| self.facts.contains_key(id));
                !selectors.is_empty()
            });
        } else {
            // Complete direct-loader graphs reconstruct provenance solely from
            // signed ancestry. No preexisting cache can bless a changed body.
            let selectors = self
                .facts
                .iter()
                .filter_map(|(id, fact)| {
                    matches!(
                        fact.content.body,
                        FactBody::AuthorityLineageResolution { .. }
                    )
                    .then_some(*id)
                })
                .collect::<Vec<_>>();
            for selector in selectors {
                if let Some(fact) = self.facts.get(&selector) {
                    if let Ok(provenance) = self.planned_provenance(fact) {
                        self.authority_provenance.extend(provenance);
                    }
                }
            }
        }
        self.indexed_fact_count = self.facts.len();
        self.indexed_revision = self.facts_revision;
        self.admitted_fact_count = u64::try_from(self.facts.len()).unwrap_or(u64::MAX);
        // The maps are derived from the canonical fact set.  Reconcile the
        // scalar ownership ledger at the same boundary so a loader or
        // compaction path cannot leave bytes/edge counters from an older
        // graph attached to the rebuilt indexes.  An overflow poisons the
        // scalar with the closed sentinel; the next checked admission then
        // refuses instead of silently underfunding the graph.
        if let Ok((admitted_bytes, quarantined_bytes, admitted_edges, quarantined_edges)) =
            self.reconciled_fact_totals()
        {
            self.admitted_bytes = admitted_bytes;
            self.quarantined_bytes = quarantined_bytes;
            self.admitted_dependency_edges = admitted_edges;
            self.quarantined_dependency_edges = quarantined_edges;
        } else {
            self.admitted_bytes = u64::MAX;
            self.quarantined_bytes = u64::MAX;
            self.admitted_dependency_edges = u64::MAX;
            self.quarantined_dependency_edges = u64::MAX;
        }
        self.derived_index_bytes = self.logical_index_residency_bytes().unwrap_or(u64::MAX);
        *self.projection_cache.lock() = None;
    }

    /// Return the complete canonical dependency edge set for one admitted row.
    /// It includes content parents, evidence/cited heads, and every declared
    /// AuthorityUse predecessor; callers must not persist parents alone.
    pub(crate) fn canonical_dependency_edges(&self, id: &FactId) -> Option<Vec<FactId>> {
        self.indexes_current()
            .then(|| self.facts.get(id).map(dependencies))
            .flatten()
    }

    /// Deterministically restore a snapshot without making database row order
    /// authoritative. Facts are verified, dependency-complete, topologically
    /// ordered, and then admitted through the normal checked path. The ready
    /// batch remains bounded by the same policy as ordinary ingress; unresolved
    /// rows are admitted afterward and are never silently promoted here.
    #[cfg(test)]
    pub(crate) fn bulk_restore_admitted(
        &mut self,
        admitted: Vec<SignedFact>,
        quarantined: Vec<SignedFact>,
    ) -> Result<(), SemanticError> {
        self.ensure_indexes_current();
        let mut rollback = GraphRollback::new(self);
        for fact in admitted.iter().chain(quarantined.iter()) {
            rollback.capture_admission(self, fact);
        }
        let result = self.bulk_restore_admitted_inner(admitted, quarantined);
        if result.is_err() {
            rollback.restore(self);
        }
        result
    }

    #[cfg(test)]
    fn bulk_restore_admitted_inner(
        &mut self,
        admitted: Vec<SignedFact>,
        quarantined: Vec<SignedFact>,
    ) -> Result<(), SemanticError> {
        let mut batch = BTreeMap::<FactId, SignedFact>::new();
        for fact in admitted {
            fact.verify()?;
            if fact.content.mesh_context != self.context_id {
                return Err(SemanticError::ContextMismatch {
                    expected: self.context_id,
                    found: fact.content.mesh_context.to_string(),
                });
            }
            let fact_id = fact.id;
            if batch.insert(fact_id, fact).is_some() {
                return Err(SemanticError::DuplicateFact(fact_id));
            }
        }
        let batch_ids = batch.keys().copied().collect::<BTreeSet<_>>();
        let mut indegree = BTreeMap::<FactId, usize>::new();
        let mut dependents = BTreeMap::<FactId, BTreeSet<FactId>>::new();
        for (id, fact) in &batch {
            let edges = dependencies(fact);
            for dependency in &edges {
                if !batch_ids.contains(dependency) && !self.facts.contains_key(dependency) {
                    return Err(SemanticError::MissingParent(*dependency));
                }
            }
            let count = edges
                .iter()
                .filter(|dependency| batch_ids.contains(dependency))
                .count();
            indegree.insert(*id, count);
            for dependency in edges {
                if batch_ids.contains(&dependency) {
                    dependents.entry(dependency).or_default().insert(*id);
                }
            }
        }
        let mut ready = indegree
            .iter()
            .filter_map(|(id, count)| (*count == 0).then_some(*id))
            .collect::<BTreeSet<_>>();
        let mut order = Vec::with_capacity(batch.len());
        while let Some(id) = ready.iter().next().copied() {
            ready.remove(&id);
            order.push(id);
            for dependent in dependents.get(&id).into_iter().flatten() {
                let count = indegree
                    .get_mut(dependent)
                    .expect("bulk restore dependency index is complete");
                *count = count
                    .checked_sub(1)
                    .expect("rebuild dependency indegree remains positive");
                if *count == 0 {
                    ready.insert(*dependent);
                }
            }
        }
        if order.len() != batch.len() {
            return Err(SemanticError::Cycle);
        }
        for id in order {
            self.admit_inner(
                batch.remove(&id).expect("bulk restore order has row"),
                false,
            )?;
        }
        for fact in quarantined {
            fact.verify()?;
            match self.admit_inner(fact, false)? {
                Admission::Quarantined { .. } => {}
                Admission::AlreadyPresent | Admission::Inserted => {
                    return Err(SemanticError::DomainMismatch)
                }
            }
        }
        Ok(())
    }

    fn ensure_indexes_current(&mut self) {
        if !self.indexes_current() {
            self.rebuild_indexes();
        }
    }

    fn index_fact(&mut self, fact_id: FactId) {
        if !self.facts.contains_key(&fact_id) {
            return;
        }
        self.index_fact_metadata(fact_id);
        self.index_fact_heads(fact_id);
    }

    fn indexed_authority_subjects(fact: &SignedFact) -> BTreeSet<DeviceId> {
        fact.content
            .authority_uses
            .iter()
            .filter(|authority_use| {
                !Self::is_payload_local_resolution(
                    &fact.content.body,
                    &fact.content.author,
                    &authority_use.subject,
                )
            })
            .map(|authority_use| authority_use.subject.clone())
            .collect()
    }

    fn index_authority_fact_subjects(&mut self, fact_id: FactId) {
        let Some(fact) = self.facts.get(&fact_id) else {
            return;
        };
        for subject in Self::indexed_authority_subjects(fact) {
            self.authority_facts_index
                .entry(subject)
                .or_default()
                .insert(fact_id);
        }
    }

    fn rebuild_authority_facts_index(&mut self) {
        self.authority_facts_index.clear();
        let fact_ids = self.facts.keys().copied().collect::<Vec<_>>();
        for fact_id in fact_ids {
            self.index_authority_fact_subjects(fact_id);
        }
    }

    #[cfg(test)]
    fn rebuild_test_only_indexes(&mut self) {
        self.authority_dependents_index.clear();
        self.dependency_index.clear();
        let fact_ids = self.facts.keys().copied().collect::<Vec<_>>();
        for fact_id in fact_ids {
            let Some(fact) = self.facts.get(&fact_id) else {
                continue;
            };
            self.dependency_index.insert(fact_id, dependencies(fact));
            for authority_use in &fact.content.authority_uses {
                if Self::is_payload_local_resolution(
                    &fact.content.body,
                    &fact.content.author,
                    &authority_use.subject,
                ) {
                    continue;
                }
                for predecessor in &authority_use.predecessors {
                    self.authority_dependents_index
                        .entry((authority_use.subject.clone(), *predecessor))
                        .or_default()
                        .insert(fact_id);
                }
            }
        }
    }

    fn index_fact_metadata(&mut self, fact_id: FactId) {
        let Some(fact) = self.facts.get(&fact_id) else {
            return;
        };
        let authority_subjects = Self::indexed_authority_subjects(fact);
        for subject in authority_subjects {
            self.authority_facts_index
                .entry(subject)
                .or_default()
                .insert(fact_id);
        }
        let cells = fact
            .content
            .body
            .exclusive_cells()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let stand_down = match &fact.content.body {
            FactBody::EvictionProof { target, .. } => Some(target.clone()),
            FactBody::SelfStandDown { device_id, .. } => Some(device_id.clone()),
            _ => None,
        };
        #[cfg(test)]
        {
            self.dependency_index.insert(fact_id, dependencies(fact));
            for authority_use in &fact.content.authority_uses {
                if Self::is_payload_local_resolution(
                    &fact.content.body,
                    &fact.content.author,
                    &authority_use.subject,
                ) {
                    continue;
                }
                for predecessor in &authority_use.predecessors {
                    self.authority_dependents_index
                        .entry((authority_use.subject.clone(), *predecessor))
                        .or_default()
                        .insert(fact_id);
                }
            }
        }
        for cell in &cells {
            self.cells_index.insert(cell.clone());
        }
        if let Some(target) = stand_down {
            self.stand_down_index
                .entry(target)
                .or_default()
                .insert(fact_id);
        }
        if let FactBody::AuthorityLineageResolution {
            subject,
            selected_head,
            ..
        } = &fact.content.body
        {
            self.authority_selector_index
                .entry(subject.clone())
                .or_default()
                .insert((fact_id, *selected_head));
        }
    }

    fn index_fact_heads(&mut self, fact_id: FactId) {
        let Some(fact) = self.facts.get(&fact_id) else {
            return;
        };
        let cells = fact
            .content
            .body
            .exclusive_cells()
            .into_iter()
            .collect::<BTreeSet<_>>();
        let authority_subjects = fact
            .content
            .body
            .authority_use_subjects(&fact.content.author);
        for cell in cells {
            let mut heads = self.cell_heads_index.remove(&cell).unwrap_or_default();
            insert_maximal_head(&self.facts, &mut heads, fact_id);
            self.cell_heads_index.insert(cell, heads);
        }
        for subject in authority_subjects {
            if Self::is_payload_local_resolution(&fact.content.body, &fact.content.author, &subject)
            {
                continue;
            }
            let mut heads = self
                .authority_heads_index
                .remove(&subject)
                .unwrap_or_default();
            insert_maximal_head(&self.facts, &mut heads, fact_id);
            self.authority_heads_index.insert(subject, heads);
        }
    }

    pub(crate) fn indexed_cells(&self) -> BTreeSet<ExclusiveCell> {
        if self.indexes_current() {
            return self.cells_index.clone();
        }
        self.facts
            .values()
            .flat_map(|fact| fact.content.body.exclusive_cells())
            .collect()
    }

    pub(crate) fn indexed_stand_down_candidates(&self) -> BTreeMap<DeviceId, BTreeSet<FactId>> {
        if self.indexes_current() {
            return self.stand_down_index.clone();
        }
        let mut candidates = BTreeMap::new();
        for (id, fact) in &self.facts {
            let target = match &fact.content.body {
                FactBody::EvictionProof { target, .. } => Some(target),
                FactBody::SelfStandDown { device_id, .. } => Some(device_id),
                _ => None,
            };
            if let Some(target) = target {
                candidates
                    .entry(target.clone())
                    .or_insert_with(BTreeSet::new)
                    .insert(*id);
            }
        }
        candidates
    }

    pub(crate) fn indexed_stand_down_candidates_for(
        &self,
        target: &DeviceId,
    ) -> Option<&BTreeSet<FactId>> {
        self.indexes_current()
            .then(|| self.stand_down_index.get(target))
            .flatten()
    }

    /// Return the exact projection/roster subjects touched by a bounded
    /// journal delta.  The lookup starts from changed facts and the maintained
    /// subject-scoped reverse witness index; it never enumerates the whole
    /// ledger.
    fn projection_impact_for_facts_with_staged(
        &self,
        fact_ids: impl IntoIterator<Item = FactId>,
        staged_cold: &[FactId],
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        let mut cells = BTreeSet::new();
        let mut subjects = BTreeSet::new();
        for fact_id in fact_ids {
            let Some(fact) = self.facts.get(&fact_id) else {
                continue;
            };
            let (fact_cells, fact_subjects) =
                self.projection_impact_for_fact_with_staged(fact, staged_cold);
            cells.extend(fact_cells);
            subjects.extend(fact_subjects);
        }
        (cells, subjects)
    }

    fn authority_resolution_selection(body: &FactBody, subject: &DeviceId) -> Option<FactId> {
        match body {
            FactBody::AuthorityLineageResolution {
                subject: selected_subject,
                selected_head,
                ..
            } if selected_subject == subject => Some(*selected_head),
            FactBody::Resolution {
                cell:
                    ExclusiveCell::Role {
                        subject: cell_subject,
                    },
                selected_head,
                ..
            } if cell_subject == subject => Some(*selected_head),
            _ => None,
        }
    }

    /// Collect only cells on an authority branch that a typed resolution can
    /// change.  The reverse witness index follows exact subject-scoped
    /// AuthorityUse edges, including descendants of both the selected and
    /// losing branches whose authority status changes at the resolution.
    fn authority_branch_impact_with_staged(
        &self,
        subject: &DeviceId,
        seeds: impl IntoIterator<Item = FactId>,
        staged_cold: &[FactId],
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        // Resolutions are rare. Build subject-local reverse edges for the
        // duration of this operation instead of retaining an O(history)
        // predecessor tree beside the compact subject index for every
        // ordinary admission.
        let mut dependents_by_predecessor = BTreeMap::<FactId, Vec<FactId>>::new();
        // Cold rows staged from SQLite remain outside the live subject index.
        // Borrow only their bounded subject edges for this calculation and
        // deduplicate them against resident rows; do not promote or charge
        // the temporary overlay as live index residency.
        let mut candidate_ids = BTreeSet::new();
        candidate_ids.extend(
            self.authority_facts_index
                .get(subject)
                .into_iter()
                .flatten()
                .copied(),
        );
        for fact_id in staged_cold {
            let Some(fact) = self.facts.get(fact_id) else {
                continue;
            };
            if fact.content.authority_uses.iter().any(|authority_use| {
                authority_use.subject == *subject
                    && !Self::is_payload_local_resolution(
                        &fact.content.body,
                        &fact.content.author,
                        subject,
                    )
            }) {
                candidate_ids.insert(*fact_id);
            }
        }
        for fact_id in candidate_ids {
            let Some(fact) = self.facts.get(&fact_id) else {
                continue;
            };
            #[cfg(test)]
            record_graph_work(|work| {
                work.authority_fact_rows = work.authority_fact_rows.saturating_add(1);
            });
            for authority_use in &fact.content.authority_uses {
                #[cfg(test)]
                record_graph_work(|work| {
                    work.authority_uses_examined = work.authority_uses_examined.saturating_add(1);
                });
                if authority_use.subject != *subject
                    || Self::is_payload_local_resolution(
                        &fact.content.body,
                        &fact.content.author,
                        subject,
                    )
                {
                    continue;
                }
                for predecessor in &authority_use.predecessors {
                    #[cfg(test)]
                    record_graph_work(|work| {
                        work.authority_edges_followed =
                            work.authority_edges_followed.saturating_add(1);
                    });
                    dependents_by_predecessor
                        .entry(*predecessor)
                        .or_default()
                        .push(fact_id);
                }
            }
        }
        let mut cells = BTreeSet::new();
        let mut subjects = BTreeSet::new();
        let mut pending = seeds.into_iter().collect::<Vec<_>>();
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(fact) = self.facts.get(&id) else {
                continue;
            };
            #[cfg(test)]
            record_graph_work(|work| {
                work.authority_branch_nodes = work.authority_branch_nodes.saturating_add(1);
            });
            for cell in fact.content.body.exclusive_cells() {
                if let ExclusiveCell::Role {
                    subject: cell_subject,
                }
                | ExclusiveCell::Membership {
                    subject: cell_subject,
                } = &cell
                {
                    subjects.insert(cell_subject.clone());
                }
                cells.insert(cell);
            }
            match &fact.content.body {
                FactBody::EvictionProof { target, .. }
                | FactBody::SelfStandDown {
                    device_id: target, ..
                }
                | FactBody::Evict { target } => {
                    subjects.insert(target.clone());
                }
                _ => {}
            }
            if let Some(dependents) = dependents_by_predecessor.get(&id) {
                pending.extend(dependents.iter().copied());
            }
        }
        (cells, subjects)
    }

    fn ordinary_authority_fork_impact_with_staged(
        &self,
        fact: &SignedFact,
        subject: &DeviceId,
        staged_cold: &[FactId],
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        // A resident linear current-head transition already has its own cell
        // in the caller's impact set. Cold overlay rows are a conservative
        // subject-participant superset, not proven maximal heads, and may
        // require the bounded subject sweep even for a linear hydrated chain.
        let mut heads = BTreeSet::new();
        heads.extend(
            self.authority_heads_index
                .get(subject)
                .into_iter()
                .flatten()
                .copied(),
        );
        for fact_id in staged_cold {
            let Some(staged) = self.facts.get(fact_id) else {
                continue;
            };
            if Self::indexed_authority_subjects(staged).contains(subject) {
                heads.insert(*fact_id);
            }
        }
        let candidate_dependencies = dependencies(fact);
        let needs_branch_impact = heads
            .iter()
            .any(|head| *head != fact.id && !candidate_dependencies.contains(head));
        if !needs_branch_impact {
            return (BTreeSet::new(), BTreeSet::new());
        }
        // Once a new incomparable head is admitted, every subject-indexed
        // authority fact is a possible participant in the invalidated branch
        // set. Seed the bounded walk with that deduplicated subject-local set,
        // not merely the latest head: an A->B->C history can have B outside
        // the reverse descendants of C while still losing authority at the
        // new fork. Staged rows are borrowed into the same exceptional sweep.
        self.authority_participant_impact_with_staged(subject, heads, staged_cold)
    }

    fn authority_participant_impact_with_staged(
        &self,
        subject: &DeviceId,
        seeds: impl IntoIterator<Item = FactId>,
        staged_cold: &[FactId],
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        // An exceptional selection can change ancestor propositions as well
        // as descendants. In particular, selecting between cell-less typed
        // selectors must revisit their older membership/role participants.
        // Seed the existing walk from the bounded subject index and borrowed
        // canonical overlay, even if the selectors are not resident yet
        // (aggregate preplanning). No new retained reverse index is needed.
        let mut participating = seeds.into_iter().collect::<BTreeSet<_>>();
        participating.extend(
            self.authority_facts_index
                .get(subject)
                .into_iter()
                .flatten()
                .copied(),
        );
        for fact_id in staged_cold {
            let Some(staged) = self.facts.get(fact_id) else {
                continue;
            };
            if Self::indexed_authority_subjects(staged).contains(subject) {
                participating.insert(*fact_id);
            }
        }
        self.authority_branch_impact_with_staged(subject, participating, staged_cold)
    }

    #[cfg(test)]
    fn projection_impact_for_fact(
        &self,
        fact: &SignedFact,
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        self.projection_impact_for_fact_with_staged(fact, &[])
    }

    fn provenance_row_bytes(&self, row: &AuthorityProvenanceRow) -> Result<u64, SemanticError> {
        self.checked_entry_bytes(
            self.checked_size::<(FactId, AuthorityProvenanceRow)>()?,
            0,
            row.len(),
            self.checked_size::<(FactId, AuthoritySelectorRelation)>()?,
        )
    }

    fn planned_provenance(&self, fact: &SignedFact) -> Result<AuthorityProvenance, SemanticError> {
        let mut changes = BTreeMap::new();
        // A quarantined candidate owns no admitted provenance yet. Its
        // eventual promotion is costed again against the complete parents.
        if dependencies(fact)
            .iter()
            .any(|id| !self.facts.contains_key(id))
        {
            return Ok(changes);
        }
        let mut planned_bytes = 0;
        let mut row = self
            .authority_provenance
            .get(&fact.id)
            .cloned()
            .unwrap_or_default();
        for parent in &fact.content.parents {
            if let Some(provenance) = self.authority_provenance.get(parent) {
                for (selector, relation) in provenance {
                    if relation.post_selector || relation.selected_before {
                        let entry = row.entry(*selector).or_insert(AuthoritySelectorRelation {
                            selected: relation.selected,
                            post_selector: false,
                            selected_before: false,
                            before_selected: false,
                        });
                        entry.post_selector |= relation.post_selector;
                        entry.selected_before |= relation.selected_before;
                    }
                }
            }
        }
        if !row.is_empty() {
            planned_bytes = self.provenance_row_bytes(&row)?;
            self.check_capacity(
                super::SemanticCapacityDimension::AdmittedBytes,
                planned_bytes,
                self.policy_limits.max_database_bytes,
            )?;
            changes.insert(fact.id, row);
        }
        let mut contexts = BTreeMap::new();
        if let FactBody::AuthorityLineageResolution { selected_head, .. } = &fact.content.body {
            contexts.insert(fact.id, *selected_head);
        }
        if self.staged_cold_pending != 0 {
            for id in self.complete_ancestors(fact.id, Some(fact))? {
                if let Some(stored) = self.facts.get(&id) {
                    if let FactBody::AuthorityLineageResolution { selected_head, .. } =
                        &stored.content.body
                    {
                        contexts.insert(id, *selected_head);
                    }
                }
            }
            for (selector, selected) in self.authority_selector_index.values().flatten() {
                contexts.insert(*selector, *selected);
            }
        }
        for (selector, selected) in contexts {
            // Newly introduced/reintroduced anchors are computed over the
            // bounded canonical overlay, not guessed across a missing edge.
            let selected_ancestors = self.complete_ancestors(selected, Some(fact))?;
            let ids = if selector == fact.id || self.staged_cold_pending != 0 {
                self.facts
                    .keys()
                    .copied()
                    .chain(std::iter::once(fact.id))
                    .collect::<BTreeSet<_>>()
            } else {
                BTreeSet::from([fact.id])
            };
            for id in ids {
                let ancestors = self.complete_ancestors(id, Some(fact))?;
                let relation = AuthoritySelectorRelation {
                    selected,
                    post_selector: id == selector || ancestors.contains(&selector),
                    selected_before: id == selected || ancestors.contains(&selected),
                    before_selected: id == selected || selected_ancestors.contains(&id),
                };
                if relation.post_selector || relation.selected_before || relation.before_selected {
                    let prior = changes
                        .get(&id)
                        .or_else(|| self.authority_provenance.get(&id));
                    let base = if changes.contains_key(&id) {
                        0
                    } else {
                        match prior {
                            Some(row) => self.provenance_row_bytes(row)?,
                            None => self.checked_size::<(FactId, AuthorityProvenanceRow)>()?,
                        }
                    };
                    let added = if prior.is_some_and(|row| row.contains_key(&selector)) {
                        0
                    } else {
                        self.checked_size::<(FactId, AuthoritySelectorRelation)>()?
                    };
                    let next = self
                        .checked_add_bytes(planned_bytes, self.checked_add_bytes(base, added)?)?;
                    self.check_capacity(
                        super::SemanticCapacityDimension::AdmittedBytes,
                        next,
                        self.policy_limits.max_database_bytes,
                    )?;
                    let entry = changes.entry(id).or_insert_with(|| {
                        self.authority_provenance
                            .get(&id)
                            .cloned()
                            .unwrap_or_default()
                    });
                    entry.insert(selector, relation);
                    planned_bytes = next;
                }
            }
        }
        let mut bytes = 0;
        for row in changes.values() {
            bytes = self.checked_add_bytes(bytes, self.provenance_row_bytes(row)?)?;
            self.check_capacity(
                super::SemanticCapacityDimension::AdmittedBytes,
                bytes,
                self.policy_limits.max_database_bytes,
            )?;
        }
        Ok(changes)
    }

    fn rebuild_provenance_checked(&mut self) -> Result<(), SemanticError> {
        let selectors = self
            .facts
            .iter()
            .filter_map(|(id, fact)| {
                matches!(
                    fact.content.body,
                    FactBody::AuthorityLineageResolution { .. }
                )
                .then_some(*id)
            })
            .collect::<Vec<_>>();
        for selector in selectors {
            let fact = self
                .facts
                .get(&selector)
                .expect("collected selector remains owned");
            let changes = self.planned_provenance(fact)?;
            self.authority_provenance.extend(changes);
        }
        self.derived_index_bytes = self.logical_index_residency_bytes()?;
        Ok(())
    }

    fn cold_provenance_index_reserve(&self, fact: &SignedFact) -> Result<u64, SemanticError> {
        if self.staged_cold_pending == 0 {
            return Ok(0);
        }
        let plan = self.planned_provenance(fact)?;
        let mut retained = self.provenance_live_roots();
        retained.insert(fact.id);
        for row in plan.values() {
            for (selector, relation) in row {
                retained.insert(*selector);
                retained.insert(relation.selected);
            }
        }
        let witnesses = retained
            .iter()
            .filter_map(|id| {
                if *id == fact.id {
                    Some(fact)
                } else {
                    self.facts.get(id)
                }
            })
            .flat_map(dependencies)
            .collect::<BTreeSet<_>>();
        retained.extend(witnesses);
        let mut new_subjects = BTreeSet::new();
        let mut bytes = 0;
        let contexts = plan
            .values()
            .flat_map(|row| row.keys().copied())
            .collect::<BTreeSet<_>>();
        let mut selector_subjects = BTreeSet::new();
        for selector in contexts {
            if selector == fact.id {
                continue;
            }
            let Some(stored) = self.facts.get(&selector) else {
                continue;
            };
            if let FactBody::AuthorityLineageResolution {
                subject,
                selected_head,
                ..
            } = &stored.content.body
            {
                if !self
                    .authority_selector_index
                    .get(subject)
                    .is_some_and(|ids| ids.contains(&(selector, *selected_head)))
                {
                    bytes =
                        self.checked_add_bytes(bytes, self.checked_size::<(FactId, FactId)>()?)?;
                    if !self.authority_selector_index.contains_key(subject)
                        && selector_subjects.insert(subject.clone())
                    {
                        bytes = self.checked_add_bytes(
                            bytes,
                            self.checked_add_bytes(
                                self.checked_size::<(DeviceId, BTreeSet<(FactId, FactId)>)>()?,
                                self.device_dynamic_bytes(subject)?,
                            )?,
                        )?;
                    }
                }
            }
        }
        for id in retained {
            if id == fact.id {
                continue;
            } // ordinary candidate cost already owns these entries
            let Some(stored) = self.facts.get(&id) else {
                continue;
            };
            for subject in Self::indexed_authority_subjects(stored) {
                if self
                    .authority_facts_index
                    .get(&subject)
                    .is_some_and(|ids| ids.contains(&id))
                {
                    continue;
                }
                bytes = self.checked_add_bytes(bytes, self.checked_size::<FactId>()?)?;
                if !self.authority_facts_index.contains_key(&subject)
                    && new_subjects.insert(subject.clone())
                {
                    bytes = self.checked_add_bytes(
                        bytes,
                        self.checked_add_bytes(
                            self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                            self.device_dynamic_bytes(&subject)?,
                        )?,
                    )?;
                }
            }
        }
        Ok(bytes)
    }

    fn complete_ancestors(
        &self,
        id: FactId,
        candidate: Option<&SignedFact>,
    ) -> Result<BTreeSet<FactId>, SemanticError> {
        let mut pending = vec![id];
        let mut seen = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if !seen.insert(next) {
                continue;
            }
            let fact = candidate
                .filter(|fact| fact.id == next)
                .or_else(|| self.facts.get(&next))
                .ok_or(SemanticError::MissingParent(next))?;
            pending.extend(fact.content.parents.iter().copied());
        }
        seen.remove(&id);
        Ok(seen)
    }

    fn provenance_residency_delta(
        &self,
        fact: &SignedFact,
    ) -> Result<IndexResidencyDelta, SemanticError> {
        let mut delta = IndexResidencyDelta::default();
        for (id, row) in self.planned_provenance(fact)? {
            if let Some(previous) = self.authority_provenance.get(&id) {
                self.remove_index_residency(&mut delta, self.provenance_row_bytes(previous)?)?;
            }
            self.add_index_residency(&mut delta, self.provenance_row_bytes(&row)?)?;
        }
        Ok(delta)
    }

    fn projection_impact_for_fact_with_staged(
        &self,
        fact: &SignedFact,
        staged_cold: &[FactId],
    ) -> (BTreeSet<ExclusiveCell>, BTreeSet<DeviceId>) {
        let mut cells = BTreeSet::new();
        let mut subjects = BTreeSet::new();
        let fact_cells = fact.content.body.exclusive_cells();
        cells.extend(fact_cells.iter().cloned());
        for cell in &fact_cells {
            match cell {
                ExclusiveCell::Role { subject } | ExclusiveCell::Membership { subject } => {
                    subjects.insert(subject.clone());
                }
                ExclusiveCell::Decision { .. } => {}
            }
        }
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            subjects.insert(subject.clone());
            if let Some(_selected) =
                Self::authority_resolution_selection(&fact.content.body, &subject)
            {
                let seeds = fact
                    .content
                    .authority_uses
                    .iter()
                    .find(|authority_use| authority_use.subject == subject)
                    .into_iter()
                    .flat_map(|authority_use| authority_use.predecessors.iter().copied());
                let (branch_cells, branch_subjects) = if matches!(
                    fact.content.body,
                    FactBody::AuthorityLineageResolution { .. }
                ) {
                    self.authority_participant_impact_with_staged(&subject, seeds, staged_cold)
                } else {
                    self.authority_branch_impact_with_staged(&subject, seeds, staged_cold)
                };
                cells.extend(branch_cells);
                subjects.extend(branch_subjects);
            } else if !Self::is_payload_local_resolution(
                &fact.content.body,
                &fact.content.author,
                &subject,
            ) {
                let (branch_cells, branch_subjects) =
                    self.ordinary_authority_fork_impact_with_staged(fact, &subject, staged_cold);
                cells.extend(branch_cells);
                subjects.extend(branch_subjects);
            }
        }
        match &fact.content.body {
            FactBody::EvictionProof { target, .. }
            | FactBody::SelfStandDown {
                device_id: target, ..
            }
            | FactBody::Evict { target } => {
                subjects.insert(target.clone());
            }
            _ => {}
        }
        (cells, subjects)
    }

    fn indexed_dependencies(&self, id: &FactId) -> Option<Vec<FactId>> {
        self.indexes_current()
            .then(|| self.facts.get(id).map(dependencies))
            .flatten()
    }

    pub fn ids(&self) -> impl Iterator<Item = &FactId> {
        self.facts.keys()
    }

    /// Return canonical fact ids strictly after an optional cursor. The
    /// cursor is a stable page boundary for bounded anti-entropy producers:
    /// facts inserted before it may be repaired by a later pass, while facts
    /// after it are observed in deterministic key order.
    pub fn ids_after(&self, cursor: Option<FactId>) -> impl Iterator<Item = &FactId> {
        let start = cursor.map_or(Bound::Unbounded, Bound::Excluded);
        self.facts
            .range((start, Bound::Unbounded))
            .map(|(id, _)| id)
    }

    fn accounting_error(&self) -> SemanticError {
        SemanticError::CapacityExceeded {
            dimension: super::SemanticCapacityDimension::AdmittedBytes,
            limit: self.policy_limits.max_database_bytes,
            observed: u64::MAX,
        }
    }

    fn checked_len(&self, value: usize) -> Result<u64, SemanticError> {
        u64::try_from(value).map_err(|_| self.accounting_error())
    }

    fn checked_size<T>(&self) -> Result<u64, SemanticError> {
        self.checked_len(size_of::<T>())
    }

    fn checked_add_bytes(&self, left: u64, right: u64) -> Result<u64, SemanticError> {
        left.checked_add(right)
            .ok_or_else(|| self.accounting_error())
    }

    fn checked_mul_bytes(&self, left: u64, right: u64) -> Result<u64, SemanticError> {
        left.checked_mul(right)
            .ok_or_else(|| self.accounting_error())
    }

    fn checked_entry_bytes(
        &self,
        inline_bytes: u64,
        dynamic_bytes: u64,
        value_count: usize,
        value_bytes: u64,
    ) -> Result<u64, SemanticError> {
        let values = self.checked_mul_bytes(self.checked_len(value_count)?, value_bytes)?;
        self.checked_add_bytes(self.checked_add_bytes(inline_bytes, dynamic_bytes)?, values)
    }

    fn device_dynamic_bytes(&self, device: &DeviceId) -> Result<u64, SemanticError> {
        let _ = device;
        Ok(0)
    }

    fn cell_dynamic_bytes(&self, cell: &ExclusiveCell) -> Result<u64, SemanticError> {
        match cell {
            ExclusiveCell::Role { subject } | ExclusiveCell::Membership { subject } => {
                self.device_dynamic_bytes(subject)
            }
            ExclusiveCell::Decision { .. } => Ok(0),
        }
    }

    fn logical_index_residency_bytes(&self) -> Result<u64, SemanticError> {
        #[cfg(test)]
        RESIDENCY_SCAN_COUNT.with(|count| count.set(count.get().saturating_add(1)));
        let mut total = 0;
        for (cell, heads) in &self.cell_heads_index {
            let entry = self.checked_entry_bytes(
                self.checked_size::<(ExclusiveCell, BTreeSet<FactId>)>()?,
                self.cell_dynamic_bytes(cell)?,
                heads.len(),
                self.checked_size::<FactId>()?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        for (subject, heads) in &self.authority_heads_index {
            let entry = self.checked_entry_bytes(
                self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                self.device_dynamic_bytes(subject)?,
                heads.len(),
                self.checked_size::<FactId>()?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        for (subject, facts) in &self.authority_facts_index {
            let entry = self.checked_entry_bytes(
                self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                self.device_dynamic_bytes(subject)?,
                facts.len(),
                self.checked_size::<FactId>()?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        for (subject, selectors) in &self.authority_selector_index {
            let entry = self.checked_entry_bytes(
                self.checked_size::<(DeviceId, BTreeSet<(FactId, FactId)>)>()?,
                self.device_dynamic_bytes(subject)?,
                selectors.len(),
                self.checked_size::<(FactId, FactId)>()?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        for row in self.authority_provenance.values() {
            total = self.checked_add_bytes(total, self.provenance_row_bytes(row)?)?;
        }
        for cell in &self.cells_index {
            let entry = self.checked_add_bytes(
                self.checked_size::<ExclusiveCell>()?,
                self.cell_dynamic_bytes(cell)?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        for (target, proofs) in &self.stand_down_index {
            let entry = self.checked_entry_bytes(
                self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                self.device_dynamic_bytes(target)?,
                proofs.len(),
                self.checked_size::<FactId>()?,
            )?;
            total = self.checked_add_bytes(total, entry)?;
        }
        Ok(total)
    }

    fn add_index_residency(
        &self,
        delta: &mut IndexResidencyDelta,
        bytes: u64,
    ) -> Result<(), SemanticError> {
        delta.added = self.checked_add_bytes(delta.added, bytes)?;
        Ok(())
    }

    fn remove_index_residency(
        &self,
        delta: &mut IndexResidencyDelta,
        bytes: u64,
    ) -> Result<(), SemanticError> {
        delta.removed = self.checked_add_bytes(delta.removed, bytes)?;
        Ok(())
    }

    fn head_replacement_residency_delta(
        &self,
        delta: &mut IndexResidencyDelta,
        heads: Option<&BTreeSet<FactId>>,
        direct_dependencies: &[FactId],
        map_inline_bytes: u64,
        map_dynamic_bytes: u64,
    ) -> Result<(), SemanticError> {
        if heads.is_none() {
            self.add_index_residency(
                delta,
                self.checked_add_bytes(map_inline_bytes, map_dynamic_bytes)?,
            )?;
        }
        self.add_index_residency(delta, self.checked_size::<FactId>()?)?;
        let removed_heads = heads
            .into_iter()
            .flatten()
            .filter(|head| signed_head_is_dominated(&self.facts, direct_dependencies, head))
            .count();
        let removed_bytes = self.checked_mul_bytes(
            self.checked_len(removed_heads)?,
            self.checked_size::<FactId>()?,
        )?;
        self.remove_index_residency(delta, removed_bytes)
    }

    fn exact_index_residency_delta(
        &self,
        fact: &SignedFact,
    ) -> Result<IndexResidencyDelta, SemanticError> {
        let mut delta = IndexResidencyDelta::default();
        let direct_dependencies = dependencies(fact);

        let cells = fact
            .content
            .body
            .exclusive_cells()
            .into_iter()
            .collect::<BTreeSet<_>>();
        for cell in &cells {
            if !self.cells_index.contains(cell) {
                self.add_index_residency(
                    &mut delta,
                    self.checked_add_bytes(
                        self.checked_size::<ExclusiveCell>()?,
                        self.cell_dynamic_bytes(cell)?,
                    )?,
                )?;
            }
            self.head_replacement_residency_delta(
                &mut delta,
                self.cell_heads_index.get(cell),
                &direct_dependencies,
                self.checked_size::<(ExclusiveCell, BTreeSet<FactId>)>()?,
                if self.cell_heads_index.contains_key(cell) {
                    0
                } else {
                    self.cell_dynamic_bytes(cell)?
                },
            )?;
        }

        let subjects = Self::indexed_authority_subjects(fact);
        for subject in subjects {
            let indexed_facts = self.authority_facts_index.get(&subject);
            if indexed_facts.is_none() {
                self.add_index_residency(
                    &mut delta,
                    self.checked_add_bytes(
                        self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                        self.device_dynamic_bytes(&subject)?,
                    )?,
                )?;
            }
            if !indexed_facts.is_some_and(|facts| facts.contains(&fact.id)) {
                self.add_index_residency(&mut delta, self.checked_size::<FactId>()?)?;
            }
            self.head_replacement_residency_delta(
                &mut delta,
                self.authority_heads_index.get(&subject),
                &direct_dependencies,
                self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                if self.authority_heads_index.contains_key(&subject) {
                    0
                } else {
                    self.device_dynamic_bytes(&subject)?
                },
            )?;
        }

        if let FactBody::AuthorityLineageResolution {
            subject,
            selected_head,
            ..
        } = &fact.content.body
        {
            let selectors = self.authority_selector_index.get(subject);
            if selectors.is_none() {
                self.add_index_residency(
                    &mut delta,
                    self.checked_add_bytes(
                        self.checked_size::<(DeviceId, BTreeSet<(FactId, FactId)>)>()?,
                        self.device_dynamic_bytes(subject)?,
                    )?,
                )?;
            }
            if !selectors.is_some_and(|selectors| selectors.contains(&(fact.id, *selected_head))) {
                self.add_index_residency(&mut delta, self.checked_size::<(FactId, FactId)>()?)?;
            }
        }
        let provenance = self.provenance_residency_delta(fact)?;
        self.add_index_residency(&mut delta, provenance.added)?;
        self.remove_index_residency(&mut delta, provenance.removed)?;

        let stand_down_target = match &fact.content.body {
            FactBody::EvictionProof { target, .. }
            | FactBody::SelfStandDown {
                device_id: target, ..
            } => Some(target),
            _ => None,
        };
        if let Some(target) = stand_down_target {
            let proofs = self.stand_down_index.get(target);
            if proofs.is_none() {
                self.add_index_residency(
                    &mut delta,
                    self.checked_add_bytes(
                        self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?,
                        self.device_dynamic_bytes(target)?,
                    )?,
                )?;
            }
            if !proofs.is_some_and(|proofs| proofs.contains(&fact.id)) {
                self.add_index_residency(&mut delta, self.checked_size::<FactId>()?)?;
            }
        }
        Ok(delta)
    }

    fn apply_index_residency_delta(
        &self,
        current: u64,
        delta: IndexResidencyDelta,
    ) -> Result<u64, SemanticError> {
        let after_removals = current
            .checked_sub(delta.removed)
            .ok_or_else(|| self.accounting_error())?;
        self.checked_add_bytes(after_removals, delta.added)
    }

    fn index_residency_delta(&self, fact: &SignedFact) -> Result<u64, SemanticError> {
        let mut total = 0;
        let cells = fact
            .content
            .body
            .exclusive_cells()
            .into_iter()
            .collect::<BTreeSet<_>>();
        for cell in &cells {
            if !self.cells_index.contains(cell) {
                total = self.checked_add_bytes(
                    total,
                    self.checked_add_bytes(
                        self.checked_size::<ExclusiveCell>()?,
                        self.cell_dynamic_bytes(cell)?,
                    )?,
                )?;
            }
            let heads = self.cell_heads_index.get(cell);
            let inline = if heads.is_none() {
                self.checked_size::<(ExclusiveCell, BTreeSet<FactId>)>()?
            } else {
                0
            };
            total = self.checked_add_bytes(
                total,
                self.checked_entry_bytes(
                    inline,
                    if heads.is_none() {
                        self.cell_dynamic_bytes(cell)?
                    } else {
                        0
                    },
                    1,
                    self.checked_size::<FactId>()?,
                )?,
            )?;
        }
        let subjects = Self::indexed_authority_subjects(fact);
        for subject in subjects {
            let indexed_facts = self.authority_facts_index.get(&subject);
            total = self.checked_add_bytes(
                total,
                self.checked_entry_bytes(
                    if indexed_facts.is_none() {
                        self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?
                    } else {
                        0
                    },
                    if indexed_facts.is_none() {
                        self.device_dynamic_bytes(&subject)?
                    } else {
                        0
                    },
                    if indexed_facts.is_some_and(|facts| facts.contains(&fact.id)) {
                        0
                    } else {
                        1
                    },
                    self.checked_size::<FactId>()?,
                )?,
            )?;
            let heads = self.authority_heads_index.get(&subject);
            total = self.checked_add_bytes(
                total,
                self.checked_entry_bytes(
                    if heads.is_none() {
                        self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?
                    } else {
                        0
                    },
                    if heads.is_none() {
                        self.device_dynamic_bytes(&subject)?
                    } else {
                        0
                    },
                    1,
                    self.checked_size::<FactId>()?,
                )?,
            )?;
        }
        if let FactBody::AuthorityLineageResolution { subject, .. } = &fact.content.body {
            let selectors = self.authority_selector_index.get(subject);
            total = self.checked_add_bytes(
                total,
                self.checked_entry_bytes(
                    if selectors.is_none() {
                        self.checked_size::<(DeviceId, BTreeSet<(FactId, FactId)>)>()?
                    } else {
                        0
                    },
                    if selectors.is_none() {
                        self.device_dynamic_bytes(subject)?
                    } else {
                        0
                    },
                    1,
                    self.checked_size::<(FactId, FactId)>()?,
                )?,
            )?;
        }
        // Conservative reservation includes the complete positive replacement
        // delta; exact commit accounting releases the superseded sparse rows.
        let provenance = self.provenance_residency_delta(fact)?;
        total =
            self.checked_add_bytes(total, provenance.added.saturating_sub(provenance.removed))?;
        // Canonical body bytes are already admitted-owned; reserve the exact
        // additional subject-index entries for cold witnesses before commit
        // can retain them. Retirement may release more, never charge more.
        total = self.checked_add_bytes(total, self.cold_provenance_index_reserve(fact)?)?;
        if let FactBody::EvictionProof { target, .. }
        | FactBody::SelfStandDown {
            device_id: target, ..
        } = &fact.content.body
        {
            let proofs = self.stand_down_index.get(target);
            total = self.checked_add_bytes(
                total,
                self.checked_entry_bytes(
                    if proofs.is_none() {
                        self.checked_size::<(DeviceId, BTreeSet<FactId>)>()?
                    } else {
                        0
                    },
                    if proofs.is_none() {
                        self.device_dynamic_bytes(target)?
                    } else {
                        0
                    },
                    1,
                    self.checked_size::<FactId>()?,
                )?,
            )?;
        }
        Ok(total)
    }

    fn fact_encoded_and_edges(&self, fact: &SignedFact) -> Result<(u64, u64), SemanticError> {
        let encoded_bytes = self.checked_len(
            serde_json::to_vec(fact)
                .map_err(|_| SemanticError::EncodingFailed)?
                .len(),
        )?;
        // `dependencies` already contains every authority predecessor.  The
        // durable store charges those canonical dependency rows once, plus
        // one logical edge for each authority-use row.  Keep admission and
        // durable accounting identical so a clean checkpoint can be
        // validated in constant work at restart.
        let dependency_count = self.checked_len(dependencies(fact).len())?;
        let authority_use_count = self.checked_len(fact.content.authority_uses.len())?;
        let edges = self.checked_add_bytes(dependency_count, authority_use_count)?;
        Ok((encoded_bytes, edges))
    }

    fn reconciled_fact_totals(&self) -> Result<(u64, u64, u64, u64), SemanticError> {
        let mut admitted_bytes = 0;
        let mut quarantined_bytes = 0;
        let mut admitted_edges = 0;
        let mut quarantined_edges = 0;
        for fact in self.facts.values() {
            let (bytes, edges) = self.fact_encoded_and_edges(fact)?;
            admitted_bytes = self.checked_add_bytes(admitted_bytes, bytes)?;
            admitted_edges = self.checked_add_bytes(admitted_edges, edges)?;
        }
        for fact in self.quarantined.values() {
            let (bytes, edges) = self.fact_encoded_and_edges(fact)?;
            quarantined_bytes = self.checked_add_bytes(quarantined_bytes, bytes)?;
            quarantined_edges = self.checked_add_bytes(quarantined_edges, edges)?;
        }
        Ok((
            admitted_bytes,
            quarantined_bytes,
            admitted_edges,
            quarantined_edges,
        ))
    }

    #[cfg(test)]
    fn authority_dependents_residency_bytes(&self) -> Result<u64, SemanticError> {
        Ok(0)
    }

    fn authority_dependents_residency_delta(
        &self,
        _fact: &SignedFact,
    ) -> Result<u64, SemanticError> {
        Ok(0)
    }

    fn fact_cost(&self, fact: &SignedFact) -> Result<FactCost, SemanticError> {
        self.fact_cost_with_history(fact, None)
    }

    fn fact_cost_with_history(
        &self,
        fact: &SignedFact,
        history: Option<&FactGraph>,
    ) -> Result<FactCost, SemanticError> {
        let (encoded_bytes, dependency_edges) = self.fact_encoded_and_edges(fact)?;
        let dependencies = dependencies(fact);
        let missing = dependencies
            .iter()
            .copied()
            .filter(|dependency| {
                !self.facts.contains_key(dependency)
                    && history.is_none_or(|history| !history.facts.contains_key(dependency))
            })
            .collect::<Vec<_>>();
        // Each component is a logical request made by a retained map/vector
        // value.  Shared map keys are charged only when this fact introduces
        // the key; the reverse witness helper applies the same rule to its
        // subject-scoped dependent sets.  These values intentionally exclude
        // allocator slabs and private B-tree node metadata.
        let authority_reverse_index_bytes = self.authority_dependents_residency_delta(fact)?;
        let derived_index_bytes = self.index_residency_delta(fact)?;
        debug_assert!(derived_index_bytes >= authority_reverse_index_bytes);

        self.check_capacity(
            super::SemanticCapacityDimension::FactEncodedBytes,
            encoded_bytes,
            self.policy_limits.max_fact_encoded_bytes,
        )?;
        self.check_capacity(
            super::SemanticCapacityDimension::DependenciesPerFact,
            self.checked_len(dependencies.len())?,
            self.policy_limits.max_dependencies_per_fact,
        )?;
        self.check_capacity(
            super::SemanticCapacityDimension::AuthorityUsesPerFact,
            self.checked_len(fact.content.authority_uses.len())?,
            self.policy_limits.max_authority_uses_per_fact,
        )?;
        self.check_capacity(
            super::SemanticCapacityDimension::AuthorityPredecessorsPerUse,
            fact.content
                .authority_uses
                .iter()
                .map(|authority_use| self.checked_len(authority_use.predecessors.len()))
                .try_fold(None::<u64>, |maximum, value| {
                    let value = value?;
                    Ok::<_, SemanticError>(Some(
                        maximum.map_or(value, |current| current.max(value)),
                    ))
                })?
                .unwrap_or(0),
            self.policy_limits.max_authority_predecessors_per_use,
        )?;
        Ok(FactCost {
            encoded_bytes,
            derived_index_bytes,
            _authority_dependents_index_bytes: authority_reverse_index_bytes,
            dependency_edges,
            missing,
        })
    }

    fn check_capacity(
        &self,
        dimension: super::SemanticCapacityDimension,
        observed: u64,
        limit: u64,
    ) -> Result<(), SemanticError> {
        if observed > limit {
            return Err(SemanticError::CapacityExceeded {
                dimension,
                limit,
                observed,
            });
        }
        Ok(())
    }

    fn checked_total(
        &self,
        dimension: super::SemanticCapacityDimension,
        current: u64,
        additional: u64,
        limit: u64,
    ) -> Result<u64, SemanticError> {
        let observed = current
            .checked_add(additional)
            .ok_or(SemanticError::CapacityExceeded {
                dimension,
                limit,
                observed: u64::MAX,
            })?;
        self.check_capacity(dimension, observed, limit)?;
        Ok(observed)
    }

    fn reserve_retained(&self, author: &DeviceId, cost: &FactCost) -> Result<(), SemanticError> {
        let (author_facts, author_bytes) = self
            .retained_by_author
            .get(author)
            .copied()
            .unwrap_or_default();
        self.checked_total(
            super::SemanticCapacityDimension::RetainedFactsPerAuthor,
            author_facts,
            1,
            self.policy_limits.max_retained_facts_per_author,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::RetainedBytesPerAuthor,
            author_bytes,
            cost.encoded_bytes,
            self.policy_limits.max_retained_bytes_per_author,
        )?;
        Ok(())
    }

    fn retain_author(&mut self, author: &DeviceId, cost: &FactCost) {
        self.retained_by_author
            .entry(author.clone())
            .and_modify(|(count, bytes)| {
                *count = count
                    .checked_add(1)
                    .expect("retained author count was preflighted");
                *bytes = bytes
                    .checked_add(cost.encoded_bytes)
                    .expect("retained author bytes were preflighted");
            })
            .or_insert((1, cost.encoded_bytes));
    }

    fn release_author(&mut self, author: &DeviceId, cost: &FactCost) {
        if let Some((count, bytes)) = self.retained_by_author.get_mut(author) {
            *count = count
                .checked_sub(1)
                .expect("retained author count remains owned");
            *bytes = bytes
                .checked_sub(cost.encoded_bytes)
                .expect("retained author bytes remain owned");
            if *count == 0 {
                self.retained_by_author.remove(author);
            }
        }
    }

    fn reserve_quarantine(
        &self,
        fact: &SignedFact,
        cost: &FactCost,
        retained_reserved: bool,
    ) -> Result<(), SemanticError> {
        if !retained_reserved {
            self.reserve_retained(&fact.content.author, cost)?;
        }
        self.checked_total(
            super::SemanticCapacityDimension::QuarantinedFacts,
            self.checked_len(self.quarantined.len())?,
            1,
            self.policy_limits.max_quarantined_facts,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::QuarantinedBytes,
            self.quarantined_bytes,
            cost.encoded_bytes,
            self.policy_limits.max_quarantined_bytes,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::DependencyEdges,
            self.admitted_dependency_edges
                .checked_add(self.quarantined_dependency_edges)
                .ok_or(SemanticError::CapacityExceeded {
                    dimension: super::SemanticCapacityDimension::DependencyEdges,
                    limit: self.policy_limits.max_dependency_edges,
                    observed: u64::MAX,
                })?,
            cost.dependency_edges,
            self.policy_limits.max_dependency_edges,
        )?;
        let (author_facts, author_bytes) = self
            .quarantined_by_author
            .get(&fact.content.author)
            .copied()
            .unwrap_or_default();
        self.checked_total(
            super::SemanticCapacityDimension::QuarantinedFactsPerAuthor,
            author_facts,
            1,
            self.policy_limits.max_quarantined_facts_per_author,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::QuarantinedBytesPerAuthor,
            author_bytes,
            cost.encoded_bytes,
            self.policy_limits.max_quarantined_bytes_per_author,
        )?;
        Ok(())
    }

    fn reserve_admitted(
        &self,
        fact: &SignedFact,
        cost: &FactCost,
        retained_reserved: bool,
    ) -> Result<(), SemanticError> {
        if !retained_reserved {
            self.reserve_retained(&fact.content.author, cost)?;
        }
        self.checked_total(
            super::SemanticCapacityDimension::AdmittedFacts,
            self.admitted_fact_count,
            1,
            self.policy_limits.max_admitted_facts,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::AdmittedBytes,
            self.admitted_bytes,
            cost.encoded_bytes,
            self.policy_limits.max_admitted_bytes,
        )?;
        let fact_and_indexes = self
            .admitted_bytes
            .checked_add(cost.encoded_bytes)
            .and_then(|value| value.checked_add(self.derived_index_bytes))
            .and_then(|value| value.checked_add(cost.derived_index_bytes))
            .ok_or(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::AdmittedBytes,
                limit: self.policy_limits.max_database_bytes,
                observed: u64::MAX,
            })?;
        self.check_capacity(
            super::SemanticCapacityDimension::AdmittedBytes,
            fact_and_indexes,
            self.policy_limits.max_database_bytes,
        )?;
        self.checked_total(
            super::SemanticCapacityDimension::DependencyEdges,
            self.admitted_dependency_edges
                .checked_add(self.quarantined_dependency_edges)
                .ok_or(SemanticError::CapacityExceeded {
                    dimension: super::SemanticCapacityDimension::DependencyEdges,
                    limit: self.policy_limits.max_dependency_edges,
                    observed: u64::MAX,
                })?,
            cost.dependency_edges,
            self.policy_limits.max_dependency_edges,
        )?;
        Ok(())
    }

    pub fn admit(&mut self, fact: SignedFact) -> Result<Admission, SemanticError> {
        self.ensure_indexes_current();
        let mut rollback = GraphRollback::new(self);
        rollback.capture_admission(self, &fact);
        let result = self.admit_inner(fact, false);
        if result.is_err() {
            rollback.restore(self);
        }
        result
    }

    /// Run the allocation and identity checks without changing this graph.
    /// The apply phase consumes the returned graph/revision-fenced token and
    /// performs only the candidate-relative authority checks that require the
    /// tentative graph mutation. This cheap phase lets an owner reject an
    /// obviously impossible row before taking a journal or durable slot.
    pub(crate) fn preflight_admission(
        &self,
        fact: &SignedFact,
    ) -> Result<AdmissionPreflight, SemanticError> {
        self.preflight_admission_with_history(fact, None)
    }

    fn preflight_admission_with_history(
        &self,
        fact: &SignedFact,
        history: Option<&FactGraph>,
    ) -> Result<AdmissionPreflight, SemanticError> {
        // Cost and index accounting are meaningful only against the same
        // derived-index revision that the apply phase will consume.
        // Rebuilding here is exceptional loader repair; the normal lane is
        // already current and remains sparse.
        // `FactGraph` is immutably borrowed by this method, so an external
        // loader cannot mutate it between this check and token creation.
        // The explicit fence is carried in the token below for the apply
        // boundary.
        if !self.indexes_current() {
            return Err(SemanticError::NoOp("stale semantic index"));
        }
        fact.verify()?;
        if fact.content.mesh_context != self.context_id {
            return Err(SemanticError::ContextMismatch {
                expected: self.context_id,
                found: fact.content.mesh_context.to_string(),
            });
        }
        self.validate_domain(fact)?;
        if let Some(existing) = self.facts.get(&fact.id) {
            return if existing == fact {
                Ok(AdmissionPreflight::new(
                    self,
                    fact,
                    Admission::AlreadyPresent,
                    None,
                ))
            } else {
                Err(SemanticError::DuplicateFact(fact.id))
            };
        }
        if let Some(existing) = self.quarantined.get(&fact.id) {
            return if existing == fact {
                Ok(AdmissionPreflight::new(
                    self,
                    fact,
                    Admission::AlreadyPresent,
                    None,
                ))
            } else {
                Err(SemanticError::DuplicateFact(fact.id))
            };
        }
        if fact.content.parents.contains(&fact.id) {
            return Err(SemanticError::SelfParent);
        }
        let cost = self.fact_cost_with_history(fact, history)?;
        if cost.missing.is_empty() {
            if let Some(operation) = self.semantic_noop_for_candidate(fact, history)? {
                return Err(SemanticError::NoOp(operation));
            }
            for parent in &fact.content.parents {
                if !self.facts.contains_key(parent)
                    && history.is_none_or(|history| !history.facts.contains_key(parent))
                {
                    return Err(SemanticError::MissingParent(*parent));
                }
            }
            self.reserve_admitted(fact, &cost, false)?;
            Ok(AdmissionPreflight::new(
                self,
                fact,
                Admission::Inserted,
                Some(cost),
            ))
        } else {
            if !self.is_authorized_signer(&fact.content.author) {
                return Err(SemanticError::QuarantineSignerNotEligible);
            }
            self.reserve_quarantine(fact, &cost, false)?;
            Ok(AdmissionPreflight::new(
                self,
                fact,
                Admission::Quarantined {
                    missing: cost.missing.clone(),
                },
                Some(cost),
            ))
        }
    }

    /// Mutate one fact and at most one owner-selected ready batch while
    /// retaining enough exact, touched-entry state to roll the graph back.
    /// The returned journal must be committed only after the corresponding
    /// durable delta succeeds; otherwise call `AdmissionJournal::rollback`.
    pub(crate) fn admit_journaled(
        &mut self,
        fact: SignedFact,
    ) -> Result<AdmissionJournal<'_>, SemanticError> {
        let preflight = self.preflight_admission(&fact)?;
        self.apply_preflight_journaled_with_history(fact, preflight, None, Vec::new(), None)
    }

    pub(crate) fn admit_journaled_with_history(
        &mut self,
        fact: SignedFact,
        history: Vec<SignedFact>,
    ) -> Result<AdmissionJournal<'_>, SemanticError> {
        self.ensure_indexes_current();
        // Materialize the complete logical projection before attaching cold
        // SQLite-owned rows. The hot graph alone may intentionally be too
        // small to reconstruct this cache during a later rollback.
        let rollback_projection = self.projection();
        let overlay_rollback = GraphRollback::new(self);
        let staged_cold = match self.stage_cold_history(history) {
            Ok(staged) => staged,
            Err(error) => {
                overlay_rollback.restore(self);
                return Err(error);
            }
        };
        let preflight = match self.preflight_admission(&fact) {
            Ok(preflight) => preflight,
            Err(error) => {
                self.remove_staged_cold(&staged_cold);
                overlay_rollback.restore(self);
                return Err(error);
            }
        };
        self.apply_preflight_journaled_with_history(
            fact,
            preflight,
            None,
            staged_cold,
            Some(rollback_projection),
        )
    }

    /// Admit a bounded group behind one durable handoff. Inputs are evaluated
    /// in enqueue order against the graph produced by earlier successful
    /// inputs. An input-local refusal is recorded and does not undo earlier
    /// valid mutations; only the returned aggregate journal owns rollback of
    /// the whole group.
    #[cfg(test)]
    pub(crate) fn admit_journaled_batch(
        &mut self,
        facts: Vec<SignedFact>,
    ) -> Result<AggregateAdmissionJournal<'_>, SemanticError> {
        self.admit_journaled_batch_with_history(facts, Vec::new())
    }

    pub(crate) fn admit_journaled_batch_with_history(
        &mut self,
        facts: Vec<SignedFact>,
        history: Vec<SignedFact>,
    ) -> Result<AggregateAdmissionJournal<'_>, SemanticError> {
        self.ensure_indexes_current();
        let batch_limit = usize::try_from(self.policy_limits.max_ready_batch).map_err(|_| {
            SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                observed: self.policy_limits.max_ready_batch,
            }
        })?;
        if facts.len() > batch_limit {
            return Err(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: self.policy_limits.max_ready_batch,
                observed: u64::try_from(facts.len()).unwrap_or(u64::MAX),
            });
        }

        // Cold rows remain SQLite-owned. Materialize the logical projection
        // before staging them, then retain it only on this exceptional path so
        // rollback can restore the exact pre-request state.
        let rollback_projection = if history.is_empty() {
            None
        } else {
            Some(self.projection())
        };
        let mut rollback = GraphRollback::new(self);
        if let Some(projection) = &rollback_projection {
            rollback.capture_projection_full(self.generation, projection);
        }
        let staged_cold = match self.stage_cold_history(history) {
            Ok(staged) => staged,
            Err(error) => {
                rollback.restore(self);
                return Err(error);
            }
        };

        // Capture only the sparse base values needed by the finite group.
        // The temporary projection is dropped before the first mutation, so
        // the update path retains unique Merkle maps and does not trigger a
        // full Arc::make_mut copy merely to support rollback.
        let base_generation = self.generation;
        let base_commitment = self.projection_commitment_root();
        let mut planned_cells = BTreeSet::new();
        let mut planned_subjects = BTreeSet::new();
        for fact in &facts {
            let (cells, subjects) = self.projection_impact_for_fact_with_staged(fact, &staged_cold);
            planned_cells.extend(cells);
            planned_subjects.extend(subjects);
        }
        for id in &self.ready_quarantine {
            #[cfg(test)]
            record_graph_work(|work| {
                work.aggregate_ready_entries = work.aggregate_ready_entries.saturating_add(1);
            });
            if let Some(fact) = self.quarantined.get(id) {
                let (cells, subjects) =
                    self.projection_impact_for_fact_with_staged(fact, &staged_cold);
                planned_cells.extend(cells);
                planned_subjects.extend(subjects);
            }
        }
        let mut waiter_seeds = facts.iter().map(|fact| fact.id).collect::<Vec<_>>();
        waiter_seeds.extend(self.ready_quarantine.iter().copied());
        let mut pending_waiters = waiter_seeds;
        let mut seen_waiter_dependencies = BTreeSet::new();
        while let Some(dependency) = pending_waiters.pop() {
            if !seen_waiter_dependencies.insert(dependency) {
                continue;
            }
            if let Some(waiters) = self.waiting_by_dependency.get(&dependency) {
                for waiter in waiters {
                    #[cfg(test)]
                    record_graph_work(|work| {
                        work.aggregate_waiter_edges = work.aggregate_waiter_edges.saturating_add(1);
                    });
                    if let Some(fact) = self.quarantined.get(waiter) {
                        #[cfg(test)]
                        record_graph_work(|work| {
                            work.aggregate_waiter_nodes =
                                work.aggregate_waiter_nodes.saturating_add(1);
                        });
                        let (cells, subjects) =
                            self.projection_impact_for_fact_with_staged(fact, &staged_cold);
                        planned_cells.extend(cells);
                        planned_subjects.extend(subjects);
                    }
                    pending_waiters.push(*waiter);
                }
            }
        }
        let (base_cells, base_stand_down) = {
            let projection = self.projection();
            projection.sparse_entries(&planned_cells, &planned_subjects)
        };
        rollback.capture_projection_sparse(&base_cells, &base_stand_down);

        let initial_ready = self.ready_quarantine.iter().copied().collect::<Vec<_>>();
        rollback.capture_waiter_closure(self, &initial_ready);
        let mut results = Vec::with_capacity(facts.len());
        let mut touched_ids = BTreeSet::new();
        let mut affected_cells = BTreeSet::new();
        let mut affected_subjects = BTreeSet::new();
        let mut retry_budget = 0usize;

        // A group has one durable projection boundary. Keep the sparse maps
        // current for authority evaluation between inputs, but defer the
        // Patricia rebuild until every accepted input has been applied.
        self.begin_deferred_projection_commitment();

        for fact in facts {
            let fact_id = fact.id;
            let preflight = match self.preflight_admission(&fact) {
                Ok(preflight) => preflight,
                Err(error) => {
                    if Self::is_aggregate_precommit_failure(&error) {
                        self.finish_deferred_projection_commitment();
                        self.remove_staged_cold(&staged_cold);
                        rollback.restore(self);
                        return Err(error);
                    }
                    results.push(AggregateAdmissionResult {
                        outcome: AggregateAdmissionOutcome::Refused { fact_id, error },
                        _delta: SemanticDelta::default(),
                    });
                    continue;
                }
            };
            if matches!(preflight.admission(), Admission::AlreadyPresent) {
                results.push(AggregateAdmissionResult {
                    outcome: AggregateAdmissionOutcome::AlreadyPresent { fact_id },
                    _delta: SemanticDelta::default(),
                });
                continue;
            }

            rollback.capture_admission(self, &fact);
            rollback.capture_waiter_closure(self, &[fact_id]);
            let (item_admission, item_delta) = match self.apply_preflight_for_aggregate(
                fact,
                preflight,
                &staged_cold,
                &mut retry_budget,
            ) {
                Ok(applied) => applied,
                Err(error) => {
                    if Self::is_aggregate_precommit_failure(&error) {
                        self.finish_deferred_projection_commitment();
                        self.remove_staged_cold(&staged_cold);
                        rollback.restore(self);
                        return Err(error);
                    }
                    results.push(AggregateAdmissionResult {
                        outcome: AggregateAdmissionOutcome::Refused { fact_id, error },
                        _delta: SemanticDelta::default(),
                    });
                    continue;
                }
            };

            for id in item_delta.changed_ids() {
                touched_ids.insert(id);
            }
            affected_cells.extend(item_delta.affected_cells().iter().cloned());
            affected_subjects.extend(item_delta.affected_subjects().iter().cloned());

            let outcome = match item_admission {
                Admission::Inserted => AggregateAdmissionOutcome::Inserted { fact_id },
                Admission::Quarantined { missing } => {
                    AggregateAdmissionOutcome::Quarantined { fact_id, missing }
                }
                Admission::AlreadyPresent => AggregateAdmissionOutcome::AlreadyPresent { fact_id },
            };
            results.push(AggregateAdmissionResult {
                outcome,
                _delta: item_delta,
            });
        }

        // Close the deferred interval before observing or persisting the
        // projection root. This rebuilds the exact final root once rather
        // than rebuilding every intermediate root in the group.
        self.finish_deferred_projection_commitment();

        // Normalize repeated/touched rows to their final resident state. The
        // per-input records above retain attribution for replies, while this
        // single delta is the only payload handed to the durable store.
        let mut delta = SemanticDelta {
            affected_cells,
            affected_subjects,
            ..SemanticDelta::default()
        };
        for id in touched_ids {
            let base_admitted = rollback.facts.get(&id).and_then(Option::as_ref).is_some();
            let base_quarantined = rollback
                .quarantined
                .get(&id)
                .and_then(Option::as_ref)
                .is_some();
            let final_admitted = self.facts.contains_key(&id);
            let final_quarantined = self.quarantined.contains_key(&id);

            if base_quarantined && final_admitted {
                delta.promoted.push(id);
            }
            if (base_admitted || base_quarantined) && !final_admitted && !final_quarantined {
                delta.removed.push(id);
            }
            if !base_quarantined && final_quarantined {
                delta.provisional_added.push(id);
            }
            if base_quarantined && !final_quarantined {
                delta.provisional_removed.push(id);
            }
            if let Some(fact) = self.facts.get(&id) {
                delta.rows.push(SemanticFactRow {
                    fact: fact.clone(),
                    status: SemanticFactStatus::Admitted,
                });
            } else if let Some(fact) = self.quarantined.get(&id) {
                delta.rows.push(SemanticFactRow {
                    fact: fact.clone(),
                    status: SemanticFactStatus::Quarantined,
                });
            }
        }

        let current_projection = self.projection();
        let current_commitment = current_projection.commitment_root();
        if current_commitment != base_commitment {
            let projection_delta = current_projection.delta_from_sparse(
                base_generation,
                self.generation,
                base_commitment,
                &base_cells,
                &base_stand_down,
            );
            if projection_delta.cells().is_empty() && projection_delta.stand_down().is_empty() {
                self.remove_staged_cold(&staged_cold);
                rollback.restore(self);
                return Err(SemanticError::NoOp(
                    "aggregate projection impact incomplete",
                ));
            }
            delta.projection_delta = Some(projection_delta);
        }
        if !delta.is_bounded_and_unique(self.policy_limits.max_ready_batch) {
            let observed = u64::try_from(delta.rows.len()).unwrap_or(u64::MAX);
            self.remove_staged_cold(&staged_cold);
            rollback.restore(self);
            return Err(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: self.policy_limits.max_ready_batch,
                observed,
            });
        }

        Ok(AggregateAdmissionJournal {
            graph: self,
            rollback: Some(rollback),
            staged_cold,
            results,
            delta,
        })
    }

    fn is_aggregate_precommit_failure(error: &SemanticError) -> bool {
        matches!(error, SemanticError::CapacityExceeded { .. })
    }

    /// Apply one already-checked aggregate input and close its borrow before
    /// the caller decides whether an error is batch-fatal. The outer aggregate
    /// rollback remains the sole owner of reverting earlier successful inputs.
    fn apply_preflight_for_aggregate(
        &mut self,
        fact: SignedFact,
        preflight: AdmissionPreflight,
        staged_cold: &[FactId],
        retry_budget: &mut usize,
    ) -> Result<(Admission, SemanticDelta), SemanticError> {
        let budget_before = *retry_budget;
        let journal = match self.apply_preflight_journaled_with_history_and_impact(
            fact,
            preflight,
            None,
            Vec::new(),
            None,
            Some(staged_cold),
            retry_budget,
        ) {
            Ok(journal) => journal,
            Err(error) => {
                *retry_budget = budget_before;
                return Err(error);
            }
        };
        let admission = journal.admission().clone();
        let mut delta = journal.delta().clone();
        let changed_ids = delta.changed_ids().collect::<Vec<_>>();
        let (affected_cells, affected_subjects) = journal
            .graph()
            .projection_impact_for_facts_with_staged(changed_ids, staged_cold);
        delta.affected_cells.extend(affected_cells);
        delta.affected_subjects.extend(affected_subjects);
        journal.commit();
        Ok((admission, delta))
    }

    /// Apply a preflight result while retaining the same journal guarantees.
    /// The caller must hold the graph's publication fence between the
    /// read-only preflight and this method so the checked graph cannot change.
    #[cfg(test)]
    pub(crate) fn apply_preflight_journaled(
        &mut self,
        fact: SignedFact,
        preflight: AdmissionPreflight,
    ) -> Result<AdmissionJournal<'_>, SemanticError> {
        self.apply_preflight_journaled_with_history(fact, preflight, None, Vec::new(), None)
    }

    fn apply_preflight_journaled_with_history(
        &mut self,
        fact: SignedFact,
        preflight: AdmissionPreflight,
        history: Option<&FactGraph>,
        staged_cold: Vec<FactId>,
        rollback_projection: Option<Projection>,
    ) -> Result<AdmissionJournal<'_>, SemanticError> {
        let mut retry_budget = 0usize;
        self.apply_preflight_journaled_with_history_and_impact(
            fact,
            preflight,
            history,
            staged_cold,
            rollback_projection,
            None,
            &mut retry_budget,
        )
    }

    // Owned staged rows/rollback and borrowed history/impact have distinct
    // journal lifetimes; keep those existing admission inputs explicit.
    #[allow(clippy::too_many_arguments)]
    fn apply_preflight_journaled_with_history_and_impact(
        &mut self,
        fact: SignedFact,
        preflight: AdmissionPreflight,
        history: Option<&FactGraph>,
        staged_cold: Vec<FactId>,
        rollback_projection: Option<Projection>,
        impact_staged_cold: Option<&[FactId]>,
        retry_budget: &mut usize,
    ) -> Result<AdmissionJournal<'_>, SemanticError> {
        self.ensure_indexes_current();
        let staged_for_impact = impact_staged_cold.unwrap_or(&staged_cold);
        preflight.validate_for(self, &fact)?;
        let fact_id = fact.id;
        if matches!(preflight.admission(), &Admission::AlreadyPresent) {
            let rollback = if staged_cold.is_empty() {
                None
            } else {
                let mut rollback = GraphRollback::new(self);
                rollback.staged_cold_pending = rollback
                    .staged_cold_pending
                    .checked_sub(staged_cold.len())
                    .expect("staged cold count includes the hydrated overlay");
                rollback.indexed_fact_count = self
                    .indexed_fact_count
                    .checked_sub(staged_cold.len())
                    .expect("staged cold rows are reflected in the index count");
                rollback.capture_staged_absence(&staged_cold);
                Some(rollback)
            };
            return Ok(AdmissionJournal {
                graph: self,
                rollback,
                staged_cold,
                delta: SemanticDelta::default(),
                admission: preflight.admission,
            });
        }
        let cost = preflight
            .cost
            .expect("non-replay admission preflight carries its fact cost");
        let mut rollback = GraphRollback::new(self);
        if rollback_projection.is_some() && !staged_cold.is_empty() {
            // Single-fact history hydration stages its cold rows before this
            // inner journal is created. The journal baseline is the caller's
            // pre-overlay ownership, so remove only that transient increment
            // from the captured scalar before cleanup and restore.
            rollback.staged_cold_pending = rollback
                .staged_cold_pending
                .checked_sub(staged_cold.len())
                .expect("staged cold count includes the hydrated overlay");
        }
        let previous_generation = self.generation;
        let previous_projection = self.projection_for_update();
        if let Some(rollback_projection) = rollback_projection.as_ref() {
            rollback.capture_projection_full(previous_generation, rollback_projection);
        }
        let base_commitment = previous_projection.commitment_root();
        let (mut potential_cells, mut potential_subjects) =
            self.projection_impact_for_fact_with_staged(&fact, staged_for_impact);
        let batch_limit = usize::try_from(self.policy_limits.max_ready_batch).map_err(|_| {
            SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                observed: self.policy_limits.max_ready_batch,
            }
        })?;
        let mut retry_seeds = self.ready_quarantine.iter().copied().collect::<Vec<_>>();
        retry_seeds.push(fact_id);
        let retry_closure = rollback.capture_waiter_closure_with_ids(self, &retry_seeds);
        for id in retry_closure {
            if let Some(waiter) = self.quarantined.get(&id) {
                let (cells, subjects) =
                    self.projection_impact_for_fact_with_staged(waiter, staged_for_impact);
                potential_cells.extend(cells);
                potential_subjects.extend(subjects);
            }
        }
        let (previous_cells, previous_stand_down) =
            previous_projection.sparse_entries(&potential_cells, &potential_subjects);
        rollback.capture_projection_sparse(&previous_cells, &previous_stand_down);
        rollback.capture_fact(self, fact_id);
        rollback.capture_provenance_admission(self, &fact);
        rollback.capture_author(self, &fact.content.author);
        if cost.missing.is_empty() {
            rollback.capture_dependency(self, fact_id);
        } else {
            for dependency in &cost.missing {
                rollback.capture_dependency(self, *dependency);
            }
        }
        let admission = match self.admit_inner_with_projection_staged(
            fact,
            false,
            Some(previous_projection),
            history,
            Some(cost),
            staged_for_impact,
        ) {
            Ok(admission) => admission,
            Err(error) => {
                self.remove_staged_cold(&staged_cold);
                rollback.restore(self);
                return Err(error);
            }
        };

        let mut retry_ids = Vec::new();
        if matches!(&admission, Admission::Inserted) {
            if batch_limit == 0 {
                self.remove_staged_cold(&staged_cold);
                rollback.restore(self);
                return Err(SemanticError::CapacityExceeded {
                    dimension: super::SemanticCapacityDimension::ReadyBatch,
                    limit: 0,
                    observed: 1,
                });
            }
            if let Err(error) = self.retry_quarantined_batch_bounded(
                batch_limit,
                staged_for_impact,
                &mut rollback,
                retry_budget,
                &mut retry_ids,
            ) {
                self.remove_staged_cold(&staged_cold);
                rollback.restore(self);
                return Err(error);
            }
        }

        let mut delta = SemanticDelta::default();
        if matches!(
            &admission,
            Admission::Inserted | Admission::Quarantined { .. }
        ) {
            if let Some(fact) = self
                .facts
                .get(&fact_id)
                .or_else(|| self.quarantined.get(&fact_id))
            {
                delta.rows.push(SemanticFactRow {
                    fact: fact.clone(),
                    status: if self.facts.contains_key(&fact_id) {
                        SemanticFactStatus::Admitted
                    } else {
                        SemanticFactStatus::Quarantined
                    },
                });
            }
        }
        for id in retry_ids {
            if let Some(fact) = self.facts.get(&id) {
                delta.promoted.push(id);
                delta.provisional_removed.push(id);
                delta.rows.push(SemanticFactRow {
                    fact: fact.clone(),
                    status: SemanticFactStatus::Admitted,
                });
            } else {
                delta.removed.push(id);
                delta.provisional_removed.push(id);
            }
        }
        if matches!(&admission, Admission::Quarantined { .. }) {
            delta.provisional_added.push(fact_id);
        }
        let impacted_fact_ids = delta
            .rows
            .iter()
            .filter(|row| row.status == SemanticFactStatus::Admitted)
            .map(|row| row.fact.id)
            .collect::<Vec<_>>();
        let (affected_cells, affected_subjects) =
            self.projection_impact_for_facts_with_staged(impacted_fact_ids, staged_for_impact);
        delta.affected_cells = affected_cells;
        delta.affected_subjects = affected_subjects;
        if delta
            .rows
            .iter()
            .any(|row| row.status == SemanticFactStatus::Admitted)
        {
            delta.projection_delta = Some(self.projection_delta_from_sparse(
                previous_generation,
                self.generation,
                base_commitment,
                &previous_cells,
                &previous_stand_down,
            ));
        }
        if !delta.is_bounded_and_unique(self.policy_limits.max_ready_batch) {
            self.remove_staged_cold(&staged_cold);
            rollback.restore(self);
            return Err(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: self.policy_limits.max_ready_batch,
                observed: u64::try_from(delta.rows.len()).unwrap_or(u64::MAX),
            });
        }
        Ok(AdmissionJournal {
            graph: self,
            rollback: Some(rollback),
            staged_cold,
            delta,
            admission,
        })
    }

    #[cfg(test)]
    fn retry_quarantined_batch(
        &mut self,
        batch_limit: usize,
        staged_cold: &[FactId],
    ) -> Result<Vec<FactId>, SemanticError> {
        let ready = self
            .ready_quarantine
            .iter()
            .copied()
            .take(batch_limit)
            .collect::<Vec<_>>();
        let mut inserted = Vec::new();
        for id in ready {
            let Some(fact) = self.remove_quarantine(&id)? else {
                continue;
            };
            let cost = self.fact_cost(&fact)?;
            let author = fact.content.author.clone();
            let body = fact.content.body.clone();
            let candidate_dependencies = dependencies(&fact);
            match self.admit_inner_with_staged(fact, true, staged_cold) {
                Ok(Admission::Inserted) => inserted.push(id),
                Ok(Admission::AlreadyPresent | Admission::Quarantined { .. }) => {}
                Err(error)
                    if Self::is_terminal_waiter_error(
                        self,
                        &body,
                        &author,
                        &candidate_dependencies,
                        &error,
                    ) =>
                {
                    self.release_author(&author, &cost);
                    // Validation failure after the waiter was removed is a
                    // terminal rejection of that waiter.  Keep the valid
                    // parent admission and the other ready waiters; the
                    // absent ID is emitted in the journal delta below.
                }
                Err(error) => return Err(error),
            }
        }
        Ok(inserted)
    }

    /// Retry the indexed ready frontier to a fixed point, counting every
    /// waiter touched across all frontiers against the one admission's
    /// cumulative retry envelope.  The ordinary helper above intentionally
    /// retains its direct test/maintenance semantics; journaled admission
    /// uses this variant so a newly woken transitive waiter cannot reset the
    /// ready-batch budget.
    fn retry_quarantined_batch_bounded(
        &mut self,
        batch_limit: usize,
        staged_cold: &[FactId],
        rollback: &mut GraphRollback,
        retry_budget: &mut usize,
        retry_ids: &mut Vec<FactId>,
    ) -> Result<(), SemanticError> {
        let mut processed = BTreeSet::new();
        loop {
            let ready = self
                .ready_quarantine
                .iter()
                .copied()
                .filter(|id| !processed.contains(id))
                .take(batch_limit.saturating_sub(*retry_budget))
                .collect::<Vec<_>>();
            if ready.is_empty() {
                if self
                    .ready_quarantine
                    .iter()
                    .any(|id| !processed.contains(id))
                {
                    return Err(SemanticError::CapacityExceeded {
                        dimension: super::SemanticCapacityDimension::ReadyBatch,
                        limit: u64::try_from(batch_limit).unwrap_or(u64::MAX),
                        observed: u64::try_from(*retry_budget)
                            .unwrap_or(u64::MAX)
                            .saturating_add(1),
                    });
                }
                return Ok(());
            }

            for id in ready {
                if !processed.insert(id) {
                    continue;
                }
                *retry_budget = (*retry_budget)
                    .checked_add(1)
                    .expect("bounded retry budget is representable");
                rollback.capture_fact(self, id);
                let Some(fact) = self.quarantined.get(&id) else {
                    self.ready_quarantine.remove(&id);
                    continue;
                };

                // All rollback and projection entries for this waiter must
                // be captured from the pre-admission projection before the
                // waiter is removed.  The indexed waiter closure, rather
                // than unrelated quarantine, is the only discovery path.
                rollback.capture_author(self, &fact.content.author);
                rollback.capture_dependency(self, id);
                for dependency in dependencies(fact) {
                    rollback.capture_dependency(self, dependency);
                }

                let Some(fact) = self.remove_quarantine(&id)? else {
                    continue;
                };
                let cost = self.fact_cost(&fact)?;
                let author = fact.content.author.clone();
                let body = fact.content.body.clone();
                let candidate_dependencies = dependencies(&fact);
                match self.admit_inner_with_staged(fact, true, staged_cold) {
                    Ok(Admission::Inserted) => {}
                    Ok(Admission::AlreadyPresent | Admission::Quarantined { .. }) => {}
                    Err(error)
                        if Self::is_terminal_waiter_error(
                            self,
                            &body,
                            &author,
                            &candidate_dependencies,
                            &error,
                        ) =>
                    {
                        self.release_author(&author, &cost);
                    }
                    Err(error) => return Err(error),
                }
                retry_ids.push(id);
            }
        }
    }

    fn is_terminal_waiter_error(
        graph: &FactGraph,
        body: &FactBody,
        _author: &DeviceId,
        candidate_dependencies: &[FactId],
        error: &SemanticError,
    ) -> bool {
        matches!(
            error,
            SemanticError::UnsupportedVersion(_)
                | SemanticError::EmptyField(_)
                | SemanticError::DomainMismatch
                | SemanticError::UnsortedParents
                | SemanticError::DuplicateParent
                | SemanticError::AuthorMismatch
                | SemanticError::NonCanonicalSet(_)
                | SemanticError::IncompleteEvictionProof
                | SemanticError::FactIdMismatch
                | SemanticError::InvalidSignature
                | SemanticError::InvalidStandDownProof
                | SemanticError::InvalidAuthorityUse
        ) || Self::is_terminal_authorization_waiter(
            graph,
            body,
            _author,
            candidate_dependencies,
            error,
        )
    }

    fn is_terminal_authorization_waiter(
        graph: &FactGraph,
        body: &FactBody,
        _author: &DeviceId,
        candidate_dependencies: &[FactId],
        error: &SemanticError,
    ) -> bool {
        // This predicate is reached only after retry's immutable fact
        // verification and ready-frontier removal. Recheck the dependency
        // gate here so only a complete, candidate-relative authorization
        // refusal is terminal; capacity and incomplete/unknown work remain
        // transactional errors.
        candidate_dependencies
            .iter()
            .all(|dependency| graph.facts.contains_key(dependency))
            && matches!(
                error,
                SemanticError::UnauthorizedRoleGrant
                    | SemanticError::UnauthorizedMembershipAdmit
                    | SemanticError::UnauthorizedAttestation
                    | SemanticError::UnauthorizedEviction
            )
            && matches!(
                body,
                FactBody::RoleGrant { .. }
                    | FactBody::RoleRevoke { .. }
                    | FactBody::Evict { .. }
                    | FactBody::Resolution { .. }
                    | FactBody::AuthorityLineageResolution { .. }
                    | FactBody::MembershipAdmit { .. }
                    | FactBody::Attestation { .. }
                    | FactBody::EvictionProof { .. }
            )
    }

    fn admit_inner(
        &mut self,
        fact: SignedFact,
        retained_reserved: bool,
    ) -> Result<Admission, SemanticError> {
        self.admit_inner_with_projection(fact, retained_reserved, None, None, None)
    }

    fn admit_inner_with_staged(
        &mut self,
        fact: SignedFact,
        retained_reserved: bool,
        staged_cold: &[FactId],
    ) -> Result<Admission, SemanticError> {
        self.admit_inner_with_projection_staged(
            fact,
            retained_reserved,
            None,
            None,
            None,
            staged_cold,
        )
    }

    fn admit_quarantined(
        &mut self,
        fact: SignedFact,
        cost: FactCost,
        retained_reserved: bool,
    ) -> Result<Admission, SemanticError> {
        if !self.is_authorized_signer(&fact.content.author) {
            return Err(SemanticError::QuarantineSignerNotEligible);
        }
        self.reserve_quarantine(&fact, &cost, retained_reserved)?;
        let missing = cost.missing.iter().copied().collect::<BTreeSet<_>>();
        for dependency in &missing {
            self.waiting_by_dependency
                .entry(*dependency)
                .or_default()
                .insert(fact.id);
        }
        self.quarantine_missing.insert(fact.id, missing.clone());
        self.quarantined_by_author
            .entry(fact.content.author.clone())
            .and_modify(|(count, bytes)| {
                *count = count
                    .checked_add(1)
                    .expect("quarantine author count was preflighted");
                *bytes = bytes
                    .checked_add(cost.encoded_bytes)
                    .expect("quarantine author bytes were preflighted");
            })
            .or_insert((1, cost.encoded_bytes));
        self.quarantined_bytes = self
            .quarantined_bytes
            .checked_add(cost.encoded_bytes)
            .expect("quarantine bytes were preflighted");
        self.quarantined_dependency_edges = self
            .quarantined_dependency_edges
            .checked_add(cost.dependency_edges)
            .expect("quarantine edges were preflighted");
        let author = fact.content.author.clone();
        self.quarantined.insert(fact.id, fact);
        if !retained_reserved {
            self.retain_author(&author, &cost);
        }
        Ok(Admission::Quarantined {
            missing: missing.into_iter().collect(),
        })
    }

    fn admit_inner_with_projection(
        &mut self,
        fact: SignedFact,
        retained_reserved: bool,
        supplied_previous_projection: Option<Projection>,
        history: Option<&FactGraph>,
        validated_cost: Option<FactCost>,
    ) -> Result<Admission, SemanticError> {
        self.admit_inner_with_projection_staged(
            fact,
            retained_reserved,
            supplied_previous_projection,
            history,
            validated_cost,
            &[],
        )
    }

    fn admit_inner_with_projection_staged(
        &mut self,
        fact: SignedFact,
        retained_reserved: bool,
        supplied_previous_projection: Option<Projection>,
        history: Option<&FactGraph>,
        validated_cost: Option<FactCost>,
        staged_cold: &[FactId],
    ) -> Result<Admission, SemanticError> {
        self.ensure_indexes_current();
        let preflight_validated = validated_cost.is_some();
        let cost = if let Some(cost) = validated_cost {
            cost
        } else {
            fact.verify()?;
            if fact.content.mesh_context != self.context_id {
                return Err(SemanticError::ContextMismatch {
                    expected: self.context_id,
                    found: fact.content.mesh_context.to_string(),
                });
            }
            self.validate_domain(&fact)?;
            if let Some(existing) = self.facts.get(&fact.id) {
                return if existing == &fact {
                    Ok(Admission::AlreadyPresent)
                } else {
                    Err(SemanticError::DuplicateFact(fact.id))
                };
            }
            if let Some(existing) = self.quarantined.get(&fact.id) {
                return if existing == &fact {
                    Ok(Admission::AlreadyPresent)
                } else {
                    Err(SemanticError::DuplicateFact(fact.id))
                };
            }
            if fact.content.parents.contains(&fact.id) {
                return Err(SemanticError::SelfParent);
            }
            let cost = self.fact_cost_with_history(&fact, history)?;
            if cost.missing.is_empty() {
                if let Some(operation) = self.semantic_noop_for_candidate(&fact, history)? {
                    return Err(SemanticError::NoOp(operation));
                }
                for parent in &fact.content.parents {
                    if !self.facts.contains_key(parent)
                        && history.is_none_or(|history| !history.facts.contains_key(parent))
                    {
                        return Err(SemanticError::MissingParent(*parent));
                    }
                }
            }
            cost
        };
        if !cost.missing.is_empty() {
            if preflight_validated || self.is_authorized_signer(&fact.content.author) {
                return self.admit_quarantined(fact, cost, retained_reserved);
            }
            return Err(SemanticError::QuarantineSignerNotEligible);
        }
        let causal = if self.current_heads_are_complete(&fact) {
            CausalAdmissionGraph::Full(self)
        } else if let Some(history) = history {
            CausalAdmissionGraph::Full(history)
        } else {
            self.causal_past(&fact)?
        };
        if let FactBody::Resolution {
            cell,
            cited_heads,
            selected_head,
        } = &fact.content.body
        {
            if !cited_heads.contains(selected_head) {
                return Err(SemanticError::ResolutionSelectionNotCited);
            }
            let mut cited = cited_heads.clone();
            cited.sort();
            cited.dedup();
            if cited.len() < 2
                || cited.len() != cited_heads.len()
                || cited.as_slice() != cited_heads.as_slice()
            {
                return Err(SemanticError::IncompleteResolution);
            }
            for head in &cited {
                if !causal.contains(head) {
                    return Err(SemanticError::UnknownResolutionHead(*head));
                }
                if !fact.content.parents.contains(head) {
                    return Err(SemanticError::IncompleteResolution);
                }
            }
            for head in &cited {
                if !causal
                    .get(head)
                    .is_some_and(|head| super::verify::body_advances_cell(&head.content.body, cell))
                {
                    return Err(SemanticError::IncompleteResolution);
                }
            }
            if causal.raw_cell_heads(cell) != cited {
                return Err(SemanticError::ResolutionNotCurrent);
            }
        }
        if let FactBody::AuthorityLineageResolution {
            subject,
            cited_heads,
            selected_head,
        } = &fact.content.body
        {
            if !cited_heads.contains(selected_head) {
                return Err(SemanticError::ResolutionSelectionNotCited);
            }
            let mut cited = cited_heads.clone();
            cited.sort();
            cited.dedup();
            if cited.len() < 2
                || cited.len() != cited_heads.len()
                || cited.as_slice() != cited_heads.as_slice()
            {
                return Err(SemanticError::IncompleteResolution);
            }
            for head in &cited {
                if !causal.contains(head)
                    || !fact.content.parents.contains(head)
                    || !causal.get(head).is_some_and(|head| {
                        head.content
                            .authority_uses
                            .iter()
                            .any(|use_| use_.subject == *subject)
                    })
                {
                    return Err(SemanticError::InvalidAuthorityUse);
                }
            }
            if cited.as_slice() != causal.authority_lineage(subject).heads() {
                return Err(SemanticError::ResolutionNotCurrent);
            }
        }
        if let Some(error) = Self::authorization_error(&fact.content.body) {
            causal.validate_authority_lineage(&fact, error.clone())?;
            if !causal.is_authorized_for(&fact.content.body, &fact.content.author) {
                return Err(error);
            }
        }
        match &fact.content.body {
            FactBody::EvictionProof { target, evidence } => {
                causal.validate_authority_lineage(&fact, SemanticError::UnauthorizedEviction)?;
                causal.validate_eviction_proof(target, evidence, &fact.content.author)?;
            }
            FactBody::SelfStandDown {
                device_id,
                evidence,
            } => {
                causal.validate_authority_lineage(&fact, SemanticError::InvalidStandDownProof)?;
                causal.validate_self_stand_down(device_id, evidence, &fact.content.author)?;
            }
            _ => {}
        }
        let exact_index_delta = self.exact_index_residency_delta(&fact)?;
        let provenance = self.planned_provenance(&fact)?;
        self.reserve_admitted(&fact, &cost, retained_reserved)?;
        let fact_id = fact.id;
        let author = fact.content.author.clone();
        let previous_projection =
            supplied_previous_projection.unwrap_or_else(|| self.projection_for_update());
        self.admitted_bytes = self
            .admitted_bytes
            .checked_add(cost.encoded_bytes)
            .expect("admitted bytes were preflighted");
        self.admitted_dependency_edges = self
            .admitted_dependency_edges
            .checked_add(cost.dependency_edges)
            .expect("admitted edges were preflighted");
        self.facts.insert(fact_id, fact);
        self.admitted_fact_count = self
            .admitted_fact_count
            .checked_add(1)
            .expect("admitted fact count was preflighted");
        self.cold_history_since_retirement = self.cold_history_since_retirement.saturating_add(1);
        self.admission_order.push(fact_id);
        self.facts_revision = self
            .facts_revision
            .checked_add(1)
            .expect("FactGraph fact revision exhausted");
        self.generation = self
            .generation
            .checked_add(1)
            .expect("FactGraph projection generation exhausted");
        self.authority_provenance.extend(provenance);
        self.index_fact(fact_id);
        self.indexed_fact_count = self.facts.len();
        self.indexed_revision = self.facts_revision;
        self.derived_index_bytes =
            self.apply_index_residency_delta(self.derived_index_bytes, exact_index_delta)?;
        let stored_fact = self
            .facts
            .get(&fact_id)
            .expect("indexed fact remains in the admitted graph");
        let (projection_cells, projection_stand_down_targets) =
            self.projection_impact_for_fact_with_staged(stored_fact, staged_cold);
        let projection = if self.defer_projection_commitment {
            Projection::update_from_graph_deferred_commitment(
                self,
                previous_projection,
                &projection_cells,
                &projection_stand_down_targets,
            )
        } else {
            Projection::update_from_graph(
                self,
                previous_projection,
                &projection_cells,
                &projection_stand_down_targets,
            )
        };
        let projection_bytes = projection.commitment_bytes();
        let resident = self
            .admitted_bytes
            .checked_add(self.derived_index_bytes)
            .and_then(|bytes| bytes.checked_add(projection_bytes))
            .ok_or(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::AdmittedBytes,
                limit: self.policy_limits.max_database_bytes,
                observed: u64::MAX,
            })?;
        self.check_capacity(
            super::SemanticCapacityDimension::AdmittedBytes,
            resident,
            self.policy_limits.max_database_bytes,
        )?;
        *self.projection_cache.lock() = Some((self.generation, projection));
        if !retained_reserved {
            self.retain_author(&author, &cost);
        }
        self.wake_dependency(fact_id);
        Ok(Admission::Inserted)
    }

    fn validate_domain(&self, _fact: &SignedFact) -> Result<(), SemanticError> {
        if matches!(&self.policy, VerifiedProjectPolicy::Open) {
            return Err(SemanticError::DomainMismatch);
        }
        Ok(())
    }

    fn semantic_noop_for_candidate(
        &self,
        fact: &SignedFact,
        history: Option<&FactGraph>,
    ) -> Result<Option<&'static str>, SemanticError> {
        if matches!(
            fact.content.body,
            FactBody::RoleGrant { .. }
                | FactBody::RoleRevoke { .. }
                | FactBody::Resolution { .. }
                | FactBody::AuthorityLineageResolution { .. }
        ) {
            // Redundancy is intrinsic to this signed operation's causal past,
            // not to a receiver's concurrent arrival order. Both callers have
            // already classified missing dependencies before reaching here.
            // causal_past borrows the normal complete-current-head role path;
            // it does not clone the live graph for each admission.
            let causal = history.unwrap_or(self).causal_past(fact)?;
            Ok(causal.graph().semantic_noop(&fact.content.body))
        } else {
            Ok(self.semantic_noop(&fact.content.body))
        }
    }

    fn semantic_noop(&self, body: &FactBody) -> Option<&'static str> {
        let evaluator = self.evaluator();
        match body {
            FactBody::RoleGrant { target, role }
                if evaluator.effective_role(target) == Some(*role) =>
            {
                Some("role grant already effective")
            }
            FactBody::RoleRevoke { target } => {
                let absent = match evaluator.projection().role_cell(target) {
                    None => !self.authority_roots.contains(target),
                    Some(super::projection::CellProjection::Conflict(_)) => false,
                    Some(super::projection::CellProjection::Value(id)) => self
                        .facts
                        .get(id)
                        .and_then(|fact| super::verify::projected_role(&fact.content.body, target))
                        .is_none(),
                };
                absent.then_some("role revoke targets an absent role")
            }
            FactBody::MembershipAdmit { target }
                if evaluator.effective_membership(target) == Some(true) =>
            {
                Some("membership is already admitted")
            }
            FactBody::Evict { target } if evaluator.effective_membership(target) == Some(false) => {
                Some("membership is already evicted")
            }
            FactBody::SelfStandDown { device_id, .. } if evaluator.is_stood_down(device_id) => {
                Some("stand-down is already effective")
            }
            FactBody::Resolution { cell, .. } if !evaluator.is_conflicted(cell) => {
                Some("resolution has no live conflict")
            }
            FactBody::AuthorityLineageResolution { subject, .. }
                if !self.authority_lineage(subject).is_conflicted() =>
            {
                Some("authority-lineage resolution has no live conflict")
            }
            _ => None,
        }
    }

    fn validate_eviction_proof(
        &self,
        target: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        if !self.is_authorized_for(
            &FactBody::Evict {
                target: target.clone(),
            },
            author,
        ) {
            return Err(SemanticError::UnauthorizedEviction);
        }
        for evidence_id in evidence {
            let Some(attestation) = self.facts.get(evidence_id) else {
                return Err(SemanticError::InvalidEvictionEvidence);
            };
            let FactBody::Attestation {
                target: attestation_target,
                decision: super::AttestationDecision::Evict,
                signer,
                ..
            } = &attestation.content.body
            else {
                return Err(SemanticError::InvalidEvictionEvidence);
            };
            if attestation_target != target
                || !self.evaluator().has_tier(signer, Role::Member)
                || *signer != attestation.content.author
            {
                return Err(SemanticError::InvalidEvictionEvidence);
            }
        }
        Ok(())
    }

    /// Return the existing domain-specific admission error for every fact that
    /// can mutate governance or an exclusive cell. Participation and durable
    /// evidence retain their separate self-author/proof rules below; they do
    /// not become implicitly authorized by this table.
    fn authorization_error(body: &FactBody) -> Option<SemanticError> {
        match body {
            FactBody::RoleGrant { .. }
            | FactBody::RoleRevoke { .. }
            | FactBody::Evict { .. }
            | FactBody::Resolution { .. }
            | FactBody::AuthorityLineageResolution { .. } => {
                Some(SemanticError::UnauthorizedRoleGrant)
            }
            FactBody::MembershipAdmit { .. } => Some(SemanticError::UnauthorizedMembershipAdmit),
            FactBody::Attestation { .. } => Some(SemanticError::UnauthorizedAttestation),
            _ => None,
        }
    }

    /// Require an authority-bearing candidate to carry each signed
    /// AuthorityUse predecessor set in its own causal past. Receiver arrival
    /// order is intentionally irrelevant; concurrent omitted forks remain
    /// explicit conflicts in projection.
    fn validate_authority_lineage(
        &self,
        fact: &SignedFact,
        error: SemanticError,
    ) -> Result<(), SemanticError> {
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            let Some(use_) = fact
                .content
                .authority_uses
                .iter()
                .find(|use_| use_.subject == subject)
            else {
                return Err(error);
            };
            let expected = self.raw_authority_use_heads(&subject);
            let mut actual = use_.predecessors.clone();
            actual.sort();
            actual.dedup();
            let payload_local = Self::is_payload_local_resolution(
                &fact.content.body,
                &fact.content.author,
                &subject,
            );
            if actual != expected
                || (expected.len() > 1
                    && !payload_local
                    && !Self::resolution_selects_authority_heads(&fact.content.body, &subject)
                    && !self.same_cell_role_resolution(&fact.content.body, &subject, &expected))
            {
                return Err(error);
            }
        }
        Ok(())
    }

    fn resolution_selects_authority_heads(body: &FactBody, subject: &DeviceId) -> bool {
        matches!(
            body,
            FactBody::AuthorityLineageResolution {
                subject: selected_subject,
                ..
            } if selected_subject == subject
        )
    }

    fn same_cell_role_resolution(
        &self,
        body: &FactBody,
        subject: &DeviceId,
        expected: &[FactId],
    ) -> bool {
        let FactBody::Resolution {
            cell: ExclusiveCell::Role {
                subject: cell_subject,
            },
            cited_heads,
            ..
        } = body
        else {
            return false;
        };
        cell_subject == subject
            && cited_heads == expected
            && expected.iter().all(|head| {
                self.facts.get(head).is_some_and(|fact| {
                    super::verify::body_advances_cell(
                        &fact.content.body,
                        &ExclusiveCell::role(subject.clone()),
                    )
                })
            })
    }

    fn validate_self_stand_down(
        &self,
        device_id: &DeviceId,
        evidence: &[FactId],
        author: &DeviceId,
    ) -> Result<(), SemanticError> {
        if device_id != author {
            return Err(SemanticError::InvalidStandDownProof);
        }
        for evidence_id in evidence {
            let Some(proof) = self.facts.get(evidence_id) else {
                return Err(SemanticError::InvalidStandDownProof);
            };
            let FactBody::EvictionProof { target, .. } = &proof.content.body else {
                return Err(SemanticError::InvalidStandDownProof);
            };
            if target != device_id {
                return Err(SemanticError::InvalidStandDownProof);
            }
        }
        Ok(())
    }

    pub fn is_authorized_signer(&self, signer: &DeviceId) -> bool {
        self.evaluator().effective_role(signer).is_some()
    }

    fn is_authorized_for(&self, body: &FactBody, author: &DeviceId) -> bool {
        self.evaluator().authorizes(author, body)
    }

    pub fn missing_dependencies(&self, fact: &SignedFact) -> Vec<FactId> {
        dependencies(fact)
            .into_iter()
            .filter(|dependency| !self.facts.contains_key(dependency))
            .collect()
    }

    fn wake_dependency(&mut self, dependency: FactId) {
        let Some(waiters) = self.waiting_by_dependency.remove(&dependency) else {
            return;
        };
        for waiter in waiters {
            let Some(missing) = self.quarantine_missing.get_mut(&waiter) else {
                continue;
            };
            missing.remove(&dependency);
            if missing.is_empty() {
                self.ready_quarantine.insert(waiter);
            }
        }
    }

    fn remove_quarantine(&mut self, id: &FactId) -> Result<Option<SignedFact>, SemanticError> {
        let Some(stored) = self.quarantined.get(id) else {
            self.ready_quarantine.remove(id);
            return Ok(None);
        };
        let cost = self.fact_cost(stored)?;
        let Some(fact) = self.quarantined.remove(id) else {
            self.ready_quarantine.remove(id);
            return Ok(None);
        };
        self.ready_quarantine.remove(id);
        let missing = self.quarantine_missing.remove(id).unwrap_or_default();
        for dependency in missing {
            let empty = if let Some(waiters) = self.waiting_by_dependency.get_mut(&dependency) {
                waiters.remove(id);
                waiters.is_empty()
            } else {
                false
            };
            if empty {
                self.waiting_by_dependency.remove(&dependency);
            }
        }
        self.quarantined_bytes = self
            .quarantined_bytes
            .checked_sub(cost.encoded_bytes)
            .expect("quarantine bytes remain owned");
        self.quarantined_dependency_edges = self
            .quarantined_dependency_edges
            .checked_sub(cost.dependency_edges)
            .expect("quarantine edges remain owned");
        if let Some((count, bytes)) = self.quarantined_by_author.get_mut(&fact.content.author) {
            *count = count
                .checked_sub(1)
                .expect("quarantine author count remains owned");
            *bytes = bytes
                .checked_sub(cost.encoded_bytes)
                .expect("quarantine author bytes remain owned");
            if *count == 0 {
                self.quarantined_by_author.remove(&fact.content.author);
            }
        }
        Ok(Some(fact))
    }

    /// Build the exact graph visible to a candidate fact.  Facts that merely
    /// arrived earlier in this process, but are not ancestors or explicitly
    /// cited evidence, are deliberately excluded from authorization and head
    /// resolution.
    fn causal_past(&self, fact: &SignedFact) -> Result<CausalAdmissionGraph<'_>, SemanticError> {
        // A normal current-head role operation carries every indexed head
        // that can affect its authority or exclusive cell.  Prove that local
        // boundary first and borrow the canonical graph directly; concurrent
        // or stale branches fall through to the exact candidate-relative
        // closure below.
        if self.current_heads_are_complete(fact) {
            return Ok(CausalAdmissionGraph::Full(self));
        }
        let mut ids = BTreeSet::new();
        let mut pending = dependencies(fact);
        while let Some(id) = pending.pop() {
            if !ids.insert(id) {
                continue;
            }
            let Some(parent) = self.facts.get(&id) else {
                return Err(SemanticError::MissingParent(id));
            };
            if let Some(dependencies) = self.indexed_dependencies(&id) {
                pending.extend(dependencies.iter().copied());
            } else {
                pending.extend(dependencies(parent));
            }
        }
        if ids.len() == self.facts.len() {
            return Ok(CausalAdmissionGraph::Full(self));
        }
        let mut causal = Self {
            facts: ids
                .into_iter()
                .filter_map(|id| self.facts.get(&id).cloned().map(|fact| (id, fact)))
                .collect(),
            admitted_fact_count: 0,
            admission_order: Vec::new(),
            quarantined: BTreeMap::new(),
            policy_limits: self.policy_limits,
            admitted_bytes: 0,
            derived_index_bytes: 0,
            quarantined_bytes: 0,
            admitted_dependency_edges: 0,
            quarantined_dependency_edges: 0,
            quarantined_by_author: BTreeMap::new(),
            retained_by_author: BTreeMap::new(),
            quarantine_missing: BTreeMap::new(),
            waiting_by_dependency: BTreeMap::new(),
            ready_quarantine: BTreeSet::new(),
            context_id: self.context_id,
            authority_roots: self.authority_roots.clone(),
            policy: self.policy.clone(),
            cell_heads_index: BTreeMap::new(),
            authority_heads_index: BTreeMap::new(),
            #[cfg(test)]
            authority_dependents_index: BTreeMap::new(),
            authority_facts_index: BTreeMap::new(),
            authority_selector_index: BTreeMap::new(),
            authority_provenance: BTreeMap::new(),
            #[cfg(test)]
            dependency_index: BTreeMap::new(),
            cells_index: BTreeSet::new(),
            stand_down_index: BTreeMap::new(),
            indexed_fact_count: 0,
            facts_revision: 0,
            indexed_revision: 0,
            generation: 0,
            defer_projection_commitment: false,
            cold_history_since_retirement: 0,
            staged_cold_pending: 0,
            projection_cache: Arc::new(Mutex::new(None)),
        };
        causal.rebuild_indexes();
        // A provenance capacity failure is transactional, never an apparent
        // authorization denial that retry could terminally discard.
        causal.rebuild_provenance_checked()?;
        Ok(CausalAdmissionGraph::Scoped(causal))
    }

    fn current_heads_are_complete(&self, fact: &SignedFact) -> bool {
        if !self.indexes_current() {
            return false;
        }
        if !matches!(
            &fact.content.body,
            FactBody::RoleGrant { .. } | FactBody::RoleRevoke { .. }
        ) {
            return false;
        }
        let parents = &fact.content.parents;
        for cell in fact.content.body.exclusive_cells() {
            if self
                .raw_cell_heads(&cell)
                .iter()
                .any(|head| !parents.contains(head))
            {
                return false;
            }
        }
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            if self
                .raw_authority_use_heads(&subject)
                .iter()
                .any(|head| !parents.contains(head))
            {
                return false;
            }
        }
        true
    }

    /// Derive exclusive-cell predecessors and typed AuthorityUse predecessors
    /// from the current canonical graph. This signed profile prevents stale
    /// forks from silently regaining root fallback.
    pub fn authoring_witness(&self, body: &FactBody, author: &DeviceId) -> AuthoringWitness {
        let required_tier = self.evaluator().required_tier(body);
        let mut parents = body
            .exclusive_cells()
            .into_iter()
            .flat_map(|cell| self.cell_heads(&cell))
            .collect::<Vec<_>>();
        for subject in body.authority_use_subjects(author) {
            parents.extend(self.authority_use_heads(&subject));
        }
        if let FactBody::MembershipAdmit { target } = body {
            parents.extend(self.stand_down_heads(target));
        }
        parents.sort();
        parents.dedup();
        AuthoringWitness {
            author: author.clone(),
            parents,
            required_tier,
        }
    }

    /// Retry only facts woken by a newly admitted dependency. The waiter index
    /// avoids scanning unrelated quarantine entries and the owner-selected
    /// batch limit bounds one admission's retry work.
    pub fn retry_quarantined(&mut self) -> Result<Vec<FactId>, SemanticError> {
        self.ensure_indexes_current();
        let mut rollback = GraphRollback::new(self);
        let result = self.retry_quarantined_inner(&mut rollback);
        if result.is_err() {
            rollback.restore(self);
        }
        result
    }

    fn retry_quarantined_inner(
        &mut self,
        rollback: &mut GraphRollback,
    ) -> Result<Vec<FactId>, SemanticError> {
        let batch_limit = usize::try_from(self.policy_limits.max_ready_batch).map_err(|_| {
            SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: u64::try_from(usize::MAX).unwrap_or(u64::MAX),
                observed: self.policy_limits.max_ready_batch,
            }
        })?;
        if batch_limit == 0 {
            return Err(SemanticError::CapacityExceeded {
                dimension: super::SemanticCapacityDimension::ReadyBatch,
                limit: 0,
                observed: 1,
            });
        }
        let mut inserted = Vec::new();
        let mut first_error = None;
        while !self.ready_quarantine.is_empty() {
            let ready = self
                .ready_quarantine
                .iter()
                .copied()
                .take(batch_limit)
                .collect::<Vec<_>>();
            if ready.is_empty() {
                return first_error.map_or(Ok(inserted), Err);
            }
            for id in ready {
                rollback.capture_fact(self, id);
                if let Some(fact) = self.quarantined.get(&id) {
                    rollback.capture_author(self, &fact.content.author);
                    rollback.capture_dependency(self, id);
                    for dependency in dependencies(fact) {
                        rollback.capture_dependency(self, dependency);
                    }
                }
                let Some(fact) = self.remove_quarantine(&id)? else {
                    continue;
                };
                let cost = self.fact_cost(&fact)?;
                let author = fact.content.author.clone();
                let body = fact.content.body.clone();
                let candidate_dependencies = dependencies(&fact);
                match self.admit_inner(fact, true) {
                    Ok(Admission::Inserted) => inserted.push(id),
                    Ok(Admission::AlreadyPresent | Admission::Quarantined { .. }) => {}
                    Err(error)
                        if Self::is_terminal_authorization_waiter(
                            self,
                            &body,
                            &author,
                            &candidate_dependencies,
                            &error,
                        ) =>
                    {
                        self.release_author(&author, &cost);
                    }
                    Err(error) => {
                        self.release_author(&author, &cost);
                        // A ready fact can still fail causal authorization or
                        // canonical validation.  It is rejected and removed;
                        // retaining it would let one malformed FactId starve
                        // every valid sibling in the same ready round.
                        first_error.get_or_insert(error);
                    }
                }
            }
        }
        first_error.map_or(Ok(inserted), Err)
    }

    pub fn quarantined(&self) -> impl Iterator<Item = (&FactId, &SignedFact)> {
        self.quarantined.iter()
    }

    pub fn cell_heads(&self, cell: &super::ExclusiveCell) -> Vec<FactId> {
        self.cell_heads_with_ancestry(cell, &mut |ancestor, descendant| {
            Ok::<_, std::convert::Infallible>(self.is_ancestor(ancestor, descendant))
        })
        .unwrap_or_else(|never| match never {})
    }

    fn cell_heads_with_ancestry<E>(
        &self,
        cell: &ExclusiveCell,
        ancestry: &mut impl FnMut(&FactId, &FactId) -> Result<bool, E>,
    ) -> Result<Vec<FactId>, E> {
        let raw = self.raw_cell_heads(cell);
        let mut authoritative = Vec::new();
        for id in &raw {
            if self.fact_is_authoritative_with_ancestry(id, ancestry)? {
                authoritative.push(*id);
            }
        }
        if authoritative.is_empty() && raw.len() > 1 {
            // A concurrent AuthorityUse fork may make each branch
            // individually ineligible; retain the raw incomparable set so
            // projection exposes an explicit conflict rather than silently
            // erasing the cell.
            Ok(raw)
        } else {
            Ok(authoritative)
        }
    }

    /// Select the same eligible cell heads as `cell_heads`, using bounded
    /// durable rows only when signed-parent reachability leaves the hot cache.
    /// The loader must enforce the owner's existing proof-link/byte limits.
    /// Current indexes and selector provenance remain on this graph; the
    /// supplemental rows never become a second graph or authority frontier.
    pub(crate) fn proof_cell_heads_with_history<E>(
        &self,
        cells: &[ExclusiveCell],
        mut load: impl FnMut(FactId) -> Result<Vec<SignedFact>, E>,
    ) -> Result<Vec<FactId>, ProofAncestryError<E>> {
        if !self.indexes_current() {
            return Err(ProofAncestryError::Invalid("stale proof head index"));
        }
        // Check the entire candidate set before evaluating any eligibility or
        // applying the ordinary multi-head conflict fallback.
        for cell in cells {
            for id in self.raw_cell_heads(cell) {
                let fact = self
                    .facts
                    .get(&id)
                    .ok_or(ProofAncestryError::Invalid("missing proof head"))?;
                for parent in &fact.content.parents {
                    if !self.facts.contains_key(parent) {
                        return Err(ProofAncestryError::Invalid("missing direct proof parent"));
                    }
                }
            }
        }
        let mut pool: Vec<SignedFact> = Vec::new();
        let mut ancestry = |ancestor: &FactId, descendant: &FactId| {
            if let Some(reachable) =
                Self::parent_reachability(ancestor, descendant, |id| self.facts.get(id))
            {
                return Ok(reachable);
            }
            if pool
                .binary_search_by_key(descendant, |fact| fact.id)
                .is_err()
            {
                // Release the previous allocation before requesting another
                // bounded pool. Reuse it for any descendant already covered.
                drop(std::mem::take(&mut pool));
                pool = load(*descendant).map_err(ProofAncestryError::Read)?;
                pool.sort_unstable_by_key(|fact| fact.id);
                if pool.windows(2).any(|pair| pair[0].id == pair[1].id) {
                    return Err(ProofAncestryError::Invalid("duplicate ancestry row"));
                }
                for fact in &pool {
                    if fact.content.mesh_context != self.context_id {
                        return Err(ProofAncestryError::Invalid("foreign ancestry context"));
                    }
                    fact.verify().map_err(|_| {
                        ProofAncestryError::Invalid("invalid ancestry signature or content")
                    })?;
                    if self.facts.get(&fact.id).is_some_and(|hot| hot != fact) {
                        return Err(ProofAncestryError::Invalid(
                            "ancestry differs from hot body",
                        ));
                    }
                }
            }
            // This is the signed parents relation, NOT the broader dependency
            // index used by the loader to supply a complete bounded pool.
            Self::parent_reachability(ancestor, descendant, |id| {
                pool.binary_search_by_key(id, |fact| fact.id)
                    .ok()
                    .map(|index| &pool[index])
            })
            .ok_or(ProofAncestryError::Invalid(
                "incomplete signed-parent ancestry",
            ))
        };
        let mut heads = Vec::new();
        for cell in cells {
            heads.extend(self.cell_heads_with_ancestry(cell, &mut ancestry)?);
        }
        // At most C*S*(P*(P-1)+L) reachability comparisons for C candidates,
        // S subjects, P direct parents and L current lineage heads. These are
        // bounded by existing semantic policy/index residency. Each cold query
        // is bounded by the loader, not constant-cost; only one pool is retained.
        Ok(heads)
    }

    /// None distinguishes missing bodies from a complete negative answer.
    /// Inspect every reachable signed parent, even after finding a path, so a
    /// used incomplete pool cannot masquerade as a verified positive answer.
    fn parent_reachability<'a>(
        ancestor: &FactId,
        descendant: &FactId,
        mut lookup: impl FnMut(&FactId) -> Option<&'a SignedFact>,
    ) -> Option<bool> {
        let mut pending = vec![*descendant];
        let mut seen = BTreeSet::from([*descendant]);
        let mut reachable = false;
        while let Some(id) = pending.pop() {
            let fact = lookup(&id)?;
            for parent in &fact.content.parents {
                reachable |= parent == ancestor;
                if seen.insert(*parent) {
                    pending.push(*parent);
                }
            }
        }
        Some(reachable)
    }

    pub fn authority_use_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        self.authority_lineage(subject).heads().to_vec()
    }

    /// Return the semantic owner's complete current AuthorityLineage relation.
    /// The returned value is graph-derived and cannot be supplied by a fact,
    /// transport envelope, or compatibility role map.
    pub fn authority_lineage(&self, subject: &DeviceId) -> super::content::AuthorityLineage {
        let heads = self.raw_authority_use_heads(subject);
        let selected_branch = self.selected_authority_branch(subject, &heads);
        super::content::AuthorityLineage::from_heads(subject.clone(), heads, selected_branch)
    }

    fn raw_authority_use_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        let ids: Vec<_> = if self.indexes_current() {
            self.authority_heads_index
                .get(subject)
                .into_iter()
                .flat_map(|ids| ids.iter().copied())
                .filter(|id| {
                    self.facts.get(id).is_some_and(|fact| {
                        !Self::is_payload_local_resolution(
                            &fact.content.body,
                            &fact.content.author,
                            subject,
                        )
                    })
                })
                .collect()
        } else {
            let candidates = self
                .facts
                .iter()
                .filter_map(|(id, fact)| {
                    fact.content
                        .authority_uses
                        .iter()
                        .any(|use_| {
                            &use_.subject == subject
                                && !Self::is_payload_local_resolution(
                                    &fact.content.body,
                                    &fact.content.author,
                                    subject,
                                )
                        })
                        .then_some(*id)
                })
                .collect::<Vec<_>>();
            self.maximal_ids(&candidates)
        };
        ids
    }

    /// A non-self Membership resolution may need to carry an AuthorityUse
    /// witness for its payload subject, but that witness is not a persistent
    /// Role-lineage edge. A self-authored Membership witness remains an author
    /// edge. Otherwise a
    /// payload resolution could collapse an unrelated Role fork into one
    /// apparent head and revive a losing branch.
    fn is_payload_local_resolution(body: &FactBody, author: &DeviceId, subject: &DeviceId) -> bool {
        match body {
            FactBody::Resolution {
                cell:
                    ExclusiveCell::Membership {
                        subject: cell_subject,
                    },
                ..
            } => cell_subject == subject && cell_subject != author,
            _ => false,
        }
    }

    pub(crate) fn raw_cell_heads(&self, cell: &super::ExclusiveCell) -> Vec<FactId> {
        let ids: Vec<_> = if self.indexes_current() {
            self.cell_heads_index
                .get(cell)
                .into_iter()
                .flat_map(|ids| ids.iter().copied())
                .collect()
        } else {
            let candidates = self
                .facts
                .iter()
                .filter_map(|(id, fact)| {
                    fact.content
                        .body
                        .exclusive_cells()
                        .contains(cell)
                        .then_some(*id)
                })
                .collect::<Vec<_>>();
            self.maximal_ids(&candidates)
        };
        ids
    }

    /// Compute exact maximal heads only for stale direct-loader state. Normal
    /// admissions use the maintained index and do not perform this walk.
    fn maximal_ids(&self, ids: &[FactId]) -> Vec<FactId> {
        ids.iter()
            .copied()
            .filter(|candidate| {
                !ids.iter()
                    .any(|other| candidate != other && self.is_ancestor(candidate, other))
            })
            .collect()
    }

    /// Whether one admitted fact still belongs to its signed profile lineage.
    /// The signed predecessor set is evaluated against the fact's own causal
    /// past, not receiver arrival order. Concurrent forks remain explicit
    /// conflicting heads and therefore fail closed in projection.
    pub(crate) fn fact_is_authoritative(&self, id: &FactId) -> bool {
        self.fact_is_authoritative_with_ancestry(id, &mut |ancestor, descendant| {
            Ok::<_, std::convert::Infallible>(self.is_ancestor(ancestor, descendant))
        })
        .unwrap_or_else(|never| match never {})
    }

    fn fact_is_authoritative_with_ancestry<E>(
        &self,
        id: &FactId,
        ancestry: &mut impl FnMut(&FactId, &FactId) -> Result<bool, E>,
    ) -> Result<bool, E> {
        let Some(fact) = self.facts.get(id) else {
            return Ok(false);
        };
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            let payload_local = Self::is_payload_local_resolution(
                &fact.content.body,
                &fact.content.author,
                &subject,
            );
            let lineage = self.authority_lineage(&subject);
            if !payload_local && !self.selector_provenance_complete(&subject) {
                return Ok(false);
            }
            if !payload_local
                && self
                    .maximal_typed_selectors(&subject, lineage.heads())
                    .len()
                    > 1
            {
                return Ok(false);
            }
            if !payload_local && !lineage.is_singular() {
                let mut common_ancestor = true;
                for head in lineage.heads() {
                    if fact.id != *head && !ancestry(&fact.id, head)? {
                        common_ancestor = false;
                        break;
                    }
                }
                if !common_ancestor {
                    // Concurrent signed uses are an explicit authority fork.
                    // A later Resolution can supersede the fork because it
                    // becomes the sole AuthorityUse head and cites both
                    // branches. Common causal ancestors remain authoritative.
                    return Ok(false);
                }
            }
            let Some(use_) = fact
                .content
                .authority_uses
                .iter()
                .find(|use_| use_.subject == subject)
            else {
                return Ok(false);
            };
            let expected =
                self.authority_use_heads_from_parents_with_ancestry(fact, &subject, ancestry)?;
            if use_.predecessors != expected {
                return Ok(false);
            }
            if !payload_local {
                let Some(selectors) = self.relevant_typed_selectors(&subject, lineage.heads())
                else {
                    return Ok(false);
                };
                for selector in selectors {
                    if !self.selector_permits_fact(selector, fact.id) {
                        // Public selected_branch is intentionally None during
                        // an unresolved ordinary fork. It is NOT proof that
                        // earlier typed exclusions disappeared. Compose all
                        // still-relevant selectors: raw ancestry through an
                        // old losing edge cannot resurrect that signed row.
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    /// Return a branch selected by the unique latest typed lineage selector.
    /// Ordinary same-cell resolutions never establish this persistent
    /// relation; their projection is handled by the exclusive cell itself.
    fn selected_authority_branch(&self, subject: &DeviceId, heads: &[FactId]) -> Option<FactId> {
        if heads.len() != 1 {
            return None;
        }
        let selectors = self.maximal_typed_selectors(subject, heads);
        let [selector] = selectors.as_slice() else {
            return None;
        };
        let FactBody::AuthorityLineageResolution { selected_head, .. } =
            &self.facts.get(selector)?.content.body
        else {
            return None;
        };
        Some(*selected_head)
    }

    fn selector_provenance_complete(&self, subject: &DeviceId) -> bool {
        self.authority_selector_index
            .get(subject)
            .into_iter()
            .flatten()
            .all(|(selector, selected)| {
                self.authority_provenance
                    .get(selector)
                    .and_then(|row| row.get(selector))
                    .is_some_and(|relation| {
                        relation.post_selector && relation.selected == *selected
                    })
            })
    }

    fn ancestral_typed_selectors(&self, subject: &DeviceId, heads: &[FactId]) -> BTreeSet<FactId> {
        let mut candidates = BTreeSet::new();
        for head in heads {
            for (selector, relation) in self.authority_provenance.get(head).into_iter().flatten() {
                if relation.post_selector && self.facts.get(selector).is_some_and(|fact| {
                    matches!(&fact.content.body, FactBody::AuthorityLineageResolution { subject: selected_subject, selected_head, .. }
                        if selected_subject == subject && *selected_head == relation.selected)
                }) { candidates.insert(*selector); }
            }
        }
        candidates
    }

    fn maximal_typed_selectors(&self, subject: &DeviceId, heads: &[FactId]) -> Vec<FactId> {
        let candidates = self.ancestral_typed_selectors(subject, heads);
        candidates
            .iter()
            .copied()
            .filter(|candidate| {
                !candidates.iter().any(|other| {
                    candidate != other
                        && self
                            .authority_provenance
                            .get(other)
                            .and_then(|row| row.get(candidate))
                            .is_some_and(|relation| relation.post_selector)
                })
            })
            .collect()
    }

    fn selector_permits_fact(&self, selector: FactId, fact: FactId) -> bool {
        let Some(SignedFact { content, .. }) = self.facts.get(&selector) else {
            return false;
        };
        let FactBody::AuthorityLineageResolution { selected_head, .. } = &content.body else {
            return false;
        };
        self.authority_provenance
            .get(&fact)
            .and_then(|row| row.get(&selector))
            .is_some_and(|relation| {
                relation.selected == *selected_head
                    && (relation.post_selector
                        || relation.selected_before
                        || relation.before_selected)
            })
    }

    fn relevant_typed_selectors(
        &self,
        subject: &DeviceId,
        heads: &[FactId],
    ) -> Option<Vec<FactId>> {
        // Relations remain raw, canonically validated reachability facts.
        // Evaluate context relevance newest-first. A selector on the losing
        // branch of a later selector must not veto its selected competitor;
        // an earlier selector common to both later branches still applies.
        // Scratch is bounded by this subject's retained charged contexts,
        // never by all fact bodies or a cloned projection.
        let mut pending = self.ancestral_typed_selectors(subject, heads);
        let mut relevant = Vec::new();
        while !pending.is_empty() {
            let maxima = pending
                .iter()
                .copied()
                .filter(|candidate| {
                    !pending.iter().any(|other| {
                        candidate != other
                            && self
                                .authority_provenance
                                .get(other)
                                .and_then(|row| row.get(candidate))
                                .is_some_and(|relation| relation.post_selector)
                    })
                })
                .collect::<Vec<_>>();
            if maxima.is_empty() {
                // Canonical signed history is acyclic. A damaged in-memory
                // summary must not erase its exclusions on a cycle.
                return None;
            }
            let permitted = maxima
                .iter()
                .copied()
                .filter(|candidate| {
                    relevant
                        .iter()
                        .all(|later| self.selector_permits_fact(*later, *candidate))
                })
                .collect::<Vec<_>>();
            for selector in maxima {
                pending.remove(&selector);
            }
            relevant.extend(permitted);
        }
        Some(relevant)
    }

    #[cfg(test)]
    fn authority_use_heads_from_parents(
        &self,
        fact: &SignedFact,
        subject: &DeviceId,
    ) -> Vec<FactId> {
        self.authority_use_heads_from_parents_with_ancestry(
            fact,
            subject,
            &mut |ancestor, descendant| {
                Ok::<_, std::convert::Infallible>(self.is_ancestor(ancestor, descendant))
            },
        )
        .unwrap_or_else(|never| match never {})
    }

    fn authority_use_heads_from_parents_with_ancestry<E>(
        &self,
        fact: &SignedFact,
        subject: &DeviceId,
        ancestry: &mut impl FnMut(&FactId, &FactId) -> Result<bool, E>,
    ) -> Result<Vec<FactId>, E> {
        // Authoring witnesses carry the current AuthorityUse heads directly
        // in the signed parent list. V4 has no ancestry-search compatibility
        // path: an incomplete signed witness is authority-negative.
        let direct = fact
            .content
            .parents
            .iter()
            .copied()
            .filter(|id| {
                self.facts.get(id).is_some_and(|parent| {
                    parent.content.authority_uses.iter().any(|use_| {
                        &use_.subject == subject
                            && !Self::is_payload_local_resolution(
                                &parent.content.body,
                                &parent.content.author,
                                subject,
                            )
                    })
                })
            })
            .collect::<Vec<_>>();
        let mut maxima = Vec::new();
        for candidate in &direct {
            let mut dominated = false;
            for other in &direct {
                if candidate != other && ancestry(candidate, other)? {
                    dominated = true;
                    break;
                }
            }
            if !dominated {
                maxima.push(*candidate);
            }
        }
        Ok(maxima)
    }

    /// Return the maximal active stand-down evidence for one subject.  These
    /// facts are outside the ordinary exclusive-cell union, so a restoration
    /// must carry them explicitly rather than silently omitting the proof.
    fn stand_down_heads(&self, subject: &DeviceId) -> Vec<FactId> {
        if self.indexes_current() {
            let ids = self
                .stand_down_index
                .get(subject)
                .into_iter()
                .flat_map(|ids| ids.iter().copied())
                .filter(|id| self.fact_is_authoritative(id))
                .collect::<Vec<_>>();
            return ids
                .iter()
                .copied()
                .filter(|candidate| {
                    !ids.iter()
                        .any(|other| candidate != other && self.direct_dependency(other, candidate))
                })
                .collect();
        }
        let ids = self
            .facts
            .iter()
            .filter_map(|(id, fact)| {
                let target = match &fact.content.body {
                    FactBody::EvictionProof { target, .. }
                    | FactBody::SelfStandDown {
                        device_id: target, ..
                    } => Some(target),
                    _ => None,
                };
                (target == Some(subject) && self.fact_is_authoritative(id)).then_some(*id)
            })
            .collect::<Vec<_>>();
        self.maximal_ids(&ids)
    }

    fn direct_dependency(&self, descendant: &FactId, ancestor: &FactId) -> bool {
        self.facts
            .get(descendant)
            .is_some_and(|fact| dependencies(fact).contains(ancestor))
    }

    /// Return the incomparable head set only when the cell is conflicted.
    pub fn conflict_heads(&self, cell: &super::ExclusiveCell) -> Option<Vec<FactId>> {
        let heads = self.cell_heads(cell);
        (heads.len() > 1).then_some(heads)
    }

    pub fn is_ancestor(&self, ancestor: &FactId, descendant: &FactId) -> bool {
        let mut pending = vec![*descendant];
        let mut seen = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            let Some(fact) = self.facts.get(&id) else {
                continue;
            };
            for parent in &fact.content.parents {
                if parent == ancestor {
                    return true;
                }
                pending.push(*parent);
            }
        }
        false
    }

    /// Canonical roots needed before a cold/new-selector operation can
    /// introduce new reachability anchors. The publication owner resolves
    /// these once under its existing bounded SQLite history contract.
    pub(crate) fn selector_provenance_history_roots(
        &self,
        candidates: &[SignedFact],
    ) -> Vec<FactId> {
        if self.admitted_fact_count <= self.facts.len() as u64 {
            return Vec::new();
        }
        let mut pending = self.ready_quarantine.iter().copied().collect::<Vec<_>>();
        pending.extend(candidates.iter().map(|fact| fact.id));
        let mut seen = BTreeSet::new();
        let mut selector = candidates.iter().any(|fact| {
            matches!(
                fact.content.body,
                FactBody::AuthorityLineageResolution { .. }
            )
        });
        while let Some(id) = pending.pop() {
            if !seen.insert(id) {
                continue;
            }
            selector |= self.quarantined.get(&id).is_some_and(|fact| {
                matches!(
                    fact.content.body,
                    FactBody::AuthorityLineageResolution { .. }
                )
            });
            pending.extend(
                self.waiting_by_dependency
                    .get(&id)
                    .into_iter()
                    .flatten()
                    .copied(),
            );
        }
        let cold_relation = candidates
            .iter()
            .chain(seen.iter().filter_map(|id| self.quarantined.get(id)))
            .any(|fact| {
                let direct = dependencies(fact);
                let hidden_head = fact.content.body.exclusive_cells().iter().any(|cell| {
                    self.cell_heads_index
                        .get(cell)
                        .into_iter()
                        .flatten()
                        .any(|head| !direct.contains(head))
                }) || Self::indexed_authority_subjects(fact).iter().any(
                    |subject| {
                        self.authority_heads_index
                            .get(subject)
                            .into_iter()
                            .flatten()
                            .any(|head| !direct.contains(head))
                    },
                );
                let witness = self.authoring_witness(&fact.content.body, &fact.content.author);
                hidden_head
                    || (!self.authority_provenance.is_empty()
                        && (!self.current_heads_are_complete(fact)
                            || dependencies(fact)
                                .iter()
                                .any(|id| !self.facts.contains_key(id))
                            || fact
                                .content
                                .parents
                                .iter()
                                .any(|id| !witness.parents.contains(id))))
            });
        if !selector && !cold_relation {
            return Vec::new();
        }
        let mut roots = self.facts.keys().copied().collect::<BTreeSet<_>>();
        for fact in candidates {
            roots.extend(dependencies(fact));
        }
        for id in seen {
            if let Some(fact) = self.quarantined.get(&id) {
                roots.extend(dependencies(fact));
            }
        }
        for fact in candidates {
            roots.remove(&fact.id);
        }
        roots
            .into_iter()
            .filter(|id| !self.quarantined.contains_key(id))
            .collect()
    }

    /// Recompute the complete resident graph projection for differential lab
    /// controls, without reading or updating the incremental cache.
    #[cfg(feature = "transport-lab")]
    pub fn full_projection_for_lab(&self) -> (Projection, [u8; 32]) {
        let projection = Projection::from_graph(self);
        let root = projection.commitment_root();
        (projection, root)
    }

    pub fn projection(&self) -> Projection {
        if self.indexes_current() {
            let cached = self.projection_cache.lock().clone();
            if let Some((generation, projection)) = cached {
                if generation == self.generation {
                    return projection;
                }
            }
            let projection = Projection::from_graph(self);
            *self.projection_cache.lock() = Some((self.generation, projection.clone()));
            projection
        } else {
            Projection::from_graph(self)
        }
    }

    fn projection_for_update(&self) -> Projection {
        let mut cache = self.projection_cache.lock();
        if let Some((generation, projection)) = cache.take() {
            if generation == self.generation {
                return projection;
            }
        }
        Projection::from_graph(self)
    }

    fn projection_delta_from_sparse(
        &self,
        base_generation: u64,
        generation: u64,
        base_commitment: [u8; 32],
        previous_cells: &BTreeMap<ExclusiveCell, Option<super::CellProjection>>,
        previous_stand_down: &BTreeMap<DeviceId, Option<super::StandDown>>,
    ) -> super::projection::ProjectionDelta {
        let cache = self.projection_cache.lock();
        if let Some((cached_generation, projection)) = cache.as_ref() {
            if *cached_generation == self.generation {
                return projection.delta_from_sparse(
                    base_generation,
                    generation,
                    base_commitment,
                    previous_cells,
                    previous_stand_down,
                );
            }
        }
        drop(cache);
        Projection::from_graph(self).delta_from_sparse(
            base_generation,
            generation,
            base_commitment,
            previous_cells,
            previous_stand_down,
        )
    }

    /// Construct the sealed evaluator for this graph's exact bootstrap policy.
    /// Callers cannot provide an alternate root, profile, or policy snapshot.
    pub fn evaluator(&self) -> SemanticEvaluator<'_> {
        SemanticEvaluator {
            graph: self,
            projection: self.projection(),
        }
    }

    /// Decide the canonical session policy for two devices.  The bootstrap
    /// binding is checked here so callers cannot pair a graph with an
    /// unrelated policy or context; transport callers only consume this
    /// typed verdict.
    pub fn admits_policy_session(
        &self,
        bootstrap: &VerifiedBootstrap,
        local: &DeviceId,
        remote: &DeviceId,
    ) -> bool {
        if self.context_id != bootstrap.context_id() {
            return false;
        }
        let evaluator = self.evaluator();
        match bootstrap.policy() {
            // Open participation is a transport-local policy now; it has no
            // durable fact or projection gate.
            VerifiedProjectPolicy::Open => evaluator.admits_closed_session(local, remote),
            VerifiedProjectPolicy::Closed(_) => evaluator.admits_closed_session(local, remote),
        }
    }

    /// Return the complete causal closure for a currently projected Closed
    /// eviction.  The role and membership cells are both roots because an
    /// eviction advances both independent semantic cells.
    pub fn eviction_proof_bundle(&self, target: &DeviceId) -> Option<Vec<SignedFact>> {
        if self.evaluator().effective_membership(target) != Some(false) {
            return None;
        }
        let mut pending = self.cell_heads(&ExclusiveCell::role(target.clone()));
        pending.extend(self.cell_heads(&ExclusiveCell::membership(target.clone())));
        let mut ids = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if !ids.insert(id) {
                continue;
            }
            let fact = self.get(&id)?;
            pending.extend(dependencies(fact));
        }
        ids.into_iter().map(|id| self.get(&id).cloned()).collect()
    }

    /// Verify projection conditions for a received ordinary fact bundle.
    /// The graph remains the sole authority; this method does not inspect its
    /// carrier or route.
    pub fn bundle_projection_is_verified(&self, facts: &[SignedFact]) -> bool {
        let evaluator = self.evaluator();
        facts.iter().all(|fact| match &fact.content.body {
            FactBody::Evict { target } => evaluator.effective_membership(target) == Some(false),
            FactBody::EvictionProof { target, .. }
            | FactBody::SelfStandDown {
                device_id: target, ..
            } => evaluator.is_stood_down(target),
            _ => true,
        })
    }

    /// Verify that a proof bundle is exactly the causal closure of the
    /// selected target evidence and that the target is currently stood down.
    pub fn proof_bundle_is_verified(&self, target: &DeviceId, facts: &[SignedFact]) -> bool {
        let projection = self.projection();
        let evaluator = self.evaluator();
        if evaluator.effective_membership(target) != Some(false)
            && !projection.is_stood_down(target)
        {
            return false;
        }
        let mut selected_roots = BTreeSet::new();
        selected_roots.extend(self.cell_heads(&ExclusiveCell::role(target.clone())));
        selected_roots.extend(self.cell_heads(&ExclusiveCell::membership(target.clone())));
        if let Some(stand_down) = projection.stand_down(target) {
            selected_roots.insert(stand_down.proof);
        }
        if selected_roots.is_empty() || facts.iter().any(|fact| self.get(&fact.id) != Some(fact)) {
            return false;
        }

        let delivered_ids = facts.iter().map(|fact| fact.id).collect::<BTreeSet<_>>();
        let mut closure = BTreeSet::new();
        let mut pending = selected_roots.into_iter().collect::<Vec<_>>();
        while let Some(id) = pending.pop() {
            if !closure.insert(id) {
                continue;
            }
            let Some(fact) = self.get(&id) else {
                return false;
            };
            pending.extend(dependencies(fact));
        }
        closure == delivered_ids
    }
}

/// Canonical authority evaluator for the validated V4 semantic profile.
///
/// The evaluator is intentionally constructed only by [`FactGraph::evaluator`];
/// its private graph and projection fields prevent callers from substituting a
/// display identity, compatibility role map, or unrelated bootstrap roots.
#[derive(Debug)]
pub struct SemanticEvaluator<'a> {
    graph: &'a FactGraph,
    projection: Projection,
}

impl<'a> SemanticEvaluator<'a> {
    pub(crate) fn projection(&self) -> &Projection {
        &self.projection
    }

    /// Resolve the effective role from the projected role cell. The bootstrap
    /// root is an Owner only while its role cell has never advanced. A revoke,
    /// eviction, conflict, or stand-down therefore removes authority rather
    /// than falling back to the root.
    pub fn effective_role(&self, subject: &DeviceId) -> Option<Role> {
        if self.projection.is_stood_down(subject) {
            return None;
        }
        let role_cell = ExclusiveCell::role(subject.clone());
        if self.projection.is_conflicted(&role_cell) {
            return None;
        }
        let Some(id) = self
            .projection
            .role_cell(subject)
            .and_then(|cell| match cell {
                super::CellProjection::Value(id) => Some(*id),
                super::CellProjection::Conflict(_) => None,
            })
        else {
            return self
                .graph
                .authority_roots
                .contains(subject)
                .then_some(Role::Owner);
        };
        self.effective_role_from_fact(&id, subject)
    }

    /// Effective role for policy projection.  A role-cell value is not enough
    /// to authorize a session while the subject's independent AuthorityUse
    /// relation is forked; the typed relation must be empty (bootstrap) or
    /// singular first.
    pub fn effective_authorized_role(&self, subject: &DeviceId) -> Option<Role> {
        if !self.graph.selector_provenance_complete(subject) {
            return None;
        }
        self.graph
            .authority_lineage(subject)
            .is_singular()
            .then(|| self.effective_role(subject))
            .flatten()
    }

    fn effective_role_from_fact(&self, id: &FactId, subject: &DeviceId) -> Option<Role> {
        let fact = self.graph.facts.get(id)?;
        super::verify::projected_role(&fact.content.body, subject)
    }

    /// Effective membership is explicit when a membership cell has advanced;
    /// callers may treat `None` as the bootstrap-era implicit membership.
    pub fn effective_membership(&self, subject: &DeviceId) -> Option<bool> {
        let cell = ExclusiveCell::membership(subject.clone());
        let fact = self.projected_fact(&cell)?;
        super::verify::projected_membership(&fact.content.body, subject)
    }

    /// Effective attestation decision for one proposal. Conflicts and
    /// malformed resolution chains return `None` through `projected_fact`.
    pub fn effective_decision(&self, proposal: &FactId) -> Option<super::AttestationDecision> {
        let cell = ExclusiveCell::decision(*proposal);
        let fact = self.projected_fact(&cell)?;
        super::verify::projected_decision(&fact.content.body, proposal)
    }

    fn projected_fact(&self, cell: &ExclusiveCell) -> Option<&SignedFact> {
        let id = self.projection.value(cell)?;
        let fact = self.graph.facts.get(&id)?;
        super::verify::body_advances_cell(&fact.content.body, cell).then_some(fact)
    }

    /// Whether an author may create the supplied operation under the current
    /// projected authority. Controllers may grant or demote Controllers, but
    /// only an Owner may grant an Owner.
    pub fn authorizes(&self, author: &DeviceId, body: &FactBody) -> bool {
        let required = match body {
            FactBody::RoleGrant { role, .. } => match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            },
            FactBody::RoleRevoke { target } | FactBody::Evict { target } => {
                self.target_tier(target)
            }
            FactBody::EvictionProof { target, .. } => self.target_tier(target),
            FactBody::MembershipAdmit { .. } => Role::Controller,
            FactBody::Attestation { .. } => Role::Member,
            FactBody::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => self.resolution_tier(cell, cited_heads, selected_head),
            FactBody::AuthorityLineageResolution {
                subject,
                cited_heads,
                selected_head,
            } => self.authority_lineage_resolution_tier(subject, cited_heads, selected_head),
            FactBody::SelfStandDown { device_id, .. } => {
                return author == device_id;
            }
        };
        self.has_tier(author, required)
    }

    /// The tier required by an authoring witness.  This is public so an
    /// authoring caller can use the same candidate-relative rule as admission
    /// without reconstructing predecessor state itself.
    pub fn required_tier(&self, body: &FactBody) -> Option<Role> {
        if matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            return None;
        }
        match body {
            FactBody::RoleGrant { role, .. } => Some(match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            }),
            FactBody::RoleRevoke { target } | FactBody::Evict { target } => {
                Some(self.target_tier(target))
            }
            FactBody::EvictionProof { target, .. } => Some(self.target_tier(target)),
            FactBody::MembershipAdmit { .. } => Some(Role::Controller),
            FactBody::Attestation { .. } => Some(Role::Member),
            FactBody::Resolution {
                cell,
                cited_heads,
                selected_head,
            } => Some(self.resolution_tier(cell, cited_heads, selected_head)),
            FactBody::AuthorityLineageResolution {
                subject,
                cited_heads,
                selected_head,
            } => Some(self.authority_lineage_resolution_tier(subject, cited_heads, selected_head)),
            _ => None,
        }
    }

    /// Session admission for the selected profile. Runtime presence is
    /// transport-local; only Closed membership projection is a durable gate.
    pub fn admits_closed_session(&self, local: &DeviceId, remote: &DeviceId) -> bool {
        if matches!(&self.graph.policy, VerifiedProjectPolicy::Open) {
            return true;
        }
        self.graph.authority_lineage(local).is_singular()
            && self.graph.authority_lineage(remote).is_singular()
            && self.role_admits(local)
            && self.role_admits(remote)
    }

    pub fn is_conflicted(&self, cell: &ExclusiveCell) -> bool {
        self.projection.is_conflicted(cell)
    }

    pub fn is_stood_down(&self, subject: &DeviceId) -> bool {
        self.projection.is_stood_down(subject)
    }

    fn role_admits(&self, subject: &DeviceId) -> bool {
        if self.effective_role(subject).is_none() {
            return false;
        }
        self.effective_membership(subject)
            .is_none_or(|joined| joined)
    }

    fn has_tier(&self, signer: &DeviceId, required: Role) -> bool {
        if !self.graph.selector_provenance_complete(signer) {
            return false;
        }
        let Some(actual) = self.effective_role(signer) else {
            return false;
        };
        matches!(
            (actual, required),
            (Role::Owner, _)
                | (Role::Controller, Role::Controller | Role::Member)
                | (Role::Member, Role::Member)
        )
    }

    fn target_tier(&self, target: &DeviceId) -> Role {
        match self.effective_role(target) {
            Some(Role::Owner) => Role::Owner,
            Some(Role::Controller) => Role::Controller,
            Some(Role::Member) => Role::Controller,
            None => Role::Owner,
        }
    }

    fn resolution_tier(
        &self,
        cell: &ExclusiveCell,
        cited_heads: &[FactId],
        _selected_head: &FactId,
    ) -> Role {
        let mut visited = BTreeSet::new();
        self.resolution_tier_with_visited(cell, cited_heads, &mut visited)
    }

    fn authority_lineage_resolution_tier(
        &self,
        subject: &DeviceId,
        cited_heads: &[FactId],
        selected_head: &FactId,
    ) -> Role {
        self.resolution_tier(
            &ExclusiveCell::role(subject.clone()),
            cited_heads,
            selected_head,
        )
    }

    fn resolution_tier_with_visited(
        &self,
        cell: &ExclusiveCell,
        cited_heads: &[FactId],
        visited: &mut BTreeSet<FactId>,
    ) -> Role {
        match cell {
            ExclusiveCell::Role { subject } => cited_heads
                .iter()
                .filter_map(|head| {
                    let mut branch_visited = visited.clone();
                    self.resolution_candidate_tier(cell, head, subject, &mut branch_visited)
                })
                .max()
                .unwrap_or_else(|| self.target_tier(subject)),
            ExclusiveCell::Membership { subject } => self.target_tier(subject),
            ExclusiveCell::Decision { .. } => Role::Member,
        }
    }

    fn resolution_candidate_tier(
        &self,
        cell: &ExclusiveCell,
        head: &FactId,
        subject: &DeviceId,
        visited: &mut BTreeSet<FactId>,
    ) -> Option<Role> {
        if !visited.insert(*head) {
            return None;
        }
        let fact = self.graph.facts.get(head)?;
        match &fact.content.body {
            FactBody::RoleGrant { target, role } if target == subject => Some(match role {
                Role::Member | Role::Controller => Role::Controller,
                Role::Owner => Role::Owner,
            }),
            FactBody::RoleRevoke { target } if target == subject => {
                let causal = self
                    .graph
                    .causal_past(fact)
                    .ok()?
                    .evaluator()
                    .effective_role(subject);
                Some(match causal {
                    Some(Role::Owner) => Role::Owner,
                    Some(Role::Controller) => Role::Controller,
                    Some(Role::Member) => Role::Controller,
                    None => Role::Owner,
                })
            }
            FactBody::Resolution {
                cell: nested_cell,
                cited_heads,
                ..
            } if nested_cell == cell => {
                Some(self.resolution_tier_with_visited(nested_cell, cited_heads, visited))
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    fn key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    fn device(key: &SigningKey) -> DeviceId {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
            .expect("test key produces a canonical device")
    }

    fn closed(seed: u8) -> (VerifiedBootstrap, SigningKey) {
        let signing_key = key(seed);
        (
            VerifiedBootstrap::create_closed(
                "causal-evaluator",
                vec![signing_key.clone()],
                [seed; 32],
            )
            .expect("closed bootstrap verifies"),
            signing_key,
        )
    }

    fn fact(
        bootstrap: &VerifiedBootstrap,
        signing_key: &SigningKey,
        body: FactBody,
        parents: Vec<FactId>,
    ) -> SignedFact {
        SignedFact::sign(
            super::super::FactContent::new(
                body.domain(),
                bootstrap.context_id(),
                body,
                device(signing_key),
                parents,
            ),
            signing_key,
        )
        .expect("test fact signs")
    }

    fn fact_with_authority_predecessors(
        bootstrap: &VerifiedBootstrap,
        signing_key: &SigningKey,
        body: FactBody,
        parents: Vec<FactId>,
        overrides: &[(DeviceId, Vec<FactId>)],
    ) -> SignedFact {
        let mut content = super::super::FactContent::new(
            body.domain(),
            bootstrap.context_id(),
            body,
            device(signing_key),
            parents,
        );
        for authority_use in &mut content.authority_uses {
            if let Some((_, predecessors)) = overrides
                .iter()
                .find(|(subject, _)| subject == &authority_use.subject)
            {
                let mut predecessors = predecessors.clone();
                predecessors.sort();
                predecessors.dedup();
                authority_use.predecessors = predecessors;
            }
        }
        SignedFact::sign(content, signing_key).expect("authority lineage fact signs")
    }

    fn witnessed_fact(graph: &FactGraph, signing_key: &SigningKey, body: FactBody) -> SignedFact {
        let author = device(signing_key);
        let witness = graph.authoring_witness(&body, &author);
        SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                graph,
                body,
                &witness,
                std::iter::empty(),
            ),
            signing_key,
        )
        .expect("witnessed fact signs")
    }

    // Independent pre-change hot predicate, kept here to check the shared
    // fallible implementation against the original short-circuit contract.
    fn reference_hot_authoritative(graph: &FactGraph, id: &FactId) -> bool {
        let Some(fact) = graph.facts.get(id) else {
            return false;
        };
        for subject in fact
            .content
            .body
            .authority_use_subjects(&fact.content.author)
        {
            let payload_local = FactGraph::is_payload_local_resolution(
                &fact.content.body,
                &fact.content.author,
                &subject,
            );
            let lineage = graph.authority_lineage(&subject);
            if !payload_local && !graph.selector_provenance_complete(&subject) {
                return false;
            }
            if !payload_local
                && graph
                    .maximal_typed_selectors(&subject, lineage.heads())
                    .len()
                    > 1
            {
                return false;
            }
            if !payload_local
                && !lineage.is_singular()
                && !lineage
                    .heads()
                    .iter()
                    .all(|head| fact.id == *head || graph.is_ancestor(&fact.id, head))
            {
                return false;
            }
            let Some(use_) = fact
                .content
                .authority_uses
                .iter()
                .find(|use_| use_.subject == subject)
            else {
                return false;
            };
            let direct = fact
                .content
                .parents
                .iter()
                .copied()
                .filter(|id| {
                    graph.facts.get(id).is_some_and(|parent| {
                        parent.content.authority_uses.iter().any(|use_| {
                            use_.subject == subject
                                && !FactGraph::is_payload_local_resolution(
                                    &parent.content.body,
                                    &parent.content.author,
                                    &subject,
                                )
                        })
                    })
                })
                .collect::<Vec<_>>();
            let expected = direct
                .iter()
                .copied()
                .filter(|candidate| {
                    !direct
                        .iter()
                        .any(|other| candidate != other && graph.is_ancestor(candidate, other))
                })
                .collect::<Vec<_>>();
            assert_eq!(
                graph.authority_use_heads_from_parents(fact, &subject),
                expected
            );
            if use_.predecessors != expected {
                return false;
            }
            if !payload_local {
                let Some(selectors) = graph.relevant_typed_selectors(&subject, lineage.heads())
                else {
                    return false;
                };
                if selectors
                    .into_iter()
                    .any(|selector| !graph.selector_permits_fact(selector, fact.id))
                {
                    return false;
                }
            }
        }
        true
    }

    fn assert_warm_proof_head_parity(graph: &FactGraph) {
        for id in graph.facts.keys() {
            assert_eq!(
                graph.fact_is_authoritative(id),
                reference_hot_authoritative(graph, id)
            );
        }
        for cell in graph.indexed_cells() {
            let raw = graph.raw_cell_heads(&cell);
            let eligible = raw
                .iter()
                .copied()
                .filter(|id| reference_hot_authoritative(graph, id))
                .collect::<Vec<_>>();
            let expected = if eligible.is_empty() && raw.len() > 1 {
                raw
            } else {
                eligible
            };
            assert_eq!(graph.cell_heads(&cell), expected);
            assert_eq!(
                graph
                    .proof_cell_heads_with_history(
                        &[cell],
                        |_| -> Result<Vec<SignedFact>, &'static str> {
                            panic!("complete warm ancestry must not load durable rows")
                        }
                    )
                    .unwrap(),
                expected
            );
        }
    }

    fn cold_proof_fixture() -> (FactGraph, FactGraph, DeviceId, Vec<FactId>, FactId) {
        let (bootstrap, root) = closed(221);
        let target = device(&key(222));
        let mut warm = FactGraph::from_bootstrap(&bootstrap);
        for body in [
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            FactBody::MembershipAdmit {
                target: target.clone(),
            },
        ] {
            let fact = witnessed_fact(&warm, &root, body);
            assert_eq!(warm.admit(fact).unwrap(), Admission::Inserted);
        }
        let mut roles = Vec::new();
        for role in [
            Role::Controller,
            Role::Member,
            Role::Controller,
            Role::Member,
        ] {
            let fact = witnessed_fact(
                &warm,
                &root,
                FactBody::RoleGrant {
                    target: target.clone(),
                    role,
                },
            );
            roles.push(fact.id);
            assert_eq!(warm.admit(fact).unwrap(), Admission::Inserted);
        }
        let evict = witnessed_fact(
            &warm,
            &root,
            FactBody::Evict {
                target: target.clone(),
            },
        );
        let evict_id = evict.id;
        assert_eq!(warm.admit(evict).unwrap(), Admission::Inserted);
        let mut cold = warm.clone();
        cold.seal_live_checkpoint();
        assert!(
            cold.get(&roles[1]).is_none(),
            "middle C2 must actually be cold"
        );
        assert!(
            cold.get(&roles[3]).is_some(),
            "direct C4 endpoint stays hot"
        );
        assert!(cold.get(&evict_id).is_some());
        assert_eq!(cold.evaluator().effective_membership(&target), Some(false));
        (warm, cold, target, roles, evict_id)
    }

    fn proof_history_for_test(graph: &FactGraph, root: FactId) -> Vec<SignedFact> {
        let mut pending = vec![root];
        let mut ids = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if ids.insert(id) {
                pending.extend(dependencies(graph.get(&id).unwrap()));
            }
        }
        ids.into_iter()
            .map(|id| graph.get(&id).unwrap().clone())
            .collect()
    }

    #[test]
    fn proof_ancestry_cold_four_role_chain_preserves_exact_eligible_closure() {
        let (warm, cold, target, _, evict) = cold_proof_fixture();
        assert_warm_proof_head_parity(&warm);
        let cells = [
            ExclusiveCell::role(target.clone()),
            ExclusiveCell::membership(target.clone()),
        ];
        assert!(
            cold.cell_heads(&cells[0]).is_empty(),
            "old hot predicate reproduces missing edge"
        );
        let before = serde_json::to_vec(&cold.live_checkpoint()).unwrap();
        let mut reads = Vec::new();
        let heads = cold
            .proof_cell_heads_with_history(&cells, |root| {
                reads.push(root);
                // Exact descendant closure; production supplies it through bounded SQL.
                Ok::<_, &'static str>(proof_history_for_test(&warm, root))
            })
            .unwrap();
        assert_eq!(heads, vec![evict, evict]);
        assert!((1..=2).contains(&reads.len()));
        assert_eq!(
            reads.iter().copied().collect::<BTreeSet<_>>().len(),
            reads.len(),
            "one pool reuses already covered descendants across both cells"
        );
        let expected = warm.eviction_proof_bundle(&target).unwrap();
        let mut pending = heads;
        let mut ids = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if ids.insert(id) {
                pending.extend(dependencies(warm.get(&id).unwrap()));
            }
        }
        assert_eq!(
            ids.into_iter().collect::<Vec<_>>(),
            expected.iter().map(|fact| fact.id).collect::<Vec<_>>()
        );
        assert_eq!(
            serde_json::to_vec(&cold.live_checkpoint()).unwrap(),
            before,
            "no hydration or mutation"
        );
    }

    #[test]
    fn proof_ancestry_complete_hot_negative_never_loads_history() {
        let (warm, _, _, roles, _) = cold_proof_fixture();
        assert_eq!(
            FactGraph::parent_reachability(&roles[3], &roles[0], |id| warm.get(id)),
            Some(false)
        );
        assert_warm_proof_head_parity(&warm);
    }

    #[test]
    fn proof_ancestry_pool_membership_is_not_signed_parent_reachability() {
        let (warm, _, _, roles, evict) = cold_proof_fixture();
        let mut pool = warm.facts.values().cloned().collect::<Vec<_>>();
        pool.sort_unstable_by_key(|fact| fact.id);
        assert!(pool.binary_search_by_key(&evict, |fact| fact.id).is_ok());
        for ancestor in [evict, roles[0]] {
            let reachable = FactGraph::parent_reachability(&ancestor, &roles[0], |id| {
                pool.binary_search_by_key(id, |fact| fact.id)
                    .ok()
                    .map(|index| &pool[index])
            });
            assert_eq!(
                reachable,
                Some(false),
                "neither row presence nor self is an ancestor"
            );
        }
    }

    #[test]
    fn proof_ancestry_warm_fork_keeps_original_raw_conflict_fallback() {
        let (bootstrap, root) = closed(223);
        let target = device(&key(224));
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let first = witnessed_fact(
            &graph,
            &root,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
        );
        let second = witnessed_fact(
            &graph,
            &root,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
        );
        assert_eq!(graph.admit(first.clone()).unwrap(), Admission::Inserted);
        assert_eq!(graph.admit(second.clone()).unwrap(), Admission::Inserted);
        assert!(!graph.fact_is_authoritative(&first.id));
        assert!(!graph.fact_is_authoritative(&second.id));
        let cell = ExclusiveCell::role(target);
        assert_eq!(graph.cell_heads(&cell).len(), 2);
        assert_warm_proof_head_parity(&graph);
        assert_eq!(
            graph.cell_heads_with_ancestry(&cell, &mut |_, _| {
                Err::<bool, _>("unreadable ancestry")
            }),
            Err("unreadable ancestry"),
            "error must not become the raw-conflict fallback"
        );
    }

    #[test]
    fn proof_ancestry_cold_common_ancestor_keeps_dynamic_fork_gate() {
        let (mut warm, _, target, _, evict) = cold_proof_fixture();
        let root = key(221);
        let other = device(&key(225));
        for role in [
            Role::Member,
            Role::Controller,
            Role::Member,
            Role::Controller,
        ] {
            let fact = witnessed_fact(
                &warm,
                &root,
                FactBody::RoleGrant {
                    target: other.clone(),
                    role,
                },
            );
            assert_eq!(warm.admit(fact).unwrap(), Admission::Inserted);
        }
        let branches = [226, 227].map(|seed| {
            witnessed_fact(
                &warm,
                &root,
                FactBody::RoleGrant {
                    target: device(&key(seed)),
                    role: Role::Member,
                },
            )
        });
        for fact in &branches {
            assert_eq!(warm.admit(fact.clone()).unwrap(), Admission::Inserted);
        }
        assert!(warm.authority_lineage(&device(&root)).is_conflicted());
        assert!(
            warm.fact_is_authoritative(&evict),
            "common ancestor is eligible under both branches"
        );
        let mut cold = warm.clone();
        cold.seal_live_checkpoint();
        assert!(!cold.is_ancestor(&evict, &branches[0].id));
        let mut queried = Vec::new();
        let heads = cold
            .proof_cell_heads_with_history(&[ExclusiveCell::membership(target)], |descendant| {
                queried.push(descendant);
                Ok::<_, &'static str>(proof_history_for_test(&warm, descendant))
            })
            .unwrap();
        assert_eq!(heads, vec![evict]);
        assert!(
            queried
                .iter()
                .any(|id| branches.iter().any(|fact| fact.id == *id)),
            "dynamic lineage reachability, not only own-parent maxima, uses the resolver"
        );
    }

    #[test]
    fn proof_ancestry_missing_candidate_direct_parent_and_stale_index_refuse() {
        let (_, cold, target, _, evict) = cold_proof_fixture();
        let cell = ExclusiveCell::role(target);
        for case in 0..3 {
            let mut broken = cold.clone();
            match case {
                0 => {
                    broken.facts.remove(&evict);
                    broken.indexed_fact_count = broken.facts.len();
                }
                1 => {
                    let parent = broken.get(&evict).unwrap().content.parents[0];
                    broken.facts.remove(&parent);
                    broken.indexed_fact_count = broken.facts.len();
                }
                _ => {
                    broken.indexed_revision = broken.indexed_revision.wrapping_add(1);
                }
            }
            let mut calls = 0;
            let result = broken.proof_cell_heads_with_history(std::slice::from_ref(&cell), |_| {
                calls += 1;
                Ok::<_, &'static str>(Vec::new())
            });
            assert!(matches!(result, Err(ProofAncestryError::Invalid(_))));
            assert_eq!(calls, 0, "reject before any partial frontier or lookup");
        }
    }

    #[test]
    fn proof_ancestry_invalid_supplemental_rows_and_read_limits_propagate() {
        let (warm, cold, target, roles, _) = cold_proof_fixture();
        let cell = ExclusiveCell::role(target);
        for case in 0..7 {
            let result = cold.proof_cell_heads_with_history(std::slice::from_ref(&cell), |root| {
                let mut rows = warm.facts.values().cloned().collect::<Vec<_>>();
                match case {
                    0 => rows.retain(|fact| fact.id != root),
                    1 => rows.retain(|fact| fact.id != roles[1]),
                    2 => {
                        rows[0].signature.push('x');
                    }
                    3 => {
                        rows[0].content.mesh_context = MeshContextId::from_bytes([7; 32]);
                    }
                    4 => rows.push(rows[0].clone()),
                    5 => return Err("proof history limit refusal"),
                    _ => return Err("proof history read refusal"),
                }
                Ok(rows)
            });
            if case >= 5 {
                let expected = if case == 5 {
                    "proof history limit refusal"
                } else {
                    "proof history read refusal"
                };
                assert!(
                    matches!(result, Err(ProofAncestryError::Read(error)) if error == expected)
                );
            } else {
                assert!(
                    matches!(result, Err(ProofAncestryError::Invalid(_))),
                    "case {case}: {result:?}"
                );
            }
        }
        // Corrupt the live overlap only: the durable row still has a valid
        // signature, so this specifically discriminates the exact-body gate.
        for change_signature in [true, false] {
            let mut changed = cold.clone();
            let hot = changed.facts.get_mut(&roles[3]).unwrap();
            if change_signature {
                hot.signature.push('x');
            } else if let FactBody::RoleGrant { role, .. } = &mut hot.content.body {
                *role = Role::Owner;
            } else {
                panic!("C4 is a role grant");
            }
            let result = changed.proof_cell_heads_with_history(std::slice::from_ref(&cell), |_| {
                Ok::<_, &'static str>(warm.facts.values().cloned().collect())
            });
            assert!(matches!(
                result,
                Err(ProofAncestryError::Invalid(
                    "ancestry differs from hot body"
                ))
            ));
        }
    }

    #[test]
    fn proof_ancestry_quarantined_intermediate_is_not_admitted_history() {
        let (warm, mut cold, target, roles, _) = cold_proof_fixture();
        let intermediate = warm.get(&roles[1]).unwrap().clone();
        cold.quarantined.insert(intermediate.id, intermediate);
        let result =
            cold.proof_cell_heads_with_history(&[ExclusiveCell::membership(target)], |_| {
                // Model the existing admitted-only SQL reader: provisional custody
                // cannot supply the missing admitted row.
                Ok::<_, &'static str>(
                    warm.facts
                        .values()
                        .filter(|fact| fact.id != roles[1])
                        .cloned()
                        .collect(),
                )
            });
        assert!(matches!(
            result,
            Err(ProofAncestryError::Invalid(
                "incomplete signed-parent ancestry"
            ))
        ));
    }

    #[test]
    fn root_owner_fallback_stops_after_root_cell_advances() {
        let (bootstrap, root_key) = closed(41);
        let root = device(&root_key);
        let revoke = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: root.clone(),
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        assert_eq!(graph.evaluator().effective_role(&root), Some(Role::Owner));
        graph
            .admit(revoke)
            .expect("the root may revoke its own role cell");
        let evaluator = graph.evaluator();
        assert_eq!(evaluator.effective_role(&root), None);
        assert!(!evaluator.admits_closed_session(&root, &root));
    }

    #[test]
    fn authoring_witness_carries_root_revoke_into_later_root_authored_fact() {
        let (bootstrap, root_key) = closed(48);
        let root = device(&root_key);
        let revoke = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: root.clone(),
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(revoke.clone())
            .expect("the root revoke is admitted into the canonical graph");

        let body = FactBody::RoleGrant {
            target: device(&key(49)),
            role: Role::Member,
        };
        let witness = graph.authoring_witness(&body, &root);
        assert!(
            witness.parents().contains(&revoke.id),
            "tiered root-authored work must carry the signed AuthorityUse predecessor"
        );
        let candidate = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                body,
                &witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("witness-derived candidate signs");
        assert_eq!(
            graph.admit(candidate),
            Err(SemanticError::UnauthorizedRoleGrant),
            "the revoked root must not regain bootstrap-owner fallback"
        );
    }

    #[test]
    fn projection_follows_nested_same_cell_resolutions() {
        let (bootstrap, root_key) = closed(40);
        let target = device(&key(41));
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let third = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Owner,
            },
            Vec::new(),
        );
        let first_resolution = fact(
            &bootstrap,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: vec![first.id, second.id],
                selected_head: first.id,
            },
            vec![first.id, second.id],
        );
        let second_resolution = fact(
            &bootstrap,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: vec![first_resolution.id, third.id],
                selected_head: first_resolution.id,
            },
            vec![first_resolution.id, third.id],
        );
        let terminal_resolution = second_resolution.id;
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.facts.insert(first.id, first.clone());
        graph.facts.insert(second.id, second);
        graph.facts.insert(third.id, third);
        graph.facts.insert(first_resolution.id, first_resolution);
        graph.facts.insert(second_resolution.id, second_resolution);
        let evaluator = graph.evaluator();
        assert_eq!(
            evaluator.effective_role(&target),
            Some(Role::Member),
            "nested resolution selects the terminal same-cell head"
        );
        drop(evaluator);
        assert_eq!(graph.projection(), Projection::from_graph(&graph));
        graph.rebuild_indexes();
        assert_warm_proof_head_parity(&graph);
        let roots = graph
            .proof_cell_heads_with_history(&[ExclusiveCell::role(target)], |_| {
                Err::<Vec<SignedFact>, _>("unexpected warm history read")
            })
            .unwrap();
        assert_eq!(
            roots,
            vec![terminal_resolution],
            "retain typed outer Resolution, not selected leaf"
        );
        let mut pending = roots;
        let mut closure = BTreeSet::new();
        while let Some(id) = pending.pop() {
            if closure.insert(id) {
                pending.extend(dependencies(graph.get(&id).unwrap()));
            }
        }
        assert_eq!(
            closure,
            graph.facts.keys().copied().collect(),
            "both nested cited branches remain in the closure"
        );
    }

    #[test]
    fn shared_nested_controller_resolution_dag_is_path_local_and_accepted() {
        let (bootstrap, root_key) = closed(67);
        let controller_key = key(68);
        let controller = device(&controller_key);
        let left_key = key(70);
        let right_key = key(71);
        let left = device(&left_key);
        let right = device(&right_key);
        let target = device(&key(69));
        let controller_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let left_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: left.clone(),
                role: Role::Controller,
            },
            vec![controller_grant.id],
        );
        let right_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: right.clone(),
                role: Role::Controller,
            },
            vec![left_grant.id],
        );
        let base_a = fact(
            &bootstrap,
            &left_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![left_grant.id],
        );
        let base_b = fact(
            &bootstrap,
            &right_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![right_grant.id],
        );
        let mut base_heads = vec![base_a.id, base_b.id];
        base_heads.sort();
        let nested_a = fact(
            &bootstrap,
            &left_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: base_heads.clone(),
                selected_head: base_a.id,
            },
            [vec![left_grant.id], base_heads.clone()].concat(),
        );
        let nested_b = fact(
            &bootstrap,
            &right_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: base_heads,
                selected_head: base_b.id,
            },
            [vec![right_grant.id], vec![base_a.id, base_b.id]].concat(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        for fact in [
            controller_grant.clone(),
            left_grant,
            right_grant,
            base_a,
            base_b,
            nested_a.clone(),
            nested_b.clone(),
        ] {
            graph.facts.insert(fact.id, fact);
        }
        let mut nested_heads = vec![nested_a.id, nested_b.id];
        nested_heads.sort();
        let top = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: nested_heads.clone(),
                selected_head: nested_a.id,
            },
            vec![controller_grant.id, nested_a.id, nested_b.id],
            &[
                (controller.clone(), vec![controller_grant.id]),
                (target.clone(), nested_heads.clone()),
            ],
        );
        graph
            .admit(top)
            .expect("Controller may resolve shared nested Controller-tier branches");
        assert_eq!(
            graph.evaluator().effective_role(&target),
            Some(Role::Member),
            "the selected nested branch remains the effective proposition"
        );
    }

    #[test]
    fn conflicted_root_role_cell_fails_closed() {
        let (bootstrap, root_key) = closed(47);
        let root = device(&root_key);
        let member = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: root.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: root.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        member.verify().expect("first root branch verifies");
        controller.verify().expect("second root branch verifies");
        graph.facts.insert(member.id, member);
        graph.facts.insert(controller.id, controller);
        let evaluator = graph.evaluator();
        assert!(evaluator.is_conflicted(&ExclusiveCell::role(root.clone())));
        assert_eq!(evaluator.effective_role(&root), None);
        assert!(!evaluator.admits_closed_session(&root, &root));
    }

    #[test]
    fn controller_can_grant_controller_but_not_owner() {
        let (bootstrap, root_key) = closed(42);
        let controller_key = key(43);
        let controller = device(&controller_key);
        let target_key = key(44);
        let target = device(&target_key);
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller.clone())
            .expect("the root grants the controller tier");
        let controller_grant = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![grant_controller.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (target.clone(), vec![]),
            ],
        );
        graph
            .admit(controller_grant.clone())
            .expect("a controller may grant another controller");
        assert_eq!(
            graph.evaluator().effective_role(&target),
            Some(Role::Controller)
        );
        let owner_grant = fact(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target,
                role: Role::Owner,
            },
            vec![controller_grant.id],
        );
        assert_eq!(
            graph.admit(owner_grant),
            Err(SemanticError::UnauthorizedRoleGrant)
        );
    }

    #[test]
    fn authorization_uses_candidate_causal_past_not_later_target_role() {
        let (bootstrap, root_key) = closed(51);
        let root = device(&root_key);
        let controller_key = key(52);
        let controller = device(&controller_key);
        let target_key = key(53);
        let target = device(&target_key);
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let grant_member = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
            &[
                (root.clone(), vec![grant_controller.id]),
                (target.clone(), vec![]),
            ],
        );
        let later_owner = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Owner,
            },
            vec![grant_member.id],
        );
        let revoke = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleRevoke {
                target: target.clone(),
            },
            vec![grant_controller.id, grant_member.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (target.clone(), vec![grant_member.id]),
            ],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller)
            .expect("root controller grant admits");
        graph
            .admit(grant_member.clone())
            .expect("root member grant admits");
        graph.admit(later_owner).expect("later owner grant admits");
        graph
            .admit(revoke)
            .expect("controller is authorized by the candidate's causal target role");
    }

    #[test]
    fn resolution_authority_uses_selected_controller_proposition() {
        let (bootstrap, root_key) = closed(54);
        let controller_key = key(55);
        let controller = device(&controller_key);
        let left_key = key(57);
        let right_key = key(58);
        let left = device(&left_key);
        let right = device(&right_key);
        let target = device(&key(56));
        let controller_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let left_grant = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: left,
                role: Role::Controller,
            },
            vec![controller_grant.id],
            &[
                (device(&root_key), vec![controller_grant.id]),
                (device(&left_key), vec![]),
            ],
        );
        let right_grant = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: right,
                role: Role::Controller,
            },
            vec![left_grant.id],
            &[
                (device(&root_key), vec![left_grant.id]),
                (device(&right_key), vec![]),
            ],
        );
        let membership_admit = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::MembershipAdmit {
                target: target.clone(),
            },
            vec![right_grant.id],
            &[
                (device(&root_key), vec![right_grant.id]),
                (target.clone(), vec![]),
            ],
        );
        let member_head = fact_with_authority_predecessors(
            &bootstrap,
            &left_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![left_grant.id, membership_admit.id],
            &[
                (device(&left_key), vec![left_grant.id]),
                (target.clone(), vec![membership_admit.id]),
            ],
        );
        let controller_head = fact_with_authority_predecessors(
            &bootstrap,
            &right_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![right_grant.id, membership_admit.id],
            &[
                (device(&right_key), vec![right_grant.id]),
                (target.clone(), vec![membership_admit.id]),
            ],
        );
        let resolution = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(target.clone()),
                cited_heads: vec![member_head.id, controller_head.id],
                selected_head: controller_head.id,
            },
            vec![controller_grant.id, member_head.id, controller_head.id],
            &[
                (controller.clone(), vec![controller_grant.id]),
                (target.clone(), vec![member_head.id, controller_head.id]),
            ],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(controller_grant)
            .expect("root controller grant admits");
        graph
            .admit(left_grant)
            .expect("left branch signer grant admits");
        graph
            .admit(right_grant)
            .expect("right branch signer grant admits");
        graph
            .admit(membership_admit)
            .expect("root admits membership before the authority fork");
        graph.admit(member_head).expect("first target head admits");
        graph
            .admit(controller_head)
            .expect("second target head admits");
        let mut retirement_graph = FactGraph::from_bootstrap(&bootstrap);
        retirement_graph.policy_limits.max_hot_history_facts = 1;
        let retirement_target = device(&key(76));
        let retired_fact = witnessed_fact(
            &retirement_graph,
            &root_key,
            FactBody::RoleGrant {
                target: retirement_target.clone(),
                role: Role::Member,
            },
        );
        retirement_graph
            .admit(retired_fact.clone())
            .expect("retirement seed admits");
        let retained_fact = witnessed_fact(
            &retirement_graph,
            &root_key,
            FactBody::RoleGrant {
                target: retirement_target.clone(),
                role: Role::Controller,
            },
        );
        retirement_graph
            .admit(retained_fact)
            .expect("retirement successor admits");
        let terminal_fact = witnessed_fact(
            &retirement_graph,
            &root_key,
            FactBody::RoleGrant {
                target: retirement_target,
                role: Role::Member,
            },
        );
        retirement_graph
            .admit(terminal_fact)
            .expect("retirement terminal successor admits");
        retirement_graph.cold_history_since_retirement = 1;
        retirement_graph.retire_cold_history();
        assert!(
            retirement_graph.get(&retired_fact.id).is_none(),
            "the signed fixture row was admitted and then retired"
        );
        // Keep the signed resolution transcript fixed while growing only
        // unrelated hot facts. The impact set must remain branch-local even
        // though the current authority implementation still derives each
        // indexed subject edge on demand; these counters expose that work
        // for later tuning without treating today's O(history) scan as a
        // performance gate.
        let baseline = graph.clone();
        let mut expanded = graph.clone();
        for seed in 180..196 {
            let unrelated = witnessed_fact(
                &expanded,
                &root_key,
                FactBody::RoleGrant {
                    target: device(&key(seed)),
                    role: Role::Member,
                },
            );
            expanded
                .admit(unrelated)
                .expect("unrelated signed grant admits");
        }
        reset_graph_work();
        let baseline_impact = baseline.projection_impact_for_fact(&resolution);
        let baseline_work = graph_work();
        reset_graph_work();
        let expanded_impact = expanded.projection_impact_for_fact(&resolution);
        let expanded_work = graph_work();
        assert_eq!(baseline_impact, expanded_impact);
        assert_eq!(
            baseline.authority_facts_index.get(&target),
            expanded.authority_facts_index.get(&target),
            "unrelated subjects do not enter the selected-subject index"
        );
        assert!(baseline_work.authority_fact_rows > 0);
        assert!(baseline_work.authority_uses_examined > 0);
        assert!(baseline_work.authority_edges_followed > 0);
        assert!(baseline_work.authority_branch_nodes > 0);
        assert_eq!(
            expanded_work.authority_fact_rows,
            baseline_work.authority_fact_rows
        );
        assert_eq!(
            expanded_work.authority_uses_examined,
            baseline_work.authority_uses_examined
        );
        assert_eq!(
            expanded_work.authority_edges_followed,
            baseline_work.authority_edges_followed
        );
        assert_eq!(
            expanded_work.authority_branch_nodes, baseline_work.authority_branch_nodes,
            "unrelated facts do not expand the selected authority branch"
        );

        // A verified, previously admitted-and-retired row is deliberately
        // absent from the live subject index. Keep the synthetic dependent
        // row as a branch discriminator, while the retired row proves that
        // the overlay accepts the same signed history representation that a
        // loader supplies. Neither row becomes live index residency.
        assert!(
            retirement_graph.get(&retired_fact.id).is_none(),
            "the overlay input remains absent from the hot graph"
        );
        let cited_head = match &resolution.content.body {
            FactBody::Resolution { cited_heads, .. } => cited_heads[0],
            _ => unreachable!("resolution fixture has a resolution body"),
        };
        let staged_fact = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
            vec![cited_head],
            &[
                (device(&root_key), vec![cited_head]),
                (target.clone(), vec![cited_head]),
            ],
        );
        let mut complete = graph.clone();
        complete
            .stage_cold_history(vec![retired_fact.clone(), staged_fact.clone()])
            .expect("signed cold row stages");
        assert!(!complete
            .authority_facts_index
            .get(&target)
            .is_some_and(|ids| ids.contains(&staged_fact.id)));
        complete.rebuild_authority_facts_index();
        assert!(complete
            .authority_facts_index
            .get(&target)
            .is_some_and(|ids| ids.contains(&staged_fact.id)));
        let complete_impact = complete.projection_impact_for_fact(&resolution);
        let cold_before = graph.clone();
        let cold_before_residency = graph
            .logical_index_residency_bytes()
            .expect("cold baseline index residency computes");
        let mut complete_reference = graph.clone();
        complete_reference
            .stage_cold_history(vec![retired_fact.clone(), staged_fact.clone()])
            .expect("the identical signed cold rows stage in the complete reference");
        complete_reference.rebuild_authority_facts_index();
        complete_reference
            .admit(resolution.clone())
            .expect("complete reference admits the same resolution");
        let cold_journal = graph
            .admit_journaled_with_history(
                resolution.clone(),
                vec![retired_fact.clone(), staged_fact],
            )
            .expect("resolution admits with verified cold history");
        assert_eq!(
            cold_journal.graph().projection(),
            complete_reference.projection(),
            "staged overlay mutation matches the complete projection"
        );
        assert_eq!(
            cold_journal.graph().projection_commitment_root(),
            complete_reference.projection_commitment_root(),
            "staged overlay mutation matches the complete commitment root"
        );
        let expected_cold_delta = complete_reference.projection().delta_from(
            &cold_before.projection(),
            cold_before.generation,
            complete_reference.generation,
            cold_journal.delta().affected_cells(),
            cold_journal.delta().affected_subjects(),
        );
        assert_eq!(
            cold_journal.delta().projection_delta(),
            Some(&expected_cold_delta),
            "staged overlay delta matches the complete reference"
        );
        assert_eq!(
            cold_journal.delta().affected_cells,
            complete_impact.0,
            "staged cold authority branch matches complete index impact"
        );
        assert_eq!(
            cold_journal.delta().affected_subjects,
            complete_impact.1,
            "staged cold authority subjects match complete index impact"
        );
        assert!(
            cold_journal
                .delta()
                .affected_cells
                .contains(&ExclusiveCell::membership(target.clone())),
            "cold dependent contributes its distinct membership cell"
        );
        cold_journal.rollback();
        assert_graph_state_eq(&graph, &cold_before);
        assert_eq!(
            graph
                .logical_index_residency_bytes()
                .expect("rolled-back cold index residency computes"),
            cold_before_residency,
            "cold overlay leaves live index charge unchanged"
        );
        let before_resolution = graph_snapshot(&graph);
        let preflight = graph
            .preflight_admission(&resolution)
            .expect("fixed signed resolution preflights");
        let journal = graph
            .apply_preflight_journaled(resolution.clone(), preflight)
            .expect("fixed signed resolution journals");
        assert_eq!(
            journal.graph().projection(),
            Projection::from_graph(journal.graph())
        );
        journal.rollback();
        assert_graph_state_eq(&graph, &before_resolution);
        graph
            .admit(resolution)
            .expect("a controller may resolve to a controller proposition");
        assert_eq!(graph.projection(), Projection::from_graph(&graph));
        graph.cold_history_since_retirement =
            usize::try_from(graph.policy_limits.max_hot_history_facts).unwrap_or(usize::MAX);
        graph.retire_cold_history();
        let retired = graph.clone();
        graph.rebuild_indexes();
        assert_eq!(graph.authority_facts_index, retired.authority_facts_index);
        assert_eq!(graph.projection(), Projection::from_graph(&graph));
        assert_graph_state_eq(&graph, &retired);
    }

    #[test]
    fn authority_lineage_selection_survives_cross_cell_forks_and_rejects_losers() {
        let (bootstrap, root_key) = closed(72);
        let controller_key = key(73);
        let controller = device(&controller_key);
        let target_key = key(74);
        let target = device(&target_key);
        let other_key = key(75);
        let other = device(&other_key);
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let grant_other = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: other.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (other.clone(), Vec::new()),
            ],
        );
        let revoke_controller = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
            vec![grant_controller.id],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let mut branches = vec![grant_other.clone(), revoke_controller.clone()];
        branches.sort_by_key(|fact| fact.id);
        let branch_ids = [grant_other.id, revoke_controller.id];

        for selected in branch_ids {
            for reverse in [false, true] {
                let mut graph = FactGraph::from_bootstrap(&bootstrap);
                graph
                    .admit(grant_controller.clone())
                    .expect("controller grant admits");
                let branch_cost = graph
                    .fact_cost(&grant_other)
                    .expect("branch residency cost computes");
                assert_eq!(
                    branch_cost._authority_dependents_index_bytes,
                    graph
                        .authority_dependents_residency_delta(&grant_other)
                        .expect("branch reverse-index delta computes"),
                    "cost and retained residency agree"
                );
                assert_eq!(
                    branch_cost._authority_dependents_index_bytes, 0,
                    "the production graph derives rare subject-local reverse edges on demand"
                );
                let order = if reverse {
                    branches.iter().rev().cloned().collect::<Vec<_>>()
                } else {
                    branches.clone()
                };
                for branch in order {
                    graph.admit(branch).expect("cross-cell branch admits");
                }
                let reverse_dependents = graph
                    .authority_dependents_index
                    .get(&(controller.clone(), grant_controller.id))
                    .expect("declared authority predecessor has a reverse index entry");
                assert!(
                    reverse_dependents.contains(&grant_other.id)
                        && reverse_dependents.contains(&revoke_controller.id),
                    "both authority branches retain exact reverse dependents"
                );
                let mut cited = branch_ids.to_vec();
                cited.sort();
                let resolution = fact_with_authority_predecessors(
                    &bootstrap,
                    &root_key,
                    FactBody::AuthorityLineageResolution {
                        subject: controller.clone(),
                        cited_heads: cited.clone(),
                        selected_head: selected,
                    },
                    [vec![grant_controller.id], cited.clone()].concat(),
                    &[
                        (device(&root_key), vec![revoke_controller.id]),
                        (controller.clone(), cited.clone()),
                    ],
                );
                let resolution_id = resolution.id;
                let resolution_impact = graph.projection_impact_for_fact(&resolution);
                assert!(
                    resolution_impact
                        .0
                        .contains(&ExclusiveCell::role(other.clone())),
                    "selected branch cell is included in sparse authority impact"
                );
                assert!(
                    resolution_impact
                        .0
                        .contains(&ExclusiveCell::role(controller.clone())),
                    "losing branch cell is included in sparse authority impact"
                );
                let before_resolution = graph.clone();
                let before_resolution_residency = graph
                    .authority_dependents_residency_bytes()
                    .expect("authority reverse-index residency computes");
                let preflight = graph
                    .preflight_admission(&resolution)
                    .expect("cross-cell authority resolution preflights");
                let journal = graph
                    .apply_preflight_journaled(resolution.clone(), preflight)
                    .expect("cross-cell authority resolution applies");
                let journal_graph = journal.graph();
                assert_eq!(
                    journal_graph.projection(),
                    Projection::from_graph(journal_graph),
                    "each branch selection matches the full projection"
                );
                journal.rollback();
                assert_eq!(graph.projection(), before_resolution.projection());
                assert_eq!(
                    graph.authority_dependents_index, before_resolution.authority_dependents_index,
                    "authority branch rollback restores reverse-index ownership"
                );
                assert_eq!(
                    graph
                        .authority_dependents_residency_bytes()
                        .expect("rolled-back authority residency computes"),
                    before_resolution_residency,
                    "authority branch rollback restores the exact logical charge"
                );
                graph
                    .admit(resolution)
                    .expect("typed resolution selects either cross-cell branch");
                let lineage = graph.authority_lineage(&controller);
                assert_eq!(lineage.effective_head(), Some(resolution_id));
                assert_eq!(lineage.selected_branch(), Some(selected));
                assert_eq!(
                    graph.projection(),
                    Projection::from_graph(&graph),
                    "fork/resolution sparse impact matches the full reference"
                );
                let loser = branch_ids
                    .into_iter()
                    .find(|id| *id != selected)
                    .expect("two branch ids");
                assert!(
                    graph.fact_is_authoritative(&grant_controller.id),
                    "the common causal ancestor remains authoritative after selection"
                );
                assert!(!graph.fact_is_authoritative(&loser));

                let later = fact(
                    &bootstrap,
                    &root_key,
                    FactBody::RoleRevoke {
                        target: controller.clone(),
                    },
                    vec![resolution_id],
                );
                assert_eq!(
                    graph.admit(later),
                    Err(SemanticError::NoOp("role revoke targets an absent role"))
                );

                let loser_only = fact(
                    &bootstrap,
                    &controller_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                    vec![loser],
                );
                assert_eq!(
                    graph.admit(loser_only),
                    Err(SemanticError::UnauthorizedRoleGrant),
                    "a losing branch cannot revive authority after selection"
                );

                let both_branches = fact_with_authority_predecessors(
                    &bootstrap,
                    &controller_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                    branch_ids.to_vec(),
                    &[
                        (controller.clone(), branch_ids.to_vec()),
                        (target.clone(), Vec::new()),
                    ],
                );
                assert_eq!(
                    graph.admit(both_branches),
                    Err(SemanticError::UnauthorizedRoleGrant),
                    "an ordinary fact cannot merge incomparable AuthorityUse heads"
                );
            }
        }
    }

    #[test]
    fn ordinary_role_resolution_cannot_join_cross_cell_authority_heads() {
        let (bootstrap, root_key) = closed(89);
        let controller_key = key(90);
        let target_key = key(91);
        let controller = device(&controller_key);
        let target = device(&target_key);
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let outside_role = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (target.clone(), Vec::new()),
            ],
        );
        let role_revoke = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
            vec![grant_controller.id],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let role_grant = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
            vec![grant_controller.id],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let mut role_heads = vec![role_revoke.id, role_grant.id];
        role_heads.sort();
        let ordinary = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::Resolution {
                cell: ExclusiveCell::role(controller.clone()),
                cited_heads: role_heads.clone(),
                selected_head: role_revoke.id,
            },
            vec![
                grant_controller.id,
                outside_role.id,
                role_revoke.id,
                role_grant.id,
            ],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (
                    controller.clone(),
                    [vec![outside_role.id], role_heads.clone()].concat(),
                ),
            ],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller)
            .expect("Controller grant admits");
        graph.facts.insert(outside_role.id, outside_role.clone());
        graph.facts.insert(role_revoke.id, role_revoke);
        graph.facts.insert(role_grant.id, role_grant);
        assert_eq!(
            graph.admit(ordinary),
            Err(SemanticError::UnauthorizedRoleGrant),
            "ordinary Role resolution cannot join an outside-cell AuthorityUse"
        );
        let mut expected_heads = vec![outside_role.id, role_heads[0], role_heads[1]];
        expected_heads.sort();
        assert_eq!(
            graph.authority_lineage(&controller).heads(),
            expected_heads.as_slice()
        );
        assert!(!graph.fact_is_authoritative(&outside_role.id));
        assert_eq!(
            graph.evaluator().effective_role(&target),
            None,
            "the outside-cell RoleGrant cannot project through the fork"
        );
    }

    #[test]
    fn payload_resolution_does_not_join_a_transitive_role_fork() {
        let (bootstrap, root_key) = closed(80);
        let controller_key = key(81);
        let owner_a_key = key(82);
        let owner_d_key = key(83);
        let target_key = key(84);
        let controller = device(&controller_key);
        let owner_a = device(&owner_a_key);
        let owner_d = device(&owner_d_key);
        let target = device(&target_key);

        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let grant_a = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: owner_a.clone(),
                role: Role::Owner,
            },
            vec![grant_controller.id],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (owner_a.clone(), Vec::new()),
            ],
        );
        let grant_d = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: owner_d.clone(),
                role: Role::Owner,
            },
            vec![grant_a.id],
            &[
                (device(&root_key), vec![grant_a.id]),
                (owner_d.clone(), Vec::new()),
            ],
        );
        let role_branch = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (target.clone(), Vec::new()),
            ],
        );
        let revoke_branch = fact_with_authority_predecessors(
            &bootstrap,
            &owner_a_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
            vec![grant_a.id, grant_controller.id],
            &[
                (owner_a.clone(), vec![grant_a.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let membership_branch = fact_with_authority_predecessors(
            &bootstrap,
            &owner_d_key,
            FactBody::MembershipAdmit {
                target: controller.clone(),
            },
            vec![grant_d.id, grant_controller.id],
            &[
                (owner_d.clone(), vec![grant_d.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let evict_branch = fact_with_authority_predecessors(
            &bootstrap,
            &owner_d_key,
            FactBody::Evict {
                target: controller.clone(),
            },
            vec![grant_d.id, grant_controller.id],
            &[
                (owner_d.clone(), vec![grant_d.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let mut cited_heads = vec![membership_branch.id, evict_branch.id];
        cited_heads.sort();
        let resolution = fact_with_authority_predecessors(
            &bootstrap,
            &owner_a_key,
            FactBody::Resolution {
                cell: ExclusiveCell::membership(controller.clone()),
                cited_heads: cited_heads.clone(),
                selected_head: evict_branch.id,
            },
            vec![
                role_branch.id,
                revoke_branch.id,
                membership_branch.id,
                evict_branch.id,
            ],
            &[
                (owner_a.clone(), vec![revoke_branch.id]),
                (
                    controller.clone(),
                    vec![
                        role_branch.id,
                        revoke_branch.id,
                        membership_branch.id,
                        evict_branch.id,
                    ],
                ),
            ],
        );
        for branch in [
            &grant_controller,
            &grant_a,
            &grant_d,
            &role_branch,
            &revoke_branch,
            &membership_branch,
            &evict_branch,
            &resolution,
        ] {
            branch.verify().expect("fixture remains canonically signed");
        }

        let mut base = FactGraph::from_bootstrap(&bootstrap);
        base.admit(grant_controller)
            .expect("controller grant admits");
        base.admit(grant_a).expect("first Owner grant admits");
        base.admit(grant_d).expect("second Owner grant admits");
        let role_branch_id = role_branch.id;
        let branches = [role_branch, revoke_branch, membership_branch, evict_branch];
        let mut expected_heads = cited_heads.clone();
        expected_heads.extend([branches[0].id, branches[1].id]);
        expected_heads.sort();
        for order in [[0usize, 1, 2, 3], [3, 2, 1, 0], [2, 0, 3, 1]] {
            let mut graph = base.clone();
            for index in order {
                let branch = &branches[index];
                graph.facts.insert(branch.id, branch.clone());
            }
            graph
                .admit(resolution.clone())
                .expect("payload resolution admits against exact payload heads");
            let lineage = graph.authority_lineage(&controller);
            assert_eq!(lineage.heads(), expected_heads.as_slice());
            assert_eq!(
                lineage.selected_branch(),
                None,
                "a payload resolution cannot select the Role lineage"
            );
            assert!(graph.fact_is_authoritative(&resolution.id));
            assert!(
                !graph.fact_is_authoritative(&role_branch_id),
                "the losing Role branch remains inactive"
            );
            assert_eq!(graph.evaluator().effective_role(&target), None);
            assert_eq!(
                graph.evaluator().effective_membership(&controller),
                Some(false)
            );
        }
    }

    #[test]
    fn selector_provenance_continuations_cold_restore_and_rollback() {
        let (bootstrap, root_key) = closed(171);
        let controller_key = key(172);
        let controller = device(&controller_key);
        let old_target = device(&key(173));
        let first_target = device(&key(174));
        let second_target = device(&key(175));
        let mut seed = FactGraph::from_bootstrap(&bootstrap);
        let grant = witnessed_fact(
            &seed,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
        );
        assert_eq!(seed.admit(grant.clone()).unwrap(), Admission::Inserted);
        let operation = witnessed_fact(
            &seed,
            &controller_key,
            FactBody::RoleGrant {
                target: old_target.clone(),
                role: Role::Member,
            },
        );
        let revoke = witnessed_fact(
            &seed,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
        );
        let mut expected_transcript: Option<Vec<FactId>> = None;
        for order in [
            [operation.clone(), revoke.clone()],
            [revoke.clone(), operation.clone()],
        ] {
            let mut graph = seed.clone();
            for fact in order {
                assert_eq!(graph.admit(fact).unwrap(), Admission::Inserted);
            }
            let mut cited = vec![operation.id, revoke.id];
            cited.sort();
            let selector = witnessed_fact(
                &graph,
                &root_key,
                FactBody::AuthorityLineageResolution {
                    subject: controller.clone(),
                    cited_heads: cited,
                    selected_head: revoke.id,
                },
            );
            let competing_selector = witnessed_fact(
                &graph,
                &root_key,
                FactBody::AuthorityLineageResolution {
                    subject: controller.clone(),
                    cited_heads: vec![operation.id, revoke.id]
                        .into_iter()
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect(),
                    selected_head: operation.id,
                },
            );
            assert_eq!(graph.admit(selector.clone()).unwrap(), Admission::Inserted);
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
            assert!(!graph.fact_is_authoritative(&operation.id));
            assert_warm_proof_head_parity(&graph);
            {
                let mut competing = graph.clone();
                assert_eq!(
                    competing.admit(competing_selector).unwrap(),
                    Admission::Inserted
                );
                assert_eq!(
                    competing.authority_lineage(&controller).selected_branch(),
                    None
                );
                assert!(competing.authority_lineage(&controller).is_conflicted());
                assert_eq!(
                    competing
                        .maximal_typed_selectors(
                            &controller,
                            competing.authority_lineage(&controller).heads()
                        )
                        .len(),
                    2
                );
                assert!(!competing.fact_is_authoritative(&operation.id));
                assert_eq!(competing.projection(), Projection::from_graph(&competing));
                assert_warm_proof_head_parity(&competing);
            }
            let regrant = witnessed_fact(
                &graph,
                &root_key,
                FactBody::RoleGrant {
                    target: controller.clone(),
                    role: Role::Owner,
                },
            );
            assert_eq!(graph.admit(regrant).unwrap(), Admission::Inserted);
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
            let first = witnessed_fact(
                &graph,
                &controller_key,
                FactBody::RoleGrant {
                    target: first_target.clone(),
                    role: Role::Member,
                },
            );
            assert_eq!(graph.admit(first).unwrap(), Admission::Inserted);
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
            let second = witnessed_fact(
                &graph,
                &controller_key,
                FactBody::RoleGrant {
                    target: second_target.clone(),
                    role: Role::Member,
                },
            );
            let second_id = second.id;
            assert_eq!(graph.admit(second).unwrap(), Admission::Inserted);
            for index in 0..8 {
                assert_eq!(
                    graph.authority_lineage(&controller).selected_branch(),
                    Some(revoke.id)
                );
                assert!(!graph.fact_is_authoritative(&operation.id));
                assert_eq!(graph.evaluator().effective_role(&old_target), None);
                let full = Projection::from_graph(&graph);
                assert_eq!(graph.projection(), full);
                assert_eq!(graph.projection_commitment_root(), full.commitment_root());
                let fact = witnessed_fact(
                    &graph,
                    &controller_key,
                    FactBody::RoleGrant {
                        target: second_target.clone(),
                        role: if index % 2 == 0 {
                            Role::Controller
                        } else {
                            Role::Member
                        },
                    },
                );
                assert_eq!(graph.admit(fact).unwrap(), Admission::Inserted);
            }
            let canonical_history = graph.facts.values().cloned().collect::<Vec<_>>();
            let transcript = canonical_history
                .iter()
                .map(|fact| fact.id)
                .collect::<Vec<_>>();
            if let Some(expected) = &expected_transcript {
                assert_eq!(&transcript, expected);
            } else {
                expected_transcript = Some(transcript);
            }
            graph.cold_history_since_retirement =
                graph.policy_limits.max_hot_history_facts as usize;
            graph.retire_cold_history();
            assert!(
                !graph.facts.contains_key(&second_id),
                "actual intermediate body retired"
            );
            assert!(
                graph.facts.contains_key(&selector.id),
                "actual signed selector retained"
            );
            assert!(
                graph.facts.contains_key(&revoke.id),
                "actual selected branch witness retained"
            );
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
            assert_eq!(
                graph.logical_index_residency_bytes().unwrap(),
                graph.derived_index_bytes
            );
            let checkpoint = graph.live_checkpoint();
            let restored = FactGraph::from_live_checkpoint_with_history(
                &bootstrap,
                crate::config::SemanticPolicyConfig::default(),
                checkpoint.clone(),
                |_| Ok(canonical_history.clone()),
            )
            .expect("pristine cold provenance validated without admission replay");
            assert_eq!(
                restored.authority_lineage(&controller).selected_branch(),
                Some(revoke.id)
            );
            assert_eq!(restored.projection(), Projection::from_graph(&restored));
            assert!(
                restored
                    .proof_cell_heads_with_history(
                        &[ExclusiveCell::role(old_target.clone())],
                        |_| Ok::<_, &'static str>(canonical_history.clone()),
                    )
                    .unwrap()
                    .is_empty(),
                "complete historical rows never revive the selector's excluded operation"
            );
            let mut omitted = checkpoint.clone();
            let omitted_bytes = graph
                .authority_provenance
                .values()
                .map(|row| graph.provenance_row_bytes(row).unwrap())
                .sum::<u64>();
            omitted.authority_provenance.clear();
            omitted.derived_index_bytes = omitted
                .derived_index_bytes
                .checked_sub(omitted_bytes)
                .unwrap();
            assert!(
                FactGraph::from_live_checkpoint_with_history(
                    &bootstrap,
                    crate::config::SemanticPolicyConfig::default(),
                    omitted,
                    |_| Ok(canonical_history.clone()),
                )
                .is_err(),
                "omitted required provenance is not selector-free"
            );
            let mut false_post = checkpoint.clone();
            let false_relation = AuthoritySelectorRelation {
                selected: revoke.id,
                post_selector: true,
                selected_before: false,
                before_selected: false,
            };
            assert!(!graph
                .authority_provenance
                .get(&operation.id)
                .is_some_and(|row| row.contains_key(&selector.id)));
            let mut false_row = graph
                .authority_provenance
                .get(&operation.id)
                .cloned()
                .unwrap_or_default();
            let prior_bytes = if false_row.is_empty() {
                0
            } else {
                graph.provenance_row_bytes(&false_row).unwrap()
            };
            false_row.insert(selector.id, false_relation);
            false_post
                .authority_provenance
                .retain(|(id, _)| *id != operation.id);
            false_post.authority_provenance.push((
                operation.id,
                false_row
                    .iter()
                    .map(|(id, relation)| (*id, *relation))
                    .collect(),
            ));
            false_post.derived_index_bytes = false_post
                .derived_index_bytes
                .checked_sub(prior_bytes)
                .unwrap()
                .checked_add(graph.provenance_row_bytes(&false_row).unwrap())
                .unwrap();
            assert!(
                FactGraph::from_live_checkpoint_with_history(
                    &bootstrap,
                    crate::config::SemanticPolicyConfig::default(),
                    false_post,
                    |_| Ok(canonical_history.clone()),
                )
                .is_err(),
                "a losing-parent edge is not post-selector provenance even with exact accounting"
            );
            let mut substituted = checkpoint;
            for (_, row) in &mut substituted.authority_provenance {
                for (_, relation) in row {
                    if relation.selected == revoke.id {
                        relation.selected = operation.id;
                    }
                }
            }
            assert!(
                FactGraph::from_live_checkpoint_with_history(
                    &bootstrap,
                    crate::config::SemanticPolicyConfig::default(),
                    substituted,
                    |_| Ok(canonical_history.clone()),
                )
                .is_err(),
                "selected losing-row substitution refuses"
            );
            let next = witnessed_fact(
                &graph,
                &controller_key,
                FactBody::RoleGrant {
                    target: second_target.clone(),
                    role: Role::Controller,
                },
            );
            let baseline = graph_snapshot(&graph);
            {
                let journal = graph.admit_journaled(next.clone()).unwrap();
                assert_eq!(journal.admission(), &Admission::Inserted);
                assert_eq!(
                    journal.graph().projection(),
                    Projection::from_graph(journal.graph())
                );
                assert_ne!(
                    journal.graph().authority_provenance,
                    baseline.authority_provenance
                );
            }
            assert_graph_state_eq(&graph, &baseline);
            graph.admit_journaled(next.clone()).unwrap().rollback();
            assert_graph_state_eq(&graph, &baseline);
            graph.admit_journaled(next).unwrap().commit();
            assert_eq!(
                graph.authority_lineage(&controller).selected_branch(),
                Some(revoke.id)
            );
            assert!(!graph.fact_is_authoritative(&operation.id));
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
        }
    }

    #[test]
    fn self_authored_membership_keeps_a_role_authority_fork_explicit() {
        let (bootstrap, root_key) = closed(86);
        let controller_key = key(87);
        let owner_a_key = key(88);
        let controller = device(&controller_key);
        let owner_a = device(&owner_a_key);

        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let membership = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::MembershipAdmit {
                target: controller.clone(),
            },
            vec![grant_controller.id],
            &[(controller.clone(), vec![grant_controller.id])],
        );
        let evict = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::Evict {
                target: controller.clone(),
            },
            vec![grant_controller.id],
            &[(controller.clone(), vec![grant_controller.id])],
        );
        let mut role_heads = vec![membership.id, evict.id];
        role_heads.sort();
        let role_resolution = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: role_heads.clone(),
                selected_head: evict.id,
            },
            [grant_controller.id]
                .into_iter()
                .chain(role_heads.iter().copied())
                .collect(),
            &[
                (device(&root_key), vec![grant_controller.id]),
                (controller.clone(), role_heads.clone()),
            ],
        );
        let role_resolution_id = role_resolution.id;
        let regrant = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
            vec![role_resolution_id],
            &[
                (device(&root_key), vec![role_resolution_id]),
                (controller.clone(), vec![role_resolution_id]),
            ],
        );

        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(grant_controller)
            .expect("controller grant admits");
        graph.facts.insert(membership.id, membership.clone());
        graph.facts.insert(evict.id, evict.clone());
        graph
            .admit(role_resolution)
            .expect("typed Role resolution over the complete C fork admits");
        graph
            .admit(regrant.clone())
            .expect("causal Owner regrant admits");
        let grant_owner_a = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: owner_a.clone(),
                role: Role::Owner,
            },
            vec![regrant.id],
            &[
                (device(&root_key), vec![regrant.id]),
                (owner_a.clone(), Vec::new()),
            ],
        );
        graph
            .admit(grant_owner_a.clone())
            .expect("distinct Owner A grant admits");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(evict.id)
        );

        let mut membership_heads = vec![membership.id, evict.id];
        membership_heads.sort();

        let self_membership = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::Resolution {
                cell: ExclusiveCell::membership(controller.clone()),
                cited_heads: membership_heads.clone(),
                selected_head: membership.id,
            },
            vec![regrant.id, membership.id, evict.id],
            &[(controller.clone(), vec![regrant.id])],
        );
        let self_membership_id = self_membership.id;
        graph.facts.insert(self_membership.id, self_membership);
        assert!(graph.fact_is_authoritative(&self_membership_id));
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            Some(true)
        );

        let late_revoke = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
            vec![grant_owner_a.id, regrant.id],
            &[
                (device(&root_key), vec![grant_owner_a.id]),
                (controller.clone(), vec![regrant.id]),
            ],
        );
        let late_revoke_id = late_revoke.id;
        graph.facts.insert(late_revoke.id, late_revoke);
        let mut explicit_heads = vec![self_membership_id, late_revoke_id];
        explicit_heads.sort();
        let lineage = graph.authority_lineage(&controller);
        assert_eq!(lineage.heads(), explicit_heads.as_slice());
        assert!(!lineage.is_singular());
        assert!(!graph.fact_is_authoritative(&self_membership_id));
        assert!(!graph.fact_is_authoritative(&late_revoke_id));
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "the self-authored payload is suppressed by the Role fork"
        );

        let newer_resolution = fact_with_authority_predecessors(
            &bootstrap,
            &owner_a_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: explicit_heads.clone(),
                selected_head: late_revoke_id,
            },
            [vec![grant_owner_a.id], explicit_heads.clone()].concat(),
            &[
                (owner_a.clone(), vec![grant_owner_a.id]),
                (controller.clone(), explicit_heads),
            ],
        );
        let newer_resolution_id = newer_resolution.id;
        graph
            .admit(newer_resolution)
            .expect("Owner A selects the current root revoke");
        let later_regrant = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
            vec![late_revoke_id, newer_resolution_id],
            &[
                (device(&root_key), vec![late_revoke_id]),
                (controller.clone(), vec![newer_resolution_id]),
            ],
        );
        assert!(
            later_regrant.content.parents.contains(&late_revoke_id)
                && later_regrant.content.parents.contains(&newer_resolution_id),
            "U2 retains the redundant R/T2 parent set"
        );
        graph
            .admit(later_regrant)
            .expect("later Owner regrant admits on the selected branch");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(late_revoke_id)
        );
        assert!(!graph.fact_is_authoritative(&self_membership_id));
        assert_eq!(
            graph.evaluator().effective_membership(&controller),
            None,
            "later Role resolution/regrant cannot revive the losing payload"
        );

        // Continue two ordinary authority-use steps beyond the typed
        // selector. These rows are the public-shaped T->U->F1->F2 case: the
        // active frontier must carry the selected branch even when the typed
        // selector itself is no longer a direct parent.
        let continuation_revoke = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
        );
        graph
            .admit(continuation_revoke)
            .expect("first ordinary continuation admits");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(late_revoke_id)
        );
        let continuation_grant = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
        );
        let continuation_grant_id = continuation_grant.id;
        graph
            .admit(continuation_grant)
            .expect("second ordinary continuation admits");
        assert_eq!(
            graph.authority_lineage(&controller).selected_branch(),
            Some(late_revoke_id)
        );
        assert!(graph.fact_is_authoritative(&continuation_grant_id));
        assert_eq!(graph.projection(), Projection::from_graph(&graph));

        // A cache checksum is not a proof that a branch was selected. A
        // resident but losing signed row must not be substitutable for the
        // selected ID in the derived frontier summary.
        let valid_checkpoint = graph.live_checkpoint();
        FactGraph::from_live_checkpoint(
            &bootstrap,
            crate::config::SemanticPolicyConfig::default(),
            valid_checkpoint.clone(),
        )
        .expect("complete resident typed-selector ancestry validates");
        let mut forged_checkpoint = valid_checkpoint.clone();
        let (_, row) = forged_checkpoint
            .authority_provenance
            .iter_mut()
            .find(|(id, _)| *id == continuation_grant_id)
            .expect("continuation has provenance");
        let (_, relation) = row
            .iter_mut()
            .find(|(_, relation)| relation.selected == late_revoke_id)
            .expect("controller selection has a persisted provenance relation");
        relation.selected = self_membership_id;
        assert!(
            FactGraph::from_live_checkpoint(
                &bootstrap,
                crate::config::SemanticPolicyConfig::default(),
                forged_checkpoint,
            )
            .is_err(),
            "resident losing row is not typed-selector provenance"
        );
        assert_eq!(
            graph.logical_index_residency_bytes().unwrap(),
            graph.derived_index_bytes
        );

        // A journaled continuation changes the compact frontier and must put
        // it back exactly on both Drop and explicit rollback.
        let rollback_candidate = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
        );
        let before_continuation = graph_snapshot(&graph);
        let preflight = graph
            .preflight_admission(&rollback_candidate)
            .expect("frontier continuation preflights");
        let journal = graph
            .apply_preflight_journaled(rollback_candidate.clone(), preflight)
            .expect("frontier continuation journals");
        assert_ne!(
            journal.graph().authority_provenance,
            before_continuation.authority_provenance,
            "journal mutates the compact selector frontier"
        );
        drop(journal);
        assert_graph_state_eq(&graph, &before_continuation);
        let preflight = graph
            .preflight_admission(&rollback_candidate)
            .expect("frontier continuation re-preflights");
        let journal = graph
            .apply_preflight_journaled(rollback_candidate, preflight)
            .expect("frontier continuation re-journals");
        journal.rollback();
        assert_graph_state_eq(&graph, &before_continuation);

        // Retirement keeps signed selector/selected witnesses, not the
        // ordinary continuation chain. Restore independently checks the
        // derived relations against this same complete signed history.
        let canonical_history = graph.facts.values().cloned().collect::<Vec<_>>();
        graph.cold_history_since_retirement =
            usize::try_from(graph.policy_limits.max_hot_history_facts).unwrap_or(usize::MAX);
        graph.retire_cold_history();
        let checkpoint = graph.live_checkpoint();
        let restored = FactGraph::from_live_checkpoint_with_history(
            &bootstrap,
            crate::config::SemanticPolicyConfig::default(),
            checkpoint,
            |_| Ok(canonical_history.clone()),
        )
        .expect("selector provenance validates across the cold boundary");
        assert_eq!(
            restored.authority_lineage(&controller).selected_branch(),
            Some(late_revoke_id)
        );
        assert!(restored.fact_is_authoritative(&continuation_grant_id));
        assert_eq!(restored.projection(), Projection::from_graph(&restored));
        assert_eq!(
            restored.projection_commitment_root(),
            graph.projection_commitment_root()
        );
    }

    #[test]
    fn authority_resolution_tracks_distinct_membership_and_stand_down_branches() {
        let (bootstrap, root_key) = closed(120);
        let target_a = device(&key(122));
        let target_b = device(&key(123));
        let root = device(&root_key);

        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let grant_a = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: target_a.clone(),
                role: Role::Member,
            },
        );
        graph.admit(grant_a).expect("first target role admits");
        let grant_b = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: target_b.clone(),
                role: Role::Member,
            },
        );
        graph.admit(grant_b).expect("second target role admits");

        let proposal_b = witnessed_fact(
            &graph,
            &root_key,
            FactBody::Evict {
                target: target_b.clone(),
            },
        );
        graph
            .admit(proposal_b.clone())
            .expect("eviction proposal admits");
        let attestation_b = witnessed_fact(
            &graph,
            &key(122),
            FactBody::Attestation {
                target: target_b.clone(),
                proposal: proposal_b.id,
                decision: super::super::AttestationDecision::Evict,
                signer: target_a.clone(),
                contributions: Vec::new(),
            },
        );
        graph
            .admit(attestation_b.clone())
            .expect("member eviction attestation admits");

        let branch_membership = witnessed_fact(
            &graph,
            &root_key,
            FactBody::MembershipAdmit {
                target: target_a.clone(),
            },
        );
        let branch_stand_down = witnessed_fact(
            &graph,
            &root_key,
            FactBody::EvictionProof {
                target: target_b.clone(),
                evidence: vec![attestation_b.id],
            },
        );
        graph
            .admit(branch_membership.clone())
            .expect("membership branch admits");
        graph
            .admit(branch_stand_down.clone())
            .expect("stand-down branch admits without the other branch as a parent");
        let reverse_before_rebuild = graph.authority_dependents_index.clone();
        let residency_before_rebuild = graph
            .authority_dependents_residency_bytes()
            .expect("reverse-index residency computes before rebuild");
        graph.rebuild_indexes();
        assert_eq!(graph.authority_dependents_index, reverse_before_rebuild);
        assert_eq!(
            graph
                .authority_dependents_residency_bytes()
                .expect("reverse-index residency computes after rebuild"),
            residency_before_rebuild
        );

        let mut branch_ids = vec![branch_membership.id, branch_stand_down.id];
        branch_ids.sort();
        let cited_heads = branch_ids.clone();
        let baseline = graph.clone();
        assert_eq!(
            baseline
                .authority_dependents_residency_bytes()
                .expect("cloned authority residency computes"),
            graph
                .authority_dependents_residency_bytes()
                .expect("authority residency computes"),
            "clone preserves the exact logical reverse-index charge"
        );
        for selected_head in cited_heads.iter().copied() {
            let mut graph = baseline.clone();
            let resolution = witnessed_fact(
                &graph,
                &root_key,
                FactBody::AuthorityLineageResolution {
                    subject: root.clone(),
                    cited_heads: cited_heads.clone(),
                    selected_head,
                },
            );
            let impact = graph.projection_impact_for_fact(&resolution);
            assert!(
                impact
                    .0
                    .contains(&ExclusiveCell::membership(target_a.clone())),
                "membership branch cell is included"
            );
            assert!(
                impact.1.contains(&target_a) && impact.1.contains(&target_b),
                "membership and stand-down branch targets are both included"
            );
            let before = graph.clone();
            let before_residency = graph
                .authority_dependents_residency_bytes()
                .expect("baseline authority residency computes");
            let preflight = graph
                .preflight_admission(&resolution)
                .expect("distinct-effect resolution preflights");
            let journal = graph
                .apply_preflight_journaled(resolution.clone(), preflight)
                .expect("distinct-effect resolution applies");
            let journal_graph = journal.graph();
            assert_eq!(
                journal_graph.projection(),
                Projection::from_graph(journal_graph)
            );
            if selected_head == branch_membership.id {
                assert_eq!(
                    journal_graph.evaluator().effective_membership(&target_a),
                    Some(true)
                );
                assert!(!journal_graph.projection().is_stood_down(&target_b));
            } else {
                assert_eq!(
                    journal_graph.evaluator().effective_membership(&target_a),
                    None
                );
                assert!(journal_graph.projection().is_stood_down(&target_b));
            }
            journal.rollback();
            assert_eq!(graph.projection(), before.projection());
            assert_eq!(graph.stand_down_index, before.stand_down_index);
            assert_eq!(
                graph.authority_dependents_index,
                before.authority_dependents_index
            );
            assert_eq!(
                graph
                    .authority_dependents_residency_bytes()
                    .expect("rolled-back distinct residency computes"),
                before_residency
            );
            graph
                .admit(resolution)
                .expect("reapplying selected branch resolution succeeds");
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
        }
    }

    #[test]
    fn membership_resolution_does_not_select_authority_lineage_branch() {
        let (bootstrap, root_key) = closed(76);
        let target_key = key(77);
        let member_key = key(78);
        let resolver_key = key(79);
        let target = device(&target_key);
        let member = device(&member_key);
        let resolver = device(&resolver_key);
        let authored = |graph: &FactGraph, signing_key: &SigningKey, body: FactBody| {
            let author = device(signing_key);
            let witness = graph.authoring_witness(&body, &author);
            SignedFact::sign(
                super::super::FactContent::from_authoring_witness(
                    graph,
                    body,
                    &witness,
                    std::iter::empty(),
                ),
                signing_key,
            )
            .expect("witness-derived fact signs")
        };

        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let grant = authored(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
        );
        graph.admit(grant).expect("target grant admits");
        let member_grant = authored(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: member.clone(),
                role: Role::Member,
            },
        );
        graph.admit(member_grant).expect("member grant admits");
        let proposal = authored(
            &graph,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
        );
        graph
            .admit(proposal.clone())
            .expect("eviction proposal admits");
        let attestation = authored(
            &graph,
            &member_key,
            FactBody::Attestation {
                target: target.clone(),
                proposal: proposal.id,
                decision: super::super::AttestationDecision::Evict,
                signer: member.clone(),
                contributions: Vec::new(),
            },
        );
        graph
            .admit(attestation.clone())
            .expect("member eviction attestation admits");
        let proof = authored(
            &graph,
            &root_key,
            FactBody::EvictionProof {
                target: target.clone(),
                evidence: vec![attestation.id],
            },
        );
        graph.admit(proof.clone()).expect("eviction proof admits");
        let resolver_grant = authored(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: resolver.clone(),
                role: Role::Owner,
            },
        );
        graph
            .admit(resolver_grant)
            .expect("distinct Owner resolver grant admits");

        let membership = authored(
            &graph,
            &root_key,
            FactBody::MembershipAdmit {
                target: target.clone(),
            },
        );
        let evict = authored(
            &graph,
            &resolver_key,
            FactBody::Evict {
                target: target.clone(),
            },
        );
        let mut concurrent = graph.clone();
        concurrent
            .admit(membership)
            .expect("concurrent membership admit admits");
        concurrent
            .admit(evict.clone())
            .expect("concurrent evict admits");
        let cell = ExclusiveCell::membership(target.clone());
        let mut cited_heads = concurrent.cell_heads(&cell);
        cited_heads.sort();
        let resolution = authored(
            &concurrent,
            &resolver_key,
            FactBody::Resolution {
                cell,
                cited_heads,
                selected_head: evict.id,
            },
        );
        let before_resolution = concurrent.clone();
        let resolution_impact = concurrent.projection_impact_for_fact(&resolution);
        assert!(
            resolution_impact.1.contains(&target),
            "stand-down target remains in the selected-branch impact"
        );
        let resolution_for_rollback = resolution.clone();
        let preflight = concurrent
            .preflight_admission(&resolution_for_rollback)
            .expect("stand-down branch resolution preflights");
        let journal = concurrent
            .apply_preflight_journaled(resolution_for_rollback, preflight)
            .expect("stand-down branch resolution applies");
        let journal_graph = journal.graph();
        assert_eq!(
            journal_graph.projection(),
            Projection::from_graph(journal_graph),
            "selected stand-down branch matches full projection"
        );
        journal.rollback();
        assert_eq!(concurrent.projection(), before_resolution.projection());
        assert_eq!(
            concurrent.stand_down_index, before_resolution.stand_down_index,
            "stand-down branch rollback restores index ownership"
        );
        concurrent
            .admit(resolution)
            .expect("membership resolution selects Evict");

        assert_eq!(
            concurrent.evaluator().effective_membership(&target),
            Some(false),
            "membership projection follows the selected Evict branch"
        );
        assert_eq!(
            concurrent.authority_lineage(&target).selected_branch(),
            None,
            "membership resolution must not select an authority branch"
        );
        assert!(
            concurrent.fact_is_authoritative(&proof.id),
            "prior eviction evidence remains authoritative"
        );
        assert!(concurrent.projection().is_stood_down(&target));
        assert_eq!(
            concurrent.projection(),
            Projection::from_graph(&concurrent),
            "stand-down selection remains equal to the full reference"
        );
    }

    #[test]
    fn eviction_removes_closed_session_admission() {
        let (bootstrap, root_key) = closed(45);
        let controller_key = key(46);
        let controller = device(&controller_key);
        let root = device(&root_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: controller.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("member grant admits");
        assert!(graph.evaluator().admits_closed_session(&root, &controller));
        assert_eq!(graph.evaluator().effective_membership(&controller), None);
        graph.admit(eviction).expect("root eviction admits");
        let evaluator = graph.evaluator();
        assert!(!evaluator.is_conflicted(&ExclusiveCell::role(controller.clone())));
        assert_eq!(evaluator.effective_role(&controller), None);
        assert_eq!(evaluator.effective_membership(&controller), Some(false));
        assert!(!evaluator.admits_closed_session(&root, &controller));
    }

    #[test]
    fn membership_admit_restores_membership_but_not_role() {
        let (bootstrap, root_key) = closed(57);
        let root = device(&root_key);
        let target_key = key(58);
        let target = device(&target_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("initial member grant admits");
        graph.admit(eviction.clone()).expect("eviction admits");
        assert_eq!(graph.evaluator().effective_membership(&target), Some(false));

        let membership_body = FactBody::MembershipAdmit {
            target: target.clone(),
        };
        let witness = graph.authoring_witness(&membership_body, &root);
        assert!(witness.parents().contains(&eviction.id));
        let membership = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                membership_body,
                &witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("owner membership admit signs");
        graph.admit(membership).expect("membership admit admits");
        let evaluator = graph.evaluator();
        assert_eq!(evaluator.effective_membership(&target), Some(true));
        assert_eq!(evaluator.effective_role(&target), None);
        assert!(!evaluator.admits_closed_session(&root, &target));

        let role_body = FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        };
        let role_witness = graph.authoring_witness(&role_body, &root);
        assert!(
            role_witness.parents().contains(&eviction.id),
            "role restoration must retain the evicted role-cell head"
        );
        let role = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                role_body,
                &role_witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("owner role grant signs");
        graph.admit(role).expect("causal role restoration admits");
        assert!(graph.evaluator().admits_closed_session(&root, &target));
    }

    #[test]
    fn membership_admit_rejects_self_and_open_profile_facts() {
        let (bootstrap, root_key) = closed(59);
        let target_key = key(60);
        let target = device(&target_key);
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let eviction = fact(
            &bootstrap,
            &root_key,
            FactBody::Evict {
                target: target.clone(),
            },
            vec![grant.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant).expect("initial member grant admits");
        graph.admit(eviction).expect("eviction admits");
        let self_body = FactBody::MembershipAdmit {
            target: target.clone(),
        };
        let self_witness = graph.authoring_witness(&self_body, &target);
        let self_admit = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &graph,
                self_body,
                &self_witness,
                std::iter::empty(),
            ),
            &target_key,
        )
        .expect("self-authored candidate signs");
        assert_eq!(
            graph.admit(self_admit),
            Err(SemanticError::UnauthorizedMembershipAdmit)
        );

        let open = VerifiedBootstrap::open("membership-open").expect("open bootstrap");
        let open_key = key(61);
        let open_target = device(&key(62));
        let open_admit = fact(
            &open,
            &open_key,
            FactBody::MembershipAdmit {
                target: open_target,
            },
            Vec::new(),
        );
        let mut open_graph = FactGraph::from_bootstrap(&open);
        assert_eq!(
            open_graph.admit(open_admit),
            Err(SemanticError::DomainMismatch)
        );
    }

    #[test]
    fn evaluator_derives_decision_from_the_selected_attestation() {
        let (bootstrap, root_key) = closed(46);
        let target = device(&key(47));
        let proposal = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let attestation = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::Attestation {
                target,
                proposal: proposal.id,
                decision: super::super::AttestationDecision::Approve,
                signer: device(&root_key),
                contributions: Vec::new(),
            },
            vec![proposal.id],
            &[(device(&root_key), vec![proposal.id])],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(proposal.clone()).expect("proposal admits");
        graph.admit(attestation).expect("attestation admits");
        assert_eq!(
            graph.evaluator().effective_decision(&proposal.id),
            Some(super::super::AttestationDecision::Approve)
        );
    }

    #[test]
    fn open_profile_has_no_durable_fact_domain() {
        let open = VerifiedBootstrap::open("causal-open-domain").expect("open bootstrap verifies");
        let participant_key = key(48);
        let participant = device(&participant_key);
        let fact = fact(
            &open,
            &participant_key,
            FactBody::RoleGrant {
                target: participant,
                role: Role::Member,
            },
            Vec::new(),
        );
        assert_eq!(
            FactGraph::from_bootstrap(&open).admit(fact),
            Err(SemanticError::DomainMismatch)
        );
    }

    #[test]
    fn admission_budget_refuses_n_plus_one_but_replays_duplicates() {
        let (bootstrap, root_key) = closed(62);
        let policy = SemanticAdmissionPolicy {
            max_admitted_facts: 1,
            ..SemanticAdmissionPolicy::default()
        };
        let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(63)),
                role: Role::Member,
            },
            Vec::new(),
        );
        assert_eq!(graph.admit(first.clone()), Ok(Admission::Inserted));
        assert_eq!(graph.admit(first), Ok(Admission::AlreadyPresent));
        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(64)),
                role: Role::Member,
            },
            Vec::new(),
        );
        assert!(matches!(
            graph.admit(second),
            Err(SemanticError::CapacityExceeded {
                dimension: super::super::SemanticCapacityDimension::AdmittedFacts,
                ..
            })
        ));
        assert_eq!(graph.len(), 1);
    }

    #[test]
    fn dependency_waiters_wake_only_after_their_parent_arrives() {
        let (bootstrap, root_key) = closed(65);
        let policy = SemanticAdmissionPolicy {
            max_ready_batch: 1,
            ..SemanticAdmissionPolicy::default()
        };
        let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(66)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(66)),
                role: Role::Controller,
            },
            vec![parent.id],
        );
        assert!(matches!(
            graph.admit(child.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(graph.retry_quarantined().unwrap().is_empty());
        graph.admit(parent).expect("parent admits");
        assert_eq!(graph.retry_quarantined().unwrap(), vec![child.id]);
        assert!(graph.get(&child.id).is_some());
    }

    #[test]
    fn admitted_parent_is_ready_but_absent_parent_quarantines_exactly() {
        let (bootstrap, root_key) = closed(66);
        let target = device(&key(67));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let child_cost_before = graph.fact_cost(&child).expect("child cost computes");
        assert_eq!(child_cost_before.missing, vec![parent.id]);
        assert_eq!(
            graph.admit(parent.clone()),
            Ok(Admission::Inserted),
            "the root parent admits first"
        );

        let child_cost_after = graph.fact_cost(&child).expect("child cost recomputes");
        assert!(child_cost_after.missing.is_empty());
        assert_eq!(
            graph.admit(child),
            Ok(Admission::Inserted),
            "an admitted causal parent is not quarantined"
        );
        assert_eq!(
            graph.admitted_dependency_edges,
            FactGraph::from_bootstrap(&bootstrap)
                .fact_cost(&parent)
                .expect("parent cost computes")
                .dependency_edges
                + child_cost_after.dependency_edges,
            "dependency accounting retains all canonical edges"
        );

        let absent = FactId::from_bytes([0xee; 32]);
        let missing_child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(68)),
                role: Role::Member,
            },
            vec![absent],
        );
        let missing_cost = graph
            .fact_cost(&missing_child)
            .expect("missing-child cost computes");
        assert_eq!(missing_cost.missing, vec![absent]);
        assert_eq!(
            graph.admit(missing_child),
            Ok(Admission::Quarantined {
                missing: vec![absent]
            }),
            "a truly absent dependency remains quarantined"
        );
        assert_eq!(
            graph.quarantined_dependency_edges, missing_cost.dependency_edges,
            "quarantine accounting retains all canonical edges"
        );
    }

    #[test]
    fn retained_author_budget_spans_quarantine_and_promotion() {
        let (bootstrap, root_key) = closed(67);
        let target = device(&key(68));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::Attestation {
                target: target.clone(),
                proposal: parent.id,
                decision: super::super::AttestationDecision::Approve,
                signer: device(&root_key),
                contributions: Vec::new(),
            },
            vec![parent.id],
        );
        let policy = SemanticAdmissionPolicy {
            max_retained_facts_per_author: 2,
            ..SemanticAdmissionPolicy::default()
        };
        let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        assert!(matches!(
            graph.admit(child.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        graph.admit(parent).expect("parent admits");
        assert_eq!(graph.retry_quarantined().unwrap(), vec![child.id]);

        let third = fact(
            &bootstrap,
            &root_key,
            FactBody::Attestation {
                target,
                proposal: child.id,
                decision: super::super::AttestationDecision::Reject,
                signer: device(&root_key),
                contributions: Vec::new(),
            },
            vec![child.id],
        );
        assert!(matches!(
            graph.admit(third),
            Err(SemanticError::CapacityExceeded {
                dimension: super::super::SemanticCapacityDimension::RetainedFactsPerAuthor,
                ..
            })
        ));
    }

    #[test]
    fn semantic_noops_and_ineligible_quarantine_do_not_retain() {
        let (bootstrap, root_key) = closed(69);
        let target = device(&key(70));
        let grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(grant.clone()).expect("grant admits");
        let same_effect = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Member,
            },
            vec![grant.id],
        );
        assert_eq!(
            graph.admit(same_effect),
            Err(SemanticError::NoOp("role grant already effective"))
        );

        let unknown_key = key(71);
        let missing = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(72)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let untrusted = fact(
            &bootstrap,
            &unknown_key,
            FactBody::RoleGrant {
                target: device(&key(73)),
                role: Role::Member,
            },
            vec![missing.id],
        );
        assert_eq!(
            graph.admit(untrusted),
            Err(SemanticError::QuarantineSignerNotEligible)
        );
        assert_eq!(graph.quarantined().count(), 0);
    }

    fn signed_membership_maxima(
        facts: &BTreeMap<FactId, SignedFact>,
        subject: &DeviceId,
    ) -> BTreeSet<FactId> {
        // Independent oracle: no maintained heads, selector summaries,
        // graph.is_ancestor, or production head-removal predicate.
        let cell = ExclusiveCell::membership(subject.clone());
        let members = facts
            .values()
            .filter(|fact| fact.content.body.exclusive_cells().contains(&cell))
            .map(|fact| fact.id)
            .collect::<BTreeSet<_>>();
        members
            .iter()
            .copied()
            .filter(|candidate| {
                !members
                    .iter()
                    .filter(|other| *other != candidate)
                    .any(|other| {
                        let mut pending = dependencies(facts.get(other).unwrap());
                        let mut seen = BTreeSet::new();
                        while let Some(id) = pending.pop() {
                            if id == *candidate {
                                return true;
                            }
                            if seen.insert(id) {
                                pending.extend(dependencies(
                                    facts
                                        .get(&id)
                                        .expect("oracle owns complete signed ancestry"),
                                ));
                            }
                        }
                        false
                    })
            })
            .collect()
    }

    fn assert_historical_membership_boundary(
        graph: &FactGraph,
        complete: &FactGraph,
        subject: &DeviceId,
        old_membership: FactId,
        fresh_membership: FactId,
        expected_value: Option<FactId>,
        fresh_authoritative: bool,
    ) {
        let cell = ExclusiveCell::membership(subject.clone());
        let raw = signed_membership_maxima(&complete.facts, subject);
        assert_eq!(
            graph
                .raw_cell_heads(&cell)
                .into_iter()
                .collect::<BTreeSet<_>>(),
            raw
        );
        assert!(
            graph.get(&old_membership).is_some(),
            "old signed loser remains a retained selector witness"
        );
        assert!(!graph.fact_is_authoritative(&old_membership));
        if complete.get(&fresh_membership).is_some() {
            assert!(graph.get(&fresh_membership).is_some());
            assert_eq!(
                graph.fact_is_authoritative(&fresh_membership),
                fresh_authoritative
            );
            assert_eq!(raw, BTreeSet::from([fresh_membership]));
        }
        let full = Projection::from_graph(complete);
        assert_eq!(full.value(&cell), expected_value);
        assert_eq!(graph.projection(), full);
        assert_eq!(Projection::from_graph(graph), full);
        assert_eq!(graph.projection_commitment_root(), full.commitment_root());
        assert_eq!(
            graph.derived_index_bytes,
            graph.logical_index_residency_bytes().unwrap()
        );
    }

    #[test]
    fn historical_membership_exclusion_survives_later_selectors_and_cold_journals() {
        let (bootstrap, root_key) = closed(184);
        let controller_key = key(185);
        let other_owner_key = key(186);
        let controller = device(&controller_key);
        let policy = SemanticAdmissionPolicy {
            max_hot_history_facts: 4,
            ..SemanticAdmissionPolicy::default()
        };
        let mut seed = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        for ordinal in 0..8 {
            let precursor = witnessed_fact(
                &seed,
                &root_key,
                FactBody::RoleGrant {
                    target: device(&key(187)),
                    role: if ordinal % 2 == 0 {
                        Role::Member
                    } else {
                        Role::Controller
                    },
                },
            );
            assert_eq!(seed.admit(precursor), Ok(Admission::Inserted));
        }
        let owner = witnessed_fact(
            &seed,
            &root_key,
            FactBody::RoleGrant {
                target: device(&other_owner_key),
                role: Role::Owner,
            },
        );
        assert_eq!(seed.admit(owner), Ok(Admission::Inserted));
        let grant = witnessed_fact(
            &seed,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
        );
        assert_eq!(seed.admit(grant), Ok(Admission::Inserted));
        let m = witnessed_fact(
            &seed,
            &controller_key,
            FactBody::MembershipAdmit {
                target: controller.clone(),
            },
        );
        let v = witnessed_fact(
            &seed,
            &root_key,
            FactBody::Evict {
                target: controller.clone(),
            },
        );
        let mut fork = seed.clone();
        assert_eq!(fork.admit(m.clone()), Ok(Admission::Inserted));
        assert_eq!(fork.admit(v.clone()), Ok(Admission::Inserted));
        let cited = vec![m.id, v.id]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let s = witnessed_fact(
            &fork,
            &root_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: cited.clone(),
                selected_head: v.id,
            },
        );
        let alternative = witnessed_fact(
            &fork,
            &other_owner_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: cited,
                selected_head: m.id,
            },
        );
        let mut selected = fork.clone();
        assert_eq!(selected.admit(s.clone()), Ok(Admission::Inserted));
        let n = witnessed_fact(
            &selected,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
        );
        assert_eq!(selected.admit(n.clone()), Ok(Admission::Inserted));
        let q = witnessed_fact(
            &selected,
            &controller_key,
            FactBody::MembershipAdmit {
                target: controller.clone(),
            },
        );
        let r = witnessed_fact(
            &selected,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
        );
        assert!(
            !dependencies(&q).contains(&m.id),
            "same public witness hides the losing raw M head"
        );
        assert!(dependencies(&q).contains(&v.id));
        assert!(dependencies(&q).contains(&n.id));
        assert_historical_membership_boundary(
            &selected,
            &selected,
            &controller,
            m.id,
            q.id,
            Some(v.id),
            false,
        );

        let mut after_q = selected.clone();
        let old_bytes = after_q.derived_index_bytes;
        let priced = after_q.exact_index_residency_delta(&q).unwrap();
        let predicted = after_q
            .apply_index_residency_delta(old_bytes, priced)
            .unwrap();
        assert_eq!(after_q.admit(q.clone()), Ok(Admission::Inserted));
        assert_eq!(
            after_q.derived_index_bytes, predicted,
            "hidden-head removal is priced before mutation"
        );
        assert_historical_membership_boundary(
            &after_q,
            &after_q,
            &controller,
            m.id,
            q.id,
            Some(q.id),
            true,
        );
        let mut after_r = after_q.clone();
        assert_eq!(after_r.admit(r.clone()), Ok(Admission::Inserted));
        assert_historical_membership_boundary(
            &after_r,
            &after_r,
            &controller,
            m.id,
            q.id,
            None,
            false,
        );
        let t2 = witnessed_fact(
            &after_r,
            &root_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: vec![q.id, r.id]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                selected_head: r.id,
            },
        );
        let mut after_t2 = after_r.clone();
        assert_eq!(after_t2.admit(t2.clone()), Ok(Admission::Inserted));
        assert_historical_membership_boundary(
            &after_t2,
            &after_t2,
            &controller,
            m.id,
            q.id,
            None,
            false,
        );
        let u2 = witnessed_fact(
            &after_t2,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Owner,
            },
        );
        let mut after_u2 = after_t2.clone();
        assert_eq!(after_u2.admit(u2.clone()), Ok(Admission::Inserted));
        assert_historical_membership_boundary(
            &after_u2,
            &after_u2,
            &controller,
            m.id,
            q.id,
            None,
            false,
        );
        let future = witnessed_fact(
            &after_u2,
            &controller_key,
            FactBody::RoleGrant {
                target: device(&key(188)),
                role: Role::Member,
            },
        );
        let mut final_graph = after_u2.clone();
        assert_eq!(final_graph.admit(future.clone()), Ok(Admission::Inserted));
        assert_historical_membership_boundary(
            &final_graph,
            &final_graph,
            &controller,
            m.id,
            q.id,
            None,
            false,
        );

        // Both M/V and Q/R schedules use these exact signed bodies. The
        // independent raw oracle must agree before any checkpoint is made.
        for reverse_old in [false, true] {
            for reverse_new in [false, true] {
                let mut graph = seed.clone();
                for fact in if reverse_old {
                    [v.clone(), m.clone()]
                } else {
                    [m.clone(), v.clone()]
                } {
                    assert_eq!(graph.admit(fact), Ok(Admission::Inserted));
                }
                assert_eq!(graph.admit(s.clone()), Ok(Admission::Inserted));
                assert_eq!(graph.admit(n.clone()), Ok(Admission::Inserted));
                assert_historical_membership_boundary(
                    &graph,
                    &selected,
                    &controller,
                    m.id,
                    q.id,
                    Some(v.id),
                    false,
                );
                for fact in if reverse_new {
                    [r.clone(), q.clone()]
                } else {
                    [q.clone(), r.clone()]
                } {
                    assert_eq!(graph.admit(fact), Ok(Admission::Inserted));
                }
                assert_historical_membership_boundary(
                    &graph,
                    &after_r,
                    &controller,
                    m.id,
                    q.id,
                    None,
                    false,
                );
                for (fact, complete) in
                    [(&t2, &after_t2), (&u2, &after_u2), (&future, &final_graph)]
                {
                    assert_eq!(graph.admit(fact.clone()), Ok(Admission::Inserted));
                    assert_historical_membership_boundary(
                        &graph,
                        complete,
                        &controller,
                        m.id,
                        q.id,
                        None,
                        false,
                    );
                }
                assert_eq!(graph.facts, final_graph.facts);
            }
        }

        for (base, candidate, complete, value, q_allowed) in [
            (&selected, &q, &after_q, Some(q.id), true),
            (&after_q, &r, &after_r, None, false),
            (&after_r, &t2, &after_t2, None, false),
            (&after_t2, &u2, &after_u2, None, false),
            (&after_u2, &future, &final_graph, None, false),
        ] {
            let mut rebuilt = complete.clone();
            rebuilt.rebuild_indexes();
            assert_historical_membership_boundary(
                &rebuilt,
                complete,
                &controller,
                m.id,
                q.id,
                value,
                q_allowed,
            );
            assert_eq!(rebuilt.authority_provenance, complete.authority_provenance);
            for cold in [false, true] {
                let history = base.facts.values().cloned().collect::<Vec<_>>();
                let mut graph = base.clone();
                if cold {
                    graph.retire_cold_history();
                    assert!(graph.facts.len() < history.len());
                }
                graph.projection();
                let before = graph_snapshot(&graph);
                for terminal in 0..3 {
                    let journal = if cold {
                        graph.admit_journaled_with_history(candidate.clone(), history.clone())
                    } else {
                        graph.admit_journaled(candidate.clone())
                    }
                    .expect("same signed transition journals");
                    assert_eq!(journal.admission(), &Admission::Inserted);
                    assert_eq!(journal.delta().rows().len(), 1);
                    assert_eq!(journal.delta().rows()[0].fact().id, candidate.id);
                    assert!(journal.delta().removed().is_empty());
                    assert_historical_membership_boundary(
                        journal.graph(),
                        complete,
                        &controller,
                        m.id,
                        q.id,
                        value,
                        q_allowed,
                    );
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&graph, &before);
                    }
                }
                assert_historical_membership_boundary(
                    &graph,
                    complete,
                    &controller,
                    m.id,
                    q.id,
                    value,
                    q_allowed,
                );
                if cold {
                    let canonical = complete.facts.values().cloned().collect::<Vec<_>>();
                    let restored = FactGraph::from_live_checkpoint_with_history(
                        &bootstrap,
                        crate::config::SemanticPolicyConfig {
                            max_hot_history_facts: 4,
                            ..Default::default()
                        },
                        graph.live_checkpoint(),
                        |_| Ok(canonical.clone()),
                    )
                    .expect("pristine cold provenance validates against complete signed history");
                    assert_historical_membership_boundary(
                        &restored,
                        complete,
                        &controller,
                        m.id,
                        q.id,
                        value,
                        q_allowed,
                    );
                }
            }
        }
        for cold in [false, true] {
            let mut graph = selected.clone();
            let history = graph.facts.values().cloned().collect::<Vec<_>>();
            if cold {
                graph.retire_cold_history();
                assert!(graph.facts.len() < history.len());
            }
            graph.projection();
            let before = graph_snapshot(&graph);
            for terminal in 0..3 {
                let inputs = vec![q.clone(), r.clone(), t2.clone(), u2.clone(), future.clone()];
                let journal = graph
                    .admit_journaled_batch_with_history(
                        inputs.clone(),
                        if cold { history.clone() } else { Vec::new() },
                    )
                    .expect("whole two-selector lifecycle fits one bounded group");
                assert_eq!(journal.results().len(), inputs.len());
                for (result, input) in journal.results().iter().zip(&inputs) {
                    assert!(
                        matches!(result.outcome(), AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == input.id)
                    );
                }
                assert_eq!(journal.delta().rows().len(), inputs.len());
                assert!(journal
                    .delta()
                    .rows()
                    .iter()
                    .all(|row| row.status() == SemanticFactStatus::Admitted));
                assert!(journal.delta().removed().is_empty());
                assert_historical_membership_boundary(
                    journal.graph(),
                    &final_graph,
                    &controller,
                    m.id,
                    q.id,
                    None,
                    false,
                );
                match terminal {
                    0 => journal.rollback(),
                    1 => drop(journal),
                    _ => journal.commit(),
                }
                if terminal < 2 {
                    assert_graph_state_eq(&graph, &before);
                }
            }
            assert_historical_membership_boundary(
                &graph,
                &final_graph,
                &controller,
                m.id,
                q.id,
                None,
                false,
            );
        }

        // Balance the serialized index charge as well as omitting old S, so
        // this rejection tests canonical predecessor-context completeness,
        // not merely the earlier structural byte-accounting guard.
        let mut omitted = after_u2.clone();
        omitted.authority_provenance.retain(|_, row| {
            row.remove(&s.id);
            !row.is_empty()
        });
        assert!(omitted
            .authority_selector_index
            .get_mut(&controller)
            .unwrap()
            .remove(&(s.id, v.id)));
        omitted.derived_index_bytes = omitted.logical_index_residency_bytes().unwrap();
        let canonical = after_u2.facts.values().cloned().collect::<Vec<_>>();
        let result = FactGraph::from_live_checkpoint_with_history(
            &bootstrap,
            crate::config::SemanticPolicyConfig {
                max_hot_history_facts: 4,
                ..Default::default()
            },
            omitted.live_checkpoint(),
            |_| Ok(canonical.clone()),
        );
        assert!(
            matches!(result, Err(error) if error == "checkpoint omits required selector provenance")
        );

        // A later selector can choose between competing selector bodies.
        // The losing selector's exclusion must NOT veto the selected one.
        let mut competitors = fork.clone();
        assert_eq!(competitors.admit(s.clone()), Ok(Admission::Inserted));
        assert_eq!(
            competitors.admit(alternative.clone()),
            Ok(Admission::Inserted)
        );
        assert_eq!(
            competitors
                .maximal_typed_selectors(
                    &controller,
                    competitors.authority_lineage(&controller).heads()
                )
                .len(),
            2
        );
        let winner = witnessed_fact(
            &competitors,
            &root_key,
            FactBody::AuthorityLineageResolution {
                subject: controller.clone(),
                cited_heads: vec![s.id, alternative.id]
                    .into_iter()
                    .collect::<BTreeSet<_>>()
                    .into_iter()
                    .collect(),
                selected_head: s.id,
            },
        );
        let role_cell = ExclusiveCell::role(controller.clone());
        let membership_cell = ExclusiveCell::membership(controller.clone());
        let before_winner_projection = Projection::from_graph(&competitors);
        assert_eq!(competitors.projection(), before_winner_projection);
        assert_eq!(before_winner_projection.value(&role_cell), None);
        assert!(
            matches!(before_winner_projection.membership_cell(&controller),
            Some(super::super::CellProjection::Conflict(ids))
                if ids.iter().copied().collect::<BTreeSet<_>>() == BTreeSet::from([m.id, v.id]))
        );
        let (impact_cells, impact_subjects) = competitors.projection_impact_for_fact(&winner);
        assert!(impact_cells.contains(&role_cell));
        assert!(impact_cells.contains(&membership_cell));
        assert!(impact_subjects.contains(&controller));
        let before_winner = graph_snapshot(&competitors);
        assert_eq!(competitors.admit(winner.clone()), Ok(Admission::Inserted));
        let relevant = competitors
            .relevant_typed_selectors(
                &controller,
                competitors.authority_lineage(&controller).heads(),
            )
            .expect("signed selector ancestry is acyclic");
        assert!(relevant.contains(&s.id));
        assert!(relevant.contains(&winner.id));
        assert!(!relevant.contains(&alternative.id));
        assert_historical_membership_boundary(
            &competitors,
            &competitors,
            &controller,
            m.id,
            q.id,
            Some(v.id),
            false,
        );
        let final_projection = Projection::from_graph(&competitors);
        assert_eq!(final_projection.value(&role_cell), Some(v.id));
        assert_eq!(final_projection.value(&membership_cell), Some(v.id));
        let expected_cells = BTreeMap::from([
            (
                role_cell.clone(),
                Some(super::super::CellProjection::Value(v.id)),
            ),
            (
                membership_cell.clone(),
                Some(super::super::CellProjection::Value(v.id)),
            ),
        ]);
        // Winner changes exactly these two entries, not unrelated roles.
        let assert_delta = |delta: &super::super::projection::ProjectionDelta,
                            base: &Projection| {
            assert_eq!(delta.cells(), &expected_cells);
            assert!(delta.stand_down().is_empty());
            assert_eq!(delta.base_commitment(), base.commitment_root());
            assert_eq!(delta.commitment(), final_projection.commitment_root());
        };
        for reverse in [false, true] {
            let selectors = if reverse {
                vec![alternative.clone(), s.clone()]
            } else {
                vec![s.clone(), alternative.clone()]
            };
            let mut direct = fork.clone();
            for selector in &selectors {
                assert_eq!(direct.admit(selector.clone()), Ok(Admission::Inserted));
                assert_eq!(direct.projection(), Projection::from_graph(&direct));
            }
            assert_eq!(direct.projection(), before_winner_projection);
            assert_eq!(direct.admit(winner.clone()), Ok(Admission::Inserted));
            assert_eq!(direct.facts, competitors.facts);
            assert_historical_membership_boundary(
                &direct,
                &competitors,
                &controller,
                m.id,
                q.id,
                Some(v.id),
                false,
            );

            let mut ordered_before = fork.clone();
            for selector in &selectors {
                assert_eq!(
                    ordered_before.admit(selector.clone()),
                    Ok(Admission::Inserted)
                );
            }
            assert_eq!(ordered_before.facts, before_winner.facts);
            for cold in [false, true] {
                let history = ordered_before.facts.values().cloned().collect::<Vec<_>>();
                let mut single = ordered_before.clone();
                if cold {
                    single.retire_cold_history();
                    assert!(single.facts.len() < history.len());
                }
                assert_eq!(single.projection(), before_winner_projection);
                let baseline = graph_snapshot(&single);
                for terminal in 0..3 {
                    let journal = if cold {
                        single.admit_journaled_with_history(winner.clone(), history.clone())
                    } else {
                        single.admit_journaled(winner.clone())
                    }
                    .expect("winner single transaction has complete ancestor impact");
                    assert_eq!(journal.admission(), &Admission::Inserted);
                    assert_eq!(journal.delta().rows().len(), 1);
                    assert_eq!(journal.delta().rows()[0].fact().id, winner.id);
                    assert_eq!(
                        journal.delta().rows()[0].status(),
                        SemanticFactStatus::Admitted
                    );
                    assert!(journal.delta().promoted().is_empty());
                    assert!(journal.delta().removed().is_empty());
                    assert!(journal.delta().affected_cells().contains(&role_cell));
                    assert!(journal.delta().affected_cells().contains(&membership_cell));
                    let delta = journal
                        .delta()
                        .projection_delta()
                        .expect("winner publishes both changed cell entries");
                    assert_delta(delta, &before_winner_projection);
                    assert_eq!(delta.base_generation(), baseline.generation);
                    assert_eq!(delta.generation(), journal.graph().generation);
                    assert_historical_membership_boundary(
                        journal.graph(),
                        &competitors,
                        &controller,
                        m.id,
                        q.id,
                        Some(v.id),
                        false,
                    );
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&single, &baseline);
                    }
                }
                assert_historical_membership_boundary(
                    &single,
                    &competitors,
                    &controller,
                    m.id,
                    q.id,
                    Some(v.id),
                    false,
                );
                assert_eq!(single.len(), competitors.len());

                // All three typed selectors are absent during outer
                // preplanning. The common M/V participants already exist.
                let mut aggregate = fork.clone();
                let history = aggregate.facts.values().cloned().collect::<Vec<_>>();
                if cold {
                    aggregate.retire_cold_history();
                    assert!(aggregate.facts.len() < history.len());
                }
                let aggregate_projection = aggregate.projection();
                let baseline = graph_snapshot(&aggregate);
                for terminal in 0..3 {
                    let mut inputs = selectors.clone();
                    inputs.push(winner.clone());
                    let journal = aggregate
                        .admit_journaled_batch_with_history(
                            inputs.clone(),
                            if cold { history.clone() } else { Vec::new() },
                        )
                        .expect(
                            "selector batch captures ancestor preimages before its first input",
                        );
                    assert_eq!(journal.results().len(), 3);
                    for (result, input) in journal.results().iter().zip(&inputs) {
                        assert!(
                            matches!(result.outcome(), AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == input.id)
                        );
                    }
                    assert_eq!(journal.delta().rows().len(), 3);
                    assert_eq!(
                        journal
                            .delta()
                            .rows()
                            .iter()
                            .map(|row| row.fact().id)
                            .collect::<BTreeSet<_>>(),
                        inputs.iter().map(|fact| fact.id).collect::<BTreeSet<_>>()
                    );
                    assert!(journal
                        .delta()
                        .rows()
                        .iter()
                        .all(|row| row.status() == SemanticFactStatus::Admitted));
                    assert!(journal.delta().promoted().is_empty());
                    assert!(journal.delta().removed().is_empty());
                    // Per-input records attribute sparse cell changes while
                    // the group defers commitment rebuilding. Only the
                    // normalized aggregate is a durable root boundary.
                    let item_delta = journal.results()[2]
                        .delta()
                        .projection_delta()
                        .expect("winner per-input delta");
                    assert_eq!(item_delta.cells(), &expected_cells);
                    assert!(item_delta.stand_down().is_empty());
                    assert_eq!(item_delta.base_generation(), baseline.generation + 2);
                    assert_eq!(item_delta.generation(), baseline.generation + 3);
                    let delta = journal
                        .delta()
                        .projection_delta()
                        .expect("normalized aggregate projection delta");
                    assert_delta(delta, &aggregate_projection);
                    assert_eq!(delta.base_generation(), baseline.generation);
                    assert_eq!(delta.generation(), journal.graph().generation);
                    assert_historical_membership_boundary(
                        journal.graph(),
                        &competitors,
                        &controller,
                        m.id,
                        q.id,
                        Some(v.id),
                        false,
                    );
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&aggregate, &baseline);
                    }
                }
                assert_historical_membership_boundary(
                    &aggregate,
                    &competitors,
                    &controller,
                    m.id,
                    q.id,
                    Some(v.id),
                    false,
                );
                assert_eq!(aggregate.len(), competitors.len());
            }
        }
    }

    fn assert_candidate_noop_projection(graph: &FactGraph, expected: &Projection) {
        let full = Projection::from_graph(graph);
        assert_eq!(&full, expected);
        assert_eq!(graph.projection(), full);
        assert_eq!(graph.projection_commitment_root(), full.commitment_root());
    }

    fn assert_intrinsic_noop_unchanged(
        base: &FactGraph,
        candidate: &SignedFact,
        operation: &'static str,
    ) {
        candidate
            .verify()
            .expect("intrinsic refusal has a genuine signature");
        let mut graph = base.clone();
        graph.projection();
        let before = graph_snapshot(&graph);
        assert!(matches!(graph.preflight_admission(candidate),
            Err(SemanticError::NoOp(reason)) if reason == operation));
        assert_graph_state_eq(&graph, &before);
        assert_eq!(
            graph.admit(candidate.clone()),
            Err(SemanticError::NoOp(operation))
        );
        assert_graph_state_eq(&graph, &before);
        assert!(matches!(graph.admit_journaled(candidate.clone()),
            Err(SemanticError::NoOp(reason)) if reason == operation));
        assert_graph_state_eq(&graph, &before);
        let journal = graph
            .admit_journaled_batch(vec![candidate.clone()])
            .expect("input-local intrinsic refusal is attributed, not retained");
        assert!(matches!(journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Refused { fact_id, error: SemanticError::NoOp(reason) }
                if *fact_id == candidate.id && *reason == operation));
        assert!(journal.delta().rows().is_empty());
        assert!(journal.delta().promoted().is_empty());
        assert!(journal.delta().removed().is_empty());
        journal.commit();
        assert_graph_state_eq(&graph, &before);

        let history = base.facts.values().cloned().collect::<Vec<_>>();
        graph.retire_cold_history();
        assert!(
            graph.facts.len() < history.len(),
            "refusal really attaches retired history"
        );
        let cold_before = graph_snapshot(&graph);
        assert!(
            matches!(graph.admit_journaled_with_history(candidate.clone(), history),
            Err(SemanticError::NoOp(reason)) if reason == operation)
        );
        assert_graph_state_eq(&graph, &cold_before);
    }

    #[test]
    fn candidate_relative_noops_preserve_concurrent_role_operations_across_journals() {
        // The very same signed bodies exercise grant/grant, revoke/revoke,
        // and competing ordinary resolutions. Their common support is also
        // delivered late, so the shared helper is exercised by ready retry.
        let (bootstrap, root_key) = closed(201);
        let left_key = key(202);
        let right_key = key(203);
        let target = device(&key(204));
        let policy = SemanticAdmissionPolicy {
            max_hot_history_facts: 4,
            ..SemanticAdmissionPolicy::default()
        };
        let mut eligible = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        for ordinal in 0..8 {
            let support = witnessed_fact(
                &eligible,
                &root_key,
                FactBody::RoleGrant {
                    target: device(&key(205)),
                    role: if ordinal % 2 == 0 {
                        Role::Member
                    } else {
                        Role::Controller
                    },
                },
            );
            assert_eq!(eligible.admit(support), Ok(Admission::Inserted));
        }
        for signer in [&left_key, &right_key] {
            let support = witnessed_fact(
                &eligible,
                &root_key,
                FactBody::RoleGrant {
                    target: device(signer),
                    role: Role::Controller,
                },
            );
            assert_eq!(eligible.admit(support), Ok(Admission::Inserted));
        }
        for kind in 0..3 {
            let mut base = eligible.clone();
            let supports = if kind == 2 {
                let left = witnessed_fact(
                    &base,
                    &left_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                );
                let right = witnessed_fact(
                    &base,
                    &right_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Controller,
                    },
                );
                vec![left, right]
            } else {
                vec![witnessed_fact(
                    &base,
                    &root_key,
                    FactBody::RoleGrant {
                        target: if kind == 0 {
                            device(&key(206))
                        } else {
                            target.clone()
                        },
                        role: Role::Member,
                    },
                )]
            };
            for support in &supports {
                support
                    .verify()
                    .expect("same dependency-ordered signed support verifies");
                assert_eq!(base.admit(support.clone()), Ok(Admission::Inserted));
            }
            let heads = base.raw_cell_heads(&ExclusiveCell::role(target.clone()));
            if kind == 2 {
                assert_eq!(heads.len(), 2);
                assert!(base
                    .evaluator()
                    .is_conflicted(&ExclusiveCell::role(target.clone())));
            }
            let mut pair = Vec::new();
            for (ordinal, signer) in [&left_key, &right_key].into_iter().enumerate() {
                let body = match kind {
                    0 => FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                    1 => FactBody::RoleRevoke {
                        target: target.clone(),
                    },
                    _ => FactBody::Resolution {
                        cell: ExclusiveCell::role(target.clone()),
                        cited_heads: heads.clone(),
                        selected_head: heads[ordinal],
                    },
                };
                let witness = base.authoring_witness(&body, &device(signer));
                let signed = SignedFact::sign(
                    super::super::FactContent::from_authoring_witness(
                        &base,
                        body,
                        &witness,
                        supports.iter().map(|fact| fact.id),
                    ),
                    signer,
                )
                .expect("complete canonical witness signs");
                signed.verify().expect("concurrent operation verifies");
                let mut independent = base.clone();
                assert_eq!(
                    independent.admit(signed.clone()),
                    Ok(Admission::Inserted),
                    "kind={kind} independently valid candidate={ordinal}"
                );
                assert_candidate_noop_projection(
                    &independent,
                    &Projection::from_graph(&independent),
                );
                pair.push(signed);
            }
            assert_ne!(pair[0].id, pair[1].id);
            let mut expected_ids = base.facts.keys().copied().collect::<BTreeSet<_>>();
            expected_ids.extend(pair.iter().map(|fact| fact.id));
            let mut reference = base.clone();
            for candidate in &pair {
                assert_eq!(reference.admit(candidate.clone()), Ok(Admission::Inserted));
                assert_candidate_noop_projection(&reference, &Projection::from_graph(&reference));
            }
            let expected = Projection::from_graph(&reference);
            for reverse in [false, true] {
                let order = if reverse {
                    vec![pair[1].clone(), pair[0].clone()]
                } else {
                    pair.clone()
                };
                let mut direct = base.clone();
                for candidate in &order {
                    assert_eq!(
                        direct.preflight_admission(candidate).unwrap().admission(),
                        &Admission::Inserted
                    );
                    assert_eq!(direct.admit(candidate.clone()), Ok(Admission::Inserted));
                    assert_candidate_noop_projection(&direct, &Projection::from_graph(&direct));
                }
                assert_eq!(
                    direct.facts.keys().copied().collect::<BTreeSet<_>>(),
                    expected_ids
                );
                assert_candidate_noop_projection(&direct, &expected);

                let mut single = base.clone();
                assert_eq!(single.admit(order[0].clone()), Ok(Admission::Inserted));
                single.projection();
                let before = graph_snapshot(&single);
                for terminal in 0..3 {
                    let journal = single
                        .admit_journaled(order[1].clone())
                        .expect("concurrent single input admits");
                    assert_eq!(journal.admission(), &Admission::Inserted);
                    assert_eq!(journal.delta().rows().len(), 1);
                    assert_eq!(journal.delta().rows()[0].fact().id, order[1].id);
                    assert_candidate_noop_projection(journal.graph(), &expected);
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&single, &before);
                    }
                }
                assert_eq!(single.facts, direct.facts);

                let mut cold_single = before.clone();
                let history = cold_single.facts.values().cloned().collect::<Vec<_>>();
                cold_single.retire_cold_history();
                assert!(cold_single.facts.len() < history.len());
                let cold_before = graph_snapshot(&cold_single);
                for terminal in 0..3 {
                    let journal = cold_single
                        .admit_journaled_with_history(order[1].clone(), history.clone())
                        .expect("same concurrent second input admits with retired causal history");
                    assert_eq!(journal.admission(), &Admission::Inserted);
                    assert_eq!(journal.delta().rows().len(), 1);
                    assert_eq!(journal.delta().rows()[0].fact().id, order[1].id);
                    assert_candidate_noop_projection(journal.graph(), &expected);
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&cold_single, &cold_before);
                    }
                }
                assert_eq!(cold_single.len(), direct.len());
                assert_eq!(cold_single.projection(), expected);
                assert_eq!(
                    cold_single.projection_commitment_root(),
                    expected.commitment_root()
                );

                for hydrated in [false, true] {
                    let history = base.facts.values().cloned().collect::<Vec<_>>();
                    let mut aggregate = base.clone();
                    if hydrated {
                        aggregate.retire_cold_history();
                        assert!(aggregate.facts.len() < history.len());
                    }
                    aggregate.projection();
                    let before = graph_snapshot(&aggregate);
                    for terminal in 0..3 {
                        let journal = if hydrated {
                            aggregate
                                .admit_journaled_batch_with_history(order.clone(), history.clone())
                        } else {
                            aggregate.admit_journaled_batch(order.clone())
                        }
                        .expect("same concurrent inputs admit atomically");
                        for (result, candidate) in journal.results().iter().zip(&order) {
                            assert!(
                                matches!(result.outcome(), AggregateAdmissionOutcome::Inserted { fact_id }
                                if *fact_id == candidate.id)
                            );
                        }
                        assert_eq!(journal.results().len(), 2);
                        assert_eq!(journal.delta().rows().len(), 2);
                        assert!(journal
                            .delta()
                            .rows()
                            .iter()
                            .all(|row| row.status() == SemanticFactStatus::Admitted));
                        assert_eq!(
                            journal
                                .delta()
                                .rows()
                                .iter()
                                .map(|row| row.fact().id)
                                .collect::<BTreeSet<_>>(),
                            order.iter().map(|fact| fact.id).collect::<BTreeSet<_>>()
                        );
                        assert!(journal.delta().promoted().is_empty());
                        assert!(journal.delta().removed().is_empty());
                        assert_candidate_noop_projection(journal.graph(), &expected);
                        match terminal {
                            0 => journal.rollback(),
                            1 => drop(journal),
                            _ => journal.commit(),
                        }
                        if terminal < 2 {
                            assert_graph_state_eq(&aggregate, &before);
                        }
                    }
                    assert_eq!(aggregate.len(), direct.len());
                    assert_eq!(aggregate.projection(), expected);
                    assert_eq!(
                        aggregate.projection_commitment_root(),
                        expected.commitment_root()
                    );
                }

                let mut waiting = eligible.clone();
                for candidate in &order {
                    let missing = dependencies(candidate)
                        .into_iter()
                        .filter(|id| !waiting.facts.contains_key(id))
                        .collect::<BTreeSet<_>>();
                    assert!(!missing.is_empty());
                    assert!(
                        matches!(waiting.admit(candidate.clone()), Ok(Admission::Quarantined { missing: actual })
                        if actual.iter().copied().collect::<BTreeSet<_>>() == missing)
                    );
                }
                let mut retry_single = waiting.clone();
                for support in &supports[..supports.len() - 1] {
                    assert_eq!(retry_single.admit(support.clone()), Ok(Admission::Inserted));
                }
                retry_single.projection();
                let retry_before = graph_snapshot(&retry_single);
                for terminal in 0..3 {
                    let journal = retry_single
                        .admit_journaled(supports.last().unwrap().clone())
                        .expect("late support retries both concurrent operations");
                    assert_eq!(journal.admission(), &Admission::Inserted);
                    assert_eq!(
                        journal
                            .delta()
                            .promoted()
                            .iter()
                            .copied()
                            .collect::<BTreeSet<_>>(),
                        pair.iter().map(|fact| fact.id).collect::<BTreeSet<_>>()
                    );
                    assert!(journal.delta().removed().is_empty());
                    assert_candidate_noop_projection(journal.graph(), &expected);
                    match terminal {
                        0 => journal.rollback(),
                        1 => drop(journal),
                        _ => journal.commit(),
                    }
                    if terminal < 2 {
                        assert_graph_state_eq(&retry_single, &retry_before);
                    }
                }
                assert_eq!(retry_single.facts, direct.facts);

                let mut retry_aggregate = waiting.clone();
                let journal = retry_aggregate
                    .admit_journaled_batch(supports.clone())
                    .expect("aggregate support delivery attributes both ready promotions");
                assert_eq!(
                    journal
                        .delta()
                        .promoted()
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>(),
                    pair.iter().map(|fact| fact.id).collect::<BTreeSet<_>>()
                );
                assert!(journal.delta().removed().is_empty());
                assert_candidate_noop_projection(journal.graph(), &expected);
                journal.commit();
                assert_eq!(retry_aggregate.facts, direct.facts);
                for support in &supports {
                    assert_eq!(waiting.admit(support.clone()), Ok(Admission::Inserted));
                }
                assert_eq!(
                    waiting
                        .retry_quarantined()
                        .unwrap()
                        .into_iter()
                        .collect::<BTreeSet<_>>(),
                    pair.iter().map(|fact| fact.id).collect::<BTreeSet<_>>()
                );
                assert!(waiting.quarantined.is_empty());
                assert_eq!(waiting.facts, direct.facts);
                assert_candidate_noop_projection(&waiting, &expected);
            }

            let mut intrinsic_base = base.clone();
            assert_eq!(
                intrinsic_base.admit(pair[0].clone()),
                Ok(Admission::Inserted)
            );
            let redundant =
                witnessed_fact(&intrinsic_base, &right_key, pair[0].content.body.clone());
            assert_ne!(redundant.id, pair[0].id);
            assert_intrinsic_noop_unchanged(
                &intrinsic_base,
                &redundant,
                match kind {
                    0 => "role grant already effective",
                    1 => "role revoke targets an absent role",
                    _ => "resolution has no live conflict",
                },
            );
            if kind == 2 {
                let typed = witnessed_fact(
                    &base,
                    &root_key,
                    FactBody::AuthorityLineageResolution {
                        subject: target.clone(),
                        cited_heads: heads.clone(),
                        selected_head: heads[0],
                    },
                );
                assert_eq!(base.admit(typed), Ok(Admission::Inserted));
                assert!(!base
                    .evaluator()
                    .is_conflicted(&ExclusiveCell::role(target.clone())));
                let suppressed = witnessed_fact(&base, &right_key, pair[0].content.body.clone());
                assert_intrinsic_noop_unchanged(
                    &base,
                    &suppressed,
                    "resolution has no live conflict",
                );
            }
        }
    }

    #[test]
    fn journal_rolls_back_only_touched_rows_and_bounds_ready_promotions() {
        let (bootstrap, root_key) = closed(74);
        let target = device(&key(75));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let first_child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let second_child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke { target },
            vec![parent.id],
        );
        let policy = SemanticAdmissionPolicy {
            max_ready_batch: 2,
            ..SemanticAdmissionPolicy::default()
        };
        let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        assert!(matches!(
            graph.admit(first_child),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            graph.admit(second_child),
            Ok(Admission::Quarantined { .. })
        ));
        assert_eq!(graph.len(), 0);
        assert_eq!(graph.quarantined().count(), 2);
        let preflight = graph.preflight_admission(&parent).unwrap();
        assert_eq!(preflight.admission(), &Admission::Inserted);
        assert!(preflight.encoded_bytes().is_some());
        let before_rollback = graph.clone();

        let journal = graph
            .apply_preflight_journaled(parent.clone(), preflight)
            .expect("parent and one bounded ready batch admit");
        assert_eq!(journal.admission(), &Admission::Inserted);
        assert_eq!(journal.delta().promoted().len(), 2);
        assert_eq!(journal.delta().rows().len(), 3);
        assert_eq!(journal.delta().provisional_removed().len(), 2);
        assert!(journal.delta().provisional_added().is_empty());
        assert!(journal.delta().removed().is_empty());
        let changed_ids = journal.delta().changed_ids().collect::<BTreeSet<_>>();
        assert_eq!(changed_ids.len(), journal.delta().changed_ids().count());
        assert!(journal.delta().rows().len() <= 3);
        assert!(journal.delta().promoted().len() <= 2);
        assert!(journal.delta().removed().len() <= 1);
        let provisional_removed = journal
            .delta()
            .provisional_removed()
            .iter()
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            provisional_removed.len(),
            journal.delta().provisional_removed().len()
        );
        assert_eq!(
            journal.delta().rows()[0].status(),
            SemanticFactStatus::Admitted
        );
        assert_eq!(journal.delta().rows()[0].fact().id, parent.id);
        journal.rollback();
        assert_eq!(graph.facts, before_rollback.facts);
        assert_eq!(graph.quarantined, before_rollback.quarantined);
        assert_eq!(graph.policy_limits, before_rollback.policy_limits);
        assert_eq!(graph.admitted_bytes, before_rollback.admitted_bytes);
        assert_eq!(
            graph.derived_index_bytes,
            before_rollback.derived_index_bytes
        );
        assert_eq!(graph.quarantined_bytes, before_rollback.quarantined_bytes);
        assert_eq!(
            graph.admitted_dependency_edges,
            before_rollback.admitted_dependency_edges
        );
        assert_eq!(
            graph.quarantined_dependency_edges,
            before_rollback.quarantined_dependency_edges
        );
        assert_eq!(
            graph.quarantined_by_author,
            before_rollback.quarantined_by_author
        );
        assert_eq!(graph.retained_by_author, before_rollback.retained_by_author);
        assert_eq!(graph.quarantine_missing, before_rollback.quarantine_missing);
        assert_eq!(
            graph.waiting_by_dependency,
            before_rollback.waiting_by_dependency
        );
        assert_eq!(graph.ready_quarantine, before_rollback.ready_quarantine);
        assert_eq!(graph.context_id, before_rollback.context_id);
        assert_eq!(graph.authority_roots, before_rollback.authority_roots);
        assert_eq!(graph.policy, before_rollback.policy);

        graph.policy_limits.max_ready_batch = 1;
        let before_capacity = graph_snapshot(&graph);
        let preflight = graph.preflight_admission(&parent).unwrap();
        assert!(matches!(
            graph.apply_preflight_journaled(parent.clone(), preflight),
            Err(SemanticError::CapacityExceeded {
                dimension: super::super::SemanticCapacityDimension::ReadyBatch,
                ..
            })
        ));
        assert_graph_state_eq(&graph, &before_capacity);
        graph.policy_limits.max_ready_batch = 2;

        // Dropping an unconsumed journal has the same exact rollback effect.
        let journal = graph
            .admit_journaled(parent.clone())
            .expect("parent and both bounded ready waiters admit");
        assert_eq!(journal.graph().len(), 3);
        drop(journal);
        assert_eq!(graph.len(), 0);
        assert_eq!(graph.quarantined().count(), 2);

        let journal = graph
            .admit_journaled(parent)
            .expect("repeat parent and both bounded ready waiters admit");
        journal.commit();
        assert_eq!(graph.len(), 3);
        assert_eq!(graph.quarantined().count(), 0);
    }

    #[test]
    fn journal_retries_transitive_waiters_with_one_cumulative_bound() {
        let (bootstrap, root_key) = closed(173);
        let target = device(&key(174));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let grandchild = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Owner,
            },
            vec![child.id],
        );
        let policy = SemanticAdmissionPolicy {
            max_ready_batch: 2,
            ..SemanticAdmissionPolicy::default()
        };
        let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
        assert!(matches!(
            graph.admit(grandchild.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            graph.admit(child.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        let before = graph_snapshot(&graph);
        let preflight = graph.preflight_admission(&parent).unwrap();
        let journal = graph
            .apply_preflight_journaled(parent.clone(), preflight)
            .expect("parent admits both generations within one retry envelope");
        assert_eq!(journal.delta().promoted(), &[child.id, grandchild.id]);
        assert_eq!(journal.delta().rows().len(), 3);
        assert!(journal.graph().get(&grandchild.id).is_some());
        journal.commit();

        let mut reference = FactGraph::from_bootstrap_with_policy(
            &bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 2,
                ..SemanticAdmissionPolicy::default()
            },
        );
        assert!(matches!(
            reference.admit(grandchild.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            reference.admit(child.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        reference.admit(parent.clone()).unwrap();
        reference.retry_quarantined().unwrap();
        assert_graph_state_eq(&graph, &reference);

        let mut dropped = before.clone();
        let preflight = dropped.preflight_admission(&parent).unwrap();
        let journal = dropped
            .apply_preflight_journaled(parent.clone(), preflight)
            .expect("rollback control reaches transitive promotion");
        drop(journal);
        assert_graph_state_eq(&dropped, &before);

        let mut explicitly_rolled_back = before.clone();
        let preflight = explicitly_rolled_back.preflight_admission(&parent).unwrap();
        let journal = explicitly_rolled_back
            .apply_preflight_journaled(parent.clone(), preflight)
            .expect("explicit rollback control reaches transitive promotion");
        assert_eq!(journal.delta().promoted(), &[child.id, grandchild.id]);
        journal.rollback();
        assert_graph_state_eq(&explicitly_rolled_back, &before);

        let mut too_small = before.clone();
        too_small.policy_limits.max_ready_batch = 1;
        let before_refusal = graph_snapshot(&too_small);
        let preflight = too_small.preflight_admission(&parent).unwrap();
        assert!(matches!(
            too_small.apply_preflight_journaled(parent, preflight),
            Err(SemanticError::CapacityExceeded {
                dimension: super::super::SemanticCapacityDimension::ReadyBatch,
                ..
            })
        ));
        assert_graph_state_eq(&too_small, &before_refusal);
    }

    #[test]
    fn preflight_token_rejects_changed_fact_and_stale_graph() {
        let (bootstrap, root_key) = closed(175);
        let candidate = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(176)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let preflight = graph
            .preflight_admission(&candidate)
            .expect("candidate preflight succeeds");

        let mut changed = candidate.clone();
        changed.signature = "tampered".to_owned();
        assert!(graph.apply_preflight_journaled(changed, preflight).is_err());
        assert!(graph.facts.is_empty());

        let stale = graph
            .preflight_admission(&candidate)
            .expect("candidate can be preflighted again");
        graph
            .admit(fact(
                &bootstrap,
                &root_key,
                FactBody::RoleGrant {
                    target: device(&key(177)),
                    role: Role::Member,
                },
                Vec::new(),
            ))
            .expect("unrelated fact advances the graph fence");
        assert!(graph.apply_preflight_journaled(candidate, stale).is_err());
    }

    #[test]
    fn rollback_cache_fence_preserves_root_without_projection_map_clone() {
        let (bootstrap, root_key) = closed(178);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(179)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first).expect("initial fact admits");
        let before_root = graph.projection_commitment_root();
        let before_cache = graph
            .projection_cache
            .lock()
            .as_ref()
            .map(|(generation, projection)| (*generation, projection.commitment_root()));
        let rollback = GraphRollback::new(&graph);
        assert_eq!(rollback.projection_cache_fence, before_cache);
        drop(rollback);

        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(180)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let preflight = graph
            .preflight_admission(&second)
            .expect("sparse candidate preflights");
        let journal = graph
            .apply_preflight_journaled(second, preflight)
            .expect("sparse candidate applies");
        journal.rollback();
        assert_eq!(graph.projection_commitment_root(), before_root);
        let after_cache = graph
            .projection_cache
            .lock()
            .as_ref()
            .map(|(generation, projection)| (*generation, projection.commitment_root()));
        assert_eq!(after_cache, before_cache);
    }

    #[test]
    fn journal_records_terminal_ready_waiter_without_rolling_back_parent() {
        let (bootstrap, root_key) = closed(76);
        let target = device(&key(77));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let child_id = child.id;
        let mut graph = FactGraph::from_bootstrap_with_policy(
            &bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 1,
                ..SemanticAdmissionPolicy::default()
            },
        );
        assert!(matches!(
            graph.admit(child),
            Ok(Admission::Quarantined { .. })
        ));
        graph
            .quarantined
            .get_mut(&child_id)
            .expect("child is retained as a waiter")
            .signature = "tampered".to_owned();

        let journal = graph
            .admit_journaled(parent)
            .expect("a terminal waiter cannot cancel the valid parent");
        assert_eq!(journal.delta().removed(), &[child_id]);
        assert_eq!(journal.delta().promoted().len(), 0);
        assert_eq!(journal.delta().provisional_removed(), &[child_id]);
        assert!(journal
            .delta()
            .rows()
            .iter()
            .any(|row| row.status() == SemanticFactStatus::Admitted));
        journal.commit();
        assert_eq!(graph.len(), 1);
        assert_eq!(graph.quarantined().count(), 0);
    }

    #[test]
    fn journal_terminally_removes_member_signed_unauthorized_owner_waiter() {
        let (bootstrap, root_key) = closed(181);
        let member_key = key(182);
        let member = device(&member_key);
        let member_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: member.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let parent_target = device(&key(183));
        let parent = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: parent_target.clone(),
                role: Role::Member,
            },
            vec![member_grant.id],
            &[
                (device(&root_key), vec![member_grant.id]),
                (parent_target, Vec::new()),
            ],
        );
        let owner_target = device(&key(184));
        let waiter = fact_with_authority_predecessors(
            &bootstrap,
            &member_key,
            FactBody::RoleGrant {
                target: owner_target.clone(),
                role: Role::Owner,
            },
            vec![member_grant.id, parent.id],
            &[
                (member.clone(), vec![member_grant.id]),
                (owner_target, Vec::new()),
            ],
        );
        let waiter_id = waiter.id;
        let mut graph = FactGraph::from_bootstrap_with_policy(
            &bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 1,
                ..SemanticAdmissionPolicy::default()
            },
        );
        graph
            .admit(member_grant)
            .expect("root grants the eligible member");
        assert_eq!(
            graph.evaluator().effective_authorized_role(&member),
            Some(Role::Member)
        );
        assert!(matches!(
            graph.admit(waiter),
            Ok(Admission::Quarantined { missing }) if missing == vec![parent.id]
        ));

        graph.preflight_admission(&parent).unwrap();
        let journal = graph
            .admit_journaled(parent)
            .expect("valid parent remains admissible");
        assert_eq!(journal.delta().removed(), &[waiter_id]);
        assert!(journal.delta().promoted().is_empty());
        assert_eq!(journal.delta().provisional_removed(), &[waiter_id]);
        assert!(journal.graph().get(&waiter_id).is_none());
        journal.commit();
        assert_eq!(graph.quarantined().count(), 0);
        assert_eq!(graph.len(), 2);
    }

    #[test]
    fn candidate_authorization_taxonomy_is_role_independent() {
        let (bootstrap, root_key) = closed(185);
        let member_key = key(186);
        let member = device(&member_key);
        let controller_key = key(187);
        let controller = device(&controller_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let member_grant = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: member.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        graph
            .admit(member_grant.clone())
            .expect("member grant admits");
        let controller_grant = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
        );
        graph
            .admit(controller_grant.clone())
            .expect("controller grant admits");

        let denied = vec![
            (
                "member-controller",
                fact_with_authority_predecessors(
                    &bootstrap,
                    &member_key,
                    FactBody::RoleGrant {
                        target: device(&key(188)),
                        role: Role::Controller,
                    },
                    vec![member_grant.id],
                    &[
                        (member.clone(), vec![member_grant.id]),
                        (device(&key(188)), Vec::new()),
                    ],
                ),
            ),
            (
                "member-owner",
                fact_with_authority_predecessors(
                    &bootstrap,
                    &member_key,
                    FactBody::RoleGrant {
                        target: device(&key(189)),
                        role: Role::Owner,
                    },
                    vec![member_grant.id],
                    &[
                        (member.clone(), vec![member_grant.id]),
                        (device(&key(189)), Vec::new()),
                    ],
                ),
            ),
            (
                "controller-owner",
                fact_with_authority_predecessors(
                    &bootstrap,
                    &controller_key,
                    FactBody::RoleGrant {
                        target: device(&key(190)),
                        role: Role::Owner,
                    },
                    vec![controller_grant.id],
                    &[
                        (controller.clone(), vec![controller_grant.id]),
                        (device(&key(190)), Vec::new()),
                    ],
                ),
            ),
        ];
        for (label, candidate) in denied {
            let candidate_for_classification = candidate.clone();
            let error = graph.admit(candidate).expect_err(label);
            assert_eq!(error, SemanticError::UnauthorizedRoleGrant);
            assert!(FactGraph::is_terminal_waiter_error(
                &graph,
                &candidate_for_classification.content.body,
                &candidate_for_classification.content.author,
                &dependencies(&candidate_for_classification),
                &error,
            ));
        }

        let authorized = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: device(&key(191)),
                role: Role::Controller,
            },
            vec![controller_grant.id],
            &[
                (controller, vec![controller_grant.id]),
                (device(&key(191)), Vec::new()),
            ],
        );
        assert_eq!(graph.admit(authorized), Ok(Admission::Inserted));
    }

    #[test]
    fn journal_projection_capacity_refusal_restores_parent_and_ready_waiter() {
        let (bootstrap, root_key) = closed(189);
        let target = device(&key(190));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let mut graph = FactGraph::from_bootstrap_with_policy(
            &bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 1,
                ..SemanticAdmissionPolicy::default()
            },
        );
        graph
            .admit(child.clone())
            .expect("child is retained as a waiter");

        let parent_cost = graph.fact_cost(&parent).expect("parent cost computes");
        let parent_reserve_bound = graph
            .admitted_bytes
            .checked_add(parent_cost.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(graph.derived_index_bytes))
            .and_then(|bytes| bytes.checked_add(parent_cost.derived_index_bytes))
            .expect("parent reserve boundary remains representable");
        let mut after_parent = graph.clone();
        after_parent
            .admit(parent.clone())
            .expect("parent admits without retrying waiter");
        let parent_resident = after_parent
            .admitted_bytes
            .checked_add(after_parent.derived_index_bytes)
            .and_then(|bytes| bytes.checked_add(after_parent.projection().commitment_bytes()))
            .expect("parent resident boundary remains representable");
        let child_cost = after_parent.fact_cost(&child).expect("child cost computes");
        let child_reserve_bound = after_parent
            .admitted_bytes
            .checked_add(child_cost.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(after_parent.derived_index_bytes))
            .and_then(|bytes| bytes.checked_add(child_cost.derived_index_bytes))
            .expect("waiter reserve boundary remains representable");
        let mut after_promotion = after_parent.clone();
        after_promotion
            .retry_quarantined_batch(1, &[])
            .expect("unbounded waiter promotion succeeds");
        let promoted_resident = after_promotion
            .admitted_bytes
            .checked_add(after_promotion.derived_index_bytes)
            .and_then(|bytes| bytes.checked_add(after_promotion.projection().commitment_bytes()))
            .expect("promoted resident boundary remains representable");
        assert!(promoted_resident > parent_resident);
        assert!(promoted_resident > parent_reserve_bound);
        assert!(promoted_resident > child_reserve_bound);
        graph.policy_limits.max_database_bytes = promoted_resident - 1;
        assert!(graph.policy_limits.max_database_bytes >= parent_resident);
        assert!(graph.policy_limits.max_database_bytes >= parent_reserve_bound);
        assert!(graph.policy_limits.max_database_bytes >= child_reserve_bound);
        let before = graph_snapshot(&graph);

        let preflight = graph
            .preflight_admission(&parent)
            .expect("parent preflights before ready waiter retry");
        assert!(matches!(
            graph.apply_preflight_journaled(parent, preflight),
            Err(SemanticError::CapacityExceeded { .. })
        ));
        assert_graph_state_eq(&graph, &before);
    }

    #[test]
    fn indexed_projection_matches_reference_and_rollback_restores_indexes() {
        let (bootstrap, root_key) = closed(78);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(79)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(first)
            .expect("first indexed admission succeeds");
        assert!(graph.indexes_current());
        let indexed = graph.projection();

        let mut reference = graph.clone();
        reference.indexed_fact_count = 0;
        *reference.projection_cache.lock() = None;
        assert_eq!(indexed, Projection::from_graph(&reference));
        let reverse_before_rebuild = graph.authority_dependents_index.clone();
        let residency_before_rebuild = graph
            .authority_dependents_residency_bytes()
            .expect("reverse-index residency computes");
        let reverse_edge_count = |graph: &FactGraph| {
            graph
                .authority_dependents_index
                .values()
                .map(BTreeSet::len)
                .sum::<usize>()
        };
        let cloned = graph.clone();
        assert_eq!(
            reverse_edge_count(&cloned),
            reverse_edge_count(&graph),
            "clone preserves every funded reverse authority edge"
        );
        graph.rebuild_indexes();
        assert_eq!(
            graph.authority_dependents_index, reverse_before_rebuild,
            "rebuild preserves deterministic reverse authority cardinality"
        );
        assert_eq!(
            graph
                .authority_dependents_residency_bytes()
                .expect("rebuilt reverse-index residency computes"),
            residency_before_rebuild,
            "rebuild preserves the exact logical reverse-index charge"
        );

        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(80)),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let before = graph.clone();
        let preflight = graph
            .preflight_admission(&second)
            .expect("second admission preflight succeeds");
        let journal = graph
            .apply_preflight_journaled(second, preflight)
            .expect("second admission applies");
        journal.rollback();
        assert!(graph.indexes_current());
        assert_eq!(graph.projection(), before.projection());
        assert_eq!(graph.cell_heads_index, before.cell_heads_index);
        assert_eq!(graph.authority_heads_index, before.authority_heads_index);
        assert_eq!(
            graph.authority_dependents_index,
            before.authority_dependents_index
        );
        assert_eq!(
            graph
                .authority_dependents_residency_bytes()
                .expect("rollback reverse-index residency computes"),
            before
                .authority_dependents_residency_bytes()
                .expect("baseline reverse-index residency computes")
        );
        assert_eq!(
            graph.derived_index_bytes, before.derived_index_bytes,
            "rollback restores the exact derived logical-byte scalar"
        );
        assert_eq!(graph.dependency_index, before.dependency_index);
        assert_eq!(graph.cells_index, before.cells_index);
    }

    #[test]
    fn rebuild_reconciles_loader_mutated_scalar_accounting() {
        let (bootstrap, root_key) = closed(121);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(122)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut expected = FactGraph::from_bootstrap(&bootstrap);
        expected
            .admit(first.clone())
            .expect("first canonical row admits");
        let second = witnessed_fact(
            &expected,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(123)),
                role: Role::Controller,
            },
        );
        expected
            .admit(second.clone())
            .expect("second canonical row admits");

        let mut loaded = FactGraph::from_bootstrap(&bootstrap);
        loaded
            .admit(first)
            .expect("first canonical row admits into loader graph");
        loaded.facts.insert(second.id, second);
        loaded.facts_revision = loaded
            .facts_revision
            .checked_add(1)
            .expect("test revision remains representable");
        loaded.admitted_bytes = 0;
        loaded.derived_index_bytes = 0;
        loaded.admitted_dependency_edges = 0;
        loaded.rebuild_indexes();

        assert_eq!(loaded.admitted_bytes, expected.admitted_bytes);
        assert_eq!(loaded.derived_index_bytes, expected.derived_index_bytes);
        assert_eq!(
            loaded.admitted_dependency_edges,
            expected.admitted_dependency_edges
        );
        assert_eq!(loaded.cell_heads_index, expected.cell_heads_index);
        assert_eq!(loaded.cells_index, expected.cells_index);
        assert_eq!(loaded.projection(), expected.projection());
    }

    #[test]
    fn current_head_role_admission_uses_borrowed_causal_graph() {
        let (bootstrap, root_key) = closed(79);
        let target = device(&key(80));
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first.clone()).expect("first role admits");
        let next = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke { target },
            vec![first.id],
        );
        assert!(matches!(
            graph.causal_past(&next).expect("causal view resolves"),
            CausalAdmissionGraph::Full(_)
        ));

        let refusal_policy = SemanticAdmissionPolicy {
            max_database_bytes: 1,
            ..SemanticAdmissionPolicy::default()
        };
        let mut refused = FactGraph::from_bootstrap_with_policy(&bootstrap, refusal_policy);
        assert!(matches!(
            refused.admit(first),
            Err(SemanticError::CapacityExceeded { .. })
        ));
        assert_eq!(refused.len(), 0);
        assert_eq!(refused.derived_index_bytes, 0);
    }

    #[test]
    fn warm_current_head_admission_is_sparse_over_an_unrelated_tail() {
        let (bootstrap, root_key) = closed(201);
        let indexed_key = |index: u16| {
            let mut bytes = [0u8; 32];
            bytes[..2].copy_from_slice(&index.to_le_bytes());
            SigningKey::from_bytes(&bytes)
        };
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let mut previous_root = None;
        let tail = (0..1024u16)
            .map(|index| {
                let target = device(&indexed_key(index));
                let parents = previous_root.into_iter().collect::<Vec<_>>();
                let fact = fact_with_authority_predecessors(
                    &bootstrap,
                    &root_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                    parents.clone(),
                    &[(target, Vec::new()), (device(&root_key), parents)],
                );
                previous_root = Some(fact.id);
                fact
            })
            .collect::<Vec<_>>();
        let latest_root = tail.last().expect("tail is nonempty").id;
        graph
            .bulk_restore_admitted(tail, Vec::new())
            .expect("large unrelated tail restores");

        let target = device(&indexed_key(777));
        let previous_head = graph
            .cell_heads(&ExclusiveCell::role(target.clone()))
            .into_iter()
            .next()
            .expect("tail role head exists");
        let candidate = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Controller,
            },
            vec![previous_head, latest_root],
            &[
                (device(&root_key), vec![latest_root]),
                (target, vec![previous_head]),
            ],
        );
        let mut reference = graph.clone();
        reference
            .admit(candidate.clone())
            .expect("reference replacement admits");
        let expected_derived = reference.derived_index_bytes;

        RESIDENCY_SCAN_COUNT.with(|count| count.set(0));
        INDEX_REBUILD_COUNT.with(|count| count.set(0));
        graph
            .admit(candidate)
            .expect("warm current-head replacement admits");
        assert_eq!(
            RESIDENCY_SCAN_COUNT.with(Cell::get),
            0,
            "warm admission must not rescan all derived indexes"
        );
        assert_eq!(
            INDEX_REBUILD_COUNT.with(Cell::get),
            0,
            "warm admission must not rebuild unrelated indexes"
        );
        assert_eq!(graph.derived_index_bytes, expected_derived);
        assert_eq!(
            graph.derived_index_bytes,
            graph
                .logical_index_residency_bytes()
                .expect("full residency reference remains representable")
        );
        assert_eq!(
            RESIDENCY_SCAN_COUNT.with(Cell::get),
            1,
            "only the explicit post-admission reference may scan"
        );
    }

    fn assert_graph_state_eq(actual: &FactGraph, expected: &FactGraph) {
        assert_eq!(actual.facts, expected.facts);
        assert_eq!(actual.quarantined, expected.quarantined);
        assert_eq!(actual.policy_limits, expected.policy_limits);
        assert_eq!(actual.admitted_fact_count, expected.admitted_fact_count);
        assert_eq!(actual.admission_order, expected.admission_order);
        assert_eq!(actual.admitted_bytes, expected.admitted_bytes);
        assert_eq!(actual.derived_index_bytes, expected.derived_index_bytes);
        assert_eq!(actual.quarantined_bytes, expected.quarantined_bytes);
        assert_eq!(
            actual.admitted_dependency_edges,
            expected.admitted_dependency_edges
        );
        assert_eq!(
            actual.quarantined_dependency_edges,
            expected.quarantined_dependency_edges
        );
        assert_eq!(actual.quarantined_by_author, expected.quarantined_by_author);
        assert_eq!(actual.retained_by_author, expected.retained_by_author);
        assert_eq!(actual.quarantine_missing, expected.quarantine_missing);
        assert_eq!(actual.waiting_by_dependency, expected.waiting_by_dependency);
        assert_eq!(actual.ready_quarantine, expected.ready_quarantine);
        assert_eq!(actual.context_id, expected.context_id);
        assert_eq!(actual.authority_roots, expected.authority_roots);
        assert_eq!(actual.policy, expected.policy);
        assert_eq!(actual.cell_heads_index, expected.cell_heads_index);
        assert_eq!(actual.authority_heads_index, expected.authority_heads_index);
        assert_eq!(
            actual.authority_dependents_index,
            expected.authority_dependents_index
        );
        assert_eq!(actual.authority_facts_index, expected.authority_facts_index);
        assert_eq!(
            actual.authority_selector_index,
            expected.authority_selector_index
        );
        assert_eq!(actual.authority_provenance, expected.authority_provenance);
        assert_eq!(actual.dependency_index, expected.dependency_index);
        assert_eq!(actual.cells_index, expected.cells_index);
        assert_eq!(actual.stand_down_index, expected.stand_down_index);
        assert_eq!(actual.indexed_fact_count, expected.indexed_fact_count);
        assert_eq!(actual.facts_revision, expected.facts_revision);
        assert_eq!(actual.indexed_revision, expected.indexed_revision);
        assert_eq!(actual.generation, expected.generation);
        assert_eq!(
            actual.defer_projection_commitment,
            expected.defer_projection_commitment
        );
        assert_eq!(
            actual.cold_history_since_retirement,
            expected.cold_history_since_retirement
        );
        assert_eq!(actual.staged_cold_pending, expected.staged_cold_pending);
        assert_eq!(
            actual.projection_cache.lock().clone(),
            expected.projection_cache.lock().clone()
        );
        assert_eq!(actual.projection(), expected.projection());
    }

    fn graph_snapshot(graph: &FactGraph) -> FactGraph {
        let snapshot = graph.clone();
        *snapshot.projection_cache.lock() = graph.projection_cache.lock().clone();
        snapshot
    }

    #[test]
    fn direct_projection_capacity_refusal_restores_exact_graph_state() {
        let (bootstrap, root_key) = closed(181);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(182)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(183)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(first).expect("first fact admits");
        let cost = graph.fact_cost(&second).expect("second cost computes");
        graph.policy_limits.max_database_bytes = graph
            .admitted_bytes
            .checked_add(cost.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(graph.derived_index_bytes))
            .and_then(|bytes| bytes.checked_add(cost.derived_index_bytes))
            .expect("pre-projection boundary remains representable");
        let before = graph_snapshot(&graph);

        assert!(matches!(
            graph.admit(second),
            Err(SemanticError::CapacityExceeded { .. })
        ));
        assert_graph_state_eq(&graph, &before);
        assert_eq!(graph.facts, before.facts);
        assert_eq!(graph.quarantined, before.quarantined);
        assert_eq!(graph.cell_heads_index, before.cell_heads_index);
        assert_eq!(graph.authority_heads_index, before.authority_heads_index);
        assert_eq!(
            graph.authority_dependents_index,
            before.authority_dependents_index
        );
        assert_eq!(
            graph.authority_selector_index,
            before.authority_selector_index
        );
        assert_eq!(graph.dependency_index, before.dependency_index);
        assert_eq!(graph.cells_index, before.cells_index);
        assert_eq!(graph.stand_down_index, before.stand_down_index);
        assert_eq!(graph.admitted_bytes, before.admitted_bytes);
        assert_eq!(graph.derived_index_bytes, before.derived_index_bytes);
        assert_eq!(graph.quarantined_bytes, before.quarantined_bytes);
        assert_eq!(
            graph.admitted_dependency_edges,
            before.admitted_dependency_edges
        );
        assert_eq!(
            graph.quarantined_dependency_edges,
            before.quarantined_dependency_edges
        );
        assert_eq!(graph.retained_by_author, before.retained_by_author);
        assert_eq!(graph.quarantined_by_author, before.quarantined_by_author);
        assert_eq!(graph.quarantine_missing, before.quarantine_missing);
        assert_eq!(graph.waiting_by_dependency, before.waiting_by_dependency);
        assert_eq!(graph.ready_quarantine, before.ready_quarantine);
        assert_eq!(graph.facts_revision, before.facts_revision);
        assert_eq!(graph.indexed_revision, before.indexed_revision);
        assert_eq!(graph.indexed_fact_count, before.indexed_fact_count);
        assert_eq!(graph.generation, before.generation);
        assert_eq!(graph.projection(), before.projection());
    }

    #[test]
    fn bulk_restore_error_restores_the_committed_prefix() {
        let (bootstrap, root_key) = closed(184);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(185)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let mut after_first = graph.clone();
        after_first
            .admit(first.clone())
            .expect("first prefix fact admits");
        let second = witnessed_fact(
            &after_first,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(186)),
                role: Role::Member,
            },
        );
        let second_cost = after_first
            .fact_cost(&second)
            .expect("second cost computes");
        let reserve_bound = after_first
            .admitted_bytes
            .checked_add(second_cost.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(after_first.derived_index_bytes))
            .and_then(|bytes| bytes.checked_add(second_cost.derived_index_bytes))
            .expect("pre-projection capacity boundary remains representable");
        let mut after_second = after_first.clone();
        after_second
            .admit(second.clone())
            .expect("unbounded second fact admits");
        let post_second_resident = after_second
            .admitted_bytes
            .checked_add(after_second.derived_index_bytes)
            .and_then(|bytes| bytes.checked_add(after_second.projection().commitment_bytes()))
            .expect("post-mutation capacity remains representable");
        assert!(post_second_resident > reserve_bound);
        assert!(post_second_resident > after_first.admitted_bytes);
        graph.policy_limits.max_database_bytes = post_second_resident - 1;
        assert!(graph.policy_limits.max_database_bytes >= reserve_bound);
        let before = graph_snapshot(&graph);

        assert!(matches!(
            graph.bulk_restore_admitted(vec![first, second], Vec::new()),
            Err(SemanticError::CapacityExceeded { .. })
        ));
        assert_graph_state_eq(&graph, &before);
        assert_eq!(graph.facts, before.facts);
        assert_eq!(graph.cell_heads_index, before.cell_heads_index);
        assert_eq!(graph.authority_heads_index, before.authority_heads_index);
        assert_eq!(graph.dependency_index, before.dependency_index);
        assert_eq!(graph.admitted_bytes, before.admitted_bytes);
        assert_eq!(graph.derived_index_bytes, before.derived_index_bytes);
        assert_eq!(graph.facts_revision, before.facts_revision);
        assert_eq!(graph.generation, before.generation);
        assert_eq!(graph.projection(), before.projection());
    }

    #[test]
    fn retry_projection_capacity_refusal_restores_quarantine_and_waiters() {
        let (bootstrap, root_key) = closed(186);
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(187)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut witness_graph = FactGraph::from_bootstrap(&bootstrap);
        witness_graph
            .admit(parent.clone())
            .expect("witness parent admits");
        let child = witnessed_fact(
            &witness_graph,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(188)),
                role: Role::Member,
            },
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph
            .admit(child.clone())
            .expect("child is retained as a waiter");
        graph.admit(parent).expect("parent admits");
        let cost = graph.fact_cost(&child).expect("ready child cost computes");
        let reserve_bound = graph
            .admitted_bytes
            .checked_add(cost.encoded_bytes)
            .and_then(|bytes| bytes.checked_add(graph.derived_index_bytes))
            .and_then(|bytes| bytes.checked_add(cost.derived_index_bytes))
            .expect("retry pre-projection boundary remains representable");
        let mut after_retry = graph.clone();
        after_retry
            .retry_quarantined()
            .expect("unbounded ready child admits");
        let post_retry_resident = after_retry
            .admitted_bytes
            .checked_add(after_retry.derived_index_bytes)
            .and_then(|bytes| bytes.checked_add(after_retry.projection().commitment_bytes()))
            .expect("post-retry capacity remains representable");
        assert!(post_retry_resident > reserve_bound);
        graph.policy_limits.max_database_bytes = post_retry_resident - 1;
        assert!(graph.policy_limits.max_database_bytes >= reserve_bound);
        let before = graph_snapshot(&graph);

        assert!(matches!(
            graph.retry_quarantined(),
            Err(SemanticError::CapacityExceeded { .. })
        ));
        assert_graph_state_eq(&graph, &before);
        assert_eq!(graph.quarantined, before.quarantined);
        assert_eq!(graph.quarantine_missing, before.quarantine_missing);
        assert_eq!(graph.waiting_by_dependency, before.waiting_by_dependency);
        assert_eq!(graph.ready_quarantine, before.ready_quarantine);
        assert_eq!(graph.quarantined_bytes, before.quarantined_bytes);
        assert_eq!(graph.admitted_bytes, before.admitted_bytes);
        assert_eq!(graph.derived_index_bytes, before.derived_index_bytes);
        assert_eq!(graph.retained_by_author, before.retained_by_author);
        assert_eq!(graph.quarantined_by_author, before.quarantined_by_author);
        assert_eq!(graph.facts, before.facts);
        assert_eq!(graph.facts_revision, before.facts_revision);
        assert_eq!(graph.generation, before.generation);
        assert_eq!(graph.projection(), before.projection());
    }

    #[test]
    fn authority_impact_stays_sparse_and_matches_full_projection() {
        let (bootstrap, root_key) = closed(116);
        let root = device(&root_key);
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let mut targets = Vec::new();
        for seed in 117..137 {
            let target = device(&key(seed));
            let candidate = witnessed_fact(
                &graph,
                &root_key,
                FactBody::RoleGrant {
                    target: target.clone(),
                    role: Role::Member,
                },
            );
            let (cells, _) = graph.projection_impact_for_fact(&candidate);
            assert_eq!(
                cells.len(),
                1,
                "a current-head grant does not rescan historical authority cells"
            );
            graph.admit(candidate).expect("current-head grant admits");
            assert_eq!(graph.projection(), Projection::from_graph(&graph));
            targets.push(target);
        }

        let revoke = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleRevoke {
                target: targets[0].clone(),
            },
        );
        let (cells, _) = graph.projection_impact_for_fact(&revoke);
        assert_eq!(cells.len(), 1, "revoke impact remains cell-local");
        graph.admit(revoke).expect("member revoke admits");
        assert_eq!(graph.projection(), Projection::from_graph(&graph));

        let before = graph.projection();
        let pending = witnessed_fact(
            &graph,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(137)),
                role: Role::Member,
            },
        );
        let preflight = graph
            .preflight_admission(&pending)
            .expect("rollback candidate preflights");
        let journal = graph
            .apply_preflight_journaled(pending, preflight)
            .expect("rollback candidate applies");
        assert_eq!(journal.delta().affected_cells().len(), 1);
        journal.rollback();
        assert_eq!(graph.projection(), before);
        assert_eq!(graph.projection(), Projection::from_graph(&graph));
        assert!(graph.authority_lineage(&root).is_singular());
    }

    #[test]
    fn bulk_restore_is_deterministic_and_matches_incremental_projection() {
        let (bootstrap, root_key) = closed(80);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(81)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut incremental = FactGraph::from_bootstrap(&bootstrap);
        incremental
            .admit(first.clone())
            .expect("first incremental fact admits");
        let second_body = FactBody::RoleGrant {
            target: device(&key(82)),
            role: Role::Controller,
        };
        let second_witness = incremental.authoring_witness(&second_body, &device(&root_key));
        let second = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &incremental,
                second_body,
                &second_witness,
                std::iter::empty(),
            ),
            &root_key,
        )
        .expect("exact authoring witness signs the second fact");
        incremental
            .admit(second.clone())
            .expect("second incremental fact admits");

        let mut restored = FactGraph::from_bootstrap(&bootstrap);
        restored
            .bulk_restore_admitted(vec![second, first], Vec::new())
            .expect("bulk restore validates and orders dependencies");
        assert_eq!(restored.projection(), incremental.projection());
        assert_eq!(
            restored.projection_commitment_root(),
            incremental.projection_commitment_root()
        );
        let first_id = incremental.ids().next().copied().expect("restored fact id");
        assert_eq!(
            restored.canonical_dependency_edges(&first_id),
            incremental.canonical_dependency_edges(&first_id)
        );
    }

    #[test]
    fn canonical_dependencies_include_declared_authority_predecessors() {
        let (bootstrap, root_key) = closed(83);
        let predecessor = FactId::from_bytes([0xabu8; 32]);
        let target = device(&key(84));
        let fact = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Member,
            },
            vec![predecessor],
            &[(device(&root_key), vec![predecessor])],
        );
        assert!(dependencies(&fact).contains(&predecessor));
        let graph = FactGraph::from_bootstrap(&bootstrap);
        assert_eq!(
            graph
                .fact_cost(&fact)
                .expect("fact cost computes")
                .dependency_edges,
            dependencies(&fact).len() as u64 + fact.content.authority_uses.len() as u64,
            "canonical dependency rows and authority-use rows are each charged once"
        );
    }

    #[test]
    fn cold_history_retirement_keeps_constant_live_state_and_hydrates_exact_dependencies() {
        let (bootstrap, root_key) = closed(85);
        let author = device(&root_key);
        let target = device(&key(86));
        let mut complete = FactGraph::from_bootstrap(&bootstrap);
        let mut live = FactGraph::from_bootstrap(&bootstrap);
        let mut history = Vec::new();

        for index in 0..64 {
            let body = FactBody::RoleGrant {
                target: target.clone(),
                role: if index % 2 == 0 {
                    Role::Member
                } else {
                    Role::Controller
                },
            };
            let witness = live.authoring_witness(&body, &author);
            let fact = SignedFact::sign(
                super::super::FactContent::from_authoring_witness(
                    &live,
                    body,
                    &witness,
                    std::iter::empty(),
                ),
                &root_key,
            )
            .expect("cold-history fact signs");
            complete
                .admit(fact.clone())
                .expect("complete reference admits fact");
            live.admit(fact.clone()).expect("live graph admits fact");
            live.retire_cold_history();
            history.push(fact);

            assert_eq!(live.len(), index + 1, "logical history remains exact");
            assert_eq!(live.projection(), complete.projection());
            assert!(
                live.facts.len()
                    <= usize::try_from(live.policy_limits.max_hot_history_facts)
                        .unwrap_or(usize::MAX)
                        .saturating_add(4),
                "live continuation stays independent of total history"
            );
            assert_eq!(
                live.derived_index_bytes,
                live.logical_index_residency_bytes()
                    .expect("live index footprint is measurable"),
                "retirement accounting describes only resident indexes"
            );
        }

        let cold = history.first().expect("history has a cold row").clone();
        assert!(live.get(&cold.id).is_none(), "old row is owned by SQLite");
        let next_body = FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Member,
        };
        let next_witness = live.authoring_witness(&next_body, &author);
        let next = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &live,
                next_body,
                &next_witness,
                [cold.id],
            ),
            &root_key,
        )
        .expect("cold-dependent fact signs");
        let complete_before_next = complete.clone();
        complete
            .admit(next.clone())
            .expect("complete reference admits cold-dependent fact");
        let next_journal = live
            .admit_journaled_with_history(next, history.clone())
            .expect("durable cold dependency hydrates for admission");
        assert_eq!(
            next_journal.graph().projection(),
            complete.projection(),
            "hydrated single admission matches the complete projection before commit"
        );
        assert_eq!(
            next_journal.graph().projection_commitment_root(),
            complete.projection_commitment_root(),
            "hydrated single admission matches the complete commitment root"
        );
        let next_projection_delta = next_journal
            .delta()
            .projection_delta()
            .expect("cold-dependent admission carries a projection delta");
        let expected_next_delta = complete.projection().delta_from(
            &complete_before_next.projection(),
            complete_before_next.generation,
            complete.generation,
            next_journal.delta().affected_cells(),
            next_journal.delta().affected_subjects(),
        );
        assert_eq!(
            next_projection_delta, &expected_next_delta,
            "single hydrated delta is exact against the complete graph"
        );
        next_journal.commit();
        live.retire_cold_history();
        assert_eq!(live.len(), complete.len());
        assert_eq!(live.projection(), complete.projection());

        // An AlreadyPresent candidate may still have attached cold rows. Its
        // journal must release that overlay on both Drop and explicit
        // rollback, restoring the pre-overlay revision/index/cache fence.
        let already_before = graph_snapshot(&live);
        let already_drop = live
            .admit_journaled_with_history(cold.clone(), history.clone())
            .expect("cold duplicate preflights as AlreadyPresent");
        assert_eq!(already_drop.admission(), &Admission::AlreadyPresent);
        assert!(already_drop.graph().get(&cold.id).is_some());
        drop(already_drop);
        assert_graph_state_eq(&live, &already_before);

        let already_before = graph_snapshot(&live);
        let already_rollback = live
            .admit_journaled_with_history(cold.clone(), history.clone())
            .expect("cold duplicate preflights as AlreadyPresent");
        assert_eq!(already_rollback.admission(), &Admission::AlreadyPresent);
        already_rollback.rollback();
        assert_graph_state_eq(&live, &already_before);

        let aggregate_cold = history[2].clone();
        assert!(
            live.get(&aggregate_cold.id).is_none(),
            "aggregate hydration uses an actually retired signed row"
        );
        let aggregate_before = live.clone();
        let aggregate_body = FactBody::RoleGrant {
            target: target.clone(),
            role: Role::Controller,
        };
        let aggregate_witness = live.authoring_witness(&aggregate_body, &author);
        let aggregate_fact = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &live,
                aggregate_body,
                &aggregate_witness,
                [aggregate_cold.id],
            ),
            &root_key,
        )
        .expect("aggregate cold-dependent fact signs");
        let mut aggregate_complete = complete.clone();
        aggregate_complete
            .admit(aggregate_fact.clone())
            .expect("complete reference admits aggregate cold-dependent fact");
        let aggregate_journal = live
            .admit_journaled_batch_with_history(vec![aggregate_fact], history.clone())
            .expect("aggregate hydration admits against retired history");
        assert_eq!(
            aggregate_journal.results().len(),
            1,
            "aggregate hydration retains ordered per-input attribution"
        );
        assert!(matches!(
            aggregate_journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Inserted { .. }
        ));
        assert_eq!(
            aggregate_journal.graph().projection(),
            aggregate_complete.projection(),
            "aggregate hydration matches the complete projection before rollback"
        );
        assert_eq!(
            aggregate_journal.graph().projection_commitment_root(),
            aggregate_complete.projection_commitment_root(),
            "aggregate hydration matches the complete commitment root"
        );
        let expected_aggregate_delta = aggregate_complete.projection().delta_from(
            &aggregate_before.projection(),
            aggregate_before.generation,
            aggregate_complete.generation,
            aggregate_journal.delta().affected_cells(),
            aggregate_journal.delta().affected_subjects(),
        );
        assert_eq!(
            aggregate_journal.delta().projection_delta(),
            Some(&expected_aggregate_delta),
            "aggregate hydrated delta is exact against the complete graph"
        );
        aggregate_journal.rollback();
        assert_graph_state_eq(&live, &aggregate_before);
        assert_eq!(
            live.projection(),
            complete.projection(),
            "rollback retains the canonical projection beyond the bounded hot set"
        );

        let rollback_cold = history[1].clone();
        assert!(live.get(&rollback_cold.id).is_none());
        let before = live.clone();
        let rollback_body = FactBody::RoleGrant {
            target,
            role: Role::Controller,
        };
        let rollback_witness = live.authoring_witness(&rollback_body, &author);
        let rollback_fact = SignedFact::sign(
            super::super::FactContent::from_authoring_witness(
                &live,
                rollback_body,
                &rollback_witness,
                [rollback_cold.id],
            ),
            &root_key,
        )
        .expect("rollback fact signs");
        live.admit_journaled_with_history(rollback_fact, history)
            .expect("rollback candidate hydrates")
            .rollback();
        assert_eq!(live.len(), before.len());
        assert_eq!(live.projection(), before.projection());
        assert_eq!(live.facts, before.facts);
        assert!(
            live.get(&rollback_cold.id).is_none(),
            "rollback releases cold staging"
        );
        assert_eq!(live.retained_by_author, before.retained_by_author);
    }

    #[test]
    fn ordinary_authority_fork_invalidation_is_order_independent_and_journaled() {
        let (bootstrap, root_key) = closed(251);
        let controller_key = key(252);
        let controller = device(&controller_key);
        let other = device(&key(253));
        let grant_controller = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: controller.clone(),
                role: Role::Controller,
            },
            Vec::new(),
        );
        let grant_other = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: other.clone(),
                role: Role::Member,
            },
            vec![grant_controller.id],
            &[
                (controller.clone(), vec![grant_controller.id]),
                (other.clone(), Vec::new()),
            ],
        );
        let revoke_controller = fact_with_authority_predecessors(
            &bootstrap,
            &root_key,
            FactBody::RoleRevoke {
                target: controller.clone(),
            },
            vec![grant_controller.id],
            &[
                (device(&root_key), vec![grant_controller.id]),
                (controller.clone(), vec![grant_controller.id]),
            ],
        );
        let deeper = device(&key(254));
        let grant_deeper = fact_with_authority_predecessors(
            &bootstrap,
            &controller_key,
            FactBody::RoleGrant {
                target: deeper.clone(),
                role: Role::Member,
            },
            vec![grant_other.id],
            &[
                (controller.clone(), vec![grant_other.id]),
                (deeper.clone(), Vec::new()),
            ],
        );
        let branches = [grant_other, grant_deeper, revoke_controller];

        for reverse in [false, true] {
            let mut seeded = FactGraph::from_bootstrap(&bootstrap);
            seeded
                .admit(grant_controller.clone())
                .expect("common authority parent admits");
            let order = if reverse {
                [
                    branches[2].clone(),
                    branches[0].clone(),
                    branches[1].clone(),
                ]
            } else {
                [
                    branches[0].clone(),
                    branches[1].clone(),
                    branches[2].clone(),
                ]
            };

            let mut direct = seeded.clone();
            direct
                .admit(order[0].clone())
                .expect("first cross-cell branch admits");
            direct
                .admit(order[1].clone())
                .expect("second cross-cell branch or descendant admits");
            let impact = direct.projection_impact_for_fact(&order[2]);
            let prior_cells = [
                ExclusiveCell::role(other.clone()),
                ExclusiveCell::role(deeper.clone()),
                ExclusiveCell::role(controller.clone()),
            ];
            for prior_cell in prior_cells {
                assert!(
                    impact.0.contains(&prior_cell),
                    "ordinary fork impact retains every earlier branch cell"
                );
            }
            direct
                .admit(order[2].clone())
                .expect("third cross-cell branch admits");
            assert!(direct.get(&grant_controller.id).is_some());
            let mut expected_heads = vec![branches[1].id, branches[2].id];
            expected_heads.sort();
            assert_eq!(
                direct.authority_use_heads(&controller),
                expected_heads,
                "the unresolved authority fork retains both signed heads"
            );
            assert!(direct.projection().role_cell(&other).is_none());
            assert!(direct.projection().role_cell(&deeper).is_none());
            assert!(direct.projection().role_cell(&controller).is_none());
            assert_eq!(direct.projection(), Projection::from_graph(&direct));

            let mut journaled = seeded;
            journaled
                .admit(order[0].clone())
                .expect("journal first branch admits");
            journaled
                .admit(order[1].clone())
                .expect("journal second branch or descendant admits");
            let before_second = graph_snapshot(&journaled);
            let preflight = journaled
                .preflight_admission(&order[2])
                .expect("third branch preflights");
            let journal = journaled
                .apply_preflight_journaled(order[2].clone(), preflight)
                .expect("third branch journals");
            assert_eq!(
                journal.graph().projection(),
                Projection::from_graph(journal.graph())
            );
            for prior_cell in [
                ExclusiveCell::role(other.clone()),
                ExclusiveCell::role(deeper.clone()),
                ExclusiveCell::role(controller.clone()),
            ] {
                assert!(
                    journal.delta().affected_cells().contains(&prior_cell),
                    "journal delta explicitly removes every fork branch cell"
                );
            }
            journal.rollback();
            assert_graph_state_eq(&journaled, &before_second);

            let preflight = journaled
                .preflight_admission(&order[2])
                .expect("third branch re-preflights after rollback");
            let journal = journaled
                .apply_preflight_journaled(order[2].clone(), preflight)
                .expect("third branch re-journals");
            journal.commit();
            assert_eq!(journaled.authority_use_heads(&controller), expected_heads);
            assert_eq!(journaled.projection(), direct.projection());

            let mut aggregate = FactGraph::from_bootstrap(&bootstrap);
            aggregate
                .admit(grant_controller.clone())
                .expect("aggregate common authority parent admits");
            aggregate
                .admit(order[0].clone())
                .expect("aggregate first branch admits");
            aggregate
                .admit(order[1].clone())
                .expect("aggregate second branch or descendant admits");
            let aggregate_before = graph_snapshot(&aggregate);
            let aggregate_journal = aggregate
                .admit_journaled_batch(vec![order[2].clone()])
                .expect("aggregate third branch journals");
            for prior_cell in [
                ExclusiveCell::role(other.clone()),
                ExclusiveCell::role(deeper.clone()),
                ExclusiveCell::role(controller.clone()),
            ] {
                assert!(
                    aggregate_journal
                        .delta()
                        .affected_cells()
                        .contains(&prior_cell),
                    "aggregate delta explicitly removes every fork branch cell"
                );
            }
            assert_eq!(
                aggregate_journal.graph().projection(),
                Projection::from_graph(aggregate_journal.graph())
            );
            drop(aggregate_journal);
            assert_graph_state_eq(&aggregate, &aggregate_before);
            let aggregate_journal = aggregate
                .admit_journaled_batch(vec![order[2].clone()])
                .expect("aggregate third branch re-journals");
            aggregate_journal.rollback();
            assert_graph_state_eq(&aggregate, &aggregate_before);
        }
    }

    #[test]
    fn aggregate_preplanning_work_tracks_ready_frontier_without_extra_promotion() {
        fn frontier_fixture(
            bootstrap_seed: u8,
            child_count: u8,
        ) -> (FactGraph, SignedFact, FactGraph, Vec<FactId>, Vec<FactId>) {
            let (bootstrap, root_key) = closed(bootstrap_seed);
            let root = device(&root_key);
            let policy = SemanticAdmissionPolicy {
                max_ready_batch: 1,
                ..SemanticAdmissionPolicy::default()
            };
            let mut graph = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
            let mut root_head = None;
            let mut supports = Vec::new();
            for offset in 0..child_count {
                let author_key = key(bootstrap_seed.wrapping_add(10 + offset));
                let author = device(&author_key);
                let target = device(&key(bootstrap_seed.wrapping_add(40 + offset)));
                let root_parents = root_head.into_iter().collect::<Vec<_>>();
                let author_support = fact_with_authority_predecessors(
                    &bootstrap,
                    &root_key,
                    FactBody::RoleGrant {
                        target: author.clone(),
                        role: Role::Owner,
                    },
                    root_parents.clone(),
                    &[(root.clone(), root_parents), (author.clone(), Vec::new())],
                );
                graph
                    .admit(author_support.clone())
                    .expect("support grant admits before the waiter frontier");
                root_head = Some(author_support.id);
                let target_parents = root_head.into_iter().collect::<Vec<_>>();
                let target_support = fact_with_authority_predecessors(
                    &bootstrap,
                    &root_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Member,
                    },
                    target_parents.clone(),
                    &[(root.clone(), target_parents), (target, Vec::new())],
                );
                graph
                    .admit(target_support.clone())
                    .expect("target support admits before the waiter frontier");
                root_head = Some(target_support.id);
                supports.push((author_key, author_support, target_support));
            }
            let parent_target = device(&key(bootstrap_seed.wrapping_add(1)));
            let parent_parents = root_head.into_iter().collect::<Vec<_>>();
            let parent = fact_with_authority_predecessors(
                &bootstrap,
                &root_key,
                FactBody::RoleGrant {
                    target: parent_target.clone(),
                    role: Role::Member,
                },
                parent_parents.clone(),
                &[
                    (root.clone(), parent_parents),
                    (device(&key(bootstrap_seed.wrapping_add(1))), Vec::new()),
                ],
            );
            let mut children = Vec::new();
            for (author_key, author_support, target_support) in &supports {
                let author = device(author_key);
                let target = match &target_support.content.body {
                    FactBody::RoleGrant { target, .. } => target.clone(),
                    _ => unreachable!("target support is a role grant"),
                };
                let child = fact_with_authority_predecessors(
                    &bootstrap,
                    author_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Controller,
                    },
                    vec![parent.id, author_support.id, target_support.id],
                    &[
                        (author.clone(), vec![author_support.id]),
                        (target, vec![target_support.id]),
                    ],
                );
                children.push(child);
            }
            let mut grandchildren = Vec::new();
            for (offset, child) in children.iter().enumerate() {
                let (author_key, _, target_support) = &supports[offset];
                let target = match &target_support.content.body {
                    FactBody::RoleGrant { target, .. } => target.clone(),
                    _ => unreachable!("target support is a role grant"),
                };
                let grandchild = fact_with_authority_predecessors(
                    &bootstrap,
                    author_key,
                    FactBody::RoleGrant {
                        target: target.clone(),
                        role: Role::Owner,
                    },
                    vec![child.id],
                    &[
                        (device(author_key), vec![child.id]),
                        (target, vec![child.id]),
                    ],
                );
                grandchildren.push(grandchild);
            }
            let trigger = fact_with_authority_predecessors(
                &bootstrap,
                &root_key,
                FactBody::RoleGrant {
                    target: device(&key(bootstrap_seed.wrapping_add(100))),
                    role: Role::Member,
                },
                vec![parent.id],
                &[
                    (root.clone(), vec![parent.id]),
                    (device(&key(bootstrap_seed.wrapping_add(100))), Vec::new()),
                ],
            );

            // Prove the exact signed rows are dependency-valid before placing
            // the same rows into the intentionally incomplete quarantine graph.
            let mut reference = FactGraph::from_bootstrap_with_policy(&bootstrap, policy);
            for (_, author_support, target_support) in &supports {
                assert_eq!(
                    reference.admit(author_support.clone()),
                    Ok(Admission::Inserted)
                );
                assert_eq!(
                    reference.admit(target_support.clone()),
                    Ok(Admission::Inserted)
                );
            }
            assert_eq!(reference.admit(parent.clone()), Ok(Admission::Inserted));
            for child in &children {
                assert_eq!(reference.admit(child.clone()), Ok(Admission::Inserted));
            }
            for grandchild in &grandchildren {
                assert_eq!(reference.admit(grandchild.clone()), Ok(Admission::Inserted));
            }
            assert_eq!(reference.admit(trigger.clone()), Ok(Admission::Inserted));

            for child in &children {
                assert!(matches!(
                    graph.admit(child.clone()),
                    Ok(Admission::Quarantined { .. })
                ));
            }
            for grandchild in &grandchildren {
                assert!(matches!(
                    graph.admit(grandchild.clone()),
                    Ok(Admission::Quarantined { .. })
                ));
            }
            graph
                .admit(parent.clone())
                .expect("parent admits one ready child");
            assert_eq!(
                graph.ready_quarantine.len(),
                usize::from(child_count),
                "admit wakes the full frontier; journaled apply enforces the promotion bound"
            );
            let child_ids = children.iter().map(|child| child.id).collect();
            let grandchild_ids = grandchildren.iter().map(|fact| fact.id).collect();
            (graph, trigger, reference, child_ids, grandchild_ids)
        }

        let (mut small, small_trigger, small_reference, small_children, small_grandchildren) =
            frontier_fixture(197, 2);
        let (
            mut expanded,
            expanded_trigger,
            _expanded_reference,
            _expanded_children,
            _expanded_grandchildren,
        ) = frontier_fixture(217, 8);
        let small_before = graph_snapshot(&small);
        let expanded_before = graph_snapshot(&expanded);

        reset_graph_work();
        // End the journal-bearing Result's drop scope before borrowing the graph again.
        {
            let small_result = small.admit_journaled_batch(vec![small_trigger.clone()]);
            match small_result {
                Err(error) => assert!(
                    matches!(
                        &error,
                        SemanticError::CapacityExceeded {
                            dimension: super::super::SemanticCapacityDimension::ReadyBatch,
                            ..
                        }
                    ),
                    "small frontier returned unexpected error: {error:?}"
                ),
                Ok(journal) => {
                    let outcomes = journal
                        .results()
                        .iter()
                        .map(|result| format!("{:?}", result.outcome()))
                        .collect::<Vec<_>>();
                    panic!(
                    "small frontier unexpectedly succeeded: outcomes={outcomes:?} ready={} rows={} promoted={} removed={}",
                    journal.graph().ready_quarantine.len(),
                    journal.delta().rows().len(),
                    journal.delta().promoted().len(),
                    journal.delta().removed().len(),
                );
                }
            }
        }
        let small_work = graph_work();
        assert!(small_work.aggregate_ready_entries > 0);
        assert!(small_work.aggregate_waiter_edges > 0);
        assert!(small_work.aggregate_waiter_nodes > 0);

        reset_graph_work();
        {
            let expanded_result = expanded.admit_journaled_batch(vec![expanded_trigger]);
            match expanded_result {
                Err(error) => assert!(
                    matches!(
                        &error,
                        SemanticError::CapacityExceeded {
                            dimension: super::super::SemanticCapacityDimension::ReadyBatch,
                            ..
                        }
                    ),
                    "expanded frontier returned unexpected error: {error:?}"
                ),
                Ok(journal) => {
                    let outcomes = journal
                        .results()
                        .iter()
                        .map(|result| format!("{:?}", result.outcome()))
                        .collect::<Vec<_>>();
                    panic!(
                    "expanded frontier unexpectedly succeeded: outcomes={outcomes:?} ready={} rows={} promoted={} removed={}",
                    journal.graph().ready_quarantine.len(),
                    journal.delta().rows().len(),
                    journal.delta().promoted().len(),
                    journal.delta().removed().len(),
                );
                }
            }
        }
        let expanded_work = graph_work();
        assert!(expanded_work.aggregate_ready_entries > small_work.aggregate_ready_entries);
        assert!(expanded_work.aggregate_waiter_edges >= small_work.aggregate_waiter_edges);
        assert!(expanded_work.aggregate_waiter_nodes >= small_work.aggregate_waiter_nodes);

        assert_graph_state_eq(&small, &small_before);
        assert_graph_state_eq(&expanded, &expanded_before);
        assert_eq!(small.projection(), Projection::from_graph(&small));
        assert_eq!(expanded.projection(), Projection::from_graph(&expanded));

        small.policy_limits.max_ready_batch = 4;
        let sufficient_before = graph_snapshot(&small);
        let small_trigger_id = small_trigger.id;
        reset_graph_work();
        let sufficient_journal = small
            .admit_journaled_batch(vec![small_trigger.clone()])
            .expect("sufficient canonical retry envelope reaches its fixed point");
        assert!(matches!(
            sufficient_journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == small_trigger_id
        ));
        let expected_promoted = small_children
            .iter()
            .chain(&small_grandchildren)
            .copied()
            .collect::<BTreeSet<_>>();
        assert_eq!(
            sufficient_journal.results()[0]
                .delta()
                .promoted()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected_promoted
        );
        assert_eq!(
            sufficient_journal
                .delta()
                .promoted()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected_promoted
        );
        assert!(sufficient_journal.results()[0].delta().removed().is_empty());
        assert!(sufficient_journal.delta().removed().is_empty());
        assert_eq!(sufficient_journal.results()[0].delta().promoted().len(), 4);
        assert_eq!(sufficient_journal.delta().promoted().len(), 4);
        for delta in [
            sufficient_journal.results()[0].delta(),
            sufficient_journal.delta(),
        ] {
            assert_eq!(delta.rows().len(), 5);
            assert!(delta
                .rows()
                .iter()
                .all(|row| row.status() == SemanticFactStatus::Admitted));
        }
        assert_eq!(sufficient_journal.graph().quarantined().count(), 0);
        let admitted_rows = sufficient_journal.results()[0]
            .delta()
            .rows()
            .iter()
            .map(|row| row.fact().id)
            .collect::<BTreeSet<_>>();
        let mut expected_rows = expected_promoted.clone();
        expected_rows.insert(small_trigger_id);
        assert_eq!(admitted_rows, expected_rows);
        let aggregate_rows = sufficient_journal
            .delta()
            .rows()
            .iter()
            .map(|row| row.fact().id)
            .collect::<BTreeSet<_>>();
        assert_eq!(aggregate_rows, expected_rows);
        assert_eq!(
            sufficient_journal.graph().projection(),
            small_reference.projection()
        );
        assert_eq!(
            sufficient_journal.graph().projection_commitment_root(),
            small_reference.projection_commitment_root()
        );
        sufficient_journal.rollback();
        assert_graph_state_eq(&small, &sufficient_before);

        let mut dropped = sufficient_before.clone();
        let drop_journal = dropped
            .admit_journaled_batch(vec![small_trigger.clone()])
            .expect("drop control reaches the same transitive fixed point");
        assert_eq!(
            drop_journal.results()[0]
                .delta()
                .promoted()
                .iter()
                .copied()
                .collect::<BTreeSet<_>>(),
            expected_promoted
        );
        drop(drop_journal);
        assert_graph_state_eq(&dropped, &sufficient_before);
    }

    #[test]
    fn aggregate_ready_leaf_rollback_and_drop_preserve_seed_ownership() {
        // A ready leaf has no descendant waiter through which rollback could
        // discover its preimage. Exercise both promotion and terminal removal
        // from the same exact ready-leaf baseline.
        let (leaf_bootstrap, leaf_root_key) = closed(247);
        let leaf_parent_target = device(&key(248));
        let leaf_parent = fact(
            &leaf_bootstrap,
            &leaf_root_key,
            FactBody::RoleGrant {
                target: leaf_parent_target,
                role: Role::Member,
            },
            Vec::new(),
        );
        let leaf_target = device(&key(249));
        let leaf = fact_with_authority_predecessors(
            &leaf_bootstrap,
            &leaf_root_key,
            FactBody::RoleGrant {
                target: leaf_target.clone(),
                role: Role::Controller,
            },
            vec![leaf_parent.id],
            &[
                (device(&leaf_root_key), vec![leaf_parent.id]),
                (leaf_target, Vec::new()),
            ],
        );
        let leaf_id = leaf.id;
        let leaf_trigger = fact_with_authority_predecessors(
            &leaf_bootstrap,
            &leaf_root_key,
            FactBody::RoleGrant {
                target: device(&key(250)),
                role: Role::Member,
            },
            vec![leaf_parent.id],
            &[
                (device(&leaf_root_key), vec![leaf_parent.id]),
                (device(&key(250)), Vec::new()),
            ],
        );
        let mut leaf_graph = FactGraph::from_bootstrap_with_policy(
            &leaf_bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 2,
                ..SemanticAdmissionPolicy::default()
            },
        );
        // Prove the exact signed rows are legal before staging a missing
        // dependency. A fresh target has no authority predecessor even though
        // the author's lineage and generic dependency cite the parent.
        let mut reference = graph_snapshot(&leaf_graph);
        for row in [&leaf_parent, &leaf, &leaf_trigger] {
            assert!(row.verify().is_ok());
            assert_eq!(reference.admit(row.clone()), Ok(Admission::Inserted));
        }
        // Both signed siblings are retained, but neither remains authoritative
        // after the root's fork. Recompute independently of either admission
        // cache: only their common parent's distinct role cell remains.
        let full_reference = Projection::from_graph(&reference);
        assert_eq!(reference.projection(), full_reference);
        assert_eq!(full_reference.cells().count(), 1);
        assert_eq!(
            full_reference.value(&ExclusiveCell::role(device(&key(248)))),
            Some(leaf_parent.id)
        );
        assert!(full_reference.role_cell(&device(&key(249))).is_none());
        assert!(full_reference.role_cell(&device(&key(250))).is_none());
        let mut expected_heads = vec![leaf_id, leaf_trigger.id];
        expected_heads.sort();
        assert_eq!(
            reference.authority_use_heads(&device(&leaf_root_key)),
            expected_heads
        );
        assert!(matches!(
            leaf_graph.admit(leaf),
            Ok(Admission::Quarantined { .. })
        ));
        assert_eq!(
            leaf_graph.admit(leaf_parent.clone()),
            Ok(Admission::Inserted)
        );
        assert_eq!(
            leaf_graph
                .ready_quarantine
                .iter()
                .copied()
                .collect::<Vec<_>>(),
            [leaf_id]
        );
        let leaf_before = graph_snapshot(&leaf_graph);

        let mut leaf_promoted = leaf_before.clone();
        let leaf_journal = leaf_promoted
            .admit_journaled_batch(vec![leaf_trigger.clone()])
            .expect("ready leaf promotion remains bounded");
        assert_eq!(leaf_journal.results()[0].delta().promoted(), &[leaf_id]);
        assert!(leaf_journal.results()[0].delta().removed().is_empty());
        assert_eq!(leaf_journal.delta().promoted(), &[leaf_id]);
        let full_journal = Projection::from_graph(leaf_journal.graph());
        assert_eq!(full_journal, full_reference);
        assert_eq!(leaf_journal.graph().projection(), full_journal);
        assert_eq!(
            leaf_journal.graph().ids().copied().collect::<BTreeSet<_>>(),
            [leaf_parent.id, leaf_id, leaf_trigger.id]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert_eq!(
            leaf_journal.graph().projection_commitment_root(),
            full_journal.commitment_root()
        );
        leaf_journal.rollback();
        assert_graph_state_eq(&leaf_promoted, &leaf_before);

        let mut leaf_dropped = leaf_before.clone();
        let leaf_journal = leaf_dropped
            .admit_journaled_batch(vec![leaf_trigger.clone()])
            .expect("ready leaf Drop control remains bounded");
        assert_eq!(leaf_journal.results()[0].delta().promoted(), &[leaf_id]);
        assert_eq!(Projection::from_graph(leaf_journal.graph()), full_reference);
        assert_eq!(leaf_journal.graph().projection(), full_reference);
        drop(leaf_journal);
        assert_graph_state_eq(&leaf_dropped, &leaf_before);

        let mut terminal_leaf = leaf_before.clone();
        let original_cost = terminal_leaf
            .fact_encoded_and_edges(terminal_leaf.quarantined.get(&leaf_id).unwrap())
            .expect("original ready leaf cost is measurable");
        {
            let waiter = terminal_leaf
                .quarantined
                .get_mut(&leaf_id)
                .expect("ready leaf remains quarantined before retry");
            let replacement = if waiter.signature.starts_with('a') {
                "b"
            } else {
                "a"
            };
            waiter.signature.replace_range(..1, replacement);
            assert!(matches!(
                waiter.verify(),
                Err(SemanticError::InvalidSignature)
            ));
        }
        assert_eq!(
            terminal_leaf
                .fact_encoded_and_edges(terminal_leaf.quarantined.get(&leaf_id).unwrap())
                .expect("tampered ready leaf cost is measurable"),
            original_cost,
            "terminal corruption preserves the exact funded cost"
        );
        let terminal_before = graph_snapshot(&terminal_leaf);
        let terminal_journal = terminal_leaf
            .admit_journaled_batch(vec![leaf_trigger.clone()])
            .expect("terminal ready leaf removal remains bounded");
        assert!(terminal_journal.results()[0].delta().promoted().is_empty());
        assert_eq!(terminal_journal.results()[0].delta().removed(), &[leaf_id]);
        assert_eq!(terminal_journal.delta().removed(), &[leaf_id]);
        terminal_journal.rollback();
        assert_graph_state_eq(&terminal_leaf, &terminal_before);

        let mut terminal_dropped = terminal_before.clone();
        let terminal_journal = terminal_dropped
            .admit_journaled_batch(vec![leaf_trigger])
            .expect("terminal ready leaf Drop control remains bounded");
        assert_eq!(terminal_journal.results()[0].delta().removed(), &[leaf_id]);
        drop(terminal_journal);
        assert_graph_state_eq(&terminal_dropped, &terminal_before);
    }

    #[test]
    fn aggregate_retry_budget_is_cumulative_across_inputs() {
        let (bootstrap, root_key) = closed(228);
        let target_a = device(&key(229));
        let target_b = device(&key(230));
        let parent_a = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target_a.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let parent_b = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target_b.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child_a = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target_a,
                role: Role::Controller,
            },
            vec![parent_a.id],
        );
        let terminal_a = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(229)),
                role: Role::Owner,
            },
            vec![parent_a.id],
        );
        let child_b = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target_b,
                role: Role::Controller,
            },
            vec![parent_b.id],
        );
        let mut graph = FactGraph::from_bootstrap_with_policy(
            &bootstrap,
            SemanticAdmissionPolicy {
                max_ready_batch: 2,
                ..SemanticAdmissionPolicy::default()
            },
        );
        assert!(matches!(
            graph.admit(child_a.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            graph.admit(terminal_a.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        assert!(matches!(
            graph.admit(child_b.clone()),
            Ok(Admission::Quarantined { .. })
        ));
        for id in [child_a.id, terminal_a.id] {
            let original_cost = graph
                .fact_encoded_and_edges(graph.quarantined.get(&id).unwrap())
                .expect("original terminal waiter cost is measurable");
            {
                let waiter = graph
                    .quarantined
                    .get_mut(&id)
                    .expect("terminal waiter is quarantined");
                // Corrupt authentication without changing its funded encoded
                // size. Appending bytes would invalidate the fixture ledger.
                let replacement = if waiter.signature.starts_with('a') {
                    "b"
                } else {
                    "a"
                };
                waiter.signature.replace_range(..1, replacement);
                assert!(matches!(
                    waiter.verify(),
                    Err(SemanticError::InvalidSignature)
                ));
            }
            assert_eq!(
                graph
                    .fact_encoded_and_edges(graph.quarantined.get(&id).unwrap())
                    .expect("tampered terminal waiter cost is measurable"),
                original_cost,
                "terminal corruption preserves funded bytes and dependency edges"
            );
        }
        let before = graph_snapshot(&graph);
        assert!(matches!(
            graph.admit_journaled_batch(vec![parent_a.clone(), parent_b.clone()]),
            Err(SemanticError::CapacityExceeded {
                dimension: super::super::SemanticCapacityDimension::ReadyBatch,
                limit: 2,
                observed: 3,
            })
        ));
        assert_graph_state_eq(&graph, &before);

        // A reset-per-input implementation would incorrectly accept this
        // shape: parent A consumes two terminal waiter removals, while
        // parent B wakes one valid promotion.  The cumulative envelope must
        // account for all three retry entries and restore the outer graph.
        let mut sufficient = before.clone();
        sufficient.policy_limits.max_ready_batch = 3;
        let journal = sufficient
            .admit_journaled_batch(vec![parent_a.clone(), parent_b.clone()])
            .expect("B3 permits both terminal removals and the promotion");
        assert_eq!(journal.delta().rows().len(), 3);
        assert_eq!(journal.delta().removed().len(), 2);
        assert_eq!(journal.delta().promoted().len(), 1);
        assert!(journal.delta().removed().contains(&child_a.id));
        assert!(journal.delta().removed().contains(&terminal_a.id));
        assert!(journal.delta().promoted().contains(&child_b.id));
        assert!(journal.graph().get(&parent_a.id).is_some());
        assert!(journal.graph().get(&parent_b.id).is_some());
        assert!(journal.graph().get(&child_b.id).is_some());
        assert!(journal.graph().get(&child_a.id).is_none());
        assert!(journal.graph().get(&terminal_a.id).is_none());
        journal.commit();
        assert_eq!(sufficient.quarantined().count(), 0);

        // The aggregate journal owns the same mixed closure and must restore
        // every scalar, index, and projection on Drop.
        let mut dropped = before;
        dropped.policy_limits.max_ready_batch = 3;
        let dropped_before = graph_snapshot(&dropped);
        let journal = dropped
            .admit_journaled_batch(vec![parent_a, parent_b])
            .expect("drop control reaches the mixed retry closure");
        assert_eq!(journal.delta().removed().len(), 2);
        assert_eq!(journal.delta().promoted().len(), 1);
        drop(journal);
        assert_graph_state_eq(&dropped, &dropped_before);
    }

    #[test]
    fn aggregate_journal_is_ordered_and_isolates_input_refusal() {
        let (bootstrap, root_key) = closed(231);
        let first = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(232)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut refused = first.clone();
        refused.signature.push('x');
        let second = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(233)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let before = graph_snapshot(&graph);
        let journal = graph
            .admit_journaled_batch(vec![first.clone(), first.clone(), refused, second.clone()])
            .expect("input-local refusal does not abort valid group members");
        assert_eq!(journal.results().len(), 4);
        assert!(matches!(
            journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == first.id
        ));
        assert!(matches!(
            journal.results()[1].outcome(),
            AggregateAdmissionOutcome::AlreadyPresent { fact_id } if *fact_id == first.id
        ));
        assert!(matches!(
            journal.results()[2].outcome(),
            AggregateAdmissionOutcome::Refused {
                fact_id,
                error: SemanticError::InvalidSignature,
            } if *fact_id == first.id
        ));
        assert!(matches!(
            journal.results()[3].outcome(),
            AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == second.id
        ));
        assert_eq!(journal.delta().rows().len(), 2);
        assert!(journal.graph().get(&first.id).is_some());
        assert!(journal.graph().get(&second.id).is_some());
        journal.rollback();
        assert_graph_state_eq(&graph, &before);
    }

    #[test]
    fn aggregate_journal_evolves_graph_and_attributes_promotions() {
        let (bootstrap, root_key) = closed(234);
        let target = device(&key(235));
        let parent = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: target.clone(),
                role: Role::Member,
            },
            Vec::new(),
        );
        let child = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target,
                role: Role::Controller,
            },
            vec![parent.id],
        );
        let grandchild = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(235)),
                role: Role::Owner,
            },
            vec![child.id],
        );
        let trigger = fact(
            &bootstrap,
            &root_key,
            FactBody::RoleGrant {
                target: device(&key(236)),
                role: Role::Member,
            },
            Vec::new(),
        );
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        let aggregate_before = graph_snapshot(&graph);
        let parent_id = parent.id;
        let child_id = child.id;
        let grandchild_id = grandchild.id;
        let journal = graph
            .admit_journaled_batch(vec![grandchild.clone(), child.clone(), parent.clone()])
            .expect("bounded group admits against its evolving graph");
        assert!(matches!(
            journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Quarantined { fact_id, missing }
                if *fact_id == grandchild.id && missing == &vec![child.id]
        ));
        assert!(matches!(
            journal.results()[1].outcome(),
            AggregateAdmissionOutcome::Quarantined { fact_id, missing }
                if *fact_id == child.id && missing == &vec![parent.id]
        ));
        assert!(matches!(
            journal.results()[2].outcome(),
            AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == parent.id
        ));
        assert!(journal.results()[2].delta().promoted().contains(&child.id));
        assert!(journal.results()[2]
            .delta()
            .promoted()
            .contains(&grandchild.id));
        assert!(journal.graph().get(&grandchild.id).is_some());
        journal.commit();
        assert!(graph.get(&parent.id).is_some());
        assert!(graph.get(&child.id).is_some());
        assert!(graph.get(&grandchild.id).is_some());

        let dropped_before = aggregate_before.clone();
        let mut dropped = aggregate_before;
        let journal = dropped
            .admit_journaled_batch(vec![grandchild.clone(), child.clone(), parent.clone()])
            .expect("aggregate drop reaches transitive promotion");
        assert_eq!(journal.delta().rows().len(), 3);
        assert!(journal.delta().promoted().is_empty());
        let mut row_ids = BTreeSet::new();
        for row in journal.delta().rows() {
            assert_eq!(row.status(), SemanticFactStatus::Admitted);
            row_ids.insert(row.fact().id);
        }
        assert_eq!(
            row_ids,
            [parent_id, child_id, grandchild_id]
                .into_iter()
                .collect::<BTreeSet<_>>()
        );
        assert!(journal.results()[2].delta().promoted().contains(&child_id));
        assert!(journal.results()[2]
            .delta()
            .promoted()
            .contains(&grandchild_id));
        assert!(journal.graph().get(&parent_id).is_some());
        assert!(journal.graph().get(&child_id).is_some());
        assert!(journal.graph().get(&grandchild_id).is_some());
        drop(journal);
        assert_graph_state_eq(&dropped, &dropped_before);

        let journal = graph
            .admit_journaled_batch(vec![trigger.clone()])
            .expect("a later bounded group retries the transitive waiter");
        assert!(matches!(
            journal.results()[0].outcome(),
            AggregateAdmissionOutcome::Inserted { fact_id } if *fact_id == trigger.id
        ));
        assert!(!journal.results()[0]
            .delta()
            .promoted()
            .contains(&grandchild.id));
        assert!(journal.graph().get(&grandchild.id).is_some());
        journal.commit();
        assert!(graph.get(&grandchild.id).is_some());
    }
}
