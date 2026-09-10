//! Pure projection of the causal graph into exclusive semantic cells.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::causal::FactGraph;
use super::content::{DeviceId, Encoder, ExclusiveCell, FactBody};
use super::FactId;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CellProjection {
    Value(FactId),
    Conflict(Vec<FactId>),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandDown {
    pub target: DeviceId,
    pub proof: FactId,
}

pub(crate) type ProjectionCheckpointParts = (
    Vec<(ExclusiveCell, CellProjection)>,
    Vec<(DeviceId, StandDown)>,
);

const PROJECTION_COMMITMENT_DOMAIN: &[u8] = b"myownmesh-v4/projection-patricia-merkle/v1";

#[derive(Debug, Clone, PartialEq, Eq)]
enum MerkleNode {
    Empty {
        hash: [u8; 32],
        bytes: u64,
    },
    Leaf {
        entries: Vec<(Vec<u8>, [u8; 32])>,
        hash: [u8; 32],
        bytes: u64,
    },
    Branch {
        left: Arc<MerkleNode>,
        right: Arc<MerkleNode>,
        hash: [u8; 32],
        bytes: u64,
    },
}

impl MerkleNode {
    fn hash(&self) -> [u8; 32] {
        match self {
            Self::Empty { hash, .. } | Self::Leaf { hash, .. } | Self::Branch { hash, .. } => *hash,
        }
    }

    fn bytes(&self) -> u64 {
        match self {
            Self::Empty { bytes, .. } | Self::Leaf { bytes, .. } | Self::Branch { bytes, .. } => {
                *bytes
            }
        }
    }

    fn is_empty(&self) -> bool {
        matches!(self, Self::Empty { .. })
    }
}

fn empty_node(depth: usize) -> Arc<MerkleNode> {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_COMMITMENT_DOMAIN);
    hasher.update([b'e']);
    hasher.update((depth as u16).to_be_bytes());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    Arc::new(MerkleNode::Empty {
        hash,
        bytes: 1 + 32,
    })
}

fn leaf_node(entries: Vec<(Vec<u8>, [u8; 32])>) -> Arc<MerkleNode> {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_COMMITMENT_DOMAIN);
    hasher.update([b'l']);
    hasher.update((entries.len() as u64).to_be_bytes());
    for (key, value) in &entries {
        hasher.update((key.len() as u64).to_be_bytes());
        hasher.update(key);
        hasher.update(value);
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    let bytes = entries.iter().fold(1u64 + 32, |total, (key, _)| {
        total.checked_add(key.len() as u64 + 32).unwrap_or(u64::MAX)
    });
    Arc::new(MerkleNode::Leaf {
        entries,
        hash,
        bytes,
    })
}

fn branch_node(depth: usize, left: Arc<MerkleNode>, right: Arc<MerkleNode>) -> Arc<MerkleNode> {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_COMMITMENT_DOMAIN);
    hasher.update([b'b']);
    hasher.update((depth as u16).to_be_bytes());
    hasher.update(left.hash());
    hasher.update(right.hash());
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&hasher.finalize());
    let bytes = (1u64 + 32)
        .checked_add(left.bytes())
        .and_then(|value| value.checked_add(right.bytes()))
        .unwrap_or(u64::MAX);
    Arc::new(MerkleNode::Branch {
        left,
        right,
        hash,
        bytes,
    })
}

fn key_digest(key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PROJECTION_COMMITMENT_DOMAIN);
    hasher.update([b'k']);
    hasher.update((key.len() as u64).to_be_bytes());
    hasher.update(key);
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&hasher.finalize());
    digest
}

fn digest_bit(digest: &[u8; 32], depth: usize) -> bool {
    digest[depth / 8] & (0x80 >> (depth % 8)) != 0
}

fn update_merkle(
    node: &Arc<MerkleNode>,
    depth: usize,
    digest: &[u8; 32],
    key: Vec<u8>,
    value: Option<[u8; 32]>,
) -> Arc<MerkleNode> {
    if depth == 256 {
        let mut entries = match node.as_ref() {
            MerkleNode::Leaf { entries, .. } => entries.clone(),
            MerkleNode::Empty { .. } => Vec::new(),
            MerkleNode::Branch { .. } => Vec::new(),
        };
        match entries.binary_search_by(|(existing, _)| existing.cmp(&key)) {
            Ok(index) => match value {
                Some(value) => entries[index].1 = value,
                None => {
                    entries.remove(index);
                }
            },
            Err(index) => {
                if let Some(value) = value {
                    entries.insert(index, (key, value));
                }
            }
        }
        return if entries.is_empty() {
            empty_node(depth)
        } else {
            leaf_node(entries)
        };
    }

    let (left, right) = match node.as_ref() {
        MerkleNode::Branch { left, right, .. } => (Arc::clone(left), Arc::clone(right)),
        MerkleNode::Empty { .. } | MerkleNode::Leaf { .. } => {
            (empty_node(depth + 1), empty_node(depth + 1))
        }
    };
    let next = if digest_bit(digest, depth) {
        branch_node(
            depth,
            left,
            update_merkle(&right, depth + 1, digest, key, value),
        )
    } else {
        branch_node(
            depth,
            update_merkle(&left, depth + 1, digest, key, value),
            right,
        )
    };
    if let MerkleNode::Branch { left, right, .. } = next.as_ref() {
        if left.is_empty() && right.is_empty() {
            return empty_node(depth);
        }
    }
    next
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProjectionCommitment {
    root: Arc<MerkleNode>,
}

impl Default for ProjectionCommitment {
    fn default() -> Self {
        Self {
            root: empty_node(0),
        }
    }
}

impl ProjectionCommitment {
    fn apply(&self, key: Vec<u8>, value: Option<[u8; 32]>) -> Self {
        Self {
            root: update_merkle(&self.root, 0, &key_digest(&key), key, value),
        }
    }

    fn root(&self) -> [u8; 32] {
        self.root.hash()
    }

    fn retained_bytes(&self) -> u64 {
        self.root.bytes()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Projection {
    cells: Arc<BTreeMap<ExclusiveCell, CellProjection>>,
    stand_down: Arc<BTreeMap<DeviceId, StandDown>>,
    commitment: Arc<ProjectionCommitment>,
}

/// Exact affected-entry input for an incremental durable projection update.
/// Entries are sparse: an absent value means the prior entry was removed.
/// The generation is the graph fence that produced this delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProjectionDelta {
    pub(crate) base_generation: u64,
    pub(crate) generation: u64,
    pub(crate) base_commitment: [u8; 32],
    pub(crate) commitment: [u8; 32],
    pub(crate) cells: BTreeMap<ExclusiveCell, Option<CellProjection>>,
    pub(crate) stand_down: BTreeMap<DeviceId, Option<StandDown>>,
}

impl ProjectionDelta {
    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn base_generation(&self) -> u64 {
        self.base_generation
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u64 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn base_commitment(&self) -> [u8; 32] {
        self.base_commitment
    }

    pub(crate) fn commitment(&self) -> [u8; 32] {
        self.commitment
    }

    pub(crate) fn cells(&self) -> &BTreeMap<ExclusiveCell, Option<CellProjection>> {
        &self.cells
    }

    pub(crate) fn stand_down(&self) -> &BTreeMap<DeviceId, Option<StandDown>> {
        &self.stand_down
    }
}

/// Follow a same-cell resolution chain to the effective non-resolution head.
/// A malformed or cyclic chain is authority-negative; the visited set keeps
/// projection total even when a test or a future loader presents a graph that
/// was not admitted through the normal causal checks.
fn resolve_effective_head(
    graph: &FactGraph,
    cell: &ExclusiveCell,
    head: FactId,
    visited: &mut BTreeSet<FactId>,
) -> Option<FactId> {
    if !visited.insert(head) {
        return None;
    }
    let fact = graph.facts.get(&head)?;
    match &fact.content.body {
        FactBody::Resolution {
            cell: resolution_cell,
            cited_heads,
            selected_head,
        } if resolution_cell == cell => {
            let mut cited = cited_heads.clone();
            cited.sort();
            cited.dedup();
            if cited.len() < 2
                || cited.len() != cited_heads.len()
                || cited.as_slice() != cited_heads.as_slice()
                || !cited.contains(selected_head)
                || heads_at(graph, cell, head) != cited
            {
                return None;
            }
            let selected = graph.facts.get(selected_head)?;
            super::verify::body_advances_cell(&selected.content.body, cell)
                .then(|| resolve_effective_head(graph, cell, *selected_head, visited))?
        }
        body if super::verify::body_advances_cell(body, cell) => Some(head),
        _ => None,
    }
}

/// Return the complete incomparable head set visible immediately before one
/// resolution fact.  Looking at the whole graph would admit a resolution
/// against unrelated later branches, so this deliberately walks only the
/// candidate's causal parents.
fn heads_at(graph: &FactGraph, cell: &ExclusiveCell, resolution: FactId) -> Vec<FactId> {
    let mut visible = BTreeSet::new();
    let mut pending = graph
        .facts
        .get(&resolution)
        .into_iter()
        .flat_map(|fact| fact.content.parents.iter().copied())
        .collect::<Vec<_>>();
    while let Some(id) = pending.pop() {
        if !visible.insert(id) {
            continue;
        }
        if let Some(fact) = graph.facts.get(&id) {
            pending.extend(fact.content.parents.iter().copied());
        }
    }
    let candidates = visible
        .iter()
        .copied()
        .filter(|id| {
            graph
                .facts
                .get(id)
                .is_some_and(|fact| super::verify::body_advances_cell(&fact.content.body, cell))
        })
        .collect::<Vec<_>>();
    candidates
        .iter()
        .copied()
        .filter(|candidate| {
            !candidates.iter().any(|other| {
                candidate != other && is_ancestor_within(graph, &visible, candidate, other)
            })
        })
        .collect()
}

fn is_ancestor_within(
    graph: &FactGraph,
    visible: &BTreeSet<FactId>,
    ancestor: &FactId,
    descendant: &FactId,
) -> bool {
    let mut pending = vec![*descendant];
    let mut seen = BTreeSet::new();
    while let Some(id) = pending.pop() {
        if !seen.insert(id) {
            continue;
        }
        let Some(fact) = graph.facts.get(&id) else {
            continue;
        };
        for parent in &fact.content.parents {
            if parent == ancestor {
                return true;
            }
            if visible.contains(parent) {
                pending.push(*parent);
            }
        }
    }
    false
}

impl Projection {
    pub(crate) fn checkpoint_parts(&self) -> ProjectionCheckpointParts {
        (
            self.cells
                .iter()
                .map(|(cell, value)| (cell.clone(), value.clone()))
                .collect(),
            self.stand_down
                .iter()
                .map(|(target, value)| (target.clone(), value.clone()))
                .collect(),
        )
    }

    pub(crate) fn from_checkpoint_parts(
        cells: Vec<(ExclusiveCell, CellProjection)>,
        stand_down: Vec<(DeviceId, StandDown)>,
    ) -> Option<Self> {
        let cell_count = cells.len();
        let stand_down_count = stand_down.len();
        let cells = cells.into_iter().collect::<BTreeMap<_, _>>();
        let stand_down = stand_down.into_iter().collect::<BTreeMap<_, _>>();
        if cells.len() != cell_count || stand_down.len() != stand_down_count {
            return None;
        }
        let commitment = commitment_from_maps(&cells, &stand_down);
        Some(Self {
            cells: Arc::new(cells),
            stand_down: Arc::new(stand_down),
            commitment: Arc::new(commitment),
        })
    }

    pub(crate) fn sparse_entries(
        &self,
        cells: &BTreeSet<ExclusiveCell>,
        subjects: &BTreeSet<DeviceId>,
    ) -> (
        BTreeMap<ExclusiveCell, Option<CellProjection>>,
        BTreeMap<DeviceId, Option<StandDown>>,
    ) {
        let cells = cells
            .iter()
            .map(|cell| (cell.clone(), self.cells.get(cell).cloned()))
            .collect();
        let stand_down = subjects
            .iter()
            .map(|subject| (subject.clone(), self.stand_down.get(subject).cloned()))
            .collect();
        (cells, stand_down)
    }

    pub(crate) fn delta_from_sparse(
        &self,
        base_generation: u64,
        generation: u64,
        base_commitment: [u8; 32],
        previous_cells: &BTreeMap<ExclusiveCell, Option<CellProjection>>,
        previous_stand_down: &BTreeMap<DeviceId, Option<StandDown>>,
    ) -> ProjectionDelta {
        let cells = previous_cells
            .iter()
            .filter_map(|(cell, previous)| {
                let current = self.cells.get(cell).cloned();
                (current != *previous).then(|| (cell.clone(), current))
            })
            .collect();
        let stand_down = previous_stand_down
            .iter()
            .filter_map(|(subject, previous)| {
                let current = self.stand_down.get(subject).cloned();
                (current != *previous).then(|| (subject.clone(), current))
            })
            .collect();
        ProjectionDelta {
            base_generation,
            generation,
            base_commitment,
            commitment: self.commitment_root(),
            cells,
            stand_down,
        }
    }

    /// Apply a sparse projection delta only when both the caller's generation
    /// and the prior Merkle root match the captured base fence. Ownership of
    /// the projection is intentional: its uniquely owned `Arc` maps can be
    /// updated in place without cloning the full projection. The resulting
    /// root is checked against the delta, so a stale or reordered durable
    /// update cannot silently publish a different projection.
    #[cfg(test)]
    pub(crate) fn apply_delta(
        self,
        delta: &ProjectionDelta,
        expected_base_generation: u64,
        expected_base_commitment: [u8; 32],
    ) -> Option<Self> {
        if delta.base_generation != expected_base_generation
            || delta.base_commitment != expected_base_commitment
            || self.commitment_root() != expected_base_commitment
        {
            return None;
        }
        let mut next = self;
        let mut commitment = (*next.commitment).clone();
        let cells = Arc::make_mut(&mut next.cells);
        for (cell, value) in &delta.cells {
            match value {
                Some(value) => {
                    cells.insert(cell.clone(), value.clone());
                }
                None => {
                    cells.remove(cell);
                }
            }
            commitment = commitment.apply(cell_key(cell), value.as_ref().map(cell_value));
        }
        let stand_down = Arc::make_mut(&mut next.stand_down);
        for (target, value) in &delta.stand_down {
            match value {
                Some(value) => {
                    stand_down.insert(target.clone(), value.clone());
                }
                None => {
                    stand_down.remove(target);
                }
            }
            commitment =
                commitment.apply(stand_down_key(target), value.as_ref().map(stand_down_value));
        }
        if commitment.root() != delta.commitment {
            return None;
        }
        next.commitment = Arc::new(commitment);
        Some(next)
    }

    /// Restore exact values for a bounded set of projection keys.
    ///
    /// Admission rollback moves the post-mutation projection out of the graph
    /// and applies these inverse entries. Keeping only the touched entries
    /// avoids retaining a shared clone of both complete projection maps on the
    /// successful path, while the commitment is updated through the same
    /// Patricia operations used by ordinary sparse publication.
    pub(crate) fn restore_sparse_entries(
        &mut self,
        previous_cells: &BTreeMap<ExclusiveCell, Option<CellProjection>>,
        previous_stand_down: &BTreeMap<DeviceId, Option<StandDown>>,
    ) {
        let cells = Arc::make_mut(&mut self.cells);
        for (cell, value) in previous_cells {
            match value {
                Some(value) => {
                    cells.insert(cell.clone(), value.clone());
                }
                None => {
                    cells.remove(cell);
                }
            }
        }
        let stand_down = Arc::make_mut(&mut self.stand_down);
        for (target, value) in previous_stand_down {
            match value {
                Some(value) => {
                    stand_down.insert(target.clone(), value.clone());
                }
                None => {
                    stand_down.remove(target);
                }
            }
        }
        let mut commitment = (*self.commitment).clone();
        for (cell, value) in previous_cells {
            commitment = commitment.apply(cell_key(cell), value.as_ref().map(cell_value));
        }
        for (target, value) in previous_stand_down {
            commitment =
                commitment.apply(stand_down_key(target), value.as_ref().map(stand_down_value));
        }
        self.commitment = Arc::new(commitment);
    }

    #[cfg(any(test, feature = "transport-lab"))]
    pub(crate) fn delta_from(
        &self,
        previous: &Self,
        base_generation: u64,
        generation: u64,
        affected_cells: &BTreeSet<ExclusiveCell>,
        affected_subjects: &BTreeSet<DeviceId>,
    ) -> ProjectionDelta {
        let mut cells = BTreeMap::new();
        for cell in affected_cells {
            let current = self.cells.get(cell).cloned();
            if current != previous.cells.get(cell).cloned() {
                cells.insert(cell.clone(), current);
            }
        }
        let mut stand_down = BTreeMap::new();
        for subject in affected_subjects {
            let current = self.stand_down.get(subject).cloned();
            if current != previous.stand_down.get(subject).cloned() {
                stand_down.insert(subject.clone(), current);
            }
        }
        ProjectionDelta {
            base_generation,
            generation,
            base_commitment: previous.commitment_root(),
            commitment: self.commitment_root(),
            cells,
            stand_down,
        }
    }

    fn projected_cell(graph: &FactGraph, cell: &ExclusiveCell) -> Option<CellProjection> {
        let heads = graph.cell_heads(cell);
        match heads.as_slice() {
            [] => None,
            [head] => resolve_effective_head(graph, cell, *head, &mut BTreeSet::new())
                .map(CellProjection::Value)
                .or_else(|| Some(CellProjection::Conflict(vec![*head]))),
            _ => Some(CellProjection::Conflict(heads)),
        }
    }

    pub(crate) fn from_graph(graph: &FactGraph) -> Self {
        let mut cells = BTreeMap::new();
        let stand_down = projected_stand_down(graph);
        let all_cells = graph.indexed_cells();
        for cell in all_cells {
            if let Some(value) = Self::projected_cell(graph, &cell) {
                cells.insert(cell, value);
            }
        }
        let commitment = commitment_from_maps(&cells, &stand_down);
        Self {
            cells: Arc::new(cells),
            stand_down: Arc::new(stand_down),
            commitment: Arc::new(commitment),
        }
    }

    /// Update only cells and stand-down targets whose authority or causal
    /// heads may have changed. The caller supplies the exact affected sets;
    /// all other projected values are retained from the previous snapshot.
    pub(crate) fn update_from_graph(
        graph: &FactGraph,
        previous: Self,
        affected_cells: &BTreeSet<ExclusiveCell>,
        affected_stand_down_targets: &BTreeSet<DeviceId>,
    ) -> Self {
        let mut next = previous;
        let cells = Arc::make_mut(&mut next.cells);
        for cell in affected_cells {
            match Self::projected_cell(graph, cell) {
                Some(value) => {
                    cells.insert(cell.clone(), value);
                }
                None => {
                    cells.remove(cell);
                }
            }
        }
        let stand_down = Arc::make_mut(&mut next.stand_down);
        for target in affected_stand_down_targets {
            let next_stand_down = graph
                .indexed_stand_down_candidates_for(target)
                .and_then(|proofs| projected_stand_down_for_target(graph, target, proofs));
            match next_stand_down {
                Some(value) => {
                    stand_down.insert(target.clone(), value);
                }
                None => {
                    stand_down.remove(target);
                }
            }
        }
        let mut commitment = (*next.commitment).clone();
        for cell in affected_cells {
            commitment = commitment.apply(cell_key(cell), next.cells.get(cell).map(cell_value));
        }
        for target in affected_stand_down_targets {
            commitment = commitment.apply(
                stand_down_key(target),
                next.stand_down.get(target).map(stand_down_value),
            );
        }
        next.commitment = Arc::new(commitment);
        next
    }

    /// Restore-only variant of the sparse map update. The Patricia root is
    /// rebuilt once after the ordered replay, avoiding 256 Merkle allocations
    /// per historical fact while preserving the same projected maps.
    pub(crate) fn update_from_graph_deferred_commitment(
        graph: &FactGraph,
        previous: Self,
        affected_cells: &BTreeSet<ExclusiveCell>,
        affected_stand_down_targets: &BTreeSet<DeviceId>,
    ) -> Self {
        let mut next = previous;
        let cells = Arc::make_mut(&mut next.cells);
        for cell in affected_cells {
            match Self::projected_cell(graph, cell) {
                Some(value) => {
                    cells.insert(cell.clone(), value);
                }
                None => {
                    cells.remove(cell);
                }
            }
        }
        let stand_down = Arc::make_mut(&mut next.stand_down);
        for target in affected_stand_down_targets {
            let next_stand_down = graph
                .indexed_stand_down_candidates_for(target)
                .and_then(|proofs| projected_stand_down_for_target(graph, target, proofs));
            match next_stand_down {
                Some(value) => {
                    stand_down.insert(target.clone(), value);
                }
                None => {
                    stand_down.remove(target);
                }
            }
        }
        next
    }

    pub(crate) fn rebuild_commitment(mut self) -> Self {
        self.commitment = Arc::new(commitment_from_maps(&self.cells, &self.stand_down));
        self
    }

    pub fn cell(&self, cell: &ExclusiveCell) -> Option<&CellProjection> {
        self.cells.get(cell)
    }

    pub fn cells(&self) -> impl Iterator<Item = (&ExclusiveCell, &CellProjection)> {
        self.cells.iter()
    }

    pub fn is_conflicted(&self, cell: &ExclusiveCell) -> bool {
        matches!(self.cell(cell), Some(CellProjection::Conflict(_)))
    }

    pub fn conflicted_cells(&self) -> impl Iterator<Item = &ExclusiveCell> {
        self.cells.iter().filter_map(|(cell, projection)| {
            matches!(projection, CellProjection::Conflict(_)).then_some(cell)
        })
    }

    pub fn value(&self, cell: &ExclusiveCell) -> Option<FactId> {
        match self.cell(cell) {
            Some(CellProjection::Value(id)) => Some(*id),
            _ => None,
        }
    }

    /// Read the projected role cell without allowing a caller to substitute a
    /// stringly-typed authority key.
    pub fn role_cell(&self, subject: &DeviceId) -> Option<&CellProjection> {
        self.cell(&ExclusiveCell::role(subject.clone()))
    }

    /// Read the projected membership cell for Closed session admission.
    pub fn membership_cell(&self, subject: &DeviceId) -> Option<&CellProjection> {
        self.cell(&ExclusiveCell::membership(subject.clone()))
    }

    pub fn stand_down(&self, target: &DeviceId) -> Option<&StandDown> {
        self.stand_down.get(target)
    }

    pub fn is_stood_down(&self, target: &DeviceId) -> bool {
        self.stand_down.contains_key(target)
    }

    pub fn stand_down_targets(&self) -> impl Iterator<Item = &DeviceId> {
        self.stand_down.keys()
    }

    pub(crate) fn commitment_root(&self) -> [u8; 32] {
        self.commitment.root()
    }

    pub(crate) fn commitment_bytes(&self) -> u64 {
        self.commitment.retained_bytes()
    }
}

fn cell_key(cell: &ExclusiveCell) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.tag("cell");
    cell.encode(&mut encoder);
    encoder.finish()
}

fn cell_value(value: &CellProjection) -> [u8; 32] {
    let mut encoder = Encoder::new();
    match value {
        CellProjection::Value(id) => {
            encoder.tag("value");
            encoder.id(*id);
        }
        CellProjection::Conflict(ids) => {
            encoder.tag("conflict");
            encoder.list_ids(ids);
        }
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(encoder.finish()));
    hash
}

fn stand_down_key(target: &DeviceId) -> Vec<u8> {
    let mut encoder = Encoder::new();
    encoder.tag("stand_down");
    encoder.device(target);
    encoder.finish()
}

fn stand_down_value(value: &StandDown) -> [u8; 32] {
    let mut encoder = Encoder::new();
    encoder.device(&value.target);
    encoder.id(value.proof);
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&Sha256::digest(encoder.finish()));
    hash
}

fn commitment_from_maps(
    cells: &BTreeMap<ExclusiveCell, CellProjection>,
    stand_down: &BTreeMap<DeviceId, StandDown>,
) -> ProjectionCommitment {
    let mut commitment = ProjectionCommitment::default();
    for (cell, value) in cells {
        commitment = commitment.apply(cell_key(cell), Some(cell_value(value)));
    }
    for (target, value) in stand_down {
        commitment = commitment.apply(stand_down_key(target), Some(stand_down_value(value)));
    }
    commitment
}

/// Project stand-down evidence independently of arrival order.  A signed
/// MembershipAdmit is the only restoration operation; it must be the selected
/// membership value and must causally descend from the active proof.  A
/// concurrent or losing membership branch cannot clear a stand-down, so the
/// result remains fail-closed.
fn projected_stand_down(graph: &FactGraph) -> BTreeMap<DeviceId, StandDown> {
    let mut evidence = BTreeMap::<DeviceId, Vec<FactId>>::new();
    for (target, candidates) in graph.indexed_stand_down_candidates() {
        for id in candidates {
            if graph.fact_is_authoritative(&id) {
                evidence.entry(target.clone()).or_default().push(id);
            }
        }
    }

    let mut result = BTreeMap::new();
    for (target, proofs) in evidence {
        let restoration = projected_membership_restoration(graph, &target);
        let active = proofs.iter().copied().find(|proof| {
            restoration
                .is_none_or(|restored| *proof != restored && !graph.is_ancestor(proof, &restored))
        });
        if let Some(proof) = active {
            result.insert(target.clone(), StandDown { target, proof });
        }
    }
    result
}

fn projected_stand_down_for_target(
    graph: &FactGraph,
    target: &DeviceId,
    proofs: &BTreeSet<FactId>,
) -> Option<StandDown> {
    let restoration = projected_membership_restoration(graph, target);
    let proof = proofs.iter().copied().find(|proof| {
        graph.fact_is_authoritative(proof)
            && restoration
                .is_none_or(|restored| *proof != restored && !graph.is_ancestor(proof, &restored))
    })?;
    Some(StandDown {
        target: target.clone(),
        proof,
    })
}

fn projected_membership_restoration(graph: &FactGraph, target: &DeviceId) -> Option<FactId> {
    let cell = ExclusiveCell::membership(target.clone());
    let heads = graph.cell_heads(&cell);
    let [head] = heads.as_slice() else {
        return None;
    };
    let selected = resolve_effective_head(graph, &cell, *head, &mut BTreeSet::new())?;
    matches!(
        graph.facts.get(&selected).map(|fact| &fact.content.body),
        Some(FactBody::MembershipAdmit { target: admitted }) if admitted == target
    )
    .then_some(selected)
}

#[cfg(test)]
mod commitment_tests {
    use super::*;

    fn entry(key: u8, value: u8) -> (Vec<u8>, [u8; 32]) {
        (vec![key], [value; 32])
    }

    #[test]
    fn canonical_root_is_insertion_order_independent() {
        let first = ProjectionCommitment::default()
            .apply(entry(1, 9).0, Some(entry(1, 9).1))
            .apply(entry(2, 8).0, Some(entry(2, 8).1))
            .apply(entry(3, 7).0, Some(entry(3, 7).1));
        let second = ProjectionCommitment::default()
            .apply(entry(3, 7).0, Some(entry(3, 7).1))
            .apply(entry(1, 9).0, Some(entry(1, 9).1))
            .apply(entry(2, 8).0, Some(entry(2, 8).1));
        assert_eq!(first.root(), second.root());
    }

    #[test]
    fn incremental_update_matches_full_and_delete_rollback_restores_root() {
        let base_entries = [entry(4, 1), entry(5, 2), entry(6, 3)];
        let base = base_entries.iter().fold(
            ProjectionCommitment::default(),
            |commitment, (key, value)| commitment.apply(key.clone(), Some(*value)),
        );
        let incremental = base.apply(vec![5], None).apply(vec![5], Some([8; 32]));
        let full = ProjectionCommitment::default()
            .apply(vec![4], Some([1; 32]))
            .apply(vec![5], Some([8; 32]))
            .apply(vec![6], Some([3; 32]));
        assert_eq!(incremental.root(), full.root());

        let deleted = incremental.apply(vec![5], None);
        let restored = deleted.apply(vec![5], Some([8; 32]));
        assert_eq!(restored.root(), incremental.root());
        assert_ne!(deleted.root(), incremental.root());
        assert!(restored.retained_bytes() >= deleted.retained_bytes());
    }

    #[test]
    fn projection_delta_carries_generation_and_root_fence() {
        let previous = Projection::default();
        let current = Projection::default();
        let delta = current.delta_from(&previous, 11, 12, &BTreeSet::new(), &BTreeSet::new());
        assert_eq!(delta.base_generation(), 11);
        assert_eq!(delta.generation(), 12);
        assert_eq!(delta.base_commitment(), previous.commitment_root());
        assert_eq!(delta.commitment(), current.commitment_root());
        assert!(current
            .clone()
            .apply_delta(&delta, 11, previous.commitment_root())
            .is_some());
        assert!(current
            .clone()
            .apply_delta(&delta, 10, previous.commitment_root())
            .is_none());
        let mut stale = delta.clone();
        stale.base_commitment = [0xff; 32];
        assert!(current
            .clone()
            .apply_delta(&stale, 11, previous.commitment_root())
            .is_none());
    }
}
