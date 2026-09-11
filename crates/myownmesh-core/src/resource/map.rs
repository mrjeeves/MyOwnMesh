//! An ordered map in which every entry owns exactly one allocation and pays for
//! exactly that allocation.
//!
//! **Why not `BTreeMap`.** A B-tree entry does not own an allocation. Several
//! entries share a node, and the node is freed only when it empties, so an
//! owner charging per entry and releasing per removal releases memory the
//! allocator still holds: a map that fills and drains gives back everything it
//! claimed while the nodes are still there. The bytes of a slot are real, but
//! the *allocation* term cannot be released at the moment an entry leaves,
//! because nothing about that moment says whether an allocation left with it.
//!
//! **Why not a sorted `Vec` either.** That makes the collection's capacity
//! exact, which is a different thing from making an entry's cost exact: the
//! buffer and its slack survive every removal, so no entry can release its own
//! share, and the shift on each insert and remove is linear in the session's
//! own size — which an adversary chooses.
//!
//! **A treap.** One `Box` per entry, so `size_of::<LeasedMapNode<K, V>>()` is
//! the allocation and there is no spare capacity anywhere. Ordered by key for
//! lookup, heap-ordered by a priority derived from hashing the key, which keeps
//! the expected depth logarithmic without any rebalancing that allocates.
//! Insertion and removal move nodes by rotation and allocate nothing beyond the
//! one node being added.
//!
//! **The priority is not identity and not authority.** It is a balancing detail
//! and nothing reads it but the rotations below. It is derived per map from a
//! [`std::collections::hash_map::RandomState`], so it is unpredictable across
//! processes and a peer choosing names cannot choose a shape.

use std::borrow::Borrow;
use std::cmp::Ordering;
use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash};

use super::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};

/// One retained entry: the caller's key and value, and the two links.
///
/// The lease that funds this allocation is deliberately **not** here. It lives
/// in the [`FundedNode`] link that owns the box, because a lease stored inside
/// the allocation it pays for is released by that allocation's own drop glue —
/// which runs while the allocation is still there. See [`FundedNode`].
struct LeasedMapNode<K, V> {
    key: K,
    value: V,
    /// Heap order. A balancing detail — never compared for identity, never
    /// serialized, never shown to a caller.
    priority: u64,
    left: Option<FundedNode<K, V>>,
    right: Option<FundedNode<K, V>>,
}

/// A node allocation and the lease that pays for it, in that order.
///
/// **The lease is a sibling of the box, not a field inside it.** Drop glue runs
/// a value's fields before freeing the value, so a lease held inside the node
/// would go back to the provider while the node's memory was still allocated —
/// a window in which the ledger says the bytes are free and they are not. As a
/// sibling declared *after* the box, the box is dropped first and the lease is
/// released only once the allocation is genuinely gone. Every path gets this,
/// including the ones that never intended to release anything: the map's own
/// teardown, a refused insert's natural drop, and any link overwritten in
/// place.
///
/// There is no way to take the box out. [`Deref`](std::ops::Deref) borrows the
/// node so the whole module reads and rebuilds the tree exactly as it did when
/// the links were plain boxes, and [`FundedNode::into_entry`] is the single
/// consuming exit, written so the allocation is freed before the lease goes
/// back. A `(Box, ResourceLease)` accessor is not offered on purpose — it would
/// hand a caller the two halves and let it drop them in the wrong order, which
/// is the exact defect this shape exists to make unspellable.
struct FundedNode<K, V> {
    node: Box<LeasedMapNode<K, V>>,
    /// Covers only this map node's allocation. Any off-node retention in `key`
    /// or `value` owns a separate lease for its full lifetime.
    ///
    /// Declared after `node`, and that order is the entire point.
    _entry: ResourceLease,
}

/// Borrowing a link reaches the node, so every walk in this module is written
/// against `LeasedMapNode` and never has to name the funding.
///
/// This deliberately cannot move the node out: `FundedNode` is not a smart
/// pointer a caller can dereference-and-move through, so the only consuming
/// path is [`FundedNode::into_entry`].
impl<K, V> std::ops::Deref for FundedNode<K, V> {
    type Target = LeasedMapNode<K, V>;

    fn deref(&self) -> &Self::Target {
        &self.node
    }
}

impl<K, V> std::ops::DerefMut for FundedNode<K, V> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.node
    }
}

impl<K, V> FundedNode<K, V> {
    /// Detach the entry, free its allocation, and only then release its lease.
    ///
    /// The order is load-bearing and is the reason removal does not simply drop
    /// the link: moving out of `*node` frees the allocation at the end of that
    /// statement, and `_entry` — a local from this function's own destructuring
    /// — is released after it, on return. The key and value are handed back
    /// still owning whatever separate leases their off-node storage holds.
    fn into_entry(self) -> (K, V) {
        let FundedNode { node, _entry } = self;
        let LeasedMapNode { key, value, .. } = *node;
        // The allocation is gone as of the statement above. `_entry` is
        // released below, when this frame ends — never before.
        (key, value)
    }
}

/// The candidate an insert refused, still in the node that was allocated and
/// funded for it.
///
/// **One pointer, and the refusal costs no allocation of its own.** The insert
/// had already boxed the key, the value and the lease before it discovered the
/// collision, so handing that same box back is both the cheapest and the most
/// truthful answer: nothing was unpacked, nothing was rebuilt, and the caller
/// holds exactly what it supplied.
///
/// **Dropping it is the release, and there is nothing else to do with it.**
/// Dropping a [`FundedNode`] frees the node allocation and only then releases
/// the lease that paid for it, so this path needs no destructor of its own to
/// be truthful — the ordering is a property of the link type rather than of
/// each site that drops one. Its links were never attached, so this is a leaf's
/// drop and cannot recurse.
///
/// There is deliberately no accessor. A caller that could take the value back
/// out would be holding a payload whose lease had already been released with
/// the node around it, and every caller in the crate wants only the fact of the
/// refusal.
pub struct LeasedMapInsertRefusal<K, V> {
    /// Never read; it exists to be dropped. Underscored because the whole
    /// content of this field is its destructor.
    _node: FundedNode<K, V>,
}

/// Names the refusal and nothing inside it.
///
/// Needed because callers `expect` on this result, and deliberately not derived:
/// a derived `Debug` would demand `K: Debug` and `V: Debug` of every map, and
/// would put a caller's payload and its accounting handle into a panic message.
/// Which key collided is already known to the caller that supplied it.
impl<K, V> std::fmt::Debug for LeasedMapInsertRefusal<K, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("LeasedMapInsertRefusal")
    }
}

/// An ordered map whose every entry is separately funded.
///
/// Generic over key and value because the shape — exact per-entry funding,
/// release on removal, release on drop — is the same fact for a session's held
/// names and for its live flows, and two copies of it would be two places to
/// get the drop order wrong.
pub struct LeasedMap<K, V> {
    /// The root link, and with it the root node's lease. Every other node's
    /// lease is held by the link in its parent, so no lease in the whole tree
    /// sits inside the allocation it pays for.
    root: Option<FundedNode<K, V>>,
    len: usize,
    /// Seeds the per-entry priority. Per map and per process, so the tree's
    /// shape is not a function a caller can compute.
    priorities: RandomState,
}

/// Dropping the map drops every entry it still holds.
///
/// Written out rather than derived because the derived drop is recursive: it
/// would descend one stack frame per level, and although a treap's expected
/// depth is logarithmic, a teardown that is only *probably* shallow is not a
/// property worth relying on when the alternative is this short.
///
/// The tree is flattened toward a right spine by rotation and then unlinked, so
/// every node is dropped with both children empty and nothing is allocated
/// while freeing. Entries are destroyed in key order, which is incidental but
/// makes the teardown observable rather than arbitrary.
impl<K, V> Drop for LeasedMap<K, V> {
    fn drop(&mut self) {
        let mut root = self.root.take();
        while let Some(mut node) = root {
            match node.left.take() {
                Some(mut pivot) => {
                    // Rotate the left child up. No allocation, and the tree
                    // shrinks toward a spine one step at a time.
                    node.left = pivot.right.take();
                    pivot.right = Some(node);
                    root = Some(pivot);
                }
                None => {
                    root = node.right.take();
                    // `node` drops here with no children. It is a `FundedNode`,
                    // so the box is freed and only then is the lease released —
                    // this arm does not have to spell that ordering out, and
                    // could not get it wrong if it tried.
                }
            }
        }
    }
}

impl<K, V> Default for LeasedMap<K, V> {
    fn default() -> Self {
        Self::new()
    }
}

impl<K, V> LeasedMap<K, V> {
    pub fn new() -> Self {
        Self {
            root: None,
            len: 0,
            priorities: RandomState::new(),
        }
    }

    /// Everything one entry costs: exactly this map's node.
    ///
    /// The single calibration point. An owner never writes the node's size
    /// itself. The node's size is `size_of` over the concrete node type, so it
    /// already includes the key and value inline, the priority, and both links
    /// — and each link is now a pointer *and* the child's lease handle, since
    /// [`FundedNode`] holds a child's funding beside the child's box rather
    /// than inside it. Those inline lease handles are part of this allocation
    /// and are counted here exactly once, by the parent that allocates them.
    ///
    /// This entry's own lease is not in this allocation at all: it is held by
    /// the link in the parent, or by the map's `root` field for the root node.
    /// Nothing is double-counted and nothing is missed — every node allocation
    /// is paid for by exactly one claim, taken here.
    ///
    /// The residual is 1 because the entry is exactly one allocation, and
    /// unlike a B-tree slot that residual is released at the moment the entry
    /// is. Off-node retention owned by `K` or `V` carries its own lease in that
    /// value, so removal may release this node and safely return both values.
    #[must_use = "the entry claim must be acquired before the entry is inserted"]
    pub fn entry_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record_bytes =
            u64::try_from(std::mem::size_of::<LeasedMapNode<K, V>>()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// How many entries are live.
    ///
    /// Constant-time count for explicit entry limits, quiescence observations,
    /// and settlement controls. A count does not replace resource admission:
    /// each entry and its retained values still require their own funding.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }
}

impl<K: Ord + Hash, V> LeasedMap<K, V> {
    /// Whether any live value satisfies `predicate`, without allocating an
    /// iterator stack or exposing the map's representation.
    pub fn any_value(&self, mut predicate: impl FnMut(&V) -> bool) -> bool {
        fn visit<K, V>(
            node: Option<&LeasedMapNode<K, V>>,
            predicate: &mut impl FnMut(&V) -> bool,
        ) -> bool {
            let Some(node) = node else { return false };
            predicate(&node.value)
                || visit(node.left.as_deref(), predicate)
                || visit(node.right.as_deref(), predicate)
        }
        visit(self.root.as_deref(), &mut predicate)
    }

    /// Visit every live key and value without exposing or allocating an
    /// iterator representation.
    ///
    /// Callers that need an owned snapshot perform their own allocation while
    /// this borrowed walk keeps the map's node and lease ownership private.
    pub fn for_each(&self, mut visit_entry: impl FnMut(&K, &V)) {
        fn visit<K, V>(node: Option<&LeasedMapNode<K, V>>, visit_entry: &mut impl FnMut(&K, &V)) {
            let Some(node) = node else { return };
            visit(node.left.as_deref(), visit_entry);
            visit_entry(&node.key, &node.value);
            visit(node.right.as_deref(), visit_entry);
        }
        visit(self.root.as_deref(), &mut visit_entry);
    }

    /// The greatest live key and its value, borrowed.
    ///
    /// One descent down the right spine and nothing else: no allocation, no
    /// traversal of the rest of the map, and the borrow ends with the caller's
    /// `&self`. A caller fixing an upper bound for an ordered pass needs this
    /// one node, and reaching it through [`Self::for_each`] would visit every
    /// entry to learn the same fact.
    pub fn last_key_value(&self) -> Option<(&K, &V)> {
        let mut node = self.root.as_deref()?;
        while let Some(right) = node.right.as_deref() {
            node = right;
        }
        Some((&node.key, &node.value))
    }

    /// The least live key strictly greater than `after`, and its value.
    ///
    /// `None` for `after` answers the least key in the map, so one ordered pass
    /// is `successor_after(None)` followed by `successor_after(Some(previous))`
    /// and needs no separate first-entry call.
    ///
    /// **One descent per step, not one traversal per step.** The walk keeps the
    /// closest right-hand candidate seen so far and goes left when the current
    /// key is a better one, so it touches the tree's depth rather than its size.
    /// That is the whole reason this exists: a caller resuming an ordered pass
    /// through [`Self::for_each`] performs a complete walk for every step, which
    /// turns a pass over `n` entries into `n` full traversals while whatever
    /// lock protects the map is held.
    ///
    /// `after` is a borrowed key rather than a `Borrow<Q>` bound because the
    /// cursor a caller resumes from is a key it already holds, and the narrower
    /// signature keeps inference at the call site unambiguous.
    ///
    /// Nothing is allocated and nothing is removed. The returned borrows name
    /// nodes the map still owns, so the funding of every entry is untouched by
    /// asking.
    pub fn successor_after(&self, after: Option<&K>) -> Option<(&K, &V)> {
        let mut node = self.root.as_deref();
        let mut best: Option<&LeasedMapNode<K, V>> = None;
        while let Some(current) = node {
            let ahead = match after {
                Some(after) => current.key > *after,
                // No cursor yet, so every key is a candidate and the least one
                // is the leftmost.
                None => true,
            };
            if ahead {
                best = Some(current);
                node = current.left.as_deref();
            } else {
                node = current.right.as_deref();
            }
        }
        best.map(|node| (&node.key, &node.value))
    }

    /// Borrow one live value satisfying `predicate` mutably.
    ///
    /// The walk allocates nothing. It is used for bounded teardown quanta: one
    /// retained child is removed under the owner lock, then dropped after the
    /// lock is released.
    pub fn find_value_mut(&mut self, mut predicate: impl FnMut(&V) -> bool) -> Option<&mut V> {
        fn visit<'a, K, V>(
            node: Option<&'a mut LeasedMapNode<K, V>>,
            predicate: &mut impl FnMut(&V) -> bool,
        ) -> Option<&'a mut V> {
            let node = node?;
            if predicate(&node.value) {
                return Some(&mut node.value);
            }
            if let Some(value) = visit(node.left.as_deref_mut(), predicate) {
                return Some(value);
            }
            visit(node.right.as_deref_mut(), predicate)
        }
        visit(self.root.as_deref_mut(), &mut predicate)
    }

    /// Insert one entry, which now owns the lease that funded it.
    ///
    /// A key already present is **refused**, and the candidate comes straight
    /// back in the `Err` still inside the node that was allocated for it, so
    /// dropping the result destroys the value and releases the funding.
    /// Replacing silently would destroy a live entry that something else is
    /// still holding a name for, and refusing while keeping the lease would
    /// retain funding for an entry that does not exist.
    ///
    /// The `Err` carries the whole rejected node — the boxed entry and the
    /// lease that funded it — precisely so that dropping it releases both. It
    /// is **not** small: a [`ResourceLease`] alone is well over a hundred bytes,
    /// and that is what makes this a deliberate exception to
    /// `clippy::result_large_err` rather than an oversight. The alternative the
    /// lint suggests is boxing the error, which would allocate on the refusal
    /// path — the one path that must not need the allocator, since it is
    /// reached because capacity is already contended.
    ///
    /// What the shape does buy is that the candidate comes back *packed*:
    /// handing the caller an unpacked value and lease would widen the success
    /// path too, to describe a case that did not happen.
    #[expect(
        clippy::result_large_err,
        reason = "the Err is the rejected node itself, returned by value so dropping it \
                  releases its lease; boxing would allocate on the refusal path"
    )]
    pub fn insert(
        &mut self,
        key: K,
        value: V,
        entry: ResourceLease,
    ) -> Result<(), LeasedMapInsertRefusal<K, V>> {
        let priority = self.priority(&key);
        let node = FundedNode {
            node: Box::new(LeasedMapNode {
                key,
                value,
                priority,
                left: None,
                right: None,
            }),
            _entry: entry,
        };
        match Self::insert_node(&mut self.root, node) {
            Some(refused) => Err(LeasedMapInsertRefusal { _node: refused }),
            None => {
                // Not saturating: the count and the tree must agree, and a
                // saturated count would disagree silently. It cannot overflow
                // either — every entry is a live allocation, so `usize::MAX` of
                // them is unreachable.
                self.len = self
                    .len
                    .checked_add(1)
                    .expect("one live allocation per entry bounds the count");
                Ok(())
            }
        }
    }

    /// This map's priority for one key.
    ///
    /// `hash_one` over a borrow of the key, so nothing is moved and no second
    /// hasher state is spelled out here — the `RandomState` seeded per map is
    /// the only thing that decides the value, which is what keeps the shape
    /// unpredictable across processes.
    fn priority(&self, key: &K) -> u64 {
        self.priorities.hash_one(key)
    }

    /// Place `node`, or hand it back if its key is already present.
    ///
    /// Recursive, and bounded by the tree's depth rather than its size: the
    /// priorities are hashes of the keys, so the expected depth is logarithmic
    /// and no caller-chosen key order produces a spine.
    ///
    /// **Mutation may recurse; teardown may not.** A mutation walks one root-to-
    /// leaf path under priorities a caller cannot guess and a population the
    /// owner's leases already bound, so its depth is bounded twice over. Drop
    /// has neither guarantee — it runs on every node, on a tree of whatever size
    /// the owner funded, and on a path that must not allocate to unwind — so it
    /// is written iteratively rather than recursively.
    fn insert_node(
        slot: &mut Option<FundedNode<K, V>>,
        node: FundedNode<K, V>,
    ) -> Option<FundedNode<K, V>> {
        let Some(mut current) = slot.take() else {
            *slot = Some(node);
            return None;
        };
        let refused = match node.key.cmp(&current.key) {
            Ordering::Equal => Some(node),
            Ordering::Less => {
                let refused = Self::insert_node(&mut current.left, node);
                if refused.is_none() && Self::outranks(current.left.as_deref(), current.priority) {
                    current = Self::rotate_right(current);
                }
                refused
            }
            Ordering::Greater => {
                let refused = Self::insert_node(&mut current.right, node);
                if refused.is_none() && Self::outranks(current.right.as_deref(), current.priority) {
                    current = Self::rotate_left(current);
                }
                refused
            }
        };
        *slot = Some(current);
        refused
    }

    fn outranks(child: Option<&LeasedMapNode<K, V>>, priority: u64) -> bool {
        child.is_some_and(|child| child.priority > priority)
    }

    /// Move the left child above this node. Allocates nothing, and moves each
    /// node's lease with the link that holds it.
    fn rotate_right(mut node: FundedNode<K, V>) -> FundedNode<K, V> {
        let mut pivot = node
            .left
            .take()
            .expect("a right rotation is only reached with a left child");
        node.left = pivot.right.take();
        pivot.right = Some(node);
        pivot
    }

    /// Move the right child above this node. Allocates nothing, and moves each
    /// node's lease with the link that holds it.
    fn rotate_left(mut node: FundedNode<K, V>) -> FundedNode<K, V> {
        let mut pivot = node
            .right
            .take()
            .expect("a left rotation is only reached with a right child");
        node.right = pivot.left.take();
        pivot.left = Some(node);
        pivot
    }

    /// Join two subtrees, every key in `left` ordering before every key in
    /// `right`. Allocates nothing.
    fn merge(
        left: Option<FundedNode<K, V>>,
        right: Option<FundedNode<K, V>>,
    ) -> Option<FundedNode<K, V>> {
        match (left, right) {
            (None, right) => right,
            (left, None) => left,
            (Some(mut left_node), Some(right_node)) => {
                if left_node.priority >= right_node.priority {
                    left_node.right = Self::merge(left_node.right.take(), Some(right_node));
                    Some(left_node)
                } else {
                    let mut right_node = right_node;
                    right_node.left = Self::merge(Some(left_node), right_node.left.take());
                    Some(right_node)
                }
            }
        }
    }
}

impl<K: Ord + Hash, V> LeasedMap<K, V> {
    /// The value under `key`, if the map holds one.
    ///
    /// Borrowed lookup, so asking about a name costs nothing the name does not
    /// already own — a caller with raw bytes never has to build a funded key
    /// merely to ask a question.
    pub fn get<Q>(&self, key: &Q) -> Option<&V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).map(|node| &node.value)
    }

    pub fn get_mut<Q>(&mut self, key: &Q) -> Option<&mut V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find_mut(key).map(|node| &mut node.value)
    }

    /// The stored key beside its value, for a caller that needs the map's own
    /// copy rather than the one it looked up with.
    ///
    /// Controls only, and that is a property of the production paths rather than
    /// an accident. A caller holding the map's key holds the leased label that
    /// funds it, which is the session's to hold and not a lookup's to hand out;
    /// the two consumers are the test seams that have to build a delivery
    /// addressed to a flow, and both are themselves gated.
    #[cfg(test)]
    pub(crate) fn get_key_value<Q>(&self, key: &Q) -> Option<(&K, &V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).map(|node| (&node.key, &node.value))
    }

    pub fn contains_key<Q>(&self, key: &Q) -> bool
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.find(key).is_some()
    }

    /// Remove one entry and return its value, releasing the stored key and the
    /// entry's funding as they drop.
    ///
    /// Call [`Self::remove_entry`] instead when the caller must retain the
    /// map's owned key for a later ordering or delivery step.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<V>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        self.remove_entry(key).map(|(_, value)| value)
    }

    /// Remove one entry and hand back both halves, releasing the map node's
    /// funding before the returned tuple is observed by the caller.
    ///
    /// The node lease funds only the container node. A caller that keeps the
    /// owned key or value after removal must make that retained storage carry
    /// its own lease; returning the two values does not extend the node lease.
    pub fn remove_entry<Q>(&mut self, key: &Q) -> Option<(K, V)>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let node = Self::remove_node(&mut self.root, key)?;
        // Reached only after a node really came out of the tree, so this cannot
        // underflow unless the count and the tree have already diverged — which
        // is the thing worth failing on rather than absorbing.
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        // Frees the node allocation first and releases its lease after; see
        // `FundedNode::into_entry`.
        Some(node.into_entry())
    }

    /// Remove and return the first ordered entry without cloning a key.
    ///
    /// Teardown paths use this to drain attacker-sized maps one owned record at
    /// a time. Building a key snapshot first would allocate and duplicate every
    /// retained key precisely while the table is being torn down. As with
    /// [`Self::remove_entry`], the map-node lease ends inside this call; any
    /// storage the returned key or value retains must carry its own funding.
    pub fn pop_first_entry(&mut self) -> Option<(K, V)> {
        let node = Self::remove_first_node(&mut self.root)?;
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        Some(node.into_entry())
    }

    /// Remove and return the first ordered entry accepted by `predicate`.
    ///
    /// Conditional teardown cannot use [`Self::pop_first_entry`] without also
    /// removing entries it does not own. Pushing those entries back would need
    /// fresh node leases, which would put a fallible acquisition on the cleanup
    /// path. This instead searches the live tree in order and detaches only a
    /// matching node: no key is cloned, no snapshot is allocated, and no node
    /// is reinserted or reacquired.
    ///
    /// As with the other removal methods, the returned key and value must carry
    /// any funding their off-node retention needs after the map-node lease ends.
    pub fn pop_first_where(&mut self, mut predicate: impl FnMut(&K, &V) -> bool) -> Option<(K, V)> {
        let node = Self::remove_first_where_node(&mut self.root, &mut predicate)?;
        self.len = self
            .len
            .checked_sub(1)
            .expect("an entry was removed, so the count was not zero");
        Some(node.into_entry())
    }

    fn find<Q>(&self, key: &Q) -> Option<&LeasedMapNode<K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut cursor = self.root.as_deref();
        while let Some(node) = cursor {
            cursor = match key.cmp(node.key.borrow()) {
                Ordering::Less => node.left.as_deref(),
                Ordering::Greater => node.right.as_deref(),
                Ordering::Equal => return Some(node),
            };
        }
        None
    }

    fn find_mut<Q>(&mut self, key: &Q) -> Option<&mut LeasedMapNode<K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut cursor = self.root.as_deref_mut();
        while let Some(node) = cursor {
            match key.cmp(node.key.borrow()) {
                Ordering::Less => cursor = node.left.as_deref_mut(),
                Ordering::Greater => cursor = node.right.as_deref_mut(),
                Ordering::Equal => return Some(node),
            }
        }
        None
    }

    /// Detach the node under `key`, leaving the rest of the tree ordered.
    ///
    /// The detached node comes back with both children taken, so its own drop
    /// is a leaf's drop and cannot recurse.
    fn remove_node<Q>(slot: &mut Option<FundedNode<K, V>>, key: &Q) -> Option<FundedNode<K, V>>
    where
        K: Borrow<Q>,
        Q: Ord + ?Sized,
    {
        let mut current = slot.take()?;
        let removed = match key.cmp(current.key.borrow()) {
            Ordering::Equal => {
                *slot = Self::merge(current.left.take(), current.right.take());
                return Some(current);
            }
            Ordering::Less => Self::remove_node(&mut current.left, key),
            Ordering::Greater => Self::remove_node(&mut current.right, key),
        };
        *slot = Some(current);
        removed
    }

    /// Detach the first ordered node without first borrowing or cloning its
    /// key. The detached node has no children, so dropping its box cannot
    /// recurse through the remaining tree.
    fn remove_first_node(slot: &mut Option<FundedNode<K, V>>) -> Option<FundedNode<K, V>> {
        let mut current = slot.take()?;
        if current.left.is_some() {
            let removed = Self::remove_first_node(&mut current.left)
                .expect("a present left subtree has a first node");
            *slot = Some(current);
            return Some(removed);
        }
        *slot = current.right.take();
        Some(current)
    }

    /// Detach the first in-order node accepted by `predicate`.
    ///
    /// A rejected node is restored in the same allocation before the search
    /// continues. A selected node is joined out exactly as in [`Self::remove_node`],
    /// so the returned box has no children and dropping it cannot recurse into
    /// the live tree.
    fn remove_first_where_node(
        slot: &mut Option<FundedNode<K, V>>,
        predicate: &mut impl FnMut(&K, &V) -> bool,
    ) -> Option<FundedNode<K, V>> {
        let mut current = slot.take()?;

        if let Some(removed) = Self::remove_first_where_node(&mut current.left, predicate) {
            *slot = Some(current);
            return Some(removed);
        }

        if predicate(&current.key, &current.value) {
            *slot = Self::merge(current.left.take(), current.right.take());
            return Some(current);
        }

        let removed = Self::remove_first_where_node(&mut current.right, predicate);
        *slot = Some(current);
        removed
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::{
        FiniteResourceProvider, ResourceAuthorityClass, ResourceProviderPort, ResourceScope,
    };
    use std::sync::{Arc, Mutex};

    type DropLog = Arc<Mutex<Vec<u32>>>;

    fn drop_log() -> DropLog {
        Arc::new(Mutex::new(Vec::new()))
    }

    /// A value that reports its own destruction.
    struct ControlValue {
        key: u32,
        dropped: DropLog,
        _retention: ResourceLease,
    }

    impl Drop for ControlValue {
        fn drop(&mut self) {
            self.dropped
                .lock()
                .expect("the control drop log is uncontended")
                .push(self.key);
        }
    }

    /// The retention one control entry declares beyond its node. Non-zero and
    /// in a dimension the node term does not use, so a claim that dropped
    /// either term is visible rather than absorbed.
    fn control_retention() -> ResourceClaim {
        ResourceClaim::single(ResourceClass::QueuedBytes, 64)
    }

    fn control_entry_claim() -> ResourceClaim {
        LeasedMap::<u32, ControlValue>::entry_claim()
            .expect("the control entry claim is representable")
    }

    /// A grant that funds exactly `entries` entries and nothing spare, derived
    /// from the same `entry_claim` an owner would use plus the provider's own
    /// per-reservation and per-scope bookkeeping.
    fn control_grant(entries: u64) -> ResourceClaim {
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let node = control_entry_claim()
            .checked_add(scope_record)
            .expect("the control entry claim plus its reservation record is representable");
        let retention = control_retention()
            .checked_add(scope_record)
            .expect("the value retention plus its reservation record is representable");
        (0..entries)
            .try_fold(scope_record, |total, _| {
                total.checked_add(node)?.checked_add(retention)
            })
            .expect("the bounded control grant is representable")
    }

    fn control_provider(
        entries: u64,
    ) -> (FiniteResourceProvider, ResourceProviderPort, ResourceScope) {
        let provider = FiniteResourceProvider::new(control_grant(entries));
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the control grant accounts for the process scope");
        let scope = port.process_scope();
        (provider, port, scope)
    }

    fn control_lease(port: &ResourceProviderPort, scope: &ResourceScope) -> ResourceLease {
        port.acquire(
            scope,
            ResourceAuthorityClass::Admitted,
            control_entry_claim(),
        )
        .expect("the control grant funds this entry")
    }

    fn control_value(
        key: u32,
        dropped: &DropLog,
        port: &ResourceProviderPort,
        scope: &ResourceScope,
    ) -> ControlValue {
        ControlValue {
            key,
            dropped: Arc::clone(dropped),
            _retention: port
                .acquire(scope, ResourceAuthorityClass::Admitted, control_retention())
                .expect("the control grant funds this value's retention"),
        }
    }

    /// Keys are found by order regardless of insertion order, and a key that
    /// was never inserted is not found.
    ///
    /// The insertion order is deliberately not sorted: a structure that ignored
    /// its priorities and simply chained entries would still answer these
    /// lookups, so the negative and the count below are what make it a test of
    /// an ordered map rather than of a list.
    #[test]
    fn v4_arc05_entries_are_found_by_key_whatever_order_they_arrived_in() {
        let dropped = drop_log();
        let (_provider, port, scope) = control_provider(5);
        let mut map = LeasedMap::new();
        for key in [30_u32, 10, 50, 20, 40] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }

        assert_eq!(map.len(), 5);
        for key in [10_u32, 20, 30, 40, 50] {
            assert_eq!(map.get(&key).map(|value| value.key), Some(key));
            assert!(map.contains_key(&key));
            assert_eq!(map.get_key_value(&key).map(|(key, _)| *key), Some(key));
        }
        assert!(map.get(&35).is_none(), "a key never inserted is not found");
        assert!(!map.contains_key(&35));
    }

    /// A duplicate key is refused, and the refusal retains nothing.
    #[test]
    fn v4_arc05_a_duplicate_key_is_refused_and_its_funding_goes_back() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(2);
        let mut map = LeasedMap::new();
        assert!(map
            .insert(
                7_u32,
                control_value(7, &dropped, &port, &scope),
                control_lease(&port, &scope),
            )
            .is_ok());
        let held = provider.in_use();

        let refused = map.insert(
            7_u32,
            control_value(700, &dropped, &port, &scope),
            control_lease(&port, &scope),
        );
        assert!(refused.is_err(), "the live entry is not replaced");
        drop(refused);

        assert_eq!(
            provider.in_use(),
            held,
            "the refused entry's funding went back, so a caller that retries \
             forever retains nothing"
        );
        assert_eq!(map.len(), 1);
        assert_eq!(
            dropped
                .lock()
                .expect("the control drop log is uncontended")
                .as_slice(),
            [700],
            "the refused value was destroyed and the live one was not"
        );
    }

    /// Removing one entry releases exactly that entry's node and lease, and
    /// leaves the rest of the map intact and still funded.
    #[test]
    fn v4_arc05_removing_one_entry_releases_exactly_that_entrys_funding() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(4);
        let mut map = LeasedMap::new();
        for key in [1_u32, 2, 3] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }
        let full = provider.in_use();

        let removed = map.remove(&2).expect("the entry was there");
        assert_eq!(removed.key, 2);
        let after_node_removal = provider.in_use();
        assert_eq!(
            after_node_removal.amount(ResourceClass::QueuedBytes),
            full.amount(ResourceClass::QueuedBytes),
            "the returned value keeps its own retention funded"
        );
        drop(removed);

        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            full.amount(ResourceClass::QueuedBytes)
                - control_retention().amount(ResourceClass::QueuedBytes),
            "exactly one entry's retention was released — not a share of a \
             shared node, and not nothing"
        );
        assert_eq!(map.len(), 2);
        assert!(map.get(&2).is_none());
        assert!(map.contains_key(&1) && map.contains_key(&3));

        // The provider funds four entries at a time, and three were taken, so
        // the fourth admits only because the removal really gave one back.
        assert!(map
            .insert(
                4_u32,
                control_value(4, &dropped, &port, &scope),
                control_lease(&port, &scope),
            )
            .is_ok());
    }

    /// A teardown can take every owned record without first allocating a key
    /// snapshot, and the returned value keeps its independent retention alive
    /// after the map node has gone.
    #[test]
    fn v4_f1_c_pop_first_drains_owned_records_without_a_key_snapshot() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(3);
        let mut map = LeasedMap::new();
        for key in [30_u32, 10, 20] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }

        let full = provider.in_use();
        let node_charge =
            FiniteResourceProvider::reservation_charge_for_test(control_entry_claim())
                .expect("the production reservation charge is representable");
        let retention_charge =
            FiniteResourceProvider::reservation_charge_for_test(control_retention())
                .expect("the production reservation charge is representable");

        for (index, expected_key) in [10_u32, 20, 30].into_iter().enumerate() {
            let (key, value) = map
                .pop_first_entry()
                .expect("one owned record remains to drain");
            assert_eq!(key, expected_key, "the ordered first record is removed");
            assert_eq!(value.key, expected_key);
            assert_eq!(map.len(), 2 - index);

            let released_nodes = node_charge
                .checked_scale((index + 1) as u64)
                .expect("the node release total is representable");
            let previously_released_values = retention_charge
                .checked_scale(index as u64)
                .expect("the prior retention release total is representable");
            assert_eq!(
                provider.in_use(),
                full.checked_sub(released_nodes)
                    .and_then(|use_| use_.checked_sub(previously_released_values))
                    .expect("the live use contains the previously released charges"),
                "the map node is gone while the returned value's retention is still funded"
            );
            drop(value);

            let released_values = retention_charge
                .checked_scale((index + 1) as u64)
                .expect("the retention release total is representable");
            assert_eq!(
                provider.in_use(),
                full.checked_sub(released_nodes)
                    .and_then(|use_| use_.checked_sub(released_values))
                    .expect("the live use contains the removed record charges"),
                "dropping the owned value releases exactly its independent retention"
            );
        }
        assert!(map.pop_first_entry().is_none());
    }

    /// A conditional cleanup detaches only matching entries, without cloning a
    /// key or reacquiring nodes for the entries it must leave behind.
    #[test]
    fn v4_f1_d_pop_first_where_preserves_every_unmatched_funded_record() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(5);
        let mut map = LeasedMap::new();
        for key in [5_u32, 2, 4, 1, 3] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }
        let full = provider.in_use();
        // The first matching entry is determined by key order, not insertion
        // order. Holding the returned value proves its independent retention
        // survives the node removal.
        let (key, value) = map
            .pop_first_where(|key, _| *key % 2 == 0)
            .expect("one even entry exists");
        assert_eq!(key, 2);
        assert_eq!(value.key, 2);
        assert_eq!(map.len(), 4);
        assert!(map.contains_key(&1));
        assert!(map.contains_key(&3));
        assert!(map.contains_key(&4));
        assert!(map.contains_key(&5));

        // The node and value are independent reservations, so compute their
        // release separately rather than pretending one combined reservation
        // has the same provider bookkeeping.
        let node_charge =
            FiniteResourceProvider::reservation_charge_for_test(control_entry_claim())
                .expect("the node charge is representable");
        assert_eq!(
            provider.in_use(),
            full.checked_sub(node_charge)
                .expect("the full use contains one node charge"),
            "the matching node is gone while its returned value stays funded"
        );
        drop(value);
        let retention_charge =
            FiniteResourceProvider::reservation_charge_for_test(control_retention())
                .expect("the retention charge is representable");
        assert_eq!(
            provider.in_use(),
            full.checked_sub(node_charge)
                .and_then(|use_| use_.checked_sub(retention_charge))
                .expect("the full use contains the removed record's two charges"),
            "dropping the returned value releases only its own retention"
        );

        let (key, value) = map
            .pop_first_where(|key, _| *key % 2 == 0)
            .expect("the second even entry exists");
        assert_eq!(key, 4);
        drop(value);
        assert!(map.pop_first_where(|key, _| *key % 2 == 0).is_none());
        assert_eq!(map.len(), 3);
        assert_eq!(map.get(&1).map(|value| value.key), Some(1));
        assert_eq!(map.get(&3).map(|value| value.key), Some(3));
        assert_eq!(map.get(&5).map(|value| value.key), Some(5));
    }

    /// Dropping the map drops every entry and releases every entry's funding.
    #[test]
    fn v4_arc05_dropping_the_map_drops_and_releases_every_entry() {
        let dropped = drop_log();
        let (provider, port, scope) = control_provider(5);
        let mut map = LeasedMap::new();
        for key in [30_u32, 10, 50, 20, 40] {
            assert!(map
                .insert(
                    key,
                    control_value(key, &dropped, &port, &scope),
                    control_lease(&port, &scope),
                )
                .is_ok());
        }
        assert!(dropped
            .lock()
            .expect("the control drop log is uncontended")
            .is_empty());

        drop(map);

        let mut destroyed = dropped
            .lock()
            .expect("the control drop log is uncontended")
            .clone();
        destroyed.sort_unstable();
        assert_eq!(
            destroyed,
            vec![10, 20, 30, 40, 50],
            "every entry's own drop ran"
        );
        assert_eq!(
            provider.in_use().amount(ResourceClass::QueuedBytes),
            0,
            "no entry's retention outlived the map that held it"
        );
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            0,
            "no entry's node bytes outlived the map that held it"
        );

        // The third dimension needs the scope gone before it can be asserted at
        // zero, and that is a property of the provider rather than a hedge: the
        // residual dimension is also where the provider records its own scope,
        // so a live scope holds one legitimately. Tearing the scope down after
        // the map lets the assertion be a plain zero instead of an arithmetic
        // that would quietly still pass if a node's residual leaked.
        drop(scope);
        drop(port);
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::OpaqueDependencyResidual),
            0,
            "no entry's allocation residual outlived the map that held it"
        );
    }

    /// The ordered cursor answers the exact lower bound, and the greatest key.
    ///
    /// Every clause is a way a successor walk is got wrong. Strictness, so a
    /// caller resuming after the entry it just handled is not handed that same
    /// entry again forever. An absent cursor key, because a caller's cursor
    /// names an entry that may have been removed since — the answer must be the
    /// next live key, not nothing. Past the end, because a pass has to finish.
    /// And `None` for the cursor answering the least key, because that is what
    /// lets one pass be a single operation repeated rather than a first-entry
    /// call followed by a different one.
    ///
    /// The keys are inserted out of order so nothing here would pass against a
    /// structure that ignored its priorities and chained entries in arrival
    /// order.
    #[test]
    fn v4_r3_core_the_ordered_cursor_answers_the_exact_lower_bound() {
        let dropped = drop_log();
        let (_provider, port, scope) = control_provider(4);
        let mut map: LeasedMap<u32, ControlValue> = LeasedMap::new();

        assert!(
            map.successor_after(None).is_none(),
            "an empty map has no least key"
        );
        assert!(map.last_key_value().is_none(), "and no greatest key either");

        for key in [30u32, 10, 40, 20] {
            map.insert(
                key,
                control_value(key, &dropped, &port, &scope),
                control_lease(&port, &scope),
            )
            .expect("the control grant funds this entry");
        }

        let key_after = |map: &LeasedMap<u32, ControlValue>, after: Option<u32>| {
            map.successor_after(after.as_ref()).map(|(key, _)| *key)
        };

        assert_eq!(
            key_after(&map, None),
            Some(10),
            "no cursor answers the least"
        );
        assert_eq!(
            key_after(&map, Some(10)),
            Some(20),
            "the successor is strictly greater, so a cursor cannot answer itself"
        );
        assert_eq!(
            key_after(&map, Some(25)),
            Some(30),
            "a cursor naming no live entry still answers the next live one"
        );
        assert_eq!(
            key_after(&map, Some(40)),
            None,
            "and the last has no successor"
        );
        assert_eq!(
            key_after(&map, Some(41)),
            None,
            "nor does a cursor past every entry"
        );
        assert_eq!(
            map.last_key_value().map(|(key, _)| *key),
            Some(40),
            "the greatest key is the greatest, not the last inserted"
        );

        // The bound follows the map rather than being remembered from the walk
        // that established it.
        map.remove(&40).expect("the greatest entry is removed");
        assert_eq!(map.last_key_value().map(|(key, _)| *key), Some(30));
        assert_eq!(key_after(&map, Some(30)), None);
    }

    /// One ordered pass costs one descent per step, not one traversal per step.
    ///
    /// **The counter is the observation and it is exact.** `CountedKey` counts
    /// every order comparison the map makes, so what is asserted is work the
    /// implementation really did rather than elapsed time or an inspection of
    /// its shape. A pass driven by a complete walk per step — which is what a
    /// caller resuming through `for_each` performs — compares at least once per
    /// live entry on every step, so `n` steps cost at least `n * n`. The bound
    /// below is far under that and comfortably over one descent per step.
    ///
    /// `1024` entries make the two shapes separate by more than an order of
    /// magnitude: a per-step traversal costs at least 1_048_576 comparisons,
    /// while a descent costs the tree's depth — expected near fourteen — for a
    /// pass total near 14_000. The assertion is set at 32_768 so it is neither
    /// a restatement of the expected figure nor reachable by the shape it
    /// excludes, and so a randomized treap's depth variation cannot reach it.
    ///
    /// Asking is also free of the provider: the ledger is read on both sides of
    /// the pass and must not move, because a borrowed cursor that allocated or
    /// released would be doing something a caller holding a lock did not ask
    /// for.
    #[test]
    fn v4_r3_core_an_ordered_pass_walks_one_descent_per_step() {
        use std::hash::Hasher;
        use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};

        /// A key that reports how often the map compared it.
        #[derive(Clone)]
        struct CountedKey {
            key: u32,
            compares: Arc<AtomicUsize>,
        }

        impl PartialEq for CountedKey {
            fn eq(&self, other: &Self) -> bool {
                self.cmp(other).is_eq()
            }
        }
        impl Eq for CountedKey {}
        impl PartialOrd for CountedKey {
            fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
                Some(self.cmp(other))
            }
        }
        impl Ord for CountedKey {
            fn cmp(&self, other: &Self) -> Ordering {
                self.compares.fetch_add(1, AtomicOrdering::Relaxed);
                self.key.cmp(&other.key)
            }
        }
        // Hashed by the ordering key alone: the counter is instrumentation and
        // must not make two equal keys hash differently.
        impl std::hash::Hash for CountedKey {
            fn hash<H: Hasher>(&self, state: &mut H) {
                self.key.hash(state);
            }
        }

        const ENTRIES: u32 = 1024;
        const COMPARISON_CEILING: usize = 32 * ENTRIES as usize;

        let entry = LeasedMap::<CountedKey, u32>::entry_claim()
            .expect("the counted entry claim is representable");
        let scope_record = FiniteResourceProvider::scope_record_charge_for_test();
        let node = entry
            .checked_add(scope_record)
            .expect("the counted entry plus its reservation record is representable");
        let grant = (0..ENTRIES)
            .try_fold(scope_record, |total, _| total.checked_add(node))
            .expect("the bounded counted grant is representable");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone())
            .expect("the counted grant accounts for the process scope");
        let scope = port.process_scope();

        let compares = Arc::new(AtomicUsize::new(0));
        let mut map: LeasedMap<CountedKey, u32> = LeasedMap::new();
        // Arrival order is scrambled by an odd stride over a power-of-two ring,
        // which visits every key exactly once and in no useful order.
        for step in 0..ENTRIES {
            let key = step.wrapping_mul(613) % ENTRIES;
            map.insert(
                CountedKey {
                    key,
                    compares: Arc::clone(&compares),
                },
                key,
                port.acquire(&scope, ResourceAuthorityClass::Admitted, entry)
                    .expect("the counted grant funds this entry"),
            )
            .expect("every key in the ring is distinct");
        }

        // Read per dimension rather than as a whole claim: the claim type is
        // deliberately not `Debug`, and naming the two dimensions an entry
        // actually moves says what a drift would have been.
        let held = |provider: &FiniteResourceProvider| {
            (
                provider
                    .in_use()
                    .amount(ResourceClass::AccountedMemoryBytes),
                provider
                    .in_use()
                    .amount(ResourceClass::OpaqueDependencyResidual),
            )
        };
        let before = held(&provider);
        // Only the pass is measured. Building the map compared too, and those
        // comparisons are not what this control is about.
        compares.store(0, AtomicOrdering::Relaxed);

        let mut cursor: Option<CountedKey> = None;
        let mut seen = 0usize;
        let mut previous: Option<u32> = None;
        loop {
            let Some((key, value)) = map.successor_after(cursor.as_ref()) else {
                break;
            };
            assert_eq!(
                key.key, *value,
                "the cursor answers a key with its own value"
            );
            if let Some(previous) = previous {
                assert!(
                    key.key > previous,
                    "the pass is strictly increasing, so nothing is revisited: \
                     {previous} then {}",
                    key.key
                );
            }
            previous = Some(key.key);
            seen += 1;
            cursor = Some(key.clone());
        }

        assert_eq!(
            seen, ENTRIES as usize,
            "non-vacuity: the pass reached every entry exactly once"
        );
        let walked = compares.load(AtomicOrdering::Relaxed);
        assert!(
            walked > 0,
            "non-vacuity: the pass really did compare keys, so the ceiling below \
             is a bound on work that happened"
        );
        assert!(
            walked < COMPARISON_CEILING,
            "one ordered pass over {ENTRIES} entries compared {walked} times; a \
             traversal-per-step shape costs at least {} and this ceiling is \
             {COMPARISON_CEILING}",
            ENTRIES as usize * ENTRIES as usize
        );
        assert_eq!(
            held(&provider),
            before,
            "and the pass acquired and released nothing: a borrowed cursor is \
             not an allocation the caller has to fund"
        );
    }
}
