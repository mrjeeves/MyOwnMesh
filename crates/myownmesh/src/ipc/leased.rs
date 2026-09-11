//! Storage whose funding has the same owner and outlives the allocation it pays
//! for.
//!
//! Every cleanup path in this daemon hands something back to a caller that can
//! do what the registry cannot — release a core registration, retire a route,
//! close a flow through its network. Those hand-backs are collections, and a
//! collection is an allocation the daemon holds on a client's behalf, so it has
//! to be admitted like everything else.
//!
//! **Why not a `Vec`, and why not a `LinkedList`.** Both are untrue in the same
//! two ways. A `Vec`'s buffer is sized by *capacity*, not by length, so
//! geometric growth retains slots that no entry ever paid for, and extra opaque
//! residuals do not fund missing bytes — resource classes are not
//! interchangeable. And both destroy their elements before they free the storage
//! those elements sat in: `Vec`'s `Drop` runs every element's drop glue and then
//! deallocates one shared buffer, and a `LinkedList` node's drop glue runs
//! *inside* the node's own allocation.
//!
//! **And why the lease is not in the node either.** A lease stored inside a
//! `Box` is released by that `Box`'s drop glue, which runs *before* the
//! allocation is freed. Field declaration order cannot fix it: deallocation is
//! not a field drop and does not participate in that order at all. So the lease
//! lives one level out, in a wrapper that owns the `Box` — the wrapper's own
//! field order then does hold, because both halves really are fields. The `Box`
//! is dropped first and frees the node; the lease is released after it.

use myownmesh_core::{ResourceClaim, ResourceClaimArithmeticError, ResourceClass, ResourceLease};

/// One item and the link to the next.
///
/// Everything in here lives inside one heap allocation, which is the allocation
/// [`FundedNode`]'s lease pays for. Nothing that funds that allocation may live
/// in here — see the module note.
struct LeasedListNode<T> {
    value: T,
    next: Option<FundedNode<T>>,
}

/// One node's allocation, and the lease that funds it, in that nesting.
///
/// The nesting *is* the ordering. Dropping this drops `node` first — which runs
/// the item's own drop glue and then frees the node's allocation — and releases
/// `_entry` second. Both are fields of the same struct, so declaration order is
/// the drop order and the guarantee is the language's rather than an allocator
/// detail's.
///
/// Written the other way round, with the lease inside the `Box`, the provider
/// would be told the node's bytes were free while the node still occupied them.
/// That is the exact false exact-release claim this whole module exists to
/// remove, so it must not be reintroduced by moving this field one level in.
struct FundedNode<T> {
    node: Box<LeasedListNode<T>>,
    /// Covers only this node's allocation. Any off-node retention in the item
    /// owns a separate lease inside the item.
    _entry: ResourceLease,
}

/// A list whose every item is separately funded, in advance, by whoever will one
/// day be swept into it.
///
/// **Order is unspecified and nothing may depend on it.** Removal order is the
/// reverse of insertion, because that is what costs nothing; every caller here
/// is draining an obligation set — registrations to release, routes to retire,
/// flows to close, connection tasks to join — where the obligations are
/// independent. A caller that needed an order would need a different type, and
/// would have to say why.
pub(crate) struct LeasedList<T> {
    head: Option<FundedNode<T>>,
    len: usize,
}

/// Dropping the list drops every item it still holds, each in the same order a
/// removal would.
///
/// Written out rather than derived because the derived drop is recursive: it
/// would descend one stack frame per item, and a list long enough to be worth
/// accounting is long enough to overflow the stack while being freed. Unlinking
/// first means every wrapper is dropped with an empty `next`, so the recursion
/// is flattened *and* each wrapper's two-step order — free the node, then
/// release its lease — is the one [`FundedNode`] describes.
impl<T> Drop for LeasedList<T> {
    fn drop(&mut self) {
        let mut cursor = self.head.take();
        while let Some(mut funded) = cursor {
            cursor = funded.node.next.take();
            // `funded` drops here with an empty link: its `Box` frees the node's
            // allocation, and only then is `_entry` released.
        }
    }
}

impl<T> Default for LeasedList<T> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T> LeasedList<T> {
    pub(crate) const fn new() -> Self {
        Self { head: None, len: 0 }
    }

    /// Everything one item costs: exactly this list's node.
    ///
    /// The single calibration point, and the reason a caller never writes a node
    /// size itself. `size_of` over the concrete node type already includes the
    /// item inline and the link — and the link is a [`FundedNode`], so the
    /// wrapper's pointer and lease handle are counted with it. The residual is 1
    /// because the node is exactly one allocation, and unlike a shared buffer's
    /// slot that residual is released at the moment the node is.
    ///
    /// Anything the item retains off-node owns a separate lease inside the item.
    /// That separation is load-bearing: [`Self::pop`] releases the removed node
    /// before returning the item, while the returned item may stay live for
    /// arbitrarily longer. A combined lease would tell the provider that the
    /// item's retention had ended while the caller still owned it.
    #[must_use = "the node claim must be acquired before the item is pushed"]
    pub(crate) fn node_claim() -> Result<ResourceClaim, ResourceClaimArithmeticError> {
        let record_bytes =
            u64::try_from(std::mem::size_of::<LeasedListNode<T>>()).map_err(|_| {
                ResourceClaimArithmeticError::Overflow {
                    dimension: ResourceClass::AccountedMemoryBytes,
                }
            })?;
        ResourceClaim::try_from_entries([
            (ResourceClass::AccountedMemoryBytes, record_bytes),
            (ResourceClass::OpaqueDependencyResidual, 1),
        ])
    }

    /// Add one item, which now owns the lease that funded it.
    ///
    /// Infallible on purpose: the decision was made when the lease was acquired,
    /// which for the cleanup paths is when the entry being swept was installed.
    /// A push that could still fail would leave a disconnect path with no honest
    /// answer — it cannot decline to clean up.
    pub(crate) fn push(&mut self, value: T, entry: ResourceLease) {
        self.head = Some(FundedNode {
            node: Box::new(LeasedListNode {
                value,
                next: self.head.take(),
            }),
            _entry: entry,
        });
        self.len = self
            .len
            .checked_add(1)
            .expect("one list cannot hold more items than the address space has bytes");
    }

    /// Remove one item, releasing only its node's funding.
    pub(crate) fn pop(&mut self) -> Option<T> {
        let mut funded = self.head.take()?;
        self.head = funded.node.next.take();
        // Reached only after a node really came off the chain, so this cannot
        // underflow unless the count and the chain have already diverged --
        // which is the thing worth failing on rather than absorbing.
        self.len = self
            .len
            .checked_sub(1)
            .expect("an item was removed, so the count was not zero");
        Some(Self::take_value(funded))
    }

    /// Whether anything is still held.
    pub(crate) fn is_empty(&self) -> bool {
        self.head.is_none()
    }

    /// How many funded nodes the list currently owns.
    ///
    /// Resource capacity is still bounded by the grant, not this count. The
    /// production connection reaper needs the count only after it splits out
    /// finished handles, to retire the same number from its completion signal;
    /// controls use it to assert exact movement between lists.
    pub(crate) const fn len(&self) -> usize {
        self.len
    }

    /// Move every item `ready` accepts into a list of its own, funding included.
    ///
    /// One pass, and no allocation: a matched wrapper is *relinked* into the
    /// answer, so its node and the lease that funds it never move and never
    /// briefly disagree. The caller then drains the answer at its own pace —
    /// which for the control runtime's accepted connections means awaiting each
    /// handle, work that must not happen inside a walk of the list it came from.
    ///
    /// Split rather than removed-one-at-a-time because the caller wants all of
    /// them: repeating a single-removal walk would be a fresh traversal per
    /// item, and the whole reason this exists is that the caller reaps a batch.
    pub(crate) fn split_where(&mut self, mut ready: impl FnMut(&mut T) -> bool) -> Self {
        let mut source = self.head.take();
        let mut kept: Option<FundedNode<T>> = None;
        let mut taken: Option<FundedNode<T>> = None;
        let mut moved = 0usize;
        while let Some(mut funded) = source {
            source = funded.node.next.take();
            if ready(&mut funded.node.value) {
                funded.node.next = taken.take();
                taken = Some(funded);
                moved += 1;
            } else {
                funded.node.next = kept.take();
                kept = Some(funded);
            }
        }
        self.head = kept;
        self.len = self
            .len
            .checked_sub(moved)
            .expect("no more items were moved than the chain held");
        Self {
            head: taken,
            len: moved,
        }
    }

    /// Free one wrapper's node and release its lease, in that order, answering
    /// the item.
    ///
    /// Spelled once so every removal path has the same order and there is one
    /// place to read it. `*node` moves the item out and frees the allocation;
    /// `_entry` is released on the line after, when there is nothing left for it
    /// to be funding.
    fn take_value(funded: FundedNode<T>) -> T {
        let FundedNode { node, _entry } = funded;
        let LeasedListNode { value, .. } = *node;
        drop(_entry);
        value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes this provider holds beyond `baseline`.
    ///
    /// Every assertion in this module is a delta rather than an absolute, so
    /// none of them depends on which dimensions the provider's own bookkeeping
    /// happens to touch. `saturating_sub` because this runs inside a `Drop`,
    /// where a panic during an unwind is an abort: an impossible reading should
    /// fail the assertion that reads it, not take the process down.
    fn charged(provider: &myownmesh_core::FiniteResourceProvider, baseline: u64) -> u64 {
        provider
            .in_use()
            .amount(ResourceClass::AccountedMemoryBytes)
            .saturating_sub(baseline)
    }

    /// A provider granting exactly `nodes` list nodes, the port that spends it,
    /// and what that port had already charged before any node existed.
    ///
    /// Exact rather than generous, so what the ledger says while an item is
    /// being destroyed is attributable to that item's node and not to slack the
    /// fixture happened to have. Exact means *including the provider's own
    /// records*: it charges one for the process scope and one per reservation,
    /// and both are asked of core rather than restated here. Locally owned and
    /// installed nowhere — it races no other control in this binary and starves
    /// nothing.
    fn node_grant(
        nodes: u64,
    ) -> (
        myownmesh_core::FiniteResourceProvider,
        myownmesh_core::ResourceProviderPort,
        myownmesh_core::ResourceScope,
        u64,
    ) {
        // Asked of core rather than restated here. The provider retains a
        // bookkeeping record per reservation and one for the scope, so a grant
        // sized to the node claims alone is short by one residual per node plus
        // one -- and short in a residual, which refuses a *later* acquisition
        // than the one that was underfunded, so the fixture would fail somewhere
        // other than where it was wrong. A figure restated on this side would be
        // a second answer to a question core already answers, which is the exact
        // drift this crate's accounting notes are written against.
        let node = LeasedList::<Probe>::node_claim().expect("the node claim is representable");
        let claim = myownmesh_core::FiniteResourceProvider::reservation_planning_charge(node)
            .expect("a node reservation is representable")
            .checked_scale(nodes)
            .expect("the fixture grant is representable")
            .checked_add(myownmesh_core::FiniteResourceProvider::scope_planning_charge())
            .expect("the process scope record is representable");
        let provider = myownmesh_core::FiniteResourceProvider::new(claim);
        let port = myownmesh_core::ResourceProviderPort::new(provider.clone())
            .expect("the fixture grant funds its own process scope");
        let scope = port.process_scope();
        // Read after the port, because opening the process scope is itself a
        // charge against this grant.
        let baseline = charged(&provider, 0);
        (provider, port, scope, baseline)
    }

    /// One node's funding, from the fixture's own port.
    fn node_lease(
        port: &myownmesh_core::ResourceProviderPort,
        scope: &myownmesh_core::ResourceScope,
    ) -> myownmesh_core::ResourceLease {
        port.acquire(
            scope,
            myownmesh_core::ResourceAuthorityClass::Admitted,
            LeasedList::<Probe>::node_claim().expect("the node claim is representable"),
        )
        .expect("the fixture grant funds this node")
    }

    /// An item that reports what the provider still held at the instant it was
    /// destroyed.
    ///
    /// This is the observation. The item's own drop glue runs *inside* the
    /// node's allocation — it is the first half of freeing that node — so a
    /// ledger that still shows the node's bytes here is a ledger that had not
    /// released the node lease before the allocation went. The remaining step,
    /// that the lease outlives the deallocation itself, is structural rather
    /// than observable in safe Rust: the lease is a field of [`FundedNode`] and
    /// the `Box` is the field before it, so no drop glue inside the `Box` can
    /// reach it. Moving that field one level in is what this control cannot
    /// catch and the module note is written against.
    struct Probe {
        charged_while_dropping: std::sync::Arc<std::sync::Mutex<Vec<u64>>>,
        provider: myownmesh_core::FiniteResourceProvider,
        /// What the grant already held before the first node, so what this
        /// records is nodes and nothing else.
        baseline: u64,
    }

    impl Drop for Probe {
        fn drop(&mut self) {
            let held = charged(&self.provider, self.baseline);
            self.charged_while_dropping
                .lock()
                .expect("the probe log is not poisoned")
                .push(held);
        }
    }

    /// The node bytes for one item, as this list charges them.
    fn node_bytes() -> u64 {
        LeasedList::<Probe>::node_claim()
            .expect("the node claim is representable")
            .amount(ResourceClass::AccountedMemoryBytes)
    }

    /// Every removal path keeps a node's funding live until the node is gone.
    ///
    /// Three paths, because there are three and they are easy to fix one at a
    /// time: `pop`, `split_where` followed by draining the answer, and dropping
    /// the whole list with items still in it. The last is the one that was
    /// wrong: an iterative unlink that let each `Box` drop normally released the
    /// lease inside the node before the node's allocation was freed.
    #[test]
    fn v4_r2_daemon_every_removal_holds_a_node_lease_until_its_node_is_gone() {
        for path in ["pop", "split", "drop"] {
            let (provider, port, scope, baseline) = node_grant(3);
            let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
            let mut list = LeasedList::<Probe>::new();
            for _ in 0..3 {
                let entry = node_lease(&port, &scope);
                list.push(
                    Probe {
                        charged_while_dropping: log.clone(),
                        provider: provider.clone(),
                        baseline,
                    },
                    entry,
                );
            }
            assert_eq!(
                charged(&provider, baseline),
                3 * node_bytes(),
                "{path}: non-vacuity — three funded nodes are held before anything is removed"
            );

            match path {
                "pop" => {
                    while let Some(item) = list.pop() {
                        assert_eq!(
                            charged(&provider, baseline),
                            u64::try_from(list.len()).expect("the list length fits") * node_bytes(),
                            "pop frees and releases the removed node before handing its item back"
                        );
                        drop(item);
                    }
                }
                "split" => {
                    let mut finished = list.split_where(|_| true);
                    assert_eq!(finished.len(), 3, "split moves every matching item");
                    assert_eq!(list.len(), 0, "and leaves none behind");
                    while let Some(item) = finished.pop() {
                        assert_eq!(
                            charged(&provider, baseline),
                            u64::try_from(finished.len()).expect("the list length fits")
                                * node_bytes(),
                            "split keeps every moved node funded until that answer pops it"
                        );
                        drop(item);
                    }
                }
                _ => drop(list),
            }

            let observed = log.lock().expect("the probe log is not poisoned").clone();
            assert_eq!(
                observed.len(),
                3,
                "{path}: every item was destroyed exactly once"
            );
            // Whole-list teardown destroys each value inside its allocation, so
            // its probe sees its own node plus those not yet removed. `pop`
            // moves the value out and deliberately frees and releases its node
            // before returning it, so those probes see only the remaining nodes.
            let expected = if path == "drop" {
                vec![3 * node_bytes(), 2 * node_bytes(), node_bytes()]
            } else {
                vec![2 * node_bytes(), node_bytes(), 0]
            };
            assert_eq!(
                observed, expected,
                "{path}: the ledger reflects the path's exact ownership point"
            );
            assert_eq!(
                charged(&provider, baseline),
                0,
                "{path}: and every node's funding is returned once the list is empty"
            );
        }
    }

    /// A split answers only what the predicate accepted, and keeps the rest
    /// funded where it was.
    #[test]
    fn v4_r2_daemon_a_split_moves_matching_nodes_without_touching_the_others() {
        let (provider, port, scope, baseline) = node_grant(4);
        let log = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let mut list = LeasedList::<Probe>::new();
        for _ in 0..4 {
            let entry = node_lease(&port, &scope);
            list.push(
                Probe {
                    charged_while_dropping: log.clone(),
                    provider: provider.clone(),
                    baseline,
                },
                entry,
            );
        }
        // Every other one, so the answer is neither the whole list nor a
        // contiguous run of it.
        let mut seen = 0;
        let taken = list.split_where(|_| {
            seen += 1;
            seen % 2 == 0
        });
        assert_eq!(taken.len(), 2);
        assert_eq!(list.len(), 2);
        assert_eq!(
            charged(&provider, baseline),
            4 * node_bytes(),
            "nothing was released by the split itself: the nodes moved, and their \
             leases moved with them"
        );
        drop(taken);
        assert_eq!(
            charged(&provider, baseline),
            2 * node_bytes(),
            "and only the moved half is returned when the answer is dropped"
        );
    }
}
