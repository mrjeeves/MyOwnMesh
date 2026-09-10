//! Generic, connector-neutral resource admission primitives.
//!
//! A [`ResourceProviderPort`] is the authority-bearing entry point. It mints
//! process-local scopes, but scope creation does not mint capacity. Capacity
//! enters through the provider selected by the process owner, and every
//! successful acquisition is represented by one non-cloneable
//! [`ResourceLease`].

use std::collections::BTreeSet;
use std::fmt;
use std::num::NonZeroU64;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, Weak};

/// Number of independent dimensions in a [`ResourceClaim`].
pub const RESOURCE_CLASS_COUNT: usize = 11;

/// Connector-neutral resource dimensions understood by the admission spine.
///
/// Each value is an ordinary finite quantity. No value, including `u64::MAX`,
/// means unlimited.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(usize)]
pub enum ResourceClass {
    AccountedMemoryBytes,
    QueuedBytes,
    SocketOrHandle,
    NativeTransportObject,
    WorkerOrTask,
    CallbackOrScheduledWork,
    StorageBytes,
    StorageObject,
    RelayOrProviderAllocation,
    ParsingOrCpuWork,
    OpaqueDependencyResidual,
}

impl ResourceClass {
    pub const ALL: [Self; RESOURCE_CLASS_COUNT] = [
        Self::AccountedMemoryBytes,
        Self::QueuedBytes,
        Self::SocketOrHandle,
        Self::NativeTransportObject,
        Self::WorkerOrTask,
        Self::CallbackOrScheduledWork,
        Self::StorageBytes,
        Self::StorageObject,
        Self::RelayOrProviderAllocation,
        Self::ParsingOrCpuWork,
        Self::OpaqueDependencyResidual,
    ];

    const fn index(self) -> usize {
        self as usize
    }
}

/// A finite, composite resource quantity.
///
/// The representation has no unlimited sentinel. Composite construction and
/// arithmetic report the exact dimension that overflowed or underflowed.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceClaim {
    amounts: [u64; RESOURCE_CLASS_COUNT],
}

impl ResourceClaim {
    pub const ZERO: Self = Self {
        amounts: [0; RESOURCE_CLASS_COUNT],
    };

    pub const fn single(dimension: ResourceClass, amount: u64) -> Self {
        let mut amounts = [0; RESOURCE_CLASS_COUNT];
        amounts[dimension.index()] = amount;
        Self { amounts }
    }

    pub fn try_from_entries(
        entries: impl IntoIterator<Item = (ResourceClass, u64)>,
    ) -> Result<Self, ResourceClaimArithmeticError> {
        let mut claim = Self::ZERO;
        for (dimension, amount) in entries {
            claim.amounts[dimension.index()] = claim
                .amount(dimension)
                .checked_add(amount)
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(claim)
    }

    pub const fn amount(self, dimension: ResourceClass) -> u64 {
        self.amounts[dimension.index()]
    }

    pub fn checked_add(self, other: Self) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_add(other.amount(dimension))
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(result)
    }

    pub fn checked_sub(self, other: Self) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_sub(other.amount(dimension))
                .ok_or(ResourceClaimArithmeticError::Underflow { dimension })?;
        }
        Ok(result)
    }

    /// Multiply every resource dimension by an explicit finite factor.
    ///
    /// This is claim arithmetic only. It creates no lease, capacity, object
    /// count, or unlimited sentinel.
    pub fn checked_scale(self, factor: u64) -> Result<Self, ResourceClaimArithmeticError> {
        let mut result = Self::ZERO;
        for dimension in ResourceClass::ALL {
            result.amounts[dimension.index()] = self
                .amount(dimension)
                .checked_mul(factor)
                .ok_or(ResourceClaimArithmeticError::Overflow { dimension })?;
        }
        Ok(result)
    }

    pub fn is_zero(self) -> bool {
        self.amounts.iter().all(|amount| *amount == 0)
    }
}

impl Default for ResourceClaim {
    fn default() -> Self {
        Self::ZERO
    }
}

impl fmt::Debug for ResourceClaim {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut map = formatter.debug_map();
        for dimension in ResourceClass::ALL {
            let amount = self.amount(dimension);
            if amount != 0 {
                map.entry(&dimension, &amount);
            }
        }
        map.finish()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceClaimArithmeticError {
    Overflow { dimension: ResourceClass },
    Underflow { dimension: ResourceClass },
}

impl fmt::Display for ResourceClaimArithmeticError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Overflow { dimension } => {
                write!(formatter, "resource claim overflow in {dimension:?}")
            }
            Self::Underflow { dimension } => {
                write!(formatter, "resource claim underflow in {dimension:?}")
            }
        }
    }
}

impl std::error::Error for ResourceClaimArithmeticError {}

/// A process-local scope identifier minted by one provider port.
///
/// The numeric value is diagnostic only. It carries no capacity and is not a
/// durable identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ResourceScopeId(NonZeroU64);

impl ResourceScopeId {
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

struct ResourceScopeInner {
    id: ResourceScopeId,
    _identity: Arc<ResourceScopeIdentity>,
    parent: Option<ResourceScope>,
    port: Weak<ResourceProviderPortInner>,
    provider: Arc<dyn ResourceProvider>,
    provider_authority: Arc<ResourceProviderAuthority>,
    registered: AtomicBool,
}

#[derive(Debug)]
struct ResourceScopeIdentity {
    _owned: u8,
}

fn scope_identity() -> (Arc<ResourceScopeIdentity>, ResourceScopeId) {
    let identity = Arc::new(ResourceScopeIdentity { _owned: 0 });
    let address = Arc::as_ptr(&identity) as usize as u64;
    let id = ResourceScopeId(
        NonZeroU64::new(address).expect("an allocated resource-scope identity is nonzero"),
    );
    (identity, id)
}

impl Drop for ResourceScopeInner {
    fn drop(&mut self) {
        if let Some(port) = self.port.upgrade() {
            port.scopes
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .known_scopes
                .remove(&self.id);
        }
        if self.registered.swap(false, Ordering::AcqRel) {
            self.provider
                .release_scope(&self.provider_authority, self.id);
        }
    }
}

/// Cloneable RAII ownership token for one process-local resource scope.
///
/// A child retains its parent, and every lease retains its exact scope. The
/// final token drop retires the diagnostic identifier from the port registry.
#[derive(Clone)]
pub struct ResourceScope {
    inner: Arc<ResourceScopeInner>,
}

impl ResourceScope {
    pub fn id(&self) -> ResourceScopeId {
        self.inner.id
    }

    pub fn parent_id(&self) -> Option<ResourceScopeId> {
        self.inner.parent.as_ref().map(Self::id)
    }
}

impl fmt::Debug for ResourceScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceScope")
            .field("id", &self.id())
            .field("parent_id", &self.parent_id())
            .finish_non_exhaustive()
    }
}

impl PartialEq for ResourceScope {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }
}

impl Eq for ResourceScope {}

/// Why an admitted allocation exists.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResourceAuthorityClass {
    Cleanup,
    Admitted,
    Speculative,
}

/// Exact finite pressure observed in one resource dimension.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourcePressure {
    pub scope_id: ResourceScopeId,
    pub authority: ResourceAuthorityClass,
    pub dimension: ResourceClass,
    pub requested: u64,
    pub in_use: u64,
    pub capacity: u64,
}

/// Typed resource-admission failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResourceUnavailable {
    Pressure(ResourcePressure),
    UnknownScope { scope_id: ResourceScopeId },
    ProviderInvariant { dimension: ResourceClass },
}

impl ResourceUnavailable {
    pub const fn dimension(self) -> Option<ResourceClass> {
        match self {
            Self::Pressure(pressure) => Some(pressure.dimension),
            Self::ProviderInvariant { dimension } => Some(dimension),
            Self::UnknownScope { .. } => None,
        }
    }
}

impl fmt::Display for ResourceUnavailable {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pressure(pressure) => write!(
                formatter,
                "resource pressure in {:?}: requested {}, in use {}, capacity {}",
                pressure.dimension, pressure.requested, pressure.in_use, pressure.capacity
            ),
            Self::UnknownScope { scope_id } => {
                write!(formatter, "unknown resource scope {}", scope_id.get())
            }
            Self::ProviderInvariant { dimension } => {
                write!(
                    formatter,
                    "resource provider invariant failed in {dimension:?}"
                )
            }
        }
    }
}
impl std::error::Error for ResourceUnavailable {}

/// The process root already owns a different resource-provider identity.
///
/// Replacing the provider while leases may exist would split the process
/// grant. Callers must clone and reuse the originally installed port.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the process resource provider is already installed with a different identity")]
pub struct ResourceProviderConflict;

/// Owner-supplied admission and accounting implementation.
///
/// Reservation identifiers are provider-local and must identify one live
/// reservation exactly. `transition` must replace `current` with `replacement`
/// atomically. `release` is called exactly once by the owning lease. Provider
/// implementations must not call back into application code while holding an
/// internal accounting lock.
///
/// Every mutating method requires the unforgeable authority owned by the
/// [`ResourceProviderPort`]. Keeping a clone of a concrete provider therefore
/// cannot release, replace, or reuse port-owned reservations.
pub struct ResourceProviderAuthority {
    _private: (),
    identity: Arc<ResourceScopeIdentity>,
}

/// Provider-local facts that identify the exact reservation being replaced.
///
/// This value is not authority. Mutating the provider still requires the
/// matching unforgeable [`ResourceProviderAuthority`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ResourceReservationState {
    pub reservation_id: u64,
    pub scope_id: ResourceScopeId,
    pub authority: ResourceAuthorityClass,
    pub claim: ResourceClaim,
}

pub trait ResourceProvider: Send + Sync + 'static {
    fn create_scope(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        parent_scope_id: Option<ResourceScopeId>,
    ) -> Result<(), ResourceUnavailable>;

    fn create_scope_and_acquire(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        parent_scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<u64, ResourceUnavailable>;

    fn release_scope(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
    );

    fn acquire(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<u64, ResourceUnavailable>;

    fn transition(
        &self,
        provider_authority: &ResourceProviderAuthority,
        current: ResourceReservationState,
        replacement_authority: ResourceAuthorityClass,
        replacement: ResourceClaim,
    ) -> Result<(), ResourceUnavailable>;

    fn release(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    );

    fn retain_after_failed_cleanup(
        &self,
        provider_authority: &ResourceProviderAuthority,
        reservation_id: u64,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<ResourceClaim, ResourceUnavailable>;

    fn pressure(
        &self,
        provider_authority: &ResourceProviderAuthority,
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> ResourcePressure;
}
#[derive(Debug)]
struct ScopeRegistry {
    known_scopes: BTreeSet<ResourceScopeId>,
}

struct ResourceProviderPortInner {
    provider: Arc<dyn ResourceProvider>,
    provider_authority: Arc<ResourceProviderAuthority>,
    scopes: Mutex<ScopeRegistry>,
    process_scope: ResourceScope,
}

/// Cloneable authority port for one process resource provider.
///
/// The port validates scopes under its registry lock and releases that lock
/// before invoking provider code. Provider callbacks can therefore re-enter a
/// port without deadlocking on the scope registry.
#[derive(Clone)]
pub struct ResourceProviderPort {
    inner: Arc<ResourceProviderPortInner>,
}

impl fmt::Debug for ResourceProviderPort {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceProviderPort")
            .field("process_scope", &self.inner.process_scope.id())
            .finish_non_exhaustive()
    }
}

impl ResourceProviderPort {
    pub fn new(provider: impl ResourceProvider) -> Result<Self, ResourceUnavailable> {
        let provider: Arc<dyn ResourceProvider> = Arc::new(provider);
        let (process_identity, process_scope_id) = scope_identity();
        let provider_authority = Arc::new(ResourceProviderAuthority {
            _private: (),
            identity: Arc::clone(&process_identity),
        });
        let inner = Arc::new_cyclic(|weak_port| {
            let process_scope = ResourceScope {
                inner: Arc::new(ResourceScopeInner {
                    id: process_scope_id,
                    _identity: Arc::clone(&process_identity),
                    parent: None,
                    port: Weak::clone(weak_port),
                    provider: Arc::clone(&provider),
                    provider_authority: Arc::clone(&provider_authority),
                    registered: AtomicBool::new(false),
                }),
            };
            let mut known_scopes = BTreeSet::new();
            known_scopes.insert(process_scope_id);
            ResourceProviderPortInner {
                provider,
                provider_authority,
                scopes: Mutex::new(ScopeRegistry { known_scopes }),
                process_scope,
            }
        });
        inner
            .provider
            .create_scope(&inner.provider_authority, inner.process_scope.id(), None)?;
        inner
            .process_scope
            .inner
            .registered
            .store(true, Ordering::Release);
        Ok(Self { inner })
    }

    pub fn process_scope(&self) -> ResourceScope {
        self.inner.process_scope.clone()
    }

    /// True only when both ports reference the same provider and scope root.
    pub fn same_provider(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.inner, &other.inner)
    }

    /// Mint a child scope without granting it any capacity.
    pub fn create_scope(
        &self,
        parent: &ResourceScope,
    ) -> Result<ResourceScope, ResourceUnavailable> {
        self.validate_scope(parent)?;
        // Identity is tied to a live allocation rather than a never-reused
        // process counter. A refused scope therefore burns no lifetime-wide
        // namespace, and an address can be reused only after the old scope and
        // every lease retaining it have been released.
        let (identity, scope_id) = scope_identity();
        debug_assert!(!self.lock_scopes().known_scopes.contains(&scope_id));
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                parent: Some(parent.clone()),
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        self.inner.provider.create_scope(
            &self.inner.provider_authority,
            scope_id,
            Some(parent.id()),
        )?;
        scope.inner.registered.store(true, Ordering::Release);
        self.lock_scopes().known_scopes.insert(scope_id);
        Ok(scope)
    }

    /// Atomically mint a child scope and acquire its first exact lease.
    pub fn create_scope_with_lease(
        &self,
        parent: &ResourceScope,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<(ResourceScope, ResourceLease), ResourceUnavailable> {
        self.validate_scope(parent)?;
        let (identity, scope_id) = scope_identity();
        debug_assert!(!self.lock_scopes().known_scopes.contains(&scope_id));
        let scope = ResourceScope {
            inner: Arc::new(ResourceScopeInner {
                id: scope_id,
                _identity: identity,
                parent: Some(parent.clone()),
                port: Arc::downgrade(&self.inner),
                provider: Arc::clone(&self.inner.provider),
                provider_authority: Arc::clone(&self.inner.provider_authority),
                registered: AtomicBool::new(false),
            }),
        };
        let reservation_id = self.inner.provider.create_scope_and_acquire(
            &self.inner.provider_authority,
            scope_id,
            parent.id(),
            authority,
            claim,
        )?;
        scope.inner.registered.store(true, Ordering::Release);
        self.lock_scopes().known_scopes.insert(scope_id);
        let lease = ResourceLease {
            provider: Arc::clone(&self.inner.provider),
            reservation_id: Some(reservation_id),
            scope: scope.clone(),
            authority,
            claim,
        };
        Ok((scope, lease))
    }

    pub fn acquire(
        &self,
        scope: &ResourceScope,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    ) -> Result<ResourceLease, ResourceUnavailable> {
        self.validate_scope(scope)?;
        let scope_id = scope.id();
        let reservation_id = self.inner.provider.acquire(
            &self.inner.provider_authority,
            scope_id,
            authority,
            claim,
        )?;
        Ok(ResourceLease {
            provider: Arc::clone(&self.inner.provider),
            reservation_id: Some(reservation_id),
            scope: scope.clone(),
            authority,
            claim,
        })
    }

    /// Read current pressure without reserving capacity or authorizing work.
    pub fn pressure(
        &self,
        scope: &ResourceScope,
        authority: ResourceAuthorityClass,
        dimension: ResourceClass,
    ) -> Result<ResourcePressure, ResourceUnavailable> {
        self.validate_scope(scope)?;
        Ok(self.inner.provider.pressure(
            &self.inner.provider_authority,
            scope.id(),
            authority,
            dimension,
        ))
    }

    fn validate_scope(&self, scope: &ResourceScope) -> Result<(), ResourceUnavailable> {
        let same_port = scope
            .inner
            .port
            .upgrade()
            .is_some_and(|port| Arc::ptr_eq(&port, &self.inner));
        let known = same_port && self.lock_scopes().known_scopes.contains(&scope.id());
        if known {
            Ok(())
        } else {
            Err(ResourceUnavailable::UnknownScope {
                scope_id: scope.id(),
            })
        }
    }

    fn lock_scopes(&self) -> MutexGuard<'_, ScopeRegistry> {
        self.inner
            .scopes
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// One exact, non-cloneable resource allocation.
///
/// Dropping the lease releases its current claim exactly once. Transition is
/// atomic at the provider boundary: the lease changes its local claim only
/// after the provider commits the complete replacement.
#[must_use = "dropping the lease immediately releases the resource allocation"]
pub struct ResourceLease {
    provider: Arc<dyn ResourceProvider>,
    reservation_id: Option<u64>,
    scope: ResourceScope,
    authority: ResourceAuthorityClass,
    claim: ResourceClaim,
}

impl fmt::Debug for ResourceLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ResourceLease")
            .field("scope_id", &self.scope.id())
            .field("authority", &self.authority)
            .field("claim", &self.claim)
            .finish_non_exhaustive()
    }
}

impl ResourceLease {
    pub fn scope_id(&self) -> ResourceScopeId {
        self.scope.id()
    }

    pub fn scope(&self) -> ResourceScope {
        self.scope.clone()
    }

    pub const fn authority(&self) -> ResourceAuthorityClass {
        self.authority
    }

    pub const fn claim(&self) -> ResourceClaim {
        self.claim
    }

    pub fn transition(&mut self, replacement: ResourceClaim) -> Result<(), ResourceUnavailable> {
        self.transition_to(self.authority, replacement)
    }

    /// Atomically replace both the authority class and resource claim.
    ///
    /// A refusal leaves both old values intact.
    pub fn transition_to(
        &mut self,
        replacement_authority: ResourceAuthorityClass,
        replacement: ResourceClaim,
    ) -> Result<(), ResourceUnavailable> {
        let reservation_id = self
            .reservation_id
            .expect("a live resource lease always owns its reservation");
        self.provider.transition(
            &self.scope.inner.provider_authority,
            ResourceReservationState {
                reservation_id,
                scope_id: self.scope.id(),
                authority: self.authority,
                claim: self.claim,
            },
            replacement_authority,
            replacement,
        )?;
        self.authority = replacement_authority;
        self.claim = replacement;
        Ok(())
    }

    /// Transfer an exact charge to the provider after cleanup cannot prove
    /// that the protected native resource was released.
    ///
    /// This consumes the lease and suppresses ordinary Drop release. The
    /// provider becomes the sole owner of the retained charge.
    pub fn retain_after_failed_cleanup(mut self) -> Result<ResourceClaim, ResourceUnavailable> {
        let Some(reservation_id) = self.reservation_id.take() else {
            return Err(ResourceUnavailable::ProviderInvariant {
                dimension: ResourceClass::OpaqueDependencyResidual,
            });
        };
        self.provider.retain_after_failed_cleanup(
            &self.scope.inner.provider_authority,
            reservation_id,
            self.scope.id(),
            self.authority,
            self.claim,
        )
    }
}

impl Drop for ResourceLease {
    fn drop(&mut self) {
        if let Some(reservation_id) = self.reservation_id.take() {
            self.provider.release(
                &self.scope.inner.provider_authority,
                reservation_id,
                self.scope.id(),
                self.authority,
                self.claim,
            );
        }
    }
}

/// A shared application value and the one lease that funds all strong handles.
///
/// The lease is itself held by an `Arc`, so clones share one owner rather than
/// mirroring `Arc`'s allocator counters inside the provider. When the last
/// strong [`FundedArc`] goes, the lease goes with it. A remaining weak handle
/// keeps only the standard-library control block alive; that dependency detail
/// is covered by the record's broad residual rather than a second exact theorem.
///
/// There is no accessor returning the inner `Arc`: every reachable strong
/// handle must continue to carry the shared lease beside it.
pub struct FundedArc<T: ?Sized> {
    value: Arc<T>,
    funding: Arc<ResourceLease>,
}

/// A weak observer of a [`FundedArc`].
///
/// The weak funding pointer makes `upgrade` all-or-nothing: it first obtains a
/// strong lease owner and only then obtains the value. A weak-only control block
/// does not retain the value's claim.
pub struct FundedWeak<T: ?Sized> {
    value: std::sync::Weak<T>,
    funding: std::sync::Weak<ResourceLease>,
}

impl<T> FundedArc<T> {
    /// Fund and share one new allocation.
    ///
    /// Takes the exclusive lease **by value** and internalizes one shared owner
    /// beside the allocation. Callers never receive that owner separately, so
    /// one lease funds exactly one allocation.
    ///
    /// A speculative lease is refused and handed straight back. Speculative
    /// work remains an exclusive owner that can transition or retire as one
    /// unit; shared application values use admitted or cleanup authority.
    #[expect(
        clippy::result_large_err,
        reason = "the Err is the funding lease returned by value, still funding what it arrived funding; the whole point of taking it by value is that a refusal leaks nothing, which a boxed or narrowed error cannot express"
    )]
    pub fn new(value: T, funding: ResourceLease) -> Result<Self, ResourceLease> {
        if funding.authority == ResourceAuthorityClass::Speculative {
            return Err(funding);
        }
        Ok(Self {
            value: Arc::new(value),
            funding: Arc::new(funding),
        })
    }
}

impl<T: ?Sized> FundedArc<T> {
    /// Adopt an `Arc` that was already built and already admitted.
    ///
    /// The one way to hold an unsized pointee — `Arc<dyn Fn(..)>` and the like —
    /// since unsizing has to happen at the `Arc::new` that this crate performs
    /// before wrapping. Crate-private precisely because the caller supplies the
    /// pointer: an outside caller could pass one it had kept a second copy of,
    /// and the funding would then describe an allocation with a reachable
    /// unfunded alias. Callers outside this crate build through
    /// [`FundedArc::new`], which cannot have that problem because it allocates
    /// the value itself.
    ///
    /// Nothing escapes afterwards: there is still no accessor handing the
    /// pointer back out, and as with [`FundedArc::new`] the exclusive lease is
    /// taken by value and internalized, so no funding owner is ever in a
    /// caller's hands to attach to a second allocation.
    #[expect(
        clippy::result_large_err,
        reason = "same contract as [`FundedArc::new`]: the refused lease comes back by value, intact and still funding its reservation, so the refusal path allocates nothing and releases nothing"
    )]
    pub(crate) fn from_admitted_arc(
        value: Arc<T>,
        funding: ResourceLease,
    ) -> Result<Self, ResourceLease> {
        if funding.authority == ResourceAuthorityClass::Speculative {
            return Err(funding);
        }
        Ok(Self {
            value,
            funding: Arc::new(funding),
        })
    }

    /// A weak observer that can only upgrade together with live funding.
    pub fn downgrade(&self) -> FundedWeak<T> {
        FundedWeak {
            value: Arc::downgrade(&self.value),
            funding: Arc::downgrade(&self.funding),
        }
    }

    /// Whether two handles name the same allocation.
    ///
    /// Exposes the *answer*, not the pointer. An owner proving that the handle
    /// it is holding is the exact one a table still records — rather than a
    /// successor that legitimately took its place — needs this comparison and
    /// nothing else, and giving it the comparison keeps the `Arc` itself from
    /// escaping. Without it a caller would have to invent a second identity to
    /// compare, which is the drift this type exists to prevent.
    pub fn ptr_eq(this: &Self, other: &Self) -> bool {
        Arc::ptr_eq(&this.value, &other.value)
    }
}

impl<T: ?Sized> Clone for FundedArc<T> {
    fn clone(&self) -> Self {
        Self {
            value: Arc::clone(&self.value),
            funding: Arc::clone(&self.funding),
        }
    }
}

impl<T: ?Sized> std::ops::Deref for FundedArc<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

impl<T: ?Sized> FundedWeak<T> {
    /// A strong handle, if the value is still live.
    ///
    /// Funding is upgraded first. If the last strong owner is already gone,
    /// neither the value nor an unfunded strong alias escapes.
    pub fn upgrade(&self) -> Option<FundedArc<T>> {
        // Funding first: if the last strong value owner is dropping at the
        // same time, this keeps its lease live across the value upgrade.
        let funding = self.funding.upgrade()?;
        let value = self.value.upgrade()?;
        Some(FundedArc { value, funding })
    }

    /// How many strong handles are left — `0` once the value is gone.
    ///
    /// For pruning a registry of weak links without the strong clone that
    /// [`Self::upgrade`] would make just to drop it again. It observes and
    /// hands out nothing, so it cannot be a route to an unfunded alias.
    ///
    /// Says nothing about funding; a weak-only control block retains no claim.
    pub fn strong_count(&self) -> usize {
        std::sync::Weak::strong_count(&self.value)
    }
}

impl<T: ?Sized> Clone for FundedWeak<T> {
    fn clone(&self) -> Self {
        Self {
            value: std::sync::Weak::clone(&self.value),
            funding: std::sync::Weak::clone(&self.funding),
        }
    }
}

mod finite {
    use super::*;
    #[cfg(test)]
    use std::collections::VecDeque;
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Debug)]
    struct Reservation {
        scope_id: ResourceScopeId,
        authority: ResourceAuthorityClass,
        claim: ResourceClaim,
    }

    #[derive(Debug)]
    struct State {
        grant: ResourceClaim,
        in_use: ResourceClaim,
        retained_after_failed_cleanup: ResourceClaim,
        poisoned: Option<ResourceClass>,
        provider_authority: Option<Arc<ResourceScopeIdentity>>,
        next_reservation_id: u64,
        reservations: BTreeMap<u64, Reservation>,
        scopes: BTreeSet<ResourceScopeId>,
        #[cfg(test)]
        scripted_pressure: VecDeque<ResourceClass>,
    }

    /// Work-conserving provider backed by one explicit finite process grant.
    ///
    /// Every operation is immediate: it either commits one exact accounting
    /// transition under the provider lock or returns typed pressure without
    /// changing provider state. Scopes attribute work; they never partition or
    /// expand the process grant.
    #[derive(Clone, Debug)]
    pub struct FiniteResourceProvider {
        state: Arc<Mutex<State>>,
    }

    impl FiniteResourceProvider {
        pub fn new(grant: ResourceClaim) -> Self {
            Self {
                state: Arc::new(Mutex::new(State {
                    grant,
                    in_use: ResourceClaim::ZERO,
                    retained_after_failed_cleanup: ResourceClaim::ZERO,
                    poisoned: None,
                    provider_authority: None,
                    next_reservation_id: 1,
                    reservations: BTreeMap::new(),
                    scopes: BTreeSet::new(),
                    #[cfg(test)]
                    scripted_pressure: VecDeque::new(),
                })),
            }
        }

        pub fn reservation_planning_charge(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_charge(claim)
        }

        pub fn scope_planning_charge() -> ResourceClaim {
            Self::bookkeeping_claim()
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn scope_record_charge_for_test() -> ResourceClaim {
            Self::bookkeeping_claim()
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn reservation_charge_for_test(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_planning_charge(claim)
        }

        #[cfg(any(test, feature = "transport-lab"))]
        pub(crate) fn child_scope_with_reservation_charge_for_test(
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            Self::reservation_charge(claim)?
                .checked_add(Self::bookkeeping_claim())
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })
        }

        pub fn in_use(&self) -> ResourceClaim {
            self.lock_state().in_use
        }

        pub fn retained_after_failed_cleanup(&self) -> ResourceClaim {
            self.lock_state().retained_after_failed_cleanup
        }

        /// Read-only cardinality for exact terminal provider accounting.
        #[cfg(any(test, feature = "transport-lab"))]
        #[doc(hidden)]
        pub fn active_reservations(&self) -> usize {
            self.lock_state().reservations.len()
        }

        /// Read-only cardinality; exposes no scope or reservation authority.
        #[cfg(any(test, feature = "transport-lab"))]
        #[doc(hidden)]
        pub fn active_scopes(&self) -> usize {
            self.lock_state().scopes.len()
        }

        #[cfg(test)]
        pub(crate) fn script_pressure(&self, dimension: ResourceClass) {
            self.lock_state().scripted_pressure.push_back(dimension);
        }

        #[cfg(test)]
        pub(crate) fn poison_accounting_mutex(&self) {
            let state = Arc::clone(&self.state);
            let _ = std::thread::spawn(move || {
                let _guard = state.lock().expect("test mutex starts healthy");
                panic!("intentional provider mutex poison");
            })
            .join();
        }

        fn lock_state(&self) -> MutexGuard<'_, State> {
            match self.state.lock() {
                Ok(state) => state,
                Err(poisoned) => {
                    let mut state = poisoned.into_inner();
                    state
                        .poisoned
                        .get_or_insert(ResourceClass::OpaqueDependencyResidual);
                    state
                }
            }
        }

        fn bookkeeping_claim() -> ResourceClaim {
            ResourceClaim::single(ResourceClass::OpaqueDependencyResidual, 1)
        }

        fn reservation_charge(claim: ResourceClaim) -> Result<ResourceClaim, ResourceUnavailable> {
            claim.checked_add(Self::bookkeeping_claim()).map_err(|_| {
                ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }
            })
        }

        fn bind_provider_authority(
            state: &mut State,
            authority: &ResourceProviderAuthority,
        ) -> Result<(), ResourceUnavailable> {
            match state.provider_authority.as_ref() {
                Some(bound) if Arc::ptr_eq(bound, &authority.identity) => Ok(()),
                Some(_) => Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                }),
                None => {
                    state.provider_authority = Some(Arc::clone(&authority.identity));
                    Ok(())
                }
            }
        }

        fn require_provider_authority(
            state: &State,
            authority: &ResourceProviderAuthority,
        ) -> Result<(), ResourceUnavailable> {
            if state
                .provider_authority
                .as_ref()
                .is_some_and(|bound| Arc::ptr_eq(bound, &authority.identity))
            {
                Ok(())
            } else {
                Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })
            }
        }

        fn poisoned(state: &State) -> Result<(), ResourceUnavailable> {
            match state.poisoned {
                Some(dimension) => Err(ResourceUnavailable::ProviderInvariant { dimension }),
                None => Ok(()),
            }
        }

        fn poison(state: &mut State, dimension: ResourceClass) {
            state.poisoned.get_or_insert(dimension);
        }

        fn checked_admission(
            state: &mut State,
            base: ResourceClaim,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            parts: &[ResourceClaim],
        ) -> Result<(ResourceClaim, ResourceClaim), ResourceUnavailable> {
            let mut requested = ResourceClaim::ZERO;
            let mut next = base;
            for dimension in ResourceClass::ALL {
                let in_use = base.amount(dimension);
                let capacity = state.grant.amount(dimension);
                if in_use > capacity {
                    Self::poison(state, dimension);
                    return Err(ResourceUnavailable::ProviderInvariant { dimension });
                }
                let total = parts
                    .iter()
                    .fold(0_u128, |sum, part| sum + u128::from(part.amount(dimension)));
                let total = u64::try_from(total)
                    .map_err(|_| ResourceUnavailable::ProviderInvariant { dimension })?;
                if total > capacity - in_use {
                    return Err(ResourceUnavailable::Pressure(ResourcePressure {
                        scope_id,
                        authority,
                        dimension,
                        requested: total,
                        in_use,
                        capacity,
                    }));
                }
                requested.amounts[dimension.index()] = total;
                next.amounts[dimension.index()] = in_use
                    .checked_add(total)
                    .ok_or(ResourceUnavailable::ProviderInvariant { dimension })?;
            }
            Ok((requested, next))
        }

        #[cfg(test)]
        fn scripted_pressure(
            state: &mut State,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Option<ResourceUnavailable> {
            let dimension = *state.scripted_pressure.front()?;
            if claim.amount(dimension) == 0 {
                return None;
            }
            state.scripted_pressure.pop_front();
            Some(ResourceUnavailable::Pressure(ResourcePressure {
                scope_id,
                authority,
                dimension,
                requested: claim.amount(dimension),
                in_use: state.in_use.amount(dimension),
                capacity: state.grant.amount(dimension),
            }))
        }

        /// Name one live reservation, for as long as it is live.
        ///
        /// Monotonic and never reused. The identity is handed out under the
        /// same lock acquisition that inserts the reservation, and a released
        /// identity is never handed out again, so no holder of a stale
        /// identity can name a reservation a later admission took over.
        /// Both failures here are internal invariant failures rather than
        /// admission outcomes: exhausting `u64` reservation identities in one
        /// process cannot happen, and if the counter ever did wrap it would
        /// hand a live reservation's name to a second one, which is not a
        /// condition any caller can be told about truthfully.
        fn allocate_reservation_id(state: &mut State) -> u64 {
            let id = state.next_reservation_id;
            state.next_reservation_id = id
                .checked_add(1)
                .expect("reservation identities are exhausted; the provider can no longer name a live reservation uniquely");
            id
        }
    }

    impl ResourceProvider for FiniteResourceProvider {
        fn create_scope(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            parent_scope_id: Option<ResourceScopeId>,
        ) -> Result<(), ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::bind_provider_authority(&mut state, provider_authority)?;
            if let Some(parent) = parent_scope_id {
                if !state.scopes.contains(&parent) {
                    return Err(ResourceUnavailable::UnknownScope { scope_id: parent });
                }
            }
            if state.scopes.contains(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let base = state.in_use;
            let (_, next) = Self::checked_admission(
                &mut state,
                base,
                scope_id,
                ResourceAuthorityClass::Speculative,
                &[Self::bookkeeping_claim()],
            )?;
            state.scopes.insert(scope_id);
            state.in_use = next;
            Ok(())
        }

        fn create_scope_and_acquire(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            parent_scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<u64, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains(&parent_scope_id) {
                return Err(ResourceUnavailable::UnknownScope {
                    scope_id: parent_scope_id,
                });
            }
            if state.scopes.contains(&scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let charge = Self::reservation_charge(claim)?
                .checked_add(Self::bookkeeping_claim())
                .map_err(|_| ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                })?;
            let base = state.in_use;
            let (_, next) =
                Self::checked_admission(&mut state, base, scope_id, authority, &[charge])?;
            #[cfg(test)]
            if let Some(pressure) = Self::scripted_pressure(&mut state, scope_id, authority, charge)
            {
                return Err(pressure);
            }
            if !state.scopes.insert(scope_id) {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            // Taken past every refusal, so no identity is minted for a
            // reservation that is not about to exist.
            let id = Self::allocate_reservation_id(&mut state);
            assert!(
                state
                    .reservations
                    .insert(
                        id,
                        Reservation {
                            scope_id,
                            authority,
                            claim,
                        },
                    )
                    .is_none(),
                "reservation identities are never reused, so this insertion cannot displace a live reservation"
            );
            state.in_use = next;
            Ok(id)
        }

        fn release_scope(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
        ) {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return;
            }
            if !state.scopes.contains(&scope_id)
                || state
                    .reservations
                    .values()
                    .any(|reservation| reservation.scope_id == scope_id)
            {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            let Ok(next) = state.in_use.checked_sub(Self::bookkeeping_claim()) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            state.scopes.remove(&scope_id);
            state.in_use = next;
        }

        fn acquire(
            &self,
            provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<u64, ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains(&scope_id) {
                return Err(ResourceUnavailable::UnknownScope { scope_id });
            }
            let charge = Self::reservation_charge(claim)?;
            let base = state.in_use;
            let (_, next) =
                Self::checked_admission(&mut state, base, scope_id, authority, &[charge])?;
            #[cfg(test)]
            if let Some(pressure) = Self::scripted_pressure(&mut state, scope_id, authority, charge)
            {
                return Err(pressure);
            }
            // Taken past every refusal, so no identity is minted for a
            // reservation that is not about to exist.
            let id = Self::allocate_reservation_id(&mut state);
            assert!(
                state
                    .reservations
                    .insert(
                        id,
                        Reservation {
                            scope_id,
                            authority,
                            claim,
                        },
                    )
                    .is_none(),
                "reservation identities are never reused, so this insertion cannot displace a live reservation"
            );
            state.in_use = next;
            Ok(id)
        }

        fn transition(
            &self,
            provider_authority: &ResourceProviderAuthority,
            current: ResourceReservationState,
            replacement_authority: ResourceAuthorityClass,
            replacement: ResourceClaim,
        ) -> Result<(), ResourceUnavailable> {
            let mut state = self.lock_state();
            Self::poisoned(&state)?;
            Self::require_provider_authority(&state, provider_authority)?;
            if !state.scopes.contains(&current.scope_id) {
                return Err(ResourceUnavailable::UnknownScope {
                    scope_id: current.scope_id,
                });
            }
            let exact =
                state
                    .reservations
                    .get(&current.reservation_id)
                    .is_some_and(|reservation| {
                        reservation.scope_id == current.scope_id
                            && reservation.authority == current.authority
                            && reservation.claim == current.claim
                    });
            if !exact {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let without_current = state
                .in_use
                .checked_sub(Self::reservation_charge(current.claim)?)
                .map_err(|error| match error {
                    ResourceClaimArithmeticError::Overflow { dimension }
                    | ResourceClaimArithmeticError::Underflow { dimension } => {
                        ResourceUnavailable::ProviderInvariant { dimension }
                    }
                })?;
            let charge = Self::reservation_charge(replacement)?;
            let (_, next) = Self::checked_admission(
                &mut state,
                without_current,
                current.scope_id,
                replacement_authority,
                &[charge],
            )?;
            #[cfg(test)]
            if let Some(pressure) =
                Self::scripted_pressure(&mut state, current.scope_id, replacement_authority, charge)
            {
                return Err(pressure);
            }
            let reservation = state
                .reservations
                .get_mut(&current.reservation_id)
                .expect("the exact reservation was validated under this lock");
            reservation.authority = replacement_authority;
            reservation.claim = replacement;
            state.in_use = next;
            Ok(())
        }

        fn release(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return;
            }
            let exact = state
                .reservations
                .get(&reservation_id)
                .is_some_and(|reservation| {
                    reservation.scope_id == scope_id
                        && reservation.authority == authority
                        && reservation.claim == claim
                });
            if !state.scopes.contains(&scope_id) || !exact {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            }
            let Ok(charged_claim) = Self::reservation_charge(claim) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            let Ok(next) = state.in_use.checked_sub(charged_claim) else {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return;
            };
            state.reservations.remove(&reservation_id);
            state.in_use = next;
        }

        fn retain_after_failed_cleanup(
            &self,
            provider_authority: &ResourceProviderAuthority,
            reservation_id: u64,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            claim: ResourceClaim,
        ) -> Result<ResourceClaim, ResourceUnavailable> {
            let mut state = self.lock_state();
            if Self::require_provider_authority(&state, provider_authority).is_err() {
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let exact = state
                .reservations
                .get(&reservation_id)
                .is_some_and(|reservation| {
                    reservation.scope_id == scope_id
                        && reservation.authority == authority
                        && reservation.claim == claim
                });
            if !state.scopes.contains(&scope_id) || !exact {
                Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                return Err(ResourceUnavailable::ProviderInvariant {
                    dimension: ResourceClass::OpaqueDependencyResidual,
                });
            }
            let retained = match state.retained_after_failed_cleanup.checked_add(claim) {
                Ok(retained) => retained,
                Err(_) => {
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return Err(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    });
                }
            };
            let next = match state.in_use.checked_sub(Self::bookkeeping_claim()) {
                Ok(next) => next,
                Err(_) => {
                    Self::poison(&mut state, ResourceClass::OpaqueDependencyResidual);
                    return Err(ResourceUnavailable::ProviderInvariant {
                        dimension: ResourceClass::OpaqueDependencyResidual,
                    });
                }
            };
            state.reservations.remove(&reservation_id);
            state.retained_after_failed_cleanup = retained;
            state.in_use = next;
            Ok(claim)
        }

        fn pressure(
            &self,
            _provider_authority: &ResourceProviderAuthority,
            scope_id: ResourceScopeId,
            authority: ResourceAuthorityClass,
            dimension: ResourceClass,
        ) -> ResourcePressure {
            let state = self.lock_state();
            ResourcePressure {
                scope_id,
                authority,
                dimension,
                requested: 0,
                in_use: state.in_use.amount(dimension),
                capacity: state.grant.amount(dimension),
            }
        }
    }
}
pub use finite::FiniteResourceProvider;

#[cfg(test)]
pub(crate) mod test_support {
    pub(crate) use super::FiniteResourceProvider as DeterministicGrantProvider;
}

#[cfg(test)]
mod tests {
    use super::test_support::DeterministicGrantProvider;
    use super::*;

    fn claim(entries: &[(ResourceClass, u64)]) -> ResourceClaim {
        ResourceClaim::try_from_entries(entries.iter().copied()).expect("finite test claim")
    }

    #[test]
    fn composite_claim_arithmetic_reports_the_exact_dimension() {
        let base = claim(&[
            (ResourceClass::QueuedBytes, u64::MAX),
            (ResourceClass::WorkerOrTask, 1),
        ]);
        assert_eq!(
            base.checked_add(ResourceClaim::single(ResourceClass::QueuedBytes, 1)),
            Err(ResourceClaimArithmeticError::Overflow {
                dimension: ResourceClass::QueuedBytes,
            })
        );
        assert_eq!(
            ResourceClaim::ZERO.checked_sub(ResourceClaim::single(ResourceClass::StorageObject, 1)),
            Err(ResourceClaimArithmeticError::Underflow {
                dimension: ResourceClass::StorageObject,
            })
        );
    }

    #[test]
    fn one_process_grant_is_conserved_across_scopes_and_authorities() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::AccountedMemoryBytes, 18),
            (ResourceClass::WorkerOrTask, 3),
            (ResourceClass::OpaqueDependencyResidual, 5),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let process = port.process_scope();
        let first_scope = port.create_scope(&process).expect("first scope");
        let second_scope = port.create_scope(&process).expect("second scope");
        let first_claim = claim(&[
            (ResourceClass::AccountedMemoryBytes, 7),
            (ResourceClass::WorkerOrTask, 1),
        ]);
        let second_claim = claim(&[
            (ResourceClass::AccountedMemoryBytes, 11),
            (ResourceClass::WorkerOrTask, 2),
        ]);
        let first = port
            .acquire(
                &first_scope,
                ResourceAuthorityClass::Speculative,
                first_claim,
            )
            .expect("first claim");
        let second = port
            .acquire(&second_scope, ResourceAuthorityClass::Cleanup, second_claim)
            .expect("second claim");
        assert_eq!(provider.active_reservations(), 2);
        assert!(matches!(
            port.acquire(
                &process,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 1),
            ),
            Err(ResourceUnavailable::Pressure(ResourcePressure {
                dimension: ResourceClass::AccountedMemoryBytes,
                ..
            }))
        ));
        drop((first, second, first_scope, second_scope, process, port));
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn transition_is_atomic_and_pressure_preserves_the_old_claim() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 13),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let opening = ResourceClaim::single(ResourceClass::QueuedBytes, 3);
        let connected = ResourceClaim::single(ResourceClass::QueuedBytes, 9);
        let mut lease = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Speculative,
                opening,
            )
            .expect("opening claim");
        provider.script_pressure(ResourceClass::QueuedBytes);
        assert!(matches!(
            lease.transition(connected),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert_eq!(lease.claim(), opening);
        lease
            .transition_to(ResourceAuthorityClass::Cleanup, connected)
            .expect("replacement");
        assert_eq!(lease.claim(), connected);
        assert_eq!(lease.authority(), ResourceAuthorityClass::Cleanup);
    }

    #[test]
    fn refused_scope_and_first_lease_is_one_transaction() {
        let provider = DeterministicGrantProvider::new(ResourceClaim::single(
            ResourceClass::OpaqueDependencyResidual,
            2,
        ));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let process = port.process_scope();
        let baseline = provider.in_use();
        assert!(matches!(
            port.create_scope_with_lease(
                &process,
                ResourceAuthorityClass::Admitted,
                ResourceClaim::ZERO,
            ),
            Err(ResourceUnavailable::Pressure(_))
        ));
        assert_eq!(provider.in_use(), baseline);
        assert_eq!(provider.active_scopes(), 1);
        assert_eq!(provider.active_reservations(), 0);
    }

    #[test]
    fn failed_cleanup_retains_the_exact_claim_without_a_live_reservation() {
        let protected = claim(&[
            (ResourceClass::NativeTransportObject, 1),
            (ResourceClass::AccountedMemoryBytes, 5),
        ]);
        let provider = DeterministicGrantProvider::new(
            protected
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    2,
                ))
                .expect("bookkeeping"),
        );
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let lease = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Cleanup,
                protected,
            )
            .expect("native allocation");
        assert_eq!(lease.retain_after_failed_cleanup(), Ok(protected));
        assert_eq!(provider.retained_after_failed_cleanup(), protected);
        assert_eq!(provider.active_reservations(), 0);
    }

    #[test]
    fn one_claim_funds_a_shared_allocation_until_the_last_strong_handle() {
        let claim = ResourceClaim::single(ResourceClass::AccountedMemoryBytes, 8);
        let provider = DeterministicGrantProvider::new(
            claim
                .checked_add(ResourceClaim::single(
                    ResourceClass::OpaqueDependencyResidual,
                    2,
                ))
                .expect("bookkeeping"),
        );
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        let lease = port
            .acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Admitted,
                claim,
            )
            .expect("allocation");
        let first = FundedArc::new(String::from("funded"), lease).expect("shareable lease");
        let second = first.clone();
        let weak = first.downgrade();
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            8
        );
        drop(first);
        drop(second);
        assert!(weak.upgrade().is_none());
        assert_eq!(
            provider
                .in_use()
                .amount(ResourceClass::AccountedMemoryBytes),
            0
        );
        drop(weak);
    }

    #[test]
    fn accounting_mutex_poison_fails_closed() {
        let provider = DeterministicGrantProvider::new(claim(&[
            (ResourceClass::QueuedBytes, 1),
            (ResourceClass::OpaqueDependencyResidual, 2),
        ]));
        let port = ResourceProviderPort::new(provider.clone()).expect("process scope");
        provider.poison_accounting_mutex();
        assert!(matches!(
            port.acquire(
                &port.process_scope(),
                ResourceAuthorityClass::Admitted,
                ResourceClaim::single(ResourceClass::QueuedBytes, 1),
            ),
            Err(ResourceUnavailable::ProviderInvariant { .. })
        ));
    }
}
