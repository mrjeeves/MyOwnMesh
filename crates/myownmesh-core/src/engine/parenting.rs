//! Bounded advisory HubTree parenting.
//!
//! This is deliberately separate from semantic authority and from the wire
//! protocol.  An adapter supplies a [`PeerOwnerToken`] that it has already
//! checked against the exact promoted authenticated session; this component
//! only retains the fixed binding coordinate.  It never authenticates a peer,
//! creates a session capability, elects a parent, or forwards a message.

use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};
use std::time::Instant;

use crate::resource::{
    FiniteResourceProvider, LeasedMap, LocalApplicationResourceScope, ResourceClaim,
    ResourceClaimArithmeticError, ResourceUnavailable,
};
use crate::semantic::DeviceId;

use super::peer_registry::PeerOwnerToken;

/// A retained full Ed25519 key without an interned `DeviceId` allocation.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ParentDeviceKey([u8; 32]);

impl ParentDeviceKey {
    pub(super) fn from_device(device: &DeviceId) -> Self {
        Self(device.as_bytes())
    }

    pub(super) const fn as_bytes(self) -> [u8; 32] {
        self.0
    }
}

/// The only supported shallow tree roles.  `Hub(1)` is the sole non-root hub
/// tier: root -> hub -> leaf has the exact four-hop route ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentingRole {
    Root,
    Hub(u8),
    Leaf,
}

impl ParentingRole {
    const MAX_HUB_TIER: u8 = 1;
}

/// Exact process-local installation binding copied from a checked owner token.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ParentOwnerCoordinate {
    peer: ParentDeviceKey,
    binding_namespace: [u8; 16],
    binding_epoch: u64,
}

/// Opaque adapter witness.  Constructing one does not authenticate anything;
/// the caller must first apply the peer registry's current promoted-session
/// fence and then pass the same owner token here.
pub(super) struct ParentOwnerWitness {
    coordinate: ParentOwnerCoordinate,
}

impl ParentOwnerWitness {
    pub(super) fn from_owner(owner: &PeerOwnerToken) -> Result<Self, ParentingRefusal> {
        let coordinate = owner.binding_coordinate();
        let device = DeviceId::from_canonical_str(&coordinate.device_id)
            .map_err(|_| ParentingRefusal::InvalidOwner)?;
        Ok(Self {
            coordinate: ParentOwnerCoordinate {
                peer: ParentDeviceKey::from_device(&device),
                binding_namespace: coordinate.binding_namespace,
                binding_epoch: coordinate.binding_epoch,
            },
        })
    }

    fn peer(&self) -> ParentDeviceKey {
        self.coordinate.peer
    }
}

/// Primary or optional warm-sibling relation.  This is an engine-local
/// classification; no wire field or unsigned caller string carries it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentingRelationKind {
    Primary,
    Backup,
}

/// Internal request seam for the protocol adapter.  The adapter maps the
/// typed HubTree request's context/config/sequence/IDs into this fixed shape
/// and supplies the configured roles; the roles are not serialized on wire.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParentAttachRequest {
    pub(super) context_id: [u8; 32],
    pub(super) configuration_digest: [u8; 32],
    pub(super) request_sequence: u64,
    pub(super) child: ParentDeviceKey,
    pub(super) parent: ParentDeviceKey,
    pub(super) child_role: ParentingRole,
    pub(super) parent_role: ParentingRole,
    pub(super) kind: ParentingRelationKind,
}

impl ParentAttachRequest {
    pub(super) fn new(
        context_id: [u8; 32],
        configuration_digest: [u8; 32],
        request_sequence: u64,
        child: ParentDeviceKey,
        parent: ParentDeviceKey,
        child_role: ParentingRole,
        parent_role: ParentingRole,
        kind: ParentingRelationKind,
    ) -> Result<Self, ParentingRefusal> {
        if request_sequence == 0 || child == parent {
            return Err(ParentingRefusal::InvalidRequest);
        }
        Ok(Self {
            context_id,
            configuration_digest,
            request_sequence,
            child,
            parent,
            child_role,
            parent_role,
            kind,
        })
    }
}

/// Closed response rejection classes for the later protocol adapter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentAttachRejection {
    UnsupportedRole,
    NotCurrentOwner,
    Capacity,
    StaleRequest,
    ContextMismatch,
    ConfigurationMismatch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentAttachResponse {
    Accepted {
        request: ParentAttachRequest,
        relation_generation: u64,
    },
    Rejected {
        request: ParentAttachRequest,
        reason: ParentAttachRejection,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum ParentAdoption {
    Accepted,
    Rejected(ParentAttachRejection),
}

/// Opaque pending child-side registration.  A response must match every
/// field in its retained request plus this exact sequence/generation.
pub(super) struct ParentAttachTicket {
    key: ParentingKey,
    request_sequence: u64,
    relation_generation: u64,
    owner: ParentOwnerCoordinate,
}

impl ParentAttachTicket {
    pub(super) fn request_key(&self) -> ParentDeviceKey {
        self.key.child
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParentingPolicy {
    pub(super) local: ParentDeviceKey,
    pub(super) root: ParentDeviceKey,
    pub(super) role: ParentingRole,
    pub(super) max_hub_tier: u8,
    pub(super) max_children: usize,
    pub(super) max_backups: usize,
    pub(super) max_pending: usize,
    pub(super) max_age_ticks: u64,
    pub(super) context_id: [u8; 32],
    pub(super) configuration_digest: [u8; 32],
}

impl ParentingPolicy {
    pub(super) fn checked(self) -> Result<Self, ParentingRefusal> {
        if self.max_hub_tier != ParentingRole::MAX_HUB_TIER
            || self.max_pending != 1
            || self.max_age_ticks == 0
            || self.max_backups > usize::from(u16::MAX) - 1
            || matches!(self.role, ParentingRole::Hub(tier) if tier != 1)
            || (!matches!(self.role, ParentingRole::Root) && self.local == self.root)
            || (matches!(self.role, ParentingRole::Root) && self.local != self.root)
        {
            return Err(ParentingRefusal::InvalidPolicy);
        }
        self.relation_bound()?;
        Ok(self)
    }

    fn slot_backup(self, index: usize) -> Result<u16, ParentingRefusal> {
        if index >= self.max_backups {
            return Err(ParentingRefusal::Capacity);
        }
        let slot = index.checked_add(1).ok_or(ParentingRefusal::Arithmetic)?;
        u16::try_from(slot).map_err(|_| ParentingRefusal::InvalidPolicy)
    }

    fn relation_bound(self) -> Result<usize, ParentingRefusal> {
        let per_child = self
            .max_backups
            .checked_add(1)
            .ok_or(ParentingRefusal::Arithmetic)?;
        self.max_children
            .checked_mul(per_child)
            .and_then(|children| children.checked_add(self.max_pending))
            .and_then(|records| records.checked_add(1))
            .ok_or(ParentingRefusal::Arithmetic)
    }

    fn accepts_child(self, child_role: ParentingRole) -> bool {
        match self.role {
            ParentingRole::Root => matches!(child_role, ParentingRole::Hub(1)),
            ParentingRole::Hub(1) => matches!(child_role, ParentingRole::Leaf),
            ParentingRole::Hub(_) | ParentingRole::Leaf => false,
        }
    }

    fn accepts_parent(self, parent: ParentDeviceKey, parent_role: ParentingRole) -> bool {
        match self.role {
            ParentingRole::Root => false,
            ParentingRole::Hub(1) => parent == self.root && parent_role == ParentingRole::Root,
            ParentingRole::Hub(_) => false,
            ParentingRole::Leaf => {
                parent != self.root && matches!(parent_role, ParentingRole::Hub(1))
            }
        }
    }
}

pub(super) trait ParentingClock: Clone + Send + Sync {
    fn now(&self) -> ParentingTick;
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(super) struct ParentingTick(pub(super) u64);

#[derive(Clone)]
pub(super) struct MonotonicParentingClock {
    origin: Instant,
    offset_ms: Arc<AtomicU64>,
}

impl MonotonicParentingClock {
    pub(super) fn new() -> Self {
        Self {
            origin: Instant::now(),
            offset_ms: Arc::new(AtomicU64::new(0)),
        }
    }

    #[cfg(feature = "transport-lab")]
    pub(super) fn advance(&self, delta_ms: u64) -> Result<(), ParentingRefusal> {
        let mut current = self.offset_ms.load(Ordering::Acquire);
        loop {
            let next = current
                .checked_add(delta_ms)
                .ok_or(ParentingRefusal::TimeOverflow)?;
            match self.offset_ms.compare_exchange_weak(
                current,
                next,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Ok(()),
                Err(observed) => current = observed,
            }
        }
    }
}

impl ParentingClock for MonotonicParentingClock {
    fn now(&self) -> ParentingTick {
        let elapsed = u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX);
        ParentingTick(elapsed.saturating_add(self.offset_ms.load(Ordering::Acquire)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(super) enum ParentingRefusal {
    #[error("HubTree parenting is disabled or invalid")]
    InvalidPolicy,
    #[error("HubTree request is invalid")]
    InvalidRequest,
    #[error("HubTree owner token is invalid")]
    InvalidOwner,
    #[error("HubTree request context does not match")]
    ContextMismatch,
    #[error("HubTree request configuration does not match")]
    ConfigurationMismatch,
    #[error("HubTree role or depth is unsupported")]
    UnsupportedRole,
    #[error("HubTree relation capacity is exhausted")]
    Capacity,
    #[error("HubTree relation owner is not the exact installation")]
    OwnerMismatch,
    #[error("HubTree request is stale")]
    StaleRequest,
    #[error("HubTree pending response does not match")]
    PendingMismatch,
    #[error("HubTree relation generation overflowed")]
    GenerationOverflow,
    #[error("HubTree time arithmetic overflowed")]
    TimeOverflow,
    #[error("HubTree resource arithmetic failed")]
    Arithmetic,
    #[error("HubTree map invariant failed")]
    Invariant,
    #[error("HubTree resource provider refused the relation: {0}")]
    Provider(ResourceUnavailable),
    #[error("HubTree clock moved backwards")]
    ClockRegression,
}

impl From<ResourceUnavailable> for ParentingRefusal {
    fn from(value: ResourceUnavailable) -> Self {
        Self::Provider(value)
    }
}

impl From<ResourceClaimArithmeticError> for ParentingRefusal {
    fn from(_: ResourceClaimArithmeticError) -> Self {
        Self::Arithmetic
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RelationState {
    Pending,
    Primary,
    Backup,
}

#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
struct ParentingKey {
    child: ParentDeviceKey,
    slot: u16,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParentingRelation {
    owner: ParentOwnerCoordinate,
    parent: ParentDeviceKey,
    child_role: ParentingRole,
    parent_role: ParentingRole,
    kind: ParentingRelationKind,
    request_sequence: u64,
    relation_generation: u64,
    expires_at: ParentingTick,
    state: RelationState,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParentingRelationSnapshot {
    pub(super) child: ParentDeviceKey,
    pub(super) parent: ParentDeviceKey,
    pub(super) owner: [u8; 16],
    pub(super) owner_epoch: u64,
    pub(super) kind: ParentingRelationKind,
    pub(super) relation_generation: u64,
}

/// Fixed, read-only observation of the local parenting table for a
/// transport-lab control.  The raw parent key is a routing identity only; no
/// owner coordinate, authority fact, or session capability crosses this seam.
#[cfg(feature = "transport-lab")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct ParentingSnapshotForLab {
    pub(super) primary_parent: Option<[u8; 32]>,
    pub(super) accepted_children: usize,
    pub(super) pending: usize,
    pub(super) generation: u64,
}

/// One local HubTree owner.  The only dynamic allocation is the individually
/// leased relation node; accepted links remain until exact owner/peer retire.
pub(super) struct ParentingState<C: ParentingClock> {
    records: LeasedMap<ParentingKey, ParentingRelation>,
    policy: ParentingPolicy,
    clock: C,
    next_relation_generation: u64,
    primary_children: usize,
    backup_children: usize,
    pending_count: usize,
    record_count: usize,
    last_now: Option<ParentingTick>,
    maintenance_cursor: Option<ParentingKey>,
    resources: LocalApplicationResourceScope,
}

impl<C: ParentingClock> ParentingState<C> {
    pub(super) fn new(
        resources: LocalApplicationResourceScope,
        policy: ParentingPolicy,
        clock: C,
    ) -> Result<Self, ParentingRefusal> {
        let policy = policy.checked()?;
        Ok(Self {
            records: LeasedMap::new(),
            policy,
            clock,
            next_relation_generation: 1,
            primary_children: 0,
            backup_children: 0,
            pending_count: 0,
            record_count: 0,
            last_now: None,
            maintenance_cursor: None,
            resources,
        })
    }

    pub(super) fn planned_retained_claim(
        policy: ParentingPolicy,
    ) -> Result<ResourceClaim, ParentingRefusal> {
        let policy = policy.checked()?;
        let node = LeasedMap::<ParentingKey, ParentingRelation>::entry_claim()?;
        let per_entry = FiniteResourceProvider::reservation_planning_charge(node)?;
        per_entry
            .checked_scale(
                u64::try_from(policy.relation_bound()?)
                    .map_err(|_| ParentingRefusal::Arithmetic)?,
            )
            .map_err(Into::into)
    }

    fn now(&mut self) -> Result<ParentingTick, ParentingRefusal> {
        let now = self.clock.now();
        if self.last_now.is_some_and(|last| now < last) {
            return Err(ParentingRefusal::ClockRegression);
        }
        self.last_now = Some(now);
        Ok(now)
    }

    fn expiry(&self, now: ParentingTick) -> Result<ParentingTick, ParentingRefusal> {
        now.0
            .checked_add(self.policy.max_age_ticks)
            .map(ParentingTick)
            .ok_or(ParentingRefusal::TimeOverflow)
    }

    fn next_relation_generation(&mut self) -> Result<u64, ParentingRefusal> {
        let generation = self.next_relation_generation;
        self.next_relation_generation = generation
            .checked_add(1)
            .ok_or(ParentingRefusal::GenerationOverflow)?;
        Ok(generation)
    }

    fn next_key_after(&self, cursor: Option<&ParentingKey>) -> Option<ParentingKey> {
        self.records
            .successor_after(cursor)
            .map(|(key, _)| *key)
            .or_else(|| {
                cursor.and_then(|_| self.records.successor_after(None).map(|(key, _)| *key))
            })
    }

    fn remove_key(&mut self, key: &ParentingKey) -> Result<ParentingRelation, ParentingRefusal> {
        let relation = self
            .records
            .remove(key)
            .ok_or(ParentingRefusal::Invariant)?;
        self.record_count = self
            .record_count
            .checked_sub(1)
            .ok_or(ParentingRefusal::Invariant)?;
        match relation.state {
            RelationState::Pending => {
                self.pending_count = self
                    .pending_count
                    .checked_sub(1)
                    .ok_or(ParentingRefusal::Invariant)?;
            }
            RelationState::Primary => {
                self.primary_children = self
                    .primary_children
                    .checked_sub(if key.child != self.policy.local { 1 } else { 0 })
                    .ok_or(ParentingRefusal::Invariant)?;
            }
            RelationState::Backup => {
                self.backup_children = self
                    .backup_children
                    .checked_sub(if key.child != self.policy.local { 1 } else { 0 })
                    .ok_or(ParentingRefusal::Invariant)?;
            }
        }
        Ok(relation)
    }

    fn maintain_at(&mut self, now: ParentingTick) -> Result<usize, ParentingRefusal> {
        let mut cursor = self.maintenance_cursor;
        let start = self.next_key_after(cursor.as_ref());
        let mut removed: usize = 0;
        for step in 0..self.policy.max_pending {
            let Some(key) = self.next_key_after(cursor.as_ref()) else {
                cursor = None;
                break;
            };
            if step > 0 && Some(key) == start {
                break;
            }
            cursor = Some(key);
            let expired = self
                .records
                .get(&key)
                .is_some_and(|relation| relation.expires_at <= now);
            if expired {
                self.remove_key(&key)?;
                removed = removed.checked_add(1).ok_or(ParentingRefusal::Invariant)?;
            }
        }
        self.maintenance_cursor = cursor;
        Ok(removed)
    }

    pub(super) fn maintain_now(&mut self) -> Result<usize, ParentingRefusal> {
        let now = self.now()?;
        self.maintain_at(now)
    }

    fn check_request(&self, request: ParentAttachRequest) -> Result<(), ParentingRefusal> {
        if request.request_sequence == 0 || request.child == request.parent {
            return Err(ParentingRefusal::InvalidRequest);
        }
        if request.context_id != self.policy.context_id {
            return Err(ParentingRefusal::ContextMismatch);
        }
        if request.configuration_digest != self.policy.configuration_digest {
            return Err(ParentingRefusal::ConfigurationMismatch);
        }
        Ok(())
    }

    fn primary_key(&self, child: ParentDeviceKey) -> ParentingKey {
        ParentingKey { child, slot: 0 }
    }

    fn relation_snapshot(
        key: ParentingKey,
        relation: ParentingRelation,
    ) -> ParentingRelationSnapshot {
        ParentingRelationSnapshot {
            child: key.child,
            parent: relation.parent,
            owner: relation.owner.binding_namespace,
            owner_epoch: relation.owner.binding_epoch,
            kind: relation.kind,
            relation_generation: relation.relation_generation,
        }
    }

    /// Parent-side atomic accept.  The exact owner witness is checked before
    /// any relation lease is acquired; duplicate identical acceptance returns
    /// the original generation without allocating or appending.
    pub(super) fn accept_request(
        &mut self,
        owner: &ParentOwnerWitness,
        request: ParentAttachRequest,
    ) -> Result<ParentAttachResponse, ParentingRefusal> {
        self.check_request(request)?;
        if request.parent != self.policy.local || owner.peer() != request.child {
            return Err(ParentingRefusal::OwnerMismatch);
        }
        if request.parent_role != self.policy.role || !self.policy.accepts_child(request.child_role)
        {
            return Err(ParentingRefusal::UnsupportedRole);
        }
        let now = self.now()?;
        self.maintain_at(now)?;
        let accepted_expires_at = self.expiry(now)?;
        let key = match request.kind {
            ParentingRelationKind::Primary => self.primary_key(request.child),
            ParentingRelationKind::Backup => {
                let mut free = None;
                for index in 0..self.policy.max_backups {
                    let candidate = ParentingKey {
                        child: request.child,
                        slot: self.policy.slot_backup(index)?,
                    };
                    if self.expire_key_if_needed(candidate, now)? {
                        if free.is_none() {
                            free = Some(candidate);
                        }
                        continue;
                    }
                    if let Some(existing) = self.records.get(&candidate).copied() {
                        if existing.owner == owner.coordinate
                            && existing.parent == request.parent
                            && existing.child_role == request.child_role
                            && existing.parent_role == request.parent_role
                            && existing.kind == request.kind
                            && existing.state != RelationState::Pending
                        {
                            if request.request_sequence < existing.request_sequence {
                                return Err(ParentingRefusal::StaleRequest);
                            }
                            if let Some(relation) = self.records.get_mut(&candidate) {
                                relation.request_sequence = request.request_sequence;
                                relation.expires_at = accepted_expires_at;
                            }
                            return Ok(ParentAttachResponse::Accepted {
                                request,
                                relation_generation: existing.relation_generation,
                            });
                        }
                    } else if free.is_none() {
                        free = Some(candidate);
                    }
                }
                free.ok_or(ParentingRefusal::Capacity)?
            }
        };
        self.expire_key_if_needed(key, now)?;
        if let Some(existing) = self.records.get(&key).copied() {
            if existing.owner == owner.coordinate
                && existing.parent == request.parent
                && existing.child_role == request.child_role
                && existing.parent_role == request.parent_role
                && existing.kind == request.kind
                && existing.state != RelationState::Pending
            {
                if request.request_sequence < existing.request_sequence {
                    return Err(ParentingRefusal::StaleRequest);
                }
                if let Some(relation) = self.records.get_mut(&key) {
                    relation.request_sequence = request.request_sequence;
                    relation.expires_at = accepted_expires_at;
                }
                return Ok(ParentAttachResponse::Accepted {
                    request,
                    relation_generation: existing.relation_generation,
                });
            }
            return Err(ParentingRefusal::StaleRequest);
        }
        if request.kind == ParentingRelationKind::Primary
            && self.primary_children >= self.policy.max_children
        {
            return Err(ParentingRefusal::Capacity);
        }
        if request.kind == ParentingRelationKind::Backup
            && self.backup_children
                >= self
                    .policy
                    .max_children
                    .checked_mul(self.policy.max_backups)
                    .ok_or(ParentingRefusal::Arithmetic)?
        {
            return Err(ParentingRefusal::Capacity);
        }
        let lease = self
            .resources
            .acquire(LeasedMap::<ParentingKey, ParentingRelation>::entry_claim()?)?;
        let relation_generation = self.next_relation_generation()?;
        let relation = ParentingRelation {
            owner: owner.coordinate,
            parent: request.parent,
            child_role: request.child_role,
            parent_role: request.parent_role,
            kind: request.kind,
            request_sequence: request.request_sequence,
            relation_generation,
            expires_at: accepted_expires_at,
            state: match request.kind {
                ParentingRelationKind::Primary => RelationState::Primary,
                ParentingRelationKind::Backup => RelationState::Backup,
            },
        };
        if self.records.insert(key, relation, lease).is_err() {
            return Err(ParentingRefusal::Invariant);
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(ParentingRefusal::Invariant)?;
        match relation.state {
            RelationState::Primary => {
                self.primary_children = self
                    .primary_children
                    .checked_add(1)
                    .ok_or(ParentingRefusal::Invariant)?
            }
            RelationState::Backup => {
                self.backup_children = self
                    .backup_children
                    .checked_add(if key.child != self.policy.local { 1 } else { 0 })
                    .ok_or(ParentingRefusal::Invariant)?
            }
            RelationState::Pending => return Err(ParentingRefusal::Invariant),
        }
        Ok(ParentAttachResponse::Accepted {
            request,
            relation_generation,
        })
    }

    /// Child-side registration reserves its exact pending node before a wire
    /// request is sent.  No parent response can bind a successor after this
    /// pending record is purged or cancelled.
    pub(super) fn begin_child_attach(
        &mut self,
        owner: &ParentOwnerWitness,
        request: ParentAttachRequest,
    ) -> Result<ParentAttachTicket, ParentingRefusal> {
        self.check_request(request)?;
        if request.child != self.policy.local
            || owner.peer() != request.parent
            || request.child_role != self.policy.role
            || request.parent_role == self.policy.role
            || !self
                .policy
                .accepts_parent(request.parent, request.parent_role)
        {
            return Err(ParentingRefusal::UnsupportedRole);
        }
        let now = self.now()?;
        self.maintain_at(now)?;
        let pending_key = match request.kind {
            ParentingRelationKind::Primary => self.primary_key(request.child),
            ParentingRelationKind::Backup => {
                let mut free = None;
                for index in 0..self.policy.max_backups {
                    let candidate = ParentingKey {
                        child: request.child,
                        slot: self.policy.slot_backup(index)?,
                    };
                    if self.expire_key_if_needed(candidate, now)? {
                        if free.is_none() {
                            free = Some(candidate);
                        }
                        continue;
                    }
                    if let Some(existing) = self.records.get(&candidate).copied() {
                        if existing.state == RelationState::Pending
                            && existing.owner == owner.coordinate
                            && existing.parent == request.parent
                            && existing.child_role == request.child_role
                            && existing.parent_role == request.parent_role
                            && existing.kind == request.kind
                            && existing.request_sequence == request.request_sequence
                        {
                            return Ok(ParentAttachTicket {
                                key: candidate,
                                request_sequence: existing.request_sequence,
                                relation_generation: existing.relation_generation,
                                owner: existing.owner,
                            });
                        }
                    } else if free.is_none() {
                        free = Some(candidate);
                    }
                }
                free.ok_or(ParentingRefusal::Capacity)?
            }
        };
        self.expire_key_if_needed(pending_key, now)?;
        if let Some(existing) = self.records.get(&pending_key).copied() {
            return if existing.state == RelationState::Pending
                && existing.owner == owner.coordinate
                && existing.parent == request.parent
                && existing.child_role == request.child_role
                && existing.parent_role == request.parent_role
                && existing.kind == request.kind
                && existing.request_sequence == request.request_sequence
            {
                Ok(ParentAttachTicket {
                    key: pending_key,
                    request_sequence: existing.request_sequence,
                    relation_generation: existing.relation_generation,
                    owner: existing.owner,
                })
            } else {
                Err(ParentingRefusal::StaleRequest)
            };
        }
        if self.pending_count >= self.policy.max_pending {
            return Err(ParentingRefusal::Capacity);
        }
        let key = pending_key;
        let lease = self
            .resources
            .acquire(LeasedMap::<ParentingKey, ParentingRelation>::entry_claim()?)?;
        let relation_generation = self.next_relation_generation()?;
        let relation = ParentingRelation {
            owner: owner.coordinate,
            parent: request.parent,
            child_role: request.child_role,
            parent_role: request.parent_role,
            kind: request.kind,
            request_sequence: request.request_sequence,
            relation_generation,
            expires_at: self.expiry(now)?,
            state: RelationState::Pending,
        };
        if self.records.insert(key, relation, lease).is_err() {
            return Err(ParentingRefusal::Invariant);
        }
        self.record_count = self
            .record_count
            .checked_add(1)
            .ok_or(ParentingRefusal::Invariant)?;
        self.pending_count = self
            .pending_count
            .checked_add(1)
            .ok_or(ParentingRefusal::Invariant)?;
        Ok(ParentAttachTicket {
            key,
            request_sequence: request.request_sequence,
            relation_generation,
            owner: owner.coordinate,
        })
    }

    pub(super) fn adopt_response(
        &mut self,
        owner: &ParentOwnerWitness,
        ticket: &ParentAttachTicket,
        response: ParentAttachResponse,
    ) -> Result<ParentAdoption, ParentingRefusal> {
        let (request, accepted_generation, rejection) = match response {
            ParentAttachResponse::Accepted {
                request,
                relation_generation,
            } => (request, Some(relation_generation), None),
            ParentAttachResponse::Rejected { request, reason } => (request, None, Some(reason)),
        };
        self.check_request(request)?;
        if request.child != self.policy.local || owner.peer() != request.parent {
            return Err(ParentingRefusal::OwnerMismatch);
        }
        let key = ticket.key;
        if key.child != self.policy.local
            || (request.kind == ParentingRelationKind::Primary && key.slot != 0)
            || (request.kind == ParentingRelationKind::Backup
                && (key.slot == 0 || usize::from(key.slot - 1) >= self.policy.max_backups))
        {
            return Err(ParentingRefusal::PendingMismatch);
        }
        if ticket.key != key
            || ticket.owner != owner.coordinate
            || ticket.request_sequence != request.request_sequence
        {
            return Err(ParentingRefusal::PendingMismatch);
        }
        let Some(existing) = self.records.get(&key).copied() else {
            return Err(ParentingRefusal::PendingMismatch);
        };
        if existing.state != RelationState::Pending
            || existing.owner != owner.coordinate
            || existing.request_sequence != request.request_sequence
            || existing.relation_generation != ticket.relation_generation
            || existing.parent != request.parent
            || existing.parent_role != request.parent_role
            || existing.child_role != request.child_role
            || existing.kind != request.kind
        {
            return Err(ParentingRefusal::PendingMismatch);
        }
        let now = self.now()?;
        if existing.expires_at <= now {
            self.remove_key(&key)?;
            return Err(ParentingRefusal::StaleRequest);
        }
        if let Some(reason) = rejection {
            self.remove_key(&key)?;
            return Ok(ParentAdoption::Rejected(reason));
        }
        let relation_generation = accepted_generation.ok_or(ParentingRefusal::PendingMismatch)?;
        if relation_generation == 0 {
            return Err(ParentingRefusal::PendingMismatch);
        }
        let next = relation_generation
            .checked_add(1)
            .ok_or(ParentingRefusal::GenerationOverflow)?;
        if self.next_relation_generation < next {
            self.next_relation_generation = next;
        }
        let next_state = match request.kind {
            ParentingRelationKind::Primary => RelationState::Primary,
            ParentingRelationKind::Backup => RelationState::Backup,
        };
        let accepted_expires_at = self.expiry(now)?;
        {
            let relation = self
                .records
                .get_mut(&key)
                .ok_or(ParentingRefusal::Invariant)?;
            relation.relation_generation = relation_generation;
            relation.expires_at = accepted_expires_at;
            relation.state = next_state;
        }
        self.pending_count = self
            .pending_count
            .checked_sub(1)
            .ok_or(ParentingRefusal::Invariant)?;
        match next_state {
            RelationState::Primary => {}
            RelationState::Backup => {
                self.backup_children = self
                    .backup_children
                    .checked_add(if key.child != self.policy.local { 1 } else { 0 })
                    .ok_or(ParentingRefusal::Invariant)?;
            }
            RelationState::Pending => return Err(ParentingRefusal::Invariant),
        }
        Ok(ParentAdoption::Accepted)
    }

    pub(super) fn cancel_child_attach(
        &mut self,
        owner: &ParentOwnerWitness,
        ticket: ParentAttachTicket,
    ) -> Result<(), ParentingRefusal> {
        let Some(existing) = self.records.get(&ticket.key).copied() else {
            return Err(ParentingRefusal::StaleRequest);
        };
        if existing.state != RelationState::Pending
            || existing.owner != ticket.owner
            || existing.owner != owner.coordinate
            || existing.request_sequence != ticket.request_sequence
            || existing.relation_generation != ticket.relation_generation
        {
            return Err(ParentingRefusal::StaleRequest);
        }
        self.remove_key(&ticket.key)?;
        Ok(())
    }

    pub(super) fn primary_parent(&mut self) -> Option<ParentingRelationSnapshot> {
        self.primary_parent_at_now().ok().flatten()
    }

    pub(super) fn primary_parent_at_now(
        &mut self,
    ) -> Result<Option<ParentingRelationSnapshot>, ParentingRefusal> {
        let now = self.now()?;
        let key = self.primary_key(self.policy.local);
        if self.expire_key_if_needed(key, now)? {
            return Ok(None);
        }
        Ok(self
            .records
            .get(&key)
            .copied()
            .filter(|relation| {
                relation.state == RelationState::Primary && relation.expires_at > now
            })
            .map(|relation| Self::relation_snapshot(key, relation)))
    }

    /// Return only bounded table facts needed by transport-lab controls.
    /// This is deliberately a snapshot rather than an authority predicate;
    /// callers must continue to use the exact peer-owner fences for traffic.
    #[cfg(feature = "transport-lab")]
    pub(super) fn snapshot_for_lab(&mut self) -> ParentingSnapshotForLab {
        ParentingSnapshotForLab {
            primary_parent: self
                .primary_parent_at_now()
                .ok()
                .flatten()
                .map(|relation| relation.parent.as_bytes()),
            accepted_children: self.primary_children.saturating_add(self.backup_children),
            pending: self.pending_count,
            generation: self.next_relation_generation.saturating_sub(1),
        }
    }

    /// Return whether an authenticated session may carry a tree application
    /// frame for this owner.  Leaves have exactly one accepted primary parent;
    /// roots and hubs may use only accepted child relations.  Pending,
    /// expired, or unrelated records never satisfy this gate.
    pub(super) fn allows_peer(&mut self, peer: ParentDeviceKey) -> bool {
        let Ok(now) = self.now() else {
            return false;
        };
        if matches!(self.policy.role, ParentingRole::Leaf) {
            return self
                .primary_parent_at_now()
                .ok()
                .flatten()
                .is_some_and(|relation| relation.parent == peer);
        }
        let mut cursor = None;
        let bound = self.record_count;
        for _ in 0..bound {
            let Some((key, relation)) = self.records.successor_after(cursor.as_ref()) else {
                break;
            };
            cursor = Some(*key);
            if relation.expires_at <= now {
                if self.expire_key_if_needed(*key, now).is_err() {
                    return false;
                }
                continue;
            }
            if relation.state != RelationState::Primary && relation.state != RelationState::Backup {
                continue;
            }
            if key.child == peer || relation.parent == peer {
                return true;
            }
        }
        false
    }

    fn expire_key_if_needed(
        &mut self,
        key: ParentingKey,
        now: ParentingTick,
    ) -> Result<bool, ParentingRefusal> {
        if self
            .records
            .get(&key)
            .is_some_and(|relation| relation.expires_at <= now)
        {
            self.remove_key(&key)?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn retire_owner(
        &mut self,
        owner: &ParentOwnerWitness,
    ) -> Result<usize, ParentingRefusal> {
        self.remove_matching(|_, relation| relation.owner == owner.coordinate)
    }

    pub(super) fn retire_peer(&mut self, peer: ParentDeviceKey) -> Result<usize, ParentingRefusal> {
        self.remove_matching(|key, relation| {
            key.child == peer || relation.parent == peer || relation.owner.peer == peer
        })
    }

    fn remove_matching(
        &mut self,
        mut matches: impl FnMut(ParentingKey, ParentingRelation) -> bool,
    ) -> Result<usize, ParentingRefusal> {
        let mut cursor = None;
        let start = self.records.successor_after(None).map(|(key, _)| *key);
        let bound = self.record_count;
        let mut removed: usize = 0;
        for step in 0..bound {
            let Some(key) = self.next_key_after(cursor.as_ref()) else {
                break;
            };
            if step > 0 && Some(key) == start {
                break;
            }
            cursor = Some(key);
            if self
                .records
                .get(&key)
                .copied()
                .is_some_and(|relation| matches(key, relation))
            {
                self.remove_key(&key)?;
                removed = removed.checked_add(1).ok_or(ParentingRefusal::Invariant)?;
            }
        }
        Ok(removed)
    }

    #[cfg(test)]
    pub(super) fn record_count_for_test(&self) -> usize {
        self.record_count
    }

    #[cfg(test)]
    pub(super) fn pending_count_for_test(&self) -> usize {
        self.pending_count
    }

    #[cfg(test)]
    pub(super) fn accepted_children_for_test(&self) -> usize {
        self.primary_children.saturating_add(self.backup_children)
    }
}

#[cfg(feature = "transport-lab")]
impl ParentingState<MonotonicParentingClock> {
    pub(super) fn advance_clock(&self, delta_ms: u64) -> Result<(), ParentingRefusal> {
        self.clock.advance(delta_ms)
    }
}

#[cfg(all(test, feature = "transport-lab"))]
mod tests {
    use super::*;
    use crate::resource::ResourceProviderPort;
    use ed25519_dalek::SigningKey;

    #[derive(Clone)]
    struct TestClock(std::sync::Arc<std::sync::atomic::AtomicU64>);

    impl TestClock {
        fn new(value: u64) -> Self {
            Self(std::sync::Arc::new(std::sync::atomic::AtomicU64::new(
                value,
            )))
        }

        fn set(&self, value: u64) {
            self.0.store(value, std::sync::atomic::Ordering::Release);
        }
    }

    impl ParentingClock for TestClock {
        fn now(&self) -> ParentingTick {
            ParentingTick(self.0.load(std::sync::atomic::Ordering::Acquire))
        }
    }

    fn device(value: u8) -> ParentDeviceKey {
        let signing_key = SigningKey::from_bytes(&[value; 32]);
        ParentDeviceKey::from_device(
            &DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
                .expect("derived valid test key"),
        )
    }

    fn policy(
        local: ParentDeviceKey,
        root: ParentDeviceKey,
        role: ParentingRole,
    ) -> ParentingPolicy {
        ParentingPolicy {
            local,
            root,
            role,
            max_hub_tier: 1,
            max_children: 2,
            max_backups: 1,
            max_pending: 1,
            max_age_ticks: 10,
            context_id: [1; 32],
            configuration_digest: [2; 32],
        }
    }

    fn fixture(
        policy: ParentingPolicy,
        clock: TestClock,
    ) -> (
        ParentingState<TestClock>,
        FiniteResourceProvider,
        LocalApplicationResourceScope,
    ) {
        let node = LeasedMap::<ParentingKey, ParentingRelation>::entry_claim()
            .expect("relation node claim");
        let per_entry =
            FiniteResourceProvider::reservation_planning_charge(node).expect("reservation claim");
        let grant = FiniteResourceProvider::scope_planning_charge()
            .checked_add(
                per_entry
                    .checked_scale(policy.relation_bound().expect("bounded relation count") as u64)
                    .expect("finite grant"),
            )
            .expect("finite grant");
        let provider = FiniteResourceProvider::new(grant);
        let port = ResourceProviderPort::new(provider.clone()).expect("provider port");
        let scope =
            LocalApplicationResourceScope::transport_lab_child_of(&port).expect("parenting scope");
        let state = ParentingState::new(scope.clone(), policy, clock).expect("valid policy");
        (state, provider, scope)
    }

    fn owner(value: u8) -> ParentOwnerWitness {
        let signing_key = SigningKey::from_bytes(&[value; 32]);
        let device = DeviceId::from_public_key_bytes(*signing_key.verifying_key().as_bytes())
            .expect("derived valid owner key");
        let token = PeerOwnerToken::detached_for_control(&device.base32());
        ParentOwnerWitness::from_owner(&token).expect("owner witness")
    }

    #[test]
    fn parent_accept_is_idempotent_and_peer_retire_releases_exact_node() {
        let clock = TestClock::new(1);
        let root = device(1);
        let child = device(2);
        let (mut state, provider, scope) = fixture(policy(root, root, ParentingRole::Root), clock);
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            1,
            child,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("request");
        let before = provider.in_use();
        let response = state.accept_request(&owner(2), request).expect("accepted");
        assert!(matches!(response, ParentAttachResponse::Accepted { .. }));
        assert_eq!(state.record_count_for_test(), 1);
        let duplicate = state
            .accept_request(&owner(2), request)
            .expect("idempotent");
        assert_eq!(duplicate, response);
        assert_eq!(state.record_count_for_test(), 1);
        assert!(state.retire_peer(child).expect("retire peer") == 1);
        assert_eq!(state.record_count_for_test(), 0);
        assert_eq!(provider.in_use(), before);
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn parent_accept_reack_preserves_generation_and_rejects_replacements() {
        let clock = TestClock::new(1);
        let root = device(10);
        let child = device(11);
        let (mut state, provider, scope) = fixture(policy(root, root, ParentingRole::Root), clock);
        let first_request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            1,
            child,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("first request");
        let owner = owner(11);
        let initial = provider.in_use();
        let initial_reservations = provider.active_reservations();
        let first = state
            .accept_request(&owner, first_request)
            .expect("first acceptance");
        let generation = match first {
            ParentAttachResponse::Accepted {
                relation_generation,
                ..
            } => relation_generation,
            ParentAttachResponse::Rejected { .. } => panic!("first request rejected"),
        };
        let accepted = provider.in_use();
        let accepted_reservations = provider.active_reservations();
        assert_ne!(accepted, initial);
        assert_eq!(accepted_reservations, initial_reservations + 1);
        let reack_request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            2,
            child,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("re-ack request");
        let reack = state
            .accept_request(&owner, reack_request)
            .expect("re-ack acceptance");
        assert!(matches!(
            reack,
            ParentAttachResponse::Accepted {
                relation_generation,
                ..
            } if relation_generation == generation
        ));
        assert_eq!(state.record_count_for_test(), 1);
        assert_eq!(provider.in_use(), accepted);
        assert_eq!(provider.active_reservations(), accepted_reservations);
        assert!(matches!(
            state.accept_request(&owner, reack_request),
            Ok(ParentAttachResponse::Accepted {
                relation_generation,
                ..
            }) if relation_generation == generation
        ));
        assert!(matches!(
            state.accept_request(&owner, first_request),
            Err(ParentingRefusal::StaleRequest)
        ));
        let replacement = ParentOwnerWitness {
            coordinate: ParentOwnerCoordinate {
                peer: child,
                binding_namespace: [9; 16],
                binding_epoch: 1,
            },
        };
        assert!(matches!(
            state.accept_request(&replacement, reack_request),
            Err(ParentingRefusal::StaleRequest)
        ));
        assert_eq!(state.record_count_for_test(), 1);
        assert_eq!(provider.in_use(), accepted);
        assert_eq!(provider.active_reservations(), accepted_reservations);
        assert_eq!(state.retire_peer(child).expect("retire child"), 1);
        assert_eq!(provider.in_use(), initial);
        assert_eq!(provider.active_reservations(), initial_reservations);
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn child_pending_requires_exact_response_and_cancellation_releases_node() {
        let clock = TestClock::new(1);
        let root = device(3);
        let hub = device(4);
        let policy = policy(hub, root, ParentingRole::Hub(1));
        let (mut state, provider, scope) = fixture(policy, clock);
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            7,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("request");
        let witness = owner(3);
        let before = provider.in_use();
        let ticket = state
            .begin_child_attach(&witness, request)
            .expect("pending registration");
        assert_eq!(state.pending_count_for_test(), 1);
        assert!(matches!(
            state.adopt_response(
                &witness,
                &ticket,
                ParentAttachResponse::Accepted {
                    request,
                    relation_generation: 9,
                },
            ),
            Ok(ParentAdoption::Accepted)
        ));
        assert_eq!(state.pending_count_for_test(), 0);
        assert!(state.primary_parent().is_some());
        assert!(state.cancel_child_attach(&witness, ticket).is_err());
        assert!(state.retire_owner(&witness).expect("retire owner") == 1);
        assert_eq!(provider.in_use(), before);
        drop(state);
        drop(scope);
    }

    #[test]
    fn accepted_relation_expires_and_reaccepts_with_new_generation() {
        let clock = TestClock::new(1);
        let root = device(12);
        let child = device(13);
        let (mut state, provider, scope) =
            fixture(policy(root, root, ParentingRole::Root), clock.clone());
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            1,
            child,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("request");
        let witness = owner(13);
        let before = provider.in_use();
        let first = state.accept_request(&witness, request).expect("accepted");
        let first_generation = match first {
            ParentAttachResponse::Accepted {
                relation_generation,
                ..
            } => relation_generation,
            ParentAttachResponse::Rejected { .. } => panic!("first request rejected"),
        };
        assert_eq!(state.record_count_for_test(), 1);
        clock.set(10);
        assert!(state.allows_peer(child));
        clock.set(11);
        assert!(!state.allows_peer(child));
        assert_eq!(state.record_count_for_test(), 0);
        assert_eq!(provider.in_use(), before);
        let successor = state.accept_request(&witness, request).expect("reaccepted");
        let successor_generation = match successor {
            ParentAttachResponse::Accepted {
                relation_generation,
                ..
            } => relation_generation,
            ParentAttachResponse::Rejected { .. } => panic!("successor request rejected"),
        };
        assert!(successor_generation > first_generation);
        assert_eq!(state.record_count_for_test(), 1);
        state.retire_owner(&witness).expect("retire successor");
        assert_eq!(provider.in_use(), before);
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn accepted_expiry_maintenance_is_bounded_and_child_reattaches() {
        let clock = TestClock::new(1);
        let root = device(14);
        let hub = device(15);
        let child_a = device(16);
        let child_b = device(17);
        let (mut parent, provider, scope) =
            fixture(policy(root, root, ParentingRole::Root), clock.clone());
        let request = |child, sequence| {
            ParentAttachRequest::new(
                [1; 32],
                [2; 32],
                sequence,
                child,
                root,
                ParentingRole::Hub(1),
                ParentingRole::Root,
                ParentingRelationKind::Primary,
            )
            .expect("request")
        };
        parent
            .accept_request(&owner(16), request(child_a, 1))
            .expect("first child");
        parent
            .accept_request(&owner(17), request(child_b, 2))
            .expect("second child");
        assert_eq!(parent.record_count_for_test(), 2);
        clock.set(11);
        assert_eq!(parent.maintain_now().expect("first maintenance"), 1);
        assert_eq!(parent.record_count_for_test(), 1);
        assert_eq!(parent.maintain_now().expect("second maintenance"), 1);
        assert_eq!(parent.record_count_for_test(), 0);
        drop(parent);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);

        let clock = TestClock::new(1);
        let (mut child_state, provider, scope) =
            fixture(policy(hub, root, ParentingRole::Hub(1)), clock.clone());
        let first_request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            10,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("first child request");
        let witness = owner(14);
        let first_ticket = child_state
            .begin_child_attach(&witness, first_request)
            .expect("first pending");
        child_state
            .adopt_response(
                &witness,
                &first_ticket,
                ParentAttachResponse::Accepted {
                    request: first_request,
                    relation_generation: 20,
                },
            )
            .expect("first adoption");
        clock.set(11);
        assert!(child_state
            .primary_parent_at_now()
            .expect("expired child parent")
            .is_none());
        assert!(matches!(
            child_state.adopt_response(
                &witness,
                &first_ticket,
                ParentAttachResponse::Accepted {
                    request: first_request,
                    relation_generation: 21,
                },
            ),
            Err(ParentingRefusal::PendingMismatch)
        ));
        let successor_request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            11,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("successor request");
        let successor_ticket = child_state
            .begin_child_attach(&witness, successor_request)
            .expect("successor pending");
        child_state
            .adopt_response(
                &witness,
                &successor_ticket,
                ParentAttachResponse::Accepted {
                    request: successor_request,
                    relation_generation: 21,
                },
            )
            .expect("successor adoption");
        assert!(child_state.primary_parent().is_some());
        child_state.retire_owner(&witness).expect("retire child");
        drop(child_state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn child_backup_adoption_does_not_consume_child_capacity_and_expires() {
        let clock = TestClock::new(1);
        let root = device(18);
        let hub = device(19);
        let (mut state, provider, scope) =
            fixture(policy(hub, root, ParentingRole::Hub(1)), clock.clone());
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            1,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Backup,
        )
        .expect("backup request");
        let witness = owner(18);
        let before = provider.in_use();
        let before_reservations = provider.active_reservations();
        let ticket = state
            .begin_child_attach(&witness, request)
            .expect("backup pending registration");
        state
            .adopt_response(
                &witness,
                &ticket,
                ParentAttachResponse::Accepted {
                    request,
                    relation_generation: 1,
                },
            )
            .expect("backup adoption");
        assert_eq!(state.accepted_children_for_test(), 0);
        assert!(state.allows_peer(root));
        assert_ne!(provider.in_use(), before);
        assert_eq!(provider.active_reservations(), before_reservations + 1);

        clock.set(11);
        assert!(!state.allows_peer(root));
        assert_eq!(state.record_count_for_test(), 0);
        assert_eq!(state.accepted_children_for_test(), 0);
        assert_eq!(provider.in_use(), before);
        assert_eq!(provider.active_reservations(), before_reservations);
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn child_binds_remote_parent_and_rejects_directly_expired_response() {
        let clock = TestClock::new(1);
        let root = device(7);
        let hub = device(8);
        let (mut state, provider, scope) =
            fixture(policy(hub, root, ParentingRole::Hub(1)), clock.clone());
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            10,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("request");
        assert!(state.begin_child_attach(&owner(8), request).is_err());
        assert!(state.begin_child_attach(&owner(9), request).is_err());
        let remote_parent = owner(7);
        let ticket = state
            .begin_child_attach(&remote_parent, request)
            .expect("remote parent registration");
        clock.set(11);
        assert!(matches!(
            state.adopt_response(
                &remote_parent,
                &ticket,
                ParentAttachResponse::Accepted {
                    request,
                    relation_generation: 12,
                },
            ),
            Err(ParentingRefusal::StaleRequest)
        ));
        assert_eq!(state.record_count_for_test(), 0);
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }

    #[test]
    fn pending_expiry_is_bounded_and_old_ticket_cannot_bind_successor() {
        let clock = TestClock::new(1);
        let root = device(5);
        let hub = device(6);
        let (mut state, provider, scope) =
            fixture(policy(hub, root, ParentingRole::Hub(1)), clock.clone());
        let request = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            8,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("request");
        let witness = owner(5);
        let ticket = state
            .begin_child_attach(&witness, request)
            .expect("pending");
        clock.set(12);
        assert_eq!(state.maintain_now().expect("maintenance"), 1);
        assert_eq!(state.pending_count_for_test(), 0);
        assert!(state.cancel_child_attach(&witness, ticket).is_err());
        let replacement = ParentAttachRequest::new(
            [1; 32],
            [2; 32],
            9,
            hub,
            root,
            ParentingRole::Hub(1),
            ParentingRole::Root,
            ParentingRelationKind::Primary,
        )
        .expect("successor request");
        let successor = state
            .begin_child_attach(&witness, replacement)
            .expect("successor");
        assert!(state
            .adopt_response(
                &witness,
                &successor,
                ParentAttachResponse::Rejected {
                    request: replacement,
                    reason: ParentAttachRejection::StaleRequest,
                },
            )
            .is_ok());
        assert!(state.cancel_child_attach(&witness, successor).is_err());
        state.retire_owner(&witness).expect("retire owner");
        drop(state);
        drop(scope);
        assert_eq!(provider.in_use(), ResourceClaim::ZERO);
    }
}
