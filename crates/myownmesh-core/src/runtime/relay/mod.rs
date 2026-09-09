//! Closed-member opaque relay runtime.
//!
//! A relay allocation owns only a bounded ciphertext queue and lifecycle
//! witnesses. Endpoint key material lives in [`OpaqueRelaySession`] and never
//! crosses into this relay-side port.

use std::time::{Duration, Instant};

use parking_lot::Mutex;
use rand_core::OsRng;
use thiserror::Error;
use tokio::sync::mpsc;
use x25519_dalek::{EphemeralSecret, PublicKey};
use zeroize::Zeroize;

use crate::config::ClosedRelayPolicyConfig;
use crate::identity::Identity;
#[cfg(test)]
use crate::protocol::relay::ClosedRelayRoute;
use crate::protocol::relay::{
    OpaqueRelayPacket, RelayKeyShare, OPAQUE_RELAY_NONCE_BYTES, OPAQUE_RELAY_VERSION,
};
use crate::resource::{
    FundedArc, ResourceAuthorityClass, ResourceClaim, ResourceClass, ResourceLease,
};
use crate::runtime::endpoint_cipher::{decrypt, derive_material, encrypt, ReplayWindow};
use crate::runtime::session_broker::SessionValidityWitness;
use crate::semantic::{DeviceId, MeshContextId};

const AEAD_TAG_BYTES: usize = 16;
const KEY_BYTES: usize = 32;
const NONCE_PREFIX_BYTES: usize = 4;
// A canonical DeviceId and MeshContextId are 32 bytes encoded as lowercase
// unpadded base32. This is a representation bound for retained route strings,
// not a relay workload selector.
const CANONICAL_ROUTE_STRING_BYTES: usize = 52;
const RELAY_DIRECTION_COUNT: usize = 2;
// Each retained packet owns its three route strings and ciphertext buffer.
// The channel node itself is a separate opaque dependency allocation.
const PACKET_HEAP_ALLOCATIONS: u64 = 4;
const CHANNEL_NODE_ALLOCATIONS: u64 = 1;

/// Convert the owner-selected plaintext ceiling into the corresponding wire
/// ciphertext ceiling.  The AEAD tag is part of the ciphertext, and the
/// conversion is checked so malformed platform-sized values fail closed.
pub(crate) fn checked_ciphertext_ceiling(
    plaintext_ceiling: u64,
) -> Result<usize, ClosedRelayRefusal> {
    usize::try_from(plaintext_ceiling)
        .ok()
        .and_then(|value| value.checked_add(AEAD_TAG_BYTES))
        .ok_or(ClosedRelayRefusal::InvalidProfile)
}

/// Typed failures at the relay and endpoint envelope boundaries.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ClosedRelayRefusal {
    #[error("closed relay profile is invalid")]
    InvalidProfile,
    #[error("closed relay owner witness is not live")]
    OwnerNotLive,
    #[error("closed relay owner witnesses do not match")]
    OwnerMismatch,
    #[error("closed relay endpoints are invalid: {0}")]
    InvalidEndpoints(String),
    #[error("closed relay packet is invalid: {0}")]
    InvalidPacket(String),
    #[error("closed relay queue is full")]
    QueueFull,
    #[error("closed relay queue is closed")]
    QueueClosed,
    #[error("closed relay carrier is unavailable")]
    CarrierUnavailable,
    #[error("closed relay allocation expired")]
    Expired,
    #[error("closed relay cryptographic operation failed: {0}")]
    Crypto(String),
}

/// The two independently bounded directions of one A–B–C allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDirection {
    RequesterToTarget,
    TargetToRequester,
}

impl RelayDirection {
    const fn index(self) -> usize {
        match self {
            Self::RequesterToTarget => 0,
            Self::TargetToRequester => 1,
        }
    }
}

/// Route metadata for one exact closed allocation. It contains no IP address,
/// fanout selector, endpoint key, or authority-bearing capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClosedRelayEndpoints {
    pub mesh: MeshContextId,
    pub requester: DeviceId,
    pub target: DeviceId,
    pub session_id: [u8; 16],
    pub allocation_epoch: u64,
}

impl ClosedRelayEndpoints {
    pub(crate) fn new(
        mesh: MeshContextId,
        requester: DeviceId,
        target: DeviceId,
        session_id: [u8; 16],
        allocation_epoch: u64,
    ) -> Result<Self, ClosedRelayRefusal> {
        let endpoints = Self {
            mesh,
            requester,
            target,
            session_id,
            allocation_epoch,
        };
        endpoints.validate()?;
        Ok(endpoints)
    }

    fn validate(&self) -> Result<(), ClosedRelayRefusal> {
        if self.requester == self.target {
            return Err(ClosedRelayRefusal::InvalidEndpoints(
                "requester and target must differ".into(),
            ));
        }
        if self.allocation_epoch == 0 {
            return Err(ClosedRelayRefusal::InvalidEndpoints(
                "allocation epoch must be nonzero after admission".into(),
            ));
        }
        Ok(())
    }
}

/// A provider-backed, move-only lease for one closed relay allocation.
///
/// There is no public constructor: the engine must first present an exact
/// current session witness, so a caller cannot fabricate relay authority from
/// route strings alone.
pub struct RelayAllocationPermit {
    owner: SessionValidityWitness,
    _lease: ResourceLease,
}

impl RelayAllocationPermit {
    pub(crate) fn allocation_claim(
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<ResourceClaim, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let queue = usize::try_from(profile.queue_items_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let max_ciphertext_bytes = checked_ciphertext_ceiling(profile.max_frame_ciphertext_bytes)?;
        let retained_endpoint_string_bytes = CANONICAL_ROUTE_STRING_BYTES
            .checked_mul(2)
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let retained_member_string_bytes = CANONICAL_ROUTE_STRING_BYTES;
        let packet_retained_bytes = std::mem::size_of::<OpaqueRelayPacket>()
            .checked_add(
                CANONICAL_ROUTE_STRING_BYTES
                    .checked_mul(RELAY_DIRECTION_COUNT + 1)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .and_then(|value| value.checked_add(max_ciphertext_bytes))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let queue_slots = queue
            .checked_mul(2)
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let queue_bytes = queue_slots
            .checked_mul(packet_retained_bytes)
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let bytes = std::mem::size_of::<Self>()
            .checked_add(std::mem::size_of::<ClosedRelayHandle>())
            // The ActiveAllocation value itself lives in the fixed,
            // root-funded state table; only its retained member string is
            // charged to this allocation below.
            .and_then(|value| value.checked_add(retained_endpoint_string_bytes))
            .and_then(|value| value.checked_add(retained_member_string_bytes))
            .and_then(|value| value.checked_add(queue_bytes))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let queued_bytes = profile
            .queue_bytes_per_direction
            .checked_mul(2)
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        // Each channel has one bounded bookkeeping container and each possible
        // retained packet has its route/ciphertext buffers plus one queue node.
        let opaque_allocations = 2_u64
            .checked_add(
                u64::try_from(queue_slots)
                    .map_err(|_| ClosedRelayRefusal::InvalidProfile)?
                    .checked_mul(PACKET_HEAP_ALLOCATIONS + CHANNEL_NODE_ALLOCATIONS)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .and_then(|value| value.checked_add(1))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(bytes).map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
            ),
            (ResourceClass::QueuedBytes, queued_bytes),
            (ResourceClass::RelayOrProviderAllocation, 1),
            (ResourceClass::OpaqueDependencyResidual, opaque_allocations),
        ])
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)
    }

    pub(crate) fn try_new(
        owner: SessionValidityWitness,
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<Self, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        if !owner.is_live() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let claim = Self::allocation_claim(profile)?;
        let lease = owner
            .reserve_retained(claim)
            .map_err(|_| ClosedRelayRefusal::OwnerNotLive)?;
        Ok(Self {
            owner,
            _lease: lease,
        })
    }
}

/// Runtime port for relay-side allocation admission and settlement.
pub struct ClosedRelayRuntime {
    profile: ClosedRelayPolicyConfig,
    local_device_id: DeviceId,
    state: FundedArc<Mutex<RelayAdmissionState>>,
}

impl ClosedRelayRuntime {
    // One Arc value allocation, one Arc lease allocation, and the two fixed
    // occupancy tables. The tables are allocated before this value is
    // published, so no later admission can require an uncharged resize.
    const ROOT_HEAP_ALLOCATIONS: u64 = 4;

    /// Exact process-local custody for the runtime's shared admission root.
    ///
    /// The active and tombstone values are stored in fixed tables sized by the
    /// configured ceilings. Per-handle accounting covers the handle itself;
    /// this claim covers the shared root, table slots, handshake owners, and
    /// the runtime's FundedArc owner.
    pub(crate) fn runtime_claim(
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<ResourceClaim, ClosedRelayRefusal> {
        if !profile.enabled || !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let active_bytes = capacity
            .checked_mul(std::mem::size_of::<Option<ActiveAllocation>>())
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let tombstone_bytes = capacity
            .checked_mul(std::mem::size_of::<Option<RelayTerminalTombstone>>())
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let handshake_bytes = usize::try_from(profile.max_pending_handshakes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?
            .checked_mul(std::mem::size_of::<ClosedRelayHandshakeGuard>())
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let bytes = std::mem::size_of::<Mutex<RelayAdmissionState>>()
            .checked_add(active_bytes)
            .and_then(|value| value.checked_add(tombstone_bytes))
            .and_then(|value| value.checked_add(handshake_bytes))
            .and_then(|value| {
                value.checked_add(std::mem::size_of::<FundedArc<Mutex<RelayAdmissionState>>>())
            })
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        ResourceClaim::try_from_entries([
            (
                ResourceClass::AccountedMemoryBytes,
                u64::try_from(bytes).map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
            ),
            (
                ResourceClass::OpaqueDependencyResidual,
                Self::ROOT_HEAP_ALLOCATIONS,
            ),
        ])
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)
    }

    pub(crate) fn new(
        profile: ClosedRelayPolicyConfig,
        local_device_id: DeviceId,
        funding: ResourceLease,
    ) -> Result<Self, ClosedRelayRefusal> {
        let root_claim = Self::runtime_claim(&profile)?;
        if funding.authority() != ResourceAuthorityClass::Admitted || funding.claim() != root_claim
        {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let terminal_tombstone_capacity = usize::try_from(profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let active_allocations = (0..terminal_tombstone_capacity)
            .map(|_| None)
            .collect::<Vec<Option<ActiveAllocation>>>()
            .into_boxed_slice();
        let terminal_tombstones = (0..terminal_tombstone_capacity)
            .map(|_| None)
            .collect::<Vec<Option<RelayTerminalTombstone>>>()
            .into_boxed_slice();
        let state = FundedArc::new(
            Mutex::new(RelayAdmissionState {
                active_allocations,
                terminal_tombstones,
                terminal_tombstone_capacity,
                terminal_tombstones_len: 0,
                pending_handshakes: 0,
                next_allocation_id: 0,
                next_allocation_epoch: 0,
            }),
            funding,
        )
        .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        Ok(Self {
            profile,
            local_device_id,
            state,
        })
    }

    pub(crate) fn try_begin_handshake(
        &self,
    ) -> Result<ClosedRelayHandshakeGuard, ClosedRelayRefusal> {
        let expires_at = Instant::now()
            .checked_add(Duration::from_millis(
                self.profile.pending_handshake_timeout_ms,
            ))
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        let mut state = self.state.lock();
        let limit = usize::try_from(self.profile.max_pending_handshakes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        if state.pending_handshakes >= limit {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        state.pending_handshakes += 1;
        Ok(ClosedRelayHandshakeGuard {
            state: self.state.clone(),
            expires_at,
        })
    }

    #[cfg(test)]
    pub(crate) fn terminal_tombstone_epoch(&self, session_id: [u8; 16]) -> Option<u64> {
        self.state.lock().terminal_tombstone(session_id)
    }

    /// Mint the checked, monotonic epoch that B places on every operation
    /// after pending Open admission. Epoch zero is reserved for Open itself.
    pub(crate) fn mint_allocation_epoch(&self) -> Result<u64, ClosedRelayRefusal> {
        let mut state = self.state.lock();
        let epoch = state
            .next_allocation_epoch
            .checked_add(1)
            .ok_or(ClosedRelayRefusal::InvalidProfile)?;
        state.next_allocation_epoch = epoch;
        Ok(epoch)
    }

    pub(crate) fn admit_closed_relay(
        &self,
        permit: RelayAllocationPermit,
        requester: SessionValidityWitness,
        target: SessionValidityWitness,
        endpoints: ClosedRelayEndpoints,
    ) -> Result<ClosedRelayHandle, ClosedRelayRefusal> {
        if !requester.is_live() || !target.is_live() {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        if !permit.owner.same_validity(&requester) {
            return Err(ClosedRelayRefusal::OwnerMismatch);
        }
        endpoints.validate()?;
        if endpoints.requester == self.local_device_id || endpoints.target == self.local_device_id {
            return Err(ClosedRelayRefusal::InvalidEndpoints(
                "relay host cannot be an endpoint".into(),
            ));
        }
        let capacity = usize::try_from(self.profile.queue_items_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let member = endpoints.requester.base32();
        let max_allocations = usize::try_from(self.profile.max_allocations)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let max_per_member = usize::try_from(self.profile.max_allocations_per_member)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let max_ciphertext_bytes =
            checked_ciphertext_ceiling(self.profile.max_frame_ciphertext_bytes)?;
        #[cfg(test)]
        let max_control_bytes = usize::try_from(self.profile.max_control_bytes)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        let queue_bytes_capacity = usize::try_from(self.profile.queue_bytes_per_direction)
            .map_err(|_| ClosedRelayRefusal::InvalidProfile)?;
        {
            let mut state = self.state.lock();
            if state
                .terminal_tombstone(endpoints.session_id)
                .is_some_and(|epoch| endpoints.allocation_epoch <= epoch)
            {
                return Err(ClosedRelayRefusal::OwnerMismatch);
            }
            if state
                .active_allocations
                .iter()
                .filter_map(Option::as_ref)
                .any(|active| active.session_id == endpoints.session_id)
            {
                return Err(ClosedRelayRefusal::OwnerMismatch);
            }
            if state
                .active_allocations
                .iter()
                .filter(|active| active.is_some())
                .count()
                >= max_allocations
                || state
                    .active_allocations
                    .iter()
                    .filter_map(Option::as_ref)
                    .filter(|active| active.member == member)
                    .count()
                    >= max_per_member
            {
                return Err(ClosedRelayRefusal::QueueFull);
            }
            let allocation_id = state.next_allocation_id;
            state.next_allocation_id = state
                .next_allocation_id
                .checked_add(1)
                .ok_or(ClosedRelayRefusal::InvalidProfile)?;
            let active_slot = state
                .active_allocations
                .iter()
                .position(Option::is_none)
                .ok_or(ClosedRelayRefusal::QueueFull)?;
            state.active_allocations[active_slot] = Some(ActiveAllocation {
                id: allocation_id,
                member: member.clone(),
                session_id: endpoints.session_id,
            });
            let (requester_tx, requester_rx) = mpsc::channel(capacity);
            let (target_tx, target_rx) = mpsc::channel(capacity);
            Ok(ClosedRelayHandle {
                requester,
                target,
                endpoints,
                max_ciphertext_bytes,
                #[cfg(test)]
                max_control_bytes,
                queue_items_capacity: capacity,
                queue_bytes_capacity,
                queue: Mutex::new([QueueAccounting::default(), QueueAccounting::default()]),
                bandwidth: Mutex::new(BandwidthBucket::new(
                    self.profile.bandwidth_rate_bytes_per_second,
                    self.profile.bandwidth_burst_bytes,
                )),
                state: self.state.clone(),
                allocation_id,
                opened_at: Instant::now(),
                last_activity: Instant::now(),
                idle_timeout: Duration::from_millis(self.profile.idle_timeout_ms),
                lifetime: Duration::from_millis(self.profile.max_lifetime_ms),
                requester_tx,
                requester_rx,
                target_tx,
                target_rx,
                settled: false,
                _permit: permit,
            })
        }
    }
}

/// One exact relay allocation. This is intentionally keyless: it can forward
/// an endpoint-authenticated ciphertext but cannot decrypt or mint authority.
pub struct ClosedRelayHandle {
    requester: SessionValidityWitness,
    target: SessionValidityWitness,
    endpoints: ClosedRelayEndpoints,
    max_ciphertext_bytes: usize,
    #[cfg(test)]
    max_control_bytes: usize,
    queue_items_capacity: usize,
    queue_bytes_capacity: usize,
    queue: Mutex<[QueueAccounting; 2]>,
    bandwidth: Mutex<BandwidthBucket>,
    state: FundedArc<Mutex<RelayAdmissionState>>,
    allocation_id: u64,
    opened_at: Instant,
    last_activity: Instant,
    idle_timeout: Duration,
    lifetime: Duration,
    requester_tx: mpsc::Sender<OpaqueRelayPacket>,
    requester_rx: mpsc::Receiver<OpaqueRelayPacket>,
    target_tx: mpsc::Sender<OpaqueRelayPacket>,
    target_rx: mpsc::Receiver<OpaqueRelayPacket>,
    settled: bool,
    // Last so channels, queued packets, and all other handle-owned values are
    // destroyed before their funding is released, including terminal errors.
    _permit: RelayAllocationPermit,
}

impl ClosedRelayHandle {
    #[cfg(test)]
    pub(crate) fn try_forward(
        &mut self,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        let requester = self.endpoints.requester.base32();
        let target = self.endpoints.target.base32();
        let direction = if packet.from == requester && packet.to == target {
            RelayDirection::RequesterToTarget
        } else if packet.from == target && packet.to == requester {
            RelayDirection::TargetToRequester
        } else {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet route does not match allocation".into(),
            ));
        };
        self.try_forward_direction(direction, packet)
    }

    pub(crate) fn try_forward_direction(
        &mut self,
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        self.ensure_active()?;
        packet
            .validate(self.max_ciphertext_bytes)
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        let (from, to) = match direction {
            RelayDirection::RequesterToTarget => (
                self.endpoints.requester.base32(),
                self.endpoints.target.base32(),
            ),
            RelayDirection::TargetToRequester => (
                self.endpoints.target.base32(),
                self.endpoints.requester.base32(),
            ),
        };
        if packet.mesh != self.endpoints.mesh.base32()
            || packet.session_id != self.endpoints.session_id
            || packet.from != from
            || packet.to != to
        {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet route does not match allocation".into(),
            ));
        }
        let bytes = packet.ciphertext.len();
        {
            let queues = self.queue.lock();
            let queue = &queues[direction.index()];
            if queue.items >= self.queue_items_capacity
                || queue
                    .bytes
                    .checked_add(bytes)
                    .is_none_or(|total| total > self.queue_bytes_capacity)
            {
                return Err(ClosedRelayRefusal::QueueFull);
            }
        }
        let sender_is_closed = match direction {
            RelayDirection::RequesterToTarget => self.requester_tx.is_closed(),
            RelayDirection::TargetToRequester => self.target_tx.is_closed(),
        };
        if sender_is_closed {
            self.terminate();
            return Err(ClosedRelayRefusal::QueueClosed);
        }
        if !self.bandwidth.lock().consume(bytes) {
            return Err(ClosedRelayRefusal::QueueFull);
        }
        let channel_closed = {
            let mut queues = self.queue.lock();
            let queue = &mut queues[direction.index()];
            if queue.items >= self.queue_items_capacity
                || queue
                    .bytes
                    .checked_add(bytes)
                    .is_none_or(|total| total > self.queue_bytes_capacity)
            {
                return Err(ClosedRelayRefusal::QueueFull);
            }
            let sender = match direction {
                RelayDirection::RequesterToTarget => &self.requester_tx,
                RelayDirection::TargetToRequester => &self.target_tx,
            };
            match sender.try_send(packet) {
                Ok(()) => {
                    queue.items += 1;
                    queue.bytes += bytes;
                    false
                }
                Err(mpsc::error::TrySendError::Full(_)) => {
                    return Err(ClosedRelayRefusal::QueueFull);
                }
                Err(mpsc::error::TrySendError::Closed(_)) => true,
            }
        };
        if channel_closed {
            self.terminate();
            return Err(ClosedRelayRefusal::QueueClosed);
        }
        self.last_activity = Instant::now();
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn try_forward_control(
        &mut self,
        packet: OpaqueRelayPacket,
    ) -> Result<(), ClosedRelayRefusal> {
        if packet.ciphertext.len() > self.max_control_bytes {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "control packet exceeds configured bound".into(),
            ));
        }
        self.try_forward(packet)
    }

    /// Receive while preserving terminal ownership errors for the engine.
    #[cfg(test)]
    pub(crate) async fn recv_checked(
        &mut self,
    ) -> Result<Option<OpaqueRelayPacket>, ClosedRelayRefusal> {
        self.ensure_active()?;
        let Some(deadline) = self.expiration_deadline() else {
            self.terminate();
            return Err(ClosedRelayRefusal::InvalidProfile);
        };
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let (direction, packet) = tokio::select! {
            packet = self.requester_rx.recv() => Some((RelayDirection::RequesterToTarget, packet)),
            packet = self.target_rx.recv() => Some((RelayDirection::TargetToRequester, packet)),
            _ = &mut sleep => {
                self.terminate();
                return Err(ClosedRelayRefusal::Expired);
            },
        }
        .ok_or(ClosedRelayRefusal::QueueClosed)?;
        let packet = match packet {
            Some(packet) => packet,
            None => {
                self.terminate();
                return Err(ClosedRelayRefusal::QueueClosed);
            }
        };
        self.ensure_active()?;
        Ok(Some(self.account_received(direction, packet)))
    }

    /// Direction-specific receive which exposes expiry and stale-owner
    /// terminal outcomes to the registry/engine owner.
    pub(crate) async fn recv_direction_checked(
        &mut self,
        direction: RelayDirection,
    ) -> Result<Option<OpaqueRelayPacket>, ClosedRelayRefusal> {
        self.ensure_active()?;
        let Some(deadline) = self.expiration_deadline() else {
            self.terminate();
            return Err(ClosedRelayRefusal::InvalidProfile);
        };
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        tokio::pin!(sleep);
        let packet = match direction {
            RelayDirection::RequesterToTarget => tokio::select! {
                packet = self.requester_rx.recv() => packet,
                _ = &mut sleep => {
                    self.terminate();
                    return Err(ClosedRelayRefusal::Expired);
                },
            },
            RelayDirection::TargetToRequester => tokio::select! {
                packet = self.target_rx.recv() => packet,
                _ = &mut sleep => {
                    self.terminate();
                    return Err(ClosedRelayRefusal::Expired);
                },
            },
        };
        let packet = match packet {
            Some(packet) => packet,
            None => {
                self.terminate();
                return Err(ClosedRelayRefusal::QueueClosed);
            }
        };
        self.ensure_active()?;
        Ok(Some(self.account_received(direction, packet)))
    }

    fn account_received(
        &mut self,
        direction: RelayDirection,
        packet: OpaqueRelayPacket,
    ) -> OpaqueRelayPacket {
        let bytes = packet.ciphertext.len();
        let mut queue = self.queue.lock();
        let queue = &mut queue[direction.index()];
        queue.items = queue.items.saturating_sub(1);
        queue.bytes = queue.bytes.saturating_sub(bytes);
        self.last_activity = Instant::now();
        packet
    }

    pub(crate) fn settle(mut self) -> ClosedRelayTerminal {
        self.terminate();
        ClosedRelayTerminal::Settled
    }

    pub(crate) fn settle_stale(mut self) -> ClosedRelayTerminal {
        self.terminate();
        ClosedRelayTerminal::Settled
    }

    fn ensure_active(&mut self) -> Result<(), ClosedRelayRefusal> {
        if self.settled {
            return Err(ClosedRelayRefusal::OwnerNotLive);
        }
        let refusal = if !self.requester.is_live() || !self.target.is_live() {
            Some(ClosedRelayRefusal::OwnerNotLive)
        } else {
            let now = Instant::now();
            (now.duration_since(self.opened_at) >= self.lifetime
                || now.duration_since(self.last_activity) >= self.idle_timeout)
                .then_some(ClosedRelayRefusal::Expired)
        };
        if let Some(refusal) = refusal {
            self.terminate();
            return Err(refusal);
        }
        Ok(())
    }

    fn expiration_deadline(&self) -> Option<Instant> {
        let lifetime = self.opened_at.checked_add(self.lifetime)?;
        let idle = self.last_activity.checked_add(self.idle_timeout)?;
        Some(lifetime.min(idle))
    }

    fn terminate(&mut self) {
        if self.settled {
            return;
        }
        let mut state = self.state.lock();
        if let Some(index) = state.active_allocations.iter().position(|active| {
            active
                .as_ref()
                .is_some_and(|active| active.id == self.allocation_id)
        }) {
            state.active_allocations[index] = None;
        }
        state.record_terminal_tombstone(self.endpoints.session_id, self.endpoints.allocation_epoch);
        drop(state);
        self.settled = true;
    }

    fn release_allocation(&mut self) {
        if self.settled {
            return;
        }
        self.terminate();
    }
}

impl Drop for ClosedRelayHandle {
    fn drop(&mut self) {
        self.release_allocation();
    }
}

#[derive(Default)]
struct QueueAccounting {
    items: usize,
    bytes: usize,
}

struct RelayAdmissionState {
    active_allocations: Box<[Option<ActiveAllocation>]>,
    terminal_tombstones: Box<[Option<RelayTerminalTombstone>]>,
    terminal_tombstone_capacity: usize,
    terminal_tombstones_len: usize,
    pending_handshakes: usize,
    next_allocation_id: u64,
    next_allocation_epoch: u64,
}

struct ActiveAllocation {
    id: u64,
    member: String,
    session_id: [u8; 16],
}

struct RelayTerminalTombstone {
    session_id: [u8; 16],
    allocation_epoch: u64,
}

impl RelayAdmissionState {
    fn terminal_tombstone(&self, session_id: [u8; 16]) -> Option<u64> {
        self.terminal_tombstones[..self.terminal_tombstones_len]
            .iter()
            .filter_map(Option::as_ref)
            .find(|tombstone| tombstone.session_id == session_id)
            .map(|tombstone| tombstone.allocation_epoch)
    }

    fn record_terminal_tombstone(&mut self, session_id: [u8; 16], allocation_epoch: u64) {
        if self.terminal_tombstone_capacity == 0 {
            return;
        }
        if let Some(tombstone) = self.terminal_tombstones[..self.terminal_tombstones_len]
            .iter_mut()
            .filter_map(Option::as_mut)
            .find(|tombstone| tombstone.session_id == session_id)
        {
            tombstone.allocation_epoch = tombstone.allocation_epoch.max(allocation_epoch);
            return;
        }
        if self.terminal_tombstones_len >= self.terminal_tombstone_capacity {
            // The table is bounded by the configured allocation ceiling. The
            // newest epoch is more useful than an older unrelated session,
            // while replacing an existing session above preserves its fence.
            let last = self.terminal_tombstones_len - 1;
            self.terminal_tombstones[0] = self.terminal_tombstones[last].take();
            self.terminal_tombstones[last] = Some(RelayTerminalTombstone {
                session_id,
                allocation_epoch,
            });
            return;
        }
        self.terminal_tombstones[self.terminal_tombstones_len] = Some(RelayTerminalTombstone {
            session_id,
            allocation_epoch,
        });
        self.terminal_tombstones_len += 1;
    }
}

pub(crate) struct ClosedRelayHandshakeGuard {
    state: FundedArc<Mutex<RelayAdmissionState>>,
    expires_at: Instant,
}

impl ClosedRelayHandshakeGuard {
    fn is_expired(&self) -> bool {
        Instant::now() >= self.expires_at
    }
}

impl Drop for ClosedRelayHandshakeGuard {
    fn drop(&mut self) {
        let mut state = self.state.lock();
        state.pending_handshakes = state.pending_handshakes.saturating_sub(1);
    }
}

struct BandwidthBucket {
    rate: u64,
    burst: u64,
    tokens: u64,
    last: Instant,
}

impl BandwidthBucket {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            rate,
            burst,
            tokens: burst,
            last: Instant::now(),
        }
    }

    fn consume(&mut self, bytes: usize) -> bool {
        let elapsed = self.last.elapsed();
        let Some(refill) = u128::from(self.rate)
            .checked_mul(elapsed.as_nanos())
            .and_then(|value| value.checked_div(1_000_000_000))
            .and_then(|value| u64::try_from(value).ok())
        else {
            return false;
        };
        self.tokens = self.tokens.saturating_add(refill).min(self.burst);
        self.last = Instant::now();
        let Ok(bytes) = u64::try_from(bytes) else {
            return false;
        };
        if bytes > self.tokens {
            return false;
        }
        self.tokens -= bytes;
        true
    }
}

/// Exactly one terminal transition for a consumed relay allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClosedRelayTerminal {
    Settled,
}

/// Pending endpoint side of the authenticated key agreement. This object is
/// move-only so the ephemeral secret cannot be copied into relay state.
pub struct PendingEndpointKeyAgreement {
    mesh: MeshContextId,
    local_id: DeviceId,
    peer_id: DeviceId,
    session_id: [u8; 16],
    local_public: [u8; 32],
    secret: EphemeralSecret,
    max_packet_bytes: usize,
    replay_window: usize,
    _handshake: Option<ClosedRelayHandshakeGuard>,
}

impl PendingEndpointKeyAgreement {
    /// Begin endpoint negotiation through the runtime's bounded handshake
    /// admission. The guard stays owned by the move-only pending agreement
    /// until finish or refusal, so a production caller cannot bypass the
    /// configured pending-handshake ceiling.
    pub(crate) fn begin_with_runtime(
        runtime: &ClosedRelayRuntime,
        identity: &Identity,
        mesh: MeshContextId,
        peer_id: DeviceId,
        session_id: [u8; 16],
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<(Self, RelayKeyShare), ClosedRelayRefusal> {
        let guard = runtime.try_begin_handshake()?;
        let (mut pending, share) = Self::begin(identity, mesh, peer_id, session_id, profile)?;
        pending._handshake = Some(guard);
        Ok((pending, share))
    }

    pub(crate) fn begin(
        identity: &Identity,
        mesh: MeshContextId,
        peer_id: DeviceId,
        session_id: [u8; 16],
        profile: &ClosedRelayPolicyConfig,
    ) -> Result<(Self, RelayKeyShare), ClosedRelayRefusal> {
        if !profile.validate() {
            return Err(ClosedRelayRefusal::InvalidProfile);
        }
        let local_id = DeviceId::from_canonical_str(identity.public_id())
            .map_err(ClosedRelayRefusal::Crypto)?;
        if local_id == peer_id {
            return Err(ClosedRelayRefusal::Crypto(
                "endpoint key agreement requires distinct peers".into(),
            ));
        }
        let secret = EphemeralSecret::random_from_rng(OsRng);
        let local_public = PublicKey::from(&secret).to_bytes();
        let mut share = RelayKeyShare {
            version: OPAQUE_RELAY_VERSION,
            mesh: mesh.base32(),
            session_id,
            from: local_id.base32(),
            to: peer_id.base32(),
            ephemeral_public: local_public,
            signature: String::new(),
        };
        share.signature = crate::signing::sign_with(identity.signing_key(), &share.signing_bytes());
        Ok((
            Self {
                mesh,
                local_id,
                peer_id,
                session_id,
                local_public,
                secret,
                max_packet_bytes: usize::try_from(profile.max_frame_ciphertext_bytes)
                    .map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
                replay_window: usize::try_from(profile.replay_window)
                    .map_err(|_| ClosedRelayRefusal::InvalidProfile)?,
                _handshake: None,
            },
            share,
        ))
    }

    pub(crate) fn finish(
        self,
        peer_share: &RelayKeyShare,
    ) -> Result<OpaqueRelaySession, ClosedRelayRefusal> {
        if self
            ._handshake
            .as_ref()
            .is_some_and(ClosedRelayHandshakeGuard::is_expired)
        {
            return Err(ClosedRelayRefusal::Expired);
        }
        peer_share.validate().map_err(ClosedRelayRefusal::Crypto)?;
        if peer_share.mesh != self.mesh.base32()
            || peer_share.session_id != self.session_id
            || peer_share.from != self.peer_id.base32()
            || peer_share.to != self.local_id.base32()
        {
            return Err(ClosedRelayRefusal::Crypto(
                "key-share context does not match pending endpoint".into(),
            ));
        }
        if !crate::signing::verify(
            &peer_share.from,
            &peer_share.signing_bytes(),
            &peer_share.signature,
        )
        .map_err(|error| ClosedRelayRefusal::Crypto(error.to_string()))?
        {
            return Err(ClosedRelayRefusal::Crypto(
                "peer key-share signature did not verify".into(),
            ));
        }
        let peer_public = PublicKey::from(peer_share.ephemeral_public);
        let shared = self.secret.diffie_hellman(&peer_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(ClosedRelayRefusal::Crypto(
                "peer supplied a low-order X25519 key".into(),
            ));
        }
        let mut info = Vec::new();
        info.extend_from_slice(b"myownmesh-closed-opaque-relay-session-v1:");
        push_field(&mut info, self.mesh.base32().as_bytes());
        info.extend_from_slice(&self.session_id);
        let (first_id, second_id, first_key, second_key) = if self.local_id < self.peer_id {
            (
                &self.local_id,
                &self.peer_id,
                &self.local_public,
                &peer_share.ephemeral_public,
            )
        } else {
            (
                &self.peer_id,
                &self.local_id,
                &peer_share.ephemeral_public,
                &self.local_public,
            )
        };
        let first_id_bytes = first_id.as_bytes();
        let second_id_bytes = second_id.as_bytes();
        push_field(&mut info, &first_id_bytes);
        push_field(&mut info, &second_id_bytes);
        info.extend_from_slice(first_key);
        info.extend_from_slice(second_key);
        let material = derive_material(shared.as_bytes(), &info)
            .map_err(|_| ClosedRelayRefusal::Crypto("HKDF expansion failed".into()))?;
        let first_key = &material[..KEY_BYTES];
        let second_key = &material[KEY_BYTES..KEY_BYTES * 2];
        let first_prefix = &material[KEY_BYTES * 2..KEY_BYTES * 2 + NONCE_PREFIX_BYTES];
        let second_prefix = &material[KEY_BYTES * 2 + NONCE_PREFIX_BYTES..];
        let (send_key, recv_key, send_prefix, recv_prefix) = if self.local_id < self.peer_id {
            (first_key, second_key, first_prefix, second_prefix)
        } else {
            (second_key, first_key, second_prefix, first_prefix)
        };
        let mut send_key_bytes = [0u8; KEY_BYTES];
        let mut recv_key_bytes = [0u8; KEY_BYTES];
        let mut send_prefix_bytes = [0u8; NONCE_PREFIX_BYTES];
        let mut recv_prefix_bytes = [0u8; NONCE_PREFIX_BYTES];
        send_key_bytes.copy_from_slice(send_key);
        recv_key_bytes.copy_from_slice(recv_key);
        send_prefix_bytes.copy_from_slice(send_prefix);
        recv_prefix_bytes.copy_from_slice(recv_prefix);
        if self
            ._handshake
            .as_ref()
            .is_some_and(ClosedRelayHandshakeGuard::is_expired)
        {
            return Err(ClosedRelayRefusal::Expired);
        }
        Ok(OpaqueRelaySession {
            mesh: self.mesh,
            local_id: self.local_id,
            peer_id: self.peer_id,
            session_id: self.session_id,
            send_key: send_key_bytes,
            recv_key: recv_key_bytes,
            send_prefix: send_prefix_bytes,
            recv_prefix: recv_prefix_bytes,
            next_send_sequence: 0,
            replay: ReplayWindow::new(self.replay_window),
            max_packet_bytes: self.max_packet_bytes,
        })
    }
}

/// Endpoint-only AEAD session. The relay runtime never receives this type.
pub struct OpaqueRelaySession {
    mesh: MeshContextId,
    local_id: DeviceId,
    peer_id: DeviceId,
    session_id: [u8; 16],
    send_key: [u8; KEY_BYTES],
    recv_key: [u8; KEY_BYTES],
    send_prefix: [u8; NONCE_PREFIX_BYTES],
    recv_prefix: [u8; NONCE_PREFIX_BYTES],
    next_send_sequence: u64,
    replay: ReplayWindow,
    max_packet_bytes: usize,
}

impl OpaqueRelaySession {
    /// Check an established endpoint session against one complete typed relay
    /// route without consuming sequence or replay state.  The endpoint pair,
    /// context, and session coordinate come from this unforgeable session;
    /// the relay identity is accepted only as part of the independently
    /// validated complete route and can never select a peer or address here.
    /// Allocation generations remain the relay registry's exact fence, so an
    /// established route must carry a nonzero generation before this seam is
    /// usable for allocation admission.
    #[cfg(test)]
    pub(crate) fn matches_route(&self, route: &ClosedRelayRoute) -> bool {
        route.validate().is_ok()
            && route.allocation_epoch != 0
            && self.mesh == route.context_id
            && self.session_id == route.session_id
            && ((self.local_id == route.requester && self.peer_id == route.target)
                || (self.local_id == route.target && self.peer_id == route.requester))
    }

    pub(crate) fn seal(
        &mut self,
        plaintext: &[u8],
    ) -> Result<OpaqueRelayPacket, ClosedRelayRefusal> {
        if plaintext.len() > self.max_packet_bytes {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "plaintext exceeds configured bound".into(),
            ));
        }
        let sequence = self.next_send_sequence;
        self.next_send_sequence = sequence
            .checked_add(1)
            .ok_or_else(|| ClosedRelayRefusal::Crypto("send sequence exhausted".into()))?;
        let nonce = nonce_for(self.send_prefix, sequence);
        let mesh = self.mesh.base32();
        let local_id = self.local_id.base32();
        let peer_id = self.peer_id.base32();
        let aad = aad_for(&mesh, &self.session_id, &local_id, &peer_id, sequence);
        let ciphertext = encrypt(&self.send_key, &nonce, &aad, plaintext)
            .map_err(|_| ClosedRelayRefusal::Crypto("AEAD seal failed".into()))?;
        let packet = OpaqueRelayPacket {
            version: OPAQUE_RELAY_VERSION,
            mesh,
            session_id: self.session_id,
            from: local_id,
            to: peer_id,
            sequence,
            nonce,
            ciphertext,
        };
        packet
            .validate(
                self.max_packet_bytes
                    .checked_add(AEAD_TAG_BYTES)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        Ok(packet)
    }

    pub(crate) fn open(
        &mut self,
        packet: &OpaqueRelayPacket,
    ) -> Result<Vec<u8>, ClosedRelayRefusal> {
        packet
            .validate(
                self.max_packet_bytes
                    .checked_add(AEAD_TAG_BYTES)
                    .ok_or(ClosedRelayRefusal::InvalidProfile)?,
            )
            .map_err(ClosedRelayRefusal::InvalidPacket)?;
        if packet.mesh != self.mesh.base32()
            || packet.session_id != self.session_id
            || packet.from != self.peer_id.base32()
            || packet.to != self.local_id.base32()
            || packet.nonce != nonce_for(self.recv_prefix, packet.sequence)
        {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet context or nonce does not match session".into(),
            ));
        }
        if !self.replay.can_accept(packet.sequence) {
            return Err(ClosedRelayRefusal::InvalidPacket(
                "packet replayed or outside replay window".into(),
            ));
        }
        let aad = aad_for(
            &self.mesh.base32(),
            &self.session_id,
            &packet.from,
            &packet.to,
            packet.sequence,
        );
        let plaintext = decrypt(&self.recv_key, &packet.nonce, &aad, &packet.ciphertext)
            .map_err(|_| ClosedRelayRefusal::Crypto("AEAD open failed".into()))?;
        self.replay.record(packet.sequence);
        Ok(plaintext)
    }
}

impl Drop for OpaqueRelaySession {
    fn drop(&mut self) {
        self.send_key.zeroize();
        self.recv_key.zeroize();
        self.send_prefix.zeroize();
        self.recv_prefix.zeroize();
    }
}

fn nonce_for(prefix: [u8; NONCE_PREFIX_BYTES], sequence: u64) -> [u8; OPAQUE_RELAY_NONCE_BYTES] {
    let mut nonce = [0u8; OPAQUE_RELAY_NONCE_BYTES];
    nonce[..NONCE_PREFIX_BYTES].copy_from_slice(&prefix);
    nonce[NONCE_PREFIX_BYTES..].copy_from_slice(&sequence.to_be_bytes());
    nonce
}

fn aad_for(mesh: &str, session_id: &[u8; 16], from: &str, to: &str, sequence: u64) -> Vec<u8> {
    let mut aad = Vec::new();
    aad.extend_from_slice(b"myownmesh-closed-opaque-relay-packet-v1:");
    push_field(&mut aad, mesh.as_bytes());
    aad.extend_from_slice(session_id);
    push_field(&mut aad, from.as_bytes());
    push_field(&mut aad, to.as_bytes());
    aad.extend_from_slice(&sequence.to_be_bytes());
    aad
}

fn push_field(output: &mut Vec<u8>, field: &[u8]) {
    output.extend_from_slice(&u64::try_from(field.len()).unwrap_or(u64::MAX).to_be_bytes());
    output.extend_from_slice(field);
}

#[cfg(test)]
mod behavior_tests;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource::ResourceClass;

    #[test]
    fn endpoint_aead_round_trip_and_replay_fence() {
        let profile = ClosedRelayPolicyConfig::default();
        let alice = Identity::ephemeral();
        let bob = Identity::ephemeral();
        let mesh = MeshContextId::from_bytes([3; 32]);
        let alice_id = DeviceId::from_canonical_str(alice.public_id()).expect("alice id");
        let bob_id = DeviceId::from_canonical_str(bob.public_id()).expect("bob id");
        let (alice_pending, alice_share) =
            PendingEndpointKeyAgreement::begin(&alice, mesh, bob_id.clone(), [7; 16], &profile)
                .expect("alice key share");
        let (bob_pending, bob_share) =
            PendingEndpointKeyAgreement::begin(&bob, mesh, alice_id, [7; 16], &profile)
                .expect("bob key share");
        let mut alice_session = alice_pending.finish(&bob_share).expect("alice session");
        let mut bob_session = bob_pending.finish(&alice_share).expect("bob session");
        let packet = alice_session.seal(b"opaque").expect("seal");
        assert_eq!(bob_session.open(&packet).expect("open"), b"opaque");
        assert!(bob_session.open(&packet).is_err(), "replay must be refused");
    }

    #[test]
    fn relay_profile_refuses_oversized_packets() {
        let oversized = ClosedRelayPolicyConfig {
            max_frame_ciphertext_bytes: crate::config::MAX_CLOSED_RELAY_PACKET_BYTES + 1,
            pending_handshake_timeout_ms: ClosedRelayPolicyConfig::default()
                .pending_handshake_timeout_ms,
            ..ClosedRelayPolicyConfig::default()
        };
        assert!(!oversized.validate());
    }

    #[test]
    fn relay_checked_ciphertext_ceiling_adds_aead_tag() {
        let plaintext = crate::protocol::relay::CLOSED_RELAY_MAX_PLAINTEXT_BYTES;
        assert_eq!(
            checked_ciphertext_ceiling(plaintext)
                .expect("safe plaintext boundary adds the AEAD tag"),
            usize::try_from(plaintext + crate::protocol::relay::CLOSED_RELAY_AEAD_TAG_BYTES)
                .expect("safe boundary fits usize")
        );
    }

    #[test]
    fn endpoint_session_route_validator_is_read_only_and_generation_fenced() {
        let profile = ClosedRelayPolicyConfig::default();
        let requester = Identity::ephemeral();
        let target = Identity::ephemeral();
        let context = MeshContextId::from_bytes([12; 32]);
        let requester_id = DeviceId::from_canonical_str(requester.public_id()).expect("requester");
        let target_id = DeviceId::from_canonical_str(target.public_id()).expect("target");
        let relay_id =
            DeviceId::from_canonical_str(Identity::ephemeral().public_id()).expect("relay");
        let session_id = [13; 16];
        let (requester_pending, requester_share) = PendingEndpointKeyAgreement::begin(
            &requester,
            context,
            target_id.clone(),
            session_id,
            &profile,
        )
        .expect("requester share");
        let (target_pending, target_share) = PendingEndpointKeyAgreement::begin(
            &target,
            context,
            requester_id.clone(),
            session_id,
            &profile,
        )
        .expect("target share");
        let requester_session = requester_pending
            .finish(&target_share)
            .expect("requester session");
        let _target_session = target_pending
            .finish(&requester_share)
            .expect("target session");
        let route = ClosedRelayRoute::with_epoch(
            context,
            requester_id.clone(),
            relay_id.clone(),
            target_id.clone(),
            session_id,
            1,
        );
        assert!(requester_session.matches_route(&route));
        assert!(
            !requester_session.matches_route(&ClosedRelayRoute::with_epoch(
                context,
                requester_id.clone(),
                relay_id.clone(),
                target_id.clone(),
                session_id,
                0,
            ))
        );
        assert!(
            !requester_session.matches_route(&ClosedRelayRoute::with_epoch(
                MeshContextId::from_bytes([14; 32]),
                requester_id,
                relay_id,
                target_id,
                session_id,
                1,
            ))
        );
    }

    #[test]
    fn relay_allocation_claim_covers_payload_and_runtime_custody() {
        let profile = ClosedRelayPolicyConfig {
            enabled: true,
            pending_handshake_timeout_ms: 30_000,
            ..ClosedRelayPolicyConfig::default()
        };
        let claim = RelayAllocationPermit::allocation_claim(&profile)
            .expect("valid relay profile has a finite claim");
        assert_eq!(claim.amount(ResourceClass::RelayOrProviderAllocation), 1);
        assert_eq!(
            claim.amount(ResourceClass::QueuedBytes),
            profile
                .queue_bytes_per_direction
                .checked_mul(RELAY_DIRECTION_COUNT as u64)
                .expect("configured queue bytes fit")
        );
        assert!(
            claim.amount(ResourceClass::AccountedMemoryBytes)
                >= u64::try_from(
                    std::mem::size_of::<RelayAllocationPermit>()
                        + std::mem::size_of::<ClosedRelayHandle>(),
                )
                .expect("test platform sizes fit")
        );
        assert!(claim.amount(ResourceClass::OpaqueDependencyResidual) > 0);
    }

    #[test]
    fn terminal_tombstones_update_latest_epoch_with_a_bounded_table() {
        let mut state = RelayAdmissionState {
            active_allocations: (0..2).map(|_| None).collect(),
            terminal_tombstones: (0..2).map(|_| None).collect(),
            terminal_tombstone_capacity: 2,
            terminal_tombstones_len: 0,
            pending_handshakes: 0,
            next_allocation_id: 0,
            next_allocation_epoch: 0,
        };
        state.record_terminal_tombstone([1; 16], 1);
        state.record_terminal_tombstone([1; 16], 3);
        assert_eq!(state.terminal_tombstone([1; 16]), Some(3));
        assert_eq!(state.terminal_tombstones_len, 1);
        state.record_terminal_tombstone([2; 16], 1);
        state.record_terminal_tombstone([3; 16], 1);
        assert_eq!(state.terminal_tombstones_len, 2);
        assert_eq!(state.terminal_tombstone([3; 16]), Some(1));
    }
}
