//! Durable proof-delivery records.
//!
//! A proof record is an exact semantic delivery obligation.  Its identity is
//! derived only from the authenticated mesh context, target device, and the
//! canonical sorted fact set; owner and binding metadata describe custody but
//! cannot create a second delivery identity.  The records are persisted by
//! [`DurableSemanticStore`] in the same atomic snapshot as the semantic graph.

use data_encoding::BASE32_NOPAD;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(test)]
use super::store::DurableSemanticStore;
use super::store::{DurableSemanticOwner, DurableStoreError};
use super::{DeviceId, FactId, MeshContextId};
use crate::config::SemanticPolicyConfig;
use std::sync::Arc;

const PROOF_DELIVERY_DOMAIN: &[u8] = b"myownmesh-semantic-v4-proof-delivery-v1";
const PROOF_RECORD_VERSION: u16 = 1;

/// Stable identity for one exact proof delivery obligation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProofDeliveryId([u8; 32]);

impl ProofDeliveryId {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }

    /// Derive the delivery identity from exactly the context, target, and
    /// sorted/deduplicated fact identities.
    pub fn digest(context_id: MeshContextId, target: &DeviceId, fact_ids: &[FactId]) -> Self {
        let mut canonical = fact_ids.to_vec();
        canonical.sort();
        canonical.dedup();
        let mut hasher = Sha256::new();
        hasher.update(PROOF_DELIVERY_DOMAIN);
        hasher.update(context_id.as_bytes());
        hasher.update(target.as_bytes());
        hasher.update((canonical.len() as u64).to_be_bytes());
        for fact_id in canonical {
            hasher.update(fact_id.as_bytes());
        }
        let digest = hasher.finalize();
        let mut bytes = [0; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }
}

impl std::fmt::Debug for ProofDeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ProofDeliveryId")
            .field(&self.base32())
            .finish()
    }
}

impl std::fmt::Display for ProofDeliveryId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for ProofDeliveryId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for ProofDeliveryId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded != encoded.to_lowercase() {
            return Err(D::Error::custom(
                "ProofDeliveryId must use lowercase base32",
            ));
        }
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("ProofDeliveryId must decode to 32 bytes"));
        }
        let mut value = [0; 32];
        value.copy_from_slice(&bytes);
        let id = Self(value);
        if encoded != id.base32() {
            return Err(D::Error::custom("ProofDeliveryId is not canonical base32"));
        }
        Ok(id)
    }
}

/// Terminal state retained for exact idempotent settlement and restart.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProofRecordState {
    Pending,
    Settled,
    Superseded,
}

/// One pending or settled proof delivery, including its exact custody
/// binding.  The fields are public for transport adapters, but every adapter
/// must pass [`ProofRecord::validate`] before using a record.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofRecord {
    pub version: u16,
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
    pub fact_ids: Vec<FactId>,
    pub owner: String,
    pub binding: String,
    pub state: ProofRecordState,
}

impl ProofRecord {
    /// Create a canonical pending record.  Fact identities are sorted and
    /// deduplicated before the stable delivery identity is derived.
    pub fn pending(
        context_id: MeshContextId,
        target: DeviceId,
        mut fact_ids: Vec<FactId>,
        owner: impl Into<String>,
        binding: impl Into<String>,
    ) -> Result<Self, ProofOutboxError> {
        fact_ids.sort();
        fact_ids.dedup();
        let delivery_id = ProofDeliveryId::digest(context_id, &target, &fact_ids);
        let record = Self {
            version: PROOF_RECORD_VERSION,
            context_id,
            target,
            delivery_id,
            fact_ids,
            owner: owner.into(),
            binding: binding.into(),
            state: ProofRecordState::Pending,
        };
        record.validate()?;
        Ok(record)
    }

    pub fn validate(&self) -> Result<(), ProofOutboxError> {
        if self.version != PROOF_RECORD_VERSION {
            return Err(ProofOutboxError::InvalidRecord(format!(
                "unsupported proof record version {}",
                self.version
            )));
        }
        if self.fact_ids.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof record has no canonical facts".into(),
            ));
        }
        if self.fact_ids.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ProofOutboxError::InvalidRecord(
                "proof fact identities are not sorted and unique".into(),
            ));
        }
        if self.owner.is_empty() || self.binding.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof owner and binding are required".into(),
            ));
        }
        let expected = ProofDeliveryId::digest(self.context_id, &self.target, &self.fact_ids);
        if self.delivery_id != expected {
            return Err(ProofOutboxError::InvalidRecord(
                "proof delivery identity does not match canonical facts".into(),
            ));
        }
        Ok(())
    }

    pub fn is_pending(&self) -> bool {
        self.state == ProofRecordState::Pending
    }
}

/// Durable access to proof records for one local semantic store.
#[derive(Debug, Clone)]
pub struct DurableProofOutbox {
    backend: ProofOutboxBackend,
    #[cfg(test)]
    policy: SemanticPolicyConfig,
}

#[derive(Debug, Clone)]
// Only tests carry a direct store inline. Preserve that fixture ownership and
// the production shared-owner representation without introducing a new Box.
#[cfg_attr(test, allow(clippy::large_enum_variant))]
enum ProofOutboxBackend {
    #[cfg(test)]
    Store(DurableSemanticStore),
    Owner(Arc<DurableSemanticOwner>),
}

impl DurableProofOutbox {
    /// Construct a direct-store fixture with the already validated network
    /// semantic lifetime policy. This constructor exists only for this
    /// module's unit tests: a direct store has no provider-backed
    /// `StorageBytes` custody and therefore must never be a production
    /// mutation path. Production callers attach through
    /// [`Self::from_owner_with_policy`].
    #[cfg(test)]
    pub fn with_policy(
        instance_root: impl Into<std::path::PathBuf>,
        local_slot: impl AsRef<str>,
        policy: SemanticPolicyConfig,
    ) -> Result<Self, ProofOutboxError> {
        let policy = checked_policy(policy)?;
        Ok(Self {
            backend: ProofOutboxBackend::Store(DurableSemanticStore::with_policy(
                instance_root,
                local_slot,
                policy,
            )),
            #[cfg(test)]
            policy,
        })
    }

    /// Attach an outbox to an existing semantic owner with the network's
    /// checked policy.
    pub(crate) fn from_owner_with_policy(
        owner: Arc<DurableSemanticOwner>,
        policy: SemanticPolicyConfig,
    ) -> Result<Self, ProofOutboxError> {
        #[cfg(test)]
        let policy = checked_policy(policy)?;
        #[cfg(not(test))]
        checked_policy(policy)?;
        Ok(Self {
            backend: ProofOutboxBackend::Owner(owner),
            #[cfg(test)]
            policy,
        })
    }

    /// Enumerate only still-pending records for the exact authenticated
    /// context.  Settled records remain persisted so replay is idempotent.
    pub fn pending(&self, context_id: MeshContextId) -> Result<Vec<ProofRecord>, ProofOutboxError> {
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(store) => store
                .pending_proof_records(context_id)
                .map_err(ProofOutboxError::from),
            ProofOutboxBackend::Owner(owner) => owner
                .pending_proof_records(context_id)
                .map_err(ProofOutboxError::from),
        }
    }

    /// Persist one exact pending/settled record.  Re-enqueuing the identical
    /// record is a no-op; a conflicting record with the same stable identity
    /// is refused without changing the existing custody.
    pub fn enqueue(&self, record: ProofRecord) -> Result<ProofRecord, ProofOutboxError> {
        record.validate()?;
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(_) => {
                let mut result = record.clone();
                let context_id = record.context_id;
                self.mutate_proof_records(context_id, |records| {
                    if let Some(existing) = records
                        .iter()
                        .find(|existing| existing.delivery_id == record.delivery_id)
                    {
                        if !same_delivery_payload(existing, &record) {
                            return Err(DurableStoreError::ProofConflict);
                        }
                        result = existing.clone();
                        return Ok(());
                    }
                    records.push(record.clone());
                    records.sort_by_key(|record| record.delivery_id);
                    enforce_proof_limits(records, &self.policy)?;
                    Ok(())
                })?;
                Ok(result)
            }
            ProofOutboxBackend::Owner(owner) => {
                owner.enqueue_proof(record).map_err(ProofOutboxError::from)
            }
        }
    }

    /// Atomically rebind a pending delivery after an authenticated live
    /// binding transition. The expected owner and binding are a CAS witness;
    /// only those two fields may change, and the stable delivery identity and
    /// fact set remain untouched.
    pub fn rebind(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_owner: &str,
        expected_binding: &str,
        new_owner: impl Into<String>,
        new_binding: impl Into<String>,
    ) -> Result<ProofRecord, ProofOutboxError> {
        let new_owner = new_owner.into();
        let new_binding = new_binding.into();
        if new_owner.is_empty() || new_binding.is_empty() {
            return Err(ProofOutboxError::InvalidRecord(
                "proof owner and binding are required".into(),
            ));
        }
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(_) => {
                match self
                    .proof_records(context_id)?
                    .into_iter()
                    .find(|record| record.delivery_id == delivery_id)
                    .ok_or(ProofOutboxError::NotFound)?
                    .state
                {
                    ProofRecordState::Pending => {}
                    ProofRecordState::Settled => return Err(ProofOutboxError::AlreadySettled),
                    ProofRecordState::Superseded => {
                        return Err(ProofOutboxError::AlreadySuperseded)
                    }
                }
                let mut rebound = None;
                self.mutate_proof_records(context_id, |records| {
                    let record = records
                        .iter_mut()
                        .find(|record| record.delivery_id == delivery_id)
                        .ok_or(DurableStoreError::ProofNotFound)?;
                    if record.state != ProofRecordState::Pending {
                        return Err(DurableStoreError::ProofSettled);
                    }
                    if record.owner != expected_owner || record.binding != expected_binding {
                        return Err(DurableStoreError::StaleProofBinding);
                    }
                    record.owner = new_owner.clone();
                    record.binding = new_binding.clone();
                    rebound = Some(record.clone());
                    enforce_proof_limits(records, &self.policy)?;
                    Ok(())
                })?;
                rebound.ok_or_else(|| {
                    ProofOutboxError::InvalidRecord("rebind produced no record".into())
                })
            }
            ProofOutboxBackend::Owner(owner) => owner
                .rebind_proof(
                    context_id,
                    delivery_id,
                    expected_owner,
                    expected_binding,
                    new_owner,
                    new_binding,
                )
                .map_err(ProofOutboxError::from),
        }
    }

    /// Settle one exact delivery identity.  Repeated settlement is a no-op;
    /// a different context cannot select or settle the record.
    pub fn settle(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
    ) -> Result<bool, ProofOutboxError> {
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(_) => {
                let mut settled = false;
                self.mutate_proof_records(context_id, |records| {
                    if let Some(record) = records
                        .iter_mut()
                        .find(|record| record.delivery_id == delivery_id)
                    {
                        match record.state {
                            ProofRecordState::Pending => {
                                record.state = ProofRecordState::Settled;
                                settled = true;
                            }
                            ProofRecordState::Settled | ProofRecordState::Superseded => {}
                        }
                    }
                    enforce_proof_limits(records, &self.policy)?;
                    Ok(())
                })?;
                Ok(settled)
            }
            ProofOutboxBackend::Owner(owner) => owner
                .settle_proof(context_id, delivery_id)
                .map_err(ProofOutboxError::from),
        }
    }

    /// Retire one obsolete Pending delivery without representing an
    /// acknowledgement. The exact target is a CAS witness; an optional
    /// replacement identity documents the successor selected by the caller
    /// but never makes this record replayable or settles the successor.
    pub fn supersede(
        &self,
        context_id: MeshContextId,
        delivery_id: ProofDeliveryId,
        expected_target: &DeviceId,
        replacement_delivery_id: Option<ProofDeliveryId>,
    ) -> Result<bool, ProofOutboxError> {
        if replacement_delivery_id == Some(delivery_id) {
            return Err(ProofOutboxError::InvalidRecord(
                "proof replacement must have a distinct delivery identity".into(),
            ));
        }
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(_) => {
                let mut superseded = false;
                self.mutate_proof_records(context_id, |records| {
                    let record = records
                        .iter_mut()
                        .find(|record| record.delivery_id == delivery_id)
                        .ok_or(DurableStoreError::ProofNotFound)?;
                    if &record.target != expected_target {
                        return Err(DurableStoreError::StaleProofTarget);
                    }
                    match record.state {
                        ProofRecordState::Pending => {
                            record.state = ProofRecordState::Superseded;
                            superseded = true;
                        }
                        ProofRecordState::Settled => return Err(DurableStoreError::ProofSettled),
                        ProofRecordState::Superseded => {}
                    }
                    enforce_proof_limits(records, &self.policy)?;
                    Ok(())
                })?;
                Ok(superseded)
            }
            ProofOutboxBackend::Owner(owner) => owner
                .supersede_proof(
                    context_id,
                    delivery_id,
                    expected_target,
                    replacement_delivery_id,
                )
                .map_err(ProofOutboxError::from),
        }
    }

    #[cfg(test)]
    fn proof_records(
        &self,
        context_id: MeshContextId,
    ) -> Result<Vec<ProofRecord>, DurableStoreError> {
        match &self.backend {
            #[cfg(test)]
            ProofOutboxBackend::Store(store) => {
                let records = store.proof_records(context_id)?;
                enforce_proof_limits(&records, &self.policy)?;
                Ok(records)
            }
            ProofOutboxBackend::Owner(owner) => owner.proof_records(context_id),
        }
    }

    #[cfg(test)]
    fn mutate_proof_records<F>(
        &self,
        context_id: MeshContextId,
        mutation: F,
    ) -> Result<Vec<ProofRecord>, DurableStoreError>
    where
        F: FnOnce(&mut Vec<ProofRecord>) -> Result<(), DurableStoreError>,
    {
        match &self.backend {
            ProofOutboxBackend::Store(store) => store.mutate_proof_records(context_id, mutation),
            ProofOutboxBackend::Owner(_) => Err(DurableStoreError::InvalidProof(
                "test-only direct-store mutation helper cannot use an owner backend".into(),
            )),
        }
    }
}

fn checked_policy(policy: SemanticPolicyConfig) -> Result<SemanticPolicyConfig, ProofOutboxError> {
    policy
        .checked()
        .map_err(|error| ProofOutboxError::Policy(error.to_string()))
}

#[cfg(test)]
fn canonical_record_bytes(record: &ProofRecord) -> Result<u64, ProofOutboxError> {
    let bytes = serde_json::to_vec(record)
        .map_err(|error| ProofOutboxError::Serialization(error.to_string()))?;
    u64::try_from(bytes.len()).map_err(|_| {
        ProofOutboxError::LimitExceeded("proof record encoded bytes exceed u64 accounting")
    })
}

#[cfg(test)]
fn enforce_proof_limits(
    records: &[ProofRecord],
    policy: &SemanticPolicyConfig,
) -> Result<(), DurableStoreError> {
    let mut total_count = 0u64;
    let mut pending_count = 0u64;
    let mut total_bytes = 0u64;
    let mut pending_bytes = 0u64;
    for record in records {
        let encoded_bytes = serde_json::to_vec(record).map_err(DurableStoreError::Serialization)?;
        let encoded_bytes = u64::try_from(encoded_bytes.len()).map_err(|_| {
            DurableStoreError::LimitExceeded("proof record encoded bytes exceed u64 accounting")
        })?;
        total_count = total_count
            .checked_add(1)
            .ok_or(DurableStoreError::LimitExceeded(
                "proof record count overflow",
            ))?;
        total_bytes =
            total_bytes
                .checked_add(encoded_bytes)
                .ok_or(DurableStoreError::LimitExceeded(
                    "proof record bytes overflow",
                ))?;
        if record.is_pending() {
            pending_count =
                pending_count
                    .checked_add(1)
                    .ok_or(DurableStoreError::LimitExceeded(
                        "pending proof count overflow",
                    ))?;
            pending_bytes = pending_bytes.checked_add(encoded_bytes).ok_or(
                DurableStoreError::LimitExceeded("pending proof bytes overflow"),
            )?;
        }
    }
    if total_count > policy.max_proof_records {
        return Err(DurableStoreError::LimitExceeded("proof record count"));
    }
    if total_bytes > policy.max_proof_bytes {
        return Err(DurableStoreError::LimitExceeded("proof record bytes"));
    }
    if pending_count > policy.max_pending_proofs {
        return Err(DurableStoreError::LimitExceeded("pending proof count"));
    }
    if pending_bytes > policy.max_pending_proof_bytes {
        return Err(DurableStoreError::LimitExceeded("pending proof bytes"));
    }
    if total_bytes > policy.max_database_bytes {
        return Err(DurableStoreError::LimitExceeded(
            "proof record retained bytes",
        ));
    }
    Ok(())
}

#[cfg(test)]
fn same_delivery_payload(left: &ProofRecord, right: &ProofRecord) -> bool {
    left.version == right.version
        && left.context_id == right.context_id
        && left.target == right.target
        && left.delivery_id == right.delivery_id
        && left.fact_ids == right.fact_ids
        && left.owner == right.owner
        && left.binding == right.binding
}

#[derive(Debug, Error)]
pub enum ProofOutboxError {
    #[error("invalid proof record: {0}")]
    InvalidRecord(String),
    #[error("proof outbox context mismatch: expected {expected}, found {actual}")]
    ContextMismatch {
        expected: MeshContextId,
        actual: MeshContextId,
    },
    #[error("proof delivery identity is already bound to different metadata")]
    Conflict,
    #[error("proof delivery identity was not found")]
    NotFound,
    #[error("proof delivery is already settled")]
    AlreadySettled,
    #[error("proof delivery is already superseded")]
    AlreadySuperseded,
    #[error("proof delivery binding is stale")]
    StaleBinding,
    #[error("proof delivery target is stale")]
    StaleTarget,
    #[error("proof outbox policy rejected: {0}")]
    Policy(String),
    #[error("proof outbox limit exceeded: {0}")]
    LimitExceeded(&'static str),
    #[error("proof record serialization failed: {0}")]
    Serialization(String),
    #[error("durable proof outbox storage failed: {0}")]
    Storage(String),
}

impl From<DurableStoreError> for ProofOutboxError {
    fn from(error: DurableStoreError) -> Self {
        match error {
            DurableStoreError::ContextMismatch { expected, actual } => {
                Self::ContextMismatch { expected, actual }
            }
            DurableStoreError::ProofConflict => Self::Conflict,
            DurableStoreError::ProofNotFound => Self::NotFound,
            DurableStoreError::ProofSettled => Self::AlreadySettled,
            DurableStoreError::StaleProofBinding => Self::StaleBinding,
            DurableStoreError::StaleProofTarget => Self::StaleTarget,
            DurableStoreError::LimitExceeded(reason) => Self::LimitExceeded(reason),
            DurableStoreError::Serialization(error) => Self::Serialization(error.to_string()),
            error => Self::Storage(error.to_string()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{
        FactBody, FactContent, FactDomain, FactGraph, Role, SignedFact, VerifiedBootstrap,
    };
    use ed25519_dalek::SigningKey;
    use std::sync::atomic::{AtomicUsize, Ordering};

    static NEXT_ROOT: AtomicUsize = AtomicUsize::new(0);

    fn root() -> std::path::PathBuf {
        let id = NEXT_ROOT.fetch_add(1, Ordering::Relaxed);
        let root = std::env::temp_dir().join(format!(
            "myownmesh-proof-outbox-{}-{id}",
            std::process::id()
        ));
        std::fs::create_dir_all(&root).expect("test root");
        root
    }

    fn checked_default_policy() -> SemanticPolicyConfig {
        SemanticPolicyConfig::default()
            .checked()
            .expect("test semantic policy is valid")
    }

    fn shared_owner_components() -> (
        std::path::PathBuf,
        Arc<DurableSemanticOwner>,
        MeshContextId,
        ProofRecord,
        u64,
    ) {
        let root = root();
        let key = SigningKey::from_bytes(&[9; 32]);
        let bootstrap =
            VerifiedBootstrap::create_closed("proof-outbox-race", vec![key.clone()], [9; 32])
                .expect("bootstrap");
        let device =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("device");
        let fact = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: device.clone(),
                    role: Role::Member,
                },
                device.clone(),
                Vec::new(),
            ),
            &key,
        )
        .expect("fact");
        let fact_encoded_bytes =
            u64::try_from(serde_json::to_vec(&fact).expect("fact JSON encoding").len())
                .expect("fact JSON length fits");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("fact admission");
        let store = DurableSemanticStore::new(&root, "slot");
        store.commit(&graph, Vec::new()).expect("snapshot");
        let owner = Arc::new(store.open_writable().expect("shared owner"));
        let record = ProofRecord::pending(
            bootstrap.context_id(),
            device,
            vec![fact.id],
            "race-owner",
            "race-binding",
        )
        .expect("record");
        (
            root,
            owner,
            bootstrap.context_id(),
            record,
            fact_encoded_bytes,
        )
    }

    fn owner_with_policy(
        root: &std::path::Path,
        policy: SemanticPolicyConfig,
    ) -> Arc<DurableSemanticOwner> {
        Arc::new(
            DurableSemanticStore::with_policy(root, "slot", policy)
                .open_writable()
                .expect("shared owner with requested policy"),
        )
    }

    fn shared_owner_fixture() -> (
        std::path::PathBuf,
        Arc<DurableProofOutbox>,
        MeshContextId,
        ProofRecord,
    ) {
        let (root, owner, context, record, _) = shared_owner_components();
        let outbox = Arc::new(
            DurableProofOutbox::from_owner_with_policy(owner, checked_default_policy())
                .expect("checked owner policy"),
        );
        outbox.enqueue(record.clone()).expect("enqueue");
        (root, outbox, context, record)
    }

    fn second_target_record(context: MeshContextId, fact_ids: &[FactId]) -> ProofRecord {
        let key = SigningKey::from_bytes(&[10; 32]);
        let target =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("target");
        ProofRecord::pending(
            context,
            target,
            fact_ids.to_vec(),
            "second-owner",
            "second-binding",
        )
        .expect("second record")
    }

    fn policy_for_pending_limits(
        max_fact_encoded_bytes: u64,
        max_pending_proofs: u64,
        max_pending_proof_bytes: u64,
    ) -> SemanticPolicyConfig {
        SemanticPolicyConfig {
            max_fact_encoded_bytes,
            max_pending_proofs,
            max_pending_proof_bytes,
            max_ready_batch: max_pending_proofs,
            ..SemanticPolicyConfig::default()
        }
    }

    fn policy_for_total_limits(
        max_fact_encoded_bytes: u64,
        max_proof_records: u64,
        max_proof_bytes: u64,
    ) -> SemanticPolicyConfig {
        SemanticPolicyConfig {
            max_fact_encoded_bytes,
            max_pending_proofs: 1,
            max_pending_proof_bytes: max_proof_bytes,
            max_ready_batch: 1,
            max_proof_records,
            max_proof_bytes,
            ..SemanticPolicyConfig::default()
        }
    }

    #[test]
    fn pending_limits_measure_exact_records_and_refuse_before_mutation() {
        let (root, owner, context, first, fact_encoded_bytes) = shared_owner_components();
        let second = second_target_record(context, &first.fact_ids);
        let first_bytes = canonical_record_bytes(&first).expect("first record bytes");
        let second_bytes = canonical_record_bytes(&second).expect("second record bytes");
        let exact_bytes = first_bytes
            .checked_add(second_bytes)
            .expect("test record bytes fit");
        let policy = policy_for_pending_limits(fact_encoded_bytes, 2, exact_bytes);
        drop(owner);
        let owner = owner_with_policy(&root, policy);
        let outbox = DurableProofOutbox::from_owner_with_policy(owner, policy)
            .expect("exact pending policy");

        assert_eq!(outbox.enqueue(first.clone()).expect("first enqueue"), first);
        assert_eq!(
            outbox.enqueue(first.clone()).expect("identical replay"),
            first
        );
        assert_eq!(
            outbox
                .pending(context)
                .expect("pending after identical replay")
                .len(),
            1,
            "byte-identical replay must not grow the outbox"
        );
        assert_eq!(
            outbox.enqueue(second.clone()).expect("exact byte grant"),
            second
        );
        let pending = outbox.pending(context).expect("exact pending set");
        assert_eq!(pending.len(), 2);
        assert_eq!(
            pending
                .iter()
                .map(|record| canonical_record_bytes(record).expect("record bytes"))
                .sum::<u64>(),
            exact_bytes,
            "the accepted set consumes the exact measured grant"
        );
        drop(outbox);
        let _ = std::fs::remove_dir_all(root);

        let (short_root, short_owner, short_context, short_first, short_fact_encoded_bytes) =
            shared_owner_components();
        let short_second = second_target_record(short_context, &short_first.fact_ids);
        let short_first_bytes = canonical_record_bytes(&short_first).expect("first bytes");
        let short_second_bytes = canonical_record_bytes(&short_second).expect("second bytes");
        let short_policy = policy_for_pending_limits(
            short_fact_encoded_bytes,
            2,
            short_first_bytes
                .checked_add(short_second_bytes)
                .expect("short test bytes fit")
                - 1,
        );
        drop(short_owner);
        let short_owner = owner_with_policy(&short_root, short_policy);
        let short_outbox = DurableProofOutbox::from_owner_with_policy(short_owner, short_policy)
            .expect("one-unit-short policy");
        short_outbox
            .enqueue(short_first.clone())
            .expect("first short-grant enqueue");
        assert!(matches!(
            short_outbox.enqueue(short_second),
            Err(ProofOutboxError::LimitExceeded("pending proof bytes"))
        ));
        assert_eq!(
            short_outbox
                .pending(short_context)
                .expect("pending after refused enqueue"),
            vec![short_first],
            "one-unit-short refusal must leave the durable set unchanged"
        );
        drop(short_outbox);
        let _ = std::fs::remove_dir_all(short_root);

        let (count_root, count_owner, count_context, count_first, count_fact_encoded_bytes) =
            shared_owner_components();
        let count_second = second_target_record(count_context, &count_first.fact_ids);
        let count_policy = policy_for_pending_limits(count_fact_encoded_bytes, 1, 65_535);
        drop(count_owner);
        let count_owner = owner_with_policy(&count_root, count_policy);
        let count_outbox = DurableProofOutbox::from_owner_with_policy(count_owner, count_policy)
            .expect("count-limited policy");
        count_outbox
            .enqueue(count_first.clone())
            .expect("count-limited first enqueue");
        assert!(matches!(
            count_outbox.enqueue(count_second),
            Err(ProofOutboxError::LimitExceeded("pending proof count"))
        ));
        assert_eq!(
            count_outbox
                .pending(count_context)
                .expect("pending after count refusal"),
            vec![count_first]
        );
        drop(count_outbox);
        let _ = std::fs::remove_dir_all(count_root);

        let (
            history_root,
            history_owner,
            history_context,
            history_first,
            history_fact_encoded_bytes,
        ) = shared_owner_components();
        let history_second = second_target_record(history_context, &history_first.fact_ids);
        let history_policy = policy_for_total_limits(history_fact_encoded_bytes, 1, 65_535);
        drop(history_owner);
        let history_owner = owner_with_policy(&history_root, history_policy);
        let history_outbox =
            DurableProofOutbox::from_owner_with_policy(history_owner, history_policy)
                .expect("total-count-limited policy");
        history_outbox
            .enqueue(history_first.clone())
            .expect("total-count first enqueue");
        let history_result = history_outbox.enqueue(history_second);
        assert!(
            matches!(
                &history_result,
                &Err(ProofOutboxError::LimitExceeded("proof count"))
            ),
            "total-count refusal result: {history_result:?}"
        );
        assert_eq!(
            history_outbox
                .pending(history_context)
                .expect("pending after total-count refusal"),
            vec![history_first]
        );
        drop(history_outbox);
        let _ = std::fs::remove_dir_all(history_root);

        let (bytes_root, bytes_owner, bytes_context, bytes_first, bytes_fact_encoded_bytes) =
            shared_owner_components();
        let bytes_second = second_target_record(bytes_context, &bytes_first.fact_ids);
        let bytes_total = canonical_record_bytes(&bytes_first)
            .expect("history first bytes")
            .checked_add(canonical_record_bytes(&bytes_second).expect("history second bytes"))
            .expect("history bytes fit")
            - 1;
        let bytes_policy = policy_for_total_limits(bytes_fact_encoded_bytes, 2, bytes_total);
        drop(bytes_owner);
        let bytes_owner = owner_with_policy(&bytes_root, bytes_policy);
        let bytes_outbox = DurableProofOutbox::from_owner_with_policy(bytes_owner, bytes_policy)
            .expect("total-byte-limited policy");
        bytes_outbox
            .enqueue(bytes_first.clone())
            .expect("total-byte first enqueue");
        let bytes_result = bytes_outbox.enqueue(bytes_second);
        assert!(
            matches!(
                &bytes_result,
                &Err(ProofOutboxError::LimitExceeded("proof bytes"))
            ),
            "total-byte refusal result: {bytes_result:?}"
        );
        assert_eq!(
            bytes_outbox
                .pending(bytes_context)
                .expect("pending after total-byte refusal"),
            vec![bytes_first]
        );
        drop(bytes_outbox);
        let _ = std::fs::remove_dir_all(bytes_root);
    }

    #[test]
    fn identity_is_order_independent_and_metadata_bound() {
        let context = MeshContextId::from_bytes([1; 32]);
        let target_key = SigningKey::from_bytes(&[2; 32]);
        let target = DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes())
            .expect("target");
        let first = FactId::from_bytes([3; 32]);
        let second = FactId::from_bytes([4; 32]);
        let left = ProofRecord::pending(
            context,
            target.clone(),
            vec![first, second],
            "owner",
            "binding",
        )
        .expect("left record");
        let right = ProofRecord::pending(
            context,
            target,
            vec![second, first, first],
            "different-owner",
            "different-binding",
        )
        .expect("right record");
        assert_eq!(left.delivery_id, right.delivery_id);
        assert_eq!(left.fact_ids, vec![first, second]);
        assert_ne!(left.owner, right.owner);
    }

    #[test]
    fn pending_record_survives_reopen_and_settlement_is_idempotent() {
        let root = root();
        let key = SigningKey::from_bytes(&[7; 32]);
        let bootstrap =
            VerifiedBootstrap::create_closed("proof-outbox", vec![key.clone()], [7; 32])
                .expect("bootstrap");
        let device =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("device");
        let fact = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target: device.clone(),
                    role: Role::Member,
                },
                device.clone(),
                Vec::new(),
            ),
            &key,
        )
        .expect("fact");
        let mut graph = FactGraph::from_bootstrap(&bootstrap);
        graph.admit(fact.clone()).expect("fact admission");
        let store = DurableSemanticStore::new(&root, "slot");
        store.commit(&graph, Vec::new()).expect("snapshot");

        let outbox = DurableProofOutbox::with_policy(&root, "slot", checked_default_policy())
            .expect("checked outbox policy");
        let record = ProofRecord::pending(
            bootstrap.context_id(),
            device,
            vec![fact.id],
            "semantic-owner",
            "proof-binding",
        )
        .expect("record");
        assert_eq!(outbox.enqueue(record.clone()).expect("enqueue"), record);
        assert_eq!(
            outbox.pending(bootstrap.context_id()).expect("pending"),
            vec![record.clone()]
        );
        let conflict = ProofRecord::pending(
            bootstrap.context_id(),
            record.target.clone(),
            record.fact_ids.clone(),
            "other-owner",
            record.binding.clone(),
        )
        .expect("conflicting record");
        assert!(matches!(
            outbox.enqueue(conflict),
            Err(ProofOutboxError::Conflict)
        ));
        let rebound = outbox
            .rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "semantic-owner",
                "proof-binding",
                "rebound-owner",
                "rebound-binding",
            )
            .expect("rebind");
        assert_eq!(rebound.delivery_id, record.delivery_id);
        assert_eq!(rebound.fact_ids, record.fact_ids);
        assert_eq!(rebound.owner, "rebound-owner");
        assert_eq!(rebound.binding, "rebound-binding");
        assert!(matches!(
            outbox.rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "semantic-owner",
                "proof-binding",
                "stale-owner",
                "stale-binding",
            ),
            Err(ProofOutboxError::StaleBinding)
        ));
        let unknown = ProofRecord::pending(
            bootstrap.context_id(),
            rebound.target.clone(),
            vec![FactId::from_bytes([0xa5; 32])],
            "semantic-owner",
            "unknown-binding",
        )
        .expect("unknown record");
        assert!(matches!(
            outbox.enqueue(unknown),
            Err(ProofOutboxError::Storage(_))
        ));
        let obsolete_target_key = SigningKey::from_bytes(&[8; 32]);
        let obsolete_target =
            DeviceId::from_public_key_bytes(*obsolete_target_key.verifying_key().as_bytes())
                .expect("obsolete target");
        let obsolete = ProofRecord::pending(
            bootstrap.context_id(),
            obsolete_target.clone(),
            vec![fact.id],
            "obsolete-owner",
            "obsolete-binding",
        )
        .expect("obsolete record");
        outbox.enqueue(obsolete.clone()).expect("obsolete enqueue");
        assert!(outbox
            .supersede(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete_target,
                Some(rebound.delivery_id),
            )
            .expect("supersede"));
        assert!(!outbox
            .supersede(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete_target,
                None,
            )
            .expect("repeat supersede"));
        assert!(!outbox
            .pending(bootstrap.context_id())
            .expect("pending after supersede")
            .iter()
            .any(|record| record.delivery_id == obsolete.delivery_id));
        assert!(matches!(
            outbox.rebind(
                bootstrap.context_id(),
                obsolete.delivery_id,
                &obsolete.owner,
                &obsolete.binding,
                "stale-owner",
                "stale-binding",
            ),
            Err(ProofOutboxError::AlreadySuperseded)
        ));
        let superseded_reopen =
            DurableProofOutbox::with_policy(&root, "slot", checked_default_policy())
                .expect("checked outbox policy");
        let superseded_records = superseded_reopen
            .proof_records(bootstrap.context_id())
            .expect("superseded tombstone reopen");
        let mut expected_obsolete = obsolete.clone();
        expected_obsolete.state = ProofRecordState::Superseded;
        assert_eq!(
            superseded_records
                .iter()
                .find(|persisted| persisted.delivery_id == obsolete.delivery_id),
            Some(&expected_obsolete)
        );
        store
            .commit(&graph, Vec::new())
            .expect("graph commit preserves proof");

        let reopened = DurableProofOutbox::with_policy(&root, "slot", checked_default_policy())
            .expect("checked outbox policy");
        assert_eq!(
            reopened.pending(bootstrap.context_id()).expect("reopen"),
            vec![rebound.clone()]
        );
        assert!(reopened
            .settle(bootstrap.context_id(), record.delivery_id)
            .expect("settle"));
        assert!(!reopened
            .settle(bootstrap.context_id(), record.delivery_id)
            .expect("repeat settle"));
        assert!(reopened
            .pending(bootstrap.context_id())
            .expect("settled pending")
            .is_empty());
        let settled_reopen =
            DurableProofOutbox::with_policy(&root, "slot", checked_default_policy())
                .expect("checked outbox policy");
        let settled_records = settled_reopen
            .proof_records(bootstrap.context_id())
            .expect("settled tombstone reopen");
        assert_eq!(settled_records.len(), 2);
        assert!(settled_records.iter().any(|persisted| {
            persisted.delivery_id == obsolete.delivery_id
                && persisted.state == ProofRecordState::Superseded
        }));
        assert!(settled_records.iter().any(|persisted| {
            persisted.delivery_id == record.delivery_id
                && persisted.state == ProofRecordState::Settled
        }));
        assert!(settled_reopen
            .pending(bootstrap.context_id())
            .expect("settled tombstone pending")
            .is_empty());
        assert!(matches!(
            reopened.rebind(
                bootstrap.context_id(),
                record.delivery_id,
                "rebound-owner",
                "rebound-binding",
                "settled-owner",
                "settled-binding",
            ),
            Err(ProofOutboxError::AlreadySettled)
        ));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shared_owner_rebind_vs_supersede_has_one_terminal_and_exact_metadata() {
        let (root, outbox, context, record) = shared_owner_fixture();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let rebind_outbox = Arc::clone(&outbox);
        let rebind_barrier = Arc::clone(&barrier);
        let rebind_record = record.clone();
        let rebind_thread = std::thread::spawn(move || {
            rebind_barrier.wait();
            rebind_outbox.rebind(
                context,
                rebind_record.delivery_id,
                "race-owner",
                "race-binding",
                "rebound-owner",
                "rebound-binding",
            )
        });

        let supersede_outbox = Arc::clone(&outbox);
        let supersede_barrier = Arc::clone(&barrier);
        let supersede_record = record.clone();
        let supersede_thread = std::thread::spawn(move || {
            supersede_barrier.wait();
            supersede_outbox.supersede(
                context,
                supersede_record.delivery_id,
                &supersede_record.target,
                None,
            )
        });
        barrier.wait();
        let rebind_result = rebind_thread.join().expect("rebind race thread");
        let supersede_result = supersede_thread.join().expect("supersede race thread");
        assert!(
            supersede_result.is_ok(),
            "supersede must complete under the shared owner: {supersede_result:?}"
        );
        assert!(
            rebind_result.is_ok()
                || matches!(
                    &rebind_result,
                    Err(ProofOutboxError::AlreadySettled)
                        | Err(ProofOutboxError::AlreadySuperseded)
                ),
            "rebind may win or observe the terminal supersession: {rebind_result:?}"
        );

        let pending = outbox.pending(context).expect("pending race records");
        assert!(pending.is_empty(), "a terminal race cannot leave Pending");
        let persisted = outbox
            .proof_records(context)
            .expect("terminal race record")
            .into_iter()
            .find(|candidate| candidate.delivery_id == record.delivery_id)
            .expect("terminal race tombstone");
        assert_eq!(persisted.state, ProofRecordState::Superseded);
        assert_eq!(persisted.version, record.version);
        assert_eq!(persisted.context_id, record.context_id);
        assert_eq!(persisted.target, record.target);
        assert_eq!(persisted.delivery_id, record.delivery_id);
        assert_eq!(persisted.fact_ids, record.fact_ids);
        assert!(
            (persisted.owner == "race-owner" && persisted.binding == "race-binding")
                || (persisted.owner == "rebound-owner" && persisted.binding == "rebound-binding"),
            "only the exact original or CAS-rebound custody metadata is valid"
        );
        drop(outbox);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn shared_owner_settle_vs_supersede_has_one_terminal_and_exact_metadata() {
        let (root, outbox, context, record) = shared_owner_fixture();
        let barrier = Arc::new(std::sync::Barrier::new(3));
        let settle_outbox = Arc::clone(&outbox);
        let settle_barrier = Arc::clone(&barrier);
        let settle_id = record.delivery_id;
        let settle_thread = std::thread::spawn(move || {
            settle_barrier.wait();
            settle_outbox.settle(context, settle_id)
        });

        let supersede_outbox = Arc::clone(&outbox);
        let supersede_barrier = Arc::clone(&barrier);
        let supersede_record = record.clone();
        let supersede_thread = std::thread::spawn(move || {
            supersede_barrier.wait();
            supersede_outbox.supersede(
                context,
                supersede_record.delivery_id,
                &supersede_record.target,
                None,
            )
        });
        barrier.wait();
        let settled = settle_thread.join().expect("settle race thread");
        let superseded = supersede_thread.join().expect("supersede race thread");
        let terminal_state = match (settled, superseded) {
            (Ok(true), Ok(false)) => ProofRecordState::Settled,
            (Ok(false), Ok(true)) => ProofRecordState::Superseded,
            (settled, superseded) => panic!(
                "shared-owner race returned an invalid terminal pair: {settled:?}, {superseded:?}"
            ),
        };

        let pending = outbox.pending(context).expect("pending race records");
        assert!(pending.is_empty(), "a terminal race cannot leave Pending");
        let persisted = outbox
            .proof_records(context)
            .expect("terminal race record")
            .into_iter()
            .find(|candidate| candidate.delivery_id == record.delivery_id)
            .expect("terminal race tombstone");
        assert_eq!(persisted.state, terminal_state);
        assert_eq!(persisted.version, record.version);
        assert_eq!(persisted.context_id, record.context_id);
        assert_eq!(persisted.target, record.target);
        assert_eq!(persisted.delivery_id, record.delivery_id);
        assert_eq!(persisted.fact_ids, record.fact_ids);
        assert_eq!(persisted.owner, record.owner);
        assert_eq!(persisted.binding, record.binding);
        drop(outbox);
        let _ = std::fs::remove_dir_all(root);
    }
}
