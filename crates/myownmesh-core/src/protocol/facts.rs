//! Wire wrappers for the transport-independent V4 semantic facts.
//!
//! Canonical content, FactId computation, signatures, and projection belong
//! exclusively to `crate::semantic`.  This module deliberately re-exports
//! those exact types instead of defining a second protocol-local hash or body
//! representation.  A fact therefore has one identity regardless of whether
//! it arrived over a peer, from a cache, or from a durable store.

use serde::{de::Error as _, Deserialize, Deserializer, Serialize};

pub use crate::semantic::{
    CanonicalFact, DeviceId, FactContent, FactId, MeshContextId, ProofDeliveryId, SignedFact,
};

/// One exact durable stand-down proof delivery.
///
/// The delivery identity is derived from the authenticated mesh context,
/// target, and canonical fact identities. Transport custody is deliberately
/// absent from the wire envelope: a sender validates the current owner and
/// binding separately, and a receiver acknowledges only this stable identity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ProofDeliveryMessage {
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
    pub facts: Vec<SignedFact>,
}

impl ProofDeliveryMessage {
    pub fn new(
        context_id: MeshContextId,
        target: DeviceId,
        mut facts: Vec<SignedFact>,
    ) -> Result<Self, String> {
        facts.sort_by_key(|fact| fact.id);
        let delivery_id = ProofDeliveryId::digest(
            context_id,
            &target,
            &facts.iter().map(|fact| fact.id).collect::<Vec<_>>(),
        );
        let message = Self {
            context_id,
            target,
            delivery_id,
            facts,
        };
        message.validate()?;
        Ok(message)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.facts.is_empty() {
            return Err("proof delivery must contain at least one signed fact".into());
        }
        if self.facts.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err("proof facts must be sorted by unique FactId".into());
        }
        if self
            .facts
            .iter()
            .any(|fact| fact.content.mesh_context != self.context_id)
        {
            return Err("proof fact mesh context does not match delivery context".into());
        }
        let fact_ids: Vec<_> = self.facts.iter().map(|fact| fact.id).collect();
        let expected = ProofDeliveryId::digest(self.context_id, &self.target, &fact_ids);
        if self.delivery_id != expected {
            return Err("proof delivery identity does not match its exact payload".into());
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawProofDeliveryMessage {
    context_id: MeshContextId,
    target: DeviceId,
    delivery_id: ProofDeliveryId,
    facts: Vec<SignedFact>,
}

impl<'de> Deserialize<'de> for ProofDeliveryMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawProofDeliveryMessage::deserialize(deserializer)?;
        let message = Self {
            context_id: raw.context_id,
            target: raw.target,
            delivery_id: raw.delivery_id,
            facts: raw.facts,
        };
        message.validate().map_err(D::Error::custom)?;
        Ok(message)
    }
}

/// Verified durable receipt for one exact proof delivery.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProofAckMessage {
    pub context_id: MeshContextId,
    pub target: DeviceId,
    pub delivery_id: ProofDeliveryId,
}

impl ProofAckMessage {
    pub fn for_delivery(delivery: &ProofDeliveryMessage) -> Self {
        Self {
            context_id: delivery.context_id,
            target: delivery.target.clone(),
            delivery_id: delivery.delivery_id,
        }
    }

    pub fn matches(&self, delivery: &ProofDeliveryMessage) -> bool {
        self.context_id == delivery.context_id
            && self.target == delivery.target
            && self.delivery_id == delivery.delivery_id
    }
}

/// One bounded page of canonical semantic facts on the peer wire.
///
/// The context, exclusive continuation cursor, and completion bit are part of
/// the frame rather than inferred from its carrier. This makes a page safe to
/// reject before any graph mutation and gives a receiver a deterministic way
/// to request the next finite portion of a graph.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct FactPageMessage {
    pub context_id: MeshContextId,
    pub facts: Vec<SignedFact>,
    pub next_cursor: Option<FactId>,
    pub complete: bool,
}

impl FactPageMessage {
    pub fn new(
        context_id: MeshContextId,
        facts: Vec<SignedFact>,
        next_cursor: Option<FactId>,
        complete: bool,
    ) -> Result<Self, String> {
        let page = Self {
            context_id,
            facts,
            next_cursor,
            complete,
        };
        page.validate()?;
        Ok(page)
    }

    pub fn validate(&self) -> Result<(), String> {
        if self.facts.is_empty() && (!self.complete || self.next_cursor.is_some()) {
            return Err("an empty fact page must be complete without a cursor".into());
        }
        if self
            .facts
            .iter()
            .any(|fact| fact.content.mesh_context != self.context_id)
        {
            return Err("fact page contains a foreign mesh context".into());
        }
        if self.facts.windows(2).any(|pair| pair[0].id >= pair[1].id) {
            return Err("fact page IDs must be strictly increasing".into());
        }
        let expected_cursor = self.facts.last().map(|fact| fact.id);
        if self.complete {
            if self.next_cursor.is_some() {
                return Err("a complete fact page cannot have a continuation cursor".into());
            }
        } else if self.next_cursor != expected_cursor {
            return Err("an incomplete fact page must end at its continuation cursor".into());
        }
        let encoded_len = self
            .encoded_len()
            .ok_or_else(|| "fact page length overflow".to_string())?;
        if encoded_len > super::RECEIVE_FRAME_BYTES {
            return Err("fact page exceeds the receive frame boundary".into());
        }
        Ok(())
    }

    pub(crate) fn encoded_len(&self) -> Option<usize> {
        super::encoded_json_len(&super::MeshMessage::FactPage(self.clone()))
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFactPageMessage {
    context_id: MeshContextId,
    facts: Vec<SignedFact>,
    next_cursor: Option<FactId>,
    complete: bool,
}

impl<'de> Deserialize<'de> for FactPageMessage {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFactPageMessage::deserialize(deserializer)?;
        let page = Self {
            context_id: raw.context_id,
            facts: raw.facts,
            next_cursor: raw.next_cursor,
            complete: raw.complete,
        };
        page.validate().map_err(D::Error::custom)?;
        Ok(page)
    }
}

/// A non-authoritative inventory of canonical facts known by one peer.
///
/// The context is exact and the identifiers are canonicalized at construction
/// time. The inventory contains no fact bodies and therefore cannot authorize,
/// replace, or project anything; it only lets a peer decide which signed facts
/// to request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactInventory {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

impl FactInventory {
    pub fn new(
        context_id: crate::semantic::MeshContextId,
        fact_ids: impl IntoIterator<Item = FactId>,
    ) -> Self {
        Self {
            context_id,
            fact_ids: canonical_fact_ids(fact_ids),
        }
    }

    pub fn context_id(&self) -> crate::semantic::MeshContextId {
        self.context_id
    }

    pub fn fact_ids(&self) -> &[FactId] {
        &self.fact_ids
    }

    /// Stream canonical inventory pages at the exact receive-safe wire
    /// boundary. Pages retain the same context and canonical ordering; no
    /// page is authority and a lost page is repaired by the next inventory
    /// pass.
    #[cfg(test)]
    pub(crate) fn pages(&self) -> ExactFramePages<'_, FactId, impl Fn(&[FactId]) -> Option<usize>> {
        let context_id = self.context_id;
        exact_frame_pages(&self.fact_ids, move |fact_ids| {
            super::encoded_json_len(&super::MeshMessage::FactInventory(Self {
                context_id,
                fact_ids: fact_ids.to_vec(),
            }))
        })
    }
}

/// A non-authoritative request for exact canonical facts.
///
/// Only the identifiers are requested. The response must carry the signed
/// bodies in [`FactPageMessage`]; this request itself is never an authority
/// input and cannot install a fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactRequest {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

impl FactRequest {
    pub fn new(
        context_id: crate::semantic::MeshContextId,
        fact_ids: impl IntoIterator<Item = FactId>,
    ) -> Self {
        Self {
            context_id,
            fact_ids: canonical_fact_ids(fact_ids),
        }
    }

    pub fn context_id(&self) -> crate::semantic::MeshContextId {
        self.context_id
    }

    pub fn fact_ids(&self) -> &[FactId] {
        &self.fact_ids
    }

    /// Stream this exact-context request using the same encoded frame
    /// boundary as inventory pages. A request page never changes the
    /// requested IDs.
    pub(crate) fn pages(&self) -> ExactFramePages<'_, FactId, impl Fn(&[FactId]) -> Option<usize>> {
        let context_id = self.context_id;
        exact_frame_pages(&self.fact_ids, move |fact_ids| {
            super::encoded_json_len(&super::MeshMessage::FactRequest(Self {
                context_id,
                fact_ids: fact_ids.to_vec(),
            }))
        })
    }
}

pub(crate) struct ExactFramePages<'a, T, F> {
    values: std::slice::Iter<'a, T>,
    pending: Option<T>,
    encoded_len: F,
    started: bool,
    finished: bool,
    invalid: bool,
}

impl<'a, T: Clone, F> ExactFramePages<'a, T, F>
where
    F: Fn(&[T]) -> Option<usize>,
{
    pub(crate) fn is_valid(&self) -> bool {
        !self.invalid
    }
}

impl<'a, T: Clone, F> Iterator for ExactFramePages<'a, T, F>
where
    F: Fn(&[T]) -> Option<usize>,
{
    type Item = Vec<T>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished || self.invalid {
            return None;
        }
        let mut current = Vec::new();
        let Some(mut value) = self.pending.take().or_else(|| self.values.next().cloned()) else {
            self.finished = true;
            return (!self.started).then(|| {
                self.started = true;
                current
            });
        };
        self.started = true;
        loop {
            current.push(value.clone());
            match (self.encoded_len)(&current) {
                Some(length) if length <= super::RECEIVE_FRAME_BYTES => {}
                Some(_) | None => {
                    current.pop();
                    if current.is_empty() {
                        self.invalid = true;
                        return None;
                    }
                    self.pending = Some(value);
                    return Some(current);
                }
            }
            let Some(next) = self.values.next() else {
                self.finished = true;
                return Some(current);
            };
            value = next.clone();
        }
    }
}

fn exact_frame_pages<'a, T: Clone, F>(values: &'a [T], encoded_len: F) -> ExactFramePages<'a, T, F>
where
    F: Fn(&[T]) -> Option<usize>,
{
    ExactFramePages {
        values: values.iter(),
        pending: None,
        encoded_len,
        started: false,
        finished: false,
        invalid: false,
    }
}

fn canonical_fact_ids(fact_ids: impl IntoIterator<Item = FactId>) -> Vec<FactId> {
    let mut fact_ids: Vec<_> = fact_ids.into_iter().collect();
    fact_ids.sort_unstable();
    fact_ids.dedup();
    fact_ids
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawFactSet {
    context_id: crate::semantic::MeshContextId,
    fact_ids: Vec<FactId>,
}

fn deserialize_canonical_fact_ids<E>(
    raw: RawFactSet,
) -> Result<(crate::semantic::MeshContextId, Vec<FactId>), E>
where
    E: serde::de::Error,
{
    let canonical = canonical_fact_ids(raw.fact_ids.clone());
    if raw.fact_ids != canonical {
        return Err(E::custom(
            "fact identifiers must be sorted and deduplicated",
        ));
    }
    Ok((raw.context_id, canonical))
}

impl<'de> Deserialize<'de> for FactInventory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFactSet::deserialize(deserializer)?;
        let (context_id, fact_ids) = deserialize_canonical_fact_ids(raw)?;
        Ok(Self {
            context_id,
            fact_ids,
        })
    }
}

impl<'de> Deserialize<'de> for FactRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawFactSet::deserialize(deserializer)?;
        let (context_id, fact_ids) = deserialize_canonical_fact_ids(raw)?;
        Ok(Self {
            context_id,
            fact_ids,
        })
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use crate::semantic::{FactBody, FactDomain};

    use super::*;

    fn signed_fact(context_id: MeshContextId) -> SignedFact {
        let key = SigningKey::from_bytes(&[11; 32]);
        let device = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap();
        let content = FactContent::new(
            FactDomain::Governance,
            context_id,
            FactBody::RoleRevoke {
                target: device.clone(),
            },
            device,
            Vec::new(),
        );
        SignedFact::sign(content, &key).unwrap()
    }

    #[test]
    fn proof_delivery_round_trips_with_exact_identity() {
        let context_id = MeshContextId::from_bytes([7; 32]);
        let target_key = SigningKey::from_bytes(&[12; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let delivery =
            ProofDeliveryMessage::new(context_id, target, vec![signed_fact(context_id)]).unwrap();
        let ack = ProofAckMessage::for_delivery(&delivery);
        assert!(ack.matches(&delivery));

        let encoded = serde_json::to_vec(&delivery).unwrap();
        let decoded: ProofDeliveryMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, delivery);
    }

    #[test]
    fn proof_delivery_rejects_payload_or_context_mutation() {
        let context_id = MeshContextId::from_bytes([8; 32]);
        let target_key = SigningKey::from_bytes(&[13; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let delivery =
            ProofDeliveryMessage::new(context_id, target, vec![signed_fact(context_id)]).unwrap();
        let mut wire = serde_json::to_value(&delivery).unwrap();
        wire["context_id"] = serde_json::to_value(MeshContextId::from_bytes([9; 32])).unwrap();
        assert!(serde_json::from_value::<ProofDeliveryMessage>(wire).is_err());
    }

    #[test]
    fn fact_page_requires_exact_context_order_and_continuation() {
        let context_id = MeshContextId::from_bytes([0x18; 32]);
        let fact = signed_fact(context_id);
        let page = FactPageMessage::new(context_id, vec![fact.clone()], None, true).unwrap();
        let encoded = serde_json::to_vec(&page).unwrap();
        let decoded: FactPageMessage = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded, page);

        let mut foreign = serde_json::to_value(&page).unwrap();
        foreign["context_id"] =
            serde_json::to_value(MeshContextId::from_bytes([0x19; 32])).unwrap();
        assert!(serde_json::from_value::<FactPageMessage>(foreign).is_err());

        let mut incomplete = serde_json::to_value(&page).unwrap();
        incomplete["complete"] = serde_json::json!(false);
        assert!(serde_json::from_value::<FactPageMessage>(incomplete).is_err());

        let mut unknown = serde_json::to_value(&page).unwrap();
        unknown["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FactPageMessage>(unknown).is_err());

        let mut duplicate = serde_json::to_value(&page).unwrap();
        duplicate["facts"] = serde_json::json!([fact.clone(), fact]);
        assert!(serde_json::from_value::<FactPageMessage>(duplicate).is_err());
    }

    #[test]
    fn cutover_fact_wrappers_reject_unknown_fields() {
        let context_id = MeshContextId::from_bytes([0x19; 32]);
        let target_key = SigningKey::from_bytes(&[14; 32]);
        let target =
            DeviceId::from_public_key_bytes(*target_key.verifying_key().as_bytes()).unwrap();
        let delivery =
            ProofDeliveryMessage::new(context_id, target, vec![signed_fact(context_id)]).unwrap();

        let mut delivery_wire = serde_json::to_value(&delivery).unwrap();
        delivery_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProofDeliveryMessage>(delivery_wire).is_err());

        let mut ack_wire = serde_json::to_value(ProofAckMessage::for_delivery(&delivery)).unwrap();
        ack_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<ProofAckMessage>(ack_wire).is_err());

        assert!(serde_json::from_str::<crate::protocol::MeshMessage>(
            r#"{"kind":"fact_bundle","facts":[],"legacy":true}"#
        )
        .is_err());

        let fact_id = FactId::from_bytes([1; 32]);
        let context = serde_json::to_string(&context_id).unwrap();
        let fact_id = serde_json::to_string(&fact_id).unwrap();
        assert!(serde_json::from_str::<crate::protocol::MeshMessage>(&format!(
            r#"{{"kind":"fact_inventory","context_id":{context},"fact_ids":[{fact_id}],"legacy":true}}"#
        ))
        .is_err());
    }

    #[test]
    fn anti_entropy_pages_are_canonical_and_fit_the_exact_frame_boundary() {
        let context_id = MeshContextId::from_bytes([0x42; 32]);
        let ids = (0u64..2_000)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&index.to_be_bytes());
                FactId::from_bytes(bytes)
            })
            .collect::<Vec<_>>();
        let inventory = FactInventory::new(context_id, ids.clone());
        let mut pages = inventory.pages();
        let mut page_count = 0;
        let mut flattened = Vec::new();
        for fact_ids in pages.by_ref() {
            page_count += 1;
            assert!(fact_ids.windows(2).all(|pair| pair[0] < pair[1]));
            let page = FactInventory::new(context_id, fact_ids);
            let encoded =
                serde_json::to_vec(&crate::protocol::MeshMessage::FactInventory(page.clone()))
                    .unwrap();
            assert!(encoded.len() <= super::super::RECEIVE_FRAME_BYTES);
            assert_eq!(page.context_id(), context_id);
            flattened.extend_from_slice(page.fact_ids());
        }
        assert!(pages.is_valid());
        assert!(
            page_count > 1,
            "paging must be driven by bytes, not item count"
        );
        assert_eq!(flattened, inventory.fact_ids());
    }

    #[test]
    fn inventory_strict_subset_incomparable_and_lost_page_controls() {
        let context_id = MeshContextId::from_bytes([0x51; 32]);
        let ids = (0u64..2_000)
            .map(|index| {
                let mut bytes = [0; 32];
                bytes[..8].copy_from_slice(&index.to_be_bytes());
                FactId::from_bytes(bytes)
            })
            .collect::<Vec<_>>();
        let full = FactInventory::new(context_id, ids.clone());
        let strict = FactInventory::new(context_id, ids[..2].iter().copied());
        let left = FactInventory::new(context_id, [ids[0], ids[1]]);
        let right = FactInventory::new(context_id, [ids[0], ids[2]]);
        assert!(strict
            .fact_ids()
            .iter()
            .all(|id| full.fact_ids().contains(id)));
        assert!(!left
            .fact_ids()
            .iter()
            .all(|id| right.fact_ids().contains(id)));
        assert!(!right
            .fact_ids()
            .iter()
            .all(|id| left.fact_ids().contains(id)));

        let mut first_pass = full.pages();
        let dropped = first_pass.next().expect("full inventory has a page");
        assert!(first_pass.is_valid());
        let mut recovery_pass = full.pages();
        let recovered = recovery_pass.next().expect("ticker can repair a lost page");
        assert_eq!(recovered, dropped);
        assert!(recovery_pass.is_valid());
    }
}
