//! Canonical fact identities and signed semantic content.

use data_encoding::BASE32_NOPAD;
use ed25519_dalek::SigningKey;
use serde::{de::Error as _, Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};

use super::content::{AuthorityUse, DeviceId, Encoder, FactBody, FactDomain};
use super::verify::SemanticError;
use super::MeshContextId;

/// The digest of canonical fact content.  It is the only identity used by the
/// causal graph; envelopes and couriers cannot create a second identity.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FactId([u8; 32]);

impl FactId {
    pub fn from_content(content: &FactContent) -> Self {
        let digest = Sha256::digest(content.canonical_bytes());
        let mut bytes = [0u8; 32];
        bytes.copy_from_slice(&digest);
        Self(bytes)
    }

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn base32(&self) -> String {
        BASE32_NOPAD.encode(&self.0).to_lowercase()
    }
}

impl std::fmt::Debug for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("FactId").field(&self.base32()).finish()
    }
}

impl std::fmt::Display for FactId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.base32())
    }
}

impl Serialize for FactId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.base32())
    }
}

impl<'de> Deserialize<'de> for FactId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let encoded = String::deserialize(deserializer)?;
        if encoded != encoded.to_lowercase() {
            return Err(D::Error::custom("FactId must use lowercase base32"));
        }
        let bytes = BASE32_NOPAD
            .decode(encoded.to_uppercase().as_bytes())
            .map_err(D::Error::custom)?;
        if bytes.len() != 32 {
            return Err(D::Error::custom("FactId must decode to 32 bytes"));
        }
        let mut value = [0u8; 32];
        value.copy_from_slice(&bytes);
        let id = Self(value);
        if encoded != id.base32() {
            return Err(D::Error::custom("FactId is not canonical base32"));
        }
        Ok(id)
    }
}

/// The signed, transport-independent content of a V4 semantic fact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FactContent {
    /// Explicit wire-carried version. Only V4 semantic content is admitted.
    pub version: u32,
    pub domain: FactDomain,
    pub mesh_context: MeshContextId,
    pub body: FactBody,
    pub author: DeviceId,
    pub parents: Vec<FactId>,
    #[serde(default)]
    pub authority_uses: Vec<AuthorityUse>,
}

impl FactContent {
    pub fn new(
        domain: FactDomain,
        mesh_context: MeshContextId,
        body: FactBody,
        author: DeviceId,
        mut parents: Vec<FactId>,
    ) -> Self {
        parents.sort();
        parents.dedup();
        let mut body = body;
        body.normalize();
        let authority_uses = body
            .authority_use_subjects(&author)
            .into_iter()
            .map(|subject| AuthorityUse::new(subject, parents.clone()))
            .collect();
        Self {
            version: super::SEMANTIC_SCHEMA_VERSION,
            domain,
            mesh_context,
            body,
            author,
            parents,
            authority_uses,
        }
    }

    /// Construct canonical content from the graph's exact exclusive-cell
    /// witness.  Callers may add authority/evidence support explicitly; body
    /// support (evidence, attestation inputs, and cited resolution heads) is
    /// included automatically.  This prevents an unrelated current graph
    /// fact from silently becoming part of the candidate's causal past.
    pub fn from_authoring_witness<I>(
        graph: &super::FactGraph,
        body: FactBody,
        witness: &super::causal::AuthoringWitness,
        support: I,
    ) -> Self
    where
        I: IntoIterator<Item = FactId>,
    {
        let mut parents = witness.clone().into_parents();
        parents.extend(body.causal_support());
        parents.extend(support);
        let mut content = Self::new(
            body.domain(),
            graph.context_id(),
            body,
            witness.author().clone(),
            parents,
        );
        content.authority_uses = content
            .body
            .authority_use_subjects(&content.author)
            .into_iter()
            .map(|subject| AuthorityUse::new(subject.clone(), graph.authority_use_heads(&subject)))
            .collect();
        content
    }

    pub fn canonical_bytes(&self) -> Vec<u8> {
        let mut out = Encoder::new();
        out.tag("myownmesh-semantic-v4");
        out.tag("schema");
        out.bytes(&self.version.to_be_bytes());
        out.tag(self.domain.tag());
        out.context(self.mesh_context);
        out.device(&self.author);
        out.tag("parents");
        out.list_ids(&self.parents);
        out.tag("authority_uses");
        out.list_authority_uses(&self.authority_uses);
        out.tag("body");
        self.body.encode(&mut out);
        out.finish()
    }

    pub fn validate(&self) -> Result<(), SemanticError> {
        if self.version != super::SEMANTIC_SCHEMA_VERSION {
            return Err(SemanticError::UnsupportedVersion(self.version));
        }
        if self.body.domain() != self.domain {
            return Err(SemanticError::DomainMismatch);
        }
        self.body.validate_canonical()?;
        let expected = self.body.authority_use_subjects(&self.author);
        let actual = self
            .authority_uses
            .iter()
            .map(|use_| use_.subject.clone())
            .collect::<Vec<_>>();
        if actual != expected {
            return Err(SemanticError::InvalidAuthorityUse);
        }
        for authority_use in &self.authority_uses {
            if !authority_use
                .predecessors
                .windows(2)
                .all(|pair| pair[0] < pair[1])
            {
                return Err(SemanticError::NonCanonicalSet("authority use predecessors"));
            }
            if !authority_use
                .predecessors
                .iter()
                .all(|predecessor| self.parents.contains(predecessor))
            {
                return Err(SemanticError::InvalidAuthorityUse);
            }
        }
        for pair in self.parents.windows(2) {
            if pair[0] == pair[1] {
                return Err(SemanticError::DuplicateParent);
            }
            if pair[0] > pair[1] {
                return Err(SemanticError::UnsortedParents);
            }
        }
        match &self.body {
            FactBody::SelfStandDown { device_id, .. } => {
                if self.author != *device_id {
                    return Err(SemanticError::InvalidStandDownProof);
                }
            }
            FactBody::Attestation { signer, .. } => {
                if self.author != *signer {
                    return Err(SemanticError::AuthorMismatch);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFactContent {
    version: u32,
    domain: FactDomain,
    mesh_context: MeshContextId,
    body: FactBody,
    author: DeviceId,
    parents: Vec<FactId>,
    #[serde(default)]
    authority_uses: Vec<AuthorityUse>,
}

impl<'de> Deserialize<'de> for FactContent {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = WireFactContent::deserialize(deserializer)?;
        let content = Self {
            version: wire.version,
            domain: wire.domain,
            mesh_context: wire.mesh_context,
            body: wire.body,
            author: wire.author,
            parents: wire.parents,
            authority_uses: wire.authority_uses,
        };
        content.validate().map_err(D::Error::custom)?;
        Ok(content)
    }
}

/// A canonical fact plus a signature over its content-derived FactId.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SignedFact {
    pub content: FactContent,
    pub id: FactId,
    pub signature: String,
}

impl SignedFact {
    pub fn sign(content: FactContent, key: &SigningKey) -> Result<Self, SemanticError> {
        content.validate()?;
        let expected_author = DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes())
            .map_err(|_| SemanticError::AuthorMismatch)?;
        if content.author != expected_author {
            return Err(SemanticError::AuthorMismatch);
        }
        let id = FactId::from_content(&content);
        let signature = crate::signing::sign_with(key, id.as_bytes());
        Ok(Self {
            content,
            id,
            signature,
        })
    }

    pub fn verify(&self) -> Result<(), SemanticError> {
        super::verify::verify_fact(self)
    }
}

/// Alias used by adapters when they need to state that a value is canonical.
pub type CanonicalFact = SignedFact;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::semantic::{FactBody, FactDomain, VerifiedBootstrap};

    fn key() -> SigningKey {
        SigningKey::from_bytes(&[9; 32])
    }

    fn device(key: &SigningKey) -> DeviceId {
        DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).unwrap()
    }

    #[test]
    fn canonical_context_and_device_are_part_of_fact_identity() {
        let key = key();
        let device = device(&key);
        let bootstrap = VerifiedBootstrap::create_closed("mesh-a", vec![key.clone()], [0; 32])
            .expect("bootstrap");
        let context = bootstrap.context_id();
        let content = FactContent::new(
            FactDomain::Governance,
            context,
            FactBody::RoleRevoke {
                target: device.clone(),
            },
            device,
            Vec::new(),
        );
        let fact = SignedFact::sign(content, &key).expect("canonical fact");
        assert!(fact.verify().is_ok());
        assert_eq!(FactId::from_content(&fact.content), fact.id);
    }

    #[test]
    fn nested_canonical_fact_fields_reject_unknown_keys() {
        let key = key();
        let device = device(&key);
        let context =
            VerifiedBootstrap::create_closed("mesh-nested-wire", vec![key.clone()], [0; 32])
                .expect("bootstrap")
                .context_id();
        let content = FactContent::new(
            FactDomain::Governance,
            context,
            FactBody::RoleRevoke {
                target: device.clone(),
            },
            device,
            Vec::new(),
        );
        let fact = SignedFact::sign(content, &key).expect("canonical fact");

        let mut content_wire = serde_json::to_value(&fact.content).unwrap();
        content_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<FactContent>(content_wire).is_err());

        let mut body_wire = serde_json::to_value(&fact.content.body).unwrap();
        body_wire["legacy"] = serde_json::json!(true);
        let mut fact_wire = serde_json::to_value(&fact).unwrap();
        fact_wire["content"]["body"] = body_wire;
        assert!(serde_json::from_value::<SignedFact>(fact_wire).is_err());

        let mut signed_wire = serde_json::to_value(&fact).unwrap();
        signed_wire["legacy"] = serde_json::json!(true);
        assert!(serde_json::from_value::<SignedFact>(signed_wire).is_err());
    }

    #[test]
    fn grant_revoke_evict_and_resolution_share_only_typed_cells() {
        let key = key();
        let device = device(&key);
        let grant = FactBody::RoleGrant {
            target: device.clone(),
            role: crate::semantic::Role::Member,
        };
        let revoke = FactBody::RoleRevoke {
            target: device.clone(),
        };
        let evict = FactBody::Evict {
            target: device.clone(),
        };
        assert_eq!(grant.exclusive_cells(), revoke.exclusive_cells());
        assert_eq!(evict.exclusive_cells().len(), 2);
        assert!(matches!(
            evict.exclusive_cells().as_slice(),
            [
                crate::semantic::ExclusiveCell::Role { .. },
                crate::semantic::ExclusiveCell::Membership { .. }
            ]
        ));

        let proposal = FactId::from_bytes([3; 32]);
        let resolution = FactBody::Resolution {
            cell: crate::semantic::ExclusiveCell::decision(proposal),
            cited_heads: vec![proposal],
            selected_head: proposal,
        };
        assert!(matches!(
            resolution.exclusive_cells().as_slice(),
            [crate::semantic::ExclusiveCell::Decision { proposal: id }] if *id == proposal
        ));
    }

    #[test]
    fn unknown_semantic_kind_is_rejected_before_graph_admission() {
        let unsupported = serde_json::json!({
            "kind": "future_semantic_kind",
        });
        assert!(serde_json::from_value::<FactBody>(unsupported).is_err());
    }
}
