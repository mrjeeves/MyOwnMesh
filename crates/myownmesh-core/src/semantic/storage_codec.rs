//! Compact representation used only by the durable semantic store.
//!
//! The public/wire representation remains canonical JSON. SQLite does not
//! need to repeat base32 text, the per-network context, the row's author, or
//! authority-use subjects which are fixed by the fact body. This codec stores
//! the irreducible signed values and reconstructs the exact canonical fact
//! before it is trusted.

use bincode::Options as _;
use data_encoding::BASE32_NOPAD;
use serde::{Deserialize, Serialize};

#[cfg(test)]
use super::FactDomain;
use super::{
    content::AuthorityUse, AttestationDecision, DeviceId, ExclusiveCell, FactBody, FactContent,
    FactId, MeshContextId, Role, SignedFact, SEMANTIC_SCHEMA_VERSION,
};

const MAGIC: &[u8; 5] = b"MOMF\x01";

#[derive(Debug, Serialize, Deserialize)]
struct StoredFact {
    body: StoredFactBody,
    parents: Vec<[u8; 32]>,
    authority_predecessors: Vec<Vec<[u8; 32]>>,
    signature: Vec<u8>,
}

#[derive(Debug, Serialize, Deserialize)]
enum StoredExclusiveCell {
    Role([u8; 32]),
    Membership([u8; 32]),
    Decision([u8; 32]),
}

#[derive(Debug, Serialize, Deserialize)]
enum StoredFactBody {
    RoleGrant {
        target: [u8; 32],
        role: Role,
    },
    RoleRevoke {
        target: [u8; 32],
    },
    Evict {
        target: [u8; 32],
    },
    MembershipAdmit {
        target: [u8; 32],
    },
    EvictionProof {
        target: [u8; 32],
        evidence: Vec<[u8; 32]>,
    },
    SelfStandDown {
        device_id: [u8; 32],
        evidence: Vec<[u8; 32]>,
    },
    Attestation {
        target: [u8; 32],
        proposal: [u8; 32],
        decision: AttestationDecision,
        signer: [u8; 32],
        contributions: Vec<[u8; 32]>,
    },
    Resolution {
        cell: StoredExclusiveCell,
        cited_heads: Vec<[u8; 32]>,
        selected_head: [u8; 32],
    },
    AuthorityLineageResolution {
        subject: [u8; 32],
        cited_heads: Vec<[u8; 32]>,
        selected_head: [u8; 32],
    },
}

fn ids(values: &[FactId]) -> Vec<[u8; 32]> {
    values.iter().map(|value| *value.as_bytes()).collect()
}

fn fact_ids(values: Vec<[u8; 32]>) -> Vec<FactId> {
    values.into_iter().map(FactId::from_bytes).collect()
}

fn stored_cell(cell: &ExclusiveCell) -> StoredExclusiveCell {
    match cell {
        ExclusiveCell::Role { subject } => StoredExclusiveCell::Role(subject.as_bytes()),
        ExclusiveCell::Membership { subject } => {
            StoredExclusiveCell::Membership(subject.as_bytes())
        }
        ExclusiveCell::Decision { proposal } => StoredExclusiveCell::Decision(*proposal.as_bytes()),
    }
}

fn decoded_device(bytes: [u8; 32]) -> Result<DeviceId, String> {
    DeviceId::from_public_key_bytes(bytes)
}

fn decoded_cell(cell: StoredExclusiveCell) -> Result<ExclusiveCell, String> {
    match cell {
        StoredExclusiveCell::Role(subject) => Ok(ExclusiveCell::Role {
            subject: decoded_device(subject)?,
        }),
        StoredExclusiveCell::Membership(subject) => Ok(ExclusiveCell::Membership {
            subject: decoded_device(subject)?,
        }),
        StoredExclusiveCell::Decision(proposal) => Ok(ExclusiveCell::Decision {
            proposal: FactId::from_bytes(proposal),
        }),
    }
}

fn stored_body(body: &FactBody) -> StoredFactBody {
    match body {
        FactBody::RoleGrant { target, role } => StoredFactBody::RoleGrant {
            target: target.as_bytes(),
            role: *role,
        },
        FactBody::RoleRevoke { target } => StoredFactBody::RoleRevoke {
            target: target.as_bytes(),
        },
        FactBody::Evict { target } => StoredFactBody::Evict {
            target: target.as_bytes(),
        },
        FactBody::MembershipAdmit { target } => StoredFactBody::MembershipAdmit {
            target: target.as_bytes(),
        },
        FactBody::EvictionProof { target, evidence } => StoredFactBody::EvictionProof {
            target: target.as_bytes(),
            evidence: ids(evidence),
        },
        FactBody::SelfStandDown {
            device_id,
            evidence,
        } => StoredFactBody::SelfStandDown {
            device_id: device_id.as_bytes(),
            evidence: ids(evidence),
        },
        FactBody::Attestation {
            target,
            proposal,
            decision,
            signer,
            contributions,
        } => StoredFactBody::Attestation {
            target: target.as_bytes(),
            proposal: *proposal.as_bytes(),
            decision: *decision,
            signer: signer.as_bytes(),
            contributions: ids(contributions),
        },
        FactBody::Resolution {
            cell,
            cited_heads,
            selected_head,
        } => StoredFactBody::Resolution {
            cell: stored_cell(cell),
            cited_heads: ids(cited_heads),
            selected_head: *selected_head.as_bytes(),
        },
        FactBody::AuthorityLineageResolution {
            subject,
            cited_heads,
            selected_head,
        } => StoredFactBody::AuthorityLineageResolution {
            subject: subject.as_bytes(),
            cited_heads: ids(cited_heads),
            selected_head: *selected_head.as_bytes(),
        },
    }
}

fn decoded_body(body: StoredFactBody) -> Result<FactBody, String> {
    match body {
        StoredFactBody::RoleGrant { target, role } => Ok(FactBody::RoleGrant {
            target: decoded_device(target)?,
            role,
        }),
        StoredFactBody::RoleRevoke { target } => Ok(FactBody::RoleRevoke {
            target: decoded_device(target)?,
        }),
        StoredFactBody::Evict { target } => Ok(FactBody::Evict {
            target: decoded_device(target)?,
        }),
        StoredFactBody::MembershipAdmit { target } => Ok(FactBody::MembershipAdmit {
            target: decoded_device(target)?,
        }),
        StoredFactBody::EvictionProof { target, evidence } => Ok(FactBody::EvictionProof {
            target: decoded_device(target)?,
            evidence: fact_ids(evidence),
        }),
        StoredFactBody::SelfStandDown {
            device_id,
            evidence,
        } => Ok(FactBody::SelfStandDown {
            device_id: decoded_device(device_id)?,
            evidence: fact_ids(evidence),
        }),
        StoredFactBody::Attestation {
            target,
            proposal,
            decision,
            signer,
            contributions,
        } => Ok(FactBody::Attestation {
            target: decoded_device(target)?,
            proposal: FactId::from_bytes(proposal),
            decision,
            signer: decoded_device(signer)?,
            contributions: fact_ids(contributions),
        }),
        StoredFactBody::Resolution {
            cell,
            cited_heads,
            selected_head,
        } => Ok(FactBody::Resolution {
            cell: decoded_cell(cell)?,
            cited_heads: fact_ids(cited_heads),
            selected_head: FactId::from_bytes(selected_head),
        }),
        StoredFactBody::AuthorityLineageResolution {
            subject,
            cited_heads,
            selected_head,
        } => Ok(FactBody::AuthorityLineageResolution {
            subject: decoded_device(subject)?,
            cited_heads: fact_ids(cited_heads),
            selected_head: FactId::from_bytes(selected_head),
        }),
    }
}

pub(super) fn encode(fact: &SignedFact) -> Result<Vec<u8>, String> {
    fact.content.validate().map_err(|error| error.to_string())?;
    let signature = BASE32_NOPAD
        .decode(fact.signature.to_uppercase().as_bytes())
        .map_err(|error| format!("invalid fact signature: {error}"))?;
    if signature.len() != ed25519_dalek::SIGNATURE_LENGTH
        || BASE32_NOPAD.encode(&signature).to_lowercase() != fact.signature
    {
        return Err("fact signature is not canonical".into());
    }
    let stored = StoredFact {
        body: stored_body(&fact.content.body),
        parents: ids(&fact.content.parents),
        authority_predecessors: fact
            .content
            .authority_uses
            .iter()
            .map(|use_| ids(&use_.predecessors))
            .collect(),
        signature,
    };
    let payload = bincode::DefaultOptions::new()
        .with_varint_encoding()
        .serialize(&stored)
        .map_err(|error| error.to_string())?;
    let mut encoded = Vec::with_capacity(MAGIC.len() + payload.len());
    encoded.extend_from_slice(MAGIC);
    encoded.extend_from_slice(&payload);
    Ok(encoded)
}

pub(super) fn decode(
    encoded: &[u8],
    context: MeshContextId,
    author: [u8; 32],
    id: [u8; 32],
) -> Result<SignedFact, String> {
    if !encoded.starts_with(MAGIC) {
        return Err("unsupported durable fact encoding".into());
    }
    let payload = &encoded[MAGIC.len()..];
    let stored: StoredFact = bincode::DefaultOptions::new()
        .with_varint_encoding()
        .with_limit(u64::try_from(payload.len()).map_err(|_| "stored fact is too large")?)
        .reject_trailing_bytes()
        .deserialize(payload)
        .map_err(|error| error.to_string())?;
    if stored.signature.len() != ed25519_dalek::SIGNATURE_LENGTH {
        return Err("stored fact signature length is invalid".into());
    }
    let author = decoded_device(author)?;
    let body = decoded_body(stored.body)?;
    let subjects = body.authority_use_subjects(&author);
    if subjects.len() != stored.authority_predecessors.len() {
        return Err("stored authority-use count is invalid".into());
    }
    let authority_uses = subjects
        .into_iter()
        .zip(stored.authority_predecessors)
        .map(|(subject, predecessors)| AuthorityUse {
            subject,
            predecessors: fact_ids(predecessors),
        })
        .collect();
    let fact = SignedFact {
        content: FactContent {
            version: SEMANTIC_SCHEMA_VERSION,
            domain: body.domain(),
            mesh_context: context,
            body,
            author,
            parents: fact_ids(stored.parents),
            authority_uses,
        },
        id: FactId::from_bytes(id),
        signature: BASE32_NOPAD.encode(&stored.signature).to_lowercase(),
    };
    if FactId::from_content(&fact.content) != fact.id {
        return Err("stored fact id does not match canonical content".into());
    }
    Ok(fact)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::semantic::VerifiedBootstrap;

    #[test]
    fn compact_codec_round_trips_without_changing_authority() {
        let key = SigningKey::from_bytes(&[42; 32]);
        let bootstrap = VerifiedBootstrap::create_closed("compact-codec", [key.clone()], [42; 32])
            .expect("bootstrap");
        let author =
            DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("author");
        let target = DeviceId::from_public_key_bytes(
            *SigningKey::from_bytes(&[43; 32]).verifying_key().as_bytes(),
        )
        .expect("target");
        let parent = FactId::from_bytes([7; 32]);
        let fact = SignedFact::sign(
            FactContent::new(
                FactDomain::Governance,
                bootstrap.context_id(),
                FactBody::RoleGrant {
                    target,
                    role: Role::Member,
                },
                author.clone(),
                vec![parent],
            ),
            &key,
        )
        .expect("fact");
        let encoded = encode(&fact).expect("encode");
        let decoded = decode(
            &encoded,
            bootstrap.context_id(),
            author.as_bytes(),
            *fact.id.as_bytes(),
        )
        .expect("decode");
        assert_eq!(decoded, fact);
        assert!(
            encoded.len() <= 256,
            "basic stored fact is {} bytes",
            encoded.len()
        );

        let human_readable = serde_json::to_vec(&fact).expect("human-readable JSON");
        assert_eq!(
            decode(
                &human_readable,
                bootstrap.context_id(),
                author.as_bytes(),
                *fact.id.as_bytes(),
            )
            .expect_err("JSON must never be accepted as durable storage"),
            "unsupported durable fact encoding"
        );
        println!(
            "compact_fact_bytes={} human_readable_json_bytes={}",
            encoded.len(),
            human_readable.len()
        );
        assert!(encoded.len() < human_readable.len());
    }
}
