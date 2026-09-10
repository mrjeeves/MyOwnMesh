#![cfg(feature = "transport-lab")]

//! Bootstrap controls for the canonical V4 Semantic owner.

use ed25519_dalek::SigningKey;

use myownmesh_core::semantic::{
    DeviceId, FactBody, FactContent, FactDomain, FactGraph, Role, SemanticError, SignedFact,
    VerifiedBootstrap,
};

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn author(key: &SigningKey) -> DeviceId {
    DeviceId::from_public_key_bytes(*key.verifying_key().as_bytes()).expect("valid device id")
}

fn closed(seed: u8, creation_id: u8) -> VerifiedBootstrap {
    VerifiedBootstrap::create_closed("bootstrap-controls", vec![key(seed)], [creation_id; 32])
        .expect("closed bootstrap verifies")
}

fn fact(bootstrap: &VerifiedBootstrap, signing_key: &SigningKey) -> SignedFact {
    SignedFact::sign(
        FactContent::new(
            FactDomain::Governance,
            bootstrap.context_id(),
            FactBody::RoleGrant {
                target: author(signing_key),
                role: Role::Member,
            },
            author(signing_key),
            Vec::new(),
        ),
        signing_key,
    )
    .expect("bootstrap fact signs")
}

#[test]
fn shared_bootstrap_context_is_required_by_every_graph() {
    let alice = closed(21, 1);
    let bob = VerifiedBootstrap::from_record(alice.record().clone()).expect("exact import");
    assert_eq!(alice.context_id(), bob.context_id());

    let signed = fact(&alice, &key(21));
    let mut alice_graph = FactGraph::from_bootstrap(&alice);
    let mut bob_graph = FactGraph::from_bootstrap(&bob);
    alice_graph
        .admit(signed.clone())
        .expect("Alice admits fact");
    bob_graph.admit(signed).expect("Bob admits exact fact");
    assert_eq!(alice_graph.context_id(), bob_graph.context_id());
    assert_eq!(alice_graph.projection(), bob_graph.projection());
}

#[test]
fn foreign_context_refuses_before_quarantine_or_projection() {
    let local = closed(22, 1);
    let foreign = closed(22, 2);
    let mut graph = FactGraph::from_bootstrap(&local);
    let result = graph.admit(fact(&foreign, &key(22)));
    assert!(matches!(result, Err(SemanticError::ContextMismatch { .. })));
    assert_eq!(graph.len(), 0);
    assert_eq!(graph.quarantined().count(), 0);
    assert!(graph.projection().cells().next().is_none());
}

#[test]
fn unknown_semantic_kind_wire_is_rejected() {
    let unsupported = serde_json::json!({
        "kind": "future_semantic_kind",
    });
    assert!(
        serde_json::from_value::<FactBody>(unsupported).is_err(),
        "unsupported semantic kind is refused before graph admission"
    );
}
