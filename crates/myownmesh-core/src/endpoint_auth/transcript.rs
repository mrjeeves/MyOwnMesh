//! The one signed-transcript framing for endpoint authentication.
//!
//! This module owns the byte layout and nothing else. It is the single
//! implementation: the existing attempt path and the task state machine both
//! call it, so there is no second copy that could drift from the bytes a peer
//! actually verifies.
//!
//! Two properties are load-bearing here. Every paired field is ordered by role
//! rather than by which side is local, so both endpoints derive byte-identical
//! input from opposite views. And every field is length-prefixed rather than
//! separator-joined, so no free-form value can shift a later field boundary and
//! make two distinct field tuples serialize identically.

use super::context::EndpointAuthContext;
use super::{EndpointAuthProfile, EndpointRole, ENDPOINT_AUTH_DOMAIN_TAG};

/// Netstring-style `len:value` framing.
///
/// Injective by construction: the length prefix is what makes a separator
/// inside a field harmless.
fn push_field(out: &mut Vec<u8>, field: &str) {
    out.extend_from_slice(field.len().to_string().as_bytes());
    out.push(b':');
    out.extend_from_slice(field.as_bytes());
}

/// Canonical role ordering for one Device pair.
///
/// Derived from the pair, never chosen by the caller, so a caller cannot pick
/// whichever ordering makes a signature verify.
pub(crate) fn role_of(local_device_id: &str, remote_device_id: &str) -> EndpointRole {
    if local_device_id < remote_device_id {
        EndpointRole::Initiator
    } else {
        EndpointRole::Responder
    }
}

/// The exact bytes the named role must sign.
///
/// Fields arrive endpoint-relative and are reordered here into role-canonical
/// position, which is why both endpoints can call this with their own view and
/// obtain the same bytes.
// Still necessary, and deliberate: this is the low-level framing entry point,
// and every field is a distinct signed component that arrives endpoint-relative
// from a different owner (mesh, profile, role, the Device pair, the
// contribution pair, the binding pair). Grouping them into a struct would
// re-introduce exactly the caller-assembled bag of fields the context type
// exists to prevent, and would let a caller build a partially-populated
// transcript input. `transcript_for_context` is the argument-free path callers
// actually use.
#[allow(
    clippy::too_many_arguments,
    reason = "explicit-field transcript framing: each argument is a separate signed component supplied endpoint-relative"
)]
pub(crate) fn transcript_bytes(
    mesh_context: &str,
    profile: EndpointAuthProfile,
    signer: EndpointRole,
    local_device_id: &str,
    remote_device_id: &str,
    local_contribution: &str,
    remote_contribution: &str,
    local_fingerprint: &str,
    remote_fingerprint: &str,
) -> Vec<u8> {
    let (
        initiator_id,
        responder_id,
        initiator_contribution,
        responder_contribution,
        initiator_fingerprint,
        responder_fingerprint,
    ) = match role_of(local_device_id, remote_device_id) {
        EndpointRole::Initiator => (
            local_device_id,
            remote_device_id,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
        ),
        EndpointRole::Responder => (
            remote_device_id,
            local_device_id,
            remote_contribution,
            local_contribution,
            remote_fingerprint,
            local_fingerprint,
        ),
    };

    let mut transcript = Vec::from(ENDPOINT_AUTH_DOMAIN_TAG.as_bytes());
    for field in [
        mesh_context,
        profile.tag(),
        signer.tag(),
        initiator_id,
        responder_id,
        initiator_contribution,
        responder_contribution,
        initiator_fingerprint,
        responder_fingerprint,
    ] {
        push_field(&mut transcript, field);
    }
    transcript
}

/// The transcript for a task that already fixed its context.
///
/// The context supplies the mesh, the Device pair, the locally selected
/// profile, and the role-canonical binding pair, so the task never re-derives
/// ordering and never accepts it from a caller. This is a thin adapter over
/// [`transcript_bytes`], not a second framing.
pub(crate) fn transcript_for_context(
    context: &EndpointAuthContext,
    signer: EndpointRole,
    local_contribution: &str,
    peer_contribution: &str,
) -> Vec<u8> {
    transcript_bytes(
        context.mesh_context(),
        context.profile(),
        signer,
        context.local_device_id(),
        context.expected_remote_device_id(),
        local_contribution,
        peer_contribution,
        context.binding().local_component(),
        context.binding().remote_component(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connector::EndpointAuthBinding;

    fn context(local: &str, remote: &str) -> EndpointAuthContext {
        EndpointAuthContext::new(
            "mesh-1",
            local,
            remote,
            EndpointAuthBinding::webrtc_certificate_fingerprints("fp-of-a", "fp-of-b")
                .expect("both components present"),
        )
        .expect("non-empty identifiers")
    }

    /// Transcript for one endpoint's view, with every field overridable so a
    /// control can change exactly one thing.
    #[allow(
        clippy::too_many_arguments,
        reason = "permutation helper: each control changes exactly one signed field, so every field must stay individually overridable"
    )]
    fn bytes_with(
        mesh: &str,
        signer: EndpointRole,
        local_device: &str,
        remote_device: &str,
        local_contribution: &str,
        remote_contribution: &str,
        local_fingerprint: &str,
        remote_fingerprint: &str,
    ) -> Vec<u8> {
        transcript_bytes(
            mesh,
            EndpointAuthProfile::V1Ed25519Dtls,
            signer,
            local_device,
            remote_device,
            local_contribution,
            remote_contribution,
            local_fingerprint,
            remote_fingerprint,
        )
    }

    fn baseline() -> Vec<u8> {
        bytes_with(
            "mesh-1",
            EndpointRole::Initiator,
            "device-a",
            "device-b",
            "draw-a",
            "draw-b",
            "fp-of-a",
            "fp-of-b",
        )
    }

    #[test]
    fn v4_arc04_transcript_binds_mesh_context() {
        // A proof for one mesh must not verify for another: the mesh is a
        // signed field, not context the verifier supplies out of band.
        assert_ne!(
            baseline(),
            bytes_with(
                "mesh-2",
                EndpointRole::Initiator,
                "device-a",
                "device-b",
                "draw-a",
                "draw-b",
                "fp-of-a",
                "fp-of-b",
            )
        );
    }

    #[test]
    fn v4_arc04_transcript_commits_to_the_fixed_profile_selection() {
        // The selected profile is inside the signed bytes, so a peer cannot
        // negotiate one profile and prove another.
        let transcript = baseline();
        let tag = EndpointAuthProfile::V1Ed25519Dtls.tag();
        let framed = format!("{}:{tag}", tag.len());
        assert!(String::from_utf8_lossy(&transcript).contains(&framed));
    }

    #[test]
    fn v4_arc04_transcript_binds_both_endpoint_fingerprints() {
        // Either endpoint's certificate changing must change the bytes. A
        // signer-only binding would leave the verifier's endpoint uncommitted.
        for (local, remote) in [("other-fp", "fp-of-b"), ("fp-of-a", "other-fp")] {
            assert_ne!(
                baseline(),
                bytes_with(
                    "mesh-1",
                    EndpointRole::Initiator,
                    "device-a",
                    "device-b",
                    "draw-a",
                    "draw-b",
                    local,
                    remote,
                )
            );
        }
    }

    #[test]
    fn v4_arc04_fingerprint_pair_order_is_role_canonical_not_positional() {
        // The responder passes its own fingerprint as "local", yet both sides
        // must place the pair identically. Positional ordering would make the
        // two endpoints sign different bytes.
        let initiator = bytes_with(
            "mesh-1",
            EndpointRole::Initiator,
            "device-a",
            "device-b",
            "draw-a",
            "draw-b",
            "fp-of-a",
            "fp-of-b",
        );
        let responder = bytes_with(
            "mesh-1",
            EndpointRole::Initiator,
            "device-b",
            "device-a",
            "draw-b",
            "draw-a",
            "fp-of-b",
            "fp-of-a",
        );
        assert_eq!(initiator, responder);
    }

    #[test]
    fn v4_arc04_role_tag_defeats_signature_reflection() {
        // The two halves of one attempt sign different bytes, so a responder
        // cannot reflect the initiator's signature back as its own.
        assert_ne!(
            baseline(),
            bytes_with(
                "mesh-1",
                EndpointRole::Responder,
                "device-a",
                "device-b",
                "draw-a",
                "draw-b",
                "fp-of-a",
                "fp-of-b",
            )
        );
    }

    #[test]
    fn v4_arc04_both_endpoints_derive_one_identical_transcript() {
        let initiator = context("device-a", "device-b");
        let responder = EndpointAuthContext::new(
            "mesh-1",
            "device-b",
            "device-a",
            EndpointAuthBinding::webrtc_certificate_fingerprints("fp-of-b", "fp-of-a")
                .expect("both components present"),
        )
        .expect("non-empty identifiers");

        assert_eq!(
            transcript_for_context(&initiator, EndpointRole::Initiator, "draw-a", "draw-b"),
            transcript_for_context(&responder, EndpointRole::Initiator, "draw-b", "draw-a"),
        );
    }

    #[test]
    fn v4_arc04_separator_in_a_field_cannot_collide_two_transcripts() {
        // Length-prefixed framing is injective: a colon inside a free-form
        // field cannot shift a later boundary into a different field tuple that
        // serializes identically.
        let one = bytes_with(
            "mesh:1",
            EndpointRole::Initiator,
            "device-a",
            "device-b",
            "draw-a",
            "draw-b",
            "fp-of-a",
            "fp-of-b",
        );
        let other = bytes_with(
            "mesh",
            EndpointRole::Initiator,
            "device-a",
            "device-b",
            "draw-a",
            "draw-b",
            "fp-of-a",
            "fp-of-b",
        );
        assert_ne!(one, other);
    }

    #[test]
    fn v4_arc04_role_is_derived_from_the_pair_not_chosen() {
        // Ordering comes from the Device pair, so neither endpoint can pick the
        // role that makes a signature verify.
        assert_eq!(role_of("device-a", "device-b"), EndpointRole::Initiator);
        assert_eq!(role_of("device-b", "device-a"), EndpointRole::Responder);
    }

    #[test]
    fn v4_arc04b_context_transcript_matches_the_shared_framing() {
        // The context adapter must produce exactly the bytes the existing
        // framing produces for the same facts; if it ever diverges, the two
        // endpoints stop agreeing.
        let context = context("device-a", "device-b");
        let direct = transcript_bytes(
            "mesh-1",
            EndpointAuthProfile::V1Ed25519Dtls,
            EndpointRole::Initiator,
            "device-a",
            "device-b",
            "local-contribution",
            "peer-contribution",
            "fp-of-a",
            "fp-of-b",
        );

        assert_eq!(
            transcript_for_context(
                &context,
                EndpointRole::Initiator,
                "local-contribution",
                "peer-contribution",
            ),
            direct
        );
    }

    #[test]
    fn v4_arc04b_both_endpoints_derive_identical_context_transcripts() {
        let initiator = context("device-a", "device-b");
        // The responder's own view swaps local and remote on every paired
        // field, including its binding components.
        let responder = EndpointAuthContext::new(
            "mesh-1",
            "device-b",
            "device-a",
            EndpointAuthBinding::webrtc_certificate_fingerprints("fp-of-b", "fp-of-a")
                .expect("both components present"),
        )
        .expect("non-empty identifiers");

        assert_eq!(
            transcript_for_context(&initiator, EndpointRole::Initiator, "draw-a", "draw-b"),
            transcript_for_context(&responder, EndpointRole::Initiator, "draw-b", "draw-a"),
        );
    }
}
