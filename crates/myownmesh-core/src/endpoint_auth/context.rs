//! Immutable construction context for one endpoint-authentication task.
//!
//! Everything a task authenticates *against* is fixed here, once, before any
//! contribution is drawn or any proof is built. Nothing in this type changes
//! for the life of the task, so a later caller cannot substitute a mesh, a
//! Device identity, a profile, or a channel binding after the fact.
//!
//! The context also owns the one place the role is decided: it is derived from
//! the exact Device pair, never supplied. Canonical ordering of the connector's
//! endpoint-relative binding components follows from that role and is applied
//! once, in [`super::transcript::transcript_bytes`], where the bytes are
//! actually framed. A transport therefore cannot choose roles, and no caller
//! can pick whichever ordering makes a signature verify.

use super::{EndpointAuthProfile, EndpointAuthSetupError, EndpointRole};
use crate::connector::EndpointAuthBinding;

/// The fixed facts one task authenticates under.
///
/// Crate-private, with no public constructor, no `Clone`, and no serialization:
/// a context is built once by the owner that knows these facts and then only
/// read.
pub(crate) struct EndpointAuthContext {
    mesh_context: String,
    local_device_id: String,
    expected_remote_device_id: String,
    profile: EndpointAuthProfile,
    binding: EndpointAuthBinding,
    local_role: EndpointRole,
}

impl EndpointAuthContext {
    /// Fix the context for one attempt.
    ///
    /// `mesh_context` is the canonical mesh identifier in the same form the
    /// durable layer signs under, not a display string. `binding` is the
    /// connector's own supplied material, already fail-closed on a missing
    /// component.
    ///
    /// The profile is **fixed here**, not supplied. A connector states what it
    /// can prove; endpoint authentication decides what that means, and what it
    /// decides is the one closed profile this build authenticates under. No
    /// caller — engine included — selects profile semantics, so a peer cannot
    /// cause a weaker variant to be chosen.
    ///
    /// Empty identifiers are refused here rather than deeper in transcript
    /// framing, so an attempt cannot exist with a field that would produce an
    /// ambiguous signed record.
    ///
    /// The refusal is an [`EndpointAuthSetupError`]. Construction runs *before*
    /// any task exists — there is no attempt yet for a failure here to be
    /// terminal for — so it must not hand back a cause that says one is over.
    /// The production caller fails closed on its own state instead, retiring
    /// the exact connector whose channel would have been authenticated.
    pub(crate) fn new(
        mesh_context: &str,
        local_device_id: &str,
        expected_remote_device_id: &str,
        binding: EndpointAuthBinding,
    ) -> Result<Self, EndpointAuthSetupError> {
        if mesh_context.is_empty()
            || local_device_id.is_empty()
            || expected_remote_device_id.is_empty()
        {
            return Err(EndpointAuthSetupError::MissingIdentityField);
        }
        // Derived from the pair, never supplied by a caller or a peer.
        let local_role = if local_device_id < expected_remote_device_id {
            EndpointRole::Initiator
        } else {
            EndpointRole::Responder
        };
        Ok(Self {
            mesh_context: mesh_context.to_owned(),
            local_device_id: local_device_id.to_owned(),
            expected_remote_device_id: expected_remote_device_id.to_owned(),
            profile: EndpointAuthProfile::V1Ed25519Dtls,
            binding,
            local_role,
        })
    }

    pub(crate) fn mesh_context(&self) -> &str {
        &self.mesh_context
    }

    pub(crate) fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    /// The one remote identity this task may ever authenticate.
    ///
    /// Named "expected" because it is fixed at construction: a proof that
    /// verifies under a different Device is not this task's proof.
    ///
    /// This is the canonical cryptographic Device ID — the raw public-key form
    /// peers exchange on the wire, with any display suffix already stripped by
    /// the caller — not the display string. The transcript and every signature
    /// check bind that canonical form, so a display spelling can never widen
    /// what a proof covers.
    pub(crate) fn expected_remote_device_id(&self) -> &str {
        &self.expected_remote_device_id
    }

    pub(crate) fn profile(&self) -> EndpointAuthProfile {
        self.profile
    }

    pub(crate) fn binding(&self) -> &EndpointAuthBinding {
        &self.binding
    }

    /// This endpoint's derived role.
    pub(crate) fn local_role(&self) -> EndpointRole {
        self.local_role
    }

    /// Whether this context is the one for that exact mesh and Device pair.
    ///
    /// The mismatch controls use this: a task built for one mesh or one remote
    /// Device answers `false` for any other, before any cryptographic work.
    pub(crate) fn matches(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.mesh_context == mesh_context && self.expected_remote_device_id == remote_device_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> EndpointAuthBinding {
        EndpointAuthBinding::webrtc_certificate_fingerprints("local-fp", "remote-fp")
            .expect("both components present")
    }

    fn context(local: &str, remote: &str) -> EndpointAuthContext {
        EndpointAuthContext::new("mesh-1", local, remote, binding()).expect("non-empty identifiers")
    }

    #[test]
    fn v4_arc04b_context_derives_role_from_the_device_pair() {
        let initiator = context("device-a", "device-b");
        let responder = context("device-b", "device-a");

        assert_eq!(initiator.local_role(), EndpointRole::Initiator);
        assert_eq!(responder.local_role(), EndpointRole::Responder);

        // The components stay endpoint-relative here. Canonical ordering is
        // applied once, inside `transcript::transcript_bytes`, which is where
        // it is controlled: a second ordering helper on this type would be a
        // parallel implementation of the same pure function that nothing signs.
        assert_eq!(initiator.binding().local_component(), "local-fp");
        assert_eq!(responder.binding().local_component(), "local-fp");
    }

    #[test]
    fn v4_arc04b_context_is_fixed_to_one_mesh_and_one_remote_device() {
        let context = context("device-a", "device-b");

        assert!(context.matches("mesh-1", "device-b"));
        assert!(!context.matches("mesh-2", "device-b"));
        assert!(!context.matches("mesh-1", "device-c"));
    }

    #[test]
    fn v4_arc04b_context_refuses_an_empty_identifier() {
        for (mesh, local, remote) in [
            ("", "device-a", "device-b"),
            ("mesh-1", "", "device-b"),
            ("mesh-1", "device-a", ""),
        ] {
            assert!(matches!(
                EndpointAuthContext::new(mesh, local, remote, binding()),
                Err(EndpointAuthSetupError::MissingIdentityField)
            ));
        }
        // Non-vacuity: the same constructor with every identifier present
        // succeeds on the same binding, so the refusals above are the empty
        // field and not a constructor that never yields a context.
        assert!(EndpointAuthContext::new("mesh-1", "device-a", "device-b", binding()).is_ok());
    }

    #[test]
    fn v4_arc04h_construction_refuses_an_input_and_claims_no_lifecycle() {
        // The setup half of the split, stated where the refusal happens.
        // Construction is the boundary that runs *before* an attempt exists,
        // so its `Err` cannot be a terminal cause: there is nothing yet for it
        // to be terminal for.
        //
        // Expressed as a mapping the compiler has to keep exhaustive: a variant
        // added to `EndpointAuthSetupError` fails to compile here until it is
        // placed at a named boundary. Each boundary is a distinct answer rather
        // than a shared "yes", so the mapping discriminates — a control that
        // said the same thing about every input would hold just as well if the
        // split were undone.
        fn boundary_of(error: EndpointAuthSetupError) -> &'static str {
            match error {
                // Fixed here, before `EndpointAuthTask::begin` is reachable.
                EndpointAuthSetupError::MissingIdentityField => "EndpointAuthContext::new",
                // Parsed on the inbound path, before the attempt is reached.
                EndpointAuthSetupError::MissingContribution
                | EndpointAuthSetupError::ContributionWrongWidth
                | EndpointAuthSetupError::ContributionMalformed => "PeerContribution::from_wire",
                // Read off the inbound Hello, before any proof work.
                EndpointAuthSetupError::IncompatibleProfile => "negotiate_profile",
            }
        }

        let refusal = EndpointAuthContext::new("", "device-a", "device-b", binding())
            .err()
            .expect("an empty mesh identifier is refused");

        assert_eq!(refusal, EndpointAuthSetupError::MissingIdentityField);
        assert_eq!(
            boundary_of(refusal),
            "EndpointAuthContext::new",
            "a construction refusal is owned by construction, and happens before \
             any attempt exists — so it terminalizes nothing"
        );
        // Every other setup cause belongs to a different boundary, and none of
        // the three boundaries holds a task. No cause in this set can therefore
        // be produced by a lifecycle transition, which is what keeps it
        // unmistakable for a terminal one.
        for (error, boundary) in [
            (
                EndpointAuthSetupError::MissingContribution,
                "PeerContribution::from_wire",
            ),
            (
                EndpointAuthSetupError::ContributionWrongWidth,
                "PeerContribution::from_wire",
            ),
            (
                EndpointAuthSetupError::ContributionMalformed,
                "PeerContribution::from_wire",
            ),
            (
                EndpointAuthSetupError::IncompatibleProfile,
                "negotiate_profile",
            ),
        ] {
            assert_eq!(boundary_of(error), boundary);
            assert_ne!(
                boundary_of(error),
                "EndpointAuthContext::new",
                "and construction does not absorb a cause another boundary owns"
            );
        }
    }
}
