//! Private provenance for an authenticated channel.
//!
//! Session Broker must be able to read what was actually authenticated without
//! reconstructing it from parallel mutable engine state, and without a caller
//! being able to supply a replacement. That is what this record is: an exact,
//! immutable, non-serializable statement of the facts one completed exchange
//! proved, derived from the task's own context and proof state rather than
//! assembled from a bag of caller-supplied fields.

use super::context::EndpointAuthContext;
use super::EndpointRole;
use crate::connector::{ConnectedChannelHandoff, ConnectorIncarnation};
use crate::runtime::RuntimeIncarnation;
use std::sync::Arc;

/// One completed authentication, recorded exactly.
///
/// Crate-private, no public constructor, no `Clone`, no serialization: there is
/// deliberately no session handle to hand out. Readback is by narrow accessor
/// only, so a consumer reads what was proved and cannot substitute anything.
///
/// Every field here is one a substituted record could differ in, so every field
/// here is compared by [`super::EndpointAuthTask::issued`]. The profile and the
/// binding pair are deliberately *not* among them: both are already inside the
/// bytes `transcript_digest` covers — [`super::transcript::transcript_bytes`]
/// commits the profile tag and reorders the endpoint-relative components into
/// role-canonical position — so a second copy here would be a second thing that
/// can disagree with the proof rather than another thing that must match it.
pub(crate) struct AuthenticatedBindingRecord {
    mesh_context: String,
    local_device_id: String,
    remote_device_id: String,
    /// The exact role this endpoint proved under. Compared by
    /// [`super::EndpointAuthTask::issued`], so a record proved under the peer's
    /// role cannot be installed through this task.
    local_role: EndpointRole,
    /// Digest of the exact transcript both halves verified over.
    transcript_digest: String,
    connector: Arc<ConnectorIncarnation>,
    runtime: RuntimeIncarnation,
}

impl AuthenticatedBindingRecord {
    /// Derive the record from the task's own immutable state.
    ///
    /// Every field comes from the context the task fixed at construction or
    /// from the transcript it actually verified. Nothing here is caller
    /// supplied, which is the property that lets a later consumer trust it.
    pub(crate) fn from_verified_exchange(
        context: &EndpointAuthContext,
        transcript: &[u8],
        connector: Arc<ConnectorIncarnation>,
        runtime: RuntimeIncarnation,
    ) -> Self {
        Self {
            mesh_context: context.mesh_context().to_owned(),
            local_device_id: context.local_device_id().to_owned(),
            remote_device_id: context.expected_remote_device_id().to_owned(),
            local_role: context.local_role(),
            transcript_digest: digest_of(&[transcript]),
            connector,
            runtime,
        }
    }

    pub(crate) fn mesh_context(&self) -> &str {
        &self.mesh_context
    }

    pub(crate) fn local_device_id(&self) -> &str {
        &self.local_device_id
    }

    pub(crate) fn remote_device_id(&self) -> &str {
        &self.remote_device_id
    }

    pub(crate) fn local_role(&self) -> EndpointRole {
        self.local_role
    }

    pub(crate) fn transcript_digest(&self) -> &str {
        &self.transcript_digest
    }

    pub(crate) fn connector(&self) -> &Arc<ConnectorIncarnation> {
        &self.connector
    }

    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        &self.runtime
    }

    /// Whether this record is the one for that exact mesh and remote Device.
    ///
    /// The cross-context install controls use this: a capability from one
    /// context answers `false` for another even when a caller supplies the
    /// current task alongside it.
    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        // Through the accessors, so there is exactly one reader per field and a
        // future change to how either is stored cannot leave this comparison
        // reading a stale representation.
        self.mesh_context() == mesh_context && self.remote_device_id() == remote_device_id
    }
}

/// Local proof that both Device identities were freshly authenticated on one
/// exact connected channel.
///
/// Issued only by [`super::EndpointAuthTask`], from a verified exchange. It has
/// no public constructor, so a connected channel cannot become an authenticated
/// one by any other route.
///
/// It privately retains the exact authenticated binding record, so a later
/// consumer reads what was actually proved instead of reconstructing it from
/// parallel mutable state — and cannot substitute anything, because there is no
/// setter and no serializable handle.
///
/// A connected channel has no implicit conversion into authentication:
///
/// ```compile_fail,E0308
/// use myownmesh_core::connector::ConnectedChannelCapability;
/// use myownmesh_core::endpoint_auth::AuthenticatedChannelCapability;
///
/// fn connected() -> ConnectedChannelCapability { unimplemented!() }
/// fn requires_authentication(_: AuthenticatedChannelCapability) {}
///
/// requires_authentication(connected());
/// ```
pub struct AuthenticatedChannelCapability {
    record: AuthenticatedBindingRecord,
    /// The whole handoff, not the bare capability: its `Drop` is what returns
    /// the connected claim to connector retention, so a capability dropped on
    /// retirement or a refused install cannot release the claim early.
    handoff: ConnectedChannelHandoff,
}

impl AuthenticatedChannelCapability {
    /// The one construction path: a verified exchange, nothing else.
    ///
    /// The record and the handoff arrive together from the task that proved
    /// them, so no caller can pair a record with a different channel.
    pub(crate) fn from_verified_exchange(
        record: AuthenticatedBindingRecord,
        handoff: ConnectedChannelHandoff,
    ) -> Self {
        Self { record, handoff }
    }

    /// The runtime this capability is bound to.
    ///
    /// Read straight off the proved record. There is no separate permit token:
    /// one would only re-state the runtime the record already carries, and a
    /// second copy is a second thing that can disagree with the proof.
    pub(crate) fn runtime(&self) -> &RuntimeIncarnation {
        self.record.runtime()
    }

    /// Whether this capability was promoted from that exact connector
    /// incarnation.
    ///
    /// Install must check this, not merely that the *task* it was handed is
    /// current. Checking the task alone would accept a capability promoted from
    /// a superseded channel as long as the caller passed the current task
    /// alongside it — precisely the cross-channel relay the non-session-unique
    /// binding cannot rule out on its own.
    pub(crate) fn belongs_to(&self, incarnation: &Arc<ConnectorIncarnation>) -> bool {
        self.handoff.belongs_to(incarnation)
    }

    /// The private authenticated binding record.
    ///
    /// Crate-private readback: a consumer reads the proved facts, and there is
    /// no path to replace them.
    pub(crate) fn record(&self) -> &AuthenticatedBindingRecord {
        &self.record
    }

    /// Whether this capability authenticates that exact mesh and remote Device.
    ///
    /// Install rechecks this even when the caller supplies the current task, so
    /// a capability from one context cannot be installed into another.
    pub(crate) fn authenticated_for(&self, mesh_context: &str, remote_device_id: &str) -> bool {
        self.record
            .authenticated_for(mesh_context, remote_device_id)
    }
}

/// Length-prefixed digest input, so two different field tuples cannot produce
/// the same digest.
fn digest_of(fields: &[&[u8]]) -> String {
    use sha2::{Digest, Sha256};

    let mut hasher = Sha256::new();
    for field in fields {
        hasher.update(field.len().to_string().as_bytes());
        hasher.update(b":");
        hasher.update(field);
    }
    data_encoding::BASE32_NOPAD
        .encode(&hasher.finalize())
        .to_lowercase()
}

/// One genuine capability over a fixture channel.
///
/// Test-only. It builds a real record from a real context and a real handoff,
/// so a control that consumes it exercises the same type production issues —
/// what it skips is the exchange that would have proved it, which is covered
/// by the task controls instead.
#[cfg(test)]
pub(crate) fn authenticated_for_test(
    runtime: RuntimeIncarnation,
) -> AuthenticatedChannelCapability {
    authenticated_over_for_test(
        crate::connector::handoff_for_test(runtime),
        "fixture-mesh",
        "fixture-device-local",
        "fixture-device-remote",
    )
}

/// One genuine capability over **that exact connector's** handoff, in **that
/// exact context**.
///
/// The same construction as [`authenticated_for_test`], with every identity
/// taken from the caller's real values instead of fixture constants: the
/// connector incarnation and the retention obligation come from the supplied
/// handoff, and the runtime is read off the connected capability that handoff
/// carries. A capability built here therefore satisfies `belongs_to` against
/// the connector that produced it, `authenticated_for` against the mesh and
/// remote Device named here, and the broker's runtime conjunct — because each
/// is the real value rather than a stand-in that would have to be excused.
///
/// This exists so a control can reach a *genuinely promoted* session. Promotion
/// is not bypassed by it: `SessionBroker::promote` still evaluates every
/// conjunct against this capability and still refuses one that does not match
/// the connector, policy, runtime, or available session capacity. What is
/// skipped is only the proof exchange, exactly as for the fixture form above,
/// and the task controls cover that separately.
///
/// The stand-in transcript is derived from the mesh and the remote Device id so
/// that two peers in one control do not share a transcript digest — a shared
/// digest would let a cross-peer confusion pass unnoticed. The binding
/// components are likewise derived per Device, which is what a real exchange's
/// transcript would commit.
///
/// Reachable under `transport-lab` without this crate's `cfg(test)` because the
/// promoted-peer fixture another crate's controls construct promotes through
/// exactly this path.
#[cfg(any(test, feature = "transport-lab"))]
pub(crate) fn authenticated_over_for_test(
    handoff: ConnectedChannelHandoff,
    mesh_context: &str,
    local_device_id: &str,
    remote_device_id: &str,
) -> AuthenticatedChannelCapability {
    let binding = crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
        &format!("fp-local-{local_device_id}"),
        &format!("fp-remote-{remote_device_id}"),
    )
    .expect("both binding components present");
    let context =
        EndpointAuthContext::new(mesh_context, local_device_id, remote_device_id, binding)
            .expect("non-empty identifiers");
    let channel_runtime = handoff
        .capability()
        .expect("a fresh handoff holds its capability")
        .runtime()
        .clone();
    let record = AuthenticatedBindingRecord::from_verified_exchange(
        &context,
        format!("transcript-{mesh_context}-{remote_device_id}").as_bytes(),
        Arc::clone(handoff.incarnation()),
        channel_runtime,
    );
    AuthenticatedChannelCapability::from_verified_exchange(record, handoff)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc02_authenticated_channel_preserves_runtime_binding() {
        // The capability answers with the runtime of the channel it was
        // promoted from, read from its own record rather than from a caller.
        let runtime = crate::runtime::runtime_for_test();
        let capability = authenticated_for_test(runtime.clone());

        assert!(capability.runtime().is_same(&runtime));
        assert!(capability.record().runtime().is_same(&runtime));
    }

    #[test]
    fn v4_arc04_capability_context_and_runtime_are_exact_and_not_caller_supplied() {
        // Replacement for the old unreachable `RuntimeMismatch` control. The
        // record answers for exactly one mesh and one remote Device, read from
        // itself rather than from the caller asking.
        //
        // The last two assertions are about *channel* identity, not about the
        // proof: two capabilities built over different fixture channels carry
        // the same context and therefore the same transcript, and what
        // distinguishes them is the runtime and the connector incarnation each
        // was minted against. Those are the two the install-side comparison
        // rests on — a capability from another channel answers `false` to
        // `belongs_to` even when its context matches exactly.
        let first = authenticated_for_test(crate::runtime::runtime_for_test());
        let second = authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(first.authenticated_for("fixture-mesh", "fixture-device-remote"));
        assert!(!first.authenticated_for("other-mesh", "fixture-device-remote"));
        assert!(!first.authenticated_for("fixture-mesh", "other-device"));
        assert!(!first.record().runtime().is_same(second.record().runtime()));
        assert!(!first.belongs_to(second.record().connector()));
    }

    #[test]
    fn v4_arc04b_record_carries_the_role_it_proved_under() {
        // The retained role is recorded from the context the exchange ran
        // under, not defaulted and not caller-supplied — which is what lets
        // `EndpointAuthTask::issued` compare it on install. Deleting the field
        // or its derivation in `from_verified_exchange` breaks this control.
        //
        // Role is a conjunct that discriminates today, which is why it is the
        // one retained here: the pair below derives opposite roles from the
        // same fixture, so the negative is real rather than deferred to a
        // future enum variant. The profile and the binding pair are not
        // retained alongside it — the transcript already commits both, and
        // `transcript_digest` is what `issued` compares them through.
        let binding = crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
            "role-local-fp",
            "role-remote-fp",
        )
        .expect("both fixture components present");
        let context = EndpointAuthContext::new(
            "fixture-mesh",
            "fixture-device-local",
            "fixture-device-remote",
            binding,
        )
        .expect("non-empty fixture identifiers");
        let handoff = crate::connector::handoff_for_test(crate::runtime::runtime_for_test());
        let channel_runtime = handoff
            .capability()
            .expect("fixture handoff holds its capability")
            .runtime()
            .clone();
        let record = AuthenticatedBindingRecord::from_verified_exchange(
            &context,
            b"fixture-transcript",
            Arc::clone(handoff.incarnation()),
            channel_runtime,
        );

        assert_eq!(
            record.local_role(),
            context.local_role(),
            "the record must carry the exact role this endpoint proved under"
        );

        // The same fixture with the Device pair reversed derives the opposite
        // role, so a record built under one role does not match a context built
        // under the other.
        let mirrored = EndpointAuthContext::new(
            "fixture-mesh",
            "fixture-device-remote",
            "fixture-device-local",
            crate::connector::EndpointAuthBinding::webrtc_certificate_fingerprints(
                "role-remote-fp",
                "role-local-fp",
            )
            .expect("both fixture components present"),
        )
        .expect("non-empty fixture identifiers");
        assert_ne!(
            record.local_role(),
            mirrored.local_role(),
            "non-vacuity: the two endpoints of one attempt hold different roles, so the role comparison in `issued` can fail"
        );
    }
}
