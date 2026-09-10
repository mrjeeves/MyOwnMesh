//! The canonical typed promotion input derived from current policy.
//!
//! The promotion guard requires "Open or Closed policy currently allows the
//! peer". The live tree's answer to that question is
//! `PeerStateData::is_admitted()` — proven Device identity plus mutual approval.
//! This input is the one place that carries it for promotion purposes, so the
//! broker depends on a *proof value* rather than on a boolean it could re-derive
//! differently.
//!
//! Deliberately not a governance framework. It adds no policy, no Closed profile
//! selection, and no new authority: it carries the current answer, once, from the
//! fence that computed it to the promotion that consumes it. The typed answer
//! is consumed directly by the broker and cannot be stored, cloned, or
//! and cannot be presented a second time.

use crate::endpoint_auth::AuthenticatedChannelCapability;

/// The current policy answer for one exact peer, valid for one promotion.
///
/// Move-only and not `Clone`, `Copy`, `Debug`, `Default`, or serializable: an
/// admission answer that could be retained would be exactly the transient
/// boolean this replaces. It is constructed only by [`Self::from_admitted_peer`],
/// which the engine calls while holding the registry mutation lock, so the
/// answer cannot go stale between being computed and being consumed.
#[must_use = "a policy answer authorizes at most one promotion and must be consumed"]
pub(crate) struct CurrentPolicyAdmission {
    /// The exact mesh and remote Device the answer was computed for.
    ///
    /// Retained so the broker can check that the answer describes the channel it
    /// is promoting. Without it, a policy value computed for peer A could be
    /// presented alongside peer B's authenticated channel.
    mesh_context: String,
    remote_device_id: String,
    admitted: bool,
}

impl CurrentPolicyAdmission {
    /// Record the current policy answer for one exact peer.
    ///
    /// `pub(crate)` and taking the answer as an argument rather than computing
    /// it: the engine's registry fence is the only linearization point at which
    /// "currently admits" is true of an installation rather than of a device id,
    /// so the fence decides and this value carries.
    pub(crate) fn from_admitted_peer(
        mesh_context: &str,
        remote_device_id: &str,
        admitted: bool,
    ) -> Self {
        Self {
            mesh_context: mesh_context.to_owned(),
            remote_device_id: remote_device_id.to_owned(),
            admitted,
        }
    }

    /// Whether this answer admits that exact authenticated channel.
    ///
    /// Both conjuncts matter. A refused answer never admits, and an answer
    /// computed for a different mesh or a different remote Device never admits
    /// either — so a policy value cannot be paired with a channel it was not
    /// computed for.
    pub(crate) fn admits(&self, channel: &AuthenticatedChannelCapability) -> bool {
        self.admitted && channel.authenticated_for(&self.mesh_context, &self.remote_device_id)
    }

    #[cfg(test)]
    pub(crate) fn admitted_for_test() -> Self {
        Self::from_admitted_peer("fixture-mesh", "fixture-device-remote", true)
    }

    #[cfg(test)]
    pub(crate) fn refused_for_test() -> Self {
        Self::from_admitted_peer("fixture-mesh", "fixture-device-remote", false)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc05_a_refused_policy_answer_admits_nothing() {
        let channel =
            crate::endpoint_auth::authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(!CurrentPolicyAdmission::refused_for_test().admits(&channel));
        // Non-vacuity: the same channel is admitted by the positive answer, so
        // the refusal above is the `admitted` flag and not a mismatched fixture.
        assert!(CurrentPolicyAdmission::admitted_for_test().admits(&channel));
    }

    #[test]
    fn v4_arc05_a_policy_answer_cannot_be_presented_for_another_peer() {
        // An admitting answer computed for a different remote Device — and one
        // for a different mesh — must not admit this channel, even though the
        // answer itself says yes.
        let channel =
            crate::endpoint_auth::authenticated_for_test(crate::runtime::runtime_for_test());

        assert!(
            !CurrentPolicyAdmission::from_admitted_peer("fixture-mesh", "other-device", true)
                .admits(&channel)
        );
        assert!(!CurrentPolicyAdmission::from_admitted_peer(
            "other-mesh",
            "fixture-device-remote",
            true
        )
        .admits(&channel));
    }
}
