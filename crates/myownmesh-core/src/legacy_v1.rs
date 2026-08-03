//! Explicit authority for frozen pre-V4 application routing compatibility.
//!
//! This profile does not belong to the V4 connector, Endpoint Auth, or
//! session-capability path. It exists only so downstream applications can
//! retain the historical routing and relay behavior while they migrate. New
//! code must opt in at the construction boundary.

/// Explicit opt-in to the frozen LegacyV1 routing and relay behavior.
///
/// The profile has one fixed value and no conversion from any V4 capability.
/// It does not authorize a V4 connector or authenticated session to relay
/// application data through MyOwnMesh.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LegacyV1CompatibilityProfile {
    _sealed: (),
}

impl LegacyV1CompatibilityProfile {
    /// Select the frozen compatibility behavior without adding policy knobs.
    pub const fn frozen() -> Self {
        Self { _sealed: () }
    }
}
