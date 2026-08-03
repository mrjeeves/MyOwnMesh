//! Explicit runtime authority for frozen pre-V4 application routing compatibility.
//!
//! This profile does not belong to the V4 connector, Endpoint Auth, or
//! session-capability path. It exists only so downstream applications can
//! retain the historical routing and relay behavior while they migrate. New
//! code must enable the `legacy-v1` feature and pass this runtime at the
//! construction boundary.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LegacyV1Marker {
    _sealed: (),
}

/// Explicit opt-in runtime for the frozen LegacyV1 routing and relay behavior.
///
/// This type exists only when the `legacy-v1` feature is enabled. Possessing it
/// lets a compatibility owner reach the private marker consumed by legacy
/// routing code. No V4 connector or session capability can create that marker.
#[derive(Clone, Debug)]
pub struct LegacyV1Runtime {
    marker: LegacyV1Marker,
}

impl LegacyV1Runtime {
    /// Construct the one frozen compatibility runtime.
    #[deprecated(
        since = "0.3.2",
        note = "LegacyV1 application routing is frozen and scheduled for removal after downstream migration"
    )]
    pub const fn frozen() -> Self {
        Self {
            marker: LegacyV1Marker { _sealed: () },
        }
    }

    pub(crate) const fn marker(&self) -> LegacyV1Marker {
        self.marker
    }
}
