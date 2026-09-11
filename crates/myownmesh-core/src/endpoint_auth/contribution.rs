//! Per-attempt contributions: one local draw, one accepted peer value.
//!
//! Moved here unchanged in behaviour from the combined module. Freshness is the
//! primary anti-replay mechanism for this profile, because the channel binding
//! is not session-unique, so the construction rules are invariants rather than
//! conventions: a local contribution can only come from the CSPRNG, and a peer
//! contribution is decoded rather than measured.

use super::EndpointAuthSetupError;

/// A 32-byte draw encoded as lowercase BASE32 without padding.
pub(crate) const CONTRIBUTION_BYTES: usize = 32;

/// This endpoint's own per-attempt contribution.
///
/// Constructible **only** from a fresh CSPRNG draw. Deliberately not `Clone`: a
/// clone would let any crate code copy a stale value into a second attempt,
/// which is exactly the reuse the construction rule exists to prevent.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct LocalContribution(String);

impl LocalContribution {
    /// Draw one fresh contribution from the OS CSPRNG.
    pub(crate) fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; CONTRIBUTION_BYTES];
        rand::rngs::OsRng.fill_bytes(&mut bytes);
        Self(data_encoding::BASE32_NOPAD.encode(&bytes).to_lowercase())
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    /// Rebuild an exact prior contribution. **Controls only.**
    ///
    /// Compiled out of production entirely. The construction rule above is
    /// unchanged: outside `cfg(test)` `generate` remains the only constructor
    /// and this type stays non-`Clone`, so no production path can carry a stale
    /// value into a second attempt.
    ///
    /// This exists because one control has to build the exact case the rule
    /// prevents — two channels between one Device pair reusing the same
    /// certificates *and* the same contribution pair — in order to show what
    /// still holds there. Without it that control silently degenerates into an
    /// ordinary freshness check and stops proving anything about ownership.
    #[cfg(test)]
    pub(crate) fn reuse_for_test(value: &str) -> Self {
        Self(value.to_owned())
    }
}

/// The peer's per-attempt contribution, as received on the wire.
///
/// Decoded, not measured: a character count would accept any long-enough
/// string, which is a width check masquerading as a full-width contribution
/// guard. The round-trip comparison is what makes the encoding canonical rather
/// than merely decodable, so one draw has exactly one accepted wire form.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PeerContribution(String);

impl PeerContribution {
    /// Accept exactly the canonical lowercase BASE32-nopad encoding of
    /// [`CONTRIBUTION_BYTES`] bytes.
    ///
    /// Refuses with an [`EndpointAuthSetupError`], which is a statement about
    /// the value and nothing else. This is a parser: it holds no task, cannot
    /// reach the exchange lock, and terminalizes nothing, so it must not be
    /// able to hand back a cause that says an attempt is over. The caller that
    /// refuses here still fails closed on its own state — the production
    /// inbound path drops the exact current peer — but that is the caller's
    /// act, not this function's claim.
    pub(crate) fn from_wire(value: &str) -> Result<Self, EndpointAuthSetupError> {
        if value.is_empty() {
            return Err(EndpointAuthSetupError::MissingContribution);
        }
        let decoded = data_encoding::BASE32_NOPAD
            .decode(value.to_ascii_uppercase().as_bytes())
            .map_err(|_| EndpointAuthSetupError::ContributionMalformed)?;
        if decoded.len() != CONTRIBUTION_BYTES {
            return Err(EndpointAuthSetupError::ContributionWrongWidth);
        }
        if data_encoding::BASE32_NOPAD.encode(&decoded).to_lowercase() != value {
            return Err(EndpointAuthSetupError::ContributionMalformed);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_arc04_local_contribution_is_fresh_per_draw() {
        // Freshness is the primary anti-replay mechanism for this profile,
        // because the channel binding is not session-unique. Two draws must
        // therefore differ, and each must be a full-width canonical value.
        let first = LocalContribution::generate();
        let second = LocalContribution::generate();

        assert_ne!(first, second);
        for drawn in [&first, &second] {
            PeerContribution::from_wire(drawn.as_str())
                .expect("a local draw is canonical on the wire");
        }
    }

    #[test]
    fn v4_arc04_peer_contribution_rejects_short_and_noncanonical_wire_values() {
        let drawn = LocalContribution::generate();
        let canonical = drawn.as_str();

        assert_eq!(
            PeerContribution::from_wire(""),
            Err(EndpointAuthSetupError::MissingContribution)
        );
        // A short value cannot carry a full-width draw, and accepting one would
        // silently shrink the freshness the transcript rests on.
        //
        // Built by encoding a deterministic all-zero buffer one byte short,
        // rather than by truncating the random draw above. Truncation was
        // flaky: lopping characters off an arbitrary encoding usually leaves
        // nonzero trailing bits, which `decode` rejects first, so the value
        // came back `ContributionMalformed` on some draws and
        // `ContributionWrongWidth` on others. Zero bytes encode to zero trailing
        // bits, so this decodes cleanly and fails on width alone — every run.
        let short = data_encoding::BASE32_NOPAD
            .encode(&[0u8; CONTRIBUTION_BYTES - 1])
            .to_lowercase();
        assert_eq!(
            PeerContribution::from_wire(&short),
            Err(EndpointAuthSetupError::ContributionWrongWidth)
        );
        // And the other side of the same predicate. The guard is an equality
        // against the full draw width, not a minimum, so an over-wide value is
        // refused on the same footing — and with the same cause, which is why
        // that cause is named for the width rather than for the short side of
        // it. Built from zero bytes for the same reason as the short leg: the
        // encoding decodes cleanly, so it fails on width alone rather than on
        // trailing bits.
        let over_wide = data_encoding::BASE32_NOPAD
            .encode(&[0u8; CONTRIBUTION_BYTES + 1])
            .to_lowercase();
        assert_eq!(
            PeerContribution::from_wire(&over_wide),
            Err(EndpointAuthSetupError::ContributionWrongWidth)
        );
        // The companion case at full width: 32 zero bytes encode to 52
        // characters, so length is not what rejects this one. Altering the
        // final character sets a trailing bit that the canonical encoding of
        // any 32-byte value leaves clear, so the value is rejected as
        // malformed rather than accepted as a full-width draw — the guard is a
        // decode, not a character count.
        let mut full_width = data_encoding::BASE32_NOPAD
            .encode(&[0u8; CONTRIBUTION_BYTES])
            .to_lowercase();
        assert_eq!(full_width.len(), 52, "non-vacuity: full encoded width");
        assert!(full_width.ends_with('a'));
        full_width.pop();
        full_width.push('b');
        assert_eq!(
            PeerContribution::from_wire(&full_width),
            Err(EndpointAuthSetupError::ContributionMalformed)
        );
        // Uppercase decodes to the same bytes but is not the canonical
        // spelling: one draw has exactly one accepted wire form.
        assert_eq!(
            PeerContribution::from_wire(&canonical.to_ascii_uppercase()),
            Err(EndpointAuthSetupError::ContributionMalformed)
        );
        assert_eq!(
            PeerContribution::from_wire("not-base32!"),
            Err(EndpointAuthSetupError::ContributionMalformed)
        );
        assert!(PeerContribution::from_wire(canonical).is_ok());
    }

    #[test]
    fn v4_arc04h_every_wire_refusal_is_a_setup_cause_at_this_one_boundary() {
        // The census for this parser's half of the setup type. The `match` is
        // what makes it one: a variant added to `EndpointAuthSetupError` fails
        // to compile here until it is either driven from a wire value below or
        // stated as belonging to another boundary. Without it a new input cause
        // could be introduced with no control ever producing it, and the claim
        // that every refusal here is a *setup* refusal would rest on reading
        // the source rather than on the compiler.
        fn boundary_of(error: EndpointAuthSetupError) -> &'static str {
            match error {
                EndpointAuthSetupError::MissingContribution
                | EndpointAuthSetupError::ContributionWrongWidth
                | EndpointAuthSetupError::ContributionMalformed => "PeerContribution::from_wire",
                EndpointAuthSetupError::MissingIdentityField => "EndpointAuthContext::new",
                EndpointAuthSetupError::IncompatibleProfile => "negotiate_profile",
            }
        }

        let short = data_encoding::BASE32_NOPAD
            .encode(&[0u8; CONTRIBUTION_BYTES - 1])
            .to_lowercase();
        let over_wide = data_encoding::BASE32_NOPAD
            .encode(&[0u8; CONTRIBUTION_BYTES + 1])
            .to_lowercase();
        // Every value this parser can refuse, and the cause each one carries.
        // Driven rather than asserted about, so a cause that no wire value can
        // actually produce cannot pass this control. Both sides of the width
        // predicate are driven, because one cause covers both.
        for (value, expected) in [
            ("", EndpointAuthSetupError::MissingContribution),
            (
                short.as_str(),
                EndpointAuthSetupError::ContributionWrongWidth,
            ),
            (
                over_wide.as_str(),
                EndpointAuthSetupError::ContributionWrongWidth,
            ),
            ("not-base32!", EndpointAuthSetupError::ContributionMalformed),
        ] {
            assert_eq!(PeerContribution::from_wire(value), Err(expected));
            assert_eq!(
                boundary_of(expected),
                "PeerContribution::from_wire",
                "a wire value is refused at the parser, and the cause says so"
            );
        }
        // Non-vacuity: the two causes this boundary does *not* own are owned
        // elsewhere, so the mapping above discriminates rather than answering
        // the same way for everything.
        assert_ne!(
            boundary_of(EndpointAuthSetupError::MissingIdentityField),
            "PeerContribution::from_wire"
        );
        assert_ne!(
            boundary_of(EndpointAuthSetupError::IncompatibleProfile),
            "PeerContribution::from_wire"
        );
    }
}
