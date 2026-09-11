//! Endpoint-authentication capability boundary for V4.
//!
//! This module states the boundary and re-exports the narrow internal types.
//! The work is owned by purpose-owned modules rather than gathered here:
//!
//! - [`context`] fixes what one task authenticates under, and derives the
//!   endpoint-authentication profile from the connector's closed binding;
//! - [`contribution`] owns the local draw and the accepted peer value;
//! - [`transcript`] owns the one signed framing and its role-canonical order;
//! - [`task`] owns the exchange: one draw, one bound peer contribution, one
//!   cached proof, one verified peer proof, and a terminal state;
//! - [`capability`] owns the issued capability and its private provenance.
//!
//! Endpoint authentication is transport independent. It names the generic
//! connector types — the handoff, the incarnation, and the binding — and
//! imports no `transport::webrtc` type. A future exporter, QUIC, serial, or
//! storage profile supplies another closed binding without changing the task.
//!
//! The channel-binding terms in the currently accepted profile are DTLS
//! certificate fingerprints, which are not session-unique; replay separation is
//! carried by per-attempt CSPRNG contributions and by connector-incarnation
//! ownership. See `BOUNDARY.md`.

mod capability;
mod context;
mod contribution;
/// Live two-connector controls over the production `on_auth_response` handler,
/// and the real-link fixture they share.
///
/// Basal V4 behaviour, so it is gated on `transport-lab` alone — these are the
/// only controls that prove the production handler refuses a substituted
/// channel binding.
///
/// The gate is the feature alone rather than `all(test, …)` because the link
/// half is also what the crate's `transport-lab` promoted-peer fixture is built
/// from, and that fixture is constructed from another crate's tests, where this
/// crate's `cfg(test)` is not set. Everything only the in-crate controls use
/// stays behind `cfg(test)` inside the module.
#[cfg(feature = "transport-lab")]
pub(crate) mod native_link;
mod task;
mod transcript;

#[cfg(test)]
pub(crate) use capability::authenticated_for_test;
#[cfg(any(test, feature = "transport-lab"))]
pub(crate) use capability::authenticated_over_for_test;
pub use capability::AuthenticatedChannelCapability;
pub(crate) use context::EndpointAuthContext;
// The peer's canonical value is parsed on the production inbound path, so it
// stays a current re-export. The local draw is *not* exported for production
// use: generation belongs to `EndpointAuthTask`, which draws once per attempt
// and owns that value for its whole life, so the only crate-root callers are
// fixtures that need to mint a canonical value to feed a control. Gating it
// keeps that true — a production caller that started generating its own
// contribution outside the task would fail to resolve the name.
#[cfg(test)]
pub(crate) use contribution::LocalContribution;
pub(crate) use contribution::PeerContribution;
#[cfg(test)]
pub(crate) use task::{peer_proof_for_test, task_for_test, task_reusing_contribution_for_test};
pub(crate) use task::{
    AcceptedPeerHello, EndpointAuthTask, LocalIdentitySigner, PeerProofAcceptance,
};
// The signed framing is deliberately *not* re-exported. Rebuilding the exact
// bytes outside this module would mean restating the mesh, profile, Device pair
// and channel binding, which is the substitution the task exists to prevent. A
// control that needs the peer's half asks `peer_proof_for_test` for it instead,
// and gets bytes derived from the task's own context rather than from its own
// arguments.

/// Domain tag for every endpoint-authentication transcript.
///
/// Distinct from the legacy handshake tag, so a signature produced under one
/// can never verify under the other. Domain separation is what makes the hard
/// cutover safe: a peer speaking the old format fails to verify rather than
/// being offered a weaker format it could select.
pub(crate) const ENDPOINT_AUTH_DOMAIN_TAG: &str = "myownmesh-endpoint-auth-v1:";

/// Ordered endpoint roles for one exact authentication attempt.
///
/// The role is signed, so the two sides of one attempt produce different
/// transcripts. A responder cannot reflect the initiator's signature back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointRole {
    Initiator,
    Responder,
}

impl EndpointRole {
    fn tag(self) -> &'static str {
        match self {
            Self::Initiator => "initiator",
            Self::Responder => "responder",
        }
    }

    pub(crate) fn peer(self) -> Self {
        match self {
            Self::Initiator => Self::Responder,
            Self::Responder => Self::Initiator,
        }
    }
}

/// A **terminal** endpoint-authentication failure.
///
/// Returned only by the task's lifecycle transitions
/// ([`EndpointAuthTask::accept_peer_hello`], [`accept_peer_proof`]). An attempt
/// that returns one of these is terminalized: retired, owned by no connector,
/// and vouching for nothing.
///
/// Two things are therefore never spelled with this type. A benign duplicate is
/// a non-error outcome ([`AcceptedPeerHello::ExactDuplicate`],
/// [`PeerProofAcceptance::AlreadyPromoted`]), and an unusable *input* is an
/// [`EndpointAuthSetupError`], which terminalizes nothing. There is no
/// conversion in either direction: widening a setup refusal would let a parse
/// failure claim a transition it never made.
///
/// [`accept_peer_proof`]: EndpointAuthTask::accept_peer_proof
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthError {
    /// A peer proof arrived for an attempt that has bound nothing, so there is
    /// no transcript for it to be a proof *of*: this endpoint drew its half and
    /// no peer half exists.
    NoBoundTranscript,
    /// Local and remote Device IDs are equal, so no mutual proof exists.
    NotMutual,
    /// Both endpoints supplied the same contribution, so neither is fresh.
    ContributionNotFresh,
    /// The remote signature did not verify over the exact transcript.
    SignatureInvalid,
    /// The task's channel was replaced or retired, so no connected claim is
    /// left for this attempt to promote.
    ///
    /// A security condition, not housekeeping: the channel binding is not
    /// session-unique, so exact connector-incarnation ownership is what
    /// distinguishes two channels between the same pair, and refusing here is
    /// what defeats cross-channel relay. A second promotion of a live attempt is
    /// *not* filed here — that is the non-error
    /// [`PeerProofAcceptance::AlreadyPromoted`].
    ChannelNotCurrent,
    /// A second, different peer contribution arrived after this attempt was
    /// already bound to one. Terminal for this exact task.
    ///
    /// Distinct from [`Self::ChannelNotCurrent`]: nothing had gone stale, so
    /// this separates a live peer sending what it cannot send from this endpoint
    /// closing up. Retirement follows, but it is the consequence, not the cause.
    ConflictingPeerContribution,
}

/// A **pre-task** refusal: an input this endpoint declined to build anything
/// from. It makes no claim about any attempt's lifecycle.
///
/// Every variant here is refused at a boundary that runs *before* an
/// [`EndpointAuthTask`] exists, or *beside* one without touching it:
/// [`PeerContribution::from_wire`] parsing a wire value,
/// [`negotiate_profile`] reading what a peer advertised, and
/// [`EndpointAuthContext::new`] fixing the facts an attempt would
/// authenticate under. None of them holds a task, none can reach the exchange
/// lock, and none can terminalize anything — so an `Err` of this type says only
/// that the value it was handed was refused.
///
/// That separation is the whole point of the type. [`EndpointAuthError`] means
/// "this attempt is over"; a value that could also carry a parse failure would
/// leave a caller — and the compiler — unable to tell a dead task from an
/// unparseable string. The two senses are distinct types, so the mistake is not
/// expressible: a setup refusal cannot be recorded as a terminal cause, cannot
/// be returned from a transition, and cannot be compared against one.
///
/// A caller that refuses on one of these must still fail closed — the
/// production paths drop the exact current peer or retire the exact current
/// connector — but that closure is the caller's own act on its own state, not
/// something this value performed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthSetupError {
    /// An identifier an attempt would be fixed to was empty: the mesh, this
    /// endpoint's Device ID, or the expected remote Device ID.
    ///
    /// Refused where the field is first fixed, so no attempt can exist with a
    /// field that would produce an ambiguous signed record.
    MissingIdentityField,
    /// A peer contribution arrived empty, so it carries no draw at all.
    MissingContribution,
    /// A contribution decoded cleanly but not to exactly the full draw width.
    ///
    /// Named for the predicate rather than for one side of it: the check is
    /// `decoded.len() != CONTRIBUTION_BYTES`, so an over-wide value is refused
    /// on exactly the same footing as a short one. A short value cannot carry a
    /// full-width draw; an over-wide one is not the draw either, and accepting
    /// either would let the freshness the transcript rests on be set by the
    /// peer rather than by the profile.
    ContributionWrongWidth,
    /// A contribution was not in the canonical lowercase BASE32-nopad
    /// encoding: it failed to decode, or it decoded from a non-canonical
    /// spelling of the same bytes.
    ContributionMalformed,
    /// The peer did not advertise the one closed endpoint-authentication
    /// profile, so there is no agreed transcript to prove anything over.
    ///
    /// Refused *before* any proof work: no transcript is built, no signature
    /// is produced or verified, and no capability can be minted. There is no
    /// fallback and no second profile to select.
    ///
    /// A setup refusal rather than a terminal one, and deliberately so. The
    /// gate runs on the inbound Hello before the attempt is reached, so nothing
    /// has been terminalized when it fires; what closes the connection is the
    /// handler's own fail-closed drop of the exact current peer.
    IncompatibleProfile,
}

/// The closed set of endpoint-authentication crypto profiles.
///
/// A closed enum rather than a caller string: the profile is bound into the
/// transcript so a peer cannot negotiate one profile and prove another. The
/// value is fixed by this protocol and taken in [`context`], never supplied by
/// the engine or by a peer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum EndpointAuthProfile {
    /// Ed25519 device signatures over a DTLS-fingerprint-bound transcript.
    V1Ed25519Dtls,
}

/// Resolve the profile to prove under, from what the peer advertised.
///
/// Called before any transcript is built, so an unsupported peer costs no
/// signing or verification work. Returns the one closed profile or refuses;
/// there is deliberately no third outcome, because a "negotiation" that could
/// select a weaker profile is exactly what this must not become. Advertising
/// [`Feature::ENDPOINT_AUTH_V1`] is how a peer states it speaks the closed
/// profile, not how it chooses among alternatives.
///
/// The refusal is an [`EndpointAuthSetupError`], not a terminal one. This runs
/// on an inbound Hello before the attempt is reached, so nothing has been
/// terminalized when it fires and the value must not claim otherwise; the
/// handler's own drop of the exact current peer is what fails the connection
/// closed.
pub(crate) fn negotiate_profile(
    peer_features: &[String],
) -> Result<EndpointAuthProfile, EndpointAuthSetupError> {
    if crate::protocol::features::peer_supports(
        peer_features,
        crate::protocol::features::Feature::ENDPOINT_AUTH_V1,
    ) {
        Ok(EndpointAuthProfile::V1Ed25519Dtls)
    } else {
        Err(EndpointAuthSetupError::IncompatibleProfile)
    }
}

impl EndpointAuthProfile {
    fn tag(self) -> &'static str {
        match self {
            Self::V1Ed25519Dtls => "ed25519-dtls-v1",
        }
    }
}
