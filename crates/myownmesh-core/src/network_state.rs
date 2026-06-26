//! Closed-network governance: kinds, roles, signed transitions.
//!
//! This module owns the types and signing primitives that distinguish
//! an `open` network (any member can write to the roster) from a
//! `closed` one (role-based authority enforced by signature
//! verification on every transition). See
//! [`docs/NETWORK-TYPES.md`](../../../docs/NETWORK-TYPES.md) for the
//! design.
//!
//! The on-disk shape is per-network state under
//! `~/.myownmesh/mesh/states/{network_id}.json`. Transitions are
//! ed25519-signed under the `myownmesh-network-state-v1:` domain tag,
//! distinct from the per-peer handshake domain so a handshake
//! signature can't be replayed as a state-transition signature or
//! vice-versa.
//!
//! Authority is enforced *at the engine layer* on every inbound
//! `network_state_*` frame: a peer that receives a proposal whose
//! signer set doesn't satisfy the quorum table drops the frame
//! silently and surfaces a diag entry. The GUI's role-grant gates
//! are convenience, not security — the wire is the security
//! boundary.

use std::path::PathBuf;

use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Domain-separation tag prefixed to every signed state-transition
/// payload. Distinct from [`crate::SIGN_DOMAIN_TAG`] so a signature
/// from one protocol step (e.g. the per-peer handshake) cannot be
/// replayed at another (a network-state transition).
pub const SIGN_DOMAIN_TAG_STATE: &str = "myownmesh-network-state-v1:";

/// File-format schema version for the per-network state log.
pub const NETWORK_STATE_VERSION: u32 = 1;

// ---- kinds + roles --------------------------------------------------

/// Governance kind of a network. `Open` (default) has no role
/// enforcement; any current member can author roster edits. `Closed`
/// gates roster edits and kind transitions behind the signed authority
/// chain in [`NetworkState`].
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    #[default]
    Open,
    Closed,
}

/// Authority tier within a closed network. `Member` is the default
/// for every roster entry and the only role on an `open` network.
/// Ordering is intentional: `as u8` comparisons reflect the authority
/// hierarchy without a lookup table.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// No roster-edit authority. May *propose* additions to an
    /// owner/controller for co-signature.
    #[default]
    Member,
    /// Can add `member` peers to the roster. Cannot grant
    /// `controller` or `owner`.
    Controller,
    /// Can grant any role + approve network-kind transitions.
    /// Every owner grant needs unanimous owner consent.
    Owner,
}

impl Role {
    /// Numeric tier — strictly monotonic with authority. Used by
    /// quorum checks ("can `granter` grant `target`?").
    pub fn rank(self) -> u8 {
        match self {
            Role::Member => 1,
            Role::Controller => 2,
            Role::Owner => 3,
        }
    }

    /// True if a peer holding `self` has authority to grant `target`
    /// in a closed network. Members can grant nothing. Otherwise
    /// the rank must be ≥ the target rank.
    pub fn can_grant(self, target: Role) -> bool {
        if self == Role::Member {
            return false;
        }
        self.rank() >= target.rank()
    }
}

// ---- transitions ----------------------------------------------------

/// A single ratified change to a closed-network's governance state.
/// The signer set is captured alongside so a later reader can
/// re-verify the authority chain back to the founder.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Transition {
    /// Unix-seconds at which the proposer floated this transition.
    pub at: u64,
    pub variant: TransitionVariant,
    /// Pubkeys of every member whose ed25519 signature is in
    /// `signatures`, in the same order. Always non-empty for a
    /// ratified transition — at minimum, the proposer signed.
    pub signers: Vec<String>,
    /// Base32-lowercase ed25519 signatures over the canonical
    /// transition payload (see [`transition_payload`]). Position
    /// matches `signers`.
    pub signatures: Vec<String>,
}

/// The shape of a transition. Each variant is signed as a single
/// canonical byte string to keep the protocol parseable across
/// future field additions: new fields must be opted into by a new
/// variant rather than tacked onto an existing one.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum TransitionVariant {
    /// Change the network's governance kind.
    KindChange { to: NetworkKind },
    /// Grant or change a peer's role.
    RoleGrant { target: String, role: Role },
    /// Drop a peer's role tag back to `Member` (or remove from the
    /// closed-network's controlling set).
    RoleRevoke { target: String },
    /// Evict a peer from the closed network entirely: drop its role
    /// *and* remove it from the roster, so every member that ratifies
    /// this transition stops authorising it. Where [`Self::RoleRevoke`]
    /// only demotes (the peer stays a `Member`), an evict is the
    /// propagating removal — the lost/stolen-device kick. Authority
    /// mirrors revoke: over a member needs a controller/owner, over a
    /// controller needs an owner, over an owner needs unanimous owners.
    Evict { target: String },
    /// Spawn a new closed network derived from this one. Carried in
    /// the log of the *parent* network so members can discover the
    /// new network's existence via gossip.
    Split {
        new_network_id: String,
        members: Vec<String>,
    },
}

/// Canonical signed-payload bytes for a transition. The signer
/// computes these locally, signs them with their secret key, and
/// embeds the signature in [`Transition::signatures`]. Verifiers
/// reconstruct the same byte string and check every signature in
/// the set against its corresponding signer's pubkey.
///
/// The `network_id` binds the signature to a specific mesh —
/// otherwise a transition signed for network *A* could be replayed
/// against network *B* if both happened to use the same variant
/// shape.
pub fn transition_payload(network_id: &str, variant: &TransitionVariant) -> Vec<u8> {
    // Use a serde-deterministic representation. `serde_json` with
    // sorted keys would technically work but allocates intermediate
    // objects; for v1 we hand-format each variant into a compact
    // string. Each variant gets a distinct prefix so a future variant
    // can never alias an older one.
    let variant_str = match variant {
        TransitionVariant::KindChange { to } => format!(
            "kind_change|to={}",
            match to {
                NetworkKind::Open => "open",
                NetworkKind::Closed => "closed",
            }
        ),
        TransitionVariant::RoleGrant { target, role } => format!(
            "role_grant|target={}|role={}",
            target,
            match role {
                Role::Member => "member",
                Role::Controller => "controller",
                Role::Owner => "owner",
            }
        ),
        TransitionVariant::RoleRevoke { target } => {
            format!("role_revoke|target={target}")
        }
        TransitionVariant::Evict { target } => {
            format!("evict|target={target}")
        }
        TransitionVariant::Split {
            new_network_id,
            members,
        } => {
            // Members included in the signed payload so the signer
            // can't post-facto extend the new network's membership
            // without re-signing. Order-normalise so payload is
            // deterministic regardless of the input order.
            let mut sorted = members.clone();
            sorted.sort();
            let members_csv = sorted.join(",");
            format!("split|new_id={new_network_id}|members={members_csv}")
        }
    };
    format!("{SIGN_DOMAIN_TAG_STATE}{network_id}|{variant_str}").into_bytes()
}

// ---- proposals ------------------------------------------------------

/// In-flight transition awaiting signatures. Members surface these in
/// their Approvals tab; the engine collects acks until the quorum
/// table for the variant is satisfied (or a single deny invalidates
/// it).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Proposal {
    /// Random per-proposal id. Used to dedupe acks; the engine drops
    /// any ack referencing an unknown id.
    pub id: String,
    pub created_at: u64,
    /// Pubkey of the member who floated the proposal.
    pub proposer: String,
    pub variant: TransitionVariant,
    /// Pubkeys + signatures from members who've ack'd `sign`. Always
    /// includes the proposer (the proposer signs at issue time).
    pub signers: Vec<String>,
    pub signatures: Vec<String>,
    /// Pubkeys of members who've ack'd `deny`. Any non-empty entry
    /// invalidates the proposal.
    pub deniers: Vec<String>,
    /// True once the proposer has fired the split fallback for this
    /// proposal. Prevents firing twice.
    pub split_spawned: bool,
}

/// Per-network split derivation record. Surfaced in the parent
/// network's state log so members can discover (and optionally join)
/// the derived network.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SplitRecord {
    pub new_network_id: String,
    pub spawned_at: u64,
    pub spawned_by: String,
    pub members: Vec<String>,
}

// ---- top-level state ------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkState {
    /// Schema version. Mismatched versions are refused on load — a
    /// future revision bumps this rather than silently parsing the
    /// new shape into the old.
    pub version: u32,
    /// Wire-level network id this state log belongs to. Mismatch
    /// with the on-disk filename triggers a fresh state on load.
    pub network_id: String,
    pub kind: NetworkKind,
    /// Roles assigned to peers in this network. Empty for `open`
    /// networks — every peer is implicitly `Member`. For `closed`
    /// networks, presence in this map is what gives a peer their
    /// authority; absence defaults to `Member`.
    pub roles: std::collections::BTreeMap<String, Role>,
    /// Append-only signed log. Most recent last.
    pub transitions: Vec<Transition>,
    /// Pending proposals awaiting ratification.
    pub pending: Vec<Proposal>,
    /// Splits this network has spawned. Each entry was derived from
    /// a stuck close proposal here.
    pub splits: Vec<SplitRecord>,
}

impl Default for NetworkState {
    fn default() -> Self {
        Self::empty_for("")
    }
}

impl NetworkState {
    pub fn empty_for(network_id: &str) -> Self {
        Self {
            version: NETWORK_STATE_VERSION,
            network_id: network_id.to_string(),
            kind: NetworkKind::Open,
            roles: Default::default(),
            transitions: Vec::new(),
            pending: Vec::new(),
            splits: Vec::new(),
        }
    }

    /// Role for a peer in this network. Returns [`Role::Member`]
    /// when the peer is not in the `roles` map (the default for
    /// open networks and for un-promoted members on closed ones).
    pub fn role_of(&self, pubkey: &str) -> Role {
        self.roles.get(pubkey).copied().unwrap_or(Role::Member)
    }
}

// ---- split-id derivation -------------------------------------------

/// Deterministic derivation of a split's `network_id` from the
/// parent's id + the signer set. The hash binds the new network
/// to its founding cohort so the same close-with-the-same-signers
/// always produces the same network id (idempotent retries; no
/// silent shadow networks).
///
/// Format: `base32_lowercase(SHA-256("myownmesh-split-v1:" || parent_id || "|" || sorted_pubkeys.join("|")))`
/// — encoded with the RFC-4648 alphabet, no padding, lowercased.
pub fn derive_split_network_id(parent_id: &str, signers: &[String]) -> String {
    use sha2::{Digest, Sha256};
    let mut sorted: Vec<&str> = signers.iter().map(|s| s.as_str()).collect();
    sorted.sort_unstable();
    let mut hasher = Sha256::new();
    hasher.update(b"myownmesh-split-v1:");
    hasher.update(parent_id.as_bytes());
    hasher.update(b"|");
    hasher.update(sorted.join("|").as_bytes());
    let digest = hasher.finalize();
    data_encoding::BASE32_NOPAD.encode(&digest).to_lowercase()
}

// ---- signing primitives --------------------------------------------

/// Sign a transition with the given secret key. The returned string
/// is base32-lowercase ed25519, ready to drop into
/// [`Transition::signatures`].
///
/// Used by the engine when this device authors a transition (the
/// founder self-election on `open → closed`, role grants, role
/// revokes, splits) and by the control surface (`mesh_propose_*`)
/// which signs at proposal-issuance time.
#[allow(dead_code)] // wired in by engine + control protocol in subsequent commits
pub(crate) fn sign_transition(
    network_id: &str,
    variant: &TransitionVariant,
    key: &SigningKey,
) -> String {
    let payload = transition_payload(network_id, variant);
    crate::signing::sign_with(key, &payload)
}

/// Verify every signature in `transition.signatures` against the
/// corresponding signer in `transition.signers`. Returns Ok only
/// when every signature is valid for the canonical transition
/// payload under its signer's pubkey.
///
/// Does NOT check whether the signer set satisfies the quorum table
/// — that's the job of [`verify_quorum`], which needs the network's
/// state at the moment of the transition. Splitting the two keeps
/// the signature check pure: a transition can be cryptographically
/// valid (every signature verifies) but politically invalid (the
/// signer set is insufficient for the operation). The wire-layer
/// drops both.
pub fn verify_transition_signatures(network_id: &str, transition: &Transition) -> Result<()> {
    if transition.signers.len() != transition.signatures.len() {
        return Err(Error::Protocol(format!(
            "transition has {} signers but {} signatures",
            transition.signers.len(),
            transition.signatures.len()
        )));
    }
    if transition.signers.is_empty() {
        return Err(Error::Protocol("transition has no signers".to_string()));
    }
    let payload = transition_payload(network_id, &transition.variant);
    for (signer, sig) in transition.signers.iter().zip(&transition.signatures) {
        let ok = crate::signing::verify(signer, &payload, sig)?;
        if !ok {
            return Err(Error::SignatureInvalid);
        }
    }
    Ok(())
}

/// Check whether the signer set on `transition` satisfies the quorum
/// table for its variant *against the supplied `state_before`*
/// (the network state in effect just prior to this transition).
///
/// Quorum table:
///   - `KindChange { to: Closed }` — unanimous of current members.
///   - `KindChange { to: Open }` — unanimous of current owners.
///   - `RoleGrant { role: Owner }` — unanimous of current owners.
///   - `RoleGrant { role: Controller }` — ≥ 1 owner.
///   - `RoleGrant { role: Member }` — ≥ 1 controller or owner.
///   - `RoleRevoke` — same authority as the corresponding grant.
///   - `Split` — single signer (the proposer), who becomes
///     founder-owner of the derived network.
///
/// `state_before` reflects the *full* member set of the network at
/// this transition's `at`. For the genesis transition (founder
/// self-elects on `open → closed`) the state_before is the empty
/// open network — exactly one signer (the founder) is acceptable.
pub fn verify_quorum(
    state_before: &NetworkState,
    transition: &Transition,
    members: &[String],
) -> Result<()> {
    use std::collections::BTreeSet;

    let signers: BTreeSet<&str> = transition.signers.iter().map(|s| s.as_str()).collect();

    let owners: BTreeSet<&str> = state_before
        .roles
        .iter()
        .filter(|(_, r)| matches!(r, Role::Owner))
        .map(|(k, _)| k.as_str())
        .collect();
    let controllers_and_owners: BTreeSet<&str> = state_before
        .roles
        .iter()
        .filter(|(_, r)| matches!(r, Role::Controller | Role::Owner))
        .map(|(k, _)| k.as_str())
        .collect();

    match (&transition.variant, state_before.kind) {
        // Founder self-election: `open → closed` with no existing
        // members or with the founder as sole signer.
        (
            TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            NetworkKind::Open,
        ) => {
            if members.is_empty() {
                if signers.len() != 1 {
                    return Err(Error::Protocol(
                        "founder self-election needs exactly one signer".into(),
                    ));
                }
            } else {
                // Every existing member must sign.
                for m in members {
                    if !signers.contains(m.as_str()) {
                        return Err(Error::Protocol(format!(
                            "open → closed needs unanimous member consent; missing {}",
                            &m[..m.len().min(12)]
                        )));
                    }
                }
            }
        }
        (
            TransitionVariant::KindChange {
                to: NetworkKind::Open,
            },
            NetworkKind::Closed,
        ) => {
            if owners.is_empty() {
                return Err(Error::Protocol(
                    "closed → open requires owners; network has none".into(),
                ));
            }
            for o in &owners {
                if !signers.contains(o) {
                    return Err(Error::Protocol(format!(
                        "closed → open needs unanimous owner consent; missing {}",
                        &o[..o.len().min(12)]
                    )));
                }
            }
        }
        // Same-kind transitions don't make sense.
        (TransitionVariant::KindChange { .. }, _) => {
            return Err(Error::Protocol(
                "KindChange to the current kind is a no-op".into(),
            ));
        }

        (
            TransitionVariant::RoleGrant {
                role: Role::Owner, ..
            },
            NetworkKind::Closed,
        ) => {
            if owners.is_empty() {
                // First owner after a clean close lands via the
                // founder self-election above, not via a separate
                // grant. Reject here.
                return Err(Error::Protocol(
                    "grant owner needs at least one existing owner".into(),
                ));
            }
            for o in &owners {
                if !signers.contains(o) {
                    return Err(Error::Protocol(format!(
                        "grant owner needs unanimous owner consent; missing {}",
                        &o[..o.len().min(12)]
                    )));
                }
            }
        }
        (
            TransitionVariant::RoleGrant {
                role: Role::Controller,
                ..
            },
            NetworkKind::Closed,
        ) => {
            if !signers.iter().any(|s| owners.contains(s)) {
                return Err(Error::Protocol(
                    "grant controller needs ≥ 1 owner signature".into(),
                ));
            }
        }
        (
            TransitionVariant::RoleGrant {
                role: Role::Member, ..
            },
            NetworkKind::Closed,
        ) => {
            if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                return Err(Error::Protocol(
                    "grant member needs ≥ 1 controller or owner signature".into(),
                ));
            }
        }
        (TransitionVariant::RoleGrant { .. }, NetworkKind::Open) => {
            // Roles are cosmetic on open networks. Any member signs.
            // Engine accepts but doesn't enforce on open kind.
        }

        (TransitionVariant::RoleRevoke { target }, NetworkKind::Closed) => {
            let target_role = state_before.role_of(target);
            // Revocation requires authority over the *target's*
            // current role.
            match target_role {
                Role::Owner => {
                    for o in &owners {
                        if !signers.contains(o) {
                            return Err(Error::Protocol(format!(
                                "revoke owner needs unanimous owner consent; missing {}",
                                &o[..o.len().min(12)]
                            )));
                        }
                    }
                }
                Role::Controller => {
                    if !signers.iter().any(|s| owners.contains(s)) {
                        return Err(Error::Protocol(
                            "revoke controller needs ≥ 1 owner signature".into(),
                        ));
                    }
                }
                Role::Member => {
                    if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                        return Err(Error::Protocol(
                            "revoke member needs ≥ 1 controller or owner signature".into(),
                        ));
                    }
                }
            }
        }
        (TransitionVariant::RoleRevoke { .. }, NetworkKind::Open) => {
            // Cosmetic on open kind; any signer accepted.
        }

        (TransitionVariant::Evict { target }, NetworkKind::Closed) => {
            // Eviction authority is authority over the *target's* current
            // role — identical to revoke, since an evict subsumes a revoke
            // (it also strips roster membership).
            let target_role = state_before.role_of(target);
            match target_role {
                Role::Owner => {
                    for o in &owners {
                        if !signers.contains(o) {
                            return Err(Error::Protocol(format!(
                                "evict owner needs unanimous owner consent; missing {}",
                                &o[..o.len().min(12)]
                            )));
                        }
                    }
                }
                Role::Controller => {
                    if !signers.iter().any(|s| owners.contains(s)) {
                        return Err(Error::Protocol(
                            "evict controller needs ≥ 1 owner signature".into(),
                        ));
                    }
                }
                Role::Member => {
                    if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                        return Err(Error::Protocol(
                            "evict member needs ≥ 1 controller or owner signature".into(),
                        ));
                    }
                }
            }
        }
        (TransitionVariant::Evict { .. }, NetworkKind::Open) => {
            // An open network's roster is permissionless (gossip re-adds
            // anyone), so an evict can't stick — accept the signer set but
            // it has no lasting effect. Closed is the meaningful case.
        }

        (TransitionVariant::Split { .. }, _) => {
            if signers.len() != 1 {
                return Err(Error::Protocol(
                    "split must be signed by exactly one party (the would-be owner)".into(),
                ));
            }
        }
    }
    Ok(())
}

/// Apply a verified transition to a [`NetworkState`], producing the
/// state-after. Pure; never touches the filesystem.
///
/// Caller is responsible for invariants the apply step doesn't
/// re-check (signature verification, quorum). The state-machine
/// view is "given that the transition is ratified, here is the
/// new state."
pub fn apply_transition(mut state: NetworkState, t: &Transition) -> NetworkState {
    match &t.variant {
        TransitionVariant::KindChange { to } => {
            state.kind = *to;
            // Founder election on `open → closed`: the *proposer*
            // becomes founder-owner, regardless of how many
            // co-signers there are. The signer set's first entry
            // is the proposer by convention (the engine always
            // self-signs at issue time and appends co-signers
            // afterward). Co-signers consent to the close + to the
            // proposer's ownership; they don't acquire ownership
            // themselves.
            if matches!(to, NetworkKind::Closed) {
                if let Some(founder) = t.signers.first() {
                    state.roles.insert(founder.clone(), Role::Owner);
                }
            }
        }
        TransitionVariant::RoleGrant { target, role } => {
            state.roles.insert(target.clone(), *role);
        }
        TransitionVariant::RoleRevoke { target } => {
            state.roles.remove(target);
        }
        TransitionVariant::Evict { target } => {
            // Strip any role here; the roster projection (where the
            // device's authorisation actually lives) is removed by the
            // engine when it mirrors this ratified transition.
            state.roles.remove(target);
        }
        TransitionVariant::Split {
            new_network_id,
            members,
        } => {
            state.splits.push(SplitRecord {
                new_network_id: new_network_id.clone(),
                spawned_at: t.at,
                spawned_by: t.signers.first().cloned().unwrap_or_default(),
                members: members.clone(),
            });
        }
    }
    state.transitions.push(t.clone());
    state
}

/// Verify a whole signed transition log from genesis and return the state it
/// produces. Every transition must (a) carry valid signatures
/// ([`verify_transition_signatures`]) and (b) satisfy the quorum table
/// ([`verify_quorum`]) against the state it applies to — both *reconstructed
/// from the log itself*, so the authority chain is checked end-to-end with no
/// external trust. The member set each step is quorum-checked against is the
/// union of every pubkey seen so far as a signer or role target; for the
/// genesis founder election that set is empty (the single-signer self-election
/// the quorum table accepts), and it grows as the log does — exactly the set
/// the owners had in hand when they authored each later step.
///
/// This is what lets a node converge governance — most importantly *who the
/// owner is* — by pulling a peer's log and re-deriving the roles itself, rather
/// than trusting a gossiped role tag. A log that fails any check is rejected
/// whole (returns `Err`); the caller keeps its current state untouched.
///
/// Adoption policy (whether a verified log *replaces* the local one) is the
/// caller's: the engine only adopts a log that **extends** its own (shared
/// prefix), so a peer can never rewrite a genesis — and the owner it elected —
/// out from under a node that already holds one.
pub fn verify_log(network_id: &str, transitions: &[Transition]) -> Result<NetworkState> {
    use std::collections::BTreeSet;
    let mut state = NetworkState::empty_for(network_id);
    let mut members: BTreeSet<String> = BTreeSet::new();
    for t in transitions {
        verify_transition_signatures(network_id, t)?;
        let members_vec: Vec<String> = members.iter().cloned().collect();
        verify_quorum(&state, t, &members_vec)?;
        // Grow the reconstructed member set from this transition's participants
        // before applying the next, mirroring how authority accrues live.
        for s in &t.signers {
            members.insert(s.clone());
        }
        match &t.variant {
            TransitionVariant::RoleGrant { target, .. }
            | TransitionVariant::RoleRevoke { target }
            | TransitionVariant::Evict { target } => {
                members.insert(target.clone());
            }
            TransitionVariant::Split { members: m, .. } => {
                for x in m {
                    members.insert(x.clone());
                }
            }
            TransitionVariant::KindChange { .. } => {}
        }
        state = apply_transition(state, t);
    }
    Ok(state)
}

// ---- on-disk persistence -------------------------------------------

fn state_path(network_id: &str) -> Result<PathBuf> {
    Ok(crate::dirs::states_dir()?.join(format!("{network_id}.json")))
}

/// Load the network state scoped to the given Network ID. Missing
/// file → fresh empty open state. Schema mismatch → error, so a
/// future revision can't silently parse the new shape into the old.
pub fn load(network_id: &str) -> Result<NetworkState> {
    let path = state_path(network_id)?;
    if !path.exists() {
        return Ok(NetworkState::empty_for(network_id));
    }
    let raw = std::fs::read_to_string(&path)
        .map_err(|e| Error::Other(format!("read network_state at {}: {e}", path.display())))?;
    let state: NetworkState = serde_json::from_str(&raw)
        .map_err(|e| Error::Other(format!("parse network_state at {}: {e}", path.display())))?;
    if state.version != NETWORK_STATE_VERSION {
        return Err(Error::Other(format!(
            "network_state version {} unsupported (this build expects v{})",
            state.version, NETWORK_STATE_VERSION
        )));
    }
    if state.network_id != network_id {
        // Filename is the index of truth; on mismatch, start fresh.
        return Ok(NetworkState::empty_for(network_id));
    }
    Ok(state)
}

pub fn save(state: &NetworkState) -> Result<()> {
    let path = state_path(&state.network_id)?;
    let parent = path
        .parent()
        .ok_or_else(|| Error::Other(format!("state path has no parent: {}", path.display())))?;
    std::fs::create_dir_all(parent)
        .map_err(|e| Error::Other(format!("create states dir at {}: {e}", parent.display())))?;
    let serialized = serde_json::to_string_pretty(state)?;
    std::fs::write(&path, serialized)
        .map_err(|e| Error::Other(format!("write network_state to {}: {e}", path.display())))?;
    restrict_file_permissions(&path)?;
    Ok(())
}

/// Remove the per-network state file. Used by the "forget network"
/// path so removed networks don't leak governance state on disk.
pub fn delete(network_id: &str) -> Result<()> {
    let path = state_path(network_id)?;
    if path.exists() {
        std::fs::remove_file(&path).map_err(|e| {
            Error::Other(format!("remove network_state at {}: {e}", path.display()))
        })?;
    }
    Ok(())
}

#[cfg(unix)]
fn restrict_file_permissions(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)
        .map_err(|e| Error::io(path.to_path_buf(), e))?
        .permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms).map_err(|e| Error::io(path.to_path_buf(), e))?;
    Ok(())
}

#[cfg(not(unix))]
fn restrict_file_permissions(_path: &std::path::Path) -> Result<()> {
    Ok(())
}

// ---- tests ----------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixture_key(seed: u8) -> (SigningKey, String) {
        let sk = SigningKey::from_bytes(&[seed; 32]);
        let pubkey_b32 = data_encoding::BASE32_NOPAD
            .encode(sk.verifying_key().as_bytes())
            .to_lowercase();
        (sk, pubkey_b32)
    }

    #[test]
    fn role_rank_is_strictly_monotonic() {
        assert!(Role::Member.rank() < Role::Controller.rank());
        assert!(Role::Controller.rank() < Role::Owner.rank());
    }

    #[test]
    fn can_grant_table() {
        assert!(!Role::Member.can_grant(Role::Member));
        assert!(!Role::Member.can_grant(Role::Controller));
        assert!(!Role::Member.can_grant(Role::Owner));

        assert!(Role::Controller.can_grant(Role::Member));
        assert!(Role::Controller.can_grant(Role::Controller));
        assert!(!Role::Controller.can_grant(Role::Owner));

        assert!(Role::Owner.can_grant(Role::Member));
        assert!(Role::Owner.can_grant(Role::Controller));
        assert!(Role::Owner.can_grant(Role::Owner));
    }

    #[test]
    fn default_role_is_member_default_kind_is_open() {
        assert_eq!(Role::default(), Role::Member);
        assert_eq!(NetworkKind::default(), NetworkKind::Open);
    }

    #[test]
    fn payload_includes_domain_tag_and_network_id() {
        let payload = transition_payload(
            "net-1",
            &TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
        );
        let s = String::from_utf8(payload).unwrap();
        assert!(s.starts_with(SIGN_DOMAIN_TAG_STATE));
        assert!(s.contains("net-1"));
        assert!(s.contains("kind_change"));
        assert!(s.contains("closed"));
    }

    #[test]
    fn payload_binds_to_network_id() {
        // Same variant under different networks must produce
        // different payloads — otherwise a signature could be
        // replayed cross-network.
        let v = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let a = transition_payload("net-a", &v);
        let b = transition_payload("net-b", &v);
        assert_ne!(a, b);
    }

    #[test]
    fn split_payload_normalises_member_order() {
        // The signature must not depend on the input order of
        // `members` — otherwise the same split with the same signers
        // could produce a different signed payload depending on how
        // the proposer ordered the list.
        let a = transition_payload(
            "net-1",
            &TransitionVariant::Split {
                new_network_id: "derived".into(),
                members: vec!["c".into(), "a".into(), "b".into()],
            },
        );
        let b = transition_payload(
            "net-1",
            &TransitionVariant::Split {
                new_network_id: "derived".into(),
                members: vec!["a".into(), "b".into(), "c".into()],
            },
        );
        assert_eq!(a, b);
    }

    #[test]
    fn sign_then_verify_round_trip() {
        let (sk, pk) = fixture_key(7);
        let variant = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let sig = sign_transition("net-1", &variant, &sk);
        let t = Transition {
            at: 0,
            variant,
            signers: vec![pk],
            signatures: vec![sig],
        };
        verify_transition_signatures("net-1", &t).unwrap();
    }

    #[test]
    fn verify_rejects_tampered_variant() {
        let (sk, pk) = fixture_key(7);
        let sig = sign_transition(
            "net-1",
            &TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            &sk,
        );
        // Same signers + sigs, but the variant has been swapped.
        // The signed payload no longer matches — sig should fail.
        let tampered = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Open,
            },
            signers: vec![pk],
            signatures: vec![sig],
        };
        assert!(matches!(
            verify_transition_signatures("net-1", &tampered),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_wrong_network_id() {
        let (sk, pk) = fixture_key(7);
        let sig = sign_transition(
            "net-original",
            &TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            &sk,
        );
        let t = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signers: vec![pk],
            signatures: vec![sig],
        };
        // Replay attempt: same transition, different network_id.
        assert!(matches!(
            verify_transition_signatures("net-target", &t),
            Err(Error::SignatureInvalid)
        ));
    }

    #[test]
    fn split_id_is_deterministic_and_order_independent() {
        let parent = "net-1";
        let a = derive_split_network_id(parent, &["c".into(), "a".into(), "b".into()]);
        let b = derive_split_network_id(parent, &["a".into(), "b".into(), "c".into()]);
        assert_eq!(a, b);
        // And matches a fresh recomputation.
        let c = derive_split_network_id(parent, &["a".into(), "b".into(), "c".into()]);
        assert_eq!(a, c);
    }

    #[test]
    fn split_id_differs_per_parent() {
        let signers = vec!["a".to_string(), "b".into()];
        assert_ne!(
            derive_split_network_id("net-1", &signers),
            derive_split_network_id("net-2", &signers)
        );
    }

    #[test]
    fn quorum_founder_self_election_accepted() {
        let (_, pk) = fixture_key(7);
        let state = NetworkState::empty_for("net-1");
        let t = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signers: vec![pk],
            signatures: vec![String::new()], // signature shape is irrelevant for quorum
        };
        verify_quorum(&state, &t, &[]).unwrap();
    }

    #[test]
    fn quorum_open_to_closed_needs_every_member() {
        let (_, pk_alice) = fixture_key(1);
        let (_, pk_bob) = fixture_key(2);
        let (_, pk_carol) = fixture_key(3);
        let state = NetworkState::empty_for("net-1");
        let members = vec![pk_alice.clone(), pk_bob.clone(), pk_carol.clone()];

        // Missing Carol's signature → reject.
        let t = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signers: vec![pk_alice.clone(), pk_bob.clone()],
            signatures: vec![String::new(), String::new()],
        };
        assert!(verify_quorum(&state, &t, &members).is_err());

        // All three signed → accept.
        let t_ok = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signers: vec![pk_alice, pk_bob, pk_carol],
            signatures: vec![String::new(), String::new(), String::new()],
        };
        verify_quorum(&state, &t_ok, &members).unwrap();
    }

    #[test]
    fn quorum_member_cannot_grant_controller() {
        let (_, owner) = fixture_key(1);
        let (_, member) = fixture_key(2);
        let (_, candidate) = fixture_key(3);
        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner.clone(), Role::Owner);
        state.roles.insert(member.clone(), Role::Member);

        // Member-only signer → must be rejected.
        let t = Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: candidate.clone(),
                role: Role::Controller,
            },
            signers: vec![member],
            signatures: vec![String::new()],
        };
        let members = vec![owner.clone(), candidate];
        assert!(verify_quorum(&state, &t, &members).is_err());
    }

    #[test]
    fn quorum_owner_grant_needs_every_owner() {
        let (_, owner_a) = fixture_key(1);
        let (_, owner_b) = fixture_key(2);
        let (_, candidate) = fixture_key(3);
        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner_a.clone(), Role::Owner);
        state.roles.insert(owner_b.clone(), Role::Owner);

        let members = vec![owner_a.clone(), owner_b.clone(), candidate.clone()];

        // Only owner_a signed — owner grant needs unanimous → reject.
        let t = Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: candidate.clone(),
                role: Role::Owner,
            },
            signers: vec![owner_a.clone()],
            signatures: vec![String::new()],
        };
        assert!(verify_quorum(&state, &t, &members).is_err());

        // Both owners signed → accept.
        let t_ok = Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: candidate,
                role: Role::Owner,
            },
            signers: vec![owner_a, owner_b],
            signatures: vec![String::new(), String::new()],
        };
        verify_quorum(&state, &t_ok, &members).unwrap();
    }

    #[test]
    fn apply_kind_change_promotes_founder() {
        let (_, pk) = fixture_key(7);
        let s = NetworkState::empty_for("net-1");
        let t = Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signers: vec![pk.clone()],
            signatures: vec![String::new()],
        };
        let after = apply_transition(s, &t);
        assert_eq!(after.kind, NetworkKind::Closed);
        assert_eq!(after.role_of(&pk), Role::Owner);
        assert_eq!(after.transitions.len(), 1);
    }

    #[test]
    fn quorum_evict_member_needs_controller_or_owner() {
        let (_, owner) = fixture_key(1);
        let (_, member) = fixture_key(2);
        let (_, target) = fixture_key(3);
        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner.clone(), Role::Owner);
        // `target` is a plain member (absent from roles → defaults Member).
        let members = vec![owner.clone(), member.clone(), target.clone()];

        // A member-only signer can't evict.
        let t_bad = Transition {
            at: 0,
            variant: TransitionVariant::Evict {
                target: target.clone(),
            },
            signers: vec![member],
            signatures: vec![String::new()],
        };
        assert!(verify_quorum(&state, &t_bad, &members).is_err());

        // The owner can — single-signer, the fleet's lost-device kick.
        let t_ok = Transition {
            at: 0,
            variant: TransitionVariant::Evict { target },
            signers: vec![owner],
            signatures: vec![String::new()],
        };
        verify_quorum(&state, &t_ok, &members).unwrap();
    }

    #[test]
    fn apply_evict_strips_role_and_logs() {
        let mut s = NetworkState::empty_for("net-1");
        s.kind = NetworkKind::Closed;
        s.roles.insert("alice".into(), Role::Controller);
        let t = Transition {
            at: 0,
            variant: TransitionVariant::Evict {
                target: "alice".into(),
            },
            signers: vec!["owner".into()],
            signatures: vec![String::new()],
        };
        let after = apply_transition(s, &t);
        // Role gone (roster removal is the engine's job, tested there).
        assert_eq!(after.role_of("alice"), Role::Member);
        assert!(!after.roles.contains_key("alice"));
        assert_eq!(after.transitions.len(), 1);
    }

    #[test]
    fn apply_role_grant() {
        let mut s = NetworkState::empty_for("net-1");
        s.kind = NetworkKind::Closed;
        let t = Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: "alice".into(),
                role: Role::Controller,
            },
            signers: vec!["owner".into()],
            signatures: vec![String::new()],
        };
        let after = apply_transition(s, &t);
        assert_eq!(after.role_of("alice"), Role::Controller);
    }

    #[test]
    fn role_serde_round_trip() {
        for r in [Role::Member, Role::Controller, Role::Owner] {
            let s = serde_json::to_string(&r).unwrap();
            let back: Role = serde_json::from_str(&s).unwrap();
            assert_eq!(r, back);
        }
    }

    #[test]
    fn network_kind_serde_round_trip() {
        for k in [NetworkKind::Open, NetworkKind::Closed] {
            let s = serde_json::to_string(&k).unwrap();
            let back: NetworkKind = serde_json::from_str(&s).unwrap();
            assert_eq!(k, back);
        }
    }

    // ---- verify_log (from-genesis replay) -----------------------------

    #[test]
    fn verify_log_replays_founder_and_grant_from_genesis() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, member) = fixture_key(2);
        let net = "fleet-1";
        // Genesis: founder self-elects (open → closed), single signer.
        let v0 = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let t0 = Transition {
            at: 1,
            variant: v0.clone(),
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v0, &owner_sk)],
        };
        // Owner grants the member a controller role.
        let v1 = TransitionVariant::RoleGrant {
            target: member.clone(),
            role: Role::Controller,
        };
        let t1 = Transition {
            at: 2,
            variant: v1.clone(),
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v1, &owner_sk)],
        };
        let state = verify_log(net, &[t0, t1]).expect("a well-formed log verifies");
        assert_eq!(state.kind, NetworkKind::Closed);
        // The whole fleet can re-derive *who the owner is* from the log alone.
        assert_eq!(state.role_of(&owner), Role::Owner);
        assert_eq!(state.role_of(&member), Role::Controller);
        assert_eq!(state.transitions.len(), 2);
    }

    #[test]
    fn verify_log_rejects_forged_signature() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, victim) = fixture_key(2);
        let net = "fleet-1";
        let v0 = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let t0 = Transition {
            at: 1,
            variant: v0.clone(),
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v0, &owner_sk)],
        };
        // A grant that *claims* the owner signed it, but the signature is junk.
        let v1 = TransitionVariant::RoleGrant {
            target: victim,
            role: Role::Owner,
        };
        let t1 = Transition {
            at: 2,
            variant: v1,
            signers: vec![owner],
            signatures: vec!["not-a-real-signature".into()],
        };
        assert!(verify_log(net, &[t0, t1]).is_err());
    }

    #[test]
    fn verify_log_rejects_unauthorized_grant_on_closed_net() {
        // A non-owner can't self-promote on a closed network: the quorum check,
        // reconstructed from the log, needs an owner's signature for the grant.
        let (owner_sk, owner) = fixture_key(1);
        let (att_sk, attacker) = fixture_key(9);
        let net = "fleet-1";
        let v0 = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let t0 = Transition {
            at: 1,
            variant: v0.clone(),
            signers: vec![owner],
            signatures: vec![sign_transition(net, &v0, &owner_sk)],
        };
        let v1 = TransitionVariant::RoleGrant {
            target: attacker.clone(),
            role: Role::Controller,
        };
        let t1 = Transition {
            at: 2,
            variant: v1.clone(),
            signers: vec![attacker],
            signatures: vec![sign_transition(net, &v1, &att_sk)],
        };
        assert!(verify_log(net, &[t0, t1]).is_err());
    }
}
