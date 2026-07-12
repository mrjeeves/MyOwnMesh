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
///
/// v2 split the single transition log into the governance log (`transitions`)
/// and the multi-writer `member_log`. A v1 file still loads — [`load`] migrates
/// it via [`split_member_tier`] — so the bump is a forward, not a break.
pub const NETWORK_STATE_VERSION: u32 = 2;

// ---- kinds + roles --------------------------------------------------

/// Governance kind of a network. `Open` (default) has no role
/// enforcement; any current member can author roster edits. `Closed`
/// gates roster edits and kind transitions behind the signed authority
/// chain in [`NetworkState`]. `Silent` is governance-identical to `Open`
/// (permissionless roster, auto-accept — there is no signed cert chain to
/// enforce) but changes two *connection* behaviours: the engine never
/// auto-dials a peer just because it announced on signaling (it records the
/// peer as `Sighted` without opening a WebRTC session — a session is opened
/// only by an explicit [`crate::JoinedNetwork::connect_peer`] or by
/// answering an inbound offer), and it never gossips the roster. That makes
/// "nothing connects until a deliberate dial" true at the transport layer —
/// the shape a remote-support ("AnyDesk-style") product needs on a shared
/// open mesh. See `docs/NETWORK-TYPES.md`.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkKind {
    #[default]
    Open,
    Closed,
    Silent,
}

impl NetworkKind {
    /// True for the kinds whose governance is permissionless / auto-accept
    /// (`Open` and `Silent`) — i.e. NOT the signed-authority `Closed` model.
    /// Every governance branch that asks "open vs closed?" routes `Silent`
    /// down the open path through this predicate.
    pub fn is_open_governance(self) -> bool {
        matches!(self, NetworkKind::Open | NetworkKind::Silent)
    }
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
    /// Can admit/demote `member`s **and** mint or demote other
    /// `controller`s (managers make managers). Cannot grant `owner`.
    Controller,
    /// Can grant/demote any role (owners make owners) and approve
    /// network-kind transitions. Flat peer authority — a single owner
    /// signature suffices; there is no unanimous-owner requirement.
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
    /// mirrors revoke: over a member or controller needs a
    /// controller/owner, over an owner needs an owner.
    Evict { target: String },
    /// Spawn a new closed network derived from this one. Carried in
    /// the log of the *parent* network so members can discover the
    /// new network's existence via gossip.
    Split {
        new_network_id: String,
        members: Vec<String>,
    },
    /// Set the network's connection topology — the whole shape in one
    /// signed entry (mode, hub set, spoke redundancy), so "make this
    /// node an infra hub" is an owner action that every member's
    /// daemon converges on via the ordinary log adoption path, exactly
    /// like `kind`. `None` on [`NetworkState::topology`] (no such
    /// transition ratified yet) means the network's shape is whatever
    /// each device's local config says — the pre-governance behaviour.
    TopologyChange { to: crate::config::TopologyMode },
    /// A transition kind a newer build introduced. Parsing it as
    /// `Unknown` (instead of failing the enclosing message) keeps
    /// roster anti-entropy alive across mixed-version fleets: an older
    /// daemon can still ingest entries and membership, while
    /// [`verify_log`] refuses to adopt a governance log containing a
    /// variant it can't verify — it stays behind on governance until
    /// it updates, rather than breaking the whole sync channel.
    #[serde(other)]
    Unknown,
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
                // `Silent` is a creation-time config kind, never a KindChange
                // target (the quorum table rejects transitioning *to* it), but
                // the payload encoder must stay exhaustive over NetworkKind.
                NetworkKind::Silent => "silent",
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
        TransitionVariant::TopologyChange { to } => {
            use crate::config::TopologyMode;
            match to {
                TopologyMode::FullMesh => "topology|full_mesh".to_string(),
                TopologyMode::Ring { n_preferred } => format!(
                    "topology|ring|n={}",
                    n_preferred.map_or("none".to_string(), |n| n.to_string())
                ),
                TopologyMode::Star { hub } => format!("topology|star|hub={hub}"),
                TopologyMode::Hubs {
                    hubs,
                    spoke_redundancy,
                } => {
                    // Hub order is meaningless to the selector
                    // (rendezvous hashing), so order-normalise like
                    // `Split` does — the same designation signed by two
                    // UIs that listed hubs differently must verify as
                    // the same payload.
                    let mut sorted = hubs.clone();
                    sorted.sort();
                    format!(
                        "topology|hubs|hubs={}|r={}",
                        sorted.join(","),
                        spoke_redundancy.map_or("none".to_string(), |r| r.to_string())
                    )
                }
            }
        }
        // Never signed by this build — and a foreign signature over a
        // variant we can't render byte-identically can never verify,
        // which is exactly the "stay behind until updated" contract.
        TransitionVariant::Unknown => "unknown".to_string(),
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
    /// Append-only signed **governance** log: kind changes, owner and manager
    /// (controller) grants/revokes/evicts, and splits. Strict-prefix-extend on
    /// adoption — the slow-changing root + intermediate tiers of the cert
    /// chain. Most recent last.
    pub transitions: Vec<Transition>,
    /// Signed **member** log: per-entry admits (`RoleGrant{Member}`) and
    /// removals (`RoleRevoke`/`Evict`) of plain members, each authored by a
    /// single owner/manager. Multi-writer: union-merged on adoption so
    /// distributed managers can admit concurrently (offline) without forking —
    /// the leaf tier of the cert chain. Projected via [`verify_member_log`];
    /// merged via [`merge_member_logs`]. `#[serde(default)]` so a pre-split
    /// (legacy single-log) state still loads, then [`split_member_tier`]
    /// migrates it.
    #[serde(default)]
    pub member_log: Vec<Transition>,
    /// Pending proposals awaiting ratification.
    pub pending: Vec<Proposal>,
    /// Splits this network has spawned. Each entry was derived from
    /// a stuck close proposal here.
    pub splits: Vec<SplitRecord>,
    /// Governed connection topology, set by a ratified
    /// [`TransitionVariant::TopologyChange`]. `Some` is authoritative
    /// over the device-local config topology (the same precedence
    /// `kind` has); `None` means no topology transition has ever been
    /// ratified and the local config rules. `#[serde(default)]` so
    /// pre-topology state files keep loading.
    #[serde(default)]
    pub topology: Option<crate::config::TopologyMode>,
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
            member_log: Vec::new(),
            pending: Vec::new(),
            splits: Vec::new(),
            topology: None,
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
/// Quorum table — **flat peer authority**: a holder of a tier may grant or
/// demote at that tier or below, on a single signature, with no consensus
/// round:
///   - `KindChange { to: Closed }` — the founder self-elects
///     (`signers.first()` becomes owner); ≥ 1 signer. Multi-signer capable:
///     a close may be co-signed (a peer mesh can't assume one always-online
///     founder), and only the empty signer set is rejected.
///   - `KindChange { to: Open }` — ≥ 1 owner.
///   - `RoleGrant { role: Owner }` — ≥ 1 owner (owners make owners).
///   - `RoleGrant { role: Controller }` — ≥ 1 controller or owner
///     (managers make managers).
///   - `RoleGrant { role: Member }` — ≥ 1 controller or owner.
///   - `RoleRevoke` / `Evict` — authority at the target's *current* tier:
///     an owner over an owner; a controller or owner over a controller or
///     member.
///   - `Split` — single signer (the proposer), who becomes
///     founder-owner of the derived network.
///
/// This is deliberately permissive: a lone rogue owner can mint or demote
/// owners; a lone manager can mint or demote managers. That danger is the
/// *application* layer's to guard (approval UX, out-of-band confirmation) —
/// the network layer stays flat, single-signer, and self-similar.
///
/// Every check reads authority off `state_before.roles`, which a
/// converging peer reconstructs from the signed log itself
/// ([`verify_log`]). Genesis is deliberately **single-signer**: the
/// founder self-elects, and no other check depends on an external
/// member roster. That matters for convergence — a peer replaying the
/// log has no way to reconstruct who *else* was in the open network at
/// close time, so a multi-signer "unanimous member consent" genesis
/// could never be re-verified downstream. Existing peers become plain
/// members of the closed network and may leave if they object.
pub fn verify_quorum(state_before: &NetworkState, transition: &Transition) -> Result<()> {
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
        // Founder self-election: `open → closed`. `apply_transition` elects
        // `signers.first()` — the founder — as the sole owner; any peers already
        // present become plain members (ownership is then distributed via
        // peer-authority owner grants, so the mesh never depends on the founder
        // staying online).
        //
        // Genesis is **multi-signer capable** — a peer mesh can't assume one
        // always-online founder, so a close may be co-signed. We accept **≥ 1**
        // signer and elect the first; the rest gain nothing at genesis. Requiring
        // exactly one would fail `verify_log` for the whole log on every adopting
        // peer — silently dropping every member admit on the adopting side while
        // the authoring owner still holds it locally (its ratify-time roster
        // mirror runs unconditionally). That is exactly the "one owner sees the
        // device, the other never does" split.
        (
            TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            NetworkKind::Open,
        ) => {
            if signers.is_empty() {
                return Err(Error::Protocol(
                    "founder self-election needs a signer".into(),
                ));
            }
        }
        (
            TransitionVariant::KindChange {
                to: NetworkKind::Open,
            },
            NetworkKind::Closed,
        ) => {
            if !signers.iter().any(|s| owners.contains(s)) {
                return Err(Error::Protocol(
                    "reopen (closed → open) needs ≥ 1 owner signature".into(),
                ));
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
            // Owners make owners: any single existing owner suffices. The first
            // owner lands via the founder self-election (genesis) above, so a
            // closed network always has ≥ 1 owner to author this.
            if !signers.iter().any(|s| owners.contains(s)) {
                return Err(Error::Protocol(
                    "grant owner needs ≥ 1 owner signature".into(),
                ));
            }
        }
        (
            TransitionVariant::RoleGrant {
                role: Role::Controller,
                ..
            },
            NetworkKind::Closed,
        ) => {
            // Managers make managers: a controller can mint a controller, and so
            // can an owner (the higher tier).
            if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                return Err(Error::Protocol(
                    "grant controller needs ≥ 1 controller or owner signature".into(),
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
        (TransitionVariant::RoleGrant { .. }, NetworkKind::Open | NetworkKind::Silent) => {
            // Roles are cosmetic on open networks. Any member signs.
            // Engine accepts but doesn't enforce on open kind. Silent is
            // governance-identical to Open here.
        }

        (TransitionVariant::RoleRevoke { target }, NetworkKind::Closed) => {
            let target_role = state_before.role_of(target);
            // Demotion requires authority at the *target's* current tier: an
            // owner demotes an owner; a controller (or owner) demotes a
            // controller or a member. Flat peer authority — no consensus round.
            match target_role {
                Role::Owner => {
                    if !signers.iter().any(|s| owners.contains(s)) {
                        return Err(Error::Protocol(
                            "revoke owner needs ≥ 1 owner signature".into(),
                        ));
                    }
                }
                Role::Controller | Role::Member => {
                    if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                        return Err(Error::Protocol(
                            "revoke controller/member needs ≥ 1 controller or owner signature"
                                .into(),
                        ));
                    }
                }
            }
        }
        (TransitionVariant::RoleRevoke { .. }, NetworkKind::Open | NetworkKind::Silent) => {
            // Cosmetic on open kind; any signer accepted. Silent == Open.
        }

        (TransitionVariant::Evict { target }, NetworkKind::Closed) => {
            // Eviction authority is authority over the *target's* current tier —
            // identical to revoke, since an evict subsumes a revoke (it also
            // strips roster membership).
            let target_role = state_before.role_of(target);
            match target_role {
                Role::Owner => {
                    if !signers.iter().any(|s| owners.contains(s)) {
                        return Err(Error::Protocol(
                            "evict owner needs ≥ 1 owner signature".into(),
                        ));
                    }
                }
                Role::Controller | Role::Member => {
                    if !signers.iter().any(|s| controllers_and_owners.contains(s)) {
                        return Err(Error::Protocol(
                            "evict controller/member needs ≥ 1 controller or owner signature"
                                .into(),
                        ));
                    }
                }
            }
        }
        (TransitionVariant::Evict { .. }, NetworkKind::Open | NetworkKind::Silent) => {
            // An open network's roster is permissionless (gossip re-adds
            // anyone), so an evict can't stick — accept the signer set but
            // it has no lasting effect. Closed is the meaningful case. Silent
            // is governance-identical to Open (and gossips nothing anyway).
        }

        (TransitionVariant::Split { .. }, _) => {
            if signers.len() != 1 {
                return Err(Error::Protocol(
                    "split must be signed by exactly one party (the would-be owner)".into(),
                ));
            }
        }

        (TransitionVariant::TopologyChange { to }, NetworkKind::Closed) => {
            // Same-shape transitions don't make sense (mirrors the
            // KindChange no-op rule) — without this, a re-assert would
            // append an identical entry to the log forever.
            if state_before.topology.as_ref() == Some(to) {
                return Err(Error::Protocol(
                    "TopologyChange to the current topology is a no-op".into(),
                ));
            }
            // Shaping the fabric is an owner act — the same tier as
            // reopening the network. Controllers govern members; the
            // owner governs the infrastructure.
            if !signers.iter().any(|s| owners.contains(s)) {
                return Err(Error::Protocol(
                    "topology change needs ≥ 1 owner signature".into(),
                ));
            }
        }
        (TransitionVariant::TopologyChange { .. }, NetworkKind::Open | NetworkKind::Silent) => {
            // Open/Silent networks have no enforced owner, so a signed
            // network-wide topology would be anyone's to hijack. Their
            // shape stays a per-device config choice (`TopologySet`).
            return Err(Error::Protocol(
                "topology is governed on closed networks only — open/silent \
                 networks set it per-device in local config"
                    .into(),
            ));
        }

        (TransitionVariant::Unknown, _) => {
            // A variant from a newer build. We can't reconstruct its
            // canonical payload, so we can't verify authority over it —
            // refuse, which makes `verify_log` hold this node at its
            // current governance state until it updates.
            return Err(Error::Protocol(
                "transition kind from a newer build — update to verify it".into(),
            ));
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
        TransitionVariant::TopologyChange { to } => {
            state.topology = Some(to.clone());
        }
        // Unreachable through verified paths (the quorum table refuses
        // Unknown), but apply stays total: record the entry, mutate
        // nothing.
        TransitionVariant::Unknown => {}
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
/// Every step is quorum-checked against the state reconstructed *from the log
/// so far* — genesis against the empty open network (single-signer founder
/// election), each later grant/revoke against the roles the prior transitions
/// established. No external member roster is consulted, which is exactly why
/// genesis must be single-signer: there is nothing here to reconstruct a
/// pre-close member set from.
///
/// Adoption policy (whether a verified log *replaces* the local one) is the
/// caller's: the engine only adopts a log that **extends** its own (shared
/// prefix), so a peer can never rewrite a genesis — and the owner it elected —
/// out from under a node that already holds one.
pub fn verify_log(network_id: &str, transitions: &[Transition]) -> Result<NetworkState> {
    let mut state = NetworkState::empty_for(network_id);
    for t in transitions {
        verify_transition_signatures(network_id, t)?;
        verify_quorum(&state, t)?;
        state = apply_transition(state, t);
    }
    Ok(state)
}

// ---- member tier (multi-writer leaf of the cert chain) --------------

/// Stable, collision-resistant identity for a ratified member-tier entry: its
/// timestamp, canonical signed variant, and exact signer/signature set. Two
/// byte-identical entries share a key (so a union-merge dedupes them); any
/// difference yields a distinct key. Used for both dedup and a deterministic
/// sort tiebreak, so every peer derives the same membership from the same set.
fn member_entry_key(t: &Transition) -> String {
    serde_json::to_string(t).unwrap_or_default()
}

/// True if `variant`, applied when the target held `target_role`, is a
/// member-tier change (admit/remove of a plain member) rather than a
/// governance-tier one (kind change, owner/manager grant, owner/manager
/// removal, or split). Drives [`split_member_tier`].
fn is_member_tier(variant: &TransitionVariant, target_role: Role) -> bool {
    match variant {
        TransitionVariant::RoleGrant {
            role: Role::Member, ..
        } => true,
        TransitionVariant::RoleRevoke { .. } | TransitionVariant::Evict { .. } => {
            target_role == Role::Member
        }
        _ => false,
    }
}

/// Project the member-tier log against the governance state, returning the set
/// of devices that currently hold membership.
///
/// The member tier is **multi-writer**: any current owner or manager
/// (controller) may author an admit (`RoleGrant{Member}`) or a removal
/// (`RoleRevoke`/`Evict`) of a member, each entry individually signed by its
/// author. Entries from every author merge by union; for a given device the
/// latest entry (by `at`, then [`member_entry_key`]) wins, so an admit and a
/// later removal converge to "removed" regardless of the order two peers
/// received them — the property a strict-prefix log can't give concurrent
/// writers.
///
/// Authority is evaluated against the *current* governance roles: an entry
/// counts only if at least one of its signers is presently an owner or manager,
/// and only `Member` may be granted here (owner/manager grants live in the
/// owner-signed governance log). Any entry that fails its signature, authority,
/// or shape check is silently skipped — never counted, but also never able to
/// poison the rest of the set, so one malformed entry can't deny-of-service the
/// whole membership. Skipped entries stay in the log and are re-evaluated as
/// governance converges (e.g. once the manager who authored them is known).
pub fn verify_member_log(
    gov: &NetworkState,
    member_log: &[Transition],
    network_id: &str,
) -> std::collections::BTreeSet<String> {
    member_log_verdict(gov, member_log, network_id)
        .into_iter()
        .filter(|(_, p)| *p)
        .map(|(k, _)| k)
        .collect()
}

/// Devices the signed member log has **explicitly removed** — the latest
/// authorised entry for the device is an `Evict`/`RoleRevoke`. These are the
/// only devices the roster mirror deletes on adoption; a device merely *absent*
/// from the signed log (e.g. one added by `roster_approve` but not yet signed
/// in) is left alone, never pruned.
pub fn member_log_removed(
    gov: &NetworkState,
    member_log: &[Transition],
    network_id: &str,
) -> std::collections::BTreeSet<String> {
    member_log_verdict(gov, member_log, network_id)
        .into_iter()
        .filter(|(_, p)| !*p)
        .map(|(k, _)| k)
        .collect()
}

/// The member-tier verdict: device → currently a member (`true`) or explicitly
/// removed (`false`). Only entries that verify and are authored by a current
/// owner/manager count; for each device the latest such entry (by `at`, then a
/// stable key) wins. A device with no authorised member-tier entry does not
/// appear at all.
fn member_log_verdict(
    gov: &NetworkState,
    member_log: &[Transition],
    network_id: &str,
) -> std::collections::BTreeMap<String, bool> {
    use std::collections::{BTreeMap, BTreeSet};
    let authorities: BTreeSet<&str> = gov
        .roles
        .iter()
        .filter(|(_, r)| matches!(r, Role::Controller | Role::Owner))
        .map(|(k, _)| k.as_str())
        .collect();

    // Deterministic order: by timestamp, then tombstones *before* grants,
    // then a stable per-entry key. The middle term is the tie-break that
    // matters: the fold below is last-writer-wins, so at an equal `at` the
    // grant is applied after the tombstone and membership survives. Live
    // authoring stamps member-tier entries strictly past the newest existing
    // entry, so an evict that *means* to remove a member always lands later
    // than the grant it removes — an equal-stamp pair only arises from legacy
    // logs where a re-admit raced its evict inside one wall-clock second (or
    // the authors' clocks were skewed), and there the re-admit was the later
    // intent. Letting the tombstone win that tie is what silently stranded
    // devices out of every fleet roster on upgrade (remote control refused
    // fleet-wide while video kept streaming).
    let is_member_grant = |t: &&Transition| {
        matches!(
            t.variant,
            TransitionVariant::RoleGrant {
                role: Role::Member,
                ..
            }
        )
    };
    let mut ordered: Vec<&Transition> = member_log.iter().collect();
    ordered.sort_by(|a, b| {
        a.at.cmp(&b.at)
            .then_with(|| is_member_grant(a).cmp(&is_member_grant(b)))
            .then_with(|| member_entry_key(a).cmp(&member_entry_key(b)))
    });

    let mut present: BTreeMap<String, bool> = BTreeMap::new();
    for t in ordered {
        // Skip anything that doesn't cleanly verify — fail-safe, never fatal.
        if verify_transition_signatures(network_id, t).is_err() {
            continue;
        }
        if !t.signers.iter().any(|s| authorities.contains(s.as_str())) {
            continue;
        }
        match &t.variant {
            TransitionVariant::RoleGrant {
                target,
                role: Role::Member,
            } => {
                present.insert(target.clone(), true);
            }
            TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target } => {
                present.insert(target.clone(), false);
            }
            // A controller/owner grant, kind change, or split is not a
            // member-tier change — ignored here (those ride the governance log).
            _ => {}
        }
    }
    present
}

/// Union-merge two member-tier logs: keep every distinct entry from either
/// side, deduped by [`member_entry_key`]. Commutative and idempotent, so two
/// managers' concurrent admissions converge without the fork a strict-prefix
/// log would hit. Ordering is irrelevant — [`verify_member_log`] re-sorts.
pub fn merge_member_logs(local: &[Transition], incoming: &[Transition]) -> Vec<Transition> {
    use std::collections::BTreeMap;
    let mut by_key: BTreeMap<String, Transition> = BTreeMap::new();
    for t in local.iter().chain(incoming.iter()) {
        by_key
            .entry(member_entry_key(t))
            .or_insert_with(|| t.clone());
    }
    by_key.into_values().collect()
}

/// Migrate a legacy single-log state into the two-tier shape: member-tier
/// admits/removes move out of `transitions` into `member_log`; the governance
/// log keeps kind changes, owner/manager grants and removals, and splits. The
/// projected roster is unchanged — a migrated member is still re-derived into
/// the roles map by [`verify_member_log`]. Idempotent: re-running on an
/// already-split state is a no-op, because the governance log then holds no
/// member-tier entry.
pub fn split_member_tier(state: &mut NetworkState) {
    // Replay to learn each target's role at the instant a revoke/evict applied,
    // so removals are classified by the tier they actually touched.
    let mut roles: std::collections::BTreeMap<String, Role> = std::collections::BTreeMap::new();
    let mut governance: Vec<Transition> = Vec::new();
    let mut members: Vec<Transition> = Vec::new();
    for t in std::mem::take(&mut state.transitions) {
        let target_role = match &t.variant {
            TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target } => {
                roles.get(target).copied().unwrap_or(Role::Member)
            }
            _ => Role::Member,
        };
        let member_tier = is_member_tier(&t.variant, target_role);
        // Advance the replay roles so later transitions classify correctly.
        match &t.variant {
            TransitionVariant::RoleGrant { target, role } => {
                roles.insert(target.clone(), *role);
            }
            TransitionVariant::RoleRevoke { target } | TransitionVariant::Evict { target } => {
                roles.remove(target);
            }
            TransitionVariant::KindChange { to } => {
                if matches!(to, NetworkKind::Closed) {
                    if let Some(founder) = t.signers.first() {
                        roles.insert(founder.clone(), Role::Owner);
                    }
                }
            }
            // Neither touches roles, and both are governance-tier —
            // they fall through to the governance vec below.
            TransitionVariant::Split { .. }
            | TransitionVariant::TopologyChange { .. }
            | TransitionVariant::Unknown => {}
        }
        if member_tier {
            members.push(t);
        } else {
            governance.push(t);
        }
    }
    // Preserve anything already in the member log (defensive; empty pre-split).
    members.append(&mut state.member_log);
    state.transitions = governance;
    state.member_log = members;
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
    // Corrupt (a power cut mid-write leaves a truncated file) → the
    // same treatment as missing: quarantine + fresh, loudly. Failing
    // here failed every subsequent join of the network. Governance
    // state re-converges from the network's signed transition
    // broadcasts, so empty is always recoverable.
    let mut state: NetworkState = match serde_json::from_str(&raw) {
        Ok(s) => s,
        Err(e) => {
            let kept = crate::persist::quarantine(&path);
            tracing::error!(
                network = network_id,
                path = %path.display(),
                quarantined = ?kept,
                "network_state file is corrupt ({e}) — starting fresh; \
                 governance re-converges from the network's signed \
                 transitions"
            );
            return Ok(NetworkState::empty_for(network_id));
        }
    };
    match state.version {
        // v1 (legacy single log): split the member tier out of `transitions`
        // into `member_log`, then it is a v2 state. Idempotent and roster-
        // preserving — a migrated member still re-derives into the roles map.
        1 => {
            split_member_tier(&mut state);
            state.version = NETWORK_STATE_VERSION;
        }
        NETWORK_STATE_VERSION => {}
        other => {
            return Err(Error::Other(format!(
                "network_state version {other} unsupported (this build expects v{NETWORK_STATE_VERSION})"
            )));
        }
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
    crate::persist::write_atomic(&path, serialized.as_bytes())
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
    fn silent_kind_serde_round_trips_and_is_open_governance() {
        // Snake-case wire form.
        assert_eq!(
            serde_json::to_string(&NetworkKind::Silent).unwrap(),
            "\"silent\""
        );
        let back: NetworkKind = serde_json::from_str("\"silent\"").unwrap();
        assert_eq!(back, NetworkKind::Silent);
        // Silent routes down the permissionless (open) governance path;
        // Closed does not.
        assert!(NetworkKind::Silent.is_open_governance());
        assert!(NetworkKind::Open.is_open_governance());
        assert!(!NetworkKind::Closed.is_open_governance());
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
        verify_quorum(&state, &t).unwrap();
    }

    #[test]
    fn quorum_open_to_closed_elects_the_first_signer() {
        // Genesis is a founder self-election: the first signer becomes owner.
        // New fleets sign it alone, but a multi-signer genesis (from the retired
        // unanimous-consent model) must still verify so an older fleet converges
        // on upgrade rather than being stranded — only the empty signer set is
        // rejected.
        let (_, pk_alice) = fixture_key(1);
        let (_, pk_bob) = fixture_key(2);
        let state = NetworkState::empty_for("net-1");

        let close = |signers: Vec<String>| Transition {
            at: 0,
            variant: TransitionVariant::KindChange {
                to: NetworkKind::Closed,
            },
            signatures: vec![String::new(); signers.len()],
            signers,
        };

        // Lone founder → accept.
        verify_quorum(&state, &close(vec![pk_alice.clone()])).unwrap();
        // Multi-signer genesis → still accepted (founder = first signer).
        verify_quorum(&state, &close(vec![pk_alice.clone(), pk_bob])).unwrap();
        // No signer at all → reject.
        assert!(verify_quorum(&state, &close(vec![])).is_err());

        // apply_transition elects the *first* signer as the sole owner,
        // regardless of how many co-signers rode along.
        let after = apply_transition(state, &close(vec![pk_alice.clone(), "someone".into()]));
        assert_eq!(after.role_of(&pk_alice), Role::Owner);
        assert_eq!(after.role_of("someone"), Role::Member);
    }

    #[test]
    fn verify_log_accepts_a_multi_signer_genesis_and_elects_the_founder() {
        // The heal path: an older fleet's genesis may carry more than one signer
        // (unanimous-consent era). `verify_log` must accept it — electing the
        // first signer as owner — so the whole log verifies and members converge,
        // rather than the log failing wholesale and every admit being dropped on
        // the adopting side (the "one owner sees the device, the other doesn't"
        // split).
        let (alice_sk, alice) = fixture_key(1);
        let (bob_sk, bob) = fixture_key(2);
        let net = "heal-net";
        let variant = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let payload = transition_payload(net, &variant);
        let genesis = Transition {
            at: 1,
            variant,
            signers: vec![alice.clone(), bob.clone()],
            signatures: vec![
                crate::signing::sign_with(&alice_sk, &payload),
                crate::signing::sign_with(&bob_sk, &payload),
            ],
        };
        let state = verify_log(net, std::slice::from_ref(&genesis))
            .expect("a multi-signer genesis must still verify");
        assert_eq!(
            state.role_of(&alice),
            Role::Owner,
            "the founder (first signer) is owner"
        );
        assert_eq!(
            state.role_of(&bob),
            Role::Member,
            "a genesis co-signer is a plain member, not a second owner"
        );
    }

    #[test]
    fn member_log_removed_lists_only_tombstoned_devices() {
        // The surgical-removal contract: `member_log_removed` returns exactly the
        // devices the log has evicted/revoked — never a device that is merely
        // absent from the projection. That is what keeps the roster mirror from
        // over-pruning a device added out-of-band (e.g. `roster_approve`).
        let (owner_sk, owner) = fixture_key(1);
        let (_, m) = fixture_key(2);
        let (_, n) = fixture_key(3);
        let net = "surgical-net";
        let mut gov = NetworkState::empty_for(net);
        gov.kind = NetworkKind::Closed;
        gov.roles.insert(owner.clone(), Role::Owner);

        let signed = |variant: TransitionVariant, at: u64| {
            let payload = transition_payload(net, &variant);
            Transition {
                at,
                signatures: vec![crate::signing::sign_with(&owner_sk, &payload)],
                signers: vec![owner.clone()],
                variant,
            }
        };
        let member_log = vec![
            signed(
                TransitionVariant::RoleGrant {
                    target: m.clone(),
                    role: Role::Member,
                },
                1,
            ),
            signed(
                TransitionVariant::RoleGrant {
                    target: n.clone(),
                    role: Role::Member,
                },
                1,
            ),
            // M is evicted later; N is untouched.
            signed(TransitionVariant::Evict { target: m.clone() }, 2),
        ];

        let present = verify_member_log(&gov, &member_log, net);
        let removed = member_log_removed(&gov, &member_log, net);
        assert!(present.contains(&n), "N is still a member");
        assert!(!present.contains(&m), "M was evicted");
        assert!(
            removed.contains(&m) && removed.len() == 1,
            "only the explicitly-evicted M is tombstoned, not merely-absent devices"
        );
        assert!(
            !removed.contains(&n),
            "an active member is never in the removed set"
        );
    }

    #[test]
    fn equal_stamp_readmit_beats_the_tombstone() {
        // The legacy re-admit race: before authoring stamped member-tier
        // entries strictly past the newest existing one, a re-admit could
        // carry the same wall-clock second as the evict it undoes (same
        // author, or a skewed second author). The verdict's tie-break must
        // resolve that pair to *membership* — the re-admit was the later
        // intent — or the device is stranded evicted, the roster mirror
        // deletes it on every peer at adoption, and remote control is
        // refused fleet-wide while video keeps streaming.
        let (owner_sk, owner) = fixture_key(1);
        let (_, m) = fixture_key(2);
        let net = "tie-net";
        let mut gov = NetworkState::empty_for(net);
        gov.kind = NetworkKind::Closed;
        gov.roles.insert(owner.clone(), Role::Owner);

        let signed = |variant: TransitionVariant, at: u64| {
            let payload = transition_payload(net, &variant);
            Transition {
                at,
                signatures: vec![crate::signing::sign_with(&owner_sk, &payload)],
                signers: vec![owner.clone()],
                variant,
            }
        };
        // Admitted at 1, evicted at 5, re-admitted in the same second.
        let member_log = vec![
            signed(
                TransitionVariant::RoleGrant {
                    target: m.clone(),
                    role: Role::Member,
                },
                1,
            ),
            signed(TransitionVariant::Evict { target: m.clone() }, 5),
            signed(
                TransitionVariant::RoleGrant {
                    target: m.clone(),
                    role: Role::Member,
                },
                5,
            ),
        ];

        let present = verify_member_log(&gov, &member_log, net);
        let removed = member_log_removed(&gov, &member_log, net);
        assert!(
            present.contains(&m),
            "an equal-stamp evict/re-admit pair resolves to membership"
        );
        assert!(
            removed.is_empty(),
            "a re-admitted device is never handed to the roster mirror for deletion"
        );
        // A *strictly later* evict still wins — deliberate removals stand.
        let mut evicted_later = member_log;
        evicted_later.push(signed(TransitionVariant::Evict { target: m.clone() }, 6));
        assert!(!verify_member_log(&gov, &evicted_later, net).contains(&m));
        assert!(member_log_removed(&gov, &evicted_later, net).contains(&m));
    }

    #[test]
    fn quorum_controller_grant_is_peer_authority() {
        let (_, owner) = fixture_key(1);
        let (_, member) = fixture_key(2);
        let (_, controller) = fixture_key(3);
        let (_, candidate) = fixture_key(4);
        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner.clone(), Role::Owner);
        state.roles.insert(member.clone(), Role::Member);
        state.roles.insert(controller.clone(), Role::Controller);

        let grant_controller = |signer: &str| Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: candidate.clone(),
                role: Role::Controller,
            },
            signers: vec![signer.to_string()],
            signatures: vec![String::new()],
        };

        // A member has no authority → rejected.
        assert!(verify_quorum(&state, &grant_controller(&member)).is_err());
        // Managers make managers: a controller alone can mint a controller.
        verify_quorum(&state, &grant_controller(&controller)).unwrap();
        // An owner (higher tier) can too.
        verify_quorum(&state, &grant_controller(&owner)).unwrap();
    }

    #[test]
    fn quorum_owner_grant_needs_one_owner() {
        // Owners make owners: a single existing owner suffices (no unanimous
        // requirement). A non-owner can't.
        let (_, owner_a) = fixture_key(1);
        let (_, owner_b) = fixture_key(2);
        let (_, controller) = fixture_key(3);
        let (_, candidate) = fixture_key(4);
        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner_a.clone(), Role::Owner);
        state.roles.insert(owner_b.clone(), Role::Owner);
        state.roles.insert(controller.clone(), Role::Controller);

        let grant_owner = |signers: Vec<String>| Transition {
            at: 0,
            variant: TransitionVariant::RoleGrant {
                target: candidate.clone(),
                role: Role::Owner,
            },
            signatures: vec![String::new(); signers.len()],
            signers,
        };

        // One owner alone → accept.
        verify_quorum(&state, &grant_owner(vec![owner_a.clone()])).unwrap();
        // A controller can't mint an owner (only same-or-higher tier).
        assert!(verify_quorum(&state, &grant_owner(vec![controller])).is_err());
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

        // A member-only signer can't evict.
        let t_bad = Transition {
            at: 0,
            variant: TransitionVariant::Evict {
                target: target.clone(),
            },
            signers: vec![member],
            signatures: vec![String::new()],
        };
        assert!(verify_quorum(&state, &t_bad).is_err());

        // The owner can — single-signer, the fleet's lost-device kick.
        let t_ok = Transition {
            at: 0,
            variant: TransitionVariant::Evict { target },
            signers: vec![owner],
            signatures: vec![String::new()],
        };
        verify_quorum(&state, &t_ok).unwrap();
    }

    #[test]
    fn quorum_evict_authority_matrix() {
        // The full spec: owners evict anyone; managers (controllers) evict
        // managers and members but NOT owners; members evict nothing.
        let (_, owner) = fixture_key(1);
        let (_, manager) = fixture_key(2);
        let (_, member) = fixture_key(3);
        let (_, other_owner) = fixture_key(4);
        let (_, other_manager) = fixture_key(5);
        let (_, other_member) = fixture_key(6);

        let mut state = NetworkState::empty_for("net-1");
        state.kind = NetworkKind::Closed;
        state.roles.insert(owner.clone(), Role::Owner);
        state.roles.insert(other_owner.clone(), Role::Owner);
        state.roles.insert(manager.clone(), Role::Controller);
        state.roles.insert(other_manager.clone(), Role::Controller);
        // `member` / `other_member` are absent → default Member.

        let can_evict = |signer: &str, target: &str| {
            verify_quorum(
                &state,
                &Transition {
                    at: 0,
                    variant: TransitionVariant::Evict {
                        target: target.to_string(),
                    },
                    signers: vec![signer.to_string()],
                    signatures: vec![String::new()],
                },
            )
            .is_ok()
        };

        // Owners evict anyone.
        assert!(can_evict(&owner, &other_owner), "owner evicts owner");
        assert!(can_evict(&owner, &manager), "owner evicts manager");
        assert!(can_evict(&owner, &member), "owner evicts member");
        // Managers evict managers + members, but never owners.
        assert!(
            can_evict(&manager, &other_manager),
            "manager evicts manager"
        );
        assert!(can_evict(&manager, &member), "manager evicts member");
        assert!(
            !can_evict(&manager, &owner),
            "manager must NOT evict an owner"
        );
        // Members evict nothing.
        assert!(!can_evict(&member, &owner), "member evicts nothing (owner)");
        assert!(
            !can_evict(&member, &manager),
            "member evicts nothing (manager)"
        );
        assert!(
            !can_evict(&member, &other_member),
            "member evicts nothing (member)"
        );
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

    // ---- topology governance -------------------------------------------

    fn hubs_mode(hubs: &[&str], r: Option<u32>) -> crate::config::TopologyMode {
        crate::config::TopologyMode::Hubs {
            hubs: hubs.iter().map(|s| s.to_string()).collect(),
            spoke_redundancy: r,
        }
    }

    #[test]
    fn topology_payload_normalises_hub_order_and_signs_all_fields() {
        let pay =
            |mode| transition_payload("net-1", &TransitionVariant::TopologyChange { to: mode });
        // Hub order is selector-irrelevant (rendezvous hashing), so two
        // UIs listing the same hubs differently must sign identically.
        let a = pay(hubs_mode(&["hub-b", "hub-a"], Some(2)));
        let b = pay(hubs_mode(&["hub-a", "hub-b"], Some(2)));
        assert_eq!(a, b);
        // …while membership and redundancy are signed content.
        assert_ne!(a, pay(hubs_mode(&["hub-a", "hub-b"], Some(1))));
        assert_ne!(a, pay(hubs_mode(&["hub-a"], Some(2))));
        assert_ne!(a, pay(hubs_mode(&["hub-a", "hub-b"], None)));
        // Distinct prefix from every earlier variant family.
        let s = String::from_utf8(a).unwrap();
        assert!(s.contains("|topology|hubs|"));
    }

    #[test]
    fn topology_change_needs_an_owner_on_closed() {
        let (_, owner) = fixture_key(1);
        let (_, controller) = fixture_key(2);
        let gov = closed_gov(
            "net-1",
            &[(&owner, Role::Owner), (&controller, Role::Controller)],
        );
        let v = TransitionVariant::TopologyChange {
            to: hubs_mode(&[&owner], Some(2)),
        };
        // Quorum only — signature validity is a separate check.
        let by = |signer: &str| Transition {
            at: 5,
            variant: v.clone(),
            signers: vec![signer.to_string()],
            signatures: vec!["sig".into()],
        };
        verify_quorum(&gov, &by(&owner)).expect("owner shapes the fabric");
        assert!(
            verify_quorum(&gov, &by(&controller)).is_err(),
            "controllers govern members, not infrastructure"
        );
    }

    #[test]
    fn topology_change_is_refused_on_open_and_silent() {
        let (_, anyone) = fixture_key(3);
        let v = TransitionVariant::TopologyChange {
            to: crate::config::TopologyMode::FullMesh,
        };
        let t = Transition {
            at: 1,
            variant: v,
            signers: vec![anyone],
            signatures: vec!["sig".into()],
        };
        let open = NetworkState::empty_for("net-open");
        assert!(verify_quorum(&open, &t).is_err());
        let mut silent = NetworkState::empty_for("net-silent");
        silent.kind = NetworkKind::Silent;
        assert!(verify_quorum(&silent, &t).is_err());
    }

    #[test]
    fn verify_log_carries_topology_to_every_replayer() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, hub_a) = fixture_key(7);
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
        let mode = hubs_mode(&[&hub_a, &owner], Some(2));
        let v1 = TransitionVariant::TopologyChange { to: mode.clone() };
        let t1 = Transition {
            at: 2,
            variant: v1.clone(),
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v1, &owner_sk)],
        };
        let state = verify_log(net, &[t0, t1]).expect("owner-signed topology verifies");
        assert_eq!(state.topology, Some(mode));
        // And a non-owner's attempt fails the replay outright.
        let (mallory_sk, mallory) = fixture_key(9);
        let v2 = TransitionVariant::TopologyChange {
            to: crate::config::TopologyMode::FullMesh,
        };
        let t2 = Transition {
            at: 3,
            variant: v2.clone(),
            signers: vec![mallory.clone()],
            signatures: vec![sign_transition(net, &v2, &mallory_sk)],
        };
        let log = [
            state.transitions[0].clone(),
            state.transitions[1].clone(),
            t2,
        ];
        assert!(verify_log(net, &log).is_err());
    }

    #[test]
    fn unknown_variant_parses_but_never_verifies() {
        // A transition kind from a newer build must not break parsing —
        // roster anti-entropy carries whole logs, and 0.2.35↔0.2.36-style
        // mixed fleets have to keep converging membership — but it can't
        // be verified, so log adoption holds this node at its current
        // governance until it updates.
        let json = r#"{
            "at": 9,
            "variant": { "kind": "from_the_future", "field": true },
            "signers": ["p1"],
            "signatures": ["s1"]
        }"#;
        let t: Transition = serde_json::from_str(json).unwrap();
        assert_eq!(t.variant, TransitionVariant::Unknown);
        let gov = NetworkState::empty_for("net-x");
        assert!(verify_quorum(&gov, &t).is_err());
    }

    #[test]
    fn pre_topology_state_file_loads_with_none() {
        // State written by a build that predates governed topology.
        let json = r#"{
            "version": 2,
            "network_id": "net-a",
            "kind": "closed",
            "roles": {},
            "transitions": [],
            "pending": [],
            "splits": []
        }"#;
        let s: NetworkState = serde_json::from_str(json).unwrap();
        assert_eq!(s.topology, None);
    }

    // ---- member tier (multi-writer leaf) ------------------------------

    fn member_grant(
        net: &str,
        target: &str,
        author_sk: &SigningKey,
        author_pk: &str,
        at: u64,
    ) -> Transition {
        let v = TransitionVariant::RoleGrant {
            target: target.to_string(),
            role: Role::Member,
        };
        Transition {
            at,
            signers: vec![author_pk.to_string()],
            signatures: vec![sign_transition(net, &v, author_sk)],
            variant: v,
        }
    }

    fn member_evict(
        net: &str,
        target: &str,
        author_sk: &SigningKey,
        author_pk: &str,
        at: u64,
    ) -> Transition {
        let v = TransitionVariant::Evict {
            target: target.to_string(),
        };
        Transition {
            at,
            signers: vec![author_pk.to_string()],
            signatures: vec![sign_transition(net, &v, author_sk)],
            variant: v,
        }
    }

    fn closed_gov(net: &str, roles: &[(&str, Role)]) -> NetworkState {
        let mut gov = NetworkState::empty_for(net);
        gov.kind = NetworkKind::Closed;
        for (pk, r) in roles {
            gov.roles.insert((*pk).to_string(), *r);
        }
        gov
    }

    #[test]
    fn member_log_owner_and_manager_admits_union_merge() {
        let (owner_sk, owner) = fixture_key(1);
        let (mgr_sk, mgr) = fixture_key(2);
        let (_, a) = fixture_key(3);
        let (_, b) = fixture_key(4);
        let net = "fleet-m";
        let gov = closed_gov(net, &[(&owner, Role::Owner), (&mgr, Role::Controller)]);
        // Independent authors (owner admits A, manager admits B) — the two
        // concurrent admissions a strict-prefix log would fork on.
        let log = vec![
            member_grant(net, &a, &owner_sk, &owner, 10),
            member_grant(net, &b, &mgr_sk, &mgr, 11),
        ];
        let members = verify_member_log(&gov, &log, net);
        assert!(members.contains(&a) && members.contains(&b));
        assert_eq!(members.len(), 2);
    }

    #[test]
    fn member_log_skips_a_member_authored_admit() {
        let (_, owner) = fixture_key(1);
        let (rogue_sk, rogue) = fixture_key(5); // plain member: absent from roles
        let (_, victim) = fixture_key(6);
        let net = "fleet-m";
        let gov = closed_gov(net, &[(&owner, Role::Owner)]);
        // A non-authority's admit is skipped, not honoured — so a member can't
        // conscript identities into the closed network (the strong MOM-01 form).
        let log = vec![member_grant(net, &victim, &rogue_sk, &rogue, 10)];
        assert!(!verify_member_log(&gov, &log, net).contains(&victim));
    }

    #[test]
    fn member_log_evict_tombstones_a_prior_admit_order_independent() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, a) = fixture_key(3);
        let net = "fleet-m";
        let gov = closed_gov(net, &[(&owner, Role::Owner)]);
        let admit = member_grant(net, &a, &owner_sk, &owner, 10);
        let evict = member_evict(net, &a, &owner_sk, &owner, 20);
        // The later removal wins regardless of the order the entries arrive in.
        assert!(verify_member_log(&gov, &[admit.clone(), evict.clone()], net).is_empty());
        assert!(verify_member_log(&gov, &[evict, admit], net).is_empty());
    }

    #[test]
    fn member_log_ignores_a_non_member_grant() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, x) = fixture_key(3);
        let net = "fleet-m";
        let gov = closed_gov(net, &[(&owner, Role::Owner)]);
        // Even owner-signed, a controller grant grants no membership here: roles
        // are set by the governance log, not the member log.
        let v = TransitionVariant::RoleGrant {
            target: x.clone(),
            role: Role::Controller,
        };
        let t = Transition {
            at: 10,
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v, &owner_sk)],
            variant: v,
        };
        assert!(verify_member_log(&gov, &[t], net).is_empty());
    }

    #[test]
    fn merge_member_logs_is_commutative_and_dedups() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, a) = fixture_key(3);
        let (_, b) = fixture_key(4);
        let net = "fleet-m";
        let ga = member_grant(net, &a, &owner_sk, &owner, 10);
        let gb = member_grant(net, &b, &owner_sk, &owner, 11);
        let left = vec![ga.clone(), ga.clone()]; // includes a duplicate
        let right = vec![gb.clone()];
        let m1 = merge_member_logs(&left, &right);
        let m2 = merge_member_logs(&right, &left);
        assert_eq!(m1.len(), 2); // ga deduped + gb
        assert_eq!(m1, m2); // union is order-independent
    }

    #[test]
    fn split_member_tier_splits_then_is_idempotent() {
        let (owner_sk, owner) = fixture_key(1);
        let (_, a) = fixture_key(3);
        let net = "fleet-m";
        // Legacy single log: founder election + a member grant in `transitions`.
        let v0 = TransitionVariant::KindChange {
            to: NetworkKind::Closed,
        };
        let t0 = Transition {
            at: 1,
            signers: vec![owner.clone()],
            signatures: vec![sign_transition(net, &v0, &owner_sk)],
            variant: v0,
        };
        let mut state = NetworkState::empty_for(net);
        state.kind = NetworkKind::Closed;
        state.transitions = vec![t0, member_grant(net, &a, &owner_sk, &owner, 2)];
        split_member_tier(&mut state);
        assert_eq!(
            state.transitions.len(),
            1,
            "founder election stays in gov log"
        );
        assert_eq!(state.member_log.len(), 1, "the member grant moved out");
        // The migrated member still re-derives: roles come from the governance
        // log (founder election → owner), and the owner authored the admit.
        let gov = verify_log(net, &state.transitions).expect("gov log verifies");
        assert!(verify_member_log(&gov, &state.member_log, net).contains(&a));
        // Idempotent.
        let (gov_before, mem_before) = (state.transitions.clone(), state.member_log.clone());
        split_member_tier(&mut state);
        assert_eq!(state.transitions, gov_before);
        assert_eq!(state.member_log, mem_before);
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
