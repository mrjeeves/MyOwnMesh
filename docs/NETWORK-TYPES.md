# Network types: open and closed

**Status: implemented and shipped.** Types live in
[`crates/myownmesh-core/src/network_state.rs`](../crates/myownmesh-core/src/network_state.rs);
wire frames are in
[`crates/myownmesh-core/src/protocol/`](../crates/myownmesh-core/src/protocol/);
the engine enforces authority on every inbound `network_state_*`
frame and surfaces quorum-violating proposals as diag entries; the
`JoinedNetwork` handle exposes propose / sign / deny / split. The
ratify + deny lifecycle is exercised end-to-end in
[`tests/closed_network_governance.rs`](../crates/myownmesh-core/tests/closed_network_governance.rs).
This doc remains the contract; the four foundational decisions
(sync algorithm, deadlock resolution, fork semantics, wire shape)
are settled — see [Decisions](#decisions) at the bottom.

## Why

A MyOwnMesh network defaults to permissive: anyone holding the
network id can knock, and once approved by any current member they
become a peer with equal authority. That's right for a friend-mesh
and most small deployments. It's wrong for an office mesh
where ten people share infrastructure they don't all administer —
one member shouldn't be able to add a stranger to the org's mesh.

Closed networks add role-based authority on top of the same roster
file. `open` is the default and still does what it does today;
closed networks layer onto the same primitives without forking the
embedder API.

## Enforcement is at the network layer

Authority — who can add to the roster, who can change the kind, who
can grant roles — is enforced **at the engine / daemon level**, not
in any one client. The `network_state.json` sibling file is a signed
log: every transition (kind change, role grant, role revoke, split)
carries the ed25519 signatures of the members whose authority makes
it valid. A peer that receives a `network_state_propose` it didn't
ask for, or whose signer set doesn't satisfy the quorum table for
its operation, drops the frame at the protocol layer. On a closed
network the unsigned `roster_entries` gossip carries no authority at
all — membership rides two signed logs (see [Closed
networks](#closed-networks-a-two-log-cert-chain)). A member-add is a
signed entry in the member log; a member who gossips a roster entry, or
who tries to author a controller-add, produces something that fails
verification on every honest receiver.

The GUI's role checks (`canGrant()`, the disabled role-radio
buttons, the propose-close button gating) are convenience —
keeping a user from issuing a request the engine would just reject.
A determined adversary holding the control socket can bypass the
GUI; what they can't bypass is the cryptographic verification on
the other side. **The wire, not the UI, is the security boundary.**

Both halves have shipped: the daemon signs, broadcasts, verifies,
and persists `network_state_*` frames, and the GUI's Governance tab
drives them over the control socket. Roster membership converges by
anti-entropy gossip — each node advertises a compact membership root
and pulls only what it's missing — so a member approved on one device
propagates to the rest of the network rather than living on one box.

## Two kinds

| Kind | Who can add to the roster | Roster sync |
|---|---|---|
| `open`   | any current member | gossip with merge |
| `closed` | owners, managers (controllers); members may *propose* | two signed logs (governance + member); unsigned gossip ignored |

Network kind is part of the per-network state — signed (alongside
the role assignments and the transition log) by everyone who has
consented to it. A peer learns its view of the network from this
signed state, not from a flag in local config.

## Three roles in a closed network

| Role | Authority |
|---|---|
| **owner**      | Add/remove owners, controllers, members. Approve network-kind transitions. |
| **controller** | Add/remove members. Cannot grant `controller` or `owner`. |
| **member**     | No roster authority. May *propose* additions for an owner/controller to approve. |

Roles live as a tag on each roster entry, not as separate files. The
existing `~/.myownmesh/mesh/rosters/{network_id}.json` carries every
peer with their role; closed networks add a sibling
`~/.myownmesh/mesh/states/{network_id}.json` for the kind + signed
transition log.

In an `open` network the role tag is always `member` and is unused
by the engine — it's there so a future open→closed transition
doesn't need to migrate the file shape.

## Open networks

Roster gossip on every connection: each peer carries a Merkle root
over its sorted-by-pubkey roster, and exchanges a `roster_summary`
frame on ACTIVE transition (root, count, last-edit timestamp). When
the roots disagree, a diff walk fetches the entries that differ —
see [Wire protocol](#wire-protocol).

Deletes are tombstones (entry with `tombstoned_at` timestamp,
expires after `TOMBSTONE_TTL`). Without tombstones, a peer who
didn't see your delete would re-add the entry on the next gossip
round and the delete would never converge.

## Closed networks: a two-log cert chain

A closed network's membership is **entirely signed** — it does NOT
trust unsigned roster gossip, not even from a controller/owner. The
`entries` in a `roster_entries` frame are ignored on a closed network;
membership is re-derived from two signed logs that together form a
certificate chain rooted at the founder:

| Section | What it holds | Who signs | Convergence |
|---|---|---|---|
| **governance log** (`transitions`) | kind changes, **owner** + **manager** (controller) grants/revokes/evicts, splits | ≥ 1 **owner** for an owner grant/revoke; ≥ 1 **controller or owner** for a manager grant/revoke (flat peer authority, single-signer) | strict-prefix-extend: a peer can only *extend* the shared prefix, never rewrite the genesis (and the owner it elected) |
| **member log** (`member_log`) | per-member admit/remove entries | any one owner/manager (≥1 authority) | **union-merge**: every distinct entry from either side is kept, deduped by content; latest-per-device wins (removals are tombstones) |

This is the cert chain in motion: the **owner** is the root and issues
**managers** (governance log); a **manager** issues **members** (member
log). Every member re-verifies the whole chain from genesis —
`verify_log` for the governance log, `verify_member_log` for the member
log — so authority over the *messenger* is never authority over the
*data*. The data itself must be signed by the right tier: a member who
gossips a roster entry, or a manager who tries to grant `controller` in
the member log, produces something every honest peer ignores.

**Why two logs.** Owner and manager changes are rare and sit at the
root/intermediate tiers of the cert chain, so the governance log is a
single strict-prefix chain and a fork is rejected outright. (Authority
there is still flat and single-signer — any owner mints owners, any
manager mints managers — the strict-prefix shape is about ordering the
rare high-tier changes, not about requiring a quorum.) Member changes are
frequent and **multi-writer**: two managers, each
offline, can admit different members at the same time. A strict-prefix
log would fork on that and neither side would adopt the other; the
union-merged member log keeps both admissions and converges with no
fork. Per-device identity keys throughout — being admitted to a role
adds *your* pubkey to that tier's authorized signer set and you sign
with your own key, so there are no shared secrets to leak or rotate and
every change is attributable to a specific device.

Members that can't write to the roster can still **propose** an addition
and surface it as an Approval-tab entry on every controller/owner; the
addition lands when an authorised role signs it into the member log.

### Role bootstrapping

A node creating a closed network self-elects `owner` and lists
itself as the sole roster entry. The network's `network_state.json`
carries the kind (`closed`) and the initial owner list, both signed
under `SIGN_DOMAIN_TAG_STATE = "myownmesh-network-state-v1:"` by
the founder.

From that point forward:

- New `controller` (manager) grants need ≥1 `owner` signature, and
  ride the **governance log**.
- New `owner` grants need every current owner's signature, on the
  governance log.
- **Member admits ride the member log**: a single owner/manager signs
  the admit and the union-merged member log converges it to everyone —
  see [Closed networks](#closed-networks-a-two-log-cert-chain).
- Removals of any role need the same authority as additions of that
  role (a member removal is a tombstone in the member log; an
  owner/manager removal rides the governance log).

## Network-kind transitions

A network's kind can change at runtime. The transition is itself a
signed state-update appended to the per-network state log.

| From | To | Authority |
|---|---|---|
| `open`   | `closed` | founder self-election — `signers.first()` becomes owner (≥ 1 signer; co-signing allowed) |
| `closed` | `open`   | ≥ 1 owner |

Founding a closed network is a **founder self-election**: `signers.first()`
becomes the owner, and everyone already present in the open network becomes
a plain `member` of the closed one (ownership is then distributed via
peer-authority owner grants, so the network never depends on the founder
staying online). It is *not* a consent vote — the founder needs no one
else's signature.

Genesis is **multi-signer capable**: because a peer mesh can't assume a
single always-online founder, a close may be co-signed, and `verify_log`
accepts any non-empty signer set (electing the first). What it does *not*
do is try to prove "unanimous consent" — a converging peer replays from an
empty member set and can't reconstruct who else was present, so genesis
authority rests on the elected founder alone, not on a headcount. This is
what keeps the whole log verifiable by anyone who later pulls it.

Each transition appends to `network_state.json`'s transition log:

```jsonc
{
  "version": 2,
  "kind": "closed",
  // Governance log (root + manager tiers): kind changes, owner and
  // manager grants/revokes/evicts, splits. Strict-prefix-extend.
  "transitions": [
    {
      "variant": { "kind": "kind_change", "to": "closed" },
      "at": 1718000000,
      "signers":    ["<founder_pubkey>"],
      "signatures": ["<base32 sig>"]
    }
  ],
  // Member log (leaf tier): per-member admits/removes, each signed by a
  // single owner/manager. Union-merged across peers, so two managers'
  // concurrent offline admits both survive.
  "member_log": [
    {
      "variant": { "kind": "role_grant", "target": "<member_pubkey>", "role": "member" },
      "at": 1718000100,
      "signers":    ["<manager_pubkey>"],
      "signatures": ["<base32 sig>"]
    }
  ]
}
```

Verification: a peer accepts a `network_state` from another peer
only when the chain of transitions back to the founder is fully
signed by the right authorities at each step.

### Founding is immediate — there is no stalled close

Because founding needs no co-signers, a close never stalls. The founder
publishes `network_state_propose { transition: { to: "closed" } }`,
self-signs, and it ratifies **at once** on the founder and converges to
every other peer via gossip — each adopts the genesis (electing
`signers.first()`) without being asked to co-sign. A closed network's
identity is its
`network_id` (at the app layer, derived from a shared key) plus the
members on its signed roster — never its display label. Two unrelated
closed networks may carry the same human name; they never collide,
because convergence is on the key-derived id and the roster, not the
name. There is no consent round, no pending
Approvals card for a close, and therefore no "some members are still
silent" state to resolve. (A *deny* still applies to a proposal the
proposer can't authorize alone — e.g. a **member** proposing an admission
for an owner/manager to co-sign — just not to founding, which the founder
signs by itself.)

> **Legacy note (split fallback).** Earlier revisions required *unanimous
> member consent* to close, with a timeout-driven **split** fallback for
> when signatures stalled: after `STATE_PROPOSAL_TIMEOUT_S` the would-be
> owner published `network_state_split` to spawn a derived closed network
> from the signers gathered so far. Single-signer founding removes the
> stall that fallback existed for, so **the close path no longer triggers
> a split.** The split primitive still lives in the codebase (its wire
> type `network_state_split` and the deterministic id derivation below are
> unchanged) but is no longer reached via close; removing or repurposing
> it is a follow-up, not a behaviour this path relies on.

### Split id derivation (retained)

A split spawns a **new** network rather than mutating the original. Its
id is derived deterministically from the original's id and the signer set:

```
new_network_id = base32_lowercase(SHA-256(
    "myownmesh-split-v1:" ||
    original_network_id   ||
    "|" || sorted_signer_pubkeys_joined("|")
))
```

The closer becomes the new network's founder-owner; the original
network is untouched. Members who didn't sign stay where they are,
in the original network, under its existing rules — they're not
ejected, demoted, or otherwise harmed. They simply aren't members
of the new closed network.

The new network shares signaling discovery with the original (same
Trystero app id; the derived `new_network_id` lands in a sibling
Nostr room), so members who join both see both in their network
list. Peer connections established under the original network keep
working — see [Forks](#forks-governance-not-connectivity).

## Forks: governance, not connectivity

A fork is what happens when not everyone agrees on the rules. It
is **only a matter of controlling power dispute** — never a
suggestion to members about whether they should drop the private
connections that the network's signaling layer originally brought
them together over.

Concretely:

- The roster, the kind, the transition log, and the role
  assignments are **per-network** state. A fork means two networks
  exist with overlapping membership but distinct state.
- Peer-to-peer data channels, RPCs, and typed channels live at the
  **peer layer**, below the network layer. Two peers that are both
  in network *A* and that have an active connection don't lose it
  because one of them later joins network *A-split* and the other
  doesn't.

So the practical model after a split:

- Alice closes-via-split with Bob + Carol. They're now members of
  the new closed network *N'*.
- Dave was offline. He comes back to find the original network *N*
  unchanged in his roster, and a new network *N'* in his
  "available to join" list (advertised by Alice in *N*'s gossip).
- Dave, Alice, Bob, Carol can all still talk to each other over
  any channel established in *N* — those connections are theirs,
  not the network's.
- If Dave wants the closed-network governance, he asks an owner
  of *N'* to add him.

### What does that mean for "potential threats"?

Visibility, not isolation. The Activity log surfaces every
split-spawn (`network *N'* spawned from *N* by Alice with [Bob,
Carol] — you are not a member`) and Dave's *N* view shows Alice's
row carrying a small chip indicating "also runs *N'*". Dave can
choose to drop his connections to Alice or remove her from *N*'s
roster (under *N*'s open rules he has authority to do so for
himself) — but the engine doesn't do it for him. A split is not
an attack; it's a choice the engine surfaces honestly.

The only case the engine *does* refuse outright is an unsigned
`network_state` claim — i.e. someone publishing a transition log
that doesn't verify against the chain of authorities. Those frames
are dropped silently at the protocol layer and logged as
`malformed network_state from <peer> — signature chain broken`.
That's not a fork; that's just a bad frame.

## UX requirements

- **Approve dialog.** When the local node has authority to grant a
  role (always in open networks; `owner`/`controller` in closed
  networks), the approve UI surfaces three radio options —
  **Member** / **Controller** / **Owner** — with the levels above
  the local node's authority disabled and a one-line "why disabled"
  hint.
- **Network row badge.** Every place a network name renders
  (sidebar, settings overlay, GUI graph header) carries a tiny icon
  next to the name: `open` = open-padlock outline, `closed` =
  filled-padlock. Hover reveals the local node's role within that
  network.
- **Pending state-transition banner.** When a `network_state`
  proposal is in flight (e.g. an open→closed close awaiting your
  signature), the network row shows an amber dot and the Approvals
  tab gets a "Network kind change requested by X" card with the
  proposed state diff inline. Approve / Deny live there.
- **Split spawned card.** When a `network_state_split` arrives for
  a network you're in but didn't sign, the Approvals tab gets a
  "*N'* spawned from *N* by X (without your signature)" card. It's
  informational; the call-to-action is "Join *N'*" (asks an owner
  to add you) or "Dismiss". The original network is unaffected.
- **"Also runs *N'*" peer chip.** In the original network's
  Connections tab, peers who joined a split spawned from this
  network carry a small chip noting the derived network's short
  id. Hover reveals the full id and the signer list. Visibility,
  not isolation.
- **Role chip on Connections row.** Every peer row in a closed
  network carries an `owner` / `controller` / `member` chip so the
  local user can see at a glance who can do what.

## Wire protocol

Net-new message kinds, all gated by the `network_state_v1` feature
flag so old peers (and bare-MyOwnLLM peers on the pre-closed-network
build) silently ignore them.

| Kind | Direction | Purpose |
|---|---|---|
| `network_state` | broadcast on ACTIVE | "This is what I think the network looks like." Carries `kind`, the governance-log length, the **member-log length**, and the roster Merkle root — a receiver behind on *either* log (or on membership) pulls. |
| `network_state_propose` | targeted | "I propose this transition" — closed-network kind change or role grant. Signed by the proposer. |
| `network_state_ack` | targeted | "I sign / deny your proposal." Co-signature by another authorised role; the `decision` field is `"sign"` or `"deny"`. |
| `network_state_split` | targeted | "Stuck close — I'm spawning a derived closed network from the signers I have." Signed by the proposer + every signer who's opted in. Receivers verify, then add the new network to their available-to-join list. |
| `roster_summary` | broadcast on ACTIVE | Merkle root + count + last-edit-ts of the sender's current roster view. |
| `roster_request` | targeted | "Send me the entries under hash X." Merkle-tree diff walk. |
| `roster_entries` | targeted | The roster entries **plus both signed logs** (governance + member). On an `open` network the receiver merges the entries; on a `closed` network the entries are ignored and membership is re-derived from the logs — governance strict-prefix-extend, member union-merge. |

Domain-separation tag for state signatures:
`SIGN_DOMAIN_TAG_STATE = "myownmesh-network-state-v1:"`, distinct
from the per-peer auth tag `myownmesh-mesh-auth-v1:` so a handshake
signature cannot be replayed as a state-transition signature or
vice-versa.

## Decisions

The four foundational choices, settled:

1. **Roster sync algorithm — Merkle-root + tombstones.** Simpler
   than OR-Set CRDT, matches the existing append-mostly roster
   file shape, and the partition risk in the deployments this
   targets (friend-mesh / office-mesh) is low.
2. **Founding a closed network — founder self-election.**
   `signers.first()` signs `to: "closed"` and becomes owner; peers
   already present become plain members, and ownership spreads from
   there via peer-authority grants so the mesh never leans on the
   founder being online. Genesis is multi-signer capable (a close may
   be co-signed), but authority rests on the elected founder, not on a
   consent headcount — so a close never stalls and needs no consent
   round. *(Superseded design: founding once required
   unanimous member consent with a would-be-owner-initiated
   **split** fallback after `STATE_PROPOSAL_TIMEOUT_S` when
   signatures stalled. That stall can't happen under single-signer
   founding, so the split fallback is no longer on the close path —
   the `network_state_split` primitive remains in the code pending a
   follow-up cleanup.)*
3. **Forks are governance scope, not connectivity scope.** A
   fork's existence does not break the peer connections that the
   original network's signaling brought together. Two peers in
   network *N* who end up on opposite sides of an *N → N'* split
   keep their data channels, their channels, and their RPCs.
   "Threats" are surfaced (Activity log, peer chip noting "also
   runs *N'*"), not enforced (no auto-disconnect, no
   hard-partition).
4. **Wire shape — net-new message kinds.** Discriminated-kind
   matches the existing protocol shape; a generic signed-event
   envelope is worth doing only once a second feature wants the
   same plumbing.

## Out of scope for this design

- **Role-level capability matrix** (e.g. "owners can edit signaling
  relays, controllers cannot"). v1 ties `owner` to "can manage
  roster + transitions"; finer ACL lives in a follow-up.
- **Cross-network role transfer.** Each network's role state is
  independent; an `owner` in one network is a `member` in another
  unless granted there too.
- **Out-of-band invitation links** (signed deep-links that bootstrap
  a roster addition without an existing member online). Worth doing
  but layers above this design.
- **Membership expiry / time-bounded grants.** Roster entries are
  permanent until explicitly removed.
- **Founder recovery.** If the sole owner of a closed network loses
  their identity file, the network is unrecoverable without an
  out-of-band reset. A "recovery key" mechanism is a follow-up.

## Implementation map

This feature is implemented and shipped; the touch points across the
code are:

- `crates/myownmesh-core/src/roster.rs` — add a `role` field to
  `AuthorizedPeer` (default `Member` for backward-compat), the
  Merkle-root helper, and tombstone handling.
- `crates/myownmesh-core/src/protocol/` — net-new message kinds
  above, gated by `features::network_state_v1`.
- `crates/myownmesh-core/src/` (new) `network_state.rs` — the
  `NetworkState` struct, transition log, signature verification,
  and the `derive_split_network_id()` helper.
- `crates/myownmesh-core/src/handle.rs` — `Mesh::join_split()` for
  the "I want in on the spawned derived network" flow; the
  signaling subsystem already discovers the new id via the
  original network's gossip.
- `crates/myownmesh-core/src/dirs.rs` — `states_dir()` for the new
  per-network signed-state files.
- `crates/myownmesh-core/src/engine/` — gossip driver for
  `roster_summary` exchanges + diff walks; signature check on every
  inbound `network_state_propose`.
- GUI: padlock badges in `gui/src/`, role chips on peer rows, the
  Approvals card variant for network-kind changes.
- `docs/PROTOCOL.md` — document the new message kinds + the new
  domain tag.
- `crates/myownmesh-core/src/lib.rs` — export
  `SIGN_DOMAIN_TAG_STATE`, `NetworkKind`, `Role`.

All of the above is implemented and shipped; this document remains the
design contract those changes follow.
