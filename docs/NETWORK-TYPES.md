# Network types: open and closed

**Status: design — not yet implemented.** `PROPOSED` markers below
flag default choices awaiting confirmation; everything else is the
agreed model. See [Open questions](#open-questions) at the bottom
for the four decisions reviewers should sign off before any code
lands.

## Why

A MyOwnMesh network defaults to permissive: anyone holding the
network id can knock, and once approved by any current member they
become a peer with equal authority. That's right for friend-mesh
and most MyOwnLLM deployments today. It's wrong for an office mesh
where ten people share infrastructure they don't all administer —
one member shouldn't be able to add a stranger to the org's mesh.

Closed networks add role-based authority on top of the same roster
file. `open` is the default and still does what it does today;
closed networks layer onto the same primitives without forking the
embedder API.

## Two kinds

| Kind | Who can add to the roster | Roster sync |
|---|---|---|
| `open`   | any current member | gossip with merge |
| `closed` | controllers + owners (members may *propose*) | controllers/owners author; gossip with merge |

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
round and the delete would never converge. `PROPOSED — Merkle-root
+ tombstones, not OR-Set CRDT. Simpler, matches the current append-
mostly file shape, and the partition risk in a friend-mesh is low.`

## Closed networks

Same gossip, but only roster proposals **signed by an authorised
role** are merged. A peer holding `controller` signs a proposal to
add a `member`; everyone receiving the proposal verifies the
signature against the proposer's authority *at the proposer's
view of the network state*.

Members that can't write to the roster can still **propose** an
addition (signed by the proposer + the candidate) and surface it as
an Approval-tab entry on every controller/owner; the addition lands
when an authorised role co-signs.

### Role bootstrapping

A node creating a closed network self-elects `owner` and lists
itself as the sole roster entry. The network's `network_state.json`
carries the kind (`closed`) and the initial owner list, both signed
under `SIGN_DOMAIN_TAG_STATE = "myownmesh-network-state-v1:"` by
the founder.

From that point forward:

- New `controller` grants need ≥1 `owner` signature.
- New `owner` grants need every current owner's signature.
- Removals of any role need the same authority as additions of that
  role.

## Network-kind transitions

A network's kind can change at runtime. The transition is itself a
signed state-update appended to the per-network state log.

| From | To | Authority |
|---|---|---|
| `open`   | `closed` | every current member must sign (= unanimous member consent) |
| `closed` | `open`   | every current owner must sign |

Each transition appends to `network_state.json`'s transition log:

```jsonc
{
  "version": 1,
  "kind": "closed",
  "transitions": [
    {
      "to": "closed",
      "at": "@1718000000",
      "signers":    ["<owner_pubkey>", "<member_pubkey>", "..."],
      "signatures": ["<base32 sig>", "<base32 sig>", "..."]
    }
  ]
}
```

Verification: a peer accepts a `network_state` from another peer
only when the chain of transitions back to the founder is fully
signed by the right authorities at each step.

### Quorum for "unanimous member consent"

A strict unanimous-of-currently-rostered rule deadlocks every time
one device is offline. `PROPOSED — unanimous-of-online at proposal
time, plus an automatic "do you agree to the close that happened
while you were offline?" prompt on the next online of each missing
signer. The closer's view is "pending" until every offline member
either signs or denies; if any denies, the transition is invalidated
and the network reverts to "open" from that peer's signed view.`

The deny case is the interesting edge: a denying member produces a
*signed* `network_state_ack { decision: "deny" }`, which the closer
must accept. The closer's local view then rewinds to open and
removes the pending close from the transition log. This means the
window between "close proposed" and "all offline members back
online" carries some uncertainty — the UX surfaces this with a
`pending` badge and disables operations that depend on the chosen
state (e.g. role-restricted approvals) until the quorum resolves.

## Forks (rogue-close scenarios)

A peer that locally writes `kind = closed` and tries to push it
without the unanimous signoff produces a signed `network_state` that
fails verification on every other member. Two things happen:

1. **Non-signers ignore the would-be close.** They keep treating
   the network as `open` and continue peering with the rogue node.
2. **The Activity log surfaces the attempt.** Every member sees
   `peer X proposed close — rejected (you did not sign)`, and X's
   row in the Connections tab carries a small `!` warning badge
   that persists until the user dismisses it.

`PROPOSED — non-signers continue to peer with the rogue, treating
its close-proposal as advisory. The alternative (hard-partition
non-signers) is safer if you assume the close-attempt is
adversarial, but breaks the friend-mesh case where someone's GUI
glitch published a stale state — and "potential threats" in the
spec is about visibility, not isolation.`

The rogue node's *own* view says the network is closed and only it
is an owner; data channels to peers that don't recognise its closed
state will keep working at the peer level, but the rogue's UI will
show "1 peer in this closed network" while every honest member's
UI will show the rogue under its open network with the
rejected-close badge. Two ground truths, neither hidden.

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
- **Rejected-close warning.** Peers who pushed a close that didn't
  pass surface with a small `!` badge in the Connections tab until
  the user dismisses or removes them.
- **Role chip on Connections row.** Every peer row in a closed
  network carries an `owner` / `controller` / `member` chip so the
  local user can see at a glance who can do what.

## Wire protocol

Net-new message kinds, all gated by the `network_state_v1` feature
flag so old peers (and bare-MyOwnLLM peers on the pre-closed-network
build) silently ignore them. `PROPOSED — net-new wire kinds rather
than a generic signed-event channel. Closer to the existing
discriminated-kind shape in` [`PROTOCOL.md`](PROTOCOL.md)`; the
generic-channel path becomes worthwhile only when we have a second
feature riding the same envelope.`

| Kind | Direction | Purpose |
|---|---|---|
| `network_state` | broadcast on ACTIVE | "This is what I think the network looks like." Carries `kind`, transition log, and the roster Merkle root. |
| `network_state_propose` | targeted | "I propose this transition" — closed-network kind change or role grant. Signed by the proposer. |
| `network_state_ack` | targeted | "I sign / deny your proposal." Co-signature by another authorised role; the `decision` field is `"sign"` or `"deny"`. |
| `roster_summary` | broadcast on ACTIVE | Merkle root + count + last-edit-ts of the sender's current roster view. |
| `roster_request` | targeted | "Send me the entries under hash X." Merkle-tree diff walk. |
| `roster_entries` | targeted | The requested entries; receiver merges into local roster after authority verification. |

Domain-separation tag for state signatures:
`SIGN_DOMAIN_TAG_STATE = "myownmesh-network-state-v1:"`, distinct
from the per-peer auth tag `myownmesh-mesh-auth-v1:` so a handshake
signature cannot be replayed as a state-transition signature or
vice-versa.

## Open questions

These are the four decisions the design depends on. The `PROPOSED`
default in each section is my recommendation; reviewers should
confirm or push back before turning any of this into code.

1. **Roster sync algorithm.** `PROPOSED:` Merkle-root + tombstones.
   `Alt:` OR-Set CRDT (delete-safe across partitions, heavier wire,
   different file shape).
2. **Quorum for "unanimous member consent" on open→closed.**
   `PROPOSED:` unanimous-of-online with offline backfill on
   reconnect. `Alts:` strict-unanimous-of-rostered (offline =
   blocks), or M-of-N owners after bootstrap (no unanimous needed).
3. **Fork visibility.** `PROPOSED:` soft fork — non-signers ignore
   the close and keep peering, with the rejected-close badge as
   feedback. `Alt:` hard partition — non-signers refuse data-channel
   traffic with the rogue.
4. **Wire shape.** `PROPOSED:` net-new message kinds. `Alt:`
   generic signed-event channel (`network_event { topic, payload,
   sig }`) that this layer rides on.

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

## Implementation notes (non-binding)

When this becomes code, the touch points are:

- `crates/myownmesh-core/src/roster.rs` — add a `role` field to
  `AuthorizedPeer` (default `Member` for backward-compat), the
  Merkle-root helper, and tombstone handling.
- `crates/myownmesh-core/src/protocol/` — net-new message kinds
  above, gated by `features::network_state_v1`.
- `crates/myownmesh-core/src/` (new) `network_state.rs` — the
  `NetworkState` struct, transition log, signature verification.
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

None of that is committed by this design doc — the doc is the
contract, the code lands in a follow-up PR once the four questions
above are settled.
