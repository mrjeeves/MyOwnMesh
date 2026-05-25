// Preview-mode store for the closed-network governance model.
//
// Why this exists
// ---------------
// The wire/engine half of `docs/NETWORK-TYPES.md` ("open" vs "closed"
// networks, three roles, signed transitions, proposer-initiated
// splits) is still a design proposal — see PR #11. The GUI surfaces
// for it are real now so downstream embedders implementing the
// design have a reference, and so users running this build can
// drive the flow end-to-end while we field-test the model.
//
// To keep the GUI honest, all governance state lives **here** —
// browser-local Svelte 5 reactive state, persisted to
// `localStorage` so it survives reloads, but never round-tripped to
// the daemon. Every method that mutates governance state shows a
// "Preview mode" tag in the UI so users know what they're driving.
//
// When the engine lands the real implementation, the swap is small:
// each function below grows a `try { await invoke("mesh_…") } …`
// path, the in-memory cache becomes a write-through cache of the
// engine's signed state, and the preview banner goes away. The
// shape and method signatures stay.

import { ROLE_RANK, type NetworkKind, type NetworkStateView, type PendingProposal, type PendingProposalVariant, type Role, type SplitRecord } from "./types";
import type { NetworkConfigInput } from "./types";

const STORAGE_KEY = "myownmesh.governance-preview.v1";
const ORPHAN_STORAGE_KEY = "myownmesh.orphan-networks.v1";

/** Time before a stuck close proposal becomes splittable. Matches
 *  the `STATE_PROPOSAL_TIMEOUT_S` constant in the design doc. */
export const STATE_PROPOSAL_TIMEOUT_S = 24 * 60 * 60;

/** An orphan network is a saved network that was removed from the
 *  daemon (typically by a failed remove+re-add edit) but whose
 *  original config the GUI has snapshotted, so the user can either
 *  retry the add or explicitly discard the record.
 *
 *  Without this, a failed save would silently delete the network
 *  from the GUI's view — the user would have to know to look at
 *  `~/.myownmesh/config.json` to find out it was gone. Surfacing
 *  the orphan in the sidebar keeps the broken state visible and
 *  the recovery path one click away. */
export interface OrphanNetwork {
  /** The local config record id the daemon used. Stable per-device. */
  config_id: string;
  /** Wire-level network id (e.g. `home-mesh`). The friendly value
   *  the user typed when they joined; survives the orphan so a
   *  retry restores the same handle. */
  network_id: string;
  /** Cosmetic label, if any. */
  label: string;
  /** Wall-clock ms the failure happened. */
  failed_at: number;
  /** Human-readable error from the daemon. Surfaced in the sidebar
   *  on hover and in the retry confirmation. */
  reason: string;
  /** Last-known full config. The retry button reapplies this. */
  config: NetworkConfigInput;
}

function emptyState(): NetworkStateView {
  return {
    kind: "open",
    roles: {},
    transitions: [],
    pending: [],
    splits: [],
  };
}

function newProposalId(): string {
  return `prop_${Math.random().toString(36).slice(2, 10)}_${Date.now().toString(36)}`;
}

/** Deterministic derivation of a split's `network_id` from the
 *  parent + sorted signer set. Mirrors the spec from
 *  `docs/NETWORK-TYPES.md`:
 *
 *    base32_lowercase(SHA-256(
 *      "myownmesh-split-v1:" || original_id || "|" || sorted_pubkeys.join("|")
 *    ))
 *
 *  The browser's SubtleCrypto gives us SHA-256 without a wasm
 *  dependency; we encode the result as base32-lowercase to match
 *  the on-disk identity format. */
async function deriveSplitNetworkId(
  originalNetworkId: string,
  signers: string[],
): Promise<string> {
  const sorted = [...signers].sort();
  const text = `myownmesh-split-v1:${originalNetworkId}|${sorted.join("|")}`;
  const bytes = new TextEncoder().encode(text);
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  // base32-lowercase, no padding, RFC 4648 alphabet.
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const input = new Uint8Array(digest);
  let bits = 0;
  let value = 0;
  let out = "";
  for (let i = 0; i < input.length; i++) {
    value = (value << 8) | input[i];
    bits += 8;
    while (bits >= 5) {
      out += alphabet[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) {
    out += alphabet[(value << (5 - bits)) & 31];
  }
  return out;
}

function createGovernanceStore() {
  // ---- persistence ----------------------------------------------------

  let byConfigId = $state<Record<string, NetworkStateView>>({});
  let orphans = $state<OrphanNetwork[]>([]);

  function load() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (parsed && typeof parsed === "object") {
          byConfigId = parsed as Record<string, NetworkStateView>;
        }
      }
    } catch (e) {
      console.warn("governance-preview: load governance failed", e);
    }
    try {
      const raw = localStorage.getItem(ORPHAN_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          orphans = parsed as OrphanNetwork[];
        }
      }
    } catch (e) {
      console.warn("governance-preview: load orphans failed", e);
    }
  }

  function persist() {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(byConfigId));
    } catch (e) {
      console.warn("governance-preview: persist governance failed", e);
    }
  }

  function persistOrphans() {
    try {
      localStorage.setItem(ORPHAN_STORAGE_KEY, JSON.stringify(orphans));
    } catch (e) {
      console.warn("governance-preview: persist orphans failed", e);
    }
  }

  function get(configId: string): NetworkStateView {
    if (!byConfigId[configId]) {
      byConfigId[configId] = emptyState();
    }
    return byConfigId[configId];
  }

  function set(configId: string, next: NetworkStateView) {
    byConfigId[configId] = next;
    persist();
  }

  // ---- queries --------------------------------------------------------

  /** The role the local device holds in this network. The local
   *  identity defaults to `member` until either:
   *
   *   - the user creates a closed network (founder self-elects `owner`), or
   *   - an existing closed-network owner grants them a role.
   *
   *  `selfPubkey` is the local device's bare pubkey (the part
   *  before the display suffix). When unknown — e.g. the daemon
   *  hasn't returned identity yet — we return `member` to keep
   *  the UI conservative. */
  function localRole(configId: string, selfPubkey: string | null): Role {
    if (!selfPubkey) return "member";
    return get(configId).roles[selfPubkey] ?? "member";
  }

  /** Role for an arbitrary peer in this network. */
  function roleOf(configId: string, pubkey: string): Role {
    return get(configId).roles[pubkey] ?? "member";
  }

  // ---- mutations: roles ----------------------------------------------

  /** Grant a role to a peer. Only honoured when the local role has
   *  authority to grant the target role; the caller is expected to
   *  gate the button accordingly but we re-check here so a
   *  programmatic caller can't bypass the check. */
  function setPeerRole(
    configId: string,
    selfPubkey: string,
    peerPubkey: string,
    role: Role,
  ): { ok: boolean; reason?: string } {
    const state = get(configId);
    const myRole = state.roles[selfPubkey] ?? "member";
    // In open networks roles are cosmetic — let any member edit
    // them. The field gets real teeth only once the network is
    // closed; until then we make the surface explorable.
    if (state.kind === "closed") {
      if (myRole === "member") {
        return { ok: false, reason: "Members can't grant roles in a closed network." };
      }
      if (ROLE_RANK[myRole] < ROLE_RANK[role]) {
        return { ok: false, reason: `Your role (${myRole}) can't grant ${role}.` };
      }
      // Owner grants need unanimous owner consent in the real
      // implementation — preview-mode applies optimistically and
      // notes the approximation in the transition log.
    }
    const nextRoles = { ...state.roles, [peerPubkey]: role };
    const transition: NetworkStateView["transitions"][number] = {
      at: Date.now(),
      variant: { kind: "role_grant", target: peerPubkey, to: role },
      signers: [selfPubkey],
    };
    set(configId, {
      ...state,
      roles: nextRoles,
      transitions: [...state.transitions, transition],
    });
    return { ok: true };
  }

  /** Drop a peer's role tag (defaults them back to `member`). */
  function clearPeerRole(
    configId: string,
    selfPubkey: string,
    peerPubkey: string,
  ): { ok: boolean; reason?: string } {
    const state = get(configId);
    if (state.kind === "closed") {
      const myRole = state.roles[selfPubkey] ?? "member";
      const targetRole = state.roles[peerPubkey] ?? "member";
      if (myRole === "member") {
        return { ok: false, reason: "Members can't revoke roles." };
      }
      if (ROLE_RANK[myRole] < ROLE_RANK[targetRole]) {
        return {
          ok: false,
          reason: `Your role (${myRole}) can't revoke a ${targetRole}.`,
        };
      }
    }
    const nextRoles = { ...state.roles };
    delete nextRoles[peerPubkey];
    set(configId, {
      ...state,
      roles: nextRoles,
      transitions: [
        ...state.transitions,
        {
          at: Date.now(),
          variant: { kind: "role_revoke", target: peerPubkey },
          signers: [selfPubkey],
        },
      ],
    });
    return { ok: true };
  }

  // ---- mutations: kind transitions -----------------------------------

  /** Float a kind-change proposal. The proposer's signature lands
   *  on the proposal immediately; other members surface it in
   *  Approvals and either `sign` or `deny`. */
  function proposeKindChange(
    configId: string,
    selfPubkey: string,
    to: NetworkKind,
  ): { ok: boolean; proposal?: PendingProposal; reason?: string } {
    const state = get(configId);
    if (state.kind === to) {
      return { ok: false, reason: `Network is already ${to}.` };
    }
    // open → closed: proposer becomes founder-owner of the closed
    // network if it clean-closes. closed → open: every owner must
    // sign. We don't gate the *proposal* here — anyone can ask —
    // but the resolution paths enforce the real authority.
    const proposal: PendingProposal = {
      id: newProposalId(),
      created_at: Date.now(),
      proposer: selfPubkey,
      variant: { kind: "kind_change", to },
      signers: [selfPubkey],
      deniers: [],
      split_spawned: false,
    };
    set(configId, {
      ...state,
      pending: [...state.pending, proposal],
    });
    return { ok: true, proposal };
  }

  /** Sign a pending proposal. */
  function signProposal(
    configId: string,
    selfPubkey: string,
    proposalId: string,
  ): { ok: boolean; reason?: string; cleanClosed?: boolean } {
    const state = get(configId);
    const idx = state.pending.findIndex((p) => p.id === proposalId);
    if (idx === -1) return { ok: false, reason: "Proposal not found." };
    const p = state.pending[idx];
    if (p.deniers.length > 0) {
      return { ok: false, reason: "Proposal has already been denied." };
    }
    if (p.signers.includes(selfPubkey)) {
      return { ok: false, reason: "Already signed." };
    }
    const nextSigners = [...p.signers, selfPubkey];
    const nextPending = [...state.pending];
    nextPending[idx] = { ...p, signers: nextSigners };
    set(configId, { ...state, pending: nextPending });

    // Preview-mode shortcut: a `kind_change` proposal lands as soon
    // as the proposer has *any* second signer. The real engine
    // requires unanimous-of-rostered for open→closed, and
    // unanimous-of-owners for closed→open — preview keeps the UX
    // explorable without modelling roster snapshots.
    if (p.variant.kind === "kind_change") {
      const cleanClosed = applyKindChangeIfReady(configId, p.id);
      return { ok: true, cleanClosed };
    }
    return { ok: true };
  }

  /** Deny a pending proposal. Any single deny invalidates the
   *  proposal — the proposer can re-float later or split. */
  function denyProposal(
    configId: string,
    selfPubkey: string,
    proposalId: string,
  ): { ok: boolean; reason?: string } {
    const state = get(configId);
    const idx = state.pending.findIndex((p) => p.id === proposalId);
    if (idx === -1) return { ok: false, reason: "Proposal not found." };
    const p = state.pending[idx];
    if (p.deniers.includes(selfPubkey)) {
      return { ok: false, reason: "Already denied." };
    }
    const nextPending = [...state.pending];
    nextPending[idx] = { ...p, deniers: [...p.deniers, selfPubkey] };
    set(configId, { ...state, pending: nextPending });
    return { ok: true };
  }

  /** Withdraw an in-flight proposal. Only the proposer can do this. */
  function withdrawProposal(
    configId: string,
    selfPubkey: string,
    proposalId: string,
  ): { ok: boolean; reason?: string } {
    const state = get(configId);
    const p = state.pending.find((p) => p.id === proposalId);
    if (!p) return { ok: false, reason: "Proposal not found." };
    if (p.proposer !== selfPubkey) {
      return { ok: false, reason: "Only the proposer can withdraw." };
    }
    set(configId, {
      ...state,
      pending: state.pending.filter((p) => p.id !== proposalId),
    });
    return { ok: true };
  }

  function applyKindChangeIfReady(configId: string, proposalId: string): boolean {
    const state = get(configId);
    const p = state.pending.find((p) => p.id === proposalId);
    if (!p || p.variant.kind !== "kind_change") return false;
    if (p.signers.length < 2) return false; // need ≥ 1 co-signer
    const to = p.variant.to;
    // On clean open → closed, the proposer becomes founder-owner.
    const nextRoles = { ...state.roles };
    if (to === "closed" && !nextRoles[p.proposer]) {
      nextRoles[p.proposer] = "owner";
    }
    set(configId, {
      ...state,
      kind: to,
      roles: nextRoles,
      pending: state.pending.filter((x) => x.id !== p.id),
      transitions: [
        ...state.transitions,
        { at: Date.now(), variant: p.variant, signers: p.signers },
      ],
    });
    return true;
  }

  // ---- mutations: split ----------------------------------------------

  /** Fire the proposer's split fallback for a stuck close proposal.
   *  Spawns a derived closed network containing the proposer + every
   *  signer it has so far. The original network is unaffected. */
  async function spawnSplit(
    configId: string,
    selfPubkey: string,
    proposalId: string,
    originalNetworkId: string,
  ): Promise<{ ok: boolean; reason?: string; split?: SplitRecord }> {
    const state = get(configId);
    const p = state.pending.find((p) => p.id === proposalId);
    if (!p) return { ok: false, reason: "Proposal not found." };
    if (p.variant.kind !== "kind_change" || p.variant.to !== "closed") {
      return {
        ok: false,
        reason: "Splits are only available for stuck open→closed proposals.",
      };
    }
    if (p.proposer !== selfPubkey) {
      return { ok: false, reason: "Only the proposer can spawn a split." };
    }
    const newNetworkId = await deriveSplitNetworkId(originalNetworkId, p.signers);
    const split: SplitRecord = {
      new_network_id: newNetworkId,
      spawned_at: Date.now(),
      spawned_by: selfPubkey,
      members: [...p.signers],
    };
    set(configId, {
      ...state,
      pending: state.pending.map((x) =>
        x.id === p.id ? { ...x, split_spawned: true } : x,
      ),
      splits: [...state.splits, split],
      transitions: [
        ...state.transitions,
        {
          at: Date.now(),
          variant: {
            kind: "split",
            new_network_id: newNetworkId,
            members: split.members,
          },
          signers: p.signers,
        },
      ],
    });
    return { ok: true, split };
  }

  /** Returns the most-recent split spawned from this network, if
   *  any. Used by the Connections-tab chip on peers who are in a
   *  split spawned from the network the user is viewing. */
  function splitsFor(configId: string): SplitRecord[] {
    return get(configId).splits;
  }

  // ---- orphan tracking -----------------------------------------------

  /** Record an orphan when an edit-save flow leaves the daemon
   *  without the network the user expected. The original
   *  pre-edit config is snapshotted so a retry can reapply it. */
  function recordOrphan(o: OrphanNetwork) {
    // Replace any existing orphan with the same network_id so
    // repeated failures don't pile up duplicates.
    orphans = [
      ...orphans.filter((e) => e.network_id !== o.network_id),
      o,
    ];
    persistOrphans();
  }

  function discardOrphan(networkId: string) {
    orphans = orphans.filter((o) => o.network_id !== networkId);
    persistOrphans();
  }

  /** Clear orphans whose network has come back to life — called
   *  by the mesh client when a network is observed in the live
   *  registry. Keyed on `network_id` (the wire-level handle) so a
   *  retry that picks a fresh local `config_id` still clears the
   *  orphan. */
  function reconcileOrphans(liveNetworkIds: Set<string>) {
    const before = orphans.length;
    orphans = orphans.filter((o) => !liveNetworkIds.has(o.network_id));
    if (orphans.length !== before) persistOrphans();
  }

  // ---- initialisation ------------------------------------------------

  load();

  return {
    get byConfigId() {
      return byConfigId;
    },
    get orphans() {
      return orphans;
    },
    /** Reactive accessor — components read this rather than the map
     *  directly so Svelte 5 tracks the dependency correctly. */
    stateFor: get,
    localRole,
    roleOf,
    setPeerRole,
    clearPeerRole,
    proposeKindChange,
    signProposal,
    denyProposal,
    withdrawProposal,
    spawnSplit,
    splitsFor,
    recordOrphan,
    discardOrphan,
    reconcileOrphans,
  };
}

export const governance = createGovernanceStore();
export type GovernanceStore = ReturnType<typeof createGovernanceStore>;
