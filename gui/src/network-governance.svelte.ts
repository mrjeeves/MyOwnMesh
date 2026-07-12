// Per-network governance: thin wrapper around `mesh-client`'s
// daemon-backed governance state + browser-local orphan tracking.
//
// Before the engine half shipped, the governance methods on this
// store ran entirely in localStorage as a preview. Now the daemon
// owns the authoritative state (signed transitions, role
// assignments, pending proposals) and every mutation round-trips
// through the control socket. What stays browser-local:
//
//   - **Orphans** — failed-save networks the GUI snapshots so the
//     user can retry or discard without poking config.json by hand.
//     A real engine concept (the daemon doesn't know a network is
//     orphaned; only the GUI's save flow can decide that), so it
//     keeps living in localStorage on this side.
//
// The exported `governance` object is shaped just like the
// preview-mode store it replaces — components keep their existing
// imports + call sites — but the methods are async (daemon
// round-trip) and the `stateFor()` accessor reads from
// `meshClient.governanceByNetwork` rather than browser state.

import { meshClient } from "./mesh-client.svelte";
import {
  ROLE_RANK,
  topologyToOpArgs,
  type NetworkKind,
  type NetworkStateView,
  type Role,
  type SplitRecord,
  type TopologyMode,
} from "./types";
import type { NetworkConfigInput } from "./types";

const ORPHAN_STORAGE_KEY = "myownmesh.orphan-networks.v1";

/** Time before a stuck close proposal becomes splittable. Pinned
 *  to match the daemon's
 *  `crate::engine::governance::STATE_PROPOSAL_TIMEOUT_S`. Used by
 *  the Governance tab to gate the "Spawn split" button. */
export const STATE_PROPOSAL_TIMEOUT_S = 3 * 60;

export interface OrphanNetwork {
  config_id: string;
  network_id: string;
  label: string;
  failed_at: number;
  reason: string;
  config: NetworkConfigInput;
}

const EMPTY_STATE: NetworkStateView = {
  kind: "open",
  roles: {},
  transitions: [],
  pending: [],
  splits: [],
};

/** Pull the daemon's snapshot for `configId` into the
 *  `NetworkStateView` shape the rest of the GUI consumes. The
 *  daemon's Rust JSON uses snake_case keys + slightly different
 *  field names — `network_id` on splits, `signers` arrays on
 *  transitions — so we coerce here rather than scatter coercion
 *  across every reader. */
function coerce(raw: unknown): NetworkStateView {
  if (!raw || typeof raw !== "object") return EMPTY_STATE;
  const obj = raw as Record<string, unknown>;
  const kind: NetworkKind = obj.kind === "closed" ? "closed" : "open";
  const roles =
    typeof obj.roles === "object" && obj.roles
      ? (obj.roles as Record<string, Role>)
      : {};
  const transitions = Array.isArray(obj.transitions)
    ? (obj.transitions as NetworkStateView["transitions"])
    : [];
  const pending = Array.isArray(obj.pending)
    ? (obj.pending as NetworkStateView["pending"])
    : [];
  const splits: SplitRecord[] = Array.isArray(obj.splits)
    ? (obj.splits as SplitRecord[])
    : [];
  const topology =
    typeof obj.topology === "object" && obj.topology
      ? (obj.topology as TopologyMode)
      : null;
  return { kind, roles, transitions, pending, splits, topology };
}

function createGovernanceStore() {
  // ---- orphans (browser-local) ----

  let orphans = $state<OrphanNetwork[]>([]);

  function loadOrphans() {
    try {
      const raw = localStorage.getItem(ORPHAN_STORAGE_KEY);
      if (raw) {
        const parsed = JSON.parse(raw);
        if (Array.isArray(parsed)) {
          orphans = parsed as OrphanNetwork[];
        }
      }
    } catch (e) {
      console.warn("orphan-networks: load failed", e);
    }
  }

  function persistOrphans() {
    try {
      localStorage.setItem(ORPHAN_STORAGE_KEY, JSON.stringify(orphans));
    } catch (e) {
      console.warn("orphan-networks: persist failed", e);
    }
  }

  function recordOrphan(o: OrphanNetwork) {
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

  function reconcileOrphans(liveNetworkIds: Set<string>) {
    if (orphans.length === 0) return;
    const next = orphans.filter((o) => !liveNetworkIds.has(o.network_id));
    if (next.length === orphans.length) return;
    orphans = next;
    persistOrphans();
  }

  // ---- daemon-backed reads ----

  /** Reactive read of the daemon's governance snapshot for
   *  `configId`. Reads through `meshClient.governanceByNetwork`
   *  (refreshed on the global poll tick + after every mutation),
   *  so Svelte components re-render when the daemon's state
   *  changes. Returns the shared `EMPTY_STATE` when the daemon
   *  hasn't yet returned a snapshot for this network — a
   *  brand-new join takes one poll tick before its state lands. */
  function stateFor(configId: string): NetworkStateView {
    const raw = meshClient.governanceByNetwork[configId];
    if (!raw) return EMPTY_STATE;
    return coerce(raw);
  }

  function localRole(configId: string, selfPubkey: string | null): Role {
    if (!selfPubkey) return "member";
    return stateFor(configId).roles[selfPubkey] ?? "member";
  }

  function roleOf(configId: string, pubkey: string): Role {
    return stateFor(configId).roles[pubkey] ?? "member";
  }

  // ---- mutations: roles ----

  async function setPeerRole(
    configId: string,
    _selfPubkey: string,
    peerPubkey: string,
    role: Role,
    mfaCode?: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    try {
      if (role === "member") {
        await meshClient.governanceProposeRoleRevoke(
          configId,
          peerPubkey,
          mfaCode,
        );
      } else {
        await meshClient.governanceProposeRoleGrant(
          configId,
          peerPubkey,
          role,
          mfaCode,
        );
      }
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  async function clearPeerRole(
    configId: string,
    selfPubkey: string,
    peerPubkey: string,
    mfaCode?: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    return setPeerRole(configId, selfPubkey, peerPubkey, "member", mfaCode);
  }

  // ---- mutations: kind transitions ----

  async function proposeKindChange(
    configId: string,
    _selfPubkey: string,
    // `silent` is a creation-time kind, never a KindChange target —
    // the daemon's quorum table rejects it, so don't let the UI offer it.
    to: Extract<NetworkKind, "open" | "closed">,
    mfaCode?: string,
  ): Promise<{ ok: boolean; proposalId?: string; reason?: string }> {
    try {
      const id = await meshClient.governanceProposeKindChange(
        configId,
        to,
        mfaCode,
      );
      return { ok: true, proposalId: id };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  // ---- mutations: governed topology ----

  /** Float the owner-signed, network-wide shape. On the owner this
   *  ratifies immediately (single-signer quorum) and the daemon
   *  reshapes live; every other member converges as the signed log
   *  gossips to them. */
  async function proposeTopology(
    configId: string,
    mode: TopologyMode,
    mfaCode?: string,
  ): Promise<{ ok: boolean; proposalId?: string; reason?: string }> {
    try {
      const { topology, hub } = topologyToOpArgs(mode);
      const id = await meshClient.governanceProposeTopology(
        configId,
        topology,
        hub,
        mfaCode,
      );
      return { ok: true, proposalId: id };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  /** The governed shape, when a ratified TopologyChange owns it —
   *  `null` when this network's topology is still a per-device config
   *  choice. */
  function governedTopology(configId: string): TopologyMode | null {
    return stateFor(configId).topology ?? null;
  }

  async function signProposal(
    configId: string,
    _selfPubkey: string,
    proposalId: string,
    mfaCode?: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    try {
      await meshClient.governanceSign(configId, proposalId, mfaCode);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  // ---- per-device custody MFA (TOTP) ----

  async function mfaStatus(configId: string): Promise<boolean> {
    try {
      return await meshClient.governanceMfaStatus(configId);
    } catch {
      return false;
    }
  }

  async function mfaEnroll(
    configId: string,
  ): Promise<
    | { ok: true; secret: string; otpauthUri: string; recoveryCodes: string[] }
    | { ok: false; reason: string }
  > {
    try {
      const r = await meshClient.governanceMfaEnroll(configId);
      return {
        ok: true,
        secret: r.secret,
        otpauthUri: r.otpauth_uri,
        recoveryCodes: r.recovery_codes,
      };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  async function mfaDisable(
    configId: string,
    code: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    try {
      await meshClient.governanceMfaDisable(configId, code);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  async function denyProposal(
    configId: string,
    _selfPubkey: string,
    proposalId: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    try {
      await meshClient.governanceDeny(configId, proposalId);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  async function withdrawProposal(
    configId: string,
    _selfPubkey: string,
    proposalId: string,
  ): Promise<{ ok: boolean; reason?: string }> {
    try {
      await meshClient.governanceWithdraw(configId, proposalId);
      return { ok: true };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  async function spawnSplit(
    configId: string,
    _selfPubkey: string,
    proposalId: string,
    _originalNetworkId: string,
  ): Promise<{ ok: boolean; reason?: string; newNetworkId?: string }> {
    try {
      const id = await meshClient.governanceSpawnSplit(configId, proposalId);
      return { ok: true, newNetworkId: id };
    } catch (e) {
      return { ok: false, reason: String(e) };
    }
  }

  function splitsFor(configId: string): SplitRecord[] {
    return stateFor(configId).splits;
  }

  loadOrphans();

  return {
    get orphans() {
      return orphans;
    },
    stateFor,
    localRole,
    roleOf,
    setPeerRole,
    clearPeerRole,
    proposeKindChange,
    proposeTopology,
    governedTopology,
    signProposal,
    denyProposal,
    withdrawProposal,
    spawnSplit,
    splitsFor,
    mfaStatus,
    mfaEnroll,
    mfaDisable,
    recordOrphan,
    discardOrphan,
    reconcileOrphans,
  };
}

export const governance = createGovernanceStore();
export type GovernanceStore = ReturnType<typeof createGovernanceStore>;
