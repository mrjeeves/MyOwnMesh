// GUI governance projection and exact named control operations.
//
// The daemon is authoritative. This module does not mirror a governance
// snapshot or proposal state machine: network kind and
// topology come from config, roles come from the read-only roster, and all
// role/MFA mutations use named daemon requests.

import {
  commandFailure,
  isOutcomeUnknown,
  meshClient,
} from "./mesh-client.svelte";
import type {
  NetworkConfigInput,
  Role,
} from "./types";

const ORPHAN_STORAGE_KEY = "myownmesh.orphan-networks.v1";

export interface OrphanNetwork {
  config_id: string;
  network_id: string;
  label: string;
  failed_at: number;
  reason: string;
  config: NetworkConfigInput;
}

export interface MfaMaterial {
  secret: string;
  otpauthUri: string;
  recoveryCodes: string[];
  transactionId: string;
}

export interface MfaTransaction {
  network: string;
  transaction_id: string;
  state: "prepared" | "committed" | "absent";
  secret?: string;
  otpauth_uri?: string;
  recovery_codes?: string[];
}

export interface GovernanceFailure {
  reason: string;
  code?: string;
  data?: Record<string, unknown>;
  outcomeUnknown?: boolean;
}

function governanceFailure(error: unknown): GovernanceFailure {
  const failure = commandFailure(error);
  return {
    reason: failure.message,
    code: typeof failure.data?.code === "string" ? failure.data.code : undefined,
    data: failure.data,
    outcomeUnknown: isOutcomeUnknown(error),
  };
}

interface GovernanceProjection {
  kind: "open" | "closed" | "silent";
  roles: Record<string, Role>;
  topology?: import("./types").TopologyMode | null;
}

const EMPTY_STATE: GovernanceProjection = {
  kind: "open",
  roles: {},
};

function createGovernanceStore() {
  let orphans = $state<OrphanNetwork[]>([]);

  function loadOrphans() {
    try {
      const raw = localStorage.getItem(ORPHAN_STORAGE_KEY);
      const parsed = raw ? JSON.parse(raw) : null;
      if (Array.isArray(parsed)) orphans = parsed as OrphanNetwork[];
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
    orphans = [...orphans.filter((e) => e.network_id !== o.network_id), o];
    persistOrphans();
  }

  function discardOrphan(networkId: string) {
    orphans = orphans.filter((o) => o.network_id !== networkId);
    persistOrphans();
  }

  function reconcileOrphans(liveNetworkIds: Set<string>) {
    const next = orphans.filter((o) => !liveNetworkIds.has(o.network_id));
    if (next.length !== orphans.length) {
      orphans = next;
      persistOrphans();
    }
  }

  /** Read-only projection. No roster or config field is accepted as a
   * signed transition; the daemon owns all mutations. */
  function stateFor(configId: string): GovernanceProjection {
    const network = meshClient.networks.find((n) => n.config_id === configId);
    const roles: Record<string, Role> = {};
    for (const peer of meshClient.rostersByNetwork[configId] ?? []) {
      roles[peer.device_id] = peer.role ?? "member";
    }
    return {
      ...EMPTY_STATE,
      kind: meshClient.networkKindsByNetwork[configId] ?? "open",
      roles,
      topology: network?.topology ?? null,
    };
  }

  function localRole(configId: string, selfPubkey: string | null): Role {
    return selfPubkey ? stateFor(configId).roles[selfPubkey] ?? "member" : "member";
  }

  function roleOf(configId: string, pubkey: string): Role {
    return stateFor(configId).roles[pubkey] ?? "member";
  }

  async function setPeerRole(
    configId: string,
    _selfPubkey: string,
    peerPubkey: string,
    role: Role,
    mfaCode?: string,
  ): Promise<{ ok: true } | ({ ok: false } & GovernanceFailure)> {
    try {
      if (role === "member") {
        await meshClient.governanceProposeRoleRevoke(configId, peerPubkey, mfaCode);
      } else {
        await meshClient.governanceProposeRoleGrant(
          configId,
          peerPubkey,
          role,
          mfaCode,
        );
      }
      await meshClient.refreshRoster(configId);
      return { ok: true };
    } catch (e) {
      return { ok: false, ...governanceFailure(e) };
    }
  }

  async function clearPeerRole(
    configId: string,
    selfPubkey: string,
    peerPubkey: string,
    mfaCode?: string,
  ) {
    return setPeerRole(configId, selfPubkey, peerPubkey, "member", mfaCode);
  }

  async function proposeEvict(
    configId: string,
    target: string,
    mfaCode?: string,
  ): Promise<{ ok: true } | ({ ok: false } & GovernanceFailure)> {
    try {
      await meshClient.governanceProposeEvict(configId, target, mfaCode);
      await meshClient.refreshRoster(configId);
      return { ok: true };
    } catch (e) {
      return { ok: false, ...governanceFailure(e) };
    }
  }

  async function mfaStatus(configId: string): Promise<boolean> {
    try {
      return await meshClient.governanceMfaStatus(configId);
    } catch {
      return false;
    }
  }

  async function mfaPrepare(configId: string): Promise<
    { ok: true; material: MfaMaterial } | ({ ok: false } & GovernanceFailure)
  > {
    try {
      const r = await meshClient.governanceMfaPrepare(configId);
      return {
        ok: true,
        material: {
          secret: r.secret,
          otpauthUri: r.otpauth_uri,
          recoveryCodes: r.recovery_codes,
          transactionId: r.transaction_id,
        },
      };
    } catch (e) {
      return { ok: false, ...governanceFailure(e) };
    }
  }

  async function mfaQuery(configId: string, transactionId: string) {
    return meshClient.governanceMfaQuery(configId, transactionId);
  }

  async function mfaRedeliver(configId: string, transactionId: string) {
    return meshClient.governanceMfaRedeliver(configId, transactionId);
  }

  async function mfaCommit(configId: string, transactionId: string) {
    return meshClient.governanceMfaCommit(configId, transactionId);
  }

  async function mfaAbort(configId: string, transactionId: string) {
    return meshClient.governanceMfaAbort(configId, transactionId);
  }

  async function mfaDisable(configId: string, code: string) {
    try {
      await meshClient.governanceMfaDisable(configId, code);
      return { ok: true };
    } catch (e) {
      return { ok: false, ...governanceFailure(e) };
    }
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
    proposeEvict,
    mfaStatus,
    mfaPrepare,
    mfaQuery,
    mfaRedeliver,
    mfaCommit,
    mfaAbort,
    mfaDisable,
    recordOrphan,
    discardOrphan,
    reconcileOrphans,
  };
}

export const governance = createGovernanceStore();
export type GovernanceStore = ReturnType<typeof createGovernanceStore>;
