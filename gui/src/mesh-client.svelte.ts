// Reactive client wrapper around the daemon's control protocol.
// Talks to the Tauri backend via `invoke(...)` for one-shot ops and
// subscribes to the long-lived event stream via `listen(...)`.
//
// The exported `meshClient` singleton holds Svelte 5 reactive state
// (`$state(...)`) so any component that reads it re-renders when the
// daemon's view changes. Polling cadence is coarse (peer/network
// snapshots refresh every 2s) — fine-grained updates ride on the
// event stream, and the polling is purely a safety net for cases
// where we missed an event (lagged, subscription dropped, etc.).

import { invoke } from "@tauri-apps/api/core";
import { listen, type UnlistenFn } from "@tauri-apps/api/event";
import type {
  AuthorizedPeer,
  DaemonStatus,
  DiagEntry,
  IdentityInfo,
  MeshConfigSnapshot,
  NetworkConfigInput,
  NetworkSummary,
  PeerInfo,
  ServicesConfig,
  ServicesStatusResponse,
  StreamFrame,
  SubscriptionStatus,
} from "./types";

const POLL_INTERVAL_MS = 2000;
const MAX_DIAG_ENTRIES = 200;

function createMeshClient() {
  // ---- reactive state -------------------------------------------------

  let status = $state<DaemonStatus | null>(null);
  let identity = $state<IdentityInfo | null>(null);
  let networks = $state<NetworkSummary[]>([]);
  // Per-network peer snapshots, keyed by config_id.
  let peersByNetwork = $state<Record<string, PeerInfo[]>>({});
  // Per-network rosters (authorised peers persisted on disk). The
  // graph merges these with `peersByNetwork` so peers we've ever
  // connected to stay visible even when offline / not in signaling.
  let rostersByNetwork = $state<Record<string, AuthorizedPeer[]>>({});
  /** Per-network signed governance snapshot — kind, roles,
   *  transition log, pending proposals, splits. Mirrors the daemon's
   *  `crate::network_state::NetworkState`. Polled on the same cadence
   *  as peers + rosters; refreshed eagerly after each governance
   *  mutation so the UI sees its own writes immediately. Loosely
   *  typed because we don't currently mirror every field in
   *  `types.ts` — the Governance tab reads what it needs by key. */
  let governanceByNetwork = $state<Record<string, unknown>>({});
  let diags = $state<DiagEntry[]>([]);
  // Device-level infrastructure services this device hosts (relay /
  // signaling / STUN / TURN): live status + the persisted config the
  // Services settings section edits. `null` until first fetched.
  let services = $state<ServicesStatusResponse | null>(null);
  // Wall-clock ms of the most recent "network change" diag, per
  // network. The NodeMap animates the self↔internet edge for a few
  // seconds after this bumps so the user sees that the engine
  // noticed a network shift.
  let networkChangeTsByNetwork = $state<Record<string, number>>({});

  // Tracks the live state of the long-lived event subscription. The
  // SettingsPanel surfaces this so users can tell when the daemon is
  // down without having to interpret a stale peer list.
  let connected = $state<"connecting" | "live" | "disconnected">("connecting");
  let lastError = $state<string | null>(null);

  // Last-resort polling timer. Cleared when `dispose()` runs.
  let pollTimer: ReturnType<typeof setInterval> | null = null;
  let unsubEvent: UnlistenFn | null = null;
  let unsubStatus: UnlistenFn | null = null;

  // ---- one-shot fetchers ----------------------------------------------

  async function refreshStatus() {
    try {
      status = (await invoke("mesh_status")) as DaemonStatus;
      lastError = null;
    } catch (e) {
      lastError = String(e);
    }
  }

  async function refreshIdentity() {
    try {
      identity = (await invoke("mesh_identity")) as IdentityInfo;
    } catch (e) {
      lastError = String(e);
    }
  }

  async function identitySetLabel(label: string) {
    // The daemon writes the label to disk + updates its in-memory
    // copy in one shot and echoes the resulting IdentityInfo back,
    // so we can replace the cached value without a follow-up
    // refresh.
    identity = (await invoke("mesh_identity_set_label", { label })) as IdentityInfo;
  }

  async function refreshNetworks() {
    try {
      const resp = (await invoke("mesh_networks")) as { networks: NetworkSummary[] };
      networks = resp.networks ?? [];
      // Drop peer-cache entries for networks that no longer exist.
      const live = new Set(networks.map((n) => n.config_id));
      for (const k of Object.keys(peersByNetwork)) {
        if (!live.has(k)) delete peersByNetwork[k];
      }
    } catch (e) {
      lastError = String(e);
    }
  }

  async function refreshPeers(configId: string) {
    try {
      const resp = (await invoke("mesh_peers", { network: configId })) as {
        peers: PeerInfo[];
      };
      peersByNetwork[configId] = resp.peers ?? [];
    } catch (e) {
      // Network may have been removed since the last sweep — leave
      // the cached snapshot in place and surface the error
      // non-fatally.
      lastError = String(e);
    }
  }

  async function refreshAllPeers() {
    await Promise.all(networks.map((n) => refreshPeers(n.config_id)));
  }

  async function refreshRoster(configId: string) {
    try {
      const resp = (await invoke("mesh_roster_list", { network: configId })) as {
        roster: AuthorizedPeer[];
      };
      rostersByNetwork[configId] = resp.roster ?? [];
    } catch (e) {
      // Same non-fatal handling as `refreshPeers` — the roster is a
      // best-effort overlay, not a blocker for the rest of the UI.
      lastError = String(e);
    }
  }

  async function refreshAllRosters() {
    await Promise.all(networks.map((n) => refreshRoster(n.config_id)));
  }

  /** Refresh every snapshot. Called on startup, after major state
   *  changes (topology set, roster approve), and whenever the event
   *  stream signals a lag so we can resync from the daemon's
   *  ground truth. */
  async function refreshAll() {
    await Promise.all([
      refreshStatus(),
      refreshIdentity(),
      refreshNetworks(),
      refreshServices(),
    ]);
    await Promise.all([
      refreshAllPeers(),
      refreshAllRosters(),
      refreshAllGovernance(),
    ]);
  }

  // ---- mutations ------------------------------------------------------

  async function rosterApprove(network: string, deviceId: string, label?: string) {
    await invoke("mesh_roster_approve", { network, deviceId, label: label ?? null });
    await Promise.all([refreshPeers(network), refreshRoster(network)]);
  }

  async function rosterRemove(network: string, deviceId: string) {
    await invoke("mesh_roster_remove", { network, deviceId });
    await Promise.all([refreshPeers(network), refreshRoster(network)]);
  }

  async function rosterList(network: string) {
    const resp = (await invoke("mesh_roster_list", { network })) as {
      roster: Array<{ device_id: string; label: string; approved_at: number }>;
    };
    return resp.roster ?? [];
  }

  async function topologySet(
    network: string,
    topology: "ring" | "star" | "full_mesh",
    hub?: string,
  ) {
    await invoke("mesh_topology_set", { network, topology, hub: hub ?? null });
    await refreshNetworks();
    await refreshPeers(network);
  }

  // ---- network add / remove / import / export ------------------------

  /** Fetch the on-disk MeshConfig. The GUI uses this for the export
   *  flow (it pulls the full NetworkConfig including STUN/TURN /
   *  signaling that the registry summary doesn't carry). */
  async function configShow(): Promise<MeshConfigSnapshot> {
    const resp = (await invoke("mesh_config_show")) as {
      config: MeshConfigSnapshot;
    };
    return resp.config;
  }

  async function networkAdd(config: NetworkConfigInput) {
    await invoke("mesh_network_add", { config });
    await refreshNetworks();
    // Refresh peers for the new network so its sidebar row populates
    // immediately rather than waiting on the next poll tick.
    await refreshAllPeers();
  }

  async function networkRemove(network: string) {
    await invoke("mesh_network_remove", { network });
    await refreshNetworks();
  }

  /** Accept any JSON-shaped value — the GUI exports the
   *  shareable `NetworkSettingsExport` envelope, not the raw
   *  `NetworkConfig`, so the type here is intentionally loose. */
  async function exportNetworkFile(path: string, config: unknown): Promise<void> {
    await invoke("mesh_network_export_file", { path, config });
  }

  // ---- governance (closed networks) ----------------------------------
  //
  // Daemon-backed governance state. Each call below proxies through
  // the corresponding `mesh_governance_*` Tauri command which round-
  // trips to the daemon, signs (where applicable), and persists.
  // After every mutation we refresh the cached state so the UI
  // re-renders.

  async function governanceState(network: string): Promise<unknown> {
    const resp = (await invoke("mesh_governance_state", { network })) as {
      state: unknown;
    };
    return resp.state;
  }

  async function refreshGovernance(network: string) {
    try {
      const s = await governanceState(network);
      governanceByNetwork[network] = s;
    } catch (e) {
      // Daemon may not yet have this network in its registry, or
      // we're racing a remove. Keep the prior cached state.
      lastError = String(e);
    }
  }

  async function refreshAllGovernance() {
    await Promise.all(networks.map((n) => refreshGovernance(n.config_id)));
  }

  async function governanceProposeKindChange(
    network: string,
    to: "open" | "closed",
  ): Promise<string> {
    const resp = (await invoke("mesh_governance_propose_kind_change", {
      network,
      to,
    })) as { proposal_id: string };
    await refreshGovernance(network);
    return resp.proposal_id;
  }

  async function governanceProposeRoleGrant(
    network: string,
    target: string,
    role: "member" | "controller" | "owner",
  ): Promise<string> {
    const resp = (await invoke("mesh_governance_propose_role_grant", {
      network,
      target,
      role,
    })) as { proposal_id: string };
    await refreshGovernance(network);
    return resp.proposal_id;
  }

  async function governanceProposeRoleRevoke(
    network: string,
    target: string,
  ): Promise<string> {
    const resp = (await invoke("mesh_governance_propose_role_revoke", {
      network,
      target,
    })) as { proposal_id: string };
    await refreshGovernance(network);
    return resp.proposal_id;
  }

  async function governanceSign(network: string, proposalId: string) {
    await invoke("mesh_governance_sign", { network, proposalId });
    await refreshGovernance(network);
    await refreshRoster(network);
  }

  async function governanceDeny(network: string, proposalId: string) {
    await invoke("mesh_governance_deny", { network, proposalId });
    await refreshGovernance(network);
  }

  async function governanceWithdraw(network: string, proposalId: string) {
    await invoke("mesh_governance_withdraw", { network, proposalId });
    await refreshGovernance(network);
  }

  async function governanceSpawnSplit(
    network: string,
    proposalId: string,
  ): Promise<string> {
    const resp = (await invoke("mesh_governance_spawn_split", {
      network,
      proposalId,
    })) as { new_network_id: string };
    await refreshGovernance(network);
    return resp.new_network_id;
  }

  // ---- infrastructure services (relay / signaling / STUN / TURN) -----

  /** Fetch the device's service status + persisted config. Cheap; runs
   *  on every `refreshAll` so the Services section has current data. */
  async function refreshServices() {
    try {
      services = (await invoke("mesh_services_status")) as ServicesStatusResponse;
    } catch (e) {
      lastError = String(e);
    }
  }

  /** Persist a new services config and reconcile the running services.
   *  Re-fetches the full status so the cache reflects the new persisted
   *  config + live running state (a service can be enabled but fail to
   *  start, e.g. a port in use). */
  async function servicesSet(config: ServicesConfig) {
    await invoke("mesh_services_set", { services: config });
    await refreshServices();
  }

  // ---- event stream handling ------------------------------------------

  function ingestEvent(frame: StreamFrame) {
    if (frame.kind === "lagged") {
      // We dropped events. Resync from the daemon's snapshot APIs so
      // the UI doesn't show a stale peer list.
      void refreshAll();
      return;
    }
    const event = frame.event;
    if (!event || typeof event !== "object") return;
    const family = (event as { event_kind?: string }).event_kind;
    if (family === "diag") {
      // The DiagEntry fields are spread alongside `event_kind`; strip
      // the family tag to land back at a clean DiagEntry shape.
      const { event_kind: _ek, ...rest } = event as Record<string, unknown>;
      const entry = rest as unknown as DiagEntry;
      pushDiag(entry);
      // Side-effect: stamp the network-change timestamp so the
      // NodeMap can pulse the self↔internet edge. Cheap to do on
      // every diag; the keyed lookup makes the per-network animation
      // self-contained.
      if (entry.category === "network" && entry.network_id) {
        const cfg = networks.find((n) => n.network_id === entry.network_id);
        if (cfg) networkChangeTsByNetwork[cfg.config_id] = entry.ts || Date.now();
      }
      return;
    }
    if (family === "peer" || family === "phase") {
      // Refresh affected network's snapshot. Cheap enough to refresh
      // all networks on any state change — the daemon trims its
      // response to whatever we own, and connections are local.
      const networkId = (event as Record<string, unknown>).network_id;
      if (typeof networkId === "string") {
        // The networkId on the wire is the wire-level network id;
        // peersByNetwork is keyed by config_id. We refresh the whole
        // set rather than mapping wire-id → config-id since the cost
        // is negligible against a local socket.
        void refreshAllPeers();
        if (family === "phase") void refreshNetworks();
      }
      // Mirror peer + phase events into the activity log as synthetic
      // diag entries. Matches MyOwnLLM's Activity tab, where every
      // mesh-relevant transition lands in one chronological feed —
      // users debugging "why isn't this peer showing up" don't have
      // to know which subsystem fired which transition.
      const synthetic = synthesizeDiagFromEvent(family, event as Record<string, unknown>);
      if (synthetic) pushDiag(synthetic);
    }
  }

  /** Prepend a diag entry to the in-memory log, capped to the
   *  configured backlog. Single call site so the dedup / cap policy
   *  lives in one place. */
  function pushDiag(entry: DiagEntry) {
    diags = [entry, ...diags].slice(0, MAX_DIAG_ENTRIES);
  }

  /** Turn a peer / phase event into a `DiagEntry` so it shows up in
   *  the Activity tab alongside the explicit `MeshEvent::Diag`
   *  entries the engine emits. Branches on the inner `kind` tag,
   *  which (after the outer rename to `event_kind`) is unambiguously
   *  the variant within the family. */
  function synthesizeDiagFromEvent(
    family: "peer" | "phase",
    event: Record<string, unknown>,
  ): DiagEntry | null {
    const ts = Date.now();
    const network_id = typeof event.network_id === "string" ? event.network_id : "";
    const variant = typeof event.kind === "string" ? event.kind : "";

    if (family === "phase") {
      // Only PhaseEvent::Changed exists today.
      const prev = String(event.prev ?? "?");
      const next = String(event.next ?? "?");
      return {
        ts,
        network_id,
        level: "info",
        category: "phase",
        message: `phase: ${prev} → ${next}`,
        detail: null,
      };
    }

    const peer = typeof event.device_id === "string" ? shortPeerId(event.device_id) : "peer";
    const label =
      typeof event.label === "string" && event.label ? `${event.label} (${peer})` : peer;

    // Skip variants the engine already emits a paired `log_diag`
    // for — duplicating them here would put two rows in the
    // activity log for one event. Pairs (engine-side diag):
    //   sighted        → "peer sighted: …" (engine/mod.rs)
    //   authenticated  → "auth ok with …" (handshake.rs)
    //   approved       → "peer active: …" (handshake.rs)
    //   dropped        → "peer dropped: …" (engine/mod.rs)
    // Remaining variants (shelved / unshelved / capabilities_changed)
    // have no engine-side diag pair, so the GUI synthesis is the
    // only thing that surfaces them in the log.
    switch (variant) {
      case "sighted":
      case "authenticated":
      case "approved":
      case "dropped":
        return null;
      case "shelved": {
        const by_us = (event as { by_us?: boolean }).by_us === true;
        return {
          ts,
          network_id,
          level: "info",
          category: "topology",
          message: by_us ? `shelved ${label}` : `peer shelved us: ${label}`,
          detail: null,
        };
      }
      case "unshelved": {
        const by_us = (event as { by_us?: boolean }).by_us === true;
        return {
          ts,
          network_id,
          level: "info",
          category: "topology",
          message: by_us ? `unshelved ${label}` : `peer unshelved us: ${label}`,
          detail: null,
        };
      }
      case "capabilities_changed":
        return {
          ts,
          network_id,
          level: "info",
          category: "peer",
          message: `capabilities changed: ${label}`,
          detail: null,
        };
      default:
        // Unknown peer-event variant — render a generic line so it's
        // still visible in the log rather than silently dropped.
        return {
          ts,
          network_id,
          level: "info",
          category: "peer",
          message: `${variant || "event"}: ${label}`,
          detail: null,
        };
    }
  }

  function shortPeerId(id: string): string {
    if (id.length <= 12) return id;
    return `${id.slice(0, 6)}…${id.slice(-4)}`;
  }

  async function startEventSubscription() {
    unsubEvent = await listen<StreamFrame>("mesh://event", (evt) => {
      ingestEvent(evt.payload);
    });
    unsubStatus = await listen<SubscriptionStatus>("mesh://subscription", (evt) => {
      applySubscriptionStatus(evt.payload);
    });
    // Race-safety: the backend emits `mesh://subscription` exactly
    // once per subscribe cycle, which on a fast machine can fire
    // before `listen()` registers our handler. The backend caches
    // the most recent payload; pull it now so we pick up the
    // current state regardless of whether we missed the emit.
    try {
      const current = (await invoke("mesh_subscription_state")) as SubscriptionStatus;
      applySubscriptionStatus(current);
    } catch (e) {
      // If the backend doesn't have the command (older build) just
      // fall through — the event-driven path still works once a
      // status change actually fires.
      console.warn("mesh_subscription_state query failed:", e);
    }
  }

  function applySubscriptionStatus(payload: SubscriptionStatus) {
    const wasLive = connected === "live";
    connected = payload.status === "live" ? "live" : "disconnected";
    if (payload.error) lastError = payload.error;
    if (connected === "live") {
      // Clear stale error once we're back up.
      lastError = null;
      // Subscription just (re-)connected; resync from snapshot APIs.
      // Skip if we were already live to avoid double-refresh when
      // the cached state happens to match an event we also got.
      if (!wasLive) void refreshAll();
    }
  }

  function startPolling() {
    if (pollTimer) return;
    pollTimer = setInterval(() => {
      void refreshAllPeers();
      // Rosters don't change as often as peer state, but they DO
      // change without an obvious event we can hook (a peer
      // approving us from their side will refresh ours via the
      // approve flow — but a manual edit on the host wouldn't),
      // so piggy-back on the same poll cadence.
      void refreshAllRosters();
      // Same logic for governance state: it changes via peer-
      // initiated proposals / acks / splits, and there's no event
      // surface for those yet. Polled cheap; the daemon returns a
      // small JSON.
      void refreshAllGovernance();
    }, POLL_INTERVAL_MS);
  }

  // ---- lifecycle ------------------------------------------------------

  async function init() {
    await startEventSubscription();
    await refreshAll();
    startPolling();
  }

  function dispose() {
    if (pollTimer) clearInterval(pollTimer);
    pollTimer = null;
    unsubEvent?.();
    unsubStatus?.();
    unsubEvent = null;
    unsubStatus = null;
  }

  return {
    // Reactive getters keep callers from accidentally writing into
    // internal state — Svelte 5 still tracks the dependency through
    // the getter, so reactivity works as expected.
    get status() {
      return status;
    },
    get identity() {
      return identity;
    },
    get networks() {
      return networks;
    },
    get peersByNetwork() {
      return peersByNetwork;
    },
    get rostersByNetwork() {
      return rostersByNetwork;
    },
    get governanceByNetwork() {
      return governanceByNetwork;
    },
    get networkChangeTsByNetwork() {
      return networkChangeTsByNetwork;
    },
    get diags() {
      return diags;
    },
    get services() {
      return services;
    },
    get connected() {
      return connected;
    },
    get lastError() {
      return lastError;
    },

    init,
    dispose,
    refreshAll,
    refreshPeers,
    refreshRoster,
    refreshNetworks,
    identitySetLabel,
    rosterApprove,
    rosterRemove,
    rosterList,
    topologySet,
    configShow,
    networkAdd,
    networkRemove,
    exportNetworkFile,

    // services
    refreshServices,
    servicesSet,

    // governance
    governanceState,
    refreshGovernance,
    governanceProposeKindChange,
    governanceProposeRoleGrant,
    governanceProposeRoleRevoke,
    governanceSign,
    governanceDeny,
    governanceWithdraw,
    governanceSpawnSplit,
  };
}

export const meshClient = createMeshClient();
export type MeshClient = ReturnType<typeof createMeshClient>;
