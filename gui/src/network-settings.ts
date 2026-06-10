// Network-settings envelope — the JSON shape used for sharing /
// importing / exporting a network across devices. Modelled directly
// on MyOwnLLM's `NetworkSettingsExport` so a file produced there is
// trivially convertible here.
//
// The envelope is intentionally flatter than the engine's on-disk
// `NetworkConfig`:
//
//   - `signaling_servers` is a string[] — each URL becomes one
//     entry in `SignalingConfig.servers`.
//   - `stun_servers` is a string[] — each URL becomes one
//     `StunServer { urls: [url] }`.
//   - `turn_servers` is `{ url, username?, credential? }[]` — each
//     entry becomes one `TurnServer { urls: [url], ... }`.
//
// The local `id` field of NetworkConfig is NEVER in the envelope —
// dropping it lets the same blob apply on multiple devices without
// colliding. The receiving side generates a fresh local id via
// `newNetworkInternalId`.
//
// A `kind` marker (`"myownmesh.network-settings"`) gates import so
// we don't try to apply an unrelated JSON blob by accident.

import { invoke } from "@tauri-apps/api/core";
import type { NetworkConfigInput, TopologyMode } from "./types";

export const NETWORK_SETTINGS_KIND = "myownmesh.network-settings";
export const NETWORK_SETTINGS_VERSION = 1;

/** Defaults the modals seed new networks with — the project's
 *  semi-public MyOwnMesh endpoints, matching the engine's own
 *  `config.rs` defaults so the value the user sees in the UI is the
 *  value the daemon actually uses. The engine resolves an empty
 *  signaling list to the same `wss://myownmesh.com` relay (reached
 *  over standard `wss://` on 443), so seeding it explicitly is just so
 *  it's visible and editable. */
export const DEFAULT_NETWORK_SIGNALING: string[] = ["wss://myownmesh.com"];
export const DEFAULT_NETWORK_STUN: string[] = ["stun:stun.myownmesh.com:3478"];

export interface TurnEntry {
  url: string;
  username?: string;
  credential?: string;
}

/** Default TURN relay for new networks — the project's reference TURN
 *  with its shared semi-public guest credential, so symmetric-NAT /
 *  CGNAT peers relay out of the box. Bandwidth-capped; run your own
 *  (`services.turn` on any myownmesh host) for sustained throughput.
 *  Kept in lockstep with `myownmesh_core::config::default_turn_servers`. */
export const DEFAULT_NETWORK_TURN: TurnEntry[] = [
  {
    url: "turn:turn.myownmesh.com:3478",
    username: "guest",
    credential: "theguestpassword",
  },
];

export interface NetworkSettingsExport {
  kind: typeof NETWORK_SETTINGS_KIND;
  version: number;
  network_id: string;
  /** Cosmetic label. Optional in the envelope since the original
   *  device's name may not be meaningful on the receiving end. */
  label?: string;
  signaling_servers: string[];
  stun_servers: string[];
  turn_servers: TurnEntry[];
}

/** Fresh per-device internal id for a NetworkConfig record. The
 *  engine uses `id` as a uniqueness key within one device's config
 *  but the user never types it. We mirror MyOwnLLM's pattern: a
 *  `net_` prefix + short random suffix. */
export function newNetworkInternalId(): string {
  const rand = Math.random().toString(36).slice(2, 10);
  const stamp = Date.now().toString(36);
  return `net_${rand}_${stamp}`;
}

/** Build the export envelope from an in-memory NetworkConfig.
 *  Strips the internal `id` and flattens the urls-array shape. */
export function exportNetworkSettings(cfg: NetworkConfigInput): NetworkSettingsExport {
  return {
    kind: NETWORK_SETTINGS_KIND,
    version: NETWORK_SETTINGS_VERSION,
    network_id: cfg.network_id,
    ...(cfg.label ? { label: cfg.label } : {}),
    signaling_servers: cfg.signaling?.servers ?? [],
    stun_servers: (cfg.stun_servers ?? []).flatMap((s) => s.urls),
    turn_servers: (cfg.turn_servers ?? []).map((t) => ({
      url: t.urls[0] ?? "",
      ...(t.username ? { username: t.username } : {}),
      ...(t.credential ? { credential: t.credential } : {}),
    })),
  };
}

/** True when the parsed JSON value carries our envelope marker.
 *  Cheap shape-only check; field validation lives in
 *  `coerceNetworkSettings`. */
export function isNetworkSettingsExport(raw: unknown): raw is NetworkSettingsExport {
  if (!raw || typeof raw !== "object") return false;
  const obj = raw as Record<string, unknown>;
  return obj.kind === NETWORK_SETTINGS_KIND && typeof obj.network_id === "string";
}

/** Parse a JSON string into a `NetworkSettingsExport`. Returns null
 *  when the input isn't JSON, isn't an object, or doesn't carry the
 *  `kind` marker. Drops malformed individual entries rather than
 *  rejecting the whole blob — the user expects "import a JSON" to
 *  be tolerant. */
export function tryParseNetworkSettings(text: string): NetworkSettingsExport | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  if (!isNetworkSettingsExport(parsed)) return null;
  return coerceNetworkSettings(parsed);
}

function coerceNetworkSettings(raw: NetworkSettingsExport): NetworkSettingsExport {
  const signaling = Array.isArray(raw.signaling_servers)
    ? raw.signaling_servers.filter((s): s is string => typeof s === "string")
    : [];
  const stun = Array.isArray(raw.stun_servers)
    ? raw.stun_servers.filter((s): s is string => typeof s === "string")
    : [];
  const turn: TurnEntry[] = Array.isArray(raw.turn_servers)
    ? raw.turn_servers
        .filter(
          (t): t is TurnEntry =>
            !!t && typeof t === "object" && typeof (t as TurnEntry).url === "string",
        )
        .map((t) => ({
          url: t.url,
          ...(typeof t.username === "string" && t.username ? { username: t.username } : {}),
          ...(typeof t.credential === "string" && t.credential
            ? { credential: t.credential }
            : {}),
        }))
    : [];
  return {
    kind: NETWORK_SETTINGS_KIND,
    version: NETWORK_SETTINGS_VERSION,
    network_id: String(raw.network_id ?? ""),
    ...(typeof raw.label === "string" && raw.label ? { label: raw.label } : {}),
    signaling_servers: signaling,
    stun_servers: stun,
    turn_servers: turn,
  };
}

/** Build a NetworkConfig wire payload (the JSON shape the daemon's
 *  `NetworkAdd` expects) from the modal's primitives. Centralised
 *  so the modal doesn't replicate the schema translation. */
export function buildNetworkConfig(args: {
  /** Existing local config record id to edit in place. Omit when adding
   *  a new network — a fresh id is minted. Pass the current `config_id`
   *  when building a payload for `networkUpdate`, so the daemon edits the
   *  same record (and keeps its roster) rather than creating a new one. */
  id?: string;
  networkId: string;
  label?: string;
  topology: TopologyMode;
  signalingServers: string[];
  stunUrls: string[];
  turnEntries: TurnEntry[];
  autoApprove?: boolean;
}): NetworkConfigInput {
  return {
    id: args.id ?? newNetworkInternalId(),
    network_id: args.networkId,
    label: args.label?.trim() || undefined,
    topology: args.topology,
    signaling:
      args.signalingServers.length > 0 ? { servers: args.signalingServers } : undefined,
    stun_servers: args.stunUrls.length > 0
      ? args.stunUrls.map((u) => ({ urls: [u] }))
      : undefined,
    turn_servers: args.turnEntries.length > 0
      ? args.turnEntries.map((t) => ({
          urls: [t.url],
          username: t.username,
          credential: t.credential,
        }))
      : undefined,
    auto_approve: args.autoApprove,
  };
}

// ---- network-id helpers (proxied through the daemon control RPC) ----
//
// `generate` / `normalize` are stateless utilities that live in
// `myownmesh_core::identity`. The GUI proxies through the daemon
// control socket so the engine remains the single source of truth
// for the canonical alphabet + validation rules.

export async function generateNetworkId(): Promise<string> {
  const resp = (await invoke("mesh_network_id_generate")) as {
    network_id: string;
  };
  return resp.network_id;
}

export async function normalizeNetworkId(input: string): Promise<string> {
  const resp = (await invoke("mesh_network_id_normalize", { input })) as {
    network_id: string;
  };
  return resp.network_id;
}
