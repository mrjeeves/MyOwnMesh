// TypeScript shapes that mirror the daemon's control protocol +
// the public types from `myownmesh-core`. Kept in sync by hand
// against the Rust source (see `crates/myownmesh-core/src/handle.rs`,
// `crates/myownmesh-core/src/events.rs`, and
// `crates/myownmesh-core/src/config.rs`). Changes on the Rust side
// surface here as runtime decode errors if the shapes drift.

// ---- coarse-grained per-network phase rollup -------------------------

export type MeshPhase =
  | "joining"
  | "alone"
  | "discovering"
  | "active"
  | "degraded"
  | "stopped";

// ---- topology ---------------------------------------------------------
//
// TopologyMode is internally tagged in the Rust source — every
// variant carries a `kind` field with the snake_case discriminant.
// See `crates/myownmesh-core/src/config.rs` (the `topology_serde_tags_by_kind`
// test pins this shape down).

export type TopologyMode =
  | { kind: "ring"; n_preferred: number | null }
  | { kind: "star"; hub: string }
  | { kind: "full_mesh" };

export function topologyName(t: TopologyMode): "ring" | "star" | "full_mesh" {
  return t.kind;
}

export function topologyHub(t: TopologyMode): string | null {
  return t.kind === "star" ? t.hub : null;
}

/** Build a TopologyMode value from the picker primitives the UI
 *  collects (a discriminant + optional hub). Centralised so add /
 *  set-topology paths share the same construction. */
export function buildTopology(
  name: "ring" | "star" | "full_mesh",
  hub?: string | null,
): TopologyMode {
  if (name === "ring") return { kind: "ring", n_preferred: null };
  if (name === "full_mesh") return { kind: "full_mesh" };
  return { kind: "star", hub: hub ?? "" };
}

// ---- network config (write shape — sent into NetworkAdd) -------------
//
// Mirrors `myownmesh_core::NetworkConfig`. Most fields are
// `#[serde(default)]` on the Rust side, so the GUI only sets what
// the user actually edited; missing fields fill from defaults.

// These mirror the engine's on-disk shapes — see
// `crates/myownmesh-core/src/config.rs`. The user-facing import /
// export envelope (`NetworkSettingsExport`) flattens these to plain
// URL strings; conversion lives in `network-settings.ts`.

export interface SignalingConfig {
  strategy?: string;
  servers?: string[];
  redundancy?: number;
  denylist?: string[];
}

export interface StunServer {
  urls: string[];
}

export interface TurnServer {
  urls: string[];
  username?: string | null;
  credential?: string | null;
}

export interface NetworkConfigInput {
  id: string;
  network_id: string;
  label?: string;
  topology?: TopologyMode;
  signaling?: SignalingConfig;
  stun_servers?: StunServer[];
  turn_servers?: TurnServer[];
  roster_path?: string | null;
  auto_approve?: boolean;
}

// ---- mesh config (read-only shape from ConfigShow) -------------------

export interface MeshConfigSnapshot {
  version: number;
  identity_path?: string | null;
  networks: NetworkConfigInput[];
  // Other fields (auto_update, auto_cleanup, daemon) exist on the
  // wire but aren't surfaced in the UI yet; ignore them.
  [key: string]: unknown;
}

// ---- peer status / tier ----------------------------------------------

export type PeerStatus =
  | "sighted"
  | "handshaking"
  | "pending_approval"
  | "active"
  | "shelved"
  | "reconnecting"
  | "offline"
  | "error";

// Serialised tier — the Rust enum uses serde's externally tagged form
// for tuple-style variants. We only inspect the discriminant tag in
// the UI, so a coarse `Record<string, unknown>` is enough.
export type ConnectionTier =
  | "Steady"
  | "WakeProbe"
  | { IceWatchdog: { since: string } }
  | { IceRestart: { started: string } }
  | { Rehandshake: { attempt: number; next_at: string } }
  | { RoomRejoin: { attempt: number; next_at: string } }
  | "StopStart";

export function tierName(t: ConnectionTier): string {
  if (typeof t === "string") return t.toLowerCase();
  const key = Object.keys(t)[0];
  return key ? key.replace(/([A-Z])/g, "_$1").slice(1).toLowerCase() : "unknown";
}

// ---- capability advert ------------------------------------------------

export interface CapabilityAdvert {
  tags: string[];
  app_version: string | null;
  max_connections: number | null;
  extra: unknown;
}

// ---- peer snapshot ----------------------------------------------------

export interface PeerInfo {
  device_id: string;
  status: PeerStatus;
  tier: ConnectionTier;
  rtt_ms: number | null;
  label: string;
  capabilities: CapabilityAdvert | null;
  local_shelved: boolean;
  remote_shelved: boolean;
  authenticated: boolean;
}

// ---- roster -----------------------------------------------------------

export interface AuthorizedPeer {
  device_id: string;
  label: string;
  approved_at: number;
}

// ---- network summary (from NetworksList) -----------------------------

export interface NetworkSummary {
  /** Auto-generated local config record id (`net_<rand>_<stamp>`).
   *  Stable key for control-protocol ops — NOT the friendly display
   *  name. Use [`networkDisplayName`] for anything user-facing. */
  config_id: string;
  /** Wire-level rendezvous handle that peers share to find each
   *  other (e.g. `home-mesh`). Falls back to this when `label` is
   *  empty. */
  network_id: string;
  /** Cosmetic display name picked at create time. Empty string when
   *  the user didn't pick one. */
  label: string;
  phase: MeshPhase;
  topology: TopologyMode;
}

/** What to show the human for a network. Mirrors MyOwnLLM's pattern:
 *  prefer the user-picked cosmetic `label`, fall back to the
 *  human-typed `network_id` (e.g. `home-mesh`), and only as a last
 *  resort fall back to the auto-generated `config_id` (the
 *  `net_<rand>_<stamp>` blob the user never sees in MyOwnLLM).
 *  Anywhere the GUI used to render `config_id` as a label should go
 *  through this. The raw ids stay available for tooltips / debug
 *  chips. */
export function networkDisplayName(net: {
  label?: string;
  network_id?: string;
  config_id?: string;
}): string {
  const label = net.label?.trim();
  if (label) return label;
  const netId = net.network_id?.trim();
  if (netId) return netId;
  return net.config_id ?? "";
}

// ---- identity ---------------------------------------------------------

export interface IdentityInfo {
  device_id: string;
  pubkey: string;
  label: string;
}

// ---- daemon status ----------------------------------------------------

export interface DaemonStatus {
  version: string;
  device_id: string;
  joined_networks: string[];
}

// ---- events -----------------------------------------------------------

export type DiagLevel = "debug" | "info" | "warn" | "error";

export interface DiagEntry {
  network_id: string;
  level: DiagLevel;
  category: string;
  message: string;
  detail: unknown;
}

export type DropReason =
  | { kind: "denied" }
  | { kind: "ice_failed" }
  | { kind: "auth_failed" }
  | { kind: "user_left" }
  | { kind: "heartbeat_timeout" }
  | { kind: "transport_error"; message: string };

export type PeerEvent =
  | { kind: "sighted"; network_id: string; device_id: string }
  | {
      kind: "authenticated";
      network_id: string;
      device_id: string;
      label: string;
      verification_code: string;
      capabilities: CapabilityAdvert;
      rostered: boolean;
    }
  | { kind: "approved"; network_id: string; device_id: string; label: string }
  | {
      kind: "shelved";
      network_id: string;
      device_id: string;
      reason: string | null;
      by_us: boolean;
    }
  | { kind: "unshelved"; network_id: string; device_id: string; by_us: boolean }
  | {
      kind: "capabilities_changed";
      network_id: string;
      device_id: string;
      capabilities: CapabilityAdvert;
    }
  | {
      kind: "dropped";
      network_id: string;
      device_id: string;
      reason: DropReason;
      grace_window_ms: number;
    };

export type PhaseEvent = {
  kind: "changed";
  network_id: string;
  prev: MeshPhase;
  next: MeshPhase;
};

export type MeshEvent =
  | { kind: "peer"; [k: string]: unknown }
  | { kind: "phase"; [k: string]: unknown }
  | { kind: "diag"; [k: string]: unknown };

// Wrapper emitted by the daemon's event stream — distinguishes a
// regular event from a "lagged" notification (slow subscriber).
export type StreamFrame =
  | { kind: "event"; event: MeshEvent }
  | { kind: "lagged"; skipped: number };

// Tauri "mesh://subscription" status payload.
export interface SubscriptionStatus {
  status: "live" | "disconnected";
  error?: string;
}
