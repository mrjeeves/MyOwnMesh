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

export type TopologyMode =
  | { Ring: { n_preferred: number | null } }
  | { Star: { hub: string } }
  | "FullMesh";

export function topologyName(t: TopologyMode): "ring" | "star" | "full_mesh" {
  if (typeof t === "string") return "full_mesh";
  if ("Ring" in t) return "ring";
  return "star";
}

export function topologyHub(t: TopologyMode): string | null {
  if (typeof t === "string") return null;
  if ("Star" in t) return t.Star.hub;
  return null;
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
  config_id: string;
  network_id: string;
  phase: MeshPhase;
  topology: TopologyMode;
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
