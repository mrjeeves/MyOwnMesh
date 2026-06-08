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

// ---- infrastructure services (relay / signaling / STUN / TURN) -------
//
// Device-level service hosting. The *config* shapes mirror
// `myownmesh_core::config::ServicesConfig` (the write shape sent into
// `ServicesSet`); the *report* shapes mirror the daemon's
// `ServicesReport` (the live status returned by `ServicesStatus`). These
// toggles apply to the whole device, not a single network.

export interface NodeServiceConfig {
  enabled: boolean;
}

export interface RelayServiceConfig {
  enabled: boolean;
  max_fanout: number;
}

/** Flood-protection limits for the self-hosted signaling relay. `0`
 *  means "no limit" for any field. */
export interface SignalingLimits {
  max_event_rate: number;
  max_req_rate: number;
  max_subscriptions: number;
  max_filters_per_req: number;
  max_message_bytes: number;
  max_connections_per_ip: number;
}

export interface SignalingServerConfig {
  enabled: boolean;
  bind: string;
  port: number;
  limits: SignalingLimits;
}

export interface StunServiceConfig {
  enabled: boolean;
  bind: string;
  port: number;
}

export interface TurnCredential {
  username: string;
  password: string;
}

export interface TurnServiceConfig {
  enabled: boolean;
  bind: string;
  port: number;
  public_ip: string;
  realm: string;
  credentials: TurnCredential[];
  /** Per-connection (per-allocation) relayed-bandwidth cap in bytes per
   *  second, each direction. 0 = unlimited. */
  max_bps_per_connection: number;
}

export interface ServicesConfig {
  /** Mesh participation. Off = pure-infrastructure box. */
  node: NodeServiceConfig;
  relay: RelayServiceConfig;
  signaling: SignalingServerConfig;
  stun: StunServiceConfig;
  turn: TurnServiceConfig;
}

/** Live activity for the signaling relay — `connections: 0` is the tell
 *  that peers aren't reaching it (DNS / TLS / firewall). */
export interface RelayStatsSnapshot {
  connections: number;
  connections_total: number;
  rooms: number;
  events_relayed: number;
}

/** Live status of one network-listener service (signaling / STUN /
 *  TURN). `running` differs from `enabled` when a start failed — e.g. a
 *  port already in use, or TURN enabled without credentials. `activity`
 *  is present only for the signaling relay. */
export interface EndpointReport {
  enabled: boolean;
  running: boolean;
  listen: string | null;
  activity?: RelayStatsSnapshot | null;
}

export interface RelayReport {
  enabled: boolean;
  networks: number;
  max_fanout: number;
}

export interface NodeReport {
  enabled: boolean;
  /** Networks joined as a node (0 in pure-infrastructure mode). */
  joined: number;
}

export interface ServicesReport {
  node: NodeReport;
  relay: RelayReport;
  signaling: EndpointReport;
  stun: EndpointReport;
  turn: EndpointReport;
}

/** Daemon response to `ServicesStatus`: the live runtime status plus the
 *  persisted config the toggles edit. */
export interface ServicesStatusResponse {
  status: ServicesReport;
  config: ServicesConfig;
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
  /** 5-char UPPERCASE-HEX display tag derived from the peer's
   *  pubkey. Surfaced separately so the GUI can render it in a
   *  distinct "suffix" tile during pending-approval, where users
   *  read it aloud to confirm the right device is on the other end. */
  device_suffix: string;
  /** Verification code the PEER sent us in their `hello` — i.e.
   *  the peer's own code, displayed as "theirs" in the approval
   *  UI. 6 chars `[a-z0-9]`. `null` until we receive their hello. */
  verification_code_received: string | null;
  /** Verification code WE sent the peer in our `hello` — i.e. our
   *  own code, displayed as "ours" in the approval UI. The pair
   *  (received, sent) is what the user reads aloud to the other
   *  side: both sides display the same four values (this device's
   *  suffix + code, the peer's suffix + code) so confirmation is
   *  symmetric and the connection is truly bilateral. `null` until
   *  our handshake has fired. */
  verification_code_sent: string | null;
  /** True once we've sent our local Approve to this peer. Pairs
   *  with `remote_approve_seen`; the engine transitions the peer
   *  to Active only when BOTH are true. The approval UI uses this
   *  to flip the row from "review and approve" to "awaiting peer
   *  approval" once the local user has clicked Approve. */
  local_approve_sent: boolean;
  /** True once the peer has sent us their Approve. When set while
   *  `local_approve_sent` is still false, the UI surfaces "the
   *  peer has already approved you — confirm to complete." */
  remote_approve_seen: boolean;
  /** Engine has decided the peer is unreachable without a TURN
   *  relay — repeated ICE failures and zero relay candidates on
   *  either side. The graph paints a "needs TURN" badge on these
   *  so the user doesn't have to grep the Activity log to learn
   *  why the data pipe never comes up. */
  needs_turn: boolean;
  /** Counts of ICE candidate kinds we gathered locally for this
   *  peer. The graph uses them to decide how to draw the link —
   *  host-host pairs sit next to "you" as LAN; anything with srflx
   *  or relay sits on the far side of the Internet node. */
  local_candidates: IceCandidateStats;
  /** Same as `local_candidates`, for candidates the peer sent us.
   *  Both sides have to advertise a host candidate before we call
   *  the link LAN-direct. */
  remote_candidates: IceCandidateStats;
  /** The ICE candidate pair the agent actually selected for sending
   *  packets. Set once ICE reaches Connected. Authoritative input
   *  for link classification — supersedes the heuristic over
   *  `local_candidates` / `remote_candidates`. */
  selected_pair: SelectedCandidatePair | null;
}

export type IceCandidateKindStr =
  | "host"
  | "server_reflexive"
  | "peer_reflexive"
  | "relay"
  | "unknown";

export interface SelectedCandidatePair {
  local: IceCandidateKindStr;
  remote: IceCandidateKindStr;
}

export interface IceCandidateStats {
  host: number;
  server_reflexive: number;
  peer_reflexive: number;
  relay: number;
  unknown: number;
}

/** Coarse classification of the link to a peer — drives where the
 *  peer node is placed on the graph and how the edge is drawn.
 *
 *   - `lan`     direct: both sides surfaced a host candidate, no
 *               STUN / TURN inferred. Peer sits next to "you".
 *   - `stun`    server-reflexive in use: peer reached via a public
 *               internet path discovered through STUN. Routed
 *               through the Internet node.
 *   - `turn`    a relay candidate is in the mix on at least one
 *               side: data path runs through a TURN server.
 *   - `blocked` `needs_turn` flag is set — signaling sees the peer
 *               but ICE can't punch through and there's no relay.
 *   - `unknown` ICE hasn't gathered enough to classify yet, or the
 *               peer is offline/sighted-only. */
export type LinkKind = "lan" | "stun" | "turn" | "blocked" | "unknown";

/** Infer the link kind from a peer's selected ICE pair + flags.
 *  The selected pair (populated once ICE reaches Connected) is the
 *  authoritative input — gathered-candidate counts only tell us what
 *  was tried. We only fall back to candidate counts when ICE hasn't
 *  reported a selection yet.
 *
 *    1. `needs_turn`                      → `blocked`
 *    2. selected_pair has any relay       → `turn`
 *    3. selected_pair is host ↔ host      → `lan`
 *    4. selected_pair otherwise present   → `stun`
 *    5. no pair yet but relay candidates  → `turn` (best guess)
 *    6. no pair yet, srflx gathered       → `stun`
 *    7. otherwise                         → `unknown` */
export function linkKindOf(p: PeerInfo): LinkKind {
  if (p.needs_turn) return "blocked";
  const sp = p.selected_pair;
  if (sp) {
    if (sp.local === "relay" || sp.remote === "relay") return "turn";
    if (sp.local === "host" && sp.remote === "host") return "lan";
    return "stun";
  }
  const lc = p.local_candidates;
  const rc = p.remote_candidates;
  if ((lc?.relay ?? 0) > 0 || (rc?.relay ?? 0) > 0) return "turn";
  if ((lc?.server_reflexive ?? 0) > 0 || (rc?.server_reflexive ?? 0) > 0) {
    return "stun";
  }
  return "unknown";
}

// ---- roster -----------------------------------------------------------

export interface AuthorizedPeer {
  device_id: string;
  label: string;
  approved_at: number;
  /** Role this peer holds in the network's governance model. The
   *  field exists on every roster entry so the same on-disk shape
   *  works for `open` (everyone is `member`, the field is unused)
   *  and `closed` networks (the field gates roster-edit authority).
   *
   *  Optional in the wire shape — entries written before
   *  `network_state_v1` shipped don't carry the field and the GUI
   *  treats `undefined` as `"member"`. See
   *  [`docs/NETWORK-TYPES.md`](../../docs/NETWORK-TYPES.md). On a
   *  `closed` network the engine enforces this via the signed
   *  transition log; on an `open` network it's a cosmetic tag. */
  role?: Role;
}

// ---- governance (closed networks) ------------------------------------
//
// These mirror the daemon's signed closed-network state — the kind, the
// role map, the append-only transition log, and in-flight proposals. The
// engine owns and enforces all of it (every transition is a signed
// `network_state_*` frame verified against the quorum table in
// `docs/NETWORK-TYPES.md`); the GUI reads snapshots through
// `network-governance.svelte.ts` and issues mutations over the control
// socket.

/** Network kind. `open` is the default and matches the engine's
 *  current behaviour. `closed` adds role-based roster authority +
 *  signed network-state transitions. */
export type NetworkKind = "open" | "closed";

/** Three role tiers in a closed network. Members can only propose;
 *  controllers can add members; owners can add anything and approve
 *  network-kind transitions. */
export type Role = "owner" | "controller" | "member";

/** Per-role authority levels, exposed for UI gating logic. Pure
 *  function of the role enum; centralised so the role-radio,
 *  propose-button-disabled checks, and "why disabled" hints all
 *  agree. */
export const ROLE_RANK: Record<Role, number> = {
  owner: 3,
  controller: 2,
  member: 1,
};

export function canGrant(local: Role, target: Role): boolean {
  return ROLE_RANK[local] >= ROLE_RANK[target] && local !== "member";
}

export function roleColor(r: Role): string {
  switch (r) {
    case "owner":
      return "#fbbf24";
    case "controller":
      return "#60a5fa";
    case "member":
      return "#94a3b8";
  }
}

/** A pending signed-state proposal on a network. Carried in the
 *  governance store + surfaced as Approvals-tab cards on every
 *  member who needs to sign. */
export interface PendingProposal {
  id: string;
  /** Wall-clock ms the proposer floated the proposal. */
  created_at: number;
  /** Pubkey of the member who issued the proposal. */
  proposer: string;
  variant: PendingProposalVariant;
  /** Signers who've already ack'd `sign`. Always includes the proposer. */
  signers: string[];
  /** Members who've ack'd `deny`. Non-empty = proposal dead. */
  deniers: string[];
  /** True once the proposer has fired the split fallback. */
  split_spawned: boolean;
}

export type PendingProposalVariant =
  | { kind: "kind_change"; to: NetworkKind }
  | { kind: "role_grant"; target: string; to: Role }
  | { kind: "role_revoke"; target: string }
  | {
      kind: "split";
      /** Deterministic id of the network spawned by this split. */
      new_network_id: string;
      /** Members the proposer is bringing into the new closed network. */
      members: string[];
    };

/** Snapshot of a network's signed governance state — the kind, the
 *  per-peer role map, the transition log, and any in-flight proposals.
 *  Owned and emitted by the daemon; read here via the control socket. */
export interface NetworkStateView {
  kind: NetworkKind;
  /** Pubkey → role assignments. Pubkeys not in this map default to
   *  `member`. Open networks keep this empty (the role tag is
   *  cosmetic when no closed-network rules are enforced). */
  roles: Record<string, Role>;
  /** Append-only signed log of every transition this network has
   *  gone through. Most recent last. Empty on open networks that
   *  have never gone through a kind change. */
  transitions: NetworkTransition[];
  /** Proposals awaiting signatures or in deny/split-fallback. */
  pending: PendingProposal[];
  /** Last-known split derivations from this network (each spawning
   *  a new closed network with the listed members). Used to render
   *  the "also runs *N'*" chip on the Connections tab. */
  splits: SplitRecord[];
}

export interface NetworkTransition {
  at: number;
  variant: PendingProposalVariant;
  /** Pubkeys that signed this transition. */
  signers: string[];
}

export interface SplitRecord {
  new_network_id: string;
  spawned_at: number;
  spawned_by: string;
  members: string[];
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
  /** Optional governance kind. Field is intentionally optional so a
   *  pre-`network_state_v1` daemon can return the same JSON shape
   *  without emitting the field; the GUI treats `undefined` as
   *  `"open"`. */
  kind?: NetworkKind;
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

// ---- self-update ------------------------------------------------------
//
// Mirrors `myownmesh_updater::{UpdateStatus, CheckOutcome, UpdatePrefs}`.
// The daemon owns the actual check/stage/apply; the GUI just renders this
// status and forwards preference edits.

export interface UpdateStatus {
  current_version: string;
  /** `raw` self-updates; `package_manager` defers to the OS updater. */
  install_kind: "raw" | "package_manager";
  enabled: boolean;
  channel: string;
  /** `patch` | `minor` | `all` | `none`. */
  auto_apply: string;
  check_interval_hours: number;
  /** Unix seconds of the last successful feed check, or null. */
  last_check_at: number | null;
  /** Version staged and waiting to apply on next daemon start, or null. */
  staged_version: string | null;
  /** Effective release-feed URL for the active channel. */
  release_url: string;
  /** True when `release_url` comes from a config override (white-label). */
  release_url_overridden: boolean;
}

/** Outcome of a forced update check. Tagged by `outcome` (snake_case). */
export type UpdateCheckOutcome =
  | { outcome: "disabled" }
  | { outcome: "package_manager" }
  | { outcome: "not_due" }
  | { outcome: "up_to_date"; current: string; latest: string }
  | { outcome: "policy_blocked"; current: string; latest: string; policy: string }
  | { outcome: "staged"; version: string };

/** Partial updater-preferences edit. Omitted fields are left untouched.
 *  `stable_url` / `beta_url` are the white-labelling hook (empty string
 *  clears the override back to the default feed). */
export interface UpdatePrefs {
  enabled?: boolean;
  channel?: string;
  auto_apply?: string;
  check_interval_hours?: number;
  stable_url?: string;
  beta_url?: string;
}

// ---- events -----------------------------------------------------------

export type DiagLevel = "debug" | "info" | "warn" | "error";

export interface DiagEntry {
  /** Unix epoch milliseconds — the time the daemon produced the
   *  entry, rendered as HH:MM:SS in the Activity log. */
  ts: number;
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

/** Top-level mesh event. The outer family discriminator is
 *  `event_kind` (not `kind`) because both `PeerEvent` and
 *  `PhaseEvent` use `kind` for their internal variant tag — a
 *  single `kind` on both layers produced duplicate JSON keys where
 *  the inner one silently won the parse, leaving the GUI unable to
 *  tell families apart. With distinct tag names a consumer first
 *  branches on `event_kind` (peer | phase | diag) and then on
 *  `kind` (the variant within). Pinned by `events::wire_tests` on
 *  the Rust side. */
export type MeshEvent =
  | { event_kind: "peer"; kind: string; [k: string]: unknown }
  | { event_kind: "phase"; kind: string; [k: string]: unknown }
  | { event_kind: "diag"; [k: string]: unknown };

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
