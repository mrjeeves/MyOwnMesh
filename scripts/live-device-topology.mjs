// Pure scale-case planner. No IO, processes, keys, grants, enrollment or dial commands.
// Edges are expected steady-state adjacency, NOT authority or runtime admission.
import { createHash } from "node:crypto";

export const SCALE_STAGES = Object.freeze([10, 50, 100, 250, 500]);
export const TOPOLOGY_PLAN_SCHEMA = "myownmesh.scale-topology.v1";
const BASE32 = "abcdefghijklmnopqrstuvwxyz234567";
const MAX_HUBS = 12;
const HUB_PROFILE = Object.freeze({
  max_parallel_dials: 1, max_dials_per_pass: 1, max_advertisements_per_pass: 1,
  exploration_interval_ms: 4000, max_exploration_probes_per_pass: 1,
  max_exploration_peers_per_reply: 1, trickle_imin_ms: 4000, trickle_imax_ms: 8000,
  trickle_redundancy: 1, trickle_reset_window_ms: 8000, trickle_max_resets_per_window: 1,
});
const SEMANTIC_FIELDS = `max_fact_encoded_bytes max_dependencies_per_fact
  max_authority_uses_per_fact max_authority_predecessors_per_use max_admitted_facts
  max_admitted_bytes max_quarantined_facts max_quarantined_bytes max_quarantined_facts_per_author
  max_quarantined_bytes_per_author max_retained_facts_per_author max_retained_bytes_per_author
  max_hot_history_facts max_dependency_edges max_ready_batch max_pending_proofs
  max_pending_proof_bytes max_proof_records max_proof_bytes max_proof_links max_author_usage_rows
  max_provisional_rows max_transaction_dirty_main_pages max_uncheckpointed_wal_frames
  max_freelist_pages max_fragmented_pages max_main_journal_bytes max_live_checkpoint_bytes
  max_database_bytes max_wal_bytes wal_checkpoint_threshold_bytes emergency_reserve_bytes`.split(/\s+/);
const SCHEDULER_FIELDS = `reactive_announce_min_interval_ms reoffer_min_interval_ms
  stale_inbound_timeout_ms probe_ttl_ms probe_resolve_timeout_ms skew_warn_ms skew_clear_ms
  skew_warn_ticks handshake_timeout_ms handshake_hello_retry_schedule_ms heartbeat_interval_ms
  heartbeat_timeout_ms wake_coalesce_ms wake_probe_delay_ms liveness_probe_min_interval_ms
  ice_disconnected_restart_ms state_watch_interval_ms reconnect_retry_backoff_ms
  data_channel_open_timeout_ms offer_build_timeout_ms ice_introspect_timeout_ms peer_send_timeout_ms
  restart_traffic_grace_ms relay_rescue_min_interval_ms network_change_restart_cooldown_ms
  reconnecting_grace_ms`.split(/\s+/);
const ROUTING_FIELDS = `max_next_hops max_parallel_routes max_envelope_bytes max_dedup_entries
  max_dedup_bytes max_hop_budget`.split(/\s+/);
const RELAY_FIELDS = `enabled max_allocations max_allocations_per_member max_pending_handshakes
  pending_handshake_timeout_ms replay_window max_frame_ciphertext_bytes queue_items_per_direction
  queue_bytes_per_direction bandwidth_rate_bytes_per_second bandwidth_burst_bytes idle_timeout_ms
  max_lifetime_ms max_control_bytes shutdown_grace_ms`.split(/\s+/);
const MDNS_FIELDS = `max_active_connections max_discovered_peers outbound_queue_capacity
  max_resolve_owners event_capacity max_event_epochs max_txt_entries max_txt_bytes
  max_resolved_addresses dial_timeout_ms connection_idle_timeout_ms inbound_idle_timeout_ms
  reannounce_interval_ms query_deadline_ms accept_error_backoff_ms`.split(/\s+/);
const NOSTR_FIELDS = `connect_timeout_ms reconnect_initial_ms reconnect_max_ms reconnect_max_attempts
  jitter_percent fallback_poll_ms fallback_activation_grace_ms session_close_timeout_ms
  announcer_cancel_quantum_ms`.split(/\s+/);

function requireValue(ok, message) {
  if (!ok) throw new TypeError(`scale topology: ${message}`);
}
function object(value, name) {
  requireValue(value !== null && typeof value === "object" && !Array.isArray(value)
    && Object.getPrototypeOf(value) === Object.prototype, `${name} must be a plain object`);
}
function fields(value, names, name) {
  object(value, name);
  requireValue(Object.keys(value).length === names.length
    && names.every((key) => Object.hasOwn(value, key)), `${name} needs exactly its explicit fields`);
}
function uint(value, name, minimum = 0) {
  requireValue(Number.isSafeInteger(value) && value >= minimum, `${name} must be a safe unsigned integer`);
}
function label(value, name) {
  requireValue(typeof value === "string" && /^[A-Za-z0-9_-]{1,128}$/.test(value), `${name} must be a bounded label`);
}
function numericPolicy(value, names, name) {
  fields(value, names, name);
  for (const key of names) uint(value[key], `${name}.${key}`);
}

// Bounded data-only copy, stable object-key order. Refuse cycles/accessors/non-JSON
// before serialization; never stringify errors/configs which may contain credentials.
function copyJson(value, budget = { left: 65536 }, depth = 0, ancestors = new Set()) {
  requireValue(depth <= 16 && --budget.left >= 0, "base config exceeds structural bound");
  if (typeof value === "string") {
    requireValue(value.length <= 4096, "config string exceeds bound");
    budget.left -= value.length;
    requireValue(budget.left >= 0, "base config exceeds text bound");
    return value;
  }
  if (value === null || typeof value === "boolean") return value;
  if (typeof value === "number") { uint(value, "config number"); return value; }
  requireValue(typeof value === "object" && !ancestors.has(value), "config must be acyclic JSON");
  ancestors.add(value);
  let result;
  if (Array.isArray(value)) {
    requireValue(value.length <= 512, "config array exceeds bound");
    result = value.map((item) => copyJson(item, budget, depth + 1, ancestors));
  } else {
    object(value, "config object");
    const keys = Object.keys(value).sort();
    requireValue(keys.length <= 128, "config object exceeds bound");
    result = {};
    for (const key of keys) {
      requireValue(key.length <= 128 && !["__proto__", "constructor", "prototype"].includes(key), "unsafe config key");
      const descriptor = Object.getOwnPropertyDescriptor(value, key);
      requireValue(Object.hasOwn(descriptor, "value"), "config accessors are not supported");
      result[key] = copyJson(descriptor.value, budget, depth + 1, ancestors);
    }
  }
  ancestors.delete(value);
  return result;
}

const P = (1n << 255n) - 19n;
const mod = (n) => ((n % P) + P) % P;
function pow(base, exponent) {
  let result = 1n;
  for (base = mod(base); exponent > 0n; exponent >>= 1n, base = mod(base * base)) {
    if (exponent & 1n) result = mod(result * base);
  }
  return result;
}
const EDWARDS_D = mod(-121665n * pow(121666n, P - 2n));

export function validateCanonicalDeviceId(value) {
  requireValue(typeof value === "string" && /^[a-z2-7]{52}$/.test(value), "device ID must be canonical base32");
  const bytes = Buffer.alloc(32);
  let bits = 0, accumulator = 0, index = 0;
  for (const char of value) {
    accumulator = (accumulator << 5) | BASE32.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes[index++] = accumulator >> bits;
      accumulator &= (1 << bits) - 1;
    }
  }
  requireValue(index === 32 && accumulator === 0, "device ID has nonzero base32 padding bits");
  // DeviceId::from_canonical_str also requires a decompressible Edwards point.
  // This bounded public-data check is NOT signature, membership or key-possession proof.
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(bytes[i]);
  y = mod(y & ((1n << 255n) - 1n));
  const yy = mod(y * y), denominator = mod(EDWARDS_D * yy + 1n);
  requireValue(denominator !== 0n, "invalid compressed Ed25519 key");
  const xx = mod((yy - 1n) * pow(denominator, P - 2n));
  requireValue(xx === 0n || pow(xx, (P - 1n) / 2n) === 1n, "invalid compressed Ed25519 key");
  return value;
}

// Rust topology/{hubs,tree}.rs: SHA256(ASCII(spoke + ':' + hub)), first 8
// digest bytes interpreted LITTLE endian, descending; ties use ASCII key order.
export function rendezvousScore(spoke, hub) {
  validateCanonicalDeviceId(spoke);
  validateCanonicalDeviceId(hub);
  return scoreUnchecked(spoke, hub);
}
function scoreUnchecked(spoke, hub) {
  return createHash("sha256").update(`${spoke}:${hub}`, "utf8").digest().readBigUInt64LE(0);
}
function primaryHub(spoke, hubs) {
  let best = null, bestScore = -1n;
  for (const hub of hubs) {
    const score = scoreUnchecked(spoke, hub.device_id);
    if (score > bestScore || (score === bestScore && hub.device_id < best.device_id)) {
      best = hub; bestScore = score;
    }
  }
  return best;
}

function validateBase(base) {
  const keys = `id network_id event_capacity connection_trace_capacity label kind scheduler
    semantic_policy topology routing_policy hub tree local_observations signaling closed_relay
    stun_servers turn_servers pinned_peers auto_approve`.split(/\s+/);
  fields(base, keys, "base_network_config");
  uint(base.event_capacity, "event_capacity", 1);
  uint(base.connection_trace_capacity, "connection_trace_capacity", 1);
  requireValue(Array.isArray(base.pinned_peers) && base.pinned_peers.length === 0, "routed case must not contain pins");
  requireValue(typeof base.auto_approve === "boolean", "auto_approve must be explicit");
  requireValue(base.tree === null && base.local_observations === null, "base tree/observations must be null; tree limits are per node");
  for (const key of ["stun_servers", "turn_servers"]) requireValue(Array.isArray(base[key]), `${key} must be explicit`);
  numericPolicy(base.semantic_policy, SEMANTIC_FIELDS, "semantic_policy");
  numericPolicy(base.routing_policy, ROUTING_FIELDS, "routing_policy");
  requireValue(Object.values(base.routing_policy).every((v) => v > 0)
    && base.routing_policy.max_parallel_routes <= base.routing_policy.max_next_hops
    && base.routing_policy.max_hop_budget === 4, "routing policy must retain the four-hop bounded path");
  fields(base.scheduler, SCHEDULER_FIELDS, "scheduler");
  for (const key of SCHEDULER_FIELDS) {
    const length = key === "handshake_hello_retry_schedule_ms" ? 3 : key === "reconnect_retry_backoff_ms" ? 4 : 0;
    if (length) {
      requireValue(Array.isArray(base.scheduler[key]) && base.scheduler[key].length === length, `scheduler.${key} length`);
      base.scheduler[key].forEach((v) => uint(v, key, 1));
    } else uint(base.scheduler[key], key, 1);
  }
  requireValue(base.scheduler.state_watch_interval_ms === 2000, "scale case requires nonfast 2000ms state watch");
  fields(base.hub, Object.keys(HUB_PROFILE), "hub");
  for (const key of Object.keys(HUB_PROFILE)) requireValue(base.hub[key] === HUB_PROFILE[key], `hub.${key} differs from reviewed nonfast profile`);
  fields(base.closed_relay, RELAY_FIELDS, "closed_relay");
  requireValue(typeof base.closed_relay.enabled === "boolean", "closed_relay.enabled must be explicit");
  for (const key of RELAY_FIELDS.filter((k) => k !== "enabled")) uint(base.closed_relay[key], key);
  fields(base.signaling, ["strategy", "mdns", "servers", "redundancy", "denylist", "public_fallback", "mdns_policy", "nostr_timing"], "signaling");
  requireValue(["none", "nostr"].includes(base.signaling.strategy), "unsupported signaling strategy");
  requireValue(typeof base.signaling.mdns === "boolean" && typeof base.signaling.public_fallback === "boolean", "signaling flags must be explicit");
  for (const key of ["servers", "denylist"]) requireValue(Array.isArray(base.signaling[key]), `signaling.${key} must be explicit`);
  numericPolicy(base.signaling.mdns_policy, MDNS_FIELDS, "mdns_policy");
  numericPolicy(base.signaling.nostr_timing, NOSTR_FIELDS, "nostr_timing");
  uint(base.signaling.redundancy, "signaling.redundancy", 1);
  // Daemon config admission remains authoritative for nested protocol/storage
  // constraints. This planner does not grant resources or certify enrollment.
}

/**
 * Caller selects the exact stage subset and capacity-weighted physical placement.
 * This case family permits 3..12 hubs, at least one on each of three hosts;
 * it never chooses hosts, roles, stage subsets or capacity on the caller's behalf.
 * Each node: device_id, physical_host, role(root/hub/leaf), local_alias; tree mode
 * additionally requires complete tree_policy. Closed only sets bootstrap shape:
 * real signed enrollment MUST precede timed traffic. No topology or key is authority.
 * plan_sha256 hashes JSON.stringify(the returned object WITHOUT plan_sha256).
 * Object keys/configs and arrays are deterministically ordered, never locale-sorted.
 * Returned configs may contain supplied server credentials; retain privately.
 */
export function planScaleTopology(input) {
  fields(input, ["stage", "mode", "kind", "network_id", "nodes", "base_network_config"], "input");
  requireValue(SCALE_STAGES.includes(input.stage), "unsupported stage");
  requireValue(["hubs", "hub_tree"].includes(input.mode), "only Hubs R1 and HubTree backup0 are supported");
  requireValue(["open", "closed"].includes(input.kind), "only Open/Closed cases are supported");
  requireValue(typeof input.network_id === "string" && /^[a-z0-9_-]{3,64}$/.test(input.network_id), "wire context must already be normalized");
  requireValue(Array.isArray(input.nodes) && input.nodes.length === input.stage, "node count must equal stage");
  const base = copyJson(input.base_network_config);
  validateBase(base);
  const nodes = [], ids = new Set(), aliases = new Set(), hostIds = new Set();
  for (const supplied of input.nodes) {
    fields(supplied, ["device_id", "physical_host", "role", "local_alias", ...(input.mode === "hub_tree" ? ["tree_policy"] : [])], "node");
    const node = copyJson(supplied);
    validateCanonicalDeviceId(node.device_id);
    label(node.physical_host, "physical_host"); label(node.local_alias, "local_alias");
    requireValue(["root", "hub", "leaf"].includes(node.role), "invalid node role");
    requireValue(!ids.has(node.device_id) && !aliases.has(node.local_alias), "duplicate key or local alias");
    ids.add(node.device_id); aliases.add(node.local_alias); hostIds.add(node.physical_host);
    if (input.mode === "hub_tree") {
      numericPolicy(node.tree_policy, ["max_children", "max_backups", "max_pending", "max_age_ms"], "tree_policy");
      requireValue(node.tree_policy.max_backups === 0 && node.tree_policy.max_pending === 1
        && node.tree_policy.max_age_ms > 0, "tree requires backup0/pending1/finite positive age");
    }
    nodes.push(node);
  }
  requireValue(hostIds.size === 3, "exactly three supplied physical hosts are required");
  nodes.sort((a, b) => a.device_id < b.device_id ? -1 : 1);
  const roots = nodes.filter((n) => n.role === "root"), hubs = nodes.filter((n) => n.role === "hub"), leaves = nodes.filter((n) => n.role === "leaf");
  requireValue(roots.length === (input.mode === "hub_tree" ? 1 : 0), "incorrect root count");
  requireValue(hubs.length >= 3 && hubs.length <= MAX_HUBS && leaves.length > 0, "require 3..12 hubs and at least one leaf");
  requireValue(new Set(hubs.map((n) => n.physical_host)).size === 3, "each physical machine must host a hub");
  const children = new Map(nodes.map((n) => [n.device_id, []]));
  const neighbors = new Map(nodes.map((n) => [n.device_id, []]));
  const parent = new Map(), edges = [];
  function edge(left, right, kind) {
    const [a, b] = left.device_id < right.device_id ? [left, right] : [right, left];
    edges.push({ a: a.device_id, b: b.device_id, a_host: a.physical_host, b_host: b.physical_host,
      placement: a.physical_host === b.physical_host ? "intra_host" : "inter_host", kind });
    neighbors.get(a.device_id).push(b.device_id); neighbors.get(b.device_id).push(a.device_id);
  }
  if (input.mode === "hub_tree") {
    for (const hub of hubs) {
      edge(roots[0], hub, "root_hub"); parent.set(hub.device_id, roots[0].device_id);
      children.get(roots[0].device_id).push(hub.device_id);
    }
  } else {
    for (let i = 0; i < hubs.length; i++) for (let j = i + 1; j < hubs.length; j++) edge(hubs[i], hubs[j], "hub_hub");
  }
  for (const leaf of leaves) {
    const hub = primaryHub(leaf.device_id, hubs);
    edge(hub, leaf, "hub_leaf"); parent.set(leaf.device_id, hub.device_id);
    children.get(hub.device_id).push(leaf.device_id);
  }
  edges.sort((a, b) => a.a === b.a ? (a.b < b.b ? -1 : 1) : (a.a < b.a ? -1 : 1));
  const topology = input.mode === "hub_tree"
    ? { kind: "hub_tree", root: roots[0].device_id, hubs: hubs.map((n) => n.device_id), backup_candidates: 0 }
    : { kind: "hubs", hubs: hubs.map((n) => n.device_id), spoke_redundancy: 1 };
  const outputNodes = nodes.map((node) => {
    const assigned = children.get(node.device_id).sort();
    const required = input.mode === "hub_tree" ? assigned.length : 0;
    if (input.mode === "hub_tree") requireValue(node.tree_policy.max_children >= required, "supplied tree child capacity is below actual assignment");
    return { device_id: node.device_id, physical_host: node.physical_host, local_alias: node.local_alias,
      role: node.role, primary_candidate: parent.get(node.device_id) ?? null,
      assigned_children: assigned, required_max_children: required,
      expected_neighbors: neighbors.get(node.device_id).sort(),
      network_config: { ...copyJson(base), id: node.local_alias, network_id: input.network_id,
        kind: input.kind, topology: copyJson(topology), tree: input.mode === "hub_tree" ? copyJson(node.tree_policy) : null } };
  });
  const hosts = [...hostIds].sort().map((physical_host) => {
    const local = outputNodes.filter((n) => n.physical_host === physical_host);
    return { physical_host, nodes: local.length, roots: local.filter((n) => n.role === "root").length,
      hubs: local.filter((n) => n.role === "hub").length, leaves: local.filter((n) => n.role === "leaf").length,
      intra_host_edges: edges.filter((e) => e.placement === "intra_host" && e.a_host === physical_host).length,
      inter_host_incident_edges: edges.filter((e) => e.placement === "inter_host" && (e.a_host === physical_host || e.b_host === physical_host)).length };
  });
  const result = { schema: TOPOLOGY_PLAN_SCHEMA, stage: input.stage, mode: input.mode, kind: input.kind,
    network_id: input.network_id, root: roots[0]?.device_id ?? null,
    hubs: hubs.map((n) => n.device_id), leaves: leaves.map((n) => n.device_id), nodes: outputNodes,
    edges, counts: { nodes: nodes.length, roots: roots.length, hubs: hubs.length, leaves: leaves.length,
      unique_edges: edges.length, intra_host_edges: edges.filter((e) => e.placement === "intra_host").length,
      inter_host_edges: edges.filter((e) => e.placement === "inter_host").length }, hosts };
  return { ...result, plan_sha256: createHash("sha256").update(JSON.stringify(result)).digest("hex") };
}
