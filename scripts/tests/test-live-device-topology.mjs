import assert from "node:assert/strict";
import test from "node:test";
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { planScaleTopology, rendezvousScore, validateCanonicalDeviceId, SCALE_STAGES } from "../live-device-topology.mjs";

// Test-only deterministic Ed25519 fixtures; never exported as deployment identities.
function encode32(bytes) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  let bits = 0, accumulator = 0, result = "";
  for (const byte of bytes) {
    accumulator = (accumulator << 8) | byte; bits += 8;
    while (bits >= 5) { bits -= 5; result += alphabet[(accumulator >> bits) & 31]; }
    accumulator &= (1 << bits) - 1;
  }
  if (bits) result += alphabet[(accumulator << (5 - bits)) & 31];
  return result;
}
const keyCache = new Map();
function key(index) {
  if (!keyCache.has(index)) {
    const seed = createHash("sha256").update(`topology-test-only:${index}`).digest();
    const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]), format: "der", type: "pkcs8" });
    keyCache.set(index, encode32(createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32)));
  }
  return keyCache.get(index);
}

function numeric(names, value) {
  return Object.fromEntries(names.trim().split(/\s+/).map((name) => [name, value]));
}
// Complete structural inputs to the pure planner, NOT a native resource grant or
// a claim that these synthetic storage bounds pass daemon semantic admission.
function baseConfig() {
  return {
    id: "base", network_id: "base-context", label: "scale test", kind: "open",
    event_capacity: 256, connection_trace_capacity: 256,
    topology: { kind: "full_mesh" }, tree: null, local_observations: null,
    auto_approve: true, pinned_peers: [], stun_servers: [], turn_servers: [],
    semantic_policy: numeric(`max_fact_encoded_bytes max_dependencies_per_fact max_authority_uses_per_fact
      max_authority_predecessors_per_use max_admitted_facts max_admitted_bytes max_quarantined_facts
      max_quarantined_bytes max_quarantined_facts_per_author max_quarantined_bytes_per_author
      max_retained_facts_per_author max_retained_bytes_per_author max_hot_history_facts
      max_dependency_edges max_ready_batch max_pending_proofs max_pending_proof_bytes
      max_proof_records max_proof_bytes max_proof_links max_author_usage_rows max_provisional_rows
      max_transaction_dirty_main_pages max_uncheckpointed_wal_frames max_freelist_pages
      max_fragmented_pages max_main_journal_bytes max_live_checkpoint_bytes max_database_bytes
      max_wal_bytes wal_checkpoint_threshold_bytes emergency_reserve_bytes`, 65536),
    routing_policy: { max_next_hops: 8, max_parallel_routes: 4, max_envelope_bytes: 65536,
      max_dedup_entries: 4096, max_dedup_bytes: 4194304, max_hop_budget: 4 },
    scheduler: {
      ...numeric(`reactive_announce_min_interval_ms reoffer_min_interval_ms stale_inbound_timeout_ms
        probe_ttl_ms probe_resolve_timeout_ms skew_warn_ms skew_clear_ms handshake_timeout_ms
        heartbeat_interval_ms heartbeat_timeout_ms wake_coalesce_ms wake_probe_delay_ms
        liveness_probe_min_interval_ms ice_disconnected_restart_ms state_watch_interval_ms
        data_channel_open_timeout_ms offer_build_timeout_ms ice_introspect_timeout_ms
        peer_send_timeout_ms restart_traffic_grace_ms relay_rescue_min_interval_ms
        network_change_restart_cooldown_ms reconnecting_grace_ms`, 2000),
      skew_warn_ticks: 3, handshake_hello_retry_schedule_ms: [5000, 7000, 10000],
      reconnect_retry_backoff_ms: [2000, 4000, 8000, 15000],
    },
    hub: { max_parallel_dials: 1, max_dials_per_pass: 1, max_advertisements_per_pass: 1,
      exploration_interval_ms: 4000, max_exploration_probes_per_pass: 1, max_exploration_peers_per_reply: 1,
      trickle_imin_ms: 4000, trickle_imax_ms: 8000, trickle_redundancy: 1,
      trickle_reset_window_ms: 8000, trickle_max_resets_per_window: 1 },
    closed_relay: { enabled: false, ...numeric(`max_allocations max_allocations_per_member
      max_pending_handshakes pending_handshake_timeout_ms replay_window max_frame_ciphertext_bytes
      queue_items_per_direction queue_bytes_per_direction bandwidth_rate_bytes_per_second
      bandwidth_burst_bytes idle_timeout_ms max_lifetime_ms max_control_bytes shutdown_grace_ms`, 64) },
    signaling: { strategy: "none", mdns: true, servers: [], redundancy: 1, denylist: [],
      public_fallback: false,
      mdns_policy: numeric(`max_active_connections max_discovered_peers outbound_queue_capacity
        max_resolve_owners event_capacity max_event_epochs max_txt_entries max_txt_bytes
        max_resolved_addresses dial_timeout_ms connection_idle_timeout_ms inbound_idle_timeout_ms
        reannounce_interval_ms query_deadline_ms accept_error_backoff_ms`, 1000),
      nostr_timing: { connect_timeout_ms: 30000, reconnect_initial_ms: 2000,
        reconnect_max_ms: 60000, reconnect_max_attempts: 6, jitter_percent: 15,
        fallback_poll_ms: 3000, fallback_activation_grace_ms: 20000,
        session_close_timeout_ms: 1000, announcer_cancel_quantum_ms: 1000 } },
  };
}
function input(stage = 10, mode = "hub_tree", hubCount = 3) {
  const rootCount = mode === "hub_tree" ? 1 : 0;
  return { stage, mode, kind: "open", network_id: "scale-test-context", base_network_config: baseConfig(),
    nodes: Array.from({ length: stage }, (_, i) => ({ device_id: key(i),
      physical_host: `host-${(i < rootCount ? 0 : i - rootCount) % 3}`,
      local_alias: `peer-${i}`, role: i < rootCount ? "root" : i < rootCount + hubCount ? "hub" : "leaf",
      ...(mode === "hub_tree" ? { tree_policy: { max_children: stage, max_backups: 0, max_pending: 1, max_age_ms: 600000 } } : {}) })) };
}
function oracleScore(spoke, hub) {
  // Independent byte-fold expression: guards against accidental BE or string-number ordering.
  const digest = createHash("sha256").update(spoke).update(":").update(hub).digest();
  return [...digest.subarray(0, 8)].reduce((total, byte, index) => total + BigInt(byte) * (256n ** BigInt(index)), 0n);
}
function assertManifest(plan) {
  const byId = new Map(plan.nodes.map((node) => [node.device_id, node]));
  const unique = new Set();
  for (const edge of plan.edges) {
    assert.ok(edge.a < edge.b);
    assert.ok(!unique.has(`${edge.a}:${edge.b}`)); unique.add(`${edge.a}:${edge.b}`);
    assert.ok(byId.get(edge.a).expected_neighbors.includes(edge.b));
    assert.ok(byId.get(edge.b).expected_neighbors.includes(edge.a));
    assert.equal(edge.placement, edge.a_host === edge.b_host ? "intra_host" : "inter_host");
  }
  assert.equal(plan.nodes.reduce((n, node) => n + node.expected_neighbors.length, 0), 2 * plan.edges.length);
  assert.equal(plan.counts.intra_host_edges + plan.counts.inter_host_edges, plan.edges.length);
  assert.equal(plan.hosts.reduce((n, host) => n + host.nodes, 0), plan.stage);
  for (const leaf of plan.nodes.filter((n) => n.role === "leaf")) {
    const ranked = plan.hubs.map((hub) => ({ hub, score: oracleScore(leaf.device_id, hub) }))
      .sort((a, b) => a.score === b.score ? (a.hub < b.hub ? -1 : 1) : (a.score > b.score ? -1 : 1));
    assert.equal(leaf.primary_candidate, ranked[0].hub);
    assert.deepEqual(leaf.expected_neighbors, [ranked[0].hub]);
  }
  const { plan_sha256, ...body } = plan;
  assert.equal(plan_sha256, createHash("sha256").update(JSON.stringify(body)).digest("hex"));
}

test("scale planner matches Rust little-endian rendezvous and canonical keys", () => {
  assert.equal(validateCanonicalDeviceId(key(0)), key(0));
  assert.equal(rendezvousScore(key(0), key(1)), oracleScore(key(0), key(1)));
  for (const invalid of [key(0).toUpperCase(), `${key(0)}-ABCDE`, `${key(0)}=`, "a".repeat(51), "7".repeat(52)]) {
    assert.throws(() => validateCanonicalDeviceId(invalid));
  }
  const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
  const badPadding = key(0).slice(0, -1) + alphabet[alphabet.indexOf(key(0).at(-1)) | 1];
  assert.throws(() => validateCanonicalDeviceId(badPadding), /padding/);
});

test("all finite stages have exact tree and R1 hub edge counts", () => {
  const hubCounts = [3, 3, 6, 9, 12], expectedHubs = [10, 50, 109, 277, 554];
  for (const [index, stage] of SCALE_STAGES.entries()) {
    for (const mode of ["hub_tree", "hubs"]) {
      const plan = planScaleTopology(input(stage, mode, hubCounts[index]));
      assert.equal(plan.counts.unique_edges, mode === "hub_tree" ? stage - 1 : expectedHubs[index]);
      assertManifest(plan);
      assert.ok(plan.nodes.every((n) => n.network_config.topology.kind === mode));
    }
  }
});

test("planner is permutation deterministic and preserves supplied configs without mutation", () => {
  const original = input(), before = structuredClone(original);
  const plan = planScaleTopology(original);
  const permuted = structuredClone(original); permuted.nodes.reverse();
  permuted.base_network_config = Object.fromEntries(Object.entries(permuted.base_network_config).reverse());
  assert.deepEqual(planScaleTopology(permuted), plan);
  assert.deepEqual(original, before);
  for (const node of plan.nodes) {
    assert.equal(node.network_config.id, node.local_alias);
    assert.equal(node.network_config.network_id, original.network_id);
    assert.equal(node.network_config.tree.max_children, original.stage);
    assert.deepEqual(node.network_config.semantic_policy, original.base_network_config.semantic_policy);
  }
  plan.nodes[0].network_config.hub.trickle_imin_ms = 99;
  assert.equal(plan.nodes[1].network_config.hub.trickle_imin_ms, 4000);
  assert.deepEqual(original, before);
});

test("actual child demand is sufficient at exact limits and one-less refuses", () => {
  const request = input(50), preview = planScaleTopology(request);
  for (const node of request.nodes) node.tree_policy.max_children = preview.nodes.find((p) => p.device_id === node.device_id).required_max_children;
  assertManifest(planScaleTopology(request));
  const occupiedHub = request.nodes.find((n) => n.role === "hub" && n.tree_policy.max_children > 0);
  occupiedHub.tree_policy.max_children--;
  assert.throws(() => planScaleTopology(request), /below actual assignment/);
});

test("capacity-weighted host placement and Closed shape do not invent authority", () => {
  const request = input(50); request.kind = "closed";
  for (const node of request.nodes.filter((n) => n.role === "leaf")) node.physical_host = "host-0";
  const plan = planScaleTopology(request); assertManifest(plan);
  assert.ok(plan.hosts.find((h) => h.physical_host === "host-0").nodes > 40);
  assert.ok(plan.nodes.every((n) => n.network_config.kind === "closed"));
  assert.equal(Object.hasOwn(plan, "bootstrap"), false);
  assert.equal(Object.hasOwn(plan, "resource_grant"), false);
});

test("planner refuses duplicate identities, aliases, excess roles and unsupported scope", () => {
  const changes = [
    (r) => { r.nodes[1].device_id = r.nodes[0].device_id; },
    (r) => { r.nodes[1].local_alias = r.nodes[0].local_alias; },
    (r) => { r.nodes[1].role = "root"; },
    (r) => { r.nodes[1].role = "leaf"; },
    (r) => { r.nodes[1].physical_host = "host-3"; },
    (r) => { r.nodes[1].tree_policy.max_children = Number.MAX_SAFE_INTEGER + 1; },
    (r) => { r.nodes[1].tree_policy.max_backups = 1; },
    (r) => { r.stage = 501; }, (r) => { r.nodes.pop(); },
    (r) => { r.mode = "full_mesh"; }, (r) => { r.kind = "silent"; },
    (r) => { r.network_id = " Not-Normalized "; },
  ];
  for (const change of changes) { const request = input(); change(request); assert.throws(() => planScaleTopology(request)); }
});

test("planner refuses incomplete policies, pins, fast timers and unbounded config", () => {
  const changes = [
    (c) => { delete c.semantic_policy.max_hot_history_facts; },
    (c) => { delete c.scheduler.reoffer_min_interval_ms; },
    (c) => { delete c.signaling.mdns_policy.max_discovered_peers; },
    (c) => { delete c.turn_servers; }, (c) => { c.pinned_peers = [key(8)]; },
    (c) => { c.hub.exploration_interval_ms = 20; }, (c) => { c.scheduler.state_watch_interval_ms = 5; },
    (c) => { c.routing_policy.max_hop_budget = 5; },
    (c) => { c.label = "x".repeat(4097); }, (c) => { c.self = c; },
    (c) => { Object.defineProperty(c, "label", { enumerable: true, get() { throw new Error("must not call"); } }); },
  ];
  for (const change of changes) { const request = input(); change(request.base_network_config); assert.throws(() => planScaleTopology(request), /scale topology:/); }
});
