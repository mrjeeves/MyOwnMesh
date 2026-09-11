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
import type {
  NetworkConfigInput,
  SemanticPolicyConfig,
  TopologyMode,
} from "./types";

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

/** Defaults mirrored from `SemanticPolicyConfig::default` in the daemon.
 *  Keep this complete so exporting an older or partially materialised config
 *  never drops a policy dimension. */
export const DEFAULT_SEMANTIC_POLICY: SemanticPolicyConfig = {
  max_fact_encoded_bytes: 65_535,
  max_dependencies_per_fact: 64,
  max_authority_uses_per_fact: 32,
  max_authority_predecessors_per_use: 64,
  max_admitted_facts: 100_000,
  max_admitted_bytes: 128 * 1024 * 1024,
  max_quarantined_facts: 4_096,
  max_quarantined_bytes: 16 * 1024 * 1024,
  max_quarantined_facts_per_author: 256,
  max_quarantined_bytes_per_author: 4 * 1024 * 1024,
  max_retained_facts_per_author: 10_000,
  max_retained_bytes_per_author: 16 * 1024 * 1024,
  max_dependency_edges: 1_000_000,
  max_ready_batch: 256,
  max_pending_proofs: 10_000,
  max_pending_proof_bytes: 16 * 1024 * 1024,
  max_proof_records: 100_000,
  max_proof_bytes: 64 * 1024 * 1024,
  max_proof_links: 100_000,
  max_author_usage_rows: 100_000,
  max_provisional_rows: 100_000,
  max_transaction_dirty_main_pages: 1024,
  max_uncheckpointed_wal_frames: 1_018,
  max_freelist_pages: 1024,
  max_fragmented_pages: 1024,
  max_main_journal_bytes: 8 * 1024 * 1024,
  max_database_bytes: 2 * 1024 * 1024 * 1024,
  max_wal_bytes: 8_413_072,
  wal_checkpoint_threshold_bytes: 32 + 1_018 * (4_096 + 24),
  emergency_reserve_bytes: 8 * 1024 * 1024,
};

export const SEMANTIC_POLICY_FIELDS = [
  "max_fact_encoded_bytes",
  "max_dependencies_per_fact",
  "max_authority_uses_per_fact",
  "max_authority_predecessors_per_use",
  "max_admitted_facts",
  "max_admitted_bytes",
  "max_quarantined_facts",
  "max_quarantined_bytes",
  "max_quarantined_facts_per_author",
  "max_quarantined_bytes_per_author",
  "max_retained_facts_per_author",
  "max_retained_bytes_per_author",
  "max_dependency_edges",
  "max_ready_batch",
  "max_pending_proofs",
  "max_pending_proof_bytes",
  "max_proof_records",
  "max_proof_bytes",
  "max_proof_links",
  "max_author_usage_rows",
  "max_provisional_rows",
  "max_transaction_dirty_main_pages",
  "max_uncheckpointed_wal_frames",
  "max_freelist_pages",
  "max_fragmented_pages",
  "max_main_journal_bytes",
  "max_database_bytes",
  "max_wal_bytes",
  "wal_checkpoint_threshold_bytes",
  "emergency_reserve_bytes",
] as const satisfies readonly (keyof SemanticPolicyConfig)[];

export interface SemanticStorageEnvelope {
  page_size_bytes: number;
  main_pages: number;
  main_bytes: number;
  main_journal_bytes: number;
  wal_frames: number;
  wal_bytes: number;
  shm_bytes: number;
  emergency_reserve_bytes: number;
  total_bytes: number;
}

const SQLITE_WAL_HEADER_BYTES = 32;
const SQLITE_WAL_FRAME_OVERHEAD_BYTES = 24;
const SQLITE_SHM_CHUNK_BYTES = 32_768;
const SQLITE_SHM_FIRST_CHUNK_FRAMES = 4_062;
const SQLITE_SHM_FOLLOWING_CHUNK_FRAMES = 4_096;
const FACT_ID_BYTES = 32;
const DEVICE_KEY_BYTES = 32;
const SQL_INTEGER_BYTES = 8;
const FACT_STATUS_MAX_BYTES = 11;
const FACT_DOMAIN_MAX_BYTES = 16;
const PROOF_STATE_MAX_BYTES = 12;
const META_KEY_MAX_BYTES = 16;
const COMMITMENT_NAME_MAX_BYTES = 10;
const SEMANTIC_INGRESS_OWNER_MAX_BYTES = 16;

function checkedAdd(...values: number[]): number | null {
  let result = 0;
  for (const value of values) {
    result += value;
    if (!Number.isSafeInteger(result)) return null;
  }
  return result;
}

function checkedMul(left: number, right: number): number | null {
  const result = left * right;
  return Number.isSafeInteger(result) ? result : null;
}

function checkedCeilDiv(value: number, divisor: number): number | null {
  if (divisor <= 0) return null;
  const rounded = checkedAdd(value, divisor - 1);
  return rounded === null ? null : Math.floor(rounded / divisor);
}

function checkedObjectPages(
  rows: number,
  payloadBytes: number,
  usable: number,
  leafCapacity: number,
  interiorCapacity: number,
): number | null {
  const recordHeaderBytes = checkedMul(rows, 13);
  const pointerBytes = checkedMul(rows, 2);
  const recordBytes = recordHeaderBytes === null || pointerBytes === null
    ? null
    : checkedAdd(payloadBytes, recordHeaderBytes, pointerBytes);
  if (recordBytes === null) return null;
  if (usable < 4) return null;
  const overflowPayload = usable - 4;
  const overflow = checkedCeilDiv(payloadBytes, overflowPayload);
  const leaves = checkedCeilDiv(recordBytes, leafCapacity);
  if (overflow === null || leaves === null) return null;
  const interior = checkedCeilDiv(Math.max(leaves - 1, 0), interiorCapacity);
  return interior === null ? null : checkedAdd(Math.max(leaves, 1), interior, overflow, 1);
}

/** Mirror the Rust checked_storage_envelope planner for a selected page size. */
export function checkedSemanticStorageEnvelope(
  policy: SemanticPolicyConfig,
  pageSizeBytes = 4_096,
): SemanticStorageEnvelope | null {
  if (!Number.isSafeInteger(pageSizeBytes) || pageSizeBytes <= 0) return null;
  for (const field of SEMANTIC_POLICY_FIELDS) {
    if (!Number.isSafeInteger(policy[field]) || policy[field] <= 0) return null;
  }
  const usable = pageSizeBytes - 8;
  if (usable < 2) return null;
  const leafCapacity = usable - 2;
  const interiorCapacity = Math.max(Math.floor(usable / 16), 2);
  const objectPages = (rows: number, payload: number) =>
    checkedObjectPages(rows, payload, usable, Math.max(leafCapacity, 1), interiorCapacity);
  const checkedSum = (values: number[]) => checkedAdd(...values);
  const checkedRows = (rows: number, bytesPerRow: number) => checkedMul(rows, bytesPerRow);
  const factRows = checkedAdd(policy.max_admitted_facts, policy.max_quarantined_facts);
  const factPayload = factRows === null
    ? null
    : (() => {
        const bytesPerRow = checkedSum([
          FACT_ID_BYTES,
          FACT_STATUS_MAX_BYTES,
          DEVICE_KEY_BYTES,
          FACT_DOMAIN_MAX_BYTES,
          SQL_INTEGER_BYTES,
        ]);
        const rowBytes = bytesPerRow === null ? null : checkedRows(factRows, bytesPerRow);
        return rowBytes === null
          ? null
          : checkedAdd(policy.max_admitted_bytes, policy.max_quarantined_bytes, rowBytes);
      })();
  const dependencyPayload = checkedRows(policy.max_dependency_edges, 2 * FACT_ID_BYTES);
  const proofIndexBytes = checkedRows(
    policy.max_proof_records,
    FACT_ID_BYTES * 3 + PROOF_STATE_MAX_BYTES,
  );
  const proofPayload = proofIndexBytes === null
    ? null
    : checkedAdd(policy.max_proof_bytes, proofIndexBytes);
  if (factRows === null || factPayload === null || dependencyPayload === null || proofPayload === null) {
    return null;
  }
  const metaPayload = checkedSum([META_KEY_MAX_BYTES, 4, 10, FACT_ID_BYTES]);
  const authorPayload = checkedRows(
    policy.max_author_usage_rows,
    DEVICE_KEY_BYTES + 4 * SQL_INTEGER_BYTES,
  );
  const provisionalPayload = checkedRows(
    policy.max_provisional_rows,
    FACT_ID_BYTES + SEMANTIC_INGRESS_OWNER_MAX_BYTES,
  );
  const proofLinkPayload = checkedRows(policy.max_proof_links, 2 * FACT_ID_BYTES);
  if (
    metaPayload === null ||
    authorPayload === null ||
    provisionalPayload === null ||
    proofLinkPayload === null
  ) {
    return null;
  }
  const tableInputs: Array<[number, number]> = [
    [2, metaPayload],
    [factRows, factPayload],
    [1, SQL_INTEGER_BYTES + 8 * SQL_INTEGER_BYTES],
    [policy.max_author_usage_rows, authorPayload],
    [policy.max_dependency_edges, dependencyPayload],
    [policy.max_provisional_rows, provisionalPayload],
    [policy.max_proof_records, proofPayload],
    [policy.max_proof_links, proofLinkPayload],
    [1, COMMITMENT_NAME_MAX_BYTES + FACT_ID_BYTES],
    [1, SQL_INTEGER_BYTES + 5 * SQL_INTEGER_BYTES],
  ];
  let mainPages = 1;
  for (const [rows, payload] of tableInputs) {
    const pages = objectPages(rows, payload);
    if (pages === null) return null;
    const nextPages = checkedAdd(mainPages, pages);
    if (nextPages === null) return null;
    mainPages = nextPages;
  }
  const primaryTrees: Array<[number, number]> = [
    [2, META_KEY_MAX_BYTES],
    [factRows, FACT_ID_BYTES],
    [1, SQL_INTEGER_BYTES],
    [policy.max_author_usage_rows, DEVICE_KEY_BYTES],
    [policy.max_dependency_edges, 2 * FACT_ID_BYTES],
    [
      policy.max_provisional_rows,
      FACT_ID_BYTES + SEMANTIC_INGRESS_OWNER_MAX_BYTES,
    ],
    [policy.max_proof_records, FACT_ID_BYTES],
    [policy.max_proof_links, 2 * FACT_ID_BYTES],
    [1, COMMITMENT_NAME_MAX_BYTES],
    [1, SQL_INTEGER_BYTES],
  ];
  for (const [rows, keyRows] of primaryTrees) {
    const payload = checkedRows(rows, keyRows);
    const pages = payload === null ? null : objectPages(rows, payload);
    if (pages === null) return null;
    const nextPages = checkedAdd(mainPages, pages);
    if (nextPages === null) return null;
    mainPages = nextPages;
  }
  const secondaryTrees: Array<[number, number]> = [
    [factRows, FACT_STATUS_MAX_BYTES],
    [factRows, DEVICE_KEY_BYTES],
    [factRows, SQL_INTEGER_BYTES],
    [factRows, FACT_DOMAIN_MAX_BYTES + SQL_INTEGER_BYTES],
    [policy.max_dependency_edges, FACT_ID_BYTES],
    [policy.max_proof_links, FACT_ID_BYTES],
  ];
  for (const [rows, keyRows] of secondaryTrees) {
    const payload = checkedRows(rows, keyRows);
    const pages = payload === null ? null : objectPages(rows, payload);
    if (pages === null) return null;
    const nextPages = checkedAdd(mainPages, pages);
    if (nextPages === null) return null;
    mainPages = nextPages;
  }
  const pageTotal = checkedAdd(
    mainPages,
    policy.max_transaction_dirty_main_pages,
    policy.max_freelist_pages,
    policy.max_fragmented_pages,
  );
  if (pageTotal === null) return null;
  mainPages = pageTotal;
  const mainBytes = checkedMul(mainPages, pageSizeBytes);
  const frameBytes = checkedAdd(pageSizeBytes, SQLITE_WAL_FRAME_OVERHEAD_BYTES);
  const walFrameBytes = frameBytes === null
    ? null
    : checkedMul(policy.max_uncheckpointed_wal_frames, frameBytes);
  const walBytes = walFrameBytes === null
    ? null
    : checkedAdd(SQLITE_WAL_HEADER_BYTES, walFrameBytes);
  if (mainBytes === null || frameBytes === null || walBytes === null) return null;
  if (walBytes > policy.max_wal_bytes) return null;
  const walFrames = policy.max_uncheckpointed_wal_frames;
  let shmChunks: number | null;
  if (walFrames === 0) {
    shmChunks = 0;
  } else if (walFrames <= SQLITE_SHM_FIRST_CHUNK_FRAMES) {
    shmChunks = 1;
  } else {
    const remaining = walFrames - SQLITE_SHM_FIRST_CHUNK_FRAMES;
    const following = checkedCeilDiv(remaining, SQLITE_SHM_FOLLOWING_CHUNK_FRAMES);
    shmChunks = following === null ? null : checkedAdd(following, 1);
  }
  const shmBytes = shmChunks === null ? null : checkedMul(SQLITE_SHM_CHUNK_BYTES, shmChunks);
  const totalBytes = shmBytes === null
    ? null
    : checkedAdd(
        mainBytes,
        policy.max_main_journal_bytes,
        walBytes,
        shmBytes,
        policy.emergency_reserve_bytes,
      );
  if (shmBytes === null || totalBytes === null || totalBytes > policy.max_database_bytes) return null;
  return {
    page_size_bytes: pageSizeBytes,
    main_pages: mainPages,
    main_bytes: mainBytes,
    main_journal_bytes: policy.max_main_journal_bytes,
    wal_frames: walFrames,
    wal_bytes: walBytes,
    shm_bytes: shmBytes,
    emergency_reserve_bytes: policy.emergency_reserve_bytes,
    total_bytes: totalBytes,
  };
}

/** Validate GUI-edited policy values before sending them to the daemon. The
 *  daemon repeats these checks; this keeps invalid drafts visible locally and
 *  prevents an unrelated edit from silently dropping a stored policy. */
export function validateSemanticPolicy(policy: SemanticPolicyConfig, pageSizeBytes = 4_096): string | null {
  if (!Number.isSafeInteger(pageSizeBytes) || pageSizeBytes <= 0) {
    return "SQLite page size must be a positive safe integer";
  }
  for (const field of SEMANTIC_POLICY_FIELDS) {
    const value = policy[field];
    if (!Number.isSafeInteger(value) || value <= 0) {
      return `${field} must be a positive safe integer`;
    }
  }
  if (policy.max_quarantined_facts_per_author > policy.max_quarantined_facts) {
    return "max_quarantined_facts_per_author cannot exceed max_quarantined_facts";
  }
  if (policy.max_quarantined_bytes_per_author > policy.max_quarantined_bytes) {
    return "max_quarantined_bytes_per_author cannot exceed max_quarantined_bytes";
  }
  if (policy.max_retained_facts_per_author < policy.max_quarantined_facts_per_author) {
    return "max_retained_facts_per_author must cover quarantine per-author capacity";
  }
  if (policy.max_retained_bytes_per_author < policy.max_quarantined_bytes_per_author) {
    return "max_retained_bytes_per_author must cover quarantine per-author capacity";
  }
  if (policy.max_dependencies_per_fact > policy.max_dependency_edges) {
    return "max_dependencies_per_fact cannot exceed max_dependency_edges";
  }
  if (policy.max_authority_uses_per_fact > policy.max_dependency_edges) {
    return "max_authority_uses_per_fact cannot exceed max_dependency_edges";
  }
  if (policy.max_authority_predecessors_per_use > policy.max_dependency_edges) {
    return "max_authority_predecessors_per_use cannot exceed max_dependency_edges";
  }
  if (policy.max_ready_batch > policy.max_pending_proofs) {
    return "max_ready_batch cannot exceed max_pending_proofs";
  }
  if (policy.max_pending_proofs > policy.max_proof_records) {
    return "max_pending_proofs cannot exceed max_proof_records";
  }
  if (policy.max_pending_proof_bytes > policy.max_proof_bytes) {
    return "max_pending_proof_bytes cannot exceed max_proof_bytes";
  }
  if (policy.max_fact_encoded_bytes > policy.max_admitted_bytes) {
    return "max_fact_encoded_bytes cannot exceed max_admitted_bytes";
  }
  if (policy.max_fact_encoded_bytes > policy.max_quarantined_bytes) {
    return "max_fact_encoded_bytes cannot exceed max_quarantined_bytes";
  }
  if (policy.max_fact_encoded_bytes > policy.max_pending_proof_bytes) {
    return "max_fact_encoded_bytes cannot exceed max_pending_proof_bytes";
  }
  if (policy.max_fact_encoded_bytes > policy.max_proof_bytes) {
    return "max_fact_encoded_bytes cannot exceed max_proof_bytes";
  }
  if (policy.wal_checkpoint_threshold_bytes > policy.max_wal_bytes) {
    return "wal_checkpoint_threshold_bytes cannot exceed max_wal_bytes";
  }
  if (policy.max_transaction_dirty_main_pages > policy.max_database_bytes) {
    return "max_transaction_dirty_main_pages cannot exceed max_database_bytes";
  }
  if (policy.max_main_journal_bytes > policy.max_database_bytes) {
    return "max_main_journal_bytes cannot exceed max_database_bytes";
  }
  const maxDatabasePages = Math.floor(policy.max_database_bytes / pageSizeBytes);
  if (policy.max_freelist_pages > maxDatabasePages) {
    return "max_freelist_pages cannot exceed max_database_bytes page capacity";
  }
  if (policy.max_fragmented_pages > maxDatabasePages) {
    return "max_fragmented_pages cannot exceed max_database_bytes page capacity";
  }
  const retainedFacts = policy.max_admitted_facts + policy.max_quarantined_facts;
  if (!Number.isSafeInteger(retainedFacts) || policy.max_retained_facts_per_author > retainedFacts) {
    return "retained per-author fact capacity exceeds global retained capacity";
  }
  const retainedBytes = policy.max_admitted_bytes + policy.max_quarantined_bytes;
  if (!Number.isSafeInteger(retainedBytes) || policy.max_retained_bytes_per_author > retainedBytes) {
    return "retained per-author byte capacity exceeds global retained capacity";
  }
  const envelope = checkedSemanticStorageEnvelope(policy, pageSizeBytes);
  if (envelope === null) {
    return "semantic storage envelope exceeds a checked policy dimension";
  }
  if (policy.wal_checkpoint_threshold_bytes > envelope.wal_bytes) {
    return "wal_checkpoint_threshold_bytes cannot exceed derived retained WAL";
  }
  return null;
}

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
  semantic_policy: SemanticPolicyConfig;
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
    semantic_policy: canonicalSemanticPolicy(cfg.semantic_policy ?? DEFAULT_SEMANTIC_POLICY),
  };
}

/** True when the parsed JSON value carries our envelope marker.
 *  Cheap shape-only check; field validation lives in
 *  `coerceNetworkSettings`. */
export function isNetworkSettingsExport(raw: unknown): raw is NetworkSettingsExport {
  if (!raw || typeof raw !== "object") return false;
  const obj = raw as Record<string, unknown>;
  return (
    obj.kind === NETWORK_SETTINGS_KIND &&
    obj.version === NETWORK_SETTINGS_VERSION &&
    typeof obj.network_id === "string" &&
    "semantic_policy" in obj
  );
}

/** Parse a JSON string into a `NetworkSettingsExport`. Returns null
 *  when the input isn't JSON, lacks the envelope marker, or has an
 *  incomplete/unknown semantic-policy field set. Drops malformed individual
 *  entries rather than
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

function coerceNetworkSettings(raw: NetworkSettingsExport): NetworkSettingsExport | null {
  if (raw.version !== NETWORK_SETTINGS_VERSION) return null;
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
  const semanticPolicy = coerceSemanticPolicy(raw.semantic_policy);
  if (semanticPolicy === null) return null;
  return {
    kind: NETWORK_SETTINGS_KIND,
    version: NETWORK_SETTINGS_VERSION,
    network_id: String(raw.network_id ?? ""),
    ...(typeof raw.label === "string" && raw.label ? { label: raw.label } : {}),
    signaling_servers: signaling,
    stun_servers: stun,
    turn_servers: turn,
    semantic_policy: semanticPolicy,
  };
}

function coerceSemanticPolicy(raw: unknown): SemanticPolicyConfig | null {
  if (!raw || typeof raw !== "object") return null;
  const obj = raw as Record<string, unknown>;
  if (
    Object.keys(obj).length !== SEMANTIC_POLICY_FIELDS.length ||
    SEMANTIC_POLICY_FIELDS.some((field) => !Object.prototype.hasOwnProperty.call(obj, field))
  ) {
    return null;
  }
  const candidate = {} as SemanticPolicyConfig;
  for (const field of SEMANTIC_POLICY_FIELDS) {
    if (typeof obj[field] !== "number") return null;
    candidate[field] = obj[field] as number;
  }
  return validateSemanticPolicy(candidate) === null ? candidate : null;
}

function canonicalSemanticPolicy(raw: unknown): SemanticPolicyConfig {
  const policy = coerceSemanticPolicy(raw);
  if (policy === null) {
    throw new Error("semantic_policy must contain the exact canonical V4 fields");
  }
  return policy;
}

/** Executable, allocation-free policy controls for the GUI/Rust contract.
 *  These are intentionally opt-in so importing this module never changes UI
 *  state; the GUI test harness calls them directly. */
export function runSemanticPolicyControls(): void {
  const defaults = { ...DEFAULT_SEMANTIC_POLICY };
  const envelope = checkedSemanticStorageEnvelope(defaults);
  if (envelope === null) throw new Error("canonical semantic defaults lack a valid envelope");
  if (defaults.wal_checkpoint_threshold_bytes !== 32 + 1_018 * (4_096 + 24)) {
    throw new Error("canonical WAL checkpoint threshold drifted");
  }
  if (defaults.max_wal_bytes < envelope.wal_bytes) {
    throw new Error("canonical WAL ceiling does not cover the retained frame envelope");
  }

  const base: NetworkSettingsExport = {
    kind: NETWORK_SETTINGS_KIND,
    version: NETWORK_SETTINGS_VERSION,
    network_id: "semantic-policy-controls",
    signaling_servers: [],
    stun_servers: [],
    turn_servers: [],
    semantic_policy: defaults,
  };
  const parse = (value: unknown) => tryParseNetworkSettings(JSON.stringify(value));
  if (parse(base) === null) throw new Error("canonical settings were refused");

  const missing = { ...base, semantic_policy: { ...defaults } };
  delete (missing.semantic_policy as unknown as Record<string, unknown>).max_wal_bytes;
  if (parse(missing) !== null) throw new Error("missing policy field was accepted");

  const unknown = {
    ...base,
    semantic_policy: { ...defaults, unknown_policy_field: 1 } as SemanticPolicyConfig,
  };
  if (parse(unknown) !== null) throw new Error("unknown policy field was accepted");

  if (parse({ ...base, version: NETWORK_SETTINGS_VERSION - 1 }) !== null) {
    throw new Error("old settings version was accepted");
  }
  if (parse({ ...base, version: NETWORK_SETTINGS_VERSION + 1 }) !== null) {
    throw new Error("future settings version was accepted");
  }

  const walBelow = { ...defaults, max_wal_bytes: envelope.wal_bytes - 1 };
  if (checkedSemanticStorageEnvelope(walBelow) !== null) {
    throw new Error("N-1 WAL ceiling was accepted");
  }
  const thresholdAbove = {
    ...defaults,
    wal_checkpoint_threshold_bytes: envelope.wal_bytes + 1,
  };
  if (validateSemanticPolicy(thresholdAbove) === null) {
    throw new Error("N+1 WAL threshold was accepted");
  }
  const databaseBelow = { ...defaults, max_database_bytes: envelope.total_bytes - 1 };
  if (checkedSemanticStorageEnvelope(databaseBelow) !== null) {
    throw new Error("N-1 database envelope was accepted");
  }
  const databaseExact = { ...defaults, max_database_bytes: envelope.total_bytes };
  if (validateSemanticPolicy(databaseExact) !== null) {
    throw new Error("exact database envelope was refused");
  }
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
  semanticPolicy?: SemanticPolicyConfig;
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
    semantic_policy: canonicalSemanticPolicy(args.semanticPolicy ?? DEFAULT_SEMANTIC_POLICY),
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
