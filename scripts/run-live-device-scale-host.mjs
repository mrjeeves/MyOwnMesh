#!/usr/bin/env node

// One bounded coordinator per physical host for native live-device trials.
// It owns many real daemon identities through import-safe peer sessions, but
// exposes no network service and never retries a command with an unknown result.

import { spawn } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import { open, readFile, rename, stat, unlink } from "node:fs/promises";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { pathToFileURL } from "node:url";

import {
  ControllerError,
  JsonlWriter,
  LIMITS as PEER_LIMITS,
  controlEndpoint,
  createPeerSession,
  mergeControllerError,
  monoMs,
  sanitizeEvidence,
  stopOwnedChild,
} from "./live-device-peer.mjs";
import { validateCanonicalDeviceId } from "./live-device-topology.mjs";

export const SCALE_LIMITS = Object.freeze({
  peers: 500,
  manifestBytes: 8 * 1024 * 1024,
  journalBytes: 64 * 1024 * 1024,
  journalRows: 4096,
  commands: 100_000,
  samplerLineBytes: 1024 * 1024,
  samplerOutputBytes: 64 * 1024 * 1024,
  pollMs: 100,
  teardownReserveMs: 30_000,
});

export const GRANT_DIMENSIONS = Object.freeze([
  "accounted_memory_bytes",
  "queued_bytes",
  "socket_or_handle",
  "native_transport_object",
  "worker_or_task",
  "callback_or_scheduled_work",
  "storage_bytes",
  "storage_object",
  "relay_or_provider_allocation",
  "parsing_or_cpu_work",
  "opaque_dependency_residual",
]);

function checkedText(value, label, max = 128) {
  if (
    typeof value !== "string" ||
    value.length === 0 ||
    Buffer.byteLength(value, "utf8") > max ||
    /[\u0000-\u001f]/.test(value)
  ) {
    throw new ControllerError(`${label} is missing or invalid`);
  }
  return value;
}

function checkedInteger(value, label, min, max) {
  if (!Number.isSafeInteger(value) || value < min || value > max) {
    throw new ControllerError(`${label} must be an integer from ${min} through ${max}`);
  }
  return value;
}

function snapshotEqual(before, after) {
  return (
    before.dev === after.dev &&
    before.ino === after.ino &&
    before.size === after.size &&
    before.mtimeMs === after.mtimeMs &&
    before.ctimeMs === after.ctimeMs
  );
}

async function readStable(filePath, maxBytes, label) {
  const before = await stat(filePath);
  if (!before.isFile()) throw new ControllerError(`${label} is not a regular file`);
  if (before.size > maxBytes) throw new ControllerError(`${label} exceeds ${maxBytes} bytes`);
  const bytes = await readFile(filePath);
  const after = await stat(filePath);
  if (!snapshotEqual(before, after) || bytes.length !== after.size) return null;
  return bytes;
}

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

function requireAbsolute(value, label) {
  checkedText(value, label, 4096);
  if (!path.isAbsolute(value)) throw new ControllerError(`${label} must be absolute`);
  return path.resolve(value);
}

function decimalBigInt(value, label) {
  const text = typeof value === "bigint" ? value.toString() : String(value);
  if (!/^(0|[1-9][0-9]*)$/.test(text)) {
    throw new ControllerError(`${label} must be a finite nonnegative decimal integer`);
  }
  return BigInt(text);
}

export function parseGrant(raw, label = "resource grant") {
  if (typeof raw !== "string" || raw.trim().length === 0) {
    throw new ControllerError(`${label} must be nonempty`);
  }
  const result = new Map();
  for (const entry of raw.trim().split(",")) {
    const split = entry.split("=");
    if (split.length !== 2) throw new ControllerError(`${label} has an invalid entry`);
    const name = split[0].trim();
    if (!GRANT_DIMENSIONS.includes(name) || result.has(name)) {
      throw new ControllerError(`${label} has an unknown or duplicate dimension ${name}`);
    }
    result.set(name, decimalBigInt(split[1].trim(), `${label}.${name}`));
  }
  for (const name of GRANT_DIMENSIONS) {
    if (!result.has(name)) throw new ControllerError(`${label} omits ${name}`);
  }
  return result;
}

export function enforceHostGrantLedger(grants, ledger) {
  if (ledger === null || Array.isArray(ledger) || typeof ledger !== "object") {
    throw new ControllerError("hostGrantLedger must be an object");
  }
  const totals = new Map(GRANT_DIMENSIONS.map((name) => [name, 0n]));
  for (const grant of grants) {
    for (const name of GRANT_DIMENSIONS) totals.set(name, totals.get(name) + grant.get(name));
  }
  const evidence = {};
  for (const name of GRANT_DIMENSIONS) {
    if (!Object.hasOwn(ledger, name)) throw new ControllerError(`hostGrantLedger omits ${name}`);
    const limit = decimalBigInt(ledger[name], `hostGrantLedger.${name}`);
    const total = totals.get(name);
    if (total > limit) throw new ControllerError(`aggregate grant exceeds host ledger ${name}`);
    evidence[name] = { admitted: total.toString(), limit: limit.toString() };
  }
  if (Object.keys(ledger).some((name) => !GRANT_DIMENSIONS.includes(name))) {
    throw new ControllerError("hostGrantLedger contains an unknown dimension");
  }
  return evidence;
}

export function validateManifest(value) {
  if (value === null || Array.isArray(value) || typeof value !== "object") {
    throw new ControllerError("scale manifest must be one object");
  }
  if (value.schema !== "myownmesh-live-scale-host/v1") {
    throw new ControllerError("unsupported scale manifest schema");
  }
  const runId = checkedText(value.runId, "runId", 64);
  const physicalHost = checkedText(value.physicalHost, "physicalHost", 64);
  if (!/^[A-Za-z0-9._-]+$/.test(runId)) throw new ControllerError("runId has unsafe characters");
  if (!/^[A-Za-z0-9_-]+$/.test(physicalHost)) throw new ControllerError("physicalHost has unsafe characters");
  const stage = checkedInteger(value.stage, "stage", 1, SCALE_LIMITS.peers);
  if (![10, 50, 100, 250, 500].includes(stage)) {
    throw new ControllerError("stage must be one of 10, 50, 100, 250, or 500");
  }
  const aggregateDeadlineMs = checkedInteger(
    value.aggregateDeadlineMs,
    "aggregateDeadlineMs",
    SCALE_LIMITS.teardownReserveMs + 1,
    PEER_LIMITS.maxDurationMs,
  );
  const teardownReserveMs = checkedInteger(
    value.teardownReserveMs,
    "teardownReserveMs",
    PEER_LIMITS.shutdownMs,
    aggregateDeadlineMs - 1,
  );
  if (!Array.isArray(value.peers) || value.peers.length < 1 || value.peers.length > stage) {
    throw new ControllerError("peers must be this host's nonempty subset of the global stage");
  }
  const localPeerCount = value.peers.length;
  const maxConcurrentStarts = checkedInteger(
    value.maxConcurrentStarts,
    "maxConcurrentStarts",
    1,
    localPeerCount,
  );
  if (maxConcurrentStarts !== 1) {
    throw new ControllerError("the initial executable gate requires maxConcurrentStarts=1");
  }
  const maxConcurrentCommands = checkedInteger(
    value.maxConcurrentCommands,
    "maxConcurrentCommands",
    1,
    localPeerCount,
  );
  const topologyPlanPath = requireAbsolute(value.topologyPlanPath, "topologyPlanPath");
  if (typeof value.topologyPlanSha256 !== "string" || !/^[0-9a-f]{64}$/.test(value.topologyPlanSha256)) {
    throw new ControllerError("topologyPlanSha256 must be a lowercase SHA-256 digest");
  }
  const aliases = new Set();
  const paths = new Set();
  const peers = value.peers.map((peer, index) => {
    if (peer === null || Array.isArray(peer) || typeof peer !== "object") {
      throw new ControllerError(`peers[${index}] must be an object`);
    }
    const localAlias = checkedText(peer.localAlias, `peers[${index}].localAlias`, 64);
    if (!/^[A-Za-z0-9._-]+$/.test(localAlias) || aliases.has(localAlias)) {
      throw new ControllerError(`peers[${index}].localAlias is unsafe or duplicated`);
    }
    aliases.add(localAlias);
    const args = peer.args;
    if (args === null || Array.isArray(args) || typeof args !== "object") {
      throw new ControllerError(`peers[${index}].args must be an object`);
    }
    const normalized = {
      binary: requireAbsolute(args.binary, `${localAlias}.binary`),
      home: requireAbsolute(args.home, `${localAlias}.home`),
      config: requireAbsolute(args.config, `${localAlias}.config`),
      grantFile: requireAbsolute(args.grantFile, `${localAlias}.grantFile`),
      output: requireAbsolute(args.output, `${localAlias}.output`),
      durationMs: checkedInteger(
        args.durationMs,
        `${localAlias}.durationMs`,
        1,
        PEER_LIMITS.maxDurationMs,
      ),
      reuseHome: args.reuseHome === true,
    };
    for (const [kind, candidate] of Object.entries({ home: normalized.home, output: normalized.output })) {
      const key = process.platform === "win32" ? candidate.toLowerCase() : candidate;
      if (paths.has(key)) throw new ControllerError(`${kind} path is duplicated across peers`);
      paths.add(key);
    }
    if (!normalized.reuseHome) {
      throw new ControllerError(`${localAlias} must use an explicitly prepared isolated identity home`);
    }
    const expectedDeviceId = checkedText(peer.expectedDeviceId, `${localAlias}.expectedDeviceId`, 128);
    try { validateCanonicalDeviceId(expectedDeviceId); }
    catch (error) { throw new ControllerError(`${localAlias}.expectedDeviceId is not canonical`, "failed", error); }
    return {
      localAlias,
      expectedDeviceId,
      args: normalized,
    };
  });
  const sampler = value.sampler;
  if (typeof sampler !== "object" || sampler === null || Array.isArray(sampler)) {
    throw new ControllerError("a required sampler configuration must be an object");
  }
  {
    if (sampler.required !== true) throw new ControllerError("configured sampler must be required");
    requireAbsolute(sampler.scriptPath, "sampler.scriptPath");
    requireAbsolute(sampler.policyPath, "sampler.policyPath");
    requireAbsolute(sampler.manifestPath, "sampler.manifestPath");
    checkedInteger(sampler.heartbeatMs, "sampler.heartbeatMs", 100, 60_000);
    if (!Array.isArray(sampler.files)) throw new ControllerError("sampler.files must be an array");
    const samplerPaths = new Set();
    for (const [index, file] of sampler.files.entries()) {
      if (!file || typeof file !== "object" || Array.isArray(file)) {
        throw new ControllerError(`sampler.files[${index}] must be an object`);
      }
      const filePath = requireAbsolute(file.path, `sampler.files[${index}].path`);
      const fileKey = process.platform === "win32" ? filePath.toLowerCase() : filePath;
      if (samplerPaths.has(fileKey)) throw new ControllerError("sampler.files contains a duplicate path");
      samplerPaths.add(fileKey);
      if (file.nodeAlias !== null && file.nodeAlias !== undefined && !aliases.has(file.nodeAlias)) {
        throw new ControllerError(`sampler.files[${index}].nodeAlias is unknown`);
      }
      if (!["main", "wal", "shm", "journal", "log", "evidence"].includes(file.kind)) {
        throw new ControllerError(`sampler.files[${index}].kind is invalid`);
      }
    }
    for (const alias of aliases) {
      if (!sampler.files.some((file) => file.kind === "main" && file.nodeAlias === alias)) {
        throw new ControllerError(`sampler.files must identify a main database for ${alias}`);
      }
    }
  }
  return {
    runId,
    physicalHost,
    stage,
    aggregateDeadlineMs,
    teardownReserveMs,
    maxConcurrentStarts,
    maxConcurrentCommands,
    topologyPlanPath,
    topologyPlanSha256: value.topologyPlanSha256,
    hostGrantLedger: value.hostGrantLedger,
    peers,
    sampler,
  };
}

export function parseJournal(bytes, priorDigests = []) {
  if (!Buffer.isBuffer(bytes)) bytes = Buffer.from(bytes);
  if (bytes.length === 0) {
    if (priorDigests.length > 0) throw new ControllerError("host command journal truncated accepted history");
    return { rows: [], digests: [] };
  }
  if (bytes.length > SCALE_LIMITS.journalBytes) throw new ControllerError("host command journal is too large");
  if (bytes.at(-1) !== 0x0a) return null;
  const lines = bytes.toString("utf8").split("\n");
  lines.pop();
  if (lines.length < priorDigests.length) {
    throw new ControllerError("host command journal truncated accepted history");
  }
  if (lines.length > SCALE_LIMITS.journalRows) throw new ControllerError("host command journal has too many rows");
  const rows = [];
  const digests = [];
  for (let index = 0; index < lines.length; index += 1) {
    if (lines[index].length === 0) throw new ControllerError("host command journal has an empty row");
    const digest = sha256(Buffer.from(lines[index], "utf8"));
    if (index < priorDigests.length && priorDigests[index] !== digest) {
      throw new ControllerError("host command journal rewrote accepted history");
    }
    let row;
    try {
      row = JSON.parse(lines[index]);
    } catch (error) {
      throw new ControllerError("host command journal contains invalid JSON", "failed", error);
    }
    if (row === null || Array.isArray(row) || typeof row !== "object") {
      throw new ControllerError("host command journal row must be an object");
    }
    if (row.sequence !== index + 1) throw new ControllerError("journal sequence must be contiguous from one");
    if (!['phase', 'complete'].includes(row.kind)) throw new ControllerError("unsupported journal row kind");
    if (row.kind === "phase") {
      checkedText(row.phase, "journal phase", 80);
      if (!Array.isArray(row.commands) || row.commands.length === 0) {
        throw new ControllerError("journal phase requires commands");
      }
    } else if (row.commands !== undefined) {
      throw new ControllerError("journal complete row cannot contain commands");
    }
    rows.push(row);
    digests.push(digest);
  }
  return { rows, digests };
}

export function parseArgs(argv) {
  const values = new Map();
  for (let index = 0; index < argv.length; index += 2) {
    const key = argv[index];
    const value = argv[index + 1];
    if (!["--manifest", "--commands", "--output"].includes(key) || value === undefined) {
      throw new ControllerError("usage: --manifest ABS --commands ABS --output ABS");
    }
    if (values.has(key)) throw new ControllerError(`duplicate ${key}`);
    values.set(key, value);
  }
  for (const key of ["--manifest", "--commands", "--output"]) {
    if (!values.has(key)) throw new ControllerError(`missing ${key}`);
  }
  return {
    manifest: requireAbsolute(values.get("--manifest"), "manifest"),
    commands: requireAbsolute(values.get("--commands"), "commands"),
    output: requireAbsolute(values.get("--output"), "output"),
  };
}

function controllerStatus(error) {
  return error?.kind === "outcome_unknown"
    ? "outcome_unknown"
    : error?.kind === "censored"
      ? "censored"
      : error
        ? "failed"
        : "complete";
}

async function writeAtomicJson(filePath, value) {
  const temporary = `${filePath}.${process.pid}.${randomUUID()}.tmp`;
  const handle = await open(temporary, "wx", 0o600);
  let renamed = false;
  try {
    await handle.writeFile(`${JSON.stringify(value)}\n`, "utf8");
    await handle.sync();
    await handle.close();
    await rename(temporary, filePath);
    renamed = true;
  } finally {
    await handle.close().catch(() => {});
    if (!renamed) await unlink(temporary).catch(() => {});
  }
}

function samplerOwner(ownerId, nodeId, role, pid, terminalRequired) {
  return { ownerId, nodeId, role, pid, creationTimeUtcTicks: null, terminalRequired };
}

export function samplerFreshnessMs(policy) {
  const interval = checkedInteger(policy?.sampleIntervalMs, "policy.sampleIntervalMs", 1, 60_000);
  const sweep = checkedInteger(policy?.maxSweepMs, "policy.maxSweepMs", 1, 86_400_000);
  const result = interval + sweep;
  if (!Number.isSafeInteger(result)) throw new ControllerError("sampler freshness bound overflowed");
  return result;
}

export function samplerObservationError(record, phase) {
  if (!record || typeof record !== "object" || !["sample", "terminal"].includes(record.kind)) {
    return new ControllerError("resource sampler emitted an unsupported record");
  }
  if (record.kind === "terminal") {
    return phase === "complete" && record.success === true && record.observedRequiredExited === true
      ? null
      : new ControllerError("resource sampler terminated without successful required-owner custody");
  }
  const reasons = Array.isArray(record.reasons) ? record.reasons : [];
  const bootstrapOnly = phase === "startup" && record.decision === "Freeze" && reasons.length > 0 &&
    reasons.every((reason) => reason === "owner_unconfirmed");
  if (record.decision === "StopTrial") return new ControllerError("resource sampler ordered StopTrial");
  if (record.decision === "Freeze" && !bootstrapOnly) {
    return new ControllerError("resource sampler froze incomplete or stale evidence", "censored");
  }
  if (record.decision !== "Continue" && !bootstrapOnly) {
    return new ControllerError("resource sampler emitted an invalid decision");
  }
  if (record.decision === "Continue" && record.complete !== true) {
    return new ControllerError("resource sampler continued with incomplete evidence");
  }
  return null;
}

export class ResourceSampler {
  constructor(config, runId, signal, hooks = {}) {
    this.config = config;
    this.runId = runId;
    this.signal = signal;
    this.spawn = hooks.spawn ?? spawn;
    this.atomicWrite = hooks.atomicWrite ?? writeAtomicJson;
    this.now = hooks.monoMs ?? monoMs;
    this.onRecord = hooks.onRecord;
    this.onViolation = hooks.onViolation;
    this.owners = [];
    this.revision = 0;
    this.phase = "startup";
    this.latest = null;
    this.waiters = new Set();
    this.outputBytes = 0;
    this.closed = false;
    this.publishChain = Promise.resolve();
    this.files = config.files.filter((file) => file.nodeAlias == null);
  }

  async start() {
    const policyBytes = await readStable(this.config.policyPath, 64 * 1024, "resource sampler policy");
    if (policyBytes === null) throw new ControllerError("resource sampler policy changed while read");
    let policy;
    try { policy = JSON.parse(policyBytes.toString("utf8")); } catch (error) {
      throw new ControllerError("resource sampler policy is invalid JSON", "failed", error);
    }
    if (policy?.schema !== "myownmesh-resource-policy/v1" || policy.runId !== this.runId) {
      throw new ControllerError("resource sampler policy identity does not match the host run");
    }
    this.freshnessMs = samplerFreshnessMs(policy);
    this.owners.push(samplerOwner("host-controller", "host", "controller", process.pid, false));
    await this.#publish();
    this.child = this.spawn(
      "powershell.exe",
      ["-NoProfile", "-NonInteractive", "-File", this.config.scriptPath,
        "-PolicyPath", this.config.policyPath, "-ManifestPath", this.config.manifestPath],
      { windowsHide: true, stdio: ["ignore", "pipe", "pipe"] },
    );
    await new Promise((resolve, reject) => {
      this.child.once("spawn", resolve);
      this.child.once("error", reject);
    });
    this.child.stderr.on("data", (chunk) => {
      this.samplerStderrBytes = (this.samplerStderrBytes ?? 0) + chunk.length;
      if (this.samplerStderrBytes > SCALE_LIMITS.samplerLineBytes) {
        this.#violate(new ControllerError("resource sampler stderr exceeded its bound"));
      }
    });
    const lines = readline.createInterface({ input: this.child.stdout, crlfDelay: Infinity });
    this.reader = (async () => {
      try {
        for await (const line of lines) {
          this.outputBytes += Buffer.byteLength(line, "utf8") + 1;
          if (this.outputBytes > SCALE_LIMITS.samplerOutputBytes || Buffer.byteLength(line, "utf8") > SCALE_LIMITS.samplerLineBytes) {
            throw new ControllerError("resource sampler output exceeded its bound");
          }
          let record;
          try { record = JSON.parse(line); } catch (error) {
            throw new ControllerError("resource sampler emitted invalid JSON", "failed", error);
          }
          await this.acceptObservation(record);
        }
        if (!this.closed && this.latest?.kind !== "terminal") {
          this.#violate(new ControllerError("resource sampler ended without a terminal record"));
        }
      } catch (error) {
        this.#violate(error);
      }
    })();
    this.heartbeat = setInterval(() => {
      this.#publish().catch((error) => this.#violate(error));
    }, this.config.heartbeatMs);
    this.heartbeat.unref?.();
    await this.#pinOwner("host-controller", () => !this.signal.aborted);
  }

  #violate(error) {
    clearInterval(this.heartbeat);
    clearTimeout(this.freshnessTimer);
    this.failure = mergeControllerError(this.failure, error);
    try { this.onViolation?.(this.failure); } catch (callbackError) {
      this.failure = mergeControllerError(this.failure, callbackError);
    }
    for (const wake of this.waiters) wake();
    this.waiters.clear();
  }

  async acceptObservation(record) {
    this.latest = record;
    this.#observeHealth(record);
    await this.onRecord?.(record);
    for (const wake of this.waiters) wake();
    this.waiters.clear();
  }

  #armFreshness() {
    clearTimeout(this.freshnessTimer);
    if (this.closed || this.latest?.kind === "terminal") return;
    this.freshnessTimer = setTimeout(() => {
      this.#violate(new ControllerError(
        "resource sampler produced no observation within sampleIntervalMs + maxSweepMs",
        "censored",
      ));
    }, this.freshnessMs);
  }

  #observeHealth(record) {
    if (record?.kind === "terminal") {
      clearTimeout(this.freshnessTimer);
    } else if (record?.kind === "sample") this.#armFreshness();
    const error = samplerObservationError(record, this.phase);
    if (error) this.#violate(error);
  }

  async #publish() {
    this.publishChain = this.publishChain.then(async () => {
      const revision = ++this.revision;
      const manifest = {
        schema: "myownmesh-owned-resources/v1",
        runId: this.runId,
        revision,
        phase: this.phase,
        owners: this.owners.map((owner) => ({ ...owner })),
        files: this.files.map((file) => ({ path: path.resolve(file.path), kind: file.kind })),
      };
      await this.atomicWrite(this.config.manifestPath, manifest);
      return revision;
    });
    return this.publishChain;
  }

  async #waitFor(predicate, deadlineMs, ignoreWorkAbort = false, ignoreFailure = false) {
    for (;;) {
      if (this.failure && !ignoreFailure) throw this.failure;
      if (predicate(this.latest)) return this.latest;
      if (!ignoreFailure && this.latest?.decision === "StopTrial") {
        throw new ControllerError("resource sampler stopped the trial");
      }
      if ((!ignoreWorkAbort && this.signal.aborted) || this.now() >= deadlineMs) {
        throw new ControllerError("resource sampler observation deadline reached", "censored");
      }
      await new Promise((resolve) => {
        const timer = setTimeout(() => { this.waiters.delete(wake); resolve(); }, SCALE_LIMITS.pollMs);
        timer.unref?.();
        const wake = () => { clearTimeout(timer); resolve(); };
        this.waiters.add(wake);
      });
    }
  }

  async #pinOwner(ownerId, stillOwned) {
    const sample = await this.#waitFor(
      (row) => row?.kind === "sample" && row.processes?.some(
        (processRow) => processRow.ownerId === ownerId && processRow.registrationState === "unconfirmed",
      ),
      this.now() + 30_000,
    );
    const processRow = sample.processes.find((row) => row.ownerId === ownerId);
    if (!stillOwned()) throw new ControllerError(`${ownerId} exited before creation identity pin`);
    const owner = this.owners.find((row) => row.ownerId === ownerId);
    owner.creationTimeUtcTicks = checkedText(processRow.creationTimeUtcTicks, `${ownerId} ticks`, 19);
    if (!/^[1-9][0-9]{0,18}$/.test(owner.creationTimeUtcTicks)) {
      throw new ControllerError(`${ownerId} creation identity is invalid`);
    }
    if (!stillOwned()) throw new ControllerError(`${ownerId} exited during creation identity pin`);
    const pinnedRevision = await this.#publish();
    await this.#waitFor(
      (row) => row?.kind === "sample" && row.lastAcceptedRevision >= pinnedRevision &&
        row.processes?.some((entry) => entry.ownerId === ownerId && entry.registrationState === "confirmed"),
      this.now() + 30_000,
    );
    return owner.creationTimeUtcTicks;
  }

  async registerDaemon(alias, session, ready) {
    if (!session.daemonIsRunning()) throw new ControllerError(`${alias} daemon exited before registration`);
    const ownedFiles = this.config.files.filter((file) => file.nodeAlias === alias);
    for (const file of ownedFiles.filter((entry) => entry.kind === "main")) {
      const info = await stat(file.path);
      if (!info.isFile()) throw new ControllerError(`${alias} main database is not a regular file`);
    }
    this.files.push(...ownedFiles);
    const owner = samplerOwner(`daemon-${sha256(Buffer.from(alias, "utf8")).slice(0, 32)}`,
      alias, "daemon", ready.daemonPid, true);
    this.owners.push(owner);
    await this.#publish();
    const ticks = await this.#pinOwner(owner.ownerId, () => session.daemonIsRunning());
    await session.pinDaemonCreationIdentity(ticks);
    return ticks;
  }

  async gate(deadlineMs) {
    const requiredRevision = this.revision;
    return this.#waitFor(
      (row) => row?.kind === "sample" && row.lastAcceptedRevision >= requiredRevision && row.decision === "Continue",
      deadlineMs,
    );
  }

  async setPhase(phase) {
    this.phase = phase;
    await this.#publish();
  }

  async complete(deadlineMs) {
    await this.setPhase("complete");
    const terminal = await this.#waitFor(
      (row) => row?.kind === "terminal",
      deadlineMs,
      true,
      true,
    );
    if (terminal.success !== true || terminal.observedRequiredExited !== true) {
      throw new ControllerError("resource sampler did not prove required owners exited");
    }
    return terminal;
  }

  async close() {
    this.closed = true;
    clearInterval(this.heartbeat);
    clearTimeout(this.freshnessTimer);
    if (this.child && this.child.exitCode === null && this.child.signalCode === null) {
      await stopOwnedChild(this.child, this.now() + PEER_LIMITS.shutdownMs).catch((error) => {
        this.failure ??= error;
      });
    }
    await this.reader?.catch(() => {});
    if (this.failure) throw this.failure;
  }
}

function validatePhaseCommand(entry, peers, sequence, index) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) {
    throw new ControllerError("phase command must be an object");
  }
  const peer = checkedText(entry.peer, "phase command peer", 80);
  if (!peers.has(peer)) throw new ControllerError(`phase command references unknown peer ${peer}`);
  if (!entry.command || typeof entry.command !== "object" || Array.isArray(entry.command)) {
    throw new ControllerError("phase command.command must be an object");
  }
  if (entry.command.action === "stop") {
    throw new ControllerError("host phases close peers automatically and cannot contain stop actions");
  }
  if (!Array.isArray(entry.acceptedStatuses) || entry.acceptedStatuses.length === 0 ||
      entry.acceptedStatuses.some((status) => !["acknowledged", "observed", "ready", "pending", "passed"].includes(status))) {
    throw new ControllerError("phase command acceptedStatuses is invalid");
  }
  return {
    peer,
    command: { ...entry.command, id: `${sequence}-${index}-${entry.command.id ?? "command"}` },
    acceptedStatuses: [...new Set(entry.acceptedStatuses)],
  };
}

function canonicalJson(value) {
  if (Array.isArray(value)) return value.map(canonicalJson);
  if (value !== null && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, canonicalJson(value[key])]));
  }
  return value;
}

async function verifyTopology(manifest) {
  const bytes = await readStable(manifest.topologyPlanPath, SCALE_LIMITS.manifestBytes, "topology plan");
  if (bytes === null) throw new ControllerError("topology plan changed while read");
  if (sha256(bytes) !== manifest.topologyPlanSha256) throw new ControllerError("topology plan hash mismatch");
  let plan;
  try { plan = JSON.parse(bytes.toString("utf8")); } catch (error) {
    throw new ControllerError("topology plan is invalid JSON", "failed", error);
  }
  const { plan_sha256: embeddedDigest, ...digestInput } = plan;
  if (typeof embeddedDigest !== "string" ||
      sha256(Buffer.from(JSON.stringify(digestInput), "utf8")) !== embeddedDigest) {
    throw new ControllerError("topology plan embedded digest is invalid");
  }
  if (plan?.schema !== "myownmesh.scale-topology.v1" || plan.stage !== manifest.stage ||
      !Array.isArray(plan.nodes) || plan.nodes.length !== manifest.stage) {
    throw new ControllerError("topology plan does not match the exact stage");
  }
  if (new Set(plan.nodes.map((node) => node.local_alias)).size !== manifest.stage ||
      new Set(plan.nodes.map((node) => node.device_id)).size !== manifest.stage ||
      new Set(plan.nodes.map((node) => node.physical_host)).size !== 3 ||
      plan.nodes.some((node) => !/^[A-Za-z0-9_-]{1,128}$/.test(node.local_alias) ||
        !/^[A-Za-z0-9_-]{1,128}$/.test(node.physical_host))) {
    throw new ControllerError("topology plan does not contain unique global identities on three hosts");
  }
  for (const node of plan.nodes) {
    try { validateCanonicalDeviceId(node.device_id); }
    catch (error) { throw new ControllerError("topology plan contains a noncanonical identity", "failed", error); }
  }
  const aliases = plan.nodes.filter((node) => node.physical_host === manifest.physicalHost)
    .map((node) => node.local_alias).sort();
  const expected = manifest.peers.map((peer) => peer.localAlias).sort();
  if (JSON.stringify(aliases) !== JSON.stringify(expected)) {
    throw new ControllerError("topology plan host assignment does not match local peer sessions");
  }
  const planNodes = new Map(plan.nodes.map((node) => [node.local_alias, node]));
  const configSha256ByAlias = {};
  const endpoints = new Set();
  for (const peer of manifest.peers) {
    const node = planNodes.get(peer.localAlias);
    if (node?.device_id !== peer.expectedDeviceId) {
      throw new ControllerError(`${peer.localAlias} public identity differs from the topology plan`);
    }
    const configBytes = await readStable(peer.args.config, PEER_LIMITS.configBytes, `${peer.localAlias} config`);
    if (configBytes === null) throw new ControllerError(`${peer.localAlias} config changed while read`);
    let config;
    try { config = JSON.parse(configBytes.toString("utf8")); } catch (error) {
      throw new ControllerError(`${peer.localAlias} config is invalid JSON`, "failed", error);
    }
    if (!Array.isArray(config.networks) || config.networks.length !== 1 ||
        JSON.stringify(canonicalJson(config.networks[0])) !== JSON.stringify(canonicalJson(node.network_config))) {
      throw new ControllerError(`${peer.localAlias} config is not the exact planned network config`);
    }
    if (config.auto_update?.enabled !== false || config.auto_update?.auto_apply !== "none") {
      throw new ControllerError(`${peer.localAlias} config does not disable the updater`);
    }
    const endpoint = controlEndpoint(peer.args.home, config);
    const endpointKey = process.platform === "win32" ? endpoint.toLowerCase() : endpoint;
    if (endpoints.has(endpointKey)) throw new ControllerError("peer control endpoints are not unique");
    endpoints.add(endpointKey);
    configSha256ByAlias[peer.localAlias] = sha256(configBytes);
  }
  return { schema: plan.schema, plan_sha256: embeddedDigest, stage: plan.stage,
    file_sha256: manifest.topologyPlanSha256, config_sha256_by_alias: configSha256ByAlias };
}

async function loadManifest(filePath) {
  const bytes = await readStable(filePath, SCALE_LIMITS.manifestBytes, "scale manifest");
  if (bytes === null) throw new ControllerError("scale manifest changed while read");
  let value;
  try { value = JSON.parse(bytes.toString("utf8")); } catch (error) {
    throw new ControllerError("scale manifest is invalid JSON", "failed", error);
  }
  return { manifest: validateManifest(value), sha256: sha256(bytes) };
}

export async function runScaleHost(args, hooks = {}) {
  const clock = hooks.monoMs ?? monoMs;
  const createSession = hooks.createPeerSession ?? createPeerSession;
  const sleepFn = hooks.sleep ?? ((ms) => new Promise((resolve) => setTimeout(resolve, ms)));
  const loaded = await loadManifest(args.manifest);
  const manifest = loaded.manifest;
  const startedMs = clock();
  const deadlineMs = startedMs + manifest.aggregateDeadlineMs;
  const workDeadlineMs = deadlineMs - manifest.teardownReserveMs;
  const writer = await JsonlWriter.create(args.output);
  const emitLifecycle = hooks.emitLifecycle ?? (async (value) => {
    const line = `${JSON.stringify(value)}\n`;
    await new Promise((resolve, reject) => {
      process.stdout.write(line, (error) => error ? reject(error) : resolve());
    });
  });
  const abort = new AbortController();
  const externalAbort = () => abort.abort();
  hooks.signal?.addEventListener("abort", externalAbort, { once: true });
  if (hooks.signal?.aborted) externalAbort();
  const sessions = new Map();
  let sampler;
  let terminalError;
  let totalCommands = 0;
  let journalDigests = [];
  let processedRows = 0;
  let runResult;
  const signalAbort = () => abort.abort();
  const emergencyExit = () => {
    for (const session of sessions.values()) session.terminateOwnedChildOnParentExit?.();
  };
  process.on("SIGINT", signalAbort);
  process.on("SIGTERM", signalAbort);
  process.on("exit", emergencyExit);
  const timer = setTimeout(signalAbort, manifest.aggregateDeadlineMs - manifest.teardownReserveMs);
  timer.unref?.();
  const record = async (value, lifecycle = false) => {
    const safe = sanitizeEvidence(value);
    await writer.append(safe);
    if (lifecycle) await emitLifecycle(safe);
  };
  try {
    const topology = await verifyTopology(manifest);
    const grants = [];
    const grantSha256ByAlias = {};
    for (const peer of manifest.peers) {
      const bytes = await readStable(peer.args.grantFile, PEER_LIMITS.grantBytes, `${peer.localAlias} grant`);
      if (bytes === null) throw new ControllerError(`${peer.localAlias} grant changed while read`);
      grants.push(parseGrant(bytes.toString("utf8"), `${peer.localAlias} grant`));
      grantSha256ByAlias[peer.localAlias] = sha256(bytes);
      if (peer.args.durationMs < manifest.aggregateDeadlineMs) {
        throw new ControllerError(`${peer.localAlias} durationMs is shorter than aggregateDeadlineMs`);
      }
    }
    const ledger = enforceHostGrantLedger(grants, manifest.hostGrantLedger);
    await record({ type: "host_start", mono_ms: clock(), pid: process.pid, hostname: os.hostname(),
      platform: process.platform, arch: process.arch, run_id: manifest.runId, stage: manifest.stage,
      physical_host: manifest.physicalHost, local_peer_count: manifest.peers.length,
      manifest_sha256: loaded.sha256, topology, grant_ledger: ledger }, true);
    if (manifest.sampler) {
      const Sampler = hooks.ResourceSampler ?? ResourceSampler;
      sampler = new Sampler(manifest.sampler, manifest.runId, abort.signal, {
        ...hooks.samplerHooks,
        onRecord: (row) => record({ type: "resource_observation", record: row }),
        onViolation: (error) => {
          terminalError = mergeControllerError(terminalError, error);
          abort.abort();
        },
      });
      await sampler.start();
    }
    for (const peer of manifest.peers) {
      if (abort.signal.aborted || clock() >= workDeadlineMs) throw new ControllerError("startup exceeded work deadline", "censored");
      await sampler?.gate(workDeadlineMs);
      const session = createSession(peer.args, {
        signal: abort.signal,
        onRecord: (row) => record({ type: "peer_record", peer: peer.localAlias, record: row }),
      });
      sessions.set(peer.localAlias, session);
      const ready = await session.ready;
      if (ready.configSha256 !== topology.config_sha256_by_alias[peer.localAlias] ||
          ready.grantSha256 !== grantSha256ByAlias[peer.localAlias]) {
        throw new ControllerError(`${peer.localAlias} inputs changed between planning and launch`);
      }
      const creationTimeUtcTicks = sampler
        ? await sampler.registerDaemon(peer.localAlias, session, ready)
        : ready.daemonCreationIdentity;
      const status = await session.execute({ id: `status-${peer.localAlias}`, action: "rpc", request: { op: "status" } });
      if (status.status !== "acknowledged") throw new ControllerError(`${peer.localAlias} status was not acknowledged`);
      const identity = await session.execute({ id: `identity-${peer.localAlias}`, action: "rpc",
        request: { op: "identity_show" } });
      if (identity.status !== "acknowledged") throw new ControllerError(`${peer.localAlias} identity_show was not acknowledged`);
      const deviceId = identity.result?.data?.pubkey;
      try { validateCanonicalDeviceId(deviceId); }
      catch (error) { throw new ControllerError(`${peer.localAlias} identity_show omitted a canonical pubkey`, "failed", error); }
      if (deviceId !== peer.expectedDeviceId) {
        throw new ControllerError(`${peer.localAlias} canonical identity did not match the manifest`);
      }
      if ([...sessions.entries()].some(([alias, current]) => alias !== peer.localAlias && current.deviceId === deviceId)) {
        throw new ControllerError("two peer sessions exposed the same public identity");
      }
      session.deviceId = deviceId;
      await record({ type: "peer_ready", mono_ms: clock(), peer: peer.localAlias,
        daemon_pid: ready.daemonPid, creation_time_utc_ticks: creationTimeUtcTicks,
        device_id: deviceId, display_id: status.result?.data?.device_id ?? identity.result?.data?.device_id,
        binary_sha256: ready.binarySha256, config_sha256: ready.configSha256,
        grant_sha256: ready.grantSha256 }, true);
    }
    await sampler?.setPhase("warm");
    await sampler?.gate(workDeadlineMs);
    while (!abort.signal.aborted && clock() < workDeadlineMs) {
      const bytes = await readStable(args.commands, SCALE_LIMITS.journalBytes, "host command journal");
      if (bytes !== null) {
        const parsed = parseJournal(bytes, journalDigests);
        if (parsed !== null) {
          journalDigests = parsed.digests;
          while (processedRows < parsed.rows.length) {
            const row = parsed.rows[processedRows];
            if (row.kind === "complete") {
              await record({ type: "host_plan_complete", sequence: row.sequence, mono_ms: clock() }, true);
              processedRows += 1;
              runResult = { status: "complete", sessions: sessions.size, commands: totalCommands };
              break;
            }
            await sampler?.gate(workDeadlineMs);
            await sampler?.setPhase("steady");
            await sampler?.gate(workDeadlineMs);
            const commands = row.commands.map((entry, index) => validatePhaseCommand(entry, sessions, row.sequence, index));
            totalCommands += commands.length;
            if (totalCommands > SCALE_LIMITS.commands) throw new ControllerError("host command count exceeded the bound");
            for (let offset = 0; offset < commands.length; offset += manifest.maxConcurrentCommands) {
              const batch = commands.slice(offset, offset + manifest.maxConcurrentCommands);
              if (new Set(batch.map((item) => item.peer)).size !== batch.length) {
                throw new ControllerError("a concurrent command batch repeats a peer");
              }
              const results = await Promise.all(batch.map(async (item) => {
                try {
                  return { item, result: await sessions.get(item.peer).execute(item.command) };
                } catch (error) {
                  return { item, error };
                }
              }));
              let batchError;
              for (const { item, result, error } of results) {
                if (error) {
                  try {
                    await record({ type: "host_command_result", sequence: row.sequence, peer: item.peer,
                      id: item.command.id, action: item.command.action, status: controllerStatus(error),
                      mono_ms: clock(), error: { name: error?.name, kind: error?.kind } }, true);
                  } catch (captureError) {
                    batchError = mergeControllerError(batchError, captureError);
                  }
                  batchError = mergeControllerError(batchError, error);
                  continue;
                }
                try {
                  await record({ type: "host_command_result", sequence: row.sequence, peer: item.peer,
                    id: result.id, action: result.action, status: result.status, mono_ms: clock() }, true);
                } catch (captureError) {
                  batchError = mergeControllerError(batchError, captureError);
                }
                if (result.status === "outcome_unknown") {
                  batchError = mergeControllerError(batchError,
                    new ControllerError(`peer ${item.peer} returned outcome_unknown`, "outcome_unknown"));
                } else if (!item.acceptedStatuses.includes(result.status)) {
                  batchError = mergeControllerError(batchError,
                    new ControllerError(`peer ${item.peer} returned unexpected status ${result.status}`));
                }
              }
              if (abort.signal.aborted) {
                batchError = mergeControllerError(batchError,
                  new ControllerError("host work deadline interrupted a command batch", "censored"));
              }
              if (batchError) throw batchError;
            }
            await record({ type: "host_phase_terminal", sequence: row.sequence, phase: row.phase,
              status: "complete", commands: commands.length, mono_ms: clock() }, true);
            processedRows += 1;
          }
          if (runResult) break;
        }
      }
      if (runResult) break;
      await sleepFn(SCALE_LIMITS.pollMs);
    }
    if (!runResult) throw new ControllerError("host plan ended without an explicit complete row", "censored");
  } catch (error) {
    terminalError = mergeControllerError(terminalError, error);
    abort.abort();
  } finally {
    for (const [inputPath, expectedHash, limit, label] of [
      [args.manifest, loaded.sha256, SCALE_LIMITS.manifestBytes, "scale manifest"],
      [manifest.topologyPlanPath, manifest.topologyPlanSha256, SCALE_LIMITS.manifestBytes, "topology plan"],
    ]) {
      try {
        const bytes = await readStable(inputPath, limit, label);
        if (bytes === null || sha256(bytes) !== expectedHash) throw new ControllerError(`${label} changed during execution`);
      } catch (error) {
        terminalError = mergeControllerError(terminalError, error);
      }
    }
    await sampler?.setPhase("teardown").catch((error) => {
      terminalError = mergeControllerError(terminalError, error);
    });
    const terminals = await Promise.all([...sessions.entries()].reverse().map(async ([alias, session]) => {
      try { return { peer: alias, terminal: await session.close() }; }
      catch (error) {
        terminalError = mergeControllerError(terminalError, error);
        return { peer: alias, error: { message: String(error?.message), kind: error?.kind } };
      }
    }));
    let samplerTerminal;
    if (sampler) {
      try { samplerTerminal = await sampler.complete(deadlineMs); }
      catch (error) { terminalError = mergeControllerError(terminalError, error); }
      await sampler.close().catch((error) => {
        terminalError = mergeControllerError(terminalError, error);
      });
    }
    clearTimeout(timer);
    process.off("SIGINT", signalAbort);
    process.off("SIGTERM", signalAbort);
    process.off("exit", emergencyExit);
    hooks.signal?.removeEventListener("abort", externalAbort);
    await record({ type: "host_terminal", mono_ms: clock(), elapsed_ms: clock() - startedMs,
      status: controllerStatus(terminalError), peer_terminals: terminals, sampler_terminal: samplerTerminal,
      error: terminalError ? { name: terminalError.name, kind: terminalError.kind } : null,
      output_close_pending: true }, true).catch((error) => {
      terminalError = mergeControllerError(terminalError, error);
    });
    await writer.close().catch((error) => {
      terminalError = mergeControllerError(terminalError, error);
    });
  }
  if (terminalError) throw terminalError;
  return runResult;
}

async function main() {
  let code = 0;
  try { await runScaleHost(parseArgs(process.argv.slice(2))); }
  catch { code = 1; }
  process.exitCode = code;
}

if (pathToFileURL(process.argv[1] ?? "").href === import.meta.url) {
  await main();
}
